#include <Windows.h>
#include "xorstr.hpp"
#include <lazy_importer.hpp>
#include <string>

#include <winternl.h>
#include "xorstr.hpp"
DWORD64 b_exit_process = 0;

void call_dll_main(uintptr_t image_base,void* dll_main_address)
{

	NTSTATUS __stdcall NtCreateThreadEx(
		PHANDLE     hThread,
		ACCESS_MASK DesiredAccess,
		PVOID       ObjectAttributes,
		HANDLE      ProcessHandle,
		PVOID       lpStartAddress,
		PVOID       lpParameter,
		ULONG       Flags,
		SIZE_T      StackZeroBits,
		SIZE_T      SizeOfStackCommit,
		SIZE_T      SizeOfStackReserve,
		PVOID       lpBytesBuffer
	);




	DWORD64 pRtlExitUserThread = (DWORD64)LI_FN(GetProcAddress).get()(LI_FN(GetModuleHandleA).get()(xorstr_("ntdll")), xorstr_("RtlExitUserThread"));
	auto pNtCreateThreadEx = LI_FN(NtCreateThreadEx).in_safe((HMODULE)GetModuleHandleA("ntdll.dll"));

	if (!pNtCreateThreadEx) return;


	CONTEXT nt_createthreadex{};
	



	{

		
		DWORD dwp;
		
		{



			DWORD dwthread;

	

			HANDLE thread = NULL;
			if (NT_SUCCESS(pNtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)(Sleep), NULL, TRUE , 0, 0, 0, NULL)))
			{
				nt_createthreadex.ContextFlags = CONTEXT_FULL;


				LI_FN(GetThreadContext).get()(thread, &nt_createthreadex);


				nt_createthreadex.Rcx = image_base;
				nt_createthreadex.Rdx = 1;
				nt_createthreadex.R8 = 0;
				nt_createthreadex.Rip = (DWORD64)dll_main_address;

				//nt_createthreadex.Rsp -= 0x28;

				*(ULONG_PTR*)nt_createthreadex.Rsp = pRtlExitUserThread;

				nt_createthreadex.ContextFlags = CONTEXT_FULL;
				LI_FN(SetThreadContext).get()(thread, &nt_createthreadex);
				LI_FN(ResumeThread).get()(thread);

			}
			else
			{
				/*MYLOG("[-] NtCreateThreadEx failed\n");*/
			}


		}
		
	}
	



}