#include "stdafx.h"

_NT_BEGIN

NTSTATUS WINAPI CheckDeadLock(PEXCEPTION_POINTERS pep)
{
	if (STATUS_POSSIBLE_DEADLOCK == pep->ExceptionRecord->ExceptionCode)
	{
		MessageBoxW(0, 0, L"STATUS_POSSIBLE_DEADLOCK", MB_ICONINFORMATION);
		ExitProcess((ULONG)STATUS_POSSIBLE_DEADLOCK);
		//TerminateProcess(NtCurrentProcess(), STATUS_POSSIBLE_DEADLOCK);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

ULONG WINAPI dfg(CRITICAL_SECTION* pcs)
{
	EnterCriticalSection(pcs);
	LeaveCriticalSection(pcs);

	return 0;
}

BOOL IsCriticalSectionDefaultTimeoutPresent()
{
	ULONG s;
	if (PIMAGE_LOAD_CONFIG_DIRECTORY ilcd = (PIMAGE_LOAD_CONFIG_DIRECTORY)
		RtlImageDirectoryEntryToData(&__ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &s))
	{
		enum { es = RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY, CriticalSectionDefaultTimeout) };
		if (es <= s && es <= ilcd->Size && ilcd->Size <= s)
		{
			if (DWORD CriticalSectionDefaultTimeout = ilcd->CriticalSectionDefaultTimeout)
			{
				if (CriticalSectionDefaultTimeout < 3600 * 1000)
				{
					WCHAR sz[0x100];
					if (0 < swprintf_s(sz, _countof(sz), L"CriticalSectionDefaultTimeout: %u ms", CriticalSectionDefaultTimeout))
					{
						MessageBoxW(0, sz, L"++", MB_ICONINFORMATION);

						return TRUE;
					}
				}
			}
		}
	}

	MessageBoxW(0, L"CriticalSectionDefaultTimeout", 0, MB_ICONWARNING);
	return FALSE;
}

void WINAPI ep(void*)
{
	if (IsCriticalSectionDefaultTimeoutPresent())
	{
		if (PVOID pv = AddVectoredExceptionHandler(TRUE, CheckDeadLock))
		{
			CRITICAL_SECTION cs;
			InitializeCriticalSection(&cs);
			EnterCriticalSection(&cs);
			if (HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)dfg, &cs, 0, 0))
			{
				WaitForSingleObject(hThread, INFINITE);
				NtClose(hThread);
			}

			RemoveVectoredExceptionHandler(pv);
		}
	}

	ExitProcess(0);
}

_NT_END