#include "stdafx.h"

_NT_BEGIN
#include "print.h"

BOOL GetFileOffset(HANDLE hFile, _Inout_ PLARGE_INTEGER ByteOffset, DWORD VirtualAddress, ULONG NumberOfSections)
{
	BOOL fOk = FALSE;

	if (NumberOfSections && VirtualAddress)
	{
		ULONG VO = NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

		if (PVOID buf = _malloca(VO))
		{
			IO_STATUS_BLOCK iosb;

			if (0 <= NtReadFile(hFile, 0, 0, 0, &iosb, buf, VO, ByteOffset, 0) && VO == iosb.Information)
			{
				PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)buf;

				do
				{
					if (pish->VirtualAddress <= VirtualAddress)
					{
						VO = VirtualAddress - pish->VirtualAddress;
						if (VO < pish->Misc.VirtualSize && VO < pish->SizeOfRawData)
						{
							ByteOffset->QuadPart = pish->PointerToRawData + VO;
							fOk = TRUE;
							break;
						}
					}

				} while (pish++, --NumberOfSections);
			}

			_freea(buf);
		}
	}

	return fOk;
}

NTSTATUS SetCriticalSectionDefaultTimeout(HANDLE hFile, ULONG CriticalSectionDefaultTimeout)
{
	union {
		IMAGE_DOS_HEADER idh;
		IMAGE_NT_HEADERS inth;
		IMAGE_NT_HEADERS64 inth64;
		IMAGE_NT_HEADERS32 inth32;
		IMAGE_LOAD_CONFIG_DIRECTORY ilcd;
	};

	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	LARGE_INTEGER ByteOffset = {};

	if (0 <= (status = NtReadFile(hFile, 0, 0, 0, &iosb, &idh, sizeof(idh), &ByteOffset, 0)))
	{
		status = STATUS_INVALID_IMAGE_NOT_MZ;

		if (sizeof(idh) == iosb.Information && IMAGE_DOS_SIGNATURE == idh.e_magic)
		{
			ByteOffset.LowPart = idh.e_lfanew;

			if (0 <= (status = NtReadFile(hFile, 0, 0, 0, &iosb, &inth, sizeof(inth64), &ByteOffset, 0)))
			{
				status = STATUS_INVALID_IMAGE_FORMAT;

				if (sizeof(inth64) == iosb.Information && IMAGE_NT_SIGNATURE == inth.Signature)
				{
					PIMAGE_DATA_DIRECTORY pidd = 0;

					switch (inth.OptionalHeader.Magic)
					{
					case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
						pidd = inth32.OptionalHeader.DataDirectory;
						break;
					case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
						pidd = inth64.OptionalHeader.DataDirectory;
						break;
					}

					if (pidd)
					{
						pidd += IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;

						status = STATUS_NOT_FOUND;

						if (DWORD Size = pidd->Size)
						{
							enum { es = RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY, CriticalSectionDefaultTimeout) };

							if (es <= Size)
							{
								ByteOffset.QuadPart += FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + inth.FileHeader.SizeOfOptionalHeader;

								if (GetFileOffset(hFile, &ByteOffset, pidd->VirtualAddress, inth.FileHeader.NumberOfSections) &&
									0 <= (status = NtReadFile(hFile, 0, 0, 0, &iosb, &ilcd, es, &ByteOffset, 0)))
								{
									status = STATUS_NOT_FOUND;

									if (es == iosb.Information && es <= ilcd.Size)
									{
										ByteOffset.QuadPart += FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY, CriticalSectionDefaultTimeout);

										return NtWriteFile(hFile, 0, 0, 0, &iosb,
											&CriticalSectionDefaultTimeout,
											sizeof(CriticalSectionDefaultTimeout), &ByteOffset, 0);
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return status;
}

NTSTATUS SetCriticalSectionDefaultTimeout(PCWSTR pcszFileName, ULONG CriticalSectionDefaultTimeout)
{
	DbgPrint("::(%u, \"%ws\")\r\n", CriticalSectionDefaultTimeout, pcszFileName);

	UNICODE_STRING ObjectName;
	NTSTATUS status;
	PWSTR FilePart;
	if (0 <= (status = RtlDosPathNameToNtPathName_U_WithStatus(pcszFileName, &ObjectName, &FilePart, 0)))
	{
		static const WCHAR fmt[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
		PWSTR psz = (PWSTR)alloca(sizeof(fmt) + wcslen(FilePart) * sizeof(WCHAR));
		wcscpy(wcscpy(psz, fmt) + _countof(fmt) - 1, FilePart);

		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		IO_STATUS_BLOCK iosb;
		HANDLE hFile;
		status = NtOpenFile(&hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &oa, &iosb, 0, FILE_SYNCHRONOUS_IO_NONALERT);
		RtlFreeUnicodeString(&ObjectName);

		DbgPrint("OpenFile=%x\r\n", status);

		if (0 <= status)
		{
			status = SetCriticalSectionDefaultTimeout(hFile, CriticalSectionDefaultTimeout);
			NtClose(hFile);

			RtlInitUnicodeString(&ObjectName, psz);

			if (0 <= status && 0 <= (status = ZwCreateKey(&hFile, KEY_SET_VALUE, &oa, 0, 0, 0, 0)))
			{
				RtlInitUnicodeString(&ObjectName, L"RaiseExceptionOnPossibleDeadlock");
				ULONG v = 1;
				status = ZwSetValueKey(hFile, &ObjectName, 0, REG_DWORD, &v, sizeof(v));
				NtClose(hFile);
			}
		}
	}

	DbgPrint("status=%x\r\n", status);
	PrintError(status);
	return status;
}

NTSTATUS SetCriticalSectionDefaultTimeout(PWSTR pszCmdLine = GetCommandLineW())
{
	if (pszCmdLine = wcschr(pszCmdLine, '*'))
	{
		if (ULONG CriticalSectionDefaultTimeout = wcstoul(pszCmdLine + 1, &pszCmdLine, 10))
		{
			if ('*' == *pszCmdLine && CriticalSectionDefaultTimeout < 3600 * 1000)
			{
				return SetCriticalSectionDefaultTimeout(pszCmdLine + 1, CriticalSectionDefaultTimeout);
			}
		}
	}

	DbgPrint("invalid command line: *<Timeout>*<file path>\r\n");
	return STATUS_INVALID_PARAMETER;
}

void WINAPI ep(void*)
{
	PrintInfo pi;
	InitPrintf();
	ExitProcess(SetCriticalSectionDefaultTimeout());
}

_NT_END