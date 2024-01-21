#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>

typedef int(WINAPI *PFnMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);
typedef FARPROC(WINAPI* PFnGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* PFnLoadLibraryW)(LPCWSTR);


PPEB GetPEB()
{
#if defined(_M_X64) // x64
	PTEB tebPtr = (PTEB)__readgsqword(offsetof(NT_TIB, Self));
#else // x86
	PTEB tebPtr = (PTEB)__readfsdword(offsetof(NT_TIB, Self));
#endif

	return tebPtr->ProcessEnvironmentBlock;
}

//bool SimpleDyLoadFunc()
//{
//	HMODULE hMod = LoadLibrary(L"user32.dll");
//	if (!hMod)
//		return false;
//
//	PFnMessageBox pfnMessageBox = (PFnMessageBox)GetProcAddress(hMod, "MessageBoxW");
//	if (!pfnMessageBox)
//	{
//		FreeLibrary(hMod);
//		return false;
//	}
//
//	pfnMessageBox(NULL, L"Hello World", L"OK", MB_OK);
//	FreeLibrary(hMod);
//
//	return true;
//}

DWORD GetApi(HMODULE hMod, const char* pszApiName);

int main()
{
	size_t offset = offsetof(struct _LDR_DATA_TABLE_ENTRY, DllBase);

	PPEB pPEBAddr = GetPEB();
	if (!pPEBAddr)
		return -1;

	PPEB_LDR_DATA pLdrData = pPEBAddr->Ldr;
	if (!pLdrData)
		return -2;

	DWORD dwDllBase = 0;
	LIST_ENTRY listEntry = pLdrData->InMemoryOrderModuleList;
	LIST_ENTRY tmpListEntry = listEntry;

	//ntdll!_LDR_DATA_TABLE_ENTRY
	//	+ 0x000 InLoadOrderLinks : _LIST_ENTRY[0x15451a8 - 0x7740db0c]
	//	+ 0x008 InMemoryOrderLinks : _LIST_ENTRY[0x15451b0 - 0x7740db14]
	//	+ 0x010 InInitializationOrderLinks : _LIST_ENTRY[0x0 - 0x0]
	//	+ 0x018 DllBase : 0x00f30000 Void
	//	+ 0x01c EntryPoint : 0x00f312a7 Void

	// * below is InMemoryOrderLinks of _LDR_DATA_TABLE_ENTRY
	// |-LDRDATATABLEENTRY-|        |-LDRDATATABLEENTRY-|        |-LDRDATATABLEENTRY-|
	// |      8bits        |        |      8bits        |        |      8bits        |
	// |        *          |-Flink->|        *          |-Flink->|        *          |
	// |-------------------|        |-------------------|        |-------------------|
	// |     exe name      |        |       ntdll       |        |      kernel32     |
	// |-------------------|        |-------------------|        |-------------------|
	// ref: https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode#finding-kernel32-address-in-assembly
	for (size_t id = 0; id < 3; id++)
	{
		LDR_DATA_TABLE_ENTRY* pItem = (LDR_DATA_TABLE_ENTRY*)((DWORD)listEntry.Flink - 0x08);
		auto name = pItem->FullDllName;
		dwDllBase = (DWORD)pItem->DllBase;
		listEntry = *listEntry.Flink;
	}

	printf("Base address of kernel32dll is 0x%x\n", dwDllBase);

	PFnGetProcAddress pFnGetProcAddress = (PFnGetProcAddress)GetApi((HMODULE)dwDllBase, "GetProcAddress");
	if (!pFnGetProcAddress)
		return -3;

	PFnLoadLibraryW pfnLoadraryW = (PFnLoadLibraryW)pFnGetProcAddress((HMODULE)dwDllBase, "LoadLibraryW");
	if (!pfnLoadraryW)
		return -4;

	HMODULE hModUser32 = pfnLoadraryW(L"user32.dll");
	if (!hModUser32)
		return -5;

	PFnMessageBox pfnMessageBoxW = (PFnMessageBox)pFnGetProcAddress(hModUser32, "MessageBoxW");
	if (!pfnMessageBoxW)
		return -6;

	pfnMessageBoxW(NULL, L"Hello World", L"OK", MB_OK);

	return 0;
}

DWORD GetApi(HMODULE hMod, const char* pszApiName)
{
	PIMAGE_NT_HEADERS pImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)hMod + *(PDWORD)((DWORD)hMod + 0x3c));
	PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hMod + pImageNTHeaders->OptionalHeader.DataDirectory->VirtualAddress);

	DWORD dwAddressOfNames = (DWORD)hMod + pImageExportDir->AddressOfNames;
	DWORD dwTmpAddressOfName = dwAddressOfNames;

	DWORD dwOffset = 0;
	for (size_t id = 0; id < pImageExportDir->NumberOfNames; id++)
	{
		DWORD dwNameAddr =  (DWORD)hMod + *(PDWORD)dwTmpAddressOfName;
		char* pszName = (char*)dwNameAddr;
		if (strcmp(pszName, pszApiName) == 0)
		{
			printf("Find named function %s\n", pszName);
			dwOffset = dwTmpAddressOfName - dwAddressOfNames;
			break;
		}

		dwTmpAddressOfName += sizeof(DWORD);
	}

	dwOffset = (dwOffset) >> 1;  // DWORD -> WORD

	DWORD dwAddressOfNameOrdinal = (DWORD)hMod + pImageExportDir->AddressOfNameOrdinals + dwOffset;
	WORD wIndexOfTargetFunc = *(PWORD)dwAddressOfNameOrdinal;

	DWORD dwAddressOfFuncs = (DWORD)hMod + pImageExportDir->AddressOfFunctions;
	DWORD dwTargetFuncEntryOffset = dwAddressOfFuncs + wIndexOfTargetFunc * sizeof(DWORD);

	DWORD dwTargetFuncEntry = (DWORD)hMod + *(PDWORD)dwTargetFuncEntryOffset;

	return dwTargetFuncEntry;
}