#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>

typedef int(WINAPI *PFnMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

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
	// |-LDRDATATABLEENTRY-|        |-LDRDATATABLEENTRY-|		 |-LDRDATATABLEENTRY-|
	// |      8bits        |        |      8bits        |		 |      8bits        |
	// |        *          |-Flink->|        *          |-Flink->|        *          |
	// |-------------------|        |-------------------| 		 |-------------------|
	// |     exe name      |        |       ntdll       | 		 |      kernel32     |
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

	return 0;
} 