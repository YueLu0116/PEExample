#include <Windows.h>
#include <stdio.h>

#include "resource.h"

typedef void(__cdecl *PFN_PrintMsg)();

bool CreateDll(HINSTANCE hInstance);

int main()
{
    printf("Hello World!\n");

    if(!CreateDll(NULL))
        return -1;

    HMODULE hMod = LoadLibraryA("DelayLoadDll.dll");
    if (hMod == NULL)
    {
        printf("LoadLibrary failed. Reason=%ld\n", GetLastError());
        return -2;
    }

    PFN_PrintMsg pFnPrintMsg = (PFN_PrintMsg)GetProcAddress(hMod, "PrintMsg");
    if (!pFnPrintMsg)
    {
        printf("GetProcAddress failed. Reason=%ld\n", GetLastError());
        return -3;
    }

    pFnPrintMsg();

    return 0;
}

bool CreateDll(HINSTANCE hInstance)
{
    HRSRC hResouce = FindResourceA(hInstance, MAKEINTRESOURCEA(IDR_DLL1), "DLL");
    if (hResouce == NULL)
        return false;

    DWORD dwSize = SizeofResource(hInstance, hResouce);
    LPVOID lpRes = LockResource(LoadResource(hInstance, hResouce));
    if (!lpRes)
        return false;

    HANDLE hFile = CreateFileA("DelayLoadDll.dll", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwWriteSize;

    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    WriteFile(hFile, lpRes, dwSize, &dwWriteSize, NULL);
    CloseHandle(hFile);

    return true;
}
