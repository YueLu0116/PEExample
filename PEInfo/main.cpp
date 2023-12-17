#include <Windows.h>
#include <cstdio>

#include <string>

struct PEFileInfo
{
	LPVOID            pStartAddress;
	LONGLONG          llFileSize;
	PIMAGE_NT_HEADERS pImageNTHeaders;
};

static PEFileInfo g_peFileInfo{};

bool OpenPEFile(const std::string& strPEPath, LPVOID* pStartAddress);
bool CheckPEFile(PIMAGE_DOS_HEADER pImageDOSHeader);
bool GetPEImportInfo();
DWORD RVA2FOV(PIMAGE_NT_HEADERS pImageNTHeaders, DWORD dwRVA);

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("Usage: PEInfo.exe <exe_path>\n");
		return -1;
	}

	printf("Handling PE path: %s\n", argv[1]);

	PIMAGE_DOS_HEADER pImageDosHeder = NULL;
	if (!OpenPEFile(argv[1], (LPVOID*)&pImageDosHeder))
	{
		printf("Failed to open PE file\n");
		return -2;
	}

	if (!CheckPEFile(pImageDosHeder))
	{
		printf("Invalid PE file\n");
		return -3;
	}

	GetPEImportInfo();

	return 0;
}

bool OpenPEFile(const std::string& strPEPath, LPVOID* ppStartAddress)
{
	HANDLE hFile = CreateFileA(strPEPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	LARGE_INTEGER lnFileSize{};
	if (!GetFileSizeEx(hFile, &lnFileSize))
	{
		CloseHandle(hFile);
		return false;
	}

	if (!lnFileSize.QuadPart)
	{
		CloseHandle(hFile);
		return false;
	}

	printf("File size is %lld\n", lnFileSize.QuadPart);
	
	HANDLE hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hFileMap || hFileMap == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return false;
	}

	*ppStartAddress = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (!*ppStartAddress)
	{
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		return false;
	}

	g_peFileInfo.llFileSize = lnFileSize.QuadPart;
	g_peFileInfo.pStartAddress = *ppStartAddress;

	return true;
}

bool CheckPEFile(PIMAGE_DOS_HEADER pImageDOSHeader)
{
	if (!pImageDOSHeader || pImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS)((unsigned long)pImageDOSHeader + pImageDOSHeader->e_lfanew);
	if (!pImageNTHeader || pImageNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	g_peFileInfo.pImageNTHeaders = pImageNTHeader;

	return true;
}

bool GetPEImportInfo()
{
	if (!g_peFileInfo.pImageNTHeaders || !g_peFileInfo.pStartAddress)
	{
		return false;
	}

	auto pPEFileHeader = g_peFileInfo.pImageNTHeaders;
	if (!pPEFileHeader->OptionalHeader.DataDirectory[1].VirtualAddress)  // import table
	{
		return false;
	}
	
	DWORD dwOffsetImportTable = RVA2FOV(pPEFileHeader, pPEFileHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	IMAGE_IMPORT_DESCRIPTOR* pImageImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((unsigned long)g_peFileInfo.pStartAddress + dwOffsetImportTable);
	while (pImageImportDesc->OriginalFirstThunk || pImageImportDesc->TimeDateStamp || pImageImportDesc->ForwarderChain || pImageImportDesc->Name || pImageImportDesc->FirstThunk)
	{
		DWORD dwOffsetImportName = RVA2FOV(pPEFileHeader, pImageImportDesc->Name);
		auto pDllFileName = (char*)((unsigned long)g_peFileInfo.pStartAddress + dwOffsetImportName);
		printf("## Import library: %s\n", pDllFileName);

		DWORD dwRVAofIAT;
		if (pImageImportDesc->OriginalFirstThunk)
		{
			dwRVAofIAT = pImageImportDesc->OriginalFirstThunk;
		}
		else 
		{
			dwRVAofIAT = pImageImportDesc->FirstThunk;
		}

		DWORD dwOffsetIAT = RVA2FOV(pPEFileHeader, dwRVAofIAT);
		DWORD* pdwTmp = (DWORD*)((unsigned long)g_peFileInfo.pStartAddress + dwOffsetIAT);
		while (*pdwTmp)
		{
			DWORD dwRVATmp;
			if (*pdwTmp & IMAGE_ORDINAL_FLAG32)
			{
				printf("0x%hx\n", *pdwTmp & 0x0ffff);
			}
			else 
			{
				DWORD dwOffset = RVA2FOV(pPEFileHeader, *pdwTmp);
				IMAGE_IMPORT_BY_NAME* pImageImportByName = (IMAGE_IMPORT_BY_NAME*)((unsigned long)g_peFileInfo.pStartAddress + dwOffset);
				printf("%u %s\n", pImageImportByName->Hint, pImageImportByName->Name);
			}

			pdwTmp++;
		}

		pImageImportDesc++;
	}

	return true;
}

DWORD RVA2FOV(PIMAGE_NT_HEADERS pImageNTHeaders, DWORD dwRVA)
{
	if (!pImageNTHeaders)
	{
		return 0;
	}

	DWORD dwRet = 0;
	IMAGE_SECTION_HEADER* pImageSectionHeader = (IMAGE_SECTION_HEADER*)((unsigned long)pImageNTHeaders + sizeof(IMAGE_NT_HEADERS));
	for (int nIdSection = 0; nIdSection < pImageNTHeaders->FileHeader.NumberOfSections; nIdSection++)
	{
		DWORD dwSectionEndVirtualAddress = pImageSectionHeader->VirtualAddress + pImageSectionHeader->SizeOfRawData;
		if (dwRVA < dwSectionEndVirtualAddress && dwRVA >= pImageSectionHeader->VirtualAddress)
		{
			DWORD dwOffsetInSection = dwRVA - pImageSectionHeader->VirtualAddress;
			dwRet = dwOffsetInSection + pImageSectionHeader->PointerToRawData;
			return dwRet;
		}

		pImageSectionHeader++;
	}

	return dwRet;
}