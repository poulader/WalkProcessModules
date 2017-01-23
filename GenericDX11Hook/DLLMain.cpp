#ifndef  _DEBUG
#define _RELEASE_TESTING
#endif // ! _DEBUG


#include <Windows.h>
//#include "GenericHook.h"
#ifdef _DEBUG
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#endif
#ifdef _RELEASE_TESTING
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#endif
#include <winternl.h>
#include <tchar.h>


extern "C"
{
	#include "HookHelpers.h"
	__declspec(dllexport) int SetTargetName(TCHAR const *name, uint32_t strLen);
}

int SetTargetName(TCHAR const *name, uint32_t strLen)
{
	//todo
	return -1;
}

int quicktest();

const TCHAR processName[] = _T("bf4.exe");
const char logFilePath[] = "D:\\Documents\\bf4log.txt";

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		quicktest();
	}
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	defaut:
		break;
	};

	return 0;
}


int quicktest()
{

	//get PEB
	PEB *pPEB = GetPEB();

	if (pPEB == NULL)
		return -1;

	TCHAR imageName[MAX_PATH];
	int imageNameLength = 0;

	if ((imageNameLength = GetProcessName(pPEB, imageName, MAX_PATH)) <= 0)
		return -2;

	//I dont want to use psapi so we have to parse the modules, which means we need the name... might manually parse image base sections
	PE_PEB_LDR_DATA pLdr = (PE_PEB_LDR_DATA)pPEB->Ldr;

	//the various lists, note that initorder does not contain the base .exe in the list
	LIST_ENTRY *pMemoryOrderHead = &pLdr->InMemoryOrderModuleList;
	LIST_ENTRY *pLoadOrderHead = &pLdr->InLoadOrderModuleList;
	LIST_ENTRY *pInitOrderHead = &pLdr->InInitializationOrderModuleList;

	LIST_ENTRY *pInitOrderCursor = pInitOrderHead->Flink;
	LIST_ENTRY *pLoadOrderCursor = pLoadOrderHead->Flink;

	//we can tell when we have completed parse when we hit the head again

	//current entry
	E_LDR_DATA_TABLE_ENTRY *curInitOrderEntry = NULL, *curLoadOrderEntry = NULL;

	//note that the InitOrder link is the third memeber of struct, inmemory is the second, inloadorder is the first



	curInitOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)(pInitOrderCursor - 2);
	curLoadOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)pLoadOrderCursor;

	PUNICODE_STRING pWStrKernel32 = NULL;

	TCHAR kname[13] = _T("kernel32.dll");

#ifdef _RELEASE_TESTING
	std::wofstream outFileData;
	outFileData.open("D:\\Documents\\bf4log.txt", std::ios::in | std::ios::out | std::ios::trunc);
	outFileData << std::hex;
#endif

	

#ifdef _DEBUG
	std::wstring moduleName, targetKernel32Name(_T("kernel32.dll")), targetExeName;
#endif

	PVOID kernel32Base = NULL, exeBase = NULL;
	uint32_t exeImageSize = 0;

#ifdef _DEBUG
	_tprintf(_T("Init Order Modules:\n"));
#endif

#ifdef _RELEASE_TESTING
	outFileData << _T("Init Order Modules") << std::endl;
#endif

	while (pInitOrderCursor != pInitOrderHead)
	{
		curInitOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)(pInitOrderCursor - 2);
		pInitOrderCursor = pInitOrderCursor->Flink;
		//base dll name offset
		pWStrKernel32 = &curInitOrderEntry->BaseDllName;

		if (pWStrKernel32->Length == 0 || pWStrKernel32->MaximumLength == 0)
			curInitOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)((curInitOrderEntry->InInitializationOrderLinks.Flink) - 2);
		else
		{

#ifdef _DEBUG

			moduleName = std::wstring(pWStrKernel32->Buffer);
			_tprintf(moduleName.c_str());

			if ((moduleName == targetKernel32Name) && kernel32Base == NULL)
			{
				kernel32Base = curInitOrderEntry->DllBase;
			}

			printf("\n");

#else

#ifdef _RELEASE_TESTING
			std::wstring modString(pWStrKernel32->Buffer);
			outFileData << modString.c_str() << std::endl;
#endif

			BYTE foundIt = 1;
			if (kernel32Base == NULL)
			{
				for (UINT i = 0; i < pWStrKernel32->MaximumLength && (i < (sizeof(kname) / sizeof(TCHAR))); i++)
				{
					if (kname[i] != pWStrKernel32->Buffer[i])
					{
						foundIt = 0;
						break;
					}
				}
				if (foundIt == 1)
				{
					kernel32Base = curInitOrderEntry->DllBase;
				}
			}


#endif

			curInitOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)((curInitOrderEntry->InInitializationOrderLinks.Flink) - 2);
			continue;
		}
	}

#ifdef _DEBUG
	_tprintf(_T("\nLoad Order Modules:\n"));
#endif

#ifdef _RELEASE_TESTING
	outFileData << _T("\nLoad Order Modules") << std::endl;
#endif

	while (pLoadOrderCursor != pLoadOrderHead)
	{

		curLoadOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)pLoadOrderCursor;
		pLoadOrderCursor = pLoadOrderCursor->Flink;
		//base dll name offset
		pWStrKernel32 = &curLoadOrderEntry->BaseDllName;

		if (pWStrKernel32->Length == 0 || pWStrKernel32->MaximumLength == 0)
			curLoadOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)(curLoadOrderEntry->InLoadOrderLinks.Flink);
		else
		{

#ifdef _DEBUG
			moduleName = std::wstring(pWStrKernel32->Buffer);
			_tprintf(moduleName.c_str());

			if ( exeBase == NULL && (moduleName.find_first_of(_T(".exe")) != std::wstring::npos))
			{
				targetExeName = moduleName;
				exeBase = curLoadOrderEntry->DllBase;
				exeImageSize = curLoadOrderEntry->SizeOfImage;
			}

			printf("\n");

#else


#ifdef _RELEASE_TESTING
			std::wstring modString(pWStrKernel32->Buffer);
			outFileData << modString << std::endl;
			outFileData << _T("Base: ") << (uint64_t)curLoadOrderEntry->DllBase << std::endl;
#endif

			BYTE foundIt = 1;
			if (exeBase == NULL)
			{
				for (UINT i = 0; i < pWStrKernel32->MaximumLength && (i < (sizeof(processName) / sizeof(TCHAR))); i++)
				{
					if (processName[i] != pWStrKernel32->Buffer[i])
					{
						foundIt = 0;
						break;
					}
				}
				if (foundIt == 1)
				{
					exeBase = curLoadOrderEntry->DllBase;
					exeImageSize = curLoadOrderEntry->SizeOfImage;
				}
			}

#endif

			curLoadOrderEntry = (E_LDR_DATA_TABLE_ENTRY *)(curLoadOrderEntry->InLoadOrderLinks.Flink);
			continue;
		}

	}


	//quick test
	uint64_t possiblePresentCalls[MAX_PATH][2];

	for (uint32_t i = 0; i < MAX_PATH; ++i)
	{
		possiblePresentCalls[i][0] = 0;
		possiblePresentCalls[i][1] = 0;
	}

	uint32_t possiblePresentCallsCount = 0;

	//look for all call qword ptr [rax+40h]

	//then, assuming we are still in image, look for up to 33 bytes behind the first byte of opcode
	//for mov rax, qword ptr [rax]. (33 bytes because the largest possible instruction in x86-64 is 15 bytes)

	//so we are looking for the entry in vtable for Present

	//i suppose another way to do it would be to find it in dxgi.dll,, that is not going to change very often,
	//hook it there, look at return address on stack... unless they jmp, then maybe set veh &change permissions

	//im also considering writing a stripped down version of this in assembly and looking for code cave,
	//rather than injecting dll. Just allocate some memory and create a remote thread pointing at the first instruction.

	//normally the two arguments for present are 0,0, however its possible
	//some devs do some bizarre shit, or M$ updates the function parameters.
	//hence searching for up to 15 bytes * 2 (two max instruction sizes back) + 3 bytes to load the vtable into rax.

	//TODO: Add 32 bit option

	//how far back from the last instruction in sequence call qword ptr [rax+40h] to check?
	//it probably wont be more than 3 8 byte instructions at most, + 3 bytes to load vtable into rax. Realistically, it will be 16 bytes
	uint64_t maxSizeToCheck = 27;
	uint64_t baseSearch = (uint64_t)exeBase + 0x1000 + maxSizeToCheck;

	//the last place the call could be (again unlikely) is 3 bytes back from the end of the image (again not really, but I will add parsing of code sections later)
	uint64_t callInstructionSize = 3;

	uint64_t endSearch = (uint64_t)exeBase + exeImageSize - callInstructionSize;

#ifdef _RELEASE_TESTING
	outFileData << std::hex;

	outFileData << _T("\nBF4 Module Base: ") << (uint64_t)exeBase << _T('\n') << std::endl;
	outFileData << _T("BF4 Module Size: ") << exeImageSize << _T('\n') << std::endl;

#endif

	for (uint64_t i = baseSearch; i < endSearch; ++i)
	{
		//look for call qword ptr [rax+40h]
		if ((*(uint16_t*)i == 0x50FF) && ((*(uint8_t*)(i + 2)) == 0x40))
		{

			//scan backwards as far as we can, up to maxSizeToCheck (really only need to check while we are near start of .text section)
			for (uint64_t j = i - maxSizeToCheck; j < i - 2; ++j)
			{
				if (*(uint16_t*)j == 0x8B48 && (*(uint8_t*)(j + 2) == 0x00))
				{
					possiblePresentCalls[possiblePresentCallsCount][0] = j;
					possiblePresentCalls[possiblePresentCallsCount++][1] = i;
				}
			}

		}
	}

#ifdef _RELEASE_TESTING
	for (uint32_t i = 0; i < possiblePresentCallsCount; ++i)
	{
		outFileData << _T("mov rax, qword ptr [rax] is at: ") << possiblePresentCalls[i][0] << std::endl;
		outFileData << _T("call qword ptr [rax + 40h] is at: ") << possiblePresentCalls[i][1] << std::endl;
	}

	outFileData.close();

#endif



	return 0;
};