#include "HookHelpers.h"

//Returns a pointer to the process environment block

//note: if you aren't using a compiler which supports x64 inline asm, use the ms intrinsics, or compile an asm file separetely (you can do this with property fiddling in vs) as a dynamic or static library

PEB * __CALLCONV GetPEB()
{

	PEB *pebPtr = NULL;

#ifdef _AMD64_
		_asm
		{
			push r9;
			push 60h;
			pop r9;
			mov r9, qword ptr gs : [r9];
			mov pebPtr, r9;
			pop r9;
		};

#endif

#ifdef _X86_
		_asm
		{
			push eax;
			push 30h;
			pop eax;
			mov eax, dword ptr fs : [eax];
			mov pebPtr, eax;
			pop eax;
		}
#endif

	return pebPtr;

}



//gets process name, returns number of wide characters in proc name, not counting null terminator
//len = number of chars in t he buffer you pass in
int __CALLCONV GetProcessName(const PEB * const targetPEB, TCHAR * const buf, uint32_t len)
{

	uint32_t ind = 0, lastDash =0;

	const PRTL_USER_PROCESS_PARAMETERS procParams = targetPEB->ProcessParameters;

	if (targetPEB == NULL || buf == NULL)
		return -1;

	if (procParams == NULL || (procParams->ImagePathName.Buffer == NULL))
		return -2;

	if (procParams->ImagePathName.MaximumLength > len)
		return -3;

	if (procParams->ImagePathName.MaximumLength == 0)
		return 0;

	for (; ind < procParams->ImagePathName.MaximumLength; ++ind)
	{
		if (procParams->ImagePathName.Buffer[ind] == (wchar_t)'\\')
			lastDash = ind;
	}

	ind = 0;

	for (++lastDash; lastDash < procParams->ImagePathName.MaximumLength; ++lastDash, ++ind)
	{
		buf[ind] = (TCHAR)procParams->ImagePathName.Buffer[lastDash];
	}
	
	//null terminate
	buf[ind] = 0;

	return ind;

};