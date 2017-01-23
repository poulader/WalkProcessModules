#pragma once

#include <Windows.h>
#include <assert.h>
#include <vector>
#include <map>
extern "C"
{
	#include "HookHelpers.h"
}



typedef uint32_t(WINAPI * pTestHookFunction)();

typedef enum E_HOOK_METHOD : uint32_t
{
	HM_TRAMPOLINE = 0,
	HM_VEH = 1,
	HM_HWBP = 2,
	HM_THREADCONTEXT = 3
} E_HOOK_METHOD;

typedef struct _HOOK_SEGMENT
{
	uint32_t mHookSegID;
	size_t	 mHookSegStartAddress;
	uint32_t mHookSegLength;
	std::vector<uint8_t> mPreviousBytes;
	std::vector<uint8_t> mHookBytes;
} HOOK_SEGMENT, *pHOOK_SEGMENT;

typedef struct _HOOK_MASTER
{
	uint32_t mHookID;
	uint32_t mHookSegmentCount;
	E_HOOK_METHOD mHookMethod;
	std::vector<HOOK_SEGMENT> mHooks;
} HOOK_MASTER, *pHOOK_MASTER;

class GenericHookFactory
{
public:
	GenericHookFactory();
	GenericHookFactory(const GenericHookFactory&);
	virtual ~GenericHookFactory();
	virtual GenericHookFactory& operator=(const GenericHookFactory& rhs);


	virtual uint32_t HookAddressAt(size_t targetAddr, pTestHookFunction);

private:

	std::map<uint32_t, HOOK_MASTER> mHookMap;
};



class PatternScanner
{
	PatternScanner();
	virtual ~PatternScanner();
	int32_t ScanForPattern();
	int32_t SetScanParameters(const uint8_t  *pPatternBytes, uint32_t length, size_t startAddr, size_t endAddr);

private:
	std::vector<uint8_t> mPatternToFind;
	std::vector<size_t> mPatternFoundAddresses;
	size_t  mPatternScanStart;
	size_t  mPatternScanEnd;
	bool	mIsPatternFound;
	bool	mAreSearchParamsValid;
};

uint32_t  TestHookFunction();