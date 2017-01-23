#include "GenericHook.h"
#include <Windows.h>
#include <assert.h>
#include <vector>
#include <map>
extern "C"
{
	#include "HookHelpers.h"
}

GenericHookFactory::GenericHookFactory()
{

}

GenericHookFactory::GenericHookFactory(const GenericHookFactory& rhs)
{

}

GenericHookFactory::~GenericHookFactory()
{

}

uint32_t GenericHookFactory::HookAddressAt(size_t targetAddr, pTestHookFunction nFunction)
{

	return 0;
}

GenericHookFactory& GenericHookFactory::operator=(const GenericHookFactory& rhs)
{

	return *this;
}


PatternScanner::PatternScanner()
	: mPatternScanStart(0), mPatternScanEnd(0), mIsPatternFound(false), mAreSearchParamsValid(false)
{

}

PatternScanner::~PatternScanner()
{

}

int32_t PatternScanner::SetScanParameters(const uint8_t  *pPatternBytes, uint32_t length, size_t startAddr, size_t endAddr)
{
	mIsPatternFound = false;
	mAreSearchParamsValid = false;
	mPatternToFind.clear();
	mPatternFoundAddresses.clear();

	if (!pPatternBytes)
		return 1;
	else if (length == 0)
		return -2;
	else if (startAddr == endAddr && length != 1)
		return -3;

	
	//Make sure valid addresses, really we need to figure out which one is lower, divide the range into page-length sequences of addresses, and check them all in order.
	//TODO - Do that later

	MEMORY_BASIC_INFORMATION mBasicInfoStart, mBasicInfoEnd;
	ZeroMemory(&mBasicInfoStart, sizeof(MEMORY_BASIC_INFORMATION));

	SIZE_T res = VirtualQuery((LPCVOID)startAddr, &mBasicInfoStart, sizeof(MEMORY_BASIC_INFORMATION));

	if (res != S_OK)
		return -4;

	ZeroMemory(&mBasicInfoEnd, sizeof(MEMORY_BASIC_INFORMATION));

	res = VirtualQuery((LPCVOID)endAddr, &mBasicInfoEnd, sizeof(MEMORY_BASIC_INFORMATION));

	if (res != S_OK)
		return -5;

	for (UINT i = 0; i < length; ++i)
	{
		mPatternToFind.push_back(*(pPatternBytes+ i));
	}

	mPatternScanStart = startAddr;
	mPatternScanEnd = endAddr;
	mAreSearchParamsValid = true;

	return 0;
}

int32_t PatternScanner::ScanForPattern()
{
	if (!mAreSearchParamsValid)
		return -1;

	//I want a way to include wildcards in the pattern
	
	return 0;
}




uint32_t	TestHookFunction()
{
	_CrtDbgBreak();
	return 0;
}