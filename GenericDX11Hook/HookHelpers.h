#pragma once

#include <Windows.h>
#include <winternl.h>
#include <winnt.h>

/* Integer types */

/* Exact-width integer types */

typedef signed char             int8_t;
typedef signed short            int16_t;
typedef signed int              int32_t;
typedef signed long long int    int64_t;

typedef unsigned char           uint8_t;
typedef unsigned short          uint16_t;
typedef unsigned int            uint32_t;
typedef unsigned long long int  uint64_t;

#ifdef _AMD64_
#define __CALLCONV __fastcall
#endif
#ifdef _X86_
#define __CALLCONV __stdcall
#endif


/*

64 BIT

+0x000 InLoadOrderLinks : struct _LIST_ENTRY, 2 elements, 0x10 bytes
+0x010 InMemoryOrderLinks : struct _LIST_ENTRY, 2 elements, 0x10 bytes
+0x020 InInitializationOrderLinks : struct _LIST_ENTRY, 2 elements, 0x10 bytes
+0x030 DllBase          : Ptr64 to Void
+0x038 EntryPoint       : Ptr64 to Void
+0x040 SizeOfImage      : Uint4B
+0x048 FullDllName      : struct _UNICODE_STRING, 3 elements, 0x10 bytes
+0x058 BaseDllName      : struct _UNICODE_STRING, 3 elements, 0x10 bytes
+0x068 Flags            : Uint4B
+0x06c LoadCount        : Uint2B
+0x06e TlsIndex         : Uint2B
+0x070 HashLinks        : struct _LIST_ENTRY, 2 elements, 0x10 bytes
+0x070 SectionPointer   : Ptr64 to Void
+0x078 CheckSum         : Uint4B
+0x080 TimeDateStamp    : Uint4B
+0x080 LoadedImports    : Ptr64 to Void
+0x088 EntryPointActivationContext : Ptr64 to struct _ACTIVATION_CONTEXT, 0 elements, 0x0 bytes
+0x090 PatchInformation : Ptr64 to Void
+0x098 ForwarderLinks   : struct _LIST_ENTRY, 2 elements, 0x10 bytes
+0x0a8 ServiceTagLinks  : struct _LIST_ENTRY, 2 elements, 0x10 bytes
+0x0b8 StaticLinks      : struct _LIST_ENTRY, 2 elements, 0x10 bytes
+0x0c8 ContextInformation : Ptr64 to Void
+0x0d0 OriginalBase     : Uint8B
+0x0d8 LoadTime         : union _LARGE_INTEGER, 4 elements, 0x8 bytes

*/

/*

32 BIT

+0x000 InLoadOrderLinks : struct _LIST_ENTRY, 2 elements, 0x8 bytes
+0x008 InMemoryOrderLinks : struct _LIST_ENTRY, 2 elements, 0x8 bytes
+0x010 InInitializationOrderLinks : struct _LIST_ENTRY, 2 elements, 0x8 bytes
+0x018 DllBase          : Ptr32 to Void
+0x01c EntryPoint       : Ptr32 to Void
+0x020 SizeOfImage      : Uint4B
+0x024 FullDllName      : struct _UNICODE_STRING, 3 elements, 0x8 bytes
+0x02c BaseDllName      : struct _UNICODE_STRING, 3 elements, 0x8 bytes
+0x034 Flags            : Uint4B
+0x038 LoadCount        : Uint2B
+0x03a TlsIndex         : Uint2B
+0x03c HashLinks        : struct _LIST_ENTRY, 2 elements, 0x8 bytes
+0x03c SectionPointer   : Ptr32 to Void
+0x040 CheckSum         : Uint4B
+0x044 TimeDateStamp    : Uint4B
+0x044 LoadedImports    : Ptr32 to Void
+0x048 EntryPointActivationContext : Ptr32 to struct _ACTIVATION_CONTEXT, 0 elements, 0x0 bytes
+0x04c PatchInformation : Ptr32 to Void
+0x050 ForwarderLinks   : struct _LIST_ENTRY, 2 elements, 0x8 bytes
+0x058 ServiceTagLinks  : struct _LIST_ENTRY, 2 elements, 0x8 bytes
+0x060 StaticLinks      : struct _LIST_ENTRY, 2 elements, 0x8 bytes
+0x068 ContextInformation : Ptr32 to Void
+0x06c OriginalBase     : Uint4B
+0x070 LoadTime         : union _LARGE_INTEGER, 4 elements, 0x8 bytes


*/

//should automatically fit both 64 and 32 bit builds
//works for 64 bit, need to test for 32 bit

#ifdef _AMD64_
#pragma pack(push, r1, 8)
#endif
#ifdef _X86_
#pragma pack(push, r1, 4)
#endif

//credits: learn_more

/*

template <class T>
int pvfIndex(T func)
{
union {
T pfn;
unsigned char* pb;
};
pfn = func;
if( !pb ) return -1;
int pboff = -1;
if( pb[0] == 0x8b && pb[1] == 0x01 ) {	//mov eax, [ecx]
pboff = 2;
} else if( pb[0] == 0x8b && pb[1] == 0x44 && pb[2] == 0x24 && pb[3] == 0x04 &&		//mov eax, [esp+arg0]
pb[4] == 0x8b && pb[5] == 0x00 ) {										//mov eax, [eax]
pboff = 6;
}

if( pboff > 0 ) {
if( pb[pboff] == 0xff ) {
switch( pb[pboff+1] ) {
case 0x20:	//jmp dword ptr [eax]
return 0;
case 0x60:	//jmp dword ptr [eax+0xNN]
return (((int)pb[pboff+2])&0xff)/4;
case 0xa0:	//jmp dword ptr [eax+0xNNN]
return (*(unsigned int*)(pb+(pboff+2)))/4;
default:
break;
}
}
}
return -1;
}

usage:
Code:

pvfIndex(&IClass::pureVirtualFunc0)



*/

typedef struct E_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;

	PVOID DllBase;
	PVOID EntryPoint;

	uint32_t SizeOfImage;

	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

	uint32_t Flags;
	uint16_t LoadCount;
	uint16_t TlsIndex;

	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			uint32_t CheckSum;
		};
	};

	union
	{
		uint32_t TimeDateStamp;
		PVOID LoadedImports;
	};

	PVOID EntryPointActivationContext;
	PVOID PatchInformation;

	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;

	PVOID ContextInformation;

#ifdef _AMD64_
	uint64_t OriginalBase;
#endif
#ifdef _X86_
	uint32_t OriginalBase;
#endif

	LARGE_INTEGER	LoadTime;

} E_LDR_DATA_TABLE_ENTRY, *PE_LDR_DATA_TABLE_ENTRY;


/*
typedef struct _PEB_LDR_DATA {
BYTE Reserved1[8];
PVOID Reserved2[3];
LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
*/

typedef struct E_PEB_LDR_DATA
{

	uint32_t Length;
	uint8_t Initialized;

#ifdef _AMD64_
	PVOID64 SsHandle;
#endif
#ifdef _X86_
	PVOID SsHandle;
#endif

	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;

#ifdef _AMD64_
	PVOID64 EntryInProgress;
#endif
#ifdef _X86_
	PVOID EntryInProgress;
#endif

	uint8_t ShutdownInProgress;

#ifdef _AMD64_
	PVOID64 ShutdownThreadId;
#endif
#ifdef _X86_
	PVOID ShutdownThreadId;
#endif


} E_PEB_LDR_DATA, *PE_PEB_LDR_DATA;

#pragma pack(pop, r1)


//helper functions

//returns pointer to PEB
PEB * __CALLCONV GetPEB();

//returns process name
int __CALLCONV GetProcessName(const PEB * const targetPEB, TCHAR * const buf, uint32_t len);

