#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <Winternl.h>
#include <tlhelp32.h>
//#include <Ntstatus.h>

#define PROCESS_ERROR_RETURN(Condition) \
    if (!(Condition)) {                 \
        return 0;                       \
    }

#define PROCESS_ERROR_LOG_RETURN(Condition, LOG, ...)   \
    if (!(Condition)) {                                 \
        printf(LOG, __VA_ARGS__);                       \
        return 0;                                       \
    }

#define PROCESS_ERROR_CONTINUE(Condition)   \
    if (!Condition) {                       \
        continue;                           \
    }

#define SAFE_FREE(p)    \
    if ((p)) {          \
        free((p));      \
        (p) = NULL;     \
    }

#define SAFE_CLOSE_HANDLE(h)    \
    if ((h)) {                  \
        CloseHandle((h));       \
        (h) = NULL;             \
    }

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

BOOL GetProcessIDByName(LPTSTR szProcessName, LPDWORD lpPID)
{
    STARTUPINFO st;
    PROCESSENTRY32 ps;
    HANDLE hSnapshot;
    size_t uCount = 0;

    ZeroMemory(&st, sizeof(STARTUPINFO));
    ZeroMemory(&ps, sizeof(PROCESSENTRY32));
    st.cb = sizeof(STARTUPINFO);
    ps.dwSize = sizeof(PROCESSENTRY32);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESS_ERROR_RETURN(hSnapshot != INVALID_HANDLE_VALUE);
    PROCESS_ERROR_RETURN(Process32First(hSnapshot, &ps));

    do
    {
        if (lstrcmpi(ps.szExeFile, szProcessName) == 0)
        {
            *lpPID++ = ps.th32ProcessID;
            uCount++;
        }
    } while (Process32Next(hSnapshot, &ps));

    SAFE_CLOSE_HANDLE(hSnapshot);
    return uCount;
}

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS(NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

int wmain(int argc, WCHAR *argv[])
{
    _NtQuerySystemInformation	NtQuerySystemInformation	= GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    _NtDuplicateObject			NtDuplicateObject			= GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
    _NtQueryObject				NtQueryObject				= GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

    NTSTATUS nStatus;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo;
    ULONG uHandleInfoSize = 0x10000;
    ULONG uArrPid[MAX_PATH];
    LPTSTR wsMutexName = NULL;
    HANDLE hProcess;
    size_t uPidCount = 0;
    ULONG i = 0;
    size_t j = 0;
    int k = 0;

    PROCESS_ERROR_LOG_RETURN(argc >= 2, "MutexName will not be NULL!\n");

    uPidCount = GetProcessIDByName(argv[1], uArrPid);

    pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(uHandleInfoSize);

    while ((nStatus = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, uHandleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, uHandleInfoSize *= 2);

    PROCESS_ERROR_LOG_RETURN(NT_SUCCESS(nStatus), "NtQuerySystemInformation failed!\n");

    for (i = 0; i < pHandleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE hSystem = pHandleInfo->Handles[i];

        for (j = 0; j < uPidCount; j++)
        {
            HANDLE dupHandle = NULL;
            HANDLE dupMutantHandle = NULL;
            BYTE pbyTypeInfo[0x1000];
            BYTE* pbyNameInfo = malloc(0x1000);
            POBJECT_TYPE_INFORMATION pNameInfo = NULL;
            POBJECT_TYPE_INFORMATION pNameType = NULL;
            ULONG uInfoBuffLen;

            ULONG uPid = uArrPid[j];

            PROCESS_ERROR_LOG_RETURN(hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, uPid), "Could not open PID %d! (Don't try to open a system process.)\n", uPid);

            PROCESS_ERROR_CONTINUE(hSystem.ProcessId == uPid);
            PROCESS_ERROR_CONTINUE(NT_SUCCESS(NtDuplicateObject(hProcess, (HANDLE)hSystem.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)));

            if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, pbyTypeInfo, 0x1000, NULL)))
            {
                printf("[%#x] Error!\n", hSystem.Handle);
                SAFE_CLOSE_HANDLE(dupHandle);
                continue;
            }

            if (hSystem.GrantedAccess == 0x0012019f)
            {
                SAFE_CLOSE_HANDLE(dupHandle);
                continue;
            }

            if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, pbyNameInfo, 0x1000, &uInfoBuffLen)))
            {
                pbyNameInfo = realloc(pbyNameInfo, uInfoBuffLen);
                if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, pbyNameInfo, uInfoBuffLen, NULL)))
                {
                    SAFE_FREE(pbyNameInfo);
                    SAFE_CLOSE_HANDLE(dupHandle);
                    continue;
                }
            }

            pNameType = (POBJECT_TYPE_INFORMATION)pbyTypeInfo;
            pNameInfo = (POBJECT_TYPE_INFORMATION)pbyNameInfo;

            //printf("%wZ   %wZ\n", pNameType, pNameInfo);

            if (pNameType->Name.Length > 0 && !wcscmp((wchar_t *)pNameType->Name.Buffer, L"Mutant"))
            {
                BOOL bMutantMatach = argc < 3;
                for (k = 2; !bMutantMatach && pNameInfo->Name.Length > 0 && k < argc; k++)
                {
                    bMutantMatach = wcsstr((wchar_t *)pNameInfo->Name.Buffer, argv[k]) != NULL;
                }

                if (bMutantMatach)
                {
                    if (NT_SUCCESS(NtDuplicateObject(hProcess, (HANDLE)hSystem.Handle, GetCurrentProcess(), &dupMutantHandle, 0, 0, 0x1)))
                    {
                        printf("[%#x] %.*S: %.*S Closed!\n", hSystem.Handle, pNameType->Name.Length / 2,
                            pNameType->Name.Buffer, pNameInfo->Name.Length / 2, pNameInfo->Name.Buffer);

                        SAFE_CLOSE_HANDLE(dupMutantHandle);
                    }
                }
            }

            SAFE_FREE(pbyNameInfo);
            SAFE_CLOSE_HANDLE(dupHandle);
            SAFE_CLOSE_HANDLE(hProcess);
        }
    }

    SAFE_FREE(pHandleInfo);
    system("pause");

    return 0;
}
