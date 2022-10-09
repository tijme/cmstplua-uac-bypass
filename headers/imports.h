#pragma once

#ifdef BOF
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	#define CreateFileW KERNEL32$CreateFileW
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	#define WriteFile KERNEL32$WriteFile
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeleteFileW(LPCWSTR);
	#define DeleteFileW KERNEL32$DeleteFileW
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
	#define CloseHandle KERNEL32$CloseHandle
	DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
	#define LoadLibraryExW KERNEL32$LoadLibraryExW
	DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
	#define GetLastError KERNEL32$GetLastError
	DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
	#define GetProcAddress KERNEL32$GetProcAddress
	DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
	#define GlobalAlloc KERNEL32$GlobalAlloc
	DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
	#define GlobalFree KERNEL32$GlobalFree
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
	#define DeviceIoControl KERNEL32$DeviceIoControl
	DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId();
	#define GetCurrentProcessId KERNEL32$GetCurrentProcessId
	DECLSPEC_IMPORT UINT WINAPI KERNEL32$GetWindowsDirectoryW(LPWSTR, UINT);
	#define GetWindowsDirectoryW KERNEL32$GetWindowsDirectoryW
	DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
	#define GetModuleFileNameW KERNEL32$GetModuleFileNameW
	DECLSPEC_IMPORT DWORD WINAPI KERNEL32$FormatMessageA(DWORD, LPCVOID, DWORD, DWORD, LPTSTR, DWORD, va_list*);
	#define FormatMessageA KERNEL32$FormatMessageA
	DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
	#define GetModuleHandleW KERNEL32$GetModuleHandleW

	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
	#define StartServiceW ADVAPI32$StartServiceW
	DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
	#define CreateServiceW ADVAPI32$CreateServiceW
	DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
	#define OpenSCManagerW ADVAPI32$OpenSCManagerW
	DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
	#define OpenServiceW ADVAPI32$OpenServiceW
	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
	#define ControlService ADVAPI32$ControlService
	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE);
	#define DeleteService ADVAPI32$DeleteService
	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
	#define CloseServiceHandle ADVAPI32$CloseServiceHandle

	DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR, LPIID);
	#define IIDFromString OLE32$IIDFromString
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitialize(LPVOID);
	#define CoInitialize OLE32$CoInitialize
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoGetObject(LPCWSTR, BIND_OPTS*, REFIID, void**);
	#define CoGetObject OLE32$CoGetObject

	DECLSPEC_IMPORT BOOL WINAPI NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	#define NtQuerySystemInformation NTDLL$NtQuerySystemInformation

	WINBASEAPI  int         __cdecl     MSVCRT$fclose (FILE *fStream);
	#define fclose MSVCRT$fclose
	WINBASEAPI  errno_t     __cdecl     MSVCRT$fopen_s (FILE **fStream, const char* _fName, const char *_Mode);
	#define fopen_s MSVCRT$fopen_s
	WINBASEAPI  int         __cdecl     MSVCRT$fseek (FILE *fStream, long _Offset, int _Origin);
	#define fseek MSVCRT$fseek
	WINBASEAPI  long        __cdecl     MSVCRT$ftell (FILE *fStream);
	#define ftell MSVCRT$ftell
	WINBASEAPI  int         __cdecl     MSVCRT$getc (FILE *fStream);
	#define getc MSVCRT$getc
	WINBASEAPI  long        __cdecl     MSVCRT$rewind (FILE *fStream);
	#define rewind MSVCRT$rewind
	WINBASEAPI  char*       __cdecl     MSVCRT$strstr (char* _String, const char* _SubString);
	#define strstr MSVCRT$strstr
	WINBASEAPI  void*       __cdecl     MSVCRT$memset (void* _Dst, int _Val, size_t Size);
	#define memset MSVCRT$memset
	WINBASEAPI  errno_t     __cdecl     MSVCRT$wcscat_s (wchar_t*, size_t, const wchar_t*);
	#define wcscat_s MSVCRT$wcscat_s
	WINBASEAPI  errno_t     __cdecl     MSVCRT$wcscpy_s (wchar_t*, rsize_t, const wchar_t*);
	#define wcscpy_s MSVCRT$wcscpy_s
	WINBASEAPI  void*       __cdecl     MSVCRT$malloc (size_t);
	#define malloc MSVCRT$malloc
	WINBASEAPI  void*       __cdecl     MSVCRT$calloc (size_t, size_t);
	#define calloc MSVCRT$calloc
	WINBASEAPI  int         __cdecl     MSVCRT$_wcsicmp (const wchar_t*, const wchar_t*);
	#define _wcsicmp MSVCRT$_wcsicmp
	WINBASEAPI  size_t      __cdecl     MSVCRT$wcslen (const wchar_t*);
	#define wcslen MSVCRT$wcslen
	WINBASEAPI  void*       __cdecl     MSVCRT$memcpy (void*, const void*, size_t);
	#define memcpy MSVCRT$memcpy
	WINBASEAPI  size_t      __cdecl     MSVCRT$strlen (const char*);
	#define strlen MSVCRT$strlen
	WINBASEAPI  size_t      __cdecl     MSVCRT$mbstowcs (wchar_t*, const char*, size_t);
	#define mbstowcs MSVCRT$mbstowcs
#endif