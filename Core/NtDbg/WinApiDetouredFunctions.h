#pragma once
#include "pch.h"
#include "WinApiFunctionPointers.h"
#include "NamedPipe.h"

namespace HookUtil
{
	namespace DetouredFunctions
	{
		int WINAPI MessageBoxA_Detour(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
		SOCKET WSAAPI accept_Detour(SOCKET s, sockaddr* addr, int* addrlen);
		BOOL WINAPI AdjustTokenPrivileges_Detour(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
		BOOL WINAPI AttachThreadInput_Detour(DWORD idAttach, DWORD idAttachTo, BOOL fAttach);
		BOOL WINAPI bind_Detour(SOCKET s, const sockaddr* addr, int namelen);
		BOOL WINAPI BitBlt_Detour(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
		HCERTSTORE WINAPI CertOpenSystemStoreA_Detour(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol);
		HCERTSTORE WINAPI CertOpenSystemStoreW_Detour(HCRYPTPROV_LEGACY hProv, LPCWSTR szSubsystemProtocol);
		BOOL WINAPI connect_Detour(_In_ SOCKET s, _In_ const struct sockaddr* name, _In_ int namelen);
		BOOL WINAPI ConnectNamedPipe_Detour(_In_ HANDLE hNamedPipe, _In_opt_ LPOVERLAPPED lpOverlapped);
		BOOL WINAPI ControlService_Detour(_In_ SC_HANDLE hService, _In_ DWORD dwControl, _Out_ LPSERVICE_STATUS lpServiceStatus);
		HANDLE WINAPI CreateFile_Detour(_In_ LPCTSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile);
		BOOL WINAPI CreateProcess_Detour(_In_opt_ LPCTSTR lpApplicationName, _Inout_opt_ LPTSTR lpCommandLine, _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCTSTR lpCurrentDirectory, _In_ LPSTARTUPINFO lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation);
		HANDLE WINAPI CreateRemoteThread_Detour(_In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId);
		SC_HANDLE WINAPI CreateService_Detour(_In_ SC_HANDLE hSCManager, _In_ LPCTSTR lpServiceName, _In_opt_ LPCTSTR lpDisplayName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwServiceType, _In_ DWORD dwStartType, _In_ DWORD dwErrorControl, _In_opt_ LPCTSTR lpBinaryPathName, _In_opt_ LPCTSTR lpLoadOrderGroup, _Out_opt_ LPDWORD lpdwTagId, _In_opt_ LPCTSTR lpDependencies, _In_opt_ LPCTSTR lpServiceStartName, _In_opt_ LPCTSTR lpPassword);
		HANDLE WINAPI CreateToolhelp32Snapshot_Detour(_In_ DWORD dwFlags, _In_ DWORD th32ProcessID);
		BOOL WINAPI CryptAcquireContext_Detour(_Out_ HCRYPTPROV* phProv, _In_ LPCTSTR pszContainer, _In_ LPCTSTR pszProvider, _In_ DWORD dwProvType, _In_ DWORD dwFlags);
		BOOL WINAPI DeviceIoControl_Detour(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode, _In_opt_ LPVOID lpInBuffer, _In_ DWORD nInBufferSize, _Out_opt_ LPVOID lpOutBuffer, _In_ DWORD nOutBufferSize, _Out_opt_ LPDWORD lpBytesReturned, _Inout_opt_ LPOVERLAPPED lpOverlapped);
		BOOL WINAPI EnumProcesses_Detour(_Out_ DWORD* lpidProcess, _In_ DWORD cb, _Out_ LPDWORD lpcbNeeded);
		BOOL WINAPI EnumProcessModules_Detour(_In_ HANDLE hProcess, _Out_ HMODULE* lphModule, _In_ DWORD cb, _Out_ LPDWORD lpcbNeeded);
		HANDLE WINAPI FindFirstFile_Detour(_In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATA lpFindFileData);
		BOOL WINAPI FindNextFile_Detour(_In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATA lpFindFileData);
		HRSRC WINAPI FindResource_Detour(_In_ HMODULE hModule, _In_ LPCWSTR lpName, _In_ LPCWSTR lpType);
		HWND WINAPI FindWindow_Detour(_In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName);
		BOOL WINAPI FtpPutFile_Detour(_In_ HINTERNET hConnect, _In_ LPCWSTR lpszLocalFile, _In_ LPCWSTR lpszNewRemoteFile, _In_ DWORD dwFlags, _In_ DWORD_PTR dwContext);
		DWORD WINAPI GetAdaptersInfo_Detour(_Out_ PIP_ADAPTER_INFO pAdapterInfo, _Inout_ PULONG pOutBufLen);
		SHORT WINAPI GetAsyncKeyState_Detour(_In_ int vKey);
		HDC WINAPI GetDC_Detour(_In_opt_ HWND hWnd);
		HWND WINAPI GetForegroundWindow_Detour();
		struct hostent* WSAAPI gethostbyname_Detour(_In_ const char* name);
		int WINAPI gethostname_Detour(_Out_ char* name, _In_ int namelen);
		SHORT WINAPI GetKeyState_Detour(_In_ int nVirtKey);
		DWORD WINAPI GetModuleFileName_Detour(_In_opt_ HMODULE hModule, _Out_ LPWSTR lpFilename, _In_ DWORD nSize);
		HMODULE WINAPI GetModuleHandle_Detour(_In_opt_ LPCWSTR lpModuleName);
		FARPROC WINAPI GetProcAddress_Detour(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
		VOID WINAPI GetStartupInfo_Detour(_Out_ LPSTARTUPINFO lpStartupInfo);
		LANGID WINAPI GetSystemDefaultLangID_Detour();
		DWORD WINAPI GetTempPath_Detour(_In_ DWORD nBufferLength, _Out_ LPWSTR lpBuffer);
		BOOL WINAPI GetThreadContext_Detour(_In_ HANDLE hThread, _Inout_ LPCONTEXT lpContext);
		UINT WINAPI GetWindowsDirectory_Detour(_Out_ LPWSTR lpBuffer, _In_ UINT uSize);
		ULONG WINAPI inet_addr_Detour(_In_ const char* cp);
		HINTERNET WINAPI InternetOpen_Detour(_In_ LPCWSTR lpszAgent, _In_ DWORD dwAccessType, _In_ LPCWSTR lpszProxy, _In_ LPCWSTR lpszProxyBypass, _In_ DWORD dwFlags);
		HINTERNET WINAPI InternetOpenUrl_Detour(_In_ HINTERNET hInternet, _In_ LPCWSTR lpszUrl, _In_ LPCWSTR lpszHeaders, _In_ DWORD dwHeadersLength, _In_ DWORD dwFlags, _In_ DWORD_PTR dwContext);
		BOOL WINAPI InternetReadFile_Detour(_In_ HINTERNET hFile, _Out_ LPVOID lpBuffer, _In_ DWORD dwNumberOfBytesToRead, _Out_ LPDWORD lpdwNumberOfBytesRead);
		BOOL WINAPI InternetWriteFile_Detour(_In_ HINTERNET hFile, _In_ LPCVOID lpBuffer, _In_ DWORD dwNumberOfBytesToWrite, _Out_ LPDWORD lpdwNumberOfBytesWritten);
		BOOL WINAPI IsUserAnAdmin_Detour();
		BOOL WINAPI IsWow64Process_Detour(_In_ HANDLE hProcess, _Out_ PBOOL Wow64Process);
		HGLOBAL WINAPI LoadResource_Detour(_In_opt_ HMODULE hModule, _In_ HRSRC hResInfo);
		NTSTATUS WINAPI LsaEnumerateLogonSessions_Detour(_Out_ PULONG LogonSessionCount, _Out_ PLUID* LogonSessionList);
		LPVOID WINAPI MapViewOfFile_Detour(_In_ HANDLE hFileMappingObject, _In_ DWORD dwDesiredAccess, _In_ DWORD dwFileOffsetHigh, _In_ DWORD dwFileOffsetLow, _In_ SIZE_T dwNumberOfBytesToMap);
		UINT WINAPI MapVirtualKey_Detour(_In_ UINT uCode, _In_ UINT uMapType);
		BOOL WINAPI Module32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPMODULEENTRY32 lpme);
		BOOL WINAPI Module32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPMODULEENTRY32 lpme);
		NET_API_STATUS WINAPI NetScheduleJobAdd_Detour(_In_ LPCWSTR Servername, _In_ LPBYTE Buffer, _Out_ LPDWORD JobId);
		NET_API_STATUS WINAPI NetShareEnum_Detour(_In_ LPWSTR servername, _In_ DWORD level, _Out_ LPBYTE* bufptr, _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_ LPDWORD resume_handle);
		HANDLE WINAPI OpenMutex_Detour(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ LPCWSTR lpName);
		HANDLE WINAPI OpenProcess_Detour(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwProcessId);
		VOID WINAPI OutputDebugString_Detour(_In_opt_ LPCWSTR lpOutputString);
		BOOL WINAPI PeekNamedPipe_Detour(_In_ HANDLE hNamedPipe, _Out_ LPVOID lpBuffer, _In_ DWORD nBufferSize, _Out_ LPDWORD lpBytesRead, _Out_ LPDWORD lpTotalBytesAvail, _Out_ LPDWORD lpBytesLeftThisMessage);
		BOOL WINAPI Process32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPPROCESSENTRY32 lppe);
		BOOL WINAPI Process32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe);
		DWORD WINAPI QueueUserAPC_Detour(_In_ PAPCFUNC pfnAPC, _In_ HANDLE hThread, _In_ ULONG_PTR dwData);
		BOOL WINAPI ReadProcessMemory_Detour(_In_ HANDLE hProcess, _In_ LPCVOID lpBaseAddress, _Out_ LPVOID lpBuffer, _In_ SIZE_T nSize, _Out_ SIZE_T* lpNumberOfBytesRead);
		int WINAPI recv_Detour(_In_ SOCKET s, _Out_ char* buf, _In_ int len, _In_ int flags);
		BOOL WINAPI RegisterHotKey_Detour(_In_opt_ HWND hWnd, _In_ int id, _In_ UINT fsModifiers, _In_ UINT vk);
		LONG WINAPI RegOpenKey_Detour(_In_ HKEY hKey, _In_ LPCWSTR lpSubKey, _Out_ PHKEY phkResult);
		DWORD WINAPI ResumeThread_Detour(_In_ HANDLE hThread);
		int WINAPI send_Detour(_In_ SOCKET s, _In_ const char* buf, _In_ int len, _In_ int flags);
		BOOL WINAPI SetFileTime_Detour(_In_ HANDLE hFile, _In_opt_ const FILETIME* lpCreationTime, _In_opt_ const FILETIME* lpLastAccessTime, _In_opt_ const FILETIME* lpLastWriteTime);
		BOOL WINAPI SetThreadContext_Detour(_In_ HANDLE hThread, _In_ const CONTEXT* lpContext);
		HHOOK WINAPI SetWindowsHookEx_Detour(_In_ int idHook, _In_ HOOKPROC lpfn, _In_ HINSTANCE hMod, _In_ DWORD dwThreadId);
		HINSTANCE WINAPI ShellExecute_Detour(_In_opt_ HWND hwnd, _In_opt_ LPCTSTR lpOperation, _In_ LPCTSTR lpFile, _In_opt_ LPCTSTR lpParameters, _In_opt_ LPCTSTR lpDirectory, _In_ INT nShowCmd);
		BOOL WINAPI StartServiceCtrlDispatcher_Detour(_In_ const SERVICE_TABLE_ENTRY* lpServiceTable);
		DWORD WINAPI SuspendThread_Detour(_In_ HANDLE hThread);
		int WINAPI system_Detour(_In_opt_ const char* command);
		BOOL WINAPI Thread32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPTHREADENTRY32 lpte);
		BOOL WINAPI Thread32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPTHREADENTRY32 lpte);
		BOOL WINAPI Toolhelp32ReadProcessMemory_Detour(_In_ DWORD th32ProcessID, _In_ LPCVOID lpBaseAddress, _Out_ LPVOID lpBuffer, _In_ SIZE_T cbRead, _Out_ SIZE_T* lpNumberOfBytesRead);
		HRESULT WINAPI URLDownloadToFile_Detour(_In_opt_ LPUNKNOWN pCaller, _In_ LPCWSTR szURL, _In_ LPCWSTR szFileName, _In_ DWORD dwReserved, _In_opt_ LPBINDSTATUSCALLBACK lpfnCB);
		LPVOID WINAPI VirtualAllocEx_Detour(_In_ HANDLE hProcess, _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
		BOOL WINAPI VirtualProtectEx_Detour(_In_ HANDLE hProcess, _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
		int WINAPI WideCharToMultiByte_Detour(_In_ UINT CodePage, _In_ DWORD dwFlags, _In_ LPCWSTR lpWideCharStr, _In_ int cchWideChar, _Out_opt_ LPSTR lpMultiByteStr, _In_ int cbMultiByte, _In_opt_ LPCSTR lpDefaultChar, _Out_opt_ LPBOOL lpUsedDefaultChar);
		UINT WINAPI WinExec_Detour(_In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow);
		BOOL WINAPI WriteProcessMemory_Detour(_In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, _In_ LPCVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesWritten);
		int WINAPI WSAStartup_Detour(_In_ WORD wVersionRequested, _Out_ LPWSADATA lpWSAData);
	}
}

extern Pipe* pPipe;