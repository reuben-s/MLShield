#include "pch.h"
#include "HookManager.h"

int WINAPI MessageBoxA_Detour(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    pPipe->SendMessage(LP_TEXT_STRING("MessageBoxA Called"));
    return pMessageBoxA(hWnd, lpText, lpCaption, uType);
}

SOCKET WSAAPI accept_Detour(SOCKET s, sockaddr* addr, int* addrlen)
{
    pPipe->SendMessage(LP_TEXT_STRING("accept Called"));
    return pAccept(s, addr, addrlen);
}

BOOL WINAPI AdjustTokenPrivileges_Detour(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
{
    pPipe->SendMessage(LP_TEXT_STRING("AdjustTokenPrivileges Called"));
    return pAdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}

BOOL WINAPI AttachThreadInput_Detour(DWORD idAttach, DWORD idAttachTo, BOOL fAttach)
{
    pPipe->SendMessage(LP_TEXT_STRING("AttachThreadInput Called"));
    return pAttachThreadInput(idAttach, idAttachTo, fAttach);
}

int WSAAPI bind_Detour(SOCKET s, const sockaddr* addr, int namelen)
{
    pPipe->SendMessage(LP_TEXT_STRING("bind Called"));
    return pBind(s, addr, namelen);
}

BOOL WINAPI BitBlt_Detour(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop)
{
    pPipe->SendMessage(LP_TEXT_STRING("BitBlt Called"));
    return pBitBlt(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
}

HCERTSTORE WINAPI CertOpenSystemStoreA_Detour(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol)
{
    pPipe->SendMessage(LP_TEXT_STRING("CertOpenSystemStoreA Called"));
    return pCertOpenSystemStoreA(hProv, szSubsystemProtocol);
}

HCERTSTORE WINAPI CertOpenSystemStoreW_Detour(HCRYPTPROV_LEGACY hProv, LPCWSTR szSubsystemProtocol)
{
    pPipe->SendMessage(LP_TEXT_STRING("CertOpenSystemStoreW Called"));
    return pCertOpenSystemStoreW(hProv, szSubsystemProtocol);
}

BOOL WINAPI connect_Detour(_In_ SOCKET s, _In_ const struct sockaddr* name, _In_ int namelen)
{
    pPipe->SendMessage(LP_TEXT_STRING("connect Called"));
    return pConnect(s, name, namelen);
}

BOOL WINAPI ConnectNamedPipe_Detour(_In_ HANDLE hNamedPipe, _In_opt_ LPOVERLAPPED lpOverlapped)
{
    pPipe->SendMessage(LP_TEXT_STRING("ConnectNamedPipe Called"));
    return pConnectNamedPipe(hNamedPipe, lpOverlapped);
}

BOOL WINAPI ControlService_Detour(_In_ SC_HANDLE hService, _In_ DWORD dwControl, _Out_ LPSERVICE_STATUS lpServiceStatus)
{
    pPipe->SendMessage(LP_TEXT_STRING("ControlService Called"));
    return pControlService(hService, dwControl, lpServiceStatus);
}

HANDLE WINAPI CreateFileA_Detour(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    pPipe->SendMessage(LP_TEXT_STRING("CreateFileA Called"));
    return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI CreateFileW_Detour(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    pPipe->SendMessage(LP_TEXT_STRING("CreateFileW Called"));
    return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI CreateProcess_Detour(_In_opt_ LPCTSTR lpApplicationName, _Inout_opt_ LPTSTR lpCommandLine, _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCTSTR lpCurrentDirectory, _In_ LPSTARTUPINFO lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
    pPipe->SendMessage(LP_TEXT_STRING("CreateProcess Called"));
    return pCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

HANDLE WINAPI CreateRemoteThread_Detour(_In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId)
{
    pPipe->SendMessage(LP_TEXT_STRING("CreateRemoteThread Called"));
    return pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

SC_HANDLE WINAPI CreateService_Detour(_In_ SC_HANDLE hSCManager, _In_ LPCTSTR lpServiceName, _In_opt_ LPCTSTR lpDisplayName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwServiceType, _In_ DWORD dwStartType, _In_ DWORD dwErrorControl, _In_opt_ LPCTSTR lpBinaryPathName, _In_opt_ LPCTSTR lpLoadOrderGroup, _Out_opt_ LPDWORD lpdwTagId, _In_opt_ LPCTSTR lpDependencies, _In_opt_ LPCTSTR lpServiceStartName, _In_opt_ LPCTSTR lpPassword)
{
    pPipe->SendMessage(LP_TEXT_STRING("CreateService Called"));
    return pCreateService(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
}

HANDLE WINAPI CreateToolhelp32Snapshot_Detour(_In_ DWORD dwFlags, _In_ DWORD th32ProcessID)
{
    pPipe->SendMessage(LP_TEXT_STRING("CreateToolhelp32Snapshot Called"));
    return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

BOOL WINAPI CryptAcquireContext_Detour(_Out_ HCRYPTPROV* phProv, _In_ LPCTSTR pszContainer, _In_ LPCTSTR pszProvider, _In_ DWORD dwProvType, _In_ DWORD dwFlags)
{
    pPipe->SendMessage(LP_TEXT_STRING("CryptAcquireContext Called"));
    return pCryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI DeviceIoControl_Detour(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode, _In_opt_ LPVOID lpInBuffer, _In_ DWORD nInBufferSize, _Out_opt_ LPVOID lpOutBuffer, _In_ DWORD nOutBufferSize, _Out_opt_ LPDWORD lpBytesReturned, _Inout_opt_ LPOVERLAPPED lpOverlapped)
{
    pPipe->SendMessage(LP_TEXT_STRING("DeviceIoControl Called"));
    return pDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}

BOOL WINAPI EnumProcesses_Detour(_Out_ DWORD* lpidProcess, _In_ DWORD cb, _Out_ LPDWORD lpcbNeeded)
{
    pPipe->SendMessage(LP_TEXT_STRING("EnumProcesses Called"));
    return pEnumProcesses(lpidProcess, cb, lpcbNeeded);
}

BOOL WINAPI EnumProcessModules_Detour(_In_ HANDLE hProcess, _Out_ HMODULE* lphModule, _In_ DWORD cb, _Out_ LPDWORD lpcbNeeded)
{
    pPipe->SendMessage(LP_TEXT_STRING("EnumProcessModules Called"));
    return pEnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
}

HANDLE WINAPI FindFirstFile_Detour(_In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATA lpFindFileData)
{
    pPipe->SendMessage(LP_TEXT_STRING("FindFirstFile Called"));
    return pFindFirstFile(lpFileName, lpFindFileData);
}

BOOL WINAPI FindNextFile_Detour(_In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATA lpFindFileData)
{
    pPipe->SendMessage(LP_TEXT_STRING("FindNextFile Called"));
    return pFindNextFile(hFindFile, lpFindFileData);
}

HRSRC WINAPI FindResource_Detour(_In_ HMODULE hModule, _In_ LPCWSTR lpName, _In_ LPCWSTR lpType)
{
    pPipe->SendMessage(LP_TEXT_STRING("FindResource Called"));
    return pFindResource(hModule, lpName, lpType);
}

HWND WINAPI FindWindow_Detour(_In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName)
{
    pPipe->SendMessage(LP_TEXT_STRING("FindWindow Called"));
    return pFindWindow(lpClassName, lpWindowName);
}

BOOL WINAPI FtpPutFile_Detour(_In_ HINTERNET hConnect, _In_ LPCWSTR lpszLocalFile, _In_ LPCWSTR lpszNewRemoteFile, _In_ DWORD dwFlags, _In_ DWORD_PTR dwContext)
{
    pPipe->SendMessage(LP_TEXT_STRING("FtpPutFile Called"));
    return pFtpPutFile(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
}

DWORD WINAPI GetAdaptersInfo_Detour(_Out_ PIP_ADAPTER_INFO pAdapterInfo, _Inout_ PULONG pOutBufLen)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetAdaptersInfo Called"));
    return pGetAdaptersInfo(pAdapterInfo, pOutBufLen);
}

SHORT WINAPI GetAsyncKeyState_Detour(_In_ int vKey)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetAsyncKeyState Called"));
    return pGetAsyncKeyState(vKey);
}

HDC WINAPI GetDC_Detour(_In_opt_ HWND hWnd)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetDC Called"));
    return pGetDC(hWnd);
}

HWND WINAPI GetForegroundWindow_Detour()
{
    pPipe->SendMessage(LP_TEXT_STRING("GetForegroundWindow Called"));
    return pGetForegroundWindow();
}

/*
struct WSAAPI gethostbyname_Detour(_In_ const char* name)
{
    pPipe->SendMessage(LP_TEXT_STRING("gethostbyname Called"));
    return pGethostbyname(name);
}
*/

int WINAPI gethostname_Detour(_Out_ char* name, _In_ int namelen)
{
    pPipe->SendMessage(LP_TEXT_STRING("gethostname Called"));
    return pGethostname(name, namelen);
}

SHORT WINAPI GetKeyState_Detour(_In_ int nVirtKey)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetKeyState Called"));
    return pGetKeyState(nVirtKey);
}

DWORD WINAPI GetModuleFileName_Detour(_In_opt_ HMODULE hModule, _Out_ LPWSTR lpFilename, _In_ DWORD nSize)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetModuleFileName Called"));
    return pGetModuleFileName(hModule, lpFilename, nSize);
}

HMODULE WINAPI GetModuleHandle_Detour(_In_opt_ LPCWSTR lpModuleName)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetModuleHandle Called"));
    return pGetModuleHandle(lpModuleName);
}

FARPROC WINAPI GetProcAddress_Detour(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetProcAddress Called"));
    return pGetProcAddress(hModule, lpProcName);
}

VOID WINAPI GetStartupInfo_Detour(_Out_ LPSTARTUPINFO lpStartupInfo)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetStartupInfo Called"));
    return pGetStartupInfo(lpStartupInfo);
}

LANGID WINAPI GetSystemDefaultLangID_Detour()
{
    pPipe->SendMessage(LP_TEXT_STRING("GetSystemDefaultLangID Called"));
    return pGetSystemDefaultLangID();
}

DWORD WINAPI GetTempPath_Detour(_In_ DWORD nBufferLength, _Out_ LPWSTR lpBuffer)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetTempPath Called"));
    return pGetTempPath(nBufferLength, lpBuffer);
}

BOOL WINAPI GetThreadContext_Detour(_In_ HANDLE hThread, _Inout_ LPCONTEXT lpContext)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetThreadContext Called"));
    return pGetThreadContext(hThread, lpContext);
}

UINT WINAPI GetWindowsDirectory_Detour(_Out_ LPWSTR lpBuffer, _In_ UINT uSize)
{
    pPipe->SendMessage(LP_TEXT_STRING("GetWindowsDirectory Called"));
    return pGetWindowsDirectory(lpBuffer, uSize);
}

ULONG WINAPI inet_addr_Detour(_In_ const char* cp)
{
    pPipe->SendMessage(LP_TEXT_STRING("inet_addr Called"));
    return pinet_addr(cp);
}

HINTERNET WINAPI InternetOpen_Detour(_In_ LPCWSTR lpszAgent, _In_ DWORD dwAccessType, _In_ LPCWSTR lpszProxy, _In_ LPCWSTR lpszProxyBypass, _In_ DWORD dwFlags)
{
    pPipe->SendMessage(LP_TEXT_STRING("InternetOpen Called"));
    return pInternetOpen(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI InternetOpenUrl_Detour(_In_ HINTERNET hInternet, _In_ LPCWSTR lpszUrl, _In_ LPCWSTR lpszHeaders, _In_ DWORD dwHeadersLength, _In_ DWORD dwFlags, _In_ DWORD_PTR dwContext)
{
    pPipe->SendMessage(LP_TEXT_STRING("InternetOpenUrl Called"));
    return pInternetOpenUrl(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

BOOL WINAPI InternetReadFile_Detour(_In_ HINTERNET hFile, _Out_ LPVOID lpBuffer, _In_ DWORD dwNumberOfBytesToRead, _Out_ LPDWORD lpdwNumberOfBytesRead)
{
    pPipe->SendMessage(LP_TEXT_STRING("InternetReadFile Called"));
    return pInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WINAPI InternetWriteFile_Detour(_In_ HINTERNET hFile, _In_ LPCVOID lpBuffer, _In_ DWORD dwNumberOfBytesToWrite, _Out_ LPDWORD lpdwNumberOfBytesWritten)
{
    pPipe->SendMessage(LP_TEXT_STRING("InternetWriteFile Called"));
    return pInternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
}

BOOL WINAPI IsUserAnAdmin_Detour()
{
    pPipe->SendMessage(LP_TEXT_STRING("IsUserAnAdmin Called"));
    return pIsUserAnAdmin();
}

BOOL WINAPI IsWow64Process_Detour(_In_ HANDLE hProcess, _Out_ PBOOL Wow64Process)
{
    pPipe->SendMessage(LP_TEXT_STRING("IsWow64Process Called"));
    return pIsWow64Process(hProcess, Wow64Process);
}

HGLOBAL WINAPI LoadResource_Detour(_In_opt_ HMODULE hModule, _In_ HRSRC hResInfo)
{
    pPipe->SendMessage(LP_TEXT_STRING("LoadResource Called"));
    return pLoadResource(hModule, hResInfo);
}

NTSTATUS WINAPI LsaEnumerateLogonSessions_Detour(_Out_ PULONG LogonSessionCount, _Out_ PLUID* LogonSessionList)
{
    pPipe->SendMessage(LP_TEXT_STRING("LsaEnumerateLogonSessions Called"));
    return pLsaEnumerateLogonSessions(LogonSessionCount, LogonSessionList);
}

LPVOID WINAPI MapViewOfFile_Detour(_In_ HANDLE hFileMappingObject, _In_ DWORD dwDesiredAccess, _In_ DWORD dwFileOffsetHigh, _In_ DWORD dwFileOffsetLow, _In_ SIZE_T dwNumberOfBytesToMap)
{
    pPipe->SendMessage(LP_TEXT_STRING("MapViewOfFile Called"));
    return pMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

UINT WINAPI MapVirtualKey_Detour(_In_ UINT uCode, _In_ UINT uMapType)
{
    pPipe->SendMessage(LP_TEXT_STRING("MapVirtualKey Called"));
    return pMapVirtualKey(uCode, uMapType);
}

BOOL WINAPI Module32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPMODULEENTRY32 lpme)
{
    pPipe->SendMessage(LP_TEXT_STRING("Module32First Called"));
    return pModule32First(hSnapshot, lpme);
}

BOOL WINAPI Module32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPMODULEENTRY32 lpme)
{
    pPipe->SendMessage(LP_TEXT_STRING("Module32Next Called"));
    return pModule32Next(hSnapshot, lpme);
}

NET_API_STATUS WINAPI NetScheduleJobAdd_Detour(_In_ LPCWSTR Servername, _In_ LPBYTE Buffer, _Out_ LPDWORD JobId)
{
    pPipe->SendMessage(LP_TEXT_STRING("NetScheduleJobAdd Called"));
    return pNetScheduleJobAdd(Servername, Buffer, JobId);
}

NET_API_STATUS WINAPI NetShareEnum_Detour(_In_ LPWSTR servername, _In_ DWORD level, _Out_ LPBYTE* bufptr, _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_ LPDWORD resume_handle)
{
    pPipe->SendMessage(LP_TEXT_STRING("NetShareEnum Called"));
    return pNetShareEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
}

HANDLE WINAPI OpenMutex_Detour(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ LPCWSTR lpName)
{
    pPipe->SendMessage(LP_TEXT_STRING("OpenMutex Called"));
    return pOpenMutex(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE WINAPI OpenProcess_Detour(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwProcessId)
{
    pPipe->SendMessage(LP_TEXT_STRING("OpenProcess Called"));
    return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

VOID WINAPI OutputDebugString_Detour(_In_opt_ LPCWSTR lpOutputString)
{
    pPipe->SendMessage(LP_TEXT_STRING("OutputDebugString Called"));
    return pOutputDebugString(lpOutputString);
}

BOOL WINAPI PeekNamedPipe_Detour(_In_ HANDLE hNamedPipe, _Out_ LPVOID lpBuffer, _In_ DWORD nBufferSize, _Out_ LPDWORD lpBytesRead, _Out_ LPDWORD lpTotalBytesAvail, _Out_ LPDWORD lpBytesLeftThisMessage)
{
    pPipe->SendMessage(LP_TEXT_STRING("PeekNamedPipe Called"));
    return pPeekNamedPipe(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage);
}

BOOL WINAPI Process32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPPROCESSENTRY32 lppe)
{
    pPipe->SendMessage(LP_TEXT_STRING("Process32First Called"));
    return pProcess32First(hSnapshot, lppe);
}

BOOL WINAPI Process32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe)
{
    pPipe->SendMessage(LP_TEXT_STRING("Process32Next Called"));
    return pProcess32Next(hSnapshot, lppe);
}

DWORD WINAPI QueueUserAPC_Detour(_In_ PAPCFUNC pfnAPC, _In_ HANDLE hThread, _In_ ULONG_PTR dwData)
{
    pPipe->SendMessage(LP_TEXT_STRING("QueueUserAPC Called"));
    return pQueueUserAPC(pfnAPC, hThread, dwData);
}

BOOL WINAPI ReadProcessMemory_Detour(_In_ HANDLE hProcess, _In_ LPCVOID lpBaseAddress, _Out_ LPVOID lpBuffer, _In_ SIZE_T nSize, _Out_ SIZE_T* lpNumberOfBytesRead)
{
    pPipe->SendMessage(LP_TEXT_STRING("ReadProcessMemory Called"));
    return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

int WINAPI recv_Detour(_In_ SOCKET s, _Out_ char* buf, _In_ int len, _In_ int flags)
{
    pPipe->SendMessage(LP_TEXT_STRING("recv Called"));
    return pRecv(s, buf, len, flags);
}

BOOL WINAPI RegisterHotKey_Detour(_In_opt_ HWND hWnd, _In_ int id, _In_ UINT fsModifiers, _In_ UINT vk)
{
    pPipe->SendMessage(LP_TEXT_STRING("RegisterHotKey Called"));
    return pRegisterHotKey(hWnd, id, fsModifiers, vk);
}

LONG WINAPI RegOpenKey_Detour(_In_ HKEY hKey, _In_ LPCWSTR lpSubKey, _Out_ PHKEY phkResult)
{
    pPipe->SendMessage(LP_TEXT_STRING("RegOpenKey Called"));
    return pRegOpenKey(hKey, lpSubKey, phkResult);
}

DWORD WINAPI ResumeThread_Detour(_In_ HANDLE hThread)
{
    pPipe->SendMessage(LP_TEXT_STRING("ResumeThread Called"));
    return pResumeThread(hThread);
}

int WINAPI send_Detour(_In_ SOCKET s, _In_ const char* buf, _In_ int len, _In_ int flags)
{
    pPipe->SendMessage(LP_TEXT_STRING("send Called"));
    return pSend(s, buf, len, flags);
}

BOOL WINAPI SetFileTime_Detour(_In_ HANDLE hFile, _In_opt_ const FILETIME* lpCreationTime, _In_opt_ const FILETIME* lpLastAccessTime, _In_opt_ const FILETIME* lpLastWriteTime)
{
    pPipe->SendMessage(LP_TEXT_STRING("SetFileTime Called"));
    return pSetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
}

BOOL WINAPI SetThreadContext_Detour(_In_ HANDLE hThread, _In_ const CONTEXT* lpContext)
{
    pPipe->SendMessage(LP_TEXT_STRING("SetThreadContext Called"));
    return pSetThreadContext(hThread, lpContext);
}

HHOOK WINAPI SetWindowsHookEx_Detour(_In_ int idHook, _In_ HOOKPROC lpfn, _In_ HINSTANCE hMod, _In_ DWORD dwThreadId)
{
    pPipe->SendMessage(LP_TEXT_STRING("SetWindowsHookEx Called"));
    return pSetWindowsHookEx(idHook, lpfn, hMod, dwThreadId);
}

HINSTANCE WINAPI ShellExecute_Detour(_In_opt_ HWND hwnd, _In_opt_ LPCTSTR lpOperation, _In_ LPCTSTR lpFile, _In_opt_ LPCTSTR lpParameters, _In_opt_ LPCTSTR lpDirectory, _In_ INT nShowCmd)
{
    pPipe->SendMessage(LP_TEXT_STRING("ShellExecute Called"));
    return pShellExecute(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

BOOL WINAPI StartServiceCtrlDispatcher_Detour(_In_ const SERVICE_TABLE_ENTRY* lpServiceTable)
{
    pPipe->SendMessage(LP_TEXT_STRING("StartServiceCtrlDispatcher Called"));
    return pStartServiceCtrlDispatcher(lpServiceTable);
}

DWORD WINAPI SuspendThread_Detour(_In_ HANDLE hThread)
{
    pPipe->SendMessage(LP_TEXT_STRING("SuspendThread Called"));
    return pSuspendThread(hThread);
}

int WINAPI system_Detour(_In_opt_ const char* command)
{
    pPipe->SendMessage(LP_TEXT_STRING("system Called"));
    return pSystem(command);
}

BOOL WINAPI Thread32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPTHREADENTRY32 lpte)
{
    pPipe->SendMessage(LP_TEXT_STRING("Thread32First Called"));
    return pThread32First(hSnapshot, lpte);
}

BOOL WINAPI Thread32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPTHREADENTRY32 lpte)
{
    pPipe->SendMessage(LP_TEXT_STRING("Thread32Next Called"));
    return pThread32Next(hSnapshot, lpte);
}

BOOL WINAPI Toolhelp32ReadProcessMemory_Detour(_In_ DWORD th32ProcessID, _In_ LPCVOID lpBaseAddress, _Out_ LPVOID lpBuffer, _In_ SIZE_T cbRead, _Out_ SIZE_T* lpNumberOfBytesRead)
{
    pPipe->SendMessage(LP_TEXT_STRING("Toolhelp32ReadProcessMemory Called"));
    return pToolhelp32ReadProcessMemory(th32ProcessID, lpBaseAddress, lpBuffer, cbRead, lpNumberOfBytesRead);
}

HRESULT WINAPI URLDownloadToFile_Detour(_In_opt_ LPUNKNOWN pCaller, _In_ LPCWSTR szURL, _In_ LPCWSTR szFileName, _In_ DWORD dwReserved, _In_opt_ LPBINDSTATUSCALLBACK lpfnCB)
{
    pPipe->SendMessage(LP_TEXT_STRING("URLDownloadToFile Called"));
    return pURLDownloadToFile(pCaller, szURL, szFileName, dwReserved, lpfnCB);
}

LPVOID WINAPI VirtualAllocEx_Detour(_In_ HANDLE hProcess, _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect)
{
    pPipe->SendMessage(LP_TEXT_STRING("VirtualAllocEx Called"));
    return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI VirtualProtectEx_Detour(_In_ HANDLE hProcess, _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect)
{
    pPipe->SendMessage(LP_TEXT_STRING("VirtualProtectEx Called"));
    return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

int WINAPI WideCharToMultiByte_Detour(_In_ UINT CodePage, _In_ DWORD dwFlags, _In_ LPCWSTR lpWideCharStr, _In_ int cchWideChar, _Out_opt_ LPSTR lpMultiByteStr, _In_ int cbMultiByte, _In_opt_ LPCSTR lpDefaultChar, _Out_opt_ LPBOOL lpUsedDefaultChar)
{
    pPipe->SendMessage(LP_TEXT_STRING("WideCharToMultiByte Called"));
    return pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

UINT WINAPI WinExec_Detour(_In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow)
{
    pPipe->SendMessage(LP_TEXT_STRING("WinExec Called"));
    return pWinExec(lpCmdLine, uCmdShow);
}

BOOL WINAPI WriteProcessMemory_Detour(_In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, _In_ LPCVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesWritten)
{
    pPipe->SendMessage(LP_TEXT_STRING("WriteProcessMemory Called"));
    return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

int WINAPI WSAStartup_Detour(_In_ WORD wVersionRequested, _Out_ LPWSADATA lpWSAData)
{
    pPipe->SendMessage(LP_TEXT_STRING("WSAStartup Called"));
    return pWSAStartup(wVersionRequested, lpWSAData);
}

HookManager::HookManager(Pipe* pPipe)
{
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)pMessageBoxA, MessageBoxA_Detour);
    DetourAttach(&(PVOID&)pAccept, accept_Detour);
    DetourAttach(&(PVOID&)pAdjustTokenPrivileges, AdjustTokenPrivileges_Detour);
    DetourAttach(&(PVOID&)pAttachThreadInput, AttachThreadInput_Detour);
    DetourAttach(&(PVOID&)pBind, bind_Detour);
    DetourAttach(&(PVOID&)pBitBlt, BitBlt_Detour);
    DetourAttach(&(PVOID&)pCertOpenSystemStoreA, CertOpenSystemStoreA_Detour);
    DetourAttach(&(PVOID&)pCertOpenSystemStoreW, CertOpenSystemStoreW_Detour);
    DetourAttach(&(PVOID&)pConnect, connect_Detour);
    DetourAttach(&(PVOID&)pConnectNamedPipe, ConnectNamedPipe_Detour);
    DetourAttach(&(PVOID&)pControlService, ControlService_Detour);
    DetourAttach(&(PVOID&)pCreateFileA, CreateFileA_Detour);
    DetourAttach(&(PVOID&)pCreateFileW, CreateFileW_Detour);
    DetourAttach(&(PVOID&)pCreateProcess, CreateProcess_Detour);
    DetourAttach(&(PVOID&)pCreateRemoteThread, CreateRemoteThread_Detour);
    DetourAttach(&(PVOID&)pCreateService, CreateService_Detour);
    DetourAttach(&(PVOID&)pCreateToolhelp32Snapshot, CreateToolhelp32Snapshot_Detour);
    DetourAttach(&(PVOID&)pCryptAcquireContext, CryptAcquireContext_Detour);
    DetourAttach(&(PVOID&)pDeviceIoControl, DeviceIoControl_Detour);
    DetourAttach(&(PVOID&)pEnumProcesses, EnumProcesses_Detour);
    DetourAttach(&(PVOID&)pEnumProcessModules, EnumProcessModules_Detour);
    DetourAttach(&(PVOID&)pFindFirstFile, FindFirstFile_Detour);
    DetourAttach(&(PVOID&)pFindNextFile, FindNextFile_Detour);
    DetourAttach(&(PVOID&)pFindResource, FindResource_Detour);
    DetourAttach(&(PVOID&)pFindWindow, FindWindow_Detour);
    DetourAttach(&(PVOID&)pFtpPutFile, FtpPutFile_Detour);
    DetourAttach(&(PVOID&)pGetAdaptersInfo, GetAdaptersInfo_Detour);
    DetourAttach(&(PVOID&)pGetAsyncKeyState, GetAsyncKeyState_Detour);
    DetourAttach(&(PVOID&)pGetDC, GetDC_Detour);
    DetourAttach(&(PVOID&)pGetForegroundWindow, GetForegroundWindow_Detour);
    // DetourAttach(&(PVOID&)pGethostbyname, gethostbyname_Detour);
    DetourAttach(&(PVOID&)pGethostname, gethostname_Detour);
    DetourAttach(&(PVOID&)pGetKeyState, GetKeyState_Detour);
    DetourAttach(&(PVOID&)pGetModuleFileName, GetModuleFileName_Detour);
    DetourAttach(&(PVOID&)pGetModuleHandle, GetModuleHandle_Detour);
    DetourAttach(&(PVOID&)pGetProcAddress, GetProcAddress_Detour);
    DetourAttach(&(PVOID&)pGetStartupInfo, GetStartupInfo_Detour);
    DetourAttach(&(PVOID&)pGetSystemDefaultLangID, GetSystemDefaultLangID_Detour);
    DetourAttach(&(PVOID&)pGetTempPath, GetTempPath_Detour);
    DetourAttach(&(PVOID&)pGetThreadContext, GetThreadContext_Detour);
    DetourAttach(&(PVOID&)pGetWindowsDirectory, GetWindowsDirectory_Detour);
    DetourAttach(&(PVOID&)pinet_addr, inet_addr_Detour);
    DetourAttach(&(PVOID&)pInternetOpen, InternetOpen_Detour);
    DetourAttach(&(PVOID&)pInternetOpenUrl, InternetOpenUrl_Detour);
    DetourAttach(&(PVOID&)pInternetReadFile, InternetReadFile_Detour);
    DetourAttach(&(PVOID&)pInternetWriteFile, InternetWriteFile_Detour);
    DetourAttach(&(PVOID&)pIsUserAnAdmin, IsUserAnAdmin_Detour);
    DetourAttach(&(PVOID&)pIsWow64Process, IsWow64Process_Detour);
    DetourAttach(&(PVOID&)pLoadResource, LoadResource_Detour);
    DetourAttach(&(PVOID&)pLsaEnumerateLogonSessions, LsaEnumerateLogonSessions_Detour);
    DetourAttach(&(PVOID&)pMapViewOfFile, MapViewOfFile_Detour);
    DetourAttach(&(PVOID&)pMapVirtualKey, MapVirtualKey_Detour);
    DetourAttach(&(PVOID&)pModule32First, Module32First_Detour);
    DetourAttach(&(PVOID&)pModule32Next, Module32Next_Detour);
    DetourAttach(&(PVOID&)pNetScheduleJobAdd, NetScheduleJobAdd_Detour);
    DetourAttach(&(PVOID&)pNetShareEnum, NetShareEnum_Detour);
    DetourAttach(&(PVOID&)pOpenMutex, OpenMutex_Detour);
    DetourAttach(&(PVOID&)pOpenProcess, OpenProcess_Detour);
    DetourAttach(&(PVOID&)pOutputDebugString, OutputDebugString_Detour);
    DetourAttach(&(PVOID&)pPeekNamedPipe, PeekNamedPipe_Detour);
    DetourAttach(&(PVOID&)pProcess32First, Process32First_Detour);
    DetourAttach(&(PVOID&)pProcess32Next, Process32Next_Detour);
    DetourAttach(&(PVOID&)pQueueUserAPC, QueueUserAPC_Detour);
    DetourAttach(&(PVOID&)pReadProcessMemory, ReadProcessMemory_Detour);
    DetourAttach(&(PVOID&)pRecv, recv_Detour);
    DetourAttach(&(PVOID&)pRegisterHotKey, RegisterHotKey_Detour);
    DetourAttach(&(PVOID&)pRegOpenKey, RegOpenKey_Detour);
    DetourAttach(&(PVOID&)pResumeThread, ResumeThread_Detour);
    DetourAttach(&(PVOID&)pSend, send_Detour);
    DetourAttach(&(PVOID&)pSetFileTime, SetFileTime_Detour);
    DetourAttach(&(PVOID&)pSetThreadContext, SetThreadContext_Detour);
    DetourAttach(&(PVOID&)pSetWindowsHookEx, SetWindowsHookEx_Detour);
    DetourAttach(&(PVOID&)pShellExecute, ShellExecute_Detour);
    DetourAttach(&(PVOID&)pStartServiceCtrlDispatcher, StartServiceCtrlDispatcher_Detour);
    DetourAttach(&(PVOID&)pSuspendThread, SuspendThread_Detour);
    DetourAttach(&(PVOID&)pSystem, system_Detour);
    DetourAttach(&(PVOID&)pThread32First, Thread32First_Detour);
    DetourAttach(&(PVOID&)pThread32Next, Thread32Next_Detour);
    DetourAttach(&(PVOID&)pToolhelp32ReadProcessMemory, Toolhelp32ReadProcessMemory_Detour);
    DetourAttach(&(PVOID&)pURLDownloadToFile, URLDownloadToFile_Detour);
    DetourAttach(&(PVOID&)pVirtualAllocEx, VirtualAllocEx_Detour);
    DetourAttach(&(PVOID&)pVirtualProtectEx, VirtualProtectEx_Detour);
    DetourAttach(&(PVOID&)pWideCharToMultiByte, WideCharToMultiByte_Detour);
    DetourAttach(&(PVOID&)pWinExec, WinExec_Detour);
    DetourAttach(&(PVOID&)pWriteProcessMemory, WriteProcessMemory_Detour);
    DetourAttach(&(PVOID&)pWSAStartup, WSAStartup_Detour);

    DetourTransactionCommit();

    pPipe->SendMessage(LP_TEXT_STRING("Detours hooks initalised."));
}

HookManager::~HookManager()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)pMessageBoxA, MessageBoxA_Detour);
    DetourDetach(&(PVOID&)pAccept, accept_Detour);
    DetourDetach(&(PVOID&)pAdjustTokenPrivileges, AdjustTokenPrivileges_Detour);
    DetourDetach(&(PVOID&)pAttachThreadInput, AttachThreadInput_Detour);
    DetourDetach(&(PVOID&)pBind, bind_Detour);
    DetourDetach(&(PVOID&)pBitBlt, BitBlt_Detour);
    DetourDetach(&(PVOID&)pCertOpenSystemStoreA, CertOpenSystemStoreA_Detour);
    DetourDetach(&(PVOID&)pCertOpenSystemStoreW, CertOpenSystemStoreW_Detour);
    DetourDetach(&(PVOID&)pConnect, connect_Detour);
    DetourDetach(&(PVOID&)pConnectNamedPipe, ConnectNamedPipe_Detour);
    DetourDetach(&(PVOID&)pControlService, ControlService_Detour);
    DetourDetach(&(PVOID&)pCreateFileA, CreateFileA_Detour);
    DetourDetach(&(PVOID&)pCreateFileW, CreateFileW_Detour);
    DetourDetach(&(PVOID&)pCreateProcess, CreateProcess_Detour);
    DetourDetach(&(PVOID&)pCreateRemoteThread, CreateRemoteThread_Detour);
    DetourDetach(&(PVOID&)pCreateService, CreateService_Detour);
    DetourDetach(&(PVOID&)pCreateToolhelp32Snapshot, CreateToolhelp32Snapshot_Detour);
    DetourDetach(&(PVOID&)pCryptAcquireContext, CryptAcquireContext_Detour);
    DetourDetach(&(PVOID&)pDeviceIoControl, DeviceIoControl_Detour);
    DetourDetach(&(PVOID&)pEnumProcesses, EnumProcesses_Detour);
    DetourDetach(&(PVOID&)pEnumProcessModules, EnumProcessModules_Detour);
    DetourDetach(&(PVOID&)pFindFirstFile, FindFirstFile_Detour);
    DetourDetach(&(PVOID&)pFindNextFile, FindNextFile_Detour);
    DetourDetach(&(PVOID&)pFindResource, FindResource_Detour);
    DetourDetach(&(PVOID&)pFindWindow, FindWindow_Detour);
    DetourDetach(&(PVOID&)pFtpPutFile, FtpPutFile_Detour);
    DetourDetach(&(PVOID&)pGetAdaptersInfo, GetAdaptersInfo_Detour);
    DetourDetach(&(PVOID&)pGetAsyncKeyState, GetAsyncKeyState_Detour);
    DetourDetach(&(PVOID&)pGetDC, GetDC_Detour);
    DetourDetach(&(PVOID&)pGetForegroundWindow, GetForegroundWindow_Detour);
    //DetourDetach(&(PVOID&)pGethostbyname, gethostbyname_Detour);
    DetourDetach(&(PVOID&)pGethostname, gethostname_Detour);
    DetourDetach(&(PVOID&)pGetKeyState, GetKeyState_Detour);
    DetourDetach(&(PVOID&)pGetModuleFileName, GetModuleFileName_Detour);
    DetourDetach(&(PVOID&)pGetModuleHandle, GetModuleHandle_Detour);
    DetourDetach(&(PVOID&)pGetProcAddress, GetProcAddress_Detour);
    DetourDetach(&(PVOID&)pGetStartupInfo, GetStartupInfo_Detour);
    DetourDetach(&(PVOID&)pGetSystemDefaultLangID, GetSystemDefaultLangID_Detour);
    DetourDetach(&(PVOID&)pGetTempPath, GetTempPath_Detour);
    DetourDetach(&(PVOID&)pGetThreadContext, GetThreadContext_Detour);
    DetourDetach(&(PVOID&)pGetWindowsDirectory, GetWindowsDirectory_Detour);
    DetourDetach(&(PVOID&)pinet_addr, inet_addr_Detour);
    DetourDetach(&(PVOID&)pInternetOpen, InternetOpen_Detour);
    DetourDetach(&(PVOID&)pInternetOpenUrl, InternetOpenUrl_Detour);
    DetourDetach(&(PVOID&)pInternetReadFile, InternetReadFile_Detour);
    DetourDetach(&(PVOID&)pInternetWriteFile, InternetWriteFile_Detour);
    DetourDetach(&(PVOID&)pIsUserAnAdmin, IsUserAnAdmin_Detour);
    DetourDetach(&(PVOID&)pIsWow64Process, IsWow64Process_Detour);
    DetourDetach(&(PVOID&)pLoadResource, LoadResource_Detour);
    DetourDetach(&(PVOID&)pLsaEnumerateLogonSessions, LsaEnumerateLogonSessions_Detour);
    DetourDetach(&(PVOID&)pMapViewOfFile, MapViewOfFile_Detour);
    DetourDetach(&(PVOID&)pMapVirtualKey, MapVirtualKey_Detour);
    DetourDetach(&(PVOID&)pModule32First, Module32First_Detour);
    DetourDetach(&(PVOID&)pModule32Next, Module32Next_Detour);
    DetourDetach(&(PVOID&)pNetScheduleJobAdd, NetScheduleJobAdd_Detour);
    DetourDetach(&(PVOID&)pNetShareEnum, NetShareEnum_Detour);
    DetourDetach(&(PVOID&)pOpenMutex, OpenMutex_Detour);
    DetourDetach(&(PVOID&)pOpenProcess, OpenProcess_Detour);
    DetourDetach(&(PVOID&)pOutputDebugString, OutputDebugString_Detour);
    DetourDetach(&(PVOID&)pPeekNamedPipe, PeekNamedPipe_Detour);
    DetourDetach(&(PVOID&)pProcess32First, Process32First_Detour);
    DetourDetach(&(PVOID&)pProcess32Next, Process32Next_Detour);
    DetourDetach(&(PVOID&)pQueueUserAPC, QueueUserAPC_Detour);
    DetourDetach(&(PVOID&)pReadProcessMemory, ReadProcessMemory_Detour);
    DetourDetach(&(PVOID&)pRecv, recv_Detour);
    DetourDetach(&(PVOID&)pRegisterHotKey, RegisterHotKey_Detour);
    DetourDetach(&(PVOID&)pRegOpenKey, RegOpenKey_Detour);
    DetourDetach(&(PVOID&)pResumeThread, ResumeThread_Detour);
    DetourDetach(&(PVOID&)pSend, send_Detour);
    DetourDetach(&(PVOID&)pSetFileTime, SetFileTime_Detour);
    DetourDetach(&(PVOID&)pSetThreadContext, SetThreadContext_Detour);
    DetourDetach(&(PVOID&)pSetWindowsHookEx, SetWindowsHookEx_Detour);
    DetourDetach(&(PVOID&)pShellExecute, ShellExecute_Detour);
    DetourDetach(&(PVOID&)pStartServiceCtrlDispatcher, StartServiceCtrlDispatcher_Detour);
    DetourDetach(&(PVOID&)pSuspendThread, SuspendThread_Detour);
    DetourDetach(&(PVOID&)pSystem, system_Detour);
    DetourDetach(&(PVOID&)pThread32First, Thread32First_Detour);
    DetourDetach(&(PVOID&)pThread32Next, Thread32Next_Detour);
    DetourDetach(&(PVOID&)pToolhelp32ReadProcessMemory, Toolhelp32ReadProcessMemory_Detour);
    DetourDetach(&(PVOID&)pURLDownloadToFile, URLDownloadToFile_Detour);
    DetourDetach(&(PVOID&)pVirtualAllocEx, VirtualAllocEx_Detour);
    DetourDetach(&(PVOID&)pVirtualProtectEx, VirtualProtectEx_Detour);
    DetourDetach(&(PVOID&)pWideCharToMultiByte, WideCharToMultiByte_Detour);
    DetourDetach(&(PVOID&)pWinExec, WinExec_Detour);
    DetourDetach(&(PVOID&)pWriteProcessMemory, WriteProcessMemory_Detour);
    DetourDetach(&(PVOID&)pWSAStartup, WSAStartup_Detour);

    DetourTransactionCommit();

    delete pHookManager;
}