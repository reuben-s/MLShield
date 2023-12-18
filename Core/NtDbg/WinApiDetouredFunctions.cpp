#include "pch.h"
#include "WinApiDetouredFunctions.h"

namespace HookUtil
{
	namespace DetouredFunctions
	{
        int WINAPI MessageBoxA_Detour(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
        {
            pPipe->SendMessage(LP_TEXT_STRING("MessageBoxA Called"));
            return HookUtil::FunctionPointers::pMessageBoxA(hWnd, lpText, lpCaption, uType);
        }

        SOCKET WSAAPI accept_Detour(SOCKET s, sockaddr* addr, int* addrlen)
        {
            pPipe->SendMessage(LP_TEXT_STRING("accept Called"));
            return HookUtil::FunctionPointers::pAccept(s, addr, addrlen);
        }

        BOOL WINAPI AdjustTokenPrivileges_Detour(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
        {
            pPipe->SendMessage(LP_TEXT_STRING("AdjustTokenPrivileges Called"));
            return HookUtil::FunctionPointers::pAdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
        }

        BOOL WINAPI AttachThreadInput_Detour(DWORD idAttach, DWORD idAttachTo, BOOL fAttach)
        {
            pPipe->SendMessage(LP_TEXT_STRING("AttachThreadInput Called"));
            return HookUtil::FunctionPointers::pAttachThreadInput(idAttach, idAttachTo, fAttach);
        }

        int WSAAPI bind_Detour(SOCKET s, const sockaddr* addr, int namelen)
        {
            pPipe->SendMessage(LP_TEXT_STRING("bind Called"));
            return HookUtil::FunctionPointers::pBind(s, addr, namelen);
        }

        BOOL WINAPI BitBlt_Detour(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop)
        {
            pPipe->SendMessage(LP_TEXT_STRING("BitBlt Called"));
            return HookUtil::FunctionPointers::pBitBlt(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
        }
        
        HCERTSTORE WINAPI CertOpenSystemStoreA_Detour(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CertOpenSystemStoreA Called"));
            return HookUtil::FunctionPointers::pCertOpenSystemStoreA(hProv, szSubsystemProtocol);
        }

        HCERTSTORE WINAPI CertOpenSystemStoreW_Detour(HCRYPTPROV_LEGACY hProv, LPCWSTR szSubsystemProtocol)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CertOpenSystemStoreW Called"));
            return HookUtil::FunctionPointers::pCertOpenSystemStoreW(hProv, szSubsystemProtocol);
        }

        BOOL WINAPI connect_Detour(_In_ SOCKET s, _In_ const struct sockaddr* name, _In_ int namelen)
        {
            pPipe->SendMessage(LP_TEXT_STRING("connect Called"));
            return HookUtil::FunctionPointers::pConnect(s, name, namelen);
        }

        BOOL WINAPI ConnectNamedPipe_Detour(_In_ HANDLE hNamedPipe, _In_opt_ LPOVERLAPPED lpOverlapped)
        {
            pPipe->SendMessage(LP_TEXT_STRING("ConnectNamedPipe Called"));
            return HookUtil::FunctionPointers::pConnectNamedPipe(hNamedPipe, lpOverlapped);
        }

        BOOL WINAPI ControlService_Detour(_In_ SC_HANDLE hService, _In_ DWORD dwControl, _Out_ LPSERVICE_STATUS lpServiceStatus)
        {
            pPipe->SendMessage(LP_TEXT_STRING("ControlService Called"));
            return HookUtil::FunctionPointers::pControlService(hService, dwControl, lpServiceStatus);
        }

        HANDLE WINAPI CreateFile_Detour(_In_ LPCTSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CreateFile Called"));
            return HookUtil::FunctionPointers::pCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }

        BOOL WINAPI CreateProcess_Detour(_In_opt_ LPCTSTR lpApplicationName, _Inout_opt_ LPTSTR lpCommandLine, _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCTSTR lpCurrentDirectory, _In_ LPSTARTUPINFO lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CreateProcess Called"));
            return HookUtil::FunctionPointers::pCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }

        HANDLE WINAPI CreateRemoteThread_Detour(_In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CreateRemoteThread Called"));
            return HookUtil::FunctionPointers::pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        }

        SC_HANDLE WINAPI CreateService_Detour(_In_ SC_HANDLE hSCManager, _In_ LPCTSTR lpServiceName, _In_opt_ LPCTSTR lpDisplayName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwServiceType, _In_ DWORD dwStartType, _In_ DWORD dwErrorControl, _In_opt_ LPCTSTR lpBinaryPathName, _In_opt_ LPCTSTR lpLoadOrderGroup, _Out_opt_ LPDWORD lpdwTagId, _In_opt_ LPCTSTR lpDependencies, _In_opt_ LPCTSTR lpServiceStartName, _In_opt_ LPCTSTR lpPassword)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CreateService Called"));
            return HookUtil::FunctionPointers::pCreateService(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
        }

        HANDLE WINAPI CreateToolhelp32Snapshot_Detour(_In_ DWORD dwFlags, _In_ DWORD th32ProcessID)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CreateToolhelp32Snapshot Called"));
            return HookUtil::FunctionPointers::pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
        }

        BOOL WINAPI CryptAcquireContext_Detour(_Out_ HCRYPTPROV* phProv, _In_ LPCTSTR pszContainer, _In_ LPCTSTR pszProvider, _In_ DWORD dwProvType, _In_ DWORD dwFlags)
        {
            pPipe->SendMessage(LP_TEXT_STRING("CryptAcquireContext Called"));
            return HookUtil::FunctionPointers::pCryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
        }

        BOOL WINAPI DeviceIoControl_Detour(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode, _In_opt_ LPVOID lpInBuffer, _In_ DWORD nInBufferSize, _Out_opt_ LPVOID lpOutBuffer, _In_ DWORD nOutBufferSize, _Out_opt_ LPDWORD lpBytesReturned, _Inout_opt_ LPOVERLAPPED lpOverlapped)
        {
            pPipe->SendMessage(LP_TEXT_STRING("DeviceIoControl Called"));
            return HookUtil::FunctionPointers::pDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
        }

        BOOL WINAPI EnumProcesses_Detour(_Out_ DWORD* lpidProcess, _In_ DWORD cb, _Out_ LPDWORD lpcbNeeded)
        {
            pPipe->SendMessage(LP_TEXT_STRING("EnumProcesses Called"));
            return HookUtil::FunctionPointers::pEnumProcesses(lpidProcess, cb, lpcbNeeded);
        }

        BOOL WINAPI EnumProcessModules_Detour(_In_ HANDLE hProcess, _Out_ HMODULE* lphModule, _In_ DWORD cb, _Out_ LPDWORD lpcbNeeded)
        {
            pPipe->SendMessage(LP_TEXT_STRING("EnumProcessModules Called"));
            return HookUtil::FunctionPointers::pEnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
        }

        HANDLE WINAPI FindFirstFile_Detour(_In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATA lpFindFileData)
        {
            pPipe->SendMessage(LP_TEXT_STRING("FindFirstFile Called"));
            return HookUtil::FunctionPointers::pFindFirstFile(lpFileName, lpFindFileData);
        }

        BOOL WINAPI FindNextFile_Detour(_In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATA lpFindFileData)
        {
            pPipe->SendMessage(LP_TEXT_STRING("FindNextFile Called"));
            return HookUtil::FunctionPointers::pFindNextFile(hFindFile, lpFindFileData);
        }

        HRSRC WINAPI FindResource_Detour(_In_ HMODULE hModule, _In_ LPCWSTR lpName, _In_ LPCWSTR lpType)
        {
            pPipe->SendMessage(LP_TEXT_STRING("FindResource Called"));
            return HookUtil::FunctionPointers::pFindResource(hModule, lpName, lpType);
        }

        HWND WINAPI FindWindow_Detour(_In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName)
        {
            pPipe->SendMessage(LP_TEXT_STRING("FindWindow Called"));
            return HookUtil::FunctionPointers::pFindWindow(lpClassName, lpWindowName);
        }

        BOOL WINAPI FtpPutFile_Detour(_In_ HINTERNET hConnect, _In_ LPCWSTR lpszLocalFile, _In_ LPCWSTR lpszNewRemoteFile, _In_ DWORD dwFlags, _In_ DWORD_PTR dwContext)
        {
            pPipe->SendMessage(LP_TEXT_STRING("FtpPutFile Called"));
            return HookUtil::FunctionPointers::pFtpPutFile(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
        }

        DWORD WINAPI GetAdaptersInfo_Detour(_Out_ PIP_ADAPTER_INFO pAdapterInfo, _Inout_ PULONG pOutBufLen)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetAdaptersInfo Called"));
            return HookUtil::FunctionPointers::pGetAdaptersInfo(pAdapterInfo, pOutBufLen);
        }

        SHORT WINAPI GetAsyncKeyState_Detour(_In_ int vKey)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetAsyncKeyState Called"));
            return HookUtil::FunctionPointers::pGetAsyncKeyState(vKey);
        }

        HDC WINAPI GetDC_Detour(_In_opt_ HWND hWnd)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetDC Called"));
            return HookUtil::FunctionPointers::pGetDC(hWnd);
        }

        HWND WINAPI GetForegroundWindow_Detour()
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetForegroundWindow Called"));
            return HookUtil::FunctionPointers::pGetForegroundWindow();
        }

        struct hostent* WSAAPI gethostbyname_Detour(_In_ const char* name)
        {
            pPipe->SendMessage(LP_TEXT_STRING("gethostbyname Called"));
            return HookUtil::FunctionPointers::pGethostbyname(name);
        }

        int WINAPI gethostname_Detour(_Out_ char* name, _In_ int namelen)
        {
            pPipe->SendMessage(LP_TEXT_STRING("gethostname Called"));
            return HookUtil::FunctionPointers::pGethostname(name, namelen);
        }

        SHORT WINAPI GetKeyState_Detour(_In_ int nVirtKey)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetKeyState Called"));
            return HookUtil::FunctionPointers::pGetKeyState(nVirtKey);
        }

        DWORD WINAPI GetModuleFileName_Detour(_In_opt_ HMODULE hModule, _Out_ LPWSTR lpFilename, _In_ DWORD nSize)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetModuleFileName Called"));
            return HookUtil::FunctionPointers::pGetModuleFileName(hModule, lpFilename, nSize);
        }

        HMODULE WINAPI GetModuleHandle_Detour(_In_opt_ LPCWSTR lpModuleName)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetModuleHandle Called"));
            return HookUtil::FunctionPointers::pGetModuleHandle(lpModuleName);
        }

        FARPROC WINAPI GetProcAddress_Detour(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetProcAddress Called"));
            return HookUtil::FunctionPointers::pGetProcAddress(hModule, lpProcName);
        }

        VOID WINAPI GetStartupInfo_Detour(_Out_ LPSTARTUPINFO lpStartupInfo)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetStartupInfo Called"));
            return HookUtil::FunctionPointers::pGetStartupInfo(lpStartupInfo);
        }

        LANGID WINAPI GetSystemDefaultLangID_Detour()
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetSystemDefaultLangID Called"));
            return HookUtil::FunctionPointers::pGetSystemDefaultLangID();
        }

        DWORD WINAPI GetTempPath_Detour(_In_ DWORD nBufferLength, _Out_ LPWSTR lpBuffer)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetTempPath Called"));
            return HookUtil::FunctionPointers::pGetTempPath(nBufferLength, lpBuffer);
        }

        BOOL WINAPI GetThreadContext_Detour(_In_ HANDLE hThread, _Inout_ LPCONTEXT lpContext)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetThreadContext Called"));
            return HookUtil::FunctionPointers::pGetThreadContext(hThread, lpContext);
        }

        UINT WINAPI GetWindowsDirectory_Detour(_Out_ LPWSTR lpBuffer, _In_ UINT uSize)
        {
            pPipe->SendMessage(LP_TEXT_STRING("GetWindowsDirectory Called"));
            return HookUtil::FunctionPointers::pGetWindowsDirectory(lpBuffer, uSize);
        }

        ULONG WINAPI inet_addr_Detour(_In_ const char* cp)
        {
            pPipe->SendMessage(LP_TEXT_STRING("inet_addr Called"));
            return HookUtil::FunctionPointers::pinet_addr(cp);
        }

        HINTERNET WINAPI InternetOpen_Detour(_In_ LPCWSTR lpszAgent, _In_ DWORD dwAccessType, _In_ LPCWSTR lpszProxy, _In_ LPCWSTR lpszProxyBypass, _In_ DWORD dwFlags)
        {
            pPipe->SendMessage(LP_TEXT_STRING("InternetOpen Called"));
            return HookUtil::FunctionPointers::pInternetOpen(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
        }

        HINTERNET WINAPI InternetOpenUrl_Detour(_In_ HINTERNET hInternet, _In_ LPCWSTR lpszUrl, _In_ LPCWSTR lpszHeaders, _In_ DWORD dwHeadersLength, _In_ DWORD dwFlags, _In_ DWORD_PTR dwContext)
        {
            pPipe->SendMessage(LP_TEXT_STRING("InternetOpenUrl Called"));
            return HookUtil::FunctionPointers::pInternetOpenUrl(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
        }

        BOOL WINAPI InternetReadFile_Detour(_In_ HINTERNET hFile, _Out_ LPVOID lpBuffer, _In_ DWORD dwNumberOfBytesToRead, _Out_ LPDWORD lpdwNumberOfBytesRead)
        {
            pPipe->SendMessage(LP_TEXT_STRING("InternetReadFile Called"));
            return HookUtil::FunctionPointers::pInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
        }

        BOOL WINAPI InternetWriteFile_Detour(_In_ HINTERNET hFile, _In_ LPCVOID lpBuffer, _In_ DWORD dwNumberOfBytesToWrite, _Out_ LPDWORD lpdwNumberOfBytesWritten)
        {
            pPipe->SendMessage(LP_TEXT_STRING("InternetWriteFile Called"));
            return HookUtil::FunctionPointers::pInternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
        }

        BOOL WINAPI IsUserAnAdmin_Detour()
        {
            pPipe->SendMessage(LP_TEXT_STRING("IsUserAnAdmin Called"));
            return HookUtil::FunctionPointers::pIsUserAnAdmin();
        }

        BOOL WINAPI IsWow64Process_Detour(_In_ HANDLE hProcess, _Out_ PBOOL Wow64Process)
        {
            pPipe->SendMessage(LP_TEXT_STRING("IsWow64Process Called"));
            return HookUtil::FunctionPointers::pIsWow64Process(hProcess, Wow64Process);
        }

        HGLOBAL WINAPI LoadResource_Detour(_In_opt_ HMODULE hModule, _In_ HRSRC hResInfo)
        {
            pPipe->SendMessage(LP_TEXT_STRING("LoadResource Called"));
            return HookUtil::FunctionPointers::pLoadResource(hModule, hResInfo);
        }

        NTSTATUS WINAPI LsaEnumerateLogonSessions_Detour(_Out_ PULONG LogonSessionCount, _Out_ PLUID* LogonSessionList)
        {
            pPipe->SendMessage(LP_TEXT_STRING("LsaEnumerateLogonSessions Called"));
            return HookUtil::FunctionPointers::pLsaEnumerateLogonSessions(LogonSessionCount, LogonSessionList);
        }

        LPVOID WINAPI MapViewOfFile_Detour(_In_ HANDLE hFileMappingObject, _In_ DWORD dwDesiredAccess, _In_ DWORD dwFileOffsetHigh, _In_ DWORD dwFileOffsetLow, _In_ SIZE_T dwNumberOfBytesToMap)
        {
            pPipe->SendMessage(LP_TEXT_STRING("MapViewOfFile Called"));
            return HookUtil::FunctionPointers::pMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
        }

        UINT WINAPI MapVirtualKey_Detour(_In_ UINT uCode, _In_ UINT uMapType)
        {
            pPipe->SendMessage(LP_TEXT_STRING("MapVirtualKey Called"));
            return HookUtil::FunctionPointers::pMapVirtualKey(uCode, uMapType);
        }

        BOOL WINAPI Module32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPMODULEENTRY32 lpme)
        {
            pPipe->SendMessage(LP_TEXT_STRING("Module32First Called"));
            return HookUtil::FunctionPointers::pModule32First(hSnapshot, lpme);
        }

        BOOL WINAPI Module32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPMODULEENTRY32 lpme)
        {
            pPipe->SendMessage(LP_TEXT_STRING("Module32Next Called"));
            return HookUtil::FunctionPointers::pModule32Next(hSnapshot, lpme);
        }

        NET_API_STATUS WINAPI NetScheduleJobAdd_Detour(_In_ LPCWSTR Servername, _In_ LPBYTE Buffer, _Out_ LPDWORD JobId)
        {
            pPipe->SendMessage(LP_TEXT_STRING("NetScheduleJobAdd Called"));
            return HookUtil::FunctionPointers::pNetScheduleJobAdd(Servername, Buffer, JobId);
        }

        NET_API_STATUS WINAPI NetShareEnum_Detour(_In_ LPWSTR servername, _In_ DWORD level, _Out_ LPBYTE* bufptr, _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_ LPDWORD resume_handle)
        {
            pPipe->SendMessage(LP_TEXT_STRING("NetShareEnum Called"));
            return HookUtil::FunctionPointers::pNetShareEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
        }

        HANDLE WINAPI OpenMutex_Detour(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ LPCWSTR lpName)
        {
            pPipe->SendMessage(LP_TEXT_STRING("OpenMutex Called"));
            return HookUtil::FunctionPointers::pOpenMutex(dwDesiredAccess, bInheritHandle, lpName);
        }

        HANDLE WINAPI OpenProcess_Detour(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwProcessId)
        {
            pPipe->SendMessage(LP_TEXT_STRING("OpenProcess Called"));
            return HookUtil::FunctionPointers::pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        }

        VOID WINAPI OutputDebugString_Detour(_In_opt_ LPCWSTR lpOutputString)
        {
            pPipe->SendMessage(LP_TEXT_STRING("OutputDebugString Called"));
            return HookUtil::FunctionPointers::pOutputDebugString(lpOutputString);
        }

        BOOL WINAPI PeekNamedPipe_Detour(_In_ HANDLE hNamedPipe, _Out_ LPVOID lpBuffer, _In_ DWORD nBufferSize, _Out_ LPDWORD lpBytesRead, _Out_ LPDWORD lpTotalBytesAvail, _Out_ LPDWORD lpBytesLeftThisMessage)
        {
            pPipe->SendMessage(LP_TEXT_STRING("PeekNamedPipe Called"));
            return HookUtil::FunctionPointers::pPeekNamedPipe(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage);
        }

        BOOL WINAPI Process32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPPROCESSENTRY32 lppe)
        {
            pPipe->SendMessage(LP_TEXT_STRING("Process32First Called"));
            return HookUtil::FunctionPointers::pProcess32First(hSnapshot, lppe);
        }

        BOOL WINAPI Process32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe)
        {
            pPipe->SendMessage(LP_TEXT_STRING("Process32Next Called"));
            return HookUtil::FunctionPointers::pProcess32Next(hSnapshot, lppe);
        }

        DWORD WINAPI QueueUserAPC_Detour(_In_ PAPCFUNC pfnAPC, _In_ HANDLE hThread, _In_ ULONG_PTR dwData)
        {
            pPipe->SendMessage(LP_TEXT_STRING("QueueUserAPC Called"));
            return HookUtil::FunctionPointers::pQueueUserAPC(pfnAPC, hThread, dwData);
        }

        BOOL WINAPI ReadProcessMemory_Detour(_In_ HANDLE hProcess, _In_ LPCVOID lpBaseAddress, _Out_ LPVOID lpBuffer, _In_ SIZE_T nSize, _Out_ SIZE_T* lpNumberOfBytesRead)
        {
            pPipe->SendMessage(LP_TEXT_STRING("ReadProcessMemory Called"));
            return HookUtil::FunctionPointers::pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        }

        int WINAPI recv_Detour(_In_ SOCKET s, _Out_ char* buf, _In_ int len, _In_ int flags)
        {
            pPipe->SendMessage(LP_TEXT_STRING("recv Called"));
            return HookUtil::FunctionPointers::pRecv(s, buf, len, flags);
        }

        BOOL WINAPI RegisterHotKey_Detour(_In_opt_ HWND hWnd, _In_ int id, _In_ UINT fsModifiers, _In_ UINT vk)
        {
            pPipe->SendMessage(LP_TEXT_STRING("RegisterHotKey Called"));
            return HookUtil::FunctionPointers::pRegisterHotKey(hWnd, id, fsModifiers, vk);
        }

        LONG WINAPI RegOpenKey_Detour(_In_ HKEY hKey, _In_ LPCWSTR lpSubKey, _Out_ PHKEY phkResult)
        {
            pPipe->SendMessage(LP_TEXT_STRING("RegOpenKey Called"));
            return HookUtil::FunctionPointers::pRegOpenKey(hKey, lpSubKey, phkResult);
        }

        DWORD WINAPI ResumeThread_Detour(_In_ HANDLE hThread)
        {
            pPipe->SendMessage(LP_TEXT_STRING("ResumeThread Called"));
            return HookUtil::FunctionPointers::pResumeThread(hThread);
        }

        int WINAPI send_Detour(_In_ SOCKET s, _In_ const char* buf, _In_ int len, _In_ int flags)
        {
            pPipe->SendMessage(LP_TEXT_STRING("send Called"));
            return HookUtil::FunctionPointers::pSend(s, buf, len, flags);
        }

        BOOL WINAPI SetFileTime_Detour(_In_ HANDLE hFile, _In_opt_ const FILETIME* lpCreationTime, _In_opt_ const FILETIME* lpLastAccessTime, _In_opt_ const FILETIME* lpLastWriteTime)
        {
            pPipe->SendMessage(LP_TEXT_STRING("SetFileTime Called"));
            return HookUtil::FunctionPointers::pSetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
        }

        BOOL WINAPI SetThreadContext_Detour(_In_ HANDLE hThread, _In_ const CONTEXT* lpContext)
        {
            pPipe->SendMessage(LP_TEXT_STRING("SetThreadContext Called"));
            return HookUtil::FunctionPointers::pSetThreadContext(hThread, lpContext);
        }

        HHOOK WINAPI SetWindowsHookEx_Detour(_In_ int idHook, _In_ HOOKPROC lpfn, _In_ HINSTANCE hMod, _In_ DWORD dwThreadId)
        {
            pPipe->SendMessage(LP_TEXT_STRING("SetWindowsHookEx Called"));
            return HookUtil::FunctionPointers::pSetWindowsHookEx(idHook, lpfn, hMod, dwThreadId);
        }

        HINSTANCE WINAPI ShellExecute_Detour(_In_opt_ HWND hwnd, _In_opt_ LPCTSTR lpOperation, _In_ LPCTSTR lpFile, _In_opt_ LPCTSTR lpParameters, _In_opt_ LPCTSTR lpDirectory, _In_ INT nShowCmd)
        {
            pPipe->SendMessage(LP_TEXT_STRING("ShellExecute Called"));
            return HookUtil::FunctionPointers::pShellExecute(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
        }

        BOOL WINAPI StartServiceCtrlDispatcher_Detour(_In_ const SERVICE_TABLE_ENTRY* lpServiceTable)
        {
            pPipe->SendMessage(LP_TEXT_STRING("StartServiceCtrlDispatcher Called"));
            return HookUtil::FunctionPointers::pStartServiceCtrlDispatcher(lpServiceTable);
        }

        DWORD WINAPI SuspendThread_Detour(_In_ HANDLE hThread)
        {
            pPipe->SendMessage(LP_TEXT_STRING("SuspendThread Called"));
            return HookUtil::FunctionPointers::pSuspendThread(hThread);
        }

        int WINAPI system_Detour(_In_opt_ const char* command)
        {
            pPipe->SendMessage(LP_TEXT_STRING("system Called"));
            return HookUtil::FunctionPointers::pSystem(command);
        }

        BOOL WINAPI Thread32First_Detour(_In_ HANDLE hSnapshot, _Inout_ LPTHREADENTRY32 lpte)
        {
            pPipe->SendMessage(LP_TEXT_STRING("Thread32First Called"));
            return HookUtil::FunctionPointers::pThread32First(hSnapshot, lpte);
        }

        BOOL WINAPI Thread32Next_Detour(_In_ HANDLE hSnapshot, _Out_ LPTHREADENTRY32 lpte)
        {
            pPipe->SendMessage(LP_TEXT_STRING("Thread32Next Called"));
            return HookUtil::FunctionPointers::pThread32Next(hSnapshot, lpte);
        }

        BOOL WINAPI Toolhelp32ReadProcessMemory_Detour(_In_ DWORD th32ProcessID, _In_ LPCVOID lpBaseAddress, _Out_ LPVOID lpBuffer, _In_ SIZE_T cbRead, _Out_ SIZE_T* lpNumberOfBytesRead)
        {
            pPipe->SendMessage(LP_TEXT_STRING("Toolhelp32ReadProcessMemory Called"));
            return HookUtil::FunctionPointers::pToolhelp32ReadProcessMemory(th32ProcessID, lpBaseAddress, lpBuffer, cbRead, lpNumberOfBytesRead);
        }

        HRESULT WINAPI URLDownloadToFile_Detour(_In_opt_ LPUNKNOWN pCaller, _In_ LPCWSTR szURL, _In_ LPCWSTR szFileName, _In_ DWORD dwReserved, _In_opt_ LPBINDSTATUSCALLBACK lpfnCB)
        {
            pPipe->SendMessage(LP_TEXT_STRING("URLDownloadToFile Called"));
            return HookUtil::FunctionPointers::pURLDownloadToFile(pCaller, szURL, szFileName, dwReserved, lpfnCB);
        }

        LPVOID WINAPI VirtualAllocEx_Detour(_In_ HANDLE hProcess, _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect)
        {
            pPipe->SendMessage(LP_TEXT_STRING("VirtualAllocEx Called"));
            return HookUtil::FunctionPointers::pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
        }

        BOOL WINAPI VirtualProtectEx_Detour(_In_ HANDLE hProcess, _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect)
        {
            pPipe->SendMessage(LP_TEXT_STRING("VirtualProtectEx Called"));
            return HookUtil::FunctionPointers::pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }

        int WINAPI WideCharToMultiByte_Detour(_In_ UINT CodePage, _In_ DWORD dwFlags, _In_ LPCWSTR lpWideCharStr, _In_ int cchWideChar, _Out_opt_ LPSTR lpMultiByteStr, _In_ int cbMultiByte, _In_opt_ LPCSTR lpDefaultChar, _Out_opt_ LPBOOL lpUsedDefaultChar)
        {
            pPipe->SendMessage(LP_TEXT_STRING("WideCharToMultiByte Called"));
            return HookUtil::FunctionPointers::pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
        }

        UINT WINAPI WinExec_Detour(_In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow)
        {
            pPipe->SendMessage(LP_TEXT_STRING("WinExec Called"));
            return HookUtil::FunctionPointers::pWinExec(lpCmdLine, uCmdShow);
        }

        BOOL WINAPI WriteProcessMemory_Detour(_In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, _In_ LPCVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesWritten)
        {
            pPipe->SendMessage(LP_TEXT_STRING("WriteProcessMemory Called"));
            return HookUtil::FunctionPointers::pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        }

        int WINAPI WSAStartup_Detour(_In_ WORD wVersionRequested, _Out_ LPWSADATA lpWSAData)
        {
            pPipe->SendMessage(LP_TEXT_STRING("WSAStartup Called"));
            return HookUtil::FunctionPointers::pWSAStartup(wVersionRequested, lpWSAData);
        }
	}
}
