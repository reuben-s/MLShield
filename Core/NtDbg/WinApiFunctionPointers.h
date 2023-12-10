#pragma once
#include "pch.h"

namespace WinApiFunctionPointers
{
    // MessageBoxA
    static int(WINAPI* pMessageBoxA)(
        HWND    hWnd,
        LPCSTR  lpText,
        LPCSTR  lpCaption,
        UINT    uType
     ) = MessageBoxA;

    // accept
    static SOCKET(WSAAPI* pAccept)(
        SOCKET      s,
        sockaddr* addr,
        int* addrlen
        ) = accept;

    // AdjustTokenPrivileges
    static BOOL(WINAPI* pAdjustTokenPrivileges)(
        HANDLE              TokenHandle,
        BOOL                DisableAllPrivileges,
        PTOKEN_PRIVILEGES   NewState,
        DWORD               BufferLength,
        PTOKEN_PRIVILEGES   PreviousState,
        PDWORD              ReturnLength
        ) = AdjustTokenPrivileges;

    // AttachThreadInput
    static BOOL(WINAPI* pAttachThreadInput)(
        DWORD   idAttach,
        DWORD   idAttachTo,
        BOOL    fAttach
        ) = AttachThreadInput;

    // bind
    static BOOL(WINAPI* pBind)(
        SOCKET              s,
        const sockaddr* addr,
        int                 namelen
        ) = bind;

    // BitBlt
    static BOOL(WINAPI* pBitBlt)(
        HDC     hdc,
        int     x,
        int     y,
        int     cx,
        int     cy,
        HDC     hdcSrc,
        int     x1,
        int     y1,
        DWORD   rop
        ) = BitBlt;
    
    // CertOpenSystemStoreA
    static HCERTSTORE(WINAPI* pCertOpenSystemStoreA)(
        HCRYPTPROV_LEGACY hProv,
        LPCSTR           szSubsystemProtocol
        ) = CertOpenSystemStoreA;

    // CertOpenSystemStoreW
    static HCERTSTORE(WINAPI* pCertOpenSystemStoreW)(
        HCRYPTPROV_LEGACY hProv,
        LPCWSTR           szSubsystemProtocol
        ) = CertOpenSystemStoreW;

    // Connect
    static BOOL(WINAPI* pConnect)(
        _In_        SOCKET          s,
        _In_  const struct sockaddr* name,
        _In_        int             namelen
        ) = connect;

    // ConnectNamedPipe
    static BOOL(WINAPI* pConnectNamedPipe)(
        _In_        HANDLE       hNamedPipe,
        _In_opt_    LPOVERLAPPED lpOverlapped
        ) = ConnectNamedPipe;

    // ControlService
    static BOOL(WINAPI* pControlService)(
        _In_ SC_HANDLE        hService,
        _In_ DWORD            dwControl,
        _Out_ LPSERVICE_STATUS lpServiceStatus
        ) = ControlService;

    // CreateFile
    static HANDLE(WINAPI* pCreateFile)(
        _In_     LPCTSTR               lpFileName,
        _In_     DWORD                 dwDesiredAccess,
        _In_     DWORD                 dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_     DWORD                 dwCreationDisposition,
        _In_     DWORD                 dwFlagsAndAttributes,
        _In_opt_ HANDLE                hTemplateFile
        ) = CreateFile;

    // CreateProcess
    static BOOL(WINAPI* pCreateProcess)(
        _In_opt_     LPCTSTR               lpApplicationName,
        _Inout_opt_  LPTSTR                lpCommandLine,
        _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
        _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
        _In_         BOOL                  bInheritHandles,
        _In_         DWORD                 dwCreationFlags,
        _In_opt_     LPVOID                lpEnvironment,
        _In_opt_     LPCTSTR               lpCurrentDirectory,
        _In_         LPSTARTUPINFO         lpStartupInfo,
        _Out_        LPPROCESS_INFORMATION lpProcessInformation
        ) = CreateProcess;

    // CreateRemoteThread
    static HANDLE(WINAPI* pCreateRemoteThread)(
        _In_        HANDLE                 hProcess,
        _In_opt_    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        _In_        SIZE_T                 dwStackSize,
        _In_        LPTHREAD_START_ROUTINE lpStartAddress,
        _In_opt_    LPVOID                 lpParameter,
        _In_        DWORD                  dwCreationFlags,
        _Out_opt_   LPDWORD                lpThreadId
        ) = CreateRemoteThread;

    // CreateService
    static SC_HANDLE(WINAPI* pCreateService)(
        _In_        SC_HANDLE    hSCManager,
        _In_        LPCTSTR      lpServiceName,
        _In_opt_    LPCTSTR      lpDisplayName,
        _In_        DWORD        dwDesiredAccess,
        _In_        DWORD        dwServiceType,
        _In_        DWORD        dwStartType,
        _In_        DWORD        dwErrorControl,
        _In_opt_    LPCTSTR      lpBinaryPathName,
        _In_opt_    LPCTSTR      lpLoadOrderGroup,
        _Out_opt_   LPDWORD      lpdwTagId,
        _In_opt_    LPCTSTR      lpDependencies,
        _In_opt_    LPCTSTR      lpServiceStartName,
        _In_opt_    LPCTSTR      lpPassword
        ) = CreateService;

    // CreateToolhelp32Snapshot
    static HANDLE(WINAPI* pCreateToolhelp32Snapshot)(
        _In_ DWORD dwFlags,
        _In_ DWORD th32ProcessID
        ) = CreateToolhelp32Snapshot;

    // CryptAcquireContext
    static BOOL(WINAPI* pCryptAcquireContext)(
        _Out_ HCRYPTPROV* phProv,
        _In_  LPCTSTR     pszContainer,
        _In_  LPCTSTR     pszProvider,
        _In_  DWORD       dwProvType,
        _In_  DWORD       dwFlags
        ) = CryptAcquireContext;

    // DeviceIoControl
    static BOOL(WINAPI* pDeviceIoControl)(
        _In_        HANDLE       hDevice,
        _In_        DWORD        dwIoControlCode,
        _In_opt_    LPVOID       lpInBuffer,
        _In_        DWORD        nInBufferSize,
        _Out_opt_   LPVOID       lpOutBuffer,
        _In_        DWORD        nOutBufferSize,
        _Out_opt_   LPDWORD      lpBytesReturned,
        _Inout_opt_ LPOVERLAPPED lpOverlapped
        ) = DeviceIoControl;

    // EnumProcesses
    static BOOL(WINAPI* pEnumProcesses)(
        _Out_ DWORD* lpidProcess,
        _In_  DWORD   cb,
        _Out_ LPDWORD lpcbNeeded
        ) = EnumProcesses;

    // EnumProcessModules
    static BOOL(WINAPI* pEnumProcessModules)(
        _In_  HANDLE  hProcess,
        _Out_ HMODULE* lphModule,
        _In_  DWORD   cb,
        _Out_ LPDWORD lpcbNeeded
        ) = EnumProcessModules;

    // FindFirstFile/FindNextFile
    static HANDLE(WINAPI* pFindFirstFile)(
        _In_ LPCWSTR            lpFileName,
        _Out_ LPWIN32_FIND_DATA lpFindFileData
        ) = FindFirstFile;

    static BOOL(WINAPI* pFindNextFile)(
        _In_  HANDLE            hFindFile,
        _Out_ LPWIN32_FIND_DATA lpFindFileData
        ) = FindNextFile;

    // FindResource
    static HRSRC(WINAPI* pFindResource)(
        _In_ HMODULE hModule,
        _In_ LPCWSTR lpName,
        _In_ LPCWSTR lpType
        ) = FindResource;

    // FindWindow
    static HWND(WINAPI* pFindWindow)(
        _In_opt_ LPCWSTR lpClassName,
        _In_opt_ LPCWSTR lpWindowName
        ) = FindWindow;

    // FtpPutFile
    static BOOL(WINAPI* pFtpPutFile)(
        _In_ HINTERNET hConnect,
        _In_ LPCWSTR   lpszLocalFile,
        _In_ LPCWSTR   lpszNewRemoteFile,
        _In_ DWORD     dwFlags,
        _In_ DWORD_PTR dwContext
        ) = FtpPutFile;

    // GetAdaptersInfo
    static DWORD(WINAPI* pGetAdaptersInfo)(
        _Out_ PIP_ADAPTER_INFO pAdapterInfo,
        _Inout_ PULONG        pOutBufLen
        ) = GetAdaptersInfo;

    // GetAsyncKeyState
    static SHORT(WINAPI* pGetAsyncKeyState)(
        _In_ int vKey
        ) = GetAsyncKeyState;

    // GetDC
    static HDC(WINAPI* pGetDC)(
        _In_opt_ HWND hWnd
        ) = GetDC;

    // GetForegroundWindow
    static HWND(WINAPI* pGetForegroundWindow)() = GetForegroundWindow;

    // Gethostbyname
    static struct hostent* (WINAPI* pGethostbyname)(
        _In_ const char* name
        ) = gethostbyname;

    // Gethostname
    static int(WINAPI* pGethostname)(
        _Out_ char* name,
        _In_  int  namelen
        ) = gethostname;

    // GetKeyState
    static SHORT(WINAPI* pGetKeyState)(
        _In_ int nVirtKey
        ) = GetKeyState;

    // GetModuleFilename
    static DWORD(WINAPI* pGetModuleFileName)(
        _In_opt_ HMODULE hModule,
        _Out_    LPWSTR  lpFilename,
        _In_     DWORD   nSize
        ) = GetModuleFileName;

    // GetModuleHandle
    static HMODULE(WINAPI* pGetModuleHandle)(
        _In_opt_ LPCWSTR lpModuleName
        ) = GetModuleHandle;

    // GetProcAddress
    static FARPROC(WINAPI* pGetProcAddress)(
        _In_ HMODULE hModule,
        _In_ LPCSTR  lpProcName
        ) = GetProcAddress;

    // GetStartupInfo
    static VOID(WINAPI* pGetStartupInfo)(
        _Out_ LPSTARTUPINFO lpStartupInfo
        ) = GetStartupInfo;

    // GetSystemDefaultLangId
    static LANGID(WINAPI* pGetSystemDefaultLangID)() = GetSystemDefaultLangID;

    // GetTempPath
    static DWORD(WINAPI* pGetTempPath)(
        _In_  DWORD  nBufferLength,
        _Out_ LPWSTR lpBuffer
        ) = GetTempPath;

    // GetThreadContext
    static BOOL(WINAPI* pGetThreadContext)(
        _In_    HANDLE    hThread,
        _Inout_ LPCONTEXT lpContext
        ) = GetThreadContext;

    /* Depreciated functions 
    // GetVersionExA
    static BOOL(WINAPI* pGetVersionEx)(
        _Inout_ LPOSVERSIONINFOA lpVersionInformation
        ) = GetVersionExA;
    
    // GetVersionExW
    static BOOL(WINAPI* pGetVersionEx)(
        _Inout_ LPOSVERSIONINFOW lpVersionInformation
        ) = GetVersionExW;
    */

    // GetWindowsDirectory
    static UINT(WINAPI* pGetWindowsDirectory)(
        _Out_ LPWSTR lpBuffer,
        _In_  UINT   uSize
        ) = GetWindowsDirectory;

    // inet_addr
    static ULONG(WINAPI* pinet_addr)(
        _In_ const char* cp
        ) = inet_addr;

    // InternetOpen
    static HINTERNET(WINAPI* pInternetOpen)(
        _In_ LPCWSTR lpszAgent,
        _In_ DWORD   dwAccessType,
        _In_ LPCWSTR lpszProxy,
        _In_ LPCWSTR lpszProxyBypass,
        _In_ DWORD   dwFlags
        ) = InternetOpen;

    // InternetOpenUrl
    static HINTERNET(WINAPI* pInternetOpenUrl)(
        _In_ HINTERNET hInternet,
        _In_ LPCWSTR   lpszUrl,
        _In_ LPCWSTR   lpszHeaders,
        _In_ DWORD     dwHeadersLength,
        _In_ DWORD     dwFlags,
        _In_ DWORD_PTR dwContext
        ) = InternetOpenUrl;

    // InternetReadFile
    static BOOL(WINAPI* pInternetReadFile)(
        _In_  HINTERNET hFile,
        _Out_ LPVOID    lpBuffer,
        _In_  DWORD     dwNumberOfBytesToRead,
        _Out_ LPDWORD   lpdwNumberOfBytesRead
        ) = InternetReadFile;

    // InternetWriteFile
    static BOOL(WINAPI* pInternetWriteFile)(
        _In_  HINTERNET hFile,
        _In_  LPCVOID   lpBuffer,
        _In_  DWORD     dwNumberOfBytesToWrite,
        _Out_ LPDWORD   lpdwNumberOfBytesWritten
        ) = InternetWriteFile;

    // IsUserAnAdmin
    static BOOL(WINAPI* pIsUserAnAdmin)() = IsUserAnAdmin;

    // IsWoW64Process
    static BOOL(WINAPI* pIsWow64Process)(
        _In_  HANDLE hProcess,
        _Out_ PBOOL  Wow64Process
        ) = IsWow64Process;

    /* This is a function from the Native API so it is commented out for now.
    // LdrLoadDll
    static NTSTATUS(WINAPI* pLdrLoadDll)(
        _In_opt_ PWSTR           PathToFile,
        _In_opt_ ULONG           Flags,
        _In_opt_ PUNICODE_STRING ModuleFileName,
        _Out_    PHANDLE         ModuleHandle
        ) = LdrLoadDll;
    */

    // LoadResource
    static HGLOBAL(WINAPI* pLoadResource)(
        _In_opt_ HMODULE hModule,
        _In_     HRSRC   hResInfo
        ) = LoadResource;

    // LsaEnumerateLogonSessions
    static NTSTATUS(WINAPI* pLsaEnumerateLogonSessions)(
        _Out_ PULONG LogonSessionCount,
        _Out_ PLUID* LogonSessionList
        ) = LsaEnumerateLogonSessions;
}