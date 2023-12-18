#ifndef PCH_H
#define PCH_H

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <wingdi.h>
#include <TlHelp32.h>
#include <wincrypt.h>
#include <wininet.h>
#include <NTSecAPI.h>
#include <iphlpapi.h>
#include <shlobj_core.h>
#include <psapi.h>
#include <winnls.h>
#include <sysinfoapi.h>
#include <urlmon.h>
#include <LMat.h>
#include <LMShare.h>
#include <Windows.h>
#define WIN32_NO_STATUS
#define DETOURS_INTERNAL
#include "detours/detours.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Netapi32.lib")

#endif //PCH_H
