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
#include <Windows.h>
#include "detours/detours.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Iphlpapi.lib")


#endif //PCH_H
