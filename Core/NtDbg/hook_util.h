#pragma once

#include "pch.h"

// Hooked function pointer types
typedef SOCKET (WSAAPI* ACCEPT)(SOCKET, sockaddr*, int*);

// Hooked function detour logic
SOCKET WSAAPI detour_accept(SOCKET s, sockaddr* addr, int* addrlen);