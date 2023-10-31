#include "pch.h"
#include "hook_util.h"

SOCKET WSAAPI detour_accept(SOCKET s, sockaddr* addr, int* addrlen)
{
	// do something
	return accept(s, addr, addrlen);
}