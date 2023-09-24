#pragma once

#include "pch.h"

enum class EventType : short {
	None,
	ProcessCreate,
	ProcessExit
};

struct EventHeader {
	EventType Type;
	USHORT Size;
	LARGE_INTEGER Time;
};

struct ProcessExitInfo : EventHeader {
	ULONG ProcessId;
	ULONG ExitCode;
};