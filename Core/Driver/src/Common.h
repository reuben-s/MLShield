#pragma once

enum class NotificationType : short 
{
	None,
	ProcessCreate,
	ProcessExit,
	ThreadCreate,
	ThreadExit,
	ImageLoad
};

struct NotificationHeader 
{
	NotificationType Type;
	USHORT Size;
	LARGE_INTEGER Time;
};

struct ProcessExitInfo : NotificationHeader
{
	ULONG ProcessId;
	ULONG ExitCode;
};

struct ProcessCreateInfo : NotificationHeader
{
	ULONG ProcessId;
	ULONG ParentProcessId;
	ULONG CreatingThreadId;
	ULONG CreatingProcessId;
	USHORT CommandLineLength;
	WCHAR CommandLine[1];
};

struct ThreadCreateInfo : NotificationHeader
{
	ULONG ThreadId;
	ULONG ProcessId;
};

struct ThreadExitInfo : ThreadCreateInfo 
{
	ULONG ExitCode;
};

const int MaxImageFileSize = 300;

struct ImageLoadInfo : NotificationHeader
{
	ULONG ProcessId;
	ULONG ImageSize;
	ULONG64 LoadAddress;
	WCHAR ImageFileName[MaxImageFileSize + 1];
};