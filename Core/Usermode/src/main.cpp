#include <Windows.h>
#include <stdio.h>
#include <memory>
#include "..\..\Driver\src\Common.h"
#include <string>
#include <unordered_map>

int Error(const char* text) 
{
	printf("%s (%u)\n", text, GetLastError());
	return 1;
}

void DisplayTime(const LARGE_INTEGER& time) 
{
	FILETIME local;
	FileTimeToLocalFileTime((FILETIME*)&time, &local);
	SYSTEMTIME st;
	FileTimeToSystemTime(&local, &st);
	printf("%02d:%02d:%02d.%03d: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void DisplayInfo(BYTE* buffer, DWORD size) 
{
	while (size > 0) 
	{
		auto header = (NotificationHeader*)buffer;
		switch (header->Type) {
		case NotificationType::ProcessExit:
		{
			DisplayTime(header->Time);
			auto info = (ProcessExitInfo*)buffer;
			printf("Process %u Exited (Code: %u)\n", info->ProcessId, info->ExitCode);
			break;
		}

		case NotificationType::ProcessCreate:
		{
			DisplayTime(header->Time);
			auto info = (ProcessCreateInfo*)buffer;
			std::wstring commandline(info->CommandLine, info->CommandLineLength);
			printf("Process %u Created. Command line: %ws\n", info->ProcessId, commandline.c_str());
			break;
		}
		default:
			break;
		}
		buffer += header->Size;
		size -= header->Size;
	}
}

int main() {
	auto hFile = CreateFile(L"\\\\.\\MLShield", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE) return Error("Failed to open file");

	int size = 1 << 16;	// 64 KB
	auto buffer = std::make_unique<BYTE[]>(size);

	while (true) 
	{
		DWORD bytes = 0;

		if (!ReadFile(hFile, buffer.get(), size, &bytes, nullptr)) return Error("Failed to read");
		if (bytes) DisplayInfo(buffer.get(), bytes);

		Sleep(400);
	}
	CloseHandle(hFile);
	return 0;
}
