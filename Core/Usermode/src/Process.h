#pragma once

#include <Windows.h>

class Process
{
public:
	int id;

	Process(ULONG pid);
	void AttatchDebugger();
};