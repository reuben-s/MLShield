#pragma once

#include "pch.h"
#include "NamedPipe.h"
#include "WinApiDetouredFunctions.h"

class HookManager
{
public:
	HookManager(Pipe* pPipe);
	~HookManager();
};

extern HookManager* pHookManager;