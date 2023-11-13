#pragma once

#include "pch.h"
#include "NamedPipe.h"
#include "detours/detours.h"

class HookManager
{
public:
	HookManager(Pipe* pPipe);
	~HookManager();
};

extern HookManager* pHookManager;
extern Pipe* pPipe;