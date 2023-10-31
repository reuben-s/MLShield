#pragma once

#include "pch.h"
#include "hook_util.h"

class HookManager
{
public:
	BOOL HooksActive;

	HookManager();
	~HookManager();
private:
	ACCEPT fpAccept = NULL;
};
