#include "pch.h"
#include "HookManager.h"

HookManager::HookManager()
{
	this->HooksActive = FALSE;

	if (MH_Initialize() != MH_OK)
	{
		return;
	}

	// Start creating hooks if initialisation successfull.
	MH_CreateHook(static_cast<ACCEPT>(&accept), &detour_accept, reinterpret_cast<LPVOID*>(&this->fpAccept));

	MH_EnableHook(MH_ALL_HOOKS);
}

HookManager::~HookManager()
{
	if (this->fpAccept != NULL) MH_DisableHook(static_cast<ACCEPT>(&accept));
	MH_Uninitialize();
}