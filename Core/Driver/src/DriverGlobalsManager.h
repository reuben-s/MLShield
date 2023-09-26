#pragma once

#include "FastMutex.h"

struct DriverGlobalsManager 
{
	void Init(ULONG maxItems = 10000);

	void AddItemToList(LIST_ENTRY* entry);
	void AddItemToHead(LIST_ENTRY* entry);
	LIST_ENTRY* RemoveItemFromList();

private:
	LIST_ENTRY m_ItemsHead;
	ULONG m_CurrentItemCount;
	ULONG m_MaximumItemCount;
	FastMutex m_LockForManager;
};