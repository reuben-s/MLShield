#include "pch.h"
#include "DriverGlobalsManager.h"
#include "Locker.h"
#include "Driver.h"

void DriverGlobalsManager::Init(ULONG maxCount)
{
	InitializeListHead(&m_ItemsHead);
	m_LockForManager.Init();
	m_CurrentItemCount = 0;
	m_MaximumItemCount = maxCount;
}

void DriverGlobalsManager::AddItemToList(LIST_ENTRY* entry)
{
	Locker locker(m_LockForManager);
	if (m_CurrentItemCount == m_MaximumItemCount) {
		auto head = RemoveHeadList(&m_ItemsHead);
		ExFreePool(CONTAINING_RECORD(head, NotificationItem<NotificationHeader>, Entry));
		m_CurrentItemCount--;
	}

	InsertTailList(&m_ItemsHead, entry);
	m_CurrentItemCount++;
}

void DriverGlobalsManager::AddItemToHead(LIST_ENTRY* entry)
{
	Locker locker(m_LockForManager);
	InsertHeadList(&m_ItemsHead, entry);
	m_CurrentItemCount++;
}

LIST_ENTRY* DriverGlobalsManager::RemoveItemFromList()
{
	Locker locker(m_LockForManager);
	auto item = RemoveHeadList(&m_ItemsHead);
	if (item == &m_ItemsHead) return nullptr;

	m_CurrentItemCount--;
	return item;
}