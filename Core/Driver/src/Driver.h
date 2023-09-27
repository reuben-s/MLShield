#pragma once

#include "Common.h"

#define DRIVER_PREFIX "MLShield: "
#define DRIVER_TAG 'ARn0'

NTSTATUS ioCreateClose(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS ioRead(PDEVICE_OBJECT, PIRP Irp);
void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
void OnImageLoadNotify(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
void Unload(PDRIVER_OBJECT DriverObject);

template<typename T>
struct NotificationItem 
{
	LIST_ENTRY Entry;
	T Data;
};

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);