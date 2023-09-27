#include "pch.h"
#include "Driver.h"
#include "DriverGlobalsManager.h"

// DriverEntry

DriverGlobalsManager dgmObj;

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	// Configure driver object
	DriverObject->DriverUnload = Unload;

	// I/O Handlers
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = ioCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ]   = ioRead;

    // Symbolic link for user mode communication
    UNICODE_STRING devName      = RTL_CONSTANT_STRING(L"\\Device\\MLShield");
    UNICODE_STRING symLink      = RTL_CONSTANT_STRING(L"\\??\\MLShield");
    PDEVICE_OBJECT DeviceObject = nullptr;
    bool symLinkCreated         = false;
    bool processCallbacks       = false;
    bool threadCallbacks        = false;

    auto status = STATUS_SUCCESS;

    do
    {
        // Create a device object named "\\Device\\MLShield"
        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
        if (!NT_SUCCESS(status))
        {
            // If device creation fails, print an error message and exit the loop
            KdPrint((DRIVER_PREFIX "failed to create device (0x%08X)\n", status));
            break;
        }

        // Set up Direct I/O for the device
        DeviceObject->Flags |= DO_DIRECT_IO;

        // Create a symbolic link "\\??\\MLShield" for user-mode access to the device
        status = IoCreateSymbolicLink(&symLink, &devName);
        if (!NT_SUCCESS(status))
        {
            // If symbolic link creation fails, print an error message and exit the loop
            KdPrint((DRIVER_PREFIX "failed to create symbolic link (0x%08X)\n", status));
            break;
        }
        symLinkCreated = true;

        status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
        if (!NT_SUCCESS(status)) 
        {
            KdPrint((DRIVER_PREFIX "failed to register process callback (0x%08X)\n", status));
            break;
        }
        processCallbacks = true;

        status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
        if (!NT_SUCCESS(status)) 
        {
            KdPrint((DRIVER_PREFIX "failed to set thread callback (status=%08X)\n", status));
            break;
        }
        threadCallbacks = true;

        status = PsSetLoadImageNotifyRoutine(OnImageLoadNotify);
        if (!NT_SUCCESS(status)) 
        {
            KdPrint((DRIVER_PREFIX "failed to set image load callback (status=%08X)\n", status));
            break;
        }

    } while (false);

    // Clean up if there was an error during initialization
    if (!NT_SUCCESS(status))
    {
        if (threadCallbacks) PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
        if (processCallbacks) PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
        if (symLinkCreated) IoDeleteSymbolicLink(&symLink); // Delete the symbolic link if created
        if (DeviceObject) IoDeleteDevice(DeviceObject);     // Delete the device object if created
    }

    dgmObj.Init(); // Init linked list in device global manager

	return status;

}

// Prototype definitionsNotificationType

// Called when driver is unloaded
void Unload(PDRIVER_OBJECT DriverObject)
{
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE); // Delete process create callback
    PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
    PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);

    LIST_ENTRY* entry;
    while ((entry = dgmObj.RemoveItemFromList()) != nullptr)ExFreePool(CONTAINING_RECORD(entry, NotificationItem<NotificationHeader>, Entry));

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MLShield");
	IoDeleteSymbolicLink(&symLink);                           // Delete symbolic link
	IoDeleteDevice(DriverObject->DeviceObject);               // Delete device object
}


// IRP Handlers 

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info) 
{
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS ioCreateClose(PDEVICE_OBJECT, PIRP Irp) 
{
    return CompleteRequest(Irp);
}

NTSTATUS ioRead(PDEVICE_OBJECT, PIRP Irp)
{
    auto irpSp = IoGetCurrentIrpStackLocation(Irp);
    auto len = irpSp->Parameters.Read.Length;
    auto status = STATUS_SUCCESS;
    ULONG bytes = 0;
    NT_ASSERT(Irp->MdlAddress); // using Direct I/O
    auto buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    // User's read operation will block while the notification list is empty.
    while (dgmObj.IsListEmpty()) continue;

    if (!buffer)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        while (true)
        {
            auto entry = dgmObj.RemoveItemFromList();
            if (entry == nullptr) break;
            // get pointer to the actual data item
            auto info = CONTAINING_RECORD(entry, NotificationItem<NotificationHeader>, Entry);
            auto size = info->Data.Size;
            if (len < size)
            {
                // user's buffer too small, insert item back
                dgmObj.AddItemToHead(entry);
                break;
            }
            memcpy(buffer, &info->Data, size);
            len -= size;
            buffer += size;
            bytes += size;
            ExFreePool(info);
        }
    }
    return CompleteRequest(Irp, status, bytes);
}


// Notification handlers

void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo) 
    {
        // process create

        USHORT allocSize = sizeof(NotificationItem<ProcessCreateInfo>);
        USHORT commandLineSize = 0;
        if (CreateInfo->CommandLine)
        {
            commandLineSize = CreateInfo->CommandLine->Length;
            allocSize += commandLineSize + sizeof(WCHAR); // Allocate space for null terminator
        }

        auto info = (NotificationItem<ProcessCreateInfo>*)ExAllocatePoolWithTag(PagedPool, allocSize, DRIVER_TAG);
        if (info == nullptr) 
        {
            KdPrint((DRIVER_PREFIX "failed allocation\n"));
            return;
        }

        auto& item = info->Data;
        KeQuerySystemTimePrecise(&item.Time);
        item.Type = NotificationType::ProcessCreate;
        item.Size = sizeof(ProcessCreateInfo) + commandLineSize + sizeof(WCHAR); // Include space for null terminator
        item.ProcessId = HandleToULong(ProcessId);
        item.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        item.CreatingProcessId = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
        item.CreatingThreadId = HandleToULong(CreateInfo->CreatingThreadId.UniqueThread);

        if (commandLineSize > 0)
        {
            // Copy the command line string into item.CommandLine
            memcpy(item.CommandLine, CreateInfo->CommandLine->Buffer, commandLineSize);

            // Add the null terminator at the end
            item.CommandLine[commandLineSize / sizeof(WCHAR)] = L'\0'; // Null-terminate the string
        }
        else
        {
            item.CommandLine[0] = L'\0'; // Null-terminate an empty string
        }

        dgmObj.AddItemToList(&info->Entry);
    }
    else 
    {
        // process exit

		auto info = (NotificationItem<ProcessExitInfo>*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(NotificationItem<ProcessExitInfo>), DRIVER_TAG);
		if (info == nullptr) 
        {
			KdPrint((DRIVER_PREFIX "failed allocation\n"));
			return;
		}

        auto& item = info->Data;
        KeQuerySystemTimePrecise(&item.Time);
        item.Type      = NotificationType::ProcessExit;
        item.ProcessId = HandleToULong(ProcessId);
        item.Size      = sizeof(ProcessExitInfo);
        item.ExitCode  = PsGetProcessExitStatus(Process);

        dgmObj.AddItemToList(&info->Entry);
    }
}

void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) 
{
    auto size = Create ? sizeof(NotificationItem<ThreadCreateInfo>) : sizeof(NotificationItem<ThreadExitInfo>);
    auto info = (NotificationItem<ThreadExitInfo>*)ExAllocatePool2(POOL_FLAG_PAGED, size, DRIVER_TAG);
    if (info == nullptr) 
    {
        KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
        return;
    }
    auto& item = info->Data;
    KeQuerySystemTimePrecise(&item.Time);
    item.Size = Create ? sizeof(ThreadCreateInfo) : sizeof(ThreadExitInfo);
    item.Type = Create ? NotificationType::ThreadCreate : NotificationType::ThreadExit;
    item.ProcessId = HandleToULong(ProcessId);
    item.ThreadId = HandleToULong(ThreadId);
    if (!Create) 
    {
        PETHREAD thread;
        if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread))) 
        {
            item.ExitCode = PsGetThreadExitStatus(thread);
            ObDereferenceObject(thread);
        }
    }
    dgmObj.AddItemToList(&info->Entry);
}

void OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (ProcessId == nullptr) 
    {
        // system image, ignore
        return;
    }

    auto size = sizeof(NotificationItem<ImageLoadInfo>);
    auto info = (NotificationItem<ImageLoadInfo>*)ExAllocatePool2(POOL_FLAG_PAGED, size, DRIVER_TAG);
    if (info == nullptr) 
    {
        KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
        return;
    }

    auto& item = info->Data;
    KeQuerySystemTimePrecise(&item.Time);
    item.Size = sizeof(item);
    item.Type = NotificationType::ImageLoad;
    item.ProcessId = HandleToULong(ProcessId);
    item.ImageSize = (ULONG)ImageInfo->ImageSize;
    item.LoadAddress = (ULONG64)ImageInfo->ImageBase;
    item.ImageFileName[0] = 0;

    if (ImageInfo->ExtendedInfoPresent) 
    {
        auto exinfo = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
        PFLT_FILE_NAME_INFORMATION nameInfo;
        if (NT_SUCCESS(FltGetFileNameInformationUnsafe(exinfo->FileObject, nullptr, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) 
        {
            wcscpy_s(item.ImageFileName, nameInfo->Name.Buffer);
            FltReleaseFileNameInformation(nameInfo);
        }
    }
    if (item.ImageFileName[0] == 0 && FullImageName) 
    {
        wcscpy_s(item.ImageFileName, FullImageName->Buffer);
    }

    dgmObj.AddItemToList(&info->Entry);
}