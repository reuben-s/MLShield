#include "pch.h"
#include "Driver.h"

// Prototypes

void Unload(PDRIVER_OBJECT DriverObject);
NTSTATUS ioCreateClose(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS ioRead(PDEVICE_OBJECT, PIRP Irp);


// DriverEntry

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

    } while (false);

    // Clean up if there was an error during initialization
    if (!NT_SUCCESS(status))
    {
        if (symLinkCreated) IoDeleteSymbolicLink(&symLink); // Delete the symbolic link if created
        if (DeviceObject) IoDeleteDevice(DeviceObject);     // Delete the device object if created
    }

	return status;

}

// Prototype definitions

// Called when driver is unloaded
void Unload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MLShield");
	IoDeleteSymbolicLink(&symLink);             // Delete symbolic link
	IoDeleteDevice(DriverObject->DeviceObject); // Delete device object
}


// IRP Handlers 

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0) 
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