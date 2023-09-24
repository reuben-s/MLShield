#include "pch.h"

#define DRIVER_PREFIX "MLShield: "

// Prototypes

void Unload(PDRIVER_OBJECT DriverObject);
DRIVER_DISPATCH ioCreateClose, ioRead, ioWrite, ioDeviceControl;

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
	DriverObject->MajorFunction[IRP_MJ_WRITE]  = ioWrite;

    // Symbolic link for user mode communication
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MLShield");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MLShield");
    PDEVICE_OBJECT DeviceObject = nullptr;
    auto status = STATUS_SUCCESS;

    do
    {
        // Create a device object named "\\Device\\MLShield"
        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
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
    } while (false);

    // Clean up if there was an error during initialization
    if (!NT_SUCCESS(status))
    {
        if (DeviceObject) IoDeleteDevice(DeviceObject); // Delete the device object if created
    }

	return status;
}

// Prototype definitions

void Unload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MLShield");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}