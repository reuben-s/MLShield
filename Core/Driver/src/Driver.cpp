#include "pch.h"

#define DRIVER_PREFIX "MLShield: "

// Prototypes

void MLShieldUnload(PDRIVER_OBJECT DriverObject);
DRIVER_DISPATCH MLShieldCreateClose, MLShieldRead, MLShieldWrite, MLShieldDeviceControl;

// DriverEntry

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	// Configure driver object
	DriverObject->DriverUnload = MLShieldUnload;

	// I/O Handlers
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = MLShieldCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ]   = MLShieldRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE]  = MLShieldWrite;

	// Symbolic link for user mode communication
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MLShield");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MLShield");
	PDEVICE_OBJECT DeviceObject = nullptr;
	auto status = STATUS_SUCCESS;

	do 
	{
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "failed to create device (0x%08X)\n", status));
			break;
		}

		// set up Direct I/O
		DeviceObject->Flags |= DO_DIRECT_IO;
		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "failed to create symbolic link (0x%08X)\n", status));
			break;
		}
	} while (false);
	if (!NT_SUCCESS(status)) 
	{
			if (DeviceObject) IoDeleteDevice(DeviceObject);
	}

	return status;
}

void MLShieldUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MLShield");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}