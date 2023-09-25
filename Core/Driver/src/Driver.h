#pragma once

#define DRIVER_PREFIX "MLShield: "

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);