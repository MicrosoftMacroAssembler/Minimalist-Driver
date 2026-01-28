//#include <ntddk.h>
#include "Gizmo.h"

NTSTATUS Minimalist(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("DriverEntry called\n");
    //DbgPrint("PVOID: %p", minimalist_base(1820));
    //loop_enum_process_dirbase();
    // Add your driver initialization code here
    return InitMinimalist();
}
