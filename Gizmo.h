#pragma once
#include "Communication.h"




PVOID FindJmp(PVOID moduleBase) {
	CONST PIMAGE_NT_HEADERS ntHeader = RtlImageNtHeader(moduleBase);
	CONST PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(ntHeader);

	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeader->FileHeader.NumberOfSections; section++)
	{
		if (!section)
			continue;

		if (!(section->Characteristics & 0x20000000) || !(section->Characteristics & 0x08000000))
			continue;

		CONST UINT64 sectionStart = (UINT64)moduleBase + section->VirtualAddress;
		CONST UINT64 sectionSize = section->SizeOfRawData;

		for (UINT64 current = sectionStart; current < (sectionStart + sectionSize); current++)
		{
			if (*(USHORT*)current == 0xe1ff) // jmp ecx: FF E1
				return (PVOID)current;
		}
	}

	return (PVOID)NULL;
}

void* get_system_information(SYSTEM_INFORMATION_CLASS information_class)
{
	unsigned long size = 32;
	char buffer[32];

	ZwQuerySystemInformation(information_class, buffer, size, &size);

	void* info = ExAllocatePoolZero(NonPagedPool, size, 'mnls');
	if (!info)
		return nullptr;

	if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size))) {
		ExFreePool(info);
		return nullptr;
	}

	return info;
}

uintptr_t get_kernel_module(const char* name)
{
	const auto to_lower = [](char* string) -> const char* {
		for (char* pointer = string; *pointer != '\0'; ++pointer) {
			*pointer = (char)(short)tolower(*pointer);
		}

		return string;
		};

	const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)get_system_information(SystemModuleInformation);

	if (!info)
		return NULL;

	for (size_t i = 0; i < info->NumberOfModules; ++i) {
		const auto& mod = info->Modules[i];

		if (strcmp(to_lower((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0) {
			const void* address = mod.ImageBase;
			ExFreePool(info);
			return (uintptr_t)address;
		}
	}

	ExFreePool(info);
	return NULL;
}


NTSTATUS InitMinimalist()
{
	auto nvraid_base = (char*)get_kernel_module("ndis.sys");
	//auto nvraid_base2 = (char*)get_kernel_module("nvvhci.sys");

	if (!nvraid_base)
		return 0xC0000008;
		
	//if (!nvraid_base2)
		//return 0xC0000008;

	auto jmp_rcx = FindJmp(nvraid_base);
	//auto jmp_rcx2 = FindJmp(nvraid_base2);

	if (jmp_rcx == NULL)
		return 0xC0000225;	
	//if (jmp_rcx2 == NULL)
		//return 0xC0000225;

	RtlInitUnicodeString(&key, L"OraclVal");
	return CmRegisterCallback((PEX_CALLBACK_FUNCTION)jmp_rcx, Minimalist_Callback, &cookie);
}
