#pragma once
#include "ReadWrite.h"


typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;


HANDLE minimalist_pid(const char* process_name)
{
	ANSI_STRING AS = { 0 };
	UNICODE_STRING US = { 0 };

	RtlInitAnsiString(&AS, process_name);
	RtlAnsiStringToUnicodeString(&US, &AS, true); // converting to the type used by the process ID in SYSTEM_PROCESS_INFO struct

	ULONG buffer_size = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &buffer_size);  // gets the size of the SYSTEM_PROCESS_INFO struct

	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'MNLR'); // allocates pool memory to buffer
	if (!buffer)
	{
		return 0;
	}
	ZwQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, NULL); // returns pointer to SYSTEM_PROCESS_INFO


	PSYSTEM_PROCESS_INFO process_info = reinterpret_cast<PSYSTEM_PROCESS_INFO>(buffer);

	if (!process_info)
	{
		ExFreePoolWithTag(buffer, 'MNLR');
		return 0;
	}

	while (process_info->NextEntryOffset) // loops through all the processes
	{
		if (!RtlCompareUnicodeString(&US, &process_info->ImageName, TRUE))
		{
			ExFreePoolWithTag(buffer, 'MNLR');
			return process_info->ProcessId;
		}

		process_info = (PSYSTEM_PROCESS_INFO)((BYTE*)process_info + process_info->NextEntryOffset); // sets it to the address of the next struct

	}

	RtlFreeUnicodeString(&US);
	RtlFreeAnsiString(&AS);
	ExFreePoolWithTag(buffer, 'MNLR');
	return 0;
}

PVOID minimalist_base(uintptr_t PID)
{
	if (!PID)
	{
		DbgPrint("DID NOT FIND PID!");
		return 0;
	}

	PEPROCESS TempProcess;
	if (!PsLookupProcessByProcessId((HANDLE)PID, &TempProcess))
	{
		DbgPrint("DID NOT FIND PEPROCESS!");
		return 0;
	}

	PVOID BaseAddress = PsGetProcessSectionBaseAddress(TempProcess);

	if (!BaseAddress)
	{
		DbgPrint("INVALID BASE!");
		return 0;
	}

	return BaseAddress;
}


namespace big_pools
{
	typedef struct _bigpool_info {
		void* start_addr;
		size_t size;
		void* thread_start_addr;
	} bigpool_inf, pbigpool_inf;

	PSYSTEM_BIGPOOL_INFORMATION g_bigpool_info{};

	void query_bigpools()
	{
		SYSTEM_BIGPOOL_INFORMATION _bpi{};

		ULONG size{};
		NTSTATUS status = ZwQuerySystemInformation(SystemBigPoolInformation, &_bpi,
			sizeof(_bpi), &size);
		PSYSTEM_BIGPOOL_INFORMATION bigpool_info =
			reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(
				ExAllocatePoolZero(NonPagedPool, size, 'loop'));

		status = ZwQuerySystemInformation(SystemBigPoolInformation, bigpool_info,
			size, &size);

		if (g_bigpool_info && MmIsAddressValid(g_bigpool_info))
			ExFreePool(g_bigpool_info);

		g_bigpool_info = bigpool_info;
	}
}

uintptr_t retrieve_guarded()
{
	big_pools::query_bigpools();
	auto pool_information = big_pools::g_bigpool_info;
	uintptr_t guarded = 0;

	if (pool_information)
	{
		auto count = pool_information->Count;
		for (auto i = 0ul; i < count; i++)
		{
			SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[i];
			const auto virtual_address = (PVOID)((uintptr_t)allocation_entry->VirtualAddress & ~1ull);
			if (allocation_entry->NonPaged && allocation_entry->SizeInBytes == 0x200000)
				if (allocation_entry->TagUlong == 'TnoC')
				{
					guarded = reinterpret_cast<uintptr_t>(virtual_address);
					break;
				}
		}
	}

	return guarded;
}