#pragma once
#include "ProcessID.h"



enum requests
{
	REQUEST_BASE,
	REQUEST_PID,
	REQUEST_READ,
	REQUEST_WRITE,
	REQUEST_CR3,
	REQUEST_PROBE,
	REQUEST_GUARDED
};

struct Minimalist_CMD
{
	int magic_code;
	uintptr_t request;
	uintptr_t address;
	uintptr_t PID;
	const char* processName;
	const char* moduleName;
	void* pBuffer;
	uintptr_t size_of_buffer;
};

LARGE_INTEGER cookie;
UNICODE_STRING key = { 0 };

ULONGLONG process_base;

const UINT64 minimalist_cr3(const PEPROCESS pProcess)
{
	//KAPC_STATE apc{};

	uintptr_t process_dirbase = *(uintptr_t*)((UINT8*)pProcess + 0x28);
	if (process_dirbase == 0)
	{
		ULONG user_diroffset = GetUserDirectoryTableBaseOffset();
		process_dirbase = *(uintptr_t*)((UINT8*)pProcess + user_diroffset);
	}
	else if ((process_dirbase >> 0x38) == 0x40)
	{
		KAPC_STATE apc_state{};

		KeStackAttachProcess(pProcess, &apc_state);

		process_dirbase = (UINT64)__readcr3();

		KeUnstackDetachProcess(&apc_state);


		//KeStackAttachProcess(pProcess, &apc);
		//process_dirbase = (UINT64)__readcr3();
		//KeUnstackDetachProcess(&apc);
		//process_dirbase = (UINT64)enum_process_dirbase(pProcess);
	}
	return process_dirbase;
}

//KIRQL currentIrql;
//KIRQL newIrql = DISPATCH_LEVEL;

_Use_decl_annotations_
NTSTATUS
Minimalist_Callback(PVOID  CallbackContext, PVOID  Argument1, PVOID  Argument2)
{
	if (Argument1 != (PVOID)RegNtSetValueKey)
	{
		return STATUS_SUCCESS;
	}

	REG_SET_VALUE_KEY_INFORMATION* preInfo = (REG_SET_VALUE_KEY_INFORMATION*)Argument2;

	if (RtlEqualUnicodeString(preInfo->ValueName, &key, TRUE) == 0)
	{
		return STATUS_SUCCESS;
	}
	Minimalist_CMD* request = *(Minimalist_CMD**)preInfo->Data;
	if (!request)
	{
		return STATUS_SUCCESS;
	}
	if (request->magic_code != 1337)
	{
		return STATUS_SUCCESS;
	}
	__try
	{
		//KeLowerIrql(PASSIVE_LEVEL);
		//KeRaiseIrql(APC_LEVEL, &currentIrql);

		if (request->request == REQUEST_PID)
		{
			//DbgPrint("CALLED PID");
			request->PID = (uintptr_t)minimalist_pid(request->processName);
		}
		if (request->request == REQUEST_CR3)
		{
			__try
			{
				//DbgPrint("CALLED CR3");
				PEPROCESS process = NULL;
				PsLookupProcessByProcessId((HANDLE)request->PID, &process);
				if (!process)
				{
					return STATUS_UNSUCCESSFUL;
				}
				process_base = minimalist_dtb(process);
				request->pBuffer = (PVOID)process_base;
				ObDereferenceObject(process);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return STATUS_UNSUCCESSFUL;
			}

		}
		if (request->request == REQUEST_BASE)
		{
			//DbgPrint("CALLED BASE");
			request->pBuffer = minimalist_base(request->PID);
		}
		if (request->request == REQUEST_READ)
		{
			__try
			{
				if (!process_base)
				{
					PEPROCESS process = NULL;
					PsLookupProcessByProcessId((HANDLE)request->PID, &process);
					if (!process)
					{
						return STATUS_UNSUCCESSFUL;
					}
					process_base = minimalist_dtb(process);
					request->pBuffer = (PVOID)process_base;
					ObDereferenceObject(process);
				}
				//DbgPrint("CALLED READ");
				SIZE_T this_offset = NULL;
				SIZE_T total_size = request->size_of_buffer;
				PVOID virtualaddress = (PVOID)request->address;
				INT64 physical_address = translate_linear_address(process_base, (ULONG64)request->address + this_offset);

				if (!physical_address)
				{
					return STATUS_UNSUCCESSFUL;
				}
				ULONG64 final_size = min(PAGE_SIZE - (physical_address & 0xFFF), total_size);
				SIZE_T submitted_bytes = 0;
				NTSTATUS NtRet = get_phys_addr(PVOID(physical_address), (PVOID)((ULONG64)request->pBuffer + this_offset), final_size, &submitted_bytes);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				// Exception handling code here
				return STATUS_UNSUCCESSFUL; // Or any appropriate error code
			}
		}
		if (request->request == REQUEST_WRITE)
		{
			//DbgPrint("CALLED WRITE");
			SIZE_T this_offset = NULL;
			SIZE_T total_size = request->size_of_buffer;
			INT64 physical_address = translate_linear_address(process_base, (ULONG64)request->address + this_offset);
			if (!physical_address)
				return STATUS_UNSUCCESSFUL;
			ULONG64 final_size = min(PAGE_SIZE - (physical_address & 0xFFF), total_size);
			SIZE_T submitted_bytes = NULL;
			WritePhysicalAddress((PVOID)physical_address, (PVOID)((ULONG64)request->pBuffer + this_offset), final_size, &submitted_bytes);
		}
		if (request->request == REQUEST_PROBE)
		if (request->request == REQUEST_GUARDED)
		{
			//DbgPrint("CALLED PROBE");
			request->pBuffer = (PVOID)retrieve_guarded();
		}

		request->magic_code = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}

}
