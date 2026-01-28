#pragma once

#include "Extfuncts.h"
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180
#define WINDOWS_22H2 19045
#define WINDOWS_23H2 25951





const DWORD GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);
	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	case WINDOWS_22H2:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

//uintptr_t enum_process_dirbase(const PEPROCESS pProcess) {
//
//	init_pte_base();
//	init_mmpfn_database();
//	uintptr_t realdirbase;
//	auto mem_range = MmGetPhysicalMemoryRanges();
//	auto mem_range_count = 0;
//	static const uint64_t cr3_ptebase = self_mapidx * 8 + pxe_base;
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "cr3 ptebase 0x%llx\n", cr3_ptebase);
//
//	for (mem_range_count = 0; mem_range_count < 200; mem_range_count++) {
//
//		if (mem_range[mem_range_count].BaseAddress.QuadPart == 0 && mem_range[mem_range_count].NumberOfBytes.QuadPart == 0)
//			break;
//
//		auto start_pfn = mem_range[mem_range_count].BaseAddress.QuadPart >> 12;
//		auto end_pfn = start_pfn + (mem_range[mem_range_count].NumberOfBytes.QuadPart >> 12);
//
//		for (auto i = start_pfn; i < end_pfn; i++) {
//			auto cur_mmpfn = reinterpret_cast<_MMPFN*>(mm_pfn_database + 0x30 * i);
//			if (cur_mmpfn->flags) {
//				if (cur_mmpfn->flags == 1) continue;
//				if (cur_mmpfn->pte_address != cr3_ptebase) continue;
//				auto decrypted_eprocess = ((cur_mmpfn->flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
//				auto dirbase = i << 12;
//				if (MmIsAddressValid(reinterpret_cast<void*>(decrypted_eprocess))) {
//					// Check if the process name starts with "FortniteClient"
//					CHAR* processName = PsGetProcessImageFileName(decrypted_eprocess);
//					CHAR* desiredname = GetProcessNameFromPid(pProcess);
//					if (processName &&
//						processName[0] == desiredname[0] &&
//						processName[1] == desiredname[1] &&
//						processName[2] == desiredname[2] &&
//						processName[3] == desiredname[3] &&
//						processName[4] == desiredname[4] &&
//						processName[5] == desiredname[5] &&
//						processName[6] == desiredname[6] &&
//						processName[7] == desiredname[7] &&
//						processName[8] == desiredname[8] &&
//						processName[9] == desiredname[9] &&
//						processName[10] == desiredname[10] &&
//						processName[11] == desiredname[11] &&
//						processName[12] == desiredname[12] &&
//						processName[13] == desiredname[13]
//						) {
//						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Process -> 0x%llx\nProcessName -> %s\nDirBase -> 0x%llx\n\n", decrypted_eprocess, processName, (UINT64)dirbase);
//						// Break after printing the first result
//						realdirbase = dirbase;
//						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nRealDirBase -> 0x%llx\n\n", realdirbase);
//						break;
//					}
//				}
//			}
//		}
//		// Break the outer loop after printing the first result
//	}
//	return realdirbase;
//}
//
//
//
//void loop_enum_process_dirbase() {
//	init_pte_base();
//	init_mmpfn_database();
//	auto mem_range = MmGetPhysicalMemoryRanges();
//	auto mem_range_count = 0;
//	static const uint64_t cr3_ptebase = self_mapidx * 8 + pxe_base;
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "cr3 ptebase 0x%llx\n", cr3_ptebase);
//
//	for (mem_range_count = 0; mem_range_count < 200; mem_range_count++) {
//
//		if (mem_range[mem_range_count].BaseAddress.QuadPart == 0 && mem_range[mem_range_count].NumberOfBytes.QuadPart == 0)
//			break;
//
//		auto start_pfn = mem_range[mem_range_count].BaseAddress.QuadPart >> 12;
//		auto end_pfn = start_pfn + (mem_range[mem_range_count].NumberOfBytes.QuadPart >> 12);
//
//		for (auto i = start_pfn; i < end_pfn; i++) {
//			auto cur_mmpfn = reinterpret_cast<_MMPFN*>(mm_pfn_database + 0x30 * i);
//			if (cur_mmpfn->flags) {
//				if (cur_mmpfn->flags == 1) continue;
//				if (cur_mmpfn->pte_address != cr3_ptebase) continue;
//				auto decrypted_eprocess = ((cur_mmpfn->flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
//				auto dirbase = i << 12;
//				if (MmIsAddressValid(reinterpret_cast<void*>(decrypted_eprocess))) {
//					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Process -> 0x%llx\nProcessName -> %s\nDirBase -> 0x%llx\n\n", decrypted_eprocess, PsGetProcessImageFileName(decrypted_eprocess), dirbase);
//				}
//			}
//		}
//
//
//	}
//}
//




PVOID UtilMemMem(PVOID SearchBase, SIZE_T SearchSize, const void* Pattern, SIZE_T PatternSize)
{
	const UCHAR* searchBase = static_cast<const UCHAR*>(SearchBase);
	const UCHAR* pattern = static_cast<const UCHAR*>(Pattern);

	for (SIZE_T i = 0; i <= SearchSize - PatternSize; ++i)
	{
		SIZE_T j = 0;
		for (; j < PatternSize; ++j)
		{
			if (searchBase[i + j] != pattern[j])
				break;
		}

		if (j == PatternSize)
			return const_cast<UCHAR*>(&searchBase[i]);
	}

	return nullptr;
}


void* g_mmonp_MmPfnDatabase;

NTSTATUS init_mmpfn_database_2()
{
	struct MmPfnDatabaseSearchPattern
	{
		const UCHAR* bytes;
		SIZE_T bytes_size;
		bool hard_coded;
	};

	MmPfnDatabaseSearchPattern patterns;

	// Windows 10 x64 Build 14332+
	static const UCHAR kPatternWin10x64[] = {
		0x48, 0x8B, 0xC1,        // mov     rax, rcx
		0x48, 0xC1, 0xE8, 0x0C,  // shr     rax, 0Ch
		0x48, 0x8D, 0x14, 0x40,  // lea     rdx, [rax + rax * 2]
		0x48, 0x03, 0xD2,        // add     rdx, rdx
		0x48, 0xB8,              // mov     rax, 0FFFFFA8000000008h
	};

	patterns.bytes = kPatternWin10x64;
	patterns.bytes_size = sizeof(kPatternWin10x64);
	patterns.hard_coded = true;

	const auto p_MmGetVirtualForPhysical = reinterpret_cast<UCHAR*>(((MmGetVirtualForPhysical)));

	if (!p_MmGetVirtualForPhysical) {
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	auto found = reinterpret_cast<UCHAR*>(UtilMemMem(p_MmGetVirtualForPhysical, 0x20, patterns.bytes, patterns.bytes_size));
	if (!found) {
		return STATUS_UNSUCCESSFUL;
	}


	found += patterns.bytes_size;
	if (patterns.hard_coded) {
		g_mmonp_MmPfnDatabase = *reinterpret_cast<void**>(found);
	}
	else {
		const auto mmpfn_address = *reinterpret_cast<ULONG_PTR*>(found);
		g_mmonp_MmPfnDatabase = *reinterpret_cast<void**>(mmpfn_address);
	}

	g_mmonp_MmPfnDatabase = PAGE_ALIGN(g_mmonp_MmPfnDatabase);

	return STATUS_SUCCESS;
}

typedef union _virt_addr_t
{
	void* value;
	struct
	{
		uintptr_t offset : 12;
		uintptr_t pt_index : 9;
		uintptr_t pd_index : 9;
		uintptr_t pdpt_index : 9;
		uintptr_t pml4_index : 9;
		uintptr_t reserved : 16;
	};
} virt_addr_t, * pvirt_addr_t;




NTSTATUS read_physical(unsigned long long TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
	return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}



uintptr_t dirbase_from_base_address(void* base)
{

	if (!NT_SUCCESS(init_mmpfn_database_2()))
		return 0;

	virt_addr_t virt_base{}; virt_base.value = base;

	size_t read{};

	auto ranges = MmGetPhysicalMemoryRanges();

	for (int i = 0;; i++) {

		auto elem = &ranges[i];

		if (!elem->BaseAddress.QuadPart || !elem->NumberOfBytes.QuadPart)
			break;

		uintptr_t current_phys_address = elem->BaseAddress.QuadPart;

		for (int j = 0; j < (elem->NumberOfBytes.QuadPart / 0x1000); j++, current_phys_address += 0x1000) {

			_MMPFN* pnfinfo = (_MMPFN*)((uintptr_t)g_mmonp_MmPfnDatabase + (current_phys_address >> 12) * sizeof(_MMPFN));

			if (pnfinfo->u4.PteFrame == (current_phys_address >> 12)) {
				MMPTE pml4e{};
				if (!NT_SUCCESS(read_physical(current_phys_address + 8 * virt_base.pml4_index, &pml4e, 8, &read)))
					continue;

				if (!pml4e.u.Hard.Valid)
					continue;

				MMPTE pdpte{};
				if (!NT_SUCCESS(read_physical((pml4e.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pdpt_index, &pdpte, 8, &read)))
					continue;

				if (!pdpte.u.Hard.Valid)
					continue;

				MMPTE pde{};
				if (!NT_SUCCESS(read_physical((pdpte.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pd_index, &pde, 8, &read)))
					continue;

				if (!pde.u.Hard.Valid)
					continue;

				MMPTE pte{};
				if (!NT_SUCCESS(read_physical((pde.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pt_index, &pte, 8, &read)))
					continue;

				if (!pte.u.Hard.Valid)
					continue;

				return current_phys_address;
			}
		}
	}

	return 0;
}



const UINT64 minimalist_dtb(const PEPROCESS pProcess)
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
		process_dirbase = (UINT64)dirbase_from_base_address(PsGetProcessSectionBaseAddress(pProcess));
	}
	return process_dirbase;
}