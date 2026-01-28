#pragma once
#include "Structures.h"
#pragma comment(lib, "ntoskrnl.lib")

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID ModuleAddress);
extern "C"
PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
EXTERN_C NTSYSAPI CHAR* PsGetProcessImageFileName(__in uintptr_t Process);
EXTERN_C NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);




constexpr auto cr3_pfn(uint64_t _cr3) -> uint64_t { return ((_cr3 & 0xFFFFFFFFF000) >> 12); }
constexpr auto cr3_dirbase(uint64_t _cr3) -> uint64_t { return (_cr3 & 0xFFFFFFFFF000); }

#pragma warning(push)
#pragma warning(disable:4201)
//struct _MMPFN {
//	uintptr_t flags;
//	uintptr_t pte_address;
//	uintptr_t Unused_1;
//	uintptr_t Unused_2;
//	uintptr_t Unused_3;
//	uintptr_t Unused_4;
//};
//static_assert(sizeof(_MMPFN) == 0x30);
//
//typedef union {
//	struct {
//		uint64_t reserved1 : 3;
//		uint64_t page_level_write_through : 1;
//		uint64_t page_level_cache_disable : 1;
//		uint64_t reserved2 : 7;
//		uint64_t address_of_page_directory : 36;
//		uint64_t reserved3 : 16;
//	};
//	uint64_t flags;
//} cr3;
//static_assert(sizeof(cr3) == 0x8);
//
//typedef union {
//	struct {
//		uint64_t present : 1;
//		uint64_t write : 1;
//		uint64_t supervisor : 1;
//		uint64_t page_level_write_through : 1;
//		uint64_t page_level_cache_disable : 1;
//		uint64_t accessed : 1;
//		uint64_t dirty : 1;
//		uint64_t large_page : 1;
//		uint64_t global : 1;
//		uint64_t ignored_1 : 2;
//		uint64_t restart : 1;
//		uint64_t page_frame_number : 36;
//		uint64_t reserved1 : 4;
//		uint64_t ignored_2 : 7;
//		uint64_t protection_key : 4;
//		uint64_t execute_disable : 1;
//	};
//
//	uint64_t flags;
//} pt_entry_64;
//static_assert(sizeof(pt_entry_64) == 0x8);
#pragma warning(pop)

//static uint64_t pte_base = 0;
//static uint64_t pde_base = 0;
//static uint64_t ppe_base = 0;
//static uint64_t pxe_base = 0;
//static uint64_t self_mapidx = 0;
//static uint64_t mm_pfn_database = 0;
//
//uint64_t get_dirbase() {
//	return __readcr3() & 0xFFFFFFFFFFFFF000;
//}
//
//void* phys_to_virt(uint64_t phys) {
//	PHYSICAL_ADDRESS phys_addr = { .QuadPart = (int64_t)(phys) };
//	return reinterpret_cast<void*>(MmGetVirtualForPhysical(phys_addr));
//}
//
//void init_pte_base() {
//	cr3 system_cr3 = { .flags = get_dirbase() };
//	uint64_t dirbase_phys = system_cr3.address_of_page_directory << 12;
//	pt_entry_64* pt_entry = reinterpret_cast<pt_entry_64*>(phys_to_virt(dirbase_phys));
//	for (uint64_t idx = 0; idx < 0x200; idx++) {
//		if (pt_entry[idx].page_frame_number == system_cr3.address_of_page_directory) {
//			pte_base = (idx + 0x1FFFE00ui64) << 39ui64;
//			pde_base = (idx << 30ui64) + pte_base;
//			ppe_base = (idx << 30ui64) + pte_base + (idx << 21ui64);
//			pxe_base = (idx << 12ui64) + ppe_base;
//			self_mapidx = idx;
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PteBase 0x%llx\n", pte_base);
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PdeBase 0x%llx\n", pde_base);
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PpeBase 0x%llx\n", ppe_base);
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PxeBase 0x%llx\n", pxe_base);
//			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "idx 0x%llx\n", idx);
//
//			break;
//		}
//	}
//}

uintptr_t get_kernel_base() {
	const auto idtbase = *reinterpret_cast<uint64_t*>(__readgsqword(0x18) + 0x38);
	const auto descriptor_0 = *reinterpret_cast<uint64_t*>(idtbase);
	const auto descriptor_1 = *reinterpret_cast<uint64_t*>(idtbase + 8);
	const auto isr_base = ((descriptor_0 >> 32) & 0xFFFF0000) + (descriptor_0 & 0xFFFF) + (descriptor_1 << 32);
	auto align_base = isr_base & 0xFFFFFFFFFFFFF000;

	for (; ; align_base -= 0x1000) {
		for (auto* search_base = reinterpret_cast<uint8_t*>(align_base); search_base < reinterpret_cast<uint8_t*>(align_base) + 0xFF9; search_base++) {
			if (search_base[0] == 0x48 &&
				search_base[1] == 0x8D &&
				search_base[2] == 0x1D &&
				search_base[6] == 0xFF) {
				const auto relative_offset = *reinterpret_cast<int*>(&search_base[3]);
				const auto address = reinterpret_cast<uint64_t>(search_base + relative_offset + 7);
				if ((address & 0xFFF) == 0) {
					if (*reinterpret_cast<uint16_t*>(address) == 0x5A4D) {
						return address;
					}
				}
			}
		}
	}
}

uintptr_t search_pattern(void* module_handle, const char* signature_value) {
	static auto in_range = [](auto x, auto a, auto b) { return (x >= a && x <= b); };
	static auto get_bits = [](auto  x) { return (in_range((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (in_range(x, '0', '9') ? x - '0' : 0)); };
	static auto get_byte = [](auto  x) { return (get_bits(x[0]) << 4 | get_bits(x[1])); };

	const auto dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(module_handle);
	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(module_handle) + dos_headers->e_lfanew);

	const auto range_start = reinterpret_cast<uintptr_t>(module_handle);
	const auto range_end = range_start + nt_headers->OptionalHeader.SizeOfImage;

	auto first_match = 0ui64;
	auto pat = signature_value;

	for (uintptr_t cur = range_start; cur < range_end; cur++) {
		if (*pat == '\0') {
			return first_match;
		}
		if (*(uint8_t*)pat == '\?' || *reinterpret_cast<uint8_t*>(cur) == get_byte(pat)) {
			if (!first_match)
				first_match = cur;

			if (!pat[2])
				return first_match;

			if (*(uint16_t*)pat == 16191 || *(uint8_t*)pat != '\?') {
				pat += 3;
			}
			else {
				pat += 2;
			}
		}
		else {
			pat = signature_value;
			first_match = 0;
		}
	}
	return 0u;
}

uintptr_t search_pattern(void* module_handle, const char* section, const char* signature_value) {
	static auto in_range = [](auto x, auto a, auto b) { return (x >= a && x <= b); };
	static auto get_bits = [](auto  x) { return (in_range((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (in_range(x, '0', '9') ? x - '0' : 0)); };
	static auto get_byte = [](auto  x) { return (get_bits(x[0]) << 4 | get_bits(x[1])); };

	const auto dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(module_handle);
	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(module_handle) + dos_headers->e_lfanew);
	const auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);

	auto range_start = 0ui64;
	auto range_end = 0ui64;
	for (auto cur_section = section_headers; cur_section < section_headers + nt_headers->FileHeader.NumberOfSections; cur_section++) {
		if (strcmp(reinterpret_cast<const char*>(cur_section->Name), section) == 0) {
			range_start = reinterpret_cast<uintptr_t>(module_handle) + cur_section->VirtualAddress;
			range_end = range_start + cur_section->Misc.VirtualSize;
		}
	}

	if (range_start == 0)
		return 0u;

	auto first_match = 0ui64;
	auto pat = signature_value;
	for (uintptr_t cur = range_start; cur < range_end; cur++) {
		if (*pat == '\0') {
			return first_match;
		}
		if (*(uint8_t*)pat == '\?' || *reinterpret_cast<uint8_t*>(cur) == get_byte(pat)) {
			if (!first_match)
				first_match = cur;

			if (!pat[2])
				return first_match;

			if (*(uint16_t*)pat == 16191 || *(uint8_t*)pat != '\?') {
				pat += 3;
			}
			else {
				pat += 2;
			}
		}
		else {
			pat = signature_value;
			first_match = 0;
		}
	}
	return 0u;
}

//uintptr_t init_mmpfn_database() {
//	auto search = search_pattern(reinterpret_cast<void*>(get_kernel_base()), ".text", "B9 ? ? ? ? 48 8B 05 ? ? ? ? 48 89 43 18") + 5;
//	auto resolved_base = search + *reinterpret_cast<int32_t*>(search + 3) + 7;
//	mm_pfn_database = *reinterpret_cast<uintptr_t*>(resolved_base);
//	return mm_pfn_database;
//}

char* GetProcessNameFromPid(const PEPROCESS pProcess)
{
	return (CHAR*)PsGetProcessImageFileName((uintptr_t)pProcess);
}





typedef struct _MI_ACTIVE_PFN
{
	union
	{
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned __int64 Tradable : 1; /* bit position: 0 */
				/* 0x0000 */ unsigned __int64 NonPagedBuddy : 43; /* bit position: 1 */
			}; /* bitfield */
		} /* size: 0x0008 */ Leaf;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned __int64 Tradable : 1; /* bit position: 0 */
				/* 0x0000 */ unsigned __int64 WsleAge : 3; /* bit position: 1 */
				/* 0x0000 */ unsigned __int64 OldestWsleLeafEntries : 10; /* bit position: 4 */
				/* 0x0000 */ unsigned __int64 OldestWsleLeafAge : 3; /* bit position: 14 */
				/* 0x0000 */ unsigned __int64 NonPagedBuddy : 43; /* bit position: 17 */
			}; /* bitfield */
		} /* size: 0x0008 */ PageTable;
		/* 0x0000 */ unsigned __int64 EntireActiveField;
	}; /* size: 0x0008 */
} MI_ACTIVE_PFN, * PMI_ACTIVE_PFN; /* size: 0x0008 */








typedef struct _MIPFNBLINK
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 Blink : 40; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 NodeBlinkLow : 19; /* bit position: 40 */
			/* 0x0000 */ unsigned __int64 TbFlushStamp : 3; /* bit position: 59 */
			/* 0x0000 */ unsigned __int64 PageBlinkDeleteBit : 1; /* bit position: 62 */
			/* 0x0000 */ unsigned __int64 PageBlinkLockBit : 1; /* bit position: 63 */
		}; /* bitfield */
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 ShareCount : 62; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 PageShareCountDeleteBit : 1; /* bit position: 62 */
			/* 0x0000 */ unsigned __int64 PageShareCountLockBit : 1; /* bit position: 63 */
		}; /* bitfield */
		/* 0x0000 */ unsigned __int64 EntireField;
		/* 0x0000 */ volatile __int64 Lock;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 LockNotUsed : 62; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 DeleteBit : 1; /* bit position: 62 */
			/* 0x0000 */ unsigned __int64 LockBit : 1; /* bit position: 63 */
		}; /* bitfield */
	}; /* size: 0x0008 */
} MIPFNBLINK, * PMIPFNBLINK; /* size: 0x0008 */

typedef struct _MMPFNENTRY1
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned char PageLocation : 3; /* bit position: 0 */
		/* 0x0000 */ unsigned char WriteInProgress : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned char Modified : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned char ReadInProgress : 1; /* bit position: 5 */
		/* 0x0000 */ unsigned char CacheAttribute : 2; /* bit position: 6 */
	}; /* bitfield */
} MMPFNENTRY1, * PMMPFNENTRY1; /* size: 0x0001 */

typedef struct _MMPFNENTRY3
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned char Priority : 3; /* bit position: 0 */
		/* 0x0000 */ unsigned char OnProtectedStandby : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned char InPageError : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned char SystemChargedPage : 1; /* bit position: 5 */
		/* 0x0000 */ unsigned char RemovalRequested : 1; /* bit position: 6 */
		/* 0x0000 */ unsigned char ParityError : 1; /* bit position: 7 */
	}; /* bitfield */
} MMPFNENTRY3, * PMMPFNENTRY3; /* size: 0x0001 */

typedef struct _MI_PFN_ULONG5
{
	union
	{
		/* 0x0000 */ unsigned long EntireField;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned long NodeBlinkHigh : 21; /* bit position: 0 */
				/* 0x0000 */ unsigned long NodeFlinkMiddle : 11; /* bit position: 21 */
			}; /* bitfield */
		} /* size: 0x0004 */ StandbyList;
		struct
		{
			/* 0x0000 */ unsigned char ModifiedListBucketIndex : 4; /* bit position: 0 */
		} /* size: 0x0001 */ MappedPageList;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned char AnchorLargePageSize : 2; /* bit position: 0 */
				/* 0x0000 */ unsigned char Spare1 : 6; /* bit position: 2 */
			}; /* bitfield */
			/* 0x0001 */ unsigned char ViewCount;
			/* 0x0002 */ unsigned short Spare2;
		} /* size: 0x0004 */ Active;
	}; /* size: 0x0004 */
} MI_PFN_ULONG5, * PMI_PFN_ULONG5; /* size: 0x0004 */

typedef struct _MMPFN
{
	union
	{
		/* 0x0000 */ struct _LIST_ENTRY ListEntry;
		/* 0x0000 */ struct _RTL_BALANCED_NODE TreeNode;
		struct
		{
			union
			{
				union
				{
					/* 0x0000 */ struct _SINGLE_LIST_ENTRY NextSlistPfn;
					/* 0x0000 */ void* Next;
					struct /* bitfield */
					{
						/* 0x0000 */ unsigned __int64 Flink : 40; /* bit position: 0 */
						/* 0x0000 */ unsigned __int64 NodeFlinkLow : 24; /* bit position: 40 */
					}; /* bitfield */
					/* 0x0000 */ struct _MI_ACTIVE_PFN Active;
				}; /* size: 0x0008 */
			} /* size: 0x0008 */ u1;
			union
			{
				/* 0x0008 */ struct _MMPTE* PteAddress;
				/* 0x0008 */ unsigned __int64 PteLong;
			}; /* size: 0x0008 */
			/* 0x0010 */ struct _MMPTE OriginalPte;
		}; /* size: 0x0018 */
	}; /* size: 0x0018 */
	/* 0x0018 */ struct _MIPFNBLINK u2;
	union
	{
		union
		{
			struct
			{
				/* 0x0020 */ unsigned short ReferenceCount;
				/* 0x0022 */ struct _MMPFNENTRY1 e1;
				/* 0x0023 */ struct _MMPFNENTRY3 e3;
			}; /* size: 0x0004 */
			struct
			{
				/* 0x0020 */ unsigned short ReferenceCount;
			} /* size: 0x0002 */ e2;
			struct
			{
				/* 0x0020 */ unsigned long EntireField;
			} /* size: 0x0004 */ e4;
		}; /* size: 0x0004 */
	} /* size: 0x0004 */ u3;
	/* 0x0024 */ struct _MI_PFN_ULONG5 u5;
	union
	{
		union
		{
			struct /* bitfield */
			{
				/* 0x0028 */ unsigned __int64 PteFrame : 40; /* bit position: 0 */
				/* 0x0028 */ unsigned __int64 ResidentPage : 1; /* bit position: 40 */
				/* 0x0028 */ unsigned __int64 Unused1 : 1; /* bit position: 41 */
				/* 0x0028 */ unsigned __int64 Unused2 : 1; /* bit position: 42 */
				/* 0x0028 */ unsigned __int64 Partition : 10; /* bit position: 43 */
				/* 0x0028 */ unsigned __int64 FileOnly : 1; /* bit position: 53 */
				/* 0x0028 */ unsigned __int64 PfnExists : 1; /* bit position: 54 */
				/* 0x0028 */ unsigned __int64 NodeFlinkHigh : 5; /* bit position: 55 */
				/* 0x0028 */ unsigned __int64 PageIdentity : 3; /* bit position: 60 */
				/* 0x0028 */ unsigned __int64 PrototypePte : 1; /* bit position: 63 */
			}; /* bitfield */
			/* 0x0028 */ unsigned __int64 EntireField;
		}; /* size: 0x0008 */
	} /* size: 0x0008 */ u4;
} MMPFN, * PMMPFN; /* size: 0x0030 */