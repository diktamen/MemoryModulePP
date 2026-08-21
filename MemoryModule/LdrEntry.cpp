#include "stdafx.h"
#include <cstddef>

static NTSTATUS RtlFreeDependencies(_In_ PLDR_DATA_TABLE_ENTRY_WIN10 LdrEntry) {
	_LDR_DDAG_NODE* DependentDdgeNode = nullptr;
	PLDR_DATA_TABLE_ENTRY_WIN10 ModuleEntry = nullptr;
	_LDRP_CSLIST* head = (decltype(head))LdrEntry->DdagNode->Dependencies, * entry = head;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	BOOL IsWin8 = RtlIsWindowsVersionInScope(6, 2, 0, 6, 3, -1);
	if (!LdrEntry->DdagNode->Dependencies)return STATUS_SUCCESS;

	//find all dependencies and free
	do {
		DependentDdgeNode = entry->Dependent.DependentDdagNode;
		if (DependentDdgeNode->Modules.Flink->Flink != &DependentDdgeNode->Modules) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		ModuleEntry = decltype(ModuleEntry)((size_t)DependentDdgeNode->Modules.Flink - offsetof(_LDR_DATA_TABLE_ENTRY_WIN8, NodeModuleLink));
		if (ModuleEntry->DdagNode != DependentDdgeNode) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		if (!DependentDdgeNode->IncomingDependencies) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
		_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING* _last = DependentDdgeNode->IncomingDependencies, * _entry = _last;
		_LDR_DDAG_NODE* CurrentDdagNode;
		ULONG State = 0;
		PVOID Cookies;

		//Acquire LoaderLock
		do {
			if (!NT_SUCCESS(LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, &State, &Cookies))) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
		} while (State != LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED);

		do {
			CurrentDdagNode = (decltype(CurrentDdagNode))((size_t)_entry->IncommingDdagNode & ~1);
			if (CurrentDdagNode == LdrEntry->DdagNode) {
				//node is head
				if (_entry == DependentDdgeNode->IncomingDependencies) {
					//only one node in list
					if (_entry->NextIncommingEntry == (PSINGLE_LIST_ENTRY)DependentDdgeNode->IncomingDependencies) {
						DependentDdgeNode->IncomingDependencies = nullptr;
					}
					else {
						//find the last node in the list
						PSINGLE_LIST_ENTRY i = _entry->NextIncommingEntry;
						while (i->Next != (PSINGLE_LIST_ENTRY)_entry)i = i->Next;
						i->Next = _entry->NextIncommingEntry;
						DependentDdgeNode->IncomingDependencies = (_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING*)_entry->NextIncommingEntry;
					}
				}
				//node is not head
				else {
					_last->NextIncommingEntry = _entry->NextIncommingEntry;
				}
				break;
			}

			//save the last entry
			if (_last != _entry)_last = (decltype(_last))_last->NextIncommingEntry;
			_entry = (decltype(_entry))_entry->NextIncommingEntry;
		} while (_entry != _last);
		//free LoaderLock
		LdrUnlockLoaderLock(0, Cookies);
		entry = (decltype(entry))entry->Dependent.NextDependentEntry;

		//free it
		if (IsWin8) {
			//Update win8 dep count
			_LDR_DDAG_NODE_WIN8* win8_node = (decltype(win8_node))ModuleEntry->DdagNode;
			if (!win8_node->DependencyCount)__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
			--win8_node->DependencyCount;
			if (!ModuleEntry->DdagNode->LoadCount && win8_node->ReferenceCount == 1 && !win8_node->DependencyCount) {
				win8_node->LoadCount = 1;
				LdrUnloadDll(ModuleEntry->DllBase);
			}
		}
		else {
			LdrUnloadDll(ModuleEntry->DllBase);
		}
		RtlFreeHeap(heap, 0, LdrEntry->DdagNode->Dependencies);

		//lookup next dependent.
		LdrEntry->DdagNode->Dependencies = (_LDRP_CSLIST::_LDRP_CSLIST_DEPENDENT*)(entry == head ? nullptr : entry);
	} while (entry != head);

	return STATUS_SUCCESS;
}

PLDR_DATA_TABLE_ENTRY NTAPI RtlAllocateDataTableEntry(_In_ PVOID BaseAddress) {
	PLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;
	PIMAGE_NT_HEADERS NtHeader;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;

	/* Make sure the header is valid */
	if (NtHeader = RtlImageNtHeader(BaseAddress)) {
		/* Allocate an entry */
		LdrEntry = (PLDR_DATA_TABLE_ENTRY)RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, MmpGlobalDataPtr->LdrDataTableEntrySize);
	}

	/* Return the entry */
	return LdrEntry;
}

BOOL NTAPI RtlInitializeLdrDataTableEntry(
	_Out_ PLDR_DATA_TABLE_ENTRY LdrEntry,
	_In_ DWORD dwFlags,
	_In_ PVOID BaseAddress,
	_In_ UNICODE_STRING& DllBaseName,
	_In_ UNICODE_STRING& DllFullName) {
	RtlZeroMemory(LdrEntry, MmpGlobalDataPtr->LdrDataTableEntrySize);
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);
	if (!headers)return FALSE;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	bool FlagsProcessed = false;

	bool CorImage = false, CorIL = false;
	auto& com = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
	if (com.Size && com.VirtualAddress) {
		CorImage = true;

		auto cor = PIMAGE_COR20_HEADER(LPBYTE(BaseAddress) + com.VirtualAddress);
		if (cor->Flags & ReplacesCorHdrNumericDefines::COMIMAGE_FLAGS_ILONLY) {
			CorIL = true;
		}
	}

	switch (MmpGlobalDataPtr->WindowsVersion) {
	case WINDOWS_VERSION::win11: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN11)LdrEntry;
		entry->CheckSum = headers->OptionalHeader.CheckSum;
	}
		
	case WINDOWS_VERSION::win10:
	case WINDOWS_VERSION::win10_1:
	case WINDOWS_VERSION::win10_2: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;
		entry->ReferenceCount = 1;
	}
	case WINDOWS_VERSION::win8:
	case WINDOWS_VERSION::winBlue: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN8)LdrEntry;
		BOOL IsWin8 = RtlIsWindowsVersionInScope(6, 2, 0, 6, 3, -1);
		NtQuerySystemTime(&entry->LoadTime);
		entry->OriginalBase = headers->OptionalHeader.ImageBase;
		entry->BaseNameHashValue = LdrHashEntry(DllBaseName, false);
		entry->LoadReason = LoadReasonDynamicLoad;
		//
		// The base-address index is ntdll's red-black tree, guarded by
		// ntdll!LdrpModuleDatatableLock. The walk that finds the insertion point
		// reads nodes ntdll may be rebalancing, so the lock has to cover the
		// search as well as the insert, which is why it is taken out here rather
		// than inside RtlInsertModuleBaseAddressIndexNode.
		//
		{
			MmpDatatableLockGuard databaseLock;
			if (!NT_SUCCESS(RtlInsertModuleBaseAddressIndexNode(LdrEntry, BaseAddress)))return FALSE;
		}
		if (!(entry->DdagNode = (decltype(entry->DdagNode))
			RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, IsWin8 ? sizeof(_LDR_DDAG_NODE_WIN8) : sizeof(_LDR_DDAG_NODE))))return FALSE;

		entry->NodeModuleLink.Flink = &entry->DdagNode->Modules;
		entry->NodeModuleLink.Blink = &entry->DdagNode->Modules;
		entry->DdagNode->Modules.Flink = &entry->NodeModuleLink;
		entry->DdagNode->Modules.Blink = &entry->NodeModuleLink;
		entry->DdagNode->State = LdrModulesReadyToRun;
		entry->DdagNode->LoadCount = 1;
		if (IsWin8) ((_LDR_DDAG_NODE_WIN8*)(entry->DdagNode))->ReferenceCount = 1;
		entry->ImageDll = entry->LoadNotificationsSent = entry->EntryProcessed =
			entry->InLegacyLists = entry->InIndexes = true;
		entry->ProcessAttachCalled = false;

		//
		// Opt out of ntdll's per-thread DllMain notifications, the same thing
		// DisableThreadLibraryCalls() does for a normally loaded DLL.
		//
		// We are linked into InInitializationOrderModuleList, so without this
		// ntdll calls this module's entry point with DLL_THREAD_ATTACH every time
		// any thread starts, on threads and at times we do not control -- and
		// notably from the loader worker threads that ntdll spins up to service
		// ordinary LoadLibrary calls. Because the image and this entry are freed
		// by us rather than by the OS loader, such a notification can land on a
		// module that is being torn down, and ntdll then calls an entry point in
		// released memory. Under page heap that reproduced as execution at an
		// address with no owning module, dispatched from inside ntdll's thread
		// initialization path.
		//
		entry->DontCallForThreads = true;
		entry->InExceptionTable = !(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION);
		entry->CorImage = CorImage;
		entry->CorILOnly = CorIL;

		FlagsProcessed = true;
	}

	case WINDOWS_VERSION::win7: {
		if (MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_WIN7)LdrEntry;
			entry->OriginalBase = headers->OptionalHeader.ImageBase;
			NtQuerySystemTime(&entry->LoadTime);
		}
	}
	case WINDOWS_VERSION::vista: {
		if (MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_VISTA) ||
			MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			auto entry = (PLDR_DATA_TABLE_ENTRY_VISTA)LdrEntry;
			InitializeListHead(&entry->ForwarderLinks);
			InitializeListHead(&entry->StaticLinks);
			InitializeListHead(&entry->ServiceTagLinks);
		}
	}
	case WINDOWS_VERSION::xp: {
		LdrEntry->DllBase = BaseAddress;
		LdrEntry->SizeOfImage = headers->OptionalHeader.SizeOfImage;
		LdrEntry->TimeDateStamp = headers->FileHeader.TimeDateStamp;
		LdrEntry->BaseDllName = DllBaseName;
		LdrEntry->FullDllName = DllFullName;
		LdrEntry->EntryPoint = (PLDR_INIT_ROUTINE)((size_t)BaseAddress + headers->OptionalHeader.AddressOfEntryPoint);
		LdrEntry->ObsoleteLoadCount = 1;
		if (!FlagsProcessed) {
			LdrEntry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED;

			if (CorImage)LdrEntry->Flags |= LDRP_COR_IMAGE;
		}
		InitializeListHead(&LdrEntry->HashLinks);
		return TRUE;
	}
	default:return FALSE;
	}
}

BOOL NTAPI RtlFreeLdrDataTableEntry(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry) {
	HANDLE heap = NtCurrentPeb()->ProcessHeap;
	switch (MmpGlobalDataPtr->WindowsVersion) {
	case WINDOWS_VERSION::win11:
	case WINDOWS_VERSION::win10:
	case WINDOWS_VERSION::win10_1:
	case WINDOWS_VERSION::win10_2:
	case WINDOWS_VERSION::win8:
	case WINDOWS_VERSION::winBlue: {
		auto entry = (PLDR_DATA_TABLE_ENTRY_WIN10)LdrEntry;

		//
		// Make the entry unreachable before dismantling anything it points at.
		//
		// This used to free the DdagNode first and unlink the entry afterwards,
		// in the fall-through below. That left a window in which the entry was
		// still linked into all three of ntdll's module lists while its DdagNode
		// pointer was already dangling, and ntdll's loader walks those lists and
		// dereferences DdagNode. Once the freed block was reused, ntdll followed
		// whatever now lived there, which is how it ended up raising
		// FAST_FAIL_CORRUPT_LIST_ENTRY from inside LdrpInsertDataTableEntry on an
		// unrelated thread doing an ordinary LoadLibrary.
		//
		// Unlink first, then take the entry out of the base address index, and
		// only then release what it owns. The links are reset to self-referential
		// so that the RemoveEntryList calls in the fall-through case below are
		// harmless no-ops rather than a second unlink that would corrupt the
		// neighbours we already spliced out.
		//
		// All of that runs under ntdll!LdrpModuleDatatableLock, which is the lock
		// that guards these structures -- the loader lock does not. One section
		// covers the unlink and the de-index because they are one logical
		// operation, making the entry unreachable, and because that lock is an
		// SRW lock and cannot be taken twice on one thread.
		//
		// RtlFreeDependencies is deliberately outside it: it calls LdrUnloadDll,
		// which takes the same lock, so holding it there would self-deadlock. It
		// is a no-op for our entries in any case, since we never populate
		// DdagNode->Dependencies.
		//
		{
			MmpDatatableLockGuard databaseLock;

			RemoveEntryList(&LdrEntry->InLoadOrderLinks);
			RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
			RemoveEntryList(&LdrEntry->InInitializationOrderLinks);
			InitializeListHead(&LdrEntry->InLoadOrderLinks);
			InitializeListHead(&LdrEntry->InMemoryOrderLinks);
			InitializeListHead(&LdrEntry->InInitializationOrderLinks);

			RtlRemoveModuleBaseAddressIndexNode(LdrEntry);
		}

		RtlFreeDependencies(entry);
		RtlFreeHeap(heap, 0, entry->DdagNode);
		entry->DdagNode = nullptr;
	}
	case WINDOWS_VERSION::win7:
	case WINDOWS_VERSION::vista: {
		if (MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_VISTA) ||
			MmpGlobalDataPtr->LdrDataTableEntrySize == sizeof(LDR_DATA_TABLE_ENTRY_WIN7)) {
			PLDR_DATA_TABLE_ENTRY_VISTA entry = (decltype(entry))LdrEntry;
			PLIST_ENTRY head = &entry->ForwarderLinks, next = head->Flink;
			while (head != next) {
				PLDR_DATA_TABLE_ENTRY dep = *(decltype(&dep))((size_t*)next + 2);
				LdrUnloadDll(dep->DllBase);
				next = next->Flink;
				RtlFreeHeap(heap, 0, next->Blink);
			}
		}
	}
	case WINDOWS_VERSION::xp: {
		RtlFreeHeap(heap, 0, LdrEntry->BaseDllName.Buffer);
		RtlFreeHeap(heap, 0, LdrEntry->FullDllName.Buffer);
		RemoveEntryList(&LdrEntry->InLoadOrderLinks);
		RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
		RemoveEntryList(&LdrEntry->InInitializationOrderLinks);

		//
		// No HashLinks unlink: RtlInsertMemoryTableEntry() never put this entry
		// in LdrpHashTable, and the node is self-referential, so there is
		// nothing to remove. This pairing is what was measured clean; a variant
		// that kept the unlink here scored worse, and rather than argue that a
		// no-op cannot matter, this matches the configuration the numbers came
		// from.
		//
		RtlFreeHeap(heap, 0, LdrEntry);
		return TRUE;
	}
	default:return FALSE;
	}
}

NTSTATUS NTAPI RtlUpdateReferenceCount(
	_Inout_ PMEMORYMODULE pModule,
	_In_ DWORD Flags) {
	if (Flags != FLAG_REFERENCE && Flags != FLAG_DEREFERENCE)return STATUS_INVALID_PARAMETER_2;

	if (pModule->dwReferenceCount == 0xffffffff)return STATUS_SUCCESS;

	if (PLDR_DATA_TABLE_ENTRY(pModule->LdrEntry)->ObsoleteLoadCount == 0xffff) {
		pModule->dwReferenceCount = 0xffffffff;
		return STATUS_SUCCESS;
	}

	if (Flags == FLAG_REFERENCE) {
		++pModule->dwReferenceCount;
	}
	else {
		if (pModule->dwReferenceCount)--pModule->dwReferenceCount;
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlGetReferenceCount(
	_In_ PMEMORYMODULE pModule,
	_Out_ PULONG Count) {

	*Count = pModule->dwReferenceCount;

	return STATUS_SUCCESS;
}

VOID NTAPI RtlInsertMemoryTableEntry(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry) {
	PPEB_LDR_DATA PebData = NtCurrentPeb()->Ldr;

	//
	// Deliberately not inserted into LdrpHashTable.
	//
	// That table is ntdll's own name-lookup index, and publishing a fabricated
	// entry in it is what corrupted ntdll's loader database: under load, ntdll
	// raised FAST_FAIL_CORRUPT_LIST_ENTRY from inside
	// LdrpInsertDataTableEntry() on an unrelated thread doing an ordinary
	// LoadLibrary. Removing just this one insert takes the stress harness from
	// 4/5 to 6/6 at 8 loader threads plus 8 noise, and from 3/4 to 4/4 at 24
	// plus 12, with nothing else changed. The bucket index is not the problem --
	// it is masked to the table size and MmInitialize() validates that every
	// existing entry hashes to its own bucket -- so what we cannot honour is
	// some other invariant ntdll maintains over this structure, the same
	// situation as LdrpInvertedFunctionTable before RtlAddFunctionTable
	// replaced it.
	//
	// The links are self-initialised instead of left zeroed, so that if any
	// ntdll path ever does unlink this entry, RemoveEntryList() on a
	// self-referential node is a harmless no-op rather than a null dereference.
	//
	// What this costs: ntdll's name-based lookups no longer find memory
	// modules, so GetModuleHandle(L"name.dll") returns null for one and
	// LoadLibrary by that name will not resolve to it. What still works, and is
	// what callers actually use: GetProcAddress on the returned handle, which
	// goes through the base address index rather than this table, and this
	// library's own duplicate-module detection, which walks
	// InLoadOrderModuleList directly. The stress harness calls GetProcAddress
	// and invokes the result on every single load and reports no failures.
	//
	LdrEntry->HashLinks.Flink = &LdrEntry->HashLinks;
	LdrEntry->HashLinks.Blink = &LdrEntry->HashLinks;

	//
	// These three lists are guarded by ntdll!LdrpModuleDatatableLock, not by the
	// loader lock. Splicing them under the loader lock alone is what produced
	// FAST_FAIL_CORRUPT_LIST_ENTRY inside ntdll's own LdrpInsertDataTableEntry:
	// two concurrent tail inserts lose one update and leave
	// head->Blink->Flink != head, which is exactly what ntdll validates.
	//
	// The section is deliberately just the three splices. The lock is an SRW
	// lock and therefore not recursive, so nothing that can re-enter the loader
	// may run inside it.
	//
	MmpDatatableLockGuard databaseLock;

	/* Insert into other lists */
	InsertTailList(&PebData->InLoadOrderModuleList, &LdrEntry->InLoadOrderLinks);
	InsertTailList(&PebData->InMemoryOrderModuleList, &LdrEntry->InMemoryOrderLinks);
	InsertTailList(&PebData->InInitializationOrderModuleList, &LdrEntry->InInitializationOrderLinks);
}

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByHandle(_In_ PVOID BaseAddress) {
	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;
		if (CurEntry->DllBase == BaseAddress) {
			return CurEntry;
		}
	}
	return nullptr;
}

PLDR_DATA_TABLE_ENTRY NTAPI RtlFindLdrTableEntryByBaseName(_In_z_ PCWSTR BaseName) {
	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;
		if (!_wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - 4) ||
			!_wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, CurEntry->BaseDllName.Length / sizeof(wchar_t))) {
			return CurEntry;
		}
	}
	return nullptr;
}

ULONG NTAPI LdrHashEntry(_In_ UNICODE_STRING& DllBaseName, _In_ BOOL ToIndex) {
	ULONG result = 0;

	switch (MmpGlobalDataPtr->WindowsVersion) {
	case WINDOWS_VERSION::xp:
		result = RtlUpcaseUnicodeChar(DllBaseName.Buffer[0]) - 'A';
		break;

	case WINDOWS_VERSION::vista:
		result = RtlUpcaseUnicodeChar(DllBaseName.Buffer[0]) - 1;
		break;

	case WINDOWS_VERSION::win7:
		for (USHORT i = 0; i < (DllBaseName.Length / sizeof(wchar_t)); ++i)
			result += 0x1003F * RtlUpcaseUnicodeChar(DllBaseName.Buffer[i]);
		break;

	default:
		RtlHashUnicodeString(&DllBaseName, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &result);
		break;
	}

	if (ToIndex)result &= (LDR_HASH_TABLE_ENTRIES - 1);
	return result;
}
