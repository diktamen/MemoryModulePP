#include "stdafx.h"
#include "LoaderPrivate.h"
#include <wchar.h>
#include <cstdio>

PMMP_GLOBAL_DATA MmpGlobalDataPtr;

#if MEMORY_MODULE_IS_PREVIEW(MEMORY_MODULE_MINOR_VERSION)
#pragma message("WARNING: You are using a preview version of MemoryModulePP.")
#endif

//
// Locate ntdll!LdrpModuleBaseAddressIndex by climbing from ntdll's own node to
// the tree root and then finding the RTL_RB_TREE in .data that points at it.
//
// The caller must hold ntdll!LdrpModuleDatatableLock. The climb reads
// ParentValue on nodes ntdll rebalances during any concurrent load, so without
// the lock it can follow a link that is mid-update and land on a stale node
// whose address is nowhere in .data -- which reads as "not found" and silently
// disables memory loading for the life of the process. Measured on a 3-core x64
// box under load: 1.58% of attempts, every one of them a stale climb.
//
PRTL_RB_TREE FindLdrpModuleBaseAddressIndex() {
    PRTL_RB_TREE LdrpModuleBaseAddressIndex = nullptr;
    PLDR_DATA_TABLE_ENTRY_WIN10 nt10 = decltype(nt10)(MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry);
    PRTL_BALANCED_NODE node = nullptr;
    if (!nt10 || !RtlIsWindowsVersionOrGreater(6, 2, 0))return nullptr;
    node = &nt10->BaseAddressIndexNode;
    while (node->ParentValue & (~7)) node = decltype(node)(node->ParentValue & (~7));

    //
    // This used to run only when the root read black, on the theory that a red
    // root meant the tree was mid-rebalance. That gate is gone. Driving ntdll's
    // own exported RtlRbInsertNodeEx/RtlRbRemoveNode over 200,255 operations and
    // sampling the root colour after every one produced zero red roots on all
    // three ntdll builds tested -- ntdll keeps the classic root-is-black
    // invariant, so on a settled tree the gate could never fire. When it did
    // fire it was reading a torn ParentValue from the unlocked climb above, so
    // it was detecting a symptom of the missing lock while paying for it by
    // disabling the capability outright. With the lock held the climb is stable
    // and the colour says nothing worth acting on.
    //
    BYTE count = 0;
    PRTL_RB_TREE tmp = nullptr;
    SEARCH_CONTEXT SearchContext{};
    SearchContext.SearchPattern = (LPBYTE)&node;
    SearchContext.PatternSize = sizeof(size_t);
    while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection((HMODULE)nt10->DllBase, ".data", &SearchContext))) {
        if (count++)return nullptr;
        tmp = (decltype(tmp))SearchContext.Result;
    }
    if (count && tmp && tmp->Root && tmp->Min) {
        LdrpModuleBaseAddressIndex = tmp;
    }

    return LdrpModuleBaseAddressIndex;
}

static __forceinline bool IsModuleUnloaded(PLDR_DATA_TABLE_ENTRY entry) {
	if (RtlIsWindowsVersionOrGreater(6, 2, 0)) {
		return PLDR_DATA_TABLE_ENTRY_WIN8(entry)->DdagNode->State == LdrModulesUnloaded;
	}
	else {
		return entry->DllBase == nullptr;
	}
}


BOOL IsValidLdrpHashTable(PLIST_ENTRY LdrpHashTable) {

	//
	// Additional checks are performed to ensure that the LdrpHashTable is valid.
	//

	__try {

		for (ULONG i = 0; i < LDR_HASH_TABLE_ENTRIES; ++i) {
			PLIST_ENTRY head = &LdrpHashTable[i], entry = head->Flink;

			while (head != entry) {
				PLDR_DATA_TABLE_ENTRY current = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY::HashLinks);

				if (LdrHashEntry(current->BaseDllName) != i) {
					return FALSE;
				}

				entry = entry->Flink;
			}
		}

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

}

PLIST_ENTRY FindLdrpHashTable() {
	PLIST_ENTRY head = &NtCurrentPeb()->Ldr->InInitializationOrderModuleList, entry = head->Flink;

	while (head != entry) {
		PLDR_DATA_TABLE_ENTRY current = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY::InInitializationOrderLinks);
		PLIST_ENTRY hashEntry = &current->HashLinks;

		//
		// A module alone in its bucket: its HashLinks ring has exactly one member,
		// so Flink is the bucket head and the bucket index is the module's hash.
		//
		if (hashEntry->Flink != hashEntry && hashEntry->Flink->Flink == hashEntry) {
			PLIST_ENTRY table = &hashEntry->Flink[-(LONG)LdrHashEntry(current->BaseDllName)];

			//
			// Keep looking rather than giving up on the first candidate that does
			// not validate. This used to return nullptr here, so one module whose
			// ring was momentarily inconsistent -- or one whose name hashes
			// differently than this build computes -- disabled the hash table for
			// the entire process lifetime, with no way to tell why.
			//
			if (IsValidLdrpHashTable(table)) return table;
		}

		entry = entry->Flink;
	}

	return nullptr;
}

VOID InitializeWindowsVersion() {

	WINDOWS_VERSION version = WINDOWS_VERSION::invalid;
	DWORD MajorVersion, MinorVersion, BuildNumber, LdrDataTableEntrySize;

	RtlGetNtVersionNumbers(
		&MajorVersion,
		&MinorVersion,
		&BuildNumber
	);
	if (BuildNumber & 0xf0000000)BuildNumber &= 0xffff;

	switch (MajorVersion) {
	case 5: {
		if ((MinorVersion == 1 && BuildNumber == 2600) ||
			(MinorVersion == 2 && BuildNumber == 3790)) {
			version = WINDOWS_VERSION::xp;
			LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_XP);
		}

		break;
	}

	case 6: {
		switch (MinorVersion) {
		case 0: {
			switch (BuildNumber) {
			case 6000:
			case 6001:
			case 6002:
				version = WINDOWS_VERSION::vista;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_VISTA);
				break;
			}
			break;
		}

		case 1: {
			switch (BuildNumber) {
			case 7600:
			case 7601:
				version = WINDOWS_VERSION::win7;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN7);
				break;
			}
			break;
		}

		case 2: {
			if (BuildNumber == 9200) {
				version = WINDOWS_VERSION::win8;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN8);
			}
			break;
		}

		case 3: {
			if (BuildNumber == 9600) {
				version = WINDOWS_VERSION::winBlue;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WINBLUE);
			}
			break;
		}

		}
		break;
	}

	case 10: {
		if (MinorVersion)break;

		if (BuildNumber >= 10240) {
			if (BuildNumber >= 14393) {
				if (BuildNumber >= 15063) {
					if (BuildNumber >= 22000) {
						// [22000, ?)
						version = WINDOWS_VERSION::win11;
						LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
					}
					else {
						// [15063, 22000)
						version = WINDOWS_VERSION::win10_2;
						LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN10_2);
					}
				}
				else {
					//  [14393, 15063)
					version = WINDOWS_VERSION::win10_1;
					LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN10_1);
				}
			}
			else {
				// [10240, 14393)
				version = WINDOWS_VERSION::win10;
				LdrDataTableEntrySize = sizeof(LDR_DATA_TABLE_ENTRY_WIN10);
			}
		}

		break;
	}

	}

	MmpGlobalDataPtr->WindowsVersion = version;
	if (version != WINDOWS_VERSION::invalid) {
		MmpGlobalDataPtr->NtVersions.MajorVersion = MajorVersion;
		MmpGlobalDataPtr->NtVersions.MinorVersion = MinorVersion;
		MmpGlobalDataPtr->NtVersions.BuildNumber = BuildNumber;
		MmpGlobalDataPtr->LdrDataTableEntrySize = (WORD)LdrDataTableEntrySize;
	}

}

NTSTATUS MmpAllocateGlobalData() {
	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	LARGE_INTEGER li;
	WCHAR buffer[128];
	HANDLE hSection = nullptr;
	UNICODE_STRING us{};
	PVOID BaseAddress = 0;
	SIZE_T ViewSize = 0;
	PTEB teb = NtCurrentTeb();

	if (NtCurrentPeb()->SessionId == 0) {
		swprintf_s(
			buffer,
			L"\\BaseNamedObjects\\MMPP*%p",
			(PVOID)(~(ULONG_PTR)teb->ClientId.UniqueProcess ^ (ULONG_PTR)teb->ProcessEnvironmentBlock->ProcessHeap)
		);
	}
	else {
		swprintf_s(
			buffer,
			L"\\Sessions\\%d\\BaseNamedObjects\\MMPP*%p",
			NtCurrentPeb()->SessionId,
			(PVOID)(~(ULONG_PTR)teb->ClientId.UniqueProcess ^ (ULONG_PTR)teb->ProcessEnvironmentBlock->ProcessHeap)
		);
	}

	RtlInitUnicodeString(&us, buffer);
	InitializeObjectAttributes(&oa, &us, 0, nullptr, nullptr);

	li.QuadPart = 0x1000;

	status = NtCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		&oa,
		&li,
		PAGE_READWRITE,
		SEC_COMMIT,
		nullptr
	);
	if (NT_SUCCESS(status)) {
		status = NtMapViewOfSection(
			hSection,
			NtCurrentProcess(),
			(PVOID*)&MmpGlobalDataPtr,
			0,
			0,
			nullptr,
			&ViewSize,
			ViewUnmap,
			0,
			PAGE_READWRITE
		);

		//
		// Close the handle either way. The mapping keeps the section alive, so
		// holding the handle past this point bought nothing and leaked it for the
		// life of the process on the success path.
		//
		NtClose(hSection);
	}
	else {
		if (status == STATUS_OBJECT_NAME_COLLISION) {
			status = NtOpenSection(
				&hSection,
				SECTION_ALL_ACCESS,
				&oa
			);

			if (NT_SUCCESS(status)) {
				status = NtMapViewOfSection(
					hSection,
					NtCurrentProcess(),
					&BaseAddress,
					0,
					0,
					nullptr,
					&ViewSize,
					ViewUnmap,
					0,
					PAGE_READONLY
				);
				
				NtClose(hSection);

				if (NT_SUCCESS(status)) {
					MmpGlobalDataPtr = (PMMP_GLOBAL_DATA)((PMMP_GLOBAL_DATA)BaseAddress)->BaseAddress;
					NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

					status = STATUS_ALREADY_INITIALIZED;
				}

			}
		}
	}

	return status;
}

NTSTATUS InitializeLockHeld() {
    NTSTATUS status;

    do {

		status = MmpAllocateGlobalData();
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_ALREADY_INITIALIZED) {
				if ((MmpGlobalDataPtr->MajorVersion != MEMORY_MODULE_MAJOR_VERSION) ||
					MEMORY_MODULE_IS_PREVIEW(MmpGlobalDataPtr->MinorVersion) != MEMORY_MODULE_IS_PREVIEW(MEMORY_MODULE_MINOR_VERSION) ||
					(MEMORY_MODULE_IS_PREVIEW(MEMORY_MODULE_MINOR_VERSION) ? MmpGlobalDataPtr->MinorVersion != MEMORY_MODULE_MINOR_VERSION :
						MmpGlobalDataPtr->MinorVersion < MEMORY_MODULE_MINOR_VERSION)) {
					status = STATUS_NOT_SUPPORTED;
				}
				else {
					++MmpGlobalDataPtr->ReferenceCount;
					status = STATUS_SUCCESS;
				}
			}

			break;
		}

        MmpGlobalDataPtr->MajorVersion = MEMORY_MODULE_MAJOR_VERSION;
        MmpGlobalDataPtr->MinorVersion = MEMORY_MODULE_MINOR_VERSION;
		MmpGlobalDataPtr->BaseAddress = MmpGlobalDataPtr;
		MmpGlobalDataPtr->ReferenceCount = 1;

		GetSystemInfo(&MmpGlobalDataPtr->SystemInfo);

		InitializeWindowsVersion();
		if (MmpGlobalDataPtr->WindowsVersion == WINDOWS_VERSION::invalid) {
			NtUnmapViewOfSection(NtCurrentProcess(), MmpGlobalDataPtr);
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		MmpGlobalDataPtr->MmpBaseAddressIndex = (PMMP_BASE_ADDRESS_INDEX_DATA)((LPBYTE)MmpGlobalDataPtr + sizeof(MMP_GLOBAL_DATA));
		MmpGlobalDataPtr->MmpInvertedFunctionTable = (PMMP_INVERTED_FUNCTION_TABLE_DATA)((LPBYTE)MmpGlobalDataPtr->MmpBaseAddressIndex + sizeof(MMP_BASE_ADDRESS_INDEX_DATA));
		MmpGlobalDataPtr->MmpLdrEntry = (PMMP_LDR_ENTRY_DATA)((LPBYTE)MmpGlobalDataPtr->MmpInvertedFunctionTable + sizeof(MMP_INVERTED_FUNCTION_TABLE_DATA));
		MmpGlobalDataPtr->MmpTls = (PMMP_TLS_DATA)((LPBYTE)MmpGlobalDataPtr->MmpLdrEntry + sizeof(MMP_LDR_ENTRY_DATA));
		MmpGlobalDataPtr->MmpFunctions = (PMMP_FUNCTIONS)((LPBYTE)MmpGlobalDataPtr->MmpTls + sizeof(MMP_TLS_DATA));
		MmpGlobalDataPtr->MmpIat = (PMMP_IAT_DATA)((LPBYTE)MmpGlobalDataPtr->MmpFunctions + sizeof(MMP_FUNCTIONS));

		//
		// Locate ntdll!LdrpModuleDatatableLock FIRST. Everything below walks
		// ntdll's live loader structures -- the module list, the base-address
		// tree, the hash table -- and those walks are only sound while that lock
		// is held. It used to be located thirteen lines further down, which made
		// holding it during discovery not merely omitted but impossible.
		//
		// Failure is not fatal: the guards degrade to no-ops, which is the
		// behaviour that shipped before, and the exported
		// MmpModuleDatatableLockLocated says which way it went. Callers that
		// need certainty should read that.
		//
		// This must run before the guard below, not inside it: it calls
		// GetModuleHandle and GetProcAddress, which enter ntdll's loader and
		// take this same lock, and an SRW lock is not recursive.
		//
		MmpInitializeModuleDatatableLock();

		PLDR_DATA_TABLE_ENTRY pNtdllEntry = nullptr;
		{
			//
			// One acquisition spanning the whole discovery. Taking it separately
			// per step would be a time-of-check race: the module list walk that
			// finds ntdll's entry, the climb from that entry to the tree root,
			// and the hash-table walk all have to see one consistent snapshot.
			//
			// Nothing in here re-enters the loader. RtlFindLdrTableEntryByBaseName
			// and FindLdrpHashTable are plain list walks, and
			// RtlFindMemoryBlockFromModuleSection is a byte scan over an already
			// mapped image -- on 64-bit it uses ntdll's RtlCompareMemory directly
			// rather than the GetProcAddress thunk the 32-bit build needs.
			//
			MmpDatatableLockGuard databaseLock;

			pNtdllEntry = RtlFindLdrTableEntryByBaseName(L"ntdll.dll");
			MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry = pNtdllEntry;
			MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex = FindLdrpModuleBaseAddressIndex();
			MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable = FindLdrpHashTable();
		}

		if (!pNtdllEntry) {
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		//
		// Outside the lock, for the reason given above: GetProcAddress enters
		// ntdll's loader.
		//
		MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx = GetProcAddress((HMODULE)pNtdllEntry->DllBase, "RtlRbInsertNodeEx");
		MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode = GetProcAddress((HMODULE)pNtdllEntry->DllBase, "RtlRbRemoveNode");

		//
		// LdrpInvertedFunctionTable is no longer located at all. Unwind info is
		// published through RtlAddFunctionTable, which needs nothing from ntdll's
		// internals, and with x86 support removed there is no caller left for the
		// inverted table. The feature bit stays defined for ABI compatibility but
		// is never set; MEMORY_FEATURE_ALL callers should not expect it.
		//
		MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable = nullptr;

        MmpGlobalDataPtr->MmpFeatures = MEMORY_FEATURE_SUPPORT_VERSION | MEMORY_FEATURE_LDRP_HEAP | MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA | MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY;
        if (MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX;
        if (MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_LDRP_HASH_TABLE;

		MmpGlobalDataPtr->MmpFunctions->_LdrLoadDllMemoryExW = LdrLoadDllMemoryExW;
		MmpGlobalDataPtr->MmpFunctions->_LdrUnloadDllMemory = LdrUnloadDllMemory;
		MmpGlobalDataPtr->MmpFunctions->_LdrUnloadDllMemoryAndExitThread = LdrUnloadDllMemoryAndExitThread;
		MmpGlobalDataPtr->MmpFunctions->_MmpHandleTlsData = MmpHandleTlsData;
		MmpGlobalDataPtr->MmpFunctions->_MmpReleaseTlsEntry = MmpReleaseTlsEntry;

		InitializeCriticalSection(&MmpGlobalDataPtr->MmpIat->MmpIatResolverListLock);
		InitializeListHead(&MmpGlobalDataPtr->MmpIat->MmpIatResolverList);
		InitializeListHead(&MmpGlobalDataPtr->MmpIat->MmpIatResolverHead.InMmpIatResolverList);
		MmpGlobalDataPtr->MmpIat->MmpIatResolverHead.LoadLibraryProv = LoadLibraryA;
		MmpGlobalDataPtr->MmpIat->MmpIatResolverHead.FreeLibraryProv = FreeLibrary;
		MmpGlobalDataPtr->MmpIat->MmpIatResolverHead.ReferenceCount = 1;
		InsertTailList(&MmpGlobalDataPtr->MmpIat->MmpIatResolverList, &MmpGlobalDataPtr->MmpIat->MmpIatResolverHead.InMmpIatResolverList);

		//
		// A FALSE return means TLS handling is unavailable: either the helpers
		// could not be located, or they were located and this process must not
		// call them (the ARM64EC case). Not fatal -- a caller passing
		// LOAD_FLAGS_NOT_HANDLE_TLS, or loading modules without a TLS directory,
		// is unaffected -- but it must not be invisible the way it used to be.
		// MmpTlsInitialize has already cleared the feature bit;
		// LdrQuerySystemMemoryModuleFeatures and the exported MmpTlsLocated /
		// MmpTlsRefused say which of the two happened.
		//
		if (!MmpTlsInitialize()) {
			MmpGlobalDataPtr->MmpFeatures &= ~MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY;
		}

    } while (false);

    return status;
}

NTSTATUS NTAPI MmInitialize() {
    NTSTATUS status;

	PVOID cookie;
	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &cookie);

	__try {
		status = InitializeLockHeld();
	}
	__finally {
		LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie);
	}

	//
	// With the loader lock down, the causality check can run. Doing it here and
	// not only in MmpEnsureInitialized is what makes prewarming work: a caller
	// that spawns a thread to call MmInitialize before any memory module is
	// loaded pays this cost there instead of on whichever thread happens to
	// perform the first load. Idempotent, and it skips itself when this is being
	// called from a DllMain.
	//
	if (NT_SUCCESS(status)) MmpVerifyModuleDatatableLock();

    return status;
}

//
// Initialization used to run from DllMain, and none of it needed to.
//
// What it does is not DllMain work: it creates a named section, calls out to
// kernel32 for GetSystemInfo and five GetProcAddress lookups -- which re-enter
// ntdll's loader -- walks PEB->Ldr, and pattern-scans ntdll. Best practice says
// keep DllMain to a minimum, and this was the opposite of minimum.
//
// It also cost us the one check that would settle whether the located lock is
// the right one. The causality check needs a probe thread and a wait on it, and
// from DllMain that deadlocks: the new thread cannot run its DLL_THREAD_ATTACH
// until the loader lock we are holding comes free. That is the whole of why the
// library had to accept the address on structural checks while the bench could
// prove it.
//
// So initialization is deferred to the first call that actually needs it, which
// runs on an ordinary thread with nothing held. MmpVerifyModuleDatatableLock
// becomes legal there, and DllMain does nothing at all.
//
// Reference counting stays with MmInitialize, which is public and may be called
// explicitly; this guard runs it at most once and stands aside entirely if a
// caller got there first.
//
static volatile LONG MmpInitializeState = 0;    // 0 untouched, 1 running, 2 done
static volatile LONG MmpInitializeOwner = 0;
static NTSTATUS      MmpInitializeStatus = STATUS_UNSUCCESSFUL;

NTSTATUS NTAPI MmpEnsureInitialized() {
	if (MmpInitializeState == 2) return MmpInitializeStatus;

	LONG self = HandleToLong(NtCurrentTeb()->ClientId.UniqueThread);

	//
	// Re-entered by the thread already running initialization -- a memory
	// module's DllMain calling back in through the loader, say. Spinning here
	// would wait on ourselves.
	//
	if (MmpInitializeState == 1 && MmpInitializeOwner == self) return MmpInitializeStatus;

	if (InterlockedCompareExchange(&MmpInitializeState, 1, 0) == 0) {
		InterlockedExchange(&MmpInitializeOwner, self);

		//
		// Test for "somebody already initialized us" under the loader lock,
		// which is the lock MmInitialize holds while it fills the global data
		// in. MmpGlobalDataPtr is published by the section mapping *before* the
		// fields behind it are written, so an unlocked test can see a
		// half-built structure while another thread is still inside
		// InitializeLockHeld -- which is exactly what a caller prewarming on its
		// own thread produces. Taking the lock makes us wait for that to finish.
		//
		PVOID cookie;
		LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &cookie);
		BOOLEAN already = MmpGlobalDataPtr != nullptr;
		LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie);

		MmpInitializeStatus = already ? STATUS_SUCCESS : MmInitialize();

		//
		// Retried here even when initialization was somebody else's: if they
		// called MmInitialize from a DllMain the check will have skipped itself,
		// and this call runs on an ordinary thread where it can succeed. A no-op
		// once verification has passed.
		//
		if (NT_SUCCESS(MmpInitializeStatus)) MmpVerifyModuleDatatableLock();

		InterlockedExchange(&MmpInitializeState, 2);
		return MmpInitializeStatus;
	}

	//
	// Another thread got there first. This is a one-time window measured in
	// milliseconds, so yielding beats standing up an event we would never use
	// again.
	//
	while (MmpInitializeState != 2) NtYieldExecution();
	return MmpInitializeStatus;
}

NTSTATUS CleanupLockHeld() {

	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry;

	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;

		if (IsValidMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase)) {

			//
			// Make sure all memory module is unloaded.
			//

			return STATUS_NOT_SUPPORTED;
		}
	}

	if (--MmpGlobalDataPtr->ReferenceCount > 0) {
		return STATUS_SUCCESS;
	}

	MmpTlsCleanup();

	NtUnmapViewOfSection(NtCurrentProcess(), MmpGlobalDataPtr->BaseAddress);
	MmpGlobalDataPtr = nullptr;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmCleanup() {
	NTSTATUS status;
	PVOID cookie;
	LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &cookie);

	__try {

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_ACCESS_VIOLATION;
			__leave;
		}

		status = CleanupLockHeld();
	}
	__finally {
		LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie);
	}

	return status;
}

#ifdef _USRDLL
extern "C" __declspec(dllexport) BOOL WINAPI ReflectiveMapDll(HMODULE hModule) {
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(hModule);

	headers->OptionalHeader.ImageBase = (SIZE_T)hModule;

	NTSTATUS status = MmpInitializeStructure(0, nullptr, headers);
	if (!NT_SUCCESS(status))return FALSE;

	PMEMORYMODULE module = MapMemoryModuleHandle(hModule);
	if (!module)return FALSE;

	//
	// Everything below publishes into structures ntdll's own loader mutates, so
	// it runs under the loader lock like every other publish path in this
	// library. DllMain already holds it when the reflective loader arrives here,
	// but this function is exported and can be called with nothing held; the
	// lock is recursive, so covering both cases costs nothing.
	//
	MmpLoaderLockGuard loaderLock;
	if (loaderLock.Failed()) return FALSE;

	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
	status = LdrMapDllMemory(hModule, 0, nullptr, nullptr, &ModuleEntry);
	if (!NT_SUCCESS(status))return FALSE;

	//
	// Record the publish before anything else can fail. These two are what the
	// teardown below -- and any later unload -- read to know there is a loader
	// entry to unlink; setting them only at the end left a failed call with the
	// module in ntdll's three lists and its base-address index, and nothing
	// anywhere able to tell. Loader.cpp sets them in the same position for the
	// same reason.
	//
	module->MappedDll = true;
	module->LdrEntry = ModuleEntry;

	//
	// MmpRegisterExceptionTable, not RtlInsertInvertedFunctionTable: on x64 that
	// publishes through RtlAddFunctionTable instead of editing ntdll's .mrdata
	// inverted table, whose page flip races ntdll's own no matter what lock we
	// hold. This was the last caller of the direct edit on a live path. It also
	// pairs with the MmpUnregisterExceptionTable that unload runs when
	// InsertInvertedFunctionTableEntry is set, which the old call did not.
	//
	status = MmpRegisterExceptionTable(hModule, headers->OptionalHeader.SizeOfImage);
	if (!NT_SUCCESS(status)) {
		if (!RtlFreeLdrDataTableEntry(ModuleEntry)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
		module->LdrEntry = nullptr;
		module->MappedDll = false;
		return FALSE;
	}

	module->InsertInvertedFunctionTableEntry = true;

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
#ifdef _HAS_AUTO_INITIALIZE
		//
		// A reflective load is the one case that has to initialize here: the
		// injector has already mapped us and calls this entry point directly,
		// so there is no later API call to defer to. It pays the DllMain cost
		// knowingly, and MmpVerifyModuleDatatableLock detects the held loader
		// lock and skips itself.
		//
		// Every other consumer initializes on first use. See
		// MmpEnsureInitialized for why none of that belongs here.
		//
		if (lpReserved == (PVOID)-1) {
			if (!NT_SUCCESS(MmpEnsureInitialized())) return FALSE;
			if (!ReflectiveMapDll(hModule)) {
				RtlRaiseStatus(STATUS_NOT_SUPPORTED);
			}
		}
#endif
	}

	return TRUE;
}
#else
#ifdef _HAS_AUTO_INITIALIZE
//
// Static-library build. This runs from CRT static initialization, which for an
// executable is an ordinary thread with nothing held -- so the causality check
// can run here, and going through the guard rather than MmInitialize directly is
// what gives it the chance. Linked into somebody else's DLL it lands in their
// DllMain instead, where the check detects the held loader lock and skips.
//
const NTSTATUS Initializer = MmpEnsureInitialized();
#endif
#endif
