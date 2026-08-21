#include "stdafx.h"
#include "LoaderPrivate.h"
#include <wchar.h>
#include <cstdio>

PMMP_GLOBAL_DATA MmpGlobalDataPtr;

#if MEMORY_MODULE_IS_PREVIEW(MEMORY_MODULE_MINOR_VERSION)
#pragma message("WARNING: You are using a preview version of MemoryModulePP.")
#endif

PRTL_RB_TREE FindLdrpModuleBaseAddressIndex() {
    PRTL_RB_TREE LdrpModuleBaseAddressIndex = nullptr;
    PLDR_DATA_TABLE_ENTRY_WIN10 nt10 = decltype(nt10)(MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry);
    PRTL_BALANCED_NODE node = nullptr;
    if (!nt10 || !RtlIsWindowsVersionOrGreater(6, 2, 0))return nullptr;
    node = &nt10->BaseAddressIndexNode;
    while (node->ParentValue & (~7)) node = decltype(node)(node->ParentValue & (~7));

    if (!node->Red) {
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

#ifndef _WIN64
PVOID FindLdrpInvertedFunctionTable32() {
	// _RTL_INVERTED_FUNCTION_TABLE						x86
	//		Count										+0x0	????????
	//		MaxCount									+0x4	0x00000200
	//		Overflow									+0x8	0x00000000(Win7) ????????(Win10)
	//		NextEntrySEHandlerTableEncoded				+0xc	0x00000000(Win10) ++++++++(Win7)
	// _RTL_INVERTED_FUNCTION_TABLE_ENTRY[0]			+0x10	ntdll.dll(win10) or The smallest base module
	//		ImageBase									+0x10	++++++++
	//		ImageSize									+0x14	++++++++
	//		SEHandlerCount								+0x18	++++++++
	//		NextEntrySEHandlerTableEncoded				+0x1c	++++++++(Win10) ????????(Win7)
	//	_RTL_INVERTED_FUNCTION_TABLE_ENTRY[1] ...		...
	// ......
	HMODULE hModule = nullptr, hNtdll = GetModuleHandleW(L"ntdll.dll");
	PIMAGE_NT_HEADERS NtdllHeaders = RtlImageNtHeader(hNtdll), ModuleHeaders = nullptr;
	_RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 entry{};
	LPCSTR lpSectionName = ".data";
	SEARCH_CONTEXT SearchContext{ SearchContext.SearchPattern = (LPBYTE)&entry,SearchContext.PatternSize = sizeof(entry) };
	PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList,
		ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
	DWORD SEHTable, SEHCount;
	BYTE Offset = 0x20;	//sizeof(_RTL_INVERTED_FUNCTION_TABLE_ENTRY)*2

	if (RtlIsWindowsVersionOrGreater(6, 3, 0)) lpSectionName = ".mrdata";
	else if (!RtlIsWindowsVersionOrGreater(6, 2, 0)) Offset = 0xC;

	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		ListEntry = ListEntry->Flink;
		if (IsModuleUnloaded(CurEntry))continue;					//skip unloaded module
		if (IsValidMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase))continue;  //skip our memory module.
		if (CurEntry->DllBase == hNtdll && Offset == 0x20)continue;	//Win10 skip first entry, if the base of ntdll is smallest.
		hModule = (HMODULE)(hModule ? min(hModule, CurEntry->DllBase) : CurEntry->DllBase);
	}
	ModuleHeaders = RtlImageNtHeader(hModule);
	if (!hModule || !ModuleHeaders || !hNtdll || !NtdllHeaders)return nullptr;

	RtlCaptureImageExceptionValues(hModule, &SEHTable, &SEHCount);
	entry = { RtlEncodeSystemPointer((PVOID)SEHTable),(DWORD)hModule,ModuleHeaders->OptionalHeader.SizeOfImage,(PVOID)SEHCount };

	while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(hNtdll, lpSectionName, &SearchContext))) {
		PRTL_INVERTED_FUNCTION_TABLE_WIN7_32 tab = decltype(tab)(SearchContext.Result - Offset);

		//Note: Same memory layout for RTL_INVERTED_FUNCTION_TABLE_ENTRY in Windows 10 x86 and x64.
		if (RtlIsWindowsVersionOrGreater(6, 2, 0) && tab->MaxCount == 0x200 && !tab->NextEntrySEHandlerTableEncoded) return tab;
		else if (tab->MaxCount == 0x200 && !tab->Overflow) return tab;
	}

	return nullptr;
}

#define FindLdrpInvertedFunctionTable FindLdrpInvertedFunctionTable32
#else
PVOID FindLdrpInvertedFunctionTable64() {
	// _RTL_INVERTED_FUNCTION_TABLE						x64
	//		Count										+0x0	????????
	//		MaxCount									+0x4	0x00000200
	//		Epoch										+0x8	????????
	//		OverFlow									+0xc	0x00000000
	// _RTL_INVERTED_FUNCTION_TABLE_ENTRY[0]			+0x10	ntdll.dll(win10) or The smallest base module
	//		ExceptionDirectory							+0x10	++++++++
	//		ImageBase									+0x18	++++++++
	//		ImageSize									+0x20	++++++++
	//		ExceptionDirectorySize						+0x24	++++++++
	//	_RTL_INVERTED_FUNCTION_TABLE_ENTRY[1] ...		...
	// ......
	HMODULE hModule = nullptr, hNtdll = GetModuleHandleW(L"ntdll.dll");
	PIMAGE_NT_HEADERS NtdllHeaders = RtlImageNtHeader(hNtdll), ModuleHeaders = nullptr;
	_RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 entry{};
	LPCSTR lpSectionName = ".data";
	PIMAGE_DATA_DIRECTORY dir = nullptr;
	SEARCH_CONTEXT SearchContext{ SearchContext.SearchPattern = (LPBYTE)&entry,SearchContext.PatternSize = sizeof(entry) };

	//Windows 8
	if (RtlVerifyVersion(6, 2, 0, RTL_VERIFY_FLAGS_MAJOR_VERSION | RTL_VERIFY_FLAGS_MINOR_VERSION)) {
		hModule = hNtdll;
		ModuleHeaders = NtdllHeaders;
		//lpSectionName = ".data";
	}
	//Windows 8.1 ~ Windows 10
	else if (RtlIsWindowsVersionOrGreater(6, 3, 0)) {
		hModule = hNtdll;
		ModuleHeaders = NtdllHeaders;
		lpSectionName = ".mrdata";
	}
	else {
		PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList,
			ListEntry = ListHead->Flink;
		PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
		while (ListEntry != ListHead) {
			CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;
			//Make sure the smallest base address is not our memory module
			if (IsValidMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase))continue;
			hModule = (HMODULE)(hModule ? min(hModule, CurEntry->DllBase) : CurEntry->DllBase);
		}
		ModuleHeaders = RtlImageNtHeader(hModule);
	}

	if (!hModule || !ModuleHeaders || !hNtdll || !NtdllHeaders)return nullptr;
	dir = &ModuleHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	entry = {
		dir->Size ? decltype(entry.ExceptionDirectory)((size_t)hModule + dir->VirtualAddress) : nullptr ,
		(PVOID)hModule, ModuleHeaders->OptionalHeader.SizeOfImage,dir->Size
	};

	while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(hNtdll, lpSectionName, &SearchContext))) {
		PRTL_INVERTED_FUNCTION_TABLE_64 tab = decltype(tab)(SearchContext.Result - 0x10);
		if (RtlIsWindowsVersionOrGreater(6, 2, 0) && tab->MaxCount == 0x200 && !tab->Overflow) return tab;
		else if (tab->MaxCount == 0x200 && !tab->Epoch) return tab;
	}

	return nullptr;
}

#define FindLdrpInvertedFunctionTable FindLdrpInvertedFunctionTable64
#endif

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

		if (hashEntry->Flink != hashEntry && hashEntry->Flink->Flink == hashEntry) {
			PLIST_ENTRY table = &hashEntry->Flink[-(LONG)LdrHashEntry(current->BaseDllName)];

			return IsValidLdrpHashTable(table) ? table : nullptr;
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

		if (!NT_SUCCESS(status)) {
			NtClose(hSection);
		}
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

		PLDR_DATA_TABLE_ENTRY pNtdllEntry = RtlFindLdrTableEntryByBaseName(L"ntdll.dll");
		MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry = pNtdllEntry;
        MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex = FindLdrpModuleBaseAddressIndex();
		MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx = GetProcAddress((HMODULE)pNtdllEntry->DllBase, "RtlRbInsertNodeEx");
		MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode = GetProcAddress((HMODULE)pNtdllEntry->DllBase, "RtlRbRemoveNode");

		MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable = FindLdrpHashTable();

		//
		// Locate ntdll!LdrpModuleDatatableLock, the lock that actually guards
		// the loader database. Failure is not fatal here: the guards degrade to
		// no-ops, which is the behaviour that shipped before, and the exported
		// MmpModuleDatatableLockLocated says which way it went. Callers that
		// need certainty should read that.
		//
		MmpInitializeModuleDatatableLock();

		MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable = FindLdrpInvertedFunctionTable();

        MmpGlobalDataPtr->MmpFeatures = MEMORY_FEATURE_SUPPORT_VERSION | MEMORY_FEATURE_LDRP_HEAP | MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA | MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY;
        if (MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX;
        if (MmpGlobalDataPtr->MmpLdrEntry->LdrpHashTable)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_LDRP_HASH_TABLE;
        if (MmpGlobalDataPtr->MmpInvertedFunctionTable->LdrpInvertedFunctionTable)MmpGlobalDataPtr->MmpFeatures |= MEMORY_FEATURE_INVERTED_FUNCTION_TABLE;

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

		MmpTlsInitialize();

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

		MmpInitializeStatus = MmpGlobalDataPtr ? STATUS_SUCCESS : MmInitialize();
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
