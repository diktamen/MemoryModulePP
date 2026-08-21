#include "stdafx.h"
#include "LoaderPrivate.h"
#include <cmath>

#ifdef _USRDLL
#if (defined(_WIN64) || defined(_M_ARM))
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=LdrUnloadDllMemoryAndExitThread")
#else
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread=_LdrUnloadDllMemoryAndExitThread@8")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=_LdrUnloadDllMemoryAndExitThread@8")
#endif
#endif

NTSTATUS NTAPI LdrMapDllMemory(
	_In_ HMEMORYMODULE ViewBase,
	_In_ DWORD dwFlags,
	_In_opt_ PCWSTR DllName,
	_In_opt_ PCWSTR lpFullDllName,
	_Out_opt_ PLDR_DATA_TABLE_ENTRY* DataTableEntry) {

	UNICODE_STRING FullDllName, BaseDllName;
	PIMAGE_NT_HEADERS NtHeaders;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;

	if (!(NtHeaders = RtlImageNtHeader(ViewBase))) return STATUS_INVALID_IMAGE_FORMAT;

	if (!(LdrEntry = RtlAllocateDataTableEntry(ViewBase))) return STATUS_NO_MEMORY;

	if (!NT_SUCCESS(RtlResolveDllNameUnicodeString(DllName, lpFullDllName, &BaseDllName, &FullDllName))) {
		RtlFreeHeap(heap, 0, LdrEntry);
		return STATUS_NO_MEMORY;
	}

	if (!RtlInitializeLdrDataTableEntry(LdrEntry, dwFlags, ViewBase, BaseDllName, FullDllName)) {
		RtlFreeHeap(heap, 0, LdrEntry);
		RtlFreeHeap(heap, 0, BaseDllName.Buffer);
		RtlFreeHeap(heap, 0, FullDllName.Buffer);
		return STATUS_UNSUCCESSFUL;
	}

	RtlInsertMemoryTableEntry(LdrEntry);
	if (DataTableEntry)*DataTableEntry = LdrEntry;
	return STATUS_SUCCESS;
}

//
// Probe the caller's buffers and out-parameters under SEH.
//
// This lives in its own function because MSVC forbids __try in a function that
// requires object unwinding (C2712), and LdrLoadDllMemoryExW below needs an RAII
// loader lock guard.
//
static NTSTATUS MmpValidateLoadDllMemoryParameters(
	_Out_ HMEMORYMODULE* BaseAddress,
	_Out_opt_ PVOID* LdrEntry,
	_In_ DWORD dwFlags,
	_In_ LPVOID BufferAddress,
	_In_ size_t BufferSize) {
	NTSTATUS status = STATUS_SUCCESS;

	__try {
		*BaseAddress = nullptr;
		if (LdrEntry)*LdrEntry = nullptr;

		if (!RtlIsValidImageBuffer(BufferAddress, &BufferSize) && !(dwFlags & LOAD_FLAGS_PASS_IMAGE_CHECK)) {
			status = STATUS_INVALID_IMAGE_FORMAT;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	return status;
}

NTSTATUS NTAPI LdrLoadDllMemoryExW(
	_Out_ HMEMORYMODULE* BaseAddress,
	_Out_opt_ PVOID* LdrEntry,
	_In_ DWORD dwFlags,
	_In_ LPVOID BufferAddress,
	_In_ size_t BufferSize,
	_In_opt_ LPCWSTR DllName,
	_In_opt_ LPCWSTR DllFullName) {
	PMEMORYMODULE module = nullptr;
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
	PIMAGE_NT_HEADERS headers = nullptr;

	if (BufferSize)return STATUS_INVALID_PARAMETER_5;

	status = MmpValidateLoadDllMemoryParameters(BaseAddress, LdrEntry, dwFlags, BufferAddress, BufferSize);
	if (!NT_SUCCESS(status))return status;

	//
	// Serialize the whole lookup-and-publish window against ntdll's loader.
	//
	// Two things below require it. The duplicate-module scan walks
	// PEB->Ldr->InLoadOrderModuleList, a list ntdll only ever mutates under this
	// lock, so an unlocked walk can observe it mid-splice while any other thread
	// loads a DLL. And the scan is a check-then-act: without holding the lock
	// across the map and the LdrMapDllMemory() publish, two threads loading the
	// same image can both miss and both map it, producing two loader entries for
	// one module and a doubled DllMain.
	//
	// The lock is dropped again before the module's own entry points run; see
	// the Release() calls below.
	//
	MmpLoaderLockGuard loaderLock;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
		DllName = DllFullName = nullptr;
	}
	if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName))return STATUS_INVALID_PARAMETER_3;

	if (DllName) {
		int length = (int)wcslen(DllName);
		PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
		PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
		if (!h1)return STATUS_INVALID_IMAGE_FORMAT;
		
		while (ListEntry != ListHead) {
			PLDR_DATA_TABLE_ENTRY CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;

			/* Check if it's being unloaded */
			if (!CurEntry->InMemoryOrderLinks.Flink) continue;

			auto dist = (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - length;
			bool equal = false;
			if (dist == 0 || dist == 4) {
				equal = !_wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, length);
			}
			else {
				continue;
			}
			
			/* Check if name matches */
			if (equal) {

				/* Let's compare their headers */
				if (!(h2 = RtlImageNtHeader(CurEntry->DllBase)))continue;
				if (!(module = MapMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase)))continue;

				//
				// Skip a module that is already being torn down. Its loader entry
				// stays linked while DLL_PROCESS_DETACH runs outside the lock, so
				// without this check we would take a reference on it and hand back
				// a handle that the unloading thread is about to free.
				//
				if (module->underUnload)continue;

				if ((h1->OptionalHeader.SizeOfCode == h2->OptionalHeader.SizeOfCode) &&
					(h1->OptionalHeader.SizeOfHeaders == h2->OptionalHeader.SizeOfHeaders)) {
				
					/* This is our entry!, update load count and return success */
					if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)return STATUS_INVALID_PARAMETER_3;
					
					RtlUpdateReferenceCount(module, FLAG_REFERENCE);
					*BaseAddress = (HMEMORYMODULE)CurEntry->DllBase;
					if (LdrEntry)*LdrEntry = CurEntry;
					return STATUS_SUCCESS;
				}
			}
		}
	}

	status = MemoryLoadLibrary(BaseAddress, BufferAddress, (DWORD)BufferSize);
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)return status;

	if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
		__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		DebugBreak();
		ExitProcess(STATUS_INVALID_ADDRESS);
		TerminateProcess(NtCurrentProcess(), STATUS_INVALID_ADDRESS);
	}
	module->loadFromLdrLoadDllMemory = true;

	headers = RtlImageNtHeader(*BaseAddress);
	if (headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)dwFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {

		do {
			status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
			if (!NT_SUCCESS(status))break;

			status = MemorySetSectionProtection(LPBYTE(*BaseAddress), headers);
			if (!NT_SUCCESS(status))break;

			//
			// Run the module's TLS callbacks and DllMain without the loader lock,
			// as they were run before the lock was introduced. Holding it here
			// would let a DllMain that waits on another thread deadlock the
			// process against that thread's DLL_THREAD_ATTACH.
			//
			loaderLock.Release();

			if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
				status = STATUS_DLL_INIT_FAILED;
				break;
			}

		} while (false);

		if (!NT_SUCCESS(status)) {
			//
			// Retake the lock for the cleanup. MemoryFreeLibrary() enters the IAT
			// resolver lock and calls FreeLibrary() under it, so it has to run in
			// the same loader-lock-then-resolver-lock order as everywhere else.
			//
			MmpLoaderLockGuard cleanupLock;
			MemoryFreeLibrary(*BaseAddress);
		}

		return status;
	}

	do {

		status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
		if (!NT_SUCCESS(status))break;

		module->MappedDll = true;
		module->LdrEntry = ModuleEntry;

		status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
		if (!NT_SUCCESS(status))break;

		status = MemorySetSectionProtection(LPBYTE(*BaseAddress), headers);
		if (!NT_SUCCESS(status))break;

		if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;

		if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
			status = MmpRegisterExceptionTable((PVOID)module->codeBase, headers->OptionalHeader.SizeOfImage);
			if (!NT_SUCCESS(status)) break;

			module->InsertInvertedFunctionTableEntry = true;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
			status = MmpGlobalDataPtr->MmpFunctions->_MmpHandleTlsData(ModuleEntry);
			if (!NT_SUCCESS(status)) {
				if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) status = 0x7fffffff;
				if (!NT_SUCCESS(status))break;
			}
			else {
				module->TlsHandled = true;
			}
		}

		//
		// Everything that touches ntdll's shared structures is done; the module
		// is mapped and published. Drop the lock so the module's TLS callbacks
		// and DllMain run exactly as they did before the lock was introduced.
		// Holding it across DllMain would deadlock any module whose DllMain
		// waits on another thread, since that thread's DLL_THREAD_ATTACH needs
		// the same lock.
		//
		loaderLock.Release();

		if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
			status = STATUS_DLL_INIT_FAILED;
			break;
		}

	} while (false);

	//
	// Released either at the Release() above or here, before the failure path
	// re-enters LdrUnloadDllMemory (which takes the lock itself).
	//
	loaderLock.Release();

	if (NT_SUCCESS(status)) {
		if (LdrEntry)*LdrEntry = ModuleEntry;
	}
	else {
		LdrUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
	}

	return status;
}

NTSTATUS NTAPI LdrUnloadDllMemory(_In_ HMEMORYMODULE BaseAddress) {
	PLDR_DATA_TABLE_ENTRY CurEntry;
	ULONG count = 0;
	NTSTATUS status = STATUS_SUCCESS;

	//
	// Mirror of the load path: hold the loader lock across the reference count
	// decision so two threads cannot both conclude they are the last reference
	// and tear the module down twice, then drop it to run DLL_PROCESS_DETACH,
	// then retake it for the structural teardown.
	//
	// The lock is taken before the handle is resolved, not after. MapMemoryModuleHandle()
	// and RtlImageNtHeader() both read the image, and if another thread completed
	// the final unload first, that memory is already released -- reading it
	// outside the lock is a use after free.
	//
	MmpLoaderLockGuard loaderLock;

	PMEMORYMODULE module = MapMemoryModuleHandle(BaseAddress);
	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);

	do {

		//Not a memory module loaded via LdrLoadDllMemory
		if (!module || !module->loadFromLdrLoadDllMemory) {
			status = STATUS_INVALID_HANDLE;
			break;
		}

		if (MmpGlobalDataPtr == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		//Mapping dll failed
		if (!module->MappedDll) {
			module->underUnload = true;
			status = (MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
			break;
		}

		CurEntry = (PLDR_DATA_TABLE_ENTRY)module->LdrEntry;

		if (headers->OptionalHeader.SizeOfImage != CurEntry->SizeOfImage) __fastfail(FAST_FAIL_FATAL_APP_EXIT);

		if (module->UseReferenceCount) {
			status = RtlGetReferenceCount(module, &count);
			if (!NT_SUCCESS(status)) break;
		}

		if (count & ~1) {
			status = RtlUpdateReferenceCount(module, FLAG_DEREFERENCE);
			break;
		}

		//
		// underUnload is published before the lock is dropped, so a concurrent
		// unload of the same module sees the teardown already in progress.
		//
		module->underUnload = true;

		//
		// DLL_PROCESS_DETACH is module code, so run it outside the lock for the
		// same reason DLL_PROCESS_ATTACH is run outside it in the load path.
		//
		loaderLock.Release();

		if (module->initialized) {
			PLDR_INIT_ROUTINE((LPVOID)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))(
				(HINSTANCE)module->codeBase,
				DLL_PROCESS_DETACH,
				0
				);
		}

		//
		// Retake it for the teardown: unlinking the loader entry and removing the
		// inverted function table entry both mutate ntdll's shared structures.
		//
		MmpLoaderLockGuard teardownLock;

		if (module->MappedDll) {
			if (module->InsertInvertedFunctionTableEntry) {
				status = MmpUnregisterExceptionTable(BaseAddress);
				if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
			}

			if (module->TlsHandled) {
				status = MmpGlobalDataPtr->MmpFunctions->_MmpReleaseTlsEntry(CurEntry);
				if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
			}

			if (!RtlFreeLdrDataTableEntry(CurEntry)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
		}

		if (!MemoryFreeLibrary(BaseAddress)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);

	} while (false);

	return status;
}

DECLSPEC_NORETURN
VOID NTAPI LdrUnloadDllMemoryAndExitThread(_In_ HMEMORYMODULE BaseAddress, _In_ DWORD dwExitCode) {
	LdrUnloadDllMemory(BaseAddress);
	RtlExitUserThread(dwExitCode);
}

NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(_Out_ PDWORD pFeatures) {
	NTSTATUS status = STATUS_SUCCESS;
	__try {
		*pFeatures = MmpGlobalDataPtr->MmpFeatures;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	return status;
}
