#include "stdafx.h"
#include <cstdlib>

static NTSTATUS NTAPI LdrMapDllMemory(IN HMEMORYMODULE ViewBase, IN DWORD dwFlags, IN PCWSTR DllName OPTIONAL,
	IN PCWSTR lpFullDllName OPTIONAL, OUT PLDR_DATA_TABLE_ENTRY* DataTableEntry OPTIONAL) {

	UNICODE_STRING FullDllName, BaseDllName;
	PIMAGE_NT_HEADERS NtHeaders;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	HANDLE heap = NtCurrentPeb()->ProcessHeap;

	if (!(NtHeaders = RtlImageNtHeader(ViewBase))) return STATUS_INVALID_IMAGE_FORMAT;

	if (!(LdrEntry = RtlAllocateDataTableEntry(ViewBase))) return STATUS_NO_MEMORY;

	if (!RtlResolveDllNameUnicodeString(DllName, lpFullDllName, &BaseDllName, &FullDllName)) {
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

NTSTATUS NTAPI LdrLoadDllMemory(OUT HMEMORYMODULE* BaseAddress, IN LPVOID BufferAddress, IN size_t BufferSize) {
	return LdrLoadDllMemoryExW(BaseAddress, nullptr, LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS, BufferAddress, BufferSize, nullptr, nullptr);
}

NTSTATUS NTAPI LdrLoadDllMemoryExW(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PVOID* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCWSTR DllName OPTIONAL,
	IN LPCWSTR DllFullName OPTIONAL) {
	PMEMORYMODULE module = nullptr;
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
	PIMAGE_NT_HEADERS headers = nullptr;

	if (BufferSize)return STATUS_INVALID_PARAMETER_5;
	__try {
		*BaseAddress = nullptr;
		if (LdrEntry)*LdrEntry = nullptr;
		if (!(dwFlags & LOAD_FLAGS_PASS_IMAGE_CHECK) && !RtlIsValidImageBuffer(BufferAddress, &BufferSize))status = STATUS_INVALID_IMAGE_FORMAT;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))return status;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
		dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
		DllName = DllFullName = nullptr;
	}
	if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName))return STATUS_INVALID_PARAMETER_3;

	if (DllName) {
		PLIST_ENTRY ListHead, ListEntry;
		PLDR_DATA_TABLE_ENTRY CurEntry;
		PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
		if (!h1)return STATUS_INVALID_IMAGE_FORMAT;
		ListEntry = (ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList)->Flink;
		while (ListEntry != ListHead) {
			CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			ListEntry = ListEntry->Flink;
			/* Check if it's being unloaded */
			if (!CurEntry->InMemoryOrderLinks.Flink) continue;
			/* Check if name matches */
			if (!wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - 4) ||
				!wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, CurEntry->BaseDllName.Length / sizeof(wchar_t))) {
				/* Let's compare their headers */
				if (!(h2 = RtlImageNtHeader(CurEntry->DllBase)))continue;
				if (!(module = MapMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase)))continue;
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

	status = MemoryLoadLibrary(BaseAddress, BufferAddress, BufferSize);
	if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)return status;

	if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
		__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		DebugBreak();
		ExitProcess(STATUS_INVALID_ADDRESS);
		TerminateProcess(NtCurrentProcess(), STATUS_INVALID_ADDRESS);
	}
	module->loadFromNtLoadDllMemory = true;

	headers = RtlImageNtHeader(*BaseAddress);
	if (headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)dwFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

	if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {

		do {
			status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
			if (!NT_SUCCESS(status))break;

			status = MemorySetSectionProtection(LPBYTE(*BaseAddress), headers);
			if (!NT_SUCCESS(status))break;

			if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
				status = STATUS_DLL_INIT_FAILED;
				break;
			}

		} while (false);

		if (!NT_SUCCESS(status)) {
			MemoryFreeLibrary(*BaseAddress);
		}

		return status;
	}

	do {

		status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
		if (!NT_SUCCESS(status))break;

		module->MappedDll = true;

		status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
		if (!NT_SUCCESS(status))break;

		status = MemorySetSectionProtection(LPBYTE(*BaseAddress), headers);
		if (!NT_SUCCESS(status))break;

		if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;

		if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
			status = RtlInsertInvertedFunctionTable((PVOID)module->codeBase, headers->OptionalHeader.SizeOfImage);
			if (!NT_SUCCESS(status)) break;

			module->InsertInvertedFunctionTableEntry = true;
		}

		if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
			status = MmpHandleTlsData(ModuleEntry);
			if (!NT_SUCCESS(status)) {
				if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) status = 0x7fffffff;
				if (!NT_SUCCESS(status))break;
			}
			else {
				module->TlsHandled = true;
			}
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			MmpPreInitializeHooksForDotNet();
		}

		if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
			status = STATUS_DLL_INIT_FAILED;
			break;
		}

		if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) {
			MmpInitializeHooksForDotNet();
		}

	} while (false);

	if (NT_SUCCESS(status)) {
		if (LdrEntry)*LdrEntry = ModuleEntry;
	}
	else {
		LdrUnloadDllMemory(*BaseAddress);
		*BaseAddress = nullptr;
	}

	return status;
}

NTSTATUS NTAPI LdrLoadDllMemoryExA(
	OUT HMEMORYMODULE* BaseAddress,
	OUT PVOID* LdrEntry OPTIONAL,
	IN DWORD dwFlags,
	IN LPVOID BufferAddress,
	IN size_t BufferSize,
	IN LPCSTR DllName OPTIONAL,
	IN LPCSTR DllFullName OPTIONAL){
	LPWSTR _DllName = nullptr, _DllFullName = nullptr;
	size_t size;
	NTSTATUS status;
	if (DllName) {
		size = strlen(DllName) + 1;
		_DllName = new wchar_t[size];
		mbstowcs(_DllName, DllName, size);
	}
	if (DllFullName) {
		size = strlen(DllFullName) + 1;
		_DllFullName = new wchar_t[size];
		mbstowcs(_DllFullName, DllFullName, size);
	}
	status = LdrLoadDllMemoryExW(BaseAddress, LdrEntry, dwFlags, BufferAddress, BufferSize, _DllName, _DllFullName);
	if (_DllName)delete[]_DllName;
	if (_DllFullName)delete[]_DllFullName;
	return status;
}

NTSTATUS NTAPI LdrUnloadDllMemory(IN HMEMORYMODULE BaseAddress) {
	__try {
		ProbeForRead(BaseAddress, sizeof(size_t));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
	
	PLDR_DATA_TABLE_ENTRY CurEntry;
	ULONG count = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PMEMORYMODULE module = MapMemoryModuleHandle(BaseAddress);

	//Not a memory module loaded via LdrLoadDllMemory
	if (!module || !module->loadFromNtLoadDllMemory)return STATUS_INVALID_HANDLE;

	//Mapping dll failed
	if (module->loadFromNtLoadDllMemory && !module->MappedDll) {
		module->underUnload = true;
		return MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	if (CurEntry = RtlFindLdrTableEntryByHandle(BaseAddress)) {
		PIMAGE_NT_HEADERS headers = RtlImageNtHeader(BaseAddress);
		if (headers->OptionalHeader.SizeOfImage == CurEntry->SizeOfImage) {
			if (module->UseReferenceCount) {
				status = RtlGetReferenceCount(module, &count);
				if (!NT_SUCCESS(status))return status;
			}
			if (!(count & ~1)) {
				module->underUnload = true;
				if (module->initialized) {
					PDLL_STARTUP_ROUTINE((LPVOID)(module->codeBase + headers->OptionalHeader.AddressOfEntryPoint))(
						(HINSTANCE)module->codeBase,
						DLL_PROCESS_DETACH,
						0
					);
				}
				if (module->MappedDll) {
					if (module->InsertInvertedFunctionTableEntry) {
						status = RtlRemoveInvertedFunctionTable(BaseAddress);
						if (!NT_SUCCESS(status))__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY);
					}
					if (module->TlsHandled) {
						
						status = MmpReleaseTlsEntry(CurEntry);
						if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
					}
					if (!RtlFreeLdrDataTableEntry(CurEntry))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				}
				if (!MemoryFreeLibrary(BaseAddress))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
				return STATUS_SUCCESS;
			}
			else {
				return RtlUpdateReferenceCount(module, FLAG_DEREFERENCE);
			}
		}
	}

	return STATUS_INVALID_HANDLE;
}

__declspec(noreturn)
VOID NTAPI LdrUnloadDllMemoryAndExitThread(IN HMEMORYMODULE BaseAddress, IN DWORD dwExitCode) {
	LdrUnloadDllMemory(BaseAddress);
	RtlExitUserThread(dwExitCode);
}

NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(OUT PDWORD pFeatures) {
	static DWORD features = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pfn = nullptr;
	bool value = false;
	__try {
		if (features) {
			*pFeatures = features;
			return status;
		} 

		if (RtlFindLdrpModuleBaseAddressIndex())features |= MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX;
		if (RtlFindLdrpHashTable())features |= MEMORY_FEATURE_LDRP_HASH_TABLE;
		if (RtlFindLdrpInvertedFunctionTable())features |= MEMORY_FEATURE_INVERTED_FUNCTION_TABLE;
		features |= MEMORY_FEATURE_LDRP_HEAP | MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA | MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY;

		if (features)features |= MEMORY_FEATURE_SUPPORT_VERSION;
		*pFeatures = features;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	return status;
}