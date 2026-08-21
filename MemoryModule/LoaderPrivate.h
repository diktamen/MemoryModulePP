#pragma once

//
// RAII wrapper around ntdll's loader lock.
//
// The loader lock is what ntdll's own loader holds while it mutates the
// process-global structures we also touch: the PEB module lists, the
// LdrpInvertedFunctionTable, and LdrpHandleTlsData's internals. Holding it
// makes us mutually exclusive with concurrent LoadLibrary calls on other
// threads. It is recursive per-thread, so nested acquisition (a dependency
// load re-entering through the import resolver) is safe.
//
// Acquisition is best effort: if the lock cannot be taken, Held stays false
// and the caller proceeds unserialized rather than failing the load.
//
struct MmpLoaderLockGuard {
	PVOID Cookie = nullptr;
	bool Held = false;

	MmpLoaderLockGuard() {
		ULONG disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID;
		if (NT_SUCCESS(LdrLockLoaderLock(0, &disposition, &Cookie)) &&
			disposition == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED) {
			Held = true;
		}
	}
	~MmpLoaderLockGuard() { Release(); }

	//
	// Drop the lock before the point it is no longer needed. Used to run module
	// entry points (TLS callbacks, DllMain) outside the lock, so their
	// threading behaviour is unchanged from before the lock was introduced.
	//
	void Release() {
		if (Held) {
			LdrUnlockLoaderLock(0, Cookie);
			Held = false;
		}
	}

	MmpLoaderLockGuard(const MmpLoaderLockGuard&) = delete;
	MmpLoaderLockGuard& operator=(const MmpLoaderLockGuard&) = delete;
};

NTSTATUS NTAPI LdrMapDllMemory(
	_In_ HMEMORYMODULE ViewBase,
	_In_ DWORD dwFlags,
	_In_opt_ PCWSTR DllName,
	_In_opt_ PCWSTR lpFullDllName,
	_Out_opt_ PLDR_DATA_TABLE_ENTRY* DataTableEntry
);
