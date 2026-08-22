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
//
// Counts loader lock acquisitions that did not succeed. Exported so the stress
// harness can tell "we mutated ntdll's lists unlocked" apart from every other
// explanation for list corruption. Should be zero.
//
extern "C" __declspec(dllexport) volatile LONG MmpLoaderLockAcquireFailures;

struct MmpLoaderLockGuard {
	PVOID Cookie = nullptr;
	bool Held = false;

	//
	// Set once in the constructor and never cleared, so it stays meaningful after
	// a deliberate Release() -- which also leaves Held false.
	//
	bool AcquireFailed = false;

	//
	// Acquisition must not silently fall through to unserialized access: the
	// caller is about to splice ntdll's module lists, and doing that without the
	// lock is exactly what corrupts them. Retry until the lock is genuinely
	// held, the way ntdll's own callers do.
	//
	// This used to give up after 64 attempts and carry on with Held == false,
	// which is the one thing a caller about to splice ntdll's structures must
	// never do. Worse, with Held == false the IAT resolver lock was then taken
	// *before* the loader lock, inverting the order used everywhere else and
	// opening a genuine AB-BA deadlock against any other thread. The counter has
	// read 0 across every measurement, so this has never fired -- but "never
	// observed" is not a reason to leave the unsafe branch in place.
	//
	// Failure is now reported instead. Load paths fail the load; teardown paths,
	// which have no way to decline, treat it as fatal -- the same judgement the
	// unlink failures in LdrUnloadDllMemory already make.
	//
	MmpLoaderLockGuard() {
		for (ULONG attempt = 0; attempt < 64 && !Held; ++attempt) {
			ULONG disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID;
			Cookie = nullptr;
			if (NT_SUCCESS(LdrLockLoaderLock(0, &disposition, &Cookie)) &&
				disposition == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED) {
				Held = true;
			}
			else {
				MmpLoaderLockAcquireFailures++;
			}
		}
		AcquireFailed = !Held;
	}

	//
	// True when the lock could not be taken at all. Distinct from !Held, which is
	// also the normal state after a deliberate Release().
	//
	bool Failed() const { return AcquireFailed; }
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

	//
	// Retake the lock after a Release(). Used to step around a region that must
	// not run with the loader lock held, such as one that calls LoadLibrary().
	//
	void Reacquire() {
		if (Held) return;
		ULONG disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID;
		Cookie = nullptr;
		if (NT_SUCCESS(LdrLockLoaderLock(0, &disposition, &Cookie)) &&
			disposition == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED) {
			Held = true;
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
