#pragma once

//
// ntdll!LdrpModuleDatatableLock -- the lock that actually protects the loader
// database.
//
// Modern ntdll has two loader locks and they are disjoint objects:
//
//   LdrpLoaderLock          CRITICAL_SECTION  runs init routines: DllMain and
//                                             thread attach/detach
//   LdrpModuleDatatableLock SRWLOCK           the loader database: the three
//                                             PEB->Ldr module lists,
//                                             LdrpHashTable, and the module
//                                             base-address index
//
// LdrLockLoaderLock(), the only loader lock ntdll exports, takes the first one.
// We were taking that and splicing the structures guarded by the second, so
// every splice raced ntdll's own and ntdll eventually raised
// FAST_FAIL_CORRUPT_LIST_ENTRY out of LdrpInsertDataTableEntry on an unrelated
// thread doing an ordinary LoadLibrary. stress/README.md, "The wrong lock", has
// the disassembly.
//
// Two properties of this lock shape the code that uses it:
//
//   It is an SRW lock, so it is NOT recursive. Sections holding it must never
//   re-enter ntdll's loader. In particular it must never be held across
//   MemoryResolveImportTable (calls LoadLibrary), MemoryFreeLibrary (calls
//   FreeLibrary), a module entry point, or RtlFreeDependencies (calls
//   LdrUnloadDll). Any of those self-deadlocks immediately. Keep every section
//   down to the pointer writes themselves.
//
//   Ordering against the legacy lock is safe. Of ntdll's loader functions that
//   touch this lock, only LdrUnloadDll and LdrpDecrementModuleLoadCountEx also
//   take the legacy one, and both take them sequentially rather than nested:
//   acquire datatable, release it, then acquire legacy. ntdll therefore never
//   holds datatable while waiting for legacy, so our holding legacy and then
//   taking datatable cannot close a cycle.
//
// It is not exported, so it has to be located. That is done by ABI rather than
// by an opcode signature for the function or a per-build RVA: several exported
// ntdll functions acquire it by calling the exported RtlAcquireSRWLockShared or
// RtlAcquireSRWLockExclusive, and the calling convention puts the lock pointer
// in the first argument, so both ends of the pattern are GetProcAddress
// results and the only thing decoded is the instruction that materialises that
// argument. Several donors must agree. See MmpInitializeModuleDatatableLock.
//
// stress/lockprobe.cpp is the same locator as a standalone tool, plus a
// causality check that cannot be run from here: it holds the candidate and
// confirms an ordinary LoadLibrary on another thread blocks until release.
// Initialization runs inside DllMain under ntdll's loader lock, where creating
// a thread would deadlock, so this file relies on donor agreement plus range
// validation and leaves the behavioural proof to the bench.
//

//
// Diagnostics, exported so the stress harness can confirm the fix is actually
// active rather than inferring it from a passing run.
//
//   Located  1 once the lock has been found and validated, 0 otherwise. Zero
//            means every guard below is a no-op and we are running with the old
//            unsynchronized behaviour.
//   Acquires count of outermost acquisitions.
//   Skipped  count of guard constructions that did nothing because the lock was
//            never located.
//   Rva      offset of the located lock within ntdll.
//   Agreement how many donors agreed on it. Compare against the minimum of two:
//            this is the early warning that a Windows update has started
//            inlining the acquire in donor after donor, since the capability
//            does not fail loudly -- it just stops locating the lock.
//
//   Verified 1 once the causality check below has confirmed the address
//            behaviourally. 0 means the address rests on donor agreement and
//            the structural checks alone -- which is what shipped originally,
//            and is still the case whenever the check has to be skipped.
//
extern "C" __declspec(dllexport) volatile LONG MmpModuleDatatableLockLocated;
extern "C" __declspec(dllexport) volatile LONG MmpModuleDatatableLockAcquires;
extern "C" __declspec(dllexport) volatile LONG MmpModuleDatatableLockSkipped;
extern "C" __declspec(dllexport) volatile LONG MmpModuleDatatableLockRva;
extern "C" __declspec(dllexport) volatile LONG MmpModuleDatatableLockAgreement;
extern "C" __declspec(dllexport) volatile LONG MmpModuleDatatableLockVerified;

//
// Locate the lock. Call once from MmInitialize, with the loader lock already
// held. Returns STATUS_NOT_SUPPORTED when it cannot be found, which is not
// fatal: the guards degrade to no-ops and behaviour is exactly what it was
// before this file existed.
//
NTSTATUS NTAPI MmpInitializeModuleDatatableLock();

//
// Confirm the located address behaviourally: hold it exclusively and require
// that an ordinary LoadLibrary on another thread cannot finish, then require
// that it finishes the moment we let go. A wrong address cannot pass both.
//
// Must be called with the loader lock NOT held, which is why it cannot live
// beside MmpInitializeModuleDatatableLock: the probe thread's DLL_THREAD_ATTACH
// needs the loader lock, so running this from DllMain would deadlock. It runs
// from MmpEnsureInitialized instead, on the first real load. Safe to call more
// than once and safe to call when the lock was never located; both are no-ops.
//
VOID NTAPI MmpVerifyModuleDatatableLock();

//
// RAII exclusive hold. Constructing one when the lock was never located is a
// no-op, so call sites need no conditionals.
//
// Deliberately not recursive, matching the lock. Every call site below is a
// leaf: none of them is reachable from inside another. Where one operation
// needs two of them -- unlinking an entry and removing its base-address index
// node -- they are placed in the same guard rather than nested.
//
struct MmpDatatableLockGuard {
	PVOID Lock;

	MmpDatatableLockGuard();
	~MmpDatatableLockGuard();
	VOID Release();

	MmpDatatableLockGuard(const MmpDatatableLockGuard&) = delete;
	MmpDatatableLockGuard& operator=(const MmpDatatableLockGuard&) = delete;
};
