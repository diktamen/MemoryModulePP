#include "stdafx.h"

extern "C" volatile LONG MmpModuleDatatableLockLocated = 0;
extern "C" volatile LONG MmpModuleDatatableLockAcquires = 0;
extern "C" volatile LONG MmpModuleDatatableLockSkipped = 0;
extern "C" volatile LONG MmpModuleDatatableLockRva = 0;

//
// How many donors agreed on the address that won. The margin above
// MMP_LOCK_MIN_AGREEMENT is the only warning available when a future Windows
// build starts inlining the acquire in one donor after another: the capability
// does not fail loudly, it just stops locating the lock. Reading this in the
// stress harness turns "still works" into "still works, with N to spare".
//
extern "C" volatile LONG MmpModuleDatatableLockAgreement = 0;

typedef VOID(NTAPI* PFN_SRWLOCK_OP)(PVOID);

static PVOID           MmpModuleDatatableLock = nullptr;
static PFN_SRWLOCK_OP  MmpAcquireSRWLockExclusive = nullptr;
static PFN_SRWLOCK_OP  MmpReleaseSRWLockExclusive = nullptr;

//
// Exported ntdll functions from which the lock address can be decoded, either
// because they take it themselves or because they call a helper that does.
//
// This list is not guessed. lockprobe --survey decodes every named ntdll export
// on a machine and groups them by the address each yields; the group containing
// the causality-verified lock is the set of usable anchors on that build. Run
// across three configurations, that gives:
//
//                                    x64 2022   x64/ARM64X   ARM64
//   LdrQueryModuleServiceTags         yes        yes          yes
//   LdrGetDllHandleByMapping          yes        yes          yes
//   LdrInitShimEngineDynamic          yes        yes          yes
//   LdrGetDllHandleByName             yes        yes          -
//   LdrGetDllHandleEx                 yes        yes          -
//   LdrAddRefDll                      yes        -            yes
//   LdrDisableThreadCalloutsForDll    yes        -            yes
//   LdrGetDllFullName                 yes        -            -
//   LdrFindEntryForAddress            yes        -            -
//
// Worst case is five agreeing rather than the two this used to scrape by on.
// "-" means the export did not decode at all, which costs nothing; what matters
// is that none of these decodes to the *wrong* address on any configuration.
//
// Deliberately excluded, though both are loader functions that survey does place
// in the right group on some builds: LdrGetDllHandle and RtlQueueWorkItem each
// decode to a *different* ntdll SRW lock under ARM64EC. The plurality vote below
// exists to survive a stray answer like that, not to be fed them on purpose.
//
// Do not trim this list to whatever works on the machine in front of you --
// three of these carry ARM64 and two carry ARM64EC. Trimming silently disables
// the capability on an architecture you are not testing, and the failure is
// quiet: the guards become no-ops and the list corruption comes back.
//
static const char* const MmpLockDonors[] = {
	"LdrQueryModuleServiceTags",
	"LdrGetDllHandleByMapping",
	"LdrInitShimEngineDynamic",
	"LdrGetDllHandleByName",
	"LdrGetDllHandleEx",
	"LdrAddRefDll",
	"LdrDisableThreadCalloutsForDll",
	"LdrGetDllFullName",
	"LdrFindEntryForAddress",
};

#define MMP_LOCK_DONOR_COUNT (sizeof(MmpLockDonors) / sizeof(MmpLockDonors[0]))
#define MMP_LOCK_MIN_AGREEMENT 2

//
// MMPP_NO_DATATABLE_LOCK builds a control: the decoder always fails, the lock is
// never located, every guard becomes a no-op, and the library behaves exactly as
// it did before this file existed. That is what makes a same-session A/B
// possible, which stress/README.md insists on -- comparing against numbers from
// an earlier session is how this investigation went wrong twice.
//
#if !defined(MMPP_NO_DATATABLE_LOCK)

//
// Both decoders are compiled for both architectures on purpose. An x64 binary
// running on ARM64 Windows -- an x64 JDK on an arm64 machine, which is a common
// pairing -- gets ARM64EC fast-forward thunks from GetProcAddress, and the real
// code behind them is ARM64. So an x64 build has to be able to read ARM64.
//
static SIZE_T MmpAcquireTargetCount = 0;
static PVOID  MmpAcquireTargets[4] = { nullptr };

static BOOLEAN MmpIsAcquireTarget(_In_ const VOID* Target) {
	for (SIZE_T i = 0; i < MmpAcquireTargetCount; ++i)
		if (MmpAcquireTargets[i] == Target) return TRUE;
	return FALSE;
}

//
// On ARM64X, the x64 view of an ntdll export is a fast-forward sequence into the
// ARM64EC body rather than x64 code:
//
//     48 8B C4        mov  rax, rsp
//     48 89 58 20     mov  [rax+20h], rbx
//     55              push rbp
//     5D              pop  rbp
//     E9 <rel32>      jmp  <ARM64EC entry>
//
static BOOLEAN MmpFollowEcThunk(_In_ const VOID* Function, _Out_ const VOID** Target) {
	static const UCHAR sig[] = { 0x48,0x8B,0xC4,0x48,0x89,0x58,0x20,0x55,0x5D,0xE9 };
	const UCHAR* b = (const UCHAR*)Function;
	*Target = nullptr;

	for (SIZE_T i = 0; i < sizeof(sig); ++i)
		if (b[i] != sig[i]) return FALSE;

	LONG rel = (LONG)((ULONG)b[10] | ((ULONG)b[11] << 8) |
		((ULONG)b[12] << 16) | ((ULONG)b[13] << 24));
	*Target = b + 14 + rel;
	return TRUE;
}

//
// ntdll's own function table, used to decide whether a computed call target is
// real before recursing into it.
//
// The x64 decoder finds calls by scanning for an 0xE8 byte, and plenty of those
// bytes are operands rather than opcodes. Following one lands mid-instruction in
// unrelated code and the decode wanders. IMAGE_DIRECTORY_ENTRY_EXCEPTION already
// lists the start RVA of every function with unwind data, so "is this a function
// start" is a lookup rather than a guess, and the next entry's start says how far
// a scan may run before it leaves the function it began in.
//
// Both x64 and ARM64 put BeginAddress first and the table is sorted, which is
// what the OS unwinder relies on; only the entry stride differs. Searched in
// place -- no allocation, because this runs from DllMain.
//
static const UCHAR* MmpNtdllBase = nullptr;
static SIZE_T       MmpNtdllSize = 0;
static const UCHAR* MmpPdata = nullptr;
static SIZE_T       MmpPdataCount = 0;
static SIZE_T       MmpPdataStride = 0;
static ULONG        MmpPdataLow = 0;
static ULONG        MmpPdataHigh = 0;

static ULONG MmpPdataBegin(_In_ SIZE_T Index) {
	return *(const ULONG*)(MmpPdata + Index * MmpPdataStride);
}

static VOID MmpInitFunctionTable(_In_ HMODULE Ntdll) {
	MmpNtdllBase = (const UCHAR*)Ntdll;

	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(Ntdll);
	if (!headers) return;
	MmpNtdllSize = headers->OptionalHeader.SizeOfImage;

	IMAGE_DATA_DIRECTORY* dir =
		&headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (!dir->VirtualAddress || !dir->Size) return;

	MmpPdataStride = (headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? 12 : 8;
	MmpPdataCount = dir->Size / MmpPdataStride;
	if (!MmpPdataCount) return;

	MmpPdata = MmpNtdllBase + dir->VirtualAddress;
	__try {
		MmpPdataLow = MmpPdataBegin(0);
		MmpPdataHigh = MmpPdataBegin(MmpPdataCount - 1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		MmpPdata = nullptr;
		MmpPdataCount = 0;
	}
}

static BOOLEAN MmpIsFunctionStart(_In_ ULONG Rva) {
	SIZE_T lo = 0, hi = MmpPdataCount;
	while (lo < hi) {
		SIZE_T mid = lo + (hi - lo) / 2;
		ULONG begin = MmpPdataBegin(mid);
		if (begin == Rva) return TRUE;
		if (begin < Rva) lo = mid + 1; else hi = mid;
	}
	return FALSE;
}

//
// How far a scan starting at Rva may run without crossing into the next
// function. Falls back to Cap when the table cannot say.
//
static SIZE_T MmpFunctionExtent(_In_ ULONG Rva, _In_ SIZE_T Cap) {
	if (!MmpPdataCount || Rva < MmpPdataLow || Rva > MmpPdataHigh) return Cap;

	SIZE_T lo = 0, hi = MmpPdataCount;
	while (lo < hi) {                            // first start strictly above Rva
		SIZE_T mid = lo + (hi - lo) / 2;
		if (MmpPdataBegin(mid) <= Rva) lo = mid + 1; else hi = mid;
	}
	if (lo >= MmpPdataCount) return Cap;

	SIZE_T span = MmpPdataBegin(lo) - Rva;
	return (span && span < Cap) ? span : Cap;
}

//
// Whether a computed call target is worth recursing into. Certain when the
// function table covers the address; a shape check otherwise, because ARM64X
// keeps the x64/EC bodies outside the native .pdata this parses.
//
static BOOLEAN MmpIsFollowable(_In_ const VOID* Target) {
	if (!MmpNtdllBase || !MmpNtdllSize) return FALSE;

	ULONG_PTR t = (ULONG_PTR)Target;
	ULONG_PTR base = (ULONG_PTR)MmpNtdllBase;
	if (t < base || t + 16 >= base + MmpNtdllSize) return FALSE;

	ULONG rva = (ULONG)(t - base);
	if (MmpPdataCount) {
		if (MmpIsFunctionStart(rva)) return TRUE;
		if (rva >= MmpPdataLow && rva <= MmpPdataHigh) return FALSE;  // covered, not a start
	}

	if ((rva & 0xF) == 0) return TRUE;                 // aligned function start
	const UCHAR* p = (const UCHAR*)Target;             // rva is not page-aligned,
	return p[-1] == 0xCC || p[-1] == 0xC3;             // so p[-1] is on this page
}

//
// Track the result of every ADRP, and when a BL reaches an SRW acquire, report
// whatever the most recent `add x0, xN, #imm` produced -- the first argument,
// which at these call sites is the lock.
//
// Depth allows recursion into a callee, which ARM64EC needs. Native ARM64 ntdll
// loads the lock and calls the acquire in the exported function itself, but the
// ARM64EC compilation pushes it down: LdrQueryModuleServiceTags calls
// LdrpAcquireModuleDatatableLock directly, while the other donors reach it
// through LdrpFindLoadedDllByHandle or LdrpDereferenceModule first, so it can
// be two levels below the export.
//
static PVOID MmpDecodeArm64(
	_In_ const VOID* Function,
	_In_ SIZE_T MaxInstructions,
	_In_ ULONG Depth) {

	const ULONG* Code = (const ULONG*)Function;
	ULONG64 AdrpResult[32] = { 0 };
	BOOLEAN AdrpValid[32] = { 0 };
	ULONG64 Arg0 = 0;
	BOOLEAN Arg0Valid = FALSE;
	ULONG Calls = 0;

	for (SIZE_T i = 0; i < MaxInstructions; ++i) {
		ULONG insn = Code[i];
		ULONG64 pc = (ULONG64)(Code + i);

		// ADRP Xd, #imm
		if ((insn & 0x9F000000ul) == 0x90000000ul) {
			ULONG rd = insn & 0x1F;
			LONG64 immlo = (insn >> 29) & 0x3;
			LONG64 immhi = (insn >> 5) & 0x7FFFF;
			LONG64 imm = (immhi << 2) | immlo;
			if (imm & (1LL << 20)) imm -= (1LL << 21);
			AdrpResult[rd] = (pc & ~0xFFFULL) + (imm << 12);
			AdrpValid[rd] = TRUE;
			continue;
		}

		// ADD Xd, Xn, #imm12   (64-bit, immediate form, LSL #0)
		if ((insn & 0xFF800000ul) == 0x91000000ul) {
			ULONG rd = insn & 0x1F;
			ULONG rn = (insn >> 5) & 0x1F;
			ULONG imm12 = (insn >> 10) & 0xFFF;
			if (rd == 0 && AdrpValid[rn]) {
				Arg0 = AdrpResult[rn] + imm12;
				Arg0Valid = TRUE;
			}
			continue;
		}

		// BL #imm26
		if ((insn & 0xFC000000ul) == 0x94000000ul) {
			LONG64 off = insn & 0x03FFFFFF;
			if (off & (1LL << 25)) off -= (1LL << 26);
			const VOID* target = (const VOID*)(pc + (off << 2));
			if (MmpIsAcquireTarget(target)) {
				return Arg0Valid ? (PVOID)Arg0 : nullptr;
			}
			if (Depth > 0 && ++Calls <= 6) {
				PVOID r = MmpDecodeArm64(target, 128, Depth - 1);
				if (r) return r;
			}
			continue;
		}

		if (insn == 0xD65F03C0ul) break;   // RET
	}

	return nullptr;
}

#endif

#if !defined(MMPP_NO_DATATABLE_LOCK)

static LONG MmpReadLE32(_In_ const UCHAR* p) {
	return (LONG)((ULONG)p[0] | ((ULONG)p[1] << 8) | ((ULONG)p[2] << 16) | ((ULONG)p[3] << 24));
}

static ULONG64 MmpReadLE64(_In_ const UCHAR* p) {
	ULONG64 v = 0;
	for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
	return v;
}

//
// A byte scan rather than a length-disassembler, because we only need to find
// one call and the instruction that set its first argument. Find `call rel32`
// whose target is an SRW acquire, then walk back a short way for whatever loaded
// RCX: `lea rcx,[rip+disp32]` in every case seen so far, with `mov rcx, imm64`
// accepted too since it costs nothing.
//
// Walking backwards over variable-length x86 is not generally sound, but it is
// safe enough here: we are testing for two fixed opcode prefixes at each offset,
// a false positive has to survive the range and alignment validation below, and
// two donors have to independently agree on the same address.
//
// Depth mirrors what the ARM64 decoder has always done, and is what makes this
// work on x64 rather than limping. Only LdrQueryModuleServiceTags and
// LdrAddRefDll take the lock in the exported function itself; the rest hand a
// caller-supplied handle to an internal helper -- LdrpFindLoadedDllByHandle and
// friends -- and the acquire happens down there. Without recursion those exports
// simply do not decode, which is why a genuine x64 Server 2022 used to scrape by
// on the bare minimum of two agreeing donors and now gets all of them.
//
// Unlike a BL on ARM64, an 0xE8 found by byte scanning may be an operand rather
// than an opcode, so recursion only follows targets MmpIsFollowable accepts.
//
static PVOID MmpDecodeX64(
	_In_ const VOID* Function,
	_In_ SIZE_T MaxBytes,
	_In_ ULONG Depth) {

	const UCHAR* p = (const UCHAR*)Function;
	ULONG followed = 0;

	ULONG_PTR base = (ULONG_PTR)MmpNtdllBase;
	if (MmpNtdllBase && (ULONG_PTR)p >= base && (ULONG_PTR)p < base + MmpNtdllSize)
		MaxBytes = MmpFunctionExtent((ULONG)((ULONG_PTR)p - base), MaxBytes);

	for (SIZE_T i = 0; i + 5 <= MaxBytes; ++i) {
		if (p[i] != 0xE8 && p[i] != 0xE9) continue;             // call / jmp rel32
		const VOID* target = p + i + 5 + MmpReadLE32(p + i + 1);

		if (MmpIsAcquireTarget(target)) {
			for (SIZE_T back = 3; back <= 64 && back <= i; ++back) {
				const UCHAR* q = p + i - back;
				if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) {  // lea rcx,[rip+d]
					return (PVOID)(q + 7 + MmpReadLE32(q + 3));
				}
				if (q[0] == 0x48 && q[1] == 0xB9) {                  // mov rcx, imm64
					return (PVOID)MmpReadLE64(q + 2);
				}
			}
			continue;      // acquire on a register we cannot source; keep looking
		}

		if (Depth > 0 && ++followed <= 8 && MmpIsFollowable(target)) {
			PVOID r = MmpDecodeX64(target, 1024, Depth - 1);
			if (r) return r;
		}
	}

	return nullptr;
}

//
// Pick the right reader for whatever this export actually is. Three shapes have
// been observed, all verified by lockprobe's causality check:
//
//   native x64      x64 code, `lea rcx,[rip+d]` then `call rel32`
//   native ARM64    ARM64 code, `adrp`/`add x0` then `bl`, acquire in-function
//   x64 on ARM64X   fast-forward thunk into an ARM64EC body, acquire up to two
//                   calls deeper, and note it resolves to a *different* lock
//                   than the native ARM64 view of the same ntdll
//
static PVOID MmpDecodeDonor(_In_ const VOID* Function) {
	const VOID* ecBody = nullptr;

	if (MmpFollowEcThunk(Function, &ecBody)) {
		PVOID r = MmpDecodeArm64(ecBody, 256, 2);
		if (r) return r;
		return MmpDecodeX64(ecBody, 512, 2);
	}

	PVOID r = MmpDecodeX64(Function, 512, 2);
	if (r) return r;
	return MmpDecodeArm64(Function, 256, 2);
}

#else

//
// Control build (MMPP_NO_DATATABLE_LOCK). Returning null leaves every guard a
// no-op, which is the behaviour that shipped before this file existed rather
// than a guess.
//
static PVOID MmpDecodeDonor(_In_ const VOID* Function) {
	UNREFERENCED_PARAMETER(Function);
	return nullptr;
}

#endif

//
// A decoded address is only accepted if it lands inside ntdll's image, on a
// committed writable page, and is pointer-aligned. Combined with several donors
// having to agree, that is what stands in for the causality check the bench
// does. Acquiring the wrong word as an SRW lock would corrupt ntdll, so this
// stays strict: anything unexpected disables the capability.
//
static BOOLEAN MmpIsPlausibleLockAddress(_In_ PVOID Candidate, _In_ HMODULE Ntdll) {
	if (!Candidate) return FALSE;
	if ((ULONG_PTR)Candidate & (sizeof(PVOID) - 1)) return FALSE;

	PIMAGE_NT_HEADERS headers = RtlImageNtHeader(Ntdll);
	if (!headers) return FALSE;

	ULONG_PTR base = (ULONG_PTR)Ntdll;
	ULONG_PTR end = base + headers->OptionalHeader.SizeOfImage;
	if ((ULONG_PTR)Candidate < base || (ULONG_PTR)Candidate + sizeof(PVOID) > end) return FALSE;

	MEMORY_BASIC_INFORMATION mbi{};
	if (!VirtualQuery(Candidate, &mbi, sizeof(mbi))) return FALSE;
	if (mbi.State != MEM_COMMIT) return FALSE;

	//
	// Must be writable, since ntdll writes the lock word. Every writable
	// protection is accepted rather than just PAGE_READWRITE: a false reject here
	// would silently disable the capability on some build whose .data happens to
	// be mapped write-copy or, on a page shared with code, executable. Read-only
	// and no-access still fail, which is what actually rules out a bad decode.
	//
	const DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY |
		PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
	if (!(mbi.Protect & writable)) return FALSE;

	return TRUE;
}

NTSTATUS NTAPI MmpInitializeModuleDatatableLock() {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) return STATUS_NOT_SUPPORTED;

	PVOID acquireExclusive = GetProcAddress(ntdll, "RtlAcquireSRWLockExclusive");
	PVOID acquireShared = GetProcAddress(ntdll, "RtlAcquireSRWLockShared");
	PVOID releaseExclusive = GetProcAddress(ntdll, "RtlReleaseSRWLockExclusive");
	if (!acquireExclusive || !acquireShared || !releaseExclusive) return STATUS_NOT_SUPPORTED;

#if !defined(MMPP_NO_DATATABLE_LOCK)
	MmpInitFunctionTable(ntdll);

	//
	// A call site targets either the export itself or, on ARM64X, the ARM64EC
	// body its fast-forward thunk jumps to. Accept both, or the ARM64EC decode
	// finds no acquire to anchor on.
	//
	MmpAcquireTargetCount = 0;
	MmpAcquireTargets[MmpAcquireTargetCount++] = acquireExclusive;
	MmpAcquireTargets[MmpAcquireTargetCount++] = acquireShared;
	{
		const VOID* followed = nullptr;
		__try {
			if (MmpFollowEcThunk(acquireExclusive, &followed))
				MmpAcquireTargets[MmpAcquireTargetCount++] = (PVOID)followed;
			if (MmpFollowEcThunk(acquireShared, &followed))
				MmpAcquireTargets[MmpAcquireTargetCount++] = (PVOID)followed;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}
#endif

	//
	// Tally votes per distinct address and take the plurality, rather than
	// rejecting outright the moment two donors disagree. With the donor list
	// spanning two architectures most entries do not decode at all on any given
	// target, and one spurious decode should not be able to disable the whole
	// capability -- which is what "any disagreement means trust nothing" would
	// do. The winner still has to clear MMP_LOCK_MIN_AGREEMENT, and a tie is
	// treated as no answer.
	//
	PVOID candidates[MMP_LOCK_DONOR_COUNT] = { nullptr };
	ULONG votes[MMP_LOCK_DONOR_COUNT] = { 0 };
	SIZE_T distinct = 0;

	for (SIZE_T i = 0; i < MMP_LOCK_DONOR_COUNT; ++i) {
		PVOID donor = GetProcAddress(ntdll, MmpLockDonors[i]);
		if (!donor) continue;

		PVOID candidate = nullptr;
		__try {
			candidate = MmpDecodeDonor(donor);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			candidate = nullptr;
		}

		if (!candidate || !MmpIsPlausibleLockAddress(candidate, ntdll)) continue;

		SIZE_T slot = 0;
		for (; slot < distinct; ++slot) if (candidates[slot] == candidate) break;
		if (slot == distinct) candidates[distinct++] = candidate;
		++votes[slot];
	}

	PVOID agreed = nullptr;
	ULONG agree = 0;
	BOOLEAN tied = FALSE;

	for (SIZE_T i = 0; i < distinct; ++i) {
		if (votes[i] > agree) { agreed = candidates[i]; agree = votes[i]; tied = FALSE; }
		else if (votes[i] == agree) tied = TRUE;
	}

	if (!agreed || agree < MMP_LOCK_MIN_AGREEMENT || tied) return STATUS_NOT_SUPPORTED;

	MmpAcquireSRWLockExclusive = (PFN_SRWLOCK_OP)acquireExclusive;
	MmpReleaseSRWLockExclusive = (PFN_SRWLOCK_OP)releaseExclusive;
	MmpModuleDatatableLock = agreed;

	MmpModuleDatatableLockRva = (LONG)((ULONG_PTR)agreed - (ULONG_PTR)ntdll);
	MmpModuleDatatableLockAgreement = (LONG)agree;
	MmpModuleDatatableLockLocated = 1;
	return STATUS_SUCCESS;
}

extern "C" volatile LONG MmpModuleDatatableLockVerified = 0;

//
// Context for the probe thread. File-scope rather than a local: on the
// pathological path where the probe cannot finish we give up waiting for it, and
// a stack-allocated context would be released while that thread still held a
// pointer to it. Only ever used by the single verification below.
//
static struct {
	HANDLE Ready;
	HANDLE Go;
	HANDLE Done;
} MmpLockProbe = { nullptr, nullptr, nullptr };

static DWORD WINAPI MmpLockProbeThread(LPVOID Parameter) {
	UNREFERENCED_PARAMETER(Parameter);
	SetEvent(MmpLockProbe.Ready);
	WaitForSingleObject(MmpLockProbe.Go, INFINITE);

	//
	// An ordinary load. It has to pass through the loader database, so it has to
	// take the lock we are holding.
	//
	HMODULE module = LoadLibraryW(L"version.dll");
	if (module) FreeLibrary(module);

	SetEvent(MmpLockProbe.Done);
	return 0;
}

//
// True when this thread already owns ntdll's loader lock, which is what being
// called from inside somebody's DllMain looks like.
//
static BOOLEAN MmpLoaderLockHeldByCurrentThread() {
	PRTL_CRITICAL_SECTION lock = NtCurrentPeb()->LoaderLock;
	return lock && lock->OwningThread == NtCurrentTeb()->ClientId.UniqueThread;
}

static volatile LONG MmpVerifyClaimed = 0;

VOID NTAPI MmpVerifyModuleDatatableLock() {
	if (!MmpModuleDatatableLock || MmpModuleDatatableLockVerified) return;

	//
	// Entered from a DllMain we do not control. The probe thread cannot run its
	// DLL_THREAD_ATTACH until that DllMain returns, so both waits below would
	// expire and a perfectly good address would read as a failure. Skip, and
	// leave the lock resting on donor agreement plus the structural checks.
	//
	// Tested before the claim below, so that a skipped attempt leaves the way
	// open for a later call from an ordinary thread to try again.
	//
	if (MmpLoaderLockHeldByCurrentThread()) return;

	//
	// One attempt per process. A caller that prewarms on its own thread and a
	// first load arriving at the same time both reach here, and two threads each
	// taking the lock exclusively to time the other's loads would measure
	// nothing useful. The loser returns and carries on; verification is
	// advisory, and the lock is already usable.
	//
	if (InterlockedCompareExchange(&MmpVerifyClaimed, 1, 0) != 0) return;

	MmpLockProbe.Ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	MmpLockProbe.Go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	MmpLockProbe.Done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!MmpLockProbe.Ready || !MmpLockProbe.Go || !MmpLockProbe.Done) return;

	//
	// Started before the lock is taken: thread start-up runs DLL_THREAD_ATTACH,
	// which enters the loader, and that has to happen while nothing is held.
	//
	HANDLE thread = CreateThread(nullptr, 0, MmpLockProbeThread, nullptr, 0, nullptr);
	if (!thread) return;

	//
	// Wait for the probe to reach its wait rather than sleeping a guessed
	// interval. If it cannot even get that far the machine is in no state to be
	// measured, so leave the lock on the structural checks and give up.
	//
	if (WaitForSingleObject(MmpLockProbe.Ready, 5000) != WAIT_OBJECT_0) return;

	MmpAcquireSRWLockExclusive(MmpModuleDatatableLock);
	SetEvent(MmpLockProbe.Go);
	DWORD blocked = WaitForSingleObject(MmpLockProbe.Done, 400);
	MmpReleaseSRWLockExclusive(MmpModuleDatatableLock);
	DWORD freed = WaitForSingleObject(MmpLockProbe.Done, 5000);

	if (blocked == WAIT_OBJECT_0) {
		//
		// Positive disproof: the loader walked straight through a lock we were
		// holding exclusively, so this is not the lock it needs. Stand the
		// capability down rather than keep taking an unrelated word as an SRW
		// lock, which would corrupt whatever actually owns it.
		//
		MmpModuleDatatableLock = nullptr;
		MmpModuleDatatableLockLocated = 0;
	}
	else if (freed == WAIT_OBJECT_0) {
		MmpModuleDatatableLockVerified = 1;
	}
	//
	// Anything else is inconclusive -- a loaded-down machine, or a probe that
	// never got scheduled. Deliberately not treated as a failure: switching the
	// lock off on an ambiguous result brings back the list corruption this
	// exists to prevent, and the structural checks already stand behind it.
	//

	if (WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0) {
		CloseHandle(thread);
		CloseHandle(MmpLockProbe.Ready);
		CloseHandle(MmpLockProbe.Go);
		CloseHandle(MmpLockProbe.Done);
		MmpLockProbe.Ready = MmpLockProbe.Go = MmpLockProbe.Done = nullptr;
	}
	//
	// Otherwise leak the three handles on purpose. The thread still holds the
	// event handles, and closing them under it is worse than a bounded leak on a
	// path that runs at most once per process.
	//
}

MmpDatatableLockGuard::MmpDatatableLockGuard() : Lock(MmpModuleDatatableLock) {
	if (!Lock) {
		InterlockedIncrement(&MmpModuleDatatableLockSkipped);
		return;
	}
	MmpAcquireSRWLockExclusive(Lock);
	InterlockedIncrement(&MmpModuleDatatableLockAcquires);
}

VOID MmpDatatableLockGuard::Release() {
	if (!Lock) return;
	PVOID held = Lock;
	Lock = nullptr;
	MmpReleaseSRWLockExclusive(held);
}

MmpDatatableLockGuard::~MmpDatatableLockGuard() { Release(); }
