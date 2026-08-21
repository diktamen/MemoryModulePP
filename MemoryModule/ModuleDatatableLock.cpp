#include "stdafx.h"

extern "C" volatile LONG MmpModuleDatatableLockLocated = 0;
extern "C" volatile LONG MmpModuleDatatableLockAcquires = 0;
extern "C" volatile LONG MmpModuleDatatableLockSkipped = 0;
extern "C" volatile LONG MmpModuleDatatableLockRva = 0;

typedef VOID(NTAPI* PFN_SRWLOCK_OP)(PVOID);

static PVOID           MmpModuleDatatableLock = nullptr;
static PFN_SRWLOCK_OP  MmpAcquireSRWLockExclusive = nullptr;
static PFN_SRWLOCK_OP  MmpReleaseSRWLockExclusive = nullptr;

//
// Exported ntdll functions that load the lock into the first-argument register
// and then call an exported SRW acquire.
//
// This has to be the union across architectures and Windows versions, because
// which of them are decodable varies and the overlap is thin. Measured:
//
//                                    ARM64 10.0.26100   x64 6.3-era (2014)
//   LdrQueryModuleServiceTags         yes                yes
//   LdrDisableThreadCalloutsForDll    yes                no (inlined)
//   LdrGetDllHandleByMapping          yes                no (inlined)
//   LdrAddRefDll                      no (inlined)       yes
//   LdrGetDllFullName                 no (inlined)       no (inlined)
//
// Only LdrQueryModuleServiceTags decodes on both, so on each target exactly two
// donors agree -- which is the minimum this file accepts. Do not trim this list
// to the ones that work on whatever machine you happen to be testing: dropping
// LdrAddRefDll silently disables the whole capability on x64, and dropping the
// other two disables it on ARM64. If a future build inlines one more of these,
// agreement falls below the minimum and the capability turns itself off, which
// is the intended failure direction but shows up as the bug coming back.
//
static const char* const MmpLockDonors[] = {
	"LdrQueryModuleServiceTags",
	"LdrDisableThreadCalloutsForDll",
	"LdrGetDllHandleByMapping",
	"LdrAddRefDll",
	"LdrGetDllFullName",
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
static PVOID MmpDecodeX64(_In_ const VOID* Function, _In_ SIZE_T MaxBytes) {
	const UCHAR* p = (const UCHAR*)Function;

	for (SIZE_T i = 0; i + 5 <= MaxBytes; ++i) {
		if (p[i] != 0xE8) continue;                                  // call rel32
		const VOID* target = p + i + 5 + MmpReadLE32(p + i + 1);
		if (!MmpIsAcquireTarget(target)) continue;

		for (SIZE_T back = 3; back <= 64 && back <= i; ++back) {
			const UCHAR* q = p + i - back;
			if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) {      // lea rcx,[rip+d]
				return (PVOID)(q + 7 + MmpReadLE32(q + 3));
			}
			if (q[0] == 0x48 && q[1] == 0xB9) {                      // mov rcx, imm64
				return (PVOID)MmpReadLE64(q + 2);
			}
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
		return MmpDecodeX64(ecBody, 512);
	}

	PVOID r = MmpDecodeX64(Function, 512);
	if (r) return r;
	return MmpDecodeArm64(Function, 256, 0);
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
	MmpModuleDatatableLockLocated = 1;
	return STATUS_SUCCESS;
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
