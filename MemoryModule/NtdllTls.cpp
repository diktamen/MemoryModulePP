#include "stdafx.h"
#include "NtdllTls.h"

extern "C" volatile LONG MmpTlsLocated = 0;
extern "C" volatile LONG MmpTlsHandleRva = 0;
extern "C" volatile LONG MmpTlsReleaseRva = 0;
extern "C" volatile LONG MmpTlsAgreement = 0;
extern "C" volatile LONG MmpTlsRefused = 0;

// ============================================================ ntdll image model

//
// ARM64X images carry a code map saying which ranges hold ARM64, ARM64EC and x64
// code, and a second runtime-function table for the other architecture. Both
// matter here: the loader is compiled twice on such a build, so the name literal
// is referenced from both copies and a locator that ignores the map gets two
// disagreeing answers. We must take the copy matching the code we ourselves run.
//
enum MMP_FLAVOUR { MMP_FL_ANY = -1, MMP_FL_ARM64 = 0, MMP_FL_ARM64EC = 1, MMP_FL_X64 = 2 };

typedef struct _MMP_ARM64EC_METADATA {
	ULONG Version, CodeMap, CodeMapCount, CodeRangesToEntryPoints, RedirectionMetadata;
	ULONG d0, d1, d2, d3, d4;
	ULONG AlternateEntryPoint, AuxiliaryIAT, CodeRangesToEntryPointsCount;
	ULONG RedirectionMetadataCount, GetX64InformationFunctionPointer;
	ULONG SetX64InformationFunctionPointer, ExtraRFETable, ExtraRFETableSize;
} MMP_ARM64EC_METADATA;

struct MMP_SECTION { ULONG Rva, Size; BOOLEAN Exec; };
struct MMP_FNTABLE { ULONG Rva, Size, Stride; BOOLEAN X64Fmt; };
struct MMP_CODERANGE { ULONG Rva, Size; MMP_FLAVOUR Flavour; };

static const UCHAR* MmpNt;
static SIZE_T       MmpNtSize;

static MMP_SECTION   MmpSec[32];
static ULONG         MmpSecCount;
static MMP_FNTABLE   MmpTab[2];
static ULONG         MmpTabCount;
static MMP_CODERANGE MmpRange[64];
static ULONG         MmpRangeCount;
static MMP_FLAVOUR   MmpOurFlavour = MMP_FL_ANY;

static ULONG* MmpFnStart;                                       // ascending, merged
static SIZE_T MmpFnCount;

static BOOLEAN MmpInExec(_In_ ULONG Rva) {
	for (ULONG i = 0; i < MmpSecCount; ++i)
		if (MmpSec[i].Exec && Rva >= MmpSec[i].Rva && Rva < MmpSec[i].Rva + MmpSec[i].Size) return TRUE;
	return FALSE;
}

static MMP_FLAVOUR MmpFlavourOf(_In_ ULONG Rva) {
	for (ULONG i = 0; i < MmpRangeCount; ++i)
		if (Rva >= MmpRange[i].Rva && Rva < MmpRange[i].Rva + MmpRange[i].Size) return MmpRange[i].Flavour;
	return MMP_FL_ANY;
}

static VOID MmpReadCodeMap(_In_ PIMAGE_NT_HEADERS Headers) {
	IMAGE_DATA_DIRECTORY* lc =
		&Headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (!lc->VirtualAddress || lc->Size < 0xD0) return;

	const UCHAR* cfg = MmpNt + lc->VirtualAddress;
	if (*(const ULONG*)cfg < 0xD0) return;

	ULONGLONG chpe = *(const ULONGLONG*)(cfg + 0xC8);           // CHPEMetadataPointer
	if (chpe <= (ULONGLONG)MmpNt || chpe >= (ULONGLONG)MmpNt + MmpNtSize) return;

	const MMP_ARM64EC_METADATA* m = (const MMP_ARM64EC_METADATA*)chpe;
	if (!m->CodeMap || m->CodeMap >= MmpNtSize || m->CodeMapCount > 256) return;

	const ULONG* cm = (const ULONG*)(MmpNt + m->CodeMap);
	for (ULONG i = 0; i < m->CodeMapCount && MmpRangeCount < 64; ++i) {
		ULONG start = cm[i * 2], len = cm[i * 2 + 1];
		MMP_CODERANGE* r = &MmpRange[MmpRangeCount++];
		r->Rva = start & ~3ul;
		r->Size = len;
		r->Flavour = (MMP_FLAVOUR)(start & 3);
	}

	//
	// The other architecture's runtime-function table. Without it, half the
	// functions in an ARM64X ntdll are invisible and the unwind walk cannot
	// resolve the copy belonging to this view.
	//
	if (MmpTabCount == 1 && m->ExtraRFETable && m->ExtraRFETableSize &&
		m->ExtraRFETable < MmpNtSize) {
		MMP_FNTABLE* t = &MmpTab[MmpTabCount++];
		t->Rva = m->ExtraRFETable;
		t->Size = m->ExtraRFETableSize;
		t->X64Fmt = MmpTab[0].X64Fmt ? FALSE : TRUE;            // always the opposite
		t->Stride = t->X64Fmt ? 12 : 8;
	}
}

//
// One ascending list of function starts out of every table. Merged by insertion
// rather than sorted: each table is already ascending, which is what the OS
// unwinder relies on, so this walks back over at most the tail contributed by
// the other table.
//
static BOOLEAN MmpBuildFunctionList() {
	SIZE_T cap = 0;
	for (ULONG i = 0; i < MmpTabCount; ++i) cap += MmpTab[i].Size / MmpTab[i].Stride;
	if (!cap) return FALSE;

	MmpFnStart = (ULONG*)RtlAllocateHeap(RtlProcessHeap(), 0, cap * sizeof(ULONG));
	if (!MmpFnStart) return FALSE;

	for (ULONG i = 0; i < MmpTabCount; ++i) {
		SIZE_T n = MmpTab[i].Size / MmpTab[i].Stride;
		const UCHAR* e = MmpNt + MmpTab[i].Rva;
		for (SIZE_T k = 0; k < n; ++k) {
			ULONG begin = *(const ULONG*)(e + k * MmpTab[i].Stride);
			if (!begin || begin >= MmpNtSize || !MmpInExec(begin)) continue;

			SIZE_T at = MmpFnCount;
			while (at && MmpFnStart[at - 1] > begin) { MmpFnStart[at] = MmpFnStart[at - 1]; --at; }
			if (at && MmpFnStart[at - 1] == begin) {
				// Duplicate: undo the shift we just made.
				while (at < MmpFnCount) { MmpFnStart[at] = MmpFnStart[at + 1]; ++at; }
				continue;
			}
			MmpFnStart[at] = begin;
			++MmpFnCount;
		}
	}
	return MmpFnCount != 0;
}

static BOOLEAN MmpInitImage(_In_ HMODULE Ntdll) {
	if (MmpFnCount) return TRUE;                                // already done

	MmpNt = (const UCHAR*)Ntdll;
	PIMAGE_NT_HEADERS h = RtlImageNtHeader(Ntdll);
	if (!h) return FALSE;

	MmpNtSize = h->OptionalHeader.SizeOfImage;

	PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(h);
	for (WORD i = 0; i < h->FileHeader.NumberOfSections && MmpSecCount < 32; ++i, ++s) {
		MMP_SECTION* d = &MmpSec[MmpSecCount++];
		d->Rva = s->VirtualAddress;
		d->Size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
		d->Exec = (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;
	}

	IMAGE_DATA_DIRECTORY* ex = &h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (ex->VirtualAddress && ex->Size) {
		MMP_FNTABLE* t = &MmpTab[MmpTabCount++];
		t->Rva = ex->VirtualAddress;
		t->Size = ex->Size;
		t->X64Fmt = (h->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? TRUE : FALSE;
		t->Stride = t->X64Fmt ? 12 : 8;
	}
	MmpReadCodeMap(h);

	if (!MmpBuildFunctionList()) return FALSE;

	//
	// Which instruction set this process actually reaches ntdll's code through.
	// It has to be read off an ntdll export we ourselves resolve, not off a
	// function in this DLL: on ARM64X the same ntdll file serves both an ARM64 and
	// an ARM64EC view, and only the address GetProcAddress hands *us* says which
	// one we are in.
	//
	// For an x64 process on ARM64X that address is a fast-forward thunk into the
	// EC body, so follow it before asking the code map.
	//
	PVOID probe = GetProcAddress(Ntdll, "LdrLoadDll");
	if (probe) {
		const UCHAR* b = (const UCHAR*)probe;
		static const UCHAR thunk[] = { 0x48,0x8B,0xC4,0x48,0x89,0x58,0x20,0x55,0x5D,0xE9 };
		BOOLEAN isThunk = TRUE;
		for (SIZE_T i = 0; i < sizeof(thunk); ++i) if (b[i] != thunk[i]) { isThunk = FALSE; break; }
		if (isThunk) {
			LONG rel = *(const LONG*)(b + 10);
			b = b + 14 + rel;
		}
		if (b > MmpNt && (SIZE_T)(b - MmpNt) < MmpNtSize)
			MmpOurFlavour = MmpFlavourOf((ULONG)(b - MmpNt));
	}
	return TRUE;
}

// ================================================================== table lookup

static BOOLEAN MmpIsFunctionStart(_In_ ULONG Rva) {
	SIZE_T lo = 0, hi = MmpFnCount;
	while (lo < hi) {
		SIZE_T mid = lo + (hi - lo) / 2;
		if (MmpFnStart[mid] == Rva) return TRUE;
		if (MmpFnStart[mid] < Rva) lo = mid + 1; else hi = mid;
	}
	return FALSE;
}

static ULONG MmpTableEnclosing(_In_ ULONG Rva) {
	if (!MmpFnCount || Rva < MmpFnStart[0]) return 0;
	SIZE_T lo = 0, hi = MmpFnCount;
	while (lo < hi) {
		SIZE_T mid = lo + (hi - lo) / 2;
		if (MmpFnStart[mid] <= Rva) lo = mid + 1; else hi = mid;
	}
	ULONG start = MmpFnStart[lo - 1];
	ULONG next = (lo < MmpFnCount) ? MmpFnStart[lo] : (ULONG)MmpNtSize;
	if (Rva >= next) return 0;
	if (next - start > 0x20000) return 0;                       // implausible: a gap
	return start;
}

//
// How far a function extends, for the bounded scans below.
//
static ULONG MmpFunctionExtent(_In_ ULONG Rva, _In_ ULONG Cap) {
	SIZE_T lo = 0, hi = MmpFnCount;
	while (lo < hi) {                                           // first start above Rva
		SIZE_T mid = lo + (hi - lo) / 2;
		if (MmpFnStart[mid] <= Rva) lo = mid + 1; else hi = mid;
	}
	if (lo >= MmpFnCount) return Cap;
	ULONG span = MmpFnStart[lo] - Rva;
	return (span && span < Cap) ? span : Cap;
}

//
// Which function owns an address. RtlLookupFunctionEntry is the authority: it is
// exported, documented, and on ARM64X it already knows which of the two tables
// applies to the view we run in. The merged table is only the fallback for
// addresses this view will not resolve.
//
static ULONG MmpFunctionStartOf(_In_ ULONG Rva) {
	if (Rva >= MmpNtSize) return 0;
	const ULONG* rf = nullptr;
	DWORD64 base = 0;
	__try {
		rf = (const ULONG*)RtlLookupFunctionEntry((DWORD64)(MmpNt + Rva), &base, nullptr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { rf = nullptr; }
	if (rf) {
		ULONG begin = rf[0];
		if (begin && begin <= Rva && begin < MmpNtSize) return begin;
	}
	return MmpTableEnclosing(Rva);
}

static BOOLEAN MmpLookupRecord(_In_ ULONG FnRva, _Out_ const UCHAR** Rec, _Out_ BOOLEAN* X64Fmt) {
	for (ULONG i = 0; i < MmpTabCount; ++i) {
		SIZE_T n = MmpTab[i].Size / MmpTab[i].Stride;
		const UCHAR* e = MmpNt + MmpTab[i].Rva;
		SIZE_T lo = 0, hi = n;
		while (lo < hi) {
			SIZE_T mid = lo + (hi - lo) / 2;
			ULONG b = *(const ULONG*)(e + mid * MmpTab[i].Stride);
			if (b == FnRva) {
				*Rec = e + mid * MmpTab[i].Stride;
				*X64Fmt = MmpTab[i].X64Fmt;
				return TRUE;
			}
			if (b < FnRva) lo = mid + 1; else hi = mid;
		}
	}
	return FALSE;
}

static BOOLEAN MmpInFunctionTable(_In_ ULONG Rva) {
	for (ULONG i = 0; i < MmpTabCount; ++i)
		if (Rva >= MmpTab[i].Rva && Rva < MmpTab[i].Rva + MmpTab[i].Size) return TRUE;
	return FALSE;
}

//
// A PGO build splits a function into fragments, each with its own
// runtime-function record chained to the primary's. The fragment is not the
// function, and resolving the chain is how the ABI says so. Server 2022's ntdll
// is split this way, and without this LdrpHandleTlsData gains a spurious second
// address at a cold fragment.
//
static ULONG MmpChainPrimary(_In_ ULONG FnRva) {
	const UCHAR* rec; BOOLEAN x64fmt;
	if (!MmpLookupRecord(FnRva, &rec, &x64fmt) || !x64fmt) return FnRva;

	ULONG begin = FnRva;
	for (int i = 0; i < 4; ++i) {
		begin = *(const ULONG*)rec;
		ULONG unwind = *(const ULONG*)(rec + 8);
		if (!unwind || unwind + 4 > MmpNtSize) return begin;
		const UCHAR* u = MmpNt + unwind;
		UCHAR ver = u[0] & 7, flags = u[0] >> 3, codes = u[2];
		if (ver != 1 && ver != 2) return begin;
		if (!(flags & 0x4)) return begin;                       // not chained: this is it
		const UCHAR* next = u + 4 + (SIZE_T)((codes + 1) & ~1) * 2;
		if (next + 12 > MmpNt + MmpNtSize) return begin;
		rec = next;
	}
	return begin;
}

// ================================================================ scope records

struct MMP_SCOPE { ULONG Begin, End, Handler, Target; };

//
// MSVC's SEH handler data is a count followed by { Begin, End, Handler, Target }
// records, the same shape on x64 and ARM64. C++ EH puts something else there, so
// every record is validated as a whole before it is believed.
//
static BOOLEAN MmpParseHandlerData(
	_In_ const ULONG* Hd, _In_ ULONG FnRva, _In_ ULONG FnEnd,
	MMP_SCOPE* Out, _In_ int Max, _Out_ int* Count) {

	*Count = 0;
	if ((const UCHAR*)Hd < MmpNt || (const UCHAR*)Hd + 8 > MmpNt + MmpNtSize) return FALSE;
	ULONG n = Hd[0];
	if (!n || n > 256) return FALSE;
	if ((const UCHAR*)(Hd + 1 + n * 4) > MmpNt + MmpNtSize) return FALSE;

	for (ULONG i = 0; i < n; ++i) {
		MMP_SCOPE s;
		s.Begin = Hd[1 + i * 4]; s.End = Hd[2 + i * 4];
		s.Handler = Hd[3 + i * 4]; s.Target = Hd[4 + i * 4];
		if (s.Begin >= s.End) return FALSE;
		if (s.Begin < FnRva || (FnEnd && s.End > FnEnd)) return FALSE;
		if (s.Begin >= MmpNtSize || s.End > MmpNtSize) return FALSE;
		// Target is an address in the parent; Handler is a funclet, the literal 1
		// (a constant __except filter) or 0.
		if (s.Target && (s.Target < FnRva || (FnEnd && s.Target > FnEnd))) return FALSE;
		if (s.Handler > 1 && !MmpInExec(s.Handler)) return FALSE;
		if (*Count < Max) Out[(*Count)++] = s;
	}
	return TRUE;
}

//
// The scope table of one function, from its runtime-function record. Follows x64
// chained unwind info so a separated fragment reports its parent.
//
static BOOLEAN MmpScopesOfFunction(
	_In_ ULONG FnRva, MMP_SCOPE* Out, _In_ int Max,
	_Out_ int* Count, _Out_opt_ ULONG* HandlerOut, _Out_opt_ ULONG* PrimaryOut) {

	*Count = 0;
	if (HandlerOut) *HandlerOut = 0;
	if (PrimaryOut) *PrimaryOut = FnRva;

	const UCHAR* rec; BOOLEAN x64fmt;
	if (!MmpLookupRecord(FnRva, &rec, &x64fmt)) return FALSE;

	for (int chain = 0; chain < 4; ++chain) {
		if (x64fmt) {
			ULONG begin = *(const ULONG*)rec;
			ULONG end = *(const ULONG*)(rec + 4);
			ULONG unwind = *(const ULONG*)(rec + 8);
			if (!unwind || unwind + 4 > MmpNtSize) return FALSE;
			const UCHAR* u = MmpNt + unwind;
			UCHAR ver = u[0] & 7, flags = u[0] >> 3, codes = u[2];
			if (ver != 1 && ver != 2) return FALSE;
			SIZE_T after = 4 + (SIZE_T)((codes + 1) & ~1) * 2;
			if (flags & 0x4) {                                  // UNW_FLAG_CHAININFO
				rec = u + after;
				if (rec + 12 > MmpNt + MmpNtSize) return FALSE;
				continue;
			}
			if (!(flags & 0x3)) return FALSE;                   // no handler at all
			if (u + after + 4 > MmpNt + MmpNtSize) return FALSE;
			if (HandlerOut) *HandlerOut = *(const ULONG*)(u + after);
			// After chain following, begin is the primary's start.
			if (PrimaryOut) *PrimaryOut = begin;
			return MmpParseHandlerData((const ULONG*)(u + after + 4), begin, end, Out, Max, Count);
		}
		else {
			ULONG begin = *(const ULONG*)rec;
			ULONG second = *(const ULONG*)(rec + 4);
			if (second & 3) return FALSE;                       // packed: no handler
			if (!second || second + 8 > MmpNtSize) return FALSE;
			const ULONG* x = (const ULONG*)(MmpNt + second);
			ULONG hdr = x[0];
			ULONG flen = hdr & 0x3FFFF;
			ULONG X = (hdr >> 20) & 1, E = (hdr >> 21) & 1;
			ULONG epilogs = (hdr >> 22) & 0x1F, codeWords = (hdr >> 27) & 0x1F;
			SIZE_T w = 1;
			if (!epilogs && !codeWords) {                       // extended header
				epilogs = x[1] & 0xFFFF;
				codeWords = (x[1] >> 16) & 0xFF;
				w = 2;
			}
			if (!X) return FALSE;                               // no handler
			SIZE_T after = w + (E ? 0 : epilogs) + codeWords;
			if ((const UCHAR*)(x + after + 2) > MmpNt + MmpNtSize) return FALSE;
			if (HandlerOut) *HandlerOut = x[after];
			return MmpParseHandlerData(x + after + 1, begin, begin + flen * 4, Out, Max, Count);
		}
	}
	return FALSE;
}

// ======================================================================= scans

//
// Every reference to an address from executable code, accepting any destination
// register. The old scan hardcoded `lea rdx` -- one register, one instruction
// set -- which is most of why it found nothing outside genuine x64.
//
static ULONG MmpScanCodeRefs(_In_ ULONG TargetRva, ULONG* Out, _In_ ULONG Max) {
	ULONG n = 0;
	ULONGLONG targetVa = (ULONGLONG)(MmpNt + TargetRva);

	for (ULONG si = 0; si < MmpSecCount && n < Max; ++si) {
		if (!MmpSec[si].Exec) continue;
		const UCHAR* p = MmpNt + MmpSec[si].Rva;
		SIZE_T len = MmpSec[si].Size;

		// lea r64,[rip+disp32] -- REX.W, 8D, ModRM mod=00 rm=101, any reg field
		for (SIZE_T i = 0; i + 7 <= len && n < Max; ++i) {
			if ((p[i] & 0xF0) != 0x40) continue;
			if (p[i + 1] != 0x8D) continue;
			if ((p[i + 2] & 0xC7) != 0x05) continue;
			LONG d = *(const LONG*)(p + i + 3);
			if ((ULONGLONG)(p + i + 7 + d) != targetVa) continue;
			Out[n++] = (ULONG)(MmpSec[si].Rva + i);
		}

		// ADRP forms a page base, a later ADD completes it. The register file is
		// cleared at every function start, so a stale ADRP from the previous
		// function cannot manufacture a hit.
		const ULONG* c = (const ULONG*)p;
		SIZE_T words = len / 4;
		ULONGLONG adrp[32] = { 0 };
		BOOLEAN have[32] = { 0 };
		for (SIZE_T i = 0; i < words && n < Max; ++i) {
			ULONG rva = (ULONG)(MmpSec[si].Rva + i * 4);
			if (MmpIsFunctionStart(rva)) RtlZeroMemory(have, sizeof(have));
			ULONG insn = c[i];
			ULONGLONG pc = (ULONGLONG)(c + i);

			if ((insn & 0x9F000000ul) == 0x90000000ul) {         // ADRP Xd,#page
				ULONG rd = insn & 0x1F;
				LONG64 immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7FFFF;
				LONG64 imm = (immhi << 2) | immlo;
				if (imm & (1LL << 20)) imm -= (1LL << 21);
				adrp[rd] = (pc & ~0xFFFULL) + (imm << 12);
				have[rd] = TRUE;
				continue;
			}
			if ((insn & 0xFF800000ul) == 0x91000000ul) {         // ADD Xd,Xn,#imm12
				ULONG rd = insn & 0x1F, rn = (insn >> 5) & 0x1F, imm12 = (insn >> 10) & 0xFFF;
				if (have[rn] && adrp[rn] + imm12 == targetVa) Out[n++] = rva;
				if (rd != rn) have[rd] = FALSE;
				continue;
			}
		}
	}
	return n;
}

//
// Does this function contain a direct call to one specific target? Used to tell
// LdrpReleaseTlsEntry from its siblings by the exported routines it calls.
//
static BOOLEAN MmpCallsTarget(_In_ ULONG FnRva, _In_ ULONGLONG TargetVa) {
	ULONG extent = MmpFunctionExtent(FnRva, 0x800);
	const UCHAR* p = MmpNt + FnRva;

	for (ULONG i = 0; i + 5 <= extent; ++i) {                   // call rel32
		if (p[i] != 0xE8) continue;
		LONG rel = *(const LONG*)(p + i + 1);
		if ((ULONGLONG)(p + i + 5 + rel) == TargetVa) return TRUE;
	}

	const ULONG* c = (const ULONG*)p;
	for (ULONG i = 0; (i + 1) * 4 <= extent; ++i) {             // BL imm26
		ULONG insn = c[i];
		if ((insn & 0xFC000000ul) != 0x94000000ul) continue;
		LONG64 off = insn & 0x03FFFFFF;
		if (off & (1LL << 25)) off -= (1LL << 26);
		if ((ULONGLONG)((ULONGLONG)(c + i) + (off << 2)) == TargetVa) return TRUE;
	}
	return FALSE;
}

//
// Direct call targets that are themselves function starts. Gated on the function
// table so a stray 0xE8 operand byte cannot invent a callee.
//
static ULONG MmpDirectCallees(_In_ ULONG FnRva, ULONG* Out, _In_ ULONG Max) {
	ULONG n = 0;
	ULONG extent = MmpFunctionExtent(FnRva, 0x800);
	const UCHAR* p = MmpNt + FnRva;

	for (ULONG i = 0; i + 5 <= extent && n < Max; ++i) {
		if (p[i] != 0xE8) continue;
		LONG rel = *(const LONG*)(p + i + 1);
		ULONGLONG va = (ULONGLONG)(p + i + 5 + rel);
		if (va <= (ULONGLONG)MmpNt || va >= (ULONGLONG)MmpNt + MmpNtSize) continue;
		ULONG t = (ULONG)(va - (ULONGLONG)MmpNt);
		if (!MmpIsFunctionStart(t)) continue;
		BOOLEAN dup = FALSE;
		for (ULONG k = 0; k < n; ++k) if (Out[k] == t) dup = TRUE;
		if (!dup) Out[n++] = t;
	}

	const ULONG* c = (const ULONG*)p;
	for (ULONG i = 0; (i + 1) * 4 <= extent && n < Max; ++i) {
		ULONG insn = c[i];
		if ((insn & 0xFC000000ul) != 0x94000000ul) continue;
		LONG64 off = insn & 0x03FFFFFF;
		if (off & (1LL << 25)) off -= (1LL << 26);
		ULONGLONG va = (ULONGLONG)(c + i) + (off << 2);
		if (va <= (ULONGLONG)MmpNt || va >= (ULONGLONG)MmpNt + MmpNtSize) continue;
		ULONG t = (ULONG)(va - (ULONGLONG)MmpNt);
		if (!MmpIsFunctionStart(t)) continue;
		BOOLEAN dup = FALSE;
		for (ULONG k = 0; k < n; ++k) if (Out[k] == t) dup = TRUE;
		if (!dup) Out[n++] = t;
	}
	return n;
}

// ====================================================== anchors for the handler

//
// Anchor 1. A scope record naming the funclet has to exist in read-only data,
// because that is where MSVC puts an SEH function's handler data. Find it by its
// Handler field and read Begin out of the same record; Begin is an address inside
// the parent, which RtlLookupFunctionEntry turns into the parent's start.
//
static ULONG MmpParentsFromScopeRecords(_In_ ULONG Funclet, ULONG* Out, _In_ ULONG Max) {
	ULONG n = 0;
	for (ULONG si = 0; si < MmpSecCount && n < Max; ++si) {
		if (MmpSec[si].Exec) continue;
		const UCHAR* p = MmpNt + MmpSec[si].Rva;
		for (SIZE_T k = 8; k + 4 <= MmpSec[si].Size && n < Max; k += 4) {
			if (*(const ULONG*)(p + k) != Funclet) continue;

			ULONG at = (ULONG)(MmpSec[si].Rva + k - 8);
			//
			// A runtime-function table is full of code RVAs in triples, so a hit
			// inside one is a coincidence rather than a scope record.
			//
			if (MmpInFunctionTable(at) || MmpInFunctionTable(at + 12)) continue;

			const ULONG* r = (const ULONG*)(p + k - 8);
			MMP_SCOPE s = { r[0], r[1], r[2], r[3] };
			if (s.Handler != Funclet) continue;
			if (s.Begin >= s.End || s.End - s.Begin > 0x10000) continue;
			if (!MmpInExec(s.Begin) || !MmpInExec(s.End - 1)) continue;
			ULONG owner = MmpFunctionStartOf(s.Begin);
			if (!owner || owner == Funclet) continue;
			if (MmpFunctionStartOf(s.End - 1) != owner) continue;
			ULONG parent = MmpChainPrimary(owner);
			if (!parent || parent == Funclet || !MmpIsFunctionStart(parent)) continue;
			if (s.Target && (s.Target < parent || s.Target > s.End)) continue;

			BOOLEAN dup = FALSE;
			for (ULONG i = 0; i < n; ++i) if (Out[i] == parent) dup = TRUE;
			if (!dup) Out[n++] = parent;
		}
	}
	return n;
}

//
// Anchor 2. The same association read out of the unwind tables instead: walk
// every function the image declares and ask its own unwind data which funclets it
// owns. Reaches the same answer without depending on a value scan through
// read-only data, which is why requiring both to agree removes the false
// positives each produces alone.
//
static ULONG MmpParentsFromUnwind(_In_ ULONG Funclet, ULONG* Out, _In_ ULONG Max) {
	ULONG n = 0;
	MMP_SCOPE scopes[64];
	for (SIZE_T i = 0; i < MmpFnCount && n < Max; ++i) {
		ULONG fn = MmpFnStart[i];
		if (fn == Funclet) continue;
		int count = 0;
		ULONG handler = 0, primary = fn;
		if (!MmpScopesOfFunction(fn, scopes, 64, &count, &handler, &primary)) continue;
		// The language-specific handler must be a real function; that is what
		// separates a genuine scope table from a C++ EH blob read as one.
		if (!MmpIsFunctionStart(handler)) continue;
		for (int k = 0; k < count; ++k) {
			if (scopes[k].Handler != Funclet) continue;
			BOOLEAN dup = FALSE;
			for (ULONG j = 0; j < n; ++j) if (Out[j] == primary) dup = TRUE;
			if (!dup) Out[n++] = primary;
			break;
		}
	}
	return n;
}

// ================================================================ ARM64EC gate

//
// The dword before an ARM64EC function is (entryThunkRva - fnRva) | 1 when it has
// an entry thunk. Exported functions have one; ntdll's internal loader helpers do
// not. An emulated x64 caller needs that thunk to reach ARM64 code, and calling
// without it does not fault -- the emulator ends the process with
// STATUS_WX86_INTERNAL_ERROR, with no first-chance exception dispatched. So this
// has to be checked and refused, never attempted and caught.
//
static BOOLEAN MmpCallableFromHere(_In_ ULONG Rva) {
	MMP_FLAVOUR fl = MmpFlavourOf(Rva);
	if (fl == MMP_FL_ANY) return TRUE;                          // single-architecture image

#if defined(_M_X64)
	if (fl == MMP_FL_ARM64) return FALSE;                       // cannot reach ARM64 code
	if (fl == MMP_FL_ARM64EC) {
		if (Rva < 4) return FALSE;
		ULONG tag = *(const ULONG*)(MmpNt + Rva - 4);
		return (tag & 3) == 1;
	}
	return TRUE;
#else
	// A native ARM64 caller must use the ARM64 copy, not the EC one.
	return fl != MMP_FL_ARM64EC;
#endif
}

// ==================================================================== locators

//
// The literal ntdll logs its own function by. Everything else hangs off this, so
// if a future build stops emitting the logging call both anchors die together and
// the result is "not located" -- which is the correct failure direction.
//
static ULONG MmpLocateHandleTlsData(_Out_ ULONG* Agreement) {
	*Agreement = 0;

	static const char name[] = "LdrpHandleTlsData";
	ULONG strRva = 0;
	for (SIZE_T off = 0; off + sizeof(name) <= MmpNtSize; ++off) {
		if (RtlCompareMemory(MmpNt + off, name, sizeof(name)) == sizeof(name)) { strRva = (ULONG)off; break; }
	}
	if (!strRva) return 0;

	ULONG sites[32];
	ULONG siteCount = MmpScanCodeRefs(strRva, sites, 32);
	if (!siteCount) return 0;

	for (ULONG i = 0; i < siteCount; ++i) {
		//
		// The reference lives inside an exception filter funclet. Take only the
		// copy compiled for the code we ourselves run: on ARM64X the loader is
		// compiled twice and both copies reference this string.
		//
		if (MmpFlavourOf(sites[i]) != MmpOurFlavour) continue;

		ULONG funclet = MmpFunctionStartOf(sites[i]);
		if (!funclet) continue;

		ULONG a[8], b[8];
		ULONG na = MmpParentsFromScopeRecords(funclet, a, 8);
		ULONG nb = MmpParentsFromUnwind(funclet, b, 8);
		if (na != 1 || nb != 1 || a[0] != b[0]) continue;        // must be unique and agree

		*Agreement = 2;
		return a[0];
	}
	return 0;
}

//
// LdrpReleaseTlsEntry has no name literal anywhere in ntdll, so it is selected
// from LdrpHandleTlsData's direct callees -- it is called on the error path after
// a TLS entry has been allocated. Discriminators: it frees (calls the exported
// RtlFreeHeap) and never allocates (never calls RtlAllocateHeap). The winner has
// to be unique; anything else returns nothing.
//
static ULONG MmpLocateReleaseTlsEntry(_In_ HMODULE Ntdll, _In_ ULONG HandleRva) {
	PVOID freeHeap = GetProcAddress(Ntdll, "RtlFreeHeap");
	PVOID allocHeap = GetProcAddress(Ntdll, "RtlAllocateHeap");
	if (!freeHeap || !allocHeap) return 0;

	//
	// Scan the primary and every fragment chained to it. A PGO build splits a
	// function into hot and cold pieces with separate runtime-function records,
	// and the error path that calls LdrpReleaseTlsEntry is exactly the kind of
	// code that lands in the cold piece. Server 2022's ntdll is split this way, so
	// scanning only the primary's extent finds no candidate at all.
	//
	ULONG callees[96];
	ULONG n = MmpDirectCallees(HandleRva, callees, 96);

	for (SIZE_T i = 0; i < MmpFnCount && n < 96; ++i) {
		ULONG fn = MmpFnStart[i];
		if (fn == HandleRva) continue;
		if (MmpChainPrimary(fn) != HandleRva) continue;

		ULONG extra[32];
		ULONG m = MmpDirectCallees(fn, extra, 32);
		for (ULONG k = 0; k < m && n < 96; ++k) {
			BOOLEAN dup = FALSE;
			for (ULONG j = 0; j < n; ++j) if (callees[j] == extra[k]) dup = TRUE;
			if (!dup) callees[n++] = extra[k];
		}
	}
	if (!n) return 0;

	ULONG winner = 0, count = 0;
	for (ULONG i = 0; i < n; ++i) {
		if (!MmpCallsTarget(callees[i], (ULONGLONG)freeHeap)) continue;
		if (MmpCallsTarget(callees[i], (ULONGLONG)allocHeap)) continue;
		if (MmpFunctionExtent(callees[i], 0x800) > 0x200) continue;   // it is a small function
		winner = callees[i];
		++count;
	}
	return count == 1 ? winner : 0;
}

// ======================================================================== entry

BOOL NTAPI MmpLocateNtdllTls(_Out_ PVOID* HandleTlsData, _Out_ PVOID* ReleaseTlsEntry) {
	*HandleTlsData = nullptr;
	*ReleaseTlsEntry = nullptr;

	HMODULE ntdll = (HMODULE)MmpGlobalDataPtr->MmpBaseAddressIndex->NtdllLdrEntry->DllBase;
	if (!ntdll) return FALSE;

	ULONG handleRva = 0, releaseRva = 0, agreement = 0;

	__try {
		if (!MmpInitImage(ntdll)) return FALSE;

		handleRva = MmpLocateHandleTlsData(&agreement);
		if (!handleRva) return FALSE;

		// Publish as soon as it is known, so a later failure still says how far
		// this got rather than looking like the string was never found.
		MmpTlsHandleRva = (LONG)handleRva;
		MmpTlsAgreement = (LONG)agreement;

		//
		// Gate before going any further. If we cannot call it there is nothing to
		// be gained by locating the rest, and every call would be fatal.
		//
		if (!MmpCallableFromHere(handleRva)) {
			MmpTlsHandleRva = (LONG)handleRva;
			MmpTlsAgreement = (LONG)agreement;
			MmpTlsRefused = 1;
			return FALSE;
		}

		releaseRva = MmpLocateReleaseTlsEntry(ntdll, handleRva);
		if (!releaseRva) return FALSE;
		if (!MmpCallableFromHere(releaseRva)) {
			MmpTlsHandleRva = (LONG)handleRva;
			MmpTlsReleaseRva = (LONG)releaseRva;
			MmpTlsAgreement = (LONG)agreement;
			MmpTlsRefused = 1;
			return FALSE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	*HandleTlsData = (PVOID)(MmpNt + handleRva);
	*ReleaseTlsEntry = (PVOID)(MmpNt + releaseRva);

	MmpTlsHandleRva = (LONG)handleRva;
	MmpTlsReleaseRva = (LONG)releaseRva;
	MmpTlsAgreement = (LONG)agreement;
	MmpTlsLocated = 1;
	return TRUE;
}
