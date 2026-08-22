//
// probe_tls_release -- locate and verify ntdll!LdrpReleaseTlsEntry at runtime,
// without a hardcoded RVA, a PDB, or an opcode signature for the function.
//
// Why we want it: MemoryModulePP hands its fabricated LDR_DATA_TABLE_ENTRY to
// ntdll's LdrpHandleTlsData on load and to LdrpReleaseTlsEntry on unload.
// Neither is exported. MmpLdrpTls.cpp finds the second one with a single
// hardcoded 21-byte prologue signature that is x64-only, Windows-10-only, and
// -- because the last byte of it is a jcc displacement -- sensitive to how
// large the *following* basic block happens to be. If the scan misses,
// MmpTlsInitialize() nulls BOTH TLS pointers, clears the feature bit, and
// returns FALSE into a caller that discards it. See OPEN-ISSUES.md issues 4
// and 6. That signature is the anchor this probe exists to replace.
//
// -------------------------------------------------------------------------
// How this finds it instead
//
// The function is small and stereotyped, and every interesting thing it
// touches is either an exported ntdll routine or a global we can identify from
// live data. Measured shape, identical on native ARM64, on ARM64EC, and on
// genuine x64:
//
//   NTSTATUS LdrpReleaseTlsEntry(PLDR_DATA_TABLE_ENTRY Module, PVOID *Out)
//   {
//       if (!Out) RtlAcquireSRWLockExclusive(&LdrpTlsLock);   // exported
//       e = LdrpFindTlsEntry(Module);                         // walks LdrpTlsList
//       if (e) { unlink e; LdrpTlsBitmap.Buffer[i>>3] &= ~(1<<(i&7)); }
//       if (!Out) RtlReleaseSRWLockExclusive(&LdrpTlsLock);   // exported
//       if (!e)   return STATUS_NOT_FOUND;
//       if (Out)  { *Out = e; return STATUS_SUCCESS; }
//       RtlFreeHeap(LdrpTlsHeap, 0, e);                       // exported
//       return STATUS_SUCCESS;
//   }
//
// So the probe works outwards from one thing it can establish beyond doubt:
//
//   1. LdrpTlsList, found in *live data*, not in code. It is the one circular
//      LIST_ENTRY in ntdll's writable sections whose members are heap blocks
//      that each carry a byte-for-byte copy of a loaded module's
//      IMAGE_TLS_DIRECTORY together with a pointer to that module's
//      LDR_DATA_TABLE_ENTRY from PEB->Ldr. Nothing else in the address space
//      looks like that. The member layout -- where the module back-pointer sits
//      and where the directory copy sits -- is measured off the live entries
//      rather than assumed.
//
//   2. The TLS cluster: every function in ntdll's exception directory whose
//      code materialises &LdrpTlsList, plus its immediate callers and callees.
//
//   3. LdrpTlsLock, LdrpTlsHeap and LdrpTlsBitmap, decoded as the first
//      argument the cluster passes to the *exported* RtlAcquireSRWLock*,
//      RtlFreeHeap / RtlAllocateHeap and RtlSetBits / RtlClearBits. Same
//      ABI-driven trick lockprobe.cpp uses for LdrpModuleDatatableLock: both
//      ends of the pattern are things GetProcAddress resolves, and the only
//      thing decoded is the instruction that materialises the argument.
//
//   4. The function itself, as the unique exception-directory entry satisfying
//      four independent required anchors, ranked by seven more. See
//      SelectCandidates.
//
// Everything is bounded by IMAGE_DIRECTORY_ENTRY_EXCEPTION exactly as
// lockprobe does it: a computed call target is followed only when the
// exception directory, or a conservative shape check, says it is a function
// start, and the same table bounds each scan to the function it began in.
//
// -------------------------------------------------------------------------
// How this is proved rather than argued
//
// Structure alone is an argument. The causality check is a proof:
//
//   - fabricate an LDRP_TLS_ENTRY of our own and a token that stands in for a
//     module's LDR_DATA_TABLE_ENTRY (only its address is ever compared),
//   - splice the fabricated entry into LdrpTlsList, under LdrpTlsLock,
//   - call candidate(token, &out). The second argument is non-null, so the
//     real function takes neither the lock nor the free path -- it can never
//     hand our pointer to RtlFreeHeap,
//   - require that it returns success, hands back *our* entry through out, and
//     has unlinked it from the list.
//
// Only a function that walks LdrpTlsList matching on the module back-pointer,
// unlinks the hit and returns it through the second argument can pass that.
// The splice is exactly reversed by the unlink, and the fabricated entry is
// filled end to end with a TLS index whose bitmap bit is already clear, so the
// one write the function makes outside our own memory rewrites a byte with the
// value it already had -- which the probe then checks.
//
// A negative half runs first, on a token that is in no list at all: it must
// report not-found and leave the out parameter untouched.
//
// Fail closed. If the anchors do not converge on exactly one function, or the
// causality check does not pass, the answer is NOT LOCATED. A wrong address
// here gets called with a fabricated LDR_DATA_TABLE_ENTRY, which is worse than
// not calling anything.
//
// Build (not via build.cmd -- that rebuilds the shared library):
//   cl /nologo /std:c++17 /O2 /MT /EHsc probe_tls_release.cpp
//      /link /OUT:probe_tls_release.exe
//
// Options:
//   --survey        every step's working set: the list, the cluster, the locks
//                   and heaps and bitmaps they vote for, and the scorecard for
//                   every function that satisfied the required anchors
//   --survey-all    additionally, every ntdll function that takes any SRW lock,
//                   grouped by lock -- the starting point on an unfamiliar build
//   --dump          hexdump the winner
//   --no-causality  structure only; call nothing
//
// Exit code: 0 = located and verified,
//            1 = not located, not verified, or located but not callable from
//                this process (see the ARM64EC entry-thunk note below),
//            2 = setup failure.
//
// One measured result deserves to be read before the code: on ARM64X, an x64
// process locates the ARM64EC body correctly and still cannot call it. Internal
// ntdll EC functions carry no x64 entry thunk, and the emulator's failure to
// make that transition terminates the process uncatchably. The probe checks for
// the thunk and refuses. An x64 build of MemoryModulePP on ARM64 Windows must
// therefore not route TLS through ntdll at all, however good its address is.
//

#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>

//
// Our own image must carry a TLS directory, because LdrpTlsList discovery needs
// at least one live entry to match against and a bare console EXE is not
// guaranteed to have one. This is the cheapest way to guarantee the process has
// TLS, and it gives the probe an entry it owns to measure the layout from.
//
static thread_local volatile int g_tlsAnchor = 0x5A5A5A5A;

static bool g_survey = false, g_surveyAll = false, g_dump = false, g_causality = true;

// ============================================================ small utilities

static bool ReadPtrSafe(const void* p, void** out) {
    __try { *out = *(void* const*)p; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool ReadU32Safe(const void* p, uint32_t* out) {
    __try { *out = *(const uint32_t*)p; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool ReadU8Safe(const void* p, uint8_t* out) {
    __try { *out = *(const uint8_t*)p; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool CompareSafe(const void* a, const void* b, size_t n, bool* equal) {
    __try { *equal = memcmp(a, b, n) == 0; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ================================================================ ntdll image

static HMODULE        g_nt;
static const uint8_t* g_ntBase;
static uint32_t       g_ntSize;
static WORD           g_ntMachine;
static DWORD          g_ntStamp;

static uint32_t Rva(const void* p) { return (uint32_t)((const uint8_t*)p - g_ntBase); }
static bool InNtdll(const void* p) {
    ULONG_PTR v = (ULONG_PTR)p, b = (ULONG_PTR)g_ntBase;
    return v >= b && v < b + g_ntSize;
}

static PIMAGE_NT_HEADERS NtHeaders(const void* base) {
    PIMAGE_DOS_HEADER d = (PIMAGE_DOS_HEADER)base;
    if (d->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((const uint8_t*)base + d->e_lfanew);
    return h->Signature == IMAGE_NT_SIGNATURE ? h : nullptr;
}

//
// Which instruction set ntdll's bodies are in *from this process's view*. An
// x64 process on an ARM64X host reads ARM64EC bodies behind x64 fast-forward
// thunks, so "built for x64" does not mean "decode x64". Set in main, before
// anything decodes.
//
static bool g_isEcHost = false;
static bool g_codeIsArm64 = false;

// ================================================ exception directory (.pdata)
//
// Same idea as lockprobe.cpp: IMAGE_DIRECTORY_ENTRY_EXCEPTION lists the start
// RVA of every function with unwind data, so "is this a function start" is a
// lookup rather than a guess, and the next entry bounds how far a scan may run.
//
// Two differences, both forced by ARM64X.
//
// The entry stride is *measured* rather than derived from FileHeader.Machine:
// the x64 view of an ARM64X image reports AMD64 in a header whose exception
// directory may be laid out either way, so each table is parsed at both strides
// and whichever yields a coherent ascending function list wins.
//
// And the directory the header points at is not the whole story. An ARM64X
// ntdll carries two tables inside one .pdata section: the ARM64 one, which
// covers both the native bodies and the ARM64EC bodies, and a small AMD64 one
// covering just the x64 fast-forward thunks. Each view's header points at its
// own. An x64 process therefore starts with 544 entries covering nothing but
// thunks -- measured on 10.0.26200 -- which is why this parses the entire
// section the directory lives in and merges what it finds. Everything else here
// depends on being able to enumerate ntdll's functions, so getting only one of
// the two tables is the difference between a full answer and no answer at all.
//
static uint32_t* g_fnStart = nullptr;
static uint32_t  g_fnCount = 0;
static uint32_t  g_fnLow = 0, g_fnHigh = 0;

struct PdataPiece { uint32_t rva, bytes, stride, count; };
static PdataPiece g_pieces[3];
static int        g_pieceCount = 0;

static uint32_t ScoreStride(const uint8_t* tbl, uint32_t bytes, uint32_t stride) {
    uint32_t n = bytes / stride, good = 0, prev = 0;
    if (n > 400000) n = 400000;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t b; memcpy(&b, tbl + (size_t)i * stride, 4);
        if (b == 0 || b >= g_ntSize || b <= prev) continue;
        prev = b; ++good;
    }
    return good;
}

//
// Collect the ascending function starts a candidate table yields, at whichever
// stride explains it better. A range that is not a table at all scores near
// zero at both and contributes nothing.
//
static uint32_t CollectPiece(uint32_t rva, uint32_t bytes, uint32_t* out, uint32_t cap) {
    if (bytes < 64 || rva >= g_ntSize) return 0;
    if (rva + bytes > g_ntSize) bytes = g_ntSize - rva;
    const uint8_t* tbl = g_ntBase + rva;
    uint32_t s8 = ScoreStride(tbl, bytes, 8), s12 = ScoreStride(tbl, bytes, 12);
    if (s8 < 8 && s12 < 8) return 0;
    uint32_t stride = (s12 >= s8) ? 12u : 8u;
    uint32_t n = bytes / stride, k = 0, prev = 0;
    for (uint32_t i = 0; i < n && k < cap; ++i) {
        uint32_t b; memcpy(&b, tbl + (size_t)i * stride, 4);
        if (!b || b >= g_ntSize || b <= prev) continue;   // strictly ascending
        prev = b; out[k++] = b;
    }
    if (g_pieceCount < 3) {
        g_pieces[g_pieceCount].rva = rva;
        g_pieces[g_pieceCount].bytes = bytes;
        g_pieces[g_pieceCount].stride = stride;
        g_pieces[g_pieceCount].count = k;
        ++g_pieceCount;
    }
    return k;
}

static int CompareU32(const void* a, const void* b) {
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static void InitFunctionTable() {
    PIMAGE_NT_HEADERS h = NtHeaders(g_ntBase);
    if (!h) return;
    IMAGE_DATA_DIRECTORY& d =
        h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!d.VirtualAddress || d.Size < 64) return;

    // The section the directory lives in bounds where a sibling table can hide.
    uint32_t secStart = d.VirtualAddress, secEnd = d.VirtualAddress + d.Size;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(h);
    for (WORD s = 0; s < h->FileHeader.NumberOfSections; ++s) {
        uint32_t a = sec[s].VirtualAddress;
        uint32_t b = a + (sec[s].Misc.VirtualSize ? sec[s].Misc.VirtualSize
                                                  : sec[s].SizeOfRawData);
        if (d.VirtualAddress >= a && d.VirtualAddress < b) { secStart = a; secEnd = b; break; }
    }

    uint32_t cap = (secEnd - secStart) / 8 + 16;
    uint32_t* buf = (uint32_t*)malloc((size_t)cap * 4);
    if (!buf) return;
    uint32_t n = 0;
    n += CollectPiece(d.VirtualAddress, d.Size, buf + n, cap - n);
    if (d.VirtualAddress > secStart)
        n += CollectPiece(secStart, d.VirtualAddress - secStart, buf + n, cap - n);
    if (secEnd > d.VirtualAddress + d.Size)
        n += CollectPiece(d.VirtualAddress + d.Size,
                          secEnd - (d.VirtualAddress + d.Size), buf + n, cap - n);

    qsort(buf, n, 4, CompareU32);
    uint32_t k = 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!k || buf[i] != buf[k - 1]) buf[k++] = buf[i];

    g_fnStart = buf; g_fnCount = k;
    if (k) { g_fnLow = buf[0]; g_fnHigh = buf[k - 1]; }
}

static int FindFunctionIndex(uint32_t rva) {             // exact start, or -1
    uint32_t lo = 0, hi = g_fnCount;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_fnStart[mid] == rva) return (int)mid;
        if (g_fnStart[mid] < rva) lo = mid + 1; else hi = mid;
    }
    return -1;
}

static uint32_t FunctionExtent(int index, uint32_t cap) {
    if (index < 0 || (uint32_t)(index + 1) >= g_fnCount) return cap;
    uint32_t span = g_fnStart[index + 1] - g_fnStart[index];
    return (span && span < cap) ? span : cap;
}

//
// Whether a computed call target is worth believing.
//
// On ARM64 a BL is an instruction, not a byte pattern, so every target is real
// and the answer is simply "is it inside ntdll". On x64 an 0xE8 found by byte
// scanning may be an operand, so the target has to look like a function start.
//
// Note what is deliberately NOT required: an entry in the exception directory.
// LdrpFindTlsEntry is a leaf with no unwind data and no .pdata entry on every
// build measured, and it is the edge the whole "reaches &LdrpTlsList in one
// call" test hangs on. Rejecting targets merely because the table does not name
// them is what made the first version of this probe miss its own answer.
//
static bool IsFollowable(const void* target) {
    if (!InNtdll(target)) return false;
    uint32_t rva = Rva(target);
    if (rva + 16 >= g_ntSize) return false;
    if (g_codeIsArm64) return (rva & 3) == 0;
    if (g_fnCount && FindFunctionIndex(rva) >= 0) return true;
    if ((rva & 0xF) == 0) return true;
    uint8_t prev = 0;
    if (!ReadU8Safe((const uint8_t*)target - 1, &prev)) return false;
    return prev == 0xCC || prev == 0xC3 || prev == 0x90;
}

// ================================================= exported callees we decode
//
// Everything the probe keys on is resolvable with GetProcAddress. On ARM64X an
// x64 caller's export is a fast-forward thunk into the ARM64EC body and EC call
// sites target the body, so both addresses are registered for the same callee.
//
enum CalleeKind {
    CK_ACQ_EXCL = 0, CK_ACQ_SHARED, CK_REL_EXCL, CK_REL_SHARED,
    CK_FREE_HEAP, CK_ALLOC_HEAP, CK_BITS
};

struct Callee { const char* name; CalleeKind kind; const void* addr[2]; int n; };

static Callee g_callees[] = {
    { "RtlAcquireSRWLockExclusive", CK_ACQ_EXCL,   {}, 0 },
    { "RtlAcquireSRWLockShared",    CK_ACQ_SHARED, {}, 0 },
    { "RtlReleaseSRWLockExclusive", CK_REL_EXCL,   {}, 0 },
    { "RtlReleaseSRWLockShared",    CK_REL_SHARED, {}, 0 },
    { "RtlFreeHeap",                CK_FREE_HEAP,  {}, 0 },
    { "RtlAllocateHeap",            CK_ALLOC_HEAP, {}, 0 },
    { "RtlSetBits",                 CK_BITS,       {}, 0 },
    { "RtlClearBits",               CK_BITS,       {}, 0 },
    { "RtlFindClearBitsAndSet",     CK_BITS,       {}, 0 },
    { "RtlAreBitsSet",              CK_BITS,       {}, 0 },
};
static const int kCalleeCount = (int)(sizeof(g_callees) / sizeof(g_callees[0]));

//
// The x64 fast-forward thunk an ARM64X image publishes for an export:
//     48 8b c4        mov  rax, rsp
//     48 89 58 20     mov  [rax+20h], rbx
//     55 5d           push rbp / pop rbp
//     e9 <rel32>      jmp  <ARM64EC entry>
//
static bool IsEcFastForward(const void* p, const void** target) {
    static const uint8_t sig[] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x20,0x55,0x5d,0xe9 };
    const uint8_t* b = (const uint8_t*)p;
    bool eq = false;
    if (!CompareSafe(b, sig, sizeof(sig), &eq) || !eq) return false;
    int32_t rel; memcpy(&rel, b + 10, 4);
    if (target) *target = b + 14 + rel;
    return true;
}

//
// Once we know we are on such a host, taking the first `jmp rel32` inside the
// first 24 bytes as the body covers the thunks that are shaped a little
// differently. Never attempted on a genuine x64 host, where those bytes would
// be the real function.
//
static const void* EcAlias(const void* fn) {
    const void* t = nullptr;
    if (IsEcFastForward(fn, &t)) return t;
    if (!g_isEcHost) return nullptr;
    const uint8_t* b = (const uint8_t*)fn;
    for (int i = 0; i < 24; ++i) {
        uint8_t op = 0;
        if (!ReadU8Safe(b + i, &op) || op != 0xE9) continue;
        int32_t rel; memcpy(&rel, b + i + 1, 4);
        const void* d = b + i + 5 + rel;
        if (InNtdll(d)) return d;
    }
    return nullptr;
}

//
// ARM64EC entry thunk, or 0 if the function has none.
//
// The dword immediately before an ARM64EC function holds
// (entryThunkRVA - functionRVA) with 1 in the low bits. That thunk is what
// marshals an emulated x64 caller's register state into the ARM64 ABI, and the
// compiler emits one only for functions x64 code is expected to reach --
// exports, callbacks. ntdll's internal loader helpers have none: measured 0 for
// #LdrpReleaseTlsEntry, #LdrpHandleTlsData and #LdrpFindTlsEntry on 10.0.26200,
// against 0x9659 for the exported #RtlSetLastWin32Error.
//
// This matters far beyond the probe. Calling such a function from emulated x64
// does not raise an exception that SEH can catch -- it terminates the process
// with 0xC000026F. So on ARM64X an x64 build can locate LdrpReleaseTlsEntry
// perfectly and still must not call it.
//
static uint32_t EcEntryThunk(const void* fn) {
    if (!InNtdll(fn) || Rva(fn) < 4) return 0;
    uint32_t marker = 0;
    if (!ReadU32Safe((const uint8_t*)fn - 4, &marker)) return 0;
    if ((marker & 3) != 1) return 0;
    uint64_t t = (uint64_t)Rva(fn) + (marker & ~3u);
    return t < g_ntSize ? (uint32_t)t : 0;
}

static int ResolveCallees() {
    int missing = 0;
    for (int i = 0; i < kCalleeCount; ++i) {
        void* fn = (void*)GetProcAddress(g_nt, g_callees[i].name);
        if (!fn) { ++missing; continue; }
        g_callees[i].addr[g_callees[i].n++] = fn;
        const void* alias = EcAlias(fn);
        if (alias) g_callees[i].addr[g_callees[i].n++] = alias;
    }
    return missing;
}

static int CalleeAt(const void* target) {       // index into g_callees, or -1
    for (int i = 0; i < kCalleeCount; ++i)
        for (int j = 0; j < g_callees[i].n; ++j)
            if (g_callees[i].addr[j] == target) return i;
    return -1;
}

// =============================================================== loaded modules

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length; BOOLEAN Initialized; PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA;

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY;

struct ModInfo {
    MY_LDR_ENTRY* entry;
    const uint8_t* base;
    const void* tlsDir;             // IMAGE_TLS_DIRECTORY in the module, or null
    const wchar_t* name;
    USHORT nameBytes;
};
static ModInfo g_mods[512];
static int     g_modCount = 0;
static int     g_modsWithTls = 0;

static void EnumerateModules() {
    PPEB peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb) return;
    MY_PEB_LDR_DATA* ldr = (MY_PEB_LDR_DATA*)peb->Ldr;
    if (!ldr) return;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* p = head->Flink; p && p != head; p = p->Flink) {
        if (g_modCount == (int)(sizeof(g_mods) / sizeof(g_mods[0]))) break;
        MY_LDR_ENTRY* e = CONTAINING_RECORD(p, MY_LDR_ENTRY, InLoadOrderLinks);
        if (!e->DllBase) continue;
        ModInfo& m = g_mods[g_modCount];
        m.entry = e;
        m.base = (const uint8_t*)e->DllBase;
        m.name = e->BaseDllName.Buffer;
        m.nameBytes = e->BaseDllName.Length;
        m.tlsDir = nullptr;
        PIMAGE_NT_HEADERS h = NtHeaders(m.base);
        if (h) {
            IMAGE_DATA_DIRECTORY& d =
                h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (d.VirtualAddress && d.Size >= 4 * sizeof(void*)) {
                m.tlsDir = m.base + d.VirtualAddress;
                ++g_modsWithTls;
            }
        }
        ++g_modCount;
    }
}

static const ModInfo* ModuleForLdrEntry(const void* p) {
    for (int i = 0; i < g_modCount; ++i)
        if (g_mods[i].entry == p) return &g_mods[i];
    return nullptr;
}

static void PrintName(const ModInfo* m) {
    if (!m || !m->name) { printf("<unnamed>"); return; }
    printf("%.*ls", (int)(m->nameBytes / sizeof(wchar_t)), m->name);
}

// ================================================================ LdrpTlsList
//
// The one thing here that is not a decode. LdrpTlsList is a LIST_ENTRY in
// ntdll's writable data whose members are heap-allocated LDRP_TLS_ENTRY blocks.
// On the builds measured they are laid out
//
//     +0x00  LIST_ENTRY            Links
//     +0x10  IMAGE_TLS_DIRECTORY   TlsDirectory     (copied from the module)
//     +0x38  PLDR_DATA_TABLE_ENTRY ModuleEntry
//     +0x40  ULONG                 Index
//
// but the probe assumes none of that. It requires only that every member holds,
// somewhere in its first 0x78 bytes, a pointer to an LDR_DATA_TABLE_ENTRY that
// PEB->Ldr also holds, and a byte-identical copy of that same module's first
// four IMAGE_TLS_DIRECTORY fields. Those four are absolute addresses inside the
// module, so a coincidental match is not a thing that happens. Whichever
// offsets satisfy it are recorded and used later.
//
static void*    g_tlsList = nullptr;
static uint32_t g_tlsModOff = 0;         // offset of ModuleEntry inside an entry
static uint32_t g_tlsDirOff = 0;         // offset of the TLS directory copy
static int      g_tlsListLen = 0;
static int      g_tlsListCandidates = 0;

struct TlsListMember { void* entry; const ModInfo* mod; };
static TlsListMember g_tlsMembers[64];
static int           g_tlsMemberCount = 0;

static const ModInfo* ClassifyTlsEntry(const void* blk, uint32_t* modOff, uint32_t* dirOff) {
    for (uint32_t off = 0x10; off <= 0x78; off += sizeof(void*)) {
        void* p = nullptr;
        if (!ReadPtrSafe((const uint8_t*)blk + off, &p)) return nullptr;
        const ModInfo* m = ModuleForLdrEntry(p);
        if (!m || !m->tlsDir) continue;
        for (uint32_t d = 0x08; d <= 0x40; d += sizeof(void*)) {
            bool eq = false;
            if (!CompareSafe((const uint8_t*)blk + d, m->tlsDir, 4 * sizeof(void*), &eq))
                return nullptr;
            if (eq) { *modOff = off; *dirOff = d; return m; }
        }
    }
    return nullptr;
}

static bool TryTlsListHead(void* head, int* lenOut, uint32_t* modOff, uint32_t* dirOff,
                           TlsListMember* members, int maxMembers, int* memberCount) {
    void* f = nullptr; void* b = nullptr;
    if (!ReadPtrSafe(head, &f) || !ReadPtrSafe((uint8_t*)head + sizeof(void*), &b))
        return false;
    if (!f || !b) return false;
    if (((ULONG_PTR)f | (ULONG_PTR)b) & (sizeof(void*) - 1)) return false;
    if (f == head) return false;            // empty; nothing to match against

    int len = 0, mc = 0;
    uint32_t mo = 0, dof = 0;
    void* prev = head;
    void* cur = f;
    while (cur != head) {
        if (++len > 200) return false;
        if (InNtdll(cur)) return false;                     // members are heap blocks
        if ((ULONG_PTR)cur & (sizeof(void*) - 1)) return false;
        void* curBlink = nullptr;
        if (!ReadPtrSafe((uint8_t*)cur + sizeof(void*), &curBlink)) return false;
        if (curBlink != prev) return false;                 // doubly linked, properly
        uint32_t o1 = 0, o2 = 0;
        const ModInfo* m = ClassifyTlsEntry(cur, &o1, &o2);
        if (!m) return false;
        if (len == 1) { mo = o1; dof = o2; }
        else if (o1 != mo || o2 != dof) return false;       // uniform layout
        if (mc < maxMembers) { members[mc].entry = cur; members[mc].mod = m; ++mc; }
        prev = cur;
        if (!ReadPtrSafe(cur, &cur)) return false;
    }
    if (b != prev) return false;                            // head's Blink is the tail

    *lenOut = len; *modOff = mo; *dirOff = dof; *memberCount = mc;
    return true;
}

static void DiscoverTlsList() {
    PIMAGE_NT_HEADERS h = NtHeaders(g_ntBase);
    if (!h) return;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(h);

    TlsListMember tmp[64];
    for (WORD s = 0; s < h->FileHeader.NumberOfSections; ++s) {
        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        uint32_t start = sec[s].VirtualAddress;
        if (start >= g_ntSize) continue;
        uint32_t size = sec[s].Misc.VirtualSize;
        if (!size || start + size > g_ntSize) size = g_ntSize - start;
        for (uint32_t o = 0; o + 2 * sizeof(void*) <= size; o += sizeof(void*)) {
            void* head = (void*)(g_ntBase + start + o);
            int len = 0, mc = 0; uint32_t mo = 0, dof = 0;
            if (!TryTlsListHead(head, &len, &mo, &dof, tmp, 64, &mc)) continue;
            ++g_tlsListCandidates;
            if (!g_tlsList) {
                g_tlsList = head; g_tlsListLen = len;
                g_tlsModOff = mo; g_tlsDirOff = dof;
                g_tlsMemberCount = mc;
                memcpy(g_tlsMembers, tmp, sizeof(tmp[0]) * mc);
            }
        }
    }
}

// ============================================================= region scanning
//
// A "region" is one exception-directory entry. On a PGO/BBT-laid-out ntdll a
// source function may own several of them -- a hot body plus cold fragments
// parked megabytes away -- so a region is a unit of code, not a unit of
// meaning. That is fine here: every anchor this probe requires lives in the hot
// body of the function it is looking for. It is also the first thing that
// breaks if a future build splits that body, and the probe fails closed if it
// does.
//

struct ArgRef {                    // what a call's first argument was set from
    enum Kind { NONE, ADDR, LOAD } kind;
    const void* value;             // ADDR: the address itself. LOAD: [value].
};

struct LockUse { const void* lock; uint8_t modes; };   // bit0 acqE,1 acqS,2 relE,3 relS
struct GlobUse { const void* glob; uint8_t modes; };   // bit0 free, bit1 alloc

struct Region {
    uint32_t rva, extent;
    LockUse  locks[6];      uint8_t nLocks;
    GlobUse  heaps[6];      uint8_t nHeaps;
    const void* bitmaps[4]; uint8_t nBitmaps;
    uint8_t  callsFree, callsAlloc, refsTlsList;
    uint32_t calleeOff, calleeCount;   // slice of g_edges
    uint32_t callerCount;
};

static Region*   g_regions = nullptr;
static uint32_t* g_edges = nullptr;
static uint32_t  g_edgeCount = 0, g_edgeCap = 0, g_edgeSliceStart = 0;

static void AddEdge(uint32_t rva) {
    for (uint32_t i = g_edgeSliceStart; i < g_edgeCount; ++i)
        if (g_edges[i] == rva) return;                  // dedup within this region
    if (g_edgeCount - g_edgeSliceStart >= 64) return;   // enough for any real function
    if (g_edgeCount == g_edgeCap) {
        uint32_t cap = g_edgeCap ? g_edgeCap * 2 : 65536;
        uint32_t* n = (uint32_t*)realloc(g_edges, (size_t)cap * 4);
        if (!n) return;
        g_edges = n; g_edgeCap = cap;
    }
    g_edges[g_edgeCount++] = rva;
}

static void NoteLock(Region& r, const void* lock, int bit) {
    for (int i = 0; i < r.nLocks; ++i)
        if (r.locks[i].lock == lock) { r.locks[i].modes |= (uint8_t)(1u << bit); return; }
    if (r.nLocks < 6) {
        r.locks[r.nLocks].lock = lock;
        r.locks[r.nLocks].modes = (uint8_t)(1u << bit);
        ++r.nLocks;
    }
}
static void NoteHeap(Region& r, const void* g, int bit) {
    for (int i = 0; i < r.nHeaps; ++i)
        if (r.heaps[i].glob == g) { r.heaps[i].modes |= (uint8_t)(1u << bit); return; }
    if (r.nHeaps < 6) {
        r.heaps[r.nHeaps].glob = g;
        r.heaps[r.nHeaps].modes = (uint8_t)(1u << bit);
        ++r.nHeaps;
    }
}
static void NoteBitmap(Region& r, const void* g) {
    for (int i = 0; i < r.nBitmaps; ++i) if (r.bitmaps[i] == g) return;
    if (r.nBitmaps < 4) r.bitmaps[r.nBitmaps++] = g;
}

static void RecordCall(Region& r, int calleeIdx, const ArgRef& a) {
    switch (g_callees[calleeIdx].kind) {
    case CK_ACQ_EXCL:   if (a.kind == ArgRef::ADDR) NoteLock(r, a.value, 0); break;
    case CK_ACQ_SHARED: if (a.kind == ArgRef::ADDR) NoteLock(r, a.value, 1); break;
    case CK_REL_EXCL:   if (a.kind == ArgRef::ADDR) NoteLock(r, a.value, 2); break;
    case CK_REL_SHARED: if (a.kind == ArgRef::ADDR) NoteLock(r, a.value, 3); break;
    case CK_FREE_HEAP:  r.callsFree = 1;
                        if (a.kind == ArgRef::LOAD) NoteHeap(r, a.value, 0); break;
    case CK_ALLOC_HEAP: r.callsAlloc = 1;
                        if (a.kind == ArgRef::LOAD) NoteHeap(r, a.value, 1); break;
    case CK_BITS:       if (a.kind == ArgRef::ADDR) NoteBitmap(r, a.value); break;
    }
}

// -------------------------------------------------------------- ARM64 decoding

struct A64State { uint64_t val[32]; bool known[32]; };

static void A64Clear(A64State& s, uint32_t rd) { if (rd < 31) s.known[rd] = false; }

//
// One linear pass over a region's instructions, tracking which registers hold a
// known address (adrp, adrp+add, mov, literal pool). That is enough to resolve
// both "the argument is &G" and "the argument is the value at [G]", which is
// the difference between an SRW lock and a heap handle.
//
// refTarget, when non-null, additionally reports whether any instruction in the
// region computes or dereferences that exact address.
//
static void ScanArm64(const void* fn, uint32_t bytes, Region* r,
                      const void* refTarget, bool* refHit) {
    const uint32_t* code = (const uint32_t*)fn;
    uint32_t n = bytes / 4;
    if (n > 8192) n = 8192;

    A64State s{};
    ArgRef arg0{ ArgRef::NONE, nullptr };

    for (uint32_t i = 0; i < n; ++i) {
        uint32_t insn;
        if (!ReadU32Safe(code + i, &insn)) return;
        uint64_t pc = (uint64_t)(code + i);
        uint32_t rd = insn & 0x1F, rn = (insn >> 5) & 0x1F;

        if ((insn & 0x9F000000u) == 0x90000000u) {                 // ADRP Xd, page
            int64_t immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & (1LL << 20)) imm -= (1LL << 21);
            if (rd < 31) { s.val[rd] = (pc & ~0xFFFULL) + ((uint64_t)imm << 12); s.known[rd] = true; }
            continue;
        }
        if ((insn & 0xFF800000u) == 0x91000000u) {                 // ADD Xd, Xn, #imm12
            uint32_t imm12 = (insn >> 10) & 0xFFF;
            if (rn < 31 && s.known[rn]) {
                uint64_t v = s.val[rn] + imm12;
                if (rd < 31) { s.val[rd] = v; s.known[rd] = true; }
                if (refHit && refTarget == (const void*)v) *refHit = true;
                if (rd == 0) { arg0.kind = ArgRef::ADDR; arg0.value = (const void*)v; }
            }
            else A64Clear(s, rd);
            continue;
        }
        if ((insn & 0xFF000000u) == 0x58000000u) {                 // LDR Xt, <literal>
            int64_t imm19 = (insn >> 5) & 0x7FFFF;
            if (imm19 & (1LL << 18)) imm19 -= (1LL << 19);
            const void* lit = (const void*)(pc + ((uint64_t)imm19 << 2));
            void* v = nullptr;
            if (InNtdll(lit) && ReadPtrSafe(lit, &v) && InNtdll(v)) {
                if (rd < 31) { s.val[rd] = (uint64_t)v; s.known[rd] = true; }
                if (refHit && refTarget == v) *refHit = true;
            }
            else A64Clear(s, rd);
            continue;
        }
        // LDR/STR (immediate, unsigned offset), scalar: size(2) 111 V=0 01 opc(2)
        if ((insn & 0x3F000000u) == 0x39000000u) {
            uint32_t size = insn >> 30;                   // 0=b 1=h 2=w 3=x
            uint32_t opc = (insn >> 22) & 3;              // 0=str, else load
            uint32_t imm12 = (insn >> 10) & 0xFFF;
            if (rn < 31 && s.known[rn]) {
                uint64_t addr = s.val[rn] + ((uint64_t)imm12 << size);
                if (refHit && refTarget == (const void*)addr) *refHit = true;
                if (opc != 0 && rd == 0 && size == 3) {   // ldr x0, [Xn, #imm]
                    arg0.kind = ArgRef::LOAD; arg0.value = (const void*)addr;
                }
            }
            //
            // A load clobbers Rt -- except from SP or FP, which is an epilogue
            // restoring a callee-saved register. This scan is linear, not a
            // walk of the control flow graph, and a PGO-scheduled function
            // routinely places a block *after* its own epilogue: in
            // LdrpReleaseTlsEntry the `add x0,x21,#LdrpTlsLock` feeding the
            // release sits below the `ldr x21,[sp,#0x10]` that restores x21.
            // Honouring that restore loses the release anchor entirely.
            //
            if (opc != 0 && rn != 31 && rn != 29) A64Clear(s, rd);
            continue;
        }
        if ((insn & 0xFFE0FFE0u) == 0xAA0003E0u) {                 // MOV Xd, Xm
            uint32_t rm = (insn >> 16) & 0x1F;
            if (rm < 31 && s.known[rm]) {
                if (rd < 31) { s.val[rd] = s.val[rm]; s.known[rd] = true; }
                if (rd == 0) { arg0.kind = ArgRef::ADDR; arg0.value = (const void*)s.val[rm]; }
            }
            else { A64Clear(s, rd); if (rd == 0) arg0.kind = ArgRef::NONE; }
            continue;
        }
        if ((insn & 0xFC000000u) == 0x94000000u) {                 // BL imm26
            int64_t off = insn & 0x03FFFFFF;
            if (off & (1LL << 25)) off -= (1LL << 26);
            const void* target = (const void*)(pc + ((uint64_t)off << 2));
            int ci = CalleeAt(target);
            if (ci >= 0) { if (r) RecordCall(*r, ci, arg0); }
            else if (r && IsFollowable(target)) AddEdge(Rva(target));
            arg0.kind = ArgRef::NONE;
            for (uint32_t k = 0; k <= 18; ++k) s.known[k] = false;  // call-clobbered
            continue;
        }
        if ((insn & 0x1F000000u) == 0x0B000000u ||                 // add/sub (reg)
            (insn & 0x1F800000u) == 0x12800000u ||                 // movn/movz/movk
            (insn & 0x1F800000u) == 0x52800000u ||
            (insn & 0x1F800000u) == 0x72800000u)
            A64Clear(s, rd);
    }
}

// ---------------------------------------------------------------- x64 decoding

//
// Byte scan rather than a length disassembler, the same trade lockprobe makes:
// an 0xE8 found this way may be an operand byte, so a computed target is
// believed only when IsFollowable says so.
//
static ArgRef X64Arg0Before(const uint8_t* p, uint32_t i) {
    ArgRef a{ ArgRef::NONE, nullptr };
    for (uint32_t back = 3; back <= 96 && back <= i; ++back) {
        const uint8_t* q = p + i - back;
        if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) {            // lea rcx,[rip+d]
            int32_t d; memcpy(&d, q + 3, 4);
            a.kind = ArgRef::ADDR; a.value = q + 7 + d; return a;
        }
        if (q[0] == 0x48 && q[1] == 0x8B && q[2] == 0x0D) {            // mov rcx,[rip+d]
            int32_t d; memcpy(&d, q + 3, 4);
            a.kind = ArgRef::LOAD; a.value = q + 7 + d; return a;
        }
        if (q[0] == 0x48 && q[1] == 0xB9) {                            // mov rcx, imm64
            uint64_t v; memcpy(&v, q + 2, 8);
            a.kind = ArgRef::ADDR; a.value = (const void*)v; return a;
        }
    }
    return a;
}

//
// Does a RIP-relative operand anywhere in this region resolve to `target`? The
// forms accepted are the two-byte opcodes that reach memory with mod=00,rm=101
// -- lea/mov/add/sub/cmp/test/or/and/xor -- which covers both "load the
// address" and "read the field", including the `add rdx,[LdrpTlsBitmap+8]` the
// inlined single-bit clear compiles to.
//
static bool X64RefersTo(const uint8_t* p, uint32_t bytes, const void* target) {
    static const uint8_t ops[] = { 0x8D,0x8B,0x89,0x03,0x2B,0x3B,0x39,0x33,0x0B,0x23,0x85,0x01,0x29 };
    for (uint32_t i = 0; i + 7 <= bytes; ++i) {
        uint8_t rex = p[i];
        uint32_t o = (rex == 0x48 || rex == 0x49 || rex == 0x4C || rex == 0x4D) ? 1u : 0u;
        uint8_t op = p[i + o], modrm = p[i + o + 1];
        if ((modrm & 0xC7) != 0x05) continue;
        bool ok = false;
        for (size_t k = 0; k < sizeof(ops); ++k) if (ops[k] == op) { ok = true; break; }
        if (!ok) continue;
        int32_t d; memcpy(&d, p + i + o + 2, 4);
        if ((const void*)(p + i + o + 6 + d) == target) return true;
    }
    return false;
}

static void ScanX64(const void* fn, uint32_t bytes, Region* r,
                    const void* refTarget, bool* refHit) {
    const uint8_t* p = (const uint8_t*)fn;
    if (refTarget && refHit && X64RefersTo(p, bytes, refTarget)) *refHit = true;
    if (!r) return;
    for (uint32_t i = 0; i + 5 <= bytes; ++i) {
        if (p[i] != 0xE8) continue;                                // call rel32
        int32_t rel; memcpy(&rel, p + i + 1, 4);
        const void* target = p + i + 5 + rel;
        int ci = CalleeAt(target);
        if (ci >= 0) { RecordCall(*r, ci, X64Arg0Before(p, i)); continue; }
        if (IsFollowable(target)) AddEdge(Rva(target));
    }
}

static void ScanRegion(const void* fn, uint32_t bytes, Region* r,
                       const void* refTarget, bool* refHit) {
    __try {
        if (g_codeIsArm64) ScanArm64(fn, bytes, r, refTarget, refHit);
        else               ScanX64(fn, bytes, r, refTarget, refHit);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { /* a wandering scan is a normal outcome */ }
}

static bool CodeRefers(const void* fn, uint32_t bytes, const void* target) {
    bool hit = false;
    ScanRegion(fn, bytes, nullptr, target, &hit);
    return hit;
}

static void ScanAllRegions() {
    g_regions = (Region*)calloc(g_fnCount, sizeof(Region));
    if (!g_regions) return;
    for (uint32_t i = 0; i < g_fnCount; ++i) {
        Region& r = g_regions[i];
        r.rva = g_fnStart[i];
        r.extent = FunctionExtent((int)i, 0x2000);
        r.calleeOff = g_edgeCount;
        g_edgeSliceStart = g_edgeCount;
        bool hit = false;
        ScanRegion(g_ntBase + r.rva, r.extent, &r, g_tlsList, g_tlsList ? &hit : nullptr);
        r.refsTlsList = hit ? 1 : 0;
        r.calleeCount = g_edgeCount - r.calleeOff;
    }
    for (uint32_t i = 0; i < g_fnCount; ++i)          // reverse edges
        for (uint32_t k = 0; k < g_regions[i].calleeCount; ++k) {
            int j = FindFunctionIndex(g_edges[g_regions[i].calleeOff + k]);
            if (j >= 0) ++g_regions[j].callerCount;
        }
}

static bool Calls(uint32_t from, uint32_t toRva) {
    const Region& r = g_regions[from];
    for (uint32_t k = 0; k < r.calleeCount; ++k)
        if (g_edges[r.calleeOff + k] == toRva) return true;
    return false;
}

//
// Does this region reach &LdrpTlsList directly, or through exactly one call?
// The second case is LdrpFindTlsEntry, which on ARM64X is a shared helper that
// lives outside whichever .pdata this process sees -- so a callee with no
// exception-directory entry is scanned directly, with a capped extent.
//
static bool ReachesList(uint32_t i) {
    if (g_regions[i].refsTlsList) return true;
    const Region& r = g_regions[i];
    for (uint32_t k = 0; k < r.calleeCount; ++k) {
        uint32_t rva = g_edges[r.calleeOff + k];
        int j = FindFunctionIndex(rva);
        if (j >= 0) { if (g_regions[j].refsTlsList) return true; continue; }
        if (CodeRefers(g_ntBase + rva, 0x200, g_tlsList)) return true;
    }
    return false;
}

// ==================================================== cluster and TLS globals

static uint8_t* g_inCluster = nullptr;      // 1 = references the list, 2 = neighbour
static int      g_l0Count = 0, g_l1Count = 0;

static void BuildCluster() {
    g_inCluster = (uint8_t*)calloc(g_fnCount, 1);
    if (!g_inCluster) return;
    for (uint32_t i = 0; i < g_fnCount; ++i)
        if (g_regions[i].refsTlsList) { g_inCluster[i] = 1; ++g_l0Count; }
    for (uint32_t i = 0; i < g_fnCount; ++i) {
        if (g_inCluster[i] == 1) {                          // callees of an L0 member
            for (uint32_t k = 0; k < g_regions[i].calleeCount; ++k) {
                int j = FindFunctionIndex(g_edges[g_regions[i].calleeOff + k]);
                //
                // Skip the general-purpose helpers -- memcpy, the exception
                // machinery, the logging paths. Everything the TLS code calls
                // that is actually about TLS has one or two callers; anything
                // with a crowd of them is shared with the rest of ntdll and its
                // locks would only dilute the vote below.
                //
                if (j >= 0 && !g_inCluster[j] && g_regions[j].callerCount <= 8)
                    g_inCluster[j] = 2;
            }
            continue;
        }
        for (uint32_t k = 0; k < g_regions[i].calleeCount; ++k) {   // callers of one
            int j = FindFunctionIndex(g_edges[g_regions[i].calleeOff + k]);
            if (j >= 0 && g_regions[j].refsTlsList) { g_inCluster[i] = 2; break; }
        }
    }
    for (uint32_t i = 0; i < g_fnCount; ++i) if (g_inCluster[i]) ++g_l1Count;
}

struct Tally { const void* addr; int votes; };
static void Vote(Tally* t, int& n, int cap, const void* a) {
    for (int i = 0; i < n; ++i) if (t[i].addr == a) { ++t[i].votes; return; }
    if (n < cap) { t[n].addr = a; t[n].votes = 1; ++n; }
}
static const void* Winner(Tally* t, int n, int* votes, int* runnerUp) {
    const void* best = nullptr; int bv = 0, second = 0;
    for (int i = 0; i < n; ++i)
        if (t[i].votes > bv) { second = bv; bv = t[i].votes; best = t[i].addr; }
        else if (t[i].votes > second) second = t[i].votes;
    if (votes) *votes = bv;
    if (runnerUp) *runnerUp = second;
    return best;
}

static const void* g_tlsLock = nullptr;   static int g_tlsLockVotes = 0, g_tlsLockRunner = 0;
static const void* g_tlsHeap = nullptr;   static int g_tlsHeapVotes = 0, g_tlsHeapRunner = 0;
static const void* g_tlsBitmap = nullptr; static int g_tlsBitmapVotes = 0, g_tlsBitmapRunner = 0;

static Tally g_lockTally[64];   static int g_lockTallyN = 0;
static Tally g_heapTally[64];   static int g_heapTallyN = 0;
static Tally g_bitTally[64];    static int g_bitTallyN = 0;

static void DeriveGlobals() {
    if (!g_inCluster) return;
    for (uint32_t i = 0; i < g_fnCount; ++i) {
        if (!g_inCluster[i]) continue;
        const Region& r = g_regions[i];
        for (int k = 0; k < r.nLocks; ++k)   Vote(g_lockTally, g_lockTallyN, 64, r.locks[k].lock);
        for (int k = 0; k < r.nHeaps; ++k)   Vote(g_heapTally, g_heapTallyN, 64, r.heaps[k].glob);
        for (int k = 0; k < r.nBitmaps; ++k) Vote(g_bitTally, g_bitTallyN, 64, r.bitmaps[k]);
    }
    g_tlsLock = Winner(g_lockTally, g_lockTallyN, &g_tlsLockVotes, &g_tlsLockRunner);
    g_tlsHeap = Winner(g_heapTally, g_heapTallyN, &g_tlsHeapVotes, &g_tlsHeapRunner);
    g_tlsBitmap = Winner(g_bitTally, g_bitTallyN, &g_tlsBitmapVotes, &g_tlsBitmapRunner);
}

// ============================================================ candidate choice
//
// Required, all four:
//   R1  the region is an exception-directory function start (true by construction)
//   R2  it touches LdrpTlsLock -- through the exported SRW routines, or just by
//       materialising the address. The weaker half of that matters: MSVC already
//       inlines the SRW acquire fast path into LdrpHandleTlsData on ARM64, and
//       the day it does the same to LdrpReleaseTlsEntry an exported-call-only
//       test would stop finding it. K1/K2 below still reward the call form.
//   R3  it calls the exported RtlFreeHeap
//   R4  it reaches &LdrpTlsList directly or through exactly one call
//       (LdrpFindTlsEntry; if a build inlines that, R4 holds directly instead)
//
// Ranking, to break a tie and to report a margin:
//   K1  acquires LdrpTlsLock *exclusively* -- the readers hold it shared
//   K2  releases it exclusively
//   K3  frees from LdrpTlsHeap specifically
//   K4  reads LdrpTlsBitmap.Buffer -- the inlined single-bit clear
//   K5  never calls RtlAllocateHeap; this function only ever frees
//   K6  has at least one caller inside ntdll
//   K7  its extent is under 0x200 bytes
//
// LdrpHandleTlsData is the one other function that satisfies R2..R4 on every
// build measured. K5 alone separates them; K4, K6 and K7 agree.
//
static const char* kAnchorNames[7] = {
    "acquires TLS lock exclusive",
    "releases TLS lock exclusive",
    "frees from LdrpTlsHeap",
    "reads LdrpTlsBitmap.Buffer",
    "never allocates",
    "has an ntdll caller",
    "extent under 0x200",
};

struct Candidate { uint32_t idx; uint8_t k[7]; int score; };
static Candidate g_cands[64];
static int       g_candCount = 0;

static bool UsesLock(const Region& r, const void* lock, uint8_t mask) {
    for (int i = 0; i < r.nLocks; ++i)
        if (r.locks[i].lock == lock && (r.locks[i].modes & mask)) return true;
    return false;
}
static bool UsesHeap(const Region& r, const void* g, uint8_t mask) {
    for (int i = 0; i < r.nHeaps; ++i)
        if (r.heaps[i].glob == g && (r.heaps[i].modes & mask)) return true;
    return false;
}

static void SelectCandidates() {
    const void* bitmapBuffer = g_tlsBitmap
        ? (const void*)((const uint8_t*)g_tlsBitmap + sizeof(void*)) : nullptr;

    for (uint32_t i = 0; i < g_fnCount && g_candCount < 64; ++i) {
        const Region& r = g_regions[i];
        if (!r.callsFree) continue;                                   // R3, cheapest
        if (!UsesLock(r, g_tlsLock, 0x0F) &&                          // R2
            !CodeRefers(g_ntBase + r.rva, r.extent, g_tlsLock)) continue;
        if (!ReachesList(i)) continue;                                // R4

        Candidate c{}; c.idx = i;
        c.k[0] = UsesLock(r, g_tlsLock, 0x01) ? 1 : 0;
        c.k[1] = UsesLock(r, g_tlsLock, 0x04) ? 1 : 0;
        c.k[2] = (g_tlsHeap && UsesHeap(r, g_tlsHeap, 0x01)) ? 1 : 0;
        c.k[3] = (bitmapBuffer &&
                  CodeRefers(g_ntBase + r.rva, r.extent, bitmapBuffer)) ? 1 : 0;
        c.k[4] = r.callsAlloc ? 0 : 1;
        c.k[5] = r.callerCount ? 1 : 0;
        c.k[6] = (r.extent && r.extent < 0x200) ? 1 : 0;
        for (int k = 0; k < 7; ++k) c.score += c.k[k];
        g_cands[g_candCount++] = c;
    }
}

// ================================================================ verification

typedef NTSTATUS(NTAPI* PFN_RELEASE_TLS)(void* /*LdrEntry*/, void** /*Out*/);
typedef VOID(NTAPI* PFN_SRW)(PVOID);

static PFN_SRW g_acqExcl, g_relExcl;

//
// Refuse to acquire anything that does not look like a writable global. This is
// the same gate lockprobe applies before treating an address as an SRW lock;
// getting it wrong writes into ntdll.
//
static bool PlausibleLock(const void* p) {
    if (!p || ((ULONG_PTR)p & (sizeof(void*) - 1))) return false;
    if (!InNtdll(p)) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & writable) != 0;
}

//
// A TLS index whose bitmap bit is already clear, chosen from the top so it is
// as far as possible from the indices in use. The fabricated entry is filled
// with it as 32-bit units end to end, so wherever this build reads the index
// from, the bit-clear rewrites a byte with the value it already had.
//
static bool PickSafeIndex(uint32_t* index, uint8_t** byteAddr) {
    if (!g_tlsBitmap) return false;
    uint32_t sizeOfBitMap = 0;
    void* buffer = nullptr;
    if (!ReadU32Safe(g_tlsBitmap, &sizeOfBitMap)) return false;
    if (!ReadPtrSafe((const uint8_t*)g_tlsBitmap + sizeof(void*), &buffer)) return false;
    if (!buffer || !sizeOfBitMap || sizeOfBitMap > (1u << 22)) return false;
    for (uint32_t bit = sizeOfBitMap; bit-- > 0;) {
        uint8_t* by = (uint8_t*)buffer + (bit >> 3);
        uint8_t v = 0;
        if (!ReadU8Safe(by, &v)) return false;
        if ((v >> (bit & 7)) & 1) continue;
        *index = bit; *byteAddr = by; return true;
    }
    return false;
}

struct CausalityResult {
    bool ran, notFoundOk, positiveOk, bitmapIntact, relinked, lockHeld;
    NTSTATUS negStatus, posStatus;
    void* handedBack;
    uint32_t safeIndex;
};

static void RunCausality(PFN_RELEASE_TLS fn, CausalityResult* out) {
    memset(out, 0, sizeof(*out));
    if (!g_tlsList) return;

    uint32_t safeIndex = 0; uint8_t* bitByte = nullptr;
    if (!PickSafeIndex(&safeIndex, &bitByte)) return;
    uint8_t bitBefore = *bitByte;
    out->safeIndex = safeIndex;

    // Two committed, zero-backed pages: a token standing in for an
    // LDR_DATA_TABLE_ENTRY (only its address is ever compared) and the
    // fabricated TLS entry. A stray read off either lands on our own memory.
    void* token = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* fake = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!token || !fake) {
        if (token) VirtualFree(token, 0, MEM_RELEASE);
        if (fake) VirtualFree(fake, 0, MEM_RELEASE);
        return;
    }
    out->ran = true;

    // ---- negative half: a module the list has never heard of.
    void* sentinel = (void*)(ULONG_PTR)0xF00DF00DF00DF00DULL;
    void* neg = sentinel;
    __try { out->negStatus = fn(token, &neg); }
    __except (EXCEPTION_EXECUTE_HANDLER) { out->negStatus = (NTSTATUS)1; neg = nullptr; }
    out->notFoundOk = (out->negStatus != 0) && (neg == sentinel);

    // ---- positive half: splice a fabricated entry and require it back.
    for (uint32_t o = 0; o < 0x400; o += 4)
        *(uint32_t*)((uint8_t*)fake + o) = safeIndex;

    //
    // Held across the call, not just across the splice. That is the right thing
    // -- ntdll's contract for the two-argument form is that the caller holds the
    // lock -- and it keeps any other thread out of a list that briefly contains
    // a fabricated entry. The cost is that a *wrong* candidate which acquires
    // LdrpTlsLock itself would deadlock here rather than fail cleanly. Any such
    // candidate would have had to score 7/7 first, so this is a hang the
    // operator sees, not a wrong answer the operator does not.
    //
    if (g_acqExcl && PlausibleLock(g_tlsLock)) {
        g_acqExcl((PVOID)g_tlsLock);
        out->lockHeld = true;
    }

    LIST_ENTRY* head = (LIST_ENTRY*)g_tlsList;
    LIST_ENTRY* oldFlink = head->Flink;
    LIST_ENTRY* links = (LIST_ENTRY*)fake;
    links->Flink = oldFlink;
    links->Blink = head;
    *(void**)((uint8_t*)fake + g_tlsModOff) = token;
    oldFlink->Blink = links;
    head->Flink = links;

    void* got = sentinel;
    __try { out->posStatus = fn(token, &got); }
    __except (EXCEPTION_EXECUTE_HANDLER) { out->posStatus = (NTSTATUS)1; got = nullptr; }

    bool unlinked = (head->Flink == oldFlink) && (oldFlink->Blink == head);
    if (!unlinked) {                              // put the list back ourselves
        links->Blink->Flink = links->Flink;
        links->Flink->Blink = links->Blink;
        out->relinked = true;
    }
    if (out->lockHeld) g_relExcl((PVOID)g_tlsLock);

    out->handedBack = got;
    out->positiveOk = (out->posStatus == 0) && (got == fake) && unlinked;
    out->bitmapIntact = (*bitByte == bitBefore);

    VirtualFree(token, 0, MEM_RELEASE);
    VirtualFree(fake, 0, MEM_RELEASE);
}

// ==================================================================== reporting

static void DumpBytes(const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; ++i) {
        if (i && (i % 16) == 0) printf("\n                  ");
        printf("%02X ", b[i]);
    }
    printf("\n");
}

static void PrintLockModes(uint8_t m) {
    printf("%s%s%s%s",
        (m & 1) ? "acqE " : "", (m & 2) ? "acqS " : "",
        (m & 4) ? "relE " : "", (m & 8) ? "relS " : "");
}

static void PrintTally(const char* what, Tally* t, int n, const void* winner) {
    printf("  %s\n", what);
    for (int i = 0; i < n; ++i)
        printf("    ntdll+0x%-8X %2d vote%s%s\n", Rva(t[i].addr), t[i].votes,
            t[i].votes == 1 ? " " : "s", t[i].addr == winner ? "   <== chosen" : "");
    if (!n) printf("    (none)\n");
}

static void PrintSurvey() {
    printf("\n--- survey: LdrpTlsList membership ---\n");
    printf("list head       : ntdll+0x%X   entries %d   head candidates %d\n",
        g_tlsList ? Rva(g_tlsList) : 0, g_tlsListLen, g_tlsListCandidates);
    printf("entry layout    : ModuleEntry +0x%X, TLS directory copy +0x%X (measured)\n",
        g_tlsModOff, g_tlsDirOff);
    for (int i = 0; i < g_tlsMemberCount; ++i) {
        printf("    %p  ->  ", g_tlsMembers[i].entry);
        PrintName(g_tlsMembers[i].mod);
        printf("\n");
    }

    printf("\n--- survey: TLS cluster ---\n");
    for (uint32_t i = 0; i < g_fnCount; ++i) {
        if (!g_inCluster[i]) continue;
        const Region& r = g_regions[i];
        printf("  ntdll+0x%-8X %-6s ext 0x%-4X callers %-3u", r.rva,
            g_inCluster[i] == 1 ? "direct" : "adj", r.extent, r.callerCount);
        if (r.callsFree)  printf(" free");
        if (r.callsAlloc) printf(" alloc");
        for (int k = 0; k < r.nLocks; ++k) {
            printf("  lock ntdll+0x%X[", Rva(r.locks[k].lock));
            PrintLockModes(r.locks[k].modes);
            printf("]");
        }
        for (int k = 0; k < r.nHeaps; ++k)
            printf("  heap ntdll+0x%X", Rva(r.heaps[k].glob));
        for (int k = 0; k < r.nBitmaps; ++k)
            printf("  bitmap ntdll+0x%X", Rva(r.bitmaps[k]));
        printf("\n");
    }

    printf("\n--- survey: globals the cluster votes for ---\n");
    PrintTally("SRW locks", g_lockTally, g_lockTallyN, g_tlsLock);
    PrintTally("heap handles", g_heapTally, g_heapTallyN, g_tlsHeap);
    PrintTally("bitmaps", g_bitTally, g_bitTallyN, g_tlsBitmap);

    printf("\n--- survey: everything that passed the four required anchors ---\n");
    for (int i = 0; i < g_candCount; ++i) {
        const Region& r = g_regions[g_cands[i].idx];
        printf("  ntdll+0x%-8X score %d/7  ext 0x%-4X callers %u\n",
            r.rva, g_cands[i].score, r.extent, r.callerCount);
        for (int k = 0; k < 7; ++k)
            printf("      %-30s %s\n", kAnchorNames[k], g_cands[i].k[k] ? "yes" : "no");
    }
}

static void PrintSurveyAll() {
    printf("\n--- survey-all: every ntdll function that takes an SRW lock, by lock ---\n");
    struct Bucket { const void* lock; int n; uint32_t rva[8]; };
    static Bucket b[512]; int nb = 0;
    for (uint32_t i = 0; i < g_fnCount; ++i) {
        const Region& r = g_regions[i];
        for (int k = 0; k < r.nLocks; ++k) {
            int f = -1;
            for (int j = 0; j < nb; ++j) if (b[j].lock == r.locks[k].lock) { f = j; break; }
            if (f < 0) { if (nb == 512) continue; f = nb++; b[f].lock = r.locks[k].lock; b[f].n = 0; }
            if (b[f].n < 8) b[f].rva[b[f].n] = r.rva;
            ++b[f].n;
        }
    }
    for (int rank = 0; rank < nb; ++rank) {
        int pick = -1;
        for (int j = 0; j < nb; ++j)
            if (b[j].n >= 0 && (pick < 0 || b[j].n > b[pick].n)) pick = j;
        if (pick < 0) break;
        printf("  ntdll+0x%-8X %3d function%s%s\n", Rva(b[pick].lock), b[pick].n,
            b[pick].n == 1 ? "" : "s",
            b[pick].lock == g_tlsLock ? "   <== LdrpTlsLock" : "");
        for (int k = 0; k < b[pick].n && k < 8; ++k)
            printf("        ntdll+0x%X\n", b[pick].rva[k]);
        b[pick].n = -1;
    }
}

// ========================================================================= main

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);   // a probe that faults must still have reported
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--survey")) g_survey = true;
        else if (!strcmp(argv[i], "--survey-all")) { g_survey = true; g_surveyAll = true; }
        else if (!strcmp(argv[i], "--dump")) g_dump = true;
        else if (!strcmp(argv[i], "--no-causality")) g_causality = false;
    }

    g_tlsAnchor ^= 1;                 // make sure our own TLS is really live

    g_nt = GetModuleHandleW(L"ntdll.dll");
    if (!g_nt) { printf("no ntdll\n"); return 2; }
    g_ntBase = (const uint8_t*)g_nt;
    PIMAGE_NT_HEADERS h = NtHeaders(g_ntBase);
    if (!h) { printf("ntdll header unreadable\n"); return 2; }
    g_ntSize = h->OptionalHeader.SizeOfImage;
    g_ntMachine = h->FileHeader.Machine;
    g_ntStamp = h->FileHeader.TimeDateStamp;

    printf("================ probe_tls_release report ================\n");
#if defined(_M_ARM64)
    printf("built for       : arm64\n");
#elif defined(_M_X64)
    printf("built for       : x64\n");
#else
    printf("built for       : (unsupported)\n");
#endif
    printf("ntdll base      : %p\n", (void*)g_nt);
    printf("ntdll machine   : 0x%04X  (0x8664=x64, 0xAA64=ARM64)\n", g_ntMachine);
    printf("ntdll build id  : TimeDateStamp 0x%08lX  SizeOfImage 0x%08lX\n",
        (unsigned long)g_ntStamp, (unsigned long)g_ntSize);

    {   // which instruction set are ntdll's bodies in, from this process's view?
        void* p = (void*)GetProcAddress(g_nt, "RtlAcquireSRWLockExclusive");
        const void* t = nullptr;
        if (p && IsEcFastForward(p, &t)) g_isEcHost = true;
    }
#if defined(_M_ARM64)
    g_codeIsArm64 = true;
#else
    g_codeIsArm64 = g_isEcHost;
#endif
    printf("code decoded as : %s%s\n", g_codeIsArm64 ? "arm64" : "x64",
        g_isEcHost ? "  (ARM64EC bodies behind x64 fast-forward thunks)" : "");

    InitFunctionTable();
    printf("function table  : %u entries  (ntdll+0x%X .. +0x%X)\n",
        g_fnCount, g_fnLow, g_fnHigh);
    for (int i = 0; i < g_pieceCount; ++i)
        printf("     .pdata part: ntdll+0x%-8X 0x%-6X bytes, stride %u -> %u entries\n",
            g_pieces[i].rva, g_pieces[i].bytes, g_pieces[i].stride, g_pieces[i].count);
    if (!g_fnCount) { printf("no exception directory; cannot bound a scan\n"); return 2; }

    int missing = ResolveCallees();
    g_acqExcl = (PFN_SRW)GetProcAddress(g_nt, "RtlAcquireSRWLockExclusive");
    g_relExcl = (PFN_SRW)GetProcAddress(g_nt, "RtlReleaseSRWLockExclusive");
    printf("exported anchors: %d of %d resolved%s\n",
        kCalleeCount - missing, kCalleeCount, g_isEcHost ? "  (+ EC aliases)" : "");
    if (!g_acqExcl || !g_relExcl) { printf("SRW routines missing\n"); return 2; }

    // ------------------------------------------------------------------ step 1
    EnumerateModules();
    DiscoverTlsList();
    printf("\n--- step 1: LdrpTlsList, from live data ---\n");
    printf("modules         : %d loaded, %d with a TLS directory\n",
        g_modCount, g_modsWithTls);
    if (!g_tlsList) {
        printf("LdrpTlsList     : NOT FOUND -- no circular list in ntdll's writable\n"
               "                  sections has members matching a loaded module's\n"
               "                  IMAGE_TLS_DIRECTORY\n");
        printf("\nRESULT: NOT LOCATED\n");
        printf("=========================================================\n");
        return 1;
    }
    printf("LdrpTlsList     : ntdll+0x%X   %d entr%s, %d head candidate%s\n",
        Rva(g_tlsList), g_tlsListLen, g_tlsListLen == 1 ? "y" : "ies",
        g_tlsListCandidates, g_tlsListCandidates == 1 ? "" : "s");
    printf("entry layout    : ModuleEntry +0x%X, TLS directory copy +0x%X (measured)\n",
        g_tlsModOff, g_tlsDirOff);
    if (g_tlsListCandidates > 1)
        printf("WARNING         : more than one structure matched; using the first\n");

    // ------------------------------------------------------------------ step 2
    ScanAllRegions();
    if (!g_regions) { printf("out of memory\n"); return 2; }
    BuildCluster();
    DeriveGlobals();
    printf("\n--- step 2: the TLS cluster and its globals ---\n");
    printf("cluster         : %d function%s reference &LdrpTlsList, %d with neighbours\n",
        g_l0Count, g_l0Count == 1 ? "" : "s", g_l1Count);
    if (g_tlsLock)
        printf("LdrpTlsLock     : ntdll+0x%-8X %d cluster vote%s (runner-up %d)\n",
            Rva(g_tlsLock), g_tlsLockVotes, g_tlsLockVotes == 1 ? "" : "s", g_tlsLockRunner);
    else printf("LdrpTlsLock     : NOT DERIVED\n");
    if (g_tlsHeap)
        printf("LdrpTlsHeap     : ntdll+0x%-8X %d cluster vote%s (runner-up %d)\n",
            Rva(g_tlsHeap), g_tlsHeapVotes, g_tlsHeapVotes == 1 ? "" : "s", g_tlsHeapRunner);
    else printf("LdrpTlsHeap     : NOT DERIVED\n");
    if (g_tlsBitmap)
        printf("LdrpTlsBitmap   : ntdll+0x%-8X %d cluster vote%s (runner-up %d)\n",
            Rva(g_tlsBitmap), g_tlsBitmapVotes, g_tlsBitmapVotes == 1 ? "" : "s", g_tlsBitmapRunner);
    else printf("LdrpTlsBitmap   : NOT DERIVED  (every bit operation is inlined)\n");

    if (!g_tlsLock) {
        printf("\nRESULT: NOT LOCATED -- no SRW lock is reached from the TLS cluster,\n"
               "        so this build inlines every acquire. Run --survey-all.\n");
        printf("=========================================================\n");
        return 1;
    }

    // ------------------------------------------------------------------ step 3
    SelectCandidates();
    printf("\n--- step 3: candidates ---\n");
    printf("required        : touches LdrpTlsLock, calls RtlFreeHeap, reaches"
           " &LdrpTlsList in <=1 call\n");
    printf("passing         : %d\n", g_candCount);

    int best = -1, bestScore = -1, runnerUp = -1, tied = 0;
    for (int i = 0; i < g_candCount; ++i) {
        const Region& r = g_regions[g_cands[i].idx];
        printf("  ntdll+0x%-8X score %d/7  ext 0x%-4X callers %u\n",
            r.rva, g_cands[i].score, r.extent, r.callerCount);
        if (g_cands[i].score > bestScore) {
            runnerUp = bestScore; bestScore = g_cands[i].score; best = i; tied = 1;
        }
        else if (g_cands[i].score == bestScore) ++tied;
        else if (g_cands[i].score > runnerUp) runnerUp = g_cands[i].score;
    }
    //
    // The margin is the early-warning number, the way lockprobe's donor count
    // is. It shrinking across Windows updates is the signal that this technique
    // is eroding, long before it starts returning the wrong answer.
    //
    printf("margin          : %d over the runner-up (%d of 7 vs %d)\n",
        runnerUp < 0 ? bestScore : bestScore - runnerUp, bestScore,
        runnerUp < 0 ? 0 : runnerUp);
    if (best < 0 || tied != 1) {
        printf("\nRESULT: NOT LOCATED -- %s\n", best < 0
            ? "nothing satisfied the required anchors"
            : "the ranking anchors did not separate the candidates");
        printf("=========================================================\n");
        return 1;
    }

    const Region& win = g_regions[g_cands[best].idx];
    void* fn = (void*)(g_ntBase + win.rva);
    printf("\ncandidate       : %p  (ntdll+0x%X)\n", fn, win.rva);
    for (int k = 0; k < 7; ++k)
        printf("  %-30s %s\n", kAnchorNames[k], g_cands[best].k[k] ? "yes" : "NO");
    printf("  %-30s", "callers");
    int shown = 0;
    for (uint32_t i = 0; i < g_fnCount && shown < 8; ++i)
        if (Calls(i, win.rva)) { printf(" ntdll+0x%X", g_regions[i].rva); ++shown; }
    if (!shown) printf(" none");
    printf("\n");
    if (g_dump) { printf("  first 48 bytes  : "); DumpBytes(fn, 48); }

    //
    // Refuse to call an ARM64EC body that has no x64 entry thunk. The emulator
    // cannot make that transition and does not raise a catchable exception; it
    // kills the process. Checked before anything else touches the address.
    //
    bool callable = true;
    if (g_isEcHost && EcEntryThunk(fn) == 0) {
        callable = false;
        printf("\ncallability     : NOT CALLABLE from this process\n");
        printf("  This is the ARM64EC body. Its entry-thunk marker at fn-4 is 0, so\n");
        printf("  no thunk exists to marshal an emulated x64 caller into the ARM64\n");
        printf("  ABI, and the transition terminates the process (0xC000026F) rather\n");
        printf("  than raising anything SEH can catch. The address is right; calling\n");
        printf("  it from an x64 build on ARM64X is not possible. Use the native\n");
        printf("  ARM64 build, or do not handle TLS through ntdll here.\n");
    }

    // ------------------------------------------------------------------ step 4
    CausalityResult cr{};
    if (g_causality && callable) {
        printf("\n--- step 4: causality ---\n");
        RunCausality((PFN_RELEASE_TLS)fn, &cr);
        if (!cr.ran) {
            printf("  SKIPPED -- needs LdrpTlsBitmap, to pick a TLS index whose bit is\n"
                   "             already clear so the call cannot change any state\n");
        }
        else {
            printf("  spare TLS index : %u   list lock held during splice: %s\n",
                cr.safeIndex, cr.lockHeld ? "yes" : "no");
            printf("  unknown module  : status 0x%08lX, out untouched  : %s\n",
                (unsigned long)cr.negStatus, cr.notFoundOk ? "yes (expected)" : "NO");
            printf("  fabricated entry: status 0x%08lX, handed back %p : %s\n",
                (unsigned long)cr.posStatus, cr.handedBack,
                cr.positiveOk ? "yes, and unlinked (expected)" : "NO");
            printf("  bitmap unchanged: %s\n", cr.bitmapIntact ? "yes" : "NO");
            if (cr.relinked)
                printf("  note            : the list was repaired by the probe\n");
        }
    }
    else if (!callable)
        printf("\n--- step 4: causality not attempted (would kill the process) ---\n");
    else printf("\n--- step 4: causality skipped (--no-causality) ---\n");

    if (g_survey) PrintSurvey();
    if (g_surveyAll) PrintSurveyAll();

    bool verified = cr.ran && cr.notFoundOk && cr.positiveOk && cr.bitmapIntact;
    bool structural = bestScore >= 6;
    bool ok = (g_causality && callable) ? verified : structural;

    printf("\nRESULT: ");
    if (!callable)
        printf("LOCATED at %d/7 on structure, but NOT CALLABLE here --\n"
               "        the ARM64EC body has no x64 entry thunk\n", bestScore);
    else if (ok && g_causality)
        printf("VERIFIED -- this is LdrpReleaseTlsEntry\n");
    else if (ok)
        printf("LOCATED at %d/7 on structure alone (causality not run)\n", bestScore);
    else if (cr.ran)
        printf("FAILED VERIFICATION -- do not use this address\n");
    else
        printf("NOT VERIFIED -- structure agrees but nothing was proved\n");
    printf("address         : ntdll+0x%X\n", win.rva);
    printf("=========================================================\n");
    return (ok && callable) ? 0 : 1;
}
