//
// probe_ift -- locate and validate ntdll!LdrpInvertedFunctionTable and
// ntdll!LdrpHashTable at runtime, without a byte signature, a hardcoded struct
// offset, a hardcoded MaxCount, or a PDB.
//
// Standalone by design: it links nothing from MemoryModule/, exactly like
// stress/lockprobe.cpp, so it can be built and run against an unfamiliar
// Windows build without dragging the library in. That is also why the
// LdrpModuleDatatableLock locator below is a copy of lockprobe's rather than a
// call into it.
//
// ---------------------------------------------------------------------------
// What is wrong with how the library finds these today
// ---------------------------------------------------------------------------
//
// FindLdrpInvertedFunctionTable64() in MemoryModule/Initialize.cpp builds a
// 24-byte RTL_INVERTED_FUNCTION_TABLE_ENTRY for ntdll, byte-scans ntdll's
// ".mrdata" for it, subtracts a hardcoded 0x10 to reach the table head, and
// accepts the hit if MaxCount == 0x200 and Overflow == 0. Every one of those is
// an assumption about a structure whose shape already changed once between
// Windows 7 and Windows 8 (see InvertedFunctionTable.h, which carries two
// incompatible layouts for it):
//   - that entry[0] describes ntdll,
//   - that the entry is {ExceptionDirectory, ImageBase, ImageSize, EDSize},
//   - that the header is exactly 0x10 bytes,
//   - that MaxCount is 0x200,
//   - that the table lives in a section literally named ".mrdata",
//   - and, implicitly, that there is only one such table in the image.
// A build that changes any of them either misses (feature silently off) or --
// worse -- matches something else that happens to hold a pointer to ntdll. The
// last assumption is already false: an ARM64X ntdll carries two of these tables,
// and this tool had to grow a rule for telling them apart (see
// ChooseInvertedTable).
//
// FindLdrpHashTable() is much better: it derives the address from live loader
// state (a module that is alone in its bucket points at its bucket head, and the
// head's index is the module's name hash) and then re-hashes every entry in
// every bucket. But it still reaches HashLinks through a compile-time struct
// offset, hardcodes 32 buckets, gives up after the first candidate instead of
// trying the next module, and runs before the datatable lock is located -- so
// the walk is unsynchronised against ntdll's own inserts.
//
// ---------------------------------------------------------------------------
// What this does instead
// ---------------------------------------------------------------------------
//
// The unifying idea: both structures are *derivable from live loader state*,
// and both carry an invariant strong enough to prove a candidate.
//
//   LdrpHashTable
//     Derivation. For every loaded module, the LIST_ENTRY at some fixed offset
//     inside its LDR_DATA_TABLE_ENTRY is a member of a ring whose one non-module
//     node is the bucket head. Which offset that is gets *measured*: try every
//     pointer-aligned offset, keep the ones where every module's ring is
//     well-formed, discard the three PEB->Ldr list heads and any head outside
//     ntdll's image. Then table = head - index*sizeof(LIST_ENTRY), where index
//     is the module's name hash -- and every module must produce the same table.
//     That is N independent anchors voting, with N = the module count.
//     Bucket count and hash algorithm are searched over, not assumed.
//
//     Independent second method. Scan ntdll's non-executable sections for an
//     array of N LIST_ENTRYs that are all well-formed ring heads whose members
//     are all loader entries. That uses no hash at all, so agreement between the
//     two methods is real corroboration.
//
//     Proof. Every member of every bucket must re-hash to the bucket it sits in,
//     and every loaded module must appear exactly once.
//
//   LdrpInvertedFunctionTable
//     Derivation. Collect the base address of every loaded module, then scan
//     ntdll's non-executable sections for those values. The table's ImageBase
//     column is the longest arithmetic progression of such hits with ascending
//     bases. That yields the entry stride with nothing assumed. The remaining
//     field offsets are then measured the same way: the offset at which *every*
//     entry holds its module's SizeOfImage is the ImageSize field, and so on.
//     The header is found by walking back from the run to the first ULONG pair
//     (Count, MaxCount) with Count about the number of entries present -- which
//     yields MaxCount as a measurement. The run does not always start at
//     entry[0], because Windows 8 and later pin ntdll at index 0 outside the
//     sort, so the array start is then pulled back a whole entry at a time for
//     as long as that accounts for more of the table.
//
//     Independent second method. The classic-layout header scan: look for
//     (Count, MaxCount, ..., Overflow) followed by entries at +0x10 with stride
//     0x18. This is deliberately the library's assumption, so agreement between
//     the two methods is the evidence that the assumption still holds on this
//     build, and disagreement is the warning that it does not.
//
//     Disambiguation. On ARM64X both methods find two tables, back to back in
//     .mrdata, both structurally valid and both updated on every load. They are
//     told apart by which one's ExceptionDirectory column reproduces the .pdata
//     pointers this process's view of each image reports -- see
//     ChooseInvertedTable.
//
//     Proof, structural. Every entry must name a currently loaded module, carry
//     that module's SizeOfImage, sit in ascending ImageBase order from index 1,
//     and -- the direct analogue of the hash table's re-hash test -- carry the
//     exception directory pointer and size recomputed from that module's own PE
//     headers.
//
//     Proof, behavioural. LoadLibrary a DLL that is not loaded and the candidate
//     must gain an entry for exactly that base; FreeLibrary and it must lose it.
//     A wrong address cannot pass that, in the same way a wrong lock cannot pass
//     lockprobe's causality test.
//
// Walking ntdll's loader lists safely means holding ntdll!LdrpModuleDatatableLock,
// so lockprobe's locator is carried here verbatim and everything that reads
// loader state runs under the lock, shared.
//
// Build:
//   cl /nologo /std:c++17 /O2 /MT /EHsc probe_ift.cpp /link /OUT:probe_ift.exe
//
// Options:
//   --fast         skip the lock causality check (~450 ms) and the LoadLibrary test
//   --dump         hex-dump the located structures
//   --verbose      per-bucket detail
//   --hits         list every place in ntdll's data that holds a module base
//   --no-preload   do not load extra DLLs first; run against the bare process
//
// Exit code: 0 = both located and fully validated, 1 = one or both failed,
//            2 = setup failure.
//

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cwchar>

static bool g_verbose = false;
static bool g_dump = false;
static bool g_fast = false;
static bool g_showHits = false;
static bool g_noPreload = false;

// ============================================================ ntdll basics ==

static const uint8_t*    g_ntBase = nullptr;
static size_t            g_ntSize = 0;
static PIMAGE_NT_HEADERS g_ntHdr = nullptr;

struct SecInfo { char name[9]; uint32_t rva, size; DWORD chars; };
static SecInfo g_secs[48];
static int     g_secCount = 0;

static const char* SectionOfRva(uint32_t rva) {
    for (int i = 0; i < g_secCount; ++i)
        if (rva >= g_secs[i].rva && rva < g_secs[i].rva + g_secs[i].size) return g_secs[i].name;
    return "(none)";
}

static const char* SectionOf(const void* p) {
    if ((const uint8_t*)p < g_ntBase || (const uint8_t*)p >= g_ntBase + g_ntSize) return "(outside ntdll)";
    return SectionOfRva((uint32_t)((const uint8_t*)p - g_ntBase));
}

static void InitSections(HMODULE nt) {
    g_ntBase = (const uint8_t*)nt;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt;
    g_ntHdr = (PIMAGE_NT_HEADERS)(g_ntBase + dos->e_lfanew);
    g_ntSize = g_ntHdr->OptionalHeader.SizeOfImage;

    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(g_ntHdr);
    for (WORD i = 0; i < g_ntHdr->FileHeader.NumberOfSections && g_secCount < 48; ++i, ++s) {
        memcpy(g_secs[g_secCount].name, s->Name, 8);
        g_secs[g_secCount].name[8] = 0;
        g_secs[g_secCount].rva = s->VirtualAddress;
        g_secs[g_secCount].size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        g_secs[g_secCount].chars = s->Characteristics;
        ++g_secCount;
    }
}

//
// The ranges a data scan is allowed to touch: everything mapped from ntdll that
// is not code. Naming no section keeps ".mrdata" from being load-bearing the way
// it is in the library today -- if a future build moves the table to another
// data section this still finds it, and reports where it went.
//
static bool IsScannableSection(const SecInfo& s) {
    if (!s.size) return false;
    if (s.chars & IMAGE_SCN_MEM_EXECUTE) return false;
    return true;
}

// ------------------------------------------------- safe reads / memory tests

static bool Readable(const void* p, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    size_t avail = (size_t)(((const uint8_t*)mbi.BaseAddress + mbi.RegionSize) - (const uint8_t*)p);
    return avail >= n;
}

static bool RdPtr(const void* p, const uint8_t** out) {
    __try { *out = *(const uint8_t* const*)p; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool RdU32(const void* p, uint32_t* out) {
    __try { *out = *(const uint32_t*)p; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool RdU16(const void* p, uint16_t* out) {
    __try { *out = *(const uint16_t*)p; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

//
// A pointer that really is the base of a mapped image. VirtualQuery is what
// makes this strong: MEM_IMAGE plus AllocationBase == p cannot be faked by a
// stray pointer into the middle of something.
//
static bool LooksLikeImageBase(const uint8_t* p) {
    if (!p || ((uintptr_t)p & 0xFFF)) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) return false;
    if (mbi.AllocationBase != (PVOID)p) return false;
    uint16_t magic;
    if (!RdU16(p, &magic) || magic != IMAGE_DOS_SIGNATURE) return false;
    uint32_t lfanew;
    if (!RdU32(p + 0x3C, &lfanew) || lfanew < 0x40 || lfanew > 0x1000) return false;
    uint32_t sig;
    if (!RdU32(p + lfanew, &sig) || sig != IMAGE_NT_SIGNATURE) return false;
    return true;
}

static const IMAGE_NT_HEADERS* NtHeadersOf(const uint8_t* base) {
    uint32_t lfanew;
    if (!RdU32(base + 0x3C, &lfanew)) return nullptr;
    return (const IMAGE_NT_HEADERS*)(base + lfanew);
}

static void DumpBytes(const void* p, size_t n, const char* indent) {
    const uint8_t* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; ++i) {
        if ((i % 16) == 0) printf("%s%04zX  ", indent, i);
        printf("%02X ", b[i]);
        if ((i % 16) == 15) printf("\n");
    }
    if (n % 16) printf("\n");
}

// ==================================== ntdll!LdrpModuleDatatableLock locator ==
//
// Verbatim from stress/lockprobe.cpp -- see the long comment there for why this
// shape works. Repeated rather than shared because this tool has to stay
// standalone. Only the reporting is trimmed.
//

typedef VOID(NTAPI* PFN_SRW)(PVOID);
static PFN_SRW g_acqExcl, g_acqShared, g_relExcl, g_relShared;
static void* g_acqTargets[4];
static int   g_acqTargetCount = 0;

static const char* kDonors[] = {
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

static bool IsAcquireTarget(const void* p) {
    for (int i = 0; i < g_acqTargetCount; ++i)
        if (g_acqTargets[i] == p) return true;
    return false;
}

static bool IsEcFastForward(const void* p, void** jmpTarget) {
    static const uint8_t sig[] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x20,0x55,0x5d,0xe9 };
    const uint8_t* b = (const uint8_t*)p;
    if (memcmp(b, sig, sizeof(sig)) != 0) return false;
    int32_t rel; memcpy(&rel, b + 10, 4);
    if (jmpTarget) *jmpTarget = (void*)(b + 14 + rel);
    return true;
}

static uint32_t* g_fnStarts = nullptr;
static size_t    g_fnCount = 0;
static uint32_t  g_fnLow = 0, g_fnHigh = 0;

static void InitFunctionTable() {
    IMAGE_DATA_DIRECTORY& dir =
        g_ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size) return;

    size_t stride = (g_ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? 12 : 8;
    size_t count = dir.Size / stride;
    if (!count) return;

    g_fnStarts = (uint32_t*)malloc(count * sizeof(uint32_t));
    if (!g_fnStarts) return;

    const uint8_t* e = g_ntBase + dir.VirtualAddress;
    size_t n = 0;
    for (size_t i = 0; i < count; ++i) {
        uint32_t begin;
        memcpy(&begin, e + i * stride, 4);
        if (!begin || begin >= g_ntSize) continue;
        if (n && begin < g_fnStarts[n - 1]) continue;
        g_fnStarts[n++] = begin;
    }
    g_fnCount = n;
    if (n) { g_fnLow = g_fnStarts[0]; g_fnHigh = g_fnStarts[n - 1]; }
}

static bool IsFunctionStart(uint32_t rva) {
    size_t lo = 0, hi = g_fnCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_fnStarts[mid] == rva) return true;
        if (g_fnStarts[mid] < rva) lo = mid + 1; else hi = mid;
    }
    return false;
}

static size_t FunctionExtent(uint32_t rva, size_t cap) {
    if (!g_fnCount || rva < g_fnLow || rva > g_fnHigh) return cap;
    size_t lo = 0, hi = g_fnCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_fnStarts[mid] <= rva) lo = mid + 1; else hi = mid;
    }
    if (lo >= g_fnCount) return cap;
    size_t span = g_fnStarts[lo] - rva;
    return span && span < cap ? span : cap;
}

static bool IsFollowable(const void* target) {
    if (!g_ntBase) return false;
    ULONG_PTR t = (ULONG_PTR)target, b = (ULONG_PTR)g_ntBase;
    if (t < b || t + 16 >= b + g_ntSize) return false;

    uint32_t rva = (uint32_t)(t - b);
    if (g_fnCount) {
        if (IsFunctionStart(rva)) return true;
        if (rva >= g_fnLow && rva <= g_fnHigh) return false;
    }
    if ((rva & 0xF) == 0) return true;
    const uint8_t* p = (const uint8_t*)target;
    return p[-1] == 0xCC || p[-1] == 0xC3;
}

static void* DecodeArm64(const void* fn, size_t maxInsns, int depth) {
    const uint32_t* code = (const uint32_t*)fn;
    uint64_t adrp[32] = { 0 };
    bool     haveAdrp[32] = { false };
    uint64_t pendingArg0 = 0;
    bool     havePendingArg0 = false;
    int      calls = 0;

    for (size_t i = 0; i < maxInsns; ++i) {
        uint32_t insn = code[i];
        uint64_t pc = (uint64_t)(code + i);

        if ((insn & 0x9F000000u) == 0x90000000u) {              // ADRP Xd, imm
            uint32_t rd = insn & 0x1F;
            int64_t immlo = (insn >> 29) & 0x3;
            int64_t immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & (1LL << 20)) imm -= (1LL << 21);
            adrp[rd] = (pc & ~0xFFFULL) + (imm << 12);
            haveAdrp[rd] = true;
            continue;
        }
        if ((insn & 0xFF800000u) == 0x91000000u) {              // ADD Xd, Xn, #imm12
            uint32_t rd = insn & 0x1F;
            uint32_t rn = (insn >> 5) & 0x1F;
            uint32_t imm12 = (insn >> 10) & 0xFFF;
            if (rd == 0 && haveAdrp[rn]) { pendingArg0 = adrp[rn] + imm12; havePendingArg0 = true; }
            continue;
        }
        if ((insn & 0xFC000000u) == 0x94000000u) {              // BL imm26
            int64_t off = insn & 0x03FFFFFF;
            if (off & (1LL << 25)) off -= (1LL << 26);
            const void* target = (const void*)(pc + (off << 2));
            if (IsAcquireTarget(target))
                return havePendingArg0 ? (void*)pendingArg0 : nullptr;
            if (depth > 0 && ++calls <= 6) {
                if (void* r = DecodeArm64(target, 128, depth - 1)) return r;
            }
            continue;
        }
        if (insn == 0xD65F03C0u) break;                          // RET
    }
    return nullptr;
}

static void* DecodeX64(const void* fn, size_t window, int depth) {
    const uint8_t* p = (const uint8_t*)fn;
    int followed = 0;

    ULONG_PTR b = (ULONG_PTR)g_ntBase;
    if (g_ntBase && (ULONG_PTR)p >= b && (ULONG_PTR)p < b + g_ntSize)
        window = FunctionExtent((uint32_t)((ULONG_PTR)p - b), window);

    for (size_t i = 0; i + 5 <= window; ++i) {
        if (p[i] != 0xE8 && p[i] != 0xE9) continue;
        int32_t rel; memcpy(&rel, p + i + 1, 4);
        const uint8_t* target = p + i + 5 + rel;

        if (IsAcquireTarget(target)) {
            for (size_t back = 3; back <= 64 && back <= i; ++back) {
                const uint8_t* q = p + i - back;
                if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) {
                    int32_t d; memcpy(&d, q + 3, 4);
                    return (void*)(q + 7 + d);
                }
                if (q[0] == 0x48 && q[1] == 0xB9) {
                    uint64_t v; memcpy(&v, q + 2, 8);
                    return (void*)v;
                }
            }
            continue;
        }
        if (depth > 0 && followed < 8 && IsFollowable(target)) {
            ++followed;
            if (void* r = DecodeX64(target, 1024, depth - 1)) return r;
        }
    }
    return nullptr;
}

static void DecodeAny(const void* at, bool isEc, int depth, void** lockOut) {
    *lockOut = nullptr;
    __try {
        if (isEc) {
            if ((*lockOut = DecodeArm64(at, 256, depth)) != nullptr) return;
            if ((*lockOut = DecodeX64(at, 512, depth)) != nullptr) return;
        }
        else {
            if ((*lockOut = DecodeX64(at, 512, depth)) != nullptr) return;
            if ((*lockOut = DecodeArm64(at, 256, depth)) != nullptr) return;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { *lockOut = nullptr; }
}

static void* g_lock = nullptr;
static int   g_lockAgree = 0, g_lockDecoded = 0;
static bool  g_lockVerified = false;

static void LocateLock(HMODULE nt) {
    const int kDonorCount = (int)(sizeof(kDonors) / sizeof(kDonors[0]));
    void* agreed = nullptr; int agree = 0, matched = 0;

    for (int i = 0; i < kDonorCount; ++i) {
        void* fn = (void*)GetProcAddress(nt, kDonors[i]);
        if (!fn) continue;
        void* ecTarget = nullptr;
        bool isThunk = IsEcFastForward(fn, &ecTarget);
        const void* decodeAt = isThunk ? ecTarget : fn;

        void* lock = nullptr;
        DecodeAny(decodeAt, isThunk, 0, &lock);
        if (!lock) DecodeAny(decodeAt, isThunk, 2, &lock);
        if (!lock) continue;

        ++matched;
        if (!agreed) { agreed = lock; agree = 1; }
        else if (agreed == lock) ++agree;
    }

    g_lockDecoded = matched;
    g_lockAgree = agree;
    if (agree >= 2 && agreed) {
        // Same structural gate the library applies before it will use an address.
        ULONG_PTR c = (ULONG_PTR)agreed;
        bool aligned = (c & (sizeof(void*) - 1)) == 0;
        bool inImage = c >= (ULONG_PTR)g_ntBase && c + sizeof(void*) <= (ULONG_PTR)g_ntBase + g_ntSize;
        MEMORY_BASIC_INFORMATION mbi{};
        bool q = VirtualQuery(agreed, &mbi, sizeof(mbi)) != 0;
        const DWORD wmask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if (aligned && inImage && q && mbi.State == MEM_COMMIT && (mbi.Protect & wmask))
            g_lock = agreed;
    }
}

struct ProbeCtx { HANDLE go, done; };

static DWORD WINAPI LockProbeThread(LPVOID param) {
    ProbeCtx* c = (ProbeCtx*)param;
    WaitForSingleObject(c->go, INFINITE);
    HMODULE h = LoadLibraryW(L"version.dll");
    if (h) FreeLibrary(h);
    SetEvent(c->done);
    return 0;
}

static bool VerifyLockByCausality(void* candidate) {
    ProbeCtx ctx;
    ctx.go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ctx.done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ctx.go || !ctx.done) return false;

    HANDLE th = CreateThread(nullptr, 0, LockProbeThread, &ctx, 0, nullptr);
    if (!th) return false;
    Sleep(50);

    g_acqExcl(candidate);
    SetEvent(ctx.go);
    DWORD blocked = WaitForSingleObject(ctx.done, 400);
    g_relExcl(candidate);
    DWORD freed = WaitForSingleObject(ctx.done, 5000);

    WaitForSingleObject(th, 5000);
    CloseHandle(th); CloseHandle(ctx.go); CloseHandle(ctx.done);
    return blocked == WAIT_TIMEOUT && freed == WAIT_OBJECT_0;
}

//
// Everything that reads the loader database runs between these. Shared, not
// exclusive: ntdll takes it exclusive to mutate, so shared is enough for a
// consistent read and does not stop the world any longer than it must.
//
static void LockShared()   { if (g_lock) g_acqShared(g_lock); }
static void UnlockShared() { if (g_lock) g_relShared(g_lock); }

// ======================================================== loader snapshot ===

//
// The only offsets taken on faith anywhere in this tool: PEB->Ldr and the three
// list heads inside PEB_LDR_DATA. Both are validated below -- the first module
// in InLoadOrderModuleList must be the image PEB->ImageBaseAddress names, which
// simultaneously confirms the PEB layout and the derived DllBase offset.
//
#ifdef _WIN64
#define PEB_LDR_OFFSET        0x18
#define PEB_IMAGEBASE_OFFSET  0x10
#define LDR_INLOAD_OFFSET     0x10
#define LDR_INMEM_OFFSET      0x20
#define LDR_ININIT_OFFSET     0x30
#else
#define PEB_LDR_OFFSET        0x0C
#define PEB_IMAGEBASE_OFFSET  0x08
#define LDR_INLOAD_OFFSET     0x0C
#define LDR_INMEM_OFFSET      0x14
#define LDR_ININIT_OFFSET     0x1C
#endif

static const size_t kPtr = sizeof(void*);
static const size_t kLinkSize = 2 * sizeof(void*);       // sizeof(LIST_ENTRY)

#define MAX_MODS 1024

struct ModInfo {
    const uint8_t* entry;
    const uint8_t* base;
    uint32_t       sizeOfImage;
    const uint8_t* pdata;
    uint32_t       pdataSize;
    wchar_t        name[96];
    uint16_t       nameBytes;
};

static ModInfo g_mods[MAX_MODS];
static int     g_modCount = 0;
static int     g_baseOrder[MAX_MODS];       // indices, sorted by base

static const uint8_t* g_peb = nullptr;
static const uint8_t* g_ldrData = nullptr;
static const uint8_t* g_listHeads[3];

// Derived LDR_DATA_TABLE_ENTRY field offsets. -1 == not derived.
static int g_offDllBase = -1;
static int g_offSizeOfImage = -1;
static int g_offBaseDllName = -1;
static int g_offHashLinks = -1;
static int g_offDllBaseAlt = 0;             // how many other offsets also qualified
static int g_offSizeAlt = 0;
static int g_offNameAlt = 0;
static int g_altList[3][8];                 // DllBase / SizeOfImage / BaseDllName
static int g_altN[3] = { 0, 0, 0 };

static void RecordAlt(int which, int off) {
    if (g_altN[which] < 8) g_altList[which][g_altN[which]++] = off;
}

static int CmpByBase(const void* a, const void* b) {
    const uint8_t* x = g_mods[*(const int*)a].base;
    const uint8_t* y = g_mods[*(const int*)b].base;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static int FindModByBase(const uint8_t* b) {
    int lo = 0, hi = g_modCount;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        const uint8_t* v = g_mods[g_baseOrder[mid]].base;
        if (v == b) return g_baseOrder[mid];
        if (v < b) lo = mid + 1; else hi = mid;
    }
    return -1;
}

static int FindModByEntry(const uint8_t* e) {
    for (int i = 0; i < g_modCount; ++i) if (g_mods[i].entry == e) return i;
    return -1;
}

//
// Walk InLoadOrderModuleList. LDR_DATA_TABLE_ENTRY::InLoadOrderLinks is at
// offset 0 by definition of that list, so no offset is being assumed here --
// the links are the entries.
//
static bool SnapshotModules() {
    g_peb = (const uint8_t*)NtCurrentTeb();
#ifdef _WIN64
    if (!RdPtr(g_peb + 0x60, &g_peb)) return false;         // TEB->ProcessEnvironmentBlock
#else
    if (!RdPtr(g_peb + 0x30, &g_peb)) return false;
#endif
    if (!RdPtr(g_peb + PEB_LDR_OFFSET, &g_ldrData)) return false;
    if (!g_ldrData) return false;

    g_listHeads[0] = g_ldrData + LDR_INLOAD_OFFSET;
    g_listHeads[1] = g_ldrData + LDR_INMEM_OFFSET;
    g_listHeads[2] = g_ldrData + LDR_ININIT_OFFSET;

    const uint8_t* head = g_listHeads[0];
    const uint8_t* cur;
    if (!RdPtr(head, &cur)) return false;

    g_modCount = 0;
    while (cur && cur != head && g_modCount < MAX_MODS) {
        g_mods[g_modCount].entry = cur;
        g_mods[g_modCount].base = nullptr;
        ++g_modCount;
        if (!RdPtr(cur, &cur)) return false;
    }
    return g_modCount > 2;
}

//
// Derive the DllBase / SizeOfImage / BaseDllName offsets by requiring the
// candidate to hold for *every* loaded module, not by trusting a struct
// definition compiled months ago against a different Windows.
//
static bool DeriveEntryOffsets(const uint8_t* exeBase) {
    const int kMaxOff = 0x220;

    // ---- DllBase: the only pointer field that names a mapped image in every entry.
    for (int off = kPtr; off <= kMaxOff; off += (int)kPtr) {
        bool ok = true;
        for (int i = 0; i < g_modCount && ok; ++i) {
            const uint8_t* v;
            if (!RdPtr(g_mods[i].entry + off, &v)) { ok = false; break; }
            if (!LooksLikeImageBase(v)) ok = false;
        }
        if (!ok) continue;
        const uint8_t* first;
        RdPtr(g_mods[0].entry + off, &first);
        if (exeBase && first != exeBase) continue;      // list head must be the EXE
        if (g_offDllBase < 0) g_offDllBase = off; else { ++g_offDllBaseAlt; RecordAlt(0, off); }
    }
    if (g_offDllBase < 0) return false;

    for (int i = 0; i < g_modCount; ++i) {
        const uint8_t* v;
        RdPtr(g_mods[i].entry + g_offDllBase, &v);
        g_mods[i].base = v;
        const IMAGE_NT_HEADERS* h = NtHeadersOf(v);
        g_mods[i].sizeOfImage = h ? h->OptionalHeader.SizeOfImage : 0;
        g_mods[i].pdata = nullptr;
        g_mods[i].pdataSize = 0;
        if (h) {
            const IMAGE_DATA_DIRECTORY& d =
                h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (d.VirtualAddress && d.Size) {
                g_mods[i].pdata = v + d.VirtualAddress;
                g_mods[i].pdataSize = d.Size;
            }
        }
    }

    // ---- SizeOfImage: the ULONG that equals the PE header's value everywhere.
    for (int off = 4; off <= kMaxOff; off += 4) {
        bool ok = true;
        for (int i = 0; i < g_modCount && ok; ++i) {
            uint32_t v;
            if (!RdU32(g_mods[i].entry + off, &v) || v != g_mods[i].sizeOfImage) ok = false;
        }
        if (!ok) continue;
        if (g_offSizeOfImage < 0) g_offSizeOfImage = off; else { ++g_offSizeAlt; RecordAlt(1, off); }
    }

    // ---- BaseDllName: a well-formed UNICODE_STRING with no path separator, and
    //      the entry whose DllBase is ntdll must spell "ntdll.dll".
    for (int off = (int)kPtr; off <= kMaxOff; off += (int)kPtr) {
        bool ok = true, sawNtdll = false;
        for (int i = 0; i < g_modCount && ok; ++i) {
            uint16_t len, maxLen;
            const uint8_t* buf;
            if (!RdU16(g_mods[i].entry + off, &len) ||
                !RdU16(g_mods[i].entry + off + 2, &maxLen) ||
                !RdPtr(g_mods[i].entry + off + kPtr, &buf)) { ok = false; break; }
            if (!len || (len & 1) || len > maxLen || len > 0x400) { ok = false; break; }
            if (!buf || !Readable(buf, len)) { ok = false; break; }
            const wchar_t* w = (const wchar_t*)buf;
            for (int k = 0; k < len / 2; ++k) {
                if (w[k] == L'\\' || w[k] == L'/' || w[k] < 0x20) { ok = false; break; }
            }
            if (ok && g_mods[i].base == g_ntBase) {
                sawNtdll = (len == 9 * 2) && _wcsnicmp(w, L"ntdll.dll", 9) == 0;
                if (!sawNtdll) ok = false;
            }
        }
        if (!ok || !sawNtdll) continue;
        if (g_offBaseDllName < 0) g_offBaseDllName = off; else { ++g_offNameAlt; RecordAlt(2, off); }
    }

    if (g_offBaseDllName >= 0) {
        for (int i = 0; i < g_modCount; ++i) {
            uint16_t len; const uint8_t* buf;
            RdU16(g_mods[i].entry + g_offBaseDllName, &len);
            RdPtr(g_mods[i].entry + g_offBaseDllName + kPtr, &buf);
            if (len > (uint16_t)(sizeof(g_mods[i].name) - 2)) len = (uint16_t)(sizeof(g_mods[i].name) - 2);
            memcpy(g_mods[i].name, buf, len);
            g_mods[i].name[len / 2] = 0;
            g_mods[i].nameBytes = len;
        }
    }

    for (int i = 0; i < g_modCount; ++i) g_baseOrder[i] = i;
    qsort(g_baseOrder, g_modCount, sizeof(int), CmpByBase);
    return g_offSizeOfImage >= 0 && g_offBaseDllName >= 0;
}

// ========================================================== LdrpHashTable ===

typedef LONG(NTAPI* PFN_HASHUS)(const void*, BOOLEAN, ULONG, PULONG);
typedef WCHAR(NTAPI* PFN_UPCASE)(WCHAR);
static PFN_HASHUS g_hashUs;
static PFN_UPCASE g_upcase;

struct UStr { USHORT Length, MaximumLength; PWSTR Buffer; };

enum HashAlgo { HA_DEFAULT = 0, HA_WIN7, HA_VISTA, HA_XP, HA_COUNT };
static const char* kAlgoName[HA_COUNT] = {
    "RtlHashUnicodeString(DEFAULT)", "Win7 sum(0x1003F*upcase)",
    "Vista upcase(first)-1", "XP upcase(first)-'A'"
};

static bool ComputeHash(const wchar_t* buf, uint16_t lenBytes, HashAlgo a, ULONG* out) {
    switch (a) {
    case HA_DEFAULT: {
        UStr us; us.Length = lenBytes; us.MaximumLength = lenBytes; us.Buffer = (PWSTR)buf;
        ULONG h = 0;
        if (g_hashUs(&us, TRUE, 0, &h) < 0) return false;
        *out = h; return true;
    }
    case HA_WIN7: {
        ULONG r = 0;
        for (int i = 0; i < lenBytes / 2; ++i) r += 0x1003F * (ULONG)g_upcase(buf[i]);
        *out = r; return true;
    }
    case HA_VISTA: *out = (ULONG)g_upcase(buf[0]) - 1; return true;
    case HA_XP:    *out = (ULONG)g_upcase(buf[0]) - L'A'; return true;
    default: return false;
    }
}

// results
static const uint8_t* g_hashTable = nullptr;
static int            g_hashBuckets = 0;
static HashAlgo       g_hashAlgo = HA_DEFAULT;
static int            g_hashAnchors = 0;         // modules that voted for it
static int            g_hashAnchorsTotal = 0;
static const uint8_t* g_hashTableScan = nullptr; // independent scan result
static int            g_hashScanHits = 0;
static bool           g_hashValidated = false;
static int            g_hashMembers = 0, g_hashBadHash = 0, g_hashUnknownNode = 0;
static int            g_hashMissingMods = 0, g_hashDupMods = 0;
static int            g_hashCandidateOffsets = 0;
static int            g_hashBucketUse[256];

//
// Walk the ring that (entry+off) belongs to and return the one node that is not
// a loader entry at the same offset -- the bucket head. Anything else about the
// ring's shape being wrong returns false, which is how the wrong offsets get
// rejected.
//
static bool RingHead(const uint8_t* member, int off, const uint8_t** headOut, int* ringLen) {
    const uint8_t *flink, *blink;
    if (!RdPtr(member, &flink) || !RdPtr(member + kPtr, &blink)) return false;
    if (!flink || !blink) return false;
    const uint8_t* back;
    if (!RdPtr(flink + kPtr, &back) || back != member) return false;   // Flink->Blink == self
    if (!RdPtr(blink, &back) || back != member) return false;          // Blink->Flink == self

    const uint8_t* head = nullptr;
    int n = 0, guard = 0;
    const uint8_t* cur = flink;
    while (cur != member) {
        if (FindModByEntry(cur - off) < 0) {
            if (head) return false;                                    // two non-member nodes
            head = cur;
        }
        else ++n;
        if (!RdPtr(cur, &cur)) return false;
        if (++guard > 4096) return false;
    }
    if (!head) return false;                                           // no external head
    *headOut = head;
    *ringLen = n;
    return true;
}

static bool InNtdll(const void* p) {
    return (const uint8_t*)p >= g_ntBase && (const uint8_t*)p < g_ntBase + g_ntSize;
}

//
// Method 1: derive the table from every module independently and require them
// to agree. Searches the HashLinks offset, the bucket count and the hash
// algorithm rather than assuming any of the three.
//
static void DeriveHashTable() {
    const uint8_t* heads[MAX_MODS];
    int bestVotes = 0;

    for (int off = 0; off <= 0x220; off += (int)kPtr) {
        bool ok = true;
        for (int i = 0; i < g_modCount; ++i) {
            int len;
            if (!RingHead(g_mods[i].entry + off, off, &heads[i], &len)) { ok = false; break; }
            if (!InNtdll(heads[i])) { ok = false; break; }
            if (heads[i] == g_listHeads[0] || heads[i] == g_listHeads[1] ||
                heads[i] == g_listHeads[2]) { ok = false; break; }
        }
        if (!ok) continue;
        ++g_hashCandidateOffsets;

        for (int nb = 8; nb <= 256; nb <<= 1) {
            for (int a = 0; a < HA_COUNT; ++a) {
                const uint8_t* base = nullptr;
                int votes = 0, total = 0;
                bool consistent = true;
                for (int i = 0; i < g_modCount; ++i) {
                    ULONG h;
                    if (!g_mods[i].nameBytes ||
                        !ComputeHash(g_mods[i].name, g_mods[i].nameBytes, (HashAlgo)a, &h)) continue;
                    ++total;
                    const uint8_t* b = heads[i] - (size_t)(h & (nb - 1)) * kLinkSize;
                    if (!base) { base = b; votes = 1; }
                    else if (base == b) ++votes;
                    else { consistent = false; break; }
                }
                if (!consistent || !base || votes < 3) continue;
                if (votes > bestVotes) {
                    bestVotes = votes;
                    g_hashTable = base;
                    g_hashBuckets = nb;
                    g_hashAlgo = (HashAlgo)a;
                    g_hashAnchors = votes;
                    g_hashAnchorsTotal = total;
                    g_offHashLinks = off;
                }
            }
        }
    }
}

//
// Method 2, independent of the hash entirely: an array of N LIST_ENTRYs where
// every element is a well-formed ring head and every node hanging off it is a
// loader entry at the derived HashLinks offset. Corroborates method 1 without
// sharing its assumptions.
//
static void ScanForHashTable(int off, int buckets) {
    g_hashScanHits = 0;
    if (off < 0 || buckets <= 0) return;

    for (int s = 0; s < g_secCount; ++s) {
        if (!IsScannableSection(g_secs[s])) continue;
        const uint8_t* lo = g_ntBase + g_secs[s].rva;
        const uint8_t* hi = lo + g_secs[s].size;
        if (!Readable(lo, 1)) continue;

        for (const uint8_t* p = lo; p + (size_t)buckets * kLinkSize <= hi; p += kPtr) {
            int nonEmpty = 0, members = 0;
            bool ok = true;
            for (int i = 0; i < buckets && ok; ++i) {
                const uint8_t* h = p + (size_t)i * kLinkSize;
                const uint8_t *f, *b, *t;
                if (!RdPtr(h, &f) || !RdPtr(h + kPtr, &b)) { ok = false; break; }
                if (!f || !b) { ok = false; break; }
                if (!RdPtr(f + kPtr, &t) || t != h) { ok = false; break; }
                if (!RdPtr(b, &t) || t != h) { ok = false; break; }
                if (f == h) continue;                       // empty bucket
                ++nonEmpty;
                const uint8_t* cur = f;
                int guard = 0;
                while (cur != h) {
                    if (FindModByEntry(cur - off) < 0) { ok = false; break; }
                    ++members;
                    if (!RdPtr(cur, &cur)) { ok = false; break; }
                    if (++guard > 4096) { ok = false; break; }
                }
            }
            //
            // Accept only when the array accounts for every loaded module. That
            // is independent of how many modules there are, unlike a fixed
            // "at least N non-empty buckets" floor.
            //
            if (ok && members == g_modCount && nonEmpty >= 2) {
                if (!g_hashScanHits) g_hashTableScan = p;
                ++g_hashScanHits;
            }
        }
    }
}

//
// Proof: every member of every bucket re-hashes to the bucket it is in, every
// node is a real loader entry, and every loaded module appears exactly once.
// The last of those is a check the library does not currently make.
//
static void ValidateHashTable() {
    if (!g_hashTable || g_offHashLinks < 0) return;
    int seen[MAX_MODS] = { 0 };
    bool ok = true;

    for (int i = 0; i < g_hashBuckets && i < 256; ++i) {
        const uint8_t* head = g_hashTable + (size_t)i * kLinkSize;
        const uint8_t *f, *b, *t;
        if (!RdPtr(head, &f) || !RdPtr(head + kPtr, &b) || !f || !b) { ok = false; break; }
        if (!RdPtr(f + kPtr, &t) || t != head) { ok = false; break; }
        if (!RdPtr(b, &t) || t != head) { ok = false; break; }

        int used = 0;
        const uint8_t* cur = f;
        int guard = 0;
        while (cur != head) {
            int m = FindModByEntry(cur - g_offHashLinks);
            if (m < 0) { ++g_hashUnknownNode; ok = false; break; }
            ULONG h;
            if (!ComputeHash(g_mods[m].name, g_mods[m].nameBytes, g_hashAlgo, &h) ||
                (int)(h & (g_hashBuckets - 1)) != i) { ++g_hashBadHash; ok = false; }
            ++seen[m];
            ++g_hashMembers;
            ++used;
            if (!RdPtr(cur, &cur)) { ok = false; break; }
            if (++guard > 4096) { ok = false; break; }
        }
        g_hashBucketUse[i] = used;
    }

    for (int i = 0; i < g_modCount; ++i) {
        if (seen[i] == 0) ++g_hashMissingMods;
        else if (seen[i] > 1) ++g_hashDupMods;
    }
    g_hashValidated = ok && g_hashBadHash == 0 && g_hashUnknownNode == 0 &&
                      g_hashMissingMods == 0 && g_hashDupMods == 0;
}

// =============================================== LdrpInvertedFunctionTable ===

struct Hit { const uint8_t* addr; int mod; };
static Hit  g_hits[8192];
static int  g_hitCount = 0;

static int CmpHit(const void* a, const void* b) {
    const uint8_t* x = ((const Hit*)a)->addr;
    const uint8_t* y = ((const Hit*)b)->addr;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static int HitAt(const uint8_t* addr) {
    int lo = 0, hi = g_hitCount;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (g_hits[mid].addr == addr) return mid;
        if (g_hits[mid].addr < addr) lo = mid + 1; else hi = mid;
    }
    return -1;
}

// discovered layout
static const uint8_t* g_ift = nullptr;          // table base (the Count field)
static int   g_iftHeaderSize = -1;
static int   g_iftStride = -1;
static int   g_iftOffImageBase = -1;
static int   g_iftOffImageSize = -1;
static int   g_iftOffExcDir = -1;
static int   g_iftOffExcDirSize = -1;
static uint32_t g_iftCount = 0, g_iftMaxCount = 0, g_iftEpoch = 0, g_iftOverflow = 0;
static int   g_iftRunLen = 0;
static const uint8_t* g_iftClassic = nullptr;   // classic-layout scan result
static const uint8_t* g_iftClassicAll[8];
static uint32_t g_iftClassicCnt[8], g_iftClassicMx[8];
static int   g_iftClassicHits = 0;
static uint32_t g_iftClassicMax = 0;
static int   g_iftMatched = 0, g_iftBadOrder = 0, g_iftUnknownBase = 0, g_iftBadSize = 0;
static int   g_iftEdMatched = 0, g_iftEdChecked = 0;
static int   g_iftModsMissing = 0;
static bool  g_iftValidated = false;
static bool  g_iftEntry0IsNtdll = false;

//
// Every place in ntdll's data where a loaded module's base address is stored.
// Most are unrelated cached handles; the inverted table's ImageBase column is
// the one that forms a long arithmetic progression with ascending bases.
//
static void CollectBaseHits() {
    g_hitCount = 0;
    for (int s = 0; s < g_secCount && g_hitCount < 8192; ++s) {
        if (!IsScannableSection(g_secs[s])) continue;
        const uint8_t* lo = g_ntBase + g_secs[s].rva;
        const uint8_t* hi = lo + g_secs[s].size;
        if (!Readable(lo, 1)) continue;
        __try {
            for (const uint8_t* p = lo; p + kPtr <= hi && g_hitCount < 8192; p += kPtr) {
                const uint8_t* v = *(const uint8_t* const*)p;
                if (!v) continue;
                int m = FindModByBase(v);
                if (m < 0) continue;
                g_hits[g_hitCount].addr = p;
                g_hits[g_hitCount].mod = m;
                ++g_hitCount;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    qsort(g_hits, g_hitCount, sizeof(Hit), CmpHit);
}

static void FindBaseColumn(const uint8_t** startOut, int* strideOut, int* lenOut) {
    int bestLen = 0, bestStride = 0;
    const uint8_t* bestStart = nullptr;

    for (int i = 0; i < g_hitCount; ++i) {
        for (int j = i + 1; j < g_hitCount && j <= i + 8; ++j) {
            ptrdiff_t s = g_hits[j].addr - g_hits[i].addr;
            if (s < (ptrdiff_t)kPtr || s > 256 || (s % (ptrdiff_t)kPtr)) continue;

            int len = 1;
            const uint8_t* cur = g_hits[i].addr;
            const uint8_t* lastBase = g_mods[g_hits[i].mod].base;
            for (;;) {
                int k = HitAt(cur + s);
                if (k < 0) break;
                if (g_mods[g_hits[k].mod].base <= lastBase) break;   // must ascend
                lastBase = g_mods[g_hits[k].mod].base;
                cur += s;
                ++len;
            }
            if (len > bestLen) { bestLen = len; bestStride = (int)s; bestStart = g_hits[i].addr; }
        }
    }
    *startOut = bestStart; *strideOut = bestStride; *lenOut = bestLen;
}

static const uint8_t* g_runStart = nullptr;
static int g_runStride = 0, g_runLenRaw = 0;

//
// With the column located, the remaining field offsets are measurements: the
// delta at which every entry in the run holds its own module's SizeOfImage is
// the ImageSize field, and so on. Nothing about the struct is assumed.
//
static int ModAtColumn(const uint8_t* col0, int stride, int i) {
    int k = HitAt(col0 + (ptrdiff_t)i * stride);
    return k < 0 ? -1 : g_hits[k].mod;
}

static int FindFieldDelta32(const uint8_t* col0, int stride, int len, bool wantSize) {
    for (int d = -stride + 4; d <= stride - 4; d += 4) {
        bool ok = true;
        for (int i = 0; i < len && ok; ++i) {
            int m = ModAtColumn(col0, stride, i);
            uint32_t v;
            if (m < 0 || !RdU32(col0 + (ptrdiff_t)i * stride + d, &v)) { ok = false; break; }
            uint32_t want = wantSize ? g_mods[m].sizeOfImage : g_mods[m].pdataSize;
            if (v != want) ok = false;
        }
        if (ok) return d;
    }
    return INT32_MIN;
}

//
// ExceptionDirectory is the one field that can legitimately fail to match: on
// ARM64X an x64 caller reads the hybrid view's data directories while ntdll
// stored the native view's. So this is a majority test over the entries that
// have a .pdata at all, and the count is reported rather than swallowed.
//
static int FindFieldDeltaPtr(const uint8_t* col0, int stride, int len,
                             int* matchedOut, int* checkedOut) {
    int havePdata = 0;
    for (int i = 0; i < len; ++i) {
        int m = ModAtColumn(col0, stride, i);
        if (m >= 0 && g_mods[m].pdata) ++havePdata;
    }
    *checkedOut = havePdata;

    int bestD = INT32_MIN, bestN = 0;
    for (int d = -stride + (int)kPtr; d <= stride - (int)kPtr; d += (int)kPtr) {
        if (d == 0) continue;
        int n = 0;
        for (int i = 0; i < len; ++i) {
            int m = ModAtColumn(col0, stride, i);
            const uint8_t* v;
            if (m < 0 || !RdPtr(col0 + (ptrdiff_t)i * stride + d, &v)) break;
            if (g_mods[m].pdata && v == g_mods[m].pdata) ++n;
        }
        if (n > bestN) { bestN = n; bestD = d; }
    }
    *matchedOut = bestN;
    return (havePdata && bestN * 2 >= havePdata) ? bestD : INT32_MIN;
}

//
// How many of `count` entries starting at `entries` name a currently loaded
// module and carry that module's SizeOfImage. Used to settle where the array
// really begins; also the core of the validation below.
//
static int ScoreEntryArray(const uint8_t* entries, uint32_t count) {
    int score = 0;
    for (uint32_t i = 0; i < count && i < 0x10000; ++i) {
        const uint8_t* e = entries + (size_t)i * g_iftStride;
        const uint8_t* ib;
        if (!RdPtr(e + g_iftOffImageBase, &ib)) break;
        int m = FindModByBase(ib);
        if (m < 0) continue;
        if (g_iftOffImageSize >= 0) {
            uint32_t sz;
            if (!RdU32(e + g_iftOffImageSize, &sz) || sz != g_mods[m].sizeOfImage) continue;
        }
        ++score;
    }
    return score;
}

static void DeriveInvertedTable() {
    const uint8_t* col0 = nullptr;
    int stride = 0, len = 0;
    FindBaseColumn(&col0, &stride, &len);
    g_runStart = col0; g_runStride = stride; g_runLenRaw = len;
    if (!col0 || len < 3) return;

    g_iftStride = stride;
    g_iftRunLen = len;

    int dSize = FindFieldDelta32(col0, stride, len, true);
    int dEdSize = FindFieldDelta32(col0, stride, len, false);
    int edMatched = 0, edChecked = 0;
    int dEd = FindFieldDeltaPtr(col0, stride, len, &edMatched, &edChecked);
    g_iftEdMatched = edMatched;
    g_iftEdChecked = edChecked;

    // entry start is the lowest field delta seen (0 for ImageBase itself)
    int lowest = 0;
    if (dSize != INT32_MIN && dSize < lowest) lowest = dSize;
    if (dEdSize != INT32_MIN && dEdSize < lowest) lowest = dEdSize;
    if (dEd != INT32_MIN && dEd < lowest) lowest = dEd;

    const uint8_t* entry0 = col0 + lowest;
    g_iftOffImageBase = -lowest;
    g_iftOffImageSize = (dSize == INT32_MIN) ? -1 : dSize - lowest;
    g_iftOffExcDirSize = (dEdSize == INT32_MIN) ? -1 : dEdSize - lowest;
    g_iftOffExcDir = (dEd == INT32_MIN) ? -1 : dEd - lowest;

    //
    // Header: walk back from the run's first element to the first (Count,
    // MaxCount) pair where Count is about the number of entries present.
    // MaxCount arrives as a measurement rather than the hardcoded 0x200.
    //
    // The run does not necessarily start at entry[0]. Since Windows 8, ntdll
    // pins its own entry at index 0 and sorts from index 1 (the library's own
    // RtlpInsertInvertedFunctionTable starts Index at 1 for exactly this
    // reason), so the ascending-order run begins at entry[1] whenever ntdll is
    // not the lowest-based image -- which, with ASLR, is most of the time.
    // Hence the refinement below: once the header pins the table, pull the array
    // start back by whole entries for as long as that scores better.
    //
    for (int h = 4; h <= 160; h += 4) {
        const uint8_t* base = entry0 - h;
        if ((uintptr_t)base & 3) continue;
        if (!InNtdll(base)) break;
        uint32_t count, maxCount;
        if (!RdU32(base, &count) || !RdU32(base + 4, &maxCount)) break;
        if (maxCount < 8 || maxCount > 0x100000) continue;
        if (count > maxCount) continue;
        if ((int)count < len || (int)count > len + 8) continue;

        //
        // Ties go to the smaller header, i.e. the earlier array start. The
        // array keeps stale entries past Count -- removal shifts the live ones
        // down without clearing the tail -- so a window shifted one entry late
        // can score just as well as the true one. Shifting *early* instead reads
        // header bytes as an entry and always loses a point, so preferring the
        // smaller header cannot overshoot.
        //
        int bestH = h, bestScore = -1;
        for (int k = 0; k <= 4; ++k) {
            int hh = h - k * stride;
            if (hh < 8) break;
            int score = ScoreEntryArray(base + hh, count);
            if (score > bestScore || (score == bestScore && hh < bestH)) {
                bestScore = score; bestH = hh;
            }
        }

        g_ift = base;
        g_iftHeaderSize = bestH;
        g_iftCount = count;
        g_iftMaxCount = maxCount;
        RdU32(base + 8, &g_iftEpoch);
        RdU32(base + 12, &g_iftOverflow);
        break;
    }
}

//
// The classic layout, scanned for independently: header {Count, MaxCount, Epoch,
// Overflow} then entries at +0x10 with stride sizeof(void*)*2+8. This is exactly
// what MemoryModule/Initialize.cpp assumes, so agreement between this and the
// derivation above is the evidence the assumption still holds -- and a
// disagreement is the warning that it does not.
//
static void ScanClassicInvertedTable() {
    const int kHdr = 0x10;
#ifdef _WIN64
    const int kEnt = 0x18;
    const int kOffBase = 8, kOffSize = 0x10;
#else
    const int kEnt = 0x10;
    const int kOffBase = 0, kOffSize = 4;
#endif
    g_iftClassicHits = 0;

    for (int s = 0; s < g_secCount; ++s) {
        if (!IsScannableSection(g_secs[s])) continue;
        const uint8_t* lo = g_ntBase + g_secs[s].rva;
        const uint8_t* hi = lo + g_secs[s].size;
        if (!Readable(lo, 1)) continue;

        for (const uint8_t* p = lo; p + kHdr + 8 * kEnt <= hi; p += 4) {
            uint32_t count, maxCount, overflow;
            if (!RdU32(p, &count) || !RdU32(p + 4, &maxCount) || !RdU32(p + 12, &overflow)) continue;
            if (count < 4 || count > maxCount) continue;
            if (maxCount < 0x20 || maxCount > 0x10000) continue;
            if (maxCount & (maxCount - 1)) continue;              // power of two
            if (overflow > 1) continue;

            int check = (int)count < 8 ? (int)count : 8;
            bool ok = true;
            const uint8_t* prev = nullptr;
            for (int i = 0; i < check && ok; ++i) {
                const uint8_t* e = p + kHdr + (ptrdiff_t)i * kEnt;
                const uint8_t* ib;
                uint32_t isz;
                if (!RdPtr(e + kOffBase, &ib) || !RdU32(e + kOffSize, &isz)) { ok = false; break; }
                int m = FindModByBase(ib);
                if (m < 0 || g_mods[m].sizeOfImage != isz) { ok = false; break; }
                // Index 0 is ntdll's pinned slot and is exempt from the sort.
                if (i >= 1) {
                    if (prev && ib <= prev) { ok = false; break; }
                    prev = ib;
                }
            }
            if (!ok) continue;
            if (!g_iftClassicHits) { g_iftClassic = p; g_iftClassicMax = maxCount; }
            if (g_iftClassicHits < 8) {
                g_iftClassicAll[g_iftClassicHits] = p;
                g_iftClassicCnt[g_iftClassicHits] = count;
                g_iftClassicMx[g_iftClassicHits] = maxCount;
            }
            ++g_iftClassicHits;
        }
    }
}

//
// ARM64X ntdll keeps *two* inverted function tables back to back in .mrdata: one
// holding x64 .pdata pointers and one holding native ARM64 ones. Both are
// maintained on every load, both pass a structural check, and they differ only
// in which images the architecture has unwind data for. Picking whichever sorts
// first, or whichever happens to have more entries, is a coin flip.
//
// The criterion that actually decides it: the table for this architecture is the
// one whose ExceptionDirectory column reproduces the .pdata pointers this
// process's view of each image reports. That is a measurement, and it is also
// the table our own unwind info would have to go into.
//
static int g_iftChosenBy = 0;         // 0 = single candidate, 1 = .pdata view match

static void ScoreCandidate(const uint8_t* base, int* edOk, int* edTot, int* matched) {
    *edOk = *edTot = *matched = 0;
    uint32_t count = 0;
    if (!RdU32(base, &count) || !count || count > 0x10000) return;
    int stride = g_iftStride > 0 ? g_iftStride : (int)(kPtr * 2 + 8);
    int offB = g_iftOffImageBase >= 0 ? g_iftOffImageBase : (int)kPtr;
    int offE = g_iftOffExcDir >= 0 ? g_iftOffExcDir : 0;
    int hdr = g_iftHeaderSize > 0 ? g_iftHeaderSize : 0x10;

    for (uint32_t k = 0; k < count && k < 2048; ++k) {
        const uint8_t* e = base + hdr + (size_t)k * stride;
        const uint8_t *ib, *ed;
        if (!RdPtr(e + offB, &ib)) break;
        int m = FindModByBase(ib);
        if (m < 0) continue;
        ++*matched;
        if (!g_mods[m].pdata) continue;
        ++*edTot;
        if (RdPtr(e + offE, &ed) && ed == g_mods[m].pdata) ++*edOk;
    }
}

static void ChooseInvertedTable() {
    if (g_iftClassicHits < 2) return;
    const uint8_t* best = g_ift;
    int bestOk = -1, bestTot = 1, bestMatch = -1;
    if (g_ift) ScoreCandidate(g_ift, &bestOk, &bestTot, &bestMatch);

    for (int i = 0; i < g_iftClassicHits && i < 8; ++i) {
        if (g_iftClassicAll[i] == g_ift) continue;
        int ok, tot, match;
        ScoreCandidate(g_iftClassicAll[i], &ok, &tot, &match);
        bool better = (tot && bestTot && ok * bestTot > bestOk * tot) ||
                      (ok == bestOk && match > bestMatch);
        if (better) { best = g_iftClassicAll[i]; bestOk = ok; bestTot = tot; bestMatch = match; }
    }
    if (best && best != g_ift) {
        g_ift = best;
        RdU32(g_ift, &g_iftCount);
        RdU32(g_ift + 4, &g_iftMaxCount);
        RdU32(g_ift + 8, &g_iftEpoch);
        RdU32(g_ift + 12, &g_iftOverflow);
    }
    g_iftChosenBy = 1;
}

//
// The analogue of the hash table's re-hash test: every entry has to be
// reproducible from the PE headers of the module it names. Recomputing
// ExceptionDirectory and its size from the image is a check the library never
// makes, and it is what turns "a pointer to ntdll sits here" into proof.
//
static void ValidateInvertedTable() {
    if (!g_ift || g_iftStride <= 0 || g_iftOffImageBase < 0) return;
    const uint8_t* entries = g_ift + g_iftHeaderSize;
    const uint8_t* prev = nullptr;
    bool inTable[MAX_MODS] = { false };

    g_iftMatched = g_iftBadOrder = g_iftUnknownBase = g_iftBadSize = 0;
    int edOk = 0, edSeen = 0;

    for (uint32_t i = 0; i < g_iftCount && i < 0x10000; ++i) {
        const uint8_t* e = entries + (size_t)i * g_iftStride;
        const uint8_t* ib;
        if (!RdPtr(e + g_iftOffImageBase, &ib)) { ++g_iftUnknownBase; continue; }
        int m = FindModByBase(ib);
        if (m < 0) { ++g_iftUnknownBase; continue; }
        inTable[m] = true;
        if (i == 0) g_iftEntry0IsNtdll = (ib == g_ntBase);

        // Index 0 is ntdll's pinned slot; the sort invariant starts at index 1.
        if (i >= 1) {
            if (prev && ib <= prev) ++g_iftBadOrder;
            prev = ib;
        }

        if (g_iftOffImageSize >= 0) {
            uint32_t sz;
            if (!RdU32(e + g_iftOffImageSize, &sz) || sz != g_mods[m].sizeOfImage) ++g_iftBadSize;
        }
        if (g_iftOffExcDir >= 0 && g_mods[m].pdata) {
            const uint8_t* ed;
            ++edSeen;
            if (RdPtr(e + g_iftOffExcDir, &ed) && ed == g_mods[m].pdata) ++edOk;
        }
        ++g_iftMatched;
    }

    g_iftEdMatched = edOk;
    g_iftEdChecked = edSeen;

    g_iftModsMissing = 0;
    for (int i = 0; i < g_modCount; ++i) if (!inTable[i]) ++g_iftModsMissing;

    //
    // Three is the floor, not a confidence threshold: a bare statically linked
    // process has four modules, and requiring more would fail a correct answer.
    // The confidence comes from every entry matching, not from how many there
    // are -- which is also why the tool preloads a dozen DLLs by default.
    //
    g_iftValidated = (g_iftMatched == (int)g_iftCount) && g_iftBadOrder == 0 &&
                     g_iftUnknownBase == 0 && g_iftBadSize == 0 && g_iftCount >= 3;
}

// ------------------------------------------------------ behavioural check ---

struct IftSnap { uint32_t count, overflow; const uint8_t* bases[2048]; int n; };

static void SnapIft(IftSnap* s) {
    s->n = 0; s->count = 0; s->overflow = 0;
    if (!g_ift) return;
    LockShared();
    __try {
        RdU32(g_ift, &s->count);
        RdU32(g_ift + 12, &s->overflow);
        const uint8_t* entries = g_ift + g_iftHeaderSize;
        for (uint32_t i = 0; i < s->count && i < 2048; ++i) {
            const uint8_t* ib;
            if (!RdPtr(entries + (size_t)i * g_iftStride + g_iftOffImageBase, &ib)) break;
            s->bases[s->n++] = ib;
        }
    }
    __finally { UnlockShared(); }
}

static bool SnapHas(const IftSnap* s, const uint8_t* b) {
    for (int i = 0; i < s->n; ++i) if (s->bases[i] == b) return true;
    return false;
}

static const wchar_t* kProbeDlls[] = {
    L"winmm.dll", L"imagehlp.dll", L"mpr.dll", L"avrt.dll",
    L"netapi32.dll", L"cabinet.dll", L"wintrust.dll", L"userenv.dll",
};

static bool  g_behaveRan = false, g_behaveOk = false;
static const wchar_t* g_behaveDll = nullptr;
static uint32_t g_behaveBefore = 0, g_behaveAfter = 0, g_behaveEnd = 0;
static bool  g_behaveAppeared = false, g_behaveDisappeared = false, g_behaveUnloaded = false;

//
// ARM64X ntdll turns out to carry two of these back to back in .mrdata, so the
// Count of every candidate is sampled at each step. Which ones move under a load
// is the only way to say which table the running architecture actually consults.
//
static uint32_t g_candCount[3][8];
static bool     g_candHas[3][8];

static void SampleCandidates(int phase, const uint8_t* probeBase) {
    for (int i = 0; i < g_iftClassicHits && i < 8; ++i) {
        uint32_t c = 0;
        RdU32(g_iftClassicAll[i], &c);
        g_candCount[phase][i] = c;
        g_candHas[phase][i] = false;
        if (!probeBase) continue;
        for (uint32_t k = 0; k < c && k < 2048; ++k) {
            const uint8_t* ib;
            if (!RdPtr(g_iftClassicAll[i] + 0x10 + (size_t)k * (kPtr * 2 + 8) + kPtr, &ib)) break;
            if (ib == probeBase) { g_candHas[phase][i] = true; break; }
        }
    }
}

static void BehaviouralCheck() {
    if (!g_ift || !g_iftValidated) return;

    SampleCandidates(0, nullptr);

    HMODULE h = nullptr;
    for (size_t i = 0; i < sizeof(kProbeDlls) / sizeof(kProbeDlls[0]); ++i) {
        if (GetModuleHandleW(kProbeDlls[i])) continue;
        h = LoadLibraryW(kProbeDlls[i]);
        if (h) { g_behaveDll = kProbeDlls[i]; break; }
    }
    if (!h) return;
    g_behaveRan = true;

    IftSnap after; SnapIft(&after);
    g_behaveAfter = after.count;
    g_behaveAppeared = SnapHas(&after, (const uint8_t*)h);
    SampleCandidates(1, (const uint8_t*)h);

    FreeLibrary(h);
    g_behaveUnloaded = GetModuleHandleW(g_behaveDll) == nullptr;

    IftSnap end; SnapIft(&end);
    g_behaveEnd = end.count;
    g_behaveDisappeared = !SnapHas(&end, (const uint8_t*)h);
    SampleCandidates(2, (const uint8_t*)h);

    g_behaveOk = g_behaveAppeared &&
                 g_behaveAfter > g_behaveBefore &&
                 (!g_behaveUnloaded || (g_behaveDisappeared && g_behaveEnd < g_behaveAfter));
}

// ==================================================================== main ==

static void PrintIdentity(HMODULE nt) {
    printf("==================== probe_ift report ====================\n");
#if defined(_M_ARM64)
    printf("built for       : arm64\n");
#elif defined(_M_X64)
    printf("built for       : x64\n");
#else
    printf("built for       : x86\n");
#endif
    printf("ntdll base      : %p\n", (void*)nt);
    printf("ntdll machine   : 0x%04X  (0x8664=x64, 0xAA64=ARM64)\n", g_ntHdr->FileHeader.Machine);
    printf("ntdll timestamp : 0x%08lX   (opaque build id, not a date)\n",
        (unsigned long)g_ntHdr->FileHeader.TimeDateStamp);
    printf("ntdll SizeOfImg : 0x%08lX\n", (unsigned long)g_ntHdr->OptionalHeader.SizeOfImage);
    printf("ntdll sections  : ");
    for (int i = 0; i < g_secCount; ++i)
        printf("%s%s", g_secs[i].name, i + 1 < g_secCount ? " " : "\n");
}

static void ReportOffset(const char* what, int got, int libAssumes) {
    if (got < 0) { printf("  %-14s: NOT DERIVED (library assumes +0x%X)\n", what, libAssumes); return; }
    printf("  %-14s: +0x%-4X  library assumes +0x%-4X  %s\n", what, got, libAssumes,
        got == libAssumes ? "agree" : "*** DIFFERS ***");
}

//
// A statically linked probe loads four DLLs, which is too thin a sample to say
// much: the ImageBase-column derivation wants a long arithmetic progression and
// the bucket vote wants many voters. Pulling in a dozen ordinary system DLLs
// costs nothing and multiplies the evidence. Nothing here is required for
// correctness -- --no-preload runs against the bare process.
//
static const wchar_t* kPreload[] = {
    L"advapi32.dll", L"user32.dll", L"gdi32.dll", L"ole32.dll", L"oleaut32.dll",
    L"shlwapi.dll", L"shell32.dll", L"ws2_32.dll", L"crypt32.dll", L"bcrypt.dll",
    L"psapi.dll", L"secur32.dll", L"iphlpapi.dll", L"dbghelp.dll", L"setupapi.dll",
};
static int g_preloaded = 0;

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--verbose")) g_verbose = true;
        else if (!strcmp(argv[i], "--dump")) g_dump = true;
        else if (!strcmp(argv[i], "--fast")) g_fast = true;
        else if (!strcmp(argv[i], "--hits")) g_showHits = true;
        else if (!strcmp(argv[i], "--no-preload")) g_noPreload = true;
    }

    if (!g_noPreload)
        for (size_t i = 0; i < sizeof(kPreload) / sizeof(kPreload[0]); ++i)
            if (LoadLibraryW(kPreload[i])) ++g_preloaded;

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) { printf("no ntdll\n"); return 2; }
    InitSections(nt);
    InitFunctionTable();

    g_acqExcl = (PFN_SRW)GetProcAddress(nt, "RtlAcquireSRWLockExclusive");
    g_acqShared = (PFN_SRW)GetProcAddress(nt, "RtlAcquireSRWLockShared");
    g_relExcl = (PFN_SRW)GetProcAddress(nt, "RtlReleaseSRWLockExclusive");
    g_relShared = (PFN_SRW)GetProcAddress(nt, "RtlReleaseSRWLockShared");
    g_hashUs = (PFN_HASHUS)GetProcAddress(nt, "RtlHashUnicodeString");
    g_upcase = (PFN_UPCASE)GetProcAddress(nt, "RtlUpcaseUnicodeChar");
    if (!g_acqExcl || !g_acqShared || !g_relExcl || !g_relShared || !g_hashUs || !g_upcase) {
        printf("could not resolve the exported ntdll routines this needs\n");
        return 2;
    }

    PrintIdentity(nt);

    g_acqTargets[g_acqTargetCount++] = (void*)g_acqExcl;
    g_acqTargets[g_acqTargetCount++] = (void*)g_acqShared;
    void* t = nullptr;
    if (IsEcFastForward((void*)g_acqExcl, &t))   g_acqTargets[g_acqTargetCount++] = t;
    if (IsEcFastForward((void*)g_acqShared, &t)) g_acqTargets[g_acqTargetCount++] = t;

    // ---------------------------------------------------------------- lock
    printf("\n--- ntdll!LdrpModuleDatatableLock (needed to walk the database) ---\n");
    LocateLock(nt);
    printf("donors decoded  : %d of %d\n", g_lockDecoded, (int)(sizeof(kDonors) / sizeof(kDonors[0])));
    printf("agreeing        : %d (need 2)\n", g_lockAgree);
    if (g_lock) {
        printf("lock            : %p  (ntdll+0x%llX, section %s)\n", g_lock,
            (unsigned long long)((const uint8_t*)g_lock - g_ntBase), SectionOf(g_lock));
        if (!g_fast) {
            g_lockVerified = VerifyLockByCausality(g_lock);
            printf("causality       : %s\n", g_lockVerified ? "VERIFIED" : "FAILED -- not using it");
            if (!g_lockVerified) g_lock = nullptr;
        }
        else printf("causality       : skipped (--fast)\n");
    }
    else {
        printf("lock            : NOT LOCATED -- the loader walk below is UNSYNCHRONISED\n");
    }

    // ----------------------------------------------- everything under the lock
    const uint8_t* exeBase = nullptr;
    bool snapOk = false, offOk = false;

    LockShared();
    __try {
        snapOk = SnapshotModules();
        if (snapOk) {
            RdPtr(g_peb + PEB_IMAGEBASE_OFFSET, &exeBase);
            offOk = DeriveEntryOffsets(exeBase);
        }
        if (offOk) {
            DeriveHashTable();
            ValidateHashTable();
            ScanForHashTable(g_offHashLinks, g_hashBuckets ? g_hashBuckets : 32);

            CollectBaseHits();
            DeriveInvertedTable();
            ScanClassicInvertedTable();
            ChooseInvertedTable();
            ValidateInvertedTable();
        }
    }
    __finally { UnlockShared(); }

    printf("\n--- loader snapshot ---\n");
    if (!snapOk) { printf("could not walk PEB->Ldr\n"); return 2; }
    printf("modules         : %d  (walked %s, %d preloaded for sample size)\n", g_modCount,
        g_lock ? "holding LdrpModuleDatatableLock shared" : "WITHOUT the lock", g_preloaded);
    printf("PEB             : %p   Ldr: %p\n", (void*)g_peb, (void*)g_ldrData);
    printf("EXE image base  : %p  (matches first list entry's DllBase: %s)\n",
        (void*)exeBase, (g_modCount && g_mods[0].base == exeBase) ? "yes" : "NO");
    printf("derived LDR_DATA_TABLE_ENTRY offsets:\n");
#ifdef _WIN64
    ReportOffset("DllBase", g_offDllBase, 0x30);
    ReportOffset("SizeOfImage", g_offSizeOfImage, 0x40);
    ReportOffset("BaseDllName", g_offBaseDllName, 0x58);
    ReportOffset("HashLinks", g_offHashLinks, 0x70);
#else
    ReportOffset("DllBase", g_offDllBase, 0x18);
    ReportOffset("SizeOfImage", g_offSizeOfImage, 0x20);
    ReportOffset("BaseDllName", g_offBaseDllName, 0x2C);
    ReportOffset("HashLinks", g_offHashLinks, 0x38);
#endif
    printf("  ambiguity     : DllBase %d other offset(s) also qualified, "
           "SizeOfImage %d, BaseDllName %d\n", g_offDllBaseAlt, g_offSizeAlt, g_offNameAlt);
    for (int w = 0; w < 3; ++w) {
        if (!g_altN[w]) continue;
        printf("                  also-qualifying %s offsets:",
            w == 0 ? "DllBase" : (w == 1 ? "SizeOfImage" : "BaseDllName"));
        for (int i = 0; i < g_altN[w]; ++i) printf(" +0x%X", g_altList[w][i]);
        printf("\n");
    }
    if (!offOk) { printf("offset derivation FAILED -- cannot continue\n"); return 1; }

    // ------------------------------------------------------------ hash table
    printf("\n--- ntdll!LdrpHashTable ---\n");
    if (!g_hashTable) {
        printf("NOT LOCATED\n");
    }
    else {
        printf("address         : %p  (ntdll+0x%llX, section %s)\n", (void*)g_hashTable,
            (unsigned long long)(g_hashTable - g_ntBase), SectionOf(g_hashTable));
        printf("method 1        : per-module derivation, %d of %d modules agreed\n",
            g_hashAnchors, g_hashAnchorsTotal);
        printf("  HashLinks off : +0x%X   (searched every pointer-aligned offset; "
               "%d offset(s) had well-formed rings)\n", g_offHashLinks, g_hashCandidateOffsets);
        printf("  buckets       : %d   library hardcodes LDR_HASH_TABLE_ENTRIES 32  %s\n",
            g_hashBuckets, g_hashBuckets == 32 ? "agree" : "*** DIFFERS ***");
        printf("  hash          : %s\n", kAlgoName[g_hashAlgo]);
        printf("  span          : 0x%llX bytes (ntdll+0x%llX .. +0x%llX)\n",
            (unsigned long long)(g_hashBuckets * kLinkSize),
            (unsigned long long)(g_hashTable - g_ntBase),
            (unsigned long long)(g_hashTable - g_ntBase + g_hashBuckets * kLinkSize));
        printf("method 2        : hash-free ring-array scan -> %s (%d hit%s)%s\n",
            !g_hashTableScan ? "NO HIT"
                             : (g_hashTableScan == g_hashTable ? "SAME address" : "DIFFERENT address"),
            g_hashScanHits, g_hashScanHits == 1 ? "" : "s",
            (g_hashTableScan && g_hashTableScan != g_hashTable) ? "  *** METHODS DISAGREE ***" : "");
        if (g_hashTableScan && g_hashTableScan != g_hashTable)
            printf("  scan address  : ntdll+0x%llX\n",
                (unsigned long long)(g_hashTableScan - g_ntBase));
        printf("validation      : %d members walked, %d wrong bucket, %d non-loader node, "
               "%d module(s) missing, %d duplicated\n",
            g_hashMembers, g_hashBadHash, g_hashUnknownNode, g_hashMissingMods, g_hashDupMods);
        printf("verdict         : %s\n", g_hashValidated ? "VALIDATED" : "*** FAILED ***");

        if (g_verbose) {
            printf("  bucket use    :");
            for (int i = 0; i < g_hashBuckets && i < 256; ++i) printf(" %d", g_hashBucketUse[i]);
            printf("\n");
        }
        if (g_dump) DumpBytes(g_hashTable, (size_t)g_hashBuckets * kLinkSize, "  ");
    }

    // ------------------------------------------------- inverted function table
    printf("\n--- ntdll!LdrpInvertedFunctionTable ---\n");
    printf("module-base refs: %d place(s) in ntdll's non-code sections hold a "
           "loaded module base\n", g_hitCount);
    if (g_showHits) {
        for (int i = 0; i < g_hitCount; ++i)
            printf("  ntdll+0x%-8llX %-10s -> %ls\n",
                (unsigned long long)(g_hits[i].addr - g_ntBase),
                SectionOf(g_hits[i].addr), g_mods[g_hits[i].mod].name);
    }
    if (!g_ift) {
        printf("NOT LOCATED by derivation "
               "(longest ImageBase progression: %d entries, stride %d, at ntdll+0x%llX)\n",
            g_runLenRaw, g_runStride,
            g_runStart ? (unsigned long long)(g_runStart - g_ntBase) : 0ull);
        if (g_iftClassic)
            printf("classic-layout scan did find ntdll+0x%llX, MaxCount 0x%X -- "
                   "derivation and scan DISAGREE\n",
                (unsigned long long)(g_iftClassic - g_ntBase), g_iftClassicMax);
    }
    else {
        printf("address         : %p  (ntdll+0x%llX, section %s)\n", (void*)g_ift,
            (unsigned long long)(g_ift - g_ntBase), SectionOf(g_ift));
        printf("method 1        : ImageBase-column derivation, run of %d entries\n", g_iftRunLen);
        printf("  entries begin : ntdll+0x%llX\n",
            (unsigned long long)(g_ift + g_iftHeaderSize - g_ntBase));
        printf("  header size   : 0x%X   library assumes 0x10   %s\n", g_iftHeaderSize,
            g_iftHeaderSize == 0x10 ? "agree" : "*** DIFFERS ***");
#ifdef _WIN64
        const int libStride = 0x18, libB = 8, libS = 0x10, libED = 0, libEDS = 0x14;
#else
        const int libStride = 0x10, libB = 0, libS = 4, libED = -1, libEDS = 8;
#endif
        printf("  entry stride  : 0x%X   library assumes 0x%X   %s\n", g_iftStride, libStride,
            g_iftStride == libStride ? "agree" : "*** DIFFERS ***");
        printf("  ImageBase     : +0x%X  (library +0x%X) %s\n", g_iftOffImageBase, libB,
            g_iftOffImageBase == libB ? "" : "*** DIFFERS ***");
        if (g_iftOffImageSize >= 0)
            printf("  ImageSize     : +0x%X  (library +0x%X) %s\n", g_iftOffImageSize, libS,
                g_iftOffImageSize == libS ? "" : "*** DIFFERS ***");
        else printf("  ImageSize     : not derivable\n");
        if (g_iftOffExcDir >= 0)
            printf("  ExcDirectory  : +0x%X  (library +0x%X) %s\n", g_iftOffExcDir, libED,
                g_iftOffExcDir == libED ? "" : "*** DIFFERS ***");
        else printf("  ExcDirectory  : not derivable (no majority match against PE headers)\n");
        if (g_iftOffExcDirSize >= 0)
            printf("  ExcDirSize    : +0x%X  (library +0x%X) %s\n", g_iftOffExcDirSize, libEDS,
                g_iftOffExcDirSize == libEDS ? "" : "*** DIFFERS ***");
        else printf("  ExcDirSize    : not derivable\n");
        printf("  Count         : %u\n", g_iftCount);
        printf("  MaxCount      : 0x%X   library hardcodes 0x200   %s\n", g_iftMaxCount,
            g_iftMaxCount == 0x200 ? "agree" : "*** DIFFERS ***");
        printf("  Epoch/word2   : 0x%X\n", g_iftEpoch);
        printf("  Overflow      : 0x%X\n", g_iftOverflow);
        printf("  table span    : 0x%llX bytes\n",
            (unsigned long long)(g_iftHeaderSize + (size_t)g_iftMaxCount * g_iftStride));
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(g_ift, &mbi, sizeof(mbi)))
            printf("  protection    : 0x%lX (%s)\n", (unsigned long)mbi.Protect,
                (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) ? "writable"
                                                                          : "read-only, needs an mrdata flip");
        printf("method 2        : classic-layout scan -> %s (%d hit%s)%s\n",
            g_iftClassic ? (g_iftClassic == g_ift ? "SAME address" : "DIFFERENT address") : "no hit",
            g_iftClassicHits, g_iftClassicHits == 1 ? "" : "s",
            (g_iftClassicHits == 1 && g_iftClassic != g_ift) ? "  *** METHODS DISAGREE ***" : "");
        if (g_iftChosenBy)
            printf("                  more than one table exists here; chosen by which one's "
                   "ExceptionDirectory column matches this architecture's view\n");
        for (int i = 0; i < g_iftClassicHits && i < 8; ++i) {
            printf("  scan hit %d    : ntdll+0x%-8llX Count %-5u MaxCount 0x%-5X %s\n", i,
                (unsigned long long)(g_iftClassicAll[i] - g_ntBase),
                g_iftClassicCnt[i], g_iftClassicMx[i],
                g_iftClassicAll[i] == g_ift ? "<== derivation agrees" : "(other candidate)");
            //
            // With more than one candidate the interesting question is what each
            // one contains. ARM64X keeps two tables; the difference between them
            // is which images the running architecture has unwind data for, so
            // listing the absentees names the table.
            //
            int edOk = 0, edTot = 0, miss = 0;
            bool present[MAX_MODS] = { false };
            for (uint32_t k = 0; k < g_iftClassicCnt[i] && k < 2048; ++k) {
                const uint8_t* e = g_iftClassicAll[i] + 0x10 + (size_t)k * (kPtr * 2 + 8);
                const uint8_t *ib, *ed;
                if (!RdPtr(e + kPtr, &ib)) break;
                int m = FindModByBase(ib);
                if (m < 0) continue;
                present[m] = true;
                if (g_mods[m].pdata) {
                    ++edTot;
                    if (RdPtr(e, &ed) && ed == g_mods[m].pdata) ++edOk;
                }
            }
            printf("                  .pdata pointers matching this view: %d of %d; absent:",
                edOk, edTot);
            for (int m = 0; m < g_modCount; ++m)
                if (!present[m]) { printf(" %ls", g_mods[m].name); ++miss; }
            printf("%s\n", miss ? "" : " (none)");
        }
        printf("validation      : %d of %u entries name a loaded module with matching "
               "SizeOfImage\n", g_iftMatched, g_iftCount);
        printf("  entry[0]      : %s (Win8+ pins ntdll there, outside the sort)\n",
            g_iftEntry0IsNtdll ? "ntdll" : "NOT ntdll");
        printf("  ordering      : %d out-of-order (index >= 1), %d unknown ImageBase, "
               "%d wrong ImageSize\n", g_iftBadOrder, g_iftUnknownBase, g_iftBadSize);
        printf("  exc directory : %d of %d entries reproduce the module's own .pdata pointer\n",
            g_iftEdMatched, g_iftEdChecked);
        printf("  coverage      : %d loaded module(s) have no entry\n", g_iftModsMissing);
        printf("verdict         : %s\n", g_iftValidated ? "VALIDATED" : "*** FAILED ***");
        if (g_dump) DumpBytes(g_ift, (size_t)g_iftHeaderSize + 6 * (size_t)g_iftStride, "  ");
    }

    // ------------------------------------------------------- behavioural check
    if (!g_fast && g_ift && g_iftValidated) {
        IftSnap before; SnapIft(&before);
        g_behaveBefore = before.count;
        BehaviouralCheck();
    }
    printf("\n--- behavioural proof (LdrpInvertedFunctionTable) ---\n");
    if (g_fast) printf("skipped (--fast)\n");
    else if (!g_behaveRan) printf("skipped (no unloaded probe DLL available, or table not validated)\n");
    else {
        printf("probe DLL       : %ls\n", g_behaveDll);
        printf("Count           : %u before -> %u after load -> %u after free\n",
            g_behaveBefore, g_behaveAfter, g_behaveEnd);
        printf("entry appeared  : %s\n", g_behaveAppeared ? "yes (expected)" : "NO -- wrong address");
        printf("module unloaded : %s\n", g_behaveUnloaded ? "yes" : "no (pinned; removal not testable)");
        if (g_behaveUnloaded)
            printf("entry removed   : %s\n", g_behaveDisappeared ? "yes (expected)" : "NO");
        if (g_iftClassicHits > 1) {
            printf("all candidates  : (Count before -> after load -> after free; "
                   "* = holds the probe DLL)\n");
            for (int i = 0; i < g_iftClassicHits && i < 8; ++i)
                printf("  ntdll+0x%-8llX %u%s -> %u%s -> %u%s   %s\n",
                    (unsigned long long)(g_iftClassicAll[i] - g_ntBase),
                    g_candCount[0][i], g_candHas[0][i] ? "*" : "",
                    g_candCount[1][i], g_candHas[1][i] ? "*" : "",
                    g_candCount[2][i], g_candHas[2][i] ? "*" : "",
                    g_iftClassicAll[i] == g_ift ? "<== chosen" : "");
        }
        printf("verdict         : %s\n", g_behaveOk ? "PROVEN" : "*** FAILED ***");
    }

    bool ok = g_hashValidated && g_iftValidated && (g_fast || !g_behaveRan || g_behaveOk);
    printf("\nRESULT: %s\n", ok
        ? "both structures located and validated"
        : "at least one structure could not be located or validated");
    printf("==========================================================\n");
    return ok ? 0 : 1;
}
