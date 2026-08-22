//
// probe_baseindex -- locate and verify ntdll!LdrpModuleBaseAddressIndex at
// runtime, deterministically, without a hardcoded RVA, a PDB, or a byte
// signature.
//
// Standalone by design: it links nothing from this tree, exactly like
// stress/lockprobe.cpp, so it can be built and run against any ntdll without
// dragging MemoryModulePP along. The datatable-lock locator below is copied
// from lockprobe.cpp rather than shared, for that reason.
//
// ---------------------------------------------------------------------------
// What the library does today, and why it is flaky
// ---------------------------------------------------------------------------
//
// MemoryModule/Initialize.cpp, FindLdrpModuleBaseAddressIndex():
//
//     node = &ntdllEntry->BaseAddressIndexNode;           // offset 0xC8, fixed
//     while (node->ParentValue & ~7) node = parent(node); // walk up to the root
//     if (!node->Red) {                                   // <-- the problem
//         scan ntdll's .data for the 8-byte value `node`;
//         accept only if there is exactly one hit and tmp->Root && tmp->Min;
//     }
//
// The walk up is sound: every loaded module's LDR_DATA_TABLE_ENTRY carries a
// BaseAddressIndexNode, they are all in one red-black tree, so climbing parent
// pointers from ntdll's own node lands on the tree's root. Finding the
// RTL_RB_TREE that owns that root by looking for a pointer to it in ntdll's
// writable data is also sound -- the tree's Root field is exactly such a
// pointer.
//
// `Red` is bit 0 of ParentValue, and the gate says "only trust the root I found
// if it is black". OPEN-ISSUES issue 7 and stress/README.md both describe this
// as a live per-run coin flip. It is not, and the difference matters, so this
// probe measures it three ways instead of repeating the claim:
//
//   --rbtest drives ntdll's OWN exported RtlRbInsertNodeEx and RtlRbRemoveNode
//   over a private tree, 200k operations, sampling the root's colour after
//   every one. It is never red. ntdll's red-black code keeps the classic
//   root-is-black invariant, so on a settled tree the gate cannot fire.
//
//   --sweep re-runs both algorithms after loading DLLs one at a time, walking
//   the process through forty-odd different module sets. Still never red.
//
//   --race is where it does happen. FindLdrpModuleBaseAddressIndex() climbs the
//   parent chain and reads the colour with NO loader-database lock held, and
//   initialization is deferred to first use, so it runs on an ordinary thread
//   while other threads may be loading. Sampling that unlocked climb at full
//   rate while three threads churn LoadLibrary/FreeLibrary, a red root does show
//   up -- around 2 in 10 million samples on a 3-core Server 2022 box, and not at
//   all in 2.2 billion samples on this ARM64 host.
//
// So the gate is real but it is a torn read, not a coin flip -- and it is not
// even the main way that function fails. The same unlocked climb lands on a
// stale node far more often, and then the address is not in `.data` at all and
// the search returns null: measured at 1.5 to 1.7 per hundred attempts under
// that same contention, against zero for a red root. Either way the capability
// silently disappears with nothing logged. `--legacy` reproduces the current
// code exactly, so all of these are measured rather than argued about.
//
// Three more fragilities in the same function:
//   * the BaseAddressIndexNode offset (0xC8) is hardcoded per Windows version;
//   * only `.data` is scanned, and the scan is byte-granular, so an unaligned
//     coincidence would be accepted as a tree, and a future build that moved
//     the variable to `.mrdata` or `.bss` would silently find nothing;
//   * the whole thing runs before MmpInitializeModuleDatatableLock() has even
//     located the lock, so there is nothing available to hold.
//
// ---------------------------------------------------------------------------
// What this probe does instead
// ---------------------------------------------------------------------------
//
// Four independent techniques, in increasing order of strength. The result is
// only reported as located when the decisive one succeeds.
//
// 1. DISCOVER the node offset instead of hardcoding it. For every candidate
//    offset in the LDR_DATA_TABLE_ENTRY, treat entry+offset as an
//    RTL_BALANCED_NODE and ask: do all loaded modules climb to the same root,
//    does an in-order walk of that root visit exactly the set of loaded
//    modules, and is it ascending in DllBase? Only the base-address index
//    answers yes to all three. (LDR_DATA_TABLE_ENTRY carries a second
//    RTL_BALANCED_NODE, MappingInfoIndexNode; it fails the DllBase ordering
//    test, which is what makes this discriminating rather than lucky.)
//
// 2. CLIMB to the root with no reference to its colour. Then compute the tree's
//    minimum by walking left from the root, so we know both fields of the
//    RTL_RB_TREE we are looking for, not just one.
//
// 3. SCAN every writable section of ntdll -- not just `.data` -- at pointer
//    alignment, for the {Root, Min} pair. Sixteen known bytes instead of eight,
//    and no dependence on which section the variable lives in.
//
// 4. RECONCILE, which is the decisive step and the reason this target can be
//    verified far harder than the datatable lock can. The tree must contain one
//    node per loaded module and nothing else. So for each candidate: in-order
//    traversal must equal the PEB->Ldr->InLoadOrderModuleList set exactly, be
//    strictly ascending in DllBase, have consistent parent back-pointers, obey
//    the red-black height bound, have Tree->Min equal to the leftmost node, and
//    answer a by-DllBase binary search for every loaded module. Then it is
//    tested BEHAVIOURALLY: load a DLL that is not currently loaded and the whole
//    reconciliation must still hold with the new module in it; free it and the
//    reconciliation must still hold with the module gone. A wrong address cannot
//    survive that.
//
// Walking ntdll's loader structures means reading nodes ntdll may be
// rebalancing, so every walk here runs while holding
// ntdll!LdrpModuleDatatableLock shared. That lock is located and causality-
// verified using the technique from stress/lockprobe.cpp, copied in below, and
// ONE shared acquisition spans the module snapshot, the offset discovery, the
// climb, the scan and the reconciliation -- taking it separately for each is a
// time-of-check race that a loading process loses. That is not a detail: with
// the lock this probe is 100% across every measurement taken; run with --nolock
// under the same contention it drops to 52-81% first-try. It never returns a
// wrong address either way, because reconciliation fails closed -- but "fails
// closed" is only a safe answer if you are not the one thing standing between
// the caller and a silently disabled feature.
//
// `--survey` is the analogue of lockprobe's: RtlRbInsertNodeEx and
// RtlRbRemoveNode are *exported* and take the tree as their first argument, so
// every call site of them inside ntdll can be found by exact target match and
// the first argument decoded. Grouping the results enumerates every RB tree
// ntdll manipulates through those exports and shows where the base-address
// index sits among them. That is a genuinely independent locator, and it is
// reported as corroboration when it agrees.
//
// Build (do not use build.cmd, it rebuilds the shared library):
//   cl /nologo /std:c++17 /O2 /MT /EHsc probe_baseindex.cpp
//        /link /OUT:probe_baseindex.exe
//
// Options:
//   --survey    add the RtlRb* call-site survey
//   --sweep     load DLLs one at a time and re-run BOTH algorithms after each,
//               which is how the old one's failure rate gets measured: the root
//               colour is a function of the module set, not of the run
//   --race [N]  run both algorithms N times while another thread loads and
//               frees DLLs, and tally how each one fares
//   --rbtest    drive ntdll's own exported RtlRbInsertNodeEx/RtlRbRemoveNode
//               over a private tree and count how often the root ends up red --
//               i.e. test whether the colour gate's premise is even true
//   --legacy    only run the library's current algorithm and report its verdict
//   --quiet     one summary line, for scripted repeat runs
//   --nolock    skip locating/holding LdrpModuleDatatableLock (faster; unsafe
//               in a process that loads DLLs on other threads)
//   --nobehave  skip the load/unload behavioural test
//
// Exit code: 0 located and fully verified, 1 not located or not verified,
//            2 setup failure.
//

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>

// ============================================================================
//                           ntdll structures
// ============================================================================
//
// Only the parts that are public and have not moved since NT: the PEB's Ldr
// pointer, PEB_LDR_DATA's three list heads, and LDR_DATA_TABLE_ENTRY's
// documented prefix up to BaseDllName. Everything past that -- notably where
// BaseAddressIndexNode lives -- is discovered at runtime rather than declared.
//

typedef struct _PRB_NODE {
    struct _PRB_NODE* Left;
    struct _PRB_NODE* Right;
    ULONG_PTR         ParentValue;      // low 3 bits: colour / balance
} RB_NODE, *PRB_NODE;

typedef struct _PRB_TREE {
    PRB_NODE Root;
    PRB_NODE Min;                       // low bit is RTL_RB_TREE::Encoded
} RB_TREE, *PRB_TREE;

#define RB_PARENT(n) ((PRB_NODE)((n)->ParentValue & ~(ULONG_PTR)7))
#define RB_IS_RED(n) (((n)->ParentValue & 1) != 0)

typedef struct _PROBE_USTRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PROBE_USTRING;

typedef struct _PROBE_LDR_ENTRY {
    LIST_ENTRY    InLoadOrderLinks;            // 0x00
    LIST_ENTRY    InMemoryOrderLinks;          // 0x10
    LIST_ENTRY    InInitializationOrderLinks;  // 0x20
    PVOID         DllBase;                     // 0x30
    PVOID         EntryPoint;                  // 0x38
    ULONG         SizeOfImage;                 // 0x40
    PROBE_USTRING FullDllName;                 // 0x48
    PROBE_USTRING BaseDllName;                 // 0x58
} PROBE_LDR_ENTRY, *PPROBE_LDR_ENTRY;

typedef struct _PROBE_PEB_LDR {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;                       // 0x08
    LIST_ENTRY InLoadOrderModuleList;          // 0x10
    LIST_ENTRY InMemoryOrderModuleList;        // 0x20
    LIST_ENTRY InInitializationOrderModuleList;// 0x30
} PROBE_PEB_LDR, *PPROBE_PEB_LDR;

static PPROBE_PEB_LDR PebLdr() {
    // TEB+0x60 is ProcessEnvironmentBlock, PEB+0x18 is Ldr. Same on x64 and
    // ARM64; both are LLP64 with the identical TEB/PEB prefix.
    BYTE* peb = *(BYTE**)((BYTE*)NtCurrentTeb() + 0x60);
    return *(PPROBE_PEB_LDR*)(peb + 0x18);
}

// ============================================================================
//                      ntdll image geometry
// ============================================================================

static const uint8_t* g_ntBase = nullptr;
static size_t         g_ntSize = 0;
static WORD           g_ntMachine = 0;
static DWORD          g_ntStamp = 0;

struct ProbeSect {
    char           name[9];
    const uint8_t* base;
    size_t         size;
    DWORD          chars;
};
static ProbeSect g_sects[48];
static int       g_sectCount = 0;

static void InitImage(HMODULE nt) {
    g_ntBase = (const uint8_t*)nt;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)(g_ntBase + dos->e_lfanew);
    g_ntSize = h->OptionalHeader.SizeOfImage;
    g_ntMachine = h->FileHeader.Machine;
    g_ntStamp = h->FileHeader.TimeDateStamp;

    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(h);
    for (WORD i = 0; i < h->FileHeader.NumberOfSections && g_sectCount < 48; ++i, ++s) {
        ProbeSect& d = g_sects[g_sectCount++];
        memcpy(d.name, s->Name, 8);
        d.name[8] = 0;
        d.base = g_ntBase + s->VirtualAddress;
        d.size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        d.chars = s->Characteristics;
    }
}

static const ProbeSect* SectionOf(const void* p) {
    for (int i = 0; i < g_sectCount; ++i)
        if ((const uint8_t*)p >= g_sects[i].base &&
            (const uint8_t*)p < g_sects[i].base + g_sects[i].size)
            return &g_sects[i];
    return nullptr;
}

static const ProbeSect* SectionByName(const char* name) {
    for (int i = 0; i < g_sectCount; ++i)
        if (!_strnicmp(name, g_sects[i].name, 8)) return &g_sects[i];
    return nullptr;
}

static bool InNtdll(const void* p) {
    return (const uint8_t*)p >= g_ntBase && (const uint8_t*)p < g_ntBase + g_ntSize;
}

static unsigned long long Rva(const void* p) {
    return (unsigned long long)((const uint8_t*)p - g_ntBase);
}

//
// A user-mode pointer we are willing to dereference: non-null, pointer-aligned,
// and below the user address-space ceiling. Everything that follows one of
// these is additionally wrapped in SEH, because "plausible" is not "mapped".
//
static bool PlausiblePtr(const void* p) {
    ULONG_PTR v = (ULONG_PTR)p;
    return v >= 0x10000 && v < 0x7FFFFFFF0000ULL && (v & 7) == 0;
}

// ------------------------------------------------- ntdll function table (.pdata)
//
// Copied from lockprobe.cpp. Following a computed call target means trusting
// bytes we have not proved are an instruction; IMAGE_DIRECTORY_ENTRY_EXCEPTION
// lists the start RVA of every function with unwind data, so "is this a real
// function start" becomes a lookup, and the next entry bounds how far a scan may
// run before it leaves the function it began in.
//
static uint32_t* g_fnStarts = nullptr;
static size_t    g_fnCount = 0;
static uint32_t  g_fnLow = 0, g_fnHigh = 0;

static void InitFunctionTable(HMODULE nt) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((const uint8_t*)nt + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY& dir =
        h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size) return;

    size_t stride = (h->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? 12 : 8;
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

//
// On ARM64X an x64 caller's GetProcAddress returns an ARM64EC fast-forward
// sequence rather than an x64 body. Copied from lockprobe.cpp.
//
static bool IsEcFastForward(const void* p, void** jmpTarget) {
    static const uint8_t sig[] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x20,0x55,0x5d,0xe9 };
    const uint8_t* b = (const uint8_t*)p;
    if (!b) return false;
    if (memcmp(b, sig, sizeof(sig)) != 0) return false;
    int32_t rel; memcpy(&rel, b + 10, 4);
    if (jmpTarget) *jmpTarget = (void*)(b + 14 + rel);
    return true;
}

// ============================================================================
//         ntdll!LdrpModuleDatatableLock  (technique copied from lockprobe.cpp)
// ============================================================================
//
// The loader database -- the three PEB->Ldr lists, LdrpHashTable, and the tree
// this probe is looking for -- is guarded by LdrpModuleDatatableLock, not by
// LdrpLoaderLock. Reading the tree without it means reading nodes ntdll may be
// rebalancing. It is not exported, so it is decoded out of the instruction that
// materialises the first argument of an exported SRW acquire, inside exported
// donor functions. See stress/lockprobe.cpp for the full argument; this is a
// verbatim copy so the probe stays standalone.
//

typedef VOID(NTAPI* PFN_SRW)(PVOID);
static PFN_SRW g_acqExcl, g_acqShared, g_relExcl, g_relShared;
static void*   g_acqTargets[4];
static int     g_acqTargetCount = 0;

static const char* kLockDonors[] = {
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
            if (rd == 0 && haveAdrp[rn]) {
                pendingArg0 = adrp[rn] + imm12;
                havePendingArg0 = true;
            }
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
                if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) {  // lea rcx,[rip+d]
                    int32_t d; memcpy(&d, q + 3, 4);
                    return (void*)(q + 7 + d);
                }
                if (q[0] == 0x48 && q[1] == 0xB9) {                  // mov rcx, imm64
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

static void DecodeAnyLock(const void* at, bool isEc, int depth, void** out) {
    *out = nullptr;
    __try {
        if (isEc) {
            if ((*out = DecodeArm64(at, 256, depth)) != nullptr) return;
            *out = DecodeX64(at, 512, depth);
        }
        else {
            if ((*out = DecodeX64(at, 512, depth)) != nullptr) return;
            *out = DecodeArm64(at, 256, depth);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { *out = nullptr; }
}

static void* g_lock = nullptr;
static int   g_lockAgree = 0;
static bool  g_lockVerified = false;

static void* LocateDatatableLock(HMODULE nt, int* agreeOut, int* decodedOut) {
    void* agreed = nullptr;
    int agree = 0, decoded = 0;
    const int n = (int)(sizeof(kLockDonors) / sizeof(kLockDonors[0]));

    for (int i = 0; i < n; ++i) {
        void* fn = (void*)GetProcAddress(nt, kLockDonors[i]);
        if (!fn) continue;
        void* ecTarget = nullptr;
        bool isThunk = IsEcFastForward(fn, &ecTarget);
        const void* at = isThunk ? ecTarget : fn;

        void* lock = nullptr;
        DecodeAnyLock(at, isThunk, 0, &lock);
        if (!lock) DecodeAnyLock(at, isThunk, 2, &lock);
        if (!lock) continue;

        ++decoded;
        if (!agreed) { agreed = lock; agree = 1; }
        else if (agreed == lock) ++agree;
    }
    *agreeOut = agree;
    *decodedOut = decoded;
    return agree >= 2 ? agreed : nullptr;
}

struct LockProbeCtx { HANDLE go, done; };

static DWORD WINAPI LockProbeThread(LPVOID param) {
    LockProbeCtx* c = (LockProbeCtx*)param;
    WaitForSingleObject(c->go, INFINITE);
    HMODULE h = LoadLibraryW(L"version.dll");
    if (h) FreeLibrary(h);
    SetEvent(c->done);
    return 0;
}

//
// Hold the candidate exclusively; an ordinary LoadLibrary on another thread must
// be unable to finish, and must finish the moment we let go.
//
static bool VerifyLockByCausality(void* candidate) {
    LockProbeCtx ctx;
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
// All loader-structure reads below happen between these two. If the lock could
// not be located the guard degrades to a no-op, and the probe says so; that is
// the same "fail visible, not silent" discipline the library is asked to adopt.
//
static void LoaderDbLock()   { if (g_lock) g_acqShared(g_lock); }
static void LoaderDbUnlock() { if (g_lock) g_relShared(g_lock); }

// ============================================================================
//                        module snapshot
// ============================================================================

#define MAX_MODULES 512

struct ModInfo {
    PPROBE_LDR_ENTRY entry;
    void*            base;
    ULONG            size;
    wchar_t          name[64];
};

struct ModSnapshot {
    ModInfo mods[MAX_MODULES];
    int     count;
    bool    truncated;
};

//
// Caller must already hold the datatable lock. Split out from SnapshotModules
// because everything that compares the list against the tree has to see ONE
// consistent state -- taking the lock separately for the snapshot and for the
// tree walk is a time-of-check race that a loading process will lose. SRW locks
// are not recursive, so there is no acquiring it twice on the way in either.
//
static bool SnapshotModulesLockHeld(ModSnapshot* s) {
    s->count = 0;
    s->truncated = false;
    PPROBE_PEB_LDR ldr = PebLdr();
    if (!ldr) return false;

    bool ok = true;
    __try {
        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY e = head->Flink;
        int guard = 0;
        while (e && e != head) {
            if (++guard > MAX_MODULES * 2) { ok = false; break; }
            PPROBE_LDR_ENTRY m = (PPROBE_LDR_ENTRY)e;
            if (s->count < MAX_MODULES) {
                ModInfo& d = s->mods[s->count++];
                d.entry = m;
                d.base = m->DllBase;
                d.size = m->SizeOfImage;
                d.name[0] = 0;
                if (m->BaseDllName.Buffer && m->BaseDllName.Length) {
                    int cch = m->BaseDllName.Length / 2;
                    if (cch > 63) cch = 63;
                    memcpy(d.name, m->BaseDllName.Buffer, cch * 2);
                    d.name[cch] = 0;
                }
            }
            else s->truncated = true;
            e = e->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok && s->count > 0;
}

static bool SnapshotModules(ModSnapshot* s) {
    LoaderDbLock();
    bool ok = SnapshotModulesLockHeld(s);
    LoaderDbUnlock();
    return ok;
}

// ============================================================================
//                        red-black tree walking
// ============================================================================

#define MAX_NODES MAX_MODULES

struct TreeWalk {
    PRB_NODE nodes[MAX_NODES];      // in-order
    int      count;
    int      height;
    bool     ok;
    const char* err;
};

//
// Iterative in-order traversal with a depth cap, a visit cap and a plausibility
// check on every pointer before it is dereferenced. A wrong candidate typically
// dies here, which is why the caller wraps this in SEH as well.
//
static void WalkInOrder(PRB_NODE root, TreeWalk* w) {
    w->count = 0; w->height = 0; w->ok = false; w->err = "";
    PRB_NODE stack[128];
    int sp = 0;
    PRB_NODE cur = root;
    long guard = 0;

    while (cur || sp) {
        while (cur) {
            if (!PlausiblePtr(cur)) { w->err = "implausible node pointer"; return; }
            if (sp >= 128) { w->err = "tree deeper than 128"; return; }
            stack[sp++] = cur;
            if (sp > w->height) w->height = sp;
            cur = cur->Left;
            if (++guard > MAX_NODES * 4L) { w->err = "cycle or oversized tree"; return; }
        }
        cur = stack[--sp];
        if (w->count >= MAX_NODES) { w->err = "more nodes than modules possible"; return; }
        w->nodes[w->count++] = cur;
        cur = cur->Right;
        if (++guard > MAX_NODES * 4L) { w->err = "cycle or oversized tree"; return; }
    }
    w->ok = true;
}

//
// Climb to the root with no reference to the node's colour. This is the whole
// of the fix for the black-root nondeterminism: the colour bit is read nowhere.
//
static PRB_NODE ClimbToRoot(PRB_NODE n) {
    int guard = 0;
    while (n && PlausiblePtr(n)) {
        PRB_NODE p = RB_PARENT(n);
        if (!p) return n;
        if (++guard > 256) return nullptr;
        n = p;
    }
    return nullptr;
}

static PRB_NODE LeftMost(PRB_NODE n) {
    int guard = 0;
    while (n && PlausiblePtr(n) && n->Left) {
        n = n->Left;
        if (++guard > 256) return nullptr;
    }
    return n;
}

static PRB_NODE FindByBase(PRB_NODE root, const void* base, size_t nodeOff) {
    PRB_NODE n = root;
    int guard = 0;
    while (n && PlausiblePtr(n)) {
        if (++guard > 256) return nullptr;
        const void* b = ((PPROBE_LDR_ENTRY)((BYTE*)n - nodeOff))->DllBase;
        if (base < b)      n = n->Left;
        else if (base > b) n = n->Right;
        else               return n;
    }
    return nullptr;
}

// ============================================================================
//              step 1: discover the BaseAddressIndexNode offset
// ============================================================================
//
// Instead of trusting a per-version constant (0xC8 in LdrEntry.h), ask the live
// process. A candidate offset is accepted only if, for EVERY loaded module,
// entry+offset climbs to one shared root, and an in-order walk of that root
// visits exactly the set of loaded modules in ascending DllBase order.
//
// LDR_DATA_TABLE_ENTRY holds a second RTL_BALANCED_NODE (MappingInfoIndexNode,
// 0xE0 on Win10/11 x64) that is also a tree over all modules -- keyed by mapping
// information, not by base address. The DllBase-ordering requirement is what
// separates them, so this is discrimination rather than luck. The probe reports
// every offset that passes so an ambiguity would be visible.
//

struct OffsetResult {
    size_t   off;
    PRB_NODE root;
    int      nodes;
    int      height;
    bool     ascending;
    bool     exact;                 // node set == module set
};

static bool EvaluateOffset(const ModSnapshot* s, size_t off, OffsetResult* r) {
    r->off = off; r->root = nullptr; r->nodes = 0; r->height = 0;
    r->ascending = false; r->exact = false;

    bool ok = false;
    __try {
        PRB_NODE root = nullptr;
        for (int i = 0; i < s->count; ++i) {
            PRB_NODE n = (PRB_NODE)((BYTE*)s->mods[i].entry + off);
            PRB_NODE rt = ClimbToRoot(n);
            if (!rt) __leave;
            if (!root) root = rt;
            else if (root != rt) __leave;
        }
        if (!root) __leave;

        TreeWalk w;
        WalkInOrder(root, &w);
        if (!w.ok) __leave;

        r->root = root;
        r->nodes = w.count;
        r->height = w.height;

        // In-order must be strictly ascending in DllBase, and parent
        // back-pointers must be consistent both ways.
        bool asc = true;
        const void* prev = nullptr;
        for (int i = 0; i < w.count; ++i) {
            PRB_NODE n = w.nodes[i];
            const void* b = ((PPROBE_LDR_ENTRY)((BYTE*)n - off))->DllBase;
            if (i && !(prev < b)) { asc = false; break; }
            prev = b;
            if (n->Left && RB_PARENT(n->Left) != n) { asc = false; break; }
            if (n->Right && RB_PARENT(n->Right) != n) { asc = false; break; }
        }
        r->ascending = asc;

        // Every module in the tree, and nothing else.
        bool exact = (w.count == s->count);
        if (exact) {
            for (int i = 0; i < s->count && exact; ++i) {
                PRB_NODE want = (PRB_NODE)((BYTE*)s->mods[i].entry + off);
                bool found = false;
                for (int j = 0; j < w.count; ++j)
                    if (w.nodes[j] == want) { found = true; break; }
                if (!found) exact = false;
            }
        }
        r->exact = exact;
        ok = asc && exact;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok;
}

// ============================================================================
//        step 3: scan every writable ntdll section for the {Root, Min} pair
// ============================================================================

struct Candidate {
    PRB_TREE          tree;
    const ProbeSect*  sect;
    bool              minMatches;
    bool              aligned;
    bool              writable;
    bool              committed;
    // reconciliation
    bool              reconciled;
    const char*       why;
    int               nodes;
    int               height;
};

static Candidate g_cands[64];
static int       g_candCount = 0;
static int       g_unalignedHits = 0;

static void ScanOneSection(const ProbeSect* s, ULONG_PTR want, PRB_NODE expectedMin) {
    __try {
        // Byte-granular pass purely to count what a byte-granular scanner (the
        // library's current one) would have seen; the candidate list itself is
        // built at pointer alignment, where a real RTL_RB_TREE must live.
        for (size_t off = 0; off + 8 <= s->size; ++off) {
            ULONG_PTR v;
            memcpy(&v, s->base + off, 8);
            if (v != want) continue;
            if (((ULONG_PTR)(s->base + off) & 7) != 0) { ++g_unalignedHits; continue; }
            if (g_candCount >= 64) continue;
            Candidate* c = &g_cands[g_candCount++];
            memset(c, 0, sizeof(*c));
            c->tree = (PRB_TREE)(s->base + off);
            c->sect = s;
            c->aligned = true;
            c->writable = true;
            PRB_NODE mn = (PRB_NODE)((ULONG_PTR)c->tree->Min & ~(ULONG_PTR)1);
            c->minMatches = (mn == expectedMin);
            MEMORY_BASIC_INFORMATION mbi;
            c->committed = VirtualQuery(c->tree, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void ScanForRoot(PRB_NODE root, PRB_NODE expectedMin) {
    g_candCount = 0;
    g_unalignedHits = 0;
    ULONG_PTR want = (ULONG_PTR)root;

    for (int i = 0; i < g_sectCount; ++i) {
        if (!(g_sects[i].chars & IMAGE_SCN_MEM_WRITE)) continue;
        if (g_sects[i].size < 16) continue;
        ScanOneSection(&g_sects[i], want, expectedMin);
    }
}

// ============================================================================
//                 step 4: reconcile a candidate against PEB->Ldr
// ============================================================================

struct Reconcile {
    bool ok;
    const char* why;
    int  nodes;
    int  modules;
    int  height;
    int  heightBound;
    bool minOk;
    bool ascending;
    bool parentsOk;
    bool setEqual;
    bool searchable;
};

//
// The decisive check. Everything the tree claims must line up with what
// PEB->Ldr->InLoadOrderModuleList says, in both directions, and the tree must
// still behave like a red-black tree while it does.
//
static void ReconcileCandidate(PRB_TREE tree, size_t nodeOff,
                               const ModSnapshot* s, Reconcile* r) {
    memset(r, 0, sizeof(*r));
    r->modules = s->count;
    r->why = "faulted";

    __try {
        PRB_NODE root = tree->Root;
        if (!PlausiblePtr(root)) { r->why = "root implausible"; __leave; }
        if (RB_PARENT(root)) { r->why = "tree->Root has a parent"; __leave; }

        TreeWalk w;
        WalkInOrder(root, &w);
        if (!w.ok) { r->why = w.err; __leave; }
        r->nodes = w.count;
        r->height = w.height;

        // Red-black height bound: 2*log2(n+1) is the classic limit.
        int bound = 2;
        for (int n = w.count + 1; n > 1; n >>= 1) bound += 2;
        r->heightBound = bound;

        PRB_NODE mn = (PRB_NODE)((ULONG_PTR)tree->Min & ~(ULONG_PTR)1);
        r->minOk = (w.count > 0 && mn == w.nodes[0]);

        bool asc = true, par = true;
        const void* prev = nullptr;
        for (int i = 0; i < w.count; ++i) {
            PRB_NODE n = w.nodes[i];
            if (n->Left && RB_PARENT(n->Left) != n) par = false;
            if (n->Right && RB_PARENT(n->Right) != n) par = false;
            const void* b = ((PPROBE_LDR_ENTRY)((BYTE*)n - nodeOff))->DllBase;
            if (i && !(prev < b)) asc = false;
            prev = b;
        }
        r->ascending = asc;
        r->parentsOk = par;

        bool eq = (w.count == s->count);
        if (eq) {
            for (int i = 0; i < s->count && eq; ++i) {
                PRB_NODE want = (PRB_NODE)((BYTE*)s->mods[i].entry + nodeOff);
                bool found = false;
                for (int j = 0; j < w.count; ++j)
                    if (w.nodes[j] == want) { found = true; break; }
                if (!found) eq = false;
            }
        }
        r->setEqual = eq;

        // ntdll's own use of this tree is a by-DllBase binary search
        // (LdrpFindLoadedDllByAddress). Every module must be reachable that way.
        bool searchable = true;
        for (int i = 0; i < s->count; ++i) {
            PRB_NODE want = (PRB_NODE)((BYTE*)s->mods[i].entry + nodeOff);
            if (FindByBase(root, s->mods[i].base, nodeOff) != want) { searchable = false; break; }
        }
        r->searchable = searchable;

        r->ok = r->minOk && asc && par && eq && searchable &&
                w.height <= bound && w.count > 0;
        r->why = r->ok ? "reconciled"
               : !eq ? "node set differs from the module list"
               : !asc ? "in-order traversal is not ascending in DllBase"
               : !par ? "parent back-pointers inconsistent"
               : !searchable ? "by-DllBase search does not find every module"
               : !r->minOk ? "Tree->Min is not the leftmost node"
               : "height exceeds the red-black bound";
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r->ok = false; r->why = "faulted while walking"; }
}

// ============================================================================
//                   behavioural verification
// ============================================================================
//
// Structure can be coincidence; behaviour cannot. Load a DLL that is not
// currently loaded and the tree must reconcile again with the new module in it,
// found by a by-DllBase search at its actual base. Free it and the tree must
// reconcile again with it gone. Nothing else in ntdll's writable data both
// looks like this tree and tracks the module list in real time.
//

// One acquisition, so the list and the tree are compared in the same state.
static bool SnapshotAndReconcile(PRB_TREE tree, size_t nodeOff,
                                 ModSnapshot* s, Reconcile* r) {
    LoaderDbLock();
    bool ok = SnapshotModulesLockHeld(s);
    if (ok) ReconcileCandidate(tree, nodeOff, s, r);
    LoaderDbUnlock();
    return ok;
}

static const wchar_t* kSpareDlls[] = {
    L"version.dll", L"winmm.dll", L"imagehlp.dll", L"msimg32.dll",
    L"wtsapi32.dll", L"mpr.dll", L"cabinet.dll",
};

struct BehaveResult {
    bool        ran;
    bool        ok;
    const char* why;
    const wchar_t* dll;
    void*       loadedBase;
    int         nodesBefore, nodesAfterLoad, nodesAfterFree;
    bool        appeared, disappeared, freedForReal;
};

static void BehaviourTest(PRB_TREE tree, size_t nodeOff, BehaveResult* b) {
    memset(b, 0, sizeof(*b));
    b->why = "no unloaded spare DLL available";

    const wchar_t* pick = nullptr;
    for (size_t i = 0; i < sizeof(kSpareDlls) / sizeof(kSpareDlls[0]); ++i) {
        if (!GetModuleHandleW(kSpareDlls[i])) { pick = kSpareDlls[i]; break; }
    }
    if (!pick) return;
    b->ran = true;
    b->dll = pick;

    // File-scope, not stack: a ModSnapshot is ~78 KB and three of them would be
    // a quarter of the default stack.
    static ModSnapshot s0, s1, s2;

    Reconcile r0;
    if (!SnapshotAndReconcile(tree, nodeOff, &s0, &r0)) { b->why = "module snapshot failed"; return; }
    b->nodesBefore = r0.nodes;
    if (!r0.ok) { b->why = "did not reconcile before the load"; return; }

    HMODULE h = LoadLibraryW(pick);
    if (!h) { b->why = "LoadLibrary failed"; return; }

    Reconcile r1;
    if (!SnapshotAndReconcile(tree, nodeOff, &s1, &r1)) { b->why = "module snapshot failed after load"; FreeLibrary(h); return; }
    b->nodesAfterLoad = r1.nodes;
    b->loadedBase = (void*)h;

    bool appeared = false;
    LoaderDbLock();
    __try {
        PRB_NODE n = FindByBase(tree->Root, (void*)h, nodeOff);
        appeared = (n != nullptr) &&
                   ((PPROBE_LDR_ENTRY)((BYTE*)n - nodeOff))->DllBase == (void*)h;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { appeared = false; }
    LoaderDbUnlock();
    b->appeared = appeared;

    if (!r1.ok) { b->why = "did not reconcile after the load"; FreeLibrary(h); return; }
    if (!appeared) { b->why = "the newly loaded module is not in the tree"; FreeLibrary(h); return; }

    FreeLibrary(h);
    bool reallyGone = (GetModuleHandleW(pick) == nullptr);
    b->freedForReal = reallyGone;

    Reconcile r2;
    if (!SnapshotAndReconcile(tree, nodeOff, &s2, &r2)) { b->why = "module snapshot failed after free"; return; }
    b->nodesAfterFree = r2.nodes;

    bool gone = true;
    if (reallyGone) {
        LoaderDbLock();
        __try { gone = (FindByBase(tree->Root, (void*)h, nodeOff) == nullptr); }
        __except (EXCEPTION_EXECUTE_HANDLER) { gone = false; }
        LoaderDbUnlock();
    }
    b->disappeared = gone;

    if (!r2.ok) { b->why = "did not reconcile after the free"; return; }
    if (!gone) { b->why = "the freed module is still in the tree"; return; }

    b->ok = true;
    b->why = "load and unload both tracked";
}

// ============================================================================
//         survey: every RtlRbInsertNodeEx / RtlRbRemoveNode call site
// ============================================================================
//
// The lockprobe idea applied to this target. Both routines are *exported*, and
// the calling convention puts the RTL_RB_TREE in the first argument, so a call
// site can be found by exact target match (not by a byte signature) and its
// first argument decoded. Grouping by the decoded address enumerates every RB
// tree ntdll drives through those exports, and the group containing the
// reconciled address is an independent confirmation of it.
//

static void* g_rbTargets[8];
static int   g_rbTargetCount = 0;

static bool IsRbTarget(const void* p) {
    for (int i = 0; i < g_rbTargetCount; ++i)
        if (g_rbTargets[i] == p) return true;
    return false;
}

//
// A decoded first argument is only kept if it could be a global RTL_RB_TREE:
// pointer-aligned and inside a writable ntdll section. That is what makes a
// backwards byte scan safe -- an accidental "48 8D 0D" inside an operand almost
// never lands on one.
//
static bool PlausibleTreeAddr(const void* p) {
    if (!InNtdll(p) || ((ULONG_PTR)p & 7)) return false;
    const ProbeSect* s = SectionOf(p);
    return s && (s->chars & IMAGE_SCN_MEM_WRITE);
}

static void* X64Arg0Before(const uint8_t* call, int lookback) {
    for (int back = 3; back <= lookback; ++back) {
        const uint8_t* q = call - back;
        if (!InNtdll(q)) break;
        if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) {          // lea rcx,[rip+d]
            int32_t d; memcpy(&d, q + 3, 4);
            void* r = (void*)(q + 7 + d);
            if (PlausibleTreeAddr(r)) return r;
        }
        if (q[0] == 0x48 && q[1] == 0xB9) {                          // mov rcx, imm64
            uint64_t v; memcpy(&v, q + 2, 8);
            if (PlausibleTreeAddr((void*)v)) return (void*)v;
        }
    }
    return nullptr;
}

static void* Arm64Arg0Before(const uint32_t* call, int lookback) {
    uint64_t adrp[32] = { 0 };
    bool     have[32] = { false };
    void*    best = nullptr;

    const uint32_t* p = call - lookback;
    if (!InNtdll(p)) p = (const uint32_t*)g_ntBase;
    for (; p < call; ++p) {
        uint32_t insn = *p;
        uint64_t pc = (uint64_t)p;
        if ((insn & 0x9F000000u) == 0x90000000u) {                   // ADRP
            uint32_t rd = insn & 0x1F;
            int64_t immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & (1LL << 20)) imm -= (1LL << 21);
            adrp[rd] = (pc & ~0xFFFULL) + (imm << 12);
            have[rd] = true;
            continue;
        }
        if ((insn & 0x9F000000u) == 0x10000000u) {                   // ADR
            uint32_t rd = insn & 0x1F;
            int64_t immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & (1LL << 20)) imm -= (1LL << 21);
            if (rd == 0) {
                void* r = (void*)(pc + imm);
                if (PlausibleTreeAddr(r)) best = r;
            }
            continue;
        }
        if ((insn & 0xFF800000u) == 0x91000000u) {                   // ADD Xd,Xn,#imm12
            uint32_t rd = insn & 0x1F, rn = (insn >> 5) & 0x1F, imm12 = (insn >> 10) & 0xFFF;
            if (rd == 0 && have[rn]) {
                void* r = (void*)(adrp[rn] + imm12);
                if (PlausibleTreeAddr(r)) best = r;
            }
            continue;
        }
    }
    return best;
}

struct RbBucket {
    void* tree;
    int   sites;
    int   insertSites, removeSites;
    unsigned long long firstSiteRva;
};
static RbBucket g_rb[64];
static int      g_rbCount = 0;
static int      g_rbSitesTotal = 0, g_rbSitesDecoded = 0;

static void RecordRb(void* tree, unsigned long long siteRva, bool isInsert) {
    RbBucket* b = nullptr;
    for (int i = 0; i < g_rbCount; ++i)
        if (g_rb[i].tree == tree) { b = &g_rb[i]; break; }
    if (!b) {
        if (g_rbCount == 64) return;
        b = &g_rb[g_rbCount++];
        b->tree = tree; b->sites = 0; b->insertSites = 0; b->removeSites = 0;
        b->firstSiteRva = siteRva;
    }
    ++b->sites;
    if (isInsert) ++b->insertSites; else ++b->removeSites;
}

// Which export a call target belongs to, for the insert/remove split.
static void* g_rbInsert[4]; static int g_rbInsertCount = 0;
static bool IsInsertTarget(const void* p) {
    for (int i = 0; i < g_rbInsertCount; ++i) if (g_rbInsert[i] == p) return true;
    return false;
}

static void SurveyRbCallSites() {
    g_rbCount = 0; g_rbSitesTotal = 0; g_rbSitesDecoded = 0;

    for (int i = 0; i < g_sectCount; ++i) {
        const ProbeSect& s = g_sects[i];
        if (!(s.chars & IMAGE_SCN_MEM_EXECUTE)) continue;

        // x64 form: E8/E9 rel32 whose target is exactly one of the exports.
        __try {
            for (size_t off = 0; off + 5 <= s.size; ++off) {
                const uint8_t* p = s.base + off;
                if (p[0] != 0xE8 && p[0] != 0xE9) continue;
                int32_t rel; memcpy(&rel, p + 1, 4);
                const uint8_t* target = p + 5 + rel;
                if (!IsRbTarget(target)) continue;
                ++g_rbSitesTotal;
                void* tree = X64Arg0Before(p, 128);
                if (tree) { ++g_rbSitesDecoded; RecordRb(tree, Rva(p), IsInsertTarget(target)); }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        // ARM64 / ARM64EC form: BL or B with imm26 hitting the same targets.
        __try {
            const uint32_t* w = (const uint32_t*)s.base;
            size_t n = s.size / 4;
            for (size_t k = 0; k < n; ++k) {
                uint32_t insn = w[k];
                uint32_t op = insn & 0xFC000000u;
                if (op != 0x14000000u && op != 0x94000000u) continue;  // B / BL imm26
                int64_t o = insn & 0x03FFFFFF;
                if (o & (1LL << 25)) o -= (1LL << 26);
                const void* target = (const void*)((uint64_t)(w + k) + (o << 2));
                if (!IsRbTarget(target)) continue;
                ++g_rbSitesTotal;
                void* tree = Arm64Arg0Before(w + k, 24);
                if (tree) { ++g_rbSitesDecoded; RecordRb(tree, Rva(w + k), IsInsertTarget(target)); }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ============================================================================
//        the library's current algorithm, reproduced for measurement
// ============================================================================
//
// A faithful transcription of FindLdrpModuleBaseAddressIndex() in
// MemoryModule/Initialize.cpp: fixed 0xC8 node offset, root colour gate,
// byte-granular `.data` scan, reject on a second hit. Reported on every run so
// the black-root failure rate is measured rather than asserted.
//

enum LegacyVerdict {
    LEGACY_OK, LEGACY_RED_SKIP, LEGACY_MULTI, LEGACY_NOHIT, LEGACY_ERROR
};

static const char* LegacyName(LegacyVerdict v) {
    switch (v) {
    case LEGACY_OK:       return "found";
    case LEGACY_RED_SKIP: return "SKIPPED (tree root is red)";
    case LEGACY_MULTI:    return "rejected (more than one .data hit)";
    case LEGACY_NOHIT:    return "rejected (no .data hit)";
    default:              return "error";
    }
}

static LegacyVerdict LegacyLocate(PPROBE_LDR_ENTRY ntdllEntry, void** out, bool* rootWasRed) {
    *out = nullptr;
    *rootWasRed = false;
    LegacyVerdict v = LEGACY_ERROR;

    __try {
        PRB_NODE node = (PRB_NODE)((BYTE*)ntdllEntry + 0xC8);   // hardcoded offset
        int guard = 0;
        while (node->ParentValue & ~(ULONG_PTR)7) {
            node = (PRB_NODE)(node->ParentValue & ~(ULONG_PTR)7);
            if (++guard > 256) __leave;
        }

        *rootWasRed = RB_IS_RED(node);
        if (RB_IS_RED(node)) { v = LEGACY_RED_SKIP; __leave; }

        const ProbeSect* data = SectionByName(".data");
        if (!data) { v = LEGACY_NOHIT; __leave; }

        int count = 0;
        PRB_TREE tmp = nullptr;
        bool multi = false;
        for (size_t off = 0; off + 8 <= data->size; ++off) {     // byte-granular
            ULONG_PTR val;
            memcpy(&val, data->base + off, 8);
            if (val != (ULONG_PTR)node) continue;
            if (count++) { multi = true; break; }
            tmp = (PRB_TREE)(data->base + off);
        }
        if (multi) { v = LEGACY_MULTI; __leave; }
        if (count && tmp && tmp->Root && tmp->Min) { *out = tmp; v = LEGACY_OK; __leave; }
        v = LEGACY_NOHIT;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = LEGACY_ERROR; }
    return v;
}

// ============================================================================
//     the failure that is actually there:  --race
// ============================================================================
//
// FindLdrpModuleBaseAddressIndex() runs with no loader-database lock. It climbs
// a parent chain and reads a colour bit out of a tree another thread may be
// rotating. Initialization is deferred to first use, so the thread it runs on is
// an ordinary one and nothing stops a second thread from loading a DLL at the
// same instant -- which is exactly the shape of a host application that starts
// worker threads and then loads its first memory module.
//
// So: one thread hammers LoadLibrary/FreeLibrary while this thread runs both
// algorithms over and over, and both are tallied. The old one has no
// synchronisation to lose; the new one holds the datatable lock shared across
// its entire critical section, which is the difference being measured.
//

static volatile LONG g_raceStop = 0;

static DWORD WINAPI RaceLoaderThread(LPVOID) {
    static const wchar_t* churn[] = {
        L"version.dll", L"winmm.dll", L"imagehlp.dll",
        L"msimg32.dll", L"cabinet.dll", L"wtsapi32.dll",
    };
    unsigned i = 0;
    while (!g_raceStop) {
        HMODULE h = LoadLibraryW(churn[i++ % (sizeof(churn) / sizeof(churn[0]))]);
        if (h) FreeLibrary(h);
    }
    return 0;
}

// RunRace itself lives below LocateOnce; see the "main" section.

// ============================================================================
//     is the colour gate's premise even true?  --rbtest
// ============================================================================
//
// The library skips discovery when the root is red, and both OPEN-ISSUES and
// stress/README.md describe that as a live nondeterminism. Neither measured it,
// and a repeat-run of one binary cannot: the root's colour is a property of the
// tree's shape, and a console program loads the same modules every time.
//
// So ask ntdll's implementation directly. RtlRbInsertNodeEx and RtlRbRemoveNode
// are exported; drive them over a private tree with pseudo-random keys, exactly
// the way LdrpInsertModuleToIndexLockHeld and RtlInsertModuleBaseAddressIndexNode
// do (descend to find the parent, then hand ntdll the parent and the side), and
// sample the root's colour after every single operation. Whatever answer comes
// back is about ntdll's real red-black code, not about this process's module
// list, and it settles whether the gate can ever fire.
//

typedef VOID(NTAPI* PFN_RB_INSERT)(PRB_TREE, PRB_NODE, BOOLEAN, PRB_NODE);
typedef VOID(NTAPI* PFN_RB_REMOVE)(PRB_TREE, PRB_NODE);

#define RBTEST_MAX 400
struct RbTestNode { RB_NODE n; ULONG_PTR key; bool in; };
static RbTestNode g_rbn[RBTEST_MAX];

static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint64_t NextRand() {
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}

static bool RbTestOrdered(PRB_TREE t) {
    TreeWalk w;
    if (!t->Root) return true;
    WalkInOrder(t->Root, &w);
    if (!w.ok) return false;
    ULONG_PTR prev = 0;
    for (int i = 0; i < w.count; ++i) {
        ULONG_PTR k = CONTAINING_RECORD(w.nodes[i], RbTestNode, n)->key;
        if (i && k <= prev) return false;
        prev = k;
    }
    return true;
}

static void RunRbTest(HMODULE nt, int inserts, int mixedOps) {
    PFN_RB_INSERT ins = (PFN_RB_INSERT)GetProcAddress(nt, "RtlRbInsertNodeEx");
    PFN_RB_REMOVE rem = (PFN_RB_REMOVE)GetProcAddress(nt, "RtlRbRemoveNode");
    printf("\n--- premise check: can ntdll's own RtlRb* leave the root red? ---\n");
    if (!ins || !rem) { printf("  RtlRbInsertNodeEx / RtlRbRemoveNode not exported\n"); return; }
    if (inserts > RBTEST_MAX) inserts = RBTEST_MAX;

    RB_TREE t;
    memset(g_rbn, 0, sizeof(g_rbn));
    for (int i = 0; i < RBTEST_MAX; ++i) g_rbn[i].key = NextRand() >> 3;

    // Seed the first node by hand -- a lone black root with no children -- so
    // the test never depends on how ntdll treats a null Parent.
    g_rbn[0].n.Left = g_rbn[0].n.Right = nullptr;
    g_rbn[0].n.ParentValue = 0;
    g_rbn[0].in = true;
    t.Root = &g_rbn[0].n;
    t.Min = &g_rbn[0].n;

    int live = 1;
    int sampA = 0, redA = 0, sampB = 0, redB = 0;
    int maxRedRunSize = 0, minRedRunSize = 0;

    for (int i = 1; i < inserts; ++i) {
        PRB_NODE cur = t.Root, parent = nullptr;
        BOOLEAN right = FALSE;
        bool dup = false;
        while (cur) {
            parent = cur;
            RbTestNode* c = CONTAINING_RECORD(cur, RbTestNode, n);
            if (g_rbn[i].key < c->key) { cur = cur->Left; right = FALSE; }
            else if (g_rbn[i].key > c->key) { cur = cur->Right; right = TRUE; }
            else { dup = true; break; }
        }
        if (dup) continue;
        ins(&t, parent, right, &g_rbn[i].n);
        g_rbn[i].in = true;
        ++live;
        ++sampA;
        if (RB_IS_RED(t.Root)) {
            ++redA;
            if (!minRedRunSize || live < minRedRunSize) minRedRunSize = live;
            if (live > maxRedRunSize) maxRedRunSize = live;
        }
    }
    bool orderedA = RbTestOrdered(&t);

    for (int op = 0; op < mixedOps; ++op) {
        bool doInsert = (NextRand() & 1) != 0;
        if (live <= 2) doInsert = true;
        if (live >= inserts) doInsert = false;

        if (doInsert) {
            int i = -1;
            for (int k = 0; k < inserts; ++k) {
                int c = (int)(NextRand() % (unsigned)inserts);
                if (!g_rbn[c].in) { i = c; break; }
            }
            if (i < 0) continue;
            g_rbn[i].key = NextRand() >> 3;
            PRB_NODE cur = t.Root, parent = nullptr;
            BOOLEAN right = FALSE;
            bool dup = false;
            while (cur) {
                parent = cur;
                RbTestNode* c = CONTAINING_RECORD(cur, RbTestNode, n);
                if (g_rbn[i].key < c->key) { cur = cur->Left; right = FALSE; }
                else if (g_rbn[i].key > c->key) { cur = cur->Right; right = TRUE; }
                else { dup = true; break; }
            }
            if (dup) continue;
            ins(&t, parent, right, &g_rbn[i].n);
            g_rbn[i].in = true;
            ++live;
        }
        else {
            int i = -1;
            for (int k = 0; k < inserts; ++k) {
                int c = (int)(NextRand() % (unsigned)inserts);
                if (g_rbn[c].in) { i = c; break; }
            }
            if (i < 0) continue;
            rem(&t, &g_rbn[i].n);
            g_rbn[i].in = false;
            --live;
        }
        ++sampB;
        if (t.Root && RB_IS_RED(t.Root)) {
            ++redB;
            if (!minRedRunSize || live < minRedRunSize) minRedRunSize = live;
            if (live > maxRedRunSize) maxRedRunSize = live;
        }
    }
    bool orderedB = RbTestOrdered(&t);

    printf("  RtlRbInsertNodeEx : %p    RtlRbRemoveNode : %p\n", (void*)ins, (void*)rem);
    printf("  insert-only phase : %d samples, root red %d  (%.2f%%)%s\n",
        sampA, redA, sampA ? 100.0 * redA / sampA : 0.0,
        orderedA ? "" : "   *** tree left unordered -- test is invalid ***");
    printf("  insert+remove mix : %d samples, root red %d  (%.2f%%)%s\n",
        sampB, redB, sampB ? 100.0 * redB / sampB : 0.0,
        orderedB ? "" : "   *** tree left unordered -- test is invalid ***");
    printf("  final tree        : %d nodes, in-order %s\n",
        live, (orderedA && orderedB) ? "ascending (test valid)" : "BROKEN");
    if (redA + redB)
        printf("  red at sizes      : %d .. %d nodes\n", minRedRunSize, maxRedRunSize);
    printf("  conclusion        : ntdll's red-black code %s leave the root red,\n",
        (redA + redB) ? "DOES" : "never observed to");
    printf("                      so the library's `if (!node->Red)` gate %s.\n",
        (redA + redB) ? "can and does fire" : "is dead weight, not a live coin flip");
}

// ============================================================================
//                                  main
// ============================================================================

static void PrintIdentity(HMODULE nt) {
    printf("ntdll base      : %p\n", (void*)nt);
    printf("ntdll machine   : 0x%04X  (0x8664=x64, 0xAA64=ARM64)\n", g_ntMachine);
    printf("ntdll build id  : TimeDateStamp 0x%08lX  SizeOfImage 0x%08lX\n",
        (unsigned long)g_ntStamp, (unsigned long)g_ntSize);
}

//
// One complete structural location, steps 1 through 4. Factored out of main so
// --sweep can re-run it after every DLL load and show that the answer does not
// move as the loaded-module set changes -- which is exactly the variable the
// old algorithm is sensitive to.
//
struct LocateResult {
    bool     ok;
    PRB_TREE tree;
    size_t   nodeOff;
    PRB_NODE root;
    bool     rootRed;
    int      nodes;
    int      modules;
    int      offsetsAccepted;
    int      candidates;
    int      candidatesReconciled;
    int      unalignedExtras;
    const ProbeSect* sect;
    const char* why;
};

static bool LocateOnceLockHeld(LocateResult* out, bool verbose) {
    static ModSnapshot snap;                     // ~78 KB; not on the stack
    memset(out, 0, sizeof(*out));
    out->why = "PEB->Ldr walk failed";
    if (!SnapshotModulesLockHeld(&snap)) return false;
    out->modules = snap.count;

    // ---- step 1: discover the node offset -----------------------------------
    OffsetResult accepted[8];
    int acceptedCount = 0;
    OffsetResult probed[64];
    int probedCount = 0;

    for (size_t off = 0x40; off <= 0x1F0; off += 8) {
        OffsetResult r;
        bool ok = EvaluateOffset(&snap, off, &r);
        if (r.root && r.exact && probedCount < 64) probed[probedCount++] = r;
        if (ok && acceptedCount < 8) accepted[acceptedCount++] = r;
    }
    out->offsetsAccepted = acceptedCount;

    if (verbose) {
        printf("\n--- step 1: BaseAddressIndexNode offset, discovered ---\n");
        printf("  modules in PEB->Ldr : %d\n", snap.count);
        printf("  offsets that form a whole-module tree:\n");
        for (int i = 0; i < probedCount; ++i)
            printf("    +0x%-4llX  %3d nodes  height %2d  DllBase-ordered %-3s%s\n",
                (unsigned long long)probed[i].off, probed[i].nodes, probed[i].height,
                probed[i].ascending ? "yes" : "NO",
                probed[i].ascending ? "   <== base-address index"
                                    : "   (mapping-info index)");
        printf("  accepted            : %d\n", acceptedCount);
        printf("  library hardcodes   : +0xC8\n");
    }
    if (acceptedCount != 1) {
        out->why = acceptedCount ? "node offset ambiguous" : "no node offset found";
        return false;
    }

    out->nodeOff = accepted[0].off;
    out->root = accepted[0].root;
    out->rootRed = RB_IS_RED(accepted[0].root);
    PRB_NODE minNode = LeftMost(out->root);

    if (verbose) {
        const wchar_t* rootName = L"(unknown)";
        for (int i = 0; i < snap.count; ++i)
            if ((BYTE*)snap.mods[i].entry + out->nodeOff == (BYTE*)out->root)
                rootName = snap.mods[i].name;
        printf("\n--- step 2: root, without reading its colour ---\n");
        printf("  root node   : %p  (%s -- reported here for the record, never\n",
            (void*)out->root, out->rootRed ? "RED" : "black");
        printf("                consulted as a gate, which is the whole point)\n");
        printf("  root module : %ls\n", rootName);
        printf("  leftmost    : %p  (expected Tree->Min)\n", (void*)minNode);
    }

    // ---- step 3: scan every writable section --------------------------------
    ScanForRoot(out->root, minNode);
    out->candidates = g_candCount;
    out->unalignedExtras = g_unalignedHits;

    if (verbose) {
        printf("\n--- step 3: writable-section scan for {Root, Min} ---\n");
        printf("  aligned hits   : %d   (byte-granular extras: %d)\n",
            g_candCount, g_unalignedHits);
        for (int i = 0; i < g_candCount; ++i)
            printf("    %-8s ntdll+0x%-8llX  Min %s  committed %s\n",
                g_cands[i].sect ? g_cands[i].sect->name : "?", Rva(g_cands[i].tree),
                g_cands[i].minMatches ? "matches" : "DIFFERS",
                g_cands[i].committed ? "yes" : "NO");
    }

    // ---- step 4: reconcile ---------------------------------------------------
    int reconciledIdx = -1;
    for (int i = 0; i < g_candCount; ++i) {
        Reconcile r;
        ReconcileCandidate(g_cands[i].tree, out->nodeOff, &snap, &r);
        g_cands[i].reconciled = r.ok;
        g_cands[i].nodes = r.nodes;
        if (r.ok) { ++out->candidatesReconciled; if (reconciledIdx < 0) reconciledIdx = i; }

        if (verbose) {
            printf("\n--- step 4: reconcile ntdll+0x%llX against PEB->Ldr ---\n",
                Rva(g_cands[i].tree));
            printf("  nodes / modules  : %d / %d\n", r.nodes, r.modules);
            printf("  node set equal   : %s\n", r.setEqual ? "yes" : "NO");
            printf("  DllBase ascending: %s\n", r.ascending ? "yes" : "NO");
            printf("  parent links     : %s\n", r.parentsOk ? "consistent" : "INCONSISTENT");
            printf("  Tree->Min        : %s\n", r.minOk ? "is the leftmost node" : "WRONG");
            printf("  by-base search   : %s\n", r.searchable ? "finds every module" : "MISSES A MODULE");
            printf("  height / bound   : %d / %d\n", r.height, r.heightBound);
            printf("  verdict          : %s\n", r.why);
        }
    }

    if (out->candidatesReconciled != 1) {
        out->why = out->candidatesReconciled ? "more than one candidate reconciled"
                                             : "no candidate reconciled";
        return false;
    }

    out->tree = g_cands[reconciledIdx].tree;
    out->sect = g_cands[reconciledIdx].sect;
    out->nodes = g_cands[reconciledIdx].nodes;
    out->ok = true;
    out->why = "located";
    return true;
}

//
// One shared acquisition covers the module snapshot, the offset discovery, the
// climb, the section scan and the reconciliation, so every one of them sees the
// same loader database. The scan is the only part that does not strictly need
// the lock, and it costs well under a millisecond, so it is not worth splitting
// the critical section and reintroducing the race.
//
static bool LocateOnce(LocateResult* out, bool verbose) {
    LoaderDbLock();
    bool ok = LocateOnceLockHeld(out, verbose);
    LoaderDbUnlock();
    return ok;
}

// ============================================================================
//     sweep: how the two algorithms behave as the module set changes
// ============================================================================
//
// The point of the sweep. The root's colour is a function of the shape of the
// tree, which is a function of which modules are loaded and where -- so a plain
// repeat-run of one binary can measure the same colour every time and prove
// nothing. Loading DLLs one at a time walks the process through many different
// module sets inside a single run, and both algorithms are asked again after
// each one. That is the measurement that says how often the colour gate costs
// the library its capability in a real host process.
//
static const wchar_t* kSweepDlls[] = {
    L"version.dll",  L"winmm.dll",    L"imagehlp.dll", L"msimg32.dll",
    L"wtsapi32.dll", L"mpr.dll",      L"cabinet.dll",  L"secur32.dll",
    L"netapi32.dll", L"userenv.dll",  L"dnsapi.dll",   L"iphlpapi.dll",
    L"ws2_32.dll",   L"crypt32.dll",  L"wintrust.dll", L"shlwapi.dll",
    L"ole32.dll",    L"oleaut32.dll", L"gdi32.dll",    L"user32.dll",
    L"advapi32.dll", L"rpcrt4.dll",   L"setupapi.dll", L"cfgmgr32.dll",
    L"powrprof.dll", L"winsta.dll",   L"credui.dll",   L"dwmapi.dll",
    L"uxtheme.dll",  L"comctl32.dll", L"propsys.dll",  L"urlmon.dll",
    L"wininet.dll",  L"winhttp.dll",  L"psapi.dll",    L"dbghelp.dll",
    L"ntdsapi.dll",  L"avrt.dll",     L"bcrypt.dll",   L"ncrypt.dll",
    L"sspicli.dll",  L"profapi.dll",  L"clbcatq.dll",  L"msctf.dll",
    L"oleacc.dll",   L"shell32.dll",  L"comdlg32.dll", L"mswsock.dll",
};

static void RunSweep(PPROBE_LDR_ENTRY ntdllEntry, PRB_TREE expected, bool quiet) {
    int samples = 0, red = 0, legacyOk = 0, legacyOther = 0;
    int probeOk = 0, probeMoved = 0;

    if (!quiet) {
        printf("\n--- sweep: both algorithms after every DLL load ---\n");
        printf("  step  modules  root    legacy                probe\n");
    }

    for (int i = -1; i < (int)(sizeof(kSweepDlls) / sizeof(kSweepDlls[0])); ++i) {
        if (i >= 0) {
            if (GetModuleHandleW(kSweepDlls[i])) continue;      // already in
            if (!LoadLibraryW(kSweepDlls[i])) continue;         // not on this SKU
        }

        void* lt = nullptr; bool lr = false;
        LegacyVerdict lv = LegacyLocate(ntdllEntry, &lt, &lr);
        LocateResult pr;
        bool pok = LocateOnce(&pr, false);

        ++samples;
        if (lr) ++red;
        if (lv == LEGACY_OK) ++legacyOk; else ++legacyOther;
        if (pok) ++probeOk;
        if (pok && pr.tree != expected) ++probeMoved;

        if (!quiet)
            printf("  %4d  %7d  %-6s  %-20s  %s\n",
                samples, pr.modules, lr ? "RED" : "black",
                lv == LEGACY_OK ? "found" :
                lv == LEGACY_RED_SKIP ? "SKIPPED (root red)" :
                lv == LEGACY_MULTI ? "rejected (>1 hit)" :
                lv == LEGACY_NOHIT ? "rejected (no hit)" : "error",
                !pok ? "FAILED" : pr.tree == expected ? "located, same address" : "MOVED");
    }

    printf("\n  sweep summary over %d module-set states:\n", samples);
    printf("    root observed RED       : %d  (%.1f%%)\n",
        red, samples ? 100.0 * red / samples : 0.0);
    printf("    legacy algorithm found  : %d of %d  (%.1f%%)\n",
        legacyOk, samples, samples ? 100.0 * legacyOk / samples : 0.0);
    printf("    this probe located      : %d of %d  (%.1f%%), address moved %d time%s\n",
        probeOk, samples, samples ? 100.0 * probeOk / samples : 0.0,
        probeMoved, probeMoved == 1 ? "" : "s");
}

//
// The --race tally. See the "the failure that is actually there" section above
// for what it is measuring and why; it lives down here only because it needs
// LocateOnce.
//
#define RACE_LOADERS 3

static void RunRace(PPROBE_LDR_ENTRY ntdllEntry, PRB_TREE expected, int iterations) {
    printf("\n--- race: both algorithms while %d threads load and free ---\n", RACE_LOADERS);

    g_raceStop = 0;
    HANDLE th[RACE_LOADERS];
    int started = 0;
    for (int i = 0; i < RACE_LOADERS; ++i) {
        th[i] = CreateThread(nullptr, 0, RaceLoaderThread, nullptr, 0, nullptr);
        if (th[i]) ++started;
    }
    if (!started) { printf("  could not start a loader thread\n"); return; }
    Sleep(20);

    int lOk = 0, lRed = 0, lMulti = 0, lNoHit = 0, lErr = 0, lWrong = 0;
    int pOk = 0, pOk3 = 0, pMoved = 0, pFail = 0;
    const char* pFirstFail = "";

    for (int i = 0; i < iterations; ++i) {
        void* lt = nullptr; bool lr = false;
        switch (LegacyLocate(ntdllEntry, &lt, &lr)) {
        case LEGACY_OK:       ++lOk; if (lt != (void*)expected) ++lWrong; break;
        case LEGACY_RED_SKIP: ++lRed; break;
        case LEGACY_MULTI:    ++lMulti; break;
        case LEGACY_NOHIT:    ++lNoHit; break;
        default:              ++lErr; break;
        }

        // First attempt, and then up to three, because "fail closed and try
        // again" is the cheap mitigation and it is worth knowing what it buys.
        LocateResult pr;
        bool got = false;
        for (int attempt = 0; attempt < 3; ++attempt) {
            got = LocateOnce(&pr, false);
            if (attempt == 0) {
                if (!got) { ++pFail; if (!*pFirstFail) pFirstFail = pr.why; }
                else if (pr.tree != expected) ++pMoved;
                else ++pOk;
            }
            if (got) break;
        }
        if (got && pr.tree == expected) ++pOk3;
    }

    //
    // The gate itself, sampled as fast as the CPU will do it. The `.data` scan
    // dominates a full legacy run, so the window that actually matters -- the
    // unlocked climb plus the colour read -- gets sampled only rarely above.
    // Here nothing else is in the loop, so if a rotating tree can ever be caught
    // with a red root, this is where it shows up.
    //
    long long colourSamples = 0, colourRed = 0, climbFailed = 0;
    ULONGLONG deadline = GetTickCount64() + 2000;
    while (GetTickCount64() < deadline) {
        for (int k = 0; k < 1000; ++k) {
            __try {
                PRB_NODE n = (PRB_NODE)((BYTE*)ntdllEntry + 0xC8);
                int guard = 0;
                while (n->ParentValue & ~(ULONG_PTR)7) {
                    n = (PRB_NODE)(n->ParentValue & ~(ULONG_PTR)7);
                    if (++guard > 256) break;
                }
                ++colourSamples;
                if (guard > 256) ++climbFailed;
                else if (RB_IS_RED(n)) ++colourRed;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { ++colourSamples; ++climbFailed; }
        }
    }

    g_raceStop = 1;
    for (int i = 0; i < RACE_LOADERS; ++i)
        if (th[i]) { WaitForSingleObject(th[i], 10000); CloseHandle(th[i]); }

    printf("  iterations, each algorithm run once  : %d\n", iterations);
    printf("  legacy : found %d, root-red skip %d, >1 hit %d, no hit %d, faulted %d\n",
        lOk, lRed, lMulti, lNoHit, lErr);
    printf("  legacy : wrong address when it answered : %d\n", lWrong);
    printf("  legacy success rate                  : %.2f%%\n",
        iterations ? 100.0 * lOk / iterations : 0.0);
    printf("  probe  : located-same %d, moved %d, failed %d%s%s\n",
        pOk, pMoved, pFail, pFail ? "   first reason: " : "", pFail ? pFirstFail : "");
    printf("  probe success rate                   : %.2f%% first try, %.2f%% within 3\n",
        iterations ? 100.0 * pOk / iterations : 0.0,
        iterations ? 100.0 * pOk3 / iterations : 0.0);
    printf("  unlocked climb+colour, 2 s at full rate:\n");
    printf("    samples %lld, root observed RED %lld, climb failed %lld\n",
        colourSamples, colourRed, climbFailed);
}

int main(int argc, char** argv) {
    bool survey = false, quiet = false, legacyOnly = false, sweep = false;
    bool rbtest = false, useLock = true, behave = true;
    int  race = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--survey")) survey = true;
        else if (!strcmp(argv[i], "--quiet")) quiet = true;
        else if (!strcmp(argv[i], "--legacy")) legacyOnly = true;
        else if (!strcmp(argv[i], "--sweep")) sweep = true;
        else if (!strcmp(argv[i], "--rbtest")) rbtest = true;
        else if (!strcmp(argv[i], "--race")) {
            race = 400;
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9')
                race = atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--nolock")) useLock = false;
        else if (!strcmp(argv[i], "--nobehave")) behave = false;
    }

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) { printf("no ntdll\n"); return 2; }
    InitImage(nt);
    InitFunctionTable(nt);

    g_acqExcl = (PFN_SRW)GetProcAddress(nt, "RtlAcquireSRWLockExclusive");
    g_acqShared = (PFN_SRW)GetProcAddress(nt, "RtlAcquireSRWLockShared");
    g_relExcl = (PFN_SRW)GetProcAddress(nt, "RtlReleaseSRWLockExclusive");
    g_relShared = (PFN_SRW)GetProcAddress(nt, "RtlReleaseSRWLockShared");
    if (!g_acqExcl || !g_acqShared || !g_relExcl || !g_relShared) {
        printf("could not resolve the exported SRW routines\n");
        return 2;
    }
    g_acqTargets[g_acqTargetCount++] = (void*)g_acqExcl;
    g_acqTargets[g_acqTargetCount++] = (void*)g_acqShared;
    { void* t = nullptr;
      if (IsEcFastForward((void*)g_acqExcl, &t))   g_acqTargets[g_acqTargetCount++] = t;
      if (IsEcFastForward((void*)g_acqShared, &t)) g_acqTargets[g_acqTargetCount++] = t; }

    if (!quiet) {
        printf("================= probe_baseindex report =================\n");
#if defined(_M_ARM64)
        printf("built for       : arm64\n");
#elif defined(_M_X64)
        printf("built for       : x64\n");
#else
        printf("built for       : (unsupported -- 64-bit only)\n");
#endif
        PrintIdentity(nt);
        printf("sections        : %d  (.pdata gives %llu function starts)\n",
            g_sectCount, (unsigned long long)g_fnCount);
    }

    // ---- ntdll's own loader entry, the seed for every structural step -------
    static ModSnapshot snap;                     // ~78 KB; not on the stack
    PPROBE_LDR_ENTRY ntdllEntry = nullptr;
    if (!SnapshotModules(&snap)) { printf("PEB->Ldr walk failed\n"); return 2; }
    for (int i = 0; i < snap.count; ++i)
        if (snap.mods[i].base == (void*)nt) { ntdllEntry = snap.mods[i].entry; break; }
    if (!ntdllEntry) { printf("no LDR entry for ntdll\n"); return 2; }

    // ---- the library's current algorithm, for comparison --------------------
    void* legacyTree = nullptr;
    bool  legacyRootRed = false;
    LegacyVerdict legacy = LegacyLocate(ntdllEntry, &legacyTree, &legacyRootRed);

    if (legacyOnly) {
        if (quiet) {
            printf("legacy=%s root=%s tree=%s\n",
                legacy == LEGACY_OK ? "OK" :
                legacy == LEGACY_RED_SKIP ? "RED-SKIP" :
                legacy == LEGACY_MULTI ? "MULTI" :
                legacy == LEGACY_NOHIT ? "NOHIT" : "ERR",
                legacyRootRed ? "red" : "black",
                legacyTree ? "found" : "null");
        }
        else {
            printf("\n--- library's current algorithm (Initialize.cpp) ---\n");
            printf("  tree root colour : %s\n", legacyRootRed ? "RED" : "black");
            printf("  verdict          : %s\n", LegacyName(legacy));
            if (legacyTree)
                printf("  address          : %p  (ntdll+0x%llX)\n", legacyTree, Rva(legacyTree));
            printf("=========================================================\n");
        }
        return legacy == LEGACY_OK ? 0 : 1;
    }

    // ---- LdrpModuleDatatableLock -------------------------------------------
    int lockAgree = 0, lockDecoded = 0;
    if (useLock) {
        g_lock = LocateDatatableLock(nt, &lockAgree, &lockDecoded);
        if (g_lock) g_lockVerified = VerifyLockByCausality(g_lock);
        if (g_lock && !g_lockVerified) g_lock = nullptr;   // fail closed
    }
    if (!quiet) {
        printf("\n--- ntdll!LdrpModuleDatatableLock (lockprobe technique) ---\n");
        if (!useLock) printf("  skipped (--nolock); walks below are unsynchronised\n");
        else if (g_lock)
            printf("  ntdll+0x%llX  (%d of %d donors decoded, %d agreed) causality VERIFIED\n",
                Rva(g_lock), lockDecoded,
                (int)(sizeof(kLockDonors) / sizeof(kLockDonors[0])), lockAgree);
        else
            printf("  NOT LOCATED (%d donors decoded, %d agreed) -- walks are unsynchronised\n",
                lockDecoded, lockAgree);
    }

    // ---- steps 1 to 4 --------------------------------------------------------
    LocateResult lr;
    if (!LocateOnce(&lr, !quiet)) {
        if (quiet) printf("result=FAIL reason=%s legacy=%s\n", lr.why,
            legacy == LEGACY_OK ? "OK" : legacy == LEGACY_RED_SKIP ? "RED-SKIP" : "other");
        else printf("\nRESULT: NOT LOCATED -- %s\n", lr.why);
        return 1;
    }

    PRB_TREE located = lr.tree;
    size_t   nodeOff = lr.nodeOff;

    // ---- behavioural verification -------------------------------------------
    BehaveResult bh;
    memset(&bh, 0, sizeof(bh));
    if (behave) {
        BehaviourTest(located, nodeOff, &bh);
        if (!quiet) {
            printf("\n--- behavioural verification ---\n");
            if (!bh.ran) printf("  skipped: %s\n", bh.why);
            else {
                printf("  probe DLL        : %ls -> %p\n", bh.dll, bh.loadedBase);
                printf("  nodes before/after load/after free : %d / %d / %d\n",
                    bh.nodesBefore, bh.nodesAfterLoad, bh.nodesAfterFree);
                printf("  node appeared    : %s\n", bh.appeared ? "yes" : "NO");
                printf("  module unloaded  : %s\n", bh.freedForReal ? "yes" : "no (still referenced)");
                printf("  node disappeared : %s\n", bh.disappeared ? "yes" : "NO");
                printf("  verdict          : %s\n", bh.why);
            }
        }
    }

    // ---- survey --------------------------------------------------------------
    bool surveyAgrees = false;
    if (survey) {
        void* ins = (void*)GetProcAddress(nt, "RtlRbInsertNodeEx");
        void* rem = (void*)GetProcAddress(nt, "RtlRbRemoveNode");
        void* t = nullptr;
        if (ins) { g_rbTargets[g_rbTargetCount++] = ins; g_rbInsert[g_rbInsertCount++] = ins;
                   if (IsEcFastForward(ins, &t)) { g_rbTargets[g_rbTargetCount++] = t; g_rbInsert[g_rbInsertCount++] = t; } }
        if (rem) { g_rbTargets[g_rbTargetCount++] = rem;
                   if (IsEcFastForward(rem, &t)) g_rbTargets[g_rbTargetCount++] = t; }
        SurveyRbCallSites();

        if (!quiet) {
            printf("\n--- survey: every RtlRbInsertNodeEx / RtlRbRemoveNode call site ---\n");
            printf("  RtlRbInsertNodeEx : %p\n", ins);
            printf("  RtlRbRemoveNode   : %p\n", rem);
            printf("  call sites found  : %d   (first argument decoded at %d of them)\n",
                g_rbSitesTotal, g_rbSitesDecoded);
            printf("  distinct trees    : %d\n", g_rbCount);
        }
        for (int i = 0; i < g_rbCount; ++i) {
            bool isOurs = (g_rb[i].tree == (void*)located);
            if (isOurs) surveyAgrees = true;
            if (!quiet) {
                const ProbeSect* s = SectionOf(g_rb[i].tree);
                printf("    %-8s ntdll+0x%-8llX  %2d site%s (%d insert, %d remove)%s\n",
                    s ? s->name : "?", Rva(g_rb[i].tree), g_rb[i].sites,
                    g_rb[i].sites == 1 ? " " : "s", g_rb[i].insertSites, g_rb[i].removeSites,
                    isOurs ? "   <== LdrpModuleBaseAddressIndex (reconciled)" : "");
            }
        }
    }

    // ---- library-side validation --------------------------------------------
    MEMORY_BASIC_INFORMATION mbi{};
    bool queried = VirtualQuery(located, &mbi, sizeof(mbi)) != 0;
    const DWORD writableMask = PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    bool wouldAccept = ((ULONG_PTR)located & 7) == 0 && InNtdll(located) &&
        queried && mbi.State == MEM_COMMIT && (mbi.Protect & writableMask) != 0;

    bool ok = wouldAccept && (!behave || !bh.ran || bh.ok);

    if (quiet) {
        printf("result=%s tree=ntdll+0x%llX nodeoff=0x%llX nodes=%d lock=%s behave=%s legacy=%s%s\n",
            ok ? "OK" : "FAIL",
            Rva(located), (unsigned long long)nodeOff, lr.nodes,
            !useLock ? "skipped" : g_lock ? "OK" : "NOT-LOCATED",
            !behave ? "skipped" : !bh.ran ? "n/a" : bh.ok ? "OK" : "FAIL",
            legacy == LEGACY_OK ? "OK" : legacy == LEGACY_RED_SKIP ? "RED-SKIP" :
            legacy == LEGACY_MULTI ? "MULTI" : legacy == LEGACY_NOHIT ? "NOHIT" : "ERR",
            (legacy == LEGACY_OK && legacyTree != (void*)located) ? " legacy-DISAGREES" : "");
        if (sweep) RunSweep(ntdllEntry, located, true);
        return ok ? 0 : 1;
    }

    // ---- premise check, race, sweep ------------------------------------------
    if (rbtest) RunRbTest(nt, RBTEST_MAX, 200000);
    if (race) RunRace(ntdllEntry, located, race);

    // The sweep goes last, because it deliberately changes the module set.
    if (sweep) RunSweep(ntdllEntry, located, false);

    printf("\n--- comparison with the library's current algorithm ---\n");
    printf("  root colour this run : %s\n", legacyRootRed ? "RED" : "black");
    printf("  legacy verdict       : %s\n", LegacyName(legacy));
    printf("  legacy address       : ");
    if (legacyTree) printf("ntdll+0x%llX%s\n", Rva(legacyTree),
        legacyTree == (void*)located ? "  (same as this probe)" : "  *** DIFFERENT ***");
    else printf("none -- MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX would be off\n");

    printf("\n--- summary ---\n");
    printf("LdrpModuleBaseAddressIndex : ntdll+0x%llX  (%p)\n", Rva(located), (void*)located);
    printf("  section                  : %s\n", lr.sect ? lr.sect->name : "?");
    printf("  node offset in LDR entry : 0x%llX\n", (unsigned long long)nodeOff);
    printf("  modules reconciled       : %d\n", lr.nodes);
    printf("  datatable lock           : %s\n",
        !useLock ? "not used" : g_lock ? "held shared during every walk" : "NOT LOCATED");
    printf("  behavioural test         : %s\n",
        !behave ? "skipped" : !bh.ran ? "not run" : bh.ok ? "PASSED" : "FAILED");
    if (survey)
        printf("  RtlRb* call-site survey  : %s\n", surveyAgrees
            ? "agrees (independent decode of the same address)"
            : "no call site decoded to this address");
    printf("  library would accept     : %s\n", wouldAccept ? "yes" : "NO");

    printf("\nRESULT: %s\n", ok
        ? "LOCATED and VERIFIED -- deterministic, no dependence on the root's colour"
        : "NOT VERIFIED -- do not use this address");
    printf("=========================================================\n");
    return ok ? 0 : 1;
}
