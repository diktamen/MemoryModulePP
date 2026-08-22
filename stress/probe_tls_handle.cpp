//
// probe_tls_handle -- locate and verify ntdll!LdrpHandleTlsData at runtime,
// without a hardcoded RVA, a PDB, or a byte signature for the function body.
//
// Why we want it: a memory module with a TLS directory has no TLS storage until
// ntdll's LdrpHandleTlsData is run over its LDR_DATA_TABLE_ENTRY -- that is what
// allocates the module's TLS index, links an LDRP_TLS_ENTRY into ntdll's
// LdrpTlsList, and makes ThreadLocalStoragePointer[index] resolve. The function
// is not exported. MemoryModulePP finds it today with a multi-stage byte scan
// (MemoryModule/MmpLdrpTls.cpp); see OPEN-ISSUES.md items 4 and 6.
//
// How this finds it instead. Everything below is either a documented PE/ABI
// structure or an exported ntdll routine; nothing is a signature of the
// function's own instructions.
//
//   The name survives in the binary. MSVC compiles
//
//       __try { ... } __except (LdrpLogError(..., "LdrpHandleTlsData"), ...)
//
//   into a separate filter funclet that loads the address of the literal. So
//   ntdll's .rdata carries the string "LdrpHandleTlsData", and exactly one
//   funclet references it. That is a *name*, the closest thing to a symbol a
//   PDB-less process can read, and it is not a pattern over the function's code.
//
//   Getting from the funclet to the function it belongs to is pure ABI:
//
//     anchor 1  the funclet is named by a C scope-table record
//               { Begin, End, Handler, Target } that lives in read-only data.
//               Find the record, take Begin -- an address inside the parent --
//               and ask ntdll!RtlLookupFunctionEntry which function owns it.
//
//     anchor 2  the same association, derived the other way round: walk the
//               image's runtime-function tables, parse each function's unwind
//               data, and find the function whose scope table names the funclet.
//               Independent of where in .rdata the record happens to sit.
//
//   Two corroborators that do not involve the string at all:
//
//     anchor 3  LdrpTlsList is found structurally -- it is the only circular
//               list in ntdll's writable data holding a node that mirrors this
//               process's own TLS directory -- and then the functions that
//               reference it, and *their* callers, are enumerated. The answer
//               has to be one of those callers, because it is what asks for a
//               TLS entry to be allocated.
//
//     anchor 4  reachability: walking direct calls upward from the candidate has
//               to arrive at a named, exported loader entry point.
//
//   And a behavioural proof, in the spirit of lockprobe's causality test:
//
//     Fabricate an in-memory image whose only content is a TLS directory
//     pointing at a template we chose, hand it to the candidate exactly the way
//     the library does, and require that it allocates a TLS index, writes it
//     through our AddressOfIndex, appends one node to LdrpTlsList describing our
//     directory, and makes our template bytes appear at
//     ThreadLocalStoragePointer[index]. Nothing but the real function does that.
//     A second fabricated module must then get the next index.
//
// --survey decodes and prints every one of those derivations, groups them by the
// address each yields, and lists the sets they were chosen from, so the anchors
// can be re-measured on an unfamiliar build rather than assumed.
//
// One result worth knowing before reading the output: on an ARM64X host, an x64
// build finds the address and then cannot use it. ntdll's loader is compiled
// twice there and the copy an x64 process can see is ARM64EC; a transition from
// emulated x64 into ARM64EC code needs the callee's entry thunk, and ntdll's
// internal loader helpers have none. The call is not a catchable fault -- the
// emulator ends the process with STATUS_WX86_INTERNAL_ERROR. So the probe makes
// the call from a child process, reports callability separately from
// correctness, and exits 3 rather than pretending either answer.
//
// Build (see stress/README.md; do not use build.cmd, it rebuilds the library):
//   cl /nologo /std:c++17 /O2 /MT /EHsc probe_tls_handle.cpp /link /OUT:probe_tls_handle.exe
//
// Exit code: 0 = located and behaviourally verified, 1 = not located or the
//            behaviour did not match, 2 = setup failure, 3 = located but not
//            callable from this build's instruction set (ARM64X, see below).
//

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>

// ---------------------------------------------------------------------------
// This gives the probe process its own TLS directory. Anchor 3 needs one: it
// recognises ntdll's LdrpTlsList by finding the node that describes *us*.
// The pragma keeps the directory in the image even if the optimiser decides the
// variable itself is uninteresting -- without _tls_used there is no directory,
// and the anchor silently has nothing to match against.
// ---------------------------------------------------------------------------
thread_local volatile int g_ownTlsSlot = 0x5AA5;
#pragma comment(linker, "/INCLUDE:_tls_used")

static bool g_survey = false;

#define PRN(...)  do { printf(__VA_ARGS__); fflush(stdout); } while (0)

// ===========================================================================
// ntdll image model
// ===========================================================================

static const uint8_t* g_nt;
static size_t         g_ntSize;
static WORD           g_ntMachine;
static DWORD          g_ntStamp;

struct Section { char name[9]; uint32_t rva, size; bool exec, write; };
static Section g_sec[48];
static int     g_secCount;

//
// ARM64X images carry a code map that says which ranges hold ARM64, ARM64EC and
// x64 code. On such a build the loader is compiled twice and the string is
// referenced from both copies, so a probe that ignores the map gets two
// disagreeing answers. We must take the copy that matches the code we ourselves
// run. On a single-architecture ntdll there is no map and no ambiguity.
//
enum Flavour { FL_ANY = -1, FL_ARM64 = 0, FL_ARM64EC = 1, FL_X64 = 2 };
struct CodeRange { uint32_t rva, size; Flavour flavour; };
static CodeRange g_range[64];
static int       g_rangeCount;
static Flavour   g_ourFlavour = FL_ANY;
static uint32_t  g_flavourWitness;              // export the flavour was read from

static const char* FlavourName(Flavour f) {
    switch (f) {
    case FL_ARM64:   return "arm64";
    case FL_ARM64EC: return "arm64ec";
    case FL_X64:     return "x64";
    default:         return "any";
    }
}

//
// A runtime-function table. An ARM64X ntdll has two: the one the exception
// directory points at (the format matching the view we are running in) and the
// other architecture's, reachable through the ARM64EC metadata's ExtraRFETable.
// Both must be read, because the funclet we care about may live in either.
//
struct FnTable { uint32_t rva, size; size_t stride; bool x64fmt; };
static FnTable g_tab[2];
static int     g_tabCount;

// merged, ascending list of every function start in the image
static uint32_t* g_fnStart;
static size_t    g_fnCount;

typedef struct _ARM64EC_METADATA {
    ULONG Version, CodeMap, CodeMapCount, CodeRangesToEntryPoints, RedirectionMetadata;
    ULONG d0, d1, d2, d3, d4;
    ULONG AlternateEntryPoint, AuxiliaryIAT, CodeRangesToEntryPointsCount;
    ULONG RedirectionMetadataCount, GetX64InformationFunctionPointer;
    ULONG SetX64InformationFunctionPointer, ExtraRFETable, ExtraRFETableSize;
} ARM64EC_METADATA;

static const char* SectionOf(uint32_t rva) {
    for (int i = 0; i < g_secCount; ++i)
        if (rva >= g_sec[i].rva && rva < g_sec[i].rva + g_sec[i].size) return g_sec[i].name;
    return "?";
}
static bool InExecSection(uint32_t rva) {
    for (int i = 0; i < g_secCount; ++i)
        if (g_sec[i].exec && rva >= g_sec[i].rva && rva < g_sec[i].rva + g_sec[i].size) return true;
    return false;
}

static Flavour FlavourOf(uint32_t rva) {
    for (int i = 0; i < g_rangeCount; ++i)
        if (rva >= g_range[i].rva && rva < g_range[i].rva + g_range[i].size) return g_range[i].flavour;
    return FL_ANY;
}

static int CompareU32(const void* a, const void* b) {
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static void ReadCodeMap(PIMAGE_NT_HEADERS h) {
    IMAGE_DATA_DIRECTORY& lc = h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!lc.VirtualAddress || lc.Size < 0xD0) return;

    const uint8_t* cfg = g_nt + lc.VirtualAddress;
    ULONG declared; memcpy(&declared, cfg, 4);
    if (declared < 0xD0) return;

    ULONGLONG chpe; memcpy(&chpe, cfg + 0xC8, 8);       // CHPEMetadataPointer
    if (chpe <= (ULONGLONG)g_nt || chpe >= (ULONGLONG)g_nt + g_ntSize) return;

    const ARM64EC_METADATA* m = (const ARM64EC_METADATA*)chpe;
    if (!m->CodeMap || m->CodeMap >= g_ntSize || m->CodeMapCount > 256) return;

    const ULONG* cm = (const ULONG*)(g_nt + m->CodeMap);
    for (ULONG i = 0; i < m->CodeMapCount && g_rangeCount < 64; ++i) {
        ULONG start = cm[i * 2], len = cm[i * 2 + 1];
        CodeRange& r = g_range[g_rangeCount++];
        r.rva = start & ~3u;
        r.size = len;
        r.flavour = (Flavour)(start & 3);
    }

    // The other architecture's runtime-function table.
    if (g_tabCount == 1 && m->ExtraRFETable && m->ExtraRFETableSize &&
        m->ExtraRFETable < g_ntSize) {
        FnTable& t = g_tab[g_tabCount++];
        t.rva = m->ExtraRFETable;
        t.size = m->ExtraRFETableSize;
        t.x64fmt = !g_tab[0].x64fmt;                    // always the opposite format
        t.stride = t.x64fmt ? 12 : 8;
    }
}

static bool InitNtdll(HMODULE nt) {
    g_nt = (const uint8_t*)nt;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)(g_nt + dos->e_lfanew);
    if (h->Signature != IMAGE_NT_SIGNATURE) return false;

    g_ntSize = h->OptionalHeader.SizeOfImage;
    g_ntMachine = h->FileHeader.Machine;
    g_ntStamp = h->FileHeader.TimeDateStamp;

    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(h);
    for (int i = 0; i < h->FileHeader.NumberOfSections && g_secCount < 48; ++i, ++s) {
        Section& d = g_sec[g_secCount++];
        memcpy(d.name, s->Name, 8); d.name[8] = 0;
        d.rva = s->VirtualAddress;
        d.size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        d.exec = (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        d.write = (s->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    IMAGE_DATA_DIRECTORY& ex = h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ex.VirtualAddress && ex.Size) {
        FnTable& t = g_tab[g_tabCount++];
        t.rva = ex.VirtualAddress;
        t.size = ex.Size;
        t.x64fmt = (g_ntMachine == IMAGE_FILE_MACHINE_AMD64);
        t.stride = t.x64fmt ? 12 : 8;
    }
    ReadCodeMap(h);

    size_t cap = 0;
    for (int i = 0; i < g_tabCount; ++i) cap += g_tab[i].size / g_tab[i].stride;
    g_fnStart = (uint32_t*)malloc(cap * sizeof(uint32_t));
    if (!g_fnStart) return false;

    for (int i = 0; i < g_tabCount; ++i) {
        size_t n = g_tab[i].size / g_tab[i].stride;
        const uint8_t* e = g_nt + g_tab[i].rva;
        for (size_t k = 0; k < n; ++k) {
            uint32_t begin; memcpy(&begin, e + k * g_tab[i].stride, 4);
            if (!begin || begin >= g_ntSize || !InExecSection(begin)) continue;
            g_fnStart[g_fnCount++] = begin;
        }
    }
    // One ascending list out of both tables; LookupRecord still goes back to the
    // table a given start came from, so nothing needs the pairing kept here.
    qsort(g_fnStart, g_fnCount, sizeof(uint32_t), CompareU32);
    return g_fnCount != 0;
}

static bool IsFunctionStart(uint32_t rva) {
    size_t lo = 0, hi = g_fnCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_fnStart[mid] == rva) return true;
        if (g_fnStart[mid] < rva) lo = mid + 1; else hi = mid;
    }
    return false;
}

// greatest function start <= rva, using the merged table
static uint32_t TableEnclosing(uint32_t rva) {
    if (!g_fnCount || rva < g_fnStart[0]) return 0;
    size_t lo = 0, hi = g_fnCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_fnStart[mid] <= rva) lo = mid + 1; else hi = mid;
    }
    uint32_t start = g_fnStart[lo - 1];
    uint32_t next = (lo < g_fnCount) ? g_fnStart[lo] : (uint32_t)g_ntSize;
    if (rva >= next) return 0;
    if (next - start > 0x20000) return 0;               // implausible extent: a gap
    return start;
}

//
// Which function owns an address. ntdll!RtlLookupFunctionEntry is the authority
// -- it is exported, documented, and on ARM64X it already knows which of the two
// tables applies to the view we are running in. The merged table is the fallback
// for addresses the running view will not resolve, which is how --survey can
// still show the copy belonging to the other architecture.
//
static uint32_t FunctionStartOf(uint32_t rva) {
    if (rva >= g_ntSize) return 0;
    DWORD64 base = 0;
    const uint32_t* rf = nullptr;
    __try {
        rf = (const uint32_t*)RtlLookupFunctionEntry((DWORD64)(g_nt + rva), &base, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { rf = nullptr; }
    if (rf) {
        uint32_t begin = rf[0];
        if (begin && begin <= rva && begin < g_ntSize) return begin;
    }
    return TableEnclosing(rva);
}

// The runtime-function record for a function start, in whichever table holds it.
static bool LookupRecord(uint32_t fnRva, const uint8_t** rec, bool* x64fmt) {
    for (int i = 0; i < g_tabCount; ++i) {
        size_t n = g_tab[i].size / g_tab[i].stride;
        const uint8_t* e = g_nt + g_tab[i].rva;
        size_t lo = 0, hi = n;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            uint32_t b; memcpy(&b, e + mid * g_tab[i].stride, 4);
            if (b == fnRva) { *rec = e + mid * g_tab[i].stride; *x64fmt = g_tab[i].x64fmt; return true; }
            if (b < fnRva) lo = mid + 1; else hi = mid;
        }
    }
    return false;
}

// ===========================================================================
// exports
// ===========================================================================

struct Export { const char* name; uint32_t rva; };
static Export* g_exp;
static int     g_expCount;

//
// On ARM64X an x64 caller's GetProcAddress lands on a fast-forward thunk rather
// than a function body:
//     48 8b c4  48 89 58 20  55  5d  e9 <rel32>
// Following it is what makes the export table usable as an anchor there.
//
static bool IsEcFastForward(const void* p, uint32_t* targetRva) {
    static const uint8_t sig[] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x20,0x55,0x5d,0xe9 };
    const uint8_t* b = (const uint8_t*)p;
    if ((size_t)(b - g_nt) + 14 > g_ntSize) return false;
    if (memcmp(b, sig, sizeof(sig)) != 0) return false;
    int32_t rel; memcpy(&rel, b + 10, 4);
    if (targetRva) *targetRva = (uint32_t)((b + 14 + rel) - g_nt);
    return true;
}

static uint32_t ResolvedExportRva(HMODULE nt, const char* name) {
    void* p = (void*)GetProcAddress(nt, name);
    if (!p) return 0;
    uint32_t rva = (uint32_t)((const uint8_t*)p - g_nt);
    uint32_t follow;
    if (IsEcFastForward(p, &follow)) rva = follow;
    return rva;
}

static void InitExports(HMODULE nt) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)(g_nt + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY& d = h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!d.VirtualAddress) return;
    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(g_nt + d.VirtualAddress);
    DWORD* nameRvas = (DWORD*)(g_nt + ed->AddressOfNames);
    WORD* ords = (WORD*)(g_nt + ed->AddressOfNameOrdinals);
    DWORD* fns = (DWORD*)(g_nt + ed->AddressOfFunctions);

    g_exp = (Export*)malloc(sizeof(Export) * ed->NumberOfNames);
    if (!g_exp) return;
    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        DWORD rva = fns[ords[i]];
        if (rva >= d.VirtualAddress && rva < d.VirtualAddress + d.Size) continue;  // forwarder
        uint32_t follow;
        if (IsEcFastForward(g_nt + rva, &follow)) rva = follow;
        g_exp[g_expCount].name = (const char*)g_nt + nameRvas[i];
        g_exp[g_expCount].rva = rva;
        ++g_expCount;
    }
}

static const char* ExportNameAt(uint32_t rva) {
    for (int i = 0; i < g_expCount; ++i) if (g_exp[i].rva == rva) return g_exp[i].name;
    return nullptr;
}

// ===========================================================================
// scanning primitives
// ===========================================================================

struct Site { uint32_t rva; const char* kind; };

//
// Every code reference to a data address, in either instruction set. x64 uses a
// rip-relative LEA; ARM64 (and therefore ARM64EC, whose bodies are ARM64 code)
// uses an ADRP that forms a page address followed by an ADD of the offset. Both
// are the ordinary way a compiler materialises the address of a literal, so
// matching them is not a signature of any particular function.
//
static int ScanCodeRefs(uint32_t targetRva, Site* out, int max) {
    int n = 0;
    const uint64_t targetVa = (uint64_t)(g_nt + targetRva);

    for (int si = 0; si < g_secCount && n < max; ++si) {
        if (!g_sec[si].exec) continue;
        const uint8_t* p = g_nt + g_sec[si].rva;
        size_t len = g_sec[si].size;

        for (size_t i = 0; i + 7 <= len && n < max; ++i) {          // lea r64,[rip+d]
            if ((p[i] & 0xF0) != 0x40) continue;
            if (p[i + 1] != 0x8D) continue;
            if ((p[i + 2] & 0xC7) != 0x05) continue;
            int32_t d; memcpy(&d, p + i + 3, 4);
            if ((uint64_t)(p + i + 7 + d) != targetVa) continue;
            out[n].rva = (uint32_t)(g_sec[si].rva + i);
            out[n].kind = "x64 lea";
            ++n;
        }

        // ADRP forms a page base; a later ADD of an immediate completes it. The
        // register file is cleared at every function start so a stale ADRP from
        // the previous function cannot manufacture a hit.
        const uint32_t* c = (const uint32_t*)p;
        size_t words = len / 4;
        uint64_t adrp[32] = { 0 };
        bool have[32] = { false };
        for (size_t i = 0; i < words && n < max; ++i) {
            uint32_t rva = (uint32_t)(g_sec[si].rva + i * 4);
            if (IsFunctionStart(rva)) memset(have, 0, sizeof(have));
            uint32_t insn = c[i];
            uint64_t pc = (uint64_t)(c + i);

            if ((insn & 0x9F000000u) == 0x90000000u) {              // ADRP Xd,#page
                uint32_t rd = insn & 0x1F;
                int64_t immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7FFFF;
                int64_t imm = (immhi << 2) | immlo;
                if (imm & (1LL << 20)) imm -= (1LL << 21);
                adrp[rd] = (pc & ~0xFFFULL) + (imm << 12);
                have[rd] = true;
                continue;
            }
            if ((insn & 0xFF800000u) == 0x91000000u) {              // ADD Xd,Xn,#imm12
                uint32_t rd = insn & 0x1F, rn = (insn >> 5) & 0x1F, imm12 = (insn >> 10) & 0xFFF;
                if (have[rn] && adrp[rn] + imm12 == targetVa) {
                    out[n].rva = rva;
                    out[n].kind = "arm64 adrp+add";
                    ++n;
                }
                if (rd != rn) have[rd] = false;
                continue;
            }
        }
    }
    return n;
}

// every occurrence of a NUL-terminated literal in the image
static int ScanString(const char* s, uint32_t* out, int max) {
    size_t len = strlen(s) + 1;
    int n = 0;
    for (size_t off = 0; off + len <= g_ntSize && n < max; ++off)
        if (memcmp(g_nt + off, s, len) == 0) out[n++] = (uint32_t)off;
    return n;
}

// ------------------------------------------------------------ call edge list

struct Edge { uint32_t target, site; };
static Edge*  g_edge;
static size_t g_edgeCount, g_edgeCap;

static void AddEdge(uint32_t target, uint32_t site) {
    if (g_edgeCount == g_edgeCap) {
        size_t cap = g_edgeCap ? g_edgeCap * 2 : 65536;
        Edge* e = (Edge*)realloc(g_edge, cap * sizeof(Edge));
        if (!e) return;
        g_edge = e; g_edgeCap = cap;
    }
    g_edge[g_edgeCount].target = target;
    g_edge[g_edgeCount].site = site;
    ++g_edgeCount;
}

static int CompareEdge(const void* a, const void* b) {
    const Edge* x = (const Edge*)a; const Edge* y = (const Edge*)b;
    if (x->target != y->target) return x->target < y->target ? -1 : 1;
    return x->site < y->site ? -1 : x->site > y->site ? 1 : 0;
}

//
// Direct calls, both instruction sets, built once. A call target is only
// recorded when the runtime-function tables confirm it is a function start:
// byte-scanning for 0xE8 finds plenty of operand bytes that are not opcodes, and
// that filter removes essentially all of them.
//
static void BuildCallGraph() {
    for (int si = 0; si < g_secCount; ++si) {
        if (!g_sec[si].exec) continue;
        const uint8_t* p = g_nt + g_sec[si].rva;
        size_t len = g_sec[si].size;

        for (size_t i = 0; i + 5 <= len; ++i) {
            if (p[i] != 0xE8 && p[i] != 0xE9) continue;
            int32_t rel; memcpy(&rel, p + i + 1, 4);
            int64_t t = (int64_t)(g_sec[si].rva + i + 5) + rel;
            if (t <= 0 || (uint64_t)t >= g_ntSize) continue;
            if (!IsFunctionStart((uint32_t)t)) continue;
            AddEdge((uint32_t)t, (uint32_t)(g_sec[si].rva + i));
        }
        const uint32_t* c = (const uint32_t*)p;
        for (size_t i = 0; i < len / 4; ++i) {
            uint32_t insn = c[i];
            bool bl = (insn & 0xFC000000u) == 0x94000000u;      // BL
            bool b = (insn & 0xFC000000u) == 0x14000000u;       // B (tail call)
            if (!bl && !b) continue;
            int64_t off = insn & 0x03FFFFFF;
            if (off & (1LL << 25)) off -= (1LL << 26);
            int64_t t = (int64_t)(g_sec[si].rva + i * 4) + (off << 2);
            if (t <= 0 || (uint64_t)t >= g_ntSize) continue;
            if (!IsFunctionStart((uint32_t)t)) continue;
            AddEdge((uint32_t)t, (uint32_t)(g_sec[si].rva + i * 4));
        }
    }
    qsort(g_edge, g_edgeCount, sizeof(Edge), CompareEdge);
}

// call sites targeting fn; returns the count, fills the enclosing functions
static int CallersOf(uint32_t fn, uint32_t* out, int max) {
    size_t lo = 0, hi = g_edgeCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_edge[mid].target < fn) lo = mid + 1; else hi = mid;
    }
    int n = 0;
    for (size_t i = lo; i < g_edgeCount && g_edge[i].target == fn && n < max; ++i) {
        uint32_t owner = FunctionStartOf(g_edge[i].site);
        if (!owner) continue;
        bool dup = false;
        for (int k = 0; k < n; ++k) if (out[k] == owner) dup = true;
        if (!dup) out[n++] = owner;
    }
    return n;
}

// ===========================================================================
// unwind data -- the ABI's own record of which function a funclet belongs to
// ===========================================================================

struct Scope { uint32_t begin, end, handler, target; };

//
// The scope table an SEH handler carries. Both __C_specific_handler and
// _GSHandlerCheck_SEH begin their handler data with a count followed by
// { Begin, End, Handler, Target } records, and that shape is identical on x64
// and ARM64. Functions using C++ EH carry something else there, so every record
// is validated before it is believed.
//
static bool ParseHandlerData(const uint32_t* hd, uint32_t fnRva, uint32_t fnEnd,
                             Scope* out, int max, int* count) {
    *count = 0;
    if ((const uint8_t*)hd < g_nt || (const uint8_t*)hd + 8 > g_nt + g_ntSize) return false;
    uint32_t n = hd[0];
    if (n == 0 || n > 256) return false;
    if ((const uint8_t*)(hd + 1 + n * 4) > g_nt + g_ntSize) return false;
    for (uint32_t i = 0; i < n; ++i) {
        Scope s;
        s.begin = hd[1 + i * 4]; s.end = hd[2 + i * 4];
        s.handler = hd[3 + i * 4]; s.target = hd[4 + i * 4];
        if (s.begin >= s.end) return false;
        if (s.begin < fnRva || (fnEnd && s.end > fnEnd)) return false;
        if (s.begin >= g_ntSize || s.end > g_ntSize) return false;
        // Target is always an address in the parent; Handler is a funclet, the
        // literal 1 (a constant __except filter) or 0.
        if (s.target && (s.target < fnRva || (fnEnd && s.target > fnEnd))) return false;
        if (s.handler > 1 && !InExecSection(s.handler)) return false;
        if (*count < max) out[(*count)++] = s;
    }
    return true;
}

//
// Scope table of one function, from its runtime-function record. Follows x64
// chained unwind info, which is how a separated code fragment names its parent.
//
static bool ScopesOfFunction(uint32_t fnRva, Scope* out, int max, int* count,
                             uint32_t* handlerOut, uint32_t* primaryOut = nullptr) {
    *count = 0;
    if (handlerOut) *handlerOut = 0;
    if (primaryOut) *primaryOut = fnRva;
    const uint8_t* rec; bool x64fmt;
    if (!LookupRecord(fnRva, &rec, &x64fmt)) return false;

    for (int chain = 0; chain < 4; ++chain) {
        if (x64fmt) {
            uint32_t begin, end, unwind;
            memcpy(&begin, rec, 4); memcpy(&end, rec + 4, 4); memcpy(&unwind, rec + 8, 4);
            if (!unwind || unwind + 4 > g_ntSize) return false;
            const uint8_t* u = g_nt + unwind;
            uint8_t ver = u[0] & 7, flags = u[0] >> 3, codes = u[2];
            if (ver != 1 && ver != 2) return false;
            size_t after = 4 + (size_t)((codes + 1) & ~1) * 2;
            if (flags & 0x4) {                                   // UNW_FLAG_CHAININFO
                rec = u + after;
                if (rec + 12 > g_nt + g_ntSize) return false;
                continue;
            }
            if (!(flags & 0x3)) return false;                    // no handler at all
            uint32_t handler; memcpy(&handler, u + after, 4);
            if (handlerOut) *handlerOut = handler;
            // After chain following, begin is the primary function's start --
            // a separated fragment must not be mistaken for the function.
            if (primaryOut) *primaryOut = begin;
            return ParseHandlerData((const uint32_t*)(u + after + 4), begin, end, out, max, count);
        }
        else {
            uint32_t begin, second;
            memcpy(&begin, rec, 4); memcpy(&second, rec + 4, 4);
            if (second & 3) return false;                        // packed: no handler
            if (!second || second + 8 > g_ntSize) return false;
            const uint32_t* x = (const uint32_t*)(g_nt + second);
            uint32_t hdr = x[0];
            uint32_t flen = hdr & 0x3FFFF;
            uint32_t X = (hdr >> 20) & 1, E = (hdr >> 21) & 1;
            uint32_t epilogs = (hdr >> 22) & 0x1F, codeWords = (hdr >> 27) & 0x1F;
            size_t w = 1;
            if (epilogs == 0 && codeWords == 0) {                // extended header
                epilogs = x[1] & 0xFFFF;
                codeWords = (x[1] >> 16) & 0xFF;
                w = 2;
            }
            if (!X) return false;                                // no handler
            size_t after = w + (E ? 0 : epilogs) + codeWords;
            if ((const uint8_t*)(x + after + 2) > g_nt + g_ntSize) return false;
            if (handlerOut) *handlerOut = x[after];
            return ParseHandlerData(x + after + 1, begin, begin + flen * 4, out, max, count);
        }
    }
    return false;
}

// ===========================================================================
// anchor 1 -- scope record found in read-only data
// ===========================================================================

//
// A scope record naming the funclet has to exist somewhere in read-only data,
// because that is where MSVC puts the handler data an SEH function carries. Find
// it by its Handler (or Target) field and read Begin out of the same record;
// Begin is an address inside the parent, which RtlLookupFunctionEntry turns into
// the parent's start.
//
// Every hit is validated as a whole record before it is believed: Begin < End,
// the two ends must live in one function, that function must be a real function
// start, and it must not be the funclet itself.
//
//
// A PGO build splits a function into fragments, each with its own
// runtime-function record whose unwind info is chained to the primary's. The
// fragment is not a function; resolving the chain is how the ABI says so.
//
static uint32_t ChainPrimary(uint32_t fnRva) {
    const uint8_t* rec; bool x64fmt;
    if (!LookupRecord(fnRva, &rec, &x64fmt) || !x64fmt) return fnRva;
    uint32_t begin = fnRva;
    for (int i = 0; i < 4; ++i) {
        uint32_t unwind;
        memcpy(&begin, rec, 4); memcpy(&unwind, rec + 8, 4);
        if (!unwind || unwind + 4 > g_ntSize) return begin;
        const uint8_t* u = g_nt + unwind;
        uint8_t ver = u[0] & 7, flags = u[0] >> 3, codes = u[2];
        if (ver != 1 && ver != 2) return begin;
        if (!(flags & 0x4)) return begin;                // not chained: this is it
        const uint8_t* next = u + 4 + (size_t)((codes + 1) & ~1) * 2;
        if (next + 12 > g_nt + g_ntSize) return begin;
        rec = next;
    }
    return begin;
}

static bool InFunctionTable(uint32_t rva) {
    for (int i = 0; i < g_tabCount; ++i)
        if (rva >= g_tab[i].rva && rva < g_tab[i].rva + g_tab[i].size) return true;
    return false;
}

static int ParentsFromDataScan(uint32_t funclet, uint32_t* out, int max, uint32_t* recRvaOut) {
    int n = 0;
    for (int si = 0; si < g_secCount && n < max; ++si) {
        if (g_sec[si].exec) continue;
        const uint8_t* p = g_nt + g_sec[si].rva;
        for (size_t k = 0; k + 4 <= g_sec[si].size && n < max; k += 4) {
            uint32_t w; memcpy(&w, p + k, 4);
            if (w != funclet) continue;
            if (k < 8) continue;

            uint32_t at = (uint32_t)(g_sec[si].rva + k - 8);
            // A runtime-function table is full of code RVAs in triples, so a hit
            // inside one is a coincidence, not a scope record. Skipping the
            // tables removes the only false positive this scan produced across
            // the three configurations it was measured on.
            if (InFunctionTable(at) || InFunctionTable(at + 12)) continue;

            const uint32_t* r = (const uint32_t*)(p + k - 8);
            Scope s = { r[0], r[1], r[2], r[3] };
            if (s.handler != funclet) continue;             // Handler names the funclet
            if (s.begin >= s.end || s.end - s.begin > 0x10000) continue;
            if (!InExecSection(s.begin) || !InExecSection(s.end - 1)) continue;
            uint32_t owner = FunctionStartOf(s.begin);
            if (!owner || owner == funclet) continue;
            if (FunctionStartOf(s.end - 1) != owner) continue;
            uint32_t parent = ChainPrimary(owner);
            if (!parent || parent == funclet) continue;
            if (!IsFunctionStart(parent)) continue;
            if (s.target && (s.target < parent || s.target > s.end)) continue;

            bool dup = false;
            for (int i = 0; i < n; ++i) if (out[i] == parent) dup = true;
            if (!dup) {
                if (recRvaOut && !n) *recRvaOut = at;
                out[n++] = parent;
            }
            if (g_survey)
                PRN("      record  %-8s ntdll+0x%08X  begin 0x%X end 0x%X handler 0x%X "
                    "target 0x%X -> parent 0x%X\n",
                    g_sec[si].name, at, s.begin, s.end, s.handler, s.target, parent);
        }
    }
    return n;
}

// ===========================================================================
// anchor 2 -- the same association read out of the unwind tables
// ===========================================================================

//
// Walk every function the image declares and ask its own unwind data which
// funclets it owns. This reaches the same answer as anchor 1 without depending
// on finding the record by a value scan through .rdata.
//
static int ParentsFromUnwindTables(uint32_t funclet, uint32_t* out, int max) {
    int n = 0;
    Scope scopes[64];
    for (size_t i = 0; i < g_fnCount && n < max; ++i) {
        uint32_t fn = g_fnStart[i];
        if (fn == funclet) continue;
        int count = 0;
        uint32_t handler = 0, primary = fn;
        if (!ScopesOfFunction(fn, scopes, 64, &count, &handler, &primary)) continue;
        // The language-specific handler has to be a real function, which is what
        // separates a genuine scope table from a C++ EH blob read as one.
        if (!IsFunctionStart(handler)) continue;
        for (int k = 0; k < count; ++k) {
            if (scopes[k].handler != funclet) continue;
            bool dup = false;
            for (int j = 0; j < n; ++j) if (out[j] == primary) dup = true;
            if (!dup) out[n++] = primary;
            if (g_survey)
                PRN("      unwind  fn 0x%08X%s handler 0x%X scope { 0x%X 0x%X 0x%X 0x%X }\n",
                    fn, fn == primary ? "" : " (chained fragment)", handler,
                    scopes[k].begin, scopes[k].end, scopes[k].handler, scopes[k].target);
            break;
        }
    }
    return n;
}

// ===========================================================================
// anchor 3 -- LdrpTlsList, located structurally, and who feeds it
// ===========================================================================

typedef struct _TLS_DIR64 {
    ULONGLONG StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks;
    ULONG SizeOfZeroFill, Characteristics;
} TLS_DIR64;

static bool Readable(const void* p, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (const uint8_t*)p + n <= (const uint8_t*)mbi.BaseAddress + mbi.RegionSize;
}

static TLS_DIR64* OwnTlsDirectory() {
    HMODULE self = GetModuleHandleW(nullptr);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((BYTE*)self + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY& d = h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!d.VirtualAddress) return nullptr;
    return (TLS_DIR64*)((BYTE*)self + d.VirtualAddress);
}

//
// A node of LdrpTlsList holds a copy of the module's IMAGE_TLS_DIRECTORY. Rather
// than assume where in the node it sits, look for our own directory's
// { StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex } triple at any
// aligned offset in the node's first 0x40 bytes. That survives a node layout
// change.
//
static bool NodeDescribes(const void* node, const TLS_DIR64* mine, size_t* dirOff) {
    if (!Readable(node, 0x48)) return false;
    const uint8_t* b = (const uint8_t*)node;
    for (size_t off = 8; off + 24 <= 0x48; off += 8) {
        const TLS_DIR64* t = (const TLS_DIR64*)(b + off);
        if (t->StartAddressOfRawData == mine->StartAddressOfRawData &&
            t->EndAddressOfRawData == mine->EndAddressOfRawData &&
            t->AddressOfIndex == mine->AddressOfIndex) {
            if (dirOff) *dirOff = off;
            return true;
        }
    }
    return false;
}

static uint32_t g_tlsListRva;
static size_t   g_tlsDirOffset = 0x10;

static bool ListIsSane(const LIST_ENTRY* head) {
    if (!Readable(head, sizeof(LIST_ENTRY))) return false;
    const LIST_ENTRY* f = head->Flink;
    const LIST_ENTRY* b = head->Blink;
    if (!f || f == head || !b) return false;
    if (!Readable(f, sizeof(LIST_ENTRY)) || !Readable(b, sizeof(LIST_ENTRY))) return false;
    return f->Blink == head && b->Flink == head;
}

static bool FindTlsList(const TLS_DIR64* mine) {
    for (int si = 0; si < g_secCount; ++si) {
        if (!g_sec[si].write || g_sec[si].exec) continue;
        const uint8_t* p = g_nt + g_sec[si].rva;
        for (size_t off = 0; off + sizeof(LIST_ENTRY) <= g_sec[si].size; off += 8) {
            const LIST_ENTRY* head = (const LIST_ENTRY*)(p + off);
            if (!ListIsSane(head)) continue;
            const LIST_ENTRY* cur = head->Flink;
            for (int guard = 0; cur != head && guard < 256; ++guard) {
                if (!Readable(cur, sizeof(LIST_ENTRY))) break;
                size_t dirOff;
                if (NodeDescribes(cur, mine, &dirOff)) {
                    g_tlsListRva = (uint32_t)(g_sec[si].rva + off);
                    g_tlsDirOffset = dirOff;
                    return true;
                }
                cur = cur->Flink;
            }
        }
    }
    return false;
}

static int TlsListLength() {
    if (!g_tlsListRva) return -1;
    const LIST_ENTRY* head = (const LIST_ENTRY*)(g_nt + g_tlsListRva);
    if (!ListIsSane(head)) return -1;
    int n = 0;
    for (const LIST_ENTRY* c = head->Flink; c != head && n < 4096; c = c->Flink) {
        if (!Readable(c, sizeof(LIST_ENTRY))) return -1;
        ++n;
    }
    return n;
}

// ===========================================================================
// legacy comparison -- what MemoryModule/MmpLdrpTls.cpp finds today
// ===========================================================================

static const Section* SectionNamed(const char* name) {
    for (int i = 0; i < g_secCount; ++i)
        if (_strnicmp(g_sec[i].name, name, 8) == 0) return &g_sec[i];
    return nullptr;
}

static const uint8_t* SearchSection(const char* secName, const void* pat, size_t patSize,
                                    const uint8_t* resume) {
    const Section* s = SectionNamed(secName);
    if (!s) return nullptr;
    const uint8_t* start = resume ? resume + 1 : g_nt + s->rva;
    const uint8_t* end = g_nt + s->rva + s->size;
    for (const uint8_t* p = start; p + patSize <= end; ++p)
        if (memcmp(p, pat, patSize) == 0) return p;
    return nullptr;
}

//
// RtlFindLdrpHandleTlsData10() from MmpLdrpTls.cpp, reproduced so the probe can
// report what the shipping code resolves to on the same machine. Stage names
// match the source.
//
static void ReportLegacyScan(uint32_t verified) {
    PRN("\n--- what MemoryModule/MmpLdrpTls.cpp resolves today ---\n");

    const uint8_t* strOff = SearchSection(".rdata", "LdrpHandleTlsData\x00", 18, nullptr);
    if (!strOff) { PRN("  stage 1 (.rdata \"LdrpHandleTlsData\")   : NOT FOUND -> STATUS_NOT_SUPPORTED\n"); return; }
    PRN("  stage 1 string in .rdata               : ntdll+0x%08zX\n", (size_t)(strOff - g_nt));

    const uint8_t* block = nullptr, * hit = nullptr;
    while ((hit = SearchSection(".text", "\x48\x8D\x15", 3, hit)) != nullptr) {
        int32_t d; memcpy(&d, hit + 3, 4);
        if (hit + 7 + d == strOff) { block = hit; break; }
    }
    if (!block) {
        PRN("  stage 2 (lea rdx,[rip+..] to string)   : NOT FOUND -> STATUS_NOT_SUPPORTED\n");
        PRN("        this is the whole TLS capability turning itself off: MmpTlsInitialize\n"
            "        nulls both pointers and clears MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA.\n");
        return;
    }
    PRN("  stage 2 lea rdx to the string          : ntdll+0x%08zX\n", (size_t)(block - g_nt));

    const uint8_t* fun = block;
    while (*fun != 0xCC) {
        if (block - fun > 0x50) { PRN("  stage 3 (back-scan to 0xCC)            : gave up -> STATUS_NOT_SUPPORTED\n"); return; }
        --fun;
    }
    ++fun;
    PRN("  stage 3 funclet start by 0xCC back-scan: ntdll+0x%08zX%s\n",
        (size_t)(fun - g_nt),
        FunctionStartOf((uint32_t)(fun - g_nt)) == (uint32_t)(fun - g_nt) ? "  (agrees with .pdata)"
                                                                         : "  (DISAGREES with .pdata)");

    uint32_t funRva = (uint32_t)(fun - g_nt);
    const uint8_t* rec = SearchSection(".rdata", &funRva, 4, nullptr);
    if (!rec) { PRN("  stage 4 (scope record in .rdata)       : NOT FOUND -> STATUS_NOT_SUPPORTED\n"); return; }
    uint32_t begin; memcpy(&begin, rec - 8, 4);
    PRN("  stage 4 scope record                   : ntdll+0x%08zX, begin 0x%08X\n",
        (size_t)(rec - g_nt), begin);

    const uint32_t* blk = (const uint32_t*)((ULONG_PTR)(g_nt + begin) / 4 * 4);
    const uint32_t* backup = blk;
    while (*blk != 0xCCCCCCCCu) {
        if (backup - blk > 0x400) { PRN("  stage 5 (back-scan to CC CC CC CC)     : gave up -> STATUS_NOT_SUPPORTED\n"); return; }
        --blk;
    }
    ++blk;
    uint32_t got = (uint32_t)((const uint8_t*)blk - g_nt);
    PRN("  stage 5 function start by CC CC CC CC  : ntdll+0x%08X\n", got);
    PRN("  legacy answer                          : ntdll+0x%08X   %s\n", got,
        verified && got == verified ? "== the verified address"
        : verified ? "*** DIFFERS from the verified address ***" : "(nothing to compare against)");

    // LdrpReleaseTlsEntry, whose locator is a single hardcoded 20-byte signature
    static const uint8_t relSig[] = {
        0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,
        0x48,0x8b,0xfa,0x48,0x8b,0xd9,0x48,0x85,0xd2,0x75 };
    const uint8_t* rel = SearchSection(".text", relSig, sizeof(relSig), nullptr);
    PRN("  LdrpReleaseTlsEntry byte signature     : %s\n",
        rel ? "found" : "NOT FOUND -> the whole TLS capability is disabled anyway");
}

// ===========================================================================
// behavioural verification
// ===========================================================================

typedef struct _PROBE_USTRING { USHORT Length, MaximumLength; ULONG Pad; PWSTR Buffer; } PROBE_USTRING;

typedef struct _PROBE_LDR_ENTRY {           // Vista..Win11, 64-bit layout
    LIST_ENTRY InLoadOrderLinks;            // 0x00
    LIST_ENTRY InMemoryOrderLinks;          // 0x10
    LIST_ENTRY InInitializationOrderLinks;  // 0x20
    PVOID      DllBase;                     // 0x30
    PVOID      EntryPoint;                  // 0x38
    ULONG      SizeOfImage;                 // 0x40
    ULONG      Pad0;
    PROBE_USTRING FullDllName;              // 0x48
    PROBE_USTRING BaseDllName;              // 0x58
    ULONG      Flags;                       // 0x68
    USHORT     ObsoleteLoadCount;           // 0x6C
    USHORT     TlsIndex;                    // 0x6E
    LIST_ENTRY HashLinks;                   // 0x70
    ULONG      TimeDateStamp;               // 0x80
    ULONG      Pad1;
    PVOID      EntryPointActivationContext; // 0x88
    PVOID      Lock;                        // 0x90
    PVOID      DdagNode;                    // 0x98
    LIST_ENTRY NodeModuleLink;              // 0xA0
    PVOID      LoadContext;                 // 0xB0
    PVOID      ParentDllBase;               // 0xB8
    PVOID      SwitchBackContext;           // 0xC0
    BYTE       Tail[0x120];
} PROBE_LDR_ENTRY;

typedef struct _PROBE_DDAG_NODE {
    LIST_ENTRY Modules;                     // 0x00
    PVOID      ServiceTagList;              // 0x10
    ULONG      LoadCount;                   // 0x18
    ULONG      LoadWhileUnloadingCount;     // 0x1C
    ULONG      LowestLink;                  // 0x20
    ULONG      Pad0;
    PVOID      Dependencies;                // 0x28
    PVOID      IncomingDependencies;        // 0x30
    ULONG      State;                       // 0x38  LdrModulesReadyToRun == 9
    ULONG      Pad1;
    PVOID      CondenseLink;                // 0x40
    ULONG      PreorderNumber;              // 0x48
    BYTE       Tail[0x40];
} PROBE_DDAG_NODE;

#define TLS_TEMPLATE_BYTES 64

struct FakeModule {
    uint8_t*         image;        // headers at +0, TLS payload at +0x1000
    TLS_DIR64*       tls;
    volatile ULONG*  indexSlot;
    uint8_t*         raw;
    PROBE_LDR_ENTRY* entry;
    PROBE_DDAG_NODE* node;
    uint8_t          magic;
};

//
// The smallest thing that is still an image with a TLS directory: valid DOS and
// PE headers, one section, and a TLS directory whose raw-data template we filled
// with a byte pattern of our choosing. LdrpHandleTlsData reaches it exactly the
// way it reaches a real module's, through RtlImageDirectoryEntryToData.
//
static bool BuildFakeModule(FakeModule* fm, uint8_t magic, const wchar_t* name) {
    memset(fm, 0, sizeof(*fm));
    fm->magic = magic;

    fm->image = (uint8_t*)VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fm->image) return false;
    memset(fm->image, 0, 0x2000);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fm->image;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(fm->image + 0x80);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = g_ntMachine;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL |
                                     IMAGE_FILE_LARGE_ADDRESS_AWARE;
    IMAGE_OPTIONAL_HEADER64& oh = nt->OptionalHeader;
    oh.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    oh.SectionAlignment = 0x1000;
    oh.FileAlignment = 0x200;
    oh.MajorSubsystemVersion = 6;
    oh.SizeOfImage = 0x2000;
    oh.SizeOfHeaders = 0x400;
    oh.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    oh.ImageBase = (ULONGLONG)fm->image;
    oh.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec->Name, ".data\0\0\0", 8);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x1000;
    sec->SizeOfRawData = 0x1000;
    sec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    uint8_t* page = fm->image + 0x1000;
    fm->tls = (TLS_DIR64*)(page + 0x00);
    fm->indexSlot = (volatile ULONG*)(page + 0x40);
    PVOID* callbacks = (PVOID*)(page + 0x80);
    fm->raw = page + 0x100;

    memset(fm->raw, magic, TLS_TEMPLATE_BYTES);
    *fm->indexSlot = 0xFFFFFFFFu;                     // sentinel: nothing has written it
    callbacks[0] = nullptr;

    fm->tls->StartAddressOfRawData = (ULONGLONG)fm->raw;
    fm->tls->EndAddressOfRawData = (ULONGLONG)(fm->raw + TLS_TEMPLATE_BYTES);
    fm->tls->AddressOfIndex = (ULONGLONG)fm->indexSlot;
    fm->tls->AddressOfCallBacks = (ULONGLONG)callbacks;
    fm->tls->SizeOfZeroFill = 0;
    fm->tls->Characteristics = IMAGE_SCN_ALIGN_16BYTES;

    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0x1000;
    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(TLS_DIR64);

    fm->entry = (PROBE_LDR_ENTRY*)VirtualAlloc(nullptr, sizeof(PROBE_LDR_ENTRY),
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    fm->node = (PROBE_DDAG_NODE*)VirtualAlloc(nullptr, sizeof(PROBE_DDAG_NODE),
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fm->entry || !fm->node) return false;
    memset(fm->entry, 0, sizeof(*fm->entry));
    memset(fm->node, 0, sizeof(*fm->node));

    // Nothing must be able to walk out of our fabricated entry into ntdll's
    // lists, so every list head in it points at itself.
    fm->entry->InLoadOrderLinks.Flink = fm->entry->InLoadOrderLinks.Blink = &fm->entry->InLoadOrderLinks;
    fm->entry->InMemoryOrderLinks.Flink = fm->entry->InMemoryOrderLinks.Blink = &fm->entry->InMemoryOrderLinks;
    fm->entry->InInitializationOrderLinks.Flink = fm->entry->InInitializationOrderLinks.Blink =
        &fm->entry->InInitializationOrderLinks;
    fm->entry->HashLinks.Flink = fm->entry->HashLinks.Blink = &fm->entry->HashLinks;
    fm->entry->NodeModuleLink.Flink = fm->entry->NodeModuleLink.Blink = &fm->entry->NodeModuleLink;

    fm->entry->DllBase = fm->image;
    fm->entry->SizeOfImage = 0x2000;
    fm->entry->Flags = 0x00004004;                    // LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED
    fm->entry->ObsoleteLoadCount = 1;
    fm->entry->TlsIndex = 0;
    fm->entry->DdagNode = fm->node;

    static wchar_t nameBuf[2][64];
    int slot = magic & 1;
    wcscpy_s(nameBuf[slot], 64, name);
    USHORT bytes = (USHORT)(wcslen(nameBuf[slot]) * sizeof(wchar_t));
    fm->entry->FullDllName.Buffer = fm->entry->BaseDllName.Buffer = nameBuf[slot];
    fm->entry->FullDllName.Length = fm->entry->BaseDllName.Length = bytes;
    fm->entry->FullDllName.MaximumLength = fm->entry->BaseDllName.MaximumLength =
        (USHORT)(bytes + sizeof(wchar_t));

    fm->node->Modules.Flink = fm->node->Modules.Blink = &fm->node->Modules;
    fm->node->LoadCount = 1;
    fm->node->State = 9;                              // LdrModulesReadyToRun
    return true;
}

typedef NTSTATUS(NTAPI* PFN_HANDLE_TLS)(PVOID LdrEntry);
typedef NTSTATUS(NTAPI* PFN_LOCK_LOADER)(ULONG, PULONG, PULONG_PTR);
typedef NTSTATUS(NTAPI* PFN_UNLOCK_LOADER)(ULONG, ULONG_PTR);
static PFN_LOCK_LOADER   g_lockLoader;
static PFN_UNLOCK_LOADER g_unlockLoader;

//
// Calling a wrong address, or a right address the wrong way, can fail in ways a
// __try does not see -- a fast fail, or an emulator refusing a call target. A
// first-chance reporter turns "the probe vanished" into a code and an address.
//
static volatile LONG g_firstChanceSeen;

static LONG CALLBACK FirstChanceReporter(PEXCEPTION_POINTERS ep) {
    if (InterlockedIncrement(&g_firstChanceSeen) <= 4) {
        const uint8_t* at = (const uint8_t*)ep->ExceptionRecord->ExceptionAddress;
        PRN("  first chance    : code 0x%08lX at %p%s",
            (unsigned long)ep->ExceptionRecord->ExceptionCode, (void*)at,
            (at >= g_nt && (size_t)(at - g_nt) < g_ntSize) ? "" : "\n");
        if (at >= g_nt && (size_t)(at - g_nt) < g_ntSize)
            PRN("  (ntdll+0x%08zX, in fn 0x%08X)\n",
                (size_t)(at - g_nt), FunctionStartOf((uint32_t)(at - g_nt)));
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static NTSTATUS CallCandidate(uint32_t rva, PVOID entry, bool* faulted) {
    PFN_HANDLE_TLS fn = (PFN_HANDLE_TLS)(g_nt + rva);
    NTSTATUS st = (NTSTATUS)0xC0000001L;
    *faulted = false;

    // The loader holds its own lock across this call, and so does the library
    // (MmpLoaderLockGuard). Mirror that here rather than call it bare.
    ULONG disp = 0; ULONG_PTR cookie = 0;
    bool held = g_lockLoader && g_lockLoader(0, &disp, &cookie) >= 0;
    __try {
        st = fn(entry);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *faulted = true;
        st = (NTSTATUS)GetExceptionCode();
    }
    if (held && g_unlockLoader) g_unlockLoader(0, cookie);
    return st;
}

static void** ThreadTlsVector() {
    return *(void***)((BYTE*)NtCurrentTeb() + 0x58);   // TEB.ThreadLocalStoragePointer
}

//
// Whether an x64 caller may call an ARM64EC function at all.
//
// On ARM64X the loader is compiled twice and the copy an x64 process can reach
// is the ARM64EC one. A transition from emulated x64 into ARM64EC code goes
// through the function's *entry thunk*, whose association is recorded in the
// four bytes immediately before the entry point, tagged 1 in the low bits.
// The compiler only emits one where it can see an x64 caller, so ntdll's
// internal loader helpers have none:
//
//     RtlAcquireSRWLockExclusive (exported) ec body ... dword[-4] = 0x0015A039
//     LdrLoadDll                 (exported) ec body ... dword[-4] = 0x000DA829
//     LdrpHandleTlsData          (internal) ec body ... dword[-4] = 0x00000000
//
// Calling one of those from x64 is not a catchable fault: the emulator ends the
// process with STATUS_WX86_INTERNAL_ERROR (0xC000026F). Measured on
// 10.0.26100 ARM64X -- the direct call to the exported body above succeeds, the
// internal one kills the process. So the address being correct is not the same
// question as the address being usable, and both have to be reported.
//
static uint32_t EcEntryThunkTag(uint32_t fnRva) {
    if (fnRva < 4) return 0;
    uint32_t v; memcpy(&v, g_nt + fnRva - 4, 4);
    return v;
}

static bool CandidateIsCallableFromHere(uint32_t rva, const char** why) {
    Flavour fl = FlavourOf(rva);
#if defined(_M_X64)
    if (fl == FL_ARM64EC) {
        uint32_t tag = EcEntryThunkTag(rva);
        if ((tag & 3) != 1) {
            *why = "ARM64EC body with no entry thunk: an x64 caller cannot reach it";
            return false;
        }
        *why = "ARM64EC body with an entry thunk";
        return true;
    }
    if (fl == FL_ARM64) {
        *why = "native ARM64 body: an x64 caller cannot reach it";
        return false;
    }
#else
    if (fl == FL_ARM64EC) {
        *why = "ARM64EC body: a native ARM64 caller must not use the EC copy";
        return false;
    }
#endif
    *why = "same instruction set as this process";
    return true;
}

//
// The proof. A fabricated module with a TLS directory goes in; a TLS index, a
// list node describing our directory, and our template bytes in this thread's
// TLS vector come out. Then a second module has to get the next index, which is
// what says the candidate is driving ntdll's allocator rather than writing
// something that merely looks like an index.
//
static bool VerifyByEffect(uint32_t rva) {
    FakeModule a{}, b{};
    if (!BuildFakeModule(&a, 0xA5, L"MmProbeTlsA.dll") ||
        !BuildFakeModule(&b, 0x5A, L"MmProbeTlsB.dll")) {
        PRN("  could not build the fabricated modules\n");
        return false;
    }
    PRN("  fabricated      : image %p, entry %p, TLS dir at image+0x1000\n",
        (void*)a.image, (void*)a.entry);
    PVOID veh = AddVectoredExceptionHandler(1, FirstChanceReporter);

    int before = TlsListLength();
    bool faulted = false;
    PRN("  calling         : ntdll+0x%08X with the fabricated entry\n", rva);
    NTSTATUS st = CallCandidate(rva, a.entry, &faulted);
    int afterA = TlsListLength();
    ULONG idxA = *a.indexSlot;

    PRN("  call #1 status  : 0x%08lX%s\n", (unsigned long)st, faulted ? "   (RAISED AN EXCEPTION)" : "");
    if (faulted) { PRN("  the candidate is not callable with a module entry -- wrong address\n"); return false; }

    PRN("  TLS index taken : %s", idxA == 0xFFFFFFFFu ? "none, sentinel untouched" : "");
    if (idxA != 0xFFFFFFFFu) PRN("%lu", (unsigned long)idxA);
    PRN("\n");
    PRN("  LdrpTlsList     : %d -> %d node%s\n", before, afterA, afterA == 1 ? "" : "s");

    bool ok = (st >= 0) && (idxA != 0xFFFFFFFFu) && (idxA < 0x10000);
    if (before >= 0 && afterA != before + 1) {
        PRN("  the list did not gain exactly one node\n");
        ok = false;
    }

    // Our template bytes have to be reachable through this thread's TLS vector.
    bool blockOk = false;
    void** vec = ThreadTlsVector();
    if (ok && vec && Readable(vec + idxA, sizeof(void*))) {
        void* blk = vec[idxA];
        if (blk && Readable(blk, TLS_TEMPLATE_BYTES)) {
            blockOk = true;
            for (int i = 0; i < TLS_TEMPLATE_BYTES; ++i)
                if (((uint8_t*)blk)[i] != a.magic) { blockOk = false; break; }
        }
        PRN("  TLS block       : %s\n", blockOk
            ? "this thread's vector holds our template bytes"
            : blk ? "slot is populated but does not match our template"
                  : "slot is empty (allocated lazily on this build)");
    }
    else if (ok) {
        PRN("  TLS block       : vector too short to hold the new index yet\n");
    }

    // A second module must take the next index off the same allocator.
    NTSTATUS st2 = CallCandidate(rva, b.entry, &faulted);
    ULONG idxB = *b.indexSlot;
    int afterB = TlsListLength();
    PRN("  call #2 status  : 0x%08lX%s, index %s", (unsigned long)st2,
        faulted ? " (RAISED AN EXCEPTION)" : "",
        idxB == 0xFFFFFFFFu ? "not taken" : "");
    if (idxB != 0xFFFFFFFFu) PRN("%lu", (unsigned long)idxB);
    PRN(", list %d -> %d\n", afterA, afterB);

    bool monotone = !faulted && st2 >= 0 && idxB != 0xFFFFFFFFu && idxB == idxA + 1;
    PRN("  index sequence  : %s\n", monotone
        ? "consecutive, so both came from ntdll's TLS bitmap"
        : "NOT consecutive");

    ok = ok && monotone;
    if (veh) RemoveVectoredExceptionHandler(veh);
    PRN("  verdict         : %s\n", ok
        ? "BEHAVIOUR MATCHES LdrpHandleTlsData"
        : "behaviour does not match");
    return ok;
}

//
// The call happens in a child process. Two reasons: a wrong address handed a
// module entry can corrupt this one, and on ARM64X a refused architecture
// transition is not an exception -- it ends the process outright. A child makes
// both outcomes something the probe can report rather than something that eats
// the report.
//
static int RunVerifyChild(uint32_t rva) {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return -1;
    wchar_t cmd[MAX_PATH + 64];
    swprintf_s(cmd, L"\"%s\" --verify-call %X", path, rva);

    HANDLE hOut = nullptr, hErr = nullptr;
    HANDLE self = GetCurrentProcess();
    DuplicateHandle(self, GetStdHandle(STD_OUTPUT_HANDLE), self, &hOut, 0, TRUE, DUPLICATE_SAME_ACCESS);
    DuplicateHandle(self, GetStdHandle(STD_ERROR_HANDLE), self, &hErr, 0, TRUE, DUPLICATE_SAME_ACCESS);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr; si.hStdOutput = hOut; si.hStdError = hErr;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        PRN("  could not start the verification child (error %lu)\n", GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD code = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if (hOut) CloseHandle(hOut);
    if (hErr) CloseHandle(hErr);
    return (int)code;
}

// ===========================================================================
// vote bookkeeping
// ===========================================================================

struct Bucket { uint32_t rva; int votes; unsigned anchors; const char* how[16]; int howCount; };
static Bucket g_bucket[16];
static int    g_bucketCount;

static void Vote(uint32_t rva, const char* how, unsigned anchorBit) {
    for (int i = 0; i < g_bucketCount; ++i)
        if (g_bucket[i].rva == rva) {
            ++g_bucket[i].votes;
            g_bucket[i].anchors |= anchorBit;
            if (g_bucket[i].howCount < 16) g_bucket[i].how[g_bucket[i].howCount++] = how;
            return;
        }
    if (g_bucketCount == 16) return;
    Bucket& b = g_bucket[g_bucketCount++];
    b.rva = rva; b.votes = 1; b.anchors = anchorBit; b.howCount = 1; b.how[0] = how;
}

static int AnchorCount(unsigned mask) {
    int n = 0;
    for (unsigned m = mask; m; m &= m - 1) ++n;
    return n;
}

// ===========================================================================
// main
// ===========================================================================

static void PrintIdentity() {
#if defined(_M_ARM64)
    PRN("built for       : arm64\n");
#elif defined(_M_X64)
    PRN("built for       : x64\n");
#else
    PRN("built for       : (unsupported: this probe is 64-bit only)\n");
#endif
    PRN("ntdll base      : %p\n", (void*)g_nt);
    PRN("ntdll machine   : 0x%04X  (0x8664=x64, 0xAA64=ARM64)\n", g_ntMachine);
    PRN("ntdll timestamp : 0x%08lX   (an opaque build id, not a date)\n", (unsigned long)g_ntStamp);
    PRN("ntdll SizeOfImg : 0x%08lX\n", (unsigned long)g_ntSize);
    for (int i = 0; i < g_tabCount; ++i)
        PRN("function table  : ntdll+0x%08X size 0x%X stride %zu (%s) -> %s\n",
            g_tab[i].rva, g_tab[i].size, g_tab[i].stride,
            g_tab[i].x64fmt ? "x64 format" : "arm64 format",
            i == 0 ? "exception directory" : "ARM64EC ExtraRFETable");
    PRN("function starts : %zu merged\n", g_fnCount);
    if (g_rangeCount) {
        PRN("code map        : %d ranges", g_rangeCount);
        for (int i = 0; i < g_rangeCount && i < 4; ++i)
            PRN("%s0x%X+0x%X %s", i ? ", " : " -- ", g_range[i].rva, g_range[i].size,
                FlavourName(g_range[i].flavour));
        PRN("%s\n", g_rangeCount > 4 ? ", ..." : "");
    }
    else {
        PRN("code map        : none (single-architecture image)\n");
    }
    PRN("our flavour     : %s", FlavourName(g_ourFlavour));
    if (g_flavourWitness) PRN("   (from ntdll!LdrLoadDll at ntdll+0x%X)", g_flavourWitness);
    PRN("\n");
}

int main(int argc, char** argv) {
    bool noVerify = false;
    uint32_t verifyRva = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--survey")) g_survey = true;
        else if (!strcmp(argv[i], "--no-verify")) noVerify = true;
        else if (!strcmp(argv[i], "--verify-call") && i + 1 < argc)
            verifyRva = (uint32_t)strtoul(argv[++i], nullptr, 16);
    }

    g_ownTlsSlot ^= (int)(ULONG_PTR)argv;             // keep the TLS reference live

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) { PRN("no ntdll\n"); return 2; }
    if (!InitNtdll(nt)) { PRN("could not read ntdll's headers or function tables\n"); return 2; }
    InitExports(nt);
    g_lockLoader = (PFN_LOCK_LOADER)GetProcAddress(nt, "LdrLockLoaderLock");
    g_unlockLoader = (PFN_UNLOCK_LOADER)GetProcAddress(nt, "LdrUnlockLoaderLock");

    //
    // Child half: the parent has already decided on an address, so all this does
    // is make the call and report what changed. Nothing here re-derives the
    // address, which is why an address that kills the process still leaves the
    // parent's findings on the log.
    //
    if (verifyRva) {
        TLS_DIR64* mine = OwnTlsDirectory();
        if (mine) FindTlsList(mine);
        PRN("  child           : pid %lu, ntdll %p, LdrpTlsList %s\n",
            GetCurrentProcessId(), (void*)g_nt,
            g_tlsListRva ? "located" : "not located (node count unavailable)");
        bool ok = VerifyByEffect(verifyRva);
        return ok ? 0 : 1;
    }

    // Which of an ARM64X image's two loader builds is ours: whichever one an
    // ordinary export resolves into once its fast-forward thunk is followed.
    g_flavourWitness = ResolvedExportRva(nt, "LdrLoadDll");
    if (!g_flavourWitness) g_flavourWitness = ResolvedExportRva(nt, "LdrGetDllHandle");
    if (g_flavourWitness) g_ourFlavour = FlavourOf(g_flavourWitness);

    PRN("================= probe_tls_handle report =================\n");
    PrintIdentity();

    BuildCallGraph();
    PRN("call edges      : %zu direct calls, target confirmed by the function tables\n", g_edgeCount);

    // ---------------------------------------------------------------- anchors 1 and 2
    PRN("\n--- anchor 1/2: the name string, then the ABI ---\n");
    uint32_t strs[8];
    int strCount = ScanString("LdrpHandleTlsData", strs, 8);
    PRN("string occurrences : %d\n", strCount);
    for (int i = 0; i < strCount; ++i)
        PRN("  ntdll+0x%08X  section %s\n", strs[i], SectionOf(strs[i]));
    if (!strCount)
        PRN("  the literal is gone from this build; anchors 1 and 2 cannot run\n");

    Site sites[64];
    int siteCount = 0;
    for (int i = 0; i < strCount && siteCount < 64; ++i)
        siteCount += ScanCodeRefs(strs[i], sites + siteCount, 64 - siteCount);
    PRN("code references    : %d\n", siteCount);

    for (int i = 0; i < siteCount; ++i) {
        uint32_t funclet = FunctionStartOf(sites[i].rva);
        Flavour fl = FlavourOf(sites[i].rva);
        bool otherArch = (g_ourFlavour != FL_ANY && fl != g_ourFlavour);
        PRN("  %-16s ntdll+0x%08X  funclet 0x%08X  flavour %s%s\n",
            sites[i].kind, sites[i].rva, funclet, FlavourName(fl),
            otherArch ? (g_survey ? "   (other architecture: shown, not counted)"
                                  : "   (other architecture: ignored)") : "");
        if (!funclet) { PRN("      no function table entry covers it\n"); continue; }
        if (otherArch && !g_survey) continue;

        uint32_t viaData[8], viaUnwind[8], recRva = 0;
        int nd = ParentsFromDataScan(funclet, viaData, 8, &recRva);
        int nu = ParentsFromUnwindTables(funclet, viaUnwind, 8);
        for (int k = 0; k < nd; ++k) {
            PRN("      anchor 1 (scope record in %s) -> ntdll+0x%08X\n",
                SectionOf(recRva), viaData[k]);
            if (!otherArch) Vote(viaData[k], "scope record in read-only data", 1);
        }
        if (!nd) PRN("      anchor 1: no scope record names this funclet\n");
        for (int k = 0; k < nu; ++k) {
            PRN("      anchor 2 (unwind tables)             -> ntdll+0x%08X\n", viaUnwind[k]);
            if (!otherArch) Vote(viaUnwind[k], "unwind tables", 2);
        }
        if (!nu) PRN("      anchor 2: no function's unwind data claims this funclet\n");
    }

    //
    // An address counts only when both derivations reached it independently.
    // Either one on its own can be fooled -- a stray four bytes that happen to
    // sit where a scope record would, or a handler data blob that is not a scope
    // table at all -- and requiring agreement is what makes the pair worth more
    // than either.
    //
    uint32_t candidate = 0;
    int anchorsAgreed = 0, votes = 0;
    for (int i = 0; i < g_bucketCount; ++i) {
        int na = AnchorCount(g_bucket[i].anchors);
        if (na > anchorsAgreed || (na == anchorsAgreed && g_bucket[i].votes > votes)) {
            anchorsAgreed = na; votes = g_bucket[i].votes; candidate = g_bucket[i].rva;
        }
    }
    if (g_bucketCount > 1) {
        PRN("  derivations landed on %d addresses: ", g_bucketCount);
        for (int i = 0; i < g_bucketCount; ++i)
            PRN("%sntdll+0x%X (%d anchor%s)", i ? ", " : "", g_bucket[i].rva,
                AnchorCount(g_bucket[i].anchors),
                AnchorCount(g_bucket[i].anchors) == 1 ? "" : "s");
        PRN("\n");
    }
    if (anchorsAgreed < 2) {
        PRN("  *** no address was reached by both derivations ***\n");
    }

    // ---------------------------------------------------------------- anchor 3
    PRN("\n--- anchor 3: LdrpTlsList and the callers that feed it ---\n");
    bool inTlsCallers = false;
    TLS_DIR64* mine = OwnTlsDirectory();
    if (!mine) {
        PRN("  this probe has no TLS directory of its own; anchor 3 cannot run\n");
    }
    else if (!FindTlsList(mine)) {
        PRN("  no list in ntdll's writable data describes this process's TLS directory\n");
    }
    else {
        PRN("  LdrpTlsList     : ntdll+0x%08X  (%s, directory at node+0x%zX, %d node%s)\n",
            g_tlsListRva, SectionOf(g_tlsListRva), g_tlsDirOffset,
            TlsListLength(), TlsListLength() == 1 ? "" : "s");
        if (g_survey) {
            const LIST_ENTRY* head = (const LIST_ENTRY*)(g_nt + g_tlsListRva);
            int i = 0;
            for (const LIST_ENTRY* c = head->Flink; c != head && i < 32; c = c->Flink, ++i) {
                const TLS_DIR64* t = (const TLS_DIR64*)((const BYTE*)c + g_tlsDirOffset);
                ULONG idx = Readable((void*)t->AddressOfIndex, 4) ? *(ULONG*)t->AddressOfIndex : ~0u;
                PRN("      node %p  raw 0x%llX..0x%llX  index slot 0x%llX = %lu\n", (void*)c,
                    (unsigned long long)t->StartAddressOfRawData,
                    (unsigned long long)t->EndAddressOfRawData,
                    (unsigned long long)t->AddressOfIndex, (unsigned long)idx);
            }
        }

        Site refs[32];
        int nrefs = ScanCodeRefs(g_tlsListRva, refs, 32);
        PRN("  referenced by   : %d site%s\n", nrefs, nrefs == 1 ? "" : "s");

        uint32_t owners[32]; int nowners = 0;
        for (int i = 0; i < nrefs; ++i) {
            uint32_t fn = FunctionStartOf(refs[i].rva);
            if (!fn) continue;
            if (g_ourFlavour != FL_ANY && FlavourOf(fn) != g_ourFlavour) continue;
            bool dup = false;
            for (int k = 0; k < nowners; ++k) if (owners[k] == fn) dup = true;
            if (!dup && nowners < 32) owners[nowners++] = fn;
        }
        for (int i = 0; i < nowners; ++i) {
            uint32_t callers[32];
            int nc = CallersOf(owners[i], callers, 32);
            PRN("    ntdll+0x%08X touches the list; %d caller%s:", owners[i], nc, nc == 1 ? "" : "s");
            for (int k = 0; k < nc; ++k) {
                if (g_ourFlavour != FL_ANY && FlavourOf(callers[k]) != g_ourFlavour) continue;
                PRN(" 0x%08X%s", callers[k], callers[k] == candidate ? "*" : "");
                if (callers[k] == candidate) inTlsCallers = true;
            }
            PRN("\n");
        }
        PRN("  candidate is a caller of a list-touching function : %s\n",
            inTlsCallers ? "yes (marked *)" : "NO");
    }

    // ---------------------------------------------------------------- anchor 4
    PRN("\n--- anchor 4: reachability from named exports ---\n");
    bool reachesLoad = false;
    if (candidate) {
        uint32_t frontier[256], next[256], seen[1024];
        int nf = 1, nseen = 0;
        frontier[0] = candidate;
        seen[nseen++] = candidate;
        for (int depth = 1; depth <= 10 && nf; ++depth) {
            int nn = 0;
            for (int i = 0; i < nf; ++i) {
                uint32_t callers[32];
                int nc = CallersOf(frontier[i], callers, 32);
                for (int k = 0; k < nc; ++k) {
                    bool dup = false;
                    for (int j = 0; j < nseen; ++j) if (seen[j] == callers[k]) dup = true;
                    if (dup) continue;
                    if (nseen < 1024) seen[nseen++] = callers[k];
                    const char* nm = ExportNameAt(callers[k]);
                    if (nm) {
                        PRN("  depth %-2d exported : %s  (ntdll+0x%08X)\n", depth, nm, callers[k]);
                        if (strstr(nm, "LdrLoadDll") || strstr(nm, "LdrpLoadDll")) reachesLoad = true;
                    }
                    else if (nn < 256) next[nn++] = callers[k];
                }
            }
            memcpy(frontier, next, sizeof(uint32_t) * nn);
            nf = nn;
        }
        PRN("  functions walked : %d;  reaches ntdll!LdrLoadDll : %s\n", nseen,
            reachesLoad ? "yes" : "no");
    }
    else {
        PRN("  no candidate to walk from\n");
    }

    // ---------------------------------------------------------------- survey
    if (g_survey) {
        PRN("\n--- survey: derivations grouped by the address they yield ---\n");
        for (int i = 0; i < g_bucketCount; ++i) {
            PRN("ntdll+0x%08X -- %d derivation%s from %d anchor%s%s\n",
                g_bucket[i].rva, g_bucket[i].votes, g_bucket[i].votes == 1 ? "" : "s",
                AnchorCount(g_bucket[i].anchors), AnchorCount(g_bucket[i].anchors) == 1 ? "" : "s",
                g_bucket[i].rva == candidate ? "   <== candidate" : "");
            for (int k = 0; k < g_bucket[i].howCount; ++k)
                PRN("    %s\n", g_bucket[i].how[k]);
        }
        if (candidate) {
            uint32_t callers[32];
            int nc = CallersOf(candidate, callers, 32);
            PRN("direct callers of the candidate : %d\n", nc);
            for (int k = 0; k < nc; ++k) {
                const char* nm = ExportNameAt(callers[k]);
                PRN("    ntdll+0x%08X %s\n", callers[k], nm ? nm : "");
            }
            Scope sc[64]; int n = 0; uint32_t handler = 0;
            if (ScopesOfFunction(candidate, sc, 64, &n, &handler)) {
                PRN("candidate's own scope table (handler ntdll+0x%X), %d record%s\n",
                    handler, n, n == 1 ? "" : "s");
                for (int k = 0; k < n; ++k)
                    PRN("    begin 0x%08X end 0x%08X handler 0x%08X target 0x%08X\n",
                        sc[k].begin, sc[k].end, sc[k].handler, sc[k].target);
            }
        }
    }

    // ---------------------------------------------------------------- summary
    PRN("\n--- summary ---\n");
    if (!candidate) {
        PRN("candidate       : NONE\n");
        ReportLegacyScan(0);
        PRN("\nRESULT: NOT LOCATED -- do not call anything\n");
        PRN("==========================================================\n");
        return 1;
    }
    PRN("candidate       : ntdll+0x%08X   (%s, flavour %s)\n",
        candidate, SectionOf(candidate), FlavourName(FlavourOf(candidate)));
    PRN("agreement       : %d of 2 name-derived anchors, %s by anchor 3, %s by anchor 4\n",
        anchorsAgreed, inTlsCallers ? "corroborated" : "NOT corroborated",
        reachesLoad ? "corroborated" : "NOT corroborated");

    if (anchorsAgreed < 2 && !inTlsCallers) {
        PRN("\nRESULT: NOT LOCATED -- one derivation and no corroboration is not enough\n");
        ReportLegacyScan(0);
        PRN("==========================================================\n");
        return 1;
    }

    const char* why = "";
    bool callable = CandidateIsCallableFromHere(candidate, &why);
    PRN("callable here   : %s -- %s\n", callable ? "yes" : "NO", why);
    if (FlavourOf(candidate) == FL_ARM64EC)
        PRN("EC entry thunk  : 0x%08X\n", EcEntryThunkTag(candidate));

    PRN("\n--- behavioural verification (in a child process) ---\n");
    bool ok = false;
    if (noVerify) {
        PRN("  skipped (--no-verify)\n");
    }
    else {
        int code = RunVerifyChild(candidate);
        if (code == 0) { ok = true; PRN("  child exit      : 0 -- verified\n"); }
        else if (code == 1) PRN("  child exit      : 1 -- the effects did not match\n");
        else if (code == (int)0xC000026F)
            PRN("  child exit      : 0xC000026F STATUS_WX86_INTERNAL_ERROR -- the x64\n"
                "                    emulator refused the call into ARM64EC code; the\n"
                "                    address is right but unusable from an x64 build\n");
        else
            PRN("  child exit      : 0x%08X -- the call did not survive\n", (unsigned)code);
    }

    ReportLegacyScan(ok ? candidate : 0);

    PRN("\nRESULT: %s\n", ok
        ? "VERIFIED -- this is LdrpHandleTlsData"
        : !callable
        ? "LOCATED BUT NOT CALLABLE from this build's instruction set --\n"
          "        the capability has to stand down here, whatever the address is"
        : "FAILED VERIFICATION -- do not use this address");
    PRN("==========================================================\n");
    return ok ? 0 : callable ? 1 : 3;
}
