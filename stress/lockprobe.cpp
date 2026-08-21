//
// lockprobe -- locate and verify ntdll!LdrpModuleDatatableLock at runtime,
// without a hardcoded RVA, a PDB, or an opcode signature for the function.
//
// Why we want it: ntdll protects the loader database -- the three PEB->Ldr
// module lists, LdrpHashTable, and the module base-address index -- with
// LdrpModuleDatatableLock, an SRW lock. It does NOT use LdrpLoaderLock for
// that; the legacy lock only serialises init routines (DllMain, thread
// attach/detach). MemoryModulePP splices those same lists while holding only
// the legacy lock, so every splice races ntdll's own, and ntdll eventually
// raises FAST_FAIL_CORRUPT_LIST_ENTRY from LdrpInsertDataTableEntry. See
// stress/README.md, "The wrong lock".
//
// How this finds it, without imitating ntdll or pinning a build:
//
//   Several *exported* ntdll functions acquire that lock by calling the
//   *exported* RtlAcquireSRWLockShared/Exclusive. The calling convention says
//   the lock pointer is the first argument. So both ends of the pattern are
//   things GetProcAddress can resolve, and the only thing we decode is the one
//   instruction that materialises the first argument.
//
//   ARM64, as emitted in 10.0.26100.8972:
//       adrp x21, #page
//       add  x0, x21, #0x9E0          <- first argument
//       bl   ntdll!RtlAcquireSRWLockExclusive
//
//   x64, expected shape:
//       lea  rcx, [rip+disp32]        <- first argument
//       call ntdll!RtlAcquireSRWLockExclusive
//
// Three donors must independently agree on one address, and then the address
// has to survive a causality test: hold it exclusively and an ordinary
// LoadLibrary on another thread must block, and must complete the moment we
// let go. A wrong address cannot pass that. This is what makes the technique
// safe to ship -- if it cannot be verified, the caller must refuse to publish
// into ntdll's lists rather than guess.
//
// Build:  see stress/build.cmd, or by hand:
//   cl /nologo /std:c++17 /O2 /MT /EHsc lockprobe.cpp /link /OUT:lockprobe.exe
//
// Exit code: 0 = located and verified, 1 = not verified, 2 = setup failure.
//

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

typedef VOID(NTAPI* PFN_SRW)(PVOID);

static PFN_SRW g_acqExcl, g_acqShared, g_relExcl;
static void* g_acqTargets[4];
static int   g_acqTargetCount = 0;

//
// Donors: exported, and each loads the lock into the first-argument register
// immediately before an explicit call to an exported SRW acquire. Verified on
// ARM64 10.0.26100.8972. Listed most-preferred first; any two agreeing is
// enough.
//
static const char* kDonors[] = {
    "LdrQueryModuleServiceTags",       // -> RtlAcquireSRWLockExclusive
    "LdrDisableThreadCalloutsForDll",  // -> RtlAcquireSRWLockShared
    "LdrGetDllHandleByMapping",        // -> RtlAcquireSRWLockShared
    "LdrAddRefDll",                    // inlined acquire on ARM64; may be a
                                       // plain call on x64, so worth trying
    "LdrGetDllFullName",
};

static bool IsAcquireTarget(const void* p) {
    for (int i = 0; i < g_acqTargetCount; ++i)
        if (g_acqTargets[i] == p) return true;
    return false;
}

//
// On ARM64X, an x64 caller's GetProcAddress returns an ARM64EC fast-forward
// sequence rather than an x64 body:
//     48 8b c4        mov  rax, rsp
//     48 89 58 20     mov  [rax+20h], rbx
//     55              push rbp
//     5d              pop  rbp
//     e9 <rel32>      jmp  <ARM64EC entry>
// Recognising it matters only so we can say so plainly instead of reporting a
// mysterious "no match".
//
static bool IsEcFastForward(const void* p, void** jmpTarget) {
    static const uint8_t sig[] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x20,0x55,0x5d,0xe9 };
    const uint8_t* b = (const uint8_t*)p;
    if (memcmp(b, sig, sizeof(sig)) != 0) return false;
    int32_t rel; memcpy(&rel, b + 10, 4);
    if (jmpTarget) *jmpTarget = (void*)(b + 14 + rel);
    return true;
}

// ------------------------------------------------------------- ARM64 decoding

//
// depth allows one level of recursion into a callee, which the ARM64EC build
// needs. Native ARM64 ntdll loads the lock into x0 and calls the SRW acquire
// directly, but the ARM64EC compilation of the same function instead calls a
// dedicated helper (LdrpAcquireModuleDatatableLock) that does the adrp/add/bl.
// So on ARM64EC the pattern is one `bl` further down.
//
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
            if (imm & (1LL << 20)) imm -= (1LL << 21);          // sign extend
            adrp[rd] = (pc & ~0xFFFULL) + (imm << 12);
            haveAdrp[rd] = true;
            continue;
        }

        // ADD Xd, Xn, #imm12 (64-bit, immediate, LSL #0)
        if ((insn & 0xFF800000u) == 0x91000000u) {
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
            if (off & (1LL << 25)) off -= (1LL << 26);          // sign extend
            const void* target = (const void*)(pc + (off << 2));
            if (IsAcquireTarget(target))
                return havePendingArg0 ? (void*)pendingArg0 : nullptr;
            // ARM64EC: the acquire lives in a callee. LdrQueryModuleServiceTags
            // calls LdrpAcquireModuleDatatableLock directly, but the other
            // donors go through LdrpFindLoadedDllByHandle or
            // LdrpDereferenceModule first, so it can be two levels down.
            if (depth > 0 && ++calls <= 6) {
                if (void* r = DecodeArm64(target, 128, depth - 1)) return r;
            }
            continue;
        }

        if (insn == 0xD65F03C0u) break;                          // RET
    }
    return nullptr;
}

// --------------------------------------------------------------- x64 decoding

//
// Byte scan rather than a length-disassembler: find the direct call to a known
// SRW acquire, then look back a short way for the instruction that loaded RCX.
// Both `lea rcx,[rip+d]` (48 8D 0D) and `mov rcx, imm64` (48 B9) are accepted.
//
static void* DecodeX64(const void* fn, size_t window) {
    const uint8_t* p = (const uint8_t*)fn;

    for (size_t i = 0; i + 5 <= window; ++i) {
        if (p[i] != 0xE8) continue;                              // call rel32
        int32_t rel; memcpy(&rel, p + i + 1, 4);
        if (!IsAcquireTarget(p + i + 5 + rel)) continue;

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
    }
    return nullptr;
}

// ---------------------------------------------------------------- diagnostics

static void DumpBytes(const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; ++i) {
        if (i && (i % 16) == 0) printf("\n                 ");
        printf("%02X ", b[i]);
    }
    printf("\n");
}

static void PrintNtdllIdentity(HMODULE nt) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((BYTE*)nt + dos->e_lfanew);
    printf("ntdll base      : %p\n", (void*)nt);
    printf("ntdll machine   : 0x%04X  (0x8664=x64, 0xAA64=ARM64)\n", h->FileHeader.Machine);
    printf("ntdll timestamp : 0x%08lX\n", (unsigned long)h->FileHeader.TimeDateStamp);
    printf("ntdll SizeOfImg : 0x%08lX\n", (unsigned long)h->OptionalHeader.SizeOfImage);
}

//
// Try the decoders in the order that suits the code we are looking at, under
// SEH. Recursing into a callee means following addresses we have not validated,
// and scanning ARM64 bytes with the x64 decoder can wander, so a fault here is
// a normal outcome and must not take the process down.
//
static void DecodeAny(const void* at, bool isEc, void** lockOut, const char** howOut) {
    *lockOut = nullptr;
    *howOut = "none";
    __try {
        if (isEc) {
            // ARM64EC body: ARM64 instructions, acquire up to two calls deeper.
            if ((*lockOut = DecodeArm64(at, 256, 2)) != nullptr) { *howOut = "arm64ec"; return; }
            if ((*lockOut = DecodeX64(at, 512)) != nullptr) { *howOut = "x64"; return; }
        }
        else {
            if ((*lockOut = DecodeX64(at, 512)) != nullptr) { *howOut = "x64"; return; }
            if ((*lockOut = DecodeArm64(at, 256, 0)) != nullptr) { *howOut = "arm64"; return; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *lockOut = nullptr;
        *howOut = "fault";
    }
}

// -------------------------------------------------- library-side validation

//
// The library cannot run the causality check below: it initialises inside
// DllMain, where spawning the probe thread would deadlock against the loader
// lock. So it accepts an address on donor agreement plus these structural
// checks instead. Reporting them here means one probe run answers both
// questions -- "is this the lock" and "would the library accept it" -- rather
// than leaving the second to be found out by a stress run on another machine.
//
// Keep this in step with MmpIsPlausibleLockAddress in
// MemoryModule/ModuleDatatableLock.cpp.
//
static bool ReportLibraryValidation(void* candidate, HMODULE nt) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((BYTE*)nt + dos->e_lfanew);

    bool aligned = ((ULONG_PTR)candidate & (sizeof(void*) - 1)) == 0;
    ULONG_PTR base = (ULONG_PTR)nt;
    ULONG_PTR end = base + h->OptionalHeader.SizeOfImage;
    bool inImage = (ULONG_PTR)candidate >= base &&
        (ULONG_PTR)candidate + sizeof(void*) <= end;

    MEMORY_BASIC_INFORMATION mbi{};
    bool queried = VirtualQuery(candidate, &mbi, sizeof(mbi)) != 0;
    bool committed = queried && mbi.State == MEM_COMMIT;
    const DWORD writableMask = PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    bool writable = queried && (mbi.Protect & writableMask) != 0;

    printf("  pointer-aligned : %s\n", aligned ? "yes" : "NO");
    printf("  inside ntdll    : %s (SizeOfImage 0x%lX)\n",
        inImage ? "yes" : "NO", (unsigned long)h->OptionalHeader.SizeOfImage);
    printf("  committed       : %s\n", committed ? "yes" : "NO");
    printf("  writable        : %s (protect 0x%lX)\n",
        writable ? "yes" : "NO", (unsigned long)mbi.Protect);

    bool accepted = aligned && inImage && committed && writable;
    printf("  library verdict : %s\n", accepted
        ? "WOULD ACCEPT"
        : "WOULD REJECT -- library needs a fix even though the probe verified");
    return accepted;
}

// --------------------------------------------------------------- verification

struct ProbeCtx { HANDLE go, done; };

static DWORD WINAPI ProbeThread(LPVOID param) {
    ProbeCtx* c = (ProbeCtx*)param;
    WaitForSingleObject(c->go, INFINITE);
    // An ordinary load: it must pass through the loader database, so it must
    // take the lock we are holding.
    HMODULE h = LoadLibraryW(L"version.dll");
    if (h) FreeLibrary(h);
    SetEvent(c->done);
    return 0;
}

//
// Hold the candidate exclusively and require that an ordinary LoadLibrary on
// another thread cannot finish, then require that it finishes once we release.
// Both halves matter: the first says we hold something that load path needs,
// the second says we were holding a lock rather than having wedged the process
// some other way.
//
static bool VerifyByCausality(void* candidate) {
    ProbeCtx ctx;
    ctx.go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ctx.done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ctx.go || !ctx.done) return false;

    // Create the thread before taking the lock: thread start-up runs
    // DLL_THREAD_ATTACH, which enters the loader.
    HANDLE th = CreateThread(nullptr, 0, ProbeThread, &ctx, 0, nullptr);
    if (!th) return false;
    Sleep(50);                        // let it reach its wait

    g_acqExcl(candidate);
    SetEvent(ctx.go);
    DWORD blocked = WaitForSingleObject(ctx.done, 400);
    g_relExcl(candidate);
    DWORD freed = WaitForSingleObject(ctx.done, 5000);

    WaitForSingleObject(th, 5000);
    CloseHandle(th); CloseHandle(ctx.go); CloseHandle(ctx.done);

    printf("  while held    : %s\n",
        blocked == WAIT_TIMEOUT ? "LoadLibrary blocked      (expected)"
        : "LoadLibrary COMPLETED    (wrong address)");
    printf("  after release : %s\n",
        freed == WAIT_OBJECT_0 ? "LoadLibrary completed    (expected)"
        : "LoadLibrary STILL BLOCKED (not the lock)");
    return blocked == WAIT_TIMEOUT && freed == WAIT_OBJECT_0;
}

// ---------------------------------------------------------------------- main

int main(int argc, char** argv) {
    bool dumpAlways = (argc > 1 && !strcmp(argv[1], "--dump"));

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) { printf("no ntdll\n"); return 2; }

    g_acqExcl = (PFN_SRW)GetProcAddress(nt, "RtlAcquireSRWLockExclusive");
    g_acqShared = (PFN_SRW)GetProcAddress(nt, "RtlAcquireSRWLockShared");
    g_relExcl = (PFN_SRW)GetProcAddress(nt, "RtlReleaseSRWLockExclusive");
    if (!g_acqExcl || !g_acqShared || !g_relExcl) {
        printf("could not resolve the exported SRW routines\n");
        return 2;
    }

    printf("==================== lockprobe report ====================\n");
#if defined(_M_ARM64)
    printf("built for       : arm64\n");
#elif defined(_M_X64)
    printf("built for       : x64\n");
#else
    printf("built for       : (unsupported)\n");
#endif
    PrintNtdllIdentity(nt);

    // A call site may target either the export or, on ARM64X, whatever its
    // fast-forward thunk jumps to. Accept both.
    g_acqTargets[g_acqTargetCount++] = (void*)g_acqExcl;
    g_acqTargets[g_acqTargetCount++] = (void*)g_acqShared;
    void* t = nullptr;
    if (IsEcFastForward((void*)g_acqExcl, &t))   g_acqTargets[g_acqTargetCount++] = t;
    if (IsEcFastForward((void*)g_acqShared, &t)) g_acqTargets[g_acqTargetCount++] = t;

    printf("SRW acquire     : excl=%p shared=%p\n", (void*)g_acqExcl, (void*)g_acqShared);
    printf("\n--- donors ---\n");

    void* agreed = nullptr;
    int matched = 0, agree = 0, thunked = 0;
    const int kDonorCount = (int)(sizeof(kDonors) / sizeof(kDonors[0]));

    for (int i = 0; i < kDonorCount; ++i) {
        void* fn = (void*)GetProcAddress(nt, kDonors[i]);
        printf("%s\n", kDonors[i]);
        if (!fn) { printf("  NOT EXPORTED\n\n"); continue; }
        printf("  addr          : %p  (ntdll+0x%llX)\n",
            fn, (unsigned long long)((BYTE*)fn - (BYTE*)nt));

        //
        // On ARM64X an x64 caller's export is a fast-forward thunk into the
        // ARM64EC body. Follow it and decode there: the bytes at the export
        // itself are only the thunk, and the real code is ARM64.
        //
        void* ecTarget = nullptr;
        bool isThunk = IsEcFastForward(fn, &ecTarget);
        const void* decodeAt = fn;
        if (isThunk) {
            ++thunked;
            decodeAt = ecTarget;
            printf("  form          : ARM64EC fast-forward thunk -> %p\n", ecTarget);
        }

        void* lock = nullptr;
        const char* how = "none";
        DecodeAny(decodeAt, isThunk, &lock, &how);

        if (lock) {
            ++matched;
            printf("  decoded via   : %s\n", how);
            printf("  LOCK          : %p  (ntdll+0x%llX)\n",
                lock, (unsigned long long)((BYTE*)lock - (BYTE*)nt));
            if (!agreed) { agreed = lock; agree = 1; }
            else if (agreed == lock) ++agree;
            else printf("  *** DISAGREES with %p ***\n", agreed);
        }
        else {
            printf("  decoded via   : NO MATCH\n");
        }

        if (!lock || dumpAlways) {
            printf("  first 48 bytes: ");
            DumpBytes(fn, 48);
        }
        printf("\n");
    }

    printf("--- summary ---\n");
    printf("donors decoded  : %d of %d\n", matched, kDonorCount);
    printf("agreeing        : %d\n", agree);
    if (thunked) printf("EC thunks seen  : %d  (running x64 on an ARM64X host)\n", thunked);

    if (!agreed || agree < 2) {
        printf("\nRESULT: NOT LOCATED -- need %s\n",
            thunked ? "a genuine x64 host, or ARM64X redirection support"
            : "a decoder fix; send the byte dumps above");
        printf("==========================================================\n");
        return 1;
    }

    printf("candidate       : %p  (ntdll+0x%llX)\n",
        agreed, (unsigned long long)((BYTE*)agreed - (BYTE*)nt));

    printf("\n--- library-side validation ---\n");
    bool accepted = ReportLibraryValidation(agreed, nt);

    printf("\n--- causality check ---\n");
    bool ok = VerifyByCausality(agreed);

    printf("\nRESULT: %s\n", (ok && accepted)
        ? "VERIFIED -- this is LdrpModuleDatatableLock, and the library will use it"
        : ok
        ? "VERIFIED as the lock, but the library's validation would REJECT it"
        : "FAILED VERIFICATION -- do not use this address");
    ok = ok && accepted;
    printf("==========================================================\n");
    return ok ? 0 : 1;
}
