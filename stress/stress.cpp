//
// Loader stress harness for MemoryModulePP.
//
// Exercises the concurrency this library was never designed for, and validates
// the thing that actually breaks: ntdll's loader database. A memory module load
// writes into PEB->Ldr's three module lists, ntdll's LdrpHashTable, and ntdll's
// LdrpModuleBaseAddressIndex red-black tree. ntdll mutates those from its own
// loader under the loader lock, so unsynchronized writes from here corrupt them,
// and the damage usually surfaces later and somewhere unrelated.
//
// So rather than only watching for crashes, this walks the three loader lists
// and verifies every node's Flink/Blink still agree. A crossed or dropped link
// is caught at the next check instead of as a mystery access violation minutes
// later. The walk itself is done holding the loader lock, which is the only way
// to read those lists safely while other threads load.
//
// Modes:
//   same     - every thread loads the same image under the same name, which
//              drives the duplicate-module scan and the reference count path
//   distinct - every thread uses its own name, so each gets its own mapping and
//              they all insert into the shared lists concurrently
//   mixed    - both, plus noise threads doing ordinary LoadLibrary/FreeLibrary
//              of system DLLs to race ntdll's own loader against us
//
// Build with stress/build.cmd. Exit code is 0 only if every check passed.
//

#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <random>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ntdll.lib")

//
// From MemoryModule/Loader.h. Duplicated rather than included so the harness
// builds against a shipped DLL without needing the source tree's headers.
//
#define LOAD_FLAGS_USE_DLL_NAME               0x00040000
#define LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS     0x20000000
#define LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION  0x00010000

//
// Set by --no-ift. Loading with LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION skips all
// LdrpInvertedFunctionTable manipulation, which isolates whether a failure comes
// from that table or from the rest of the load path.
//
static bool g_skipInvertedTable = false;

//
// Set by --force-seh. Uses the exception-raising probe even under --no-ift, to
// test whether x64 exception dispatch into a memory module works without an
// LdrpInvertedFunctionTable entry at all.
//
static bool g_forceSeh = false;

typedef HMODULE(WINAPI* PFN_LoadLibraryMemoryExW)(PVOID, size_t, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL(WINAPI* PFN_FreeLibraryMemory)(HMODULE);
typedef int(*PFN_StressPing)(int);

typedef NTSTATUS(NTAPI* PFN_LdrLockLoaderLock)(ULONG, ULONG*, PVOID*);
typedef NTSTATUS(NTAPI* PFN_LdrUnlockLoaderLock)(ULONG, PVOID);
typedef VOID(NTAPI* PFN_SRW)(PVOID);

//
// ntdll!LdrpModuleDatatableLock, which is what actually guards the three
// PEB->Ldr lists. Not exported by ntdll, so it is taken from the DLL under
// test: it locates the lock and exports the RVA it found. Resolved in main().
//
// This matters for the integrity check below. Walking those lists under
// LdrLockLoaderLock does not exclude ntdll's own splices, so the walk could
// observe a genuine mid-splice tear and report it as corruption -- a false
// positive that made the "soft failure" count untrustworthy. Reading them under
// the right lock, shared, is sound.
//
static PVOID    g_datatableLock = nullptr;
static PFN_SRW  g_acquireShared = nullptr;
static PFN_SRW  g_releaseShared = nullptr;

static PFN_LoadLibraryMemoryExW g_loadMemory = nullptr;
static PFN_FreeLibraryMemory    g_freeMemory = nullptr;
static PFN_LdrLockLoaderLock    g_lockLoader = nullptr;
static PFN_LdrUnlockLoaderLock  g_unlockLoader = nullptr;

static std::atomic<long long> g_loads{ 0 };
static std::atomic<long long> g_unloads{ 0 };
static std::atomic<long long> g_loadFailures{ 0 };
static std::atomic<long long> g_unloadFailures{ 0 };
static std::atomic<long long> g_pingFailures{ 0 };
static std::atomic<long long> g_noiseLoads{ 0 };
static std::atomic<long long> g_integrityChecks{ 0 };
static std::atomic<long long> g_integrityFailures{ 0 };
static std::atomic<bool>      g_stop{ false };

//
// PEB_LDR_DATA as winternl.h declares it only names InMemoryOrderModuleList, so
// declare the full shape to reach all three lists.
//
struct STRESS_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

static STRESS_PEB_LDR_DATA* GetLdrData() {
    PPEB peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    return (STRESS_PEB_LDR_DATA*)peb->Ldr;
}

//
// Verify a doubly linked list is internally consistent: every node's neighbours
// must point back at it, and the walk must terminate at the head. A torn insert
// shows up as a broken back-pointer or a walk that never comes home.
//
static bool CheckList(LIST_ENTRY* head, const char* name, std::string& detail) {
    const int kMaxNodes = 8192;
    int count = 0;

    for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
        if (++count > kMaxNodes) {
            char buf[256];
            sprintf_s(buf, "%s: walk exceeded %d nodes (list is looped or corrupt)", name, kMaxNodes);
            detail = buf;
            return false;
        }

        if (e->Flink == nullptr || e->Blink == nullptr) {
            char buf[256];
            sprintf_s(buf, "%s: node %p has a null link (Flink=%p Blink=%p)",
                name, (void*)e, (void*)e->Flink, (void*)e->Blink);
            detail = buf;
            return false;
        }

        if (e->Flink->Blink != e) {
            char buf[256];
            sprintf_s(buf, "%s: node %p Flink->Blink=%p (expected %p)",
                name, (void*)e, (void*)e->Flink->Blink, (void*)e);
            detail = buf;
            return false;
        }

        if (e->Blink->Flink != e) {
            char buf[256];
            sprintf_s(buf, "%s: node %p Blink->Flink=%p (expected %p)",
                name, (void*)e, (void*)e->Blink->Flink, (void*)e);
            detail = buf;
            return false;
        }
    }

    return true;
}

//
// Read the loader lists under the loader lock. Without the lock this check would
// race the very mutations it is looking for and report false positives.
//
static bool CheckLoaderIntegrity(std::string& detail) {
    STRESS_PEB_LDR_DATA* ldr = GetLdrData();
    ULONG disposition = 0;
    PVOID cookie = nullptr;
    bool held = false;
    bool sharedHeld = false;

    //
    // Prefer the lock that actually guards these lists. Fall back to the loader
    // lock only when testing a DLL that cannot tell us where it is, in which
    // case this check keeps its old, unsound behaviour rather than none at all.
    //
    if (g_datatableLock && g_acquireShared) {
        g_acquireShared(g_datatableLock);
        sharedHeld = true;
    }
    else if (g_lockLoader && g_lockLoader(0, &disposition, &cookie) >= 0 && disposition == 1) {
        held = true;
    }

    bool ok = true;
    __try {
        ok = CheckList(&ldr->InLoadOrderModuleList, "InLoadOrderModuleList", detail) &&
            CheckList(&ldr->InMemoryOrderModuleList, "InMemoryOrderModuleList", detail) &&
            CheckList(&ldr->InInitializationOrderModuleList, "InInitializationOrderModuleList", detail);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        detail = "access violation while walking the loader lists";
        ok = false;
    }

    if (sharedHeld && g_releaseShared) {
        g_releaseShared(g_datatableLock);
    }
    else if (held && g_unlockLoader) {
        g_unlockLoader(0, cookie);
    }

    g_integrityChecks.fetch_add(1);
    if (!ok) g_integrityFailures.fetch_add(1);
    return ok;
}

static PVOID ReadFileIntoMemory(const char* path, size_t* sizeOut) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return nullptr;

    _fseeki64(f, 0, SEEK_END);
    long long size = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
    if (size <= 0) { fclose(f); return nullptr; }

    //
    // MemoryModulePP wants the raw image in RWX memory; it maps out of this
    // buffer and the buffer must outlive nothing (it copies), but PAGE_EXECUTE
    // matches how the product supplies it.
    //
    PVOID buffer = VirtualAlloc(nullptr, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) { fclose(f); return nullptr; }

    size_t read = fread(buffer, 1, (size_t)size, f);
    fclose(f);

    if (read != (size_t)size) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return nullptr;
    }

    if (sizeOut) *sizeOut = (size_t)size;
    return buffer;
}

//
// One loader thread: load the payload from memory, call into it to prove the
// module is actually usable (this is what catches a module published with a
// missing inverted function table or unhandled TLS), then unload.
//
static void LoaderThread(int index, PVOID image, bool distinctNames, int iterations) {
    std::mt19937 rng((unsigned)(GetTickCount64() ^ (index * 2654435761u)));
    std::uniform_int_distribution<int> shortSleep(0, 3);
    std::uniform_int_distribution<int> longSleep(0, 40);
    std::uniform_int_distribution<int> coin(0, 9);

    //
    // In distinct mode each thread claims its own module name so every load maps
    // a new image; in same mode they all collide on one name and drive the
    // duplicate scan and reference counting instead.
    //
    std::wstring baseName = distinctNames
        ? (L"stress_" + std::to_wstring(index) + L".dll")
        : std::wstring(L"stress_shared.dll");
    std::wstring fullName = L"C:\\MemoryModules\\" + baseName;

    DWORD flags = LOAD_FLAGS_USE_DLL_NAME | LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS;
    if (g_skipInvertedTable) flags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

    const char* pingExport = (g_skipInvertedTable && !g_forceSeh) ? "StressPingNoSeh" : "StressPing";

    for (int i = 0; i < iterations && !g_stop.load(); ++i) {
        if (coin(rng) == 0) Sleep(longSleep(rng)); else Sleep(shortSleep(rng));

        HMODULE mod = g_loadMemory(image, 0, baseName.c_str(), fullName.c_str(), flags);
        if (!mod) {
            g_loadFailures.fetch_add(1);
            continue;
        }
        g_loads.fetch_add(1);

        //
        // Interleave here on purpose: this is the window where the module is
        // published in the loader lists but this thread has not unloaded it yet.
        //
        if (coin(rng) < 3) SwitchToThread(); else Sleep(shortSleep(rng));

        PFN_StressPing ping = (PFN_StressPing)GetProcAddress(mod, pingExport);
        if (!ping) {
            g_pingFailures.fetch_add(1);
        }
        else {
            //
            // StressPing raises and handles an access violation internally and
            // returns value+1, so a wrong answer means exception dispatch or TLS
            // through this module is broken.
            //
            if (ping(index) != index + 1) g_pingFailures.fetch_add(1);
        }

        if (coin(rng) < 3) SwitchToThread(); else Sleep(shortSleep(rng));

        if (!g_freeMemory(mod)) g_unloadFailures.fetch_add(1);
        else g_unloads.fetch_add(1);
    }
}

//
// Ordinary LoadLibrary/FreeLibrary traffic. This is the important adversary: it
// makes ntdll mutate the same lists we write, from another thread, under the
// loader lock we may or may not be holding.
//
static void NoiseThread(int index) {
    static const wchar_t* kModules[] = {
        L"winmm.dll", L"version.dll", L"wintrust.dll", L"imagehlp.dll",
        L"psapi.dll", L"userenv.dll", L"secur32.dll", L"dnsapi.dll",
        L"iphlpapi.dll", L"powrprof.dll", L"cryptnet.dll", L"wtsapi32.dll",
    };
    const int kCount = (int)(sizeof(kModules) / sizeof(kModules[0]));

    std::mt19937 rng((unsigned)(GetTickCount64() ^ (index * 40503u) ^ 0x5bd1e995u));
    std::uniform_int_distribution<int> pick(0, kCount - 1);
    std::uniform_int_distribution<int> nap(0, 5);

    while (!g_stop.load()) {
        HMODULE h = LoadLibraryW(kModules[pick(rng)]);
        if (h) {
            g_noiseLoads.fetch_add(1);
            Sleep(nap(rng));
            FreeLibrary(h);
        }
        Sleep(nap(rng));
    }
}

//
// Resolve a faulting address to module + offset. Without this a crash report is
// just a bare address, which says nothing about whether the fault is in ntdll's
// loader, in MemoryModulePP, or in the payload.
//
static void DescribeAddress(PVOID addr, char* out, size_t outSize) {
    HMODULE mod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)addr, &mod) && mod) {
        wchar_t path[MAX_PATH] = L"";
        GetModuleFileNameW(mod, path, MAX_PATH);
        const wchar_t* leaf = wcsrchr(path, L'\\');
        leaf = leaf ? leaf + 1 : path;
        sprintf_s(out, outSize, "%ls+0x%llX",
            leaf, (unsigned long long)((BYTE*)addr - (BYTE*)mod));
    }
    else {
        //
        // No owning module: typically a memory module that has already been
        // unmapped, or a wild jump.
        //
        sprintf_s(out, outSize, "<no module> %p", addr);
    }
}

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* info) {
    char where[512];
    DescribeAddress(info->ExceptionRecord->ExceptionAddress, where, sizeof(where));

    fprintf(stderr,
        "\n!! CRASH: code=0x%08lX at %p (%s)\n",
        info->ExceptionRecord->ExceptionCode,
        info->ExceptionRecord->ExceptionAddress, where);

    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        info->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, "   %s address %p\n",
            info->ExceptionRecord->ExceptionInformation[0] ? "writing" : "reading",
            (PVOID)info->ExceptionRecord->ExceptionInformation[1]);
    }

    fprintf(stderr,
        "   loads=%lld unloads=%lld noise=%lld integrityChecks=%lld\n",
        g_loads.load(), g_unloads.load(), g_noiseLoads.load(), g_integrityChecks.load());
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void Usage() {
    printf(
        "usage: stress [options]\n"
        "  --dll <path>       MemoryModule DLL to test   (default MemoryModule64.dll)\n"
        "  --payload <path>   image to load from memory  (default stresspayload.dll)\n"
        "  --mode <m>         same | distinct | mixed    (default mixed)\n"
        "  --threads <n>      loader threads             (default 8, 0 = noise-only control)\n"
        "  --noise <n>        LoadLibrary noise threads  (default 4)\n"
        "  --iters <n>        load/unload per thread     (default 200)\n"
        "  --seconds <n>      duration when --threads 0  (default 5)\n"
    );
}

int main(int argc, char** argv) {
    const char* dllPath = "MemoryModule64.dll";
    const char* payloadPath = "stresspayload.dll";
    std::string mode = "mixed";
    int threads = 8, noise = 4, iters = 200, noiseSeconds = 5;

    for (int i = 1; i < argc; ++i) {
        auto next = [&](const char* what) -> const char* {
            if (i + 1 >= argc) { fprintf(stderr, "missing value for %s\n", what); exit(2); }
            return argv[++i];
        };
        if (!strcmp(argv[i], "--dll")) dllPath = next("--dll");
        else if (!strcmp(argv[i], "--payload")) payloadPath = next("--payload");
        else if (!strcmp(argv[i], "--mode")) mode = next("--mode");
        else if (!strcmp(argv[i], "--threads")) threads = atoi(next("--threads"));
        else if (!strcmp(argv[i], "--noise")) noise = atoi(next("--noise"));
        else if (!strcmp(argv[i], "--iters")) iters = atoi(next("--iters"));
        else if (!strcmp(argv[i], "--seconds")) noiseSeconds = atoi(next("--seconds"));
        else if (!strcmp(argv[i], "--no-ift")) g_skipInvertedTable = true;
        else if (!strcmp(argv[i], "--force-seh")) g_forceSeh = true;
        else { Usage(); return 2; }
    }

    if (mode != "same" && mode != "distinct" && mode != "mixed") { Usage(); return 2; }
    if (threads < 0) threads = 0;
    if (iters < 1) iters = 1;

    //
    // threads == 0 is the control case: noise only, no memory modules at all.
    // If that ever fails, the harness or the machine is at fault rather than
    // MemoryModulePP, because it is nothing but ordinary LoadLibrary traffic.
    //
    if (threads == 0 && noise == 0) {
        fprintf(stderr, "nothing to do: both --threads and --noise are 0\n");
        return 2;
    }

    //
    // Under a debugger, leave the exception alone so it reaches second chance
    // and the debugger can produce a stack. Our filter returns
    // EXECUTE_HANDLER, which would otherwise exit cleanly and hide the fault.
    //
    if (!IsDebuggerPresent()) {
        SetUnhandledExceptionFilter(CrashFilter);
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    g_lockLoader = (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock");
    g_unlockLoader = (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock");
    if (!g_lockLoader || !g_unlockLoader) {
        fprintf(stderr, "could not resolve LdrLockLoaderLock/LdrUnlockLoaderLock\n");
        return 1;
    }

    HMODULE mm = LoadLibraryA(dllPath);
    if (!mm) {
        fprintf(stderr, "failed to load %s (error %lu)\n", dllPath, GetLastError());
        return 1;
    }
    g_loadMemory = (PFN_LoadLibraryMemoryExW)GetProcAddress(mm, "LoadLibraryMemoryExW");
    g_freeMemory = (PFN_FreeLibraryMemory)GetProcAddress(mm, "FreeLibraryMemory");
    if (!g_loadMemory || !g_freeMemory) {
        fprintf(stderr, "%s does not export LoadLibraryMemoryExW/FreeLibraryMemory\n", dllPath);
        return 1;
    }

    //
    // Take the address of ntdll!LdrpModuleDatatableLock from the DLL under test,
    // which located it during its own initialization. Used only to make the
    // integrity check below read the loader lists under the correct lock.
    //
    {
        auto rva = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockRva");
        auto located = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockLocated");
        g_acquireShared = (PFN_SRW)GetProcAddress(ntdll, "RtlAcquireSRWLockShared");
        g_releaseShared = (PFN_SRW)GetProcAddress(ntdll, "RtlReleaseSRWLockShared");
        if (rva && located && *located && *rva && g_acquireShared && g_releaseShared) {
            g_datatableLock = (PVOID)((BYTE*)ntdll + *rva);
        }
    }

    size_t imageSize = 0;
    PVOID image = ReadFileIntoMemory(payloadPath, &imageSize);
    if (!image) {
        fprintf(stderr, "failed to read payload %s\n", payloadPath);
        return 1;
    }

    printf("MemoryModulePP loader stress\n");
    printf("  dll      : %s\n", dllPath);
    printf("  payload  : %s (%zu bytes)\n", payloadPath, imageSize);
    printf("  mode     : %s\n", mode.c_str());
    printf("  threads  : %d loader, %d noise\n", threads, mode == "same" || mode == "distinct" ? noise : noise);
    printf("  iters    : %d per loader thread\n\n", iters);

    std::string detail;
    if (!CheckLoaderIntegrity(detail)) {
        fprintf(stderr, "loader lists were already inconsistent before starting: %s\n", detail.c_str());
        return 1;
    }

    ULONGLONG start = GetTickCount64();

    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) {
        //
        // In mixed mode half the threads collide on one name and half use their
        // own, so the duplicate-scan path and the concurrent-insert path run at
        // the same time.
        //
        bool distinct = (mode == "distinct") || (mode == "mixed" && (i % 2 == 0));
        workers.emplace_back(LoaderThread, i, image, distinct, iters);
    }

    std::vector<std::thread> noisers;
    for (int i = 0; i < noise; ++i) noisers.emplace_back(NoiseThread, i);

    //
    // Poll the loader lists while the workers hammer, so corruption is attributed
    // to roughly when it happened rather than discovered at the end.
    //
    std::thread monitor([&]() {
        std::string d;
        while (!g_stop.load()) {
            if (!CheckLoaderIntegrity(d)) {
                fprintf(stderr, "\n!! LOADER LIST CORRUPTION: %s\n", d.c_str());
                fflush(stderr);
                g_stop.store(true);
                return;
            }
            Sleep(50);
        }
        });

    if (workers.empty()) {
        //
        // Noise-only control run: there is no iteration count to bound it, so
        // give the noise threads a fixed window.
        //
        printf("noise-only control run: %d seconds\n", noiseSeconds);
        for (int i = 0; i < noiseSeconds * 10 && !g_stop.load(); ++i) Sleep(100);
    }

    for (auto& t : workers) t.join();
    g_stop.store(true);
    for (auto& t : noisers) t.join();
    monitor.join();

    ULONGLONG elapsed = GetTickCount64() - start;

    if (!CheckLoaderIntegrity(detail)) {
        fprintf(stderr, "final loader list check failed: %s\n", detail.c_str());
    }

    printf("\nresults after %llu ms\n", elapsed);
    printf("  memory loads      : %lld\n", g_loads.load());
    printf("  memory unloads    : %lld\n", g_unloads.load());
    printf("  noise loads       : %lld\n", g_noiseLoads.load());
    printf("  integrity checks  : %lld\n", g_integrityChecks.load());
    printf("  ----\n");
    printf("  load failures     : %lld\n", g_loadFailures.load());
    printf("  unload failures   : %lld\n", g_unloadFailures.load());
    printf("  ping failures     : %lld\n", g_pingFailures.load());
    printf("  integrity failures: %lld\n", g_integrityFailures.load());

    //
    // Read the loader lock failure counter out of the DLL under test. Anything
    // but zero means it spliced ntdll's module lists without the loader lock
    // held, which would explain list corruption directly and rule everything
    // else out.
    //
    {
        auto failures = (volatile LONG*)GetProcAddress(mm, "MmpLoaderLockAcquireFailures");
        if (failures) printf("  loaderlock acq failures: %ld\n", *failures);
        else printf("  loaderlock acq failures: (not exported)\n");
    }

    //
    // Whether the datatable lock is actually in play. A clean run means nothing
    // unless "located" is 1 and "acquires" tracks the load count -- otherwise
    // every guard was a no-op and the run proved only that the race is
    // probabilistic.
    //
    {
        auto located = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockLocated");
        auto acquires = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockAcquires");
        auto skipped = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockSkipped");
        auto rva = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockRva");
        auto agree = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockAgreement");
        if (located) {
            printf("  datatable lock    : %s", *located ? "LOCATED" : "NOT LOCATED (guards are no-ops)");
            if (*located && rva) printf(" at ntdll+0x%lX", (unsigned long)*rva);
            //
            // The margin above the two-donor minimum. Printed on every run
            // because a shrinking margin is the only advance warning that a
            // Windows update is inlining the acquire donor by donor.
            //
            if (*located && agree) printf("  (%ld donors agreed, need 2)", (long)*agree);
            printf("\n");
            if (acquires) printf("  datatable acquires: %ld\n", *acquires);
            if (skipped && *skipped) printf("  datatable skipped : %ld\n", *skipped);
        }
        else {
            printf("  datatable lock    : (not exported -- old build under test)\n");
        }
    }

    long long bad = g_loadFailures.load() + g_unloadFailures.load() +
        g_pingFailures.load() + g_integrityFailures.load();

    //
    // Any leftover reference means load/unload did not balance.
    //
    if (g_loads.load() != g_unloads.load()) {
        printf("  NOTE: %lld loads did not pair with an unload\n",
            g_loads.load() - g_unloads.load());
    }

    printf("\n%s\n", bad == 0 ? "PASS" : "FAIL");
    return bad == 0 ? 0 : 1;
}
