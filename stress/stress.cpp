//
// Loader stress harness for MemoryModulePP -- options, setup, orchestration and
// the report. The workload lives in workload.cpp and the shared state, payload
// IO, integrity checking and crash reporting in bench.{h,cpp}.
//
// Exercises the concurrency this library was never designed for, and validates
// the thing that actually breaks: ntdll's loader database. A memory module load
// writes into PEB->Ldr's three module lists, ntdll's LdrpHashTable, and ntdll's
// LdrpModuleBaseAddressIndex red-black tree. ntdll mutates those from its own
// loader, so unsynchronized writes from here corrupt them, and the damage
// usually surfaces later and somewhere unrelated.
//
// So rather than only watching for crashes, this walks the three loader lists
// and verifies every node's Flink/Blink still agree. A crossed or dropped link
// is caught at the next check instead of as a mystery access violation minutes
// later.
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

#include "bench.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>

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
        "  --prewarm          MmInitialize on its own thread before any load\n"
        "  --native           map the payload with LoadLibraryW, not MemoryModulePP\n"
        "                     (single-variable control; everything else identical)\n"
        "  --no-ift           load with LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION\n"
        "  --force-seh        use the SEH ping even under --no-ift\n"
    );
}

int main(int argc, char** argv) {
    const char* dllPath = "MemoryModule64.dll";
    const char* payloadPath = "stresspayload.dll";
    std::string mode = "mixed";
    int threads = 8, noise = 4, iters = 200, noiseSeconds = 5;
    bool prewarm = false;

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
        else if (!strcmp(argv[i], "--native")) g_native = true;
        else if (!strcmp(argv[i], "--prewarm")) prewarm = true;
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

    size_t imageSize = 0;
    PVOID image = ReadFileIntoMemory(payloadPath, &imageSize);
    if (!image) {
        fprintf(stderr, "failed to read payload %s\n", payloadPath);
        return 1;
    }

    //
    // The library no longer initializes from DllMain, so nothing has been
    // located yet -- read the flag now and assert that, because a build that
    // regressed to initializing in DllMain would still pass every other check
    // here while silently losing the causality verification.
    //
    auto locatedFlag = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockLocated");
    auto verifiedFlag = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockVerified");
    bool eagerInDllMain = locatedFlag && *locatedFlag;

    //
    // --prewarm models a consumer that pushes initialization onto a thread of
    // its own so nothing is left to pay for on the first real load. What has to
    // hold for that to be worth doing is that the causality check -- the only
    // expensive part -- runs on that thread and not later. So measure it there
    // and require it to be complete before any load happens.
    //
    long long prewarmMs = -1;
    if (prewarm) {
        auto init = (NTSTATUS(NTAPI*)())GetProcAddress(mm, "MmInitialize");
        if (!init) {
            fprintf(stderr, "%s does not export MmInitialize\n", dllPath);
            return 1;
        }

        auto start = std::chrono::steady_clock::now();
        NTSTATUS st = 0;
        std::thread t([&] { st = init(); });
        t.join();
        prewarmMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();

        if (st < 0) {
            fprintf(stderr, "prewarm MmInitialize failed (0x%08lX)\n", (unsigned long)st);
            return 1;
        }
        if (!locatedFlag || !*locatedFlag) {
            fprintf(stderr, "prewarm did not locate the datatable lock\n");
            return 1;
        }
        if (!verifiedFlag || !*verifiedFlag) {
            fprintf(stderr, "prewarm left causality unverified -- the cost would "
                            "still land on the first load\n");
            return 1;
        }
    }

    //
    // One throwaway load to trigger first-use initialization. This is the path a
    // real consumer takes, and it is what runs the causality check -- on an
    // ordinary thread, which is the whole point of moving init out of DllMain.
    //
    {
        // Same flags the loader threads use, minus the name options: a bare
        // load fails on the TLS defect this bench already tolerates.
        DWORD warmFlags = LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS;
        if (g_skipInvertedTable) warmFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

        HMODULE warmup = g_loadMemory(image, 0, nullptr, nullptr, warmFlags);
        if (!warmup) {
            fprintf(stderr, "warm-up load failed (error %lu); lock located=%ld\n",
                GetLastError(), locatedFlag ? (long)*locatedFlag : -1);
            return 1;
        }
        g_freeMemory(warmup);
    }

    //
    // Take the address of ntdll!LdrpModuleDatatableLock from the DLL under test,
    // now that initialization has run. Used only to make the integrity check
    // read the loader lists under the correct lock.
    //
    {
        auto rva = (volatile LONG*)GetProcAddress(mm, "MmpModuleDatatableLockRva");
        g_acquireShared = (PFN_SRW)GetProcAddress(ntdll, "RtlAcquireSRWLockShared");
        g_releaseShared = (PFN_SRW)GetProcAddress(ntdll, "RtlReleaseSRWLockShared");
        if (rva && locatedFlag && *locatedFlag && *rva && g_acquireShared && g_releaseShared) {
            g_datatableLock = (PVOID)((BYTE*)ntdll + *rva);
        }
    }

    //
    // One payload copy per loader thread for --native, regardless of mode: mixed
    // mode decides distinctNames per thread, so sizing this by mode alone
    // indexed off the end of the vector and handed LoadLibraryW a garbage
    // wstring -- which faulted inside ntdll on environment-block bytes and
    // looked exactly like a loader bug. Index 0 doubles as the shared path.
    //
    if (g_native) {
        for (int i = 0; i < (threads > 0 ? threads : 1); ++i) {
            char dest[MAX_PATH];
            _snprintf_s(dest, sizeof(dest), _TRUNCATE, "%s.native%d.dll", payloadPath, i);
            if (!CopyFileA(payloadPath, dest, FALSE)) {
                fprintf(stderr, "failed to copy payload to %s (error %lu)\n", dest, GetLastError());
                return 1;
            }
            wchar_t wdest[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, dest, -1, wdest, MAX_PATH);
            g_nativePaths.emplace_back(wdest);
        }
    }

    printf("MemoryModulePP loader stress\n");
    printf("  dll      : %s\n", dllPath);
    printf("  loader   : %s\n", g_native
        ? "LoadLibraryW  (CONTROL -- MemoryModulePP loaded but not used to map)"
        : "MemoryModulePP");
    printf("  payload  : %s (%zu bytes)\n", payloadPath, imageSize);
    printf("  mode     : %s\n", mode.c_str());
    printf("  threads  : %d loader, %d noise\n", threads, noise);
    printf("  iters    : %d per loader thread\n", iters);

    //
    // Which capabilities actually came up. This is not decoration: the TLS
    // locator is an x64-only byte scan, so on ARM64 it finds nothing,
    // MmpTlsInitialize nulls both TLS pointers and clears this bit, and the load
    // then succeeds anyway because the loader threads pass
    // LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS. The payload's thread_local resolves
    // through an unallocated index and the run still reports PASS.
    //
    // So a ping-failure count is only interpretable next to this line. Comparing
    // arms while TLS handling is off on one of them measures nothing.
    //
    DWORD features = 0;
    {
        auto q = (PFN_LdrQueryFeatures)GetProcAddress(mm, "LdrQuerySystemMemoryModuleFeatures");
        if (q && q(&features) >= 0) {
            printf("  features : 0x%02lX  tls-handle=%s tls-release=%s base-index=%s hash=%s ift=%s\n",
                features,
                (features & MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA) ? "ON" : "OFF",
                (features & MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY) ? "ON" : "OFF",
                (features & MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX) ? "ON" : "OFF",
                (features & MEMORY_FEATURE_LDRP_HASH_TABLE) ? "ON" : "OFF",
                (features & MEMORY_FEATURE_INVERTED_FUNCTION_TABLE) ? "ON" : "OFF");
            //
            // Where the TLS locator actually got to. "Refused" is the ARM64EC
            // gate: the addresses are right and this process must not call them,
            // which is a platform limit rather than a locator failure and has to
            // read differently from "found nothing".
            //
            auto tlsLoc = (volatile LONG*)GetProcAddress(mm, "MmpTlsLocated");
            auto tlsH = (volatile LONG*)GetProcAddress(mm, "MmpTlsHandleRva");
            auto tlsR = (volatile LONG*)GetProcAddress(mm, "MmpTlsReleaseRva");
            auto tlsA = (volatile LONG*)GetProcAddress(mm, "MmpTlsAgreement");
            auto tlsX = (volatile LONG*)GetProcAddress(mm, "MmpTlsRefused");
            if (tlsLoc) {
                printf("  ntdll tls: %s  handle=ntdll+0x%lX release=ntdll+0x%lX anchors=%ld%s\n",
                    *tlsLoc ? "located" : (tlsX && *tlsX ? "REFUSED (ARM64EC: not callable here)"
                                                         : "not located"),
                    tlsH ? (unsigned long)*tlsH : 0ul,
                    tlsR ? (unsigned long)*tlsR : 0ul,
                    tlsA ? (long)*tlsA : -1,
                    (tlsX && *tlsX) ? "" : "");
            }

            if (!g_native && !(features & MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA)) {
                printf("  WARNING  : TLS handling is OFF -- memory-loaded modules get no TLS\n"
                       "             setup at all, so ping results say nothing about\n"
                       "             MmpHandleTlsData on this build.\n");
            }
        }
        else {
            printf("  features : (LdrQuerySystemMemoryModuleFeatures unavailable)\n");
        }
    }
    printf("\n");

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
            //
            // Deferring init out of DllMain is what makes the causality check
            // possible at all, so report both facts together: they stand or
            // fall as one change.
            //
            printf("  datatable init    : %s, causality %s\n",
                eagerInDllMain ? "EAGER IN DllMain (regressed)"
                : prewarmMs >= 0 ? "prewarmed on its own thread"
                : "deferred to first use",
                !verifiedFlag ? "(not exported)"
                : *verifiedFlag ? "VERIFIED"
                : "not verified (structural checks only)");
            if (prewarmMs >= 0)
                printf("  prewarm cost      : %lld ms, off the load path\n", prewarmMs);
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
