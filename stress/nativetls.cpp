//
// nativetls -- the control for OPEN-ISSUES issue 4, "TLS: about one wrong answer
// per few thousand calls".
//
// The stress harness sees StressPing() occasionally return the wrong value,
// which means the payload's thread_local was not correct for that thread on that
// call. Rates measured: roughly 1 in 1,600 pings on arm64, 1 in 12,800 on the
// x64 Server 2022 box. It is assumed to be MemoryModulePP's TLS handling
// (MmpLdrpTls.cpp reimplementing ntdll!LdrpHandleTlsData), but nothing has ever
// checked that assumption.
//
// This is that check, and it is deliberately as dumb as possible: load the SAME
// payload DLL with the ORDINARY Windows loader -- plain LoadLibraryW, no
// MemoryModulePP anywhere in the process -- and hammer the same exports the same
// way.
//
//   wrong answers here  -> the bug is in Windows, the CRT, or the payload/test
//                          itself, and chasing MemoryModulePP would waste days
//   zero wrong answers  -> the bug is MemoryModulePP's, and issue 4 is real
//
// This links nothing from this tree and never loads MemoryModule*.dll, which is
// the entire point. If it did, it would not be a control.
//
// Three phases, because "dynamically loaded DLL with implicit TLS" has more than
// one interesting case:
//
//   steady    load first, then create threads. The easy case: every thread gets
//             DLL_THREAD_ATTACH and its TLS block the normal way.
//   retrofit  create threads first, then load. The threads already exist when
//             the module arrives, so the loader has to fit TLS to them after the
//             fact. This is exactly the job MmpHandleTlsData reimplements, so it
//             is the phase most likely to show a difference.
//   churn     ping continuously while other threads load and free the same
//             module over and over, so TLS setup and teardown overlap the reads.
//
// Build: see stress\build.cmd, or by hand:
//   cl /nologo /std:c++17 /O2 /MT /EHsc nativetls.cpp /link /OUT:nativetls.exe
//
// Exit code: 0 = no wrong answers (control is clean, suspicion stays on
// MemoryModulePP), 1 = wrong answers reproduced WITHOUT MemoryModulePP, 2 =
// setup failure.
//

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <thread>
#include <vector>

// Same typedef the harness uses, so the call is identical.
typedef int(*PFN_StressPing)(int);

static std::atomic<long long> g_pings{ 0 };
static std::atomic<long long> g_wrong{ 0 };
static std::atomic<long long> g_resolveFailures{ 0 };
static std::atomic<bool>      g_stop{ false };

//
// One thread's worth of pinging. Each thread uses values derived from its own
// id, so if TLS were actually shared between threads rather than per-thread the
// readback would come back as some other thread's value.
//
// Both exports are exercised: StressPing goes through an SEH frame, so a failure
// there could be exception dispatch rather than TLS, while StressPingNoSeh is a
// bare thread_local write and read back. Splitting them says which.
//
static void PingLoop(HMODULE mod, int threadIndex, long long pings) {
    auto ping = (PFN_StressPing)GetProcAddress(mod, "StressPing");
    auto pingNoSeh = (PFN_StressPing)GetProcAddress(mod, "StressPingNoSeh");
    if (!ping || !pingNoSeh) {
        g_resolveFailures.fetch_add(1);
        return;
    }

    // Values well apart per thread, so a cross-thread read is unmistakable.
    int base = (threadIndex + 1) * 1000000;

    for (long long i = 0; i < pings && !g_stop.load(std::memory_order_relaxed); ++i) {
        int v = base + (int)(i & 0xFFFF);

        if (ping(v) != v + 1) g_wrong.fetch_add(1);
        g_pings.fetch_add(1);

        if (pingNoSeh(v) != v + 1) g_wrong.fetch_add(1);
        g_pings.fetch_add(1);

        // Give the scheduler a chance to interleave threads.
        if ((i & 0x3FF) == 0) SwitchToThread();
    }
}

static void Report(const char* phase, long long pingsBefore, long long wrongBefore) {
    long long pings = g_pings.load() - pingsBefore;
    long long wrong = g_wrong.load() - wrongBefore;
    printf("  %-9s %10lld pings   %lld wrong\n", phase, pings, wrong);
}

// ---------------------------------------------------------------------- phases

//
// Load, then create threads. Each thread gets DLL_THREAD_ATTACH.
//
static bool PhaseSteady(const wchar_t* payload, int threads, long long pings) {
    HMODULE mod = LoadLibraryW(payload);
    if (!mod) {
        fprintf(stderr, "steady: LoadLibraryW failed (error %lu)\n", GetLastError());
        return false;
    }

    long long p0 = g_pings.load(), w0 = g_wrong.load();

    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i)
        pool.emplace_back([=] { PingLoop(mod, i, pings); });
    for (auto& t : pool) t.join();

    Report("steady", p0, w0);
    FreeLibrary(mod);
    return true;
}

//
// Create threads first and park them, then load, then let them ping. The
// threads pre-date the module, so the loader has to attach TLS to them after the
// fact -- the case MmpHandleTlsData exists to reproduce.
//
static bool PhaseRetrofit(const wchar_t* payload, int threads, long long pings) {
    HANDLE go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!go) return false;

    HMODULE mod = nullptr;
    long long p0 = g_pings.load(), w0 = g_wrong.load();

    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i) {
        pool.emplace_back([&, i] {
            WaitForSingleObject(go, INFINITE);
            PingLoop(mod, i, pings);
        });
    }

    // Let every thread actually reach the wait before the module shows up.
    Sleep(200);

    mod = LoadLibraryW(payload);
    if (!mod) {
        fprintf(stderr, "retrofit: LoadLibraryW failed (error %lu)\n", GetLastError());
        g_stop.store(true);
        SetEvent(go);
        for (auto& t : pool) t.join();
        CloseHandle(go);
        return false;
    }

    SetEvent(go);
    for (auto& t : pool) t.join();

    Report("retrofit", p0, w0);
    FreeLibrary(mod);
    CloseHandle(go);
    return true;
}

//
// Ping continuously while other threads load and free the same module, so TLS
// setup and teardown overlap the reads. One reference is held throughout, so the
// module never actually unmaps and the pinging threads' pointers stay valid --
// this is about overlapping loader traffic, not about use-after-free.
//
static bool PhaseChurn(const wchar_t* payload, int threads, long long pings) {
    HMODULE pin = LoadLibraryW(payload);
    if (!pin) {
        fprintf(stderr, "churn: LoadLibraryW failed (error %lu)\n", GetLastError());
        return false;
    }

    long long p0 = g_pings.load(), w0 = g_wrong.load();
    std::atomic<bool> churnStop{ false };

    std::vector<std::thread> churners;
    for (int i = 0; i < 2; ++i) {
        churners.emplace_back([&] {
            while (!churnStop.load(std::memory_order_relaxed)) {
                HMODULE m = LoadLibraryW(payload);
                if (m) FreeLibrary(m);
            }
        });
    }

    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i)
        pool.emplace_back([=] { PingLoop(pin, i, pings); });
    for (auto& t : pool) t.join();

    churnStop.store(true);
    for (auto& t : churners) t.join();

    Report("churn", p0, w0);
    FreeLibrary(pin);
    return true;
}

// ------------------------------------------------------------------------ main

int main(int argc, char** argv) {
    const char* payload = "stresspayload.dll";
    int threads = 8;
    long long pings = 40000;   // x2 exports x3 phases -> ~2M calls per thread set

    for (int i = 1; i < argc; ++i) {
        auto next = [&](const char* what) -> const char* {
            if (i + 1 >= argc) { fprintf(stderr, "missing value for %s\n", what); exit(2); }
            return argv[++i];
        };
        if (!strcmp(argv[i], "--payload")) payload = next("--payload");
        else if (!strcmp(argv[i], "--threads")) threads = atoi(next("--threads"));
        else if (!strcmp(argv[i], "--pings")) pings = atoll(next("--pings"));
        else {
            printf("usage: nativetls [--payload <path>] [--threads <n>] [--pings <n>]\n"
                   "  Loads the payload with the ORDINARY Windows loader and checks\n"
                   "  StressPing/StressPingNoSeh round-trip through thread_local.\n");
            return 2;
        }
    }

    wchar_t wpayload[MAX_PATH];
    if (!MultiByteToWideChar(CP_ACP, 0, payload, -1, wpayload, MAX_PATH)) {
        fprintf(stderr, "bad payload path\n");
        return 2;
    }

    //
    // Prove MemoryModulePP is not in this process. If it were, a wrong answer
    // here would prove nothing at all.
    //
    if (GetModuleHandleW(L"MemoryModule64.dll") || GetModuleHandleW(L"MemoryModulearm.dll")) {
        fprintf(stderr, "MemoryModule DLL is loaded -- this is not a control\n");
        return 2;
    }

    printf("native-loader TLS control  (OPEN-ISSUES issue 4)\n");
    printf("  payload  : %s\n", payload);
    printf("  loader   : LoadLibraryW  (no MemoryModulePP in this process)\n");
    printf("  threads  : %d\n", threads);
    printf("  pings    : %lld per thread per export per phase\n\n", pings);

    bool ok = PhaseSteady(wpayload, threads, pings);
    ok = PhaseRetrofit(wpayload, threads, pings) && ok;
    ok = PhaseChurn(wpayload, threads, pings) && ok;

    long long total = g_pings.load(), wrong = g_wrong.load();
    printf("\n  total     %10lld pings   %lld wrong", total, wrong);
    if (g_resolveFailures.load())
        printf("   (%lld export resolve failures)", g_resolveFailures.load());
    printf("\n\n");

    if (!ok || g_resolveFailures.load()) {
        printf("RESULT: SETUP FAILURE -- result is not usable\n");
        return 2;
    }

    if (wrong) {
        //
        // The interesting outcome. The payload's thread_local misbehaves under
        // the ordinary Windows loader, so issue 4 is not MemoryModulePP's bug and
        // no amount of work on MmpLdrpTls.cpp will fix it.
        //
        printf("RESULT: REPRODUCED WITHOUT MemoryModulePP -- %lld wrong of %lld.\n"
               "        Issue 4 is an OS, CRT, or payload/test bug. Do not chase\n"
               "        MmpLdrpTls.cpp.\n", wrong, total);
        return 1;
    }

    //
    // Absence of evidence is only worth something if enough was sampled. The
    // observed rates are ~1/1,600 (arm64) and ~1/12,800 (x64), so state the
    // sample size and let the reader judge rather than claiming "proven clean".
    //
    printf("RESULT: CLEAN -- 0 wrong in %lld pings with the ordinary loader.\n", total);
    if (total >= 100000) {
        printf("        At the rate the harness sees under MemoryModulePP\n"
               "        (~1/1,600 arm64, ~1/12,800 x64) this sample would have\n"
               "        shown roughly %lld and %lld failures. Suspicion stays on\n"
               "        MemoryModulePP's TLS handling.\n", total / 1600, total / 12800);
    }
    else {
        printf("        NOTE: only %lld pings -- too few to be conclusive at a\n"
               "        1/12,800 rate. Re-run with a larger --pings.\n", total);
    }
    return 0;
}
