//
// The threads that generate load: memory-module load/ping/unload cycles, and
// ordinary LoadLibrary traffic to race ntdll's own loader against them.
//
// See bench.h for how the harness is split.
//

#include "bench.h"

#include <random>

void LoaderThread(int index, PVOID image, bool distinctNames, int iterations) {
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

        //
        // Under --native the only thing that changes is which loader maps the
        // image. Everything else on this path -- timing, interleave points,
        // GetProcAddress, the ping check -- stays identical, which is what makes
        // the comparison single-variable.
        //
        size_t slot = (distinctNames && (size_t)index < g_nativePaths.size()) ? (size_t)index : 0;
        HMODULE mod = g_native
            ? LoadLibraryW(g_nativePaths[slot].c_str())
            : g_loadMemory(image, 0, baseName.c_str(), fullName.c_str(), flags);
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

        BOOL freed = g_native ? FreeLibrary(mod) : g_freeMemory(mod);
        if (!freed) g_unloadFailures.fetch_add(1);
        else g_unloads.fetch_add(1);
    }
}

void NoiseThread(int index) {
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
