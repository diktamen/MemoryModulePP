//
// Shared bench state, payload IO, loader-list integrity checking and crash
// reporting. See bench.h for how the harness is split.
//

#include "bench.h"

#include <cstdio>

#pragma comment(lib, "ntdll.lib")

bool g_skipInvertedTable = false;
bool g_forceSeh = false;
bool g_native = false;
std::vector<std::wstring> g_nativePaths;

PFN_LoadLibraryMemoryExW g_loadMemory = nullptr;
PFN_FreeLibraryMemory    g_freeMemory = nullptr;
PFN_LdrLockLoaderLock    g_lockLoader = nullptr;
PFN_LdrUnlockLoaderLock  g_unlockLoader = nullptr;

PVOID    g_datatableLock = nullptr;
PFN_SRW  g_acquireShared = nullptr;
PFN_SRW  g_releaseShared = nullptr;

std::atomic<long long> g_loads{ 0 };
std::atomic<long long> g_unloads{ 0 };
std::atomic<long long> g_loadFailures{ 0 };
std::atomic<long long> g_unloadFailures{ 0 };
std::atomic<long long> g_pingFailures{ 0 };
std::atomic<long long> g_noiseLoads{ 0 };
std::atomic<long long> g_integrityChecks{ 0 };
std::atomic<long long> g_integrityFailures{ 0 };
std::atomic<bool>      g_stop{ false };

// ----------------------------------------------------------------- payload IO

PVOID ReadFileIntoMemory(const char* path, size_t* sizeOut) {
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

// ---------------------------------------------------------- integrity checking

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
// The walk itself, kept in its own function because __try/__except cannot live
// in a frame that needs unwinding.
//
static bool WalkAllLists(STRESS_PEB_LDR_DATA* ldr, std::string& detail) {
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
    return ok;
}

bool CheckLoaderIntegrity(std::string& detail) {
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

    bool ok = WalkAllLists(ldr, detail);

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

// ------------------------------------------------------------ crash reporting

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

LONG WINAPI CrashFilter(EXCEPTION_POINTERS* info) {
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
