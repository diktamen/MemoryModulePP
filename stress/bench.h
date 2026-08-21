#pragma once

//
// Shared bench infrastructure for the loader stress harness.
//
// stress.cpp had grown to hold four separate concerns: option parsing and
// orchestration, the load/unload workload, the loader-list integrity checker,
// and crash reporting. They are split so each can be read without the others.
//
//   bench.h / bench.cpp   process-wide state, payload IO, integrity checking,
//                         crash reporting -- everything both of the others need
//   workload.cpp          the loader and noise threads
//   stress.cpp            options, setup, orchestration, the report
//
// Note this is deliberately *not* shared with lockprobe.cpp, nativetls.cpp or
// the probe_*.cpp tools. Those are standalone by design: each links nothing from
// this tree so it can be copied to another machine on its own, which is how they
// get run on hosts that have no build environment.
//

#include <Windows.h>
#include <winternl.h>
#include <atomic>
#include <string>
#include <vector>

//
// From MemoryModule/Loader.h. Duplicated rather than included so the harness
// builds against a shipped DLL without needing the source tree's headers.
//
#define LOAD_FLAGS_USE_DLL_NAME               0x00040000
#define LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS     0x20000000
#define LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION  0x00010000

//
// From MemoryModule/Loader.h, same reason.
//
#define MEMORY_FEATURE_SUPPORT_VERSION          0x00000001
#define MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX 0x00000002
#define MEMORY_FEATURE_LDRP_HEAP                0x00000004
#define MEMORY_FEATURE_LDRP_HASH_TABLE          0x00000008
#define MEMORY_FEATURE_INVERTED_FUNCTION_TABLE  0x00000010
#define MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA     0x00000020
#define MEMORY_FEATURE_LDRP_RELEASE_TLS_ENTRY   0x00000040

typedef NTSTATUS(NTAPI* PFN_LdrQueryFeatures)(PDWORD);

typedef HMODULE(WINAPI* PFN_LoadLibraryMemoryExW)(PVOID, size_t, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL(WINAPI* PFN_FreeLibraryMemory)(HMODULE);
typedef int(*PFN_StressPing)(int);

typedef NTSTATUS(NTAPI* PFN_LdrLockLoaderLock)(ULONG, ULONG*, PVOID*);
typedef NTSTATUS(NTAPI* PFN_LdrUnlockLoaderLock)(ULONG, PVOID);
typedef VOID(NTAPI* PFN_SRW)(PVOID);

// ------------------------------------------------------------------- options

//
// Set by --no-ift. Loading with LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION skips all
// LdrpInvertedFunctionTable manipulation, which isolates whether a failure comes
// from that table or from the rest of the load path.
//
extern bool g_skipInvertedTable;

//
// Set by --force-seh. Uses the exception-raising probe even under --no-ift, to
// test whether x64 exception dispatch into a memory module works without an
// LdrpInvertedFunctionTable entry at all.
//
extern bool g_forceSeh;

//
// Set by --native. The loader threads then map the payload with the ordinary
// LoadLibraryW instead of MemoryModulePP, and change nothing else: same thread
// count, same iteration count, same sleeps, same SwitchToThread points, same
// GetProcAddress, same ping check, same counters.
//
// This is the single-variable A/B for the TLS wrong-answer defect. nativetls.cpp
// answers "does the OS reproduce it at all", but it hammers a module that is
// already loaded, whereas this harness pings once per fresh load -- so on its
// own it cannot rule out the workload shape. Here only the loader differs.
//
// MemoryModulePP stays loaded and initialized in this mode on purpose. It is
// simply not used to map the payload. Unloading it would change two things at
// once, and it is also what supplies the datatable lock address the integrity
// checker reads.
//
extern bool g_native;

//
// One real file per loader thread, so --native --mode distinct maps genuinely
// distinct modules each with their own TLS index -- matching what distinct mode
// does under MemoryModulePP. Loading one path N times would just bump a
// reference count and quietly test something much weaker.
//
extern std::vector<std::wstring> g_nativePaths;

// ------------------------------------------------------------ resolved entry points

extern PFN_LoadLibraryMemoryExW g_loadMemory;
extern PFN_FreeLibraryMemory    g_freeMemory;
extern PFN_LdrLockLoaderLock    g_lockLoader;
extern PFN_LdrUnlockLoaderLock  g_unlockLoader;

//
// ntdll!LdrpModuleDatatableLock, which is what actually guards the three
// PEB->Ldr lists. Not exported by ntdll, so it is taken from the DLL under
// test: it locates the lock and exports the RVA it found.
//
// This matters for the integrity check. Walking those lists under
// LdrLockLoaderLock does not exclude ntdll's own splices, so the walk could
// observe a genuine mid-splice tear and report it as corruption -- a false
// positive that made the "soft failure" count untrustworthy. Reading them under
// the right lock, shared, is sound.
//
extern PVOID    g_datatableLock;
extern PFN_SRW  g_acquireShared;
extern PFN_SRW  g_releaseShared;

// ------------------------------------------------------------------- counters

extern std::atomic<long long> g_loads;
extern std::atomic<long long> g_unloads;
extern std::atomic<long long> g_loadFailures;
extern std::atomic<long long> g_unloadFailures;
extern std::atomic<long long> g_pingFailures;
extern std::atomic<long long> g_noiseLoads;
extern std::atomic<long long> g_integrityChecks;
extern std::atomic<long long> g_integrityFailures;
extern std::atomic<bool>      g_stop;

// --------------------------------------------------------------------- bench.cpp

//
// Read a file into RWX memory. MemoryModulePP wants the raw image that way, and
// it matches how the product supplies it.
//
PVOID ReadFileIntoMemory(const char* path, size_t* sizeOut);

//
// Walk the three PEB->Ldr lists and verify every node's Flink/Blink still agree,
// holding the lock that actually guards them. Returns false and fills detail on
// the first inconsistency. Bumps g_integrityChecks / g_integrityFailures.
//
bool CheckLoaderIntegrity(std::string& detail);

//
// Unhandled-exception filter that resolves the faulting address to module+offset
// and dumps the counters, so a crash report says whether the fault is in ntdll's
// loader, in MemoryModulePP, or in the payload.
//
LONG WINAPI CrashFilter(EXCEPTION_POINTERS* info);

// ------------------------------------------------------------------ workload.cpp

//
// One loader thread: map the payload, call into it to prove the module is
// actually usable (this is what catches a module published with a missing
// inverted function table or unhandled TLS), then unload.
//
void LoaderThread(int index, PVOID image, bool distinctNames, int iterations);

//
// Ordinary LoadLibrary/FreeLibrary traffic. The important adversary: it makes
// ntdll mutate the same lists we write, from another thread.
//
void NoiseThread(int index);
