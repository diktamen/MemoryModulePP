//
// Payload DLL for the loader stress harness.
//
// Deliberately silent. The bundled a.dll printfs from DllMain, and stdout is
// serialized by its own lock, which would serialize the loader threads too and
// hide the races this harness exists to find.
//
// It still exercises the paths that matter: a DllMain that touches per-module
// state, thread_local data so LdrpHandleTlsData has real work to do, and an SEH
// frame so the inverted function table entry is used.
//

#include <Windows.h>

static volatile LONG g_attachCount = 0;
static volatile LONG g_threadAttachCount = 0;

//
// Forces a TLS directory into the image, so the load path runs
// MmpHandleTlsData()/LdrpHandleTlsData() instead of skipping it.
//
static thread_local volatile int t_tlsSlot = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(reserved);

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        InterlockedIncrement(&g_attachCount);
        t_tlsSlot = 1;
        break;
    case DLL_THREAD_ATTACH:
        InterlockedIncrement(&g_threadAttachCount);
        break;
    case DLL_PROCESS_DETACH:
        InterlockedDecrement(&g_attachCount);
        break;
    default:
        break;
    }

    return TRUE;
}

extern "C" __declspec(dllexport) int StressPing(int value) {
    //
    // Touch TLS and take an exception through an SEH frame, so a module whose
    // inverted function table entry went missing fails here rather than silently
    // passing.
    //
    t_tlsSlot = value;

    __try {
        volatile int* p = nullptr;
        *p = 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return t_tlsSlot + 1;
    }

    return -1;
}

//
// Same as StressPing but without the SEH frame, for runs that deliberately load
// with LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION. Without an inverted function table
// entry, x64 exception dispatch cannot find this module's exception directory,
// so raising there would be an unhandled fault rather than a test result.
//
extern "C" __declspec(dllexport) int StressPingNoSeh(int value) {
    t_tlsSlot = value;
    return t_tlsSlot + 1;
}

extern "C" __declspec(dllexport) int StressAttachCount() {
    return g_attachCount;
}
