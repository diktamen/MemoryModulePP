#pragma once

NTSTATUS NTAPI MmInitialize();
NTSTATUS NTAPI MmCleanup();

//
// Run initialization once, on first use, from whichever thread gets here first.
// Every public entry point calls this; it is a single read once initialization
// has happened. Stands aside if a caller already invoked MmInitialize directly,
// so reference counting stays that function's business.
//
// This exists so that nothing has to initialize from DllMain. See the comment on
// the definition for what that bought.
//
NTSTATUS NTAPI MmpEnsureInitialized();

//
// This function is available only if the MMPP is compiled as a DLL. The linkage
// has to match the definition in Initialize.cpp exactly, now that this header is
// visible to it through stdafx.h.
//
#ifdef _USRDLL
extern "C" __declspec(dllexport) BOOL WINAPI ReflectiveMapDll(HMODULE hModule);
#endif
