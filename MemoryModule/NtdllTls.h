#pragma once

//
// Locating ntdll's TLS helpers -- LdrpHandleTlsData and LdrpReleaseTlsEntry.
//
// Neither is exported, so both have to be found. The signature scans this
// replaces were x64 machine code, and one of them was compiled under
// `#ifdef _WIN64` -- which is defined for ARM64 too, so an ARM64 build searched
// ARM64 .text for x64 bytes. Measured: 0 hits in the ARM64X ntdll, 0 hits on
// native ARM64. When either scan missed, MmpTlsInitialize nulled both pointers
// and cleared MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA, and loads then succeeded
// anyway whenever the caller passed LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS. Every
// memory-loaded module on ARM64 ran with no TLS at all, silently.
//
// What replaces them is ABI-driven, the same idea that located the datatable
// lock: anchor on things the image itself declares rather than on one
// compilation's register allocation.
//
//   LdrpHandleTlsData  ntdll logs its own name, so the literal
//                      "LdrpHandleTlsData" sits in read-only data. The code that
//                      references it is inside an exception filter funclet;
//                      RtlLookupFunctionEntry -- exported, and on ARM64X already
//                      aware of which function table applies to this view --
//                      turns that reference into the funclet's start. The
//                      funclet is named by the Handler field of a scope record,
//                      and the same record's Begin field is an address inside
//                      the parent. Two independent derivations must agree on
//                      that parent: one from the scope record found in
//                      read-only data, one from walking every function's own
//                      unwind data. Each alone produced a false positive during
//                      development; requiring both removed them.
//
//   LdrpReleaseTlsEntry  has no name literal anywhere in ntdll, so the same
//                      trick does not transfer. It is instead selected from the
//                      direct callees of LdrpHandleTlsData -- it is called on
//                      the error path -- by requiring that it calls the exported
//                      RtlFreeHeap, never calls RtlAllocateHeap, and is small.
//                      The winner must be unique or nothing is returned.
//
// Both results are gated on being callable from this process. On ARM64X ntdll's
// loader is compiled twice and the copy an x64 process reaches is ARM64EC; the
// transition needs the callee's entry thunk, and these internal helpers have
// none. Calling one from emulated x64 ends the process with
// STATUS_WX86_INTERNAL_ERROR and is NOT catchable by SEH, so this must be
// refused rather than attempted. The old code escaped that only because its scan
// already failed; a locator that works without the gate would turn a silent
// no-op into an undiagnosable process kill.
//

//
// Diagnostics, exported so the bench can tell "located and usable" apart from
// the three other outcomes without inferring it from a passing run.
//
//   Located    1 when both functions were found AND are callable here.
//   HandleRva  offset of LdrpHandleTlsData within ntdll, 0 if not found.
//   ReleaseRva likewise for LdrpReleaseTlsEntry.
//   Agreement  how many independent derivations agreed on LdrpHandleTlsData.
//              Two is the requirement; watch it the way the datatable lock's
//              donor count is watched.
//   Refused    1 when the addresses were found but the ARM64EC gate refused
//              them. Distinguishes "cannot find it" from "found it, must not
//              call it" -- a platform limit, not a locator failure.
//
extern "C" __declspec(dllexport) volatile LONG MmpTlsLocated;
extern "C" __declspec(dllexport) volatile LONG MmpTlsHandleRva;
extern "C" __declspec(dllexport) volatile LONG MmpTlsReleaseRva;
extern "C" __declspec(dllexport) volatile LONG MmpTlsAgreement;
extern "C" __declspec(dllexport) volatile LONG MmpTlsRefused;

//
// Find both. Returns FALSE and leaves both output pointers null unless the pair
// was located and is callable from this process. Safe to call more than once.
//
BOOL NTAPI MmpLocateNtdllTls(_Out_ PVOID* HandleTlsData, _Out_ PVOID* ReleaseTlsEntry);
