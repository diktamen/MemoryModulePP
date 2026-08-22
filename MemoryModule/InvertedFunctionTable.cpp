#include "stdafx.h"

//
// Publishing a memory module's unwind info.
//
// This file used to carry a second implementation that edited ntdll's
// LdrpInvertedFunctionTable in place. That table is a fixed-size array in
// ntdll's .mrdata, and reaching it meant flipping that shared page writable and
// back with RtlProtectMrdata(). ntdll flips the same page for its own inserts
// and serializes that on a lock we cannot take, so our flip raced its flip no
// matter what we held: we either wrote to a page ntdll had just made read-only,
// or made it read-only underneath ntdll's own write. Both were reproducible
// under stress/stress.cpp as a crash in the RtlMoveMemory() shift or as a
// loader-wide hang, identically with and without the loader lock.
//
// RtlAddFunctionTable() is the documented way to do this and has none of those
// problems: ntdll guards its dynamic function table itself,
// RtlLookupFunctionEntry consults it for addresses not in the inverted table,
// and it has no fixed capacity -- which also drops the ceiling the 0x200-entry
// array imposed on concurrently loaded memory modules. It is what JITs use for
// generated code.
//
// The inverted-table path survived only for x86, which has no equivalent API.
// With x86 support removed there is no caller left, so the pattern scan that
// located the table, its hardcoded struct offsets and MaxCount, and
// RtlProtectMrdata are all gone with it.
//

NTSTATUS NTAPI MmpRegisterExceptionTable(
	_In_ PVOID BaseAddress,
	_In_ ULONG ImageSize) {
	UNREFERENCED_PARAMETER(ImageSize);

	ULONG DirectorySize = 0;
	auto FunctionTable = (PRUNTIME_FUNCTION)RtlImageDirectoryEntryToData(
		BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &DirectorySize);

	//
	// No exception directory means nothing to publish. That is not a failure: a
	// module with no unwind info needs no registration.
	//
	if (!FunctionTable || !DirectorySize) return STATUS_SUCCESS;

	if (DirectorySize % sizeof(RUNTIME_FUNCTION)) return STATUS_INVALID_IMAGE_FORMAT;

	//
	// The entries live in the mapped image's .pdata and stay valid until unload,
	// which is exactly the lifetime RtlAddFunctionTable requires.
	//
	return RtlAddFunctionTable(FunctionTable,
		DirectorySize / sizeof(RUNTIME_FUNCTION),
		(DWORD64)BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI MmpUnregisterExceptionTable(_In_ PVOID BaseAddress) {
	ULONG DirectorySize = 0;
	auto FunctionTable = (PRUNTIME_FUNCTION)RtlImageDirectoryEntryToData(
		BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &DirectorySize);

	//
	// Mirrors the registration side: nothing was published for an image without
	// an exception directory, so there is nothing to remove.
	//
	if (!FunctionTable || !DirectorySize) return STATUS_SUCCESS;

	//
	// RtlDeleteFunctionTable takes the same pointer that was registered, which we
	// recompute from the still-mapped image rather than caching it.
	//
	return RtlDeleteFunctionTable(FunctionTable) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
