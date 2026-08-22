#pragma once

//
// Make a memory module's unwind info visible to RtlLookupFunctionEntry, and undo
// it.
//
// These use ntdll's documented dynamic function table --
// RtlAddFunctionTable/RtlDeleteFunctionTable -- which ntdll guards with its own
// lock, has no fixed capacity, and is what JITs use for generated code.
//
// They used to have a second implementation that edited ntdll's
// LdrpInvertedFunctionTable directly, for x86, which has no such API. That is
// gone along with the rest of the x86 support, and with it the whole
// LdrpInvertedFunctionTable apparatus: locating the table by byte pattern with
// hardcoded struct offsets and a hardcoded MaxCount of 0x200, the RtlProtectMrdata
// page flip whose race against ntdll's own flip could not be closed by any lock
// we could take, and the hard ceiling that fixed-size table put on the number of
// concurrently loaded memory modules.
//
NTSTATUS NTAPI MmpRegisterExceptionTable(
	_In_ PVOID BaseAddress,
	_In_ ULONG ImageSize
);

NTSTATUS NTAPI MmpUnregisterExceptionTable(_In_ PVOID BaseAddress);
