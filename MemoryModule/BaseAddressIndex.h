#pragma once

//
// Inserted reports whether this entry's node actually went into the tree. It is
// the only thing that may drive InIndexes, and therefore the only thing that may
// drive the matching RtlRemoveModuleBaseAddressIndexNode on teardown. Reporting
// success without inserting is what used to hand ntdll a zeroed node to remove.
//
NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(
	_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry,
	_In_ PVOID BaseAddress,
	_Out_opt_ PBOOLEAN Inserted
);

NTSTATUS NTAPI RtlRemoveModuleBaseAddressIndexNode(_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry);
