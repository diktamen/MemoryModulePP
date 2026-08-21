#include "stdafx.h"

VOID NTAPI RtlRbInsertNodeEx(
	_In_ PRTL_RB_TREE Tree,
	_In_ PRTL_BALANCED_NODE Parent,
	_In_ BOOLEAN Right,
	_Out_ PRTL_BALANCED_NODE Node) {
	RtlZeroMemory(Node, sizeof(*Node));

	if (!MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx)return;
	return decltype(&RtlRbInsertNodeEx)(MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbInsertNodeEx)(Tree, Parent, Right, Node);
}

VOID NTAPI RtlRbRemoveNode(
	_In_ PRTL_RB_TREE Tree,
	_In_ PRTL_BALANCED_NODE Node) {
	if (!MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode)return;
	return decltype(&RtlRbRemoveNode)(MmpGlobalDataPtr->MmpBaseAddressIndex->_RtlRbRemoveNode)(Tree, Node);
}

//
// Both of the routines below mutate ntdll's LdrpModuleBaseAddressIndex, and the
// search in the first one reads nodes that ntdll may be rebalancing.
//
// The caller must hold ntdll!LdrpModuleDatatableLock -- see
// ModuleDatatableLock.h. This mirrors ntdll's own convention for the same
// structure, where the helper that does the work is named
// LdrpInsertModuleToIndexLockHeld and takes no lock itself. Taking the guard
// here instead would nest it inside the one RtlFreeLdrDataTableEntry holds
// while unlinking, and an SRW lock is not recursive.
//
NTSTATUS NTAPI RtlInsertModuleBaseAddressIndexNode(
	_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry,
	_In_ PVOID BaseAddress,
	_Out_opt_ PBOOLEAN Inserted) {
	if (Inserted)*Inserted = FALSE;

	auto LdrpModuleBaseAddressIndex = MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex;
	if (!LdrpModuleBaseAddressIndex)return STATUS_UNSUCCESSFUL;

	PLDR_DATA_TABLE_ENTRY_WIN8 LdrNode = CONTAINING_RECORD(LdrpModuleBaseAddressIndex->Root, LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode);
	bool bRight = false;

	while (true) {
		if (BaseAddress < LdrNode->DllBase) {
			if (!LdrNode->BaseAddressIndexNode.Left)break;
			LdrNode = CONTAINING_RECORD(LdrNode->BaseAddressIndexNode.Left, LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode);
		}
		else if (BaseAddress > LdrNode->DllBase) {
			if (!LdrNode->BaseAddressIndexNode.Right) {
				bRight = true;
				break;
			}
			LdrNode = CONTAINING_RECORD(LdrNode->BaseAddressIndexNode.Right, LDR_DATA_TABLE_ENTRY_WIN8, BaseAddressIndexNode);
		}
		else {
			//
			// A node already keyed on this base. For a memory module that cannot
			// legitimately happen: MemoryLoadLibrary just reserved this range, so
			// it is exclusively ours, and a genuine reflective load arrives with a
			// base ntdll has never seen. Reaching here means either the tree still
			// holds a stale node for an address that has since been recycled, or
			// the caller passed a base ntdll already owns -- which is what calling
			// the exported ReflectiveMapDll on an already-loaded module does.
			//
			// This used to bump the found entry's LoadCount and return success.
			// Both halves were wrong. The count belongs to a different module and
			// nothing in our teardown ever gives it back, so it leaked a reference
			// on an unrelated entry; and reporting success while inserting nothing
			// let the caller set InIndexes, after which unload handed ntdll's
			// RtlRbRemoveNode an all-zero node whose null ParentValue reads as "I
			// am the root" -- corrupting the whole index.
			//
			// Fail instead. The tree is telling us something we know to be
			// impossible, and publishing further into a structure that is already
			// inconsistent is precisely how the original corruption happened.
			//
			return STATUS_OBJECT_NAME_COLLISION;
		}
	}

	RtlRbInsertNodeEx(LdrpModuleBaseAddressIndex, &LdrNode->BaseAddressIndexNode, bRight, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	if (Inserted)*Inserted = TRUE;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlRemoveModuleBaseAddressIndexNode(_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry) {
	RtlRbRemoveNode(MmpGlobalDataPtr->MmpBaseAddressIndex->LdrpModuleBaseAddressIndex, &PLDR_DATA_TABLE_ENTRY_WIN8(DataTableEntry)->BaseAddressIndexNode);
	return STATUS_SUCCESS;
}
