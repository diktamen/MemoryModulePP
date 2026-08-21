#pragma once

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#include "../3rdparty/phnt/include/phnt_windows.h"
#include "../3rdparty/phnt/include/phnt.h"
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#endif

//
// Determine whether to use MmpTls(1) or LdrpTls(0)
//
#ifndef MMPP_USE_TLS
#define MMPP_USE_TLS 0
#endif

// offsetof()
#include <cstddef>

//memory module base support
#include "MemoryModule.h"

//import table support
#include "ImportTable.h"

//LDR_DATA_TABLE_ENTRY
#include "LdrEntry.h"

//rtl inverted function table for exception handling
#include "InvertedFunctionTable.h"

//base address index
#include "BaseAddressIndex.h"

//ntdll!LdrpModuleDatatableLock, which is what actually guards the loader database
#include "ModuleDatatableLock.h"

//tls support
#include "MmpTls.h"

//MemoryModulePP api interface
#include "Loader.h"

//MmInitialize/MmCleanup, and the first-use initialization guard
#include "Initialize.h"

//utils
#include "Utils.h"

//global data
#include "MmpGlobalData.h"