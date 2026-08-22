/* arm64ec_thunk.cpp -- see arm64ec_thunk.h.
 *
 * Compiles into the x64 and ARM64 targets. On native ARM64 (and genuine x64)
 * every entry point degrades to a direct call. Only when running x64-emulated on
 * ARM64 does it borrow an entry thunk. Win32 only; its own translation unit
 * (no phnt, no PCH).
 *
 * Two properties of the patch are load-bearing under concurrency, and both were
 * learned from the loader stress harness rather than from first principles:
 *
 *   The page must stay executable. VirtualProtect works on whole pages, and the
 *   slot at fn-4 shares its page with the function itself (0x2186FC and 0x218700
 *   on the measured build) and with whatever else of ntdll's .text is nearby.
 *   Asking for PAGE_READWRITE strips execute from all of it, so any other thread
 *   running any code on that page during the window takes a DEP fault --
 *   STATUS_ACCESS_VIOLATION reported at the instruction pointer, which reads like
 *   a wild jump and is nothing of the kind. PAGE_EXECUTE_READWRITE keeps it
 *   runnable for the few instructions the write takes.
 *
 *   The patch is applied once and left in place. Restoring the slot after every
 *   call reintroduces a window in which the tag is zero, and a thread that
 *   transitions during that window is killed by the emulator with
 *   STATUS_WX86_INTERNAL_ERROR -- uncatchable, so it cannot be retried around.
 *   What stays behind is a valid entry-thunk tag on a function that had none,
 *   which is inert to everything except an emulated x64 caller reaching this
 *   exact address: ntdll itself never reads it, and the write lands in this
 *   process's own copy-on-write copy of the page, so no other process sees it.
 *   That costs one modified dword per helper for the life of the process and
 *   buys a slot no thread can ever observe in a fatal state.
 */
#include <windows.h>
#include "arm64ec_thunk.h"

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((LONG)0xC0000002L)
#endif
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif

typedef LONG (*PFN_1)(void *);
typedef LONG (*PFN_2)(void *, void **);

/* The indirect calls below must not be rewritten by Control Flow Guard: the
 * target is an internal ntdll function that is not a registered call target.
 * Isolated so guard(nocf) applies to exactly these sites (no-op without CFG). */
static __declspec(guard(nocf)) LONG InvokeNoCfg1(void *fn, void *a0)
{
    return ((PFN_1)fn)(a0);
}
static __declspec(guard(nocf)) LONG InvokeNoCfg2(void *fn, void *a0, void **a1)
{
    return ((PFN_2)fn)(a0, a1);
}

/* Guards one-time resolution and the one-time patch of each slot. Never held
 * across a call into ntdll, so it cannot invert against the loader lock: callers
 * arrive already holding that, and this is taken and dropped underneath it. */
static SRWLOCK g_lock     = SRWLOCK_INIT;
static LONG    g_init     = 0;
static BOOL    g_emulated = FALSE;
static BYTE   *g_thunk1   = NULL;  /* entry thunk for  NTSTATUS f(void*)       */
static BYTE   *g_thunk2   = NULL;  /* entry thunk for  NTSTATUS f(void*,void*) */

static BOOL DetectEmulatedX64OnArm64(void)
{
#if defined(_M_ARM64) || defined(_M_ARM64EC)
    return FALSE;                  /* native code: a direct call already works */
#else
    typedef BOOL (WINAPI *PFN_ISWOW64PROCESS2)(HANDLE, USHORT *, USHORT *);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    PFN_ISWOW64PROCESS2 fn = k32
        ? (PFN_ISWOW64PROCESS2)GetProcAddress(k32, "IsWow64Process2") : NULL;
    if (!fn) return FALSE;
    USHORT proc = 0, native = 0;
    if (!fn(GetCurrentProcess(), &proc, &native)) return FALSE;
    return native == IMAGE_FILE_MACHINE_ARM64;   /* processMachine reads 0 for x64-on-ARM64 */
#endif
}

/* An exported function's x64-visible address is a fast-forward sequence, not its
 * ARM64EC body. Decode the FFS to the EC body so [body-4] can be read. NULL on
 * any shape we do not recognise (e.g. an inline-hooked donor). */
static BYTE *EcBodyFromExport(BYTE *p, int depth)
{
    if (!p || depth > 4) return NULL;
    if (p[0] == 0xFF && p[1] == 0x25)                     /* jmp qword[rip+imm32] */
        return EcBodyFromExport(*(BYTE **)(p + 6 + *(LONG *)(p + 2)), depth + 1);
    if (p[9] == 0xE9 &&                                   /* <9-byte prologue> jmp rel32 */
        ((p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) ||
         (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xFF)))
        return p + 14 + *(LONG *)(p + 10);
    return NULL;
}

/* Absolute VA of an entry thunk borrowed from the first donor export whose C
 * signature matches. Decode and encode both use "base = function entry", so any
 * constant base offset cancels between donor and target. */
static BYTE *ResolveDonorThunk(const char *const *candidates)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return NULL;
    for (; *candidates; ++candidates) {
        BYTE *body = EcBodyFromExport((BYTE *)GetProcAddress(nt, *candidates), 0);
        if (!body) continue;
        LONG tag = *(LONG *)(body - 4);
        if ((tag & 3) != 1) continue;                     /* donor must be EC-callable */
        return body + (tag & ~(LONG)3);
    }
    return NULL;
}

static void EnsureResolved(void)
{
    if (g_init) return;
    AcquireSRWLockExclusive(&g_lock);
    if (!g_init) {
        g_emulated = DetectEmulatedX64OnArm64();
        if (g_emulated) {
            static const char *const kDonors1[] = {
                "RtlDeleteCriticalSection", "RtlLeaveCriticalSection",
                "RtlEnterCriticalSection", NULL };
            static const char *const kDonors2[] = {
                "RtlInitUnicodeStringEx", "RtlGUIDFromString",
                "RtlStringFromGUID", NULL };
            g_thunk1 = ResolveDonorThunk(kDonors1);
            g_thunk2 = ResolveDonorThunk(kDonors2);
        }
        g_init = 1;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

static BOOL SlotHasThunk(void *fn)
{
    return (*(volatile LONG *)((BYTE *)fn - 4) & 3) == 1;
}

/* Give fn a permanent entry-thunk tag pointing at thunk. Idempotent, and safe to
 * race: the winner writes, everyone else finds the tag already valid. */
static BOOL EnsurePatched(void *fn, BYTE *thunk)
{
    if (!fn || !thunk) return FALSE;
    if (SlotHasThunk(fn)) return TRUE;                    /* already done, no write at all */

    AcquireSRWLockExclusive(&g_lock);
    BOOL ok = TRUE;
    if (!SlotHasThunk(fn)) {
        LONG    *slot  = (LONG *)((BYTE *)fn - 4);
        LONGLONG delta = (LONGLONG)(thunk - (BYTE *)fn);  /* intra-ntdll: fits int32 */
        LONG     tag   = (LONG)((delta & ~(LONGLONG)3) | 1);
        DWORD    oldProt = 0, tmp = 0;

        /* EXECUTE_READWRITE, not READWRITE: this page holds live code that other
         * threads are running right now. See the note at the top of the file. */
        if (VirtualProtect(slot, sizeof(LONG), PAGE_EXECUTE_READWRITE, &oldProt)) {
            *slot = tag;
            VirtualProtect(slot, sizeof(LONG), oldProt, &tmp);
            FlushInstructionCache(GetCurrentProcess(), slot, sizeof(LONG));
        }
        else {
            ok = FALSE;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    return ok;
}

extern "C" int Arm64ecEmulationActive(void)
{
    EnsureResolved();
    return g_emulated ? 1 : 0;
}

extern "C" int Arm64ecBorrowReady(void)
{
    EnsureResolved();
    return (g_emulated && g_thunk1 && g_thunk2) ? 1 : 0;
}

extern "C" long EcCallHandleTlsData(void *fn, void *ldrEntry)
{
    EnsureResolved();
    if (!g_emulated)
        return InvokeNoCfg1(fn, ldrEntry);
    if (!EnsurePatched(fn, g_thunk1))
        return STATUS_NOT_SUPPORTED;                      /* keep the caller's gate honest */
    return InvokeNoCfg1(fn, ldrEntry);
}

extern "C" long EcCallReleaseTlsEntry(void *fn, void *ldrEntry, void **tlsVector)
{
    EnsureResolved();
    if (!g_emulated)
        return InvokeNoCfg2(fn, ldrEntry, tlsVector);
    if (!EnsurePatched(fn, g_thunk2))
        return STATUS_NOT_SUPPORTED;
    return InvokeNoCfg2(fn, ldrEntry, tlsVector);
}
