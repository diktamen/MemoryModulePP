# TLS for memory-loaded modules, and why ARM64X is different

## What is needed

A DLL with `thread_local` data carries a TLS directory. When the OS loader maps
such a DLL it allocates a TLS index, records the module in `LdrpTlsList`, and
makes sure every thread's `ThreadLocalStoragePointer` vector has a block for it —
including threads that already existed. On unload it gives the index back.

A memory-loaded module gets none of that for free: we map the image ourselves, so
nothing has told ntdll it exists. Without that work, a `thread_local` access in
the module resolves through an unallocated index and reads whatever is there.

ntdll does this in two internal functions:

| | |
| --- | --- |
| `LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY*)` | allocate the index, publish, populate threads |
| `LdrpReleaseTlsEntry(LDR_DATA_TABLE_ENTRY*, void**)` | undo it |

Neither is exported. We call them rather than reimplementing TLS ourselves, for
the same reason we take ntdll's own loader lock rather than inventing one: the
OS's machinery is the only thing guaranteed to agree with the OS.

`MemoryModule/NtdllTls.cpp` locates them by ABI rather than byte signature — the
name literal in `.rdata`, the exception funclet that references it,
`RtlLookupFunctionEntry`, and two independent derivations of the parent function
that must agree. That part works everywhere; see `NtdllTls.h` for how.

**Locating them is not the problem. Calling them is.**

## Where it works

**Genuine x64.** Our code is x64, ntdll's loader is x64. A direct call.

**Native ARM64.** Our code is ARM64, ntdll's loader is ARM64. A direct call.

Both verified behaviourally, not just structurally: 7,200 load/unload cycles on
ARM64 and 24,000 on genuine x64, zero failures. That also exercises the release
function specifically — a wrong one would leak TLS indices until ntdll's bitmap
exhausted, and it does not.

```
native ARM64        features 0x67   tls-handle=ON   +0xD2270 / +0xD2D18
genuine x64 2022    features 0x67   tls-handle=ON   +0x35BF0 / +0x82394
```

## Where it fails: an x64 process on ARM64 hardware

Windows on ARM64 ships **ARM64X** binaries: one file containing two compilations
of the same code. Native ARM64 processes execute the ARM64 half; emulated x64
processes execute the **ARM64EC** half — ARM64 instructions using an x64-shaped
calling convention, so that emulated and native code can call each other.

An emulated x64 caller cannot jump straight into ARM64EC code. The emulator has
to switch out of emulation and marshal the x64 register state into the ARM64 ABI,
and it does that through an **entry thunk** the compiler generates per function.
A function advertises its thunk in the four bytes immediately *before* its entry
point:

```
dword at (fn - 4) == (entryThunkRva - fnRva) | 1
```

Exported functions have one. ntdll's internal loader helpers do not. Measured on
10.0.26100:

```
RtlAcquireSRWLockExclusive   EC body ntdll+0x18AC00   dword[-4] = 0x0015A039   low bits 1   -> callable
LdrLoadDll                   EC body ntdll+0x20A030   dword[-4] = 0x000DA829   low bits 1   -> callable
LdrpHandleTlsData            EC body ntdll+0x218700   dword[-4] = 0x00000000   low bits 0   -> NOT callable
LdrpReleaseTlsEntry          EC body ntdll+0x218F70   dword[-4] = 0x00000000   low bits 0   -> NOT callable
LdrpFindTlsEntry             EC body ntdll+0x218150   dword[-4] = 0x00000000   low bits 0   -> NOT callable
```

Calling one anyway does not fault. **The emulator terminates the process with
`STATUS_WX86_INTERNAL_ERROR` (`0xC000026F`), and it is not catchable by SEH** —
confirmed by experiment; an `__except` around the call never runs.

So on ARM64X the locator finds the correct address and must refuse to use it:

```
x64 on ARM64X       features 0x07   tls-handle=OFF
                    ntdll tls: REFUSED (ARM64EC: not callable here)
                    handle=ntdll+0x218700  anchors=2
```

`REFUSED` reads differently from "not located" on purpose. The address is right;
the platform will not permit the call.

### Two questions this always raises

**Why not call the native ARM64 copy instead?** We are emulated x64. We cannot
execute ARM64 instructions directly — going through the EC copy *is* the
mechanism for that, and that is what is blocked.

**Why not synthesize an entry thunk?** In principle the signature is simple
enough to marshal by hand. In practice the tag is an RVA relative to ntdll's own
image, so the thunk would have to live inside ntdll and the four bytes before a
function in ntdll's read-only code would have to be rewritten. Patching ntdll's
image to work around ntdll is precisely the class of thing this project has spent
its time removing.

### Note

Before the gate existed, this configuration was safe only by accident: the old
locator was an x64 byte signature that found nothing in an ARM64X ntdll, so the
call was never attempted. A locator that worked without a callability check would
have converted a silent no-op into an undiagnosable process kill.

## Options for x64-on-ARM64X

1. **Ship a native ARM64 build.** TLS works there. Best answer where it is
   available.
2. **`MMPP_USE_TLS=1`** — the library's own TLS implementation in `MmpTls.cpp`,
   which needs no ntdll internals and so is immune to this entirely. It is not the
   default and is not a free lunch: it Detour-patches `RtlUserThreadStart`,
   `LdrShutdownThread` and `NtSetInformationProcess` **process-wide** and takes
   over `ThreadLocalStoragePointer`. Inside a JVM that is a compatibility surface
   against every profiler, APM and AV agent. It compiles cleanly today but will
   not link: the Detours sources in `3rdparty/Detours` are not in
   `MemoryModule.vcxproj`.
3. **Avoid TLS in memory-loaded payloads**, and pass
   `LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS`. Without that flag such a load now fails,
   which is the honest outcome.

Whatever is chosen, read `LdrQuerySystemMemoryModuleFeatures` at startup rather
than assuming: `MEMORY_FEATURE_LDRP_HANDLE_TLS_DATA` tells you which of these you
are in, and `MmpTlsRefused` distinguishes "this platform will not allow it" from
"could not find it".

---

## Appendix: minimal reproduction, with one blank to fill

Self-contained, no dependency on this library. It fabricates the smallest thing
`LdrpHandleTlsData` will accept — an image whose only content is a PE header and
a TLS directory, plus a loader entry pointing at it — calls the function, and
reports whether a TLS index came back.

Build it twice from the same source. **Native ARM64 and genuine x64 both print an
allocated index. x64 on ARM64 hardware dies before printing anything**, and no
exception is dispatched on the way.

The only thing that differs between working and dying is `CallTarget`. If there
is a supported way to reach a thunkless ARM64EC function from emulated x64, it
goes there and everything else should behave as it does natively.

```c
/* arm64x_tls_poc.c
 *
 *   cl /nologo arm64x_tls_poc.c          (build for arm64, and for x64)
 *   arm64x_tls_poc <LdrpHandleTlsData-RVA>
 *
 * Measured RVAs, ntdll TimeDateStamp 0x105BCDDA (Win11 ARM64X, SizeOfImage 0x437000):
 *     native ARM64     0xD2270      -> works
 *     x64 on ARM64X    0x218700     -> kills the process
 * Server 2022 x64, TimeDateStamp 0x534DA4B0:
 *     genuine x64      0x35BF0      -> works
 *
 * A success leaks one TLS index and one LdrpTlsList node. Fine for a probe.
 * A real caller also holds the loader lock across the call; single-threaded here.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* Offsets in LDR_DATA_TABLE_ENTRY, measured on Win10/11 for both x64 and ARM64. */
#define LDR_DLLBASE     0x30
#define LDR_SIZEOFIMAGE 0x40
#define LDR_DDAGNODE    0x98

typedef LONG NTSTATUS;
typedef NTSTATUS (*PFN_HANDLE_TLS)(void *LdrEntry);

/* ------------------------------------------------------------- THE BLANK ---
 * Same instruction set as ntdll's loader -> an ordinary call.
 *
 * Emulated x64 on ARM64 -> `fn` is an ARM64EC body whose entry-thunk tag, the
 * dword at fn-4, is 0. The emulator refuses the transition and ends the process
 * with STATUS_WX86_INTERNAL_ERROR. It is not a fault; there is nothing to catch.
 */
static NTSTATUS CallTarget(PFN_HANDLE_TLS fn, void *arg)
{
    return fn(arg);                                   /* <-- fill this in */
}
/* ------------------------------------------------------------------------- */

static void *BuildFakeModule(ULONG **indexOut)
{
    BYTE *img = VirtualAlloc(NULL, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    IMAGE_DOS_HEADER      *dos = (IMAGE_DOS_HEADER *)img;
    IMAGE_NT_HEADERS64    *nt  = (IMAGE_NT_HEADERS64 *)(img + 0x40);
    IMAGE_TLS_DIRECTORY64 *tls = (IMAGE_TLS_DIRECTORY64 *)(img + 0x400);
    BYTE  *tmpl  = img + 0x500;                       /* the per-thread template */
    ULONG *index = (ULONG *)(img + 0x600);

    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(nt->OptionalHeader);
    nt->OptionalHeader.Magic               = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage         = 0x3000;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0x400;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(*tls);

    memset(tmpl, 0xA5, 64);
    tls->StartAddressOfRawData = (ULONGLONG)tmpl;
    tls->EndAddressOfRawData   = (ULONGLONG)(tmpl + 64);
    tls->AddressOfIndex        = (ULONGLONG)index;
    *index = 0xFFFFFFFF;                              /* sentinel */

    *indexOut = index;
    return img;
}

static void *BuildFakeEntry(void *image)
{
    BYTE *e    = calloc(1, 0x200);
    BYTE *ddag = calloc(1, 0x60);
    int   off;

    /* The three module lists, each a ring of one. */
    for (off = 0; off <= 0x20; off += 0x10) {
        LIST_ENTRY *l = (LIST_ENTRY *)(e + off);
        l->Flink = l->Blink = l;
    }
    /* LDR_DDAG_NODE.Modules, likewise. */
    ((LIST_ENTRY *)ddag)->Flink = ((LIST_ENTRY *)ddag)->Blink = (LIST_ENTRY *)ddag;

    *(void **)(e + LDR_DLLBASE)     = image;
    *(ULONG *)(e + LDR_SIZEOFIMAGE) = 0x3000;
    *(void **)(e + LDR_DDAGNODE)    = ddag;
    return e;
}

int main(int argc, char **argv)
{
    HMODULE nt;
    PFN_HANDLE_TLS fn;
    ULONG *index;
    void *img, *entry;
    NTSTATUS st;

    if (argc < 2) { printf("usage: %s <LdrpHandleTlsData-RVA>\n", argv[0]); return 2; }

    nt  = GetModuleHandleW(L"ntdll.dll");
    fn  = (PFN_HANDLE_TLS)((BYTE *)nt + strtoul(argv[1], NULL, 0));
    img = BuildFakeModule(&index);
    entry = BuildFakeEntry(img);

    printf("ntdll        : %p\n", (void *)nt);
    printf("target       : %p\n", (void *)fn);
    /* Only meaningful when the target is an ARM64EC body: this is the entry-thunk
     * tag, and low bits 1 means an emulated x64 caller can reach it. For a native
     * ARM64 or a genuine x64 target these four bytes are just code or padding. */
    printf("dword at fn-4: 0x%08lX\n", *(ULONG *)((BYTE *)fn - 4));
    printf("index before : 0x%08lX\n", *index);
    fflush(stdout);                                   /* the last thing you see */

    st = CallTarget(fn, entry);                       /* dies here under emulation */

    printf("status       : 0x%08lX\n", (ULONG)st);
    printf("index after  : 0x%08lX  %s\n", *index,
           *index != 0xFFFFFFFF ? "<- TLS index allocated" : "<- unchanged");
    return (st == 0 && *index != 0xFFFFFFFF) ? 0 : 1;
}
```

### Actual output

Both built from the source above, same machine, Win11 ARM64X, ntdll
`TimeDateStamp 0x105BCDDA`:

```
$ poc_arm64.exe 0xD2270                     # native ARM64
ntdll        : 00007FFDEC2F0000
target       : 00007FFDEC3C2270
dword at fn-4: 0x00000000
index before : 0xFFFFFFFF
status       : 0x00000000
index after  : 0x00000001  <- TLS index allocated
exit=0

$ poc_x64.exe 0x218700                      # x64 under emulation
ntdll        : 00007FFDEC2F0000
target       : 00007FFDEC508700
dword at fn-4: 0x00000000
index before : 0xFFFFFFFF
exit=0xC000026F
```

The second run stops mid-output. There is no `status` line because control never
came back, and no crash dialog or exception record — the emulator ends the
process at the transition. Everything printed before the call is the only
evidence available.

Worth noting for anyone investigating: **reaching ARM64EC code from emulated x64
is not itself the problem.** Calling the EC body of an *exported* function works
fine from the same process — `RtlAcquireSRWLockExclusive`'s EC body at
`ntdll+0x18AC00` has tag `0x0015A039` and can be called and released normally.
The difference is only whether the compiler emitted an entry thunk, and for
ntdll's internal loader helpers it did not.
