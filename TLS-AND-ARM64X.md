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
