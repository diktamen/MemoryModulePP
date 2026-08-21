# Loader stress harness

A bench for MemoryModulePP's concurrency behaviour, and a record of the bug
currently being hunted with it.

The library was written single-threaded and its upstream author says so plainly
(bb107/MemoryModulePP#58: "I really didn't consider multithread safety when
implementing this"). We load DLLs from memory inside a process that also loads
DLLs normally, from threads we do not control, so the untested case is our
production case. This harness exists so a change can be judged by measurement
instead of by reading.

## What is currently broken

**Where it stands.** One open bug, and it is not ours. Measured at 8 loader
threads plus 8 noise over 200 iterations, 8 runs each: 7/8 clean now, against
5/8 before the `LdrpHashTable` change below. Roughly a 12% failure rate, down
from about a third. Not clean.

**Symptom.** Exit `0xC0000409`. Caught under `cdb`, the subcode and stack are
unambiguous:

```
Subcode: 0x3 FAST_FAIL_CORRUPT_LIST_ENTRY
ntdll!LdrpInsertDataTableEntry+0x12c
ntdll!LdrpMapDllWithSectionHandle
ntdll!LdrpLoadKnownDll
ntdll!LdrpFindOrPrepareLoadingModule
ntdll!LdrpLoadDependentModuleInternal
...
KERNELBASE!LoadLibraryExW
stress!NoiseThread
```

This is **ntdll fast-failing on its own list validation**, on a noise thread
doing an ordinary `LoadLibraryExW`, while inserting an unrelated module. Not one
of MemoryModulePP's own `__fastfail` calls. It means a list in ntdll's loader
database is inconsistent, and since the only foreign entries in those lists are
the ones we fabricate, we are still corrupting something.

Partly localised: not inserting into `LdrpHashTable` cuts the rate roughly in
half, so that insert is one source but not the only one. What remains is most
likely elsewhere in the fabricated `LDR_DATA_TABLE_ENTRY` -- the `DdagNode` and
its `Modules`/dependency lists are the obvious suspects, since
`RtlFreeLdrDataTableEntry` dismantles them and can re-enter ntdll through
`LdrUnloadDll` while our entry is still linked.

Worth noting for anyone reading the stacks: this machine is ARM64 running the
x64 harness under emulation, so stacks carry `ARM64EC` frames and
`CpuSetInSyscallCallback`-style artifacts. Nothing here has been confirmed on
native x64.

### Correction: there was never a deadlock here

An earlier version of this document reported a deadlock at 24 threads and
doubted `00ed378` because of it. **That was a measurement error, and the
conclusion drawn from it was wrong.** Runs at 24+12 legitimately take 54s at 100
iterations and 110s at 200; they were being killed at a 60 or 90 second timeout
and scored as hangs. With a 300 second timeout the same configuration passes.

Two things follow. `00ed378` (`DontCallForThreads`) is **not** suspect: it fixed
the heap corruption, which has not recurred, and the hang it appeared to cause
did not exist. And the loader lock is heavily contended at this load --
`ntdll!LdrpLoaderLock` showed a contention count of 4250 -- so runs get slow, not
stuck. When a dump showed 18 threads in `LdrpCallInitializers` and 6 in
`LdrUnloadDllMemory`, all waiting while one noise thread held the loader lock
inside `NtUnmapViewOfSection`, that was ordinary contention, not a cycle.

**Lesson for anyone running this: scale the timeout with the load.** 300s at 24
threads. A verdict of "hang" is only meaningful once you have confirmed the same
configuration can finish at all.

### Ruled out for the fast-fail

| Hypothesis | Test | Result |
| --- | --- | --- |
| Loader TLS handling | payload built without `thread_local`, so no TLS directory | identical, not this |
| Loader lock held across import resolution | released around `MemoryResolveImportTable` | identical, not this; the release was reverted |
| Hash bucket index out of range | index is masked to the table size, and `MmInitialize` validates that every existing entry hashes to its own bucket | sound, not this |

### On sampling, because it has misled this investigation twice

These failures are probabilistic, and small samples have produced two confident
conclusions here that were both wrong. A 60 second timeout turned slow runs into
a phantom deadlock and an entire document section arguing about it. A 6/6 and a
4/4 made the `LdrpHashTable` change look like a complete fix; at 8 runs a side it
is 7/8 against 5/8, which is a real improvement and nothing like a cure.

Treat anything below about 8 runs a side as a hint, not a result, and when a
change looks like a total fix, re-measure before writing it down. Where a
comparison matters, build the previous commit into `stress\bin-basehash` with an
`OutDir` override and run both with the same rep count, rather than comparing
against numbers from an earlier session.

One control result is worth keeping permanently, because it is what makes every
other verdict here trustworthy: `--threads 0 --noise 8` did 2943 ordinary
`LoadLibrary`/`FreeLibrary` calls with 179 clean loader-list checks and zero
failures. The OS loader handles parallel loads of different DLLs perfectly well,
and the harness does not invent failures. Anything this bench reports needs
MemoryModulePP in the mix.

**Page heap.** `gflags /p /enable stress.exe /full` is what found the cause of the
heap corruption, so it is worth reaching for again. Two things to know: it needs
elevation, and it perturbs timing so heavily that it becomes useless above a
handful of threads. Under it, 4 loader threads finished in 742ms while 8 ran past
four minutes, so a hang measured under page heap means nothing. Use it to locate
a specific corrupting write at low thread counts, then turn it off with
`gflags /p /disable stress.exe` before measuring anything.

Elevation note: an elevated process cannot see a per-user mapped network drive,
so launching one with its working directory on `Z:` fails. Pass an explicit local
working directory (`-WorkingDirectory "C:\Windows\Temp"`).

## What this bench already found and fixed

Each was found by the harness and confirmed fixed by it, with before/after
numbers in the relevant commit message.

1. **Unsynchronized writes into ntdll's loader database** (`79765e7`). Every
   memory-module load did four unlocked `InsertTailList` calls into
   `LdrpHashTable` and PEB->Ldr's three module lists, plus an insert into
   ntdll's `LdrpModuleBaseAddressIndex` red-black tree. ntdll only mutates those
   under the loader lock. Taking that lock across load and unload fixed
   concurrent loading of different modules: 2/3 crashing to 0/3.

2. **Editing `LdrpInvertedFunctionTable` in ntdll's `.mrdata`** (`66972af`).
   Reaching it means flipping a shared page writable with `RtlProtectMrdata()`
   and back. ntdll flips the same page for its own inserts and serializes that on
   a lock we cannot take, so the flips race whatever we hold: we either write to
   a page ntdll just made read-only, or make it read-only under ntdll's write.
   This reproduced 100% of the time with a *single* memory load plus noise, as
   either an access violation in the `RtlMoveMemory()` shift or a process-wide
   loader hang. The hang stacks were frame-for-frame identical with and without
   the loader lock, down to the ntdll offsets, which is what ruled locking out as
   cause or cure. Replaced with `RtlAddFunctionTable()`, the documented
   dynamic-function-table API that ntdll guards itself, which also removes the
   inverted table's fixed capacity ceiling.

3. **Use-after-free in unload** (`66972af`). `LdrUnloadDllMemory()` resolved the
   handle before taking the lock, and both `MapMemoryModuleHandle()` and
   `RtlImageNtHeader()` read the image, which is released memory if another
   thread finished the final unload first.

4. **Reference taken on a module being torn down** (`66972af`). A module's loader
   entry stays linked while its `DLL_PROCESS_DETACH` runs outside the lock, so
   the duplicate-module scan could hand back a handle the unloading thread was
   about to free. It now skips `underUnload` entries.

5. **Double teardown** (`9d7d571`). `LdrUnloadDllMemory()` never checked
   `underUnload`, so two threads could both commit to tearing one module down,
   freeing the loader entry, the import list and the image twice.

## How it works

Three files: `stress.cpp` is the harness, `payload.cpp` the DLL it loads,
`build.cmd` builds both plus the DLL under test.

The harness does not only wait for crashes. After every check it walks all three
`PEB->Ldr` module lists and verifies each node's `Flink`/`Blink` still agree,
**holding the loader lock while it reads them**, which is the only way to read
those lists safely while other threads load. A crossed or dropped link is
reported when it happens rather than as an unrelated fault minutes later. A
monitor thread runs this every 50ms, and once more at the end.

The payload is deliberately silent. The bundled `a.dll` printfs from `DllMain`,
and stdout's lock would serialize the loader threads and hide the races. It still
carries `thread_local` data so `LdrpHandleTlsData` has real work to do, and
`StressPing` raises and handles an access violation so a module whose unwind info
was not published fails loudly instead of silently passing.

### Modes

- `--mode distinct` - every thread uses its own module name, so each gets its own
  mapping and they all insert into the shared loader structures at once.
- `--mode same` - every thread collides on one name, driving the duplicate-module
  scan and the reference-count path.
- `--mode mixed` - half and half.

### Diagnostic build variants

`build.cmd` also emits byte-identical copies of `stress.exe` under other names.
The only difference is the filename, which is what gflags keys Image File
Execution Options on, so choosing a diagnostic mode is just choosing which name
to run -- no elevation at run time. Register them once with
`scratchpad\gflags-setup.ps1` (elevated; `-Off` removes them, `-Show` prints
state without elevation).

| Name | Carries |
| --- | --- |
| `stress.exe` | nothing; the only variant whose timings are meaningful |
| `stress_htc.exe` | heap tail, free and parameter checking; catches overruns at free time, far cheaper than page heap |
| `stress_hvc.exe` | validate the whole heap on every heap call; very slow, very thorough |
| `stress_ph.exe` | standard page heap, pattern fill and check on free |
| `stress_phf.exe` | full page heap, guard page after every block; faults on the overrunning instruction |
| `stress_phb.exe` | full page heap with the guard page before the block, for underruns |
| `stress_sls.exe` | loader snaps, traces ntdll loader activity to the debugger |
| `stress_soe.exe` | stop on exception |

The copies keep `stress.exe`'s debug directory, so they still resolve
`stress.pdb` and stacks stay symbolised.

### Controls

These exist to falsify hypotheses, and each has already paid for itself:

- `--threads 0` - noise only, no memory modules. Validates the harness and the
  machine: if this ever fails, the bug is not in MemoryModulePP.
- `--no-ift` - loads with `LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION`, excluding all
  function-table work from the run.
- `--payload stresspayload_notls.dll` - a variant of the payload built without
  `thread_local`, so the image has no TLS directory and the loader TLS path is
  skipped. Used to rule TLS handling out of a failure.
- `--force-seh` - keeps the exception-raising probe even under `--no-ift`. Used to
  establish that publishing unwind info is load-bearing: without it, a memory
  module that raises crashes unhandled.

## Running it

```
stress\build.cmd
stress\bin\stress.exe --dll stress\bin\MemoryModule64.dll ^
                      --payload stress\bin\stresspayload.dll ^
                      --mode mixed --threads 8 --noise 4 --iters 200
```

`build.cmd` builds the DLL under test into `stress\bin` via an `OutDir` override,
so a test build can never overwrite the signed binaries in `nativelibs\lib-bin`.
Two traps it defends against, both of which bit during development:

- A quoted MSBuild property ending in a backslash (`/p:OutDir="...\bin\"`)
  escapes its own closing quote. The override is silently dropped and the build
  lands in `nativelibs\lib-bin`. The properties are passed unquoted, so keep
  these paths free of spaces.
- An ambient developer environment targeting x86 leaves `VCINSTALLDIR` set, `cl`
  quietly emits x86, and the harness fails at runtime with error 193 loading the
  x64 DLL. The script keys off `VSCMD_ARG_TGT_ARCH` instead, and asserts every
  artifact is x64 before finishing.

### Reading the result

Exit code is the classifier. A run is only clean at 0.

| Exit | Meaning |
| --- | --- |
| `0` | PASS |
| `1` | soft failure: a load, unload, ping or integrity check failed, process survived |
| `0xC0000005` | access violation; the crash reporter prints module+offset, access type and target |
| `0xC0000374` | heap corruption; fast-fail, so no reporter output |
| killed by timeout | deadlock; attach and dump all thread stacks |

Because races are probabilistic, judge a configuration over several runs, not
one. Some of these reproduce 1-in-3.

### Debugging notes

- The crash reporter stands aside when a debugger is attached, so the exception
  reaches second chance and `cdb` can produce a stack instead of the filter
  exiting cleanly.
- Under `cdb`, use `sxd av`. The payload raises a *handled* access violation on
  every ping, and first-chance breaks on those will bury the real fault.
- The heap-corruption case does not reproduce under `cdb` at all. Reproduce it
  free-running, or use page heap.
- For a hang: run free, wait, then attach non-invasively and dump every thread
  (`cdb -p <pid> -pv -c "~*kv 14; qd"`). Comparing those stacks across two builds
  is what exonerated the loader lock.
