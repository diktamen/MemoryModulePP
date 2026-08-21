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

**Where it stands.** Clean through 8 loader threads plus 8 noise threads.
Marginal at 16 plus 8. Reliably broken at 24 plus 12, which is where work
stopped.

**The failure mode changed once, and that matters.** Until `00ed378` the 24-thread
configuration died with `STATUS_HEAP_CORRUPTION` (`0xC0000374`), a fast-fail with
no stack. Page heap identified the cause: ntdll was calling a module entry point
in memory that had already been released, dispatched from its thread
initialization path, because memory modules never set `DontCallForThreads` and so
received `DLL_THREAD_ATTACH` on threads we do not control. `00ed378` sets that
flag. The heap corruption has not recurred since.

**What replaced it is a deadlock**, and whether that is progress is genuinely
unresolved. Two readings fit the evidence equally well: either the corruption was
killing the process before a pre-existing deadlock could form, and fixing it
merely exposed the next bug; or the flag itself introduced the hang. Against the
first reading, 16+8 also went from 3/3 clean to 2/3, which is a small sample but
the wrong direction. **Do not treat `00ed378` as validated.** Deciding between
those two readings is the next task, and reverting it to re-measure is a
legitimate way to start.

At the hang, 18 threads sit in `LdrpCallInitializers` running a payload
`DllMain` (process attach) and 6 in `LdrUnloadDllMemory` running one (process
detach). Both run outside the loader lock by design. The payload frames are
misattributed by cdb to its only export; they are really its static CRT.

**Conditions required to reproduce the 24-thread failure.** Both together:

- **Many loader threads each mapping a *distinct* image.** 24 threads in
  `--mode distinct` reproduces; 16 threads mostly does not.
- **Concurrent ordinary `LoadLibrary`/`FreeLibrary` traffic.** With `--noise 0`
  the same 24 threads are clean.

**Conditions ruled out.** Each was tested and is *not* involved:

| Hypothesis | Test | Result |
| --- | --- | --- |
| Shared-module reference counting | `--mode same --threads 24 --noise 12` | 3/3 pass, not this |
| The exception / function-table path | `--mode mixed --threads 24 --noise 12 --no-ift` | still fails, not this |
| Concurrency alone, without real DLL loads | `--mode mixed --threads 24 --noise 0` | 3/3 pass, noise is required |
| The OS loader mishandling parallel loads | `--threads 0 --noise 8` | 2943 loads, 0 failures, the OS is fine |

Measured, 3 runs each, 200 iterations per thread:

```
24L + 12N distinct         0/3 pass    3 heap corruption   <-- the target
24L + 12N same             3/3 pass
24L +  0N mixed            3/3 pass
24L + 12N mixed --no-ift   0/3 pass    1 heap, 1 crash, 1 hang
16L +  8N mixed            3/3 pass
```

**Where that points.** Distinct images share no `MEMORYMODULE` state, so the
corruption is not in per-module bookkeeping. What they do share is the process
heap and ntdll's loader database. The load/unload path allocates and frees
several things on that heap: the `LDR_DATA_TABLE_ENTRY`, the `BaseDllName` and
`FullDllName` buffers, and the `hModulesList` import-handle array. It also calls
two ntdll internals located by signature scan, `LdrpHandleTlsData` and
`LdrpReleaseTlsEntry`, which allocate and free ntdll's own TLS vectors on that
same heap. Those internals have invariants we may not be honouring, and the
noise DLLs reach the same structures through ntdll's supported path. That is the
next thing to narrow.

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

### Controls

These exist to falsify hypotheses, and each has already paid for itself:

- `--threads 0` - noise only, no memory modules. Validates the harness and the
  machine: if this ever fails, the bug is not in MemoryModulePP.
- `--no-ift` - loads with `LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION`, excluding all
  function-table work from the run.
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
