# Loader stress harness

A bench for MemoryModulePP's concurrency behaviour, and a record of the bug
hunted with it.

**Status: the `0xC0000409` fast-fail is root-caused and fixed on arm64.** We were
splicing ntdll's loader lists while holding `LdrpLoaderLock`; ntdll splices them
while holding `LdrpModuleDatatableLock`. Two different locks, so no mutual
exclusion, so a lost tail update. Taking the right lock takes 8+8 from 18/24
clean to **24/24**, and 24+12 from 2-6/12 to the numbers in "After the fix"
below. x64 is deliberately unchanged for now and still has the bug; see
`X64-DATA-REQUEST.md`.

Jump to "The wrong lock" for the disassembly and "After the fix" for the
measurements. Everything before those is the trail that led there, kept because
two of its conclusions were confidently wrong and the corrections are the useful
part.

**If you only want to know what is still broken, read `../OPEN-ISSUES.md`
instead.** This file is the investigation log and it reads like one; that file is
the short, ordered list of what remains open and how each one would show up.

The library was written single-threaded and its upstream author says so plainly
(bb107/MemoryModulePP#58: "I really didn't consider multithread safety when
implementing this"). We load DLLs from memory inside a process that also loads
DLLs normally, from threads we do not control, so the untested case is our
production case. This harness exists so a change can be judged by measurement
instead of by reading.

## What is currently broken

**Build arm64 and test there.** `build.cmd arm64` produces a native ARM64
harness in `stress\bin-arm64`. On this host that is roughly **8x faster** than
the x64 build, which runs under emulation: the same 8+8 configuration takes ~6s
instead of ~50s. More loader operations per second means more contention, and it
finds far more. Prefer it for measurement, and note that the x64 numbers below
are correspondingly optimistic.

**Where it stands, measured on arm64** with real sample sizes:

```
 8 loaders +  8 noise, 200it, 20 runs   15/20 pass   2 fast-fail  3 soft
24 loaders + 12 noise, 200it, 12 runs    2-6/12 pass  highly variable at this load
```

So roughly a quarter of runs fail at 8+8, and about half at 24+12. The same
8+8 configuration on emulated x64 read 7/8,
which is the sampling trap again in a new guise: the slower environment simply
does not generate enough contention to expose the rate.

Two distinct defects:

1. **`__fastfail`, exit `0xC0000409`** -- ntdll's own list validation.
   **Root-caused: we hold the wrong lock.** See "The wrong lock" below. Not a
   lifetime bug and not an emulation artifact; it is an ordinary data race
   between our list splices and ntdll's, which no amount of entry-lifetime
   auditing was ever going to find.
2. **A rare wrong answer from the payload**, about 1 ping in 1600. With the TLS
   payload `StressPing` round-trips through `thread_local`, so a wrong result
   means this module's TLS was not correct for that thread on that call. Much
   rarer than the fast-fail and not yet investigated.

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
the ones we fabricate, we are corrupting something.

We are. The mechanism is in "The wrong lock" two sections down: we splice those
lists under `LdrpLoaderLock` while ntdll splices them under
`LdrpModuleDatatableLock`, so the two never exclude each other and a lost tail
update leaves exactly the inconsistency reported here. The section below on what
ntdll validates is still accurate and worth reading first, but it describes the
*check*, not the cause.

### What ntdll is actually checking

Disassembled (`uf ntdll!LdrpInsertDataTableEntry`, public symbols), the function
is short and entirely legible. In order:

1. `ldr w8,[x2,#0x68]` then `tbnz x8,#6` -- **if `InLegacyLists` is already set
   it returns immediately.** We set that flag, so ntdll never inserts our
   entries. Useful to know: our entries are inert to this function.
2. If `BaseNameHashValue` (`+0x108`) is zero it calls `LdrpHashUnicodeString`,
   otherwise it **trusts the stored value**. Bucket is `hash & 0x1F`.
3. Three guarded `InsertTailList` operations, all branching to one
   `brk #0xF003` (`FAST_FAIL_CORRUPT_LIST_ENTRY`) at `+0x50`:
   - the `LdrpHashTable` bucket
   - `InLoadOrderModuleList` (`PEB->Ldr+0x10`, `Blink` at `+0x18`)
   - `InMemoryOrderModuleList` (`PEB->Ldr+0x20`, `Blink` at `+0x28`)

The invariant in every case is the standard one: **`head->Blink->Flink == head`**.
So ntdll is telling us the tail linkage of one of those lists is wrong at the
moment it tries to append. Since a single `brk` serves all three, the ARM64
offset does not say which; the x64 build faulted at `+0x12c`, deeper in its
version of the function, which suggests one of the two module lists rather than
the hash bucket.

### The wrong lock

**`LdrLockLoaderLock` does not protect the loader database.** It never did on
this Windows generation. Everything below is from `cdb` against
ntdll 10.0.26100.8972 with the public PDB; RVAs are for that build.

Modern ntdll has **two** loader locks, and they are disjoint objects:

| Symbol | Type | RVA | Guards |
| --- | --- | --- | --- |
| `ntdll!LdrpLoaderLock` | `CRITICAL_SECTION` | `0x3886A0` | running init routines: `DllMain`, thread attach/detach |
| `ntdll!LdrpModuleDatatableLock` | `SRWLOCK` | `0x3929E0` | **the loader database**: the three `PEB->Ldr` lists, `LdrpHashTable` (`0x392DE0`), the module base-address index |

Note the spelling ntdll uses: *Datatable*, not Database.

The chain that proves it:

1. `LdrLockLoaderLock` -- the only loader lock ntdll exports, and the one
   `MmpLoaderLockGuard` calls -- tail-calls `LdrpAcquireLoaderLock`, which does
   `adrp x8,#0x…678000` / `add x0,x8,#0x6A0` then
   `bl ntdll!RtlEnterCriticalSection`. That address is exactly
   `ntdll!LdrpLoaderLock`. So we take the critical section.

2. `LdrpInsertDataTableEntry`, the function that fast-fails, **takes no lock at
   all.** The entire function contains one `bl` (to `LdrpHashUnicodeString`) and
   one `brk #0xF003`. It is a lock-held helper, in the same family as the
   `…LockHeld`-suffixed symbols next to it in the export walk
   (`LdrpInsertModuleToIndexLockHeld`, `LdrpFindLoadedDllByNameLockHeld`).

3. Its caller `LdrpMapDllWithSectionHandle` acquires
   `LdrpModuleDatatableLock` exclusive, via the inlined SRW fast path --
   `add x23,x8,#0x9E0` then `ldsetab w8,w8,[x23]`, branching to the contended
   path if bit 0 was already set -- and drops it with
   `RtlReleaseSRWLockExclusive`. Immediately inside that lock it reads
   `BaseNameHashValue` at `+0x108` and masks `hash & 0x1F` to pick the
   `LdrpHashTable` bucket: the exact sequence disassembled above, now with the
   lock visible around it.

4. **Nothing on the crash-stack path takes the legacy lock.** `LdrLoadDll`,
   `LdrpLoadDllInternal` and `LdrpDrainWorkQueue` each contain **zero** calls to
   `LdrpAcquireLoaderLock`. The legacy lock's remaining job is initialization:
   `LdrpPrepareModuleForExecution`, `LdrpInitializeThread` and
   `LdrShutdownThread` take it, and none of those touch the datatable lock.

5. `LdrUnloadDll` is the only one that takes both, and it takes them
   **sequentially, not nested**: acquire datatable lock, release it, then
   acquire the legacy loader lock. So the datatable lock is a short leaf-level
   lock held only across database mutation.

So `MmpLoaderLockGuard` buys mutual exclusion against `DllMain` and thread
notifications, and against nothing else. **Every `InsertTailList` and
`RemoveEntryList` we perform on the `PEB->Ldr` lists, and every mutation of the
base-address index, races ntdll's own splices.** Two threads doing a concurrent
tail insert lose one of the two updates, and the loser leaves
`head->Blink->Flink != head` -- which is precisely, and only, what ntdll
reported.

This is worth stating plainly because the counter-evidence was so convincing:
`MmpLoaderLockAcquireFailures` reading 0 over thousands of loads proves the lock
was *acquired*, and says nothing whatever about whether the access was
*synchronized*. A contention count of 4250 on `LdrpLoaderLock` reinforced the
illusion, but that traffic is `DllMain` and thread attach, not list maintenance.

It also retires the entire lifetime line of inquiry, and explains the two
partial fixes as what they actually were:

- Dropping the `LdrpHashTable` insert **halved** the rate because it removed one
  of four unsynchronized splices per load. A linear reduction in racing writes,
  not a logic fix -- which is exactly what the 7/8-against-5/8 measurement was
  telling us, and why it looked like a cure at small samples.
- The `DdagNode` unlink-before-free fix (9/16 to 27/32) fixed a real
  use-after-free that was a second, independent bug. It could not cure this one.
- The rate tracking contention -- 8x more failures on native arm64, none at
  `--threads 0` -- is the signature of a data race, not of a lifetime error.

**What this does not yet establish.** Taking `LdrpModuleDatatableLock` is
*necessary*; it is not proven *sufficient*. Our entries still have to satisfy
every other invariant ntdll keeps over a database it believes it allocated --
the DDAG state machine, the work queue, and whatever `LdrpHashTable` wanted that
we could not honour. Given how often this investigation has mistaken an
improvement for a cure, that has to be measured, not assumed. And the lock is
not exported: reaching it means locating an internal ntdll data symbol, the same
fragile technique that `LdrpInvertedFunctionTable` had to be abandoned for. See
"Two ways out" below.

### Baseline at the time of this finding

`HEAD` = `15895c6`, native arm64, mixed mode, 8 loaders + 8 noise, 200
iterations, 24 runs, exit codes captured exactly:

```
18/24 clean   2 soft (exit 1)   4 fast-fail (0xC0000409)
```

A 17% fast-fail rate, agreeing closely with the 15/20 recorded earlier, which is
the first time two independent samples in this investigation have agreed.

### Getting the lock: `lockprobe`

`lockprobe.cpp` locates `LdrpModuleDatatableLock` at runtime with **no
hardcoded RVA, no PDB, and no opcode signature for the function itself**, and
then proves the answer before anyone trusts it. `build.cmd` builds it.

The trick is that both ends of the pattern are things `GetProcAddress` can
resolve. Several *exported* ntdll functions acquire the lock by calling the
*exported* `RtlAcquireSRWLockShared`/`Exclusive`, and the ABI puts the lock
pointer in the first argument. So the only thing decoded is the single
instruction that materialises that argument:

```
adrp x21, #page
add  x0, x21, #0x9E0        <- first argument
bl   ntdll!RtlAcquireSRWLockExclusive
```

Three exported donors have that shape: `LdrQueryModuleServiceTags` (exclusive),
`LdrDisableThreadCalloutsForDll` and `LdrGetDllHandleByMapping` (both shared).
`LdrAddRefDll` and `LdrGetDllFullName` reference the lock too but inline the
acquire, so they are kept in the donor list only in case x64 differs.

Two donors must agree, and then the address has to survive a **causality
test**, which is what makes this safe to ship rather than merely clever: hold
the candidate exclusively and an ordinary `LoadLibrary` on another thread must
block, and must complete the moment it is released. A wrong address cannot pass
that. Measured on this host:

```
LdrQueryModuleServiceTags        -> ntdll+0x3929E0
LdrDisableThreadCalloutsForDll   -> ntdll+0x3929E0
LdrGetDllHandleByMapping         -> ntdll+0x3929E0
donors decoded: 3 of 5, agreeing: 3
while held    : LoadLibrary blocked      (expected)
after release : LoadLibrary completed    (expected)
RESULT: VERIFIED
```

That matches the symbol-derived RVA exactly, by an entirely independent route.

**The x64 decoder is unproven.** On this ARM64X host every one of those exports,
seen from an x64 process, is an ARM64EC fast-forward thunk
(`48 8B C4 48 89 58 20 55 5D E9 …`) with no x64 body behind it, so the x64 path
cannot be exercised here at all -- the probe detects the thunks and fails safe,
which is the correct behaviour but not a test. `X64-DATA-REQUEST.md` says what
to collect on a genuine x64 box to close this.

**Lock ordering is safe, and that was checked rather than assumed.** Of the
loader functions that reference the datatable lock, only `LdrUnloadDll` and
`LdrpDecrementModuleLoadCountEx` also take the legacy lock, and both take them
**sequentially, not nested**: acquire datatable, release it, *then* acquire
legacy. So ntdll never holds datatable while wanting legacy, and our nesting
legacy → datatable cannot close a cycle.

**`LdrpModuleDatatableLock` is an SRW lock, so it is not recursive**, unlike the
legacy critical section. That constrains the fix more than the ordering does:
the sections we hold it across must never re-enter ntdll's loader. In
particular it must **not** be held across `MemoryResolveImportTable` (which
calls `LoadLibrary`), `MemoryFreeLibrary` (which calls `FreeLibrary`), DllMain,
or `RtlFreeDependencies` (which calls `LdrUnloadDll`) -- each of those would
self-deadlock instantly. ntdll's own TLS routines are clear: `LdrpHandleTlsData`
and `LdrpReleaseTlsEntry` take `LdrpTlsLock` and never the datatable lock.

So the shape of the fix is a narrow critical section per mutation, not a wider
lock: keep the recursive legacy lock for the coarse check-then-act window that
the duplicate-module scan needs, and take the datatable lock only around the
list splices themselves, the base-address index edits, and the list walks --
mirroring what ntdll does.

### After the fix

Taking `LdrpModuleDatatableLock` around the database mutations is implemented on
arm64 in `MemoryModule/ModuleDatatableLock.{h,cpp}`, with narrow sections at four
sites: the three `InsertTailList` calls in `RtlInsertMemoryTableEntry`, the
unlink-and-de-index block in `RtlFreeLdrDataTableEntry`, the base-address index
insert in `RtlInitializeLdrDataTableEntry`, and the duplicate-module scan's walk
of `InLoadOrderModuleList` in `LdrLoadDllMemoryExW`.

**Confirm it is actually on before believing any run.** The harness prints
`datatable lock : LOCATED at ntdll+0x…` and an acquisition count. If it says
`NOT LOCATED (guards are no-ops)` then the guards did nothing and a clean run
proves only that the race is probabilistic. Typical numbers: about 2.6
acquisitions per memory load, so 4,174 for 1,600 loads at 8+8, and 12,015 for
4,800 loads at 24+12.

Measured with a **same-session A/B**, which is the discipline this document had
to learn twice. `MMPP_NO_DATATABLE_LOCK` builds the identical source with the
decoder compiled out, so the control is byte-for-byte the same library with the
lock never located and every guard a no-op:

The headline run is 48 pairs at 8+8, **interleaved** so any machine drift hits
both sides equally:

```
8 loaders + 8 noise, 200it, 48 runs a side, interleaved
  control  31 clean   5 soft   11 fast-fail (0xC0000409)   1 heap corruption (0xC0000374)
  fixed    47 clean   1 soft    0 fast-fail                0 heap corruption
```

11 fast-fails in 48 against 0 in 48 is p of roughly 4e-6. The control also threw
one `0xC0000374`, which is the heap corruption this bench chased earlier and
which the fix also removes -- consistent with list corruption being the upstream
cause of it rather than a separate defect.

Smaller sets, run before that one, agree:

```
8 loaders + 8 noise, 200it, 24 runs
  control  19 clean   3 soft   2 fast-fail
  fixed    24 clean   0 soft   0 fast-fail

24 loaders + 12 noise, 200it, 12 runs
  control   8 clean   3 soft   1 fast-fail
  fixed    11 clean   1 soft   0 fast-fail
```

And the same A/B run as **x64 on this ARM64X host**, which is the x64-JDK-on-arm64
configuration:

```
12 loaders + 8 noise, 200it, 10 runs a side, interleaved, x64 emulated
  control   8 clean   0 soft   2 fast-fail
  fixed    10 clean   0 soft   0 fast-fail
```

Treat that one as confirmatory, not conclusive: 2 against 0 in ten runs a side is
not significant on its own, and emulated x64 runs roughly 8x slower so it
generates far less contention than native arm64. What it does establish is that
the bug is real in that configuration -- the control reproduces it -- and that
the ARM64EC lock is the right one, which the causality check had already shown
independently.

Across every A/B above: **0 fast-fails in 94 runs with the lock, 16 in 94
without it.**

**The remaining `soft` failures are the other defect, not this one.** The single
soft failure at 24+12 was one wrong ping in 4,800 with zero list-corruption
fast-fails, zero integrity failures and zero load or unload failures. That is
defect 2 at the top of this document -- the payload's `thread_local` round-trip
occasionally returning the wrong answer -- and nothing in this change addresses
it. Do not read it as residual list corruption.

**A note on run times.** Do not compare the 6-7s seen here at 24+12 against the
110s recorded in the deadlock correction below. That figure was measured on the
emulated x64 build, most likely with page heap enabled, so it is not the same
environment and there is no performance claim to make either way.

**The harness's integrity check is now sound.** It used to walk the lists under
`LdrLockLoaderLock`, which does not exclude ntdll's splices, so it could report a
transient mid-splice tear as corruption. It now takes the datatable lock
*shared*, using the RVA the DLL under test exports, and falls back to the old
behaviour only when testing a library that cannot tell it where the lock is.
That is why the `soft` counts above are trustworthy where earlier ones were not.

### x64, and x64-on-arm64

All three configurations now locate the lock. The third one matters most in
practice: **an x64 process on ARM64 Windows**, which is what an x64 JDK on an
arm64 machine is.

| Configuration | Decoded via | Lock |
| --- | --- | --- |
| native arm64, 10.0.26100 | `arm64` | `ntdll+0x3929E0` |
| native x64, ~Win10 1709 | `x64` | `ntdll+0x1D1478` |
| native x64, ~6.3 / 2012 R2 | `x64` | `ntdll+0x175AC0` |
| **x64 on ARM64X, 10.0.26100** | `arm64ec` | `ntdll+0x38E930` |

The x64-on-ARM64X case needed two things beyond the plain decoders, and produced
the most surprising result in this whole investigation.

**The export is a thunk, and the code behind it is ARM64.** On ARM64X an x64
caller's `GetProcAddress` returns an ARM64EC fast-forward sequence
(`48 8B C4 48 89 58 20 55 5D E9 <rel32>`), not an x64 body. Following the `jmp`
lands on the ARM64EC compilation of the function, which is ARM64 instructions.
So an **x64 binary has to be able to read ARM64**, which is why both decoders are
compiled into both builds.

**The ARM64EC build hides the acquire two calls deep.** Native ARM64 ntdll loads
the lock and calls the SRW acquire inside the exported function. The ARM64EC
compilation instead routes through a dedicated
`LdrpAcquireModuleDatatableLock` helper: `LdrQueryModuleServiceTags` calls it
directly, but `LdrAddRefDll`, `LdrGetDllFullName` and the rest reach it only via
`LdrpFindLoadedDllByHandle` or `LdrpDereferenceModule` first. Hence the
depth-limited recursion into callees, which is used only on the ARM64EC path.

**And the ARM64EC view uses a different lock object than the native view of the
same ntdll** -- `ntdll+0x38E930` against `ntdll+0x3929E0`. That is not a decoding
error. An ARM64X image is effectively two ntdlls merged behind one export table,
and a given process runs one view throughout, so each view having its own lock
is consistent. It is exactly the kind of thing that would have been impossible to
guess, and it is why the causality check earns its place: it confirmed
`0x38E930` is the lock an ordinary `LoadLibrary` actually blocks on **from an x64
process on this host**, which no amount of reading would have settled.

An earlier version of this section claimed the ARM64EC path was a dead end,
because following the thunk appeared to land in unrelated telemetry code. That
was arithmetic error on my part, not a property of ntdll -- the thunk lands
exactly on `ntdll!#LdrQueryModuleServiceTags`. Recompute before concluding a
path is closed.

Five configurations measured across four machines. The `ntdll` column is the PE
`TimeDateStamp`, used purely as an opaque build identifier -- **do not read these
as dates.** Modern Windows binaries use a reproducible-build hash there, and an
earlier version of this table mistakenly dated the Server 2022 box to 2014 by
doing exactly that.

| ntdll build | SizeOfImage | running as | lock RVA | donors |
| --- | --- | --- | --- | --- |
| `0x105BCDDA` (10.0.26100) | `0x437000` | native ARM64 | `0x3929E0` | 3 of 5 |
| `0x105BCDDA` (10.0.26100) | `0x437000` | x64 on ARM64X | `0x38E930` | 2 of 5 |
| `0x534DA4B0` (Server 2022, 20348) | `0x205000` | native x64 | `0x175AC0` | 2 of 5 |
| `0x59A29EB0` | `0x266000` | native x64 | `0x1D1478` | 4 of 5 |
| `0x6A51BE80` | `0x1D3000` | native x64 | `0x153130` | 3 of 5 |

Which donors decode, per configuration:

| Donor | ARM64 | x64/ARM64X | x64 `534D` | x64 `59A2` | x64 `6A51` |
| --- | --- | --- | --- | --- | --- |
| `LdrQueryModuleServiceTags` | yes | yes | yes | yes | yes |
| `LdrGetDllHandleByMapping` | yes | yes | no | yes | yes |
| `LdrAddRefDll` | no | no | yes | yes | yes |
| `LdrGetDllFullName` | no | no | no | yes | no |
| `LdrDisableThreadCalloutsForDll` | yes | no | no | no | no |

Two things that fall out of this, both load-bearing:

**The usable donors are nearly disjoint, and only one works everywhere.**
`LdrQueryModuleServiceTags` decodes in all five configurations; every other entry
fails in at least two, and `LdrGetDllFullName` and
`LdrDisableThreadCalloutsForDll` each work in exactly one. The rest inline the
acquire where they fail, leaving no call to anchor on. `LdrAddRefDll` had been
left out of the library's donor list on the grounds that it was undecodable --
true on arm64, wrong on all three native x64 builds -- which would have left
exactly one donor on the Server 2022 box, below the two-donor minimum, and the
capability silently off. **The donor list is the union of all of them and must
not be trimmed to whatever works on the machine in front of you.** Two of the
five configurations clear the minimum with nothing to spare, so if a future build
inlines one more the capability turns itself off: the intended direction, but it
presents as the bug returning. The `datatable lock` line in the harness output is
how you tell.

Because the margin is that thin, donor disagreement is resolved by plurality
rather than by rejecting everything, so one spurious decode cannot disable the
feature. A tie, or a winner with fewer than two votes, still yields nothing.

**Four configurations, four unrelated addresses.** Anything hardcoded would have
been wrong in three of them, which is the whole argument for locating it at
runtime -- and the two 10.0.26100 rows are the *same ntdll file* resolving to two
different locks depending on whether the process is native or emulated.

### Confirmed on genuine x64 hardware

The last gap is closed. On a Windows Server 2022 box (build 20348, Intel Xeon,
`PROCESSOR_ARCHITECTURE=AMD64`, 3 cores) the **library's own locator** reports
`datatable lock : LOCATED at ntdll+0x175AC0` through the harness, with 6,000-odd
acquisitions per run, and `lockprobe` there independently agrees and passes both
its library-validation and causality checks.

That also settles this document's longest-standing caveat -- that nothing had
ever been confirmed on genuinely x64 silicon. **The fast-fail reproduces there,
and the fix removes it:**

```
12 loaders + 8 noise, 200it, 14 runs a side, interleaved, native x64 Server 2022
  control  12 clean   0 soft   2 fast-fail
  fixed    11 clean   3 soft   0 fast-fail
```

The three soft failures on the fixed side are **not** a regression, and the
asymmetry against the control's zero is small-sample noise. All three were
`ping failures : 1` with zero load, unload and integrity failures, i.e. the
unrelated TLS defect. A follow-up of 16 runs isolated it: 3 non-clean, every one
a single wrong ping out of 2,400, and never an integrity failure. That is about 1
in 12,800 pings on this box, rarer than the roughly 1 in 1,600 seen on arm64, and
at that rate about 17% of runs should contain one -- which is what both sets show.
The control's 0 of 14 is the mildly unlucky number here, not the fixed side's 3.

Only 3 cores, so this box generates little contention and is weak for rate
comparisons; its value is being real x64 silicon.

### The road not taken

Option 1 below is what shipped, and is described in "After the fix" above. The
alternative is recorded because it is still the stronger long-term answer and
this fix does not close it off.

1. **Take `LdrpModuleDatatableLock` as well.** *Done, arm64 only.* Smallest
   change, keeps every feature. Costs, all still live: the lock is located rather
   than imported, so it needs the validation gate and the no-op fallback it now
   has; the x64 decoder is unproven; and it remains necessary-not-sufficient, in
   that our fabricated entries still have to satisfy every other invariant ntdll
   keeps over a database it believes it allocated.

2. **Stop publishing into ntdll's database at all.** Keep the fabricated
   `LDR_DATA_TABLE_ENTRY` -- `LdrpHandleTlsData` needs the struct -- but link it
   into nothing: no `PEB->Ldr` lists, no hash table, no base-address index.
   Resolve exports from our own parsed PE instead of via `GetProcAddress`, and
   keep publishing unwind info through `RtlAddFunctionTable`. That deletes the
   entire bug class rather than synchronizing it. Costs: the OS loader APIs stop
   seeing memory modules, and debuggers and profilers no longer enumerate them.

Both `RtlAddFunctionTable` and the dropped hash-table insert were this same
shape -- stop hand-maintaining an ntdll internal, either delegate to a
documented API or give up the feature -- and both worked. That is the strongest
prior available here.

### Other defects found in the same pass

None of these is the fast-fail, and none is exercised by the harness as it
stands. Recorded so they are not re-discovered.

1. **`MmpLoaderLockGuard` still gives up.** `LoaderPrivate.h` retries 64 times
   and then proceeds with `Held == false`. In practice
   `MmpLoaderLockAcquireFailures` has always read 0, so this has never fired --
   but the fallback is "splice ntdll's lists unlocked", which is the one thing
   the comment above it says must never happen. It should fail the load instead.
   Note this is now a *robustness* issue rather than the cause: with the wrong
   lock, `Held == true` was never sufficient anyway.

2. **`ImportTable.cpp` unlinks the wrong node.**
   `RemoveHeadList(&resolver->InMmpIatResolverList)` removes
   `resolver->...Flink` -- the *next* entry -- and leaves `resolver` itself
   linked, which is then freed on the following line. It should be
   `RemoveEntryList`. Reachable only through the public
   `MmRemoveImportTableResolver`, which nothing here calls, so it is latent, but
   it is an unambiguous list corruption plus use-after-free.

3. **`ReflectiveMapDll` publishes into ntdll with no lock at all.** It reaches
   `LdrMapDllMemory` (three `InsertTailList` calls plus the base-address index)
   and `RtlInsertInvertedFunctionTable` (a direct `.mrdata` edit, still live on
   this path even though `RtlAddFunctionTable` replaced it everywhere else) with
   no guard on the path, and never tears any of it down. Reachable in the DLL
   build when `DllMain` sees `lpReserved == (PVOID)-1`.

4. **Base-address index edge cases.** The equal-base branch returns
   `STATUS_SUCCESS` without inserting, after which unload calls
   `RtlRemoveModuleBaseAddressIndexNode` unconditionally and hands ntdll's
   `RtlRbRemoveNode` a zeroed node whose null `ParentValue` reads as "I am the
   root". Separately, if the `DdagNode` allocation fails after the node is
   inserted, the entry is freed without removing the node, leaving ntdll's tree
   pointing into a freed heap block. And the node is published into the tree
   before `DllBase`, `SizeOfImage` and `DdagNode` are filled in.

5. **`LdrpModuleBaseAddressIndex` discovery is conditional on tree colour.** The
   scan is skipped unless ntdll's tree root happens to be black, so on some runs
   discovery silently yields null and every memory load fails. Nondeterministic
   capability rather than corruption, but it will look like a flaky bug.

Checked and clean, so do not re-chase:

| Hypothesis | Verdict |
| --- | --- |
| Our `LDR_DATA_TABLE_ENTRY` is too small for build 26100, so ntdll writes past the heap block | **False alarm.** `?? sizeof(ntdll!_LDR_DATA_TABLE_ENTRY)` is `0x138`, exactly `sizeof(LDR_DATA_TABLE_ENTRY_WIN11)`. Last field `HotPatchState` at `+0x130` in both. `sizeof(_LDR_DDAG_NODE)` is `0x50`. |
| Lock-ordering inversion between the loader lock and the IAT resolver lock | Ordering is uniformly loader → IAT on every path. The only inversion needs `Held == false`, i.e. item 1 above. |

### The elimination table, and the row that was wrong

Eliminated so far, each with a measurement or a symbol dump behind it:

| Hypothesis | How it was ruled out |
| --- | --- |
| ~~We mutate the lists without the loader lock~~ | **This row was wrong, and it cost the investigation the most.** `MmpLoaderLockAcquireFailures == 0` proves only that `LdrLockLoaderLock` succeeded. It is the wrong lock, so the mutations were unsynchronized the whole time. See "The wrong lock". |
| Native loader cannot take this traffic | 72,094 native load/unload ops across 24 threads, zero failures |
| Our `LDR_DATA_TABLE_ENTRY` layout is stale for this build | Confirmed twice: `dt` matches ours field for field to `HotPatchState` at `+0x130`, and `?? sizeof(ntdll!_LDR_DATA_TABLE_ENTRY)` is `0x138`, exactly `sizeof(LDR_DATA_TABLE_ENTRY_WIN11)` |
| Our `LDR_DDAG_NODE` layout is wrong | `dt ntdll!_LDR_DDAG_NODE` matches ours field for field |
| Claiming `InIndexes` while only being in one of two index trees | cleared it; 4/12 against 5/12, no effect |
| `LdrpHashTable` insert | removing it roughly halved the rate, so it was *a* source but not the only one |
| Freeing `DdagNode` before unlinking the entry | fixed; 9/16 to 27/32 at 8+8 |

Worth noting for anyone reading x64 stacks on this host: they carry `ARM64EC`
frames and `CpuSetInSyscallCallback`-style artifacts, because the x64 harness is
emulated. Build arm64 to get clean stacks. Nothing here has been confirmed on a
genuinely x64 machine.

### Two corrections about arm64 and TLS

**TLS works on arm64.** An earlier claim in this investigation was that it could
not, because `RtlFindLdrpHandleTlsData10` searches for x64 opcodes
(`48 8D 15`, `lea rdx,[rip+disp32]`) that an ARM64 ntdll would not contain. That
reasoning was wrong: ntdll on this host is **ARM64X**, a hybrid image carrying
both ARM64 and x64 code, so the pattern is present and the located target is
callable. Measured: 3 runs of 1600 per-thread TLS round-trips each, zero
failures. So hardcoding per-build anchors for the bench, which would be easy
given public symbols do export `LdrpHandleTlsData`
(RVA `0xD2270` in ntdll 10.0.26100.8972, timestamp `0x105BCDDA`), is not
necessary. Keep those numbers in mind only if a future ntdll drops the x64 half.

**The no-TLS payload had a bug of its own.** With `STRESS_NO_TLS`, `t_tlsSlot`
becomes a plain static shared by every thread, so `StressPing` reading it back
raced and produced about 30 bogus ping failures per 1600 calls -- which looked
exactly like a loader defect. That variant now derives its answer from its
argument. If you add a probe here, make sure it cannot fail for reasons of its
own.

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
`PEB->Ldr` module lists and verifies each node's `Flink`/`Blink` still agree. A
crossed or dropped link is reported when it happens rather than as an unrelated
fault minutes later. A monitor thread runs this every 50ms, and once more at the
end.

> **The integrity check is currently unsound, for the same reason the library
> was.** `CheckLoaderIntegrity()` takes `LdrLockLoaderLock` and calls that
> safe. Per "The wrong lock" above, that lock does not exclude ntdll's own list
> mutations, so the walk can observe a genuine mid-splice tear that ntdll was
> about to complete correctly. `InsertTailList` and `RemoveEntryList` are not
> atomic, and a reader that does not hold `LdrpModuleDatatableLock` has no
> right to expect a consistent view.
>
> Consequence for reading results: **the `soft` bucket is suspect.** Reported
> integrity failures may be transient tears rather than corruption. The
> `0xC0000409` fast-fails are not affected -- those are ntdll's own verdict on
> its own structures -- so treat the fast-fail count as the trustworthy signal
> until the checker is fixed to take the right lock. This is also why "soft"
> and "fast-fail" have been counted separately above rather than summed.

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

### Reading ntdll directly, which is what finally worked

The public PDB is enough to answer questions about ntdll's *own* locking, and
that turned out to be worth more than every dynamic experiment in this document
combined. The wrong-lock finding took four queries and no measurement:

```
set _NT_SYMBOL_PATH=srv*%LOCALAPPDATA%\Temp\symbols*https://msdl.microsoft.com/download/symbols
cdb -c "x ntdll!Ldrp*Lock*; q" C:\Windows\System32\cmd.exe
cdb -c "uf ntdll!LdrpInsertDataTableEntry; q" C:\Windows\System32\cmd.exe
cdb -c "uf ntdll!LdrpMapDllWithSectionHandle; q" C:\Windows\System32\cmd.exe
cdb -c "uf ntdll!LdrpAcquireLoaderLock; q" C:\Windows\System32\cmd.exe
```

`x ntdll!Ldrp*Lock*` is the one to run first. It lists every loader lock by
name, and seeing `LdrpModuleDatatableLock` sitting next to `LdrpLoaderLock` is
what made the whole thing obvious. Only the x64 `cdb` ships in this SDK
installation, but the ARM64X ntdll carries both halves, so it disassembles the
ARM64 code fine -- the prompt just reads `ARM64EC`.

Useful conventions once you are in there: a `…LockHeld` suffix means the
function asserts a caller-held lock and takes none itself, so **the lock you
need is always in the caller**. An SRW acquire is usually inlined and looks like
`ldsetab w8,w8,[xN]` with a branch to a contended path, not a `bl` -- grepping
the disassembly for `bl.*Acquire` will miss it and did, at first.

**A caution about "just do what LoadLibrary does".** Tracing to find out what
ntdll requires is exactly right, and is how this was solved. Copying what ntdll
*does* is a different proposition: the sequence it follows also drives the DDAG
state machine, the loader work queue and `LdrpHashTable`, none of which is a
stable contract, and the lock it uses is not exported. This project has tried
that twice -- `LdrpInvertedFunctionTable` and `LdrpHashTable` -- and both times
the fix was to stop imitating ntdll and either call a documented API or drop the
feature. Trace to learn the constraint; then prefer the option that does not
require honouring it.
