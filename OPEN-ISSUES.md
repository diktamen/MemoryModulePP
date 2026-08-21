# Open issues

What is still wrong, or still unproven, in MemoryModulePP after the
`LdrpModuleDatatableLock` fix. Written to be read on its own:
`stress/README.md` is the investigation log and has grown into an archaeology
site, so this file is the short answer to "what should still worry me".

Ordered by how likely it is to bite in production.

---

## 1. Taking the right lock is necessary, not proven sufficient

**Status:** open by construction, no known reproducer.

The fix makes our splices of ntdll's loader database mutually exclusive with
ntdll's own. It does nothing about the other invariants ntdll maintains over a
database it believes it allocated: the DDAG state machine, the loader work queue,
`LdrpHashTable`, the `LDR_DDAG_NODE` dependency lists, and whatever else a future
build starts checking. We fabricate an `LDR_DATA_TABLE_ENTRY` and assert
`LdrModulesReadyToRun` directly.

Two of the three fixes this bench has produced were of the form "stop
hand-maintaining an ntdll internal": `RtlAddFunctionTable()` replaced editing
`LdrpInvertedFunctionTable`, and the `LdrpHashTable` insert was dropped rather
than corrected. Both worked. The lock fix is the first one that keeps
hand-maintaining an internal and just synchronises it better.

**The stronger answer, still not taken:** stop publishing into ntdll's database
at all. Keep the fabricated entry, because `LdrpHandleTlsData` needs the struct,
but link it into nothing — no `PEB->Ldr` lists, no hash table, no base-address
index. Resolve exports from our own parsed PE instead of `GetProcAddress`, keep
publishing unwind info through `RtlAddFunctionTable`. That deletes the whole bug
class instead of guarding it. Cost: the OS loader APIs stop seeing memory
modules, and debuggers and profilers no longer enumerate them.

---

## 2. The lock locator fails silently when it fails

**Status:** margin materially improved; the silent-failure mode remains.

`LdrpModuleDatatableLock` is not exported, so it is located by decoding the
instruction that sets the first argument of an exported SRW acquire inside an
exported donor function. Several donors must agree; the minimum accepted is two.

This used to be the second-worst item on the list, with two configurations
sitting exactly at the minimum. Two changes fixed that:

- **The x64 decoder now recurses**, as the ARM64 one always had. Most loader
  exports do not take the lock themselves — they hand a caller-supplied handle
  to an internal helper (`LdrpFindLoadedDllByHandle` and friends) and the acquire
  happens down there. Without recursion those exports simply did not decode,
  which is the entire reason genuine x64 scraped by on two donors. Recursion is
  gated on ntdll's own `.pdata`, so a call target is followed only when the
  exception directory confirms it is a function start; the same table bounds each
  scan to the function it began in.
- **The donor list was measured rather than guessed.** `lockprobe --survey`
  decodes every named ntdll export and groups them by the address each yields;
  the group containing the causality-verified lock is the complete set of usable
  anchors on that build. Intersecting three configurations gave nine donors.

| Configuration | before | after |
| --- | --- | --- |
| native ARM64 (10.0.26100) | 3 of 5 | **5 of 9** |
| x64 on ARM64X (10.0.26100) | **2 of 5** | **5 of 9** |
| native x64 (Server 2022, 20348) | **2 of 5** | **9 of 9** |
| native x64 (build `0x59A29EB0`) | 4 of 5 | not re-measured |
| native x64 (build `0x6A51BE80`) | 3 of 5 | not re-measured |

Worst case is now five agreeing against a minimum of two, and three donors
decode in every configuration instead of one. Every configuration resolved to
**the same address it did before**, so the new machinery raised confidence
without changing any answer, and no configuration produced a disagreeing vote.

The last two rows are machines this session had no access to; they were 4 of 5
and 3 of 5 on the old list and old decoder, so both should improve, but that is
inference, not measurement.

**What has not changed:** the failure is still silent. If a future Windows build
inlines the acquire in donor after donor, agreement eventually drops below two
and the capability turns itself off. That direction is deliberate — a wrong
address acquired as an SRW lock would corrupt ntdll, which is worse than not
locking — but it **presents as the original bug returning**, not as an error.
Mitigations in place:

- Never trim the donor list to whatever works on the machine in front of you.
  Three entries carry ARM64 and two carry ARM64EC; trimming silently disables the
  capability on an architecture you are not testing.
- Two loader exports are deliberately *excluded*, `LdrGetDllHandle` and
  `RtlQueueWorkItem`: the survey places both in the right group on some builds,
  but under ARM64EC they decode to a different ntdll SRW lock. The plurality vote
  exists to survive a stray answer like that, not to be fed them on purpose.
- The harness prints the margin on every run —
  `datatable lock : LOCATED at ntdll+0x… (5 donors agreed, need 2)` — or
  `NOT LOCATED (guards are no-ops)`. **Treat any `NOT LOCATED` run as a
  non-result, never as a pass**; a no-op build still passes most runs. A falling
  donor count across Windows updates is the advance warning.
- Production code should read the exported `MmpModuleDatatableLockLocated` and
  `MmpModuleDatatableLockAgreement` at startup and decide for itself whether to
  proceed. Nothing does this yet.

**Not done:** no telemetry or hard failure when the lock cannot be found. The
library currently loads and runs unsynchronized, exactly as before the fix.

---

## 3. The library's validation is weaker than the probe's — FIXED

**Status:** fixed. The library now runs the same causality check the bench does,
and reports the result.

`stress/lockprobe.cpp` proves an address by causality: hold it exclusively and
confirm an ordinary `LoadLibrary` on another thread blocks, then completes on
release. A wrong address cannot pass that.

The library could not run that test *only because initialization ran from
`DllMain`*, where the probe thread cannot start — its `DLL_THREAD_ATTACH` needs
the loader lock `DllMain` is holding, so the wait deadlocks. That constraint was
self-imposed, not inherent: nothing about locating the lock required `DllMain`.

**Initialization now happens on first use.** `MmpEnsureInitialized` runs the
whole of `MmInitialize` once, from whichever thread first calls
`LdrLoadDllMemoryExW` or `LdrQuerySystemMemoryModuleFeatures` — an ordinary
thread with nothing held. `MmpVerifyModuleDatatableLock` runs there, and
`MmpModuleDatatableLockVerified` reports whether it passed. Measured on all three
configurations: `deferred to first use, causality VERIFIED`.

This also took a substantial amount of work out of `DllMain` that never belonged
there: a named section creation, `GetSystemInfo`, five `GetProcAddress` lookups
that re-enter ntdll's loader, a `PEB->Ldr` walk, and four pattern scans.
`DllMain` now does nothing on `DLL_PROCESS_ATTACH`.

Two things to know about the new behaviour:

- **The diagnostic exports and `MmpGlobalDataPtr` read zero until the first
  load.** Anything reading them straight after `LoadLibrary` sees an
  uninitialized library. Call `MmInitialize` explicitly if eager setup is wanted;
  the guard stands aside when it finds the library already initialized.
- **The check costs ~420–500 ms on the first load**, which is the window it waits
  to be sure a non-blocked `LoadLibrary` would have finished. One-time, and
  tunable if that turns out to matter.

**Moving that cost off the load path:** call the exported `MmInitialize` from a
thread of your own before any memory module is loaded. It runs the causality
check too, so once it returns everything is located and verified and the first
real load pays nothing. `stress --prewarm` is exactly that pattern and asserts
it: measured 419 ms on arm64, 504 ms on x64-under-ARM64X, 425–431 ms on genuine
x64, all off the load path. The first-use guard tests for "already initialized"
under the loader lock rather than by reading `MmpGlobalDataPtr`, because that
pointer is published by the section mapping before the fields behind it are
written — an unlocked test could see a half-built structure while the prewarm
thread was still inside it.

**Residual gap:** the check skips itself when the calling thread already owns the
loader lock — a consumer calling in from their own `DllMain`, and the reflective
path, which must initialize there. Skipping is deliberate: the probe thread could
not start, both waits would expire, and a correct address would read as a
failure. In that case the lock still rests on donor agreement plus the structural
checks, exactly as before, and `MmpModuleDatatableLockVerified` reads 0 to say
so. Note also that only a *positive* disproof — the load completing while the
lock is held — stands the capability down; an inconclusive result leaves it in
place, because switching it off on ambiguity brings back the corruption it
exists to prevent.

---

## 4. TLS: about one wrong answer per few thousand calls

**Status:** open, pre-existing, unrelated to the lock, never investigated.

With the TLS payload, `StressPing` round-trips a value through `thread_local`.
Occasionally it returns the wrong answer, which means this module's TLS was not
correct for that thread on that call. Rates measured: roughly 1 in 1,600 pings on
arm64, about 1 in 12,800 on the x64 Server 2022 box.

It is not list corruption — the failing runs show zero load, unload and integrity
failures. It survives the lock fix untouched and is the only reason a run still
reports `FAIL` on a healthy build. **When triaging, separate exit `1` with a lone
ping failure from exit `0xC0000409`; they are different bugs.**

Suspects, in order: `MmpLdrpTls.cpp` locating ntdll's `LdrpHandleTlsData` by a
multi-stage code-and-data pattern scan (see issue 6); the ordering between
`MmpHandleTlsData` and the module's TLS callbacks; and per-thread TLS vector
growth racing a load.

---

## 5. Latent list-corruption bug in the IAT resolver — FIXED

**Status:** fixed; correct by inspection, never executed.

`MmRemoveImportTableResolver` in `ImportTable.cpp` called
`RemoveHeadList(&resolver->InMmpIatResolverList)` where it meant
`RemoveEntryList`. `RemoveHeadList(h)` unlinks `h->Flink`, treating its argument
as a list *head*, so it removed the resolver registered *after* this one and left
`resolver` itself linked — and the next line freed it. The list was left holding
a pointer into freed heap, and an unrelated resolver was silently dropped.

Now `RemoveEntryList`, which is the primitive that unlinks the entry you hand it.

**This is not execution-tested, and cannot easily be.** Neither
`MmRegisterImportTableResolver` nor `MmRemoveImportTableResolver` appears in
`MemoryModulePP.def`, so they are unreachable from a consumer of the DLL and
unreachable from the harness; the bug had never fired because the code cannot be
called at all in the shipped surface. Verifying it by execution means adding both
to the `.def`, which widens the public API and is a separate decision.

If that is ever done, the check is cheap and deterministic. `InMmpIatResolverList`
sits at offset 0 of `MM_IAT_RESOLVER` and the returned `HANDLE` is the struct
pointer, so a test can read the links straight off the handles: register A, B, C;
remove B; assert `A->Flink == C` and `C->Blink == A`. Under the old code
`A->Flink` still pointed at the freed B and C had been unlinked instead.

---

## 6. Everything else located by pattern scanning

**Status:** pre-existing, unchanged, and the largest remaining source of
version fragility.

The lock is now found by an ABI-driven decode, which is comparatively robust. The
rest of the ntdll internals this library depends on are not:

| Target | How it is found | Risk |
| --- | --- | --- |
| `LdrpHandleTlsData` | multi-stage pattern scan over `.rdata`/`.text`, plus hardcoded prologue offsets for 6.1/6.2/6.3 | high; x86 unsupported; Win11 uses the Win10 signature because it reports major version 10 |
| `LdrpReleaseTlsEntry` | a single hardcoded 21-byte signature, x64 Windows 10 only | high |
| `LdrpInvertedFunctionTable` | byte-pattern scan with hardcoded struct offsets and a hardcoded `MaxCount` of `0x200` | low on x64: since issue 8, no live caller remains there. x86 still reaches it through `MmpRegisterExceptionTable`'s fallback |
| `LdrpModuleBaseAddressIndex` | structural derivation, then an address-value scan of `.data` | medium, plus issue 7 |
| `LdrpHashTable` | structural derivation, validated by re-hashing every entry | low; located but deliberately never written |

If either TLS scan misses, **both** pointers are nulled, the feature bit is
cleared after having been set, `MmpTlsInitialize()`'s failure return is discarded
by the caller, and loads then fail unless the caller passes
`LOAD_FLAGS_NOT_HANDLE_TLS`. That is a lot of silent degradation.

---

## 7. Base-address index edge cases

**Status:** open, low probability, high consequence.

Three distinct problems in `BaseAddressIndex.cpp` and its caller:

1. **Equal-base branch lied about success — FIXED.** When an entry with the same
   `DllBase` already existed, the function bumped that entry's `LoadCount` and
   returned `STATUS_SUCCESS` *without inserting*. The caller then set
   `InIndexes = true`, and unload called `RtlRemoveModuleBaseAddressIndexNode`
   unconditionally — handing ntdll's `RtlRbRemoveNode` an all-zero node whose
   null `ParentValue` reads as "I am the root", corrupting the tree.

   It now returns `STATUS_OBJECT_NAME_COLLISION` and inserts nothing, so the
   load fails cleanly. For a memory module the collision cannot legitimately
   happen — `MemoryLoadLibrary` just reserved that range, so it is exclusively
   ours, and a genuine reflective load arrives with a base ntdll has never seen.
   Reaching it means the tree holds a stale node for a recycled address, or the
   caller passed a base ntdll already owns (calling the exported
   `ReflectiveMapDll` on an already-loaded module does exactly that). Publishing
   further into a structure already known to be inconsistent is how the original
   corruption happened, so it fails instead.

   The `LoadCount` bump is gone too: it incremented a *different* module's count
   and nothing in our teardown ever gave it back, leaking a reference on an
   unrelated entry.

   `RtlInsertModuleBaseAddressIndexNode` now reports insertion through an
   `_Out_opt_ PBOOLEAN Inserted`, that is the only thing that sets `InIndexes`,
   and teardown removes the node only when `InIndexes` is set.
2. **Inserted but not removed on partial failure — FIXED.** If the node went in
   and the `DdagNode` allocation then failed, `RtlInitializeLdrDataTableEntry`
   returned FALSE and the caller freed the entry without removing the node,
   leaving ntdll's tree pointing into a freed heap block. That path now removes
   the node before returning. Needs an allocation failure to reach, so it is
   correct by inspection rather than by test.
3. **Published before valid.** The node enters the tree before `DllBase`,
   `SizeOfImage`, `BaseDllName` and `DdagNode` are filled in. The datatable lock
   now covers this window, so ntdll cannot observe it — but the ordering is still
   wrong and would break again if the lock were ever lost.

Also: index discovery is skipped unless ntdll's tree root happens to be black, so
on some runs the capability is silently absent and every memory load fails.
Nondeterministic, and it will look like a flaky bug.

---

## 8. `ReflectiveMapDll` publishes with no loader lock at all — FIXED

**Status:** fixed; correct by inspection and consistent with the main load path,
but the reflective path itself is still not exercised by any test.

`Initialize.cpp`'s `ReflectiveMapDll` reached `LdrMapDllMemory` — three
`InsertTailList` calls plus the base-address index — and
`RtlInsertInvertedFunctionTable` with **no `MmpLoaderLockGuard` anywhere on the
call chain**, and never tore any of it down. Three changes:

1. **The publish now runs under `MmpLoaderLockGuard`,** covering both the
   `LdrMapDllMemory` publish and the exception-table registration, which is the
   same shape `LdrLoadDllMemoryExW` has used since the lock work. In the
   `DllMain` path ntdll already holds that lock, so it is a recursive re-acquire
   and changes nothing; the exposure was the exported entry point, callable with
   nothing held.
2. **`RtlInsertInvertedFunctionTable` → `MmpRegisterExceptionTable`.** This was
   the last live caller of the direct `.mrdata` edit. On x64 the replacement
   publishes through `RtlAddFunctionTable` instead, avoiding a page flip that
   races ntdll's own *regardless of what lock is held* — see the comment above
   `MmpRegisterExceptionTable` for why the main path was migrated off it. It also
   pairs correctly with the `MmpUnregisterExceptionTable` that unload runs when
   `InsertInvertedFunctionTableEntry` is set; the old call did not, so the flag
   and its teardown named different primitives. On x86 it forwards to the old
   path, so nothing changes there.
3. **`MappedDll` and `LdrEntry` are set immediately after the publish** rather
   than at the very end, and a failed registration now unlinks the loader entry
   before returning. Previously a failure after `LdrMapDllMemory` succeeded left
   the module in ntdll's three lists and its base-address index with those fields
   still clear — so nothing, anywhere, could tell there was anything to unlink.

**Not covered by a test.** The reflective path runs only when `DllMain` sees
`lpReserved == (PVOID)-1`, which means a real reflective-injection harness; the
stress bench never reaches it. The build is verified and the normal load path is
unaffected (stress clean on arm64 and x64), but that is a regression check, not
evidence about this code.

Still open here: **the equal-base branch of issue 7.** That is only reachable by
calling the exported `ReflectiveMapDll` on a module ntdll has already loaded — a
genuine reflective load has no existing entry for that base — but the export
makes it reachable, and nothing rejects it.

---

## 9. `MmpLoaderLockGuard` still gives up

**Status:** open, never observed firing.

After 64 failed attempts the guard proceeds with `Held == false` and increments
`MmpLoaderLockAcquireFailures`. For a caller about to splice ntdll's structures
that is the one thing it must not do; it should fail the load. The counter has
read 0 across every measurement, so this has never happened.

Note the secondary consequence: with `Held == false` the IAT resolver lock is
taken before the loader lock, inverting the ordering used everywhere else and
creating a genuine AB-BA deadlock against any other thread. Same trigger.

---

## 10. Unbounded and cosmetic

- **Address-space leak per failed load.** If `MmpInitializeStructure` returns
  `STATUS_NOT_SUPPORTED` because a section starts before
  `sizeOfHeaders + sizeof(MEMORYMODULE)`, the signature was never written, so
  cleanup's `MapMemoryModuleHandle` returns null and `MemoryFreeLibrary` bails
  out *before* the `VirtualFree`. The whole `SizeOfImage` reservation leaks.
- **`MmCleanup` unmaps the global data** while other threads may hold live
  pointers into it.
- **`MmpAllocateGlobalData` leaks its section handle** on the success path, and
  derives the section name from `~pid ^ ProcessHeap`, which is guessable.
- **`MMP_GLOBAL_DATA_SIZE`** uses `sizeof(PMMP_IAT_DATA)` where it means
  `sizeof(MMP_IAT_DATA)`. Harmless only because the macro is unused.
- **`RtlProtectMrdata` caches into unsynchronized function-local statics.**
  Benign — concurrent first-callers write the same values — but it is a race.
- **`MmpTlsFiber.cpp` is dead code** with an uninitialized `CRITICAL_SECTION`;
  its only initializer lives in the compiled-out `MmpTls.cpp`.

---

## Bench caveats worth knowing

- **Measure on arm64.** Emulated x64 runs roughly 8x slower and generates far
  less contention, so it under-reports failure rates. The `winmssql` x64 box has
  3 cores and is weak for the same reason; its value is being real x64 silicon.
- **Exit code is the classifier**, not the console text: `0` clean, `1` soft,
  `0xC0000409` list corruption, `0xC0000374` heap corruption. Capture it with
  `Start-Process -PassThru`; bash mangles NTSTATUS values (`0xC0000409` arrives
  as `127`).
- **Always A/B against a same-session control.** `MMPP_NO_DATATABLE_LOCK` builds
  the identical source with the decoder disabled. Comparing against numbers from
  an earlier session is how this investigation went wrong twice.
- **Do not read ntdll PE `TimeDateStamp` values as dates.** They are
  reproducible-build hashes. An earlier revision of the readme dated a Server
  2022 box to 2014 that way.
- **On an unfamiliar build, run `lockprobe --survey` before guessing.** It
  decodes every named ntdll export and groups them by the address each yields,
  marking the group that passes the causality check. That group is the complete
  anchor list for that build; the other groups are ntdll's other SRW locks, and
  seeing them separate out is the evidence the decoder is discriminating rather
  than emitting one answer for everything. Note that the *largest* group is not
  the lock — on Server 2022 it is a 27-export group around an unrelated lock — so
  pick the group by the causality mark, never by size.
