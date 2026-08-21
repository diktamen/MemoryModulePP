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

## 3. The library's validation is weaker than the probe's

**Status:** by design, mitigated, not eliminated.

`stress/lockprobe.cpp` proves an address by causality: hold it exclusively and
confirm an ordinary `LoadLibrary` on another thread blocks, then completes on
release. A wrong address cannot pass that.

The library cannot run that test. It initialises inside `DllMain`, where creating
the probe thread would deadlock against the loader lock. So it accepts an address
on donor agreement plus structural checks: pointer-aligned, inside ntdll's image,
committed, writable. Those are a sanity filter, not a proof.

`lockprobe` now prints a `library verdict` line predicting whether the library
would accept what it verified; it has read `WOULD ACCEPT` in every configuration
tested. But the two paths remain different tests, and only the probe is
conclusive.

**Possible improvement, not implemented:** defer the causality check to the first
`LdrLoadDllMemoryExW` call, which runs outside `DllMain` and could safely spawn
the probe thread once.

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
| `LdrpInvertedFunctionTable` | byte-pattern scan with hardcoded struct offsets and a hardcoded `MaxCount` of `0x200` | medium; only reachable via `ReflectiveMapDll` now |
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

1. **Equal-base branch lies about success.** When an entry with the same
   `DllBase` already exists, the function bumps that entry's `LoadCount` and
   returns `STATUS_SUCCESS` *without inserting*. The caller then sets
   `InIndexes = true`, and unload calls `RtlRemoveModuleBaseAddressIndexNode`
   unconditionally — handing ntdll's `RtlRbRemoveNode` an all-zero node whose
   null `ParentValue` reads as "I am the root". That corrupts the tree.
   Reachable via `ReflectiveMapDll`, which passes an already-loaded `hModule`.
2. **Inserted but not removed on partial failure.** If the node goes in and the
   `DdagNode` allocation then fails, `RtlInitializeLdrDataTableEntry` returns
   FALSE and the caller frees the entry without removing the node. ntdll's tree
   is left pointing into a freed heap block. Needs an allocation failure.
3. **Published before valid.** The node enters the tree before `DllBase`,
   `SizeOfImage`, `BaseDllName` and `DdagNode` are filled in. The datatable lock
   now covers this window, so ntdll cannot observe it — but the ordering is still
   wrong and would break again if the lock were ever lost.

Also: index discovery is skipped unless ntdll's tree root happens to be black, so
on some runs the capability is silently absent and every memory load fails.
Nondeterministic, and it will look like a flaky bug.

---

## 8. `ReflectiveMapDll` publishes with no loader lock at all

**Status:** open; reachable in the DLL build.

`Initialize.cpp`'s `ReflectiveMapDll` reaches `LdrMapDllMemory` — three
`InsertTailList` calls plus the base-address index — and
`RtlInsertInvertedFunctionTable`, a direct `.mrdata` edit still live on that path,
with **no `MmpLoaderLockGuard` anywhere on the call chain**, and it never tears
any of it down. It also hits the equal-base branch of issue 7.

It gets the datatable lock for free, because those guards live inside the callees
rather than at the call site, so the worst of it is now covered. The missing
loader lock and the absent teardown are not. Reachable whenever `DllMain` sees
`lpReserved == (PVOID)-1`, or if anyone calls the exported `ReflectiveMapDll`.

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
