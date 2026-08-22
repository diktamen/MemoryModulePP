# Still open

What is actually still wrong, or still unproven, in MemoryModulePP.

`OPEN-ISSUES.md` is the historical record: most of what it lists has since been
fixed, and several of its diagnoses turned out to be wrong in instructive ways.
It is worth reading for *why* things are the way they are — but read this file
for what to worry about now.

Ordered by how likely each is to bite in production.

---

## 1. TLS is not set up at all on ARM64 or on x64-under-ARM64X

**Status:** open, actively happening on every load, silent.

This is the most serious item on the list and the newest. Measured with
`LdrQuerySystemMemoryModuleFeatures`, which the harness now prints every run:

| Configuration | features | `LDRP_HANDLE_TLS_DATA` |
| --- | --- | --- |
| native ARM64 | `0x5F` | **OFF** |
| x64 under ARM64X | `0x5F` | **OFF** |
| genuine x64 (Server 2022) | `0x7F` | ON |

Two independent causes, either sufficient:

- `RtlFindLdrpHandleTlsData10` scans `.text` for the literal bytes `48 8D 15`
  (`lea rdx,[rip+disp32]`) — an x64-only encoding, and it also hardcodes the
  destination register.
- `RtlFindLdrpReleaseTlsEntry` compiles a 21-byte x64 signature under
  `#ifdef _WIN64` — **and `_WIN64` is defined for ARM64** — then searches ARM64
  `.text` for x64 machine code. Byte-scanned directly: 1 hit on Server 2022 x64
  (correct), **0 hits in the ARM64X ntdll**.

When either misses, `MmpTlsInitialize()` nulls *both* TLS pointers, clears the
feature bit after having set it, and returns FALSE into a caller that discards
it. The load then succeeds anyway whenever the caller passes
`LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS`, so **memory-loaded modules run with no TLS
and nothing reports it.** The payload's `thread_local` resolves through an
unallocated index; it mostly appears to work because the fallback slot is still
per-thread.

Also dead code: the release scan requires `MajorVersion == 10` exactly, so on any
other version it returns `STATUS_NOT_SUPPORTED` first — the elaborate 6.1/6.2/6.3
`LdrpHandleTlsData` patterns above it can never run.

**Do not just fix the locator.** On ARM64X ntdll's loader is compiled twice and
the copy an x64 process reaches is ARM64EC. The dword before an ARM64EC function
is `(entryThunkRVA - fnRVA) | 1`; it is non-zero for exported functions and
**`0` for `#LdrpHandleTlsData`, `#LdrpReleaseTlsEntry` and `#LdrpFindTlsEntry`**.
Calling one from emulated x64 terminates the process with
`STATUS_WX86_INTERNAL_ERROR` (`0xC000026F`) and **is not catchable by SEH**. The
current build escapes this only because its scan already fails. A better locator
without an architecture-callability gate converts a silent no-op into an
undiagnosable process kill.

**What to do:** adopt `stress/probe_tls_release.cpp`'s pipeline — it locates
`LdrpHandleTlsData` for free as the winner's caller, so both rows go together.
Gate on the entry-thunk marker. Stop discarding `MmpTlsInitialize()`'s return.
See §2 for the probe results.

---

## 2. Every ntdll internal except the datatable lock is still pattern-scanned

**Status:** open. Verified replacements exist and are not adopted.

The datatable lock is found by ABI-driven decode with donor agreement and a
causality check. Nothing else is:

| Target | How the library finds it | Risk |
| --- | --- | --- |
| `LdrpHandleTlsData` | multi-stage `.rdata`/`.text` scan, hardcoded prologue offsets | **broken on ARM64/ARM64X — see §1** |
| `LdrpReleaseTlsEntry` | one hardcoded 21-byte x64 signature, `MajorVersion == 10` only | **broken on ARM64/ARM64X — see §1** |
| `LdrpModuleBaseAddressIndex` | `.data` byte scan, unaligned, unvalidated | medium — see §5 |
| `LdrpInvertedFunctionTable` | byte scan, hardcoded offsets and `MaxCount 0x200` | low on x64 (no live caller since the `ReflectiveMapDll` fix) but **the scan still runs at init on every architecture**, so a wrong hit is pure downside. Gate it `#ifndef _WIN64` |
| `LdrpHashTable` | structural derivation, validated by re-hashing | low — the best locator in the tree, and the standard the others should meet |

Four standalone probes now exist, each verified on native ARM64, x64-under-ARM64X
and genuine x64, and cross-checked against Microsoft's public PDBs (the probes
themselves never read a PDB):

| Probe | Finds | Result |
| --- | --- | --- |
| `stress/probe_tls_handle.cpp` | `LdrpHandleTlsData` | 2/2 anchors, behavioural proof, exact PDB match |
| `stress/probe_tls_release.cpp` | `LdrpReleaseTlsEntry` | 7/7 anchors, causality proof, exact PDB match |
| `stress/probe_baseindex.cpp` | `LdrpModuleBaseAddressIndex` | 75/75 processes deterministic |
| `stress/probe_ift.cpp` | `LdrpInvertedFunctionTable`, `LdrpHashTable` | structural + behavioural, every hardcoded constant confirmed |

Known weak spots carried forward, all fail-closed:

- Both TLS probes rest ultimately on the `"LdrpHandleTlsData"` literal in
  `.rdata`. If the compiler stops emitting the logging call, both anchors die
  together and the answer is NOT LOCATED.
- `probe_tls_release` does not survive the function being split into hot/cold
  `.pdata` regions by BBT. Server 2022's ntdll is BBT-split; this function
  happens not to be.
- `probe_baseindex` treats `Tree->Min` as a hard requirement, so a future
  `RTL_RB_TREE` gaining a field before `Min` fails closed even on a right answer.
  Make it a scoring signal, not a gate.

Also worth fixing while in there: `FindLdrpHashTable()` returns `nullptr` on the
*first* failed candidate instead of trying the next module, so one transiently
inconsistent ring disables the capability for the process lifetime.

---

## 3. Holding the right lock is necessary, not proven sufficient

**Status:** open by construction, no known reproducer.

The lock makes our splices of ntdll's loader database mutually exclusive with
ntdll's own. It does nothing about the other invariants ntdll maintains over a
database it believes it allocated: the DDAG state machine, the loader work queue,
`LdrpHashTable`, the `LDR_DDAG_NODE` dependency lists, and whatever a future
build starts checking. We fabricate an `LDR_DATA_TABLE_ENTRY` and assert
`LdrModulesReadyToRun` directly.

Note the pattern in what has actually worked here: the durable fixes were all
"stop hand-maintaining an ntdll internal" — `RtlAddFunctionTable()` replaced
editing `LdrpInvertedFunctionTable`, and the `LdrpHashTable` insert was dropped
rather than corrected. The lock fix is the only one that keeps hand-maintaining
an internal and just synchronises it better.

**The stronger answer, still not taken:** stop publishing into ntdll's database
at all. Keep the fabricated entry, because `LdrpHandleTlsData` needs the struct,
but link it into nothing. Resolve exports from our own parsed PE, keep publishing
unwind info through `RtlAddFunctionTable`. That deletes the bug class instead of
guarding it. Cost: OS loader APIs, debuggers and profilers stop seeing memory
modules.

---

## 4. The lock locator still fails silently when it fails

**Status:** margin materially improved; the failure mode is unchanged.

Nine measured donors now, worst case five agreeing against a minimum of two
(was two against two). Three decode on every configuration instead of one. But if
a future Windows build inlines the acquire in donor after donor, agreement
eventually drops below the minimum and the capability turns itself off — and that
**presents as the original list corruption returning**, not as an error.

Mitigations in place: the harness prints
`datatable lock : LOCATED at ntdll+0x… (N donors agreed, need 2)` every run, and
`MmpModuleDatatableLockAgreement` is exported. A falling donor count is the only
advance warning.

**Not done:** no telemetry or hard failure when the lock cannot be found — the
library loads and runs unsynchronized. Production code should read
`MmpModuleDatatableLockLocated` and `MmpModuleDatatableLockVerified` at startup
and decide for itself. Nothing does this yet.

Two loader exports are deliberately excluded from the donor list,
`LdrGetDllHandle` and `RtlQueueWorkItem`: both decode to a *different* ntdll SRW
lock under ARM64EC. Do not add them back.

---

## 5. The base-address index is still accepted without validation

**Status:** open; the race that made it flaky is fixed, the weak acceptance is not.

Discovery now runs under the datatable lock, which removed a measured 1.58%
silent-failure rate on genuine x64. What remains is how the address is accepted:
a byte-granular scan of `.data` only, taking any single match, with no check that
the result is actually the module tree.

`stress/probe_baseindex.cpp` shows the stronger form: pointer-aligned scan for the
`{Root, Min}` pair across all writable sections, then reconciliation against
`PEB->Ldr->InLoadOrderModuleList` (set equality both ways, in-order ascending by
`DllBase`, parent back-pointers consistent, binary search finds every module),
then a behavioural load/free. 75/75 processes deterministic, and it never
returned a wrong address.

Also still true: `MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX` being absent fails
every memory load, and nothing reports why.

---

## 6. `MmpLoaderLockGuard` gives up, and inverts a lock order when it does

**Status:** open, never observed firing.

After 64 failed attempts the guard proceeds with `Held == false` and increments
`MmpLoaderLockAcquireFailures`. For a caller about to splice ntdll's structures
that is the one thing it must not do; it should fail the load. The counter has
read 0 across every measurement.

Secondary consequence, same trigger: with `Held == false` the IAT resolver lock
is taken before the loader lock, inverting the ordering used everywhere else and
creating a genuine AB-BA deadlock against any other thread.

---

## 7. Residuals from fixes that are otherwise done

- **The causality check skips itself when the calling thread already owns the
  loader lock** — a consumer calling in from their own `DllMain`, and the
  reflective path, which must initialize there. Deliberate: the probe thread
  could not start and a correct address would read as a failure. In that case
  the lock rests on donor agreement plus structural checks and
  `MmpModuleDatatableLockVerified` reads 0. Only a *positive* disproof stands the
  capability down.
- **`ReflectiveMapDll` has no unload path.** It publishes and never tears down.
  Fine for a reflectively injected module that lives for the process, wrong if
  anyone calls the export directly.
- **The equal-base branch is still reachable** by calling the exported
  `ReflectiveMapDll` on a module ntdll already has. It now fails closed with
  `STATUS_OBJECT_NAME_COLLISION` rather than corrupting the tree, but nothing
  rejects the call earlier.
- **The IAT resolver APIs are not in `MemoryModulePP.def`**, so the
  `RemoveEntryList` fix there is correct by inspection and cannot be
  execution-tested without widening the public surface.

---

## 8. Unbounded and cosmetic

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

## Platform facts worth not rediscovering

- **On ARM64X the same ntdll resolves loader globals to different RVAs depending
  on the process view.** Same image base, same `TimeDateStamp`: datatable lock
  `+0x3929E0` native ARM64 vs `+0x38E930` as x64; base index `+0x3929F8` vs
  `+0x38E960`; hash table `+0x392DE0` vs `+0x394AA0`. The deltas differ between
  symbols, so it is not an image shift — ARM64X dynamic relocations give the EC
  view its own globals. **Any RVA table must be keyed on process architecture,
  not just on the ntdll build id.**
- **ARM64X carries two inverted function tables**, both structurally valid and
  both incremented on every load. They are told apart by which table's
  `ExceptionDirectory` column reproduces *this* view's `.pdata` pointers. The
  library gets this right by construction rather than by intent — anyone
  simplifying its byte pattern would make it a coin flip.
- **`.mrdata` reads `PAGE_READONLY` on all three configurations**, so
  `RtlProtectMrdata`'s page flip — and the race documented above
  `MmpRegisterExceptionTable` — is exactly as described.

---

## Bench caveats

- **Read the `features` line before reading anything else.** A run with
  `tls-handle=OFF` says nothing about TLS handling; a run with `base-index=OFF`
  would fail every load. Both are printed on every run now.
- **Measure on arm64 for contention**, but remember TLS handling is off there
  (§1), so arm64 cannot test anything TLS-related. Genuine x64 is the only
  configuration where the TLS path runs at all.
- **Exit code is the classifier**, not the console text: `0` clean, `1` soft,
  `0xC0000409` list corruption, `0xC0000374` heap corruption. Capture it with
  `Start-Process -PassThru`; bash mangles NTSTATUS values (`0xC0000409` arrives
  as `127`).
- **Always A/B against a same-session control.** `stress --native` swaps only the
  loader; `MMPP_NO_DATATABLE_LOCK` builds the identical source with the lock
  decoder disabled. Comparing against numbers from an earlier session is how this
  investigation went wrong twice.
- **Match the control to the axis being measured.** `nativetls.cpp` hammers pings
  at a module that is already loaded; the harness pings once per fresh load. If
  the defect is at load time, the former barely probes it. That mistake was made
  here and cost a round of wrong conclusions.
- **Do not read ntdll PE `TimeDateStamp` values as dates.** They are
  reproducible-build hashes.
- **On an unfamiliar build, run `lockprobe --survey` before guessing.** It groups
  every named ntdll export by the address it yields and marks the group that
  passes the causality check. Pick the group by that mark, never by size — the
  largest group is not the lock.
