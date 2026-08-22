# Still open

What is actually still wrong, or still unproven, in MemoryModulePP.

`OPEN-ISSUES.md` is the historical record: everything it lists has now been fixed
or superseded, and several of its diagnoses turned out to be wrong in instructive
ways. Read it for *why* things are the way they are; read this file for what to
worry about now.

Ordered by how likely each is to bite in production.

---

## 1. No TLS for x64 processes on ARM64 hardware

**Status:** open, and a platform limit rather than a bug. This is the one that
matters for an x64 JDK on an ARM64 machine.

| Configuration | features | TLS |
| --- | --- | --- |
| native ARM64 | `0x6F` | ON — `LdrpHandleTlsData` `+0xD2270`, `LdrpReleaseTlsEntry` `+0xD2D18` |
| **x64 under ARM64X** | `0x0F` | **OFF — located, then refused** |
| genuine x64 (Server 2022) | `0x6F` | ON — `+0x35BF0` / `+0x82394` |

On ARM64X ntdll's loader is compiled twice and the copy an x64 process reaches is
ARM64EC. The dword before an ARM64EC function is `(entryThunkRva - fnRva) | 1`;
it is non-zero for exported functions and **`0` for `#LdrpHandleTlsData`,
`#LdrpReleaseTlsEntry` and `#LdrpFindTlsEntry`**. Calling one from emulated x64
terminates the process with `STATUS_WX86_INTERNAL_ERROR` (`0xC000026F`) and **is
not catchable by SEH**.

So `MmpLocateNtdllTls` finds the right address there and refuses it. The harness
prints `REFUSED (ARM64EC: not callable here)`, deliberately distinct from "not
located": the address is correct, the platform will not allow the call. Before
this was a decision, the build was safe here only because its x64 byte scan
happened to fail.

**Consequence:** a memory-loaded module with a TLS directory gets no TLS in that
configuration. Loads still succeed if the caller passes
`LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS`; without it they fail, which is the honest
outcome. `thread_local` in such a module resolves through an unallocated index.

**The available option is `MMPP_USE_TLS=1`** — the library's own TLS
implementation in `MmpTls.cpp`, which needs no ntdll internals and so is immune
to the EC problem. It is not the default and should not be enabled casually: it
Detour-patches `RtlUserThreadStart`, `LdrShutdownThread` and
`NtSetInformationProcess` **process-wide** and takes over
`ThreadLocalStoragePointer`. Inside a JVM that is a compatibility surface against
every profiler, APM and AV agent, and it is the same "reimplement OS behaviour"
pattern that every durable fix in this project moved away from. It compiles
cleanly today but **will not link**: the Detours sources in `3rdparty/Detours`
are not in `MemoryModule.vcxproj`. Enabling it is a deliberate decision with a
build change and a test campaign attached.

The third option is to ship a native ARM64 build, where TLS now works.

---

## 2. Holding the right lock is necessary, not proven sufficient

**Status:** open by construction, no known reproducer.

The lock makes our splices of ntdll's loader database mutually exclusive with
ntdll's own. It does nothing about the other invariants ntdll maintains over a
database it believes it allocated: the DDAG state machine, the loader work queue,
`LdrpHashTable`, the `LDR_DDAG_NODE` dependency lists, and whatever a future
build starts checking. We fabricate an `LDR_DATA_TABLE_ENTRY` and assert
`LdrModulesReadyToRun` directly.

Note the pattern in what has actually worked here. Every durable fix was of the
form "stop hand-maintaining an ntdll internal": `RtlAddFunctionTable()` replaced
editing `LdrpInvertedFunctionTable` — and with x86 gone, that apparatus is now
deleted outright — the `LdrpHashTable` insert was dropped rather than corrected,
and the TLS helpers are now located by ABI rather than by byte signature. The
lock fix is the only one that keeps hand-maintaining an internal and just
synchronises it better.

**The stronger answer, still not taken:** stop publishing into ntdll's database
at all. Keep the fabricated entry, because `LdrpHandleTlsData` needs the struct,
but link it into nothing. Resolve exports from our own parsed PE, keep publishing
unwind info through `RtlAddFunctionTable`. That deletes the bug class instead of
guarding it. Cost: OS loader APIs, debuggers and profilers stop seeing memory
modules.

---

## 3. Two locators still fail silently when they fail

**Status:** open by design; the failure direction is deliberate, the silence is
the problem.

Both the datatable lock and the TLS helpers fail closed — they turn the
capability off rather than guess. That is right. What is missing is anyone acting
on it: the library loads and runs regardless, and a locator that stops working
after a Windows update **presents as the original bug returning**, not as an
error.

Everything needed to detect it is exported and printed every run:

| Export | Meaning |
| --- | --- |
| `MmpModuleDatatableLockLocated` / `…Verified` / `…Agreement` | lock found / causality-proved / donors agreeing (9 donors, worst case 5, minimum 2) |
| `MmpTlsLocated` / `MmpTlsRefused` / `MmpTlsAgreement` | TLS found / refused by the ARM64EC gate / anchors agreeing (2 required) |
| `LdrQuerySystemMemoryModuleFeatures` | which capabilities actually came up |

**Production code should read these at startup and decide for itself whether to
proceed. Nothing does this yet.** A falling `Agreement` across Windows updates is
the advance warning in both cases.

Two loader exports are deliberately excluded from the lock's donor list,
`LdrGetDllHandle` and `RtlQueueWorkItem`: both decode to a *different* ntdll SRW
lock under ARM64EC. Do not add them back.

---

## 4. The base-address index is accepted without validation

**Status:** open. The race that made it flaky is fixed; the weak acceptance is
not.

Discovery now runs under the datatable lock, which removed a measured 1.58%
silent-failure rate on genuine x64. What remains is *how* the address is
accepted: a byte-granular scan of `.data` only, taking any single match, with no
check that the result is actually the module tree.

`stress/probe_baseindex.cpp` shows the stronger form — pointer-aligned scan for
the `{Root, Min}` pair across all writable sections, then reconciliation against
`PEB->Ldr->InLoadOrderModuleList` (set equality both ways, in-order ascending by
`DllBase`, parent back-pointers consistent, binary search finds every module),
then a behavioural load/free. 75/75 processes deterministic, and it never
returned a wrong address.

`MEMORY_FEATURE_MODULE_BASEADDRESS_INDEX` being absent fails every memory load,
and the features line is the only thing that says why.

---

## 5. Teardown still proceeds without the loader lock

**Status:** open, never observed.

`MmpLoaderLockGuard` retries 64 times and then reports failure. Load paths now
decline with `STATUS_LOCK_NOT_GRANTED` rather than publishing unserialized — that
also closed the AB-BA inversion, where a failed acquire put the IAT resolver lock
before the loader lock. Teardown paths have no way to decline and still proceed.

`MmpLoaderLockAcquireFailures` is printed every run and has read 0 across every
measurement, so this has never fired. The remaining question is what teardown
*should* do instead; `__fastfail` on a condition never observed did not seem
proportionate.

---

## 6. Smaller open items

- **`MmCleanup` unmaps the global data** while other threads may hold live
  pointers into it. Needs a reference-counted or deferred teardown.
- **`MmpAllocateGlobalData` derives its section name from `~pid ^ ProcessHeap`**,
  which is guessable. The section is `\BaseNamedObjects\MMPP*<hash>`; another
  process in the same session could open it.
- **The equal-base branch is still reachable** by calling the exported
  `ReflectiveMapDll` on a module ntdll already has. It now fails closed with
  `STATUS_OBJECT_NAME_COLLISION` rather than corrupting the tree, but nothing
  rejects the call earlier.
- **`ReflectiveMapDll` has no unload path.** It publishes and never tears down.
  Fine for a reflectively injected module that lives for the process, wrong if
  anyone calls the export directly.
- **The IAT resolver APIs are not in `MemoryModulePP.def`**, so the
  `RemoveEntryList` fix there is correct by inspection and cannot be
  execution-tested without widening the public surface.
- **The causality check skips itself when the calling thread already owns the
  loader lock** — a consumer calling in from their own `DllMain`, and the
  reflective path. Deliberate: the probe thread could not start and a correct
  address would read as a failure. `MmpModuleDatatableLockVerified` reads 0 to say
  so, and only a *positive* disproof stands the capability down.
- **The duplicate-module scan matches loosely.** It compares base name with
  `dist == 0 || dist == 4`, then only `SizeOfCode` and `SizeOfHeaders`. Two
  different DLLs sharing a base name and those two header fields would alias, and
  re-loading a *different build* of the same-named DLL can silently return the old
  module. Give distinct content distinct names.

---

## Platform facts worth not rediscovering

- **On ARM64X the same ntdll resolves loader globals to different RVAs depending
  on the process view.** Same image base, same `TimeDateStamp`: datatable lock
  `+0x3929E0` native ARM64 vs `+0x38E930` as x64; base index `+0x3929F8` vs
  `+0x38E960`; hash table `+0x392DE0` vs `+0x394AA0`; `LdrpHandleTlsData`
  `+0xD2270` vs `+0x218700`. The deltas differ between symbols, so it is not an
  image shift — ARM64X dynamic relocations give the EC view its own globals.
  **Any RVA table must be keyed on process architecture, not just on the ntdll
  build id.**
- **"Which instruction set am I" must be read from an ntdll export, not a
  compile-time macro.** Only the address `GetProcAddress` hands *you* says which
  view you are in, and for an x64 process on ARM64X it is a fast-forward thunk
  that has to be followed first. Getting this wrong is silent: every candidate
  gets skipped and the capability reports "not found".
- **ntdll is BBT-split on some builds.** Server 2022's `LdrpHandleTlsData` has a
  cold fragment at `+0xB851E`; anything scanning a function's body must follow the
  unwind chain to collect every fragment or it will silently miss code.
- **ARM64X carries two inverted function tables**, both structurally valid and
  both incremented on every load, told apart by which one's `ExceptionDirectory`
  column reproduces this view's `.pdata`. No longer relevant to the library, which
  does not touch them at all, but it will bite anyone who goes looking.
- **`.mrdata` reads `PAGE_READONLY`**, and flipping it races ntdll's own flip
  regardless of what lock is held. That is why unwind info goes through
  `RtlAddFunctionTable` and the inverted-table code is gone.

---

## Bench caveats

- **Read the `features` line before reading anything else.** A run with
  `tls-handle=OFF` says nothing about TLS handling; `base-index=OFF` would fail
  every load. Both print every run, with a warning when TLS is off.
- **Measure on arm64 for contention**, but check `features` first — the three
  configurations no longer have the same capabilities.
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
- **On an unfamiliar build, run the probes before guessing.** `lockprobe --survey`
  groups every named ntdll export by the address it yields and marks the group
  that passes the causality check — pick by that mark, never by size, because the
  largest group is not the lock. `probe_tls_handle`, `probe_tls_release`,
  `probe_baseindex` and `probe_ift` do the same for their targets, each verified
  against Microsoft's public PDBs on three configurations.
