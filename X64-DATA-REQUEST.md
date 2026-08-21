> **CLOSED.** Everything below has been answered. Five configurations across four
> machines are verified, including the library's own locator on genuine x64
> hardware (Windows Server 2022, reachable as `ssh winmssql`), and the fast-fail
> is confirmed to reproduce on real x64 and to be removed by the fix. See
> "Confirmed on genuine x64 hardware" in `stress/README.md` for the numbers.
> Kept as the record of what was asked and why, and as the recipe if a sixth
> configuration ever needs checking.
>
> One correction carried over: the `ntdll timestamp` values below are PE
> `TimeDateStamp` build hashes, **not dates**. An earlier version of this file
> dated the Server 2022 box to 2014 from its `0x534DA4B0` stamp. It is Server
> 2022, build 20348.

# What I need from a genuine x64 machine

## ANSWERED -- Ask 1 came back VERIFIED

`stress/lock_result.txt` holds the run. The x64 decoder works, on a genuinely
x64 host (`ntdll machine : 0x8664`, no ARM64EC thunks anywhere in the output):

```
ntdll timestamp : 0x534DA4B0        (~April 2014, so a 6.3 / 2012 R2-era ntdll)
ntdll SizeOfImg : 0x00205000

LdrQueryModuleServiceTags   decoded via x64  -> ntdll+0x175AC0
LdrAddRefDll                decoded via x64  -> ntdll+0x175AC0
donors decoded : 2 of 5, agreeing : 2

while held    : LoadLibrary blocked      (expected)
after release : LoadLibrary completed    (expected)
RESULT: VERIFIED -- this is LdrpModuleDatatableLock
```

Three things that came out of it, all of which changed the code:

1. **The `lea rcx,[rip+disp32]` / `call rel32` shape is real on x64**, so
   `MmpDecodeDonor` is now implemented there and no longer a no-op.

2. **The working donors are almost disjoint between architectures.** On x64 only
   `LdrQueryModuleServiceTags` and `LdrAddRefDll` decode; on ARM64 only
   `LdrQueryModuleServiceTags`, `LdrDisableThreadCalloutsForDll` and
   `LdrGetDllHandleByMapping` do. `LdrAddRefDll` was not in the library's donor
   list at all, so the library would have found exactly one donor on x64, fallen
   below its two-donor minimum, and silently stayed disabled even with the
   decoder enabled. The list is now the union of both, and each target gets
   exactly two votes -- the minimum. Do not trim it.

3. **The RVA is nothing like ARM64's.** `0x175AC0` here against `0x3929E0` on
   10.0.26100, which is what a hardcoded RVA would have got wrong, and is the
   argument for locating it at runtime.

## Also solved since: x64 on ARM64 hardware

An x64 process on an ARM64 machine -- an x64 JDK on arm64, the common pairing --
now works too, and it needed more than the plain x64 decoder. It is verified end
to end on this host: `LOCATED at ntdll+0x38E930`, causality check passing, and
the harness reporting a normal acquisition count.

Three things made it different, and the last one is genuinely surprising:

- The export is an **ARM64EC fast-forward thunk**, not x64 code, so it has to be
  followed. The code behind it is ARM64, which means an x64 binary must be able
  to decode ARM64.
- The ARM64EC build **hides the acquire two calls deep**, behind
  `LdrpAcquireModuleDatatableLock`, reached via `LdrpFindLoadedDllByHandle` or
  `LdrpDereferenceModule`. Hence depth-limited recursion on that path only.
- **The ARM64EC view uses a different lock object than the native view of the
  same ntdll file** -- `ntdll+0x38E930` versus `ntdll+0x3929E0`. An ARM64X image
  is two ntdlls behind one export table and a process runs one view throughout,
  so this is consistent, but it is not something anyone would have guessed. The
  causality check is what settled it.

So of the four configurations that matter, three are confirmed end to end and
one is confirmed only by the probe:

| Configuration | probe | library |
| --- | --- | --- |
| native arm64 | verified | verified |
| x64 on ARM64X | verified | verified |
| native x64 (2017 and 2014 builds) | verified | **not yet** |

The remaining gap is narrow but real: `lockprobe` validates by causality,
whereas the library validates by donor agreement plus a range and
writable-page check, because it initialises inside `DllMain` where it cannot
spawn the probe thread. Those are not the same test, so **the library's own
locator has still never run on genuine x64 hardware**. Closing that needs one
more thing, below. (`lockprobe` now prints a `library verdict` line that predicts
the answer -- it read `WOULD ACCEPT` in both configurations tested here.)

## Still wanted -- confirm the library, not just the probe

Copy `stress\bin` to the same x64 machine and run any small stress
configuration. The only line that matters is the `datatable lock` one:

```cmd
stress\bin\stress.exe --dll stress\bin\MemoryModule64.dll ^
                      --payload stress\bin\stresspayload.dll ^
                      --mode mixed --threads 4 --noise 4 --iters 50
```

Expected: `datatable lock : LOCATED at ntdll+0x175AC0` with a non-zero acquire
count. If it says `NOT LOCATED (guards are no-ops)` then the library's extra
validation is rejecting an address the probe accepted -- almost certainly the
writable-page check -- and that is a one-line fix once I know.

Then, if that reads LOCATED, Ask 3 below becomes worth doing: it would be the
first measurement of this bug on real x64 hardware.

## Why (original context)

`stress/README.md` ("The wrong lock") establishes the cause of the
`0xC0000409` fast-fail: ntdll protects its loader database with
`ntdll!LdrpModuleDatatableLock`, an SRW lock, while MemoryModulePP splices the
same lists holding only `LdrpLoaderLock`. Two disjoint locks, so no mutual
exclusion, so a lost tail update and `head->Blink->Flink != head`.

The fix needs that lock. `stress/lockprobe.cpp` locates it at runtime without a
hardcoded RVA, a PDB, or an opcode signature for the function: several
*exported* ntdll functions acquire it by calling the *exported*
`RtlAcquireSRWLockShared/Exclusive`, and the ABI puts the lock pointer in the
first argument. So both ends of the pattern are `GetProcAddress` results, and
the only thing decoded is the one instruction that materialises that argument.
The answer is then verified by causality rather than trusted.

**This is proven on ARM64 and unproven on x64.** Three donors agree on
`ntdll+0x3929E0` and the causality check passes on this host. But this host is
ARM64, and its x64 ntdll exports are ARM64EC fast-forward thunks
(`48 8B C4 48 89 58 20 55 5D E9 …`) with no x64 body, so the x64 decoder cannot
be exercised here at all. Nothing in this investigation has ever run on real
x64 hardware — `stress/README.md` flags that too.

## The machine

Genuine x64 Windows on AMD or Intel silicon. **Not** ARM64, and not an x64 VM
hosted on ARM64 — both give the ARM64EC thunks again, which is precisely the
case that already fails here. The probe prints `ntdll machine : 0x8664` and
reports no EC thunks when it is on the right kind of box; if you see
`ARM64EC fast-forward thunk` in the output, the machine is wrong.

If you can reach more than one, a Windows 10 and a Windows 11 or Server build
are worth more than two of the same, because the open question is how stable
the pattern is across builds.

## Ask 1 — the probe output. This is the one that matters.

**The binary to copy:**

```
Z:\diktalaunch\MemoryModulePP\stress\bin\lockprobe.exe
```

Already a native x64 PE (`8664 machine (x64)`), statically linked (`/MT`), 144 KB.
One self-contained executable: nothing to install on the target, no arguments or
config needed, and it does not need the MemoryModule DLL, the payload, or any
other file from this tree. Copy it anywhere on the x64 box and run it.
`stress\build.cmd x64` regenerates it.

Run:

```
lockprobe.exe
lockprobe.exe --dump
```

Send both outputs verbatim, including the header block. Exit code 0 means
located and verified, 1 means not located or not verified, 2 means setup
failure.

To rebuild instead of copying, from an x64 Developer Command Prompt:

```
cl /nologo /std:c++17 /O2 /MT /EHsc stress\lockprobe.cpp /link /OUT:lockprobe.exe
```

### What a good result looks like

```
built for       : x64
ntdll machine   : 0x8664
...
LdrQueryModuleServiceTags
  decoded via   : x64
  LOCK          : <addr>  (ntdll+0x…)
...
donors decoded  : 3 of 5
agreeing        : 3
--- causality check ---
  while held    : LoadLibrary blocked      (expected)
  after release : LoadLibrary completed    (expected)
RESULT: VERIFIED -- this is LdrpModuleDatatableLock
```

If that is what comes back, the technique is portable and I can wire it into
the library behind the same verification.

### What a bad result means, and what I need instead

- `decoded via : NO MATCH` on all donors, no EC thunks reported — the x64 code
  shape differs from what the decoder expects. Most likely ntdll inlines the
  SRW acquire on x64 (a `lock bts` on the lock word) instead of calling the
  exported routine, in which case there is no `call` to anchor on. **Then I
  need Ask 2**, which gives me the real instruction sequence to decode.
- `RESULT: FAILED VERIFICATION` — a decoded address that does not behave like
  the lock. Send it anyway; it is more informative than a miss.
- The 48-byte dumps in `--dump` output may not reach the acquire site. They are
  a fallback, not a substitute for Ask 2.

## Ask 2 — cdb ground truth

Needs Debugging Tools for Windows on the target, plus outbound access to the
Microsoft symbol server. If Ask 1 comes back VERIFIED this is optional; if it
comes back NO MATCH it is the thing that unblocks me.

```cmd
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols

cdb -c "x ntdll!Ldrp*Lock*; q"                             C:\Windows\System32\cmd.exe
cdb -c "? ntdll!LdrpModuleDatatableLock - ntdll; q"         C:\Windows\System32\cmd.exe
cdb -c "uf ntdll!LdrQueryModuleServiceTags; q"              C:\Windows\System32\cmd.exe
cdb -c "uf ntdll!LdrpInsertDataTableEntry; q"               C:\Windows\System32\cmd.exe
cdb -c "uf ntdll!LdrpMapDllWithSectionHandle; q"            C:\Windows\System32\cmd.exe
cdb -c "uf ntdll!LdrUnloadDll; q"                           C:\Windows\System32\cmd.exe
cdb -c "?? sizeof(ntdll!_LDR_DATA_TABLE_ENTRY); dt ntdll!_LDR_DATA_TABLE_ENTRY; q" C:\Windows\System32\cmd.exe
cdb -c "?? sizeof(ntdll!_LDR_DDAG_NODE); q"                 C:\Windows\System32\cmd.exe
```

What each one settles:

| Query | Question it answers |
| --- | --- |
| `x ntdll!Ldrp*Lock*` | Does `LdrpModuleDatatableLock` exist under that name on this build, and what else is nearby |
| `? … - ntdll` | Its RVA on this build, to compare against ARM64's `0x3929E0` |
| `uf LdrQueryModuleServiceTags` | **The critical one.** Is the acquire an explicit `call RtlAcquireSRWLockExclusive` with `lea rcx,[rip+…]` before it, or inlined? This is what the decoder has to match |
| `uf LdrpInsertDataTableEntry` | Confirm it still takes no lock itself and still holds the `brk`/`int 29h` for `FAST_FAIL_CORRUPT_LIST_ENTRY` |
| `uf LdrpMapDllWithSectionHandle` | Confirm the caller is what acquires the datatable lock on x64 too |
| `uf LdrUnloadDll` | Confirm the two locks are still taken **sequentially, not nested** — acquire datatable, release it, then take the legacy lock. This is what makes it safe for us to nest legacy → datatable |
| `sizeof(_LDR_DATA_TABLE_ENTRY)` / `dt` | MemoryModulePP hardcodes this layout. On ARM64 build 26100 it is `0x138` with `HotPatchState` last at `+0x130`, matching `LDR_DATA_TABLE_ENTRY_WIN11`. Needs confirming on the production target |
| `sizeof(_LDR_DDAG_NODE)` | Same reason; `0x50` here |

`uf` output can be long. Redirect to a file and send the file:

```cmd
cdb -c "uf ntdll!LdrQueryModuleServiceTags; q" C:\Windows\System32\cmd.exe > svctags.txt
```

## Ask 3 — an x64 stress baseline

Lower priority, but valuable because no verdict in this investigation has ever
been confirmed on real x64, and the README's numbers all carry that caveat.

Copy the whole `stress\bin` directory over and run:

```cmd
stress\bin\stress.exe --dll stress\bin\MemoryModule64.dll ^
                      --payload stress\bin\stresspayload.dll ^
                      --mode mixed --threads 8 --noise 8 --iters 200
```

Twelve runs, and record the exit code of each — the exit code is the
classifier, not the console text. `0` clean, `1` soft, `0xC0000409` the
fast-fail, `0xC0000005` an access violation. In PowerShell:

```powershell
1..12 | ForEach-Object {
  $p = Start-Process .\stress.exe -PassThru -Wait -WindowStyle Hidden `
       -ArgumentList '--dll','.\MemoryModule64.dll','--payload','.\stresspayload.dll',
                     '--mode','mixed','--threads','8','--noise','8','--iters','200'
  '0x{0:X8}' -f $p.ExitCode
}
```

Two things I want out of this. Whether the fast-fail reproduces at all on real
x64 hardware — it should, since the cause is architecture-independent, and if
it does not that is important news. And the rate, to compare against the 17%
measured on ARM64 here (18 clean, 2 soft, 4 fast-fail over 24 runs).

Note the `soft` count is not fully trustworthy: the harness's own integrity
checker takes the same wrong lock, so it can report a transient mid-splice tear
as corruption. The `0xC0000409` count is the reliable signal.

## Summary of what to send back

1. `lockprobe.exe` output, plain and `--dump`, plus exit codes. **Required.**
2. The cdb outputs, especially `uf ntdll!LdrQueryModuleServiceTags`. Required
   only if 1 does not come back VERIFIED, but welcome regardless.
3. Twelve stress exit codes. Nice to have.
4. Windows build number and edition for each machine, so the results can be
   attributed (`cmd /c ver`, or the probe's `ntdll timestamp` line).

With 1 alone I can either wire the locator in or fix the decoder. With 1 and 2
I can also confirm the lock ordering and struct layout assumptions hold on the
production architecture, which are the two remaining places this design could
still be wrong.
