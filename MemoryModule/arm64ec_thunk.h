/* arm64ec_thunk.h
 *
 * Lets an emulated-x64-on-ARM64 caller invoke ntdll's thunkless internal ARM64EC
 * loader helpers (LdrpHandleTlsData / LdrpReleaseTlsEntry) by borrowing a
 * signature-compatible entry thunk for the duration of one call. See
 * arm64ec_thunk.cpp and TLS-AND-ARM64X.md for the mechanism.
 *
 * Dependency-free on purpose: builtin types only, no includes, so it is safe to
 * pull into phnt-based translation units that must not see <windows.h>.
 *
 * On genuine x64 and native ARM64 the call wrappers are a plain direct call.
 * Return values are NTSTATUS (== long). Caller must hold the loader lock across
 * the call, exactly as when calling the helper directly.
 */
#ifndef ARM64EC_THUNK_H
#define ARM64EC_THUNK_H

#ifdef __cplusplus
extern "C" {
#endif

/* nonzero iff this is an x64 image running under emulation on ARM64 hardware */
int  Arm64ecEmulationActive(void);

/* nonzero iff a thunkless ARM64EC helper can be reached from here right now:
 * emulated on ARM64 AND both donor entry thunks were resolved. When this is
 * false the NtdllTls gate should keep refusing rather than attempt a fatal call. */
int  Arm64ecBorrowReady(void);

/* NTSTATUS LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY *entry) */
long EcCallHandleTlsData(void *fn, void *ldrEntry);

/* NTSTATUS LdrpReleaseTlsEntry(LDR_DATA_TABLE_ENTRY *entry, void **tlsVector) */
long EcCallReleaseTlsEntry(void *fn, void *ldrEntry, void **tlsVector);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ARM64EC_THUNK_H */
