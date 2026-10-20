# Targetcore release notes

User-facing changes, newest first, starting with 3.4.6. The full rationale for every version,
including the ones before this file existed, is kept in `Targetcore_version.h`.

## 3.4.7

A patch release. The flat C API (103 symbols), every class layout and the wire format are
unchanged.

### New: an external key protector (`IdProtect_External`)

The identity store can now hand the private-key payload of `identity.key` and
`agreement.key` to a wrap/unwrap function the host supplies, instead of DPAPI (Windows) or
plain storage with 0600 permissions (POSIX).

```cpp
p2pcng::SetExternalProtector(&MyWrap, pCtx);    // once, before the first key is touched
p2pcng::LoadOrCreateIdentity(path, key, &created, p2pcng::IdProtect_External);
```

- **What it is for:** P2PeerLan's Android app registers AES-GCM under an Android Keystore
  key. The plaintext keys exist only in memory, as DPAPI keeps them on Windows.
- **Threads:** the protector may be called on any thread that loads or saves a key, pump
  threads included. It must not wait on the UI.
- **Failures:** with no protector registered, an External save or load fails
  `IdErrUnsupported` and writes nothing. A protector that refuses (wrong key, tampered blob)
  gives `IdErrProtect` / `IdErrUnprotect`.
- **Existing files:** they load exactly as before; the container records the protection.

**Compatibility:** a build older than 3.4.7 refuses a key file with protection 3
(`IdErrFormat`). Only a host that registers a protector writes one.

## 3.4.6

A patch release that brings **Android**. The flat C API (103 symbols), every class layout and the
wire format are unchanged, and a Windows build compiles to the same code. It needs Msgcore 3.4.1.

### New: Android (NDK)

Targetcore now builds with the Android NDK (clang, libc++, bionic) for `arm64-v8a` and `x86_64`,
API 29 and later. P2PeerLan's Android app is the first consumer: it runs the cores natively.

- **`P2P_IO_BACKEND`** (`uring` | `epoll`) chooses the async I/O backend.
  - `epoll` is Msgcore 3.4.1's new backend. It is the default when building for Android,
    because Android blocks io_uring for apps.
  - Linux keeps `uring` by default.
  - liburing is now required only for the `uring` build.
- **Message maps work under clang.** The `BEGIN_*_MAP` macros took handler addresses as
  `&Handler`, without the class name. MSVC accepts that; clang does not, even with
  `-fms-extensions`.
  - Off MSVC, each map now names the class itself (`P2PThisClass`).
  - No map in any consumer needs editing, and the MSVC expansion is unchanged.
  - A **hand-written** map outside the macros needs `typedef YourClass P2PThisClass;`.
- **Identity store without hard links.** Android's SELinux denies `link()`, which the identity
  file's exclusive write relied on. It now falls back to `renameat2(RENAME_NOREPLACE)`, which is
  equally atomic and equally refuses to overwrite.
- `WSA_Ext.h` defines `SOCKET` only on Windows.

### Tested

- Linux, full suite: 101/101 on io_uring. 100/101 on epoll; the failure was a timing check that
  passes when run alone.
- Windows: 96/96.
- Android 14 emulator (x86_64): P2PeerLan's native suite passed 11/12. `lan_ctl_test` must run
  inside an app to bind its socket file.
- arm64 has run only under the emulator's ARM translation, not on a phone yet.
