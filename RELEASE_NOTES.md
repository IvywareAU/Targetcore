# Targetcore release notes

User-facing changes, newest first, starting with 3.4.6. The full rationale for every version,
including the ones before this file existed, is kept in `Targetcore_version.h`.

## 3.7.4

A patch release that changes build settings only. The Visual Studio project now builds Release
with full inlining (`/Ob2`) instead of explicit-inline-only (`/Ob1`), matching the CMake build.
The source, the flat C API, every exported class layout and every wire format are unchanged.

| `perf_ab`, 64 B, Windows Release, Visual Studio-built DLLs | 3.7.3 + Msgcore 3.6.1 | 3.7.4 + Msgcore 3.6.2 |
|---|---|---|
| one-way latency p50 | 105.0 µs | ~94 µs |
| throughput | 21.9k msg/s | ~26.4k msg/s |

## 3.7.3

A patch release: a message pump no longer takes a process-wide lock on every visit, and a hub's
timers are guarded by one lock instead of two. The flat C API, every exported class layout and
every wire format are unchanged. It runs on the same Msgcore as 3.7.2 (3.5.1 or later).

- **Fixed: timers set from two threads could corrupt the pump's timer list.** Timers set for a
  connection, and the pump reading its timers, used one lock; timers set for a `P2Peerio` or a
  `P2PeerTarget`, and `NextP2PmsgTimer`, used another. It needed a connection timer armed from
  another thread at the same moment and has not been seen to fire. All timer operations now
  take the pump's own lock.
- **A pump visit takes no process-wide lock.** Each pump finds itself without the lock that
  every thread posting to it also takes. Throughput and latency are unchanged within
  measurement noise; contended lock waits fall.

## 3.7.2

A patch release: routing a message to a hub's later connections no longer slows down with the
square of the connection count. The flat C API, every exported class layout and every wire
format are unchanged. It runs on the same Msgcore as 3.7.1 (3.5.1 or later).

- **One walk per route.** Finding the connection a message leaves by used to take the
  process-wide hub lock and re-scan the hub's list from the start once per connection passed.
  It is now one pass under one lock. Which connection a message takes is unchanged.
- **Measured** (`perf_fanout fan`, 250 connections, p50): the extra cost of reaching the last
  connection fell from 75 to 18 µs on Windows and from 131 to 28 µs on Linux; throughput to it
  rose 54% and 75%. Hubs with a handful of connections see no change.

## 3.7.1

A patch release: a message quoted inside another one is quoted without its unused space. The
flat C API, every exported class layout and every wire format are unchanged. Use it with
**Msgcore 3.5.1**; it also runs on 3.5.0.

- **Error and exception reports, and timer wraps, embed the live message.** These embed the
  wrapped message's whole image, and that image is its heap, free space included. They now trim
  it first, as sending has since 3.7.0. An embedded message is smaller, so fewer reports reach
  the size bound where the body is left out.
- **Why now:** from Msgcore 3.5.1 a message's heap doubles when it grows, so an untrimmed report
  could have quoted up to half its message in free space.
- Unwrapping is unchanged. A trimmed embedded image is read the way any received image is.

## 3.7.0

A minor release: unsealed frames are much smaller. **Requires Msgcore 3.5.0.** The flat C API,
every exported class layout and the receive path are unchanged, and peers on older releases accept
the new frames.

- **A frame now carries the message, not its heap.** A message's frame used to be its whole heap,
  including about 1.4 KB of free space at the end, so a 64-byte message went out as 2,032 bytes.
  Before sending, Targetcore now trims that free space (Msgcore's `TrimP2Piomage`). This applies
  on every transport (TCP, pipes and in-process DMX links), before the link cypher and the frame
  size check.
- **Measured with a 64-byte payload, the same on Windows and Linux:** an unsealed frame is 629
  bytes instead of 2,032 (−69%), and a sealed one 1,058 instead of 1,344 (−21%). Latency and CPU
  per message are unchanged on loopback. The saving is bandwidth, so it shows on real links.
- **The largest unsealed payload that fits a frame rises from 30,686 to 32,203 bytes.** A
  message's own structure now costs 565 bytes on the wire, not about 2,082.
- **Older peers accept the new frames, and this release accepts theirs.** A frame records only
  its length, and a trimmed frame passes every check a receiver makes. Tested both ways against
  3.6.0 on a real socket, with and without the link cypher, and against the C++23 bridge.
- A message can be added to after it is sent: its heap grows again as usual.

## 3.6.0

A minor release that changes one security default. The flat C API (103 symbols), every exported
class layout and the wire are unchanged.

- **`WaiveEndToEndInProcess` is now on by default.** A message to a hub in the same process,
  carried over links inside the process, is no longer sealed or signed end to end. Those two
  protections were 93% of the CPU per message on a default hub. Per-hop protections (key
  agreement, the signed login and the link cypher) are unaffected.
- **The waiver is now checked on every hop, which is what makes it safe as a default.** Until now
  it was opt-in, because it trusted that a route between two hubs in one process never left the
  process. With hubs A and C in one process and B on another host, wired A-B-C, A's message to C
  crossed to B in clear text. Now:
  - A hub waives only on a link that stays in the process, and only when both the sender and the
    destination are hubs in this process. In A-B-C, A seals and signs as before. Messages from
    any other source, including ones rewritten by a VNet mount, are handled as before.
  - An unsigned message from a hub in this process is accepted only if it also arrived over a
    link that stays in the process.
  - A relay refuses a waived, still-unsealed message rather than send it over a link that leaves
    the process. It logs a warning saying so.
  - Only in-process (DMX) links count as staying in the process. Every other transport, including
    TCP on loopback, counts as leaving.
- **Behaviour change:** in a tree where the route between two in-process hubs passes through
  another process, such messages can now be refused instead of delivered. Before 3.6.0 they were
  either sealed (waiver off) or sent in clear (waiver on). Call `WaiveEndToEndInProcess(false)` on
  the sending hub to have them sealed and signed at the origin as before. The flat C equivalent is
  `p2peerhub_waive_end_to_end_in_process(h, 0)`.
- New exported C++ entry points, all non-virtual: `IsP2PmsgHubSealWaivedInProcess`,
  `P2PeerHub::IsSealWaivedInProcessNoLock`, `P2PeerCon::StaysInProcess` and
  `P2PeerCon::WaivedBodyLeavesProcess`.

## 3.5.1

A patch release that takes a repeated check off the message pump. Nothing exported, no class
layout and nothing on the wire changed.

- **Each message's tree is now checked once on the pump, not twice.** In Release the pump walked
  every message's whole tree when the message was queued, and walked it again when it was
  dispatched, though nothing changes the message in between. The repeat now runs only in Debug
  builds, or in Release when the environment variable `P2P_PUMP_VERIFY` is set to anything but
  `0`. That variable is read once at start-up and brings back the old behaviour.
- **The check when a message is queued stays on.** Every message received from the network passes
  it.
- Measured on Windows on a direct link (`perf_ab`, security posture A): throughput +7.5% and about 6 µs
  less CPU per message. No measurable change on Linux.

## 3.5.0

A minor release that makes the security path faster. Every accept/refuse decision is the same,
the wire is unchanged and so are the sealed bytes. The flat C API (103 symbols) and every exported
class layout are unchanged too.

New exported C++ entry points, all non-virtual:
- `p2pcng::EcdhP256::DeriveRawSecret(const EcdhP256&)` agrees with a peer key that was already
  imported.
- `p2pseal::SealToKeyed` and `p2pseal::OpenKeyed` seal and open with reader and sender keys that
  were already imported. `p2pseal::SealTo` and `p2pseal::Open` behave as before.

What changed:

- **Replay checks are now constant-time per message.** The relay and seal replay caches used to
  compare each arriving signature against every cached one, up to 4,096 of them. They are now
  indexed, with the same age trim and the same eviction order.
- **Static public keys are imported once.** A reader's agreement key and a sender's identity key
  used to be re-imported for every message. They are now cached by the policy and cleared
  whenever the allow-list is reloaded.
- Together, those two changes cut CPU per message on a sealed relay chain by 10–11% on Windows and
  15–17% on Linux.
- **Windows: hashing and AES providers are opened once per process.** SHA-256, HMAC and AES-GCM
  now share a provider, as ECDH and ECDSA have since 3.4.5. HKDF is 46% faster, which saves about
  11–16 µs per seal or open.
- **Linux: the link cypher keys AES once per direction** instead of on every frame. That saves
  about 1 µs per seal and 0.9 µs per open. An `AesGcm` object can still be used from two threads
  at once, and allocation counts are unchanged.
- **`RequireSeal` costs much less on a link that never seals.** The last-hop test now runs first
  and the scope is read once. On a direct link the overhead is about half what it was on Windows,
  and under a third on Linux.

## 3.4.9

A patch release: an oversized message no longer drops the link. The flat C API (103 symbols),
every class layout and the wire format are unchanged. `P2Peerio` gains the constant
`kSendRefusedFrame` and the non-virtual member `MeasureSendFrame`; nothing virtual was added.

- **A message too big for the link is refused and reported, and the link stays up.** Nothing
  checked a frame against the link's send limit (32,768 bytes, about 30,680 bytes of payload on
  an unsealed link), so an oversized message was sent anyway. The receiver threw on its own
  limit and dropped the connection, and the sender was never told why. `P2Peerio::SendP2PeerMsg`
  now measures the frame before it is sent, counting the link cypher when it is on, and returns
  `P2Peerio::kSendRefusedFrame`. The connection reports the message to its sender as
  `P2Pevent_UNDELIVERABLE`, with the frame size and the limit in the text, then deletes it and
  sends the next queued message.
- **A refused message no longer stalls the send side.** When the VNet gate, the seal or the size
  check refused a message, the connection stopped sending until something else was posted.
  It now takes the next queued message straight away.
- **Transports with their own framing keep their own limits.** `P2PeerioDmx`, `P2PeerioBSTR` and
  P2PeerWeb's HTTP transport override `SendP2PeerMsg` and are not affected. P2PeerWeb's 34 KB
  HTTP frames still go out.

**Behaviour change:** code that calls `SendP2PeerMsg` on a stock transport directly can now get
`kSendRefusedFrame` back. Before, it got success followed by a dropped link. The new MscsUnitTests
case `p2p_oversize` covers a plain link and a cyphered one.

## 3.4.8

A patch release: a fix to the login handshake. The flat C API, every class layout and the wire format are
unchanged; `P2PeerCon` gains four non-virtual members (`ParkForLogin`, `ReleaseLoginHold`,
`PostHandshakeP2PeerMsg`, `GetSendableP2PeerMsg`) and the state bits `ConState_LoginHold` and
`ConState_LoginParked`.

- **A dialling connection no longer sends application messages ahead of its login.** Messages
  posted while a link was down or still connecting used to leave before the `Login` that opens
  it — on a restarted link the send path could even run before `OnConnect()` — and the far end
  refused them ("Application message received before login") and dropped the link. The next
  dial met the same queue, so a hub that kept posting never got through. A `CLIENT` connection
  now sends handshake messages only (`Login`, key agreement) until its login completes, and
  `Login`/`LoginAck` go to the front of the queue. Found by P2PeerLan's `lan_join_test`, whose
  in-process Dmx link from an app's `Talk` hub failed nearly every Release run.
- **A message right behind a `Login` or `LoginAck` is no longer gated before that login is
  applied.** The receive loop posts the handshake to the pump and used to read straight on, so
  when both arrived in one completion the next message met `GateAppMsgInbound()` before
  `OnLogin()`/`OnLoginAck()` had set `ConState_Login`. The loop now stops reading until the
  pump has applied the login, then resumes — order kept, nothing admitted early, and a login
  the pump refuses drops the connection with the next message still unread.

**Behaviour change:** a `CLIENT` connection whose peer never answers its `Login` now keeps its
application messages queued instead of sending them to be refused. Every connect handler in
these repositories logs in (`P2PeerTarget::On_ConConnect`, `PeerFsMesh`).

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
