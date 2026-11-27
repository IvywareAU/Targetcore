# Targetcore release notes

User-facing changes, newest first, starting with 3.4.6. The full rationale for every version,
including the ones before this file existed, is kept in `Targetcore_version.h`.

## 3.11.2

A patch release: a shared-memory connection can no longer stall. The flat C API, every exported
class layout and every wire format are unchanged. It needs Msgcore 3.7.1 or later.

- **A shared-memory connection that was sending and receiving at once could stop** until its
  timeout. If the outgoing ring was full and the peer emptied it at the same moment, the side
  could go to sleep waiting for a wake-up that the peer had no reason to send, while the peer
  waited for that side's data. It now sleeps only when every pending send and receive has really
  parked, and otherwise tries again.
- **Seen on Linux only:** the `shm_xproc` test hung in 4 of 150 runs before the fix and in none of
  450 after. Windows never showed it, and its shared-memory tests stay green.
- TCP and pipe connections are not affected.

## 3.11.1

A patch release: a process holding many hubs sends faster on Linux. The flat C API, every exported
class layout and every wire format are unchanged. It needs Msgcore 3.7.1 or later.

- **"Is this address a hub in this process?" is answered from an index** of hub addresses instead
  of a walk of every hub in the process, which ran under the process hub lock for every message
  not on its last hop. The answers, and what they decide about unsealed bodies, are unchanged.
  Debug builds check every answer against the walk and abort on a disagreement; on Linux, build
  with `-DP2P_ROUTE_CHECK` to get that check.
- **The check builds' mismatch markers now print on Linux.** They were silent once a warning had
  been written to stderr. The checks themselves worked: a mismatch still throws (3.11.0's) or
  aborts (the new one).
- **It matters to a process holding many hubs**, not to a hub with many connections from other
  processes.
- **Measured on Linux** (`perf_fanout fan`, every hub in one process, the last connection,
  p50): throughput rose 66% and 74% at 250 connections (two runs) and 11% to 14% at 64. At 16 it
  rose 3% (one run); at 1 the change was within noise. From 1 to 250 connections it no longer
  falls (38% before).
- **Measured on Windows: no throughput gain, and a small cost.** Two runs, 8 and 12 rounds. The
  cause of the cost at 16 and 64 connections is not known.

| Windows, 3.11.1 against 3.11.0 | Run 1 | Run 2 |
|---|---|---|
| throughput, 1 connection | −1.9% (better in 4 of 8) | −0.3% (5 of 12) |
| throughput, 16 | −0.3% (2 of 8) | −1.1% (2 of 12) |
| throughput, 64 | −1.7% (2 of 8) | −2.1% (3 of 12) |
| throughput, 250 | +0.8% (5 of 8) | +0.5% (8 of 12) |
| latency, 250 (lower is better) | −2.7% (7 of 8) | −2.6% (12 of 12) |

## 3.11.0

A minor release: routing to a hub with many connections is faster. The flat C API, every exported
class layout and every wire format are unchanged. It needs Msgcore 3.7.1 or later.

- **The hub finds a message's connection through an index** on the address segment below the hub,
  instead of asking every connection in turn. The test and the connection a message takes are
  unchanged.
- **A C++ class derived from `P2PeerCon` must not write `m_oThatP2Paddr` directly after login**;
  its messages may be mis-routed. Writing it before login is fine, and connections that never
  log in are routed as before. Debug builds check every pick against the full walk and stop on a
  disagreement; on Linux, build with `-DP2P_ROUTE_CHECK` to get that check.
- **Measured** (`perf_fanout fan`, the last of 250 connections, p50): throughput to it rose 41%
  on Windows (37.5k → 53.0k msg/s) and 36% on Linux (13.1k → 17.9k). Between 1 and 64 connections
  it moved between −1% and +13%. Throughput still falls as a hub gains connections: from 1 to 250
  by 7% on Windows (33% before) and by 38% on Linux (49% before).

## 3.10.1

A patch release: a received message is now checked for a forged structure before it is
dispatched. The flat C API and every wire format are unchanged. **It needs Msgcore 3.7.1 or
later.**

- **A frame with a forged object graph is refused instead of hanging or crashing the hub.**
  3.10.0 (below) said received messages were checked as before. That was wrong on one path: the
  check that accepts a frame proves its block structure but not the *graph* those blocks form,
  and the whole-tree check that would was not run on the receive path. A frame carrying a
  sibling chain linked back on itself hung the hub thread inside reading the message's source —
  reachable by any logged-in peer — and one with a descendant pointing at an ancestor overflowed
  the stack. The hub now runs the whole-tree check (bounded against both by Msgcore 3.7.1) on
  every inbound application message before it is routed, and drops the connection on a bad one,
  as it does for any malformed frame. A well-formed message is unaffected.

## 3.10.0

A minor release: a shared-memory transport, and a much cheaper round trip on every transport.
The flat C API and every wire format are unchanged. **It needs Msgcore 3.7.0 or later.**

- **Recompile C++ code.** `P2Peerio` gained five virtual functions, so any class derived from it
  must be recompiled, and the `P2PeerMsgnn` constructors now call a function new in this DLL, so
  a program compiled against these headers needs 3.10.0. Programs using only the flat C API need
  no change.
- **Shared memory between processes on one host** (`P2PeerConShm`). A named pipe, or a local
  socket on Linux, still makes the connection, controls access and notices a peer that dies; the
  messages go through shared memory. On Windows it needs Windows 8 or later
  (`P2PeerConShm::IsSupported`).
- **Messages this process builds are no longer validated in Release.** Msgcore 3.7.0 turns
  `g_bP2Pmsg_AssertValid` off by default in Release, and the pump queue now follows that switch
  for the hub's own posts. Set `P2P_ASSERT_VALID=1` to turn it back on. (This note originally
  claimed received-message checking was unchanged; that was wrong on one path — see 3.10.1, which
  adds the structural check a received message was missing.)
- **Fewer repeated header reads, and addresses built in one pass.** Message images are identical,
  byte for byte.

| `perf_ab`, two processes, 64 B, p50 | Windows 3.9.1 | Windows 3.10.0 | Linux VM 3.9.1 | Linux VM 3.10.0 |
|---|---|---|---|---|
| round trip, TCP | 164 µs | 117 µs | 236 µs | 176 µs |
| round trip, pipe | 139 µs | 92 µs | 193 µs | 158 µs |
| round trip, shared memory | 140 µs | 90 µs | 189 µs | 158 µs |
| pipelined, TCP | 19.6k msg/s | 35.2k msg/s | 11.0k msg/s | 16.2k msg/s |
| pipelined, pipe | 20.3k msg/s | 37.2k msg/s | 11.2k msg/s | 16.6k msg/s |
| pipelined, shared memory | 20.3k msg/s | 37.3k msg/s | 11.3k msg/s | 16.4k msg/s |

The shared-memory 3.9.1 columns are the 3.10.0 transport without the round-trip changes; 3.9.1
itself had no such transport. Shared memory clearly beats TCP on one host and is about level with
a pipe for small messages.

## 3.9.1

A patch release: routing to a hub with many connections is faster. The flat C API, every
exported class layout and every wire format are unchanged. It runs on Msgcore 3.5.1 or later.

- **The route walk measures each address once.** Finding the connection a message leaves by
  tests every connection in turn, and each test re-measured the destination, the hub and the
  connection's address. The lengths, and whether the hub itself covers the destination, are
  now taken once per message and once per connection. The tests, their order and the
  connection a message takes are unchanged; Debug builds check every answer against the 3.9.0
  test and stop on a disagreement.
- **Measured** (`perf_fanout fan`, the last of 250 connections, p50): throughput to it rose
  30% on Windows (19.8k → 25.8k msg/s) and 26% on Linux (10.3k → 13.0k). One connection and
  64 connections move by 5% or less. The walk is still one pass over the connections, so
  throughput still falls as a hub gains connections.
- **CI.** A push to master no longer re-runs the sanitizer and solution-build workflows for a
  commit that already passed on its branch, tags no longer start a CI run of their own, and
  the release workflow names the newest run that actually tested the commit. This is the
  first release made that way.

## 3.9.0

A minor release: a connection sends everything waiting in its queue with one write, up to 64
messages or 64 KB, instead of one write per message. Each message is still sealed, checked
against the frame limit and encrypted on its own, so the bytes on the wire are exactly what
would have gone out before, and any receiver reads them. Order is kept. A message too big for
the frame limit is still refused and reported, and the rest of the batch goes out. The flat C
API, every exported class layout and every wire format are unchanged. It runs on Msgcore 3.5.1
or later.

| 64 B, 5 rounds, gather off vs on | Windows | Linux VM |
|---|---|---|
| pipelined throughput | +56.6% | +43.9% |
| CPU per message, pipelined | −38% | −32% |
| fan-out to 64 connections, throughput to the last | +84.0% | +26.5% |
| one-way latency | flat | flat |
| system calls (Linux) | — | −73% |

It applies to TCP, named pipe and serial connections. In-process (DMX) connections and
transports that frame their own bytes are unchanged. `P2P_SEND_GATHER=0` in the environment
turns it off.

Why a minor version: `P2Peerio` gains public methods (`CanGatherSend`, `ResetStaged`,
`StageP2PeerMsg`, `GatherFull`, `SendStaged`) and `P2Peerio.h` the gather layout
(`P2PeerioSendGather`). None is virtual, so no vtable slot moves.

## 3.8.0

A minor release: a connection reads everything that has arrived in one go and then hands out
every complete message in it. Until now each message took two reads from the socket, one for
its 8-byte header and one for the rest. The checks a frame must pass are unchanged and refuse
the same frames with the same messages. The flat C API, every exported class layout and every
wire format are unchanged. It runs on Msgcore 3.5.1 or later.

| 64 B, 5 rounds, base 3.7.6 | Windows | Linux VM |
|---|---|---|
| one-way latency | −6.1% | −5.7% |
| fan-out to 64 connections, throughput to the last | +14.2% | +10.2% |
| fan-out to 64 connections, full round | −11.6% | −3.9% |
| pipelined throughput | −1.5% | +2.0% |
| system calls per message (Linux) | — | −27% |

Pipelined throughput does not improve yet: that path is limited by the sending side, which is
the next change.

Why a minor version: `P2Peerio.h` gains the receive buffer's layout (`P2PeerioRecvRing`) and
inline helpers (`P2PeerioRecvRequest`, `P2PeerioRecvPending`). Code that subclasses `P2Peerio`
and writes into a receive `OVERLAPPEDcon`'s buffers itself, as a test harness might, must use
them. Subclasses that override `RecvP2PeerMsg` are not affected. Each connection that has
received holds a 16 KB receive buffer.

Also fixed: the 3.7.6 DLL's binary file version resource read 3.7.5.0. Its version strings were
right.

## 3.7.6

A patch release: timers fire on time. A PITimer's deadline used to be counted in whole seconds
of wall-clock time, so a timer set for 50 ms fired anywhere from almost immediately to a full
second later, and a change of the system clock moved every pending timer. Deadlines now use a
monotonic millisecond clock. The one-second wait for a connection in the demultiplexer had the
same fault and is fixed the same way. The flat C API, every exported class layout and every wire
format are unchanged. It runs on Msgcore 3.5.1 or later.

| 50 ms timer, re-armed 10 times | 3.7.5 | 3.7.6 |
|---|---|---|
| time to fire, Windows | 708–1014 ms | 49–51 ms |
| time to fire, Linux VM | — | 50–64 ms |

## 3.7.5

A patch release: reading a message's source, destination or scope address takes one lookup
instead of two and no heap allocation. The answers are the same, and the flat C API, every
exported class layout and every wire format are unchanged. It runs on Msgcore 3.5.1 or later;
the lookup is allocation-free from Msgcore 3.6.1.

| 64 B, 5 rounds, base 3.7.3 on Msgcore 3.6.1 | Linux VM | Windows |
|---|---|---|
| allocations per delivered message | 34 → 30 | — |
| `perf_ab` throughput | +9.5% | +0.5% |
| `perf_ab` one-way latency | −5.3% | −1.7% (CPU −13%) |
| fan-out to 64 connections, throughput to the last | +8.7% | +2.0% |

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
