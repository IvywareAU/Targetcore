<div align="center">

# TargetCore

### One address. Any transport. Every message routed.

**A peer-to-peer message-routing kernel in C++ — priority queues, IOCP pump threads, and a handler-map dispatch, over TCP, named pipes, RS-232 or DMX (Direct Memory eXchange).**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/C%2B%2B-23-00599C.svg)](#requirements)
[![Windows](https://img.shields.io/badge/Windows-authoritative%20build-0078D6.svg)](#supported-platforms)
[![Linux](https://img.shields.io/badge/Linux-Ported%20from%20Windows%2C%20not%20the%20reference-brightgreen.svg)](#supported-platforms)
[![Since](https://img.shields.io/badge/since-2002-6f42c1.svg)](#history)

</div>

> **⚠️ Security is ON by default since 2026-08-18, and a hub that cannot enforce it does not start.**
> `RequireAuth` defaults to **true**: a hub that requires authentication and holds no identity refuses
> to arm — `CreateHub()` returns `FALSE`, `SpawnHub()` returns `0`, and the refusal names the file that
> is missing. `RequireAuth(false)` remains a supported answer for loopback, trusted LAN segments and
> attached hardware buses; what is no longer possible is turning security off by saying nothing. There
> has been no independent audit. See [Security](#security) and [SECURITY.md](SECURITY.md) before
> deploying.

---

## Contents

- [Introduction](#introduction)
- [How a message gets routed](#how-a-message-gets-routed)
- [Description](#description)
  - [The object model](#the-object-model)
  - [Same hub, different wire](#same-hub-different-wire)
  - [Addressing](#addressing)
  - [Priorities](#priorities)
  - [Security](#security)
- [Requirements](#requirements)
- [Supported platforms](#supported-platforms)
- [Building](#building)
  - [The sibling dependencies](#the-sibling-dependencies)
  - [Windows — Visual Studio](#windows--visual-studio-authoritative)
  - [CMake](#cmake-in-tree)
- [Usage](#usage)
  - [Reporting the version](#reporting-the-version)
  - [Hosting a hub where nobody can see a dialog](#hosting-a-hub-where-nobody-can-see-a-dialog)
- [Documentation](#documentation)
- [Project status](#project-status)
- [History](#history)
- [License](#license)
- [Contact](#contact)
- [Contributing — we need your help](#contributing--we-need-your-help)
  · full policy in [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Introduction

TargetCore is a **message-routing kernel**, not a socket wrapper.

You give a *hub* an address on a virtual network — a dotted path such as `Root.MyHub`. The hub
owns a **priority queue**, runs **pump threads** on a Windows I/O completion port, and hands each
arriving message to a **handler map** keyed by message id. Routing decisions read that dotted
address string; they never read an IP.

Everything else — the wire — is a pluggable detail. Swap `P2PeerConWsa` for `P2PeerConPipe` and
the address, the queue, and the map stay exactly as they are. The same kernel that moves chat
frames between two machines over a socket hands them between two hubs in one process as a bare
pointer, with nothing serialised on the way.

The library ships as an MFC extension DLL (`TargetCore.dll`) with a C++ class API, plus a flat
`extern "C"` surface (`TargetCore_c.h`) for FFI consumers — including a Java Panama / jextract
bridge. The C surface is **93 exported entry points** covering `P2Paddr`, `P2PeerMsg`,
`P2PeerConWsa` and `P2PeerHub`, each `wchar_t`-based call paired with a UTF-8 `_u8` twin so a
cross-platform FFI caller never has to reason about the platform's `wchar_t` width.

---

## How a message gets routed

The full path, from an empty hub to a handled message:

```text
  ┌───────────────┐                            ┌──────────────────────────────────────────────┐
  │  CLIENT PEER  │                            │  P2PeerHub          Root.MyHub               │
  │  Root.Sender  │  ①  ECDH P-256 (default)   │                                              │
  │               │═══════════════════════════▶│   ┌────────┐   ┌──────────────┐   ┌────────┐ │
  │ P2PeerConWsa  │   ②  Login / LoginAck      │   │  PORT  │   │ P2PeerMsgQue │   │  MAP   │ │
  │               │                            │   │ :7777  │──▶│ pri  2  HIGH │──▶│ 42 ──▶ │ │
  │               │   ③  msg 42, pri HIGH      │   │ listen │   │ pri  7  NORM │   │ onChat │ │
  │               │───────────────────────────▶│   └────────┘   │ pri 12  LOW  │   └────────┘ │
  └───────────────┘                            │                └──────────────┘        │     │
                                               │                   ▲    ▲               ▼     │
                                               │                 pump 0  pump 1   msgHANDLED  │
                                               └──────────────────────────────────────────────┘
```

| Step | Call | What happens |
|-----:|------|--------------|
| 1 | `StartupP2Pmsg(n)` | The kernel comes up first: shared critical sections, the hub manager table, the pump pool hint. |
| 2 | `P2PeerHub(L"Root.MyHub")` | The hub takes an address on the virtual network. Every hop is a dot-separated name. |
| 3 | `RegisterTarget()` *(optional)* | Sub-targets register under the hub to share its pump without being hubs themselves. |
| 4 | `SpawnHub()` | The pump thread starts, creates its completion port, and blocks on the queue. The hub is live. |
| 5 | `ServiceFactory()` → `PostP2PeerCon()` | A service-mode connection listens. Accepted sockets are driven through the con-map. |
| 6 | `ClientFactory()` → `PostP2PeerCon()` | The peer dials in. The socket is up but untrusted — no message crosses it yet. |
| 7 | key agreement · `Login()` | `RequireAuth` is **on by default**: an ephemeral ECDH P-256 agreement derives the session key before the login, and the login binds the remote address to this connection. A hub that cannot enforce what it requires never reaches this step — it refuses to arm. With `RequireAuth(false)`, the connection goes straight to the login in clear. |
| 8 | `PostP2PeerMsg()` | The message enters the queue **by priority**, ahead of normal and low traffic already waiting. A pump takes the head, the map hits the id, the handler returns `msgHANDLED` — routing stops. |

---

## Description

### The object model

| Class | Role |
|-------|------|
| `P2PeerTarget` | Base of everything routable. Supplies the `P2PeerCon_MAP`, `P2PeerSys_MAP` and `P2PeerMsg_MAP` handler tables. Override its `On_Con*` / `On_*Cast` virtuals to react to lifecycle and message events. |
| `P2PeerHub` | A `P2PeerTarget` that owns a pump thread and routes `P2PeerMsg`s between peers. **This is the class you subclass** for an application endpoint. |
| `P2PeerCon` | One connection. Owns its completion-port association, its completion key (`this`), and four `OVERLAPPED` slots — send, recv, accept, connect. |
| `P2PeerMsg` | The unit of routing: source address, destination address, message id, priority, payload. `P2PeerMsg32` pre-allocates a 32-byte address area. |
| `P2PeerMsgQue` | Thread-safe priority queue. Highest-priority message leaves first, regardless of append order. |
| `P2PeerExplorer` | A `P2PeerTarget` on its own pump that exposes a hub's registered pumps, connections and status in real time — introspection, not discovery. |
| `P2PeerService` | Hosts a hub inside a Windows service (SCM integration). Routes the hub's diagnostics to the Windows event log — see [Hosting a hub where nobody can see a dialog](#hosting-a-hub-where-nobody-can-see-a-dialog). No environment setting needed since 2026-08-17. |

A hub *is* a target, so it inherits every connection handler. Connections are handed over with
`PostP2PeerCon()`; once the login handshake completes, application messages flow through
`PostP2PeerMsg()` → `On_P2PeerBCast()` / `On_P2PeerUCast()`.

### Same hub, different wire

A connection is a typed transport bolted onto the hub. The routing above is unchanged.

| Transport | Class | Wire | Service factory | Client factory |
|-----------|-------|------|-----------------|----------------|
| **TCP/IP** | `P2PeerConWsa` | WSA sockets, `AcceptEx` / `ConnectEx`, across machines | `(peerAddr, short port)` | `(peerAddr, ip, port)` |
| **Named pipe** | `P2PeerConPipe` | Local processes, or hub↔hub in one process | `(peerAddr, pipeName)` | `(peerAddr, pipeName)` |
| **Serial** | `P2PeerCon232` | RS-232 to attached hardware | `(peerAddr, short comPort)` | `(peerAddr, short comPort)` |
| **DMX** (Direct Memory eXchange) | `P2PeerConDmx` | Hub↔hub in one address space; the message image is handed over as a pointer, never serialised | `(peerAddr, serviceName)` | `(peerAddr, serviceName)` |

`P2PeerConWsa` requires `WSAStartup` before use; the other three do not.

**The client factory's `ip` may be a dotted literal or a host NAME**, and an empty string means
"this machine" — it is served by resolving `gethostname()`'s answer. All three go through one
`getaddrinfo()` call since 2026-08-28. Before that date **only the literal worked**: the resolver
tested `InetPton(...) == INADDR_NONE` to decide whether to fall back to `gethostbyname()`, a test
written for `inet_addr()` — which signals failure that way — and left behind when the call was
changed. `InetPton()` answers 0 and writes nothing, so a name stayed `0.0.0.0`, the fallback could
only fire for the literal `"255.255.255.255"`, and a client given a name failed inside `ConnectEx`
with `WSAEADDRNOTAVAIL` rather than saying it could not resolve anything. The self-connection path
went the same way. Nothing caught it because every test in the suite dials the literal
`"127.0.0.1"`; `p2p_resolve` is the one that passes a name.

**Which records it resolves is the FAMILY's answer, not this line's, since 2026-08-28.**
`SetFamily(P2PeerConFamily_IPv4)` — the default, and what every caller written before that date
keeps — asks for A records only; `_IPv6` asks for AAAA only; `_Dual` takes either and lets the
host's own RFC 6724 ordering choose. A name holding only the other kind of record is unreachable
under a family that does not match it, and says which it could not find. Until that date the hint
was the literal `AF_INET` because every socket the class opened was `AF_INET`, and answering an
AAAA record the connect could not use would have traded one silent failure for another.

**IPv6 is supported, and it is opt-in.** `P2PeerConWsa::SetFamily()` chooses `AF_INET` (default),
`AF_INET6`, or `AF_INET6` with `IPV6_V6ONLY` cleared — one socket serving both families, which is
what `_Dual` means. The option is set **explicitly in both directions** rather than inherited,
because the platforms disagree: Windows defaults it on and most Linux distributions default it
off, so a socket that did not say would be v6-only on one build and dual-stack on the other from
identical source. Set on a SERVICE before `Listen()` and on a CLIENT before `Connect()`, like the
backlog and the listen scope beside it. **A dual service reports a v4 peer as `::ffff:a.b.c.d`
and this class normalises that back to `AF_INET`** before anything reads it, so an operator's
`"10.0.0.0/8"` means the same thing on either socket — refer the accept allow-list below.
`P2PsourceKey` is 64 bits and a v6 address is 128, so a v6 origin is keyed by a hash of its **/64
prefix**, which is the block one host is actually delegated: keying the whole address would let a
single subscriber line mint 2⁶⁴ keys and walk through the per-source bound. Gated by `p2p_ipv6`,
`p2p_ipv6dual` and `p2p_ipv6filter`.

**What `_Dual` cannot do**, stated because the failure is deliberate: it cannot bind
`P2PeerConScope_Loopback`. `::1` is not the v4-mapped form of `127.0.0.1` — that is
`::ffff:127.0.0.1`, a different address — so one socket cannot bind both loopbacks, and `Listen()`
refuses the pair naming the two ways to spell it rather than silently narrowing to one of them.

A fifth is not on the list. Surveyed against these two seams, the embedded mesh
protocols mostly want a
`P2Peerio` codec on the serial transport rather than a transport of their own — while the
whole Thread/Wi-SUN/Matter family is blocked behind one missing thing, a datagram socket.

### Addressing

```text
[VNetname:]RootHubname.Hubname[i]. . .Hubname
```

Underneath, a `P2Paddr` is just a string — no hashing, no GUID, no registry lookup. All routing
meaning lives in the dots, expressed as three predicates:

| Predicate | Meaning |
|-----------|---------|
| `IsChild(a)` | `a` is a proper descendant — a prefix match that must end on a `.` boundary, so `CEXTRA` is *not* a child of `CEX`. |
| `IsRable(a)` | `a` is routable **down** through us — equal, or the same boundary-respecting prefix. |
| `IsMapped(a)` | A `P2Padomain` wildcard match, used to police what a peer may claim at login. |

> **Heads-up:** the `[VNetname:]` qualifier appears in the grammar and in the class layout but is
> **never parsed, read or written** anywhere in the tree. It is a placeholder from the original
> 2002 design. Reading the grammar at face value will mislead you — see
> [P2PeerHub.md](P2PeerHub.md) for the full autopsy.

### Priorities

Lower value wins. `P2PeerMsgQue` is a priority queue, not a FIFO.

| Constant | Value | Use |
|----------|------:|-----|
| `P2PeerPriFlush` | 0 | Reserved — cleaning out pending control sequences. |
| `P2PeerPriHigh` | 2 | Activities of greater importance. |
| `P2PeerPriNormal` | 7 | **The default. Stick to it** unless you have a reason — off-normal priorities create secondary ordering behaviour. |
| `P2PeerPriLow` | 12 | Activities of less importance. |

Maximum message size is `MAX_P2Psize` = 32768 bytes.

### Security

> ### ⚠️ On by default since 2026-08-18 — and a hub that cannot enforce it does not start
>
> TargetCore authenticates its peers and encrypts its traffic **by default**. `RequireAuth` defaults
> to **true**, and a hub that requires it and **cannot** enforce it **refuses to arm**:
> `CreateHub()` returns `FALSE`, `SpawnHub()` returns `0`, and the refusal names the file that is
> missing.
>
> **This reverses what this section said until 2026-08-18, and it is a breaking change.** The old
> default was opt-in and off, which meant a hub verified nothing unless somebody remembered to ask —
> so the deployments that most needed it were exactly the ones that never called `RequireAuth`. The
> gate moves that failure from the first peer's login, at 3am, to the deployment.
>
> **`RequireAuth(false)` is a supported answer**, not a defeat: a hub on a trusted segment, an
> in-process router, a test that is not about authentication. What is no longer possible is turning
> it off by *saying nothing*. Read this section before you deploy anything.

| Property | Status |
|----------|--------|
| Pre-login traffic blocked | ✅ Enforced, always. An application message arriving before login is discarded and the connection dropped. |
| Hub refuses to arm when it cannot enforce what it requires | ✅ **On by default since 2026-08-18, and widened on 2026-08-21.** A hub that requires authentication and holds no identity does not start, and says which file is missing. Without this the flip would have been worse than the old default: a hub that requires auth and holds no keys refuses *everyone*. **Seven reasons now, not five** — the two added are a missing revocation list and an unreadable one, and the advice and the file named follow the reason rather than always pointing at the allow-list. Covered by `p2p_armgate`, which includes both the `RequireAuth(false)` and `RequireRevocation(false)` opt-outs as required phases. |
| Peer **identity** verified | ✅ **On by default since 2026-08-18.** A login carries an ECDSA P-256 signature over its addresses, a nonce, a timestamp and the key-exchange transcript, checked against an allow-list. |
| Payload encryption | ✅ **On by default since 2026-08-18** — it rides on `RequireAuth`, and the two are one switch on purpose: a confidential channel to an unproven peer and a proven peer on a readable wire are each half an answer. **Since 2026-08-20 the transport is also required to USE the key**, rather than being trusted to because of the class it inherits from: a hub that requires authentication refuses to key a connection whose transport says its frames leave this process and that it will not consult the cypher, and refuses to write a frame that no sealing decision was recorded against. The in-process DMX transport declares itself exempt, and says why at the declaration. Gated by `p2p_confchannel`. |
| Message integrity / AEAD | ✅ Active wherever authentication is. A frame whose GCM tag fails raises `P2Pmsg_CypherEx` and drops the connection. |
| Proof bound to the channel | ✅ **On by default, and required at BOTH ends since 2026-08-20.** The login signature covers the key-exchange transcript, so a proof made for one connection is worthless on any other. Until 2026-08-20 only the *initiating* end treated that as one switch with `RequireAuth`; a verifier accepted a login signed with a **null** binding by a peer that had run no key agreement — an authenticated session in cleartext. Found by writing [THREAT_MODEL.md](THREAT_MODEL.md) (F-S6-1) and gated by `p2p_authchannel`. |
| Message source bound to the connection | ✅ **Enforced on every link by default since 2026-08-18**, including a link to an **ancestor**, which carried no source check at all before that. See below for what changed and what it still does not cover. |
| Replayed login or sealed body refused | ✅ **On by default since 2026-08-18.** A nonce cache plus a ±300 s freshness window for the login; the sealed body has its own cache. |
| Body hidden from an intermediate hub | ✅ **On by default since 2026-08-21, and it REFUSES rather than downgrades.** A message whose destination is not the peer on the far end of the link is sealed to that destination before it goes; a hub holding no agreement key for the destination **drops the message and says so** rather than sending the body in clear. That is the entire decision — a seal that quietly became cleartext when the directory was incomplete would be F-S6-3 again, a protection inherited rather than enforced. **The wire format moved 1 → 2 to make the default possible at all.** v1 sealed to exactly one reader, so on-by-default would have broken every deployment that needs an intermediate hub to read a body — content routing, filtering, store-and-forward. v2 encrypts the body once under a random content key and wraps that key once per reader, so a destination *and* the hubs the sender names can each open it. **Only the sender names them:** the reader set is bound into the body's additional data and the signed transcript, so no relay can add itself and no policy on a relay can add it. A v2 reader still opens a v1 body; a v1 reader refuses a v2 one, so a mixed mesh upgrades receivers first. Opt-out is `RequireSeal(false)`. Gated by `p2p_sealdefault` (7 phases), and the v1 read path is gated by `seal_interop` against bodies sealed on the other backend. **Broadcast is a separate answer, and since 2026-08-25 it is a separate switch.** A broadcast has an AUDIENCE rather than a destination: `On_P2PeerBCast` sends a copy per link and the scope those copies carry names a *subtree*, which no single agreement key opens. So a broadcast on a sealing hub is **refused**, every time, and `RequireSealBroadcast(false)` is how a deployment records that its broadcasts are not confidential — exempting fanned-out copies **only**, leaving relayed unicast sealed, and leaving the origin's attestation on the exempt copies, so they are unencrypted and still unforgeable. `TryReadPosture` reports it as `SealBcast`. **Confidential broadcast is not available and is an open design question.** The previous text here said sealing and broadcast "do not compose" because a broadcast could never be sealed and was therefore always refused; the second half was wrong in the worse direction — until the scope field, a broadcast was not refused at all, it crossed relays **in clear**, because the fan-out re-addressed every copy and the last-hop exemption could not tell it apart from a final delivery. Measured by `p2p_sealbcast`, 5 phases. |
| Revoked key refused | ✅ **On by default since 2026-08-21** — not the checking, which was always unconditional, but the *position*. A hub that requires authentication must either name a revocation list or say `RequireRevocation(false)`; one that does neither no longer arms, and the refusal names the revocation file rather than the allow-list. Still fail-closed where a list exists — one that will not load makes the hub refuse every peer rather than trust everyone, and since 2026-08-21 it refuses at **startup** instead of at the first login. Reloadable on a running hub. **This is the loudest break in the tree so far and it is deliberate:** step 8 refused a hub that would have refused everyone anyway, this refuses one that works. The argument for paying that is in `p2pauth::ArmResult` — rotation and the allow-list only ever *add* trust, so a hub with no revocation position cannot withdraw any. Gated by `p2p_armgate`. |
| Key exchange | ✅ Ephemeral ECDH P-256 → HKDF-SHA256 → AES-256-GCM, per connection, no negotiation — a security upgrade with a negotiation is one an attacker can decline. |
| Wire-framing bounds checks | ✅ The framing path is fuzzed in-process (`p2p_fuzzframe`: 3,618 frames a run, no crash, no hang) and, since 2026-08-15, **under AddressSanitizer** — which found four more out-of-bounds accesses on the receive path that the CRT debug heap could only report as damage with no writer. All four are fixed; **none was inside an `ASSERT`**, so all four were live in Release and merely undetected there. ASan-clean on the standing seed and on four fresh seeds, each baselined against the unfixed tree. **That sentence used to end *“one seed family and a fixed iteration budget is still coverage, not proof, and Linux has not been re-measured against these fixes”*, and both halves are now answered (2026-08-20).** The corpus is persistent and replayed by every gate run; the campaign is continuous - daily, on both platforms, seeded from the CI run number so it moves without becoming irreproducible; the frames span the receive ceiling as well as the ~2 KB band; and the four **authenticated** wire parsers now have their own harness, `p2p_fuzzblock`. A finding leaves a reproducer file rather than a log line. **And the assert population of Stage 1 step 4 — the last item that kept this row short of green — is CLOSED (2026-08-21).** The fuzz gate is back on `--strict-assert` with a budget of **zero on both platforms**, down from a tracked 89,901 on Windows and 1,044 on Linux. What closed it was not silence. The receive path was building its message from a pointer alone, which reaches the heap-create overload whose two block walks sit **inside `ASSERT()`** — so a Release build did not run a reduced structural check on a frame from an unauthenticated stranger, it ran none, and adopted the forged block chain unwalked. Stage 2 already knows how many bytes it put in the buffer; it now passes that length, and the image is adopted through the length-validated create, which walks it **in every build** and refuses on the answer. Alongside it the walks learned whose bytes they are judging: over a heap this process built a broken invariant is a bug here and `ASSERT` is right, over an image a stranger sent it is the ordinary case and the answer is to refuse — quietly, at the first bad block, and **without writing the image's own root back into agreement with itself on the way past**, which is a validator editing the bytes it was asked to judge. **The number that shows it is a fix rather than a mute:** on the same 3,618 frames, a Release build used to turn **550** of them into messages and now refuses all but **246** — 304 forged frames on Windows, 303 on Linux — and Debug and Release now agree frame for frame where they used to differ by two. On Linux the depth figure went from **71.2% to 100%**: 1,041 inputs that the POSIX assert trap used to abandon mid-parse now run to the end and are refused on the merits. Falsified by reverting the one line and watching the gate go red on both platforms (89,919 and 1,041). **And a new `security` test, `p2p_framegate`, pins it where the fuzz gate cannot (2026-08-22):** an assert budget can only go red in a Debug build, and this defect was a Release-only one, so `p2p_framegate` states the same two properties without spelling either of them with an `ASSERT` - what the length-validated path refuses the receive path must refuse, and a refused image must be byte-identical to what arrived. Both were proven red in a *Release* build before they were believed. Suites green in both configurations on both platforms: **45/45 Windows, 48/48 Linux**, and the `security` label **29/29 under ASan on Windows and under ASan+UBSan+LSan on Linux** (the figures for that day's tree, kept as the verification of *this* fix rather than refreshed — four tests have joined since, and the current totals are in the two-totals paragraph under *Supported platforms*) - which matters here because the fix makes a Release build walk a chain it used to skip, so those are paths no shipped binary had run before. |
| Posture readable from a running hub | ✅ **New 2026-08-20.** The hub's snapshot carries `AuthRequired`, `AuthCanSign`, `AuthArm`, `RelayAuth`, `RelayReplay`, `SealReplay` and — since 2026-08-21 — five revocation fields, the new one being `RevocReq`, which is intent where the other four are capability: `RevocList=0` alone cannot say whether a hub has no list because nobody provisioned one or because `RequireRevocation(false)` said so, and those are a misconfiguration and a decision; a connection's carries `AuthDone`, `AuthPeer`, `KeyXDone`, `Cypher` and — since 2026-08-20 — `OffProcess`, which is what makes `Cypher=0` readable: on a wire it is a defect, on the in-process DMX handoff it is correct, and until the pair existed no snapshot could say which. Intent, capability and enforceability are separate fields on purpose — for two days *“this hub requires authentication”* and *“this connection is encrypted”* were different facts on the same hub and nothing inside the process or outside it could have reported it. Gated by `p2p_authposture`. |
| Misconfiguration warnings actually reach the operator | ✅ **New 2026-08-20, and it is a behaviour change for every existing host.** The default diagnostic notification mask is now `ERROR|WARNING`; it was `ERROR` alone, which meant every `EVWRN->…->Display()` in these repositories formatted its message, formatted its advice and **emitted nothing**, on every build. Three warnings become visible and all three are operator misconfigurations that carry their own fix: a relay attestation that could not be signed, a peer signing logins to a hub that does not require them, and `P2PeerioBSTR` — the transport that carries cleartext — being constructed. Volume is not a concern and that is by construction: all three report through `SetLast()`, so a misconfigured hub costs one line **per connection**, not one per message. Found by writing a gate for something else and watching it not fire (F-S6-4). Opt out with `P2Pevent::Configure(P2PeventCfg_REMMASK, P2Pevotn_WARNING)`; recorded as an unreleased break. |
| Legacy `DHKeyXChanger` / `Rijndael` | 🗑️ **Deleted.** Non-functional and cryptographically broken; removed from the tree rather than left to mislead. |
| Independent security audit | ❌ Not done. An internal review and a written [threat model](THREAT_MODEL.md) exist, with open findings. |

**Two rules apply whether or not you configure anything.** `P2PeerCon` refuses application messages
until the connection has completed login, and it rejects any message whose source address is not the
identity that connection logged in as — or a descendant of it, so a hub can still relay for its own
sub-targets. Both drop the connection on violation, and both are covered by tests.

**The second rule had a documented hole, and this README once claimed it did not.** A connection to
a peer *at or above* this hub in the address tree was admitted with **no source check at all**. That
was not an oversight: an ancestor is the hub's gateway to the rest of the tree, so a message routed
down from it legitimately carries a source from any other branch, and refusing those made downward
transit and multi-hop broadcast impossible. The address alone cannot tell that apart from the parent
inventing the source.

**`RequireRelayAuth` closes it, and it is ON by default since 2026-08-18.** What was missing was
never a better predicate — it was evidence. With relay attestation on, a message admitted down an ancestor link must
carry a signature made by the **origin's** identity key, covering both addresses, the message name and
a digest of the body; the relaying ancestor does not hold that key, so it can forward the message but
cannot forge it or edit anything the receiver acts on. The same at-or-below test then applies to the
identity that *signed* rather than to the peer that *delivered*, so the rule is not excepted on this
link, only bound against a different and provable thing. Both ends need configuring and not
identically: the origin needs an identity to sign with, and the receiver needs that origin in its
allow-list — and **only the hub that verifies** needs the origin listed, which is the fact that made
on-by-default possible and which the paragraph this replaced assumed the other way round. Note what
the rule never covered in either mode: a peer may always speak
for its own subtree, and this hub is *inside* its parent's, so a parent has always been able to claim
its children's addresses. Links to a **descendant** and to an **unrelated** peer are checked exactly
as described above, in both modes.

Covered by its own test (`p2p_authancestor`), which until 2026-08-14 was the only one in the suite
asserting a *gap* rather than a protection. It now asserts both: a genuinely attested cross-branch
message relayed down through two hubs and admitted, the relaying parent claiming that same source
without a signature and being refused, and the pre-2026-08-18 behaviour still being exactly what
`RequireRelayAuth(false)` gets.

**Provisioning a hub** takes two calls, before `SpawnHub()`/`CreateHub()`. There is no third:
`RequireAuth(true)` is the default, and a hub that reaches `SpawnHub()` without these two does not
start.

```cpp
    oHub.SetIdentity  ( "/etc/p2p/peer.key", /*create if absent*/ true );
    oHub.SetAllowList ( "/etc/p2p/peers.allow" );
```

The login then carries a signature over its addresses, a nonce, a timestamp and the key-exchange
transcript, and the session cypher comes on with it — the two are one switch on purpose, because a
confidential channel to an unproven peer and a proven peer on a readable wire are each half an
answer, and since 2026-08-20 the **verifying** end enforces that too rather than trusting the
initiator to have run the exchange. Peers need loosely synchronised clocks: a login more than
±300 s out is refused.

**Turning it off** is one call and it has to be deliberate: `RequireAuth(false)` before arming. That
is a supported configuration; what it is not is a default.

**With `RequireAuth(false)`, the old exposure stands, and it is worth stating plainly** — an
*unconfigured* hub no longer reaches this state, because it does not start at all. Without an allow-list
the only restriction on a claimed address is the domain — for `P2PeerConWsa` the `ServiceFactory`
peer argument doubles as the pattern a peer's address must match — and a domain is a *wildcard*. A
service expecting exactly one peer is genuinely tight; a service accepting many needs a broad
pattern, and then every peer matching it may claim every address matching it. In that configuration,
treat the address as *proof of nothing and a routing key for everything*.

**The session cypher protects one hop, not the whole path.** A hub decides where a message goes from
its destination address, so an intermediate hub necessarily decrypts what it forwards — a hub that
could not read the frame could not route it. Where the body must stay hidden from the hubs carrying
it, seal it to the destination instead:

```cpp
    oHub.SetAgreementKey ( "/etc/p2p/peer.agree", /*create*/ true );
    oHub.SealFor ( L"Me", L"Them", pBody, cbBody, pOut, cbOut, &cbSealed );
```

That costs 156 bytes per message and leaves the addresses in clear so routing still works. It is
independent of `RequireAuth` — the two compose, and neither substitutes for the other.

**The crypto is `P2PCngCrypto`:** AES-256-GCM (AEAD), ECDH and ECDSA on NIST P-256, and HKDF-SHA256,
over **CNG/BCrypt** on Windows and **OpenSSL 3** on Linux, wire-compatible between the two and
covered by cross-backend known-answer tests.

**The legacy crypto has been deleted.** `DHKeyXChanger` (Diffie–Hellman over the `Buint`
big-integer type) and `Rijndael` predated the modernisation and were never reachable — neither
class was constructed anywhere in the tree. Their defects are recorded here rather than in the
source, so nobody re-adopts them: a composite 256-bit modulus, private exponents drawn from
`srand(time(NULL))`/`rand()`, peer public-value validation commented out, and no authentication of
the exchange. The code is in git history if it is ever wanted.

`Buint` itself followed on **2026-08-24**. It outlived the two classes above by a few months
because it is a general-purpose big-integer type and deleting it was a separate decision from
deleting the crypto that used it. By then nothing in the tree called it but its own
`Buint_Test_*` self-tests, while `Buint::Random` still carried the `srand(time(NULL))` this
paragraph condemns — so every reader who grepped `srand` over a library whose live crypto is
CNG/OpenSSL found it and had to be told it did not matter. It was exported, so its removal drops
symbols from the DLL export table; nothing in the tree imported them.

**Deploy accordingly.** A hub running with `RequireAuth(false)` belongs on loopback, a trusted LAN
segment or an attached hardware bus, and nowhere else. A hub with `RequireAuth(true)`, a provisioned identity and
a reviewed allow-list is a different proposition — but it has had no independent audit, so if you
put it in front of hostile traffic, put it inside a tunnel that has: WireGuard, IPsec, or a TLS
wrapper, with the listening port firewalled to known peers.

See **[SECURITY.md](SECURITY.md)** for the full posture, the hardening checklist, and how to
report a vulnerability privately.

See **[THREAT_MODEL.md](THREAT_MODEL.md)** for the analysis behind that posture — the adversaries
each protection answers, what is deliberately out of scope and why, and the gaps the mapping found.

---

## Requirements

Familiarity with Win32 overlapped I/O and completion ports will help a great deal — the pump
model is IOCP end to end. See [Architecture(IOCP).md](<Architecture(IOCP).md>).

**Windows (authoritative build)**

- Visual Studio 2026, platform toolset **v145**
- C++23 (`/std:c++latest`), C17
- MFC (built as a **dynamic MFC extension DLL**, `_AFXEXT`)
- Windows SDK 10 — links `ws2_32`, `MsWsock`, `Propsys`, `comsuppw`, `bcrypt`, `ncrypt`
- Minimum target: **Windows 8.1**. Pinned deliberately: `P2PCngCrypto` derives the ECDH shared
  secret with `BCRYPT_KDF_RAW_SECRET`, which `bcrypt.h` gates on `NTDDI_WINBLUE`.

**Linux (ported from Windows, not the reference)**

- GCC/Clang with C++23
- **liburing** — the io_uring implementation of the `p2p_iocp_*` hooks
- **OpenSSL 3** (libcrypto) — the crypto backend

**Not vendored, required at build time**

> TargetCore is one component of a larger solution. It needs two sibling trees that are **not in
> this repository** — `..\Msgcore` and `..\Platform`. A standalone clone does not compile: every
> translation unit includes `stdafx.h`, and `stdafx.h` includes `..\Platform`. See
> [The sibling dependencies](#the-sibling-dependencies) for exactly where each binding is.

---

## Supported platforms

| Platform | Arch | Build system | Crypto | Async I/O | Status |
|----------|------|--------------|--------|-----------|--------|
| Windows 11 / 10 / 8.1 | x64 | `TargetCore(2026).sln` | CNG / BCrypt | IOCP | ✅ **Stable** — the reference build |
| Windows 11 / 10 / 8.1 | Win32 | `TargetCore(2026).sln` | CNG / BCrypt | IOCP | ✅ Stable |
| Windows | x64 / Win32 | CMake | CNG / BCrypt | IOCP | ✅ **Signed off 2026-08-22 — at parity for what this build is scoped to produce: the two cores, `p2pplatform`, and the whole test suite.** This row was yellow until that date, and the last thing holding it there was not a defect but an unmade decision, which is a different status and should not be spelled the same. **Green here does not mean CMake replaces the `.sln`** — the `.vcxproj` is kept for the MFC UI projects permanently, and the staging paragraph below says exactly which builds still do not meet. The artifacts were **diffed rather than asserted (2026-08-22)** — `dumpbin -exports` on the CMake-built and `.vcxproj`-built DLLs gives **1,009 exports, name-for-name identical, in Debug AND Release**; the dependency sets are identical too (dynamic MFC `mfc140ud`, `bcrypt`, `ws2_32`/`mswsock`), and the version resource matches to the field — same `0.10.0.0`, same company, same `InternalName`. Suite: **45/45 in both configurations** — the 45 that existed on that date. **Re-measured 2026-08-28: the tree now registers 52 and Debug measures 52/52. Release has not been re-run since 2026-08-22**, so the figure beside it is not a current total; the two-totals paragraph under *Supported platforms* names the seven tests that moved it and why. **The configurations gap closed on 2026-08-22, and closing it found two defects that had been shipping.** `windows-msvc-x86` builds Win32 and `windows-msvc-lib` builds `msgcore_static`/`targetcore_static` — the `.vcxproj` `DebugLib`/`ReleaseLib` shape, read out of the project files rather than guessed. Win32 measures **45/45 in Debug and 45/45 in Release**, the same 45 as x64. It did not start there. **The first suite ever run against a 32-bit build failed 3 of 45 in both configurations**, and the cause was memory corruption in `Msgcore`: `P2PmsgVect_SizeofItem` allocated the item block by one rule and `P2PmsgVect_InitItem` laid it out by another, sizing the name at **27** bytes on Win32 where the layout wrote **127** — so the `VBLockData` landed past the end of its block. x64 was never wrong because there both rules already answered 127; the pass was luck, not correctness. **The second defect was in the static arm.** `P2PCngCrypto.h` guarded its export macro as `_WIN32 && !TargetCore_STATIC`, so a Windows static build fell through to the GCC branch and MSVC was handed `__attribute__((visibility("default")))`. That arm had never been compiled by anything — **the `.vcxproj`'s own `DebugLib`/`ReleaseLib` configurations could not build this header either, which is 4 of the 8 configurations the `.sln` declares**, verified by compiling `DebugLib|x64` directly before and after the fix. **What the static targets do not claim:** they compile and archive, and the `.sln`'s `DebugLib|x64` compiles again — but **no test links against either archive**, so nothing exercises a `TargetCore_STATIC` consumer end to end. Given that the two configurations nobody exercised each turned out to be hiding a live defect, read that as an open question rather than a formality. **The one thing green does NOT cover, stated plainly because a green row invites the assumption. Staging:** `Directory.Build.props` puts import libraries under `$(WDMSCS_LIB)\$(Platform)\$(Configuration)` and a `CustomBuildStep` copies the DLLs to `bin\<Config><Arch>`, which is where every downstream consumer resolves; CMake installs into a `GNUInstallDirs` prefix instead. **So a `.sln`-built consumer — the MFC UI projects, the facades, both `_UseExamples` trees — still loads `.vcxproj` output, not this build's, and that is by design rather than by omission.** The line between the two build systems is **product versus verification, not Windows versus Linux**: the `.vcxproj` owns the Windows product and its delivery, this build owns verification on both platforms plus the Linux product, and verification does not write into a delivery tree. An `MSCS_STAGE_TO_BIN` switch existed for a few hours on 2026-08-22 and was removed the same day; the argument against it — including why calling the `.vcxproj`'s own copy script is necessary but not sufficient, since the import library is placed by the linker rather than copied by any script — is recorded in `..\CMakeLists.txt` under "WHY THERE IS NO STAGING STEP HERE". Green means the cores and the suite are at parity and proven so. It does not mean the deployment tree changed hands, and it is not waiting to. **What is NOT a reason, and was wrongly listed as one here until 2026-08-22:** the 120 `.vcxproj` against 13 `CMakeLists.txt`. CMake is scoped to the cores, `p2pplatform` and the test suite, and the `.vcxproj` is "kept only for the MFC UI projects" after sign-off. The facades, COM layers, MFC GUIs, `Chartboard`, `P2PmsgPython` and both `_UseExamples` trees having no CMake is the declared scope, not a shortfall, and a row held to a bar the project decided not to clear can never go green. (One item that was written off as cosmetic is also closed, and it was not cosmetic: the CMake targets now carry `OUTPUT_NAME` and produce `Msgcore.dll`/`TargetCore.dll` rather than lowercase. On a case-insensitive filesystem a staged `targetcore.dll` **is** the `.vcxproj`'s file, so it would have overwritten the reference build's DLL while appearing to add one — harmless right up until staging exists, which is the very next thing on this list.) **A finding from taking this measurement, which is about the authoritative build rather than the new one:** the `.vcxproj` Release x64 link **failed** on `P3PmsgBSTR::P3PmsgBSTR(VBListIOmage*, unsigned __int64)` — one of the length-carrying constructors Stage 1 step 4 added on 2026-08-21 — because `TargetCore(2026).sln` contains **one project** and links against a prebuilt `lib\x64\Release\Msgcore.lib` that was a day stale. The CMake tree was immune because it compiles Msgcore from source. Rebuilding Msgcore Release x64 fixed it, and both DLLs above are from after that. **The reference build is the one that can be silently a day behind its sibling.** |
| Linux | x86-64 | CMake | OpenSSL 3 | io_uring | ✅ **Signed off 2026-08-22 — green for what this build is scoped to be on Linux, which is both the product and the verification.** "Green, not the reference" is kept, because it is true and worth saying — but it is a **statement of scope, not a deficiency**, and it should not be spelled in the pending colour. This row said "Green" in its own first two words while its status glyph said "pending", and that disagreement is the same defect the Windows row above was corrected for on the same day. **Re-measured 2026-08-22, and reported as two runs rather than one, because they are not the same measurement.** Ordinary `linux-gcc-debug` with `MSCS_BUILD_STATIC_LIBS=ON`: **49/49** — the default 48 plus `p2p_staticlink`. Sanitised `linux-gcc-asan` (ASan+UBSan+LSan): **48/48**, with the whole **29**-test `security` label passing and nothing in that label excluded. **Both figures are that day's tree.** **`linux-gcc-debug` was re-measured on 2026-08-28 at 55/55**, with the `security` label — now **35** — passing 35/35, on Ubuntu 26.04 / gcc 15.2 / liburing 2.14 / OpenSSL 3.5.5. **The sanitised configuration was re-run the same day and stands at 53/54** under `detect_leaks=1:halt_on_error=1:abort_on_error=1` — 54 rather than 55 because `p2p_installtree` deregisters itself in a sanitised tree, by the note in `TargetCore/CMakeLists.txt`. That run is what found the `StartupP2Pmsg()` leak. **The one remaining failure is an intermittent that is NOT this work's**, and it is named rather than rounded away: a **different one** of `p2p_authchannel` and `p2p_confchannel` aborts on each full sanitised run and both pass in isolation. The stack is a `P2PeerMsg` the test posts from its own login-ack handler and that the pump never drains before `CloseHub` — a teardown race, the same class as `BUGFIXES.md` item 2 (*undispatched messages leaked at teardown*), which closed that hole for the sink path and not for a posted connection message. Both tests call `StartupP2Pmsg()` exactly **once**, so the guard added to it that day takes the same branch it always did and cannot reach them. **Open, unfixed, and outside the change that found it.** Getting to 55/55 took three fixes for defects that predate the work being measured, all named in the two-totals section under *Supported platforms*: `P2PeerConWsa.cpp` did not compile here at all, `p2p_listenscope` could not find this host's own address by the Windows convention it was using, and `run_alex_test.sh` was checked out CRLF. The sanitised figure was taken with `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1` and `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, **because the defaults let a leak or a UBSan finding exit 0** — a sanitiser gate run at its defaults can report green over both. **The two totals differ by exactly one test, and the reason is in the build file rather than in the result:** `p2p_installtree` is deliberately not registered in a sanitised tree (`CMakeLists.txt`, the note above the `sanitize` guard), because its consumer is a separate CMake project built without `-fsanitize` and a binary carrying no ASan runtime cannot link libraries that carry one. The install *rules* are identical either way, so nothing is lost. **Three things used to hold this row short of green, and all three were examined rather than waited out.** *"CMake is not yet authoritative" is void* — its stated premise was that CMake-on-Windows was still parity-in-progress, and that row was signed off the same day; meanwhile the root `..\CMakeLists.txt` has said the opposite all along, that the `.vcxproj` are authoritative for the Windows **product** and that file is authoritative for **Linux**. Linux has no second build system to defer to, so no amount of work could ever have satisfied this item; it was a category error, not a gap. *"The SCM layer is a no-op" is declared scope, and its Linux replacement is tested* — the port splits `P2PeerService` deliberately: SCM install/uninstall/status compile Windows-only, and the protocol-neutral console path **becomes** the Linux daemon entry. `../Msgcore/Platform/p2psvc.h` supplies the WinSvc types and constants so the 1026-line legacy `.cpp` compiles unmodified, and `StartServiceCtrlDispatcher` returns FALSE so control falls through to `Run()`. **That fall-through is not an unexercised arm**, which matters because unexercised arms have now cost this project two live defects in one day: `p2p_daemon_harness` drives construct → post hub → `SpawnHub` → `OnStop` → `CloseHub`, and `p2p_servicedialog` asserts the no-dialog rule, both green on Linux in both runs above. *"The substrate is re-implemented rather than shared" is permanent, and it is exactly what "not the reference" already means* — 4,447 lines of `../Msgcore/Platform`, with the IOCP pump an io_uring shim, the MFC layer a header shim, and crypto a second implementation. It is **pinned rather than trusted**: `golden_utf16_bytes` compares the Linux-built serialised heap image byte-for-byte against the checked-in Windows reference, `crypto_kat` runs the OpenSSL known-answer vectors, and `seal_interop` fails if a Windows peer and a Linux peer cannot read each other. **What green does NOT cover, stated plainly because a green row invites the assumption:** there is no init-system integration. `sd_notify` is optional and appears nowhere in the tree — so a Linux daemon runs correctly and simply never tells systemd when it is ready. That is a missing convenience with a named owner rather than a failing gate, and it is the one honest open item left on this row. **The `66/66` and `27` this row used to carry are not wrong, they are a different tree on an earlier day** — 2026-08-21, before Stage 3 steps 19 and 20, in a tree that also configured the external suite. The fuzz depth was a fourth blocker until 2026-08-21 and is closed. |

**What "not the reference" means, now that the colour no longer says "pending".** The Linux tree has
been green since 2026-08-20, and green again on 2026-08-22 under an ordinary build and a sanitised
one — so "port under way", which this row said until 2026-08-21, was out of date, and "a pending
decision", which its colour said until 2026-08-22, was out of date as well. **The row has now twice
carried a caveat that had outlived the thing it warned about**: first that the figure had not been
re-taken since Stage 3 steps 19 and 20, when it had been, four sections above in this same file;
then that three named items held it short of green, when one of them had been void since the Windows
row was signed off and the other two were decisions this project had already made and written down.
A caveat that outlives its cause is the same defect as a stale number, and it is the harder of the
two to see, because it reads as caution rather than as error. **"Not the reference" survives all of
that and still means something exact:** Windows is where a behaviour is defined and Linux is where it
is reproduced, so when the two disagree the Windows answer is the specification and the Linux one is
the bug. That is a statement about which tree arbitrates, not about which tree passes.

**Two totals in this document count different things and neither is wrong.** The Windows tree
registers **52** tests and measured **52/52 in Debug on 2026-08-28**. The Linux tree registers
**55** and measured **55/55 in `linux-gcc-debug` on the same day**; the extra three are
`com232_mesh`, `crypto_kat` and `platform_iocp_test`, Linux-only by construction, so the Windows
set is a strict subset rather than a shortfall. The `security` label is **35 on both, 35/35 on
both**.

**Where the seven since 2026-08-22 came from, because a count that moves without a reason is
drift.** The figure was 45 and 48, measured in both configurations on that date. `p2p_sealbcast`
joined after it and **this paragraph was not updated**, which is the one movement here that nobody
recorded at the time — it is named now rather than absorbed into a larger number. Three landed on
2026-08-27 and 2026-08-28: `p2p_listenscope` and `p2p_acceptfilter` for the listen scope and the
accept allow-list, and `p2p_resolve` for the client-side resolver defect described under *Same hub,
different wire*. Three more landed on 2026-08-28 with the dual-stack port: `p2p_ipv6` for the
transport and the v6-only half of `IPV6_V6ONLY`, `p2p_ipv6dual` for one socket serving both
families, and `p2p_ipv6filter` for an allow-list meaning the same thing on a v4 socket and a dual
one. One gate per finding or decision, so the count has moved for a reason every time rather than
by drift.

**What has NOT been re-measured, stated because the figures above are the kind that get carried.**
**Windows Debug**, **`linux-gcc-debug`** and **`linux-gcc-asan`** were all run on 2026-08-28 —
52/52, 55/55 and 53/54 respectively, `security` 35/35 on the first two. Only Windows **Release**
still carries its 2026-08-22 answer, taken before any of these seven tests existed, so the right
reading of it is *45 of the 45 that were there then* rather than a current total. All seven new
tests are registered unconditionally — none sits inside a `NOT WIN32` guard — so the registration
counts hold everywhere; it is that one configuration's pass/fail that is unmeasured. The sanitised
54 is 55 minus `p2p_installtree`, which deregisters itself in a sanitised tree by design, and its
one failure is a pre-existing intermittent named in the Linux row below.

**The Linux run was not a formality and should not be read as one — it found FOUR things, three of
them in code that predates the dual-stack work and two of them gates reporting nothing while
looking like they agreed.** (i) `P2PeerConWsa.cpp` **did
not compile on Linux at all**: the allow-list prefix parser added 2026-08-27 was written against
`CStringA::Find`/`Mid`/`Left`/`Trim`/`operator[]`, none of which `../Msgcore/Platform/p2pstr.h` carries. Ten
errors in the file that owns the transport, unseen because nothing had built it there in between.
(ii) `p2p_listenscope` **could never have run on Linux**: it located this host's own routable
address by resolving `gethostname()`, which is a Windows convention — Debian and Ubuntu write
`127.0.1.1 <hostname>` into `/etc/hosts`, so on a VM sitting on a live 192.168.1.x interface the
lookup returned loopback and the gate reported SETUP and skipped itself. It asks the routing table
now (a UDP `connect()` to RFC 5737 TEST-NET-1, which sends nothing, then `getsockname()`), and
passes there for the first time. (iii) `run_alex_test.sh` was **checked out CRLF**, so `bash` read
the trailing carriage return as part of every command and `alex_test` died in a heap of `command not
found`. `.gitattributes` already pins `tools/hooks/*` to LF and argues why — *a hook that cannot run
is a hook that silently permits every push* — and `*.sh` is now pinned for the same reason applied
to a gate. (iv) **The sanitised run found a leak in `StartupP2Pmsg()` itself**, and it is the one
finding here that is in the library rather than the harness: that function initialised
`s_oCSectionP2Pmsg` unconditionally while setting the very flag that says it need not, so a second
`StartupP2Pmsg()` — which the note above `CleanupP2Pmsg()` explicitly permits — overwrote the
pointer and orphaned the first mutex. `CleanupP2Pmsg()` deliberately does *not* delete that one:
unlike the Hub and Pump sections beside it, it is **process** lifetime, guards the sink registry,
and has a lazy-init path that can raise it before any environment exists. On Windows a
`CRITICAL_SECTION` is a plain struct and this cost nothing observable; on Linux
`../Msgcore/Platform/p2pthread.h` allocates a `std::recursive_mutex`, so **every startup/shutdown cycle
leaked 40 bytes**. The three gates that caught it — `p2p_ipv6`, `p2p_listenscope` and `p2p_resolve`
— are the only tests in the suite that stand a hub up and tear it down more than once, which is why
nothing else has ever shown it. All three passed their own assertions first; LeakSanitizer fired at
exit. **All four predate the dual-stack work and none is in it.** What the work did was cause the
file to be compiled, the suite to be run, and the sanitisers to be pointed at the platform that
could see them.

**The one IPv6 assertion that only Linux could ever have checked now passes there.** `IPV6_V6ONLY`
defaults **on** on Windows and **off** on most Linux distributions, so "a v6-only service refuses a
v4 client" is free on the platform this was written on and fails on the platform it was not —
unless `Listen()` sets the option explicitly, which it does. `p2p_ipv6` reports
`IPv6 family, 127.0.0.1 : refused (expected)` on Ubuntu 26.04 / gcc 15.2. That line was an argument
until 2026-08-28 and is a measurement now. The Windows
Debug run was taken in a tree that also configures `P2PeerWeb`, whose five tests were excluded to
match the four-repository shape this paragraph describes; four of them fail there on a missing
DLL search path in that project's own ctest wiring, which predates this work and is unrelated to
it. **The `66` this paragraph used to quote came from a
tree that also configured `MscsUnitTestsExternal`, and `MSCS_BUILD_EXTERNAL_TESTS` — named here as
the switch that turns it off — is not in any build file**: those suites are built from their own
directory and there is deliberately no switch (`CMakeLists.txt`). **The `security` label
is 35 on both**, and it is the only figure in this paragraph that is checkable without saying which
tree: `grep -c "LABELS security" ../MscsUnitTests/CMakeLists.txt`, the sibling tree that owns the gates. The label is
the number to compare when comparing platforms — a total is a statement about a build tree and the
label is a statement about the code. Say which tree a figure came from, because this file has three
times carried totals that disagreed while all of them looked current. What still separates it from the Windows build is not failing tests:

- **Two of the three substrates are substitutions, not the same code.** The IOCP pump is an io_uring
  shim (`../Msgcore/Platform/p2piocp.cpp`, compiled straight into the library on Linux only,
  `CMakeLists.txt:108`) and the MFC layer is `../Msgcore/Platform/mfcshim.h`. Crypto is a **second
  implementation** — which is why `crypto_kat` and `seal_interop` exist as Linux-only gates: the login
  transcript and block layout *are* the wire, so a byte of drift between the CNG and OpenSSL backends
  is a login that works only within one operating system. This is permanent and by design, and it is
  what "not the reference" means — but it is **pinned rather than trusted**: `golden_utf16_bytes`
  compares the Linux-built serialised heap image byte-for-byte with the checked-in Windows reference,
  so substrate drift fails ctest instead of reaching a peer.
- **`P2PeerService` is shimmed to a no-op, and that is the plan's design rather than a shortfall.**
  §6.2 splits it: SCM install/uninstall/status compile Windows-only, and the protocol-neutral console
  path becomes the Linux daemon entry — `../Msgcore/Platform/p2psvc.h` returns FALSE from
  `StartServiceCtrlDispatcher` so control falls through to `Run()`, which lets the 1026-line legacy
  `.cpp` compile unmodified. The Linux path that replaces it is covered by `p2p_daemon_harness` and
  `p2p_servicedialog`, both green here. **The genuinely absent piece is `sd_notify`**, which §6.2
  marks optional and which is in no file in the tree: the daemon runs, and never signals readiness to
  the init system.

**Two more items stood on this list and neither does now.** The third was "the build system underneath
it is not authoritative", struck on 2026-08-22 as **void rather than done**: its premise was that CMake-on-
Windows was still parity-in-progress, that row is now signed off, and `../CMakeLists.txt` already makes
the `.vcxproj` authoritative for the Windows product and this file authoritative for Linux. The fourth was
the fuzz depth, and it closed on 2026-08-21. glibc's `assert`
calls `abort()`, so the harness used to *abandon* an asserting input where Windows continued past it:
measured on 2026-08-20 the two platforms reported **89,901** and **1,044** asserts for the same 3,618
inputs, and Linux finished only **71.2%** of them. The assert budget is now **zero on both platforms**
and Linux runs **3,618/3,618 — 100%**, so there is no depth gap left to warn about. What closed it was a
Release-only defect on the receive path, not Debug-only noise — see [Security](#security).

---

## Building

### The sibling dependencies

Expected layout — one sibling, a peer of this directory, not a submodule:

```text
<parent>\
├── Msgcore\      ← headers + Msgcore.lib / Msgcore.dll
│   └── Platform\ ← platform.h, mfcshim.h, p2piocp.cpp, p2psvc.h
└── TargetCore\   ← this repository
```

`Platform\` was its own repository, and a second peer here, until 2026-09-03. It was
retired and its tree vendored into Msgcore, so there is one sibling to check out
instead of two, and the shim layer arrives with it. Nothing else about the coupling
changed: the same headers, the same single `.cpp`, one directory deeper.

There are **four** distinct bindings, and they fail in different ways:

**1 · Compile-time — four `Msgcore` headers, included by bare name**

Resolved by `<AdditionalIncludeDirectories>..\Msgcore</AdditionalIncludeDirectories>`
(`TargetCore(2026).vcxproj:198`, and :242, :284, :324, :393, :424, :457, :485 — one per
configuration, and there are eight of those, not four).

| Header | Included from | Weight |
|--------|---------------|--------|
| `P2PmsgBSTR.h` | `P2PeerMsg.h:30` | **Structural.** `P2PeerMsg` derives from `P3PmsgBSTR`, and the on-the-wire frame — `P2Piomage` — is a Msgcore type allocated by Msgcore. |
| `Msgexception.h` | `P2PeerMsg.h:29`, `P2PeerCon.h:39`, `P2PeerEvents.h:29`, `TargetCoreLog.h:20`, + 5 `.cpp` | The `P2Pevent` logging/exception system. Pervasive (~950 references) but shallow — the same handful of macros. |
| `Kernel32_Ext.h` | `P2PeerHub.cpp:26`, `P2PeerCon.cpp:22`, `P2Pwin32.cpp:18`, `P2PeerMsgQue.cpp:22`, `P2PeerioDmx.cpp:23`, `P2PeerConDmx.cpp:23`, `P2PeerExplorer.cpp:25` | Four exported RAII wrappers (`P2PsafeCS`, `P2PsafeHANDLE`, …). Implementation-only. |
| `MsgCollectors.h` | `P2PmsgMaps.h:25` | `P2PSafePtr` / `P2PSafeLock` templates. Header-only — no link dependency. |

> The first two, and `MsgCollectors.h` via `P2PmsgMaps.h` (itself pulled in at
> `P2PeerTarget.h:29`), are reached through **public** headers — the ones a consumer includes. So
> `..\Msgcore` has to be on the include path of **anything that uses this library**, not just of
> this project.

> The dependency is not "Msgcore packages, TargetCore ships raw bytes." `P2Piomage`
> (`Msgcore\P2PmsgBSTR.h:54-69`) is a packed sync-header frame defined by Msgcore and allocated
> by `Msgcore_EXT P2Piomage_Alloc`; `PrepareP2Piomage()` is inherited, and its call sites are
> commented `// Mandatory`. Msgcore defines the frame; TargetCore encrypts and moves it.

**2 · Compile-time — the `Platform` shim, hardcoded in `stdafx.h`**

Not in the project file at all. `stdafx.h:32` and `:38`:

```cpp
#include "../Msgcore/Platform/platform.h"   // Win32: passthrough to WinSock2/ws2tcpip/mswsock/atlstr
#include "../Msgcore/Platform/mfcshim.h"    // Linux: CObject/CList/CMap/CString/ASSERT
```

An explicit relative path out of the project directory, on **both** platforms. Every TU includes
`stdafx.h`, so `..\Msgcore\Platform` is as mandatory as `..\Msgcore` — and invisible to anyone
reading only the `.vcxproj`. Since the shim moved inside Msgcore this is no longer a *separate*
checkout, only a separate include: binding 1 already puts `..\Msgcore` on the include path, and
this path reaches through the same directory it names.

**3 · Link-time and run-time — `Msgcore.lib` / `Msgcore.dll`**

`Msgcore.lib` heads the linker inputs at `TargetCore(2026).vcxproj:206` (and :248, :291, :329),
alongside `MsWsock.lib`, `ws2_32.lib`, `comsuppwd.lib`, `Propsys.lib`. It is found through
`<AdditionalLibraryDirectories>$(WDMSCS_LIB)</AdditionalLibraryDirectories>` (`:208`) — an
**environment variable**, not a relative path, which is why an unset `WDMSCS_LIB` produces an
opaque LNK failure. `Debug|x64` additionally prepends a literal `..\Msgcore\x64\DebugLib`
(`:250`). As the platform-floor block in `TargetCore_version.h` puts it: *"TargetCore links Msgcore.dll"* — so `Msgcore.dll`
must also sit beside `TargetCore.dll` at run time.

**4 · CMake — the same three, declared plainly**

| Line | Binding |
|------|---------|
| `CMakeLists.txt:113-115` | include directory `../Msgcore` |
| `CMakeLists.txt:123` | `target_link_libraries(targetcore PUBLIC msgcore $<BUILD_INTERFACE:p2pplatform>)` — targets the parent solution defines. `p2pplatform` is build-interface only because it contributes no binary and an installed consumer needs none of its headers |
| `CMakeLists.txt:108` | Linux only: compiles `../Msgcore/Platform/p2piocp.cpp` straight into this library |

### Windows — Visual Studio (authoritative)

```bat
:: with Msgcore and Platform already checked out alongside
set WDMSCS_LIB=<path where the import libraries are collected>
msbuild "TargetCore(2026).sln" /p:Configuration=Release /p:Platform=x64
```

**Eight** configurations are defined, not the four this line used to name: `Debug|Win32`, `Debug|x64`,
`Release|Win32`, `Release|x64`, and the static-archive pair added later — `DebugLib|Win32`,
`DebugLib|x64`, `ReleaseLib|Win32`, `ReleaseLib|x64`. The four `*Lib` ones build the same sources
into an archive rather than a DLL; everything above about the sibling bindings applies to them
unchanged. The import library is emitted to `$(WDMSCS_LIB)`, so that variable must be set for the
build to complete even once the siblings are in place.

### CMake (in-tree)

The `CMakeLists.txt` here is a component script, not a standalone project — the parent solution
picks it up, enabled with `MSCS_BUILD_LIBS=ON`. It expects the `msgcore` and `p2pplatform`
targets to already exist.

On Linux it additionally builds two CTest-registered security tests:

- `crypto_kat` runs the OpenSSL backend's own known-answer tests and round-trips. It proves that
  backend behaves as specified — it says nothing about the CNG backend, and a backend passing its
  own tests is not evidence that the two agree.
- `seal_interop` is the one that does: it opens bodies sealed by the *other* backend from checked-in
  vectors, so it fails if a Windows peer and a Linux peer cannot talk. That is the wire-compatibility
  claim, and it is the only test in the tree that runs the two backends against each other.

### Installing

`cmake --install` stages a prefix a third party can build and run against. Rules first appeared
2026-08-16 and were completed 2026-08-19; before 08-16 there was no `install()` rule in any of the
three repositories, so every consumer staged binaries by hand out of the build tree.

```
<prefix>/bin/          targetcore.dll, msgcore.dll          (Windows)
<prefix>/lib/          libtargetcore.so, libmsgcore.so      (Linux)
                       targetcore.lib, msgcore.lib          (Windows import libraries)
<prefix>/lib/cmake/    TargetCoreConfig.cmake, MsgcoreConfig.cmake + targets/version files
<prefix>/include/      TargetCore_c.h, TargetCore_version.h
                       Msgcore_c.h,    Msgcore_version.h
<prefix>/share/licenses/targetcore/   LICENSE, NOTICE
<prefix>/share/licenses/msgcore/      LICENSE, NOTICE
```

A consumer writes one line:

```cmake
find_package(TargetCore REQUIRED)      # pulls in Msgcore as a declared dependency
target_link_libraries(app PRIVATE TargetCore::targetcore)
```

**The flat C headers are the shipped surface**, and both components' `_version.h` ship with them —
each `_c.h` includes its own on the first line, so staging one without the other produced a header
that would not preprocess. That was a real defect here until 2026-08-19, as was `Msgcore_c.h` using
`wchar_t` seventy times without including `<wchar.h>`: legal in C++, where it is a keyword, and
invisible under MSVC, which makes it native in C as well. It failed the first time a C compiler on
Linux was asked to include the shipped header — which had never happened before the install gate.

What does **not** ship: the C++ headers, deliberately. Every one of them reaches `stdafx.h`, which
reaches `..\Platform` and MFC, so installing them would publish a surface that cannot compile
outside this solution — and a header that cannot be included is worse than no header.

`p2pplatform` appears nowhere in the install tree, and that is correct rather than an omission: it
is an INTERFACE library holding an include directory, it contributes no binary, and an installed
consumer needs none of its headers. On Linux the same is true of OpenSSL and liburing — the `.so`
records them itself, so building against the installed library needs neither development package.

An installed `targetcore` still needs `msgcore` beside it to load; that is what linking means. What
changed is that `cmake --install` now puts it there, and **`ctest -R p2p_installtree` fails if it
does not** — it stages into a scratch prefix, builds a C program that knows only
`find_package(TargetCore)`, runs it with the build tree scrubbed off `PATH`, then deletes the staged
sibling and requires the same binary to stop working.

### Is the coupling mutual?

No. **Msgcore does not depend on TargetCore**, so the layering is acyclic:

```text
Platform  ←  Msgcore  ←  TargetCore
```

`Msgcore(2026).vcxproj` has no `AdditionalIncludeDirectories` element at all, its
`AdditionalDependencies` are system libraries only, and `Msgcore\CMakeLists.txt:55` links
`p2pplatform` and nothing else.

---

## Usage

An application endpoint is a `P2PeerHub` subclass. Overriding the handlers *is* the application
code — the pattern is identical for every transport; only the factory differs.

```cpp
#include "P2Pwin32.h"      // StartupP2Pmsg / CleanupP2Pmsg
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"

class MyHub : public P2PeerHub
{
public:
    MyHub(P2PaddrSTR strAddr) : P2PeerHub(strAddr) {}

    // A broadcast message arrived and was routed to this hub.
    // (On_P2PeerUCast is the same shape, for messages addressed to us alone.)
    msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        wprintf(L"from '%s': %s\n", pMsg->GetSource(), (LPCWSTR)pMsg->Data());
        return msgHANDLED;               // consumed — stop routing
    }

    // The login handshake completed (with RequireAuth on, which is the
    // default, that includes the ECDH P-256 agreement and the signed
    // login). Safe to post now.
    conRESULT On_ConLoginAck(P2PeerCon* pCon, P2PaddrSTR strThis,
                             P2PaddrSTR strThat, const void* pvAck,
                             P2Psize_t iSize) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck(pCon, strThis, strThat, pvAck, iSize);

        LPCWSTR   lpszMsg = L"Hello from the client!";
        P2Psize_t nBytes  = (P2Psize_t)((wcslen(lpszMsg) + 1) * sizeof(wchar_t));

        // (source, destination, msg-id, data, bytes). The hub takes ownership.
        PostP2PeerMsg(new P2PeerMsg32(GetP2PaddrHub(), strThat,
                                      P2Pmsg_BCast, lpszMsg, nBytes));
        return r;
    }
};

int main()
{
    StartupP2Pmsg(16);                                   // kernel up
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);       // TCP needs Winsock

    MyHub  hub(L"MyApp.Client");

    // Security is ON by default, so an unprovisioned hub REFUSES TO ARM and
    // SpawnHub() returns 0. This one line is the opt-out, said out loud; the
    // alternative is to provision an identity and an allow-list. See Security.
    hub.RequireAuth(false);

    HANDLE hThread = hub.SpawnHub();                     // pump starts, or 0

    hub.PostP2PeerCon(                                   // dial out
        P2PeerConWsa::ClientFactory(L"MyApp.Server", L"127.0.0.1", 7777));

    Sleep(3000);

    hub.CloseHub();                                      // teardown, reverse order
    CloseHandle(hThread);
    CleanupP2Pmsg();
    WSACleanup();
    return 0;
}
```

The server side is the same class with `P2PeerConWsa::ServiceFactory(L"MyApp.Client", 7777)`.
The pipe version is the same again with `P2PeerConPipe` and a pipe name in place of the port.

**Handler order on the wire:**

```text
SERVER: On_ConStartup → On_ConListen  → On_ConAccept   → On_ConLogin
CLIENT: On_ConStartup → On_ConConnect → On_ConLoginAck  ⇒ posts BCast
SERVER: On_P2PeerBCast                                  ⇒ message delivered
```

Full worked examples for both transports, sub-targets, and teardown ordering are in
**[examples.md](examples.md)**.

### Reporting the version

The current release is **3.1.0** (tag `v3.1.0`), and what the number *promises* is written
down. The short form is that
the flat C ABI — 101 symbols, enumerated and gated — is the covered surface, the C++ classes
are not, and each wire format versions on its own byte. The major does **not** cover the packed
message image, which carries no version field at all.

The MINOR moved from 3.0.0 because the security revision **added** eight symbols to that surface —
the per-class link policy, the trust fence and the end-to-end waiver, with their getters — and
changed the meaning of none. A consumer built against 3.0.0 links against 3.1.0 unchanged.

`TargetCore_version.h` is the single place the version number is written; it feeds the
DLL's `VERSIONINFO` resource and the macros below, so the two can never disagree. That is
checked rather than assumed — `ctest -R p2p_abisurface` reads the shipped binary's
`FileVersion` and fails if it is not the number the header declares.

```cpp
#include "TargetCore.h"                  // pulls in TargetCore_version.h

wprintf(L"built against TargetCore %s\n", TARGETCORE_VERSION_STRINGW);

#if !TARGETCORE_VERSION_AT_LEAST(3,0,0)   // compile-time floor
#  error TargetCore 3.0.0 or later is required
#endif
```

A **hub reports the version it is actually running** as part of its state snapshot — no
special message and no handler to write:

```cpp
P3PmsgItem oHub = hub.Serialise(0);      // the {P2PeerHub} node

wprintf(L"hub is running TargetCore %s (0x%08X)\n",
        oHub.SelectItem(_N("Version")).r_data().c_wstr(),
        oHub.SelectItem(_N("VersionHex")).r_data().c_uint());
// hub is running TargetCore 3.1.0.0 (0x03010000)
```

`Version` is for display, `VersionHex` packs `MAJOR,MINOR,PATCH,BUILD` for comparison.
Because this is the same snapshot the kernel attaches to `P2Pevent`s and to hub-status
replies, anything that already carries hub state now carries its version too.

The shipped binary also answers without being run — the resource is on the file itself:

```powershell
(Get-Item TargetCore.dll).VersionInfo.FileVersion   # 3.1.0.0
```

> **This is a build identity, not a wire version.** Whether two hubs can talk is decided
> by the login block's own version byte, which is versioned separately and on purpose
> (see [P2PAuthLogin.h](P2PAuthLogin.h)). Do not read interoperability out of these fields.
> The versioning policy lists every wire format, the version each is at, and
> what happens on a mismatch — including the two that still carry no version at all, which are
> the **GCM transport record** and the **`.p2p` file image**. They are named rather than counted
> because this line said *"the two"* while the policy listed **three**: the message image was
> the third, and it stopped being unversioned on 2026-08-20 when it gained a layout generation. A count
> that goes stale silently is worth less than a list that cannot.

### Hosting a hub where nobody can see a dialog

**Nothing to set since 2026-08-17.** This section used to open by telling you to put
`P2PMSG_NO_UI=1` in a service's environment. It is kept because the reasoning is worth knowing, and
because the workaround still works — but the case it guarded against is now handled in code.

Should you still want the variable set for a service — it is honoured, and harmless:

```powershell
# a service's environment, not the interactive session's
sc.exe stop  MyHubService
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MyHubService" /v Environment `
        /t REG_MULTI_SZ /d "P2PMSG_NO_UI=1" /f
sc.exe start MyHubService
```

A `P2Pevent` is emitted as **text** when the process has somewhere to write it — a console, or a
redirected stderr — and as a **modal dialog** when it has neither. A service started by the SCM has
neither. The dialog is then raised on whichever thread produced the event, and for a routing or
connection diagnostic that is the hub's **own pump thread**: the pump stops dispatching, never sees
the CLOSE signal, and `CloseHub()` waits on it without a bound — deliberately, since bounding that
wait would let teardown run past a live pump and trade a hang for a use-after-free. In a
non-interactive session there is nobody to click OK, so the wait does not end.

**What changed.** The library now asks whether anybody *could see* a dialog before asking whether
there is anywhere to *write* one: `ProcessIdToSessionId` for the isolated services session, and
`WSF_VISIBLE` on the process window station. A service fails both and gets text, with no
configuration. A windowed application is in session >= 1 on a visible station and keeps its dialogs,
unchanged. A failed query counts as viewable, so an API error cannot silence a windowed host. Off
Windows `MessageBoxEx` is a stub and text was always unconditional.

`P2Pevent::ForceTextOutput(true)` is the same switch as the variable, from code and reversible — it
returns the setting it replaced. `P2PeerService` calls it for a hosted hub either way.

**Where the text then goes matters just as much**, because a service has no stderr for it to land on;
refusing the dialog without a destination would trade a hang for silence.
`P2Pevent::SetTextSink()` installs one. In service mode `P2PeerService` uses it to route diagnostics
to the **Windows application event log** under the service's own name, and registers the event source
during `Install()`. This is deliberately *not* the `Register4P2Pevents` notification sink, which is a
single global slot — a service claiming that would silence whatever its host had registered.

**And a way to say all of this without writing any code.** A plain text file named `P2Pmsg.cfg`,
read once and lazily from beside the host executable — or from beside `Msgcore.dll` itself, which is
where a foreign host such as a bare JVM under the Panama bindings will find it:

```ini
ErrToMessageBox: 1        # 1/0, on/off, yes/no, true/false
LogFile: errorLog.txt     # relative to THIS file's folder
```

Both settings are optional and **the defaults are the dialog on and no log file** — with no such
file present, nothing about this library's output differs from before the file was understood. Two
properties are worth stating outright:

- **`ErrToMessageBox` moves in one direction only.** Setting it to `0` is a third way of saying what
  `P2PMSG_NO_UI=1` and `ForceTextOutput(true)` already say. Setting it to `1` merely declines to say
  it — it cannot cancel either of those, and it cannot override the viewability test. A deployment
  artefact must not be able to re-arm a deadlock a host had disarmed.
- **`LogFile` loses to an installed `SetTextSink()`**, and a *relative* `LogFile` resolves against
  the folder holding the configuration file rather than the working directory. Both for the same
  reason: a service's working directory is `%SystemRoot%\System32`, and a stray file must not be able
  to divert a service's diagnostics out of the event log and into a system folder.

The log is **UTF-8 with no byte order mark on both platforms**, opened and closed per entry and
serialised across threads. `P2Pmsg.cfg` itself is UTF-8 (with or without a mark); a UTF-16 file is
detected and refused by name rather than parsed into nonsense. A setting that cannot be read is
ignored and reported through `P2Pevent::ConfigDiagnostic()`, never guessed at in either direction.
`P2Pevent::LoadConfigFile()`, `LogFilePath()` and `SetLogFile()` are the code-side equivalents;
`P2PMSG_CONFIG` in the environment overrides the search with an explicit path.

Two worked examples, both in `_TargetCore_UseExamples/ErrorReportingExamples`:
`NTServiceEventLog` raises a diagnostic on the pump thread on purpose and reports to the event log;
`DialogOrLogFile` drives both settings of `ErrToMessageBox` and re-executes itself as a console-less,
stderr-less child to reach the one host shape where the dialog is still reachable.

While you are there, **a hub reports its own state in the snapshot every consumer already
receives.** `P2PeerHub::Serialise()` is what builds the `MSG_P2PexpHub` reply and every `P2Pevent`
carrying hub state, so a monitor holding one of those needs no new call and no instrumentation in
the hub:

| Field | What it says |
|-------|--------------|
| `QueDepth` | `P2Pmsg`'s queued and not yet dispatched **across all of the hub's pumps** — not just the one the caller is standing in, which is what `GetP2PmsgCount()` alone reports |
| `Accepted` | connections the hub's services are currently holding, the number `SetMaxAccepted()` bounds |
| `Throttled` | backpressure holds applied to this hub's connections — read it *with* `QueDepth`: a low queue and a climbing hold count is not an idle hub, it is one holding the line |
| `PumpsMax` | the hub's configured pump ceiling. It reported a literal `0` on every hub that ever ran until 2026-08-19 |
| `Version` · `VersionHex` | the build identity of the `TargetCore` binary. Not the wire version — see below |

The same numbers are reachable directly: `GetP2PmsgHubQueCount()`, `GetP2PmsgHubAcceptedCount()`,
`GetP2PmsgHubHeldCount()` and `GetP2PmsgHubPumpsMax()` take a `P2PmsgHubID` and, unlike their
neighbours, **do not throw** — they are read by the code that builds a diagnostic, so a hub that is
being torn down has to be reportable rather than a second fault. `GetP2PmsgCount()` (per pump) and
`P2PeerCon::GetAcceptedCount()` / `GetRecvThrottleCount()` (per connection) remain for attribution.
Guarded by `p2p_hubsnap`, whose monitor deliberately calls nothing but `Serialise()`.

---

## Documentation

| Document | What it covers |
|----------|----------------|
| **[examples.md](examples.md)** | Worked TCP and named-pipe examples, sub-targets, startup/teardown boilerplate. |
| **[Architecture(IOCP).md](<Architecture(IOCP).md>)** | The completion-port design, traced end to end with `file:line` references — port creation, association, the completion key trick, and the lifecycle of one completion. |
| **[P2PeerHub.md](P2PeerHub.md)** | How a hub acquires its `P2Paddr`, the routing predicates, and why the `VNetname:` qualifier is a dead letter. |
| **[P2PeerCon.md](P2PeerCon.md)** | Connection internals and the handshake state machine. |
| **[BUGFIXES.md](BUGFIXES.md)** | The acknowledged leaks and crashes, each with the symptom, the site, the wrong fix, and the right one. |
| **[SECURITY.md](SECURITY.md)** | The current security posture, the hardening checklist for today's users, and how to report a vulnerability privately. |
| **[byte_order.md](byte_order.md)** | Which of this library's persisted and wire layouts are byte-order sensitive and which are not — the endian sentinel in the message image header, the layout generation the same six bits carry, and the rule that a persisted type is never widened. The C++ core is host-order; the `P2PeerHub` peers written in other languages are big-endian by convention, and the document says why those do not conflict. |
| **[THREAT_MODEL.md](THREAT_MODEL.md)** | Who this is defended against and who it is not: seven named adversaries, nine assets, the five trust boundaries traffic crosses, every protection mapped to the adversary it answers and the line that enforces it — and the three gaps that mapping found. |
| **[NOTICE](NOTICE)** | Third-party components, and the files *not* covered by Apache-2.0. |

---

## Project status

This is an **active modernisation of a 2002 codebase**, not a finished product. Being explicit
about what is solid and what is not:

| Area | Status |
|------|--------|
| Routing kernel, hub, priority queue, IOCP pumps | ✅ Working, in use, documented |
| `P2PeerConWsa` (TCP) · `P2PeerConPipe` (pipe) | ✅ Working, both covered by examples. **TCP is dual-stack since 2026-08-28, opt-in and IPv4 by default.** It was `AF_INET` at all three socket sites with `sockaddr_in` for bind and connect from the import until that date — a v6 peer could not reach a service and a client could not dial one, and what made that a *default* rather than a limitation is that nothing said so and nothing could be told otherwise. `SetFamily()` is the setting: `_IPv4` (unchanged, and what every existing caller keeps), `_IPv6`, or `_Dual` — `AF_INET6` with `IPV6_V6ONLY` **explicitly** cleared, because Windows defaults that option on and most Linux distributions default it off, so a socket that did not say would mean two different things on the two builds. The groundwork was already in place and is why the port was small: `P2PsourceKey` had been widened to 64 bits against exactly this, `AcceptEx` already passed `SOCKADDR_STORAGE`-sized address lengths, and the detached-connect carrier had been widened to `SOCKADDR_STORAGE` by SECURITY_REVIEW H1. A v6 origin is keyed by a hash of its **/64** — the block one host is delegated — with bit 63 set so v4 and v6 keys cannot collide and `::1` cannot fold to the 0 that means "unnameable". A v4 peer on a dual socket is normalised out of its `::ffff:` form before anything reads it. **What `_Dual` refuses:** a loopback scope, because `::1` is not the v4-mapped form of `127.0.0.1` and one bind cannot cover both. Client-side name resolution went through `getaddrinfo()` on the same day, replacing an `InetPton()` test and a `gethostbyname()` fallback that could not run — so a peer dialled by NAME, and the documented empty-address self-connection, reached `0.0.0.0` instead of their host; `gethostbyname()` was also the one API here that could not be carried to IPv6, so replacing it was the port's first step. Gated by `p2p_resolve`, `p2p_ipv6`, `p2p_ipv6dual` and `p2p_ipv6filter` |
| `P2PeerConDmx` (DMX, in-process) | ✅ Working, covered by an example (`DirectExamples/DmxMeshTest`) and by `dmx_mesh`, which is registered on **both** platforms (`MscsUnitTests/CMakeLists.txt:144`) and sits inside the totals above. `DspChain` is built on it |
| `P2PeerCon232` (serial) | 🟡 Working where it is tested, and it is tested on **Linux only**: `com232_mesh` is registered inside `if(NOT WIN32)` (`MscsUnitTests/CMakeLists.txt:1463`) because a Windows run needs the external `com0com` null-modem driver, which nothing here provisions. The example (`DirectExamples/Com232MeshTest`) needs that same pair, so it cannot run unattended either, and the Linux gate has one TIMEOUT flake on record (see the Linux port row). Not a defect in the transport - an untested platform, named rather than averaged away |
| Flat C API (`TargetCore_c.h`) + UTF-8 twins | ✅ Surface complete for `P2Paddr`, `P2PeerMsg`, `P2PeerConWsa`, `P2PeerHub` — **93** exported symbols, enumerated in `.github/ci/abi-flat.manifest` and checked against both the header and the built library, built into both the DLL and the `.so`. Handles are validated against a registry of live handles, and `P2Pevent` is caught at every entry point rather than unwinding across the boundary |
| Java Panama / jextract bridge | ✅ **93 of 93, and 6 of 6 tests green on both configurations — regenerated 2026-08-21 and re-measured here 2026-08-22.** This row stood 🔴 at **83 of 93** from 2026-08-21, because the revocation arm gate and the sealing default (Stage 3 steps 19 and 20) added ten covered entry points to this repository's manifest between them and the bindings had not been rebuilt against it. They have been. `AbiCoverage` — which reads `.github/ci/abi-flat.manifest` from *here*, not a copy — reports **promised 93, generated 93**, and all ten (`p2peerhub_require_revocation`, `p2peerhub_is_revocation_required`, `p2peerhub_set_revocation_list`, `p2peerhub_auth_revocation_list_path`, `p2peerhub_require_seal`, `p2peerhub_is_seal_required`, `p2peerhub_set_agreement_key`, `p2peerhub_add_seal_reader`, `p2peerhub_add_seal_reader_u8`, `p2peerhub_clear_seal_readers`) are reachable from the **friendly** layer rather than merely generated — nine wrappers for ten symbols, the wide `add_seal_reader` reached through its `_u8` twin because an address is a wide string on the C side. **The arm-gate test moved for the substantive reason rather than the bookkeeping one, and that half is the one worth reading:** it provisioned an identity and an allow-list and expected `NO_IDENTITY → NO_ALLOW_LIST → OK`; a hub that has done both now reports `NO_REVOCATION`, so the sequence it walks is `NO_IDENTITY → NO_ALLOW_LIST → NO_REVOCATION → OK` and it clears the new position with the documented one-line migration (`requireRevocation(false)`) rather than dodging the gate — the migration exercised rather than asserted. **Re-measured on 2026-08-22 against the DLLs this tree builds** (`build-win-cmake/TargetCore/{Debug,Release}`, both from that day's F-S4-3 build), 6/6 in each, compiled on a JDK 23 and run on jextract 25's own runtime — which is a run of the current library rather than a reading of the last one. **Two things the regeneration forced, recorded over there rather than absorbed:** the Java floor moves 22 → 23, set by the *generator* and not by anything these bindings need (jextract 25 emits `SymbolLookup.findOrThrow()`, a 23 method); and compiling needs 23+ while running needs a bundled `msvcp140` of **14.40+**, which on the test machine is satisfied by no single JDK — hence the split. **The account below is the 2026-08-20 state, kept because the failure it records is the whole reason `AbiCoverage` exists.** ✅ **83 of 83, measured on both configurations.** The bindings are `jextract` output over `TargetCore_c.h` plus hand-written wrappers, and they live in a **separate repository** (`MSCS_JavaBindings`) — generated code regenerated from this header does not belong in the tree that owns the header, and the copy of the C wrapper that used to live over there was deleted on 2026-08-14 for exactly that reason. **They spent 2026-08-14 to 2026-08-20 covering only 72 of the 83**, and nothing failed: `mvn compile` was green and the smoke test printed "passed" while printing `Hub created: false` three lines above it. The eleven missing were the whole authentication block and both halves of the receive sink, so a Java caller could not start a hub at all once auth became the default — nor call `require_auth(0)` to opt out, that being one of the eleven. Regenerated 2026-08-20, and the friendly layer now wraps **82** of them; the 83rd is the `wchar_t` sink, left deliberately because `wchar_t` is 16 bits here and 32 on Linux and the header names the `_u8` twin as the form Panama should bind. **The gap is now a test rather than a hope:** `AbiCoverage` reads `.github/ci/abi-flat.manifest` — this repository's copy, not a duplicate kept over there — and fails naming any promised entry point that has no binding. Six tests, **6/6 Debug and 6/6 Release**, covering the object model, the `_u8` round-trip, the startup guard, the arm gate end to end (provision an identity from Java, publish it, write an allow-list, watch `NO_IDENTITY → NO_ALLOW_LIST → OK`) and the receive sink as a Panama upcall on the hub's own pump thread. **Two Windows deployment facts came out of finishing it**, both now documented there: a JDK ships its own `msvcp140.dll` in `bin\` and `jvm.dll` loads it first, so a library built with toolset 14.40+ dies with `0xC0000005` and no diagnostic on any JDK bundling an older one (measured: 14.36 crashes, 14.40 and 14.44 do not — and every JDK 22+ on the test machine bundles 14.36); and `-Djava.library.path` no longer locates the DLL at all, because jextract 25 emits `SymbolLookup.libraryLookup`, which uses the OS loader search. **This is not the only way Java reaches this kernel.** `_TargetCore_UseExamples/PanamaJavaExamples` binds `TargetFacade`'s pure-vtable interfaces straight from `java.lang.foreign` with no jextract and no generated code, and records 14/14 on Debug and Release — but by construction it is x64-Windows-only, because it assumes MSVC vtable layout and `wchar_t` ≡ UTF-16. The flat C surface exists so the *portable* half does not have to |
| Linux port (io_uring + OpenSSL) | 🟢 **Green on both, and three of the four configurations re-measured on 2026-08-28 — Windows Debug 52/52, `linux-gcc-debug` 55/55, `linux-gcc-asan` 53/54, `security` 35/35 on the first two and 34/35 sanitised.** The remaining total is the 2026-08-22 Windows Release 45/45, the count of what existed that day rather than a current total. The sanitised shortfall is a **pre-existing** teardown-race leak that lands on a different one of `p2p_authchannel` and `p2p_confchannel` each run and is detailed under *Supported platforms*. Seven tests have joined since and all seven are registered on both platforms, so the trees hold 52 and 55; which seven, and why the count moved, is in the two-totals paragraph under *Supported platforms*. **The Linux re-measurement was the one that paid**: it found that `P2PeerConWsa.cpp` had stopped compiling there a day earlier, that `p2p_listenscope` had never been able to run there at all, and that `run_alex_test.sh` was checked out CRLF — three pre-existing faults, two of them gates that reported nothing while looking like they agreed. Green here therefore still means green, and three of the four numbers are simply older than the suite. All from a four-repository tree, TargetCore + Msgcore + MscsUnitTests + Platform, configured by the top-level `CMakeLists.txt` on both platforms. The `security` label is **35** tests on both as of 2026-08-28 — `p2p_conreap` the 24th, `p2p_fuzzblock` the 25th, `p2p_reportsign` the 26th, `p2p_imagegen` the 27th, `p2p_sealdefault` the 28th, `p2p_framegate` the 29th, `p2p_sealbcast` the 30th, `p2p_listenscope` and `p2p_acceptfilter` the 31st and 32nd for the listen scope and the accept allow-list, and `p2p_ipv6`, `p2p_ipv6dual` and `p2p_ipv6filter` the 33rd to 35th for the dual-stack port — one gate per finding or decision, so the count has moved for a reason every time rather than by drift. **35/35 measured on Windows Debug, 2026-08-28.** **35/35 measured on `linux-gcc-debug` too, 2026-08-28**, and **34/35 under ASan+UBSan+LSan with `detect_leaks=1` on the same day** — the one short being the pre-existing teardown-race intermittent named in the Linux row above, which lands on a different one of `p2p_authchannel` and `p2p_confchannel` each run. **All six of the newest gates were run under the sanitisers and all six pass**, which is the sweep that matters most for them: they all refuse a connection at accept and two of them parse operator-supplied prefix strings. It is also the run that caught the `StartupP2Pmsg()` mutex leak, through the three of them that cycle the environment more than once. **For the three IPv6 gates the plain Linux run mattered as much as a sanitised one would**, for a reason about the platform rather than the code: `IPV6_V6ONLY` defaults **on** on Windows and **off** on most Linux distributions, so the assertion that a v6-only service refuses a v4 client passes for free where it was written and fails where it was not. `Listen()` sets the option explicitly in both directions precisely so that cannot happen — and Linux has now said so. **The `61/61` and `44/44` this row carried until now were not wrong, they were taken from a tree shape that no longer exists** - one that also configured `MscsUnitTestsExternal`. It cannot be configured from here any more and there is deliberately no switch for it (`CMakeLists.txt`, the comment at the end of the `MSCS_BUILD_LIBS` block), so `MSCS_BUILD_EXTERNAL_TESTS`, which this file quoted as the way to turn it off, no longer appears in any build file. **The three tests that separate 48 from 45 are named rather than assumed:** `ctest -N` on both trees makes Windows a strict subset of Linux, and the extra three are `com232_mesh` (a serial mesh over a PTY pair), `crypto_kat` (the OpenSSL known-answer vectors) and `platform_iocp_test` (the io_uring shim) - all three Linux-only by construction, none of them an external suite. Getting the Linux figure meant finding that the build VM's tree did not carry F-S6-2's hub snapshot at all, so its gate for that finding was red there and green here — a partial copy failing in exactly the shape of a real defect. Synced from the branch, it passes. Earlier in the same pass, at 22 tests, one full Linux run in that pass reported `com232_mesh` as a TIMEOUT, which passed alone in 8 seconds and passed in the next full run, so it is recorded as a flake in a serial-loopback test rather than swept up; the two totals differ by the three Linux-only gates named above. Every security gate passes on both, including the accept bounds and backpressure. **`p2p_logindeadline` is no longer a Windows-only entry:** the cause recorded for that ("the drop cancels the listening socket's pending accept") was traced on 2026-08-18 and found *wrong* — the real fault was a completion key erased before its cancellations completed, and it is fixed. **The port is still not a formality**, and the findings it has cost are worth keeping: `p2p_acceptcap` first hung here on `SO_RCVTIMEO`, whose argument is a `DWORD` of milliseconds on Winsock and a `struct timeval` on POSIX; a `memcpy` with a one-byte forward overlap that MSVC's CRT tolerated corrupted the recv image under glibc's vectorised implementation; and `p2p_srcbound` was inconclusive here on a timing assumption that had passed on Windows by luck. **The newest of them is the plainest, and it had been shipping for a day: `P2PeerConWsa.cpp` did not COMPILE on Linux.** The accept allow-list's prefix parser, added 2026-08-27, was written against `CStringA::Find`, `Mid`, `Left`, `Trim` and `operator[]` — and `../Msgcore/Platform/p2pstr.h`'s `CStringA` carries construction, `GetString()`, `GetLength()` and `IsEmpty()` and nothing else. Ten errors, in the one translation unit that owns the transport. It went unseen because **nothing built this file on Linux between that commit and 2026-08-28**, which is the same shape as every other finding on this row: not a hard defect, an unasked question. The parser now works on a plain `char` buffer and needs no string class at all — a smaller change than widening the shim, and the version that cannot be broken again by whichever class a platform lends it. **The coverage caveat this row used to end with is CLOSED (2026-08-21).** It said glibc's `assert` calls `abort()`, so the harness *abandoned* an asserting input where Windows *continued past* it - **136** messages with **796** inputs abandoned on Linux against **315** with **0** on Windows, last measured 2026-08-16 - and told the reader to halve the Linux fuzz row. The assert budget is now **zero on both platforms** and Linux runs **3,618/3,618, 100%**, so the two depths are the same number and the instruction to discount one of them would now be the error. Windows stays the reference build |
| Pre-login traffic gate | ✅ Enforced always — an application message arriving before login is dropped with the connection |
| Bounds on an **unauthenticated** peer | 🟡 **Three bounds, all on both platforms; one is on by default and two are opt-in.** `SetMaxAccepted(n)` caps concurrent accepted connections **per service** (default 1024) and refuses the next at accept — on by default, guarded by `p2p_acceptcap`. `SetMaxAcceptedPerSource(n)` caps them **per source IP** (2026-08-19): the key is `getpeername()` on the accepted socket, read on the service at the one instant it still owns the half-accepted endpoint, so it works on a peer that has said nothing. **Default 0 (off), and that is a decision rather than an omission** — a source is an IP, and both topologies this library is actually run in collapse many peers onto one of them: loopback, which every test in the suite dials, and NAT. The mechanism is always present; the number is opt-in. Guarded by `p2p_srcbound`, which proves the refusal is about the origin by serving a *different* address while the first is refused. `SetLoginDeadline(ms)` drops a peer that connects and never logs in — **off by default, and working on both platforms since 2026-08-18**; the earlier "Linux takes the listener down with it" cause was traced and found wrong, and the real fault (a completion key erased before its cancellations completed) is fixed. Guarded by `p2p_logindeadline`, registered on both. **All three are enforced in `P2PeerConWsa` only:** the pipe, serial and DMX accept paths never test them. 232 and DMX are point-to-point by construction, so there is no share for an origin to take more than and the bound is correctly inert; **the pipe is a real gap** — `CreateNamedPipe` is called with a hardcoded `nMaxInstances` of 2, a bound the library does not own, and refusing at capacity there means declining to re-arm, which the morphing transport has no path for. Before 2026-08-16 there was no bound of any kind. **`F-S4-1` is FIXED as of 2026-08-20, and this row used to end with it as an open caveat:** on Windows a peer that connected, said nothing and disconnected was never reaped, so both accept bounds counted connections *ever accepted* rather than currently held - which made `SetMaxAccepted(1024)` retire a service permanently after 1024 connect-and-leave cycles, and the protection a slower version of the attack. The peer's FIN and the connection's own arming post both arrive as a zero-byte success completion and nothing told them apart; a mark set at submission now does, and Windows reports the same `ERROR_HANDLE_EOF` the Linux shim always has, so both platforms leave by one route. Gated by `p2p_conreap`, which measures the fall to zero AND that a peer still on the line is not reaped - the second half because the obvious fix drops every connection at accept |
| Reach of the listener | 🟡 **Two controls, both `P2PeerConWsa` only, both off by default and both added 2026-08-27.** Until then `Listen()` bound `INADDR_ANY` as a **literal** with no setting anywhere on the class to say otherwise, so every service this library ever stood up was reachable from every interface its host routes and a deployment that wanted less could only get it in a firewall, where nothing here could read it back. `SetListenScope(P2PeerConScope_Loopback)` binds `127.0.0.1` and `P2PeerConScope_Address` binds one nominated local interface — **the only one of the two the kernel enforces**, and the only protection anywhere in this component that acts before the framing parser sees a byte. An address the host does not hold fails the `bind()` and drops the service rather than widening back to `INADDR_ANY`. Guarded by `p2p_listenscope`, whose control runs *first*: the default scope must be reachable on this host's own routable address before the loopback scope is asked to refuse it, or a firewalled host would report a restriction it does not have. `AllowAcceptFrom("192.168.1.0/24")` — with `AllowAcceptLoopback()` and `AllowAcceptPrivate()` as shorthands — tests prefixes against `getpeername()` at accept, before the connection object exists. **Both families since 2026-08-28**: a `':'` in the rule makes it IPv6 (`"2001:db8::/32"`, `"fd00::/8"`, a bare `"::1"` meaning /128) and its absence IPv4, so a rule and its family cannot be written to disagree, and a zone suffix is refused because a rule that dropped it would be about every link rather than the one named. **A rule matches only its own family** — so a list holding only v4 prefixes refuses every v6 peer, which is a restriction that will be believed to be about addresses and is really about which lines were written. The one place the two spaces touch is a v4 peer arriving on a dual socket as `::ffff:a.b.c.d`, and that is normalised to `AF_INET` before it is tested, so `"10.0.0.0/8"` admits the same peer on a v4 service and a dual one. Guarded by `p2p_ipv6filter`, which measures the normalisation end to end. **It exists because a bind cannot express "the LAN":** binding a LAN interface restricts which *interface* accepts, not which *source* reaches it, so a NAT or a port-forward delivers an internet peer to that same interface. It **fails closed** on a source the kernel will not name — the deliberate opposite of `SetMaxAcceptedPerSource` one line away in the same function, which fails open, because a bound that cannot identify its subject must refuse nobody and a policy that cannot must refuse it. A malformed prefix is reported and adds **nothing**, and `AllowAcceptFrom` answers false so the caller finds out. Neither control is authentication: `RequireAuth` still decides who may speak, these decide who is listened to at all. Guarded by `p2p_acceptfilter`, whose positive control (a permitted source still served) is what keeps a filter that refused everybody from passing |
| Source binding | ✅ Enforced always on a link to a **descendant** or an **unrelated** peer. A link to an **ancestor** is bound to the **origin's signature** by `RequireRelayAuth`, which is **ON by default since 2026-08-18** (`AuthPolicy::m_bRelayRequired`). `RequireRelayAuth(false)` restores the old exemption exactly and is the documented migration. Deliberately not part of the arming gate — see the Security section for why that asymmetry is the right one |
| Undeliverable-report amplification | ✅ Capped — an undeliverable exception is dropped rather than answered with another one wrapping it |
| **Peer identity proof** | ✅ **Implemented, and ON by default since 2026-08-18** — ECDSA P-256 signed login against an allow-list, bound to the key-exchange transcript. A hub that requires it and cannot enforce it refuses to arm. The opt-out is `RequireAuth(false)`, said out loud |
| **Payload encryption on the live path** | ✅ **Implemented, and ON by default since 2026-08-18** — ephemeral ECDH P-256 → HKDF-SHA256 → AES-256-GCM, per connection, from the login onward; it rides on `RequireAuth`. Since 2026-08-20 the transport must also consult the key it is given |
| **End-to-end seal** (hub cannot read the body) | ✅ **Implemented, and ON by default since 2026-08-21** — a multi-recipient envelope (`kSealVersion` 2): the body is encrypted once under a random content key, wrapped once per reader, and signed by the sender over the whole recipient block. Addresses stay readable so routing still works. A relayed body that cannot be sealed is **not sent**. `AddSealReader` names an intermediate hub that may also read; only the sending hub's operator can name one. Opt-out `RequireSeal(false)`. **A BROADCAST is refused rather than sealed** — its scope names a subtree and no single key opens one — with `RequireSealBroadcast(false)` the targeted opt-out, which leaves relayed unicast sealed and the attestation intact |
| **Key rotation · revocation** | 🟡 **Implemented; revocation is a required position since 2026-08-21, rotation is still operator-driven** — an allow-list may carry several keys for one address and every one is tried, so a peer can be issued its next key before it uses one and cut over without a flag day. A separate revocation list overrides the allow-list, covers identity and agreement keys alike, reloads on a running hub, and **fails closed** if it is configured and unreadable. What it is *not* is self-service: there is no signed rollover, so someone still has to put the new key in front of each hub. Guarded by `p2p_keyrotate` |
| Session rekeying (per-message forward secrecy) | ❌ Not implemented — the session key lives as long as the connection |
| Legacy `DHKeyXChanger` / `Rijndael` | 🗑️ Deleted — broken, dormant and never reachable |
| `VNetname:` virtual networks | ❌ **Never implemented. Placeholder only** — the grammar promises it, nothing parses it, and a colon in an address is silently absorbed into the first hop's name. What shipped instead is per-connection interface mapping (`P2PeerIDmap_STATIC` / `_FRACTAL`), which is untested and mutually exclusive with authentication |
| Diagnostics cannot hang the hub | 🟢 **Holds, and needs no configuration since 2026-08-17.** A `P2Pevent` goes to stderr when there is a console or a redirected handle, and to a **modal dialog** when there is neither — and a dialog blocks the thread that raised it, which for a connection diagnostic is the hub's own pump, which `CloseHub()` then waits on without a bound. A Windows service was the one shape with nowhere to write *and* nobody to click OK. The library now refuses a dialog wherever it could not be seen (session 0, or a window station without `WSF_VISIBLE`), and `P2PeerService` routes a hosted hub's diagnostics to the Windows event log. A `P2Pmsg.cfg` beside the executable can also refuse the dialog and name a log file with no code at all (`ErrToMessageBox`, `LogFile`), and the setting moves only towards text — it cannot re-arm a dialog a host had refused. Asserted on both platforms by `p2p_servicedialog` (53 checks), and the dialog is driven for real by `ErrorReportingExamples/DialogOrLogFile`, which reaches a service's host shape by re-executing itself without a console or a stderr. **The end-to-end SCM run was executed, elevated, on 2026-08-22, and passed** — a real service under the SCM in session 0 reached `STOPPED` in 40 ms rather than sitting in `STOP_PENDING`. The evidence is not the clean stop, which an unarmed hub also produces: it is that `RunHub()` logged its pump entry, then the deliberate `P2Pevent`, then its pump exit, all in one second, and a `MessageBox` would have parked that thread between the second and the third. See [Hosting a hub where nobody can see a dialog](#hosting-a-hub-where-nobody-can-see-a-dialog) |
| Backpressure on a flooding peer | ✅ **Real backpressure since 2026-08-19, on by default, both platforms.** The ceiling `s_cP2PmsgMAX` (50000 live `P2Pmsg`'s, process-wide) is still there and still throws `P2Pevent_QUEFULL`, but it is no longer the *first* thing that happens. Two marks make the same budget a slope: at or above **37500** a connection stops asking its transport for another message, at or below **25000** it starts again. Stopping is expressed by *not calling* `RecvP2PeerMsg()` — the call that issues the next `Recv()` — so no read is outstanding, the socket buffer fills and the TCP window closes. **The peer is throttled by the transport: nothing is discarded and nothing is refused.** The gap between the marks is hysteresis, not decoration — one mark makes a connection resume the instant the budget dips a message below it and re-hold on its next completion. `SetP2PmsgBudgetMarks(high, low)` moves them (it throws rather than clamping, and requires `high < MAX`, because a held connection arms a poll timer and a timer *is* a `P2Pmsg`). Watch it with `GetP2PmsgHeldCount()` process-wide or the hub snapshot's `Throttled` field. Guarded by `p2p_backpressure`, whose third phase is the one that matters: after the pressure is released, **every held message must arrive** — throttling that loses messages is dropping with a better name. ~~The limit is written three ways and all seven sites print "10000 entries"~~ — that was true when this row was written on 2026-08-17 and was fixed on 2026-08-18: all seven test the constant and render it through one format. **Not bounded:** a peer's send *rate* below the high mark, and the destination pump's own FIFO depth as distinct from the process budget |
| Independent security audit | ❌ Not done |

---

## History

TargetCore began at **Ivyware Pty Ltd** in Melbourne in 2002 as the P2Pmsg kernel, in Visual
C++ of that era. The whole tree arrived in this repository in a single "Initial code" commit,
so the provenance lives in the file headers rather than in the log.

Since then it has been relicensed under Apache-2.0, pinned to a documented platform floor,
retired of its VS.NET 2002 project file, carried forward to the v145 toolset and C++23, given
a CNG crypto backend, and started on the road to Linux and the JVM. Files that predate the
import stay attributed to Ivyware; everything written after it is Khrustal & Mann.

---

## License

Distributed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE).

```
Copyright 2000-2026 Ivyware Pty Ltd, Khrustal & Mann
             MELBOURNE, VICTORIA, AUSTRALIA, 3000
```

Some files in this repository are **not** covered by that licence — Microsoft project-template
and wizard-generated files keep their own notices, and the MFC / Visual C++ runtime / Windows
SDK components this library links against are licensed separately and are not bundled here.
[NOTICE](NOTICE) lists every one of them.

---

## Contact

Use the [issue tracker](../../issues) — it is the right place for everything, including
questions. **Except security vulnerabilities:** report those privately, following
[SECURITY.md](SECURITY.md).

---

## Contributing — we need your help

**Right now this project is accepting bug reports and feedback.** That is a deliberate scope,
not a lack of interest: the codebase is mid-modernisation and the interfaces are still moving,
so unsolicited code changes are likely to collide with work already in flight.

Pull requests are **not** being merged at this stage. If you want to change code, open an issue
first and say what you intend.

**[CONTRIBUTING.md](CONTRIBUTING.md) is the full policy** — what a bug report needs to be actionable
(build identity, transport, addresses, and *which thread*), what feedback is most valuable, and the
verification standard this project holds itself to. It is kept as one file rather than duplicated
here, because two copies of a policy are two things that can drift apart.

Three things worth saying twice:

- 🔒 **A bug with a security consequence goes to [SECURITY.md](SECURITY.md)**, privately. Not here.
- 🧵 Concurrency and lifetime defects dominate this codebase — [BUGFIXES.md](BUGFIXES.md) is three
  worked examples. A report that says *which thread* is worth ten that don't.
- 📄 **Docs that lie** are the most valuable report you can send: a table or comment describing
  something the code does not do is the one defect class that can lead someone into a bad
  deployment. The `VNetname:` qualifier was found this way, and so was a security row in this very
  README that claimed an unconditional guarantee the code had a documented exemption from.

Not a bug and not quite feedback? Open an issue anyway — the tracker is the front door.

<div align="center">

---

**TargetCore** · Ivyware Pty Ltd · Khrustal & Mann · Melbourne, Australia · 2002–2026

</div>
