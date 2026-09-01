# Threat model

> **Written 2026-08-20** against `master` at 0.10.0.
> Every protection named here exists in the tree today and is cited to the line that enforces it.
> Where a protection has no automatic check, that is said rather than left to be assumed.

`SECURITY.md` has always argued about threats — one named revocation authority *because a deny-list
any peer can inject is a denial of service*; merged-never-substituted *so an arriving list can only
ever add*. The arguments were good and they were scattered, and scattered arguments cannot be
checked for **coverage**. This document exists to put them in one place and ask the question that
only becomes askable once they are there: *which adversary answers this, and is there an adversary
nothing answers?*

It found three. One of them is closed, by a one-condition change and a gate test committed with
this document; two are open and recorded as findings. See §8.

---

## 1. What this document is, and is not

**It is** a model of the code as built: the adversaries it was written against, the assets it is
defending, and the mapping between them.

**It is not** a model of your deployment. It cannot be — every protection below is conditional on
configuration, the topology is yours, and the most important input to a real threat model is what
the hub is *for*. Take this as the component's half.

**It is not an audit.** An audit is Stage 6 step 18 and is deliberately last: auditing a tree whose
defaults are off audits the wrong tree. The defaults have been on since 2026-08-18.

---

## 2. Method, and what it cost

The sweep was mechanical and boring on purpose. For every protection: name the adversary it
answers, find the line that enforces it, find the test that checks it, and write down all three. A
protection with no adversary is over-engineering. An adversary with no protection is a gap. A
protection with no test is a claim.

**The method has a failure mode and it fired on the first finding, which is worth recording because
it is the one this project keeps re-learning.** The gate test written to prove F-S6-1 **passed
against the tree that had the defect** — the worst outcome a test can have. It measured whether a
message was *delivered*, and delivery was blocked by something incidental (the client's stock
acknowledgement handler refusing an ack it did not expect to carry data), while the server had
already accepted the login. The run log said both things one line apart:

```
[authchannel] SERVER accepted a login claiming 'AuthChan.Client'
[ERROR] P2PeerTarget::On_ConLoginAck ... Remote MSG_P2PeerLoginAck contains data
```

Re-pointed at the proposition it was actually about — *did the server accept the login* — it went
red immediately, and the fix turned it green. **A gate must measure the decision, not a consequence
of the decision**, because the consequences have their own reasons for not happening.

---

## 3. The system as drawn

```
    +-------------------+                    +-------------------+
    |   PEER  (hub A)   |                    |   PEER  (hub B)   |
    |                   |     TCP / pipe     |                   |
    |  identity key ----+====================+---- allow-list    |
    |  allow-list       |   serial (RS-232)  |     revocation    |
    |  revocation list  |                    |     identity key  |
    +-------------------+                    +-------------------+
              \                                       /
               \          +-----------------+        /
                +=========|  RELAYING HUB   |=======+
                          |  (carries what  |
                          |  it cannot read |
                          |  if sealed)     |
                          +-----------------+
```

**Trust boundaries, in the order traffic crosses them:**

| # | Boundary | What is on the far side |
|---|---|---|
| B1 | The socket | Anything that can reach the bound interface and passes the accept allow-list. Bytes with no provenance |
| B2 | The framing parser | A frame that is self-consistent **and of this build’s message-image layout generation** — and nothing more |
| B3 | The login gate | A peer that holds a key this hub lists, on a channel this hub agreed |
| B4 | The routing gate | A message whose source address the sender is entitled to claim |
| B5 | The seal | A body only the named destination can open |

Everything before B3 is reachable by **anyone who can open a TCP connection**. That is the single
most important sentence in this document: the framing parser, the whole of `P2Peerio::RecvP2PeerMsg`
and everything `VBListIOmage` does to a buffer, run *before* any proof of anything. That is why the
fuzzing (Stage 1 step 4, Stage 6 step 16) and the sanitiser gate (Stage 1 step 5) are security work
and not hygiene.

**Since 2026-08-27 a deployment can narrow who "anyone" is, and B1 is the only boundary in this
table that moved.** `P2PeerConWsa::SetListenScope()` decides where the socket binds and
`AllowAcceptFrom()` decides which sources survive the accept — the first enforced by the kernel
before a byte arrives, the second by `AcceptSpawn()` before a connection object is allocated. Both
are **off by default**, because `INADDR_ANY` and "no allow-list" are what every caller written
before them gets, so the sentence above remains true of an unconfigured hub and of every hub that
ran before that date. What changed is that it is now a **choice** a deployment can make and read
back (`Serialise()` carries both), rather than one it could only make in a firewall where this
process could not see it. Refer §6.1.

**One transport is not a wire and it matters here.** `P2PeerConDmx` hands a pointer between two
`P2PeerioDmx` objects **inside one process** — `pThat = (P2PeerioDmx *)hFile`, and the receiver
copies. There is no boundary B1 for it and encryption on it would protect nothing. That reasoning
had never been written down anywhere until this document, and §8 explains why writing it down
mattered. **It is now written in the tree as well, at `P2PeerioDmx`'s own declaration**
(`LeavesProcess()` returning false), so the exemption is something the class asserts rather than
something a reader has to reconstruct — see F-S6-3 in §8.

---

## 4. Assets

What an attacker would be trying to get, in the order the tree defends them.

| # | Asset | Lost when |
|---|---|---|
| S1 | **The content of a message, on one hop** | Anyone on the path can read it |
| S2 | **The content of a message, end to end** | A hub that merely *carries* it can read it |
| S3 | **The authenticity of a source address** | A peer speaks as someone else, and routing believes it |
| S4 | **The integrity of a message in flight** | A byte changes and nothing notices |
| S5 | **The hub's availability** | Memory, threads, connections or queue exhausted; a hang |
| S6 | **The private identity key** | Read from disk, from memory, or from a core file |
| S7 | **The trust state** — the allow-list and the revocation list | Someone else decides who is trusted |
| S8 | **The host's memory safety** | A parse defect becomes execution |
| S9 | **The operator's knowledge of which of these is in force** | The deployment is secured in belief only |

**S9 is an asset, not a nicety.** Every protection below is conditional on configuration. A
protection that is off, and looks exactly like one that is on, defends nothing and is worse than an
absent one because it is budgeted for. F-S6-2 is the finding against S9.

---

## 5. Adversaries

| # | Adversary | What they can do | What they hold |
|---|---|---|---|
| **A1** | **Passive observer on the path** | Read every byte. Inject nothing | Nothing |
| **A2** | **Active attacker on the path** | Modify, drop, reorder, delay, replay, inject. Terminate a TCP connection and relay it | Nothing |
| **A3** | **Unauthenticated peer that can reach the listener** | Complete TCP, send arbitrary bytes, open many connections, say nothing and stay | Nothing |
| **A4** | **Authenticated peer** | Everything A3 can, plus everything a member of the tree may legitimately do | A key on this hub's allow-list |
| **A5** | **Intermediate hub on a route** | Read, alter, drop or fabricate anything it carries; claim to have relayed what it did not | A key, and a legitimate place in the topology |
| **A6** | **Publisher of a revocation list** | Offer a list to any hub that will take one | Possibly a valid key — just not the authority's |
| **A7** | **Local user on the host** | Read files, read process memory, read a core file | Local access |

**A4 and A5 are the two the design is really about.** A1–A3 are answered by the login and the
session cypher, which is table stakes. A mesh in which members route for each other has to decide
what a member may do to traffic that is merely passing through, and that is where the attestation
(A5) and the end-to-end seal (S2) live.

**A7 is mostly out of scope and partly not** — see §7. The identity store defends against a
*careless* local posture (a world-readable key file), not against a local attacker who has already
won.

---

## 6. The protection map

Every protection in the tree, the adversary it answers, where it is enforced, and what checks it.
**Default** says whether it is on without configuration. A row with no check is a **claim**, not a
promise, and is marked as one — there are five.

### 6.1 Getting in

| Protection | Answers | Default | Enforced at | Checked by |
|---|---|---|---|---|
| Signed login, ECDSA P-256 against an allow-list | A2, A3 | **on** | `AuthPolicy::VerifyLogin` ← `P2PeerCon::AuthGateInbound` | `p2p_authpsk` |
| Refusal to arm when it cannot enforce what it requires | operator error | **on** | `P2PeerHub::AuthArm`, consulted by `CreateHub`/`SpawnHub` | `p2p_armgate` |
| Channel binding folded into the transcript (login `kVersion` 2) | A2 forwarding a genuine proof | **on** | `AuthChannelBind` ← `KeyXDerive`; `Transcript()` | `p2p_authrelay` |
| **The agreement is required at the VERIFIER, not only at the initiator** | A4 downgrading its own channel; A1 thereafter | **on** | `AuthGateInbound`, `KeyXWanted() && !m_bKeyXDone` | `p2p_authchannel` |
| Nonce cache and a ±300 s freshness window | A2 replay | **on** | `AuthPolicy::NoteNonce` / `SeenNonce` | `p2p_replayguard` |
| Login deadline on an accepted connection | A3 holding a slot in silence | **on** | `P2PeerCon::ArmLoginDeadline` | `p2p_logindeadline` |
| Pre-login application traffic discarded, connection dropped | A3 | **on** | `P2PeerCon`, `ConState_Login` | `p2p_authgate` |
| Login address restricted to a domain pattern | A3, A4 | where set | `P2PeerConWsa::ServiceFactory` peer argument | — *claim* |
| **Listen scope: the socket binds one interface, or loopback** | A3 that is not on this machine | off (every interface) | `P2PeerConWsa::Listen` ← `ListenBindSockaddr()`, **kernel-enforced** | `p2p_listenscope` |
| **Accept allow-list: IPv4 and IPv6 prefixes tested at accept** | A3 that is not on a permitted network | off (empty list) | `P2PeerConWsa::AcceptSpawn` → `IsAcceptSourceAllowed()` | `p2p_acceptfilter`, `p2p_ipv6filter` |
| **Address family: which space the socket opens in, `IPV6_V6ONLY` set explicitly** | A3 reaching a service over a family the operator did not intend to serve | IPv4 | `P2PeerConWsa::Listen` ← `SocketFamily()`, **kernel-enforced** | `p2p_ipv6`, `p2p_ipv6dual` |

**The last three rows are the only protections in this table that act BEFORE B2**, and that is the
whole of their value. Every other row here answers a peer that has already had its bytes parsed.
The family and the listen scope stop the SYN in the stack; the allow-list refuses the socket before
a connection object exists. None is authentication and none is offered as any — `RequireAuth`
decides who may speak, these decide who is listened to — and none is a substitute for another: a
**bind cannot express "the LAN"**, because binding a LAN interface restricts which interface
accepts and not which source reaches it, so a NAT or a port-forward delivers an internet peer to
that same interface. Being off by default is deliberate and is the same judgement
`DEF_P2PeerConAcceptSource` records: an address-shaped default refuses legitimate traffic silently,
at accept, in exactly the two topologies this library is actually run in.

**The family row is new on 2026-08-28 and reads two ways.** As a capability it is the smaller half:
the transport can now serve and dial IPv6, which it could not before. As a *control* it is
`IPV6_V6ONLY` being **stated rather than inherited** — Windows defaults it on and most Linux
distributions default it off, so a socket that did not say would admit a different set of peers on
the two builds from identical source. That is asset S9 exactly: not a protection that is missing,
but one whose real state cannot be read off the code. The same argument makes `_Dual` refuse a
loopback scope instead of choosing between `::1` and `127.0.0.1`, and makes a listen-scope literal
of the wrong family an error rather than a silent v4-mapped bind that would turn a dual service
into a v4-only one with nothing to show for it.

**Widening a transport widens what an allow-list has to say.** A rule matches only its own family,
so an existing v4-only allow-list on a service moved to `_Dual` refuses every v6 peer — fail-closed,
which is the right direction, but it is a restriction the operator did not write and would not
expect to read in the refusal line. The refusal names the address and says so. The one crossing
point, a v4 peer reported by a dual socket as `::ffff:a.b.c.d`, is normalised to `AF_INET` before it
is tested or keyed, so a v4 rule and a per-source share both mean the same thing on either socket.

### 6.2 Staying in

| Protection | Answers | Default | Enforced at | Checked by |
|---|---|---|---|---|
| AES-256-GCM session cypher, per connection, ephemeral ECDH → HKDF | A1, A2 | **on** | `P2Peerio::Encrypt/DecryptP2PiomageSwap` | `wsa_mesh`, `crypto_kat` |
| Every inbound frame decrypted — no exemption by type on receipt | A2 injecting cleartext after the handshake | **on** | `P2Peerio.cpp` receive path (unconditional) | — *claim* (observed once, falsifying F-S6-3's second gate) |
| **A keyed transport must CONSULT the cypher, or declare it is not a wire** | A1 reading a channel its operator was told is encrypted | **on** | `P2PeerCon::KeyXDerive` (declaration), `P2Peerio::Send` (no declaration needed) | `p2p_confchannel` |
| Source address bound to the identity that logged in | A4 speaking as someone else | **on**, and since 2026-08-20 with **no exemption of any kind** (F-S9-1) | `GateRelayInbound`, `RouteP2PeerMsg` | `p2p_authspoof`, `p2p_srcbound`, `p2p_reportsign` |
| Relay attestation: a downward relay carries the **origin's** signature | A5 fabricating traffic it claims to have relayed | **on** | `RequireRelayAuth`, `AuthGateInbound` relay path | `p2p_authancestor`, `p2p_authrelay` |
| End-to-end seal: body sealed to the destination | A5 reading what it carries | opt-in | `P2PeerHub::SealFor` / `OpenFrom` | `p2p_sealhop`, `seal_interop` |
| Seal replay cache and floor | A5, A2 replaying a sealed body | **on** | `AuthPolicy::NoteSealSig`, `m_bSealReplay` | `p2p_replayguard` |
| Allow-list holds several keys per address, and every one is tried | rotation without a flag day | **on** | `FindPeer` | `p2p_keyrotate` |
| Revocation list: fail-closed, reloadable live, merge-only, one issuer | A4 after compromise; A6 injecting a deny-list | opt-in | `SetRevocationList`, `ReloadRevocationList` | `p2p_keyrotate`, `p2p_revokedist` |
| Revocation list bounded at **4096** entries | A6 exhausting memory with a signed list | **on** | `kRevMaxEntries`, `P2PAuthLogin.h:424` | — *claim* |

### 6.3 Not falling over

| Protection | Answers | Default | Enforced at | Checked by |
|---|---|---|---|---|
| Accepted-connection cap, default **1024**, refused *at accept* | A3 | **on**, TCP only | `P2PeerConWsa::AcceptSpawn` → `AcceptAtCapacity()` | `p2p_acceptcap` |
| Listen backlog is settable rather than a hardcoded 32 | A3 | **on** | `P2PeerConWsa::SetBacklog` | `p2p_acceptcap` |
| Receive size ceiling, default **32768** | A3, A4 | **on** | `P2Peerio.cpp:514` | `p2p_fuzzframe` |
| Backpressure on the message queue | A4 flooding | **on** | `P2PmsgPump` | `p2p_backpressure` |
| Undeliverable-report amplification capped | A3, A4 | **on** | `P2PeerMsg::WrappedResponseFactory` | `p2p_bigreport` |
| A diagnostic cannot open a dialog on a host with nobody at it | availability of any service | **on** | `P2PeventUseTextOutput()` | `p2p_servicedialog` |
| Framing bounds under ASan / UBSan / LSan | A3 reaching S8 | in CI | `RecvP2PeerMsg`, `MsgVBHeap` | `p2p_fuzzframe`, `sanitizers.yml` |
| Message image **layout generation** refused unless current | A3 reaching S8 | **on** | `P2Peerio::RecvP2PeerMsg` stage 2, before the allocation | `p2p_imagegen` |

**The generation row is newer than the rest of this table and is worth one paragraph, because what
it answers is not obvious from its name.** Every other protection here defends against bytes that
are *wrong*. This one defends against bytes that are *right for a different build*. A body layout
change — aligning a payload, reordering a field, widening a length — moves nothing the header can
show: the size and the addressing mode are unchanged, so a peer accepts the frame and parses the
body against the wrong map. That is a parse defect (S8) reachable by A3, and it is one no amount of
bounds checking finds, because every bound is satisfied. The six sentinel bits carry a generation
code; anything that is not this build’s is refused before `new char[nSizeof+4]` runs.

**The store deliberately does NOT enforce this**, and that is a decision rather than a gap:
`P2PmsgMgr::Load` still accepts a pre-sentinel image and warns. A frame is a peer and a peer can be
upgraded; a file is data somebody already has. The asset at risk there is different too — loading
your own old store is not A3.

### 6.4 At rest and in memory

| Protection | Answers | Default | Enforced at | Checked by |
|---|---|---|---|---|
| Identity file written `0600`, and a DACL that is its Windows counterpart | A7 (careless posture) | **on** | `P2PIdentityStore.cpp` | `crypto_kat` |
| A group- or world-readable identity file is **refused**, `IdErrPerms` | A7 | **on** | `LoadKeyFile` | `crypto_kat` |
| DPAPI wrapping of the stored private key | A7 | **Windows only** | `P2PIdentityStore.cpp` protect/unprotect | `crypto_kat` |
| Key material zeroised after use | A7 reading a core file or swap | **on** | `SecureZeroMemory`, `ZeroMem`/`ZeroVec` | — *claim* |
| No key material in any diagnostic | A1 via a log, A7 | **on** | by construction | — *claim* |

**The DPAPI row is an asymmetry, not an oversight, and it is stated so it is not mistaken for one.**
Off Windows there is no equivalent, so `IdProtect_None` is returned and *the file mode is the whole
protection*. A Linux deployment's identity key is plaintext on disk at `0600`. That is the honest
description; if it is not enough for your deployment, the key belongs somewhere this library does
not manage.

---

## 7. Deliberately out of scope

Each of these is a decision, not an omission, and each has a reason that is not "we ran out of time".

- **A hub the operator configured with `RequireAuth(false)`.** That is a supported answer — a
  trusted segment, an in-process router, a test that is not about authentication. It verifies
  nothing and encrypts nothing, by instruction. What is *not* out of scope is a defect in the
  authentication or encryption path of a hub that requires them.

- **Routing metadata.** A hub sees the source and destination of everything it routes; that is what
  routing is. The end-to-end seal hides **bodies from carriers**, and nothing hides the graph from
  the members that constitute it. A mesh whose members route for each other cannot keep its shape
  secret from itself, and pretending otherwise would be the most dangerous line in this document.

- **Traffic analysis generally** — timing, sizes, connection patterns. No padding, no cover traffic,
  no constant-rate anything. Message sizes are visible to A1 even under the session cypher, because
  GCM adds a fixed 28 bytes and nothing else.

- **An adversary with more bandwidth than the host.** The bounds in §6.3 keep a hub from destroying
  itself on hostile input. They do not make it survive a flood, and no library-level bound can.

- **An already-compromised local machine.** §6.4 answers a careless posture, not an attacker who is
  already running as the same user. Once they are, the key is theirs.

- **Upstream code** — MFC, the Visual C++ runtime, the Windows SDK, OpenSSL, liburing. Report those
  upstream.

- **The C++ class surface.** The compatibility promise excludes it, and it
  is excluded here for the stronger reason: a consumer compiled against `P2PeerHub` and friends is
  **inside** the library, not on the far side of a boundary. There is no trust boundary to model
  between a class and code that shares its heap, its exception model and its `_ITERATOR_DEBUG_LEVEL`.
  The flat C ABI is a boundary in the linkage sense and is in scope for handle confusion, a handle
  the library never issued, a freed handle, and an exception escaping `extern "C"`.

- **Components not published from this repository** — the external test suite and what it exercises,
  and the generated Java/Panama bindings. The C surface they are generated *from* is in scope.

---

## 8. Gaps found by writing this

The step's exit criterion asks for at least one. There are three, and they are of three different
kinds — which is itself the argument for having done it.

### F-S6-1 — a hub that required authentication did not require the channel ✅ **FIXED 2026-08-20**

**What it was.** Two conditions in `P2PeerCon` are independent and the documentation calls them one:

- `KeyXWanted()` — *does my hub require authentication* — decides whether this connection runs the
  ECDH agreement, and therefore whether it has a session cypher and a channel binding at all.
- `CanAuthSign()` — *do I hold an identity key* — decides whether this connection **signs** its login.

`AuthGateInbound()` verified the signature and passed `m_bKeyXBound ? m_KeyXBind : 0` as the
binding. A peer that never ran the agreement signs a **null-binding** transcript; the verifier,
having no agreement either, computes the same null-binding transcript, and **the signature
verifies**. The result was an authenticated session in **cleartext** on a hub whose operator had set
`RequireAuth(true)`, reported as an ordinary login.

**Who could do it.** A4 — a peer holding a key the hub lists. It needs no modified client: a hub
with `RequireAuth(false)` that *also* holds an identity key is the ordinary state of a peer
provisioned for somewhere else in the tree. It signs because it can, and exchanges no keys because
it was not asked to.

**Two things were lost, not one.** Confidentiality is the obvious half. The other is the reason the
login block's `kVersion` moved from 1 to 2: v2 exists to bind the proof to the connection it was
made on, and a null binding names no connection — so for that session the binding was not in the
transcript at all, which is precisely the proof-forwarding v2 exists to refuse.

**Measured, not reasoned.** `p2p_authchannel` runs three phases against one auth-requiring server
with **one client key and one client address**, changing exactly one call between phases:

```
[authchannel] phase 2: login accepted = YES, payload delivered = no      <- before
[authchannel] phase 2: login accepted = no,  payload delivered = no      <- after
```

See §2 for why the first version of that test passed and had to be re-pointed.

**Fixed** by one condition in `AuthGateInbound`: refuse when `KeyXWanted()` is true and the
agreement has not completed, for a login and an acknowledgement alike. **This refuses a peer that
used to be accepted.** That is a MINOR-bump break while MAJOR is 0, and it
is the intended one — the alternative is a switch whose two halves can be separated by whoever is on
the other end.

### F-S6-2 — a running hub cannot be asked whether any of this is on ✅ **FIXED 2026-08-20**

**What it is.** Asset S9, undefended. The hub's snapshot serialises `Version`, `VersionHex`,
`PumpsMax`, `QueDepth`, `Accepted`, `Throttled`, `Name`, `P2Paddr`, `P2Padom`. A connection's
serialises `P2Paddress`, `P2Padomain`, `ConMode` and the login timer. **Neither carries a single
security fact.** Not whether the hub requires authentication, not whether relay attestation is on,
not whether a revocation list is loaded or when it was last reloaded, not whether *this* connection
authenticated, not which identity it authenticated as, and not whether its cypher is installed.

`P2PeerHub::IsAuthRequired()` exists and is exported (`p2peerhub_is_auth_required`), so the hub's
*intent* is queryable from code. `P2PeerCon` has no equivalent: its two auth-adjacent members are
`GetAuthHub()` and `GetAuthStripLen()`, and while the second is non-zero after a verified login it is
a wire-stripping length used by the dispatcher, not a posture accessor — there is no
`IsAuthenticated`, no peer identity, and no cypher state. None of it reaches the diagnostic image an
operator actually reads.

**Why it is a finding and not a wish.** F-S6-1 is the proof. From the day the defaults went on
(2026-08-18) until 2026-08-20, *"this hub requires authentication"* and *"this connection is
encrypted"* were different facts, and there was no way — from inside the process or outside it — to
discover that they had come apart. The next divergence
will be just as quiet. A deployment can only confirm its posture by reading source.

**Fixed 2026-08-20**, in the shape this section proposed. `P2PeerHub::Serialise` gained ten fields —
`AuthRequired`, `AuthCanSign`, `AuthArm`, `RelayAuth`, `RelayReplay`, `SealReplay`, `RevocList`,
`RevocOk`, `RevocFresh`, `RevocEpoch` — and `P2PeerCon::Serialise` gained four: `AuthDone`,
`AuthPeer`, `KeyXDone`, `Cypher`. `P2PeerCon` gained `IsAuthenticated()`, `IsKeyXDone()`,
`GetAuthPeer()` and `IsCypherActive()`; `AuthGateInbound` records the address the verified
transcript covered, which is the identity, rather than the address the peer asked to be called.

**The compatibility question, answered rather than deferred.** Every field is APPENDED, none is
renamed, moved or retyped, and every reader in this tree selects by name — so a consumer that knows
nothing of these sees what it saw before.

**Intent, capability and enforceability are three fields, not one.** `AuthRequired` is what the
operator asked for, `AuthCanSign` is whether the hub holds a key at all, `AuthArm` is whether what
was asked for can be enforced. F-S6-1 lived in the gap between the first two, and a single "secure"
flag — however computed — would have reported that hub as fine. The same reasoning splits the
connection's four.

**Cypher is asked of the io object, not inferred from the key agreement**, and it is virtual:
`P2Peerio::IsCypherActive()` is the pointer for a transport that runs the base class's hooks, and
`P2PeerioDmx` and `P2PeerioBSTR` override it to `false` because they override both message methods
and consult neither. That reported F-S6-3; it did not close it. **It is now joined by a fifth
connection field, `OffProcess`**, added closing F-S6-3 — and the pair is the point. `Cypher=0` alone
says *not encrypted*, which is a defect on a wire and correct on the in-process DMX handoff, and no
snapshot could previously tell a reader which one they were looking at. `0/0` is DMX; `1/0` on a
keyed connection is the state the library now refuses to create.

**The gate is `p2p_authposture`**, five phases, and it was RED against the tree before the change in
both halves — *"the hub snapshot does not carry the posture at all"* and *"the connection snapshot
carries no proof state"* — and green after. Three of its phases exist only to stop a constant from
passing: auth-off and auth-on must read differently, capability and intent must read separately
(the F-S6-1 shape), and an unauthenticated connection must report all four of its fields as absent
proof.

**Writing the reader corrected the thing being read.** The first version of `RevocList` reported
`IsRevocationUsable()`, described as *"a revocation list is loaded and usable"*, and the gate
printed **1** out of a hub that had never seen a list: Usable means *"revocation is not refusing
anything"*, which is true when none is configured. A hub with no revocation would have reported its
revocation as fine. It is now `IsRevocationConfigured()` — a new accessor — with `RevocOk` carrying
the other question. This is the second time in this document that a check written to measure
something found the thing it was measuring to be differently shaped; the first was F-S6-1's gate
measuring delivery instead of the decision.

### F-S6-3 — confidentiality is inherited from a class, not enforced by a rule ✅ **FIXED 2026-08-20**

**What it is.** The cypher lives in `P2Peerio::SendP2PeerMsg` / `RecvP2PeerMsg`. Whether a transport
is encrypted therefore depends on which subclass its factory happens to construct:

| Transport | Constructs | Cypher |
|---|---|---|
| TCP (`P2PeerConWsa`) | `P2Peerio` | inherited ✅ |
| Named pipe (`P2PeerConPipe`) | `P2Peerio` | inherited ✅ |
| Serial (`P2PeerCon232`) | `P2Peerio` | inherited ✅ |
| DMX (`P2PeerConDmx`) | `P2PeerioDmx` | **overridden, absent — and correct** |
| — | `P2PeerioBSTR` | **overridden, absent — and constructed nowhere** |

`P2PeerioDmx` is right to have no cypher: it is a pointer handoff between two objects in one
process, there is no wire, and encrypting it would protect nothing. **That reasoning appears nowhere
in the tree** — it was reconstructed for this document by reading the transport, and a reader who
found the omission would reasonably conclude it was a bug.

`P2PeerioBSTR` is the live trap. It overrides both methods, calls neither hook, and **nothing
anywhere constructs it** — its `Clone()` returns a fresh one and no factory calls it. The day a
transport is wired to it, that transport is plaintext on a hub reporting `RequireAuth(true)`, and
F-S6-1's fix does not catch it: the agreement *will* have completed, the
cypher *will* be installed on the io object, and the override simply will not consult it.

**Shape of the fix, as written when this was opened.** Not "encrypt DMX". State the rule where a
subclass author will meet it — *any transport that leaves the process routes through the base
class's cypher hooks, or documents at its override why it does not* — write DMX's reason at DMX, and
either delete `P2PeerioBSTR` or make its omission loud.

**What was done, 2026-08-20.** The rule is stated over "Protocol translation" in
[`P2Peerio.h`](P2Peerio.h), where the two virtuals a subclass overrides are declared, and it is
enforced in **two** places that answer different failures.

**The declaration.** A second virtual, `LeavesProcess()`, joins `IsCypherActive()`. It defaults to
**true** — the unsafe-sounding answer, deliberately, so that a subclass which says nothing is taken
to be a wire and refused until its author has answered. True is also simply correct for the base
class, which is the wire class: TCP, named pipe and serial all construct `P2Peerio` itself. The two
answers are what the rule reads:

| Class | `LeavesProcess()` | `IsCypherActive()` | |
|---|---|---|---|
| `P2Peerio` | 1 | 1 (once keyed) | the wire, doing what a wire must |
| `P2PeerioDmx` | **0** | 0 | exempt **by declaration**, with the reason written at the declaration |
| `P2PeerioBSTR` | 1 | 0 | refused |

**The first enforcement is `P2PeerCon::KeyXDerive`**, one statement after `PostP2Pcrypto()` and
*before* `m_bKeyXDone = true`. That is the moment this finding describes — the agreement has
completed, the cypher is installed, the override will not consult it — and it is precisely the state
F-S6-1's condition cannot see, because that one tests `m_bKeyXDone` and `m_bKeyXDone` is one
statement away from true. Refusing before it is set means such a connection never reports itself
keyed, never signs a login naming a channel it does not have, and never writes a frame. Same shape
as Stage 3 step 8's arming gate: a protection that cannot be enforced does not start.

**The second enforcement is `P2Peerio::Send`**, and it needs nothing from the subclass author, which
is why it exists. `SendP2PeerMsg` records that it made the sealing decision — on both branches, so
the key-agreement exemption is a decision too — and `Send`, the one function in the class where
bytes actually leave the process, refuses to write any frame that has no such record while a cypher
is installed. The author who overrides the message methods and answers *neither* question inherits
`IsCypherActive() == the pointer`, so the declaration gate correctly waves them through; this catches
them on their first frame. It is the residual the F-S6-2 note above could only describe.

**`P2PeerioBSTR` was made loud rather than deleted.** Deleting it takes the only worked example of
the trap with it and breaks an exported surface for a class that costs nothing to keep. Kept, it
declares `1/0` — so `KeyXDerive` refuses any connection carrying it — and its constructor announces
what it takes out of the path.

**And the announcement is where this turned up something else.** The gate test did not see that
warning, and the reason was that **the default notification mask was `P2Pevotn_ERROR` alone**, so
every `EVWRN->…->Display()` in these repositories was invisible out of the box, including the
pre-existing one in `AuthGateInbound`. `WARNING` was also the one class with no mask constant, which
is part of why nobody noticed; `P2Pevotn_WARNING` now exists. The gate widens the mask itself and
then requires the warning, because a "loud" diagnostic that nothing checks is a claim.

**That was recorded as F-S6-4 and left as a decision rather than a rider, and the decision was taken
on 2026-08-20: the default mask is now `ERROR|WARNING`.** What an unconfigured deployment reports is
an operator-facing choice, which is why it was not made inside a confidentiality fix — but left
alone it meant the three warnings this tree raises were all raised into nothing. Each is an operator
**misconfiguration** carrying its own fix in an `Advice` line: a relay attestation that could not be
signed, a peer signing logins to a hub that does not require them, and the `P2PeerioBSTR`
announcement above. The usual objection to warnings-on-by-default is volume, and it does not apply
here — all three end in `SetLast()`, so a misconfigured hub costs one line per connection, not one
per message. It is a behaviour change for every existing host and is written down as an unreleased
break; the opt-out is one call.

**The gate is `p2p_confchannel`** (`MscsUnitTests/p2p_confchannel.cpp`), six phases, and it was
falsified in both directions rather than merely observed to pass — each enforcement was disabled in
turn and the test went red for that half alone. Phase 0 asserts what each io class declares, because
the rule reads exactly those answers. Phases 2 and 4 run each offending io class against an **open**
hub where no cypher exists to ignore, and both must deliver — without them a refusal is
indistinguishable from an io class that cannot talk. Phases 3 and 5 are the two gates, one call
different from their controls.

**Two things the run established that reading would not have.** First, the phase-3 class *delegates*
to the base and therefore really does seal its frames — it only lies about the hooks — so phase 3
proves the declaration is **read and acted on**, and is not a disclosure test; the test says so
rather than claiming the stronger thing. Second, with the `Send` refusal disabled, the phase-5
cleartext frame **reached the wire** and was refused at the far end by the receiving decrypt
(`On_ConCypherEx`) — so the payload fails to arrive either way, and confidentiality has already been
lost by the time it does not. Delivery is the wrong thing to read there, which is step 17's lesson
arriving a second time; the gate reads the refusal itself, out of the process diagnostic stream.
That run is also the only direct exercise this tree has of the *"every inbound frame decrypted — no
exemption by type on receipt"* row in §6, which is still marked *claim* because nothing gates it
continuously.

### And the documentation that contradicted it

A threat model that disagrees with the Readme is worth less than either, so the mapping was carried
back through the operator-facing documents. Four things did not survive:

- **`Readme.md`'s entire Security section described the pre-2026-08-18 world.** Its banner read
  *"Implemented, opt-in, and **off unless you switch it on**"*; its posture table carried 🟡 *opt-in*
  against peer identity, payload encryption and the channel binding; `RequireRelayAuth` was
  documented as *off by default* when `m_bRelayRequired` has been `true` since Stage 3 step 9; and
  *"Switching authentication on takes three calls"* named a `RequireAuth(true)` that is now the
  default. **The most-read document in the repository told a deployer the protections were off, two
  days after they were turned on and made refusal-to-arm.** Rewritten, with every row that moved
  dated, and the opt-out paragraphs reworded from *unconfigured* to *with `RequireAuth(false)`* —
  because an unconfigured hub no longer reaches that state. It does not start.
- **`SECURITY.md`'s scope section said the flat C ABI is 74 entry points.** It was **83** when this
  was written, enumerated and gated by the ABI manifest since 0.10.0, and it is **93** as of
  2026-08-22 — it moved to 87 with step 19's revocation entry points and to 93 with step 20's
  sealing ones, and `SECURITY.md` says 93 today. A scope statement that undercounts the surface
  excludes something by accident; the manifest is what makes each move a decision rather than a
  drift.
- **`Readme.md` carried two more of that same 74**, which step 15 believed it had corrected
  everywhere.
- **`Readme.md` claimed *"Linux 57/57 and Windows 54/54, re-measured 2026-08-19"*** on a day
  the production plan recorded **59/59 and 56/56** — two documents disagreeing
  about the same measurement, each reading as current. Now **Linux 60/60, Windows 57/57** in both
  configurations.

None of these is a defect in the code, and that is the point: a protection nobody can find out is on
is F-S6-2, and a protection the documentation says is *off* is the same failure one level up.

**A fifth, found on 2026-08-20 by the F-S6-2 gate and belonging to this list.** `P2PeerHub.h` said
`RefuseRelayReplay` was *"default off"*. It has defaulted to **on** since Stage 3 step 10, along
with `RefuseSealReplay`, and the snapshot printed both as 1 out of a hub that had configured
neither. Corrected in the header, and dated there. Documentation that understates a protection is
the gentler direction of the same error, and it is still an error: it is the reason an operator
turns on something already on and believes something else instead.

---

## 9. What this document does not do

- It does not claim the protections in §6 are correctly implemented. It claims they exist, says
  where, and says what checks them. Five rows have no check and are marked *claim* — the most
  interesting being that nothing injects a cleartext frame into an established session to prove the
  receive path refuses it. It does, by construction; by construction is not by measurement. **That
  one has now been seen to work exactly once**, and by accident: falsifying F-S6-3's second gate
  meant disabling the sender-side refusal, and the unsealed frame that then reached the peer was
  refused with `On_ConCypherEx`. One observation during a deliberately broken build is evidence and
  is not a gate, so the row stays a *claim*.
- It does not close the open findings tracked in the production plan, and **both findings this bullet
  named have since closed** — recorded here rather than left for a reader to discover, because a
  document that lists what is open is only as good as the day it was last checked against the
  table. F-S4-1 (a connection that is never reaped, so an accept bound counts connections *ever
  accepted*) was an availability defect against **A3**, closed 2026-08-20 and gated by
  `p2p_conreap`. F-S5-3 was a memory-model finding against **S8**, closed the same day by an
  alignment-safe read contract (`c_vBlobCopy`, `P2Pc_vBlob::Load`/`Store`) rather than by re-laying
  the packed message image — so the wire did not move, and `-fno-sanitize=alignment` came off
  `linux-gcc-asan`, where it promptly went red on `p2p_confchannel` and `p2p_authchannel`, two
  gates written *after* the finding was recorded. **A suppression does not stay scoped to the
  tests it was taken for.** Everything this document itself opened is closed too: F-S6-1, F-S6-2
  and F-S6-3 each have a gate, and F-S6-4 — §8's operator-facing default — was decided by turning
  the warning class on.
- **F-S9-1 was the last exemption in §6 and it closed on 2026-08-20**, so no protection in that
  table is now qualified by a class. `P2Pmsg_Exception` had been exempt from the relay gate
  **by class**, because the library's own undeliverable report was sourced from the address that
  could not be reached — `Ghost.Nowhere` — so it declared a source in no branch and carried no
  attestation, nobody holding a key for an address that does not exist. It was byte-for-byte the
  shape **A5** would forge, and the residual was bounded but not nothing: a peer on an ancestor
  link could tell an application a message had failed when it had not, or hand it a fabricated
  error attributed to any address. **The fix is the one this bullet used to name as future work
  — the reporting hub signs the report as itself — and executing it moved where the fix lives.**
  It is not at the gate at all: `P2PeerTarget::RouteP2PeerMsg` stamps the report with the address
  of the hub that raised it, which is both the truth and an address that hub is entitled to speak
  for, and `GateRelayInbound` then needs no special case. One hop down the plain descendant test
  admits the report with no keys anywhere; further down `AttestAppMsgOutbound` signs it as the
  origin like any other message. `p2p_reportsign` is the gate and it is shaped to reach the second
  case — a **keyless relay** in the middle, because with the reader one hop below the reporting
  hub the attestation path is never entered and a green run would say nothing about signing.
  **This is the second finding in this document whose stated fix turned out to be in a different
  file from the one the finding named** — F-S5-7 was the first — and it is worth noticing as a
  shape rather than as a coincidence.
- It does not replace `SECURITY.md`, which is the operator-facing document: how to turn things on,
  what the defaults are, and how to report a vulnerability. This is the analysis behind it.
- It is not evidence of coverage by existing. It is the *record* of one sweep, on one day, by one
  reader. §8 is what that sweep found; a second sweep by someone else is Stage 6 step 18.
