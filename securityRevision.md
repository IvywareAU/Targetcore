# Security revision: posture per hub, cost per link

*2026-09-04. A design review of where Targetcore's security switch lives, what it costs on the links
that cannot benefit from it, and how to move the decision to the link without giving up the
fail-closed properties the hub-only rule was written to protect. Line references are to the tree at
commit `a145834`.*

---

## 1. The short answer

The complaint is correct, and it is larger than it looks.

Every security switch in the tree is a property of the **hub** (`p2pauth::AuthPolicy`, one per
`P2PeerHub`), and every connection asks its hub and nothing else. A DMX connection, which is a
pointer handoff between two objects in one process, therefore runs the full login machinery under
the default posture: an ephemeral ECDH agreement, a BCrypt AES key handle that is created, held for
the life of the connection and **never consulted**, and four ECDSA operations on the login exchange.
That is the part the complaint names.

The part it does not name costs more. The two **per-message** protections, relay attestation
(`RequireRelayAuth`) and end-to-end sealing (`RequireSeal`), are also hub-wide and also default on.
On an in-process tree of hubs that means an ECDSA signature on **every** application message the
tree originates, and an ECIES seal (an ECDH key generation, an agreement, an HKDF, an AES-GCM pass
and a second ECDSA signature, plus 234 bytes) on every message that crosses more than one hop. None
of it protects anything, because every party to it shares a heap. The one protection DMX is exempt
from, the link cypher, is the cheapest of the lot.

The premise about named pipes needs one correction before it can be acted on: **as coded, the pipe
transport is not local-only.** `CreateNamedPipe` is called without `PIPE_REJECT_REMOTE_CLIENTS` and
with a null security descriptor, so the pipe is reachable over SMB from another host as
`\\host\pipe\name` wherever file sharing is on. Locality has to be made true by the transport before
a policy can be allowed to rely on it. Once it is, a pipe belongs in the same class as a loopback
TCP bind, which the tree already calls "the one restriction the kernel enforces".

The recommendation is not "a per-connection `RequireAuth`". It is:

1. **The transport declares a trust class** (`Wire`, `Local`, `InProcess`) the way `P2PeerioDmx`
   already declares `LeavesProcess()`: a virtual on the class, not a field copied by `AcceptSpawn`.
2. **The hub keeps the policy**, but keeps it **per class**: what a wire must do, what a local link
   may skip, what an in-process link may skip. The connection contributes a fact it cannot lose, and
   the hub contributes a decision that is still made in one place.
3. **Per-link protections** (agreement, cypher, signed login) are gated on the link's class.
   **End-to-end protections** (attestation, seal) cannot be, because a DMX first hop says nothing
   about the third; they are gated on whether the **destination** is in this process.
4. **Every relaxation comes with a fence.** A hub that opts its in-process links out of the
   handshake can be told to refuse a wire connection outright, so the opt-out cannot be extended
   onto a network by a later `PostP2PeerCon` that nobody re-read the policy for.
5. **Defaults do not move.** Every existing hub sees every existing link as `Wire` and behaves
   byte-for-byte as today until an operator names a class and relaxes it.

The rest of this document is the evidence and the shape of the change.

---

## 2. Where the switch lives today

### 2.1 One policy object, one question

| What | Where | What it asks |
|---|---|---|
| Should this connection run a key agreement? | `P2PeerCon::KeyXWanted()`, `P2PeerCon.cpp:2428` | `GetAuthHub()->IsAuthRequired()` and nothing else |
| Must a login carry a verified signature? | `AuthGateInbound`, `P2PeerCon.cpp:3371` | the hub's `IsAuthRequired()` |
| Must the agreement have completed before a login is accepted? | `AuthGateInbound`, `:3421` | `KeyXWanted() && !m_bKeyXDone` |
| Sign every outbound application message? | `AttestAppMsgOutbound`, `:3268` | the hub's `IsRelayAuthRequired() && CanAuthSign()` |
| Verify the origin's signature on an ancestor link? | `GateRelayInbound`, `:3085` | the hub's `IsRelayAuthRequired()` |
| Seal a body that will cross an intermediate hub? | `SealAppMsgOutbound`, `:2837` | the hub's `IsSealRequired()` |
| May the hub arm at all? | `AuthArmOrRefuse`, `P2PeerHub.cpp:2206` | the hub's `AuthArm()` |

Nothing on `P2PeerCon` contributes to any of those decisions. The connection holds runtime state
only (`m_pKeyX`, `m_bKeyXDone`, `m_cbAuthStrip`, `m_oAuthPeer`; `P2PeerCon.h:606-629`), and the
header says so: *"The POLICY lives on the hub. What lives here is per-connection RUNTIME state only."*

All of the policy defaults are **on** (`P2PAuthLogin.cpp:497-519`): `m_bRequired`,
`m_bRelayRequired`, `m_bSealRequired`, `m_bRelayReplay`, `m_bSealReplay`, and revocation is
required unless waived.

### 2.2 The reason it was put there, in the tree's own words

`SECURITY.md:205`:

> **`RequireAuth` is a hub property with no per-connection override.** That is deliberate — it is
> the one setting that must not be losable when an accepted connection is built from the listener.

`P2PeerHub.h:150-158`:

> An accepted P2PeerCon is built by AcceptSpawn from a HAND-MAINTAINED list of copied fields, so a
> security setting living on the connection is one forgotten line away from silently not applying;
> the hub link is propagated because the connection cannot work without it.

That is a real hazard and `AcceptSpawn` (`P2PeerCon.cpp:386-440`) is exactly what it describes: a
dozen explicit member copies. Any proposal has to keep the property that a forgotten line in that
function **cannot weaken** a connection. §6.4 shows how.

### 2.3 The tree already lets a transport state facts about itself

The hub-only rule is about *policy*. The tree has, since F-S6-3, been comfortable with a transport
asserting *facts* that the policy then acts on:

| Fact | Declared by | Acted on by |
|---|---|---|
| "My frames never leave this process" | `P2PeerioDmx::LeavesProcess()` returning false (`P2PeerioDmx.h:56-87`) | `KeyXDerive`'s refusal to arm a plaintext wire (`P2PeerCon.cpp:2638`) |
| "I have no notion of a source to bound" | `P2PeerCon::AcceptSourceKey()` returning 0 for DMX and serial (`P2PeerCon.h:191-196`) | the per-source accept bound |
| "This socket cannot be reached from another machine" | `SetListenScope(P2PeerConScope_Loopback)` (`P2PeerConWsa.h:41-46`) | the kernel, before a byte arrives |
| "This connection's cypher is not consulted, and that is correct" | the `Cypher` / `OffProcess` pair in the connection snapshot (`Readme.md:249`) | the operator reading the posture |

So "the transport knows something the hub does not" is already accepted. What is missing is the
step where that knowledge is allowed to **change what the hub demands**, rather than only to excuse
the transport from a rule the hub applied anyway.

---

## 3. What a DMX link pays under the defaults

### 3.1 Per connection

Under `RequireAuth(true)`, the default, a DMX connection runs the whole of §2.1's first three rows:

| Step | Where | Cost on DMX | Protects |
|---|---|---|---|
| Ephemeral P-256 key pair generated, both ends | `KeyXBegin` / `KeyXOnRequest` (`P2PeerCon.cpp:2445, 2490`) | two key generations | nothing: no wire |
| Two plaintext flights carrying the public halves | `P2Pmsg_KeyX` | two round trips through both pumps before the login can start | nothing |
| Shared secret, channel binding, HKDF | `KeyXDerive` (`:2556-2584`) | two agreements, two HKDFs | nothing |
| `P2PeerioGcm` constructed, `SetKey` creates a BCrypt AES key handle, `PostP2Pcrypto` installs it | `:2590-2610` | one kernel-backed key object **per DMX connection, for its lifetime** | nothing: `P2PeerioDmx` overrides both message methods and never reads it |
| F-S6-3 gate | `:2638` | passes, because `LeavesProcess()` is false | correct, and the reason the key object above is tolerated rather than refused |
| Login signed and verified, ack signed and verified | `LoginSend` / `AuthGateInbound` | four ECDSA operations, one nonce-cache entry per end | binds a P2P address to a connection inside one process |

The tree's own figure for one signature is "tens of microseconds" (`P2PeerHub.h:470`); a P-256
verification and an ECDH agreement are each typically two to four times that. Per connection this is
a fraction of a millisecond and, on its own, tolerable. It is not on its own.

### 3.2 Per message

These two are the cost that matters, and neither is touched by `RequireAuth(false)`:

**Relay attestation, default on.** `AttestAppMsgOutbound` runs on the single send funnel every
outbound `P2PeerMsg` passes through (`P2PeerCon.cpp:796-805`). When the hub requires attestation and
holds an identity, it ECDSA-signs **every application message sourced at or below the hub**, on
every link regardless of transport. The comment at `P2PeerCon.cpp:2738` still says *"Default OFF"*;
the constructor at `P2PAuthLogin.cpp:502` says `m_bRelayRequired(true)`, and `Readme.md:266` agrees
with the constructor. (Stale comment, noted in §9.) Verification happens only on ancestor links
(`GateAppMsgInbound`, `:2781-2790`), but the signing does not wait to find out.

**Sealing, default on.** `SealAppMsgOutbound` seals any message whose scope is not the peer on the
far end of the link (`:2896-2907`). In a hub tree that is every message that crosses more than one
hop, which is every message not addressed to a direct neighbour. Per message at the origin: a P-256
key generation, an agreement, an HKDF, an AES-GCM pass and an ECDSA signature; at the destination an
agreement, a GCM pass, a signature verification and a replay-cache insert. Plus 234 bytes on the
wire (`Sealing.md:187`: a 400-byte body becomes 634). If no agreement key is provisioned for the
destination, **the message is dropped** (`:2946-2965`). That is the right behaviour on a wire. In a
process it means an in-process tree either provisions agreement keys for hubs that share its heap
or loses every relayed message.

### 3.3 Per hub, before it may start

The arm gate (`AuthArmOrRefuse`, `P2PeerHub.cpp:2206`) refuses `CreateHub`/`SpawnHub` unless the hub
holds an identity, an allow-list naming somebody, and a revocation position. For an application
built as a dozen in-process hubs that is a dozen identity files, a dozen allow-lists that each name
the others, a dozen revocation positions, and, to keep §3.2's seal from dropping traffic, a dozen
agreement keys, all for hubs that could read each other's memory by dereferencing a pointer. The
`MixConTestAuth` example (`_Targetcore_UseExamples/SecurityExamples/MixConTestAuth/README.md:60-73`)
walks through exactly this for three hubs and it is four files per hub.

Every in-tree harness that uses DMX takes the other exit: `dmx_mesh.cpp:201,216`,
`mix_con3.cpp:199-223`, `alex_test.cpp:260`, every example in `examples.md` (its own banner at line
25 says so). `RequireAuth(false)` is the supported migration and the tree says it is *"not a
defeat"*. But it is all-or-nothing per hub: a hub with three DMX links and one TCP link either pays
§3.1 and §3.2 on all four or authenticates none of them. `MixConTest` is precisely that shape, and
it chose none.

### 3.4 What this adds up to

For an in-process tree under defaults, per application message that crosses two hops:

| Operation | Count | Protects, in-process |
|---|---|---|
| ECDSA sign (attestation, at origin) | 1 | nothing |
| P-256 keygen + ECDH + HKDF + GCM + ECDSA sign (seal, at origin) | 1 each | nothing |
| ECDH + GCM + ECDSA verify (open, at destination) | 1 each | nothing |
| ECDSA verify (attestation, at an ancestor-link receiver) | 0 or 1 | nothing |
| Bytes added | 234 + the attestation block | nothing |

Against a message pump whose whole point (`p2p_PumpPerf.md`) is microsecond-scale in-process
routing, that is the difference between the transport being the bottleneck and the crypto being it.
None of it has been measured in this tree; §8.4 proposes the measurement, and the numbers above are
counts, not timings.

---

## 4. Named pipes and loopback: the "local" class, and what has to be true first

### 4.1 The pipe is not local-only today

`P2PeerConPipe::CreateListenPipe` (`P2PeerConPipe.cpp:393-401`):

```cpp
    m_hFile = CreateNamedPipe ( m_sPipename
                              , PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
                              , PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
                              , 2, 64000, 64000, 1000
                              , NULL );                 // default security descriptor
```

Two things follow from that line:

- **Remote clients are accepted.** Without `PIPE_REJECT_REMOTE_CLIENTS` in the pipe mode, a named
  pipe server accepts a client arriving through the SMB redirector as `\\host\pipe\name`. Whether
  that happens in practice depends on the host's file-sharing and firewall state, which is outside
  this library and invisible to it, which is asset S9 in `THREAT_MODEL.md` exactly: a locality that
  cannot be read off the code.
- **The DACL is the platform's default.** For a named pipe that grants full control to the creator,
  administrators and LocalSystem, and read access to Everyone and Anonymous. Because the client opens
  `GENERIC_READ | GENERIC_WRITE` (`P2PeerConPipe.cpp:639`), a different non-administrative local
  user's open fails today, but only as a side effect of the access mask, not as a decision.

The client side opens the pipe with no `SECURITY_SQOS_PRESENT` flags (`:639-645`), so a hostile
server on the same name could impersonate the client at the default level. That is a separate
finding from this document's subject and is recorded in §9.

So the sentence "with named pipes we can communicate on a local machine only" is a statement of
intent that the transport does not currently enforce. That does not make the intent wrong. It means
the order of work is: **make the pipe provably local first, then let the policy rely on it.** The
tree took the same order with TCP: `SetListenScope(Loopback)` exists because a bind is the kernel's
promise, and only a kernel's promise is worth letting a policy read.

### 4.2 What security buys on a link that is provably local

Take the adversary table (`THREAT_MODEL.md` §5) against a link that the kernel guarantees does not
leave the machine:

| Adversary | On a wire | On a kernel-local link |
|---|---|---|
| A1 passive observer on the path | the link cypher answers it | there is no path |
| A2 active attacker on the path | cypher + channel binding | there is no path |
| A3 unauthenticated peer reaching the listener | signed login refuses it | the DACL decides who may open the endpoint; the OS has already authenticated the principal |
| A4 authenticated peer speaking as someone else | source binding | unchanged, and still cheap |
| A7 local user on the host | out of scope | out of scope, and the only adversary left |

The login signature on a local link buys a **P2P-address** identity where the OS already provides a
**Windows-principal** identity. A deployment can legitimately want both (two hubs run as the same
user but must not be confused with each other) or only the second. That is a choice, and it is the
choice `Local` exists to let an operator make. It is not a choice the library should make for them,
which is why `Local` defaults to the wire posture in §6.

### 4.3 The class has three members, not one

| Class | Member | What makes it true | Who enforces it |
|---|---|---|---|
| `InProcess` | `P2PeerConDmx` | the handoff is a pointer; `P2PeerioDmx::LeavesProcess()` is false | construction |
| `Local` | `P2PeerConPipe` | `PIPE_REJECT_REMOTE_CLIENTS` + an explicit DACL (§4.1, to do) | the kernel |
| `Local` | `P2PeerConWsa` with `SetListenScope(Loopback)` | the bind | the kernel |
| `Wire` | `P2PeerConWsa` otherwise, `P2PeerCon232` | nothing; a serial cable can be clipped | nobody |

Serial is deliberately a wire. "Directly attached hardware bus" describes where it is usually
deployed, not what an adversary with access to the cable can do to it, and RS-232 has no DACL.

`Local` is **not** `Trusted`. Another principal on the same machine is A7, and A7 is answered by the
DACL, the identity file's permissions and nothing in this library. The class says "no network
adversary can reach this", and only that.

---

## 5. Why the hub-only rule need not block this

The rule in §2.2 defends against one failure: a per-connection *setting* that an accepted connection
fails to inherit. Read closely, it defends against a setting that would **weaken** the child. A
setting the child fails to inherit, and therefore falls back to the hub's full posture for, is a
setting whose loss makes the child **stricter**. The hazard has a direction, and a design can choose
to be on the safe side of it.

Two further observations:

- The **transport class** cannot be lost by `AcceptSpawn`. A `P2PeerConDmx` service spawns a
  `P2PeerConDmx` child; the child's `TrustClass()` is a virtual on the class, and no copied field
  is involved. The exact mechanism F-S6-3 chose for `LeavesProcess()`.
- The **hub still owns the decision.** "What must a `Local` link do" is answered by the hub's policy,
  in one place, under the hub's lock, reported by `TryReadPosture`. What moves to the connection is a
  classification, not a permission.

So the property the sentence in `SECURITY.md:205` protects survives intact: there is still no
per-connection `RequireAuth`, still no field whose absence in `AcceptSpawn` opens anything. What is
added is a per-connection **fact** and a per-class **policy**.

---

## 6. Proposal

### 6.1 The trust class

```cpp
    //  P2PeerCon.h
    enum P2PeerConTrust_e
    { P2PeerConTrust_Wire      = 0   // frames leave the machine, or nobody can say they do not
    , P2PeerConTrust_Local           // frames cannot leave the machine; the kernel enforces it
    , P2PeerConTrust_InProcess       // frames cannot leave the process; construction enforces it
    };

    class P2PeerCon
    {
      //  What this TRANSPORT can vouch for.  A fact, not a setting: it is a
      //  property of the class and of the kernel objects it holds, it is
      //  never copied by AcceptSpawn, and Wire is the answer for any transport
      //  that has not said otherwise - the same default LeavesProcess() takes
      //  and for the same reason.
      virtual P2PeerConTrust_e
        TrustClass ( ) const { return P2PeerConTrust_Wire; }

      //  The operator's override, and it can only TIGHTEN.  A pipe an operator
      //  does not trust to be local is a wire; a wire an operator "trusts" is
      //  still a wire, because a promise this library cannot check is not a
      //  fact it can act on.
      void
        DemoteTrust ( P2PeerConTrust_e eNoBetterThan );

      //  What the policy reads: min(TrustClass(), demotion).
      P2PeerConTrust_e
        EffectiveTrust ( ) const;
    };
```

Per transport:

| Transport | `TrustClass()` returns | Condition |
|---|---|---|
| `P2PeerConDmx` | `InProcess` | always |
| `P2PeerConPipe` | `Local` | only when the pipe was created with `PIPE_REJECT_REMOTE_CLIENTS` and the DACL the transport writes (§6.6); `Wire` otherwise |
| `P2PeerConWsa` | `Local` | only when `GetListenScope() == P2PeerConScope_Loopback` on a service, or the client dialled a loopback address; `Wire` otherwise |
| `P2PeerCon232` | `Wire` | always |
| anything new | `Wire` | until its author answers |

The Wsa client-side case deserves one caution: a client that dialled `127.0.0.1` has a kernel
guarantee about its own socket, but the *service* it reached may be bound to every interface and
have other, remote, peers. `Local` on the client link is still correct, because the class describes
this link and not the far hub's other links. The far hub's posture is its own business, and §6.3
keeps end-to-end protections independent of link class for exactly this reason.

### 6.2 The policy, per class

```cpp
    //  P2PeerHub.h - alongside RequireAuth
    enum P2PeerLinkPolicy_e
    { P2PeerLinkPolicy_Full = 0   // agreement, cypher, signed login: what a wire gets today
    , P2PeerLinkPolicy_Open       // no agreement, no cypher, login unsigned and unverified
    };

    //  What a link of the given class must do.  Wire is Full and cannot be
    //  set to anything else - RequireAuth(false) remains the only way to open
    //  a wire, and it stays hub-wide and loud.  Local and InProcess default to
    //  Full, so an unconfigured hub behaves exactly as it does today.
    void
      SetLinkPolicy ( P2PeerConTrust_e eClass, P2PeerLinkPolicy_e ePolicy );
    P2PeerLinkPolicy_e
      GetLinkPolicy ( P2PeerConTrust_e eClass );
```

`KeyXWanted()` becomes:

```cpp
    P2PeerHub *pHub = GetAuthHub ( );
    if ( !pHub || !pHub -> IsAuthRequired ( ) )
      return false;                                   // hub-wide off, as today
    return pHub -> GetLinkPolicy ( EffectiveTrust ( ) ) == P2PeerLinkPolicy_Full;
```

and `AuthGateInbound` asks the same question in place of `IsAuthRequired()` alone, so both ends of
a link still read one switch and F-S6-1 cannot recur through this change.

For the operator that is two lines:

```cpp
    oHub.SetLinkPolicy ( P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open );  // DMX: no handshake
    oHub.SetLinkPolicy ( P2PeerConTrust_Local,     P2PeerLinkPolicy_Open );  // loopback / pipe: no handshake
```

and the TCP link on the same hub is untouched.

### 6.3 Per-link versus end-to-end, and why the seal cannot key on the link

| Protection | Scope | Gated on | Reason |
|---|---|---|---|
| Key agreement, link cypher | one hop | link class | protects the hop, and the hop is what the class describes |
| Signed login, channel binding | one hop | link class | same |
| Login deadline, accept caps | one hop | unchanged | availability, not confidentiality; a DMX link cannot be flooded from outside anyway |
| Source bound to logged-in identity | one hop | unchanged | cheap, and A4 exists in-process too (a misrouted message is still misrouted) |
| **Relay attestation** | end to end | **destination in this process** | only the origin can sign; a DMX first hop says nothing about a TCP third hop |
| **Seal** | end to end | **destination in this process** | same, and additionally the seal already skips the last-hop case by address |

The end-to-end rule needs the origin to answer "is the destination hub inside my process?" The
process already keeps a registry of every hub it holds, which is what `QueryP2PmsgExp_Hub`
enumerates under `s_oCSectionP2PmsgHub`; a lookup by address against it is the whole mechanism.

```cpp
    //  P2PeerHub.h
    //  Waive the two end-to-end protections for a destination that is a hub
    //  in THIS process.  Off by default.  Read the assumption before turning
    //  it on: it holds only if a message to an in-process hub never transits
    //  an out-of-process one, which is true of a tree whose in-process hubs
    //  form one subtree and is NOT guaranteed otherwise.
    void
      WaiveEndToEndInProcess ( bool bWaive );
```

`SealAppMsgOutbound` and `AttestAppMsgOutbound` then add one early return each: waiver on, and the
scope address resolves to a hub in this process. `GateRelayInbound` needs the matching receive-side
exemption, and it must be keyed on the same registry lookup rather than on the link class, or a
remote ancestor could forward an unattested message down a DMX link and be admitted.

The assumption in the comment is real and is the one thing in this proposal that cannot be made
fail-closed by construction. A tree with hubs A and C in one process and B on another host, wired
A-B-C, would send A's message to C in clear over the wire with the waiver on. The honest options are
to document it as a deployment rule (in-process hubs form one address subtree; the tree's own
routing then never leaves the process for an in-process destination), or to leave the waiver out of
the first iteration and take only §6.2. The recommendation is to ship §6.2 first and measure
(§8.4) before deciding whether §6.3 is worth its assumption.

### 6.4 Fail-closed properties, checked one by one

| Hazard | Answer |
|---|---|
| `AcceptSpawn` forgets to copy a field | there is no field. The class is virtual; the demotion is the only per-object state and forgetting to copy it makes the child **less** trusted, never more |
| A new transport is written and says nothing | `TrustClass()` defaults to `Wire`, the same default `LeavesProcess()` takes |
| A pipe on a host with SMB sharing on | `TrustClass()` returns `Local` only when the transport itself set `PIPE_REJECT_REMOTE_CLIENTS`; an old binary, or a pipe created any other way, is `Wire` |
| An operator trusts a link the library cannot verify | `DemoteTrust` only tightens; there is no `PromoteTrust` |
| A hub opened for in-process links is later handed a TCP connection | `Wire` policy is `Full` and cannot be set otherwise, so the TCP link authenticates in full; and see the fence below |
| Someone reads `Cypher=0` on a snapshot and cannot tell a defect from a decision | the snapshot gains `Trust` per connection and `LinkPolicy` per class per hub; `Cypher=0` on an `InProcess` link under `Open` is then a stated decision |
| Both ends disagree on the class | the key exchange is initiated by the client's `KeyXWanted()` and required by the server's `AuthGateInbound`; if either end says `Full`, the agreement is demanded, and a client that skipped it against a server that wanted it is refused exactly as F-S6-1's fix refuses it today |

**The fence.** A hub that relaxes its in-process links is one `PostP2PeerCon` away from carrying a
wire it did not plan for. `RequireAuth(false)` has always had this exposure; this proposal gives an
operator a way to close it:

```cpp
    //  Refuse to hold a connection below this class.  A hub that exists to
    //  route inside a process says InProcess here, and a P2PeerConWsa posted
    //  to it later is refused at PostP2PeerCon with a diagnostic, rather than
    //  authenticated in full and quietly making the hub a network endpoint.
    void
      RequireTrustAtLeast ( P2PeerConTrust_e eClass );
```

This is the piece that makes the opt-out safer than today's, not merely cheaper: `RequireAuth(false)`
opens every link the hub will ever hold, while `SetLinkPolicy(InProcess, Open)` plus
`RequireTrustAtLeast(InProcess)` opens links that cannot leave the process and refuses the rest.

### 6.5 The arm gate

`AuthArmOrRefuse` runs before any connection is posted, so it cannot know which classes the hub will
carry. Two consistent answers:

- **Leave it.** A hub that requires auth on any class needs an identity, and every class defaults
  to `Full`. A hub that has set every class it will carry to `Open` and fenced the rest with
  `RequireTrustAtLeast` still holds `RequireAuth(true)` and is still refused for want of a key it
  will never use. Correct, and annoying.
- **Let the fence inform the gate.** If `RequireTrustAtLeast(c)` is set and every class at or above
  `c` is `Open`, the hub can never demand a signature from anybody, and `AuthArm()` returns a new
  `ArmNotRequiredByPolicy` in place of a refusal. The test the `ArmResult` note applies (does the
  unprovisioned state refuse everyone, or one narrow shape?) gives the same verdict as for
  `RequireAuth(false)`: it refuses nobody, so there is nothing to gate.

The second is recommended. It is the only path that lets an in-process-only hub start with no key
files and no `RequireAuth(false)`, and it is loud about why: the posture shows `AuthRequired=1`,
`Fence=InProcess`, `LinkPolicy[InProcess]=Open`, which reads as a decision rather than an omission.

### 6.6 Transport work the proposal depends on

**`P2PeerConPipe`**, before it may return `Local`:

- `PIPE_REJECT_REMOTE_CLIENTS` in the pipe mode of `CreateNamedPipe`.
- An explicit security descriptor. The least surprising default is "the creating user only"
  (owner full control, nothing for Everyone), with a setter for deployments that need a service
  account and an interactive user to share a pipe. Today's null descriptor should be kept as an
  explicit, named, `Wire`-class option rather than deleted, so an existing deployment does not stop
  working on upgrade.
- On the client, `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` on the `CreateFile`, so a rogue
  server on the same pipe name cannot impersonate the client. Independent of this document, and
  cheap.
- What the Linux build of `P2PeerConPipe.cpp` does was not examined in this pass. `CMakeLists.txt:73`
  compiles it on both platforms. Whatever it maps to (a FIFO, a Unix-domain socket) has its own
  notion of locality and its own permission model, and `TrustClass()` must answer for that platform
  separately.

**`P2PeerConWsa`**: a `TrustClass()` override reading `m_eListenScope` on a service and the dialled
address on a client. The accepted child is spawned from the service and inherits the class through
the virtual, so no `AcceptSpawn` line is needed; the `Dual` family refusal of a loopback scope
(`P2PeerConWsa.h:80-84`) already keeps "loopback" honest.

**`P2PeerConDmx`**: an override returning `InProcess`. Nothing else.

### 6.7 The C ABI

The whole hub surface is mirrored in `Targetcore_c.h`, and the security calls were added there
deliberately (`:227-352`). This adds:

```c
    P2PC_API void p2peerhub_set_link_policy       (P2PeerHubHandle h, int trustClass, int policy);
    P2PC_API int  p2peerhub_get_link_policy       (P2PeerHubHandle h, int trustClass);
    P2PC_API void p2peerhub_require_trust_at_least(P2PeerHubHandle h, int trustClass);
    P2PC_API void p2peerhub_waive_end_to_end_in_process(P2PeerHubHandle h, int waive);
    P2PC_API int  p2peerconwsa_get_trust_class    (P2PeerConWsaHandle h);
```

plus the `Trust` and `LinkPolicy` fields wherever the posture is rendered. The COM, .NET, Panama and
Python surfaces in the sibling repositories follow from the C one and were not surveyed here beyond
noting that none of them currently exposes `RequireAuth` by name.

---

## 7. What this does not do, and what it makes worse

- **It does not make `Local` mean trusted.** §4.3. The DACL and the identity file's permissions are
  the controls against another principal on the host, and both remain the operator's.
- **It does not remove the seal's assumption** (§6.3). If the waiver ships, the deployment rule it
  depends on has to be written where an operator will read it, and `SECURITY.md` has a section for
  exactly that kind of sentence.
- **It adds a second axis to the posture.** F-S6-2 argued that intent, capability and enforceability
  must be separately readable. This adds class and per-class policy to intent, and the snapshot has
  to carry both or the design fails the finding it is built on.
- **It widens `AuthGateInbound`'s reasoning.** Today the gate has one input. After this it has the
  hub's switch, the class policy and the link's effective class, and the F-S6-1 shape (two ends
  reading different halves of one switch) is the regression to test for first. §8.3 names it.
- **A demoted trust on a service** must propagate to children or it means nothing on a listener.
  That is one copied field in `AcceptSpawn`, and it is the one line in this proposal that *can* be
  forgotten. Its failure mode is the safe direction (the child is not demoted, so it reads the class
  the transport vouches for), but the test in §8.3 pins it anyway.

---

## 8. Migration, compatibility, verification

### 8.1 Compatibility

No default moves. Every transport answers `Wire` until its override lands, and every class's policy
is `Full`. A hub compiled and configured against today's tree behaves identically, including the
arm gate. Under the versioning policy this is a MINOR addition with no break, and the pipe DACL
change is the one place a break could hide: a deployment sharing a pipe between two accounts stops
working if the default descriptor tightens, which is why §6.6 keeps the null descriptor reachable by
name.

### 8.2 Order of work

1. `TrustClass()` virtual and the three overrides, with `P2PeerConPipe` returning `Wire` until its
   own step lands. Posture fields. No behaviour change yet.
2. `SetLinkPolicy` and the rewired `KeyXWanted()` / `AuthGateInbound`. This alone removes §3.1 from
   DMX and is the smallest change that answers the original complaint.
3. `RequireTrustAtLeast` and the arm-gate result.
4. Pipe locality (§6.6), then its `TrustClass()` override.
5. Measure (§8.4). Decide on §6.3 with numbers.

### 8.3 The gate test

`p2p_linktrust`, in the shape of `p2p_confchannel`: every enforcement disabled in turn and the test
required to go red for that half alone.

| Phase | Setup | Must observe |
|---|---|---|
| 0 | each transport's `TrustClass()` | the table in §6.1, asserted by value |
| 1 | DMX, defaults | agreement runs, cypher object installed, login signed: today's behaviour, unchanged |
| 2 | DMX, `SetLinkPolicy(InProcess, Open)` both ends | no `P2Pmsg_KeyX` on the link, no cypher object, login carries no auth block, payload delivered |
| 3 | DMX, `Open` on the client hub only | server refuses the login, and names the class in the diagnostic |
| 4 | TCP on a hub with `SetLinkPolicy(InProcess, Open)` | TCP link authenticates in full |
| 5 | `RequireTrustAtLeast(InProcess)`, then `PostP2PeerCon` of a `P2PeerConWsa` | refused at post |
| 6 | pipe created without `PIPE_REJECT_REMOTE_CLIENTS` | `Wire`, full handshake regardless of policy |
| 7 | pipe service demoted to `Wire`, accepted child | child reads `Wire` |
| 8 | in-process-only hub, no key files, fence set, every class `Open` | arms with `ArmNotRequiredByPolicy` |

Phase 3 is the F-S6-1 regression and is the one to write first.

### 8.4 The measurement that has not been made

Nothing in the tree times the security path; the figures in §3 are operation counts. Before §6.3 is
decided, one run of `dmx_mesh` extended to three in-process hubs in a chain, N messages of a fixed
size, under four postures: everything off; `RequireAuth` only; plus attestation; plus seal. Report
messages per second and CPU time per message. The result decides whether the end-to-end waiver is
worth its assumption or whether §6.2 alone recovers what matters.

### 8.5 Documents that change

| File | Line | Change |
|---|---|---|
| `SECURITY.md` | 205 | the sentence becomes "no per-connection *policy*; a per-connection *class*, and here is why the distinction holds the same property" |
| `SECURITY.md` | 80-82 | "appropriate use" lists pipe as single-machine; qualify until §6.6 lands |
| `THREAT_MODEL.md` | §3, "One transport is not a wire" | three classes, and the pipe finding |
| `THREAT_MODEL.md` | §6.1 | a row for the fence and one for pipe locality, each with its gate |
| `P2PeerHub.h` | 150-158 | the `AcceptSpawn` argument stays; add why a class is not a setting |
| `examples.md` | 25 | the banner offers `SetLinkPolicy` for the in-process examples instead of `RequireAuth(false)` |

---

## 9. Incidental findings

Recorded because they were met on the way and each is one line to fix or one line to file.

1. **Stale comment.** `P2PeerCon.cpp:2738` says relay attestation is *"Default OFF, and OFF is
   byte-for-byte the old exemption"*. `P2PAuthLogin.cpp:502` initialises it true and `Readme.md:266`
   says on since 2026-08-18. The comment describes the tree before Stage 3 step 9.
2. **A key object per DMX connection.** `KeyXDerive` constructs a `P2PeerioGcm`, creates its BCrypt
   key handle, and installs it on a `P2PeerioDmx` that never consults it. It lives until the
   connection is destroyed. Harmless, wasteful, and gone under §6.2.
3. **Pipe client opens without SQOS.** `P2PeerConPipe.cpp:639` passes no
   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the server end may impersonate the client
   at the default impersonation level. Separate from locality; should be fixed with it.
4. **Pipe server accepts remote clients and takes the default DACL.** §4.1. This one contradicts
   the tree's own "appropriate use" list and belongs in `THREAT_MODEL.md` §8 as a finding whether or
   not the rest of this document is taken up.
5. **Every in-tree DMX harness opts out.** Not a defect, but it means the DMX transport under
   `RequireAuth(true)` is exercised by `p2p_confchannel` phase 0 and nothing else, which is why the
   key-object waste in item 2 has never shown up as a number anywhere.
