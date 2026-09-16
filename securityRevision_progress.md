# securityRevision_progress.md — execution log

Execution log for [securityRevision.md](securityRevision.md). Tracks the implementation of
**§8.2 order of work, steps 1 to 5** — the transport trust class, the per-class link policy, the
fence with its arm-gate result, pipe locality, and the §8.4 measurement with the §6.3 waiver
decision it was deferred for. **All five steps are done.** Step 5 changed no library source: it is
a harness, a measurement and a recommendation.

Convention follows the other `*_progress.md` docs in this tree: every claim carries the file, the
build result, and the test evidence, or it is marked unverified.

Baseline tree: commit `a145834` (`master`), the same tree the design document's line references
were taken against.

---

## Scope taken

| Step | From §8.2 | Status |
|---|---|---|
| 1 | `TrustClass()` virtual + the transport overrides; `P2PeerConPipe` stays `Wire`; posture fields. No behaviour change. | ✅ **done 2026-09-04** |
| 2 | `SetLinkPolicy` / `GetLinkPolicy` on the hub; rewired `KeyXWanted()` and `AuthGateInbound`. | ✅ **done 2026-09-04** |
| — | §6.7 flat C ABI (taken with step 2 — see *Scope taken beyond §8.2* below) | ✅ **done 2026-09-04** |
| — | §8.5 documentation (`SECURITY.md`, `THREAT_MODEL.md`) | ✅ **done 2026-09-04** |
| **8.3** | **`p2p_linktrust`, the gate test** | ✅ **done 2026-09-04 — 7 phases, falsified twice** |
| **3** | **`RequireTrustAtLeast` + `ArmNotRequiredByPolicy`; §8.3 phases 5 and 8** | ✅ **done 2026-09-04 — falsified three times** |
| **4** | **Pipe locality (`PIPE_REJECT_REMOTE_CLIENTS`, DACL, client SQOS), then `P2PeerConPipe::TrustClass()`; §8.3 phases 6 and 7** | ✅ **done 2026-09-04 — falsified three times** |
| **5** | **The §8.4 measurement (`p2p_linkcost`), then the §6.3 end-to-end waiver decision** | ✅ **done 2026-09-04 — measured twice, decided** |
| **6.3** | **The end-to-end waiver — `WaiveEndToEndInProcess`, `IsP2PmsgHubInProcess`, the three call sites, the flat C pair, `p2p_e2ewaive`** | ✅ **done 2026-09-04 — 26 checks, falsified three times** |

The two end-to-end protections (relay attestation, seal) are **not** touched by any of the five
steps. They are gated on the destination, not the link, and §6.3 says to ship §6.2 first and measure
before deciding. So a DMX link under `SetLinkPolicy(InProcess, Open)` still pays §3.2's per-message
cost after this pass; only §3.1's per-connection cost goes away.

**Step 5 measured how those two halves actually divide, and the design document's accounting was
the wrong way round.** §3.1's per-connection cost is what step 2 removed and it is ~0 per message;
§3.2's per-message cost is **93% of the total** and nothing shipped in this pass touches it. The
recommendation — build §6.3 — is in *Step 5* below with the numbers it rests on.

---

## What was measured

| | Result |
|---|---|
| `Targetcore(2026).sln`, Debug \| x64, MSBuild 17 | **clean**, exit 0, DLL produced |
| `Targetcore(2026).sln`, Release \| x64 | **clean**, exit 0, DLL produced |
| `.github/ci/check_repo_invariants.py` | **all seven sections green**; **99** flat C symbols, header and manifest agree (step 4 adds none — the flat surface has no pipe handle) |
| `dumpbin /EXPORTS` on the Release DLL | all six new flat-C symbols exported; `RequireTrustAtLeast` and `GetRequiredTrust` present as C++ exports |
| CMake tree, `windows-msvc` preset, Debug, full build | **clean**, exit 0 |
| CMake tree, Release, `p2p_linktrust` and its dependencies | **clean**, exit 0 |
| `ctest -C Debug -L security`, after step 4 | **36/37**, 245 s. The one failure is `p2p_linktrust`, and the terminate handler added in this step says why in the log: `PostP2PmsgCon — P2PmsgCon object already posted`, unhandled on a pump thread. **Not a step-4 assertion** — see *the flake*, below. Earlier runs in this pass reached 37/37 |
| `p2p_linktrust` alone, Debug, repeated | **22 runs across the step**; every run that reached a phase found that phase green. The failures are all the one fault above, in phases 5, 6, 7 and 9 — three of which no step in this pass touches |
| `p2p_linktrust`, phases 7 and 8 | **green in every run that reached them** — 8 of 8 in Debug, 5 of 5 in Release |
| `p2p_linktrust`, phases 0, 9 and 10 (step 4) | **green in every run that reached them** — 4 of 4; phase 0's four pipe declarations green in every run, including the ones that later died |
| `p2p_linktrust` falsified **eight** times in total | **red every time, on the phase and the row written for it** — two from the §8.3 pass, three from step 3, three from step 4 |
| CMake tree, Debug **and** Release, `p2p_linkcost` (step 5) | **clean**, exit 0, first compile in both configurations |
| `p2p_linkcost`, Release, N = 20 000 × 256 B, **three runs** | msg/s — A 30 183 / 29 322 / 30 591, B 30 071 / 31 584 / 31 777, C 7 532 / 7 474 / 7 658, D 1 526 / 1 488 / 1 514, E 1 520 / 1 447 / 1 517. **Reproducible to ~4%, identical ordering in all three.** Full table in *Step 5* |
| `p2p_linkcost`, the origin link read off the connection | A `keyx=0 auth=0`; B/C/D `keyx=1 auth=1`; E `keyx=0 auth=0`; `cyph=0` in **every** row. So B really authenticated, E's `SetLinkPolicy` really took, and a DMX link never installs a cypher — §9's finding 2, measured |
| `p2p_linkcost` as a registered ctest, Debug, N = 4 000 | **passes**, 21.8 s, label `measure`. Every posture delivered every message |
| `ctest -C Debug -L security` still selects **37** tests | step 5 adds no test to that label — `p2p_linkcost` is `measure`, so a `-L security` count stays comparable across the whole pass |
| `.github/ci/check_repo_invariants.py`, after §6.3 | **all seven sections green**; **101** flat C symbols, header and manifest agree |
| `p2p_e2ewaive`, Debug (§6.3) | **26 checks, 0 failed, first run**; compiled first try in Debug and Release |
| `p2p_e2ewaive` falsified **three** times | **red every time, and only on the rows written for it** — the at-or-below match (2 rows), the send-side branch removed (1 row), the default flipped on (3 rows) |
| `ctest -C Debug -L security` after §6.3 | selects **38** — `p2p_e2ewaive` is the one added, and it is the first test this pass has added to that label since §8.3. **37/38**, 246 s; the one failure is `p2p_linktrust`, and it is finding 7 — see *The flake, re-measured* below |
| **The flake, attributed rather than assumed** | `p2p_linktrust` on the **baseline tree** (`1a48340`, this work stashed, rebuilt): **3 pass / 3 fail in 6 runs**, dying in three *different* phases (9, 5, 8). On the §6.3 tree: 1 pass / 3 fail in 4. Indistinguishable at this sample size, and **the fault is reproducible without a line of this change present** |

Warnings: no new ones. The build's existing C4100/C4996/C4244 noise is unchanged.

---

## Step 1 — the trust class

### The enum

`P2PeerCon.h`, beside `P2PeerConMode_e`:

```cpp
typedef enum
{
    P2PeerConTrust_Wire      = 0,      // leaves the machine, or nobody can say it does not
    P2PeerConTrust_Local     = 1,      // cannot leave the machine; kernel
    P2PeerConTrust_InProcess = 2,      // cannot leave the process; construction
} P2PeerConTrust_e;
```

**The order is load-bearing.** Every relaxation is expressed as "no worse than", so a lower value
is always the stricter reading and `EffectiveTrust()` is a `min()`. Adding a class later means
choosing where it sits in that order, not just appending a name.

### On the connection

| Member | Kind | Where |
|---|---|---|
| `virtual P2PeerConTrust_e TrustClass() const` | **virtual, returns `Wire`** | `P2PeerCon.h` |
| `void DemoteTrust(P2PeerConTrust_e)` | tightens only; no promote exists | `P2PeerCon.cpp` |
| `P2PeerConTrust_e EffectiveTrust() const` | `min(TrustClass(), m_eTrustCeiling)` | `P2PeerCon.cpp` |
| `m_eTrustCeiling` | initialised to `InProcess` = *no ceiling* | `RenderThisSafe()` |

`DemoteTrust` is one line — `if (e < m_eTrustCeiling) m_eTrustCeiling = e;` — and that one line is
the whole guarantee: no sequence of calls, and no later caller, can hand a connection back a class
it was denied.

### Per transport

| Transport | Answers | Why |
|---|---|---|
| `P2PeerConDmx` | `InProcess`, unconditionally | the handoff is a pointer between two objects on one heap |
| `P2PeerConWsa` | `Local` when the kernel reports the peer on loopback, else `Wire` | see the departure below |
| `P2PeerConPipe` | `Wire` (base default, no override) | deliberate — the pipe is not local-only as coded; F-SR-1 |
| `P2PeerCon232` | `Wire` (base default, no override) | a serial cable can be clipped, and RS-232 has no DACL |

### One departure from the design document, and the reason for it

**§6.6 says the Wsa override should read `m_eListenScope` on a service and the dialled address on a
client, and that "the accepted child is spawned from the service and inherits the class through the
virtual, so no `AcceptSpawn` line is needed". That is wrong for this transport**, and it was
checked rather than assumed: `P2PeerConWsa::AcceptSpawn` copies `m_eFamily` and the socket and
**does not copy `m_eListenScope`**. An accepted child of a loopback-bound service would therefore
have read `Any` and answered `Wire` — so the feature would have been dead on exactly the side that
carries the traffic, or it would have needed the copied field that §6.4's first row promises there
is none of.

What is implemented instead asks the **kernel**:

```cpp
// P2PeerConWsa::TrustClass()
if ( m_oSocket != INVALID_SOCKET && getpeername(...) succeeds )
    return loopback-peer ? Local : Wire;    // the kernel's own answer
if ( m_eListenScope == P2PeerConScope_Loopback )
    return Local;                           // a service, or a client that has not dialled
return Wire;
```

This is strictly better on four counts:

1. **Nothing is copied.** The socket is carried because the connection cannot work without it —
   which is the same argument `P2PeerHub.h:150-158` makes for propagating the hub link, and the
   reason it is not a hazard.
2. **It is uniform** over a client that dialled `127.0.0.1`, a service's accepted child, and a
   connection nobody configured.
3. **It is the same reading the accept allow-list is already tested against** (`getpeername`,
   normalised through `NormaliseP2PeerConSockaddr`), so a `::ffff:127.0.0.1` on a dual-stack socket
   is the v4 loopback it stands for and not a sixteen-byte address that fails to match `::1`.
4. **A loopback peer is a kernel fact, not a claim on the wire.** An off-host packet sourced from
   `127.0.0.0/8` is a martian and is dropped by the stack before anything here sees it.

The listen scope survives only as the fallback for a socket with **no peer** — a service object, or
a client before it dials. Neither carries traffic, so what it answers there is a posture reading
rather than a gate input.

New static helper `IsP2PeerConSockaddrLoopback()` in `P2PeerConWsa.cpp` — `127.0.0.0/8` and
`::1/128`, deliberately the same two prefixes `AllowAcceptLoopback()` writes into the accept
allow-list.

### The one copied field, and it is copied

§7's last bullet is right that a demotion on a service must reach its children. `AcceptSpawn` now
carries `m_eTrustCeiling`, with a comment saying what losing that line would cost. The **class** is
not there and cannot be — it is a virtual — which is the whole reason this feature is allowed to
sit beside `SECURITY.md:205`.

### Posture

**Connection** (`P2PeerCon::Serialise`, appended after `OffProcess`, nothing renamed or moved):

| Field | Value |
|---|---|
| `TrustClass` | what the transport vouches for: 0 / 1 / 2 |
| `Trust` | ...after the operator's demotion — **what the policy actually read** |

Two fields and not one, for the reason there are five security fields already: they agree on every
connection nobody has demoted, and a reader who saw only the second could not tell a transport that
*answered* `Wire` from one that was *held down* to it.

**Hub** (`Posture::anLinkPolicy[3]`, rendered as `LinkPolWire` / `LinkPolLocal` / `LinkPolProc`):
three named fields rather than one packed number, because a consumer selects by name and the one
interesting question — *which class did they relax* — should be readable rather than decoded.
`LinkPolWire` is always 0 and is rendered anyway: a field that is present and pinned says the wire
cannot be opened here, where an absent one says nothing.

Read from the **live** policy inside `TryReadPosture`, not from a cached copy — the rule that
accessor already states for everything else in it.

---

## Step 2 — the per-class link policy

### Where it lives

`p2pauth::AuthPolicy`, as `unsigned char m_aLinkPolicy[3]`, with **int-typed** accessors
`SetLinkPolicy(int, int)` / `GetLinkPolicy(int) const`.

Ints and not the enums on purpose: `P2PAuthLogin.cpp` is one of the three TUs that deliberately
compiles with no `stdafx.h` and no MFC, because the login transcript *is* the wire and a byte of
drift between the CNG and OpenSSL builds is a login that works only within one operating system.
Both enums live in headers that reach MFC. `P2PeerHub` holds the typed surface and is the only
caller.

`std::memset(m_aLinkPolicy, 0, ...)` in the constructor rather than three assignments: 0 is
`Full`, so a fourth class added later inherits the strict default **by existing** rather than by
being remembered.

### The hub surface

```cpp
void               SetLinkPolicy ( P2PeerConTrust_e, P2PeerLinkPolicy_e );
P2PeerLinkPolicy_e GetLinkPolicy ( P2PeerConTrust_e );
```

Both take `m_oCSectionHub`, like every other setting there. `GetLinkPolicy` on a hub with no policy
object answers `Full` — the same fail-closed reading `IsAuthRequired()` gives.

**Class 0 cannot be opened.** The refusal is in `AuthPolicy::SetLinkPolicy`, one layer below both
the C++ and the flat-C entry points, so neither has to remember it. An out-of-range class is
ignored on write and answers `Full` on read.

### The rewiring — one predicate, two callers

The design document's §6.4 last row is the risk this creates: two ends of a link reading different
halves of one switch is *precisely* what F-S6-1 was, and this change adds a half. So the halves are
put together in exactly one place:

```cpp
bool P2PeerCon::AuthLinkRelaxed ( )     // hub requires auth AND this class is Open
bool P2PeerCon::KeyXWanted      ( )     // pHub->IsAuthRequired() && !AuthLinkRelaxed()
```

and every gate calls one of those rather than composing it again:

| Site | Was | Now |
|---|---|---|
| `KeyXWanted()` (initiator: run the agreement?) | `pHub->IsAuthRequired()` | composed |
| `AuthGateInbound` "not enforcing?" (verifier: demand a signature?) | `!pHub->IsAuthRequired()` | `!KeyXWanted()` |
| `AuthGateInbound` channel gate | `KeyXWanted() && !m_bKeyXDone` | unchanged — now class-aware for free |
| `Login()` deferral | `KeyXWanted() && !m_bKeyXDone` | unchanged — same |
| `LoginSend()` signing | `pAuthHub->CanAuthSign()` | `... && !AuthLinkRelaxed()` |
| `LoginAck` signing | `m_bAuthNonce && ...` | **unchanged, and correct without a change** |

**The signing change is not optional and is worth stating.** Under `Open` there is no agreement, so
`m_bKeyXBound` is false and a login signed anyway would pass a **null binding** into the
transcript — a proof naming no connection, which is F-S6-1's state reached deliberately instead of
by accident. `Open` therefore means all three of agreement, cypher and signature, or none; there is
no call that takes one and leaves the others.

The ack needed nothing: server-side `m_bAuthNonce` is set **only** by a successful verification in
`AuthGateInbound` (checked — it is assigned in exactly two places), and a relaxed link returns
before reaching it.

**`RequireAuth(false)` is untouched by all of this.** `AuthLinkRelaxed()` requires
`IsAuthRequired()` to be *true*, so a hub that turned the switch off outright signs and verifies
exactly what it did before. That is what keeps an existing deployment byte-identical, and it is
checked by the first condition of the predicate rather than argued for.

### Everything that was NOT rewired, and why

Grepped for every `IsAuthRequired()` / `IsRequired()` caller in the tree afterwards. The only two
per-link consumers are the two above. The rest are correct as they stand:

| Site | Reads | Correct because |
|---|---|---|
| `SealAppMsgOutbound` | `IsSealRequired()` | end-to-end, keyed on destination — §6.3, deferred |
| `AttestAppMsgOutbound`, `GateRelayInbound` | `IsRelayAuthRequired()` | same |
| `AuthArmOrRefuse` | `AuthArm()` | the arm gate is §8.2 step 3, deferred |
| `TryReadPosture`, `p2peerhub_is_auth_required` | `IsRequired()` | reporting intent, which has not moved |

---

## Scope taken beyond §8.2 steps 1–2, and why

Two things were taken that the numbered steps do not name. Both are recorded here rather than
folded in silently.

**§6.7, the flat C ABI (4 symbols).** Taken because this tree's own stated rule is that a hub
security setting which is not reachable through `Targetcore_c.h` has no migration at all for a
redistributed build — the argument written into that header three times over, on 2026-08-18,
2026-08-21 and again for sealing. Nothing here changes a default, so a C consumer needs nothing new
to keep working; what it would otherwise lack is the ability to *use* the feature.

```c
p2peerhub_set_link_policy   (h, trustClass, policy)
p2peerhub_get_link_policy   (h, trustClass)
p2peerconwsa_get_trust_class(h)            // EffectiveTrust(), not TrustClass()
p2peerconwsa_demote_trust   (h, trustClass)
```

No `_u8` twins — every parameter is an int. `.github/ci/abi-flat.manifest` updated (93 → 97) and
both halves of the ABI gate re-run.

**§8.5, the documentation.** `SECURITY.md:205` is the sentence this change could most easily make
into a lie, so it was corrected in place: the "no per-connection override" claim is kept, *and* the
distinction that keeps it true is written next to it. `THREAT_MODEL.md` §3 gained the three-class
table, §6.1 two rows, and §8 the pipe finding.

---

## §8.3 — `p2p_linktrust`, the gate

`MscsUnitTests/p2p_linktrust.cpp`, registered in `MscsUnitTests/CMakeLists.txt` beside
`p2p_confchannel` — its sibling by the design document's own words — with `LABELS security`,
`TIMEOUT 600` and six consecutive loopback ports locked. It carries **nine** phases now; the two
step 3 added are written up under *Step 3* below, and 0–6 are here.

Seven phases at this point. Every one of them was **observed**, not reasoned:

| # | Setup | Required | Observed |
|---|---|---|---|
| 0 | each class constructed directly, asked `TrustClass()` | Dmx `InProcess`; unbound Wsa `Wire`; loopback-scoped Wsa `Local`; Pipe `Wire`; 232 `Wire` | all five as required |
| 0 | `DemoteTrust` algebra on one connection | tightens, and a call naming a *higher* class does nothing | holds through four calls in both directions |
| 1 | DMX, both ends default | full handshake | `login=YES payload=YES keyx=1 cypher=0 authed=1 trust=InProcess` |
| 2 | DMX, `SetLinkPolicy(InProcess, Open)` **both** ends | delivered, **no** handshake | `login=YES payload=YES keyx=0 cypher=0 authed=0 trust=InProcess` |
| 3 | DMX, `Open` on the **client** hub only | server refuses | `login=no payload=no` |
| 4 | TCP loopback, hubs with `InProcess` opened and nothing else | authenticates **in full** | `login=YES payload=YES keyx=1 cypher=1 authed=1 trust=Local` |
| 5 | TCP loopback, `Local` opened, no demotion | delivered, no handshake | `login=YES keyx=0 authed=0`, child `Local/Local` |
| 6 | phase 5 + `DemoteTrust(Wire)` on the **service** | child reads `Local/Wire`, server refuses | `child=Local/Wire`, `login=no payload=no` |

**Phase 1's `cypher=0` is asserted, not tolerated.** DMX installs a cypher on a `P2PeerioDmx` that
overrides both message methods and consults neither — F-S6-3's one legitimate exemption — so a `1`
there would mean the transport changed under the test, and the phase says so by name.

**Phase 4 is the containment phase and it is the one most worth having.** Both hubs opened
`InProcess` and nothing else; the socket's class is `Local`, and it completed the full handshake.
A relaxation that leaked across classes would have passed phases 1–3 and left a hub as a network
endpoint nobody opened.

**Phase 6 is the gate on the one line that can be forgotten.** It is phase 5 plus a single
`DemoteTrust(Wire)` on the service before it is posted. The accepted child must inherit that
ceiling through `AcceptSpawn`, read `Wire`, and — because the wire's policy is `Full` and cannot be
set otherwise — have its login refused by the very hub that accepted an identical one a phase
earlier.

### Falsified, twice, once per enforcement

A gate nobody has seen go red is a claim. Both edits were made, built, run, and reverted; the suite
was green again afterwards.

| Falsification | Removed | Phase that went red | What it printed |
|---|---|---|---|
| **A** | the `m_eTrustCeiling` copy in `P2PeerCon::AcceptSpawn` | **6** | child read `Local/Local`, login accepted → *"THE DEMOTION DID NOT REACH THE ACCEPTED CHILD"* |
| **B** | `AuthGateInbound`'s `!KeyXWanted()`, back to `!IsAuthRequired()` | **2** | `login=no payload=no` on a link both hubs had opened → *"an in-process link whose hub opened its class did not get through"* |

B is worth reading twice, because the direction is not the obvious one. Reverting that gate does
not make the server *lax* — it makes it demand a signature from a peer its own operator told not to
send one, so the relaxed link stops working. Both halves of the switch have to be read at both
ends, which is F-S6-1's lesson arriving from the other side.

### What phase 3 does not isolate, stated because it changes what green means

A client that has relaxed the class sends neither an agreement nor a signature, so an unrelaxed
server has **two** independent reasons to refuse it: the channel gate (`KeyXWanted() &&
!m_bKeyXDone`, which fires first) and, behind it, a login with no auth block at all. Phase 3
asserts the **refusal**, not which of the two made it — deleting the channel gate leaves it green,
because the signature check then refuses instead. Both are correct outcomes and the property is
that the login is not accepted. Isolating the line would want the diagnostic matched out of the
event stream, the way `p2p_confchannel` matches its own phase 3. Recorded in the test's header too.

### Not covered, and why

*Written when phases 0–6 were all there was, and now half superseded — kept because what it says
about the remaining gap is still true.*

§8.3's phase 5 (`RequireTrustAtLeast` refusing a posted socket) and phase 8 (an in-process hub
arming with no key files) both needed §8.2 **step 3**, which was not implemented at the time —
there was nothing to gate. ✅ **Both landed as phases 7 and 8 later the same day**; see *Step 3*.

§8.3's phase 6 (a pipe reads `Wire`) is folded into phase 0 here, and will want rewriting when
step 4 makes the pipe provably local: the interesting case then becomes a pipe that reads `Local`,
and phase 7's list of refused classes gains a member.

Every hub in phases 1–7 is fully provisioned even where all its links are `Open`, because until
step 3 the arm gate refused a hub that requires authentication and holds no key. §6.5 called that
"correct, and annoying" and proposed `ArmNotRequiredByPolicy`. **Phase 8 is the hub that no longer
has to be provisioned**, and it is the only one in the file that is not.


---

## Step 3 — the fence, and what it does to the arm gate

Two calls, and they are one feature: the fence is what makes the relaxation of step 2 safer than
`RequireAuth(false)` rather than merely cheaper, and the arm-gate result is the consequence of
having said both halves.

### `RequireTrustAtLeast` — where it lives, and where it is enforced

| Layer | Surface |
|---|---|
| `p2pauth::AuthPolicy` | `void SetTrustFloor(int)` / `int GetTrustFloor() const`, and `unsigned char m_nTrustFloor` |
| `P2PeerHub` | `void RequireTrustAtLeast(P2PeerConTrust_e)` / `P2PeerConTrust_e GetRequiredTrust()` |
| flat C | `p2peerhub_require_trust_at_least(h, trustClass)` / `p2peerhub_get_required_trust(h)` |
| posture | `Posture::nTrustFloor`, rendered as `TrustFloor` |
| the gate | `P2PeerHub::PostP2PeerCon`, against `EffectiveTrust()` |

**It is kept on the policy object and not in a member on the hub**, and that is the one design
choice here worth arguing. `AuthPolicy::Arm()` has to read the floor to decide
`ArmNotRequiredByPolicy`; `PostP2PeerCon` has to read it to refuse. A hub-side copy would be one
forgotten line away from an arming decision made against a fence the gate does not have — the same
"read the live thing, never a cached copy" rule `TryReadPosture` already states for everything in
it. Ints and not the enum for the reason step 2's accessors are ints: `P2PAuthLogin.cpp` compiles
without MFC on purpose.

**Class 0 IS accepted by `SetTrustFloor`, where `SetLinkPolicy` refuses it**, and the asymmetry is
deliberate. On `SetLinkPolicy`, 0 is the wire and opening it would relax the whole tree. On
`SetTrustFloor`, 0 is *no fence* — it is the value the constructor writes and the one an operator
uses to say they do not want one. Refusing it would leave the default unreachable by name.

**It is a plain assignment and not a `max()`.** A fence is a statement about what a hub is *for*,
made before it arms, beside the other settings; a hub that raises it and then lowers it has changed
its mind, not lost a guarantee, because nothing below the old floor was admitted while it stood.
That is the opposite of `DemoteTrust`, which only tightens — because that is per-object state
`AcceptSpawn` carries onward, and a ceiling that could be raised would be a promise an operator
could take back after a child had already inherited it.

### The refusal

```cpp
    //  P2PeerHub::PostP2PeerCon, after the "hub is operational" check and
    //  before the duplicate scan
    const P2PeerConTrust_e eFloor = GetRequiredTrust ( );
    if ( eFloor > P2PeerConTrust_Wire &&
         pCon -> EffectiveTrust ( ) < eFloor )
      ... EVERR naming both classes ... return FALSE;
```

Four things about those four lines:

- **`eFloor` is tested first** so that a hub nobody has fenced asks the connection nothing at all.
  `EffectiveTrust()` on a socket is a `getpeername()`, which is cheap and is still a syscall this
  function did not make before; an unconfigured hub has to reach the same instruction it reached
  yesterday.
- **`EffectiveTrust()` and not `TrustClass()`** — a connection the operator demoted is judged on
  the class they demoted it *to*, which is the reading every other gate in this feature takes.
- **Before the duplicate scan and before `m_pP2PeerTarget` is assigned**, so a refused connection
  leaves the hub in the state it was in.
- **Ownership is unchanged and it is not obvious.** A refused `PostP2PeerCon` *releases* the
  connection: the `SafeP2PeerCon` at the top of that function holds the only reference, so the
  object is destroyed by the time `FALSE` comes back. That is exactly what the two refusals already
  there do, and the fence does not invent a third convention. `DropP2PmsgCon` on a never-posted
  connection finds it in neither registry and returns, which is why deleting it is safe.

### What the fence does NOT cover, stated because it changes what green means

**An accepted child does not pass through `PostP2PeerCon`** — `P2PeerCon::AcceptSpawn` calls
`PostP2PmsgCon` directly — and it does not need to. It is spawned by a service the fence already
admitted, and it inherits the class through a virtual and the ceiling through the one copied field,
neither of which can read *higher* than that service's own. A service admitted by the fence cannot
accept a child the fence would have refused.

**The one state the fence does not re-examine** is a service DEMOTED after it was posted, whose
children then read below a floor that has already been passed. That direction is safe — a demoted
link's class is stricter, so its policy is `Full` and it authenticates in full, which is phase 6 —
but it is a hole in the *shape* guarantee rather than in the security one, and it is written into
the test's header as well as here rather than left to be discovered.

### `ArmNotRequiredByPolicy`

Appended to `p2pauth::ArmResult` as value **8**, after `ArmRevocationUnusable` — the same rule the
two revocation results follow, so every value above it keeps the number it has always had.

```cpp
//  AuthPolicy::Arm()
if ( !m_bRequired )              return ArmNotRequired;
if ( LinkPolicyOpensAllHeld ( ) ) return ArmNotRequiredByPolicy;   // new
if ( !m_bHaveIdentity )          return ArmNoIdentity;
...
```

`LinkPolicyOpensAllHeld()` is *there is a fence, **and** every class at or above it is `Open`*.
**Both halves are required and the second one is the one an implementation gets wrong.** With both
relaxable classes opened it reads as "there is nothing left to demand", and that is false: without
a floor the next `PostP2PeerCon` may hand the hub a socket — class `Wire`, policy `Full` and not
settable otherwise — which would then be asked for a signature by a hub holding no key to check one
with. The no-fence case falls out of the arithmetic rather than out of a second test that could
disagree with the first: the loop starts *at* the floor, a floor of 0 asks about the wire,
`m_aLinkPolicy[0]` is pinned `Full`, and the answer is false.

Asked **before** the provisioning checks, because the whole point is a hub that holds none of those
files; asked **after** `m_bRequired`, because a hub that turned auth off outright has already said
so in the one place an operator and a posture reader both look.

`AuthArmOrRefuse` admits it beside `ArmOk` and `ArmNotRequired`, in the same condition, so the three
answers cannot drift apart. `AuthArmText` gains one line, well inside the 255-character formatted
bound that block explains at length.

**It passes the test that enum is governed by.** The question the `ArmResult` note applies
everywhere else is *does the unprovisioned state refuse EVERYONE, or one narrow shape?* This one
refuses nobody, which is the identical verdict `SetRequired(false)` gets, and it arms for the
identical reason. What it is not is quiet: the posture reads `AuthRequired=1` beside `TrustFloor`
and the three `LinkPol` fields, which is what makes it a stated decision rather than the omission
`ArmNoIdentity` exists to catch.

### §8.3 phases 5 and 8 — the two phases that had nothing to gate

Both were added to `p2p_linktrust`, and neither dials anything: the fence and the arm gate are both
answered before a peer exists.

| # | Setup | Required | Observed |
|---|---|---|---|
| 7 | `RequireTrustAtLeast(InProcess)`, then a `Wire` socket, a `Local` socket and a DMX connection offered to the same hub | both sockets refused at post, DMX accepted | as required |
| 7 | the same `Wire` socket offered to a hub identical but for that one call | accepted | as required |
| 8 | an entirely unprovisioned hub, six combinations of fence and per-class policy | `ArmNotRequiredByPolicy` exactly when there is a fence **and** every class at or above it is `Open`; `ArmNoIdentity` otherwise | all six as required |
| 8 | ...then `SpawnHub()` on that hub, with no key files at all | **starts** | `SPAWNED` |

Phase 8's six readings are the table in §6.5 turned into assertions, and each moves exactly one
half of the condition:

```
fence   InProcess policy   Local policy   must arm as
none    Full              Full           ArmNoIdentity
InProc  Full              Full           ArmNoIdentity          <- the fence alone is not enough
InProc  Open              Full           NotRequiredByPolicy
Local   Open              Full           ArmNoIdentity          <- a class it would hold is not open
Local   Open              Open           NotRequiredByPolicy
none    Open              Open           ArmNoIdentity          <- no fence, so a wire can arrive
```

**A distinct address per offered connection in phase 7, and it is not tidiness.** The first draft
posted all of them as `kDomain`, and `PostP2PeerCon` refuses a *duplicate* address as well as a
link below the floor — so with the fence removed the first socket would have been accepted and the
second refused as its duplicate, and the falsification would have reddened one assertion out of
two. It was found by running that falsification and reading the output rather than the intent.
With an address each, every post can be refused for exactly one reason.

### Falsified, three times, once per enforcement

Every edit was made, built, run, and reverted; the tree is clean afterwards.

| Falsification | Removed | Went red | What it printed |
|---|---|---|---|
| **C** | the refusal in `PostP2PeerCon` | **7**, on both sockets, in 3 of 3 runs | `Wire socket posted: ACCEPTED`, `Local socket posted: ACCEPTED` → *"THE FENCE IS NOT A FENCE"* |
| **D** | `Arm()`'s `LinkPolicyOpensAllHeld()` early return | **8**, on both `NotRequiredByPolicy` rows | `arm=2 expected 8` twice, the four `ArmNoIdentity` rows still green |
| **E** | the `m_nTrustFloor == 0` guard, so the policy answers with no fence | **8**, on the last row | `NO fence, Local and InProcess open  arm=8 expected 2` |

E is the one worth having. D proves the result exists; E proves it is not handed out to a hub that
has opened its classes and fenced nothing — which is the reading that would let an unkeyed hub arm
and then be posted a socket.

---

## Step 4 — pipe locality, and what a class may be read from

§8.2 step 4, §6.6, §4.1, and F-SR-1 in `THREAT_MODEL.md` — the finding that started the whole
document. `SECURITY.md` said the pipe was single-machine, the tree reasoned about it that way, and
`CreateNamedPipe` was called without `PIPE_REJECT_REMOTE_CLIENTS` and with a null descriptor, so it
was not. Steps 1–3 could not rely on it: the pipe answered `Wire` and was locked out of every
relaxation. This step makes the locality true and then lets the class read it.

### The three calls

`P2PeerConPipe::CreateListenPipe`, on Windows:

- `PIPE_REJECT_REMOTE_CLIENTS` in the pipe mode. This is the half that answers the finding — a
  server without it accepts a client arriving through the SMB redirector as `\\host\pipe\name`.
- An explicit **protected** descriptor, `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)`: LocalSystem,
  Administrators, Owner Rights, and nothing for Everyone or Anonymous. The platform default grants
  those last two read access; a client opening `GENERIC_READ | GENERIC_WRITE` failed on it anyway,
  but as a side effect of the access mask rather than as a decision. **The same three ACEs, in the
  same order, as `P2PIdentityStore.cpp` writes on an identity file** — not a coincidence and not
  copied carelessly: both answer "which account may reach this endpoint", and two answers to one
  question drift.
- A descriptor that does not parse **throws**. Falling back to the platform default would hand the
  caller a wider pipe than the one they asked for, silently, which is the failure this step exists
  to remove.

`P2PeerConPipe::Connect`, on the client: `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` on the
`CreateFile`. That is §9's incidental finding 3, closed here because it is one flag on the call this
step was editing anyway. It stops a server squatting the pipe name from *being* its caller;
`IDENTIFICATION` still lets a legitimate server ask who the caller is.

### The escape hatch is named, and it is a wire

§8.1 names the one place a compatibility break could hide: *"a deployment sharing a pipe between two
accounts stops working if the default descriptor tightens"*. So the old call is kept, reachable by
name:

```cpp
    enum P2PeerConPipeAccess_e
    { P2PeerConPipeAccess_Owner      = 0    // reject remote + this account only
    , P2PeerConPipeAccess_Descriptor        // reject remote + the caller's SDDL
    , P2PeerConPipeAccess_Legacy            // the pre-revision call, unchanged
    };
```

`_Legacy` reproduces the pre-revision `CreateNamedPipe` **byte for byte** — no reject, `NULL`
descriptor — and not merely the descriptor half. Both are compatibility surfaces: a deployment could
be relying on the DACL *or* on SMB reach, and an escape hatch that closed one of them silently would
be the same failure in a smaller box.

**And a `_Legacy` pipe reads `Wire`.** That is the point of naming it rather than deleting it: the
compatibility path is precisely the one that does not get to claim the class. `_Descriptor` keeps
the reject and takes the caller's SDDL, and stays `Local` — the reject is what makes the class true,
while the DACL decides *which local principal* may open the endpoint, and that is A7, which the
class has never claimed to answer.

### The fact is DERIVED, not recorded beside the request

This is the part worth reading twice, because the obvious implementation is unfalsifiable:

```cpp
    m_bPipeLocal = ( dwPipeMode & PIPE_REJECT_REMOTE_CLIENTS ) != 0 &&
                     pSA != NULL;
```

Not `bLocal = true` inside the branch that asked for the reject. A flag set beside a request records
the *request*; reading back the two values handed to the kernel records what the kernel was *told*.
The difference is exactly whether deleting `dwPipeMode |= PIPE_REJECT_REMOTE_CLIENTS` changes the
answer — and it does, which is falsification F below. Written the obvious way, that deletion would
have left every phase green.

Both halves are required and neither alone: a reject with the platform's descriptor still lets
Everyone read the endpoint, a descriptor without the reject still lets the redirector carry it off
the machine.

### `TrustClass()` — the handle first, the configuration only where there is none

```cpp
    if ( m_hFile != 0 )
      return m_bPipeLocal ? P2PeerConTrust_Local : P2PeerConTrust_Wire;

    if ( m_eP2PeerConMode == P2PeerCon_CLIENT )
      return P2PeerConPipenameIsLocal ( m_sPipename ) ? Local : Wire;

    return ( m_ePipeAccess != P2PeerConPipeAccess_Legacy ) ? Local : Wire;
```

The same shape as `P2PeerConWsa::TrustClass()`, which reads `getpeername()` and falls back to the
listen scope, and for the same reason: a class is a fact about a link, so where a link exists it is
the only thing worth reading. It also means a `SetPipeAccess()` arriving after `Listen()` cannot
re-label a pipe that is already carrying traffic.

**The two ends answer from different evidence, and are allowed to disagree.** A service's locality
is a property of what it created; a client's is a property of the device its name resolves to —
`\\.\pipe\Name` is NPFS on this machine and cannot be anything else, while `\\host\pipe\Name` goes
out through the redirector. So `\\localhost\pipe\` and `\\127.0.0.1\pipe\` read `Wire`, which is the
fail-closed direction and is meant. A `_Legacy` service is `Wire` while a client on `\\.\pipe\` is
truthfully `Local`; with the `Local` class open the client skips a handshake the server still wants
and **the server refuses the login** — the conservative outcome, and the same shape as phase 3.

`GetNamedPipeServerProcessId()` would be a stronger client-side reading — it fails for a remote
server — but it needs the handle and one more syscall on every posture read, and the device path is
already a kernel fact.

### `AcceptSpawn` — the setting travels, the fact does not

The pipe's accept is unusual: the roles **swap**. `this` (the listener, which created the pipe and
holds its handle) becomes the accepted connection; the spawn becomes the re-armed service and will
call `CreateListenPipe()` for itself. So:

- `m_ePipeAccess` and `m_sPipeSddl` are **copied** onto the spawn, or the second instance of a pipe
  would not be the same pipe as the first.
- `m_bPipeLocal` is **not**. The spawn holds no handle, and a fact about a handle that was never
  opened is a lie. It is also cleared in `Drop()` and `OnClose()`: the fact goes with the handle.

### The Linux answer, which §6.6 left open

`CreateNamedPipe` there is `socket`/`bind`/`listen` on an `AF_UNIX` path
(`Msgcore/Platform/p2psock.h`) and **both** arguments are ignored. There is no `AF_UNIX` equivalent
of a pipe over SMB, and the client dispatch matches `\\.\pipe\` and `//./pipe/` only, so a
`\\server\pipe\Name` fails rather than silently resolving to a local socket. Locality is therefore a
property of the address family, holds in every access mode, and cannot be got wrong — so
`m_bPipeLocal` is unconditionally true there, with a comment saying why rather than a pretence that
the descriptor was applied. What has no counterpart is the DACL: the endpoint is protected by a
`0700` directory and the socket file takes the process umask. Equivalent for a single-user daemon,
different in kind for a multi-user host, and recorded as such.

**Not compiled on Linux in this pass.** The reasoning above is read off `p2psock.h` and the Platform
README, and the Windows build is clean; a Linux build was not run and this document does not claim
one.

### No new ABI

The flat C surface exposes hub and `P2PeerConWsa` handles only — there is no `p2peerconpipe_*` in
`Targetcore_c.h`. So step 4 adds **no** symbols and the manifest stays at **99**. If the pipe is
ever given a flat-C surface, `set_pipe_access` and `get_trust_class` are what it needs.

### §8.3 phases 6 and 7 — and what phase 0 could not do alone

Phase 0 grew from one pipe row to four: a default service (`Local`), a `_Legacy` service (`Wire`),
a client on a local name (`Local`), a client on a UNC name (`Wire`). All four read the **fallback**
branch — none of those objects holds a handle — which is exactly why they are not enough. Under
falsification H (`_Legacy` given the new pipe anyway) phase 0 stayed **green**, because it reads the
setting and the setting had not changed. Two live phases were needed:

| Phase | Setup | Observed |
|---|---|---|
| 9 | a real pipe at `P2PeerConPipeAccess_Owner`, both hubs `SetLinkPolicy(Local, Open)` | `login=YES payload=YES keyx=0 cypher=0 authed=0 loginTrust=Local child=Local/Local` |
| 10 | the same, service `_Legacy`, client `DemoteTrust(Wire)` | `login=YES payload=YES keyx=1 cypher=1 authed=1 loginTrust=Wire child=Wire/Wire` |

Phase 10 is §8.3's phase 6 — *"pipe created without `PIPE_REJECT_REMOTE_CLIENTS`: `Wire`, full
handshake regardless of policy"* — and its client is demoted for a stated reason rather than a
convenient one: without the demotion the two ends disagree (a legacy service is `Wire`, a client on
`\\.\pipe\` is `Local`) and the phase would measure a *refusal*, which is phase 3's subject. With
both ends on `Wire` it measures the **handshake**, which is what §8.3 asked for. §8.3's phase 7 — a
pipe service demoted to `Wire`, accepted child reads `Wire` — is the same single copied field phase
6 pins on a socket, exercised on the pipe here.

The listener signal is `g_hListening`, not a sleep, and it is *better* founded here than on the
socket: `P2PeerTarget::On_ConListen` calls `pCon->OnListen()` — where `CreateListenPipe()` runs —
then `pCon->Accept()` — the overlapped `ConnectNamedPipe` — and only then returns, so by the time
the event is set the pipe exists **and** its accept is pending. `pipe_mesh.cpp` sleeps 750 ms at
this point.

The pipe name carries the **process id**: `\\.\pipe\p2p_linktrust_<pid>_<n>`. A pipe name is
machine-wide and has no `RESOURCE_LOCK`, so two concurrent copies of the suite would otherwise
contend for one endpoint.

### Falsified, three times, once per enforcement

| | Removed | Went red |
|---|---|---|
| F | `dwPipeMode \|= PIPE_REJECT_REMOTE_CLIENTS` | phase 9, `child=Wire/Wire`, "A NAMED PIPE THIS TRANSPORT CREATED DID NOT READ LOCAL" — 2 of 4 runs (the other two died to the flake before reaching it) |
| G | the descriptor (`pSA = NULL`, reject kept) | phase 9, same reading — 3 of 4 runs |
| H | `_Legacy` given the new pipe anyway | phase 10, `child=Local/Local`, "A LEGACY PIPE CLAIMED A CLASS IT CANNOT KEEP" — 2 of 5 runs |

Each reverted, and `P2PeerConPipe.cpp` restored from a byte copy taken before the first, verified by
grep for the falsification markers and for the three lines they replaced.

**F and G are what justify the derivation.** They are two deletions in the same function that both
have to change one boolean, and they do, separately.

### A defect of mine that running found

The first version of `RunPipePhase` indexed the address table with the **phase number** —
`kSrvAddr[nPhase]` — which is how every other runner in the file is written. But an index is not a
phase number here: phase 7 builds two hubs and takes indices 7 and 8, phase 8 takes 9, so phase 9
took **phase 8's address**, one millisecond after phase 8 tore its hub down. That is precisely the
process-wide-registry race the per-phase address table exists to remove, reintroduced by the
convenience of indexing with the phase number. It presented as an abrupt termination in phase 9 —
indistinguishable at a glance from the pre-existing flake, which is why it is written down here.
Fixed by passing `nAddr` explicitly, extending the tables to twelve entries, and saying so in a
comment on the table.

---

## Step 5 — the measurement, and the §6.3 decision

§8.4 is one paragraph and the first sentence is the whole reason it exists: *"Nothing in the tree
times the security path; the figures in §3 are operation counts."* Every argument §6.3 was deferred
on was an argument about numbers nobody had. There are numbers now.

### The harness

`MscsUnitTests/p2p_linkcost.cpp` — new. Three hubs in a chain over `P2PeerConDmx`, real pumps, real
login, library routing, no socket and no OS handle anywhere on the path:

```
    Cost<n>.Alice  --Dmx-->  Cost<n>  --Dmx-->  Cost<n>.Carol
      (origin)              (relay)             (destination)
```

That is §8.4's shape — `dmx_mesh` with one more hub — and it is also the shape §6.3 is *about*: the
waiver is for a destination in this process, so every cost measured here is paid against a threat
with no way in.

**Registered under the `measure` label and not `security`, and with no timing assertion of any
kind.** A messages-per-second threshold in ctest is a flake on a build machine whose load this
suite does not control, and this file exists to produce a number for a document to argue over. What
it *does* assert is **delivery** — exit 3 if a posture failed to deliver every message within its
timeout — because a posture that quietly dropped its traffic would otherwise post the best
throughput in the table.

Two things in it are worth naming because they are the difference between a measurement and a
number:

- **A send window, not a flood.** `s_cP2PmsgMAX` bounds the live messages in a process and there
  are high and low marks below it (`p2p_backpressure`). A loop posting N messages as fast as it can
  would measure the brake. The sender holds 128 in flight and waits on an event; the destination
  decrements and signals it. The counter is a shared atomic in one process — scaffolding, not
  traffic.
- **An idle baseline per posture.** Three hubs up, both links logged in, nothing sent, 500 ms,
  subtracted. It turns out to be **zero to the resolution of the instrument**, which is itself the
  result: these pumps block, they do not spin.

### A fifth posture, and it is the one that answers the question

§8.4 asked for four. The fifth could not have been asked for before step 2 landed:

| | Posture | What it adds |
|---|---|---|
| A | everything off | — |
| B | `RequireAuth` only | the per-hop handshake |
| C | + relay attestation | an ECDSA signature per message at the origin |
| D | + seal | an ECIES envelope per message, opened at the destination. **This is the tree's default posture** — all three flags initialise `true` at `P2PAuthLogin.cpp:497+`, so D is what a hub that calls nothing gets today |
| E | D + `SetLinkPolicy(InProcess, Open)` on all three hubs | **§6.2, which step 2 already shipped** |

E is the row that answers §8.4's closing question — *"or whether §6.2 alone recovers what
matters"* — by measuring it rather than reasoning about it.

### The numbers

Release, `windows-msvc`, N = 20 000 messages of 256 bytes, three runs. The per-message columns are
run 3's; the throughput column carries all three.

| Posture | msg/s (r1 / r2 / r3) | wall µs/msg | CPU µs/msg | vs. A | origin link |
|---|---|---|---|---|---|
| A everything off | 30 183 / 29 322 / 30 591 | 32.7 | 93.0 | — | keyx=0 cyph=0 auth=0 |
| B `RequireAuth` only | 30 071 / 31 584 / 31 777 | 31.5 | 89.1 | **×1.0** | keyx=**1** cyph=0 auth=**1** |
| C + relay attestation | 7 532 / 7 474 / 7 658 | 130.6 | 217.2 | ×2.3 | keyx=1 cyph=0 auth=1 |
| D + seal (**the default**) | 1 526 / 1 488 / 1 514 | 660.3 | 1 297.7 | **×14.0** | keyx=1 cyph=0 auth=1 |
| E D + `SetLinkPolicy(InProcess, Open)` | 1 520 / 1 447 / 1 517 | 659.3 | 1 299.2 | ×14.0 | keyx=**0** cyph=0 auth=**0** |

CPU is the whole process, kernel plus user, every thread. `GetProcessTimes` accumulates on the
15.625 ms scheduler tick, which at N = 20 000 is **0.78 µs per message** — the harness prints that
line itself, because a column whose resolution the reader has to guess at is an opinion. Every
difference argued from below is two orders of magnitude above it.

**Reproducible to about 4%** across the three runs, and the ordering is identical in all three.

**The last column is what stops the table being unfalsifiable**, and it was added after the first
two runs because without it the two most important rows say nothing. `IsKeyXDone`,
`IsCypherActive`, `IsAuthenticated` and `EffectiveTrust` are read off Alice's own connection at its
login ack — the same five accessors `p2p_linktrust` reads, from the same place:

- **B's `keyx=1 auth=1`** is why "`RequireAuth` costs nothing per message" is a result rather than
  a bug report. The handshake ran. It just does not run *again*.
- **E's `keyx=0 auth=0` beside a per-message cost identical to D's** is the finding in its
  strongest form: the link handshake was removed *entirely* and the number did not move.
- **`cyph=0` in every row including B, C and D** is §9's incidental finding 2 with a reading beside
  it. `KeyXDerive` builds a `P2PeerioGcm` and installs it on a `P2PeerioDmx` that never consults
  it, so an authenticated DMX link has an agreement, a signed login, and no cypher — which is
  exactly why B − A is zero.

### The primitives, timed on their own

The chain cannot see everything, for a reason worth stating precisely. `GateAppMsgInbound` reaches
`GateRelayInbound` **only** on an ancestor link carrying a source that is not at-or-below the peer
that delivered it. In a chain the relay is a common ancestor of both ends, so the descendant test
admits the message first and **the verify never runs** — which is not a discovery, it is what that
function's own notes already say, naming `p2p_sealhop`'s identical shape as the reason deleting the
branch once left the whole suite green.

So the four operations are timed directly, on a hub constructed and provisioned but never spawned:

| Operation | µs CPU per call | What it is |
|---|---|---|
| `AttestRelay` | **101.6** | one ECDSA P-256 signature |
| `VerifyRelay` | **218.8** | one ECDSA P-256 verification |
| `SealFor` | **468.8** | ephemeral ECDH keygen + ECDH + ECDSA sign — **three** public-key operations. 256 bytes in, 490 out |
| `OpenFrom` | **406.2 – 414.1** | ECDSA verify + ECDH — two |

Stable to under 2% across the three runs. They add up, which is the check that the two halves of
this harness are measuring the same thing: posture D's origin does 101.6 + 468.8 = 570 µs and its
destination 406 µs, total **977 µs**, against a measured D − B of **1 209 µs**. The remaining
~230 µs is the body growing 256 → 490 bytes and being re-serialised across two hops.

Two of these are worth reading twice. A **verify costs more than twice a sign** (218.8 against
101.6), which is the usual shape for ECDSA and matters because a tree with N relays pays the verify
N times and the sign once. And **a seal costs more than four times an attestation**, because it is
three public-key operations to attestation's one — see finding 12.

### The decision on §6.3

**§8.4's question is answered, and the answer is no.** §6.2 alone does not recover what matters:
E − D is **zero to the resolution of the instrument**. That is not a disappointment, it is exactly
what `P2PeerHub.h`'s own comment on `SetLinkPolicy` predicts — *"an in-process link under Open still
signs and still seals"* — and the value of measuring it is that the prediction is now a reading.

The rest follows from three facts:

1. **The default posture costs 14× the CPU per message, 20× the wall time and 95% of the
   throughput** of the same chain with nothing on. Every one of those hops is a pointer handoff
   between two objects on one heap.
2. **Essentially all of it is the two END-TO-END protections.** B − A is **−4 µs** — that is,
   nothing, and below the instrument: `RequireAuth` on a DMX link costs *per connection*, not per
   message. The agreement and the signed login happen once, and no cypher is ever installed on a
   `P2PeerioDmx` (§9's incidental finding 2, now with `cyph=0` printed beside it in every
   authenticated row). Of the 1 205 µs that separates D from A, **1 209 µs is D − B**.
3. **§6.2, already shipped, recovers none of it**, and no further per-link work can, because these
   two protections are not properties of a link.

So the choice §6.3 framed — document the deployment rule and ship the waiver, or leave the waiver
out and take only §6.2 — is now a choice between paying 13× on a link that cannot be observed, and
an opt-in assumption.

**RECOMMENDATION: take §6.3, as §6.3 specifies it.** Keyed on the in-process hub registry lookup —
*not* on the link class — with the receive-side exemption in `GateRelayInbound` keyed on the **same**
lookup, and off by default. Three reasons:

- the cost is **93%** of the per-message CPU in the posture a hub gets without asking for anything;
- the waiver is **opt-in**, so its unverifiable assumption is something an operator asserts rather
  than something the library assumes — the same shape as `RequireAuth(false)` and
  `RequireSealBroadcast(false)`, both of which this tree already has and both of which are read as
  decisions in the posture;
- the assumption's failure mode is bounded and nameable: hubs A and C in one process with B on
  another host, wired A-B-C. `WaiveEndToEndInProcess`'s block comment has to carry that example, not
  a paraphrase of it.

**And the part a fast implementation would get wrong**, restated because it is the only part that
is a security property rather than a performance one: the receive-side exemption must key on the
registry lookup and not on the link class. Keyed on the class, a remote ancestor forwards an
unattested message down a DMX link and is admitted. §6.3 says this already; nothing measured here
changes it.

### Two things the measurement found that §8.4 did not ask about

Both are recorded as findings rather than acted on, because neither is step 5's subject and each
belongs to someone who owns the module.

**The tree signs more than it ever verifies.** In a common-ancestor topology — which is every
multi-hub topology in this suite — attestation costs one signature at the origin, 101.6 µs per
message, and **nothing verifies it**, because the descendant test admits the message first. That is
not an argument for the waiver so much as an argument that `AttestAppMsgOutbound` and the gate that
consumes it are reached under different conditions. Finding 11.

**The seal's cost is three public-key operations per message, and one of them is a fresh key.**
`p2pseal::Seal` generates an ephemeral ECDH key per call (`P2PeerSeal.cpp:366`), derives, and signs.
That buys per-message forward secrecy, which may well be the intent — but it is *the* number in this
table, and a waiver removes it only where the destination is in this process. Every wire destination
keeps paying it, and a wire destination is the case sealing exists for. Whether the per-message
ephemeral is intended is worth asking **before** §6.3 is built, because if the answer is no then the
same 1 060 µs falls off *every* link and the waiver's assumption buys much less than this table
suggests. Finding 12, and it is a question, not a proposal.

**It was asked, and the answer is yes — see *Finding 12, settled* below.** The ephemeral is
documented in three places and was priced against a rejected alternative, and the guess written into
the sentence above is wrong: dropping the fresh key removes **230.5 µs of the 1 080 µs**, not all of
it. This paragraph is left standing as it was written because the correction is the point.

### What step 5 did NOT change

No library source. `Targetcore` is byte-identical to what step 4 left; the manifest is still 99
symbols and the ABI is untouched. Step 5 is a harness, a CMake registration and this section. The
`security` label still selects the same 37 tests — `p2p_linkcost` is labelled `measure` precisely so
that a `-L security` run is comparable across the whole pass.

---

## The flake, and the measurement that says it is not this pass's

`ctest -L security` is **36/37**, and the one failure is `p2p_linktrust` itself. It is worth being
exact about what that is, because a gate test that fails is worthless as a gate until someone knows
which.

**The shape.** The process terminates abruptly in one of the live TCP phases — 5 or 6, occasionally
in 7 — immediately after a hub has armed and before its connection is accepted. No diagnostic, no
`RESULT:` line, output simply stops. In Debug the exit code is **3** (`abort()`); in Release it is
**0xC0000409** (`__fastfail`). It is intermittent: **8 of 12** Debug runs on distinct port bases
completed all nine phases, and **5 of 6** Release runs did.

**It is not caused by step 3, and that was measured rather than argued.** The same tree was built
with both of step 3's enforcements compiled out — the `PostP2PeerCon` refusal and `Arm()`'s early
return, each behind a `false &&` — and run eight times on distinct ports. **Two of those eight died
the same way**, one in phase 5 and one in phase 7, at the same rate and in the same shape. The
phases that abort are phases this pass did not touch, and they abort with the fence disabled.

**What it is not.** Not a port collision: it reproduces on eight distinct port bases. Not the
`g_hListening` race the earlier pass fixed: that one reported `WSAECONNREFUSED` and a phase verdict,
where this one produces no verdict at all. Not a Debug assertion: Release fails the same way, at the
`__fastfail` code rather than through `abort()`.

**Also seen, in the same neighbourhood and probably the same fault:**
`PostP2PmsgCon(nHubID=N) — P2PmsgCon object already posted` on a freshly created client connection,
followed by `ConnectEx` failing 10061 because the service on the other side never bound. That one
does produce a verdict — phase 5 reports the `Local` class not honouring its policy — and is the
other face of the two failures seen under `ctest`.

### It has a name now — 2026-09-04, during step 4

The user reported **modal message boxes** appearing while this suite ran. That was the missing half
of the diagnosis, and it turned "no diagnostic" into a diagnosis:

- **The dialog is the CRT's, not the library's.** It kept appearing with `P2PMSG_NO_UI=1` already
  set, which rules out `P2Pevent`'s own message box. It is the debug-CRT assertion dialog, raised on
  whichever thread called `abort()` — a hub's pump thread.
- `p2p_linktrust` now installs `_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE)`, a report hook
  that prints and continues, `SetErrorMode(...NOGPFAULTERRORBOX)`, and
  `P2Pevent::ForceTextOutput(true)` — the same shape `TestFramework.cpp` already uses for the
  harnesses that go through it, which this file does not. No dialog, and the text is in the ctest
  log.
- A `std::set_terminate` handler then rethrows `std::current_exception()` and catches
  `P2Pevent*`, which is how this tree throws. **The abort is an unhandled exception on a pump
  thread**, and it is:

```
    [linktrust] *** TERMINATE - an exception reached the top of a thread
    [linktrust]     P2Pevent EVERR in PostP2PmsgCon(nHubID=9188,pP2PmsgCon)
    [linktrust]     P2PmsgCon object already posted
```

So the two faces are **one fault**, confirmed rather than suspected: the same
`P2Pwin32.cpp` throw, sometimes caught by a caller that turns it into a phase verdict and sometimes
reaching the top of a pump thread and calling `terminate()`. It fired in **phase 7** in the run that
caught it — a phase neither step 3 nor step 4 touches.

**And there is a plain code defect sitting on it**, `P2Pwin32.cpp`, in the guard that throws:

```cpp
    if ( s_P2PmsgCon_HubID.Lookup((DWORD_PTR)pCon,nHubIDcon) ||
         s_P2PmsgCon_HubID.Lookup((DWORD_PTR)pCon,nHubIDcon) ||   // <- twice
         nHubIDcon                                             )
```

The same map is looked up twice. The second is almost certainly meant to be `s_P2PexpCon_HubID`,
the parallel explorer registry — `DropP2PmsgCon`, thirty lines below, consults both and carries a
comment (F-S5-5) about exactly this class of mistake. **Not fixed here**, and deliberately: making
the guard stricter can only produce *more* throws, and the throw is not the bug. The bug is that
these registries are keyed on the **raw pointer address**, which the allocator recycles — the same
hazard F-S5-5 names — so a stale entry makes an unrelated new object answer "already posted".

**Still not fixed, and now well enough understood to be scoped.** It wants: which path frees a
connection without `P2PeerConPlc::Release()` (the only caller of `DropP2PmsgCon`), whether the
registries should be keyed on something other than an address, and whether a pump thread should
have a top-level handler at all. Three questions, none of them step 4's. Recorded as incidental
finding 7, with finding 9 for the duplicated lookup.

**Until it is closed**, a red `p2p_linktrust` needs its output read before it is believed: a run
that printed a `RESULT:` line is a real verdict, a run that printed `*** TERMINATE` is this, and a
run that stopped mid-phase with neither is this on a build that predates the handler.

---

## Invariants, re-checked

| # | Invariant | Held by | Verified |
|---|---|---|---|
| I1 | A forgotten `AcceptSpawn` line cannot weaken a connection | the class is a virtual; the ceiling is the only per-object state | by construction |
| I2 | Still no per-connection `RequireAuth` | connection contributes a class; hub owns the policy | by construction |
| I3 | A transport that says nothing is a `Wire` | base `TrustClass()` | by construction |
| I4 | No promoting a link the library cannot verify | `DemoteTrust` tightens only; no `PromoteTrust` exists | by construction |
| I5 | Defaults do not move | every class `Full`; `AuthLinkRelaxed()` false unless `IsAuthRequired()` | `p2p_linktrust` phase 1 + the other 36 security tests unchanged |
| I6 | F-S6-1 cannot recur through this change | both ends call `KeyXWanted()`; the halves are composed once | `p2p_linktrust` phase 3, and falsification B |
| I7 | `Cypher=0` is readable as a decision | `TrustClass`/`Trust` on the connection, `LinkPol*` on the hub | `p2p_linktrust` phases 1/2 read them off the live connection |
| I8 | A relaxed hub cannot silently become a network endpoint | `RequireTrustAtLeast` refuses below the floor at `PostP2PeerCon`, against `EffectiveTrust()` | `p2p_linktrust` phase 7, falsification C |
| I9 | A hub arms without keys only when it can never demand a signature | `LinkPolicyOpensAllHeld()` needs a fence **and** every class above it `Open`; a hub with no fence still reports `ArmNoIdentity` | `p2p_linktrust` phase 8, falsifications D and E |
| I10 | A named pipe claims `Local` only where the kernel is keeping the promise | `m_bPipeLocal` is derived from the pipe mode and the security attributes `CreateNamedPipe` was actually given, never from the setting that asked for them; the legacy call is reachable by name and reads `Wire` | `p2p_linktrust` phases 9 and 10, falsifications F, G and H |

I1 and I4 remain "by construction" and that is the right answer for both: there is no field for
`AcceptSpawn` to drop (the class is a virtual) and no `PromoteTrust` to call. Phase 0 pins the
demotion algebra, which is the part of I4 that is code rather than absence.

---

## Incidental findings

1. **`P2PeerConPipe` is not local-only** — ✅ **CLOSED by §8.2 step 4, 2026-09-04**, the same day it
   was found. `securityRevision.md` §4.1 and §9.4; `THREAT_MODEL.md` §8 **F-SR-1**, now marked
   FIXED. The transport passes `PIPE_REJECT_REMOTE_CLIENTS` and an explicit DACL, the old call is
   reachable as `P2PeerConPipeAccess_Legacy` and reads `Wire`, and `TrustClass()` answers `Local`
   for a pipe this transport made. **§9's finding 3 — the pipe client opening without
   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` — is closed with it**: one flag on a call step 4
   was editing anyway. Refer *Step 4* above.
2. **The "83 symbols" figure is stale in two places** and was already stale before this pass — the
   manifest held **93**, not 83, and now holds **99**. It appears in `Targetcore_version.h` (the
   "WHAT THE MAJOR DOES NOT CLAIM" block) and in `Targetcore/CMakeLists.txt` (the `p2p_abisurface`
   block), and probably in the versioning policy. **Not corrected here** — it was not this pass's
   subject and the versioning policy was not read. One line each when someone does.
3. **The version was not bumped.** These three steps add **6** symbols to the covered ABI, which
   under the versioning policy is a MINOR bump — 3.0.0 → 3.1.0. Not done: the number, the four
   macro spellings that must move with it and the matching release tag are a release act, not an
   implementation one.
4. **`P2PeerCon::TrustClass()` is COMDAT-folded onto `AcceptSourceKey()`** in the Release DLL's
   export table (both are `return 0`). Harmless `/OPT:ICF`, noted only so a future reader of
   `dumpbin /EXPORTS` does not take it for a mis-declared vtable slot.
5. **`securityRevision.md` §6.6's claim that the Wsa child inherits its class with no `AcceptSpawn`
   line is incorrect** as it stands — see the departure above. The document is otherwise accurate
   everywhere this pass touched it.
6. **The 11 `p2pweb_*` tests did not run under `ctest` at all** — ✅ **FIXED 2026-09-04**, see the
   section below. Every one exited `0xc0000135` (`STATUS_DLL_NOT_FOUND`) *before entering main*,
   for want of a loader path. Not caused by this pass: a load failure cannot come from a change
   that only ADDS exported symbols, and the 37 security tests linking the same two DLLs all passed
   throughout.
7. **`p2p_linktrust` terminates abruptly, intermittently, in its live TCP phases** — ⬜ **OPEN,
   and RE-MEASURED 2026-09-04 during §6.3: the rate is now ~50% on this machine, and the baseline
   tree was actually run this time — 3 pass / 3 fail in 6 runs of `1a48340` with the §6.3 work
   stashed, failing in three different phases. Refer *The flake, re-measured*.**
   Debug exit **3** (`abort()`), Release **0xC0000409** (`__fastfail`), no diagnostic and no
   `RESULT:` line, always just after a hub arms and before its connection is accepted. Roughly one
   run in four. **Measured not to be this pass's**: the same tree with both of step 3's
   enforcements compiled out died the same way in two of eight runs, in phases step 3 does not
   touch. The related `PostP2PmsgCon — P2PmsgCon object already posted` on a fresh client
   connection, with `ConnectEx` 10061 behind it, is probably the same fault seen from the side that
   still produces a verdict. It is in the connection registry / hub teardown path. Full evidence in
   *The flake* above. Not chased here — it is a different piece of work from step 3, and it wants
   the tree's other TCP suites checked for the same shape before anything is changed.
8. **§8.5's `examples.md` row is still not done.** The design document asks that the banner at
   `examples.md:25` offer `SetLinkPolicy` to the in-process examples instead of
   `RequireAuth(false)`. Now that the fence exists the better advice is both calls together, which
   is what `SECURITY.md` now says. Not done here: `examples.md` was not read, and it is one edit
   that should be made against the file rather than against a line number quoted in a design
   document.
9. **`PostP2PmsgCon` looks up the same registry twice** — ⬜ **OPEN**. `P2Pwin32.cpp`, the
   "to be sure, to be sure" guard: `s_P2PmsgCon_HubID.Lookup(...)` appears on two consecutive lines
   where the second is almost certainly `s_P2PexpCon_HubID`, the parallel explorer registry that
   `DropP2PmsgCon` consults thirty lines below with an F-S5-5 comment about this exact class of
   mistake. Consequence: an explorer connection can be posted into the message registry without the
   guard noticing. **Not fixed here** — it is one word, but it makes a guard STRICTER on a code path
   whose throw already terminates the process (finding 7), and the two want fixing together.
10. **§6.6's `P2PeerConPipe` work is done but was not compiled on Linux.** The AF_UNIX reasoning is
   read off `Msgcore/Platform/p2psock.h` and its README, and the `#ifdef` split is written for it,
   but no Linux build was run in this pass. Msgcore is outside this working directory and was not
   edited. `p2p_linkcost` (step 5) has the same status: the `#ifdef` split for `getrusage` is
   written and was not compiled.
11. **In a common-ancestor tree the origin signs an attestation nothing verifies** — ⬜ **OPEN, and
   it is a question rather than a defect.** `AttestAppMsgOutbound` is gated on
   `IsRelayAuthRequired() && CanAuthSign()` and signs every application message the hub sources.
   `GateRelayInbound`, which consumes it, is reached only from `GateAppMsgInbound`'s ancestor
   branch — i.e. only when the source is **not** at-or-below the peer that delivered it. Every
   multi-hub topology in this suite routes through a common ancestor, so that branch never fires
   and the signature is never checked. Measured cost of producing it: **101.6 µs of CPU per
   message** (step 5, part 2) — *more than the entire cost of an unprotected message on this chain*,
   which is 93.0 µs. The two
   are reached under different conditions and that asymmetry is deliberate on the receive side —
   `GateAppMsgInbound`'s notes argue it at length — but nothing argues the send side. **Not
   changed here**: narrowing what signs is a security change dressed as an optimisation, and it
   needs the `p2p_authancestor` shape to gate it.
12. **A seal is three public-key operations and one of them is a fresh key** — ✅ **CLOSED as
   ANSWERED 2026-09-04.** As raised, it was a question for whoever owns `P2PeerSeal`, and it is
   left below in the words it was raised in because the answer corrects it. `p2pseal::Seal`
   generates an ephemeral `EcdhP256` per
   call (`P2PeerSeal.cpp:366`), derives a shared secret per reader, and signs. Measured: **468.8 µs
   to seal, 414.1 µs to open**, against 99 µs for the entire unprotected message. That is the
   single largest number anywhere in step 5's table, and §6.3's waiver removes it only where the
   destination is in this process — every **wire** destination keeps paying it, and a wire
   destination is the case sealing exists for. Whether a per-message ephemeral is intended (it buys
   per-message forward secrecy) is worth settling **before** §6.3 is built: if it is not, the same
   **1 080 µs** (D − C) falls off *every* link — wire included — and the waiver's assumption buys
   much less than the table suggests.

   ✅ **ASKED AND ANSWERED 2026-09-04, and the answer is that it is intended — §6.3 is not blocked.**
   The ephemeral is a chosen property, documented three times, and **the paragraph above overstates
   the prize by 4.7×**. Refer *Finding 12, settled* below for the reading and the arithmetic.
   What the check turned up instead is a **security-neutral** saving the finding did not look for:
   the per-call public-key imports. That is **finding 13**.

13. **Every verify re-imports the peer's public key from the allow-list** — ⬜ **OPEN, and unlike
   finding 12 it is free.** `P2PeerSeal.cpp:543` and `:637` (the two open paths) construct a local
   `EcdsaP256` and `ImportPublic` the sender's identity key **per message**; `P2PAuthLogin.cpp:1305`
   does the same on the relay-verify path; and `EcdhP256::DeriveRawSecret` does its own
   `BCryptImportKeyPair` on the peer point every call (`P2PCngCrypto.cpp:437`). Measured below:
   **76.8–78.1 µs** an import, which is **36%** of a `VerifyRelay` and **~19%** of an `OpenFrom`.
   Memoising an imported public key per peer changes no wire format, no transcript and no security
   property — it caches a deterministic parse of bytes the allow-list already holds — and it pays on
   posture **C** as well as **D**, which no waiver does. Not done here: it is a `P2PIdentityStore`
   lifetime question (when does a cached handle get dropped on a revocation?) and that is the module
   owner's call, not step 5's.

---

## §6.3 — the end-to-end waiver

Step 5 recommended building this and finding 12 was checked first, as asked. Both cleared, so §6.3
is built as §6.3 specifies it: keyed on the in-process hub registry lookup at **both** ends, never
on the link class, and **off by default**.

### The predicate, and why it is the whole security argument

`IsP2PmsgHubInProcess ( P2PaddrSTR )`, `P2Pwin32.cpp`. It walks `s_ThreadID_P2PmsgHub` under
`s_oCSectionP2PmsgHub` — the registry §6.3 named — and compares addresses.

**Three properties, and each is a decision rather than an implementation detail:**

1. **The match is EQUALITY, never at-or-below.** A hub `Alice` held here says nothing about
   `Alice.Bob`, which may perfectly well be a child hub on another host — so an at-or-below test
   would waive the protections on precisely the traffic that leaves the machine. This is the same
   equality the router itself uses: `OpenAppMsgInbound` decides "is it for us" with
   `oThisHub == strDst`. Gated by `p2p_e2ewaive` phase 0 and **falsified** — swapping the compare
   for `IsRable()` turns two rows red and nothing else.
2. **It does not throw**, unlike every neighbour in that file. It is asked on the IO thread for
   every application message on a waived hub, and the answer to "no such hub" is `FALSE` — which is
   the fail-closed answer here, because `FALSE` *keeps the protections on*.
3. **It is a walk, not a lookup**, because the map is keyed by thread ID. A second index by address
   would be a second thing that can disagree with the registry, which is exactly what this must not
   be. There is one hub per thread and the counts are single digits.

The lock discipline is written down at the declaration and obeyed at all three call sites: the hub
accessor takes and releases `P2PeerHub`'s own lock, and *then* the predicate takes the process-wide
hub lock. The two are never held together, so this cannot invert against `CreateP2PmsgHub`, which
takes HUB then PUMP. The call sites spell it as two statements rather than one `&&` so the ordering
is not left to how the compiler sequences it.

### The switch

| Surface | Call |
|---|---|
| C++ | `P2PeerHub::WaiveEndToEndInProcess(bool)` / `IsEndToEndWaivedInProcess()` |
| Policy | `AuthPolicy::SetEndToEndWaivedInProcess` / `IsEndToEndWaivedInProcess`, `m_bWaiveE2EInProcess` |
| Posture | `Posture::bWaiveE2E`, read live from the policy like every other field |
| Snapshot | `WaiveE2E`, rendered by `Serialise` beside `SealReq` |
| Flat C (§6.7) | `p2peerhub_waive_end_to_end_in_process`, `p2peerhub_is_end_to_end_waived_in_process` |

Two placement decisions, and they point opposite ways on purpose:

- **In the `Posture` struct the field is APPENDED**, after `nTrustFloor`, not grouped with the seal
  fields it belongs with. Inserting a member moves every field after it, so a consumer compiled
  against the previous header would read this one where `bSealCanOpen` used to be. `anLinkPolicy`
  and `nTrustFloor` were appended for the same reason in steps 2 and 3. The cost is that the struct
  no longer reads in topic order, which is a comment's problem rather than a caller's.
- **In the SNAPSHOT it is rendered beside `SealReq`**, where topic order is all there is and no
  offset depends on it. That is the placement that matters to the person reading it: `SealReq=1`
  with `WaiveE2E=1` is a hub that requires sealing and does not always do it, and no other field in
  that snapshot says so. It is also the only `1` in that block reporting an **assumption** rather
  than a mechanism, and its description says as much.

`false` in the constructor, and **the default is the whole of its safety**: every other member of
`AuthPolicy` fails closed on a mechanism, this one fails closed on being unset. A hub with no policy
object answers `false` — the fail-closed reading here is the one that declines to waive.

§6.7 names only the setter. The getter was added with it because every other policy pair in
`Targetcore_c.h` has one and there is **no flat-C posture reader**, so without it an FFI consumer
could set the waiver and never read it back. Two symbols; the manifest is now **101**.

### The three call sites

| Site | Keyed on | Note |
|---|---|---|
| `SealAppMsgOutbound` | the **scope**, after the last-hop test | placed where `strScope` already exists, so no accessor is called twice |
| `AttestAppMsgOutbound` | the **destination**, after the entitlement test | after, deliberately — a hub that may not attest for this source must not reach a state where turning the waiver *on* is what stopped it signing |
| `GateRelayInbound` | the **source**, after the IFaddr refusal | after, deliberately — IFaddr mapping and relay attestation stay incompatible whatever this hub waived |

**Both send-side sites also require `!HasScope()`, and that condition is not in §6.3.** It is
necessary: a scope names a **subtree**, and a subtree cannot be established to be in this process
even when its root hub is, because a child hub may sit on another host. Without it, a fan-out copy
whose scope happened to equal an in-process hub address would be waived. Sealing a broadcast is
`RequireSealBroadcast`'s decision and it is a different one.

**`OpenAppMsgInbound` needs nothing**, and that is worth stating rather than leaving as an absence:
it returns early on a message that is not sealed, so an unsealed body from a waived origin is
delivered by the path that was already there.

### The part §6.3 said a fast implementation would get wrong

The receive-side exemption keys on the **registry lookup, not the link's trust class**. Keyed on the
class — "it arrived over DMX, so it is ours" — a **remote** ancestor relaying into this process
would have its unattested traffic admitted the moment the last hop happened to be in-process. Keyed
on the source being a hub this process holds, it is not. The call site carries that argument in its
own notes, beside the block explaining why the *previous* exemption there — keyed on a message
**class** — was deleted. The distinction is the same one twice: a peer can choose a message name, and
cannot put itself in this process.

### The residual, stated rather than hidden

A remote peer claiming a source that **is** an in-process hub is admitted by the receive-side
exemption. Under the deployment rule the waiver requires — in-process hubs form one address subtree
— such a message cannot arise; if that rule does not hold, the operator has already accepted a
larger hole on the send side. This is the assumption §6.3 says cannot be made fail-closed by
construction, and it is now in three places an operator will actually read: the `P2PeerHub.h` block
comment (with the A-B-C example in full, as step 5 required — not a paraphrase), `SECURITY.md`, and
`THREAT_MODEL.md` §6.2, which gets the one row in that document that *removes* a protection.

### `p2p_e2ewaive` — the gate

26 checks, **0 failed on the first run**, no sockets, per-phase hub addresses.

| Phase | Asserts |
|---|---|
| 0 | the predicate on a **live** registry: the hub's own address TRUE; one level below, two levels below, a prefix, a sibling, empty and null all FALSE; and FALSE again after the hub is destroyed |
| 1 | the default is off, the posture reports `WaiveE2E` off **beside `SealRequired` on** — the pair an operator has to be able to read |
| 1b | the flat C pair, on a handle `p2peerhub_create` owns, plus the null-handle reading |
| 2 | the setter takes, the posture follows it, and it goes **back off** — a switch, not a latch |
| 3 | **waiver OFF**: Alice requires sealing and holds no agreement key for Carol, so the message does **not** arrive |
| 4 | **waiver ON**, Carol a hub in this process: the **same** message arrives |

**The fixture is the point of phases 3 and 4.** Alice's allow-list entry for Carol carries an
identity and **no agreement key**, so `SealAppMsgOutbound` must refuse to send — and the run's own
log shows it doing so for the stated reason (`Will not send [P2PmsgBCast] scoped to [WvOff.Carol]
unsealed: no agreement key`). The observable is **delivery**, not timing and not interception, and
one switch separates the two runs. Phase 3 and 4 also each re-assert `IsP2PmsgHubInProcess` on the
live destination before sending, so a green pair cannot mean the predicate quietly went false.

### Falsified three times, once per enforcement

| | Change | Result |
|---|---|---|
| **A** | `m_oP2Paddr == strP2Paddr` → `m_oP2Paddr.IsRable(strP2Paddr)` | **red**, and only on phase 0's two below-the-hub rows |
| **B** | the waiver branch removed from `SealAppMsgOutbound` | **red**, and only on phase 4 — `delivered=0` where the run needs 1 |
| **C** | `m_bWaiveE2EInProcess ( true )` in the constructor | **red** on all three default rows, in phases 1 and 1b |

A is the one that matters: it is the at-or-below mistake, it compiles, it passes every other check in
the suite, and it silently waives the seal on traffic bound for another host.

### The flake, re-measured — and this time the baseline was actually run

`ctest -C Debug -L security` came back **37/38** on the finished tree, with `p2p_linktrust` the one
failure. Its signature is finding 7's, exactly: every phase that ran printed OK, and it died with
`PostP2PmsgCon — P2PmsgCon object already posted` unhandled on a pump thread, `abort()`, exit 3 —
phase 6 in the suite run, phase 10 when run alone.

**But the rate had moved**, and that is the part worth recording. Finding 7 says "roughly one run in
four"; this tree failed **3 of 4** in isolation. A rate change is exactly the shape of thing that
gets waved through as "the known flake", so it was attributed instead of argued:

| Tree | Runs | Result |
|---|---|---|
| **Baseline `1a48340`**, this work stashed and `targetcore` rebuilt from it | 6 | **3 pass / 3 fail**, failing in phases **9, 5 and 8** — three different ones |
| §6.3 tree | 4 (+1 in the suite) | 1 pass / 4 fail, failing in phases 6 and 10 |

**~50% on a tree with none of this change in it.** The two are indistinguishable at this sample
size, the phases differ run to run in both, and the fault reproduces with the code removed. So the
rate on this machine today is simply higher than the day finding 7 was written — load, not cause.

There is also a structural reason it cannot be this change, and it is worth stating because it is
checkable rather than statistical: **`p2p_linktrust` cannot reach any of the three new branches.**
It never calls `RequireSeal` or `RequireRelayAuth`, so `AttestAppMsgOutbound` and `GateRelayInbound`
both return at their existing policy test before the waiver is consulted; and every message it sends
is direct client-to-server, so the far-end peer **is** the scope and `SealAppMsgOutbound` returns at
the last-hop test — which sits above the waiver branch. The waiver is off by default and the harness
never sets it.

Finding 7 stays **OPEN** and its rate line is updated rather than its conclusion.

### What §6.3 does NOT include, and is still open

- **An out-of-process destination, gated behaviourally.** That needs a second **process** — no
  address this harness can invent distinguishes an in-process hub from an out-of-process one, which
  is the entire point of the predicate. Phase 0 tests the predicate directly instead.
- **The attestation half on the receive side.** `GateRelayInbound` is never reached in a chain,
  because the relay is a common ancestor of both ends — finding 11, already measured. Gating it
  wants the `p2p_authancestor` shape.
- **`examples.md`** — still finding 8, and now with a second thing to say.

---

## Finding 12, settled — the per-message ephemeral is intended, and it is not the whole bill

Step 5 raised finding 12 as a question to answer **before** §6.3 is built, on the grounds that if the
per-message ephemeral were accidental then removing it would drop the seal's whole cost off every
link. Both halves were checked on 2026-09-04. **The ephemeral is intended, and the arithmetic in the
finding is wrong by 4.7×.** §6.3 is not blocked by it.

### It is intended — three places say so, one of them by rejecting an alternative for it

1. **`Sealing.md:29`** describes the construction as ECIES and states the lifetime outright: *"Per
   message the sender generates a throwaway ECDH P-256 pair and agrees it against the recipient's
   **static agreement key**."* The two lifetimes are the design, not an artefact — `P2PCngCrypto.h:158-164`
   makes the same split the reason `EcdhP256` grew `ImportPrivate`/`ExportPrivate` at all.
2. **`P2PeerSeal.h:101-105` and `Sealing.md:85-86`** state the property it buys *and its exact
   limit*: *"the ephemeral half gives forward secrecy against later compromise of the **sender**,
   but not of the recipient."* A claim this narrow is a measured one, not an assumption.
3. **`Sealing.md:273`** is the decisive one, because it is the design **paying** for the property.
   Weighing a per-pattern group key for subtree fan-out, it is rejected in part because it *"loses
   the forward secrecy the ephemeral half provides"*. The ephemeral was priced against an
   alternative and kept. That is a decision, and this pass has no standing to reverse it.

So the question finding 12 posed — "is a per-message ephemeral intended?" — is answered **yes**, and
the honest reading is that step 5 raised it without having read `Sealing.md`.

### What it actually costs — the primitives, decomposed

Step 5 timed `SealFor` and `OpenFrom` **whole**, which is why it could attribute the whole of D − C
to the ephemeral. A scratch harness (`sealcost.cpp`, built Release against
`build/windows-msvc/Targetcore/Release/Targetcore.lib`, same instrument as `p2p_linkcost` — QPC for
wall, `GetProcessTimes` for CPU) times the exported primitives individually. N = 4 000, three runs,
CPU µs per call, **stable to under 5%**:

| Primitive | µs CPU | What it is |
|---|---|---|
| `EcdhP256::Generate` + `ExportPublic` | **230.5** | **the fresh ephemeral** — `P2PeerSeal.cpp:366-368` |
| `EcdhP256::DeriveRawSecret` | **130.2** | the agreement, per reader. Includes its own `BCryptImportKeyPair` on the peer point (`P2PCngCrypto.cpp:437`) |
| `EcdsaP256::Sign` | **96.4** | the sender signature |
| `EcdsaP256::Verify` | **108.1** | bare verify, key already loaded |
| `EcdsaP256::ImportPublic` | **76.8** | taking a peer's point out of the allow-list |
| `EcdhP256::ImportPublic` | **78.1** | the same, for an agreement key |

**The decomposition closes against step 5's whole-operation numbers**, which is the check that both
harnesses are measuring the same thing:

| Step 5 measured | Primitives predict | Residual |
|---|---|---|
| `SealFor` **468.8** | 230.5 + 130.2 + 96.4 = **457.1** | 11.7 µs — the GCM body, the wrap, two transcripts |
| `AttestRelay` **101.6** | 96.4 | 5.2 µs |
| `VerifyRelay` **218.8** | 76.8 + 108.1 = **184.9** | 33.9 µs |
| `OpenFrom` **414.1** | 76.8 + 108.1 + 130.2 = **315.1** | 99.0 µs — the slot tags, the unwrap, the allow-list lookups |

A verify costing twice a sign is now explained rather than noted: **half of `VerifyRelay` is not the
verify, it is the import.**

### The arithmetic finding 12 got wrong

The finding says that if the ephemeral were unintended, *"the same 1 080 µs (D − C) falls off every
link"*. It does not. Dropping the fresh key removes **`Generate` and nothing else**:

| | µs | Share of D − C (1 080.5) |
|---|---|---|
| The per-message ephemeral, on its own | **230.5** | **21.3%** |
| Ceiling: static sender key **and** a cached per-reader KEK (send 230.5 + 130.2, open 130.2) | **490.9** | **45.4%** |
| What finding 12 claimed | 1 080.5 | 100% |

So the finding overstates the prize by **4.7×** on its own terms, and even the most aggressive
variant leaves more than half of D − C standing — because the rest is the ECDSA sign, the ECDSA
verify and two key imports, none of which the ephemeral touches.

### And it could not be removed anyway, for a reason beyond the documented claim

`DeriveKek` takes the ephemeral public point as an input (`P2PeerSeal.cpp:428`), so a static sender
key makes the KEK **constant for every message between a given sender and reader**. The wrap is
AES-GCM with *"a fresh random nonce generated per call"* (`P2PCngCrypto.h:131`) — a 96-bit random
nonce, which is safe on a key used **once** and puts a long-lived key on the birthday bound. The
plaintext under that key is the content key itself. Today nonce reuse is impossible by construction
because the KEK never survives the message; making the ephemeral static converts a use-once key into
a use-forever one, and the v2 format has no counter field to manage it with. That is a format
change, not an optimisation.

### What the check found instead — finding 13

The 76.8 µs import is paid **per message** on every verify path (`P2PeerSeal.cpp:543`, `:637`,
`P2PAuthLogin.cpp:1305`), and caching it changes no wire format, no transcript and no security
property. It is 36% of a `VerifyRelay`, it pays on posture **C** as well as **D**, and unlike the
waiver it needs no deployment assumption at all. Recorded as finding 13 above and not acted on here.

**Conclusion: finding 12 is closed as answered. Nothing about it changes §6.3's recommendation, and
step 5's decision stands as written.**

---

## The p2pweb loader path — a fix that was not this pass's subject

Recorded here because it was found by this pass and fixed on request, and because what it exposed
is worth more than the fix.

**What was wrong.** This tree sets no unified `CMAKE_RUNTIME_OUTPUT_DIRECTORY`, so `msgcore` and
`targetcore` land in their own per-target build directories and never beside a test exe. All eleven
`p2pweb_w*` tests therefore failed under a bare `ctest` with `0xc0000135` — `STATUS_DLL_NOT_FOUND`,
raised by the loader **before main runs**. `MscsUnitTests` has had `_mscs_apply_loader_path()` for
this since 2026-08-13; `P2PeerWeb` had no equivalent and could not have one, because that function
lived in `MscsUnitTests/MscsTestCommon.cmake` — includable only by the two suites beside it, while
P2PeerWeb is its own component repository, added *before* MscsUnitTests and guarded only by its own
existence.

**The shape of it is the point.** `MscsTestCommon.cmake`'s own comment records *eleven* tests
failing at *that same status code* on 2026-08-13. This was the same failure, the same count, in a
second directory, three weeks later — because the fix was shared and **the place to put it was
not**.

**What was done.** `_mscs_apply_loader_path()` moved to the **root `CMakeLists.txt`**, which is
processed before every `add_subdirectory` and is therefore visible to every component. There is
still exactly one copy — the two existing callers did not change, same name and same behaviour —
and there is no longer a component that cannot reach it. `MscsTestCommon.cmake` keeps a note saying
where it went and why. `P2PeerWeb/CMakeLists.txt` calls it once, last in the file, guarded by the
`if(TARGET targetcore)` the tests themselves already use.

Two things were tightened while moving it, both about silent failure:

- it **returns** when the directory registered no tests, and
- it **`FATAL_ERROR`s** — rather than skipping — if it is called with tests registered but without
  `msgcore`/`targetcore` in the configure. A genex naming an absent target is a generate-time error
  anyway; the message says what the tests would have done instead of leaving a loader status code
  to explain it.

**Measured:** `ctest -C Debug -L p2pweb` **13/13**, where 11 of those had never executed a line.
`p2pweb_w1` reports *"18 checks, 0 failure(s)"*.

---

## Files changed

| File | What |
|---|---|
| `P2PeerCon.h` | `P2PeerConTrust_e`; `TrustClass`/`DemoteTrust`/`EffectiveTrust`; `m_eTrustCeiling`; `AuthLinkRelaxed` decl |
| `P2PeerCon.cpp` | those three bodies; ceiling init; ceiling copied in `AcceptSpawn`; `KeyXWanted` rewired; `AuthGateInbound` gate + a second diagnostic; `LoginSend` signing gate; two posture fields |
| `P2PeerConDmx.h` | `TrustClass()` → `InProcess` |
| `P2PeerConWsa.h` | `TrustClass()` declaration + rationale |
| `P2PeerConWsa.cpp` | `IsP2PeerConSockaddrLoopback()`; `TrustClass()` body |
| `P2PAuthLogin.h` | `Set/GetLinkPolicy` (int); `m_aLinkPolicy[3]`; **step 3:** `Set/GetTrustFloor` (int), `LinkPolicyOpensAllHeld()`, `m_nTrustFloor`, `ArmNotRequiredByPolicy` appended to `ArmResult` |
| `P2PAuthLogin.cpp` | those two bodies; array zeroed in the constructor; **step 3:** floor zeroed beside it, the three new bodies, `Arm()`'s second early return, one `AuthArmText` line |
| `P2PeerHub.h` | `P2PeerLinkPolicy_e`; `Set/GetLinkPolicy`; `Posture::anLinkPolicy[3]`; **step 3:** `RequireTrustAtLeast` / `GetRequiredTrust`, `Posture::nTrustFloor` |
| `P2PeerHub.cpp` | those two bodies; posture filled both branches; three snapshot fields; **step 3:** the two new bodies, the fence in `PostP2PeerCon`, `TrustFloor` in the posture and its snapshot field, `ArmNotRequiredByPolicy` admitted in `AuthArmOrRefuse` |
| `Targetcore_c.h` / `.cpp` | the four flat-C entry points; **step 3:** `p2peerhub_require_trust_at_least`, `p2peerhub_get_required_trust` |
| `.github/ci/abi-flat.manifest` | 4 names added for step 2, 2 more for step 3, sorted — 93 → 97 → **99** |
| `SECURITY.md` | the `RequireAuth` bullet qualified; a `SetLinkPolicy` bullet added |
| `THREAT_MODEL.md` | §3 three-class table + the pipe caveat; §6.1 two rows, both checked by `p2p_linktrust`; §8 F-SR-1 |
| `MscsUnitTests/p2p_linktrust.cpp` | **new** — the §8.3 gate, **11 phases** (7 and 8 are step 3; 9 and 10 are step 4). Also the CRT-assert report hook, the `std::set_terminate` handler and `ForceTextOutput(true)` — no modal dialog, and the abort says what it was for |
| `MscsUnitTests/CMakeLists.txt` | registers it: `security` label, TIMEOUT **720**, ports **7853–7858** locked (the pipe phases lock nothing — a pipe name carries the pid instead) |
| `P2PeerConPipe.h` | **step 4:** `P2PeerConPipeAccess_e`; `Set/GetPipeAccess`; `TrustClass()` override; `m_ePipeAccess`, `m_sPipeSddl`, `m_bPipeLocal` |
| `P2PeerConPipe.cpp` | **step 4:** `PIPE_REJECT_REMOTE_CLIENTS` + the explicit descriptor in `CreateListenPipe` and the derived `m_bPipeLocal`; SQOS on the client `CreateFile`; the setting copied by `AcceptSpawn` and the fact cleared by `Drop`/`OnClose`; `P2PeerConPipenameIsLocal`; the three new bodies |
| `MscsUnitTests/p2p_linkcost.cpp` | **new, step 5:** §8.4's measurement. Three hubs in a Dmx chain, five postures, N messages of a fixed size; wall and whole-process CPU per message with an idle baseline subtracted and the instrument's resolution printed; plus `AttestRelay`/`VerifyRelay`/`SealFor`/`OpenFrom` timed directly, because a chain's common ancestor means the chain cannot see the verify at all. Same no-modal-dialog machinery as `p2p_linktrust` |
| `MscsUnitTests/CMakeLists.txt` | **step 5:** registers `p2p_linkcost` — label **`measure`** and not `security`, TIMEOUT 900, no port and no `RESOURCE_LOCK` (every link is a pointer handoff). The `p2p_linktrust` block's closing note now points at it for §8.4 |
| `P2Pwin32.h` / `.cpp` | **§6.3:** `IsP2PmsgHubInProcess` — the registry walk, the exact match, the lock note, and the reasons for all three |
| `P2PAuthLogin.h` / `.cpp` | **§6.3:** `Set/IsEndToEndWaivedInProcess`, `m_bWaiveE2EInProcess`, `false` in the constructor |
| `P2PeerHub.h` / `.cpp` | **§6.3:** `WaiveEndToEndInProcess` / `IsEndToEndWaivedInProcess` with the A-B-C block comment; `Posture::bWaiveE2E` **appended** to the struct and filled in both branches; the `WaiveE2E` snapshot field rendered beside `SealReq` |
| `P2PeerCon.cpp` | **§6.3:** the three call sites — `SealAppMsgOutbound` (scope), `AttestAppMsgOutbound` (destination), `GateRelayInbound` (source). The two send-side ones also require `!HasScope()` |
| `Targetcore_c.h` / `.cpp` | **§6.3:** `p2peerhub_waive_end_to_end_in_process` and its getter; the assumption restated for an FFI reader who cannot see the C++ header |
| `.github/ci/abi-flat.manifest` | **§6.3:** 2 more, regenerated — 99 → **101** |
| `SECURITY.md` | **§6.3:** a `WaiveEndToEndInProcess` bullet carrying the measurement, the assumption and the A-B-C failure |
| `THREAT_MODEL.md` | **§6.3:** a §6.2 row — the only one in that document that removes a protection — and the paragraph that says why a table cannot carry it |
| `MscsUnitTests/p2p_e2ewaive.cpp` | **new, §6.3:** the gate. 6 phases, 26 checks, no sockets. Phase 0 is the predicate's algebra on a live registry; 3 and 4 are the enforcement pair, one switch apart, with delivery as the observable |
| `MscsUnitTests/CMakeLists.txt` | **§6.3:** registers `p2p_e2ewaive` — `security` label, TIMEOUT 180, no port and no `RESOURCE_LOCK` |

---

## Log

### 2026-09-04 — session start

- Read `securityRevision.md` in full.
- Confirmed `.reversa/reversa-config.json` at `MSCS/` root: `allowLegacyEdits: true`,
  `allowedPaths: []` — unrestricted, so edits to the Targetcore sources are permitted.
- Scope selected by the user: **steps 1 and 2 only**.

### 2026-09-04 — steps 1 and 2 landed

- Surveyed the seven policy sites in §2.1 against the tree; all still where the document says.
- Found the `AcceptSpawn` / `m_eListenScope` problem in §6.6 and took the `getpeername` design
  instead (above).
- Implemented, then built Debug and Release x64 clean and re-ran the repository invariants.

### 2026-09-04 — §8.3, the gate

- Wrote `p2p_linktrust`, seven phases, registered under the `security` label.
- Configured the `windows-msvc` CMake preset (there was no build tree in this checkout), built it
  whole, and ran it.
- **`ctest -L security`: 37/37 pass**, the new one among them.
- Falsified twice — the `AcceptSpawn` ceiling copy, and `AuthGateInbound`'s composed question —
  and each landed red on the phase written for it. Both edits reverted; green again afterwards.
- The two `THREAT_MODEL.md` §6.1 rows are no longer *claim*: they name `p2p_linktrust`, and the
  claim count in §6 and §9 is back to five.

### 2026-09-04 — step 3, the fence and the arm gate

- Read §6.4's fence paragraph, §6.5 and §8.3 phases 5 and 8 against the tree before writing
  anything, and confirmed that an accepted child does **not** pass through `PostP2PeerCon` — so the
  gate had to be argued for rather than assumed to cover it. It is argued for above and in the
  test's header.
- Implemented `SetTrustFloor` / `GetTrustFloor` / `LinkPolicyOpensAllHeld` on `AuthPolicy`,
  `RequireTrustAtLeast` / `GetRequiredTrust` on the hub, the refusal in `PostP2PeerCon`,
  `ArmNotRequiredByPolicy` in `Arm()` and `AuthArmOrRefuse`, the `TrustFloor` posture field, and the
  two flat-C entry points. Manifest regenerated: 97 → 99.
- Wrote phases 7 and 8 of `p2p_linktrust`, extended its address and payload tables, and locked three
  more loopback ports.
- **Falsified three times** — the fence refusal, `Arm()`'s early return, and the fence half of
  `LinkPolicyOpensAllHeld()` — each red on the row written for it, each reverted.
- The falsification of the fence is what found the duplicate-address weakness in phase 7: with the
  refusal removed, only the FIRST socket reddened, because the second was refused as a duplicate
  address instead. Fixed by giving each offered connection its own address, then re-run: both
  redden, three runs out of three.
- **Investigated the `p2p_linktrust` failure under `ctest`** rather than reporting it as flaky.
  Built the tree with both of step 3's enforcements compiled out and ran it eight times: two of the
  eight died the same way, in phases this pass did not touch. Recorded as incidental finding 7 with
  the measurement, and NOT fixed here.
- `SECURITY.md` gained the `RequireTrustAtLeast` bullet and a correction to its "appropriate use"
  line about pipes (§8.5's second row, which the earlier pass left); `THREAT_MODEL.md` §3 gained the
  paragraph separating "a class describes a link" from "a hub bounds the links it holds", and §6.1
  two more rows, both checked rather than *claim*.

### 2026-09-04 — step 4, pipe locality

- Read §4.1, §6.6, §8.1 and F-SR-1 against the transport, and read the Linux mapping in
  `Msgcore/Platform/p2psock.h` before writing anything — §6.6 records that it "was not examined",
  and it is the half that decides whether the class can be answered at all off Windows.
- Implemented `PIPE_REJECT_REMOTE_CLIENTS`, the explicit descriptor, the named legacy option, the
  client SQOS flags and `P2PeerConPipe::TrustClass()`. No ABI change: the flat C surface has no
  pipe handle, so the manifest stays at 99.
- Wrote the derivation deliberately as a read-back of the two arguments rather than a flag set
  beside them, and F and G are the two falsifications that say the difference is real.
- Grew phase 0 from one pipe row to four and added **live** phases 9 and 10. Phase 0 alone would not
  have done: under falsification H it stayed green, because it reads the setting and the setting had
  not changed.
- **Falsified three times** — the reject, the descriptor, and `_Legacy` claiming the class — each
  red on the phase written for it, each reverted from a byte copy taken beforehand.
- **Found and fixed a defect of my own by running it:** `RunPipePhase` indexed the address table by
  phase number, and phase 8 already owns index 9, so phase 9 re-used a hub address one millisecond
  after phase 8 released it. It looked exactly like the pre-existing flake. Addresses now take an
  explicit index and the table says why.
- **The user reported modal message boxes**, and that closed the diagnosis of incidental finding 7.
  They are the debug CRT's assertion dialog, not `P2Pevent`'s — they appeared with `P2PMSG_NO_UI=1`
  already set. Routed to stderr with a report hook, and a `std::set_terminate` handler added that
  names the exception: `PostP2PmsgCon — P2PmsgCon object already posted`, unhandled on a pump
  thread, in phase 7. Still NOT fixed; now scoped, with finding 9 beside it.
- `SECURITY.md`'s "appropriate use" pipe bullet rewritten with the code example and the legacy
  option; `THREAT_MODEL.md` §3's class table gained a `Local` pipe row and kept a `Wire` one, §6.1
  gained two rows (one checked, one *claim*, and the claim count moved to six), and **F-SR-1 is
  marked FIXED** with what closed it, the Linux answer, and what is still unchecked.

### 2026-09-04 — step 5, the measurement and the §6.3 decision

- Read §8.4, §6.3 and §3 first, then read `SealAppMsgOutbound`, `AttestAppMsgOutbound` and
  `GateRelayInbound` against the topology §8.4 asks for **before** writing the harness. That is
  what turned up the thing the harness had to be honest about: in a chain the relay is a common
  ancestor of both ends, so `GateAppMsgInbound`'s descendant test admits the message and the verify
  never runs. The harness says so in its own header and prices the verify separately rather than
  quietly reporting a cost with half of it missing.
- Wrote `p2p_linkcost.cpp` — five postures, not §8.4's four. The fifth is the default posture with
  `SetLinkPolicy(InProcess, Open)`, and it is the row that answers §8.4's own closing question by
  measurement instead of by argument.
- Addresses and Dmx service names are **per posture**, from an explicit table. That is step 4's
  lesson applied before it could cost anything: five stand-up/tear-down cycles on one hub address
  is the process-wide-registry race, and the previous step spent a debugging session on it.
- No timing assertion, and the label is `measure` rather than `security`. The verdict is delivery,
  so a posture that dropped its traffic cannot win the table.
- **Two defects of mine, both caught by running it.** The hubs would not arm — no revocation list —
  which every other harness in the suite answers with `RequireRevocation(false)`; and the result
  array was uninitialised, so a posture that never ran printed `1e68` microseconds per message. The
  second is why the first is written down: an unrun row has to say "(not run)".
- Measured in **Debug and Release**, and reported Release, because Debug's routing overhead swamps
  the thing under test. Ran the full measurement **twice**: reproducible to ~4%, ordering identical.
- **The answer:** §6.2 alone recovers nothing per message (E − D = 0 to the resolution of the
  instrument), the default posture costs **14× the CPU and 20× the wall time** of the same chain
  with nothing on, and **93%** of that is the two end-to-end protections. Recommendation recorded:
  **build §6.3**, keyed on the registry lookup at both ends, off by default.
- **Added an origin-link column after the first two runs**, and it is the edit that matters most in
  this step. Without it "B costs nothing over A" and "B never authenticated" produce the same
  table, and so do "E opened the link" and "`SetLinkPolicy` never took". Reading `IsKeyXDone` /
  `IsCypherActive` / `IsAuthenticated` / `EffectiveTrust` off Alice's connection settles both: B
  reads `keyx=1 auth=1`, E reads `keyx=0 auth=0` at **the same per-message cost as D**, and every
  authenticated row reads `cyph=0`.
- Third full Release run after that change; the numbers in *Step 5* are its. `ctest -C Debug -L
  security` **37/37** in 244 s on the same tree — `p2p_linktrust` included, the flake did not fire.
- Two findings recorded and not acted on: the origin signs an attestation that a common-ancestor
  tree never verifies (11), and a seal is three public-key operations with a fresh ephemeral key
  every message (12). The second is worth settling before §6.3 is built, because it would move a
  larger number and needs no deployment assumption to do it.
- **No library source changed.** The ABI manifest is still 99; `-L security` still selects 37.

### 2026-09-04 — finding 12 checked, before §6.3

- Read `Sealing.md` **before** measuring anything, which is what settled it: the per-message
  ephemeral is stated at `:29`, its exact forward-secrecy claim at `:85-86` and `P2PeerSeal.h:101-105`,
  and at `:273` a group-key alternative is **rejected in part for losing it**. Step 5 raised the
  question without having read that document; the answer was already written down.
- Then measured, because the finding's second half is an arithmetic claim and arithmetic is
  checkable. Wrote a scratch harness timing the exported primitives individually — step 5 had timed
  `SealFor` and `OpenFrom` whole, which is exactly how the whole of D − C came to be attributed to
  one of the three operations inside them.
- **The decomposition closes against step 5**: predicted `SealFor` 457.1 against measured 468.8
  (2.5% residual), and `AttestRelay` to 5%. Two harnesses, two instruments, same numbers — which is
  the only reason to trust either.
- **The answer:** the ephemeral costs **230.5 µs**, 21.3% of D − C, not the 100% the finding
  assumed — an overstatement of **4.7×**. Even a static sender key plus a cached KEK caps out at
  45.4%; the remainder is ECDSA and key imports.
- **And it is not removable regardless.** `DeriveKek` takes the ephemeral point (`P2PeerSeal.cpp:428`),
  so a static key makes the KEK constant per (sender, reader), and the wrap is AES-GCM under a
  **random 96-bit nonce** (`P2PCngCrypto.h:131`) wrapping the content key. Safe on a use-once key,
  a birthday-bound problem on a use-forever one, and v2 has no counter field. Format change, not
  optimisation.
- **Finding 13 recorded**, and it is the one worth having: the peer's public key is re-imported from
  the allow-list **per message** (`P2PeerSeal.cpp:543`, `:637`, `P2PAuthLogin.cpp:1305`) at 76.8 µs
  a time — 36% of a `VerifyRelay`. Caching it is security-neutral and pays on posture C too, which
  no waiver does. Left to the `P2PIdentityStore` owner because the revocation lifetime is theirs.
- **Finding 12 closed as answered. §6.3 is not blocked; step 5's recommendation stands unchanged.**
- **No library source changed, no test registered.** The harness is scratch
  (`sealcost.cpp`, session scratchpad) and is *not* in `MscsUnitTests` — promoting it is a separate
  call, and it would want the CMake registration and a `measure` label like `p2p_linkcost` has.

### 2026-09-04 — §6.3, the end-to-end waiver

- Read §6.3 in full first, then the three functions it names and the registry it points at, before
  writing anything. That is what turned up the two things §6.3 does not say and the implementation
  needs: `QueryP2PmsgExp_Hub` is an explorer notification and not an address lookup, so the
  predicate had to be written; and `s_ThreadID_P2PmsgHub` is keyed by THREAD, so it is a walk.
- **The exact-match decision came before the code, not after a bug.** §6.3 says "the scope address
  resolves to a hub in this process" and does not say how. At-or-below is the reading that looks
  more useful and is the one that waives the seal on traffic to a child hub on another host.
  Equality is also what `OpenAppMsgInbound` already uses to decide "is it for us", so the waiver and
  the router agree by construction rather than by coincidence.
- **Added `!HasScope()` to both send-side sites, which §6.3 does not ask for.** A scope names a
  subtree and a subtree cannot be shown to be in this process even when its root is. Without it a
  fan-out copy whose scope equalled an in-process hub address would be waived.
- Placed the receive-side exemption **after** the IFaddr refusal and the send-side attestation one
  **after** the entitlement test, both deliberately, both with the reason written at the site: a
  waiver must not make an unsupported configuration look supported, and must not be what stopped a
  hub signing when it was never entitled to sign.
- **`OpenAppMsgInbound` needed nothing**, and that is recorded rather than left as an absence.
- Wrote `p2p_e2ewaive` with **delivery** as the observable, not timing and not interception: Alice's
  allow-list entry for Carol carries an identity and no agreement key, so the seal must refuse.
  Waiver off, nothing arrives; waiver on, the same message does. **26 checks, 0 failed on the first
  run**, and the run's own log shows the refusal happening for the stated reason.
- **One defect of mine, caught by reading rather than running**: the first draft asserted the flat-C
  getter against a C++ hub cast to `P2PeerHubHandle`. Handles are validated through `P2PhandleIs`,
  which only knows objects `p2peerhub_create` made — so that check would have read 0 because there
  was no hub, not because the bit was off, and it could not have failed. Phase 1b uses a handle the
  ABI owns.
- **Falsified three times**, each red only on the rows written for it: the at-or-below match (phase
  0), the send-side branch removed (phase 4), the default flipped to true (phases 1 and 1b). A is
  the one that matters — it compiles, it passes everything else, and it is the silent version.
- §6.7's flat-C setter added as named, plus the getter, because there is no flat-C posture reader
  and without it an FFI consumer could set the waiver and never read it back. Manifest **99 → 101**;
  `check_repo_invariants.py` green on all seven sections.
- §8.5 documentation done for this piece: `SECURITY.md` gets the bullet with the measurement and the
  A-B-C failure, `THREAT_MODEL.md` §6.2 gets the one row in that document that **removes** a
  protection, plus the paragraph explaining why the table cannot carry it alone.
- **Two things caught on a last read of the diff, before committing, and both were real.** The
  posture field had been *inserted* into `Posture` rather than appended, which moves every offset
  after it — a consumer compiled against the previous header would have read it where
  `bSealCanOpen` used to be. And it had no **snapshot** field at all, so the one place an operator
  actually looks would not have shown the waiver: steps 2 and 3 both added theirs and this one had
  been missed. The two fixes point opposite ways — append in the struct, group by topic in the
  snapshot — and the reason is written at both sites.

### 2026-09-04 — branch review, finding 1: pipe-name squatting

- A security review of the branch against master found that `CreateListenPipe` asked for the
  reject and the descriptor but could not know they were **applied**: a named pipe carries the
  descriptor of its *first* instance, and a later `CreateNamedPipe` on the same name is a further
  instance of that pipe under an access check against the existing DACL. So an A7 principal who
  created the name first, permissively, would have had this transport join their pipe — clients
  admitted on their terms — while `m_bPipeLocal` read back the arguments this end passed and the
  class said `Local`. With `SetLinkPolicy(Local, Open)` that is an unauthenticated login for any
  local account.
- **Fixed with `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance only.** A new
  `m_bPipeRearm`, set by `AcceptSpawn` on the spawn and nowhere else, is what tells
  `CreateListenPipe` it is re-arming a pipe the accepted sibling still holds under this transport's
  own descriptor — the flag there would refuse the transport's own pipe. `ERROR_ACCESS_DENIED` on a
  first-instance create is refused with its own diagnostic naming the holder, rather than the
  generic "check assignment".
- **The fact gained a third half.** `m_bPipeLocal` now also requires that the open mode carried the
  flag, or that this was a re-arm — read back from the argument like the other two, so deleting the
  `|=` turns the class to `Wire`.
- `Legacy` does not pass the flag: it is documented as the pre-revision call byte for byte, it reads
  `Wire`, and a squatter gains nothing past a `Full` login gate.
- **Residual, stated at the site and in `THREAT_MODEL.md`:** if the accepted sibling drops before
  the spawn re-arms, the name is free for one dispatch and a re-arm in that window joins whatever
  was made in it. Closing that means reading the descriptor back off the created handle, which is a
  separate change.
- Linux: the mapping ignores the open mode and `bind()` on an existing `AF_UNIX` path fails rather
  than joins, so the flag has no counterpart and needs none. Guarded under `_WIN32`.
- Built Debug x64 clean. `p2p_linktrust` phases 9 and 10 are unchanged in shape; a phase that
  creates the name first and requires the service's create to be refused is the gate this wants
  and has not been written.

### 2026-09-04 — branch review, findings 2, 3 and 4

The three remaining findings of the same review. None is a downgrade on its own; each is a place
where a fact the feature rests on was asserted rather than established.

**Finding 2 — the client's `Local` was a prefix match.** `\.\` is the DOS device namespace and,
unlike `\?\`, a path under it is still normalised, so `\.\pipe\..\UNC\host\pipe\x` carried the
prefix the test matched and went out through the redirector. **Measured rather than reasoned**: a
scratch probe put that string through `GetFullPathNameW`, which returned `\.\UNC\host\pipe\x`. So
the finding was real and not merely plausible.
- The name test now requires the remainder after the prefix to be **one component with no
  separator**, which is exactly what the platform permits a pipe name to be (any character except a
  backslash) — so nothing legitimate is refused. 12 cases in a scratch probe, 0 failed, including
  both traversal spellings and both legitimate names the suite actually uses.
- And the name is no longer asked alone. `Connect()` confirms the OPEN HANDLE with
  `GetNamedPipeServerProcessId`, which a remote server cannot answer. The note that had been left in
  the source said a handle reading would cost a syscall "on every posture read" — true of asking it
  from `TrustClass()`, and not true of asking it once where the handle is opened, which is what
  moved.
- **The one assumption in this fix was measured before it was relied on**: that the call SUCCEEDS on
  a local pipe. It does — probe, pid returned on both the client and the server handle. Had it not,
  the client would have read `Wire` against a `Local` server and every relaxed pipe link would have
  broken; that is a functional break rather than a security one, but it is the kind that is found in
  somebody else's deployment.

**Finding 3 — the fence measured a service against its INTENTION, and children never met it.** At
`PostP2PeerCon` a service holds no handle: a pipe answers from `m_ePipeAccess` and a socket from
`m_eListenScope`, both of which a later setter can change, and an accepted child is spawned by its
service and never passes through that function at all. So a hub fenced at `Local` behind a service
bound to `P2PeerConScope_Any` admitted every off-host child the fence exists to refuse.
- One helper, `P2PeerCon::TrustFenceRefusesClass()`, asked at the two moments the class stops being
  an intention. It takes the class rather than reading `TrustClass()`, so a SERVICE can ask on
  behalf of a child that does not exist yet, and it applies the ceiling the child will inherit.
- `CreateListenPipe` re-asks once the pipe exists and `m_bPipeLocal` has been read back out of the
  arguments the kernel was given. **It closes the handle before it throws** — a listener the hub
  will not hold must not leave the name taken by an endpoint nothing is listening on.
- `P2PeerConWsa::AcceptSpawn` asks per child, from the `getpeername()` reading it already takes, as
  a fourth admission test beside the allow-list and the two capacity bounds. **Asked last** of the
  four, because it is the only one about the LINK rather than about the peer, and reporting a class
  to an operator who wrote an allow-list rule is the wrong-number failure that block is already
  careful about. **Traced, not raised**, for the reason its three neighbours are: it is refused at
  accept, so whoever is dialling can repeat it at will.
- **Per child and not at listen**, deliberately: a service bound to `Any` on a hub fenced at `Local`
  legitimately carries loopback peers, and refusing the LISTENER would refuse those too.
- Not changed: raising a floor on a running hub still evicts nothing. The fence is documented
  configure-before-arm like every other setting here, and that is left standing rather than quietly
  given a second meaning.

**Finding 4 — a relaxed server serviced a key agreement it did not want.** "Both ends need the same
answer" was enforced in one direction only: a client that SKIPPED the agreement was refused where it
happened, and a client that OPENED one against a relaxed hub was serviced, with the disagreement
surfacing later at `AuthGateInbound` as a login block handed to the application.
- Refused at `KeyXOnRequest`, before the exchange runs, naming the class and both ways out.
- **Gated on `AuthLinkRelaxed()` and NOT on `!KeyXWanted()`**, which is the whole care in this one.
  There are two ways to reach "this link runs no agreement" and only one is new; a hub with
  `RequireAuth(false)` has always serviced a peer's exchange, and gating on the wider predicate
  would have changed the behaviour of every deployment that predates the trust class.
- `KeyXOnAck` needs nothing: a relaxed end never sends a request, so `m_pKeyX` is null and its first
  line already refuses an acknowledgement that answers nothing.

**Verification.** Debug x64 clean, 0 errors and no warning in any of the four files touched (the
24 the solution emits are all in files this change does not open). `ctest -C Debug -L security` was
run twice: **38/38** on the second, and 37/38 on the first with `p2p_linktrust` the one failure —
finding 7 again, and **attributed rather than assumed** rather than waved at, because the phase it
died in was pipe code this change had just edited. 8 runs on this tree failed 5, in phases 5, 6 and
9; the SAME 8 runs with this work stashed and targetcore rebuilt from `0376c45` failed 5, in phases
6 and 10. Same rate, different phases, both trees, and the phase it lands in is not the phase that
was edited. `p2p_linktrust` phases 9 and 10 exercise the real pipe end to end, so the
handle confirmation and the `CreateListenPipe` fence are covered by an existing gate even though
neither has a phase of its own.

**NOT DONE.** No phase pins any of these three. What each wants: a name with a traversal in it
refused as `Wire`; a service whose access mode or listen scope changes after it is posted refused
at listen or per child; and a Full client against an Open server refused at the exchange rather than
at the login. `MscsUnitTests` is a sibling repository and the additions belong with it.
