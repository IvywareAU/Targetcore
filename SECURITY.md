# Security Policy

## ⚠️ Read this before deploying Targetcore

**Targetcore verifies peer identity and encrypts its connections BY DEFAULT since 2026-08-18. A hub
that is not provisioned to do that no longer starts.**

This reverses the posture this file carried until then, and it is a **breaking change**. Before it,
authentication was opt-in and off, which meant a hub verified nothing unless somebody remembered to
ask — so the deployments that most needed it were exactly the ones that never called `RequireAuth`.

What changed, precisely:

- `RequireAuth` now defaults to **true**. A login must carry an ECDSA P-256 signature bound to the
  connection it arrived on, and the session is AES-256-GCM sealed under an ephemeral ECDH key.
- A hub that requires auth and **cannot enforce it refuses to arm**. `CreateHub()` returns `FALSE`
  and `SpawnHub()` returns `0`, and the refusal names the file that is missing. The flip on its own
  would have been worse than the old default, not better: a hub that requires auth and holds no keys
  does not refuse an attacker, it refuses *everyone*, at the first peer's login — which in practice
  means at 3am, to whoever did not do the deployment. The gate moves that failure to the deployment.
- The migration is one line. Either provision the hub (see *Turning peer authentication on* below —
  `ProvisionAuth()` makes the identity and prints the fingerprint to publish), or call
  **`RequireAuth(false)`** before arming and mean it. What is no longer possible is turning it off by
  *saying nothing*.
- **Since 2026-08-21 the gate also asks about revocation, and this half is a bigger break.**
  `RequireRevocation` defaults to true: a hub that requires auth must either name a revocation list
  or say **`RequireRevocation(false)`**, and one that does neither does not start. Step 8 refused a
  hub that would have refused every peer anyway; this refuses one that **works**. It is worth the
  break because revocation is the only mechanism here for *withdrawing* trust already granted —
  rotation and the allow-list only ever add — so a hub with no position on it can never answer
  "this key is compromised". Turning the requirement off does not turn revocation off: a list named
  anyway is still loaded, still enforced, still fails closed.

`RequireAuth(false)` is a supported answer, not a defeat: a hub on a trusted segment, an in-process
router, a test that is not about authentication. Covered by `p2p_armgate`, which includes the
opt-out as a required phase — if the migration did not work, this change would be an outage rather
than a default.

**Do not expose an unconfigured Targetcore endpoint to a network you do not control.** The
configured path has not been externally audited, so treat it as defence in depth behind a tunnel
rather than as a substitute for one.

**~~If you host a hub inside a Windows service, set `P2PMSG_NO_UI=1` in its environment.~~ Fixed in
code on 2026-08-17 — no longer required.** The problem it worked around: a library diagnostic is
written as text when there is somewhere to write it, and raised as a `MessageBox` when there is not.
A service started by the SCM has neither a console nor a standard error, so the dialog went up on
whichever thread produced the event — for a routing or connection diagnostic, the hub's own pump
thread. Nobody can dismiss a dialog in a non-interactive session, so the pump never returned, never
saw the CLOSE signal, and `CloseHub()` waited for it indefinitely; that wait is unbounded by design,
because bounding it would trade a hang for a use-after-free.

`P2PeventUseTextOutput()` now asks whether anybody **could see** a dialog before it asks whether
there is anywhere to **write** one — `ProcessIdToSessionId` for the isolated services session, and
`WSF_VISIBLE` on the process window station. A service fails both and never reaches the dialog
branch, with no configuration at all. A windowed application is in session ≥ 1 on a visible station,
so it is unaffected and keeps its dialogs. `P2PMSG_NO_UI=1` still works, and
`P2Pevent::ForceTextOutput(true)` is the same switch from code, for a windowed host that wants no
dialogs from the library at all. `P2PeerService` sets it for a hosted hub either way.

Refusing the dialog is half the fix; the other half is a destination, or the diagnostic is written to
a handle that is not there and a defect that used to hang loudly disappears quietly. In service mode
`P2PeerService` routes diagnostics to the **Windows application event log** under the service's own
name, registering the source in `Install()`. `P2Pevent::SetTextSink()` is the hook if you want them
somewhere else. Worked example: `_Targetcore_UseExamples/ErrorReportingExamples/NTServiceEventLog`.

A plain text file beside the host executable, `P2Pmsg.cfg`, says the same two things without code —
`ErrToMessageBox: 0` to refuse the dialog and `LogFile: <name>` for the destination, defaulting to
`errorLog.txt`. Read this part before deploying one, because both rules exist to stop the file
becoming an attack on availability rather than a convenience: **`ErrToMessageBox: 1` cannot put a
dialog back** where one would hang — the setting moves only towards text, and cannot cancel
`P2PMSG_NO_UI`, `ForceTextOutput(true)` or the viewability test — and **`LogFile` loses to an
installed sink**, with a relative path resolved against the configuration file's own folder rather
than the working directory, so a file dropped beside an executable cannot divert a service's
diagnostics out of the event log and into `%SystemRoot%\System32`. Anything the parser cannot read is
ignored and reported through `P2Pevent::ConfigDiagnostic()`; neither default is ever guessed at.
Worked example: `_Targetcore_UseExamples/ErrorReportingExamples/DialogOrLogFile`.

Appropriate use today:

- Loopback and single-machine inter-process messaging — and since 2026-09-04 **`P2PeerConPipe`
  enforces it**. `CreateListenPipe` passes `PIPE_REJECT_REMOTE_CLIENTS`, which keeps the SMB
  redirector out, and an explicit protected DACL —
  `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)`, the same three ACEs the identity file gets — in place
  of the platform default that granted Everyone and Anonymous read access. The client opens with
  `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so a server squatting the pipe name is handed
  the client's bytes and not its token. **The server side of squatting is refused too**: a named
  pipe keeps the descriptor its *first* instance was created with, so a local principal who
  created the name first would have had this transport join *their* pipe while the class still
  read `Local`. The first instance `CreateListenPipe` makes therefore passes
  `FILE_FLAG_FIRST_PIPE_INSTANCE` and a name that already exists fails, `ERROR_ACCESS_DENIED`,
  with a diagnostic naming the holder; the re-arm after an accept is a second instance of the
  transport's own pipe and does not pass it. Such a pipe answers `TrustClass() == Local` and its hub may
  relax it with `SetLinkPolicy(P2PeerConTrust_Local, P2PeerLinkPolicy_Open)`
  (`THREAT_MODEL.md` F-SR-1, now closed)
- **The old pipe is still reachable, by name.** `SetPipeAccess(P2PeerConPipeAccess_Legacy)` on the
  service connection reproduces the pre-2026-09 `CreateNamedPipe` byte for byte — no reject, null
  descriptor — for a deployment that shares a pipe between a service account and an interactive
  user, or reaches one over SMB. That pipe is a wire and reads `Wire`, which is the point: the
  compatibility escape hatch is precisely the one that does not get to claim the class.
  `SetPipeAccess(P2PeerConPipeAccess_Descriptor, sddl)` is the middle — the reject stays, the
  caller supplies the DACL

  ```cpp
      // this account only, no remote clients, and the class says so
      P2PeerConPipe *pSvc = P2PeerConPipe::ServiceFactory ( L"App.*", L"\\\\.\\pipe\\MyApp" );
      oHub.SetLinkPolicy ( P2PeerConTrust_Local, P2PeerLinkPolicy_Open );
      oHub.PostP2PeerCon ( pSvc );        // pSvc->TrustClass() == Local
  ```

  On Linux the pipe is an `AF_UNIX` socket and there is no equivalent of a pipe over SMB, so the
  class is a property of the address family and holds in every mode; what has no counterpart there
  is the DACL, and access control is the `0700` directory plus the process umask
- Trusted LAN segments and lab networks
- Directly attached hardware buses (`P2PeerCon232`, `P2PeerConDmx`)
- Research, teaching, and modernisation work on the codebase itself

Not appropriate today:

- The public internet
- Any network segment carrying untrusted peers
- Any deployment where message authenticity or confidentiality matters
- Anything handling personal data, credentials, payments, or safety-critical control

## Current security posture

> The analysis behind this table — the adversaries each row answers, the assets they defend, and what is
> deliberately out of scope — is [`THREAT_MODEL.md`](THREAT_MODEL.md). This file is the operator-facing half:
> what the defaults are, how to turn things on, and how to report a vulnerability.

| Property | Status |
|---|---|
| Pre-login traffic blocked | ✅ Enforced, and covered by a test. Application messages arriving before login are discarded and the connection dropped. |
| What an unauthenticated peer may hold | 🟡 **Half bounded since 2026-08-16.** Before that there was **no bound of either kind**, which is the one exposure category none of the login, sealing or replay work touched — all of that decides who may *speak*, and this is spent before a word is said. **The connection cap is on by default, works on both platforms, and is TCP-only:** `SetMaxAccepted(n)` on the SERVICE connection caps concurrent accepted connections (default **1024**, `0` unbounds) and refuses the next one *at accept*, closing the socket rather than leaving it pending — a bound that left them queued would only move the growth into the backlog. **Scope stated precisely, because this row read as coverage until 2026-08-17:** `AcceptAtCapacity()` is called from exactly one place in the tree, `P2PeerConWsa::AcceptSpawn` — the pipe, serial and DMX transports each have their own accept path and never test it. Those three are bounded anyway, but *incidentally and by a different mechanism*: the pipe server passes `2` as `nMaxInstances` to `CreateNamedPipe`, so the OS refuses a third instance, and serial and DMX are bounded by physical ports. So there is no unbounded accept in the tree today; there is one documented bound covering one transport, and three bounds that hold for reasons this row does not control — if a future change raises that `nMaxInstances`, pipe loopback, the deployment this file recommends first, loses its bound silently. `P2PeerConWsa::SetBacklog(n)` replaces a hardcoded `listen(32)` whose comment named an `m_xConnections` that never existed. Covered by `p2p_acceptcap`, which uses **raw sockets rather than hubs** on purpose: the peer being modelled does not run this library and will not complete a handshake. **The login deadline is implemented, opt-in, off by default, and works on BOTH platforms since 2026-08-18** - `SetLoginDeadline(ms)` drops a connection that has not completed its login, guarded by `p2p_logindeadline`, now registered on Windows **and** Linux. ~~On Linux the drop that followed the timeout also cancelled the *listening* socket's pending accept, and one timed-out peer took the whole listener down; the accepted fd inherits the listen socket's completion key in `p2piocp.cpp`'s accept completion, which is where that starts.~~ **The recorded cause above was wrong**, and it was recorded in three places. Traced rather than assumed: the application re-associates the accepted fd with its own key immediately after accept, so nothing ever reads the inherited value. The real fault was that `closesocket()` erased the fd -> key association **before** the cancellations it triggered completed, so every `ERROR_OPERATION_ABORTED` arrived with completion key 0, unattributable, and the service read it as a failure of the listener. Fixed by binding the key at submission (`OVERLAPPED::_p2p_key`), which is what Windows does. `DEF_P2PeerConLogin` is still `0` - the cascade that forced that default is gone, but the deadline stays opt-in. **A per-source bound closed the gap this row used to name, on 2026-08-19.** The sentence here said the cap was per service and could not be per source *"because the address is not known until the login that has not happened"*. Half of that was right and half was a wrong turn: the P2P **address** indeed is not known, but the source **IP** is — `getpeername()` on the accepted socket, read on the SERVICE at the one instant it still owns the half-accepted endpoint, about a peer that has said nothing. `SetMaxAcceptedPerSource(n)` is that bound, accounted in a block shared between the service and every child so neither must outlive the other, taken in `AcceptSpawn()` and given back in `~P2PeerCon()` — the only release path, so no close, drop or unwind can leak a slot. **Default 0 (off), and that is a decision:** a source is an IP, and both topologies this library is actually run in collapse many peers onto one of them — loopback, which every test in the suite dials, and NAT — so a default that bound would refuse legitimate traffic silently at accept. The MECHANISM is always present; the NUMBER is opt-in, which is the judgement `DEF_P2PeerConLogin` already makes. `P2PeerCon::AcceptSourceKey()` is virtual and returns **0 for a transport with no such notion**, and a zero key is never counted and never refused — so 232 and DMX, which are point-to-point by construction, are correctly inert rather than falsely bounded. Guarded by `p2p_srcbound`, which proves the refusal is about the ORIGIN by serving a second address while the first is refused, with fourteen of the service’s sixteen slots free throughout. **Still not bounded: the pipe.** `CreateNamedPipe` is called with a hardcoded `nMaxInstances` of **2** — a bound the library does not own — and because that transport MORPHS (the listener becomes the accepted connection), refusing at capacity means declining to re-arm, which has no path today. **And read both accept bounds with `F-S4-1` in hand:** on Windows a peer that connects, says nothing and disconnects is never reaped, so both count connections EVER ACCEPTED rather than currently held — which makes a bound of 1024 a slower version of the attack unless a login deadline is armed. **The deadline was not new code**, which is the uncomfortable part: the timer has been complete since the import — expiry throws, and all three cancel sites are correct — and only the line arming it was commented out. Arming it immediately exposed a latent fatal defect in `CancelP2PmsgTimer`, which treated "the timer already fired" as corruption and threw **from `~P2PeerCon`**, terminating the process; that is fixed, and it had been reachable by the restart timer all along. |
| Message source bound to the connection | ✅ **Enforced on every link, by default, since 2026-08-18.** A link to a descendant or an unrelated peer has always been bound. A link to an ancestor is bound by `RequireRelayAuth`, which now defaults to **true**; `RequireRelayAuth(false)` restores the old exemption exactly and is the documented migration. **Deliberately NOT part of step 8's arming gate**, and the asymmetry is the judgement: an unprovisioned hub requiring *login* auth refuses every peer, so refusing to arm loses nothing, whereas one requiring *relay* auth refuses only a message arriving down an ancestor link sourced outside that ancestor's subtree - and a relay legitimately holds no keys at all, so gating on provisioning would force every router in every tree to be keyed or opted out to carry traffic it is not being asked to vouch for. What stands in for the gate is that the refusal is loud: `GateRelayInbound` names the relaying peer, the claimed source, the `AuthResult`, and whether the attestation was absent, unlisted or skewed. **One exemption survived turning the default on, and it is now GONE - closed 2026-08-20 as F-S9-1, at the other end of the path from where it lived.** It was found by turning the default on rather than reasoned about in advance: the library's own undeliverable-message report was sourced from the address that could not be reached, so it declared a source in no branch at all and nobody could hold a key for it. The report had therefore always depended on this exemption, and closing the exemption stopped senders being told their messages were undeliverable - the exact defect the *Undeliverable report* row records as fixed. So `P2Pmsg_Exception` was exempted from the relay gate **by class**, and that cost this: a peer on an ancestor link could forge an undeliverable report claiming any source, so an application could be told a message failed that did not. It could not deliver application traffic that way. **What closes it is not a better predicate but the truth about who is speaking.** The report is not from the address that could not be reached; it is from the hub that could not reach it - and that hub can speak for itself. `P2PeerTarget::RouteP2PeerMsg` now stamps the report with its own hub address, so one hop down the plain descendant test admits it with **no keys and no provisioning of any kind**, and further down `AttestAppMsgOutbound` signs it as the origin exactly as it signs anything else that hub sources. **There is no class exemption in `GateRelayInbound` any more**, and the deletion is the point rather than a tidy-up: while it stood, *every* `P2Pmsg_Exception` on an ancestor link was admitted unchecked and only one of them was the library's. Gated by `p2p_reportsign`, proven red in both directions - unstamped, the report is refused and the sender is not told; with the exemption restored, a relay's forged report sourced `Ghost.Nowhere` is admitted. **What a reader must change:** the report's declared source is no longer the address that failed. It has moved, not gone - the report wraps the original message, so `UnwrapFactory()->GetDestin()` is the failed address, and the attached `P2Pevent` names it in an `Advice` line. Recorded as an unreleased break. A message whose source is not the logged-in identity (or a descendant of it) is rejected and the connection dropped — covered by a test (`p2p_authspoof`). **What the ancestor link is:** a peer at or above this hub is its gateway to the rest of the tree, so everything routed *down* arrives still carrying its original source, which lies outside the relaying peer's subtree whenever it came from another branch. Refusing it made downward transit and multi-hop broadcast impossible (2026-08-13), so the link was exempted outright. **What closes it** (2026-08-14) is not a better predicate but evidence: with `RequireRelayAuth(true)` the message must carry an attestation signed by the **origin's** ECDSA identity key — which the relaying ancestor does not hold — and the same at-or-below test is then applied to the identity that *signed* rather than to the peer that *delivered*. The rule is not weakened on this link; it is bound against a different, proven thing. The attestation covers both addresses, the message name and a SHA-256 of the body, so a relay can forward it but cannot edit anything the receiver acts on. Off by default because verifying needs the origin provisioned into this hub's allow-list, and a tree that has not done that would simply stop carrying downward traffic. Note what was never covered by any of this: a peer may always speak for its own subtree, which contains this hub and everything below it, so a parent has always been able to claim its children's addresses. Covered by a test (`p2p_authancestor`), which until 2026-08-14 was the only test here asserting a *gap* rather than a protection and now asserts both — a genuinely attested cross-branch relay arriving, an unattested claim of the same source being refused, and the pre-existing behaviour still being what an unconfigured tree gets. **An attestation could be delivered twice until 2026-08-15**, when `RefuseRelayReplay(true)` was added — off by default, and bounded by both the freshness window and a count; see the *Replayed message refused* row. |
| Login address restricted to a domain | 🟡 Enforced where a domain is set. `P2PeerConWsa::ServiceFactory`'s peer argument doubles as the accepted-address pattern, so a service expecting exactly one peer is tight. A `P2PeerConDmx` service sets none. |
| Peer **identity** verified | ✅ **Implemented, and ON BY DEFAULT since 2026-08-18.** A hub that requires it and cannot enforce it **refuses to arm**, naming the file that is missing, so what used to be an "unconfigured" hub that verified nothing is now a hub that does not start - covered by `p2p_armgate`. The migration is `RequireAuth(false)`, said out loud. With `RequireAuth(true)` and an allow-list, a login must carry an ECDSA P-256 signature over its addresses, a nonce and a timestamp, checked against the public point the allow-list binds to the *claimed* address — so a name has to match a key. Covered by a test (`p2p_authpsk`). **Unconfigured, the old exposure stands:** a domain is a *wildcard pattern*, any server accepting more than one client needs a broad one, and every peer matching it may claim every address matching it. See *Turning peer authentication on* below. |
| Payload encryption | ✅ **Implemented, and ON BY DEFAULT since 2026-08-18** - it rides on `RequireAuth`, which now defaults to true; the two are one switch on purpose. With `RequireAuth(true)` every connection runs an ephemeral ECDH P-256 agreement before its login, and all traffic from the login onwards is AES-256-GCM sealed. **And since 2026-08-20 the transport is required to USE that key, by rule rather than by inheritance (F-S6-3).** The cypher hooks live in `P2Peerio`, so until then whether a connection was encrypted followed from which io subclass its factory happened to construct — correct for every transport in the tree, enforced nowhere. A hub that requires authentication now refuses to key a connection whose io object says its frames leave this process and that it will not consult the cypher, and refuses to write any frame that no sealing decision was recorded against. The one in-process transport, `P2PeerConDmx`, declares itself exempt and says why at the declaration. Covered by `p2p_confchannel`. Unconfigured, the hook still defaults to plaintext passthrough. |
| Message integrity / AEAD | ✅ **Active wherever authentication is — which is by default since 2026-08-18.** A frame whose GCM tag fails raises `P2Pmsg_CypherEx` and drops the connection. Covered by a test (`p2p_authrelay`). |
| Proof bound to the channel it arrived on | ✅ **Implemented, on by default, and required at BOTH ends since 2026-08-20.** The login and ack signatures cover `SHA-256("P2P-kx-v1" \| client_pub \| server_pub)`, so a proof made for one connection is refused on any other (`p2p_authrelay`). **It rides on `RequireAuth`, which defaults to true — but until 2026-08-20 only the INITIATING end treated the two as one switch.** A verifier accepted a login signed with a *null* binding by a peer that had run no key agreement, because both ends then computed the same null transcript: an authenticated session in cleartext, on a hub that required authentication. Found by writing [`THREAT_MODEL.md`](THREAT_MODEL.md) (finding F-S6-1), fixed by one condition in `AuthGateInbound`, and gated by `p2p_authchannel`. **This refuses a peer that used to be accepted:** a hub with `RequireAuth(false)` that also holds an identity key signed without exchanging keys and was let in. Set `RequireAuth(true)` on it, or `RequireAuth(false)` on the server and mean it. |
| Key exchange | ✅ Ephemeral ECDH P-256 → HKDF-SHA256 → AES-256-GCM, per connection, **no negotiation** — a security upgrade an attacker can decline is one they will decline. **This row was 🟡 until 2026-08-22, and the sentence that closed it was already sitting in it:** the yellow meant a modern exchange existed *alongside* the legacy `DHKeyXChanger`, and that path has been deleted — `grep` finds the name only in comments recording its removal. This is now the only key exchange in the tree, so there is nothing left for the dot to qualify. **The other two documents already said so:** `Readme.md` has carried this property at ✅ throughout, and [`THREAT_MODEL.md`](THREAT_MODEL.md) lists the session cypher as **on**, gated by `wsa_mesh` and `crypto_kat`. **What this row does not cover** is rekeying: the session key lives as long as the connection. That is tracked as the outstanding half of roadmap item 3 below, and as its own ❌ row in `Readme.md`, not by a dot on this one. |
| Body hidden from an intermediate hub | ✅ **ON BY DEFAULT since 2026-08-21, and it REFUSES rather than downgrades.** A message whose destination is not the peer on the far end of the link is sealed to that destination before it goes, and a hub holding no agreement key for the destination **drops the message and says so** rather than sending the body in clear. The block is now a MULTI-RECIPIENT envelope (`kSealVersion` 2, `P2PeerSeal.h:120`): the body is encrypted once under a random content key and that key is wrapped once per reader, so a destination *and* the intermediate hubs the **sender** names with `AddSealReader` can each open it — the reader set is bound into the additional data and the signed transcript, so no relay can add itself. A v2 reader still opens a v1 body; a v1 reader refuses a v2 one, so a mixed mesh upgrades receivers first. Opt-out is `RequireSeal(false)`. **Broadcast is a separate answer, and since 2026-08-25 it is a separate switch.** A broadcast has an AUDIENCE rather than a destination: `On_P2PeerBCast` sends a copy per link and the scope those copies carry names a *subtree*, which no single agreement key opens. So a broadcast on a sealing hub is **refused**, every time, and `RequireSealBroadcast(false)` is how a deployment records that its broadcasts are not confidential — exempting fanned-out copies **only**, leaving relayed unicast sealed, and leaving the origin's attestation on the exempt copies, so they are unencrypted and still unforgeable. `TryReadPosture` reports it as `SealBcast`. **Confidential broadcast is not available and is an open design question.** The previous text here said sealing and broadcast "do not compose" because a broadcast could never be sealed and was therefore always refused; the second half was wrong in the worse direction — until the scope field, a broadcast was not refused at all, it crossed relays **in clear**, because the fan-out re-addressed every copy and the last-hop exemption could not tell it apart from a final delivery. Measured by `p2p_sealbcast`, 6 phases. Gated by `p2p_sealdefault`. **AN UPCAST IS A SECOND AUDIENCE AND SINCE 2026-09-22 A SECOND SWITCH.** `On_P2PeerUCast` was dead code until then — no `P2Pmsg_UCast` ID, no map entry, nothing dispatched it. It is the mirror of the broadcast relay: a copy per *parent* link, each parent delivering it locally before relaying on, so an upcast climbs to the root and every ancestor receives it. What the origin addressed is a **chain**, no more sealable than a subtree, so an upcast is refused on the same default. It stamps `TMsg_Ups` rather than `TMsg_Scp` and `RequireSealUpcast` is its own switch, because *"my broadcasts are not confidential"* is not the same sentence as *"my upcasts are not confidential"* — and the tidier one-field version would have had a setting deployments already recorded start exempting traffic on a relay that did not exist when they recorded it. `TryReadPosture` reports it as `SealUcast`. Gated by `p2p_sealbcast` phase 6 (the guard and its control) and `p2p_ucastgate` (the routing bound, which no test could reach before). **The rest of this row is the v1 history, and it stands — the row read *"implemented, opt-in, off by default"* until 2026-08-21.** `P2PeerHub::SealFor`/`OpenFrom` seal a payload to the destination itself (ECIES: ephemeral ECDH P-256 → HKDF-SHA256 → AES-256-GCM, plus the sender's ECDSA signature), leaving the addresses in clear so every hub can still route. Covered by a test (`p2p_sealhop`, three hubs over real sockets with the middle observing transit). Note what the connection cypher cannot do here: routing is decided on the destination address, so an intermediate hub necessarily decrypts the frame — link crypto protects one *hop*, and the middle hub is the far end of the first one. **Replay is bounded rather than closed** (2026-08-15): `RefuseSealReplay(true)` refuses a body this recipient has already opened, but a sealed body carries **no timestamp and never expires**, so its cache cannot drop entries by age — an entry dropped for age would hand back exactly the replay it was holding. ~~It is bounded by **count** instead, so the most recent bodies cannot be replayed to a given recipient and an older one can.~~ ✅ **Closed 2026-08-18 by the v1 wire format.** The block now carries a **version byte** and a **signed `sealed_at`**, both bound into the GCM additional data *and* the signed transcript, so neither the wire nor the recipient can edit them. `RefuseSealReplay` is on by default; a body outside `SetSealWindow` (default 24 hours) is `SealErrStale`; and eviction from the replay cache raises a **floor** below which nothing is accepted again. **The price is store-and-forward**, and it is real: a sealed body is built for a recipient that has never connected, so the window is a bound on how long it may sit — `SetSealWindow(0)` removes it for a courier network measured in weeks, and says what that gives up. **The change is a hard break, and could not be anything else:** a v0 block began with the ephemeral X coordinate, a uniformly distributed byte, so "version 0" is not a value that can be recognised and the two formats are not distinguishable by inspection. A v0 body fails as `SealErrVersion`, or once in 256 as `SealErrSignature`; it never opens. Cross-backend interop is re-pinned by `seal_interop` against freshly emitted CNG and OpenSSL vectors. |
| Modern crypto primitives (`P2PCngCrypto`) | ✅ **Two backends behind one header, self-tested against published vectors on both, and on the live path by default since 2026-08-18.** `P2PCngCrypto.cpp` is CNG/BCrypt and `P2PCngCrypto_openssl.cpp` is OpenSSL 3; both implement `p2pcng::SelfTest()`, which carries the RFC 4231 HMAC-SHA256 and RFC 5869 HKDF-SHA256 known-answer vectors, and `unit_suite` runs it on **both** platforms rather than only where the backend was written. `crypto_kat` proves a backend agrees with itself and `seal_interop` - in the `security` label on both - opens bodies sealed by the *other* backend from checked-in vectors, which is the only check that a Windows peer and a Linux peer can actually talk. **This row was 🟡 until 2026-08-22, and the qualifier it carried - *wired in wherever authentication is required* - described the world before 2026-08-18, when the wiring was opt-in.** `RequireAuth` now defaults to true and a hub that requires it and holds no keys refuses to arm, so *wherever authentication is required* means everywhere unless an operator says `RequireAuth(false)` out loud - the same shape every ✅ row in this table has. **What it does not claim:** the primitives are the platform's, so this row is a statement about correct *use* of BCrypt and OpenSSL and not about them; and the integration has not been externally audited, which is the ❌ row at the bottom of this table. |
| Wire-framing bounds checks | ✅ The parser is fuzzed (`p2p_fuzzframe`, 3,618 frames a run) and, since 2026-08-15, under **AddressSanitizer**, which found four further out-of-bounds accesses on the receive path — one of them a *write*, which is what the CRT debug heap had been reporting without being able to attribute. All four are fixed and **none was inside an `ASSERT`**: they were live in Release and undetected there, so this row's earlier "green on both platforms" overstated what green meant. **Re-measured on both platforms 2026-08-16 and again 2026-08-17** (`57c7f70`), each time against a tree hashed file-by-file so the two figures describe the same source — the second run found 144 files differing, 130 of them only in the `©` restored that day, and 0 after syncing: Windows **47/47 Release** (178 s), **46/47 Debug** (203 s), Linux **48/49** (245 s) on a clean 214/214 rebuild, with `p2p_fuzzframe` the only red on either and `ESCAPED=0` on both — a `--strict-assert` tally rather than a crash, and the same binary without the flag exits 0 on 2,814 frames. One seed family and a fixed iteration budget is coverage, not proof. **Re-measured 2026-08-20, and the row's standing caveat - *“one seed family and a fixed iteration budget is coverage, not proof”* - is now answered rather than repeated.** The corpus is **persistent** and replayed by every gate run, the campaign is **continuous** (daily, both platforms, seeded from the run number so it moves without becoming irreproducible), the frames now span the **size ceiling** as well as the ~2 KB band, and the four **authenticated** wire parsers have a harness of their own (`p2p_fuzzblock`) whose oracle is stronger than the framing one can be: these blocks are signed, so *any change to a signed byte must not verify*, and a mutant that comes back OK is a finding with no judgement required. A finding leaves a **reproducer file**, not a log line. **AND THE LAST ITEM THAT KEPT THIS ROW SHORT OF GREEN IS CLOSED (2026-08-21):** the assert population of Stage 1 step 4. The framing gate runs with `--strict-assert` and a budget of **zero on both platforms**, down from a tracked 89,901 on Windows and 1,044 on Linux. **The half of it that was a security defect rather than noise:** stage 4 of `P2Peerio::RecvP2PeerMsg` constructed its `P2PeerMsg` from a pointer alone, reaching `P2PmsgHeap_CreateIOMAGE(pIOmage)`, whose two block walks are **inside `ASSERT()`**. A Release build therefore did not run a reduced structural check on a pre-auth frame - it ran **none**, and adopted a forged block chain without walking it. The receive path already knows the length it accumulated; it now passes it, and the image is adopted through `P2PmsgHeap_CreateIOMAGE(pIOmage,nBufferLen)`, which walks it in **every** build and throws on the answer. Two new constructors carry the length, and the root's own `aAlloc` - the address every reader connects to, and the one link neither walk ever looked at - is now required to be a valid allocated block, the check its BSTRio twin has had since F1. **The other half:** `MsgVBHeap` now distinguishes the two jobs those walks do. Over a heap this process built, a violated invariant is a bug here and `ASSERT` is right; over an image a stranger sent it is the ordinary case, and the answer is to refuse - at the first bad block, and without writing the image's root back into agreement with itself on the way past, which was a validator editing the bytes it had been asked to judge. **Measured rather than asserted, same seed and same 3,618 frames:** a Release build used to turn **550** of them into `P2PeerMsg` objects and now refuses all but **246** (Linux 547 -> 244); Debug and Release now agree frame for frame where they differed by two, because the Debug-only fixups used to change an image's fate; and Linux parse depth went **71.2% -> 100%**, the 1,041 inputs the POSIX assert trap used to abandon mid-parse now running to the end and being refused on the merits. Falsified by reverting the one call-site line and watching the gate go red on both platforms (89,919 and 1,041 tripped). **A named gate pins it, and it is not the fuzz harness:** an assert budget can only go red in a Debug build, and this defect was Release-only, so the new `security` test `p2p_framegate` states the two properties without an assertion - *what the length-validated adoption path refuses, the receive path refuses*, and *a refused image is byte-identical to what arrived* - over a sweep of single-byte mutants across the image's control region. Both were proven red in a **Release** build before they were believed (76 refused images still parsed into messages; 29 refused images modified by the walk that refused them). Suites green in both configurations on both platforms: **45/45 Windows, 48/48 Linux**, and the `security` label **29/29 under Windows MSVC ASan** and **29/29 under Linux GCC ASan+UBSan+LSan** with `halt_on_error=1` - re-run rather than inferred, because the fix makes a Release build walk an attacker-controlled block chain it used to skip, so those are paths no shipped binary had executed. **It tightens the FILE LOADER as well, deliberately.** The gate is entered by the length-validated Create overloads, and `P2PmsgMgr::Load` has used those since item 19, so a stored image whose root counters disagree with the chain they describe is now refused where it used to be silently repaired and adopted. A file is not more trustworthy than a frame for having been written to disk. Measured: `golden_ref.p2p` and its byte check still load and the load cases are green on both platforms. **What this row still does not claim:** the validators' cost is attacker-controlled in the sense the size band showed - the block walk's trip count scales with the bytes sent - and that is bounded by `m_dwMaxRecvSize` and by the first-bad-block exit, not eliminated. One seed family is still coverage rather than proof; the continuous campaign is what answers that. |
| Message image layout generation | ✅ **Enforced on the wire since 2026-08-21, and it closes a gap no bounds check could.** Every protection in the row above defends against bytes that are *wrong*; this one defends against bytes that are *right for a different build*. The message image header has 24 bits of size, 2 of addressing mode and 6 of sentinel — and those six are also a **layout generation** field, which is the image’s only version story. Change anything inside a message and neither the size nor the addressing mode moves, so a peer used to accept the frame and parse the body against the wrong map, with every bound satisfied. `P2Peerio::RecvP2PeerMsg` now refuses any frame whose generation is not this build’s, at stage 2, **before the allocation**, and the diagnostic names which kind arrived — a pre-sentinel peer, a registered later generation, an unrecognised code, or opposite endianness. **What this changes for a deployment:** a peer built before the endian sentinel went in can no longer talk to one built after it. That was already stated as a requirement in `byte_order.md` §4.3 and is now enforced instead of assumed; it is recorded as an unreleased break. **Reading a stored file is deliberately unaffected** — `P2PmsgMgr::Load` still accepts a pre-sentinel image and warns, because a frame is a peer that can be upgraded and a file is data you already have. Covered by `p2p_imagegen`, which fails any implementation that tightens the store to match the wire. |
| Undeliverable-report amplification | ✅ **Capped, and covered by a test.** The framework used to answer an undeliverable message with a `P2Pmsg_Exception` that *embedded the whole message* and was posted back to its source — so when both endpoints were unroutable the hub reported the report, on its own pump thread, wrapping a wrap each lap. Measured from a ~100-byte seed: three laps to the 64 KB message-heap ceiling, ending in an uncontrolled throw inside the allocator. An undeliverable exception is now dropped and traced instead (`P2PeerTarget::RouteP2PeerMsg`), which is the single choke point every lap must pass through. Covered by a case in `unit_suite` that fails without it on both platforms. **Re-measured after the bound in the row below landed, because that changed the failure being prevented:** with the report body elided the growth stops short of the heap ceiling, so nothing throws and nothing ends the loop. Removing the cap now makes a hub spin **4736 laps in 1.5 s** at a repeating 8280 / 12496 / 16712 bytes, indefinitely, rather than crashing on lap three. The cap stops it either way — but the failure it prevents is quieter than it used to be, and the guard's size bound was retuned to catch the first amplifying lap instead of the fifth. |
| Undeliverable report bounded to what can be delivered | ✅ **Bounded, and covered by tests.** The report embeds the message it reports on, so it is always larger than what failed — and nothing checked it against either limit above it. The message went in **twice** (once as the wrap, once inside the diagnostic event), and the report is built in a 16-bit message heap: a 30 KB message — inside what a stock peer may send, since the receive limit defaults to 32768 — threw on the **routing hub's pump thread** and produced no report at all; bound that and the report was still ~38 KB, over the receiver's limit, so the frame was refused and the connection dropped. Either way the sender was never told its message was undeliverable. The report body is now elided past `MAX_P2PmsgWrapEmbed` and the event no longer carries a second copy. Covered by three `unit_suite` cases and `p2p_bigreport`. **Off Windows this path was worse:** the report was addressed from a recycled thread-local buffer and came out addressed to `Src`, the field *name*, so it was undeliverable itself — no undeliverable message had ever been reported to its sender on Linux. Fixed with the same snapshot as `P2PeerHub::RouteP2PeerMsg` (2026-08-13). |
| Replayed message refused | ✅ **All three answers are now on by default (2026-08-18), and the sealed-body one stopped being the weak sibling.** A repeated **login** is refused by the nonce cache whenever `RequireAuth(true)` is set — always on, no switch. A repeated **relay attestation** is refused by `RefuseRelayReplay(true)`, and a repeated **sealed body** by `RefuseSealReplay(true)`; both are **on by default since 2026-08-18**, and `RefuseRelayReplay(false)` / `RefuseSealReplay(false)` are the one-line migration for a hub that legitimately receives one signed block twice — a DAG rather than a tree, or an application that re-delivers on purpose. What overturned the old default is that the shape being protected is narrow and the exposure traded against it was not: a duplicate only collides when the same hub is handed the same *signature* twice, which a tree cannot do at all, so "off" bought a replay window for every deployment in order to keep one topology working for the few that have it. A DAG deployment knows it has one; a tree deployment could not know it had a replay window. Both caches are keyed on the **signature**, which is what lets them coexist with the reason there was no cache here before: they are per hub, so a broadcast still reaches every hub, and ECDSA signing is randomised, so two legitimate sends of identical content carry different signatures and both land. That premise is asserted by the test suite rather than assumed, and fails loudly if this tree ever moves to deterministic signing. **The sealed-body guarantee used to be the weaker of the two, and that difference is closed.** A relay block carried a signed timestamp and a sealed body did not, so the relay cache could expire entries and the seal cache could not — leaving "the most recent `kSeenMax` bodies cannot be replayed, an older one can". The **v1 seal wire format** (see the row below) puts a signed `sealed_at` in the block, and with it: a body outside the freshness window is refused as `SealErrStale`; inside the window a body already opened is refused from the cache; and when the cache evicts by count, the evicted entry's stamp becomes a **floor** that permanently refuses everything sealed before it. What is left is one second wide — the floor comparison is strict, because `sealed_at` has one-second resolution and a non-strict one would refuse live traffic sealed in the same second as the eviction — and buying that costs an attacker `kSeenMax` genuinely sealed bodies through the same recipient inside that second. Covered by `AuthSelfTest` sections 17 and 18, run on both backends, **and since 2026-08-16 at the hub by `p2p_replayguard`** — which is where the coverage had been thinnest: sections 17 and 18 drive `p2pauth::AuthPolicy` directly, so until then the newest security code in the tree was also the only security feature with no test that went through `P2PeerHub`. `p2p_replayguard` posts the **identical sealed bytes** twice over a real connection, which is what a capture-and-redeliver attacker has because it is what went over the wire, and runs each half with the switch **off** first: until a replay demonstrably gets through, a refusal is not evidence of a guard. |
| Revoked key refused | ✅ **A required position since 2026-08-21** — not the checking, which was always unconditional, but the *position*: a hub that requires authentication must either name a revocation list or say `RequireRevocation(false)`, and one that does neither **no longer arms**, with the refusal naming the revocation file rather than the allow-list. Still **fail-closed** where a list exists: a list that will not load makes the hub refuse every peer rather than run on knowledge it cannot read. An allow-list may carry several keys per address, so rotation is add-then-revoke. Un-revoking is a deliberate manual edit — there is no removal API. Covered by `p2p_keyrotate`. |
| A revocation reaching hubs no operator edited | 🟡 **Implemented 2026-08-15, opt-in, off by default.** The list was a local file, so a compromised key was refused exactly where someone remembered to type it. A signed, versioned list is now carried hub to hub, verified against **one named authority** rather than against the allow-list — a deny-list any peer can inject is a denial of service — and **merged, never substituted**, so nothing that arrives can un-revoke anything. Carrying one is unprivileged; the signature is the trust, not the courier. No automatic gossip: when to publish and who to hand it to are routing decisions this layer does not own. Covered by `AuthSelfTest` section 19, run on both backends, **and since 2026-08-16 end to end by `p2p_revokedist`** — a list issued by an authority the receiving hub never connects to, applied over the API, after which the key it names stops completing a login on a hub *whose own revocation file nobody edited*. Two of its six phases test the design rather than the feature: a **newer** list naming nobody must not restore the revoked key (merged, never substituted), and a list signed by a valid stranger must come back `RevErrIssuer` and change nothing. See item 2. |
| A diagnostic cannot hang the hub that raised it | 🟢 **Holds, and needs no configuration. Fixed 2026-08-17**, the day after it was recorded as a mitigation only. A `P2Pevent` becomes a **modal `MessageBox`** when there is nowhere to write text, and `MB_TASKMODAL` blocks the thread that raised it. Events are raised on interior worker threads — `P2PeerCon::OnClose` runs on the hub's own pump — and `CloseHub()` waits on its pumps without a bound, deliberately: bounding it would let teardown proceed past a live pump and trade a hang for a use-after-free. So a dialog nobody can dismiss was not a lost diagnostic, it was a hub that could not stop, and a **service started by the SCM was exactly that shape** — no console, no standard error, non-interactive session. The 2026-08-13 fix had replaced *"is there a console window?"* with *"is there anywhere to write this?"*, which left the service case landing on the dialog. `P2PeventUseTextOutput()` now asks the prior question — *could anybody see a dialog?* — from `ProcessIdToSessionId` (session 0 has been the isolated services session since Vista, and `UI0Detect` is gone from Windows 10 on) and `WSF_VISIBLE` on the process window station (a service gets `Service-0x0-3e7$`, which is not visible). Both are needed and neither is redundant: a service registered `SERVICE_INTERACTIVE_PROCESS` gets visible `WinSta0` but is still in session 0. A failed query is treated as **viewable**, so an API error can never silence a windowed application. A windowed host is session ≥ 1 on a visible station and keeps its dialogs unchanged. The policy is pure and exported as `P2Pevent::TextOutputPolicy()`, asserted over all 16 input combinations by **`p2p_servicedialog`, which runs on both platforms** and whose *"service under the SCM"* row is the only one that fails when the viewability clause is removed — verified by removing it. **The other half is the destination:** refusing the dialog would otherwise write to a handle that is not there. `P2Pevent::SetTextSink()` names where text goes, and in service mode `P2PeerService` routes to the **Windows application event log** under the service's own name, registering the source in `Install()`. **Reproduced end to end under the SCM on 2026-08-22**, elevated, by `_Targetcore_UseExamples/ErrorReportingExamples/NTServiceEventLog`, which raises a diagnostic on the pump thread deliberately: a real service in session 0 reached `STOPPED` in 40 ms rather than `STOP_PENDING`, and its diagnostics arrived in the application event log under two distinguishable sources — the library's under the service name, the application's under its own. What makes that a result rather than a green light is the ordering, because an unarmed hub stops just as cleanly: `P2PeerService::Run()` skips `RunHub()` when `CreateHub()` is refused, so nothing runs and the service still stops promptly. The run logged pump entry, then the deliberate `P2Pevent`, then pump exit — a `MessageBox` blocks inside `Cancel()`, so the third line cannot exist if the dialog appeared. Teardown did wait on a pump: `RunHub()` returned while the SCM still reported `RUNNING`, leaving `CloseHub()` blocked on `CreateHub`'s pumps until the stop arrived. **The dialog itself IS now driven**, by the sibling `DialogOrLogFile` harness: it re-executes itself with `CREATE_NO_WINDOW` and its own standard error removed — a session and a station but no console and no stderr, which is a service's shape in every respect that this policy reads — and asserts that a modal dialog window (class `#32770`) is raised with `ErrToMessageBox: 1` and is not with `0`. It asserts the *window*, not the block, because on a live desktop something else closes a message box within a few seconds and gating on "still running" failed about one run in four. Since 2026-08-17 a **`P2Pmsg.cfg`** beside the host executable can also refuse the dialog and name a log file without any code; the setting moves only towards text and cannot re-arm the dialog against `P2PMSG_NO_UI`, `ForceTextOutput(true)` or the viewability test, and a configured `LogFile` loses to an installed sink so it cannot divert a service out of the event log. That one-way property is asserted by `p2p_servicedialog` on both platforms. Off Windows `MessageBoxEx` is a stub, text is unconditional, and the event log is not a portable concept — routing to syslog or the journal is a separate decision, though the configured log file works there today. |
| Message flooding bounded (backpressure) | ✅ **Real backpressure since 2026-08-19, on by default, both platforms.** The ceiling is unchanged and still throws: `s_cP2PmsgMAX` is **50000** live `P2Pmsg`’s process-wide, and a post beyond it raises `P2Pevent_QUEFULL`. What changed is that it is no longer the FIRST thing that happens. **Two marks make the same budget a slope** — at or above **37500** a connection stops asking its transport for another message, at or below **25000** it starts again — and stopping is expressed by *not calling* `RecvP2PeerMsg()`, the call that issues the next `Recv()`. No read is outstanding, the socket buffer fills, the TCP window closes: **the peer is throttled by the transport, nothing is discarded and nothing is refused.** The gap between the marks is hysteresis, not decoration — a single mark makes a connection resume the instant the budget dips one message below it and re-hold on its next completion. `SetP2PmsgBudgetMarks(high, low)` moves them; it **throws rather than clamping**, and requires `high < MAX` because a held connection arms a poll timer and a timer *is* a `P2Pmsg`. **The decision is visible in two counters**: `GetP2PmsgHeldCount()` process-wide, and the `Throttled` field of the hub’s own snapshot beside `QueDepth` — a low queue with a climbing hold count is a hub holding the line, not an idle one. Guarded by `p2p_backpressure`, whose third phase is the one that matters: after the pressure is released **every held message must arrive**, because throttling that loses messages is dropping with a better name. **Two corrections to what this row used to say.** It claimed the limit was *"stated three different ways"* and that all seven depth sites printed *"pump is full, 10000 entries"*; that was true on 2026-08-17 and was fixed on 2026-08-18 — all seven test the constant and render it through one format. It also said *"nothing reports it in a hub’s own snapshot"*; `QueDepth` does, since 2026-08-19. **What is still NOT bounded:** a peer’s send *rate* below the high mark — the trigger is occupancy, not throughput — and the destination pump’s own FIFO depth as distinct from the process budget. Neither is reproduced under load. |
| Independent security audit | ❌ Not done. An internal review exists with open findings. |

The legacy `DHKeyXChanger` and `Rijndael` sources have been **deleted** from the tree. Neither was
ever reachable and neither was ever constructed, but a reader who opened them reasonably concluded
they were the security story — which is the harm a comment cannot undo. Their defects stay on the
record here and in the project's internal engineering log so nobody re-adopts them; the code itself is recoverable
from git history if it is ever wanted. Deleting `DHKeyXChanger` closed **M7**, the unbounded
pre-auth bignum parse, which existed in two divergent copies.

## Turning peer authentication on

**On by default since 2026-08-18.** What you are configuring is not whether to require it — that is
already true — but whether this hub can. Configure **before** `SpawnHub()`/`CreateHub()`; a hub that
requires auth and is not provisioned will not start.

```cpp
    oHub.SetIdentity  ( "/etc/p2p/peer.key", /*create if absent*/ true );
    oHub.SetAllowList ( "/etc/p2p/peers.allow" );
    //  RequireAuth(true) is the default. Say it if you like it in writing.
```

### First run

There are two files and only one of them is mechanical. `ProvisionAuth()` does that one:

```cpp
    char szFingerprint[p2pcng::kIdFingerprintLen] = {0};
    bool bCreated = false;
    oHub.ProvisionAuth ( "/etc/p2p/peer.key", szFingerprint,
                         sizeof(szFingerprint), &bCreated );
    //  -> creates peer.key if absent, loads it if not
    //  -> writes peer.key.pub, the line to paste into every peer's allow-list
    //  -> hands back  5FAD-2289-0652-A76C-E9B8-9B23-06A0-0A2C  to read aloud
```

Run it twice and the second run **finds** the key rather than replacing it — a first-run helper that
regenerated on restart would rotate every hub's identity behind the operator's back, and every peer
holding the old point would stop being able to verify it.

It deliberately does **not** create the allow-list or the revocation list, and the hub still refuses
to arm until you have dealt with both.
Who to trust is the half of provisioning that is not mechanical, and a library that silently created
an empty allow-list would be answering it — with "nobody", which refuses every peer.

### What the refusal to arm looks like

```
[ERROR] []P2PeerHub::SpawnHub()
P2PeerHub(Acme.Gateway) will not arm: allow-list unreadable - missing, or a line that will not parse
ADVICE  : Auth is required by default (Stage 3 step 8). Provision this hub, or
          RequireAuth(false) and mean it.  Allow-list: /etc/p2p/peers.allow
```

Seven distinct reasons since 2026-08-21, all reported through the same channel and all available as
a return value from `P2PeerHub::AuthArm()` before you arm anything: no identity, no allow-list, an
allow-list that cannot be read, an allow-list that **names nobody**, no revocation list, a revocation
list that cannot be read, and `ArmNotRequired` for a hub that opted out. The empty allow-list is its
own case on purpose: it is the state an operator reaches by accident, it loads without error, and it
refuses every peer exactly as having no file would.

**The advice and the file named both follow the reason**, which they did not have to before there
was more than one candidate — sending an operator to the allow-list when the revocation list is the
problem would be worse than naming nothing, since the two sit in the same directory under similar
names:

```
[ERROR] []P2PeerHub::SpawnHub()
P2PeerHub(Acme.Gateway) will not arm: no revocation list - SetRevocationList(path), or RequireRevocation(false)
ADVICE  : No revocation list, so no key could ever be withdrawn. Name one, or
          RequireRevocation(false).
```

### Migrating a deployment that never configured this

One line per hub, and it must be an explicit one:

```cpp
    oHub.RequireAuth ( false );   // trusted segment / in-process router / not under test
```

- **The private key never leaves the peer that generated it.** Publish only the public half —
  `ProvisionAuth()` writes it as `<key>.pub`, `SavePublicKey()` writes it on its own, and
  `Fingerprint()` prints it for comparison over a phone call. An
  allow-list line is `<address> <hex public point>`, and the address must be the one the peer will
  claim at login, exactly: an entry is **not** a pattern, and `Peer.*` in that column admits nothing.
- **`RequireAuth` is a hub property with no per-connection override.** That is deliberate — it is
  the one setting that must not be losable when an accepted connection is built from the listener.
  It stays true after `SetLinkPolicy` below, and the distinction is the whole reason that call is
  allowed to exist: what moved to the connection is a **classification**, not a permission. A
  transport answers `TrustClass()` — a fact about where its frames can go, a virtual on the class,
  and therefore nothing `AcceptSpawn` can fail to copy — and the hub still decides, in one place
  and under its own lock, what a link of that class must do.
- **`SetLinkPolicy(class, policy)` is what a link that cannot benefit from the handshake pays
  instead.** A DMX connection is a pointer handoff between two objects on one heap, and under
  `RequireAuth(true)` it ran a full ECDH agreement, held a BCrypt key object that is never
  consulted, and signed four ECDSA operations onto its login — to protect a channel with no wire on
  it. `RequireAuth(false)` was the only way to say so, and it opens *every* link the hub will ever
  hold, including a socket posted to it later.

  ```cpp
      oHub.SetLinkPolicy ( P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open );  // DMX
      // ...and a TCP link on the same hub is untouched.
  ```

  Three classes: `Wire` (0, the default for every transport that has vouched for nothing — a serial
  line, a socket that is not on loopback, and a named pipe asked for
  `P2PeerConPipeAccess_Legacy`, which accepts a client arriving over SMB from another host),
  `Local` (1, the kernel keeps it on this machine — a loopback socket, and since 2026-09-04 a named
  pipe this transport created), and
  `InProcess` (2, construction keeps it in this process). **`Wire` cannot be opened** — the call is
  ignored — because a wire is what an unexamined transport answers, so opening it would relax the
  whole tree through a call that reads as though it named one kind of link.

  `Local` is **not** *trusted*: it says no network adversary can reach the link, and nothing about
  another principal on the same host, who reaches a loopback port exactly as easily as this process
  does. **Both ends need the same setting**, as with `RequireAuth`, and since 2026-09-04 that is
  enforced in **both** directions: a peer that skipped the agreement against a hub that wanted one
  is refused at the login gate, and a peer that *opens* an agreement against a hub that has relaxed
  the class is refused at `KeyXOnRequest` — before it runs, rather than after, when the disagreement
  used to surface as a login block handed to the application. A hub with `RequireAuth(false)` is
  untouched by the second half and still services an exchange, as it always has. And it is a
  per-**link** setting only — relay attestation and end-to-end sealing are properties of an origin
  and a destination rather than of one hop, so an opened link still signs and still seals.

  Every class defaults to `Full`, so a hub that never calls this behaves exactly as it did.
- **`RequireTrustAtLeast(class)` is the other half of that call, and it is what makes the opt-out
  safer than `RequireAuth(false)` rather than merely cheaper.** A hub that has opened its
  in-process links is one `PostP2PeerCon` away from carrying a socket it did not plan for. That
  socket authenticates in full — `Wire` is `Full` and cannot be set otherwise — so nothing is
  weakened; what happens is that a hub which exists to route inside a process quietly becomes a
  network endpoint, and no field anywhere says so. The fence refuses it instead, at the moment it
  is offered, naming the class:

  ```cpp
      oHub.SetLinkPolicy       ( P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open );
      oHub.RequireTrustAtLeast ( P2PeerConTrust_InProcess );   // ...and nothing else, ever
  ```

  It is measured against `EffectiveTrust()`, so a connection an operator demoted is judged on the
  class they demoted it to. `Wire` — the default — means *no* fence. An accepted child does not
  pass through `PostP2PeerCon`; it does not need to, because it is spawned by a service the fence
  already admitted and cannot read a higher class than that service.

  **It also changes what arming means for one shape of hub.** A hub that requires authentication,
  has fenced out every class it will not carry and has opened every class it will, can never demand
  a signature from anybody — so it arms with no identity and no allow-list, reporting
  `p2pauth::ArmNotRequiredByPolicy` rather than refusing to start for want of a key it will never
  use. That is not quiet: the posture still reads `AuthRequired=1` beside `TrustFloor` and the
  three `LinkPol` fields, which is what makes it a stated decision rather than the omission the
  arming gate exists to catch. Take either half away — a class above the floor still `Full`, or the
  floor removed — and it reports `ArmNoIdentity` again.
- **`WaiveEndToEndInProcess(true)` is the only switch that reaches the end-to-end cost, and it is
  the only one in this file whose correctness rests on an assumption rather than a mechanism.**
  `SetLinkPolicy` above relaxes a *hop*; the two end-to-end protections are properties of an origin
  and a destination, so an opened link still signs and still seals — and that is not a technicality.
  **Measured** (`p2p_linkcost`, five postures, three runs): the default posture costs 14× the CPU
  per message of the same chain with nothing on, **93% of it is the seal and the attestation**, and
  `SetLinkPolicy(InProcess, Open)` recovers **none** of it. This switch is what that measurement was
  taken to decide.

  It waives the seal and the relay attestation when the destination is a hub **this process holds**,
  which is a registry lookup and an **exact** address match — a hub `Alice` here says nothing about
  `Alice.Bob`, which may be a child hub on another host.

  ```cpp
      oHub.WaiveEndToEndInProcess ( true );   // off by default
  ```

  **Read the assumption before turning it on.** It holds only if a message to an in-process hub
  never transits an out-of-process one — true of a tree whose in-process hubs form one subtree, and
  not guaranteed otherwise. The failure mode in full, because a paraphrase is not enough to decide
  by: hubs A and C in one process, B on another host, wired A-B-C. A sends to C, C is in this
  process, so nothing is sealed or signed — and the body crosses the wire to B **in clear**, because
  the destination being local is a fact and the *route* staying local is not. Nothing in the library
  can tell those two apart, which is why this is opt-in: the assumption becomes something an
  operator wrote down rather than something the library made on their behalf.

  It waives nothing for a **broadcast** (a scope names a subtree, and a subtree cannot be shown to
  be in this process even when its root is — that is `RequireSealBroadcast`'s decision), and the
  receive-side exemption in `GateRelayInbound` keys on the **same registry lookup, never on the
  link's trust class**: keyed on the class, a remote ancestor could forward an unattested message
  down an in-process link and be admitted. `TryReadPosture` reports it as `WaiveE2E`, so a hub
  reading `SealRequired=1` beside `WaiveE2E=1` — requires sealing, does not always do it — is
  legible without reading the source. Gated by `p2p_e2ewaive`, falsified three times.
- **`SetIdentity` alone makes a hub sign; `RequireAuth` makes it demand.** A peer that signs to a
  hub which does not require authentication has its block handed to the application, and the stock
  `On_ConLogin` refuses the payload loudly. Configure both ends.
- **Reloading:** `ReloadAllowList()` is valid on a running hub, so adding a peer is not a restart.
  A file that fails to parse leaves the previously validated list in place.

**Clock.** The login carries a timestamp, and a login outside **±300 s** of the server's clock is
refused. Peers therefore need loosely synchronised clocks — NTP, a domain, anything that holds them
within a few minutes. Rejections are logged with the measured skew and its sign, so a wrong clock is
a one-line diagnosis rather than a mystery; the server's time is deliberately **not** returned to the
peer, which has proven nothing at that point. Note that a clock which *jumps* — a VM resumed from a
snapshot, a laptop opened after a week — will refuse logins until it resynchronises.

The window is a memory-and-clock parameter, **not** the replay defence: replay is stopped by a
per-hub cache of nonces already seen, and the timestamp only bounds how long that cache must
remember. `SetAuthWindow(0)` disables the freshness check for devices with no clock at all
(RTC-less hardware on the serial and DMX buses). That is a real trade and worth stating plainly:
with no window the cache can no longer be trimmed by time, so it is bounded by capacity instead, and
a nonce evicted by capacity becomes replayable.

**The channel.** `RequireAuth(true)` also turns on the session cypher — the two are one switch on
purpose, because a confidential channel to an unproven peer and a proven peer on a readable wire are
each half an answer. Every connection runs its own ephemeral ECDH P-256 agreement before the login:

```
  1  client -> server   client_pub      plain
  2  server -> client   server_pub      plain    both ends derive the key here
  3  client -> server   login           sealed
  4  server -> client   login ack       sealed
```

The shared secret goes through HKDF-SHA256 to an AES-256-GCM key, and everything from flight 3
onwards is sealed. There is no cipher negotiation and no version to downgrade to. The login
signature covers `SHA-256("P2P-kx-v1" | client_pub | server_pub)`, which is never transmitted —
both ends compute it from the two public halves — so a proof made for one connection cannot be
replayed onto another.

**What this does not do.** Forward secrecy is per *connection*, not per message: the session key
lives as long as the connection, so compromising it exposes that whole session. There is no
rekeying. **And this paragraph used to end *"none of this is on unless you switch it on — an
unconfigured hub is byte-identical to a build without any of it"*, which has been false since
2026-08-18 and is corrected here rather than deleted:** the session cypher rides on `RequireAuth`,
`RequireAuth` defaults to **true**, and a hub that cannot enforce it does not start. The build that
is byte-identical to one without any of this is the one that says `RequireAuth(false)` out loud.

**And it does not hide anything from a hub.** The session cypher protects one *hop*. On a route
A → B → C, hub B decrypts A's frame, decides where it goes from the destination address, and
re-seals it for C. B sees the plaintext, and no amount of link crypto changes that — a hub that
could not read the frame could not forward it. That is what the next section is for.

## Hiding a body from the hubs that carry it

Independent of `RequireAuth`, and a different question: not *who is on the wire* but *who can read
the message*. Seal the payload to the destination itself and leave the addresses in clear, so every
hub can still route and none of them can read:

```cpp
    oHub.SetIdentity     ( "/etc/p2p/peer.key",   /*create*/ true );  // to sign with
    oHub.SetAgreementKey ( "/etc/p2p/peer.agree", /*create*/ true );  // to be sealed to
    oHub.SetAllowList    ( "/etc/p2p/peers.allow" );

    size_t cbOut = 0;
    std::vector<unsigned char> vSealed ( p2pseal::SealedSize ( cbBody ) );
    oHub.SealFor ( L"Me", L"Them", pBody, cbBody,
                   &vSealed[0], vSealed.size(), &cbOut );
```

- **Two keys per peer, and they are not interchangeable.** The ECDSA *identity* key proves who you
  are at login; the ECDH *agreement* key is what others seal to. Separate files, separate container
  magic, separate DPAPI entropy — using one key for two algorithms is a standard way to turn a
  signing oracle into a decryption oracle.
- **The allow-list grew an optional third column:** `<address> <identity hex> [<agreement hex>]`.
  Existing two-column files keep working unchanged, and a peer with no agreement column can still
  log in — it just cannot be sealed to. Asking to seal to it returns `SealErrNoAgreement`. There is
  deliberately **no** fallback that sends the body in clear because the directory was incomplete.
- **A sealed body costs 156 bytes** — `eph_pub(64) | nonce(12) | ct | tag(16) | sig(64)`. The source
  and destination addresses are bound in twice, as GCM additional data and inside the signed
  transcript, so a body lifted off one message and pasted onto another does not open.
- **A key can now be replaced, and withdrawn.** The allow-list may carry more than one line for the
  same address and every key listed is tried, so a peer is issued its next key *before* it starts
  using one and cuts over on its own schedule — no instant in which one side has rotated and the
  other has not. A separate revocation list overrides the allow-list:

  ```
      peers.allow                                  peers.revoked
        alice  <old-id-hex>  <old-agree-hex>         <old-id-hex>  1760000000  # rotated out
        alice  <new-id-hex>  <new-agree-hex>
  ```

  It is keyed on the **full 64-byte point**, not the fingerprint — `Fingerprint()` says in its own
  contract that it is never an identifier the code trusts, and refusing a peer is exactly the code
  trusting one. One file covers both key kinds, because with two an operator can revoke a
  compromised peer for login and forget sealing. `ReloadRevocationList()` works on a running hub,
  which is the only way revocation helps during an incident, and a configured list that cannot be
  read **fails closed** rather than reverting to "nothing is revoked" — deleting the file to turn
  revocation off would otherwise silently re-admit every key you had withdrawn. Guarded by
  `p2p_keyrotate`, whose fourth phase is a liveness control: without it, "the revoked key was
  refused" and "the server fell over" are both silence.
- **A peer that seals also signs its logins**, because `SetIdentity` is what both need. Every hub it
  connects to must therefore either require auth or implement an `On_ConLogin` that accepts a login
  carrying data — the stock handler refuses one.
- **A Windows peer and a Linux peer can actually do this to each other**, which is a separate claim
  from either backend working, and is now tested rather than asserted. The `seal_interop` test opens
  bodies sealed by the *other* backend from checked-in vectors (`MscsUnitTests/vectors/`), covering
  the two places the two builds could silently disagree: the address transcript — `wchar_t` is 2
  bytes under MSVC and 4 under GCC, and the addresses sit inside both the GCM additional data and
  the signature, so the vectors carry an address with a Cyrillic character *and* one outside the
  BMP, exercising the surrogate-pair path only Windows takes — and the 96-byte `X||Y||d` private
  blob, which CNG exports and the OpenSSL backend reimplements. The identity container is checked
  the same way, since provisioning ships those between machines.

**What rotation and revocation do not do.** Rotation is **operator-driven**: it removes the flag day,
not the provisioning step — someone still has to put the new key in front of every hub that trusts
the peer, and until they do, that hub knows only the old one. There is deliberately no signed
rollover certificate, because a peer that can mint its own replacement key hands whoever steals the
*old* private key the ability to mint one too, silently, and revocation then has to win a race it
did not start. Nothing distributes the revocation list either: each hub reads its own local file,
so a revoked key is refused exactly by the hubs that have been given the update. And revocation is
absolute rather than time-scoped — the timestamp column is a record, never compared against a
clock, so there is no validity window to move a key back inside.

**What this does not do.** No replay defence and no freshness: a sealed body is valid forever and
can be delivered twice, because ordering and liveness belong to the layer that knows what a
duplicate means for its own messages. The ephemeral half gives forward secrecy against later
compromise of the *sender*, but not of the recipient — whoever holds the recipient's agreement key
can open every message ever sent to it. And the addresses stay in clear by construction: this hides
the body, never the traffic pattern.

## Roadmap

Security work is tracked in the open. In priority order. **These numbers are referenced from the project's internal engineering log, which is not published in this repository, and are stable — they are not renumbered.** This list stays the source of truth for the security argument behind each item.

1. ~~Binding a message's source address to the identity its connection logged in as.~~ ✅ **Done**
   on a link to a descendant and on a link to an unrelated peer, guarded by `p2p_authspoof`.
   ~~**A link to an ancestor is deliberately exempt** and carries no source check. Closing that
   exemption needs per-branch route knowledge, or an attestation from the relaying hop, neither of
   which exists.~~ ✅ **Done** — as the attestation, not the route knowledge. `RequireRelayAuth(true)`
   makes a downward relay carry the **origin's** ECDSA signature over its addresses, message name
   and body digest, and the at-or-below test is then applied to whoever signed rather than to
   whoever delivered. Guarded by `p2p_authancestor`, which now asserts the protection.
   ~~Still outstanding from this item: **on by default**, which needs every hub in a tree
   provisioned with its neighbours' identities.~~ ✅ **On by default since 2026-08-18.**
   It does *not* need every hub provisioned, which is what that
   sentence assumed and is wrong: only the hub that **verifies** needs the origin in its
   allow-list, and only the **origin** needs an identity. Every relay in between can hold nothing
   at all — which `p2p_authancestor` now demonstrates with two keyless relays and no switch set
   anywhere. ~~And there is **no replay defence**.~~ ✅ **Added 2026-08-15**, as
   `RefuseRelayReplay(true)` on the hub — a per-hub cache of the signatures it has accepted, so
   the same signed block delivered twice to one hub is refused the second time. It is keyed on the
   **signature**, not on the message, which is what lets it coexist with the reason there was no
   cache here before: a broadcast still reaches every hub, because the cache is per hub; and two
   legitimate sends of identical content still both land, because ECDSA signing is randomised, so
   they carry different signatures. That premise is asserted by the test suite rather than assumed,
   and it fails loudly if this tree ever moves to deterministic signing.

   Off by default, and this is the judgement it hands the operator: a hub that legitimately
   receives one signed block twice — a DAG rather than a tree, or an application that re-delivers
   on purpose — will see the second copy refused. Still outstanding: freshness remains the only
   bound on how long a captured block is worth replaying, and the cache is bounded by **count as
   well as age**, so a signature flushed by `kSeenMax` newer ones is replayable again even inside
   the window. That bound is deliberate rather than a shortcut — the cache is scanned once per
   block, so bounding it by age alone would have made the cost grow with the *square* of the
   relayed traffic and turned the protection into its own denial of service. The remaining
   exposure costs an attacker `kSeenMax` genuinely signed blocks through the same hub. **Sealed
   bodies are a separate case and are not covered by this** — see item 4.
2. ~~Proving identity at login rather than asserting it.~~ ✅ **Done**, as a per-peer ECDSA P-256
   signature rather than the shared PSK first planned — a shared key proves *membership*, not
   *identity*, so every holder could still produce every other holder's MAC. Opt-in; **on by
   default is the next step**. ~~Along with key rotation and revocation, which the current design
   has no answer for.~~ ✅ **Done** — an allow-list may list several keys per address and every one
   is tried, and an overriding revocation list withdraws either key kind, reloadable live and
   fail-closed. Guarded by `p2p_keyrotate`. ~~Still outstanding from that half: nothing distributes
   the revocation list between hubs.~~ ✅ **Added 2026-08-15**, as a signed, versioned list one hub
   hands another — `SetRevocationAuthority` / `IssueRevocationList` / `ApplyRevocationList`. Until
   then the deny-list was a local file, so a compromised key was refused exactly where an operator
   remembered to type it and honoured everywhere else, which for a mesh of any size is close to not
   being revoked at all.

   Two properties carry the design. A received list is verified against the **one named authority**
   the operator configured, never against the allow-list, because a deny-list any peer can inject is
   a denial of service — one compromised peer would otherwise revoke the whole mesh. And it is
   **merged, never substituted**, so nothing that arrives can un-revoke anything: a stale, replayed
   or rolled-back list can only fail to add, which is the direction a security failure is allowed to
   point. Carrying a list is unprivileged — the signature is the trust, not the courier — so a
   revoked peer can still relay one. An authority that revokes itself is applied and then stops
   being the authority. A hub with no revocation file has nowhere durable to put a list and refuses
   it rather than accepting one it will forget at the next restart.

   Still outstanding from that half: rotation is operator-driven, there is deliberately no automatic
   gossip (when to publish and who to hand it to are routing decisions this layer does not own), and
   `SetMaxRevocationStaleness` is **off by default** — expiring on silence would turn a partition
   into a total outage, which is a better attack than most of what revocation defends against.
3. ~~Wiring `P2PCngCrypto` (ECDH P-256 → HKDF-SHA256 → AES-256-GCM, CSPRNG key material,
   authenticated transcript) into the connection handshake~~ ✅ **Done**, opt-in with
   `RequireAuth(true)`, and the legacy `DHKeyXChanger` / `Rijndael` path is now deleted. Still
   ~~outstanding from this item: per-message forward secrecy (rekeying), and **on by default**.~~
   ✅ **On by default since 2026-08-18** - it rides on
   `RequireAuth`. Still outstanding from this item: per-message forward secrecy (rekeying).
4. ~~End-to-end confidentiality, so a routing hub cannot read the bodies it carries.~~ ✅ **Done**,
   opt-in, as `SealFor`/`OpenFrom` over ECIES plus a sender signature. ~~Still outstanding: replay
   defence for sealed bodies.~~ 🟡 **Partly closed 2026-08-15**, as `RefuseSealReplay(true)` — a
   recipient refuses a body it has already opened, keyed on the sender's signature.

   **It is weaker than the relay refusal in item 1, and the difference is the design, not an
   oversight.** A relay block carries a signed timestamp, so freshness refuses an old one and its
   cache only has to remember what freshness would still accept. A sealed body carries no
   timestamp and never expires, so an entry dropped for age would hand back exactly the replay it
   was holding — ageing that cache would not bound the memory, it would publish the waiting time.
   It is therefore bounded by **count**: the most recent bodies cannot be replayed to a given
   recipient, and an older one can. That stops capture-and-redeliver and does not stop a patient
   attacker. Closing it properly needs freshness inside the sealed transcript, which is a
   wire-format change to a block carrying no version byte, and is not done. A replayed body is
   decrypted before it is recognised, so the plaintext is wiped and the length zeroed before the
   refusal is returned — covered by its own case, since a caller that checks the length instead of
   the result must not find the message sitting in its buffer.

   Also still outstanding: forward secrecy against compromise of the *recipient's* agreement key. Key rotation — which the identity keys needed too — is now covered
   for both by item 2's revocation and multi-key work: an agreement key rotates by adding a second
   allow-list line and revoking the first, and `SealFor` skips a revoked agreement key rather than
   sealing to it.
5. ~~Handle validation across the flat C ABI, ahead of the Java/Panama bridge.~~ ✅ **Done**, as a
   type-aware, pointer-keyed registry of live handles that never dereferences the caller's pointer
   — reading a magic word through a hostile pointer is the defect the magic word was meant to fix.
   Every handle is registered where it is created and forgotten where it is destroyed, so a pointer
   the library never issued, a freed one, and one of the wrong kind are all refused (**M1**).
   Each entry point also catches `P2Pevent` rather than letting a C++ exception unwind across the
   `extern "C"` boundary, which an FFI downcall has no landing pad for.

   The surface was removed from this repository on 2026-08-13 for having no in-tree consumer, and
   **restored on 2026-08-14** with the registry intact; it is built into the DLL and the `.so`
   again, and `Targetcore_c.h` is the single copy that the Java tree's bindings are generated from.
   ~~Still open here: the Targetcore surface has **no test** of its own for the four refusal
   cases.~~ ✅ **Closed 2026-08-14.** The nine cases deleted with the ABI were restored with it —
   a pointer the library never issued (including `(void*)0x1`, which faults any design that reads
   through the caller's pointer), a destroyed handle, a double destroy, wrong-kind confusions, a
   throwing callee, and a control proving the registry still says yes — plus the two
   `p2peerhub_set_sink` cases and the `p2p_u8_smoke` ctest entry. `Msgcore_c.*`, a **separate**
   flat C API still built into `Msgcore.dll`, carried the identical defect, got the same registry
   on 2026-08-13 across 217 entry points, and has its own four cases plus a control. Both are run
   on both platforms; the Linux half is not a formality, since the sink cases are the only things
   that execute the copy out of the accessor ring, which is a no-op on Win32 and load-bearing
   everywhere else. *(This paragraph claimed the gap was open for a day after it was closed — the
   restore updated the report and not this file.)*
5a. Bounding what an **unauthenticated** peer can hold. Numbered out of sequence deliberately —
   items 6 and 7 are referred to by number from that internal log, and renumbering them to make
   room would silently break those references. In priority order it sits here.

   Everything above decides who may *speak*. This is spent before a word is said, and until
   2026-08-16 nothing bounded it in either dimension: no count of accepted connections, so the
   limit was the descriptor table, and no deadline on a peer that connects and never logs in.
   ✅ **The count is done** — `SetMaxAccepted(n)`, default 1024, refused at accept with the socket
   closed rather than left in the backlog, guarded by `p2p_acceptcap` on both platforms.
   ✅ **The per-source share is done too**, on 2026-08-19 — `SetMaxAcceptedPerSource(n)`,
   keyed on `getpeername()` at accept, **off by default** because loopback and NAT both collapse
   many peers onto one address. Guarded by `p2p_srcbound`. The pipe transport is still bounded by
   an `nMaxInstances` it does not own; see the posture row above.
   ✅ **The deadline works on BOTH platforms since 2026-08-18.** The mechanism was already
   complete in the tree — `On_PITimer` throws "Login timed out" on expiry and all three cancel
   sites are correct — and only the `SetPITimer` call arming it was commented out. Arming it
   turned up two defects: `CancelP2PmsgTimer` treated "already fired" as corruption and threw
   **from `~P2PeerCon`** (fixed, and it had been reachable by the restart timer all along); and a
   Linux cascade in which the drop appeared to cancel the **listening** socket's pending accept.
   ~~That second one is not fixed.~~ **That cause was wrong and was recorded in three places.**
   Traced rather than assumed: the real fault was that `closesocket()` erased the fd→key
   association *before* the cancellations it triggered completed, so every `ERROR_OPERATION_ABORTED`
   arrived unattributable and the service read it as a failure of its own listener. Fixed by binding
   the key at submission (`OVERLAPPED::_p2p_key`). `p2p_logindeadline` is registered on both
   platforms and passes on both. `DEF_P2PeerConLogin` is still `0` — the cascade that forced
   that default is gone, but the deadline stays opt-in.

   Still outstanding: the Linux cascade above; the cap is **per service**, not per host or per
   source address — 1024 connections from one peer and one each from 1024 peers are the same thing
   to it, because the address is not known until the login that has not happened; and the cap is
   enforced in `P2PeerConWsa` alone, so the pipe, serial and DMX transports rely on bounds they do
   not own (`nMaxInstances`, physical ports) rather than on this one. Recorded 2026-08-17.

   Two further resource questions are now on the record in the posture table rather than here,
   because both predate this item and neither is about an *unauthenticated* peer: the pump depth
   bound and its three disagreeing thresholds, and the diagnostic path that can block a pump
   thread in a service. Both were found on 2026-08-17 while re-answering the readiness question,
   both are read from the source rather than driven. ~~and the second one is why every service host
   needs `P2PMSG_NO_UI=1`.~~ The second was **fixed the same day** — a service host needs no setting
   at all, because the library now refuses a dialog wherever one could not be seen. `P2PMSG_NO_UI=1`
   remains available, and so does `ErrToMessageBox: 0` in `P2Pmsg.cfg`, for a windowed host that
   wants no dialogs at all.
6. ~~Systematic fuzzing of the receive/framing path.~~ **CLOSED 2026-08-20**. Fuzzing now runs **continuously** - daily, on both platforms, from a seed that moves with the run number and is still not the clock - against a **persistent corpus** that every gate run replays, at sizes **spanning the receive ceiling** rather than only the ~2 KB band it used to, and covering the **authenticated wire parsers** (`p2p_fuzzblock`: login, ack, relay attestation, revocation list) as well as the framing path. A finding arrives as a **reproducer file** rather than as a log line, which is the difference between a defect somebody has to re-derive and one that can be replayed with a single argument and promoted into the corpus as a permanent regression pin.
7. An external audit once the above land.

**A written threat model — added to this list on 2026-08-20 and closed the same day, because it was
never a numbered item and should have been.** The arguments in this file were always about threats
and were argued well; they were scattered, and scattered arguments cannot be checked for
**coverage**. [`THREAT_MODEL.md`](THREAT_MODEL.md) puts them in one place — seven adversaries, nine
assets, five trust boundaries, every protection mapped to the adversary it answers and the line that
enforces it — and the mapping found three gaps on its first pass. **All three are now fixed**
(**F-S6-1**, the posture table's channel-binding row; **F-S6-2**, a running hub that could not be
asked what was on; **F-S6-3**, confidentiality inherited from a class rather than enforced by a
rule), each with a gate test of its own, and each falsified against the tree that had the gap before
it was believed. Closing the third opened **F-S6-4** — a warning class that was masked out by
default, so every `EVWRN` diagnostic in these repositories was raised into nothing — which was named
in §8 of that document as an operator-facing default decision rather than a defect in a protection.
**That decision was taken on 2026-08-20 and the answer was to turn it on:** the default notification
mask is now `ERROR|WARNING`. The three warnings it makes visible are all operator misconfigurations
with the fix in an `Advice` line — a relay attestation that could not be signed, a peer signing
logins to a hub that does not require them, and `P2PeerioBSTR` (the transport that carries
cleartext) being constructed — and all three report through `SetLast()`, so a misconfigured hub
costs one line per connection rather than one per message. It is a **behaviour change for every
existing host** and is recorded as an unreleased break;
the opt-out is one call, `P2Pevent::Configure(P2PeventCfg_REMMASK, P2Pevotn_WARNING)`. Item
7 is unaffected: a threat model written by the people who wrote the code is not an audit, and this
one says so.

Until items 1-3 are complete, the warning at the top of this file stands unchanged.

## Supported versions

This project is under active modernisation. Security fixes land on `master` only.
There are no maintained release branches and no backports.

| Version | Supported |
|---|---|
| `master` | ✅ |
| Anything else | ❌ |

Including `v3.1.1`, `v3.1.0` and `v3.0.0`. A tag is a point you can build from and trace a binary back to, not a
branch anything is maintained on — if a fix lands after it, the fix is on `master` and the tag
does not move.

**The pre-1.0 disclaimer has been retired, by a decision rather than by a number moving past
it.** The versioning policy listed what had to be true before it could go, and three of the five
items were security work: a written threat model, F-S4-1 settled (on Windows the accept bounds
counted connections *ever accepted*, so a documented bound did not bound), and this sentence
retired deliberately. **All three are now met** - the threat model is
[THREAT_MODEL.md](THREAT_MODEL.md), F-S4-1 was closed on 2026-08-20, and the disclaimer was
retired with the 3.0.0 release on 2026-09-02.

**What the release number does not settle**, stated here because a major of 3 invites the
assumption. 3.1.1 covers the flat C ABI and nothing else. The message image is still unversioned -
its header has no version field and no spare bit - so a peer meeting a re-laid-out message parses
garbage rather than reporting a mismatch. `Targetcore_version.h` says so at the point the number
is set, and that is the statement to read before assuming the major covers more than it does.

**F-S5-3's wire-layout question stood here too until 2026-08-20, and it closed by neither of the
two routes gate 1 was written to expect.** Not by re-laying the packed message
image, and not by accepting the alignment exception as permanent. Re-diagnosed, the finding was not
*wide payloads are unaligned* but **every blob payload is** - the image is `#pragma pack(1)` end to
end, so a payload's offset is the running sum of odd-sized headers and no field ordering recovers
it. It was answered by making the contract explicit and giving callers an aligned way to read:
`P3PmsgData::c_vBlobCopy`, `P2Pc_vBlob::Load`/`Store`, and the guarantee written at the accessors
themselves. **The wire and the on-disk image are unchanged**, so the one open finding whose fix was
going to cost a format break turned out not to be one. `-fno-sanitize=alignment` is gone from
`linux-gcc-asan`, which is the check that says so - and it went **red** on two gates this finding
had never named before it went green, which is the argument for re-arming a check rather than
trusting a row. Read that list as part of this file's posture, because it is.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** The regular issue tracker is public,
and a report there discloses the flaw before there is a fix.

Use **GitHub's private vulnerability reporting** instead:

> Repository → **Security** tab → **Report a vulnerability**

If GitHub private reporting is not available to you — or the button is not there — email:

> **info@ivyware.com.au**

with `SECURITY` in the subject line. This is the same address the
[contact page](https://ivyware.com.au/contact.html) publishes, and it is a general mailbox rather
than a dedicated security one: say so in the subject or the first line, because that is what routes
it. There is no PGP key. If you need to send something you would rather not put in cleartext mail,
say so without the detail and you will be given somewhere to put it.

### What to include

The same detail that makes a normal bug report actionable, plus the security specifics:

- **What the flaw is**, and what an attacker gains from it
- **Reachability** — pre-authentication or post-? Which transport (`P2PeerConWsa`,
  `P2PeerConPipe`, `P2PeerCon232`, `P2PeerConDmx`)?
- **Affected file and line**, against a named commit
- **A reproducer** if you have one — a crafted frame, a test harness, a crash dump
- **Build identity** — configuration and platform (`Release|x64` etc.), toolset, Windows version
- For a crash: the call stack, and whether the pump thread or the caller's thread was on it

Concurrency and lifetime bugs dominate this codebase. A report that names *which thread* is worth
ten that do not.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | 5 working days |
| Initial assessment and severity | 15 working days |
| Fix or a documented mitigation plan | Depends on severity and scope; we will tell you the plan |

This is a small, unfunded project. These are honest targets, not a contractual SLA.

### Scope

**In scope** — anything in this repository that an attacker can reach:

- The receive and framing path, on any transport
- Message routing, addressing, and handler dispatch
- The end-to-end seal and the identity/allow-list storage
- Memory-safety defects: overflow, use-after-free, type confusion, integer overflow
- Concurrency defects with a security consequence
- The flat C ABI (`Targetcore_c.h` and its `_u8` twins) — **101** entry points exported from the
  DLL/`.so`, restored to this repository on 2026-08-14, and enumerated since 0.10.0 in
  [`.github/ci/abi-flat.manifest`](.github/ci/abi-flat.manifest) with two checks that keep the
  count honest. This said **74** until 2026-08-20 — the
  figure was accurate when it was written and the surface grew under it, which is exactly what the
  manifest now prevents. A scope statement that undercounts the surface excludes something by
  accident. Handle confusion, a handle the library never issued, a freed
  handle, and an exception escaping across the `extern "C"` boundary are all in scope here

**Out of scope** — already known and documented above; reporting these tells us nothing new:

- "There is no encryption on the wire" / "there is no peer authentication" **on a hub that has
  opted out with `RequireAuth(false)`** — that is a documented, deliberate posture, not a finding.
  *This bullet used to say "a hub that has not been configured for either … the documented default
  posture", and since 2026-08-18 there is no such hub:* an unconfigured hub does not start. A defect
  in the authentication or encryption path of a hub that arms very much is a finding
- "The `DHKeyXChanger` implementation is weak" (it has been deleted; findings against it are moot)
- The *generated* Java bindings in the separate Java tree — report those there. The C surface they
  are generated from is in this repository and **is** in scope, above
- Findings that require an already-compromised local machine
- Vulnerabilities in MFC, the Visual C++ runtime, the Windows SDK, OpenSSL, or liburing — report
  those upstream

### Disclosure

We will work with you on a coordinated disclosure timeline and credit you in the fix commit and
release notes unless you would rather stay anonymous. We will not take legal action against
good-faith research conducted against your own systems and consistent with this policy.

## Hardening advice for current users

If you are running Targetcore today, defence has to come from outside the library:

1. **Bind to loopback** where the peers share a machine; prefer `P2PeerConPipe` over
   `P2PeerConWsa` for local hub-to-hub links. **Since 2026-08-27 `P2PeerConWsa` can do this
   itself** — `SetListenScope(P2PeerConScope_Loopback)` on the SERVICE before it listens, and the
   socket binds `127.0.0.1` instead of `INADDR_ANY`. Until that release it bound every interface
   unconditionally and this advice could only be followed in a firewall. See 3d.
2. **Put it inside a tunnel.** A WireGuard or IPsec link, or an stunnel/TLS wrapper, gives you the
   confidentiality and peer authentication the library does not.
3. **Firewall the listening port** to an explicit allowlist of peer addresses. `AllowAcceptFrom()`
   (3d) now does a version of this inside the process; it does not replace the firewall, because a
   packet the firewall drops never costs this process a thread, a socket or a parse.
3a. **Make the service's address domain as narrow as you can bear.** For `P2PeerConWsa` the
   `ServiceFactory` peer argument *is* the accepted-address pattern, and it is the only thing
   restricting what a peer may claim to be. `MyApp.Client` admits exactly one identity;
   `MyApp.*` admits every peer to every identity under it, including each other's. Prefer one
   listening port per expected peer with an exact domain over one port with a wildcard, until
   the PSK work lands.
3b. **Bound what an unconnected stranger can hold.** Since 2026-08-16 a `P2PeerCon` in SERVICE mode
   takes `SetMaxAccepted(n)` — concurrent accepted connections, default 1024, 0 unbounds — and
   `P2PeerConWsa` takes `SetBacklog(n)`. The default is *generous*, because it is a default; set
   it to what your deployment actually expects. Before that release there was no bound at all and
   the limit was the descriptor table. Guarded by `p2p_acceptcap`, on both platforms.
   Since 2026-08-19 it also takes `SetMaxAcceptedPerSource(n)` — the same bound **per source
   IP**, so one peer opening the whole cap and 1024 peers opening one each stop being the same
   thing to it. **Off by default**, because loopback and NAT both collapse many peers onto one
   address and a default that bound would refuse legitimate traffic silently at accept; set it if
   you know your topology. Guarded by `p2p_srcbound`.
   `SetLoginDeadline(ms)` drops a peer that connects and never logs in. It is **off by default but
   safe to turn on, on either platform, since 2026-08-18** — the "it takes the listener down
   under Linux" warning that stood here was based on a cause that was traced and found wrong, and
   the real fault is fixed. **Arm it anyway, and the reason has changed as of 2026-08-20.** It used
   to be load-bearing: without it both accept bounds above counted connections ever accepted rather
   than currently held on Windows (`F-S4-1`), so the bounds did not release and the deadline was the
   only reaping path that worked on both platforms. **F-S4-1 is fixed** - an orderly close is now
   seen on Windows as it always was on Linux, gated by `p2p_conreap` - so the bounds release on
   their own and the deadline is no longer covering for a defect. What it still does is the thing it
   was always for: a peer that connects and simply **never speaks** holds a slot until it chooses to
   leave, and only a deadline takes that back.
3c. **Watch the hub, and know what "quiet" means.** Since 2026-08-19 `P2PeerHub::Serialise()` —
   the snapshot behind `MSG_P2PexpHub` and every `P2Pevent` carrying hub state — reports
   `QueDepth` (messages queued across all of the hub's pumps), `Accepted` (connections its services
   currently hold) and `Throttled` (backpressure holds applied). A monitor built on nothing but that
   call can alarm on all three; `p2p_hubsnap` is the gate that keeps it that way. **Read `QueDepth`
   and `Throttled` together.** Backpressure is on by default and holds a connection's reads at
   37500 live messages, releasing at 25000, so a hub whose queue is low *because* it has stopped
   reading looks idle on `QueDepth` alone. A climbing `Throttled` with a low `QueDepth` is a hub
   holding the line, and it is the signal to add capacity — not a hub with nothing to do.
   `SetP2PmsgBudgetMarks(high, low)` lowers the marks if you want to feel it earlier.

3d. **Say where you listen, and who may reach you.** Two settings on `P2PeerConWsa`, added
   2026-08-27, and they answer different questions — a deployment facing a network it does not own
   is expected to set both.

   **`SetFamily(family)` — WHICH ADDRESS SPACE, and it decides what the other two settings MEAN.**
   `P2PeerConFamily_IPv4` is the default and is what every caller written before 2026-08-28 keeps —
   this transport was `AF_INET` at all three socket sites until then, so a v6 peer could not reach a
   service at all. `_IPv6` opens `AF_INET6` with `IPV6_V6ONLY` **on**; `_Dual` opens it with the
   option **off**, one socket serving both families. The option is set explicitly in both
   directions and never inherited, because Windows defaults it on and most Linux distributions
   default it off: a socket that did not say would be v6-only on one build and dual-stack on the
   other from identical source, and a "v6-only" service that quietly admits v4 is the S9 failure
   this document keeps arguing about. Set it before `Listen()` on a service and before `Connect()`
   on a client. `_Dual` **refuses** a loopback scope rather than picking one — `::1` is not the
   v4-mapped form of `127.0.0.1`, so no single bind covers both. Guarded by `p2p_ipv6` and
   `p2p_ipv6dual`.

   **`SetListenScope(scope, address)` — the BIND.** `P2PeerConScope_Any` is the default and is what
   every existing caller keeps. `P2PeerConScope_Loopback` binds `127.0.0.1` (or `::1` under
   `_IPv6`), and it is the only one
   of the two the **kernel** enforces: an off-host SYN is refused by the stack, so nothing in this
   library parses a byte of it. That matters more than it sounds, because everything before the
   login gate — the whole framing parser — runs on bytes with no provenance (`THREAT_MODEL.md`
   B1/B2). `P2PeerConScope_Address` binds one nominated **local interface**. An address this host
   does not hold makes `bind()` fail and drops the service rather than quietly widening to
   `INADDR_ANY`: a restriction that silently becomes no restriction is the S9 failure this document
   keeps arguing about. Set it before `Listen()`; a socket already listening keeps what it was
   bound to. Guarded by `p2p_listenscope`.

   **`AllowAcceptFrom("192.168.1.0/24")` — the ALLOW-LIST.** A prefix list tested at accept against
   `getpeername()`, before the connection object is allocated and long before a login is attempted.
   `AllowAcceptLoopback()` and `AllowAcceptPrivate()` (RFC1918 + loopback + link-local, and their v6
   counterparts `::1`, `fc00::/7` and `fe80::/10`) are the two shorthands most deployments want.
   **Empty list = no restriction**, which is the default. It answers false for a prefix it cannot
   parse and adds nothing — check the return, a rule that failed to parse is a filter narrower in
   your belief than in the socket. Guarded by `p2p_acceptfilter`.

   **Both families, and the trap in writing only one.** A `':'` in the rule makes it IPv6
   (`"2001:db8::/32"`, `"fd00::/8"`, a bare `"::1"` meaning /128) and its absence IPv4, so a rule
   and its family cannot be written to disagree. A zone suffix is refused, because a rule that
   dropped it would be about every link rather than the one named — spell a link-local allow-list
   `"fe80::/10"`. **A rule matches only its own family**, so a list holding only v4 prefixes refuses
   every v6 peer: on a `_Dual` service that is a restriction which will be believed to be about
   addresses and is really about which lines were written. The one place the two spaces touch is a
   v4 peer arriving on a dual socket as `::ffff:a.b.c.d`, and this class normalises that back to
   `AF_INET` before it is tested — so `"10.0.0.0/8"` admits the same peer whichever socket carried
   it, which is not a convenience but the difference between one policy and two. Guarded by
   `p2p_ipv6filter`, which measures the normalisation through a real socket and not only through
   the decision.

   **The per-source bound counts a v6 peer by its /64.** `P2PsourceKey` is 64 bits and a v6 address
   is 128, so something has to be lost and what is lost is chosen: the key is a hash of the /64
   prefix, the block one host is routinely delegated. Keying the whole address would let a single
   subscriber line mint 2⁶⁴ keys and walk straight through `SetMaxAcceptedPerSource`. Two hosts in
   one /64 therefore share a share, deliberately. Bit 63 is set on every v6 key so it can never
   collide with a v4 one — and so `::1`, whose /64 prefix is all zeroes, cannot fold to the 0 that
   means "the kernel would not name the origin".

   **Why both, and what neither buys you.** A bind cannot express "the LAN": binding to a LAN
   interface's address restricts which *interface* accepts, not which *source* reaches it, so a
   packet forwarded in from the internet by a NAT or a port-forward arrives on that same interface
   and is accepted. And an allow-list is an *address* test, not a proof of locality — anything
   upstream that rewrites a source address can present a public peer under a private one. Neither
   is authentication. `RequireAuth` is still what decides who may speak; these decide who gets to
   be listened to at all.

   **The allow-list fails CLOSED**, deliberately, and it is the opposite of `SetMaxAcceptedPerSource`
   sitting one line away in the same function. A source the kernel will not name is *admitted* by
   the per-source bound — an accounting bound that cannot identify its subject must refuse nobody,
   or one `getpeername()` failure stops the service — and *refused* by the allow-list, because an
   operator who wrote down who may connect has thereby said everybody else may not.

4. **Run the process with least privilege.** Handler code executes on the pump thread with whatever
   rights the host process holds, and there is no auth gate in front of it.
5. **Keep handler maps minimal.** Every `ON_P2PeerMsg(...)` entry is reachable by any peer that can
   complete a TCP connection. Do not register a handler you would not expose deliberately.
6. **Treat `P2PeerExplorer` as sensitive.** It reports live hub, pump, and connection topology and
   registers on an unverified source address.
