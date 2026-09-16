# Sealing

End-to-end payload confidentiality between hubs — what it is designed to do, and what it does when
it is actually switched on. The design half was written against `master` @ `3227e4e` and re-checked
at `0b37f2c`; every claim in it names the file and line it was read from. Everything from *What
actually happens when it is on* downwards is a **run**, made 2026-08-24 on Windows Debug and Release,
and where it disagreed with the design half, the code has been corrected rather than the document.

---

## What sealing is

Sealing is **end-to-end confidentiality for a message body**, as distinct from the per-hop
connection cypher. `P2PeerSeal.h:17-31` states the problem it exists for:

> The session cypher … protects one HOP. An intermediate hub necessarily decrypts it: routing
> decisions are made on the message's destination address, so a hub that could not read the frame
> could not forward it. Hub B on the path A → B → C therefore sees A's plaintext, and no amount of
> link crypto changes that — it is what "routing" means.

So in a hub tree, link encryption is not enough. Every relay is a legitimate holder of the
plaintext, because it has to read the destination to know where to send it next. Sealing encrypts
the **payload** to the destination, leaves the **addresses** in clear so routing still works, and
the two compose: link crypto hides the addressing from a wire tapper, sealing hides the body from
the hubs in the middle.

### What a seal actually is

ECIES with a sender signature. Per message the sender generates a throwaway ECDH P-256 pair and
agrees it against the recipient's **static agreement key** — a different key from the identity key,
taken from the allow-list, so a body can be sealed to a peer that has never connected and survive
store-and-forward. HKDF-SHA256 derives an AES-256-GCM key from the shared secret, and the whole
thing is signed with the sender's ECDSA **identity** key — the same key the login proves, so
confidentiality and authorship rest on the two different key types they each need.

Encrypt-then-sign, deliberately: the signature covers the ciphertext, so a verifier throws out a
forgery before doing asymmetric work on attacker-chosen plaintext. Source and destination addresses
are bound in twice — as GCM additional authenticated data *and* inside the signed transcript — so a
sealed body lifted off one message and pasted onto another fails, rather than decrypting happily
under a forged sender.

### The v2 wire block

`kSealVersion` is **2** (`P2PeerSeal.h:120`), and the layout follows from the constants at
`P2PeerSeal.h:135-190`:

```
ver(1) | sealed_at(8) | eph_pub(64) | count(1) | slot(68) × N | nonce(12) | ct(n) | tag(16) | sig(64)
```

Three fields carry most of the design:

- **`ver`** — first, so a reader dispatches before parsing anything else. v0 began with the
  ephemeral X coordinate, a uniformly distributed byte, which is why v0 → v1 had to be a hard break
  and v1 → v2 did not: a v2 reader still opens a v1 body, a v1 reader refuses a v2 one, so a mixed
  mesh upgrades receivers first.
- **`sealed_at`** — seconds since the epoch, bound into both the additional data and the signed
  transcript, so nobody including the recipient can edit it. `p2pseal` only *reports* it;
  `AuthPolicy` applies the window. Cryptography here, judgement there.
- **The recipient block** — v2's addition. The body is encrypted once under a random content key,
  and that key is wrapped once per reader at 68 bytes a slot, up to `kSealMaxReaders` = 8
  (`P2PeerSeal.h:174`). The destination is always slot 0; the sender may name intermediate hubs with
  `AddSealReader` when a deployment genuinely needs a relay to read the body — content routing,
  filtering, a store-and-forward broker. The reader set is bound into the additional data and the
  transcript, **so only the sender names them**: a relay can neither splice itself in nor strip
  anyone out.

### How it behaves at runtime

`RequireSeal` defaults to **on** since 2026-08-21. `P2PeerCon::SealAppMsgOutbound` seals any
application message whose destination is not the peer at the far end of the link, and if it cannot —
no published agreement key for that destination — it **drops the message and says so** rather than
sending the body in clear (`P2PeerCon.cpp:2827-2848`). That refusal is the whole design decision; a
seal that quietly degraded to cleartext when the directory was incomplete would be a protection
inherited rather than enforced. Opt-out is `RequireSeal(false)` (`P2PeerHub.cpp:2277`).

That is the design, and until 2026-08-24 it was the last paragraph in this document describing
behaviour nobody had observed: **a message on this path died before the refusal could be reached.**
Two defects behind that are now fixed and the path carries traffic — refer *What happened when it was
first switched on*.

### What it explicitly does not give you

Two limits the header states outright (`P2PeerSeal.h:99-106`): ordering and liveness stay with the
layer above, which knows what a duplicate means for its own messages; and the ephemeral half gives
forward secrecy against later compromise of the **sender only** — whoever holds the recipient's
static agreement key can open every message ever sent to it.

---

## What happened when it was first switched on

Everything above this line is the design, read out of the source. This section is a run.

**The automatic path had never been exercised.** `p2p_sealhop` seals **by hand** and sets
`RequireSeal(false)` so that its cleartext control can happen at all; `p2p_sealdefault` exercises the
default, the v2 envelope and the refusal **in-process, with no sockets**. Every other socket test in
the suite turns sealing off for its own good local reason — `p2p_authancestor:422`,
`p2p_bigreport:329`, `p2p_reportsign:502`, `p2p_sealhop:394`. Nobody chose the consequence and it was
collective: `SealAppMsgOutbound` → wire → `OpenAppMsgInbound` had never run end to end on the
configuration every deployment gets by default.

`p2p_sealbcast` (new 2026-08-24, `MscsUnitTests`, labelled `security`) is the run. Three hubs over
two real sockets — `Bc → Bc.Mid → Bc.Mid.Leaf` — with the carrier holding no keys of any kind, auth
off so nothing can be credited to a session cypher, `IsSealRequired()` **asserted rather than set**,
and a hand call to `SealFor` during setup to prove the sender can seal to the destination before a
single message is posted. That probe returned `ok`. Then it posted one ordinary relayed unicast, and
the message never left the first hop.

Two defects sat in the way, neither of them about broadcast. Getting past them let the test reach the
question it was written for, which turned up a third. All three are now fixed.

### The payload could not grow

`SealAppMsgOutbound` seals into a scratch buffer and writes the result back over the message's own
payload:

```cpp
pMsg->SetData ( pMsg->c_name ( ), &vSealed[0], (P2Psize_t)cbSealed );   // P2PeerCon.cpp:2820
```

A seal adds a fixed 234 bytes (`P2PeerSeal.h:191`, one reader), so the payload has to **grow in
place**, and `P3PmsgData::c_vBlob` (`Msgcore/P2Pmsg.cpp:983`) is what has to grow it. It could not,
and the plaintext size decided which way it failed:

| body | what happened |
|---|---|
| ≤ 255 bytes | held in a BLOB08, whose length field is a `UINT08`. `c_vBlob` refused to widen the type tag — `Buffer overrun (262 vs 255) blocked` — and threw out of the connection's send loop. **The link dropped.** |
| > 255 bytes | a BLOB16, so the resize branch ran and handed `P2PmsgObject_NewVBLockData` the **blob** size where `c_memcpy` — ten lines below it, the same shape of code — hands it `VBLockData_Sizeof(…)`. The descriptor came out short by its own header and the copy ran off the end of the heap entry: `P3PmsgField::AssertValid … Failed Containment`, then `P2PmsgHeap_CollateIOMAGE … Attempt to collate non-free entry`. **The link dropped.** |

An `ASSERT(0);//Is resizing valid` stood at the top of that branch, so it was unreachable in **Debug**
— it only ever executed in Release, where the containment asserts inside `NewVBLockData` are also
compiled out and had nothing to catch either fault.

**Fixed.** `c_vBlob` now widens the type tag within its own family (`VBLockData_WidenBlob`) and sizes
the allocation the way `c_memcpy` always did. The tag travels on the wire and every reader dispatches
on it, so a widened cell round-trips with no agreement between the ends; widening only ever replaces
a throw, so no path that worked before behaves differently.

### The attestation covered bytes that no longer travelled

With the payload growing, the body reached the destination and was refused there:
`Relayed message from [Bc.Mid] claiming source [Bc] refused: signature does not verify`.

`AttestRelay` digests the body, and the receiver checks it in `GateAppMsgInbound` →
`GateRelayInbound` (`P2PeerCon.cpp:2708`), which runs **before** `OpenAppMsgInbound` (`:2731`). So the
bytes the far end verifies are the sealed ones. The send path attested **first** and sealed second,
signing the plaintext and then replacing it — and the hook's own note argued for the order it did not
implement.

**Fixed.** Seal, then attest (`P2PeerCon.cpp:746`). That is also encrypt-then-sign, the same
discipline `p2pseal` uses inside its own envelope, so a forgery is discarded before any asymmetric
work is done on attacker-chosen plaintext.

### One field was doing two jobs

Past those two, the broadcast finally ran — and was neither sealed nor refused. The carrier read it.

`TMsg_Dst` answers two different questions. To a sender it is *where this is ultimately going*; to a
router it is *who this link hands it to*. For a unicast those coincide, which is why nothing ever
noticed. `P2PeerHub::On_P2PeerBCast` is where they part: it does not send the message that was
posted, it sends a **copy per link**, re-addressed to that link's own peer.

```cpp
pMsgBCast = pMsg -> RedirectFactory ( oP2PaddrCon );        // P2PeerHub.cpp:1418
```

Two protections were reading the first meaning off a field that by then held the second:

| what it read `Dst` for | what re-addressing did to it |
|---|---|
| `SealAppMsgOutbound`'s last-hop exemption, `m_oThatP2Paddr == strDst` (`:2792`) | true at **every** hop, so the seal hook never fired at all — a 400-byte broadcast crossed a carrier holding no keys, in clear, on the tree that sealed phases 1 and 2 over the same hop |
| `AttestRelay`, which digests the destination | the origin's block is forwarded untouched by design, so a re-addressed copy no longer verified — `signature does not verify` at the leaf, and the **link dropped** |

**Fixed 2026-08-25.** `TMsg_Scp` (`P2PeerMsg.h`) carries what the origin addressed the message to.
It is stamped once, by the hub that fans out, and `RedirectFactory` does not touch it — the copy
inherits it like every other field in the image. Both ends of both checks now read
`GetScopeOrDestin()`, which falls back to `Dst` when nothing was stamped, so every unicast path is
byte-for-byte unchanged.

A new field rather than simply not re-addressing: the receiving hub accepts and dispatches on `Dst`
naming itself, so the rewrite is load-bearing for delivery. The next-hop meaning had to stay where it
was; it was the end-to-end meaning that needed somewhere else to live.

### What it does now

`p2p_sealbcast` phase 1, a 400-byte body: the carrier holds **634 bytes, sealed-marked, and cannot
read them**; the leaf recovers the plaintext exactly. Phase 2, a 28-byte body in the BLOB08 regime:
262 bytes, opaque, delivered, no link lost. Phase 4 — sealing off, relay attestation on, the same
fan-out — the leaf receives the broadcast and **no link closes**: a fanned-out copy is attributable
to its origin end to end, which it never was before. That phase is not a vacuous green; reverting
`AttestAppMsgOutbound` alone to `GetDestin` reproduces `signature does not verify` and the dropped
link, which was checked before the change was kept.

Phase 5 exercises the opt-out below and requires **both** halves of it: the broadcast readable, and
the relayed unicast beside it still opaque under the same policy. Dropping the `HasScope()` test
from the exemption turns that line into `PLAINTEXT - EXEMPTION LEAKED` — also checked rather than
assumed.

`ctest` **46 of 46** on Windows Debug and Release alike, and **48 of 49** on Linux (gcc, OpenSSL),
whose one failure is `com232_mesh`, a pre-existing flake on that VM that moves independently of this
work. The phase table is byte-identical across all three, so none of the three defects was
platform-specific and neither is the switch.

So the refusal described earlier in this document — publish an agreement key or do not send — is real
code, and it is now reachable for the first time.

---

## Sealing and broadcast: what this section used to get backwards

This section previously said the two are structurally incompatible because a broadcast is **refused**
for want of an agreement key. The evidence it cited was not a broadcast at all, and the real
behaviour was the opposite shape — a broadcast was not refused, it was silently exempt. A broadcast
*is* refused now, but for a different reason, and only because the fix above made the hook fire.

**The message it quoted is a unicast.** `p2p_authancestor`'s comment at `:417-421` reads *"a
BROADCAST has no single destination to seal to. The address lookup is exact, so P2PmsgBCast to a
subtree finds no agreement key and is refused."* The message that comment is attached to
(`p2p_authancestor.cpp:274`) is:

```cpp
PostP2PeerMsg ( new P2PeerMsg32 ( strSource, kLeafAddr, P2Pmsg_BCast, … ) );
```

One source, one destination, `Anc.Mid.Leaf`. It has exactly one address to seal to, and that address
could hold an agreement key. It was refused because that test provisions no agreement keys anywhere
— deliberately, and it says so at `:383`: *"Neither relay gets anything at all - a router that cannot
forge what it forwards is the whole claim."* The refusal was a **provisioning** refusal on a unicast.

**And `P2Pmsg_BCast` is the suite's generic message name.** `alex_test:193`, `com232_mesh:259`,
`dmx_mesh:172`, `mix_con:194`, `mix_con3:174` and `TargetcoreSuite:240` all post it from one address
to one address and override `On_P2PeerBCast` to receive it. Not one of them fans out. "Broadcast" in
that diagnostic was a message **name**, not a routing mode.

**What the fan-out actually did** is set out above under *One field was doing two jobs*: it
re-addressed a copy per link, which made the last-hop exemption true at every hop and left the
carrier reading a 400-byte broadcast in clear. That is fixed. What follows is what is left.

**A broadcast is now blocked by the confidentiality default rather than silently outside it.** With
the exemption keyed on the scope, the seal hook fires on a broadcast for the first time — and refuses
it:

```
Will not send [P2PmsgBCast] scoped to [Bc] unsealed: no agreement key
```

That is the designed outcome, taken deliberately on 2026-08-25 over sending in clear with a warning.
It costs nothing today: `ConState_BCasts` is set nowhere in the library outside the `P2Pexpump`
paths, so a stock hub tree does not fan out at all. And it matches what the module does everywhere
else — `SealAppMsgOutbound` refuses rather than downgrades, and broadcast was the one path that did
not.

**And there is a targeted opt-out, which is the other half of the decision.**
`RequireSealBroadcast(false)` exempts fanned-out copies and nothing else: relayed unicast stays
sealed, and the exempt copies keep the origin's attestation over their scope, so they are
unencrypted and still **unforgeable**. It defaults to on, so the exemption only exists where somebody
wrote it down, and `TryReadPosture` reports it as `SealBcast` so the choice stays visible
afterwards. The exemption keys on `TMsg_Scp`, which only the fan-out stamps — so a unicast cannot
reach that branch by construction rather than by matching a message name, which is the mistake
F-S9-1 was.

The point is not that the switch permits an unencrypted broadcast; the old code did that too, at
every hop, for free. It is that the permission now has to be asked for. The defect was never that a
broadcast went in clear — it was that nobody had chosen for it to.

**The decision that is still not made.** A scope names a **subtree**, and no single agreement key
opens one. The reader set is bound into the sealed body's additional data and its signature, so a
fan-out to a subtree of unknown size cannot be expressed as the sender-enumerated list v2 provides —
at most eight slots, all named by the sender. Three shapes have been analysed and none chosen:

- **a per-pattern group key** — constant size and the only one that scales, but it needs a secret
  distribution channel the tree does not have, makes revocation a rekey, loses the forward secrecy
  the ephemeral half provides, and makes readership *positional* rather than sender-chosen;
- **sign without encrypting** — coherent, free, and honest so long as it is loud, which is what the
  refusal above now makes it;
- **a resolved multi-envelope** — the best fit for the v2 format and the only one that keeps the
  sender naming its readers, but it needs a membership oracle that does not exist, has an unclosable
  skew between seal time and delivery time, and lets a hub make itself a reader by asserting a
  matching address — the exact splice the reader block exists to prevent.

The pragmatic middle is the third over an **explicitly configured** group via the existing
`AddSealReader`, which keeps the format and drops the scan's attack surface, paying only in
provisioning.

**What survives from the earlier section unchanged.** `RequireSeal(false)` is **hub-wide rather than
per-message**, so a tree that needs the opt-out for one class of traffic loses sealing on all of it.
The claim that a fan-out *carries no end-to-end destination* no longer survives — it now does, and
that is what `TMsg_Scp` is.

**One smaller fact the same run turned up.** `ConState_BCasts` is set nowhere in the library outside
the `P2Pexpump` paths (`P2PeerExplorer.cpp:1379`, `P2PeerHub.cpp:1301`), so `On_P2PeerBCast`
enumerates the child connections and matches none of them until the application sets it itself. A
stock hub tree does not broadcast at all; `p2p_sealbcast` sets the bit in `On_ConLogin`, which is
what an application would have to do. That is why refusing a broadcast outright costs nothing to
anyone today, and why it is the right time to have done it.
