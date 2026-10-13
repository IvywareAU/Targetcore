# P2PeerHub notes

Companion notes for `P2PeerHub.h` / `P2PeerHub.cpp`.

## `P2Paddr m_oP2PaddrHub;`

The hub's **virtual network address** — the only identity that P2P routing acts on.
Everything about where a message goes is decided by comparing this string against the
addresses of the hub's connections.

### The type

`P2Paddr` (`P2Peer.h:220`) is a hierarchical dotted address with an optional
virtual-network qualifier:

```
[VNetname:]RootHubname.Hubname[i]. . .Hubname
```

Since 3.4.0 the `VNetname:` part means a **VNet mount**: `V:x` is the address `x` inside a
network mounted at hub `V`. See [VNet mounts](#the-vnetname-qualifier--vnet-mounts-340) below.
An address without a colon is exactly what it always was: the dotted hop path.

Underneath it is **just a string**. The constructor and `operator=` do nothing but copy
(`P2Peer.cpp:259`):

```cpp
P2Paddr::P2Paddr ( P2PaddrSTR strP2Paddr )
{   m_strP2Paddr = strP2Paddr; }
```

There is no hashing, allocation, GUID, or registry lookup involved in *forming* an
address. `T_ADDR` is `TCHAR` (UTF-16 on Windows), deliberately kept synchronised with
Msgcore's `T_NAME` (`P2Peer.h:27`).

All routing meaning lives in the dots, expressed as three predicates:

| Predicate | Source | Meaning |
|---|---|---|
| `IsChild(a)` | `P2Peer.cpp:360` | `a` is a proper descendant — prefix match **that ends on a hop boundary** (`.` or `:`), so `CEXTRA` is *not* a child of `CEX`, and `CEX:Root` is |
| `IsRable(a)` | `P2Peer.cpp:389` | `a` is routable **down** through us — equal, or the same boundary-respecting prefix |
| `IsMapped(a)` | `P2Peer.cpp:693` | `P2Padomain` wildcard/set match, used to police what a peer may claim at login |

Plus two accessors: `c_name()` = last hop (`P2Peer.cpp:458`), `c_hopname(n)` = the n-th
hop (`:470`). These two still split on `.` only, so for `H:Root.Svc` `c_name()` is `Svc` and
`c_hopname(0)` is `H:Root`.

#### The `VNetname:` qualifier — VNet mounts (3.4.0)

Until 3.4.0 the `[VNetname:]` prefix was a placeholder from the original Ivyware design: it
was in the grammar and the class layout, but no code parsed it, and a colon was silently
swallowed into the first hop's name. 3.4.0 builds it. The decision and the alternatives are
recorded in `Targetcore_ProdDocs/AddressingSchemas.md` Part 5, Stage 0.

**What it means.** `V:x` is the address `x` inside the network **mounted at the hub `V`**.
`V` is an address in this network. Only the first colon separates, as on the Java wire, so
qualifiers nest: `V:W:x` is `W:x` inside `V`'s mount.

**The address.** `P2Paddr` stores one string, `m_strP2Paddr`. The two fields that were never
set (`m_strVNetname`, `m_strVNetaddr`) are gone, so a copy cannot drop anything.

| Member | Source | What it does |
|---|---|---|
| `GetVNet()` | `P2Peer.cpp:507` | The part before the first `:`, or empty |
| `GetVNetAddr()` | `P2Peer.cpp:518` | The part after it, or the whole address when there is no qualifier |
| `HasVNet()` | `P2Peer.cpp:526` | Whether there is a `:` at all |
| `IsChild` / `IsRable` | `P2Peer.cpp:360`, `:389` | Accept `:` as a hop boundary, so `V:x` is below `V` and routes towards it with no other predicate change |

`GetVNet()` and `GetVNetAddr()` return a per-thread slot, like `c_name()`: valid until the
next few calls on the same thread.

**The mount.** A mount is a connection marked with `P2PeerCon::SetVNetMount(peerHub)`
(`P2PeerCon.cpp:2828`). It joins hub `H` in one network to hub `P` in another. Set it before
`PostP2PeerCon`, on **both** ends: a client connection, or the service whose accepted
children are mounts (`AcceptSpawn` copies it).

- **Routing.** In `RouteP2PeerMsg` (`P2PeerHub.cpp:1015`), hub `H` sends every message whose
  `GetVNet(Dst) == H` into a mount. First it tries the mount whose own address covers the
  destination, then any mount. Nothing else crosses a mount.
- **Crossing.** On the send side, before seal and attestation, `VNetMountOut`
  (`P2PeerCon.cpp:2875`) rewrites `Dst H:x → x` and `Src s → P:s`. The login and its ack are
  signed over the same rewritten addresses, so their signatures match the wire.
- **A gateway, not a pipe.** Crossing opens a body sealed into `H`'s network and drops the
  origin's relay attestation (`P2PeerMsg::ClearRelayAttest`). The next hop on the far side
  seals and attests under its own identity. **End-to-end sealing and attestation stop at a
  mount**, and the mount's hub vouches for its side.
- **Source binding.** A mount peer may present any source whose VNet is this hub, because it
  is the gateway to that whole network. Any other source is refused, as on any link.
- **Unicast only.** A broadcast or upcast copy is not carried across: its scope names a
  subtree or a chain in one network, and there is no honest rewrite of it into another.

**A colon with no mount.** `P2PeerHub(L"VNetA:Root.X")` is still a mistake. The address is
now read as "`Root.X` inside the mount at hub `VNetA`", so a message to it routes towards
`VNetA`. If `VNetA` holds no mount, it ends there as `P2Pevent_UNDELIVERABLE`. Name hubs with
dots; use a colon only to address through a mount.

**Example.** P2PeerLan L7b mounts a fixed-root app (`Root`, `Root.Echo`) under its LAN graft
`Lan.A.Plant`. From the LAN the app's hub is `Lan.A.Plant:Root.Echo`. Inside the app a LAN
peer is `Root:Lan.B.Sample.Echo`, which is where a reply goes. Tests: `p2p_vnetmount` (two
networks over DMX, auth, seal and relay auth on) and `Test_AddrVNet` in MscsUnitTests.

**Still not built:** routing several address *syntaxes* side by side in one hub (reading C in
`AddressingSchemas.md`). Interface mapping (`P2PeerIDmap_STATIC` / `_FRACTAL`,
`PerformIFaddrTransform()`) is unchanged and still refuses authentication. See
[Path 2](#path-2--negotiated-during-the-login-handshake) and practical rule 4 below.

### Where it lives

The address is stored in **two** places, and they are kept in sync by hand:

1. **The C++ object** — `P2PeerHub::m_oP2PaddrHub` (`P2PeerHub.h:587`), a public member.
2. **The runtime registry** — `P2PmsgHubMgr::m_oP2Paddr` (`P2Pwin32.cpp:688`), the
   pump-side hub record, reachable from anywhere via `Get/SetP2PmsgHubAddr(nHubID, …)`
   (`P2Pwin32.cpp:2198` / `:2164`).

The registry is keyed by `P2PmsgHubID`, and that ID **is the Win32 thread id** — the
`P2PmsgHubMgr` constructor stamps it and self-registers (`P2Pwin32.cpp:892`):

```cpp
m_nHubID = GetCurrentThreadId();
s_ThreadID_P2PmsgHub.SetAt ( m_nHubID, this );
```

Hence the header's rule that "hubs exist in the context of the thread under which they
are created" (`P2PeerHub.h:57`) — hub identity *is* thread identity. See ADR-0004.

### How the address is assigned

Two paths. The constructor comment states both up front (`P2PeerHub.cpp:85-91`): the
address may be `NULL`, "in which case P2Paddress is negotiated and allocated as part of
a connection login sequence."

#### Path 1 — static, from the application (the normal case)

**Step 1 — construction.** `P2PeerHub::P2PeerHub(P2PaddrSTR)` (`P2PeerHub.cpp:93`)
calls `SetP2PaddrHub()`, which copies into `m_oP2PaddrHub`. At this point the address
exists only on the C++ object; `m_nHubID` is still `0` (`RenderHubSafe`, `:105`) and the
P2P runtime knows nothing about it.

**Step 2 — registration.** The address becomes *real* when a pump is created, by one of
two routes:

- **`SpawnHub()`** (`P2PeerHub.cpp:178`) — copies `m_oP2PaddrHub` into a `P2ProcContext`
  **before** the thread starts (`:162`), calls `CreateThread(…, &m_nHubID)` so Win32
  writes the new thread's id straight into the member, then spin-waits on
  `P2PmsgHubExists()` until the pump confirms itself live. The new thread's `ProcHub()`
  does the actual registration (`:332`):

  ```cpp
  CreateP2PmsgHub ( oP2Paddr, pHub, nPumpsMax, 8 );
  ```

- **`CreateHub(strAddr, nPumpsMax)`** (`P2PeerHub.cpp:287`) — runs in the *calling*
  thread. Note it **re-assigns the member directly**, bypassing `SetP2PaddrHub()`:

  ```cpp
  ASSERT(m_nHubID == 0 );
  m_oP2PaddrHub = strP2PaddrHub;
  m_nHubID = CreateP2PmsgHub ( strP2PaddrHub, this, nPumpsMax, 1 );
  ```

  That is safe only because the hub is not yet live (nothing to sync to). It also means
  `CreateHub` can silently **override** whatever the constructor was given.

**Step 3 — the registry entry.** `CreateP2PmsgHub()` (`P2Pwin32.cpp:1949`) builds the
`P2PmsgHubMgr`, stores the address, and derives the pump's display name from the last
hop (`:1768`, `:1780`):

```cpp
spHubMgr -> m_oP2Paddr = strP2Paddr;
spHubMgr -> m_pHub     = pHub;
...
pP2PmsgPump -> m_csName = spHubMgr -> m_oP2Paddr.c_name();
```

#### Path 2 — negotiated during the login handshake

Used when the hub is constructed with a null/empty address (console connections,
server-allocated clients).

1. **Client sends its claim.** `P2PeerCon::Login()` posts a `P2Pmsg_Login` whose
   *source* is the local hub address (`P2PeerCon.cpp:3555`).
2. **Server validates it.** `P2PeerCon::OnLogin()` (`:1827`) rejects a null address, then
   checks the claim against the connection's `P2Padomain` (`:1877`). Note the guard: the
   domain check is only enforced when a domain is actually configured — an empty
   `m_oP2Padomain` means *no restriction*.
3. **Server answers.** `P2PeerCon::LoginAck(oThatP2Paddr, …)` (`:1920`) may assign an
   address to the peer ("such P2Paddr's may be auto-assigned from the domain").
4. **Client adopts it.** `P2PeerCon::OnLoginAck()` (`:2017`) performs the actual write
   into the hub (`:2078`):

   ```cpp
   if ( !oThisP2Paddr.IsNull() )
     m_pP2PeerTarget -> GetP2PeerHub() -> SetP2PaddrHub ( oThisP2Paddr );
   ```

Two guards bound this. It throws if the assigned *and* local addresses are both null,
and it throws on any attempt to **change** an address that is already set:

```
"Attempt to swap P2Paddr's from [%s] to [%s]"
```

So login negotiation can only **fill a blank** — it can never re-address a hub that
already knows who it is. `P2PeerCon::SetP2Paddr()` (`:2965`) is the same move for the
dynamic/console case.

**The `P2PeerIDmap_e` variants do not touch the hub address.**
`OnLoginAck_Static` (`:2111`) and `OnLoginAck_Fractal` (`:2191`) store an address
*pair* — `m_oThisP2Paddr1` / `m_oThatP2Paddr1` — which is substituted into message
source/destination on send and receive. That lets a hub present a different identity
inside a foreign virtual network whose topology it has no knowledge of, while its own
`m_oP2PaddrHub` is untouched. Only the `P2PeerIDmap_NONE` path reaches
`SetP2PaddrHub`.

### Lifecycle role

`SetP2PaddrHub()` (`P2PeerHub.cpp:1052`) keeps both copies coherent under
`m_oCSectionHub`, pushing to the registry **only if the hub is live**:

```cpp
P2PsafeCS oSafeCS = m_oCSectionHub;
if ( m_nHubID )
  SetP2PmsgHubAddr ( m_nHubID, strP2PaddrHub );
m_oP2PaddrHub = strP2PaddrHub;
```

`GetP2PaddrHub()` (`:889`) does the reverse repair — if the object's copy is empty but a
hub id exists, it back-fills from the registry:

```cpp
if ( m_pTargetParent )
  return GetP2PeerHub()->GetP2PaddrHub();
if ( m_nHubID > 0 && m_oP2PaddrHub.IsEmpty() )
{
  P2PsafeCS oSafeCS = m_oCSectionHub;
  m_oP2PaddrHub = GetP2PmsgHubAddr ( m_nHubID );
}
```

On teardown the address is *not* explicitly cleared: the pump stores `m_nHubID = 0` as
the closure flag (`ProcHub`, `:335`) and `~P2PmsgHubMgr` removes the registry entry
(`P2Pwin32.cpp:908`). `m_oP2PaddrHub` survives, so a closed hub can be re-`SpawnHub`'d
under the same address.

### What it is for

**Routing — this is the whole point.** `P2PeerHub::RouteP2PeerMsg()`
(`P2PeerHub.cpp:867`) enumerates the hub's connections and picks a hop purely by
comparing addresses:

```cpp
// Immediate
if ( oP2PaddrCon == pP2PaddrMsg )                      return P2PeerContextSwap(pCon,pMsg);
// Children — con is our network child, msg routable down through it
if ( m_oP2PaddrHub.IsChild(oP2PaddrCon) &&
       oP2PaddrCon.IsRable(pP2PaddrMsg)    )            return P2PeerContextSwap(pCon,pMsg);
// Parent — con is our network parent, msg not routable down through us
if (    oP2PaddrCon.IsChild(m_oP2PaddrHub) &&
     !m_oP2PaddrHub.IsRable(pP2PaddrMsg)      )         return P2PeerContextSwap(pCon,pMsg);
```

`SERVICE` (listener) connections are skipped; anything unmatched falls through to
undeliverable. There are **no routing tables** — the address relationship *is* the
routing input (ADR-0003).

**Message provenance.** Every outgoing message stamps it as the source, e.g.
`new P2PeerMsg32(GetP2PaddrHub(), peerAddr, P2Pmsg_BCast, …)` (`examples.md:102`).

**Diagnostics.** The pump's display name is the last hop (`P2Pwin32.cpp:2010`), and
`GetP2PmsgHubAddr(pCon)` (`:2032`) resolves a connection back to its owning hub's
address for logging.

### Worth noting

- **Sub-targets have no address of their own.** `P2PeerTarget::GetP2PaddrHub()`
  (`P2PeerTarget.cpp:2303`) just walks `m_pTargetParent` upward, throwing
  *"No linked P2PeerHub"* if the chain is unterminated. `P2PeerHub`'s override begins
  with the same delegation, so even a hub nested under another target reports the
  **owning** hub's address. This is what the header means by "P2Paddresses are only ever
  assigned to objects derived from this class" (`P2PeerHub.cpp:87`).

- **Two different `GetP2PaddrHub()`s.** `P2PeerHub::GetP2PaddrHub()` returns
  `const P2Paddr&` — a reference to the live member. `P2PeerCon::GetP2PaddrHub()`
  (`P2PeerCon.cpp:4841`) returns a `P2Paddr` **by value**, rebuilt from the registry on
  every call, and yields an empty address when the connection is unregistered
  (`m_nP2PconID == 0`). Same name, different ownership and different cost.

- **`c_name()` / `c_hopname()` return a pointer into a per-THREAD scratch ring.** This
  paragraph used to say they `const_cast` away constness to rebuild the object's own
  `m_strHubname` in place, with a tautological `ASSERT(strHubname==m_strHubname)` behind it.
  **That is no longer true and the change is the interesting part:** the per-object scratch
  was a data race — one `P2Paddr` read by two threads, the build clearing and appending one
  character at a time, so a concurrent reader saw a half-built name, and this was reached in
  practice because `GetP2PmsgHubName()` hands back `c_name()` off the process-wide hub record
  and every pump thread calls it. Both accessors now build into a local and hand back a slot
  of an eight-deep `thread_local` ring (`P2PaddrNameSlot`, `P2Peer.cpp:415-425`; the accessors
  themselves at `:436` and `:448`), and `m_strHubname` is gone from the class. The lifetime
  rule is therefore the one the tree already states for wide accessors — **valid until the
  next few calls on this thread**, not on this object — and the slots are
  `std::basic_string`, not `CString`, because a `thread_local` array of `CString` handed back
  a dangling pointer on the first case tried. Copy the result if you intend to keep it.

- **The C ABI's `get_address` returns only the last hop.** `p2peerhub_get_address()`
  (`Targetcore_c.cpp:990`) is implemented as `GetP2PaddrHub().c_name()`, so a hub at
  `MyApp.Region.Server` reports `Server`. Use the full address if you need to route with
  it.

- **Mis-set addresses fail silently as undeliverable.** Because routing has no table to
  disagree with, a typo in a hub address does not error at creation — messages simply
  reach the end of `RouteP2PeerMsg` and become `P2Pevent_UNDELIVERABLE` (and only when
  `uiCtrl.EXCEPTIONS` is set).

- **`operator LPCTADDR` was a Linux-port landmine.** It now casts both `?:` branches to
  `LPCTADDR` explicitly (`P2Peer.cpp:286-294`); the older form materialised a temporary
  `CString`, which MFC's ref-counted `CString` tolerated but the `std::wstring`-backed
  Linux shim did not — it returned a pointer into a freed block.

---

## Topology mismatch — physical links vs. the address tree

Addresses are assigned by the application (`P2PeerHub(L"MyApp.Server")`), while the link
graph is whatever you happened to `Connect()`. **Nothing reconciles the two.** This
section is what happens when they disagree.

### The invariant nobody checks

`RouteP2PeerMsg` (`P2PeerHub.cpp:867-916`) evaluates three addresses per connection —
`H` = this hub, `C` = the connection's peer address, `D` = the message destination:

| Rule | Condition | Meaning |
|---|---|---|
| Immediate | `C == D` | the peer **is** the target |
| Down | `H.IsChild(C) && C.IsRable(D)` | C is my descendant **and** D is at-or-below C |
| Up | `C.IsChild(H) && !H.IsRable(D)` | C is my ancestor **and** D is not in my subtree |
| — | otherwise | `P2PeerTarget::RouteP2PeerMsg` → `P2Pevent_UNDELIVERABLE` (`P2PeerTarget.cpp:1549`) |

The physical graph contributes exactly one thing: **which connections exist to iterate
over**. `C` is whatever the peer *claimed at login* (`pCon->GetP2Paddress()`), and
`OnLogin()` validates that claim only against a `P2Padomain`, and only when one is
configured (`P2PeerCon.cpp:3701`). It never checks that the peer is your parent or your
child.

**Consequence:** a physically-wrong topology connects, logs in, and looks healthy. The
mismatch surfaces later as messages that quietly fail to route — not as a startup error.

### Case by case

**Sibling link — the common surprise.** `H = "App.A"` physically connected to
`C = "App.B"`:

- `D = "App.B"` → **Immediate matches; works.** You can talk to your sibling.
- `D = "App.B.X"` → not immediate; `H.IsChild("App.B")` false; `"App.B".IsChild("App.A")`
  false → **undeliverable**.

A sibling link is a **dead end**: point-to-point works, transit never does. Two hubs
happily exchanging messages is therefore *no evidence* that the topology is right.

**Peer claims a subtree it cannot serve.** `H = "Root"`, connection to `C = "Root.X"`,
but X has no further links. `D = "Root.X.Y"` matches Down at Root and is forwarded. X
then evaluates it: `H'.IsRable("Root.X.Y")` is **true**, so X's Up rule is blocked by
`!IsRable` — it does not bounce back. The message dies at X with
`P2Pevent_UNDELIVERABLE`, whose `ExceptionFactory` message routes back toward the source
**only if `uiCtrl.EXCEPTIONS` is set**. The failure is reported one hop away from the
misconfiguration, or not at all.

**No parent link.** A hub holding only child connections can reach its own subtree and
nothing else — the Up rule finds no candidate, so anything outside is immediately
undeliverable.

**Skip-level links are fine.** Despite the doc comment saying "direct child", `IsChild`
only requires the prefix to end on a `.` boundary (`P2Peer.cpp:347`), so `"A.B.C"` *is* a
child of `"A"`. A grandparent↔grandchild socket with no intermediate hub routes
correctly both ways.

### Two asymmetries that bite

**Broadcast and unicast disagree about siblings.** `On_P2PeerBCast` (`P2PeerHub.cpp:1390`)
filters on ancestry *only* — there is no Immediate escape hatch:

```cpp
if ( !m_oP2PaddrHub.IsChild(oP2PaddrCon) ||
     !pCon->HasState ( ConBCasts_OK )       )
  continue;
```

`On_P2PeerUCast` does the mirror image toward ancestors (`:1274`). So over a sibling
link **unicast is delivered and broadcast is silently dropped** — no event, no log, just
`continue`. (`ConBCasts_OK` = `Send|Login|BCasts`, `P2PeerCon.h:747`.)

**Ambiguity resolves by list order.** Each rule `return`s on the first matching
connection, and `EnumP2PmsgCon` walks the hub's `CList` in insertion order. Two
connections matching the same `D` — a duplicate link, or two peers with overlapping
claimed addresses — means the first-registered one silently wins for unicast, while BCast
sends to **both** (duplicate delivery over a diamond).

### Why routing loops cannot happen — and why there is no TTL

Prefix-ancestry is antisymmetric and acyclic on strings: Up strictly shortens toward the
root, Down strictly lengthens toward `D`, and a hub that sent a message Up cannot receive
it back Down (the `!H.IsRable(D)` that justified Up is exactly what blocks the reverse
Down at the next node). The addressing scheme is its own loop guard, which is why
**Targetcore carries no TTL or hop count** — there is none in the C++ core. The TTL
(default 16) described in `../P2P_architecture.md` belongs to the Java `P2PeerHub` layer,
which routes over a graph that is not guaranteed to be a tree.

A diamond still causes **duplicate delivery**, though — that is not a loop and nothing
suppresses it.

### Practical rules

1. **Make the address tree mirror the link graph.** Every connection should join an
   ancestor to a descendant. That is the invariant the whole router assumes and never
   verifies.
2. **Enforce it at the door.** Set a `P2Padomain` on the listener so `OnLogin` rejects
   peers claiming addresses outside the expected subtree — the only built-in place a
   topology error can be caught early.
3. **Monitor `P2Pevent_UNDELIVERABLE`.** With no routing tables and no validation it is
   the only signal that an address is wrong; confirm `uiCtrl.EXCEPTIONS` is on.
4. **For genuinely disjoint trees, use the interface mapping.** `P2PeerIDmap_STATIC` /
   `_FRACTAL` exist precisely for a link joining two networks whose address trees do not
   align: `PerformIFaddrTransform()` (`P2PeerCon.cpp:4387`) rewrites source/destination at
   the boundary so each side sees addresses from its own tree. That is the sanctioned way
   to bridge a mismatch, rather than giving a hub an address that lies about where it
   sits.

> Dead code seen while reading this path: `P2PeerHub.cpp:1387-1389` has an
> `if ( … ) pCon=pCon;` no-op immediately above the BCast filter — a leftover debug
> breakpoint hook. Harmless.

---

## See also

- `P2PeerCon.md` — companion notes for the connection object (`m_pP2Props`,
  `m_nP2PconID`).
- `Readme.md` — IOCP architecture, connection-handshake regressions, multi-connection
  hub tests.
- `examples.md` — runnable hub/connection walkthroughs for WSA and named pipes.
- `../P2P_architecture.md` §"Routing model in brief" — the same addressing model as
  realised in the Java kernel.
- `../_reversa_sdd/adrs/0003-hierarchical-virtual-address-routing.md` (addressing as a
  design decision) and `0004-hub-per-thread-concurrency.md` (hub id = thread id).
- `../_reversa_sdd/user-stories/connection-login-handshake.md` §A6 — the negotiated path
  as a behavioural spec, including the `P2PeerIDmap_e` styles and the
  `PerformIFaddrTransform()` send/recv substitution.
