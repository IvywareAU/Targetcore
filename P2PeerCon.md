# P2PeerCon notes

Companion notes for `P2PeerCon.h` / `P2PeerCon.cpp`.

## `P3PmsgItem *m_pP2Props;`

A **lazily-allocated, per-connection property tree** — a general-purpose bag of
structured, named, typed properties that a connection object can carry.

### The type

`P3PmsgItem` is just a typedef for `P3PmsgField` (`Msgcore\P2Pmsg.h`):

```cpp
typedef P3PmsgField P3PmsgItem;
```

`P3PmsgField` is the Msgcore hierarchical property-tree node — the same object
model that exposes `r_Desc()` (child/descendant collection), `GetP2Pos()`, typed
data slots, etc. It is exactly the node type the property grid
(`CP2PropertiesWnd` / `CMFCPropertyGridCtrl`) and the design tree bind to and
render as editable rows. So `m_pP2Props` is the **root of a property sub-tree**
attached to the connection.

### Where it lives

It is a member of `P2PeerConPlc` — the ref-counted, destroy-managed base class of
`P2PeerCon` (`P2PeerCon.h:122`). Every connection therefore inherits one.

### Lifecycle (`P2PeerCon.cpp`)

- **ctor** (`~3160`): `m_pP2Props = 0;` — starts null.
- **accessor** (`~3214`): `GetP2Props()` lazily creates it on first use and
  returns a reference:

  ```cpp
  P3PmsgItem& P2PeerConPlc::GetP2Props ( )
  {
      if ( m_pP2Props == 0 )
        m_pP2Props = new P3PmsgItem ( );
      return *m_pP2Props;
  }
  ```

- **dtor** (`~3166`): `delete m_pP2Props;` — owned by the connection, freed with it.

### What it is for

It lets kernel or application code hang arbitrary structured metadata/state off an
individual `P2PeerCon` using the standard P3Pmsg tree machinery — connection-scoped
properties that travel with the connection object but are **not** part of the wire
protocol. The raw member is `protected`, and access is the pointer-hiding,
allocate-on-demand `GetP2Props()`.

### Worth noting

- `GetP2Props()` has **no callers inside the MSCS repo itself** (only the
  declaration and definition). It is a pure **extension point**: the library
  exposes it so consumers can annotate connections with their own property trees;
  the kernel just provides storage, lifetime management, and lazy allocation.
- Because this is a `P3PmsgField` tree, set it up / attach children **in place**
  via the returned reference. Copying a `P3PmsgField` detaches it (bogus stack
  `GetP2Pos()`, dropped descendants).

## `P2PconID GetP2PconID() const;` / `P2PconID m_nP2PconID;`

The connection's **hub-scoped identity handle** — the token by which a hub (and the
P2PeerExplorer query/registration protocol) addresses one specific connection among
its collection, and whose zero / non-zero state gates the connection's
registered-vs-destroyable lifecycle.

### The type

`P2PconID` is a typedef for `DWORD_PTR` (`P2Peer.h:35`):

```cpp
typedef DWORD_PTR      P2PconID;       // P2PeerCon identification
```

### Where it lives

`m_nP2PconID` is a member of `P2PeerConPlc` — the ref-counted, destroy-managed base
class of `P2PeerCon` (`P2PeerCon.h:95`) — so every connection inherits one. The
accessor is `const` and **asserts the ID is non-zero** (`P2PeerCon.cpp:5227`):

```cpp
P2PconID P2PeerConPlc::GetP2PconID ( ) const
{
    ASSERT(m_nP2PconID);   // must already be registered on a hub
    return m_nP2PconID;
}
```

### How the ID is assigned

The value is **not** a counter — it is the MFC `CList` `POSITION` at which the hub
stores the connection. When a hub registers a connection (`P2Pwin32.cpp`,
`PostP2PmsgCon` / `PostP2PexpCon`):

```cpp
m_oCListP2PmsgCon.AddTail ( pCon );
pCon -> m_nP2PconID = (P2PconID)m_oCListP2PmsgCon.GetTailPosition();
```

So the ID is the stable, unique-per-hub node cookie into the connection list for as
long as the connection stays a member. When the hub drops it
(`DropP2PmsgCon` / `DropP2PexpCon`), the ID is reset to `0`.

### Lifecycle role

- **ctor** (`P2PeerCon.cpp:5161`): `m_nP2PconID = 0;` — unregistered.
- **register / drop**: set to the list `POSITION` on `PostP2P*Con`, back to `0` on
  `DropP2P*Con` (`P2Pwin32.cpp`).
- **`Release()`** (`P2PeerConPlc::Release`, `P2PeerCon.cpp:5178`):

  ```cpp
  int cRef = --m_cRef;                       // :5185
  if ( cRef <= 0 && m_nP2PconID == 0 )       // :5187
    Destroy ( );
  ```

  A connection that has been dropped from its hub (`ID == 0`) **and** has no
  outstanding references self-destructs. A non-zero ID keeps the connection
  "registered / alive"; zeroing it on drop is part of teardown.

### What it is for

- **Targeted signalling.** `P2PeerHub::ConSignal(P2PconID nConID, ...)`
  (`P2PeerHub.cpp:756`) enumerates the hub's connections and delivers an async
  signal only to the one whose `m_nP2PconID` matches — `nConID == 0` means
  "broadcast to all connections":

  ```cpp
  if ( nConID && nConID != pConEnum->m_nP2PconID )
    continue;                      // skip everything but the addressed connection
  ```

- **Explorer register / query protocol.** The ID is serialised into P3Pmsg property
  trees as `ConID` / `m_nP2PconID` and carried on `QCon@ID` / `RCon@ID` / `DCon@ID`
  qualifiers so `P2PeerExplorer` can register, look up, and deregister remote
  connections by handle (`P2PeerExplorer.cpp`, `P2Pwin32.cpp:1766`).

- **Diagnostics.** Rendered compactly as `%04x` in connection dumps
  (`P2Pwin32.cpp:1668`).

### Worth noting

- Because the ID **is** a `CList POSITION`, it is only meaningful within the hub
  that assigned it, and only while the connection remains in that list. Treat it as
  an opaque handle, not a stable global identifier or an index.
- Call `GetP2PconID()` **only on a registered connection** — the `ASSERT(m_nP2PconID)`
  fires if the connection has never been posted to a hub or has already been dropped.
