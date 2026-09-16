# Targetcore — I/O Completion Port (IOCP) Architecture

This document traces how the Targetcore messaging kernel uses **Windows I/O Completion
Ports** to drive all asynchronous socket, pipe and serial I/O. It walks the complete
lifecycle of a single I/O completion, end to end, with references to the actual source
(`file:line`).

> Terminology note: this is the Windows *completion port* (IOCP) mechanism — the async I/O
> facility behind `CreateIoCompletionPort` / `GetQueuedCompletionStatus`. The codebase names
> everything with a `CPort` / `IOCP` prefix.

---

## Cast of objects

| Object | Where | Role |
|--------|-------|------|
| `P2PmsgPump` | `P2Pwin32.cpp` | One per pump thread. Owns the IOCP handle `m_hIOCP` and a FIFO message queue. |
| `P2PeerCon` | `P2PeerCon.cpp` / `.h` | One per connection. Owns a copy of the pump's port (`m_hCPort`), its file/socket association (`m_hFileCPort`), a completion key (`m_dwCompletionKey`), and four `OVERLAPPEDcon` slots. |
| `OVERLAPPEDcon` | extended `OVERLAPPED` | Carries `pBuffer`, `hr`, `nSigID`, `bQueued` alongside the OS `OVERLAPPED` struct. |

### Key `P2PeerCon` members (`P2PeerCon.h:510-530`)

| Member | Meaning |
|--------|---------|
| `m_hCPort` (`HANDLE`) | the shared IOCP handle (copied from the owning pump) |
| `m_hFileCPort` (`HANDLE`) | handle returned when the file/socket is associated with the IOCP |
| `m_dwCompletionKey` (`UINT_PTR`) | the completion key — set to `(UINT_PTR)this` |
| `m_hCPortP2PumpID` (`DWORD`) | id (thread id) of the pump that owns this connection |
| `m_pOVERLAPPEDsend/recv/accept/connect` | the four per-operation OVERLAPPED slots |

---

## Lifecycle of one completion

### 0. Port creation — once per pump thread
`P2Pwin32.cpp:2012` (also `1210`, `4761`)

```c
pP2PmsgPump->m_hIOCP =
    CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, nNumberOfConcurrentThreads);
```

A bare completion port with no file attached yet. `nNumberOfConcurrentThreads` caps how many
threads the OS lets run completions concurrently. Each pump thread has its own port.

### 1. Association — when a connection is established
`P2PeerCon::CreateIOCP()` — `P2PeerCon.cpp:474`

```c
m_hFileCPort = CreateIoCompletionPort(m_hFile, m_hCPort, m_dwCompletionKey, 0);
```

The connection's socket/file (`m_hFile`) is bound to the pump's port (`m_hCPort`). **The
completion key is the connection pointer itself** — `m_dwCompletionKey = (UINT_PTR)this`
(`P2PeerCon.cpp:212`). This is the trick that lets the pump route a raw completion straight
back to the right object. Called on accept (`P2PeerCon.cpp:2036`), connect (`2094`), etc.

### 2. Issuing an I/O — posting an OVERLAPPED
Two ways an operation gets queued:

- **Real socket I/O** — the WSA variant issues `WSARecv` / `WSASend` / `AcceptEx` with an
  `OVERLAPPEDcon*`.
- **Self-posted work** — via `PostOVERLAPPED()` / `Signal()` (`P2PeerCon.cpp:1192`, `1318`):

```c
prepareOVERLAPPED(pOVERLAPPEDcon);                 // bQueued=true, AddRef()
PostQueuedCompletionStatus(m_hCPort, 0, m_dwCompletionKey, (OVERLAPPED*)pOVERLAPPEDcon);
```

`prepareOVERLAPPED` (`P2PeerCon.cpp:1215`) marks the buffer in-flight (`bQueued=true`) and
**`AddRef()`s the connection** — keeping the object alive while the OS holds the pointer.

### 3. Dequeue — the pump loop pulls the completion
`PumpP2Pmsg()` Step 3 — `P2Pwin32.cpp:5095` (a second loop exists at `2791`)

```c
GetQueuedCompletionStatus(pP2PmsgPump->m_hIOCP, &dwBytes,
                          &ulCompletionKey, &pOVERLAPPED, dwTimeout);
```

When any I/O on any associated socket finishes (or someone `PostQueuedCompletionStatus`'d),
this returns three things: bytes transferred, the completion key, and the OVERLAPPED pointer.

### 4. Route back to the connection
`P2Pwin32.cpp:5103-5123`

```c
OVERLAPPEDcon *pOVERLAPPEDcon = (OVERLAPPEDcon*)pOVERLAPPED;
P2PeerCon     *pCon           = (P2PeerCon*)ulCompletionKey;   // key IS the object
pCon->m_hCPortP2PumpID = pP2PmsgPump->m_nThreadId;             // remember which pump owns it
if (pP2PmsgPump->m_hIOCP && !pCon->m_hCPort)
    pCon->m_hCPort = pP2PmsgPump->m_hIOCP;                     // lazy back-link
pCon->AddRef();
try   { pCon->On_QueuedCompletionStatus(0, dwBytes, pOVERLAPPEDcon); }
catch (P2Pevent *pEVT) { pCon->Drop(pEVT->Isolate()); }        // any failure → drop connection
pCon->Release();
```

The key cast recovers the exact `P2PeerCon`. The whole dispatch is wrapped so any thrown
`P2Pevent` (the code signals errors by *throwing*, not returning) tears the connection down
cleanly.

### 5. Classify the completion — `P2PeerCon::On_QueuedCompletionStatus()`
`P2PeerCon.cpp:519`

The connection figures out *which* operation completed by pointer-identity against its four
OVERLAPPED slots:

| Matches | Handling | Line |
|---------|----------|------|
| `m_pOVERLAPPEDrecv` | parse received bytes into messages | `345` |
| `m_pOVERLAPPEDsend` | send confirmed → send next | `413` |
| `m_pOVERLAPPEDaccept` | new inbound connection | `477` |
| `m_pOVERLAPPEDconnect` | outbound connect done | `540` |

Every branch first calls `releaseOVERLAPPED()` (`bQueued=false` + `Release()` — the matching
un-ref for step 2's `AddRef`), then splits three ways on `hr`:

- **Success** (`hr==S_OK && m_hFileCPort`) — do the real work.
- **Failure** (`hr && m_hFileCPort`) — `Throw()` → caught in step 4 → connection dropped.
- **Cancellation** (else — port was closed) — `DropOVERLAPPED()` frees the buffer and nulls
  the slot.

Derived types (`P2PeerConWsa`, `P2PeerConDmx`, `P2PeerConPipe`, `P2PeerCon232`) override this
to handle their transport-specific accept/connect, then delegate the recv/send cases back to
the base via `P2PeerCon::On_QueuedCompletionStatus(...)` (e.g. `P2PeerConWsa.cpp:445`).

### 6. The recv success path in detail
`P2PeerCon.cpp:585-618`

```c
pOVERLAPPEDcon->dwBytes += dwBytes;
while (!HoldRecvForBackpressure() &&
       (pMsg = m_pP2Peerio->RecvP2PeerMsg(m_hFile, pOVERLAPPEDcon)) != NULL) {
    if (m_eP2PeerIDmap) PerformIFaddrTransform(true, pMsg);
    PostP2Pmsg(..., this, pMsg, m_hCPortP2PumpID);   // hand the message to the pump's FIFO
}
```

One receive buffer may hold several framed messages, so it loops to completion. Each parsed
`P2PeerMsg` is turned into a `P2Pmsg` and posted (with `m_hCPortP2PumpID` = the owning pump)
into the pump's message queue, where Step 2 of `PumpP2Pmsg` (`DispatchP2Pmsg`) later runs the
app's `CN_P2PeerMsg` / `P2P_Login` handlers. Logins/acks get special-cased.

**Note where the next read comes from.** There is no separate re-arm step: `RecvP2PeerMsg()`
*is* what issues the next `Recv()`, so the loop keeps the connection fed by asking again, and
the cycle returns to step 2.

#### 6a. Backpressure — the read is withheld by not asking

`HoldRecvForBackpressure()` in the loop **condition** is the whole of the inbound brake.
Because asking is what arms the read, *declining to ask*
leaves no read outstanding: the socket buffer fills, the TCP window closes, and the peer is
throttled by the transport rather than by an exception thrown at it. Nothing is discarded and
nothing is refused — the bytes stay where they are until this connection asks again.

- It is in the **condition** and not at the bottom of the body, because the process message
  budget can already be at its mark when the completion arrives, and the right number of
  messages to take off the peer then is none.
- The trigger is the process-wide live-`P2Pmsg` budget, at **37500** of `s_cP2PmsgMAX`'s 50000,
  releasing at **25000**. Two marks, so a connection cannot resume and re-hold on consecutive
  completions.
- The resume is a **poll**, not an event: the message that relieves the budget is released on
  some other pump and knows nothing about which connections are waiting on it. A held connection
  arms `m_uThrottleTimerID` every `DEF_P2PeerConThrottlePoll` (100 ms) until relieved, then
  calls `RearmRecv()`.
- `RearmRecv()` posts `m_pOVERLAPPEDrecv` with `PostQueuedCompletionStatus` — it **arms** a read
  rather than performing one, exactly as the initial post in `Accept()`/`OnConnect()` does, and
  the completion re-enters this handler. It is deliberately **not** `PostOVERLAPPED()`; see the
  rough edge below.

### 7. Fallthrough dispatch
`P2PeerCon.cpp:1049-1064`

If the OVERLAPPED matches none of the four slots, it's treated as a signal (`nSigID` — CLOSE,
SHUTDOWN, DESTROY, etc., handled at `615-663`) or delegated to
`m_pP2Peerio->On_QueuedCompletionStatus(...)` (`671`); anything still unhandled throws
"Unhandled OVERLAPPEDcon object".

---

## One-line summary

Completion key = the `this` pointer of the `P2PeerCon`; the OVERLAPPED pointer = which of the
four operations finished. The pump thread blocks in `GetQueuedCompletionStatus`, casts the key
back to the connection, and calls `On_QueuedCompletionStatus`, which matches the OVERLAPPED
against its send/recv/accept/connect slots and either advances the protocol or throws to drop
the connection. Reference-counting (`AddRef`/`Release` around both the post and the dispatch)
keeps the object alive across the async gap.

---

## Where the completion port is used (index)

| Concern | Location |
|---------|----------|
| Port creation (`CreateIoCompletionPort`) | `P2Pwin32.cpp:1210`, `2012`, `4761` |
| Pump wait loop (`GetQueuedCompletionStatus`) | `P2Pwin32.cpp:2791`, `5095` |
| Dispatch to connection (`On_QueuedCompletionStatus`) | `P2Pwin32.cpp:5112` |
| Socket/file association (`CreateIOCP`) | `P2PeerCon.cpp:459-483`; callers `2036`, `2094` |
| Completion key = `this` | `P2PeerCon.cpp:212` |
| Completion handler (base) | `P2PeerCon.cpp:519` |
| Manual post (`PostQueuedCompletionStatus`) | `P2PeerCon.cpp:1192`, `1318`; `P2PeerCon232.cpp:644`; `P2Pwin32.cpp:593` |
| OVERLAPPED alloc/free | `MakeOVERLAPPED` `P2PeerCon.cpp:1085`; `DropOVERLAPPED` `1116` |
| Ref-count guards | `prepareOVERLAPPED` `P2PeerCon.cpp:1215`; `releaseOVERLAPPED` `1234` |
| Transport overrides | `P2PeerConWsa.cpp:314`, `P2PeerConDmx.cpp:301`, `P2PeerConPipe.cpp:173`, `P2PeerCon232.cpp:202` |

---

## Known rough edges

- ~~**`Sleep(500)` timing hack** in `PostOVERLAPPED` for the already-queued case~~ —
  **removed (2026-07-10)**. The already-queued state is a double-post bug upstream,
  not a race; the existing `ASSERT(!bQueued)` + `Throw("buffer locked")` guard now
  enforces the invariant loudly instead of sleeping 500 ms and force-clearing the
  flag (which stomped the still-live completion and did not compile out in Release).
- ~~**`Signal(P2PsigCon_RECV)` restarts message receipt**~~ — it did not, and could not, on any
  connection that had ever received one. **Fixed 2026-08-19** by routing it through the new
  `P2PeerCon::RearmRecv()`. The signal went through `PostOVERLAPPED()`, whose "Corrupted
  OVERLAPPEDcon configuration" guard refuses a buffer with `dwBytesMax > 0` and a null
  `pBuffer` — which is the **permanent** state of a recv buffer that has received anything,
  because `P2Peerio::RecvP2PeerMsg`'s stage 0 moves the connection onto its own
  `pUserDB1`/`pUserDB2` pair on the first call and frees `pBuffer`. The guard is right for a
  buffer the transport is about to fill; it is simply not this one. **Nothing in the tree had
  ever signalled RECV**, so the trap sat unexercised from the import until the first code that
  needed it — Stage 4 step 12's backpressure resume — threw out of it on its first armed run.
  Worth reading as a pattern rather than an incident: a facility with no caller is not a
  facility, it is an untested claim.
- The serial-port variant (`P2PeerCon232.cpp:421-501`) has its IOCP-association code
  **commented out**; that path currently relies only on `PostQueuedCompletionStatus`.

---

# Connection-handshake regressions & fixes (2026-07-02)

This section documents four latent regressions in `Targetcore` that, together, broke the
**entire connection lifecycle on every transport** (WSA sockets *and* named pipes) in the
current build. Symptomatically a connection would abort at dispatch, or a hub would never
listen, or the login message would be rejected, or the first already-buffered application
message would drop the connection. None of the bugs were transport-specific — they all live
in the shared dispatch / connection / I/O-framing code.

After the four fixes below, both reference harnesses pass end to end:

- **`../MSCS/AlexTest`** — WSA sockets, two processes (server + client over `127.0.0.1:7777`):
  client posts a BCast, server receives it.
- **`../MSCS/PipeMeshTest`** — a named pipe, **single process**, two `P2PeerHub`s each on its
  own `SpawnHub()` thread: full `On_ConLoginAck` handshake **and** `On_P2PeerBCast` delivery
  in one process (proves a real MSCS hub↔hub connection can run over a pipe in-process).

## How the bugs were found

Each fix was isolated by runtime bisection, not static reading, because the failures were
silent (connections dropped via caught `P2Pevent` exceptions, not asserts). Two aids:

1. **A DBWIN (`OutputDebugString`) listener** capturing all debug output from the running
   `.exe`s. Temporary `OutputDebugStringW` probes were injected at `P2PeerCon::Drop` (to log
   the precipitating event's module/HRESULT/message), at the pump's `catch(P2Pevent*)`, and in
   `P2Peerio::RecvP2PeerMsg` (to log recv sizes/handles), plus a `dbghelp` stack backtrace on
   deliberate closes. **All of these probes were reverted after diagnosis** — only the four
   real fixes below remain in the tree.
2. **A `_CrtSetReportHook` assert trap** temporarily added to `AlexTest` so a headless run
   recorded the exact `file:line` of any assertion instead of popping a modal dialog. Also
   reverted.

The four bugs sit in series along the connection lifecycle, so they were found and fixed in
the order a connection hits them:

```
dispatch  ─▶  listen  ─▶  login (buffer)  ─▶  post-login recv (sync ReadFile)
  Fix 1        Fix 2        Fix 3               Fix 4
```

---

## Fix 1 — inverted `ASSERT` in the `P2PSig_Con` dispatch

**File:** `P2Pwin32.cpp:4518-4521` (`DispatchP2PeerCon`)

**Symptom.** Every connection notification aborted the process in debug builds. Both the WSA
server and client (and the pipe probe) hit `ASSERT` at `P2Pwin32.cpp:4519` on the very first
`On_ConStartup`.

**Root cause.** The `P2PSig_Con` signature (`conRESULT (P2PeerCon*)` — used by `P2P_Startup`,
`P2P_Accept`, `P2P_Connect`, `P2P_Listen`, `P2P_Close`, `P2P_PITimer`, …) asserted the
connection pointer was **null**:

```cpp
case P2PSig_Con:
    ASSERT(pExtra==nullptr);
    ASSERT(pCon==nullptr);            // <-- WRONG
    conResult = (pTarget->*mwf.pfn_Con)(pCon);
```

But the pump copies the posted connection straight into `pCon` (`P2Pwin32.cpp:3487-3492`,
from `pP2Pmsg->pCon`), and line 4527 immediately passes that same `pCon` to the handler. So
for any real connection notification `pCon` is **non-null**, and the assert fires. (It cannot
be a valid invariant either way: some `P2P_PITimer` posts legitimately carry a null `pCon`.)

**Fix.** Remove the bogus `pCon` assertion; keep `ASSERT(pExtra==nullptr)` (the plain
con-signature carries no message). `pCon` is passed through to the handler as-is.

---

## Fix 2 — missing `P2P_Listen` entry in the default con map

**File:** `P2PeerTarget.cpp:2341` (`P2PeerTarget::_P2PeerConEntries[]`)

**Symptom.** After Fix 1, the server reached `On_ConStartup` then immediately closed its
service connection (before any client connected); clients got `WSAECONNREFUSED`. The captured
drop event was `P2PeerTarget::NotHandled — "ON_P2PeerCon_L(...) not handled → connection
dropped"`.

**Root cause.** `On_ConStartup` for a SERVICE connection calls `Listen()`
(`P2PeerTarget.cpp:2384-2385`), and the transport's `Listen()` posts a `P2P_Listen`
notification (`P2PeerConWsa.cpp:598`, `P2PeerConPipe.cpp:344`) that is meant to drive
`On_ConListen` → `OnListen()` + `Accept()`. But the default connection map had service
handlers for `P2P_Startup`, `P2P_Accept`, `P2P_Shutdown` and **no `P2P_Listen` entry**, so the
notification fell through to `NotHandled`, which drops the connection. The server therefore
never armed its accept.

**Fix.** Add the listen handler next to the other service entries:

```cpp
// Service handlers
ON_P2PeerCon_SERVICE(L"*",P2P_Startup,On_ConStartup)
ON_P2PeerCon_SERVICE(L"*",P2P_Listen,On_ConListen)     // <-- added
ON_P2PeerCon_SERVICE(L"*",P2P_Accept,On_ConAccept)
ON_P2PeerCon_SERVICE(L"*",P2P_Shutdown,On_ConShutdown)
```

After this the server progresses `On_ConStartup → On_ConListen → On_ConAccept`, and the client
`On_ConStartup → On_ConConnect`.

---

## Fix 3 — receive buffer too small for the login/key-exchange message

**Files:** `P2PeerMsg.h:36` (`MAX_P2Psize`) and `P2Peerio.cpp:73-74`
(`m_dwMaxSendSize` / `m_dwMaxRecvSize`)

**Symptom.** After Fix 2, connect + accept succeeded but the connection dropped before login
completed. The captured drop event was `P2Peerio::RecvP2PeerMsg — "Attempt to exceed maximum
(2048) buffer size (4056)"` (`P2Peerio.cpp:514-519`).

**Root cause.** The P2P login performs a Diffie-Hellman / Rijndael key exchange (see
`adrs/0007`); that handshake message is ~4 KB. The receive size limit and the default
per-connection recv/send buffers were **2048**, so `RecvP2PeerMsg` rejected the 4056-byte
message and threw.

**Fix.** Raise the maximum message size and the P2Peerio buffer defaults from `2048` to
`32768`:

```cpp
// P2PeerMsg.h
const P2Psize_t MAX_P2Psize = 32768;   // was 2048

// P2Peerio.cpp ctor
m_dwMaxSendSize = 32768;               // was 2048
m_dwMaxRecvSize = 32768;
```

After this, `On_ConLogin` (server) and `On_ConLoginAck` (client) both fire — the login
handshake completes on both transports.

> **Historical note.** This is exactly the change that had previously been made *and reverted*
> (`_reversa_sdd`, retired `adrs/0006-raise-max-p2psize-for-login`, `MAX_P2Psize` 2048→32768).
> The revert was based on a spec-analysis conclusion that the loopback handshake "works by
> design" at 2048. **Runtime evidence contradicts that**: at 2048 the ~4 KB login message is
> rejected and the handshake cannot complete. The raise is required.

---

## Fix 4 — synchronous `ReadFile` completion misreported as a failure

**File:** `P2Peerio.cpp:753-767` (`P2Peerio::Recv`)

**Symptom.** After Fix 3, both transports reached `On_ConLoginAck`, the client posted its
BCast, but the server never fired `On_P2PeerBCast`. The captured drop event was
`P2Peerio::RecvP2PeerMsg — "Recv(N bytes) failed", HRESULT 0x7A` (`ERROR_INSUFFICIENT_BUFFER`)
— and it hit for an 8-byte header read as well as a 2 KB body read, i.e. **independent of
size**, which ruled out an actual buffer problem.

**Root cause.** `P2Peerio::Recv` issues an overlapped `ReadFile`
(`P2Peerio.cpp:734-739`). When the requested bytes are **already buffered** in the socket/pipe
— which is true for the first application message the peer has already sent — `ReadFile`
completes **synchronously and returns `TRUE`**. The old code then took the `else` branch and
read a **stale `GetLastError()`**:

```cpp
else if ( (hResult=GetLastError()) != ERROR_IO_PENDING && hResult )
{ // "Conflicting ReadFile() outcome" -> raised as an error -> connection dropped
    ...
}
return hResult;
```

`ReadFile` does **not** reset `GetLastError()` on success, so `hResult` was a leftover value
(e.g. `122`) from an earlier API call; the code misread synchronous success as a failure and
dropped the connection. The login recv only escaped this because its data had not yet arrived,
so `ReadFile` returned `FALSE` + `ERROR_IO_PENDING` (the genuine async path).

Because the handle is bound to an IOCP and `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` is **never
set** anywhere in the codebase, a synchronous completion **still posts a completion packet** to
the port. So synchronous success must be treated identically to `ERROR_IO_PENDING`: leave the
`OVERLAPPED` queued and let the IOCP completion drive processing.

**Fix.**

```cpp
// ReadFile completed SYNCHRONOUSLY (TRUE) — data was already buffered.
// The IOCP still posts a completion packet, so treat it exactly like
// ERROR_IO_PENDING and let the completion drive processing. (The old code
// read a STALE GetLastError() here and dropped every connection whose next
// message was already buffered — i.e. all post-login application messages.)
else
{
    hResult = ERROR_IO_PENDING;   // completion will arrive via the IOCP
}
return hResult;
```

After this, `On_P2PeerBCast` fires on the server and application messages are delivered on
both transports.

---

## Fix summary

| # | File:line | Bug | Fix |
|---|-----------|-----|-----|
| 1 | `P2Pwin32.cpp:4519` | `P2PSig_Con` dispatch asserted `pCon==nullptr`; con is non-null | removed the assert |
| 2 | `P2PeerTarget.cpp:2341` | default con map missing `P2P_Listen` → server never listens | added `ON_P2PeerCon_SERVICE(L"*",P2P_Listen,On_ConListen)` |
| 3 | `P2PeerMsg.h:36`, `P2Peerio.cpp:73-74` | 2048-byte cap rejects the ~4 KB login message | raised `MAX_P2Psize` + P2Peerio buffers to `32768` |
| 4 | `P2Peerio.cpp:753-767` | synchronous `ReadFile` misread stale `GetLastError()` as failure | treat synchronous success as `ERROR_IO_PENDING` |

> **Consumer impact.** These fixes are in the shared `Targetcore` DLL/`.lib` (output to
> `../lib` and `$WDMSCS_DEBUG`). Every consumer that links it — the downstream MFC
> applications and any generated projects — picks them up on the next rebuild. The changes are corrective
> (no API/ABI changes), but rebuild + smoke-test dependent apps after taking them.

---

# Multi-connection hub tests (2026-07-03)

Two runtime harnesses probe how a single `P2PeerHub` supervises **more than one** connection, and
how it behaves when those connections use **different transports**. Both are standalone MFC console
projects that link the shared `Targetcore`/`Msgcore` libs and self-connect over loopback in one
process, mirroring `AlexTest` (WSA) and `PipeMeshTest` (pipe). Both are **verified passing** (built
`Debug|x64`, VS2026 v145; run headless; verdict via exit code).

| Test | Project | Question | Result |
|------|---------|----------|--------|
| 1 | `../TwoConTest` | one hub, **two `P2PeerConWsa`** connections | **PASS** (exit 0) |
| 2 | `../MixConTest` | one hub, **`P2PeerConWsa` + `P2PeerConPipe`** mixed | **PASS** (exit 0) |

## The governing rule (verified against the source)

A `P2PeerHub` owns a **list** of connections (`EnumP2PmsgCon`) and is built to supervise many at
once. There is exactly one coexistence rule, and it is **transport-agnostic**:

> A hub keeps **at most one connection per remote-hub identity**. The identity is the connection's
> `GetP2Paddress()` → `m_oThatP2Paddr` (the *remote* peer address). It is checked twice:
> - at **post time** — `P2PeerHub::PostP2PeerCon` (`P2PeerHub.cpp:676-691`) returns `FALSE` for a
>   duplicate address (`"P2PeerCon[%s] instance already exists within P2PmsgHub[%s]"`).
> - after **login** — the identity is *rewritten* to the peer hub's real announced address, and a
>   collision there closes the connection (`"Duplicate P2PeerCon's for P2PeerHub attempted"`).

So: **a hub supervises as many connections as you like, of any mix of transports, provided their
(post-login) remote-hub identities are distinct.** Transport type never enters the key.

## Test 1 — `TwoConTest`: one hub, two `P2PeerConWsa`

One hub, TCP loopback `127.0.0.1:7788`:

```cpp
P2PeerConWsa* pConServer = P2PeerConWsa::ServiceFactory(kSvcPeer /*=PeerA*/, kPort);
oHub.PostP2PeerCon(pConServer);                       // -> TRUE
P2PeerConWsa* pConClient = P2PeerConWsa::ClientFactory(kCliPeer /*=PeerB*/, L"127.0.0.1", kPort);
oHub.PostP2PeerCon(pConClient);                       // -> TRUE
```

- **PART A (positive):** two cons with **distinct** peer addresses (`PeerA`, `PeerB`) both post; the
  hub drives all lifecycles concurrently and, over loopback, logs into itself
  (`On_ConLoginAck` fires). At runtime one hub drove **three** `P2PeerCon` objects at once
  (listener, accept-spawned, client).
- **PART B (negative):** a third con whose address **duplicates** `PeerA` → `PostP2PeerCon`
  returns `FALSE` (correctly rejected). *(Cleanup: a fresh factory con has `m_cRef==0`; wrap it in
  `SafeP2PeerCon` for destruction — calling `Release()` directly underflows the ref-count.)*

Verdict: **PASS** — one hub supervises multiple connections; duplicate addresses are rejected.

## Test 2 — `MixConTest`: one hub, `P2PeerConWsa` + `P2PeerConPipe`

A hub is transport-agnostic, so it can hold a WSA con and a pipe con simultaneously — but the
identity rule above means the two connections must target **different remote hubs** (a single hub
looping to *itself* on two transports makes both server-accept cons resolve to the same self
identity and the second is closed as a duplicate; that is *not* a transport-mix limitation). The
harness therefore uses three hubs in one process, with **HubA** as the mixed endpoint:

```
   HubB (WSA  service) <=== TCP  127.0.0.1:7799 ===  HubA   (WSA  client, peer = HubB)
   HubC (Pipe service) <== \\.\pipe\MixConProbe ==   HubA   (Pipe client, peer = HubC)
                                                       ^^^^ ONE hub, two transports
```

HubA simultaneously owns a `P2PeerConWsa` (identity `HubB`) **and** a `P2PeerConPipe` (identity
`HubC`); being the connector on both, it receives `On_ConLoginAck` **twice** — once per transport.
Runtime trace (HubA on one pump thread, two distinct con pointers):

```
HubA  On_ConLoginAck  con=...C0770 addr='MixConTest.HubB'   -> WSA  acked
HubA  On_ConLoginAck  con=...C0A20 addr='MixConTest.HubC'   -> PIPE acked
VERDICT: PASS -- one hub (HubA) holds a live P2PeerConWsa AND a live P2PeerConPipe
```

Verdict: **PASS** — one hub holds live connections of mixed transports at the same time.

## Build & runtime notes (both harnesses)

- Each project references the sibling `Msgcore` + `Targetcore` projects (`..\lib` import libs,
  `..\Msgcore` / `..\Targetcore` headers) and delay-loads `Targetcore.dll`.
- **Incremental build breaks (`error C2859`):** the post-build step copies
  `..\Targetcore\x64\Debug\vc143.pdb` next to the exe, clobbering the local compiler PDB. Use
  `/t:Rebuild`.
- **Staging the DLL:** if `Targetcore` is built only to `..\bin\Debug64\`, copy
  `Targetcore.dll` next to the test exe before running.
- **Console mode / pipe transport:** `MixConTest` deliberately does **not** put stdout in
  `_O_U16TEXT` (wide) mode. With the pipe transport active, wide (`wprintf`) and narrow stdio
  writes mix on stdout, and a stream left in `_O_U16TEXT` asserts inside the UCRT
  (`corecrt_internal_stdio.h:495`) on the first narrow write. Default translated mode + ASCII-only
  output avoids it. (`TwoConTest`, WSA-only, never exercises that path and keeps `_O_U16TEXT`.)

> These harnesses are **new sibling projects only** (`../TwoConTest`, `../MixConTest`); no existing
> project or the `Targetcore` library itself was modified. Each project also carries its own
> `README.md` with the full trace and design rationale.

---

# Licence

Targetcore is licensed under the **Apache License, Version 2.0**. See
[`LICENSE`](LICENSE) for the full text, or <http://www.apache.org/licenses/LICENSE-2.0>.

```
Copyright 2000-2026 Ivyware Pty Ltd, Khrustal & Mann

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Files not covered by the licence

Some files in this directory are Microsoft project-template, wizard-generated or
sample-derived files. They keep Microsoft's own notices and are **not** licensed under
Apache 2.0: `Resource.h`, `Targetcore.rc`, `stdafx.h`, `stdafx.cpp`,
and the Visual Studio solution and project files. See [`NOTICE`](NOTICE) for the full list.

## Dependencies licensed separately

This library is an MFC extension DLL and links against the Microsoft Foundation Classes,
the Visual C++ runtime, and the Windows SDK's CNG (`bcrypt`, `ncrypt`) — all licensed by
Microsoft, none redistributed here. The Linux build additionally uses OpenSSL 3
(Apache 2.0) and liburing (LGPL-2.1 / MIT). These are dependencies, not bundled source.
