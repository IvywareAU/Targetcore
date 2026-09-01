# TargetCore — Usage Examples

Worked examples for the four core classes:

| Class            | Role                                                                                  |
|------------------|---------------------------------------------------------------------------------------|
| `P2PeerTarget`   | Base of everything routable. Supplies the `P2PeerCon_MAP`, `P2PeerSys_MAP` and `P2PeerMsg_MAP` handler tables. You override its `On_Con*` / `On_*Cast` virtuals to react to connection-lifecycle and message events. |
| `P2PeerHub`      | A `P2PeerTarget` that owns a pump thread and routes `P2PeerMsg`s between peers. This is the object you subclass for an application endpoint. |
| `P2PeerConWsa`   | A connection (`P2PeerCon`) implemented over a **WSA TCP/IP socket**. Created via `ServiceFactory` (listen) / `ClientFactory` (connect). |
| `P2PeerConPipe`  | A connection (`P2PeerCon`) implemented over a **Windows named pipe**. Same factory shape as `P2PeerConWsa`. |

The relationship in one line:

```
P2PeerTarget  ◀── (base class) ──  P2PeerHub  ── supervises ──▶  P2PeerCon
                                                                     ├── P2PeerConWsa   (TCP/IP)
                                                                     └── P2PeerConPipe  (named pipe)
```

A hub *is* a target, so it inherits every `On_Con*` handler you see overridden below. Connections
are handed to a hub with `PostP2PeerCon()`; the hub pumps them through the con-map, and once the
login handshake completes, application `P2PeerMsg`s flow through `PostP2PeerMsg()` /
`On_P2PeerBCast()` / `On_P2PeerUCast()`.

> **⚠️ Every hub below calls `RequireAuth(false)`, and that is not decoration.** Security is
> **on by default since 2026-08-18**: a hub that requires authentication and holds no identity
> **refuses to arm**, so `SpawnHub()` returns `0` and nothing that follows it happens. These
> examples are about the routing kernel rather than about provisioning, so they opt out in one
> visible line. A deployment does the other thing — provisions an identity and an allow-list.
> See [Security](Readme.md#security) before copying any of this onto a wire.

---

## Common pieces (used by both transports)

### 1. Your endpoint = a `P2PeerHub` subclass

Overriding the `P2PeerTarget` connection handlers and the hub message handlers is *all* the
application code you write. The pattern below is identical for TCP and pipes — only the connection
factory differs.

```cpp
#include "P2Pwin32.h"      // StartupP2Pmsg / CleanupP2Pmsg
#include "P2PeerHub.h"     // P2PeerHub  (which drags in P2PeerTarget)
#include "P2PeerMsg.h"     // P2PeerMsg / P2PeerMsg32 / P2Pmsg_BCast

// A minimal application endpoint. Because P2PeerHub derives from
// P2PeerTarget, every override below is a P2PeerTarget con-map / msg-map
// handler that the hub's pump invokes for us.
class MyHub : public P2PeerHub
{
public:
    // strAddr is this hub's P2Paddr, e.g. L"MyApp.Server".
    MyHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr)   // <-- P2PeerHub ctor takes the hub address
        , m_bServer(bServer)
        , m_bSent(false)
    {}

    // ---- P2PeerMsg_MAP handlers (application messages) ------------------

    // A broadcast message arrived and was routed to this hub.
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        Print(L"BCast", pMsg);
        return msgHANDLED;                 // stop routing; we consumed it
    }

    // A message addressed specifically to this hub arrived.
    virtual msgRESULT On_P2PeerUCast(P2PeerMsg* pMsg) override
    {
        Print(L"UCast", pMsg);
        return msgHANDLED;
    }

    // ---- P2PeerCon_MAP handlers (connection lifecycle) -----------------
    // These are inherited from P2PeerTarget. Always delegate to the base
    // after your own work, or the handshake state machine won't advance.

    // Client side: the login handshake (incl. Diffie-Hellman key exchange)
    // is complete. It is now safe to post application messages.
    virtual conRESULT On_ConLoginAck(P2PeerCon*  pCon,
                                     P2PaddrSTR  strThisAddr,
                                     P2PaddrSTR  strThatAddr,
                                     const void* pvAck,
                                     P2Psize_t   iSize) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck(
                          pCon, strThisAddr, strThatAddr, pvAck, iSize);

        if (!m_bServer && !m_bSent)        // client: fire one message
        {
            PostTestMessage();
            m_bSent = true;
        }
        return r;
    }

private:
    void PostTestMessage()
    {
        LPCWSTR   lpszMsg = L"Hello from the client!";
        P2Psize_t nBytes  = (P2Psize_t)((wcslen(lpszMsg) + 1) * sizeof(wchar_t));

        // P2PeerMsg32 pre-allocates a 32-byte address area (fits typical hub
        // addresses). Args: (source, destination, msg-id, data, data-bytes).
        // The hub takes ownership of this heap object once posted.
        P2PeerMsg32* pMsg = new P2PeerMsg32(
            GetP2PaddrHub(),               // from  (this hub)
            m_strPeerAddr,                 // to    (the other hub)
            P2Pmsg_BCast,                  // message id
            lpszMsg, nBytes);

        PostP2PeerMsg(pMsg);               // hand it to the pump for routing
    }

    void Print(LPCWSTR kind, P2PeerMsg* pMsg)
    {
        LPCWSTR src  = pMsg ? pMsg->GetSource() : L"<null>";
        LPCWSTR data = (pMsg && pMsg->Data() && pMsg->DataSize() > 0)
                     ? (LPCWSTR)pMsg->Data() : L"<no data>";
        wprintf(L"[%s] %s from '%s': %s\n",
                m_bServer ? L"SERVER" : L"CLIENT", kind, src, data);
    }

public:
    P2Paddr m_strPeerAddr;   // set by main() to the peer hub's address
private:
    bool    m_bServer;
    bool    m_bSent;
};
```

### 2. Process startup / shutdown boilerplate

```cpp
// Initialise the TargetCore kernel (arg = pump/thread pool hint).
if (!StartupP2Pmsg(16)) { /* fatal */ }

// StartupP2Pmsg() does NOT call WSAStartup — when you drive a hub directly
// (rather than via P2PeerService::Run) you must init Winsock yourself.
// Required for P2PeerConWsa; harmless for P2PeerConPipe.
WSADATA wsa;
WSAStartup(MAKEWORD(2, 2), &wsa);

// ... create hubs + connections (see per-transport sections) ...

// Teardown, reverse order:
hub.CloseHub();          // stop the pump, drop connections
CleanupP2Pmsg();         // shut down the kernel
WSACleanup();
```

---

## Example A — `P2PeerHub` with `P2PeerConWsa` (TCP/IP)

Two processes: start the **server** first, then the **client**. Mirrors the `AlexTest` harness.

```cpp
#include "P2PeerConWsa.h"

static const short      kPort       = 7777;
static const P2PaddrSTR kServerAddr = L"MyApp.Server";
static const P2PaddrSTR kClientAddr = L"MyApp.Client";

int main(int argc, char* argv[])
{
    bool    bServer = !(argc >= 2 && _stricmp(argv[1], "send") == 0);
    CString strIP   = (argc >= 3) ? CString(argv[2]) : L"127.0.0.1";

    StartupP2Pmsg(16);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);   // TCP needs Winsock

    // ---- Create + spawn the hub ---------------------------------------
    MyHub hub(bServer ? kServerAddr : kClientAddr, bServer);
    hub.m_strPeerAddr = bServer ? kClientAddr : kServerAddr;

    // Opt out of the on-by-default authentication; see the note at the top.
    hub.RequireAuth(false);

    // SpawnHub() creates the pump thread and returns its HANDLE. The hub
    // lives in the context of this thread from here on. It returns 0 if the
    // hub requires an authentication it cannot enforce.
    HANDLE hThread = hub.SpawnHub();

    // ---- Create the WSA connection and hand it to the hub -------------
    P2PeerConWsa* pCon = nullptr;
    if (bServer)
    {
        // ServiceFactory(expectedPeerAddr, port): passively LISTENS on the
        // port and accepts the client. The address is the peer we expect.
        pCon = P2PeerConWsa::ServiceFactory(kClientAddr, kPort);
    }
    else
    {
        // ClientFactory(serverAddr, ip, port): actively CONNECTS out.
        pCon = P2PeerConWsa::ClientFactory(kServerAddr,
                                           strIP.GetString(), kPort);
    }

    // PostP2PeerCon hands the connection to the hub's pump, which drives it
    // through the con-map: Startup -> (Listen/Accept | Connect) -> Login ->
    // LoginAck. Your On_Con* overrides fire along the way.
    hub.PostP2PeerCon(pCon);

    // ---- Run ----------------------------------------------------------
    if (bServer)
        getchar();                 // keep listening until Enter
    else
        Sleep(3000);               // give the handshake + send time to run

    // ---- Shutdown -----------------------------------------------------
    hub.CloseHub();
    CloseHandle(hThread);
    CleanupP2Pmsg();
    WSACleanup();
    return 0;
}
```

**Flow:**
`SERVER: On_ConStartup → On_ConListen → On_ConAccept → On_ConLogin`
`CLIENT: On_ConStartup → On_ConConnect → On_ConLoginAck  ⇒  posts BCast`
`SERVER: On_P2PeerBCast  ⇒  message printed`

---

## Example B — `P2PeerHub` with `P2PeerConPipe` (named pipe)

Same application code, different transport. This version runs **both hubs in one process**, each
on its own pump thread — proving a hub↔hub link over a named pipe. Mirrors the `PipeMeshTest`
harness.

```cpp
#include "P2PeerConPipe.h"

static LPCTSTR          kPipeName   = _T("\\\\.\\pipe\\MyAppProbe");
static const P2PaddrSTR kServerAddr = L"MyApp.Server";
static const P2PaddrSTR kClientAddr = L"MyApp.Client";

int main()
{
    StartupP2Pmsg(16);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);   // not needed for pipes,
                                                     // but harmless

    // ---- Hub A: SERVER — creates and listens on the named pipe --------
    MyHub server(kServerAddr, /*bServer*/ true);
    server.m_strPeerAddr = kClientAddr;
    server.RequireAuth(false);                       // see the note at the top
    HANDLE hServer = server.SpawnHub();

    // ServiceFactory(expectedPeerAddr, pipeName): does CreateNamedPipe +
    // an overlapped ConnectNamedPipe wait. Note the SECOND arg is the pipe
    // name (a string) — that is the only signature difference from the WSA
    // ServiceFactory, which takes a port number.
    P2PeerConPipe* pSvcCon =
        P2PeerConPipe::ServiceFactory(kClientAddr, kPipeName);
    server.PostP2PeerCon(pSvcCon);

    // Let the server pump actually create the pipe before the client opens
    // it, so the client's CreateFile(OPEN_EXISTING) finds it.
    Sleep(750);

    // ---- Hub B: CLIENT — opens the existing named pipe ----------------
    MyHub client(kClientAddr, /*bServer*/ false);
    client.m_strPeerAddr = kServerAddr;
    client.RequireAuth(false);                       // see the note at the top
    HANDLE hClient = client.SpawnHub();

    // ClientFactory(serverAddr, pipeName): CreateFile(OPEN_EXISTING) on the
    // pipe, then drives the same login handshake as the TCP client.
    P2PeerConPipe* pCliCon =
        P2PeerConPipe::ClientFactory(kServerAddr, kPipeName);
    client.PostP2PeerCon(pCliCon);

    // ---- Wait for the round trip --------------------------------------
    Sleep(5000);   // handshake + BCast delivery

    // ---- Shutdown (clients first, then server, kernel last) -----------
    client.CloseHub();
    server.CloseHub();
    WaitForSingleObject(hClient, 3000);
    WaitForSingleObject(hServer, 3000);
    CloseHandle(hClient);
    CloseHandle(hServer);

    CleanupP2Pmsg();
    WSACleanup();
    return 0;
}
```

**Flow** (both hubs, same process, different threads):
`SERVER: On_ConStartup → On_ConListen → On_ConAccept → On_ConLogin`
`CLIENT: On_ConStartup → On_ConConnect → On_ConLoginAck  ⇒  posts BCast`
`SERVER: On_P2PeerBCast  ⇒  message printed`

---

## `P2PeerConWsa` vs `P2PeerConPipe` — the only differences

Everything else (hub subclass, con-map handlers, message posting, teardown) is identical.

| Aspect            | `P2PeerConWsa`                                   | `P2PeerConPipe`                                 |
|-------------------|--------------------------------------------------|-------------------------------------------------|
| Transport         | WSA TCP/IP socket                                | Windows named pipe                              |
| `ServiceFactory`  | `(peerAddr, short port)`                          | `(peerAddr, LPCTSTR pipeName)`                  |
| `ClientFactory`   | `(peerAddr, LPCTSTR ip, short port)`              | `(peerAddr, LPCTSTR pipeName)`                  |
| Endpoint id       | IP + port (e.g. `127.0.0.1:7777`)                 | pipe name (e.g. `\\.\pipe\MyAppProbe`)          |
| Winsock           | **required** (`WSAStartup` before use)            | not required                                    |
| Cross-process     | yes (across machines)                             | yes, and works well hub↔hub in one process      |

---

## A note on `P2PeerTarget` directly

You rarely instantiate `P2PeerTarget` on its own — a `P2PeerHub` already *is* one, and that is
where the con/msg handlers you saw above come from. Its standalone use is as a **sub-target**: a
routing/handler node you register *under* a hub so it can share the hub's pump and receive routed
messages, without being a full hub itself.

```cpp
// A lightweight handler node — no pump of its own; it borrows the hub's.
class MySubTarget : public P2PeerTarget
{
protected:
    // Same con-map handlers as a hub — this node can react to the
    // connection lifecycle for the connections routed to it.
    virtual conRESULT On_ConLoginAck(P2PeerCon*  pCon,
                                     P2PaddrSTR  strThisAddr,
                                     P2PaddrSTR  strThatAddr,
                                     const void* pvAck,
                                     P2Psize_t   iSize) override
    {
        wprintf(L"[SUB-TARGET] login acked with '%s'\n", strThatAddr);
        return P2PeerTarget::On_ConLoginAck(
                   pCon, strThisAddr, strThatAddr, pvAck, iSize);
    }

    virtual msgRESULT On_P2PeerMsg(P2PaddrSTR strAddr, UINT nCode,
                                   P2Pmsg_t nMsg, P2PeerMsg* pMsg,
                                   void* pvExtra,
                                   P2P_MSGHANDLERINFO* pInfo) override
    {
        // Inspect / handle messages routed through this node, then let the
        // base continue routing.
        return P2PeerTarget::On_P2PeerMsg(
                   strAddr, nCode, nMsg, pMsg, pvExtra, pInfo);
    }
};

// Registering the sub-target under a hub (priority controls handler order;
// lower value = later). The hub now pumps this target too.
MyHub        hub(L"MyApp.Server", /*bServer*/ true);
MySubTarget  sub;
hub.RegisterTarget(&sub, /*priority*/ -100);
// ... hub.RequireAuth(false); hub.SpawnHub(); hub.PostP2PeerCon(...); as before ...
// Remove it before teardown if it out-lives the hub scope:
hub.RemoveTarget(&sub);
```

Use a sub-target to split responsibilities (e.g. one target logs, another handles a message
family) while keeping a single hub/pump. For most applications, overriding the handlers directly
on your `P2PeerHub` subclass — as in Examples A and B — is all you need.
```
