// Copyright © 2026 Khrustal & Mann
//              MELBOURNE, VICTORIA, AUSTRALIA, 3000
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// TargetCore_c.cpp  –  extern "C" implementation of Panama bridge
// Compiles as part of TargetCore.dll (TargetCore_EXPORTS defined via project
// preprocessor settings; do not redefine here).
// stdafx.h MUST be the first include to satisfy the precompiled-header requirement.

#include "stdafx.h"          // precompiled header – must be first
#include "TargetCore_c.h"
#include "P2Peer.h"
#include "P2PeerMsg.h"
#include "P2PeerCon.h"
#include "P2PeerConWsa.h"
#include "P2PeerHub.h"
#include "P2Pwin32.h"        // StartupP2Pmsg / CleanupP2Pmsg (P2Pmsg environment)

#include <atomic>
#include <map>
#include <mutex>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// Handle registry (SECURITY_REVIEW M1)
//
// Every handle this API hands to a C caller is recorded here on creation and
// forgotten on destroy; every entry point looks its raw void* up before using
// it. The load-bearing property is that the lookup NEVER DEREFERENCES the
// caller's pointer. A magic word in a wrapper struct would have to read through
// the pointer to check it, which is the defect itself rather than a fix for it:
// a hostile or merely stale value crashes (or worse) at the check.
//
// std::map keyed by the address, exactly like the paging registry in
// Msgcore_c.cpp (`s_mapPaging` + `s_mtxPaging` + `MsgcorePagingForget`, called
// from msgcore_mgr_destroy): the key IS the handle, and the map's node stability
// means an entry never moves while it is registered.
//
// The registry is TYPE-AWARE. The four handle typedefs in the header are all
// `void*`, so before this nothing stopped a C caller spending a P2PeerMsg where
// a P2PeerHub was expected — four unrelated C++ classes with one ABI. Storing
// the kind alongside the key makes that a refusal instead of type confusion.
//
// What this does NOT close, and cannot: a caller that destroys a handle on one
// thread while another thread is inside an entry point holding it. The window
// between the lookup and the use is only closable by refcounting every handle,
// which would change the ownership contract the header publishes. The registry
// closes the three holes that were reachable from a correct single-threaded
// caller's mistake or from a hostile one: a pointer we never issued, a pointer
// we issued and have since forgotten, and a pointer of the wrong kind.
//
// Cost: one uncontended mutex acquisition per handle argument. p2peerhub_post_msg
// therefore takes two on the send path; that is nanoseconds against a message
// post, and correctness at an FFI boundary is not the place to trade it away.
// ─────────────────────────────────────────────────────────────────────────────

enum P2PhandleKind_e
{
    P2PhandleKind_Addr = 1,
    P2PhandleKind_Msg,
    P2PhandleKind_Wsa,
    P2PhandleKind_Hub
};

static std::map<const void*, P2PhandleKind_e> s_mapP2Phandle;
static std::mutex                             s_mtxP2Phandle;

// Records a handle just produced and returns it, so a factory reads as one line.
static void* P2PhandleAdd(void* pvHandle, P2PhandleKind_e eKind)
{
    if (!pvHandle) return nullptr;
    std::lock_guard<std::mutex> oLock(s_mtxP2Phandle);
    // Assignment rather than insert(): the allocator recycles addresses, and a
    // recycled address must take the NEW kind. insert() would silently keep the
    // dead entry's kind and turn address reuse into type confusion — the exact
    // failure this registry exists to prevent. (Same hazard MsgcorePagingForget
    // is commented against in Msgcore_c.cpp.)
    s_mapP2Phandle[pvHandle] = eKind;
    return pvHandle;
}

// True only when pvHandle is a live handle of exactly eKind. Never dereferences it.
static bool P2PhandleIs(const void* pvHandle, P2PhandleKind_e eKind)
{
    if (!pvHandle) return false;
    std::lock_guard<std::mutex> oLock(s_mtxP2Phandle);
    std::map<const void*, P2PhandleKind_e>::const_iterator it = s_mapP2Phandle.find(pvHandle);
    return it != s_mapP2Phandle.end() && it->second == eKind;
}

// Forgets a handle. Returns true ONLY for the caller that actually removed it,
// which is what makes destroy safe: a double destroy deletes once and refuses
// the second time, and two threads racing the same destroy cannot both reach
// the delete.
static bool P2PhandleForget(const void* pvHandle, P2PhandleKind_e eKind)
{
    if (!pvHandle) return false;
    std::lock_guard<std::mutex> oLock(s_mtxP2Phandle);
    std::map<const void*, P2PhandleKind_e>::iterator it = s_mapP2Phandle.find(pvHandle);
    if (it == s_mapP2Phandle.end() || it->second != eKind) return false;
    s_mapP2Phandle.erase(it);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cast helpers
// Each answers nullptr for anything that is not a live handle of its own kind,
// so every entry point's guard is the same two lines and cannot be forgotten
// halfway down a block of similar-looking functions.
// ─────────────────────────────────────────────────────────────────────────────
static inline P2Paddr*      addr(P2PAddrHandle      h) { return P2PhandleIs(h, P2PhandleKind_Addr) ? static_cast<P2Paddr*>(h)      : nullptr; }
static inline P2PeerMsg*    msg (P2PeerMsgHandle     h) { return P2PhandleIs(h, P2PhandleKind_Msg)  ? static_cast<P2PeerMsg*>(h)    : nullptr; }
static inline P2PeerConWsa* wsa (P2PeerConWsaHandle  h) { return P2PhandleIs(h, P2PhandleKind_Wsa)  ? static_cast<P2PeerConWsa*>(h) : nullptr; }
static inline P2PeerHub*    hub (P2PeerHubHandle     h) { return P2PhandleIs(h, P2PhandleKind_Hub)  ? static_cast<P2PeerHub*>(h)    : nullptr; }

// UTF-8 conversion for the _u8 sink. TargetCore_c_u8.cpp's WtoU8() cannot serve
// here: it returns a pointer into ONE thread_local buffer, and the sink needs
// three converted strings live at the same time. Returning by value costs a C++
// heap allocation on the pump thread — which is the safe heap; the one that must
// stay clear is the message's bounded heap (see CSinkHub::Deliver).
static std::string WtoU8str(const wchar_t* w)
{
    if (!w || !*w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    s.resize((size_t)n - 1);
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// CSinkHub — a P2PeerHub carrying an optional receive sink
//
// Every handle p2peerhub_create() hands out is one of these. With no sink
// registered On_P2PeerMsg delegates straight to the base, so the behaviour of
// existing consumers (the Panama bindings, the TreeFS frontend) is unchanged.
//
// The hook is On_P2PeerMsg rather than PeekP2PeerMsg deliberately. Both are
// virtual and both see inbound traffic, but PeekP2PeerMsg is ALSO called from
// P2PeerHub::RouteP2PeerMsg on the send/forward path, so a sink hung off it
// would report messages this hub merely relayed as if they had been delivered
// to it (the mistake documented in PeerFsMirror.h §8.3). On_P2PeerMsg is reached
// only from the pump's delivery branch, which is guarded by
// `pTarget->GetP2PaddrHub() == pMsg->GetDestin()` (P2Pwin32.cpp:3105).
//
// No P2PeerMsg_MAP macro here: the class overrides virtuals only and inherits
// P2PeerHub's compiled map, so it is free of the one-definition-per-TU rule that
// map macros impose.
// ─────────────────────────────────────────────────────────────────────────────
namespace {

class CSinkHub : public P2PeerHub
{
  public:
    explicit CSinkHub(P2PaddrSTR strAddr) : P2PeerHub(strAddr) {}

    // ctx is published before fn, and fn is read before ctx, so registering a
    // sink and clearing it are safe against a running pump. Swapping one live
    // sink for another is not, and the header says so.
    void SetSink  (P2PeerHubSinkFn   fn, void* ctx) { m_ctxW = ctx; m_fnW.store(fn, std::memory_order_release); }
    void SetSinkU8(P2PeerHubSinkFnU8 fn, void* ctx) { m_ctxU = ctx; m_fnU.store(fn, std::memory_order_release); }

    virtual msgRESULT On_P2PeerMsg(P2PaddrSTR strP2Paddr, UINT nCode, P2Pmsg_t nMsg,
                                    P2PeerMsg* pMsg, void* pvExtra,
                                    P2P_MSGHANDLERINFO* pHandlerInfo)
    {
        if (pMsg && Deliver(pMsg))
            return msgHANDLED;
        return P2PeerHub::On_P2PeerMsg(strP2Paddr, nCode, nMsg, pMsg, pvExtra, pHandlerInfo);
    }

  private:
    // Returns true when a sink consumed the message.
    bool Deliver(P2PeerMsg* pMsg)
    {
        P2PeerHubSinkFn   fnW = m_fnW.load(std::memory_order_acquire);
        P2PeerHubSinkFnU8 fnU = m_fnU.load(std::memory_order_acquire);
        if (!fnW && !fnU)
            return false;

        int consumed = 0;
        try
        {
            // Heap discipline (P2PeerFs spike 14.2b; PeerFsMirror.h "Heap
            // budget"): Data/DataSize/GetSource/GetDestin each allocate on the
            // message's bounded 65535-byte heap, and using all four leaves no
            // room for the wire send that a sink's reply performs on this same
            // pump. Three is safe, so GetDestin() is the one dropped — the
            // destination of a delivered message IS this hub.
            const wchar_t* id  = pMsg->c_name();
            const wchar_t* src = pMsg->GetSource();
            //  COPY both immediately.  Off Win32 c_name()/GetSource() end in
            //  p2p_wstr_from_store(), whose result lives in a 16-entry
            //  thread-local RING recycled by the next handful of accessor calls
            //  (Platform/p2pstr.h:629-651).  Two of those pointers are live at
            //  once here and both are then handed to fnW - APPLICATION code,
            //  which may call any number of accessors (a sink that replies goes
            //  through SetSource(), itself a ring call) before it reads them.
            //  This is the P2Pwin32.cpp:4138/4179 hardening applied to the C ABI.
            //  Null-ness is preserved exactly, because the refusal reads below
            //  (src ? src : L"") depend on it.  Byte-identical on Win32.
            const std::wstring sId  = id  ? id  : L"";
            const std::wstring sSrc = src ? src : L"";
            id  = id  ? sId .c_str() : nullptr;
            src = src ? sSrc.c_str() : nullptr;
            const void*    dat = pMsg->Data();
            const int64_t  sz  = static_cast<int64_t>(pMsg->DataSize());
            // c_wstr(), not c_name(): c_name() returns only the LEAF hub name
            // ("SinkHub", not "UnitMesh.SinkHub") and it derives that leaf by
            // rewriting a mutable member behind a const_cast — a data race if two
            // threads ask an address for its name. c_wstr() returns the full
            // address and only reads.
            const wchar_t* dst = GetP2PaddrHub().c_wstr();

            if (fnW)
                consumed |= fnW(m_ctxW, src ? src : L"", dst ? dst : L"",
                                       id  ? id  : L"", dat, sz);
            if (fnU)
            {
                const std::string s = WtoU8str(src);
                const std::string d = WtoU8str(dst);
                const std::string i = WtoU8str(id);
                consumed |= fnU(m_ctxU, s.c_str(), d.c_str(), i.c_str(), dat, sz);
            }
        }
        catch (...)
        {
            // The accessors signal failure by throwing P2Pevent. A throw must
            // never cross back into the pump from here; treat it as "not
            // consumed" and let the compiled map have the message.
            return false;
        }
        return consumed != 0;
    }

    std::atomic<P2PeerHubSinkFn>   m_fnW{nullptr};
    void*                          m_ctxW{nullptr};
    std::atomic<P2PeerHubSinkFnU8> m_fnU{nullptr};
    void*                          m_ctxU{nullptr};
};

// dynamic_cast, not static_cast: it yields null for a handle this API did not
// create instead of scribbling on an unrelated object. It is now reached only
// with a pointer the registry has already proved is a live hub, so the
// dynamic_cast answers the narrower question "is this hub one of OURS" — a
// P2PeerHub that some future entry point registered without the sink storage.
static inline CSinkHub* sink_hub(P2PeerHubHandle h)
{
    return dynamic_cast<CSinkHub*>(hub(h));
}

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle (P2Pmsg environment)
// StartupP2Pmsg initialises the shared hub/pump critical sections and the hub
// manager table; it MUST run once before any P2PeerHub operation, otherwise
// CreateP2PmsgHub enters uninitialised critical sections and crashes. Every
// native consumer calls it; the C/Panama surface needs its own entry point.
//
// Every entry point below is wrapped in try/catch for the same reason this one
// always was: the underlying code signals errors by throwing P2Pevent, and a C++
// exception unwinding across the extern "C" ABI is undefined behaviour for the
// FFI caller — a Panama downcall has no landing pad, and the process is gone
// before any Java-side handler sees it. Before M1 only three of the 54 entry
// points here caught, so a perfectly VALID handle could still take the process
// down; validating handles without adding the catch would have been half a fix.
// ─────────────────────────────────────────────────────────────────────────────

int targetcore_startup(unsigned int nMaxHubs)
{
    try            { return StartupP2Pmsg(nMaxHubs) ? 1 : 0; }
    catch (...)    { return 0; }
}

void targetcore_cleanup(void)
{
    // The handle registry is deliberately NOT cleared here. CleanupP2Pmsg tears
    // down the kernel, not the caller's objects: the P2Paddr and P2PeerMsg
    // handles a consumer still holds remain its property to destroy, and
    // dropping them here would turn every subsequent p2paddr_destroy into a
    // silent leak.
    try            { CleanupP2Pmsg(); }
    catch (...)    { /* best-effort teardown */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// P2Paddr
// ─────────────────────────────────────────────────────────────────────────────

P2PAddrHandle p2paddr_create()
{
    P2Paddr* p = nullptr;
    try         { p = new P2Paddr(); return P2PhandleAdd(p, P2PhandleKind_Addr); }
    catch (...) { delete p; return nullptr; }
}

P2PAddrHandle p2paddr_create_str(const wchar_t* strAddr)
{
    if (!strAddr) return nullptr;
    P2Paddr* p = nullptr;
    try         { p = new P2Paddr(strAddr); return P2PhandleAdd(p, P2PhandleKind_Addr); }
    catch (...) { delete p; return nullptr; }
}

void p2paddr_destroy(P2PAddrHandle h)
{
    // Forget FIRST and delete only if this call is the one that removed the
    // entry. A second destroy of the same handle — and a concurrent one — then
    // finds nothing and does nothing, instead of double-freeing.
    P2Paddr* p = addr(h);
    if (!p || !P2PhandleForget(h, P2PhandleKind_Addr)) return;
    // The try is uniformity, not protection: a destructor is implicitly noexcept,
    // so a throw out of one terminates before this catch could see it. The guard
    // that matters on a destroy entry point is the forget-once above.
    try         { delete p; }
    catch (...) { }
}

const wchar_t* p2paddr_c_name(P2PAddrHandle h)
{
    P2Paddr* p = addr(h);
    if (!p) return nullptr;
    try         { return p->c_name(); }
    catch (...) { return nullptr; }
}

int p2paddr_is_null(P2PAddrHandle h)
{
    // 1, not 0, for a handle we do not know — the same conservative answer
    // Msgcore_c.cpp gives (msgcore_field_is_null, :416). "Null" is the reading
    // that makes a caller stop; reporting a refused handle as a usable address
    // sends it on to the next call with the same bad pointer.
    P2Paddr* p = addr(h);
    if (!p) return 1;
    try         { return p->IsNull() ? 1 : 0; }
    catch (...) { return 1; }
}

int p2paddr_is_empty(P2PAddrHandle h)
{
    P2Paddr* p = addr(h);
    if (!p) return 1;
    try         { return p->IsEmpty() ? 1 : 0; }
    catch (...) { return 1; }
}

uint32_t p2paddr_sizeof(P2PAddrHandle h)
{
    P2Paddr* p = addr(h);
    if (!p) return 0;
    try         { return p->Sizeof(); }
    catch (...) { return 0; }
}

int p2paddr_is_child(P2PAddrHandle h, const wchar_t* strAddr)
{
    // 0 here, unlike is_null above: this one asserts a RELATIONSHIP, and a
    // refused handle must never be the reason a caller believes one holds.
    P2Paddr* p = addr(h);
    if (!p || !strAddr) return 0;
    try         { return p->IsChild(strAddr) ? 1 : 0; }
    catch (...) { return 0; }
}

int p2paddr_is_rable(P2PAddrHandle h, const wchar_t* strAddr)
{
    P2Paddr* p = addr(h);
    if (!p || !strAddr) return 0;
    try         { return p->IsRable(strAddr) ? 1 : 0; }
    catch (...) { return 0; }
}

// ─────────────────────────────────────────────────────────────────────────────
// P2PeerMsg
// ─────────────────────────────────────────────────────────────────────────────

P2PeerMsgHandle p2peermsg_create()
{
    P2PeerMsg* p = nullptr;
    try         { p = new P2PeerMsg(); return P2PhandleAdd(p, P2PhandleKind_Msg); }
    catch (...) { delete p; return nullptr; }
}

P2PeerMsgHandle p2peermsg_create_full(const wchar_t* src,
                                       const wchar_t* dst,
                                       const wchar_t* msgID,
                                       const void*    data,
                                       uint32_t       dataSize)
{
    if (!src || !dst || !msgID) return nullptr;
    if (dataSize && !data)      return nullptr;   // a size with no bytes behind it
    P2PeerMsg* p = nullptr;
    try
    {
        p = new P2PeerMsg(src, dst, msgID, data, static_cast<P2Psize_t>(dataSize));
        return P2PhandleAdd(p, P2PhandleKind_Msg);
    }
    catch (...) { delete p; return nullptr; }
}

P2PeerMsgHandle p2peermsg_create_msgid(const wchar_t* msgID)
{
    if (!msgID) return nullptr;
    P2PeerMsg* p = nullptr;
    try         { p = new P2PeerMsg(msgID); return P2PhandleAdd(p, P2PhandleKind_Msg); }
    catch (...) { delete p; return nullptr; }
}

void p2peermsg_destroy(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p || !P2PhandleForget(h, P2PhandleKind_Msg)) return;
    try         { delete p; }        // see p2paddr_destroy on the catch
    catch (...) { }
}

// The three wide getters below COPY before returning, and must keep doing so.
// GetSource()/GetDestin()/c_name() all end in p2p_wstr_from_store(), which off
// Win32 hands back a slot of a 16-entry thread-local widening RING recycled by
// the next handful of accessor calls (Platform/p2pstr.h:629-651). Returning that
// raw across the C ABI would give every C/Python/PHP caller a pointer that dies
// silently on Linux the moment it reads a second message - the exact shape of
// the P2PeerHub::RouteP2PeerMsg defect. The per-thread std::wstring makes the
// contract the _u8 twins already document (TargetCore_c.h:248-249) true for the
// wchar_t getters too, and matches Msgcore_c.cpp:1670-1685, which does the same
// for the same reason. Win32 is unaffected either way.
const wchar_t* p2peermsg_get_source(P2PeerMsgHandle h)
{
    static thread_local std::wstring s_strSource;
    P2PeerMsg* p = msg(h);
    if (!p) return nullptr;
    try         { const wchar_t* psz = p->GetSource();
                  if (!psz) return nullptr;
                  s_strSource = psz;
                  return s_strSource.c_str(); }
    catch (...) { return nullptr; }
}

void p2peermsg_set_source(P2PeerMsgHandle h, const wchar_t* src)
{
    P2PeerMsg* p = msg(h);
    if (!p || !src) return;
    try         { p->SetSource(src); }
    catch (...) { /* void return: the refusal IS the absence of the write */ }
}

const wchar_t* p2peermsg_get_destin(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p) return nullptr;
    static thread_local std::wstring s_strDestin;
    try         { const wchar_t* psz = p->GetDestin();
                  if (!psz) return nullptr;
                  s_strDestin = psz;
                  return s_strDestin.c_str(); }
    catch (...) { return nullptr; }
}

void p2peermsg_set_destin(P2PeerMsgHandle h, const wchar_t* dst)
{
    P2PeerMsg* p = msg(h);
    if (!p || !dst) return;
    try         { p->SetDestin(dst); }
    catch (...) { }
}

const wchar_t* p2peermsg_c_name(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p) return nullptr;
    static thread_local std::wstring s_strName;
    try         { const wchar_t* psz = p->c_name();
                  if (!psz) return nullptr;
                  s_strName = psz;
                  return s_strName.c_str(); }
    catch (...) { return nullptr; }
}

const char* p2peermsg_data(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p) return nullptr;
    try         { return p->Data(); }
    catch (...) { return nullptr; }
}

int64_t p2peermsg_data_size(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p) return 0;
    try         { return static_cast<int64_t>(p->DataSize()); }
    catch (...) { return 0; }
}

unsigned char p2peermsg_priority(P2PeerMsgHandle h)
{
    // 0 is P2PeerPriFlush, a real priority, so the numeric failure value is not
    // distinguishable here — the same ambiguity Msgcore_c.cpp accepts for its
    // width-typed getters. A caller that must tell "flush" from "refused" has to
    // establish the handle is live first, which is what every other call does.
    P2PeerMsg* p = msg(h);
    if (!p) return 0;
    try         { return p->Priority(); }
    catch (...) { return 0; }
}

unsigned char p2peermsg_set_priority(P2PeerMsgHandle h, unsigned char pri)
{
    P2PeerMsg* p = msg(h);
    if (!p) return 0;
    try         { return p->SetPriority(pri); }
    catch (...) { return 0; }
}

uint32_t p2peermsg_sizeof(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p) return 0;
    try         { return p->Sizeof(); }
    catch (...) { return 0; }
}

int p2peermsg_is_wrapped(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p) return 0;
    try         { return p->IsWrapped() ? 1 : 0; }
    catch (...) { return 0; }
}

int p2peermsg_is_reflected(P2PeerMsgHandle h)
{
    P2PeerMsg* p = msg(h);
    if (!p) return 0;
    try         { return p->IsReflected() ? 1 : 0; }
    catch (...) { return 0; }
}

P2PeerMsgHandle p2peermsg_response_factory(P2PeerMsgHandle h,
                                            const wchar_t*  msgID,
                                            const void*     data,
                                            uint32_t        dataSize)
{
    P2PeerMsg* p = msg(h);
    if (!p || !msgID)      return nullptr;
    if (dataSize && !data) return nullptr;
    try
    {
        // The factory's result is a handle the caller must destroy, so it is
        // registered exactly like a create_* result. Missing that registration
        // would make every response message a stranger to its own destroy.
        return P2PhandleAdd(p->ResponseFactory(msgID, data, static_cast<P2Psize_t>(dataSize)),
                            P2PhandleKind_Msg);
    }
    catch (...) { return nullptr; }
}

P2PeerMsgHandle p2peermsg_redirect_factory(P2PeerMsgHandle h, const wchar_t* dstAddr)
{
    P2PeerMsg* p = msg(h);
    if (!p || !dstAddr) return nullptr;
    try         { return P2PhandleAdd(p->RedirectFactory(dstAddr), P2PhandleKind_Msg); }
    catch (...) { return nullptr; }
}

// ─────────────────────────────────────────────────────────────────────────────
// P2PeerConWsa
// ─────────────────────────────────────────────────────────────────────────────

P2PeerConWsaHandle p2peerconwsa_client_factory(const wchar_t* strThatAddr,
                                                const wchar_t* ipAddress,
                                                short          port)
{
    if (!strThatAddr || !ipAddress) return nullptr;
    P2PeerConWsa* p = nullptr;
    try
    {
        p = P2PeerConWsa::ClientFactory(strThatAddr, ipAddress, port);
        return P2PhandleAdd(p, P2PhandleKind_Wsa);
    }
    catch (...) { delete p; return nullptr; }
}

P2PeerConWsaHandle p2peerconwsa_service_factory(const wchar_t* strThatAddr,
                                                 short          port)
{
    if (!strThatAddr) return nullptr;
    P2PeerConWsa* p = nullptr;
    try
    {
        p = P2PeerConWsa::ServiceFactory(strThatAddr, port);
        return P2PhandleAdd(p, P2PhandleKind_Wsa);
    }
    catch (...) { delete p; return nullptr; }
}

void p2peerconwsa_destroy(P2PeerConWsaHandle h)
{
    P2PeerConWsa* p = wsa(h);
    if (!p || !P2PhandleForget(h, P2PhandleKind_Wsa)) return;
    try         { delete p; }
    catch (...) { }
}

int p2peerconwsa_connect(P2PeerConWsaHandle h)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return 0;
    try         { return p->Connect() ? 1 : 0; }
    catch (...) { return 0; }
}

int p2peerconwsa_listen(P2PeerConWsaHandle h)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return 0;
    try         { return p->Listen() ? 1 : 0; }
    catch (...) { return 0; }
}

void p2peerconwsa_close(P2PeerConWsaHandle h)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return;
    try         { p->Close(); }
    catch (...) { }
}

unsigned long p2peerconwsa_get_state(P2PeerConWsaHandle h, unsigned long mask)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return 0;
    try         { return p->GetState(static_cast<DWORD>(mask)); }
    catch (...) { return 0; }
}

int p2peerconwsa_has_state(P2PeerConWsaHandle h, unsigned long mask)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return 0;
    try         { return p->HasState(static_cast<DWORD>(mask)) ? 1 : 0; }
    catch (...) { return 0; }
}

int p2peerconwsa_get_mode(P2PeerConWsaHandle h)
{
    // 0 is P2PeerConMode "Unknown", which the header already documents — the one
    // place in this file where the failure value is a named part of the contract
    // rather than a convention.
    P2PeerConWsa* p = wsa(h);
    if (!p) return 0;
    try         { return static_cast<int>(p->GetMode()); }
    catch (...) { return 0; }
}

const wchar_t* p2peerconwsa_get_address(P2PeerConWsaHandle h)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return nullptr;
    try         { return p->GetP2Paddress().c_name(); }
    catch (...) { return nullptr; }
}

// What this socket can vouch for: 0 wire, 1 local, 2 in-process.
//
// EffectiveTrust() rather than TrustClass(), because this is the value the
// hub's per-class link policy is actually read with, and a diagnostic that
// reported the transport's answer while the gate used a demoted one would be
// the kind of disagreement the posture accessors exist to prevent.
//
// 0 on a null handle or a throw. Wire is the fail-closed answer everywhere
// else in this feature and it is the answer here.
int p2peerconwsa_get_trust_class(P2PeerConWsaHandle h)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return (int)P2PeerConTrust_Wire;
    try         { return (int)p->EffectiveTrust(); }
    catch (...) { return (int)P2PeerConTrust_Wire; }
}

// Hold this connection to no better than the given class. TIGHTENS ONLY: a
// call naming a class above the one already in force does nothing, and there
// is deliberately no promote. A class this build does not have is ignored by
// the same rule.
void p2peerconwsa_demote_trust(P2PeerConWsaHandle h, int trustClass)
{
    P2PeerConWsa* p = wsa(h);
    if (!p) return;
    try         { p->DemoteTrust((P2PeerConTrust_e)trustClass); }
    catch (...) { }
}

P2PeerMsgHandle p2peerconwsa_post_msg(P2PeerConWsaHandle h, P2PeerMsgHandle m)
{
    // Return contract (unchanged): null means posted, non-null means NOT posted.
    P2PeerConWsa* p    = wsa(h);
    P2PeerMsg*    pMsg = msg(m);
    if (!p || !pMsg) return m;   // nothing was consumed; the caller still owns m

    // Ownership leaves the C caller HERE, not on success: the queue append takes
    // the message before it can fail, so a throw does not hand it back. Forget it
    // first, which is what makes a caller's mistaken p2peermsg_destroy afterwards
    // a refusal rather than a double free.
    P2PhandleForget(m, P2PhandleKind_Msg);
    try         { return P2PhandleAdd(p->PostP2PeerMsg(pMsg), P2PhandleKind_Msg); }
    catch (...) { return m; }    // not delivered; the handle is dead and unregistered
}

// ─────────────────────────────────────────────────────────────────────────────
// P2PeerHub
// ─────────────────────────────────────────────────────────────────────────────

P2PeerHubHandle p2peerhub_create(const wchar_t* strAddr)
{
    // CSinkHub, not P2PeerHub, so p2peerhub_set_sink[_u8] works on any handle
    // this API produced. With no sink registered it is behaviourally identical
    // to the bare P2PeerHub it replaces. P2PeerHub's destructor is virtual, so
    // p2peerhub_destroy's delete through the base pointer stays correct.
    if (!strAddr) return nullptr;
    CSinkHub* p = nullptr;
    try         { p = new CSinkHub(strAddr); return P2PhandleAdd(p, P2PhandleKind_Hub); }
    catch (...) { delete p; return nullptr; }
}

void p2peerhub_destroy(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p || !P2PhandleForget(h, P2PhandleKind_Hub)) return;
    try         { delete p; }
    catch (...) { }
}

int p2peerhub_create_hub(P2PeerHubHandle h,
                          const wchar_t*  strAddr,
                          unsigned int    pumpsMax)
{
    // Catch so a P2Pevent (e.g. the "environment not started" guard in
    // CreateP2PmsgHub) surfaces as a clean 0 return rather than unwinding a
    // C++ exception across the extern "C" ABI (UB for the Panama caller).
    P2PeerHub* p = hub(h);
    if (!p || !strAddr) return 0;
    try         { return p->CreateHub(strAddr, pumpsMax) ? 1 : 0; }
    catch (...) { return 0; }
}

void* p2peerhub_spawn_hub(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return nullptr;
    try         { return p->SpawnHub(); }
    catch (...) { return nullptr; }
}

void p2peerhub_close_hub(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->CloseHub(); }
    catch (...) { }
}

void p2peerhub_pause_hub(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->PauseHub(); }
    catch (...) { }
}

void p2peerhub_wakeup_hub(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->WakeupHub(); }
    catch (...) { }
}

// ── P2PeerHub peer authentication (Stage 3 step 8) ──────────
// The flat C surface had no auth entry points at all, which stopped being
// survivable the moment RequireAuth defaulted to on: a C consumer's hub would
// have refused to arm with no way, through this header, to provision it or to
// opt out. Same swallow-everything contract as the rest of the file - a
// P2Pevent must not unwind across the extern "C" ABI.
//
// The IdResult / ArmResult enums cross as ints. That is deliberate: an FFI
// consumer cannot see the C++ enum, and the numbers are documented in the
// header rather than left to be guessed at.

void p2peerhub_require_auth(P2PeerHubHandle h, int require)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->RequireAuth(require != 0); }
    catch (...) { }
}

int p2peerhub_is_auth_required(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return 0;
    try         { return p->IsAuthRequired() ? 1 : 0; }
    catch (...) { return 0; }
}

// The per-trust-class link policy. Both enums cross as ints for the reason
// IdResult and ArmResult do - an FFI consumer cannot see a C++ enum - and the
// numbers are written down in the header.
//
// A trust class this build does not have, and the wire class, are ignored by
// P2PeerHub::SetLinkPolicy rather than reported. That is the C++ contract and
// this does not invent a second one: a flat-C caller that could distinguish
// "refused because it is the wire" from "accepted" would be reading a decision
// the C++ surface does not expose either, and the posture reports what was
// actually set.
void p2peerhub_set_link_policy(P2PeerHubHandle h, int trustClass, int policy)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->SetLinkPolicy((P2PeerConTrust_e)trustClass,
                                   (P2PeerLinkPolicy_e)policy); }
    catch (...) { }
}

// 0 full, 1 open. A null handle answers 0, which is the same fail-closed
// reading a hub with no policy object gives: what cannot be read demands
// everything.
int p2peerhub_get_link_policy(P2PeerHubHandle h, int trustClass)
{
    P2PeerHub* p = hub(h);
    if (!p) return (int)P2PeerLinkPolicy_Full;
    try         { return (int)p->GetLinkPolicy((P2PeerConTrust_e)trustClass); }
    catch (...) { return (int)P2PeerLinkPolicy_Full; }
}

// The fence. An out-of-range class is ignored one layer down, in
// AuthPolicy::SetTrustFloor, so this entry point and the C++ one cannot come
// apart on it - the same arrangement set_link_policy has with the wire class.
void p2peerhub_require_trust_at_least(P2PeerHubHandle h, int trustClass)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->RequireTrustAtLeast((P2PeerConTrust_e)trustClass); }
    catch (...) { }
}

// 0 wire (no fence), 1 local, 2 in-process. A null handle answers 0, which is
// the reading that changes nothing: it is what an unconfigured hub reports, and
// the opposite direction from get_link_policy's fail-closed 0 for the reason
// written out at P2PeerHub::GetRequiredTrust - there the strict answer DEMANDS
// a handshake, here it would REFUSE a link nobody fenced out.
int p2peerhub_get_required_trust(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return (int)P2PeerConTrust_Wire;
    try         { return (int)p->GetRequiredTrust(); }
    catch (...) { return (int)P2PeerConTrust_Wire; }
}

int p2peerhub_set_identity(P2PeerHubHandle h, const char* pathUtf8, int createIfAbsent)
{
    P2PeerHub* p = hub(h);
    if (!p || !pathUtf8) return (int)p2pcng::IdErrArgs;
    try         { return (int)p->SetIdentity(pathUtf8, createIfAbsent != 0); }
    catch (...) { return (int)p2pcng::IdErrIo; }
}

int p2peerhub_set_allow_list(P2PeerHubHandle h, const char* pathUtf8)
{
    P2PeerHub* p = hub(h);
    if (!p || !pathUtf8) return (int)p2pcng::IdErrArgs;
    try         { return (int)p->SetAllowList(pathUtf8); }
    catch (...) { return (int)p2pcng::IdErrIo; }
}

int p2peerhub_reload_allow_list(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return (int)p2pcng::IdErrArgs;
    try         { return (int)p->ReloadAllowList(); }
    catch (...) { return (int)p2pcng::IdErrIo; }
}

int p2peerhub_provision_auth(P2PeerHubHandle h, const char* pathUtf8,
                              char* fingerprintOut, unsigned long cchFingerprintOut,
                              int* pCreated)
{
    P2PeerHub* p = hub(h);
    if (!p || !pathUtf8) return (int)p2pcng::IdErrArgs;
    try
    {
      bool bCreated = false;
      p2pcng::IdResult e = p->ProvisionAuth(pathUtf8, fingerprintOut,
                                            (size_t)cchFingerprintOut, &bCreated);
      if (pCreated) *pCreated = bCreated ? 1 : 0;
      return (int)e;
    }
    catch (...) { return (int)p2pcng::IdErrIo; }
}

int p2peerhub_auth_arm(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    //  A handle that is not a hub reports ArmNotRequired rather than a
    //  provisioning failure: there is no hub here to provision, and reporting
    //  a missing key file would send the caller to fix the wrong thing.
    if (!p) return (int)p2pauth::ArmNotRequired;
    try         { return (int)p->AuthArm(); }
    catch (...) { return (int)p2pauth::ArmNotRequired; }
}

const char* p2peerhub_auth_arm_text(int armResult)
{
    try         { return p2pauth::AuthArmText((p2pauth::ArmResult)armResult); }
    catch (...) { return "unknown arm result"; }
}

const char* p2peerhub_auth_allow_list_path(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return nullptr;
    try         { return p->AuthAllowListPath(); }
    catch (...) { return nullptr; }
}

const char* p2peerhub_auth_revocation_list_path(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return nullptr;
    try         { return p->AuthRevocationListPath(); }
    catch (...) { return nullptr; }
}

void p2peerhub_require_revocation(P2PeerHubHandle h, int require)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->RequireRevocation(require != 0); }
    catch (...) { }
}

int p2peerhub_is_revocation_required(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return 0;
    try         { return p->IsRevocationRequired() ? 1 : 0; }
    catch (...) { return 0; }
}

int p2peerhub_set_revocation_list(P2PeerHubHandle h, const char* pathUtf8)
{
    P2PeerHub* p = hub(h);
    if (!p || !pathUtf8) return (int)p2pcng::IdErrArgs;
    try         { return (int)p->SetRevocationList(pathUtf8); }
    catch (...) { return (int)p2pcng::IdErrIo; }
}

void p2peerhub_require_seal(P2PeerHubHandle h, int require)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->RequireSeal(require != 0); }
    catch (...) { }
}

int p2peerhub_is_seal_required(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return 0;
    try         { return p->IsSealRequired() ? 1 : 0; }
    catch (...) { return 0; }
}

int p2peerhub_set_agreement_key(P2PeerHubHandle h, const char* pathUtf8,
                                 int createIfAbsent)
{
    P2PeerHub* p = hub(h);
    if (!p || !pathUtf8) return (int)p2pcng::IdErrArgs;
    try         { return (int)p->SetAgreementKey(pathUtf8, createIfAbsent != 0); }
    catch (...) { return (int)p2pcng::IdErrIo; }
}

int p2peerhub_add_seal_reader(P2PeerHubHandle h, const wchar_t* addr)
{
    P2PeerHub* p = hub(h);
    if (!p || !addr) return (int)p2pcng::IdErrArgs;
    try         { return (int)p->AddSealReader(addr); }
    catch (...) { return (int)p2pcng::IdErrIo; }
}

void p2peerhub_clear_seal_readers(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return;
    try         { p->ClearSealReaders(); }
    catch (...) { }
}

int p2peerhub_post_con(P2PeerHubHandle    h,
                        P2PeerConWsaHandle con,
                        unsigned int       pumpID)
{
    P2PeerHub*    p    = hub(h);
    P2PeerConWsa* pCon = wsa(con);
    if (!p || !pCon) return 0;
    try
    {
        // FALSE is a refusal BEFORE the hub takes the connection (hub not
        // running, or a duplicate address), so the caller keeps it and the
        // handle stays registered — dropping it there would strand an object
        // nothing can free.
        if (!p->PostP2PeerCon(pCon, static_cast<P2PumpID>(pumpID)))
            return 0;
    }
    catch (...)
    {
        // Every throw path inside PostP2PeerCon is downstream of PostP2PmsgCon,
        // i.e. the hub is already holding this connection. Forget the handle so
        // a caller tidying up after the failure cannot destroy it underneath the
        // hub's pump.
        P2PhandleForget(con, P2PhandleKind_Wsa);
        return 0;
    }
    // Posted: ownership is the hub's, as the header says. Forget it so a later
    // p2peerconwsa_destroy is refused instead of freeing a live connection.
    P2PhandleForget(con, P2PhandleKind_Wsa);
    return 1;
}

int p2peerhub_con_exists(P2PeerHubHandle h, const wchar_t* addr_str)
{
    P2PeerHub* p = hub(h);
    if (!p || !addr_str) return 0;
    try         { return p->ConExists(addr_str) ? 1 : 0; }
    catch (...) { return 0; }
}

P2PeerMsgHandle p2peerhub_post_msg(P2PeerHubHandle h, P2PeerMsgHandle m)
{
    // Return contract (unchanged): null means posted, non-null means NOT posted.
    P2PeerHub* p    = hub(h);
    P2PeerMsg* pMsg = msg(m);
    if (!p || !pMsg) return m;   // nothing was consumed; the caller still owns m

    // PostP2Pmsg wraps the message in an owning P2PeerMsgSP before its first
    // failure check (P2Pwin32.cpp:4795), so the message is consumed whether it
    // reaches the queue or throws. Forget it first — see p2peerconwsa_post_msg.
    P2PhandleForget(m, P2PhandleKind_Msg);
    try         { return P2PhandleAdd(p->PostP2PeerMsg(pMsg), P2PhandleKind_Msg); }
    catch (...) { return m; }
}

unsigned long p2peerhub_get_hub_id(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return 0;
    try         { return static_cast<unsigned long>(p->GetHubID()); }
    catch (...) { return 0; }
}

const wchar_t* p2peerhub_get_address(P2PeerHubHandle h)
{
    P2PeerHub* p = hub(h);
    if (!p) return nullptr;
    try         { return p->GetP2PaddrHub().c_name(); }
    catch (...) { return nullptr; }
}

// ─────────────────────────────────────────────────────────────────────────────
// P2PeerHub receive sink
// Both entry points live here (not in TargetCore_c_u8.cpp with the other _u8
// twins) because they share CSinkHub's storage rather than delegating.
// ─────────────────────────────────────────────────────────────────────────────

int p2peerhub_set_sink(P2PeerHubHandle h, P2PeerHubSinkFn fn, void* ctx)
{
    CSinkHub* p = sink_hub(h);
    if (!p) return 0;
    try         { p->SetSink(fn, ctx); return 1; }
    catch (...) { return 0; }
}

int p2peerhub_set_sink_u8(P2PeerHubHandle h, P2PeerHubSinkFnU8 fn, void* ctx)
{
    CSinkHub* p = sink_hub(h);
    if (!p) return 0;
    try         { p->SetSinkU8(fn, ctx); return 1; }
    catch (...) { return 0; }
}
