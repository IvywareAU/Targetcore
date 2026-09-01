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
// TargetCore_c_u8.cpp  –  UTF-8 (_u8) parallel entry points for the Panama bridge
// Each _u8 function converts its UTF-8 strings to
// the platform-native wchar_t and delegates to the matching wchar_t p2p*_c entry
// point — no new object-model logic. Conversion via MultiByteToWideChar /
// WideCharToMultiByte with CP_UTF8: genuine Win32 on Windows (wchar_t = UTF-16),
// Platform shim on Linux (wchar_t = UTF-32); one path, correct incl. astral.
//
// Compiles as part of TargetCore.dll (TargetCore_EXPORTS via project settings).
// stdafx.h MUST be first (PCH); it also brings in MultiByteToWideChar/
// WideCharToMultiByte (windows.h on Windows, the Platform shim on Linux).

#include "stdafx.h"          // precompiled header – must be first
#include "TargetCore_c.h"

#include <string>

// --- boundary conversion (same contract as Msgcore_c_u8.cpp) ---------------
static std::wstring U8toW(const char* s)
{
    if (!s || !*s) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 1) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    w.resize((size_t)n - 1);
    return w;
}
static const char* WtoU8(const wchar_t* w)
{
    thread_local std::string tls;
    if (!w) return nullptr;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) { tls.clear(); return tls.c_str(); }
    tls.resize((size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &tls[0], n, nullptr, nullptr);
    tls.resize((size_t)n - 1);
    return tls.c_str();
}

extern "C" {

// --- P2Paddr ---------------------------------------------------------------
P2PC_API P2PAddrHandle p2paddr_create_str_u8(const char* a)
{ return p2paddr_create_str(U8toW(a).c_str()); }
P2PC_API const char* p2paddr_c_name_u8(P2PAddrHandle h)
{ return WtoU8(p2paddr_c_name(h)); }
P2PC_API int p2paddr_is_child_u8(P2PAddrHandle h, const char* a)
{ return p2paddr_is_child(h, U8toW(a).c_str()); }
P2PC_API int p2peerhub_add_seal_reader_u8(P2PeerHubHandle h, const char* addrUtf8)
{ return addrUtf8 ? p2peerhub_add_seal_reader(h, U8toW(addrUtf8).c_str()) : -1; }

P2PC_API int p2paddr_is_rable_u8(P2PAddrHandle h, const char* a)
{ return p2paddr_is_rable(h, U8toW(a).c_str()); }

// --- P2PeerMsg -------------------------------------------------------------
P2PC_API P2PeerMsgHandle p2peermsg_create_full_u8(const char* src, const char* dst,
                                                  const char* msgID, const void* data,
                                                  uint32_t    dataSize)
{ std::wstring s = U8toW(src), d = U8toW(dst), m = U8toW(msgID);
  return p2peermsg_create_full(s.c_str(), d.c_str(), m.c_str(), data, dataSize); }
P2PC_API P2PeerMsgHandle p2peermsg_create_msgid_u8(const char* m)
{ return p2peermsg_create_msgid(U8toW(m).c_str()); }
P2PC_API const char* p2peermsg_get_source_u8(P2PeerMsgHandle h)
{ return WtoU8(p2peermsg_get_source(h)); }
P2PC_API void p2peermsg_set_source_u8(P2PeerMsgHandle h, const char* s)
{ p2peermsg_set_source(h, U8toW(s).c_str()); }
P2PC_API const char* p2peermsg_get_destin_u8(P2PeerMsgHandle h)
{ return WtoU8(p2peermsg_get_destin(h)); }
P2PC_API void p2peermsg_set_destin_u8(P2PeerMsgHandle h, const char* d)
{ p2peermsg_set_destin(h, U8toW(d).c_str()); }
P2PC_API const char* p2peermsg_c_name_u8(P2PeerMsgHandle h)
{ return WtoU8(p2peermsg_c_name(h)); }
P2PC_API P2PeerMsgHandle p2peermsg_response_factory_u8(P2PeerMsgHandle h, const char* m,
                                                       const void* data, uint32_t    dataSize)
{ return p2peermsg_response_factory(h, U8toW(m).c_str(), data, dataSize); }
P2PC_API P2PeerMsgHandle p2peermsg_redirect_factory_u8(P2PeerMsgHandle h, const char* d)
{ return p2peermsg_redirect_factory(h, U8toW(d).c_str()); }

// --- P2PeerConWsa ----------------------------------------------------------
P2PC_API P2PeerConWsaHandle p2peerconwsa_client_factory_u8(const char* that, const char* ip, short port)
{ std::wstring t = U8toW(that), i = U8toW(ip); return p2peerconwsa_client_factory(t.c_str(), i.c_str(), port); }
P2PC_API P2PeerConWsaHandle p2peerconwsa_service_factory_u8(const char* that, short port)
{ return p2peerconwsa_service_factory(U8toW(that).c_str(), port); }
P2PC_API const char* p2peerconwsa_get_address_u8(P2PeerConWsaHandle h)
{ return WtoU8(p2peerconwsa_get_address(h)); }

// --- P2PeerHub -------------------------------------------------------------
P2PC_API P2PeerHubHandle p2peerhub_create_u8(const char* a)
{ return p2peerhub_create(U8toW(a).c_str()); }
P2PC_API int p2peerhub_create_hub_u8(P2PeerHubHandle h, const char* a, unsigned int pumpsMax)
{ return p2peerhub_create_hub(h, U8toW(a).c_str(), pumpsMax); }
P2PC_API int p2peerhub_con_exists_u8(P2PeerHubHandle h, const char* a)
{ return p2peerhub_con_exists(h, U8toW(a).c_str()); }
P2PC_API const char* p2peerhub_get_address_u8(P2PeerHubHandle h)
{ return WtoU8(p2peerhub_get_address(h)); }
// p2peerhub_set_sink_u8 is the one _u8 entry point NOT defined here: it shares
// CSinkHub's sink storage instead of delegating to the wchar_t twin, and it needs
// three converted strings live at once (WtoU8 above returns into a single
// thread_local buffer). See TargetCore_c.cpp.

} // extern "C"
