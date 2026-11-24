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
//  PRIVATE to Targetcore: what the shared-memory handshake (P2PeerConShm) hands the io
//  object (P2PeerioShm). Not installed, not included by any public header, so the
//  Msgcore Platform shim (p2pshm.h) stays out of Targetcore's public surface.
//  p2p_performance.md §6.3a.
//
#pragma once
#include "P2Peerio.h"
#include "../Msgcore/Platform/p2pshm.h"

#if defined(_WIN32)
typedef HANDLE P2PshmPeerWake;
#define P2PSHM_NO_PEER_WAKE nullptr
#else
typedef int    P2PshmPeerWake;
#define P2PSHM_NO_PEER_WAKE (-1)
#endif

struct P2PeerioShmState
{
    // The link. Owned: closed by the destructor
    p2pshm::Mapping  map;
    p2pshm::Ring    *in   = nullptr;           // the peer writes, we read
    p2pshm::Ring    *out  = nullptr;           // we write, the peer reads
    p2pshm::Wake     mine;                     // the peer signals it, our port receives it
    P2PshmPeerWake   peer = P2PSHM_NO_PEER_WAKE;   // we signal it

    // The pump this connection completes on, and the pipe it was set up over (NOT owned:
    // the connection's m_hFile). Filled in by P2PeerConShm at attach
    HANDLE           port  = nullptr;
    ULONG_PTR        key   = 0;
    HANDLE           hPipe = nullptr;

    // The io object's own OVERLAPPEDcons, made by the connection's MakeOVERLAPPED.
    // NOT owned by this struct: P2PeerioShm gives them back (DropOVERLAPPED) or the
    // teardown drain frees them (P2PeerCon::DrainOVERLAPPED, after ForgetOwnOVERLAPPED)
    OVERLAPPEDcon   *pWakeOv  = nullptr;
    OVERLAPPEDcon   *pDeathOv = nullptr;
    bool             wakeArmed  = false;       // pWakeOv is with the port
    bool             deathArmed = false;       // pDeathOv's 1-byte pipe read is outstanding
    BYTE             deathByte  = 0;

    // The one read and the one write the connection may have outstanding (Send/Recv
    // never overlap themselves): parked here while the ring is empty / full
    OVERLAPPED      *rOv   = nullptr;
    BYTE            *rBuf  = nullptr;
    DWORD            rCap  = 0;
    OVERLAPPED      *wOv   = nullptr;
    const BYTE      *wBuf  = nullptr;
    DWORD            wLeft = 0;
    DWORD            wTotal = 0;

    // The peer is gone (its pipe end closed or misbehaved) or the ring is corrupt
    bool             dead = false;

    P2PeerioShmState ( ) = default;
    P2PeerioShmState ( const P2PeerioShmState& ) = delete;
    P2PeerioShmState& operator = ( const P2PeerioShmState& ) = delete;
   ~P2PeerioShmState ( )
    {
        p2pshm::WakeClose ( mine );
#if defined(_WIN32)
        if ( peer ) CloseHandle ( peer );
#else
        if ( peer >= 0 ) ::close ( peer );
#endif
        p2pshm::MappingClose ( map );
    }
};
