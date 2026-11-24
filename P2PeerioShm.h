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
#pragma once
#include "P2Peerio.h"

struct P2PeerioShmState;                       // P2PeerioShmState.h, private

///////////////////////////////////////////////////////////////////////
//  P2PeerioShm - the shared-memory transport's byte I/O (p2p_performance.md §6.3a)
//  NOTES: Overrides IoWrite / IoRead and NOTHING ELSE of the message path, so framing,
//         the sealing decision (Send's F-S6-3 mark), the receive ring and every check
//         RecvP2PeerMsg makes are the stock class's, as for a socket. The bytes move
//         through two byte-stream rings in a mapping shared with the peer process.
//       : LeavesProcess() stays TRUE, deliberately: the frames DO leave this process,
//         so a keyed link seals them exactly as on a pipe, and the cypher hooks stay in
//         the path. A same-host peer is inside the host boundary, not inside ours.
//       : Completions keep WriteFile's / ReadFile's contract (P2Peerio.h, IoWrite):
//         one per call, carrying the byte count. A read completes with >= 1 byte or an
//         error, never with 0 bytes on success (that is the orderly-close signal); a
//         write completes only when ALL its bytes are in the ring.
//       : Until AttachShm() every I/O call fails - the handshake (P2PeerConShm) runs
//         before the connection's first read or write
//
class Targetcore_EXT P2PeerioShm : public P2Peerio
{
    // Constructors and destructor
    public:
        P2PeerioShm ( ) noexcept;
      virtual
       ~P2PeerioShm ( );
      virtual P2Peerio*
        Clone ( );

    // The link, from the handshake
    public:
      // Takes ownership of pState, which carries the mapping, the rings, both wakes,
      // the connection's port / key and its pipe. Makes this object's own
      // OVERLAPPEDcons and arms the death watch. false: nothing kept, pState deleted
      bool
        AttachShm ( P2PeerioShmState *pState );
      // Cancels what can be cancelled and releases the link. Safe to call twice
      void
        DetachShm ( );
      bool
        IsShmAttached ( ) const { return m_pShm != nullptr; }

    // IOCP Integration
    public:
      virtual bool
        On_QueuedCompletionStatus ( DWORD dwError
                                  , DWORD dwBytes
                                  , OVERLAPPEDcon *pOVERLAPPEDcon );
      virtual bool
        HasQueuedOwnOVERLAPPED ( ) const;
      virtual void
        ForgetOwnOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon );

    // Transport byte I/O
    protected:
      virtual BOOL
        IoWrite ( HANDLE hFile, const void *pvData, DWORD dwSize, OVERLAPPED *pOv );
      virtual BOOL
        IoRead  ( HANDLE hFile, void *pvData, DWORD dwSize, OVERLAPPED *pOv );
      // The stock framing is untouched, so a gathered batch is one longer IoWrite:
      // one ring copy, one wake and one completion for many messages (S3 A/B)
      virtual bool
        IoGathers ( ) const { return true; }

    // Implementation
    private:
      void  Complete    ( OVERLAPPED *pOv, DWORD dwBytes );
      void  Fail        ( OVERLAPPED *pOv, DWORD dwError );
      void  ArmWake     ( );
      void  ArmDeath    ( );
      void  Service     ( );
      void  SignalPeer  ( );
      void  PeerGone    ( DWORD dwError );

    // Attributes
    private:
      P2PeerioShmState *m_pShm;

      // This object's OVERLAPPEDcons still owed a completion after DetachShm (a wake or
      // the death watch, cancelled by closing what they wait on). Kept HERE, not in the
      // freed state, so HasQueuedOwnOVERLAPPED() still answers for them and the
      // teardown drain waits; the late completion gives them back
      OVERLAPPEDcon    *m_pLate[2];
};
