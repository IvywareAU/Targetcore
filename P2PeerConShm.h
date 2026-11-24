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
#include "P2PeerConPipe.h"

///////////////////////////////////////////////////////////////////////
//  P2PeerConShm - same-host, cross-process: a named pipe for control, shared memory
//  for data (p2p_performance.md §6.3, design §6.3a)
//  NOTES: EVERYTHING a pipe connection is, it is - the rendezvous name, accept and
//         spawn, the accept cap, SetPipeAccess / the DACL (Windows) or the 0700
//         directory (Linux), TrustClass() = Local, login, key agreement, sealing.
//         What changes is where the BYTES go once connected: two byte-stream rings
//         in a mapping only these two processes hold (P2PeerioShm). The pipe then
//         carries nothing but a pending 1-byte read whose completion means the peer
//         is gone.
//       : THE HANDSHAKE runs once per link, on the pump, before the link's first
//         read or write:
//           - the ACCEPTING end creates the mapping (unnamed section / sealed memfd)
//             and both wake objects, hands them to the client (DuplicateHandle into
//             the pipe client's process / SCM_RIGHTS), writes the hello and goes on.
//             It never waits for the client, so a hostile local client cannot stall
//             the hub's pump;
//           - the DIALLING end reads the hello within a deadline, checks it and the
//             mapping (size, seals, magic) and attaches. It does wait - for the
//             server it chose to dial.
//       : Refuses to arm where the platform cannot deliver the wake to the pump
//         (Windows without NtAssociateWaitCompletionPacket): IsSupported()
//
class Targetcore_EXT P2PeerConShm : public P2PeerConPipe
{
    // Constructors and destructor
    public:
        P2PeerConShm ( );
      virtual
       ~P2PeerConShm ( );

      static P2PeerConShm*
        ServiceFactory( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR      sPipename );
      static P2PeerConShm*
        ClientFactory ( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR      sPipename );
      virtual P2PeerCon*
        AcceptSpawn ( P2PeerCon *pCon );

      // Can this platform carry the transport (the wake reaches the pump)?
      static bool
        IsSupported ( );

    // IOCP Integration
    public:
      virtual void
        Drop ( P2Pevent *pEVENT );

    // Connection state operations
    public:
      using P2PeerConPipe::OnAccept;           // keep OnAccept(CP2Paddress) visible
      virtual P2PeerCon*
        OnAccept  ( );
      virtual bool
          Connect ( );
      virtual BOOL
        OnClose  ( );

    // Implementation
    private:
      void  ShmOffer  ( );                     // accepting end
      void  ShmAccept ( );                     // dialling end
      void  ShmDetach ( );
};
