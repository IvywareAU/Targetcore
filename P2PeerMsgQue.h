// Copyright © 2002-2006, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//
//  P2Peer message queue definitions and prototypes
//  NOTES: Observes assigned P2PeerMsg priority.  Highest priority
//         P2PeerMsg's are removed from the queue first regardless
//         of the order appended to the queue
//

#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2PeerMsg.h"

//
//
//  P2Peer message queue object
//  NOTES: Used to manage queues of P2PeerMsg's.
//       : Thread safe implementation.
//
class TargetCore_EXT P2PeerMsgQue
{
      void
        RenderQueSafe ( );

    // Constructors and destructor
    public:
        P2PeerMsgQue ( HANDLE hNotnEvent );
      virtual
       ~P2PeerMsgQue ( );

    // Operations
    public:
      P2PeerMsg*
        Append   ( P2PeerMsg *pMsg );
      INT_PTR
        Append   ( P2PeerMsg& oMsg );
      P2PeerMsg*
        Preppend ( P2PeerMsg *pMsg );
      P2PeerMsg*
        Remove   ( );

    // Utilities
    public:
      void
        Flush ( );

    // Property management
    public:
      INT_PTR
        GetCount ( );
      bool
        IsEmpty  ( );
      HANDLE
        GetEvent ( );

    // Attributes
    private:
      HANDLE           m_hThreadPump;
      HANDLE           m_hNotnEvent;
      CRITICAL_SECTION m_oCSectionQue;

      CListP2PeerMsg   m_oCListP2PeerMsg;
};


