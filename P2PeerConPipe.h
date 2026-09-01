// Copyright © 2006-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerConPipe definitions and prototypes
//  NOTES: Asynchronously manages serial named pipe connections and
//         facilitates IO Completion port integration
//

#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2PeerCon.h"

///////////////////////////////////////////////////////////////////////
//  P2PeerConPipe serial connection management
//  NOTES: Instances of these objects wholly manage single named pipe
//         serial connections.  Collections of P2PeerConPipe objects are
//         be supervised via P2PeerHub's
//       : P2PeerHub's pump P2PeerConPipe objects through P2PeerCon_MAP's
//         in response to state changes.
//
class TargetCore_EXT P2PeerConPipe : public P2PeerCon
{
      void
        RenderThisSafe();
      void
        CreateListenPipe();   // named-pipe creation; state-agnostic, shared by OnListen()/Accept()

    // Constructors and destructor
    public:
        P2PeerConPipe ( );
        P2PeerConPipe ( P2PaddrSTR pThatP2PaddrSTR
                      , LPCTSTR lpszPipename
                      , P2Peerio  *pP2Peerio = 0 );
        P2PeerConPipe ( LPCTSTR lpszPipename
                      , P2Peerio  *pP2Peerio = 0 );
      virtual
       ~P2PeerConPipe ( );

      static P2PeerConPipe*
        ServiceFactory( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR      sPipename );
      static P2PeerConPipe*
        ClientFactory ( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR      sPipename );
      virtual P2PeerCon*
        AcceptSpawn ( P2PeerCon *pCon );
      void
        Destroy ( );

    // IOCP Integration
    public:
      /*virtual bool
        On_QueuedCompletionStatus ( DWORD dwError
                                  , DWORD dwBytes
                                  , OVERLAPPEDcon *pOVERLAPPEDcon );*/
      virtual void
        Drop ( P2Pevent *pEVENT );

    // Connection state operations
    // NOTES: Thread safe operations used to manage connection
    //        state.  Reference from P2PeerCon_MAP handlers only
    public:
      virtual bool
          Listen  ( );
      virtual void
        OnListen  ( );
      virtual bool
          Accept  ( );
      virtual P2PeerCon*
        OnAccept  ( );
      virtual void
        OnAccept  ( CP2Paddress oThatP2Paddr );
      virtual bool
          Connect ( );
      virtual void
          Close   ( );
      virtual BOOL
        OnClose  ( );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;

    // Properties
    public:
      virtual bool
        HasDroppedOut ( HRESULT hr );

    // Attributes
    protected:
      CString  m_sPipename;
};

