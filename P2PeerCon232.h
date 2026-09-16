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
//  P2PeerCon232 definitions and prototypes
//  NOTES: Asynchronously manages RS-232 serial connections and
//         facilitates IO Completion port integration
//
#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2PeerCon.h"

///////////////////////////////////////////////////////////////////////
//  P2PeerCon232 serial connection management
//  NOTES: Instances of these objects wholly manage single RS-232
//         serial connections.  Collections of P2PeerCon232 objects are
//         be supervised via P2PeerHub's
//       : P2PeerHub's pump P2PeerCon232 objects through P2PeerCon_MAP's
//         in response to state changes.
//
class Targetcore_EXT P2PeerCon232 : public P2PeerCon
{
      void
        RenderThisSafe();

    // Constructors and destructor
    public:
        P2PeerCon232 ( );
        P2PeerCon232 ( P2PaddrSTR pThatP2PaddrSTR
                     , short nComPort
                     , P2Peerio  *pP2Peerio = 0 );
        P2PeerCon232 ( short nComPort
                     , P2Peerio  *pP2Peerio = 0 );
      virtual
       ~P2PeerCon232 ( );

      static P2PeerCon232*
        ServiceFactory( P2PaddrSTR strP2PaddrThat
                      , short nComPort );
      static P2PeerCon232*
        ClientFactory ( P2PaddrSTR strP2PaddrThat
                      , short nComPort );
      virtual P2PeerCon*
        AcceptSpawn ( P2PeerCon *pCon );
      virtual P2PeerCon*
        OnAccept ( );
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
      virtual bool
          Accept  ( );
      virtual bool
          Connect ( );
      virtual void
          Close   ( );
      virtual BOOL
        OnClose  ( );

    // Implementation helpers
    protected:
      void
        SetComPort ( short nComPort );
      void
        ConfigureComPort ( );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;

    // Attributes
    protected:
      HANDLE         m_hFileCOM;
      HANDLE         m_hEventHub;

      short          m_nComPort;
      CString        m_sFileCOM;
      DWORD          m_dwCommEvent;   // WaitCommEvent() result mask; must
                                      //   outlive the pended accept wait
};

