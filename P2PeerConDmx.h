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
//  P2PeerConDmx definitions and prototypes
//  NOTES: Asynchronously manages in-process P2PeerHub data exchanges
//         and facilitates IO Completion port integration
//       : Used in conjunction with P2PeerioDmx interface objects
//
#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2PeerCon.h"

///////////////////////////////////////////////////////////////////////
//  P2PeerConDmx connection management
//  NOTES: Instances of these objects wholly manage the exchange of
//         P2PeerMsg's between P2PeerHubs in the same address space
//       : P2PeerHub's pump P2PeerConDmx objects through P2PeerCon_MAP's
//         in response to state changes.
//
class TargetCore_EXT P2PeerConDmx : public P2PeerCon
{
      void
        RenderThisSafe();

    // Constructors and destructor
    public:
        P2PeerConDmx ( );
        P2PeerConDmx ( P2PaddrSTR strThatP2Paddr
                     , LPCTSTR strServiceName
                     , P2PeerConMode_e  eMode
                     , P2Peerio  *pP2Peerio = 0 );
        P2PeerConDmx ( P2PaddrSTR pThisP2PaddrSTR
                     , P2PeerConMode_e eMode
                     , P2Peerio  *pP2Peerio = 0 );
      virtual
       ~P2PeerConDmx ( );

      static P2PeerConDmx*
        ServiceFactory( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR strServiceName );
      static P2PeerConDmx*
        ClientFactory ( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR strServiceName );
      virtual P2PeerCon*
        AcceptSpawn ( P2PeerCon *pCon );
      void
        Destroy ( );

    // IOCP Integration
    public:
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
      virtual P2PeerCon*
        OnAccept  ( );
      virtual void
        OnAccept  ( CP2Paddress oThatP2Paddr );
      virtual bool
          Connect ( );
      virtual void
          Close   ( );
      virtual BOOL
        OnClose   ( );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
      virtual P3PmsgItem
        Serialise ( LPCTNAM lpszVar );

    // Properties
    public:
      virtual DWORD_PTR
        GetUDState ( );

    // Attributes
    protected:
      P2PeerConDmx    *m_pConThat;
      CString          m_sServiceName;
};
typedef CList<P2PeerConDmx*> CListP2PeerConDmx;

