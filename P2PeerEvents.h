// Copyright © 2002-2011, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  Definitions and prototypes for the P2PeerEvents log connection
//  object
//  NOTES: P2PeerEvents object interact with all P2PeerHub's within
//         application address space
//

#pragma   once
#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2PeerHub.h"
#include "Msgexception.h"

//
//  P2PeerEvent log connection object
//  NOTES: Manages connection with remote event logging manager
//       : Registers with P2Pevent for receipt of event notifications
//         and upon receipt passes such notifications to the remote
//         event log
//       : Create an instance of this object for each connected
//         event log.  Thread safe
//
class Targetcore_EXT P2PeerEvents : protected P2PeerHub
{
      void
        RenderEventSafe();

    // Constructors and destructor
    public:
        P2PeerEvents ( P2PaddrSTR strP2Paddr );
      virtual
       ~P2PeerEvents ( );

    // P2PmsgHub management
    public:
      static P2PeerEvents*
        WsaLogFactory ( P2PaddrSTR  strThisP2Paddr
                      , P2PaddrSTR  strEventSinkP2Paddr
                      , LPCTSTR    lpszHostName, short nHostIpPort
                      , DWORD        dwEventsMask );
      BOOL
        StartWsaLog   ( P2PaddrSTR  strEventSinkP2Paddr
                      , LPCTSTR    lpszHostName, short nHostIpPort );
      void
        StopLogging   ( );
      void
        RunEventsHub  ( );

    // Operations
    public:
      P2PeerEvents*
        Destroy ( DWORD dwDuration );
      DWORD
        RegisterEventCB ( DWORD dwEventsAddMask, DWORD dwEventsRemMask );
      void
        CancelEventCB ( );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;

    // Attributes
    private:
      P2PeventSinkID m_nP2PeventSinkID;
      P2Paddr        m_oSinkP2Paddr;
      DWORD          m_dwEventsClassMask;
      bool           m_bSinkConnected;

    // P2PeventSink handlers
    // NOTES: Intercept P2PeventSink notifications
    public:
      evtRESULT
        On_P2Pevent( P2PeventSinkID nSinkID, P2PumpID nPumpID
                   , P2Pevent *pEvent );

    // P2PeerCon map handlers
    // NOTES: Manage event sink connection
    protected:
    DECLARE_P2PeerCon_MAP()
      conRESULT
        On_SinkConnect ( P2PeerCon *pCon );
      conRESULT
        On_SinkLoginAck( P2PeerCon *pCon
                       , P2PaddrSTR strThisP2Paddr
                       , P2PaddrSTR strThatP2Paddr
                       , const void *pvLoginAck, P2Psize_t iSize );
      conRESULT
        On_SinkClose   ( P2PeerCon *pCon );

    // P2PeerMsg map handlers
    // NOTES: Automatic P2PeerMsg routing
    protected:
	  DECLARE_P2PeerMsg_MAP()
      virtual msgRESULT
        On_P2PmsgErrorCatch ( P2PeerMsg *pMsg );
};

extern Targetcore_EXT P2PeerEvents *g_pP2PeerEvents;
