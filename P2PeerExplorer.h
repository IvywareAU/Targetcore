// Copyright © 2011, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerExp definitions and prototypes
//  NOTES: Isolated and self contained definitions.  Omission of
//         this object from the build deprecates P2Pexpump facility
//         
#pragma once

#include "P2PeerHub.h"

#define P2PeerExpump_EOD

typedef void (P2PeerTarget::*RUN_EXPUMP)(void);
#define RUN_EXPUMP_cast(method) ((RUN_EXPUMP)(RUN_EXPUMP) \
		(static_cast<void (P2P_MSG_CALL P2PeerTarget::*)(void)>(method)))

typedef struct
{
    CStringADDR  strClient;            // Registered client address
} SP2PexpRegHub;
typedef CList<SP2PexpRegHub> CListRegHubs;

typedef struct _SP2PexpRegPmp
{
    CStringADDR  strClient;            // Registered client address
    P2PumpID     nPumpID{0u};          // Pump identification
} SP2PexpRegPmp;
typedef CList<SP2PexpRegPmp> CListRegPmps;

typedef struct _SP2PexpRegCon
{
    CStringADDR  strClient;            // Registered client address
    P2PconID       nConID{0u};         // Connection identification
} SP2PexpRegCon;
typedef CList<SP2PexpRegCon> CListRegCons;

typedef CMap<CStringADDR,CStringADDR&,CStringADDR,CStringADDR&> CMapADDR2ADDR;

//
//  P2PeerExplorer base class
//  NOTES: Manages the exposure of P2PeerHub properties and status in
//         real-time.
//
#define P2PeerExplorer P2PeerExpump
class Targetcore_EXT P2PeerExplorer : public P2PeerTarget
{
      void
        RenderExplorerSafe();

    // Constructors and destructor
    public:
        P2PeerExplorer ( P2PeerHub *pHub );
      virtual
       ~P2PeerExplorer ( );

      static P2PeerExpump*
        DynamicCreate ( P2PeerHub *pHub
                      , LPTHREAD_START_ROUTINE pfnThreadProc = 0
                      , RUN_EXPUMP  pfnRunExpump = 0 );

    // P2Pexpump management
    public:
      virtual HANDLE
        SpawnExpump ( LPTHREAD_START_ROUTINE pfnThreadProc
                    , RUN_EXPUMP  pfnRunExpump );
      virtual void
        CloseExpump ( P2PexpumpID nExpumpID );
      static DWORD WINAPI
        ProcExpump ( void *pvData );
      virtual void
        RunExpump ( );
      virtual void
        PostDestroyExpump ( P2PexpumpID nExpumpID );

    // P2PeerCon management
    public:
      P2PeerCon*
        PostP2PeerCon ( P2PeerCon *pCon );
      BOOL
        ConExists  ( P2PaddrSTR strP2Paddress );
      bool
        ConQuery   ( P2PaddrSTR strP2Paddress, SafeP2PeerCon& rSafeCon );
      BOOL
        ConSignal  ( P2PaddrSTR strP2Paddress
                   , P2PsigID nSigConID
                   , void *pvData = 0, int iDataSize = 0 );

    // P2PeerMsg management
    public:
      msgRESULT
        RouteP2PeerMsg ( P2PeerMsg *pMsg );
      virtual msgRESULT
        RouteP2PeerMsgPeek ( P2PeerMsg *pMsg );
      P2PeerMsg*
        PostP2PeerMsg  ( P2PeerMsg *pMsg );
      mapRESULT
        P2PexpumpContextSwap ( P2PeerMsg *pMsg );

    // P2PeerMsg_MAP operations
    public:
      virtual msgRESULT
        PeekP2PeerMsg ( P2PeerMsg *pMsg );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;

    // Properties
    public:
      virtual const P2Paddr&
        GetP2PaddrHub ( );
      virtual P2PmsgHubID
        GetHubID ( ) const;
      virtual P2PeerHub*
        GetP2PeerHub ( );

    // Attributes
    public:
      P2PeerHub        *m_pHub;
      UINT              m_nMaxECid;
      P2PexpumpID       m_nExpumpID;
      //  F-S5-4.  The thread handle SpawnExpump() creates.  It used to be
      //  returned and nothing more: all three call sites in this repository
      //  treat the return as a success code and drop it, so the handle was
      //  never closed by anybody and the explorer's thread object outlived
      //  the process.  The explorer owns the thread, so it owns the handle -
      //  the destructor waits the expump down and gives it back.  Still
      //  returned by SpawnExpump() for source compatibility, but a caller
      //  must NOT close what it is handed.
      HANDLE            m_hExpumpThread;
      CRITICAL_SECTION  m_oCSectionExpump;
      CListRegHubs      m_oCListRegHubs;
      CListRegCons      m_oCListRegCons;
      CListRegPmps      m_oCListRegPmps;

    // P2PeerCon_MAP handlers
    // NOTES: Placemarker for map.  Default set of handlers reside
    //        in P2PeerTarget.
    protected:
    DECLARE_P2PeerCon_MAP()
      virtual conRESULT
        On_XCidSvrStartup ( P2PeerCon *pCon );
      virtual conRESULT
        On_XCidSvrListen ( P2PeerCon *pCon );
      virtual conRESULT
        On_XCidSvrAccept ( P2PeerCon *pCon );

      virtual conRESULT
        On_XCidConAccept ( P2PeerCon *pCon );
      virtual conRESULT
        On_XCidConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr
                     , const void *pvLoginMsg, P2Psize_t iSize );
      virtual conRESULT
        On_XCidConClose ( P2PeerCon *pCon );

    // P2PeerMsg_MAP handlers
    // NOTES: Placemarker for map.
    protected:
	  DECLARE_P2PeerMsg_MAP()
	  virtual msgRESULT
	    On_P2PexpCtrl( P2PeerMsg *pMsg );
      //virtual msgRESULT
      //  On_P2PmsgExp ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PmsgExp_Hub ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PmsgExp_Pmp ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PmsgExp_Con ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PmsgExp_CATCH ( P2PeerMsg *pMsg );
};
typedef P2PSafePtr<P2PeerExplorer> P2PeerExpSP;

//
//  MSG_P2Pexpump definitions
//  NOTES: Generic P2PeerMsg's used to flag a raw message transmitter
//         without header details.
//       : Facilitates transparent P2Peer interaction with
//         3rd Party interfaces.
//
static
const P2PmsgID P2PmsgExp        = L"P2PmsgExp";  //TODO: LJM deprecated by P2PexpumpCtrl below
static
const P2PmsgID MSG_P2PexpCtrl   = L"P2PexpumpCtrl";
static
const P2PmsgID MSG_P2PexpHub    = L"P2PexpumpHub";
static
const P2PmsgID MSG_P2PexpCon    = L"P2PexpumpCon";
static
const P2PmsgID MSG_P2PexpPmp    = L"P2PexpumpPmp";
static
const P2PmsgID MSG_P2PexpWCard  = L"P2Pexpump*";

//
//  P2PmsgExp sink registration masks
const DWORD P2PmsgExp_HUB    = 1;
const DWORD P2PmsgExp_CON    = 2;
const DWORD P2PmsgExp_PMP    = 4;
const DWORD P2PmsgExp_ALL    = ~0u;

//
//  P2Pexpump sink management 
//  NOTES: Manage the creation, operation and life cycle of
//         P2PeventSink's.  Clients may register for P2Pevent
//         notifications
//       : Thread isolation of P2Pevent's
Targetcore_EXT P2PexpumpID
CreateP2Pexpump ( P2PmsgHubID nHubID, P2PeerTarget *pTarget );
Targetcore_EXT BOOL
CloseP2Pexpump ( );
Targetcore_EXT DWORD
RegisterP2Pexpump ( DWORD dwMask, BOOL bRegister );

Targetcore_EXT P2PeerMsg*
PostP2Pexp ( P2PeerMsg *pMsg, P2PexpumpID nP2PexpumpID
           , bool bPrepend = false );
Targetcore_EXT msgRESULT
SwapP2PexpContext  ( P2PeerMsg *pMsg );
void
PostP2PexpCon ( P2PexpumpID nExpumpID, P2PeerCon *pCon );
BOOL
EnumP2PexpCon ( P2PexpumpID nExpumpID, P2PeerCon **pCon );

Targetcore_EXT BOOL
RegisterP2PmsgExp_Hub ( P2PaddrSTR lpszDestin, BOOL bRegister = FALSE );
Targetcore_EXT BOOL
QueryP2PmsgExp_Hub ( P2PaddrSTR lpszDestin, BOOL bVerbose = FALSE );

Targetcore_EXT BOOL
RegisterP2PmsgExp_Pmp ( LPCTSTR lpszDestin, BOOL bRegister = FALSE );
Targetcore_EXT BOOL
QueryP2PmsgExp_Pmp ( P2PumpID nPumpID, P2PaddrSTR lpszDestin, BOOL bVerbose = FALSE );

Targetcore_EXT BOOL
QueryP2PmsgExp_Con ( P2PconID nConID, P2PaddrSTR lpszDestin, BOOL bRegister = FALSE );

//
//  P2PeerHub integration
//  NOTES: Manage the integration of P2PeerExp objects with Hub's
//       : P2PeerHub declarations externalised to illiminate cross
//         linkages and dependencies
//P2PeerExpump*
//P2PeerHub_SpawnExp ( P2PeerHub *pHub, P2PeerExpump *pP2PeerExp );
//void
//P2PeerHub_CloseExp ( P2PeerHub *pHub );
//P2PeerExpump*
//P2PeerHub_GetP2PeerExp ( P2PeerHub *pHub );
Targetcore_EXT P2PeerExpump*
P2PeerExpump_ACTIVATE ( P2PeerHub *pHub, P2PeerExpump *pExpump = 0 );
Targetcore_EXT P2PeerExpump*
P2PeerExpump_DESTROY ( P2PeerExpump *pExpump );
Targetcore_EXT msgRESULT
P2PeerExpump_INTERCEPT ( P2PeerHub *pHub, P2PeerExpump *pExpump, P2PeerMsg *pMsg );

// Inline P2PeerHub::P2PeerMsgPeek() interceptions
// NOTES: Added to over-written P2PeerHub::P2PeerMsgPeek method
//        to facilitate P2PeerExpump interception of  "P2Pexpump*"
//        series of messages
//      : Interception forms the basis of swapping P2PeerMsg from
//        P2PmsgHub to the P2PeerExp processing context
//      : msgRESULT
//        P2PeerHub::P2PeerMsgPeek ( P2PeerMsg *pMsg )
//        {
//          INLINE_Expump_PEEK ( pExpump, pMsg );
//          // Additional code
//          return msgCONTINUE;
//        }
#define INLINE_Expump_PEEK(pMsg) \
if ( m_pP2PeerExpump ) \
{ \
  msgRESULT msgResult = m_pP2PeerExpump->PeekP2PeerMsg(pMsg); \
  if ( msgResult != msgCONTINUE ) \
    return msgResult; \
} \

// Inline P2PeerHub::P2PeerMsgPeek() interceptions
// NOTES: Added to over-written P2PeerHub::P2PeerMsgPeek method
//        to facilitate P2PeerExpump interception of  "P2Pexpump*"
//        series of messages
//      : Interception forms the basis of swapping P2PeerMsg from
//        P2PmsgHub to the P2PeerExp processing context
//      : msgRESULT
//        P2PeerHub::P2PeerMsgPeek ( P2PeerMsg *pMsg )
//        {
//          INLINE_Expump_PEEK ( pExpump, pMsg );
//          // Additional code
//          return msgCONTINUE;
//        }
/*#define INLINE_Expump_SPAWN(pMsg) \
{
    if ( !GetP2PeerExpump() )
      PostP2PeerExpump ( new P2PeerExpump(this) );
    P2PeerExpump *pP2PeerExpump_
      = dynamic_cast<P2PeerExpump *>(GetP2PeerExpump()); 
    if (  pP2PeerExpump_ &&
         !pP2PeerExpump_->IsRunning()  )
      pP2PeerExpump_->SpawnExpump ( 0, 0 );
}*/
