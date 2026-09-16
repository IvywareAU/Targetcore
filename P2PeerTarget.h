// Copyright © 2002-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerTarget prototypes and definitions.
//  NOTES: P2PeerCon_MAP, P2PeerSys_MAP and P2PeerMsg_MAP's are
//         supported by any object derived from P2PeerTarget and
//         subsequently directly or indirectly registered with a
//         single P2PeerHub
//
#pragma once
#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2Peer.h"
#include "P2PmsgMaps.h"
#include "P2PeerCon.h"

typedef void (P2PeerTarget::*RUN_PUMP)(void);
#define RUN_PUMP_cast(method) ((RUN_PUMP)(RUN_PUMP) \
		(static_cast<void (P2P_MSG_CALL P2PeerTarget::*)(void)>(method)))

typedef std::map <std::wstring, P2PmsgSinkID> P2PmsgSinkIDmap;
typedef std::pair<std::wstring, P2PmsgSinkID> P2PmsgSinkIDpair;

//
//  P2PeerMsg_MAP handler results
//  NOTES: Used to summarise P2PeerMsg_MAP handler outcomes. Such
//         handlers return a results from the following
//
typedef  mapRESULT msgRESULT;
const    msgRESULT msgCONTINUE= FALSE; // Continue routing
const    msgRESULT msgHANDLED = TRUE;  // Handled
const    msgRESULT msgSWAP    = 7;     // Swap processing context
const    msgRESULT msgREDIRECT= 8;     // Redirect or re-route
const    msgRESULT msgREPUMP  = 9;     // Repump the message

typedef  mapRESULT sysRESULT;
const    sysRESULT sysCONTINUE= FALSE; // Continue routing
const    sysRESULT sysHANDLED = TRUE;  // Handled
const    sysRESULT sysSWAP    = 7;     // Swap processing context

typedef  mapRESULT sncRESULT;
const    sncRESULT sncCONTINUE= FALSE; // Continue routing
const    sncRESULT sncHANDLED = TRUE;  // Handled
const    sncRESULT sncSWAP    = 7;     // Swap processing context
const    sncRESULT sncREDIRECT= 8;     // Redirect or re-route
const    sncRESULT sncREPUMP  = 9;     // Repump the message

typedef  mapRESULT evtRESULT;
const    mapRESULT evtCONTINUE= FALSE; // Continue routing
const    mapRESULT evtHANDLED = TRUE;  // Handled
const    mapRESULT evtSWAP    = 7;     // Swap processing context

class P2PeerHub;
class Targetcore_EXT P2PeerTarget
{
    P2PeerTarget&
      operator = ( const P2PeerTarget& ) { ASSERT(0); return *this; }
    // Constructors and destructor
    public:
        P2PeerTarget ( );
        P2PeerTarget ( P2PeerTarget *pTargetParent
                     , P2Pri_t nPriority );
      virtual
       ~P2PeerTarget ( );

    // P2PmsgPump management
    public:
      virtual HANDLE
        SpawnPump ( LPTHREAD_START_ROUTINE pfnThreadProc
                  , RUN_PUMP  pfnRunPump
                  , LPCTNAM   lpszName
                  , P2PumpID  *pnP2PumpID );
      virtual void
        ClosePump  ( P2PumpID nPumpID );
      static DWORD WINAPI
        ProcPump ( void *pvData );
      virtual void
        RunPump ( );
      virtual void
        PostDestroyPump ( P2PumpID nPumpID );

    // P2Pump context
    // NOTES: Manage the P2Pump processing context of objects pumped
    //        through the P2PeerCon_MAP, P2PeerSys_MAP and
    //        P2PeerMsg_MAP's
    public:
      bool
        P2PeerContext     ( P2PumpID nPumpID );
      mapRESULT
        P2PeerContextSwap ( P2PumpID nPumpID );
      mapRESULT
        P2PeerContextSwap ( HWND hWnd, UINT nMsg );
      mapRESULT
        P2PeerContextSwap ( P2PeerCon *pCon, P2PeerMsg *pMsg );
      mapRESULT
        P2PeerContextSwap ( P2PeerMsg *pMsg );

    // Timers
    public:
      PITimerID
        SetPITimer ( P2Pmsecs_t uMSecDelay, DWORD dwUserKey = 0 );
      PITimerID
        PostPITimer( P2PeerMsg *pMsg
                   , P2Pmsecs_t uMSecDelay, DWORD dwUserKey = 0 );
      virtual void
        On_PITimer ( bool bCancel
                   , PITimerID nTimerID, DWORD dwUserKey );

    // P2Pevents
    // NOTES: Manage P2Pevent sink notifications
    public:
      virtual evtRESULT
        On_P2Pevent( P2PeventSinkID nSinkID, P2PumpID nPumpID
                   , P2Pevent *pEvent );

    // P2PeerTarget integration
    // NOTES: Manage P2PeerHub registration.  Which in turn facilitates
    //        the routed pumping of objects through the P2PeerCon_MAP
    //        P2PeerSys_MAP and P2PeerMsg_MAP's
    public:
      void
        RegisterTarget( P2PeerTarget *pTargetChild, P2Pri_t nPriority = -127 );
      void
        RemoveTarget  ( P2PeerTarget *pTargetChild );
      P2PeerTarget*
        IsRegistered ( ) { return m_pTargetParent; }

    // P2PmsgSink integration
    // NOTES: Manages P2PmsgSink's in the P2PeerTarget domain context.  Which
    //        in turn facilitates the direct injection of pumped objects into 
    //        the P2PeerCon_MAP, P2PeerSys_MAP and P2PeerMsg_MAP's.
    public:
      void
        RegisterWithTargetSink ( P2PmsgSinkID nSinkID, P2PsysID nP2PsysID );
      void
        CancelTargetSinkRegistration ( P2PmsgSinkID nSinkID, P2PsysID nP2PsysID = 0 );
      P2PmsgSinkID
        CreateTargetSink ( LPCTNAM lpszSinkname );
      P2PmsgSinkID
        CloseTargetSink ( P2PmsgSinkID nTargetSinkId );
      P2PmsgSinkID
        LookupTargetSink ( LPCTNAM lpszSinkname );

    // P2PeerMsg manufacture
    // NOTES: Manage ownership tags etc
    public:
      P2PeerMsg*
        P2PeerMsgFactory ( P2PaddrSTR strDestin
                         , P2PmsgID sMsg
                         , const void *pvData, short nDataSize );
      void
        AssignOwnership  ( P2PeerMsg *pMsg );
      BOOL
        HasOwnership ( P2PeerMsg *pMsg );

    // P2PeerSnc_MAP operations
    public:
      BOOL
        PostP2PeerSnc( P2PmsgSinkID nTargetSinkID, P2PsysID nP2PsysID
                     , WPARAM wParam, LPARAM lParam );
      BOOL
        PostP2PeerSnc( P2PmsgSinkID nTargetSinkID, P2PsysID nP2PsysID
                     , const P3PmsgItem& oItem 
                     , WPARAM wParam, LPARAM lParam );
      virtual BOOL
        On_P2PeerSnc ( UINT nCode, P2Pmsg_t nMsg
                     , WPARAM wParam, LPARAM lParam, void *pvExtra
                     , P2P_SNKHANDLERINFO *pHandlerInfo );
      virtual void
        NotHandledSnc( P2Pmsg_t nMsg, WPARAM wParam, LPARAM lParam );

    // P2PeerSys_MAP operations
    public:
      BOOL
        PostP2PeerSys( P2PmsgSinkID nTargetSinkID, P2PsysID nP2PsysID
                     , WPARAM wParam, LPARAM lParam );
      virtual BOOL
        On_P2PeerSys ( UINT nCode, P2Pmsg_t nMsg
                     , WPARAM wParam, LPARAM lParam, void *pvExtra
                     , P2P_SYSHANDLERINFO *pHandlerInfo );
      virtual void
        NotHandled  ( P2Pmsg_t nMsg, WPARAM wParam, LPARAM lParam );

    // P2PeerCon_MAP operations
    // NOTES: The state of a P2PeerCon object is managed by the
    //        asynchronous exchange between P2PeerCon_MAP handlers
    //        and the P2PeerHub
    public:
      virtual P2PeerCon*
        PostP2PeerCon ( P2PeerCon *pCon );
      virtual conRESULT
        On_P2PeerCon  ( const P2Paddr& oP2Paddr, UINT nCode, P2Pmsg_t nMsg
                      , P2PeerMsg *pMsg, P2PeerCon *pCon
                      , P2P_CONHANDLERINFO* pHandlerInfo );
      virtual void
        PreDestroyP2PeerCon ( P2PeerCon *pCon, conRESULT bConResult );
      virtual conRESULT
        On_DefaultCon ( UINT nCode, P2Pmsg_t nMsg
                      , P2PeerMsg *pMsg, P2PeerCon *pCon
                      , P2P_CONHANDLERINFO* pHandlerInfo );
      virtual void
        NotHandled ( P2PeerCon *pCon, P2Pmsg_t nMsg );

    // P2PeerMsg_MAP operations
    public:
      virtual P2PeerMsg*
        PostP2PeerMsg ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PeerMsg  ( P2PaddrSTR strP2Paddr, UINT nCode, P2Pmsg_t nMsg
                      , P2PeerMsg *pMsg, void *pvExtra
                      , P2P_MSGHANDLERINFO *pHandlerInfo );
      virtual msgRESULT
        RouteP2PeerMsg ( P2PeerMsg *pMsg );
      virtual msgRESULT
        PeekP2PeerMsg ( P2PeerMsg *pMsg );
      virtual msgRESULT
        ReturnP2PeerMsg ( P2PeerMsg *pMsg );
      virtual msgRESULT
        RepumpP2PeerMsg ( P2PeerMsg *pMsg );
      virtual msgRESULT
        ReflectP2PeerMsg ( P2PeerMsg *pMsg );
      virtual msgRESULT
        RedirectP2PeerMsg ( P2PeerMsg *pMsg, P2PaddrSTR strDestin );
      virtual void
        PreDestroyP2PeerMsg ( const P2PeerMsg *pMsg, msgRESULT bHandled );
      virtual void
        NotHandled ( P2PeerMsg *pMsg );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
      virtual P3PmsgItem
        Serialise ( LPCTNAM lpszVar, bool bDsc = false );
      BOOL
        IsValidObject ( ) const;

    // Attributes
    public:
      CString          m_csTargetName;
      DWORD_PTR        m_dwAddrTag{0};
      P2PeerTarget    *m_pTargetParent{nullptr};
      P2PeerTarget    *m_pTargetChildHi{nullptr};
      P2PeerTarget    *m_pTargetChildLo{nullptr};
      P2PeerTarget    *m_pTargetPrev{nullptr};
      P2PeerTarget    *m_pTargetNext{nullptr};
      short            m_nPriority{0};
      P2PmsgSinkIDmap *m_pP2PmsgSinkIDmap{nullptr};
    private:
      friend Targetcore_EXT DWORD
        PumpP2Pmsg ( DWORD, P2PsigID& );
      UINT_PTR         m_uiValidObject{0};
 
    // Properties
    public:
      virtual const P2Paddr&
        GetP2PaddrHub ( );
      virtual P2PeerHub*
        GetP2PeerHub ( );
      virtual P2PmsgHubID
        GetHubID ( ) const;

    // P2PeerSnk_MAP handlers
    // NOTES: Default set of P2PeerSnk handlers
    protected:
	  DECLARE_P2PeerSnk_MAP()

    // P2PeerSys_MAP handlers
    // NOTES: Default set of P2PeerSys handlers
    protected:
	  DECLARE_P2PeerSys_MAP()

    // P2PeerCon_MAP handlers
    // NOTES: Default set of P2PeerTarget handlers.  This set
    //        is usually customised for each connection.
    protected:
	  DECLARE_P2PeerCon_MAP()
      virtual conRESULT
        On_ConStartup  ( P2PeerCon *pCon );
      virtual conRESULT
        On_ConAccept   ( P2PeerCon *pCon );
      virtual conRESULT
        On_ConConnect  ( P2PeerCon *pCon );
      virtual conRESULT
        On_ConPKeyXChange ( P2PeerCon *pCon
                          , const void *pvPKeyXChange, P2Psize_t iSize );
      virtual conRESULT
        On_ConPKeyXChangeAck ( P2PeerCon *pCon
                             , const void *pvPKeyXChangeAck, P2Psize_t iSize );
      virtual conRESULT
        On_ConLogin    ( P2PeerCon *pCon
                       , P2PaddrSTR strThatP2Paddr
                       , const void *pvLoginMsg, P2Psize_t iSize );
      virtual conRESULT
        On_ConLoginAck ( P2PeerCon *pCon
                       , P2PaddrSTR strThisP2Paddr, P2PaddrSTR strThatP2Paddr
                       , const void *pvLoginAck, P2Psize_t iSize );
      virtual conRESULT
        On_ConClose    ( P2PeerCon *pCon );
      virtual conRESULT
        On_ConListen   ( P2PeerCon *pCon );
      virtual conRESULT
        On_ConPeek     ( P2PeerCon *pCon
                       , UINT nCode, P2Pmsg_t nMsg );
      virtual conRESULT
        On_ConShutdown ( P2PeerCon *pCon );
      virtual conRESULT
        On_ConCypherEx ( P2PeerCon *pCon, P2PeerMsg *pMsg );

    // P2PeerMsg_MAP handlers
    // NOTES: Default set of P2PeerTarget handlers
    protected:
	  DECLARE_P2PeerMsg_MAP()
      virtual msgRESULT
        On_MsgIgnore ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_MsgCatch ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_MsgCatchCatch ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_MsgReflect ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_MsgReflectCatch ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_MsgPeek ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_MsgPoll ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_MsgPing ( P2PeerMsg *pMsg );
};

///////////////////////////////////////////////////////////////////////
//  ON_P2Peer[Msg,Sys,Con]_MAP functions
//  NOTES: Refer P2PmsgMaps.h for further definitions and prototypes

union P2PeerSysMapFunctions
{
    P2P_PSYS pfn;   // Generic pointer
    sysRESULT (P2P_SYS_CALL P2PeerTarget::*pfn_MsgWin32)(WPARAM,LPARAM);
};

union P2PeerSnkMapFunctions
{
    P2P_PSNK pfn;   // Generic pointer
    sncRESULT (P2P_SNK_CALL P2PeerTarget::*pfn_MsgWin32)(WPARAM,LPARAM);
    sncRESULT (P2P_SNK_CALL P2PeerTarget::*pfn_SnkP3PmsgItem)(P3PmsgItem*,WPARAM,LPARAM);
    //sncRESULT (P2P_SNK_CALL P2PeerTarget::*pfn_SnkP3PmsgNode)(P3PmsgNode*,WPARAM,LPARAM);
};

union P2PeerConMapFunctions
{
    P2P_PCON pfn;   // Generic pointer
    conRESULT (P2P_CON_CALL P2PeerTarget::*pfn_Con)(P2PeerCon*);
    conRESULT (P2P_CON_CALL P2PeerTarget::*pfn_ConLogin)(P2PeerCon*,P2PaddrSTR,const void*,P2Psize_t);
    conRESULT (P2P_CON_CALL P2PeerTarget::*pfn_ConLoginAck)(P2PeerCon*,P2PaddrSTR,P2PaddrSTR,const void*,P2Psize_t);
    conRESULT (P2P_CON_CALL P2PeerTarget::*pfn_ConPeek)(P2PeerCon*,UINT,P2Pmsg_t);
    conRESULT (P2P_CON_CALL P2PeerTarget::*pfn_ConPKeyXChange)(P2PeerCon*,const void*,P2Psize_t);
    conRESULT (P2P_CON_CALL P2PeerTarget::*pfn_ConPKeyXChangeAck)(P2PeerCon*,const void*,P2Psize_t);
    conRESULT (P2P_CON_CALL P2PeerTarget::*pfn_ConCypherEx)(P2PeerCon*,P2PeerMsg*);
};

union P2PeerMsgMapFunctions
{
	  P2P_PMSG pfn;   // Generic pointer
    msgRESULT (P2P_MSG_CALL P2PeerTarget::*pfn_Msg)(P2PeerMsg*);
    msgRESULT (P2P_MSG_CALL P2PeerTarget::*pfn_MsgCatch)(P2PeerMsg*);
    msgRESULT (P2P_MSG_CALL P2PeerTarget::*pfn_MsgReflect)(P2PeerMsg*);
    msgRESULT (P2P_MSG_CALL P2PeerTarget::*pfn_MsgReflectCatch)(P2PeerMsg*);
    msgRESULT (P2P_MSG_CALL P2PeerTarget::*pfn_MsgWin32)(WPARAM,LPARAM);
};

//
//  P2Pevent sink management 
//  NOTES: P2PeventSink specialisation in the context of P2PeerTarget's.
//       : Such P2Pevent's are posted back in the context of the P2PmsgPump
//         under which the sink was created.
//       : Refer On_P2Pevent() handler for further details
Targetcore_EXT P2PeventSinkID
CreateP2PeventSink ( P2PeerTarget *pTarget
                   , bool bReg4all = true );
