// Copyright © 2002-2013, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2Pwin32 prototypes and definitions.
//
//
#pragma   once

#include "TargetCore.h"
#include "P2PeerHub.h"

//
//  P2Pmsg environment
//  NOTES: Manage P2Pmsg environment.  Allocates and recovers
//         resources at startup and shutdown respectively.
//       : P2Pmsg environment must be started prior to P2PmsgHub
//         and P2PmsgPump creation
//       : Normally all P2PmsgHub's and P2PmsgPump's should be
//         destroyed prior to cleanup
TargetCore_EXT BOOL
StartupP2Pmsg ( UINT nMaxHubs = 64 );
TargetCore_EXT void
CleanupP2Pmsg ( );

//
//  P2PmsgHub management
//  NOTES: Manage the creation, operation and life cycle of
//         P2PmsgHub's.  P2P messages are only ever be exchanged 
//         between P2PmsgHub's
//       : Act as containers for P2PmsgPump's
TargetCore_EXT P2PmsgHubID
CreateP2PmsgHub  ( P2PadomSTR strP2Padom, P2PeerHub *pHub
                 , UINT nMaxPumps
                 , DWORD nNumberOfConcurrentThreads );

TargetCore_EXT P2PmsgHubID
GetP2PmsgHubID ( );
TargetCore_EXT P2PmsgHubID
GetP2PmsgHubID ( const P2PeerCon *pCon );
TargetCore_EXT P2PmsgHubID
GetP2PmsgHubContext ( );
                                 
void                                   // P2Padomain management
SetP2PmsgHubAdom ( P2PmsgHubID nHubID, P2PadomSTR strP2Padom );
P2PadomSTR
GetP2PmsgHubAdom ( P2PmsgHubID nHubID = 0 );
                                 
void                                   // P2Paddress management
SetP2PmsgHubAddr ( P2PmsgHubID nHubID, P2PaddrSTR strP2Paddr );
P2PaddrSTR
GetP2PmsgHubAddr ( P2PmsgHubID nHubID = 0 );
P2PaddrSTR
GetP2PmsgHubAddr ( const P2PeerCon *pCon );
int TargetCore_EXT
GetP2PmsgHubConCount ( P2PmsgHubID nHubID = 0 );
//  Is this address a hub held by THIS process?  (securityRevision.md §6.3)
//  NOTES: The mechanism the end-to-end waiver is keyed on, and the ONLY one it
//         may be keyed on.  The process already knows every hub it holds -
//         s_ThreadID_P2PmsgHub, under s_oCSectionP2PmsgHub - so this is a walk
//         of that map and an address compare, not a new piece of state that
//         could disagree with the registry it is derived from
//       : EXACT MATCH, never at-or-below.  A hub Alice held here says nothing
//         about Alice.Bob, which may perfectly well be a child hub on another
//         host; answering TRUE for it would waive the protections on precisely
//         the traffic that leaves the machine.  The router's own test is the
//         same equality - refer P2PeerCon::OpenAppMsgInbound, which decides
//         "is it for us" with oThisHub == strDst
//       : DOES NOT THROW, unlike its neighbours above.  It is asked on the IO
//         thread for every application message on a waived hub, and the answer
//         to "no such hub" is FALSE - which is the fail-closed answer, because
//         FALSE keeps the protections on
//       : TAKES THE HUB LOCK ONLY, and callers must not hold P2PeerHub's own
//         lock across it.  CreateP2PmsgHub takes HUB then PUMP; this takes HUB
//         alone and calls nothing while it holds it
TargetCore_EXT BOOL
IsP2PmsgHubInProcess ( P2PaddrSTR strP2Paddr );
//  Hub observability (Stage 4 step 13)
//  NOTES: Aggregates over ONE hub, for a monitor holding that hub's snapshot
//         and nothing else.  P2PeerHub::Serialise() reports all three as the
//         QueDepth, Accepted and PumpsMax fields, so a consumer of
//         MSG_P2PexpHub already has them; these are the same numbers for a
//         caller that would rather ask than parse
//       : NONE OF THEM THROWS, unlike every neighbour above.  They are read
//         by the serialiser that BUILDS a diagnostic, on every hub snapshot,
//         so a hub that has gone must be reportable rather than a second
//         fault.  0 means "no such hub", and a hub that does not exist has
//         nothing queued and has accepted nothing
TargetCore_EXT UINT
GetP2PmsgHubQueCount      ( P2PmsgHubID nHubID = 0 );
TargetCore_EXT UINT
GetP2PmsgHubAcceptedCount ( P2PmsgHubID nHubID = 0 );
//  Holds applied to this hub's connections since each was accepted (step 12).
//  NOTES: A dropped connection takes its tally with it, deliberately - this
//         answers "is this hub under pressure now", not "has it ever been".
//         The process-wide GetP2PmsgHeldCount() above never forgets
TargetCore_EXT UINT
GetP2PmsgHubHeldCount     ( P2PmsgHubID nHubID = 0 );
TargetCore_EXT UINT
GetP2PmsgHubPumpsMax      ( P2PmsgHubID nHubID = 0 );
TargetCore_EXT P2PaddrSTR
GetP2PmsgHubName ( P2PmsgHubID nHubID = 0 );
TargetCore_EXT void
RegisterP2PmsgHub ( P2PeerTarget *pTarget, P2Pri_t nPriority = -127 );

HANDLE
GetIOCP          ( );
HANDLE
CreateP2PmsgHubIOCP ( HANDLE hFile );
void                                   // P2PeerCon management
PostP2PmsgCon    ( P2PmsgHubID nHubID, P2PeerCon *pCon );
void
DropP2PmsgCon    ( P2PeerCon *pCon );
// EXPORTED (2026-08-04).  A hub can hold MORE THAN ONE connection answering to
// one peer address -- AcceptSpawn (P2PeerCon.cpp:221-256) posts the accepted
// clone onto the same hub and copies m_oThatP2Paddr from the listener, so a
// NAMED listen leaves the armed service beside the connection that actually
// logs in.  P2PeerHub::ConQuery returns the FIRST of those, which is the
// service: it never logs in, and AcceptSpawn gave the clone a Clone() of the
// P2Peerio, so anything read or written through the service (trace, encrypted,
// the size limits, the state bits) is about an object carrying no traffic.
// Choosing between them needs the whole list, which until now no caller
// outside this DLL could see.  Callers outside: hold the hub's own
// m_oCSectionHub across the walk, exactly as ConQuery does.
TargetCore_EXT BOOL
EnumP2PmsgCon    ( P2PmsgHubID nHubID, P2PeerCon **pCon );
P2PeerCon*
NextP2PmsgCon    ( DWORD eMsgCon );

TargetCore_EXT bool
P2PmsgHubExists( P2PmsgHubID nHubID );

const P2PsigID P2PsigHub_CLOSE       = 1;
const P2PsigID P2PsigHub_CLOSEONIDLE = 2;
const P2PsigID P2PsigHub_PAUSE       = 3;
const P2PsigID P2PsigHub_WAKEUP      = 4;
TargetCore_EXT BOOL
SignalP2PmsgHub ( P2PmsgHubID nHubID, P2PsigID nSigID );
TargetCore_EXT void
CloseP2PmsgHub ( );

const DWORD P2PmsgHub_IDLE        = (1<<0);
const DWORD P2PmsgHub_CLOSE       = (1<<1);
const DWORD P2PmsgHub_CLOSEONIDLE = (1<<2);
const DWORD P2PmsgHub_USERDEF1    = (1<<16);

//
//  P2PmsgPump management
//  NOTES: Manage the creation, operation and life cycle of
//         P2PmsgPump's.
//       : Act as priority queues for P2Pmsg's 
TargetCore_EXT P2PumpID
CreateP2PmsgPump ( P2PmsgHubID nHubID, LPCTNAM lpszName, P2PeerTarget *pTarget );
TargetCore_EXT BOOL
EnumP2PmsgPump   ( P2PmsgHubID nHubID, P2PumpID& nPumpID );
TargetCore_EXT P2PumpID
GetP2PmsgPumpID  ( );
TargetCore_EXT P2PaddrSTR
SetP2PmsgPumpName( P2PumpID nPumpID, P2PaddrSTR strName );
TargetCore_EXT P2PaddrSTR
GetP2PmsgPumpName( P2PumpID nPumpID = 0 );
TargetCore_EXT P2PaddrSTR
SetP2PmsgPumpFunc( P2PumpID nPumpID, P2PaddrSTR strFunc );
TargetCore_EXT HANDLE
GetP2PmsgPumpHANDLE ( );

TargetCore_EXT UINT
PostP2Pmsg ( P2PaddrSTR strP2Paddr, UINT nCode, P2Pmsg_t nMsg
           , P2PeerCon *pCon, P2PeerMsg *pMsg, P2PumpID nP2PumpID = 0 );
TargetCore_EXT P2PeerMsg*
PostP2Pmsg ( P2PeerMsg *pMsg, P2PumpID nP2PumpID
           , bool bPrepend = false );
// W6 (p2p_PumpPerf.md) - batch producer handoff: post a bounded span of P2PeerMsg
// to one pump under a single registry lookup + a single m_oCSection acquire + a
// single wake (via W2).  Caller keeps nCount well below the queue cap (the pump
// cannot drain while the batch holds the lock).  Additive; single-post untouched.
TargetCore_EXT void
PostP2PmsgBatch ( P2PeerMsg **apMsg, size_t nCount, P2PumpID nPumpID );
TargetCore_EXT UINT
PostP2Pmsg ( DWORD hPumpID
           , P2Pmsg_t nMsg, WPARAM wParam, LPARAM lParam );
// W3 (p2p_PumpPerf.md) - inline recv->dispatch.  Dispatch an inbound application
// P2PeerMsg in place instead of round-tripping the pump's own FIFO, but ONLY when
// the destination pump is the one running this thread AND its FIFO is empty (so
// no queued message can be overtaken).  Returns true if dispatched inline; false
// (not the local pump / FIFO not empty / no pump) so the caller falls back to the
// 6-arg PostP2Pmsg, preserving per-connection FIFO ordering exactly.
TargetCore_EXT bool
TryInlineDispatchP2Pmsg ( P2PaddrSTR strP2Paddr, P2PeerMsg *pMsg, P2PumpID nPumpID );

TargetCore_EXT BOOL
RunP2PmsgPump ( );
const DWORD P2PmsgPump_TIMEOUT = 1;
const DWORD P2PmsgPump_MSG     = 2;
const DWORD P2PmsgPump_CON     = 3;
const DWORD P2PmsgPump_IOCP    = 4;
const DWORD P2PmsgPump_SIGNAL  = 5;
const DWORD P2PmsgPump_TIMER   = 6;
TargetCore_EXT DWORD
WaitForP2Pmsg ( DWORD dwMSecs );
TargetCore_EXT DWORD
PumpP2Pmsg ( DWORD dwMSecs, P2PsigID& nSigID );

const P2PsigID P2PsigPump_CLOSE       = 1;
const P2PsigID P2PsigPump_CLOSEONIDLE = 2;
const P2PsigID P2PsigPump_WAKEUP      = 3;
const P2PsigID P2PsigPump_UDSOS       = 0x0100;  // User defined signal offset
TargetCore_EXT BOOL
SignalP2PmsgPump ( P2PumpID nPumpID, P2PsigID nSigID );

TargetCore_EXT bool
CheckP2PmsgPumpState ( UINT nCode, P2Pmsg_t nMsg );
TargetCore_EXT bool
P2PmsgPumpExists( P2PumpID nPumpID );
TargetCore_EXT bool
IsP2PmsgPumping ( P2PumpID nPumpID = 0 );

//
//  Backoff for the loops that spin on P2PmsgPumpExists()/P2PmsgHubExists()
//  waiting for a pump or hub to appear or retire.
//
//  Those probes take the global pump-registry critical section on EVERY call,
//  and so does the pump thread at the top of every PumpP2Pmsg() visit.  Yielding
//  with SwitchToThread() alone is not enough: it only offers the processor to a
//  thread ready to run on the SAME core, so on a multi-core box the prober
//  reacquires the registry lock immediately and can starve the very pump it is
//  waiting on.  CloseHub() hung indefinitely that way - the CLOSE signal sat
//  queued on the pump while the pump never got the lock to observe it.
//
//  Stay hot for the first few turns (a retiring pump normally disappears within
//  a handful of probes, and an unconditional Sleep would put a millisecond onto
//  every hub teardown), then fall back to a real sleep, which always lets the
//  target thread run whichever core it is on.
//
inline void
YieldForP2PmsgPump ( UINT& uSpins )
{
    if ( ++uSpins <= 64 )
      SwitchToThread ( );
    else
      Sleep ( 1 );
}
TargetCore_EXT void
CloseP2PmsgPump ( );

TargetCore_EXT UINT
GetP2PmsgCount ( P2PumpID nPumpID = 0 );

//  Backpressure on the P2Pmsg budget (Stage 4 step 12)
//  NOTES: s_cP2PmsgMAX is a CLIFF - a peer may send as fast as it likes up to
//         it, and the failure at it is an exception on whichever thread
//         happened to post the message that crossed it.  These marks make the
//         same budget a slope: at or above HIGH a connection stops asking its
//         transport for more, at or below LOW it starts again, and the gap
//         between them is hysteresis rather than decoration
//       : ALWAYS ON.  The defaults are three quarters and one half of the
//         existing ceiling, so nothing in the suite comes near them and
//         turning it on by default changes no measurable behaviour.  An opt-in
//         default would leave the cliff standing for every deployment that did
//         not know to ask, which is the complaint
//       : Settable so that a deployment can feel it earlier - and so that a
//         test can reach it at all.  Refer SetP2PmsgBudgetMarks for the
//         validation, which throws rather than clamping
TargetCore_EXT void
SetP2PmsgBudgetMarks ( DWORD dwHigh, DWORD dwLow );
TargetCore_EXT DWORD
GetP2PmsgBudgetHigh  ( );
TargetCore_EXT DWORD
GetP2PmsgBudgetLow   ( );
TargetCore_EXT DWORD
GetP2PmsgBudgetMax   ( );
//  NOT the negation of each other: between the marks both are false, which is
//  the band in which a holder keeps holding and a reader keeps reading
TargetCore_EXT bool
P2PmsgBudgetPressed  ( );
TargetCore_EXT bool
P2PmsgBudgetRelieved ( );
//  The decision, visible in a counter, for a caller with no hub in hand.
//  Per-connection attribution is P2PeerCon::GetRecvThrottleCount() and the
//  hub's own figure is the Throttled field of its snapshot
TargetCore_EXT DWORD
GetP2PmsgHeldCount   ( );
//  NOT exported, deliberately.  P2PeerCon is inside this DLL and is the only
//  thing entitled to move the counter; a consumer that could inflate it could
//  make a hub look busy, which is the one thing the number is for
void
BumpP2PmsgHeldCount  ( );
TargetCore_EXT BOOL
SetP2PmsgEvent ( P2PumpID nPumpID = 0 );
TargetCore_EXT void
FlushP2Pmsg    ( P2PumpID nPumpID = 0 );

//
//  P2PmsgTimer management
//  NOTES: Manage the manufacture, translation, dispatch and
//         life cycle of internal P2PmsgTimer's
//       : Available from P2PeerCon, P2PeerTarget and P2Peerio
//         objects
TargetCore_EXT UINT
SetP2PmsgTimer   ( P2PaddrSTR strP2Paddr, UINT nCode, P2Pmsg_t nMsg
                 , P2PeerCon *pCon, P2PeerMsg *pMsg
                 , P2Pmsecs_t uiTimeout, DWORD nPumpID = 0 );
TargetCore_EXT PITimerID
SetP2PmsgTimer   ( P2PumpID nPumpID, P2Peerio *pP2Peerio
                 , P2Pmsecs_t uMSecDelay, DWORD dwUserKey );
TargetCore_EXT PITimerID
SetP2PmsgTimer   ( P2PumpID nPumpID, P2PeerCon *pCon
                 , P2Pmsecs_t uMSecDelay, DWORD dwUserKey );
TargetCore_EXT PITimerID
SetP2PmsgTimer   ( P2PumpID nPumpID, P2PeerTarget *pTarget
                 , P2Pmsecs_t uMSecDelay, DWORD dwUserKey );
TargetCore_EXT P2Pmsecs_t
NextP2PmsgTimer  ( P2PumpID nPumpID = 0 );
TargetCore_EXT UINT
KillP2PmsgTimer  ( PITimerID nPITimerID, P2PumpID nPumpID = 0 );
TargetCore_EXT void
CancelP2PmsgTimer( PITimerID nPITimerID, bool bCallback = true );

//
//  P2PeerMsg_MAP implementation prototypes
//  NOTES: Referenced from On_P2PeerMsg only
const P2P_MSGMAP_ENTRY* AFXAPI
FindP2PeerMsgEntry ( const P2P_MSGMAP_ENTRY *lpEntry
                   , P2PeerMsg *pMsg
                   , P2Pmsg_t nMsg, UINT nCode, UINT nID );
extern msgRESULT AFXAPI
DispatchP2PeerMsg  ( P2PeerTarget *pTarget, UINT nID, int nCode
                   , P2P_PMSG pfn, void *pvExtra
                   , UINT_PTR nSig
                   , P2P_MSGHANDLERINFO* pHandlerInfo );

//
//  P2PeerSnc_MAP implementation prototypes
//  NOTES: Referenced from On_P2PeerSnc only
const P2P_SNKMAP_ENTRY* AFXAPI
FindP2PeerSnkEntry ( const P2P_SNKMAP_ENTRY *lpEntry
                   , P2Pmsg_t nMsg, UINT nCode );
extern BOOL AFXAPI
DispatchP2PeerSnk  ( P2PeerTarget *pTarget, int nCode
                   , P2P_PSNK pfn, void *pvExtra
                   , UINT_PTR nSig
                   , P2P_SNKHANDLERINFO* pHandlerInfo );

//
//  P2PeerSys_MAP implementation prototypes
//  NOTES: Referenced from On_P2PeerSys only
const P2P_SYSMAP_ENTRY* AFXAPI
FindP2PeerSysEntry ( const P2P_SYSMAP_ENTRY *lpEntry
                   , P2Pmsg_t nMsg, UINT nCode );
extern BOOL AFXAPI
DispatchP2PeerSys  ( P2PeerTarget *pTarget, int nCode
                   , P2P_PSYS pfn, void *pvExtra
                   , UINT_PTR nSig
                   , P2P_SYSHANDLERINFO* pHandlerInfo );

//
//  P2PeerCon_MAP implementation prototypes
//  NOTES: Referenced from On_P2PeerCon only
const P2P_CONMAP_ENTRY* AFXAPI
FindP2PeerConEntry ( const P2P_CONMAP_ENTRY *lpEntry
                   , P2Pmsg_t nMsg, UINT nCode
                   , P2PeerCon *pCon, P2PeerMsg *pMsg );
extern conRESULT AFXAPI
DispatchP2PeerCon  ( P2PeerTarget *pTarget
                   , P2PeerCon *pCon, int nCode, P2Pmsg_t nMsg
                   , P2P_PMSG pfn, void *pvExtra
                   , UINT_PTR nSig
                   , P2P_CONHANDLERINFO* pHandlerInfo );

//
//  Processing context
//  NOTES: Manage the pump processing context of objects pumped
//         through the P2PeerCon_MAP, P2PeerSys_MAP and
//         P2PeerMsg_MAP's
mapRESULT
SwapP2PmsgContext  ( P2PeerTarget *pTarget, P2PumpID nPumpID
                   , P2PeerCon *pCon
                   , P2PeerMsg *pMsg
                   , HWND hWnd = 0, UINT nWM_APP = 0 );
mapRESULT
RedirectP2Pmsg ( P2PeerMsg *pMsg );
mapRESULT
RepumpP2Pmsg ( P2PeerMsg *pMsg );

//
//  Windows message loop integration prototypes and definitions
//  NOTES: Usually we delegate to OnP2PeerTarget() within the
//         MFC message map intercepting WM_APP_P2PeerTarget message
//       : Definition sequence is designed to trap use of the
//         message number elsewhere
//       : Usually the WM_APP_P2PeerTarget definition is nominated
//         for message exchange from the P2PeerHub to the CWinApp
//         thread.  Refer FIX-ME() for further details
const DWORD WM_APP_0x1FFF       = WM_APP + 0x1FFF;
const DWORD WM_APP_P2PeerTarget = WM_APP_0x1FFF;
TargetCore_EXT BOOL
CWnd_OnP2PeerTarget ( WPARAM wParam, LPARAM lParam );

//
//  P2Pevent sink management 
//  NOTES: Manage the creation, operation and life cycle of
//         P2PeventSink's.  Clients may register for P2Pevent
//         notifications
//       : Thread isolation of P2Pevent's
TargetCore_EXT BOOL
StartupP2Pevent ( );
TargetCore_EXT void
CleanupP2Pevent ( );
TargetCore_EXT BOOL
CloseP2PeventSink ( P2PeventSinkID nSinkID );
TargetCore_EXT P2PeventSinkID
CreateP2PeventSinkdebug ( DWORD_PTR dwCBKey
                   , P2PeventCBFnc pCBFnc
                   , bool bReg4all = true );
const DWORD P2Pevent_AddMask    = 1;
const DWORD P2Pevent_RemMask    = 2;
const DWORD P2Pevent_GetMask    = 3;
const DWORD P2Pevent_SetMask    = 4;
const DWORD P2Pevent_AddContext = 5;
const DWORD P2Pevent_RemContext = 6;
const DWORD P2Pevent_RstContext = 7;
TargetCore_EXT DWORD
RegP2PeventCmd ( P2PeventSinkID nSinkID
               , DWORD dwCmd
               , DWORD dwCmdArg );
TargetCore_EXT BOOL
EnumP2PeventSink ( P2PeventSinkID& nSinkID );
TargetCore_EXT DWORD
IsP2PeventReg ( DWORD dwP2PeventMask );
#define IsEVDBG (IsP2PeventReg(1<<P2Pevent_DEBUG)?true:false)
#define IsEVTRC (IsP2PeventReg(1<<P2Pevent_TRACE)?true:false)
#define IsEVLOG (IsP2PeventReg(1<<P2Pevent_LOG)?true:false)
//Msgcore_EXT P2Pevent*
//GetP2Pevent ( );
//TargetCore_EXT P2Pevent*
//IsolateP2Pevent ( );
TargetCore_EXT int
PerformP2PeventNotn ( P2Pevent *pEvent = 0 );

//
//  P2PmsgSinks
//  NOTES: Manage the manufacture, translation, dispatch and
//         life cycle of internal P2PmsgSinks's
TargetCore_EXT P2PmsgSinkID
P2PmsgSinkCreate (LPCTNAM lpszSinkname );
TargetCore_EXT BOOL
P2PmsgSinkRegister ( P2PmsgSinkID nP2PmsgSinkID, P2PeerTarget *pTarget, P2PsysID nP2PsysID = 0 );
TargetCore_EXT BOOL
P2PmsgSinkCancel ( P2PmsgSinkID nP2PmsgSinkID, P2PeerTarget *pTarget, P2PsysID nP2PsysID = 0 );
TargetCore_EXT BOOL
P2PmsgSinkClose ( P2PmsgSinkID nP2PmsgSinkID );
TargetCore_EXT BOOL
P2PmsgSinkIsValid ( P2PmsgSinkID nP2PmsgSinkID );
TargetCore_EXT BOOL
PostP2PmsgSink ( P2PmsgSinkID nP2PmsgSinkID, P2PsysID nP2PsysID
               , const P2PeerTarget *pTarget
               , WPARAM wParam, LPARAM lParam );
TargetCore_EXT BOOL
PostP2PmsgSink ( P2PmsgSinkID nP2PmsgSinkID, P2PsysID nP2PsysID
               , const P2PeerTarget *pTarget
               , const P3PmsgItem& oItem
               , WPARAM wParam, LPARAM lParam );

///////////////////////////////////////////////////////////////////////
//  Encoding
//  NOTES: Provides thread safe text encoding of defined parameter
//         types
LPCTSTR
EncodeP2Pmsg_t ( P2Pmsg_t nMsg );
