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
//  P2PeerTarget implementation.
//  NOTES: All objects within a virtual P2Peer network must derive
//         from P2PeerTarget
//

#include "stdafx.h"
#include "P2PeerHub.h"
#include "P2PeerTarget.h"
#include "P2Pwin32.h"

#include "Msgexception.h"

//
//  Construction and destruction
//
//
//  Parameters: P2PeerTarget *pTargetParent
//              Parent of this target.  Refer RegisterMsgTarget()
//              for further details
//
//              short nPriority
//              Priority applied to message map routing through
//              passed object
//              NOTES: Refer RegisterTarget() for further details
//
P2PeerTarget::P2PeerTarget ( )
{
    m_dwAddrTag        = (DWORD_PTR)this;
    m_uiValidObject    = (UINT_PTR)this;
}
P2PeerTarget::P2PeerTarget ( P2PeerTarget *pTargetParent
                           , P2Pri_t nPriority )
{
    // Firstly
    m_dwAddrTag     = (DWORD_PTR)this;
    m_uiValidObject = (UINT_PTR)this;
    //m_pTargetParent    = 0;
    //m_pTargetChildHi   = 0;
    //m_pTargetChildLo   = 0;
    //m_pTargetPrev      = 0;
    //m_pTargetNext      = 0;
    //m_nPriority        = nPriority;
    //m_pP2PmsgSinkIDmap = 0;

    // Associate with parent
    if ( pTargetParent )
      pTargetParent -> RegisterTarget ( this, nPriority );
}

P2PeerTarget::~P2PeerTarget(void)
{
    // Object validity flag.
    m_uiValidObject = 0;
    // Timers
    // NOTES: Target specific timers first.  Then globally cancel
    //        all timers outstanding for this object.
    //      : Targeting specific timers is best handled in derived
    //        class

    // P2PmsgSink's
    // NOTES: Recover those localised to this object
    if ( m_pP2PmsgSinkIDmap )
    {
      while ( m_pP2PmsgSinkIDmap->size() > 0 )
      {
        P2PmsgSinkIDmap::iterator it = m_pP2PmsgSinkIDmap->begin();
        P2PmsgSinkClose ( it->second );
        m_pP2PmsgSinkIDmap -> erase(it);
      }
      delete m_pP2PmsgSinkIDmap;
             m_pP2PmsgSinkIDmap = nullptr;
    }
     
    // Drop parent message map registration
    if ( m_pTargetParent )
      m_pTargetParent -> RemoveTarget ( this );

    // Drop hi-priority target registrations
    while ( m_pTargetChildHi )
      RemoveTarget ( m_pTargetChildHi );

    // Drop lo-priority target registrations
    while ( m_pTargetChildLo )
      RemoveTarget ( m_pTargetChildLo );
}

///////////////////////////////////////////////////////////////////////
//  P2PmsgPump management
//  NOTES: Started using default P2PeerTarget::SpawnTarget() or
//         CreateTarget() implementations

typedef struct
{
    P2PumpID      *pnPumpID;
    P2PeerTarget   *pTarget;
    P2Paddr         oP2Paddr;
    RUN_PUMP      pfnRunPump;
} P2PumpContext;

//
//  Creates P2PmsgPump and commences pumping
//  NOTES: Thread processing may be stopped via Close()
//
//
//  Parameters: LPTHREAD_START_ROUTINE pfnThreadProc
//              The thread procedure of the new thread.  Refer
//              win32 CreateThread() for further details
//
//              RUN_HUB pfnRunHub = 0
//              Operational method of the new thread
//
//              P2PumpID *pnPumpID
//              Pointer to pump identification code.  Retained
//              and cleared upon P2PmsgPump closure.
//
//  Returns:    HANDLE
//              Returns the handle to the newly created thread
//              or NULL on failure.
//
HANDLE
P2PeerTarget::SpawnPump ( LPTHREAD_START_ROUTINE pfnThreadProc
                        , RUN_PUMP  pfnRunPump
                        , LPCTNAM   lpszName
                        , P2PumpID  *pnP2PumpID )
{
    // Preparation
    if ( pfnThreadProc == NULL )
      pfnThreadProc = P2PeerTarget::ProcPump;
    if ( pfnRunPump == NULL )
      pfnRunPump = RUN_PUMP_cast(&P2PeerTarget::RunPump);
    ASSERT(pfnRunPump);

    // Pass context through
    P2PumpContext oContext;
                  oContext.pnPumpID   = pnP2PumpID;
                  oContext.pTarget    =   this;
                  oContext.oP2Paddr   = lpszName;
                  oContext.pfnRunPump = pfnRunPump;
    HANDLE hThread = CreateThread ( 0, 0
                                  , pfnThreadProc, &oContext //pvParam
                                  , 0, pnP2PumpID );
    if ( !hThread )
      return FALSE;

    // Confirm operation
    // NOTES: Contracted for P2PmsgPump operation upon return
    DWORD dwExitCode;
    UINT  uSpins = 0;
    while ( !P2PmsgPumpExists(*pnP2PumpID) )
    {
      if ( !GetExitCodeThread(hThread,&dwExitCode)                ||
                                       dwExitCode != STILL_ACTIVE    )
        return 0;                      // Operational failure
      YieldForP2PmsgPump ( uSpins );   // Yield (escalating - see header)
    }

    // Tidy up and
    return P2PmsgPumpExists(*pnP2PumpID) ? hThread : 0;
}

//
//  Closes or stops pump operation
//  NOTES: Pump operation may be re-started via
//         P2PeerTarget::SpawnPump() or P2PeerTarget::CreatePump()
//
//  Parameters: P2PumpID nPumpID
//              Identification code of pump to be closed
void
P2PeerTarget::ClosePump ( P2PumpID nPumpID )
{
    // Close and confirm
    SignalP2PmsgPump ( nPumpID, P2PsigPump_CLOSE );
    UINT uSpins = 0;
    while ( P2PmsgPumpExists(nPumpID) )
      YieldForP2PmsgPump ( uSpins );
}

//
//  Default thread starting address nominated in CreateThread()
//  NOTES: Provide alternative implementation to override default
//         action.  Follows P2PeerPump::ProcVanilla() base class pattern
//
//
//  Parameters:  void *pvContext
//               Thread data passed via CreateThread()
//
//  Returns:     DWORD
//               Completion code
//
DWORD WINAPI
P2PeerTarget::ProcPump ( void *pvContext )
{
    // Because this is all problematic we
    try
    {
      // Introduce locals
      // NOTES: P2PumpContext is assumed not to persist
      P2PumpContext *pContext = static_cast<P2PumpContext *>(pvContext);
      P2PeerTarget  *pTarget  = pContext -> pTarget;
      P2PumpID     *pnPumpID  = pContext -> pnPumpID;
      //P2PmsgHubID    nHubID   = pTarget  -> GetHubID ( );
      RUN_PUMP     pfnRunPump = pContext -> pfnRunPump;
      pTarget -> P2PeerTarget::AssertValid ( );

      // Mandatory P2PeerPump thread environment
      // NOTES: Sequence contains mandatory P2PeerPump and P2Pmsg
      //        life cycle management sequences
      CreateP2PmsgPump ( pTarget->GetHubID()
                       , pContext->oP2Paddr.c_name(), pTarget );
      (pTarget->*pfnRunPump) ( );
      if ( pnPumpID && *pnPumpID == GetCurrentThreadId() )
        *pnPumpID = 0;                 // Flags pump closure
      CloseP2PmsgPump ( );
    }
    // Exceptions
    catch_pP2Pevent_Cancel
    catch_pCException_Cancel
    catch_ALL_Cancel

    // Tidy up, and
    return 0;
}

//
//  Plain network P2PmsgPump implementation
//  NOTES: Simply pumps P2PeerSys, P2PeerCon and P2PeerMsg objects
//         through the P2PeerTarget base class
//       : Usually P2PeerMsg's are swapped to the context of this
//         thread via ContextSwap() and processed independantly in
//         the fullness of time
//       : It's possible to have processing delays in this context.
//         But keep in mind P2PeerMsg's may keep building up
//
void
P2PeerTarget::RunPump (  )
{
    // Locals
    DWORD    dwResult;
    P2PsigID  nSigID;

    // Because this is all problematic we
    try
    {
      // Latencies
      SetP2PmsgPumpFunc ( 0, T__FUNCTION__ );
      ThrowP2Pevent();

      // Pump messages through the P2PeerSys, P2PeerCon and
      // P2PeerMsg_MAP's until terminated and exhausted
      while ( (dwResult=PumpP2Pmsg(8000,nSigID)) != 0 )
      {
        // Immediate closure signalled
        if ( nSigID == P2PsigPump_CLOSE )
          break;

        // Idle closure signalled
        if ( nSigID == P2PsigPump_CLOSEONIDLE )
          break;

        // Wakeup signalled
        if ( nSigID == P2PsigPump_WAKEUP )
          continue;
      }
    }

    // Exceptions
    catch ( P2Pevent *pEVT)
    {
      pEVT->Advice("P2PmsgPump() has terminated" )
          ->Cancel();
    }
    catch ( ... )
    {
      EVERR->MODULE
           ->Message("Last resort exception of unknown type, "
                     "P2PmsgPump has terminated" )
           ->Cancel();
    }

    // Tidy up, and
}

//
//  Performs post P2PmsgHub destruction processing
//  NOTES: Specialise for external notifications etc
//
void
P2PeerTarget::PostDestroyPump ( P2PumpID )
{
}

///////////////////////////////////////////////////////////////////////
//  Message manufacture

//
//  Manufactures P2PeerMsg object
//  NOTES: Message will be tagged and flagged for
//         reflection back to this P2PeerTarget instance
//
//
//  Parameters:  P2PeerID strDestin
//               Message destination address
//
//               P2Pmsg_t nMsg
//               Message type
//
//               const void *pvData
//               Optional message data copied directly into
//               manufactured message.  NULL pointer negates copy
//               operation
//
//               short nDataSize
//               Message data length
//
//  Returns:     P2PeerMsg*
//               Manufactured message.  Client becomes responsible
//               for life cycle
//
P2PeerMsg*
P2PeerTarget::P2PeerMsgFactory ( P2PaddrSTR  pDestinSTR
                               , P2PmsgID    sMsg
                               , const void *pvData, short nDataSize )
{
    // Manufacture
    P2PeerMsg *pMsg = new P2PeerMsg ( GetP2PaddrHub(), pDestinSTR
                                    , sMsg
                                    , pvData, nDataSize );

    // Address tag
    // NOTES: For instances when similar P2PeerMsg's originate
    //        from multiple P2PeerTarget's for the same P2Peer.
    //        This tag is used to route possible P2PeerMsg exceptions
    //        and reflections back to this P2PeerTarget
    pMsg -> SetAddrTag ( &m_dwAddrTag, sizeof(m_dwAddrTag) );

    // Tidy up and
    return pMsg;
}

//
//  Assigns message ownership to this target
//
//
//  Parameters: P2PeerMsg *pMsg
//              Message whose ownership is to be assigned to this
//              object.
//
void
P2PeerTarget::AssignOwnership  ( P2PeerMsg *pMsg )
{
//TODO:LJM Check message is not being pumped etc
    // Simply
    pMsg -> SetSource  ( GetP2PaddrHub() );
    pMsg -> SetAddrTag ( &m_dwAddrTag, sizeof(m_dwAddrTag) );
}
BOOL
P2PeerTarget::HasOwnership  ( P2PeerMsg *pMsg )
{
    return pMsg->AddrTag() == m_dwAddrTag ? TRUE : FALSE;
}

///////////////////////////////////////////////////////////////////////
//  P2Pump context
//  NOTES: P2PeerContext() is used to check current P2Pump context
//         and the P2PeerContextSwap() implementations are used to
//         swap context.
//       : When context swapping occurs the P2PeerCon or P2PeerMsg
//         objects will be re-routed to the same handler but in
//         the context of the nominated thread.
//       : An exception is generated if not used in the context of
//         P2PeerCon_MAP, P2PeerMsg_MAP and P2PeerSys_MAP handlers

//
//  Confirms P2PmsgHub or P2PmsgPump processing context 
//  NOTES: Usually called from P2PeerCon notification or P2PeerMsg
//         handlers to confirm processing is occuring in the correct
//         thread context
//       : Under some circumstances P2PeerCon and P2PeerMsg objects
//         may be managed in one context and processed in another
//
//
//  Parameters: P2PumpID nPumpID
//              Pump whose context the P2PeerCon or P2PeerMsg
//              object is to be processed
//
//  Returns:    bool
//                TRUE... Process in current context
//                FALSE.. Requires P2PeerContextSwap()
//
bool
P2PeerTarget::P2PeerContext ( P2PumpID nPumpID )
{
    // Compare current with passed context
    if ( GetCurrentThreadId() == nPumpID )
      return TRUE;

    // Post to other context
    return FALSE;
}

//
//  Swaps the processing context for the current P2Pmsg object to
//  the nominated pump
//  NOTES: Context swap details are always thrown as as exceptions
//       : The exception will be intercepted, context swapped and
//         implemented directly through this P2PeerTarget instance
//
//  Parameters: P2PmsgPump nPumpID
//              Identifier of pump in which context the P2PeerCon
//              or P2PeerMsg object is to be processed
//
//  Returns:    mapRESULT
//              Context swap object (msgSWAP)
//               
mapRESULT
P2PeerTarget::P2PeerContextSwap ( P2PumpID nPumpID )
{
    // Delegate
    return SwapP2PmsgContext ( this, nPumpID
                             , (P2PeerCon *)0, (P2PeerMsg *)0 );
}

//
//  Swaps the processing context for the current P2Pmsg object to
//  the nominated window
//  NOTES: Context swaps MUST be immediately propagated back up through
//         the stack for implementation.  Outcome is undefined when
//         attempting further processing on a P2PeerMsg flagged for
//         a context swap.
//
//
//  Parameters: HWND hWnd
//              Window containing nWM_APP message handler that
//              subsequently delegates implementation via
//              pContext->pTarget->On_P2P(...)
//
//              UINT nWM_APP
//              WM_APP+offset message  
//              NOTES: Usually the WM_APP_P2PeerTarget definition is
//                     specified.  Should this definition conflict the
//                     option is available to specify an alternative.
//                   : Nominated window must support handler for this
//                     message type.  This handler will subsequently
//                     delegate implementation to OnP2PeerTarget()
//
//  Returns:    mapRESULT
//              Context swap object (msgSWAP)
//               
mapRESULT
P2PeerTarget::P2PeerContextSwap ( HWND hWnd, UINT nWM_APP )
{
    // Delegate
    return SwapP2PmsgContext ( this, AfxGetApp()->m_nThreadID
                             , (P2PeerCon *)0, (P2PeerMsg *)0
                             , hWnd, nWM_APP );
}

//
//  Swaps the processing context for the current P2PeerCon object
//  NOTES: Context swaps MUST be immediately propagated back up through
//         the stack for implementation.  Outcome is undefined when
//         attempting further processing on a P2PeerMsg flagged for
//         a context swap.
//
//
//  Parameters: P2PeerCon *pCon
//              Connection object to which current P2PeerMsg is to be
//              queued
//
//  Returns:    mapRESULT
//              Context swap object (msgSWAP)
//               
mapRESULT
P2PeerTarget::P2PeerContextSwap ( P2PeerCon *pCon, P2PeerMsg *pMsg )
{
    // Throw change in P2Pmsg context exception
    return SwapP2PmsgContext ( this
                             , 0, pCon, pMsg );
}

//
//  Swaps the processing context with respect to the current P2PeerMsg object
//  NOTES: Context swaps MUST be immediately propagated back up through
//         the stack for implementation.  Outcome is undefined when
//         attempting further processing on a P2PeerMsg flagged for
//         a context swap.
//
//  Returns:     mapRESULT
//               Context swap object (msgSWAP)
//               
mapRESULT
P2PeerTarget::P2PeerContextSwap ( P2PeerMsg *pMsg )
{
    // Throw change in P2Pmsg context exception
    return SwapP2PmsgContext ( this
                             , 0, (P2PeerCon *)0, pMsg );
}

///////////////////////////////////////////////////////////////////////
//  Timers
//  NOTES: Timers are managed under the context of the P2PmsgPump in
//         which they are created

//
//  Sets PIT for this P2PeerTarget object
//  NOTES: Outstanding timers must be cancelled in destructor for
//         this object
//
//
//  Parameters: P2Pmsecs_t uMSecDelay
//              Specifies the time-out value, in milliseconds
//
//              DWORD dwUserKey
//              User defined data key supplied to timeout handler
//
//  Returns:    PITimerID
//              Identifier of the new timer if successful. An
//              application passes this value to the KillTimer member
//              function to kill the timer.
//
PITimerID
P2PeerTarget::SetPITimer ( P2Pmsecs_t uMSecDelay, DWORD dwUserKey )
{
    // Delegate
    // NOTES: Handler for this object always called
    return SetP2PmsgTimer ( 0, this, uMSecDelay, dwUserKey );
}

//
//  Sets PIT for connection
//  NOTES: Outstanding timers must be cancelled in destructor for
//         this object
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Timer message
//
//               P2PeerTime_t uMSecDelay
//               Specifies the time-out value, in milliseconds
//
//               DWORD dwUserKey
//               User defined data key supplied to timeout handler
//
//  Returns:     PITimerID
//               Identifier of the new timer if successful.
//
PITimerID
P2PeerTarget::PostPITimer ( P2PeerMsg *pMsg
                          , P2Pmsecs_t uMSecDelay, DWORD dwUserKey )
{
    // Locals
    P2PeerMsg       *pMsgTimer = 0;
    Msg_P2PeerTimer  oP2PeerTimer;
                     oP2PeerTimer.dwUserKey = dwUserKey;

    // Manufacture 
    if ( pMsg )
      pMsgTimer = pMsg -> WrapFactory ( P2Pmsg_Timer
                                      , &oP2PeerTimer, sizeof(Msg_P2PeerTimer) );
    else
      pMsgTimer = new P2PeerMsg ( 0, 0, P2Pmsg_Timer
                                ,&oP2PeerTimer, sizeof(Msg_P2PeerTimer) );
    pMsgTimer -> SetSource ( GetP2PaddrHub() );
    pMsgTimer -> SetDestin ( pMsgTimer->GetSource() );

    // Deliver
    return SetP2PmsgTimer ( pMsgTimer->GetSource(), CN_P2PeerMsg, P2P_PITimer
                          ,(P2PeerCon *)0, pMsgTimer
                          , uMSecDelay, 0 );
}

//
//  Default PIT handler for P2PeerTarget
//  NOTES: Override for specialisation
//
//
//  Parameters:  bool bCancel
//               Cancellation flag.  Refer CancelPITimer() for further
//               details
//                 true... Cancelled
//                 false.. Triggered
//
//               PITimerID nPITimerID
//               Timer identification.  Refer SetPITimer() for
//               further details
//
//               DWORD dwUserKey
//               Timer user key
//
void
P2PeerTarget::On_PITimer ( bool bCancel
                         , PITimerID nPITimerID, DWORD dwUserKey )
{
    // Unknown timer
    // NOTES: Report and ignore
    EVERR->MODULE
         ->AFP(bCancel)->AFP(nPITimerID)->AFP(dwUserKey)
         ->Message(_T("PITimer not handled [P2PeerHub=%s]")
                  , GetP2PaddrHub().c_wstr() )
         ->Advice_T ("Ignored, bug (SNHappen)")
         ->Cancel ();
}

///////////////////////////////////////////////////////////////////////
//  P2Pevent's

//
//  Dedicated P2Pevent handler
//  NOTES: Processed in the context of the P2PeerTarget that created
//         the notifications sink
//
//
//  Parameters: P2PeventSinkID
//              Identification code of the Event sink for which the
//              notification sink is being performed.
//
//              P2PumpID nPumpID
//              Originating P2Pevent pump, 
//
//              const P2Pevent *pEvent
//              Posted event
//
//
evtRESULT
P2PeerTarget::On_P2Pevent( P2PeventSinkID nSinkID, P2PumpID nPumpID
                         , P2Pevent *pEvent )
{
    UNREFERENCED_PARAMETER(nSinkID);
    UNREFERENCED_PARAMETER(nPumpID);

    // Default implementation is to acknowledge
    // NOTES: Negate notifications to negate possible recursive feed
    //        back look
    pEvent -> Display ( (HWND)0 );

    // Tidy up, and
    return evtHANDLED;
}

///////////////////////////////////////////////////////////////////////
//  P2PeerCon integration
//  NOTES: The state of a P2PeerCon object is managed by the
//         asynchronous exchange between P2PeerCon_MAP handlers
//         and the P2PeerHub

//
//  Unhandled P2PeerCon notification
//  NOTES: Generates and cancels error event
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection for which notification not handled
//
//               P2Pmsg_t nMsg
//               Message type
//
void
P2PeerTarget::NotHandled ( P2PeerCon *pCon, P2Pmsg_t nMsg )
{
    // Explaination
    P2Pevent *pEVT =
      EVERR->MODULE->AFPcon(pCon)->AFP(nMsg)
           ->Message(L"ON_P2PeerCon_%s(%s,...) not handled"
                    ,  EncodeP2Pmsg_t(nMsg)
                    , (P2PaddrSTR)pCon->GetP2Paddress() )
           ->Advice (L"Version problem, bug, connection dropped" )
           ->Group  (L"P2P");

    // Tidy up, and
    //DropP2PmsgCon ( pCon );
    pCon -> Drop ( pEVT->Isolate() );
    pCon -> Destroy ( );
}

//
//  Post P2PeerCon object to linked parent P2PeerHub
//  NOTES: Control over lifecycle of passed P2PeerCon is assumed
//       : Altimately P2PeerCon objects may only ever be posted
//         to individual P2PeerHub's.
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object to be posted.
//
//  Returns:     P2PeerCon*
//               Connection posted flag
//                 0.. Posted
//
P2PeerCon*
P2PeerTarget::PostP2PeerCon ( P2PeerCon *pCon )
{
    // Nothing to pick up P2PeerMsg
    if ( m_pTargetParent == NULL )
    {
      EVERR->MODULE->AFPcon(pCon)
           ->Message("No linked P2PeerHub" )
           ->Advice ("Linked P2PeerTarget's must be terminated in P2PeerHub" )
           ->Advice ("Application bug (SNHappen)" )
           ->Cancel ( );
      return pCon;
    }

    // Simply
    // NOTES: Altimately parent P2PeerTarget will provide
    //        an implementation
    return m_pTargetParent -> PostP2PeerCon ( pCon );
}

//
//  Default P2PeerCon handler 
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object for which state transition
//               is to be routed
//
//               int nCode
//               Operational code
//
//               P2Pmsg_t nMsg
//               State transition message to be routed.
//
//               void *pExtra
//               Extra information.  Context sensitive
//
//               P2P_CONHANDLERINFO *pHandlerInfo
//
//  Returns:     BOOL
//                 TRUE... 
//                 FALSE..
BOOL
P2PeerTarget::On_P2PeerCon ( const P2Paddr& oP2Paddr, UINT nCode, P2Pmsg_t nMsg
                           , P2PeerMsg *pMsg, P2PeerCon *pCon
                           , P2P_CONHANDLERINFO* pHandlerInfo )
{
    // Introduce locals
    P2PeerTarget *pTarget;
    BOOL          bResult  = FALSE;
    BOOL          bMapcast = FALSE;

    // determine the message number and code (packed into nCode)
    const P2P_CONMAP       *pP2P_ConMap;
    const P2P_CONMAP_ENTRY *pEntry;

    // Hi-priority child delegation is always first
    // NOTES: All these priorities will be -ve.  Work backwards
    //        through the list.  A priority of -1 will be
    //        processed before -2 etc
    for ( pTarget = m_pTargetChildHi;
                     (    pTarget          &&
                       ( !bResult||bMapcast   )   );
                               pTarget = pTarget->m_pTargetNext )
      bResult |= pTarget -> On_P2PeerCon ( oP2Paddr, nCode, nMsg
                                         , pMsg, pCon
                                         , pHandlerInfo );

    // Traverse through message map to see if it applies to us
    // NOTES: Top down search. Derived class first then down
    //        through the base classes.
    //      : If there exists a desire to optimise then place
    //        frequent messages at the top of the message map
    //        and less frequent messages at the end of the list
    //      : Traverse continues until P2PeerCon flagged as
    //        handled.
    //      : The default set of handlers in this P2PeerTarget are
    //        not traversed in this instance.  Refer On_DefaultCon()
    //        processing for further details
    for ( pP2P_ConMap = GetP2PeerConMap();
                   (  pP2P_ConMap           &&
                      pP2P_ConMap->pBaseMap &&
                     !bResult                  );
	                            pP2P_ConMap = pP2P_ConMap->pBaseMap )
    {
		  // Trap BEGIN_P2PeerCon_MAP(CMyClass, CMyClass)!
      VERIFY(pP2P_ConMap != pP2P_ConMap->pBaseMap);

      // Search for handler in P2PeerCon map
      // NOTES: 
      pEntry = FindP2PeerConEntry ( pP2P_ConMap->lpEntries 
                                  , nMsg, nCode, pCon, pMsg );
		  if ( pEntry == NULL)
        continue;

      // Dispatch message
      // NOTES: P2PeerCon's are at most only ever handled once
      //        per map
      bResult = DispatchP2PeerCon ( this
                                  , pCon, nCode, nMsg
                                  , pEntry->pfn, pMsg
                                  , pEntry->nSig, pHandlerInfo );
    }

    // Lo-priority child delegation is always last
    // NOTES: All these priorities will be +ve.  Work forewards
    //        through the list.  A priority of +1 will be
    //        processed before +2 etc
    for ( pTarget = m_pTargetChildLo;
                     (    pTarget          &&
                       ( !bResult||bMapcast   )   );
                               pTarget = pTarget->m_pTargetNext )
      bResult |= pTarget -> On_P2PeerCon ( oP2Paddr, nCode, nMsg
                                         , pMsg, pCon
                                         , pHandlerInfo );

    // Tidy up and
    return bResult;                    // Handled summary
}
//
//  Default P2PeerCon handler
//  NOTES: Provides default processing services for pumped P2PeerCon
//         states changes that have not been intercepted and handled
//         via a P2PeerCon_MAP() entry
//       : The default processing services are sufficient for most pumped
//         P2PeerCon state changes.
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object for which state transition
//               is to be routed
//
//               int nCode
//               Operational code
//
//               P2Pmsg_t nMsg
//               State transition message to be routed.
//
//               void *pExtra
//               Extra information.  Context sensitive
//
//               P2P_CONHANDLERINFO *pHandlerInfo
//
//  Returns:     conRESULT
//                 TRUE... 
//                 FALSE..
BOOL
P2PeerTarget::On_DefaultCon ( UINT nCode, P2Pmsg_t nMsg
                            , P2PeerMsg *pMsg, P2PeerCon *pCon
                            , P2P_CONHANDLERINFO* pHandlerInfo )
{
    // Introduce locals
    BOOL          bResult  = FALSE;

    // Determine the message number and code (packed into nCode)
    const P2P_CONMAP       *pP2P_ConMap = P2PeerTarget::GetP2PeerConMap();
    const P2P_CONMAP_ENTRY *pEntry;

    // Search the base class only
    // NOTES: Isolates default processing in the P2PeerTarget assigned to
    //        the P2PeerPump
    //      : Access to these handlers is negated in the primary search
    //        and act as last resort defaults
    VERIFY(pP2P_ConMap&&pP2P_ConMap->pBaseMap==NULL);

    // Search for handler in P2PeerCon map
    // NOTES: Ideally there's always an entry
    pEntry = FindP2PeerConEntry ( pP2P_ConMap->lpEntries 
                                , nMsg, nCode, pCon, pMsg );

    // Dispatch message
    // NOTES: P2PeerCon's are at most only ever handled once
    //        per map
    if ( pEntry )
      bResult = DispatchP2PeerCon ( this
                                  , pCon, nCode, nMsg
                                  , pEntry->pfn, pMsg
                                  , pEntry->nSig, pHandlerInfo );

    // Tidy up and
    return bResult;                    // Handled summary
}

//
//  Pre-destruction handler for P2PeerCon objects
//  NOTES: Called as part of the P2PeerCon management procedures
//         immediately prior to destruction
//       : Override this default implementation for special processing,
//         resource recovery etc
//       : Specialisation should delegate to this base class
//         implementation to ensure propagation through the P2PeerTarget
//         heirachy
//
//
//  Parameters:  P2PeerCon *pCon
//               Completed processing message
//
//               conRESULT bConResult
//               Permutations
//                 conHANDLED... Handled
//                 conCONTINUE.. Not handled
//                 conDROP...... Handled, drop P2PeerCon object
//
void
P2PeerTarget::PreDestroyP2PeerCon ( P2PeerCon *pCon
                                  , conRESULT  bConResult )
{
    // Stops compiler warnings
    pCon       = pCon;
    bConResult = bConResult;

    // Hi-priority child delegation is always first
    // NOTES: All these priorities will be -ve.  Work backwards
    //        through the list.  A priority of -1 will be
    //        processed before -2 etc
    for ( P2PeerTarget *pTarget = m_pTargetChildHi; pTarget;
                                    pTarget = pTarget->m_pTargetNext )
      pTarget -> PreDestroyP2PeerCon ( pCon, bConResult );

    // Lo-priority child delegation is always last
    // NOTES: All these priorities will be +ve.  Work forewards
    //        through the list.  A priority of +1 will be
    //        processed before +2 etc
    for ( P2PeerTarget *pTarget = m_pTargetChildLo; pTarget;
                                    pTarget = pTarget->m_pTargetNext )
      pTarget -> PreDestroyP2PeerCon ( pCon, bConResult );
}

//
//  Exposes P2PeerHub to which this P2PeerTarget is ultimately linked
//  NOTES: RegisterTarget() and RemoveTarget() for managing
//         hierarchy's or P2PeerTarget objects
//
//
//  Returns      P2PeerHub*
//               Pointer to linked P2PeerHub in the P2Peer hierarchy
//
P2PeerHub*
P2PeerTarget::GetP2PeerHub ( )
{
    // Nothing to pick up implementation
    if ( m_pTargetParent == NULL )
      EVERR->MODULE
           ->Message("No linked P2PeerHub" )
           ->Advice ("Linked P2PeerTarget's must be terminated in P2PeerHub" )
           ->Advice ("Application bug (SNHappen)" )
           ->Throw();

    // Delegate
    // NOTES: Altimately the linked P2PeerHub will provide an
    //        implementation
    return m_pTargetParent -> GetP2PeerHub ( );
}

//
//  Exposes P2PmsgHubID to which this P2PeerTarget is ultimately linked
//  NOTES: RegisterTarget() and RemoveTarget() for  managing
//         hierarchy's or P2PeerTarget objects
//
//
//  Returns      P2PmsgHubID
//               Identification code of linked P2PeerHub in the
//               P2Peer hierarchy
//
P2PmsgHubID
P2PeerTarget::GetHubID ( ) const
{
    // Nothing to pick up implementation
    if ( m_pTargetParent == NULL )
      EVERR->MODULE
           ->Message("No linked P2PeerHub" )
           ->Advice ("Linked P2PeerTarget's must be terminated in P2PeerHub" )
           ->Advice ("Application bug (SNHappen)" )
           ->Throw();

    // Delegate
    // NOTES: Altimately the linked P2PeerHub will provide an
    //        implementation
    return m_pTargetParent -> GetHubID ( );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerTarget hierarchy management
 
//
//  Attaches P2PeerMsg map of the passed child P2PeerTarget to the
//  end of P2PeerMsg map for this the parent P2PeerTarget
//
//
//  Parameters:  P2PeerTarget *pTargetChild
//               Registered as child of this parent
//
//               short nPriority
//               Priority applied to message map routing through
//               passed object
//                 -ve.. Messages are routed through pTargetChild
//                       before being routed through this the parent.
//                       Convention is such that a priority of -1
//                       routes before -231.  A subsequent registration
//                       of priority -231 routes before the first.
//                 +ve.. Messages are routed through pTargetChild
//                       after being routed through this the parent.
//                       Convention is such that a priority of +1
//                       routes after +231.  A subsequent registration
//                       of priority +231 routes before the first.
//
void
P2PeerTarget::RegisterTarget( P2PeerTarget *pTargetChild, P2Pri_t nPriority )
{
    // Introduce locals
    P2PeerTarget *pTarget, *pTargetNext, *pTargetPrev;

    // To be sure, to be sure
    ASSERT(pTargetChild!=this);
    if ( pTargetChild->m_pTargetParent )
      EVERR->Module (L"%hs(%s)", __FUNCTION__, (LPCWSTR)m_csTargetName )
           ->Message(L"P2PeerTarget(%s) is already registered with (%s)"
                    , (LPCWSTR)pTargetChild->m_csTargetName
                    , (LPCWSTR)pTargetChild->m_pTargetParent->m_csTargetName )
           ->Advice (L"Duplicate registration" )
           ->Throw();
    pTargetChild -> m_pTargetParent = this;
    pTargetChild -> m_nPriority     = nPriority;
    pTargetChild -> m_pTargetNext   = 0;
    pTargetChild -> m_pTargetPrev   = 0;

    // Hi-priority parent linkage
    // NOTES: These P2PeerTarget's intercept P2PeerCon notifications
    //        and P2PeerMsg's before the parent
    if ( nPriority <= 0 )
    {
      pTargetNext = m_pTargetChildHi;
      pTargetPrev = 0;
      for ( pTarget = m_pTargetChildHi;
               ( pTarget                          &&
                 pTarget->m_nPriority < nPriority    );
                                 pTarget = pTarget->m_pTargetNext )
      {
        pTargetNext = pTarget->m_pTargetNext;
        pTargetPrev = pTarget;
      }

      pTargetChild -> m_pTargetNext = pTargetNext;
      pTargetChild -> m_pTargetPrev = pTargetPrev;

      if ( pTargetNext )
        pTargetNext -> m_pTargetPrev = pTargetChild;

      if ( pTargetPrev )
        pTargetPrev -> m_pTargetNext = pTargetChild;
      else
        m_pTargetChildHi = pTargetChild;
    }


    // Lo-priority parent linkage
    // NOTES: These P2PeerTarget's intercept P2PeerCon notifications
    //        and P2PeerMsg's before the parent
    if ( nPriority > 0 )
    {
      pTargetNext = m_pTargetChildLo;
      pTargetPrev = 0;
      for ( pTarget = m_pTargetChildLo;
               ( pTarget                          &&
                 pTarget->m_nPriority > nPriority    );
                                 pTarget = pTarget->m_pTargetNext )
      {
        pTargetNext = pTarget -> m_pTargetNext;
        pTargetPrev = pTarget -> m_pTargetPrev;
      }

      pTargetChild -> m_pTargetNext = pTargetNext;
      pTargetChild -> m_pTargetPrev;

      if ( pTargetNext )
        pTargetNext -> m_pTargetPrev = pTargetChild;

      if ( pTargetPrev )
        pTargetPrev -> m_pTargetNext = pTargetChild;
      else
        m_pTargetChildLo = pTargetChild;
    }
}

//
//  Removes P2PeerMsg map of the passed child P2PeerTarget from
//  the end of P2PeerMsg map for this the parent P2PeerTarget
//
//  Parameters:  P2PeerTarget *pTargetChild
//   y            Child to be attached to this parent
void
P2PeerTarget::RemoveTarget ( P2PeerTarget *pTargetChild )
{
    // To be sure, to be sure
    if ( pTargetChild->m_pTargetParent         &&
         pTargetChild->m_pTargetParent != this    )
      EVERR->Module (L"%hs(%s)", __FUNCTION__
                    , (LPCWSTR)m_csTargetName )
           ->Message(L"P2PeerTarget(%s) is registered with (%s)\n"
                    , (LPCWSTR)pTargetChild->m_csTargetName
                    , (LPCWSTR)pTargetChild->m_pTargetParent->m_csTargetName )
           ->Advice (L"Not registered with this object" )
           ->Throw();

    // Manage priority children of parent
    if ( m_pTargetChildHi == pTargetChild )
      m_pTargetChildHi = m_pTargetChildHi -> m_pTargetNext;
    if ( m_pTargetChildLo == pTargetChild )
      m_pTargetChildLo = m_pTargetChildLo -> m_pTargetNext;

    // Remove linkages
    if ( pTargetChild->m_pTargetPrev )
      pTargetChild -> m_pTargetPrev -> m_pTargetNext
            = pTargetChild->m_pTargetNext;
    if ( pTargetChild->m_pTargetNext )
      pTargetChild -> m_pTargetNext -> m_pTargetPrev
            = pTargetChild->m_pTargetPrev;

    // Tidy up and
    pTargetChild -> m_pTargetPrev   = 0;
    pTargetChild -> m_pTargetNext   = 0;
    pTargetChild -> m_pTargetParent = 0;
}

///////////////////////////////////////////////////////////////////////////////
//  P2PmsgSink integration
//  NOTES: Manages P2PmsgSink's in the P2PeerTarget domain context.  Which
//         in turn facilitates the direct injection of pumped objects into 
//         the P2PeerCon_MAP, P2PeerSys_MAP and P2PeerMsg_MAP's.

//
//   Registers this P2PeerTarget for receipt of P2PeerSys objects of the
//   designated type
//   NOTES: On_P2PeerSnc() message handlers must be declared which scope
//          of this object to handle registered P2PeerSys messages
//        : Such P2PeerSnc messages are pumped directly into this object
//          routing does NOT occur.
//
//   Parameters: P2PmsgSinkID nP2PmsgSinkID
//               Sink with which this P2PeerTarget is to be registered
//
//               P2PsysID nP2PsysID
//               Identification code of P2PeerSys messages to be received
//               NOTES: Refer On_P2PeerSnc() for handler declarations
//
void
P2PeerTarget::RegisterWithTargetSink ( P2PmsgSinkID nP2PmsgSinkID, P2PsysID nP2PsysID )
{
    P2PmsgSinkRegister ( nP2PmsgSinkID, this, nP2PsysID );
}
//
//   Cancels prior P2PeerTarget registration
//   NOTES: On_P2PeerSnc() message handlers must be declared which scope
//          of this object to handle registered P2PeerSys messages
//        : Such P2PeerSnc messages are pumped directly into this object
//          routing does NOT occur.
//
//   Parameters: P2PmsgSinkID nP2PmsgSinkID
//               Sink with which this P2PeerTarget is to be registered
//
//               P2PsysID nP2PsysID
//               Identification code of P2PeerSys messages whose 
//               prior registration is to be cancelled
//                 0... Cancel all prior registrations for P2PeerTarget
//
void
P2PeerTarget::CancelTargetSinkRegistration ( P2PmsgSinkID nP2PmsgSinkID, P2PsysID nP2PsysID )
{
    P2PmsgSinkCancel ( nP2PmsgSinkID, this, nP2PsysID );
}

//
//  Creates a P2PeerTarget domain sink
//  NOTES: LookupTargetSink() facilitates identification of domain sinks
//         from registered subordinate P2PeerTarget's
//
//  Parameters:  LPCTSTR lpszSinkname
//               Name allocated to P2PeerTarget domain sink
//
//  Returns:     P2PmsgSinkID
//               Allocated identification code.
P2PmsgSinkID
P2PeerTarget::CreateTargetSink ( LPCTNAM lpszSinkname )
{
    if ( m_pP2PmsgSinkIDmap == nullptr )
      m_pP2PmsgSinkIDmap = new P2PmsgSinkIDmap();
    P2PmsgSinkIDmap::iterator it = m_pP2PmsgSinkIDmap->find(lpszSinkname);
    if ( it != m_pP2PmsgSinkIDmap->end() )
    { // Assume sink does not already exist
      ASSERT(0);
      return it->second;
    }
    P2PmsgSinkID nP2PmsgSinkID = P2PmsgSinkCreate ( lpszSinkname );
    if ( nP2PmsgSinkID <= 0 )
      ThrowP2Pevent ( );               // Throws internal event
    P2PmsgSinkIDpair pair(lpszSinkname,nP2PmsgSinkID);
    m_pP2PmsgSinkIDmap -> insert(pair);
    return nP2PmsgSinkID;
}

//
//  Closes P2PeerTarget domain sink
//
//  Parameters:  P2PmsgSinkID nTargetSinkId
//               Identification of the P2PeerTarget domain sink
//
//  Returns:     P2PmsgSinkID
//                 0u.. Nullifier
P2PmsgSinkID
P2PeerTarget::CloseTargetSink ( P2PmsgSinkID nTargetSinkId )
{
    if ( m_pP2PmsgSinkIDmap )
    {
      m_pP2PmsgSinkIDmap->erase(L"");
      P2PmsgSinkIDmap::iterator it;
      for ( it = m_pP2PmsgSinkIDmap->begin(); it != m_pP2PmsgSinkIDmap->end(); )
      {
        if ( !nTargetSinkId               ||
              it->second != nTargetSinkId    )
        {
          P2PmsgSinkClose ( it->second );
          it = m_pP2PmsgSinkIDmap->erase(it);
        } else ++it;
      }
    }
    return 0u;
}

//
//  Retrieve P2PeerTarget domain sink
//  NOTES: Walk back up the P2PeerTarget tree until we find the
//         requested sink
//
//  Parameters:  LPCTSTR lpszSinkname
//               Name of sink within P2PeerTarget name to be retrieved
//
//  Returns:     P2PmsgSinkID
//               Identification code of located P2PmsgSink
//
P2PmsgSinkID
P2PeerTarget::LookupTargetSink ( LPCTNAM lpszSinkname )
{
    // Delegate backwards
    if ( m_pP2PmsgSinkIDmap == nullptr )
    {
      if ( m_pTargetParent == nullptr )
        return 0u;
      return m_pTargetParent->LookupTargetSink(lpszSinkname);
    }
    P2PmsgSinkIDmap::iterator it = m_pP2PmsgSinkIDmap->find(lpszSinkname);
    if ( it != m_pP2PmsgSinkIDmap->end() )
      return it->second;
    if ( m_pTargetParent == nullptr )
      return 0u;
    return m_pTargetParent -> LookupTargetSink ( lpszSinkname);
}

//
//  P2PeerMsg router
//  NOTES: Override this handler for message interceptions
//
//  Parameters:  P2PeerID nID
//               Identification code of orginating P2PeerHub
//
//               int nCode
//               P2PeerMsg code
//
//               NOTES: CN_P2PeerMsg
//                      Standard P2Peer message
//                    : CN_P2Peer
//                      Thrown by P2Peer framework
//
//               void *pExtra
//
//               P2P_CMDHANDLERINFO *pHandlerInfo
BOOL
P2PeerTarget::On_P2PeerMsg ( P2PaddrSTR pP2PaddrSTR, UINT nCode, P2Pmsg_t nMsg
                           , P2PeerMsg *pMsg, void *pvExtra
                           , P2P_MSGHANDLERINFO *pHandlerInfo )
{
    // Introduce locals
    P2PeerTarget *pTarget;
    BOOL          bResult  = msgCONTINUE;
    BOOL          bMapcast = FALSE;

    // Mapcasting
    if ( (nCode&CM_Mapcast) )
      bMapcast = TRUE;

    // determine the message number and code (packed into nCode)
    const P2P_MSGMAP       *pP2P_MsgMap;
    const P2P_MSGMAP_ENTRY *pEntry;

    // Hi-priority child delegation is always first
    // NOTES: All these priorities will be -ve.  Work backwards
    //        through the list.  A priority of -1 will be
    //        processed before -2 etc
    for ( pTarget = m_pTargetChildHi;
                     (    pTarget          &&
                       ( !bResult||bMapcast   ) );
                               pTarget = pTarget->m_pTargetNext )
      bResult |= pTarget -> On_P2PeerMsg ( pP2PaddrSTR, nCode, nMsg
                                         , pMsg, pvExtra
                                         , pHandlerInfo );
      
    // Traverse through message map to see if it applies to us
    // NOTES: Top down search. Derived class first then down
    //        through the base classes.
    //      : If there exists a desire to optimise then place
    //        frequent messages at the top of the message map
    //        and less frequent messages at the end of the list
    //      : Traverse continues until P2PeerMsg flagged as
    //        handled.
    pP2P_MsgMap = GetP2PeerMsgMap();
    while (    pP2P_MsgMap         &&
            ( !bResult||bMapcast )    )
    {
		  // Trap BEGIN_P2PeerMsg_MAP(CMyClass, CMyClass)!
      VERIFY(pP2P_MsgMap != pP2P_MsgMap->pBaseMap);
      pEntry = pP2P_MsgMap -> lpEntries;

      while ( ( !bResult||bMapcast ) &&
                 pEntry                 )
      {
        // Search for handler in P2PeerMsg map
        // NOTES: 
        pEntry = FindP2PeerMsgEntry ( pEntry //pP2P_MsgMap->lpEntries 
                                    , pMsg
                                    , nMsg, (nCode&CN_Mask), 0/*nID*/ );
        if ( !pEntry )
          break;

        // Dispatch message
        // NOTES: P2PeerMsg's are at most only ever handled once
        //        per map.  However, all subordinate maps are
        //        tried whenever map casting is switched on
        bResult = DispatchP2PeerMsg ( this, 0/*nID*/, (nCode&CN_Mask)
                                    , pEntry->pfn, pMsg
                                    , pEntry->nSig, pHandlerInfo );
        if ( bResult == msgCONTINUE )
        {
          pEntry += pEntry -> nOSets;
          continue;
        }
        if ( bResult == msgSWAP     ||
             bResult == msgREDIRECT ||
             bResult == msgREPUMP      )
          return bResult;

        // Map casting
        // NOTES: Recursively switched on.  Upon return assumes
        //        status of the previous level
        if ( pEntry -> bMapcast )
        {
          bMapcast  = TRUE;
          nCode    |= CM_Mapcast;
        }
        bResult     = msgHANDLED;
        pEntry      = 0;               // Breaks loop
        pP2P_MsgMap = 0;               // Breaks loop
      }

      // Step down through inheritance chain
      if ( pP2P_MsgMap )
        pP2P_MsgMap = pP2P_MsgMap -> pBaseMap;
    }

    // Lo-priority child delegation is always last
    // NOTES: All these priorities will be +ve.  Work forewards
    //        through the list.  A priority of +1 will be
    //        processed before +2 etc
    for ( pTarget = m_pTargetChildLo;
                     (    pTarget          &&
                       ( !bResult||bMapcast   ) );
                               pTarget = pTarget->m_pTargetNext )
      bResult |= pTarget -> On_P2PeerMsg ( pP2PaddrSTR, nCode, nMsg
                                         , pMsg, pvExtra
                                         , pHandlerInfo );

    // Tidy up and
    return bResult;                    // Handled summary
};

//
//  Post P2PeerMsg to linked parent P2PeerHub
//  NOTES: Control over lifecycle of passed P2PeerMsg is assumed
//       : Altimately posted messages are intercepted by P2PeerHub's
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be posted.
//
//  Returns:     P2PeerMsg*
//               Message posted flag
//                  0.. Posted OK
//
P2PeerMsg*
P2PeerTarget::PostP2PeerMsg ( P2PeerMsg *pMsg )
{
    // Manage message ownership
    // NOTES: Claimed by this object.  Should the P2PeerMsg prove
    //        undeliverable it will be thrown back and intercepted
    //        by this object
    if ( pMsg->AddrTag() == NULL )
      pMsg -> SetAddrTag ( &m_dwAddrTag, sizeof(m_dwAddrTag) );

    // Simply
    // NOTES: Altimately parent P2PeerTarget will provide
    //        an implementation
    if ( m_pTargetParent )
      return m_pTargetParent -> PostP2PeerMsg ( pMsg );

    // Nothing to pick up P2PeerMsg
    // NOTES: Release control over life cycle
    EVERR->MODULE->AFPmsg(pMsg)
         ->Message("No linked P2PeerHub" )
         ->Advice ("Linked P2PeerTarget's must be terminated in P2PeerHub" )
         ->Advice ("Application bug (SNHappen)" )
         ->Group("P2P")->SetLast( );
    return pMsg;
}

//
//  Generates P2Perror_UNKNOWN exception and reflects to P2PeerMsg source
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message within peer implementation
//
void
P2PeerTarget::NotHandled ( P2PeerMsg *pMsg )
{
    // Explaination
    P2Pevent *pEVT =
    EVERR->MODULE //->AFPmsg(pMsg)
         ->Message(L"Message[%s] not handled", pMsg->c_name() )
         ->Advice ("Version problem, bug" )
         ->HResult(P2Pevent_UNKNOWN)
         ->Group("P2P");
    // Delivery
    PostP2PeerMsg ( pMsg->ExceptionFactory ( pEVT ) );

    // Tidy up, and
    // NOTES: May or may not wish to report error locally
    BOOL bDisplay = P2PeerMsg_SetCtrlOptions(pMsg,0,0)&P2PeerMsgCtrl_HANDLED;
    pEVT -> Cancel ( bDisplay );
}

//
//  Re-declares an undeliverable report as coming from THIS hub
//  NOTES: F-S9-1.  ExceptionFactory() -> WrappedResponseFactory() swaps the
//         two addresses, so a response is sourced from the message's original
//         DESTINATION.  That is right everywhere else it is used, because
//         everywhere else the responder IS that destination: NotHandled() and
//         the Explorer's catch blocks answer a message that reached them.  On
//         the UNDELIVERABLE path it is the one case where the responder is
//         not the destination - the destination is precisely what could not
//         be reached - so the report went out declaring a source that,
//         in the worst and commonest case, EXISTS NOWHERE.
//       : What that cost is not hypothetical and is not about this hub.  A
//         report for [Ghost.Nowhere] arrives at its reader down a link to an
//         ANCESTOR carrying a source in no branch at all, and no attestation,
//         because nobody holds a key for an address that does not exist.  It
//         is byte-for-byte the shape P2PeerCon::GateRelayInbound refuses.
//         The gate therefore had to exempt P2Pmsg_Exception BY CLASS to keep
//         the library's own reports flowing, and that exemption let a peer on
//         an ancestor link forge a report against ANY source - telling an
//         application a message failed that did not.
//       : Stamping the hub's own address closes it at the source rather than
//         at the gate, and the exemption is gone.  A report now declares the
//         hub that RAISED it, which is both the truth and an address that
//         hub is entitled to speak for - so
//           - one hop down, the reader's plain descendant test admits it with
//             no attestation and no provisioning of any kind, which is the
//             common deployment and the one p2p_bigreport exercises;
//           - further down, P2PeerCon::AttestAppMsgOutbound signs it as the
//             ORIGIN, exactly as it signs anything else this hub sources, and
//             the reader verifies it against its allow-list.  That is the
//             whole of "the reporting hub signs the report as itself".
//       : WHAT A READER LOSES, stated rather than glossed: the report's
//         source is no longer the address that failed.  It is not lost, it
//         has moved - the report WRAPS the original message, so
//         UnwrapFactory()->GetDestin() is the failed address, and the
//         attached P2Pevent names it in an Advice line.  Consumers reading
//         GetSource() to find it must change; that is the wire-visible
//         semantic recorded as an unreleased break
//       : NEVER THROWS, and that is load-bearing rather than defensive.  The
//         caller is already in the middle of reporting a failure, and a hub
//         with no address (GetP2PaddrHub throws on an unparented target) or a
//         message that will not take a field must still get its report out -
//         degraded to the old behaviour, not dropped.  Losing the report is
//         the defect this whole path exists to avoid
//
//  Parameters:  P2PeerMsg *pReport
//               The report ExceptionFactory() has just built
//
//               P2PeerTarget *pThis
//               The reporting target, for its hub address
//
static void
StampReportOrigin ( P2PeerMsg *pReport, P2PeerTarget *pThis )
{
    if ( !pReport || !pThis )
      return;

    try
    {
      // A COPY, not the reference's c_wstr(). Off Windows every wide accessor
      // hands back a slot in a rotating thread-local ring, and SetSource()
      // makes further accessor calls before it consumes the argument - the
      // mistake this file records at RouteP2PeerMsg and WrappedResponseFactory
      const CString strHub = pThis -> GetP2PaddrHub ( ) . c_wstr ( );
      if ( strHub.IsEmpty ( ) )
        return;
      pReport -> SetSource ( (P2PaddrSTR)strHub );
    }

    // Swallowed on purpose - refer NEVER THROWS above
    catch ( P2Pevent *pEVT )
    {
      if ( pEVT )
        pEVT -> Cancel ( false );
    }
    catch ( ... )
    {
    }
}

//
//  Routes P2PeerMsg's through registered P2Peer's
//  NOTES: Local P2PeerMsg routing is handled in the derived class
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be routed.  Client must delegate
//               responsiblity for life cycle etc.
//
//  Result:      msgRESULT
//               Routing result
//
msgRESULT
P2PeerTarget::RouteP2PeerMsg ( P2PeerMsg *pMsg )
{
    // An undeliverable EXCEPTION is the end of the line
    // NOTES: The report below is addressed to the message's SOURCE, so an
    //        undeliverable exception would be reported to the address that
    //        raised it - which the exception itself has just proven
    //        unroutable.  Both endpoints are then known bad, and the report
    //        about the report is addressed to nobody by construction
    //      : Left uncapped this is not a slow leak, it is a LIVELOCK with
    //        amplification.  ExceptionFactory() embeds the whole of the
    //        undeliverable message as a BLOB16 inside the new one, and the new
    //        one is posted straight back to this hub's own pump, so each lap
    //        wraps the previous lap.  Measured from a ~100-byte seed with
    //        neither endpoint routable: three laps, and the third dies inside
    //        the allocator on "Attempt to exceed maximum P2PmsgHeap size of
    //        65535 bytes".  So one small message costs 64 KB and an
    //        uncontrolled throw on the pump thread.  Watched doing this in the
    //        p2p_sealhop Linux failure at 2048, 5856, 14713, 35890 bytes -
    //        P2PeerHub::RouteP2PeerMsg records it at the ring-pointer fix that
    //        removed the trigger; the loop itself stayed open until now
    //      : WHAT IT DOES NOW WITHOUT THIS GUARD IS DIFFERENT, and the change
    //        makes the guard MORE load-bearing rather than less.  Session 33's
    //        MAX_P2PmsgWrapEmbed elides the embedded body once the wrap passes
    //        the bound, so the amplification no longer reaches the ceiling and
    //        no longer terminates itself.  Re-measured with this branch
    //        disabled, image bytes per lap: 2040, 4875, 9091, 13307, 17523,
    //        then a fixed 8280 / 12496 / 16712 cycle repeating for as long as
    //        the hub lives - 4736 laps in the 1.5 s the case sleeps.  A
    //        self-limiting throw became an endless livelock at bounded size,
    //        which is quieter and lasts longer.  Whichever way it is read, this
    //        branch is the only thing that ends it
    //      : This ONE test is the whole cap, and that is not an accident.
    //        Every lap of every cascade has to come back through here: an
    //        exception that CAN be delivered is absorbed at its destination by
    //        the default ON_P2PeerMsg_CATCH(P2Pmsg_Exception, On_MsgCatchCatch)
    //        handler in this class's own message map, so the only way a lap
    //        continues is for the exception to be undeliverable - which is this
    //        branch.  NotHandled() above is left alone deliberately rather than
    //        given a matching guard it could never reach
    //      : Reported as a TRACE, not an error.  An unroutable peer whose
    //        report is also unroutable is normal as connections come and go,
    //        and raising an EVERR here is one more thing for a handler to fail
    //        on.  The message is not posted, so the pump's disposal is
    //        unchanged - identical ownership to the posting path below
    //      : The trace carries no format arguments on purpose.  AFPmsg() already
    //        attaches the message, addresses included, and a diagnostic that
    //        only renders with tracing switched on is a diagnostic nothing has
    //        executed - which is the whole of the narrow-format class this tree
    //        spent a session sweeping
    if ( pMsg && pMsg->Map_MatchName ( P2Pmsg_Exception ) )
    {
      if ( IsEVTRC )
        EVTRC->MODULE->AFPmsg(pMsg)
             ->Message_T("Undeliverable exception dropped: both endpoints "
                         "are unroutable, so there is nobody to report to")
             ->Group("P2P")
             ->Cancel();
      return msgHANDLED;
    }

    // Undeliverable
    // NOTES: Deliver P2PeerMsg exception back to source
    //      : NO AFPmsg(pMsg) here, and that is the fix rather than an omission.
    //        AFPmsg deep-copies the WHOLE message into the event, and this
    //        event is then attached to the response by ExceptionFactory - which
    //        has already embedded the whole message once, as the wrap.  So the
    //        response carried the message TWICE and came to a little over
    //        double its size, in a 16-bit addressed message heap: measured, a
    //        29991-byte message produced a 64574-byte response and just fitted,
    //        and a 30991-byte one threw out of VBHeapRoot_SetFree(aFree=65561)
    //        on this pump thread with no response sent at all.  A stock peer
    //        may send 32768 (P2Peerio::m_dwMaxRecvSize), so that band is
    //        reachable by any logged-in peer, and by any application posting a
    //        large message to an address that has just gone away
    //      : Nothing is lost from the log.  The line below names the message,
    //        its source and its destination explicitly; what AFPmsg added was a
    //        second copy of the body, in the one place that already had one
    //      : The response is bounded independently at the embedding step - see
    //        MAX_P2PmsgWrapEmbed - because these two copies are bounded by
    //        different things and fixing either alone leaves the other
    P2Pevent *pEVT =
    //EVTRC->Module ("%s(pMsg=%s)", __FUNCTION__  TODO Activate-me
    EVERR->MODULE
         // WIDE arguments need the WIDE overload: c_name()/GetSource()/
         // GetDestin() are all LPCWSTR, and a bare "..." literal is NARROW in
         // this tree, so this diagnostic used to render every address as its
         // first character and leak a literal %s.
         ->Message(L"Message[%s] from [%s] not deliverable to [%s]"
                  , pMsg->c_name(), pMsg->GetSource(), pMsg->GetDestin() )
         ->Advice (L"Connection lost" )
         ->Advice (L"Bad destination address [%s]", pMsg->GetDestin() )
         ->HResult(P2Pevent_UNDELIVERABLE)
         ->Group("P2P");

    // Ownership on the failing path
    // NOTES: ExceptionFactory() allocates, and an allocation that throws used
    //        to leave pEVT to leak - the Cancel() below is what releases it and
    //        it was never reached.  One leaked event per undeliverable message
    //        is not the headline defect, but it is the same defect's shadow
    try
    {
      P2PeerMsg *pReport = pMsg->ExceptionFactory(pEVT);
      StampReportOrigin ( pReport, this );
      PostP2PeerMsg ( pReport );
    }
    catch ( ... )
    {
      pEVT ->Cancel();
      throw;
    }
    pEVT ->Cancel();
    return msgHANDLED;
}

//
//  Peek P2PeerMsg handler
//  NOTES: Called immediately prior to commencement of routing a
//         P2PeerMsg through a P2PeerTarget derived object.
//       : Override this default implementation for special processing etc
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Completed processing message
//
//  Returns:     msgRESULT
//               Routing summary
//                 msgHANDLED... Message handled
//                 msgCONTINUE.. Continue routing
//
msgRESULT
P2PeerTarget::PeekP2PeerMsg ( P2PeerMsg *pMsg )
{
    // Simply
	pMsg;
    //P2Pevent *pEvent = EVERR -> MODULE->AFPmsg(pMsg)
    //                        -> Group("P2P");
    //pEvent->Print ( stdout );
    //delete pEvent;
    return msgCONTINUE;
}

//
//  Returns P2PeerMsg to source
//  NOTES: Redirections MUST be immediately propagated back up through
//         the stack for implementation.  Outcome is undefined when
//         attempting further processing on a P2PeerMsg flagged for
//         a re-direction.
//       : Returned P2PeerMsg's are usually intercepted and processed
//         in ON_P2PeerMsg() handlers in the source P2PeerHub from
//         which they are sourced.
//       : Returned P2PeerMsg's that fail delivery are usually intercepted
//         and processed in ON_P2PeerMsg_CATCH() handlers attached 
//         to the destination P2PeerHub from which they were returned.
//       : Individual P2PeerMsg exceptions can be toggled on and off via
//         the P2PeerMsg::Exceptions() method.
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Active handler message to be re-directed.  Source and
//               destination addressing properties are swapped and 
//               reflection state is toggled.
//
//  Returns:     msgRESULT
//               Redirection flag (msgREDIRECT)
//
msgRESULT
P2PeerTarget::ReturnP2PeerMsg ( P2PeerMsg *pMsg )
{
    P3PmsgItem oItemNET = pMsg->r_item(VBLockBSTR_NET).r_Object();

    // Source becomes destination and destination becomes source
    // NOTES: Swapping raw "Src" and "Dst" names preserves subsequent routing
    //        details
    P3PmsgField oFieldSrc = oItemNET.SelectObject(TMsg_Src);
    P3PmsgField oFieldDst = oItemNET.SelectObject(TMsg_Dst);
                oFieldSrc.r_name().c_name(TMsg_Dst);
                oFieldDst.r_name().c_name(TMsg_Src);

    // Tidy up, and
    return RedirectP2Pmsg ( pMsg );
}

//
//  Reflect P2PeerMsg to source
//  NOTES: Reflections MUST be immediately propagated back up through
//         the stack for implementation.  Outcome is undefined when
//         attempting further processing on a P2PeerMsg flagged for
//         a re-direction.
//       : Reflected P2PeerMsg's are usually intercepted and processed
//         in ON_P2PeerMsg_REFLECT() handlers in the source P2PeerHub from
//         which they are sourced.  Reflected-Reflected P2PeerMsg's become
//         normal P2PeerMsg's
//       : Reflected P2PeerMsg's that fail delivery are usually intercepted
//         and processed in ON_P2PeerMsg_REFLECT_CATCH() handlers attached 
//         to the destination P2PeerHub from which they were reflected.
//       : Individual P2PeerMsg exceptions can be toggled on and off via
//         the P2PeerMsg::Exceptions() method.
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Active handler message to be re-directed.  Source and
//               destination addressing properties are swapped and 
//               reflection state is toggled.
//
//  Returns:     msgRESULT
//               Redirection flag (msgREDIRECT)
//
msgRESULT
P2PeerTarget::ReflectP2PeerMsg ( P2PeerMsg *pMsg )
{
    P3PmsgItem oItemNET = pMsg->r_item(VBLockBSTR_NET).r_Object();

    // Source becomes destination and destination becomes source
    // NOTES: Swapping raw "Src" and "Dst" names preserves subsequent routing
    //        details
    P3PmsgField oFieldSrc = oItemNET.SelectObject(TMsg_Src);
    P3PmsgField oFieldDst = oItemNET.SelectObject(TMsg_Dst);
                oFieldSrc.r_name().c_name(TMsg_Dst);
                oFieldDst.r_name().c_name(TMsg_Src);

    // Swap reflected state
    // NOTES: Reflected-normal P2PeerMsg's become reflected.
    //        Refer ON_P2PeerMsg_REFLECT and ON_P2PeerMsg_REFLECT_CATCH
    //        for intercepting reflected-normal P2PeerMsg's
    //      : Reflected-reflected P2PeerMsg's messages become normal.
    //        Refer ON_P2PeerMsg and ON_P2PeerMsg_CATCH
    //        for intercepting reflected-reflected (normal) P2PeerMsg's
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)pMsg->r_data().c_vBlob();
    if ( (pPrefix->nMsg&P2P_Reflected) == P2P_Reflected )
      pPrefix -> nMsg ^= P2P_Reflected;
    else
      pPrefix -> nMsg |= P2P_Reflected;

    // Tidy up, and
    return RedirectP2Pmsg ( pMsg );
}

//
//  Redirect P2PeerMsg to another P2PeerHub
//  NOTES: Redirections MUST be immediately propagated back up through
//         the stack for implementation.  Outcome is undefined when
//         attempting further processing on a P2PeerMsg flagged for
//         a re-direction.
//       : Redirected P2PeerMsg's that fail delivery are usually intercepted
//         and processed in ON_P2PeerMsg_CATCH() handlers attached to the
//         source P2PeerHub from which they originated
//       : Individual P2PeerMsg exceptions can be toggled on and off via
//         the P2PeerMsg::Exceptions() method.
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Active handler message to be re-directed.
//
//               P2PaddrSTR strDestin
//               Re-direction destination address
//
//  Returns:     msgRESULT
//               Redirection flag (msgREDIRECT)
//
msgRESULT
P2PeerTarget::RedirectP2PeerMsg ( P2PeerMsg *pMsg, P2PaddrSTR strDestin )
{
    // Reset destination address
    pMsg->r_item(VBLockBSTR_NET).SelectItem(TMsg_Dst).r_name().c_name(strDestin);

    // Tidy up, and
    return RedirectP2Pmsg ( pMsg );
}

//
//  Repump P2PeerMsg through same hub
//  NOTES: Repump's MUST be immediately propagated back up through
//         the stack for implementation.  Outcome is undefined when
//         attempting further processing on a P2PeerMsg flagged for
//         a re-pumping.
//       : Normal processing rules apply to repumped P2PeerMsg's
//       : Individual P2PeerMsg exceptions can be toggled on and off via
//         the P2PeerMsg::Exceptions() method.
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Active handler message to be re-pumped.
//
//  Returns:     msgRESULT
//               Repump flag (msgREPUMP)
//
msgRESULT
P2PeerTarget::RepumpP2PeerMsg ( P2PeerMsg *pMsg )
{
    // To be sure, to be sure
    //ASSERT(pMsg->GetDestin()==this-

    // Tidy up, and
    return RepumpP2Pmsg ( pMsg );
}

//
//  Pre-P2PeerMsg destruction handler
//  NOTES: Called as part of the P2PeerMsg routing procedures
//         immediately prior to destruction or redirection of
//         routed P2PeerMsg's
//       : Single call made for the P2PeerTarget object nominated 
//         via CreateP2PmsgHub() or CreateP2PmsgPump()
//       : Override this default implementation for special
//         processing etc
//
//
//  Parameters: const P2PeerMsg *pMsg
//              Completed processing message
//
//              msgRESULT msgResult
//              P2PeerMsg handled summary
//                msgHANDLED... Handled
//                msgCONTINUE.. Not handled
//                msgREDIRECT.. Redirected
//
void
P2PeerTarget::PreDestroyP2PeerMsg ( const P2PeerMsg *pMsg, msgRESULT msgResult )
{
    // Stops compiler warnings
    pMsg;
    msgResult;
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerTarget::AssertValid ( ) const
{
    // TODO: Additional validation
    ASSERT(this);
    m_csTargetName.GetLength();
}

//
//  Serialise a state snapshot for this P2PeerTarget instance
//  NOTES: Such snapshots are used to inject P2PeerTarget state information
//         into P2PeerMsg's and P2Pevent's etc
//
//  Parameters:  LPCTSTR lpszVar
//               Name assigned to the generated P2PmsgNode
//                 0.. Use {P2PeerTarget}
//
//               bool bDsc = false
//                 true... Add description field attributes
//                 false.. No description field added
//
//  Returns:     P3PmsgNode
//               Snapshot instrance
//
P3PmsgItem
P2PeerTarget::Serialise ( LPCTNAM lpszVar, bool bDsc )
{
    // Create a placeholder for receipt of P2PeerHub details
    // NOTES: This will be passed by value back up the stack
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData()) );
    if ( lpszVar == 0 || wcslen(lpszVar) <= 0 )
      (P3PmsgField&)oNodeVar = P3PmsgName ( L"{P2PeerTarget}" );
    else
      oNodeVar.r_data() = P3PmsgData ( L"{P2PeerTarget}" );

    // Append P2PeerHub state to node
    P3PmsgField_SERIALISE ( oNodeVar, L"Name", (LPCWSTR)m_csTargetName, bDsc
                          , L"Target name" );

    // Tidy up and
    return oNodeVar;
}

//
//  Checks validity status of object
//  NOTES: Under some circumstances P2PeerTarget's exist in the pump queues
//         after deletion.  This method is used to validate P2PeerTarget's
//         prior to referenecing
//
//  Returns:     BOOL
//                 TRUE... Object valid
//                 FALSE.. No-valid
BOOL
P2PeerTarget::IsValidObject ( ) const
{
    if ( this== nullptr )
      return FALSE;
    if ( m_uiValidObject != (UINT_PTR)this )
      return FALSE;
    return TRUE;
}

///////////////////////////////////////////////////////////////////////
//  P2PeerSnc map integration
//  NOTES: Provides a mechanism by which Win32 drivers and system
//         call backs can integrate into the P2Peer map
//       : Minimalist raw integration is provided via
//           UNIT
//           PostP2Pmsg ( DWORD hThreadID
//                      , P2Pmsg_t nMsg, WPARAM wParam, LPARAM lParam )

//
//  Posts message to P2PmsgSnc
//  NOTES: Message is pumped in current context
//
//  Parameters:  P2PmsgSinkID nSinkID
//               Sink identification handle
//
//               P2PsysID nP2PsysID
//               Message identification code
//
//               const P3PmsgNode& oNode
//               P3PmsgNode of which copy is routed with message
//
//               WPARAM wParam
//
//               LAPARM lParam
//
//  Returns:     BOOL
BOOL
P2PeerTarget::PostP2PeerSnc ( P2PmsgSinkID nSinkID, P2PsysID nP2PsysID
                            , WPARAM wParam, LPARAM lParam )
{
    return PostP2PmsgSink ( nSinkID, nP2PsysID, (P2PeerTarget*)0, wParam, lParam );
}
BOOL
P2PeerTarget::PostP2PeerSnc ( P2PmsgSinkID nSinkID, P2PsysID nP2PsysID
                            , const P3PmsgItem& oItem
                            , WPARAM wParam, LPARAM lParam )
{
    return PostP2PmsgSink ( nSinkID, nP2PsysID, (P2PeerTarget *)0, oItem,  wParam, lParam );
}

//
//  P2PeerMsg router
//               NOTES: Override this handler for message interceptions
//
//  Parameters:  P2PeerID nID
//               Identification code of orginating P2PeerHub
//
//               int nCode
//               P2PeerMsg code
//
//               NOTES: CN_P2PeerMsg
//                      Standard P2Peer message
//                    : CN_P2Peer
//                      Thrown by P2Peer framework
//
//               void *pExtra
//
//               P2P_SYSHANDLERINFO *pHandlerInfo
BOOL
P2PeerTarget::On_P2PeerSnc ( UINT nCode, P2Pmsg_t nMsg
                           , WPARAM wParam, LPARAM lParam
                           , void *pvExtra
                           , P2P_SNKHANDLERINFO *pHandlerInfo )
{
    UNREFERENCED_PARAMETER(wParam);
    UNREFERENCED_PARAMETER(lParam);
    // Introduce locals
    //P2PeerTarget *pTarget;
    BOOL          bResult  = FALSE;
    BOOL          bMapcast = FALSE;

    // Mapcasting
    if ( (nCode&CM_Mapcast) )
      bMapcast = TRUE;

    // determine the message number and code (packed into nCode)
    const P2P_SNKMAP       *pP2P_SnkMap;
    const P2P_SNKMAP_ENTRY *pEntry;
      
    // Traverse through message map to see if it applies to us
    // NOTES: Top down search. Derived class first then down
    //        through the base classes.
    //      : If there exists a desire to optimise then place
    //        frequent messages at the top of the message map
    //        and less frequent messages at the end of the list
    //      : Traverse continues until P2PeerMsg flagged as
    //        handled.
    pP2P_SnkMap = GetP2PeerSnkMap();
    while (    pP2P_SnkMap         &&
            ( !bResult||bMapcast )    )
    {
		  // Trap BEGIN_P2PeerMsg_MAP(CMyClass, CMyClass)!
      VERIFY(pP2P_SnkMap != pP2P_SnkMap->pBaseMap);
      pEntry = pP2P_SnkMap -> lpEntries;

      while ( ( !bResult||bMapcast ) &&
                 pEntry                 )
      {
        // Search for handler in P2PeerSnk_MAP
        // NOTES: 
        pEntry = FindP2PeerSnkEntry ( pEntry //pP2P_MsgMap->lpEntries 
                                    , nMsg, (nCode&CN_Mask) );
        if ( !pEntry )
          break;

        // Dispatch message
        // NOTES: P2PeerSnc's are at most only ever handled once
        //        per map.  However, all subordinate maps are
        //        tried whenever map casting is switched on
        bResult = DispatchP2PeerSnk ( this, (nCode&CN_Mask)
                                    , pEntry->pfn, pvExtra
                                    , pEntry->nSig, pHandlerInfo );
        if ( bResult == sncCONTINUE )
        {
          pEntry += pEntry -> nOSets;
          continue;
        }
        if ( bResult == sncSWAP     ||
             bResult == sncREDIRECT ||
             bResult == sncREPUMP      )
          return bResult;

        // Map casting
        // NOTES: Recursively switched on.  Upon return assumes
        //        status of the previous level
        if ( pEntry -> bMapcast )
        {
          bMapcast  = TRUE;
          nCode    |= CM_Mapcast;
        }
        bResult     = sncHANDLED;
        pEntry      = 0;               // Breaks loop
        pP2P_SnkMap = 0;               // Breaks loop
      }

      // Step down through inheritance chain
      if ( pP2P_SnkMap )
        pP2P_SnkMap = pP2P_SnkMap -> pBaseMap;
    }

    // Tidy up and
    return bResult;                    // Handled summary
};

//
//  Default processing W32 message not handled
//
//
//  Parameters: P2Pmsg_t nMsg
//              Sys message type
//
//              WPARAM wParam
//
//              LPARAM lParam
//
void
P2PeerTarget::NotHandledSnc ( P2Pmsg_t nMsg
                            , WPARAM wParam, LPARAM lParam )
{
    // Explaination
    P2Pevent *pEVT =
    EVERR->MODULE
         ->AFP(nMsg)->AFP(wParam)->AFP(lParam)
         ->Message("Domain sink Message (%i) not handled", nMsg )
         ->Advice ("Mapping problem, bug" )
         ->HResult(P2Pevent_UNKNOWN);

    // Tidy up, and
    pEVT -> Cancel ( );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerSys map integration
//  NOTES: Provides a mechanism by which Win32 drivers and system
//         call backs can integrate into the P2Peer map
//       : Minimalist raw integration is provided via
//           UNIT
//           PostP2Pmsg ( DWORD hThreadID
//                      , P2Pmsg_t nMsg, WPARAM wParam, LPARAM lParam )

//
//  Posts message to P2PmsgSink
//  NOTES: Message is pumped in current context
//
//  Parameters:  P2PmsgSinkID nSinkID
//               Sink identification handle
//
//               P2PsysID nP2PsysID
//               Message identification code
//
//               WPARAM wParam
//
//               LAPARM lParam
//
//  Returns:     BOOL
BOOL
P2PeerTarget::PostP2PeerSys ( P2PmsgSinkID nSinkID, P2PsysID nP2PsysID
                            , WPARAM wParam, LPARAM lParam )
{
    return PostP2PmsgSink ( nSinkID, nP2PsysID, 0, wParam, lParam );
}

//
//  P2PeerMsg router
//               NOTES: Override this handler for message interceptions
//
//  Parameters:  P2PeerID nID
//               Identification code of orginating P2PeerHub
//
//               int nCode
//               P2PeerMsg code
//
//               NOTES: CN_P2PeerMsg
//                      Standard P2Peer message
//                    : CN_P2Peer
//                      Thrown by P2Peer framework
//
//               void *pExtra
//
//               P2P_SYSHANDLERINFO *pHandlerInfo
BOOL
P2PeerTarget::On_P2PeerSys ( UINT nCode, P2Pmsg_t nMsg
                           , WPARAM wParam, LPARAM lParam
                           , void *pvExtra
                           , P2P_SYSHANDLERINFO *pHandlerInfo )
{
    // Introduce locals
    P2PeerTarget *pTarget;
    BOOL          bResult  = FALSE;
    BOOL          bMapcast = FALSE;

    // Mapcasting
    if ( (nCode&CM_Mapcast) )
      bMapcast = TRUE;

    // determine the message number and code (packed into nCode)
    const P2P_SYSMAP       *pP2P_SysMap;
    const P2P_SYSMAP_ENTRY *pEntry;

    // Hi-priority child delegation is always first
    // NOTES: All these priorities will be -ve.  Work backwards
    //        through the list.  A priority of -1 will be
    //        processed before -2 etc
    for ( pTarget = m_pTargetChildHi;
                     (    pTarget          &&
                       ( !bResult||bMapcast   ) );
                               pTarget = pTarget->m_pTargetNext )
      bResult |= pTarget -> On_P2PeerSys ( nCode, nMsg
                                         , wParam, lParam, pvExtra
                                         , pHandlerInfo );
      
    // Traverse through message map to see if it applies to us
    // NOTES: Top down search. Derived class first then down
    //        through the base classes.
    //      : If there exists a desire to optimise then place
    //        frequent messages at the top of the message map
    //        and less frequent messages at the end of the list
    //      : Traverse continues until P2PeerMsg flagged as
    //        handled.
    pP2P_SysMap = GetP2PeerSysMap();
    while (    pP2P_SysMap         &&
            ( !bResult||bMapcast )    )
    {
		  // Trap BEGIN_P2PeerMsg_MAP(CMyClass, CMyClass)!
      VERIFY(pP2P_SysMap != pP2P_SysMap->pBaseMap);
      pEntry = pP2P_SysMap -> lpEntries;

      while ( ( !bResult||bMapcast ) &&
                 pEntry                 )
      {
        // Search for handler in P2PeerSys_MAP
        // NOTES: 
        pEntry = FindP2PeerSysEntry ( pEntry //pP2P_MsgMap->lpEntries 
                                    , nMsg, (nCode&CN_Mask) );
        if ( !pEntry )
          break;

        // Dispatch message
        // NOTES: P2PeerMsg's are at most only ever handled once
        //        per map.  However, all subordinate maps are
        //        tried whenever map casting is switched on
        if ( !DispatchP2PeerSys ( this, (nCode&CN_Mask)
                                , pEntry->pfn, pvExtra
                                , pEntry->nSig, pHandlerInfo ) )
        {
          pEntry += pEntry -> nOSets;
          continue;
        }

        // Map casting
        // NOTES: Recursively switched on.  Upon return assumes
        //        status of the previous level
        if ( pEntry -> bMapcast )
        {
          bMapcast  = TRUE;
          nCode    |= CM_Mapcast;
        }
        bResult     = TRUE;
        pEntry      = 0;               // Breaks loop
        pP2P_SysMap = 0;               // Breaks loop
      }

      // Step down through inheritance chain
      if ( pP2P_SysMap )
        pP2P_SysMap = pP2P_SysMap -> pBaseMap;
    }

    // Lo-priority child delegation is always last
    // NOTES: All these priorities will be +ve.  Work forewards
    //        through the list.  A priority of +1 will be
    //        processed before +2 etc
    for ( pTarget = m_pTargetChildLo;
                     (    pTarget          &&
                       ( !bResult||bMapcast   ) );
                               pTarget = pTarget->m_pTargetNext )
      bResult |= pTarget -> On_P2PeerSys ( nCode, nMsg
                                         , wParam, lParam, pvExtra
                                         , pHandlerInfo );

    // Tidy up and
    return bResult;                    // Handled summary
};

//
//  Default processing W32 message not handled
//
//
//  Parameters: P2Pmsg_t nMsg
//              Sys message type
//
//              WPARAM wParam
//
//              LPARAM lParam
//
void
P2PeerTarget::NotHandled ( P2Pmsg_t nMsg
                         , WPARAM wParam, LPARAM lParam )
{
    // Explaination
    P2Pevent *pEVT =
    EVERR->MODULE
         ->AFP(nMsg)->AFP(wParam)->AFP(lParam)
         ->Message("W32 Message (%i) not handled", nMsg )
         ->Advice ("Mapping problem, bug" )
         ->HResult(P2Pevent_UNKNOWN);

    // Tidy up, and
    pEVT -> Cancel ( );
}

///////////////////////////////////////////////////////////////////////
//  Property exposure

//
//  Exposes P2Paddr of P2Peer derived hub
//  NOTES: Keeps delegating to parent P2PeerTarget until
//         P2PeerHub provides an implementation
//
//
//  Returns:     const P2Paddr&
//               Identification code of P2Peer derived hub to which
//               this object is ultimately registered
//
const P2Paddr&
P2PeerTarget::GetP2PaddrHub ( )
{
    // To be sure, to be sure
    if ( m_pTargetParent == NULL )
      EVERR->MODULE
           ->Message("No linked P2PeerHub" )
           ->Advice ("Linked P2PeerTarget's must be terminated in P2PeerHub" )
           ->Advice ("Application bug (SNHappen)" )
           ->Throw();

    // Simply
    // NOTES: Altimately parent P2Peer will provide
    //        an implementation
    return m_pTargetParent -> GetP2PaddrHub ( );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerCon_MAP root 
//  NOTES: Placemarkers followed by some default handlers.  Only
//         accessed as part of the default processing sequences upon
//         completion of registered P2PeerTarget search
//
const P2P_CONMAP P2PeerTarget::P2PeerConMap
             = {  NULL
               , &P2PeerTarget::_P2PeerConEntries[0] };

const P2P_CONMAP*
P2PeerTarget::GetP2PeerConMap() const
{
    // Simply
    return &P2PeerTarget::P2PeerConMap;
};

PTM_WARNING_DISABLE
const P2P_CONMAP_ENTRY P2PeerTarget::_P2PeerConEntries[] =
{
    // Service handlers
    ON_P2PeerCon_SERVICE(L"*",P2P_Startup,On_ConStartup)
    ON_P2PeerCon_SERVICE(L"*",P2P_Listen,On_ConListen)   // Listen()->posts P2P_Listen; without this the listen con hits NotHandled and drops
    ON_P2PeerCon_SERVICE(L"*",P2P_Accept,On_ConAccept)
    ON_P2PeerCon_SERVICE(L"*",P2P_Shutdown,On_ConShutdown)

    // Client handlers
    ON_P2PeerCon_CLIENT(L"*",P2P_Startup,On_ConStartup)
    ON_P2PeerCon_CLIENT(L"*",P2P_Connect,On_ConConnect)
    ON_P2PeerCon_CLIENT(L"*",P2P_Shutdown,On_ConShutdown)

    // Operational handlers
    ON_P2PeerCon_LOGIN(L"*", On_ConLogin)
    ON_P2PeerCon_LOGINACK(L"*",On_ConLoginAck)
    ON_P2PeerCon_CLOSE(L"*",On_ConClose)
    ON_P2PeerCon_CYPHEREX(L"*",On_ConCypherEx)
    { 0, 0, L"", 0, P2PSig_End, 0, 0 }  // Nothing more here
};
PTM_WARNING_RESTORE

//
//  Handler to initiate STARTUP listening sequence
//  NOTES: Default implementation simply delegates to the
//         connection object
//
//
//  Parameters: P2PeerCon *pCon
//              Object for which listening sequence is to be started
//
//  Returns:    conRESULT
//              Result code
//
conRESULT
P2PeerTarget::On_ConStartup ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel();

    // Simply delegate for default processing
    // NOTES: Override for exotic and/or specific implementations
    pCon -> OnStartup ( );
    ASSERT(!pCon->PostDestroyState());

    // Delegate
    if ( pCon->GetMode() == P2PeerCon_SERVICE )
      pCon -> Listen ( );
    else if ( pCon->GetMode() == P2PeerCon_CLIENT )
      pCon -> Connect( );
    else
      EVERR->MODULE->AFPcon(pCon)
           ->Message(L"Cannot startup connection[%s] for mode (%i)\n"
                    , pCon->GetP2Paddress().c_wstr()
                    , pCon->GetMode() )
           ->Advice ("Bug (SNHappen)")
           ->Throw();

    // Tidy up, and
    return conHANDLED;                 // P2PeerCon object handled
}

//
//  WSA listen object notification
//  NOTES: Default implementation is to simply flag notification
//         as handled
//
//
//  Parameters:  P2PeerCon *pCon
//               Listening object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConListen  ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel ( );

    // Delegate for default processing
    pCon -> OnListen ( );

    // Accept remote connection
    pCon -> Accept ( );

    // Tidy up and
    return conHANDLED;
}

//
//  Handler for ACCEPT'ed connections from remote P2PeerHub
//  NOTES: Default implementation is to spawn P2PeerCon from
//         passed service and prepare for the next
//       : Initialisation and restart sequence may result in
//         null P2PeerCon being spawned
//       : Services may morph into accepted clients for some
//         P2PeerCon types
//
//
//  Parameters:  P2PeerCon *pCon
//               Service mode object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConAccept ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel ( );

    // Delegate non-SERVICE's for default processing
    // NOTES: Forms the default processing for the accepted
    //        CLIENT activity below.
    //      : Initialises accepted connection for I/O, mandatory
    //        that such activity only occur beyond this point.
    if ( pCon->GetMode() != P2PeerCon_SERVICE )
    {
      pCon -> OnAccept ( L"" );
      return conHANDLED;
    }

    // Simply delegate for specialised default processing
    // NOTES: Such processing usually spawns accepted P2PeerCon
    //        client objects.  Such objects are assumed to be
    //        fully integrated into the P2PeerCon_MAP()
    //      : However, always assume its possible for a NULL
    //        P2PeerCon to be spawned.
    P2PeerCon *pConService = pCon;
    P2PeerCon *pConAccept  = pCon -> OnAccept ( );
    if ( pConService->GetMode() != P2PeerCon_SERVICE )
    {
      pConService = pConAccept;
      pConAccept  = pCon;
    }

    // Manadatory accepted CLIENT processing
    // NOTES: Spawned out of passed service connection
    //      : Assign timer for completion of login sequence,
    //        assumed to be initiated by the CLIENT
    if ( pConAccept )
    {
      // Pump the spawned connection
      // NOTES: SERVICE has been pumped into this default handler and
      //        is now being processed.  The spawned CLIENT is auto
      //        posted to P2PeerHub, now pump the CLIENT for subsequent
      //        interception and property assignment.  Otherwise the
      //        spawned P2PeerCon sits in limbo.
      //      : The accepted CLIENT is pumped under the SERVICE address
      PostP2Pmsg ( pCon->GetP2Paddress(), CN_P2PeerCon, P2P_Accept
                 , pConAccept, 0, GetHubID() );

      // Start the login deadline
      // NOTES: This line was the one missing piece of a mechanism that was
      //        otherwise complete: On_PITimer() has always thrown "Login timed
      //        out" on expiry, and OnLogin(), OnClose() and ~P2PeerCon() have
      //        always cancelled it.  Only the arming call was commented out
      //        (as SetPITimer(1000)), so an accepted connection that never
      //        logged in was never dropped - it simply sat there, holding a
      //        socket, indefinitely, and no configuration could change that
      //      : Armed here rather than inside AcceptSpawn() because the
      //        connection is not pumped until the post above: a timer set
      //        before it can receive its own expiry has nowhere to deliver it
      //      : Deadline and default live on the connection.  Refer
      //        P2PeerCon::ArmLoginDeadline() and DEF_P2PeerConLogin
      pConAccept -> ArmLoginDeadline ( );
    }

    // Mandatory SERVICE processing
    // NOTES: Prepare SERVICE for next accepted connection, otherwise
    //        it exists in limbo
    //      : Some connection SERVICE types may morph themselves
    //        into accepted CLIENT connections
    //      : SERVICE now waits for the next accepted connection,
    //        error or closure etc. 
    if ( pConService )
      pConService -> Accept ( );

    // Tidy up, and
    return conHANDLED;                 // P2PeerCon object handled
}

//
//  P2PeerCon'nected handler
//  NOTES: Default implementation is to firstly check encyption
//         requirements and initiate key exchange
//       : Without encyption requirements initiate Login() sequence
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConConnect( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel();

    // Delegate connection processing
    pCon -> OnConnect ( );

    // Initiate PKeyXChange or jump to Login sequnce
    // NOTES: Encryption is all handled within the P2Peerio object
    //      : Assuming the Alice roll
    if ( pCon->GetP2Peerio()->IsEncrypted() )
      pCon -> PKeyXChange ( nullptr, 0 );
    else
      pCon -> Login ( strP2PaddrNULL, 0, 0 );

    // Tidy up and
    return conHANDLED;                 // P2PeerCon object handled
}

//
//  P2PeerCon PKey exchange handler (Bob)
//  NOTES: Refer On_P2PeerCon_PKEYXCHANGE() handler for interception details
//       : PKey exchange has been initiated by remote connection (Alice)
//         that is subsequently processed locally (Bob) for this connection
//       : Without encyption requirements this sequence is usually skipped
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//               const void *pvPKeyXChange
//               PKey exchange details (from Alice)
//
//               P2Psize_t iSize
//               Size of pvPKeyXChange buffer
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConPKeyXChange( P2PeerCon *pCon
                               , const void *pvPKeyXChange, P2Psize_t iSize )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel();

    // Implementation
    // NOTES: Delegated directly through to P2PeerCon object
    pCon -> OnPKeyXChange ( pvPKeyXChange, iSize );
    pCon ->   PKeyXChangeAck ( nullptr, 0 );

    // Tidy up and
    return conHANDLED;                 // P2PeerCon object handled
}

//
//  P2PeerCon PKey exchange acknowledgement handler (Alice)
//  NOTES: Refer On_P2PeerCon_PKEYXCHANGEACK() handler for interception details
//       : PKey exchange has been acknowledged by remote connection (Bob)
//         that is subsequently processed locally (Alice) for this connection
//       : Without encyption requirements this sequence is usually skipped
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//               const void *pvPKeyXChangeAck
//               PKey exchange acknowledgement details (from Bob)
//
//               P2Psize_t iSize
//               Size of pvPKeyXChangeAck buffer
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConPKeyXChangeAck( P2PeerCon *pCon
                                  , const void *pvPKeyXChangeAck, P2Psize_t iSize )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel();

    // Implementation
    // NOTES: Delegated directly through to P2PeerCon object
    pCon -> OnPKeyXChangeAck ( pvPKeyXChangeAck, iSize );

    // Initiate login
    // NOTES: All subsequent P2PeerMsg exchanges are now encrypted
    //      : Refer On_P2PeerCON_CYPHEREX() handler for interception
    //        and handling of cypher exceptions
    pCon -> Login ( strP2PaddrNULL, 0, 0 );

    // Tidy up and
    return conHANDLED;                 // P2PeerCon object handled
}

//
//  P2PeerCon login request from remote P2PeerHub
//  NOTES: Default implementation cannot accept requests containing
//         a login message.  Implement custom handler for such
//         situations
//
//
//  Parameters: P2PeerCon *pCon
//              Connection object
//
//              P2PaddrSTR strThatP2Paddr
//              Identification of the remote P2PeerHub performing
//              login
//
//              const void *pvLoginMsg
//              Login message
//
//              P2Psize_t iSize
//              Size of pvLoginMsg in bytes
//
//  Returns:    conRESULT
//              Result code
//
conRESULT
P2PeerTarget::On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr
                          , const void *pvLoginMsg, P2Psize_t iSize )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE
           ->AFPcon(pCon)->AFP(strThatP2Paddr)
           ->Cancel();

    // Confirm empty login message
    if ( pvLoginMsg ||
          iSize        )
      EVERR->MODULE
           ->AFPcon(pCon)->AFP(strThatP2Paddr)
           ->Message("Remote login request contains login data" )
           ->Advice ("Implement a custom handler" )
           ->Throw();

    // Nominated strThatP2Paddr must not already exist
    // NOTES: P2Paddr's must be unique otherwise we run into routing
    //        predictablity problems etc
    //      : Custom handlers must always address this issue
    if ( wcslen(strThatP2Paddr) >    0             &&
         pCon->GetP2Paddress() != strThatP2Paddr   &&
         GetP2PeerHub()->ConExists(strThatP2Paddr)    )
      EVERR->MODULE
           ->AFPcon(pCon)->AFP(strThatP2Paddr)
           ->Message(L"P2PeerCon with nominated strThatP2Paddr=%s already exists"
                    , strThatP2Paddr )
           ->Advice (L"Duplicate P2PeerCon's for P2PeerHub attempted" )
           ->Throw ( );

    // Implementation
    // NOTES: First we manage state, then we acknowledge login
    pCon -> OnLogin    ( strThatP2Paddr );
    pCon ->   LoginAck ( strThatP2Paddr, 0, 0 );

    // Tidy up and
    return conHANDLED;                 // P2PeerCon object handled
}

//
//  P2PeerCon login acknowledgement from remote P2PeerHub
//  NOTES: Default processing cannot accept requests containing a
//         acknowledgement message.  Implement custom handler for
//         such situations
//
//
//  Parameters: P2PeerCon *pCon
//              Connection object
//
//              P2PaddrSTR strThisP2Paddr
//              Address assigned to this P2PeerHub
//
//              const void *pvLoginMsg
//              Login message
//
//              P2Psize_t iSize
//              Size of pvLoginMsg in bytes
//
//  Returns:    conRESULT
//              Result code
//
conRESULT
P2PeerTarget::On_ConLoginAck ( P2PeerCon *pCon
                             , P2PaddrSTR strThisP2Paddr, P2PaddrSTR strThatP2Paddr
                             , const void *pvLoginAck, P2Psize_t iSize )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE
           ->AFPcon(pCon)->AFP(strThisP2Paddr)->AFP(strThatP2Paddr)->AFP(iSize)
           ->Cancel();

    // Confirm empty login message
    if ( pvLoginAck || iSize )
      EVERR->MODULE
           ->AFPcon(pCon)->AFP(strThisP2Paddr)->AFP(strThatP2Paddr)->AFP(iSize)
           ->Message("Remote MSG_P2PeerLoginAck contains data")
           ->Advice ("Implement custom handler")
           ->Throw();

    // Implementation
    // NOTES: First we manage state, then we acknowledge login
    pCon -> OnLoginAck ( strThisP2Paddr, strThatP2Paddr );

    // Tidy up and
    return conHANDLED;
}

//
//  Closed connection
//  NOTES: Default implementation is to simply drop the closed connection.
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConClose ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel();

    // Locals
    conRESULT conResult = conDROP;

    // Simply drop the connection object
    // NOTES: Use a custom handler to restart a connection
    pCon -> OnClose();

    // Re-activate connection management
    // NOTES: Restarts must experience a delay.  Otherwise application
    //        locks up in a processing loop.  But, if that's what you want.
    //      : Observe destruction state of object
    if (  pCon->m_uAutoRestart > 99           &&
          pCon->GetMode() == P2PeerCon_CLIENT &&
         !pCon->PostDestroyState()               )
    {
      pCon -> Restart ( pCon->m_uAutoRestart );
      conResult = conHANDLED;
    }

    // Done
    return conResult;
}

//
//  Peek P2PeerCon handler
//  NOTES: Override this default EVTRC implementation for special
//         processing etc
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//               UINT nCode
//               Notification code
//
//               P2Pmsg_t nMsg
//               Connection message type
//
//  Parameters:  conRESULT
//               Peek summary
//                 conTINUE... Continue routing P2PeerCon object
//                 conHANDLED
//                 conDROP
//
conRESULT
P2PeerTarget::On_ConPeek ( P2PeerCon *pCon, UINT nCode, P2Pmsg_t nMsg )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)->AFP(nCode)->AFP(nMsg)
           ->Cancel();

    // Simply
    return conTINUE;
}

//
//  Connection shutdown
//  NOTES: Default implementation varies according to 
//         connection mode
//           P2PeerCon_SERVICE.. Restart connection
//           P2PeerCon_CLIENT... Restart connection
//       : ACCEPT'ed connection's are dropped
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConShutdown ( P2PeerCon *pCon )
{
    // Locals
    conRESULT conResult = conDROP;

    // Perform default shutdown processing
    // NOTES: Being virtual maybe specialised
    pCon -> OnShutdown ( );

    // Restart connection
    // NOTES: Restarts must experience a delay.  Otherwise application
    //        locks up in a processing loop.  But, if that's what you want.
    //      : Observe destruction state of object
    if (   pCon->m_uAutoRestart > 99                 &&
         ( pCon->GetMode() == P2PeerCon_CLIENT  ||
           pCon->GetMode() == P2PeerCon_SERVICE    ) &&
          !pCon->PostDestroyState()                      )
    {
      pCon -> Restart ( pCon->m_uAutoRestart );
      conResult = conHANDLED;
    }

    // Done
    return conResult;
}

//
//  Cypher Exception
//  NOTES: Refer On_P2PeerCon_CYPHEREX() handler for further details on
//         intercepting cypher exceptions
//         Default implementation is to close connection via exception
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//               P2PeerMsg *pMsg 
//               Connection cypher exception details. May be NULL
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerTarget::On_ConCypherEx ( P2PeerCon *pCon, P2PeerMsg * )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel();

    // Trash connection
    EVERR -> MODULE
          -> AFPcon(pCon)
          -> Message_T("Cypher exception" )
          -> Throw();
    return conHANDLED;
}

///////////////////////////////////////////////////////////////////////
//  P2PeerSnk_MAP root
//  NOTES: Implementation followed by some default handlers
//
const P2P_SNKMAP P2PeerTarget::P2PeerSnkMap
             = {  NULL
               , &P2PeerTarget::_P2PeerSnkEntries[0] };
const P2P_SNKMAP*
P2PeerTarget::GetP2PeerSnkMap ( ) const
{
    // Simply
    return &P2PeerTarget::P2PeerSnkMap;
}
const P2P_SNKMAP_ENTRY P2PeerTarget::_P2PeerSnkEntries[] =
{
    { 0, 0, P2PSig_End, 0, 0 }         // Nothing more here
};

///////////////////////////////////////////////////////////////////////
//  P2PeerSys_MAP root
//  NOTES: Implementation followed by some default handlers
//
const P2P_SYSMAP P2PeerTarget::P2PeerSysMap
             = {  NULL
               , &P2PeerTarget::_P2PeerSysEntries[0] };
const P2P_SYSMAP*
P2PeerTarget::GetP2PeerSysMap ( ) const
{
    // Simply
    return &P2PeerTarget::P2PeerSysMap;
}
const P2P_SYSMAP_ENTRY P2PeerTarget::_P2PeerSysEntries[] =
{
    { 0, 0, P2PSig_End, 0, 0 }         // Nothing more here
};

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg_MAP root
//  NOTES: Implementation followed by some default handlers
//
const P2P_MSGMAP P2PeerTarget::P2PeerMsgMap
             = {  NULL
               , &P2PeerTarget::_P2PeerMsgEntries[0] };
const P2P_MSGMAP*
P2PeerTarget::GetP2PeerMsgMap ( ) const
{
    // Simply
    return &P2PeerTarget::P2PeerMsgMap;
}
PTM_WARNING_DISABLE
const P2P_MSGMAP_ENTRY P2PeerTarget::_P2PeerMsgEntries[] =
{
    ON_P2PeerMsg_CATCH(P2Pmsg_Undeliv, On_MsgCatch)
    ON_P2PeerMsg_CATCH(P2Pmsg_Exception, On_MsgCatchCatch)
    { 0, 0, 0, 0, 0, 0, 0, P2PSig_End, 0, 0, 0 }// Nothing more here
};
PTM_WARNING_RESTORE

//
//  Server side handler for P2PeerMsg
//  NOTES: Default implementation is to simply ignore client
//         P2PeerMsg content
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be handled
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerTarget::On_MsgIgnore ( P2PeerMsg *pMsg )
{
    // Leave Audit trail
    if ( IsEVTRC )
      EVTRC->MODULE->AFPmsg(pMsg)
           ->Message("Message content ignored and discarded")
           ->Cancel();

    // Tidy up and
    return msgHANDLED;
}

//
//  Client side handler for P2Pmsg_Exceptions containing P2PeerMsg's
//  in normal state
//               NOTES: Default implementation
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Exception containing the P2PeerMsg in normal
//               state
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerTarget::On_MsgCatch ( P2PeerMsg *pMsg )
{
    // Confirm exception type message
    if ( !pMsg->Map_MatchName(P2Pmsg_Exception) )
      EVERR->MODULE->AFPmsg(pMsg)
           ->Message(L"Expected P2Pmsg_Exception type message, got [%s]"
                    , pMsg->c_name() )
           ->Advice ("P2Peer network implementation BUG" )
           ->Advice ("Use alternative P2PeerMsg_MAP handler" )
           ->Throw();

    // Confirm normal message
    // NOTES: Confirm message state
    if ( (*pMsg)[1].IsReflected() )
      EVERR->MODULE->AFPmsg(pMsg)
           ->Message("Expected normal exception message state" )
           ->Advice ("P2Peer network implementation BUG" )
           ->Advice ("Use alternative P2PeerMsg_MAP handler" )
           ->Throw();

    // Extract P2Pevent from contents
    P2Pevent *pEVT = pMsg -> ExtractP2Pevent ( );

    // Undeliverable P2PeerMsg
    // NOTES: Expected as part of normal network interaction as
    //        connections drop in and out.  These are usually thown
    //        as EVTRC type events
    if ( pEVT->GetHRESULT() == P2Pevent_UNDELIVERABLE )
      pEVT->Cancel();

    // All others
    // NOTES: Simply report as passed
    else
      pEVT->Cancel();

    // Tidy up and
    return msgHANDLED;
}

msgRESULT
P2PeerTarget::On_MsgCatchCatch ( P2PeerMsg *pMsg )
{
    // Tidy up and
    pMsg;
    return msgHANDLED;
}

//
//  Client side handler for P2PeerMsg in REFLECT'ed state
//               NOTES: Default implementation
//
//
//  Parameters:  P2PeerMsg *pMsg
//               REFLECT'ed message to be handled
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerTarget::On_MsgReflect ( P2PeerMsg *pMsg )
{
    // Confirm reflected message
    // NOTES: Confirm message state
    if ( !pMsg->IsReflected() )
      EVERR->MODULE->AFPmsg(pMsg)
           ->Message("Expected REFLECT'ed message state")
           ->Advice ("P2Peer network implementation BUG")
           ->Advice ("Use alternative P2PeerMsg_MAP handler")
           ->Throw();

    // Tidy up and
    return msgHANDLED;
}

//
//  Server side handler for MSG_P2PeerExceptions containing
//  P2PeerMsg's in REFLECT'ed state
//               NOTES: Default implementation
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Exception containing the P2PeerMsg in REFLECT'ed
//               state
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerTarget::On_MsgReflectCatch ( P2PeerMsg *pMsg )
{
    // Confirm exception type message
    if ( !pMsg->Map_MatchName(P2Pmsg_Exception) )
      EVERR->MODULE->AFPmsg(pMsg)
           ->Message("Expected MSG_P2PeerException type message" )
           ->Advice ("P2Peer network implementation BUG" )
           ->Advice ("Use alternative P2PeerMsg_MAP handler" )
           ->Throw();

    // Confirm reflected message
    // NOTES: Confirm message state
    if ( !(*pMsg)[1].IsReflected() )
      EVERR->MODULE->AFPmsg(pMsg)
           ->Message("Expected REFLECT'ed exception message state" )
           ->Advice ("P2Peer network implementation BUG" )
           ->Advice ("Use alternative P2PeerMsg_MAP handler")
           ->Throw();

    // Reconstitute EVENT from contents
    P2Pevent *pEVT = pMsg -> ExtractP2Pevent ( );

    // Undeliverable P2PeerMsg
    // NOTES: Expected as part of normal network interaction as
    //        connections drop in and out.  These are usually thown
    //        as EVTRC type events
    if ( pEVT->GetHRESULT() == P2Pevent_UNDELIVERABLE )
      pEVT->Cancel();

    // All others
    // NOTES: Simply report as passed
    else
      pEVT->Cancel();

    // Tidy up and
    return msgHANDLED;
}

//
//  P2PeerMsg peek handler
//               NOTES: Default implementation
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerTarget::On_MsgPeek ( P2PeerMsg *pMsg )
{
    // Display message
    EVERR->MODULE->AFPmsg(pMsg)
         ->HResult(P2Pevent_UNKNOWN)
         ->Cancel();

    // Tidy up and
    return msgCONTINUE;                // Continue routing
}

//
//  P2PeerMsg poll handler
//  NOTES: Default implementation is to simply return to source
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerTarget::On_MsgPoll ( P2PeerMsg *pMsg )
{
    // Display message
    EVERR->MODULE->AFPmsg(pMsg)
         ->HResult(P2Pevent_UNKNOWN)
         ->Cancel();

    // Tidy up and
    return msgCONTINUE;                // Continue routing
}

//
//  P2PeerMsg ping handler
//  NOTES: Default implementation is to simply return to source
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerTarget::On_MsgPing ( P2PeerMsg *pMsg )
{
    // Display message
    EVERR->MODULE->AFPmsg(pMsg)
         ->HResult(P2Pevent_UNKNOWN)
         ->Cancel();

    // Tidy up and
    return msgCONTINUE;                // Continue routing
}
