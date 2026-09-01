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
//  Description: P2Peer event sink connection object
//               NOTES: Registers for application event notifications
//                      and passes such notifications to the nominated
//                      event sink
//                    : Designed for a standalone implementation
//                      independant of the P2Peer network for which
//                      events are being logged
//

#include "stdafx.h"

#include "P2PeerEvents.h"
#include "P2PeerConWsa.h"
#include "P2Pwin32.h"

P2PeerEvents *g_pP2PeerEvents = 0;

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

//
//  Description: P2PaddrSTR pThisP2PaddrSTR
//               Identification address for this peer
//
//               UINT nPumps
//               Number of pumps supported by hub
//
P2PeerEvents::P2PeerEvents ( P2PaddrSTR strThisP2Paddr )
            : P2PeerHub ( strThisP2Paddr )

{
    // Firstly
    RenderEventSafe();
}

P2PeerEvents::~P2PeerEvents ( )
{
    // Important
    // NOTES: Cancel event callbacks
    CancelEventCB ( );

    // Delegation
    // NOTES: Subordinate threads may have dependencies upon
    //        our resources
    CloseHub ( );
}

void
P2PeerEvents::RenderEventSafe (  )
{
    // Attributes
    m_nP2PeventSinkID   = 0;
    m_dwEventsClassMask =~0u;
    m_bSinkConnected    = false;
}

///////////////////////////////////////////////////////////////////////
//  P2PmsgHub management

//
//  Manufactures and starts instance of P2PeerEvents logging object
//
//
//  Parameters:  P2PaddrSTR strThisP2Paddr
//               Identification address of this hub
//
//               P2PaddrSTR nEventSinkP2PeerID
//               Identification address of the logged P2Pevent's hub
//
//               LPCTSTR lpszHostname
//               Logged P2Pevent's host name
//
//               short nIpPort
//               Logged P2Pevent's hub listening port
//
//               DWORD dwEventsMask
//               Logged events mask
//
//  Returns:     P2PeerEvents*
//               Manufactured object pointer.  Client becomes
//               responsible for life cycle
//                 0.. Failed to start
//
P2PeerEvents*
P2PeerEvents::WsaLogFactory( P2PaddrSTR  strThisP2Paddr
                           , P2PaddrSTR  strEventSinkP2Paddr
                           , LPCTSTR    lpszHostName, short nHostIpPort
                           , DWORD        dwEventsMask )
{
    // Manufacture
    P2PeerEvents *pP2PeerEvents;
    pP2PeerEvents = new P2PeerEvents ( strThisP2Paddr );
    pP2PeerEvents -> m_dwEventsClassMask = dwEventsMask;

    // Start
    BOOL bResult = pP2PeerEvents
      -> StartWsaLog ( strEventSinkP2Paddr
                     , lpszHostName, nHostIpPort );
    if ( bResult )
      return pP2PeerEvents;            // Up and running

    // Failure, tidy up, and
    delete pP2PeerEvents;
    return 0;                          // Flags failure
}
//P2PeerEvents*
//P2PeerEvents::FactoryStart_( HANDLE      hEventExternal
//                           , P2PaddrSTR  pThisP2PaddrSTR
//                           , P2PaddrSTR  pSinkP2PaddrSTR
//                           , LPCTSTR  lpszHostname, short nIpPort
//                           , DWORD      dwEventsMask )
//{
//    // Introduce locals
//    P2PeerEvents *pP2PeerEvents;
//
//    // Manufacture
//    pP2PeerEvents = new P2PeerEvents ( pThisP2PaddrSTR );
//    pP2PeerEvents -> m_dwEventsClassMask = dwEventsMask;
//
//    // Start
//    //TODO:LJM ACtivate if ( pP2PeerEvents->StartLogging(hEventExternal
//    //                                ,pSinkP2PaddrSTR
//    //                                ,lpszHostname,nIpPort) )
//      return pP2PeerEvents;            // Up and running
//    delete pP2PeerEvents;
//    return 0;
//}

//
//  Plain network P2PmsgHub implementation
//  NOTES: Simply pumps P2PeerSys, P2PeerCon and P2PeerMsg objects
//         through the P2PeerTarget base class
//       : P2PeerMsg's can be swapped out of this context via
//         ContextSwap() and processed independantly in the fullness
//         of time
//       : It's possible to have processing delays in this context.
//         But keep in mind P2PeerMsg's may keep building up
//
void
P2PeerEvents::RunEventsHub (  )
{
    // Because this is all problematic, we
    try
    {
      // Specialised context dependancies
      // NOTES: P2Pevent sink must be created within the context
      //        of the P2PeerHub to which the P2Pevent's notifications
      //        are posted
      //      : Refer On_P2Pevents() handler for further details
      ASSERT(m_nP2PeventSinkID==0);
      m_nP2PeventSinkID = CreateP2PeventSink ( this, true );

      // Privatise P2Pevent notifications for this hub
      // NOTES: Essentually a independant or standalone notifications
      //        hub.  Don't pollute P2Peer network with our P2Pevents
      //      : However, P2Pevent's will still flow within the context
      //        of this hub
      // TODO: 

      // Delegate for implementation
      RunHub ( );
    }

    // Exceptions
    catch ( P2Pevent *pEVT )
    {
      pEVT->Advice(_N("P2PeerEvents(%s) P2PmsgHub terminated")
                   , m_oP2PaddrHub.c_wstr() )
          ->Cancel();
    }
    catch ( ... )
    {
      EVERR->MODULE
           ->Message("Last resort exception of unknown type" )
           ->Advice (_N("P2PeerEvents(%s) P2PmsgHub terminated")
                    , m_oP2PaddrHub.c_wstr() )
           ->Cancel();
    }

    // Tidy up, and
    // NOTES: Manadatory last operations in the context of this hub
    if ( m_nP2PeventSinkID )
      CloseP2PeventSink ( m_nP2PeventSinkID );
    m_nP2PeventSinkID = 0;
}

//
//  Starts WSA logged P2Pevent's processing
//
//
//  Parameters:  P2PaddrSTR nEventSinkP2PeerID
//               Identification address of the logged P2Pevent's hub
//
//               LPCTSTR lpszHostname
//               Logged P2Pevent's host name
//
//               short nIpPort
//               Logged P2Pevent's hub listening port
//
//  Returns:     BOOL
//               Success code
//                 TRUE... Started OK
//                 FALSE.. Failure, refer EVGLE for further details
//
BOOL
P2PeerEvents::StartWsaLog ( P2PaddrSTR strEventSinkP2Paddr
                          , LPCTSTR lpszHostname, short nIpPort )
{
    // Delegate
    if ( !SpawnHub() )
      return FALSE;

    // Initiate connection with the events sink
    // NOTES: Remote sink will listen for and accept connections
    //        from multiple sources
    m_oSinkP2Paddr = strEventSinkP2Paddr;
    P2PeerConWsa *pCon
      = P2PeerConWsa::ClientFactory ( strEventSinkP2Paddr
                                    , lpszHostname, nIpPort );
    PostP2PeerCon ( pCon );

    // Tidy up, and
    return TRUE;
}
//BOOL
//P2PeerEvents::StartLogging_( HANDLE     hEventExternal
//                           , P2PaddrSTR pSinkP2PaddrSTR
//                           , LPCTSTR lpszHostname, short nIpPort )
//{
//    // Delegate
//    if ( !SpawnHub() )
//      return FALSE;
//
//    // Initiate connection with the events sink
//    // NOTES: Remote sink will listen for and accept connections
//    //        from multiple sources
//    m_oSinkP2Paddr = pSinkP2PaddrSTR;
//    P2PeerConWsa *pCon = new P2PeerConWsa ( pSinkP2PaddrSTR
//                                          , lpszHostname, nIpPort );
//    PostP2PeerCon ( pCon );
//
//    // Tidy up, and
//    return TRUE;
//}

void
P2PeerEvents::StopLogging ( )
{
    // Cancel event callbacks
    CancelEventCB ( );
}

//
//  Description: Call back that manages the receipt of logged events
//               NOTES: These events are passed directly to the
//                      events logging connection
//                    : Call back is performed in the context of the
//                      thread reporting the event.  Event is
//                      subsequently posted to the context of the
//                      thread managing the connection with the events
//                      sink
//
//
//  Parameters:  void *pP2PeerEvents
//               Pointer to object of this type
//
//               EventLogData *pLogEventails
//               Notification object
//
/*EventLogData* WINAPI
P2PeerEvents::LogEventailsCB ( void *pP2PeerEvents
                             , EventLogData *pLogEventails )
{
    // Resolve
    P2PeerEvents *pThis     = (P2PeerEvents *)pP2PeerEvents;
    //P2Paddr&      oP2Paddr  = pThis->GetP2Paddr();

ASSERT(pLogEventails->nSize<612);
    // Implementation
    PostP2Pmsg ( new P2PeerMsg ( pThis->GetP2PaddrHub()
                               , pThis->m_oSinkP2Paddr
                               , P2Pmsg_Eventails
        , (void *)pLogEventails, pLogEventails->nSize )
               , pThis->m_nHubID, false );

    // Tidy up and
    return pLogEventails;
}*/
//void WINAPI
//P2PeerEvents::P2PeventCB_ ( P2PeventSinkID nSinkID, DWORD dwCBKey
//                         , const P2Pevent& oEvent )
//{
//    // Resolve
//    ASSERT(0);//TODO:Deprecated by On_P2Pevent handler
//    P2PeerEvents *pThis  = (P2PeerEvents *)dwCBKey;
//
//    // Package and delivery
//    P2PeerMsgSP spMsg = new P2PeerMsg ( pThis->GetP2PaddrHub()
//                                      , pThis->m_oSinkP2Paddr
//                                      , P2Pmsg_Error
//                                      , 0, 0 );
//                spMsg -> AttachP2Pevent ( &oEvent );
//    PostP2Pmsg ( spMsg.Dereference(), pThis->m_nHubID, false );
//
//    // Tidy up and
//    return;
//}

///////////////////////////////////////////////////////////////////////
// Operations

//
//  Description: Registers for application P2Pevent notifications
//               NOTES: Such notifications are subsequently passed
//                      to the events log in EventLogData messages
//
//
//  Parameters:  DWORD dwEventsAddMask
//               Mask containing P2Pevent_e types to be added
//               to the registered events table
//
//               DWORD dwEventsRemMask
//               Mask containing P2Pevent_e types to be removed
//               from the registered events table
//                -1.. Masks out all notifications and effectively
//                     stops event logging
//
//  Returns:     DWORD
//               New event notifications mask
//
DWORD
P2PeerEvents::RegisterEventCB ( DWORD dwEventsAddMask
                              , DWORD dwEventsRemMask )
{
    // Persist
    m_dwEventsClassMask |=  dwEventsAddMask;
    m_dwEventsClassMask &= ~dwEventsRemMask;

    // Apply
    if ( m_nP2PeventSinkID )
      RegP2PeventCmd ( m_nP2PeventSinkID, P2Pevent_SetMask
                     , m_dwEventsClassMask );

    // Finally
    return m_dwEventsClassMask;
}

//
//  Description: Performs object destruction with wait duration
//
//
//  Parameters:  DWORD dwDuration
//               Maximum duration in milliseconds the calling thread
//               will be delayed until all outstanding events are
//               pumped through to the event sink
//               
P2PeerEvents*
P2PeerEvents::Destroy ( DWORD dwDuration )
{
    // Closure
    CloseHub ( );

    // Until wait duration exceeded or the output queue emptied
    while ( dwDuration               > 0 &&
            P2PeerHub::m_nHubID          &&
            GetP2PmsgCount(m_nHubID) > 0    )
    {
      dwDuration -= 100;
      Sleep ( 100 );
    }

    // 
    delete this;
    return 0;
}

//
//  Description: Cancels receipt of registered event call backs
//               NOTES: Mandatory that such call backs be
//                      cancelled before object destruction
void
P2PeerEvents::CancelEventCB ( )
{
    // Simply
    if ( m_nP2PeventSinkID )
      CloseP2PeventSink ( m_nP2PeventSinkID );
    m_nP2PeventSinkID = 0;
    //P2Pevent::RegisterForNotn ( P2PeerEvents::LogEventailsCB
    //                          , (void *)this
    //                          , 0, ~0 );
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerEvents::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}

///////////////////////////////////////////////////////////////////////
//  P2PeerCon connection handlers
//  NOTES: All these messages are delivered in the processing
//         context of the P2PmsgHub thread
//       : MSCS integration is managed through a single SDrvs
//         connection
BEGIN_P2PeerCon_MAP(P2PeerEvents, P2PeerHub)
    ON_P2PeerCon_STARTUP(L"*",On_ConStartup)
    ON_P2PeerCon_CONNECT(L"*",On_SinkConnect)
    ON_P2PeerCon_LOGINACK(L"*",On_SinkLoginAck)
    ON_P2PeerCon_CLOSE(L"*",On_SinkClose)
    //ON_P2PeerCon("*",On_SinkObject)
END_P2PeerCon_MAP()

//
//  Events sink connection handler
//  NOTES: Connection notification only.  Login sequence is yet
//         to proceed to completion.
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object.  Handler assumes control
//               over life cycle.
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerEvents::On_SinkConnect ( P2PeerCon *pCon )
{
    // Introduce locals
    conRESULT conResult = conDROP;

    // Because this is all problematic we
    try
    {
      // To be sure, to be sure
      ASSERT(m_oSinkP2Paddr==pCon->GetP2Paddress());

      // Perform login
      // NOTES: Provide confirmation of identification address
      pCon -> Login ( strP2PaddrNULL,
                      (P2PaddrSTR)m_oSinkP2Paddr
                                , m_oSinkP2Paddr.Sizeof()+1 );

      // Completed
      conResult = conHANDLED;
    }

    // Exceptions
    // NOTES: P2PeerCon connections self destruct if left
    //        unattended.  Failure trashes hub
    catch ( P2Pevent *pEVT )
    {
      pEVT -> Cancel();
      CloseHub ( );
      //P2PeerPump::SetEventExternal ( m_nHubID );
    }

    // Handled
    m_bSinkConnected = false;
    return conResult;                  // Message handled
}

//
//  Events sink login acknowledgement handler
//  NOTES: Completes our connection with the events sink
//       : Event notification logging will commence immediately
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//               P2PaddrSTR strThisP2Paddr
//               Remotely assigned or adopted identification address for
//               this peer
//
//               void *pvLoginMsg
//               Logon response message
//
//               P2Psize_t iSize
//               Size of above message
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerEvents::On_SinkLoginAck ( P2PeerCon *pCon
                              , P2PaddrSTR strThisP2Paddr
                              , P2PaddrSTR strThatP2Paddr
                              , const void *pvLoginAck, P2Psize_t iSize )
{
    // Introduce locals
    conRESULT wsaResult = conDROP;

    // Because this is all problematic we
    try
    {
      // Tracing
      if ( IsEVTRC )
        EVTRC->Module (_N("%hs(%s)"), __FUNCTION__
                      , GetP2PaddrHub().c_wstr() )
             ->Message(_T("Connection [%s] acknowledged")
                      , (P2PaddrSTR)pCon->GetP2Paddress() )
             ->Cancel();
CString csP2PeerID1=strThisP2Paddr;
//CString csP2PeerID2=GetP2PaddrHub();
//CString csP2PeerID3=pCon->GetP2Paddress();
      ASSERT(GetP2PaddrHub()==strThisP2Paddr);

      // Perform login acknowledgement processing
      pCon -> OnLoginAck ( strThisP2Paddr, strThatP2Paddr );

      // Observe acknowledgement contents
      // NOTES: Events sinks are different and must be implemented
      //        as stand alone hubs.
      //      : We must pre-nominate the P2Paddr of the events sink
      //        which in turn will assign us a dynamic child P2Paddr
      if (  iSize <= 0                                      ||
                                                !pvLoginAck ||
            pCon->GetP2Paddress() != (P2PaddrSTR)pvLoginAck    )
        EVERR->MODULE
             ->Message(_T("Events sink Login denied, connection destroyed") )
             ->Throw();

      // Activate events collection
      // NOTES: It's pointless accumulating events without
      //        connection with sink.  Observe existing sink status
      m_bSinkConnected = true;
      if ( m_nP2PeventSinkID <= 0 )
        m_nP2PeventSinkID = CreateP2PeventSink ( this, true );
      RegP2PeventCmd ( m_nP2PeventSinkID
                     , P2Pevent_SetMask, m_dwEventsClassMask );

      // Finally
      // NOTES: Activate connection with final operational
      //        properties
      pCon -> SetState ( ConState_Login, 0 );

      // Completed
      wsaResult        = conHANDLED;
    }

    // Exceptions
    // NOTES: P2PeerCon connections self destruct if left
    //        unattended.  Failure trashes hub
    catch ( P2Pevent *pEVT )
    {
      m_bSinkConnected = false;
      pEVT -> Cancel ( );
      CloseHub ( );
      //P2PeerPump::SetEventExternal ( m_nHubID );
    }

    // Handled
    return wsaResult;                  // Message handled
}

//
//  Events sink connection closed handler
//  NOTES: Attempt to restart connection after 20seconds
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object.  Handler assumes control
//               over life cycle.
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerEvents::On_SinkClose ( P2PeerCon *pCon )
{
    // Introduce locals
    conRESULT conResult = conDROP;

    // Because this is all problematic we
    try
    {
      // Clean up
      // NOTES: Pointless collecting events without access to
      //        the events sink
      //      : Flush undelivered events
      //      : Default closure prosessing
      ASSERT(m_oSinkP2Paddr==pCon->GetP2Paddress());
      CancelEventCB ( );
      FlushP2Pmsg ( m_nHubID );
      pCon -> OnClose ( );

      // Re-activate connection management
      pCon -> Restart ( 25000 );

      // Completed
      conResult = conHANDLED;
    }

    // Exceptions
    // NOTES: P2PeerCon connections self destruct if left
    //        unattended.  Failure to restart trashes hub
    catch ( P2Pevent *pEVT )
    {
      pEVT -> Cancel ( );
      CloseHub ( );
      //P2PeerPump::SetEventExternal ( m_nHubID );
    }

    // Handled
    m_bSinkConnected = false;
    return conResult;                  // Message handled
}

//
//  Description: Events sink object handler
//               NOTES: Handles P2PeerCon object requests.  Refer
//                      GetConObject() for further details
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object.  Handler assumes control
//               over life cycle.
//
//  Returns:     BOOL
//               Result code
//                 TRUE... Event handled
//                 FALSE.. Continue routing
//
//BOOL
//P2PeerEvents::On_SinkObject ( P2PeerCon *pCon )
//{
//    // Introduce locals
//    conRESULT wsaResult = conDROP;
//
//    // Clean up
//    // NOTES: Pointless collecting events without access to
//    //        the events sink
//    ASSERT(m_oSinkP2Paddr==pCon->GetP2Paddress());
//    CancelEventCB ( );
//
//    // Flush undelivered events
//    FlushP2Pmsg ( m_nHubID );
//
//    // Handled
//    // NOTES: P2PeerCon objects self destruct if left unattended
//    m_bSinkConnected = false;
//    return wsaResult;                  // Message handled
//}

///////////////////////////////////////////////////////////////////////
//  P2PeventSink handlers
//  NOTES: Manage P2PeventSink notifications

//
//  P2PeventSink notifications
//  NOTES: Performed in context of registered P2PmsgPump.  Such
//         notifications may originate from any context within
//         this application
//       : Exposed P2Pevent details are assumed to be public.  Should
//         details deemed to be private, then don't expose such.
//
//  Parameters:  P2PeventSinkID nSinkID
//               Notifications sink
//
//               P2PumpID nPumpID
//               P2Pevent originating P2PmsgPump context
//
//               P2Pevent *pEvent
//               Notification event
//
//  Returns:     evtRESULT
//               Result code
//
evtRESULT
P2PeerEvents::On_P2Pevent( P2PeventSinkID nSinkID, P2PumpID nPumpID
                         , P2Pevent *pEvent )
{
    // Confirm P2PmsgPump and P2PeventSinkID context
    // NOTES: P2Pevent notifications MUST be processed in the 
    //        context of this hub
    ASSERT(P2PeerContext(m_nHubID));
    ASSERT(nSinkID==m_nP2PeventSinkID);

    // Package and delivery
    // NOTES: Subsequently routed via P2PeerHub internals.  This
    //        P2PeerMsg may sit on a queue until contact established
    P2PeerMsgSP spMsg = new P2PeerMsg ( GetP2PaddrHub()
                                      , m_oSinkP2Paddr
                                      , P2Pmsg_Error
                                      , 0, 0 );
                spMsg -> AttachP2Pevent ( pEvent );
    PostP2Pmsg ( spMsg.Dereference(), nPumpID, false );

    // Tidy up and
    return evtHANDLED;
}

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg_MAP handlers
//  NOTES: Default handler set available in P2Peer derived object
//       : If there is a desire to optimise the message map
//         subjectively place frequent messages at the top and less
//         frequent messages at the bottom of the map
//
BEGIN_P2PeerMsg_MAP(P2PeerEvents, P2PeerHub)
    ON_P2PeerMsg_CATCH(P2Pmsg_Error, On_P2PmsgErrorCatch)
END_P2PeerMsg_MAP()

//
//  P2Pmsg_Error exception handler
//  NOTES: Manually dismissed to trap possible recursion
//
//
//  Parameters:  P2PeerMsg *pP2PeerMsg
//               Exception message
//
//  Returns:     msgRESULT
//               Completion summary
//
msgRESULT
P2PeerEvents::On_P2PmsgErrorCatch ( P2PeerMsg *pMsg )
{
    UNREFERENCED_PARAMETER(pMsg);

    // Simply
    // NOTES: Any action exposing us to a subsequent event could
    //        result in recursion
    return msgHANDLED;
}

