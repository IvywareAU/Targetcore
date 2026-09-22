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
//  Description: P2PeerConDmx implementation
//               NOTES: Manages P2Peer RS232 connections
//

#include "stdafx.h"
//#include "P2PTL.h"
#include "Kernel32_Ext.h"
#include "P2PeerConDmx.h"
#include "P2PeerioDmx.h"
#include "P2Pwin32.h"

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

CListP2PeerConDmx g_oCListP2PeerConDmx;
CRITICAL_SECTION  g_oCSectP2PeerConDmx;

P2PeerConDmx::P2PeerConDmx ( )
{
    // Firstly
    RenderThisSafe ( );
}

//
//  Parameters:  P2PaddrSTR strThatP2Paddr
//               Identification address for that, or the other end
//
//               LPCTSTR lpszPipename
//               Pipe name
//
P2PeerConDmx::P2PeerConDmx ( P2PaddrSTR pThatP2PaddrSTR
                           , LPCTSTR strServiceName
                           , P2PeerConMode_e eMode
                           , P2Peerio *pP2Peerio )
            : P2PeerCon ( pThatP2PaddrSTR, pP2Peerio )
{
    // Firstly
    RenderThisSafe();
    m_sServiceName   = strServiceName;
    //m_oThisP2Paddr   =    strThisP2Paddr;
    //m_oThatP2Paddr   =    strThatP2Paddr;
    m_eP2PeerConMode =    eMode;
}

//
//               short nIPort
//               Listening port
//
P2PeerConDmx::P2PeerConDmx ( P2PaddrSTR pThisP2PaddrSTR
                           , P2PeerConMode_e eMode
                           , P2Peerio *pP2Peerio )
             : P2PeerCon ( pThisP2PaddrSTR, pP2Peerio )
{
    // Firstly
    RenderThisSafe();
    //m_oThisP2Paddr   =    strThisP2Paddr;
    //m_oThatP2Paddr   =    strThisP2Paddr;
    m_eP2PeerConMode =    eMode;
}

//
//  NOTES: Listen() registers `this` in the process-global
//         g_oCListP2PeerConDmx (below) and NOTHING else ever takes it out --
//         not Drop(), not OnClose().  Deregistering has to happen HERE,
//         because here is the only point at which this address stops being a
//         valid P2PeerConDmx and becomes reusable memory.  Two things went
//         wrong while the entry outlived the object:
//           - Connect()'s rendezvous scan walks every entry and reads
//             m_eP2PeerConMode / m_sServiceName off it, so a stale entry is a
//             use-after-free on EVERY subsequent Dmx dial;
//           - Listen()'s own single-entry guard compares by POINTER, so the
//             next connection the allocator places at a recycled address
//             throws "Duplicate listen attempted on single connection" on a
//             hub that has done nothing wrong.
//         Measured before this change: after closing 8 hubs that each owned
//         an armed-but-never-dialled Dmx service, only 3 of 8 subsequent
//         in-process links completed their login; the rest failed silently.
//       : The destructor and NOT Drop(), deliberately.  Drop() also runs on a
//         connection that is merely closing and may still be Restart()ed --
//         a SERVICE con re-registers through On_ConStartup -> Listen() -- so
//         deregistering there would unregister a service that is coming back
//       : Same g_oCSectP2PeerConDmx the registration takes, scoped to just
//         the list mutation.  It is not held across anything that could take
//         the pump-registry lock, so the AB-BA inversion Listen() documents
//         is not reintroduced
//
P2PeerConDmx::~P2PeerConDmx ( )
{
    // Resource collection
    Drop ( 0 );

    // Deregistration
    {
      P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;
      POSITION  pos     = g_oCListP2PeerConDmx.GetHeadPosition();
      while ( pos )
      {
        POSITION posDrop = pos;
        if ( g_oCListP2PeerConDmx.GetNext(pos) == this )
        {
          g_oCListP2PeerConDmx.RemoveAt ( posDrop );
          break;                          // Listen()'s guard keeps it unique
        }
      }
    }
}

void
P2PeerConDmx::RenderThisSafe()
{
    // Attributes
    m_pConThat   = 0;

    // Resources
    static bool s_bInitialised = false;
    if ( !s_bInitialised )
      InitializeCriticalSection ( &g_oCSectP2PeerConDmx );
    s_bInitialised = true;
}

//
//  Description: Splits listening connection into listening and
//               accepted P2PeerCon'nections
//               NOTES: Derived classes must delegate
//
//
//  Parameters:  P2PeerCon **pConListen = 0
//               Previously manufactured listening instance
//
//               P2PeerCon **pConAccept = 0
//               Previously manufactured accept instance
//
/*void
P2PeerConDmx::AcceptSplit ( P2PeerCon **ppConListen
                          , P2PeerCon **ppConAccept )
{
    // Locals
    P2PeerConDmx *pConListen = (P2PeerConDmx *)*ppConListen;
    P2PeerConDmx *pConAccept = (P2PeerConDmx *)*ppConAccept;
    if ( pConListen==0&&pConAccept==0)
      return;

    // Listen
    // NOTES: This object by default. Pointer to this objects resides
    //        in s_oCListP2PeerConHub and as such state must be preserved
    //      : Block any further accepted connections until this one
    //        processed
    if ( !pConListen )
      pConListen = this;
    if (  pConListen->m_pOVERLAPPEDaccept )
      pConListen -> m_pOVERLAPPEDaccept
         = pConListen -> DropOVERLAPPED( pConListen->m_pOVERLAPPEDaccept );

    // Accept
    // NOTES: Mandatory P2PeerConPlc integration
    if ( !pConAccept )
    {
       pConAccept  = new P2PeerConDmx ( );
      *this += pConAccept;
    }

    // Settlement
    // NOTES: Accept removes the allocated socket
    P2PeerCon::AcceptSplit ( (P2PeerCon **)&pConListen
                           , (P2PeerCon **)&pConAccept );
    pConAccept -> m_pConThat   = pConListen -> m_pConThat;
                                 pConListen -> m_pConThat = 0;
    pConAccept -> m_hFile      = pConListen -> m_hFile;
                                 pConListen -> m_hFile = 0;
    pConAccept -> m_hFileCPort = pConListen -> m_hFileCPort;
                                 pConListen -> m_hFileCPort = 0;
    pConAccept -> m_pConThat -> m_pConThat = pConAccept;

    // Simply
    // NOTES: Operational ready
    *ppConListen = pConListen;
    *ppConAccept = pConAccept;
}*/

P2PeerConDmx*
P2PeerConDmx::ServiceFactory( P2PaddrSTR pThatP2PaddrSTR
                            , LPCTSTR strServiceName )

{
    // Locals
    P2PeerConDmx *pCon = new P2PeerConDmx ( );

    // Attributes
    //pCon -> m_oThisP2Paddr   = pThisP2PaddrSTR;
    pCon -> m_oThatP2Paddr   = pThatP2PaddrSTR;// | L4Cbit;
    pCon -> m_sServiceName   = strServiceName;
    pCon -> m_eP2PeerConMode = P2PeerCon_SERVICE;

    // Protocol
    pCon -> SetP2Peerio ( new P2PeerioDmx( ) );

    // Done
    return pCon;
}

P2PeerConDmx*
P2PeerConDmx::ClientFactory ( P2PaddrSTR pThatP2PaddrSTR
                            , LPCTSTR strServiceName )

{
    // Locals
    P2PeerConDmx *pCon = new P2PeerConDmx ( );

    // Attributes
    //pCon -> m_oThisP2Paddr   = pThisP2PaddrSTR;
    pCon -> m_oThatP2Paddr   = pThatP2PaddrSTR;
    pCon -> m_sServiceName   = strServiceName;
    pCon -> m_eP2PeerConMode = P2PeerCon_CLIENT;

    // Protocol
    pCon -> SetP2Peerio ( new P2PeerioDmx( ) );

    // Done
    return pCon;
}

P2PeerCon*
P2PeerConDmx::AcceptSpawn ( P2PeerCon *pConSpawn )
{
    // Service
    // NOTES: Pointer to this object resides in s_oCListP2PeerConHub
    //        and as such state must be preserved
    //      : Block any further accepted connections until this one
    //        processed
    if ( m_pOVERLAPPEDaccept )
      m_pOVERLAPPEDaccept = DropOVERLAPPED( m_pOVERLAPPEDaccept );

    // Instanciation etc
    // NOTES: Actual object that manages the connection
    if ( pConSpawn == NULL )
      pConSpawn = new P2PeerConDmx ( );

    // Settlement
    // NOTES: Posts object for subsequent connection processing in 
    //        response to posted OVERLAPPED IO objects
    P2PeerCon::AcceptSpawn ( pConSpawn );
    P2PsafeCS     oSafeCS  = g_oCSectP2PeerConDmx;
    P2PeerConDmx *pConThis = (P2PeerConDmx *)pConSpawn;

    pConThis -> m_pConThat   = m_pConThat;
                               m_pConThat = 0;
    pConThis -> m_hFile      = m_hFile;
                               m_hFile = 0;
    pConThis -> m_hFileCPort = m_hFileCPort;
                               m_hFileCPort = 0;

    if ( pConThis->m_pConThat )
    {
      pConThis -> m_pConThat -> m_pConThat   = pConThis;
      pConThis -> m_pConThat -> m_hFile      = (HANDLE)pConThis->GetP2Peerio();
      pConThis -> m_pConThat -> m_hFileCPort = (HANDLE)pConThis;
ASSERT(pConThis==pConThis->m_pConThat->m_pConThat);
    }

    // Done
    // NOTES: Spawned object is free floating
    return pConSpawn;
}

///////////////////////////////////////////////////////////////////////
//  IOCP Integration
//

//
//  Description: Processes IO completion status
//               NOTES:
//
//
//  Parameters:  DWORD dwError
//               Error code associated with operation
//               
//               DWORD dbBytes
//               Bytes transferred during completed I/O operation.
//
//               OVERLAPPEDcon pOVERLAPPEDcon
//               Address of OVERLAPPEDcon structure that was specified
//               for the I/O operation
//
/*bool
P2PeerConDmx::On_QueuedCompletionStatus ( DWORD dwError
                                         , DWORD dwBytes
                                         , OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // Pre-processing
    HRESULT hr = dwError;
    if ( hr == S_OK )
      hr = pOVERLAPPEDcon -> hr;

    // Because this is all problematic we
    try
    {
      // Accept
      // NOTES: Perform On_P2PeerCon_ACCEPT() notification.  At which
      //        point the intercepting handler will initiate state
      //        changes.
      //      : Perform On_P2PeerCon_LISTEN() notification.  At which
      //        point the intercepting handler will listen for another
      //        connection
      if ( pOVERLAPPEDcon == m_pOVERLAPPEDaccept )
      {
        // Success
        // NOTES: Honour expectation that the On_P2PeerCon_ACCEPT()
        //        processed before the ON_P2PeerCon_LISTEN()
        //        notification
        releaseOVERLAPPED ( pOVERLAPPEDcon );
        if (   hr == S_OK &&
             m_hFileCPort    )
        {
          if ( m_pOVERLAPPEDsend == NULL )
            m_pOVERLAPPEDsend = MakeOVERLAPPED ( );
          if ( m_pOVERLAPPEDrecv == NULL )
            m_pOVERLAPPEDrecv = MakeOVERLAPPED ( MAX_P2Psize );

          // ON_P2PeerOLD_ACCEPT() notification
          // NOTES: Spawn accepted connection
          PostP2Pmsg ( m_oThisP2Paddr, CN_P2PeerCon, P2P_Accept
                     , ExtractAccept(), 0 );

          // ON_P2PeerCon_LISTEN() notification
          // NOTES: Listen for new connection
          PostP2Pmsg ( m_oThisP2Paddr, CN_P2PeerCon, P2P_Listen
                     , this, 0 );
        }

        // Failure
        // NOTES: Accepted connection failure
        else if (   hr         &&
                  m_hFileCPort    )
          EVERR->Module ("%s[%s-%s]", __FUNCTION__
                        , EncodeP2PeerID(m_oThisP2Paddr)
                        , EncodeP2PeerID(m_oThatP2Paddr) )
               ->Message("Overlapped accept failed")
               ->HResult( hr ) -> Throw();

        // Cancellation
        // NOTES: IoCancel(m_hFileCPort) and CloseHandle(m_hFileCPort)
        //        issued
        else
          m_pOVERLAPPEDaccept = DropOVERLAPPED ( pOVERLAPPEDcon );
      }

      // Connect
      // NOTES: Perform On_P2PeerCon_CONNECT() notification.  At which
      //        point the intercepting handler will initiate the
      //        appropriate state changes.
      else if ( pOVERLAPPEDcon == m_pOVERLAPPEDconnect )
      {
        releaseOVERLAPPED ( pOVERLAPPEDcon );
        if ( hr )
          EVERR->Module  ("%s(%s-%s)", __FUNCTION__
                         , EncodeP2PeerID(m_oThisP2Paddr)
                         , EncodeP2PeerID(m_oThatP2Paddr) )
               ->Message ("Overlapped ConnectEx failed")
               ->WSAGROUP( hr ) -> Throw();

        // On_P2PeerCon_CONNECT() notification
        // NOTES: Send() and Recv() buffers required beyond this point
        if ( m_pOVERLAPPEDsend == NULL )
          m_pOVERLAPPEDsend = MakeOVERLAPPED (  );
        if ( m_pOVERLAPPEDrecv == NULL )
          m_pOVERLAPPEDrecv = MakeOVERLAPPED ( MAX_P2Psize );

        PostP2Pmsg  ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Connect
                    , this, (P2PeerMsg *)0 );
      }

      // Delegate
      else
        P2PeerCon::On_QueuedCompletionStatus ( dwError, dwBytes, pOVERLAPPEDcon );
    }

    // Exceptions
    // NOTES: Notification will eventually be routed through to
    //        ON_P2PeerCon_CLOSE() handler. At which point Restart()
    //        may be used on non accepted sockets or this object
    //        conDROP'ed
    //      : ON_P2PeerCon_CLOSE() handler to which this posted object
    //        is routed MUST cancel the attached event.  OnClose()
    //        contains such default processing.
    //      : P2P_Close notification MUST be performed once per
    //        attached event. Subsequent P2P_Close notifications are
    //        blocked until the original event is cancelled.
    catch ( P2Pevent *pEVENT )
    {
      Drop ( pEVENT->Isolate() );
    }

    // Tidy up and
    return true;
}*/


//
//  Description: Drops the encapsulated connection and performs the
//               appropriate ON_P2PeerCon_CLOSE() notification
//               NOTES: Should an EVENT already be attached the passed
//                      EVENT is simply cancelled.
//
//
//  Parameters:  P2Pevent *pEVENT
//               Precipitating event.  May be NULL
//               NOTES: Control assumed over life cycle.
//
void
P2PeerConDmx::Drop ( P2Pevent *pEVENT )
{
    //  Break the pair and tell the other end - on ITS pump, not this one
    //  NOTES: THE PEER IS TOLD BY HANDING ITS OWN PARKED READ BACK TO ITS OWN
    //         COMPLETION PORT, ABORTED.  P2PeerioDmx::UnparkRecv() posts the
    //         buffer the peer parked when it last had nothing to read, so the
    //         peer's own pump wakes with a failed receive, throws through the
    //         recv branch's failure arm, and Drop()s itself with the pump's
    //         reference in hand - which is what makes its P2P_Close post
    //         reachable at all (P2PeerCon::Drop suppresses it whenever
    //         PostDestroyState() is true, and an unreferenced idle connection
    //         is always in that state).  Its own hub then runs On_ConClose,
    //         conDROPs it, and ~P2PeerCon gives the accept slot back.  Nothing
    //         is dropped, destroyed, referenced or deleted from this side
    //       : That is the SEVENTH design for OpenCodeWork.md item 7 and the
    //         first that adds no notification.  Six were built and measured
    //         before it - async and synchronous retirement from here, three
    //         signals, and a P2PsigCon_CLOSE gated on the peer having nothing
    //         queued - and every one passed p2p_dmxcap_slot and broke p2pweb
    //         somewhere else.  They all reached for a peer that, by the
    //         accounting of the time, was owed nothing and referenced by
    //         nothing.  The park now holds a reference (P2PeerioDmx.cpp, the
    //         "Nothing waiting" branch), so the peer is provably alive for as
    //         long as it is parked, and the wake is a post to an object the
    //         port already knows how to retire
    //       : WHAT STOOD HERE WAS A DOUBLE POST, AND IT WAS THE w6 SEGFAULT.
    //         Both the branch for this object's recv and the one for the
    //         peer's took bQueued as their precondition, releaseOVERLAPPED()d
    //         the object and posted it again.  bQueued means the object is
    //         ALREADY IN THE PORT, so that put one OVERLAPPED in the port
    //         twice with the reference count unchanged; the connection could
    //         retire after the first completion and the second then loaded
    //         the vtable of freed memory - PumpP2Pmsg, P2Pwin32.cpp:5531,
    //         same fault offset on three builds, the OVERLAPPED reading back
    //         0xDDDDDDDD.  A queued completion needs no help: it arrives, and
    //         with m_hFileCPort cleared below it lands in the cancellation arm
    //         and is drained.  So nothing queued is touched here any more
    //       : This object's own parked read is handed back by
    //         P2PeerioDmx::Reset(), which P2PeerCon::Drop() calls once this
    //         has cleared m_hFileCPort - so that completion, too, is a
    //         cancellation and not a wake
    //       : m_hFile and m_hFileCPort on the PEER are deliberately left set.
    //         The failure arm the wake relies on is guarded by m_hFileCPort
    //         (P2PeerCon.cpp:664-672); clear it and the abort is read as a
    //         cancellation instead, the peer is quietly drained and not
    //         closed, and the slot leaks again by a different route.  The
    //         peer's own Drop() clears both once it runs
    //       : Best effort, because Drop() is reached from ~P2PeerConDmx
    //         (:103-106) and a throw there is std::terminate.  UnparkRecv()
    //         throws only when the peer's port is gone, which is only true of
    //         a hub already torn down, and it has released the park's
    //         reference before it does
    {
      // Isolation
      P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;

      P2PeerConDmx *pConThat = m_pConThat;
                               m_pConThat   = 0;
                               m_hFile      = 0;
                               m_hFileCPort = 0;

      if ( pConThat                     &&
           pConThat->m_pConThat == this    )
      {
        pConThat -> m_pConThat = 0;
        //  NOT A PEER WHOSE OWN HUB ALREADY HAS IT.  CloseP2PmsgHub() Destroy()s
        //  every connection it owns before it Drop()s them and drains, so a
        //  peer carrying m_bDestroy is on its own sweep: its own Drop() ->
        //  Reset() hands its park back to its own port and its own drain
        //  collects it.  A post from here could land after that drain and be
        //  collected by nobody, holding a reference nobody would release
        P2PeerioDmx *pioThat = (P2PeerioDmx *)pConThat->GetP2Peerio ( );
        if ( pioThat && !pConThat->m_bDestroy )
        {
          try                      { pioThat -> UnparkRecv ( ERROR_OPERATION_ABORTED ); }
          catch ( P2Pevent *pEVT ) { if ( pEVT ) pEVT -> Cancel ( false );             }
          catch ( ... )            {                                                   }
        }
      }
    }

    // Always delegate
    P2PeerCon::Drop ( pEVENT );
}

///////////////////////////////////////////////////////////////////////
//  Connection state management 
//  NOTES: Referenced from P2PeerCon_MAP handlers only

//
//  Description: Initiates listen processing for object.
//               NOTES: Referenced from On_P2PeerCon_STARTUP handlers
//                      for listen type objects.
//
//
//  Returns:     bool
//               Listen summary
//
bool
P2PeerConDmx::Listen ( )
{
    // Delegate for state confirmation
    P2PeerCon::Listen ( );

    // To be sure, to be sure
    // NOTES: Single entries only.  Scope the g_oCSectP2PeerConDmx lock to JUST
    //        the g_oCListP2PeerConDmx mutation below: it must NOT still be held
    //        across the PostP2Pmsg() that follows, which takes the pump-registry
    //        lock (s_oCSectionP2PmsgPump).  That nesting is one arm of an AB-BA
    //        lock-order inversion with CloseP2PmsgHub's teardown sweep
    //        (pump-lock -> pCon->Drop -> g_oCSectP2PeerConDmx); TSan flags it as
    //        a potential deadlock.  Releasing the transport lock before the post
    //        removes the transport-lock -> pump-lock edge and breaks the cycle.
    {
      P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;
      POSITION   pos    = g_oCListP2PeerConDmx.GetHeadPosition();
      while ( pos )
      {
        if ( g_oCListP2PeerConDmx.GetNext(pos) == this )
          EVERR->Module (L"%hs(%s)", __FUNCTION__
                        , GetP2Paddress().c_wstr() )
               ->Message("Duplicate listen attempted on single connection"
                         "ADVICE\t: Bug(SNHappen)" )
               ->Throw();
      }
      g_oCListP2PeerConDmx.AddTail ( this );
    }

    // On_P2PeerCon_LISTEN() notification
    // NOTES: P2P_Listen for consistency with the other transports (Wsa/Pipe): the default
    //        ON_P2PeerCon_LISTEN handler (P2PeerTarget::On_ConListen) runs OnListen() then
    //        Accept(), which creates m_pOVERLAPPEDaccept — the latch point Connect() needs.
    //        Posting P2P_Accept here ("Was P2P_Listen") reached the same end state only via a
    //        premature spawn-and-drop OnAccept() falling through to the service re-arm
    //        Accept() at the tail of On_ConAccept, and it skipped the listen notification.
    PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Listen
               , this, (P2PeerMsg *)0, m_hCPortP2PumpID );

    // Tidy up and
    return true;
}

//
//  Description: Initiates accept facility for object.
//               NOTES: Usually referenced from ON_P2PeerCon_LISTEN
//                      handlers.
//                    : Accepted connections are processed via
//                      ON_P2PeerOLD_ACCEPT handlers
//
//
//  Returns:     bool
//
bool
P2PeerConDmx::Accept ( )
{
    // Delegate for state confirmation
    P2PeerCon::Accept ( );

    // To be sure, to be sure
    if ( m_pConThat          ||
         m_pOVERLAPPEDaccept    )
      EVERR->Module (L"%hs[%s-%s]", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Message(L"Duplicate accepts attempted on single connection"
                    ,L"ADVICE\t: Bug (SNHappen)" )
           ->Throw();

    // Initiate wait for client connection
    // NOTES: Must be a non-pended operation
    if ( m_pOVERLAPPEDaccept == NULL )
      m_pOVERLAPPEDaccept = MakeOVERLAPPED ( );

    // Done
    return true;
}

//
//  Performs ACCEPT'ed connection processing
//  NOTES: This processing must be performed for all accepted
//         connections
//       : Reference from within ON_P2PeerOLD_ACCEPT() handlers
//
//
//  Parameters:  const P2Paddr oThatP2Paddr
//               Identification assigned to remote client
//               NOTES: Assignment may be defered to the login 
//                      phase by specifying a NULL value
//
P2PeerCon*
P2PeerConDmx::OnAccept ( )
{
    // To be sure, to be sure
    // NOTES: Something must have externally nominated itself by reaching
    //        into this object to be accepted
    ASSERT(GetMode()==P2PeerCon_SERVICE);
    if ( m_pConThat == NULL )
      return 0;

    // Accept admission control (OpenCodeWork.md item 2, DMX half)
    // NOTES: SetMaxAccepted() was enforced in P2PeerConWsa alone until
    //        2026-09-19 and in P2PeerConPipe from 2026-09-20; this transport
    //        had no accept bound of any kind, documented or accidental.  The
    //        DECISION has always been on the base (AcceptAtCapacity,
    //        P2PeerCon.h:255); what was missing is this call.  P2PeerCon.h:237
    //        -238 says why it has to be made here rather than there: "the
    //        refusal itself is transport-specific, because only the transport
    //        knows how to discard a half-accepted endpoint".
    //      : AND ON THIS TRANSPORT THERE IS NOTHING TO DECLINE - only
    //        something to DETACH, which is why this is longer than the Wsa
    //        and pipe refusals put together.  Wsa is asked before it adopts
    //        the socket.  Here the CLIENT does the latching: Connect() walks
    //        g_oCListP2PeerConDmx for a SERVICE whose m_sServiceName matches,
    //        writes BOTH back-pointers itself, and only then posts this
    //        object's accept OVERLAPPED (:788-813).  So by the time this runs
    //        the client is already attached, and a refusal that just returned
    //        NULL would leave it attached to a service that will never
    //        complete it - a hang, not a refusal.
    //      : THE DETACH IS OnClose()'s SEQUENCE AND IS COPIED FROM IT rather
    //        than reinvented: clear this side's pointers BEFORE the nested
    //        Drop so it cannot recurse back in, verify the peer still points
    //        at us, clear its side, then Drop(0) to complete its outstanding
    //        IO with ERROR_OPERATION_ABORTED and route it through its own
    //        close handling.  g_oCSectP2PeerConDmx is reentrant, so the
    //        nested re-acquire inside Drop() is safe - the same note
    //        OnClose() carries at :862-865.
    //      : THE CONSUMED ACCEPT MUST BE DROPPED HERE, and forgetting it
    //        turns a refusal into a dead service.  On the normal path
    //        AcceptSpawn() does it (:246-247); the tail of
    //        P2PeerTarget::On_ConAccept then re-arms unconditionally with
    //        Accept() (:2516-2517), and P2PeerConDmx::Accept() THROWS "Duplicate
    //        accepts attempted on single connection" if either m_pConThat or
    //        m_pOVERLAPPEDaccept survived (:546-553).  Refusing without this
    //        line would refuse the second client and every client after it.
    //      : NOT per-source.  AcceptSourceKey() is 0 for this transport and
    //        deliberately so - an in-process link is peer by construction, so
    //        a per-source share would divide a share of one.  Refer
    //        P2PeerCon.h:226-230
    //      : NO ATTRIBUTION FIX IS NEEDED BELOW, unlike the pipe, and this
    //        was measured rather than reasoned.  P2PeerConPipe morphs - its
    //        spawn becomes the next SERVICE - so P2PeerCon::AcceptSpawn's
    //        "zero the spawn's cap, count the slot on the spawn" is backwards
    //        there.  This AcceptSpawn hands m_pConThat/m_hFile/m_hFileCPort
    //        TO the spawn (:261-266), so the spawn really is the accepted
    //        connection, the base's attribution is right, and p2p_dmxcap's
    //        third phase says so: the slot comes back when the client leaves
    if ( AcceptAtCapacity ( ) )
    {
      // Detach the client the CLIENT attached
      {
        P2PsafeCS     oSafeCS  = g_oCSectP2PeerConDmx;
        P2PeerConDmx *pConThat = m_pConThat;
                                 m_pConThat   = 0;
                                 m_hFile      = 0;
                                 m_hFileCPort = 0;
        if ( pConThat                     &&
             pConThat->m_pConThat == this    )
        {
          pConThat -> m_pConThat   = 0;
          pConThat -> m_hFile      = 0;
          pConThat -> m_hFileCPort = 0;
          pConThat -> Drop ( 0 );
        }
      }

      // Leave the re-arm something to arm
      if ( m_pOVERLAPPEDaccept )
        m_pOVERLAPPEDaccept = DropOVERLAPPED ( m_pOVERLAPPEDaccept );

      if ( IsEVTRC )
        EVTRC->Module (L"%hs[%s]", __FUNCTION__
                      , GetP2PaddrHub().c_wstr() )
             ->Message(L"Accept refused, at capacity %i"
                      , m_xMaxAccepted.load ( ) )
             ->Advice_T("Raise P2PeerCon::SetMaxAccepted(), or 0 to unbound")
             ->Cancel ( );
      return 0;
    }

    // Delegate
    // NOTES: Spawns an object to actually manage the collection which
    //        in turn releases this object to accept additional connections
    P2PeerConDmx *pConSpawn = (P2PeerConDmx *)P2PeerCon::OnAccept ( );

    // Connection notification
    // NOTES: Connecting object has actually latched onto this listening
    //        object but to complete the connection this was previously
    //        all transfered across to the spawned accepted connection
    //        object
    /*if ( pConSpawn             &&
         pConSpawn->m_pConThat    )
    {
      P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;
      if ( pConSpawn->m_pConThat                       &&
           pConSpawn->m_pConThat->m_pOVERLAPPEDconnect    )
      {
        pConSpawn -> m_pConThat
                  -> PostOVERLAPPED ( pConSpawn->m_pConThat->m_pOVERLAPPEDconnect );
        ASSERT(pConSpawn==pConSpawn->m_pConThat->m_pConThat);
      }
    }*/

    // Lost connection
    if (  pConSpawn             &&
         !pConSpawn->m_pConThat    )
    {
      pConSpawn -> Drop ( 0 );
      pConSpawn = 0;
    }

    // Activate P2PeerMsg receipt on the accepted connection
    // NOTES: AcceptSpawn() cleared ConState_Recv|Send and left the spawn
    //        with no outstanding IO. Mirror P2PeerConPipe::OnAccept(): the
    //        accepted con must have its recv OVERLAPPED created AND posted
    //        so the in-process rendezvous with the client's login send can
    //        complete. Without the post the con has no pending IO, the
    //        login never arrives and the connection is torn down.
    if ( pConSpawn )
    {
      if ( !pConSpawn->m_pOVERLAPPEDsend )
        pConSpawn -> m_pOVERLAPPEDsend = pConSpawn -> MakeOVERLAPPED ( );
      if ( !pConSpawn->m_pOVERLAPPEDrecv )
        pConSpawn -> m_pOVERLAPPEDrecv = pConSpawn -> MakeOVERLAPPED ( MAX_P2Psize );
      if ( !pConSpawn->m_pOVERLAPPEDrecv->bQueued )
        pConSpawn -> PostOVERLAPPED ( pConSpawn->m_pOVERLAPPEDrecv );

      // Tidy up, and
      pConSpawn -> SetState ( ConState_Send | ConState_Recv, 0 );
    }
    return pConSpawn;
}
void
P2PeerConDmx::OnAccept ( const P2Paddr oThatP2Paddr )
{
    // Delegate
    P2PeerCon::OnAccept ( oThatP2Paddr );
    ASSERT(GetMode()!=P2PeerCon_SERVICE);

    // Connection notification
    // NOTES: Connecting object latches onto the listening object but to
    //        complete the connection this must be all transfered across
    //        to the allocated accepted connection object
    if ( m_pConThat )
    {
      P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;
      if ( m_pConThat                       &&
           m_pConThat->m_pOVERLAPPEDconnect    )
      {
        m_pConThat -> m_hFile      = (HANDLE)GetP2Peerio();
        m_pConThat -> m_hFileCPort = (HANDLE)this;
        m_pConThat -> PostOVERLAPPED ( m_pConThat->m_pOVERLAPPEDconnect );
      }
    }

    // Lost connection
    if ( !m_pConThat )
        Drop ( 0 );
}

//
//  Initiates connection processing for object.
//  NOTES: Referenced from On_P2PeerCon_STARTUP handlers for
//         connection type objects.
//
//
//  Returns:     bool
//               Connection summary
//
bool
P2PeerConDmx::Connect ( )
{
    // State confirmation
    P2PeerCon::Connect ( );
    ASSERT(GetMode()!=P2PeerCon_SERVICE);

    // To be sure, to be sure
    if ( m_pConThat )
      EVERR->Module (L"%hs(%s)", __FUNCTION__
                    , GetP2Paddress().c_wstr() )
           ->Message("Previously connected")
           ->Advice ("Bug(SNHappen)" )
           ->Throw();

    // Search for listening connection
    // NOTES: Single entries only
  __time64_t uTimeout = _time64(0)*1000 + 100;
TOP:if ( !m_pConThat ) 
    {
      SwitchToThread ( );
      P2PeerConDmx *pCon    = 0;
      P2PsafeCS     oSafeCS = g_oCSectP2PeerConDmx;
      POSITION       pos    = g_oCListP2PeerConDmx.GetHeadPosition();
      while ( pos )
      {
        pCon = g_oCListP2PeerConDmx.GetNext ( pos );
        if ( pCon->m_eP2PeerConMode == P2PeerCon_SERVICE &&
             pCon->m_sServiceName   == m_sServiceName       )
            break;
        pCon = 0;
      }

      // Accepted connection
      // NOTES: Base class uses m_hFileCPort as state flag
      if (  pCon                               &&
            pCon->m_pOVERLAPPEDaccept          &&
           !pCon->m_pOVERLAPPEDaccept->bQueued &&
           !pCon->m_pConThat                      )
      {
        pCon -> m_pOVERLAPPEDaccept -> dwUserData = (DWORD_PTR)this;
        //pCon -> PostOVERLAPPED    ( pCon->m_pOVERLAPPEDaccept ); prior to 22/09/2011
                      m_pConThat   =         pCon;
                      m_hFileCPort = (HANDLE)pCon;
                      m_hFile      = (HANDLE)pCon->GetP2Peerio();
        m_pConThat -> m_pConThat   =         this;
        m_pConThat -> m_hFileCPort = (HANDLE)this;
        m_pConThat -> m_hFile      = (HANDLE)this->GetP2Peerio();
        // Create our connect-completion OVERLAPPED BEFORE waking the server to
        // Accept(). The server's OnAccept() posts m_pOVERLAPPEDconnect back to this
        // (client) con, but only if it is already non-NULL. Creating it after the
        // post below races the server: under load the server runs OnAccept() first,
        // observes a NULL m_pOVERLAPPEDconnect, silently skips the notification, and
        // On_ConConnect never fires -> the Dmx handshake stalls (multiples of the
        // RunHub pump timeout). Done here under g_oCSectP2PeerConDmx (held), which the
        // server's OnAccept() also acquires, so the store is ordered-before its read.
        if ( m_pOVERLAPPEDconnect == NULL )
          m_pOVERLAPPEDconnect = MakeOVERLAPPED ( 0 );
        pCon -> PostOVERLAPPED    ( pCon->m_pOVERLAPPEDaccept ); //after 22/09/2011
      }

      // Yield and try again
      if ( !m_pConThat                 &&
           _time64(0)*1000 <= uTimeout    )
        goto TOP;
    }

    // To be sure, to be sure
    if ( !m_pConThat )
      EVERR->Module (L"%hs(%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr() )
           ->Message(L"Connection %s to %s failed"
                    , GetP2Paddress().c_wstr(), (LPCTSTR)m_sServiceName )
           ->Advice (L"This P2PeerHub not yet running?" )
           ->Throw();

    // Overlapped notification
    // NOTES: Perfomed from m_pConThat->OnAccept()
    if ( m_pOVERLAPPEDconnect == NULL )
      m_pOVERLAPPEDconnect = MakeOVERLAPPED ( 0 );

    // Tidy up and
    return true;
}

void
P2PeerConDmx::Close  ( )
{
    // Primary resource recovery
    // NOTES: P2PeerConDmx's are a little different and need to be
    //        tidied up before delegation to the base class
    //      : Remember "m_hFileCPort" is actually a pointer to the other
    //        P2PeerConDmx object
    //      : Activity requires isolation
    if ( m_pConThat )                  // Scoping CriticalSection 
    {
      P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;
      if ( m_pConThat )
      {
        // Notify the other side
        // NOTES: Mirror OnClose() - waking the paired connection is mandatory,
        //        otherwise Close() leaves it detached (back-pointer cleared) but
        //        with its outstanding overlapped recv still pending, so it never
        //        learns the partner is gone.
        //      : pConThat->Drop(0) completes that recv with
        //        ERROR_OPERATION_ABORTED, routing the peer through its own close
        //        handling (see P2PeerConDmx::Drop).
        //      : m_pConThat / the peer back-pointer are cleared BEFORE the nested
        //        Drop so it cannot recurse back into this object.
        //        g_oCSectP2PeerConDmx is a reentrant CRITICAL_SECTION, so the
        //        nested re-acquire in Drop() is safe (same pattern as OnClose()).
        P2PeerConDmx *pConThat = m_pConThat;
                                 m_pConThat   = 0;
                                 m_hFile      = 0;   // P2PeerCon attribute
                                 m_hFileCPort = 0;   // P2PeerCon attribute
        if ( pConThat                     &&
             pConThat->m_pConThat == this    )
        {
          pConThat -> m_pConThat   = 0;
          pConThat -> m_hFile      = 0;
          pConThat -> m_hFileCPort = 0;
          pConThat -> Drop ( 0 );
        }
      }
    }

    // Always delegate
    P2PeerCon::OnClose();
}

//
//  Description: Close connection
//               NOTES: Closed connections may be Restart()'ed
//                    : Usually performed in the ON_P2PeerCon_CLOSE()
//                      handler
//
//
//  Returns:     BOOL
//               Close object status
//
BOOL
P2PeerConDmx::OnClose ( )
{
    // Firstly tidy up other end
    // NOTES: Cancels all outstanding overlapped IO
    if ( m_pConThat )
    {
      P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;
      P2PeerConDmx *pConThat = m_pConThat;
                               m_pConThat   = 0;
                               m_hFile      = 0;
                               m_hFileCPort = 0;
      if ( pConThat                     &&
           pConThat->m_pConThat == this    )
      {
        pConThat -> m_pConThat   = 0;
        pConThat -> m_hFile      = 0;
        pConThat -> m_hFileCPort = 0;
        pConThat -> Drop ( 0 );
      }
    }

    // Always delegate
    return P2PeerCon::OnClose();
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerConDmx::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}

P3PmsgItem
P2PeerConDmx::Serialise ( LPCTNAM lpszVar )
{
    // Locals
    bool bDsc = true;

    // Create a placeholder for receipt of P2PeerConDmx details
    // NOTES: This will be passed by value back up the stack
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData(m_nP2PconID)) );
    if ( lpszVar == 0 || _tcslen(lpszVar) <= 0 )
      (P3PmsgField&)oNodeVar = P3PmsgName ( L"{P2PeerConDmx}" );
    else
      oNodeVar.r_data() = P3PmsgData ( L"{P2PeerConDmx}" );

    // Append our state to node
    P3PmsgField_SERIALISE ( oNodeVar, L"ServiceName", (LPCTSTR)m_sServiceName, bDsc
                          , L"Allocated connection address" );

    // Tidy up and
    oNodeVar += P2PeerCon::Serialise ( 0 );
    return oNodeVar;
}

///////////////////////////////////////////////////////////////////////
//  Properties

DWORD_PTR
P2PeerConDmx::GetUDState ( )
{
    // Under the lock every writer of m_pConThat holds - Connect(),
    // AcceptSpawn(), Drop() and the accept refusal.  This is read from the
    // io layer on the pump and by harnesses from other threads, and since
    // 2026-09-22 a departed peer's Drop() clears it on the PEER'S pump while
    // the owner may be looking; TSan reported exactly that pair on
    // p2p_dmxdead the first run it saw the fix
    P2PsafeCS oSafeCS = g_oCSectP2PeerConDmx;
    return (DWORD_PTR)m_pConThat;
}
