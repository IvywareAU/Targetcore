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
//  Description: P2PeerCon base class implementation
//               NOTES: Manages connections between P2PeerHub's
//

#include "stdafx.h"
#include "Kernel32_Ext.h"
#include "P2PeerCon.h"
#include "P2PeerHub.h"
#include "P2Pwin32.h"
#include "P2PCngCrypto.h"      // ephemeral ECDH P-256, HKDF-SHA256
#include "P2PeerioGcm.h"       // the session cypher installed on agreement

#include <map>                 // P2PeerConSourceTally

///////////////////////////////////////////////////////////////////////
//  Per-source accept accounting (Stage 4 step 11)
//  NOTES: One block per SERVICE, shared with every connection it accepts, for
//         the same reason m_pxAccepted is shared: neither the service nor a
//         child has to outlive the other, and a back-pointer to the service
//         would dangle whenever a child survives a hub teardown
//       : A map rather than a counter, because the question is per KEY, and a
//         lock rather than an atomic, because the read-decide-insert on admit
//         and the decrement-erase on release are each more than one operation.
//         The section is this block's own and is held for the length of a map
//         operation, so it contends with nothing but other accepts on the same
//         service
//       : Entries are ERASED at zero rather than left at zero.  A source that
//         connects once and goes must not cost the service a map entry
//         forever - that is the same unbounded growth the accept cap exists to
//         stop, moved one level down and made permanent
struct P2PeerConSourceTally
{
    CRITICAL_SECTION              m_oCSection;
    std::map<P2PsourceKey,long>   m_oCounts;

    P2PeerConSourceTally  ( ) { InitializeCriticalSection ( &m_oCSection ); }
    ~P2PeerConSourceTally ( ) { DeleteCriticalSection     ( &m_oCSection ); }

    long
      Count ( P2PsourceKey xSource ) const
      {
        if ( !xSource ) return 0;
        P2PsafeCS oSafeCS = const_cast<CRITICAL_SECTION&>(m_oCSection);
        std::map<P2PsourceKey,long>::const_iterator it = m_oCounts.find ( xSource );
        return it == m_oCounts.end ( ) ? 0 : it->second;
      }
    void
      Add ( P2PsourceKey xSource )
      {
        if ( !xSource ) return;
        P2PsafeCS oSafeCS = m_oCSection;
        m_oCounts[xSource] += 1;
      }
    void
      Sub ( P2PsourceKey xSource )
      {
        if ( !xSource ) return;
        P2PsafeCS oSafeCS = m_oCSection;
        std::map<P2PsourceKey,long>::iterator it = m_oCounts.find ( xSource );
        if ( it == m_oCounts.end ( ) )
          return;                      // never counted; nothing to give back
        if ( --it->second <= 0 )
          m_oCounts.erase ( it );
      }
};

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor
IMPLEMENT_DYNCREATE(P2PeerCon,P2PeerConPlc)

constexpr __time64_t
iLoginTimeoutSeconds = 20;             // Login sequences must be
                                       //   processed within this time

P2PeerCon::P2PeerCon ( )
{
    // Firstly
    RenderThisSafe ( );
}

//
//  Parameters: P2PaddrSTR strThatP2Paddr
//              Identification address for that, or the other end
//
P2PeerCon::P2PeerCon ( P2PaddrSTR pThatP2PaddrSTR
                     , P2Peerio *pP2Peerio )
{
    // Firstly
    RenderThisSafe ( );
    m_oP2Padomain    = pThatP2PaddrSTR;
    //m_oThisP2Paddr   = pThisP2PaddrSTR;
    m_oThatP2Paddr   = pThatP2PaddrSTR;
    if ( !pP2Peerio )
      pP2Peerio = new P2Peerio ( );
    m_pP2Peerio = pP2Peerio -> Register ( this );
}

P2PeerCon::P2PeerCon ( P2Peerio *pP2Peerio )
{
    // Firstly
    RenderThisSafe ( );
    //m_oThisP2Paddr = pThisP2PaddrSTR;
    //m_oThatP2Paddr = pThisP2PaddrSTR;
    if ( !pP2Peerio )
      pP2Peerio = new P2Peerio ( );
    m_pP2Peerio = pP2Peerio -> Register ( this );
}

P2PeerCon::~P2PeerCon ( )
{
    // Timers
    // NOTES: Target specific timers. Others handled in derived class
    //      : Swallowed, because this is a DESTRUCTOR and an exception leaving
    //        one is std::terminate. CancelP2PmsgTimer no longer throws on the
    //        fired-already race (P2Pwin32.cpp) which is what used to reach
    //        here, but a destructor is the wrong place to depend on that
    //        holding - and a timer that cannot be cancelled is not a reason to
    //        take the process down either way
    try
    {
      CancelP2PmsgTimer ( m_uRestartTimerID );
      CancelP2PmsgTimer ( m_uLoginTimerID );
      CancelP2PmsgTimer ( m_uThrottleTimerID );
    }
    catch ( P2Pevent *pEVT ) { if ( pEVT ) pEVT->Cancel ( false ); }
    catch ( ... )            { }

    // Accept admission control
    // NOTES: Give the slot back. This is the ONLY release path, deliberately:
    //        a connection is counted for exactly as long as the object exists,
    //        so no close path, drop path or exception unwind can leak a slot by
    //        forgetting to call something.  The counter is shared rather than
    //        reached through the service, so it is still alive here even when
    //        the service was destroyed first
    if ( m_bAcceptCounted && m_pxAccepted )
    {
      m_pxAccepted -> fetch_sub ( 1 );
      m_bAcceptCounted = false;
    }
    //  Per-source slot, released on the same principle and in the same place:
    //  counted for exactly as long as the object exists, so no close path, drop
    //  path or exception unwind can leak one
    //  NOTES: m_xAcceptSource is non-zero exactly when a slot was taken, so it
    //         is both the flag and the key.  Cleared, so a double destruction
    //         would give back nothing rather than something
    if ( m_xAcceptSource && m_pxSourceTally )
    {
      m_pxSourceTally -> Sub ( m_xAcceptSource );
      m_xAcceptSource = 0;
    }

    // P2PeerMsg queue
    // NOTES: D39.  The message HANDED TO THE WIRE is not on the queue - the
    //        send path takes it off with GetP2PeerMsg() and parks it in
    //        m_pP2PeerMsgSend until the send completion returns, and only
    //        then releases it.  FlushP2PeerMsg() cannot see it, so a
    //        connection destroyed with a send still outstanding lost the
    //        only pointer to that message and leaked the whole P2PeerMsg
    //        graph - which is why LSan reported it with NO live root.
    //      : OnClose() drains BOTH (it reports each as undeliverable), so
    //        this is only reachable when the object is destroyed without
    //        its ON_P2PeerCon_CLOSE handler running - a hub torn down with
    //        a message in flight.
    //      : Released the way OnClose() releases it, by plain delete: the
    //        message was never confirmed sent, so P2Peerio's
    //        PreDestroySendP2PeerMsg() reuse hook - which is for messages
    //        that WERE sent - does not apply.
    delete m_pP2PeerMsgSend;
           m_pP2PeerMsgSend = 0;
    FlushP2PeerMsg ( );
    DeleteCriticalSection ( &m_oCSectMsgQue );

    // Resources
    Drop ( 0 );

    // OVERLAPPED resources
    // NOTES: Reclaimed previously, to be sure, to be sure.
    DropOVERLAPPED ( m_pOVERLAPPEDsend,    false );
    DropOVERLAPPED ( m_pOVERLAPPEDrecv,    false );
    DropOVERLAPPED ( m_pOVERLAPPEDaccept,  false );
    DropOVERLAPPED ( m_pOVERLAPPEDconnect, false );

    // Session key agreement
    // NOTES: The deferred login payload is application data that never
    //        reached the wire (the connection dropped mid-exchange), so it is
    //        released here rather than leaked
    delete (p2pcng::EcdhP256 *)m_pKeyX;
    m_pKeyX = 0;
    delete [] m_pLoginDefer;
    m_pLoginDefer = 0;
    SecureZeroMemory ( m_KeyXBind, sizeof(m_KeyXBind) );

    // Garbage collection
    //delete m_pP2PeerMsgQue;
    delete m_pP2Peerio;
    if ( m_pEvent )
      m_pEvent -> Cancel ( false );
    delete m_pstrVisualSummary;
}

void
P2PeerCon::RenderThisSafe ( )
{
    // Publics
    m_uAutoRestart       = 20000;      // Autorestart delay in MSecs

    // Resources
    m_hP2PmsgCon         = NULL;
    m_hCPort             = NULL;
    m_hFile              = NULL;
    m_hFileCPort         = NULL;
    m_dwCompletionKey    = (UINT_PTR)this;
    m_hCPortP2PumpID     = 0;
    m_pP2PeerTarget      = 0;
    m_pP2Peerio          = 0;
    m_pstrVisualSummary  = 0;

    // Transport trust class - the operator's ceiling only.  The transport's
    // own answer is a virtual and has nothing to initialise here; this is the
    // demotion, and the top of the enum means "not demoted"
    m_eTrustCeiling      = P2PeerConTrust_InProcess;

    // Peer login authentication
    // NOTES: Per-connection runtime state, not configuration. Refer
    //        P2PeerCon.h and P2PAuthLogin.h
    memset ( m_AuthNonce, 0, sizeof(m_AuthNonce) );
    m_bAuthNonce         = false;
    m_cbAuthStrip        = 0;
    m_oAuthPeer          = P2Paddr ( );

    // Session key agreement
    m_pKeyX              = 0;
    memset ( m_KeyXPubThis, 0, sizeof(m_KeyXPubThis) );
    memset ( m_KeyXPubThat, 0, sizeof(m_KeyXPubThat) );
    memset ( m_KeyXBind,    0, sizeof(m_KeyXBind)    );
    m_bKeyXBound         = false;
    m_bKeyXDone          = false;
    m_bKeyXClient        = false;
    m_pLoginDefer        = 0;
    m_cbLoginDefer       = 0;
    m_bLoginDefer        = false;

    // Timers
    m_uRestartTimerID    = 0;
    m_uLoginTimerID      = 0;
    m_uThrottleTimerID   = 0;
    m_bRecvThrottled     = false;
    m_cRecvThrottled     = 0;

    // Accept admission control
    // NOTES: The counter is NOT allocated here. It is allocated by the first
    //        AcceptSpawn() off a SERVICE and shared with every child from
    //        there, so a client - which never accepts anything - carries a
    //        null pointer and no control block
    m_xMaxAccepted       = DEF_P2PeerConAccept;
    m_xLoginDeadline     = DEF_P2PeerConLogin;
    m_bAcceptCounted     = false;
    //  Per-source, and the same rule: the tally is allocated by the first
    //  AcceptSpawn() off a SERVICE, not here
    m_xMaxAcceptedPerSource = DEF_P2PeerConAcceptSource;
    m_xAcceptSource         = 0;

    // Overlapped IO 
    m_pP2PeerMsgSend     = 0;
    //m_bP2PeerMsgHdr      = true;

    // Overlapped IO buffers
    m_pOVERLAPPEDsend    = 0;
    m_pOVERLAPPEDrecv    = 0;
    m_pOVERLAPPEDaccept  = 0;
    m_pOVERLAPPEDconnect = 0;

    // Queues
    //m_pP2PeerMsgQue  = new P2PeerMsgQue ( 0 );
    InitializeCriticalSection ( &m_oCSectMsgQue );

    // Addressing
    m_eP2PeerIDmap   = P2PeerIDmap_NONE;
    //m_oThisP2Paddr  = 0; m_nThisP2PeerID1 = 0;
    //m_oThatP2Paddr  = 0; m_nThatP2PeerID1 = 0;

    // Control 
    m_dwState        = 0;
    m_eP2PeerConMode = P2PeerCon_Unknown;
    m_pEvent         = 0;
}

P2PeerCon*
P2PeerCon::AcceptSpawn ( P2PeerCon *pConSpawn )
{
    // Accept
    // NOTES: Mandatory P2PeerConPlc integration
    if (  pConSpawn          != this &&
         !pConSpawn->m_hP2PmsgCon       )
         //pConSpawn->m_pPrev ==   0  &&
         //pConSpawn->m_pNext ==   0     )
    {
      //*this += pConSpawn;
      pConSpawn -> m_pP2PeerTarget = m_pP2PeerTarget;
      PostP2PmsgCon ( GetP2PmsgHubID(/*this*/), pConSpawn );
    }

    // Settlement
    if ( pConSpawn != this )
    {
           pConSpawn -> m_hCPortP2PumpID  = m_hCPortP2PumpID;
           pConSpawn -> m_hCPort          = m_hCPort;
    delete pConSpawn -> m_pP2Peerio;
           pConSpawn -> m_pP2Peerio       = m_pP2Peerio -> Clone();
           pConSpawn -> m_pP2Peerio -> Register ( pConSpawn );
           //pConSpawn -> m_oThisP2Paddr    = m_oThisP2Paddr;
           pConSpawn -> m_oThisP2Paddr1   = L"";
           pConSpawn -> m_oThatP2Paddr    = m_oThatP2Paddr;
           pConSpawn -> m_oThatP2Paddr1   = L"";
           pConSpawn -> m_eP2PeerIDmap    = m_eP2PeerIDmap;
           pConSpawn -> m_eP2PeerConMode  =    P2PeerCon_Accept;
           pConSpawn -> m_oP2Padomain     = m_oP2Padomain;
      //  The trust CEILING, and it is the one line in the trust-class feature
      //  that this function can forget.
      //  NOTES: The CLASS is not here and cannot be - TrustClass() is a
      //         virtual, the child is the same class as the service, and that
      //         is the whole reason this feature is allowed to exist beside
      //         the hub-only rule in SECURITY.md
      //       : The DEMOTION is per-object state and has to be carried, or an
      //         operator who demoted a listener demoted only the object that
      //         never carries traffic.  Losing this line makes a child read
      //         the class its transport vouches for instead of the lower one
      //         the operator asked for - which is the direction that fails
      //         towards the transport's own honest answer rather than past it,
      //         and it is pinned by a gate-test phase rather than left to that
           pConSpawn -> m_eTrustCeiling   = m_eTrustCeiling;
           pConSpawn -> m_dwState
                       = m_dwState & ~( ConState_Recv
                                      | ConState_Send
                                      | ConState_Login );

      // Accept admission control
      // NOTES: Accounting only. The REFUSAL is the transport's, and it has
      //        already happened by the time we are here - only the transport
      //        knows how to discard a half-accepted endpoint, and it has to do
      //        it before allocating the connection this is settling.  Refer
      //        P2PeerConWsa::AcceptSpawn()
      //      : Allocated lazily, on the first spawn, so a connection that never
      //        accepts anything carries no control block
      //      : The child inherits the login deadline and NOT the cap.  The cap
      //        belongs to whoever accepts; an accepted connection accepts
      //        nothing, and a cap sitting on it would be read by nobody
      if ( !m_pxAccepted )
             m_pxAccepted = std::make_shared<std::atomic<long>> ( 0 );
           pConSpawn -> m_pxAccepted      = m_pxAccepted;
           pConSpawn -> m_xMaxAccepted    = 0;
           pConSpawn -> m_xLoginDeadline  = m_xLoginDeadline;
           pConSpawn -> m_bAcceptCounted  = true;
           m_pxAccepted -> fetch_add ( 1 );

      //  Per-source, same shape and same moment
      //  NOTES: The key is asked of THIS - the service - and it must be asked
      //         HERE.  This is the last instant the half-accepted endpoint is
      //         still the service's; the transport hands it to the child on the
      //         next statement after this call returns, and afterwards nothing
      //         can name where it came from
      //       : Allocated lazily even when no bound is set, because the count
      //         is worth having either way - GetAcceptedCountFromSource() is
      //         what an operator asks when deciding what to set the bound TO
      //       : A zero key stores nothing.  m_xAcceptSource stays 0, the
      //         destructor gives nothing back, and no map entry is made for a
      //         transport that has no sources to distinguish
      if ( !m_pxSourceTally )
             m_pxSourceTally = std::make_shared<P2PeerConSourceTally> ( );
           pConSpawn -> m_pxSourceTally          = m_pxSourceTally;
           pConSpawn -> m_xMaxAcceptedPerSource  = 0;
           pConSpawn -> m_xAcceptSource          = AcceptSourceKey ( );
           m_pxSourceTally -> Add ( pConSpawn->m_xAcceptSource );
    }

    // Tidy up, and
    // NOTES:
    return pConSpawn;
}

///////////////////////////////////////////////////////////////////////
//  IOCP Integration
//

//
//  Associates connection object with IO Completion Port 
//  NOTES: Refer win32 CreateIoCompletionPort() for further details
//
//
//  Parameters:  HANDLE hFile
//               File for with IOCP instance is to be created
void
P2PeerCon::CreateIOCP ( HANDLE hFile )
{
    // To be sure, to be sure
    if ( ( m_hFile          &&
           m_hFile != hFile    ) ||
           m_hFileCPort             )
      EVERR->Module  (__FUNCTION__)
           ->AFP((UINT_PTR)hFile)->AFPcon(this)
           ->Message (_T("IOCP already created") )
           ->Advice  (_T("Incomplete reset or sequence bug") )
           ->HResult ( GetLastError() )->Throw();
    m_hFile = hFile;

    // IO completion port attachment
    // NOTES:
    m_hFileCPort = CreateIoCompletionPort ( m_hFile
                                          , m_hCPort
                                          , m_dwCompletionKey
                                          , 0 );
    if ( m_hFileCPort == 0 )
      EVERR->Module  (__FUNCTION__)
           ->AFPcon(this)
           ->Message (_T("CreateIoCompletionPort() failed") )
           ->HResult ( GetLastError() )->Throw();
}

//
//  Description: Processes I/O completion port packets mapped to and
//               instance of this object.
//               NOTES: Such packets are retieved via the Microsoft
//                      File Storage SDK - GetQueuedCompletionStatus()
//                      module.
//
//  Exceptions:  Notification will eventually be routed through to
//               ON_P2PeerCon_CLOSE() handler. At which point Restart()
//               may be used on non accepted sockets or this object
//               conDROP'ed
//            :  ON_P2PeerCon_CLOSE() handler to which this posted object
//               is routed MUST cancel the attached event.  OnClose()
//               contains such default processing.
//            :  P2P_Close notification MUST be performed once per
//               attached event. Subsequent P2P_Close notifications are
//               blocked until the original event is cancelled.
//
//
//  Parameters:  DWORD dwError
//               Number of bytes transferred during an I/O operation
//               that has completed.  Refer ::GetQueuedCompletionStatus
//               for further details.
//               
//               DWORD dbBytes
//               Number of bytes transferred during an I/O operation
//               that has completed.  Refer ::GetQueuedCompletionStatus
//               for further details.
//
//               OVERLAPPEDcon *pOVERLAPPEDcon
//               Address of OVERLAPPEDcon structure that was specified
//               for the I/O operation.
//
bool
P2PeerCon::On_QueuedCompletionStatus ( DWORD dwError
                                     , DWORD dwBytes
                                     , OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // Pre-processing
    HRESULT hr = dwError;
    if ( hr == S_OK )
      hr = pOVERLAPPEDcon -> hr;
ASSERT(pOVERLAPPEDcon->bQueued);
ASSERT(AfxIsValidAddress(pOVERLAPPEDcon, sizeof(OVERLAPPEDcon)));
    // Recv
    // NOTES: Default implementation.
    if ( pOVERLAPPEDcon == m_pOVERLAPPEDrecv )
    {
ASSERT(m_eP2PeerConMode!=P2PeerCon_SERVICE);
      //  F-S4-1 - ORDERLY CLOSE, and it is read here because this is the only
      //  point at which both halves of the question are in hand.
      //
      //  Two completely different things arrive at this branch as a SUCCESS
      //  carrying ZERO BYTES, and on Windows nothing else tells them apart:
      //
      //    - an ARMING post.  PostOVERLAPPED() and RearmRecv() do not issue a
      //      read; they PostQueuedCompletionStatus(.., 0, ..) so that the
      //      completion re-enters here and RecvP2PeerMsg() issues the actual
      //      read.  Accept() and OnConnect() start every connection this way
      //    - the peer's FIN.  A real ReadFile that completes with 0 bytes,
      //      which is the ONLY notification a stream socket gives of an
      //      orderly close
      //
      //  Treating the second as the first is the whole defect: the branch
      //  parsed no message, posted no further read and returned, so the
      //  connection was never dropped and never reaped.  On Windows both
      //  accept bounds then counted connections EVER ACCEPTED rather than
      //  connections currently held - SetMaxAccepted(1024) retiring a service
      //  permanently after 1024 connect-and-leave cycles, which makes the
      //  admission-control protection a slower version of the attack it
      //  exists to refuse - plus a slow leak of connection objects.
      //
      //  Treating the FIRST as the second is equally wrong and was measured
      //  before this was written: it dropped every connection at accept.
      //
      //  So the answer is a MARK SET AT SUBMISSION, cleared here on receipt -
      //  the same shape as OVERLAPPED::_p2p_key.  bRecvSubmitted is true only
      //  when P2Peerio::Recv actually put a read on the wire for this object.
      //  Read and clear it FIRST: the loop below re-enters RecvP2PeerMsg,
      //  which submits the next read and sets the mark again.
      //
      //  LINUX ALREADY DID THIS and that is why the defect was one-platform:
      //  the io_uring shim marks the op _p2p_op=P2POP_READ at submission and
      //  reports res==0 on a read as ERROR_HANDLE_EOF.  Synthesising the same
      //  code here is deliberate - it puts both platforms on the ONE existing
      //  failure path below rather than giving Windows a second close route
      //  with its own notification order to get wrong.
      bool bRecvCompleted             = pOVERLAPPEDcon->bRecvSubmitted;
      pOVERLAPPEDcon->bRecvSubmitted  = false;
      if ( hr        == S_OK &&
           dwBytes   == 0    &&
           bRecvCompleted    &&
           RecvZeroIsOrderlyClose ( ) )
        hr = ERROR_HANDLE_EOF;

      // Success
      // NOTES: Received buffer may contain several messages, in which
      //        case we process to completion.
      //      : Handle 3rdParty formats by overriding P2Peerio
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      if (   hr == S_OK &&
           m_hFileCPort    )
      {
        //  BACKPRESSURE, and it is expressed by NOT ASKING (Stage 4 step 12).
        //  RecvP2PeerMsg() is what issues the next Recv() on this connection,
        //  so declining to call it leaves no read outstanding: the socket
        //  buffer fills, the TCP window closes, and the peer is throttled by
        //  the transport rather than by an exception thrown at it. Nothing is
        //  discarded and nothing is refused - the bytes stay where they are
        //  until this connection asks again.
        //
        //  In the LOOP CONDITION rather than at the bottom of the body,
        //  because the budget can already be at its mark when this completion
        //  arrives - in which case the right number of messages to take off
        //  this peer is none, and a check at the bottom would take one first.
        //
        //  The resume is RearmRecv(), which posts m_pOVERLAPPEDrecv to arm a
        //  read rather than perform one and so re-enters here. It is NOT
        //  PostOVERLAPPED, and not for tidiness: refer RearmRecv for the
        //  guard that made the class's own P2PsigCon_RECV signal unusable on
        //  any connection that had ever received a message.
        P2PeerMsg *pMsg;
        pOVERLAPPEDcon -> dwBytes += dwBytes;
        while ( !HoldRecvForBackpressure ( )  &&
                (pMsg=m_pP2Peerio
                    ->RecvP2PeerMsg(m_hFile,pOVERLAPPEDcon)) != NULL )
        {
          // Interface mapping
          // NOTES: Mandatory
          if ( m_eP2PeerIDmap )
            PerformIFaddrTransform ( true, pMsg );

          // Special interceptions
          // NOTES: AuthGateInbound() proves the claimed identity BEFORE
          //        the message is posted, so a refusal drops the
          //        connection before OnLogin() can set ConState_Login -
          //        the state every later check keys off.  It is a no-op
          //        on a hub that does not require authentication.
          // Session key agreement.  Consumed here and never posted: the
          // exchange is library business, so it needs no signal, no pump-map
          // entry and no application handler.  Both arms delete the message
          // themselves because the pump never takes ownership of it.
          if ( pMsg->Map_MatchName(P2Pmsg_KeyX) )
          {
            try                    { KeyXOnRequest ( pMsg ); }
            catch ( ... )          { delete pMsg; throw; }
            delete pMsg;
            continue;
          }
          else if ( pMsg->Map_MatchName(P2Pmsg_KeyXAck) )
          {
            try                    { KeyXOnAck ( pMsg ); }
            catch ( ... )          { delete pMsg; throw; }
            delete pMsg;
            continue;
          }
          else if (  pMsg->Map_MatchName(P2Pmsg_Login) &&
                    !pMsg->GetSource()                    )
          {
            AuthGateInbound ( pMsg, false );
            PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Login
                       , this, pMsg, m_hCPortP2PumpID ); //was 0
          }
          else if ( pMsg->Map_MatchName(P2Pmsg_Login) &&
                    pMsg->GetSource()                       )
          {
            AuthGateInbound ( pMsg, false );
            PostP2Pmsg ( pMsg->GetSource(), CN_P2PeerCon, P2P_Login
                       , this, pMsg, m_hCPortP2PumpID ); //was 0
          }
          else if ( pMsg->Map_MatchName(P2Pmsg_LoginAck) )
          {
            AuthGateInbound ( pMsg, true );
            PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_LoginAck
                       , this, pMsg, m_hCPortP2PumpID ); // was 0
          }
        /*else if ( pMsg->GetDestin() == m_oThisP2Paddr &&
                    pMsg->Type() == MSG_P2PeerAck           )
            PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Ack
                        , this, pMsg )*/
          // Application message. Login / LoginAck are handled by the branches
          // above and the cipher-exchange (P2Pmsg_CypherEx) is intercepted in
          // the io layer and posted as a CN_P2PeerCon notification
          // (P2Peerio::DecryptP2PiomageSwap returns NULL for it), so none of
          // the handshake traffic reaches here.
          //
          // GateAppMsgInbound() enforces both admission rules - login
          // completed, and the declared source bound to the logged-in identity
          // (SECURITY_REVIEW M2) - and on refusal deletes the message and
          // throws, dropping the connection. It is shared with the
          // P2PsigCon_MSG injection path so the two routes cannot drift.
          else
          {
            GateAppMsgInbound ( pMsg );

            // W3 (p2p_PumpPerf.md): this recv completion already runs on the
            // destination pump thread, so dispatch the parsed application
            // message in place instead of round-tripping the pump's own FIFO -
            // but only when that is safe (local pump + empty FIFO, so ordering
            // is preserved).  Otherwise fall back to the FIFO exactly as before.
            if ( !TryInlineDispatchP2Pmsg ( pMsg->GetSource(), pMsg
                                          , m_hCPortP2PumpID ) )
              PostP2Pmsg ( pMsg->GetSource(), CN_P2PeerMsg, 0
                         ,(P2PeerCon *)0, pMsg, m_hCPortP2PumpID ); // was 0
          }
        }
      }

      // Failure
      // NOTES: Remote connection dropped out.  P2PeerMsg receipt for
      //        connection discontinued.
      //      : Perform On_P2PeerCon_CLOSE() notification.
      else if (   hr         &&
                m_hFileCPort    )
      {
        EVERR->Module  (__FUNCTION__)
             ->AFP(dwError)->AFP(dwBytes)->AFPcon(this)
             ->Message_T("Receive failure" )
             ->Advice_T ("Conection dropped out" )
             ->HResult( hr )->Throw();
      }

      // Cancellation
      // NOTES: IoCancel(m_hFileCPort), CloseHandle(m_hFileCPort) or
      //        whatever issued.  P2PeerMsg receipt for connection
      //        discontinued
      else
        m_pOVERLAPPEDrecv = DropOVERLAPPED ( pOVERLAPPEDcon );
    }

    // Send 
    // NOTES: Confirmation must be received before next P2PeerMsg
    //        transmission is attempted.
    else if ( pOVERLAPPEDcon == m_pOVERLAPPEDsend )
    {
ASSERT(m_eP2PeerConMode!=P2PeerCon_SERVICE);
      // Success
      // NOTES: Passed buffer contains details of previous message
      //        and return with details of next
      //      : Handle 3rdParty formats by overriding RecvP2PeerMsg()
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      if (   hr == S_OK &&
            m_hFileCPort    )
      {
        if ( m_pP2PeerMsgSend )
        {
          ((P2PeerMsgPrefix *)m_pP2PeerMsgSend->r_data().c_vBlob())
                             -> uiState &= ~P2PeerMsgState_Posted;
          delete m_pP2Peerio -> PreDestroySendP2PeerMsg ( m_pP2PeerMsgSend );
          m_pP2PeerMsgSend = 0;
        }
        // Fetch next message
        if ( m_pP2PeerMsgSend == NULL )
        {
          m_pP2PeerMsgSend = GetP2PeerMsg ( );
          // Interface mapping
          // NOTES: Mandatory
          if ( m_eP2PeerIDmap   &&
               m_pP2PeerMsgSend    )
            PerformIFaddrTransform ( false, m_pP2PeerMsgSend );

          // End-to-end seal
          // NOTES: FIRST of the two, and the order is load-bearing.  The
          //        attestation digests the BODY, and the receiver checks it in
          //        GateAppMsgInbound -> GateRelayInbound, which runs BEFORE
          //        OpenAppMsgInbound (:2708 then :2731).  So the bytes the far
          //        end verifies are the SEALED ones, and the signature has to
          //        be made over those - seal, then attest.
          //      : THIS USED TO RUN SECOND, and its own note argued for the
          //        order it did not implement: attesting first signs the
          //        plaintext, sealing then replaces the body, and the far end
          //        verifies a signature over something it no longer has.  The
          //        result was "signature does not verify" at the destination
          //        and a dropped link, on the DEFAULT policy.  It was invisible
          //        because nothing reached it - c_vBlob could not grow a
          //        payload, so no relayed message survived the seal at all
          //        (Msgcore/P2Pmsg.cpp:983).  p2p_sealbcast is the run.
          //      : It is also the better construction on its own merits.
          //        Signing the ciphertext is encrypt-then-sign, the same
          //        discipline p2pseal uses inside its own envelope, so a
          //        forgery is thrown out before any asymmetric work is done on
          //        attacker-chosen plaintext.
          //      : THE ONE HOOK ON THIS PATH THAT CAN REFUSE.  Everything else
          //        here reports and sends anyway; a seal that could not be made
          //        drops the message, because sending it would be sending in
          //        clear the thing the operator asked to be hidden.  Refusing
          //        before the attestation also saves an ECDSA operation on a
          //        message that is about to be dropped
          if ( m_pP2PeerMsgSend && !SealAppMsgOutbound ( m_pP2PeerMsgSend ) )
          {
            delete m_pP2PeerMsgSend;
            m_pP2PeerMsgSend = 0;
          }

          // Origin attestation
          // NOTES: AFTER the transform and after the seal, so what is signed is
          //        what goes on the wire.  This is the single funnel every
          //        outbound P2PeerMsg passes through, which is why it is here
          //        rather than in PostP2PeerMsg - the queue is entered from
          //        application threads and left from exactly one
          //      : Does nothing at all unless the hub requires attestation.
          //        Refer AttestAppMsgOutbound
          if ( m_pP2PeerMsgSend )
            AttestAppMsgOutbound ( m_pP2PeerMsgSend );
         }

        // May become idle here
        if ( m_pP2PeerMsgSend )
          m_pP2Peerio -> SendP2PeerMsg ( m_hFile, m_pP2PeerMsgSend
                                       , pOVERLAPPEDcon );
        else if ( (m_dwState&ConState_CloseOnIdle) == ConState_CloseOnIdle )
          Drop ( 0 );
      }

      // Failure
      // NOTES: Remote connection dropped out.  P2PeerMsg transmission
      //        for connection discontinued.
      //      : Perform On_P2PeerCon_CLOSE() notification.
      else if (   hr         &&
                m_hFileCPort    )
        EVERR->Module (__FUNCTION__)
             ->AFP(dwError)->AFP(dwBytes)->AFPcon(this)
             ->Message_T("Send failed")
             ->Advice_T("Connection dropped out" )
             ->HResult( hr )->Throw();

      // Cancellation
      // NOTES: IoCancel(m_hFileCPort), CloseHandle(m_hFileCPort) or
      //        whatever issued.  P2PeerMsg transmission for connection
      //        discontinued
      else
        m_pOVERLAPPEDsend = DropOVERLAPPED ( pOVERLAPPEDcon );
    }

    // Accept
    // NOTES: Perform On_P2PeerCon_ACCEPT() notification.  At which
    //        point the intercepting handler will initiate state
    //        changes.
    //      : Perform On_P2PeerCon_LISTEN() notification.  At which
    //        point the intercepting handler will listen for another
    //        connection
    else if ( pOVERLAPPEDcon == m_pOVERLAPPEDaccept )
    {
ASSERT(m_eP2PeerConMode==P2PeerCon_SERVICE);
      // Success
      // NOTES: Honour expectation that the On_P2PeerCon_ACCEPT()
      //        processed before the ON_P2PeerCon_LISTEN()
      //        notification
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      if (   hr == S_OK &&
           m_hFileCPort    )
      {
        // Split into listening, usually this, and accepted P2PeerCon
        // NOTES: The underlying P2PeerCon objects have different styles
        //        according to the derived type.
        //P2PeerCon *pConAccept = 0, *pConListen = 0;
        //AcceptSplit ( &pConListen, &pConAccept );

        // Perform ON_P2PeerOLD_ACCEPT() notification
        // NOTES: Accepted P2PeerCon is spawned within the handler
        //if ( pConAccept == 0 && pConListen == 0 )
        PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Accept
                   , this, 0, m_hCPortP2PumpID );

        // ON_P2PeerOLD_ACCEPT() notification
        // NOTES: Spawn accepted connection
        //if ( pConAccept )
        //PostP2Pmsg ( pConAccept->m_oThatP2Paddr, CN_P2PeerCon, P2P_Accept
        //           , pConAccept, 0 );

        // ON_P2PeerCon_LISTEN() notification
        // NOTES: Listen for new connection, or stop listening etc
        //if ( pConListen )
        //{
        //P2PaddrSTR strThatP2Paddr = pConListen->m_oThatP2Paddr;
        //PostP2Pmsg ( pConListen->m_oThatP2Paddr.IsNull()
        //                 ?pConListen->m_oThatP2Paddr
        //                 :pConListen->m_oThisP2Paddr
        //PostP2Pmsg ( (strThatP2Paddr&1)==0?pConListen->m_oThisP2Paddr
        //                                  :pConListen->m_oThatP2Paddr
        //           , CN_P2PeerCon, P2P_Listen, pConListen, 0 );
        //}
      }

      // Failure
      // NOTES: Accepted connection failure
      else if (   hr         &&
                m_hFileCPort    )
        EVERR->Module (__FUNCTION__)
             ->AFP(dwError)->AFP(dwBytes)->AFPcon(this)
             ->Message(_T("Overlapped accept failed"))
             ->HResult( hr ) -> Throw();

      // Cancellation
      // NOTES: IoCancel(m_hFileCPort), CloseHandle(m_hFileCPort) or
      //        whatever issued.  Acceptance discontinued 
      else
        m_pOVERLAPPEDaccept = DropOVERLAPPED ( pOVERLAPPEDcon );
    }

    // Connect
    // NOTES: Perform On_P2PeerCon_CONNECT() notification.  At which
    //        point the intercepting handler will initiate the
    //        appropriate state changes.
    else if ( pOVERLAPPEDcon == m_pOVERLAPPEDconnect )
    {
ASSERT(m_eP2PeerConMode!=P2PeerCon_SERVICE);
      // Success
      // NOTES: OVERLAPPEDsend and OVERLAPPEDrecv buffer creation
      //        triggers IO Completion port scheduling immediately
      //        after the object has been routed through the
      //        P2PeerCon_MAP.
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      if (   hr == S_OK &&
            m_hFileCPort    )
      {
        if ( m_pOVERLAPPEDsend == NULL )
          m_pOVERLAPPEDsend = MakeOVERLAPPED ( );
        if ( m_pOVERLAPPEDrecv == NULL )
          m_pOVERLAPPEDrecv = MakeOVERLAPPED ( m_pP2Peerio->GetMaxRecvSize() );

        // Perform On_P2PeerCon_CONNECT notification
        PostP2Pmsg  ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Connect
                    , this, (P2PeerMsg *)0, m_hCPortP2PumpID );
      }

      // Failure
      // NOTES: Connection failed to complete
      //      : Perform On_P2PeerCon_CLOSE() notification.
      else if (   hr         &&
                m_hFileCPort    )
      {
        EVERR->Module (__FUNCTION__)
             ->AFP(dwError)->AFP(dwBytes)->AFPcon(this)
             ->Message(_T("Remote connection request failed") )
             ->Advice (_T("Remote server not running") )
             ->Advice (_T("Firewall configuration") )
                           /*"\t: Invalid connection address [%s]\n"
                             "\t: Invalid connection port [%i]"
                      , m_oCSIpAddress
                      , m_nIpPort*/
             ->HResult( hr )->Throw();
      }

      // Cancellation
      // NOTES: IoCancel(m_hFileCPort), CloseHandle(m_hFileCPort) or
      //        whatever issued.
      else
        m_pOVERLAPPEDconnect = DropOVERLAPPED ( pOVERLAPPEDcon );
    }

    // P2Psignal_MSG
    // NOTES: Injects P2PeerMsg into P2PeerCon object.  Primarily
    //        used to emulate 3rdParty and legacy interfaces from
    //        P2Peerio derived objects
    else if ( pOVERLAPPEDcon->nSigID == P2PsigCon_MSG )
    {
ASSERT(m_eP2PeerConMode!=P2PeerCon_SERVICE);
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      //INT_PTR whatever = *(INT_PTR*)(pOVERLAPPEDcon->pBuffer);
      P2PeerMsg *pMsg  =  (P2PeerMsg *)*(INT_PTR*)(pOVERLAPPEDcon->pBuffer); 
      pOVERLAPPEDcon   = DropOVERLAPPED ( pOVERLAPPEDcon, false );
ASSERT(m_pOVERLAPPEDrecv);
      // Special interceptions
      // NOTES: The injected path gets the same gate as the socket path.
      //        A check on one route only is a check with a way around it,
      //        and this route is how the 3rdParty and legacy transports
      //        deliver a login.
      //      : That claim used to cover the login only - an APPLICATION
      //        message injected here was posted with neither the
      //        ConState_Login test nor the source binding the socket path
      //        applies, which is precisely the hole SECURITY_REVIEW M2
      //        describes.  Unreachable today (P2PsigCon_MSG has no producer
      //        anywhere in the tree - it is the emulation seam a 3rdParty
      //        P2Peerio would post through), so this is hardening a route
      //        before it carries traffic, not fixing a live defect.  It does
      //        mean an out-of-tree transport that injects application
      //        messages without completing a login will now be refused -
      //        which is the correct default, and the reason to land it while
      //        the seam is still unused
      if ( pMsg->Map_MatchName(P2Pmsg_Login) )
      {
        AuthGateInbound ( pMsg, false );
        PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Login
                   , this, pMsg, m_hCPortP2PumpID );
      }
      else if ( pMsg->Map_MatchName(P2Pmsg_LoginAck) )
      {
        AuthGateInbound ( pMsg, true );
        PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_LoginAck
                   , this, pMsg, m_hCPortP2PumpID );
      }
      else
      {
        GateAppMsgInbound ( pMsg );
        PostP2Pmsg ( pMsg->GetSource(), CN_P2PeerMsg, 0
                   ,(P2PeerCon *)0, pMsg, m_hCPortP2PumpID );
      }
    }

    // P2PsigID_CLOSE
    // NOTES: Perform On_P2PeerCon_CLOSE() notification.  At which
    //        point the intercepting handler will manage state
    //        changes.
    else if ( pOVERLAPPEDcon->nSigID == P2PsigCon_CLOSE )
    {
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      pOVERLAPPEDcon = DropOVERLAPPED ( pOVERLAPPEDcon, false );
      Drop ( 0 );
    }

    // P2PsigID_CLOSEONIDLE
    // NOTES: Perform On_P2PeerCon_CLOSE() notification.  At which
    //        point the intercepting handler will manage state
    //        changes.
    else if ( pOVERLAPPEDcon->nSigID == P2PsigCon_CLOSEONIDLE )
    {
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      pOVERLAPPEDcon = DropOVERLAPPED ( pOVERLAPPEDcon, false );
      m_dwState |= ConState_CloseOnIdle;
      if ( m_pP2PeerMsgSend == 0 )
        Drop ( 0 );
    }

    // P2PsigID_WAKEUP
    // NOTES: Exact inverse of P2PsigCon_CLOSEONIDLE - clears the latched bit
    //        so a connection that was marked by PauseHub but has not yet gone
    //        idle stays up.  It does NOT revive a connection the pause already
    //        dropped, and is not meant to.
    //      : A dropped connection DOES still receive this signal.  Drop() does
    //        not take the object off the hub's m_oCListP2PmsgCon - it closes
    //        m_hFile, clears m_hFileCPort and posts P2P_Close - so ConSignal
    //        still walks it and Signal() still posts here through m_hCPort,
    //        which the hub owns and which stays valid.  Harmless: Drop() has
    //        already cleared this bit through SetState(0,ON_ConClose), so the
    //        clear is a no-op and nothing here reopens anything.  PauseHub
    //        reaches dropped connections by the same route with the opposite
    //        signal, so this is the established pattern rather than a new one.
    //      : m_dwState is written from the IOCP thread that owns this
    //        connection, which is why the bit is cleared here rather than by
    //        the hub thread reaching into the object.
    else if ( pOVERLAPPEDcon->nSigID == P2PsigCon_WAKEUP )
    {
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      pOVERLAPPEDcon = DropOVERLAPPED ( pOVERLAPPEDcon, false );
      m_dwState &= ~ConState_CloseOnIdle;
    }

    // P2PsigID_SHUTDOWN
    // NOTES: Perform On_P2PeerCon_DESTROY() notification.  At which
    //        point the intercepting handler will initiate state
    //        changes.
    else if ( pOVERLAPPEDcon->nSigID == P2PsigCon_SHUTDOWN )
    {
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      pOVERLAPPEDcon = DropOVERLAPPED ( pOVERLAPPEDcon, false );
      this -> Destroy ( );
      PostP2Pmsg ( m_oThatP2Paddr
                 , CN_P2PeerCon, m_hFile ? P2P_Close : P2P_Shutdown
                 , this, (P2PeerMsg *)0, m_hCPortP2PumpID  );
    }

    // P2PsigID_DESTROY
    // NOTES: Perform On_P2PeerCon_DESTROY() notification.  At which
    //        point the intercepting handler will initiate state
    //        changes.
    else if ( pOVERLAPPEDcon->nSigID == P2PsigCon_DESTROY )
    {
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      pOVERLAPPEDcon = DropOVERLAPPED ( pOVERLAPPEDcon, false );
      this -> Destroy ( );
      PostP2Pmsg ( m_oThatP2Paddr
                 , CN_P2PeerCon, m_hFile ? P2P_Close : P2P_Shutdown
                 , this, (P2PeerMsg *)0, m_hCPortP2PumpID  );
      //Drop ( 0 );
      //Destroy ( );
    }

    // Command
    // NOTES: Last resort P2Peerio delegation
    else if ( pOVERLAPPEDcon )
    {
      if ( !m_pP2Peerio      ||
           !m_pP2Peerio        
                -> On_QueuedCompletionStatus ( dwError
                                             , dwBytes
                                             ,  pOVERLAPPEDcon) )
      {
        releaseOVERLAPPED( pOVERLAPPEDcon );
        pOVERLAPPEDcon = DropOVERLAPPED   ( pOVERLAPPEDcon );
        EVERR->Module   (__FUNCTION__)
             ->AFP(dwError)->AFP(dwBytes)->AFPcon(this)
             ->Message_T( "Unhandled OVERLAPPEDcon object" )
             ->Advice_T ( "Bug (SNHappen)" )
             ->HResult( hr )->Throw();
      }
    }

    // Tidy up and
    return true;
}

//
//  Allocate and optionally size OVERLAPPEDcon object
//  NOTES: Refer complimentary DropOVERLAPPED() method for recovery
//         of allocated resources
//
//
//  Parameters:  DWORD dwBytesMax = 0
//               Allocated OVERLAPPEDcon.pBuffer size
//
//
//  Returns:     OVERLAPPEDcon*
//               Allocated and optionally size buffer
//
OVERLAPPEDcon*
P2PeerCon::MakeOVERLAPPED ( DWORD dwBytesMax )
{
    // Allocation
    OVERLAPPEDcon *pOVERLAPPEDcon = new OVERLAPPEDcon;
    ZeroMemory ( pOVERLAPPEDcon, sizeof(OVERLAPPEDcon) );
    pOVERLAPPEDcon -> pOwnerCon = this;   // stable owner for keyless teardown attribution

    // Buffers
    if ( dwBytesMax )
      pOVERLAPPEDcon -> pBuffer = new char [dwBytesMax];
    pOVERLAPPEDcon -> dwBytesMax = dwBytesMax;

    // Tidy up, and
    return pOVERLAPPEDcon;
}

//
//  Drops OVERLAPPEDcon object
//  NOTES: Cross-references against and sets to NULL OVERLAPPEDcon
//         class pointers
//       : Refer complimentary MakeOVERLAPPED() method for initial
//         allocation of resources
//
//
//  Parameters:  OVERLAPPEDcon *pOVERLAPPEDcon
//               Object to be dropped
//
//               bool bNotify = true
//               Perform appropriate P2PeerCon_MAP notifications
//
OVERLAPPEDcon*
P2PeerCon::DropOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon
                          , bool /*bNotify*/ )
{
    // To be sure, to be sure
ASSERT(AfxCheckMemory());
    if ( pOVERLAPPEDcon == NULL )
      return 0;

    // OVERLAPPEDsend
    if ( pOVERLAPPEDcon == m_pOVERLAPPEDsend )
      m_pOVERLAPPEDsend = 0;

    // OVERLAPPEDrecv
    else if ( pOVERLAPPEDcon == m_pOVERLAPPEDrecv )
      m_pOVERLAPPEDrecv = 0;

    // OVERLAPPEDconnect
    else if ( pOVERLAPPEDcon == m_pOVERLAPPEDconnect )
      m_pOVERLAPPEDconnect = 0;

    // OVERLAPPEDaccept
    else if ( pOVERLAPPEDcon == m_pOVERLAPPEDaccept )
      m_pOVERLAPPEDaccept = 0;

    // Garbage collection
    if ( pOVERLAPPEDcon->pUserDB1 == pOVERLAPPEDcon->pBuffer )
      pOVERLAPPEDcon->pBuffer = 0;
    delete [] pOVERLAPPEDcon->pUserDB1;
    if ( pOVERLAPPEDcon->pUserDB2 == pOVERLAPPEDcon->pBuffer )
      pOVERLAPPEDcon->pBuffer = 0;
    delete [] pOVERLAPPEDcon->pUserDB2;
    // NOTES: dwBytesMax IS the ownership flag, so this test is correct and
    //        must NOT become a test on pBuffer.  MakeOVERLAPPED() sets the
    //        two together, and P2PeerioDmx sets dwBytesMax = 0 precisely
    //        because its pBuffer points at the message's own P2Piomage -
    //        deleting on a non-null pBuffer would free foreign storage,
    //        and with the wrong allocator
    if ( pOVERLAPPEDcon->dwBytesMax > 0 )
      delete [] pOVERLAPPEDcon->pBuffer;
    delete    pOVERLAPPEDcon;
ASSERT(AfxCheckMemory());
    return     nullptr;
}

//
//  Posts passed OVERLAPPEDcon object to associated IOCP
//
//
//  Parameters:  OVERLAPPEDcon *pOVERLAPPEDcon
//               Object to be posted
void
P2PeerCon::PostOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // Contract: the buffer must NOT already be in-flight.  A still-queued
    // buffer at this point is a double-post bug upstream, not a timing race:
    // fail loudly instead of papering over it.  (Was a Sleep(500) "timing
    // hack" that busy-waited then force-cleared bQueued, which stomped the
    // still-live completion and could not compile out in Release.)
    ASSERT(!pOVERLAPPEDcon->bQueued);
    if ( pOVERLAPPEDcon->bQueued )
      EVERR->Module  (__FUNCTION__)
           ->AFPcon(this)
           ->Message_T ("Passed OVERLAPPEDcon buffer locked" )
           ->Throw();

    // To be sure, to be sure
    if (  pOVERLAPPEDcon->dwBytesMax > 0 &&
         !pOVERLAPPEDcon->pBuffer           ) 
      EVERR->Module  (__FUNCTION__)
           ->AFPcon(this)
           ->Message_T("Corrupted OVERLAPPEDcon configuration" )
           ->Advice_T ("Bug(SNHappen)")
           ->Throw();
            
    // Implementation
    prepareOVERLAPPED ( pOVERLAPPEDcon );
if(pOVERLAPPEDcon!=m_pOVERLAPPEDsend&&
   pOVERLAPPEDcon!=m_pOVERLAPPEDrecv&&
   pOVERLAPPEDcon!=m_pOVERLAPPEDaccept&&
   pOVERLAPPEDcon!=m_pOVERLAPPEDconnect)
   pOVERLAPPEDcon=pOVERLAPPEDcon;
    if ( !PostQueuedCompletionStatus( m_hCPort // was m_hFileCPort changed for P2PeerConDmx
                                    , 0
                                    , m_dwCompletionKey 
                                    ,(OVERLAPPED *)pOVERLAPPEDcon) )
    {
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      EVERR->Module (__FUNCTION__)
           ->AFPcon(this)
           ->Message("PostQueuedCompletionStatus() failed" )
           ->HResult( GetLastError() )->Throw();
    }
}

//
//  Prepares OVERLAPPEDcon objects prior to posting to the win32 IO
//  Completion port utilities
//  NOTES: prepareOVERLAPPED() must be complimented by 
//         releaseOVERLAPPED() for any given OVERLAPPED con object
//
//
//  Parameters:  OVERLAPPEDcon *pOVERLAPPEDcon
//               Object to be prepared
void
P2PeerCon::prepareOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // Implementation
    ASSERT(!pOVERLAPPEDcon->bQueued);
    pOVERLAPPEDcon -> bQueued = true;
    pOVERLAPPEDcon -> hr      = S_OK;
    AddRef ( );
}

//
//  Releases OVERLAPPEDcon objects upon return from the win32 IO
//  Completion port utilities
//  NOTES: prepareOVERLAPPED() must be complimented by
//         releaseOVERLAPPED() for any given OVERLAPPED con object
//
//
//  Parameters:  OVERLAPPEDcon *pOVERLAPPEDcon
//               Object to be released
void
P2PeerCon::releaseOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // Implementation
    ASSERT(pOVERLAPPEDcon->bQueued);
    pOVERLAPPEDcon -> bQueued = false;
    Release ( );
}

//
//  Teardown-drains a single completed/cancelled OVERLAPPEDcon
//  NOTES: For CloseP2PmsgHub()'s ring drain.  Unlike
//         releaseOVERLAPPED() - which only clears bQueued and Release()s the
//         ref, leaving the live pump's On_QueuedCompletionStatus() to free the
//         object - the teardown path bypasses On_QueuedCompletionStatus(), so
//         the transient control/Signal OVERLAPPEDs (e.g. P2PsigCon_DESTROY,
//         which MakeOVERLAPPED()s a throw-away object) would otherwise leak.
//         The four connection-owned member OVERLAPPEDs are reclaimed by
//         ~P2PeerCon, so only NON-member objects are freed here.
//       : WARNING - the trailing Release() may be the last ref and delete this
//         connection; the caller must not touch it afterwards.
//       : bQueued IS THE PRECONDITION, not decoration.  releaseOVERLAPPED()
//         ASSERTs it - only an object prepareOVERLAPPED() has queued owns a
//         reference, because that is the call that took it - and this function,
//         written as a variant of it, dropped the test while keeping the
//         Release().  So a completion for an object already drained (a duplicate
//         handed back by the ring, an object the live pump had consumed before
//         the pump stopped) released a reference NOBODY TOOK.  The connection
//         then retired one drain early, while completions for it were still
//         queued, and the next lap of the caller's loop loaded the vtable of a
//         freed connection to make this very call - free and read one lap apart,
//         on the same source line.  Measured on Linux/ASan as an intermittent
//         abort in p2pweb_w2, w5 and w6 (D33); the accounting either side of it
//         is sound, and this was the one unbalanced Release in it.
//
//
//  Parameters:  OVERLAPPEDcon *pOVERLAPPEDcon
//               Drained completion object
void
P2PeerCon::DrainOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // To be sure, to be sure
    if ( pOVERLAPPEDcon == NULL )
      return;

    // Nothing was queued, so nothing was referenced, so there is nothing here to
    // undo: this object has already been drained or released and is not ours to
    // free, release or touch a second time.  Idempotent by construction
    if ( !pOVERLAPPEDcon->bQueued )
      return;

    // Free transient (non-member) control/Signal OVERLAPPEDs; member
    // OVERLAPPEDs (send/recv/accept/connect) are reclaimed by ~P2PeerCon
    bool bMember = pOVERLAPPEDcon == m_pOVERLAPPEDsend    ||
                   pOVERLAPPEDcon == m_pOVERLAPPEDrecv    ||
                   pOVERLAPPEDcon == m_pOVERLAPPEDaccept  ||
                   pOVERLAPPEDcon == m_pOVERLAPPEDconnect;
    pOVERLAPPEDcon -> bQueued        = false;
    // The read this marked is being drained, not delivered.  Clear it in the
    // SAFE direction (false reads as "arming post", which drops nothing) so a
    // member recv buffer that outlives the drain cannot report a stale FIN
    pOVERLAPPEDcon -> bRecvSubmitted = false;
    if ( !bMember )
      DropOVERLAPPED ( pOVERLAPPEDcon );

    // Balance prepareOVERLAPPED()'s AddRef; may delete this
    Release ( );
}

//
//  Answers whether this connection is still owed a completion
//  NOTES: D40.  bQueued is set by prepareOVERLAPPED(), which is also the call
//         that takes the reference the completion carries, and cleared by
//         releaseOVERLAPPED()/DrainOVERLAPPED(), which give it back.  So a
//         member OVERLAPPED with bQueued set means one thing exactly: an
//         operation is outstanding and ONE REFERENCE ON THIS CONNECTION IS
//         HELD BY IT.  Until that completion is drained the connection cannot
//         reach zero, and ~P2PeerCon - which is what reclaims the four member
//         OVERLAPPEDs and their buffers - cannot run.
//       : Only the four member OVERLAPPEDs are asked about.  A transient
//         control OVERLAPPED is freed by DrainOVERLAPPED() when it arrives and
//         is not reachable from here to ask; the members are the ones whose
//         buffers are large and whose loss was measured (D40, 33 KB of accept
//         buffer on a service connection).
//
//
//  Returns:     bool
//               An operation is still outstanding on this connection
bool
P2PeerCon::HasQueuedOVERLAPPED ( ) const
{
    return ( m_pOVERLAPPEDsend    && m_pOVERLAPPEDsend    -> bQueued ) ||
           ( m_pOVERLAPPEDrecv    && m_pOVERLAPPEDrecv    -> bQueued ) ||
           ( m_pOVERLAPPEDaccept  && m_pOVERLAPPEDaccept  -> bQueued ) ||
           ( m_pOVERLAPPEDconnect && m_pOVERLAPPEDconnect -> bQueued );
}

//
//  Re-arms this connection's receive after it has been withheld
//  NOTES: Stage 4 step 12's resume, and it cannot go through PostOVERLAPPED().
//         That function refuses a buffer with dwBytesMax > 0 and a null
//         pBuffer - "Corrupted OVERLAPPEDcon configuration", a SNHappen - which
//         is the right guard for a buffer the transport is about to fill, and
//         is the PERMANENT state of a recv buffer that has received anything:
//         P2Peerio::RecvP2PeerMsg's stage 0 moves the connection onto its own
//         pUserDB1/pUserDB2 pair on the first call and frees pBuffer, leaving
//         it null for the life of the connection
//       : Which means Signal(P2PsigCon_RECV) - the one path in this class that
//         claims to restart receipt - could only ever have worked on a
//         connection that had never received one. NOTHING IN THE TREE CALLED
//         IT, which is why that never showed; it was found by the first code
//         that needed it (measured, P2Pevent "Corrupted OVERLAPPEDcon
//         configuration" thrown out of the backpressure resume). The signal
//         now routes through here, so it means what its comment says
//       : The post ARMS a read rather than performing one, exactly as the
//         initial PostOVERLAPPED in Accept()/OnConnect() does: the completion
//         re-enters On_QueuedCompletionStatus, which calls RecvP2PeerMsg,
//         which issues the actual Recv
//       : Silent when there is nothing to re-arm - no recv buffer (the recv
//         branch NULLS it on a cancelled completion), one already in flight,
//         one being deleted, or no completion port. A resume is not an
//         assertion that the connection is still there
void
P2PeerCon::RearmRecv ( )
{
    if ( !m_pOVERLAPPEDrecv           ||
          m_pOVERLAPPEDrecv->bQueued  ||
          m_pOVERLAPPEDrecv->bDelete  ||
         !m_hCPort                       )
      return;

    prepareOVERLAPPED ( m_pOVERLAPPEDrecv );
    if ( !PostQueuedCompletionStatus ( m_hCPort
                                     , 0
                                     , m_dwCompletionKey
                                     ,(OVERLAPPED *)m_pOVERLAPPEDrecv ) )
    {
      releaseOVERLAPPED ( m_pOVERLAPPEDrecv );
      EVERR->Module (__FUNCTION__)
           ->AFPcon(this)
           ->Message_T("PostQueuedCompletionStatus() failed" )
           ->HResult( GetLastError() )->Throw();
    }
}

//
//  Asynchronously signals this connection
//  NOTES: Provides facility by which P2PeerCon objects may be
//         controlled other than P2PeerCon_MAP handlers
//                     
//
//  Parameters:  P2Psignal uiSignal
//               Signal to be posted
//
//               void *pvData
//               Signal data
//
//               int iDataSize
//               Signal data size
void
P2PeerCon::Signal ( P2PsigID nSigID, void *pvData, int iDataSize  )
{
    // Interception - Start P2PeerMsg receipt
    if ( nSigID == P2PsigCon_RECV )
    {
      RearmRecv ( );
      return;
    }

    // Manufacture - Generic control
    OVERLAPPEDcon *pOVERLAPPEDcon = MakeOVERLAPPED ( iDataSize );
    pOVERLAPPEDcon -> nSigID = nSigID;
    if ( iDataSize )
      memcpy ( pOVERLAPPEDcon->pBuffer, pvData, iDataSize );
    pOVERLAPPEDcon->dwBytes = iDataSize;

    // Implementation
    prepareOVERLAPPED ( pOVERLAPPEDcon );
    if ( !PostQueuedCompletionStatus( m_hCPort
                                    , 0
                                    , m_dwCompletionKey 
                                    , (OVERLAPPED *)pOVERLAPPEDcon) )
    {
      releaseOVERLAPPED ( pOVERLAPPEDcon );
      pOVERLAPPEDcon = DropOVERLAPPED ( pOVERLAPPEDcon );
      EVERR->Module (__FUNCTION__)
           ->AFP(nSigID)->AFP(iDataSize)->AFPcon(this)
           ->Message("PostQueuedCompletionStatus() failed\n" )
           ->HResult( GetLastError() )->Throw();
    }
}

///////////////////////////////////////////////////////////////////////
//  Timers

//
//  Sets PIT for connection
//  NOTES: Outstanding timers must be cancelled in destructor for
//         this object
//
//
//  Parameters:  P2Pmsecs_t uMSecDelay
//               Specifies the time-out value, in milliseconds
//
//               DWORD dwUserKey
//               User defined data key supplied to timeout handler
//
//  Returns:     PITimerID
//               Identifier of the new timer if successful. An
//               application passes this value to the KillTimer member
//               function to kill the timer.
//
PITimerID
P2PeerCon::SetPITimer ( P2Pmsecs_t uMSecDelay, DWORD dwUserKey )
{
    // Simply
    // NOTES: Handler for this object always called
    return SetP2PmsgTimer ( m_hCPortP2PumpID, this, uMSecDelay, dwUserKey );
}

//
//  Decides whether to withhold this connection's next read
//  NOTES: Stage 4 step 12.  Returns true while the process
//         message budget is at or above its high mark, and applies the hold -
//         one poll timer per held connection - on the transition into it
//       : The hold is released by On_PITimer() below, not here, because the
//         message that relieves the budget is released on some other pump and
//         knows nothing about which connections are waiting on it.  A poll is
//         the honest shape for that; an event would need every releaser to
//         maintain a registry of waiters
//       : A connection already holding returns true without arming a second
//         timer, so a completion that arrives while held - a cancellation, a
//         signal - cannot stack timers
//       : Silent on a connection that is going away.  PostDestroyState() is
//         the same guard the login deadline learned to use: arming a timer
//         into a pump that is already unwinding is how that deadline took the
//         process down (refer On_PITimer)
//
//  Returns:     bool
//                 true... The read is being withheld
//                 false.. Carry on reading
bool
P2PeerCon::HoldRecvForBackpressure ( )
{
    if ( m_bRecvThrottled )
      return true;
    if ( !P2PmsgBudgetPressed ( ) )
      return false;
    if ( PostDestroyState ( ) )
      return false;

    m_bRecvThrottled = true;
    m_cRecvThrottled ++;
    BumpP2PmsgHeldCount ( );
    m_uThrottleTimerID = SetPITimer ( DEF_P2PeerConThrottlePoll );

    //  Traced rather than silent, and at TRACE rather than ERROR: being held
    //  is the mechanism working, not a fault.  An operator who wants to know
    //  how often reads the counter this just moved
    if ( IsEVTRC )
      EVTRC->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Read held: %lu of %lu message budget in use")
                    , (unsigned long)GetP2PmsgCount((P2PumpID)~0)
                    , (unsigned long)GetP2PmsgBudgetHigh() )
           ->Advice_T ("Backpressure, resumes when the budget recovers")
           ->Cancel ( );
    return true;
}

//
//  PIT handler for connection
//  NOTES: Override for specialisation.  But always delegate
//         unhandled timers through
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
P2PeerCon::On_PITimer ( bool bCancel
                      , PITimerID nPITimerID, DWORD dwUserKey )
{
    // Startup timer
    // NOTES: Perform connection restart.  Context is managed in the
    //        handler.  Nothing is static in an asynchronous environment
    if ( nPITimerID == m_uRestartTimerID )
    {
      m_uRestartTimerID = 0;           // No longer exists
      if ( !bCancel )
        PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Startup
                   , this, 0, m_hCPortP2PumpID );
    }

    // Login timer
    // NOTES: Login must be performed within nominated period, otherwise
    //        connection is closed via thrown exception
    //      : Should the remote P2PeerHub fail to login, we end up in
    //        limbo.  It's the exchange of P2PeerMsg's that drives the
    //        P2PeerCon'nection objects
    else if ( nPITimerID == m_uLoginTimerID )
    {
      m_uLoginTimerID = 0;             // No longer exists

      // NOTES: The throw below is how this deadline closes a connection, and
      //        it is only safe while there is still a connection to close.
      //        A hub shutting down drops its connections and latches
      //        m_bDestroy, and a deadline armed moments earlier then fires
      //        into a pump that is already unwinding - where the throw is not
      //        caught and takes the process with it (abort, exit 3).
      //      : Found by p2p_acceptcap the first time this timer was ever
      //        ARMED: the test's own verdict printed PASS and the process died
      //        during teardown, which is exactly the shape of failure that
      //        gets read as a flaky test rather than as a defect
      //      : Traced rather than silent. A deadline that expires on a
      //        connection already going away is not an event anybody has to
      //        act on, but it should still be visible
      if ( !bCancel && PostDestroyState ( ) )
      {
        if ( IsEVTRC )
          EVTRC->Module (__FUNCTION__)
               ->AFP(bCancel)->AFP(nPITimerID)->AFP(dwUserKey)->AFPcon(this)
               ->Message_T("Login deadline expired on a closing connection")
               ->Advice_T ("Ignored - the connection is already going")
               ->Cancel ();
      }
      else if ( !bCancel )
        EVERR->Module (__FUNCTION__)
             ->AFP(bCancel)->AFP(nPITimerID)->AFP(dwUserKey)->AFPcon(this)
             ->Message_T("Login timed out")
             ->Advice_T ("Remote connection withheld login")
             ->Advice_T ("Problem within remote P2PeerHub" )
             ->Throw  ();
    }

    // Backpressure poll
    // NOTES: Stage 4 step 12.  Fires while this connection's read is being
    //        withheld: either the budget has recovered to its low mark, in
    //        which case the read is re-armed, or it has not, in which case
    //        this looks again later
    //      : The two marks are NOT the same number.  Resuming at the high mark
    //        would put this connection straight back into a hold on its next
    //        completion, which is a spin rather than a brake - the gap between
    //        the marks is what makes the resume stick
    //      : Nothing here throws.  Unlike the login deadline, an expired
    //        backpressure poll is never a reason to drop a peer: the peer has
    //        done nothing except send, and the pressure is the process's
    else if ( nPITimerID == m_uThrottleTimerID )
    {
      m_uThrottleTimerID = 0;          // No longer exists
      if ( bCancel || PostDestroyState ( ) )
        return;

      if ( !P2PmsgBudgetRelieved ( ) )
        m_uThrottleTimerID = SetPITimer ( DEF_P2PeerConThrottlePoll );
      else
      {
        m_bRecvThrottled = false;
        RearmRecv ( );
      }
    }

    // Unknown timer
    // NOTES: Report and ignore.  Maintain existing P2PeerCon state
    else
      EVERR->Module (__FUNCTION__)
           ->AFP(bCancel)->AFP(nPITimerID)->AFP(dwUserKey)->AFPcon(this)
           ->Message_T("PITimer not handled" )
           ->Advice_T ("Ignored, bug (SNHappen)" )
           ->Cancel ();
}

//
//  Bounds the connections this SERVICE will accept concurrently
//  NOTES: 0 removes the bound.  Set on the SERVICE; an accepted connection
//         carries 0 because it accepts nothing
//       : Lowering it below the current count refuses the NEXT connection
//         rather than dropping any existing one - a bound is admission
//         control, and disconnecting live peers to satisfy a new setting is a
//         different and much ruder operation
//
void
P2PeerCon::SetMaxAccepted ( long xMax )
{
    m_xMaxAccepted = xMax < 0 ? 0 : xMax;
}

//
//  Bounds the connections this SERVICE will accept concurrently FROM ONE SOURCE
//  NOTES: 0 removes the bound, and is the default - refer
//         DEF_P2PeerConAcceptSource for why this one is off when the cap above
//         is on
//       : Set on the SERVICE, same as the cap, and same non-retroactive rule:
//         lowering it refuses the NEXT connection from a source already over
//         it rather than dropping any it already holds
//       : Setting it ABOVE SetMaxAccepted() is legal and does nothing, because
//         the service cap is checked first and binds first.  Not rejected: a
//         caller that raises the service cap afterwards would then find the
//         per-source bound it set had been silently altered
//
void
P2PeerCon::SetMaxAcceptedPerSource ( long xMax )
{
    m_xMaxAcceptedPerSource = xMax < 0 ? 0 : xMax;
}

//
//  Live accepted children of this SERVICE that came from one source
//
long
P2PeerCon::GetAcceptedCountFromSource ( P2PsourceKey xSource ) const
{
    return m_pxSourceTally ? m_pxSourceTally->Count ( xSource ) : 0;
}

//
//  Is this SERVICE already holding all it will hold for that source?
//  NOTES: A zero key is never at capacity.  0 means the transport could not
//         name the origin, and a bound that cannot see who it is refusing must
//         refuse nobody - refer P2PeerCon::AcceptSourceKey()
//
bool
P2PeerCon::SourceAtCapacity ( P2PsourceKey xSource ) const
{
    return xSource                                              &&
           m_xMaxAcceptedPerSource > 0                          &&
           GetAcceptedCountFromSource ( xSource ) >= m_xMaxAcceptedPerSource;
}

//
//  Milliseconds an accepted connection has to complete its login
//  NOTES: 0 disables.  Set on the SERVICE before it accepts; each accepted
//         connection inherits the value current at the moment it was spawned
//
void
P2PeerCon::SetLoginDeadline ( P2Pmsecs_t uMSec )
{
    m_xLoginDeadline = uMSec;
}

//
//  Starts this connection's login deadline
//  NOTES: Called on the ACCEPTED connection, once, as it is spawned.  Expiry
//         runs On_PITimer() above, which throws and so drops the connection;
//         OnLogin(), OnClose() and ~P2PeerCon() each cancel it
//       : Silent no-op when disabled or already armed, so a handler that
//         calls it twice - or an application that arms it itself and then
//         delegates to the default handler - does not stack two timers on one
//         connection and drop it on the first of them
//
void
P2PeerCon::ArmLoginDeadline ( )
{
    if ( !m_xLoginDeadline || m_uLoginTimerID )
      return;

    //  ONLY on an accepted connection, and this is load-bearing rather than
    //  defensive tidiness. P2PeerTarget::On_ConAccept() SWAPS its service and
    //  accept pointers for transports that morph a service into the accepted
    //  connection (P2PeerCon232), so the pointer it calls this on is not
    //  always the child. Arming a SERVICE is not a small mistake: a service
    //  never logs in, so the deadline always expires, and the drop that
    //  follows closes the LISTENING socket - one timed-out peer would take the
    //  whole listener down and every subsequent connect would be refused.
    //
    //  Observed exactly that on Linux (p2p_acceptcap, 2026-08-16: phase 2
    //  reported "CONNECT REFUSED" for the liveness control) while Windows was
    //  green, which is the divergence this guard removes rather than explains.
    if ( m_eP2PeerConMode != P2PeerCon_Accept )
    {
      if ( IsEVTRC )
        EVTRC->Module (__FUNCTION__)->AFPcon(this)
             ->Message(_T("Login deadline not armed: mode %i is not Accept")
                      , m_eP2PeerConMode )
             ->Cancel ();
      return;
    }

    m_uLoginTimerID = SetPITimer ( m_xLoginDeadline );
}

///////////////////////////////////////////////////////////////////////
//  IO Implementation
//  NOTES: Manages IO Completion Port implementation
//

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
P2PeerCon::Drop ( P2Pevent *pEVENT )
{
    // State
    SetState ( 0, ON_ConClose );

    // Restart timers
    if ( m_uRestartTimerID > 0 )
      KillP2PmsgTimer ( m_uRestartTimerID );
    m_uRestartTimerID = 0;

    // Protocol 
    if ( m_pP2Peerio )
      m_pP2Peerio -> Reset ( );

    // Reclaim IO Completion Port buffers
    if (  m_pOVERLAPPEDaccept          &&
         !m_pOVERLAPPEDaccept->bQueued    )
      m_pOVERLAPPEDaccept = DropOVERLAPPED ( m_pOVERLAPPEDaccept );
    if (  m_pOVERLAPPEDconnect          &&
         !m_pOVERLAPPEDconnect->bQueued    )
      m_pOVERLAPPEDconnect = DropOVERLAPPED ( m_pOVERLAPPEDconnect );
    if (  m_pOVERLAPPEDsend          &&
         !m_pOVERLAPPEDsend->bQueued    )
      m_pOVERLAPPEDsend = DropOVERLAPPED ( m_pOVERLAPPEDsend );
    if (  m_pOVERLAPPEDrecv          &&
         !m_pOVERLAPPEDrecv->bQueued    )
      m_pOVERLAPPEDrecv = DropOVERLAPPED ( m_pOVERLAPPEDrecv );

    // Firstly drop connection
    // NOTES: Cancels all outstanding overlapped IO
    if ( m_hFile )
    {
      if (     CloseHandle(m_hFile) &&
             !pEVENT                &&
           !m_pEvent                    )
        pEVENT =
         EVERR->Module (__FUNCTION__)->AFPcon(this)
              ->Message_T("CloseHandle() failed")
              ->Advice_T("Bug (SNHappen)" )
              ->HResult( GetLastError() );
      m_hFile      = 0;
      m_hFileCPort = 0;
    }

    // Secondly attach the precipitating EVENT
    // NOTES: Original precipitating event is latched.  Once
    //        latched such events are cancelled as part of the
    //        ON_P2PeerCon_CLOSE() handler processing
    if ( m_pEvent )
    {
      // A precipitating event is already latched, so the incoming pEVENT (if
      // any) is redundant -> discard it.  Guard the deref: the hub-close sweep
      // (CloseP2PmsgHub -> DropP2PmsgCon -> Drop(0)) passes a NULL pEVENT, and
      // the bare `pEVENT->Cancel()` here crashed on it (NULL this) whenever a
      // con still had m_pEvent latched at teardown -- a TSan-exposed shutdown
      // SEGV (Msgexception.cpp:93) that normal timing usually skips.
      if ( pEVENT )
        pEVENT = pEVENT -> Cancel ( false );
    }
    else
      m_pEvent = pEVENT;

    // Perform notification
    // NOTES: Assigned pump is mandatory
    //      : Previously latched event cancels notification
    if ( ( !m_pEvent           ||
            m_pEvent == pEVENT    )                      &&
           !PostDestroyState()                           &&
           !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Close)    )
      PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Close
                 , this, (P2PeerMsg *)0, m_hCPortP2PumpID  );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg Management

//
//  Posts a message to this P2PeerCon object. Thread safe
//  asynchronous operation
//  NOTES: Posted messages are pended until connection is completed
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be posted.
//
//  Returns:     P2PeerMsg*
//               Null P2PeerMsg routed pointer.  Otherwise exception.
//
P2PeerMsg*
P2PeerCon::PostP2PeerMsg ( P2PeerMsg *pMsg )
{
    // Append to queue
    if ( g_bP2Pmsg_AssertValid )
      pMsg -> AssertValid ( );
    //m_pP2PeerMsgQue->Append ( pMsg );
    P2PsafeCS  oSafeCS  = m_oCSectMsgQue;
    P2Pri_t    nP2Pri   = pMsg->Priority();
    //P2PeerMsg *pMsgLock = pMsg;
    ASSERT(m_eP2PeerConMode!=P2PeerCon_SERVICE);

    // Optimise - no entries, last entry or first entry
    // NOTES: Most common or normal senarios
    if ( m_oCListMsgQue.GetCount() <= 0                 ||
         m_oCListMsgQue.GetTail()->Priority() <= nP2Pri ||
         m_oCListMsgQue.GetHead()->Priority()  > nP2Pri    )
      m_oCListMsgQue.AddTail ( pMsg );

    // Sorted
    else
    {
      POSITION pos = m_oCListMsgQue.GetTailPosition();
      POSITION posInsert = 0;
      while ( pos )
      {
        posInsert = pos;
        if ( m_oCListMsgQue.GetPrev(pos)->Priority() <= nP2Pri )
        {
          m_oCListMsgQue.InsertAfter ( posInsert, pMsg );
          pMsg = 0;
          pos  = 0;
        }
      }
      if ( pMsg )
        m_oCListMsgQue.AddHead ( pMsg );
    }

    // Wakeup
    // NOTES: P2PeerCon may be idle and waiting for next P2PeerMsg
    // P2PeerMsg_P2PeerConLock ( pMsgLock, true );
    if ( m_pP2PeerMsgSend == 0      &&
         m_pOVERLAPPEDsend          &&
        !m_pOVERLAPPEDsend->bQueued    )
      PostOVERLAPPED ( m_pOVERLAPPEDsend );

    // Tidy up and
    return (P2PeerMsg *)0;
}
//
//  Fetches the next highest priority message from P2PeerMsg queue.
//  NOTES: Client assumes responsibility for life cycle of
//         retrieved P2PeerMsg
//       : Clears the P2PeerioTag, assumption is message will be
//         passed to posted P2Peerio object for transmission
//
//
//  Returns:     P2PeerMsg*
//               Retrieved message
//                 0.. No entries on the queue
//               
P2PeerMsg*
P2PeerCon::GetP2PeerMsg ( )
{
    // Isolation and retrieval
    P2PsafeCS oSafeCS = m_oCSectMsgQue;
    if ( m_oCListMsgQue.GetCount() <= 0 )
      return 0;
    return m_oCListMsgQue.RemoveHead();
}

//
//  Flushes queued P2PeerMsg's
//
void
P2PeerCon::FlushP2PeerMsg ( )
{
    // Isolation and garbage collection
    P2PsafeCS oSafeCS = m_oCSectMsgQue;
    while ( m_oCListMsgQue.GetCount() > 0 )
      delete m_oCListMsgQue.RemoveHead();
}

//
//  Retrieves queued P2PeerMsgt
//
//  Returns:     int
//               Number of queued P2PeerMsg's
INT_PTR
P2PeerCon::GetP2PeerMsgCount ( )
{
    // Delegate
    return m_oCListMsgQue.GetCount();
}

///////////////////////////////////////////////////////////////////////
//  Connection state management 
//  NOTES: Referenced from P2PeerCon_MAP handlers only

//
//  Initiates startup processing
//  NOTES: Startup processing must be performed for all connection
//         objects.  Usually from the ON_P2PeerCon_STARTUP handlers.
//       : Override Listen() or Connect() to provide interface
//         specialisation
//               
void
P2PeerCon::OnStartup ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Startup) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Requires ON_P2PeerCon_STARTUP handler state")
           ->Advice_T("Bug (SNHappen)" )
           ->Throw  ( );

    // Event state
    // NOTES: Previously latched P2Pevent's MUST have been cleared
    if ( m_pEvent )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Attempt to startup connection with uncleared P2Pevent")
           ->Advice_T("OnClose() processing not performed" )
           ->Throw  ( );
}

//
//  Performs default listen mode processing
//  NOTES: Processing must be performed for all connections.  Usually
//         from ON_P2PeerCon_STARTUP type handler.
//       : Override implementation for various connection
//         types, WSA, RS232, etc
//
bool
P2PeerCon::Listen ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Startup) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_STARTUP handler state")
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Done
    // NOTES: Derived class provides implementation
    m_eP2PeerConMode = P2PeerCon_SERVICE;
ASSERT(!m_pOVERLAPPEDrecv&&!m_pOVERLAPPEDsend);
    return true;
}

//
//  Description: Performs default listening processing
//               NOTES: This processing must be performed for all
//                      listening sockets
//
void
P2PeerCon::OnListen ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Listen) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_LISTEN handler state")
           ->Throw  ( );
ASSERT(!m_pOVERLAPPEDrecv&&!m_pOVERLAPPEDsend);
}

//
//  Initiates accept facility for object.
//  NOTES: Usually referenced from ON_P2PeerCon_STARTUP or recursively
//         from ON_P2PeerOLD_ACCEPT handlers.
//       : Accepted connections are processed via ON_P2PeerOLD_ACCEPT
//         handlers
//
//
//  Returns:     bool
//
bool
P2PeerCon::Accept ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    //      : P2P_Listen was NOT phased out.  The tree standardised on it
    //        instead - refer P2PeerConDmx.cpp, where the accept path
    //        posts P2P_Listen "for consistency with the other
    //        transports (Wsa/Pipe)"
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Listen) &&
         !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept)    )
      EVERR->MODULE->AFPcon(this)
           ->Message_T("Requires ON_P2PeerOLD_ACCEPT handler state")
           ->Throw  ( );

    // Mode confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( m_eP2PeerConMode != P2PeerCon_SERVICE )
      EVERR->MODULE->AFPcon(this)
           ->Message_T("Requires Listen mode")
           ->Throw  ( );

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
//  Parameters:  P2PaddrSTR pThatP2PaddrSTR
//               Address assigned to remote client
//               NOTES: Assignment may be defered to the login 
//                      phase by specifying a NULL value
//
P2PeerCon*
P2PeerCon::OnAccept ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept) )
      EVERR->MODULE->AFPcon(this)
           ->Message_T("Requires ON_P2PeerOLD_ACCEPT handler state")
           ->Throw  ( );

    // Mode confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( m_eP2PeerConMode != P2PeerCon_SERVICE )
      EVERR->MODULE->AFPcon(this)
           ->Message(_T("Requires P2PeerCon_SERVICE mode not %i")
                    , m_eP2PeerConMode )
           ->Throw  ( );

    // Spawn accepted P2PeerCon
    P2PeerCon *pConAccept = AcceptSpawn ( 0 );
    if ( pConAccept == NULL )
      return pConAccept;

    // Associate with IO Completion Port
    // NOTES: All subsequent notifications received via queued
    //        IO Completion Packets
    if ( !pConAccept->m_hFileCPort &&
          pConAccept->m_hFile         )
      pConAccept -> CreateIOCP ( pConAccept->m_hFile );

    // Activate P2PeerMsg receipt
    // NOTES: Action is negated whenever OVERLAPPEDrecv object already
    //        exists
    //if ( !pConAccept->m_pOVERLAPPEDsend )
    //  pConAccept -> m_pOVERLAPPEDsend = pConAccept -> MakeOVERLAPPED ( );
    //if ( !pConAccept->m_pOVERLAPPEDrecv )
    //  pConAccept -> m_pOVERLAPPEDrecv = pConAccept -> MakeOVERLAPPED ( MAX_P2Psize );
    //if ( !pConAccept->m_pOVERLAPPEDrecv->bQueued )
    //  pConAccept -> PostOVERLAPPED ( pConAccept->m_pOVERLAPPEDrecv );

    // Tidy up, and
    pConAccept -> SetState ( ConState_Send | ConState_Recv, 0 );
    return pConAccept;
}

void
P2PeerCon::OnAccept ( const P2Paddr oThatP2Paddr )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept) )
      EVERR->MODULE->AFPcon(this)
           ->Message(_T("Requires ON_P2PeerCon_ACCEPT handler state"))
           ->Throw  ( );

    // Mode confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( m_eP2PeerConMode != P2PeerCon_Accept )
      EVERR->MODULE->AFPcon(this)
           ->Message(_T("Requires P2PeerCon_Accept mode not"), m_eP2PeerConMode )
           ->Throw  ( );

    // To be sure, to be sure
    if (   !oThatP2Paddr.IsNull()        &&
         !m_oThatP2Paddr.IsNull()        &&
          m_oThatP2Paddr != oThatP2Paddr    )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(L"Attempt to swap P2Paddr's from [%s] to [%s]"
                    , (P2PaddrSTR)m_oThatP2Paddr
                    , (P2PaddrSTR)  oThatP2Paddr )
           ->Throw();

    // Assign
    if ( !oThatP2Paddr.IsNull() )
      m_oThatP2Paddr = oThatP2Paddr;

    // Associate with IO Completion Port
    // NOTES: All subsequent notifications received via queued
    //        IO Completion Packets
    if ( !m_hFileCPort )
      CreateIOCP ( m_hFile );

    // Activate P2PeerMsg receipt
    // NOTES: Action is negated whenever OVERLAPPEDrecv object already
    //        exists
    if ( !m_pOVERLAPPEDrecv )
      m_pOVERLAPPEDrecv = MakeOVERLAPPED ( m_pP2Peerio->GetMaxRecvSize() );
    if ( !m_pOVERLAPPEDsend )
      m_pOVERLAPPEDsend = MakeOVERLAPPED ( );
    if ( !m_pOVERLAPPEDrecv->bQueued )
      PostOVERLAPPED ( m_pOVERLAPPEDrecv );

    // Tidy up, and
    SetState ( ConState_Send | ConState_Recv, 0 );
    return;
}

//
//  Performs default connection processing
//  NOTES: Processing must be performed for all connections.  Usually
//         from ON_P2PeerCon_STARTUP type handler.
//       : Override implementation for various connection types, WSA,
//         RS232, etc
//
bool
P2PeerCon::Connect ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Startup) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Requires ON_P2PeerCon_STARTUP handler state") )
           ->Message(_T("Bug (SNHappen)") )
           ->Throw  ( );

    // Mode confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( m_eP2PeerConMode != P2PeerCon_CLIENT )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Requires connection mode") )
           ->Throw  ( );

    // Done
    return true;
}

//
//  Performs CONNECT'ed processing
//  NOTES: This processing must be performed for all connections
//       : Reference from within ON_P2PeerCon_CONNECT() handlers
//
//
void
P2PeerCon::OnConnect ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Connect) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Requires ON_P2PeerCon_CONNECT handler state") )
           ->Throw  ( );

    // Activate P2PeerMsg flow
    // NOTES: Action is negated should either of the OVERLAPPEDrecv
    //        or OVERLAPPEDsend objects already exists
    if ( !m_pOVERLAPPEDrecv )
      m_pOVERLAPPEDrecv = MakeOVERLAPPED ( MAX_P2Psize );
    if ( !m_pOVERLAPPEDrecv->bQueued )
      PostOVERLAPPED ( m_pOVERLAPPEDrecv );
    if ( !m_pOVERLAPPEDsend )
      m_pOVERLAPPEDsend = MakeOVERLAPPED ( );

    // Tidy up, and
    SetState ( ConState_Send | ConState_Recv, 0 );
    return;
}

//
//  Initiate PKey exchange sequence with P2PeerCon object within remote P2PeerHub
//  NOTES: First message exchanged and initiates PKey negotiations. Logically
//         object must be connected
//       : Upon receipt the remote P2PeerHub will process the request
//         via OnPKeyXChange(), respond via PKeyXChangeAck(), which in turn
//         will be procesed via OnPKeyXChangeAck() within this object
//       : 3rd Party type interfaces MUST simulate above PKey exchange.
//
//
//  Parameters:  void *pvPKeyXChange
//               Optional PKey exchange message as supplied to remote
//               P2PeerCon object
//
//               P2Psize_t iSize
//               Size of above message
//
void
P2PeerCon::PKeyXChange ( const void *pvPKeyXChange, P2Psize_t iSize )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Connect) &&
         !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept)     )
      EVERR->Module (__FUNCTION__)->AFP(iSize)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_CONNECT, ACCEPT handler state")
           ->Throw  ( );

    // Duplication
    if ( CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Login) )
      EVERR->Module (__FUNCTION__)->AFP(iSize)->AFPcon(this)
           ->Message("Attempt to exchange PKeys after login")
           ->Throw  ( );

    // Delegate through to underlying P2Peerio object
    // NOTES: Default implementation prevails
    m_pP2Peerio -> PKeyXChange ( (P2Piomage *)pvPKeyXChange );
}

//
//  Processes PKey exchange receipt
//  NOTES: Default processing for remote client PKeyXChange() request
//       : Processing cycle is completed via subsequent
//         PKeyXChangeAck() response.
//
//
//  Parameters:  void *pvPKeyXChange
//               Optional PKey exchange message as received from remote
//               P2PeerCon object
//
//               P2Psize_t iSize
//               Size of above message
//
void
P2PeerCon::OnPKeyXChange ( const void *pvPKeyXChange, P2Psize_t iSize )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Connect) &&
         !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept)     )
      EVERR->Module (__FUNCTION__)->AFP(iSize)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_CONNECT, ACCEPT handler state")
           ->Throw  ( );

    // Duplication
    if ( CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Login) )
      EVERR->Module (__FUNCTION__)->AFP(iSize)->AFPcon(this)
           ->Message("Request to exchange PKeys after login")
           ->Throw  ( );

    // Delegate through to underlying P2Peerio object
    // NOTES: Default implementation prevails
    m_pP2Peerio -> PKeyXChange ( (P2Piomage *)pvPKeyXChange );
}

void
P2PeerCon::PKeyXChangeAck ( const void *pvPKeyXChange, P2Psize_t iSize )
{
    UNREFERENCED_PARAMETER(iSize);
    // Delegate through to underlying P2Peerio object
    m_pP2Peerio -> PKeyXChangeAck ( (P2Piomage *)pvPKeyXChange );
}
void
P2PeerCon::OnPKeyXChangeAck ( const void *pvPKeyXChange, P2Psize_t iSize )
{
    UNREFERENCED_PARAMETER(iSize);
    // Delegate through to underlying P2Peerio object
    m_pP2Peerio -> OnPKeyXChange ( (P2Piomage *)pvPKeyXChange );
}

///////////////////////////////////////////////////////////////////////
//  Peer login authentication
//  NOTES: Refer P2PAuthLogin.h for the wire format and the threat
//         statement.  The policy - identity, allow-list, window, nonce
//         cache - belongs to the hub; this connection only carries the
//         nonce it signed and the length of the block it verified
//

//
//  Locate the hub whose login policy governs this connection
//  NOTES: m_pP2PeerTarget is what PostP2PeerCon() assigns and what
//         AcceptSpawn() propagates, because the connection cannot
//         function without it.  A security setting reached through a
//         link of that kind cannot be silently lost, which is the whole
//         reason the policy lives there and not here
//
//  Returns:    P2PeerHub*
//              Governing hub, or 0 for a connection not yet posted to
//              one - in which case nothing is signed and nothing is
//              required, exactly as before this feature existed
//
P2PeerHub*
P2PeerCon::GetAuthHub ( )
{
    if ( !m_pP2PeerTarget )
      return 0;
    return m_pP2PeerTarget -> GetP2PeerHub ( );
}

//
//  Verify the auth block on an inbound Login / LoginAck
//  NOTES: Runs at the interception, BEFORE the message is posted, so a
//         refusal happens before OnLogin() can set ConState_Login - the
//         gate every later check keys off.  Refusal is handled exactly
//         as the domain and source-binding violations are: the message
//         is discarded (the pump never took ownership) and the
//         connection is dropped
//       : On success the verified block length is recorded so the
//         dispatcher can hide it from the application.  Nothing is ever
//         stripped on the strength of the magic bytes alone
//
//  Parameters: P2PeerMsg *pMsg
//              The inbound login or login-acknowledgement message
//
//              bool bAck
//              true for a LoginAck, false for a Login
//
///////////////////////////////////////////////////////////////////////
//  Session key agreement
//  NOTES: Ephemeral ECDH P-256 -> HKDF-SHA256 -> AES-256-GCM, one agreement
//         per connection, no negotiation and no cipher suite to downgrade
//       : Four flights.  The two public halves travel in clear because they
//         are what the key is derived FROM - there is nothing yet to seal
//         them with - and the login travels INSIDE the sealed channel:
//
//           1  client -> server   client_pub      plain
//           2  server -> client   server_pub      plain   both derive here
//           3  client -> server   login           sealed
//           4  server -> client   login ack       sealed
//
//       : Activating on flight 2 rather than around the login is what makes
//         the ordering safe.  Both ends hold the key before either sends
//         anything that needs it, so there is no window where one side is
//         sealing and the other cannot yet open
//       : This defeats the relay of p2p_authrelay outright.  A relay carries
//         the two public points and holds neither private half, so it cannot
//         compute the session key and cannot produce a frame whose tag
//         verifies.  Forwarding a proof no longer lets it speak
//

//
//  Has this hub relaxed the per-link protections for this link's class?
//  NOTES: Two conditions and both are needed.  A hub with RequireAuth(false)
//         is NOT relaxed: it has turned the switch off outright, and every
//         reason a login is or is not signed on such a hub is what it was
//         before this feature existed.  Only a hub that still REQUIRES
//         authentication and has named a class it will not require it ON can
//         answer true here, which is what keeps every existing deployment
//         byte-identical
//       : Wire can never reach P2PeerLinkPolicy_Open - SetLinkPolicy refuses
//         it - so a link the transport could not vouch for cannot arrive here
//         and be relaxed by a policy the operator set for something else
//
bool
P2PeerCon::AuthLinkRelaxed ( )
{
    P2PeerHub *pHub = GetAuthHub ( );
    if ( !pHub || !pHub -> IsAuthRequired ( ) )
      return false;
    return pHub -> GetLinkPolicy ( EffectiveTrust ( ) )
             != P2PeerLinkPolicy_Full;
}

//
//  Does this connection run a key agreement?
//  NOTES: The single gate.  Tied to RequireAuth rather than given a switch
//         of its own, because a confidential channel to an unproven peer and
//         a proven peer on a readable wire are each half an answer
//       : Two inputs since the per-class link policy landed, and they are
//         asked in this order for a reason.  The hub's switch is still the
//         thing an operator turns; the class only says whether the hub's
//         answer for THAT class applies.  A hub that requires nothing is
//         unaffected by any of it
//       : This is the question AuthGateInbound asks too, by calling this
//         function rather than composing it a second time.  F-S6-1 was two
//         ends of one link reading different halves of one switch, and the
//         cheapest way to be sure that cannot recur through a change that
//         ADDS a half is to have exactly one place the halves are put
//         together
//
bool
P2PeerCon::KeyXWanted ( )
{
    P2PeerHub *pHub = GetAuthHub ( );
    return pHub && pHub -> IsAuthRequired ( ) && !AuthLinkRelaxed ( );
}

//
//  Client opens the agreement
//  NOTES: Called from Login(), which parks the application's payload and
//         returns.  The login itself goes out on the ack
//
void
P2PeerCon::KeyXBegin ( )
{
    if ( m_pKeyX )
      return;                          // already running

    p2pcng::EcdhP256 *pEcdh = new p2pcng::EcdhP256;
    if ( !pEcdh->Generate ( ) ||
         !pEcdh->ExportPublic ( m_KeyXPubThis ) )
    {
      delete pEcdh;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Could not generate an ephemeral key pair")
           ->Throw();
    }
    m_pKeyX       = pEcdh;
    m_bKeyXClient = true;

    PostP2PeerMsg ( new P2PeerMsg ( GetP2PaddrHub(), m_oThatP2Paddr
                                  , P2Pmsg_KeyX
                                  , m_KeyXPubThis, sizeof(m_KeyXPubThis) ) );
}

//
//  Server answers the agreement
//  NOTES: Replies with its own public half and derives immediately.  The
//         reply is exempt from sealing by message type (refer
//         P2Peerio::SendP2PeerMsg), which is what lets the cypher be
//         installed here rather than after a send this thread cannot observe
//
void
P2PeerCon::KeyXOnRequest ( P2PeerMsg *pMsg )
{
    // Does this link run an agreement at all?
    // NOTES: THE OTHER HALF of "both ends of a link need the same answer", and
    //        until this test existed only one half was enforced.  A client
    //        whose hub holds this class at Full, against a server whose hub has
    //        opened it, was SERVICED here: the agreement ran, a cypher was
    //        installed, and the disagreement only surfaced further on, at
    //        AuthGateInbound, as a login block handed to the application for
    //        the stock handler to refuse with a message about login data.  The
    //        opposite mismatch - a client that skipped the agreement against a
    //        server that wanted one - has always been refused where it happens,
    //        with a diagnostic that names the cause
    //      : AuthLinkRelaxed() and NOT !KeyXWanted(), deliberately.  There are
    //        two ways to reach "this link runs no agreement" and only ONE of
    //        them is new.  A hub with RequireAuth(false) has always serviced a
    //        peer's exchange and must go on doing so, or this branch would
    //        change the behaviour of every deployment that predates the trust
    //        class - which is the one thing this feature promised not to do.
    //        AuthLinkRelaxed() is false for such a hub by construction
    //      : REFUSED rather than ignored.  Answering nothing would leave the
    //        peer waiting on an ack until its own login deadline, and dropping
    //        the message silently would put the connection into the state
    //        F-S6-1 was about: two ends that disagree about whether there is a
    //        channel, discovering it later and somewhere else
    //      : KeyXOnAck needs no such test.  A relaxed end never sends a
    //        request, so m_pKeyX is null there and its first line already
    //        refuses an acknowledgement that answers nothing
    if ( AuthLinkRelaxed ( ) )
    {
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Peer opened a key agreement on a link this hub has "
                        "relaxed (trust class %d)")
                    , (int)EffectiveTrust ( ) )
           ->Advice_T ("The peer's hub requires the handshake on this class "
                       "and this one does not, so the two ends would disagree "
                       "about whether there is a channel")
           ->Advice_T ("SetLinkPolicy(class, P2PeerLinkPolicy_Open) on the "
                       "peer as well, or P2PeerLinkPolicy_Full here")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }

    if ( m_bKeyXDone || m_pKeyX )
    {
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Duplicate key exchange request on one connection")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }
    if ( !pMsg || (size_t)pMsg->DataSize ( ) != sizeof(m_KeyXPubThat) )
    {
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Key exchange request is %d bytes, expected %u")
                    , pMsg ? (int)pMsg->DataSize ( ) : -1
                    , (unsigned)sizeof(m_KeyXPubThat) )
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }
    memcpy ( m_KeyXPubThat, pMsg->Data ( ), sizeof(m_KeyXPubThat) );

    p2pcng::EcdhP256 *pEcdh = new p2pcng::EcdhP256;
    if ( !pEcdh->Generate ( ) ||
         !pEcdh->ExportPublic ( m_KeyXPubThis ) )
    {
      delete pEcdh;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Could not generate an ephemeral key pair")
           ->Throw();
    }
    m_pKeyX       = pEcdh;
    m_bKeyXClient = false;

    PostP2PeerMsg ( new P2PeerMsg ( GetP2PaddrHub(), m_oThatP2Paddr
                                  , P2Pmsg_KeyXAck
                                  , m_KeyXPubThis, sizeof(m_KeyXPubThis) ) );
    KeyXDerive ( );
}

//
//  Client completes the agreement, then sends the login it parked
//
void
P2PeerCon::KeyXOnAck ( P2PeerMsg *pMsg )
{
    if ( m_bKeyXDone || !m_pKeyX )
    {
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Key exchange acknowledgement without a request")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }
    if ( !pMsg || (size_t)pMsg->DataSize ( ) != sizeof(m_KeyXPubThat) )
    {
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Key exchange acknowledgement is %d bytes, expected %u")
                    , pMsg ? (int)pMsg->DataSize ( ) : -1
                    , (unsigned)sizeof(m_KeyXPubThat) )
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }
    memcpy ( m_KeyXPubThat, pMsg->Data ( ), sizeof(m_KeyXPubThat) );
    KeyXDerive ( );

    // The login the application asked for, now that there is a channel to
    // put it in and a channel for its signature to name.
    if ( m_bLoginDefer )
    {
      m_bLoginDefer = false;
      LoginSend ( m_pLoginDefer, (P2Psize_t)m_cbLoginDefer );
      delete [] m_pLoginDefer;
      m_pLoginDefer  = 0;
      m_cbLoginDefer = 0;
    }
}

//
//  Shared secret -> channel binding -> session key -> cypher
//  NOTES: The raw ECDH output is never used as a key.  It is an X coordinate
//         with structure, not a uniformly random string, so it goes through
//         HKDF first
//       : The channel binding doubles as the HKDF salt.  One value, derived
//         from both public halves, both naming this connection and keying it
//
void
P2PeerCon::KeyXDerive ( )
{
    p2pcng::EcdhP256 *pEcdh = (p2pcng::EcdhP256 *)m_pKeyX;
    unsigned char aSecret[p2pcng::kEcdhSecLen];
    if ( !pEcdh || !pEcdh->DeriveRawSecret ( m_KeyXPubThat, aSecret ) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("ECDH key agreement failed")
           ->Advice_T ("Connection dropped out")
           ->Throw();

    // By ROLE, not by arrival order: the connecting peer's point first.
    // Both ends must agree on which is which or they bind different channels.
    const unsigned char *pClientPub = m_bKeyXClient ? m_KeyXPubThis : m_KeyXPubThat;
    const unsigned char *pServerPub = m_bKeyXClient ? m_KeyXPubThat : m_KeyXPubThis;
    if ( !p2pauth::AuthChannelBind ( pClientPub, pServerPub, m_KeyXBind ) )
    {
      SecureZeroMemory ( aSecret, sizeof(aSecret) );
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Could not compute the channel binding")
           ->Throw();
    }
    m_bKeyXBound = true;

    static const char szInfo[] = "P2P-session-v1";
    unsigned char aKey[p2pcng::kAesKeyLen];
    const bool bOk = p2pcng::HkdfSha256 ( aSecret, sizeof(aSecret)
                                        , m_KeyXBind, sizeof(m_KeyXBind)
                                        , (const unsigned char *)szInfo
                                        , sizeof(szInfo) - 1
                                        , aKey, sizeof(aKey) );
    SecureZeroMemory ( aSecret, sizeof(aSecret) );
    if ( !bOk )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Session key derivation failed")
           ->Throw();

    P2PeerioGcm *pGcm = new P2PeerioGcm;
    try
    {
      pGcm -> SetKey ( (const char *)aKey, (int)sizeof(aKey), 0, 0 );
    }
    catch ( ... )
    {
      delete pGcm;
      SecureZeroMemory ( aKey, sizeof(aKey) );
      throw;
    }
    SecureZeroMemory ( aKey, sizeof(aKey) );

    if ( !m_pP2Peerio )
    {
      delete pGcm;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("No P2Peerio to install the session cypher on")
           ->Throw();
    }
    m_pP2Peerio -> PostP2Pcrypto ( pGcm );   // takes ownership

    // ...and the class it was just installed on has to CONSULT it
    // NOTES: F-S6-3, and this line is the moment to ask.
    //        The agreement has completed and the cypher is installed, which
    //        is precisely the state the channel gate in AuthGateInbound
    //        cannot see: that one reads m_bKeyXDone, and m_bKeyXDone is one
    //        statement away from true.  An io class that overrides both
    //        message methods holds this cypher and never consults it, so the
    //        wire is in clear on a connection reporting itself keyed - which
    //        is the whole of F-S6-3 and is not something F-S6-1's fix could
    //        ever have caught
    //      : TWO questions, and only the combination is a defect.
    //        LeavesProcess() says the frames go somewhere this process cannot
    //        vouch for; IsCypherActive() says the class holding the cypher
    //        runs the hooks.  P2PeerioDmx answers false to the first and is
    //        exempt BY DECLARATION rather than by being recognised as itself,
    //        which is the difference between a rule and a convention
    //      : Asked of m_pP2Peerio directly, not through this object's
    //        accessors.  Those exist for the snapshot and answer for a
    //        connection with no io object at all; here there is one, it was
    //        checked above, and the gate must not be able to read "no
    //        transport" as "nothing to protect"
    //      : Refused BEFORE m_bKeyXDone is set, so a connection in this state
    //        never reports itself keyed, never signs a login naming a channel
    //        it does not have, and never writes a frame.  Same shape as Stage
    //        3 step 8's arming gate: a protection that cannot be enforced
    //        does not start
    if (  m_pP2Peerio -> LeavesProcess  ( ) &&
         !m_pP2Peerio -> IsCypherActive ( )    )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Session cypher installed on a transport that leaves "
                       "this process and does not consult it" )
           ->Advice_T ("This connection's P2Peerio subclass overrides "
                       "SendP2PeerMsg/RecvP2PeerMsg and calls neither hook" )
           ->Advice_T ("Route it through the base class, or RequireAuth(false) "
                       "and mean it" )
           ->Advice_T ("Connection dropped out" )
           ->Throw();

    m_bKeyXDone = true;
}

void
P2PeerCon::GateAppMsgInbound ( P2PeerMsg *pMsg )
{
    // Only accept an application message once this connection has completed
    // login
    // NOTES: Login / LoginAck and the key agreement are handled by their own
    //        branches before this is reached, and P2Pmsg_CypherEx is
    //        intercepted in the io layer, so no handshake traffic arrives
    //        here.  A conformant peer sends no application traffic before it
    //        has received the LoginAck, so an application message arriving
    //        pre-login is a protocol violation -> discard it and drop the
    //        connection (the message is not posted, so the pump never takes
    //        ownership and we must free it here)
    if ( !(m_dwState & ConState_Login) )
    {
      delete pMsg;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Application message received before login")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }

    // Source binding (SECURITY_REVIEW M2)
    // NOTES: The source address is read off the wire, so without this check a
    //        peer that logged in as one identity could attribute every
    //        subsequent message to another - and the source is what routing,
    //        the Explorer registry and every application handler key on
    //      : The declared source must be the identity this connection
    //        authenticated as, or a descendant of it: IsRable() accepts an
    //        exact match and a hop-boundary prefix, so a peer logged in as
    //        Root.HubA may legitimately relay for its own sub-targets
    //        (Root.HubA.Child) but not for Root.HubB - and not for
    //        Root.HubAX, because the boundary must fall on a '.'
    //      : Rejected rather than silently re-routed: rewriting the source
    //        would leave a forged address in the message the handlers see,
    //        which is the half of the bug that actually bites
    //      : Permissive when m_oThatP2Paddr is null, matching the domain
    //        check in SetLogin(): with no established identity there is
    //        nothing to bind against.  Note this closes forgery by a peer
    //        that logged in HONESTLY; it does not stop a peer from claiming a
    //        false address AT login, because the login carries no proof of
    //        identity.  That needs the PSK work - see SECURITY.md
    //
    // DOWNWARD RELAY: an ANCESTOR link is not source-bound
    // NOTES: "source must be at or below the peer" is right for a link to a
    //        DESCENDANT - a child speaks for itself and its own sub-targets,
    //        and nothing else.  On a link to an ANCESTOR it cannot hold,
    //        because that peer is this hub's gateway to the whole of the rest
    //        of the tree: everything routed down to us arrives from it, still
    //        carrying its ORIGINAL source, which is outside its subtree
    //        whenever the message came from another branch.  With only the
    //        descendant test, Root -> Root.A -> Root.A.Leaf was refused at the
    //        Leaf (source Root is not at-or-below Root.A) and the connection
    //        DROPPED, so downward transit and any broadcast past the first hop
    //        could not work at all.  Upward transit was unaffected and always
    //        passed, which is what made the gap look like a routing bug rather
    //        than an admission rule.
    //
    // WHAT AN ANCESTOR LINK COSTS, and what it now costs instead.
    //
    // It used to be admitted with NO source check whatever, and that was the
    // outstanding half of SECURITY.md roadmap item 1.  Note first what the
    // narrower-looking fix cannot be: a "but not our own subtree" exception was
    // tried here and is UNREACHABLE by construction - the branch is only
    // entered when the source is outside the PEER's subtree, and our subtree is
    // contained in our ancestor's, so a source inside ours has already been
    // admitted by the descendant test above.  Recorded rather than left as dead
    // code that reads like a guarantee.
    //      : The incremental grant over the descendant rule was therefore: an
    //        ancestor may also present a source from OUTSIDE its own subtree
    //        (another tree entirely, say).  It could already present anything
    //        INSIDE its subtree, which includes this hub and every descendant
    //        of it - so a parent could always speak as its own children, and
    //        that part is unchanged and is not what this closes.
    //      : What was missing was never a better PREDICATE.  Binding the source
    //        on that link cannot be done from the address alone: the gate would
    //        have to know which branch a source is reachable through, which is
    //        routing state it does not have.  What it needed was EVIDENCE.
    //
    // GateRelayInbound() supplies it.  With RequireRelayAuth(true) the message
    // must carry an attestation signed by the ORIGIN - a key the relaying
    // ancestor does not hold - and the same at-or-below test is then applied to
    // the identity that SIGNED rather than to the peer that DELIVERED.  So the
    // rule is not weakened or excepted on this link; it is bound against a
    // different, proven thing.  Refer p2pauth's kRelayFixedLen block comment.
    //      : Default OFF, and OFF is byte-for-byte the old exemption.  That is
    //        not timidity: attestation needs the origin provisioned into this
    //        hub's allow-list, and a tree that has not done that would simply
    //        stop carrying downward traffic.  Turning it on is a deployment
    //        decision with a provisioning cost, so it is a deployment switch.
    //      : Links to a DESCENDANT and to an UNRELATED peer are completely
    //        unchanged in either mode - those are the forgery cases the rule
    //        was written for, and they never reached this branch.
    //      : GUARDED both ways, and the exemption was not guarded at all before
    //        p2p_authancestor existed.  Deleting this branch used to leave the
    //        whole suite GREEN - measured, 38/38 - because every multi-hub
    //        topology in it routes through a COMMON ancestor (p2p_sealhop is
    //        Seal.Alice -> Seal -> Seal.Carol), so the source is always
    //        at-or-below the peer and the DESCENDANT test admits it before this
    //        branch is reached.  The exemption only fires on a source OUTSIDE
    //        the relaying ancestor's subtree, and nothing built that shape.
    //        p2p_authancestor builds it, and now runs it in both modes.
    //      : Cost: GetP2PaddrHub() builds a P2Paddr, so it is evaluated ONLY
    //        after the cheap descendant test has already failed - i.e. never
    //        on the common path where a peer speaks for itself.  The signature
    //        verification is further down still, behind the policy switch.
    //      : An empty hub address (no con id yet) falls through to the
    //        original rule.  Refusing is the safe default.
    if (  !m_oThatP2Paddr.IsNull() && pMsg->GetSource() )
    {
      //  A COPY, not the accessor's pointer.  Off Windows GetSource() returns
      //  a slot in a ring of 16 thread-local buffers that c_wstr() widens into,
      //  and every later accessor call on this thread recycles them - so a
      //  pointer taken here and used after GetP2PaddrHub(), GetDestin() and
      //  c_name() no longer describes this message.  Measured, on Linux,
      //  2026-08-14: the source read back as "Dst" - the field NAME - and the
      //  scope test in GateRelayInbound refused a correctly attested relay
      //  because of it.  The signature had already verified; it was the address
      //  the verdict was applied to that had gone stale.  Same defect and same
      //  fix as P2PeerHub::RouteP2PeerMsg and WrappedResponseFactory before it
      //      : The refusal message below reads it too, so this also stops that
      //        diagnostic naming the wrong address on the pre-existing path
      CString    strSourceHeld = pMsg->GetSource();
      P2PaddrSTR strSource     = (P2PaddrSTR)strSourceHeld;
      bool       bBound        = m_oThatP2Paddr.IsRable ( strSource ) ? true : false;

      if ( !bBound )
      {
        //  Is the peer at or above this hub?  Then it is an ancestor link.
        const P2Paddr oThisHub = GetP2PaddrHub();
        if ( !oThisHub.IsNull() && m_oThatP2Paddr.IsRable ( oThisHub.c_wstr() ) )
        {
          //  Returns only if the message may be admitted; otherwise it has
          //  already deleted pMsg and thrown with its own diagnosis, which is
          //  a different one from the message below and worth keeping apart.
          GateRelayInbound ( pMsg );
          bBound = true;
        }
      }

      if ( !bBound )
      {
        P2Paddr oSourceClaimed ( strSource );
        delete pMsg;
        EVERR->Module (__FUNCTION__)->AFPcon(this)
             ->Message(_T("Message source [%s] is not the logged-in identity [%s]")
                      , oSourceClaimed.c_wstr()
                      , m_oThatP2Paddr.c_wstr() )
             ->Advice_T ("Connection dropped out")
             ->Throw();
      }

      // End-to-end seal
      // NOTES: Last, once the message is admitted.  A body this hub was not
      //        made a reader of is left sealed and travels on - that is the
      //        relay case and it is the point of the module.  Returns to
      //        deliver; deletes pMsg and throws to refuse, the same contract
      //        GateRelayInbound has
      OpenAppMsgInbound ( pMsg );
    }
}

//
//  Seals an outbound application message to its destination
//  NOTES: Stage 3 step 20.  THE ONLY HOOK ON THE SEND PATH
//         THAT CAN REFUSE, and that is the whole design: a seal that quietly
//         became cleartext when the directory was incomplete would be F-S6-3
//         again - a protection inherited rather than enforced
//       : WHEN IT SEALS.  Only when the destination is NOT the peer on the far
//         end of this link.  If the peer IS the destination there is no
//         intermediate hub to hide the body from and the connection cypher
//         already covers the hop; sealing then would cost 234 bytes and an
//         ECDH to protect against nobody
//       : Runs on the IO thread, after PerformIFaddrTransform and after the
//         attestation, so the addresses bound into the seal are the addresses
//         that go on the wire
//
//  Parameters:  P2PeerMsg *pMsg
//               Message about to be transmitted
//
//  Returns:     bool
//               true to send.  false means the caller must DROP it
//
bool
P2PeerCon::SealAppMsgOutbound ( P2PeerMsg *pMsg )
{
    if ( !pMsg )
      return true;

    // Policy
    P2PeerHub *pHub = GetAuthHub ( );
    if ( !pHub || !pHub -> IsSealRequired ( ) )
      return true;

    // Handshake traffic is not application traffic
    // NOTES: Same three as AttestAppMsgOutbound, and for the same reason - the
    //        login gate strips what it put there and would be handed a sealed
    //        block instead
    if ( pMsg->Map_MatchName ( P2Pmsg_Login    ) ||
         pMsg->Map_MatchName ( P2Pmsg_LoginAck ) ||
         pMsg->Map_MatchName ( P2Pmsg_CypherEx )    )
      return true;

    // Already sealed?
    // NOTES: The relay case, and the common one.  A hub forwarding a sealed
    //        body must pass it on untouched - re-sealing would substitute this
    //        hub's reader set for the one the ORIGIN chose, which is the single
    //        property the recipient block exists to protect
    if ( pMsg->IsSealed ( ) )
      return true;

    // A broadcast, on a tree that does not require broadcasts to be sealed
    // NOTES: HasScope() IS the broadcast test, and it is exact rather than
    //        approximate. TMsg_Scp is stamped by On_P2PeerBCast and
    //        On_P2PeerUCast and by nothing else, so a message carrying one is
    //        a fanned-out copy BY CONSTRUCTION - there is no message name to
    //        match and no class to get wrong, which is the mistake F-S9-1 was
    //      : DEFAULT IS TRUE, so this branch does nothing at all unless an
    //        operator has written down that their broadcasts are not
    //        confidential. That asymmetry is the point. Before TMsg_Scp the
    //        exemption below happened at EVERY hop, silently, because the
    //        fan-out re-addressed each copy and the last-hop test could not
    //        tell the difference - the defect was never that a broadcast went
    //        unencrypted, it was that nobody had chosen for it to
    //      : ATTESTATION IS UNAFFECTED, and that is what makes the exemption
    //        defensible rather than a hole with a switch on it. The copy still
    //        carries the origin's signature over its scope, so an exempt
    //        broadcast is unencrypted and still unforgeable
    if ( pMsg->HasScope ( ) && !pHub -> IsSealBroadcastRequired ( ) )
      return true;

    // Is there an intermediate hub at all?
    // NOTES: The peer on the far end is m_oThatP2Paddr.  Equal to the
    //        message's SCOPE means this link IS the last hop
    //      : SCOPE AND NOT Dst, which is the defect this replaced.  A
    //        fanned-out broadcast copy is re-addressed to the peer it is about
    //        to be handed to at EVERY hop (P2PeerHub::On_P2PeerBCast ->
    //        RedirectFactory), so comparing against Dst was true every single
    //        time and this hook never fired at all - measured, p2p_sealbcast
    //        phase 3, a 400 byte body read in clear off a carrier holding no
    //        keys of any kind.  Refer TMsg_Scp in P2PeerMsg.h
    //      : For a unicast nothing is stamped and GetScopeOrDestin() IS
    //        GetDestin(), so this path is byte-for-byte what it was
    CString    strScopeHeld = pMsg->GetScopeOrDestin ( )
                                ? pMsg->GetScopeOrDestin ( ) : L"";
    P2PaddrSTR strScope     = (P2PaddrSTR)strScopeHeld;
    if ( !strScope || !*strScope )
      return true;

    if ( m_oThatP2Paddr == strScope )
      return true;

    // Is the destination a hub in THIS process, on a hub that has waived?
    // NOTES: securityRevision.md §6.3, and it is the ONE exemption on this
    //        path whose correctness rests on a deployment assumption rather
    //        than on something the library can check.  Refer
    //        P2PeerHub::WaiveEndToEndInProcess for the A-B-C failure mode; the
    //        short version is that the DESTINATION being in this process is a
    //        fact, and the ROUTE staying in this process is not
    //      : OFF BY DEFAULT, so this branch does nothing at all unless an
    //        operator has written the assumption down - the same shape as the
    //        broadcast exemption above it, and for the same reason
    //      : NOT A BROADCAST, and the test is HasScope() rather than a
    //        comparison, exactly as the exemption above uses it.  A scope
    //        names a SUBTREE; a subtree cannot be established to be in this
    //        process even when its root hub is, because a child hub may sit on
    //        another host.  Sealing a fan-out is RequireSealBroadcast's
    //        decision and it is a different one
    //      : THE HUB LOCK IS NOT HELD ACROSS THE LOOKUP.  The accessor takes
    //        and releases P2PeerHub's lock, and IsP2PmsgHubInProcess then
    //        takes the process-wide hub lock on its own - refer the note on
    //        its declaration in P2Pwin32.h.  Written as two statements rather
    //        than one && so that the order is not a matter of how the compiler
    //        sequences it
    if ( !pMsg->HasScope ( ) && pHub -> IsEndToEndWaivedInProcess ( ) )
    {
      if ( IsP2PmsgHubInProcess ( strScope ) )
        return true;
    }

    // Nothing to hide
    if ( pMsg->DataSize ( ) == 0 )
      return true;

    // Seal
    CString    strSrcHeld = pMsg->GetSource ( ) ? pMsg->GetSource ( ) : L"";
    P2PaddrSTR strSrc     = (P2PaddrSTR)strSrcHeld;

    const size_t cbPlain = pMsg->DataSize ( );
    //  Sized for the maximum reader count rather than the configured one: the
    //  policy resolves the readers under its own lock and this side must not
    //  race it for the number
    const size_t cbRoom  = p2pseal::SealedSize ( cbPlain,
                                                 p2pseal::kSealMaxReaders );

    std::vector<unsigned char> vSealed ( cbRoom );
    size_t cbSealed = 0;

    p2pseal::SealResult eResult =
      //  TO THE SCOPE, and OpenAppMsgInbound opens from the same accessor -
      //  the two are a matched pair and the address is part of the transcript,
      //  so reading it two different ways fails as if the key were wrong
      pHub -> SealFor ( strSrc, strScope, pMsg->Data ( ), cbPlain,
                        &vSealed[0], cbRoom, &cbSealed );

    if ( eResult == p2pseal::SealOk && cbSealed )
    {
      //  Payload first, marker second.  A half-done seal is then a message
      //  whose marker and body disagree, which fails to open and says so -
      //  rather than a body that looks like application bytes
      pMsg->SetData ( pMsg->c_name ( ), &vSealed[0], (P2Psize_t)cbSealed );
      pMsg->SetSealed ( cbPlain );
      return true;
    }

    // Could not seal - REFUSE
    // NOTES: The opposite of AttestAppMsgOutbound's ending, and deliberately.
    //        There the receiver decides whether unattested traffic is
    //        acceptable and it is the only end that can.  Here the SENDER
    //        already decided, by setting RequireSeal, and the only way to
    //        honour that decision is not to send
    //      : KNOWN GAP, recorded rather than discovered: the application is
    //        told through this diagnostic and not by an undeliverable report.
    //        The reporting path sources a report from this hub and routes it
    //        back, which is a send - and a send that could itself need a seal
    //        it cannot make.  Closing that needs the report to be exempt by
    //        construction rather than by class, which is the mistake F-S9-1
    //        was.  Stage 3 step 20 carries it
    EVERR->Module (__FUNCTION__)->AFPcon(this)
         ->Message(_T("Will not send [%s] scoped to [%s] unsealed: %hs")
                  , pMsg->c_name ( ) ? pMsg->c_name ( ) : L"?"
                  , strScope
                  , p2pseal::SealResultText ( eResult ) )
         ->Advice_T ("Publish an agreement key for the scope, or "
                     "RequireSeal(false).  A BROADCAST is scoped to a SUBTREE "
                     "and no single key opens one; confidential "
                     "broadcast is an open design question")
         ->Display()->SetLast();
    return false;
}

//
//  Opens an inbound application message sealed to this hub
//  NOTES: The counterpart of SealAppMsgOutbound.  Returns to deliver; deletes
//         pMsg and throws to refuse, the same contract GateRelayInbound has
//       : A BODY THIS HUB CANNOT READ IS NOT AN ERROR.  SealErrNotAReader is
//         the relay case - the message is passing through and the reader set
//         did not name us - and it is left sealed and delivered onward.  Only
//         a body that names us and then fails is a refusal
//
//  Parameters:  P2PeerMsg *pMsg
//               Message under test.  Deleted on refusal
//
void
P2PeerCon::OpenAppMsgInbound ( P2PeerMsg *pMsg )
{
    if ( !pMsg || !pMsg->IsSealed ( ) )
      return;

    P2PeerHub *pHub = GetAuthHub ( );
    if ( !pHub )
      return;

    // Is it for us?
    // NOTES: A body in transit is not ours to open even if we could.  The
    //        destination test is the same one the router will apply, asked
    //        early so a relay does no crypto at all
    const P2Paddr oThisHub = GetP2PaddrHub ( );
    CString       strDstHeld = pMsg->GetDestin ( ) ? pMsg->GetDestin ( ) : L"";
    P2PaddrSTR    strDst     = (P2PaddrSTR)strDstHeld;
    if ( oThisHub.IsNull ( ) || !strDst || !*strDst )
      return;
    if ( !( oThisHub == strDst ) )
      return;

    CString    strSrcHeld = pMsg->GetSource ( ) ? pMsg->GetSource ( ) : L"";
    P2PaddrSTR strSrc     = (P2PaddrSTR)strSrcHeld;

    CString    strScopeHeld = pMsg->GetScopeOrDestin ( )
                                ? pMsg->GetScopeOrDestin ( ) : L"";
    P2PaddrSTR strScopeOpen = (P2PaddrSTR)strScopeHeld;

    const size_t cbIn    = pMsg->DataSize ( );
    const size_t cbRoom  = p2pseal::OpenedSize ( cbIn );
    if ( cbRoom == 0 )
    {
      delete pMsg;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Sealed body from [%s] is too short to be one"), strSrc )
           ->Advice_T ("Connection dropped out")
           ->Throw();
      return;
    }

    std::vector<unsigned char> vPlain ( cbRoom );
    size_t cbPlain = 0;

    p2pseal::SealResult eResult =
      //  THE SCOPE, matching what SealAppMsgOutbound sealed to.  The "is it
      //  for us" test above stays on Dst because that is a DELIVERY question
      //  and Dst is the field that answers it; this is the transcript, and the
      //  transcript is what the sender chose.  Identical strings for a unicast
      pHub -> OpenFrom ( strSrc, strScopeOpen,
                         (const unsigned char *)pMsg->Data ( ),
                         cbIn, &vPlain[0], cbRoom, &cbPlain );

    // Not for us to read
    // NOTES: Cannot happen on a body whose DESTINATION is this hub unless the
    //        sender sealed to a key we no longer hold - a rotation that ran
    //        one way.  Refused rather than delivered sealed, because an
    //        application handed a p2pseal block would read it as its own
    //        payload
    if ( eResult == p2pseal::SealOk )
    {
      pMsg->SetData ( pMsg->c_name ( ), &vPlain[0], (P2Psize_t)cbPlain );
      pMsg->ClearSealed ( );
      return;
    }

    delete pMsg;
    EVERR->Module (__FUNCTION__)->AFPcon(this)
         ->Message(_T("Sealed body from [%s] did not open: %hs")
                  , strSrc, p2pseal::SealResultText ( eResult ) )
         ->Advice_T ("Connection dropped out")
         ->Throw();
}

//
//  Decides an application message arriving DOWN a link to an ancestor
//  NOTES: Reached only from GateAppMsgInbound, and only after the descendant
//         test has already failed and the peer has been established to be at
//         or above this hub.  Returns to admit; deletes pMsg and throws to
//         refuse, exactly as its caller does
//       : With RequireRelayAuth(false) - the default - this is the documented
//         exemption and admits unconditionally.  That is the whole of the
//         previous behaviour, kept intact rather than approximated
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message under test.  Deleted on refusal
//
//  NOTES: Takes NO address argument, deliberately.  It used to be handed the
//         source the caller had already read, and off Windows that pointer is
//         a slot in a recycled ring which this function's own accessor calls
//         invalidate before the scope test reads it - so the test ran against
//         the field NAME rather than the address.  It reads the message
//         itself, into its own copy, and cannot be given a stale one
//
void
P2PeerCon::GateRelayInbound ( P2PeerMsg *pMsg )
{
    // Not enforcing?
    // NOTES: No hub means no way to know the policy, and this branch cannot
    //        fail closed on that the way AuthGateInbound does: a login is one
    //        event on a connection that is being set up, an application
    //        message is every message on a connection that already works.
    //        Refusing here would drop live traffic on a state the caller has
    //        already tolerated - GateAppMsgInbound's own permissive cases
    //        (null peer address, null source) are the same judgement
    P2PeerHub *pHub = GetAuthHub ( );
    if ( !pHub || !pHub -> IsRelayAuthRequired ( ) )
      return;

    // Interface address mapping is not supported with relay attestation
    // NOTES: PerformIFaddrTransform() rewrites the addresses on receipt, and
    //        those addresses are what the attestation covers.  Refused for the
    //        same reason and in the same words as AuthGateInbound refuses it,
    //        rather than verifying a transcript the origin never signed
    if ( m_eP2PeerIDmap )
    {
      delete pMsg;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Relay attestation is not supported with interface "
                       "address mapping")
           ->Advice_T ("SetIFaddrTransform(P2PeerIDmap_STATIC), or "
                       "RequireRelayAuth(false)")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }

    // THERE IS NO EXEMPTION HERE ANY MORE, and what used to be one is worth
    // keeping written down because the reason it existed is still true
    // NOTES: Stage 3 step 9 turned this gate ON BY DEFAULT
    //        and p2p_bigreport went red, which was the finding: the library's
    //        OWN undeliverable-message report was sourced from the address
    //        that could not be reached.  A report for [Ghost.Nowhere] arrived
    //        down an ancestor link declaring a source in no branch at all and
    //        carrying no attestation - because nobody holds a key for an
    //        address that does not exist - and that is byte-for-byte the shape
    //        of the attack this gate refuses.  So the report had ALWAYS
    //        depended on the exemption, and p2p_bigreport's own INCONCLUSIVE
    //        text said so before any of this was written.
    //      : The answer taken then was to exempt P2Pmsg_Exception BY CLASS.
    //        Narrower than leaving the ancestor link open, and not free: a
    //        peer on an ancestor link could forge an undeliverable report
    //        claiming ANY source, so an application could be told a message
    //        failed that did not, or handed a fabricated error attributed to
    //        an arbitrary address.  It could not deliver application traffic
    //        that way - everything the P2PeerMsg_MAP dispatches was still
    //        bound - and it was recorded as F-S9-1 rather than left implied.
    //      : F-S9-1 IS NOW CLOSED, AND NOT HERE.  The fix is at the other end
    //        of the path: P2PeerTarget::RouteP2PeerMsg stamps the report with
    //        the address of the hub that RAISED it, so the report declares a
    //        source that hub is entitled to speak for.  One hop down, the
    //        plain descendant test above admits it before this function is
    //        reached.  Further down, AttestAppMsgOutbound signs it as the
    //        origin like any other message this hub sources, and the code
    //        below verifies it with no special case of any kind.
    //      : SO THE CLASS TEST IS GONE, and deleting it is the point rather
    //        than a tidy-up: while it stood, EVERY P2Pmsg_Exception on an
    //        ancestor link was admitted unchecked, and only one of them was
    //        the library's.  p2p_reportsign is the gate - it replays the
    //        pre-fix report shape from a peer not entitled to it and requires
    //        this function to refuse it.

    // Is the SOURCE a hub in this process, on a hub that has waived?
    // NOTES: The receive-side half of the §6.3 waiver, and it must exist or
    //        the send-side half breaks this gate: AttestAppMsgOutbound stops
    //        signing for an in-process destination, and an unsigned message is
    //        exactly what the check below refuses
    //      : KEYED ON THE REGISTRY, NEVER ON THE LINK'S TRUST CLASS, and this
    //        is the part a fast implementation gets wrong.  Keyed on the class
    //        - "it arrived over DMX, so it is ours" - a REMOTE ancestor that
    //        relays into this process would have its unattested traffic
    //        admitted the moment the last hop happened to be in-process.  The
    //        source being a hub THIS PROCESS HOLDS is the fact that has to be
    //        true, and it is the same fact the sender keyed on
    //      : NOT the class exemption the block above describes, and the
    //        difference is the whole of why that one was deleted.  That test
    //        asked what a message was NAMED; this one asks the registry a
    //        question about the process it is running in.  A peer cannot put
    //        itself in this process by choosing a message name
    //      : PLACED AFTER THE IFADDR REFUSAL, deliberately.  Interface address
    //        mapping and relay attestation remain incompatible whatever this
    //        hub has waived - waiving a protection for some destinations must
    //        not make an unsupported configuration look supported for all of
    //        them
    //      : THE RESIDUAL IS THE ASSUMPTION ITSELF, stated rather than hidden:
    //        a remote peer claiming a source that IS an in-process hub is
    //        admitted here.  Under the deployment rule the waiver requires -
    //        in-process hubs form one subtree - such a message cannot arise,
    //        and if that rule does not hold the operator has already accepted
    //        a larger hole on the send side.  Refer
    //        P2PeerHub::WaiveEndToEndInProcess
    if ( pHub -> IsEndToEndWaivedInProcess ( ) )
    {
      CString strSrcWaive = pMsg->GetSource ( ) ? pMsg->GetSource ( ) : L"";
      if ( IsP2PmsgHubInProcess ( (P2PaddrSTR)strSrcWaive ) )
        return;
    }

    // Is there anything to check?
    // NOTES: An absent block is refused, not waved through.  A message with no
    //        attestation is exactly what an ancestor forging a source would
    //        produce, so "none supplied" and "supplied and wrong" have to land
    //        in the same place - they are only distinguished in the log
    size_t      cbAtt = 0;
    const void *pvAtt = pMsg -> GetRelayAttest ( &cbAtt );

    // The addresses the attestation covers are the ones this message carries
    // NOTES: COPIES, not the pointers the accessors return.  Off Windows those
    //        point into a ring of 16 thread-local buffers c_wstr() widens
    //        into, recycled by the next accessor call on this thread - and
    //        there are four accessor calls here.  Refer the same mistake, and
    //        what it cost, in P2PeerHub::RouteP2PeerMsg
    //      : The SCOPE TEST below reads strSrc, this function's own copy. That
    //        test is the whole protection on this link and it must not depend
    //        on a convention two functions away staying true - which is exactly
    //        what failed here on Linux
    //      : THE SCOPE, not Dst, and AttestAppMsgOutbound signs the same
    //        accessor at the other end.  The origin's block is forwarded
    //        untouched by every hop, so anything it covers must survive
    //        re-addressing - and Dst does not.  Refer TMsg_Scp in P2PeerMsg.h;
    //        for a unicast nothing is stamped and this IS GetDestin()
    CString    strSrc  = pMsg->GetSource ( ) ? pMsg->GetSource ( ) : L"";
    CString    strDst  = pMsg->GetScopeOrDestin ( )
                           ? pMsg->GetScopeOrDestin ( ) : L"";
    CString    strName = pMsg->c_name    ( ) ? pMsg->c_name    ( ) : L"";
    CString    strPeer = m_oThatP2Paddr.c_wstr ( );
    CString    strClaimed = strSrc;

    p2pauth::AuthResult eResult = p2pauth::AuthErrFormat;
    long                nSkew   = 0;
    wchar_t             wszAttester[p2pauth::kRelayAttesterMax + 1];
    wszAttester[0] = 0;

    if ( pvAtt && cbAtt )
      eResult = pHub -> VerifyRelay ( (P2PaddrSTR)strSrc, (P2PaddrSTR)strDst
                                    , (P2PaddrSTR)strName
                                    , pMsg->Data ( ), pMsg->DataSize ( )
                                    , (const unsigned char *)pvAtt, cbAtt
                                    , wszAttester
                                    , sizeof(wszAttester)/sizeof(wszAttester[0])
                                    , &nSkew );

    // Verified.  Now the scope test
    // NOTES: THE SAME PREDICATE the descendant link applies, applied to the
    //        identity that signed instead of to the peer that delivered.  A
    //        hub posts for its own sub-targets, so Elsewhere.Peer signing for
    //        Elsewhere.Peer.Widget is legitimate and IsRable admits it - but
    //        Elsewhere.Peer signing for Somewhere.Else is not, and this is
    //        where that is caught.  Without this test a verified signature
    //        from ANY listed peer would launder ANY source, which is the
    //        original hole with an extra step
    if ( eResult == p2pauth::AuthOk )
    {
      P2Paddr oAttester ( wszAttester );
      if ( !oAttester.IsNull ( ) &&
            oAttester.IsRable ( strClaimed ) )
        return;

      delete pMsg;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("Relayed message source [%s] is not at or below its "
                        "attester [%s]")
                    , (P2PaddrSTR)strClaimed, wszAttester )
           ->Advice_T ("The signature is valid - the signer is not entitled "
                       "to that source")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }

    // Refused
    // NOTES: The skew is logged with its sign for the same reason the login
    //        logs it - a clock that is wrong is otherwise indistinguishable
    //        from a key that is
    //      : The RELAYING peer is named as well as the claimed source.  It is
    //        the only party here that is actually identified, and on this path
    //        it is also the party that either forged the source or forwarded
    //        something it should not have
    {
      delete pMsg;
      P2Pevent *pEvent =
        EVERR->Module (__FUNCTION__)->AFPcon(this)
             ->Message(_T("Relayed message from [%s] claiming source [%s] "
                          "refused: %s")
                      , (P2PaddrSTR)strPeer
                      , (P2PaddrSTR)strClaimed
                      , CString(p2pauth::AuthResultText(eResult)).GetString() );
      if ( !pvAtt || !cbAtt )
        pEvent = pEvent -> Advice_T ("No attestation was attached.  The origin "
                                     "must set RequireRelayAuth(true) and hold "
                                     "an identity key");
      else if ( eResult == p2pauth::AuthErrUnknownPeer )
        pEvent = pEvent -> Advice_T ("The attesting identity is not in this "
                                     "hub's allow-list");
      else if ( eResult == p2pauth::AuthErrSkew )
        pEvent = pEvent -> Advice (_T("Origin clock is %ld seconds behind this hub")
                                  , nSkew );
      pEvent -> Advice_T ("Connection dropped out")
             -> Throw();
    }
}

//
//  Signs an outbound application message as its origin
//  NOTES: The counterpart of GateRelayInbound - that gate can only check a
//         signature if something made one.  Refer P2PeerCon.h for why this
//         never refuses to send
//       : Runs on the IO thread at the point the message is taken off this
//         connection's queue, AFTER PerformIFaddrTransform, so the addresses
//         signed are the addresses that go on the wire
//
//  Parameters:  P2PeerMsg *pMsg
//               Message about to be transmitted
//
void
P2PeerCon::AttestAppMsgOutbound ( P2PeerMsg *pMsg )
{
    if ( !pMsg )
      return;

    // Policy
    // NOTES: Gated on the hub REQUIRING attestation rather than merely being
    //        able to sign.  Signing every outbound message on the chance that
    //        some peer might want it is an ECDSA operation per message for a
    //        deployment that asked for none.  Enabling it is tree-wide, the
    //        same way RequireAuth is
    P2PeerHub *pHub = GetAuthHub ( );
    if ( !pHub || !pHub -> IsRelayAuthRequired ( ) || !pHub -> CanAuthSign ( ) )
      return;

    // Handshake traffic is not application traffic
    // NOTES: Login / LoginAck carry their own block and are gated by
    //        AuthGateInbound, which never reaches GateRelayInbound.  Attaching
    //        here would sign a payload the login gate is about to strip
    if ( pMsg->Map_MatchName ( P2Pmsg_Login    ) ||
         pMsg->Map_MatchName ( P2Pmsg_LoginAck ) ||
         pMsg->Map_MatchName ( P2Pmsg_CypherEx )    )
      return;

    // Already attested?
    // NOTES: This is the relay case, and it is the common one: the block
    //        belongs to the ORIGIN and every hop in between must forward it
    //        untouched.  A relaying hub that re-signed would be substituting
    //        its own authority for the one the receiver is trying to check
    if ( pMsg->HasRelayAttest ( ) )
      return;

    // Entitlement
    // NOTES: A hub may only attest for a source at or below itself - the same
    //        IsRable test the receiving gate will apply to the result.
    //        Checking it here as well is not redundancy for its own sake: it
    //        is what stops a hub emitting a block that cannot possibly be
    //        accepted, which would be indistinguishable at the far end from an
    //        attack
    const P2Paddr oThisHub = GetP2PaddrHub ( );
    if ( oThisHub.IsNull ( ) || !pMsg->GetSource ( ) )
      return;
    if ( !oThisHub.IsRable ( pMsg->GetSource ( ) ) )
      return;

    // Sign
    // NOTES: COPIES again - four accessors, one recycled buffer ring
    //      : THE SCOPE, not Dst.  The block below is forwarded untouched by
    //        every hop (the HasRelayAttest early-out above says why), so what
    //        it digests has to be something re-addressing cannot change.  Dst
    //        is not: a fanned-out copy was refused at the far end with
    //        "signature does not verify" and the LINK DROPPED - measured,
    //        p2p_sealbcast phase 3.  GateRelayInbound reads the same accessor,
    //        and for a unicast both are GetDestin()
    CString  strHub  = oThisHub.c_wstr ( );
    CString  strSrc  = pMsg->GetSource ( );
    CString  strDst  = pMsg->GetScopeOrDestin ( )
                         ? pMsg->GetScopeOrDestin ( ) : L"";
    CString  strName = pMsg->c_name    ( ) ? pMsg->c_name    ( ) : L"";

    // Is the destination a hub in THIS process, on a hub that has waived?
    // NOTES: The other half of the §6.3 waiver, and it is placed AFTER the
    //        entitlement test above rather than before it deliberately: a hub
    //        that may not attest for this source must not reach a state where
    //        turning the waiver on is what stopped it signing.  The two
    //        outcomes are the same message on the wire and completely
    //        different postures, and only one of them is a decision
    //      : Reads strDst - GetScopeOrDestin, the same accessor the signature
    //        covers and the same one SealAppMsgOutbound seals to.  Refusing
    //        scoped messages here for the reason given there: a subtree is not
    //        a hub, and this process cannot vouch for one
    //      : AFTER THE FOUR COPIES, and not between them and the accessors
    //        they come from.  The block above is one group for a reason its
    //        own note gives - off Windows those accessors return slots in a
    //        recycled ring of 16 thread-local buffers - and putting a test
    //        with its own accessor calls in the middle of that group is the
    //        mistake GateRelayInbound's header records having already been
    //        made once.  Four CString copies on a message about to skip a
    //        468 us signature is not a trade worth thinking about
    //      : SILENT, unlike the "could not sign" ending below.  A waived
    //        message is not a failure to attest, it is a decision not to, and
    //        an operator who wants to see it reads WaiveE2E off TryReadPosture
    if ( !pMsg->HasScope ( ) && pHub -> IsEndToEndWaivedInProcess ( ) )
    {
      if ( IsP2PmsgHubInProcess ( (P2PaddrSTR)strDst ) )
        return;
    }

    unsigned char aBlock[p2pauth::kRelayMaxLen];
    size_t        cbBlock = 0;
    p2pauth::AuthResult eResult =
      pHub -> AttestRelay ( (P2PaddrSTR)strHub
                          , (P2PaddrSTR)strSrc, (P2PaddrSTR)strDst
                          , (P2PaddrSTR)strName
                          , pMsg->Data ( ), pMsg->DataSize ( )
                          , aBlock, sizeof(aBlock), &cbBlock );

    if ( eResult == p2pauth::AuthOk && cbBlock )
    {
      pMsg -> SetRelayAttest ( aBlock, cbBlock );
      return;
    }

    // Could not sign
    // NOTES: Reported once and loudly, then the message goes anyway.  The
    //        receiver decides whether unattested traffic is acceptable, and it
    //        is the only end that can - see the header.  SetLast() keeps a
    //        misconfigured hub from turning one bad key into one log line per
    //        message
    EVWRN->Module (__FUNCTION__)->AFPcon(this)
         ->Message(_T("Could not attest [%s] as origin [%s]: %s")
                  , (P2PaddrSTR)strSrc, (P2PaddrSTR)strHub
                  , CString(p2pauth::AuthResultText(eResult)).GetString() )
         ->Advice_T ("A peer requiring relay attestation will refuse this "
                     "message")
         ->Display()->SetLast();
}

void
P2PeerCon::AuthGateInbound ( P2PeerMsg *pMsg, bool bAck )
{
    // No governing hub, no way to know whether proof is required
    // NOTES: Refused rather than waved through.  A login arriving on a
    //        connection with no hub link is anomalous in its own right -
    //        that link is how the connection reaches everything - and
    //        "I could not determine the policy" must never resolve to
    //        "then there is no policy".  This is the branch that makes
    //        a lost link fail CLOSED
    P2PeerHub *pHub = GetAuthHub ( );
    if ( !pHub )
    {
      delete pMsg;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Login on a connection with no governing P2PeerHub: "
                       "cannot establish whether authentication is required")
           ->Advice_T ("PostP2PeerCon() before the login sequence")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }

    // Not enforcing?
    // NOTES: A hub that requires nothing verifies nothing, and behaviour
    //        is byte-identical to a tree without this feature.
    //      : KeyXWanted() and NOT IsAuthRequired(), since the per-class link
    //        policy landed.  There are now two ways to reach "this link does
    //        not authenticate" - the hub's switch is off, or the hub has
    //        relaxed the class this link belongs to - and the INITIATING side
    //        already read both through KeyXWanted().  Asking the narrower
    //        question here would demand a signature on a link whose peer was
    //        told not to make one, which is F-S6-1 with the halves swapped
    if ( !KeyXWanted ( ) )
    {
      // A peer that signs to a hub which does not require authentication
      // gets its block handed to the application, because stripping
      // follows verification and nothing else.  The stock On_ConLogin
      // then refuses the payload loudly ("contains login data").  Named
      // here so the log identifies the misconfiguration rather than
      // leaving that message to be puzzled over.
      //
      // The two ways of arriving here need different advice, because the
      // second one is not a misconfiguration on this hub at all: the peer's
      // hub has this link in a class it still requires authentication on, and
      // ours does not.  Naming the class is what lets an operator find the
      // half that disagrees rather than re-reading the half that does not.
      if ( pMsg && pMsg->DataSize ( ) > 0 &&
           p2pauth::AuthPolicy::LooksLikeBlock ( pMsg->Data ( )
                                               , (size_t)pMsg->DataSize ( ) ) )
      {
        if ( AuthLinkRelaxed ( ) )
          EVWRN->Module (__FUNCTION__)->AFPcon(this)
               ->Message(_T("Peer sent a login auth block on a link this hub "
                            "has relaxed (trust class %d)")
                        , (int)EffectiveTrust ( ) )
               ->Advice_T ("SetLinkPolicy(class, P2PeerLinkPolicy_Open) on the "
                           "peer as well, or Full here")
               ->Display()->SetLast();
        else
          EVWRN->Module (__FUNCTION__)->AFPcon(this)
               ->Message_T("Peer sent a login auth block, but this hub does "
                           "not require authentication")
               ->Advice_T ("RequireAuth(true) on this hub, or stop signing "
                           "on the peer")
               ->Display()->SetLast();
      }
      return;
    }

    // ...and it requires the CHANNEL it authenticates on
    // NOTES: Stage 6 step 17, and the gate is
    //        p2p_authchannel. SECURITY.md calls the session cypher and the
    //        signed login "one switch on purpose", and on the INITIATING side
    //        they are - KeyXWanted() drives both. On this side they were not.
    //      : Two conditions in this file are independent and read as one.
    //        KeyXWanted() asks "does my hub require authentication" and decides
    //        whether the agreement runs. CanAuthSign() asks "do I hold an
    //        identity key" and decides whether a login is SIGNED. A hub with
    //        RequireAuth(false) holding a key - the ordinary state of a peer
    //        provisioned for somewhere else in the tree - therefore signed a
    //        login it had no channel to bind to, and the verification below
    //        passed `m_bKeyXBound ? m_KeyXBind : 0`, so BOTH ends computed the
    //        same NULL-binding transcript and the signature verified. The
    //        result was an authenticated session in CLEARTEXT on a hub whose
    //        operator had set RequireAuth(true), reported as a normal login
    //      : Two things were lost, not one. Confidentiality is the obvious
    //        half. The other is the reason kVersion moved from 1 to 2: v2 binds
    //        the proof to the connection it was made on, and a null binding
    //        names no connection, so for that session the binding was not in
    //        the transcript at all - which is exactly the proof-forwarding the
    //        version exists to refuse
    //      : Uniform over login and ack. On the client an ack can only arrive
    //        after LoginSend(), and Login() defers that until KeyXOnAck, so a
    //        client whose hub requires authentication always has the agreement
    //        behind it. There is no legitimate arrival here without one
    //      : This refuses a peer that used to be accepted, and says so. Under
    //        the versioning policy that is a MINOR-bump break while MAJOR is
    //        0, and it is the intended one: the alternative is a switch whose
    //        two halves can be separated by whoever is on the other end
    if ( KeyXWanted ( ) && !m_bKeyXDone )
    {
      delete pMsg;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message(_T("%s arrived with no session key agreement on a hub "
                        "that requires authentication")
                    , bAck ? _T("Login acknowledgement") : _T("Login") )
           ->Advice_T ("The peer signed without exchanging keys, so its proof "
                       "names no connection and the wire is in clear")
           ->Advice_T ("RequireAuth(true) on the peer as well, or "
                       "RequireAuth(false) here and mean it")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }

    // Interface address mapping is not supported with authentication
    // NOTES: PerformIFaddrTransform() rewrites the addresses on receipt,
    //        and those addresses are what the signature covers.  Rather
    //        than verify a transcript the peer never signed - which would
    //        fail confusingly, or worse, succeed - the combination is
    //        refused outright until the fractal path is signed too.
    if ( m_eP2PeerIDmap )
    {
      delete pMsg;
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message_T("Authenticated login is not supported with "
                       "interface address mapping")
           ->Advice_T ("SetIFaddrTransform(P2PeerIDmap_STATIC), or "
                       "RequireAuth(false)")
           ->Advice_T ("Connection dropped out")
           ->Throw();
    }

    // The addresses the signature covers are the ones on the wire
    // NOTES: src and dst, not this and that - which are opposite words at
    //        the two ends of one connection.
    //       : COPIES, not the pointers the accessors return.  On Linux those
    //         point into a ring of 16 thread-local buffers c_wstr() widens
    //         into, recycled by the next accessor call on this thread; these
    //         two have to survive as far as AuthVerifyLogin/Ack below, and
    //         they ARE the transcript the signature covers.  See the same
    //         mistake, and what it cost, in P2PeerHub::RouteP2PeerMsg.
    CString    strSrc = pMsg ? pMsg->GetSource ( ) : (P2PaddrSTR)0;
    CString    strDst = pMsg ? pMsg->GetDestin ( ) : (P2PaddrSTR)0;
    P2PaddrSTR pSrc   = pMsg ? (P2PaddrSTR)strSrc : 0;
    P2PaddrSTR pDst   = pMsg ? (P2PaddrSTR)strDst : 0;

    p2pauth::AuthResult eResult = p2pauth::AuthErrFormat;
    long                nSkew   = 0;
    const unsigned char *pIn    = 0;
    size_t               cbIn   = 0;
    if ( pMsg && pMsg->DataSize ( ) > 0 )
    {
      pIn  = (const unsigned char *)pMsg->Data ( );
      cbIn = (size_t)pMsg->DataSize ( );
    }

    if ( !pSrc || !pDst || !pIn )
      eResult = p2pauth::AuthErrFormat;    // no block at all -> refused
    else if ( !bAck )
    {
      unsigned char aNonce[16];
      eResult = pHub -> AuthVerifyLogin ( pSrc, pDst, pIn, cbIn
                                        , aNonce, &nSkew
                                        , m_bKeyXBound ? m_KeyXBind : 0 );
      if ( eResult == p2pauth::AuthOk )
      {
        memcpy ( m_AuthNonce, aNonce, sizeof(m_AuthNonce) );
        m_bAuthNonce  = true;
        m_cbAuthStrip = p2pauth::kAuthLoginLen;
        //  WHO this connection is now proven to be (F-S6-2). Recorded HERE
        //  and nowhere else: this is the one point at which a signature has
        //  verified over a transcript, and strSrc is the address that
        //  transcript covered - not the address the peer asked to be called,
        //  which is set long before any of this and for every connection
        m_oAuthPeer = P2Paddr ( pSrc );
      }
    }
    else if ( !m_bAuthNonce )
    {
      // An acknowledgement for a login this connection never signed.
      eResult = p2pauth::AuthErrArgs;
    }
    else
    {
      eResult = pHub -> AuthVerifyAck ( pSrc, pDst, m_AuthNonce, pIn, cbIn
                                      , m_bKeyXBound ? m_KeyXBind : 0 );
      if ( eResult == p2pauth::AuthOk )
      {
        m_cbAuthStrip = p2pauth::kAuthAckLen;
        //  The ack comes FROM the peer that answered this connection's login,
        //  so its source is the identity the acknowledgement verified as -
        //  the same field, filled at the other end of the same exchange
        m_oAuthPeer   = P2Paddr ( pSrc );
      }
    }

    if ( eResult == p2pauth::AuthOk )
      return;

    // Refused
    // NOTES: The skew is logged with its sign, because a clock that is
    //        wrong is otherwise indistinguishable from a key that is -
    //        and it is NOT sent back to the peer, which has proven
    //        nothing at this point.
    {
      P2Paddr oClaimed ( pSrc ? pSrc : L"" );
      delete pMsg;
      P2Pevent *pEvent =
        EVERR->Module (__FUNCTION__)->AFPcon(this)
             ->Message(_T("%s login from [%s] refused: %s")
                      , bAck ? _T("Acknowledged") : _T("Claimed")
                      , oClaimed.c_wstr ( )
                      , CString(p2pauth::AuthResultText(eResult)).GetString() );
      if ( eResult == p2pauth::AuthErrSkew )
        pEvent = pEvent -> Advice (_T("Peer clock is %ld seconds behind this hub")
                                  , nSkew );
      pEvent -> Advice_T ("Connection dropped out")
             -> Throw();
    }
}

//
//  Perform login sequence with P2PeerCon object within remote P2PeerHub
//  NOTES: First connection message exchanged and initiates P2Paddr
//         negotiations.  Logically object must be connected
//       : Upon receipt the remote P2PeerHub will process the request
//         via OnLogin(), respond via LoginAck(), which in turn
//         will be procesed via OnLoginAck() within this object
//       : 3rd Party type interfaces MUST simulate above exchange.
//
//
//  Parameters:  P2PaddrSTR strThatP2Paddr
//               Optionally assigned address of remote client
//                 0.. Empty, adopt currently assigned address
//                 ?.. Adopt passed remote client identification
//
//               const void *pvLoginMsg
//               Login message as supplied to remote P2PeerCon object
//
//               P2Psize_t iSize
//               Size of above message
//
//  Returns:     BOOL
//               Success summary
//                 true... Successfully queued request
//                 false.. Operation failed. Refer GetLastEvent()
//                         for further details
//
void
P2PeerCon::Login ( P2PaddrSTR strThatP2Paddr
                 , const void *pvLoginMsg, P2Psize_t iSize )
{
    // Introduce locals
    P2Paddr oThatP2Paddr(strThatP2Paddr);
    if ( oThatP2Paddr.IsNull() )
      oThatP2Paddr = m_oThatP2Paddr;

//if(strThatP2Paddr==~0)
//strThatP2Paddr=0;//FIX-ME default value should be 0
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Connect) &&
         !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept)     )
      EVERR->Module (__FUNCTION__)->AFPcon(this)->AFP(strThatP2Paddr)->AFP(iSize)
           ->Message("Requires ON_P2PeerCon_CONNECT, ACCEPT handler state")
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // To be sure, to be sure
    /*if (       oP2Paddr.IsNull() &&
         m_oThatP2Paddr.IsNull()    )
      EVERR->MODULE
           ->Message(L"Remote P2PeerHub has null P2Paddr[%s]"
                    , (P2PaddrSTR)oP2Paddr )
           ->Throw();*/

    // To be sure, to be sure
    /*if (    !oP2Paddr.IsNull()        &&
          !m_oThatP2Paddr.IsNull()    &&
           m_oThatP2Paddr != oP2Paddr    )
      EVERR->MODULE
           ->Message(L"Attempt to swap remote P2Paddr from [%s] to [%s]"
                    , (P2PaddrSTR)m_oThatP2Paddr
                    , (P2PaddrSTR)oP2Paddr )
           ->Throw();*/

    if ( !oThatP2Paddr.IsNull() )
      m_oThatP2Paddr = oThatP2Paddr;

    // Session key agreement runs first
    // NOTES: The application called this from its On_ConConnect handler and
    //        must not have to know that an exchange precedes its login, so
    //        the payload is parked and sent when the agreement completes
    //        (refer KeyXOnAck).  A hub that requires no authentication runs
    //        no exchange and falls straight through
    if ( KeyXWanted ( ) && !m_bKeyXDone )
    {
      delete [] m_pLoginDefer;
      m_pLoginDefer  = 0;
      m_cbLoginDefer = 0;
      if ( iSize > 0 && pvLoginMsg )
      {
        m_pLoginDefer  = new unsigned char [ (size_t)iSize ];
        memcpy ( m_pLoginDefer, pvLoginMsg, (size_t)iSize );
        m_cbLoginDefer = (size_t)iSize;
      }
      m_bLoginDefer = true;
      KeyXBegin ( );
      return;
    }

    LoginSend ( pvLoginMsg, iSize );
    return;
}

//
//  Builds and posts the login message
//  NOTES: Split out of Login() so the deferred path can reach it without
//         re-running the pump-state checks, which belong to the handler
//         Login() was called from and are false by the time the key
//         agreement completes on the IO thread
//
void
P2PeerCon::LoginSend ( const void *pvLoginMsg, P2Psize_t iSize )
{
    // Peer login authentication
    // NOTES: The auth block is PREPENDED to whatever the application
    //        passed, and the receiving side hides it again before the
    //        application sees the payload (refer P2Pwin32.cpp,
    //        P2PSig_ConLogin).  Prepending rather than adding a named
    //        field keeps the wire image of a login message exactly as it
    //        was, and keeps the block invisible to app code that walks
    //        the node.  Refer P2PAuthLogin.h
    //      : Signed with the addresses this message CARRIES, so the two
    //        ends agree on the transcript without either having to
    //        reason about whose "this" is whose "that".
    //      : ...and with the channel binding when a key agreement ran, so
    //        the proof names THIS connection and is worthless on any other
    //      : NOT signed on a link whose class this hub has relaxed.  There is
    //        no agreement on such a link by intent, so a block built here
    //        would pass a null binding into the transcript and name no
    //        connection - which is the exact state F-S6-1 was, arrived at
    //        deliberately instead of by accident.  A hub with
    //        RequireAuth(false) is untouched by this test: refer
    //        AuthLinkRelaxed()
    //      : A std::vector and not a raw new[].  The P2PeerMsg below
    //        copies this buffer and CAN throw doing it, and the delete
    //        that followed the construction was not reached when it did
    std::vector<unsigned char> vAuthBuf;
    const void    *pvSendMsg  = pvLoginMsg;
    P2Psize_t      iSendSize  = iSize;
    P2PeerHub     *pAuthHub   = GetAuthHub ( );
    if ( pAuthHub && pAuthHub -> CanAuthSign ( ) && !AuthLinkRelaxed ( ) )
    {
      unsigned char       aBlock[p2pauth::kAuthLoginLen];
      p2pauth::AuthResult eAuth =
        pAuthHub -> AuthBuildLogin ( GetP2PaddrHub().c_wstr()
                                   , m_oThatP2Paddr.c_wstr()
                                   , aBlock, sizeof(aBlock), m_AuthNonce
                                   , m_bKeyXBound ? m_KeyXBind : 0 );
      if ( eAuth != p2pauth::AuthOk )
        EVERR->Module (__FUNCTION__)->AFPcon(this)
             ->Message(_T("Could not sign the login: %s")
                      , CString(p2pauth::AuthResultText(eAuth)).GetString() )
             ->Advice_T ("Identity key loaded with SetIdentity()?")
             ->Throw();

      m_bAuthNonce = true;
      vAuthBuf.resize ( p2pauth::kAuthLoginLen + (size_t)iSize );
      memcpy ( &vAuthBuf[0], aBlock, p2pauth::kAuthLoginLen );
      if ( iSize > 0 && pvLoginMsg )
        memcpy ( &vAuthBuf[0] + p2pauth::kAuthLoginLen
               , pvLoginMsg, (size_t)iSize );
      pvSendMsg = &vAuthBuf[0];
      iSendSize = (P2Psize_t)( p2pauth::kAuthLoginLen + (size_t)iSize );
    }

    // Implementation
    // NOTES: Logon acknowledgement is posted directly to the
    //        output queue.
    //      : The message is held in a P2PeerMsgSP until PostP2PeerMsg()
    //        has taken it.  That call can throw BEFORE the queue holds
    //        the message - AssertValid() under g_bP2Pmsg_AssertValid,
    //        and the list insert - and the raw new leaked on both
    //        paths.  Dereference() hands ownership on once it cannot
    P2PeerMsgSP spMsg = new P2PeerMsg ( GetP2PaddrHub(), m_oThatP2Paddr
                                      , P2Pmsg_Login
                                      , pvSendMsg, iSendSize );
    PostP2PeerMsg ( spMsg.p_SafePtr ( ) );
    spMsg.Dereference ( );

    // Tidy up, and
    return;
}

void
P2PeerCon::Login_Fractal ( P2PaddrSTR strThisP2Paddr1, P2PaddrSTR strThatP2Paddr1
                         , const void *pvLoginMsg, P2Psize_t iSize )
{
    // Introduce locals
    P2Paddr oThisP2Paddr1(strThisP2Paddr1);
    if ( oThisP2Paddr1.IsNull() )
      oThisP2Paddr1 = m_oThisP2Paddr1;
    P2Paddr oThatP2Paddr1(strThatP2Paddr1);
    if ( oThatP2Paddr1.IsNull() )
      oThatP2Paddr1 = m_oThatP2Paddr1;

//if(strThatP2Paddr==~0)
//strThatP2Paddr=0;//FIX-ME default value should be 0
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Connect) &&
         !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept)     )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->AFP(strThisP2Paddr1)->AFP(strThatP2Paddr1)->AFP(iSize)
           ->Message("Requires ON_P2PeerCon_CONNECT, ACCEPT handler state")
           ->Throw  ( );

    // To be sure, to be sure
    /*if (       oP2Paddr.IsNull() &&
         m_oThatP2Paddr.IsNull()    )
      EVERR->MODULE
           ->Message(L"Remote P2PeerHub has null P2Paddr[%s]"
                    , (P2PaddrSTR)oP2Paddr )
           ->Throw();*/

    // To be sure, to be sure
    /*if (    !oP2Paddr.IsNull()        &&
          !m_oThatP2Paddr.IsNull()    &&
           m_oThatP2Paddr != oP2Paddr    )
      EVERR->MODULE
           ->Message(L"Attempt to swap remote P2Paddr from [%s] to [%s]"
                    , (P2PaddrSTR)m_oThatP2Paddr
                    , (P2PaddrSTR)oP2Paddr )
           ->Throw();*/

    if ( !oThisP2Paddr1.IsNull() )
      m_oThisP2Paddr1 = oThisP2Paddr1;
    if ( !oThatP2Paddr1.IsNull() )
      m_oThatP2Paddr1 = oThatP2Paddr1;
    m_eP2PeerIDmap = P2PeerIDmap_FRACTAL;

    // Implementation
    // NOTES: Logon acknowledgement is posted directly to the
    //        output queue.
    //      : Held in a P2PeerMsgSP for the reason given in LoginSend() -
    //        PostP2PeerMsg() can throw before the queue takes the
    //        message, and the raw new leaked when it did
    P2PeerMsgSP spMsg = new P2PeerMsg ( GetP2PaddrHub(), m_oThatP2Paddr
                                      , P2Pmsg_Login
                                      , pvLoginMsg, iSize );
    PostP2PeerMsg ( spMsg.p_SafePtr ( ) );
    spMsg.Dereference ( );

    // Tidy up, and
    return;
}

//
//  Performs login request processing
//  NOTES: Default processing for remote client Login() request
//       : Processing cycle is completed via subsequent
//         LoginAck() response.
//
//
//  Parameters:  const P2Paddr oThatP2Paddr
//               Assigned remote identification address
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote client identification
//
void
P2PeerCon::OnLogin ( const P2Paddr& oThatP2Paddr )
{
//if(strThatP2Paddr==~0)
//strThatP2Paddr=0;//FIX-ME default value should be 0
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Login) )
      EVERR->Module (__FUNCTION__)
           ->AFP(oThatP2Paddr)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_LOGIN handler state\n"
                     "ADVICE\t: Bug (SNHappen)" )
           ->Throw  ( );

    // Selected timers
    CancelP2PmsgTimer ( m_uLoginTimerID );

    // To be sure, to be sure
    // NOTES: P2Paddr is mandatory at this stage
    if (   oThatP2Paddr.IsNull() &&
         m_oThatP2Paddr.IsNull()    )
      EVERR->Module (__FUNCTION__)
           ->AFP(oThatP2Paddr)->AFPcon(this)
           ->Message(L"Null remote P2Paddr[%s]"
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Throw();

    // To be sure, to be sure
    // NOTES: P2Paddr MUST have previously been assigned to the hub
    P2Paddr oP2PaddrHub = GetP2Paddress();
    if ( oP2PaddrHub.IsNull() )
      EVERR->Module (__FUNCTION__)
           ->AFP(oThatP2Paddr)->AFPcon(this)
           ->Message("Null local P2PmsgHub address" )
           ->Throw();

    // To be sure, to be sure
    // NOTES: Passed strP2Paddr MUST exist within the P2Paddr domain
    //        assigned to this P2PeerCon
    //LPCTSTR str1=oThatP2Paddr;
    //LPCTSTR str2=m_oThatP2Paddr;
    //LPCTSTR str3=m_oP2Padomain;
    // NB: only enforce the domain check when a domain is actually configured.
    // An unconfigured (empty) m_oP2Padomain means "no restriction" — the Dmx
    // ServiceFactory never assigns one, and IsMapped() over an empty domain
    // relies on the (uninitialised) m_bWildcard, which happens to read true
    // under the Windows debug 0xCD heap-fill but is 0 on Linux. Guarding on
    // IsNull() makes the permissive case explicit and identical on both OSes
    // (on Windows the empty case already passed, so behaviour is unchanged).
    if (   !oThatP2Paddr.IsNull()              &&
         !m_oThatP2Paddr.IsNull()              &&
         !m_oP2Padomain.IsNull()               &&
         !m_oP2Padomain.IsMapped(oThatP2Paddr)     )
      EVERR->Module (__FUNCTION__)
           ->AFP(oThatP2Paddr)->AFPcon(this)
           ->Message(_T("Login P2Paddr[%s] is not within domain [%s]")
                    ,   oThatP2Paddr.c_wstr()
                    , m_oP2Padomain.c_wstr() )
           ->Throw();

    // Assignment
    if ( !oThatP2Paddr.IsNull() )
      m_oThatP2Paddr = oThatP2Paddr;

    // Tidy up, and
    SetState ( ConState_Login, 0 );
    return;
}

//
//  Perform login acknowledgement to complete remote client integration
//  NOTES: Usually performed in the ON_P2PeerCon_LOGIN() handler.
//
//
//  Parameters:  P2PaddrSTR strThatP2Paddr
//               Identification address assigned to the remote client
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote client identification
//
//               void *pvLoginAck
//               Login message
//
//               P2PeerSize_t iSize
//               Size of above message
//
//  Returns:     BOOL
//               Success summary
//                 TRUE... Successfully queued request
//                 FALSE.. Operation failed. Refer P2Pevent::GetLast()
//                         for further details
//
BOOL
P2PeerCon::LoginAck ( const P2Paddr& oThatP2Paddr
                    , const void *pvLoginAck, P2Psize_t iSize )
{
    // Introduce locals
    BOOL bResult = TRUE;

//if(strThatP2Paddr==~0)
//strThatP2Paddr=0;//FIX-ME default value should be 0

    // To be sure, to be sure
    if (   oThatP2Paddr.IsNull() &&
         m_oThatP2Paddr.IsNull()    )
      EVERR->Module (__FUNCTION__)
           ->AFP(oThatP2Paddr)->AFP(iSize)->AFPcon(this)
           ->Message("Remote hub has null P2Paddr")
           ->Advice (_T("P2PeerCon=[%s->null]")
                    , GetP2PaddrHub().c_wstr() )
           ->Group("P2P")->Throw();

    // To be sure, to be sure
    if ( GetP2PaddrHub().IsNull()  )
      EVERR->Module (__FUNCTION__)
           ->AFP(oThatP2Paddr)->AFP(iSize)->AFPcon(this)
           ->Message("Local hub has null P2Paddr")
           ->Advice (_T("P2PeerCon=[null->%s]")
                    , m_oThatP2Paddr.c_wstr() )
           ->Group("P2P")->Throw();

    // Accepted P2Paddr assignment
    // NOTES: Such P2Paddr's may be auto-assigned from the domain
    //      : This assignment deliberately bypasses the swap check below -
    //        an accepted connection IS allowed to take the address the
    //        acknowledgement carries - so the domain test is the safety on
    //        that bypass, and it had been commented out.  Enabled here
    //      : Guarded on IsNull() for the reason recorded at the OnLogin
    //        twin: an unconfigured domain means "no restriction", and
    //        IsMapped() over an empty one reads uninitialised state.  The
    //        commented original lacked that guard, so enabling it verbatim
    //        would have refused every unconfigured connection
    //      : The trace no longer casts pvLoginAck to int - a truncating
    //        cast on x64, and the pointer value said nothing
    //      : Covered by DirectExamples/LoginAckDomainTest, and by nothing
    //        else in that suite.  Reaching this block takes a handler that
    //        acknowledges with an address of its own choosing: the default
    //        chain forwards whatever the peer sent, so where no address is
    //        sent the outer IsNull() skips the block, and where one IS sent
    //        OnLogin's own domain check throws before LoginAck is called
    if (  m_eP2PeerConMode == P2PeerCon_Accept &&
           !oThatP2Paddr.IsNull()              &&
         !m_oThatP2Paddr.IsNull()                 )
    {
      if (  !m_oP2Padomain.IsNull()               &&
            !m_oP2Padomain.IsMapped(oThatP2Paddr)    )
        EVERR->Module (L"%hs(%s,%i)", __FUNCTION__
                      , m_oThatP2Paddr.c_wstr(), iSize )
             ->Message(L"LoginAck P2Paddr[%s] is not within domain [%s]"
                      ,   oThatP2Paddr.c_wstr()
                      , m_oP2Padomain.c_wstr() )
             ->Advice (L"P2PeerCon=[%s->%s]"
                      , GetP2PaddrHub().c_wstr(),m_oThatP2Paddr.c_wstr() )
             ->Advice ("Connection mis-match" )
             ->Advice ("Attempted security breach" )
             ->Group("P2P")->Throw();
      m_oThatP2Paddr = oThatP2Paddr;
    }

    // To be sure, to be sure
    if (   !oThatP2Paddr.IsNull()          &&
         !m_oThatP2Paddr.IsNull()          &&
          m_oThatP2Paddr !=   oThatP2Paddr &&
          m_oThatP2Paddr != GetP2PaddrHub()   )
      EVERR->Module (__FUNCTION__)
           ->AFP(oThatP2Paddr)->AFP(iSize)->AFPcon(this)
           ->Message(L"Attempt to swap P2PeerID's from [%s] to [%s]"
                    , (P2PaddrSTR)m_oThatP2Paddr
                    , (P2PaddrSTR)  oThatP2Paddr )
           ->Group("P2P")->Throw();

    if ( !oThatP2Paddr.IsNull() )
      m_oThatP2Paddr = oThatP2Paddr;

    // Peer login authentication
    // NOTES: The acknowledgement signs the nonce the CLIENT just sent, so
    //        it authenticates this hub to that client and is itself not
    //        replayable - mutual proof, still one round trip.  Only
    //        produced when a login block was actually verified on this
    //        connection (m_bAuthNonce), because there is otherwise no
    //        nonce to bind and an unbound signature would prove nothing.
    //      : Owned by a std::vector for the reason given in LoginSend()
    std::vector<unsigned char> vAuthBuf;
    const void    *pvSendAck = pvLoginAck;
    P2Psize_t      iSendSize = iSize;
    P2PeerHub     *pAuthHub  = GetAuthHub ( );
    if ( m_bAuthNonce && pAuthHub && pAuthHub -> CanAuthSign ( ) )
    {
      unsigned char       aBlock[p2pauth::kAuthAckLen];
      p2pauth::AuthResult eAuth =
        pAuthHub -> AuthBuildAck ( GetP2PaddrHub().c_wstr()
                                 , m_oThatP2Paddr.c_wstr()
                                 , m_AuthNonce, aBlock, sizeof(aBlock)
                                 , m_bKeyXBound ? m_KeyXBind : 0 );
      if ( eAuth != p2pauth::AuthOk )
        EVERR->Module (__FUNCTION__)->AFPcon(this)
             ->Message(_T("Could not sign the login acknowledgement: %s")
                      , CString(p2pauth::AuthResultText(eAuth)).GetString() )
             ->Advice_T ("Identity key loaded with SetIdentity()?")
             ->Throw();

      vAuthBuf.resize ( p2pauth::kAuthAckLen + (size_t)iSize );
      memcpy ( &vAuthBuf[0], aBlock, p2pauth::kAuthAckLen );
      if ( iSize > 0 && pvLoginAck )
        memcpy ( &vAuthBuf[0] + p2pauth::kAuthAckLen
               , pvLoginAck, (size_t)iSize );
      pvSendAck = &vAuthBuf[0];
      iSendSize = (P2Psize_t)( p2pauth::kAuthAckLen + (size_t)iSize );
    }

    // Implementation
    // NOTES: Logon acknowledgement is posted directly to the
    //        output queue.
    //      : Held in a P2PeerMsgSP for the reason given in LoginSend() -
    //        PostP2PeerMsg() can throw before the queue takes the
    //        message, and the raw new leaked when it did
    P2PeerMsgSP spMsg = new P2PeerMsg ( GetP2PaddrHub().c_wstr()
                                      , m_oThatP2Paddr.c_wstr()
                                      , P2Pmsg_LoginAck
                                      , pvSendAck, iSendSize );
    PostP2PeerMsg ( spMsg.p_SafePtr ( ) );
    spMsg.Dereference ( );

    // Tidy up, and
    SetState ( ConState_Login, 0 );
    return bResult;
}

//
//  Process login acknowledgement to complete P2PeerCon integration
//  with remote P2PeerHub
//  NOTES: Usually performed in the ON_P2PeerCon_LOGINACK() handler.
//       : Observes interface addressing style, refer SetIFaddrTransform()
//         for further details
//
//
//  Parameters:  const P2Paddr oThisP2Paddr
//               Remotely assigned or adopted identification address of
//               peer to which this P2PeerCon object is posted
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote P2PeerHub address
//
//               const P2Paddr oThatP2Paddr
//               Remotely assigned or adopted identification address of
//               peer to which this P2PeerCon object is connected
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote P2PeerHub address
//
void
P2PeerCon::OnLoginAck ( const P2Paddr& oThisP2Paddr
                      , const P2Paddr& oThatP2Paddr )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_LoginAck) )
      EVERR->MODULE->AFP(oThisP2Paddr)->AFP(oThatP2Paddr)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_LOGINACK handler state")
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Observe selected interface mapping
    switch ( m_eP2PeerIDmap )
    {
      // None
      case P2PeerIDmap_NONE:
        break;

      // Static interface mapping
      case P2PeerIDmap_STATIC:
        OnLoginAck_Static ( oThisP2Paddr, oThatP2Paddr );
        return;

      // Static interface mapping
      case P2PeerIDmap_FRACTAL:
        OnLoginAck_Fractal ( oThisP2Paddr, oThatP2Paddr );
        return;

      // Unknown type
      default:
        EVERR->MODULE->AFP(oThisP2Paddr)->AFP(oThatP2Paddr)->AFPcon(this)
             ->Message("Unknown interface mapping (%i)"
                      , m_eP2PeerIDmap )
             ->Advice ("Bug (SNHappen)")
             ->Throw();
    }

//if(strThisP2Paddr==~0)
//strThisP2Paddr=0;//FIX-ME default value should be 0

    // To be sure, to be sure
    if (     oThisP2Paddr.IsNull() &&
          GetP2PaddrHub().IsNull()    )
      EVERR->MODULE->AFP(oThisP2Paddr)->AFP(oThatP2Paddr)->AFPcon(this)
           ->Message(L"Local P2PeerHub has null P2Paddr[%s]"
                    , GetP2PaddrHub().c_wstr() )
           ->Throw();

    // To be sure, to be sure
    if (   !oThisP2Paddr.IsNull()         &&
         !GetP2PaddrHub().IsNull()        &&
          GetP2PaddrHub() != oThisP2Paddr    )
      EVERR->MODULE->AFP(oThisP2Paddr)->AFP(oThatP2Paddr)->AFPcon(this)
           ->Message(L"Attempt to swap P2Paddr's from [%s] to [%s]"
                    , GetP2PaddrHub().c_wstr()
                    , oThisP2Paddr.c_wstr() )
           ->Throw();

    if ( !oThisP2Paddr.IsNull() )
      m_pP2PeerTarget -> GetP2PeerHub() -> SetP2PaddrHub ( oThisP2Paddr );
    //m_oThisP2Paddr = oThisP2Paddr;

    // Tidy up, and
    SetState ( ConState_Login, 0 );
}

//
//  Process static interface login acknowledgement to complete
//  P2PeerCon address integration with remote P2PeerHub
//  NOTES: Usually performed in the ON_P2PeerCon_LOGINACK() handler
//       : Confirms IFaddrTrans_STATIC interface addressing style,
//         refer SetIFaddrTransform() for further details.  Swaps to such
//         style if existing style set to IFaddrTrans_NONE
//
//
//  Parameters:  const P2Paddr oThisP2Paddr1
//               This or the local P2Paddr.  Defines our P2PeerHub in
//               another P2Peer virtual network for which we have no
//               knowledge of structure.  Substituted for the source
//               address on out-going messages
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote client identification
//
//               const P2Paddr oThatP2Paddr1
//               That or the remote P2Paddr.  Defines a P2PeerHub in
//               another P2Peer virtual network for which we have no
//               knowledge of structure.  Substituted for the
//               destination address on out-going messages
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote client identification
//
void
P2PeerCon::OnLoginAck_Static ( const P2Paddr& oThisP2Paddr1
                             , const P2Paddr& oThatP2Paddr1 )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_LoginAck) )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_LOGINACK handler state" )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Interface addressing style confirmation
    if ( m_eP2PeerIDmap != P2PeerIDmap_STATIC &&
         m_eP2PeerIDmap != P2PeerIDmap_NONE      )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message("Incompatible interface address styles (%i vs %i)"
                    , m_eP2PeerIDmap, P2PeerIDmap_STATIC )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // This P2Paddr
    // NOTES: The other virtual network must have assigned a valid
    //        non-null P2Paddr to this peer
    if (   oThisP2Paddr1.IsNull() &&
         m_oThisP2Paddr1.IsNull()    )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message(L"Remotely assigned this P2Paddr[%s] is null"
                    , (P2PaddrSTR)m_oThisP2Paddr1 )
           ->Throw();

    // That P2Paddr
    // NOTES: The other virtual network must have assigned a valid
    //        non-null P2Paddr to that peer
    if (    oThatP2Paddr1.IsNull() &&
          m_oThatP2Paddr1.IsNull()     )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message(L"Remotely assigned that P2Paddr[%s] is null"
                    , (P2PaddrSTR)m_oThatP2Paddr1 )
           ->Throw();

    // Persist
    // NOTES: Thereafter all P2PeerMsg's will have their source and
    //        destination P2Paddr's re-assigned upon send and receive
    if ( !oThisP2Paddr1.IsNull() )
      m_oThisP2Paddr1 = oThisP2Paddr1;
    if ( !oThatP2Paddr1.IsNull() )
      m_oThatP2Paddr1 = oThatP2Paddr1;
    m_eP2PeerIDmap = P2PeerIDmap_STATIC;

    // Default attributes
    SetState ( ConState_Login, 0 );
}

//
//  Process fractal interface login acknowledgement to complete
//  P2PeerCon address integration with remote P2PeerHub
//  NOTES: Usually performed in the ON_P2PeerCon_LOGINACK() handler
//       : Confirms IFaddrTrans_FRACTAL interface addressing style,
//         refer SetIFaddrTransform() for further details.  Swaps to such
//         style if existing style set to IFaddrTrans_NONE
//
//
//  Parameters:  const P2Paddr oThisP2Paddr1
//               This or the local P2Paddr.  Defines our P2PeerHub in
//               another P2Peer virtual network for which we have no
//               knowledge of structure.  Substituted for the source
//               address on out-going messages
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote client identification
//
//               const P2Paddr oThatP2Paddr1
//               That or the remote P2Paddr.  Defines a P2PeerHub in
//               another P2Peer virtual network for which we have no
//               knowledge of structure.  Substituted for the
//               destination address on out-going messages
//                 0.. Retain existing identification
//                 ?.. Adopt passed remote client identification
//
void
P2PeerCon::OnLoginAck_Fractal ( const P2Paddr& oThisP2Paddr1
                              , const P2Paddr& oThatP2Paddr1 )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_LoginAck) )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_LOGINACK handler state" )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Interface addressing style confirmation
    if ( m_eP2PeerIDmap != P2PeerIDmap_FRACTAL &&
         m_eP2PeerIDmap != P2PeerIDmap_NONE       )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message("Incompatible interface address styles (%i vs %i)"
                    , m_eP2PeerIDmap, P2PeerIDmap_STATIC )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // This P2Paddr
    // NOTES: The other virtual network must have assigned a valid
    //        non-null P2Paddr to this peer
    if (   oThisP2Paddr1.IsNull() &&
         m_oThisP2Paddr1.IsNull()     )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message(L"Remotely assigned this P2Paddr[%s] is null"
                    , (P2PaddrSTR)m_oThisP2Paddr1 )
           ->Throw();

    // That P2Paddr
    // NOTES: The other virtual network must have assigned a valid
    //        non-null P2Paddr to that peer
    if (    oThatP2Paddr1.IsNull() &&
          m_oThatP2Paddr1.IsNull()     )
      EVERR->MODULE->AFP(oThisP2Paddr1)->AFP(oThatP2Paddr1)->AFPcon(this)
           ->Message(L"Remotely assigned that P2Paddr[%s] is null"
                    , (P2PaddrSTR)m_oThatP2Paddr1 )
           ->Throw();

    // Persist
    // NOTES: Thereafter all P2PeerMsg's will have their source and
    //        destination P2Paddr's re-assigned upon send and receive
    if ( !oThisP2Paddr1.IsNull() )
      m_oThisP2Paddr1 = oThisP2Paddr1;
    if ( !oThatP2Paddr1.IsNull() )
      m_oThatP2Paddr1 = oThatP2Paddr1;
    m_eP2PeerIDmap = P2PeerIDmap_FRACTAL;

    // Default attributes
    SetState ( ConState_Login, 0 );
}

//
//  Restarts connection after nominated delay
//  NOTES: Operation is usually performed from within
//         P2PeerCon_CLOSE handlers
//
//
//  Parameters:  P2Pmsecs_t uiMSecDelay
//               Millisecond restart delay
//
//
//  Returns:     P2PeerTime_t
//               Restart time in milliseconds
//
P2Pmsecs_t
P2PeerCon::Restart ( P2Pmsecs_t uiMSecDelay )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Close) )
      EVERR->Module (__FUNCTION__)
           ->AFP(uiMSecDelay)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_CLOSE handler state" )
           ->Message("Bug (SNHappen)" )
           ->Throw  ( );

    // Mode confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( m_eP2PeerConMode != P2PeerCon_CLIENT  &&
         m_eP2PeerConMode != P2PeerCon_SERVICE     )
      EVERR->Module (__FUNCTION__)
           ->AFP(uiMSecDelay)->AFPcon(this)
           ->Message("Requires Connect or Service mode" )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Event state
    // NOTES: Previously latched P2Pevent's MUST have been cleared
    if ( m_pEvent )
      EVERR->Module (__FUNCTION__)
           ->AFP(uiMSecDelay)->AFPcon(this)
           ->Message("Attempt to restart connection with uncleared event" )
           ->Advice ("OnClose() processing not performed" )
           ->Throw  ( );

    // Flagged destruction
    if ( PostDestroyState() )
      EVERR->Module (__FUNCTION__)
           ->AFP(uiMSecDelay)->AFPcon(this)
           ->Message("Attempt to restart destroyed connection" )
           ->Advice ("Refer PostDestroyState() for further details" )
           ->Throw  ( );


    // Connection restart time
    // NOTES: Trigger processing cycle for the hub
    P2Pmsecs_t iRestartTime = _time64(0)*1000 + uiMSecDelay;
    CancelP2PmsgTimer ( m_uRestartTimerID );
    m_uRestartTimerID = SetPITimer ( uiMSecDelay );

    // To be sure, to be sure
    if ( m_uRestartTimerID <= 0 )
    {
      m_uRestartTimerID = 0;
      EVERR->Module (__FUNCTION__)
           ->AFP(uiMSecDelay)->AFPcon(this)
           ->Message("Failed to set restart timer" )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );
    }

    // Tidy up, and
    return iRestartTime;
}

//
//  Initiates close connection processing for object.
//  NOTES: May be referenced from On_P2PeerCon_STARTUP, and
//         ACCEPT handlers.
//
void
P2PeerCon::Close  ( )
{
    // State
    SetState ( 0, ON_ConClose );

    // Implementation
    PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Close
               , this, (P2PeerMsg *)0, m_hCPortP2PumpID  );
}

//
//  Performs default ON_P2PeerCon_CLOSE() handler processing
//  NOTES: Closed connections may be Restart()'ed
//       : Usually performed from ON_P2PeerCon_CLOSE() handlers
//
//
//  Returns:     conRESULT
//               Connection handler result code
//
conRESULT
P2PeerCon::OnClose ( )
{
    // Locals
    conRESULT conResult = conHANDLED;

    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    SetState ( 0, ON_ConClose );
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Close) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_CLOSE handler state" )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Selected timers
    CancelP2PmsgTimer ( m_uLoginTimerID );
    CancelP2PmsgTimer ( m_uThrottleTimerID );

    // Display precipitating event
    // NOTES: Skip event display when remote connection drops out
    //      : Always discard event.  Such events MUST be discarded
    //        as part of the ON_P2PeerCon_CLOSE() handler processing
    if ( m_pEvent )
    {
      bool bDisplay = !HasDroppedOut ( m_pEvent->GetHRESULT() );
      m_pEvent = m_pEvent -> Cancel ( bDisplay );
    }
 
    // Reflect all internally queued messages as undeliverable
    // NOTES: Handle any buffered P2PeerMsg's first.
    while ( m_pP2PeerMsgSend              ||
            m_oCListMsgQue.GetCount() > 0    )
    {
      // Isolate undeliverable P2PeerMsg
      P2PeerMsgSP spP2PeerMsg;
      if ( m_pP2PeerMsgSend )
      {
        spP2PeerMsg = m_pP2PeerMsgSend;
                      m_pP2PeerMsgSend = 0;
      }
      else
        spP2PeerMsg = GetP2PeerMsg();

ASSERT(!spP2PeerMsg.IsEmpty());
ASSERT(AfxCheckMemory());     // (was a Sleep(100)-bracketed heap-corruption probe;
spP2PeerMsg->AssertValid();   //  spP2PeerMsg holds a ref, so no async free window)
      // Implementation
      // NOTES: Deliver P2PeerMsg exception back to source
      P2Pevent *pEVT =
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message("Undeliverable message")
           ->Advice ( "Connection closed" )
           ->HResult(P2Pevent_UNDELIVERABLE)
           ->Group("P2P");

    /*PostP2Pmsg ( GetP2Paddr(), CN_P2PeerMsg, 0
                 ,(P2PeerCon *)0
                 , spP2PeerMsg->ExceptionFactory(pEVT)  );FIX-ME Activate*/
      spP2PeerMsg = 0;                 // Control garbage collection
      pEVT -> Cancel ( false );
    }

    // Tidy up and
    if ( PostDestroyState() )
      conResult = conDROP;
    return conResult;
}

//
//  Initiates shutdown processing for object.
//  NOTES: May be referenced from On_P2PeerCon_CLOSE,
//         ????????? and ???????? handlers.
//
void
P2PeerCon::Shutdown  ( )
{
    // State
    SetState ( 0, ON_ConShutdown );

    // Implementation
    PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Shutdown
               , this, (P2PeerMsg *)0, m_hCPortP2PumpID  );
}

//
//  Performs default ON_P2PeerCon_SHUTDOWN() handler processing
//  NOTES: Closed connections may be Restart()'ed
//       : Usually performed from ON_P2PeerCon_CLOSE() handlers
//
//
//  Returns:     conRESULT
//               Handler result
//
BOOL
P2PeerCon::OnShutdown ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    SetState ( 0, ON_ConShutdown );
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Shutdown) )
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message("Requires ON_P2PeerCon_SHUTDOWN handler state")
           ->Throw  ( );

    // Selected timers
    CancelP2PmsgTimer ( m_uLoginTimerID );
    CancelP2PmsgTimer ( m_uThrottleTimerID );

    // Display precipitating event
    // NOTES: Skip event display when remote connection drops out
    //      : Always discard event.  Such events MUST be discarded
    //        as part of the ON_P2PeerCon_CLOSE() handler processing
    if ( m_pEvent )
    {
      bool bDisplay = !HasDroppedOut ( m_pEvent->GetHRESULT() );
      m_pEvent = m_pEvent -> Cancel ( bDisplay );
    }
 
    // Reflect all internally queued messages as undeliverable
    // NOTES: Handle any buffered P2PeerMsg's first.
    while ( m_pP2PeerMsgSend              ||
            m_oCListMsgQue.GetCount() > 0    )
    {
      // Isolate undeliverable P2PeerMsg
      P2PeerMsgSP spP2PeerMsg;
      if ( m_pP2PeerMsgSend )
      {
        spP2PeerMsg = m_pP2PeerMsgSend;
                      m_pP2PeerMsgSend = 0;
      }
      else
        spP2PeerMsg = GetP2PeerMsg();

ASSERT(!spP2PeerMsg.IsEmpty());
      // Implementation
      // NOTES: Deliver P2PeerMsg exception back to source
      P2Pevent *pEVT =
      EVERR->Module (__FUNCTION__)->AFPcon(this)
           ->Message("Undeliverable message")
           ->Advice ("Connection closed" )
           ->HResult(P2Pevent_UNDELIVERABLE)
           ->Group("P2P");

    /*PostP2Pmsg ( GetP2Paddr(), CN_P2PeerMsg, 0
                 ,(P2PeerCon *)0
                 , spP2PeerMsg->ExceptionFactory(pEVT)  );FIX-ME Activate*/
      spP2PeerMsg = 0;                 // Control garbage collection
      pEVT -> Cancel ( false );
    }

    // Tidy up and
    return conDROP;
}

///////////////////////////////////////////////////////////////////////
//  Utilities

//
//  Performs interface address mapping
//  NOTES: Override this method to provide 3rd party mapping
//         alternatives.  Refer SetIFaddrTransform() for further details
//       : Should mapping be considered necessary.  Then by
//         convention it is performed by the peer actively pursuing
//         the connection.  The peer accepting the connection remains
//         passive
//
//
//  Parameters:  bool bSoR
//               Receive (true=1nput) or send (false=0utput) mapping flag
//             
//               P2PeerMsg *pMsg
//               Message to be mapped
void
P2PeerCon::PerformIFaddrTransform ( BOOL bSoR, P2PeerMsg *pMsg )
{
    // Optimise
    if ( m_eP2PeerIDmap == P2PeerIDmap_NONE )
      return;

    // Introduce locals
    //P2PeerMsgHdr *pHdr = (P2PeerMsgHdr *)pMsg->Message();

    // Friendly interface mapping
    // NOTES: Facilitates friendly inter-P2Peer network address mapping
    //        whereby either side indirectly exposes internal 
    if ( m_eP2PeerIDmap == P2PeerIDmap_STATIC )
    {
      // P2PeerMsg receive mapping
      if ( bSoR )
      {
        //pHdr -> nWsamapID = pHdr -> nSourceID;
        //pHdr -> nSourceID = m_oThatP2Paddr;
        //pHdr -> strDestin = m_oThisP2Paddr;
        pMsg -> SetSource ( m_oThatP2Paddr );
        pMsg -> SetDestin ( GetP2PaddrHub() );
      }

      // P2PeerMsg send mapping
      else
      {
        //pHdr -> nSourceID = m_nThisP2PeerID1;
        //pHdr -> strDestin = m_nThatP2PeerID1;
        //if ( pHdr->nWsamapID )
        //  pHdr -> strDestin = pHdr -> nWsamapID;
        pMsg -> SetSource ( m_oThisP2Paddr1 );
        pMsg -> SetDestin ( m_oThatP2Paddr1 );
        if ( _tcslen(pMsg->GetConmap()) > 0 )
          pMsg -> SetDestin ( pMsg->GetConmap() );
      }
    }

    // Fractal interface mapping
    // NOTES: Push addressing and substitute on the way out, simply
    //        pop on the way in
    //      : Should security be an issue you would never use this style
    else if ( m_eP2PeerIDmap == P2PeerIDmap_FRACTAL )
    {
      // P2PeerMsg receive mapping
      if ( bSoR )
      {
        if ( pMsg->r_Source().IsStacked() )
          pMsg -> r_Source().r_Stck().Pop();
        else
          pMsg -> SetSource(m_oThatP2Paddr);
        if ( pMsg->r_Destin().IsStacked() )
          pMsg -> r_Destin().r_Stck().Pop();
        else
          pMsg -> SetDestin(GetP2PaddrHub().c_wstr());
      }
      // P2PeerMsg send mapping
      else
      {
        LPCTADDR lpszThisP2Paddr = m_oThisP2Paddr1.c_wstr();
        pMsg->r_Source().r_Stck().Push().r_data().c_memcpy(lpszThisP2Paddr,0);
        LPCTADDR lpszThatP2Paddr = m_oThatP2Paddr1.c_wstr();
        pMsg->r_Destin().r_Stck().Push().r_data().c_memcpy(lpszThatP2Paddr,0);
      }
    }

    // Wrapped messages
    // NOTES: Recursive implementation
    if ( pMsg->IsWrapped() )
      PerformIFaddrTransform ( bSoR, &(*pMsg)[1] );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerCon_MAP routing
//  NOTES: Used for P2PeerCon routing and handler assignment

/*bool
P2PeerCon::MAP_MatchName ( const P2Pmsg_t nMapWildcard )
{
    // Translation
    const char *pszMapWildcard = 0;
    if ( nMapWildcard == ~0 )
      pszMapWildcard = "*";
    else
      pszMapWildcard = (*g_fptrEncodeP2PeerID) ( nMapWildcard );

    // Delegate
    return MAP_MatchName ( pszMapWildcard );
}*/

//
//  Description: P2PeerCon_MAP name matching utility
//               NOTES: Internal P2Peer path is matched against the
//                      passed P2PeerCon_MAP wildcard
//                    : Example 1 (Backwards connection)
//                        Hub1/Hub2/whatever, matches wildcards
//                           */Hub2/whatever, and
//                                */whatever, and
//
//
//  Parameters:  P2PaddrSTR pszMapWildcard
//               P2PeerHub name wildcard
//
//  Returns:     bool
//                 true... Connection matches wildcard
//                 false.. No match
//
/*bool
P2PeerCon::MAP_P2Paddr ( P2PaddrSTR pszMapWildcard )
{
    // Preparation
    bool  star   = false;
    const char *pszHub = m_oThatP2Paddr.c_wstr();

    // Implmentation
Top:
    const char *p, *s;
    for ( s = pszHub, p = pszMapWildcard; *s; ++s, ++p )
    {
      switch (*p) {
         case '?':
            if (*s == '.') goto starCheck;
            break;
         case '*':
            star = TRUE;
            pszHub = s, pszMapWildcard = p;
            if (!*++pszMapWildcard) return TRUE;
            goto Top;
         default:
            //if (mapCaseTable[*s] != mapCaseTable[*p])
            if (*s != *p )
               goto starCheck;
            break;
      }
   }
   if (*p == '*') ++p;
   return (!*p);

starCheck:
   if (!star) return FALSE;
   pszHub++;
   goto Top;
}*/

//
//  Description: L4Caddr matching utility
//               NOTES:
//
//
//  Parameters:  P2PaddrSTR strP2PaddrThat
//               Remote connection address to be mapped against
//               contained L4Caddr
//
//  Returns:     bool
//                 true... Matched
//                 false.. No match
//
/*bool
P2PeerCon::MAP_L4Caddr ( P2PaddrSTR strP2PaddrThat )
{
    // Introduce the locals
    char        *pFormat   = (char *)m_oThatP2Paddr.c_wstr();
    P2Parser     oL4Caddr( (char *)strP2PaddrThat );
    P2Parser    *m_pClpEnv = &oL4Caddr;
    va_list      ap;
    char        *pCompleted = m_pClpEnv -> m_pCompleted;
    int          nMatched   = 0;

    // Loop until passed format exhausted
    while ( *pFormat )
    {
LPCTSTR lpszCommand=m_pClpEnv->m_pCommand;//DELETE-ME
LPCTSTR lpszCompleted=m_pClpEnv->m_pCompleted;//DELETE-ME
      // Alternative sequences field
      if ( *pFormat == '<' )
      {
        pFormat++;                   // Consume '<' character
        m_pClpEnv = m_pClpEnv -> Push ( m_pClpEnv -> m_pCommand
                                      , 0
                                      , m_pClpEnv -> m_pCommand );

        m_pClpEnv -> m_eFCF    = '<';
        m_pClpEnv -> m_eSeqNum =  0;

        m_pClpEnv = m_pClpEnv -> Push ( 0, 0, 0 );
        continue;
      }

      // Numeric range field
      if ( *pFormat == '#' )
      {
        pFormat++;                     // Consume '#' character
        int iBegin = strtol ( pFormat, &pFormat, 10 );
        if ( *pFormat != '-' )
          EVERR->MODULE
               ->Message("M4Caddr '#n-n' missing '-' delimiter" )
               ->Advice (L"L4Caddr=[%s]", m_oThatP2Paddr.c_wstr() )
               ->Throw();
        pFormat++;                     // Consume '-' character
        int iEnd   = strtol ( pFormat, &pFormat, 10 );
        int iNum;
        if ( !m_pClpEnv->GetINT(iNum)    &&
             !m_pClpEnv -> m_bOptional   &&
              m_pClpEnv -> m_eFCF != '<'    )
          return false;                // Matching failed
        if ( iNum < iBegin ||
             iNum > iEnd      )
        {
          if ( !m_pClpEnv -> m_bOptional   &&
                m_pClpEnv -> m_eFCF != '<'    )
            return false;
        }
        continue;
      }

      // Manage optional logic
      // NOTES: Any sequence contained between '[...]' characters
      if ( *pFormat == '[' )
      {
        pFormat++;                       // Consume '[' character
        m_pClpEnv = m_pClpEnv -> Push ( 0
                                      , 0
                                      , m_pClpEnv -> m_pCommand );
        m_pClpEnv -> m_bOptional = true; // Flag optional logic
        continue;
      }

      if ( *pFormat == ']' )
      {
        pFormat++;                       // Consume ']' character
        if ( !m_pClpEnv -> m_bOptional )
          EVERR->MODULE
               ->Message("M4Caddr ']' mismatch" )
               ->Throw();
        m_pClpEnv = m_pClpEnv -> Pop ( 0
                                     , 0
                                     , m_pClpEnv -> m_pCommand );
        continue;
      }

      // Tokens
      // NOTES: Any field bounded by the delimiters {...|...|...}
      if ( *pFormat == ',' ||
           *pFormat == '>'    )
      {
        if ( m_pClpEnv -> m_eFCF != '<' )
          EVERR->MODULE
               ->Message("Mismatching { , , } delimiters")
               ->Advice (L"L4Caddr=[%s]", m_oThatP2Paddr.c_wstr() )
               ->Throw();

        // Matching field flagged by skip mode not set
        if ( !m_pClpEnv -> m_bSkip )
        {
lpszCommand=m_pClpEnv->m_pCommand;//DELETE-ME
lpszCompleted=m_pClpEnv->m_pCompleted;//DELETE-ME
          m_pClpEnv = m_pClpEnv -> Pop (  0
                                       , m_pClpEnv -> m_pCommand
                                       , m_pClpEnv -> m_pCheckpoint );
lpszCommand=m_pClpEnv->m_pCommand;//DELETE-ME
lpszCompleted=m_pClpEnv->m_pCompleted;//DELETE-ME

          if ( m_pClpEnv -> m_nEnumItem >= 0 )
            EVERR->MODULE
                 ->Message(L"Command sequence (%s) is not unique"
                          , m_pClpEnv -> m_pCommand )
                 ->Group("CLP")->Throw();

          m_pClpEnv -> m_nEnumItem = m_pClpEnv -> m_eSeqNum;
          nMatched++;
        }

        // Non-matching field flagged by skip mode being set
        else
          m_pClpEnv = m_pClpEnv -> Pop ( 0, 0, 0 );

        // End of token, start of new token
        // NOTES: Move command pointer back to checkpoint position
        if ( *pFormat == ',' )
        {
          pFormat++;                   // Consume '|' character
          m_pClpEnv -> m_eSeqNum++;    // This sequence number
          m_pClpEnv = m_pClpEnv -> Push ( 0
                                        , 0
                                        , m_pClpEnv -> m_pCheckpoint );
          continue;
        }

        // End of token sequence
        // NOTES: Confirm one of the enumerates matched
        if ( *pFormat == '>' )
        {
          pFormat++;                   // Consume '}' character
          if (  m_pClpEnv -> m_nEnumItem < 0 &&
               !m_pClpEnv -> m_bOptional        )
            return false;

          m_pClpEnv = m_pClpEnv -> Pop ( 0
                                       , 0
                                       , m_pClpEnv -> m_pCompleted );
lpszCommand=m_pClpEnv->m_pCommand;//DELETE-ME
lpszCompleted=m_pClpEnv->m_pCompleted;//DELETE-ME
          continue;
        }
      }

      // Pattern matching is the default
      if ( *pFormat == '\\' )
        pFormat++;

      if ( !m_pClpEnv -> m_bSkip )     // Not if skip mode is on
      {
        if ( !isalnum(*pFormat)       &&
                      *pFormat != '.'    )
          EVERR->MODULE
               ->Message("Invalid L4Caddr character[%c]"
                        , *pFormat )
               ->Advice (L"L4Caddr=[%s]", m_oThatP2Paddr.c_wstr() )
               ->Throw();

        if ( toupper( (int)*pFormat )
                         == toupper ( (int)*(m_pClpEnv->m_pCommand) ) )
        {
          pFormat++;                   // Consume character
          m_pClpEnv -> m_pCommand++;
          continue;
        }

        if ( m_pClpEnv -> m_bOptional        ||
             m_pClpEnv -> m_eFCF      == '<'    )
        {
          m_pClpEnv -> m_bSkip = 1;    // Activate skip flag
          pFormat++;                   // Consume character
          continue;
        }

        // Matching failed
        return false;
      }
      pFormat++;                       // Increment format position
    }

    // Tidy up, and
    if ( m_pClpEnv -> m_nLevel != 0 )
      EVERR->MODULE
           ->Message("Parsing level (%i) did not return to zero"
                    , m_pClpEnv -> m_nLevel )
           ->Throw();
    return true;
}*/

///////////////////////////////////////////////////////////////////////
//  P2PeerCon_MAP routing
//  NOTES: Used for P2PeerCon routing and handler assignment


//
//  Description: 
//
//
//  Parameters:  const char *pszMsgWildcard
//               Message wildcard
//
//  Returns:     bool
//                 true... Message matches wildcard
//                 false.. No match
//
/*bool
P2PeerCon::Map_MatchP2PeerID ( P2PeerID_ nMapID, P2PeerID_ nSourceID )
{
    // Mask matching
    if ( (nMapID&M4Cbit) == M4Cbit )
    {
      nSourceID |= M4Cbit;
      if ( (nMapID | nSourceID) == nMapID    &&
           (nMapID & nSourceID) == nSourceID    )
        return true;
    }

    // Address matching
    if ( (nMapID&M4Cbit) != M4Cbit )
    {
      if ( nMapID == nSourceID )
        return true;
    }

    // No Match
    return false;
}*/

///////////////////////////////////////////////////////////////////////
//  Property management

//
//  Exposes P2Paddr for this connection
//  NOTES: By convention the P2Paddr of P2PeerCon objects is the
//         P2Paddr of the P2PeerHub for which the connection is being
//         managed
//
//
//  Returns:     P2Paddr&
//               Identification assigned to this P2PeerCon object.
//               NOTES: May be empty
//
const P2Paddr&
P2PeerCon::GetP2Paddress ( )
{
    // Simply
    return m_oThatP2Paddr;
}

const P2Padomain&
P2PeerCon::GetP2Padomain ( ) const
{
    return m_oP2Padomain;
}

//
//  Sets the P2Paddr of this P2PeerCon object
//  NOTES: Usually the P2Paddr of a P2PeerHub is assigned at creation
//         time.  However, under some circumstances such as negotiating
//         a console connection P2Paddr need to be set dynamically by
//         the server.
//
//
//  Parameters:  P2Paddr nThisP2PaddrSTR
//               New P2PeerHub identification code.
//               NOTES: The passed P2PaddrSTR must maintain the child
//                      relationship with P2PeerHub parent and
//                      parent relationship with any P2PeerHub
//                      children
//
//  Returns:     bool
//               Success summary
//                 true... Successfully re-addressed
//                 false.. Operation failed. Refer GetLastEvent()
//                         for further details
//
BOOL
P2PeerCon::SetP2Paddr ( P2PaddrSTR oThisP2PaddrSTR )
{
    // Simply
    // NOTES: Listening objects have equivalent m_oThisP2Paddr and
    //        m_oThatP2Paddr's
    if ( !GetP2PaddrHub().IsNull()          &&
          GetP2PaddrHub() == m_oThatP2Paddr    )
      m_oThatP2Paddr = oThisP2PaddrSTR;
    m_pP2PeerTarget -> GetP2PeerHub() -> SetP2PaddrHub ( oThisP2PaddrSTR );

    // Tidy up and
    return TRUE;
}

const P2Paddr
P2PeerCon::GetP2PaddrHub ( ) const
{
    // Simply
    if ( m_nP2PconID )
      return P2Paddr ( GetP2PmsgHubAddr(this) );
    return P2Paddr ( L"" );
}

//const P2Paddr&
//P2PeerCon::GetThatP2Paddr ( ) const
//{
//    // Simply
//    return m_oThatP2Paddr;
//}

void
P2PeerCon::SetIFaddrTransform ( P2PeerIDmap_e eIFaddrTrans )
{
    // Simply
    m_eP2PeerIDmap = eIFaddrTrans;
}

void
P2PeerCon::SetP2Peerio  ( P2Peerio *pP2Peerio )
{
    // Simply
    delete m_pP2Peerio;
           m_pP2Peerio = 0;
           m_pP2Peerio = pP2Peerio -> Register ( this );
}

P2Peerio*
P2PeerCon::GetP2Peerio ( )
{
    // Simply
    return m_pP2Peerio;
}

DWORD
P2PeerCon::SetState ( DWORD dwAdd, DWORD dwRemove )
{
    // Apply
    m_dwState &= ~dwRemove;
    m_dwState |=  dwAdd;

    // Tidy up, and
    return m_dwState;
}

DWORD
P2PeerCon::GetState ( DWORD dwMask )
{
    // Simply
    return m_dwState & dwMask;
}

bool
P2PeerCon::HasState ( DWORD dwStateMask )
{
    // Simply
    return ( (m_dwState & dwStateMask)==dwStateMask )
           ? true
           : false;
}

//
//  Fetch P2PeerCon connection mode
//
//
//  Returns:     P2PeerConMode_e
//               Object mode
P2PeerConMode_e
P2PeerCon::GetMode ( )
{
    // Simply
    return m_eP2PeerConMode;
}

DWORD_PTR
P2PeerCon::GetUDState ( )
{
   ASSERT(0);                          // Expected to be specialised
   return 0;
}

P2Pevent*
P2PeerCon::SetP2Pevent ( P2PeventSP& spP2Pevent )
{
   if ( m_pEvent )
     m_pEvent -> Cancel ( false );
   m_pEvent = spP2Pevent.Dereference ( );
   return m_pEvent;
}
P2Pevent*
P2PeerCon::GetP2Pevent ( )
{
   return m_pEvent;
}

//
//  Summarises connection failure
//  NOTES: Expectation is that the derived class will provide an
//         implementation specialised for physical layer
//
//  Parameters:  HRESULT hr
//               Precipitating error as returned from WriteFile(),
//               ReadFile()
//
//  Returns:     bool
//               Connection failure summary
//                 true... Remote failure
//                 false.. Local failure
bool
P2PeerCon::HasDroppedOut ( HRESULT /*hr*/ )
{
    // Default action
    return false;
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerCon::AssertValid ( ) const
{
    // Firstly delegate
    P2PeerConPlc::AssertValid ( );

    // IOCP completion key
    // NOTES: Very problematic should the value be corrupted
    ASSERT ( m_dwCompletionKey == (UINT_PTR)this );

    // TODO: Additional validation
}

//
//  Generates Visual Runtime Summary for P2PeerCon instance
//  FORMAT: [P2PeerCon Hub=Name, Con=Name, Domain=Domain]
//        : Such brief summaries are used to pass brief P2PeerCon state
//          information to P2Pevent's
//
//
//  Returns:     LPCTSTR
//               Pointer to encoded P2PeerCon summary
//               NOTES: (Re-)Encoded upon each reference
//
LPCTSTR
P2PeerCon::GetVisualRTSummary ( )
{
    // Container
    if ( !m_pstrVisualSummary )
      m_pstrVisualSummary = new CString ( );

    // Simply encode header
    m_pstrVisualSummary
      -> Format ( L"[P2PeerCon Hub=%s, Con=%s, Domain=%s]"
                , GetP2PaddrHub().c_wstr()
                , GetP2Paddress().c_wstr()
                , GetP2Padomain().c_wstr() );

    // Tidy up and
    return *m_pstrVisualSummary;
}

//
//  Generates state snapshot for this P2PeerCon instance
//  NOTES: Such summaries are used to inject P2PeerCon state information
//         P2PeerMsg's and P2Pevent's etc
//
//  Parameters:  LPCTSTR lpszVar
//               Name assigned to the generated P3PmsgNode
//
//  Returns:     P3PmsgNode
//               Snapshot instance
//
P3PmsgItem
P2PeerCon::SetP2PeventFParams ( LPCTNAM lpszVar )
{
    // Create a placeholder for receipt of P2PeerCon details
    // NOTES: This will be passed by value back up the stack
    if ( lpszVar == nullptr )
      lpszVar = L"P2PeerCon";
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData(m_nP2PconID)) );

    // Convention is to delegate to base class first
    //oNodeVar += __super::SetP2PeventFParams ( 0 );

    // Append our state to node
    oNodeVar += P3PmsgField ( L"m_oThisP2Paddr", DataWSTR16(GetP2PaddrHub().c_wstr()) );
    oNodeVar += P3PmsgField ( L"m_oThatP2Paddr", DataWSTR16(GetP2PaddrHub().c_wstr()) );
    oNodeVar += P3PmsgField ( L"m_oP2Padomain", DataWSTR16(GetP2Padomain().c_wstr()) );
    oNodeVar += P3PmsgField ( L"m_nP2PconID", P3PmsgData(m_nP2PconID) );

    // Tidy up and
    return oNodeVar;
}
//
//  Is this connection's traffic actually going through a cypher?
//  NOTES: F-S6-2. Asked of the io object rather than
//         answered from m_bKeyXDone, and the difference is the whole point:
//         m_bKeyXDone says the agreement completed and a cypher was POSTED,
//         and P2Peerio::IsCypherActive says the class holding it consults it.
//         For every wire transport those are the same answer; for DMX they are
//         not, and F-S6-3 is the finding that nothing makes them agree by rule
//       : No io object is not an error here - a connection that has not been
//         given one has no cypher, which is the true answer and not a fault
//         worth raising from inside a snapshot
//
bool
P2PeerCon::IsCypherActive ( )
{
    P2Peerio *pIO = GetP2Peerio ( );
    return pIO ? pIO -> IsCypherActive ( ) : false;
}

//
//  Do this connection's frames leave this process?
//  NOTES: F-S6-3.  The companion to IsCypherActive above,
//         and the reason a snapshot reader can tell the tree's one legitimate
//         plaintext transport from a defect: DMX answers 0 here and 0 for the
//         cypher and is correct, a wire answering 0 for the cypher is not
//       : Reported, not enforced from here.  The enforcement is in
//         KeyXDerive, at the instant the cypher is installed; by the time
//         anything reads a snapshot the decision has been taken
//       : No io object answers false, matching IsCypherActive.  A connection
//         that has not been given one sends nothing anywhere, which is the
//         true answer and not a fault to raise from inside a snapshot
//
bool
P2PeerCon::LeavesProcess ( )
{
    P2Peerio *pIO = GetP2Peerio ( );
    return pIO ? pIO -> LeavesProcess ( ) : false;
}

//
//  Hold this connection to no better than the given trust class
//  NOTES: TIGHTENS ONLY, and the test is one line because that is the whole
//         guarantee: a caller asking for a HIGHER class than the ceiling
//         already holds changes nothing, so no sequence of calls - and no
//         caller that reaches this after another one did - can hand a
//         connection back a class it was denied
//       : There is no PromoteTrust and there must not be.  The classes above
//         Wire are claims the kernel or construction makes good; an operator
//         asserting one the library cannot check would be writing an
//         intention into the field the policy reads as a fact, which is asset
//         S9 in THREAT_MODEL.md
//       : No lock.  It is a single enum store on a connection, it is meant to
//         be called before the connection is posted to a hub, and a torn read
//         of an enum whose values are 0, 1 and 2 is not a state this type has
//
void
P2PeerCon::DemoteTrust ( P2PeerConTrust_e eNoBetterThan )
{
    if ( eNoBetterThan < m_eTrustCeiling )
      m_eTrustCeiling = eNoBetterThan;
}

//
//  What the policy reads: the transport's answer, capped by the operator's
//  NOTES: min(), and it is a min BECAUSE the enum is ordered from least
//         trusted upwards - refer P2PeerConTrust_e.  Both inputs can only
//         lower the answer, so there is no combination of a transport and an
//         operator that produces a class neither of them stated
//
P2PeerConTrust_e
P2PeerCon::EffectiveTrust ( ) const
{
    const P2PeerConTrust_e eClass = TrustClass ( );
    return eClass < m_eTrustCeiling ? eClass : m_eTrustCeiling;
}

//
//  The lowest class the governing hub will hold a link of
//  NOTES: THE ONE PLACE the hub is read for this, so the refusal below and
//         every diagnostic that names a floor cannot come to disagree about
//         what the floor is
//       : P2PeerConTrust_Wire - no fence - for a connection with no governing
//         hub.  A connection that has not been posted is governed by nothing,
//         and a fence that cannot be read must refuse nothing: the same
//         direction P2PeerHub::GetRequiredTrust() takes for a hub with no
//         policy object, and for the reason written there
//
P2PeerConTrust_e
P2PeerCon::TrustFenceFloor ( )
{
    P2PeerHub *pHub = GetAuthHub ( );
    return pHub ? pHub -> GetRequiredTrust ( ) : P2PeerConTrust_Wire;
}

//
//  Would this hub's fence refuse a link of the given class?
//  NOTES: Takes the class rather than reading TrustClass(), so a SERVICE can
//         ask on behalf of a child that does not exist yet.  That is the case
//         the fence was missing: PostP2PeerCon() sees a service whose class is
//         still an intention, and the child that carries the traffic never
//         passes through PostP2PeerCon() at all
//       : Applies THIS object's ceiling to the class it was handed, because a
//         child inherits m_eTrustCeiling from its service - so the answer here
//         is the answer the child's own EffectiveTrust() will give, and the
//         two cannot differ
//       : The floor is compared with > Wire first, so a hub nobody has fenced
//         does no work and reaches the same answer it reached before this
//         existed
//
bool
P2PeerCon::TrustFenceRefusesClass ( P2PeerConTrust_e eClass )
{
    const P2PeerConTrust_e eFloor = TrustFenceFloor ( );
    if ( eFloor <= P2PeerConTrust_Wire )
      return false;
    if ( m_eTrustCeiling < eClass )
      eClass = m_eTrustCeiling;
    return eClass < eFloor;
}

//
//  ...and would it refuse THIS connection, as it now is?
//  NOTES: EffectiveTrust() by construction - TrustClass() through the function
//         above, which applies the ceiling.  Asked where a listener has just
//         created its handle and the class has stopped being an intention
//
bool
P2PeerCon::TrustFenceRefuses ( )
{
    return TrustFenceRefusesClass ( TrustClass ( ) );
}

P3PmsgItem
P2PeerCon::Serialise ( LPCTNAM lpszVar )
{
    bool bDsc = true;

    // Create a placeholder for receipt of P2PeerCon details
    // NOTES: This will be passed by value back up the stack
    if ( lpszVar == 0 )
      lpszVar = L"{P2PeerCon}";
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData(m_nP2PconID)) );

    // Append our state to node
    P3PmsgField_SERIALISE ( oNodeVar, L"P2Paddress", GetP2Paddress().c_wstr(), bDsc
                          , _T("Allocated connection address") );
    P3PmsgField_SERIALISE ( oNodeVar, L"P2Padomain", GetP2Padomain().c_wstr(), bDsc
                          , _T("Assigned connection address domain") );
    P3PmsgField_SERIALISE ( oNodeVar, L"ConMode", (int)m_eP2PeerConMode, bDsc
                          , _T("Connection mode") );
    if ( m_eP2PeerConMode != P2PeerCon_Accept )
      P3PmsgField_SERIALISE ( oNodeVar, L"LoginTimerID", m_uLoginTimerID, bDsc
                            , _T("Restart connection timer identification") );

    // Security posture of THIS connection
    // NOTES: F-S6-2, and the reason it is here rather than
    //        in a new message is the reason Version and QueDepth are in the
    //        hub's snapshot: this function is what every P2Pevent carrying
    //        connection state is built from, so anything that can already read
    //        one of those can read these without a new call or a new message
    //      : Until this, the snapshot of a connection carried its address, its
    //        domain, its mode and a timer id - four facts of identity and not
    //        one of protection. An operator asking "is this peer proven, and
    //        is this link in clear" had to read the source of the library
    //      : FIVE fields, not one, and they are not collapsed because F-S6-1
    //        was precisely these facts coming apart. A session was
    //        authenticated AND in cleartext, reported as an ordinary login,
    //        and a single "Secure" boolean - however computed - would have
    //        reported that state as fine. Fields that can disagree are what
    //        makes the disagreement visible
    //      : OffProcess is the fifth, added closing F-S6-3, and it is what
    //        makes Cypher=0 readable. Alone that says "not encrypted", which
    //        is a defect on a wire and correct on the in-process DMX handoff -
    //        and nothing in a snapshot could previously tell a reader which
    //        one they were looking at. The pair 0/0 is DMX; 1/0 on a keyed
    //        connection is the state KeyXDerive now refuses to create
    //      : UINT32 0/1 rather than a bool cell, to match the numeric
    //        convention the rest of these snapshots use - a reader already
    //        built for QueDepth or Accepted reads these with the same
    //        width-agnostic path and needs no new case
    //      : None of the four throws, and none takes a lock this thread might
    //        already hold. A snapshot of a connection that is being torn down
    //        must report the teardown rather than raise a second fault from
    //        inside the report of the first
    P3PmsgField_SERIALISE ( oNodeVar, L"AuthDone"
                          , (UINT32)( IsAuthenticated ( ) ? 1 : 0 ), bDsc
                          , _T("Peer login signature verified on this connection") );
    P3PmsgField_SERIALISE ( oNodeVar, L"AuthPeer"
                          , GetAuthPeer ( ).c_wstr ( ), bDsc
                          , _T("Identity the signature verified as (empty if none)") );
    P3PmsgField_SERIALISE ( oNodeVar, L"KeyXDone"
                          , (UINT32)( IsKeyXDone ( ) ? 1 : 0 ), bDsc
                          , _T("Session key agreement completed, cypher posted") );
    P3PmsgField_SERIALISE ( oNodeVar, L"Cypher"
                          , (UINT32)( IsCypherActive ( ) ? 1 : 0 ), bDsc
                          , _T("Cypher installed and consulted by this transport") );
    P3PmsgField_SERIALISE ( oNodeVar, L"OffProcess"
                          , (UINT32)( LeavesProcess ( ) ? 1 : 0 ), bDsc
                          , _T("Frames on this transport leave this process") );

    //  SEVEN since the trust class landed, and the two new ones are what make
    //  Cypher=0 readable as a DECISION rather than only as an exemption.
    //  OffProcess above already told a reader that DMX is the tree's one
    //  legitimate plaintext transport; it says nothing about a loopback socket,
    //  and nothing at all about whether the hub was ASKED to relax the link.
    //  NOTES: TWO fields and not one, for the reason there are five above.
    //         TrustClass is what the TRANSPORT vouches for; Trust is what the
    //         policy actually read after the operator's DemoteTrust(). They
    //         agree on every connection nobody has demoted, and a reader that
    //         saw only the second could not tell a transport that answered
    //         Wire from one that was held down to it
    //       : Values are P2PeerConTrust_e - 0 Wire, 1 Local, 2 InProcess - and
    //         are rendered as the number rather than a name for the same
    //         reason AuthArm renders an int: the enumeration is the ABI, and a
    //         string in a snapshot is a second spelling of it that can drift
    //       : Neither takes a lock or can throw.  TrustClass() reads a socket
    //         or nothing at all, and answers Wire for a connection being torn
    //         down - refer the note on the other four
    P3PmsgField_SERIALISE ( oNodeVar, L"TrustClass"
                          , (UINT32)TrustClass ( ), bDsc
                          , _T("What this transport vouches for: 0 wire, 1 local, 2 in-process") );
    P3PmsgField_SERIALISE ( oNodeVar, L"Trust"
                          , (UINT32)EffectiveTrust ( ), bDsc
                          , _T("...after the operator's demotion - what the policy reads") );

    // Tidy up and
    return oNodeVar;
}

///////////////////////////////////////////////////////////////////////
//  P2PeerConPlc
//  NOTES: Place marker for lists of P2PeerCon objects
//       : Optimised for and targeted to self extracting lists
//         of P2PeerCon objects
//       : Manages private interactions between P2Peer, P2PeerCon
//         objects and the P2Pmsg pump
IMPLEMENT_DYNCREATE(P2PeerConPlc,CObject)
P2PeerConPlc::P2PeerConPlc ( )
{
    // Firstly
    m_cRef      = 0;
    m_bDestroy  = false;
    m_nP2PconID = 0;
    m_pP2Props  = 0;
}

P2PeerConPlc::~P2PeerConPlc ( )
{
    ASSERT(m_cRef==0);
    delete m_pP2Props;
}

UINT
P2PeerConPlc::AddRef ( )
{
    return ++m_cRef;
}

UINT
P2PeerConPlc::Release ( )
{
    // Implementation
    // NOTES: m_cRef is atomic (Risk #3). Decide off the value THIS decrement produced
    //        (cRef), not a re-read of m_cRef: --m_cRef is a single atomic RMW, so only the
    //        thread that brings it to <= 0 sees cRef <= 0 and performs the delete - a re-read
    //        could observe another thread's concurrent change and either double-delete or leak.
    int cRef   = --m_cRef;
ASSERT(cRef>=0);
    if ( cRef <= 0 && m_nP2PconID == 0 )
      Destroy ( );
    if ( cRef <= 0 && m_bDestroy )
    {
      DropP2PmsgCon ( (P2PeerCon *)this );
      delete this;
    }
    return cRef;
}

UINT
P2PeerConPlc::Destroy ( )
{
    // Implementation
    m_bDestroy = true;                  // atomic<bool> store (was |= true; same effect)
    return m_cRef;
}

bool
P2PeerConPlc::PostDestroyState ( )
{
    // Implementation
    return m_bDestroy || m_cRef <= 0;
}

void
P2PeerConPlc::AssertValid ( ) const
{
    // Validation
    ASSERT(m_cRef>=0);
}

//  Properties
P3PmsgItem&
P2PeerConPlc::GetP2Props ( )
{
    if ( m_pP2Props == 0 )
      m_pP2Props = new P3PmsgItem ( );
    return *m_pP2Props;
}
P2PconID
P2PeerConPlc::GetP2PconID ( ) const
{
    ASSERT(m_nP2PconID);
    return m_nP2PconID;
}

///////////////////////////////////////////////////////////////////////
//  Safe P2PeerCon container
//  NOTES: Intended for use form P2PeerMsg handlers in conjunction
//         with P2PeerHub::ConQuery()
//
SafeP2PeerCon::SafeP2PeerCon ( )
{   RenderThisSafe(); }
SafeP2PeerCon::SafeP2PeerCon ( P2PeerCon *pCon )
{   RenderThisSafe(); pCon->AddRef(); m_pP2PeerCon = pCon; }
SafeP2PeerCon::~SafeP2PeerCon ( )
{   if ( m_pP2PeerCon ) m_pP2PeerCon -> Release ( ); }
void
SafeP2PeerCon::RenderThisSafe ( )
{   m_pP2PeerCon = 0; }
SafeP2PeerCon&
SafeP2PeerCon::operator = ( P2PeerCon *pCon )
{   if ( pCon ) pCon->AddRef();
    if ( m_pP2PeerCon ) m_pP2PeerCon->Release();
    m_pP2PeerCon = pCon;
    return *this; }
P2PeerCon*
SafeP2PeerCon::operator -> ( ) const
{   return m_pP2PeerCon; }
SafeP2PeerCon::operator P2PeerCon* ( )
{   return m_pP2PeerCon; }
SafeP2PeerCon::operator bool ( )
{   return m_pP2PeerCon ? true : false; }
