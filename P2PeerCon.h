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
//  P2PeerCon[nection] definitions and prototypes
//  NOTES: Base class from which all P2PeerCon[nection] objects are
//         derived (P2PeerConWsa, P2PeerConPipe and P2PeerCon232 etc).
//       : FILE type object supported by derived object must be compatible
//         with IO completion ports.
//       : Collections of P2PeerCon objects are managed by P2PeerHub's
//         to implement the asynchronous P2PeerMsg exchanges.
//                      
#pragma once

#include <atomic>   // std::atomic<int> m_cRef / atomic<bool> m_bDestroy - include BEFORE the
                    // DEBUG_NEW macro below so the header's own operator new isn't rewritten
#include <memory>   // std::shared_ptr m_pxAccepted - same rule, and it matters more here:
                    // shared_ptr's control block IS an allocation, so a DEBUG_NEW rewritten
                    // into this header would allocate it against P2PeerCon.h's line numbers

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2Peer.h"
#include "P2Peerio.h"
#include "Msgexception.h"
class P2PeerTarget;
class P2PeerHub;

///////////////////////////////////////////////////////////////////////
//  P2PeerCon_MAP handler result types
//  NOTES: Used to summarise map handler outcomes. P2PeerCon_MAP
//         handlers must return a result from the following
//
typedef  mapRESULT conRESULT;
const    conRESULT conTINUE   = FALSE; // Not handled continue routing
const    conRESULT conHANDLED = TRUE;  // Handled, discontinue routing
const    conRESULT conDROP    = 3;     // Handled, drop P2PeerCon object
const    conRESULT conSWAP    = 7;     // Swap processing context

//
//  P2PeerCon interface P2PeerID mapping
typedef enum
{
    P2PeerIDmap_NONE          = 0,
    P2PeerIDmap_Normal        = 2,
    P2PeerIDmap_Discontinuous = 3,
    P2PeerIDmap_STATIC        = 4,
    P2PeerIDmap_Recursive     = 5,
    P2PeerIDmap_FRACTAL       = 6,
//} P2PaddrTrans_e;
} P2PeerIDmap_e;

//
//  P2PeerCon mode
//  NOTES: P2PeerCon's are created with and maintain one of the
//         following modes for their complete life cycle
//       : Pumped P2PeerCon objects assume that the assigned 
//         mode is constant
typedef enum
{
    P2PeerCon_Unknown     = 0, 
    P2PeerCon_CLIENT      = 1,         // Active  connection
    P2PeerCon_SERVICE     = 2,         // Passive service
    P2PeerCon_Accept      = 3,         // Neutral accepted
} P2PeerConMode_e;

///////////////////////////////////////////////////////////////////////
//  P2PeerConPlc 
//  NOTES: Optimised for and targeted to self extracting lists
//         of P2PeerCon objects
//       : Manages private interactions between P2PeerHub, P2PeerCon
//         objects and the P2Pmsg pump
class TargetCore_EXT P2PeerConPlc : public CObject
{
    // Constructors and destructor
    public:
        DECLARE_DYNCREATE(P2PeerConPlc)
        P2PeerConPlc ( );
      virtual
       ~P2PeerConPlc ( );
        P2PconID  m_nP2PconID;

    // Life cycle management
    public:
      UINT
        AddRef ( );
      UINT
        Release ( );
      UINT
        Destroy ( );
      bool
        PostDestroyState ( );

    // Troubleshooting
    public:
      void
        AssertValid ( ) const;

    // Properties
    public:
      P3PmsgItem&
        GetP2Props ( );
      P2PconID
        GetP2PconID ( ) const;

    // Attributes
    protected:
      P3PmsgItem *m_pP2Props;
      // Refcount + destroy flag are touched across threads (AddRef/Release by posters and the
      // pump/teardown, AssertValid/PostDestroyState reads by the pump) - atomic to fix the
      // TSan-reported data race (Risk #3). Layout/size unchanged (4/1 bytes).
      std::atomic<int>  m_cRef;
      std::atomic<bool> m_bDestroy;
};

//
//  Asynchronous control signals
//  NOTES: Refer P2PeerCon::Signal() for implementation details
                                       // P2PeerCon signals
const P2PsigID P2PsigCon_CLOSE    =  1;//   On_P2PeerCon_CLOSE 
const P2PsigID P2PsigCon_MSG      =  2;//      P2PeerMsg emulation
const P2PsigID P2PsigCon_DESTROY  =  3;//   On_P2PeerCon_DESTROY
const P2PsigID P2PsigCon_SHUTDOWN =  4;//   On_P2PeerCon_SHUTDOWN
const P2PsigID P2PsigCon_CLOSEONIDLE=5;//
const P2PsigID P2PsigCon_RECV     =  6;//      P2PeerMsg receipt

                                       // P2Peerio signals
const P2PsigID P2PsigIO_ACK       =  7;//   P2PeerMsg acknowledgement
const P2PsigID P2PsigID_PKEY      =  8;

                                       // P2PeerCon signals (continued)
// NOTES: 7 and 8 belong to P2Peerio above.  Both families travel in the same
//        OVERLAPPEDcon::nSigID field and are told apart only by which handler
//        dequeues them, so the numbering is shared and must not be reused.
const P2PsigID P2PsigCon_WAKEUP   =  9;//   Cancels a pending P2PsigCon_CLOSEONIDLE

///////////////////////////////////////////////////////////////////////
//  P2PeerCon[nection] management
//  NOTES: Instances of these objects wholly manage single P2Peer
//         connections.  Collections of P2PeerCon objects are collated
//         and supervised by P2PeerHub's
//
//  Per-source accept accounting block, shared by a SERVICE with every
//  connection it accepts.  Opaque here on purpose: it owns a map and a lock,
//  neither of which belongs in a header this widely included, and nothing
//  outside P2PeerCon.cpp has any business reaching into it.  A shared_ptr to an
//  incomplete type is well-formed as a member - the deleter is captured where
//  the type IS complete, which is where the block is made
struct P2PeerConSourceTally;

class TargetCore_EXT P2PeerCon : public P2PeerConPlc
{
      friend
        P2Peerio;
      friend TargetCore_EXT DWORD
        PumpP2Pmsg ( DWORD, P2PsigID& );
      void
        RenderThisSafe();

    // Constructors, destructors and factories
    public:
        DECLARE_DYNCREATE(P2PeerCon)
        P2PeerCon ( );
        P2PeerCon ( P2PaddrSTR pThatP2PaddrSTR
                  , P2Peerio   *pP2Peerio = 0 );
        P2PeerCon ( P2Peerio   *pP2Peerio );
      virtual
       ~P2PeerCon ( );
      virtual P2PeerCon*
        AcceptSpawn ( P2PeerCon *pCon );
      //  The origin of the endpoint this SERVICE has just accepted and still
      //  owns, or 0 when this transport has no such notion.
      //  NOTES: Called ON THE SERVICE, during the accept, at the one moment the
      //         half-accepted endpoint is still reachable - the transport hands
      //         it to the child immediately afterwards
      //       : 0 is the correct answer for a point-to-point transport and is
      //         what the base returns.  A serial line or a DMX universe has one
      //         peer by construction; there is no share for one origin to take
      //         more than, and inventing a key so the bound "applies" would
      //         make it apply to nothing
      virtual P2PsourceKey
        AcceptSourceKey ( ) const { return 0; }

    // Accept admission control
    // NOTES: Set on the SERVICE connection, before or after it listens.  An
    //        accepted connection inherits the login deadline from the service
    //        that spawned it (AcceptSpawn), and never the cap - a cap on an
    //        accepted connection would bound connections it does not accept
    //      : The refusal itself is transport-specific, because only the
    //        transport knows how to discard a half-accepted endpoint.
    //        P2PeerConWsa closes the accepted socket; refer AcceptSpawn there
    public:
      void
        SetMaxAccepted   ( long xMax );
      long
        GetMaxAccepted   ( ) const { return m_xMaxAccepted; }
      // Live accepted children of this service. Cheap, and exact only in the
      // sense any concurrent counter is - it is read to admit or refuse, and
      // one connection either side of the cap is not a security property
      long
        GetAcceptedCount ( ) const
        { return m_pxAccepted ? m_pxAccepted->load ( ) : 0; }
      bool
        AcceptAtCapacity ( ) const
        { return m_xMaxAccepted > 0 &&
                 GetAcceptedCount ( ) >= m_xMaxAccepted; }

      // Per-source bound (Stage 4 step 11)
      // NOTES: The cap above counts a SERVICE's children and cannot tell 1024
      //        connections from one peer apart from one each from 1024 peers,
      //        so one source can take every slot and the cap reads as held
      //      : Also set on the SERVICE, also 0 for unlimited, and also NOT
      //        inherited by a child - for the same reason the cap is not
      //      : The P2P address is NOT the key and cannot be: it is not known
      //        until a login that a peer holding slots has not performed.  The
      //        key is what the transport can name at accept - refer
      //        AcceptSourceKey() below
      void
        SetMaxAcceptedPerSource ( long xMax );
      long
        GetMaxAcceptedPerSource ( ) const { return m_xMaxAcceptedPerSource; }
      // Live accepted children of this service FROM one source.  0 for an
      // unknown source, and 0 when nothing has been accepted from it
      long
        GetAcceptedCountFromSource ( P2PsourceKey xSource ) const;
      // NOTES: A zero key is never at capacity.  A transport that cannot name
      //        its source must not be refused by a bound that cannot see it
      bool
        SourceAtCapacity ( P2PsourceKey xSource ) const;
      // Inbound backpressure (Stage 4 step 12)
      // NOTES: Not configured per connection and deliberately so.  The
      //        pressure being relieved is the PROCESS's message budget, which
      //        no single connection owns and none of them can see the size of;
      //        the marks are set once, for the process, by
      //        SetP2PmsgBudgetMarks
      //      : What is per-connection is the DECISION and its attribution -
      //        which peer was told to wait, and how often
      bool
        IsRecvThrottled      ( ) const { return m_bRecvThrottled; }
      DWORD
        GetRecvThrottleCount ( ) const { return m_cRecvThrottled; }
      void
        SetLoginDeadline ( P2Pmsecs_t uMSec );
      P2Pmsecs_t
        GetLoginDeadline ( ) const { return m_xLoginDeadline; }
      // Arms m_uLoginTimerID for this connection. No-op when the deadline is
      // 0, or when a timer is already running, so calling it twice is safe
      void
        ArmLoginDeadline ( );

    // IOCP Integration
    public:
      void
        CreateIOCP ( HANDLE hFile );
      virtual bool
        On_QueuedCompletionStatus ( DWORD dwError
                                  , DWORD dwBytes
                                  , OVERLAPPEDcon *pOVERLAPPEDcon );
      virtual OVERLAPPEDcon*
        MakeOVERLAPPED ( DWORD dwBytesMax = 0 );
      virtual OVERLAPPEDcon*
        DropOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon
                       , bool bNotify = true );
      void
        PostOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon );
      void
        prepareOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon );
      void
        releaseOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon );
      void
        DrainOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon );
      // True while any member OVERLAPPED is still queued, i.e. while this
      // connection is still OWED a completion that holds a reference on it.
      // For the teardown drains - refer DrainPortOfOVERLAPPED()
      bool
        HasQueuedOVERLAPPED ( ) const;
      virtual void
        Signal ( P2PsigID nSigID
               , void *pvData = 0, int iDataSize = 0 );
      // True when this read is being WITHHELD because the process message
      // budget is at its high mark.  Has the side effect of applying the hold
      // on the transition, which is why it is not named like a predicate:
      // it is the decision, taken in the one place that can act on it
      bool
        HoldRecvForBackpressure ( );
      // Arms a read on a connection that has one withheld.  NOT
      // PostOVERLAPPED: that refuses a recv buffer whose pBuffer the io layer
      // freed on its first call, which is every connection that has ever
      // received anything.  Signal(P2PsigCon_RECV) routes here
      void
        RearmRecv ( );
      // Does a transport read that COMPLETES WITH ZERO BYTES on this
      // connection mean the peer closed?  On a socket it does - that is FIN,
      // and it is the only notification of an orderly close a stream socket
      // gives.  On the serial and pipe transports it does NOT: an overlapped
      // ReadFile against a handle carrying COMMTIMEOUTS completes with zero
      // bytes on a read timeout, with the peer still there, so answering yes
      // here would drop a live connection on a quiet line.  Default is
      // therefore NO and P2PeerConWsa overrides it; refer F-S4-1
      virtual bool
        RecvZeroIsOrderlyClose ( ) const { return false; }

    // Timers
    public:
      PITimerID
        SetPITimer   ( P2Pmsecs_t uMSecDelay, DWORD dwUserKey = 0 );
      virtual void
        On_PITimer   ( bool bCancel
                     , PITimerID nPITimerID, DWORD dwUserKey );
      virtual void
        Drop ( P2Pevent *pEVENT );

    // P2PeerMsg Management
    public:
      virtual P2PeerMsg*
        PostP2PeerMsg ( P2PeerMsg *pMsg );
      void
        FlushP2PeerMsg ( );
      P2PeerMsg*
        GetP2PeerMsg ( );
      INT_PTR
        GetP2PeerMsgCount ( );

    // Connection state operations
    // NOTES: Thread safe operations used to manage connection
    //        state.  Reference from P2PeerCon_MAP handlers only
    public:
      virtual P2Pmsecs_t
          Restart  ( P2Pmsecs_t uiMsecDelay = 0 );
      virtual void
        OnStartup  ( );
      virtual bool
          Listen   ( );
      virtual void
        OnListen   ( );
      virtual bool
          Accept   ( );
      virtual P2PeerCon*
        OnAccept   ( );
      virtual void
        OnAccept   ( CP2Paddress oThatP2Paddr );
      virtual bool
          Connect  ( );
      virtual void
        OnConnect  ( );
      virtual void
          PKeyXChange ( const void *pvPKeyXChange, P2Psize_t iSize );
      virtual void
        OnPKeyXChange ( const void *pvPKeyXChange, P2Psize_t iSize );
      virtual void
          PKeyXChangeAck ( const void *pvPKeyXChange, P2Psize_t iSize );
      virtual void
        OnPKeyXChangeAck ( const void *pvPKeyXChange, P2Psize_t iSize );
      virtual void
          Login    ( P2PaddrSTR strThatP2Paddr
                   , const void *pvLoginMsg, P2Psize_t nSize );
      virtual void
          Login_Fractal ( P2PaddrSTR strThisP2Paddr, P2PaddrSTR strThatP2Paddr
                        , const void *pvLoginMsg, P2Psize_t nSize );
      virtual void
        OnLogin    ( const P2Paddr& oP2Paddr );
      virtual BOOL
          LoginAck ( const P2Paddr& oThatP2Paddr
                   , const void *pvLoginAck, P2Psize_t nSize );
      virtual void
        OnLoginAck ( const P2Paddr& oThisP2Paddr
                   , const P2Paddr& oThatP2Paddr );
      virtual void
        OnLoginAck_Static ( const P2Paddr& oThisP2Paddr
                          , const P2Paddr& oThatP2Paddr );
      virtual void
        OnLoginAck_Fractal( const P2Paddr& oThisP2Paddr1
                          , const P2Paddr& oThatP2Paddr1 );
      virtual void
          Close    ( );
      virtual conRESULT
        OnClose    ( );
      virtual void
          Shutdown ( );
      virtual BOOL
        OnShutdown ( );

    // Internals
    protected:
      virtual void
        PerformIFaddrTransform ( BOOL bSoR, P2PeerMsg *pMsg );

    // Troubleshooting
    public:
      void
        AssertValid ( ) const;
      virtual LPCTSTR
        GetVisualRTSummary ( );
      virtual P3PmsgItem
        SetP2PeventFParams ( LPCTNAM lpszVar );
      virtual P3PmsgItem
        Serialise ( LPCTNAM lpszVar );

    // Properties
    public:
      const P2Padomain&
        GetP2Padomain ( ) const;
      const P2Paddr&
        GetP2Paddress ( );
      BOOL
        SetP2Paddr ( P2PaddrSTR strP2Paddress );
      const P2Paddr
        GetP2PaddrHub ( ) const;
      void 
        SetIFaddrTransform ( P2PeerIDmap_e eIFaddrTrans );
      void
        SetP2Peerio ( P2Peerio *pP2Peerio );
      P2Peerio*
        GetP2Peerio ( );
      DWORD
        SetState( DWORD dwAdd, DWORD dwRemove );
      DWORD
        GetState( DWORD dwMask = ~0 );
      bool
        HasState ( DWORD dwMask );
      P2PeerConMode_e
        GetMode ( );
      virtual DWORD_PTR
        GetUDState ( );
      P2Pevent*
        SetP2Pevent ( P2PeventSP& spP2Pevent );
      P2Pevent*
        GetP2Pevent ( );

      LPCTSTR
        EncodeP2Pmsg_t ( P2Pmsg_t nMsg );
      virtual bool
        HasDroppedOut ( HRESULT hr );

    // Peer login authentication
    // NOTES: The POLICY lives on the hub (refer P2PeerHub.h). What lives
    //        here is per-connection RUNTIME state only - the nonce this
    //        connection signed and the length of the block that was
    //        verified off the front of its login. Neither is configuration,
    //        so neither is copied by AcceptSpawn(): an accepted connection
    //        performs its own login and derives its own values. That is why
    //        forgetting a line in AcceptSpawn cannot weaken this
    //      : GetAuthStripLen() is what the P2PSig_ConLogin dispatcher uses
    //        to hide the block from the application. Non-zero ONLY after a
    //        signature verified - never on the strength of the magic alone
    public:
      P2PeerHub*
        GetAuthHub ( );
      size_t
        GetAuthStripLen ( ) const { return m_cbAuthStrip; }

      // POSTURE. F-S6-2: until these existed, a running hub
      // could be asked its Version, its queue depth and how many peers it was
      // holding, and not one thing about whether any protection was on. F-S6-1
      // is why that is a finding rather than a wish - for two days "this hub
      // requires authentication" and "this connection is encrypted" were
      // different facts, and nothing inside the process or outside it could
      // have discovered they had come apart.
      //
      // Three separate questions, deliberately not collapsed into one:
      //
      //   IsAuthenticated() - did a SIGNATURE verify on this connection. It is
      //     m_cbAuthStrip, which is set only by AuthGateInbound on AuthOk and
      //     never on the strength of the magic alone, so it cannot report a
      //     login that was merely well-formed.
      //   GetAuthPeer()     - WHO it verified as: the source address the
      //     transcript covered, which is the identity the allow-list is keyed
      //     on. Empty until a signature verifies. It is not GetP2Paddress():
      //     that is what the peer CLAIMS and is set for an unauthenticated
      //     connection too, and a posture accessor that reported a claim as an
      //     identity would be worse than no accessor.
      //   IsKeyXDone()      - did the session key agreement complete. Separate
      //     from the first on purpose, because F-S6-1 was exactly these two
      //     coming apart, and an accessor that ANDed them would have hidden it.
      //
      // Cypher state is asked of the io object (P2Peerio::IsCypherActive), not
      // stored here, because whether the hooks run is a property of the io
      // subclass the transport constructed - which was F-S6-3.
      //
      //   IsCypherActive() - is a cypher installed AND consulted.
      //   LeavesProcess()  - do this connection's frames leave this process.
      //
      // The pair, not either one. A transport that answers true and false is
      // a plaintext wire on a keyed connection, and P2PeerCon::KeyXDerive
      // refuses to arm one; DMX answers false and false and is the tree's one
      // legitimate exemption. Reporting both is what lets a reader tell those
      // two apart without reading the transport, which is what F-S6-3 was.
      bool
        IsAuthenticated ( ) const { return m_cbAuthStrip != 0; }
      bool
        IsKeyXDone      ( ) const { return m_bKeyXDone; }
      const P2Paddr&
        GetAuthPeer     ( ) const { return m_oAuthPeer; }
      bool
        IsCypherActive  ( );
      bool
        LeavesProcess   ( );

    // Attributes
    public:
      HANDLE           m_hP2PmsgCon;
      DWORD            m_hCPortP2PumpID;
      HANDLE           m_hCPort;
      P2Pmsecs_t       m_uAutoRestart;
      P2PeerTarget    *m_pP2PeerTarget;
    protected:
      CRITICAL_SECTION m_oCSectMsgQue;
      CListP2PeerMsg   m_oCListMsgQue;
      P2Pevent        *m_pEvent;
      HANDLE           m_hFile;
      HANDLE           m_hFileCPort;
      UINT_PTR         m_dwCompletionKey;
      P2Peerio        *m_pP2Peerio;

      P2PeerMsg       *m_pP2PeerMsgSend;
      P2Pmsecs_t       m_iRecvTimeout;

      OVERLAPPEDcon   *m_pOVERLAPPEDsend;
      OVERLAPPEDcon   *m_pOVERLAPPEDrecv;
      OVERLAPPEDcon   *m_pOVERLAPPEDaccept;
      OVERLAPPEDcon   *m_pOVERLAPPEDconnect;

      DWORD            m_dwState;

      PITimerID        m_uRestartTimerID;
      PITimerID        m_uLoginTimerID;

      // Inbound backpressure.  m_uThrottleTimerID is the poll that decides
      // when to resume; m_bRecvThrottled says a read is being withheld RIGHT
      // NOW and is what stops a second hold stacking a second timer;
      // m_cRecvThrottled is cumulative and never falls, because the question
      // an operator asks is how often this peer has had to be held rather
      // than whether it happens to be held at the instant they looked
      PITimerID        m_uThrottleTimerID;
      bool             m_bRecvThrottled;
      DWORD            m_cRecvThrottled;

      // Accept admission control - service-side bounds on inbound connections
      // NOTES: A SERVICE accepted without limit until 2026-08-16: nothing
      //        counted its children and nothing refused the next one, so an
      //        unauthenticated peer could hold as many sockets open as the
      //        machine had descriptors.  That is the one exposure category the
      //        login/seal work never touched, because it is spent before a
      //        login is ever attempted
      //      : m_pxAccepted is SHARED between the service and every connection
      //        it spawns, deliberately, so that neither has to outlive the
      //        other.  A raw back-pointer to the service would dangle whenever
      //        a child outlived its parent at hub teardown, and the counter is
      //        the only thing either of them needs from the other
      //      : m_xMaxAccepted is read on the SERVICE only.  0 = unlimited,
      //        which is what a client or an accepted connection always is
      std::shared_ptr<std::atomic<long>>
                       m_pxAccepted;
      long             m_xMaxAccepted;
      // Per-source accounting.  Shared with every child for exactly the reason
      // m_pxAccepted is, and allocated on the same first spawn: a service that
      // never accepts carries no block, and a child that outlives its service
      // still has somewhere to give its slot back to
      // NOTES: m_xMaxAcceptedPerSource is read on the SERVICE only
      //      : m_xAcceptSource is the key THIS connection was counted under -
      //        non-zero exactly when it holds a per-source slot, so it is both
      //        the flag and the key and the two cannot disagree.  The service
      //        holds the tally to read it and never counts itself, which is why
      //        the tally pointer cannot be the test
      std::shared_ptr<P2PeerConSourceTally>
                       m_pxSourceTally;
      long             m_xMaxAcceptedPerSource;
      P2PsourceKey     m_xAcceptSource;
      // Whether THIS connection is one of the counted children, as opposed to
      // the service holding the counter to read it.  Both hold the pointer, so
      // the pointer cannot be the test, and the mode cannot either - a 232
      // service morphs itself into an accepted connection, which would
      // decrement a count it never incremented
      bool             m_bAcceptCounted;
      // Login deadline. NOTES: The timer this arms has been complete since the
      //        import - On_PITimer() throws "Login timed out" on expiry, and
      //        OnLogin()/OnClose()/~P2PeerCon() all cancel it - but the one
      //        line that ARMED it sat commented out in P2PeerTarget.cpp, so a
      //        peer that connected and never logged in was never dropped.
      //        Milliseconds; 0 disables
      P2Pmsecs_t       m_xLoginDeadline;

      P2Padomain       m_oP2Padomain;
      P2Paddr          m_oThisP2Paddr_, m_oThisP2Paddr1;
      P2Paddr          m_oThatP2Paddr, m_oThatP2Paddr1;
      P2PeerIDmap_e    m_eP2PeerIDmap;

      CString         *m_pstrVisualSummary;
      P2PeerConMode_e  m_eP2PeerConMode;

      // Peer login authentication - per-connection runtime state
      unsigned char    m_AuthNonce[16];  // the nonce this login signed
      bool             m_bAuthNonce;     // ...and whether it is set
      size_t           m_cbAuthStrip;    // verified block bytes to hide
      P2Paddr          m_oAuthPeer;      // identity the signature verified as

      // Session key agreement - per-connection runtime state
      // NOTES: Ephemeral, per connection, and never copied by AcceptSpawn():
      //        an accepted connection runs its own agreement.  A key that
      //        outlived one connection would be a key worth stealing
      void            *m_pKeyX;          // p2pcng::EcdhP256, this end's pair
      unsigned char    m_KeyXPubThis[64];
      unsigned char    m_KeyXPubThat[64];
      unsigned char    m_KeyXBind[32];   // AuthChannelBind() over both points
      bool             m_bKeyXBound;     // ...and whether it is set
      bool             m_bKeyXDone;      // agreement complete, cypher posted
      bool             m_bKeyXClient;    // this end opened the connection

      // Login held back until the agreement completes
      // NOTES: The application calls Login() from its On_ConConnect handler
      //        and must not have to know that a key exchange runs first, so
      //        the payload it passed is parked here and sent on the ack
      unsigned char   *m_pLoginDefer;
      size_t           m_cbLoginDefer;
      bool             m_bLoginDefer;

    // Internals
    protected:
      // Verifies the auth block on an inbound Login/LoginAck when the hub
      // requires one. On refusal it deletes pMsg and throws, exactly as the
      // domain and source-binding checks do, so the connection is dropped
      // before OnLogin() can set ConState_Login.
      void
        AuthGateInbound ( P2PeerMsg *pMsg, bool bAck );

      // Gates an inbound APPLICATION message: refuses it before login, and
      // refuses a source that is not the logged-in identity (SECURITY_REVIEW
      // M2). On refusal it deletes pMsg and throws, so the connection is
      // dropped and the pump never sees the message. Shared by the socket
      // receive path and the P2PsigCon_MSG injection path, so the two cannot
      // drift - a check on one route only is a check with a way around it.
      void
        GateAppMsgInbound ( P2PeerMsg *pMsg );

      // Attaches this hub's origin attestation to an outbound APPLICATION
      // message, when the hub requires relay attestation and is entitled to
      // speak for the message's source. The counterpart of the ancestor half
      // of GateAppMsgInbound: that gate can only check a signature if
      // something made one.
      //
      // Never throws and never refuses to send. A message that cannot be
      // attested here - wrong hub for the source, no identity key, already
      // carrying an origin's block - goes out exactly as it would have. The
      // enforcement lives at the RECEIVING gate, and having only one end able
      // to refuse is deliberate: a sender that dropped its own traffic would
      // turn a receiver's policy into a sender's outage.
      void
        AttestAppMsgOutbound ( P2PeerMsg *pMsg );
      // End-to-end seal, the send half and the receive half.
      // NOTES: SealAppMsgOutbound is the ONE hook on the send path that can
      //        refuse - false means the caller must drop the message rather
      //        than send a body in clear that the operator asked to be
      //        hidden. Refer its own notes for why that is the opposite
      //        choice from AttestAppMsgOutbound's.
      bool
        SealAppMsgOutbound ( P2PeerMsg *pMsg );
      void
        OpenAppMsgInbound  ( P2PeerMsg *pMsg );

      // The ancestor half of GateAppMsgInbound, split out because it is the
      // only part of that gate with a policy switch and a second failure
      // vocabulary. Returns when the message may be admitted; otherwise
      // deletes pMsg and throws, exactly like its caller.
      //
      // Takes no address argument on purpose - it reads the message itself, so
      // it cannot be handed a pointer into the accessor ring that its own calls
      // have since recycled. That is not hypothetical; see the .cpp.
      void
        GateRelayInbound ( P2PeerMsg *pMsg );

      // Session key agreement.
      // NOTES: KeyXWanted() is the single gate - it answers "does this
      //        connection run an exchange", and everything else keys off it.
      //        An unconfigured hub answers false and none of this executes
      //      : KeyXOnRequest/KeyXOnAck consume their message; the caller
      //        deletes it and does not post it
      bool
        KeyXWanted    ( );
      void
        KeyXBegin     ( );                    // client: generate, send KeyX
      void
        KeyXOnRequest ( P2PeerMsg *pMsg );    // server: reply, derive
      void
        KeyXOnAck     ( P2PeerMsg *pMsg );    // client: derive, send login
      void
        KeyXDerive    ( );                    // secret -> binding -> cypher
      void
        LoginSend     ( const void *pvLoginMsg, P2Psize_t iSize );
};

///////////////////////////////////////////////////////////////////////
//  Safe P2PeerCon container
//  NOTES: Intended for stack use from P2PeerMsg handlers.  Do not
//         allow object to persist
//       : Useful for dynamic configuration of P2PeerCon objects
//         Example: if ( ConQuery("A.B",oSafeCon) )
//                    oSafeCon -> GetP2Peerio() -> SetIFTrace ( true );
//
class TargetCore_EXT SafeP2PeerCon
{
      void
        RenderThisSafe ( );
 
    // Constructors and destruction
    public:
        SafeP2PeerCon ( );
        SafeP2PeerCon ( P2PeerCon *pCon );
       ~SafeP2PeerCon ( );

    // Operators
    public:
      SafeP2PeerCon&
        operator = ( P2PeerCon *pCon );
      P2PeerCon*
        operator -> ( ) const;

        operator P2PeerCon* ( );

        operator bool ( );

    // Attributes
    private:
        P2PeerCon  *m_pP2PeerCon;
};

//
//  Operational states
//  NOTES: Used to summarise P2PeerCon connection behaviour and
//         states
const DWORD ConState_BCasts      = (1<<0);
const DWORD ConState_UCasts      = (1<<1);
const DWORD ConState_Recv        = (1<<2);
const DWORD ConState_Send        = (1<<3);
const DWORD ConState_PKey        = (1<<4);
const DWORD ConState_Login       = (1<<5);
const DWORD ConState_CloseOnIdle = (1<<6);

const DWORD ConBCasts_OK  = ( ConState_Send
                            | ConState_Login
                            | ConState_BCasts );
const DWORD ConUCasts_OK  = ( ConState_Send
                            | ConState_Login
                            | ConState_UCasts );
const DWORD ON_ConClose   = ( ConState_Send | ConState_Recv
                            | ConState_Login | ConState_CloseOnIdle );
const DWORD ON_ConShutdown= ( ConState_Send | ConState_Recv
                            | ConState_Login | ConState_CloseOnIdle );

                                       // P2P::nMsg alternatives
constexpr short P2P_P2Pmsg     = 0;
constexpr short P2P_Startup    = 10;
constexpr short P2P_Listen     = 1;
constexpr short P2P_Connect    = 2;
constexpr short P2P_Accept     = 3;
//constexpr short P2P_Reject     = 4;
constexpr short P2P_Close      = 5;
constexpr short P2P_Dropout    = 5;
//constexpr short P2P_Mute       = 6;
constexpr short P2P_Login      = 7;
constexpr short P2P_LoginAck   = 8;
constexpr short P2P_Notify     = 9;
constexpr short P2P_IdleNotify = 11;
constexpr short P2P_Destroy    = 12;
constexpr short P2P_PITimer    = 13;
constexpr short P2P_Shutdown   = 14;
constexpr short P2P_CypherEx   = 15;

//
//  P2Pevent::SetFParam ( const P2PmsgNode& oNode ) helpers
//  NOTES: Appends P2PmsgNode details to P2Pevent
//       : Usage
//         EVERR->MODULE
//              ->AFP(nPumpID)->AFPcon(pCon)->AFPyourObj(pYourObj)
//              ->Message("This is an event associated message")
//       : P2PmsgNode containing P2PeerCon details is appended beneath
//         the P2Pevent module node.  It should be assumed that any
//         appended parameters will have global exposure
#define AFPcon(arg) SetFParam(_N(#arg),arg->SetP2PeventFParams(_N(#arg)))

///////////////////////////////////////////////////////////////////////
//  Reserved connection management P2PmsgID's
//  NOTES: Such P2PmsgID's are reserved and as such issued and
//         intercepted by the underlying framework
//       : Refer P2PeerMsg.h for alternative framework list
//
static
P2PmsgID    P2Pmsg_ALL        = _N("P2Pmsg*");
static
P2PmsgID    P2Pmsg_Login      = _N("P2PmsgLogin");
static
P2PmsgID    P2Pmsg_LoginAck   = _N("P2PmsgLoginAck");
static
P2PmsgID    P2Pmsg_CypherEx   = _N("P2PmsgCypherEx");
//  Session key agreement. Intercepted and consumed inside P2PeerCon - these
//  never reach the pump, so they need no signal, no pump-map entry and no
//  application handler. The exchange is library business.
static
P2PmsgID    P2Pmsg_KeyX       = _N("P2PmsgKeyX");
static
P2PmsgID    P2Pmsg_KeyXAck    = _N("P2PmsgKeyXAck");


