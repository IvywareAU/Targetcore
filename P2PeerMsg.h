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
//  P2PeerMsg definitions and prototypes
//  NOTES: Container that facilitates the asychronous exchange of
//         messages between P2PeerHub's and subsequent routing through
//         the registered ID_SPIN_LBPeriodsies of derivered P2PeerTarget's
//       : These object's are not designed to be thread or context
//         safe and as such reference MUST be isolated
//
#pragma once

#include <atomic>

#include "P2Peer.h"
#include "Msgexception.h"
#include "P2PmsgBSTR.h"

//
//  P2PeerMsg associated definitions and limits
//  NOTES: Must be common across any given P2Peer network
#define MAX_P2PeerMsg_Index 16
const   P2Psize_t MAX_P2Psize = 32768; // Maximum P2PeerMsg size (login/key-exchange handshake message is ~4KB; 2048 rejects it and drops the connection)

//  Largest message WrappedResponseFactory will embed inside a response
//  NOTES: An undeliverable message is answered with a P2Pmsg_Exception that
//         embeds the whole message as a BLOB16 item, so the response is always
//         BIGGER than the thing it reports on.  Nothing bounded that, and the
//         message heap the response is built in is 16-bit addressed - 65535
//         bytes.  Measured (Debug, 2026-08-13, p2p_bigreport / the suite case):
//         a 29991-byte message produced a 64574-byte report and just fitted; a
//         30991-byte one threw "Internal VBHeapRoot.uVBLockAddr=1 corruption"
//         out of VBHeapRoot_SetFree(aFree=65561) on the ROUTING HUB'S PUMP
//         THREAD, and no report was sent at all.  The sender was never told its
//         message was undeliverable.  That band - roughly 30 KB up to
//         MAX_P2Psize - is squarely inside what a stock peer may send
//       : Half of MAX_P2Psize: the response has to carry the embedded image,
//         its own envelope AND the attached diagnostic, and still arrive under
//         the receiver's limit (P2Peerio::m_dwMaxRecvSize, also 32768 by
//         default) or the peer refuses the frame and drops the connection
//       : Past this the body is ELIDED - the response still carries a wrapped
//         message with the original name, source and destination, so
//         IsWrapped()/UnwrapFactory() and every existing handler behave as
//         before, but the payload is not copied.  A report that arrives
//         without the body beats a report that is never built
const   P2Psize_t MAX_P2PmsgWrapEmbed = MAX_P2Psize / 2;

//
//  P2PeerMsg Priority definitions
//  NOTES: General commands are issued at the P2PeerPriNormal priority.
//       : The flush priority is reserved exclusively for cleaning out
//         pending control sequences.
//       : The high priority is reserved for activities of greater importance.
//       : The low priority is reserved for activities of less importance.
//
//       : Stick to normal priority otherer wise implementation order
//         creates secondary behaviour.
//
const   UCHAR P2PeerPriFlush =  0;
const   UCHAR P2PeerPriNormal=  7;
const   UCHAR P2PeerPriHigh  = P2PeerPriNormal - 5;
const   UCHAR P2PeerPriLow   = P2PeerPriNormal + 5;

//
//  P2PeerMsg parameters
//  NOTES: Persists within the P2PeerMsgPrefix::ucState item
//
const   P2Pmsg_t P2P_Reflected       (1<<(sizeof(P2Pmsg_t)*8-1));

const   UCHAR P2PeerMsgState_Normal    =     0;
const   UCHAR P2PeerMsgState_Reflected = (1<<0);
const   UCHAR P2PeerMsgState_Ack       = (1<<1);
const   UCHAR P2PeerMsgState_Exception = (1<<2);
const   UCHAR P2PeerMsgState_Posted    = (1<<3);

//
//  P2PeerMsg control options
//  NOTES: Persist within P2PeerMsgPrefix::uiCtrl item
const   UINT08 P2PeerMsgCtrl_NONE      =     0;
const   UINT08 P2PeerMsgCtrl_EXCEPTIONS= (1<<0); // Generate routing exceptions
const   UINT08 P2PeerMsgCtrl_HANDLED   = (1<<1); // Know P2PeerMsg flag

const   UINT08 P2PeerMsgCtrl_DEFAULT   =  P2PeerMsgCtrl_EXCEPTIONS;

//
//  P2PeerMsgPrefix details
//  NOTES: P2PeerMsg prefix structure.  Contains private P2PeerMsg
//         address independant context information.
//       : Contained within P2PmsgData area of the primary P2PmsgNode
#pragma pack(push,1)
typedef struct P2PeerMsgPrefix
{
    UCHAR          eType;              //   P2PmsgVT_P2Pmsg
    DWORD          nSourceID;          // Source  P2PeerHub ID
    DWORD_PTR      dwAddrTag_;         // Source  P2PeerTarget tag
    DWORD          nDestinID;          // Destin  P2PeerHub ID
    //P2PeerID       nConmapID_;
    P2Pmsg_t       nMsg;               // TODO be deleted Xover only

    UINT08         uiCtrl;
    UINT08         ucPriority;
    UINT16         uiState;
    UINT08         uiP2Pexpump;
} P2PeerMsgPrefix;
#pragma pack(pop)

//
//  Common P2PeerMsg internal names and labels
#define TMsg_Src L"Src"
#define TMsg_Dst L"Dst"
#define TMsg_Tag L"Tag"
//  Relay attestation - the origin's signature over this message, carried
//  alongside the addresses rather than inside the payload. Refer
//  P2PeerMsg::SetRelayAttest and p2pauth's kRelayFixedLen block comment.
#define TMsg_Att L"Att"
//  End-to-end seal marker. Presence says the PAYLOAD is a p2pseal block and
//  not application bytes; the value is the plaintext length the sender sealed,
//  which is a hint for sizing and never trusted - Open reports the true length
//  and the GCM tag is what makes it true.
//
//  A MARKER AND NOT THE BODY, which is the opposite of the choice TMsg_Att
//  made, and for the opposite reason. The attestation is metadata ABOUT a
//  payload that stays readable, so it belongs beside it. A seal REPLACES the
//  payload - that is what hiding it means - so the block goes where the
//  payload was and only the fact of it lives here. A relay reads this field to
//  know it is carrying something it must not try to interpret; it does not
//  need, and must not have, anything else.
#define TMsg_Sld L"Sld"

//  End-to-end SCOPE - what the ORIGIN addressed this message to, as distinct
//  from where the next hop is taking it.
//
//  TMsg_Dst answers two different questions and for a unicast they have the
//  same answer, which is why nothing noticed for so long. To the sender it is
//  "where this is ultimately going"; to the router it is "who this link hands
//  it to". The fan-out is where the two part company: On_P2PeerBCast does not
//  send the message that was posted, it sends a COPY PER LINK re-addressed to
//  that link's own peer (P2PeerHub.cpp, RedirectFactory). From the first hop
//  onward Dst names the next hop, and nothing on the message says what the
//  origin meant any more.
//
//  Two protections read Dst as the first meaning, and so were silently wrong
//  on every fanned-out copy:
//    - SealAppMsgOutbound's last-hop exemption compares the peer against Dst,
//      which is TRUE AT EVERY HOP once the copy is re-addressed. The seal hook
//      never fired, so a broadcast crossed relays in clear - not refused by
//      the confidentiality default, silently outside it.
//    - AttestRelay digests Dst, and the origin's block is forwarded untouched
//      BY DESIGN (a relay that re-signed would substitute its own authority),
//      so a re-addressed copy no longer verifies. The far end refuses it and
//      drops the link.
//  One mechanism, two protections, both lost. Measured 2026-08-24, and again
//  on Linux 2026-08-25: p2p_sealbcast phase 3.
//
//  The scope is stamped ONCE, by the hub that fans a message out, and
//  RedirectFactory does not touch it - the copy inherits it exactly as it
//  inherits every other field in the image. ABSENT means the two meanings
//  still coincide, i.e. an ordinary unicast, and GetScopeOrDestin() falls back
//  to Dst so that path is byte-for-byte what it always was. That fallback is
//  also what keeps a fixed hub and an unfixed one agreeing about a unicast.
//
//  A NEW FIELD RATHER THAN NOT REWRITING Dst: the receiving hub accepts and
//  dispatches on Dst naming itself, so the re-addressing is load-bearing for
//  delivery and cannot simply be dropped. The next-hop meaning has to stay
//  where it is; it was the end-to-end meaning that needed somewhere else to
//  live.
#define TMsg_Scp L"Scp"

//
//
//  P2PeerMsg object
//  NOTES: P2Peer data wrapper.  
// 
class TargetCore_EXT P2PeerMsg : public P3PmsgBSTR
{
      void
        RenderThisSafe ( );
      void
        ResetThisObject ( );

    // Constructors and destructor
    public:
        P2PeerMsg ( );

        P2PeerMsg ( const P2PeerMsg& rhs );

        P2PeerMsg ( P2PmsgHANDLE hVBList );

        P2PeerMsg ( UCHAR uVBLockAddr, VBLsize nSizeof );

        P2PeerMsg ( const VBListIOmage& oIOmage );

        P2PeerMsg ( VBListIOmage *pIOmage );

        // The same, with the extent of the buffer the image sits in. Use this
        // one for anything that arrived from outside this process: it is what
        // makes the block walks run as an acceptance test rather than as a
        // debug-build assertion. P2Peerio::RecvP2PeerMsg does.
        P2PeerMsg ( VBListIOmage *pIOmage, VBLsize nBufferLen );

        P2PeerMsg ( P2PmsgID pszMsgID );

        P2PeerMsg ( P2PaddrSTR oSourceSTR, P2PaddrSTR oDestinSTR
                  , P2PmsgID pszMsg
                  , const void *pvMsgData, P2Psize_t iMsgDataSize );
        P2PeerMsg ( const P3PmsgField& oSource, const P3PmsgField& oDestin
                  , P2PmsgID pszMsg
                  , const void *pvMsgData, P2Psize_t iMsgDataSize );
        P2PeerMsg ( P2PaddrSTR oSourceSTR, P2PaddrSTR oDestinSTR
                  , P2PmsgID pszMsg
                  , LPCTSTR lpszMsgData, ... );
        P2PeerMsg ( const P3PmsgField& oSource, const P3PmsgField& oDestin
                  , P2PmsgID pszMsg
                  , LPCTSTR lpszMsgData, ... );
        //P2PeerMsg ( P2PaddrSTR oSourceSTR, P2PaddrSTR oDestinSTR
        //          , const P2Pevent& oP2Pevent );
      virtual
       ~P2PeerMsg ();

    // Overloaded operators
    public:
      P2PeerMsg&
        operator  = ( const P2PeerMsg& rhs );
      P2PeerMsg&
        operator [] ( int nIdx );

    // Factories
    public:
      P2PeerMsg*
        ResponseFactory ( P2PmsgID pszMsg
                        , const void *pvMsgData, P2Psize_t iMsgDataSize );
      P2PeerMsg*
        WrappedResponseFactory ( P2PmsgID pszMsg
                               , const void *pvMsgData, P2Psize_t iMsgSize );
      P2PeerMsg*
        ReflectFactory ( ) const;
      P2PeerMsg*
        LoopbackFactory( ) const;
      P2PeerMsg*
        ExceptionFactory ( P2Pevent *pEVT );
      P2PeerMsg*
        WrapFactory ( P2PmsgID pszMsg
                    , const void *pvMsgData, P2Psize_t iMsgDataSize );
      void
        WrapAttach ( P2PeerMsg *pP2Pmsg );
      //P2PeerMsg*
      //  ErrorResponseFactory ( P2Pevent *pP2Pevent );
      P2PeerMsg*
        RedirectFactory ( P2PaddrSTR oDestinSTR );
      P2PeerMsg*
        RedirectFactory ( P2PaddrSTR oDestinSTR
                        , P2PmsgID sMsg
                        , const void *pvMsgData, P2Psize_t iMsgDataSize );
      P2PeerMsg*
        UnwrapFactory ( );

    // P2Pevents
    public:
      void
        AttachP2Pevent ( const P2Pevent *pEvent
                       , LPCTNAM lpszFieldName = 0 );
      P2Pevent*
        ExtractP2Pevent( LPCTNAM lpszFieldName = 0 );

    // Utilities
    private:
      bool
        CheckSum ( );

    // P2PeerMsg_MAP routing
    // NOTES: Used for P2PeerMsg routing and handler assignment
    public:
      bool
        Map_MatchState( USHORT uiMsgStateWildbits );
      bool
        Map_MatchName ( LPCTNAM lpszMapWildcard ) const;

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
      virtual void
        Print ( FILE *fd );
      virtual LPCTSTR
        GetVisualRTSummary ( );
      virtual const P3PmsgItem&
        SetP2PeventFParams ( LPCTNAM lpszVar );

    // Property management
    public:
      P2PaddrSTR
        GetSource ( ) const;
      P2PaddrSTR
        SetSource ( P2PaddrSTR strSource );
      P3PmsgField&
        SetSource ( const P3PmsgField& oSource );
      P2PaddrSTR
        GetDestin ( ) const;
      P2PaddrSTR
        SetDestin ( P2PaddrSTR strDestin );
      P3PmsgField&
        SetDestin ( const P3PmsgField& oDestin );
      P2PaddrSTR
        GetConmap ( );
      P2PaddrSTR
        SetConmap ( P2PaddrSTR strConmap );
      // Relay attestation - the origin's proof of authorship
      // NOTES: A NAMED FIELD, deliberately, and not a prefix on the payload
      //        the way the login auth block is. The login block can be
      //        prepended because exactly one thing reads a login and it can
      //        hide the block again (P2PeerCon::GetAuthStripLen). An
      //        application message is read by application handlers, and
      //        prepending to it would mean every handler either saw 300-odd
      //        bytes it did not send, or depended on a strip that has to be
      //        right on every path the message can take. As a field it is
      //        invisible to Data()/DataSize() and there is no strip to get
      //        wrong.
      //      : It rides in the network node next to Src and Dst, so it
      //        survives relaying for exactly the same reason Conmap does -
      //        the whole node travels in the image, not just the payload.
      //      : Not carried by the BSTR / 3rd-party framings, which put only
      //        the payload bytes on the wire and have no addresses either.
      //        A hub that requires relay attestation cannot accept downward
      //        transit over one of those links, and refuses it as unattested
      //        rather than appearing to check something.
      const void*
        GetRelayAttest ( size_t *pcbOut );
      void
        SetRelayAttest ( const void *pvBlock, size_t cbBlock );
      bool
        HasRelayAttest ( );
      // End-to-end scope - refer TMsg_Scp above.
      // NOTES: GetScopeOrDestin() is what a caller wants almost always: the
      //        address the ORIGIN addressed this to when one was stamped, and
      //        Dst when none was - which is the unicast case and the
      //        overwhelming majority of traffic.
      //      : BOTH ENDS OF A CHECK MUST USE THE SAME ACCESSOR. The sealer and
      //        the opener, the attester and the verifier, are pairs; reading
      //        one through GetDestin and the other through GetScopeOrDestin
      //        digests two different transcripts and fails in a way that looks
      //        like a bad key.
      //      : Not carried by the BSTR / 3rd-party framings, for the same
      //        reason TMsg_Att and TMsg_Sld are not - those put only payload
      //        bytes on the wire and have no addresses either.
      P2PaddrSTR
        GetScope         ( ) const;
      P2PaddrSTR
        SetScope         ( P2PaddrSTR strScope );
      bool
        HasScope         ( ) const;
      P2PaddrSTR
        GetScopeOrDestin ( ) const;
      // End-to-end seal marker - refer TMsg_Sld above.
      // NOTES: SetSealed is called by the sealing path AFTER SetData has
      //        replaced the payload with the sealed block, and ClearSealed by
      //        the opening path after it has put the plaintext back. Neither
      //        touches the payload itself: keeping the marker and the bytes as
      //        two steps means a half-done seal is visible as a disagreement
      //        rather than as a body that looks fine and will not open.
      //      : Not carried by the BSTR / 3rd-party framings, for the same
      //        reason TMsg_Att is not - they put only payload bytes on the
      //        wire. A hub that requires sealing therefore cannot send
      //        relayed traffic over one of those links, and refuses rather
      //        than sending a block the far end cannot recognise.
      bool
        IsSealed    ( size_t *pcbPlainHint = 0 );
      void
        SetSealed   ( size_t cbPlainHint );
      void
        ClearSealed ( );
      //  THE PAYLOAD POINTER CARRIES NO ALIGNMENT GUARANTEE.  It addresses
      //  the application bytes where they sit INSIDE the packed message
      //  image, and that image is pack(1) throughout - so a payload begins
      //  at whatever offset the block headers and names before it add up to.
      //  About half of them are odd.
      //    Reading it as bytes, or memcpy-ing it somewhere aligned, is
      //  always correct.  Casting it to wchar_t* or overlaying a struct on
      //  it is undefined behaviour: it works on x86, UBSan reports it on
      //  Linux, and it faults on a strict-alignment target.  See
      //  finding F-S5-3, and P3PmsgData::c_vBlobCopy()
      //  for the alignment-safe read.
      char*
        Data ( ) const;
      size_t
        DataSize ( );
      P2Psize_t
        SetData ( P2PmsgID pszMsg
                , const void *pvMsgData, P2Psize_t iMsgDataSize );
      UCHAR
        Priority ( );
      UCHAR
        SetPriority ( UCHAR iPriority );
      DWORD_PTR
        AddrTag    ( );
      DWORD_PTR
        SetAddrTag ( const void *pvUserTag, P2Psize_t iSize );
      bool
        IsWrapped ( );
      bool
        IsReflected ( );
      virtual P2Psize_t
        Sizeof ( ) const;
      virtual int
        GetDepth ( ) const;
      bool&
        Exceptions ( );
      bool
        Exceptions ( ) const;

    // Property exposure
    public:
      LPCTNAM
        c_name ( ) const;
      P3PmsgField&
        r_Source ( ) const;
      P3PmsgField&
        r_Destin ( ) const;

    // Attributes
    private:
      P2PeerMsg    *m_pP2PmsgWrap{nullptr};
      char          m_szVisualHdr[128];
      CString      *m_pstrVisualSummary{nullptr};
      P2PeerMsg    *m_pP2PmsgParent{nullptr};
    protected:
      friend class P2PeerTarget;
      friend class P2PeerPump;
      friend class P2PeerMsgQue;
};
typedef P2PSafePtr<P2PeerMsg> P2PeerMsgSP;
typedef CList<P2PeerMsg*> CListP2PeerMsg;
extern  TargetCore_EXT std::atomic<UINT> g_P2PeerMsgInstances;  // ++/-- across pump threads - atomic (TSan Risk #3)

///////////////////////////////////////////////////////////////////////
//  P2PeerMsgnn targeted addressing 
//  NOTES: Usage P3PmsgBSTR32 oBSTR32; etc
template<UCHAR uBSTRnn>
class P2PeerMsgnn : public P2PeerMsg
{
    public:
        P2PeerMsgnn ( ) : P2PeerMsg ( uBSTRnn, 2024 ) { };
        P2PeerMsgnn ( VBLsize nSizeof ) : P2PeerMsg ( uBSTRnn, nSizeof ) {};
        P2PeerMsgnn ( P2PaddrSTR oSourceSTR, P2PaddrSTR oDestinSTR
                    , P2PmsgID pszMsg
                    , const void *pvMsgData, P2Psize_t iMsgDataSize )
                    : P2PeerMsg ( uBSTRnn, 2024 )
        {
          // Addressing
    ASSERT(r_name().VerifyContainment()); 
          r_name().c_name ( pszMsg );
    ASSERT(r_name().VerifyContainment()); 
          SetSource ( P3PmsgField ( TMsg_Src, DataWSTR08(oSourceSTR) ) );
          SetDestin ( P3PmsgField ( TMsg_Dst, DataWSTR08(oDestinSTR) ) );
          // Data
          // NOTES: Passed data is placed in the data node header
          if ( iMsgDataSize <= 255 )
            InitItem ( VBLockBSTR_MSG
                   , P3PmsgData(pvMsgData,iMsgDataSize,VBLockData_BLOB08) );
          else
            InitItem ( VBLockBSTR_MSG
                   , P3PmsgData(pvMsgData,iMsgDataSize,VBLockData_BLOB16) );
        };
      virtual
       ~P2PeerMsgnn ( ) {};
};
typedef P2PeerMsgnn<VBLock_Addr16> P2PeerMsg16;
typedef P2PeerMsgnn<VBLock_Addr32> P2PeerMsg32;
typedef P2PeerMsgnn<VBLock_Addr64> P2PeerMsg64;

//
//  P2Pevent::SetFParam ( const P2PmsgNode& oNode ) helpers
//  NOTES: Appends P2PmsgNode details to P2Pevent
//       : Usage
//         EVERR->MODULE
//              ->AFP(nPumpID)->AFPmsg(pMsg)->AFPyourObj(pYourObj)
//              ->Message("This is an event associated message")
//       : P2PmsgNode containing P2PeerMsg details is appended beneath
//         the P2Pevent module node.  It should be assumed that any
//         appended parameters will have global exposure
#define AFPmsg(arg) SetFParam(_N(#arg),arg->SetP2PeventFParams(_N(#arg)))

///////////////////////////////////////////////////////////////////////
//  Reserved framework management P2PeerMsg's
//  NOTES: These P2PmsgID's are reserved and as such intercepted and
//         interpreted by the underlying framework
//

//
//  P2Pmsg_3rdParty definition
//  NOTES: Generic P2PeerMsg used to flag a raw message transmitter
//         without header details.
//       : Facilitates transparent P2Peer interaction with
//         3rd Party interfaces.
//
static
const P2PmsgID P2Pmsg_3rdParty = _N("P2Pmsg_3rdParty");
static
const P2PmsgID P2Pmsg_3rdPartyi= _N("P2Pmsg_3rdPartyi");
static
const P2PmsgID P2Pmsg_3rdPartyo= _N("P2Pmsg_3rdPartyo");

//
//  P2Pmsg_Stop
//  NOTES: Terminate P2PeerHub processing
static
const P2PmsgID P2Pmsg_Stop = _N("P2PmsgStop");

//
//  P2Pmsg_Error
static
const P2PmsgID P2Pmsg_Error = _N("P2PmsgError");

//
//  P2Pmsg_Undeliverable definition
static
P2PmsgID P2Pmsg_Undeliv = _N("P2PmsgUndeliv");

//
//  P2Pmsg_Poll
//  NOTES: Poll remote P2PeerHub
#pragma pack(push,1)
typedef struct
{
    DWORD      dwUserData;
    DWORD      dwMillisecs;
} Msg_P2PeerPoll;
#pragma pack(pop)
static
P2PmsgID P2Pmsg_Poll = _N("P2PmsgPoll");

//
//  P2Pmsg_Ping
//  NOTES: Used to ping remote P2PeerHub.
//       : Designed measure turn around tarnsit times etc.
#pragma pack(push,1)
typedef struct
{
    DWORD      dwUserData;
    DWORD      dwCounter;
    DWORD      dwMillisecs;
} Msg_P2PeerPing;
#pragma pack(pop)
static
P2PmsgID P2Pmsg_Ping = _N("P2PmsgPing");

//
//  P2Pmsg_BCast
//  NOTES: Broadcast wrapped data down through the heirachical network
//         of P2PeerHub's
//       : P2PeerCon's must enable broadcast propagation
static
P2PmsgID P2Pmsg_BCast = _N("P2PmsgBCast");

//
//  P2Pmsg_Sync
//  NOTES: Exchange synchronisation request between P2PeerHub's
static
P2PmsgID P2Pmsg_Sync = _N("P2PmsgSync");

//
//  P2Pmsg_Eventails
static
P2PmsgID P2Pmsg_Eventails = _N("P2PmsgEventails");

//
//  P2Pmsg_Exception
//  NOTES: Used to throw and route P2PeerMsg exceptions between
//         P2PeerHub's
const   DWORD P2PeerException_Undeliv = 1;
const   DWORD P2PeerException_Unknown = 2;
const   DWORD P2PeerException_Version = 3;
#pragma pack(push,1)
typedef struct
{
    DWORD       dwExcepType;
    char        cEVTag;
} Msg_Exception;
#pragma pack(pop)
static
P2PmsgID P2Pmsg_Exception = _N("P2PmsgException");

//
//  P2Pmsg_Timer
#pragma pack(push,1)
typedef struct
{
    DWORD      dwUserKey;
} Msg_P2PeerTimer;
#pragma pack(pop)
static
P2PmsgID P2Pmsg_Timer = _N("P2PmsgTimer");

///////////////////////////////////////////////////////////////////////
//  P2PeerID networking and addressing

//
//  P2PeerMsg locking and unlocking
//TargetCore_EXT P2PeerMsg*
//P2PeerMsg_P2PmsgLock ( P2PeerMsg *pMsg, bool bEoD );
//TargetCore_EXT P2PeerMsg*
//P2PeerMsg_P2PeerConLock ( P2PeerMsg *pMsg, bool bEoD );

//
//  Manage P2PeerID addressing ID_SPIN_LBPeriodsy and routing
//  NOTES: IsP2PeerChild() is used to confirm nChildID
//         of nParentID
//       : IsP2PeerRable() is used to confirm nMsgID
//         routable down through strP2Paddr
TargetCore_EXT P2PeerMsg*
P2PeerMsg_SetReflected ( P2PeerMsg *pMsg, bool bReflected );
TargetCore_EXT P2PeerMsg*
P2PeerMsg_DstSwapSrc ( P2PeerMsg *pMsg );
TargetCore_EXT bool
Wildcard ( P2PmsgID strWildcard, P2PmsgID strMsgName );

//
//  State summary etc
TargetCore_EXT BOOL
P2PeerMsg_IsPosted ( const P2PeerMsg *pMsg );
TargetCore_EXT UINT08
P2PeerMsg_SetCtrlOptions ( P2PeerMsg *pMsg
                         , UINT uiCtrlOptionAdd, UINT08 uiCtrlOptionRemove );

