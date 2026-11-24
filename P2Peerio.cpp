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
//  P2Peerio base class implementation
//  NOTES: Manages P2PeerMsg image exchanges
//

#include "stdafx.h"
#include "P2Peerio.h"
#include "P2PeerCon.h"
#include "P2Pwin32.h"

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

P2Peerio::P2Peerio ( ) noexcept
{
    // Firstly
    RenderThisSafe();
}

P2Peerio::~P2Peerio ( )
{
    // Cancellation of PITimer's
    if ( m_nPITimerIDack )
      CancelP2PmsgTimer ( m_nPITimerIDack );

    // Garbage collection
    if ( m_pCon           &&
         m_pOVERLAPPEDack    )
      m_pCon -> DropOVERLAPPED ( m_pOVERLAPPEDack );
    if ( m_pCon              &&
         m_pOVERLAPPEDcrypto    )
      m_pCon -> DropOVERLAPPED ( m_pOVERLAPPEDcrypto );

    // Encryption objects
    if ( m_oP2Piomage.pEncrypted )
      m_oP2Piomage.pEncrypted = P2Piomage_Release ( m_oP2Piomage.pEncrypted );
    if ( m_pP2Pcrypto )
      delete m_pP2Pcrypto;
}

void
P2Peerio::RenderThisSafe() noexcept
{
    // Attributes
    m_pCon                = nullptr;
    m_pP2Pcrypto          = nullptr;
    m_oP2Piomage.pEncrypted = nullptr;
    m_oP2Piomage.nSizeof    = 0;
    m_bIFTraceEoD         = false;
    m_bAckEoD             = false;
    m_bSealDecided        = false;   // F-S6-3: no frame has been prepared yet
    m_bEncrypted          = false;   // was NEVER assigned, yet SetP2PeventFParams
                                     // (:1051) reads it into every P2Pevent raised
                                     // on a P2Peerio - i.e. on every refusal path

    m_dwIFmask            =~(DWORD)0;
    m_nPITimerIDack       = 0;
    m_dwMaxSendSize       = 32768;   // was 2048: too small for the login/key-exchange handshake message (~4KB) -> RecvP2PeerMsg rejects & drops
    m_dwMaxRecvSize       = 32768;

    m_pOVERLAPPEDack      = 0;
    m_pOVERLAPPEDcrypto   = 0;
}

P2Peerio*
P2Peerio::Clone ( )
{   
    P2Peerio *pP2Peerio = new P2Peerio();
              pP2Peerio -> SetIFmask ( GetIFmask() );
              pP2Peerio -> m_dwMaxRecvSize = m_dwMaxRecvSize;
              pP2Peerio -> m_dwMaxSendSize = m_dwMaxSendSize;
    return    pP2Peerio;
}

P2Peerio*
P2Peerio::Register ( P2PeerCon *pCon )
{   
    m_pCon = pCon;
    return this;
}

//
//  Posts an encryption - decryption object
//  NOTES: Life cycle of posted object is managed internally
//
//  Parameters:  P2Pcrypto *pP2Pcrypto
//               Posted encryption - decryption object
//
void
P2Peerio::PostP2Pcrypto ( P2PeerioCrypto *pP2Pcrypto )
{
    if ( m_pP2Pcrypto )
      delete m_pP2Pcrypto;
    m_pP2Pcrypto = pP2Pcrypto;
}

//
//  Processes I/O completion port packets mapped to an instance of this
//  object.
//  NOTES: Such packets are retieved via the Win32
//         GetQueuedCompletionStatus() module.
//
//
//  Parameters: DWORD dwError
//              Number of bytes transferred during an I/O operation
//              that has completed.  Refer ::GetQueuedCompletionStatus
//              for further details.
//               
//              DWORD dbBytes
//              Number of bytes transferred during an I/O operation
//              that has completed.  Refer ::GetQueuedCompletionStatus
//              for further details.
//
//              OVERLAPPEDcon *pOVERLAPPEDcon
//              Address of OVERLAPPEDcon structure that was specified
//              for the I/O operation.
//
//  Returns:    bool
//              Processing summary flag
//                true... Packet processed
//                false.. Not handled
bool
P2Peerio::On_QueuedCompletionStatus ( DWORD dwError
                                    , DWORD dwBytes
                                    , OVERLAPPEDcon *pOVERLAPPEDcon )
{
    UNREFERENCED_PARAMETER(dwError);
    UNREFERENCED_PARAMETER(dwBytes);

    // P2Psignal_ACK
    // NOTES: Simply release OVERLAPPEDcon whilst infrastructure
    //        manages life cycle
    if ( pOVERLAPPEDcon->nSigID == P2PsigIO_ACK )
    {
      m_pCon -> releaseOVERLAPPED ( pOVERLAPPEDcon );
      if ( pOVERLAPPEDcon->bDelete )
        m_pCon -> DropOVERLAPPED ( pOVERLAPPEDcon );
      return true;
    }

    // P2PsigID_PKEY had a branch here for the legacy Diffie-Hellman exchange
    // NOTES: Removed with that exchange.  Nothing ever assigned P2PsigID_PKEY
    //        to an OVERLAPPEDcon::nSigID anywhere in the tree, so it was
    //        unreachable - and it was wrong: it called DropOVERLAPPED() and
    //        then read pOVERLAPPEDcon->pUserDB2 out of the freed block, before
    //        an ASSERT(0) the author left as a marker that the path was never
    //        finished.  The live key agreement is ECDH P-256 / HKDF-SHA256 /
    //        AES-256-GCM, negotiated in P2PeerCon (KeyXOnRequest/KeyXOnAck)
    //        and installed here through PostP2Pcrypto()

    // Tidy up and
    return false;
}

///////////////////////////////////////////////////////////////////////
//  IO
//  NOTES: Completion Port transmission and receipt
//       : Override for 3rd Party protocol implementation
//

//
//  Sends P2PeerMsg
//  NOTES: Override this method to customise a protocol
//
//
//  Parameters:  HANDLE hFile
//               Send P2PeerMsg file handle
//
//               P2PeerMsg *pMsg
//               Message to be sent
//
//               OVERLAPPEDcon *pOVERLAPPEDsend
//               Pointer to an OVERLAPPEDcon send buffer
//
DWORD
P2Peerio::SendP2PeerMsg ( HANDLE hFile
                        , P2PeerMsg *pMsg
                        , OVERLAPPEDcon *pOVERLAPPEDsend )
{
    // Introduce locals
    const P2Piomage *pSendP2Piomage;
    DWORD            nSendP2PiomageSize;
    DWORD           dwResult;

    // To be sure, to be sure
    // NOTES: Confirm buffer not already in use
    ASSERT(!pOVERLAPPEDsend->bQueued);
    if ( pOVERLAPPEDsend->bQueued )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message(_T("OVERLAPPEDsend buffer already in use") )
           ->Advice (_T("Internal conflict (Bug)") )
           ->Group(_T("P2P"))->Throw();

    // Prepare, measure and seal the frame
    // NOTES: Shared with StageP2PeerMsg (T3) so the two cannot drift
    if ( PrepareSendFrame ( pMsg, &pSendP2Piomage ) == kSendRefusedFrame )
      return kSendRefusedFrame;

    // Send message
    nSendP2PiomageSize = P2Piomage_Sizeof ( pSendP2Piomage );
    ASSERT(nSendP2PiomageSize);
    if ( Send(hFile,pSendP2Piomage,nSendP2PiomageSize,pOVERLAPPEDsend) )
    {
      dwResult = GetLastError();
      if ( dwResult != ERROR_IO_PENDING )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message(_T("Send(%i bytes) failed")
                      , nSendP2PiomageSize )
             ->Group(_T("W32"))->HResult( dwResult )->Throw();
    }

    // Tidy up and
    return 0;
}

//
//  Prepares one outbound frame: trim, prepare, frame cap, cypher, seal mark
//  NOTES: The body of SendP2PeerMsg up to the write, unchanged, so that a
//         gathered frame (StageP2PeerMsg) and a lone one are the same bytes
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be sent
//
//               const P2Piomage **ppImage
//               Receives the frame to write: the message's own image or the
//               cypher's swap buffer, which the next call overwrites
//
//  Returns:     DWORD
//                 0.. Frame ready
//                 kSendRefusedFrame.. Over m_dwMaxSendSize, nothing encrypted
//
DWORD
P2Peerio::PrepareSendFrame ( P2PeerMsg *pMsg, const P2Piomage **ppImage )
{
    const P2Piomage *pSendP2Piomage;

    //  Live bytes only (p2p_performance.md M1, 3.7.0): the frame is the whole
    //  heap, so drop its free tail first. BEFORE the prepare, which stamps the
    //  length, so the frame-cap check and the cypher below both see the short
    //  frame. An old receiver takes it - the image carries no capacity, only
    //  its length. Refer P2PmsgHeap_TrimIOMAGE
    pMsg -> TrimP2Piomage     ( );
    pMsg -> PrepareP2Piomage  ( GetIFmask() );   // Mandatory

    // Prepare IMAGE type message exchanges
    // NOTES: These messages are sent in two parts, the first
    //        being the size and the second being the actual
    //        message
    //      : Expectation is that pMsg exists in a static state
    //        for the duration of the Send()
    ASSERT(!pMsg->Map_MatchName(P2Pmsg_3rdParty));
    pSendP2Piomage = pMsg -> P2Piomage ( );
     //nSendIOmageSize = pMsg -> IOmageSize ( );

    // Frame size limit (F-P0-15)
    // NOTES: BEFORE the cypher, and before the sealing decision is minted.  A
    //        frame over m_dwMaxSendSize is refused by the far end's
    //        RecvP2PeerMsg by dropping the connection, so it is not written:
    //        nothing leaves, nothing is encrypted, and the caller is told by a
    //        return code it can tell apart from success.  P2PeerCon refuses
    //        the MESSAGE, reports it to its source and sends the next one.
    //        Refer kSendRefusedFrame for why the check lives here
    if ( FrameSizeOf ( pMsg, pSendP2Piomage ) > m_dwMaxSendSize )
    {
      pMsg -> ReleaseP2Piomage ( );
      return kSendRefusedFrame;
    }

    // Encryption
    // NOTES: Last immediate action before buffer transmission.  Encryption 
    //        logic is intended to be fully self contained.  With function call
    //        overhead the price to pay.
    //      : Encrypted buffer substitution leaving the original P2PeerMsg
    //        internals un-encrypted for local (re-)use.
    //      : Key agreement frames are NEVER sealed.  They carry the public
    //        halves the session key is derived FROM, so sealing them would
    //        need the key they exist to establish.  Stating the exemption by
    //        message TYPE rather than by timing is what makes it
    //        deterministic: PostP2PeerMsg() only queues, and this function
    //        runs later on the IO thread, so "install the cypher once the
    //        acknowledgement has gone out" is not expressible at the call
    //        site that would have to say it
    if ( !pMsg->Map_MatchName(P2Pmsg_KeyX)    &&
         !pMsg->Map_MatchName(P2Pmsg_KeyXAck)    )
      pSendP2Piomage = EncryptP2PiomageSwap ( pSendP2Piomage );

    // The sealing decision has now been made, either way
    // NOTES: F-S6-3.  Send() below is where bytes actually
    //        leave this process, and it is reachable from an override that
    //        never came through here - P2PeerioBSTR is exactly that shape.
    //        This marks the frame Send() is about to write as one THIS
    //        function decided about; Send() requires the mark whenever a
    //        cypher is installed, and clears it again
    //      : Minted on BOTH branches on purpose.  The KeyX exemption above is
    //        a decision too, and a mark minted only where sealing happened
    //        would refuse the handshake that installs the key
    //      : This is the half of the rule that needs nothing from the subclass
    //        author.  LeavesProcess()/IsCypherActive() are answers they have
    //        to give; this one is taken rather than asked for
    m_bSealDecided = true;

    *ppImage = pSendP2Piomage;
    return 0;
}

///////////////////////////////////////////////////////////////////////
//  Send gather (p2p_performance.md T3).  Refer P2PeerioSendGather

//
//  Does THIS object gather?
//  NOTES: The stock class only, by exact type.  A subclass that overrides
//         SendP2PeerMsg frames its own bytes and must keep receiving one call
//         per message; one that does not override it would gather correctly,
//         but asking that cannot be done without a virtual, and a new vtable
//         slot is an ABI break.  Exact type is the conservative answer
//       : P2P_SEND_GATHER=0 turns it off, read once
//
bool
P2Peerio::CanGatherSend ( ) const
{
#if defined(_MSC_VER)
#  pragma warning( push )
#  pragma warning( disable : 4996 )   // getenv: read-only env lookup
#endif
    static const bool s_bOff = [] {
      const char *psz = getenv ( "P2P_SEND_GATHER" );
      return psz && strcmp ( psz, "0" ) == 0;
    } ( );
#if defined(_MSC_VER)
#  pragma warning( pop )
#endif
    return !s_bOff && ( typeid(*this) == typeid(P2Peerio) || IoGathers ( ) );
}

//
//  Starts a batch: nothing staged, no seal mark outstanding
//  NOTES: Also the recovery from a batch an exception abandoned, which is why
//         the caller runs it at the START of every batch rather than relying
//         on SendStaged having cleared it.  A buffer grown past four budgets
//         by an outsized frame is given back here
//
void
P2Peerio::ResetStaged ( OVERLAPPEDcon *pOv )
{
    P2PeerioSendGather *pG = (P2PeerioSendGather *)pOv->pUserDB1;
    ASSERT(!pOv->bQueued);
    if ( pG && pG->dwCap > 4 * P2PeerioSendGatherBudget )
    {
      delete [] pOv->pUserDB1;
      pOv->pUserDB1 = nullptr;
      pG            = nullptr;
    }
    if ( pG )
    {
      pG->dwUsed  = 0;
      pG->nFrames = 0;
      pG->nOne    = 0;
      pG->pvOne   = nullptr;
    }
    m_bSealDecided = false;
}

//
//  Copies bytes onto the end of the gather, growing it as needed
//
void
P2Peerio::GatherAppend ( OVERLAPPEDcon *pOv, const void *pv, DWORD n )
{
    P2PeerioSendGather *pG = (P2PeerioSendGather *)pOv->pUserDB1;
    if ( pG->dwCap - pG->dwUsed < n )
    {
      DWORD dwCap = pG->dwCap * 2;
      if ( dwCap < pG->dwUsed + n )
        dwCap = pG->dwUsed + n;
      char *pNew = new char [ sizeof(P2PeerioSendGather) + dwCap ];
      memcpy ( pNew, pOv->pUserDB1, sizeof(P2PeerioSendGather) + pG->dwUsed );
      delete [] pOv->pUserDB1;
      pOv->pUserDB1 = pNew;
      pG            = (P2PeerioSendGather *)pNew;
      pG->dwCap     = dwCap;
    }
    memcpy ( pOv->pUserDB1 + sizeof(P2PeerioSendGather) + pG->dwUsed, pv, n );
    pG->dwUsed += n;
}

//
//  Prepares one message's frame and adds it to the batch
//  NOTES: The pending lone frame is copied FIRST - before this message is
//         prepared - because the preparation may overwrite the cypher's swap
//         buffer it points into.  So when this returns, whatever it returns,
//         the message staged before this one is no longer referenced
//
//  Returns:     DWORD
//                 0.. Staged
//                 kSendRefusedFrame.. Refused as SendP2PeerMsg refuses it
//
DWORD
P2Peerio::StageP2PeerMsg ( P2PeerMsg *pMsg, OVERLAPPEDcon *pOv )
{
    ASSERT(!pOv->bQueued);
    if ( pOv->bQueued )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message(_T("OVERLAPPEDsend buffer already in use") )
           ->Advice (_T("Internal conflict (Bug)") )
           ->Group(_T("P2P"))->Throw();

    if ( !pOv->pUserDB1 )
    {
      pOv->pUserDB1 = new char [ sizeof(P2PeerioSendGather)
                               + P2PeerioSendGatherBudget ];
      P2PeerioSendGather *pG = (P2PeerioSendGather *)pOv->pUserDB1;
      pG->dwCap   = P2PeerioSendGatherBudget;
      pG->dwUsed  = 0;
      pG->nFrames = 0;
      pG->nOne    = 0;
      pG->pvOne   = nullptr;
    }
    P2PeerioSendGather *pG = (P2PeerioSendGather *)pOv->pUserDB1;
    if ( pG->nOne )
    {
      const void *pvOne = pG->pvOne;
      DWORD       nOne  = pG->nOne;
      pG->pvOne = nullptr;
      pG->nOne  = 0;
      GatherAppend ( pOv, pvOne, nOne );
      pG = (P2PeerioSendGather *)pOv->pUserDB1;
    }

    const P2Piomage *pImage;
    if ( PrepareSendFrame ( pMsg, &pImage ) == kSendRefusedFrame )
      return kSendRefusedFrame;
    DWORD nSize = P2Piomage_Sizeof ( pImage );
    ASSERT(nSize);

    if ( pG->nFrames == 0 )
    {
      pG->pvOne = pImage;
      pG->nOne  = nSize;
    }
    else
      GatherAppend ( pOv, pImage, nSize );
    pG = (P2PeerioSendGather *)pOv->pUserDB1;
    pG->nFrames++;
    return 0;
}

//
//  Is the batch at its bound?
//
bool
P2Peerio::GatherFull ( const OVERLAPPEDcon *pOv ) const
{
    const P2PeerioSendGather *pG = (const P2PeerioSendGather *)pOv->pUserDB1;
    return pG && ( pG->nFrames                >= P2PeerioSendGatherFrames ||
                   pG->dwUsed + pG->nOne      >= P2PeerioSendGatherBudget    );
}

//
//  Writes the batch with one transport write
//  NOTES: The lone frame from where it lies; two or more from the gather.  The
//         counters are cleared BEFORE the write: the bytes stay where they are
//         until the completion, and nothing stages again before it
//       : The seal mark Send() requires is the one PrepareSendFrame minted for
//         the staged frames - every byte written passed through it
//
//  Returns:     DWORD
//                 0.. Written, or nothing was staged
//
DWORD
P2Peerio::SendStaged ( HANDLE hFile, OVERLAPPEDcon *pOv )
{
    P2PeerioSendGather *pG = (P2PeerioSendGather *)pOv->pUserDB1;
    if ( !pG || pG->nFrames == 0 )
      return 0;
    const void *pv = pG->nOne ? pG->pvOne : pOv->pUserDB1 + sizeof(P2PeerioSendGather);
    DWORD       n  = pG->nOne ? pG->nOne  : pG->dwUsed;
    pG->dwUsed  = 0;
    pG->nFrames = 0;
    pG->nOne    = 0;
    pG->pvOne   = nullptr;
    ASSERT(n && m_bSealDecided);

    if ( Send ( hFile, pv, n, pOv ) )
    {
      DWORD dwResult = GetLastError();
      if ( dwResult != ERROR_IO_PENDING )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message(_T("Send(%i bytes) failed"), n )
             ->Group(_T("W32"))->HResult( dwResult )->Throw();
    }
    return 0;
}

//
//  Sends buffer via IO completion port
//  NOTES: Expect errors due to broken or dropped connections etc
//
//
//  Parameters: HANDLE hFile
//              Send data file handle
//
//              const void *pvData
//              Buffer to be sent.  This buffer must remain in scope
//              for the duration of the overlapped IO sequence.  May
//              or may NOT be encrypted.
//
//              DWORD dwSize
//              Buffer size in bytes
//
//              OVERLAPPEDcon *pOVERLAPPEDsend
//              Pointer to OVERLAPPEDcon structure. Returned via the
//              GetQueuedCompletionStatus()
//               
//
//  Returns:    DWORD
//              Result
//                0.. Queued OK
//                ?.. System error code
DWORD
P2Peerio::Send ( HANDLE hFile
               , const void *pvData, DWORD wDataSize
               , OVERLAPPEDcon *pOVERLAPPEDsend )
{
    // Locals
    DWORD hResult = S_OK;

    // To be sure, to be sure
    // NOTES: Confirm buffer not already queued
    if ( pOVERLAPPEDsend->bQueued )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message("Transmit buffer already in use")
           ->Advice ("Internal conflict (Bug)" )
           ->Group("P2P")->Throw();

    // Bytes are leaving this process - was a sealing decision made about them?
    // NOTES: F-S6-3, and this is the enforcement that needs
    //        no cooperation.  SendP2PeerMsg() mints the mark whether it sealed
    //        the frame or exempted it; anything reaching here WITHOUT it took
    //        the cypher hooks out of the path, and a cypher is installed, so
    //        these bytes are in clear on a connection that ran a key
    //        agreement and reports itself keyed
    //      : Conditioned on the cypher, not on the mark alone.  A hub with
    //        RequireAuth(false) posts no cypher and every transport here is
    //        in clear by the operator's own decision - refusing that would be
    //        refusing the configuration rather than the defect
    //      : Refused, not warned.  A warning on the frame that leaks is a
    //        record of the leak
    //      : Deliberately NOT conditioned on LeavesProcess().  Reaching this
    //        function IS leaving the process - it is the writer - so a
    //        subclass that declared itself in-process and then called it has
    //        contradicted itself, and the declaration is the wrong half to
    //        believe.  P2PeerioDmx, the real in-process transport, never
    //        arrives here: its handoff is a pointer, not a write
    if ( m_pP2Pcrypto && !m_bSealDecided )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message_T("Writing bytes with a session cypher installed that "
                       "nothing consulted" )
           ->Advice_T ("A P2Peerio subclass overrides SendP2PeerMsg and does "
                       "not route through EncryptP2PiomageSwap" )
           ->Advice_T ("Route the frame through P2Peerio::SendP2PeerMsg, "
                       "which makes the sealing decision" )
           ->Advice_T ("A transport that is not a wire does not reach this "
                       "function at all - refer P2PeerioDmx" )
           ->Group("P2P")->Throw();
    m_bSealDecided = false;

    // Preparation
    pOVERLAPPEDsend -> oOverlapped.Internal     = 0; 
    pOVERLAPPEDsend -> oOverlapped.InternalHigh = 0; 
    pOVERLAPPEDsend -> oOverlapped.Offset       = 0; 
    pOVERLAPPEDsend -> oOverlapped.OffsetHigh   = 0; 
    pOVERLAPPEDsend -> oOverlapped.hEvent       = 0;

    // Implementation
    // NOTES: The pvData buffer may or may not be contained within
    //        pOVERLAPPED send object
    m_pCon->prepareOVERLAPPED ( pOVERLAPPEDsend );
    if ( !IoWrite ( hFile
                  , pvData, wDataSize
                  , (OVERLAPPED *)pOVERLAPPEDsend ) )
    {
      hResult = GetLastError();
      if ( hResult == WAIT_TIMEOUT )
      {
        SetLastError ( ERROR_IO_PENDING );
        hResult = GetLastError();
      }

      if ( hResult != ERROR_IO_PENDING )
        m_pCon->releaseOVERLAPPED ( pOVERLAPPEDsend );
    }

    // Tidy up, and
    return hResult;
}

//
//  Pre-destruction handler for sent P2PeerMsg objects
//  NOTES: Called as part of the P2PeerCon management procedures
//         immediately prior to destruction
//       : Override this default implementation for special processing,
//         P2PeerMsg reuse etc
//
//
//  Parameters:  P2PeerMsg*
//               Sent message as per IOCP completion status
//
//  Returns:     P2PeerMsg*
//                 0.. Negates destruction and facilitates reuse. Life
//                     cycle control is internalised within method.
//                     
//                 
P2PeerMsg*
P2Peerio::PreDestroySendP2PeerMsg ( P2PeerMsg *pMsg )
{
   // Default implementation
   return pMsg;
}

//
//  Receives next P2PeerMsg
//  NOTES: Handles receipt of following message types
//           P2PeerMsg images, including headers
//           BSTR images, headers manufactured
//       : Override for other message formats
//
//
//  Parameters: HANDLE hFile
//              Receive P2PeerMsg file handle
//
//              OVERLAPPEDcon *pOVERLAPPEDrecv
//              Pointer to an OVERLAPPEDcon receive buffer
//
//  Returns:    P2PeerMsg*
//              Received P2PeerMsg.  Client assumes control over
//              life cycle
//                0.. Incomplete, queued IO completion port receive
//                     
//
P2PeerMsg*
P2Peerio::RecvP2PeerMsg ( HANDLE hFile
                        , OVERLAPPEDcon *pOVERLAPPEDrecv )
{
    // Introduce locals
    // NOTES: The receive ring (p2p_performance.md T2, Targetcore 3.8.0) - its
    //        layout, and why, is stated once in P2Peerio.h at P2PeerioRecvRing.
    //        One transport read takes what the transport has; every complete
    //        frame in the ring is handed out, one per call, before another read
    //        is issued.  Until 3.8.0 this function read the 8-byte header and
    //        then the body: two reads, two completions, every frame.
    //      : The refusals are the ones this function always made, with the same
    //        messages, made at the same point in a frame's arrival - the header
    //        checks as soon as the header is in, before anything is sized from
    //        it.  Only WHERE the bytes wait changed.
    DWORD             dwResult;
    VBListIOmage     *pIOmage = 0;
    const DWORD       nSync   = (DWORD)sizeof(pIOmage->oSync);
    UINT              nSizeof = 0;
    bool              bOwnBuf = false;     // the frame came through its own pUserDB2
    char             *pDst    = 0;
    DWORD             dwWant  = 0;

    // Stage 0 - Initialisation
    // NOTES: Once, at the start of receipt.  The buffer MakeOVERLAPPED gave
    //        this object is not used for receipt and is released, as before.
    if ( pOVERLAPPEDrecv->pUserDB1 == 0 )
    {
      if ( pOVERLAPPEDrecv->pBuffer == pOVERLAPPEDrecv->pUserDB2 )
        pOVERLAPPEDrecv -> pBuffer = 0;
      delete [] pOVERLAPPEDrecv -> pUserDB2;   // new char[] -> delete[]
             pOVERLAPPEDrecv -> pUserDB2 = 0;
      delete [] pOVERLAPPEDrecv -> pBuffer;    // new char[] (MakeOVERLAPPED) -> delete[]
             pOVERLAPPEDrecv -> pBuffer  = 0;
      pOVERLAPPEDrecv -> pUserDB1   = new char [sizeof(P2PeerioRecvRing)
                                               +P2PeerioRecvRingCap];
      P2PeerioRecvRing *pRing = (P2PeerioRecvRing *)pOVERLAPPEDrecv->pUserDB1;
      pRing -> dwCap  = P2PeerioRecvRingCap;
      pRing -> dwHead = 0;
      pOVERLAPPEDrecv -> dwBytesMax = P2PeerioRecvRingCap;
      pOVERLAPPEDrecv -> dwBytes    = 0;
    }

    // Stage 1 - A frame larger than the ring
    // NOTES: Its header was checked in stage 2 when it arrived and its bytes so
    //        far moved here; the rest is read straight into this buffer, exactly
    //        as every body was read before 3.8.0
    if ( pOVERLAPPEDrecv->pUserDB2 )
    {
      // To be sure, to be sure
      if ( pOVERLAPPEDrecv->dwBytes > pOVERLAPPEDrecv->dwBytesMax )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message("Recv(%i vs %i) bytes failed\n"
                       "Attempted buffer overrun"
                      , pOVERLAPPEDrecv->dwBytes, pOVERLAPPEDrecv->dwBytesMax )
             ->Group("P2P")->Throw();
      nSizeof = pOVERLAPPEDrecv -> dwBytesMax;
      bOwnBuf = true;
      if ( pOVERLAPPEDrecv->dwBytes < nSizeof )
        goto RECVNEXT;
      goto STAGE4;
    }

    // Stage 2 - The next frame in the ring
    {
      P2PeerioRecvRing *pRing = (P2PeerioRecvRing *)pOVERLAPPEDrecv->pUserDB1;
      char             *pData = P2PeerioRecvRingData ( pOVERLAPPEDrecv );
      for ( ;; )
      {
        // To be sure, to be sure
        if ( pOVERLAPPEDrecv->dwBytes > pRing->dwCap  ||
             pRing->dwHead            > pOVERLAPPEDrecv->dwBytes )
          EVERR->Module (__FUNCTION__)->AFPeerio(this)
               ->Message("Recv(%i vs %i) bytes failed\n"
                         "Attempted buffer overrun"
                        , pOVERLAPPEDrecv->dwBytes, pRing->dwCap )
               ->Group("P2P")->Throw();

        const DWORD dwAvail = pOVERLAPPEDrecv->dwBytes - pRing->dwHead;
        if ( dwAvail < nSync )
          break;                               // header not in yet

        // The header, COPIED: a frame starts wherever the last one ended, so
        // the ring offers no alignment for the two UINTs
        decltype(pIOmage->oSync) oSync;
        memcpy ( &oSync, &pData[pRing->dwHead], nSync );

        // Re-synchronisation
        // NOTES: Not a header: step past one byte and look again - the slide
        //        by one this function always did, now an index rather than a
        //        memmove of the header buffer (the memmove was itself the fix
        //        for an overlapping memcpy, see git history)
        if ( (oSync.uiSync1+oSync.uiSync2) != ~0 )
        {
          ++pRing->dwHead;
          continue;
        }

        // LAYOUT GENERATION - THE WIRE TAKES THE CURRENT ONE ONLY.
        // NOTES: The complement relation above says "this is plausibly a
        //        header".  It cannot say "this is a header I can parse":
        //        complement and byte swap commute (byte_order.md §3.2), and a
        //        pre-sentinel or foreign-generation image satisfies it exactly
        //        as a current one does.
        //      : This runs BEFORE the size is read because the size field's
        //        meaning is part of what a generation defines.  Bits 0-23 are
        //        the size in generation 1; nothing promises that of a layout
        //        this build has never seen.
        //      : The STORE answers this differently on purpose -
        //        P2PmsgMgr::Load still accepts a pre-sentinel image and warns
        //        rather than refusing, because a file is data somebody already
        //        has while a frame is a peer that can be upgraded
        //        (byte_order.md §4.3).
        //      : There is no registry of reserved codes to enumerate. One
        //        code is defined and every other non-zero pattern is a layout
        //        this build does not implement, named by its code - which
        //        covers a generation 3 nobody has designed yet, where an
        //        enumerated registry would have covered only the codes
        //        somebody remembered to reserve.
        //      : Refusing HERE rather than downstream is what makes the
        //        diagnostic specific.  Every one of these already ended the
        //        connection - as "Invalid VBListIOmage" raised from inside
        //        Msgcore, after the allocation below had already happened.
        const int nSyncForm = VBLock_SyncForm ( oSync.uiSync1 );
        if ( nSyncForm != VBLockSync_Native )
          EVERR->Module (__FUNCTION__)->AFPeerio(this)
               ->Message("Message image layout generation 0x%02X is not this "
                         "build's 0x%02X (%s)"
                        , (UINT)VBLock_SyncGenCode ( oSync.uiSync1 )
                        , (UINT)VBLock_SyncGenNow
                        , nSyncForm == VBLockSync_Legacy  ? "a pre-sentinel peer"
                        : nSyncForm == VBLockSync_Swapped ? "opposite endianness"
                        :                                   "a layout this build "
                                                            "does not implement" )
               ->Advice ("Connection discontinued")
               ->Throw();

        nSizeof = oSync.uiSync1 & 0x00FFFFFF;
        if ( nSizeof > m_dwMaxRecvSize )
          EVERR->Module (__FUNCTION__)->AFPeerio(this)
               ->Message("Attempt to exceed maximum (%i) buffer size (%i)"
                        , m_dwMaxRecvSize, nSizeof )
               ->Advice ("Connection discontinued")
               ->Throw();
        // Lower bound: a valid image must at least cover a full VBListIOmage
        // header. Without this, an undersized nSizeof (e.g. 0..7) would be
        // taken as a frame shorter than its own header - the copy-out below
        // reads only nSizeof bytes, but the image built from them would claim
        // more - and later underflows IOmage_Sizeof in the decrypt path.
        if ( nSizeof < sizeof(VBListIOmage) )
          EVERR->Module (__FUNCTION__)->AFPeerio(this)
               ->Message("Undersized message (%i) below minimum header size (%i)"
                        , nSizeof, (UINT)sizeof(VBListIOmage) )
               ->Advice ("Connection discontinued")
               ->Throw();

        // The whole frame is here: copy it out and hand it on.  The ring is
        // rewound when it empties, so a connection that is never more than one
        // frame behind never compacts
        if ( dwAvail >= nSizeof )
        {
          pOVERLAPPEDrecv -> pUserDB2 = new char [nSizeof+4];
          memcpy ( pOVERLAPPEDrecv->pUserDB2, &pData[pRing->dwHead], nSizeof );
          pRing -> dwHead += nSizeof;
          if ( pRing->dwHead == pOVERLAPPEDrecv->dwBytes )
            pRing -> dwHead = pOVERLAPPEDrecv -> dwBytes = 0;
          goto STAGE4;
        }

        // It will never fit: move what has arrived into a buffer of its own
        // and read the rest there (stage 1).  The ring is empty afterwards -
        // everything in it was the start of this frame
        if ( nSizeof > pRing->dwCap )
        {
          pOVERLAPPEDrecv -> pUserDB2   = new char [nSizeof+4];
          memcpy ( pOVERLAPPEDrecv->pUserDB2, &pData[pRing->dwHead], dwAvail );
          pRing -> dwHead = 0;
          pOVERLAPPEDrecv -> dwBytes    = dwAvail;
          pOVERLAPPEDrecv -> dwBytesMax = nSizeof;
          goto RECVNEXT;
        }
        break;                                 // fits once the rest arrives
      }

      // Make room: what is left is the start of a frame (or of a header), so
      // slide it to the front.  Then the read can take the whole remainder
      if ( pRing->dwHead )
      {
        const DWORD dwAvail = pOVERLAPPEDrecv->dwBytes - pRing->dwHead;
        memmove ( pData, &pData[pRing->dwHead], dwAvail );
        pRing -> dwHead = 0;
        pOVERLAPPEDrecv -> dwBytes = dwAvail;
      }
      goto RECVNEXT;
    }

    // Stage 4 - Construct P2PeerMsg
    // NOTES: pUserDB2 holds exactly one frame of nSizeof bytes - copied out of
    //        the ring, or read into its own buffer by stage 1
STAGE4:
    {
      // PKey negotiations
      //if ( IOmage_IsPKeySwap(pIOmage) )
      //{
      //}

      // Decryption
      // NOTES: Immediate action upon receipt of buffer.  Encryption
      //        logic is intended to be fully self contained.  With function call
      //        overhead the price to pay.
      //      : Assume DecryptIOmageSwap() is capable of exceptions.  Responses
      //        to cypher issues are handled internally at the source
      void     *vpRecvIOmage     = pOVERLAPPEDrecv -> pUserDB2;
      //  HOW MANY BYTES ARE ACTUALLY THERE.  Threaded into the P2PeerMsg
      //  construction below; see the note there for what it buys.
      //
      //  nSizeof is the header's declared size, refused above unless it lies
      //  between the minimum header and the receive cap, and it is what the
      //  pUserDB2 allocation was sized from and what was copied or read into it
      //  - so it is the extent BY CONSTRUCTION: this function wrote both
      //  numbers from the same one.
      DWORD_PTR  nRecvIOmageExtent = nSizeof;
                vpRecvIOmage     = DecryptP2PiomageSwap ( (P2Piomage *)vpRecvIOmage );
      if ( vpRecvIOmage != pOVERLAPPEDrecv -> pUserDB2 )
      {
        delete [] pOVERLAPPEDrecv -> pUserDB2;   // new char[] (stage 2 / stage 1) -> delete[]
               pOVERLAPPEDrecv -> pUserDB2 = (char *)vpRecvIOmage;
        if ( vpRecvIOmage == nullptr )
        {
          if ( bOwnBuf )                 // back onto the ring
          {
            pOVERLAPPEDrecv -> dwBytes    = 0;
            pOVERLAPPEDrecv -> dwBytesMax = P2PeerioRecvRingCap;
          }
          return nullptr;              // DecryptIOmageSwap() handles cypher issues
        }
        pIOmage = (VBListIOmage *)pOVERLAPPEDrecv->pUserDB2;
        //  A DIFFERENT BUFFER, so a different extent: this buffer holds the
        //  shorter plaintext.  DecryptP2PiomageSwap builds it with
        //  P2Piomage_Alloc and then stamps oSync with the size it allocated, so
        //  the declared size here is the extent BY CONSTRUCTION rather than by
        //  trust: this process wrote both numbers from the same one.
        nRecvIOmageExtent = (DWORD_PTR)( pIOmage->oSync.uiSync1 & 0x00FFFFFF );
      }

      // Intercept specials
      //if ( pIOmage->nAction )
      //{
      //}

      // External image morphs into P2PeerMsg at this point
      // NOTES: Bad images very quickly throw exceptions
      //      : THE EXTENT IS PASSED, and until 2026-08-21 it was not.  The
      //        one-argument constructor reaches P2PmsgHeap_CreateIOMAGE(pIOmage),
      //        which ends in
      //            ASSERT(P2PmsgHeap_AssertValidIOMAGE(pHandle));
      //            ASSERT(P2PmsgHeap_AssertVBlocksIOMAGE(pHandle));
      //        - the whole of both block walks inside the assertion.  So the
      //        structure of a frame from an unauthenticated stranger was checked
      //        in the build nobody ships and, in the build everybody does, not at
      //        all: a forged block chain was ADOPTED without being walked.  That
      //        is Stage 1 step 4, and this line is where it was
      //        entered.
      //      : The two-argument form takes the length-validated path instead,
      //        which walks the image FOR REAL in every build and throws on the
      //        answer.  It also walks it as a GATE (MsgVBHeap.h): wire data that
      //        breaks an invariant is refused rather than asserted, because it is
      //        a stranger being wrong and not this library being wrong.  Between
      //        them those two facts are why `p2p_fuzzframe` went from 89,896
      //        assertions on a Debug run to none, without losing a check.
      //      : Ownership on failure is unchanged, and the harness depends on it.
      //        The create detaches the image before closing its handle and then
      //        throws, so pUserDB2 is still ours and is still freed by the
      //        OVERLAPPEDcon; only a RETURN transfers it.
      P2PeerMsg *pMsg = new P2PeerMsg ( (VBListIOmage *)pOVERLAPPEDrecv->pUserDB2
                                      , (VBLsize)nRecvIOmageExtent );
      pOVERLAPPEDrecv -> pUserDB2   = 0;
      if ( bOwnBuf )                     // back onto the ring
      {
        pOVERLAPPEDrecv -> dwBytes    = 0;
        pOVERLAPPEDrecv -> dwBytesMax = P2PeerioRecvRingCap;
      }
      //  Before 3.8.0 this zeroed the oSync of whatever pIOmage last pointed
      //  at: the header buffer, or - on a decrypted frame - the plaintext image
      //  the message now holds.  The header buffer is gone; the second is kept
      //  exactly, because the message has carried it that way ever since
      if ( pIOmage )
        pIOmage -> oSync.uiSync1 = 0;

      // Tidy up, and
      return pMsg;
    }

    // Issue the next transport read
    // NOTES: Only here, and only with no complete frame buffered.  The request
    //        is never empty: the ring is short of a header or of a frame that
    //        fits it, and an own buffer is short of its frame - so a zero-byte
    //        completion can only be the peer's FIN (F-S4-1), never a read of
    //        nothing
RECVNEXT:
    P2PeerioRecvRequest ( pOVERLAPPEDrecv, &pDst, &dwWant );
    dwResult = Recv ( hFile, pDst, dwWant, pOVERLAPPEDrecv );
    if ( dwResult )
    {
      if ( dwResult != ERROR_IO_PENDING )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message("Recv(%i bytes) failed", dwWant )
             ->HResult( dwResult )->Throw();
    }

    // Tidy up and
    return nullptr;
}

//
//  Receives buffer via IO completion port
//  NOTES: Expect errors due to broken or dropped connections etc
//
//
//  Parameters: HANDLE hFile
//              Receive data file handle
//
//              void *pvData
//              Data receive buffer.  This buffer must remain in scope
//              for the duration of the completion port read sequence
//
//              DWORD dwSize
//              Buffer size in bytes
//
//              OVERLAPPEDcon *pOVERLAPPEDrecv
//              Pointer to OVERLAPPEDcon structure. Returned via the
//              GetQueuedCompletionStatus()
//
//  Returns:    DWORD
//              Result
//                0.. Queued OK
//                ?.. System error code
DWORD
P2Peerio::Recv ( HANDLE hFile
               , void *pvData, DWORD dwSize
               , OVERLAPPEDcon *pOVERLAPPEDrecv )
{
    // Locals
    DWORD hResult = S_OK;

    // To be sure, to be sure
    // NOTES: Confirm buffer not already queued
    if ( pOVERLAPPEDrecv->bQueued )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message_T("Receive buffer already in use" )
           ->Advice_T ("Internal conflict (Bug)" )
           ->Group("P2P")->Throw();

    // Preparation
    pOVERLAPPEDrecv -> oOverlapped.Internal     = 0; 
    pOVERLAPPEDrecv -> oOverlapped.InternalHigh = 0; 
    pOVERLAPPEDrecv -> oOverlapped.Offset       = 0; 
    pOVERLAPPEDrecv -> oOverlapped.OffsetHigh   = 0; 
    pOVERLAPPEDrecv -> oOverlapped.hEvent       = 0; 

    // Implementation
    // NOTES: Queue request, RecvP2PeerMsg() processes the result
    //      : Operation expected to return ERROR_IO_PENDING state
    //      : bRecvSubmitted is the MARK AT SUBMISSION half of F-S4-1.  This is
    //        the only place in the tree that submits a transport read on a
    //        recv OVERLAPPEDcon, so it is the only place that can say a later
    //        zero-byte completion on that object came from the wire rather
    //        than from an arming PostQueuedCompletionStatus.  Set BEFORE
    //        ReadFile, because a synchronously-completing read queues its
    //        completion packet anyway and the pump may reach it first
    m_pCon -> prepareOVERLAPPED ( pOVERLAPPEDrecv );
    pOVERLAPPEDrecv -> bRecvSubmitted = true;
    //DWORD dwRead = 0;
    if ( !IoRead(hFile
                ,pvData,dwSize,(OVERLAPPED *)pOVERLAPPEDrecv) )
    { // Error condition, OVERLAPPED object rejected by IOCP
      hResult = GetLastError();
      if ( hResult == WAIT_TIMEOUT )
      {
        SetLastError ( ERROR_IO_PENDING );
        hResult = GetLastError();
      }

      // Rejected outright: no completion will arrive, so the mark must not
      // outlive the submission that failed to happen
      if ( hResult != ERROR_IO_PENDING )
      {
        pOVERLAPPEDrecv -> bRecvSubmitted = false;
        m_pCon -> releaseOVERLAPPED ( pOVERLAPPEDrecv );
      }
    }

    // ReadFile completed SYNCHRONOUSLY (TRUE) — the requested data was already
    // buffered in the socket/pipe.  Because hFile is bound to an I/O completion
    // port and FILE_SKIP_COMPLETION_PORT_ON_SUCCESS is NOT set, a completion
    // packet is STILL queued, so this must be treated EXACTLY like
    // ERROR_IO_PENDING: leave the OVERLAPPED queued and let the IOCP completion
    // drive processing.
    // NOTE: the previous code read a STALE GetLastError() here (ReadFile does
    //       not clear it on success) and misreported synchronous success as a
    //       "Conflicting ReadFile() outcome" failure — which dropped every
    //       connection whose next message was already buffered, i.e. ALL
    //       post-login application messages (the login recv only escaped it
    //       because its data had not yet arrived and returned ERROR_IO_PENDING).
    else
    {
      hResult = ERROR_IO_PENDING;      // completion will arrive via the IOCP
    }

    // Tidy up, and
    return hResult;
}

//
//  Transport byte I/O - the defaults (refer the contract in P2Peerio.h)
//  NOTES: Exactly the calls Send() and Recv() made before 3.10.0
//
BOOL
P2Peerio::IoWrite ( HANDLE hFile, const void *pvData, DWORD dwSize, OVERLAPPED *pOv )
{
    return WriteFile ( hFile, pvData, dwSize, 0, pOv );
}

BOOL
P2Peerio::IoRead ( HANDLE hFile, void *pvData, DWORD dwSize, OVERLAPPED *pOv )
{
    return ReadFile ( hFile, pvData, dwSize, 0, pOv );
}

///////////////////////////////////////////////////////////////////////
//  Timers
//  NOTES: Implemented via synchronous callbacks from the assigned
//         P2PmsgPump

//
//  Sets PIT for P2Peerio
//  NOTES: Outstanding timers must be cancelled in destructor for
//         this object
//       : Triggered timer is implemented via On_PITimer() call back
//         to this object
//
//
//  Parameters: P2PeerTime_t uMSecDelay
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
P2Peerio::SetPITimer ( P2Pmsecs_t uMSecDelay, DWORD dwUserKey )
{
    // Delegation
    // NOTES: Handler for this object always called
    return SetP2PmsgTimer ( 0, this, uMSecDelay, dwUserKey );
}

//
//  PITimer handler for P2Peerio
//  NOTES: Override for specialisation.  But always delegate unhandled
//         timers through
//       : Callbacks to this method are synchronous from the assigned
//         pump and as such should not indulge in lengthy processing
//         sequences or suspend control flow
//
//
//  Parameters: bool bCancel
//              Cancellation flag.  Refer CancelPITimer() for further
//              details
//                true... Cancelled
//                false.. Triggered
//
//              PITimerID nPITimerID
//              Timer identification.  Refer SetPITimer() for
//              further details
//
//              DWORD dwUserKey
//              Timer user key
//
void
P2Peerio::On_PITimer ( bool bCancel
                     , PITimerID nPITimerID, DWORD dwUserKey )
{
    // Acknowledgement
    if ( nPITimerID == m_nPITimerIDack )
    {
      m_nPITimerIDack = 0;
      // NOTES: There is nothing to process.  m_nPITimerIDack is the only
      //        timer id this class holds, and it is initialised to 0,
      //        tested, cancelled and cleared - but never ARMED.  No
      //        SetPITimer() in the tree assigns it, so it stays 0, every
      //        cancel guarding it is false, and this branch can only match
      //        a dispatched timer whose id is 0 - which no live timer has.
      //        Default acknowledgement processing needs the timer started
      //        first, and that is an ack policy decision, not a gap here
      return;
    }

    // Unknown timer
    // NOTES: Report and ignore.  Maintain existing P2PeerCon state
    EVERR->Module ( T__FUNCTION__ )
         ->AFP(bCancel)->AFP(nPITimerID)->AFP(dwUserKey)->AFPeerio(this)
         ->Message(_T("PITimer on (%s-%s) not handled")
                  , m_pCon->GetP2PaddrHub().c_wstr()
                  , m_pCon->m_oThatP2Paddr.c_wstr() )
         ->Advice (_T("Ignored, bug (SNHappen)") )
         ->Cancel ();
}

///////////////////////////////////////////////////////////////////////
//  Specialisation

//
//  Acknowledge message receipt
//  NOTES: Acknowledge P2PeerMsg's in the context that they are
//         received.  As a consequence multiple OVERLAPPED sends
//         may be outstanding.
//
//
//  Parameters: HANDLE hFile
//              Send acknowledgement file handle
//
//              P2PeerMsg *pMsg
//              Message to be acknowledged
// 
void
P2Peerio::Acknowledge ( HANDLE hFile, P2PeerMsg *pMsg )
{
    UNREFERENCED_PARAMETER ( hFile );
    UNREFERENCED_PARAMETER ( pMsg );
}

//
//  On_Acknowledgement receipt processing
//  NOTES: Available for those interfaces observing low
//         level ack - nak protocols
//       : Introduces significant overhead on throughput
//
//
//  Parameters: bool bAckNak
//              Acknowledgement state
//
//
//  Returns:    Summary
//                true... Expected
//                false.. Unexpected
bool
P2Peerio::On_Acknowledge ( bool bAckNak )
{
    ASSERT(0);
    UNREFERENCED_PARAMETER(bAckNak);
    // Observe expectations
    // NOTES: OVERLAPPEDsend passes through the IOCP at least
    //        two times per P2PeerMsg
    //      : Important, clear wait for acknowledgement flag, set
    //        acknowledgement state
    if ( !m_pCon->m_pOVERLAPPEDsend->bQueued )
    {
      m_pCon -> PostOVERLAPPED ( m_pCon->m_pOVERLAPPEDsend );
      return true;
    }

    // Cancel acknowledgement PITimerID
    if ( m_nPITimerIDack )
      CancelP2PmsgTimer ( m_nPITimerIDack );

    // Tidy up, and
    return false;
}

///////////////////////////////////////////////////////////////////////
//  Encryption - decryption

//
//  Legacy Diffie-Hellman PKey exchange - REMOVED
//  NOTES: These four methods implemented the hand-rolled DH exchange that
//         DHKeyXChanger.cpp also implemented, differently: the sender emitted
//         hex and the receiver parsed radix 10, the bounds check tested
//         Alice's private value on Bob's side where it is always zero, and
//         A.Exp(b).Mod(p) expanded a 256-bit base to a 64-bit power BEFORE
//         reducing - a remote memory-exhaustion primitive on a pre-auth path
//         (SECURITY_REVIEW M7).  The modulus was not prime and the private
//         exponents came from srand(time(NULL))/rand()
//       : None of it ever ran.  m_vpDH was never allocated - there was no
//         "new DH" in this file - so OnPKeyXChange() and OnPKeyXChangeAck()
//         opened on a guaranteed null dereference, and the IOCP branch that
//         reached them was itself unreachable
//       : The live key agreement is ephemeral ECDH P-256 -> HKDF-SHA256 ->
//         AES-256-GCM, run by P2PeerCon (KeyXBegin/KeyXOnRequest/KeyXOnAck)
//         and installed on this object through PostP2Pcrypto().  See
//         P2PCngCrypto.h and SECURITY.md
//       : The declarations are kept because P2PeerCon and P2PeerTarget's
//         default handlers are part of the documented target-map surface.
//         They now refuse rather than pretend: a third-party subclass that
//         reaches one of these is asking for a protocol that no longer
//         exists, and a clear refusal beats the silent stall the empty
//         bodies used to produce
//
//  Parameters: const P2Piomage *pP2Piomage
//              Ignored
void
P2Peerio::PKeyXChange ( const P2Piomage * )
{
    EVERR->MODULE
         ->Message_T("Legacy PKey exchange removed")
         ->Advice_T ("The live key agreement is ECDH P-256 / AES-256-GCM, run by P2PeerCon")
         ->Throw ( );
}

void
P2Peerio::OnPKeyXChange ( const P2Piomage * )
{
    EVERR->MODULE
         ->Message_T("Legacy PKey exchange removed")
         ->Advice_T ("The live key agreement is ECDH P-256 / AES-256-GCM, run by P2PeerCon")
         ->Throw ( );
}

void
P2Peerio::PKeyXChangeAck ( const P2Piomage * )
{
    EVERR->MODULE
         ->Message_T("Legacy PKey exchange removed")
         ->Advice_T ("The live key agreement is ECDH P-256 / AES-256-GCM, run by P2PeerCon")
         ->Throw ( );
}

void
P2Peerio::OnPKeyXChangeAck ( const P2Piomage * )
{
    EVERR->MODULE
         ->Message_T("Legacy PKey exchange removed")
         ->Advice_T ("The live key agreement is ECDH P-256 / AES-256-GCM, run by P2PeerCon")
         ->Throw ( );
}

//
//  P2Piomage buffer encryption and swap
//  NOTES: Specialise both EncryptIOmageSwap() and DecryptIOmageSwap() methods
//         for encryption type and protocol
//       : Implementation is intended to be self contained
//
//  Parameters:  const P2Piomage *pP2PiomageSend
//               Un-encrypted P2Piomage to be sent with externally
//               managed life cycle
//
//  Returns:     const P2Piomage*
//               Encrypted P2Piomage pointer with internally managed life cycle.
//               NOTES: P2Piomage.oSync is exposed for message synchronisation
//                      purposes
//
const P2Piomage*
P2Peerio::EncryptP2PiomageSwap ( const P2Piomage *cpP2PiomageSend )
{
    // Default implementation
    if ( m_pP2Pcrypto == nullptr )
      return cpP2PiomageSend;          // No encryption

    // Sealed frame geometry
    // NOTES: The relationship is no longer one 4 one.  An AEAD prepends a
    //        nonce and appends a tag, so the sealed payload is longer than the
    //        plaintext one.  That is expressible on the wire because oSync is
    //        NOT itself encrypted - the receiver reads the length before it
    //        reads the body
    //      : P2Piomage_Alloc() stamps a total of sizeof(P2Piomage)+nDataSize,
    //        while IOmage_Sizeof() reports total-sizeof(P2Piomage)+1.  The two
    //        differ by one, so the argument that yields a payload of exactly
    //        nSealedIOmage bytes is one less than nSealedIOmage
    UINT nPlainIOmage  = IOmage_Sizeof ( cpP2PiomageSend );
    UINT nSealedIOmage = m_pP2Pcrypto -> SealedSize ( nPlainIOmage );
    if ( nSealedIOmage < nPlainIOmage || nSealedIOmage == 0 )
      EVERR->MODULE
           ->Message ( "Cypher reported a nonsensical sealed size (%u for %u)"
                     , nSealedIOmage, nPlainIOmage )
           ->Throw ( );
    UINT nSealedSizeof = nSealedIOmage + sizeof(P2Piomage) - 1;

    // Persistant encryption buffer
    // NOTES: Re-size if necessary.  nSizeof tracks the allocated capacity, so
    //        it is only ever written when the buffer is actually reallocated
    if ( m_oP2Piomage.pEncrypted    == nullptr       ||
         m_oP2Piomage.nSizeof       <  nSealedSizeof    )
    {
      m_oP2Piomage.pEncrypted = P2Piomage_Release ( m_oP2Piomage.pEncrypted );
      m_oP2Piomage.nSizeof    = nSealedSizeof;
      m_oP2Piomage.pEncrypted = P2Piomage_Alloc   ( 0, nSealedIOmage - 1 );
    }

    // Restamp the header for THIS frame
    // NOTES: oSync can no longer be copied across from the plaintext frame the
    //        way it was when sizes matched - the sealed length differs.  The
    //        addressing mode is carried over from the sender, the size is the
    //        sealed one, and the endian sentinel is stamped for this build
    m_oP2Piomage.pEncrypted -> oSync.uiSync1
      = VBLock_SyncMake ( nSealedSizeof
                        , VBLock_SyncAddr ( cpP2PiomageSend->oSync.uiSync1 ) );
    m_oP2Piomage.pEncrypted -> oSync.uiSync2
      = ~m_oP2Piomage.pEncrypted -> oSync.uiSync1;

    // Encrypt
    // NOTES: nBytes is the PLAINTEXT length; the cypher writes SealedSize() of
    //        them into the output buffer sized above
    if ( !m_pP2Pcrypto -> Encrypt ( &cpP2PiomageSend->cIOmage
                                  , &m_oP2Piomage.pEncrypted->cIOmage
                                  , (int)nPlainIOmage, 0, 0 ) )
      EVERR->MODULE
           ->Message_T ( "Payload encryption failed" )
           ->Throw ( );
    return m_oP2Piomage.pEncrypted;
}

//
//  Recv P2Piomage decryption and swap
//  NOTES: Specialise both DecryptP2PiomageSwap() and EncryptP2PiomageSwap()
//         methods for both encryption type and protocol
//       : Implementation MUST be and is intended to be self contained
//       : Should cypher issues be encountered the exception option exists
//         where by the connection will be shutdown.
//       : Alternatively a P2P_Cypher signal can be raised that will be
//         subsequently pumped through the P2PeerCon_MAP().  Connection remains
//         open and the reset action is managed in the handler
//
//  Parameters:  const P2Piomage *cpP2PiomageRecv
//               Encrypted message received
//
//  Returns:     P2Piomage pP2PiomageRecv
//               Encrypted buffer pointer with externally managed life cycle
//                 0.. Decryption failed, refer GetP2Pevent() for details
P2Piomage*
P2Peerio::DecryptP2PiomageSwap ( const P2Piomage *cpP2PiomageRecv )
{
    // Default implementation 
    if ( m_pP2Pcrypto == nullptr )
      return (P2Piomage *)cpP2PiomageRecv;

    // Decrypt
    // NOTES: Sizing parameters are not encrypted, so the sealed length is
    //        readable before the body is touched
    //      : OpenedSize() returning zero means the frame is too short to be a
    //        sealed frame at all - for an AEAD, shorter than its own nonce and
    //        tag.  That is a malformed frame and takes the cypher exception
    //        path rather than allocating a degenerate buffer
    UINT       nP2PiomageSizeof    = P2Piomage_Sizeof ( cpP2PiomageRecv );
    UINT       nSealedIOmage       = IOmage_Sizeof    ( cpP2PiomageRecv );
    UINT       nPlainIOmage        = m_pP2Pcrypto -> OpenedSize ( nSealedIOmage );
    P2Piomage *pP2PiomageDecrypted = nullptr;
    bool       bOpened             = false;

    if ( nPlainIOmage )
    {
      pP2PiomageDecrypted = P2Piomage_Alloc ( 0, nPlainIOmage - 1 );

      // Header describes the PLAINTEXT frame; addressing mode carried over
      // from the sender.  The previous revision stamped the sealed total here
      // and never corrected it, leaving the decrypted image overstating its
      // own length - unreachable, because no cypher was ever installed.
      pP2PiomageDecrypted -> oSync.uiSync1
        = VBLock_SyncMake ( nPlainIOmage + sizeof(P2Piomage) - 1
                          , VBLock_SyncAddr ( cpP2PiomageRecv->oSync.uiSync1 ) );
      pP2PiomageDecrypted -> oSync.uiSync2
        = ~pP2PiomageDecrypted -> oSync.uiSync1;

      bOpened = m_pP2Pcrypto -> Decrypt ( &cpP2PiomageRecv->cIOmage
                                        , (int)nSealedIOmage
                                        , &pP2PiomageDecrypted->cIOmage, 0, 0 )
              ? true : false;
    }

    if ( !bOpened )
    {
      // Cypher exception path: the signal below is manufactured from the
      // original (encrypted) cpP2PiomageRecv and this method returns nullptr,
      // so pP2PiomageDecrypted is never propagated - release it here to avoid
      // leaking the decryption buffer on every failed decrypt.
      // For an AEAD this is the forgery path: a tag that does not verify means
      // the frame was manufactured or altered in flight, and the connection is
      // torn down by the P2P_CypherEx handler.
      if ( pP2PiomageDecrypted )
        pP2PiomageDecrypted = P2Piomage_Release ( pP2PiomageDecrypted );
      P2PeerMsgSP spMsg = new P2PeerMsg ( m_pCon->GetP2Paddress()
                                        , m_pCon->GetP2PaddrHub()
                                        , P2Pmsg_CypherEx
                                        , cpP2PiomageRecv, nP2PiomageSizeof );
      PostP2Pmsg ( m_pCon->m_oThatP2Paddr, CN_P2PeerCon, P2P_CypherEx
                 , m_pCon, spMsg.Dereference(), m_pCon->m_hCPortP2PumpID );
      return nullptr;                  // Negates IOmage propogation
    }

    return pP2PiomageDecrypted;
}

//
//  Resets internals
//  NOTES: Intention is for object to be left in a re-usable state
//
void
P2Peerio::Reset ( )
{
    // Cancellation of PITimer's
    if ( m_nPITimerIDack )
      CancelP2PmsgTimer ( m_nPITimerIDack );

    // Garbage collection
    if ( m_pCon           &&
         m_pOVERLAPPEDack    )
      m_pCon -> DropOVERLAPPED ( m_pOVERLAPPEDack );
    if ( m_oP2Piomage.pEncrypted )
      m_oP2Piomage.pEncrypted = P2Piomage_Release ( m_oP2Piomage.pEncrypted );
    m_oP2Piomage.nSizeof = 0;

    // Encryption
    if ( m_pP2Pcrypto )
      delete m_pP2Pcrypto;
    m_pP2Pcrypto   = nullptr;
    m_bSealDecided = false;          // F-S6-3: no frame is in flight
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2Peerio::AssertValid ( ) const
{
    // TODO: Additional validation
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
P2Peerio::SetP2PeventFParams ( LPCTNAM lpszVar )
{
    // Create a placeholder for receipt of P2PeerCon details
    // NOTES: This will be passed by value back up the stack
    if ( lpszVar == nullptr )
      lpszVar = L"P2Peerio";
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData()) );

    // Summarise P2PeerCon parent state
    if ( m_pCon )
    {
      P3PmsgItem oNodeCon = oNodeVar.r_Desc().PushBack ( P3PmsgItem(L"m_pCon") );
      //  BOTH of these read GetP2PaddrHub() until 2026-09-19, so the dump
      //  reported the LOCAL hub address under both names and the peer address
      //  appeared nowhere in it. GetP2Paddress() is the accessor for the other
      //  end - it returns m_oThatP2Paddr (P2PeerCon.cpp:5150) - and the peer
      //  address is the field the source-binding gate keys on, so the one tool
      //  for debugging that gate could not see the value it turns on.
      oNodeCon += P3PmsgField ( L"m_oThisP2Paddr", DataWSTR16(m_pCon->GetP2PaddrHub().c_wstr()) );
      oNodeCon += P3PmsgField ( L"m_oThatP2Paddr", DataWSTR16(m_pCon->GetP2Paddress().c_wstr()) );
      oNodeCon += P3PmsgField ( L"m_nP2PconID", P3PmsgData(m_pCon->m_nP2PconID) );
    }
    //  m_dwMaxSendSize likewise reported m_dwMaxRecvSize. A serialiser whose
    //  whole job is to report state accurately carried two copy-paste slips
    //  four lines apart, and neither could ever fail a test: a dump that is
    //  wrong still parses.
    oNodeVar += P3PmsgField( L"m_dwMaxRecvSize",P3PmsgData(m_dwMaxRecvSize));
    oNodeVar += P3PmsgField( L"m_dwMaxSendSize",P3PmsgData(m_dwMaxSendSize));
    oNodeVar += P3PmsgField( L"m_bEncrypted",P3PmsgData(m_bEncrypted));

    // Tidy up and
    return oNodeVar;
}

///////////////////////////////////////////////////////////////////////
//  Properties

//
//  Toggles interface trace on and off
//
//  Parameters: bool bIFTraceEoD
//              Enabled or disabled state
//
//
//  Returns:    State
//                true... Enabled
//                false.. Disabled
bool
P2Peerio::SetIFTrace ( bool bIFTraceEoD )
{   
    return m_bIFTraceEoD = bIFTraceEoD;
}
bool
P2Peerio::GetIFTrace (  )
{   
    return m_bIFTraceEoD;
}

//
//  Exposes managing P2PeerCon object
//  NOTES: P2Peerio objects MUST be managed by a single P2PeerCon object
//
//  Returns:    P2PeerCon*
//              Managing connection object
//                0.. Unassigned or floating instance
//
P2PeerCon*
P2Peerio::GetP2PeerCon ( )
{   
    return m_pCon;
}

DWORD
P2Peerio::SetIFmask ( DWORD dwIFmask )
{   
    return m_dwIFmask = dwIFmask;
}

DWORD
P2Peerio::GetIFmask ( )
{   
    return m_dwIFmask;
}

DWORD
P2Peerio::SetMaxRecvSize ( DWORD dwMaxRecvSize )
{   
    ASSERT(dwMaxRecvSize>0);
    m_dwMaxRecvSize = dwMaxRecvSize;
    return m_dwMaxRecvSize;
}

DWORD
P2Peerio::GetMaxRecvSize ( ) const
{   
    return m_dwMaxRecvSize;
}

DWORD
P2Peerio::SetMaxSendSize ( DWORD dwMaxSendSize )
{   
    ASSERT(dwMaxSendSize>0);
    m_dwMaxSendSize = dwMaxSendSize;
    return m_dwMaxSendSize;
}

DWORD
P2Peerio::GetMaxSendSize ( ) const
{
    return m_dwMaxSendSize;
}

//
//  The size of the frame SendP2PeerMsg would write for a prepared image
//  NOTES: F-P0-15, refer the declaration.  Mirrors the size arithmetic of
//         EncryptP2PiomageSwap without running it: the plain frame is
//         P2Piomage_Sizeof, and a cyphered frame is the cypher's SealedSize of
//         the payload plus the header, exactly as EncryptP2PiomageSwap stamps
//         it.  The KeyX pair is never encrypted there, so it is not grown here
//
DWORD
P2Peerio::FrameSizeOf ( P2PeerMsg *pMsg, const P2Piomage *pImage )
{
    if ( !pImage )
      return 0;
    DWORD dwFrame = (DWORD)P2Piomage_Sizeof ( pImage );
    if ( m_pP2Pcrypto                        &&
         !pMsg->Map_MatchName(P2Pmsg_KeyX)   &&
         !pMsg->Map_MatchName(P2Pmsg_KeyXAck)   )
    {
      const UINT nPlain  = IOmage_Sizeof ( pImage );
      const UINT nSealed = m_pP2Pcrypto -> SealedSize ( nPlain );
      if ( nSealed >= nPlain )
        dwFrame = (DWORD)( nSealed + sizeof(P2Piomage) - 1 );
    }
    return dwFrame;
}

//
//  The frame size of an unprepared message, for a diagnostic
//  NOTES: Prepares, measures and releases.  Called by P2PeerCon only after
//         SendP2PeerMsg has returned kSendRefusedFrame, to say how big the
//         refused frame was - so it costs nothing on the path that sends
//       : The image is released on every path, a throw included:
//         PrepareP2Piomage ASSERTs that no image is outstanding
//
DWORD
P2Peerio::MeasureSendFrame ( P2PeerMsg *pMsg )
{
    if ( !pMsg )
      return 0;
    DWORD dwFrame = 0;
    pMsg -> ReleaseP2Piomage ( );
    pMsg -> PrepareP2Piomage ( GetIFmask() );
    try
    {
      dwFrame = FrameSizeOf ( pMsg, pMsg -> P2Piomage ( ) );
    }
    catch ( ... )
    {
      pMsg -> ReleaseP2Piomage ( );
      throw;
    }
    pMsg -> ReleaseP2Piomage ( );
    return dwFrame;
}

bool
P2Peerio::IsEncrypted ( )
{
    // Encryption is active iff a crypto provider has been attached; the
    // Encrypt/Decrypt paths treat m_pP2Pcrypto==nullptr as plain passthrough.
    return m_pP2Pcrypto != nullptr;
}
