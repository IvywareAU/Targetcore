// Copyright © 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerioXBee implementation
//
//  ####################################################################
//  ##  DESIGN SKETCH.  NOT COMPILED, NOT WIRED TO ANY FACTORY.       ##
//  ##  The two overrides and the framing helpers are written out;    ##
//  ##  ctor/dtor/Clone/Reset/AssertValid/SetP2PeventFParams are      ##
//  ##  named in the header and left to the implementer.              ##
//  ####################################################################
//

#include "stdafx.h"
#include "P2PeerioXBee.h"
#include "P2PeerCon.h"

///////////////////////////////////////////////////////////////////////
//  Protocol translation

//
//  Sends P2PeerMsg as a run of XBee API frames
//  NOTES: Seals ONCE, fragments the sealed image, and writes every
//         resulting frame in a SINGLE overlapped write
//       : WHY ONE WRITE AND NOT ONE PER FRAGMENT.  m_bSealDecided is
//         minted here and CONSUMED BY THE FIRST Send() - P2Peerio.cpp
//         clears it the moment it has checked it.  A loop calling
//         Send() per fragment therefore passes the F-S6-3 check on
//         fragment 0 and THROWS on fragment 1, on a frame that was
//         sealed correctly.  Minting the mark again inside the loop
//         would "fix" it by reducing the check to a rubber stamp.  The
//         serial line is a byte stream, so writing the frames
//         back to back in one buffer is what the wire wants anyway, and
//         it keeps the invariant the base class states: ONE sealing
//         decision, ONE write
//
//  Parameters:  HANDLE hFile
//               COM handle supplied by the owning P2PeerCon232
//
//               P2PeerMsg *pMsg
//               Message to be sent
//
//               OVERLAPPEDcon *pOVERLAPPEDsend
//               Pointer to an OVERLAPPEDcon send buffer
//
DWORD
P2PeerioXBee::SendP2PeerMsg ( HANDLE hFile
                            , P2PeerMsg *pMsg
                            , OVERLAPPEDcon *pOVERLAPPEDsend )
{
    // Introduce locals
    const P2Piomage *pSendP2Piomage;
    DWORD            nSendP2PiomageSize;
    DWORD            dwResult;

    // To be sure, to be sure
    ASSERT(!pOVERLAPPEDsend->bQueued);
    if ( pOVERLAPPEDsend->bQueued )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message_T("OVERLAPPEDsend buffer already in use" )
           ->Advice_T ("Internal conflict (Bug)" )
           ->Group("P2P")->Throw();
    pMsg -> PrepareP2Piomage ( GetIFmask() );      // Mandatory

    ASSERT(!pMsg->Map_MatchName(P2Pmsg_3rdParty));
    pSendP2Piomage = pMsg -> P2Piomage ( );

    // Encryption
    // NOTES: Identical in shape and in exemption to P2Peerio::SendP2PeerMsg,
    //        and that duplication is the known cost of overriding this method
    //        at all.  It is accepted here because the ALTERNATIVE - making
    //        P2Peerio::Send virtual and framing underneath it - has a worse
    //        problem on the receive side, where the base state machine asks
    //        for an exact byte count out of a stream this class does not have.
    //        Refer MeshTransports.md
    //      : Key agreement frames are never sealed - they carry the public
    //        halves the session key is derived FROM.  Stated by message TYPE,
    //        not by timing, for the reason given at the base class
    if ( !pMsg->Map_MatchName(P2Pmsg_KeyX)    &&
         !pMsg->Map_MatchName(P2Pmsg_KeyXAck)    )
      pSendP2Piomage = EncryptP2PiomageSwap ( pSendP2Piomage );

    // The sealing decision has now been made, either way
    // NOTES: Minted on BOTH branches, as at the base class.  Send() below
    //        requires it and clears it
    m_bSealDecided = true;

    nSendP2PiomageSize = P2Piomage_Sizeof ( pSendP2Piomage );
    ASSERT(nSendP2PiomageSize);

    // Fragment the SEALED image
    // NOTES: The fragment header rides inside the RF payload, so the payload
    //        available to image bytes is the module's NP less its four bytes
    const UINT nPerFrame = m_nMaxRFPayload - sizeof(P2PxbeeFragHdr);
    const UINT nFrags    = (nSendP2PiomageSize + nPerFrame - 1) / nPerFrame;
    if ( nFrags > 255 )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message("Message of %i bytes needs %i fragments, and the "
                     "fragment header counts to 255"
                    , nSendP2PiomageSize, nFrags )
           ->Advice ("Lower SetMaxSendSize(), or widen P2PxbeeFragHdr")
           ->Group("P2P")->Throw();

    // Size the scratch buffer for ALL frames, once
    const UINT nWorst = nFrags * ( XBeeAPI_FrameOverhead + XBeeAPI_TxOverhead
                                 + m_nMaxRFPayload );
    if ( m_nSendFramesMax < nWorst )
    {
      delete [] m_pSendFrames;
             m_pSendFrames    = new char [nWorst];
             m_nSendFramesMax = nWorst;
    }

    // Build every frame back to back
    const char   *pcImage = (const char *)pSendP2Piomage;
    UINT          nOffset = 0;         // into the image
    UINT          nWrite  = 0;         // into m_pSendFrames
    unsigned char ucSeq   = m_ucSeqSend++;
    for ( unsigned char ucIndex = 0; ucIndex < (unsigned char)nFrags; ucIndex++ )
    {
      // 256 is the largest NP any current firmware reports (DigiMesh); Zigbee
      // is commonly 84.  SetMaxRFPayload() bounds m_nMaxRFPayload to it, so
      // this is a fixed frame rather than a per-message allocation
      char  acPayload [256 + sizeof(P2PxbeeFragHdr)];
      const UINT nThis = min ( nPerFrame, nSendP2PiomageSize - nOffset );

      P2PxbeeFragHdr oHdr;
      oHdr.ucSeq   = ucSeq;
      oHdr.ucIndex = ucIndex;
      oHdr.ucCount = (unsigned char)nFrags;
      oHdr.ucFlags = 0;
      memcpy ( &acPayload[0], &oHdr, sizeof(oHdr) );
      memcpy ( &acPayload[sizeof(oHdr)], &pcImage[nOffset], nThis );

      // Frame ID 0 suppresses the 0x8B TX Status for this frame.  A non-zero
      // ID is what makes delivery observable, and On_APIframe() below already
      // consumes the status frames, so this is the knob that decides whether
      // a dropped fragment is DIAGNOSABLE or merely a reassembly timeout
      nWrite += BuildTxRequest ( &m_pSendFrames[nWrite]
                               , acPayload, sizeof(oHdr) + nThis
                               , ucIndex + 1 );
      nOffset += nThis;
    }
    ASSERT(nOffset==nSendP2PiomageSize);

    // ONE write.  See the note at the head of this function
    if ( Send(hFile,m_pSendFrames,nWrite,pOVERLAPPEDsend) )
    {
      dwResult = GetLastError();
      if ( dwResult != ERROR_IO_PENDING )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message("Send(%i bytes, %i API frames) failed"
                      , nWrite, nFrags )
             ->Group("W32")->HResult( dwResult )->Throw();
    }

    // Tidy up and
    return 0;
}

//
//  Receives next P2PeerMsg from the XBee API frame stream
//  NOTES: Resumable, exactly as P2Peerio::RecvP2PeerMsg is - re-entered
//         on every IOCP completion, accumulating into the OVERLAPPEDcon
//         and returning 0 until a whole message exists.  What differs is
//         the unit: the base class accumulates ONE VBListIOmage directly
//         off the wire, this accumulates ONE API FRAME and hands it to
//         On_APIframe(), which owns the message-level reassembly
//       : Two buffers, same division of labour as the base.  pUserDB1
//         holds the 3-byte frame header (delimiter + 16-bit length);
//         pUserDB2 holds the frame data plus its trailing checksum
//       : The reassembly buffer is a MEMBER, not an OVERLAPPEDcon field,
//         because it outlives any single frame and therefore any single
//         completion
//
P2PeerMsg*
P2PeerioXBee::RecvP2PeerMsg ( HANDLE hFile
                            , OVERLAPPEDcon *pOVERLAPPEDrecv )
{
    DWORD dwResult;

    // Stage 0 - Initialisation
    if ( pOVERLAPPEDrecv->pUserDB1 == 0 )
    {
      pOVERLAPPEDrecv -> pUserDB1   = new char [4];
      pOVERLAPPEDrecv -> dwBytesMax = 3;         // delimiter + length
      pOVERLAPPEDrecv -> dwBytes    = 0;
      if ( pOVERLAPPEDrecv->pBuffer == pOVERLAPPEDrecv->pUserDB2 )
        pOVERLAPPEDrecv -> pBuffer = 0;
      delete [] pOVERLAPPEDrecv -> pUserDB2;
             pOVERLAPPEDrecv -> pUserDB2 = 0;
      delete [] pOVERLAPPEDrecv -> pBuffer;
             pOVERLAPPEDrecv -> pBuffer  = 0;
    }

    // Stage 1 - Fetch the 3-byte API frame header
STAGE1:
    if ( pOVERLAPPEDrecv->dwBytes < 3 )
    {
      char *pBuffer      = pOVERLAPPEDrecv -> pUserDB1;
      DWORD dwBytes      = pOVERLAPPEDrecv -> dwBytes;
      DWORD dwBytes2Recv = 3 - dwBytes;
      dwResult = Recv ( hFile, &pBuffer[dwBytes], dwBytes2Recv
                      , pOVERLAPPEDrecv );
      if ( dwResult && dwResult != ERROR_IO_PENDING )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message("Recv(%i bytes) failed", dwBytes2Recv )
             ->HResult( dwResult )->Throw();
      return nullptr;
    }

    // Stage 2 - Size the frame from its header
    // NOTES: Re-synchronisation on anything that is not a delimiter, by the
    //        same one-byte slide the base class uses - and with the same
    //        memmove rather than memcpy, because the regions OVERLAP.  A
    //        memcpy here tolerates the overlap on MSVC's CRT and corrupts the
    //        buffer under glibc's vectorised implementation, which is the
    //        defect recorded at P2Peerio.cpp:538
    //      : Re-sync is not a theoretical path on this transport the way it is
    //        on TCP.  A module reset mid-frame, a baud mismatch, or an
    //        ATAP=2 module talking mode 2 escaping at a mode 1 host all land
    //        here, continuously
    const unsigned char *pucHdr = (const unsigned char *)pOVERLAPPEDrecv->pUserDB1;
    if ( pucHdr[0] != XBeeAPI_Delimiter )
    {
      char *pBuffer = pOVERLAPPEDrecv -> pUserDB1;
      memmove ( &pBuffer[0], &pBuffer[1], --pOVERLAPPEDrecv->dwBytes );
      pBuffer[pOVERLAPPEDrecv->dwBytes] = 0;
      goto STAGE1;
    }

    const UINT nFrameData = ( (UINT)pucHdr[1] << 8 ) | (UINT)pucHdr[2];
    if ( nFrameData == 0 || nFrameData > m_dwMaxRecvSize )
      EVERR->Module (__FUNCTION__)->AFPeerio(this)
           ->Message("API frame length %i outside 1..%i"
                    , nFrameData, m_dwMaxRecvSize )
           ->Advice ("Connection discontinued")
           ->Throw();

    if ( pOVERLAPPEDrecv->pUserDB2 == 0 )
    {
      pOVERLAPPEDrecv -> pUserDB2   = new char [nFrameData+1];
      pOVERLAPPEDrecv -> dwBytesMax = nFrameData + 1;   // + checksum
    }

    // Stage 3 - Fetch frame data and checksum
    if ( pOVERLAPPEDrecv->dwBytes < 3 + nFrameData + 1 )
    {
      DWORD dwBytes      = pOVERLAPPEDrecv->dwBytes - 3;
      DWORD dwBytes2Recv = nFrameData + 1 - dwBytes;
      dwResult = Recv ( hFile
                      , &pOVERLAPPEDrecv->pUserDB2[dwBytes], dwBytes2Recv
                      , pOVERLAPPEDrecv );
      if ( dwResult && dwResult != ERROR_IO_PENDING )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message("Recv(%i bytes) failed", dwBytes2Recv )
             ->HResult( dwResult )->Throw();
      return nullptr;
    }

    // Stage 4 - Validate and dispatch one whole frame
    const char         *pcFrame = pOVERLAPPEDrecv->pUserDB2;
    const unsigned char ucSum   = (unsigned char)pcFrame[nFrameData];
    if ( Checksum ( pcFrame, nFrameData ) != ucSum )
    {
      // A bad checksum is ONE corrupt frame, not a corrupt peer.  Drop it and
      // resynchronise - unlike the stream transports, where a bad image means
      // the byte alignment itself is lost and the connection cannot continue
      EVWRN->Module (__FUNCTION__)->AFPeerio(this)
           ->Message("API frame checksum mismatch, frame dropped")
           ->SetLast();
      DropReassembly ( );
      pOVERLAPPEDrecv -> dwBytes = 0;
      delete [] pOVERLAPPEDrecv -> pUserDB2;
             pOVERLAPPEDrecv -> pUserDB2 = 0;
      return nullptr;
    }

    P2Piomage *pIOmage = On_APIframe ( pcFrame, nFrameData );

    // Frame consumed either way - rearm for the next one
    pOVERLAPPEDrecv -> dwBytes    = 0;
    pOVERLAPPEDrecv -> dwBytesMax = 3;
    delete [] pOVERLAPPEDrecv -> pUserDB2;
           pOVERLAPPEDrecv -> pUserDB2 = 0;

    if ( pIOmage == 0 )
      return nullptr;                  // Fragment taken, message incomplete

    // Stage 5 - Decryption, then the image morphs into a P2PeerMsg
    // NOTES: The seal covers the WHOLE image and was applied before
    //        fragmentation, so it is opened here - once, after reassembly -
    //        and never per frame
    //      : DecryptP2PiomageSwap() handles cypher issues internally and
    //        returns 0 on a tag mismatch, i.e. a forged or tampered image
    // NOTES: On_APIframe() already cleared m_pReasm when it handed the buffer
    //        out, so this function owns pIOmage outright and nothing aliases
    //        it.  Getting that wrong the other way - clearing the member down
    //        HERE - leaves it dangling on the tag-mismatch return below, which
    //        is the path taken by exactly the traffic you least want a
    //        use-after-free on
    P2Piomage *pOpened = DecryptP2PiomageSwap ( pIOmage );
    if ( pOpened != pIOmage )
    {
      delete [] (char *)pIOmage;
      if ( pOpened == nullptr )
        return nullptr;                // Forged or tampered, handled at source
    }

    // Ownership of pOpened passes to the P2PeerMsg, as at the base class
    P2PeerMsg *pMsg = new P2PeerMsg ( (VBListIOmage *)pOpened );

    // Tidy up, and
    return pMsg;
}

///////////////////////////////////////////////////////////////////////
//  Framing helpers

//
//  Builds one 0x10 TX Request frame
//  NOTES: API mode 1 - NO ESCAPING, and that is only safe because
//         P2PeerCon232::ConfigureComPort configures the port with NO
//         FLOW CONTROL (P2PeerCon232.cpp:323).  A sealed P2Piomage is
//         uniformly distributed binary, so it contains 0x11 and 0x13 -
//         XON and XOFF - roughly once every 128 bytes.  The day anybody
//         turns software flow control on for this port, every message
//         larger than a few hundred bytes wedges the line, and the fix
//         is not to turn it off again but to implement ATAP=2 escaping
//         here and in the receive path
//
//  Returns:    UINT
//              Bytes written to pBuffer
//
UINT
P2PeerioXBee::BuildTxRequest ( char *pBuffer
                             , const void *pvPayload, UINT nPayloadSize
                             , unsigned char ucFrameID )
{
    const UINT nFrameData = XBeeAPI_TxOverhead + nPayloadSize;
    UINT       n          = 0;

    pBuffer[n++] = (char)XBeeAPI_Delimiter;
    pBuffer[n++] = (char)((nFrameData >> 8) & 0xFF);
    pBuffer[n++] = (char)( nFrameData       & 0xFF);

    const UINT nDataAt = n;            // Checksum covers from here
    pBuffer[n++] = (char)XBeeAPI_TxRequest;
    pBuffer[n++] = (char)ucFrameID;
    for ( int i = 7; i >= 0; i-- )     // dest64, big endian on the wire
      pBuffer[n++] = (char)((m_u64RemoteAddr >> (i*8)) & 0xFF);
    pBuffer[n++] = (char)0xFF;         // dest16 - 0xFFFE means "use the 64-bit
    pBuffer[n++] = (char)0xFE;         //   address", the module resolves it
    pBuffer[n++] = (char)0x00;         // Broadcast radius, 0 = maximum hops
    pBuffer[n++] = (char)0x00;         // Options

    memcpy ( &pBuffer[n], pvPayload, nPayloadSize );
    n += nPayloadSize;

    pBuffer[n++] = (char)Checksum ( &pBuffer[nDataAt], nFrameData );
    return n;
}

//
//  0xFF minus the 8-bit sum of the frame data bytes
//
unsigned char
P2PeerioXBee::Checksum ( const char *pcFrameData, UINT nSize ) const
{
    unsigned char ucSum = 0;
    for ( UINT i = 0; i < nSize; i++ )
      ucSum = (unsigned char)( ucSum + (unsigned char)pcFrameData[i] );
    return (unsigned char)( 0xFF - ucSum );
}

//
//  Accepts one validated inbound API frame
//  NOTES: DISPATCH BY FRAME TYPE IS NOT OPTIONAL.  The module interleaves
//         0x8B TX Status and 0x8A Modem Status frames with 0x90 data
//         frames on the same serial line, unprompted.  Treating every
//         frame as data feeds a delivery receipt into the reassembly
//         buffer, and the resulting image fails its checks a long way
//         from here
//       : Reassembly is ONE MESSAGE DEEP on purpose.  Two peers cannot
//         interleave, because one instance addresses one node; a NEW
//         sequence arriving mid-message therefore means the previous
//         message lost a fragment, and the correct response is to
//         abandon it rather than to hold both
//
//  Returns:    P2Piomage*
//              Reassembled image, caller owns.  0 when this frame did
//              not complete a message
//
P2Piomage*
P2PeerioXBee::On_APIframe ( const char *pcFrameData, UINT nSize )
{
    const unsigned char ucType = (unsigned char)pcFrameData[0];

    switch ( ucType )
    {
      case XBeeAPI_TxStatus:
        // Delivery result for a frame ID we issued.  Byte 5 is the delivery
        // status, 0 = success.  Anything else is a fragment that did NOT
        // arrive, which is worth a warning here because the alternative
        // presentation is a silent reassembly timeout with no cause attached
        if ( nSize >= 6 && pcFrameData[5] != 0 )
          EVWRN->Module (__FUNCTION__)->AFPeerio(this)
               ->Message("XBee delivery failed for frame ID %i, status 0x%02X"
                        , (UINT)(unsigned char)pcFrameData[1]
                        , (UINT)(unsigned char)pcFrameData[5] )
               ->Advice ("Fragment lost, message will be abandoned on timeout")
               ->SetLast();
        return 0;

      case XBeeAPI_ModemStatus:
      case XBeeAPI_ATResponse:
        return 0;                      // Not data, and not this class's business

      case XBeeAPI_RxPacket:
        break;                         // Fall through to reassembly

      default:
        return 0;
    }

    // 0x90 RX Packet - the RF payload follows the fixed overhead
    if ( nSize <= XBeeAPI_RxOverhead + sizeof(P2PxbeeFragHdr) )
      return 0;                        // Runt, nothing to take

    const P2PxbeeFragHdr *pHdr = (const P2PxbeeFragHdr *)
                                 &pcFrameData[XBeeAPI_RxOverhead];
    const char           *pcBody = &pcFrameData[XBeeAPI_RxOverhead
                                              + sizeof(P2PxbeeFragHdr)];
    const UINT            nBody  = nSize - XBeeAPI_RxOverhead
                                         - sizeof(P2PxbeeFragHdr);

    if ( pHdr->ucCount == 0 || pHdr->ucIndex >= pHdr->ucCount )
      return 0;                        // Malformed header, drop the frame

    // A new sequence abandons whatever was in flight
    if ( m_pReasm == 0 || pHdr->ucSeq != m_ucSeqRecv )
    {
      DropReassembly ( );
      // Worst case allocation: every fragment full.  The image's own size
      // field is not readable until fragment 0 lands, and fragment 0 is not
      // necessarily the first to arrive - which is the whole reason the
      // fragment header exists
      m_nReasmMax   = pHdr->ucCount * ( m_nMaxRFPayload
                                      - (UINT)sizeof(P2PxbeeFragHdr) );
      if ( m_nReasmMax > m_dwMaxRecvSize )
        EVERR->Module (__FUNCTION__)->AFPeerio(this)
             ->Message("Reassembly of %i fragments exceeds maximum (%i)"
                      , (UINT)pHdr->ucCount, m_dwMaxRecvSize )
             ->Advice ("Connection discontinued")
             ->Throw();
      m_pReasm      = new char [m_nReasmMax];
      m_nReasmSize  = 0;
      m_ucSeqRecv   = pHdr->ucSeq;
      m_ucFragSeen  = 0;
      m_ucFragCount = pHdr->ucCount;
      m_nPITimerReasm = SetPITimer ( 5000 );   // Abandon on silence
    }

    const UINT nAt = pHdr->ucIndex * ( m_nMaxRFPayload
                                     - (UINT)sizeof(P2PxbeeFragHdr) );
    if ( nAt + nBody > m_nReasmMax )
      return 0;                        // Would overrun, drop the frame

    memcpy ( &m_pReasm[nAt], pcBody, nBody );
    if ( nAt + nBody > m_nReasmSize )
      m_nReasmSize = nAt + nBody;      // Fragments may arrive out of order
    m_ucFragSeen++;

    if ( m_ucFragSeen < m_ucFragCount )
      return 0;                        // Still incomplete

    // Ownership leaves this object WITH the buffer
    // NOTES: m_pReasm is cleared here rather than by the caller, so the member
    //        can never alias a buffer that has been freed or handed to a
    //        P2PeerMsg.  DropReassembly() then only has the timer and the
    //        counters left to deal with
    char *pDone = m_pReasm;
           m_pReasm = 0;
    DropReassembly ( );
    return (P2Piomage *)pDone;
}
