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
//  Description: P2PeerioBSTR base class implementation
//               NOTES: Implements P2PeerHub connections
//

#include "stdafx.h"
#include "P2PeerioBSTR.h"
#include "P2PeerCon.h"

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

P2PeerioBSTR::P2PeerioBSTR ( )
{
    // Firstly
    RenderThisSafe();

    // Say out loud what this class takes out of the path
    // NOTES: F-S6-3 asked for this class to be deleted or
    //        for its omission to be made LOUD, and this is the loud half.
    //        SendP2PeerMsg/RecvP2PeerMsg below are overridden and consult
    //        neither cypher hook, so a transport wired to this class carries
    //        cleartext - see the header for why that is not P2PeerioDmx's
    //        defensible position
    //      : Costless, because nothing in this tree constructs one.  That is
    //        precisely the danger: a class with no callers has nobody to
    //        notice what it does, and the first caller would have been the
    //        one who paid.  If this ever appears in a log, the connection it
    //        appears on is the connection to look at
    //      : A warning and not a throw.  Constructing the object is not the
    //        defect - USING it on a hub that requires authentication is, and
    //        P2PeerCon::KeyXDerive refuses exactly that.  Refusing here would
    //        also refuse the BSTR translation on a hub with RequireAuth(false),
    //        which is the operator's own decision to make
    EVWRN->Module (__FUNCTION__)
         ->Message_T("P2PeerioBSTR does not encrypt: it overrides both "
                     "message methods and consults neither cypher hook" )
         ->Advice_T ("Any transport wired to this class carries cleartext" )
         ->Advice_T ("A hub that requires authentication refuses to key it" )
         ->Group("P2P")->Display()->SetLast();
}

P2PeerioBSTR::~P2PeerioBSTR ( )
{ }

void
P2PeerioBSTR::RenderThisSafe()
{ }

P2Peerio*
P2PeerioBSTR::Clone ( )
{   return new P2PeerioBSTR ( ); }

///////////////////////////////////////////////////////////////////////
//  IO
//  NOTES: Completion Port transmission and receipt
//       : BSTR protocol implementation
//

//
//  Sends P2PeerMsg
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
P2PeerioBSTR::SendP2PeerMsg ( HANDLE hFile
                            , P2PeerMsg *pMsg
                            , OVERLAPPEDcon *pOVERLAPPEDsend )
{
    // Introduce locals
    const void   *pvSendMsg;
    DWORD          nSendMsgSize;
    DWORD         dwResult;

    // To be sure, to be sure
    // NOTES: Confirm buffer not already in use
    ASSERT(!pOVERLAPPEDsend->bQueued);
    if ( pOVERLAPPEDsend->bQueued )
      EVERR->Module ("%s(%s-%s)", __FUNCTION__
                    , (P2PaddrSTR)m_pCon->GetP2PaddrHub()
                    , (P2PaddrSTR)m_pCon->GetP2Paddress() )
           ->Message("OVERLAPPEDsend buffer already in use" )
           ->Advice ("Internal conflict (Bug)" )
           ->Group("P2P")->Throw();
    //pMsg -> Defragment ( );

    // Prepare BSTR type message exchanges
    // NOTES: Whole message size in bytes prefixes the data.  P2PeerMsg
    //        header is ommitted.
    //      : The prefix is written THROUGH a P2Psize_t, so its width is
    //        sizeof(P2Psize_t) - the same constant budgeted here and the same
    //        one RecvP2PeerMsg reads back.  It used to memcpy the DWORD
    //        nSendMsgSize directly, four bytes into a slot budgeted at
    //        sizeof(P2Psize_t): while P2Psize_t was 16-bit that overwrote the
    //        first two payload bytes AND undersent the frame by two, so sender
    //        and receiver disagreed about where the data began.  Widening
    //        P2Psize_t to 32-bit makes the two widths coincide; going through
    //        the typedef is what keeps them from drifting apart again
    nSendMsgSize = sizeof(P2Psize_t) + pMsg->DataSize();
    if ( nSendMsgSize > pOVERLAPPEDsend->dwBytesMax )
    {
      delete [] pOVERLAPPEDsend->pBuffer;
                pOVERLAPPEDsend->pBuffer    = new char [nSendMsgSize];
                pOVERLAPPEDsend->dwBytesMax = nSendMsgSize;
    }
    pvSendMsg = pOVERLAPPEDsend->pBuffer;
                pOVERLAPPEDsend->dwBytes    = nSendMsgSize;
    P2Psize_t   nPrefix = (P2Psize_t)nSendMsgSize;
    memcpy ( pOVERLAPPEDsend->pBuffer
           , &nPrefix, sizeof(nPrefix) );
    memcpy (&pOVERLAPPEDsend->pBuffer[sizeof(nPrefix)]
           ,  pMsg->Data(), pMsg->DataSize() );

    // Send message
    if ( Send(hFile,pvSendMsg,nSendMsgSize,pOVERLAPPEDsend) )
    {
      dwResult = GetLastError();
      if ( dwResult != ERROR_IO_PENDING )
        EVERR->Module ("%s(%s-%s)", __FUNCTION__
                      , (P2PaddrSTR)m_pCon->GetP2PaddrHub()
                      , (P2PaddrSTR)m_pCon->GetP2Paddress() )
             ->Message("Send(%i bytes) failed\n"
                      , nSendMsgSize )
             ->HResult( dwResult )->Throw();
    }

    // Tidy up and
    return 0;
}

//
//  Receives next P2PeerMsg
//  NOTES: Handles receipt of following message types P2PeerMsg
//         images, including headers BSTR images, headers manufactured
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
P2PeerMsg*
P2PeerioBSTR::RecvP2PeerMsg ( HANDLE hFile
                            , OVERLAPPEDcon *pOVERLAPPEDrecv )
{
    // Introduce locals
    DWORD     dwResult;
    DWORD     dwBytes    = pOVERLAPPEDrecv->dwBytes;
    DWORD     dwBytesMax = pOVERLAPPEDrecv->dwBytesMax;
    char      *pBuffer   = pOVERLAPPEDrecv->pBuffer;
    P2Psize_t *pMsgSize  = (P2Psize_t *)pOVERLAPPEDrecv->pBuffer;
    const int   S        = sizeof(P2Psize_t);

    // Stage 1 - Fetch message size
    if ( dwBytes < sizeof(P2Psize_t) )
    {
      // NOTES: There is no receive timeout, and this line and its partner
      //        at stage 3 could not have supplied one.  m_iRecvTimeout is
      //        a P2PeerCon member, not this class's, and NOTHING in the
      //        tree reads it - arming a deadline here would be observed by
      //        nobody.  A timeout needs its reader built first: somewhere
      //        that checks the deadline, and a policy for what to do when
      //        it passes
      dwResult = Recv ( hFile
                      ,&pBuffer[dwBytes]
                      , S-dwBytes, pOVERLAPPEDrecv );
      if ( dwResult )
      {
        if ( dwResult != ERROR_IO_PENDING )
          EVERR->Module ("%s(%s-%s)", __FUNCTION__
                        , (P2PaddrSTR)m_pCon->GetP2PaddrHub()
                        , (P2PaddrSTR)m_pCon->GetP2Paddress() )
               ->Message("Recv(%i bytes) failed"
                        , S-dwBytes )
               ->HResult( dwResult )->Throw();
      }
    }

    // Stage 2 - Fetch message data
    if ( dwBytes >=   S       &&
         dwBytes <  *pMsgSize    )
    {
      // To be sure, to be sure
      if ( *pMsgSize > pOVERLAPPEDrecv->dwBytesMax )
        EVERR->Module ("%s(%s-%s)", __FUNCTION__
                      , (P2PaddrSTR)m_pCon->GetP2PaddrHub()
                      , (P2PaddrSTR)m_pCon->GetP2Paddress() )
             ->Message("Recv(%i vs %i) bytes failed\n"
                       "Attempted buffer overrun"
                      , *pMsgSize, dwBytesMax )
             ->Group("P2P")->Throw();

      dwResult = Recv ( hFile
                      ,&pOVERLAPPEDrecv->pBuffer[dwBytes]
                      ,*pMsgSize-dwBytes, pOVERLAPPEDrecv );
      if ( dwResult )
      {
        if ( dwResult != ERROR_IO_PENDING )
          EVERR->Module ("%s(%s-%s)", __FUNCTION__
                        , (P2PaddrSTR)m_pCon->GetP2PaddrHub()
                        , (P2PaddrSTR)m_pCon->GetP2Paddress() )
               ->Message("Overlapped Recv(%i bytes) failed\n"
                        ,*pMsgSize-dwBytes )
               ->HResult( dwResult )->Throw();
      }
    }

    // Stage 3 - Construct P2PeerMsg
    if ( dwBytes >    S       &&
         dwBytes >= *pMsgSize     )
    {
      ASSERT(dwBytes==*pMsgSize);
      P2PeerMsg *pMsg;
      pMsg = new P2PeerMsg ( m_pCon->GetP2Paddress()
                           , m_pCon->GetP2PaddrHub()
                           , P2Pmsg_3rdParty
                           , (void *)&pBuffer[S], *pMsgSize-S );

      // Buffer management
      // NOTES: TCP is a byte stream, so one read can deliver this frame PLUS
      //        the front of the next one.  This slides those leftovers down to
      //        the start of the buffer so the next call begins clean
      //      : The leftover count is RECEIVED minus CONSUMED.  It read
      //        *pMsgSize-dwBytes - the operands the wrong way round.  This
      //        branch runs only when dwBytes > *pMsgSize, so the correct answer
      //        is small and positive and that one is negative; both operands
      //        being unsigned 32-bit, it wrapped to ~4.29e9 and handed THAT to
      //        memcpy as a length.  A copy of a dozen bytes inside a <=32 KB
      //        buffer became a 4 GB wild write off the end of the heap block
      //      : memmove, not memcpy: source and destination are the same buffer
      //        and overlap by construction.  Overlapping memcpy is UB, and this
      //        codebase has already paid for it once - see the re-sync slide in
      //        P2Peerio::RecvP2PeerMsg, where glibc's vectorised memcpy
      //        corrupted the recv image that MSVC's CRT had tolerated
      //      : dwBytes -= *pMsgSize, not -= dwBytes.  Zeroing the counter
      //        declared the leftovers non-existent the instant after they were
      //        preserved, which made the copy above pointless even when its
      //        length was right
      //      : Latent rather than live on both counts - nothing in the tree
      //        constructs a P2PeerioBSTR, and Stages 1 and 2 each ask Recv for
      //        exactly the bytes still missing, so a Recv that honours its
      //        length never overshoots and the branch never runs (which is what
      //        the ASSERT above expects).  Fixed because neither guarantee is
      //        one a receive path should be resting on
      //      : The ASSERT stays.  It is the dev tripwire for an overshoot that
      //        should be impossible; this block is what keeps a Release build
      //        correct rather than catastrophic if one ever happens
      if ( *pMsgSize < dwBytes )
        memmove ( pOVERLAPPEDrecv->pBuffer
                ,&pOVERLAPPEDrecv->pBuffer[*pMsgSize]
                , dwBytes - *pMsgSize );
      pOVERLAPPEDrecv -> dwBytes -= *pMsgSize;

      // Tidy up, and
      return pMsg;
    }

    // Tidy up and
    return (P2PeerMsg *)0;
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerioBSTR::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}
