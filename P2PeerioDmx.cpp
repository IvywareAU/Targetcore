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
//  Description: P2PeerioDmx base class implementation
//  NOTES: Performs in-process P2PeerMsg image exchanges with direct
//         use of the IO Completion Port
//

#include "stdafx.h"
#include "Kernel32_Ext.h"
#include "P2PeerioDmx.h"
#include "P2PeerConDmx.h"

extern
CRITICAL_SECTION  g_oCSectP2PeerConDmx;

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

P2PeerioDmx::P2PeerioDmx ( )
{
    // Firstly
    RenderThisSafe();
}

P2PeerioDmx::~P2PeerioDmx ( )
{  }

void
P2PeerioDmx::RenderThisSafe()
{
    // Attributes
    m_pOVERLAPPEDrecv = 0;
    m_pOVERLAPPEDsend = 0;
}

P2Peerio*
P2PeerioDmx::Clone ( )
{   return new P2PeerioDmx ( ); }

///////////////////////////////////////////////////////////////////////
//  IO
//  NOTES: Completion Port transmission and receipt
//       : BSTR protocol implementation
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
P2PeerioDmx::SendP2PeerMsg ( HANDLE hFile
                           , P2PeerMsg *pMsg
                           , OVERLAPPEDcon *pOVERLAPPEDsend )
{
    // Isolation
    P2PsafeCS    oSafeCS = g_oCSectP2PeerConDmx;
    P2PeerioDmx *pThis   =                 this;
    P2PeerioDmx *pThat   = (P2PeerioDmx *)hFile;

    // To be sure, to be sure
    // NOTES: Confirm nothing is already loaded
    if ( pThis->m_pOVERLAPPEDsend )
      EVERR->MODULE
           ->Message("Previous SendP2PeerMsg outstanding\n"
                     "ADVICE\t: Bug(SNHappen)" )
           ->Throw();

    // To be sure, to be sure
    // NOTES: Confirm interface is operational.  Specialisation is
    //        thread safe mechanism to monitor other side.  Must be
    //        protected by above critical section
    //  A SEND TO A DEPARTED PEER MUST FAIL, and until 2026-09-21 it
    //  reported success.  GetUDState() is m_pConThat on this transport
    //  (P2PeerConDmx.cpp:961-963), so zero means the peer is gone.  The
    //  abort was written into hr and then erased by PostOVERLAPPED, which
    //  calls prepareOVERLAPPED, which assigns S_OK - so the completion
    //  arrived as a SUCCESS and the send branch treats a success as
    //  DELIVERED: it deletes the message (P2PeerCon.cpp:695).  A message
    //  handed to a peer that no longer exists was therefore destroyed and
    //  reported sent.  Passing the status routes it to the send failure
    //  branch instead (:764-770), which drops the connection.
    if ( m_pCon->GetUDState() == 0 )
    {
      m_pCon -> PostOVERLAPPED ( pOVERLAPPEDsend, ERROR_OPERATION_ABORTED );
      return 0;
    }

    // Setup send
    // NOTES: Receiver does the copy.  The buffer effectively sits idle
    //        locally until the receiver becomes available.
    if ( pMsg )
    {
      pMsg -> PrepareP2Piomage  ( GetIFmask() );      // Mandatory
      P2Piomage *pP2Piomage = pMsg->P2Piomage();
                 pOVERLAPPEDsend -> pBuffer = (char *)pP2Piomage;
                 pOVERLAPPEDsend -> dwBytes = P2Piomage_Sizeof(pP2Piomage);
                 pOVERLAPPEDsend -> dwBytesMax = 0;
      //pThis -> m_pCon -> prepareOVERLAPPED ( pOVERLAPPEDsend );
      pThis -> m_pOVERLAPPEDsend = pOVERLAPPEDsend;
      SetLastError ( ERROR_IO_PENDING );
    }

    // Notification
    // NOTES: Handle that P2PeerCon waiting for buffer to be received
    OVERLAPPEDcon *pOVERLAPPEDrecv = pThat -> m_pOVERLAPPEDrecv;
    if (  pOVERLAPPEDrecv          &&
         !pOVERLAPPEDrecv->bQueued    )
    {
      // Notification
      // NOTES: That side suspended for send completion
      //pThat -> m_pCon -> releaseOVERLAPPED ( pOVERLAPPEDrecv );
      pThat -> m_pOVERLAPPEDrecv = 0;
      pThat -> m_pCon -> PostOVERLAPPED ( pOVERLAPPEDrecv );
    }

    // Tidy up and
    return 0;
}

//
//  Receives next P2PeerMsg
//  NOTES: Handles receipt of following message types P2PeerMsg images,
//         including headers BSTR images, headers manufactured
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
P2PeerioDmx::RecvP2PeerMsg ( HANDLE hFile
                           , OVERLAPPEDcon *pOVERLAPPEDrecv )
{
    // Isolation
    // NOTES: This is mandatory whilst we work across the address space
    //        of multiple threads
    P2PsafeCS    oSafeCS = g_oCSectP2PeerConDmx;
    P2PeerioDmx *pThis   =                 this;
    P2PeerioDmx *pThat   = (P2PeerioDmx *)hFile;
    P2PeerMsg   *pMsg    = 0;

    // To be sure, to be sure
    if ( pThis->m_pOVERLAPPEDrecv                    &&
         pThis->m_pOVERLAPPEDrecv != pOVERLAPPEDrecv    )  //TODO:LJM added to qualify previous line 27/12/2010
      EVERR->MODULE
           ->Message("Previous RecvP2PeerMsg outstanding" )
           ->Advice ("Bug(SNHappen)" )
           ->Throw();

    // To be sure, to be sure
    // NOTES: Confirm interface is operational.  Specialisation is
    //        thread safe mechanism to monitor other side.  Must be
    //        protected by above critical section
    //  THIS STILL POSTS A SUCCESS, AND THAT IS DELIBERATE - it is the recv
    //  half of the defect the send path above had, left in place on a
    //  measurement rather than on an oversight.
    //      : The defect is identical.  hr is assigned BEFORE PostOVERLAPPED,
    //        which calls prepareOVERLAPPED, which assigns hr = S_OK
    //        (P2PeerCon.cpp:1203) - so the abort is erased by the post it is
    //        written for, and a read armed against a departed peer completes
    //        as a SUCCESS carrying zero bytes.  On this transport that is
    //        indistinguishable from an arming post (P2PeerCon.cpp:502-512),
    //        so the connection re-arms instead of closing.
    //      : The fix is one line - PostOVERLAPPED ( p, ERROR_OPERATION_ABORTED )
    //        the way SendP2PeerMsg above now does it - AND IT BREAKS TEARDOWN.
    //        Measured 2026-09-21: with this half fixed as well, p2pweb_w6
    //        SEGFAULTs after its last assertion.  p2pweb wires its hub chain
    //        with P2PeerConDmx (WebChainBuilder.cpp:477), a recv is re-armed
    //        constantly while a chain comes down, and turning a silent re-arm
    //        into a connection drop reorders the whole shutdown.  One failure
    //        in the first run with both halves fixed; five clean runs with the
    //        send half alone.
    //      : So it goes with the teardown work, not with the send fix.
    //        OpenCodeWork.md item 7.  p2p_dmxdead gates the send half only and
    //        its header says so.
    if ( m_pCon->GetUDState() == 0 )
    {
      pOVERLAPPEDrecv -> hr = ERROR_OPERATION_ABORTED;
      m_pCon -> PostOVERLAPPED ( pOVERLAPPEDrecv );
      return 0;
    }

    // Data exists
    // NOTES: Handle that P2PeerCon waiting for buffer to be received
    OVERLAPPEDcon *pOVERLAPPEDsend = pThat -> m_pOVERLAPPEDsend;
                                     pThis -> m_pOVERLAPPEDrecv = 0;
    if ( pOVERLAPPEDsend          /*&&
         pOVERLAPPEDsend->bQueued*/    )
    {
      // To be sure, to be sure
      DWORD_PTR dwBytes = pOVERLAPPEDsend -> dwBytes;
      if ( dwBytes )
      {
        pThat -> m_pOVERLAPPEDsend = 0;
        VBListIOmage *pIOmage = (VBListIOmage *)pOVERLAPPEDsend -> pBuffer;
                                                pOVERLAPPEDsend -> pBuffer = 0;
                                                pOVERLAPPEDsend -> dwBytes = 0;
        if ( pIOmage->oSync.uiSync1+pIOmage->oSync.uiSync2 != ~0 )
          EVERR->MODULE
              ->Message("Corrupted VBListIOmage header (%x + %x) compliment"
                        , pIOmage->oSync.uiSync1, pIOmage->oSync.uiSync2 )
              ->Advice ("Bug(SNHappen)" )
              ->Throw();
        // NOTES: uiSync1&0x00FFFFFF is the TOTAL image size INCLUDING oSync
        //        (see MsgVBHeap.cpp uiSync1 "Total size of this structure"
        //        and P2Piomage_Sizeof() which returns exactly that field).
        //        The sender set dwBytes = P2Piomage_Sizeof(), so the declared
        //        size must simply fit within the received bytes. The old
        //        "+ sizeof(oSync)" double-counted the header, making this
        //        guard ALWAYS fire (X + 8 > X) so no Dmx message ever passed.
        if ( (pIOmage->oSync.uiSync1&0x00FFFFFF) > dwBytes )
          EVERR->MODULE
              ->Message("Corrupted VBListIOmage byte (%x vs %x) byte count"
                        , pIOmage->oSync.uiSync1, dwBytes )
              ->Advice ("Bug(SNHappen)" )
              ->Throw();

        // P2PeerMsg receipt
        // NOTES: Image copy only, mandatory sender retains ownership for
        //        re-use etc
        pMsg = new P2PeerMsg ( *pIOmage );
      }

      // Notification
      // NOTES: That side suspended for send completion
      //pThat -> m_pCon -> releaseOVERLAPPED ( pOVERLAPPEDsend );
      pThat -> m_pCon -> PostOVERLAPPED ( pOVERLAPPEDsend );
    }

    // Nothing waiting
    // NOTES: Flag ourselves as being queued and passively wait.  Set
    //        internal to indicate such.
    if ( !pMsg )
    {
      //pThis -> m_pCon -> prepareOVERLAPPED ( pOVERLAPPEDrecv );
      pThis -> m_pOVERLAPPEDrecv = pOVERLAPPEDrecv;
      SetLastError ( ERROR_IO_PENDING );
    }

    // Tidy up and
    return pMsg;
}

//
//  Resets internals
//  NOTES: Intention is for object to be left in a re-usable state
//
void
P2PeerioDmx::Reset ( )
{
    // Delegate
  __super::Reset ( );

    // Attributes
    //if ( m_pOVERLAPPEDsend && m_pCon )
    //  m_pCon -> releaseOVERLAPPED ( m_pOVERLAPPEDsend );
    m_pOVERLAPPEDsend = 0;
    //if ( m_pOVERLAPPEDrecv && m_pCon )
    //  m_pCon -> releaseOVERLAPPED ( m_pOVERLAPPEDrecv );
    m_pOVERLAPPEDrecv = 0;
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerioDmx::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}
