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
{
    // A park holds a reference on the owning connection, and a connection is
    // only ever deleted by its last Release() - so a parked read here means a
    // reference was released that nobody took.  Refer UnparkRecv()
    ASSERT ( !m_pOVERLAPPEDrecv || !m_pOVERLAPPEDrecv->bParked );
}

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
    // NOTES: That side is parked waiting for exactly this.  UnparkRecv() posts
    //        its read as a success - data is waiting - and gives back the
    //        reference the park held.  Silent when the peer is not parked: its
    //        next RecvP2PeerMsg finds m_pOVERLAPPEDsend above and collects
    pThat -> UnparkRecv ( S_OK );

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
    //  A READ AGAINST A DEPARTED PEER MUST FAIL, the recv half of the send
    //  fix above and the same one-line defect: hr was assigned BEFORE
    //  PostOVERLAPPED, which calls prepareOVERLAPPED, which assigns S_OK - so
    //  the abort was erased and the read completed as a success carrying zero
    //  bytes, which on this transport is an arming post, so the connection
    //  re-armed forever instead of closing.
    //      : Fixed on 2026-09-21 this half SEGFAULTed p2pweb_w6 at teardown
    //        and was put back.  The crash was never this line: it was
    //        P2PeerConDmx::Drop() re-posting a recv that was already in the
    //        port (OpenCodeWork.md item 7, finding 3 of 2026-09-22), and a
    //        read that now fails instead of re-arming simply reached that
    //        double post more often.  With the double post gone this is the
    //        line it always should have been
    if ( m_pCon->GetUDState() == 0 )
    {
      m_pCon -> PostOVERLAPPED ( pOVERLAPPEDrecv, ERROR_OPERATION_ABORTED );
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
    // NOTES: PARK the read and passively wait for the peer's send to post it
    //        back (UnparkRecv, called from SendP2PeerMsg on the other side)
    //      : AND HOLD A REFERENCE WHILE IT WAITS.  The completion that
    //        brought us here was releaseOVERLAPPED()d before this function
    //        was called (P2PeerCon.cpp:546), so at this point the connection
    //        is owed nothing and referenced by nothing - and a parked read
    //        is a pending operation in every sense that matters: the read
    //        has been asked for and has not completed.  On a socket the
    //        kernel holds that read and the reference stands with it; here
    //        the io layer holds it, so the io layer takes the reference.
    //        Without it an idle in-process connection was invisible to
    //        Drop(), to PostDestroyState() and to CloseP2PmsgHub(), and its
    //        partner leaving could not be told to it - the accept slot that
    //        never came back, OpenCodeWork.md item 7.  The reference is
    //        given back by UnparkRecv() and nowhere else
    //      : The prepareOVERLAPPED that stood here, commented out, was this
    //        reference.  It could not be that call because PostOVERLAPPED()
    //        refuses a queued object; bParked is the same accounting under a
    //        name that keeps the two states apart for the teardown drain,
    //        which waits for queued completions and must not wait for parked
    //        ones
    if ( !pMsg )
    {
      pThis -> m_pCon -> AddRef ( );
      pOVERLAPPEDrecv -> bParked = true;
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
    // NOTES: Called from P2PeerCon::Drop().  A parked read is handed back to
    //        the port as ABORTED rather than forgotten: it holds a reference,
    //        and forgetting it would leak the connection for good.  Drop()
    //        has already cleared m_hFileCPort, so the completion lands in the
    //        recv branch's cancellation arm (P2PeerCon.cpp:674), which frees
    //        the buffer and releases the port's reference - and the park's
    //        is released here, after the post has taken its own, so this is
    //        never the owner's last.  On the teardown sweep the same
    //        completion is collected by the drain, because the sweep runs
    //        Drop() before it drains
    m_pOVERLAPPEDsend = 0;
    UnparkRecv ( ERROR_OPERATION_ABORTED );
    m_pOVERLAPPEDrecv = 0;
}

//
//  Hands a PARKED read back to the completion port
//  NOTES: Refer the declaration.  The order is the whole function: post
//         first, which takes the port's reference on the owner, and release
//         the park's second, so the owner is never last-released on this
//         thread.  If the post throws - the owner's port has gone, which is
//         only true of a hub already torn down - the park's reference is
//         released regardless, and if that IS the last one then this thread
//         deletes a connection whose hub has already let go of it, which is
//         the correct end for it
//
//
//  Parameters:  HRESULT hrPost
//               Status the completion carries: S_OK when the peer has sent,
//               ERROR_OPERATION_ABORTED when the peer has gone
//
//  Returns:     bool
//               A read was parked and has been posted
//
bool
P2PeerioDmx::UnparkRecv ( HRESULT hrPost )
{
    // Isolation
    P2PsafeCS      oSafeCS = g_oCSectP2PeerConDmx;
    OVERLAPPEDcon *pParked = m_pOVERLAPPEDrecv;
    if ( !pParked          ||
         !pParked->bParked ||
         !m_pCon              )
      return false;

    // Leave the park
    m_pOVERLAPPEDrecv  = 0;
    pParked -> bParked = false;

    // Post, then give back the park's reference
    try
    {
      m_pCon -> PostOVERLAPPED ( pParked, hrPost );
    }
    catch ( ... )
    {
      m_pCon -> Release ( );
      throw;
    }
    m_pCon -> Release ( );
    return true;
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
