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
//  P2PeerMsg implementation
//  NOTES: Container that facilitates the asychronous exchange of
//         messages between P2PeerHub's and subsequent routing through
//         the registered ID_SPIN_LBPeriodsies of derivered P2PeerTarget's
//       : These object's are not designed to be thread or context
//         safe and as such reference MUST be isolated
//

#include "stdafx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"


///////////////////////////////////////////////////////////////////////
//  Construction and destruction

std::atomic<UINT> g_P2PeerMsgInstances = 0;   // atomic ++/-- (TSan Risk #3)

//
//  Constructors and destructor
//
//  Parameters:  P2PeerMsg& rhs
//               Copy constructor reference
//
//               const void *pvMessage
//               Complete message, including P2PeerMsgHdr
//
//               short iMsgSize
//               Message size
P2PeerMsg::P2PeerMsg ( )
        // : P3PmsgBSTR ( VBLock_Addr16, 2048 )
{
    // Firstly
    RenderThisSafe ( );
    Init ( 0, AllocBLOB08(sizeof(P2PeerMsgPrefix)) );
}

P2PeerMsg::P2PeerMsg ( const P2PeerMsg& rhs )
         : P3PmsgBSTR( rhs )
{
    // Firstly
    RenderThisSafe ( );
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    pPrefix->uiState &= ~P2PeerMsgState_Posted;
}

P2PeerMsg::P2PeerMsg ( P2PmsgHANDLE  hVBList )
         : P3PmsgBSTR ( hVBList )
{
    // Firstly
    RenderThisSafe ( );
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    pPrefix->uiState &= ~P2PeerMsgState_Posted;
    ASSERT(0);
}

P2PeerMsg::P2PeerMsg ( UCHAR uVBLockAddr, VBLsize nSizeof )
         : P3PmsgBSTR ( uVBLockAddr, nSizeof )
{
    // Firstly
    RenderThisSafe ( );
    r_data() = AllocBLOB08(sizeof(P2PeerMsgPrefix));
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    pPrefix->uiState &= ~P2PeerMsgState_Posted;
}

/*P2PeerMsg::P2PeerMsg ( const void *pvMsgImage, P2Psize_t iMsgImageSize )
{
    // Firstly
    RenderThisSafe ( );

    //// Allocate memory
    //// NOTES: This is a special case since the whole message is
    ////        being passed.  Not just the data component
    ASSERT(0);

    // Parallel image
    //P2PmsgBSTR *pBSTR  =(P2PmsgBSTR *)pvMsgImage;
    //m_pP2PmsgBSTR_Heap = MakeBSTR ( pBSTR->iSize );
    //memcpy ( m_pP2PmsgBSTR_Heap, pvMsgImage, iMsgImageSize );

    // Propagation
    //Connect ( m_pP2PmsgBSTR_Heap);
    //SetFragmented ( );
}*/

P2PeerMsg::P2PeerMsg ( const VBListIOmage& oIOmage )
         : P3PmsgBSTR( oIOmage )
{
    // Firstly
    //RenderThisSafe ( );
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    pPrefix->uiState &= ~P2PeerMsgState_Posted;
}

P2PeerMsg::P2PeerMsg ( VBListIOmage *pIOmage )
         : P3PmsgBSTR( pIOmage )
{
    // Firstly
    RenderThisSafe ( );
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    pPrefix->uiState &= ~P2PeerMsgState_Posted;
}

P2PeerMsg::P2PeerMsg ( VBListIOmage *pIOmage, VBLsize nBufferLen )
         : P3PmsgBSTR( pIOmage, nBufferLen )
{
    //  The constructor above with the buffer extent supplied, for images that
    //  came off a wire rather than out of this process. Everything else about
    //  it is identical; what the length buys is that the two IOMAGE block walks
    //  run as a GATE -- in every build, refusing rather than asserting -- which
    //  is what the pointer-only form cannot do because it does not know where
    //  the image ends. See P2Peerio::RecvP2PeerMsg stage 4.
    RenderThisSafe ( );
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    pPrefix->uiState &= ~P2PeerMsgState_Posted;
}

P2PeerMsg::P2PeerMsg ( P2PmsgID pszMsgID )
         : P3PmsgBSTR( pszMsgID, AllocBLOB08(sizeof(P2PeerMsgPrefix)) )
{
    // Firstly
    RenderThisSafe();
    //Init ( pszMsgID, AllocBLOB08(sizeof(P2PeerMsgPrefix)) );

    // Addressing
    InitItem ( VBLockBSTR_NET,P3PmsgData() );

    // Data
    InitItem ( VBLockBSTR_MSG,P3PmsgData() );
}

P2PeerMsg::P2PeerMsg ( P2PaddrSTR oSrcSTR, P2PaddrSTR oDstSTR
                     , P2PmsgID pszMsg
                     , const void *pvMsgData, P2Psize_t iMsgDataSize )
         : P3PmsgBSTR( pszMsg, AllocBLOB08(sizeof(P2PeerMsgPrefix)) )
{
    // Firstly
    RenderThisSafe();
    //Init ( pszMsg, AllocBLOB08(sizeof(P2PeerMsgPrefix)) );

    // Addressing
    InitItem(VBLockBSTR_NET,P3PmsgData());
    SetSource ( P3PmsgField ( TMsg_Src, DataWSTR08(oSrcSTR) ) );
    SetDestin ( P3PmsgField ( TMsg_Dst, DataWSTR08(oDstSTR) ) );

    // Data
    // NOTES: Passed data is placed in the data node header
    if ( iMsgDataSize <= 255 )
      InitItem ( VBLockBSTR_MSG
               , P3PmsgData(pvMsgData,iMsgDataSize,VBLockData_BLOB08) );
    else
      InitItem ( VBLockBSTR_MSG
               , P3PmsgData(pvMsgData,iMsgDataSize,VBLockData_BLOB16) );
}

P2PeerMsg::P2PeerMsg ( const P3PmsgField& oSource, const P3PmsgField& oDestin
                     , P2PmsgID pszMsg
                     , const void *pvMsgData, P2Psize_t iMsgDataSize )
         : P3PmsgBSTR( pszMsg, AllocBLOB08(sizeof(P2PeerMsgPrefix)) )
{
    // Firstly
    RenderThisSafe();
    //Init ( pszMsg, AllocBLOB08(sizeof(P2PeerMsgPrefix)) );

    // Addressing
    InitItem(VBLockBSTR_NET,P3PmsgData());
    SetSource ( oSource );
    SetDestin ( oDestin );

    // Data
    // NOTES: Passed data is placed in the data node header
    if ( iMsgDataSize <= 255 )
      InitItem ( VBLockBSTR_MSG
               , P3PmsgData(pvMsgData,iMsgDataSize,VBLockData_BLOB08) );
    else
      InitItem ( VBLockBSTR_MSG
               , P3PmsgData(pvMsgData,iMsgDataSize,VBLockData_BLOB16) );
}

P2PeerMsg::P2PeerMsg ( P2PaddrSTR pSrcSTR, P2PaddrSTR pDstSTR
                     , P2PmsgID pszMsg
                     , LPCTSTR lpszMsgFormat, ... )
         : P3PmsgBSTR( pszMsg, AllocBLOB08(sizeof(P2PeerMsgPrefix)) )
//         : P2PmsgItem ( pszMsg, P2PmsgVT_STR, lpszMsgFormat, 0 )
{
    // Introduce locals
    va_list       ap;                  // Variable argument list.
    TCHAR         szMsgData[2048];
    P2Psize_t      iMsgDataSize = 0;
    va_start ( ap, lpszMsgFormat );
    if ( lpszMsgFormat )
      iMsgDataSize = (P2Psize_t)_vstprintf_s ( szMsgData, ARRAYSIZE(szMsgData), lpszMsgFormat, ap );
    szMsgData[iMsgDataSize++] = 0;
    szMsgData[iMsgDataSize++] = 0;
    va_end   ( ap );

    // Firstly
    RenderThisSafe();
    //Init ( pszMsg, AllocBLOB08(sizeof(P2PeerMsgPrefix)) );

    // Addressing
    P3PmsgItem& oItemAddr = InitItem(VBLockBSTR_NET,P3PmsgData());
    oItemAddr += P3PmsgField ( TMsg_Src, DataWSTR08(pSrcSTR) );
    oItemAddr += P3PmsgField ( TMsg_Dst, DataWSTR08(pDstSTR) );

    // Data
    // NOTES: Passed data is placed in the data  header
    if ( iMsgDataSize <= 255 )
      InitItem ( VBLockBSTR_MSG
               , P3PmsgData(szMsgData,iMsgDataSize,VBLockData_BSTR08) );
    else
      InitItem ( VBLockBSTR_MSG
               , P3PmsgData(szMsgData,iMsgDataSize,VBLockData_BSTR16) );
}

P2PeerMsg::~P2PeerMsg ()
{
    // Garbage collection
    delete m_pP2PmsgWrap;
    delete m_pstrVisualSummary;
    g_P2PeerMsgInstances--;
}

void
P2PeerMsg::RenderThisSafe ( )
{
    // Attributes
    //m_pP2PmsgWrap        =  0;
    //m_pP2PmsgParent      =  0;
    //m_pstrVisualSummary  =  0;
    g_P2PeerMsgInstances++;

    // Dedicated VBList
    ASSERT(sizeof(P2PeerMsgPrefix)<255);
    //r_data() = P3PmsgData ( (void *)0, sizeof(P2PeerMsgPrefix), VBLockData_BLOB08 );    
}

void
P2PeerMsg::ResetThisObject ( )
{
    // Garbage collection
    delete m_pP2PmsgWrap;
           m_pP2PmsgWrap = 0;

    // Delegation
    r_item(0).DESC.Truncate();

    // Attributes
    m_pP2PmsgParent  = 0;
}

///////////////////////////////////////////////////////////////////////
//  Overloaded Operators

//
//  operator = () overload
//
//  Parameters:  const P2PeerMsg& rhs
//               Right hand side of expression.
//
//  Returns:     P2PeerMsg&
//               Reference to self.
//
P2PeerMsg&
P2PeerMsg::operator = ( const P2PeerMsg& rhs )
{
    // Optimise
    if ( this == &rhs )
      return *this;
    ResetThisObject ( );

    // Snapshot and base class delegation
   (P3PmsgBSTR&)*this = rhs;

    // Tidy up and
    //SetFragmented ( );
    return *this;
}

//
//  operator [] overload
//  Recursively exposes wrapped messages
//
//  Parameters:  int e
//               Index of recursively wrapped message to be exposed
//               NOTES: Throws an exception should recursion level
//                      not exist
//
//  Returns:     P2PeerMsg&
//               Wrapped message reference
//
P2PeerMsg&
P2PeerMsg::operator [] ( int e )
{
    // Self reference
    if ( e == 0 )
      return *this;

    // To be sure, to be sure
    if ( e < 0                   ||
         e > MAX_P2PeerMsg_Index    )
      EVERR->MODULE->AFP(e)
           ->Message(_T("Invalid wrapped message index=%i (0 to %i)"), e, MAX_P2PeerMsg_Index )
           ->Group("P2P")->Throw();
    if ( !IsWrapped() )
      EVERR->MODULE->AFP(e)
           ->Message_T("P2PeerMsg not wrapped" )
           ->Advice_T ("Use IsWrapped() as pre-check")
           ->Throw();

    // Unwrapping
    if ( m_pP2PmsgWrap == 0 )
    {
      VBListIOmage *pIOmage = (VBListIOmage *)r_item(VBLockBSTR_WRP).r_data().c_vBlob();
      m_pP2PmsgWrap = new P2PeerMsg ( *pIOmage );
    }

    // Recursively delegate
    return (*m_pP2PmsgWrap)[e-1];
}

///////////////////////////////////////////////////////////////////////
//  Factories
//  NOTES: All methods return pointers to P2PeerMsg objects for which
//         the client becomes responsible for the life cycle

//
//  Constructs a response message from the encapsulated message
//  NOTES: Clones address properties of the contained message then swaps
//         the source and destination addresses.
//
//  Parameters:  P2PmsgID pszMsg
//               Response message type
//
//               const void *pvMsgData
//               Message data
//
//               short iMsgDataSize
//               Message data size.
//
//  Returns:     P2PeerMsg*
//               Response P2PeerMsg pointer.  Client becomes
//               responsible for life cycle.
//
P2PeerMsg*
P2PeerMsg::ResponseFactory ( P2PmsgID pszMsg
                           , const void *pvMsgData, P2Psize_t iMsgDataSize )
{
    // Build the response message
    // NOTES: Perform raw prefix copy
    P2PeerMsgSP spMsg = new P2PeerMsg ( r_Destin(), r_Source()
                                      , pszMsg, pvMsgData, iMsgDataSize );
ASSERT(!P2PeerMsg_IsPosted(spMsg.p_SafePtr()));

    // Data
    spMsg -> r_data() = r_data();
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)spMsg->r_data().c_vBlob();
    pPrefix->uiState &= ~P2PeerMsgState_Posted;
ASSERT(!P2PeerMsg_IsPosted(spMsg.p_SafePtr()));

    // Tidy up, and
    return spMsg.Dereference();
}

//
//  Builds a redirection message from this message.
//
//
//  Parameters:  P2PaddrSTR strP2Paddr
//               Redirected P2PeerMsg destination address
//
//
//  Returns:     P2PeerMsg*
//               Pointer to redirection message
//               NOTES: Client becomes responsible for life cycle
//
P2PeerMsg*
P2PeerMsg::RedirectFactory ( P2PaddrSTR strDestin )
{
    // Create an image and assign redirection address.
    // NOTES: DESTINATION ONLY.  TMsg_Scp - what the origin addressed this to -
    //        is inherited by the image untouched, and MUST be: overwriting it
    //        here is precisely the defect this field exists to undo, because
    //        every caller of this function is re-addressing a copy the origin
    //        never saw.  Refer TMsg_Scp in the header
    P2PeerMsg *pMsg = new P2PeerMsg ( *this );
               pMsg -> SetDestin ( strDestin );
//LPCTSTR lpszSource=pMsg->GetSource();
//LPCTSTR lpszDestin=pMsg->GetDestin();
//LPCTSTR lpszMsg=pMsg->c_name();

    // Then
ASSERT(pMsg->Map_MatchName(c_name()));//DELETE-ME
ASSERT(!IsWrapped()||(*this)[1].Map_MatchName((*pMsg)[1].c_name()));

    return pMsg;
}

P2PeerMsg*
P2PeerMsg::RedirectFactory ( P2PaddrSTR strP2PaddrDst
                           , P2PmsgID pszMsg
                           , const void *pvMsgData, P2Psize_t iMsgDataSize )
{
    // Simply
ASSERT(wcslen(pszMsg)>0);//DELETE-ME
    return new P2PeerMsg ( GetSource(), strP2PaddrDst
                         , pszMsg
                         , pvMsgData, iMsgDataSize );
}

//
//  Builds a wrapped response message from the encapsulated message.
//
//
//  Parameters:  P2Pmsg_t nMsg
//               Type of wrapped response
//
//               void *pvMsgData
//               Data pointer,  Null value handled.
//
//               short iDataSize
//               Size of data area in wrapped message.  Size
//               of wrapped message is exclusive to this value.
//
//
//  Returns:     P2PeerMsg*
//               Pointer to wrapped response message
//
P2PeerMsg*
P2PeerMsg::WrappedResponseFactory ( P2PmsgID pszMsg
                                  , const void *pvMsgData, P2Psize_t iDataSize )
{
    // Build a wrapped message
    // NOTES: Add an extra bit on for the size of this message
    //      : Message source and destinations are reversed.
    //      : COPIES, not the pointers the accessors return.  GetDestin(),
    //        GetSource() and c_name() all end in c_wstr()/c_name(), which off
    //        Windows hands back one of 16 ROTATING thread-local scratch buffers
    //        - valid only until the next accessor call on this thread.  The
    //        constructor below consumes its arguments one at a time and makes
    //        several such calls between them, so by the time the second was
    //        read its slot had been recycled: measured on Linux, the response
    //        to an undeliverable message was addressed to "Src" - the field
    //        NAME - instead of to the sender.  It was therefore undeliverable
    //        itself and was dropped, so on that platform an undeliverable
    //        message was NEVER reported back to whoever sent it.  Invisible on
    //        Windows, where the accessor aims straight at the stored characters
    //      : Same defect and same fix as P2PeerHub::RouteP2PeerMsg, which
    //        records the sizes it grew to at P2PeerHub.cpp:715-725.  A test
    //        that asserts the report ARRIVES is what finally reached this one
//Print(stdout);
    const CString strDestin = GetDestin ( );
    const CString strSource = GetSource ( );
    P2PeerMsgSP spMsg = new P2PeerMsg ( (P2PaddrSTR)strDestin, (P2PaddrSTR)strSource
                                      , pszMsg, pvMsgData, iDataSize );
    //if ( GetP2Pmsgnn() == VBLock_Addr16 )
    //  spMsg = new P2PeerMsg16 ( GetDestin(), GetSource(), pszMsg, pvMsgData, iDataSize );
    //if ( GetP2Pmsgnn() == VBLock_Addr32 )
    //  spMsg = new P2PeerMsg32 ( GetDestin(), GetSource(), pszMsg, pvMsgData, iDataSize );
    //else
    //  spMsg = new P2PeerMsg64 ( GetDestin(), GetSource(), pszMsg, pvMsgData, iDataSize );

    spMsg -> r_data() = r_data();
    P2PeerMsgPrefix *pPrefix0 = (P2PeerMsgPrefix *)(spMsg->r_data().c_vBlob());
                     pPrefix0 -> uiState &= ~P2PeerMsgState_Posted;
    //spMsg -> InitItem ( VBLockBSTR_WRP, P3PmsgData() );
    //spMsg -> r_item   ( VBLockBSTR_WRP) += r_item ( 0 );

    // Copy in details of the wrapped message
    // TODO:LJM This can be optimised
    // NOTES: BOUNDED.  The response embeds the whole of this message, so it is
    //        always larger than what it reports on - and it is built in a
    //        16-bit addressed message heap (65535 bytes).  Unbounded, a message
    //        of about 30 KB - well inside what a stock peer may send, since
    //        P2Peerio::m_dwMaxRecvSize defaults to 32768 - made the heap throw
    //        "Internal VBHeapRoot.uVBLockAddr=1 corruption" from
    //        VBHeapRoot_SetFree() on the routing hub's pump thread, and NO
    //        report went out at all.  See MAX_P2PmsgWrapEmbed for the
    //        measurements and for why the bound is half of MAX_P2Psize
    //      : Over the bound the body is ELIDED, not truncated.  A truncated
    //        IOMAGE is a corrupt message, and handing the parser one of those
    //        is the defect class this tree has spent sessions closing.  The
    //        stub is a VALID message carrying the original name, source and
    //        destination, so IsWrapped(), UnwrapFactory() and the stock
    //        On_MsgCatch handler all behave exactly as they did
    PrepareP2Piomage ( ~(DWORD)0 );
    const UINT nP2PiomageSize = P2PiomageSize ( );
    if ( nP2PiomageSize <= (UINT)MAX_P2PmsgWrapEmbed )
    {
      P3PmsgData oData ( (void *)P2Piomage(), nP2PiomageSize, VBLockData_BLOB16 );
      ReleaseP2Piomage ( );
      spMsg -> InitItem ( VBLockBSTR_WRP, oData );
    }
    else
    {
      ReleaseP2Piomage ( );
      // Snapshots again, for the reason given at the top of this function: the
      // name and the two addresses are all ring pointers off Windows, and each
      // call below spends slots before the previous value has been copied out
      const CString strName = c_name ( );
      P2PeerMsg oStub ( (P2PmsgID)strName );
      oStub.SetSource ( (P2PaddrSTR)strSource );
      oStub.SetDestin ( (P2PaddrSTR)strDestin );
      oStub.PrepareP2Piomage ( ~(DWORD)0 );
      P3PmsgData oData ( (void *)oStub.P2Piomage(), oStub.P2PiomageSize()
                       , VBLockData_BLOB16 );
      oStub.ReleaseP2Piomage ( );
      spMsg -> InitItem ( VBLockBSTR_WRP, oData );
      // Traced, not raised.  A message too big to quote is a routine
      // consequence of its size, not an error in its own right - and the
      // caller is in the middle of reporting a DIFFERENT failure, so throwing
      // here would lose that report as well.  (IsEVTRC lives in P2Pwin32.h,
      // which this TU deliberately does not pull in; the event is cheap beside
      // a >16 KB message and this branch is not on any hot path.)
      EVTRC->MODULE
           ->Message("Response body elided: the wrapped message is %u bytes, "
                     "over the %u-byte embedding bound"
                    , nP2PiomageSize, (UINT)MAX_P2PmsgWrapEmbed )
           ->Advice_T("The response carries the message's name and addresses "
                      "but not its payload")
           ->Group("P2P")
           ->Cancel();
    }
    P2PeerMsgPrefix *pPrefix1 = (P2PeerMsgPrefix *)((*spMsg)[1].r_data().c_vBlob());
                     pPrefix1 -> uiState &= ~P2PeerMsgState_Posted;

    // Copy in details of the wrapped message
    //spMsg -> m_pP2PmsgWrap = new P2PeerMsg ( *this );

    // Then
    return spMsg.Dereference();
}

//
//  Constructs a reflection message from the encapsulated message
//  NOTES: Simply clones a copy of the contained message and swaps
//         the source and destination addresses.
//       : The reflection state of the manufactured message is
//         inverted.  Normal messages are manufactured from reflected
//         messages and reflected state messages are manufactured
//         from normal messages
//
//  Returns:     P2PeerMsg*
//               Pointer to reflection message.  Client becomes
//               responsible for life cycle.
//
P2PeerMsg*
P2PeerMsg::ReflectFactory ( ) const
{
    // Build the response message
    // NOTES: Source and destination addresses are swapped. Content
    //        is preserved
    P2PeerMsgSP spMsg = new P2PeerMsg ( *this );
    spMsg -> SetSource ( r_Destin() );
    spMsg -> SetDestin ( r_Source() );

    // Swap reflected state
    // NOTES: Normal messages become reflected and reflected
    //        messages become normal
    //      : Refer ON_P2PeerMsg and ON_P2PeerMsg_CATCH
    //        for intercepting reflected-reflected (normal) P2PeerMsg's
    //      : Refer ON_P2PeerMsg_REFLECT and ON_P2PeerMsg_REFLECT_CATCH
    //        for intercepting reflected-normal P2PeerMsg's
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)spMsg->r_data().c_vBlob();
    if ( (pPrefix->nMsg&P2P_Reflected) == P2P_Reflected )
      pPrefix -> nMsg ^= P2P_Reflected;
    else
      pPrefix -> nMsg |= P2P_Reflected;

    // Then
    return spMsg.Dereference();
}

//
//  Constructs a loopback message from the encapsulated message
//  NOTES: Simply clones a copy of the contained message and swaps
//         the source and destination addresses.
//       : Under some circumstances P2PeerHub's may exchange the
//         same message (P2PmsgPing or P2PmsgPoll etc) to accomplish
//         a particular outcome
//
//  Returns:     P2PeerMsg*
//               Loopback P2PeerMsg pointer.  Client becomes
//               responsible for life cycle.
//
P2PeerMsg*
P2PeerMsg::LoopbackFactory ( ) const
{
    P2PeerMsgSP spMsg = new P2PeerMsg ( *this );
    spMsg -> SetSource ( r_Destin() );
    spMsg -> SetDestin ( r_Source() );
    return spMsg.Dereference();
}

//
//  Wraps message for reflection in nominated message type
//
//  Parameters:  P2Pmsg_t nMsg
//               Type of message contents are wrapped into.
//               NOTES: This is the outer message that must be
//                      unwrapped at the destination.
//
//               void *pvMsgData
//               Data pointer.  Null value handled.
//
//               short iMsgDataSize
//               Size of message data area.  This is in addition
//               to the wrapped message.
//
//  Returns:     P2PeerMsg*
//               Pointer to unwrapped message.  Client becomes
//               responsible for life cycle.
//
P2PeerMsg*
P2PeerMsg::WrapFactory ( P2PmsgID szMsg
                       , const void *pvMsgData, P2Psize_t iDataSize )
{
    // Build a wrapped message
    // NOTES: Add an extra bit on for the size of this message
    //      : Message source and destinations are reversed.
    P2PeerMsgSP spMsg
        = new P2PeerMsg ( GetDestin(), GetSource()
                        , szMsg
                        , pvMsgData, iDataSize );
    spMsg -> r_data() = r_data();

    // Copy in details of the wrapped message
    // TODO:LJM This can be optimised
    PrepareP2Piomage ( ~(DWORD)0 );
//UINT nSizeIOmage=this->IOmageSize();
    P3PmsgData oData ( (void *)P2Piomage(), P2PiomageSize(), VBLockData_BLOB16 );
//UINT nSizeData=oData.Sizeof();
    ReleaseP2Piomage ( );
    spMsg -> InitItem ( VBLockBSTR_WRP, oData );

    // and simply
    return spMsg.Dereference();
}
//P2PeerMsg*
//P2PeerMsg::WrapFactory ( P2PmsgID pszMsg
//                       , const void *pvMsgData, P2Psize_t iDataSize )
//{
//    // Build a wrapped message
//    // NOTES: Add an extra bit on for the size of this message
//    //      : Message source and destinations are reversed.
//    P2PeerMsg *pMsg
//        = new P2PeerMsg ( m_pP2PmsgBSTR -> nDestinID
//                        , m_pP2PmsgBSTR -> nSourceID
//                        , pszMsg
//                        , pvMsgData, iDataSize );
//    //pMsg -> m_pMsgHeader -> ucPriority 
//    //                    = m_pMsgHeader -> ucPriority;
//    pMsg -> m_pP2PmsgBSTR ->ucPriority 
//                        = m_pP2PmsgBSTR-> ucPriority;
//    //pMsg -> m_pMsgHeader -> dwAddrTag 
//    //                    = m_pMsgHeader -> dwAddrTag;
//    pMsg -> m_pP2PmsgBSTR ->dwAddrTag
//                        = m_pP2PmsgBSTR-> dwAddrTag;
//
//    // Copy in details of the wrapped message
//    //pMsg -> Allocate_( pvMsgData, iDataSize
//    //                 , m_pMsgHeader_, m_pMsgHeader_->iSize );
//    ASSERT(!pMsg->m_pP2PmsgWrap);
//    pMsg -> m_pP2PmsgWrap = new P2PeerMsg ( *this );
//
//    // and simply
//ASSERT(pMsg->Map_MatchName(pszMsg));
//ASSERT(Map_MatchName((*pMsg)[1].GetName()));//DELETE-ME
//    return pMsg;
//}

void
P2PeerMsg::WrapAttach ( P2PeerMsg *pP2Pmsg )
{
    // To be sure, to be sure
ASSERT(0);
    if ( m_pP2PmsgWrap )
      EVERR->MODULE
           ->Message_T("P2Pmsg already contains wrapped P2Pmsg" )
           ->Advice_T ("Bug, (SNHappen)")
           ->Throw();
    m_pP2PmsgWrap = pP2Pmsg;
}

//
//  Unwraps this message to expose the original wrapped message.
//  NOTES: Refer WrapFactory() for wrapping up messages.  Use
//         IsWrapped() to check wrapped status of a message.
//       : Client becomes responsible for life cycle of the
//         unwrapped message returned.
//
//  Returns:     P2PeerMsg*
//               Pointer to unwrapped message.  Client becomes
//               responsible for life cycle.
//                 0.. No wrapped message.
//
P2PeerMsg*
P2PeerMsg::UnwrapFactory ( )
{
    // Optimisation
    if ( m_pP2PmsgWrap )
      return new P2PeerMsg(*m_pP2PmsgWrap);

    // To be sure, to be sure
    if ( !IsWrapped() )
      EVERR->MODULE
           ->Message_T("P2PeerMsg not wrapped" )
           ->Advice_T ("Use IsWrapped() as pre-check")
           ->Throw();

    // Instanciate
    VBListIOmage *pIOmage = (VBListIOmage *)r_item(VBLockBSTR_WRP).r_data().c_vBlob();
    return new P2PeerMsg ( *pIOmage );
}

//
//  Builds an error response from the passed error message
//
//
//  Parameters:  P2Pevent *pP2Pevent
//               Error message object from which the response
//               is to be constructed
//
//  Returns:     P2PeerMsg*
//               Pointer to error response message.  Client
//               becomes responsible for life cycle.
//
/*P2PeerMsg*
P2PeerMsg::ErrorResponseFactory ( P2Pevent *pP2Pevent )
{
    // Introduce locals
    P2PeerMsg *pMsg  = 0;

    // Build response message
    EventLogData *pEventLogData
               = pP2Pevent -> LogEventialsFactory();
    pMsg = WrappedResponseFactory ( P2Pmsg_Error
                                  , pEventLogData
                                  , pEventLogData->nSize );
    delete pEventLogData;

    // Tidy up and
    return pMsg;
}*/

//
//  Creates P2Pmsg_Exception from encapsulated P2PeerMsg and passed
//  P2Pevent
//  NOTES: Clones routing properties of the contained message and
//         then swaps the source and destination addresses
//       : P2PeerMsg_CATCH handlers are used to intercept posted
//         P2Pmsg_Exceptions
//
//
//  Parameters:  P2Pevent *pEVT
//               Event object from which the exception is to be
//               constructed
//               NOTES: Use the P2PeventFactory() to extract P2Pevent's
//                      from P2Pmsg_Exception's
//
//  Returns:     P2PeerMsg*
//               Exception P2PeerMsg pointer.  Client becomes
//               responsible for life cycle.
//
P2PeerMsg*
P2PeerMsg::ExceptionFactory ( P2Pevent *pEVT )
{
    // Introduce locals
    P2PeerMsgSP spMsg;

    // Build response message
    spMsg = WrappedResponseFactory ( P2Pmsg_Exception, 0, 0 );
    spMsg -> AttachP2Pevent ( pEVT );

    // Tidy up and
    ASSERT(spMsg->Map_MatchName(P2Pmsg_Exception));//DELETE-ME
    ASSERT(spMsg->IsWrapped());//DELETE-ME
    ASSERT(AfxCheckMemory());
    ASSERT(Map_MatchName( (*spMsg)[1].c_name()));
    return spMsg.Dereference();
}

///////////////////////////////////////////////////////////////////////
//  P2Pevents

//      P2Pevent*
//        UnwrapP2Pevent( );

//  Attaches copy of passed P2Pevent to message
//  NOTES: Any existing P2Pevent is displaced by passed P2Pevent
//
//  Parameters: P2Pevent *pEvent
//              Attached event
//
//              LPCTSTR lpszFieldName = 0
//              Name of node under which event is attached
//
void
P2PeerMsg::AttachP2Pevent ( const P2Pevent *pEVT
                          , LPCTNAM lpszFieldname )
{
    // Field confirmation
    if ( lpszFieldname    == 0 ||
         lpszFieldname[0] == 0    )
      lpszFieldname = L"P2Pevent";

    // Events node may not exist
    if ( !Exists(VBLockBSTR_EVT) )
      InitItem ( VBLockBSTR_EVT, P3PmsgData() );

    // Attachment
    if ( r_item(VBLockBSTR_EVT).Exists(lpszFieldname) )
      r_item(VBLockBSTR_EVT)[lpszFieldname] = *pEVT;
    else
      r_item(VBLockBSTR_EVT) += *pEVT;
}

//
//  Extracts copy of P2Pevent from message
//  NOTES: Refer complimentary AttachP2Pevent() for attachment details
//
//
//  Parameters: LPCTSTR lpszFieldName = 0
//              Name of field from which P2Pevent is to be extracted
//
//  Returns:    P2Pevent*
//              Extracted instance, client becomes responsible for
//              life cycle
//                0.. Nothing attached
P2Pevent*
P2PeerMsg::ExtractP2Pevent( LPCTNAM lpszFieldname )
{
    // Node confirmation
    if ( lpszFieldname    == 0 ||
         lpszFieldname[0] == 0    )
      lpszFieldname = L"P2Pevent";

    // Node extraction
    if ( !Exists(VBLockBSTR_EVT)                       ||
         !r_item(VBLockBSTR_EVT).Exists(lpszFieldname)    )
      return 0;

    // Manufacture
    // NOTES: Client responsible for life cycle
    return new P2Pevent(r_item(VBLockBSTR_EVT).SelectItem(lpszFieldname));
}

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg_MAP routing
//  NOTES: Used for P2PeerMsg routing and handler assignment

//
//  Matches P2PeerMsg state against passed filter
//
//
//  Parameters:  USHORT uiMsgStateWildbits
//               Bit mask filter of allowable states
//
//
//  Returns:     bool
//               Filtered comparison result
//                 true... Matched
//                 false.. Failed to match
//
bool
P2PeerMsg::Map_MatchState( USHORT uiMsgStateFilter )
{
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    bool bStateMsg =     pPrefix -> nMsg&P2P_Reflected ? true : false;
    bool bStateFlt =    uiMsgStateFilter&P2P_Reflected ? true : false;

    // Implementation
    return bStateMsg == bStateFlt ? true : false;
}

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
bool
P2PeerMsg::Map_MatchName ( LPCTNAM pszMsgWildcard ) const
{
    // Preparation
    bool         star   = false;
    const T_ADDR *pszMsg = c_name ( );

    // Implmentation
Top:
    const T_ADDR *p, *s;
    for ( s = pszMsg, p = pszMsgWildcard; *s; ++s, ++p )
    {
      switch (*p) {
         case '?':
            if (*s == '.') goto starCheck;
            break;
         case '*':
            star = TRUE;
            pszMsg = s, pszMsgWildcard = p;
            if (!*++pszMsgWildcard) return TRUE;
            goto Top;
         case '#':
           if (!isdigit(*s))
             goto starCheck;
           while (isdigit(*(s + 1)))
             s++;
           break;
         default:
            //if (mapCaseTable[*s] != mapCaseTable[*p])
            if (*s != *p )
               goto starCheck;
            break;
      } /* endswitch */
   } /* endfor */
   if (*p == '*') ++p;
   return (!*p);

starCheck:
   if (!star) return FALSE;
   pszMsg++;
   goto Top;
}

void
P2PeerMsg::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );
}

void
P2PeerMsg::Print ( FILE *fd )
{
    // Indentation
    int nDepth = GetDepth ( );
    for ( int i = 0; i < nDepth; i++ )
      P3Pmsg_fwprintf ( fd, L"  " );

    // Encode message header
    P3Pmsg_fwprintf ( fd, L"P2PeerMsg[%i] {\n", nDepth );
    //m_oBSTR.Print ( fd, 1+nDepth );
    P3PmsgBSTR::Print ( fd, 1+nDepth );
    if ( IsWrapped() )
      (*this)[1].Print ( fd );

    // Tidy up
    for ( int i = 0; i < nDepth; i++ )
      P3Pmsg_fwprintf ( fd, L"  " );
    P3Pmsg_fwprintf ( fd, L"}\n" );
}

//
//  Generates Visual Runtime Summary for P2PeerMsg instance
//  FORMAT: [P2PeerMsg Name=MsgName, Src=MsgSource, Dst=MsgDestin]
//        : Such brief summaries are used to pass brief P2PeerMsg state
//          information to P2Pevent's
//
//
//  Returns:     LPCTSTR
//               Pointer to encoded P2PeerMsg summary
//               NOTES: (Re-)Encoded upon each reference
//
LPCTSTR
P2PeerMsg::GetVisualRTSummary ( )
{
    // Container
    if ( !m_pstrVisualSummary )
      m_pstrVisualSummary = new CString ( );

    // Simply encode header
    m_pstrVisualSummary
      -> Format ( L"[Name=%s, Source=%s, Destin=%s]"
                , c_name()
                , GetSource()
                , GetDestin() );

    // Tidy up and
    return *m_pstrVisualSummary;
}

//
//  Generates Visual Runtime Summary for P2PeerMsg instance
//  FORMAT: [P2PeerMsg Name=MsgName, Src=MsgSource, Dst=MsgDestin]
//        : Such brief summaries are used to pass brief P2PeerMsg state
//          information to P2Pevent's
//
//  Parameters:  LPCTSTR lpszVar
//               Name assigned to the generated P3PmsgItem
//
//  Returns:     LPCTSTR
//               Pointer to encoded P2PeerMsg summary
//               NOTES: (Re-)Encoded upon each reference
//
const P3PmsgItem&
P2PeerMsg::SetP2PeventFParams ( LPCTNAM lpszVar )
{
    UNREFERENCED_PARAMETER(lpszVar);
    // Create a placeholder for receipt of P2PeerMsg details
    P3PmsgItem& oItemVar = ((P2PeerMsg *)this)->r_item ( VBLockBSTR_ROOT );

    // Tidy up and
    return oItemVar;
}

///////////////////////////////////////////////////////////////////////
//  Properties

//
//  Get message source P2PaddrSTR
//
//  Returns:     P2PaddrSTR
//               Source address
//
P2PaddrSTR
P2PeerMsg::GetSource ( ) const
{
    // May not exist
    P3PmsgItem& oNodeAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    //return oNodeAddr.Select(TMsg_Src)).c_wstr(strP2PaddrNULL);
    if ( oNodeAddr.Exists(TMsg_Src) )
      return oNodeAddr[TMsg_Src].c_wstr();
    return strP2PaddrNULL;
}

//
//  Sets message source P2PaddrSTR
//
//  Parameters:  P2PaddrSTR strSource
//               New source address
//
//  Returns:     P2PaddrSTR
//               Adopted source address
//
P2PaddrSTR
P2PeerMsg::SetSource ( P2PaddrSTR strSource )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // Field may not exist
    P3PmsgItem& oAddr = r_item(VBLockBSTR_NET);
    if ( oAddr.Exists(TMsg_Src) )
      oAddr[TMsg_Src].r_data() = DataWSTR08(strSource);//TODO:LJM could be optimised
    else
      oAddr += P3PmsgField ( TMsg_Src, DataWSTR08(strSource) );
    return oAddr[TMsg_Src].c_wstr();
}

P3PmsgField&
P2PeerMsg::SetSource ( const P3PmsgField& oSource )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // Field may not exist
    P3PmsgItem& oNodeAddr = r_item(VBLockBSTR_NET);
    ASSERT(oNodeAddr.VerifyContainment());
    if ( oNodeAddr.Exists(TMsg_Src) )
      oNodeAddr[TMsg_Src].r_data() = oSource;
    else
      oNodeAddr += P3PmsgField ( TMsg_Src, oSource.r_data() );

    // Attributes
    P3PmsgField& oSrc = oNodeAddr[TMsg_Src];
    if ( oSource.IsAttributed() )
      oNodeAddr.SelectItem(TMsg_Src).r_Attr() = ((P3PmsgField&)oSource).r_Attr();
    else if ( oSrc.IsAttributed() )
      oSrc.r_Attr().Drop();

    // Stacking
    if ( oSource.IsStacked() )
    {
      oSrc.r_Stck() = oSource.r_Stck();
      oSrc.r_Stck().Rename ( TMsg_Src );
    }
    else if ( oSrc.IsStacked() )
      oSrc.r_Stck().Drop();

    // Tidy up, and
    return oSrc;
}
P3PmsgField&
P2PeerMsg::r_Source ( ) const
{
    return ((P2PeerMsg *)this)->r_item(VBLockBSTR_NET)[TMsg_Src];
}

//
//  Manages destination P2PaddrSTR
//  NOTES: Destination address of this P2PeerMsg.  Specified address
//         may be subsequently qualified via the ConMap address
//
//  Returns:     P2PaddrSTR
//               Destination address
//
P2PaddrSTR
P2PeerMsg::GetDestin ( ) const
{
    // Simply
    P3PmsgItem& oItemAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(TMsg_Dst) )
      return oItemAddr[TMsg_Dst].c_wstr();
    return strP2PaddrNULL;
}
P2PaddrSTR
P2PeerMsg::SetDestin ( P2PaddrSTR strDestin )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // May not exist
    P3PmsgItem& oNodeAddr = r_item(VBLockBSTR_NET);
    if ( oNodeAddr.Exists(TMsg_Dst) )
      oNodeAddr[TMsg_Dst].r_data() = DataWSTR08(strDestin);//TODO:LJM could be optimised
    else
      oNodeAddr += P3PmsgField ( TMsg_Dst, DataWSTR08(strDestin) );
    return oNodeAddr[TMsg_Dst].c_wstr();
}
P3PmsgField&
P2PeerMsg::SetDestin ( const P3PmsgField& oDestin )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // Field may not exist
    P3PmsgItem& oNodeAddr = r_item(VBLockBSTR_NET);
    if ( oNodeAddr.Exists(TMsg_Dst) )
      oNodeAddr[TMsg_Dst].r_data() = oDestin;
    else
      oNodeAddr += P3PmsgField ( TMsg_Dst, oDestin.r_data() );

    // Attributes
    P3PmsgField& oDst = oNodeAddr[TMsg_Dst];
    if ( oDestin.IsAttributed() )
      oNodeAddr.SelectItem(TMsg_Dst).r_Attr() = ((P3PmsgField&)oDestin).r_Attr();
    else if ( oDst.IsAttributed() )
      oDst.r_Attr().Drop();

    // Stacking
    if ( oDestin.IsStacked() )
    {
      oDst.r_Stck() = oDestin.r_Stck();
      oDst.r_Stck().Rename ( TMsg_Dst );
    }
    else if ( oDst.IsStacked() )
      oDst.r_Stck().Drop();

    // Tidy up, and
    return oDst;
}
P3PmsgField&
P2PeerMsg::r_Destin ( ) const
{
    return ((P2PeerMsg *)this)->r_item(VBLockBSTR_NET)[TMsg_Dst];
}

//
//  Manages the end-to-end scope P2PaddrSTR
//  NOTES: What the ORIGIN addressed this message to, which Dst stops being the
//         moment a copy is re-addressed - refer TMsg_Scp in the header for the
//         two protections that cost
//       : Stamped once, by the hub that fans a message out, and never
//         rewritten afterwards.  Lives in the network node beside Src and Dst
//         so it survives relaying for exactly the same reason they do: the
//         whole node travels in the image, not just the payload
//
//  Returns:     P2PaddrSTR
//               Scope address, strP2PaddrNULL when none was stamped
//
P2PaddrSTR
P2PeerMsg::GetScope ( ) const
{
    // Simply
    P3PmsgItem& oItemAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(TMsg_Scp) )
      return oItemAddr[TMsg_Scp].c_wstr();
    return strP2PaddrNULL;
}

//
//  Stamps the end-to-end scope
//  NOTES: WSTR08 to match Src and Dst - this holds the same kind of thing they
//         hold and has no reason to be framed differently
//       : The CALLER decides whether stamping is allowed.  A hub forwarding a
//         message that already carries a scope must leave it alone, the same
//         rule and for the same reason as an existing relay attestation
//
//  Parameters:  P2PaddrSTR strScope
//               Address the origin addressed this message to
//
P2PaddrSTR
P2PeerMsg::SetScope ( P2PaddrSTR strScope )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // May not exist
    P3PmsgItem& oNodeAddr = r_item(VBLockBSTR_NET);
    if ( oNodeAddr.Exists(TMsg_Scp) )
      oNodeAddr[TMsg_Scp].r_data() = DataWSTR08(strScope);
    else
      oNodeAddr += P3PmsgField ( TMsg_Scp, DataWSTR08(strScope) );
    return oNodeAddr[TMsg_Scp].c_wstr();
}

//
//  Reports whether an end-to-end scope has been stamped
//  NOTES: Presence only.  Absent means nothing has re-addressed this message,
//         so Dst still answers both questions - it does NOT mean the scope was
//         lost, and the two are indistinguishable here on purpose
//
bool
P2PeerMsg::HasScope ( ) const
{
    // Simply
    P3PmsgItem& oItemAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    return oItemAddr.Exists(TMsg_Scp) ? true : false;
}

//
//  Manages the end-to-end scope of an UPCAST P2PaddrSTR
//  NOTES: What the ORIGIN addressed an upcast to, which Dst stops being the
//         moment On_P2PeerUCast re-addresses a copy to its link peer - the
//         same loss, and the same two protections, as TMsg_Scp above
//       : A SEPARATE FIELD FROM THE SCOPE and not a second stamper of it.
//         Both name an AUDIENCE the origin chose - a subtree one way, a chain
//         of ancestors the other - and neither can be sealed.  They are kept
//         apart so that exempting one from the seal requirement is not a way
//         of exempting the other without having been asked.  Refer TMsg_Ups
//         in the header, which carries the whole argument
//       : Stamped once, by the hub that fans an upcast out, and never
//         rewritten - the identical discipline On_P2PeerBCast applies to the
//         scope, and for the identical reason
//
//  Returns:     P2PaddrSTR
//               Upcast scope, strP2PaddrNULL when none was stamped
//
P2PaddrSTR
P2PeerMsg::GetUpScope ( ) const
{
    // Simply
    P3PmsgItem& oItemAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(TMsg_Ups) )
      return oItemAddr[TMsg_Ups].c_wstr();
    return strP2PaddrNULL;
}

//
//  Stamps the end-to-end scope of an upcast
//  NOTES: WSTR08 to match Src, Dst and Scp - this holds the same kind of thing
//         they hold
//       : The CALLER decides whether stamping is allowed, exactly as SetScope
//         leaves it to the caller and for the same reason
//
//  Parameters:  P2PaddrSTR strScope
//               Address the origin addressed this upcast to
//
P2PaddrSTR
P2PeerMsg::SetUpScope ( P2PaddrSTR strScope )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // May not exist
    P3PmsgItem& oNodeAddr = r_item(VBLockBSTR_NET);
    if ( oNodeAddr.Exists(TMsg_Ups) )
      oNodeAddr[TMsg_Ups].r_data() = DataWSTR08(strScope);
    else
      oNodeAddr += P3PmsgField ( TMsg_Ups, DataWSTR08(strScope) );
    return oNodeAddr[TMsg_Ups].c_wstr();
}

//
//  Reports whether an upcast scope has been stamped
//  NOTES: Presence only, the same contract HasScope has
//
bool
P2PeerMsg::HasUpScope ( ) const
{
    // Simply
    P3PmsgItem& oItemAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    return oItemAddr.Exists(TMsg_Ups) ? true : false;
}

//
//  Reports whether this message is a copy some hub fanned out
//  NOTES: EITHER stamp answers yes, and a caller that wants "is this a
//         fan-out" must ask this rather than HasScope().  While there was one
//         relay the two questions had one answer; there are two relays now and
//         a test written as HasScope() silently means "broadcast only"
//       : WHICH IS THE POINT OF HAVING IT.  Two call sites want the general
//         question - the in-process end-to-end waiver, both halves - because
//         what they decline is a message whose address names something this
//         process cannot vouch for, and a chain of ancestors is as far outside
//         that as a subtree.  The two SEAL exemptions want the specific
//         question and keep asking it, because each is governed by its own
//         switch.  Every reader here is one or the other on purpose
//
//  Returns:     bool
//               true... a scope or an upcast scope was stamped
//
bool
P2PeerMsg::IsFannedOut ( ) const
{
    // Simply
    P3PmsgItem& oItemAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(TMsg_Scp) )
      return true;
    return oItemAddr.Exists(TMsg_Ups) ? true : false;
}

//
//  The address a security check should key on
//  NOTES: The scope when one was stamped, the upcast scope when one was, the
//         destination when neither.  This is the accessor the seal and
//         attestation paths use at BOTH ends - refer the header
//       : ONE lookup and ONE returned pointer on whichever branch answers,
//         rather than GetScope() falling through to GetUpScope() falling
//         through to GetDestin().  Off Windows c_wstr() widens into a ring of
//         16 thread-local buffers that the next accessor call recycles, so two
//         calls to hand back one answer is the shape of a defect that has
//         already been paid for twice in this file
//       : THE ORDER IS THE PRECEDENCE, not a preference.  A message carries at
//         most one of the first two, because one handler stamps each and each
//         stamps only when neither is there; a reader that saw both would be
//         looking at an image somebody assembled by hand, and taking the
//         broadcast scope is the conservative reading because it is the one
//         whose exemption has been live the longest
//       : Ups sits BEFORE Dst and not beside it, so an upcast copy is attested
//         and sealed against what the ORIGIN wrote rather than against the
//         parent it is about to be handed to.  That is the whole reason the
//         field exists - refer TMsg_Ups in the header
//
//  Returns:     P2PaddrSTR
//               Scope, else upcast scope, else destination, else
//               strP2PaddrNULL
//
P2PaddrSTR
P2PeerMsg::GetScopeOrDestin ( ) const
{
    // Simply
    P3PmsgItem& oItemAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(TMsg_Scp) )
      return oItemAddr[TMsg_Scp].c_wstr();
    if ( oItemAddr.Exists(TMsg_Ups) )
      return oItemAddr[TMsg_Ups].c_wstr();
    if ( oItemAddr.Exists(TMsg_Dst) )
      return oItemAddr[TMsg_Dst].c_wstr();
    return strP2PaddrNULL;
}

//
//  Manages destination connect map P2PaddrSTR
//  NOTES: Specified address will be qualified via this ConMap
//         at an internetwork boundary
//
//  Returns:     P2PaddrSTR
//               Destination address
//
P2PaddrSTR
P2PeerMsg::GetConmap ( )
{
    // Simply
    P3PmsgItem& oNodeAddr = ((P3PmsgBSTR&)*this).r_item(VBLockBSTR_NET);
    if ( oNodeAddr.Exists(L"Map") )
      return oNodeAddr[L"Map"].c_wstr();
    return strP2PaddrNULL;
}
P2PaddrSTR
P2PeerMsg::SetConmap ( P2PaddrSTR strConmap )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // May not exist
    P3PmsgItem& oItemAddr = r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(L"Map") )
      oItemAddr[L"Map"].r_data() = DataWSTR08(strConmap);//TODO:LJM could be optimised
    else
      oItemAddr += P3PmsgField ( L"Map", DataWSTR08(strConmap) );
    return oItemAddr[L"Map"].c_wstr();
}

//
//  Manages the relay attestation block
//  NOTES: The origin's ECDSA signature over this message - refer
//         p2pauth::AuthPolicy::BuildRelay for the format and
//         P2PeerCon::GateAppMsgInbound for what it is checked against
//       : Stored beside Src and Dst in the network node, so it travels with
//         the message through every relaying hop and is invisible to
//         Data()/DataSize().  See the header for why a named field rather
//         than a payload prefix
//       : Nothing here is a trust decision.  This is transport for an opaque
//         block; whether it means anything is decided by the hub that
//         verifies it against its own allow-list
//
//  Parameters:  size_t *pcbOut
//               Receives the block length.  Set to 0 when absent
//
//  Returns:     const void*
//               The block, owned by the message
//                 0.. No attestation attached
//
const void*
P2PeerMsg::GetRelayAttest ( size_t *pcbOut )
{
    // Simply
    if ( pcbOut ) *pcbOut = 0;
    if ( !Exists(VBLockBSTR_NET) )
      return 0;
    P3PmsgItem& oItemAddr = r_item(VBLockBSTR_NET);
    if ( !oItemAddr.Exists(TMsg_Att) )
      return 0;

    // Attachment
    P3PmsgItem& oItemAtt = oItemAddr[TMsg_Att];
    size_t      cb       = oItemAtt.r_data().c_size();
    const void *pv       = oItemAtt.c_vBlob();
    if ( !pv || cb == 0 )
      return 0;
    if ( pcbOut ) *pcbOut = cb;
    return pv;
}

//
//  Attaches the relay attestation block
//  NOTES: Any existing block is displaced.  Displacement rather than refusal
//         is what lets a hub re-attest a message it is itself entitled to
//         speak for - refer P2PeerCon::AttestAppMsgOutbound, which is the
//         only caller and which decides that entitlement
//
//  Parameters:  const void *pvBlock
//               p2pauth attestation block
//
//               size_t cbBlock
//               Size of the above
//
void
P2PeerMsg::SetRelayAttest ( const void *pvBlock, size_t cbBlock )
{
    // Nothing to attach
    if ( !pvBlock || cbBlock == 0 )
      return;

    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    // May not exist
    // NOTES: BLOB16 unconditionally.  The block is variable length (the
    //        attester address is inside it) and BLOB08 tops out at 255, so
    //        choosing the width from the current size would put a hub with a
    //        long address on a path nothing else takes
    P3PmsgItem& oItemAddr = r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(TMsg_Att) )
      oItemAddr[TMsg_Att].r_data() = P3PmsgData(pvBlock,cbBlock,VBLockData_BLOB16);
    else
      oItemAddr += P3PmsgField ( TMsg_Att
                               , P3PmsgData(pvBlock,cbBlock,VBLockData_BLOB16) );
}

//
//  Reports whether a relay attestation is attached
//  NOTES: Presence only.  A block that is present and worthless looks
//         identical here, and is meant to - deciding otherwise is the
//         verifier's job and it needs the allow-list to do it
//
//  Returns:     bool
//               Attachment summary
//
bool
P2PeerMsg::HasRelayAttest ( )
{
    // Simply
    size_t cb = 0;
    return GetRelayAttest ( &cb ) != 0;
}


//
//  Reports whether the payload is a sealed block rather than application bytes
//  NOTES: PRESENCE of the marker, and the hint it carries is a hint. A body
//         that says it is sealed and is not fails to open, loudly; a body that
//         is sealed and does not say so is delivered to an application as 234
//         bytes of noise, which is why the marker is set by the same code that
//         replaces the payload and in the same place
//
//  Parameters:  size_t *pcbPlainHint
//               Receives the plaintext length the sender recorded, or 0
//
//  Returns:     bool
//               Seal marker present
//
bool
P2PeerMsg::IsSealed ( size_t *pcbPlainHint )
{
    if ( pcbPlainHint ) *pcbPlainHint = 0;
    if ( !Exists(VBLockBSTR_NET) )
      return false;

    P3PmsgItem& oItemAddr = r_item(VBLockBSTR_NET);
    if ( !oItemAddr.Exists(TMsg_Sld) )
      return false;

    {
      P3PmsgItem& oItemSld = oItemAddr[TMsg_Sld];
      const void *pv = oItemSld.c_vBlob();
      size_t      cb = oItemSld.r_data().c_size();

      //  PRESENT BUT EMPTY MEANS NOT SEALED, and that is not a curiosity - it
      //  is what makes ClearSealed work. The item map has no removal that is
      //  safe on a node whose other fields are being read, so the marker is
      //  emptied rather than erased and the emptied state has to read as
      //  absent HERE or an opened message would go on claiming to be sealed.
      if ( !pv || cb == 0 )
        return false;
      //  Four bytes, big-endian, read a byte at a time. The payload pointer
      //  carries no alignment guarantee (F-S5-3) and this one is no different
      //  for being small.
      if ( pcbPlainHint && cb == 4 )
      {
        const unsigned char *p = (const unsigned char *)pv;
        *pcbPlainHint = ( (size_t)p[0] << 24 ) | ( (size_t)p[1] << 16 )
                      | ( (size_t)p[2] <<  8 ) |   (size_t)p[3];
      }
    }
    return true;
}

//
//  Marks the payload as a sealed block
//  NOTES: Called AFTER SetData has put the sealed bytes in place.  The two
//         are deliberately separate - refer the note at IsSealed
//
//  Parameters:  size_t cbPlainHint
//               Plaintext length before sealing
//
void
P2PeerMsg::SetSealed ( size_t cbPlainHint )
{
    // Network node may not exist
    if ( !Exists(VBLockBSTR_NET) )
      InitItem ( VBLockBSTR_NET, P3PmsgData() );

    unsigned char aLen[4];
    aLen[0] = (unsigned char)( ( cbPlainHint >> 24 ) & 0xFF );
    aLen[1] = (unsigned char)( ( cbPlainHint >> 16 ) & 0xFF );
    aLen[2] = (unsigned char)( ( cbPlainHint >>  8 ) & 0xFF );
    aLen[3] = (unsigned char)(   cbPlainHint         & 0xFF );

    P3PmsgItem& oItemAddr = r_item(VBLockBSTR_NET);
    if ( oItemAddr.Exists(TMsg_Sld) )
      oItemAddr[TMsg_Sld].r_data() = P3PmsgData(aLen,sizeof(aLen),VBLockData_BLOB08);
    else
      oItemAddr += P3PmsgField ( TMsg_Sld
                               , P3PmsgData(aLen,sizeof(aLen),VBLockData_BLOB08) );
}

//
//  Removes the sealed marker
//  NOTES: Called by the opening path once the plaintext is back in the
//         payload.  A message that reaches an application handler must not
//         still claim to be sealed
//
void
P2PeerMsg::ClearSealed ( )
{
    if ( !Exists(VBLockBSTR_NET) )
      return;
    P3PmsgItem& oItemAddr = r_item(VBLockBSTR_NET);
    if ( !oItemAddr.Exists(TMsg_Sld) )
      return;
    //  Displaced by an empty blob rather than erased: the item map has no
    //  removal that is safe to call on a node another field is being read
    //  from.  IsSealed treats present-but-empty as absent, which is what makes
    //  this a removal rather than a marker that says zero.
    oItemAddr[TMsg_Sld].r_data() = P3PmsgData((const void *)0,0,VBLockData_BLOB08);
}

//
//  Sets message data
//
//
//  Parameters:  P2Pmsg_t nMsg
//               Message type
//
//               const void *pvData
//               Message data
//
//               P2Psize_t iSize
//               Size of message data
//
//  Returns:     P2Psize_t
//               Total message size
//
P2Psize_t
P2PeerMsg::SetData ( P2PmsgID pszMsg
                   , const void *pvData, P2Psize_t iDataSize )
{
    // Persist and
    if ( pszMsg && wcslen(pszMsg) > 0 )
      r_name().c_name ( pszMsg );
    r_item(VBLockBSTR_MSG).c_vBlob( pvData, iDataSize );
    return Sizeof ( );
}

//
//  Sets message priority
//
//  Returns:     UCHAR
//               Message priority
//
UCHAR
P2PeerMsg::Priority ( )
{
    // Simply
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    return pPrefix -> ucPriority;
}

//
//  Sets message priority
//
//  Parameters:  UCHAR ucPriority
//
//  Returns:     UCHAR
//               New message priority
//
UCHAR
P2PeerMsg::SetPriority ( UCHAR ucPriority )
{
    // Simply
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    return pPrefix -> ucPriority = ucPriority;
}

//
//  Exposes message data pointer
//
//
//  Returns:     char*
//               Message data pointer
//
char*
P2PeerMsg::Data ( ) const
{
    // Simply
    return (char *)((P3PmsgBSTR&)*this).r_item(VBLockBSTR_MSG).c_vBlob();
}

//
//  Exposes message data size
//
//
//  Returns:     short
//               Size of message data
//
size_t
P2PeerMsg::DataSize ( )
{
    // Simply
    return r_item(VBLockBSTR_MSG).r_data().c_size();
    //return P2PmsgData::Sizeof ( );
    //return m_pMsgHeader_->iSizeData;
}

//
//  Exposes address tag field from the message header
//  NOTES: Refer SetAddrTag() method for further details
//
//
//  Returns:     DWORD
//               User data field contents
//
DWORD_PTR
P2PeerMsg::AddrTag ( )
{
    // Simply
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    return pPrefix -> dwAddrTag_;
}

//
//  Sets user defined source address tag in header
//  NOTES: This P2PeerMsgHdr field should always be
//         included as part of any P2PeerMsg response
//       : Upon receipt of a P2PeerMsg response this
//         tag may then be used identify the originating sequence
//
//
//  Parameters:  DWORD dwAddrTag
// 
//
//  Returns:     DWORD
//               Adopted user addr tag
//
DWORD_PTR
P2PeerMsg::SetAddrTag ( const void *pvTagData, P2Psize_t iSize )
{
    UNREFERENCED_PARAMETER(iSize);
    // May not exist
    //P3PmsgItem& oItemAddr = r_item(VBLockBSTR_NET);
    ASSERT(r_data().VerifyContainment());
    ASSERT(r_name().VerifyContainment()); 
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    pPrefix -> dwAddrTag_ = *(DWORD_PTR *)pvTagData;
    // NOTES: The tag rides in the message PREFIX, not as a named node
    //        item.  Declaring TMsg_Tag as well would put one value on
    //        the wire twice and give it two places to diverge, and
    //        nothing would read it there.  AddrTag() reads the prefix
    //        and is the only reader - refer HasOwnership() and
    //        PostP2PeerMsg() in P2PeerTarget.cpp.  TMsg_Tag has no
    //        other user in the tree

    // Simply
    return pPrefix -> dwAddrTag_;
}

//
//  Summarises wrapped status of message
//
//  Returns:     bool
//               Wrapped summary for message
//                 true... Wrapped message.
//                 false.. Not a wrapped message.
//
bool
P2PeerMsg::IsWrapped ( )
{
    if ( m_pP2PmsgWrap )
      return true;
    return Exists(VBLockBSTR_WRP);
}

//
//  Exposes reflection status of message
//
//
//  Returns:     bool
//               Reflection suumary for message
//                 true... Reflected message
//                 false.. Non-reflected message
//
bool
P2PeerMsg::IsReflected ( )
{
    // Simply
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)r_data().c_vBlob();
    return ((pPrefix->nMsg&P2P_Reflected)==P2P_Reflected) ? true : false;
}

P2Psize_t
P2PeerMsg::Sizeof ( ) const
{
    // P2PmsgBSTR component
    P2Psize_t iSizeof =  P3PmsgBSTR::Sizeof();

    // Wrapped messges
    if ( m_pP2PmsgWrap )
      iSizeof += m_pP2PmsgWrap -> Sizeof();
    return iSizeof;
}

int
P2PeerMsg::GetDepth ( ) const
{   
    if ( m_pP2PmsgParent )
      return  m_pP2PmsgParent -> GetDepth() + 1;
    return 0;
}

///////////////////////////////////////////////////////////////////////
//  Property exposure

LPCTNAM
P2PeerMsg::c_name ( ) const
{
    return ((P3PmsgBSTR*)this)->r_name().c_name();
}

///////////////////////////////////////////////////////////////////////
//  Support functions

//
//  Swaps P2PeerMsg source and destination addresses
//  NOTES: Swapping addresses facilitates routing of P2PeerMsg's back
//         to their source.
//       : Optimised by swapping names only
//
//  Parameters:  P2PeerMsg *pMsg
//               Message for which the source a.
//
//  Returns:     P2PeerMsg*
//               Original P2PeerMsg pointer (chaining etc)
//
P2PeerMsg*
P2PeerMsg_DstSwapSrc ( P2PeerMsg *pMsg )
{
    P3PmsgItem oNodeNET = pMsg->r_item(VBLockBSTR_NET).r_Object();

    // Source becomes destination and destination becomes source
    // NOTES: Swapping raw "Src" and "Dst" names preserves subsequent routing
    //        details
    P3PmsgField oFieldSrc = oNodeNET.SelectObject(TMsg_Src);
    P3PmsgField oFieldDst = oNodeNET.SelectObject(TMsg_Dst);
                oFieldSrc.r_name().c_name(TMsg_Dst);
                oFieldDst.r_name().c_name(TMsg_Src);

    // Tidy up, and
    return pMsg;
}

//
//  Sets the reflected state of a message
//  NOTES: Use ON_P2PeerMsg_REFLECT() to intercept reflected and
//         ON_P2PeerMsg() to intercept normal equivalents
//
//  Parameters:  P2PeerMsg *pMsg
//               Message for which reflected state is to be adjusted
//
//               bool bReflected
//                 true... ON_P2PeerMsg_REFLECT() state
//                 false.. ON_P2PeerMsg() state
//
//  Returns:     P2PeerMsg*
//               Original P2PeerMsg pointer (chaining etc)
//
P2PeerMsg*
P2PeerMsg_SetReflected ( P2PeerMsg *pMsg, bool bReflected )
{
    // Simply
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)pMsg->r_data().c_vBlob();
    if ( bReflected )
      pPrefix -> nMsg |=  P2P_Reflected;
    else
      pPrefix ->nMsg  &= ~P2P_Reflected;

    // Tidy up, and
    return pMsg;
}

//
//  Performs generic wildcard pattern matching
//
//
//  Parameters:  P2PmsgID strMsgWildcard
//               Message wildcard
//
//               P2PmsgID strMsgName
//               Message name to be matched against wildcard
//
//  Returns:     bool
//                 true... Message matches wildcard
//                 false.. No match
//
bool
Wildcard ( P2PmsgID strMsgWildcard, P2PmsgID strMsgName )
{
    // Locals
    BOOL bStar = FALSE;

    // Implmentation
TOP:P2PmsgID p, s;
    for ( s = strMsgName, p = strMsgWildcard; *s; ++s, ++p )
    {
      switch (*p)
      {
         case L'?':
            if ( *s == _T('.') )
            {
              goto starCheck;
            }
            break;
         case L'*':
            bStar = TRUE;
            strMsgName = s, strMsgWildcard = p;
            if ( !*++strMsgWildcard )
              return TRUE;
            goto TOP;
         default:
            //if (mapCaseTable[*s] != mapCaseTable[*p])
            if ( *s != *p )
              goto starCheck;
            break;
      }
   }
   if ( *p == L'*' ) ++p;
   return (!*p);

starCheck:
   if ( !bStar ) return FALSE;
   strMsgName++;
   goto TOP;
}

//
//  Summarises posted status
//
//  Parameters:  P2PeerMsg *pMsg
//               Message whose posted status is to be summarised
//
//  Returns:     BOOL
//                 true... Posted
//                 false.. Not posted
BOOL
P2PeerMsg_IsPosted ( const P2PeerMsg *pMsg )
{
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)((P2PeerMsg *)pMsg)->r_data().c_vBlob();
    return (pPrefix->uiState&P2PeerMsgState_Posted) == P2PeerMsgState_Posted ? TRUE : FALSE;
}

//
//  Sets P2PeerMsg control option
//
//  Parameters:  P2PeerMsg *pMsg
//               Message whose posted status is to be summarised
//
//               UINT08 uiCtrlOptionAdd
//               Control option to be added
// 
//               UINT08 uiCtrlOptionRemove
//               Control option to be removed
//
//  Returns:     UINT08
//               New control state
//
UINT08
P2PeerMsg_SetCtrlOptions ( P2PeerMsg *pMsg
                         , UINT uiCtrlOptionAdd, UINT08 uiCtrlOptionRemove )
{
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)((P2PeerMsg *)pMsg)->r_data().c_vBlob();
    UINT08 uiCtrl = pPrefix->uiCtrl;
           uiCtrl &= uiCtrlOptionRemove;
           uiCtrl |= uiCtrlOptionAdd;
    return pPrefix->uiCtrl = uiCtrl;
}