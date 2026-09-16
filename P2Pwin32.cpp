// Copyright © 2004-2013, 2026 Ivyware Pty Ltd, Khrustal & Mann
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

#include "stdafx.h"
#include "Kernel32_Ext.h"
#include "P2PeerMsg.h"
#include "P2PeerCon.h"
#include "P2Pwin32.h"
#include "P2PeerExplorer.h"

///////////////////////////////////////////////////////////////////////
//  Private P2Peer definitions
//  NOTES: Used for P2PeerCon and P2PeerMsg object pumping and
//         support
//
static
std::atomic<DWORD> s_cP2Pmsg = 0;  // live P2Pmsg count; ++/-- and capacity-check reads happen
                                   // on pump threads and posters under different locks - atomic
                                   // to fix the TSan-reported race (Risk #3). Approximate reads
                                   // (the > MAX capacity guard) are fine.
//  THE bound on live P2Pmsg's, and the only one.  Note the scope: s_cP2Pmsg is
//  a PROCESS-WIDE count of live P2Pmsg's across every pump, not the depth of the
//  pump being posted to, so this bounds the process's message budget and the
//  diagnostic's "pump is full" is the older, narrower reading of it.
//  NOTES: const, not "effectively const" - it was a mutable static that nothing
//         ever assigned, which is what let the figure and the diagnostic drift
//         apart in the first place.  The compiler now holds that open.
static
const DWORD      s_cP2PmsgMAX = 50000;

//  ONE bound, ONE rendering.  Every capacity diagnostic renders s_cP2PmsgMAX
//  through this format rather than naming a figure of its own.
//  NOTES: This is Stage 0 step 2.  Seven sites tested the depth
//         and all seven printed "10000 entries" while the bound was 50000 - the
//         literal outlived the constant, and a message nobody could trust is how
//         an operator learns to disregard the queue diagnostic entirely.
//       : Numeric-only, so the format stays NARROW at the sites that were narrow
//         - rule 3 of p2p_diag_wideformat_sweep.md.  %lu (and the unsigned long
//         cast at every site) rather than %u because DWORD is unsigned long on
//         Windows and uint32_t on Linux, and because Platform's p2p_fix_wformat
//         rewrites %s but passes %lu through untouched on the wide path.
#define P2PMSG_QUEFULL_FMT      "P2Pmsg pump is full, %lu entries"
#define P2PMSG_WIDEN_(s)       L##s
#define P2PMSG_WIDEN(s)        P2PMSG_WIDEN_(s)
#define P2PMSG_QUEFULL_FMT_W    P2PMSG_WIDEN(P2PMSG_QUEFULL_FMT)

///////////////////////////////////////////////////////////////////////
//  Backpressure on the P2Pmsg budget
//  NOTES: Stage 4 step 12.  The bound above is a CLIFF: a
//         peer may send as fast as it likes right up to it, and the failure at
//         it is an exception raised on whichever thread happens to post the
//         message that crosses it - which is nearly never the thread, or the
//         connection, responsible for the pressure.  An operator sees a
//         QUEFULL out of a send path and learns nothing about who caused it
//       : These two marks make the same budget a SLOPE.  At or above the HIGH
//         mark a connection stops asking its transport for more (refer
//         P2PeerCon::HoldRecvForBackpressure); at or below the LOW mark it
//         starts again.  The gap between them is hysteresis and is the whole
//         reason there are two numbers: a single mark makes a connection
//         resume the instant the budget dips one message below it, and it is
//         then immediately re-throttled, which is a spin rather than a brake
//       : ALWAYS ON, unlike the accept bounds, and the default marks are
//         fractions of the existing ceiling rather than new numbers.  An
//         opt-in backpressure default would leave the cliff standing for every
//         deployment that did not know to ask, which is the whole complaint
//         the step makes.  Nothing in the suite comes within an order of
//         magnitude of 37500 live messages, so turning it on by default
//         changes no measurable behaviour - which is what makes it defensible
//       : SETTABLE, unlike s_cP2PmsgMAX, and for a different reason than
//         configurability for its own sake: a deployment that wants to feel
//         backpressure earlier than three quarters of the process budget has
//         no other way to ask, and a TEST cannot manufacture 37500 live
//         messages cheaply enough to be a gate.  The ceiling stays const
//       : Atomic for the same reason s_cP2Pmsg is - read on pump threads and
//         written on whichever thread configured the hub
static
std::atomic<DWORD> s_cP2PmsgHIGH ( s_cP2PmsgMAX * 3 / 4 );   // 37500
static
std::atomic<DWORD> s_cP2PmsgLOW  ( s_cP2PmsgMAX / 2     );   // 25000

//  Cumulative count of holds applied, process-wide and never reset.
//  NOTES: The step asks for the decision to be VISIBLE IN A COUNTER, and this
//         is the one that answers "is this happening at all" without a hub, a
//         snapshot or a connection in hand.  Per-connection attribution is
//         P2PeerCon::GetRecvThrottleCount(), and the hub's own figure is the
//         Throttled field of its snapshot
static
std::atomic<DWORD> s_cP2PmsgHeld ( 0 );

//
//  Sets the backpressure marks on the P2Pmsg budget
//  NOTES: Throws rather than clamping.  A caller that named two numbers and
//         got them the wrong way round has a bug, and silently swapping them
//         would hide it behind behaviour that looks almost right
//       : dwHigh must stay BELOW the ceiling, not merely at or under it.  A
//         held connection arms a poll timer, a timer IS a P2Pmsg, and a mark
//         at the ceiling would make the act of applying backpressure throw the
//         QUEFULL it exists to prevent
//
//  Parameters:  DWORD dwHigh
//               Live-message count at which connections stop reading
//
//               DWORD dwLow
//               Live-message count at which they start again
void
SetP2PmsgBudgetMarks ( DWORD dwHigh, DWORD dwLow )
{
    if ( dwHigh == 0 || dwLow == 0 || dwLow >= dwHigh || dwHigh >= s_cP2PmsgMAX )
      EVERR->MODULE
           ->AFP(dwHigh)->AFP(dwLow)
           ->Message("Backpressure marks must satisfy 0 < low < high < %lu"
                    , (unsigned long)s_cP2PmsgMAX )
           ->Advice ("Refer SetP2PmsgBudgetMarks()" )
           ->Throw  ( );
    s_cP2PmsgHIGH = dwHigh;
    s_cP2PmsgLOW  = dwLow;
}

DWORD GetP2PmsgBudgetHigh ( ) { return s_cP2PmsgHIGH; }
DWORD GetP2PmsgBudgetLow  ( ) { return s_cP2PmsgLOW;  }
DWORD GetP2PmsgBudgetMax  ( ) { return s_cP2PmsgMAX;  }

//
//  Is the budget under pressure, and has it recovered?
//  NOTES: Deliberately NOT the negation of each other - between the two marks
//         both are false, which is the hysteresis band: a connection already
//         holding keeps holding, and one already reading keeps reading
bool P2PmsgBudgetPressed  ( ) { return s_cP2Pmsg >= s_cP2PmsgHIGH; }
bool P2PmsgBudgetRelieved ( ) { return s_cP2Pmsg <= s_cP2PmsgLOW;  }

DWORD GetP2PmsgHeldCount  ( ) { return s_cP2PmsgHeld; }
void  BumpP2PmsgHeldCount ( ) { s_cP2PmsgHeld++;      }
typedef struct
{
    //  OWNS its address; it used to be a borrowed P2PaddrSTR (F-S5-2).
    //  A P2Pmsg is QUEUED and dispatched on another thread, so a pointer
    //  stored here outlives whatever produced it. Both suppliers are unsafe:
    //  P2PeerExpump::PostP2PeerCon passed a LOCAL P2Paddr (destroyed at its
    //  return, while the queue entry still pointed into its CString), and
    //  GetSource() below returns c_wstr(), which off Win32 is a slot in a
    //  16-slot THREAD-LOCAL ring belonging to the posting thread.
    //  Owning it makes every assignment a copy and ends the class of defect
    //  rather than the one instance ASan happened to catch.
    CString     strP2Paddr;            // Identifies P2PeerCon object
                                       //   from which P2Pmsg originated
    P2Pmsg_t    nMsg;                  // Message identification
    P2PmsgCN    nCode;
    P2Peerio   *pPeerio;
    P2PeerCon  *pCon;
    P2PeerMsg  *pMsg;
    P2Pevent   *pEvent;
    void       *pTarget;
    P3PmsgItem *pP3PmsgItem;
    //P3PmsgNode *pP3PmsgNode;
    void       *pExtra;                // Extra information 
    DWORD       nHubThreadID;
    HANDLE      hEventHub;
    bool        bNotify;
  __int64       iPitime;
    UINT        iPitimeID;
    WPARAM      wParam;
    LPARAM      lParam;
    DWORD      dwUserKey;
} P2Pmsg;

P2Pmsg*
P2PmsgFactory ( )
{
    // Manufacture
    //  new P2Pmsg() and NOT ZeroMemory: strP2Paddr is a CString now, and a
    //  bulk wipe over a constructed std::wstring loses its heap pointer.
    //  Value-initialisation zeroes every POD member first and then runs the
    //  implicit default constructor, so the scalars keep the guarantee the
    //  ZeroMemory gave them.
    P2Pmsg *pP2Pmsg = new P2Pmsg();
    s_cP2Pmsg++;
    return  pP2Pmsg;
}

bool
VerifyP2Pmsg ( P2Pmsg *pP2Pmsg )
{
    // Addressing
    ASSERT ( !pP2Pmsg ||
              AfxIsValidAddress(pP2Pmsg,sizeof(P2Pmsg),true) );
    ASSERT ( !pP2Pmsg ||
             !pP2Pmsg->pCon ||
              AfxIsValidAddress(pP2Pmsg->pCon,sizeof(P2PeerCon),true) );

    // P2PeerMsg
    if ( pP2Pmsg       &&
         pP2Pmsg->pMsg    )
      pP2Pmsg -> pMsg -> AssertValid ( );

    // P2PeerCon
    if ( pP2Pmsg       &&
         pP2Pmsg->pCon    )
      pP2Pmsg -> pCon -> AssertValid ( );

    // P2PeerTarget
    P2PeerTarget *pTarget =  reinterpret_cast<P2PeerTarget*>(pP2Pmsg->pTarget);
    if ( pP2Pmsg ) {
      ASSERT(pTarget);
      ((P2PeerTarget*)pP2Pmsg->pTarget)->P2PeerTarget::AssertValid();
    }

    // Done
    return true;
}

//  P2Pmsg context
//  NOTES: Exchanged privately between static functions in the
//         P2PeerAPI
//       : In addition some helpful thread context management
//         definitions
typedef struct
{
    HWND          hWnd;                // Destination 
    UINT          nWM_APP;             // WM_APP domain message
    DWORD         nThreadID;           // Thread identifier
    P2PeerTarget *pTarget;             // Implementation target
    P2PeerCon    *pCon;
    P2PeerMsg    *pMsg;
} P2Pmsg_Context;
typedef P2PSafePtr<P2Pmsg_Context> P2Pmsg_ContextSP;

//
//  P2PmsgHub handle
typedef struct P2PmsgHub
{
    HANDLE         hFile;
    HANDLE         hIOCP;
    //P2PeerCon_e   eP2PeerCon;
    P2PeerCon     *pConThis;
    P2PeerCon     *pConThat;
    OVERLAPPEDcon *pOVERLAPPEDrecv;
    char          *pBufferRecv;
    DWORD          nBytesRecv;
    OVERLAPPEDcon *pOVERLAPPEDsend;
    char          *pBufferSend;
    DWORD          nBytesSend;
    OVERLAPPEDcon *pOVERLAPPEDaccept;
    UINT_PTR       uCompletionKey;
    P2PmsgHub     *hThat;
} P2PmsgHub;

typedef P2PSafePtr<P2PeerCon> P2PeerConSP;
///////////////////////////////////////////////////////////////////////
//  SafeCon
//  NOTES: Optimised for and targeted to P2PeerCon life cycle
//         management.  Internal private operations
/*class SafeCon
{
    // Constructors and destructor
    public:
        SafeCon ( P2PeerCon *pCon )
        {
          m_pCon     = pCon;
          m_cRef     = 0;
          m_bDestroy = false;
          m_pCon -> m_hP2PmsgCon = (HANDLE)this;
        }
      virtual
       ~SafeCon ( ) { delete m_pCon; };

    // Life cycle management
    public:
      UINT
        AddRef ( ) { return ++m_cRef; }
      UINT
        Release ( )
        {
          int cRef = --m_cRef;
          ASSERT(cRef>=0);
          if ( m_cRef <= 0 && m_bDestroy )
            delete this;
          return cRef;
        }
      UINT
        Destroy ( ) { m_bDestroy = true; return m_cRef; }
      bool
        PostDestroyState ( ) { return m_bDestroy && m_cRef <= 0; }

    // Operators
    public:
      operator P2PeerCon* ( ) { return m_pCon; }

    // Attributes
    protected:
      P2PeerCon *m_pCon;
      int        m_cRef;
      bool       m_bDestroy;
};
#define SafeConPtr(pCon) ((SafeCon*)pCon->m_hP2PmsgCon)*/

///////////////////////////////////////////////////////////////////////
//  P2PmsgPump
//  NOTES: Manages FIFO lists of P2Pmsg objects.  Strict P2Pmsg
//         ordering must be maintained

static
CRITICAL_SECTION s_oCSectionP2Pmsg;
static
bool             s_bCSectionP2Pmsg = false;
static
UINT             s_uPitimeID = 0;
static
bool             m_bP2PmsgExplorer_Pump = false;

class  P2PmsgHubMgr;
class  P2PmsgPump;
static CMap<DWORD_PTR, DWORD_PTR, P2PmsgPump*, P2PmsgPump*> s_ThreadID_P2PmsgPump;
static CRITICAL_SECTION                                     s_oCSectionP2PmsgPump;

CMap<DWORD_PTR,DWORD_PTR,P2PmsgHubID,P2PmsgHubID> s_P2PmsgCon_HubID;
CMap<DWORD_PTR,DWORD_PTR,P2PmsgHubID,P2PmsgHubID> s_P2PexpCon_HubID;
P2Pmsg* ReleaseP2Pmsg ( P2Pmsg *pP2Pmsg );   // Fwd decl: defined below, used by ~P2PmsgPump()
class P2PmsgPump
{
    // Constructors and destructor
    public:
        P2PmsgPump ( )
        {
          m_pQuePrev         = 0;
          m_pQueNext         = 0;
          m_hQueEvent        = 0;
          m_bOwnQueEvent     = false;   // F-S5-4: set by whoever creates it
          m_bWakePosted      = false;   // W2: no wake outstanding at construction
          m_nThreadId        = GetCurrentThreadId();
          m_nHubID           = 0;
          m_nPumpID          = GetCurrentThreadId();
          m_pP2Pmsg          = 0;
          m_hIOCP            = 0;
          m_pOVERLAPPED      = 0;
          m_hP2PmsgHubListen = 0;
          m_nPitimeID        = 0;
          m_pP2Pmsg          = 0;
          m_oP2Paddr         = L"";
          m_bListen          = 0;
          m_pTarget          = 0;
          m_pContext         = 0;
          m_bRedirect        = false;
          m_bRepump          = false;
          m_nID              = 0;
          m_wProps           = 0;
          m_bP2Pexplorer     = false;
          m_dwExpumpMask     = 0;
          m_pP2PmsgHubMgr    = 0;
          s_ThreadID_P2PmsgPump.SetAt( m_nThreadId, this );
          InitializeCriticalSection  ( &m_oCSection );
        };
       ~P2PmsgPump ( )
        {
          /*if ( m_pQuePrev )
            m_pQuePrev->m_pQueNext = m_pQueNext;
          if ( m_pQueNext )
            m_pQueNext->m_pQuePrev = m_pQuePrev;

          // Optimisation
          if ( s_pQueLast == this )
          {
            if ( m_pQueNext )
              s_pQueLast = m_pQueNext;
            else if ( m_pQuePrev )
              s_pQueLast = m_pQuePrev;
            else
              s_pQueLast = 0;
          }*/
          // Garbage
          if ( m_pContext )
            delete m_pContext;

          // Drain any P2Pmsg's still queued at teardown
          // NOTES: Undispatched messages (e.g. CN_P2PeerSnc sink notifications
          //        with pCon==0, which FlushP2Pmsg() deliberately re-queues)
          //        would otherwise leak - along with their pP3PmsgItem - when
          //        the pump is destroyed.  These are owned by the pump and were
          //        never dispatched, so releasing them here cannot double-free.
          while ( m_oCListP2Pmsg.GetCount() )
            ReleaseP2Pmsg ( m_oCListP2Pmsg.RemoveHead() );
          while ( m_oCListP2PmsgPit.GetCount() )
            ReleaseP2Pmsg ( m_oCListP2PmsgPit.RemoveHead() );

          // Resources
          DeleteCriticalSection ( &m_oCSection );
          if ( m_hIOCP )
            CloseHandle ( m_hIOCP );
          //  F-S5-4.  The queue event was created here and was never closed
          //  anywhere - CreateP2Pexpump() and CreateP2PmsgPump() both make one
          //  and only m_hIOCP two lines up was ever given back.  On Windows
          //  that is a kernel handle per pump for the life of the process; on
          //  Linux the shim's HANDLE is a heap object plus an eventfd, which
          //  is what LSan reports.  Ownership-gated - see m_bOwnQueEvent.
          if ( m_bOwnQueEvent && m_hQueEvent )
            CloseHandle ( m_hQueEvent );
          if ( m_pOVERLAPPED )
            delete m_pOVERLAPPED;
          s_ThreadID_P2PmsgPump.RemoveKey ( m_nThreadId );
        };
      void
        Verify ( )
        {
          POSITION pos;
          pos = m_oCListP2PmsgPit.GetHeadPosition();
          while ( pos )
            VerifyP2Pmsg ( m_oCListP2PmsgPit.GetNext(pos) );
          pos = m_oCListP2Pmsg.GetHeadPosition();
          while ( pos )
            VerifyP2Pmsg ( m_oCListP2Pmsg.GetNext(pos) );
        }

    // Patterns
    public:
      static P2PmsgPump*
        GetHead ( )
        {
          while ( s_pQueLast             &&
                  s_pQueLast->m_pQuePrev    )
            s_pQueLast = s_pQueLast->m_pQuePrev;
          return s_pQueLast;
        }
      static P2PmsgPump*
        GetP2PmsgPump ( P2PumpID nPumpID = 0 )
        {
          // Introduce locals
          if ( nPumpID == 0 )
            nPumpID = GetCurrentThreadId ( );
          P2PmsgPump *pP2PmsgPump = 0;

          // Implementation
          s_ThreadID_P2PmsgPump.Lookup ( nPumpID, pP2PmsgPump );
          return pP2PmsgPump;
        };
      static P2PmsgPump*
        GetP2PmsgHub ( P2Paddr oP2Paddr )
        {
          // To be sure, to be sure
          if ( !s_pQueLast          ||
                  oP2Paddr.IsNull()    )
            return 0;

          // Reset to first in list
          P2PmsgPump *pP2PmsgPump = s_pQueLast;
          while ( pP2PmsgPump->m_pQuePrev )
            pP2PmsgPump = pP2PmsgPump->m_pQuePrev;

          // Search
          while ( pP2PmsgPump )
          {
            if ( pP2PmsgPump->m_hP2PmsgHubListen                     &&
                 pP2PmsgPump->m_pTarget->GetP2PaddrHub() == oP2Paddr    )
              return pP2PmsgPump;
            pP2PmsgPump = pP2PmsgPump -> m_pQueNext;
          }

          // Not found
          return pP2PmsgPump;
        };
      static P2PmsgPump*
        Factory ( HANDLE hEventPump, P2PeerTarget *pTarget )
        {
          P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
          P2PmsgPump *pQue = new P2PmsgPump ( );
                      pQue -> m_pTarget   = pTarget;
                      pQue -> m_hQueEvent = hEventPump;
                      pQue -> m_nThreadId = GetCurrentThreadId();

          // Backwards positioning
          while ( s_pQueLast                                  &&
                  s_pQueLast->m_pQuePrev                      &&
                  s_pQueLast->m_nThreadId > pQue->m_nThreadId    )
            s_pQueLast = s_pQueLast->m_pQuePrev;

          // Forewards positioning
          while ( s_pQueLast                                  &&
                  s_pQueLast->m_pQueNext                      &&
                  s_pQueLast->m_nThreadId < pQue->m_nThreadId    )
            s_pQueLast = s_pQueLast->m_pQueNext;

          // Linkage
          if ( !s_pQueLast )
            s_pQueLast = pQue;

          // Linkage
          else if ( pQue->m_nThreadId < s_pQueLast->m_nThreadId )
          {
              pQue    -> m_pQueNext = s_pQueLast;
              pQue    -> m_pQuePrev = s_pQueLast->m_pQuePrev;
            s_pQueLast-> m_pQuePrev = pQue;
            if ( pQue->m_pQuePrev )
              pQue    -> m_pQuePrev -> m_pQueNext = pQue;
if(pQue&&pQue->m_pQuePrev)
ASSERT(pQue->m_nThreadId>pQue->m_pQuePrev->m_nThreadId);
if(pQue&&pQue->m_pQueNext)
ASSERT(pQue->m_nThreadId<pQue->m_pQueNext->m_nThreadId);
          }

          // Linkage
          else if ( pQue->m_nThreadId > s_pQueLast->m_nThreadId )
          {
              pQue    -> m_pQuePrev = s_pQueLast;
              pQue    -> m_pQueNext = s_pQueLast->m_pQueNext;
            s_pQueLast-> m_pQueNext = pQue;
            if ( pQue->m_pQueNext )
              pQue    -> m_pQueNext -> m_pQuePrev = pQue;
if(pQue&&pQue->m_pQuePrev)
ASSERT(pQue->m_nThreadId>pQue->m_pQuePrev->m_nThreadId);
if(pQue&&pQue->m_pQueNext)
ASSERT(pQue->m_nThreadId<pQue->m_pQueNext->m_nThreadId);
          }
          else
            pQue=pQue;

          // Tidy up, and
          return pQue;
        };
    // Operations
    public:
      P2Pmsg*
        GetP2Pmsg ( )
        { if ( m_oCListP2Pmsg.GetCount() )
            return m_pP2Pmsg = m_oCListP2Pmsg.RemoveHead();
          return m_pP2Pmsg = 0;
        };
      UINT
        PutP2Pmsg ( P2Pmsg *pP2Pmsg, bool bPrepend )
        {
ASSERT(VerifyP2Pmsg(pP2Pmsg));
auto *pTarget = reinterpret_cast<P2PeerTarget *>(pP2Pmsg->pTarget);
pTarget->P2PeerTarget::AssertValid();
auto *pTarget2 = (P2PeerTarget *)pP2Pmsg->pTarget;
pTarget2->P2PeerTarget::AssertValid();
          if ( pP2Pmsg )               // Skip NULL pointers
          {
            VerifyP2Pmsg ( pP2Pmsg );
            if ( pP2Pmsg->pTarget == nullptr )
              pP2Pmsg -> pTarget = m_pTarget;
            if ( bPrepend )
              m_oCListP2Pmsg.AddHead ( pP2Pmsg );
            else
              m_oCListP2Pmsg.AddTail ( pP2Pmsg );

            if ( !pP2Pmsg->nHubThreadID )
              pP2Pmsg->nHubThreadID = m_nThreadId;
            if ( !pP2Pmsg->hEventHub )
              pP2Pmsg->hEventHub    = m_hQueEvent;
          }
          // Wake the pump only when the producer is a DIFFERENT thread.  When
          // this pump posts to its own FIFO (e.g. the recv path parsing an
          // inbound frame and re-posting it as a P2Pmsg), the pump is already
          // running and will pick the message up on its next loop iteration -
          // so the PostQueuedCompletionStatus + the spurious key=0 completion
          // it drains are pure per-message overhead on the hot path.  Passing
          // m_nThreadId (was the ~0 sentinel, which never matched and defeated
          // the same-thread guard in Wakeup()) restores that elision.
          //
          // W2 (p2p_PumpPerf.md) - wake coalescing: only signal the pump on the
          // FIRST post since it last drained to empty.  While m_bWakePosted is
          // TRUE the pump either is running or has an outstanding completion, so
          // it will pick this message up on a subsequent GetP2Pmsg() without a
          // fresh wake.  The pump clears m_bWakePosted the moment it observes an
          // empty FIFO (see PumpP2Pmsg), and this producer holds m_oCSection, so
          // any post that races the pump's drain-to-empty re-arms the wake.
          if ( !m_bWakePosted )
          {
            m_bWakePosted = true;
            Wakeup ( m_nThreadId );   // self-elides when producer == pump thread
          }
          //VerifyP2Pmsg ( pP2Pmsg ); problems because pP2Pmsg may no longer exist
          return (UINT)m_oCListP2Pmsg.GetCount();
        };
      BOOL
        Wakeup ( DWORD nP2PumpID )
        {
          if ( nP2PumpID == GetCurrentThreadId() )
            return TRUE;
          if ( m_hIOCP )
            PostQueuedCompletionStatus( m_hIOCP, 0, 0, m_pOVERLAPPED );
          else if ( m_hQueEvent )
            return SetEvent ( m_hQueEvent );
          return FALSE;
        }

    // Timers
    public:
      UINT
        MakeTimerID ( )
        {
TOP:      UINT     uiPitimerID = m_nThreadId*0x100+m_nPitimeID++;
          POSITION   pos = m_oCListP2PmsgPit.GetHeadPosition();
          while ( pos )
          {
            P2Pmsg *pP2Pmsg = m_oCListP2PmsgPit.GetNext(pos);
            if ( pP2Pmsg->iPitimeID == uiPitimerID )
              goto TOP;
          }
          s_uPitimeID++;
          return uiPitimerID;
        }
      UINT
        SetTimer ( P2Pmsg *pP2Pmsg )
        {
          pP2Pmsg -> iPitimeID = MakeTimerID();
          POSITION pos = m_oCListP2PmsgPit.GetTailPosition();
          while ( pos )
          {
            if ( m_oCListP2PmsgPit.GetPrev(pos)->iPitime
                                          <= pP2Pmsg->iPitime )
            {
              m_oCListP2PmsgPit.InsertAfter ( pos, pP2Pmsg );
              return pP2Pmsg->iPitimeID;
            }
          };
          m_oCListP2PmsgPit.AddHead ( pP2Pmsg );
          return pP2Pmsg->iPitimeID;
        }
      P2Pmsg*
        KillTimer ( UINT uPitimerID )
        {
          P2Pmsg  *pP2Pmsg = 0; 
          POSITION     pos = m_oCListP2PmsgPit.GetHeadPosition();
          POSITION     posKill;
          while ( pos )
          {
            posKill = pos;
            pP2Pmsg = m_oCListP2PmsgPit.GetNext(pos);
            if ( pP2Pmsg->iPitimeID != uPitimerID )
              continue;
            m_oCListP2PmsgPit.RemoveAt ( posKill );
            return pP2Pmsg;            // Killed
          }
          return 0;                    // Not located
        }
    __int64
        PollTimer ( )
        {
          if ( m_oCListP2PmsgPit.IsEmpty() )
            return 0xFFFFFFFF;
          return m_oCListP2PmsgPit.GetHead()->iPitime - _time64(0)*1000;
        }
      P2Pmsg*
        GetTimer ( )
        {
          return m_oCListP2PmsgPit.RemoveHead();
        }

    // Properties
    public:
      UINT
        GetCount ( )
        { return (UINT)m_oCListP2Pmsg.GetCount(); };
      BOOL
        IsPitEmpty ( )
        { return m_oCListP2PmsgPit.IsEmpty(); };
      BOOL
        IsQueEmpty ( )
        { return m_oCListP2Pmsg.IsEmpty(); };
      // Signal-queue accessors (TSan Risk #3): m_oCListP2PsigID is written by
      // SignalP2PmsgHub / SignalP2PmsgPump on ANY thread under m_oCSection, so the pump
      // thread's own reads/pops must take the same lock (they raced under TSan otherwise).
      UINT
        SigCount ( )
        { P2PsafeCS oSafeCS = m_oCSection; return (UINT)m_oCListP2PsigID.GetCount(); }
      P2PsigID
        SigPop ( )
        { P2PsafeCS oSafeCS = m_oCSection;
          return m_oCListP2PsigID.GetCount() > 0 ? m_oCListP2PsigID.RemoveHead() : 0; }

    // Attributes
    public:
      CRITICAL_SECTION m_oCSection;
      HANDLE           m_hIOCP;
      P2PmsgHubID      m_nHubID;
      P2PumpID         m_nID;
      P2PumpID         m_nPumpID;
      P2Paddr          m_oP2Paddr;
      DWORD            m_wProps;
      CStringADDR      m_csName;
      CStringADDR      m_strFunc;
      P2PmsgHub       *m_hP2PmsgHubListen;
      bool             m_bListen;
      // W2 (p2p_PumpPerf.md) - wake coalescing.  TRUE once a cross-thread
      // producer has signalled this pump and it has not yet drained its FIFO
      // to empty; suppresses redundant PostQueuedCompletionStatus/SetEvent
      // wakes (and the spurious key==0 completions the pump would drain) for
      // the 2nd..Nth message of a burst.  Guarded by m_oCSection (all
      // PutP2Pmsg producers and the pump's empty-observation hold it), so a
      // plain bool is race-free.  Cleared by the pump the instant it observes
      // an empty FIFO (i.e. just before it may park in GetQueuedCompletion
      // Status), so any later producer - which must take m_oCSection strictly
      // afterwards - always re-arms the wake: no lost-wake window.
      bool             m_bWakePosted;
      OVERLAPPED      *m_pOVERLAPPED;
      HANDLE           m_hQueEvent;
      //  F-S5-4.  TRUE when this pump CREATED m_hQueEvent and must therefore
      //  close it, FALSE when the handle was handed in from outside and is
      //  somebody else's to close.  The distinction is not decorative: the one
      //  external supplier is Factory(hEventPump,...) via StartupP2Pmsg(), so
      //  an unconditional CloseHandle() here would be a double close on a
      //  handle the caller still owns.  m_hIOCP next to it needs no flag
      //  because the pump is the only thing that ever creates one.
      bool             m_bOwnQueEvent;
      DWORD            m_nThreadId;
      P2PeerTarget    *m_pTarget;
      P2PmsgPump      *m_pQuePrev;
      P2PmsgPump      *m_pQueNext;
      USHORT           m_nPitimeID;
      P2Pmsg_Context  *m_pContext;
      bool             m_bRedirect;
      bool             m_bRepump;
      bool             m_bP2Pexplorer;
      DWORD            m_dwExpumpMask;
      static
      P2PmsgPump      *s_pQueLast;
      P2PmsgHubMgr    *m_pP2PmsgHubMgr;

      P2Pmsg          *m_pP2Pmsg;
      CList<P2Pmsg*>   m_oCListP2Pmsg;
      CList<P2Pmsg*>   m_oCListP2PmsgPit;
      CList<P2PsigID>  m_oCListP2PsigID;
};
typedef P2PSafePtr<P2PmsgPump> SP2PmsgPump;

P2PmsgPump*
P2PmsgPump::s_pQueLast = 0;

///////////////////////////////////////////////////////////////////////////////
//  P2PmsgSink's
//  NOTES: Manage the manufacture, translation, dispatch and
//         life cycle of internal P2PmsgSinks's
typedef struct
{
    P2PmsgSinkID   nSinkID;            // Sink identification code
    P2PsysID       nSysID;             // Sys  identification code
    HWND           hWnd;               // Registered window, or
    DWORD          nThreadID;          //            thread, or
    P2PumpID       nPumpID;            //            P2Pump, or
    P2PeventCBFnc  pP2PeventCBFnc;     //            callback

    P2PeerTarget  *pTarget;            // Nominated P2PeerTarget
    DWORD         dwCBKey;             // Call back key
    DWORD         dwNotifications;     // Registered Notifications.
} P2PmsgSinkReg;
typedef std::list<P2PmsgSinkReg*> P2PmsgSinkReg_list;
typedef std::pair<P2PmsgSinkReg*, P2PmsgSinkReg*> P2PmsgSinkReg_pair;
BOOL
CleanupP2PmsgSink ( P2PmsgHubMgr *pP2PmsgHub );
BOOL
StartupP2PmsgSink ( );

class P2PmsgSink
{
    // Constructors and destructor
    public:
        P2PmsgSink ( UINT nSinkID )
        {
          m_nSinkID = nSinkID;
          InitializeCriticalSection  ( &m_oCSection );
        };
       ~P2PmsgSink ( )
        {
          P2PmsgSinkReg_list::iterator  it;
          for ( it = m_oP2PmsgSinkReglist.begin(); it != m_oP2PmsgSinkReglist.end(); ++it )
            delete (*it);
          m_oP2PmsgSinkReglist.clear();
          /*if ( m_pQuePrev )
            m_pQuePrev->m_pQueNext = m_pQueNext;
          if ( m_pQueNext )
            m_pQueNext->m_pQuePrev = m_pQuePrev;

          // Optimisation
          if ( s_pQueLast == this )
          {
            if ( m_pQueNext )
              s_pQueLast = m_pQueNext;
            else if ( m_pQuePrev )
              s_pQueLast = m_pQuePrev;
            else
              s_pQueLast = 0;
          }*/
          // Resources
          DeleteCriticalSection ( &m_oCSection );
        };
      void
        Verify ( )
        {
        }
    // Registrations
    public:
      P2PmsgSinkReg*
        RegisterTarget ( P2PeerTarget *pTarget, P2PsysID nP2PsysID )
        {
          P2PmsgSinkReg                *pP2PmsgSinkReg = nullptr;
          P2PmsgSinkReg_list::iterator  it;
          for ( it = m_oP2PmsgSinkReglist.begin(); it != m_oP2PmsgSinkReglist.end(); ++it )
          {
            pP2PmsgSinkReg = *it;
            if ( pP2PmsgSinkReg->pTarget == pTarget   &&
                 pP2PmsgSinkReg->nSysID  == nP2PsysID    )
              return pP2PmsgSinkReg;
          }
          pP2PmsgSinkReg = new P2PmsgSinkReg;
          ZeroMemory ( pP2PmsgSinkReg, sizeof(P2PmsgSinkReg) );
          pP2PmsgSinkReg -> pTarget = pTarget;
          pP2PmsgSinkReg -> nSysID  = nP2PsysID;
          m_oP2PmsgSinkReglist.push_back ( pP2PmsgSinkReg );
          return pP2PmsgSinkReg;
        }
      BOOL
        CancelTarget ( P2PeerTarget *pTarget, P2PsysID nP2PsysID )
        {
          int                           nItems         = 0;
          P2PmsgSinkReg                *pP2PmsgSinkReg = nullptr;
          P2PmsgSinkReg_list::iterator  it;
          for ( it = m_oP2PmsgSinkReglist.begin(); it != m_oP2PmsgSinkReglist.end(); )
          {
            pP2PmsgSinkReg = *it;
            if ( pTarget                            &&
                 pP2PmsgSinkReg->pTarget != pTarget    )
              { ++it; continue; }
            if ( nP2PsysID                           &&
                 nP2PsysID != pP2PmsgSinkReg->nSysID    )
              { ++it; continue; }
            delete pP2PmsgSinkReg;
            it = m_oP2PmsgSinkReglist.erase(it);
            nItems++;
          }
          return nItems;
        }
    // Properties
    public:
      UINT
        GetCount ( )
        { return (UINT)m_oP2PmsgSinkReglist.size(); };

    // Attributes
    public:
      CRITICAL_SECTION    m_oCSection;
      P2PmsgSinkID        m_nSinkID;        // Sink identification code
      CString             m_strSinkname;
      P2PmsgSinkReg_list  m_oP2PmsgSinkReglist;
      //HWND           hWnd;               // Registered window, or
      //DWORD          nThreadID;          //            thread, or
      //P2PumpID       nPumpID;            //            P2Pump, or
      //P2PeventCBFnc  pP2PeventCBFnc;     //            callback

      //P2PeerTarget  *pTarget;            // Nominated P2PeerTarget
      //DWORD         dwCBKey;             // Call back key
      //DWORD         dwNotifications;     // Registered Notifications.
};

typedef std::map <P2PmsgSinkID, P2PmsgSink*> P2PmsgSinkmap;
typedef std::pair<P2PmsgSinkID, P2PmsgSink*> P2PmsgSinkpair;
//static P2PmsgSinkIDmap  s_oP2PmsgSinkIDmap;
static CRITICAL_SECTION s_oCSectionP2PmsgSink;
static bool             s_bStartupP2PmsgSink   = false;

///////////////////////////////////////////////////////////////////////
//  P2PmsgHubMgr
//  NOTES: Manages CList of P2PmsgPump's
//       : Single P2PmsgHub per Win32 thread context

static CMap<DWORD,DWORD,P2PmsgHubMgr*,P2PmsgHubMgr*> s_ThreadID_P2PmsgHub;
static CRITICAL_SECTION                              s_oCSectionP2PmsgHub;
static bool m_bP2PmsgExplorer_Hub = false;
class P2PmsgPumpMgr;
class P2PmsgHubMgr
{
    // Constructors and destructor
    public:
        P2PmsgHubMgr ( )
        {
          m_hIOCP            = 0;
          m_pOVERLAPPED      = 0;
          m_oP2Paddr         = L"";
          m_pHub             = 0;
          m_nHubID           = GetCurrentThreadId();
          m_bP2PmsgExplorer  = false;
          m_pP2Pexplorer     = 0;
          m_pP2PmsgSinkmap   = 0;
          m_nSinksMax        = 255;
          s_ThreadID_P2PmsgHub.SetAt ( m_nHubID, this );
          InitializeCriticalSection  ( &m_oCSection );
        };
       ~P2PmsgHubMgr ( )
        {
          // Resources
          if ( m_hIOCP )
            CloseHandle ( m_hIOCP );
          if ( m_pOVERLAPPED )
            delete m_pOVERLAPPED;
          CleanupP2PmsgSink ( this );
          s_ThreadID_P2PmsgHub.RemoveKey ( m_nHubID );
          ASSERT(m_pP2PmsgSinkmap==nullptr);
          // Delete the pump object(s) tracked in m_oCListP2PmsgPump (the msg pump, plus
          // the explorer pump if one was created). ~P2PmsgPump closes each pump's
          // completion port (m_hIOCP) and unregisters it from s_ThreadID_P2PmsgPump;
          // m_apP2PmsgPump below owns only the pointer-storage array, not the objects.
          // Without this the pump leaked once per hub, taking its Linux io_uring ring
          // (an fd + pinned SQ/CQ memory) with it, so a few hundred hub create/destroy
          // cycles exhausted RLIMIT_MEMLOCK and the next CreateIoCompletionPort() failed
          // with ENOMEM (surfaced by the Phase-5 teardown stress under ASan). No other
          // code deletes pumps, so this cannot double-free.
          while ( m_oCListP2PmsgPump.GetCount() )
            delete m_oCListP2PmsgPump.RemoveHead();
          if ( m_apP2PmsgPump )
            delete [] m_apP2PmsgPump;
          // Match the ctor's InitializeCriticalSection ( &m_oCSection ). ~P2PmsgPump
          // already deletes its own m_oCSection; the hub's was leaked every teardown
          // (a fixed handle on Windows; on Linux the CRITICAL_SECTION shim's
          // recursive_mutex, flagged by the Phase-5 teardown stress under ASan). All
          // pump threads are joined by CloseHub before the hub destructs, so nothing
          // still holds this section.
          DeleteCriticalSection ( &m_oCSection );
          //if ( m_pP2PmsgSinkmap )
          //{
          //  P2PmsgSinkmap::iterator it;
          //  for ( it = m_pP2PmsgSinkmap->begin(); it != m_pP2PmsgSinkmap->end(); )
          //    delete it -> second;
          //  delete m_pP2PmsgSinkmap;
          //}
        };
      void
        Verify ( )
        {
        }

    // Pumps
    public:
      P2PmsgPump*
        CreateP2PmsgPump ( )
        {
          P2PmsgPump *pP2PmsgPump  =  new P2PmsgPump ( );
          pP2PmsgPump -> m_bP2Pexplorer  = false;
          pP2PmsgPump -> m_nHubID        = m_nHubID;
          pP2PmsgPump -> m_pTarget = dynamic_cast<P2PeerTarget *>(m_pHub);
          pP2PmsgPump -> m_pP2PmsgHubMgr = this;
          m_oCListP2PmsgPump.AddTail ( pP2PmsgPump );
          return pP2PmsgPump;
        }
      P2PmsgPump*
        CreateP2Pexplorer ( )
        {
          ASSERT(!m_pP2Pexplorer);
          m_pP2Pexplorer =  new P2PmsgPump ( );
          m_pP2Pexplorer -> m_bP2Pexplorer  = true;
          m_pP2Pexplorer -> m_nHubID        = m_nHubID;
          m_pP2Pexplorer -> m_pTarget = dynamic_cast<P2PeerTarget *>(m_pHub);
          m_pP2Pexplorer -> m_pP2PmsgHubMgr = this;
          m_oCListP2PmsgPump.AddTail ( m_pP2Pexplorer );
          return m_pP2Pexplorer;
        }
      P2PmsgSink*
        CreateP2PmsgSink ( LPCTNAM lpszSinkname )
        { 
          if ( m_pP2PmsgSinkmap == nullptr )
            m_pP2PmsgSinkmap = new P2PmsgSinkmap();
          LOP:P2PmsgSinkID nSinkID = (UINT)rand() & (UINT)rand();
          if ( nSinkID == 0 || m_pP2PmsgSinkmap->find(nSinkID) != m_pP2PmsgSinkmap->end() )
            goto LOP;
          P2PmsgSink *pP2PmsgSink = new P2PmsgSink ( nSinkID );
                      pP2PmsgSink -> m_strSinkname = lpszSinkname;
          P2PmsgSinkpair pair(nSinkID,pP2PmsgSink);
          m_pP2PmsgSinkmap -> insert(pair);
          return pP2PmsgSink;
        }
      void
        RemoveP2PmsgPump ( P2PmsgPump *pP2PmsgPump )
        {
          ASSERT(!pP2PmsgPump->m_bP2Pexplorer);
          POSITION pos = m_oCListP2PmsgPump.GetHeadPosition();
          while ( pos )
          {
            POSITION posDrop = pos;
            if ( pP2PmsgPump != m_oCListP2PmsgPump.GetNext(pos) )
              continue;
            m_oCListP2PmsgPump.RemoveAt ( posDrop );
            pos = 0;
          }
        }
      void
        RemoveP2Pexplorer ( P2PmsgPump *pP2Pexplorer )
        {
          ASSERT(m_pP2Pexplorer==pP2Pexplorer);
          m_pP2Pexplorer = 0;
          //P2PmsgPump *pP2PmsgPump;
          POSITION pos = m_oCListP2PmsgPump.GetHeadPosition();
          while ( pos )
          {
            POSITION posDrop = pos;
            if ( pP2Pexplorer != m_oCListP2PmsgPump.GetNext(pos) )
              continue;
            m_oCListP2PmsgPump.RemoveAt ( posDrop );
            pos = 0;
          }
        }
      void
        RemoveP2PmsgSink ( P2PmsgSink *pP2PmsgSink )
        {
          P2PmsgSinkmap::iterator it;
          for ( it = m_pP2PmsgSinkmap->begin(); it != m_pP2PmsgSinkmap->end(); )
          {
            if ( it->second == pP2PmsgSink )
            {
              delete it->second;
              it = m_pP2PmsgSinkmap->erase(it);
            } else ++it;
          }
        }

    // Patterns
    public:
      static P2PmsgHubMgr*
        Factory ( UINT nPumpsMax )
        {
          P2PsafeCS oSafeCS = s_oCSectionP2PmsgHub;
          P2PmsgHubMgr *pMgr = new P2PmsgHubMgr ( );
                 pMgr -> m_apP2PmsgPump = new P2PmsgPump* [nPumpsMax+7];
                 ZeroMemory(pMgr->m_apP2PmsgPump,(nPumpsMax+7)*sizeof(P2PmsgPump*));
                 pMgr -> m_nPumpsMax    = nPumpsMax;
                 pMgr -> CreateP2PmsgPump ( );
          return pMgr;
        }
      P2PmsgPump*
        GetP2PmsgPump ( int nP2PumpID )
        {
          if ( nP2PumpID <         0        ||
               nP2PumpID > (int)m_nPumpsMax    )
            return 0;
          return m_apP2PmsgPump[nP2PumpID];
        }
      P2PmsgSink*
        GetP2PmsgSink ( int nSinkID )
        {
          if ( m_pP2PmsgSinkmap == nullptr )
            return nullptr;
          P2PmsgSinkmap::iterator it = m_pP2PmsgSinkmap->find(nSinkID);
          if ( it == m_pP2PmsgSinkmap->end() )
            return nullptr;
          return it->second;
        }
    // Operations
    public:
      void
        PostP2PmsgCon ( P2PeerCon *pCon )
        {
          POSITION pos = m_oCListP2PmsgCon.GetHeadPosition();
          while ( pos )
          {
            if ( pCon == m_oCListP2PmsgCon.GetNext(pos) )
            { ASSERT(0); return; }     // Should never happen
          }
          s_P2PmsgCon_HubID.SetAt ( (DWORD_PTR)pCon, m_nHubID );
          m_oCListP2PmsgCon.AddTail ( pCon );
          pCon -> m_nP2PconID = (P2PconID)m_oCListP2PmsgCon.GetTailPosition();
        }
      void
        PostP2PexpCon ( P2PeerCon *pCon )
        {
          POSITION pos = m_oCListP2PexpCon.GetHeadPosition();
          while ( pos )
          {
            if ( pCon == m_oCListP2PexpCon.GetNext(pos) )
            { ASSERT(0); return; }     // Should never happen
          }
          s_P2PexpCon_HubID.SetAt ( (DWORD_PTR)pCon, m_nHubID );
          m_oCListP2PexpCon.AddTail ( pCon );
          pCon -> m_nP2PconID = (P2PconID)m_oCListP2PexpCon.GetTailPosition();
        }
      void
        DropP2PmsgCon ( P2PeerCon *pCon )
        {
          POSITION pos = m_oCListP2PmsgCon.GetHeadPosition();
          while ( pos )
          {
            POSITION posRemove = pos;
            if ( pCon != m_oCListP2PmsgCon.GetNext(pos) )
              continue;
            m_oCListP2PmsgCon.RemoveAt ( posRemove );
            s_P2PmsgCon_HubID.RemoveKey( (DWORD_PTR)pCon );
            pCon -> m_nP2PconID = 0;
          }
        }
      void
        DropP2PexpCon ( P2PeerCon *pCon )
        {
          POSITION pos = m_oCListP2PexpCon.GetHeadPosition();
          while ( pos )
          {
            POSITION posRemove = pos;
            if ( pCon != m_oCListP2PexpCon.GetNext(pos) )
              continue;
            m_oCListP2PexpCon.RemoveAt ( posRemove );
            s_P2PexpCon_HubID.RemoveKey( (DWORD_PTR)pCon );
            pCon -> m_nP2PconID = 0;
          }
        }
      P2PeerMsg*
        PostP2PmsgExp ( P2PeerMsg *pMsg )
        {
          pMsg -> SetSource ( m_oP2Paddr.c_wstr() );
          P2Pmsg *pP2Pmsg = P2PmsgFactory ( );
          pP2Pmsg -> nCode   = CN_P2PeerMsg | CN_P2PeerExp;
          pP2Pmsg -> nMsg    = P2P_P2Pmsg;//pMsg -> Type();
          pP2Pmsg -> pMsg    = pMsg;
          pP2Pmsg -> pTarget = m_pP2Pexplorer -> m_pTarget;
          m_pP2Pexplorer -> PutP2Pmsg ( pP2Pmsg, false );
          return 0;
        }
      BOOL
        Wakeup ( )
        {
          return FALSE;
        }

    // Timers
    public:

    // Properties
    public:
      P2PmsgPumpMgr*
        GetP2PmsgPumpMgr ( UINT idx );

    // Attributes
    public:
      CRITICAL_SECTION m_oCSection;
      P2PmsgHubID      m_nHubID;
      HANDLE           m_hIOCP;
      P2Paddr          m_oP2Paddr;
      P2Padomain       m_oP2Padomain;
      UINT             m_nPumpsMax;
      UINT             m_nSinksMax;
      P2PmsgPump     **m_apP2PmsgPump;
      OVERLAPPED      *m_pOVERLAPPED;
      P2PeerHub       *m_pHub;
      bool             m_bP2PmsgExplorer;
      P2PmsgSinkmap   *m_pP2PmsgSinkmap;
      CList<P2PmsgPump*> m_oCListP2PmsgPump;
      CList<P2PeerCon*>   m_oCListP2PmsgCon;
      CList<P2PeerCon*>   m_oCListP2PexpCon;
      P2PmsgPump      *m_pP2Pexplorer;
};
typedef P2PSafePtr<P2PmsgHubMgr> SP2PmsgHubMgr;

///////////////////////////////////////////////////////////////////////
//  P2Pexpump notifications
//  NOTES: Post snapshot state observations of P2Pmsg environment
//         for receipt by P2Pexplorer or similar

P2PexpumpID
CreateP2Pexpump ( P2PmsgHubID nHubID, P2PeerTarget *pTarget )
{
    // Locals
    // NOTES: P2PmsgPump environment isolation, keep to completion
    //      : Confirm pump not already associated with this thread
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         pP2PmsgPump                                                       )
      EVERR->MODULE->AFP(nHubID)//TODO->AFPTarget(pTarget)
           ->Message("ThreadID=%i already has P2PmsgPump context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    P2PsafeCS     oSafeCS_Hub = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module ("%s(nHubID=%i,pTarget)", __FUNCTION__
                    , nHubID )
           ->Message("Nominated nHubID=%i does not exist", nHubID )
           ->Throw  ( );
    oSafeCS_Hub = pP2PmsgHub -> m_oCSection;

    // To be sure, to be sure
    if ( pP2PmsgHub->m_pP2Pexplorer )
      EVERR->Module ("%s(nHubID=%i,pTarget)", __FUNCTION__
                    , nHubID )
           ->Message("Nominated nHubID=%i already has P2Pexplorer context" )
           ->Throw  ( );

    // Create P2PmsgPump
    // NOTES: Mandatory for P2PmsgPump to be attached to P2PmsgHub
    P2PmsgPump *pP2Pexpump;
    pP2Pexpump = pP2PmsgHub -> CreateP2Pexplorer ( );
    pP2Pexpump -> m_pTarget   = pTarget;
    pP2Pexpump -> m_hQueEvent = CreateEvent ( 0, FALSE, FALSE, 0 );
    pP2Pexpump -> m_bOwnQueEvent = true;          // F-S5-4: ours to close
    pP2Pexpump -> m_oP2Paddr  = L"Expump";
    pP2Pexpump -> m_csName    = L"Expump";
    pP2Pexpump -> m_strFunc   = L"Anon";
    pP2Pexpump -> m_hIOCP
           = CreateIoCompletionPort ( INVALID_HANDLE_VALUE
                                    , NULL
                                    , 0
                                    , 8 );
    if ( pP2Pexpump->m_hIOCP == 0 )
      EVERR->MODULE->AFP(nHubID)
           ->Message ("CreateIoCompletionPort() failed" )
           ->Advice  ("Internal (SNHappen), P2Pexpump terminating" )
           ->HResult ( GetLastError() )->Throw();

    // Tidy up, and
    return pP2Pexpump->m_nPumpID;
}
//
//  Attributes a drained completion to its owning connection, or to nothing
//  NOTES: For the teardown drains in CloseP2Pexpump() and CloseP2PmsgHub(), which
//         had this attribution written out twice - and so had D33 twice, and
//         would have had its fix once.  A roster in two places is a roster that
//         will differ.
//       : The completion key is the owning connection on Windows.  On Linux
//         CloseHandle(fd) has already erased the io_uring fd->key association by
//         the time the cancellations it triggers complete, so the key comes back
//         zero and the owner is recovered from the OVERLAPPEDcon's pOwnerCon,
//         which MakeOVERLAPPED() set and nothing changes.
//       : NEITHER OF THOSE IS A LIVENESS CLAIM - both are raw addresses recorded
//         when the operation was issued - and this function DELIBERATELY DOES NOT
//         TRY TO MAKE THEM ONE.  Filtering the attribution through the hub's
//         connection list was written, measured, and taken back out: it turns the
//         D33 crash into a LEAK, because a completion whose connection has already
//         retired still owns its OVERLAPPEDcon and that object's buffers, and
//         DrainOVERLAPPED() is the only thing that frees them.  Refusing to drain
//         it strands the lot as an unreferenced cycle - LSan reported 28 blocks,
//         99306 bytes, EVERY ONE OF THEM INDIRECT, i.e. with no live root at all,
//         which is exactly what an object nothing points at any more looks like.
//       : So the fix for D33 is in DrainOVERLAPPED(), where the accounting error
//         was, and NOT here: with the reference balanced a connection cannot
//         retire while completions naming it are still queued, so the stale
//         pointer this guard was written for is not produced in the first place.
//         Guarding the read instead of fixing the write would have hidden the
//         accounting error and paid for it in memory.
//
//
//  Parameters:  ULONG_PTR ulCompletionKey
//               Completion key as delivered; zero on a cancelled Linux op
//
//               OVERLAPPEDcon *pOVERLAPPEDcon
//               The drained completion object
//
//
//  Returns:     P2PeerCon*
//               The owning connection, still live; or 0 to drop the completion
static
P2PeerCon*
DrainConOfOVERLAPPED ( ULONG_PTR      ulCompletionKey
                     , OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // Attribution
    return ulCompletionKey
         ? reinterpret_cast<P2PeerCon *>(ulCompletionKey)
         : reinterpret_cast<P2PeerCon *>(pOVERLAPPEDcon->pOwnerCon);
}

//
//  Drains a pump's completion port at teardown, WAITING for what is still owed
//  NOTES: D40.  This drain was written twice - verbatim, as its own comments
//         said - and polled with a ZERO timeout, so it drained only what was
//         ALREADY on the port.  Destroy() cancels a pending operation, but a
//         cancellation COMPLETES ASYNCHRONOUSLY: the packet is posted after the
//         cancel is accepted, not during it.  Poll dry one moment too early and
//         the loop breaks with the completion still in flight - and that
//         completion holds the reference prepareOVERLAPPED() took, so the
//         connection never reaches zero, ~P2PeerCon never runs, and everything
//         it owns is lost.  LSan reports it INDIRECT WITH NO LIVE ROOT, because
//         what is left is a cycle: the connection points at its member
//         OVERLAPPED and the OVERLAPPEDcon points back through pOwnerCon.
//         Measured in p2p_expreg as 34976 bytes in 13 allocations, 2 runs in 24
//         - the service connection's 33 KB AcceptEx buffer and its graph.
//       : So the wait is CONDITIONAL ON SOMETHING REAL, not a sleep bolted onto
//         a teardown.  HasQueuedOVERLAPPED() asks the pinned connections whether
//         any of them is still owed a completion; when none is, dwWait stays 0
//         and this behaves EXACTLY as it did before - one poll, no added latency
//         on the overwhelming majority of teardowns, which is the path every
//         other test in the suite takes.
//       : And it is BOUNDED, by slices rather than a clock: a completion that
//         never arrives must not hang a teardown, and no wall clock is needed
//         to say "long enough".  The budget is only spent on slices that time
//         out, so a port still handing back completions is never cut off.
//       : The pins are the caller's and are held across this whole call, which
//         is what makes DrainOVERLAPPED()'s trailing Release() safe to call in
//         the loop (D33) - it cannot be the last one while a pin is held.
//
//
//  Parameters:  P2PmsgPump *pP2PmsgPump
//               The pump whose completion port is drained
//
//               CList<P2PeerCon*> &rConPinned
//               Connections pinned by the caller across the drain
static
void
DrainPortOfOVERLAPPED ( P2PmsgPump        *pP2PmsgPump
                      , CList<P2PeerCon*> &rConPinned )
{
    //  10ms slices to a half-second ceiling.  A cancellation completion is
    //  posted by the transport as soon as the cancel is accepted, so this is
    //  orders of magnitude more than it takes; the ceiling is here so that a
    //  completion which will NEVER arrive costs a bounded teardown, not a hang
    const DWORD dwDrainSlice     = 10;
    const int   nDrainSlicesMax  = 50;
    int         nDrainSlices     = 0;

    for ( ;; )
    {
      ULONG_PTR  ulCompletionKey = 0;
      OVERLAPPED *pOVERLAPPED    = 0;
      DWORD      dwBytes         = 0;
      if ( !pP2PmsgPump || !pP2PmsgPump->m_hIOCP )
        break;

      // Wait ONLY while a pinned connection is still owed a completion, and
      // only while there is budget left to wait with
      DWORD dwWait = 0;
      if ( nDrainSlices < nDrainSlicesMax )
      {
        POSITION posOwed = rConPinned.GetHeadPosition ( );
        while ( posOwed )
        {
          P2PeerCon *pConOwed = rConPinned.GetNext ( posOwed );
          if ( pConOwed && pConOwed->HasQueuedOVERLAPPED() )
          {
            dwWait = dwDrainSlice;
            break;
          }
        }
      }

      GetQueuedCompletionStatus ( pP2PmsgPump->m_hIOCP, &dwBytes
                                ,&ulCompletionKey, &pOVERLAPPED, dwWait );
      if ( !pOVERLAPPED )              // null OVERLAPPED == nothing on the port
      {
        if ( dwWait == 0 )
          break;                      // and nothing owed, or no budget left
        nDrainSlices++;               // owed but not arrived - spend a slice
        continue;
      }
      if ( pOVERLAPPED == pP2PmsgPump->m_pOVERLAPPED )
        continue;                     // the pump's own wake sentinel, not a con op
      OVERLAPPEDcon *pOVERLAPPEDcon = (OVERLAPPEDcon *)pOVERLAPPED;
      P2PeerCon     *pCon = DrainConOfOVERLAPPED ( ulCompletionKey
                                                 , pOVERLAPPEDcon );
      if ( pCon )
        pCon->DrainOVERLAPPED(pOVERLAPPEDcon);   // pinned: cannot delete pCon
    }
}

BOOL
CloseP2Pexpump ( )
{
    // Isolate P2PmsgPump environment
    // NOTES: Remove ThreadID-PumpID map entry.  After which the
    //        pump can no longer be addressed.
    P2PmsgPump  *pP2PmsgPump = 0;
    P2PsafeCS oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                       )
      return FALSE;                    // Nothing to cleanup

    // Block out-of-context CloseP2PmsgHub()
    if ( pP2PmsgPump->m_nPumpID == pP2PmsgPump->m_nHubID )
      EVERR->MODULE
           ->Message("Invalid operation from P2PmsgHub context" )
           ->Advice ("Refer CloseP2PmsgHub()" )
           ->Throw  ( );
    SP2PmsgPump spP2PmsgPump = pP2PmsgPump;

    // Isolate P2PmsgHub
    // NOTES: Swap to P2PmsgHub environment isolation
    P2PmsgHubMgr  *pP2PmsgHub = 0;
    P2PsafeCS oSafeCS_Hub = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(pP2PmsgPump->m_nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                                       )
      return FALSE;                    // Nothing to cleanup
    oSafeCS_Hub = pP2PmsgHub -> m_oCSection;

    // Posted P2PeerCon objects
    // NOTES: The explorer's connections live in their OWN list.  PostP2PexpCon
    //        /DropP2PexpCon mirror PostP2PmsgCon/DropP2PmsgCon exactly, but the
    //        teardown did not: CloseP2PmsgHub() sweeps m_oCListP2PmsgCon with
    //        Destroy()+Drop() and NOTHING anywhere swept m_oCListP2PexpCon, so
    //        every connection ever posted to an explorer outlived the process
    //        along with its OVERLAPPED buffers (32 KB apiece from
    //        MakeOVERLAPPED).  Found by fixing F-S5-4: with the expump's thread
    //        handle leaked, LSan called all of this "indirect" and named the
    //        handle; closing the handle left these as an unreferenced cycle -
    //        con <-> OVERLAPPED - which is why they report as indirect with no
    //        direct root at all.
    //      : Same index-walk as CloseP2PmsgHub(), for the same reason spelled
    //        out there: Drop() deletes out of the list being walked, so a
    //        POSITION cannot survive it.
    //      : This is the expump's own thread - CloseP2Pexpump() is keyed on
    //        GetCurrentThreadId() and throws from anywhere else - so the
    //        connections are being retired by the thread that was servicing
    //        them, not from underneath it.
    // Pin every connection across the sweep AND the drain (D33)
    // NOTES: The drain below can be handed more than one completion for the same
    //        connection, and DrainOVERLAPPED()'s Release() may be that connection's
    //        last.  Retiring it there leaves the loop holding a raw pointer to freed
    //        memory, and the next lap loads its VTABLE to make the very same call -
    //        free and read one source line apart, one lap apart.  Measured on Linux/
    //        ASan as an intermittent abort in p2pweb_w2/w5/w6 (D33), always after the
    //        suite itself had passed, because it is teardown and nothing else.
    //      : A reference held here for the WHOLE drain is what the loop was missing.
    //        Not a liveness test at the point of use: that was written and taken back
    //        out, because skipping a completion whose connection has retired strands
    //        its OVERLAPPEDcon and buffers - LSan reported 28 blocks, 99306 bytes,
    //        every one INDIRECT, i.e. with no live root at all.  The completion still
    //        owns memory that only DrainOVERLAPPED() frees, so the answer is to keep
    //        the owner alive to receive it, not to drop it on the floor.
    //      : Taken BEFORE the sweep, so Destroy()+Drop() cancels every operation
    //        without retiring anything, the drain then sees a stable list, and the
    //        release below retires them in one pass when no completion can arrive
    //        again.  Cancel everything, drain everything, THEN let go.
    //      : It also makes the sweep's index walk trivial - nothing leaves the list
    //        while it runs - though that walk is left exactly as it was, because it
    //        is correct either way and is what runs on the paths this does not touch.
    CList<P2PeerCon*> oConPinned;
    {
      POSITION posPin = pP2PmsgHub->m_oCListP2PexpCon.GetHeadPosition ( );
      while ( posPin )
      {
        P2PeerCon *pConPin = pP2PmsgHub->m_oCListP2PexpCon.GetNext ( posPin );
        if ( pConPin )
        {
          pConPin -> AddRef ( );
          oConPinned.AddTail ( pConPin );
        }
      }
    }

    for ( INT_PTR iCon = 0; iCon < pP2PmsgHub->m_oCListP2PexpCon.GetCount(); )
    {
      POSITION posCon = pP2PmsgHub->m_oCListP2PexpCon.FindIndex ( iCon );
      if ( !posCon )
        break;

      P2PeerCon *pCon    = pP2PmsgHub->m_oCListP2PexpCon.GetAt ( posCon );
      INT_PTR    nBefore = pP2PmsgHub->m_oCListP2PexpCon.GetCount();

      pCon -> Destroy ( );
      pCon -> Drop ( 0 );

      if ( pP2PmsgHub->m_oCListP2PexpCon.GetCount() >= nBefore )
        iCon++;                    // nothing left the list -- step over it
    }

    // Drain the queued and cancelled in-flight OVERLAPPEDcon objects
    // NOTES: Verbatim the drain CloseP2PmsgHub() performs, against the expump's
    //        OWN completion port, and for the same reason: the sweep above only
    //        cancels: a connection with in-flight operations still holds the
    //        refs those operations took, so it does NOT reach zero and does NOT
    //        retire.  Without this the sweep looks like it worked and the
    //        listening service connection survives with its 32 KB of OVERLAPPED
    //        buffers - measured, after the sweep alone, as 11 unfreed
    //        allocations rooted at P2PeerConWsa::ServiceFactory().
    //      : Every rule spelled out at CloseP2PmsgHub()'s drain applies here
    //        unchanged - loop on lpOverlapped rather than on the return value
    //        (a cancelled op yields FALSE and still hands back its OVERLAPPED),
    //        skip the pump's own wake sentinel, and recover a keyless
    //        completion's owner from pOwnerCon.
    //      : D40.  The drain itself now lives in DrainPortOfOVERLAPPED(), ONCE,
    //        because it was written out twice here and in CloseP2PmsgHub() and
    //        so had the zero-timeout defect twice.  This is the call site that
    //        the leak was measured at.
    DrainPortOfOVERLAPPED ( pP2PmsgPump, oConPinned );

    // Release the pins, retiring every connection whose last reference this was
    // NOTES: Ordinary Release(), so a connection still referenced elsewhere survives
    //        and one that is not is deleted here - after the drain, which is the
    //        point.  ~P2PeerCon reclaims the four member OVERLAPPEDs it still owns,
    //        and no completion can name it any more because the port is drained.
    {
      POSITION posPin = oConPinned.GetHeadPosition ( );
      while ( posPin )
        oConPinned.GetNext ( posPin ) -> Release ( );
      oConPinned.RemoveAll ( );
    }

    // Tidy up, P2PmsgPump table within P2PmsgPump
    pP2PmsgHub   -> RemoveP2Pexplorer ( spP2PmsgPump.p_SafePtr ( ) );
    spP2PmsgPump = 0;
    return TRUE;
}

DWORD
RegisterP2Pexpump ( DWORD dwMask, BOOL bRegister )
{
    // Isolate P2Pexpump environment
    // NOTES: Remove ThreadID-PumpID map entry.  After which the
    //        pump can no longer be addressed.
    P2PmsgPump  *pP2PmsgPump = 0;
    P2PsafeCS oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                    ||
         !pP2PmsgPump->m_bP2Pexplorer                                       )
      EVERR->MODULE->AFP(dwMask)->AFP(bRegister)
           ->Message("ThreadID=%i has no P2Pexplorer context"
                    , GetCurrentThreadId() )
           ->Advice ("Only valid from context of P2Pexpump, "
                     "refer CreateP2Pexpump() for further details" )
           ->Throw  ( );

    // Apply configuration
    if ( bRegister )
      pP2PmsgPump->m_dwExpumpMask |=  dwMask;
    else
      pP2PmsgPump->m_dwExpumpMask &= ~dwMask;

    // Tidy up, and
    return pP2PmsgPump->m_dwExpumpMask;
}


//
//  Description: Posts P2PeerMsg
//               NOTES: Thread context sensitive.  Use GetP2Pmsg()
//                      for retrieval of queue entries
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message object to be posted.  Control over object
//               life cycle is assumed
//
//               DWORD nThreadID
//               Thread to which P2PeerMsg is to be posted
//
//               bool bPrepend
//               Prepend P2PeerMsg flag
//
//  Returns:     UINT
//               Unpumped messages
//
P2PeerMsg*
PostP2Pexp ( P2PeerMsg *pMsg, P2PumpID nPumpID, bool bPrepend )
{
    // Isolation
    P2PeerMsgSP spMsg    = pMsg;
    P2PsafeCS    oSafeCS = s_oCSectionP2PmsgPump;

    // Pump context
    P2PmsgPump *pP2PexpPump = 0;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PexpPump) ||
         !pP2PexpPump                                          )
      EVERR->MODULE
           ->AFPmsg(pMsg)->AFP(nPumpID)->AFP(bPrepend)
           ->Message("P2PexpumpID=%i not started"
                    , nPumpID )
           ->Advice ("Refer CreateP2Pexpump() for further details" )
           ->Throw  ( );

    // Hub context
    P2PmsgPump *pP2PexpThis = 0;
    if ( s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PexpThis) &&
         pP2PexpThis                                                    &&
         pP2PexpThis->m_nHubID != pP2PexpPump->m_nHubID                    )
    {
      EVERR->MODULE
           ->AFPmsg(pMsg)->AFP(nPumpID)->AFP(bPrepend)
           ->Message("Attempt to swap PostP2Pmsg across P2PmsgHub contexts(%i to %i)"
                    , pP2PexpThis->m_nHubID
                    , pP2PexpPump->m_nHubID )
           ->Throw  ( );
    }

    // Observe P2PmsgQue capacity
    if ( s_cP2Pmsg > s_cP2PmsgMAX )
      EVERR->MODULE
           ->Message(P2PMSG_QUEFULL_FMT, (unsigned long)s_cP2PmsgMAX )
           ->Advice ("Refer PumpP2Pmsg()" )
           ->HResult(P2Pevent_QUEFULL)
           ->Throw();

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory ( );
            pP2Pmsg -> strP2Paddr   = spMsg -> GetSource();
            pP2Pmsg -> nCode        = CN_P2PeerMsg;
            pP2Pmsg -> nMsg         = P2P_P2Pmsg;//pMsg -> Type();
            pP2Pmsg -> pMsg         = spMsg.Dereference();
            pP2Pmsg -> pTarget      = pP2PexpPump -> m_pTarget;
            pP2Pmsg -> bNotify      = false;
ASSERT(VerifyP2Pmsg(pP2Pmsg));

    // Implementation
    oSafeCS = pP2PexpPump -> m_oCSection;
    pP2PexpPump -> PutP2Pmsg ( pP2Pmsg, bPrepend );
    return (P2PeerMsg *)0;
}

void
PostP2PexpCon ( P2PexpumpID nExpumpID, P2PeerCon *pCon )
{
    // Preamble
    P2PeerConSP spCon = pCon;
    if ( nExpumpID <= 0 )
      nExpumpID = GetCurrentThreadId();

    // Isolate the P2PexpPump
    P2PmsgPump *pP2PexpPump = 0;
    P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nExpumpID,pP2PexpPump) ||
         !pP2PexpPump                                         ||
         !pP2PexpPump->m_bP2Pexplorer                            )
      EVERR->MODULE
           ->AFP(nExpumpID)->AFPcon(pCon)
           ->Message("ThreadID=%i has no P2Pexpump context"
                    , nExpumpID )
           ->Throw  ( );
    P2PmsgHubID nHubID = pP2PexpPump -> m_nHubID;

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCSHub = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("nHubID=%i has no P2PmsgHub context"
                    , nHubID )
           ->Throw  ( );

    // To be sure, to be sure
    P2PumpID nHubIDcon = 0;
    if ( s_P2PexpCon_HubID.Lookup((DWORD_PTR)pCon,nHubIDcon) ||
         nHubIDcon                                          )
      EVERR->Module  ("%s(nHubID=%i,pP2PmsgCon)", __FUNCTION__
                     , nHubID )
           ->Message ("P2PexpCon object already posted" )
           ->Throw();

    // Post
    pP2PmsgHub -> PostP2PexpCon ( spCon.Dereference() );
}


BOOL
EnumP2PexpCon ( P2PexpumpID nExpumpID, P2PeerCon **ppCon )
{
    // Preamble
    if ( nExpumpID <= 0 )
      nExpumpID = GetCurrentThreadId();

    // Isolate the P2PexpPump
    P2PmsgPump *pP2PexpPump = 0;
    P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nExpumpID,pP2PexpPump) ||
         !pP2PexpPump                                         ||
         !pP2PexpPump->m_bP2Pexplorer                            )
      EVERR->MODULE
           ->AFP(nExpumpID)
           ->Message("ThreadID=%i has no P2Pexpump context"
                    , nExpumpID )
           ->Throw  ( );
    P2PmsgHubID nHubID = pP2PexpPump -> m_nHubID;

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCSHub = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("nHubID=%i has no P2PmsgHub context"
                    , nHubID )
           ->Throw  ( );
    if ( !ppCon )
      return pP2PmsgHub->m_oCListP2PexpCon.GetCount() ? TRUE : FALSE;

    // Initialisation
    POSITION pos = pP2PmsgHub->m_oCListP2PexpCon.GetHeadPosition();
    if ( *ppCon == 0 && pos )
    {
      *ppCon = pP2PmsgHub->m_oCListP2PexpCon.GetNext(pos);
       return TRUE;
    }

    // Interation
    while ( pos )
    {
      P2PeerCon *pCon = pP2PmsgHub->m_oCListP2PexpCon.GetNext(pos);
      if ( pCon == *ppCon && pos )
      {
        *ppCon = pP2PmsgHub->m_oCListP2PexpCon.GetNext(pos);
         return TRUE;
      }
    }

    // Tidy up, and
    *ppCon = 0;
    return FALSE;
}


void
P2PmsgExp_RHub ( LPCTSTR lpszSource, P2PmsgHubID nHubID )
{
    lpszSource = lpszSource;
    nHubID     = nHubID;
    // Register P2PmsgHubID for nominated P2PmsgExplorer
    /*CString strSource = lpszSource;
    POSITION pos = s_ThreadID_P2PmsgHub.GetStartPosition();
    while ( pos )
    {
      P2PmsgHubMgr *pHubMgr = 0;
      DWORD         nMapID  = 0;
      s_ThreadID_P2PmsgHub.GetNextAssoc ( pos, nMapID, pHubMgr );
      if ( ( nHubID > 0       &&
             nHubID != nMapID    ) ||
          !pHubMgr                    )
        continue;
      CString strIgnore;
      if ( !pHubMgr->m_oCMapExpHub.Lookup(strSource,strIgnore) )
        pHubMgr -> m_oCMapExpHub.SetAt ( strSource, strSource );
    }*/
}

void
NotifyP2PmsgExp_Hub ( P2PmsgHubMgr *pHubMgr, LPCTADDR lpszDestin )
{
    // Notification message creation
    P2PeerMsgSP spMsg = new P2PeerMsg ( MSG_P2PexpHub );
    if ( lpszDestin             &&
         wcslen(lpszDestin) > 0    )
      spMsg->SetDestin ( lpszDestin );
    //LPCTSTR lpszHubname = pHubMgr->m_oP2Paddr.c_name();
    //spMsg -> r_node ( VBLockBSTR_MSG, true )
    //  += P3PmsgNode ( P3PmsgField(lpszHubname,P3PmsgData()) );
    P3PmsgItem& oItemHub = spMsg->r_datn();//.SelectNode ( lpszHubname );

    // System
    if ( 1 )
    {
      bool bDsc = true;
      char szHostname[128];
      if ( !gethostname ( szHostname, sizeof(szHostname) ) )
      {
        USES_CONVERSION;
        P3PmsgField_SERIALISE ( oItemHub, L"Machine", A2W(szHostname), bDsc
                              , L"Name of machine on which Hub is running" );
      }
      // Firstly fetch name of executable
      TCHAR      szExePathname[_MAX_PATH];
      if ( GetModuleFileName(NULL,szExePathname,_MAX_PATH) > 0 )
      {
        P3PmsgField_SERIALISE ( oItemHub, L"Executable", szExePathname, bDsc
                              , L"Name of Module in which the Hub running" );
      }
    }

    // Serialise
    oItemHub += pHubMgr -> m_pHub
                        -> Serialise ( 0 );

    // Perform notification
    spMsg = pHubMgr -> PostP2PmsgExp ( spMsg.Dereference() );
}
BOOL
QueryP2PmsgExp_Hub ( LPCTADDR lpszDestin, BOOL bRegister )
{
    // Isolate the P2PmsgExp context
    // NOTES: The HUB lock is taken first and is not otherwise needed here.
    //        Since Stage 4 step 13 the snapshot this builds reports the hub's
    //        queue depth and accepted count, and those aggregates walk the
    //        hub's own lists - so Serialise() now takes the hub lock while
    //        this function holds the pump lock.  Taken in the other order
    //        that is a genuine inversion against CreateP2PmsgHub(), which
    //        takes HUB then PUMP: hub B being created while hub A's explorer
    //        serialises would have deadlocked, the locks being process-wide
    //        statics shared by every hub.  Acquiring both here, in
    //        CreateP2PmsgHub()'s order, removes the window rather than
    //        narrowing it
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                    ||
         !pP2PmsgPump->m_bP2Pexplorer                                       )
      EVERR->MODULE
           ->AFP(lpszDestin)->AFP(bRegister)
           ->Message("ThreadID=%i has no P2Pexplorer context"
                    , GetCurrentThreadId() )
           ->Advice ("Only valid from context of P2Pexplorer pump, "
                     "refer CreateP2PmsgExp() for further details" )
           ->Throw  ( );

    // Delegate request to internal notification sequence
    NotifyP2PmsgExp_Hub ( pP2PmsgPump->m_pP2PmsgHubMgr, lpszDestin );
    return TRUE;
}
/*void
P2PmsgExp_DHub ( LPCTSTR lpszSource, P2PmsgHubID nHubID )
{
    // Deregister P2PmsgHubID for nominated P2PmsgExplorer
    CString strSource = lpszSource;
    POSITION pos = s_ThreadID_P2PmsgHub.GetStartPosition();
    while ( pos )
    {
      P2PmsgHubMgr *pHubMgr = 0;
      DWORD         nMapID  = 0;
      s_ThreadID_P2PmsgHub.GetNextAssoc ( pos, nMapID, pHubMgr );
      if ( ( nHubID > 0       &&
             nHubID != nMapID    ) ||
          !pHubMgr                    )
        continue;
      if ( strSource.GetLength() > 0 )
        pHubMgr -> m_oCMapExpHub.RemoveKey ( strSource );
    }
}*/
/*static bool
Notify_P2PmsgExp_Hub ( P2PaddrSTR strDestin, P2PmsgHubID nHubID, BOOL bRegister )
{
    // Isolation
    if ( nHubID <= 0 )
      nHubID = GetP2PmsgHubID ( );

    // Isolate P2PmsgHub
    // NOTES: Swap to P2PmsgHub environment isolation
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    P2PsafeCS     oSafeCS_Hub = s_oCSectionP2PmsgHub;
    //if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
    //     !pP2PmsgHub                                        )
    //  EVERR->Message("Nominated P2PmsgHub=%i does not exist", nHubID )
    //       ->Throw  ( );
    oSafeCS_Hub = pP2PmsgHub -> m_oCSection;
   
    P2PeerMsg *pMsg = new P2PeerMsg ( );
    P3PmsgNode oNodeHub ( P3PmsgField("Hub",P3PmsgData(nHubID) ) );
               oNodeHub += P3PmsgField ( "PumpsMax", pP2PmsgHub->m_nPumpsMax  );
               oNodeHub += P3PmsgField ( "Name",     pP2PmsgHub->m_oP2Paddr.c_name() );
               oNodeHub += P3PmsgField ( "Address",  pP2PmsgHub->m_oP2Paddr.c_wstr() );
               oNodeHub += P3PmsgField ( "Adomain",  pP2PmsgHub->m_oP2Padomain.c_wstr() );

    // Posted P2PeerCon's
    P3PmsgNode oNodeCon ( P3PmsgField("Con",P3PmsgData()) );
    P2PeerCon *pCon = 0;
    while ( EnumP2PmsgCon(nHubID,&pCon) )
    { 
      char szBuffer[64];
      sprintf_s ( szBuffer, sizeof(szBuffer), _T("%04x"), pCon->GetP2PconID() );
      oNodeCon += pCon -> SetP2PeventFParams ( szBuffer );
    }

    // Perform requested P2PmsgExp_Hub notification
    if ( strDestin )
    {
      PostP2Pmsg ( strDestin, *pMsg );
      return false;
    }

    // Perform registered P2PmsgExp_Hub notifications
    POSITION pos = 0;
    while ( pos )
    {
      PostP2Pmsg ( 0, *pMsg );
    }

    // Tidy up, and
    PostP2Pmsg ( pMsg, 0 );
    return false;
}*/

static void
NotifyP2PmsgExp_Pmp ( P2PmsgHubMgr *pHubMgr, P2PmsgPump *pP2PmsgPump
                    , LPCTADDR lpszDestin, BOOL bVerbose )
{
    USES_CONVERSION;
    // Notification message creation
    P2PeerMsgSP spMsg = new P2PeerMsg ( MSG_P2PexpPmp );
    if ( lpszDestin             &&
         wcslen(lpszDestin) > 0    )
      spMsg->SetDestin ( lpszDestin );
    spMsg -> r_datn().r_data() = P3PmsgData(pP2PmsgPump->m_nPumpID);

    // Serialise
    P3PmsgItem oNodePump ( P3PmsgField ( pP2PmsgPump->m_csName
                                       , P3PmsgData(pP2PmsgPump->m_nPumpID) ) );
    P3PmsgField_SERIALISE ( oNodePump, L"PumpID", pP2PmsgPump->m_nPumpID
                          , bVerbose,  L"Pump identification" );
    P3PmsgField_SERIALISE ( oNodePump, L"Function", (LPCWSTR)pP2PmsgPump->m_strFunc
                          , bVerbose,  L"Operational function" );
    P3PmsgField_SERIALISE ( oNodePump, L"Class", L"P2PeerCon", bVerbose
                            , L"Encapsulating connection class name" );

    // Perform notification
    spMsg -> r_datn() += oNodePump;
    spMsg = pHubMgr -> PostP2PmsgExp ( spMsg.Dereference() );
}

BOOL
QueryP2PmsgExp_Pmp ( P2PumpID nPumpID, LPCTADDR lpszDestin, BOOL bVerbose )
{
    // Isolate the P2PmsgExp context
    P2PmsgPump *pP2PmsgPump = 0;
    P2PsafeCS   oSafeCS_Hub = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                    ||
         !pP2PmsgPump->m_bP2Pexplorer                                       )
      EVERR->Module ( __FUNCTION__ )
           ->AFP(nPumpID)->AFP(lpszDestin)->AFP(bVerbose)
           ->Message(L"ThreadID=%i has no P2PmsgHub or P2Pexplorer context")
           ->Advice (L"Only valid from context of P2Pexplorer pump, ")
           ->Throw  ( );
    P2PmsgHubMgr *pHubMgr = pP2PmsgPump -> m_pP2PmsgHubMgr;

    // Delegate request to internal notification sequence
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    POSITION    pos = pHubMgr -> m_oCListP2PmsgPump.GetHeadPosition();
    while ( pos )
    {
      pP2PmsgPump = pHubMgr -> m_oCListP2PmsgPump.GetNext(pos);
      if ( nPumpID == 0                      ||
           nPumpID == pP2PmsgPump->m_nPumpID    )
        NotifyP2PmsgExp_Pmp ( pP2PmsgPump->m_pP2PmsgHubMgr, pP2PmsgPump
                            , lpszDestin, bVerbose );
    }
    return TRUE;
}

void
NotifyP2PmsgExp_Con ( P2PmsgHubMgr *pHubMgr, P2PeerCon *pCon
                    , LPCTADDR lpszDestin )
{
    // Notification message creation
    P2PeerMsgSP spMsg = new P2PeerMsg ( MSG_P2PexpCon );
    if ( lpszDestin             &&
         wcslen(lpszDestin) > 0    )
      spMsg -> SetDestin ( lpszDestin );
    CString strConame = pCon->GetP2Paddress().c_name();

    // Serialise
    P3PmsgItem& oNode     = spMsg -> r_item ( VBLockBSTR_MSG, true );
                oNode    += pCon -> Serialise ( strConame );
    P3PmsgItem& oNodeCon  = oNode.SelectItem ( strConame );
                oNodeCon.r_Attr(P3PmsgField::AttrCMD_Create);
    P3PmsgField oConID ( L"ConID", P3PmsgData(pCon->m_nP2PconID) );
                oConID.SetAccess ( AttrField_HIDDEN );
                oNodeCon.r_Attr() += oConID;
    P3PmsgField oConMode ( L"ConMode", P3PmsgData(pCon->GetMode()) );
                oNodeCon.r_Attr() += oConMode;
    P3PmsgField oP2Paddr ( L"P2Paddr"),P3PmsgData(pCon->GetP2Paddress().c_wstr() );
                oNodeCon.r_Attr() += oP2Paddr;

    // Perform notification
    spMsg = pHubMgr -> PostP2PmsgExp ( spMsg.Dereference() );
}

BOOL
QueryP2PmsgExp_Con ( P2PconID nP2PconID, LPCTADDR lpszDestin, BOOL bVerbose )
{
    // Isolate the P2PmsgExp context
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                    ||
         !pP2PmsgPump->m_bP2Pexplorer                                       )
      EVERR->MODULE
           ->AFP(nP2PconID)->AFP(lpszDestin)->AFP(bVerbose)
           ->Message("ThreadID=%i has no P2Pexplorer context"
                    , GetCurrentThreadId() )
           ->Advice ("Only valid from context of P2Pexplorer pump, "
                     "refer CreateP2PmsgExp() for further details" )
           ->Throw  ( );

    // Enumerate all P2PeerCon's supported by Hub
    POSITION pos =pP2PmsgPump->m_pP2PmsgHubMgr->m_oCListP2PmsgCon.GetHeadPosition();
    while ( pos )
    {
      P2PeerCon *pCon = pP2PmsgPump->m_pP2PmsgHubMgr->m_oCListP2PmsgCon.GetNext ( pos );
      //if ( nP2PconID == 0                  ||
      //     nP2PconID == pCon->GetP2PconID()   )
        NotifyP2PmsgExp_Con ( pP2PmsgPump->m_pP2PmsgHubMgr, pCon, lpszDestin );
    }
    return TRUE;
}

static bool
Notify_P2PmsgExp_MsgMAP ( )
{
    // Tidy up, and
    return false;
}

static bool
Notify_P2PmsgExp_ConMAP ( )
{
    // Tidy up, and
    return false;
}

static bool
Notify_P2PmsgExp_SysMAP ( )
{
    // Tidy up, and
    return false;
}


///////////////////////////////////////////////////////////////////////
//  P2Pmsg environment
//  NOTES: Manage the creation, operation and life cycle of
//         P2PmsgHub's.  P2P messages are only ever to be exchanged 
//         between P2PmsgHub's
//       : Act as containers for P2PmsgPump's

static P2PmsgHubMgr                          **s_apP2PmsgHubMgr = 0;
static UINT                                    s_uxP2PmsgHubMgr = 0;

//
//  Starts up the P2Pmsg environment
//  NOTES: P2Pmsg environment must be started prior to the use of
//         any other framework modules
//
//  Parameters: UINT nMaxHubs
//              Maximum number of P2PmsgHub's supported within
//              instance of application
//              NOTES: 
BOOL
StartupP2Pmsg ( UINT nMaxHubs )
{
    // Mandatories
    StartupP2Pevent ( );

    // To be sure, to be sure
    if ( s_apP2PmsgHubMgr || s_uxP2PmsgHubMgr )
      EVERR->MODULE->AFP(nMaxHubs)
           ->Message_T ( "P2Pmsg environment already started" )
           ->Advice_T  ( "Refer StartupP2Pmsg for further details" )
           ->Throw  ( );

    // To be sure, to be sure
    if ( nMaxHubs < 1 || nMaxHubs > MAX_P2PmsgHub )
      EVERR->MODULE
           ->Message(L"nMaxHubs=%i out-of-range (1 to %i)\n"
                    , nMaxHubs, MAX_P2PmsgHub )
           ->Throw  ( );

    // Initialise environment
    // NOTES: s_oCSectionP2Pmsg is PROCESS lifetime and the other two are
    //        ENVIRONMENT lifetime, which is why only it carries a flag and why
    //        CleanupP2Pmsg() deletes the other two and not this one.  It can be
    //        raised before any environment exists - refer the lazy init in
    //        RegisterP2PmsgSink, which is the same three lines - and it is
    //        never torn down, because the sink registry it guards outlives the
    //        environment by design
    //      : GUARDED, and it was not until 2026-08-28.  This site initialised
    //        unconditionally while setting the very flag that says it need not,
    //        so a second StartupP2Pmsg() - which the note above CleanupP2Pmsg()
    //        explicitly permits - overwrote the pointer and orphaned the first
    //        mutex.  On Windows a CRITICAL_SECTION is a struct and this cost
    //        nothing visible; on Linux ../Msgcore/Platform/p2pthread.h allocates a
    //        std::recursive_mutex, so every startup/shutdown cycle leaked 40
    //        bytes.  Found by LeakSanitizer on the first sanitised Linux run
    //        since the three restart-cycling gates were written - p2p_ipv6,
    //        p2p_listenscope and p2p_resolve, which stand a hub up and tear it
    //        down two or three times each, and are the only tests in the suite
    //        shaped that way
    if ( !s_bCSectionP2Pmsg )
    {
      InitializeCriticalSection ( &s_oCSectionP2Pmsg );
                                   s_bCSectionP2Pmsg = true;
    }
    InitializeCriticalSection ( &s_oCSectionP2PmsgHub );
    P2PsafeCS oSafeCS = s_oCSectionP2PmsgHub;
    InitializeCriticalSection ( &s_oCSectionP2PmsgPump);

    // Allocate P2PmsgHubs control block
    s_apP2PmsgHubMgr = new P2PmsgHubMgr* [nMaxHubs+7];
    s_uxP2PmsgHubMgr = nMaxHubs;
    for ( UINT nHub = 0; nHub < nMaxHubs+7; nHub++ )
      s_apP2PmsgHubMgr[nHub] = 0;

    // Tidy up, and
    // NOTES: StartupP2PmsgSink() is a one-time process init that reports "sink environment
    //        up" (TRUE) whether or not this call is what raised it -- so reaching here with
    //        the environment allocated above means TRUE.  An already-started environment is
    //        reported by the Throw above, never by a FALSE return.
    if ( StartupP2PmsgSink() )
      return TRUE;
    return FALSE;
}

//
//  Cleans up the P2Pmsg environment and recovers resources
//  NOTES: Cleaned environments may be re-started
//
void
CleanupP2Pmsg ( )
{
    // Garbage collection
    if ( s_apP2PmsgHubMgr )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgHub;
      for ( UINT nHub = 1; nHub <= s_uxP2PmsgHubMgr; nHub++ )
        delete s_apP2PmsgHubMgr[nHub];

      // Render safe (array new[] at StartupP2Pmsg -> delete[]; scalar delete was UB)
      delete [] s_apP2PmsgHubMgr;
             s_apP2PmsgHubMgr = 0;
             s_uxP2PmsgHubMgr = 0;
    }

    // Resource recovery
    // NOTES: TWO of the three StartupP2Pmsg() raises, and the third is not an
    //        omission.  s_oCSectionP2Pmsg guards the process-wide sink registry,
    //        can be raised before any environment exists and is used by paths
    //        that do not check whether one does; deleting it here would leave
    //        those dereferencing a null impl on the Linux shim.  It is
    //        process lifetime on purpose - refer the guard at its init
    DeleteCriticalSection ( &s_oCSectionP2PmsgPump);
    DeleteCriticalSection ( &s_oCSectionP2PmsgHub );
}

///////////////////////////////////////////////////////////////////////
//  P2PmsgHub management
//  NOTES: Manage the creation, operation and life cycle of
//         P2PmsgHub's.  P2P messages are only ever be exchanged 
//         between P2PmsgHub's
//       : Act as containers for P2PmsgPump's

//
//  Creates P2PmsgHub
//
//
//  Parameters:  P2PeerTarget *pTarget
//               Initial P2Pmsg ownership target.  Ownership may
//               be subsequently swapped.
//
//               HANDLE hP2PmsgEvent
//               P2Pmsg to be pumped event
//
//  Returns:     P2PmsgHubID
//               Allocated P2PmsgHub identification code
P2PmsgHubID
CreateP2PmsgHub ( P2PaddrSTR strP2Paddr, P2PeerHub *pHub
                , UINT  nMaxPumps
                , DWORD nNumberOfConcurrentThreads  )
{
    // Guard: the P2Pmsg environment must be started (StartupP2Pmsg) first, else
    // the shared critical sections below are uninitialised and the P2PsafeCS
    // ctor's EnterCriticalSection hard-crashes in ntdll. s_apP2PmsgHubMgr is the
    // started/not-started flag (allocated by StartupP2Pmsg, nulled by
    // CleanupP2Pmsg). Fail with a catchable P2Pevent instead of crashing.
    if ( !s_apP2PmsgHubMgr )
      EVERR->MODULE
           ->AFP(strP2Paddr)->AFP(nMaxPumps)
           ->Message("P2Pmsg environment not started" )
           ->Advice ("Call StartupP2Pmsg() before creating a hub" )
           ->Throw  ( );

    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    // Locals
    // NOTES: P2PmsgHub environment isolation, keep to completion
    //      : Confirm pump not already associated with this thread
    P2PmsgPump *pP2PmsgPump  = 0;
    if ( s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         pP2PmsgPump                                                       )
      EVERR->MODULE
           ->AFP(strP2Paddr)->AFP(nMaxPumps)->AFP(nNumberOfConcurrentThreads)
           ->Message("P2PmsgPump already exists in contect of thread" )
           ->Advice ("Single P2PmsgPump per thread context" )
           ->Throw  ( );

    // To be sure, to be sure
    if ( nMaxPumps < 1 || nMaxPumps > MAX_P2PmsgPump )
      EVERR->MODULE
           ->Message("nMaxPumps=%i outside range 1 to %i"
                    , MAX_P2PmsgPump )
           ->Throw  ( );

    // To be sure, to be sure
    SP2PmsgHubMgr spHubMgr = 0;
    //P2PsafeCS      oSafeCS_Hub = s_oCSectionP2PmsgHub;
    if ( s_ThreadID_P2PmsgHub.GetCount() >= (INT_PTR)s_uxP2PmsgHubMgr )
       EVERR->MODULE
            ->Message("Attempt to exceed configured hub limit (%i)"
                     , s_uxP2PmsgHubMgr )
            ->Throw  ( );

    // P2PmsgHub Instanciation
    ASSERT(nMaxPumps>0);
    spHubMgr = P2PmsgHubMgr::Factory ( nMaxPumps );
    spHubMgr -> m_oP2Paddr = strP2Paddr;
    spHubMgr -> m_pHub     = pHub;

    // P2PmsgPump Instanciation
    // NOTES: Mandatory for P2PmsgPump to exist within P2PmsgHub
    //pP2PmsgPump = spHubMgr -> CreateP2PmsgPump ( );
    //pP2PmsgPump /* -> m_pP2PmsgITarget = pMsgIHub*/;

    // IOCP
    s_ThreadID_P2PmsgPump.Lookup ( GetCurrentThreadId(), pP2PmsgPump );
    pP2PmsgPump -> m_pTarget     = dynamic_cast<P2PeerTarget *>(pHub);
    pP2PmsgPump -> m_pOVERLAPPED = new OVERLAPPED;
    pP2PmsgPump -> m_csName      = spHubMgr -> m_oP2Paddr.c_name();
    pP2PmsgPump -> m_hIOCP
           = CreateIoCompletionPort ( INVALID_HANDLE_VALUE
                                    , NULL
                                    , 0
                                    , nNumberOfConcurrentThreads );
    if ( pP2PmsgPump->m_hIOCP == 0 )
      EVERR->Module  ("%s(%i)", __FUNCTION__
                     , nNumberOfConcurrentThreads )
           ->Message ("CreateIoCompletionPort() failed" )
           ->Advice  ("Internal (SNHappen), Hub terminating" )
           ->HResult ( GetLastError() )->Throw();

    // Tidy up, and
    return spHubMgr.Dereference()->m_nHubID;
}

/*StartupP2PmsgHub ( P2PadomSTR strP2Padom, P2PmsgHub_ *pMsgHub
                 , HANDLE hIOCP );*/

P2PmsgHubID
GetP2PmsgHubID ( )
{
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                       )
      EVERR->MODULE
           ->Message("ThreadID=%i has no P2PmsgHub context"
                    , GetCurrentThreadId() )
           ->Throw  ( );
    return pP2PmsgPump -> m_nHubID;
}

P2PmsgHubID
GetP2PmsgHubID ( const P2PeerCon *pCon )
{
    // Hub identification
    P2PmsgHubID   nHubID  = 0;
    P2PsafeCS     oSafeCS = s_oCSectionP2PmsgHub;
    if ( !s_P2PmsgCon_HubID.Lookup((DWORD_PTR)pCon,nHubID) ||
         !s_P2PexpCon_HubID.Lookup((DWORD_PTR)pCon,nHubID) ||
         !nHubID                                              )
      EVERR->MODULE
           ->Message("P2PeerCon object not posted")
           ->Throw  ( );

    // Simply
    return nHubID;
}
P2PmsgHubID
GetP2PmsgHubContext ( )
{
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                       )
      return 0;
    return pP2PmsgPump -> m_nHubID;
}

//
//  Fetches the P2Padomain for the nominated P2PmsgHubID
//  NOTES: P2PmsgHubID's and P2PmsgPumpID's are interchangable
//         in the context of this function
//
//
//  Parameters:  P2PmsgHubID nHubID
//               Identification of the P2PmsgHub whose P2Padomain
//               is to be retrieved
//
//  Returns      P2PadomSTR
//               Domain address of the nominated P2PmsgHubID
P2PadomSTR
GetP2PmsgHubAdom ( P2PmsgHubID nHubID )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->AFP(nHubID)
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS   = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->AFP(nHubID)
           ->Message("ThreadID=%i has no P2PmsgIHub context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Simply
    return pP2PmsgHub->m_oP2Padomain;
}

void
SetP2PmsgHubAdom ( P2PmsgHubID nHubID, P2PadomSTR strP2Padom )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->AFP(nHubID)->AFP(strP2Padom)
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS   = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->AFP(nHubID)->AFP(strP2Padom)
           ->Message("ThreadID=%i has no P2PmsgHub context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Simply
    pP2PmsgHub->m_oP2Padomain = strP2Padom;
}

//
//  Manage the P2Paddress for the nominated P2PmsgHubID
//  NOTES: P2PmsgHubID's and P2PmsgPumpID's are interchangable
//         in the context of this function
//
//
//  Parameters:  P2PmsgHubID nHubID
//               Identification of the P2PmsgHub whose P2Paddress
//               is to be retrieved
//
//  Returns      P2PaddrSTR
//               Address of the nominated P2PmsgHubID
void
SetP2PmsgHubAddr ( P2PmsgHubID nHubID, P2PaddrSTR strP2Paddr )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->AFP(nHubID)->AFP(strP2Paddr)
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS   = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->AFP(nHubID)->AFP(strP2Paddr)
           ->Message("ThreadID=%i has no P2PmsgHub context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Simply
    pP2PmsgHub->m_oP2Paddr = strP2Paddr;
}

P2PaddrSTR
GetP2PmsgHubAddr ( P2PmsgHubID nHubID )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS   = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("ThreadID=%i has no P2PmsgIHub context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Simply
    return pP2PmsgHub->m_oP2Paddr;
}

//
//  Is this address a hub held by THIS process?
//  NOTES: The whole mechanism behind P2PeerHub::WaiveEndToEndInProcess.  Refer
//         the block on the declaration in P2Pwin32.h for why the match is
//         EXACT and why this one does not throw
//       : A walk rather than a lookup because the map is keyed by THREAD ID,
//         not by address.  There is one hub per thread and the counts here are
//         single digits, so a walk under the lock is cheaper than the second
//         index it would take to avoid one - and a second index is a second
//         thing that can disagree with the registry, which is exactly what
//         this must not be
//
BOOL
IsP2PmsgHubInProcess ( P2PaddrSTR strP2Paddr )
{
    if ( !strP2Paddr || !*strP2Paddr )
      return FALSE;

    P2PsafeCS oSafeCS = s_oCSectionP2PmsgHub;

    POSITION pos = s_ThreadID_P2PmsgHub.GetStartPosition ( );
    while ( pos )
    {
      P2PmsgHubMgr *pHubMgr = 0;
      DWORD         nMapID  = 0;
      s_ThreadID_P2PmsgHub.GetNextAssoc ( pos, nMapID, pHubMgr );
      if ( !pHubMgr )
        continue;
      //  An unnamed hub matches nothing.  A hub that has been created but not
      //  yet given its address reads L"" (the P2PmsgHubMgr constructor), and
      //  an empty address must not become a wildcard on the way through
      if ( pHubMgr->m_oP2Paddr.IsNull ( ) )
        continue;
      if ( pHubMgr->m_oP2Paddr == strP2Paddr )
        return TRUE;
    }
    return FALSE;
}

P2PaddrSTR
GetP2PmsgHubName ( P2PmsgHubID nHubID )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS   = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("ThreadID=%i has no P2PmsgIHub context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Simply
    return pP2PmsgHub->m_oP2Paddr.c_name();
}

LPCTNAM
GetP2PmsgHubAddr ( const P2PeerCon *pCon )
{
    // Hub identification
    P2PmsgHubID   nHubID  = 0;
    P2PsafeCS     oSafeCS = s_oCSectionP2PmsgHub;
    if ( ( !s_P2PmsgCon_HubID.Lookup((DWORD_PTR)pCon,nHubID) &&
           !s_P2PexpCon_HubID.Lookup((DWORD_PTR)pCon,nHubID)    ) ||
           !nHubID                                                   )
      EVERR->MODULE
           ->Message("P2PeerCon object not posted")
           ->Throw  ( );

    // Hub retrieval
    P2PmsgHubMgr *pP2PmsgHub = 0;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("P2PmsgHubID=%i has no hub context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Simply
    return pP2PmsgHub->m_oP2Paddr.c_wstr();
}

void
PostP2PmsgCon ( P2PmsgHubID nHubID, P2PeerCon *pCon )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    P2PeerConSP spCon = pCon;
    if ( nHubID <= 0 )
    {
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      P2PmsgPump *pP2PmsgPump = 0;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS    = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("nHubID=%i has no P2PmsgHub context"
                    , nHubID )
           ->Throw  ( );

    // To be sure, to be sure
    // NOTES: BOTH registries, which is what the second line here was for. It
    //        read s_P2PmsgCon_HubID twice, so the hub registry was asked the
    //        same question twice and the explorer registry was never asked at
    //        all -- a connection already posted to an explorer passed this
    //        guard and was posted a second time, to the hub. Every other site
    //        that has to answer "is this connection registered anywhere"
    //        consults the pair (2252, 2508, DropP2PmsgCon below); this one now
    //        does too.
    P2PumpID nHubIDcon = 0;
    if ( s_P2PmsgCon_HubID.Lookup((DWORD_PTR)pCon,nHubIDcon) ||
         s_P2PexpCon_HubID.Lookup((DWORD_PTR)pCon,nHubIDcon) ||
         nHubIDcon                                             )
      EVERR->Module  ("%s(nHubID=%i,pP2PmsgCon)", __FUNCTION__
                     , nHubID )
           ->Message ("P2PmsgCon object already posted" )
           ->Throw();

    // Post
    // NOTES: This is a bit flacky and requires a rework
    P2PsafeCS   oSafeCSPump = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump = 0;
    if ( s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) &&
         pP2PmsgPump                                                    &&
         pP2PmsgPump->m_bP2Pexplorer                                       ) 
      pP2PmsgHub -> PostP2PexpCon ( spCon.Dereference() );
    else
      pP2PmsgHub -> PostP2PmsgCon ( spCon.Dereference() );
}

void
DropP2PmsgCon ( P2PeerCon *pCon )
{
    // P2PmsgHubID cross reference
    // NOTES: F-S5-5.  A connection is registered in ONE of two parallel
    //        registries - s_P2PmsgCon_HubID for a hub connection, s_P2PexpCon
    //        _HubID for one posted to an explorer - and this function, the ONLY
    //        caller of which is P2PeerConPlc::Release() immediately before
    //        `delete this` (P2PeerCon.cpp:4461), consulted the first one alone.
    //        So an explorer connection was deleted while still listed in
    //        m_oCListP2PexpCon and still keyed in s_P2PexpCon_HubID.  Two
    //        consequences, and the second is the worse one: EnumP2PexpCon()
    //        walks that list and dereferences whatever is in it, and every
    //        s_P2PexpCon_HubID lookup is keyed on the raw ADDRESS - so once the
    //        allocator hands that address to something else, an unrelated
    //        object answers "yes, I am a registered explorer connection of hub
    //        N".  Measured: a sweep of m_oCListP2PexpCon at expump close took a
    //        heap-use-after-free on the connection phase 4 had already dropped.
    //      : Which registry it is decides which list to unlink it from; the
    //        rest of the sequence is identical, so it is a lookup and a branch
    //        rather than a second function.
    P2PmsgHubID nHubID  = 0;
    P2PsafeCS   oSafeCS = s_oCSectionP2PmsgHub;
    bool        bExpCon = false;
    if ( !s_P2PmsgCon_HubID.Lookup((DWORD_PTR)pCon,nHubID) )
    {
      if ( !s_P2PexpCon_HubID.Lookup((DWORD_PTR)pCon,nHubID) )
        return;
      bExpCon = true;
    }

    // P2PmsgHub cross reference
    P2PmsgHubMgr *pP2PmsgHub = 0;
    s_ThreadID_P2PmsgHub.Lookup ( nHubID, pP2PmsgHub );
    if ( pP2PmsgHub )
    {
      pCon -> Drop ( 0 );
      pCon -> Destroy ( );
      if ( bExpCon )
        pP2PmsgHub -> DropP2PexpCon ( pCon );
      else
        pP2PmsgHub -> DropP2PmsgCon ( pCon );
    }
    else
    {
      // The hub is gone, and the key is not the hub's to own.
      // NOTES: ~P2PmsgHubMgr does s_ThreadID_P2PmsgHub.RemoveKey, so a connection
      //        released after its hub was destroyed finds no hub here. The whole
      //        block above was then skipped -- including the RemoveKey that the
      //        hub's own DropP2PmsgCon/DropP2PexpCon performs -- and the ONLY
      //        caller of this function is P2PeerConPlc::Release() immediately
      //        before `delete this`. So the object was deleted with its address
      //        still keyed in one of the two registries.
      //      : Both registries are keyed on the raw ADDRESS. Once the allocator
      //        hands that address to the next P2PeerCon, PostP2PmsgCon's guard
      //        looks it up, finds the dead connection's entry and refuses the
      //        live one with "P2PmsgCon object already posted" -- an abort on a
      //        thread, in whichever phase happened to draw the reused address.
      //        This is F-S5-5's hazard in the path that was meant to close it:
      //        that fix repaired the wrong-registry half and left this one.
      //      : Nothing else here applies without a hub. Drop(0) and Destroy()
      //        need one, and there is no list left to unlink from; the key is
      //        the one thing that outlives the hub and must not.
      if ( bExpCon )
        s_P2PexpCon_HubID.RemoveKey ( (DWORD_PTR)pCon );
      else
        s_P2PmsgCon_HubID.RemoveKey ( (DWORD_PTR)pCon );
    }
}

int
GetP2PmsgHubConCount ( P2PmsgHubID nHubID )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      ASSERT(pP2PmsgPump);
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS    = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("nHubID=%i has no P2PmsgHub context"
                    , nHubID )
           ->Throw  ( );

    // Post
    return (int)pP2PmsgHub->m_oCListP2PmsgCon.GetCount();
}

///////////////////////////////////////////////////////////////////////
//  Hub observability
//  NOTES: Stage 4 step 13.  P2PeerHub::Serialise() reports
//         all three, so everything that already receives a hub snapshot - the
//         MSG_P2PexpHub reply, and every P2Pevent carrying hub state - gains
//         them without asking for anything and without being instrumented
//       : NONE OF THEM THROWS, which is what separates them from every other
//         accessor on this page.  Answering "which hub?" with a throw is right
//         when a caller has NAMED a hub and wants a fact about it.  These are
//         called by the code that BUILDS a diagnostic, and a hub being torn
//         down while its own snapshot is taken is ordinary rather than
//         exceptional - a throw there turns "the hub has gone" into a second
//         fault raised from inside the report of the first.  A hub that does
//         not exist has nothing queued and has accepted nothing, and 0 says
//         precisely that
//       : Lock order is HUB then PUMP, which is CreateP2PmsgHub()'s order.
//         QueryP2PmsgExp_Hub() used to take the pump lock and then call
//         Serialise(); it now takes the hub lock first, so that these cannot
//         invert the order from underneath it

//
//  Resolves a P2PmsgHubID to its manager without throwing
//  NOTES: Resolution only - the caller holds the locks, because the pointer
//         is worthless the moment they are dropped
static P2PmsgHubMgr*
LookupP2PmsgHubMgr ( P2PmsgHubID& nHubID )
{
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        return 0;
      // The hub's OWN pump carries m_nHubID 0: it predates the hub, because
      // CreateP2PmsgHub() adopts the pump the calling thread already has
      // rather than manufacturing one, and never stamps the ID onto it.  A
      // hub's ID IS the thread ID of the thread that created it (refer
      // P2PmsgHubMgr's constructor), so falling back to the calling thread's
      // own ID is not a guess
      nHubID = pP2PmsgPump->m_nHubID ? pP2PmsgPump->m_nHubID
                                     : (P2PmsgHubID)GetCurrentThreadId();
    }

    P2PmsgHubMgr *pP2PmsgHub = 0;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) )
      return 0;
    return pP2PmsgHub;
}

//
//  P2Pmsg's queued and not yet dispatched, across the whole hub
//
//  Parameters:  P2PmsgHubID nHubID
//                 0.. The hub of the calling thread
//
//  Returns:     UINT
//               Queue depth, 0 for a hub that does not exist
UINT
GetP2PmsgHubQueCount ( P2PmsgHubID nHubID )
{
    // The environment has to be started before its critical sections exist
    if ( !s_apP2PmsgHubMgr )
      return 0;
    P2PsafeCS     oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS     oSafeCS_Pump = s_oCSectionP2PmsgPump;
    P2PmsgHubMgr *pP2PmsgHub   = LookupP2PmsgHubMgr ( nHubID );
    if ( !pP2PmsgHub )
      return 0;

    // The hub's own pump is NOT in m_oCListP2PmsgPump - that list holds the
    // pumps the hub MANUFACTURED (CreateP2PmsgPump, CreateP2Pexplorer), and
    // the hub's own was adopted.  It is reached by thread ID instead, which
    // for that pump is the hub ID itself
    UINT        uQueued = 0;
    P2PmsgPump *pOwn    = 0;
    if ( s_ThreadID_P2PmsgPump.Lookup((DWORD_PTR)nHubID,pOwn) && pOwn )
      uQueued += pOwn -> GetCount ( );

    POSITION pos = pP2PmsgHub->m_oCListP2PmsgPump.GetHeadPosition();
    while ( pos )
    {
      P2PmsgPump *pPump = pP2PmsgHub->m_oCListP2PmsgPump.GetNext(pos);
      if ( pPump && pPump != pOwn )       // never count the same pump twice
        uQueued += pPump -> GetCount ( );
    }
    return uQueued;
}

//
//  Connections currently ACCEPTED by this hub's services
//
//  Parameters:  P2PmsgHubID nHubID
//                 0.. The hub of the calling thread
//
//  Returns:     UINT
//               Live accepted connections, 0 for a hub that does not exist
UINT
GetP2PmsgHubAcceptedCount ( P2PmsgHubID nHubID )
{
    if ( !s_apP2PmsgHubMgr )
      return 0;
    P2PsafeCS     oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS     oSafeCS_Pump = s_oCSectionP2PmsgPump;
    P2PmsgHubMgr *pP2PmsgHub   = LookupP2PmsgHubMgr ( nHubID );
    if ( !pP2PmsgHub )
      return 0;

    // SERVICE connections only, and the exclusion is not tidiness.
    // P2PeerCon::AcceptSpawn() hands the child a SHARE of the service's
    // counter - m_pxAccepted is a shared_ptr on purpose, so that neither has
    // to outlive the other - so a CHILD's GetAcceptedCount() returns the
    // SERVICE's total, not its own.  Summing over every connection in the
    // list would report N accepted connections as N*(N+1), and would do it in
    // the one field an operator is being invited to alarm on
    UINT     uAccepted = 0;
    POSITION pos = pP2PmsgHub->m_oCListP2PmsgCon.GetHeadPosition();
    while ( pos )
    {
      P2PeerCon *pCon = pP2PmsgHub->m_oCListP2PmsgCon.GetNext(pos);
      if ( pCon && pCon->GetMode() == P2PeerCon_SERVICE )
        uAccepted += (UINT)pCon->GetAcceptedCount ( );
    }
    return uAccepted;
}

//
//  Holds applied to this hub's connections since each was accepted
//  NOTES: Stage 4 step 12.  Every connection in the list, not services only -
//         unlike Accepted above, this tally is the connection's own and is
//         shared with nobody, so there is nothing to double-count
//       : A dropped connection takes its tally with it.  That is the right
//         reading for a field an operator watches to answer "is this hub under
//         pressure now"; the process-wide GetP2PmsgHeldCount() is the one that
//         never forgets
//
//  Parameters:  P2PmsgHubID nHubID
//                 0.. The hub of the calling thread
//
//  Returns:     UINT
//               Cumulative holds, 0 for a hub that does not exist
UINT
GetP2PmsgHubHeldCount ( P2PmsgHubID nHubID )
{
    if ( !s_apP2PmsgHubMgr )
      return 0;
    P2PsafeCS     oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS     oSafeCS_Pump = s_oCSectionP2PmsgPump;
    P2PmsgHubMgr *pP2PmsgHub   = LookupP2PmsgHubMgr ( nHubID );
    if ( !pP2PmsgHub )
      return 0;

    UINT     uHeld = 0;
    POSITION pos = pP2PmsgHub->m_oCListP2PmsgCon.GetHeadPosition();
    while ( pos )
    {
      P2PeerCon *pCon = pP2PmsgHub->m_oCListP2PmsgCon.GetNext(pos);
      if ( pCon )
        uHeld += (UINT)pCon->GetRecvThrottleCount ( );
    }
    return uHeld;
}

//
//  Pump ceiling this hub was created with
//  NOTES: Exposed because the hub snapshot has always carried a PumpsMax
//         field and has always filled it with a literal 0 - refer
//         P2PeerHub::Serialise().  A field that reports a constant is worse
//         than an absent one: an operator reading it concludes the hub can
//         run no pumps at all
//
//  Parameters:  P2PmsgHubID nHubID
//                 0.. The hub of the calling thread
//
//  Returns:     UINT
//               Configured maximum, 0 for a hub that does not exist
UINT
GetP2PmsgHubPumpsMax ( P2PmsgHubID nHubID )
{
    if ( !s_apP2PmsgHubMgr )
      return 0;
    P2PsafeCS     oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS     oSafeCS_Pump = s_oCSectionP2PmsgPump;
    P2PmsgHubMgr *pP2PmsgHub   = LookupP2PmsgHubMgr ( nHubID );
    return pP2PmsgHub ? pP2PmsgHub->m_nPumpsMax : 0;
}

BOOL
EnumP2PmsgCon    ( P2PmsgHubID nHubID, P2PeerCon **ppCon )
{
    // Handle unspecified nHubID
    // NOTES: Perform P2PmsgPump lookup
    if ( nHubID <= 0 )
    {
      P2PmsgPump *pP2PmsgPump = 0;
      P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->Message("ThreadID=%i has no P2PmsgPump context"
                      , GetCurrentThreadId() )
             ->Throw  ( );
      nHubID = pP2PmsgPump -> m_nHubID;
    }

    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS    = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->MODULE
           ->Message("nHubID=%i has no P2PmsgHub context"
                    , nHubID )
           ->Throw  ( );
    if ( !ppCon )
      return pP2PmsgHub->m_oCListP2PmsgCon.GetCount() ? TRUE : FALSE;

    // Initialisation
    POSITION pos = pP2PmsgHub->m_oCListP2PmsgCon.GetHeadPosition();
    if ( *ppCon == 0 && pos )
    {
      *ppCon = pP2PmsgHub->m_oCListP2PmsgCon.GetNext(pos);
       return TRUE;
    }

    // Interation
    while ( pos )
    {
      P2PeerCon *pCon = pP2PmsgHub->m_oCListP2PmsgCon.GetNext(pos);
      if ( pCon == *ppCon && pos )
      {
        *ppCon = pP2PmsgHub->m_oCListP2PmsgCon.GetNext(pos);
         return TRUE;
      }
    }

    // Tidy up, and
    *ppCon = 0;
    return FALSE;
}

P2PeerCon*
NextP2PmsgCon    ( DWORD eMsgCon );

/*P2PeerTarget*                          // P2PeerHub management
GetP2PmsgHub     ( P2PmsgHubID nHubID );*/

bool
P2PmsgHubExists ( P2PmsgHubID nHubID )
{
    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS    = s_oCSectionP2PmsgHub;
    if (  s_ThreadID_P2PmsgHub.GetCount() <= 0           ||
         !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      return false;

    // Exists
    return true;
}

BOOL
SignalP2PmsgHub ( P2PmsgHubID nHubID, P2PsigID nSigID )
{
    // Isolate the hub
    P2PmsgPump *pP2PmsgPump = 0;
    P2PsafeCS     oSafeCS   = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nHubID,pP2PmsgPump) ||
         !pP2PmsgPump                                         )
      return FALSE;

    // Signal P2PmsgHub.
    // Hold s_oCSectionP2PmsgPump (oSafeCS, acquired above) for the WHOLE body rather than
    // releasing it here: CloseP2PmsgHub() takes that same global across its
    // `delete pP2PmsgHub`, which now destroys the pump (~P2PmsgHubMgr). The old code
    // reassigned oSafeCS to the pump's own m_oCSection — releasing the global — so the pump
    // thread could free the pump (and that m_oCSection) while this signaller was still
    // inside it, a use-after-free on teardown (ASan, Phase-5 stress). Keeping the global
    // held makes signal vs destroy mutually exclusive (if destroy wins, the Lookup above
    // fails); the pump's m_oCSection is taken as a NESTED lock, still guarding
    // m_oCListP2PsigID against the pump thread's read.
    P2PsafeCS oSafeCSPump = pP2PmsgPump -> m_oCSection;
    pP2PmsgPump -> m_oCListP2PsigID.AddTail ( nSigID );

    // Initiate
    pP2PmsgPump -> Wakeup ( nHubID );
    return TRUE;
}

void
CloseP2PmsgHub ( )
{
    // Locals
    // NOTES: P2PmsgHub environment isolation, keep to completion
    //      : Confirm hub associated with this thread
    P2PmsgHubID nHubID       = GetCurrentThreadId();
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nHubID,pP2PmsgPump) )
      return;
    if ( pP2PmsgPump                                     &&
         pP2PmsgPump->m_nPumpID != pP2PmsgPump->m_nHubID    )
      EVERR->MODULE
           ->Message("Invalid operation from P2PmsgPump context" )
           ->Advice ("CloseP2PmsgHub() is invalid for P2PmsgPump's" )
           ->Throw  ( );

    // Isolate P2PmsgHub
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    s_ThreadID_P2PmsgHub.Lookup ( nHubID, pP2PmsgHub );

    // Posted P2PeerCon objects
    // NOTES: Destroy()+Drop() DELETE connections out of m_oCListP2PmsgCon --
    //        the swept one itself (Drop -> final Release -> DropP2PmsgCon,
    //        which RemoveAt()s it) and, for a listening con, the accepted
    //        clones it owns.  A POSITION walk cannot survive that: GetNext()
    //        has already advanced pos to the NEXT node, so when the deleted
    //        connection is that one, the following iteration dereferences
    //        freed memory.  Observed from the facade's hub-churn test as an
    //        access violation on one run and a fail-fast (0xC0000409) on the
    //        next, at a different connection each time.
    //      : So never hold a POSITION across Destroy()/Drop().  Re-derive it
    //        from an index each pass: a connection that retires itself
    //        shrinks the list and the index stays put (the next one shifts
    //        into the slot); one that survives -- it still has in-flight ops,
    //        which the drain loop below releases -- is stepped over.  Every
    //        pass either shrinks the list or advances the index, so this
    //        terminates; and a connection visited twice is harmless, since
    //        Destroy() only latches the atomic m_bDestroy (P2PeerCon.h:122).
    // Pin every connection across the sweep AND the drain (D33)
    // NOTES: The drain below can be handed more than one completion for the same
    //        connection, and DrainOVERLAPPED()'s Release() may be that connection's
    //        last.  Retiring it there leaves the loop holding a raw pointer to freed
    //        memory, and the next lap loads its VTABLE to make the very same call -
    //        free and read one source line apart, one lap apart.  Measured on Linux/
    //        ASan as an intermittent abort in p2pweb_w2/w5/w6 (D33), always after the
    //        suite itself had passed, because it is teardown and nothing else.
    //      : A reference held here for the WHOLE drain is what the loop was missing.
    //        Not a liveness test at the point of use: that was written and taken back
    //        out, because skipping a completion whose connection has retired strands
    //        its OVERLAPPEDcon and buffers - LSan reported 28 blocks, 99306 bytes,
    //        every one INDIRECT, i.e. with no live root at all.  The completion still
    //        owns memory that only DrainOVERLAPPED() frees, so the answer is to keep
    //        the owner alive to receive it, not to drop it on the floor.
    //      : Taken BEFORE the sweep, so Destroy()+Drop() cancels every operation
    //        without retiring anything, the drain then sees a stable list, and the
    //        release below retires them in one pass when no completion can arrive
    //        again.  Cancel everything, drain everything, THEN let go.
    //      : It also makes the sweep's index walk trivial - nothing leaves the list
    //        while it runs - though that walk is left exactly as it was, because it
    //        is correct either way and is what runs on the paths this does not touch.
    CList<P2PeerCon*> oConPinned;
    {
      POSITION posPin = pP2PmsgHub->m_oCListP2PmsgCon.GetHeadPosition ( );
      while ( posPin )
      {
        P2PeerCon *pConPin = pP2PmsgHub->m_oCListP2PmsgCon.GetNext ( posPin );
        if ( pConPin )
        {
          pConPin -> AddRef ( );
          oConPinned.AddTail ( pConPin );
        }
      }
    }

    for ( INT_PTR iCon = 0; iCon < pP2PmsgHub->m_oCListP2PmsgCon.GetCount(); )
    {
      POSITION posCon = pP2PmsgHub->m_oCListP2PmsgCon.FindIndex ( iCon );
      if ( !posCon )
        break;

      P2PeerCon *pCon    = pP2PmsgHub->m_oCListP2PmsgCon.GetAt ( posCon );
      INT_PTR    nBefore = pP2PmsgHub->m_oCListP2PmsgCon.GetCount();

      pCon -> Destroy ( );
      pCon -> Drop ( 0 );

      if ( pP2PmsgHub->m_oCListP2PmsgCon.GetCount() >= nBefore )
        iCon++;                    // nothing left the list -- step over it
    }

    // Drain the queued and cancelled in-flight OVERLAPPEDcon objects (§5.6).
    // NOTES: The Destroy()+Drop() sweep above set m_bDestroy on every con and,
    //        via Drop()->CloseHandle(m_hFile), cancel_fd'd each con's in-flight
    //        io_uring ops.  Every drained completion Release()s the ref that
    //        prepareOVERLAPPED() took; when a con's ops are all drained its
    //        refcount reaches 0 and the final Release() self-deletes it (via
    //        DropP2PmsgCon, removing it from m_oCListP2PmsgCon).
    //      : A cancelled op completes with ERROR_OPERATION_ABORTED, for which
    //        GetQueuedCompletionStatus returns FALSE but STILL yields its
    //        OVERLAPPED - it MUST be drained, not treated as "no completion".
    //        The old `while(GQCS(...))` stopped at the first cancellation, so a
    //        con's cancelled recv/connect was never drained and the con leaked
    //        (Phase-5 stress). Loop on lpOverlapped instead: null == genuinely
    //        no more completions (timeout).
    //      : On Linux CloseHandle(fd) already erased the io_uring fd->key assoc,
    //        so the cancelled completion comes back KEYLESS (key 0). Recover the
    //        owning con from the OVERLAPPEDcon's stable pOwnerCon (set at
    //        MakeOVERLAPPED) - which is DrainConOfOVERLAPPED()'s job, along with
    //        checking that the con it names has not already retired in this very
    //        loop.  This comment used to end 'the con is still alive because its
    //        in-flight OVL holds the ref we are about to release', which is true
    //        of the FIRST completion belonging to a connection and false of every
    //        one after the last - and DrainOVERLAPPED() releasing a ref it had
    //        never taken (D33) made 'after the last' reachable.  An invariant that
    //        holds per-connection is not an invariant of a loop over completions.
    //      : DrainOVERLAPPED() (not releaseOVERLAPPED()) also frees the transient
    //        control/Signal OVERLAPPEDs (e.g. the P2PsigCon_DESTROY RunHub posts
    //        on close) that the bypassed live pump would have freed.
    //      : D40.  Shared with CloseP2Pexpump() rather than written out again -
    //        refer DrainPortOfOVERLAPPED() for why the zero-timeout poll this
    //        used to be leaked a connection that was still owed a completion.
    DrainPortOfOVERLAPPED ( pP2PmsgPump, oConPinned );

    // Release the pins, retiring every connection whose last reference this was
    // NOTES: Ordinary Release(), so a connection still referenced elsewhere survives
    //        and one that is not is deleted here - after the drain, which is the
    //        point.  ~P2PeerCon reclaims the four member OVERLAPPEDs it still owns,
    //        and no completion can name it any more because the port is drained.
    {
      POSITION posPin = oConPinned.GetHeadPosition ( );
      while ( posPin )
        oConPinned.GetNext ( posPin ) -> Release ( );
      oConPinned.RemoveAll ( );
    }

    // Tidy up, and
    delete pP2PmsgHub;
    return;
}

///////////////////////////////////////////////////////////////////////
//  P2PmsgPump management
//  NOTES: Manage the creation, operation and life cycle of
//         P2PmsgPump's.
//       : Act as priority queues for P2Pmsg's 

static
DWORD            s_cIOCmsg = 0;

//
//  Creates P2PmsgPump
//  NOTES: Pumps are only ever created in the context of the thread
//         under which they run
//
//
//  Parameters:  P2PmsgHubID nHubID
//               Supervisory P2PmsgHub identification
//
//               LPCTSTR lpszPumpName
//               Name allocated to pump
//
//               P2PeerTarget *pTarget
//               Initial target through which P2Pmsg's are pumped
//
//  Returns      P2PumpID
//               Allocated pump identification
//
P2PumpID
CreateP2PmsgPump ( P2PmsgHubID nHubID, LPCTNAM lpszName
                 , P2PeerTarget *pTarget )
{
    P2PsafeCS oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    P2PsafeCS oSafeCS_Pump = s_oCSectionP2PmsgPump;
    // Locals
    // NOTES: P2PmsgPump environment isolation, keep to completion
    //      : Confirm pump not already associated with this thread
    P2PmsgPump *pP2PmsgPump  = 0;
    if ( s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         pP2PmsgPump                                                       )
      EVERR->Module ("%s(nHubID=%i,pTarget)", __FUNCTION__
                    , nHubID )
           ->Message("ThreadID=%i already has P2PmsgPump context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module ("%s(nHubID=%i,pTarget)", __FUNCTION__
                    , nHubID )
           ->Message("Nominated nHubID=%i does not exist", nHubID )
           ->Throw  ( );

    // To be sure, to be sure
    if ( pP2PmsgHub->m_oCListP2PmsgPump.GetCount() >= (INT_PTR)pP2PmsgHub->m_nPumpsMax )
      EVERR->Module ("%s(nHubID=%i,pTarget)", __FUNCTION__
                    , nHubID )
           ->Message("Attempt to exceed configured pump limit (%i) for hub"
                    , pP2PmsgHub->m_nPumpsMax )
           ->Throw  ( );

    // Create P2PmsgPump
    // NOTES: Mandatory for P2PmsgPump to be attached to P2PmsgHub
    pP2PmsgPump  = pP2PmsgHub  -> CreateP2PmsgPump ( );
    pP2PmsgPump -> m_pTarget   = pTarget;
    pP2PmsgPump -> m_hQueEvent = CreateEvent ( 0, FALSE, FALSE, 0 );
    pP2PmsgPump -> m_bOwnQueEvent = true;         // F-S5-4: ours to close
    pP2PmsgPump -> m_oP2Paddr  = lpszName;
    pP2PmsgPump -> m_csName    = lpszName;

    // Tidy up, and
    return pP2PmsgPump->m_nPumpID;
}

BOOL
EnumP2PmsgPump ( P2PmsgHubID nHubID, P2PumpID& nPumpID )
{
    // Isolate the hub
    P2PmsgHubMgr *pP2PmsgHub = 0;
    P2PsafeCS     oSafeCS    = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      return FALSE;

    // Locate next
    P2PmsgPump *pP2PmsgPump;
    POSITION pos = pP2PmsgHub->m_oCListP2PmsgPump.GetHeadPosition();
    while ( pos )
    {
      pP2PmsgPump = pP2PmsgHub->m_oCListP2PmsgPump.GetNext(pos);
      if ( nPumpID == 0 )
      {
        nPumpID = pP2PmsgPump->m_nPumpID;
        return TRUE;
      }
      if ( nPumpID == pP2PmsgPump->m_nPumpID )
        nPumpID = 0;
    }

    // End-of-List
    nPumpID = (P2PumpID)~0;
    return FALSE;
}

//
//  Fetches the P2PumpID for the current thread context
//  NOTES: Use IsP2PmsgPump() to establish P2PmsgPump context
//
//
//  Returns      P2PumpID
//               Identification of P2PmsgPump associated with
//               current thread context
P2PumpID
GetP2PmsgPumpID ( )
{
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                       )
      EVERR->MODULE
           ->Message("ThreadID=%i has no P2PmsgPump context"
                    , GetCurrentThreadId() )
           ->Throw  ( );
    return pP2PmsgPump -> m_nPumpID;
}

P2PaddrSTR
GetP2PmsgPumpName ( P2PumpID nPumpID )
{
    // Preamble
    if ( nPumpID <= 0 )
      nPumpID = GetCurrentThreadId();

    // Implementation
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                                       )
      EVERR->MODULE
           ->Message(_T("ThreadID=%i has no P2PmsgPump context")
                    , nPumpID )
           ->Throw  ( );
    return pP2PmsgPump -> m_csName;
}

P2PaddrSTR
SetP2PmsgPumpFunc ( P2PumpID nPumpID, LPCTNAM lpszFunc )
{
    // Preamble
    if ( nPumpID <= 0 )
      nPumpID = GetCurrentThreadId();

    // Implementation
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      EVERR->MODULE->AFP(nPumpID)->AFP(lpszFunc)
           ->Message(_T("ThreadID=%i has no P2PmsgPump context")
                    , nPumpID )
           ->Throw  ( );
    return pP2PmsgPump -> m_strFunc = lpszFunc;
}

Targetcore_EXT HANDLE
GetP2PmsgPumpHANDLE ( )
{
    // Preamble
    P2PumpID nPumpID = GetCurrentThreadId();

    // Implementation
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      EVERR->MODULE->AFP(nPumpID)
           ->Message(L"ThreadID=%i has no P2PmsgPump context", nPumpID )
           ->Throw  ( );
    return pP2PmsgPump -> m_hQueEvent;
}

UINT
PostP2Pmsg ( P2PaddrSTR strP2Paddr, UINT nCode, P2Pmsg_t nMsg
           , P2PeerCon *pCon, P2PeerMsg *pMsg, P2PumpID nPumpID )
{
    // Preamble
    if ( nPumpID <= 0 )
      nPumpID = GetCurrentThreadId();
ASSERT(nMsg!=2838);

    // Isolate P2PmsgPump environment
    P2PmsgPump *pP2PmsgPump = 0;
    P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      EVERR->MODULE
           ->Message("ThreadID=%i has no P2PmsgPump context"
                    , GetCurrentThreadId() )
           ->Throw  ( );

    // Isolate P2PmsgPump
    // NOTES: Mandatory for P2PmsgPump to be attached to P2PmsgHub
    oSafeCS = pP2PmsgPump -> m_oCSection;

    // Observe P2PmsgQue capacity
    if ( s_cP2Pmsg > s_cP2PmsgMAX )
      EVERR->MODULE
           ->Message(P2PMSG_QUEFULL_FMT, (unsigned long)s_cP2PmsgMAX )
           ->Advice ("Refer PumpP2Pmsg()" )
           ->HResult(P2Pevent_QUEFULL)
           ->Throw  ( );

    // P2PeerCon touch-up's
    // NOTES: Enumeration is suspended whilst object exists in the
    //        P2Pmsg domain
    if (  pCon &&
         !pCon->m_hCPort )
      pCon -> m_hCPort = pP2PmsgPump -> m_hIOCP;

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> strP2Paddr   = strP2Paddr;
            pP2Pmsg -> nCode        = nCode;
            pP2Pmsg -> nMsg         = nMsg;
            pP2Pmsg -> pCon         = pCon;
            if ( pCon )
              pCon -> AddRef ( );
            pP2Pmsg -> pMsg         = pMsg;
            pP2Pmsg -> pTarget      = pP2PmsgPump -> m_pTarget;
            pP2Pmsg -> bNotify      = false;
ASSERT(VerifyP2Pmsg(pP2Pmsg));

    // Implementation
    return pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, false );
}

// Fwd decls: defined below (after this helper), used by TryInlineDispatchP2Pmsg
P2Pmsg* PreTranslateP2Pmsg ( P2Pmsg *pP2Pmsg );
void    TranslateP2Pmsg    ( P2Pmsg *pP2Pmsg );
void    DispatchP2Pmsg     ( P2Pmsg *pP2Pmsg, P2PmsgPump *pP2PmsgPump );

//
//  Description: W3 (p2p_PumpPerf.md) - inline recv->dispatch of an inbound
//               application P2PeerMsg, bypassing the pump's own FIFO.
//               NOTES: The recv completion (On_QueuedCompletionStatus) already
//                      runs on the destination pump thread, so re-posting the
//                      parsed frame to that pump's FIFO only to dequeue and
//                      dispatch it a loop-iteration later is a redundant
//                      same-thread hop (PutP2Pmsg enqueue + GetP2Pmsg dequeue +
//                      one extra PumpP2Pmsg visit).  This dispatches it in place.
//                    : Guarded twice for safety.  (1) local-only: nPumpID must
//                      be THIS thread's pump, else fall back so cross-pump
//                      routing is unchanged.  (2) ordering: the pump FIFO must
//                      be empty (checked under m_oCSection, the same lock
//                      GetP2Pmsg/PutP2Pmsg take), so nothing queued ahead can be
//                      overtaken - the per-connection FIFO order contract holds.
//                      Any other case returns false and the caller uses the
//                      6-arg PostP2Pmsg (FIFO) exactly as before.
//                    : Lifecycle mirrors the FIFO path: P2PmsgFactory()
//                      (s_cP2Pmsg++), set m_pP2Pmsg for CheckP2PmsgPumpState
//                      fidelity, then PreTranslate/Translate/Dispatch - and
//                      DispatchP2Pmsg's tail ReleaseP2Pmsg() frees the P2Pmsg +
//                      its pMsg and does the balancing s_cP2Pmsg--.
//
//  Returns:     bool - true if dispatched inline, false to fall back to FIFO.
//
bool
TryInlineDispatchP2Pmsg ( P2PaddrSTR strP2Paddr, P2PeerMsg *pMsg, P2PumpID nPumpID )
{
    // Guard 1 - local pump only (the recv completion's own pump thread)
    if ( nPumpID <= 0 )
      nPumpID = GetCurrentThreadId();
    if ( nPumpID != GetCurrentThreadId() )
      return false;

    // Resolve the pump
    P2PmsgPump *pP2PmsgPump = 0;
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
           !pP2PmsgPump                                          )
        return false;
    }

    // Guard 2 - ordering: only inline when nothing is queued ahead
    {
      P2PsafeCS oSafeCS = pP2PmsgPump -> m_oCSection;
      if ( pP2PmsgPump -> m_oCListP2Pmsg.GetCount() != 0 )
        return false;
    }

    // Manufacture exactly as the 6-arg PostP2Pmsg (pCon == 0 app message:
    // CN_P2PeerMsg, nMsg 0), then dispatch in place instead of PutP2Pmsg
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> strP2Paddr = strP2Paddr;
            pP2Pmsg -> nCode      = CN_P2PeerMsg;
            pP2Pmsg -> nMsg       = 0;
            pP2Pmsg -> pCon       = 0;
            pP2Pmsg -> pMsg       = pMsg;
            pP2Pmsg -> pTarget    = pP2PmsgPump -> m_pTarget;
            pP2Pmsg -> bNotify    = false;
ASSERT(VerifyP2Pmsg(pP2Pmsg));
    pP2PmsgPump -> m_pP2Pmsg = pP2Pmsg;   // CheckP2PmsgPumpState fidelity (cf. GetP2Pmsg)

    // Same PreTranslate/Translate/Dispatch as PumpP2Pmsg Step 2; DispatchP2Pmsg
    // releases pP2Pmsg (and pMsg) on every path (PreTranslate never returns 0).
    if ( PreTranslateP2Pmsg(pP2Pmsg) )
    {
      TranslateP2Pmsg ( pP2Pmsg );
      DispatchP2Pmsg  ( pP2Pmsg, pP2PmsgPump );
    }
    return true;
}
/*P2PeerMsg*
PostP2Pmsg ( P2PeerMsg *pMsg, P2PumpID nP2PumpID
           , bool bPrepend = false );
UINT
PostP2Pmsg ( DWORD hThreadID
           , P2Pmsg_t nMsg, WPARAM wParam, LPARAM lParam );

BOOL
RunP2PmsgPump ( );
BOOL
PumpP2Pmsg ( DWORD dwMSecs = 0 );*/

bool
P2PmsgPumpExists ( P2PumpID nPumpID )
{
    // Isolate P2PmsgPump environment
    P2PmsgPump  *pP2PmsgPump = 0;
    P2PsafeCS oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                                       )
      return false;                    // Nothing to cleanup

    // Exists
    return true;
}

bool
IsP2PmsgPumping ( P2PumpID nPumpID )
{
    // Preamble
    if ( nPumpID <= 0 )
      nPumpID = GetCurrentThreadId();

    // Isolate P2PmsgPump environment
    P2PmsgPump  *pP2PmsgPump = 0;
    P2PsafeCS oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      return false;                    // Nothing pumping

    // Exists
    return true;
}

BOOL
SignalP2PmsgPump ( P2PumpID nPumpID, P2PsigID nSigID )
{
    // Isolate the hub
    P2PmsgPump *pP2PmsgPump = 0;
    P2PsafeCS     oSafeCS   = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      return FALSE;

    // Signal P2PmsgHub.
    // Hold the pump's m_oCSection (nested under s_oCSectionP2PmsgPump) across the AddTail so
    // the signal queue has ONE consistent lock: SignalP2PmsgHub already takes it, and the pump
    // thread's SigCount()/SigPop() reads take it too (TSan Risk #3). Without this the pump
    // read raced this writer, which held only the global lock.
    P2PsafeCS oSafeCSPump = pP2PmsgPump -> m_oCSection;
    pP2PmsgPump -> m_oCListP2PsigID.AddTail ( nSigID );

    // Initiate
    pP2PmsgPump -> Wakeup ( nPumpID );
    return TRUE;
}

//
//  Closes P2PmsgPump environment and recovers resources
//  NOTES: Closed environments may be re-started
//
void
CloseP2PmsgPump ( )
{
    // Isolate P2PmsgPump environment
    // NOTES: Remove ThreadID-PumpID map entry.  After which the
    //        pump can no longer be addressed.
    P2PmsgPump  *pP2PmsgPump = 0;
    P2PsafeCS oSafeCS_Pump = s_oCSectionP2PmsgPump;
    if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
         !pP2PmsgPump                                                       )
      return;                          // Nothing to cleanup

    // Block out-of-context CloseP2PmsgHub()
    if ( pP2PmsgPump->m_nPumpID == pP2PmsgPump->m_nHubID )
      EVERR->MODULE
           ->Message("Invalid operation from P2PmsgHub context" )
           ->Advice ("Refer CloseP2PmsgHub()" )
           ->Throw  ( );
    SP2PmsgPump spP2PmsgPump = pP2PmsgPump;

    // Isolate P2PmsgHub
    // NOTES: Swap to P2PmsgHub environment isolation
    P2PmsgHubMgr  *pP2PmsgHub = 0;
    P2PsafeCS oSafeCS_Hub = s_oCSectionP2PmsgHub;
    if ( !s_ThreadID_P2PmsgHub.Lookup(pP2PmsgPump->m_nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                                       )
      return;                          // Nothing to cleanup
    oSafeCS_Hub = pP2PmsgHub -> m_oCSection;

    // Tidy up, P2PmsgPump table within P2PmsgPump
    pP2PmsgHub   -> RemoveP2PmsgPump ( spP2PmsgPump.p_SafePtr ( ) );
    spP2PmsgPump = 0;
}

///////////////////////////////////////////////////////////////////////
//  P2P[eerTarget] message translation and dispatch
//  NOTES: Manage the manufacture, translation, dispatch and
//         life cycle of P2P messages

//
//  Description: Releases resources associated with passed P2Pmsg
//               message
//               NOTES: Usage pP2Pmsg=ReleaseP2Pmsg(pP2Pmsg);
//
//
//  Parameters:  P2Pmsg *pP2Pmsg
//               P2PeerTarget message to be released
//
//  Returns:    (P2Pmsg *)0
//                 
P2Pmsg*
ReleaseP2Pmsg ( P2Pmsg *pP2Pmsg )
{
    // To be sure, to be sure
    if ( pP2Pmsg )
    {
      // Notifications
      if ( pP2Pmsg->bNotify )
        SetEvent ( pP2Pmsg->hEventHub );

      // Garbage collection
      if ( pP2Pmsg->pCon )
        pP2Pmsg -> pCon -> Release ( );
      if ( pP2Pmsg->pMsg )
        delete pP2Pmsg -> pMsg;
      if ( pP2Pmsg->pEvent )
        delete pP2Pmsg -> pEvent;
      if ( pP2Pmsg->pP3PmsgItem )
        delete pP2Pmsg->pP3PmsgItem;
      //if ( pP2Pmsg->pP3PmsgNode )
      //  delete pP2Pmsg->pP3PmsgNode;
      delete pP2Pmsg;
      s_cP2Pmsg--;
    }

    // Tidy up, and
    return (P2Pmsg *)0;
}

//
//  Stack based safe P2Pmsg container
//  NOTES: Releases the referenced P2Pmsg as the enclosing scope
//         unwinds, an escaping exception included.
//       : Binds the caller's pointer variable rather than its value,
//         because the context swaps reassign it - and zero it when
//         they take over the life cycle - before the release happens
class P2PsafeP2Pmsg
{
    public:
        P2PsafeP2Pmsg ( P2Pmsg *&rpP2Pmsg ) : m_rpP2Pmsg(rpP2Pmsg) { }
       ~P2PsafeP2Pmsg ( )
        {
          // To be sure, to be sure
          // NOTES: A destructor is implicitly noexcept, so a P2Pevent
          //        escaping here mid-unwind would terminate the
          //        process.  Cancel it, as the handlers do
          try
          {
            ReleaseP2Pmsg ( m_rpP2Pmsg );
          }
          catch ( P2Pevent *pEVT )
          {
            if ( pEVT )
              pEVT -> Cancel ( );
          }
          catch ( ... )
          {
          }
        }
    public:
        P2PsafeP2Pmsg ( const P2PsafeP2Pmsg& ) = delete;
      P2PsafeP2Pmsg&
        operator = ( const P2PsafeP2Pmsg& ) = delete;
    private:
        P2Pmsg *&m_rpP2Pmsg;
};

//
//  Pre-translation of P2Pmsg's
//  NOTES: The pre-translation processing assumes life
//         cycle control over passed P2Pmsg object
//
//
//  Parameters:  P2Pmsg *pP2Pmsg
//               Message to be pre-translated
//
//  Returns:     P2Pmsg*
//               Pre-translation summary
//                 pP2Pmsg.. Proceed with TranslateP2P() and
//                           DispatchP2P()
//                           NOTES: Caller assumes life cycle control
//                                  over this object
//                 0.......  Translated and no further processing
//                           required
//                           NOTES: Pre-translation sequences have
//                                  retained life cycle control
P2Pmsg*
PreTranslateP2Pmsg ( P2Pmsg *pP2Pmsg )
{
    // P2PeerMsg pre-translation
    if ( pP2Pmsg->pMsg                 &&
         pP2Pmsg->strP2Paddr.IsEmpty()    )
      pP2Pmsg -> strP2Paddr = pP2Pmsg -> pMsg -> GetSource();
    if ( pP2Pmsg->pMsg &&
        !pP2Pmsg->nMsg    )
      pP2Pmsg -> nMsg = P2P_P2Pmsg;//pP2Pmsg -> pMsg -> Type();

    // P2PeerCon objects dropped by default
    //if ( pP2Pmsg->pCon    )
    //  pP2Pmsg -> pCon -> SetAttributes ( WSAIOCTL_Drop, 0 );

    // Interceptions
    /*if ( pP2Pmsg->pMsg->c_name()[0] == _T('#') )
    {
      P2PeerMsg *pMsg = new P2PeerMsg ( );
      P3PmsgNode oNodeHub ( "Hub", P3PmsgData("HubName") );
                 oNodeHub += P3PmsgField ( "Pumps", 0 );
                 oNodeHub += P3PmsgField ( "Name", "name" );
                 oNodeHub += P3PmsgField ( "Address", "addr" );
                 oNodeHub += P3PmsgField ( "Adomain", "domain" );

      // Posted P2PeerCon's
      P2PeerCon *pCon = 0;
      while ( EnumP2PmsgCon(m_nHubID,&pCon) )
      { 
        P3PmsgNode oNodePump ( "Pump", P3PmsgData("PumpName") );
        const P2Paddr& oP2PaddrCon = pCon -> GetP2Paddress();
      }
      PostP2Pmsg ( pMsg, 0 );
    }*/ 

    // Tidy up, and
    return pP2Pmsg;
}

void
TranslateP2Pmsg ( P2Pmsg *pP2Pmsg )
{
    UNREFERENCED_PARAMETER(pP2Pmsg);
    // On_P2PeerCON_Close() translation
    // NOTES: No translation is currently required.  Dropping a closed
    //        connection is performed by the pump's conDROP path in
    //        PumpP2Pmsg(), not here

    // Tidy up, and
    return;
}

static mapRESULT
SwapContextP2Pmsg ( P2Pmsg **ppP2Pmsg, P2PmsgPump *pP2PmsgPump )
{
    // Locals
    P2Pmsg           *pP2Pmsg  = *ppP2Pmsg;
    P2Pmsg_ContextSP spContext =   pP2PmsgPump -> m_pContext;
                                   pP2PmsgPump -> m_pContext = 0;
    mapRESULT       mapResult  =    TRUE;
    // FIX-ME this is not necessarily so
    //ASSERT(pContext->pTarget==pTarget);

    if ( spContext.IsEmpty() )
      EVERR->Message("SwapContextP2Pmsg() ")
           ->Advice ("Reference from P2PeerCON, P2PeerSYS or "
                     "P2PeerMSG_MAP handlers only" )
           ->Throw();

    // ON_MESSAGE(pContext->nMsg,OnHandler) context for
    // nominated window
    if ( spContext->hWnd )
    {
      pP2Pmsg -> pTarget = spContext -> pTarget;
      if ( pP2Pmsg->pCon )
        pP2Pmsg -> bNotify = true;
      PostMessage ( spContext->hWnd, spContext->nWM_APP
                  ,(WPARAM)pP2Pmsg,(LPARAM)0 );
      *ppP2Pmsg = 0;
    }

    // Swap P2PmsgPump context
    else if ( spContext->nThreadID )
    {
      P2PsafeCS   oSafeCS         = s_oCSectionP2PmsgPump;
      P2PmsgPump *pP2PmsgSwap = 0;
      s_ThreadID_P2PmsgPump.Lookup(spContext->nThreadID,pP2PmsgSwap);
      if ( !pP2PmsgSwap )
        EVERR->Message("Context swap to inoperative P2PmsgPump")
             ->Throw();
      if ( pP2PmsgSwap->m_bP2Pexplorer )
        pP2Pmsg -> nCode |= CN_P2PeerExp;
      if ( pP2Pmsg->pCon )
        pP2Pmsg -> bNotify = true;
      pP2PmsgSwap -> PutP2Pmsg ( pP2Pmsg, false );
      *ppP2Pmsg = 0;
    }

    // Post P2PeerMsg to P2PeerCon object
    else if ( spContext->pCon &&
               pP2Pmsg ->pMsg    )
    {
      spContext -> pCon -> PostP2PeerMsg ( pP2Pmsg->pMsg );
      pP2Pmsg   -> pMsg = 0;
      // NOTES: The P2Pmsg is deliberately not released here.  This branch
      //        leaves *ppP2Pmsg live and DispatchP2Pmsg(), which owns it,
      //        releases it at its tail
    }

    // Swap P2PeerMsg context
    else if ( spContext->pMsg )
    {
      // To be sure, to be sure
      if ( pP2Pmsg->pMsg != spContext->pMsg )
        delete pP2Pmsg -> pMsg;
      pP2Pmsg -> pMsg       = spContext -> pMsg;
      pP2Pmsg -> nMsg       = P2P_P2Pmsg;//pMsg -> Type ( );
      pP2Pmsg -> strP2Paddr = spContext -> pMsg -> GetSource ( );
      pP2Pmsg -> pTarget    = spContext -> pTarget;
      mapResult = msgCONTINUE;
      //P2PmsgPump::GetP2PmsgPump() -> m_pContext = 0;
      //delete pContext;
      //goto TOP;
    }

    // Tidy up, and
    return mapResult;
}

static mapRESULT
RedirectP2Pmsg ( P2Pmsg **ppP2Pmsg, P2PmsgPump *pP2PmsgPump )
{
    // Locals
    P2Pmsg *pP2Pmsg  = *ppP2Pmsg;
    ASSERT(pP2PmsgPump->m_bRedirect);

    // Redirect P2PeerMsg
    if ( pP2PmsgPump->m_bRedirect )
    {
      pP2PmsgPump -> m_bRedirect = false;
      P2PmsgHubID nHubID = pP2PmsgPump -> m_nHubID;
      P2PmsgPump *pP2PmsgPumpHub = P2PmsgPump::GetP2PmsgPump(nHubID);
                  pP2PmsgPumpHub -> PutP2Pmsg ( pP2Pmsg, false );
      *ppP2Pmsg = 0;
    }

    // Tidy up, and
    return msgHANDLED;
}

//
//  Locates handler and dispatches contents of passed
//  P2PeerTarget message
//
//
//  Parameters:  P2Pmsg *pP2Pmsg
//               P2PeerTarget message
//
//  Returns:     P2P*
//               Dispatch summary
//                  0.... Handler located and message dispatched
//                 pP2P.. Not dispatched, handler not located
//
void
DispatchP2Pmsg ( P2Pmsg *pP2Pmsg, P2PmsgPump *pP2PmsgPump )
{
    // Introduce locals
    BOOL          bHandled;
    P2PeerTarget *pTarget;
    // P2Pmsg life cycle
    // NOTES: Declared ahead of TOP: so the context swap loop below
    //        cannot destroy and re-arm it.  Sole owner of the P2Pmsg
    //        from here on - see the NOTES at the tail
    P2PsafeP2Pmsg oSafeP2Pmsg ( pP2Pmsg );

    // From the top
    // NOTES: Entry point may be required by certain context swaps
TOP:bHandled = true;
    pTarget  = reinterpret_cast<P2PeerTarget *>(pP2Pmsg->pTarget);
    // Context swapping will generate exceptions
    try
    {
      // P2PeerCon_MAP routing
      // NOTES: Dispatch for implementation.
      if ( pP2Pmsg->nCode == CN_P2PeerCon )
      {
        bHandled = conDROP;
        if ( pP2Pmsg->nMsg != P2P_Destroy )
        {
          // Specialised processing
          // NOTES: Walks the full P2PeerHub registration tree
          bHandled = pTarget->On_P2PeerCon ( (P2PaddrSTR)pP2Pmsg -> strP2Paddr
                                           , pP2Pmsg -> nCode
                                           , pP2Pmsg -> nMsg
                                           , pP2Pmsg -> pMsg
                                           , pP2Pmsg -> pCon
                                           ,(P2P_CONHANDLERINFO *)0 );

          // Default processing
          // NOTES: Localised to the P2PeerHub
          if ( !bHandled )
            bHandled = pTarget->On_DefaultCon ( pP2Pmsg -> nCode
                                              , pP2Pmsg -> nMsg
                                              , pP2Pmsg -> pMsg
                                              , pP2Pmsg -> pCon
                                              ,(P2P_CONHANDLERINFO *)0 );

          // Not handled
          if ( bHandled == conTINUE )
            pTarget -> NotHandled ( pP2Pmsg->pCon, pP2Pmsg->nMsg );
          else if ( bHandled == conSWAP                    &&
                   !SwapContextP2Pmsg(&pP2Pmsg,pP2PmsgPump)   ) {
            goto TOP;
          }
        }
        //if ( !bHandled )
        //  pP2Pmsg -> pCon -> SetAttributes ( WSATTRIB_Drop, 0 );
        if ( bHandled == conDROP )
        {
          //DropP2PmsgCon ( pP2Pmsg->pCon );
          pP2Pmsg -> pCon -> Drop ( 0 );
          pP2Pmsg -> pCon -> Destroy ( );
          pTarget -> PreDestroyP2PeerCon ( pP2Pmsg->pCon, bHandled );
        }
        else
        {
          //pP2Pmsg -> pCon = 0;         // Rescue
        }

        // P2PmsgExplorer real-time state notifications
        //if ( s_bP2PmsgExp_P2PeerCon )
        //  Notify_P2PmsgExp_Con ( pP2Pmsg->pCon );
      }

      // To be sure, to be sure
      else if ( pP2Pmsg->pCon )        // Should not happen
        EVERR->MODULE
             ->Message  (L"Illogical P2PeerCon notification"
                         L"nCode=%i, nMsg=%i, P2PeerID[%s]"
                        , pP2Pmsg->nCode
                        , pP2Pmsg->nMsg
                        , (P2PaddrSTR)pP2Pmsg->strP2Paddr )
             ->Advice_T ("P2PeerCon object dropped")
             ->Advice_T ("Bug(SNHappen)" )
             ->Cancel();

      // P2PeerMsg_MAP routing
      // NOTES: Dispatch for implementation
      else if ( pP2Pmsg->nCode           == CN_P2PeerMsg               &&
                pTarget->GetP2PaddrHub() == pP2Pmsg->pMsg->GetDestin()    )
      {
        bHandled = pTarget -> PeekP2PeerMsg ( pP2Pmsg->pMsg );
        if ( bHandled == msgCONTINUE )
          bHandled = pTarget->On_P2PeerMsg ( (P2PaddrSTR)pP2Pmsg -> strP2Paddr 
                                           , pP2Pmsg -> nCode 
                                           , pP2Pmsg -> nMsg
                                           , pP2Pmsg -> pMsg
                                           , pP2Pmsg -> pExtra
                                           ,(P2P_MSGHANDLERINFO *)0 );
        if ( bHandled == msgCONTINUE )
          pTarget -> NotHandled ( pP2Pmsg->pMsg );
        else if (  bHandled == msgSWAP                    &&
                  !SwapContextP2Pmsg(&pP2Pmsg,pP2PmsgPump)   ) {
          goto TOP;
        }
        else if (  bHandled == msgREPUMP ) {
          goto TOP;
        }
        if ( bHandled == msgREDIRECT )
          bHandled = RedirectP2Pmsg(&pP2Pmsg,pP2PmsgPump);
        if ( pP2Pmsg       &&
             pP2Pmsg->pMsg    )
          pTarget -> PreDestroyP2PeerMsg ( pP2Pmsg->pMsg, bHandled );
      }

      // P2PeerExp_MAP routing
      // NOTES: Dispatch for exclusive implementation by P2Pexpump
      //      : Context of such P2Pmsg cannot be swapped
      else if ( pP2Pmsg->nCode == (CN_P2PeerMsg|CN_P2PeerExp) )
      {
        bHandled = pTarget -> PeekP2PeerMsg ( pP2Pmsg->pMsg );
        if ( bHandled == msgCONTINUE )
          bHandled = pTarget->On_P2PeerMsg ( (P2PaddrSTR)pP2Pmsg -> strP2Paddr 
                                           , pP2Pmsg -> nCode 
                                           , pP2Pmsg -> nMsg
                                           , pP2Pmsg -> pMsg
                                           , pP2Pmsg -> pExtra
                                           ,(P2P_MSGHANDLERINFO *)0 );
        if ( bHandled == msgCONTINUE )
          pTarget -> NotHandled ( pP2Pmsg->pMsg );
        else if ( bHandled == msgREPUMP ) {
          goto TOP;
        }
        ASSERT(bHandled!=msgSWAP);
        ASSERT(bHandled!=msgREDIRECT);
        if ( pP2Pmsg       &&
             pP2Pmsg->pMsg    )
          pTarget -> PreDestroyP2PeerMsg ( pP2Pmsg->pMsg, bHandled );
      }

      // P2PeerMsg's
      // NOTES: Thread swap for implementation
      else if ( pP2Pmsg->nCode           == CN_P2PeerMsg               &&
                pTarget->GetP2PaddrHub() != pP2Pmsg->pMsg->GetDestin()    )
      {
        bHandled = pTarget -> RouteP2PeerMsg ( pP2Pmsg->pMsg );
        if (  bHandled == msgSWAP                    &&
             !SwapContextP2Pmsg(&pP2Pmsg,pP2PmsgPump)   ) {
          goto TOP;
        }
        if (  bHandled == msgCONTINUE )
          pTarget -> NotHandled ( pP2Pmsg->pMsg );
      }

      // P2PeerSys_MAP routing
      // NOTES: Dispatch for implementation
      else if ( pP2Pmsg->nCode == CN_P2PeerSys )
      {
        bHandled = pTarget->On_P2PeerSys ( pP2Pmsg -> nCode 
                                         , pP2Pmsg -> nMsg
                                         , pP2Pmsg -> wParam
                                         , pP2Pmsg -> lParam 
                                         , pP2Pmsg -> pExtra
                                         ,(P2P_SYSHANDLERINFO *)0 );
        if ( bHandled == sysCONTINUE )
          pTarget -> NotHandled ( pP2Pmsg->nMsg
                                , pP2Pmsg->wParam, pP2Pmsg->lParam );
        else if (  bHandled == sysSWAP                    &&
                  !SwapContextP2Pmsg(&pP2Pmsg,pP2PmsgPump)    ) {
          goto TOP;
        }
      }

      // P2PeerSnc_MAP routing
      // NOTES: Dispatch for P2PeerTarget'ed implementation without routing
      //      : P2PeerTarget may or may NOT exist.
      else if ( pP2Pmsg->nCode == CN_P2PeerSnc )
      {
        bHandled = sncHANDLED;         // Handled is default
        if ( pTarget->IsValidObject() )
          bHandled = pTarget->On_P2PeerSnc ( pP2Pmsg -> nCode 
                                           , pP2Pmsg -> nMsg
                                           , pP2Pmsg -> wParam
                                           , pP2Pmsg -> lParam 
                                           , pP2Pmsg -> pExtra
                                           ,(P2P_SNKHANDLERINFO *)0 );
        if ( bHandled == sncCONTINUE )
          pTarget -> NotHandledSnc ( pP2Pmsg->nMsg
                                   , pP2Pmsg->wParam, pP2Pmsg->lParam );
        else if (  bHandled == sncSWAP                    &&
                  !SwapContextP2Pmsg(&pP2Pmsg,pP2PmsgPump)    ) {
          goto TOP;
        }
      }

      // P2Pevent routing
      // NOTES: Dispatched to the nominated target
      else if ( pP2Pmsg->nCode == CN_P2Pevent )
      {
        bHandled = pTarget -> On_P2Pevent ( pP2Pmsg->wParam
                                          , pP2Pmsg->lParam
                                          , pP2Pmsg->pEvent );
        if (  bHandled == evtSWAP                     &&
             !SwapContextP2Pmsg(&pP2Pmsg,pP2PmsgPump)    ) {
          goto TOP;
        }
      }

      // To be sure, to be sure
      else                             // Should not happen
        EVERR->MODULE
             ->Message("Illogical P2PeerMsg notification"
                       "nCode=%i, nMsg=%i"
                      , pP2Pmsg->nCode
                      , pP2Pmsg->nMsg )
             ->Advice ("P2PeerMsg object dropped" )
             ->Cancel();

    }

    // Exceptions
    // NOTES: Implementation context management
    /*catch ( P2Pmsg_Context *pContext )
    {
      // To be sure, to be sure
      // FIX-ME this is not necessarily so
      //ASSERT(pContext->pTarget==pTarget);

      // ON_MESSAGE(pContext->nMsg,OnHandler) context for
      // nominated window
      if ( pContext->hWnd )
      {
        pP2Pmsg -> pTarget = pContext -> pTarget;
        if ( pP2Pmsg->pCon )
          pP2Pmsg -> bNotify = true;
        PostMessage ( pContext->hWnd, pContext->nWM_APP
                    ,(WPARAM)pP2Pmsg,(LPARAM)0 );
      }

      // Swap P2Peer thread context
      else if ( pContext->nThreadID )
      {
        P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
        P2PmsgPump *pP2PmsgPump = 0;
        s_ThreadID_P2PmsgPump.Lookup(pContext->nThreadID,pP2PmsgPump);
        if ( !pP2PmsgPump )
          EVERR->MODULE
               ->Message("P2Pmsg pump not started\n"
                         "ADVICE\t: Refer CreateP2PmsgPump() for further "
                                 "details" )
               ->Throw();
        if ( pP2Pmsg->pCon )
          pP2Pmsg -> bNotify = true;
        pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, false );
      }

      // Post P2PeerMsg to P2PeerCon object
      else if ( pContext->pCon &&
                pP2Pmsg ->pMsg    )
      {
        pContext -> pCon -> PostP2PeerMsg ( pP2Pmsg->pMsg );
        pP2Pmsg  -> pMsg = 0;
        ReleaseP2Pmsg ( pP2Pmsg );
      }

      // Swap P2PeerMsg context
      else if ( pContext->pMsg )
      {
        // To be sure, to be sure
        if ( pP2Pmsg->pMsg != pContext->pMsg )
          delete pP2Pmsg -> pMsg;
        pP2Pmsg -> pMsg       = pContext -> pMsg;
        pP2Pmsg -> nMsg       = P2P_P2Pmsg;//pMsg -> Type ( );
        pP2Pmsg -> strP2Paddr = pContext -> pMsg -> GetSource ( );
        pP2Pmsg -> pTarget    = pContext -> pTarget;
        P2PmsgPump::GetP2PmsgPump() -> m_pContext = 0;
        delete pContext;
        goto TOP;
      }
      P2PmsgPump::GetP2PmsgPump() -> m_pContext = 0;
      delete pContext;
    }*/

    // Events
    // NOTES: Drop any offending P2PeerCon'nection.  Subsequently
    //        passes through ON_P2PeerCon_CLOSE handler
    catch ( P2Pevent *pEVT )
    {
//ASSERT(::AfxCheckMemory());
pEVT->Print();
      if ( pP2Pmsg->nCode == CN_P2PeerCon &&
           pP2Pmsg->pCon                     )
        pP2Pmsg -> pCon -> Drop ( pEVT->Isolate() );
      else
        pEVT -> Cancel ( );
      // pTarget -> PreDestroyP2PeerCon ( pP2Pmsg->pCon, conDROP );
    }

    // Tidy up, and
    // NOTES: oSafeP2Pmsg releases the P2Pmsg as this scope unwinds -
    //        on this path, and on any exception escaping the handler
    //        above.  ReleaseP2Pmsg() deletes unconditionally and does
    //        the balancing s_cP2Pmsg--, so no path above may release
    //        it a second time
    return;
}

///////////////////////////////////////////////////////////////////////
//  Windows integration and message routing 

//
//  Description: Placemarker for WORD-ME
//
//
//  Parameters:  WPARAM wParam
//               P2Pmsg object pointer
//
//               LPARAM lParam
//               Not used, reserved for future use
//               
//  Returns:     BOOL
//               Success flag
//
BOOL
CWnd_OnP2PeerTarget ( WPARAM wParam, LPARAM lParam )
{
    // Locals
    P2PmsgPump *pP2PmsgPump = 0;
    P2Pmsg     *pP2Pmsg = reinterpret_cast<P2Pmsg *>(wParam);
    UNREFERENCED_PARAMETER(lParam);

    // Isolation
    if ( !pP2PmsgPump )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      if ( !s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump) ||
           !pP2PmsgPump                                                       )
        EVERR->MODULE
             ->Message_T("P2Pmsg pump does not exist within MFC context")
             ->Advice_T ("Refer CreateP2PmsgPump() for further details" )
             ->Throw();
      if ( !pP2PmsgPump )
        pP2PmsgPump = P2PmsgPump::Factory ( 0, 0 );
      pP2PmsgPump -> m_pP2Pmsg = pP2Pmsg;
    }

    // Pump single P2Pmsg instance
    // NOTES: DispatchP2P() will ultimately map into P2PeerCon
    //        notification and P2PeerMsg map handlers.
    //      : Intercept and route P2PeerMsg's destined for
    //        other P2Peer's
    if ( pP2Pmsg )
    {
      //???P2PeerTarget *pTarget = reinterpret_cast<P2PeerTarget *>(pP2Pmsg->pTarget);
      if ( PreTranslateP2Pmsg(pP2Pmsg) )
      {
        TranslateP2Pmsg ( pP2Pmsg );
        DispatchP2Pmsg  ( pP2Pmsg, pP2PmsgPump );
      }
    };

    // Tidy up, and
    return TRUE;
}

///////////////////////////////////////////////////////////////////////
//  Routines for fast search of P2PeerMsg maps
//  NOTES: Manage routing of connection events through the
//         P2PeerCon_MAP's

//
//  Description: Searches for entry in the P2PeerMsg map
//               NOTES: Supports recursive searches
//
//
//  Parameters:  const P2P_MSGMAP_ENTRY *lpEntry
//               Message map to be searched
//
//               P2PeerMsg *pMsg
//               Message for which handler is to be located
//
//               UINT nMsg
//               Message identification
//
//               UINT nCode
//
//               UINT nID
//
//  Returns:     const P2P_MSGMAP_ENTRY*
//               Located message map entry
//                 0.. Not found
//
const P2P_MSGMAP_ENTRY* AFXAPI
FindP2PeerMsgEntry ( const P2P_MSGMAP_ENTRY *lpEntry
                   , P2PeerMsg *pMsg
                   , P2Pmsg_t nMsg, UINT nCode, UINT nID )
{
    // Introduce locals
    const P2P_MSGMAP_ENTRY *lpEntry1 = 0;

    // Recursive searching
	  while ( lpEntry->nSig != P2PSig_End )
    {
    /*if (   lpEntry->nCode    == nCode          &&
           ( lpEntry->nMessage == nMsg ||
             lpEntry->nMessage == ~0      )      &&
           ( lpEntry->nID      == nID  ||
             lpEntry->nLastID  == nID  ||
             lpEntry->nID      == ~0      )         )*/
		  //if ( ( lpEntry->nMessage == nMsg ||
    //         lpEntry->nMessage == ~0      )      &&
    //         lpEntry->nCode    == nCode             )
      if ( pMsg->Map_MatchName (lpEntry->sMsg)      &&
           pMsg->Map_MatchState(lpEntry->uMsgState) &&
           lpEntry->nCode    == nCode                  )
			   //nID               >= lpEntry->nID     &&
         //nID               <= lpEntry->nLastID    ) FIX-ME
      {
//short nTmp=pMsg->Type();
//ASSERT(lpEntry->nMessage == nMsg || lpEntry->nMessage == ~0);
        // Entry located
        if ( lpEntry->nSig != P2PSig_Unwrap )
			    return lpEntry;

        // Handle wrapped P2PeerMsg recursion
        P2PeerMsg *pMsg1 = &(*pMsg)[1];
        lpEntry1 = FindP2PeerMsgEntry ( lpEntry+1, pMsg1
                                      , nMsg//pMsg1->Type()
                                      , nCode, nID );
        if ( lpEntry1             ||
             lpEntry->nOSets <= 0    )
          return lpEntry1;
      }

      // Apply navigation offset
      lpEntry += lpEntry -> nOSets;
    };

    // Not found
    return NULL;
};

//
//  Description:
//
//
//  Parameters:  P2PeerTarget *pTarget
//               Target object to which P2PeerMsg is to be
//               routed
//
//               UINT nID
//
//               int nCode
//
//               P2P_PMSG pfn
//
//               void *pvExtra
//
//               UINT_PTR nSig
//
//               P2P_CMDHANDLERINFO *pHandlerInfo
//
//  Returns:     msgRESULT
//               Completion summary
//
extern msgRESULT AFXAPI
DispatchP2PeerMsg ( P2PeerTarget *pTarget, UINT nID, int nCode
                  , P2P_PMSG pfn, void *pvExtra
                  , UINT_PTR nSig
                  , P2P_MSGHANDLERINFO *pHandlerInfo )
{
    UNREFERENCED_PARAMETER(nID);
    UNREFERENCED_PARAMETER(nCode);
    // Introduce locals
    P2Pmsg    *pP2Pmsg    = reinterpret_cast<P2Pmsg *>(pvExtra);
    //P2PeerMsg    *pMsg    = 0;
    msgRESULT   msgResult = msgHANDLED;
    //ASSERT_VALID(pTarget); FIX-ME
    UNUSED(nCode);   // unused in release builds

    union P2PeerMsgMapFunctions mmf;
    mmf.pfn = pfn;

    // P2P_MSGHANDLERINFO data structure is special
    // NOTES: When suplied simply populate, don't do it
    if ( pHandlerInfo != NULL )
    {
      pHandlerInfo -> pTarget = pTarget;
      pHandlerInfo -> pmf     = mmf.pfn;
      return msgHANDLED;
    }

    // Standard P2Peer signatures
    switch ( nSig )
    {
      // Should never happen
      default:
        ASSERT(FALSE);
        return msgHANDLED;
        break;

      // Standard P2PeerMsg signature
      case P2PSig_Msg:
        ASSERT(CN_COMMAND == 0);        // CN_COMMAND same as BN_CLICKED
        ASSERT(pvExtra /*== NULL*/);
        msgResult = (pTarget->*mmf.pfn_Msg)(reinterpret_cast<P2PeerMsg*>(pvExtra));
        break;

      // Standard P2PeerMsg map casting signature
      case P2PSig_MsgMapcast:
        ASSERT(CN_COMMAND == 0);        // CN_COMMAND same as BN_CLICKED
        ASSERT(pvExtra /*== NULL*/);
        msgResult = (pTarget->*mmf.pfn_Msg)(reinterpret_cast<P2PeerMsg*>(pvExtra));
        break;

      // Catch P2PeerMsg exception signature
      case P2PSig_MsgCatch:
        ASSERT(CN_COMMAND == 0);        // CN_COMMAND same as BN_CLICKED
        ASSERT(pvExtra /*== NULL*/);
        msgResult = (pTarget->*mmf.pfn_MsgCatch)(reinterpret_cast<P2PeerMsg*>(pvExtra));
        break;

      // Reflected P2PeerMsg signature
      case P2PSig_MsgReflect:
        ASSERT(CN_COMMAND == 0);        // CN_COMMAND same as BN_CLICKED
        ASSERT(pvExtra /*== NULL*/);
        msgResult = (pTarget->*mmf.pfn_MsgCatch)(reinterpret_cast<P2PeerMsg*>(pvExtra));
        break;

      // Catch Reflected P2PeerMsg signature
      case P2PSig_MsgReflectCatch:
        ASSERT(CN_COMMAND == 0);        // CN_COMMAND same as BN_CLICKED
        ASSERT(pvExtra /*== NULL*/);
        msgResult = (pTarget->*mmf.pfn_MsgCatch)(reinterpret_cast<P2PeerMsg*>(pvExtra));
        break;

      // Ack P2PeerMsg signature
      case P2PSig_MsgAck:
        ASSERT(CN_COMMAND == 0);        // CN_COMMAND same as BN_CLICKED
        ASSERT(pvExtra /*== NULL*/);
        msgResult = (pTarget->*mmf.pfn_MsgCatch)(reinterpret_cast<P2PeerMsg*>(pvExtra));
        break;

      // Catch Ack P2PeerMsg signature
      case P2PSig_MsgAckCatch:
        ASSERT(CN_COMMAND == 0);        // CN_COMMAND same as BN_CLICKED
        ASSERT(pvExtra /*== NULL*/);
        msgResult = (pTarget->*mmf.pfn_MsgCatch)(reinterpret_cast<P2PeerMsg*>(pvExtra));
        break;

      // Win32 style message integration
      case P2PSig_Sys:
        ASSERT(pvExtra);
        msgResult = (pTarget->*mmf.pfn_MsgWin32) ( pP2Pmsg->wParam, pP2Pmsg->lParam );
        break;
	  }

    // Tidy up and
    return msgResult;
}

///////////////////////////////////////////////////////////////////////
//  Routines for fast search of P2PeerSys maps
//  NOTES: Manage routing of Sys nofication events through the
//         P2PeerSys maps

//
//  Description: Searches for entry in the P2PeerW32 map
//               NOTES: Supports recursive searches
//
//
//  Parameters:  const P2P_SYSMAP_ENTRY *lpEntry
//               Message map to be searched
//
//               UINT nMsg
//               Message identification
//
//               UINT nCode
//
//  Returns:     const P2P_SYSMAP_ENTRY*
//               Located message map entry
//                 0.. Not found
//
const P2P_SYSMAP_ENTRY* AFXAPI
FindP2PeerSysEntry ( const P2P_SYSMAP_ENTRY *lpEntry
                   , P2Pmsg_t nMsg, UINT nCode )
{
    // Introduce locals
    //const P2P_SYSMAP_ENTRY *lpEntry1 = 0;

    // Recursive searching
	  while ( lpEntry->nSig != P2PSig_End )
    {
    /*if (   lpEntry->nCode    == nCode          &&
           ( lpEntry->nMessage == nMsg ||
             lpEntry->nMessage == ~0      )      &&
           ( lpEntry->nID      == nID  ||
             lpEntry->nLastID  == nID  ||
             lpEntry->nID      == ~0      )         )*/
		  if ( ( lpEntry->nMessage == nMsg ||
             lpEntry->nMessage == ~0      )      &&
             lpEntry->nCode    == nCode             )
			   //nID               >= lpEntry->nID     &&
         //nID               <= lpEntry->nLastID    ) FIX-ME
      {
        // Entry located
        if ( lpEntry->nSig != P2PSig_Unwrap )
			    return lpEntry;
      }

      // Apply navigation offset
      lpEntry += lpEntry -> nOSets;
    };

    // Not found
    return NULL;
};

//
//  Description:
//
//
//  Parameters:  P2PeerTarget *pTarget
//               Target object to which P2PeerMsg is to be
//               routed
//
//               UINT nID
//
//               int nCode
//
//               P2P_PMSG pfn
//
//               void *pvExtra
//
//               UINT_PTR nSig
//
//               P2P_CMDHANDLERINFO *pHandlerInfo
//
//  Returns:     BOOL
//                 true... Stop message routing
//                 false.. Continue
//
extern BOOL AFXAPI
DispatchP2PeerSys ( P2PeerTarget *pTarget, int nCode
                  , P2P_PSYS pfn, void *pvExtra
                  , UINT_PTR nSig
                  , P2P_SYSHANDLERINFO* pHandlerInfo )
{
    UNREFERENCED_PARAMETER(nCode);
    // Introduce locals
    P2Pmsg    *pP2Pmsg = (P2Pmsg *)pvExtra;
    BOOL bResult = TRUE; // default is ok
    //ASSERT_VALID(pTarget); FIX-ME
    UNUSED(nCode);   // unused in release builds

    union P2PeerSysMapFunctions mmf;
    mmf.pfn = pfn;

    // P2P_SYSHANDLERINFO data structure is special
    // NOTES: When suplied simply populate, don't do it
    if ( pHandlerInfo != NULL )
    {
		  pHandlerInfo -> pTarget = pTarget;
      pHandlerInfo -> pmf     = mmf.pfn;
      return TRUE;
    }

    // Standard P2Peer signatures
    switch ( nSig )
    {
      // Should never happen
      default:
        ASSERT(FALSE);
        return 0;
        break;

      // Win32 style message integration
      case P2PSig_Sys:
        ASSERT(pvExtra);
        bResult = (pTarget->*mmf.pfn_MsgWin32) ( pP2Pmsg->wParam
                                               , pP2Pmsg->lParam );
        break;
    }

    // Tidy up and
    return bResult;
}

///////////////////////////////////////////////////////////////////////
//  Routines for fast search of P2PeerCms maps
//  NOTES: Manage routing of Snk nofication events through the
//         P2PeerSnk maps

//
//  Description: Searches for entry in the P2PeerW32 map
//               NOTES: Supports recursive searches
//
//
//  Parameters:  const P2P_SYSMAP_ENTRY *lpEntry
//               Message map to be searched
//
//               UINT nMsg
//               Message identification
//
//               UINT nCode
//
//  Returns:     const P2P_SNKMAP_ENTRY*
//               Located message map entry
//                 0.. Not found
//
const P2P_SNKMAP_ENTRY* AFXAPI
FindP2PeerSnkEntry ( const P2P_SNKMAP_ENTRY *lpEntry
                   , P2Pmsg_t nMsg, UINT nCode )
{
    // Introduce locals
    //const P2P_SNKMAP_ENTRY *lpEntry1 = 0;

    // Recursive searching
	  while ( lpEntry->nSig != P2PSig_End )
    {
    /*if (   lpEntry->nCode    == nCode          &&
           ( lpEntry->nMessage == nMsg ||
             lpEntry->nMessage == ~0      )      &&
           ( lpEntry->nID      == nID  ||
             lpEntry->nLastID  == nID  ||
             lpEntry->nID      == ~0      )         )*/
		  if ( ( lpEntry->nMessage == nMsg ||
             lpEntry->nMessage == ~0      )      &&
             lpEntry->nCode    == nCode             )
			   //nID               >= lpEntry->nID     &&
         //nID               <= lpEntry->nLastID    ) FIX-ME
      {
        // Entry located
        if ( lpEntry->nSig != P2PSig_Unwrap )
			    return lpEntry;
      }

      // Apply navigation offset
      lpEntry += lpEntry -> nOSets;
    };

    // Not found
    return NULL;
};

//
//  Description:
//
//
//  Parameters:  P2PeerTarget *pTarget
//               Target object to which P2PeerMsg is to be
//               routed
//
//               UINT nID
//
//               int nCode
//
//               P2P_PMSG pfn
//
//               void *pvExtra
//
//               UINT_PTR nSig
//
//               P2P_CMDHANDLERINFO *pHandlerInfo
//
//  Returns:     BOOL
//                 true... Stop message routing
//                 false.. Continue
//
extern BOOL AFXAPI
DispatchP2PeerSnk ( P2PeerTarget *pTarget, int nCode
                  , P2P_PSNK pfn, void *pvExtra
                  , UINT_PTR nSig
                  , P2P_SNKHANDLERINFO* pHandlerInfo )
{
    UNREFERENCED_PARAMETER(nCode);
    // Introduce locals
    P2Pmsg    *pP2Pmsg = (P2Pmsg *)pvExtra;
    BOOL bResult = TRUE; // default is ok
    //ASSERT_VALID(pTarget); FIX-ME
    UNUSED(nCode);   // unused in release builds

    union P2PeerSnkMapFunctions mmf;
    mmf.pfn = pfn;

    // P2P_SYSHANDLERINFO data structure is special
    // NOTES: When suplied simply populate, don't do it
    if ( pHandlerInfo != NULL )
    {
		  pHandlerInfo -> pTarget = pTarget;
      pHandlerInfo -> pmf     = mmf.pfn;
      return TRUE;
    }

    // Standard P2Peer signatures
    switch ( nSig )
    {
      // Should never happen
      default:
        ASSERT(FALSE);
        return 0;
        break;

      // Win32 style message integration
      case P2PSig_Snc:
        ASSERT(pvExtra);
        bResult = (pTarget->*mmf.pfn_MsgWin32) ( pP2Pmsg->wParam, pP2Pmsg->lParam );
        break;

      // P3PmsgItem style message integration
      case P2PSig_SncP2PmsgItem:
        ASSERT(pvExtra);
        bResult = (pTarget->*mmf.pfn_SnkP3PmsgItem) ( pP2Pmsg->pP3PmsgItem, pP2Pmsg->wParam, pP2Pmsg->lParam );
        break;

      // P3PmsgNode style message integration
      case P2PSig_SncP2PmsgNode:
        ASSERT(0);
        ASSERT(pvExtra);
        //bResult = (pTarget->*mmf.pfn_SnkP3PmsgNode) ( pP2Pmsg->pP3PmsgNode, pP2Pmsg->wParam, pP2Pmsg->lParam );
        break;
    }

    // Tidy up and
    return bResult;
}

///////////////////////////////////////////////////////////////////////
//  Routines for fast search of P2PeerCon maps
//  NOTES: Manage routing of connection events through the
//         P2PeerCon maps
//

//
//  Description: Searches for entry in the P2PeerCon map
//               NOTES: Performs simple hi-speed linear search
//
//
//  Parameters:  const P2P_CONMAP_ENTRY *pEntry
//               P2PeerCon_MAP to be searched
//
//               P2Pmsg_t nMsg
//               State transition message
//
//               UINT nCode
//               State transition code
//
//               P2PaddrSTR strP2Paddr
//               Connection domain
//
//               P2PeerCon *pCon
//               Connection object to be mapped
//
//  Returns:     const P2P_CONMAP_ENTRY*
//               Located P2PeerCon map entry
//                 0.. Not found
//
const P2P_CONMAP_ENTRY* AFXAPI
FindP2PeerConEntry ( const P2P_CONMAP_ENTRY *pEntry
                   , P2Pmsg_t nMsg, UINT nCode
                   , P2PeerCon *pCon, P2PeerMsg *pMsg )
{
    // Simple linear search
	while ( pEntry->nSig != P2PSig_End )
    {
      // Observe P2P_CONMAP_ENTRY filter
      // NOTES: Upon optimised mismatch apply navigation offset
      //        and try again
      if (   pEntry->nMessage  != nMsg  ||
             pEntry->nCode     != nCode /*||
           !(pEntry->nLastID&uCMFilter)*/   )
      {
        pEntry += pEntry -> nOSets;
        continue;
      }

      // Optimisation in the form of delayed instanciation
      P2Padom         oDomain ( pEntry->strP2Padom );
      P2PeerConMode_e eConMode = pCon -> GetMode();
if(eConMode==P2PeerCon_Accept)
{
  nCode++;
  nCode--;
}

      // Servers
      // NOTES: Pre-defined sub-set interception only
      if ( (pEntry->nMode&CM_SERVER) == CM_SERVER &&
            eConMode == P2PeerCon_SERVICE            )
      {
        if ( oDomain.IsMapped(pCon->GetP2Paddress().c_wstr()) )
          return pEntry;
        pEntry += pEntry -> nOSets;
        continue;
      }

      // Clients
      // NOTES: Pre-defined sub-set interception only
      if ( (pEntry->nMode&CM_CLIENT) == CM_CLIENT &&
            eConMode == P2PeerCon_CLIENT             )
      {
        if ( oDomain.IsMapped(pCon->GetP2Paddress().c_wstr()) )
          return pEntry;
        pEntry += pEntry -> nOSets;
        continue;
      }

      // Accepts
      // NOTES: Pre-defined sub-set interception only
      if ( (pEntry->nMode&CM_ACCEPT) == CM_ACCEPT &&
            eConMode == P2PeerCon_Accept             )
      {
        if ( oDomain.IsMapped(pCon->GetP2Paddress().c_wstr()) )
          return pEntry;
        pEntry += pEntry -> nOSets;
        continue;
      }

      // Login
      // NOTES: P2PeerMsg object is mandatory, and must contain
      //        P2Pmsg_Login request
      //      : Login sequences initiate exchange of P2Paddr's
      if ( nMsg == P2P_Login )
      {
        if ( pMsg == nullptr )
          EVERR->MODULE
               ->Message("Incomplete P2P_Login sequence, pMsg=NULL")
               ->Throw();
        if ( !pMsg->Map_MatchName(P2Pmsg_Login) ) 
          EVERR->MODULE
               ->Message(L"Invalid P2P_Login sequence, pMsg!=%s"
                        , P2Pmsg_Login )
               ->Throw();
        // Remote P2PeerHub nominates P2Paddr for P2PeerCon
        // NOTES: MAP_P2PeerCon_Login() contains a P2PaddrDomain through
        //        which remote P2PeerHub login's will be mapped
        if ( pMsg->GetSource()                   &&
             oDomain.IsMapped(pMsg->GetSource())    )
          return pEntry;
        // Local P2PeerHub nominates P2Paddr for P2PeerCon
        // NOTES: MAP_P2PeerCon_Login() contains a P2Paddr
        else if ( oDomain.IsMapped(pCon->GetP2Paddress().c_wstr())  )
          return pEntry;
      }

      // LoginAck
      // NOTES: P2PeerMsg object is mandatory, and must contain
      //        P2Pmsg_Login request
      //      : LoginAck sequences complete exchange of P2Paddr's
      else if ( nMsg == P2P_LoginAck )
      {
        if ( pMsg == nullptr )
          EVERR->MODULE
               ->Message("Incomplete P2P_LoginAck sequence, pMsg=NULL")
               ->Throw();
        if ( !pMsg->Map_MatchName(P2Pmsg_LoginAck) ) 
          EVERR->MODULE
               ->Message(L"Invalid P2P_LoginAck sequence, pMsg!=%s"
                        , P2Pmsg_Login )
               ->Throw();
        // Remote P2PeerHub nominates P2Paddr for P2PeerCon
        // NOTES: MAP_P2PeerCon_Login() contains a P2PaddrDomain through
        //        which remote P2PeerHub login's will be mapped
        if ( oDomain.IsMapped(pMsg->GetSource()) )
          return pEntry;
      }

      // CypherEx
      // NOTES: P2PeerMsg object is mandatory, and must contain
      //        P2Pmsg_Login request
      //      : LoginAck sequences complete exchange of P2Paddr's
      else if ( nMsg == P2P_CypherEx )
      {
        if (  pMsg                                 &&
             !pMsg->Map_MatchName(P2Pmsg_CypherEx)    ) 
          EVERR->MODULE
               ->Message(L"Invalid P2P_CypherEx sequence, pMsg!=%s"
                        , P2Pmsg_CypherEx )
               ->Throw();
        // Remote P2PeerHub nominates P2Paddr for P2PeerCon
        if ( oDomain.IsMapped(pMsg->GetSource()) )
          return pEntry;
      }

      // Default mapping
      else if ( !pEntry->nMode                                   &&
                 oDomain.IsMapped(pCon->GetP2Paddress().c_wstr())    )
        return pEntry;

      // Apply navigation offset, and try again
      pEntry += pEntry -> nOSets;
    };

    // Not found
    return NULL;
};

//
//  Description: Dispatches P2PeerCon events
//
//
//  Parameters:  P2PeerTarget *pTarget
//               Target object to which P2PeerCon event is to be
//               dispatched
//
//               P2PeerCon *pCon
//               Connection object
//
//               int nCode
//
//               short
//               State transition message
//
//               P2P_PCON pfn
//               Message map implementation function
//
//               void *pExtra
//
//               UINT_PTR nSig
//
//               P2P_CMDHANDLERINFO *pHandlerInfo
//
//  Returns:     conRESULT
//               Completion result
//
extern conRESULT AFXAPI
DispatchP2PeerCon ( P2PeerTarget *pTarget
                  , P2PeerCon *pCon, int nCode, P2Pmsg_t nMsg
                  , P2P_PCON pfn, void *pExtra
                  , UINT_PTR nSig
                  , P2P_CONHANDLERINFO *pHandlerInfo )
{
    // Introduce locals
    conRESULT conResult = conHANDLED; // default is ok
    //ASSERT_VALID(pTarget); FIX-ME
    UNUSED(nCode);   // unused in release builds

    union P2PeerConMapFunctions mwf;
    mwf.pfn = pfn;

    // P2P_CONHANDLERINFO data structure is special
    // NOTES: When supplied simply populate, don't do it
    if ( pHandlerInfo != NULL )
    {
		  pHandlerInfo -> pTarget = pTarget;
      pHandlerInfo -> pwf     = mwf.pfn;
      return conHANDLED;
    }

    // Standard P2PeerCon signatures
    switch ( nSig )
    {
      // Should never happen
      default:
        ASSERT(FALSE);
        return conDROP;
        break;

      // BOOL On_(P2PeerCon*)
      case P2PSig_Con:
        ASSERT(pExtra==nullptr);
        // NOTE: pCon is context-dependent for this signature.  Connection
        //       notifications (P2P_Startup/Accept/Connect/Listen/Close) carry
        //       the originating connection in pCon (non-NULL), whereas some
        //       P2P_PITimer variants are posted with no connection (pCon==NULL).
        //       The former ASSERT(pCon==nullptr) was therefore wrong for BOTH
        //       transports (WSA and pipe): it aborted the login handshake at
        //       dispatch time the moment any real connection notification was
        //       pumped.  pCon is passed through to the handler as-is below.
        conResult = (pTarget->*mwf.pfn_Con)(pCon);
        break;

      // BOOL OnPKeyXChange(P2PeerCon*,void*,int)
      case P2PSig_ConPKeyXChange:
      {
        ASSERT(0);
        ASSERT(pExtra);
        ASSERT(pCon);
        P2Piomage  *pP2Piomage = (P2Piomage *)pExtra;
        P2Psize_t   iDataSize  =  P2Piomage_Sizeof(pP2Piomage);
        void       *pData      =&pP2Piomage -> cIOmage; 
        conResult = (pTarget->*mwf.pfn_ConPKeyXChange)
                                  ( pCon
                                  , pData,iDataSize );
        break;
      }

      // BOOL conRESULT (P2PeerCon*,void*,P2Psize_t)
      case P2PSig_ConPKeyXChangeAck:
      {
        ASSERT(pExtra==nullptr);
        ASSERT(pCon==nullptr);
        P2Piomage  *pP2Piomage = (P2Piomage *)pExtra;
        P2Psize_t   iDataSize  =  P2Piomage_Sizeof(pP2Piomage);
        void       *pData      =&pP2Piomage -> cIOmage; 
        conResult = (pTarget->*mwf.pfn_ConPKeyXChange)
                                  ( pCon
                                  , pData,iDataSize );
        break;
      }

      // BOOL On_(P2PeerCon*,void*,int)
      // NOTES: Expose P2PeerID supplied by remote client and
      //        login request message
      case P2PSig_ConLogin:
      {
        ASSERT(pExtra);
        ASSERT(pCon);
        P2PeerMsg  *pMsg = (P2PeerMsg *)pExtra;
        //  A COPY: on Linux GetSource() ends in c_wstr(), which widens into a
        //  ring of 16 thread-local scratch buffers recycled by the next
        //  accessor call on this thread.  This one is handed to application
        //  code, which is free to call as many accessors as it likes before
        //  reading it.  (P2PeerHub::RouteP2PeerMsg is what that looks like
        //  when it goes wrong.)
        CString     strThatP2Paddr  = pMsg -> GetSource();
        P2PaddrSTR  pThatP2PaddrSTR = strThatP2Paddr;
        P2Psize_t   iDataSize     = pMsg -> DataSize();
        void       *pData         = iDataSize ? pMsg->Data() : 0;
        // Peer login authentication (P2PAuthLogin.h): hide the verified auth
        // block, so the application sees exactly the payload the peer's
        // application sent - at offset zero, byte for byte. The stock
        // P2PeerTarget::On_ConLogin THROWS on a non-empty login payload, so
        // anything less than invisibility would break every deployment that
        // has not written a custom handler the moment auth is switched on.
        // An auth-only login leaves nothing behind, and the pData/iDataSize
        // collapse above already turns that into (0,0) - identical to today.
        // GetAuthStripLen() is non-zero only after a signature verified.
        {
          size_t cbAuthStrip = pCon ? pCon->GetAuthStripLen() : 0;
          if ( cbAuthStrip && (size_t)iDataSize >= cbAuthStrip )
          {
            iDataSize = (P2Psize_t)( (size_t)iDataSize - cbAuthStrip );
            pData     = iDataSize
                      ? (void *)( (unsigned char *)pMsg->Data() + cbAuthStrip )
                      : 0;
          }
        }
        conResult = (pTarget->*mwf.pfn_ConLogin)
                                  ( pCon
                                  , pThatP2PaddrSTR
                                  , pData, iDataSize );
        break;
      }

      // BOOL On_LoginAck(P2PeerCon*,void*,int)
      // NOTES: Expose P2PeerID assigned by remote server and
      //        login acknowledgement message
      case P2PSig_ConLoginAck:
      {
        ASSERT(pExtra);
        ASSERT(pCon);
        P2PeerMsg  *pMsg = (P2PeerMsg *)pExtra;
        //  COPIES, for the reason given under P2PSig_ConLogin above - and
        //  here TWO are live at once, which is precisely the shape that made
        //  a single shared scratch buffer alias them together.
        CString     strThisP2Paddr  = pMsg->GetDestin();
        CString     strThatP2Paddr  = pMsg->GetSource();
        P2PaddrSTR  pThisP2PaddrSTR = strThisP2Paddr;
        P2PaddrSTR  pThatP2PaddrSTR = strThatP2Paddr;
        int        iDataSize     = pMsg -> DataSize();
        void      *pData         = iDataSize ? pMsg->Data() : 0;
        // Peer login authentication: strip the verified ack block, for the
        // same reason as P2PSig_ConLogin above - On_ConLoginAck throws on a
        // non-empty acknowledgement payload just as loudly.
        {
          size_t cbAuthStrip = pCon ? pCon->GetAuthStripLen() : 0;
          if ( cbAuthStrip && (size_t)iDataSize >= cbAuthStrip )
          {
            iDataSize = (int)( (size_t)iDataSize - cbAuthStrip );
            pData     = iDataSize
                      ? (void *)( (unsigned char *)pMsg->Data() + cbAuthStrip )
                      : 0;
          }
        }
        conResult = (pTarget->*mwf.pfn_ConLoginAck)
                                  ( pCon
                                  , pThisP2PaddrSTR, pThatP2PaddrSTR
                                  , pData, iDataSize );
        break;
      }

      // BOOL On_ConPeek(P2PeerCon*,UINT,P2Pmsg_t)
      // NOTES: Peek at P2PeerCon objects as routed through the
      //        P2PeerCon_MAP's
      case P2PSig_ConPeek:
      {
        ASSERT(pExtra);
        ASSERT(pCon);
        //P2PeerMsg *pMsg = (P2PeerMsg *)pExtra;
        conResult = (pTarget->*mwf.pfn_ConPeek)
                                  (     pCon
                                  ,     nCode
                                  ,     nMsg );
        break;
      }

      // BOOL On_CypherEx(P2PeerCon*,P2PeerMsg*)
      // NOTES: Expose P2PeerID assigned by remote server and
      //        login acknowledgement message
      case P2PSig_ConCypherEx:
      {
        ASSERT(pExtra);
        ASSERT(pCon);
        P2PeerMsg  *pMsg = (P2PeerMsg *)pExtra;
        conResult = (pTarget->*mwf.pfn_ConCypherEx)(pCon,pMsg);
        break;
      }
    }

    // Swap context processing

    // Tidy up, and
	  return conResult;
}

///////////////////////////////////////////////////////////////////////
//  P2Pmsg implementation
//  NOTES: Thread context sensitive P2Pmsg storage and retrieval
//       : PumpP2Pmsg()
//         P2PeerTarget P2Pmsg pumping
//       : CleanupP2Pmsg()
//         Performs pump shutdown and cleanup for thread
//

//
//  Description: Starts up IOCP driven P2Pmsg pump
//               NOTES: Compliments CleanupP2Pmsg()
//
//
//  Parameters:  P2PeerTarget *pTarget
//               Initial P2Pmsg ownership target.  Ownership may
//               be subsequently swapped.
//
//               HANDLE hP2PmsgEvent
//               P2Pmsg to be pumped event
//
//               DWORD NumberOfConcurrentThreads
//               Maximum number of threads that the operating system
//               allows to concurrently process I/O completion packets
//               for the I/O completion port.
//               NOTES: Refer Win32 CreateIoCompletionPort() for
//                      further details
//
/*BOOL
StartupIOCPmsgPump ( P2PeerTarget *pTarget, HANDLE hP2PmsgEvent
                   , DWORD NumberOfConcurrentThreads )
{
    // Locals
    P2PmsgPump *pP2PmsgPump = 0;

    // Firstly delegate
    // NOTES: Save on duplication
    if ( StartupP2Pmsg(pTarget, hP2PmsgEvent) )
    {
      P2PsafeCS oSafeCS     = s_oCSectionP2Pmsg;
                pP2PmsgPump = P2PmsgPump::GetP2PmsgPump ( );
    }

    // IO Completion port
    pP2PmsgPump -> m_pOVERLAPPED = new OVERLAPPED;
    pP2PmsgPump -> m_hIOCP
           = CreateIoCompletionPort ( INVALID_HANDLE_VALUE
                                    , NULL
                                    , 0
                                    , NumberOfConcurrentThreads );
    if ( pP2PmsgPump->m_hIOCP == 0 )
    {
      CloseP2PmsgPump ( );
      EVERR->Module  ("%s(%i)", __FUNCTION__
                     , NumberOfConcurrentThreads )
           ->Message ("CreateIoCompletionPort() failed\n"
                      "ADVICE\t: Internal (SNHappen)\n"
                            "\t: Hub terminating" )
           ->HResult ( GetLastError() )->Throw();
    }

    // Tidy up, and
    return TRUE;
}*/

//
//  Description: Pumps P2Pmsg through the P2PeerSys, P2PeerCon and
//               P2PeerMsg_MAP's
//               NOTES: P2Pmsg's are pumped in the context of
//                      the thread from which it is called
//
//
//  Parameters:  DWORD dwTimeout
//               Timeout duration in milliseconds
//
//  Returns:     BOOL
//               Status summary flag
//                 TRUE... P2Pmsg pumped
//                 FALSE.. Empty
//
DWORD
WaitForP2Pmsg ( DWORD dwTimeout )
{
    // Isolation and locals
    P2PmsgPump *pP2PmsgPump = 0;
    P2Pmsg     *pP2Pmsg     = 0;

    // Thread context
    // NOTES: Logically we should only be able to pump P2Pmsg's
    //        in the context of our own thread
    //      : Refer CreateP2PmsgPump() for pump initialisation and
    //        startup within thread context
    //      : Observe isolation
TOP:if ( pP2Pmsg == nullptr )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump);
      if ( !pP2PmsgPump )
        EVERR->MODULE->AFP(dwTimeout)
             ->Message_T("P2Pmsg pump not started" )
             ->Advice_T ("Refer StartupP2Pmsg() for further details" )
             ->Throw();

      // Timers monitoring
      P2Pmsecs_t wNext = pP2PmsgPump -> PollTimer ( );
      if ( wNext <= 0 )
        return P2PmsgPump_TIMER;
      else if ( wNext < dwTimeout )
        dwTimeout = (DWORD)wNext;

      // Posted messages monitoring
      if ( pP2PmsgPump->m_oCListP2Pmsg.GetCount() > 0 )
        return P2PmsgPump_MSG;
    };

    // Step n - Signals
    if ( pP2PmsgPump->SigCount() > 0 )        // locked read (TSan Risk #3)
      return P2PmsgPump_SIGNAL;

    // Step 3 - Pump OVERLAPPEDcon objects through the IOCP
    // NOTES: Dispatch OVERLAPPEDcon messages directly into keyed
    //        P2PeerCon objects
    if ( pP2PmsgPump->m_hIOCP )
    {
      ASSERT(0);
    }

    // Step 4 - Suspend for arrival of P2Pmsg's
    // NOTES: Skipped upon non-Wait
    if ( dwTimeout                                     &&
         pP2PmsgPump->SigCount() <= 0    )       // locked read (TSan Risk #3)
    {
      if ( WaitForSingleObject(pP2PmsgPump->m_hQueEvent
                              ,dwTimeout) == WAIT_FAILED )
        EVERR->MODULE->AFP(dwTimeout)
             ->Message_T("WaitForSingleObject() failed" )
             ->HResult( GetLastError() )
             ->Throw();              // All is lost
      dwTimeout = 0;
      goto TOP;
    }

    // Tidy up, and
    return P2PmsgPump_TIMEOUT;
};

//
//  Pumps P2Pmsg through the P2PeerSys, P2PeerCon and P2PeerMsg_MAP's
//  NOTES: P2Pmsg's are pumped in the context of the thread from
//         which it is called
//
//
//  Parameters:  DWORD dwTimeout
//               Timeout duration in milliseconds
//
//  Returns:     BOOL
//               Status summary flag
//                 TRUE... P2Pmsg pumped
//                 FALSE.. Empty
//
DWORD
PumpP2Pmsg ( DWORD dwTimeout, P2PsigID& nSigID )
{
    // Isolation and locals
    P2PmsgPump *pP2PmsgPump = 0;
    P2Pmsg     *pP2Pmsg     = 0;
    DWORD      dwResult     = P2PmsgPump_TIMEOUT;

    // Thread context
    // NOTES: Logically we should only be able to pump P2Pmsg's
    //        in the context of our own thread
    //      : Refer CreateP2PmsgPump() for pump initialisation and
    //        startup within thread context
    //      : Observe isolation
TOP:if ( pP2Pmsg == nullptr )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump);
      if ( !pP2PmsgPump )
        EVERR->MODULE->AFP(dwTimeout)->AFP(nSigID)
             ->Message("P2Pmsg pump not started" )
             ->Advice ("Refer StartupP2Pmsg() for further details" )
             ->Throw();

      // Timers monitoring
      P2Pmsecs_t wNext = pP2PmsgPump -> PollTimer ( );
      if ( wNext <= 0 )
        pP2Pmsg = pP2PmsgPump -> GetTimer ( );
      else if ( wNext < dwTimeout )
        dwTimeout = (DWORD)wNext;

      // Event monitoring
      // NOTES: Downgrade from the global pump-registry lock to the pump's own
      //        m_oCSection before touching m_oCListP2Pmsg.  Producers guard the
      //        message queue with pP2PmsgPump->m_oCSection (see PostP2Pmsg),
      //        whereas this reader previously held only the global lock - two
      //        different critical sections around the same non-thread-safe MFC
      //        CList, which corrupted the list and crashed inside GetP2Pmsg().
      //        The timer queue above stays under the global lock, matching its
      //        producers (Set/KillTimer).
      if ( !pP2Pmsg )
      {
        oSafeCS = pP2PmsgPump -> m_oCSection;
        pP2Pmsg = pP2PmsgPump -> GetP2Pmsg ( );
        if (  pP2Pmsg &&
              pP2Pmsg->pCon &&
             !pP2Pmsg->pCon->m_hCPortP2PumpID )
          pP2Pmsg -> pCon -> m_hCPortP2PumpID = pP2PmsgPump->m_nThreadId;
        // W2 (p2p_PumpPerf.md): the FIFO is now empty - the pump may park in
        // Step 3/4 below.  Disarm the wake flag under m_oCSection so the next
        // producer (which must acquire m_oCSection strictly after this point)
        // re-issues a wake.  Kept inside the lock with the GetP2Pmsg() that
        // observed empty, so there is no window where a message is enqueued
        // without a wake.
        if ( !pP2Pmsg )
          pP2PmsgPump -> m_bWakePosted = false;
      }
    };

    // Step 1 - Timer callback interceptions
    // NOTES: Effectively synchronous P2PeerCon and P2PeerTarget
    //        callbacks.
    //      : Code block effectively duplicated in CancelP2PmsgTimer
    if ( pP2Pmsg                      &&
         pP2Pmsg->nMsg == P2P_PITimer    )
    {
      // P2Peerio::On_PITimer call backs
      if ( pP2Pmsg->pPeerio )
      {
        try { pP2Pmsg->pPeerio->On_PITimer ( false
                                           , pP2Pmsg->iPitimeID 
                                           , pP2Pmsg->dwUserKey ); }
        catch ( P2Pevent *pEVT ) { pP2Pmsg->pPeerio
                                          ->GetP2PeerCon()
                                          ->Drop(pEVT->Isolate()); }
        catch ( ... )
        {
          P2Pevent *pEVT =
          EVERR->MODULE->AFP(dwTimeout)->AFP(nSigID)
               ->Message_T("Unexpected P2Peerio::On_PITimer() exception" )
               ->Advice_T ("C++, CRT, Native, Win32 (SNHappen)" )
               ->HResult( GetLastError() );
          pP2Pmsg -> pPeerio -> GetP2PeerCon() -> Drop ( pEVT->Isolate() );
        }
      }
      // P2PeerCon::On_PITimer call backs
      if ( pP2Pmsg->pCon )
      {
        try { pP2Pmsg->pCon->On_PITimer ( false
                                        , pP2Pmsg->iPitimeID 
                                        , pP2Pmsg->dwUserKey ); }
        catch ( P2Pevent *pEVT ) { pP2Pmsg->pCon->Drop(pEVT->Isolate()); }
        catch ( ... )
        {
          P2Pevent *pEVT =
          EVERR->MODULE->AFP(dwTimeout)->AFP(nSigID)
               ->Message_T("Unexpected P2PeerCon::On_PITimer() exception" )
               ->Advice_T ("C++, CRT, Native, Win32 (SNHappen)" )
               ->HResult( GetLastError() );
          pP2Pmsg -> pCon -> Drop ( pEVT->Isolate() );
        }
      }
      // P2PeerTarget::On_PITimer call backs
      else if ( pP2Pmsg->pTarget )
      {
        P2PeerTarget *pTarget = (P2PeerTarget *)pP2Pmsg->pTarget;
        try { pTarget->On_PITimer ( false
                                  , pP2Pmsg->iPitimeID 
                                  , pP2Pmsg->dwUserKey ); }
        catch ( P2Pevent *pEVT ) { pEVT->Cancel(); }
        catch ( ... )
        {
          P2Pevent *pEVT =
          EVERR->MODULE->AFP(dwTimeout)->AFP(nSigID)
               ->Message_T("Unexpected P2PeerTarget::On_PITimer() exception" )
               ->Advice_T ("C++, CRT, Native, Win32 (SNHappen)" )
               ->HResult  ( GetLastError() );
          pEVT->Cancel();
        }
      }
      pP2Pmsg   = ReleaseP2Pmsg ( pP2Pmsg );
      dwTimeout = 0;                   // Negate subsequent delay
      dwResult  = P2PmsgPump_MSG;
    }

    // Step 2 - Pump single P2Pmsg instance
    // NOTES: DispatchP2Pmsg() will ultimately map into P2PeerCon_MAP,
    //        P2PeerMsg_MAP and P2PeerSys_MAP handlers.
    //      : Intercept and route P2PeerMsg's destined for
    //        other P2Peer's
    if ( pP2Pmsg )
    {
      dwTimeout = 0;                   // Negate subsequent delay
      //P2PeerTarget *pTarget = (P2PeerTarget *)pP2Pmsg->pTarget;
      VerifyP2Pmsg ( pP2Pmsg );
      if ( PreTranslateP2Pmsg(pP2Pmsg) )
      {
        TranslateP2Pmsg ( pP2Pmsg );
        DispatchP2Pmsg  ( pP2Pmsg, pP2PmsgPump );
      }
      dwResult = P2PmsgPump_MSG;
      pP2Pmsg  = 0;
    };

    // Step 2b - W1 (p2p_PumpPerf.md): batch-drain the remaining FIFO this visit.
    // NOTES: GetP2Pmsg() only ever returns application / CN_P2Peer* messages -
    //        P2P_PITimer messages live exclusively in m_oCListP2PmsgPit and are
    //        fetched via GetTimer() at the TOP, never here - so every batched
    //        message dispatches through the Step-2 path and needs no Step-1
    //        timer handling.  Bounded by kMaxPumpBatch so a burst can neither
    //        starve Step-3 IO servicing nor the timer poll (both run once per
    //        visit) and a self-requeueing message cannot spin unbounded.  This
    //        amortises the per-visit pump lookup (global s_oCSectionP2PmsgPump
    //        + hash), the timer poll and the GetQueuedCompletionStatus(0) poll
    //        across the whole batch - the throughput lever for the pipelined
    //        Phase-T path.  Each iteration still releases m_oCSection before
    //        DispatchP2Pmsg (handlers must never run under the pump lock; see
    //        the AB-BA teardown fix), so ordering/lock discipline is unchanged.
    if ( dwResult == P2PmsgPump_MSG )
    {
      const int kMaxPumpBatch = 64;    // fairness cap (tunable)
      for ( int nBatch = 0; nBatch < kMaxPumpBatch; ++nBatch )
      {
        P2Pmsg *pBatch = 0;
        {
          P2PsafeCS oSafeCSb = pP2PmsgPump -> m_oCSection;
          pBatch = pP2PmsgPump -> GetP2Pmsg ( );
          if (  pBatch &&
                pBatch->pCon &&
               !pBatch->pCon->m_hCPortP2PumpID )
            pBatch -> pCon -> m_hCPortP2PumpID = pP2PmsgPump->m_nThreadId;
          if ( !pBatch )                // FIFO drained empty
            pP2PmsgPump -> m_bWakePosted = false;   // W2: re-arm producer wake
        }
        if ( !pBatch )
          break;
        VerifyP2Pmsg ( pBatch );
        if ( PreTranslateP2Pmsg(pBatch) )
        {
          TranslateP2Pmsg ( pBatch );
          DispatchP2Pmsg  ( pBatch, pP2PmsgPump );
        }
      }
    }

    // Step 3 - Pump OVERLAPPEDcon objects through the IOCP
    // NOTES: Dispatch OVERLAPPEDcon messages directly into keyed
    //        P2PeerCon objects
    if ( pP2PmsgPump->m_hIOCP )
    {
      ULONG_PTR  ulCompletionKey = 0;
      OVERLAPPED *pOVERLAPPED    = 0;
      DWORD      dwBytes         = 0;
      // NOTES: GetQueuedCompletionStatus() reports a FAILED completion by
      //        returning FALSE while STILL yielding the OVERLAPPED and the
      //        completion key -- the error itself only lives in
      //        GetLastError().  That result used to be discarded and every
      //        completion was dispatched as On_QueuedCompletionStatus(0,..),
      //        i.e. as an unconditional SUCCESS.  Capture it here, next to the
      //        call, before AddRef()/anything else can clobber the thread's
      //        last-error, and hand it to the connection as the dwError
      //        argument the handler has always been documented to take
      //        (P2PeerCon.cpp:355-372).
      //      : On Windows the omission was survivable: the handler treated the
      //        failure as a 0-byte read and simply re-armed, and the re-arming
      //        ReadFile()/WSARecv() then failed SYNCHRONOUSLY (WSAECONNRESET /
      //        ERROR_NETNAME_DELETED), which threw out of P2Peerio::Recv() and
      //        dropped the connection one lap later.
      //      : On Linux it is fatal.  A peer's graceful close surfaces as a
      //        read CQE of 0 bytes, which the io_uring shim reports as
      //        FALSE/ERROR_HANDLE_EOF (Platform/p2piocp.cpp:289-292), and
      //        re-arming NEVER fails synchronously there -- an io_uring submit
      //        always returns ERROR_IO_PENDING (p2piocp.cpp:184).  So the EOF
      //        came back forever: the pump spun on it at 100% CPU (measured:
      //        3.75 MILLION ERROR_HANDLE_EOF completions on one connection in
      //        the 10s of p2p_expreg's phase 4), the connection was never
      //        Drop()ped, and the ON_P2PeerCon_CLOSE notification it posts was
      //        never issued -- so no On_ConClose / On_XCidConClose handler ever
      //        ran for a disconnecting peer on Linux.
      BOOL bStatus =
      GetQueuedCompletionStatus ( pP2PmsgPump->m_hIOCP
                                ,&dwBytes
                                ,&ulCompletionKey
                                ,&pOVERLAPPED
                                , dwTimeout );
      DWORD dwGQCSerror = bStatus ? ERROR_SUCCESS : GetLastError();

      dwTimeout = 0;                   // Negate subsequent delay
      //  A completion names an OPERATION, and the OVERLAPPED is the name.  Dispatch
      //  used to turn on the key alone, so a completion carrying a key and a NULL
      //  OVERLAPPED reached the connection anyway - and every
      //  On_QueuedCompletionStatus() override begins by comparing that pointer
      //  against its member OVERLAPPEDs to decide which operation completed.  On any
      //  connection that is not currently listening m_pOVERLAPPEDaccept is NULL too,
      //  so `pOVERLAPPEDcon == m_pOVERLAPPEDaccept` is null == null, the ACCEPT branch
      //  is taken on a connection that never accepted anything, and
      //  releaseOVERLAPPED() dereferences the null (P2PeerConWsa.cpp).  Measured on
      //  Linux/ASan+UBSan as an intermittent "member access within null pointer of
      //  type OVERLAPPEDcon" under the outbound flood in p2pweb_w5 §8b (D34).
      //    : The pair does not arise on Windows and there is no handler that could
      //      use it if it did: with no OVERLAPPED there is no operation to complete,
      //      no buffer to hand back and no reference to release.  So the guard is
      //      the whole fix, and it belongs HERE rather than in each transport -
      //      P2PeerCon, P2PeerConWsa, P2PeerConDmx and P2PeerCon232 all make the
      //      same comparison, and three of them would have been left to find it
      //      again.
      if ( ulCompletionKey && !pOVERLAPPED && getenv("P2P_D34_TRACE") )
        fprintf ( stderr, "[d34] key=%p err=%u bytes=%u\n"
                , (void*)ulCompletionKey, (unsigned)dwGQCSerror, (unsigned)dwBytes );
      if ( ulCompletionKey && pOVERLAPPED )
      {
        OVERLAPPEDcon *pOVERLAPPEDcon = (OVERLAPPEDcon *)pOVERLAPPED;
        P2PeerCon     *pCon = (P2PeerCon *)ulCompletionKey;
        // AddRef FIRST, before anything is read or written through pCon
        // NOTES: SECURITY_REVIEW M6.  The two field assignments below used to
        //        run BEFORE this line, i.e. on the raw completion key with no
        //        reference held -- so every store went to a connection this
        //        thread had not yet claimed.  The reference is what makes the
        //        object this thread's for the duration; taking it after the
        //        first write is taking it after the window it exists to close
        //      : This is a REORDER, not a new guard, and it is worth being
        //        precise about what it does and does not buy.  The pointer is
        //        normally kept alive by the reference prepareOVERLAPPED() takes
        //        for the OVERLAPPED itself, so on the ordinary path the stores
        //        were landing on a live object and the defect was latent.  What
        //        the old order could not survive is a completion whose owning
        //        reference has already been dropped -- teardown, a cancelled
        //        operation, a PostQueuedCompletionStatus carrying a stale key --
        //        where the stores wrote into freed memory and AddRef() then
        //        incremented a refcount inside it
        //      : AddRef() itself dereferences pCon, so this does not make a
        //        genuinely dangling key safe; nothing at this seam can.  It
        //        narrows the window to the single unavoidable access instead of
        //        spreading it across three, and it stops the two STORES, which
        //        are what corrupt a reused allocation
        pCon -> AddRef ( );
        pCon -> m_hCPortP2PumpID = pP2PmsgPump->m_nThreadId;
        if (  pP2PmsgPump->m_hIOCP &&
             !pCon->m_hCPort          )
          pCon -> m_hCPort = pP2PmsgPump->m_hIOCP;
        try { pCon -> On_QueuedCompletionStatus ( dwGQCSerror, dwBytes
                                                , pOVERLAPPEDcon ); }
        catch ( P2Pevent *pEVT ) { pCon->Drop(pEVT->Isolate()); }
        catch ( ... )
        {
          P2Pevent *pEVT =
          EVERR->MODULE->AFP(dwTimeout)->AFP(nSigID)
               ->Message_T("Unexpected On_GetQueuedCompletionStatus() exception" )
               ->Advice_T ("C++, CRT, Native, Win32 (SNHappen)" )
               ->HResult( GetLastError() );
          pCon -> Drop ( pEVT->Isolate() );
        }
        pCon -> Release ( );
        dwResult = P2PmsgPump_MSG;
      }

      // NOTES: Use the CAPTURED error, not a second GetLastError() -- the
      //        latter is whatever the intervening code last set.
      else if ( pOVERLAPPED  != pP2PmsgPump->m_pOVERLAPPED &&
                dwGQCSerror  != WAIT_TIMEOUT                  )
        EVERR->MODULE->AFP(dwTimeout)->AFP(nSigID)
             ->Message_T("GetQueuedCompletionStatus() failed" )
             ->Advice_T ("Internal (SNHappen)" )
             ->HResult( dwGQCSerror )->Throw();
    }

    // Step 4 - Suspend for arrival of P2Pmsg's
    // NOTES: Skipped upon non-Wait
    else if ( dwTimeout                                     &&
              pP2PmsgPump->SigCount() <= 0    )      // locked read (TSan Risk #3)
    {
      if ( WaitForSingleObject(pP2PmsgPump->m_hQueEvent,dwTimeout) == WAIT_FAILED )
        EVERR->MODULE->AFP(dwTimeout)->AFP(nSigID)
             ->Message_T("WaitForSingleObject() failed" )
             ->HResult( GetLastError() )
             ->Throw();              // All is lost
      dwTimeout = 0;
      goto TOP;
    }

    // Tidy up, and
    nSigID = pP2PmsgPump -> SigPop ( );   // locked pop (TSan Risk #3)
    return dwResult;
};

//
//  Description: Posts P2Pmsg
//               NOTES: Thread context sensitive.  Use GetP2Pmsg()
//                      for retrieval of queue entries
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message object to be posted.  Control over object
//               life cycle is assumed
//
//               P2PeerCon *pCon
//               Connection object to be posted.  Control over
//               object life cycle is assumed
//
//               short nCon
//               Connection activity
//
//               P2PumpID nP2PumpID = 0
//               Pump to which P2Pmsg is posted
//                 0.. Current context
//
//  Returns:     UINT
//               Unpumped messages
//
/*UINT
PostP2Pmsg ( P2PaddrSTR strP2Paddr, UINT nCode, P2Pmsg_t nMsg
           , P2PeerCon *pCon, P2PeerMsg *pMsg, DWORD nP2PumpID )
{
    // Isolation
    P2PsafeCS   oSafeCS = s_oCSectionP2Pmsg;
    P2PmsgPump *pP2PmsgQue;

    // Thread context
    pP2PmsgQue = P2PmsgPump::GetP2PmsgPump ( nP2PumpID );
    if ( !pP2PmsgQue )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details" )
           ->Throw();

    // Observe P2PmsgQue capacity
    //  NOTES: This overload is superseded and does not compile - the whole
    //         function is inside the block comment that opens above.  The
    //         hardcoded 10000 was left here for years and is where the figure
    //         every live diagnostic printed came from; it is rendered from the
    //         constant now so the file names ONE bound, and a reader counting
    //         thresholds by grep counts one.
    if ( s_cP2Pmsg > s_cP2PmsgMAX )
      EVERR->MODULE
           ->Message(P2PMSG_QUEFULL_FMT "\n"
                     "ADVICE\t: Refer PumpP2Pmsg()", (unsigned long)s_cP2PmsgMAX )
           ->HResult(P2Pevent_QUEFULL)
           ->Throw();

    // P2PeerCon touch-up's
    // NOTES: Enumeration is suspended whilst object exists in the
    //        P2Pmsg domain
    if (  pCon &&
         !pCon->m_hCPort )
      pCon -> m_hCPort = pP2PmsgQue -> m_hIOCP;

    // Manufacture
    P2Pmsg *pP2Pmsg = new P2Pmsg;
            pP2Pmsg -> strP2Paddr   = strP2Paddr;
            pP2Pmsg -> nCode        = nCode;
            pP2Pmsg -> nMsg         = nMsg;
            pP2Pmsg -> pPeerio      = 0;
            pP2Pmsg -> pCon         = pCon;
            pP2Pmsg -> pMsg         = pMsg;
            pP2Pmsg -> pTarget      = 0;
            pP2Pmsg -> pExtra       = 0;
            pP2Pmsg -> nHubThreadID = 0;
            pP2Pmsg -> hEventHub    = 0;
            pP2Pmsg -> bNotify      = false;
            pP2Pmsg -> iPitime      = 0;
            pP2Pmsg -> iPitimeID    = 0;
            pP2Pmsg -> wParam       = 0;
            pP2Pmsg -> lParam       = 0;
    s_cP2Pmsg++;

    // Implementation
    return pP2PmsgQue -> PutP2Pmsg ( pP2Pmsg, false );
}*/

//
//  Description: Posts P2PeerMsg
//               NOTES: Thread context sensitive.  Use GetP2Pmsg()
//                      for retrieval of queue entries
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message object to be posted.  Control over object
//               life cycle is assumed
//
//               DWORD nThreadID
//               Thread to which P2PeerMsg is to be posted
//
//               bool bPrepend
//               Prepend P2PeerMsg flag
//
//  Returns:     UINT
//               Unpumped messages
//
P2PeerMsg*
PostP2Pmsg ( P2PeerMsg *pMsg, P2PumpID nPumpID, bool bPrepend )
{
    // Isolation
    P2PeerMsgSP spMsg    = pMsg;
    P2PsafeCS    oSafeCS = s_oCSectionP2PmsgPump;

    // Pump context
    P2PmsgPump *pP2PmsgPump = 0;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      EVERR->Module ("%s(pMsg=%s, nPumpID=%i, bPrepend=%i)", __FUNCTION__
                    , pMsg->GetVisualRTSummary(), nPumpID, (int)bPrepend )
           ->AFPmsg(pMsg)->AFP(nPumpID)->AFP(bPrepend)
           ->Message("P2PmsgPumpID=%i not started"
                    , nPumpID )
           ->Advice ("Refer CreateP2PmsgPump() for further details" )
           ->Throw  ( );

    // Hub context
    P2PmsgPump *pP2PmsgThis = 0;
    if ( s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgThis) &&
         pP2PmsgThis                                                    &&
         pP2PmsgThis->m_nHubID != pP2PmsgPump->m_nHubID                    )
    {
      EVERR->Module ("%s(pMsg=%s, nPumpID=%i, bPrepend=%i)", __FUNCTION__
                    , pMsg->GetVisualRTSummary(), nPumpID, bPrepend )
           ->Message("Attempt to swap PostP2Pmsg across P2PmsgHub contexts(%i to %i)"
                    , pP2PmsgThis->m_nHubID
                    , pP2PmsgPump->m_nHubID )
           ->Throw  ( );
    }

    // Duplicate posting
    // NOTES: Logically P2PeerMsg's may only ever be posted to a single pump
    P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)pMsg->r_data().c_vBlob();
    if ( (pPrefix->uiState&P2PeerMsgState_Posted) == P2PeerMsgState_Posted )
      EVERR->MODULE
           ->Message_T("Attempt to re-post a posted P2PeerMsg" )
           ->HResult(P2Pevent_QUEFULL)
           ->Throw();
    pPrefix -> uiState |= P2PeerMsgState_Posted;

    // Observe P2PmsgQue capacity
    if ( s_cP2Pmsg > s_cP2PmsgMAX )
      EVERR->MODULE
           ->Message(P2PMSG_QUEFULL_FMT_W, (unsigned long)s_cP2PmsgMAX )
           ->Advice_T ("Refer PumpP2Pmsg()" )
           ->HResult(P2Pevent_QUEFULL)
           ->Throw();

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> strP2Paddr   = spMsg -> GetSource();
            pP2Pmsg -> nCode        = CN_P2PeerMsg;
            pP2Pmsg -> nMsg         = P2P_P2Pmsg;//pMsg -> Type();
            pP2Pmsg -> pMsg         = spMsg.Dereference();
            pP2Pmsg -> pTarget      = pP2PmsgPump -> m_pTarget;
            pP2Pmsg -> bNotify      = false;
ASSERT(VerifyP2Pmsg(pP2Pmsg));

    // Implementation
    oSafeCS = pP2PmsgPump->m_oCSection;
    pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, bPrepend );
    return (P2PeerMsg *)0;
}

//
//  Description: W6 (p2p_PumpPerf.md) - batch producer handoff.  Posts a whole
//               span of P2PeerMsg's to one pump under a SINGLE pump-registry
//               lookup + a SINGLE m_oCSection acquire, and - via W2's wake
//               coalescing (PutP2Pmsg wakes only on the 0->1 queue transition)
//               - a SINGLE cross-thread wake for the burst.  The per-message
//               work (dup-post guard, capacity guard, factory, field-fill) is
//               identical to the 3-arg PostP2Pmsg; only the per-message global
//               lock (s_oCSectionP2PmsgPump), the per-message m_oCSection
//               acquire and the per-message wake are amortised.
//               NOTES: The caller MUST bound nCount well below s_cP2PmsgMAX -
//                      the pump cannot drain (it needs m_oCSection) while this
//                      holds the lock across the batch, so an over-large batch
//                      would trip the capacity guard AND stall the pipeline.
//                      Post large sends in chunks (releasing between chunks lets
//                      the pump drain).  Intended for bounded bursts such as a
//                      replication delta flush.
//                    : Additive - the single-message PostP2Pmsg/PostP2PeerMsg
//                      path is untouched; callers opt in.
//
void
PostP2PmsgBatch ( P2PeerMsg **apMsg, size_t nCount, P2PumpID nPumpID )
{
    // Nothing to do
    if ( !apMsg || nCount == 0 )
      return;

    // Pump context (looked up ONCE for the whole batch)
    P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump = 0;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      EVERR->MODULE->AFP(nPumpID)
           ->Message("P2PmsgPumpID=%i not started", nPumpID )
           ->Advice ("Refer CreateP2PmsgPump() for further details" )
           ->Throw  ( );

    // Hub context (checked ONCE - same destination pump for the whole batch)
    P2PmsgPump *pP2PmsgThis = 0;
    if ( s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgThis) &&
         pP2PmsgThis                                                    &&
         pP2PmsgThis->m_nHubID != pP2PmsgPump->m_nHubID                    )
      EVERR->MODULE
           ->Message("Attempt to swap PostP2Pmsg across P2PmsgHub contexts(%i to %i)"
                    , pP2PmsgThis->m_nHubID, pP2PmsgPump->m_nHubID )
           ->Throw  ( );

    // Enqueue the whole batch under ONE m_oCSection hold.  PutP2Pmsg's W2 wake
    // coalescing fires the single wake on the first message (queue 0->1); the
    // rest are silent.
    oSafeCS = pP2PmsgPump -> m_oCSection;
    for ( size_t i = 0; i < nCount; ++i )
    {
      if ( !apMsg[i] )                 // skip nulls
        continue;
      // Per-message ownership guard: holds pMsg until Dereference() transfers it
      // to the P2Pmsg, so a guard that throws below frees it (mirrors the 3-arg
      // PostP2Pmsg's P2PeerMsgSP).
      P2PeerMsgSP spMsg = apMsg[i];
      P2PeerMsg  *pMsg  = spMsg.p_SafePtr ( );

      // Duplicate posting guard
      P2PeerMsgPrefix *pPrefix = (P2PeerMsgPrefix *)pMsg->r_data().c_vBlob();
      if ( (pPrefix->uiState&P2PeerMsgState_Posted) == P2PeerMsgState_Posted )
        EVERR->MODULE
             ->Message_T("Attempt to re-post a posted P2PeerMsg" )
             ->HResult(P2Pevent_QUEFULL)->Throw();
      pPrefix -> uiState |= P2PeerMsgState_Posted;

      // Capacity guard (the pump cannot drain under this lock - bound the batch)
      if ( s_cP2Pmsg > s_cP2PmsgMAX )
        EVERR->MODULE
             ->Message(P2PMSG_QUEFULL_FMT_W, (unsigned long)s_cP2PmsgMAX )
             ->Advice_T ("Refer PostP2PmsgBatch(): bound the batch size" )
             ->HResult(P2Pevent_QUEFULL)->Throw();

      // Manufacture (identical to the 3-arg PostP2Pmsg)
      P2Pmsg *pP2Pmsg = P2PmsgFactory();
              pP2Pmsg -> strP2Paddr = pMsg -> GetSource();
              pP2Pmsg -> nCode      = CN_P2PeerMsg;
              pP2Pmsg -> nMsg       = P2P_P2Pmsg;
              pP2Pmsg -> pMsg       = spMsg.Dereference();  // transfer ownership
              pP2Pmsg -> pTarget    = pP2PmsgPump -> m_pTarget;
              pP2Pmsg -> bNotify    = false;
ASSERT(VerifyP2Pmsg(pP2Pmsg));
      pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, false );
    }
}

//
//  Description: Posts Win32 message through P2Peer message maps
//               NOTES: Thread context sensitive.  Use GetP2Pmsg()
//                      for retrieval of queue entries
//
//
//  Parameters:  DWORD nThreadID
//               Thread to which P2PeerMsg is to be posted
//
//               P2Pmsg_t nMsg
//               Win32 message identification
//
//               WPARAM wParam
//               User defined
//
//               LPARAM lParam
//               User defined
//
//  Returns:     UINT
//               Unpumped messages
//
UINT
PostP2Pmsg ( DWORD nThreadID
           , P2Pmsg_t nMsg, WPARAM wParam, LPARAM lParam )
{
    // Isolation
    P2PsafeCS   oSafeCS = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgQue;

    // Thread context
    pP2PmsgQue  = P2PmsgPump::GetP2PmsgPump ( nThreadID );
    if ( !pP2PmsgQue )
      EVERR->Module ("%s(P2PmsgPumpID=%i, nMsg=%i, wParam=%i, wParam=%i)", __FUNCTION__
                    , nThreadID, nMsg, wParam, lParam )
           ->Message("P2Pmsg pump (%i) not started"
                    , nThreadID )
           ->Advice ("Refer StartupP2Pmsg() for further details" )
           ->Throw();

    // Observe P2PmsgQue capacity
    if ( s_cP2Pmsg > s_cP2PmsgMAX )
      EVERR->MODULE
           ->Message(P2PMSG_QUEFULL_FMT, (unsigned long)s_cP2PmsgMAX )
           ->Advice ("Refer PumpP2Pmsg()" )
           ->HResult(P2Pevent_QUEFULL)
           ->Throw();

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> nCode        = CN_P2PeerSys;
            pP2Pmsg -> nMsg         = nMsg;
            pP2Pmsg -> pExtra       = pP2Pmsg;
            pP2Pmsg -> bNotify      = false;
            pP2Pmsg -> wParam       = wParam;
            pP2Pmsg -> lParam       = lParam;
ASSERT(VerifyP2Pmsg(pP2Pmsg));

    // Implementation
    pP2PmsgQue -> PutP2Pmsg ( pP2Pmsg, false );
    return 0;
}

//
//  Description: Fetches next queued P2Pmsg
//               NOTES: Thread context sensitive.  Use PutP2Pmsg()
//                      for placement of entries on queue
//
//  Returns:     P2Pmsg*
//                 0.. Empty P2Pmsg pump
//
P2Pmsg*
GetP2Pmsg (  )
{
    // Isolation and locals
    P2PsafeCS  oSafeCS = s_oCSectionP2Pmsg;
    P2Pmsg    *pP2Pmsg = 0;

    // Thread context
    P2PmsgPump *pP2PmsgQue = P2PmsgPump::GetP2PmsgPump();
    if ( !pP2PmsgQue )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer CreateP2PmsgPump() for further "
                               "details" )
           ->Throw();

    // Implementation
    if ( pP2PmsgQue->GetCount() )
      pP2Pmsg = pP2PmsgQue -> GetP2Pmsg ( );
    return pP2Pmsg;
}

//
//  Exposes message count for nominated pump
//
//
//  Parameters:  P2PumpID nPumpID 
//               Identification code of pump those message
//               count is to be exposed
//                 0.. Summarise all pumps
//
//  Returns:     UINT
//               Unprocessed message count for nominated pump
UINT
GetP2PmsgCount( P2PumpID nPumpID )
{
    // Simply
    if ( nPumpID == ~0 )
      return s_cP2Pmsg;
    if ( nPumpID ==  0 )
      nPumpID = GetCurrentThreadId();

    // Isolation and locals
    P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump = 0;
    s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump);
    if ( !pP2PmsgPump )
      EVERR->MODULE->AFP(nPumpID)
           ->Message_T("P2Pmsg pump not started")
           ->Advice_T ("Refer StartupP2Pmsg() for further details")
           ->Throw();

    // Simply
    return pP2PmsgPump -> GetCount ( );
}

//
//  Description: Sets P2Pmsg event for nominated pump
//
//
//  Parameters:  P2PumpID nPumpID
//               Identification code of pump those message
//               event is to be set
//
//  Returns:     BOOL
//               Result code
//                 TRUE... Success
//                 FALSE.. Failure
BOOL
SetP2PmsgEvent ( P2PumpID nPumpID )
{
    // Isolation and locals
    P2PsafeCS   oSafeCS     = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump = P2PmsgPump::GetP2PmsgPump ( nPumpID );

    // Implementation
    return pP2PmsgPump ? pP2PmsgPump -> Wakeup ( nPumpID ) : FALSE;
}

//
//  Description: Cleans up P2Pmsg pump environment
//               NOTES: Compliments StartupP2Pmsg()
//                    : Pumps can only cleanup their own environment
//
/*void
DestroyP2PmsgPump ( )
{
    // Isolation
    P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;

    // Simply
    // NOTES: Pump may or may not have been previoulsy started
    delete P2PmsgPump::GetP2PmsgPump();
    return;
}*/

//
//  Flushes contents of queued P2Pmsg's for nominated PumpID
//  NOTES: Compliments StartupP2Pmsg()
//
//
//  Parameters:  P2PumpID nPumpID
//               Pump identification code
//
void
FlushP2Pmsg ( P2PumpID nPumpID )
{
    // Isolation
    P2PsafeCS      oSafeCS  = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump = 0;
    if ( nPumpID <= 0 )
      nPumpID = GetCurrentThreadId();
    s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump);
    if ( !pP2PmsgPump )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started" )
           ->Advice ("StartupP2Pmsg() for further details" )
           ->Throw();

    // Drop all queued P2Pmsg's
    // NOTES: Retain the connection management messages
    int cMsg = pP2PmsgPump->GetCount();
    while ( cMsg-- > 0  )
    {
      P2Pmsg *pP2Pmsg = pP2PmsgPump -> GetP2Pmsg ( );
      if ( pP2Pmsg->pCon )
        ReleaseP2Pmsg ( pP2Pmsg );
      else
        pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, false );
    }
}

//
//  Description: Checks current pump state
//
//
//  Parameters:  UINT nCode
//
//               P2Pmsg_t nMsg
//
//  Returns:     bool
//               Result
bool
CheckP2PmsgPumpState ( UINT nCode, P2Pmsg_t nMsg )
{
    // Isolation and locals
    P2PsafeCS   oSafeCS = s_oCSectionP2PmsgPump;
    P2PmsgPump *pPump   = 0;
    s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pPump);

    // Simply
    // NOTES: Pump may or may not have been previoulsy started
    if ( !pPump            ||
         !pPump->m_pP2Pmsg    )
      return false;
    if (  pPump->m_pP2Pmsg->nCode != nCode )
      return false;
    if (  pPump->m_pP2Pmsg->nMsg  != nMsg )
      return false;

    // Matching
    return true;
}

///////////////////////////////////////////////////////////////////////
//  Timers
//  NOTES: Each P2Pmsg pump supports timers that are independant of
//         other pumps

//
//  Description: Sets timer for nominated pump
//               NOTES: 
//
//  Parameters:  P2PaddrSTR strP2Paddr
//
//               UINT nCode
//
//               P2Pmsg_t nMsg
//
//               P2PeerCon *pCon
//
//               P2PeerMsg *pMsg
///              Message to be posted upon timer expiry
//
//               uElapse 
//               Specifies the time-out value, in milliseconds. 
//
//               DWORD nPumpID = 0
//               Identification code of pump for which timer is to be
//               set
//                 0.. Set timer for current pump
//                 ?.. PumpID
//
//  Returns:     UINT
//               Assigned timer idetification code
//
UINT
SetP2PmsgTimer ( P2PaddrSTR strP2Paddr, UINT nCode, P2Pmsg_t nMsg
               , P2PeerCon *pCon, P2PeerMsg *pMsg
               , P2Pmsecs_t uElapse, DWORD nPumpID )
{
    // Isolation
    P2PsafeCS   oSafeCS = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump;

    // Thread context
    pP2PmsgPump = P2PmsgPump::GetP2PmsgPump ( nPumpID );
    if ( !pP2PmsgPump )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details" )
           ->Throw();

    // Outstanding Timers
    if ( pP2PmsgPump->m_oCListP2PmsgPit.GetCount() > 1024 )
      EVERR->MODULE
           ->Message("P2Pmsg pump outstanding timer limit (%i) reached\n" 
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details"
                     , 1024 )
           ->Throw();

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> strP2Paddr   =  strP2Paddr;
            pP2Pmsg -> nCode        =  nCode;
            pP2Pmsg -> nMsg         =  nMsg;
            pP2Pmsg -> pCon         =  pCon;
            if ( pCon )
              pCon -> AddRef ( );
            pP2Pmsg -> pMsg         =  pMsg;
            pP2Pmsg -> bNotify      =  false;
            pP2Pmsg -> iPitime      = _time64(0)*1000 + uElapse;

    // Implementation
    return pP2PmsgPump -> SetTimer ( pP2Pmsg );
}

PITimerID
SetP2PmsgTimer ( DWORD nPumpID, P2Peerio *pPeerio
               , P2Pmsecs_t uMSecDelay, DWORD dwUserKey )
{
    // Isolation
    P2PsafeCS   oSafeCS = s_oCSectionP2Pmsg;
    P2PmsgPump *pP2PmsgPump;

    // Thread context
    pP2PmsgPump = P2PmsgPump::GetP2PmsgPump ( nPumpID );
    if ( !pP2PmsgPump )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details" )
           ->Throw();

    // Outstanding Timers
    if ( pP2PmsgPump->m_oCListP2PmsgPit.GetCount() > 1024 )
      EVERR->MODULE
           ->Message("P2Pmsg pump outstanding timer limit (%i) reached\n" 
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details"
                     , 1024 )
           ->Throw();

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> strP2Paddr   =  pP2PmsgPump -> m_oP2Paddr;
            pP2Pmsg -> nCode        =  CN_P2PeerCon;
            pP2Pmsg -> nMsg         =  P2P_PITimer;
            pP2Pmsg -> pPeerio      =  pPeerio;
            pP2Pmsg -> bNotify      =  false;
            pP2Pmsg -> iPitime      = _time64(0)*1000 + uMSecDelay;
            pP2Pmsg -> dwUserKey    = dwUserKey;

    // Implementation
    return pP2PmsgPump -> SetTimer ( pP2Pmsg );
}

PITimerID
SetP2PmsgTimer ( DWORD nPumpID, P2PeerCon *pCon
               , P2Pmsecs_t uMSecDelay, DWORD dwUserKey )
{
    // Isolation
    P2PsafeCS   oSafeCS = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump = 0;

    // Thread context
    pP2PmsgPump = P2PmsgPump::GetP2PmsgPump ( nPumpID );
    if ( !pP2PmsgPump )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details" )
           ->Throw();

    // Outstanding Timers
    if ( pP2PmsgPump->m_oCListP2PmsgPit.GetCount() > 1024 )
      EVERR->MODULE
           ->Message("P2Pmsg pump outstanding timer limit (%i) reached\n" 
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details"
                     , 1024 )
           ->Throw();

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> strP2Paddr   =  pP2PmsgPump -> m_oP2Paddr;
            pP2Pmsg -> nCode        =  CN_P2PeerCon;
            pP2Pmsg -> nMsg         =  P2P_PITimer;
            pP2Pmsg -> pCon         =  pCon;
            if ( pCon )
              pCon -> AddRef ( );
            pP2Pmsg -> bNotify      =  false;
            pP2Pmsg -> iPitime      = _time64(0)*1000 + uMSecDelay;
            pP2Pmsg -> dwUserKey    = dwUserKey;

    // Implementation
    return pP2PmsgPump -> SetTimer ( pP2Pmsg );
}

PITimerID
SetP2PmsgTimer ( DWORD nPumpID, P2PeerTarget *pTarget
               , P2Pmsecs_t uMSecDelay, DWORD dwUserKey )
{
    // Isolation
    P2PsafeCS   oSafeCS = s_oCSectionP2Pmsg;
    P2PmsgPump *pP2PmsgPump = 0;

    // Thread context
    pP2PmsgPump = P2PmsgPump::GetP2PmsgPump ( nPumpID );
    if ( !pP2PmsgPump )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details" )
           ->Throw();

    // Outstanding Timers
    if ( pP2PmsgPump->m_oCListP2PmsgPit.GetCount() > 1024 )
      EVERR->MODULE
           ->Message("P2Pmsg pump outstanding timer limit (%i) reached\n" 
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details"
                     , 1024 )
           ->Throw();

    // Manufacture
    P2Pmsg *pP2Pmsg = P2PmsgFactory();
            pP2Pmsg -> strP2Paddr   =  pP2PmsgPump -> m_oP2Paddr;
            pP2Pmsg -> nCode        =  CN_P2PeerCon;
            pP2Pmsg -> nMsg         =  P2P_PITimer;
            pP2Pmsg -> pTarget      =  pTarget;
            pP2Pmsg -> bNotify      =  false;
            pP2Pmsg -> iPitime      = _time64(0)*1000 + uMSecDelay;
            pP2Pmsg -> dwUserKey    =  dwUserKey;

    // Implementation
    return pP2PmsgPump -> SetTimer ( pP2Pmsg );
}

//
//  Description: Exposes lapsed milliseconds until next timer fires
//               for nominated pump
//
//
//  Parameters:  DWORD nPumpID = 0
//               Identification code of pump for which timer is to be
//               killed
//                 0.. Use current context pump
//                 ?.. PumpID

P2Pmsecs_t
NextP2PmsgTimer( DWORD nPumpID )
{
    // Isolation
    P2PsafeCS   oSafeCS = s_oCSectionP2Pmsg;
    P2PmsgPump *pP2PmsgPump;

    // Pump context
    pP2PmsgPump  = P2PmsgPump::GetP2PmsgPump ( nPumpID );
    if ( !pP2PmsgPump )
      EVERR->MODULE
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details" )
           ->Throw();

    // Delegate
    return pP2PmsgPump -> PollTimer ( );
}

//
//  Description: Kills nominated timer for nominated pump
//               NOTES: The KillP2PmsgTimer function does not remove
//                      timer messages already posted to the P2PmsgQue
//
//  Parameters:  UINT nTimerID
//               Identification code of the timer to be killed.
//
//               DWORD nPumpID = 0
//               Identification code of pump for which timer is to be
//               killed
//                 0.. Kill timer for current pump
//                 ?.. PumpID
//
//  Returns:     UINT
//               Result code
//                 0.. Timer killed
//                 ?.. Not located, may have 
UINT
KillP2PmsgTimer( UINT nTimerID, DWORD nPumpID )
{
    // Thread context
    P2PsafeCS      oSafeCS  = s_oCSectionP2PmsgPump;
    P2PmsgPump *pP2PmsgPump = 0;
    if ( !s_ThreadID_P2PmsgPump.Lookup(nTimerID/0x100,pP2PmsgPump) ||
         !pP2PmsgPump                                                   )
      EVERR->Module ("%s(%i,%i)", __FUNCTION__
                    , nTimerID, nPumpID )
           ->Message("P2Pmsg pump not started\n"
                     "ADVICE\t: Refer StartupP2Pmsg() for further "
                               "details" )
           ->Throw();

    // Implementation
    P2Pmsg *pP2Pmsg = pP2PmsgPump->KillTimer ( nTimerID );
    if ( !pP2Pmsg )
      return nTimerID;
    ReleaseP2Pmsg ( pP2Pmsg );
    return 0;
}

//
//  Description: Cancels nominated timer
//               NOTES: The KillP2PmsgTimer function does not remove
//                      timer messages already posted to the P2PmsgQue
//
//  Parameters:  PITimerID nTimerID
//               Identification code of the timer to be cancelled
//
//  Returns:     UINT
//               Result code
//                 0.. Timer killed
//                 ?.. Not located, may have 
void
CancelP2PmsgTimer( UINT nPITimerID, bool bCallback )
{
    // Isolation
    P2Pmsg     *pP2Pmsg = 0;

    // To be sure, to be sure
    if ( !nPITimerID )
      return;

    // Pump context
    if ( !pP2Pmsg )
    {
      P2PsafeCS      oSafeCS  = s_oCSectionP2PmsgPump;
      P2PmsgPump *pP2PmsgPump = 0;
      if ( !s_ThreadID_P2PmsgPump.Lookup(nPITimerID/0x100,pP2PmsgPump) ||
           !pP2PmsgPump                                                   )
        EVERR->Module ("%s(%i)", __FUNCTION__
                      , nPITimerID )
             ->Message("P2Pmsg pump not running\n"
                       "ADVICE\t: Refer ShutdownP2Pmsg() for further "
                                 "details\n"
                             "\t: Corrupted PITimerID")
             ->Throw();
      pP2Pmsg = pP2PmsgPump->KillTimer ( nPITimerID );
      if ( !pP2Pmsg )
      {
        // NOT an error, and it used to throw here as "Corrupted PITimerID".
        // This function's own header says KillTimer does not remove timer
        // messages ALREADY POSTED to the P2PmsgQue - so a timer that fired
        // between its owner deciding to cancel it and this lookup is simply
        // gone from the table, which is an unavoidable race for every timer
        // rather than corruption.
        //
        // Why it mattered enough to change: ~P2PeerCon() cancels
        // m_uLoginTimerID and m_uRestartTimerID unconditionally, so losing
        // that race threw FROM A DESTRUCTOR - std::terminate, and the process
        // gone with an exit code and no explanation. It had never fired
        // because the login timer was never armed (the SetPITimer call sat
        // commented out in P2PeerTarget::On_ConAccept) and the restart timer
        // is only pending in a reconnect window. Arming the login deadline on
        // 2026-08-16 made it reproducible in p2p_acceptcap within one run.
        //
        // Nothing is leaked by returning: the message the timer already posted
        // still holds its AddRef on the connection (SetP2PmsgTimer above) and
        // is released when the pump dispatches it.
        if ( IsEVTRC )
          EVTRC->Module ("%s(%i)", __FUNCTION__, nPITimerID )
               ->Message("PITimer already fired; nothing to cancel" )
               ->Cancel ();
        return;
      }
    }

    // Step 1 - Timer callback interceptions
    // NOTES: Effectively synchronous P2PeerCon and P2PeerTarget
    //        callbacks.  Cancel flag MUST be set
    //      : Code block effectively duplicated in PumpP2Pmsg
    if ( pP2Pmsg                      &&
         pP2Pmsg->nMsg == P2P_PITimer    )
    {
      if ( pP2Pmsg->pCon &&
           bCallback        )
      {
        try { pP2Pmsg->pCon->On_PITimer ( true
                                        , pP2Pmsg->iPitimeID 
                                        , pP2Pmsg->dwUserKey ); }
        catch ( P2Pevent *pEVT ) { pP2Pmsg->pCon->Drop(pEVT->Isolate()); }
        catch ( ... )
        {
          P2Pevent *pEVT =
          EVERR->Module ("%s(%i)", __FUNCTION__
                        , nPITimerID )
               ->Message("Unexpected P2PeerCon::On_PITimer() exception\n"
                         "ADVICE\t: C++, CRT, Native, Win32 (SNHappen)" )
               ->HResult( GetLastError() );
          pP2Pmsg -> pCon -> Drop ( pEVT->Isolate() );
        }
      }
    }
    else
      ASSERT(!pP2Pmsg);

    // Tidy up, and
    ReleaseP2Pmsg ( pP2Pmsg );
}







//
//  Description: Swaps the processing context and/or parameters for
//               the current P2Pmsg object
//               NOTES: Context swap details are always thrown as
//                      as P2P_Context pointer exceptions
//                    : The P2Peer message map will intercept this
//                      exception and implement the change in context
//                      through this P2PeerTarget instance
//
//
//  Parameters:  P2PeerTarget *pTarget
//               
//               DWORD nThreadID
//               Identifier of thread in which context the P2Pmsg
//               object is to be processed
//
//               P2PeerCon *pCon
//               Connection to which current P2PeerMsg is to be
//               queued
//
//               P2PeerMsg *pMsg
//               New P2PeerMsg substituted for the existing P2PeerMsg
//               context
//
//               HWND hWnd
//               Window containing nMsg message handler that
//               subsequently delegates implementation via
//               pContext->pTarget->On_P2P(...)
//
//               UINT nWM_APP
//               WM_APP+offset message  
//               NOTES: Usually the WM_APP_P2PeerTarget definition is
//                      specified.  Should this definition conflict the
//                      option is available to specify an alterantive.
//                    : Nominated window must support handler for this
//                      message type.  This handler will subsequently
//                      delegate implementation to OnP2PeerTarget()
//
//  Exception:   P2Peer_Context*
//               Context exception intercepted by orginating
//               DispatchP2P() in order to recover P2PeerCon or
//               P2PeerMsg details and coordinate implementation in
//               the nominated context
//
mapRESULT
SwapP2PmsgContext  ( P2PeerTarget *pTarget, P2PumpID nPumpID
                   , P2PeerCon *pCon
                   , P2PeerMsg *pMsg
                   , HWND hWnd, UINT nWM_APP )
{
    // Locals
    P2Pmsg_Context *pContext    = 0;
    P2PmsgPump     *pP2PmsgPump = 0;
pTarget->P2PeerTarget::AssertValid();

    // Swap context
    // NOTES: Swaps are only ever valid from a PumpP2Pmsg context
    if ( !pP2PmsgPump )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      pP2PmsgPump       = 0;
      s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump);
      if (  pP2PmsgPump == NULL    ||
           !pP2PmsgPump->m_pP2Pmsg    )
        EVERR->MODULE
             ->Message("Non P2Peer map handler context")
             ->Advice ("Reference from P2PeerCON, P2PeerSYS or "
                       "P2PeerMSG_MAP handlers only" )
             ->Throw();
      if ( pP2PmsgPump->m_pContext )
        EVERR->MODULE
             ->Message("Recursive context swaps attempted")
             ->Advice ("SwapP2PmsgContext() has not returned immediately" )
             ->Throw();
      if ( pP2PmsgPump->m_bP2Pexplorer                    &&
           pP2PmsgPump->m_nPumpID != GetCurrentThreadId()    )
        EVERR->MODULE
             ->Message("Invalid operation from P2Pexpump context")
             ->Throw();
      pContext = new P2Pmsg_Context;
      ZeroMemory ( pContext, sizeof(P2Pmsg_Context) );
      pP2PmsgPump -> m_pContext = pContext;
    }

    // Construct and populate P2Pmsg_Context object
    // NOTES: It's important that the P2PeerCon notification or
    //        P2PeerMsg be routed back to nominated P2PeerTarget for
    //        implementation as per pContext->pTarget->On_P2PeerMsg()
    pContext -> pTarget   = pTarget;
    pContext -> nThreadID = nPumpID;
    pContext -> pCon      = pCon;
    pContext -> pMsg      = pMsg;
    pContext -> hWnd      = hWnd;
    pContext -> nWM_APP   = nWM_APP;

    // Tidy up, and
    // NOTES: Must only ever be called from P2PeerCon_MAP,
    //        P2PeerSys_MAP and P2PeerMsg_MAP handler
    //      : DispatchP2P() routing framework anticipates and
    //        processes these context swaps
    return msgSWAP;
}
//
//  Swaps the processing context and/or parameters for the current
//  P2Pmsg object
//  NOTES: For P2Pexpump context swaps P2PeerMsg to P2PmsgHub context
//         and for P2PmsgHub context swaps P2PeerMsg to P2Pexpump
//         context
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message whose context is to be swapped
//
mapRESULT
SwapP2PexpContext  ( P2PeerMsg *pMsg )
{
    // Locals
    P2Pmsg_Context *pContext    = 0;
    P2PmsgPump     *pP2PmsgPump = 0;
    P2PumpID        nPumpID     = 0;
    P2PeerTarget   *pTarget     = 0;

    // Swap context
    // NOTES: Swaps are only ever valid from a PumpP2Pmsg context
    if ( !pP2PmsgPump )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      pP2PmsgPump       = 0;
      s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump);
      if (  pP2PmsgPump == NULL    ||
           !pP2PmsgPump->m_pP2Pmsg    )
        EVERR->MODULE
             ->Message("Non P2Peer map handler context")
             ->Advice ("Reference from P2PeerCON, P2PeerSYS or "
                       "P2PeerMSG_MAP handlers only" )
             ->Throw();
      if ( pP2PmsgPump->m_pContext )
        EVERR->MODULE
             ->Message("Recursive context swaps attempted")
             ->Advice ("SwapP2PexpContext() has not returned immediately" )
             ->Throw();
      
      // Swap from P2PeerExp to P2PeerHub
      if ( pP2PmsgPump->m_bP2Pexplorer )
      {
        nPumpID = pP2PmsgPump -> m_pP2PmsgHubMgr -> m_nHubID;
        pTarget = pP2PmsgPump -> m_pP2PmsgHubMgr -> m_pHub;
      }

      // Swap from P2PeerHub to P2PeerExp
      if ( !pP2PmsgPump->m_bP2Pexplorer )
      {
        P2PmsgPump *pP2PexpPump = pP2PmsgPump -> m_pP2PmsgHubMgr -> m_pP2Pexplorer;
        if ( !pP2PexpPump )
          EVERR->MODULE
               ->Message("Hub has no P2Pexpump context")
               ->Throw();
        nPumpID = pP2PexpPump -> m_nPumpID;
        pTarget = pP2PexpPump -> m_pTarget;
      }
      pContext = new P2Pmsg_Context;
      ZeroMemory ( pContext, sizeof(P2Pmsg_Context) );
      pP2PmsgPump -> m_pContext = pContext;
    }

    // Construct and populate P2Pmsg_Context object
    // NOTES: It's important that the P2PeerCon notification or
    //        P2PeerMsg be routed back to nominated P2PeerTarget for
    //        implementation as per pContext->pTarget->On_P2PeerMsg()

    pContext -> pTarget   = pTarget;
    pContext -> nThreadID = nPumpID;
    pContext -> pMsg      = pMsg;

    // Tidy up, and
    // NOTES: Must only ever be called from P2PeerCon_MAP,
    //        P2PeerSys_MAP and P2PeerMsg_MAP handler
    //      : DispatchP2P() routing framework anticipates and
    //        processes these context swaps
    return msgSWAP;
}

//
//  Redirects the P2PeerMsg being processed in the current context
//  to another P2PeerHub
//  NOTES: For P2Pexpump context swaps P2PeerMsg to P2PmsgHub context
//         and for P2PmsgHub context swaps P2PeerMsg to P2Pexpump
//         context
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be redirected
//
mapRESULT
RedirectP2Pmsg ( P2PeerMsg *pMsg )
{
    // Locals
    //P2Pmsg_Context *pRedirect   = 0;
    P2PmsgPump     *pP2PmsgPump = 0;

    // Re-direction context
    // NOTES: Only ever valid from a PumpP2Pmsg context
    if ( !pP2PmsgPump )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      pP2PmsgPump       = 0;
      s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump);
      if (  pP2PmsgPump == NULL    ||
           !pP2PmsgPump->m_pP2Pmsg    )
        EVERR->MODULE
             ->Message("Non P2Peer map handler context")
             ->Advice ("Reference from P2PeerMSG_MAP handlers only" )
             ->Throw();
      if ( pP2PmsgPump->m_pContext )
        EVERR->MODULE
             ->Message("Redirection attempted within context swap")
             ->Advice ("SwapP2PmsgContext() has not returned immediately" )
             ->Throw();
      if ( pP2PmsgPump->m_bRedirect )
        EVERR->MODULE
             ->Message("Recursive re-directions attempted")
             ->Advice ("RedirectP2Pmsg() has not returned immediately" )
             ->Throw();
      if ( pP2PmsgPump->m_pP2Pmsg->pMsg != pMsg )
        EVERR->MODULE
             ->Message("Attempt to redirect non-active P2PeerMsg")
             ->Advice ("RedirectP2Pmsg() can only be applied to P2PeerMsg passed to handler" )
             ->Throw();
      if (  pP2PmsgPump->m_oP2Paddr == pMsg->GetDestin() &&
           !pMsg->IsReflected()                             )
        EVERR->MODULE
             ->Message("Attempt to recursively redirect P2PeerMsg" )
             ->Advice ("P2PeerMsg's must be redirected to another P2PeerHub" )
             ->Throw();

      //if ( pP2PmsgPump->m_bP2Pexplorer                    &&
      //     pP2PmsgPump->m_nPumpID != GetCurrentThreadId()    )
      //  EVERR->MODULE
      //       ->Message("Invalid operation from P2Pexpump context")
      //       ->Throw();
      pP2PmsgPump -> m_bRedirect = true;
    }

    // Tidy up, and
    // NOTES: Must only ever be called from P2PeerMsg_MAP handler
    //      : DispatchP2P() routing framework anticipates and
    //        processes these redirects
    return msgREDIRECT;
}

//
//  Repumps the P2PeerMsg being processed in the current context
//  NOTES: Action is immediate and the P2PeerMsg is not re-queued
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be redirected
//
mapRESULT
RepumpP2Pmsg ( P2PeerMsg *pMsg )
{
    // Locals
    //P2Pmsg_Context *pRepump     = 0;
    P2PmsgPump     *pP2PmsgPump = 0;

    // Re-direction context
    // NOTES: Only ever valid from a PumpP2Pmsg context
    if ( !pP2PmsgPump )
    {
      P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
      pP2PmsgPump       = 0;
      s_ThreadID_P2PmsgPump.Lookup(GetCurrentThreadId(),pP2PmsgPump);
      if (  pP2PmsgPump == NULL    ||
           !pP2PmsgPump->m_pP2Pmsg    )
        EVERR->MODULE
             ->Message("Non P2Peer map handler context")
             ->Advice ("Reference from P2PeerMSG_MAP handlers only" )
             ->Throw();
      if ( pP2PmsgPump->m_pContext )
        EVERR->MODULE
             ->Message("Redirection attempted within context swap")
             ->Advice ("SwapP2PmsgContext() has not returned immediately" )
             ->Throw();
      if ( pP2PmsgPump->m_bRedirect )
        EVERR->MODULE
             ->Message("Repump attempted within redirection context")
             ->Advice ("RedirectP2Pmsg() has not returned immediately" )
             ->Throw();
      if ( pP2PmsgPump->m_pP2Pmsg->pMsg != pMsg )
        EVERR->MODULE
             ->Message("Attempt to redirect non-active P2PeerMsg")
             ->Advice ("RedirectP2Pmsg() can only be applied to P2PeerMsg passed to handler" )
             ->Throw();
      if ( pP2PmsgPump->m_pP2PmsgHubMgr->m_oP2Paddr != pMsg->GetDestin() )
        EVERR->MODULE
             ->Message("Attempt to repump P2PeerMsg not addressed to this hub" )
             ->Advice ("P2PeerMsg's can only be repumped within P2PeerHub" )
             ->Throw();

      //if ( pP2PmsgPump->m_bP2Pexplorer                    &&
      //     pP2PmsgPump->m_nPumpID != GetCurrentThreadId()    )
      //  EVERR->MODULE
      //       ->Message("Invalid operation from P2Pexpump context")
      //       ->Throw();
      pP2PmsgPump -> m_bRepump = true;
    }

    // Tidy up, and
    // NOTES: Must only ever be called from P2PeerMsg_MAP handler
    //      : DispatchP2P() routing framework anticipates and
    //        processes these redirects
    return msgREPUMP;
}

///////////////////////////////////////////////////////////////////////
//  P2Pevent framework

static CMap<DWORD, DWORD, P2Pevent*, P2Pevent*&> s_ThreadID_P2Pevent;
static CRITICAL_SECTION                          s_oCSectionP2Pevent;
static bool           s_bStartupP2Pevent   = false;
static P2PeventSinkID s_nP2PeventSinkID    = 1;
//       P2PeventSinkID    P2PeventSinkModal = 0;
static DWORD          s_dwP2PeventRegMask  = 0;

typedef struct
{
    P2PeventSinkID nSinkID;            // Sink identification code
    HWND           hWnd;               // Registered window, or
    DWORD          nThreadID;          //            thread, or
    P2PumpID       nPumpID;            //            P2Pump, or
    P2PeventCBFnc  pP2PeventCBFnc;     //            callback

    P2PeerTarget  *pTarget;            // Nominated P2PeerTarget
    DWORD_PTR     dwCBKey;             // Call back key
    DWORD         dwNotifications;     // Registered Notifications.
} P2PeventSink;
           CList<P2PeventSink*> s_oCListP2PeventSink;
#ifdef _WIN32
extern "C" CList<P2PeventSink*> s_oCListP2PeventSink;
#endif

void
CalcP2PeventRegMask ( )
{
    // Loop for all sinks
    DWORD    dwMask = 0;
    POSITION   pos  = s_oCListP2PeventSink.GetHeadPosition();
    while ( pos )
      dwMask |= s_oCListP2PeventSink.GetNext(pos)->dwNotifications;
    s_dwP2PeventRegMask = dwMask;
}

//
//  Startups up the P2Pevent environment
//  NOTES: P2Pevent environment must be initialise prior to
//         referencing any P2Pevent utility
//
BOOL
StartupP2Pevent ( )
{
    if ( s_bStartupP2Pevent )
      return FALSE;
    InitializeCriticalSection ( &s_oCSectionP2Pevent );
    s_bStartupP2Pevent = true;

    // Default P2PeventSinkSet
    //P2PeventSinkModal = CreateP2PeventSink ( 0, 0, true );
    return TRUE;
}

//
//  Cleans up the P2Pevent environment
//  NOTES: P2Pevent environment must be cleaned up to recover
//         all allocated resources
//
void
CleanupP2Pevent ( )
{
    // To be sure, to be sure
    if ( !s_bStartupP2Pevent )
      return;
    DeleteCriticalSection ( &s_oCSectionP2Pevent );
    s_bStartupP2Pevent = false;
    s_nP2PeventSinkID  = 1;

    // Recover all P2Pevent resources
    POSITION pos = s_ThreadID_P2Pevent.GetStartPosition();
    while ( pos )
    {
      P2Pevent *pEvent    = 0;
      DWORD     nThreadId = 0;
      s_ThreadID_P2Pevent.GetNextAssoc ( pos, nThreadId, pEvent );
      delete    pEvent;
                pEvent = 0;
      s_ThreadID_P2Pevent.SetAt ( nThreadId, pEvent );
    }

    // Recover all P2PeventSink's
    while ( s_oCListP2PeventSink.GetCount() )
      delete s_oCListP2PeventSink.RemoveHead();
    s_dwP2PeventRegMask = 0;
    //P2PeventSinkModal   = 0;
}

//
//  Fetch last P2Pevent for current thread context
//  NOTES: Last thread events exist until displaced by a subsequent
//         P2Pevent or cancelled
//
//  Returns:     P2Pevent*
//               Retrieved P2Pevent
//
/*P2Pevent*
GetP2Pevent ( )
{
    // Locals
    DWORD     nThreadId = GetCurrentThreadId();
    P2Pevent *pEvent    = 0;
    
    // To be sure, to be sure
    // NOTES: Critical section requires at least one event to be
    //        initialised
    //P2PmsgPump *pP2PmsgPump   = 0;
    P2PsafeCS   oSafeCS_Event = s_oCSectionP2Pevent;
    s_ThreadID_P2Pevent.Lookup(nThreadId,pEvent);

    // Simply
    return pEvent;
}*/

/*P2Pevent*
IsolateP2Pevent ( )
{
    // Locals
    DWORD     nP2PmsgPumpId = GetCurrentThreadId();
    P2Pevent *pEvent        = 0;
    
    // To be sure, to be sure
    // NOTES: Critical section requires at least one event to be
    //        initialised
    P2PsafeCS   oSafeCS_Event = s_oCSectionP2PmsgPump;
    s_ThreadID_P2Pevent.Lookup ( nP2PmsgPumpId,pEvent );

    // Isolate
    P2Pevent *pEventNull = 0;
    s_ThreadID_P2Pevent.SetAt  ( nP2PmsgPumpId, pEventNull );

    // Tidy up, and
    return pEvent;
}*/

//
//  Closes previously opened P2PeventSink
//
//
//  Parameters: P2PeventSinkID nSinkID
//              Identification code of P2PeventSink to be closed
//
//  Returns:    BOOL
//                TRUE... Sink located and closed
//                FALSE.. Sink does not exist
BOOL
CloseP2PeventSink ( P2PeventSinkID nSinkID )
{
    // Locals
    BOOL   bResult = FALSE;

    // Locate and drop nominated P2PeventSink
    // NOTES: Destruction will recursively call this object
    P2PsafeCS oSafeCS_Event = s_oCSectionP2Pevent;
    POSITION   pos = s_oCListP2PeventSink.GetHeadPosition();
    while ( pos )
    {
      POSITION posDrop = pos;
      P2PeventSink *pP2PeventSink = s_oCListP2PeventSink.GetNext ( pos );
      if ( pP2PeventSink->nSinkID != nSinkID )
        continue;
      s_oCListP2PeventSink.RemoveAt ( posDrop );
      delete pP2PeventSink;
      bResult = TRUE;
    }

    // Simply
    CalcP2PeventRegMask ( );
    return bResult;
}

P2PeventSinkID
CreateP2PeventSinkdebug ( DWORD_PTR dwCBKey, P2PeventCBFnc pCBFnc, bool bReg4all )
{
    // Allocation
    P2PeventSink *pSink = new P2PeventSink;
    memset ( pSink, 0, sizeof(P2PeventSink) );
    pSink -> nSinkID         = s_nP2PeventSinkID++;
    pSink -> dwCBKey         = dwCBKey;
    pSink -> pP2PeventCBFnc  = pCBFnc;
    if ( bReg4all )
      pSink -> dwNotifications = ~0u;

    // Persist
    P2PsafeCS oSafeCS_Event = s_oCSectionP2Pevent;
    s_oCListP2PeventSink.AddTail ( pSink );

    // Done
    CalcP2PeventRegMask ( );
    return pSink -> nSinkID;
}

P2PeventSinkID
CreateP2PeventSink ( P2PeerTarget *pTarget
                   , bool bReg4all )
{
    // Must exist within P2PmsgPump context
    P2PmsgPump *pP2PmsgPump  = 0;
    P2PsafeCS   oSafeCS_Pump = s_oCSectionP2PmsgPump;
    P2PumpID    nThreadID    = GetCurrentThreadId();
    if ( !s_ThreadID_P2PmsgPump.Lookup(nThreadID,pP2PmsgPump) ||
         !pP2PmsgPump                                          )
      EVERR->Module ("%s(pTarget,bReg4all)", __FUNCTION__ )
           ->Message("ThreadID=%i has no P2PmsgPump context"
                    , nThreadID )
           ->Throw  ( );

    // Allocation
    P2PeventSink *pSink = new P2PeventSink;
    memset ( pSink, 0, sizeof(P2PeventSink) );
    pSink -> nSinkID         = s_nP2PeventSinkID++;
    pSink -> dwCBKey         = 0;
    pSink -> pP2PeventCBFnc  = 0;
    pSink -> nPumpID         = pP2PmsgPump -> m_nPumpID;
    pSink -> pTarget         = pTarget;
    if ( bReg4all )
      pSink -> dwNotifications = ~0u;

    // Persist
    P2PsafeCS oSafeCS_Event = s_oCSectionP2Pevent;
    s_oCListP2PeventSink.AddTail ( pSink );

    // Done
    CalcP2PeventRegMask ( );
    return pSink -> nSinkID;
}

//
// Enumerates P2PeventSink's
//
//
// Parameters: P2PeventSinkID& nSinkID
//
// Returns:    BOOL
//
BOOL
EnumP2PeventSink ( P2PeventSinkID& nSinkID )
{
    // Initialisation
    POSITION pos = s_oCListP2PeventSink.GetHeadPosition();
    if ( nSinkID == 0 && pos )
    {
       nSinkID = s_oCListP2PeventSink.GetNext(pos)->nSinkID;
       return TRUE;
    }

    // Interation
    while ( pos )
    {
      P2PeventSink *pP2PeventSink = s_oCListP2PeventSink.GetNext(pos);
      if ( pP2PeventSink->nSinkID == nSinkID && pos )
      {
         nSinkID = s_oCListP2PeventSink.GetNext(pos)->nSinkID;
         return TRUE;
      }
    }

    // Simply
    return FALSE;
}

//
//  Performs P2Pevent notifications for all registered P2PeventSinks
//
//
//  Parameters: P2Pevent *pEvent
//              Notification event
//
//  Returns:    int
//              Number of notifications performed
int
PerformP2PeventNotn ( P2Pevent *pEvent )
{
    // To be sure, to be sure
    // NOTES: P2Pevent may resolve to nothing
    if ( !pEvent )
    {
      pEvent = GetP2Pevent ( );
      if ( !pEvent )
        return 0;
    }

    // Introduce locals
    P2Pevent_e  eClass = pEvent -> GetClass();
    P2PeventSink    *pP2PeventSink = 0;
    int  nNotn = 0;

    // Loop for all registered objects
    P2PsafeCS oSafeCS_Event = s_oCSectionP2Pevent;
    POSITION pos = s_oCListP2PeventSink.GetHeadPosition();
    while ( pos )
    {
      // Filter notifications
      pP2PeventSink = s_oCListP2PeventSink.GetNext ( pos );
      if ( (pP2PeventSink->dwNotifications&(1<<eClass)) == 0 )
        continue;
      nNotn++;

      // Manage window notifications
      // NOTES: Copy asynchonously posted
      if ( pP2PeventSink->hWnd )
        ::PostMessage ( pP2PeventSink->hWnd
                      , WM_P2PeventNOTN
                      , (WPARAM)new P2Pevent(*pEvent), 0 );

      // Manage thread notifications
      // NOTES: Copy asynchronously posted
      if ( pP2PeventSink->nThreadID )
        ::PostThreadMessage ( pP2PeventSink->nThreadID
                            , WM_P2PeventNOTN
                            , (WPARAM)new P2Pevent(*pEvent), 0 );

      // Manage callback notifications
      // NOTES: Synchronous operation
      if ( pP2PeventSink->pP2PeventCBFnc )
        (*pP2PeventSink->pP2PeventCBFnc)( pP2PeventSink->nSinkID
                                        , pP2PeventSink->dwCBKey
                                        , *pEvent );

      // Manage P2PmsgPump notifications
      // NOTES: Asynchronous operation
      if ( pP2PeventSink->pTarget )
      {
        // Isolation
        P2PsafeCS oSafeCS = s_oCSectionP2PmsgPump;
        P2PumpID  nPumpID = pP2PeventSink -> nPumpID;

        // Pump context
        P2PmsgPump *pP2PmsgPump = 0;
        if ( !s_ThreadID_P2PmsgPump.Lookup(nPumpID,pP2PmsgPump) ||
             !pP2PmsgPump                                          )
          EVERR->Module ("%s(pEvent)", __FUNCTION__ )
               ->Message("P2PmsgPumpID=%i not started" )
               ->Advice ("Refer CreateP2PmsgPump() for further details"
                        , nPumpID )
               ->Throw  ( );

        // Observe P2PmsgQue capacity
        //  NOTES: This tested s_cP2PmsgMAX*2 until 2026-08-18, and the doubled
        //         band was NOT a considered exception - the reading that would
        //         justify one is that an event delivery needs headroom the
        //         ordinary posters have already been refused, so the diagnostic
        //         saying "the pump is full" can still be delivered.  That is not
        //         what happens: a raised P2Pevent reaches a client through
        //         P2Pevent::Cancel -> P2PeventPost_HWND (Msgexception.cpp),
        //         which PostMessage's to a window and calls one static callback.
        //         It never posts a P2Pmsg, so it spends none of this budget and
        //         there is nothing for a reserve to protect.  Nor is the band
        //         reachable today: PerformP2PeventNotn is exported but called
        //         from nowhere in the tree, so the second threshold never
        //         executed - it was a number waiting to surprise whoever wired
        //         the sink registry up.  One bound (Stage 0
        //         step 2); if a reserve is ever wanted, it needs a name and a
        //         test, not a *2.
        if ( s_cP2Pmsg > s_cP2PmsgMAX )
          EVERR->MODULE
               ->Message(P2PMSG_QUEFULL_FMT, (unsigned long)s_cP2PmsgMAX )
               ->Advice ("Refer PumpP2Pmsg()" )
               ->HResult(P2Pevent_QUEFULL)
               ->Throw();

        // Implementation
        //  The memset that was here is gone: P2PmsgFactory() already
        //  value-initialises, and a bulk wipe would now corrupt strP2Paddr.
        P2Pmsg *pP2Pmsg = P2PmsgFactory();
        pP2Pmsg -> nCode   = CN_P2Pevent;
        pP2Pmsg -> pTarget = pP2PeventSink -> pTarget;
        pP2Pmsg -> pEvent  = new P2Pevent ( *pEvent );
        pP2Pmsg -> wParam  = pP2PeventSink -> nSinkID;
        pP2Pmsg -> lParam  = GetCurrentThreadId();
        pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, false );
      }
    }

    // Tidy up and
    return nNotn;
}

DWORD
RegP2PeventCmd ( P2PeventSinkID nSinkID
               , DWORD dwCmd
               , DWORD dwCmdArg )
{
    // Locals
    P2PeventSink *pSink = 0;

    // Locate nominated P2PeventSink
    // NOTES: Expectation is that the sink exists
    P2PsafeCS oSafeCS_Event = s_oCSectionP2Pevent;
    POSITION   pos = s_oCListP2PeventSink.GetHeadPosition();
    while ( pos )
    {
      pSink = s_oCListP2PeventSink.GetNext ( pos );
      if ( pSink->nSinkID == nSinkID )
        break;
      pSink = 0;
    }

    // To be sure, to be sure
    if ( !pSink )
      EVERR->Module ("%s(%i,%i,%i)", __FUNCTION__
                    , nSinkID, dwCmd, dwCmdArg )
           ->Message("P2PeventSink=%i not located", nSinkID )
           ->Advice ("Perhaps corrupted P2PeventSinkID=%i", nSinkID )
           ->Throw();

    // Notification mask manangement
    if ( dwCmd == P2Pevent_AddMask )
      pSink->dwNotifications |=  dwCmdArg;
    else if ( dwCmd == P2Pevent_RemMask )
      pSink->dwNotifications &= ~dwCmdArg;
    else if ( dwCmd == P2Pevent_GetMask )
      return pSink->dwNotifications;

    // Tidy up, and
    CalcP2PeventRegMask ( );
    return pSink -> dwNotifications;
}

DWORD
IsP2PeventReg ( DWORD dwP2PeventMask )
{
    return s_dwP2PeventRegMask & dwP2PeventMask;
}

//
//  Sets last P2Pevent for current thread context
//  NOTES: Last thread events exist until displaced by a subsequent
//         P2Pevent or cancelled
//
//  Parameters:  P2Pevent *pEvent
//               New P2Pevent to be set for thread context
//
/*void
SetP2Pevent ( P2Pevent *pEvent )
{
    // Locals
    DWORD     nThreadId  = GetCurrentThreadId();
    P2Pevent *pEventLast = 0;
    
    // To be sure, to be sure
    // NOTES: Critical section requires at least one event to be
    //        initialised
    if ( pEventLast == 0 )
    {
      P2PsafeCS   oSafeCS_Event = s_oCSectionP2Pevent;
      s_ThreadID_P2Pevent.Lookup ( nThreadId, pEventLast );
      if ( pEventLast == pEvent )
        return;
      P2Pevent *pEventNull = 0;
      s_ThreadID_P2Pevent.SetAt  ( nThreadId, pEventNull );
    }

    // Clear previous and set new
    // NOTES: Destruction will recursively call this object
    delete pEventLast;
    s_ThreadID_P2Pevent.SetAt ( nThreadId, pEvent );

    // Simply
    return;
}*/

///////////////////////////////////////////////////////////////////////////////
//  P2PmsgSinks
//  NOTES: Manage the manufacture, translation, dispatch and
//         life cycle of internal P2PmsgSink's

//
//  Startups up the P2PmsgSink environment
//  NOTES: P2PmsgSink environment must be initialise prior to
//         referencing any P2PmsgSink utility
//
BOOL
StartupP2PmsgSink ( )
{
    // Idempotent one-time init: TRUE means "the sink environment IS up", NOT "this call is
    // what started it".  s_bStartupP2PmsgSink is never reset -- there is no sink-environment
    // teardown, the CS deliberately lives for the process -- so a repeat call returning FALSE
    // reported failure for a fully-initialised sink.  StartupP2Pmsg() returns this result as
    // its own, which made every re-start of a cleaned environment report failure.  Refer
    // StartupP2Pmsg() for further details.
    if ( s_bStartupP2PmsgSink )
      return TRUE;
    InitializeCriticalSection ( &s_oCSectionP2PmsgSink );
    s_bStartupP2PmsgSink = true;

    // Default P2PeventSinkSet
    //P2PeventSinkModal = CreateP2PeventSink ( 0, 0, true );
    return TRUE;
}

BOOL
CleanupP2PmsgSink ( P2PmsgHubMgr *pP2PmsgHub )
{
    // Locals
    UINT nSinks = 0;
    if ( pP2PmsgHub == nullptr )
      return nSinks;
    P2PmsgSinkmap *pP2PmsgSinkmap = pP2PmsgHub->m_pP2PmsgSinkmap;
    if ( pP2PmsgSinkmap == nullptr )
      return nSinks;
    while ( pP2PmsgSinkmap->size() > 0 )
    {
      P2PmsgSinkmap::iterator it = pP2PmsgSinkmap->begin();
      P2PmsgSinkClose ( it->first );
      // NOTES: P2PmsgSinkClose() erases the entry itself, so the loop must
      //        not erase it here
      nSinks++;
    }
    delete pP2PmsgSinkmap;
    pP2PmsgHub -> m_pP2PmsgSinkmap = nullptr;
    return nSinks;
}

//
//  Creates P2PmsgSink
//
P2PmsgSinkID
P2PmsgSinkCreate ( LPCTNAM lpszSinkname )
{
    // Locals
    P2PmsgHubID nHubID       = GetP2PmsgHubID ( );
    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;

    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module (__FUNCTION__)->AFP(lpszSinkname)
           ->Message("Attempt to create P2PmsgSink outside P2PmsgHub context" )
           ->Throw  ( );

    // To be sure, to be sure
    P2PsafeCS      oSafeCS_Sink   = s_oCSectionP2PmsgSink;
    P2PmsgSinkmap *pP2PmsgSinkmap = pP2PmsgHub->m_pP2PmsgSinkmap;
    if ( pP2PmsgSinkmap                                             &&
         pP2PmsgSinkmap->size() >= (INT_PTR)pP2PmsgHub->m_nSinksMax    )
      EVERR->Module ("%s(nHubID=%i,pTarget)", __FUNCTION__
                    , nHubID )
           ->Message("Attempt to exceed configured sink limit (%i) for hub"
                    , pP2PmsgHub->m_nSinksMax )
           ->Throw  ( );

    // Create P2PmsgSink
    // NOTES: Mandatory for P2PmsgSink to be attached to P2PmsgHub
    P2PmsgSink *pP2PmsgSink = pP2PmsgHub -> CreateP2PmsgSink ( lpszSinkname );
    return pP2PmsgSink -> m_nSinkID;
}

Targetcore_EXT BOOL
P2PmsgSinkRegister ( P2PmsgSinkID nP2PmsgSinkID, P2PeerTarget *pTarget, P2PsysID nP2PsysID )
{
    // Locals
    P2PmsgHubID nHubID      = GetP2PmsgHubID ( );
    P2PsafeCS   oSafeCS_Hub = s_oCSectionP2PmsgHub;

    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = nullptr;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)->AFP(nP2PsysID)
           ->Message("Attempt access P2PmsgSink[=%i] outside P2PmsgHub context", nP2PmsgSinkID )
           ->Throw  ( );

    // Isolate P2PmsgSink
    P2PsafeCS   oSafeCS_Sink = s_oCSectionP2PmsgSink;
    P2PmsgSink *pP2PmsgSink  = pP2PmsgHub -> GetP2PmsgSink ( nP2PmsgSinkID );
    if ( !pP2PmsgSink )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)->AFP(nP2PsysID)
           ->Message("P2PmsgSink[=%i] does not exist", nP2PmsgSinkID )
           ->Throw  ( );
    return pP2PmsgSink -> RegisterTarget ( pTarget, nP2PsysID ) ? TRUE : FALSE;
}
Targetcore_EXT BOOL
P2PmsgSinkCancel ( P2PmsgSinkID nP2PmsgSinkID, P2PeerTarget *pTarget, P2PsysID nP2PsysID )
{
    // Locals
    P2PmsgHubID nHubID      = GetP2PmsgHubID ( );
    P2PsafeCS   oSafeCS_Hub = s_oCSectionP2PmsgHub;

    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)->AFP(nP2PsysID)
           ->Message("Attempt access P2PmsgSink[=%i] outside P2PmsgHub context", nP2PmsgSinkID )
           ->Throw  ( );

    // Isolate P2PmsgSink
    P2PsafeCS   oSafeCS_Sink = s_oCSectionP2PmsgSink;
    P2PmsgSink *pP2PmsgSink  = pP2PmsgHub -> GetP2PmsgSink ( nP2PmsgSinkID );
    if ( !pP2PmsgSink )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)->AFP(nP2PsysID)
           ->Message("P2PmsgSink[=%i] does not exist", nP2PmsgSinkID )
           ->Throw  ( );
    return pP2PmsgSink -> CancelTarget ( pTarget, nP2PsysID );
}
Targetcore_EXT BOOL
P2PmsgSinkClose ( P2PmsgSinkID nP2PmsgSinkID )
{
    // Locals
    P2PmsgHubID nHubID       = GetP2PmsgHubID ( );
    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = nullptr;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)
           ->Message("Nominated nHubID=%i does not exist", nHubID )
           ->Throw  ( );
    // Isolate P2PmsgSink
    P2PsafeCS   oSafeCS_Sink = s_oCSectionP2PmsgSink;
    P2PmsgSink *pP2PmsgSink  = pP2PmsgHub -> GetP2PmsgSink(nP2PmsgSinkID);
    if ( pP2PmsgSink == nullptr )
      return FALSE;
    pP2PmsgHub -> RemoveP2PmsgSink ( pP2PmsgSink );
    return TRUE;
}
Targetcore_EXT BOOL
P2PmsgSinkIsValid ( P2PmsgSinkID nP2PmsgSinkID )
{
    // Locals
    P2PmsgHubID nHubID       = GetP2PmsgHubID ( );
    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = nullptr;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)
           ->Message("Nominated nHubID=%i does not exist", nHubID )
           ->Throw  ( );
    // Isolate P2PmsgSink
    P2PsafeCS   oSafeCS_Sink = s_oCSectionP2PmsgSink;
    P2PmsgSink *pP2PmsgSink  = pP2PmsgHub -> GetP2PmsgSink(nP2PmsgSinkID);
    return pP2PmsgSink ? TRUE : FALSE;
}
Targetcore_EXT BOOL
PostP2PmsgSink ( P2PmsgSinkID nP2PmsgSinkID, P2PsysID nP2PsysID
               , const P2PeerTarget *pTarget
               , WPARAM wParam, LPARAM lParam )
{
    // Locals
    BOOL        nItems       = 0;
    P2PmsgHubID nHubID       = GetP2PmsgHubID ( );
    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)
           ->Message("Nominated nHubID=%i does not exist", nHubID )
           ->Throw  ( );
    // Isolate P2PmsgSink
    P2PsafeCS   oSafeCS_Sink = s_oCSectionP2PmsgSink;
    P2PmsgSink *pP2PmsgSink  = pP2PmsgHub -> GetP2PmsgSink(nP2PmsgSinkID);
    if ( pP2PmsgSink == nullptr )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)
           ->Message("Nominated P2PmsgSinkID=%i does not exist", nP2PmsgSinkID )
           ->Throw  ( );
    // Post
    P2PsafeCS   oSafeCS_Pump  = s_oCSectionP2PmsgPump;
    P2PmsgSinkReg_list::iterator it;
    for ( it = pP2PmsgSink->m_oP2PmsgSinkReglist.begin(); it != pP2PmsgSink->m_oP2PmsgSinkReglist.end(); ++it )
    {
      if ( (*it)->nSysID               &&
           (*it)->nSysID  != nP2PsysID    )
        continue;
      if (        pTarget              &&
           (*it)->pTarget != pTarget      )
        continue;
      P2PmsgPump *pP2PmsgPump = 0;
      if ( !s_ThreadID_P2PmsgPump.Lookup((*it)->nPumpID,pP2PmsgPump ) )
        s_ThreadID_P2PmsgPump.Lookup(nHubID,pP2PmsgPump );
      ASSERT(pP2PmsgPump!=nullptr);
      // Manufacture
      P2Pmsg *pP2Pmsg = P2PmsgFactory ( );
              pP2Pmsg -> nCode        =  CN_P2PeerSnc;
              pP2Pmsg -> nMsg         =  nP2PsysID;
              pP2Pmsg -> pTarget      =  (*it)->pTarget;
              pP2Pmsg -> nHubThreadID =  nHubID;
              pP2Pmsg -> pExtra       =  pP2Pmsg;
              pP2Pmsg -> wParam       =  wParam;
              pP2Pmsg -> lParam       =  lParam;
ASSERT(VerifyP2Pmsg(pP2Pmsg));
      P2PsafeCS oSafeCS = pP2PmsgPump -> m_oCSection;
      pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, false );
      nItems++;
    }
    return nItems;
}
Targetcore_EXT BOOL
PostP2PmsgSink ( P2PmsgSinkID nP2PmsgSinkID, P2PsysID nP2PsysID
               , const P2PeerTarget *pTarget
               , const P3PmsgItem& oItem
               , WPARAM wParam, LPARAM lParam )
{
    // Locals
    BOOL        nItems       = 0;
    P2PmsgHubID nHubID       = GetP2PmsgHubID ( );
    P2PsafeCS   oSafeCS_Hub  = s_oCSectionP2PmsgHub;
    // Isolate P2PmsgHub
    // NOTES: P2PmsgHub[] environment isolation, keep to completion
    P2PmsgHubMgr *pP2PmsgHub  = 0;
    if ( !s_ThreadID_P2PmsgHub.Lookup(nHubID,pP2PmsgHub) ||
         !pP2PmsgHub                                        )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)
           ->Message("Nominated nHubID=%i does not exist", nHubID )
           ->Throw  ( );
    // Isolate P2PmsgSink
    P2PsafeCS   oSafeCS_Sink = s_oCSectionP2PmsgSink;
    P2PmsgSink *pP2PmsgSink  = pP2PmsgHub -> GetP2PmsgSink(nP2PmsgSinkID);
    if ( pP2PmsgSink == nullptr )
      EVERR->Module (__FUNCTION__)->AFP(nP2PmsgSinkID)
           ->Message("Nominated P2PmsgSinkID=%i does not exist", nP2PmsgSinkID )
           ->Throw  ( );
    // Post instance of message to each registered client
    P2PsafeCS   oSafeCS_Pump  = s_oCSectionP2PmsgPump;
    P2PmsgSinkReg_list::iterator it;
    for ( it = pP2PmsgSink->m_oP2PmsgSinkReglist.begin(); it != pP2PmsgSink->m_oP2PmsgSinkReglist.end(); ++it )
    {
      if ( (*it)->nSysID               &&
           (*it)->nSysID  != nP2PsysID    )
        continue;
      if (        pTarget              &&
           (*it)->pTarget != pTarget      )
        continue;
      P2PmsgPump *pP2PmsgPump = 0;
      if ( !s_ThreadID_P2PmsgPump.Lookup((*it)->nPumpID,pP2PmsgPump ) )
        s_ThreadID_P2PmsgPump.Lookup(nHubID,pP2PmsgPump );
      ASSERT(pP2PmsgPump!=nullptr);
 
      // Manufacture
      // NOTES: Ownership passes to the pump.  The message (and its pP3PmsgItem)
      //        is freed by ReleaseP2Pmsg() when dispatched, or drained by
      //        ~P2PmsgPump() if it is still queued at teardown.
      P2Pmsg *pP2Pmsg = P2PmsgFactory ( );
              pP2Pmsg -> nCode        =  CN_P2PeerSnc;
              pP2Pmsg -> nMsg         =  nP2PsysID;
              pP2Pmsg -> pTarget      =  (*it)->pTarget;
              pP2Pmsg -> nHubThreadID =  nHubID;
              pP2Pmsg -> pExtra       =  pP2Pmsg;
              pP2Pmsg -> wParam       =  wParam;
              pP2Pmsg -> lParam       =  lParam;
              pP2Pmsg -> pP3PmsgItem  =  new P3PmsgItem(oItem);
ASSERT(VerifyP2Pmsg(pP2Pmsg));
      P2PsafeCS oSafeCS = pP2PmsgPump -> m_oCSection;
      pP2PmsgPump -> PutP2Pmsg ( pP2Pmsg, false );
      nItems++;
    }
    return nItems;
}

///////////////////////////////////////////////////////////////////////
//  Encoding
//  NOTES: Provides thread safe text encoding for defined parameter
//         types

//
//  Description: Encodes raw P2Pmsg_t types
//               Format: Unknown types are encoded into 0xnnnn form
//
//
//  Parameters:  P2Pmsg_t nMsg
//               Message to be encoded
//
//  Returns:     LPCTSTR
//               Encoded P2Pmsg_t string
//
LPCTSTR
EncodeP2Pmsg_t ( P2Pmsg_t nMsg )
{
    // P2Peer Group messages
    if ( nMsg == P2P_P2Pmsg )
      return _T("P2P_P2Pmsg");
    else if ( nMsg == P2P_Startup )
      return _T("STARTUP");
    else if ( nMsg == P2P_Listen )
      return _T("LISTEN");
    //else if ( nMsg == P2P_Mute )
    //  return "MUTE";
    else if ( nMsg == P2P_Connect )
      return _T("CONNECT");
    else if ( nMsg == P2P_Accept )
      return _T("ACCEPT");
    //else if ( nMsg == P2P_Reject )
    //  return _T("REJECT");
    else if ( nMsg == P2P_Close )
      return _T("CLOSE");
    else if ( nMsg == P2P_Login )
      return _T("LOGIN");
    else if ( nMsg == P2P_LoginAck )
      return _T("LOGINACK");
    else if ( nMsg == P2P_Notify )
      return _T("NOTIFY");
    else if ( nMsg == P2P_IdleNotify )
      return _T("IDLENOTIFY");
    else if ( nMsg == P2P_Destroy )
      return _T("DESTROY");

    // Enocde hexadecimal
    static TCHAR szP2Pmsg[32][17] = { 0 };
    static int   idx = 0;
    TCHAR  *pszP2Pmsg = szP2Pmsg[idx=(idx+1)%17];
   _stprintf_s ( pszP2Pmsg, ARRAYSIZE(szP2Pmsg[0]), _T("0x%0.4x"), nMsg );

    // Tidy up and
    return pszP2Pmsg;
}
