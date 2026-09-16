// Copyright © 2001-2012, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerHub definitions and prototypes
//  NOTES: Network is built upon the local and remote exchange of
//         P2PeerMsg's between objects derived from this base class
//       : Only P2PeerHub derived network objects may be assigned
//         network P2Paddress's
//       : Network connections between P2PeeHub's are managed via
//         pumped P2PeerCon objects

#include "stdafx.h"
#include "Kernel32_Ext.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2Pwin32.h"
#include "Msgexception.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <string>   // ProvisionAuth builds the ".pub" sibling path (Stage 3 step 8)

// W8 (p2p_PumpPerf.md — deployment tuning): the per-hub pump-slot cap was hard-coded (15) in the
// SpawnHub convenience path. Expose it as an additive env knob (P2PMSG_PUMPS_MAX) so a deployment
// can raise the ceiling without recompiling; the CreateHub() integration path already takes
// nPumpsMax as a parameter, so this only closes the gap for SpawnHub. UNSET ⇒ the historical 15,
// so existing behaviour is byte-identical (no test/perf change). The value is resolved once via a
// C++11 magic-static (guard-protected init ⇒ TSan-clean under concurrent SpawnHub calls; the
// racy lazy `if(!x)` idiom would trip the TSan gate). Clamp to [15, MAX_P2PmsgPump]: the floor
// keeps it PURELY additive (a knob can only RAISE the cap, never regress a hub that legitimately
// fills the historical 15 pump slots); the ceiling is the library's own hard limit —
// CreateP2PmsgHub throws "nMaxPumps outside range 1..MAX_P2PmsgPump" (P2Pwin32.cpp), so a value
// above it would fail SpawnHub outright (measured: cap 512 ⇒ "server SpawnHub failed"). See
// PumpDeploymentTuning.md for the sizing/affinity/wait-strategy guidance this pairs with.
static UINT HubPumpsMaxKnob ( )
{
    static const UINT s_nPumpsMax = [] () -> UINT {
#if defined(_MSC_VER)
#  pragma warning( push )
#  pragma warning( disable : 4996 )   // getenv: read-only env lookup, no _dupenv_s churn needed
#endif
        const char*        p   = std::getenv ( "P2PMSG_PUMPS_MAX" );
#if defined(_MSC_VER)
#  pragma warning( pop )
#endif
        unsigned long      v   = ( p && *p ) ? std::strtoul ( p, nullptr, 10 ) : 15ul;
        const unsigned long hi = (unsigned long) MAX_P2PmsgPump;   // library hard cap (256)
        return (UINT) ( v < 15ul ? 15ul : ( v > hi ? hi : v ) );
    } ();
    return s_nPumpsMax;
}

// TSan (Risk #3): P2PeerHub::m_nHubID doubles as a cross-thread liveness/completion flag - the
// pump thread stores 0 at exit (RunHub/ProcHub) while caller threads spin-read it (SpawnHub,
// CloseHub). It can't be a plain std::atomic member because CreateThread() writes it through a
// raw DWORD* (the thread-id out-param), so wrap the CROSS-THREAD accesses in std::atomic_ref:
// the caller-side reads and the pump-side exit store. The pump's own reads stay sequenced with
// its store (same thread) and CreateThread's spawn-time write happens-before the pump runs, so
// those need no wrapping. acquire/release pairs the store-0 with the spinning loads.
static inline P2PmsgHubID LoadHubID ( const P2PmsgHubID& r )
{ return std::atomic_ref<P2PmsgHubID>(const_cast<P2PmsgHubID&>(r)).load(std::memory_order_acquire); }
static inline void        StoreHubID ( P2PmsgHubID& r, P2PmsgHubID v )
{ std::atomic_ref<P2PmsgHubID>(r).store(v, std::memory_order_release); }

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

//
//  Constructors and destructor
//
//  Parameters:  P2PaddrSTR strP2PaddrHub
//               Unique network global identification
//               NOTES: P2Paddress's are only ever assigned to objects
//                      derived from this class.
//                    : May be NULL in which case P2Paddress is negotiated
//                      and allocated as part of a connection login
//                      sequence.
//
P2PeerHub::P2PeerHub ( P2PaddrSTR strP2PaddrHub )
         : P2PeerTarget ( (P2PeerTarget *)nullptr, 0 )
{
    // Firstly
    RenderHubSafe ( );
    SetP2PaddrHub ( strP2PaddrHub );
}

P2PeerHub::~P2PeerHub ( )
{
    CloseHub ( );
    //  After CloseHub(): the pumps are down - and since CloseHub() JOINS the
    //  spawned thread, "down" now means the thread has actually left ProcHub
    //  rather than merely having flagged its hub id clear. So nothing can be
    //  inside a handshake reaching for the policy while it is being freed, and
    //  nothing is left to enter m_oCSectionHub after it is deleted.
    delete m_pAuthPolicy;
    m_pAuthPolicy = 0;

    //  The exit event's owner is the hub, so this is where it is released -
    //  on the ordinary path as well as the odd one.  CloseHub() above only
    //  WAITS on it; it deliberately neither takes it out of the member nor
    //  closes it, because SignalHubExit reads the same member and a CloseHub
    //  that nulled it first would be waiting for a signal it had made
    //  unreachable.  Refer CloseHub.
    if ( m_hHubExit )
    {
      CloseHandle ( m_hHubExit );
      m_hHubExit     = 0;
      m_nHubThreadID = 0;
    }
    DeleteCriticalSection ( &m_oCSectionHub );
}

void
P2PeerHub::RenderHubSafe()
{
    // Attributes
    m_nHubID        = 0;               // Inactive hub flag
	m_pP2PeerExpump = 0;               // P2PeerExp object
    m_hHubExit      = 0;               // No spawned pump thread to wait for
    m_nHubThreadID  = 0;

    // Resources
    InitializeCriticalSection ( &m_oCSectionHub );

    // Login policy
    // NOTES: Allocated unconditionally so no call site has to null-check it.
    //        An unconfigured policy signs nothing and requires nothing, which
    //        is precisely the pre-existing behaviour.
    m_pAuthPolicy = new p2pauth::AuthPolicy ( );
}

///////////////////////////////////////////////////////////////////////
//  Hub management
//  NOTES: Started using default P2PeerHub::SpawnHub() or
//         CreateHub() implementations

typedef struct
{
  P2PmsgHubID    *pnHubID;
  P2PeerHub      *pHub;
  P2Paddr         oP2Paddr;
  UINT            nPumpsMax;
  RUN_HUB       pfnRunHub;
} P2ProcContext;

//
//  Spawns P2PmsgHub and commences pumping in a new thread
//  NOTES: Thread processing may be stopped via CloseHub()
//       : P2PeerTarget contains equivalent implementation for pumps
//
//
//  Parameters: LPTHREAD_START_ROUTINE pfnThreadProc = 0
//              The thread procedure of the new thread.  Refer
//              win32 CreateThread() for further details
//
//              RUN_HUB pfnRunHub = 0
//              Operational method of the new thread
//
//  Returns:    HANDLE
//              Returns the handle to the newly created thread
//              or NULL on failure.
//
HANDLE
P2PeerHub::SpawnHub ( LPTHREAD_START_ROUTINE pfnThreadProc
                    , RUN_HUB  pfnRunHub )
{
    // Preparation
    ASSERT(m_nHubID == 0 );

    //  Stage 3 step 8. Before the thread exists, so a hub that cannot enforce
    //  what it requires never gets one - the alternative is a pump thread
    //  that starts, refuses every peer, and looks healthy from outside.
    if ( !AuthArmOrRefuse ( _T(__FUNCTION__) ) )
      return 0;

    if ( pfnThreadProc == NULL )
      pfnThreadProc = P2PeerHub::ProcHub;
    if ( pfnRunHub == NULL )
      pfnRunHub = RUN_HUB_cast(&P2PeerHub::RunHub);

    // Pass context through
    P2ProcContext oContext;
                  oContext.pnHubID   = &m_nHubID;
                  oContext.pHub      =     this;
                  oContext.pfnRunHub =  pfnRunHub;
                  oContext.oP2Paddr  = m_oP2PaddrHub;
                  oContext.nPumpsMax = HubPumpsMaxKnob ( );   // W8: env-tunable, default 15

    // Arm the exit event BEFORE the thread exists
    // NOTES: The thread can finish before CreateThread returns here, so an
    //        event created afterwards could be created after the only SetEvent
    //        that would ever have signalled it.
    //      : ONLY WHEN ProcHub IS THE TRAMPOLINE, and that is a scope rather
    //        than a compromise.  ProcHub is what sets the event, so arming it
    //        for a caller-supplied thread proc would leave CloseHub waiting
    //        for ever on a signal nothing raises - trading a race for a hang.
    //        A custom trampoline also does not call CloseP2PmsgHub(), which is
    //        the call the race is between, so the defect this closes does not
    //        exist on that path: it keeps exactly today's behaviour, the spin.
    //      : A previous spawn's event is closed first.  Re-spawning a hub that
    //        was never closed is already a contract violation (the ASSERT at
    //        the top of this function), but leaking a handle on top of it
    //        would make the next reader's problem the wrong one.
    //      : AND THE ARMING GATE ABOVE NEEDS NO SPECIAL CASE, which was the
    //        open question this fix sat unmerged for.  Stage 3 step 8's
    //        AuthArmOrRefuse() returns BEFORE any of this, so a hub that
    //        refuses to arm never reaches these lines: no thread is created
    //        and no event is armed, and CloseHub finds nothing to wait for.
    if ( m_hHubExit )
    {
      CloseHandle ( m_hHubExit );
      m_hHubExit = 0;
    }
    if ( pfnThreadProc == P2PeerHub::ProcHub )
      m_hHubExit = CreateEvent ( 0, TRUE /*manual reset*/, FALSE, 0 );
    m_nHubThreadID = 0;

    // Dedicated P2PmsgHub thread creation
    // NOTES: Spawned hub runs under context of this thread and hence
    //        the allocated win32 threadID becomes the P2PmsgHubID
    HANDLE hThread = CreateThread ( 0, 0
                                  , pfnThreadProc, &oContext
                                  , 0, &m_nHubID );
    if ( !hThread )
    {
      //  No thread means nothing will EVER set the event, and CloseHub's wait
      //  is unbounded.  Disarming here is what keeps a failed spawn a failed
      //  spawn instead of a hang at teardown.
      if ( m_hHubExit ) { CloseHandle ( m_hHubExit ); m_hHubExit = 0; }
      return FALSE;
    }

    //  The pump thread's id, kept so CloseHub can refuse to wait for ITSELF.
    //  Taken from the DWORD CreateThread just wrote rather than from
    //  m_nHubID later on, because the thread stores 0 there as its last act.
    m_nHubThreadID = (DWORD)m_nHubID;

    // Confirm operation
    // NOTES: Contracted for P2PmsgHub operation upon return
    DWORD dwExitCode;
    UINT  uSpins = 0;
    while ( !P2PmsgHubExists(LoadHubID(m_nHubID)) )
    {
      if ( !GetExitCodeThread(hThread,&dwExitCode)                ||
                                       dwExitCode != STILL_ACTIVE    )
        return 0;                      // Operational failure
      YieldForP2PmsgPump ( uSpins );   // Yield (escalating - see header)
    }

    // Tidy up and
    return P2PmsgHubExists(LoadHubID(m_nHubID)) ? hThread : 0;
}

//
//  Creates P2PmsgHub within the context of this thread
//  NOTES: Thread processing may be stopped via CloseHub()
//       : Facilitates integration of P2PeerHub processing in
//         3rd Party environments such as MFC or service thread
//
//
//  Parameters: P2PaddrSTR strP2PaddrHub
//              Hub network address
//
//            : UINT nPumpsMax
//              Maximum number of P2PmsgPumps supported by the hub
//
//  Returns:     BOOL
//               Success code
//                 TRUE... Created OK
//                 FALSE.. Failure
//
BOOL
P2PeerHub::CreateHub ( P2PaddrSTR strP2PaddrHub
                     , UINT nPumpsMax )
{
    // Hub is created an run in context of calling thread
    // NOTES: Client is reasponsible for pumping messages through
    //        the P2PmsgHub
    ASSERT(m_nHubID == 0 );
    m_oP2PaddrHub = strP2PaddrHub;

    //  Stage 3 step 8. Set the address first, so the refusal can name the hub
    //  it is refusing; arm nothing if the hub cannot enforce what it requires.
    if ( !AuthArmOrRefuse ( _T(__FUNCTION__) ) )
      return FALSE;

    m_nHubID = CreateP2PmsgHub ( strP2PaddrHub, this, nPumpsMax, 1 );

    // Tidy up and
    return P2PmsgHubExists(m_nHubID);
}

//
//  Pause all hub operations
//  NOTES: Upon completion hub effectively exists in idle space
//       : Both hub context and non-hub context OK
void
P2PeerHub::PauseHub ( )
{
    // Pause processing must be performed from context of this hub
    // NOTES: OK to re-signal from any other non-hub context
    if ( GetCurrentThreadId() != GetHubID() )
    {
      if ( GetHubID() > 0 )
        SignalP2PmsgHub ( GetHubID(), P2PsigHub_PAUSE );
      return;
    }
      
    // Close all idle client connections
    ConSignal ( L"*", P2PsigCon_CLOSEONIDLE );
}

//
//  Wakeup all hub operations
//  NOTES: Upon completion hub effectively operational
//       : Both hub context and non-hub context OK
//       : Cancels a PauseHub() that has not finished draining.  PauseHub
//         latches ConState_CloseOnIdle on every connection and drops the ones
//         already idle, so wakeup is the inverse of the latch and nothing
//         more: connections still carrying traffic when the pause arrived
//         survive it, connections the pause already dropped do not come back.
//         Reviving those is the connection owner's business - the default
//         ON_P2PeerCon_CLOSE handler already restarts a CLIENT after
//         m_uAutoRestart, and a SERVICE listener must be re-armed by whoever
//         knows what it was listening on.
//       : Until Stage 3 this asserted and returned, which made PauseHub a
//         one-way door through p2peerhub_wakeup_hub(), the service
//         SERVICE_CONTROL_CONTINUE handler and P2PsigHub_WAKEUP alike.
void
P2PeerHub::WakeupHub ( )
{
    // Wakeup processing must be performed from context of this hub
    // NOTES: OK to re-signal from any other non-hub context
    if ( GetCurrentThreadId() != GetHubID() )
    {
      if ( GetHubID() > 0 )
        SignalP2PmsgHub ( GetHubID(), P2PsigHub_WAKEUP );
      return;
    }

    // Un-latch close-on-idle across every surviving connection
    ConSignal ( L"*", P2PsigCon_WAKEUP );
}

//
//  Close hub and associated pumps managed through this hub
//  NOTES: Hub processing may be re-started via P2Peer::SpawnHub()
//         or CreateHub()
//
void
P2PeerHub::CloseHub ( )
{
    // Asynchronous closure
    // NOTES: P2PmsgHub exists in another context
    P2PmsgHubID nHubID = LoadHubID(m_nHubID);
    if ( nHubID > 0                     &&
         nHubID != GetCurrentThreadId()    )
    {
      SignalP2PmsgHub ( nHubID, P2PsigHub_CLOSE );
      UINT uSpins = 0;
      while ( (nHubID = LoadHubID(m_nHubID)) > 0 && P2PmsgPumpExists(nHubID) )
        YieldForP2PmsgPump ( uSpins );
    }

	  // P2PeerExp closure
    DropP2PeerExpump ( );

    // Synchronous closure
    // NOTES: P2PmsgHub exists in this context
    nHubID = LoadHubID(m_nHubID);
    if ( nHubID > 0                     &&
         nHubID != GetCurrentThreadId()    )
      CloseP2PmsgHub ( );

    // Wait for the spawned pump thread to LEAVE
    // NOTES: THE SPIN ABOVE IS NOT THE END OF THAT THREAD, and this is the
    //        whole reason this wait exists.  It ends when m_nHubID reads zero,
    //        which RunHub() stores as its own last act - so at that moment a
    //        derived RunHub()'s tail (anything a subclass does after calling
    //        the base) and then ProcHub()'s CloseP2PmsgHub() are both still to
    //        run on that thread.  Returning to the caller there let
    //        P2PeerService::Run() reach CleanupP2Pmsg(), which
    //        DeleteCriticalSection()s s_oCSectionP2PmsgHub and ...Pump, while
    //        CloseP2PmsgHub()'s first two statements take exactly those: an
    //        access violation inside ntdll's RtlEnterCriticalSection, on
    //        roughly one console run in three of the ErrorReportingExamples
    //        NTServiceEventLog harness, with the main thread already inside
    //        exit().  The same window covers ~P2PeerService's delete of the
    //        hub and the host's own teardown.
    //      : UNBOUNDED, as the spin above is.  A pump that cannot leave is the
    //        condition CloseHub() is documented to wait out rather than paper
    //        over - refer SECURITY.md - and a timeout here would restore this
    //        exact race on a loaded machine.
    //      : Never waits for itself.  CloseHub() from a handler runs ON the
    //        pump thread; the event is left for the out-of-context call that
    //        follows, or for the destructor.
    //      : IT ONLY READS THE MEMBER.  It does not take the event out and it
    //        does not close it, and the first version of this did both - which
    //        HUNG p2p_daemon_harness on the first full suite run after it
    //        landed.  Nulling m_hHubExit before waiting meant SignalHubExit,
    //        which reads the same member, found nothing to set: CloseHub was
    //        then waiting for ever on a signal it had just made unreachable.
    //        Blocked with zero CPU, which is what an unbounded wait looks like
    //        from outside and is why it was not a spin.
    //      : So the event's lifetime belongs to the HUB, not to this call.
    //        ~P2PeerHub closes it, and a re-spawn closes the previous one
    //        before arming a new one.  Two concurrent CloseHub()s therefore
    //        both wait on a manual-reset event and both return, with nothing
    //        to double-close; a re-spawn while one is still waiting is already
    //        a contract violation the ASSERT at the top of SpawnHub catches.
    HANDLE hExit = 0;
    {
      P2PsafeCS oSafeCS = m_oCSectionHub;
      if ( m_hHubExit && m_nHubThreadID != GetCurrentThreadId ( ) )
        hExit = m_hHubExit;
    }
    if ( hExit )
      WaitForSingleObject ( hExit, INFINITE );
}

//
//  Signals that this hub's spawned pump thread has finished
//  NOTES: Called by ProcHub as its VERY LAST statement, and the position is
//         the contract.  CloseHub() may be blocked on this event, and it
//         closes the hub the moment it is set - so anything the thread did
//         after setting it would be touching an object its owner is entitled
//         to have destroyed.
//       : Silent when nothing is armed.  A hub started with CreateHub(), or
//         with a caller-supplied thread proc, has no event and needs none -
//         refer SpawnHub
//       : Reads the member under the lock because CloseHub may be taking it
//         out from under this call at the same moment
//
void
P2PeerHub::SignalHubExit ( )
{
    HANDLE hExit = 0;
    {
      P2PsafeCS oSafeCS = m_oCSectionHub;
      hExit = m_hHubExit;
    }
    if ( hExit )
      SetEvent ( hExit );
}

//
//  Default thread starting address nominated in CreateThread()
//  NOTES: Provide alternative implementation to override default
//         action.
//
//
//  Parameters: void *pvData
//              Thread data passed via CreateThread()
//
//  Returns:    DWORD
//              Completion code
//
DWORD WINAPI
P2PeerHub::ProcHub ( void *pvData )
{
    // Introduce locals
    // NOTES: P2ProcContext is assumed not to persist
    P2ProcContext *pContext = (P2ProcContext *)pvData;
    P2Paddr        oP2Paddr =  pContext -> oP2Paddr;
    P2PeerHub     *pHub     =  pContext -> pHub;
    P2PmsgHubID  *pnHubID   =  pContext -> pnHubID;
    UINT           nPumpsMax=  pContext -> nPumpsMax;
    RUN_HUB      pfnRunHub  =  pContext -> pfnRunHub;
    pHub -> P2PeerHub::AssertValid ( );

    // Mandatory P2PeerHub thread environment
    // NOTES: Sequence contains mandatory P2PeerHub and P2PmsgHub
    //        life cycle management sequences
    //      : Guard the whole hub life cycle.  An exception escaping a thread
    //        proc terminates the process (std::terminate on Linux, likewise on
    //        Windows).  RunHub() self-guards its own pump loop, but the
    //        CreateP2PmsgHub() setup and CloseP2PmsgHub() teardown-drain run
    //        outside it and can throw a P2Pevent under socket/port pressure -
    //        which aborted the process on a pump thread (Phase-5 teardown
    //        stress).  Mirrors the already-guarded P2PeerTarget::ProcPump;
    //        ProcHub/ProcExpump were the only unguarded trampolines.
    try
    {
      CreateP2PmsgHub ( oP2Paddr, pHub, nPumpsMax, 8 );
      (pHub->*pfnRunHub) ( );         // Nominated Run() method
      if ( pnHubID && *pnHubID == GetCurrentThreadId() )
        StoreHubID ( *pnHubID, 0 );   // Flags pump closure (atomic_ref, TSan Risk #3)
      CloseP2PmsgHub ( );
    }
    catch ( P2Pevent *pEVT )
    {
      pEVT->Advice(_T("P2PeerHub::ProcHub terminated"))->Cancel();
    }
    catch ( ... )
    {
      EVERR->Module (L"P2PeerHub::ProcHub" )
           ->Message(L"Last resort exception of unknown type, "
                        "P2PmsgHub terminated" )
           ->Cancel();
    }

    // Tidy up, and thread is dead
    //pHub -> PostDestroyHub ( );

    //  THE LAST STATEMENT, and it has to be.  CloseHub() may be blocked on this
    //  event and will close - and its caller may destroy - the hub as soon as
    //  it is set, so anything below this line would be touching an object its
    //  owner is entitled to have finished with.  Refer SignalHubExit.
    pHub -> SignalHubExit ( );
    return 0;
}

//
//  Plain network P2PmsgHub implementation
//  NOTES: Simply pumps P2PeerSys, P2PeerCon and P2PeerMsg objects
//         through the P2PeerTarget base class
//       : P2PeerMsg's can be swapped out of this context via
//         ContextSwap() and processed independantly in the fullness
//         of time
//       : It's possible to have processing delays in this context.
//         But keep in mind P2PeerMsg's may keep building up
//
void
P2PeerHub::RunHub (  )
{
    // Introduce locals
    DWORD      dwResult;
    P2PsigID    nSigID;
    DWORD      dwMSec = 8000;
    ASSERT(m_nHubID==GetCurrentThreadId());

    // Because sequence must end orderly
    try
    {
      // Latencies
      SetP2PmsgPumpFunc ( 0, _T(__FUNCTION__) );
      ThrowP2Pevent();

      // Pump messages through the P2PeerSys, P2PeerCon and
      // P2PeerMsg_MAP's until terminated and exhausted
      while ( (dwResult=PumpP2Pmsg(dwMSec,nSigID)) != 0 )
      {
        // Signal - Immediate closure
        if ( nSigID == P2PsigHub_CLOSE )
        {
          P2PeerCon *pCon = 0;
          while ( EnumP2PmsgCon(m_nHubID,&pCon) )
            pCon -> Signal ( P2PsigCon_DESTROY );

          P2PumpID nPumpID = 0;
          while ( EnumP2PmsgPump(m_nHubID,nPumpID) )
            SignalP2PmsgPump ( nPumpID, P2PsigPump_CLOSE );
          break;
        }

        // Signal - Idle closure
        if ( nSigID == P2PsigHub_CLOSEONIDLE )
        {
          P2PeerCon *pCon = 0;
          while ( EnumP2PmsgCon(m_nHubID,&pCon) )
            pCon -> Signal ( P2PsigCon_CLOSEONIDLE );

          P2PumpID nPumpID = 0;
          while ( EnumP2PmsgPump(m_nHubID,nPumpID) )
            SignalP2PmsgPump ( nPumpID, P2PsigPump_CLOSEONIDLE );
          break;
        }

        // Signal - Pause
        if ( nSigID == P2PsigHub_PAUSE )
          PauseHub ( );
          
        // Signal - Wakeup
        if ( nSigID == P2PsigHub_WAKEUP )
          WakeupHub ( );
        ASSERT(m_nHubID==GetCurrentThreadId());
      }
    }

    // Exceptions
    catch ( P2Pevent *pEVT )
    {
      pEVT->Advice(_T("P2PeerHub(%s) P2PmsgHub terminated")
                   , m_oP2PaddrHub.c_wstr() )
          ->Cancel();
    }
    catch ( ... )
    {
      EVERR->Module (_T(__FUNCTION__) )
           ->Message(_T("Last resort exception of unknown type") )
           ->Advice (_T("P2PeerHub(%s) P2PmsgHub terminated")
                    , m_oP2PaddrHub.c_wstr() )
           ->Cancel();
    }

    // Tidy up, and
    // NOTES: Manadatory last operation. atomic_ref store pairs with the caller-thread
    //        LoadHubID spin-reads in SpawnHub/CloseHub (TSan Risk #3).
    StoreHubID ( m_nHubID, 0 );
}

//
//  Performs post P2PmsgHub destruction processing
//  NOTES: Specialise for external notifications etc
//
void
P2PeerHub::PostDestroyHub ( )
{
    ASSERT(m_nHubID==0);
}

///////////////////////////////////////////////////////////////////////
//  P2PeerCon management

//
//  Posts P2PeerCon object to this hub
//  NOTES: Control over life cycle of posted P2PeerCon object is
//         assumed.  Either service or client type objects may be
//         posted
//
//
//  Parameters: P2PeerCon *pCon
//              Connection object to be posted
//
//              P2PumpID nPumpID = 0
//              Identification code of pump to which P2PeerCon
//              object is to be posted
//                0.. Defaults to P2PmsgHub context
//
//  Returns:    BOOL
//              Completion summary flag
//                TRUE..  P2PeerCon object posted
//                FALSE.. P2Pevent generated
BOOL
P2PeerHub::PostP2PeerCon ( P2PeerCon *pCon, P2PumpID nPumpID )
{
    // Introduce locals
    SafeP2PeerCon sppCon  = pCon;
    P2Paddr   oP2PaddrCon = pCon -> GetP2Paddress();
    P2PsafeCS oSafeCS     = m_oCSectionHub;
    if ( g_bP2Pmsg_AssertValid )
      pCon -> AssertValid ( );
	  if ( nPumpID <= 0 )
		  nPumpID = m_nHubID;

    // Environmental
    // NOTES: P2PeerCon objects may only be posted to runnning hubs,
    //        negates risk of dead connections.
    if ( m_nHubID == NULL )
    {
      EVERR->Module (_T(__FUNCTION__) )->AFPcon(pCon)->AFP(nPumpID)
           ->Message(_T("P2PeerHub(%s) is not operational, ")
                     _T("P2PeerCon(%s) not posted")
                    , oP2PaddrCon.c_wstr()
                    , m_oP2PaddrHub.c_wstr() )
           ->Advice (_T("Perform SpawnHub() or CreateHub() before PostP2PeerCon()") )
           ->Advice (_T("Hub has failed?") )
           ->Display()->SetLast();
      return FALSE;
    }

    // THE FENCE
    // NOTES: RequireTrustAtLeast() names the lowest class this hub will hold a
    //        link of, and this is where that is enforced.  It is the other
    //        half of SetLinkPolicy: a hub that opened its in-process class is
    //        otherwise one call to this function away from carrying a socket
    //        it did not plan for.  That socket would authenticate IN FULL -
    //        the wire's policy is Full and cannot be set otherwise - so the
    //        refusal is not about weakening; it is about a hub that exists to
    //        route inside a process quietly becoming a network endpoint
    //      : EffectiveTrust() and not TrustClass(), so a connection the
    //        operator demoted is measured on the class they demoted it TO.
    //        Every other gate in this feature reads the same value
    //      : BEFORE the duplicate scan, and before m_pP2PeerTarget is
    //        assigned, so a refused connection leaves this hub in the state it
    //        was in.  The caller keeps ownership either way, exactly as it
    //        does for the two refusals around this one
    //      : An ACCEPTED child does not come through here - P2PeerCon::
    //        AcceptSpawn posts it directly - and it does not need to.  It is
    //        spawned by a SERVICE that was fenced when the service was posted,
    //        it inherits the class through a virtual and the ceiling through
    //        the one copied field, and neither of those can read HIGHER than
    //        the service's own.  A service admitted by the fence cannot accept
    //        a child the fence would have refused
    //      : The default floor is P2PeerConTrust_Wire, which is 0, which is
    //        what every transport that has vouched for nothing answers.  So an
    //        unconfigured hub compares 0 < 0 and refuses nothing
    //  eFloor is tested FIRST so that a hub nobody has fenced does not ask
    //  the connection anything at all.  EffectiveTrust() on a socket is a
    //  getpeername(), which is cheap and is still a syscall this function did
    //  not make before; an unconfigured hub must be able to compare 0 < 0 and
    //  reach the same instruction it reached yesterday.
    const P2PeerConTrust_e eFloor = GetRequiredTrust ( );
    if ( eFloor > P2PeerConTrust_Wire &&
         pCon -> EffectiveTrust ( ) < eFloor )
    {
      EVERR->Module (_T(__FUNCTION__) )->AFPcon(pCon)->AFP(nPumpID)
           ->Message(_T("P2PeerHub(%s) holds no link below trust class %i; ")
                     _T("P2PeerCon(%s) is class %i and is not posted")
                    , m_oP2PaddrHub.c_wstr()
                    , (int)eFloor
                    , oP2PaddrCon.c_wstr()
                    , (int)pCon -> EffectiveTrust ( ) )
           ->Advice_T ("0 wire, 1 kernel-local, 2 in-process. Post a connection "
                       "of the class this hub was fenced to, or widen the fence "
                       "with RequireTrustAtLeast()")
           ->Display()->SetLast();
      return FALSE;
    }

    // Iterate through P2PeerCon list
    // NOTES: Trap duplicates.  Null identification addresses
    //        are special
    P2PeerCon *pConEnum = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pConEnum) )
    {
      if ( pConEnum->GetP2Paddress() != oP2PaddrCon )
        continue;
      EVERR->Module (_T(__FUNCTION__))->AFPcon(pCon)->AFP(nPumpID)
           ->Message(_T("P2PeerCon[%s] instance already exists ")
                     _T("within P2PmsgHub[%s]")
                    ,   oP2PaddrCon.c_wstr()
                    , m_oP2PaddrHub.c_wstr() )
           ->SetLast();
      return FALSE;
    }

    // Tidy up, and
    pCon -> m_pP2PeerTarget = this;
    PostP2PmsgCon ( nPumpID, pCon );
    // NB: post the con's LIVE address (m_oThatP2Paddr, valid for pCon's lifetime),
    // NOT the stack-local copy oP2PaddrCon — P2Pmsg.strP2Paddr keeps a raw pointer and
    // the pump dispatches CN_P2PeerCon on another thread after this frame returns, so a
    // pointer into oP2PaddrCon is a use-after-return (ASan stack-use-after-return; masked
    // on Windows only because the pointed-at CString buffer is heap/refcounted). Every
    // other CN_P2PeerCon post already passes GetP2Paddress() for exactly this reason.
    PostP2Pmsg ( pCon->GetP2Paddress(), CN_P2PeerCon, P2P_Startup
               , pCon, (P2PeerMsg *)0, nPumpID );
    return TRUE;
}

//
//  Signals nominated P2PeerCon object
//
//
//  Parameters: P2PaddrSTR strP2Paddr
//              Address domain defining of P2PeerCon objects to
//              be signalled
//
//              P2PconID nConID
//              Identification of the P2PeerCon object to be signalled
//
//              P2PsigID nSigID
//              Signal to be posted
//
//              void *pvData = 0
//              Signal data
//
//              int iDataSize = 0
//              Signal data size
//
//  Returns     BOOL
//              Signalled event summary
//                TRUE... Located
//                FALSE.. Do not exist
BOOL
P2PeerHub::ConSignal ( P2PaddrSTR strP2PaddrTP
                     , P2PsigID nSigID, void *pvData, int iDataSize  )
{
    // Introduce locals
    P2Paddr   oP2Paddr = strP2PaddrTP;
    BOOL      bResult  = FALSE;
    P2PsafeCS oSafeCS  = m_oCSectionHub;
    ASSERT(m_nHubID>0);

    // Iterate through P2PeerCon'nections list
    P2PeerCon *pConEnum = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pConEnum) )
    {
      if ( !oP2Paddr.IsMapped(pConEnum->GetP2Paddress()) )
        continue;
      bResult = TRUE;
      pConEnum -> Signal ( nSigID, pvData, iDataSize );
      SwitchToThread ( );
    }

    // Tidy up and
    return bResult;
}
BOOL
P2PeerHub::ConSignal ( P2PconID nConID
                     , P2PsigID nSigID, void *pvData, int iDataSize  )
{
    // Introduce locals
    BOOL      bResult  = FALSE;
    P2PsafeCS oSafeCS  = m_oCSectionHub;
    ASSERT(m_nHubID>0);

    // Iterate through P2PeerCon'nections list
    P2PeerCon *pConEnum = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pConEnum) )
    {
      if ( nConID                          &&
           nConID != pConEnum->m_nP2PconID    )
        continue;
      bResult = TRUE;
      pConEnum -> Signal ( nSigID, pvData, iDataSize );
      SwitchToThread ( );
    }

    // Tidy up and
    return bResult;
}

//
//  Checks if P2PeerCon connection object exists for passed
//  P2PaddrSTR
//
//
//  Parameters: P2PaddrSTR strP2Paddr
//              Connection identification code to be checked
//
//  Returns     BOOL
//              Existence summary
//                TRUE... Exists
//                FALSE.. Does not exist
BOOL
P2PeerHub::ConExists  ( P2PaddrSTR strP2Paddr )
{
    // Locals
    P2PsafeCS oSafeCS = m_oCSectionHub;

    // Iterate through P2PeerCon list
    P2PeerCon *pCon = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pCon) )
    {
      if ( pCon->GetP2Paddress() == strP2Paddr )
        return TRUE;
    }

    // Nope, does not exist
    return FALSE;
}

//
//  Queries hub for nominated P2PeerCon
//  NOTES: Designed for use from P2PeerMsg handlers whereby
//         configuration issues require access to underlying
//         P2PeerCon'nections
//       : P2PeerCon pointers are transitory and as such should
//         only retained for the life of a P2PeerMsg handler
//
//
//  Parameters: P2PaddrSTR strP2Paddr
//              Connection idetification
//
//              SafeP2PeerCon& rSafeCon
//              Safe container
//  
//  Returns:    bool
//              Query summary
//                true... Located
//                false.. Not located
bool
P2PeerHub::ConQuery ( P2PaddrSTR strP2Paddress, SafeP2PeerCon& rSafeCon )
{
    // Locals
    P2PsafeCS oSafeCS = m_oCSectionHub;

    // Iterate through P2PeerCon list
    P2PeerCon *pCon = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pCon) )
    {
      if ( pCon->GetP2Paddress() == strP2Paddress )
      {
        rSafeCon = pCon;
        return true;
      }
    }

    // Nope, does not exist
    rSafeCon = (P2PeerCon *)0;
    return false;
}

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg operations

//
//  Routes P2PeerMsg's through P2PeerCon objects posted to this hub
//  NOTES: Local P2PeerMsg routing previously handled
//       : Referenced from P2Pwin32, PostP2PeerMsg() for local hub
//         routing
//
//
//  Parameters: P2PeerMsg *pMsg
//              Message to be routed.
//
//  Returns:    msgRESULT
//              Routing result
msgRESULT
P2PeerHub::RouteP2PeerMsg ( P2PeerMsg *pMsg )
{
    if ( m_pTargetParent )
      return m_pTargetParent -> RouteP2PeerMsg ( pMsg );

    // To be sure, to be sure
    // NOTES: Local routing must already have been performed
    ASSERT(pMsg->GetDestin()!=m_oP2PaddrHub);

    //  A COPY, not the pointer GetDestin() returns. On Windows that pointer
    //  aims straight at the stored wide characters and stays valid; on Linux
    //  the store is 16-bit and c_wstr() has to widen, so it hands back one of
    //  16 rotating thread-local scratch buffers, valid only until the next
    //  accessor call on this thread. The loop below makes several such calls
    //  per connection, so by the third connection the buffer this pointer aims
    //  at had been recycled and the destination read as a field NAME ("Net"),
    //  matching nothing. Every message then fell through to the undeliverable
    //  path, whose report was itself undeliverable, and each round wrapped the
    //  previous one - 2048, 5856, 14713, 35890 bytes - until the 64K message
    //  heap threw. That is the whole of the p2p_sealhop Linux failure.
    CString      strP2PaddrMsg = pMsg -> GetDestin ( );
    P2PaddrSTR   pP2PaddrMsg   = strP2PaddrMsg;

    // Facilitate message peeking
    // NOTES: Application may wish to observe outgoing messages
    msgRESULT msgResult = PeekP2PeerMsg ( pMsg );
    if ( msgResult != msgCONTINUE )
      return msgResult;

    // P2PeerCon routing
    // NOTES: Connections manage their own routing logic
    P2PeerCon *pCon = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pCon) )
    { 
      const P2Paddr& oP2PaddrCon = pCon -> GetP2Paddress();
      // NOTES: EnumP2PmsgCon() is deliberately unfiltered - it is the
      //        "every connection on this hub" primitive, and the ten
      //        loops in this file each apply their own predicate to it.
      //        A listener is not a routing candidate, so the
      //        test belongs at this call site and not in the enumerator
      if ( pCon->GetMode() == P2PeerCon_SERVICE )
      {
        continue;
      }

      // Immediate
      if ( oP2PaddrCon == pP2PaddrMsg )
        return P2PeerContextSwap ( pCon, pMsg );

      // Children
      // NOTES: P2PeerCon is our network child, and
      //        P2PeerMsg is routable down through P2PeerCon
      if ( m_oP2PaddrHub.IsChild(oP2PaddrCon) &&
             oP2PaddrCon.IsRable(pP2PaddrMsg)    )
        return P2PeerContextSwap ( pCon, pMsg );

      // Parent
      // NOTES: P2PeerCon is our network parent, and
      //        P2PeerMsg is not routable down through this P2Peer
      if (    oP2PaddrCon.IsChild(m_oP2PaddrHub) &&
           !m_oP2PaddrHub.IsRable(pP2PaddrMsg)      )
        return P2PeerContextSwap ( pCon, pMsg );
    }
   
    // Undeliverable
    return P2PeerTarget::RouteP2PeerMsg ( pMsg );
}

//
//  Posts P2PeerMsg to this hub for asynchronous routing
//  NOTES: Always posted to the P2PmsgHub enabling associated
//         P2PmsgPump's to observe implementation
//       : P2PmsgHub must be operational otherwise an exception
//         is thrown
//
//
//  Parameters: P2PeerMsg *pMsg
//              Message to be posted to this hub
//              NOTES: Hub assumes control over message life cycle.
//
//  Returns:    P2PeerMsg*
//              Message posted flag
//                 0.. Posted OK
//
P2PeerMsg*
P2PeerHub::PostP2PeerMsg ( P2PeerMsg *pMsg )
{
    if ( m_pTargetParent )
      return m_pTargetParent->PostP2PeerMsg ( pMsg );
    // To be sure, to be sure
    if ( g_bP2Pmsg_AssertValid )
      pMsg -> AssertValid ( );

    // Delegate
    return PostP2Pmsg ( pMsg, m_nHubID );
}

//
//  W6 (p2p_PumpPerf.md) - batch producer handoff.  Posts a bounded span of
//  P2PeerMsg to this hub's pump under a single lookup + lock + wake.  Additive
//  twin of PostP2PeerMsg; the single-message path is untouched.  Caller keeps
//  the batch well below the queue cap (see PostP2PmsgBatch).
//
void
P2PeerHub::PostP2PeerMsgBatch ( P2PeerMsg **apMsg, size_t nCount )
{
    // Nested hub: no batch pump of our own - post singly via the proven path
    // (correctness over the batch fast-path; the batch case targets top hubs).
    if ( m_pTargetParent )
    {
      for ( size_t i = 0; i < nCount; ++i )
        if ( apMsg[i] )
          m_pTargetParent -> PostP2PeerMsg ( apMsg[i] );
      return;
    }
    // To be sure, to be sure
    if ( g_bP2Pmsg_AssertValid )
      for ( size_t i = 0; i < nCount; ++i )
        if ( apMsg[i] )
          apMsg[i] -> AssertValid ( );

    // Delegate to the batch producer handoff
    PostP2PmsgBatch ( apMsg, nCount, m_nHubID );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerExpump management

//
//  Posts P2PeerExpump object to hub
//  NOTES: Hub assumes control over life cycle.  P2PeerExpump object
//         state and configuration externally managed.
//       : Refer GetP2PeerExpump() for exposure of posted object
//
//  Returns:    P2PeerTarget*
//              Object posted flag
//                 0.. Posted OK
P2PeerTarget*
P2PeerHub::PostP2PeerExpump ( P2PeerTarget *pP2PeerExpump )
{
    if ( m_pP2PeerExpump )
    {
      EVERR->Module ( T__FUNCTION__ )
           ->Message( L"Attempt to post multiple P2PeerExpump objects to P2PeerHub[%s]"
                    , m_oP2PaddrHub.c_wstr() )
           ->Display()->SetLast();
      return pP2PeerExpump;
    }

    // Tidy up, and
    m_pP2PeerExpump = pP2PeerExpump;
    return 0;
}

BOOL
P2PeerHub::DropP2PeerExpump ( )
{
    if ( !m_pP2PeerExpump )
      return FALSE;
    // Detach BEFORE destroying
    // NOTES: Anything thrown out of the P2PeerExpump destructor used to leave
    //        the member pointing at freed storage for ~P2PeerHub to delete a
    //        second time.  ~P2PeerExplorer no longer throws, but the hub has
    //        no business holding a pointer to an object it is destroying
    P2PeerTarget *pP2PeerExpump = m_pP2PeerExpump;
                  m_pP2PeerExpump = 0;
    delete pP2PeerExpump;
    return TRUE;
}

//
//  Sets the P2Paddr of this P2PeerHub
//  NOTES: Usually the P2Paddr of a hub is assigned at creation
//         time.  However, under some circumstances such as negotiating
//         console connections, P2Paddr needs to be set dynamically by
//         the server.
//
//
//  Parameters: P2PaddrSTR strP2PaddrHub
//              New P2PeerHub address.
//              NOTES: The passed address must maintain the child
//                     relationship with P2PeerHub parent and
//                     parent relationship with any P2PeerHub
//                     children
//
//  Returns:    P2Paddr&
//              Adopted hub address
//
const P2Paddr&
P2PeerHub::SetP2PaddrHub ( P2PaddrSTR strP2PaddrHub )
{
    // Simply
    // NOTES: Observe operational status of hub
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_nHubID )
      SetP2PmsgHubAddr ( m_nHubID, strP2PaddrHub );
    m_oP2PaddrHub = strP2PaddrHub;

    // Tidy up and
    return m_oP2PaddrHub;
}

///////////////////////////////////////////////////////////////////////
//  Property exposure

//
//  Exposes P2Paddr of this P2PeerHub
//  NOTES: Overrides P2PeerTarget base class and as such exposes the
//         P2Paddr of the P2PeerHub to which all P2PeerTarget
//         derived objects must altimately be registered, either
//         directly or indirectly.
//
//
//  Returns:    const P2Paddr&
//              Address of this P2PeerHub
//
const P2Paddr&
P2PeerHub::GetP2PaddrHub ( )
{
    if ( m_pTargetParent )
      return GetP2PeerHub()->GetP2PaddrHub();
    // Snapshot, and
    if ( m_nHubID                > 0 &&
         m_oP2PaddrHub.IsEmpty()        )
    {
      P2PsafeCS oSafeCS = m_oCSectionHub;
      m_oP2PaddrHub = GetP2PmsgHubAddr ( m_nHubID );
    }
    return m_oP2PaddrHub;
}

//
//  Exposes pointer to this P2PeerHub
//  NOTES: Overrides P2PeerTarget base class and as such exposes pointer
//         to P2PeerHub to which all P2PeerTarget derived objects must
//         altimately be registered, either directly or indirectly.
//
//  Returns:    P2PeerHub*
//              Pointer to this object
//
P2PeerHub*
P2PeerHub::GetP2PeerHub ( )
{
    if ( m_pTargetParent )
      return m_pTargetParent->GetP2PeerHub ( );
    return this;
}

//
//  Exposes pointer to encapsulated P2PeerExpummp object
//  NOTES: P2PeerExpump objects are managed through their corresponding
//         base class P2PeerTarget objects.
//       : Intended to limit exposure of P2PeerExpump definitions and  
//         implementation
//
//  Returns:    P2PeerTarget*
//              Pointer to downcast P2PeerExpump object
//
P2PeerTarget*
P2PeerHub::GetP2PeerExpump ( ) const
{
    return m_pP2PeerExpump;
}

//
//  Exposes P2PmsgHubID managed via this instance
//  NOTES: Overrides P2PeerTarget base class and as such exposes pointer
//         to P2PmsgHubID to which all P2PeerTarget derived objects must
//         altimately be registered, either directly or indirectly.
//
//  Returns:    P2PmsgHubID
//              Identification code of this instance.  Refer
//              CreateP2PmsgHub() for further details
//
P2PmsgHubID
P2PeerHub::GetHubID ( ) const
{
    if ( m_pTargetParent )
      return P2PeerTarget::GetHubID();
    return m_nHubID;
}

///////////////////////////////////////////////////////////////////////
//  P2PeerCon handlers
//  NOTES: If there is a desire to optimise the connection map
//         subjectively place frequent messages at the top and less
//         frequent messages at the bottom of the map
// 
BEGIN_P2PeerCon_MAP(P2PeerHub, P2PeerTarget)
END_P2PeerCon_MAP()

///////////////////////////////////////////////////////////////////////
//  P2PeerSys handlers
//  NOTES: If there is a desire to optimise the connection map
//         subjectively place frequent messages at the top and less
//         frequent messages at the bottom of the map
// 
BEGIN_P2PeerSys_MAP(P2PeerHub, P2PeerTarget)
END_P2PeerSys_MAP()

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg Handlers
//  NOTES: Default handler set available in P2PeerHub derived objects
//       : If there is a desire to optimise the message map
//         subjectively place frequent messages at the top and less
//         frequent messages at the bottom of the map
//
BEGIN_P2PeerMsg_MAP(P2PeerHub, P2PeerTarget)
    ON_P2PeerMsg(P2Pmsg_BCast, On_P2PeerBCast)
    ON_P2PeerMsg_CATCH(P2Pmsg_BCast, On_MsgCatch)
    ON_P2PeerMsg(P2Pmsg_Error, On_P2PeerError)
END_P2PeerMsg_MAP()

//
//  MSG_P2PexpumpCtrl handler
//  NOTES: Broadcasts messages to P2PeerHub children through P2PeerCon
//         connections for which broadcasts are enabled
//       : Provide implementation in derived class to intercept a
//         local copy, alternatively specialise PeekP2PeerMsg()
//
//
//  Parameters: P2PeerMsg *pMsg
//              P2Pexp control message
//
//  Returns:    msgRESULT
//              Completion summary
//
/*msgRESULT
P2PeerHub::On_P2PexpumpCtrl ( P2PeerMsg *pMsg )
{
    // Confirm thread context
    // NOTES: MSG_P2PmsgExp messages MUST be processed
    //        sequentually in the context of the P2PmsgHub
    //      : The P2PexpumpID may or may not exist
    if ( !P2PeerContext(m_nHubID) )
      return P2PeerContextSwap ( m_nHubID );

    // Delegate implementation
    // NOTES: Effectively 2 phase start-up, first being external
    //        instanciation of P2PeerExpump object and second being
    //        the demand activation of such object
    //      : External instanciation is an application dependant
    //        activity.  TargetCore provides no such service
    //      : Absense of m_pP2PeerExpump object effectively blocks
    //        exploration through this routing vector.
    P2PeerExpump *pP2PeerExpump = dynamic_cast<P2PeerExpump*>(m_pP2PeerExpump);
    //if ( pP2PeerExpump )
    // return pP2PeerExpump -> On_P2PexpumpCtrl ( pMsg );
    
    // Because this is all problematic
	try
	{
	  // NOTES: Each field becomes a command
      P3PmsgCurs& oCurs = pMsg->r_datn().GetCurs();
      for ( int i = 0; oCurs.Goto(i); i++ )
      {
	    P2PeerExpump *pP2PeerExpump = dynamic_cast<P2PeerExpump*>(m_pP2PeerExpump);
        P3PmsgField& oField = oCurs.r_field();

        // Create P2PeerExpump object
	    // NOTES: Handle redundant requests
        if ( oField == "CREATE" )
        {
		  P3PmsgField& oCreate = oCurs.r_field();
		  if (   pP2PeerExpump             &&
		       ( oCreate.IsNull()     ||
			     oCreate.c_int() == 0     )    )
		    EVERR->MODULE
		         ->Message("P2PeerExp object already exists")
			     ->Advice ("Qualify with non-zero integer")
			     ->Throw ( );
		  m_pP2PeerExpump = new P2PeerExplorer ( this );
        }

        // Spawn P2Pexpump
	    // NOTES: Handle redundant requests
        else if ( oField == "SPAWN" )
        {
		  P3PmsgField& oSpawn = oCurs.r_field();
		  if ( pP2PeerExpump == NULL )
		    EVERR->MODULE
		         ->Message("P2PeerExp does not exist")
			     ->Advice ("Preceed SPAWN with CREATE command")
			     ->Throw ( );
		  if (   pP2PeerExpump->m_nExpumpID &&
		       ( oSpawn.IsNull()     ||
			     oSpawn.c_int() == 0     )      )
		    EVERR->MODULE
		         ->Message("P2Pexpump already spawned")
			     ->Advice ("Qualify with non-zero integer")
	             ->Throw ( );
		  pP2PeerExpump -> SpawnExpump ( 0, 0 );
        }

        // Close P2Pexpump
	    // NOTES: Handle redundant requests
        else if ( oField == "CLOSE" )
        {
		  P3PmsgField& oClose = oCurs.r_field();
		  if (   !pP2PeerExpump->m_nExpumpID &&
		       ( !oClose.IsNull() &&
			     !oClose.c_int()     )          )
		    EVERR->MODULE
		         ->Message("P2Pexpump is not running")
			     ->Advice ("Qualify with null or non-zero integer to skip")
	             ->Throw ( );
		  pP2PeerExpump -> CloseExpump ( 0 );
        }

        // Drop P2PeerExpump object
	    // NOTES: Handle redundant requests
        else if ( oField == "DROP" )
        {
		  P3PmsgField& oDrop = oCurs.r_field();
		  if (   !pP2PeerExpump       &&
		       ( !oDrop.IsNull() &&
			     !oDrop.c_int()     )    )
		    EVERR->MODULE
		         ->Message("P2Pexpump does not exist")
			     ->Advice ("Qualify with null or non-zero integer to skip")
	             ->Throw ( );
		  delete m_pP2PeerExpump;
                 m_pP2PeerExpump = 0;
        }

        // Accept P2PeerConWsa interaction
	    // NOTES: 
        else if ( oField == "AcceptWSA" )
        {
		  if ( !pP2PeerExpump              || 
		       !pP2PeerExpump->m_nExpumpID    )
		    EVERR->MODULE
		         ->Message("P2Pexpump is not running")
			     ->Advice ("Preceed with CREATE and/or SPAWN commands")
			     ->Throw ( );
		  short nEConsPort = oField.c_short();
          P2PeerConWsa *pWsaECid
             = P2PeerConWsa::ServiceFactory( "EXPump", nEConsPort );
                        pWsaECid -> SetState ( ConState_BCasts
                                             | ConState_UCasts, 0 );
          pP2PeerExpump -> PostP2PeerCon ( pWsaECid );

        }

        // Query P2Pexpump status
	    // NOTES: Responds with snapshot 
        else if ( oField == "QUERY" )
	    {
		  P3PmsgField& oQuery = oCurs.r_field();
		  LPCTSTR lpszMsgResponse = "P2Pexpump_Props";
		  if ( !oQuery.IsNull() )
            lpszMsgResponse = oQuery.c_wstr();
          P2PeerMsgSP spMsg = pMsg->ResponseFactory ( lpszMsgResponse, 0, 0 );
          if ( pP2PeerExpump )
            spMsg->r_datn() += P3PmsgField ( "CREATE", P3PmsgData((int)1) );
		  else
		    spMsg->r_datn() += P3PmsgField ( "CREATE", P3PmsgData((int)0) );
		  if ( pP2PeerExpump              &&
		       pP2PeerExpump->m_nExpumpID    )
		    spMsg->r_datn() += P3PmsgField ( "SPAWN", P3PmsgData((int)1) );
          else
            spMsg->r_datn() += P3PmsgField ( "SPAWN", P3PmsgData((int)0) );
	    }

        // Unknown command
        else
        {
          EVERR->MODULE
		       ->Message(L"Unknown P2PeerHubCtrl command (%s)"
                        , oField.c_name() )
		       ->Advice ("Valid commands CREATE, SPAWN, CLOSE, DROP, AcceptWSA, QUERY")
		       ->Throw ( );
        }
      }
    }

    // Exceptions
    catch ( P2Pevent *pEVT )
    {
      pEVT ->AFPmsg(pMsg);
      PostP2PeerMsg ( pMsg->ExceptionFactory(pEVT) );
      pEVT ->Cancel ( );
    }
    catch ( ... )
    {
      P2Pevent *pEVT =
      EVERR->MODULE->AFPmsg(pMsg)
           ->Message("Last resort exception" );
      PostP2PeerMsg ( pMsg->ExceptionFactory(pEVT) );
      pEVT ->Cancel( );
    }

    // Tidy up and
    return msgHANDLED;
}*/

//
//  MSG_P2PeerBCast handler
//  NOTES: Broadcasts messages to P2PeerHub children through P2PeerCon
//         connections for which broadcasts are enabled
//       : Provide implementation in derived class to intercept a
//         local copy, alternatively specialise PeekP2PeerMsg()
//
//
//  Parameters: P2PeerMsg *pMsg
//              Broadcast message
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerHub::On_P2PeerBCast ( P2PeerMsg *pMsg )
{
    //  Stamp the end-to-end scope before the first copy is made
    //  NOTES: Every copy below is re-addressed to its own link peer, which
    //         destroys the only record of what the ORIGIN addressed this
    //         message to - and two protections read that record: the seal
    //         hook's last-hop exemption and the relay attestation's digest.
    //         Refer TMsg_Scp in P2PeerMsg.h for what that cost and how it was
    //         measured
    //       : IF ABSENT ONLY, and that is the whole rule.  A copy arriving
    //         here has already been fanned out once and carries the
    //         ORIGINATOR's scope; this hub forwards that and must not
    //         substitute its own, which is the same discipline - and the same
    //         reason - as AttestAppMsgOutbound leaving an existing attestation
    //         alone.  Stamping unconditionally would let every relay re-scope
    //         a broadcast, which is exactly the re-targeting the digest exists
    //         to prevent
    //       : A COPY, not the accessor's pointer.  Off Windows GetDestin()
    //         hands back a slot in a ring of 16 thread-local buffers that the
    //         next accessor call on this thread recycles, and SetScope() is an
    //         accessor call
    if ( pMsg && !pMsg->HasScope ( ) && pMsg->GetDestin ( ) )
    {
      CString strScopeHeld = pMsg->GetDestin ( );
      pMsg -> SetScope ( (P2PaddrSTR)strScopeHeld );
    }

    // P2PeerCon routing
    // NOTES: Connections manage their own routing logic
    P2PeerMsg *pMsgBCast = 0;
    P2PeerCon *pCon      = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pCon) )
    { 
      const P2Paddr& oP2PaddrCon =  pCon->GetP2Paddress();

      // Parents
      // NOTES: Only broadcast to P2PeerCon network parents
      //        for which upcasts are enabled
      if ( pCon->HasState(ConState_BCasts) &&
          !pCon->HasState(ConBCasts_OK)    )
          pCon=pCon;
      if ( !m_oP2PaddrHub.IsChild(oP2PaddrCon) ||
           !pCon->HasState ( ConBCasts_OK )       )
        continue;
      pMsgBCast = pMsg -> RedirectFactory ( oP2PaddrCon );
      pMsgBCast = pCon -> PostP2PeerMsg   ( pMsgBCast );
    }

    // Tidy up and
    return msgHANDLED;
}

//
//  MSG_P2PeerUCast handler
//  NOTES: UCasts messages to P2PeerHub parents through P2PeerCon
//         connections for which broadcasts are enabled
//       : Provide implementation in derived class to intercept a
//         local copy, alternatively specialise PeekP2PeerMsg()
//
//
//  Parameters: P2PeerMsg *pMsg
//              Broadcast message
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerHub::On_P2PeerUCast ( P2PeerMsg *pMsg )
{
    //  Stamp the end-to-end scope before the first copy is made
    //  NOTES: Every copy below is re-addressed to its own link peer, which
    //         destroys the only record of what the ORIGIN addressed this
    //         message to - and two protections read that record: the seal
    //         hook's last-hop exemption and the relay attestation's digest.
    //         Refer TMsg_Scp in P2PeerMsg.h for what that cost and how it was
    //         measured
    //       : IF ABSENT ONLY, and that is the whole rule.  A copy arriving
    //         here has already been fanned out once and carries the
    //         ORIGINATOR's scope; this hub forwards that and must not
    //         substitute its own, which is the same discipline - and the same
    //         reason - as AttestAppMsgOutbound leaving an existing attestation
    //         alone.  Stamping unconditionally would let every relay re-scope
    //         a broadcast, which is exactly the re-targeting the digest exists
    //         to prevent
    //       : A COPY, not the accessor's pointer.  Off Windows GetDestin()
    //         hands back a slot in a ring of 16 thread-local buffers that the
    //         next accessor call on this thread recycles, and SetScope() is an
    //         accessor call
    if ( pMsg && !pMsg->HasScope ( ) && pMsg->GetDestin ( ) )
    {
      CString strScopeHeld = pMsg->GetDestin ( );
      pMsg -> SetScope ( (P2PaddrSTR)strScopeHeld );
    }

    // P2PeerCon routing
    // NOTES: Connections manage their own routing logic
    P2PeerMsg *pMsgUCast = 0;
    P2PeerCon *pCon      = 0;
    while ( EnumP2PmsgCon(m_nHubID,&pCon) )
    { 
      const P2Paddr& oP2PaddrCon = pCon -> GetP2Paddress();

      // Parents
      // NOTES: Only upcast to P2PeerCon network parents for
      //        which upcasts are enabled
      if ( !oP2PaddrCon.IsChild(m_oP2PaddrHub) ||
           !pCon->GetState(ConUCasts_OK)          )
        continue;
      pMsgUCast = pMsg -> RedirectFactory ( oP2PaddrCon );
      pMsgUCast = pCon -> PostP2PeerMsg   ( pMsgUCast );
    }

    // Tidy up and
    return msgHANDLED;
}

//
//  MSG_P2PeerError handler
//  NOTES: Default implementation for error messages.
//
//
//  Parameters: P2PeerMsg *pMsg
//              Error message
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerHub::On_P2PeerError ( P2PeerMsg *pMsg )
{
    // Simply report the message
    P2Pevent *pP2Pevent = pMsg -> ExtractP2Pevent ( );
    if ( pP2Pevent )
       pP2Pevent -> Cancel();

    // Tidy up and
    return msgHANDLED;
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerHub::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}

//
//  Serialise a state snapshot for this P2PeerHub instance
//  NOTES: Such snapshots are used to inject P2PeerHub state information
//         into P2PeerMsg's and P2Pevent's etc
//
//  Parameters:  LPCTSTR lpszVar
//               Name assigned to the generated P2PmsgNode
//                 0.. Use {P2PeerHub}
//
//               bool bDsc = false
//                 true... Add description field attributes
//                 false.. No description field added
//
//  Returns:     P3PmsgNode
//               Snapshot instrance
//
P3PmsgItem
P2PeerHub::Serialise ( LPCTNAM lpszVar, bool bDsc )
{
    // Create a placeholder for receipt of P2PeerHub details
    // NOTES: This will be passed by value back up the stack
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData()) );
    if ( lpszVar == 0 || wcslen(lpszVar) <= 0 )
      (P3PmsgField&)oNodeVar = P3PmsgName ( L"{P2PeerHub}" );
    else
      oNodeVar.r_data() = P3PmsgData ( L"{P2PeerHub}" );

    // Append P2PeerHub state to node
    // NOTES: Version is the build identity of the TargetCore binary this hub
    //        is running, taken from TargetCore_version.h - the only place the
    //        number is written, and the same one stamped into the DLL's
    //        VERSIONINFO resource. Reported here rather than through a new
    //        message because every hub snapshot, every P2Pevent carrying hub
    //        state, and the MSG_P2PexpHub reply built by NotifyP2PmsgExp_Hub
    //        already call this function - so they all gain it at once.
    //      : VersionHex is the same value packed MAJOR,MINOR,PATCH,BUILD for a
    //        reader that wants to compare rather than display. Both are shipped
    //        because a display string that a consumer has to parse to compare
    //        is a consumer that will parse it wrongly.
    //      : This is NOT the wire version. Whether this hub can talk to another
    //        is decided by the auth block's own version byte (P2PAuthLogin.cpp)
    //        which versions independently and on purpose. Do not read
    //        interoperability out of the field below.
    P3PmsgField_SERIALISE ( oNodeVar, L"Version"
                          , TARGETCORE_VERSION_STRINGW, bDsc
                          , L"TargetCore build version of the running Hub" );
    P3PmsgField_SERIALISE ( oNodeVar, L"VersionHex"
                          , (UINT32)TARGETCORE_VERSION_HEX, bDsc
                          , L"Build version packed MAJOR,MINOR,PATCH,BUILD" );
    //      : PumpsMax reported the LITERAL 0 from the import until Stage 4
    //        step 13.  A field that always reports a constant is worse than an
    //        absent one - an absent field is asked about, a constant one is
    //        believed - and this one told every reader that the hub could run
    //        no pumps at all.  It is the hub's configured ceiling, the number
    //        CreateP2PmsgPump() refuses against
    P3PmsgField_SERIALISE ( oNodeVar, L"PumpsMax"
                          , (UINT32)GetP2PmsgHubPumpsMax(m_nHubID), bDsc
                          , L"Maxmimum number of pumps supported by Hub" );

    //      : QueDepth and Accepted are Stage 4 step 13, and the reason they
    //        are HERE rather than in a new message is the reason Version is:
    //        this function is what every hub snapshot, every P2Pevent
    //        carrying hub state and the MSG_P2PexpHub reply are built from,
    //        so a monitor that can already read one of those needs no new
    //        call, no new message and no instrumentation in the hub to watch
    //        the two numbers that say whether it is coping
    //      : QueDepth is the P2Pmsg's queued and not yet dispatched across
    //        ALL of the hub's pumps, not just the one the caller is standing
    //        in.  A per-pump figure is what GetP2PmsgCount() already gives
    //        and is the wrong scope for a hub snapshot: a hub whose explorer
    //        pump is drowning while its own is idle is not a healthy hub
    //      : Accepted counts connections the hub's SERVICES are currently
    //        holding.  It is the number SetMaxAccepted() bounds, so an
    //        operator can see the bound approaching instead of discovering it
    //        at the refusal - and, until F-S4-1 is closed, an operator
    //        watching this field on Windows will see it climb and never fall
    //        for peers that connect and disconnect without speaking.  That is
    //        the defect being visible rather than this field being wrong, and
    //        it is the first time it is visible from outside a debugger
    //      : Neither accessor throws.  A snapshot taken of a hub that is
    //        being torn down must report the teardown, not raise a second
    //        fault from inside the report of the first
    P3PmsgField_SERIALISE ( oNodeVar, L"QueDepth"
                          , (UINT32)GetP2PmsgHubQueCount(m_nHubID), bDsc
                          , L"P2Pmsg's queued across all of the Hub's pumps" );
    P3PmsgField_SERIALISE ( oNodeVar, L"Accepted"
                          , (UINT32)GetP2PmsgHubAcceptedCount(m_nHubID), bDsc
                          , L"Connections currently accepted by Hub services" );

    //      : Throttled is Stage 4 step 12, and it belongs beside QueDepth
    //        rather than in a message of its own because it is the OTHER half
    //        of the same question. QueDepth says how loaded the hub is;
    //        Throttled says how often it has had to stop reading from a peer
    //        to stay that way. A hub with a low queue depth and a climbing
    //        hold count is not idle - it is holding the line, and the two
    //        fields read together say so where either alone misleads
    P3PmsgField_SERIALISE ( oNodeVar, L"Throttled"
                          , (UINT32)GetP2PmsgHubHeldCount(m_nHubID), bDsc
                          , L"Backpressure holds applied to Hub connections" );

    //      : SECURITY POSTURE, and it is F-S6-2. Every field
    //        above this line is about identity or load. Until these existed a
    //        running hub could be asked its version, its queue depth and how
    //        many peers it was holding, and NOT ONE THING about whether any
    //        protection was on - so a deployment could confirm its own posture
    //        only by reading the source of the library it had linked
    //      : F-S6-1 is why that is a finding and not a wish. From the day the
    //        defaults went on until 2026-08-20, "this hub requires
    //        authentication" and "this connection is encrypted" were different
    //        facts, and nothing inside the process or outside it could have
    //        discovered they had come apart. The next divergence will be just
    //        as quiet, and this is the surface on which it shows
    //      : ADDITIVE, and that is the compatibility answer. The snapshot is a
    //        diagnostic image other tools parse; every field is APPENDED and
    //        none is renamed, moved or retyped, and every reader in this tree
    //        selects by NAME (p2p_hubsnap's monitor is the worked example), so
    //        a consumer that knows nothing of these sees exactly what it saw
    //      : Intent and capability are SEPARATE fields on purpose. AuthRequired
    //        is what the operator asked for; AuthCanSign is whether this hub
    //        holds a key at all; AuthArm is whether what was asked for can
    //        actually be enforced. F-S6-1 lived exactly in the gap between the
    //        first two, and a single "secure" boolean would have reported that
    //        hub as fine
    //      : READ WITHOUT BLOCKING, and that is a lock order rather than a
    //        preference. This function is called by QueryP2PmsgExp_Hub() with
    //        both process-wide statics held, while the login path takes
    //        m_oCSectionHub FIRST and a static second (SetP2PaddrHub ->
    //        SetP2PmsgHubAddr). Waiting on m_oCSectionHub here would close that
    //        cycle, so TryReadPosture() gives up instead - refer P2PeerHub.h.
    //        A hub answering "ask again" is a snapshot that failed; a hub that
    //        stops answering is an outage
    //      : PostureOk is emitted FIRST and always. Without it the absence of
    //        the fields and a hub with nothing switched on are the same
    //        picture, which is the failure this finding is about wearing a
    //        different hat
    P2PeerHub::Posture oPosture;
    bool bPosture = TryReadPosture ( oPosture );
    P3PmsgField_SERIALISE ( oNodeVar, L"PostureOk"
                          , (UINT32)( bPosture ? 1 : 0 ), bDsc
                          , L"Security fields below were readable this instant" );
    if ( bPosture )
    {
      P3PmsgField_SERIALISE ( oNodeVar, L"AuthRequired"
                            , (UINT32)( oPosture.bAuthRequired ? 1 : 0 ), bDsc
                            , L"Hub requires peers to prove their identity" );
      P3PmsgField_SERIALISE ( oNodeVar, L"AuthCanSign"
                            , (UINT32)( oPosture.bAuthCanSign ? 1 : 0 ), bDsc
                            , L"Hub holds an identity key and can sign a login" );
      P3PmsgField_SERIALISE ( oNodeVar, L"AuthArm"
                            , (UINT32)oPosture.nAuthArm, bDsc
                            , L"Can enforce what it requires: 0 armed, 1 auth off" );
      P3PmsgField_SERIALISE ( oNodeVar, L"RelayAuth"
                            , (UINT32)( oPosture.bRelayAuth ? 1 : 0 ), bDsc
                            , L"Relayed traffic must carry an origin attestation" );
      P3PmsgField_SERIALISE ( oNodeVar, L"RelayReplay"
                            , (UINT32)( oPosture.bRelayReplay ? 1 : 0 ), bDsc
                            , L"An attestation already accepted is refused again" );
      P3PmsgField_SERIALISE ( oNodeVar, L"SealReplay"
                            , (UINT32)( oPosture.bSealReplay ? 1 : 0 ), bDsc
                            , L"A sealed body already opened is refused again" );
      //  FOUR revocation fields and not one, and the first draft of this block
      //  got it wrong in a way worth keeping on the record. It reported
      //  IsRevocationUsable() as "a list is loaded and usable", and the gate
      //  test printed a 1 out of a hub that had never seen a list: Usable
      //  means "revocation is not refusing anything", which is TRUE when none
      //  is configured. A hub with no revocation would have reported its
      //  revocation as fine. "Is there a list", "is it blocking logins", "is
      //  what we know still current" and "as of when" are four questions, and
      //  the snapshot answers them as four
      //  Sealing, and the pair is the same intent/capability split the
      //  revocation fields make below: SealReq is what the operator asked for,
      //  SealOpen is whether this hub could open a body addressed to it. A hub
      //  with the first and not the second does not start (ArmNoAgreement), so
      //  seeing 1/0 here means somebody changed it after arming.
      P3PmsgField_SERIALISE ( oNodeVar, L"SealReq"
                            , (UINT32)( oPosture.bSealRequired ? 1 : 0 ), bDsc
                            , L"Relayed bodies are sealed, or not sent" );
      P3PmsgField_SERIALISE ( oNodeVar, L"SealOpen"
                            , (UINT32)( oPosture.bSealCanOpen ? 1 : 0 ), bDsc
                            , L"Hub holds an agreement key and can open a seal" );
      //  Reported separately from SealReq because it answers a different
      //  question and can disagree with it. SealReq=1 SealBcast=0 is a
      //  deployment that has decided its broadcasts are not confidential, and
      //  that is a DECISION - the whole reason the field exists is that the
      //  same state used to arise by accident and be indistinguishable from
      //  one
      P3PmsgField_SERIALISE ( oNodeVar, L"SealBcast"
                            , (UINT32)( oPosture.bSealBcast ? 1 : 0 ), bDsc
                            , L"The seal requirement extends to broadcasts" );
      //  The §6.3 waiver, and it is rendered HERE - beside SealReq rather than
      //  beside the link-policy block below - because it is the field that
      //  makes SealReq readable. SealReq=1 WaiveE2E=1 is a hub that requires
      //  sealing and does not always do it, which is not deducible from any
      //  other field in this snapshot and is exactly the state an operator
      //  would otherwise have to read the source to discover.
      //
      //  It is also the ONLY field here that reports an ASSUMPTION rather
      //  than a mechanism. Every other 1 in this block is something the
      //  library enforces; this one is something an operator asserted about
      //  the deployment - that in-process hubs form one address subtree - and
      //  it is rendered so that the assertion is visible to whoever has to
      //  live with it. Refer P2PeerHub::WaiveEndToEndInProcess.
      P3PmsgField_SERIALISE ( oNodeVar, L"WaiveE2E"
                            , (UINT32)( oPosture.bWaiveE2E ? 1 : 0 ), bDsc
                            , L"Seal and attestation waived for an "
                                 "in-process destination" );
      //  FIVE since 2026-08-21, and the new one is INTENT where the four
      //  below are capability - the same separation AuthRequired keeps from
      //  AuthArm, and it earns its place for the same reason. RevocList=0
      //  alone cannot say whether this hub has no list because nobody
      //  provisioned one or because RequireRevocation(false) said so, and
      //  those are a misconfiguration and a decision.
      P3PmsgField_SERIALISE ( oNodeVar, L"RevocReq"
                            , (UINT32)( oPosture.bRevocRequired ? 1 : 0 ), bDsc
                            , L"Hub demands a revocation position before arming" );
      P3PmsgField_SERIALISE ( oNodeVar, L"RevocList"
                            , (UINT32)( oPosture.bRevocConfigured ? 1 : 0 ), bDsc
                            , L"A revocation list is configured on this Hub" );
      P3PmsgField_SERIALISE ( oNodeVar, L"RevocOk"
                            , (UINT32)( oPosture.bRevocOk ? 1 : 0 ), bDsc
                            , L"Revocation is not refusing logins (1 if none set)" );
      P3PmsgField_SERIALISE ( oNodeVar, L"RevocFresh"
                            , (UINT32)( oPosture.bRevocFresh ? 1 : 0 ), bDsc
                            , L"Revocation knowledge is within its staleness bound" );
      P3PmsgField_SERIALISE ( oNodeVar, L"RevocEpoch"
                            , (INT64)oPosture.llRevocEpoch, bDsc
                            , L"Epoch of the revocation list this hub has applied" );
      //  The per-trust-class link policy: 0 full, 1 open. THREE fields rather
      //  than one packed number, because a reader selects by NAME and a
      //  bitfield would make the one interesting case - "which class did they
      //  relax" - something a consumer has to decode rather than read.
      //  LinkPolWire is always 0 and is rendered anyway: a field that is
      //  present and pinned tells a reader the wire cannot be opened here,
      //  where an absent one tells them nothing at all.
      //
      //  Paired with the CONNECTION snapshot's Trust field, this is what makes
      //  Cypher=0 legible. Trust=2 with LinkPolProc=1 is a decision; Trust=0
      //  with Cypher=0 on a hub with AuthRequired=1 is still the defect it
      //  always was.
      P3PmsgField_SERIALISE ( oNodeVar, L"LinkPolWire"
                            , (UINT32)oPosture.anLinkPolicy[0], bDsc
                            , L"Wire links: 0 full handshake (cannot be opened)" );
      P3PmsgField_SERIALISE ( oNodeVar, L"LinkPolLocal"
                            , (UINT32)oPosture.anLinkPolicy[1], bDsc
                            , L"Kernel-local links: 0 full handshake, 1 opened" );
      P3PmsgField_SERIALISE ( oNodeVar, L"LinkPolProc"
                            , (UINT32)oPosture.anLinkPolicy[2], bDsc
                            , L"In-process links: 0 full handshake, 1 opened" );
      //  The fence, and it is rendered beside the three above it because it
      //  is what makes them safe to read. LinkPolProc=1 with TrustFloor=0 is
      //  a hub that has relaxed its in-process links and can still be handed
      //  a socket by the next PostP2PeerCon; the same hub with TrustFloor=2
      //  cannot. Nothing else in this snapshot distinguishes those two, and
      //  they are a different exposure.
      P3PmsgField_SERIALISE ( oNodeVar, L"TrustFloor"
                            , (UINT32)oPosture.nTrustFloor, bDsc
                            , L"Lowest link class this Hub will hold (0 no fence)" );
    }

    P3PmsgField_SERIALISE ( oNodeVar, L"Name", GetP2PaddrHub().c_name(), bDsc
                          , L"Allocated Hub name" );
    P3PmsgField_SERIALISE ( oNodeVar, L"P2Paddr", GetP2PaddrHub().c_wstr(), bDsc
                          , L"Allocated Hub address" );
    P3PmsgField_SERIALISE ( oNodeVar, L"P2Padom", GetP2PaddrHub().c_wstr(), bDsc
                          , L"Allocated Hub domain" );

    // Append P2PeerTarget state to node
    oNodeVar += P2PeerTarget::Serialise ( L"" );

    // Tidy up and
    return oNodeVar;
}

///////////////////////////////////////////////////////////////////////
//  Peer login authentication
//  NOTES: Refer P2PAuthLogin.h for the wire format and the threat
//         statement, and Ahtung_Disaster_progress.md sessions 8 and 9
//         for why every piece of this lives on the hub.
//       : AuthPolicy is deliberately NOT internally locked. It is
//         reached only through the wrappers below, and every one of
//         them holds m_oCSectionHub - the same lock the nonce cache
//         needs - so there is exactly one place to get the discipline
//         right instead of one per call site.
//

//
//  Load this hub's own identity key
//  NOTES: Configure before SpawnHub()/CreateHub()
//
//  Parameters: const char *pszIdentityFileUtf8
//              Path to the protected identity file
//
//              bool bCreateIfAbsent
//              Generate and save a fresh identity when the file is missing
//
//              p2pcng::IdProtection eProtect
//              At-rest protection for a newly created file
//
//  Returns:    p2pcng::IdResult
//              IdOk, or the specific reason the key could not be loaded
//
p2pcng::IdResult
P2PeerHub::SetIdentity ( const char *pszIdentityFileUtf8
                       , bool bCreateIfAbsent
                       , p2pcng::IdProtection eProtect )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> SetIdentity ( pszIdentityFileUtf8
                                        , bCreateIfAbsent, eProtect );
}

//
//  Load the peers this hub will accept a login from
//  NOTES: Cached in memory. A login runs on a pump thread and a pump
//         thread must not do file IO, so the file is read here and
//         re-read only on ReloadAllowList()
//
p2pcng::IdResult
P2PeerHub::SetAllowList ( const char *pszAllowListFileUtf8 )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> SetAllowList ( pszAllowListFileUtf8 );
}

//
//  Re-read the allow-list from disk
//  NOTES: Valid on a running hub - this is the deliberate exception to
//         "configure before spawn", so adding a peer is not a restart.
//         The new list is built to the side and swapped in only if it
//         parses, so a bad edit leaves the hub on the list it already
//         validated
//
p2pcng::IdResult
P2PeerHub::ReloadAllowList ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> ReloadAllowList ( );
}

//
//  Load the keys this hub must no longer honour
//  NOTES: Overrides the allow-list. A revoked point is refused at login
//         and refused as a seal target, whichever of the two key kinds
//         it is and whatever the allow-list still says about it
//       : FAIL CLOSED. Once this is configured, a load that fails does
//         not fall back to "nothing is revoked" - every verification
//         refuses until a reload succeeds. Refer P2PAuthLogin.h
//       : IdErrRevoked means THIS hub's own key is on the list. The
//         list is loaded and in force; the error says do not start
//
p2pcng::IdResult
P2PeerHub::SetRevocationList ( const char *pszRevocationFileUtf8 )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> SetRevocationList ( pszRevocationFileUtf8 );
}

//
//  Re-read the revocation list from disk
//  NOTES: Valid on a running hub, and the call that makes revocation
//         useful: withdrawing a key is an edit plus this, not a restart
//       : Unlike ReloadAllowList, a bad edit here does NOT leave the
//         previous list running. The old list cannot be assumed intact
//         when the file it came from has just failed to parse, and the
//         safe reading of a broken deny-list is never "deny nothing"
//
p2pcng::IdResult
P2PeerHub::ReloadRevocationList ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> ReloadRevocationList ( );
}

//
//  Is revocation in a usable state
//  NOTES: false only in the fail-closed state - a list was configured
//         and the most recent load of it failed. True when no list is
//         configured at all, which is a valid deployment
//
bool
P2PeerHub::IsRevocationUsable ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return false;
    return m_pAuthPolicy -> IsRevocationUsable ( );
}

//
//  Is a revocation list configured on this hub at all
//  NOTES: Not the same question as IsRevocationUsable(), which answers TRUE
//         for a hub that has never been given a list - correctly, because
//         what it means is "revocation is not refusing anything". Reporting
//         that as "a list is loaded" is how a snapshot would tell an operator
//         with no revocation at all that their revocation was fine
//       : Found by the F-S6-2 gate test printing a 1 out of an unconfigured
//         hub, which is the second time in this tree that writing the reader
//         corrected the thing being read
//
bool
P2PeerHub::IsRevocationConfigured ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsRevocationConfigured ( ) : false;
}

//
//  The whole posture in one non-blocking read
//  NOTES: F-S6-2, and refer P2PeerHub.h for the lock order
//         this exists to stay out of. TryEnterCriticalSection, never Enter:
//         Serialise() runs with the two process-wide pump/hub statics already
//         held, and the login path takes them in the opposite order behind
//         this same section, so a WAIT here would be the closing edge of a
//         cycle. A snapshot must not be able to stop the hub it describes
//       : Returns false having written nothing when the section is busy. The
//         caller says so in the snapshot; it does not substitute defaults,
//         because "off" and "could not read" are different answers and only
//         one of them is safe to act on
//       : A hub with no policy object reports OFF rather than unreadable. That
//         state is reachable only if the constructor's allocation failed, and
//         a hub with no policy verifies nothing - so "off" is the true
//         description of it, exactly as it is in the accessors above
//
bool
P2PeerHub::TryReadPosture ( Posture& rOut )
{
    if ( !TryEnterCriticalSection ( &m_oCSectionHub ) )
      return false;

    if ( !m_pAuthPolicy )
    {
      rOut.bAuthRequired    = false;
      rOut.bAuthCanSign     = false;
      rOut.nAuthArm         = (int)p2pauth::ArmNotRequired;
      rOut.bRelayAuth       = false;
      rOut.bRelayReplay     = false;
      rOut.bSealReplay      = false;
      rOut.bSealRequired    = false;
      rOut.bSealBcast       = false;
      rOut.bWaiveE2E        = false;
      rOut.bSealCanOpen     = false;
      rOut.bRevocRequired   = false;
      rOut.bRevocConfigured = false;
      rOut.bRevocOk         = true;
      rOut.bRevocFresh      = true;
      rOut.llRevocEpoch     = 0;
      rOut.anLinkPolicy[0]  = (int)P2PeerLinkPolicy_Full;
      rOut.anLinkPolicy[1]  = (int)P2PeerLinkPolicy_Full;
      rOut.anLinkPolicy[2]  = (int)P2PeerLinkPolicy_Full;
      rOut.nTrustFloor      = (int)P2PeerConTrust_Wire;
    }
    else
    {
      rOut.bAuthRequired    = m_pAuthPolicy -> IsRequired ( );
      rOut.bAuthCanSign     = m_pAuthPolicy -> CanSign ( );
      rOut.nAuthArm         = (int)m_pAuthPolicy -> Arm ( );
      rOut.bRelayAuth       = m_pAuthPolicy -> IsRelayRequired ( );
      rOut.bRelayReplay     = m_pAuthPolicy -> IsRelayReplayRefused ( );
      rOut.bSealReplay      = m_pAuthPolicy -> IsSealReplayRefused ( );
      rOut.bSealRequired    = m_pAuthPolicy -> IsSealRequired ( );
      rOut.bSealBcast       = m_pAuthPolicy -> IsSealBroadcastRequired ( );
      rOut.bWaiveE2E        = m_pAuthPolicy -> IsEndToEndWaivedInProcess ( );
      rOut.bSealCanOpen     = m_pAuthPolicy -> CanOpen ( );
      rOut.bRevocRequired   = m_pAuthPolicy -> IsRevocationRequired ( );
      rOut.bRevocConfigured = m_pAuthPolicy -> IsRevocationConfigured ( );
      rOut.bRevocOk         = m_pAuthPolicy -> IsRevocationUsable ( );
      rOut.bRevocFresh      = m_pAuthPolicy -> IsRevocationFresh ( );
      rOut.llRevocEpoch     = m_pAuthPolicy -> RevocationEpoch ( );
      //  Read from the live policy like everything else here, and NOT from a
      //  copy the setters refresh - refer the note on TryReadPosture in the
      //  header. A posture that could disagree with the gate is the defect
      //  this whole accessor exists to close
      rOut.anLinkPolicy[0]  = m_pAuthPolicy -> GetLinkPolicy ( 0 );
      rOut.anLinkPolicy[1]  = m_pAuthPolicy -> GetLinkPolicy ( 1 );
      rOut.anLinkPolicy[2]  = m_pAuthPolicy -> GetLinkPolicy ( 2 );
      rOut.nTrustFloor      = m_pAuthPolicy -> GetTrustFloor ( );
    }

    LeaveCriticalSection ( &m_oCSectionHub );
    return true;
}

//
//  Name the one key whose signature this hub believes on a revocation list
//  NOTES: NOT an allow-list entry. Being able to speak on the network and
//         being able to withdraw trust from the whole mesh are different
//         powers, and a compromised routing peer must not gain the second
//       : Null clears it, which turns distribution off and leaves the
//         local file as the only source
//       : IdErrRevoked if the point is actually on this hub's list - a
//         revoked key is not a candidate for the authority. Still allowed
//         while the list is unusable or stale, which is when an operator
//         most needs to rotate - refer P2PAuthLogin.h
//
p2pcng::IdResult
P2PeerHub::SetRevocationAuthority ( const unsigned char *pIssuerPub )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> SetRevocationAuthority ( pIssuerPub );
}

bool
P2PeerHub::HasRevocationAuthority ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> HasRevocationAuthority ( ) : false;
}

//
//  Sign this hub's current revocation list for publication
//  NOTES: Signed with this hub's IDENTITY key, so it is accepted only by
//         peers that named this hub's point as their authority
//       : llEpoch of 0 uses the entry count, which is monotonic for as
//         long as the list only grows - the only way it should change.
//         Refer P2PAuthLogin.h for why this is not taken from the clock
//       : pOut needs p2pauth::RevListLen(entries) bytes
//
p2pauth::RevResult
P2PeerHub::IssueRevocationList ( long long llEpoch,
                                 unsigned char *pOut, size_t cbOut,
                                 size_t *pcbOut )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::RevErrArgs;
    return m_pAuthPolicy -> IssueRevocationList ( llEpoch, pOut, cbOut, pcbOut );
}

//
//  Verify a received revocation list and merge it in
//  NOTES: UNION only. Nothing a received list says can un-revoke a key,
//         which is what makes a stale or rolled-back list harmless
//       : Additions are appended to the revocation FILE as well, so they
//         survive a restart. No file configured is a refusal, not an
//         accept-and-forget
//       : A list that revokes this hub's own authority is applied, and
//         then clears the authority - refer P2PAuthLogin.h
//
p2pauth::RevResult
P2PeerHub::ApplyRevocationList ( const unsigned char *pIn, size_t cbIn,
                                 size_t *pnAdded )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::RevErrArgs;
    return m_pAuthPolicy -> ApplyRevocationList ( pIn, cbIn, pnAdded );
}

long long
P2PeerHub::RevocationEpoch ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> RevocationEpoch ( ) : 0;
}

//
//  How stale the last applied list may get before this hub refuses
//  NOTES: 0 (the default) never expires. Expiring on silence converts a
//         partition into a total refusal, which is a better attack than
//         most of what revocation defends against - refer P2PAuthLogin.h
//       : With an authority configured and no list yet applied the hub
//         counts as stale, so this also means "refuse until the first
//         list arrives"
//
void
P2PeerHub::SetMaxRevocationStaleness ( int nSeconds )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetMaxRevocationStaleness ( nSeconds );
}

bool
P2PeerHub::IsRevocationFresh ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsRevocationFresh ( ) : false;
}

//
//  Freshness window, seconds either side of this hub's clock
//  NOTES: 0 disables the check for peers with no clock, and degrades
//         replay protection to the capacity of the nonce cache. Refer
//         P2PAuthLogin.h
//
void
P2PeerHub::SetAuthWindow ( int nSeconds )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetWindow ( nSeconds );
}

//
//  Require a proven identity at login
//  NOTES: Hub scope with no per-connection override, in either
//         direction. It is the one setting that must not be losable
//
void
P2PeerHub::RequireAuth ( bool bRequire )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetRequired ( bRequire );
}

bool
P2PeerHub::IsAuthRequired ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsRequired ( ) : false;
}

bool
P2PeerHub::CanAuthSign ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> CanSign ( ) : false;
}

//
//  What a link of the given trust class must do
//  NOTES: Hub scope and configure-before-arm, like RequireAuth and for the
//         same reason. Refer the block on the declaration for why a per-class
//         policy is not the per-connection override SECURITY.md refuses, and
//         why P2PeerConTrust_Wire cannot be opened here
//       : The refusal of the wire class lives in AuthPolicy::SetLinkPolicy,
//         one layer down, so it applies to this call and to the flat C entry
//         point without either of them having to remember it
//
void
P2PeerHub::SetLinkPolicy ( P2PeerConTrust_e   eClass
                         , P2PeerLinkPolicy_e ePolicy )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy )
      m_pAuthPolicy -> SetLinkPolicy ( (int)eClass, (int)ePolicy );
}

//
//  ...and what it is now
//  NOTES: A hub with no policy object answers Full. That state is reachable
//         only if the constructor's allocation failed, and a hub that cannot
//         hold a policy must not be the one that says a link may skip the
//         handshake - the same fail-closed reading IsAuthRequired() gives
//
P2PeerLinkPolicy_e
P2PeerHub::GetLinkPolicy ( P2PeerConTrust_e eClass )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy )
      return P2PeerLinkPolicy_Full;
    return m_pAuthPolicy -> GetLinkPolicy ( (int)eClass ) == 0
             ? P2PeerLinkPolicy_Full
             : P2PeerLinkPolicy_Open;
}

//
//  The lowest link class this hub will hold
//  NOTES: Hub scope and configure-before-arm, like RequireAuth and
//         SetLinkPolicy, and it is the other half of the second of those.
//         Refer the block on the declaration
//       : Kept on the policy object rather than in a member here, so the one
//         thing that reads it at arm time - AuthPolicy::Arm(), deciding
//         ArmNotRequiredByPolicy - reads the same byte PostP2PeerCon refuses
//         on.  A hub-side copy would be one forgotten line away from an
//         arming decision made against a fence the gate does not have
//
void
P2PeerHub::RequireTrustAtLeast ( P2PeerConTrust_e eClass )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy )
      m_pAuthPolicy -> SetTrustFloor ( (int)eClass );
}

//
//  ...and what it is now
//  NOTES: A hub with no policy object answers Wire - no fence.  That state is
//         reachable only if the constructor's allocation failed, and it is the
//         reading that changes nothing: a hub which cannot hold a policy must
//         not be the one that starts refusing connections nobody asked it to
//         refuse.  It is the opposite direction from GetLinkPolicy's
//         fail-closed answer, and deliberately so - there, the strict reading
//         DEMANDS a handshake; here, the strict reading would REFUSE a link
//         the operator never fenced out
//
P2PeerConTrust_e
P2PeerHub::GetRequiredTrust ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy )
      return P2PeerConTrust_Wire;
    const int nFloor = m_pAuthPolicy -> GetTrustFloor ( );
    return ( nFloor >= (int)P2PeerConTrust_InProcess ) ? P2PeerConTrust_InProcess
         : ( nFloor >= (int)P2PeerConTrust_Local     ) ? P2PeerConTrust_Local
         :                                               P2PeerConTrust_Wire;
}

//
//  Can this hub enforce what it is set to require?
//  NOTES: Stage 3 step 8. Pure query - CreateHub() and
//         SpawnHub() consult it, and so may the caller.
//       : No policy object at all reports ArmNotRequired rather than a
//         failure. That state is reachable only if the allocation in the
//         constructor failed, and a hub with no policy verifies nothing, so
//         "not required" is the true description of it - not a lie that
//         hides a missing file.
//
p2pauth::ArmResult
P2PeerHub::AuthArm ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> Arm ( ) : p2pauth::ArmNotRequired;
}

const char *
P2PeerHub::AuthAllowListPath ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> AllowListPath ( ) : 0;
}

const char *
P2PeerHub::AuthRevocationListPath ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> RevocationListPath ( ) : 0;
}

//
//  First-run provisioning: make this hub an identity and tell the operator
//  what to publish
//  NOTES: Stage 3 step 8. The whole point of the step is
//         that RequireAuth is on by default, so the FIRST thing a new
//         deployment meets is a refusal to arm. This is the answer to it,
//         and it is one call rather than a page of P2PIdentityStore.
//       : The .pub file is written every run, not only on the run that
//         created the key. It is derived, it is public, and an operator who
//         deleted it should get it back by starting the hub - not by
//         learning which API regenerates it.
//       : Does not create the allow-list, and does not call RequireAuth.
//         Both would be this function deciding a trust question on the
//         operator's behalf; see the header.
//
p2pcng::IdResult
P2PeerHub::ProvisionAuth ( const char *pszIdentityFileUtf8
                         , char       *pszFingerprintOut
                         , size_t      cchFingerprintOut
                         , bool       *pbCreated
                         , p2pcng::IdProtection eProtect )
{
    if ( !pszIdentityFileUtf8 || !*pszIdentityFileUtf8 )
      return p2pcng::IdErrArgs;
    if ( pszFingerprintOut && cchFingerprintOut < p2pcng::kIdFingerprintLen )
      return p2pcng::IdErrArgs;

    //  SetIdentity(create) does the load-or-create and takes the hub lock, so
    //  the policy holds the key before anything below reads it back out.
    p2pcng::IdResult eResult = SetIdentity ( pszIdentityFileUtf8, true, eProtect );
    if ( eResult != p2pcng::IdOk )
      return eResult;

    //  Whether THIS run generated it. LoadOrCreateIdentity reports that, but
    //  it is behind SetIdentity, so it is recovered here from the .pub file
    //  not existing yet - which is the same question an operator is asking
    //  ("is this a new key I have to go and publish?").
    p2pcng::EcdsaP256 oKey;
    eResult = p2pcng::LoadIdentity ( pszIdentityFileUtf8, oKey );
    if ( eResult != p2pcng::IdOk )
      return eResult;

    std::string strPub ( pszIdentityFileUtf8 );
                strPub += ".pub";

    if ( pbCreated )
    {
      p2pcng::EcdsaP256 oExisting;
      *pbCreated = ( p2pcng::LoadPublicKey ( strPub.c_str ( ), oExisting )
                       != p2pcng::IdOk );
    }

    eResult = p2pcng::SavePublicKey ( strPub.c_str ( ), oKey );
    if ( eResult != p2pcng::IdOk )
      return eResult;

    if ( pszFingerprintOut )
    {
      unsigned char aPub[p2pcng::kEcdsaPubLen];
      if ( !oKey.ExportPublic ( aPub ) ||
           !p2pcng::Fingerprint ( aPub, pszFingerprintOut ) )
        return p2pcng::IdErrKey;
    }

    return p2pcng::IdOk;
}

//
//  Refuse to arm a hub that requires auth and cannot enforce it
//  NOTES: Stage 3 step 8, and the reason the default flip
//         is a protection rather than an outage. Shared by CreateHub() and
//         SpawnHub() so the two cannot drift on what "provisioned" means -
//         which they would, because SpawnHub is the one everybody uses and
//         CreateHub is the one the tests use.
//       : Reports through the P2Pevent channel and CANCELS rather than
//         throwing. The caller gets FALSE/0 back and can say what it likes;
//         an exception out of CreateHub would be a second breaking change
//         riding on the first.
//       : Names the allow-list PATH when there is one. "Not configured" is
//         a diagnostic the operator has to go and decode; "P2Peers.allow
//         could not be read" is one they can act on.
//       : BOTH strings are length-capped, and that is a correctness
//         requirement rather than tidiness. P2Pevent::Message and ::Advice
//         each VERIFY the FORMATTED text is under 255 characters
//         (Msgcore/Msgexception.cpp). Over it, a Debug build aborts and a
//         Release build says nothing - so an over-long refusal would kill the
//         process it exists to explain, and would do it only in Debug. A path
//         is up to MAX_PATH on its own, so it is trimmed from the LEFT: the
//         directory is what an operator can infer, the file name is not.
//
bool
P2PeerHub::AuthArmOrRefuse ( LPCTSTR lpszCaller )
{
    p2pauth::ArmResult eArm = AuthArm ( );
    //  THREE results arm, and the third is the one that looks least like the
    //  other two.  ArmNotRequiredByPolicy is a hub that requires auth, holds
    //  no identity, and has fenced and opened every class it will carry - so
    //  there is no link on it that a signature could be demanded of.  Refer
    //  the note at ArmNotRequiredByPolicy for why that passes the same test
    //  ArmNotRequired passes; it is admitted HERE, beside it, so the two
    //  answers cannot drift apart.
    if ( eArm == p2pauth::ArmOk               ||
         eArm == p2pauth::ArmNotRequired      ||
         eArm == p2pauth::ArmNotRequiredByPolicy )
    {
      //  WHAT STANDS IN FOR AN ARMING GATE ON SEALING, and it is a warning
      //  rather than a refusal on purpose - refer the note at the end of
      //  p2pauth::ArmResult. A hub that requires sealing and holds no
      //  agreement key still starts, still logs peers in and still talks to
      //  its direct peers; what it cannot do is open a body addressed to it,
      //  and a relay is entitled to be in exactly that state.
      //
      //  Once, at arm time, through SetLast() like the other three - so the
      //  operator who would rather not learn this from the first relayed
      //  message does not have to.
      if ( IsSealRequired ( ) && !CanOpen ( ) )
        EVWRN->Module (__FUNCTION__)
             ->Message(_T("P2PeerHub(%s) requires sealing and holds no agreement key")
                      , m_oP2PaddrHub.c_wstr ( ) )
             ->Advice_T ("It cannot open a body sealed to it. "
                         "SetAgreementKey(path,true), or RequireSeal(false)")
             ->Display()->SetLast();
      return true;
    }

    const char *pszWhy  = p2pauth::AuthArmText   ( eArm );

    //  WHICH FILE THE REFUSAL NAMES DEPENDS ON WHICH ONE IT IS ABOUT, and
    //  until 2026-08-21 there was only one candidate so this was a constant.
    //  Naming the allow-list at a hub whose REVOCATION list is the problem
    //  would be worse than naming nothing: it sends the operator to a file
    //  that is fine, and the two live in the same directory with similar
    //  names.
    const bool  bRevoc  = ( eArm == p2pauth::ArmNoRevocation
                         || eArm == p2pauth::ArmRevocationUnusable );
    const char *pszPath = bRevoc ? AuthRevocationListPath ( )
                                 : AuthAllowListPath ( );
    const char *pszWhich = bRevoc ? "  Revocation list: " : "  Allow-list: ";

    //  ADVICE IS PER-RESULT FOR THE SAME REASON, and it is length-capped
    //  harder than it looks: the formatted Advice already runs to ~238 of its
    //  255 characters with a trimmed path on the end, so a second sentence
    //  cannot simply be appended to the first. Each of these is written to
    //  fit WITH the path, not without it.
    const char *pszAdvice =
        ( eArm == p2pauth::ArmNoRevocation )
            ? "No revocation list, so no key could ever be withdrawn. "
              "Name one, or RequireRevocation(false)."
      : ( eArm == p2pauth::ArmRevocationUnusable )
            ? "A configured revocation list that will not load refuses "
              "EVERY peer. Restore it, or unset it."
      :       "Auth is required by default (Stage 3 step 8). "
              "Provision this hub, or RequireAuth(false) and mean it.";

    //  Keep the tail: "...\p2p\P2Peers.allow" identifies the file, and the
    //  leading directories are the part the operator already knows.
    const size_t kPathRoom = 120;
    char  szPath[kPathRoom + 8] = { 0 };
    if ( pszPath )
    {
      size_t cb = std::strlen ( pszPath );
      if ( cb <= kPathRoom )
        std::strcpy ( szPath, pszPath );
      else
      {
        std::strcpy ( szPath, "..." );
        std::strcat ( szPath, pszPath + ( cb - kPathRoom ) );
      }
    }

    EVERR->Module ( lpszCaller )
         ->Message(_T("P2PeerHub(%s) will not arm: %hs")
                  , m_oP2PaddrHub.c_wstr ( ), pszWhy )
         ->Advice (_T("%hs%hs%hs")
                  , pszAdvice
                  , pszPath ? pszWhich : ""
                  , pszPath ? szPath   : "" )
         ->Cancel ( );
    return false;
}

//
//  Require origin attestation on a downward relay
//  NOTES: Hub scope, like RequireAuth, and for the same reason - it is the
//         one thing that must not be losable per connection
//       : Configure before SpawnHub()/CreateHub().  It is read on the IO
//         thread under this critical section, so a late change is not
//         unsafe; it is just a policy that some messages saw and some did
//         not, which is not a state worth being able to reach
//
void
P2PeerHub::RequireRelayAuth ( bool bRequire )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetRelayRequired ( bRequire );
}

bool
P2PeerHub::IsRelayAuthRequired ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsRelayRequired ( ) : false;
}

//
//  Require a revocation POSITION before arming
//  NOTES: Hub scope and configure-before-arm, like RequireAuth and for the
//         same reason - see RequireRevocation in the header, and
//         p2pauth::ArmResult for why this is a gate at all when the state it
//         refuses is a working one.
//
void
P2PeerHub::RequireRevocation ( bool bRequire )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetRevocationRequired ( bRequire );
}

bool
P2PeerHub::IsRevocationRequired ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsRevocationRequired ( ) : false;
}

//
//  Require an end-to-end seal on anything that will be relayed
//  NOTES: Hub scope and configure-before-arm, like RequireAuth.  Refer
//         RequireSeal in the header for the break and the migration, and
//         P2PeerCon::SealAppMsgOutbound for where the refusal happens
//
void
P2PeerHub::RequireSeal ( bool bRequire )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetSealRequired ( bRequire );
}

bool
P2PeerHub::IsSealRequired ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsSealRequired ( ) : false;
}

//
//  Does the seal requirement extend to broadcasts
//  NOTES: Hub scope and configure-before-arm, like RequireSeal.  Refer
//         RequireSealBroadcast in the header for what the exemption does and
//         does not cover, and P2PeerCon::SealAppMsgOutbound for where it is
//         applied
//
void
P2PeerHub::RequireSealBroadcast ( bool bRequire )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetSealBroadcastRequired ( bRequire );
}

bool
P2PeerHub::IsSealBroadcastRequired ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsSealBroadcastRequired ( ) : false;
}

//
//  Waive the two end-to-end protections for an in-process destination
//  NOTES: Hub scope and configure-before-arm, like RequireSeal.  Refer
//         WaiveEndToEndInProcess in the header for the assumption, the A-B-C
//         failure mode and what it is worth, and P2PeerCon::SealAppMsgOutbound
//         / AttestAppMsgOutbound / GateRelayInbound for the three places it is
//         applied
//       : This setter takes the HUB lock and nothing else.  The registry
//         lookup that keys the waiver takes the PROCESS hub lock, and the two
//         are never held together - P2PeerCon reads this accessor, lets the
//         lock go, and only then asks IsP2PmsgHubInProcess.  Refer the note on
//         the declaration in P2Pwin32.h
//
void
P2PeerHub::WaiveEndToEndInProcess ( bool bWaive )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetEndToEndWaivedInProcess ( bWaive );
}

//
//  ...and is it waived
//  NOTES: A hub with no policy object answers FALSE, which is the fail-closed
//         reading here: FALSE keeps the protections ON.  Every other accessor
//         in this file fails closed by refusing something; this one does it by
//         declining to waive
//
bool
P2PeerHub::IsEndToEndWaivedInProcess ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsEndToEndWaivedInProcess ( )
                         : false;
}

p2pcng::IdResult
P2PeerHub::AddSealReader ( const wchar_t *pAddr )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> AddSealReader ( pAddr );
}

void
P2PeerHub::ClearSealReaders ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> ClearSealReaders ( );
}

//
//  Refuse a relay attestation this hub has already accepted
//  NOTES: Hub scope, like the two above, and for the same reason - the cache
//         it arms is the hub's, so a per-connection override would mean a
//         connection that does not refuse replays populating a cache that
//         another one trusts
//
void
P2PeerHub::RefuseRelayReplay ( bool bRefuse )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetRelayReplayRefused ( bRefuse );
}

bool
P2PeerHub::IsRelayReplayRefused ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsRelayReplayRefused ( ) : false;
}

//
//  Refuse a sealed body this hub has already opened
//  NOTES: Weaker than the relay refusal above - a sealed body carries no
//         timestamp, so its cache cannot expire entries and is bounded by
//         count instead
//
void
P2PeerHub::RefuseSealReplay ( bool bRefuse )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetSealReplayRefused ( bRefuse );
}

bool
P2PeerHub::IsSealReplayRefused ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> IsSealReplayRefused ( ) : false;
}

//
//  How old a sealed body may be before it is refused
//  NOTES: Stage 3 step 10. See P2PeerHub.h.
//
void
P2PeerHub::SetSealWindow ( int nSeconds )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( m_pAuthPolicy ) m_pAuthPolicy -> SetSealWindow ( nSeconds );
}

int
P2PeerHub::GetSealWindow ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> GetSealWindow ( ) : 0;
}

//
//  Sign this message as its origin
//  NOTES: pAttester is this hub's own address.  The identity key signs, so
//         the far end must list THAT address against THAT key
//
p2pauth::AuthResult
P2PeerHub::AttestRelay ( const wchar_t *pAttester
                       , const wchar_t *pSrc, const wchar_t *pDst
                       , const wchar_t *pMsgName
                       , const void *pBody, size_t cbBody
                       , unsigned char *pOut, size_t cbOut, size_t *pcbOut )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::AuthErrInternal;
    return m_pAuthPolicy -> BuildRelay ( pAttester, pSrc, pDst, pMsgName
                                       , pBody, cbBody, pOut, cbOut, pcbOut );
}

//
//  Verify an attestation and report who made it
//  NOTES: Says WHO signed, never whether that identity may speak for the
//         source.  That is an address-tree question and the caller
//         (P2PeerCon::GateAppMsgInbound) is what owns it - refer
//         p2pauth::AuthPolicy::VerifyRelay for why the two are split
//
p2pauth::AuthResult
P2PeerHub::VerifyRelay ( const wchar_t *pSrc, const wchar_t *pDst
                       , const wchar_t *pMsgName
                       , const void *pBody, size_t cbBody
                       , const unsigned char *pIn, size_t cbIn
                       , wchar_t *pAttesterOut, size_t cchAttesterOut
                       , long *pnSkewOut )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::AuthErrInternal;
    return m_pAuthPolicy -> VerifyRelay ( pSrc, pDst, pMsgName, pBody, cbBody
                                        , pIn, cbIn
                                        , pAttesterOut, cchAttesterOut
                                        , pnSkewOut );
}

///////////////////////////////////////////////////////////////////////
//  Peer login authentication - handshake internals
//  NOTES: Called from P2PeerCon on the IO and pump threads

p2pauth::AuthResult
P2PeerHub::AuthBuildLogin ( const wchar_t *pSrc, const wchar_t *pDst
                          , unsigned char *pOut, size_t cbOut
                          , unsigned char *pNonceOut
                          , const unsigned char *pBind )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::AuthErrInternal;
    return m_pAuthPolicy -> BuildLogin ( pSrc, pDst, pOut, cbOut, pNonceOut
                                       , pBind );
}

p2pauth::AuthResult
P2PeerHub::AuthVerifyLogin ( const wchar_t *pSrc, const wchar_t *pDst
                           , const unsigned char *pIn, size_t cbIn
                           , unsigned char *pNonceOut, long *pnSkewOut
                           , const unsigned char *pBind )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::AuthErrInternal;
    return m_pAuthPolicy -> VerifyLogin ( pSrc, pDst, pIn, cbIn
                                        , pNonceOut, pnSkewOut, pBind );
}

p2pauth::AuthResult
P2PeerHub::AuthBuildAck ( const wchar_t *pSrc, const wchar_t *pDst
                        , const unsigned char *pNonce
                        , unsigned char *pOut, size_t cbOut
                        , const unsigned char *pBind )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::AuthErrInternal;
    return m_pAuthPolicy -> BuildAck ( pSrc, pDst, pNonce, pOut, cbOut, pBind );
}

p2pauth::AuthResult
P2PeerHub::AuthVerifyAck ( const wchar_t *pSrc, const wchar_t *pDst
                         , const unsigned char *pNonce
                         , const unsigned char *pIn, size_t cbIn
                         , const unsigned char *pBind )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pauth::AuthErrInternal;
    return m_pAuthPolicy -> VerifyAck ( pSrc, pDst, pNonce, pIn, cbIn, pBind );
}

//
//  Load (or create) this hub's static agreement key
//  NOTES: The half other peers seal TO. Deliberately a different key and a
//         different file from the identity - refer P2PIdentityStore.h for
//         why one key must not do both jobs
//
p2pcng::IdResult
P2PeerHub::SetAgreementKey ( const char *pszAgreementFileUtf8
                           , bool bCreateIfAbsent
                           , p2pcng::IdProtection eProtect )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pcng::IdErrArgs;
    return m_pAuthPolicy -> SetAgreement ( pszAgreementFileUtf8
                                         , bCreateIfAbsent, eProtect );
}

bool
P2PeerHub::CanSeal ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> CanSeal ( ) : false;
}

bool
P2PeerHub::CanOpen ( )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> CanOpen ( ) : false;
}

bool
P2PeerHub::GetAgreementPublic ( unsigned char *pOut )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    return m_pAuthPolicy ? m_pAuthPolicy -> GetAgreementPublic ( pOut ) : false;
}

//
//  Seal a body to pDst, so no hub on the path can read it
//  NOTES: The destination's agreement key is looked up in the allow-list.
//         A destination that has published none is a REFUSAL - there is no
//         path here that quietly sends the body in clear instead
//
p2pseal::SealResult
P2PeerHub::SealFor ( const wchar_t *pSrc, const wchar_t *pDst
                   , const void *pPlain, size_t cbPlain
                   , unsigned char *pOut, size_t cbOut, size_t *pcbOut )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pseal::SealErrInternal;
    return m_pAuthPolicy -> Seal ( pSrc, pDst, pPlain, cbPlain
                                 , pOut, cbOut, pcbOut );
}

//
//  Open a body sealed to this hub by pSrc
//  NOTES: Which signature is demanded follows from the address the message
//         DECLARES, checked before any of the body is believed
//
p2pseal::SealResult
P2PeerHub::OpenFrom ( const wchar_t *pSrc, const wchar_t *pDst
                    , const unsigned char *pIn, size_t cbIn
                    , void *pOut, size_t cbOut, size_t *pcbOut )
{
    P2PsafeCS oSafeCS = m_oCSectionHub;
    if ( !m_pAuthPolicy ) return p2pseal::SealErrInternal;
    return m_pAuthPolicy -> Open ( pSrc, pDst, pIn, cbIn, pOut, cbOut, pcbOut );
}
