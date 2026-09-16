// Copyright © 2011, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerExplorer definitions and prototypes
//  NOTES: Network is built upon the local and remote exchange of
//         P2PeerMsg's between objects derived from this base class
//       : Only P2PeerExplorer derived network objects may be assigned
//         network P2Paddress's

#include "stdafx.h"
//#include "P2PTL.h"
#include "Kernel32_Ext.h"
#include "P2PeerExplorer.h"
#include "P2Pwin32.h"
#include "Msgexception.h"

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

//
//  Constructors and destructor
//
//  Parameters:  P2PeerHub *pHub
//               Hub to which this P2PeerExplorer is attached
//               NOTES: P2PeerHub's only support single P2PeerExplorer
//                      instance is assigned
//
P2PeerExplorer::P2PeerExplorer ( P2PeerHub *pHub )
{
    // Firstly
    RenderExplorerSafe ( );
    m_pHub = pHub;
}

P2PeerExplorer::~P2PeerExplorer ( )
{
    // Closure
    // NOTES: RegisterP2Pexpump() and CloseP2Pexpump() are BOTH keyed on
    //        GetCurrentThreadId() and are only legal from the expump's own
    //        context - RegisterP2Pexpump() THROWS from anywhere else
    //        (P2Pwin32.cpp:1117-1133).  A P2PeerExpump is deleted by whoever
    //        owns it, which is the hub owner's thread (P2PeerHub::CloseHub ->
    //        DropP2PeerExpump), never the expump thread, so calling them here
    //        unconditionally threw a P2Pevent out of a destructor on every
    //        single teardown - measured: p2p_expreg reached its verdict and
    //        then hung in shutdown until the ctest timeout.  The throw escaped
    //        DropP2PeerExpump() mid-CloseHub() and, because that nulled the
    //        member only AFTER delete returned, also left m_pP2PeerExpump
    //        dangling on freed storage for ~P2PeerHub (P2PeerHub.cpp:99-107)
    //        to delete a second time.
    //      : So: from a foreign thread, signal the expump down and wait - its
    //        own ProcExpump() performs the de-registration and CloseP2Pexpump()
    //        in the only context where they are meaningful.  From the expump's
    //        own context (an expump destroying itself), do it directly.
    //      : Nothing here may throw.  A destructor that throws during unwinding
    //        terminates the process.
    //  F-S5-4.  Decide whose thread we are on ONCE, here, from the id as it
    //  stands before anything below can zero it.  ProcExpump() stores 0 into
    //  m_nExpumpID as its own last act, so re-reading the member further down
    //  would report "not the expump thread" for an expump destroying itself,
    //  and the handle wait below would be a self-join that never returns.
    const DWORD nExpumpIDatEntry = (DWORD)m_nExpumpID;
    const bool  bExpumpContext   = nExpumpIDatEntry > 0 &&
                                   nExpumpIDatEntry == GetCurrentThreadId();
    try
    {
      DWORD nExpumpID = nExpumpIDatEntry;
      if ( nExpumpID > 0                        &&
           nExpumpID != GetCurrentThreadId()       )
      {
        if ( P2PmsgPumpExists(nExpumpID) )
          CloseExpump ( nExpumpID );
      }
      else if ( nExpumpID > 0 )
      {
        // De-registrations
        RegisterP2Pexpump ( P2PmsgExp_ALL, FALSE );
        CloseP2Pexpump ( );
      }
    }
    catch ( P2Pevent *pEVT )
    {
      pEVT->Advice(_T("~P2PeerExplorer: P2Pexpump closure"))->Cancel();
    }
    catch ( ... )
    {
    }

    // Resources
    // NOTES: Last, not first - the expump may still have been inside a
    //        P2PsafeCS on it until the wait above returned
    //      : F-S5-4 - give the thread handle back.  From a foreign thread the
    //        block above has already signalled the expump down and spun until
    //        it de-registered, but de-registration happens INSIDE ProcExpump()
    //        with the rest of its tail still to run, so "the pump no longer
    //        exists" is not "the thread has ended".  Wait for the thread
    //        itself before closing, or the close is a detach and everything
    //        the thread still holds stays unreachable and unfreed - which is
    //        precisely the 16 indirect allocations LSan hung off this handle.
    //        From the expump's OWN context (an expump destroying itself) that
    //        wait is a self-join, so close without waiting and let the shim
    //        detach; there is no second thread to keep anything alive.
    if ( m_hExpumpThread )
    {
      if ( !bExpumpContext )
        WaitForSingleObject ( m_hExpumpThread, INFINITE );
      CloseHandle ( m_hExpumpThread );
      m_hExpumpThread = 0;
    }
    DeleteCriticalSection ( &m_oCSectionExpump );
}

void
P2PeerExplorer::RenderExplorerSafe()
{
    // Attributes
    m_pHub      = 0;                   // Attached P2PeerHub
    m_nExpumpID = 0;                   // Dedicated explorer P2PumpID
    m_hExpumpThread = 0;               // F-S5-4: owned thread handle, if spawned
    m_nMaxECid  = 32;                  // XC%i exploration slots (was NEVER assigned:
                                       // it bounds the slot loops in On_XCidConLogin
                                       // and On_XCidConClose, so an unassigned value
                                       // means "no slots" or "four billion slots"
                                       // depending on what the allocator left behind)

    // Resources
    InitializeCriticalSection ( &m_oCSectionExpump );
}

P2PeerExpump*
P2PeerExpump::DynamicCreate ( P2PeerHub *pHub
                            , LPTHREAD_START_ROUTINE pfnThreadProc
                            , RUN_EXPUMP  pfnRunExpump )
{
    // To be sure, to be sure
    if ( pHub->GetP2PeerExpump() )
      EVERR->MODULE
           ->Message("P2PeerExpump already exists" )
           ->Throw();
    P2PeerExpSP spExpump = new P2PeerExpump ( pHub );
    spExpump -> SpawnExpump ( pfnThreadProc, pfnRunExpump );
    pHub -> PostP2PeerExpump ( spExpump.Dereference() );

    // Tidy up, and
    return dynamic_cast<P2PeerExpump *>(pHub->GetP2PeerExpump());
}

void
CMapStringToString_SetAtNC ( CMapADDR2ADDR *pCMap, P2PaddrSTR lpszSource )
{
    UNREFERENCED_PARAMETER(pCMap);
    CStringADDR strSource = lpszSource;
    CStringADDR strSOURCE = lpszSource;
                strSOURCE.MakeUpper ( );
    // NOTE: intended body is pCMap->SetAt(strSOURCE, strSource); it does not
    //       compile because CMapADDR2ADDR (CMap<CStringADDR,...>) has no
    //       HashKey<CStringADDR> specialisation. Left disabled until the map
    //       type provides one. No callers exist today.
    ASSERT(0);//pCMap -> SetAt ( strSOURCE, strSource );
}
BOOL
CMapStringToString_RemoveKeyNC ( CMapADDR2ADDR *pCMap, P2PaddrSTR lpszSource )
{
    UNREFERENCED_PARAMETER(pCMap);
    CStringADDR strSOURCE = lpszSource;
                strSOURCE.MakeUpper ( );
    // NOTE: see CMapStringToString_SetAtNC - blocked on a missing
    //       HashKey<CStringADDR> specialisation; no callers exist today.
    ASSERT(0);return FALSE;//return pCMap -> RemoveKey ( strSOURCE );
}

void
CListRegHubs_Insert ( CListRegHubs& oCListRegHubs
                    , const CStringADDR& strSource )
{
    SP2PexpRegHub oRegHub;
    oRegHub.strClient = strSource;
    oCListRegHubs.AddTail ( oRegHub );
}
void
CListRegHubs_Remove ( CListRegHubs& oCListRegHubs
                    , const CStringADDR& strSource )
{
    POSITION pos = oCListRegHubs.GetHeadPosition();
    while ( pos )
    {
      POSITION posDrop = pos;
      SP2PexpRegHub& oRegHub = oCListRegHubs.GetNext ( pos );
      if ( strSource.CompareNoCase(oRegHub.strClient) == 0 )
        oCListRegHubs.RemoveAt ( posDrop );
    }
}

void
CListRegPmps_Insert ( CListRegPmps& oCListRegPmps
                    , const CStringADDR& strSource, P2PumpID nPumpID )
{
    SP2PexpRegPmp oRegPmp;
    oRegPmp.nPumpID   = nPumpID;
    oRegPmp.strClient = strSource;
    oCListRegPmps.AddTail ( oRegPmp );
}
void
CListRegPmps_Remove ( CListRegPmps& oCListRegPmps
                    , const CStringADDR& strSource, P2PumpID nPumpID )
{
    POSITION pos = oCListRegPmps.GetHeadPosition();
    while ( pos )
    {
      POSITION posDrop = pos;
      SP2PexpRegPmp& oRegPmp = oCListRegPmps.GetNext ( pos );
      if ( ( nPumpID == 0               ||
             nPumpID == oRegPmp.nPumpID    ) &&
             strSource.CompareNoCase(oRegPmp.strClient) == 0 )
        oCListRegPmps.RemoveAt ( posDrop );
    }
}

void
CListRegCons_Insert ( CListRegCons& oCListRegCons
                    , const CStringADDR& strSource, P2PconID nConID )
{
    SP2PexpRegCon oRegCon;
    oRegCon.nConID    = nConID;
    oRegCon.strClient = strSource;
    oCListRegCons.AddTail ( oRegCon );
}
void
CListRegCons_Remove ( CListRegCons& oCListRegCons
                    , const CStringADDR& strSource, P2PconID nConID )
{
    POSITION pos = oCListRegCons.GetHeadPosition();
    while ( pos )
    {
      POSITION posDrop = pos;
      SP2PexpRegCon& oRegCon = oCListRegCons.GetNext ( pos );
      if ( ( nConID == 0              ||
             nConID == oRegCon.nConID    ) &&
             strSource.CompareNoCase(oRegCon.strClient) == 0 )
        oCListRegCons.RemoveAt ( posDrop );
    }
}

//
//  Binds a registration request to the P2Paddr this P2Pexplorer ASSIGNED to the
//  requesting connection
//  NOTES: On_XCidConLogin refuses any client-declared address and server-assigns
//         <hub>.XC%i, so a peer cannot choose its own identity.  It CAN, however,
//         claim a sub-identity of the slot it was given: the source-binding gate
//         (P2PeerCon::GateAppMsgInbound) admits the logged-in identity or an
//         IsRable() descendant of it, and IsRable() accepts any prefix ending on a
//         hop boundary.  Without this, CEX.XC0 registers CEX.XC0.Ghost and the
//         registry grows entries no connection owns (SECURITY_REVIEW M2).
//       : A source that matches no P2PeerCon is left untouched - local, in-process
//         registrants do not come through a connection and are not the subject.
//
static CStringADDR
P2PexpReg_BindSource ( P2PeerExplorer *pExplorer, P2PaddrSTR strSource )
{
    //  strBound, not strSource, from here on: the caller's pointer comes from
    //  P2PeerMsg::GetSource(), which on the UTF-16-store platforms points into
    //  a thread-local scratch ring that the c_wstr() calls in this very loop
    //  recycle (Platform/p2pstr.h:629-651, and see RouteP2PeerMsg below).  The
    //  copy is taken before the first of them
    CStringADDR strBound  = strSource;
    P2PsafeCS   oSafeCS   = pExplorer -> m_oCSectionExpump;
    P2PeerCon  *pConEnum  = 0;
    while ( EnumP2PexpCon(pExplorer->m_nExpumpID,&pConEnum) )
    {
      const P2Paddr& oP2PaddrCon = pConEnum -> GetP2Paddress();
      if ( oP2PaddrCon == strBound.GetString() )
        return strBound;                 // exactly the assigned slot
      if ( oP2PaddrCon.IsChild(strBound.GetString()) )
        return oP2PaddrCon.c_wstr();     // a fabricated sub-identity of it
    }
    return strBound;                     // not from a P2Pexplorer connection
}

//
//  Removes every registration routable through the passed P2Paddr
//  NOTES: The exact-match CListReg*_Remove() helpers above release the slot's own
//         entry only.  A connection dropping takes its whole sub-tree with it -
//         nothing under CEX.XC0 can outlive CEX.XC0, and the registry has no other
//         eviction path, so an entry missed here is permanent (SECURITY_REVIEW M2)
//
static void
CListRegHubs_RemoveRable ( CListRegHubs& oCListRegHubs, const P2Paddr& oP2Paddr )
{
    POSITION pos = oCListRegHubs.GetHeadPosition();
    while ( pos )
    {
      POSITION posDrop = pos;
      SP2PexpRegHub& oRegHub = oCListRegHubs.GetNext ( pos );
      if ( oP2Paddr.IsRable(oRegHub.strClient.GetString()) )
        oCListRegHubs.RemoveAt ( posDrop );
    }
}
static void
CListRegCons_RemoveRable ( CListRegCons& oCListRegCons, const P2Paddr& oP2Paddr )
{
    POSITION pos = oCListRegCons.GetHeadPosition();
    while ( pos )
    {
      POSITION posDrop = pos;
      SP2PexpRegCon& oRegCon = oCListRegCons.GetNext ( pos );
      if ( oP2Paddr.IsRable(oRegCon.strClient.GetString()) )
        oCListRegCons.RemoveAt ( posDrop );
    }
}
static void
CListRegPmps_RemoveRable ( CListRegPmps& oCListRegPmps, const P2Paddr& oP2Paddr )
{
    POSITION pos = oCListRegPmps.GetHeadPosition();
    while ( pos )
    {
      POSITION posDrop = pos;
      SP2PexpRegPmp& oRegPmp = oCListRegPmps.GetNext ( pos );
      if ( oP2Paddr.IsRable(oRegPmp.strClient.GetString()) )
        oCListRegPmps.RemoveAt ( posDrop );
    }
}

///////////////////////////////////////////////////////////////////////
//  P2Pexplorer management
//  NOTES: Started using default P2PeerExplorer::SpawnExp() or
//         CreateTarget() implementations

typedef struct
{
  P2PexpumpID    *pnExpumpID;
  P2PeerExplorer  *pExplorer;
  //P2Paddr          oP2Paddr;
  RUN_EXPUMP     pfnRunExpump;
} P2ProcContextExp;

//
//  Creates P2PmsgExp and commences pumping
//  NOTES: Thread processing may be stopped via CloseExp()
//
//
//  Parameters: LPTHREAD_START_ROUTINE pfnThreadProc
//              The thread procedure of the new thread.  Refer
//              win32 CreateThread() for further details
//
//              RUN_EXP pfnRunExp = 0
//              Operational method of the new thread
//
//              P2PexpID *pnExpID
//              Pointer to pump identification code.  Retained
//              and cleared upon P2PmsgExp closure.
//
//  Returns:    HANDLE
//              Returns the handle to the newly created thread
//              or NULL on failure.
//
HANDLE
P2PeerExplorer::SpawnExpump ( LPTHREAD_START_ROUTINE pfnThreadProc
                            , RUN_EXPUMP  pfnRunExpump )
{
    // Preparation
    if ( pfnThreadProc == NULL )
      pfnThreadProc = P2PeerExplorer::ProcExpump;
    if ( pfnRunExpump == NULL )
      pfnRunExpump = RUN_PUMP_cast(&P2PeerExplorer::RunExpump);
    ASSERT(pfnRunExpump);

    // Pass context through
    P2ProcContextExp oContext;
                     oContext.pnExpumpID   = &m_nExpumpID;
                     oContext.pExplorer    =   this;
                     oContext.pfnRunExpump =  pfnRunExpump;
    //  F-S5-4.  A re-spawn must not drop the previous handle on the floor.
    //  CloseExpump() leaves the explorer re-startable by design (see its
    //  header), so this is reachable and is where the second leak would be.
    if ( m_hExpumpThread )
    {
      CloseHandle ( m_hExpumpThread );
      m_hExpumpThread = 0;
    }
    HANDLE hThread = CreateThread ( 0, 0
                                  , pfnThreadProc, &oContext //pvParam
                                  , 0, &m_nExpumpID );
    if ( !hThread )
      return FALSE;

    // Confirm operation
    // NOTES: Contracted for P2PmsgPump operation upon return
    //      : F-S5-4 - every exit from here on gives the handle back, either to
    //        the explorer (success) or to the system (failure).  Returning 0
    //        while holding a live handle is how the failure paths leaked.
    DWORD dwExitCode;
    UINT  uSpins = 0;
    while ( !P2PmsgPumpExists(m_nExpumpID) )
    {
      if ( !GetExitCodeThread(hThread,&dwExitCode)                ||
                                       dwExitCode != STILL_ACTIVE    )
      {
        CloseHandle ( hThread );
        return 0;                      // Operational failure
      }
      YieldForP2PmsgPump ( uSpins );   // Yield (escalating - see header)
    }
    if ( !P2PmsgPumpExists(m_nExpumpID) )
    {
      CloseHandle ( hThread );
      return 0;
    }

    // Tidy up and
    // NOTES: The explorer keeps the handle - see m_hExpumpThread.  The value
    //        is still returned so existing callers keep compiling, but it is
    //        this object's to close and not the caller's.
    m_hExpumpThread = hThread;
    return hThread;
}

//
//  Closes or stops P2Pexplorer operation
//  NOTES: P2Pexplorer operation may be re-started via
//         P2PeerTarget::SpawnPump() or P2PeerTarget::CreatePump()
//
//  Parameters: P2PexpID nExpID
//              Identification code of P2Pexplorer to be closed
void
P2PeerExplorer::CloseExpump ( P2PexpumpID nExpumpID )
{
    // 
    if ( nExpumpID <= 0 )
      nExpumpID = m_nExpumpID;

    // Close and confirm
    SignalP2PmsgPump ( nExpumpID, P2PsigPump_CLOSE );
    UINT uSpins = 0;
    while ( P2PmsgPumpExists(nExpumpID) )
      YieldForP2PmsgPump ( uSpins );
}

//
//  Default thread starting address nominated in CreateThread()
//  NOTES: Provide alternative implementation to override default
//         action.  Follows P2PeerPump::ProcVanilla() base class pattern
//
//
//  Parameters:  void *pvContext
//               Thread data passed via CreateThread()
//
//  Returns:     DWORD
//               Completion code
//
DWORD WINAPI
P2PeerExplorer::ProcExpump ( void *pvContext )
{
    // Introduce locals
    // NOTES: P2PumpContext is assumed not to persist
    P2ProcContextExp *pContext   = static_cast<P2ProcContextExp *>(pvContext);
    P2PeerExplorer   *pExplorer  = pContext -> pExplorer;
    P2PexpumpID     *pnExpumpID  = pContext -> pnExpumpID;
    //P2PmsgHubID    nHubID   = pTarget  -> GetHubID ( );
    RUN_EXPUMP      pfnRunExpump = pContext -> pfnRunExpump;
    pExplorer -> AssertValid ( );

    // Mandatory P2PeerPump thread environment
    // NOTES: Sequence contains mandatory P2PeerPump and P2Pmsg
    //        life cycle management sequences
    //      : Guard the whole life cycle so no exception escapes the thread
    //        proc and terminates the process (matches P2PeerTarget::ProcPump /
    //        P2PeerHub::ProcHub).  RunExpump() self-guards its pump loop, but
    //        CreateP2Pexpump()/CloseP2Pexpump() run outside it.
    try
    {
      CreateP2Pexpump ( pExplorer->m_pHub->GetHubID(), pExplorer );
      (pExplorer->*pfnRunExpump) ( );
      if ( pnExpumpID && *pnExpumpID == GetCurrentThreadId() )
        *pnExpumpID = 0;                  // Flags pump closure
      CloseP2Pexpump ( );
    }
    catch ( P2Pevent *pEVT )
    {
      pEVT->Advice(_T("P2PeerExplorer::ProcExpump terminated"))->Cancel();
    }
    catch ( ... )
    {
      EVERR->Module (_T("P2PeerExplorer::ProcExpump") )
           ->Message(_T("Last resort exception of unknown type, "
                        "P2Pexpump terminated") )
           ->Cancel();
    }

    // Tidy up, and
    return 0;
}

//
//  Plain network P2PmsgPump implementation
//  NOTES: Simply pumps P2PeerSys, P2PeerCon and P2PeerMsg objects
//         through the P2PeerTarget base class
//       : Usually P2PeerMsg's are swapped to the context of this
//         thread via ContextSwap() and processed independantly in
//         the fullness of time
//       : It's possible to have processing delays in this context.
//         But keep in mind P2PeerMsg's may keep building up
//
void
P2PeerExplorer::RunExpump (  )
{
    // Locals
    DWORD    dwResult;
    P2PsigID  nSigID;

    // Because this is all problematic we
    try
    {
      // Latencies
      ThrowP2Pevent();

      // Pump messages through the P2PeerSys, P2PeerCon and
      // P2PeerMsg_MAP's until terminated and exhausted
      while ( (dwResult=PumpP2Pmsg(8000,nSigID)) != 0 )
      {
        // Immediate closure signalled
        if ( nSigID == P2PsigPump_CLOSE )
          break;

        // Idle closure signalled
        if ( nSigID == P2PsigPump_CLOSEONIDLE )
          break;

        // Wakeup signalled
        if ( nSigID == P2PsigPump_WAKEUP )
          continue;
      }
    }

    // Exceptions
    catch ( P2Pevent *pEVT)
    {
      pEVT->Advice("P2Pexpump() has terminated" )
          ->Cancel();
    }
    catch ( ... )
    {
      EVERR->MODULE
           ->Message("Last resort exception of unknown type, "
                     "P2Pexpump has terminated" )
           ->Cancel();
    }

    // Tidy up, and
}

//
//  Performs post P2PmsgExp destruction processing
//  NOTES: Specialise for external notifications etc
//
void
P2PeerExplorer::PostDestroyExpump ( P2PexpumpID )
{
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
//  Returns:    P2PeerCon*
//              Completion summary flag
//                0.. P2PeerCon object posted
//                    Otherwise sequence failed and passed P2PeerCon
//                    connection object is returned
P2PeerCon*
P2PeerExpump::PostP2PeerCon ( P2PeerCon *pCon )
{
    // Introduce locals
    P2Paddr   oP2PaddrCon = pCon -> GetP2Paddress();
    P2PsafeCS oSafeCS     = m_oCSectionExpump;
    if ( g_bP2Pmsg_AssertValid )
      pCon -> AssertValid ( );

    // Environmental
    // NOTES: P2PeerCon objects may only be posted to operational,
    //        P2PeerExpump's negates risk of dead connections.
    if ( m_nExpumpID == NULL )
    {
      EVERR->MODULE->AFPcon(pCon)
           ->Message(L"P2PeerExpump(%s) is not operational, "
                     "P2PeerCon(%s) not posted"
                    , oP2PaddrCon.c_wstr()
                    , GetP2PaddrHub().c_wstr() )
           ->Advice ("Perform SpawnExpump() or CreateExpump() before PostP2PeerCon()")
           ->Advice ("Hub has failed?")
           ->Display()->SetLast();
      return pCon;
    }

    // Iterate through P2PeerCon list
    // NOTES: Trap duplicates.  Null identification addresses
    //        are special
    P2PeerCon *pConEnum = 0;
    while ( EnumP2PexpCon(m_nExpumpID,&pConEnum) )
    {
      if ( pConEnum->GetP2Paddress() != oP2PaddrCon )
        continue;
      EVERR->MODULE->AFPcon(pCon)
           ->Message(L"P2PeerCon[%s] instance already exists "
                     "within P2PmsgHub[%s]"
                    ,   oP2PaddrCon.c_wstr()
                    , GetP2PaddrHub().c_wstr() )
           ->SetLast();
      return pCon;
    }

    // Tidy up, and
    pCon -> m_pP2PeerTarget = this;
    PostP2PexpCon ( m_nExpumpID, pCon );
    PostP2Pmsg ( oP2PaddrCon, CN_P2PeerCon, P2P_Startup
               , pCon, (P2PeerMsg *)0, m_nExpumpID );
    return (P2PeerCon *)0;
}

//
//  Signals nominated P2PeerCon object
//
//
//  Parameters: P2PaddrSTR strP2Paddr
//              Address domain defining of P2PeerCon objects to
//              be signalled
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
P2PeerExpump::ConSignal ( P2PaddrSTR strP2PaddrTP
                        , P2PsigID nSigID, void *pvData, int iDataSize  )
{
    // Introduce locals
    P2Paddr   oP2Paddr = strP2PaddrTP;
    BOOL      bResult  = FALSE;
    P2PsafeCS oSafeCS  = m_oCSectionExpump;
    ASSERT(m_nExpumpID>0);

    // Iterate through P2PeerCon'nections list
    P2PeerCon *pConEnum = 0;
    while ( EnumP2PexpCon(m_nExpumpID,&pConEnum) )
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
P2PeerExpump::ConExists  ( P2PaddrSTR strP2Paddr )
{
    // Locals
    P2PsafeCS oSafeCS = m_oCSectionExpump;

    // Iterate through P2PeerCon list
    P2PeerCon *pCon = 0;
    while ( EnumP2PexpCon(m_nExpumpID,&pCon) )
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
P2PeerExpump::ConQuery ( P2PaddrSTR strP2Paddress, SafeP2PeerCon& rSafeCon )
{
    // Locals
    P2PsafeCS oSafeCS = m_oCSectionExpump;

    // Iterate through P2PeerCon list
    P2PeerCon *pCon = 0;
    while ( EnumP2PexpCon(m_nExpumpID,&pCon) )
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
//  Posts P2PeerMsg to this P2Pexpump for asynchronous delivery
//  NOTES: Always posted to the P2Pexpump for dedicated delivery
//       : P2Pexpump must be operational otherwise an exception
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
P2PeerExpump::PostP2PeerMsg ( P2PeerMsg *pMsg )
{
    // To be sure, to be sure
    if ( g_bP2Pmsg_AssertValid )
      pMsg -> AssertValid ( );

    // Delegate
    return PostP2Pexp ( pMsg, m_nExpumpID );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg operations

//
//  Routes P2PeerMsg's through P2PeerCon objects posted to this P2Pexpump
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
P2PeerExplorer::RouteP2PeerMsg ( P2PeerMsg *pMsg )
{
    // To be sure, to be sure
    // NOTES: Local routing must already have been performed
    P2Paddr oP2PaddrHub = GetP2PaddrHub();
    ASSERT(pMsg->GetDestin()!=oP2PaddrHub);
    P2Paddr oP2PaddrSrc = pMsg -> GetSource ( );
    P2Paddr oP2PaddrDst = pMsg -> GetDestin ( );
    //  From the LOCAL COPY, never from pMsg->GetDestin() directly.  GetDestin()
    //  hands back a pointer into the message's wide-string store, and on the
    //  UTF-16-store platforms (everything but Win32) that is not the store at
    //  all: P3PmsgData::c_wstr() widens through p2p_wstr_from_store(), whose
    //  result lives in a 16 slot thread-local RING that the very next handful
    //  of c_wstr()/c_name() calls recycles (Platform/p2pstr.h:629-651).  This
    //  function then makes far more than sixteen such calls - one per
    //  connection in the loop below, plus RouteP2PeerMsgPeek's own - before it
    //  compares the address, so by then the cached pointer read back as some
    //  unrelated recycled value ("Dst", "Src" - the field NAMES, from
    //  P3Pmsg::c_name).  Every comparison below failed, every message the
    //  Explorer produced fell through to the undeliverable path, and the
    //  Explorer answered nothing.  On Win32 p2p_wstr_from_store() returns the
    //  store pointer unchanged, which is why this only ever bit on Linux.
    P2PaddrSTR   pP2PaddrMsg = oP2PaddrDst.c_wstr ( );

    // Facilitate message peeking
    // NOTES: Application may wish to observe outgoing messages
    msgRESULT msgResult = RouteP2PeerMsgPeek ( pMsg );
    if ( msgResult != msgCONTINUE )
      return msgResult;

    // Parent routing
    // NOTES: P2PeerMsg sourced in this P2PeerExp environment and
    //        destined for P2PeerHub parent
    //      : Interception occurs prior to attempted XCid routing
    if (  oP2PaddrHub == oP2PaddrSrc       &&
         !oP2PaddrHub.IsRable(oP2PaddrDst)    )
    {
      P2PexpumpContextSwap ( pMsg );
      return msgSWAP;
    }

    // P2PeerCon routing
    // NOTES: Connections manage their own routing logic
    P2PeerCon *pCon = 0;
    while ( EnumP2PexpCon(m_nExpumpID,&pCon) )
    { 
      const P2Paddr& oP2PaddrCon = pCon -> GetP2Paddress();
      // NOTES: EnumP2PexpCon() is deliberately unfiltered - it is the
      //        "every connection on this expump" primitive, and the six
      //        loops in this file each apply their own predicate to it.
      //        A listener is not a routing candidate, so the test
      //        belongs at this call site and not in the enumerator
      if ( pCon->GetMode() == P2PeerCon_SERVICE )
      {
        continue;
      }

      // Immediate
      if ( oP2PaddrCon == pP2PaddrMsg )
        return P2PeerContextSwap ( pCon, pMsg );

      // Ejection
      // NOTES: P2PeerMsg sourced from XCid (child of P2PeerExp) and destined
      //        child of associated P2PeerHub.  Thus ejected from from P2PeerExp
      //        environment
      //      : P2PeerMsg cannot be exchanged between XCid's
      if ( ( oP2PaddrCon == oP2PaddrSrc       ||
             oP2PaddrCon.IsChild(oP2PaddrSrc)    ) &&
             oP2PaddrHub.IsChild(oP2PaddrDst)          )
      {
        return SwapP2PexpContext ( pMsg );
      }

      // Children
      // NOTES: P2PeerCon is our network child, and
      //        P2PeerMsg is routable down through P2PeerCon
      if ( oP2PaddrHub.IsChild(oP2PaddrCon) &&
           oP2PaddrCon.IsRable(pP2PaddrMsg)    )
        return P2PeerContextSwap ( pCon, pMsg );

      // Parent
      // NOTES: P2PeerCon is our network parent, and
      //        P2PeerMsg is not routable down through this P2Peer
      if (  oP2PaddrCon.IsChild(oP2PaddrHub) &&
           !oP2PaddrHub.IsRable(pP2PaddrMsg)      )
      {
        ASSERT(0);
        return P2PeerContextSwap ( pCon, pMsg );
      }
    }

    // Undeliverable
    return P2PeerTarget::RouteP2PeerMsg ( pMsg );
}
//
//  Peek P2PeerMsg handler
//  NOTES: Called immediately prior to commencement of routing a
//         P2PeerMsg through a P2PeerTarget derived object.
//       : Override this default implementation for special processing etc
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Completed processing message
//
//  Returns:     msgRESULT
//               Routing summary
//                 msgHANDLED... Message handled
//                 msgCONTINUE.. Continue routing
//
msgRESULT
P2PeerExplorer::RouteP2PeerMsgPeek ( P2PeerMsg *pMsg )
{
    // Ejection routing
    // NOTES: P2PeerMsg received from XCid (child of hub) and destined
    //        child of this hub
    //      : P2PeerMsg cannot be exchanged between EXid's
    //LPCTSTR lpszName=pMsg->c_name();
    if ( GetCurrentThreadId() == m_nExpumpID )
    {
      P2Paddr oP2Paddr( GetP2PaddrHub(), L"XC*" ); //TODO:LJM This should persist
P2Paddr oP2PaddrSource = pMsg->GetSource();
P2Paddr oP2PaddrDestin = pMsg->GetDestin();
P2Paddr oP2PaddrThis   = GetP2PaddrHub();
if ( pMsg->Map_MatchName(L"P2Pexpump*") )
  oP2Paddr.c_hopname(0);
      if ( oP2Paddr.IsMapped(pMsg->GetSource())       &&
           GetP2PaddrHub().IsChild(pMsg->GetDestin())    )
        return P2PexpumpContextSwap ( pMsg );
    }
    return msgCONTINUE;//msgResult;
}

//
//  Swaps the processing context for the current P2PeerMsg to
//  the encapsulated P2PeerExpump
//  NOTES: Implementation requires the SwapP2PmsgContext() return
//         code to be immediately propagated backwards as stack 
//         unwinds
//
//  Parameters: P2PeerMsg *pMsg
//              Message whose processing context is to be swapped
//              to P2Pexpump context for hub
//
//  Returns:    mapRESULT
//              Context swap object (mapSWAP)
//               
msgRESULT
P2PeerExplorer::P2PexpumpContextSwap ( P2PeerMsg *pMsg )
{
    if ( m_nExpumpID > 0 )
      return SwapP2PexpContext ( pMsg );

    // Undeliverable
    // NOTES: Deliver P2PeerMsg exception back to source
    P2Pevent *pEVT =
    EVERR->MODULE->AFPmsg(pMsg)
         // WIDE arguments need the WIDE overload - see P2PeerTarget.cpp:1476.
         ->Message(L"Message[%s] from [%s] not deliverable to [%s]"
                  , pMsg->c_name(), pMsg->GetSource(), pMsg->GetDestin() )
         ->Advice (L"P2PeerExpump has shutdown" )
         ->Advice (L"Bad destination address [%s]", pMsg->GetDestin() )
         ->Group("P2P");
    PostP2PeerMsg ( pMsg->ExceptionFactory(pEVT) );
    pEVT ->Cancel();
    return msgHANDLED;
}

//
//  Peek P2PeerMsg handler
//  NOTES: Called immediately prior to commencement of routing a
//         P2PeerMsg through a P2PeerTarget derived object.
//       : Override this default implementation for special processing etc
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Completed processing message
//
//  Returns:     msgRESULT
//               Routing summary
//                 msgHANDLED... Message handled
//                 msgCONTINUE.. Continue routing
//
msgRESULT
P2PeerExplorer::PeekP2PeerMsg ( P2PeerMsg *pMsg )
{
    P2Paddr oP2Paddr( GetP2PaddrHub(), L"XC*" ); //TODO:LJM This should persist
if ( pMsg->Map_MatchName(L"P2PexpumpHub") && GetP2PaddrHub()==L"CEX")
  oP2Paddr.c_hopname(0);

    // Interception routing
    // NOTES: P2PeerMsg received from child of hub and destined for XCid 
    //      : P2PeerMsg cannot be exchanged between XCid's
    if ( GetCurrentThreadId() != m_nExpumpID )
    {
P2Paddr oP2PaddrSource = pMsg->GetSource();
P2Paddr oP2PaddrDestin = pMsg->GetDestin();
P2Paddr oP2Paddr_CEX_XCn(L"CEX.XC*");
P2Paddr oP2Paddr_CEX_XC0(L"CEX.XC0");
ASSERT(oP2Paddr_CEX_XCn.IsMapped(oP2Paddr_CEX_XC0));
if ( pMsg->Map_MatchName(L"P2Pexpump*") )
  oP2Paddr_CEX_XC0.c_hopname(0);
if ( pMsg->Map_MatchName(L"P2PexpumpHub") )
  oP2Paddr_CEX_XC0.c_hopname(0);


      if ( oP2Paddr.IsMapped(pMsg->GetDestin()) )
        return P2PexpumpContextSwap ( pMsg );
      if ( GetP2PaddrHub() == pMsg->GetDestin() &&
           pMsg->Map_MatchName(L"P2Pexp*")       )
        return P2PexpumpContextSwap ( pMsg );
      return msgCONTINUE;
    }
    //if ( GetP2PaddrHub() != pMsg->GetDestin() )
    //{
    //}
    //LPCTSTR lpszName=pMsg->c_name();
    //if ( pMsg->Map_MatchName(MSG_P2PexpCtrl) &&
    //     oP2PaddrHub.IsChild(oP2PaddrDst)    &&
    //     oP2PaddrHub.IsChild(oP2PaddrSrc)       )
    //{
    //  SwapP2PexpContext ( pMsg );
    //  return msgSWAP;
    //}
    // Simply
    //msgRESULT msgResult = On_P2PeerMsg ( pMsg -> GetSource() 
    //                                   , CN_P2PeerMsg 
    //                                   , P2P_P2Pmsg
    //                                   , pMsg
    //                                   , 0, (P2P_MSGHANDLERINFO *)0 );
    return msgCONTINUE;//msgResult;
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
P2PeerExplorer::GetP2PaddrHub ( )
{
    // Delegate, and
    return m_pHub -> GetP2PaddrHub();
}

//
//  Exposes the P2PeerHub this P2Pexplorer serves
//  NOTES: Overrides P2PeerTarget base class for the same reason
//         GetP2PaddrHub() and GetHubID() above do: a P2Pexplorer is built
//         through the default P2PeerTarget ctor, which never calls
//         RegisterTarget(), so m_pTargetParent stays null and the base
//         implementation throws "No linked P2PeerHub".
//       : This override was MISSING while its two siblings were present, and
//         the omission made the whole XCid path unreachable: every connection
//         an expump owns carries m_pP2PeerTarget = this, so
//         P2PeerCon::GetAuthHub() -> GetP2PeerHub() threw at the top of
//         AuthGateInbound() - ahead of the IsAuthRequired() test, so it bit at
//         the stock posture - and the login was discarded before
//         On_XCidConLogin was ever entered.
//
P2PeerHub*
P2PeerExplorer::GetP2PeerHub ( )
{
    // Delegate, and
    return m_pHub;
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
P2PeerExplorer::GetHubID ( ) const
{
    return m_pHub -> GetHubID();
}

///////////////////////////////////////////////////////////////////////
//  P2PeerCon handlers
//  NOTES: If there is a desire to optimise the connection map
//         subjectively place frequent messages at the top and less
//         frequent messages at the bottom of the map
// 
BEGIN_P2PeerCon_MAP(P2PeerExplorer, P2PeerTarget)
    ON_P2PeerSVR_STARTUP(L"*",On_XCidSvrStartup)
    ON_P2PeerSVR_LISTEN(L"*",On_XCidSvrListen)
    ON_P2PeerSVR_ACCEPT(L"*",On_XCidSvrAccept)

    ON_P2PeerCon_ACCEPT(L"*",On_XCidConAccept)
    ON_P2PeerCon_LOGIN(L"*",On_XCidConLogin)
    ON_P2PeerCon_CLOSE(L"*",On_XCidConClose)
END_P2PeerCon_MAP()

//
//  Handler to initiate XCid server STARTUP
//  NOTES: Default implementation simply delegates to the
//         connection object
//
//
//  Parameters: P2PeerCon *pCon
//              Object for which EXid server is to be started
//
//  Returns:    conRESULT
//              Result code
//
conRESULT
P2PeerExplorer::On_XCidSvrStartup ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel();

    // Confirm P2Pexpump context
    // NOTES: P2PeerExplorer connections must be processed exclusively
    //        in the context of a P2Pexpump
    if ( !P2PeerContext(m_nExpumpID) )
      EVERR->MODULE->AFPcon(pCon)
           ->Message("Invalid P2Pexpump startup context")
           ->Throw();

    // To be sure, to be sure
    if ( pCon->GetMode() != P2PeerCon_SERVICE )
      EVERR->MODULE->AFPcon(pCon)
           ->Message(L"Cannot startup connection[%s] for mode (%i)\n"
                    , pCon->GetP2Paddress().c_wstr()
                    , pCon->GetMode() )
           ->Advice ("Bug (SNHappen)")
           ->Throw();

    // Delegated implementation
    pCon -> OnStartup ( );
    pCon -> Listen ( );

    // Tidy up, and
    return conHANDLED;                 // P2PeerCon object handled
}

//
//  Description: WSA listen object notification
//               NOTES: Default implementation is to simply flag
//                      notification as handled
//
//
//  Parameters:  P2PeerCon *pCon
//               Listening object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerExplorer::On_XCidSvrListen ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel ( );

    // Confirm P2Pexpump context
    // NOTES: P2PeerExplorer connections must be processed exclusively
    //        in the context of a P2Pexpump
    if ( !P2PeerContext(m_nExpumpID) )
      EVERR->MODULE->AFPcon(pCon)
           ->Message("Invalid P2Pexpump listen context")
           ->Throw();

    // Delegated implementation
    pCon -> OnListen ( );
    pCon -> Accept ( );

    // Tidy up and
    return conHANDLED;
}

//
//  Handler to process ACCEPT'ed XCid server connections
//  NOTES: Default implementation simply delegates to the
//         connection object
//
//
//  Parameters:  P2PeerCon *pCon
//               Server object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerExplorer::On_XCidSvrAccept  ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel ( );

    // Confirm P2Pexpump context
    // NOTES: P2PeerExplorer connections must be processed exclusively
    //        in the context of a P2Pexpump
    if ( !P2PeerContext(m_nExpumpID) )
      EVERR->MODULE->AFPcon(pCon)
           ->Message("Invalid P2Pexpump accept context")
           ->Throw();

    // Delegate for specialised default processing
    // NOTES: Such processing usually spawns accepted P2PeerCon
    //        client objects.  Such objects are assumed to be
    //        fully integrated into the P2PeerCon_MAP()
    //      : However, always assume its possible for a NULL
    //        P2PeerCon to be spawned.
    P2PeerCon *pConService = pCon;
    P2PeerCon *pConAccept  = pCon -> OnAccept ( );
    if ( pConService->GetMode() != P2PeerCon_SERVICE )
    {
      pConService = pConAccept;
      pConAccept  = pCon;
    }

    // Manadatory accepted CLIENT processing
    // NOTES: Spawned out of passed service connection
    //      : Assign timer for completion of login sequence,
    //        assumed to be initiated by the CLIENT
    if ( pConAccept )
    {
      // Pump the spawned connection
      // NOTES: SERVICE has been pumped into this default handler and
      //        is now being processed.  The spawned CLIENT is auto
      //        posted to P2PeerHub, now pump the CLIENT for subsequent
      //        interception and property assignment.  Otherwise the
      //        spawned P2PeerCon sits in limbo.
      //      : The accepted CLIENT is pumped under the SERVICE address
      PostP2Pmsg ( pCon->GetP2Paddress(), CN_P2PeerCon, P2P_Accept
                 , pConAccept, 0, m_nExpumpID );
      //pConAccept -> m_uLoginTimerID = pConAccept -> SetPITimer ( 1000 );
    }

    // Mandatory SERVICE processing
    // NOTES: Prepare SERVICE for next accepted connection, otherwise
    //        it exists in limbo
    //      : Some connection SERVICE types may morph themselves
    //        into accepted CLIENT connections
    //      : SERVICE now waits for the next accepted connection,
    //        error or closure etc. 
    if ( pConService )
      pConService -> Accept ( );

    // Tidy up and
    return conHANDLED;
}

//
//  Handler to process ACCEPT'ed XCid client connections
//  NOTES: Default implementation simply delegates to the
//         connection object
//
//
//  Parameters:  P2PeerCon *pCon
//               Accepted client object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerExplorer::On_XCidConAccept  ( P2PeerCon *pCon )
{
    // Diagnostics
    if ( IsEVTRC )
      EVTRC->MODULE->AFPcon(pCon)
           ->Cancel ( );

    // Confirm P2Pexpump context
    // NOTES: P2PeerExplorer connections must be processed exclusively
    //        in the context of a P2Pexpump
    if ( !P2PeerContext(m_nExpumpID) )
      EVERR->MODULE->AFPcon(pCon)
           ->Message("Invalid P2Pexpump accepted client context")
           ->Throw();

    // Confirm accepted CLIENT Connection
    // NOTES: Refer On_XCidSvrAccept() handler for SERVER processing
    if ( pCon->GetMode() == P2PeerCon_SERVICE )
      EVERR->MODULE->AFPcon(pCon)
           ->Message("Attempt to process SERVER connection in CLIENT handler")
           ->Throw();

    // Delegate non-SERVICE's for default processing
    // NOTES: Forms the default processing for the accepted
    //        CLIENT activity below.
    //      : Initialises accepted connection for I/O, mandatory
    //        that such activity only occur beyond this point.
    pCon -> OnAccept ( L"" );

    // Tidy up and
    return conHANDLED;
}

//
//  P2P_Login handler
//  NOTES: Processes ECid login requests
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object.  Handler assumes control
//               over life cycle.
//
//               P2PaddrSTR strP2Paddr
//               Identification address of P2Pexplorer
//
//               const void *pvLoginMsg
//               Login request message
//
//               P2Psize_t iSize
//               Size of above message
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerExplorer::On_XCidConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr
                                , const void *pvLoginMsg, P2Psize_t iSize )
{
    // Introduce locals
    UNREFERENCED_PARAMETER(pvLoginMsg);
    P2Paddr oP2PaddrThat ( strThatP2Paddr );
    conRESULT conResult = conDROP;
    int       Ack       = ~0;

    // Because this is all problematic we
    try
    {
      // Confirm P2Pexpump context
      // NOTES: P2PeerExplorer connections must be processed exclusively
      //        in the context of a P2Pexpump
      if ( !P2PeerContext(m_nExpumpID) )
        EVERR->Message("Invalid P2Pexpump login context"
                      , strThatP2Paddr )
             ->Throw();

      // Confirm null strThatP2Paddr
      // NOTES: Connection identification is assigned as part of
      //        the login sequence
      if ( !oP2PaddrThat.IsNull() )
        EVERR->Message(L"Null P2Paddr expected, not [%s]"
                      , strThatP2Paddr )
             ->Throw();

      // Identify spare ECid slot
      for ( UINT e = 0; e < m_nMaxECid; e++ )
      {
        oP2PaddrThat = P2Paddr ( GetP2PaddrHub(), L"XC%i", e );
        Ack          = e;

        if ( !ConExists(oP2PaddrThat) )
          break;
        oP2PaddrThat.Empty ( );
      }

      // Confirm spare slot located
      if ( oP2PaddrThat.IsEmpty() )
        EVERR->Message("No free ECid exploration slots available")
             ->Throw  ( );

      // Login request granted
      // NOTES: Perform logon confirmation.  P2PeerID assignment
      //        forms part of the sequence
      //      : Accepted connections MUST have their address
      //        assigned as part of the login-logon sequence.
      pCon -> LoginAck ( oP2PaddrThat, &Ack, sizeof(Ack) );
      pCon -> SetState ( ConState_BCasts | ConState_UCasts, 0 );

      // Completed
      conResult = conHANDLED;
    }

    // Exceptions
    // NOTES: Connection denied, recover resources
    catch ( P2Pevent *pEVT )
    {
      if ( pEVT->EmptyModule() )
        pEVT->MODULE
            ->AFPmsg(pCon)->AFP(strThatP2Paddr)->AFP(iSize);
      pEVT->Advice("Connection request denied" )
          ->Cancel();
    }

    // Tidy up and
    return conResult;                  // Message handled
}

//
//  P2P_ConClose
//  NOTES: Release allocated explorer slot along with all
//         associated registrations
//
//
//  Parameters:  P2PeerCon *pCon
//               Connection object
//
//  Returns:     conRESULT
//               Result code
//
conRESULT
P2PeerExplorer::On_XCidConClose ( P2PeerCon *pCon )
{
    // Introduce locals
    BOOL    bMatched    = FALSE;
    P2Paddr oP2PaddrCon = pCon -> GetP2Paddress();

    // Identify ECid
    for ( UINT e = 0; e < m_nMaxECid; e++ )
    {
      P2Paddr oP2PaddrHub = GetP2PaddrHub();
      P2Paddr oP2PaddrECid ( oP2PaddrHub.c_wstr(), L"XC%i", e );
      if ( oP2PaddrCon != oP2PaddrECid )
        continue;
      bMatched = TRUE;

      // Remove all associated registrations
      // NOTES: By PREFIX, not by exact address.  The slot is going away, so
      //        every address routable through it goes with it - an entry left
      //        behind here is never evicted by anything (SECURITY_REVIEW M2)
      CListRegHubs_RemoveRable ( m_oCListRegHubs, oP2PaddrCon );
      CListRegCons_RemoveRable ( m_oCListRegCons, oP2PaddrCon );
      CListRegPmps_RemoveRable ( m_oCListRegPmps, oP2PaddrCon );
    }

    // Handle unknown connection
    if ( !bMatched )
      EVERR->MODULE->AFPcon(pCon)
           ->Message(L"Unknown connection closure(%s-%s)\n"
                    , (P2PaddrSTR)GetP2PaddrHub()
                    , (P2PaddrSTR)oP2PaddrCon )
           ->Cancel();

    // Tidy up and delegate
    return pCon -> OnClose ( );
}

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg Handlers
//  NOTES: Default handler set available in P2PeerExplorer derived objects
//       : If there is a desire to optimise the message map
//         subjectively place frequent messages at the top and less
//         frequent messages at the bottom of the map
//
BEGIN_P2PeerMsg_MAP(P2PeerExplorer, P2PeerTarget)
    ON_P2PeerMsg(MSG_P2PexpCtrl, On_P2PexpCtrl)
    ON_P2PeerMsg(MSG_P2PexpHub, On_P2PmsgExp_Hub)
    ON_P2PeerMsg_CATCH(MSG_P2PexpHub, On_P2PmsgExp_CATCH)
    ON_P2PeerMsg(MSG_P2PexpPmp, On_P2PmsgExp_Pmp)
    ON_P2PeerMsg_CATCH(MSG_P2PexpPmp, On_P2PmsgExp_CATCH)
    ON_P2PeerMsg(MSG_P2PexpCon, On_P2PmsgExp_Con)
    ON_P2PeerMsg_CATCH(MSG_P2PexpCon, On_P2PmsgExp_CATCH)
END_P2PeerMsg_MAP()

//
//  MSG_P2PmsgExp handler
//  NOTES: Broadcasts messages to P2PeerExplorer children through P2PeerCon
//         connections for which broadcasts are enabled
//       : Provide implementation in derived class to intercept a
//         local copy, alternatively specialise PeekP2PeerMsg()
//
//
//  Parameters: P2PeerMsg *pMsg
//              MSG_P2PmsgExp message
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerExplorer::On_P2PexpCtrl ( P2PeerMsg *pMsg )
{
    // Confirm thread context
    // NOTES: MSG_P2PmsgExp messages MUST be processed
    //        sequentually in the context of the P2Pexpump
    if ( !P2PeerContext(m_nExpumpID) )
      return P2PeerContextSwap ( m_nExpumpID );

    // Because this is all problematic we
    try
    {
      //  NOT pMsg->GetSource() as it stands: every RHub/RPmp/RCon below keys the
      //  registry on this, and a peer may legitimately pass the source-binding
      //  gate while claiming a descendant of its own slot (SECURITY_REVIEW M2).
      CStringADDR strSource = P2PexpReg_BindSource ( this, pMsg->GetSource() );
      CStringADDR strKey;

      // Each field becomes a command
      P3PmsgCurs& oCurs = pMsg->r_datn().DESC.r_Curs();
      for ( int i = 0; oCurs.Goto(i); i++ )
      {
        ///////////////////////////////////////////////////////////////
        // Register P2PeerHub
        // Format: RHub     - Base register hub command
        //         RHub@Dsc - Descriptions qualifier
        if ( pMsg->r_datn().Exists(L"RHub") )
        {
          //ASSERT(m_nExpumpID==oCurs.r_field().c_uint());
          CListRegHubs_Remove ( m_oCListRegHubs, strSource );
          CListRegHubs_Insert ( m_oCListRegHubs, strSource );
          bool bDsc = false;
          if ( pMsg->r_datn().SelectItem(L"RHub").r_Attr().Exists(L"Dsc") )
            bDsc = true;
          QueryP2PmsgExp_Hub ( strSource, bDsc );
          continue;
        }

        // Query P2PeerHub
        // Format: QHub     - Base query hub command
        //         QHub@Dsc - Descriptions qualifier
        if ( pMsg->r_datn().Exists(L"QHub") )
        {
          bool bDsc = false;
          if ( pMsg->r_datn().SelectItem(L"QHub").r_Attr().Exists(L"Dsc") )
            bDsc = true;
          QueryP2PmsgExp_Hub ( strSource, bDsc );
          continue;
        }

        // De-register P2PeerHub
        // Format: DHub     - Base de-register hub command
        if ( pMsg->r_datn().Exists(L"DHub") )
        {
          CListRegHubs_Remove ( m_oCListRegHubs, strSource );
          if ( m_oCListRegHubs.GetCount() <= 0 )
            RegisterP2Pexpump ( P2PmsgExp_HUB, FALSE );
          continue;
        }

        ///////////////////////////////////////////////////////////////
        // Register pump
        // Format: RPmp     - Base register hub command
        //         RPmp@Dsc - Descriptions qualifier
        //         QPmp@ID  - P2PumpID qualifier
        if ( pMsg->r_datn().Exists(L"RPmp") )
        {
          bool bDsc = false;
          if ( pMsg->r_datn().SelectItem(L"RPmp").r_Attr().Exists(L"Dsc") )
            bDsc = true;
          P2PumpID nPumpID = 0;
          if ( pMsg->r_datn().SelectItem(L"RPmp").r_Attr().Exists(L"ID") )
            nPumpID = pMsg->r_datn().SelectItem(L"RPmp").r_Attr().SelectItem(L"ID").c_int();

          CListRegPmps_Remove ( m_oCListRegPmps, strSource, nPumpID );
          CListRegPmps_Insert ( m_oCListRegPmps, strSource, nPumpID );

          QueryP2PmsgExp_Pmp ( nPumpID, strSource, bDsc );
          RegisterP2Pexpump ( P2PmsgExp_PMP, TRUE );
          continue;
        }

        // Query pumps
        // Format: QPmp     - Base query pump command
        //         QPmp@Dsc - Descriptions qualifier
        //         QPmp@Sum - Brief summary qualifier
        //         QPmp@ID  - P2PumpID qualifier
        if ( pMsg->r_datn().Exists(L"QPmp") )
        {
          bool bDsc = false;
          if ( pMsg->r_datn().SelectItem(L"QPmp").r_Attr().Exists(L"Dsc") )
            bDsc = true;
          P2PumpID nPumpID = 0;
          if ( pMsg->r_datn().SelectItem(L"QPmp").r_Attr().Exists(L"ID") )
            nPumpID = pMsg->r_datn().SelectItem(L"QPmp").r_Attr().SelectItem(L"ID").c_int();

          QueryP2PmsgExp_Pmp ( nPumpID, strSource, bDsc );
          continue;
        }

        // De-register pumps
        // Format: DPmp     - Base de-register hub command
        //         DPmp@ID  - P2PumpID qualifier
        if ( pMsg->r_datn().Exists(L"DPmp") )
        {
          P2PumpID nPumpID = 0;
          if ( pMsg->r_datn().SelectItem(L"DPmp").r_Attr().Exists(L"ID") )
            nPumpID = pMsg->r_datn().SelectItem(L"DPmp").r_Attr().SelectItem(L"ID").c_int();

          CListRegPmps_Remove ( m_oCListRegPmps, strSource, nPumpID );
          
          if ( m_oCListRegPmps.GetCount() <= 0 )
            RegisterP2Pexpump ( P2PmsgExp_PMP, FALSE );
          continue;
        }

        ///////////////////////////////////////////////////////////////
        // Register P2PeerCon's
        // Format: RCon     - Base register connection command
        //         RCon@Dsc - Descriptions qualifier
        //         QCon@ID  - P2PconID qualifier
        if ( pMsg->r_datn().Exists(L"RCon") )
        {
          bool bDsc = false;
          if ( pMsg->r_datn().SelectItem(L"RCon").r_Attr().Exists(L"Dsc") )
            bDsc = true;
          P2PconID nP2PconID = 0;
          if ( pMsg->r_datn().SelectItem(L"RCon").r_Attr().Exists(L"ID") )
            nP2PconID = pMsg->r_datn().SelectItem(L"RCon").r_Attr().SelectItem(L"ID").c_int();

          CListRegCons_Remove ( m_oCListRegCons, strSource, nP2PconID );
          CListRegCons_Insert ( m_oCListRegCons, strSource, nP2PconID );

          QueryP2PmsgExp_Con ( nP2PconID, strSource, bDsc );
          RegisterP2Pexpump ( P2PmsgExp_CON, TRUE );
          continue;
        }

        // Query P2PeerCon's
        // Format: QCon     - Base query pump command
        //         QCon@Dsc - Descriptions qualifier
        //         QCon@Sum - Brief summary qualifier
        //         QCon@ID  - P2PconID qualifier
        if ( pMsg->r_datn().Exists(L"QCon") )
        {
          bool bDsc = false;
          if ( pMsg->r_datn().SelectItem(L"QCon").r_Attr().Exists(L"Dsc") )
            bDsc = true;
          P2PconID nP2PconID = 0;
          if ( pMsg->r_datn().SelectItem(L"QCon").r_Attr().Exists(L"ID") )
            nP2PconID = pMsg->r_datn().SelectItem(L"QCon").r_Attr().SelectItem(L"ID").c_int();

          QueryP2PmsgExp_Con ( nP2PconID, strSource, bDsc );
          continue;
        }

        // De-register P2PeerCon's
        // Format: DCon     - Base de-register hub command
        //         DCon@ID  - nP2PconID qualifier
        if ( pMsg->r_datn().Exists(L"DCon") )
        {
          P2PconID nP2PconID = 0;
          if ( pMsg->r_datn().SelectItem(L"DCon").r_Attr().Exists(L"ID") )
            nP2PconID = pMsg->r_datn().SelectItem(L"DCon").r_Attr().SelectItem(L"ID").c_int();

          CListRegCons_Remove ( m_oCListRegCons, strSource, nP2PconID );
          
          if ( m_oCListRegCons.GetCount() <= 0 )
            RegisterP2Pexpump ( P2PmsgExp_CON, FALSE );
          continue;
        }
      }
    }

    // Exceptions
    catch ( P2Pevent *pEVT )
    {
      PostP2PeerMsg ( pMsg->ExceptionFactory(pEVT) );
      pEVT -> Cancel ( );
    }
    catch ( ... )
    {
      P2Pevent *pEVT =
      EVERR->MODULE->AFPmsg(pMsg)
           ->Group ( "P2Pexp" )
           ->Message("Last resort exception" );
      PostP2PeerMsg ( pMsg->ExceptionFactory(pEVT) );
      pEVT -> Cancel( );
    }

    // Tidy up and
    return msgHANDLED;
}

//
//  MSG_P2PmsgExp_Hub handler
//  NOTES: P2PeerHub status notifications that have been generated
//         from within the Targetcore
//       : Such notifications are subsequently broadcast to either the 
//         nominated address or all P2Pexplorers registered for such
//         notifications
//
//
//  Parameters: P2PeerMsg *pMsg
//              P2PmsgExp_Hub status notification
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerExplorer::On_P2PmsgExp_Hub ( P2PeerMsg *pMsg )
{
    // Nominated destination
    // NOTES: Forms part of a synchronisation sequence and is not
    //        necessary to broadcast to all synchronised P2Pexplorer's
    if ( wcslen(pMsg->GetDestin()) > 0 )
    {
      PostP2PeerMsg ( new P2PeerMsg(*pMsg) );
      return msgHANDLED;
    }

    // Broadcast instance to all registered P2Pexplorer's
    // NOTES: Any reflected P2PeerMsg will cause destination to be
    //        deregistered
    //      : Notification is redirected as is
    POSITION pos = m_oCListRegHubs.GetHeadPosition();
    while ( pos )
    {
      SP2PexpRegHub& oRegHub = m_oCListRegHubs.GetNext ( pos );
      PostP2PeerMsg ( pMsg->RedirectFactory(oRegHub.strClient) );
    }

    // Tidy up and
    if ( m_oCListRegHubs.GetCount() <= 0 )
      RegisterP2Pexpump ( P2PmsgExp_HUB, FALSE );
    return msgHANDLED;
}

//
//  MSG_P2PmsgExp_Pmp handler
//  NOTES: P2PmsgPump status notifications that have been generated
//         from within the Targetcore
//       : Such notifications are subsequently broadcast to either the 
//         nominated address or all P2Pexplorers registered for such
//         notifications
//
//
//  Parameters: P2PeerMsg *pMsg
//              P2PmsgExp_Pmp status notification
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerExplorer::On_P2PmsgExp_Pmp ( P2PeerMsg *pMsg )
{
    // Nominated destination
    // NOTES: Forms part of a synchronisation sequence and is not
    //        necessary to broadcast to all synchronised P2Pexplorer's
    if ( wcslen(pMsg->GetDestin()) > 0 )
    {
      PostP2PeerMsg ( new P2PeerMsg(*pMsg) );
      return msgHANDLED;
    }

    // Isolate P2PumpID
    P2PumpID nPumpID = pMsg -> r_datn().c_int();

    // Broadcast instance to all registered P2Pexplorer's
    // NOTES: Any reflected P2PeerMsg will cause destination to be
    //        deregistered
    //      : Notification is redirected as is
    POSITION pos = m_oCListRegPmps.GetHeadPosition();
    while ( pos )
    {
      SP2PexpRegPmp& oRegPmp = m_oCListRegPmps.GetNext ( pos );
      if ( oRegPmp.nPumpID            &&
           oRegPmp.nPumpID != nPumpID    )
        continue;
      PostP2PeerMsg ( pMsg->RedirectFactory(oRegPmp.strClient) );
    }

    // Tidy up and
    if ( m_oCListRegPmps.GetCount() <= 0 )
      RegisterP2Pexpump ( P2PmsgExp_PMP, FALSE );
    return msgHANDLED;
}

//
//  MSG_P2PmsgExpCon handler
//  NOTES: P2PeerCon status notifications that have been generated
//         from within the Targetcore
//       : Such notifications are subsequently broadcast to either the 
//         nominated address or all P2Pexplorers registered for such
//         notifications
//
//
//  Parameters: P2PeerMsg *pMsg
//              P2PmsgExpCon status notification
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerExplorer::On_P2PmsgExp_Con ( P2PeerMsg *pMsg )
{
    // Nominated destination
    // NOTES: Forms part of a synchronisation sequence and is not
    //        necessary to broadcast to all synchronised P2Pexplorer's
    if ( wcslen(pMsg->GetDestin()) > 0 )
    {
      PostP2PeerMsg ( new P2PeerMsg(*pMsg) );
      return msgHANDLED;
    }

    // Isolate P2PconID
    P2PconID nConID = pMsg -> r_datn().c_int();

    // Broadcast instance to all registered P2Pexplorer's
    // NOTES: Any reflected P2PeerMsg will cause destination to be
    //        deregistered
    //      : Notification is redirected as is
    POSITION pos = m_oCListRegCons.GetHeadPosition();
    while ( pos )
    {
      SP2PexpRegCon& oRegCon = m_oCListRegCons.GetNext ( pos );
      if ( oRegCon.nConID           &&
           oRegCon.nConID != nConID    )
        continue;
      PostP2PeerMsg ( pMsg->RedirectFactory(oRegCon.strClient) );
    }

    // Tidy up and
    if ( m_oCListRegCons.GetCount() <= 0 )
      RegisterP2Pexpump ( P2PmsgExp_CON, FALSE );
    return msgHANDLED;
}

//
//  P2PmsgExp_CATCH handler
//  NOTES: Any P2PmsgExp object broadcast to a registered P2Pexplorer
//         and reflected as undeliverable will cause de-registration
//         of that P2Pexplorer
//
//
//  Parameters: P2PeerMsg *pMsg
//              P2PmsgExp exceptiopn
//
//  Returns:    msgRESULT
//              Completion summary
//
msgRESULT
P2PeerExplorer::On_P2PmsgExp_CATCH ( P2PeerMsg *pMsg )
{
    // Broadcast instance to all registered P2Pexplorer's
    // NOTES: Any reflected P2PeerMsg will cause destination to be
    //        deregistered
    CStringADDR strDESTIN = pMsg -> GetDestin();
                strDESTIN.MakeUpper();

    // P2PeerHub's
    CListRegHubs_Remove ( m_oCListRegHubs, strDESTIN );
    if ( m_oCListRegHubs.GetCount() <= 0 )
      RegisterP2Pexpump ( P2PmsgExp_HUB, FALSE );

    // P2PmsgPump's
    CListRegPmps_Remove ( m_oCListRegPmps, strDESTIN, 0 );
    if ( m_oCListRegPmps.GetCount() <= 0 )
      RegisterP2Pexpump ( P2PmsgExp_PMP, FALSE );

    // P2PeerCon's
    CListRegCons_Remove ( m_oCListRegCons, strDESTIN, 0 );
    if ( m_oCListRegCons.GetCount() <= 0 )
      RegisterP2Pexpump ( P2PmsgExp_CON, FALSE );

    // Tidy up and
    return msgHANDLED;
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerExplorer::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}

///////////////////////////////////////////////////////////////////////
//  P2PeerHub integration helpers
//  NOTES: Manage the integration of P2PeerExp objects with Hub's
//       : P2PeerHub declarations externalised to illiminate cross
//         linkages and dependencies

//
//  Activates the P2Pexpump exploration service on the passed P2PeerHub
//  NOTES: External instanciation of the P2PeerExpump is deliberately the
//         application's job - Targetcore provides no such service and never
//         starts one by itself (refer P2PeerHub.cpp:1034-1040).  This is the
//         documented helper an application calls to do it.
//       : The instance is REGISTERED with the hub through PostP2PeerExpump().
//         Without that GetP2PeerExpump() stays null, so nothing that goes
//         looking for an expump can find one - the INLINE_Expump_PEEK
//         interception (P2PeerExplorer.h:275) and every m_pP2PeerExpump test
//         in P2PeerHub included - and the caller holds the only pointer to an
//         orphan.  That was the state of this function before: it spawned and
//         returned, and nothing else.
//       : Ownership.  Once registered the hub owns the object (CloseHub() ->
//         DropP2PeerExpump()).  Until registered THIS function owns it, and
//         every failure path below destroys it exactly once.  An expump is
//         never registered unless it is known to be running, so the hub can
//         never be left holding a registered-but-dead expump.
//
//  Parameters: P2PeerHub *pHub
//              Hub to be served
//
//              P2PeerExpump *pExpump = 0
//              Application supplied instance, whose life cycle is assumed.
//              NOTES: Applications specialising P2PeerExpump (the whole
//                     P2PeerCon_MAP/P2PeerMsg_MAP handler set is virtual for
//                     exactly that) have no other way through this helper.
//                   : Omit for the stock P2PeerExplorer.  P2PeerExplorer IS
//                     P2PeerExpump - P2PeerExplorer.h:58 #defines one onto the
//                     other - so this and DynamicCreate()'s "bare
//                     P2PeerExpump" construct the very same type.
//
//  Returns:    P2PeerExpump*
//              The expump now registered with the hub, or 0 on failure
//
Targetcore_EXT P2PeerExpump*
P2PeerExpump_ACTIVATE ( P2PeerHub *pHub, P2PeerExpump *pExpump )
{
    // Already active
    // NOTES: Same guard DynamicCreate() applies.  A P2PeerHub supports a
    //        single P2PeerExpump instance and PostP2PeerExpump() refuses a
    //        second one, so expose the incumbent and dispose of the candidate
    //        - the caller has no other handle on it to dispose of it with
    if ( pHub->GetP2PeerExpump() )
    {
      if ( pExpump && pExpump != pHub->GetP2PeerExpump() )
        P2PeerExpump_DESTROY ( pExpump );
      return dynamic_cast<P2PeerExpump *>(pHub->GetP2PeerExpump());
    }

    // Instanciate
    if ( !pExpump )
      pExpump = new P2PeerExplorer ( pHub );

    // Spawn, and only then register
    if ( !pExpump->SpawnExpump(0,0) )
      return P2PeerExpump_DESTROY ( pExpump );
    if ( pHub->PostP2PeerExpump(pExpump) )
    {
      // Refused (raced against another activation).  Stop what we started and
      // drop it - the incumbent is somebody else's to manage
      pExpump -> CloseExpump ( 0 );
      P2PeerExpump_DESTROY  ( pExpump );
      return dynamic_cast<P2PeerExpump *>(pHub->GetP2PeerExpump());
    }

    // Tidy up, and
    return dynamic_cast<P2PeerExpump *>(pHub->GetP2PeerExpump());
}
Targetcore_EXT P2PeerExpump*
P2PeerExpump_DESTROY ( P2PeerExpump *pExpump )
{
    if ( pExpump )
      delete pExpump;
    return (P2PeerExpump *)0;
}
Targetcore_EXT msgRESULT
P2PeerExpump_INTERCEPT ( P2PeerHub *pHub, P2PeerExpump *pExpump, P2PeerMsg *pMsg )
{
    UNREFERENCED_PARAMETER(pHub);
    UNREFERENCED_PARAMETER(pExpump);
    UNREFERENCED_PARAMETER(pMsg);
    return msgCONTINUE;
}
