// Copyright © 2026 Khrustal & Mann
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
//  P2PeerioShm - refer P2PeerioShm.h and p2p_performance.md §6.3a.
//
//  ONE THREAD. Every entry point runs on the connection's pump: IoWrite / IoRead from
//  P2Peerio::Send / Recv, which the connection calls from its completion handler, and
//  On_QueuedCompletionStatus from the same pump. So the parked read / write and the
//  armed flags need no lock. The peer process is the only concurrency, and it touches
//  nothing but the mapping (the rings' own protocol) and our wake (a signal).
//
#include "stdafx.h"
#include "P2PeerioShm.h"
#include "P2PeerioShmState.h"
#include "P2PeerCon.h"
#include "Msgexception.h"

#ifndef ERROR_BROKEN_PIPE
#  define ERROR_BROKEN_PIPE   109L
#endif
#ifndef ERROR_INVALID_DATA
#  define ERROR_INVALID_DATA  13L
#endif
#ifndef ERROR_BUSY
#  define ERROR_BUSY          170L
#endif

//  The nSigID this class marks its own OVERLAPPEDcons with: outside P2PeerCon's signal
//  numbers (1..9, P2PeerCon.h), so the connection's handler passes them through its
//  "last resort P2Peerio delegation" branch to On_QueuedCompletionStatus below
static const P2PsigID kShmSig = 0x5348;          // 'SH'

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

P2PeerioShm::P2PeerioShm ( ) noexcept
  : m_pShm ( nullptr )
{
    m_pLate[0] = m_pLate[1] = nullptr;
}

P2PeerioShm::~P2PeerioShm ( )
{
    DetachShm ( );
}

//  The re-armed SERVICE gets a fresh, unattached io object: a link is per connection
P2Peerio*
P2PeerioShm::Clone ( )
{
    return new P2PeerioShm ( );
}

///////////////////////////////////////////////////////////////////////
//  The link

bool
P2PeerioShm::AttachShm ( P2PeerioShmState *pState )
{
    if ( m_pShm || !pState || !m_pCon || !pState->in || !pState->out )
    {
      delete pState;
      return false;
    }
    m_pShm = pState;
    m_pShm->pWakeOv  = m_pCon -> MakeOVERLAPPED ( 0 );
    m_pShm->pDeathOv = m_pCon -> MakeOVERLAPPED ( 0 );
    if ( !m_pShm->pWakeOv || !m_pShm->pDeathOv )
    {
      DetachShm ( );
      return false;
    }
    m_pShm->pWakeOv  -> nSigID = kShmSig;
    m_pShm->pDeathOv -> nSigID = kShmSig;
    ArmDeath ( );
    return !m_pShm->dead;
}

//  Teardown. An idle OVERLAPPEDcon is given back now. A queued one is not freed here:
//    - an armed wake on Windows is withdrawn (WakeCancel) and, when that succeeds, NO
//      completion will come, so its reference is released and it is given back now;
//    - otherwise the port still owes the completion - Linux reports the closed eventfd
//      as an aborted poll, and the death watch is aborted when the connection closes its
//      pipe - so it moves to m_pLate, where HasQueuedOwnOVERLAPPED() keeps the teardown
//      drain waiting and the late completion (or the drain, after ForgetOwnOVERLAPPED)
//      gives it back
void
P2PeerioShm::DetachShm ( )
{
    if ( !m_pShm )
      return;
    P2PeerioShmState *s = m_pShm;
    s->dead = true;

    //  A read or write PARKED on the ring is a prepared slot - it holds a reference on
    //  the connection and the connection is owed its completion. Abort it now, as
    //  closing a socket aborts its pending reads, so the teardown drain receives it.
    //  MEASURED (LSan, shm_mesh, 2026-11-24): left parked, the drain waited out its
    //  budget for a completion that could never come and the connection leaked, 32 KB a
    //  time with its receive buffer
    if ( s->rOv ) { OVERLAPPED *p = s->rOv; s->rOv = nullptr; Fail ( p, ERROR_OPERATION_ABORTED ); }
    if ( s->wOv ) { OVERLAPPED *p = s->wOv; s->wOv = nullptr; Fail ( p, ERROR_OPERATION_ABORTED ); }

    if ( m_pCon )
    {
      if ( s->pWakeOv && s->wakeArmed && p2pshm::WakeCancel ( s->mine ) )
      {
        m_pCon -> releaseOVERLAPPED ( s->pWakeOv );
        s->wakeArmed = false;
      }
      OVERLAPPEDcon *own[2]  = { s->pWakeOv, s->pDeathOv };
      bool           busy[2] = { s->wakeArmed, s->deathArmed };
      for ( int i = 0; i < 2; ++i )
      {
        if ( !own[i] ) continue;
        if ( busy[i] ) m_pLate[i] = own[i];
        else           m_pCon -> DropOVERLAPPED ( own[i], false );
      }
    }
    s->pWakeOv = s->pDeathOv = nullptr;
    m_pShm = nullptr;
    delete s;                                  // closes the wake (aborts an armed one), the peer wake, the mapping
}

///////////////////////////////////////////////////////////////////////
//  Helpers

//  Complete pOv (a slot Send / Recv prepared) on the connection's port, with a count
void
P2PeerioShm::Complete ( OVERLAPPED *pOv, DWORD dwBytes )
{
    PostQueuedCompletionStatus ( m_pShm->port, dwBytes, m_pShm->key, pOv );
}

//  Complete pOv with an error. P2PeerCon reads the slot's hr when the completion's own
//  status is S_OK, which a posted completion's always is
void
P2PeerioShm::Fail ( OVERLAPPED *pOv, DWORD dwError )
{
    reinterpret_cast<OVERLAPPEDcon *> ( pOv ) -> hr = (HRESULT)dwError;
    PostQueuedCompletionStatus ( m_pShm->port, 0, m_pShm->key, pOv );
}

void
P2PeerioShm::SignalPeer ( )
{
    p2pshm::WakeSignal ( m_pShm->peer );
}

//  Hand pWakeOv to the port: it comes back when the peer signals our wake
void
P2PeerioShm::ArmWake ( )
{
    P2PeerioShmState *s = m_pShm;
    if ( s->wakeArmed || s->dead || !s->pWakeOv )
      return;
    m_pCon -> prepareOVERLAPPED ( s->pWakeOv );
    bool bFired = false;
    if ( !p2pshm::WakeArm ( s->mine, s->port, s->key, (LPOVERLAPPED)s->pWakeOv, bFired ) )
    {
      m_pCon -> releaseOVERLAPPED ( s->pWakeOv );
      PeerGone ( ERROR_INVALID_DATA );
      return;
    }
    s->wakeArmed = true;
}

//  A 1-byte read on the pipe, outstanding for the life of the link: the peer never
//  writes to the pipe after the handshake, so it completes only when the peer's end
//  closes - its process exited or it dropped the link - or the peer misbehaves
void
P2PeerioShm::ArmDeath ( )
{
    P2PeerioShmState *s = m_pShm;
    if ( s->deathArmed || s->dead || !s->pDeathOv || !s->hPipe )
      return;
    m_pCon -> prepareOVERLAPPED ( s->pDeathOv );
    s->pDeathOv -> oOverlapped.Internal     = 0;
    s->pDeathOv -> oOverlapped.InternalHigh = 0;
    s->pDeathOv -> oOverlapped.Offset       = 0;
    s->pDeathOv -> oOverlapped.OffsetHigh   = 0;
    s->pDeathOv -> oOverlapped.hEvent       = 0;
    if ( !ReadFile ( s->hPipe, &s->deathByte, 1, 0, (OVERLAPPED *)s->pDeathOv ) &&
         GetLastError ( ) != ERROR_IO_PENDING )
    {
      m_pCon -> releaseOVERLAPPED ( s->pDeathOv );
      PeerGone ( ERROR_BROKEN_PIPE );
      return;
    }
    s->deathArmed = true;                      // TRUE (sync) still queues a completion
}

//  The link is over: fail whatever is parked, so the connection sees an error on the
//  slot it is waiting on and takes its ordinary drop path
void
P2PeerioShm::PeerGone ( DWORD dwError )
{
    P2PeerioShmState *s = m_pShm;
    s->dead = true;
    if ( s->rOv ) { OVERLAPPED *p = s->rOv; s->rOv = nullptr; Fail ( p, dwError ); }
    if ( s->wOv ) { OVERLAPPED *p = s->wOv; s->wOv = nullptr; Fail ( p, dwError ); }
}

//  Move whatever can move now; park (and arm the wake) for whatever cannot
void
P2PeerioShm::Service ( )
{
    P2PeerioShmState *s = m_pShm;
    for ( int guard = 0; guard < 64 && !s->dead; ++guard )
    {
      bool bNeedWake = false, bProgress = false;

      // The parked write: all of it, or park on a full ring
      if ( s->wOv )
      {
        uint32_t k = 0; bool bWakeReader = false;
        p2pshm::Put r = p2pshm::RingWrite ( *s->out, s->wBuf, s->wLeft, k, bWakeReader );
        if ( r == p2pshm::Put::Bad ) { PeerGone ( ERROR_INVALID_DATA ); return; }
        if ( r == p2pshm::Put::Ok )
        {
          if ( bWakeReader ) SignalPeer ( );
          s->wBuf += k; s->wLeft -= k; bProgress = true;
          if ( !s->wLeft )
          {
            OVERLAPPED *p = s->wOv; DWORD n = s->wTotal;
            s->wOv = nullptr;
            Complete ( p, n );
          }
        }
        else if ( p2pshm::WriterPark ( *s->out ) )
          bNeedWake = true;
      }

      // The parked read: >= 1 byte, or park on an empty ring
      if ( s->rOv )
      {
        uint32_t k = 0; bool bWakeWriter = false;
        p2pshm::Get r = p2pshm::RingRead ( *s->in, s->rBuf, s->rCap, k, bWakeWriter );
        if ( r == p2pshm::Get::Bad ) { PeerGone ( ERROR_INVALID_DATA ); return; }
        if ( r == p2pshm::Get::Ok )
        {
          if ( bWakeWriter ) SignalPeer ( );
          OVERLAPPED *p = s->rOv;
          s->rOv = nullptr;
          Complete ( p, k );
          bProgress = true;
        }
        else if ( p2pshm::ReaderPark ( *s->in ) )
          bNeedWake = true;
      }

      if ( bNeedWake && !bProgress )
      {
        ArmWake ( );
        return;
      }
      if ( !s->wOv && !s->rOv )
        return;                                // nothing parked
      // Progress made or a park withdrawn (the ring moved meanwhile): go round again
    }
    // Bounded: a ring moving under us every pass is a busy peer, not a reason to spin
    // the pump. Wait for the next signal
    if ( !s->dead && (s->wOv || s->rOv) )
      ArmWake ( );
}

///////////////////////////////////////////////////////////////////////
//  Transport byte I/O

BOOL
P2PeerioShm::IoWrite ( HANDLE hFile, const void *pvData, DWORD dwSize, OVERLAPPED *pOv )
{
    UNREFERENCED_PARAMETER(hFile);
    P2PeerioShmState *s = m_pShm;
    if ( !s || s->dead )      { SetLastError ( ERROR_BROKEN_PIPE ); return FALSE; }
    if ( s->wOv || !dwSize )  { SetLastError ( ERROR_BUSY );        return FALSE; }
    s->wOv    = pOv;
    s->wBuf   = static_cast<const BYTE *> ( pvData );
    s->wLeft  = dwSize;
    s->wTotal = dwSize;
    Service ( );
    SetLastError ( ERROR_IO_PENDING );         // a completion follows, as for WriteFile
    return FALSE;
}

BOOL
P2PeerioShm::IoRead ( HANDLE hFile, void *pvData, DWORD dwSize, OVERLAPPED *pOv )
{
    UNREFERENCED_PARAMETER(hFile);
    P2PeerioShmState *s = m_pShm;
    if ( !s || s->dead )      { SetLastError ( ERROR_BROKEN_PIPE ); return FALSE; }
    if ( s->rOv || !dwSize )  { SetLastError ( ERROR_BUSY );        return FALSE; }
    s->rOv  = pOv;
    s->rBuf = static_cast<BYTE *> ( pvData );
    s->rCap = dwSize;
    Service ( );
    SetLastError ( ERROR_IO_PENDING );
    return FALSE;
}

///////////////////////////////////////////////////////////////////////
//  IOCP Integration

bool
P2PeerioShm::On_QueuedCompletionStatus ( DWORD dwError, DWORD dwBytes
                                       , OVERLAPPEDcon *pOVERLAPPEDcon )
{
    P2PeerioShmState *s = m_pShm;

    // Ours, after the link was detached: a cancellation arriving late. Give it back
    for ( int i = 0; i < 2; ++i )
      if ( pOVERLAPPEDcon && pOVERLAPPEDcon == m_pLate[i] )
      {
        m_pLate[i] = nullptr;
        m_pCon -> releaseOVERLAPPED ( pOVERLAPPEDcon );
        m_pCon -> DropOVERLAPPED ( pOVERLAPPEDcon, false );
        return true;
      }
    if ( !s )
      return P2Peerio::On_QueuedCompletionStatus ( dwError, dwBytes, pOVERLAPPEDcon );

    // The peer signalled our wake: move what is parked
    if ( pOVERLAPPEDcon == s->pWakeOv )
    {
      s->wakeArmed = false;
      m_pCon -> releaseOVERLAPPED ( pOVERLAPPEDcon );
      if ( dwError == S_OK && pOVERLAPPEDcon->hr == S_OK && !s->dead )
      {
        p2pshm::WakeConsume ( s->mine );
        Service ( );
      }
      return true;
    }

    // The pipe's death watch completed: the peer's end closed (or it wrote on a pipe it
    // must not write on). Either way the link is over
    if ( pOVERLAPPEDcon == s->pDeathOv )
    {
      s->deathArmed = false;
      m_pCon -> releaseOVERLAPPED ( pOVERLAPPEDcon );
      PeerGone ( ERROR_BROKEN_PIPE );
      return true;
    }

    return P2Peerio::On_QueuedCompletionStatus ( dwError, dwBytes, pOVERLAPPEDcon );
}

bool
P2PeerioShm::HasQueuedOwnOVERLAPPED ( ) const
{
    for ( OVERLAPPEDcon *p : m_pLate )
      if ( p && p->bQueued ) return true;
    return m_pShm && ( (m_pShm->pWakeOv  && m_pShm->pWakeOv->bQueued ) ||
                       (m_pShm->pDeathOv && m_pShm->pDeathOv->bQueued) );
}

void
P2PeerioShm::ForgetOwnOVERLAPPED ( OVERLAPPEDcon *pOVERLAPPEDcon )
{
    for ( OVERLAPPEDcon *&p : m_pLate )
      if ( p == pOVERLAPPEDcon ) p = nullptr;
    if ( !m_pShm )
      return;
    if ( pOVERLAPPEDcon == m_pShm->pWakeOv )  { m_pShm->pWakeOv  = nullptr; m_pShm->wakeArmed  = false; }
    if ( pOVERLAPPEDcon == m_pShm->pDeathOv ) { m_pShm->pDeathOv = nullptr; m_pShm->deathArmed = false; }
}
