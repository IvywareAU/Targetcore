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
//  P2PeerConShm - refer P2PeerConShm.h and p2p_performance.md §6.3a.
//
#include "stdafx.h"
#include "P2PeerConShm.h"
#include "P2PeerioShm.h"
#include "P2PeerioShmState.h"
#include "Msgexception.h"

namespace
{
    //  The hello, accepter -> dialler, over the pipe. Windows carries the three handle
    //  VALUES already duplicated into the dialler's process; Linux carries the three
    //  descriptors beside it (SCM_RIGHTS) and the handle fields are zero
    struct ShmHello
    {
        uint32_t magic;        // p2pshm::kMagic
        uint32_t version;      // p2pshm::kVersion
        uint32_t ringBytes;    // p2pshm::kRingBytes
        uint32_t reserved;
        uint64_t hMap;         // the section
        uint64_t hWakeDialler; // the dialler WAITS on this one
        uint64_t hWakeAccepter;// the dialler SIGNALS this one
    };

    const DWORD kHelloTimeoutMs = 5000;

#if defined(_WIN32)
    //  Synchronous I/O on a pipe handle that is bound to a completion port, WITHOUT a
    //  packet reaching that port: the low bit of hEvent says so (documented for
    //  GetQueuedCompletionStatus). Whole buffer or false, within ms
    bool
    PipeIoSync ( HANDLE h, void *pv, DWORD n, bool bWrite, DWORD ms )
    {
        HANDLE ev = CreateEventW ( nullptr, TRUE, FALSE, nullptr );
        if ( !ev ) return false;
        BYTE *p = static_cast<BYTE *> ( pv );
        const ULONGLONG tEnd = GetTickCount64 ( ) + ms;
        bool ok = true;
        while ( n && ok )
        {
          OVERLAPPED ov {};
          ov.hEvent = (HANDLE)((ULONG_PTR)ev | 1);
          ResetEvent ( ev );
          DWORD got = 0;
          BOOL r = bWrite ? WriteFile ( h, p, n, nullptr, &ov ) : ReadFile ( h, p, n, nullptr, &ov );
          if ( !r && GetLastError ( ) != ERROR_IO_PENDING ) { ok = false; break; }
          ULONGLONG now = GetTickCount64 ( );
          DWORD left = now >= tEnd ? 0 : (DWORD)(tEnd - now);
          if ( WaitForSingleObject ( ev, left ) != WAIT_OBJECT_0 )
          {
            CancelIoEx ( h, &ov );
            GetOverlappedResult ( h, &ov, &got, TRUE );
            ok = false; break;
          }
          if ( !GetOverlappedResult ( h, &ov, &got, FALSE ) || got == 0 ) { ok = false; break; }
          p += got; n -= got;
        }
        CloseHandle ( ev );
        return ok;
    }
#else
    int
    RawFd ( HANDLE h )
    {
        return h ? h->fd.load ( std::memory_order_acquire ) : -1;
    }
#endif
}

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

P2PeerConShm::P2PeerConShm ( )
  : P2PeerConPipe ( )
{
}

P2PeerConShm::~P2PeerConShm ( )
{
}

bool
P2PeerConShm::IsSupported ( )
{
    return p2pshm::WakeSupported ( );
}

P2PeerConShm*
P2PeerConShm::ServiceFactory ( P2PaddrSTR strP2PaddrThat, LPCTSTR lpszPipename )
{
    P2PeerConShm *pCon = new P2PeerConShm ( );
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_oP2Padomain    = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_SERVICE;
    pCon -> m_sPipename      = lpszPipename;
    pCon -> SetP2Peerio ( new P2PeerioShm ( ) );   // cloned for accepted connections
    return pCon;
}

P2PeerConShm*
P2PeerConShm::ClientFactory ( P2PaddrSTR strP2PaddrThat, LPCTSTR lpszPipename )
{
    P2PeerConShm *pCon = new P2PeerConShm ( );
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_CLIENT;
    pCon -> m_sPipename      = lpszPipename;
    pCon -> SetP2Peerio ( new P2PeerioShm ( ) );
    return pCon;
}

//  The spawn is a shared-memory service too; the pipe class does the rest
P2PeerCon*
P2PeerConShm::AcceptSpawn ( P2PeerCon *pConSpawn )
{
    if ( pConSpawn == NULL )
      pConSpawn = new P2PeerConShm ( );
    return P2PeerConPipe::AcceptSpawn ( pConSpawn );
}

///////////////////////////////////////////////////////////////////////
//  Teardown

void
P2PeerConShm::ShmDetach ( )
{
    P2PeerioShm *pIo = dynamic_cast<P2PeerioShm *> ( m_pP2Peerio );
    if ( pIo )
      pIo -> DetachShm ( );
}

//  The link first (it withdraws the wake and releases the mapping), then the pipe,
//  whose close aborts the death watch
void
P2PeerConShm::Drop ( P2Pevent *pEVENT )
{
    ShmDetach ( );
    P2PeerConPipe::Drop ( pEVENT );
}

BOOL
P2PeerConShm::OnClose ( )
{
    ShmDetach ( );
    return P2PeerConPipe::OnClose ( );
}

///////////////////////////////////////////////////////////////////////
//  The handshake

//  ACCEPTING end. The pipe class has done the cap check, the role swap and POSTED the
//  first recv arm - which runs on this same pump after we return, so the link is
//  attached before the connection's first read
P2PeerCon*
P2PeerConShm::OnAccept ( )
{
    P2PeerCon *pService = P2PeerConPipe::OnAccept ( );
    if ( m_eP2PeerConMode != P2PeerCon_Accept || !m_hFile )
      return pService;                         // refused at capacity: still the service
    try                      { ShmOffer ( ); }
    catch ( P2Pevent *pEVT ) { Drop ( pEVT ); }
    return pService;
}

//  DIALLING end. The pipe class has opened the pipe, bound it to the port and POSTED
//  the connect completion, which runs after we return
bool
P2PeerConShm::Connect ( )
{
    bool bResult = P2PeerConPipe::Connect ( );
    try                      { ShmAccept ( ); }
    catch ( P2Pevent *pEVT ) { Drop ( pEVT ); }
    return bResult;
}

void
P2PeerConShm::ShmOffer ( )
{
    if ( !IsSupported ( ) )
      EVERR->MODULE->Message_T ( "Shared-memory transport unsupported on this platform" )
           ->Advice_T ( "Windows needs NtAssociateWaitCompletionPacket (Windows 8+)" )->Throw ( );
    P2PeerioShm *pIo = dynamic_cast<P2PeerioShm *> ( m_pP2Peerio );
    if ( !pIo )
      EVERR->MODULE->Message_T ( "P2PeerConShm without a P2PeerioShm" )->Throw ( );

    P2PeerioShmState *s = new P2PeerioShmState ( );
    if ( !p2pshm::MappingCreate ( s->map ) )
    { delete s; EVERR->MODULE->Message_T ( "Shared mapping could not be created" )->HResult ( GetLastError ( ) )->Throw ( ); }
    s->in  = &s->map.view->ring[1];            // dialler -> accepter
    s->out = &s->map.view->ring[0];            // accepter -> dialler

    ShmHello hello {};
    hello.magic = p2pshm::kMagic; hello.version = p2pshm::kVersion; hello.ringBytes = p2pshm::kRingBytes;

#if defined(_WIN32)
    ULONG pid = 0;
    HANDLE hProc = nullptr, evDial = nullptr, evAcc = nullptr;
    bool ok = GetNamedPipeClientProcessId ( m_hFile, &pid ) && pid
           && ( hProc  = OpenProcess ( PROCESS_DUP_HANDLE, FALSE, pid ) ) != nullptr
           && ( evDial = CreateEventW ( nullptr, FALSE, FALSE, nullptr ) ) != nullptr
           && ( evAcc  = CreateEventW ( nullptr, FALSE, FALSE, nullptr ) ) != nullptr;
    HANDLE rMap = nullptr, rDial = nullptr, rAcc = nullptr;
    if ( ok )
    {
      rMap  = p2pshm::DuplicateInto ( hProc, s->map.h );
      rDial = p2pshm::DuplicateInto ( hProc, evDial );
      rAcc  = p2pshm::DuplicateInto ( hProc, evAcc );
      ok = rMap && rDial && rAcc;
    }
    if ( hProc ) CloseHandle ( hProc );
    if ( ok ) { s->peer = evDial; evDial = nullptr; }
    if ( ok ) { ok = p2pshm::WakeAttach ( s->mine, evAcc ); evAcc = nullptr; }
    if ( evDial ) CloseHandle ( evDial );
    if ( evAcc )  CloseHandle ( evAcc );
    if ( ok )
    {
      hello.hMap = (uint64_t)(uintptr_t)rMap; hello.hWakeDialler = (uint64_t)(uintptr_t)rDial;
      hello.hWakeAccepter = (uint64_t)(uintptr_t)rAcc;
      ok = PipeIoSync ( m_hFile, &hello, sizeof hello, true, kHelloTimeoutMs );
    }
#else
    const int sock = RawFd ( m_hFile );
    int efdDial = eventfd ( 0, EFD_NONBLOCK | EFD_CLOEXEC );
    bool ok = sock >= 0 && efdDial >= 0 && p2pshm::WakeCreate ( s->mine );
    if ( ok )
    {
      const int fds[3] = { s->map.fd, efdDial, p2pshm::WakeFd ( s->mine ) };
      ok = p2pshm::SendFds ( sock, fds, 3, &hello, sizeof hello );
    }
    if ( ok ) s->peer = efdDial;
    else if ( efdDial >= 0 ) ::close ( efdDial );
#endif
    if ( !ok )
    { delete s; EVERR->MODULE->Message_T ( "Shared-memory hello could not be sent" )->HResult ( GetLastError ( ) )->Throw ( ); }

    s->port = m_hCPort; s->key = m_dwCompletionKey; s->hPipe = m_hFile;
    if ( !pIo->AttachShm ( s ) )               // takes s either way
      EVERR->MODULE->Message_T ( "Shared-memory link could not be attached" )->Throw ( );
}

void
P2PeerConShm::ShmAccept ( )
{
    if ( !m_hFile )
      return;                                  // the pipe class already failed and dropped
    if ( !IsSupported ( ) )
      EVERR->MODULE->Message_T ( "Shared-memory transport unsupported on this platform" )
           ->Advice_T ( "Windows needs NtAssociateWaitCompletionPacket (Windows 8+)" )->Throw ( );
    P2PeerioShm *pIo = dynamic_cast<P2PeerioShm *> ( m_pP2Peerio );
    if ( !pIo )
      EVERR->MODULE->Message_T ( "P2PeerConShm without a P2PeerioShm" )->Throw ( );

    ShmHello hello {};
    P2PeerioShmState *s = new P2PeerioShmState ( );
    bool ok = false;
#if defined(_WIN32)
    ok = PipeIoSync ( m_hFile, &hello, sizeof hello, false, kHelloTimeoutMs )
      && hello.magic == p2pshm::kMagic && hello.version == p2pshm::kVersion
      && hello.ringBytes == p2pshm::kRingBytes;
    if ( ok )
    {
      //  The values name handles the server put into THIS process. A hostile server can
      //  only hand us handles it owns: the mapping is still checked (BlockValid), a wake
      //  that is not an event fails to associate, a bad peer handle fails to signal
      //  MappingOpen keeps the handle even when it fails; the state's destructor closes it
      ok = p2pshm::MappingOpen ( s->map, (HANDLE)(uintptr_t)hello.hMap );
      if ( ok ) ok = p2pshm::WakeAttach ( s->mine, (HANDLE)(uintptr_t)hello.hWakeDialler );
      else      CloseHandle ( (HANDLE)(uintptr_t)hello.hWakeDialler );
      s->peer = (HANDLE)(uintptr_t)hello.hWakeAccepter;
    }
#else
    int fds[3] = { -1, -1, -1 };
    const int sock = RawFd ( m_hFile );
    ok = sock >= 0 && p2pshm::RecvFds ( sock, fds, 3, &hello, sizeof hello, (int)kHelloTimeoutMs )
      && hello.magic == p2pshm::kMagic && hello.version == p2pshm::kVersion
      && hello.ringBytes == p2pshm::kRingBytes;
    if ( ok )
    {
      ok = p2pshm::MappingOpen ( s->map, fds[0] );   // checks size and seals; keeps the fd either way
      if ( ok ) ok = p2pshm::WakeAttach ( s->mine, fds[1] );
      else      ::close ( fds[1] );
      s->peer = fds[2];
    }
    else
      for ( int fd : fds ) if ( fd >= 0 ) ::close ( fd );
#endif
    if ( !ok )
    { delete s; EVERR->MODULE->Message_T ( "Shared-memory hello missing or invalid" )->Throw ( ); }
    s->in  = &s->map.view->ring[0];            // accepter -> dialler
    s->out = &s->map.view->ring[1];            // dialler -> accepter
    s->port = m_hCPort; s->key = m_dwCompletionKey; s->hPipe = m_hFile;
    if ( !pIo->AttachShm ( s ) )
      EVERR->MODULE->Message_T ( "Shared-memory link could not be attached" )->Throw ( );
}
