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
//  Description: P2PeerCon232 implementation
//               NOTES: Manages P2Peer RS232 connections
//

#include "stdafx.h"
#include "P2PeerCon232.h"
#include "P2Pwin32.h"

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

const __time64_t
iLoginTimeoutSeconds = 20;             // Login sequences must be
                                       //   processed within this time

P2PeerCon232::P2PeerCon232 ( )
{
    // Firstly
    RenderThisSafe ( );
}

//
//  Parameters: P2PaddrSTR strThatP2Paddr
//              Identification address for that, or the other end
//
//              DWORD oSocket
//              Socket upon which connection accepted
//
//
//              short nComPort
//              Serial connection port COM1, COM2 etc.
//
P2PeerCon232::P2PeerCon232 ( P2PaddrSTR pThatP2PaddrSTR
                           , short nComPort, P2Peerio *pP2Peerio )
            : P2PeerCon ( pThatP2PaddrSTR, pP2Peerio )
{
    // Firstly
    RenderThisSafe ( );
    SetComPort ( nComPort );
}

//
//               short nIPort
//               Listening port
//
P2PeerCon232::P2PeerCon232 ( short nComPort
                           , P2Peerio *pP2Peerio )
            : P2PeerCon ( pP2Peerio )
{
    // Firstly
    RenderThisSafe ( );
    SetComPort ( nComPort );
}

P2PeerCon232::~P2PeerCon232 ( )
{
    Drop ( 0 );
}

void
P2PeerCon232::RenderThisSafe ( )
{
    // Attributes
    m_hFileCOM    = 0;
    m_hEventHub   = 0;
    m_pP2Peerio   = 0;
    m_nComPort    = 0;
    m_dwCommEvent = 0;
}

//
//  Description: Assigns the COM port number AND the win32 device path
//               opened by Listen()/Connect()
//               NOTES: The \\.\COMn form is mandatory for ports > 9
//                      and legal for all
//
//
//  Parameters:  short nComPort
//               Serial connection port COM1, COM2 etc.
//
void
P2PeerCon232::SetComPort ( short nComPort )
{
    m_nComPort = nComPort;
    m_sFileCOM.Format ( _T("\\\\.\\COM%d"), (int)nComPort );
}

P2PeerCon232*
P2PeerCon232::ServiceFactory ( P2PaddrSTR strP2PaddrThat
                             , short nComPort )
{
    // Instanciate
    P2PeerCon232 *pCon = new P2PeerCon232 ( );

    // Attributes
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_oP2Padomain    = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_SERVICE;
    pCon -> SetComPort       ( nComPort );

    // Protocol
    // NOTES: Instance is cloned for accepted connections
    pCon -> SetP2Peerio ( new P2Peerio( ) );

    // Done
    return pCon;
}

P2PeerCon232*
P2PeerCon232::ClientFactory ( P2PaddrSTR strP2PaddrThat
                            , short nComPort )
{
    // Instanciate
    P2PeerCon232 *pCon = new P2PeerCon232 ( );

    // Attributes
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_CLIENT;
    pCon -> SetComPort       ( nComPort );

    // Protocol
    pCon -> SetP2Peerio ( new P2Peerio( ) );

    // Done
    return pCon;
}

//
//  Splits listening connection into listening and accepted
//  P2PeerCon'nections
//  NOTES: Derived classes must delegate
//
//
//  Parameters:  P2PeerCon **pConListen = 0
//               Previously manufactured listening instance
//
//               P2PeerCon **pConAccept = 0
//               Previously manufactured accept instance
//
P2PeerCon*
P2PeerCon232::AcceptSpawn ( P2PeerCon *pConSpawn )
{
    // Instanciation etc
    if ( pConSpawn == NULL )
      pConSpawn = new P2PeerCon232 ( );

    // Settlement
    // NOTES: Serial mirrors the pipe morph — the listening object keeps
    //        the open COM handle and becomes the accepted connection;
    //        the spawn takes over the (now nominal) SERVICE role. A COM
    //        port is strictly point-to-point, so the replacement
    //        service owns no handle and never re-listens (Accept()
    //        leaves it idle).
    P2PeerCon232 *pConSpawn232 = (P2PeerCon232 *)pConSpawn;
    P2PeerCon::AcceptSpawn ( pConSpawn );
    pConSpawn232 -> m_nComPort        = m_nComPort;
    pConSpawn232 -> m_sFileCOM        = m_sFileCOM;
    pConSpawn232 -> m_eP2PeerConMode  = P2PeerCon_SERVICE;
            this -> m_eP2PeerConMode  = P2PeerCon_Accept;

    // Done
    // NOTES: Spawned object is free floating
    return pConSpawn;
}

///////////////////////////////////////////////////////////////////////
//  IOCP Integration
//

//
//  Description: Processes IO completion status
//               NOTES:
//
//
//  Parameters:  DWORD dwError
//               Error code associated with operation
//               
//               DWORD dbBytes
//               Bytes transferred during completed I/O operation.
//
//               OVERLAPPEDcon pOVERLAPPEDcon
//               Address of OVERLAPPEDcon structure that was specified
//               for the I/O operation
//
/*bool
P2PeerCon232::On_QueuedCompletionStatus ( DWORD dwError
                                        , DWORD dwBytes
                                        , OVERLAPPEDcon *pOVERLAPPEDcon )
{
    // Pre-processing
    HRESULT hr = dwError;
    if ( hr == S_OK )
      hr = pOVERLAPPEDcon -> hr;

    // Because this is all problematic we
    try
    {
      // Accept
      // NOTES: Perform On_P2PeerCon_ACCEPT() notification.  At which
      //        point the intercepting handler will initiate state
      //        changes.
      if ( pOVERLAPPEDcon == m_pOVERLAPPEDaccept )
      {
        releaseOVERLAPPED ( pOVERLAPPEDcon );
        if ( hr )
          EVERR->Module ("%s[%s-%s]", __FUNCTION__
                        , EncodeP2PeerID(m_oThisP2Paddr)
                        , EncodeP2PeerID(m_oThatP2Paddr) )
               ->Message("Overlapped accept failed")
               ->HResult( hr ) -> Throw();
      }

      // Connect
      // NOTES: Perform On_P2PeerCon_CONNECT() notification.  At which
      //        point the intercepting handler will initiate the
      //        appropriate state changes.
      else if ( pOVERLAPPEDcon == m_pOVERLAPPEDconnect )
      {
        releaseOVERLAPPED ( pOVERLAPPEDcon );
        if ( hr )
          EVERR->Module  ("%s(%s-%s)", __FUNCTION__
                         , EncodeP2PeerID(m_oThisP2Paddr)
                         , EncodeP2PeerID(m_oThatP2Paddr) )
               ->Message ("Overlapped ConnectEx failed")
               ->WSAGROUP( hr ) -> Throw();

        // On_P2PeerCon_CONNECT() notification
        // NOTES: Send() and Recv() buffers required beyond this point
        if ( m_pOVERLAPPEDsend == NULL )
          m_pOVERLAPPEDsend = MakeOVERLAPPED (  );
        if ( m_pOVERLAPPEDrecv == NULL )
          m_pOVERLAPPEDrecv = MakeOVERLAPPED ( MAX_P2Psize );

        PostP2Pmsg  ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Connect
                    , this, (P2PeerMsg *)0 );
      }

      // Delegate
      else
        P2PeerCon::On_QueuedCompletionStatus ( dwError, dwBytes, pOVERLAPPEDcon );
    }

    // Exceptions
    // NOTES: Notification will eventually be routed through to
    //        ON_P2PeerCon_CLOSE() handler. At which point Restart()
    //        may be used on non accepted sockets or this object
    //        conDROP'ed
    //      : ON_P2PeerCon_CLOSE() handler to which this posted object
    //        is routed MUST cancel the attached event.  OnClose()
    //        contains such default processing.
    //      : P2P_Close notification MUST be performed once per
    //        attached event. Subsequent P2P_Close notifications are
    //        blocked until the original event is cancelled.
    catch ( P2Pevent *pEVENT )
    {
      Drop ( pEVENT->Isolate() );
    }

    // Tidy up and
    return true;
}*/

//
//  Description: Drops the encapsulated connection and performs the
//               appropriate ON_P2PeerCon_CLOSE() notification
//               NOTES: Should an EVENT already be attached the passed
//                      EVENT is simply cancelled.
//
//
//  Parameters:  P2Pevent *pEVENT
//               Precipitating event.  May be NULL
//               NOTES: Control assumed over life cycle.
//
void
P2PeerCon232::Drop ( P2Pevent *pEVENT )
{
    // Firstly drop socket
    // NOTES: Cancels all outstanding overlapped IO
    if ( m_hFileCOM )
    {
      if (     CloseHandle(m_hFileCOM) &&
             !pEVENT                      )
        pEVENT =
         EVERR->Module  (L"%hs(%s-%s)", __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , (P2PaddrSTR)m_oThatP2Paddr )
              ->Message (L"closehandle(%s) failed\n"
                         L"ADVICE\t: Bug (SNHappen)"
                        , (LPCTSTR)m_sFileCOM )
              ->HResult ( GetLastError() );
      m_hFileCOM   = 0;
      m_hFile      = 0;
      m_hFileCPort = 0;
    }

    // Always delegate
    P2PeerCon::Drop ( pEVENT );
}

///////////////////////////////////////////////////////////////////////
//  Connection state management
//  NOTES: Referenced from P2PeerCon_MAP handlers only

//
//  Description: Applies the serial line discipline to the freshly
//               opened COM handle
//               NOTES: 115200 8N1, no flow control. COMMTIMEOUTS use
//                      the documented Interval=MAXDWORD /
//                      Multiplier=MAXDWORD / 0<Constant<MAXDWORD
//                      combination so an overlapped ReadFile()
//                      completes as soon as ANY bytes are buffered —
//                      without it a MAX_P2Psize read would inherit
//                      whatever timeouts the last application left on
//                      the port and typically never complete.
//
void
P2PeerCon232::ConfigureComPort ( )
{
    // Line parameters
    DCB oDCB;
    ZeroMemory ( &oDCB, sizeof(oDCB) );
    oDCB.DCBlength = sizeof(oDCB);
    if ( !GetCommState ( m_hFileCOM, &oDCB ) )
      EVERR->MODULE
           ->Message(L"GetCommState(%s) failed", (LPCTSTR)m_sFileCOM )
           ->HResult( GetLastError() )->Throw();
    oDCB.BaudRate      = CBR_115200;
    oDCB.ByteSize      = 8;
    oDCB.Parity        = NOPARITY;
    oDCB.StopBits      = ONESTOPBIT;
    oDCB.fBinary       = TRUE;
    oDCB.fParity       = FALSE;
    oDCB.fOutxCtsFlow  = FALSE;
    oDCB.fOutxDsrFlow  = FALSE;
    oDCB.fDtrControl   = DTR_CONTROL_ENABLE;
    oDCB.fRtsControl   = RTS_CONTROL_ENABLE;
    oDCB.fOutX         = FALSE;
    oDCB.fInX          = FALSE;
    oDCB.fNull         = FALSE;
    oDCB.fAbortOnError = FALSE;
    if ( !SetCommState ( m_hFileCOM, &oDCB ) )
      EVERR->MODULE
           ->Message(L"SetCommState(%s) failed", (LPCTSTR)m_sFileCOM )
           ->HResult( GetLastError() )->Throw();

    // Read completes on first buffered byte(s); writes never time out
    COMMTIMEOUTS oTimeouts;
    ZeroMemory ( &oTimeouts, sizeof(oTimeouts) );
    oTimeouts.ReadIntervalTimeout         = MAXDWORD;
    oTimeouts.ReadTotalTimeoutMultiplier  = MAXDWORD;
    oTimeouts.ReadTotalTimeoutConstant    = MAXDWORD - 1;
    if ( !SetCommTimeouts ( m_hFileCOM, &oTimeouts ) )
      EVERR->MODULE
           ->Message(L"SetCommTimeouts(%s) failed", (LPCTSTR)m_sFileCOM )
           ->HResult( GetLastError() )->Throw();

    // Driver buffer sizing — advisory
    SetupComm ( m_hFileCOM, MAX_P2Psize, MAX_P2Psize );
}

//
//  Description: Initiates listen processing for object.
//               NOTES: Referenced from On_P2PeerCon_STARTUP handlers
//                      for listen type objects.
//
//
//  Returns:     bool
//               Listen summary
//
bool
P2PeerCon232::Listen ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Startup) )
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message(L"Requires ON_P2PeerCon_STARTUP handler state\n"
                     L"ADVICE\t: Bug (SNHappen)" )
           ->Throw  ( );

    // Open COM port
    // NOTES: FILE_FLAG_OVERLAPPED is mandatory when using IO
    //        completion ports
    m_hFileCOM = CreateFile ( (LPCTSTR)m_sFileCOM
                            , GENERIC_READ | GENERIC_WRITE
                            , 0    // exclusive access 
                            , NULL // no security attributes 
                            , OPEN_EXISTING
                            , FILE_FLAG_OVERLAPPED
                            , NULL );
    if ( m_hFileCOM == INVALID_HANDLE_VALUE )
    {
      m_hFileCOM = 0;
      EVERR->MODULE
           ->Message(L"CreateFile(%s) failed\n"
                     L"ADVICE\t: Check assignment for %s"
                    , (LPCTSTR)m_sFileCOM, (LPCTSTR)m_sFileCOM )
           ->HResult( GetLastError() )->Throw();
    }

    // Associate with IO Completion Port
    // NOTES: All subsequent notifications received via queued
    //        IO Completion Packets
    CreateIOCP ( m_hFileCOM );
    //m_hFileCPort = CreateIoCompletionPort ( m_hFileCOM
    //                                      , m_hCPort
    //                                      ,(ULONG_PTR)(P2PeerCon *)this
    //                                      , 0 );
    //if ( m_hFileCPort == 0 )
    //  EVERR->Module  ("%s(%s-%s)", __FUNCTION__
    //                 , EncodeP2PeerID(m_oThisP2Paddr)
    //                 , EncodeP2PeerID(m_oThatP2Paddr) )
    //       ->Message ("CreateIoCompletionPort() failed")
    //       ->HResult ( GetLastError() )->Throw();
    //m_hFile = m_hFileCOM;

    // Serial line discipline
    ConfigureComPort ( );

    // On_P2PeerCon_LISTEN() notification
    // NOTES: The default ON_P2PeerCon_LISTEN handler runs OnListen()
    //        then Accept(), which arms the WaitCommEvent() wait for
    //        the first inbound data — serial's accept
    PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Listen
               , this, (P2PeerMsg *)0, m_hCPortP2PumpID );

    // Tidy up and
    return true;
}

//
//  Description: Initiates accept facility for object.
//               NOTES: Referenced from the ON_P2PeerCon_LISTEN default
//                      handler, and again (via the service re-arm tail
//                      of ON_P2PeerOLD_ACCEPT) on the morph-spawned
//                      replacement service.
//                    : A COM port has no accept concept — the first
//                      inbound data IS the accept. WaitCommEvent()
//                      pends on EV_RXCHAR against the IOCP; its
//                      completion drives the base accept path
//                      (P2P_Accept -> OnAccept() morph).
//                    : The morph-spawned replacement service owns no
//                      COM handle (the session keeps it; a serial link
//                      is point-to-point) and is deliberately left
//                      idle rather than failed.
//
//
//  Returns:     bool
//
bool
P2PeerCon232::Accept ( )
{
    // Delegate for state confirmation
    P2PeerCon::Accept ( );

    // Morph-spawned replacement service: nothing to re-listen on
    if ( !m_hFileCOM )
      return true;

    // To be sure, to be sure
    if ( m_pOVERLAPPEDaccept         &&
         m_pOVERLAPPEDaccept->bQueued    )
      EVERR->Module (L"%hs[%s-%s]", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Message(L"Duplicate accepts attempted on single connection"
                    ,L"ADVICE\t: Bug (SNHappen)" )
           ->Throw();

    // Initiate wait for first inbound data
    // NOTES: The handle is IOCP-bound, so a synchronous TRUE return
    //        still queues the completion packet (FILE_SKIP_
    //        COMPLETION_PORT_ON_SUCCESS is never set)
    if ( m_pOVERLAPPEDaccept == NULL )
      m_pOVERLAPPEDaccept = MakeOVERLAPPED ( );
    if ( !SetCommMask ( m_hFileCOM, EV_RXCHAR ) )
      EVERR->MODULE
           ->Message(L"SetCommMask(%s) failed", (LPCTSTR)m_sFileCOM )
           ->HResult( GetLastError() )->Throw();
    prepareOVERLAPPED ( m_pOVERLAPPEDaccept );
    if ( !WaitCommEvent ( m_hFileCOM, &m_dwCommEvent
                        ,(OVERLAPPED *)m_pOVERLAPPEDaccept ) &&
          GetLastError() != ERROR_IO_PENDING                    )
    {
      releaseOVERLAPPED ( m_pOVERLAPPEDaccept );
      EVERR->Module  (L"%hs(%s-%s)", __FUNCTION__
                     , GetP2PaddrHub().c_wstr()
                     , m_oThatP2Paddr.c_wstr() )
           ->Message (L"WaitCommEvent(%s) failed", (LPCTSTR)m_sFileCOM )
           ->HResult ( GetLastError() )->Throw();
    }

    // Done
    return true;
}

//
//  Performs ACCEPT'ed connection processing
//  NOTES: Serial mirrors the pipe morph — this listening object keeps
//         the open COM handle and becomes the accepted session; the
//         spawn becomes the (idle) replacement service.
//       : Reference from within ON_P2PeerOLD_ACCEPT() handlers
//
//
//  Returns:     P2PeerCon*
//               Morph-spawned replacement SERVICE object
//
P2PeerCon*
P2PeerCon232::OnAccept ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept) )
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Message(L"Requires ON_P2PeerOLD_ACCEPT handler state")
           ->Advice (L"Bug (SNHappen)" )
           ->Throw  ( );

    // Mode confirmation
    if ( m_eP2PeerConMode != P2PeerCon_SERVICE )
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message(L"Requires P2PeerCon_SERVICE mode not %i"
                    , m_eP2PeerConMode )
           ->Advice (L"Bug (SNHappen)" )
           ->Throw  ( );

    // Spawn replacement service; this object morphs into the session
    // NOTES: Roles are swapped exactly as P2PeerConPipe::OnAccept()
    P2PeerCon232 *pConAccept  = this;
    P2PeerCon    *pConService = AcceptSpawn ( 0 );

    // Activate P2PeerMsg receipt on the morphed session
    // NOTES: Action is negated whenever OVERLAPPEDrecv object already
    //        exists. The posted recv drains the login bytes that
    //        completed the WaitCommEvent() wait.
    if ( !pConAccept->m_pOVERLAPPEDsend )
      pConAccept -> m_pOVERLAPPEDsend = pConAccept -> MakeOVERLAPPED ( );
    if ( !pConAccept->m_pOVERLAPPEDrecv )
      pConAccept -> m_pOVERLAPPEDrecv = pConAccept -> MakeOVERLAPPED ( MAX_P2Psize );
    if ( !pConAccept->m_pOVERLAPPEDrecv->bQueued )
      pConAccept -> PostOVERLAPPED ( pConAccept->m_pOVERLAPPEDrecv );

    // Tidy up, and
    pConAccept -> SetState ( ConState_Send | ConState_Recv, 0 );
    return pConService;
}

//
//  Description: Initiates connection processing for object.
//               NOTES: Referenced from On_P2PeerCon_STARTUP handlers
//                      for connection type objects.
//
//
//  Returns:     bool
//               Connection summary
//
bool
P2PeerCon232::Connect ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Startup) )
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message(L"Requires ON_P2PeerCon_STARTUP handler state\n"
                     L"ADVICE\t: Bug (SNHappen)" )
           ->Throw  ( );

    // Open COM port
    // NOTES: FILE_FLAG_OVERLAPPED is mandatory when using IO
    //        completion ports
    m_hFileCOM = CreateFile ( (LPCTSTR)m_sFileCOM
                            , GENERIC_READ | GENERIC_WRITE
                            , 0    // exclusive access 
                            , NULL // no security attributes 
                            , OPEN_EXISTING
                            , FILE_FLAG_OVERLAPPED
                            , NULL );
    if ( m_hFileCOM == INVALID_HANDLE_VALUE )
    {
      m_hFileCOM = 0;
      EVERR->MODULE
           ->Message(L"CreateFile(%s) failed\n"
                     L"ADVICE\t: Check assignment for %s"
                    , (LPCTSTR)m_sFileCOM, (LPCTSTR)m_sFileCOM )
           ->HResult( GetLastError() )->Throw();
    }

    // Associate with IO Completion Port
    // NOTES: All subsequent notifications received via queued
    //        IO Completion Packets
    CreateIOCP ( m_hFileCOM );
    //m_hFileCPort = CreateIoCompletionPort ( m_hFileCOM
    //                                      , m_hCPort
    //                                      ,(ULONG_PTR)(P2PeerCon *)this
    //                                      , 0 );
    //if ( m_hFileCPort == 0 )
    //  EVERR->Module  ("%s(%s-%s)", __FUNCTION__
    //                 , EncodeP2PeerID(m_oThisP2Paddr)
    //                 , EncodeP2PeerID(m_oThatP2Paddr) )
    //       ->Message ("CreateIoCompletionPort() failed")
    //       ->HResult ( GetLastError() )->Throw();
    //m_hFile = m_hFileCOM;

    // Serial line discipline
    ConfigureComPort ( );

    // Overlapped preparation
    if ( m_pOVERLAPPEDconnect == NULL )
      m_pOVERLAPPEDconnect = MakeOVERLAPPED ( 0 );

    // Post IO Completion Port 
    // NOTES: Abstraction for serial communications
    prepareOVERLAPPED ( m_pOVERLAPPEDconnect );
    if ( !PostQueuedCompletionStatus ( m_hCPort
                                     , 0 // bytes transferred
                                     , m_dwCompletionKey 
                                     , (OVERLAPPED *)m_pOVERLAPPEDconnect )  )
    {
      releaseOVERLAPPED(m_pOVERLAPPEDconnect);
      EVERR->Module  (L"%hs(%s-%s)", __FUNCTION__
                     , GetP2PaddrHub().c_wstr()
                     , m_oThatP2Paddr.c_wstr() )
           ->Message (L"PostQueuedCompletionStatus() failed")
           ->HResult ( GetLastError() )->Throw();
    }

    // Tidy up and
    return true;
}

void
P2PeerCon232::Close  ( )
{
    // Delegate
    P2PeerCon::Close ( );
}

//
//  Description: Close connection
//               NOTES: Closed connections may be Restart()'ed
//                    : Usually performed in the ON_P2PeerCon_CLOSE()
//                      handler
//
//
//  Returns:     BOOL
//               Close object status
//
BOOL
P2PeerCon232::OnClose ( )
{
    // Resource recovery
    if ( m_hFileCOM )
    {
      CloseHandle ( m_hFileCOM );
      m_hFileCOM   = 0;
      m_hFile      = 0;                // P2PeerCon attribute
      m_hFileCPort = 0;                // P2PeerCon attribute
    }

    // Always delegate
    return P2PeerCon::OnClose();
}


///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerCon232::AssertValid ( ) const
{
    // Firstly delegate
    P2PeerCon::AssertValid ( );

    // TODO: Additional validation
}

///////////////////////////////////////////////////////////////////////
//  Properties
