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
//  Description: P2PeerConPipe implementation
//               NOTES: Manages P2Peer RS232 connections
//

#include "stdafx.h"
#include "P2PeerConPipe.h"
#include "P2Pwin32.h"

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

const __time64_t
iLoginTimeoutSeconds = 20;             // Login sequences must be
                                       //   processed within this time

P2PeerConPipe::P2PeerConPipe ( )
{
    // Firstly
    RenderThisSafe ( );
}

//
//  Parameters:  P2PaddrSTR strThatP2Paddr
//               Identification address for that, or the other end
//
//               LPCTSTR lpszPipename
//               Pipe name
//
P2PeerConPipe::P2PeerConPipe ( P2PaddrSTR pThatP2PaddrSTR
                             , LPCTSTR  lpszPipename
                             , P2Peerio *pP2Peerio )
             : P2PeerCon ( pThatP2PaddrSTR, pP2Peerio )
{
    // Firstly
    RenderThisSafe();
    m_sPipename      = lpszPipename;
}

//
//               short nIPort
//               Listening port
//
P2PeerConPipe::P2PeerConPipe ( LPCTSTR lpszPipename
                             , P2Peerio *pP2Peerio )
             : P2PeerCon ( pP2Peerio )
{
    // Firstly
    RenderThisSafe();
    m_sPipename      = lpszPipename;
}

P2PeerConPipe::~P2PeerConPipe ( )
{
    // Resource collection
    Drop ( 0 );
}

void
P2PeerConPipe::RenderThisSafe()
{
    // Attributes
    m_hFile = 0;
}

P2PeerConPipe*
P2PeerConPipe::ServiceFactory ( P2PaddrSTR strP2PaddrThat
                              , LPCTSTR lpszPipename )
{
    // Instanciate
    P2PeerConPipe *pCon = new P2PeerConPipe ( );

    // Attributes
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_oP2Padomain    = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_SERVICE;
    pCon -> m_sPipename      = lpszPipename;

    // Protocol
    // NOTES: Instance is cloned for accepted connections
    pCon -> SetP2Peerio ( new P2Peerio( ) );

    // Done
    return pCon;
}

P2PeerConPipe*
P2PeerConPipe::ClientFactory ( P2PaddrSTR strP2PaddrThat
                             , LPCTSTR lpszPipename )
{
    // Instanciate
    P2PeerConPipe *pCon = new P2PeerConPipe ( );

    // Attributes
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_CLIENT;
    pCon -> m_sPipename      = lpszPipename;

    // Protocol
    pCon -> SetP2Peerio ( new P2Peerio( ) );

    // Done
    return pCon;
}

//
//  Description: Splits listening connection into listening and
//               accepted P2PeerCon'nections
//               NOTES: Derived classes must delegate
//
//
//  Parameters:  P2PeerCon **pConListen = 0
//               Previously manufactured listening instance
//
//               P2PeerCon **pConAccept = 0
//               Previously manufactured accept instance
//
P2PeerCon*
P2PeerConPipe::AcceptSpawn ( P2PeerCon *pConSpawn )
{
    // Instanciation etc
    if ( pConSpawn == NULL )
      pConSpawn = new P2PeerConPipe ( );

    // Settlement
    // NOTES: Accept removes the allocated socket
    P2PeerConPipe *pConSpawnPipe = (P2PeerConPipe *)pConSpawn;
    P2PeerCon::AcceptSpawn ( pConSpawn );
    pConSpawnPipe -> m_sPipename  = m_sPipename;
    pConSpawnPipe -> m_eP2PeerConMode  =    P2PeerCon_SERVICE;
             this -> m_eP2PeerConMode  =    P2PeerCon_Accept;

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
P2PeerConPipe::On_QueuedCompletionStatus ( DWORD dwError
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
      //      : Perform On_P2PeerCon_LISTEN() notification.  At which
      //        point the intercepting handler will listen for another
      //        connection
      if ( pOVERLAPPEDcon == m_pOVERLAPPEDaccept )
      {
        // Success
        // NOTES: Honour expectation that the On_P2PeerCon_ACCEPT()
        //        processed before the ON_P2PeerCon_LISTEN()
        //        notification
        releaseOVERLAPPED ( pOVERLAPPEDcon );
        if (   hr == S_OK &&
             m_hFileCPort    )
        {
          if ( m_pOVERLAPPEDsend == NULL )
            m_pOVERLAPPEDsend = MakeOVERLAPPED ( );
          if ( m_pOVERLAPPEDrecv == NULL )
            m_pOVERLAPPEDrecv = MakeOVERLAPPED ( MAX_P2Psize );

          // ON_P2PeerOLD_ACCEPT() notification
          // NOTES: Spawn accepted connection
          PostP2Pmsg ( m_oThisP2Paddr, CN_P2PeerCon, P2P_Accept
                     , ExtractAccept(), 0 );

          // ON_P2PeerCon_LISTEN() notification
          // NOTES: Listen for new connection
          PostP2Pmsg ( m_oThisP2Paddr, CN_P2PeerCon, P2P_Listen
                     , this, 0 );
        }

        // Failure
        // NOTES: Connection failed to complete
        //      : Perform On_P2PeerCon_CLOSE() notification.
        else if (   hr         &&
                  m_hFileCPort    )
          EVERR->Module ("%s[%s-%s]", __FUNCTION__
                        , EncodeP2PeerID(m_oThisP2Paddr)
                        , EncodeP2PeerID(m_oThatP2Paddr) )
               ->Message("Overlapped accept failed")
               ->HResult( hr ) -> Throw();

        // Cancellation
        // NOTES: IoCancel(m_hFileCPort) and CloseHandle(m_hFileCPort)
        //        issued
        else
          m_pOVERLAPPEDaccept = DropOVERLAPPED ( pOVERLAPPEDcon );
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
ASSERT(AfxCheckMemory()); //TODO: Delete-Debugging
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
P2PeerConPipe::Drop ( P2Pevent *pEVENT )
{
    // Firstly drop socket
    // NOTES: Cancels all outstanding overlapped IO
    if ( m_hFile )
    {
      if (     CloseHandle(m_hFile) &&
             !pEVENT                   )
        pEVENT =
         EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , (P2PaddrSTR)m_oThatP2Paddr )
              ->Message (_N("closehandle(%s) failed\n")
                         "ADVICE\t: Bug (SNHappen)"
                        , (LPCTSTR)m_sPipename )
              ->HResult ( GetLastError() );
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
//  Description: Initiates listen processing for object.
//               NOTES: Referenced from On_P2PeerCon_STARTUP handlers
//                      for listen type objects.
//
//
//  Returns:     bool
//               Listen summary
//
bool
P2PeerConPipe::Listen ( )
{
    // State confirmation
    P2PeerCon::Listen ( );

    // On_P2PeerCon_LISTEN() notification
    // NOTES: Synchronous activity
    PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Listen
               , this, (P2PeerMsg *)0, m_hCPortP2PumpID );

    // Tidy up and
    return true;
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
void
P2PeerConPipe::OnListen ( )
{
    // State confirmation
    // NOTES: Delegate to base for the ON_P2PeerCon_LISTEN handler-state audit,
    //        consistent with P2PeerConWsa::OnListen().  Both real listen paths
    //        (P2PeerTarget::On_ConListen, P2PeerExplorer::On_XCidSvrListen) are
    //        dispatched under {CN_P2PeerCon, P2P_Listen}, so the audit holds.
    //      : Kept OUT of the shared pipe-creation helper (CreateListenPipe)
    //        because Accept() lazily (re)creates the pipe from the P2P_Accept
    //        re-arm state, where the P2P_Listen audit would (correctly) fail.
    P2PeerCon::OnListen ( );

    // Named pipe creation
    CreateListenPipe ( );
}

//
//  Creates the listening named pipe and binds it to the IO completion port.
//  NOTES: State-agnostic - shared by OnListen() (true listen path) and the
//         lazy re-arm inside Accept() (dispatched under P2P_Accept).  Performs
//         no pump-state confirmation; that audit lives in OnListen().
//
void
P2PeerConPipe::CreateListenPipe ( )
{
    // Named pipe creation
    // NOTES: FILE_FLAG_OVERLAPPED is mandatory when using IO
    //        completion ports
    //      : Normally this is done in Listen().  But, pipes are
    //        different whereby the listening P2PeerCon morphs into the
    //        accepted connection
    ASSERT(m_hFile==0);
    m_hFile = CreateNamedPipe ( m_sPipename
                              , PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
                              , PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
                              , 2                    // maximum number of instances
                              , 64000              // output buffer size
                              , 64000              // input buffer size
                              , 1000                 // time-out interval
                              , NULL );
    if ( m_hFile == INVALID_HANDLE_VALUE )
    {
      m_hFile = 0;
      EVERR->MODULE
           ->Message(_N("CreateNamePipe(%s) failed\n")
                     "ADVICE\t: Check assignment for %s"
                    , (LPCTSTR)m_sPipename, (LPCTSTR)m_sPipename )
           ->HResult( GetLastError() )->Throw();
    }

    // Associate with IO Completion Port
    // NOTES: All subsequent notifications received via queued
    //        IO Completion Packets
    CreateIOCP ( m_hFile );
}

//
//  Initiates accept connection processing for SERVICE object.
//  NOTES: Usually referenced from ON_P2PeerCon_STARTUP handlers.
//       : Accepted connections are intercepted in
//         ON_P2PeerOLD_ACCEPT handlers
//       : Refer Connect() for CLIENT side equivalent.
//
//
//  Returns:     bool
bool
P2PeerConPipe::Accept ( )
{
  if (!m_hFile)
    CreateListenPipe();   // create the pipe without the P2P_Listen state audit
                          // (this path runs under the P2P_Accept re-arm)
    // State confirmation
    P2PeerCon::Accept ( );

    // Initiate wait for client connection
    // NOTES: Must be a non-pended operation
    if ( m_pOVERLAPPEDaccept == NULL )
      m_pOVERLAPPEDaccept = MakeOVERLAPPED ( );
    prepareOVERLAPPED ( m_pOVERLAPPEDaccept );
    if ( !ConnectNamedPipe ( m_hFile
                           ,(OVERLAPPED *)m_pOVERLAPPEDaccept ) &&
          GetLastError() != ERROR_IO_PENDING                       )
    {
      releaseOVERLAPPED ( m_pOVERLAPPEDaccept );
      HRESULT hr = GetLastError ( );
      if ( hr != ERROR_PIPE_CONNECTED )
        EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                       , GetP2PaddrHub().c_wstr()
                       , m_oThatP2Paddr.c_wstr() )
             ->Message ("ConnectNamePipe() failed")
             ->HResult ( hr )->Throw();

      // Accept must be simulated whenever client connects between
      // CreateNamedPipe() and ConnectNamedPipe()
      PostOVERLAPPED ( m_pOVERLAPPEDaccept );
    }
 
    // Accept-completion processing (spawn accepted connection + re-listen)
    // is posted asynchronously from On_QueuedCompletionStatus, the
    // m_pOVERLAPPEDaccept branch (P2P_Accept via ExtractAccept() + P2P_Listen),
    // consistent with P2PeerConWsa::Accept() and P2PeerConDmx::Accept() which
    // likewise post nothing at their tail.  No inline P2P_Connect is emitted
    // here: that event belongs to the outbound connect-completion path
    // (see line ~247), not the inbound accept path.
    return true;
}

//
//  ACCEPT'ed connection processing
//  NOTES: Processing must be performed for all accepted connections
//       : Reference from within ON_P2PeerOLD_ACCEPT() handlers
//
//
//  Parameters:  P2PaddrSTR pThatP2PaddrSTR
//               Address assigned to remote client
//               NOTES: Assignment may be defered to the login 
//                      phase by specifying a NULL value
//  Returns:     P2PeerCon*
//               Accepted and spawned P2PeerConPipe object
//
P2PeerCon*
P2PeerConPipe::OnAccept ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept) )
      EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Message("Requires ON_P2PeerOLD_ACCEPT handler state")
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Mode confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( m_eP2PeerConMode != P2PeerCon_SERVICE )
      EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message("Requires P2PeerCon_SERVICE mode not %i"
                    , m_eP2PeerConMode )
           ->Advice ("Bug (SNHappen)" )
           ->Throw  ( );

    // Spawn accepted P2PeerCon
    // NOTES: Effectively the roles are swapped, service becomes
    //        accepted connection and accepted connection becomes
    //        the service
    P2PeerConPipe *pConAccept  = this;
    P2PeerCon     *pConService = AcceptSpawn ( 0 );
    if ( pConAccept == NULL )
      return pConAccept;

    // Associate with IO Completion Port
    // NOTES: All subsequent notifications received via queued
    //        IO Completion Packets
    //if ( !pConAccept->m_hFileCPort &&
    //      pConAccept->m_hFile         )
    //  pConAccept -> CreateIOCP ( pConAccept->m_hFile );

    // Activate P2PeerMsg receipt
    // NOTES: Action is negated whenever OVERLAPPEDrecv object already
    //        exists
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
//  Performs ACCEPT'ed connection processing for SERVICE connections
//  NOTES: This processing must be performed for all accepted
//         connections
//       : Reference from within ON_P2PeerOLD_ACCEPT() handlers
//
//
//  Parameters:  const P2Paddr oThatP2Paddr
//               Identification assigned to remote client
//               NOTES: Assignment may be defered to the login 
//                      phase by specifying a NULL value
//
void
P2PeerConPipe::OnAccept ( const P2Paddr oThatP2Paddr )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Accept) )
      EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Message("Requires ON_P2PeerOLD_ACCEPT handler state\n"
                     "ADVICE\t: Bug (SNHappen)" )
           ->Throw  ( );

    // To be sure, to be sure
    if (   !oThatP2Paddr.IsNull()       &&
         !m_oThatP2Paddr.IsNull()       &&
         m_oThatP2Paddr != oThatP2Paddr    )
      EVERR->MODULE
           ->Message(_N("Attempt to swap P2PeerID's from [%s] to [%s]")
                    , (P2PaddrSTR)m_oThatP2Paddr
                    , (P2PaddrSTR)  oThatP2Paddr )
           ->Throw();

    // Assign
    if ( !oThatP2Paddr.IsNull() )
      m_oThatP2Paddr = oThatP2Paddr;

    //// Associate with IO Completion Port
    //// NOTES: All subsequent notifications received via queued
    ////        IO Completion Packets
    //m_hFileCPort = CreateIoCompletionPort ( (HANDLE)m_hFile
    //                                      , m_hCPort
    //                                      ,(ULONG_PTR)this
    //                                      , 0 );
    //if ( m_hFileCPort == 0 )
    //  EVERR->Module  ("%s(%s-%s)", __FUNCTION__
    //                 , EncodeP2PeerID(m_oThisP2Paddr)
    //                 , EncodeP2PeerID(m_oThatP2Paddr) )
    //       ->Message ("CreateIoCompletionPort() failed")
    //       ->WSAGROUP( GetLastError() )->Throw();

    // Activate P2PeerMsg receipt
    // NOTES: Action is negated whenever OVERLAPPEDrecv object already
    //        exists
    if ( !m_pOVERLAPPEDrecv )
      m_pOVERLAPPEDrecv = MakeOVERLAPPED ( MAX_P2Psize );
    if ( !m_pOVERLAPPEDrecv->bQueued )
      PostOVERLAPPED ( m_pOVERLAPPEDrecv );
    if ( !m_pOVERLAPPEDsend )
      m_pOVERLAPPEDsend = MakeOVERLAPPED ( );

    // Tidy up, and
    SetState ( ConState_Recv|ConState_Send, 0 );
    return;
}

//
//  Initiates accept connection processing for CLIENT object.
//  NOTES: Usually referenced from ON_P2PeerCon_STARTUP handlers.
//       : Successfull connections are intercepted in
//         ON_P2PeerCon_CONNECT handlers
//       : Refer Accept() for SERVICE side equivalent.
//
//
//  Returns:     bool
//               Connection summary
//
bool
P2PeerConPipe::Connect ( )
{
    // State confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( !CheckP2PmsgPumpState(CN_P2PeerCon,P2P_Startup) )
      EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message("Requires ON_P2PeerCon_STARTUP handler state\n"
                     "ADVICE\t: Bug (SNHappen)" )
           ->Throw  ( );

    // Open COM port
    // NOTES: FILE_FLAG_OVERLAPPED is mandatory when using IO
    //        completion ports
    m_hFile = CreateFile ((LPCTSTR)m_sPipename
                         , GENERIC_READ | GENERIC_WRITE
                         , 0    // exclusive access 
                         , NULL // no security attributes 
                         , OPEN_EXISTING
                         , FILE_FLAG_OVERLAPPED
                         , NULL );
    if ( m_hFile == INVALID_HANDLE_VALUE )
    {
      m_hFile = 0;
      EVERR->MODULE
           ->Message(_N("CreateFile(%s) failed\n")
                     "ADVICE\t: Check assignment for %s"
                    , (LPCTSTR)m_sPipename, (LPCTSTR)m_sPipename )
           ->HResult( GetLastError() )->Throw();
    }

    // Associate with IO Completion Port
    // NOTES: All subsequent notifications received via queued
    //        IO Completion Packets
    CreateIOCP ( m_hFile );
    //m_hFileCPort = CreateIoCompletionPort ( m_hFile
    //                                      , m_hCPort
    //                                      ,(ULONG_PTR)(P2PeerCon *)this
    //                                      , 0 );
    //if ( m_hFileCPort == 0 )
    //  EVERR->Module  ("%s(%s-%s)", __FUNCTION__
    //                 , EncodeP2PeerID(m_oThisP2Paddr)
    //                 , EncodeP2PeerID(m_oThatP2Paddr) )
    //       ->Message ("CreateIoCompletionPort() failed")
    //       ->HResult ( GetLastError() )->Throw();

    // Overlapped preparation
    if ( m_pOVERLAPPEDconnect == NULL )
      m_pOVERLAPPEDconnect = MakeOVERLAPPED ( 0 );

    // Post IO Completion Port 
    // NOTES: Abstraction for serial communications
    PostOVERLAPPED ( m_pOVERLAPPEDconnect );

    // Tidy up and
    return true;
}

void
P2PeerConPipe::Close  ( )
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
P2PeerConPipe::OnClose ( )
{
    // Resource recovery
    if ( m_hFile )
    {
      CloseHandle ( m_hFile );
      m_hFile      = 0;                // P2PeerCon attribute
      m_hFileCPort = 0;                // P2PeerCon attribute
    }

    // Always delegate
    return P2PeerCon::OnClose();
}

///////////////////////////////////////////////////////////////////////
//  Utilities

//
//  Summarises connection failure
//  NOTES: Summarises those errors likely to have resulted
//         from the remote connection dropping out.
//
//
//  Parameters:  HRESULT hr
//               Precipitating error as returned from WriteFile(),
//               ReadFile()
//
//  Returns:     bool
//               Connection failure summary
//                 true... Remote failure
//                 false.. Local failure
bool
P2PeerConPipe::HasDroppedOut ( HRESULT hr )
{
    // Default action
    if ( hr == ERROR_BROKEN_PIPE )
      return true;
    return false;
}

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerConPipe::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}
///////////////////////////////////////////////////////////////////////
//  Properties
