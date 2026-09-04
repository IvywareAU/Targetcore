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

#ifdef _WIN32
#  include <sddl.h>
#  pragma comment(lib, "advapi32.lib")   // ConvertStringSecurityDescriptorToSecurityDescriptor
#endif

//
//  The descriptor a P2PeerConPipeAccess_Owner pipe is created with.
//  NOTES: Protected (D:P), so nothing is inherited from anywhere, and three
//         ACEs and no more:
//           (A;;FA;;;SY)  LocalSystem     - full
//           (A;;FA;;;BA)  Administrators  - full (they can take ownership
//                                           regardless; denying is theatre)
//           (A;;FA;;;OW)  Owner Rights    - full, so the creating account can
//                                           still open the pipe it made
//       : What is NOT here is the change.  The platform's default descriptor
//         for a named pipe grants READ to Everyone and to Anonymous; a client
//         opening GENERIC_READ|GENERIC_WRITE failed on it anyway, but as a
//         side effect of the access mask rather than as a decision.  This is
//         the decision
//       : Byte for byte the descriptor P2PIdentityStore.cpp writes on an
//         identity file, deliberately.  Both are answering "which account may
//         reach this endpoint", and two answers to one question that drift
//         apart are worse than one answer that is wrong in one place
//
static LPCTSTR kPipeSddlOwner = _T("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)");

//
//  Whether a pipe name names the LOCAL named-pipe device.
//  NOTES: \\.\pipe\Name is NPFS on this machine and nothing else can be;
//         \\host\pipe\Name goes out through the SMB redirector and is a
//         network path even when host resolves back here.  \\localhost\pipe\
//         and \\127.0.0.1\pipe\ are therefore Wire by this test, which is
//         the fail-closed direction and is meant
//       : This is the CLIENT's half of the locality question.  A client
//         cannot see whether the server passed PIPE_REJECT_REMOTE_CLIENTS -
//         but it does not need to, because the reject is what stops a REMOTE
//         client, and the only claim being made here is about this end
//       : GetNamedPipeServerProcessId() would be a stronger reading (it fails
//         for a remote server) but needs the handle and one more syscall on
//         every posture read, and the device path is already a kernel fact
//
static bool
P2PeerConPipenameIsLocal ( LPCTSTR pszName )
{
    if ( pszName == 0 || *pszName == 0 )
      return false;
    return _tcsnicmp ( pszName, _T("\\\\.\\pipe\\"), 9 ) == 0 ||
           _tcsnicmp ( pszName, _T("//./pipe/"),    9 ) == 0;
}

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
    m_hFile       = 0;

    // Locality
    // NOTES: The DEFAULT MOVED.  Every pipe this transport creates now
    //        refuses remote clients and takes the descriptor above; the old
    //        call is P2PeerConPipeAccess_Legacy and has to be asked for
    //      : m_bPipeLocal is false because there is no handle yet, and it is
    //        never true of anything but a handle
    m_ePipeAccess = P2PeerConPipeAccess_Owner;
    m_bPipeLocal  = false;
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

    // Locality
    // NOTES: The roles swap here - THIS becomes the accepted connection and
    //        keeps the handle it created, the SPAWN becomes the service and
    //        re-arms with a CreateListenPipe() of its own.  So the SETTING
    //        travels (or the second instance of a pipe would be a different
    //        pipe from the first) and the FACT does not: m_bPipeLocal stays
    //        false on the spawn until its own CreateNamedPipe succeeds, and
    //        stays whatever it was on this, which is what this handle was
    //        actually made with
    pConSpawnPipe -> m_ePipeAccess = m_ePipeAccess;
    pConSpawnPipe -> m_sPipeSddl   = m_sPipeSddl;

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
      m_bPipeLocal = false;            // the fact goes with the handle
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

    // Locality
    // NOTES: PIPE_REJECT_REMOTE_CLIENTS and an explicit descriptor together,
    //        because they answer different halves and only both make the
    //        class true: the reject keeps the SMB redirector out, the DACL
    //        decides which local account may open what is left
    //      : Legacy reproduces the pre-revision call exactly - no reject,
    //        NULL descriptor - and the pipe it makes reads Wire.  It exists
    //        so that a deployment which shares a pipe across accounts, or
    //        reaches one over SMB, upgrades by naming that rather than by
    //        finding out
    //      : On the Linux mapping CreateNamedPipe is socket/bind/listen on an
    //        AF_UNIX path and BOTH arguments are ignored (Msgcore Platform
    //        README, "where the substrate shows through" 2 and 4).  There is
    //        no AF_UNIX equivalent of a pipe over SMB, so locality is a
    //        property of the address family and holds in every mode; what has
    //        no counterpart is the DACL, and access control there is the 0700
    //        directory plus the process umask.  Hence Local for all three
    //        modes on that platform, and a comment rather than a pretence
    //        that the descriptor was applied
#ifdef _WIN32
    DWORD                dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE;
    SECURITY_ATTRIBUTES  oSA;
    PSECURITY_DESCRIPTOR pSD  = NULL;
    LPSECURITY_ATTRIBUTES pSA = NULL;
    if ( m_ePipeAccess != P2PeerConPipeAccess_Legacy )
    {
      LPCTSTR pszSddl = ( m_ePipeAccess == P2PeerConPipeAccess_Descriptor )
                        ? (LPCTSTR)m_sPipeSddl
                        : kPipeSddlOwner;
      // A descriptor that does not parse THROWS.  Falling back to the
      // platform default would hand the caller a wider pipe than the one
      // they asked for, silently, which is the failure this whole change
      // exists to remove
      if ( !ConvertStringSecurityDescriptorToSecurityDescriptor (
               pszSddl, SDDL_REVISION_1, &pSD, NULL ) )
        EVERR->MODULE
             ->Message(_N("SDDL(%s) for pipe %s does not parse\n")
                       "ADVICE\t: Check the string given to SetPipeAccess"
                       ", or ask for P2PeerConPipeAccess_Owner"
                      , pszSddl, (LPCTSTR)m_sPipename )
             ->HResult( GetLastError() )->Throw();

      oSA.nLength              = sizeof(oSA);
      oSA.lpSecurityDescriptor = pSD;
      oSA.bInheritHandle       = FALSE;
      pSA                      = &oSA;
      dwPipeMode              |= PIPE_REJECT_REMOTE_CLIENTS;
    }
#else
    DWORD                dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE;
    void                *pSA = NULL;
#endif

    m_hFile = CreateNamedPipe ( m_sPipename
                              , PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
                              , dwPipeMode
                              , 2                    // maximum number of instances
                              , 64000              // output buffer size
                              , 64000              // input buffer size
                              , 1000                 // time-out interval
                              , pSA );
    const DWORD dwCreateErr = GetLastError ( );
#ifdef _WIN32
    if ( pSD )
      LocalFree ( pSD );
#endif
    if ( m_hFile == INVALID_HANDLE_VALUE )
    {
      m_hFile = 0;
      EVERR->MODULE
           ->Message(_N("CreateNamePipe(%s) failed\n")
                     "ADVICE\t: Check assignment for %s"
                    , (LPCTSTR)m_sPipename, (LPCTSTR)m_sPipename )
           ->HResult( dwCreateErr )->Throw();
    }

    // The FACT, and DERIVED FROM THE ARGUMENTS THAT WERE ACTUALLY PASSED
    // rather than recorded beside them.
    // NOTES: This is a deliberate three lines rather than one assignment in
    //        the branch that asked for the reject.  A flag set beside a
    //        request records the request; reading back the two values the
    //        kernel was handed records what the kernel was told.  Delete
    //        either the |= or the descriptor above and this answer changes,
    //        and p2p_linktrust phase 9 goes red - which an adjacent
    //        "m_bPipeLocal = true" would not have done
    //      : BOTH halves, because the class needs both to be true.  Neither
    //        one alone: a reject with the platform's descriptor still lets
    //        Everyone read the endpoint, and a descriptor without the reject
    //        still lets the redirector carry it off the machine
    //      : On the Linux mapping neither argument reached the kernel - the
    //        call was socket/bind/listen on an AF_UNIX path - so neither can
    //        be read back.  What makes the class true there is the address
    //        family, which is not an argument and cannot be got wrong.  Refer
    //        the note above
#ifdef _WIN32
    m_bPipeLocal = ( dwPipeMode & PIPE_REJECT_REMOTE_CLIENTS ) != 0 &&
                     pSA != NULL;
#else
    m_bPipeLocal = true;
#endif

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
    // NOTES: SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION.  Without them a
    //        pipe server may impersonate whoever opens it, at the default
    //        level, and act as that account - so a rogue server squatting the
    //        name is handed the client's token rather than merely its bytes.
    //        IDENTIFICATION lets the server ask who the client is, which is
    //        what a server legitimately wants, and stops it from being them,
    //        which nothing here ever wanted.  securityRevision.md finding 3
    //      : Guarded because the flags are a Win32 CreateFile concept.  The
    //        Linux mapping turns this call into an AF_UNIX connect and ignores
    //        its flags entirely; a server there learns the peer's credentials
    //        through SO_PEERCRED and has no way to assume them
#ifdef _WIN32
    const DWORD dwOpenFlags = FILE_FLAG_OVERLAPPED
                            | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
#else
    const DWORD dwOpenFlags = FILE_FLAG_OVERLAPPED;
#endif
    m_hFile = CreateFile ((LPCTSTR)m_sPipename
                         , GENERIC_READ | GENERIC_WRITE
                         , 0    // exclusive access 
                         , NULL // no security attributes 
                         , OPEN_EXISTING
                         , dwOpenFlags
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

    // The FACT for the client end: which DEVICE this handle was opened on.
    // \\.\pipe\Name is NPFS here; anything reached through the redirector is
    // a network path.  Refer P2PeerConPipenameIsLocal()
    m_bPipeLocal = P2PeerConPipenameIsLocal ( (LPCTSTR)m_sPipename );

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
      m_bPipeLocal = false;            // the fact goes with the handle
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
//  Locality

//
//  Description: Chooses what the next pipe this object creates will be
//               NOTES: Refer P2PeerConPipeAccess_e in the header
//                    : Takes effect at the next CreateNamedPipe and not
//                      before.  A pipe that already exists keeps the
//                      descriptor and the mode it was created with, which is
//                      why TrustClass() prefers the handle to this setting
//                    : An out-of-range mode is IGNORED rather than clamped.
//                      Clamping would pick one of three answers on the
//                      caller's behalf and every choice is wrong for someone;
//                      leaving the default in place at least leaves the
//                      TIGHTER one
//                    : pszSddl is copied, not held.  Descriptor mode with an
//                      empty string is left to fail at CreateNamedPipe, where
//                      it throws with the string in the diagnostic - the
//                      caller finds out with the pipe name in hand rather
//                      than at a setter that could only say "empty"
//
//  Parameters:  P2PeerConPipeAccess_e eAccess
//               Owner, Descriptor or Legacy
//
//               LPCTSTR pszSddl
//               The descriptor, read only by Descriptor mode
//
void
P2PeerConPipe::SetPipeAccess ( P2PeerConPipeAccess_e eAccess
                             , LPCTSTR pszSddl )
{
    if ( eAccess != P2PeerConPipeAccess_Owner      &&
         eAccess != P2PeerConPipeAccess_Descriptor &&
         eAccess != P2PeerConPipeAccess_Legacy        )
      return;

    m_ePipeAccess = eAccess;
    m_sPipeSddl   = ( pszSddl != 0 ) ? pszSddl : _T("");
}

P2PeerConPipeAccess_e
P2PeerConPipe::GetPipeAccess ( ) const
{
    return m_ePipeAccess;
}

//
//  Description: What this pipe can vouch for about where its frames go
//               NOTES: The handle first, and the settings only where there is
//                      no handle.  The same shape as
//                      P2PeerConWsa::TrustClass(), and for the same reason: a
//                      class is a fact about a link, so where a link exists
//                      it is the only thing worth reading.  It also means a
//                      SetPipeAccess() arriving after Listen() cannot re-label
//                      a pipe that is already carrying traffic
//                    : With no handle the answer is a POSTURE reading of an
//                      object that carries nothing, and the honest thing to
//                      report is what it is configured to become.  Which
//                      configuration that is depends on the end: a service
//                      creates the pipe, so its access mode decides; a client
//                      only opens a name, so the name decides
//                    : A SERVICE reads its access mode and NOT its name.  A
//                      CreateNamedPipe against a remote name fails outright,
//                      so a server's name is never the thing that makes it
//                      remote - the missing reject is
//                    : Accept mode is the morphed listener and always has the
//                      handle it created, so it never reaches the fallback.
//                      It is not named below for that reason: if it ever did
//                      reach it, the access mode is still the right question
//
//  Returns:     P2PeerConTrust_e
//               P2PeerConTrust_Local for a pipe the kernel keeps on this
//               machine, P2PeerConTrust_Wire otherwise
//
P2PeerConTrust_e
P2PeerConPipe::TrustClass ( ) const
{
    if ( m_hFile != 0 )
      return m_bPipeLocal ? P2PeerConTrust_Local : P2PeerConTrust_Wire;

    if ( m_eP2PeerConMode == P2PeerCon_CLIENT )
      return P2PeerConPipenameIsLocal ( (LPCTSTR)m_sPipename )
               ? P2PeerConTrust_Local
               : P2PeerConTrust_Wire;

    return ( m_ePipeAccess != P2PeerConPipeAccess_Legacy )
             ? P2PeerConTrust_Local
             : P2PeerConTrust_Wire;
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
