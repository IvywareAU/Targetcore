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
//       : THE PREFIX IS NOT THE WHOLE TEST, and treating it as one was a
//         defect - found by a security review of this branch, finding 2.
//         \\.\ is the DOS device namespace and, unlike \\?\, a path under it
//         is still normalised: \\.\pipe\..\UNC\host\pipe\Name has the prefix
//         this function matched, resolves through the redirector, and was
//         answered Local.  So the remainder is required to be a PIPE NAME and
//         nothing else - one component, no separator - which is exactly what
//         the platform allows a pipe name to be (every character except a
//         backslash), so nothing legitimate is refused and nothing that can
//         traverse is admitted
//       : This is the CLIENT's half of the locality question.  A client
//         cannot see whether the server passed PIPE_REJECT_REMOTE_CLIENTS -
//         but it does not need to, because the reject is what stops a REMOTE
//         client, and the only claim being made here is about this end
//       : It is what a client with NO HANDLE answers - a posture reading.  A
//         client that HAS one is answered by P2PeerConPipeHandleIsLocal()
//         below as well, and both must be true.  The name is what this end
//         asked for; the handle is what it got
//
static bool
P2PeerConPipenameIsLocal ( LPCTSTR pszName )
{
    if ( pszName == 0 || *pszName == 0 )
      return false;
    if ( _tcsnicmp ( pszName, _T("\\\\.\\pipe\\"), 9 ) != 0 &&
         _tcsnicmp ( pszName, _T("//./pipe/"),    9 ) != 0    )
      return false;

    //  The remainder is the pipe name.  Empty is not a name, and a separator
    //  in it means the path leaves \\.\pipe\ for somewhere this function
    //  cannot vouch for - refer the note above
    const TCHAR *pszLeaf = pszName + 9;
    if ( *pszLeaf == 0 )
      return false;
    for ( const TCHAR *p = pszLeaf; *p != 0; ++p )
      if ( *p == _T('\\') || *p == _T('/') )
        return false;
    return true;
}

#ifdef _WIN32
//
//  Whether an OPEN pipe handle is served from this machine.
//  NOTES: The kernel's own answer, and the half the name cannot give.  A
//         server process id is meaningless across a machine boundary, so the
//         redirector cannot answer for one and the call fails on a pipe
//         reached over SMB; it succeeds on a local pipe from the handle alone,
//         with no rights beyond having opened it
//       : ANY failure reads as not-local.  This is the fail-closed direction
//         for a class - a link that cannot be shown to be local is a wire -
//         and it is the direction every other reading in this feature takes
//       : Asked ONCE, in Connect(), and recorded.  The note this replaces said
//         a handle reading would cost a syscall "on every posture read", which
//         was true of asking it from TrustClass(); it is not true of asking it
//         where the handle is opened
//
static bool
P2PeerConPipeHandleIsLocal ( HANDLE hPipe )
{
    if ( hPipe == 0 || hPipe == INVALID_HANDLE_VALUE )
      return false;
    ULONG ulServerPid = 0;
    return GetNamedPipeServerProcessId ( hPipe, &ulServerPid ) ? true : false;
}
#endif

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
    //      : m_bPipeRearm is false because a fresh object is the FIRST
    //        instance of whatever it creates; only AcceptSpawn says otherwise
    m_ePipeAccess = P2PeerConPipeAccess_Owner;
    m_bPipeLocal  = false;
    m_bPipeRearm  = false;
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
    //      : ...and the spawn is told it is a RE-ARM.  Its CreateNamedPipe
    //        will be a further instance of the pipe THIS still holds, so it
    //        must not ask for FILE_FLAG_FIRST_PIPE_INSTANCE - that would
    //        refuse this transport's own pipe.  Refer CreateListenPipe()
    pConSpawnPipe -> m_ePipeAccess = m_ePipeAccess;
    pConSpawnPipe -> m_sPipeSddl   = m_sPipeSddl;
    pConSpawnPipe -> m_bPipeRearm  = true;

    // Done
    // NOTES: Spawned object is free floating
    return pConSpawn;
}

///////////////////////////////////////////////////////////////////////
//  IOCP Integration
//

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
         EVERR->Module  (L"%hs(%s-%s)", __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , (P2PaddrSTR)m_oThatP2Paddr )
              ->Message (L"closehandle(%s) failed\n"
                         L"ADVICE\t: Bug (SNHappen)"
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
    // Squatting
    // NOTES: A named pipe carries the descriptor its FIRST instance was made
    //        with.  A later CreateNamedPipe on the same name is a further
    //        instance of THAT pipe: it passes an access check against the
    //        existing descriptor, and the descriptor it brings is not the one
    //        the endpoint gets.  So a local principal that creates the name
    //        first, with a DACL of their choosing, would have this transport
    //        join their pipe - traffic behind their DACL, the client's opens
    //        admitted on their terms - while the derivation below still read
    //        back the reject and the descriptor THIS end passed, and the
    //        class said Local
    //      : FILE_FLAG_FIRST_PIPE_INSTANCE is the kernel's answer: with it
    //        the create FAILS, ERROR_ACCESS_DENIED, if any instance of the
    //        name already exists.  Passed on the FIRST instance this
    //        transport makes and NOT on the re-arm, because the re-arm is by
    //        definition a second instance of a pipe this transport already
    //        holds - the accepted connection is still open on it, under this
    //        transport's own descriptor - and the flag there would refuse the
    //        transport's own pipe.  AcceptSpawn is what tells the spawn it is
    //        a re-arm
    //      : NOT passed under Legacy, which is the pre-revision call byte for
    //        byte and is documented as such.  A legacy pipe reads Wire, so
    //        its policy is Full and a squatter gains nothing past the login
    //        gate; the flag is a property of the class this transport claims,
    //        and Legacy claims none
    //      : What this leaves open is stated rather than hidden: if the
    //        accepted sibling drops before the spawn re-arms, the name is
    //        briefly free, and a re-arm in that window joins whatever was
    //        created into it.  The window is one pump dispatch wide and the
    //        spawn cannot see across it; closing it means reading the
    //        descriptor back off the created handle, which is a separate
    //        change
#ifdef _WIN32
    DWORD                dwOpenMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    DWORD                dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE;
    SECURITY_ATTRIBUTES  oSA;
    PSECURITY_DESCRIPTOR pSD  = NULL;
    LPSECURITY_ATTRIBUTES pSA = NULL;
    if ( m_ePipeAccess != P2PeerConPipeAccess_Legacy )
    {
      if ( !m_bPipeRearm )
        dwOpenMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

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
             ->Message(L"SDDL(%s) for pipe %s does not parse\n"
                       L"ADVICE\t: Check the string given to SetPipeAccess"
                       L", or ask for P2PeerConPipeAccess_Owner"
                      , pszSddl, (LPCTSTR)m_sPipename )
             ->HResult( GetLastError() )->Throw();

      oSA.nLength              = sizeof(oSA);
      oSA.lpSecurityDescriptor = pSD;
      oSA.bInheritHandle       = FALSE;
      pSA                      = &oSA;
      dwPipeMode              |= PIPE_REJECT_REMOTE_CLIENTS;
    }
#else
    // The Linux mapping ignores the open mode outright - refer the note
    // above - and has no FILE_FLAG_FIRST_PIPE_INSTANCE to pass.  Squatting
    // has no counterpart there either: bind() on an AF_UNIX path that exists
    // fails, it does not join
    DWORD                dwOpenMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    DWORD                dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE;
    void                *pSA = NULL;
#endif

    m_hFile = CreateNamedPipe ( m_sPipename
                              , dwOpenMode
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

      // The name was already taken, and this was meant to be its first
      // instance.  Named separately because the advice is different: the
      // assignment is fine, it is the NAME that is held by somebody else -
      // a previous server still running, or a squatter - and the refusal is
      // the protection working rather than a configuration to check
#ifdef _WIN32
      if ( dwCreateErr == ERROR_ACCESS_DENIED &&
           ( dwOpenMode & FILE_FLAG_FIRST_PIPE_INSTANCE ) != 0 )
        EVERR->MODULE
             ->Message(L"CreateNamedPipe(%s) refused: the name already has "
                       L"an instance and this service creates the first\n"
                       L"ADVICE\t: Another process holds %s - a server still "
                       L"running, or a squatter.  Refused rather than joined, "
                       L"because a joined pipe keeps the FIRST creator's "
                       L"descriptor, not this one's\n"
                       L"ADVICE\t: Stop the other holder, or choose a name"
                      , (LPCTSTR)m_sPipename, (LPCTSTR)m_sPipename )
             ->HResult( dwCreateErr )->Throw();
#endif

      EVERR->MODULE
           ->Message(L"CreateNamePipe(%s) failed\n"
                     L"ADVICE\t: Check assignment for %s"
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
    //      : THREE halves since the squatting note above, and the third is
    //        what makes the first two MEAN anything: a reject and a
    //        descriptor were only APPLIED if this create was the pipe's first
    //        instance - which the flag makes the kernel guarantee - or a
    //        re-arm of a pipe whose first instance this transport made.
    //        Read back from the open mode that was passed, as the other two
    //        are, so deleting the |= above turns the class to Wire
    //      : On the Linux mapping neither argument reached the kernel - the
    //        call was socket/bind/listen on an AF_UNIX path - so neither can
    //        be read back.  What makes the class true there is the address
    //        family, which is not an argument and cannot be got wrong.  Refer
    //        the note above
#ifdef _WIN32
    m_bPipeLocal = ( dwPipeMode & PIPE_REJECT_REMOTE_CLIENTS ) != 0 &&
                     pSA != NULL &&
                   ( ( dwOpenMode & FILE_FLAG_FIRST_PIPE_INSTANCE ) != 0 ||
                     m_bPipeRearm );
#else
    m_bPipeLocal = true;
#endif

    // THE FENCE, asked again now that the class is a FACT
    // NOTES: P2PeerHub::PostP2PeerCon already asked it, and at that moment
    //        this object had no handle: TrustClass() answered from
    //        m_ePipeAccess, which is an INTENTION and which SetPipeAccess()
    //        can still change afterwards.  A service posted to a hub fenced at
    //        Local while it meant to make an Owner pipe, then told
    //        P2PeerConPipeAccess_Legacy before it listened, passed the fence
    //        and then created a wire - which is finding 3 of the branch review
    //      : Here the pipe EXISTS and m_bPipeLocal was read back out of the
    //        arguments the kernel was actually given, so this is the last
    //        moment before the endpoint can carry anything and the first at
    //        which the answer cannot change underneath it
    //      : THE HANDLE IS CLOSED BEFORE THE THROW.  A listener that the hub
    //        will not hold must not be left with a created pipe: the name
    //        would be taken, and a later re-arm - or another service - would
    //        find it occupied by an endpoint nothing is listening on
    //      : Covers the re-arm too, which is the path an accepted child's
    //        sibling takes, so a fence raised or a mode changed between
    //        accepts is caught at the next one rather than at none
    if ( TrustFenceRefuses ( ) )
    {
      const P2PeerConTrust_e eFloor = TrustFenceFloor ( );
      const P2PeerConTrust_e eClass = EffectiveTrust ( );
      CloseHandle ( m_hFile );
      m_hFile      = 0;
      m_bPipeLocal = false;
      EVERR->MODULE
           ->Message(L"Pipe %s is trust class %i and its hub holds no link "
                     L"below class %i\n"
                     L"ADVICE\t: 0 wire, 1 kernel-local, 2 in-process\n"
                     L"ADVICE\t: SetPipeAccess() asked for a pipe of a class "
                     L"this hub was fenced to refuse - drop the "
                     L"P2PeerConPipeAccess_Legacy, or widen the fence with "
                     L"RequireTrustAtLeast()\n"
                     L"ADVICE\t: Listener not created"
                    , (LPCTSTR)m_sPipename, (int)eClass, (int)eFloor )
           ->Throw();
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
        EVERR->Module  (L"%hs(%s-%s)", __FUNCTION__
                       , GetP2PaddrHub().c_wstr()
                       , m_oThatP2Paddr.c_wstr() )
             ->Message (L"ConnectNamePipe() failed")
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
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Message(L"Requires ON_P2PeerOLD_ACCEPT handler state")
           ->Advice (L"Bug (SNHappen)" )
           ->Throw  ( );

    // Mode confirmation
    // NOTES: Audits the development cycle and traps illogical states
    //        that can propogate subtle bugs.
    //      : Low frequency check more than worth the overhead
    if ( m_eP2PeerConMode != P2PeerCon_SERVICE )
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message(L"Requires P2PeerCon_SERVICE mode not %i"
                    , m_eP2PeerConMode )
           ->Advice (L"Bug (SNHappen)" )
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
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , (P2PaddrSTR)m_oThatP2Paddr )
           ->Message(L"Requires ON_P2PeerOLD_ACCEPT handler state\n"
                     L"ADVICE\t: Bug (SNHappen)" )
           ->Throw  ( );

    // To be sure, to be sure
    if (   !oThatP2Paddr.IsNull()       &&
         !m_oThatP2Paddr.IsNull()       &&
         m_oThatP2Paddr != oThatP2Paddr    )
      EVERR->MODULE
           ->Message(L"Attempt to swap P2PeerID's from [%s] to [%s]"
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
      EVERR->Module (L"%hs(%s-%s)", __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message(L"Requires ON_P2PeerCon_STARTUP handler state\n"
                     L"ADVICE\t: Bug (SNHappen)" )
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
           ->Message(L"CreateFile(%s) failed"
                    , (LPCTSTR)m_sPipename )
           ->Advice (L"Check assignment for %s"
                    , (LPCTSTR)m_sPipename )
           ->HResult( GetLastError() )->Throw();
    }

    // The FACT for the client end: which DEVICE this handle was opened on.
    // \\.\pipe\Name is NPFS here; anything reached through the redirector is
    // a network path.  Refer P2PeerConPipenameIsLocal()
    // NOTES: TWO readings and both must hold, which is the shape the SERVER
    //        end already had.  The name is what this end ASKED for and is
    //        checked for traversal as well as for its prefix; the handle is
    //        what it GOT, and only the kernel can answer that.  Neither alone:
    //        a name that survives normalisation still says nothing about a
    //        pipe the redirector went out and found, and a handle reading
    //        alone would let a name this transport should never have opened
    //        decide the class by whether one API call happened to succeed
    m_bPipeLocal = P2PeerConPipenameIsLocal ( (LPCTSTR)m_sPipename );
#ifdef _WIN32
    if ( m_bPipeLocal )
      m_bPipeLocal = P2PeerConPipeHandleIsLocal ( m_hFile );
#endif

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
