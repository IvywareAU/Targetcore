// Copyright © 2006-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerConPipe definitions and prototypes
//  NOTES: Asynchronously manages serial named pipe connections and
//         facilitates IO Completion port integration
//

#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2PeerCon.h"

///////////////////////////////////////////////////////////////////////
//  What a named pipe this transport creates will let through
//  NOTES: A named pipe is local ONLY if it was created to be.  Without
//         PIPE_REJECT_REMOTE_CLIENTS in the pipe mode a server accepts a
//         client arriving through the SMB redirector as \\host\pipe\name,
//         so on any host with file sharing on the endpoint is a NETWORK
//         endpoint - and no policy may be allowed to rely on a locality
//         the code does not make true.  This enum is how the transport
//         makes it true, and how it is made READABLE: TrustClass()
//         answers Local only for a pipe this transport actually created
//         with that reject and a descriptor it wrote itself
//       : Owner is the default, and it MOVES a default.  Every pipe this
//         library creates from here on refuses remote clients and takes
//         an explicit protected DACL - the creating account, LocalSystem
//         and Administrators, and NOTHING for Everyone or Anonymous,
//         which the platform's default descriptor grants read access to.
//         Same three ACEs, same order, as the identity file's descriptor
//         in P2PIdentityStore.cpp, because they are answering the same
//         question about the same account
//       : Legacy is that platform default kept reachable BY NAME, byte
//         for byte: no reject, NULL descriptor, exactly the call this
//         transport made before.  A deployment that shares a pipe between
//         two accounts, or reaches one over SMB, upgrades by NAMING that
//         rather than by discovering that it stopped working.  It is a
//         Wire-class pipe and TrustClass() says so, which is the point:
//         the compatibility escape hatch is the one that does not get to
//         claim the class
//       : Descriptor is the middle.  The reject stays and the caller
//         supplies the SDDL.  Still Local: the reject is what makes the
//         class TRUE, while the DACL decides WHICH local principal may
//         open the endpoint - that is A7 in THREAT_MODEL.md, and A7 is
//         explicitly not what this class claims to answer
//
enum P2PeerConPipeAccess_e
{ P2PeerConPipeAccess_Owner      = 0    // reject remote + this account only
, P2PeerConPipeAccess_Descriptor        // reject remote + the caller's SDDL
, P2PeerConPipeAccess_Legacy            // the pre-revision call, unchanged
};

///////////////////////////////////////////////////////////////////////
//  P2PeerConPipe serial connection management
//  NOTES: Instances of these objects wholly manage single named pipe
//         serial connections.  Collections of P2PeerConPipe objects are
//         be supervised via P2PeerHub's
//       : P2PeerHub's pump P2PeerConPipe objects through P2PeerCon_MAP's
//         in response to state changes.
//
class Targetcore_EXT P2PeerConPipe : public P2PeerCon
{
      void
        RenderThisSafe();
      void
        CreateListenPipe();   // named-pipe creation; state-agnostic, shared by OnListen()/Accept()

    // Constructors and destructor
    public:
        P2PeerConPipe ( );
        P2PeerConPipe ( P2PaddrSTR pThatP2PaddrSTR
                      , LPCTSTR lpszPipename
                      , P2Peerio  *pP2Peerio = 0 );
        P2PeerConPipe ( LPCTSTR lpszPipename
                      , P2Peerio  *pP2Peerio = 0 );
      virtual
       ~P2PeerConPipe ( );

      static P2PeerConPipe*
        ServiceFactory( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR      sPipename );
      static P2PeerConPipe*
        ClientFactory ( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR      sPipename );
      virtual P2PeerCon*
        AcceptSpawn ( P2PeerCon *pCon );
      void
        Destroy ( );

    // IOCP Integration
    public:
      virtual void
        Drop ( P2Pevent *pEVENT );

    // Connection state operations
    // NOTES: Thread safe operations used to manage connection
    //        state.  Reference from P2PeerCon_MAP handlers only
    public:
      virtual bool
          Listen  ( );
      virtual void
        OnListen  ( );
      virtual bool
          Accept  ( );
      virtual P2PeerCon*
        OnAccept  ( );
      virtual void
        OnAccept  ( CP2Paddress oThatP2Paddr );
      virtual bool
          Connect ( );
      virtual void
          Close   ( );
      virtual BOOL
        OnClose  ( );

    // Locality
    // NOTES: Refer P2PeerConPipeAccess_e above for what the three modes
    //        mean and why the legacy one is kept
    //      : SetPipeAccess() must be called BEFORE Listen()/Accept().  It
    //        describes the pipe the next CreateNamedPipe will make; it
    //        cannot reach through a HANDLE that already exists, and
    //        TrustClass() reads the handle in preference to the setting
    //        precisely so that a late call cannot re-label a pipe that is
    //        already carrying traffic
    //      : pszSddl is read only by P2PeerConPipeAccess_Descriptor and is
    //        an SDDL string in the form
    //        ConvertStringSecurityDescriptorToSecurityDescriptor takes -
    //        "D:P(A;;FA;;;SY)(A;;FA;;;OW)" and the like.  A descriptor that
    //        does not parse is a THROW at pipe creation, not a silent
    //        fallback to the platform default: falling back would hand the
    //        caller a wider pipe than the one they asked for
    public:
      void
        SetPipeAccess ( P2PeerConPipeAccess_e eAccess
                      , LPCTSTR pszSddl = 0 );
      P2PeerConPipeAccess_e
        GetPipeAccess ( ) const;

      // What this pipe can vouch for about where its frames go
      // NOTES: Refer the definition for the argument.  It reads what the
      //        HANDLE was made with and falls back to what this object is
      //        configured to make, exactly as P2PeerConWsa::TrustClass()
      //        reads getpeername() and falls back to the listen scope
      virtual P2PeerConTrust_e
        TrustClass    ( ) const;

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;

    // Properties
    public:
      virtual bool
        HasDroppedOut ( HRESULT hr );

    // Attributes
    protected:
      CString  m_sPipename;

      // What the NEXT pipe this object creates will ask for, and the
      // descriptor P2PeerConPipeAccess_Descriptor uses.  A SETTING, and
      // copied by AcceptSpawn onto the re-armed service so that the second
      // instance of a pipe is the same pipe as the first
      P2PeerConPipeAccess_e m_ePipeAccess;
      CString               m_sPipeSddl;

      // What the pipe this object HOLDS was actually made with.  True only
      // where the kernel is keeping the promise: a CreateNamedPipe that
      // succeeded with PIPE_REJECT_REMOTE_CLIENTS and a descriptor this
      // transport wrote, an AF_UNIX socket on the Linux mapping, or a
      // client CreateFile against a local NPFS name
      // NOTES: NOT copied by AcceptSpawn, and that is not an omission.  The
      //        spawn holds no handle - it is the re-armed SERVICE and will
      //        set this for itself in CreateListenPipe().  A fact about a
      //        handle that was never opened is a lie
      //      : Separate from m_ePipeAccess because a setting is an
      //        INTENTION and a class has to be a FACT.  TrustClass() reads
      //        this one wherever there is a handle to read it from
      bool                  m_bPipeLocal;

      // Is the next pipe this object creates a RE-ARM - a further instance
      // of a pipe this transport already holds - rather than the first?
      // NOTES: Set by AcceptSpawn on the spawn and nowhere else.  The
      //        service that came out of ServiceFactory creates the FIRST
      //        instance, and that one is made with
      //        FILE_FLAG_FIRST_PIPE_INSTANCE so that a name another process
      //        has already created is refused rather than joined: the
      //        descriptor a pipe carries is the one its first instance was
      //        made with, so joining a squatted name would put this
      //        transport's traffic behind somebody else's DACL while
      //        m_bPipeLocal still read back the arguments this end passed.
      //        The spawn re-arms while the accepted instance is still open
      //        under this transport's own descriptor, and there the flag
      //        would refuse the transport's own pipe - so it is not passed,
      //        and the fact rests on the sibling instead
      bool                  m_bPipeRearm;
};

