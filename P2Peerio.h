// Copyright © 2005-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2Peerio definitions and prototypes
//  NOTES: Base class from which all P2Peer protocol translation
//         objects are derived.  Such objects are aggregated within
//         P2PeerCon derived objects
//       : Manages P2PeerMsg image exchanges
//                      
#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2Peer.h"
#include "P2PeerMsg.h"

//
//  P2PeerioPKeyXChange - REMOVED
//  NOTES: The posted-exchanger interface for the legacy hand-rolled
//         Diffie-Hellman.  Its only implementation (DHPKeyXChanger) was never
//         constructed anywhere, and PostP2PKeyXChange() - the only thing that
//         could install one - had no callers.  Both are gone with it
//       : The live key agreement needs no posted object: P2PeerCon runs an
//         ephemeral ECDH P-256 exchange on the connection itself and installs
//         the resulting AES-256-GCM cypher through PostP2Pcrypto().  See
//         P2PCngCrypto.h and SECURITY.md
//

//
//  P2Peerio Encryption - decryption interface
//  NOTES: Interface used for encryption - decryption of messages
//       : Encryption is facilitated by posting an instance of this
//         interface to a P2Peerio object.  Refer PostCrypto()
//         for further details
//       : P2PeerioGcm provides the implementation (AES-256-GCM).  The legacy
//         CRijndael claimed to and never did - it overrode none of the methods
//         below (different signatures, three absent entirely), so it was
//         abstract and could not be constructed.  It has been removed
//       : Encrypt() and Decrypt() both return TRUE on success and FALSE on
//         failure.  For an AEAD a FALSE from Decrypt() is a tag mismatch, i.e.
//         the frame was forged or tampered with, and the caller drops it down
//         the P2Pmsg_CypherEx path
//       : SealedSize()/OpenedSize() describe the length change the cipher
//         applies.  They default to the identity, which is correct for a
//         one-for-one block cipher; an AEAD overrides them to account for its
//         nonce and tag.  DecryptP2PiomageSwap() sizes its output buffer from
//         OpenedSize() alone, so an implementation must never produce more
//         bytes than it promises there
struct P2PeerioCrypto
{
    virtual
     ~P2PeerioCrypto ( ) {}
    virtual void
      SetKey ( const char *pPKey, int nPKeySize
             , int iParam1, int iParam2 ) = 0;
    virtual void
      SetBlockSize ( int nBlockSize ) = 0;
    virtual BOOL
      Encrypt ( const char *pcBufferIn, char *pBufferOut, int nBytes
              , int iParam1, int iParam2 ) = 0;
    virtual BOOL
      Decrypt ( const char *pcBufferIn, int nBytes, char *pBufferOut
              , int iParam1, int iParam2 ) = 0;
    virtual DWORD
      GetOptions ( ) = 0;

    // Length change applied by this cipher, in payload (cIOmage) bytes.
    // Default identity: a block cipher of the original design's shape neither
    // grows nor shrinks its input.
    virtual UINT
      SealedSize ( UINT nPlainBytes  ) { return nPlainBytes;  }
    virtual UINT
      OpenedSize ( UINT nSealedBytes ) { return nSealedBytes; }
};

//
//  P2Peer overlapped IO control
//  NOTES: Extended implementation of the Win32 OVERLAPPED structure
typedef struct
{
    OVERLAPPED   oOverlapped;          // Win32
    P2PsigID     nSigID;               // Signal
    P2PmsgHANDLE hP2Pmsg;              // Message memory HANDLE
    HRESULT      hr;
    int          eAction;
    bool         bQueued;              // Queued state
    bool         bDelete;              // Delete
    bool         bRecvSubmitted;       // A TRANSPORT READ is outstanding on this object.
                                       // Set by P2Peerio::Recv at submission, read and
                                       // cleared by P2PeerCon::On_QueuedCompletionStatus
                                       // on receipt.  It exists to tell the two ways this
                                       // object reaches the recv branch apart, because on
                                       // Windows they are otherwise identical: an ARMING
                                       // post (PostOVERLAPPED / RearmRecv, which call
                                       // PostQueuedCompletionStatus with 0 bytes) and a
                                       // peer's ORDERLY CLOSE (a real ReadFile completing
                                       // with 0 bytes, i.e. FIN) both arrive as success
                                       // carrying zero.  Linux never needed it - the
                                       // io_uring shim marks the op OVERLAPPED::_p2p_op
                                       // at submission and turns res==0 on a READ into
                                       // ERROR_HANDLE_EOF (Platform/p2piocp.cpp) - which
                                       // is why F-S4-1 was a Windows-only defect.
    DWORD_PTR   dwUserData;
    DWORD       dwBytesMax;
    DWORD       dwBytes;               // Bytes in buffer
    char        *pUserDB1;             // User defined buffer1
    char        *pUserDB2;             // User defined buffer2
    char        *pBuffer;              // Buffer
    void        *pOwnerCon;            // Owning P2PeerCon (set by MakeOVERLAPPED). Stable for
                                       // the object's life; lets the teardown drain attribute a
                                       // cancelled completion whose fd->key assoc CloseHandle
                                       // already erased (keyless on Linux, §5.6) to its con.
} OVERLAPPEDcon;

//
//  P2Peer protocol management
//  NOTES: Instances of these objects manage protocol translation for
//         P2PeerMsg's exchanged between P2PeerHub's
//       : Aggregated within P2PeerCon objects
//
class P2PeerCon;
class TargetCore_EXT P2Peerio
{
      void
        RenderThisSafe() noexcept;

    // Constructors and destructor
    public:
        P2Peerio ( ) noexcept;
      virtual
       ~P2Peerio ( );
      virtual P2Peerio*
        Clone ( );

    // Registration and postings
    public:
      P2Peerio*
        Register ( P2PeerCon *pCon );
      virtual void
        PostP2Pcrypto ( P2PeerioCrypto *pP2Pcrypto );

      // Is a cypher installed AND consulted by this io class?
      // NOTES: F-S6-2. The snapshot answer to "is this
      //        connection's traffic encrypted", and it has to be virtual
      //        rather than a test of the pointer, because whether the hooks
      //        run at all is decided by which subclass a transport's factory
      //        constructed - which was F-S6-3. The base class holds the
      //        pointer and calls it, so here the pointer IS the answer; a
      //        subclass that overrides SendP2PeerMsg/RecvP2PeerMsg and never
      //        consults the hooks must say so by overriding this too
      //      : Reporting it did not close F-S6-3 and was never going to -
      //        nothing HERE stops the next subclass author from overriding the
      //        two message methods and forgetting this one. What closes it is
      //        the pair below plus the two enforcement points named over
      //        "Protocol translation", one of which needs no override at all
      virtual bool
        IsCypherActive ( ) const { return m_pP2Pcrypto != nullptr; }

      // Do this class's frames LEAVE this process?
      // NOTES: F-S6-3, and the companion to IsCypherActive
      //        above.  Neither question is a defect on its own; the PAIR is
      //        the rule stated over "Protocol translation" below.  A class
      //        that answers TRUE here and FALSE there is a plaintext wire on
      //        a connection that completed a key agreement, and
      //        P2PeerCon::KeyXDerive refuses to arm one
      //      : TRUE by default, and deliberately the unsafe-sounding answer.
      //        A subclass that says nothing is taken to be a wire, so a new
      //        transport is refused until its author has answered.  The
      //        opposite default would let silence mean "exempt", which is the
      //        state F-S6-3 found the tree in
      //      : True is also simply CORRECT for the base class - it is the wire
      //        class.  TCP, named pipe and serial all construct P2Peerio
      //        itself (P2PeerConWsa, P2PeerConPipe, P2PeerCon232), so this is
      //        not a safe guess standing in for an answer
      virtual bool
        LeavesProcess ( ) const { return true; }

    // IOCP Integration
    public:
      virtual bool
        On_QueuedCompletionStatus ( DWORD dwError
                                  , DWORD dwBytes
                                  , OVERLAPPEDcon *pOVERLAPPEDcon );

    // Protocol translation
    // NOTES: Perform raw P2PeerMsg exchange between P2PeerHub's
    //
    //  THE RULE, for anyone overriding the two virtuals below
    //  ------------------------------------------------------
    //  Any transport whose frames LEAVE this process routes them through this
    //  class's cypher hooks - EncryptP2PiomageSwap on the way out and
    //  DecryptP2PiomageSwap on the way in - or documents at its own override
    //  why it does not AND says so in code, by answering LeavesProcess() and
    //  IsCypherActive() for what it actually does.
    //
    //  Overriding SendP2PeerMsg / RecvP2PeerMsg takes those hooks out of the
    //  path.  A session cypher installed by PostP2Pcrypto() is then held and
    //  never consulted, and the wire is in clear on a connection that ran the
    //  agreement and reports itself keyed.  F-S6-3 is the
    //  finding that this was a CONVENTION - true of every transport in the
    //  tree by inheritance, enforced nowhere.  It is enforced in two places
    //  now, and they answer different failures:
    //
    //    * P2PeerCon::KeyXDerive refuses to arm a connection whose io object
    //      answers LeavesProcess() && !IsCypherActive(), at the instant the
    //      cypher is installed - so the refusal precedes the first frame and
    //      m_bKeyXDone is never set.  This catches the author who answers
    //      the two questions HONESTLY.
    //    * Send() below refuses to write bytes that no sealing decision was
    //      made about, whenever a cypher is installed.  This catches the
    //      author who overrides the message methods and answers nothing -
    //      the residual the F-S6-2 note above could only describe.
    //
    //  P2PeerioDmx is the one legitimate exemption in this tree, and it now
    //  declares itself rather than being recognised by class: the DMX handoff
    //  is a pointer between two objects in ONE process, so there is no wire
    //  and encrypting it would protect nothing.  Read its header before
    //  adding a second exemption.
    public:
      virtual DWORD
        SendP2PeerMsg ( HANDLE hFile
                      , P2PeerMsg *pMsg
                      , OVERLAPPEDcon *pOVERLAPPEDsend );
      DWORD
        Send ( HANDLE hFile
             , const void *pvData, DWORD wDataSize
             , OVERLAPPEDcon *pOVERLAPPEDsend );
      virtual P2PeerMsg*
        PreDestroySendP2PeerMsg ( P2PeerMsg *pMsg );
      virtual P2PeerMsg*
        RecvP2PeerMsg ( HANDLE hFile
                      , OVERLAPPEDcon *pOVERLAPPEDrecv );
      DWORD
        Recv ( HANDLE hFile
             , void *pvData, DWORD wDataSize
             , OVERLAPPEDcon *pOVERLAPPEDrecv );

    // Timers
    public:
      PITimerID
        SetPITimer ( P2Pmsecs_t uMSecDelay, DWORD dwUserKey = 0 );
      virtual void
        On_PITimer ( bool bCancel
                   , PITimerID nPITimerID, DWORD dwUserKey );

    // Encryption - decryption
    // NOTES: External interfaces control PKey exchange and encryption
    public:
      virtual void
          PKeyXChange ( const P2Piomage *pP2Piomage );
      virtual void
        OnPKeyXChange ( const P2Piomage *pP2Piomage );
      virtual void
          PKeyXChangeAck ( const P2Piomage *pP2Piomage );
      virtual void
        OnPKeyXChangeAck ( const P2Piomage *pP2Piomage );
      virtual const P2Piomage*
        EncryptP2PiomageSwap ( const P2Piomage *cpP2PiomageSend );
      virtual P2Piomage*
        DecryptP2PiomageSwap ( const P2Piomage *cpP2PiomageRecv );

    // Specialisation
    public:
      virtual void
           Acknowledge ( HANDLE hFile, P2PeerMsg *pMsg );
      virtual bool
        On_Acknowledge ( bool bAckNak );
      virtual void
        Reset ( );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
      virtual P3PmsgItem
        SetP2PeventFParams ( LPCTNAM lpszVar );

    // Properties
    public:
      bool
        SetIFTrace ( bool bIFTRaceEoD );
      bool
        GetIFTrace ( );
      P2PeerCon*
        GetP2PeerCon ( );
      DWORD
        SetIFmask ( DWORD dwIFmask );
      DWORD
        GetIFmask ( );
      DWORD
        GetMaxRecvSize ( ) const;
      DWORD
        SetMaxRecvSize ( DWORD dwMaxRecvSize );
      DWORD
        GetMaxSendSize ( ) const;
      DWORD
        SetMaxSendSize ( DWORD dwMaxSendSize );
      bool
        IsEncrypted ( );

    // Attributes
    private:
      P2PeerioCrypto      *m_pP2Pcrypto;
      OVERLAPPEDcon       *m_pOVERLAPPEDcrypto;
    protected:
      P2PeerCon      *m_pCon;
      struct
      {
        P2Piomage    *pEncrypted;      // Original size is lost with each re-use
        UINT          nSizeof;         // Original size
      } m_oP2Piomage;
      bool            m_bEncrypted;
      bool            m_bSealDecided;  // F-S6-3: SendP2PeerMsg made the seal
                                       // /exempt decision for the frame Send()
                                       // is about to write.  Minted there,
                                       // required and consumed there
      bool            m_bIFTraceEoD;
      bool            m_bAckEoD;
      DWORD           m_dwMaxRecvSize;
      DWORD           m_dwMaxSendSize;
      DWORD           m_dwIFmask;
      OVERLAPPEDcon  *m_pOVERLAPPEDack;
      PITimerID       m_nPITimerIDack;
};

//
//  P2Pevent::SetFParam ( const P2PmsgNode& oNode ) helpers
//  NOTES: Appends P2PmsgNode details to P2Pevent
//       : Usage
//         EVERR->MODULE
//              ->AFP(nPumpID)->AFPeerio(pP2Peerio)->AFPyourObj(pYourObj)
//              ->Message("This is an event associated message")
//       : P2PmsgNode containing P2Peerio details is appended beneath
//         the P2Pevent module node.  It should be assumed that any
//         appended parameters will have global exposure
#define AFPeerio(arg) SetFParam(_N(#arg),arg->SetP2PeventFParams(_N(#arg)))

/////////////////////////////////////////////////
//  Assistants and helpers

//P2Piomage*
//P2Piomage_Create ( int nIOmageSize );
//P2Piomage*
//P2Piomage_Release ( P2Piomage *pIOmage );
//UINT
//P2Piomage_Sizeof ( const P2Piomage *pIOmage );
//UINT
//IOmage_Sizeof ( const P2Piomage *pIOmage );
//BOOL
//IOmage_IsPKeySwap ( const P2Piomage *pIOmage );
