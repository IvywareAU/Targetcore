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
//
//  P2PeerioGcm - AES-256-GCM implementation of the P2PeerioCrypto interface
//  NOTES: Seals each P2Piomage payload independently under a fresh random
//         nonce.  The sealed payload is 28 bytes longer than the plaintext -
//         12 for the nonce, 16 for the tag - which is why P2PeerioCrypto grew
//         SealedSize()/OpenedSize()
//       : This replaced CRijndael, which claimed to implement P2PeerioCrypto
//         but overrode none of its methods (different signatures, three of the
//         five absent entirely) and was therefore abstract and impossible to
//         construct.  P2PeerioGcm is the first real implementation, and
//         Rijndael.{h,cpp} has since been removed from the tree
//       : Post an instance with P2Peerio::PostP2Pcrypto(), which takes
//         ownership.  The key must be installed before the first frame moves
//       : No additional authenticated data is passed today.  The frame header
//         (oSync) travels in clear and is NOT covered by the tag - it carries
//         only a length and an addressing mode, and a lie about either is
//         caught when the tag fails
//
#pragma once

#include "P2Peerio.h"
#include "P2PCngCrypto.h"

//
//  AES-256-GCM payload cypher
//  NOTES: One instance per connection, holding TWO keys - one per direction.
//         Both ends derive both, and disagree only about which is which, so
//         the key a peer seals with is never the key it opens with.  That
//         matters because the nonce is 96 bits and RANDOM: NIST SP 800-38D
//         section 8.3 bounds a random-IV key at 2^32 invocations, and a
//         single key used by both ends spends that budget from both ends at
//         once, with neither able to see the other's draws.  Split, each key
//         has exactly one writer
//       : The single-key SetKey() remains and installs the SAME key both
//         ways.  That is the LOOPBACK shape - one object sealing and opening
//         its own frames - which the self test below and the unit harnesses
//         use, and it is NOT what a connection does.  A connection calls
//         SetKeyPair()
//       : The underlying AesGcm holds a BCrypt key handle.  Encrypt on one
//         thread and Decrypt on another is sound - the OpenSSL backend
//         builds a fresh EVP_CIPHER_CTX per call and the CNG one reuses a
//         key handle documented as safe for concurrent use - but the two
//         directions now touch different members anyway
class Targetcore_EXT P2PeerioGcm : public P2PeerioCrypto
{
    // Constructors and destructor
    public:
        P2PeerioGcm ( );
      virtual
       ~P2PeerioGcm ( );

    // P2PeerioCrypto
    public:
      virtual void
        SetKey ( const char *pPKey, int nPKeySize
               , int iParam1, int iParam2 );
      virtual void
        SetBlockSize ( int nBlockSize );
      virtual BOOL
        Encrypt ( const char *pcBufferIn, char *pBufferOut, int nBytes
                , int iParam1, int iParam2 );
      virtual BOOL
        Decrypt ( const char *pcBufferIn, int nBytes, char *pBufferOut
                , int iParam1, int iParam2 );
      virtual DWORD
        GetOptions ( );
      virtual UINT
        SealedSize ( UINT nPlainBytes  );
      virtual UINT
        OpenedSize ( UINT nSealedBytes );

    // Directional keying
    //  NOTES: pSendKey is the key THIS end seals with and pRecvKey the one it
    //         opens with.  The caller decides which is which from its role in
    //         the handshake; this class does not know what a client is.  Both
    //         lengths must be kAesKeyLen, and installing one key twice is a
    //         caller error this cannot detect - it is a legitimate loopback
    public:
      void
        SetKeyPair ( const char *pSendKey, int nSendKeySize
                   , const char *pRecvKey, int nRecvKeySize );

    // State
    public:
      bool
        IsKeyed ( ) const { return m_bKeyed; }

    // Implementation
    protected:
      p2pcng::AesGcm  m_oGcmSend;      // sealed with, outbound
      p2pcng::AesGcm  m_oGcmRecv;      // opened with, inbound
      bool            m_bKeyed;

    // Not copyable - the key handle underneath has single ownership
    private:
        P2PeerioGcm ( const P2PeerioGcm & );
      P2PeerioGcm&
        operator= ( const P2PeerioGcm & );
};

//
//  Self test
//  NOTES: Exercises the interface as P2Peerio drives it, including the
//         expansion arithmetic and a deliberately corrupted tag
P2PCNG_EXT bool
GcmCryptoSelfTest ( );
