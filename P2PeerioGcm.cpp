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
//  P2PeerioGcm implementation
//  NOTES: AES-256-GCM over the P2PeerioCrypto interface
//

#include "stdafx.h"
#include "P2PeerioGcm.h"

#include <cstring>

//
//  Construction
//
P2PeerioGcm::P2PeerioGcm ( )
  : m_bKeyed ( false )
{
}

P2PeerioGcm::~P2PeerioGcm ( )
{
}

//
//  Install the session key
//  NOTES: Exactly 32 bytes - AES-256.  A short key is a programming error in
//         the key schedule above this class, not a runtime condition to be
//         absorbed quietly, so it throws rather than leaving the object in an
//         unkeyed state that would fail obscurely on the first frame
//       : iParam1/iParam2 are unused.  They exist because the interface was
//         shaped for a block cipher's mode and IV arguments
//
//  Parameters:  const char *pPKey    Key material
//               int         nPKeySize Length in bytes, must be 32
//
void
P2PeerioGcm::SetKey ( const char *pPKey, int nPKeySize
                    , int /*iParam1*/, int /*iParam2*/ )
{
    m_bKeyed = false;

    if ( pPKey == 0 || nPKeySize != (int)p2pcng::kAesKeyLen )
      EVERR->MODULE
           ->Message ( "AES-256-GCM requires a %u byte key, got %d"
                     , (unsigned)p2pcng::kAesKeyLen, nPKeySize )
           ->Throw ( );

    if ( !m_oGcm.SetKey ( (const unsigned char *)pPKey, (size_t)nPKeySize ) )
      EVERR->MODULE
           ->Message_T ( "AES-256-GCM key installation failed" )
           ->Throw ( );

    m_bKeyed = true;
}

//
//  Block size
//  NOTES: GCM is a stream mode over a counter and has no block size to set.
//         Accepted and ignored so that callers written against the old
//         interface are not surprised by a throw
//
void
P2PeerioGcm::SetBlockSize ( int /*nBlockSize*/ )
{
}

//
//  Options
//  NOTES: Never called anywhere in the library - the accessor is vestigial on
//         both crypto interfaces.  Zero rather than an invented flag word
//
DWORD
P2PeerioGcm::GetOptions ( )
{
    return 0;
}

//
//  Expansion arithmetic
//  NOTES: 12 byte nonce + 16 byte tag = 28 bytes of growth per frame
//       : OpenedSize() returns zero for anything too short to hold both, which
//         DecryptP2PiomageSwap() treats as a malformed frame
//
UINT
P2PeerioGcm::SealedSize ( UINT nPlainBytes )
{
    return (UINT)p2pcng::AesGcm::SealedSize ( (size_t)nPlainBytes );
}

UINT
P2PeerioGcm::OpenedSize ( UINT nSealedBytes )
{
    return (UINT)p2pcng::AesGcm::OpenedSize ( (size_t)nSealedBytes );
}

//
//  Seal one payload
//  NOTES: A fresh random nonce is drawn per call by AesGcm::Seal() and written
//         at the head of the output, so an identical payload never produces an
//         identical frame - the repetition leak of the original ECB design
//
//  Parameters:  const char *pcBufferIn   Plaintext
//               char       *pBufferOut   Output, SealedSize(nBytes) bytes
//               int         nBytes       PLAINTEXT length
//
//  Returns:     BOOL  TRUE on success
//
BOOL
P2PeerioGcm::Encrypt ( const char *pcBufferIn, char *pBufferOut, int nBytes
                     , int /*iParam1*/, int /*iParam2*/ )
{
    if ( !m_bKeyed || pcBufferIn == 0 || pBufferOut == 0 || nBytes < 0 )
      return FALSE;

    size_t cbOut = 0;
    if ( !m_oGcm.Seal ( (const unsigned char *)pcBufferIn, (size_t)nBytes
                      , 0, 0
                      , (unsigned char *)pBufferOut
                      , p2pcng::AesGcm::SealedSize ( (size_t)nBytes )
                      , &cbOut ) )
      return FALSE;

    return cbOut == p2pcng::AesGcm::SealedSize ( (size_t)nBytes ) ? TRUE : FALSE;
}

//
//  Open one payload
//  NOTES: A FALSE return is a tag failure - the frame was forged or altered in
//         flight.  The caller raises P2Pmsg_CypherEx and the connection goes
//         down; nothing from a frame that failed its tag is ever propagated
//
//  Parameters:  const char *pcBufferIn   Sealed frame
//               int         nBytes       SEALED length
//               char       *pBufferOut   Output, OpenedSize(nBytes) bytes
//
//  Returns:     BOOL  TRUE on success
//
BOOL
P2PeerioGcm::Decrypt ( const char *pcBufferIn, int nBytes, char *pBufferOut
                     , int /*iParam1*/, int /*iParam2*/ )
{
    if ( !m_bKeyed || pcBufferIn == 0 || pBufferOut == 0 || nBytes < 0 )
      return FALSE;

    const size_t cbPlain = p2pcng::AesGcm::OpenedSize ( (size_t)nBytes );
    if ( cbPlain == 0 )
      return FALSE;                    // Shorter than nonce + tag

    size_t cbOut = 0;
    if ( !m_oGcm.Open ( (const unsigned char *)pcBufferIn, (size_t)nBytes
                      , 0, 0
                      , (unsigned char *)pBufferOut, cbPlain, &cbOut ) )
      return FALSE;

    return cbOut == cbPlain ? TRUE : FALSE;
}

//
//  Self test
//  NOTES: Exercises the class the way P2Peerio drives it - size first, then
//         seal into a buffer of exactly that size, then open.  The negative
//         cases matter more than the positive one: a cypher that cannot detect
//         tampering is worse than no cypher, because it looks like protection
//
//  Returns:     bool  true when every check passes
//
bool
GcmCryptoSelfTest ( )
{
    unsigned char aKey[p2pcng::kAesKeyLen];
    for ( size_t i = 0; i < sizeof(aKey); ++i )
      aKey[i] = (unsigned char)( i * 7 + 1 );

    // 1. Expansion arithmetic, including the degenerate lengths
    P2PeerioGcm oGcm;
    if ( oGcm.SealedSize ( 0 )  != 28 ) return false;
    if ( oGcm.SealedSize ( 10 ) != 38 ) return false;
    if ( oGcm.OpenedSize ( 38 ) != 10 ) return false;
    if ( oGcm.OpenedSize ( 28 ) != 0  ) return false;
    if ( oGcm.OpenedSize ( 27 ) != 0  ) return false;
    if ( oGcm.OpenedSize ( 0 )  != 0  ) return false;

    // 2. Unkeyed refuses to do anything
    char aScratch[128];
    if ( oGcm.IsKeyed ( ) )                                        return false;
    if ( oGcm.Encrypt ( "abc", aScratch, 3, 0, 0 ) )               return false;
    if ( oGcm.Decrypt ( aScratch, 64, aScratch, 0, 0 ) )           return false;

    oGcm.SetKey ( (const char *)aKey, (int)sizeof(aKey), 0, 0 );
    if ( !oGcm.IsKeyed ( ) ) return false;

    // 3. Round trip
    const char szPlain[] = "TargetCore payload, sealed.";
    const UINT nPlain    = (UINT)sizeof(szPlain);   // includes the terminator
    const UINT nSealed   = oGcm.SealedSize ( nPlain );

    unsigned char *pSealed = new unsigned char[nSealed];
    unsigned char *pOpened = new unsigned char[nPlain];
    bool bOk = true;

    if ( !oGcm.Encrypt ( szPlain, (char *)pSealed, (int)nPlain, 0, 0 ) )
      bOk = false;

    // 4. The ciphertext is not the plaintext
    if ( bOk && memcmp ( pSealed + p2pcng::kGcmNonceLen, szPlain, nPlain ) == 0 )
      bOk = false;

    if ( bOk && !oGcm.Decrypt ( (const char *)pSealed, (int)nSealed
                              , (char *)pOpened, 0, 0 ) )
      bOk = false;
    if ( bOk && memcmp ( pOpened, szPlain, nPlain ) != 0 )
      bOk = false;

    // 5. Sealing the same plaintext twice must not produce the same frame -
    //    the per-call nonce is what stops an observer counting repeats
    if ( bOk )
    {
      unsigned char *pSealed2 = new unsigned char[nSealed];
      if ( !oGcm.Encrypt ( szPlain, (char *)pSealed2, (int)nPlain, 0, 0 ) )
        bOk = false;
      if ( bOk && memcmp ( pSealed, pSealed2, nSealed ) == 0 )
        bOk = false;
      delete [] pSealed2;
    }

    // 6. Tamper detection, one flipped bit at a time, across all three regions
    const UINT anProbe[] = { 0                              // nonce
                           , p2pcng::kGcmNonceLen           // first cipher byte
                           , nSealed - 1 };                 // last tag byte
    for ( size_t i = 0; bOk && i < sizeof(anProbe)/sizeof(anProbe[0]); ++i )
    {
      pSealed[anProbe[i]] ^= 0x01;
      if ( oGcm.Decrypt ( (const char *)pSealed, (int)nSealed
                        , (char *)pOpened, 0, 0 ) )
        bOk = false;                   // Accepted a forgery
      pSealed[anProbe[i]] ^= 0x01;     // Restore
    }

    // 7. Truncation is rejected
    if ( bOk && oGcm.Decrypt ( (const char *)pSealed, (int)( nSealed - 1 )
                             , (char *)pOpened, 0, 0 ) )
      bOk = false;

    // 8. A different key does not open it
    if ( bOk )
    {
      P2PeerioGcm oOther;
      aKey[0] ^= 0xFF;
      oOther.SetKey ( (const char *)aKey, (int)sizeof(aKey), 0, 0 );
      if ( oOther.Decrypt ( (const char *)pSealed, (int)nSealed
                          , (char *)pOpened, 0, 0 ) )
        bOk = false;
      aKey[0] ^= 0xFF;
    }

    delete [] pSealed;
    delete [] pOpened;
    return bOk;
}
