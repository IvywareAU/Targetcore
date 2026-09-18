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
  , m_uSealCount ( 0 )
  , m_uSealCeiling ( kGcmMaxSeals )
{
}

P2PeerioGcm::~P2PeerioGcm ( )
{
}

//
//  Install ONE key, used in both directions
//  NOTES: Exactly 32 bytes - AES-256.  A short key is a programming error in
//         the key schedule above this class, not a runtime condition to be
//         absorbed quietly, so it throws rather than leaving the object in an
//         unkeyed state that would fail obscurely on the first frame
//       : iParam1/iParam2 are unused.  They exist because the interface was
//         shaped for a block cipher's mode and IV arguments
//       : THIS IS THE LOOPBACK FORM and is kept because that is a real use -
//         one object sealing and opening its own frames, which is what the
//         self test and the unit harnesses do.  A CONNECTION must not use it:
//         one key drawn on by both ends halves the random-nonce budget and
//         leaves neither end able to count what the other spends.  Refer the
//         class note and SetKeyPair() below
//
//  Parameters:  const char *pPKey    Key material
//               int         nPKeySize Length in bytes, must be 32
//
void
P2PeerioGcm::SetKey ( const char *pPKey, int nPKeySize
                    , int /*iParam1*/, int /*iParam2*/ )
{
    SetKeyPair ( pPKey, nPKeySize, pPKey, nPKeySize );
}

//
//  Install the two directional keys
//  NOTES: Both halves are installed or neither is - m_bKeyed is cleared first
//         and set only once both have taken, so a throw between them cannot
//         leave an object that seals under a new key and opens under an old
//       : The two keys are NOT compared.  Passing the same key twice is the
//         loopback case above and is legitimate; this class cannot tell that
//         from a caller that has derived one key by mistake, and the place
//         that knows is the key schedule
//
//  Parameters:  const char *pSendKey  Key this end SEALS with
//               int         nSendKeySize  Length in bytes, must be 32
//               const char *pRecvKey  Key this end OPENS with
//               int         nRecvKeySize  Length in bytes, must be 32
//
void
P2PeerioGcm::SetKeyPair ( const char *pSendKey, int nSendKeySize
                        , const char *pRecvKey, int nRecvKeySize )
{
    m_bKeyed = false;

    if ( pSendKey == 0 || nSendKeySize != (int)p2pcng::kAesKeyLen ||
         pRecvKey == 0 || nRecvKeySize != (int)p2pcng::kAesKeyLen    )
      EVERR->MODULE
           ->Message ( "AES-256-GCM requires two %u byte keys, got %d and %d"
                     , (unsigned)p2pcng::kAesKeyLen
                     , nSendKeySize, nRecvKeySize )
           ->Throw ( );

    if ( !m_oGcmSend.SetKey ( (const unsigned char *)pSendKey
                            , (size_t)nSendKeySize ) )
      EVERR->MODULE
           ->Message_T ( "AES-256-GCM send key installation failed" )
           ->Throw ( );

    if ( !m_oGcmRecv.SetKey ( (const unsigned char *)pRecvKey
                            , (size_t)nRecvKeySize ) )
      EVERR->MODULE
           ->Message_T ( "AES-256-GCM receive key installation failed" )
           ->Throw ( );

    //  A NEW KEY IS A NEW BUDGET, and this reset is load-bearing rather than
    //  tidy: the ceiling bounds seals under ONE key, so carrying a count
    //  across a rekey would refuse traffic the new key is entitled to, and
    //  failing to reset on a key that is genuinely new would do the same.
    //  Reset here and not in the constructor alone, because SetKeyPair is
    //  where a key becomes current.
    m_uSealCount.store ( 0 );

    m_bKeyed = true;
}

//
//  Lower the nonce budget below the standard's figure
//  NOTES: Does NOT reset the count.  Setting a ceiling below the seals
//         already done means the next seal is refused, which is the honest
//         reading of "this key has had enough" and the one a test relies on
//       : Zero is accepted and means "refuse everything", which is a
//         legitimate thing to ask for and is how the gate proves the refusal
//         without sealing 2^32 frames first
//
void
P2PeerioGcm::SetSealCeiling ( unsigned long long uSeals )
{
    m_uSealCeiling.store ( uSeals );
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
//       : And that randomness is what BOUNDS the key, so this counts.  Past
//         the ceiling it refuses, and a refusal here becomes "Payload
//         encryption failed" at P2Peerio.cpp and the connection goes down -
//         fail-closed, which is the right direction.  The specific reason is
//         in the event raised below, because "encryption failed" alone would
//         send an operator looking for a crypto fault that is not there
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

    //  THE NONCE BUDGET.  One fetch_add and one comparison against the value
    //  it returned, so two senders cannot both read the same count and both
    //  pass - the same reasoning the accept bounds were fixed under on
    //  2026-09-17, where reading a bound twice let a setter land between the
    //  reads.  No more than the ceiling can ever be admitted.
    //
    //  The count keeps rising after the ceiling, on refusals as well, and
    //  that is deliberate: it costs nothing, it cannot wrap in any reachable
    //  lifetime, and it lets the diagnostic say how far past the line the
    //  caller has gone rather than only that it crossed it.
    const unsigned long long uCeiling = m_uSealCeiling.load ( );
    const unsigned long long uPrev    = m_uSealCount.fetch_add ( 1 );
    if ( uPrev >= uCeiling )
    {
      //  ONCE, at the crossing.  A dropped link retries, and a diagnostic
      //  per retry would bury the one line that explains the drop.  Cancel
      //  rather than Display: Display neither disposes the event nor hands
      //  it to anybody who will, which is the leak recorded against the
      //  image-generation gate on 2026-08-21.
      if ( uPrev == uCeiling )
        EVERR->MODULE
             ->Message ( "AES-256-GCM send key has reached its %llu seal "
                         "budget and will not be used again"
                       , (unsigned long long)uCeiling )
             ->Advice_T ( "The 96-bit random nonce bounds a key at 2^32 seals "
                          "(NIST SP 800-38D 8.3); past it a nonce collision "
                          "is no longer negligible and would expose the GHASH "
                          "subkey. Re-key the connection - drop it and let it "
                          "re-establish - rather than raising the ceiling." )
             ->Cancel ( true );
      return FALSE;
    }

    size_t cbOut = 0;
    if ( !m_oGcmSend.Seal ( (const unsigned char *)pcBufferIn, (size_t)nBytes
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
    if ( !m_oGcmRecv.Open ( (const unsigned char *)pcBufferIn, (size_t)nBytes
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
    const char szPlain[] = "Targetcore payload, sealed.";
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

    // 9. THE DIRECTIONAL SPLIT, and it is built so that a single-key build
    //    fails it rather than passing quietly.  Two objects keyed as the two
    //    ends of a connection are: A seals with K1 and opens with K2, B seals
    //    with K2 and opens with K1
    if ( bOk )
    {
      unsigned char aK1[p2pcng::kAesKeyLen];
      unsigned char aK2[p2pcng::kAesKeyLen];
      for ( size_t i = 0; i < sizeof(aK1); ++i )
      {
        aK1[i] = (unsigned char)( i * 3 + 5 );
        aK2[i] = (unsigned char)( i * 11 + 2 );
      }

      P2PeerioGcm oA, oB;
      oA.SetKeyPair ( (const char *)aK1, (int)sizeof(aK1)
                    , (const char *)aK2, (int)sizeof(aK2) );
      oB.SetKeyPair ( (const char *)aK2, (int)sizeof(aK2)
                    , (const char *)aK1, (int)sizeof(aK1) );

      const char szDir[] = "directional";
      const UINT nDir    = (UINT)sizeof(szDir);
      const UINT nDirSl  = oA.SealedSize ( nDir );

      unsigned char *pAB   = new unsigned char[nDirSl];
      unsigned char *pPlay = new unsigned char[nDir];

      // A -> B opens
      if ( !oA.Encrypt ( szDir, (char *)pAB, (int)nDir, 0, 0 ) )
        bOk = false;
      if ( bOk && !oB.Decrypt ( (const char *)pAB, (int)nDirSl
                              , (char *)pPlay, 0, 0 ) )
        bOk = false;
      if ( bOk && memcmp ( pPlay, szDir, nDir ) != 0 )
        bOk = false;

      // A MUST NOT open its own frame.  This is the whole point: with one
      // key for both directions it would succeed, so a single-key build
      // fails here.  A green round trip above proves nothing on its own
      if ( bOk && oA.Decrypt ( (const char *)pAB, (int)nDirSl
                             , (char *)pPlay, 0, 0 ) )
        bOk = false;

      // ...and the mirror, so the failure above cannot be a dud key
      if ( bOk )
      {
        unsigned char *pBA = new unsigned char[nDirSl];
        if ( !oB.Encrypt ( szDir, (char *)pBA, (int)nDir, 0, 0 ) )
          bOk = false;
        if ( bOk && !oA.Decrypt ( (const char *)pBA, (int)nDirSl
                                , (char *)pPlay, 0, 0 ) )
          bOk = false;
        if ( bOk && oB.Decrypt ( (const char *)pBA, (int)nDirSl
                               , (char *)pPlay, 0, 0 ) )
          bOk = false;
        delete [] pBA;
      }

      // A peer that got the ORDER wrong opens nothing - the loud failure the
      // derivation comment promises
      if ( bOk )
      {
        P2PeerioGcm oWrong;
        oWrong.SetKeyPair ( (const char *)aK1, (int)sizeof(aK1)
                          , (const char *)aK2, (int)sizeof(aK2) );
        if ( oWrong.Decrypt ( (const char *)pAB, (int)nDirSl
                            , (char *)pPlay, 0, 0 ) )
          bOk = false;
      }

      delete [] pAB;
      delete [] pPlay;
    }

    // 10. The single-key form is still a working loopback, because the self
    //     test and the unit harnesses depend on it
    if ( bOk )
    {
      P2PeerioGcm oLoop;
      oLoop.SetKey ( (const char *)aKey, (int)sizeof(aKey), 0, 0 );

      const char szLoop[] = "loopback";
      const UINT nLoop    = (UINT)sizeof(szLoop);
      const UINT nLoopSl  = oLoop.SealedSize ( nLoop );

      unsigned char *pLoopS = new unsigned char[nLoopSl];
      unsigned char *pLoopO = new unsigned char[nLoop];
      if ( !oLoop.Encrypt ( szLoop, (char *)pLoopS, (int)nLoop, 0, 0 ) )
        bOk = false;
      if ( bOk && !oLoop.Decrypt ( (const char *)pLoopS, (int)nLoopSl
                                 , (char *)pLoopO, 0, 0 ) )
        bOk = false;
      if ( bOk && memcmp ( pLoopO, szLoop, nLoop ) != 0 )
        bOk = false;
      delete [] pLoopS;
      delete [] pLoopO;
    }

    return bOk;
}
