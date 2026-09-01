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
//  P2PeerSeal implementation
//  NOTES: No stdafx.h - this TU compiles standalone in the Linux crypto_kat
//         target, and the sealed layout IS the wire, so a byte of drift
//         between the CNG and OpenSSL backends is a message that can be sent
//         on one operating system and never opened on the other
//

#include "P2PeerSeal.h"
#include "P2PCngCrypto.h"

#include <cstring>
#include <ctime>     // sealed_at, Stage 3 step 10
#include <string>

using p2pcng::kEcdhPubLen;
using p2pcng::kEcdhSecLen;
using p2pcng::kEcdsaPubLen;
using p2pcng::kAesKeyLen;

namespace p2pseal
{
namespace
{
    //  Distinct labels so no two hashes this module computes can ever be
    //  confused for one another, even given identical inputs.
    const char kLabelAad[] = "P2P-seal-aad-v1";
    const char kLabelSig[] = "P2P-seal-sig-v1";
    const char kLabelKdf[] = "P2P-seal-kdf-v1";
    //  v2. Distinct from the three above so that no hash computed for the
    //  envelope can ever collide with one computed for a v1 body, even given
    //  identical inputs - the same rule the first three were chosen under.
    const char kLabelRcp[] = "P2P-seal-rcp-v2";   // reader slot tag
    const char kLabelKek[] = "P2P-seal-kek-v2";   // per-reader key-wrapping key
    const char kLabelWrp[] = "P2P-seal-wrp-v2";   // AAD for one wrapped key

    //  Wipe that the optimiser may not elide. SecureZeroMemory is Windows-only
    //  and this TU builds on both, so the volatile write is done by hand.
    void Wipe ( void *pv, size_t cb )
    {
        volatile unsigned char *p = (volatile unsigned char *)pv;
        while ( cb-- ) *p++ = 0;
    }

    void PutU16 ( std::string &s, unsigned int n )
    {
        s.push_back ( (char)(unsigned char)( ( n >> 8 ) & 0xFF ) );
        s.push_back ( (char)(unsigned char)(   n        & 0xFF ) );
    }

    void AppendField ( std::string &s, const void *p, size_t n )
    {
        PutU16 ( s, (unsigned int)n );
        if ( n )
            s.append ( (const char *)p, n );
    }

    //  UTF-8, not wchar_t: wchar_t is 2 bytes under MSVC and 4 under GCC, so
    //  hashing the raw units would make a Windows peer and a Linux peer
    //  compute different transcripts for the same address.
    bool Utf8FromWide ( const wchar_t *pIn, std::string &sOut )
    {
        sOut.clear ( );
        if ( !pIn ) return false;
        for ( const wchar_t *p = pIn; *p; ++p )
        {
            unsigned int cp = (unsigned int)*p;
#if WCHAR_MAX > 0xFFFFu
            if ( cp >= 0xD800 && cp <= 0xDFFF ) return false;   // lone surrogate
#else
            if ( cp >= 0xD800 && cp <= 0xDBFF )
            {
                const unsigned int lo = (unsigned int)*( p + 1 );
                if ( lo < 0xDC00 || lo > 0xDFFF ) return false; // unpaired high
                cp = 0x10000 + ( ( cp - 0xD800 ) << 10 ) + ( lo - 0xDC00 );
                ++p;
            }
            else if ( cp >= 0xDC00 && cp <= 0xDFFF ) return false;   // stray low
#endif
            if ( cp < 0x80 )
                sOut.push_back ( (char)cp );
            else if ( cp < 0x800 )
            {
                sOut.push_back ( (char)( 0xC0 | ( cp >> 6 ) ) );
                sOut.push_back ( (char)( 0x80 | ( cp & 0x3F ) ) );
            }
            else if ( cp < 0x10000 )
            {
                sOut.push_back ( (char)( 0xE0 | ( cp >> 12 ) ) );
                sOut.push_back ( (char)( 0x80 | ( ( cp >> 6 ) & 0x3F ) ) );
                sOut.push_back ( (char)( 0x80 | ( cp & 0x3F ) ) );
            }
            else
            {
                sOut.push_back ( (char)( 0xF0 | ( cp >> 18 ) ) );
                sOut.push_back ( (char)( 0x80 | ( ( cp >> 12 ) & 0x3F ) ) );
                sOut.push_back ( (char)( 0x80 | ( ( cp >> 6 ) & 0x3F ) ) );
                sOut.push_back ( (char)( 0x80 | ( cp & 0x3F ) ) );
            }
        }
        return true;
    }

    //  sealed_at on the wire: 8 bytes, big-endian, seconds since the epoch.
    //  Big-endian and fixed width because this crosses between a 2-byte-wchar
    //  MSVC build and a 4-byte-wchar GCC one and must not depend on either's
    //  idea of a native integer - the same reason every address here becomes
    //  UTF-8 before it is hashed.
    void PutTime ( unsigned char *p, long long ll )
    {
        unsigned long long u = (unsigned long long)ll;
        for ( int i = 7; i >= 0; --i ) { p[i] = (unsigned char)( u & 0xFF ); u >>= 8; }
    }

    long long GetTime ( const unsigned char *p )
    {
        unsigned long long u = 0;
        for ( int i = 0; i < 8; ++i ) u = ( u << 8 ) | (unsigned long long)p[i];
        return (long long)u;
    }

    //  Every field length-prefixed, so no two different tuples can produce the
    //  same byte string. pBody is the sealed region for the signature
    //  transcript and absent for the AAD one.
    //
    //  The VERSION and the TIME are bound in ahead of everything else, in both
    //  transcripts. Binding them in the AAD means the GCM tag fails if either
    //  is edited; binding them in the signature means the sender's signature
    //  fails too. Neither the wire nor the recipient can move a body's clock
    //  forward to get past a freshness window, and nothing can be downgraded
    //  to an older format by rewriting one byte - which would otherwise be the
    //  first thing a version byte invites.
    bool Transcript ( const char *pszLabel,
                      const wchar_t *pSrc, const wchar_t *pDst,
                      unsigned char ucVer, long long llWhen,
                      const unsigned char *pEph,
                      const unsigned char *pBody, size_t cbBody,
                      std::string &sOut )
    {
        std::string sSrc, sDst;
        if ( !Utf8FromWide ( pSrc, sSrc ) ) return false;
        if ( !Utf8FromWide ( pDst, sDst ) ) return false;

        unsigned char aVer = ucVer;
        unsigned char aWhen[kSealTimeLen];
        PutTime ( aWhen, llWhen );

        sOut.clear ( );
        AppendField ( sOut, pszLabel, std::strlen ( pszLabel ) );
        AppendField ( sOut, &aVer, 1 );
        AppendField ( sOut, aWhen, kSealTimeLen );
        AppendField ( sOut, sSrc.data ( ), sSrc.size ( ) );
        AppendField ( sOut, sDst.data ( ), sDst.size ( ) );
        AppendField ( sOut, pEph, kSealEphLen );
        AppendField ( sOut, pBody, pBody ? cbBody : 0 );
        return true;
    }

    //  The v2 transcript. Same shape and same rules as the v1 one above, plus
    //  the RECIPIENT BLOCK - which is what stops a hub editing who may read.
    //
    //  pTags is the concatenated slot tags, nReaders * kSealRTagLen bytes. It
    //  is bound into the BODY's additional data, so removing a reader, adding
    //  one, or reordering them fails the body's GCM tag. pWraps is the
    //  concatenated wrapped keys and is bound only into the SIGNATURE - it
    //  cannot go in the body AAD because the wraps do not exist until the
    //  content key does, and the content key is what the body is sealed
    //  under. The tags DO exist beforehand, which is the whole reason the
    //  split is drawn there and not somewhere more obvious.
    bool TranscriptV2 ( const char *pszLabel,
                        const wchar_t *pSrc, const wchar_t *pDst,
                        unsigned char ucVer, long long llWhen,
                        const unsigned char *pEph,
                        size_t nReaders,
                        const unsigned char *pTags,
                        const unsigned char *pWraps,
                        const unsigned char *pBody, size_t cbBody,
                        std::string &sOut )
    {
        std::string sSrc, sDst;
        if ( !Utf8FromWide ( pSrc, sSrc ) ) return false;
        if ( !Utf8FromWide ( pDst, sDst ) ) return false;

        unsigned char aVer = ucVer;
        unsigned char aWhen[kSealTimeLen];
        unsigned char aCount = (unsigned char)nReaders;
        PutTime ( aWhen, llWhen );

        sOut.clear ( );
        AppendField ( sOut, pszLabel, std::strlen ( pszLabel ) );
        AppendField ( sOut, &aVer, 1 );
        AppendField ( sOut, aWhen, kSealTimeLen );
        AppendField ( sOut, sSrc.data ( ), sSrc.size ( ) );
        AppendField ( sOut, sDst.data ( ), sDst.size ( ) );
        AppendField ( sOut, pEph, kSealEphLen );
        //  The count is bound SEPARATELY as well as implied by the tag block's
        //  length. Belt and braces on purpose: the count is the one field a
        //  parser acts on before anything is authenticated, so it is the one
        //  most worth making unforgeable twice.
        AppendField ( sOut, &aCount, 1 );
        AppendField ( sOut, pTags,  nReaders * kSealRTagLen );
        if ( pWraps )
            AppendField ( sOut, pWraps, nReaders * kSealWrapLen );
        AppendField ( sOut, pBody, pBody ? cbBody : 0 );
        return true;
    }

    //  The per-reader key-wrapping key. Same construction as DeriveKey below
    //  and a different label, so the key that wraps the content key can never
    //  equal the key that would have sealed the body under v1.
    bool DeriveKek ( const unsigned char *pSecret,
                     const unsigned char *pEph,
                     unsigned char *pKeyOut )
    {
        return p2pcng::HkdfSha256 ( pSecret, kEcdhSecLen,
                                    pEph,    kSealEphLen,
                                    (const unsigned char *)kLabelKek,
                                    sizeof(kLabelKek) - 1,
                                    pKeyOut, kAesKeyLen );
    }

    //  Raw ECDH output is an X coordinate - structured, not uniform - so it is
    //  never used as a key directly. The ephemeral point is the salt: it is
    //  fresh per message and both ends have it before the key is needed.
    bool DeriveKey ( const unsigned char *pSecret,
                     const unsigned char *pEph,
                     unsigned char *pKeyOut )
    {
        return p2pcng::HkdfSha256 ( pSecret, kEcdhSecLen,
                                    pEph,    kSealEphLen,
                                    (const unsigned char *)kLabelKdf,
                                    sizeof(kLabelKdf) - 1,
                                    pKeyOut, kAesKeyLen );
    }
}   // anonymous namespace

const char *
SealResultText ( SealResult eResult )
{
    switch ( eResult )
    {
      case SealOk:             return "ok";
      case SealErrArgs:        return "bad arguments";
      case SealErrNoIdentity:  return "no sender identity key";
      case SealErrNoAgreement: return "no agreement key";
      case SealErrFormat:      return "not a sealed body";
      case SealErrSignature:   return "sender signature did not verify";
      case SealErrTag:         return "authentication tag did not verify";
      case SealErrRevoked:     return "key is revoked";
      case SealErrInternal:    return "internal error";
      case SealErrReplay:      return "sealed body already opened (replay)";
      case SealErrVersion:     return "sealed body version not understood";
      case SealErrStale:       return "sealed body is outside the freshness window";
    }
    return "unknown";
}

bool
LooksSealed ( const void *pv, size_t cb )
{
    // There is no magic to look for - a sealed body is indistinguishable from
    // random, which is the point. Length is the only cheap signal, and it is a
    // diagnostic hint and never a trust decision.
    return pv != 0 && cb > kSealOverhead;
}

// ---- Reader slot tag ---------------------------------------------------
bool
SealSlotTag ( const unsigned char *pEph,
              const unsigned char *pReaderPub,
              unsigned char *pTagOut )
{
    if ( !pEph || !pReaderPub || !pTagOut ) return false;

    std::string sIn;
    AppendField ( sIn, kLabelRcp, sizeof(kLabelRcp) - 1 );
    AppendField ( sIn, pEph,       kSealEphLen );
    AppendField ( sIn, pReaderPub, kEcdhPubLen );

    unsigned char aHash[p2pcng::kSha256Len];
    if ( !p2pcng::Sha256 ( (const unsigned char *)sIn.data ( ), sIn.size ( ),
                           aHash ) )
        return false;

    std::memcpy ( pTagOut, aHash, kSealRTagLen );
    return true;
}

size_t
SealReaderCount ( const void *pv, size_t cb )
{
    const unsigned char *p = (const unsigned char *)pv;
    if ( !p || cb < kSealVerLen + kSealTimeLen + kSealEphLen + kSealCountLen )
        return 0;
    if ( p[0] != kSealVersion ) return 0;      // v1 has no reader block

    const size_t n = (size_t)p[kSealVerLen + kSealTimeLen + kSealEphLen];
    if ( n == 0 || n > kSealMaxReaders )  return 0;
    if ( cb < SealOverhead ( n ) )        return 0;
    return n;
}

// ---- Seal --------------------------------------------------------------
SealResult
Seal ( p2pcng::EcdsaP256 &oSender,
       const unsigned char *pRecipAgree,
       const wchar_t *pSrc, const wchar_t *pDst,
       const void *pPlain, size_t cbPlain,
       unsigned char *pOut, size_t cbOut, size_t *pcbOut,
       long long llWhen )
{
    //  The one-reader case IS the many-reader case. Keeping it as a separate
    //  path would mean two implementations of the thing this module exists to
    //  get right, differing only in a loop bound.
    return SealTo ( oSender, pRecipAgree, 1, pSrc, pDst,
                    pPlain, cbPlain, pOut, cbOut, pcbOut, llWhen );
}

SealResult
SealTo ( p2pcng::EcdsaP256 &oSender,
         const unsigned char *pReaders, size_t nReaders,
         const wchar_t *pSrc, const wchar_t *pDst,
         const void *pPlain, size_t cbPlain,
         unsigned char *pOut, size_t cbOut, size_t *pcbOut,
         long long llWhen )
{
    if ( pcbOut ) *pcbOut = 0;
    if ( !pReaders || !pSrc || !pDst || !pOut )      return SealErrArgs;
    if ( cbPlain && !pPlain )                        return SealErrArgs;
    if ( nReaders == 0 || nReaders > kSealMaxReaders ) return SealErrReaders;
    if ( cbOut < SealedSize ( cbPlain, nReaders ) )  return SealErrArgs;

    //  Duplicates refused, not collapsed - see SealTo in the header. O(n^2)
    //  over at most 8 entries, which is cheaper than the memory to do it any
    //  other way.
    for ( size_t a = 0; a < nReaders; ++a )
      for ( size_t b = a + 1; b < nReaders; ++b )
        if ( std::memcmp ( pReaders + a * kEcdhPubLen,
                           pReaders + b * kEcdhPubLen, kEcdhPubLen ) == 0 )
          return SealErrReaders;

    if ( llWhen == 0 ) llWhen = (long long)std::time ( 0 );

    //  Layout: ver(1) | when(8) | eph(64) | n(1) | slots(68n) | body | sig(64)
    unsigned char *const pHdr   = pOut;
    unsigned char *const pEphW  = pOut + kSealVerLen + kSealTimeLen;
    unsigned char *const pCntW  = pEphW + kSealEphLen;
    unsigned char *const pSlotW = pCntW + kSealCountLen;
    unsigned char *const pBodyW = pSlotW + kSealSlotLen * nReaders;

    p2pcng::EcdhP256 oEph;
    unsigned char aEph[kSealEphLen];
    if ( !oEph.Generate ( ) || !oEph.ExportPublic ( aEph ) )
        return SealErrInternal;

    //  ---- the reader slots ------------------------------------------------
    //  Tags first and all of them, because the body's AAD binds the tag block
    //  and the body has to be sealed before the wraps can be made.
    unsigned char aTags[kSealMaxReaders * kSealRTagLen];
    for ( size_t r = 0; r < nReaders; ++r )
        if ( !SealSlotTag ( aEph, pReaders + r * kEcdhPubLen,
                            aTags + r * kSealRTagLen ) )
            return SealErrInternal;

    //  ---- the content key -------------------------------------------------
    //  Random, not derived. A content key derived from any one reader's
    //  agreement would make that reader special - able to recompute the key
    //  for messages it was not a reader of - and the whole point is that the
    //  readers are peers of one another.
    unsigned char aCek[kSealCekLen];
    if ( !p2pcng::CngRandom ( aCek, (unsigned long)sizeof(aCek) ) )
        return SealErrInternal;

    std::string sAad;
    if ( !TranscriptV2 ( kLabelAad, pSrc, pDst, kSealVersion, llWhen,
                         aEph, nReaders, aTags, 0, 0, 0, sAad ) )
    {
        Wipe ( aCek, sizeof(aCek) );
        return SealErrInternal;
    }

    p2pcng::AesGcm oGcm;
    size_t cbSealed = 0;
    const bool bSealed =
        oGcm.SetKey ( aCek, sizeof(aCek) ) &&
        oGcm.Seal ( (const unsigned char *)pPlain, cbPlain,
                    (const unsigned char *)sAad.data ( ), sAad.size ( ),
                    pBodyW,
                    p2pcng::AesGcm::SealedSize ( cbPlain ), &cbSealed );
    if ( !bSealed || cbSealed != p2pcng::AesGcm::SealedSize ( cbPlain ) )
    {
        Wipe ( aCek, sizeof(aCek) );
        return SealErrInternal;
    }

    //  ---- wrap the content key once per reader ---------------------------
    for ( size_t r = 0; r < nReaders; ++r )
    {
        const unsigned char *pRdr = pReaders + r * kEcdhPubLen;
        unsigned char *pTagW  = pSlotW + r * kSealSlotLen;
        unsigned char *pWrapW = pTagW  + kSealRTagLen;

        std::memcpy ( pTagW, aTags + r * kSealRTagLen, kSealRTagLen );

        unsigned char aSecret[kEcdhSecLen];
        if ( !oEph.DeriveRawSecret ( pRdr, aSecret ) )
        {
            Wipe ( aCek, sizeof(aCek) );
            return SealErrNoAgreement;      // not a point on P-256
        }

        unsigned char aKek[kAesKeyLen];
        const bool bKek = DeriveKek ( aSecret, aEph, aKek );
        Wipe ( aSecret, sizeof(aSecret) );
        if ( !bKek ) { Wipe ( aCek, sizeof(aCek) ); return SealErrInternal; }

        //  This slot's own tag is in its wrap AAD, so a slot cannot be moved
        //  to another position or another message even by someone who can
        //  make the ECDH work.
        std::string sWrapAad;
        if ( !TranscriptV2 ( kLabelWrp, pSrc, pDst, kSealVersion, llWhen,
                             aEph, nReaders, aTags, 0,
                             pTagW, kSealRTagLen, sWrapAad ) )
        {
            Wipe ( aKek, sizeof(aKek) ); Wipe ( aCek, sizeof(aCek) );
            return SealErrInternal;
        }

        p2pcng::AesGcm oWrap;
        size_t cbWrap = 0;
        const bool bWrapped =
            oWrap.SetKey ( aKek, sizeof(aKek) ) &&
            oWrap.Seal ( aCek, sizeof(aCek),
                         (const unsigned char *)sWrapAad.data ( ),
                         sWrapAad.size ( ),
                         pWrapW, kSealWrapLen, &cbWrap );
        Wipe ( aKek, sizeof(aKek) );
        if ( !bWrapped || cbWrap != kSealWrapLen )
        {
            Wipe ( aCek, sizeof(aCek) );
            return SealErrInternal;
        }
    }
    Wipe ( aCek, sizeof(aCek) );

    pHdr[0] = kSealVersion;
    PutTime ( pHdr + kSealVerLen, llWhen );
    std::memcpy ( pEphW, aEph, kSealEphLen );
    pCntW[0] = (unsigned char)nReaders;

    //  Encrypt THEN sign, as v1 did - and the signature covers the wraps as
    //  well as the body, which is what makes the recipient block unforgeable
    //  rather than merely tamper-evident to whoever can already open it.
    std::string sSig;
    if ( !TranscriptV2 ( kLabelSig, pSrc, pDst, kSealVersion, llWhen,
                         aEph, nReaders, aTags, 0,
                         pBodyW, cbSealed, sSig ) )
        return SealErrInternal;

    //  The wraps are NOT contiguous - each is interleaved with its own tag -
    //  so they cannot be passed as the transcript's pWraps field, which
    //  expects one run of kSealWrapLen*n. The whole slot region goes in as a
    //  single field instead, which binds the tags and the wraps together in
    //  the order they appear on the wire. Open rebuilds this identically.
    AppendField ( sSig, pSlotW, kSealSlotLen * nReaders );

    if ( !oSender.Sign ( (const unsigned char *)sSig.data ( ), sSig.size ( ),
                         pBodyW + cbSealed ) )
        return SealErrNoIdentity;

    if ( pcbOut ) *pcbOut = SealedSize ( cbPlain, nReaders );
    return SealOk;
}

// ---- Open, version 1 ---------------------------------------------------
//  KEPT WHOLE AND UNCHANGED apart from its name. A v1 body is still opened,
//  which is what makes v2 a soft break - and the way to be sure of that is
//  for this to be the same code that opened one yesterday, not a
//  reimplementation of it that agrees with the old one in the cases somebody
//  thought to test.
namespace {
SealResult
OpenV1 ( p2pcng::EcdhP256 &oRecipAgree,
       const unsigned char *pSenderId,
       const wchar_t *pSrc, const wchar_t *pDst,
       const unsigned char *pIn, size_t cbIn,
       void *pOut, size_t cbOut, size_t *pcbOut,
       long long *pllWhenOut )
{
    if ( pcbOut )    *pcbOut    = 0;
    if ( pllWhenOut ) *pllWhenOut = 0;
    if ( !pSenderId || !pSrc || !pDst || !pIn )  return SealErrArgs;
    if ( cbIn < kSealOverheadV1 )                return SealErrFormat;

    //  The version FIRST, before anything is parsed on the strength of it.
    //  That is the whole reason for the byte, and it is also what a
    //  pre-2026-08-18 body hits: those began at the ephemeral point, whose
    //  first byte is uniformly distributed, so a v0 body lands here 255 times
    //  in 256 and on the signature check the other time. It never opens.
    //  The caller dispatched on the version already; this is belt and braces
    //  at the boundary of the function that trusts it.
    if ( pIn[0] != kSealVersion1 )               return SealErrVersion;

    const long long llWhen = GetTime ( pIn + kSealVerLen );

    const size_t cbHdr    = kSealVerLen + kSealTimeLen;
    //  NOT OpenedSize(), which since v2 is an upper bound sized for the v2
    //  overhead. A v1 body's plaintext is exactly what v1's own overhead
    //  leaves, and using the bound here would under-report every v1 body by
    //  the size of the recipient block it does not have.
    const size_t cbPlain  = cbIn - kSealOverheadV1;
    const size_t cbSealed = cbIn - cbHdr - kSealEphLen - kSealSigLen;
    if ( cbOut < cbPlain )                       return SealErrArgs;

    const unsigned char *pEph  = pIn + cbHdr;
    const unsigned char *pBody = pEph + kSealEphLen;
    const unsigned char *pSig  = pBody + cbSealed;

    //  Signature first. Everything below this line does asymmetric work with
    //  OUR private key on bytes the sender chose, so authorship is settled
    //  before any of it runs.
    std::string sSig;
    if ( !Transcript ( kLabelSig, pSrc, pDst, pIn[0], llWhen,
                       pEph, pBody, cbSealed, sSig ) )
        return SealErrInternal;
    {
        p2pcng::EcdsaP256 oPeer;
        if ( !oPeer.ImportPublic ( pSenderId ) ) return SealErrInternal;
        if ( !oPeer.Verify ( (const unsigned char *)sSig.data ( ), sSig.size ( ),
                             pSig ) )
            return SealErrSignature;
    }

    unsigned char aSecret[kEcdhSecLen];
    if ( !oRecipAgree.DeriveRawSecret ( pEph, aSecret ) )
        return SealErrNoAgreement;     // no private half loaded, or bad point

    unsigned char aKey[kAesKeyLen];
    const bool bKey = DeriveKey ( aSecret, pEph, aKey );
    Wipe ( aSecret, sizeof(aSecret) );
    if ( !bKey ) return SealErrInternal;

    std::string sAad;
    if ( !Transcript ( kLabelAad, pSrc, pDst, pIn[0], llWhen,
                       pEph, 0, 0, sAad ) )
    {
        Wipe ( aKey, sizeof(aKey) );
        return SealErrInternal;
    }

    p2pcng::AesGcm oGcm;
    size_t cbGot = 0;
    const bool bOpened =
        oGcm.SetKey ( aKey, sizeof(aKey) ) &&
        oGcm.Open ( pBody, cbSealed,
                    (const unsigned char *)sAad.data ( ), sAad.size ( ),
                    (unsigned char *)pOut, cbOut, &cbGot );
    Wipe ( aKey, sizeof(aKey) );

    //  A tag failure here, with the signature already good, means the
    //  addresses do not match the ones sealed against - the body was moved to
    //  another message.
    if ( !bOpened || cbGot != cbPlain ) return SealErrTag;

    //  Reported only now, so it is a VERIFIED fact rather than a claim: the
    //  stamp is in the signed transcript and in the GCM additional data, so
    //  reaching this line means neither the sender nor anyone on the wire can
    //  have moved it.
    if ( pllWhenOut ) *pllWhenOut = llWhen;
    if ( pcbOut )     *pcbOut     = cbPlain;
    return SealOk;
}

}   // anonymous namespace

// ---- Open, version 2 ---------------------------------------------------
namespace {
SealResult
OpenV2 ( p2pcng::EcdhP256 &oRecipAgree,
         const unsigned char *pSenderId,
         const wchar_t *pSrc, const wchar_t *pDst,
         const unsigned char *pIn, size_t cbIn,
         void *pOut, size_t cbOut, size_t *pcbOut,
         long long *pllWhenOut )
{
    //  The reader count is the first thing read and the first thing bounded.
    //  Everything below indexes on it, so a block claiming nine readers is
    //  refused before a single offset is computed from the claim.
    const size_t nReaders = SealReaderCount ( pIn, cbIn );
    if ( nReaders == 0 ) return SealErrFormat;

    const long long llWhen = GetTime ( pIn + kSealVerLen );

    const unsigned char *pEph   = pIn + kSealVerLen + kSealTimeLen;
    const unsigned char *pSlots = pEph + kSealEphLen + kSealCountLen;
    const unsigned char *pBody  = pSlots + kSealSlotLen * nReaders;

    const size_t cbPlain  = cbIn - SealOverhead ( nReaders );
    const size_t cbSealed = p2pcng::AesGcm::SealedSize ( cbPlain );
    const unsigned char *pSig = pBody + cbSealed;
    if ( cbOut < cbPlain ) return SealErrArgs;

    //  Gather the tags into one run, because that is the shape both
    //  transcripts bind them in and they are interleaved with the wraps on
    //  the wire.
    unsigned char aTags[kSealMaxReaders * kSealRTagLen];
    for ( size_t r = 0; r < nReaders; ++r )
        std::memcpy ( aTags + r * kSealRTagLen,
                      pSlots + r * kSealSlotLen, kSealRTagLen );

    //  Signature FIRST, exactly as v1 does and for the same reason:
    //  everything past this line does asymmetric work with our private key on
    //  bytes the sender chose. It covers the whole slot region, so who may
    //  read is settled by the sender and cannot be edited on the path.
    std::string sSig;
    if ( !TranscriptV2 ( kLabelSig, pSrc, pDst, pIn[0], llWhen,
                         pEph, nReaders, aTags, 0, pBody, cbSealed, sSig ) )
        return SealErrInternal;
    AppendField ( sSig, pSlots, kSealSlotLen * nReaders );
    {
        p2pcng::EcdsaP256 oPeer;
        if ( !oPeer.ImportPublic ( pSenderId ) ) return SealErrInternal;
        if ( !oPeer.Verify ( (const unsigned char *)sSig.data ( ), sSig.size ( ),
                             pSig ) )
            return SealErrSignature;
    }

    //  Which slot is ours. A hash and a compare - no ECDH, no trial
    //  decryption, and nothing in the block names us.
    unsigned char aOurPub[kEcdhPubLen];
    if ( !oRecipAgree.ExportPublic ( aOurPub ) ) return SealErrNoAgreement;

    unsigned char aWant[kSealRTagLen];
    if ( !SealSlotTag ( pEph, aOurPub, aWant ) ) return SealErrInternal;

    size_t iSlot = nReaders;
    for ( size_t r = 0; r < nReaders; ++r )
        if ( p2pcng::ConstTimeEqual ( aTags + r * kSealRTagLen, aWant,
                                      kSealRTagLen ) )
        { iSlot = r; break; }

    //  Named no slot. The body is intact and somebody can open it - just not
    //  us. A relay carrying a body it was not made a reader of lands here and
    //  must pass it on, so this must never be reported as damage.
    if ( iSlot == nReaders ) return SealErrNotAReader;

    const unsigned char *pWrap = pSlots + iSlot * kSealSlotLen + kSealRTagLen;

    unsigned char aSecret[kEcdhSecLen];
    if ( !oRecipAgree.DeriveRawSecret ( pEph, aSecret ) )
        return SealErrNoAgreement;

    unsigned char aKek[kAesKeyLen];
    const bool bKek = DeriveKek ( aSecret, pEph, aKek );
    Wipe ( aSecret, sizeof(aSecret) );
    if ( !bKek ) return SealErrInternal;

    std::string sWrapAad;
    if ( !TranscriptV2 ( kLabelWrp, pSrc, pDst, pIn[0], llWhen,
                         pEph, nReaders, aTags, 0,
                         aTags + iSlot * kSealRTagLen, kSealRTagLen,
                         sWrapAad ) )
    { Wipe ( aKek, sizeof(aKek) ); return SealErrInternal; }

    unsigned char aCek[kSealCekLen];
    size_t cbCek = 0;
    p2pcng::AesGcm oWrap;
    const bool bUnwrapped =
        oWrap.SetKey ( aKek, sizeof(aKek) ) &&
        oWrap.Open ( pWrap, kSealWrapLen,
                     (const unsigned char *)sWrapAad.data ( ), sWrapAad.size ( ),
                     aCek, sizeof(aCek), &cbCek );
    Wipe ( aKek, sizeof(aKek) );
    if ( !bUnwrapped || cbCek != kSealCekLen )
    {
        Wipe ( aCek, sizeof(aCek) );
        //  Our tag matched but the wrap did not open. With the signature
        //  already good that is an 8-byte tag collision between two readers
        //  of this message - 2^-64 - and not tampering, which the signature
        //  would have caught. Reported as a tag failure because that is what
        //  it is at this layer.
        return SealErrTag;
    }

    std::string sAad;
    if ( !TranscriptV2 ( kLabelAad, pSrc, pDst, pIn[0], llWhen,
                         pEph, nReaders, aTags, 0, 0, 0, sAad ) )
    { Wipe ( aCek, sizeof(aCek) ); return SealErrInternal; }

    p2pcng::AesGcm oGcm;
    size_t cbGot = 0;
    const bool bOpened =
        oGcm.SetKey ( aCek, sizeof(aCek) ) &&
        oGcm.Open ( pBody, cbSealed,
                    (const unsigned char *)sAad.data ( ), sAad.size ( ),
                    (unsigned char *)pOut, cbOut, &cbGot );
    Wipe ( aCek, sizeof(aCek) );

    if ( !bOpened || cbGot != cbPlain ) return SealErrTag;

    if ( pllWhenOut ) *pllWhenOut = llWhen;
    if ( pcbOut )     *pcbOut     = cbPlain;
    return SealOk;
}
}   // anonymous namespace

// ---- Open --------------------------------------------------------------
//  DISPATCH ON THE VERSION AND NOTHING ELSE, before any offset is computed.
//  That byte was added at v1 for precisely this moment, and the note in the
//  header that called v0 -> v1 a hard break said so: a format whose first
//  byte says what it is can grow a second generation without a flag day, and
//  one whose first byte is a coordinate cannot.
SealResult
Open ( p2pcng::EcdhP256 &oRecipAgree,
       const unsigned char *pSenderId,
       const wchar_t *pSrc, const wchar_t *pDst,
       const unsigned char *pIn, size_t cbIn,
       void *pOut, size_t cbOut, size_t *pcbOut,
       long long *pllWhenOut )
{
    if ( pcbOut )     *pcbOut     = 0;
    if ( pllWhenOut ) *pllWhenOut = 0;
    if ( !pSenderId || !pSrc || !pDst || !pIn ) return SealErrArgs;
    if ( cbIn < kSealVerLen )                   return SealErrFormat;

    switch ( pIn[0] )
    {
      case kSealVersion:
        return OpenV2 ( oRecipAgree, pSenderId, pSrc, pDst, pIn, cbIn,
                        pOut, cbOut, pcbOut, pllWhenOut );
      case kSealVersion1:
        return OpenV1 ( oRecipAgree, pSenderId, pSrc, pDst, pIn, cbIn,
                        pOut, cbOut, pcbOut, pllWhenOut );
    }
    //  Includes every v0 body, which began with a uniformly distributed
    //  coordinate and so lands here 254 times in 256.
    return SealErrVersion;
}

// ---- Self-test ---------------------------------------------------------
//  NOTES: The refusals are what matter. A sealer that cannot tell the right
//         recipient from the wrong one is not confidentiality, it is
//         obfuscation
bool
SealSelfTest ( )
{
    const wchar_t *pA = L"VNet1:Root";
    const wchar_t *pC = L"VNet1:Root.B.C";

    p2pcng::EcdsaP256 oIdA, oIdX;          // senders: genuine, and an impostor
    p2pcng::EcdhP256  oAgrC, oAgrOther;    // recipients: intended, and another
    if ( !oIdA.Generate ( )  || !oIdX.Generate ( )  ) return false;
    if ( !oAgrC.Generate ( ) || !oAgrOther.Generate ( ) ) return false;

    unsigned char aPubA[kEcdsaPubLen], aPubX[kEcdsaPubLen];
    unsigned char aAgrC[kSealEphLen],  aAgrOther[kSealEphLen];
    if ( !oIdA.ExportPublic  ( aPubA ) || !oIdX.ExportPublic  ( aPubX ) )
        return false;
    if ( !oAgrC.ExportPublic ( aAgrC ) || !oAgrOther.ExportPublic ( aAgrOther ) )
        return false;

    // 1. Static agreement keys survive a round trip through their blob, and
    //    a restored key agrees to the same secret. Without this the allow-list
    //    entry and the stored private half could drift apart unnoticed.
    {
        unsigned char aBlob[p2pcng::kEcdhPrivLen];
        if ( !oAgrC.ExportPrivate ( aBlob ) ) return false;

        p2pcng::EcdhP256 oRestored;
        if ( !oRestored.ImportPrivate ( aBlob ) ) return false;

        unsigned char aPubBack[kSealEphLen];
        if ( !oRestored.ExportPublic ( aPubBack ) ) return false;
        if ( std::memcmp ( aPubBack, aAgrC, kSealEphLen ) != 0 ) return false;

        p2pcng::EcdhP256 oProbe;
        unsigned char aProbePub[kSealEphLen];
        unsigned char s1[kEcdhSecLen], s2[kEcdhSecLen];
        if ( !oProbe.Generate ( ) || !oProbe.ExportPublic ( aProbePub ) )
            return false;
        if ( !oProbe.DeriveRawSecret ( aAgrC, s1 ) )      return false;
        if ( !oRestored.DeriveRawSecret ( aProbePub, s2 ) ) return false;
        if ( std::memcmp ( s1, s2, kEcdhSecLen ) != 0 )   return false;

        // A garbage blob must be refused, not silently accepted.
        unsigned char aBad[p2pcng::kEcdhPrivLen];
        std::memcpy ( aBad, aBlob, sizeof(aBad) );
        aBad[0] ^= 0xFF;                    // X no longer matches d
        p2pcng::EcdhP256 oBad;
        if ( oBad.ImportPrivate ( aBad ) )  return false;

        Wipe ( aBlob, sizeof(aBlob) );
    }

    const char szSecret[] = "top-secret-payload";
    const size_t cbPlain  = sizeof(szSecret);      // includes the terminator
    const size_t cbSealed = SealedSize ( cbPlain );

    unsigned char *pSealed = new unsigned char[cbSealed];
    unsigned char *pOpened = new unsigned char[cbPlain];
    bool bOk = true;
    size_t cbGot = 0;

    // 2. Size arithmetic
    if ( SealedSize ( 0 ) != kSealOverhead )        bOk = false;
    //  OpenedSize is an UPPER BOUND across versions now, not an exact inverse
    //  of SealedSize - it subtracts the v1 overhead so a stored v1 body still
    //  fits the buffer a caller sizes with it. So the assertions are that it
    //  never UNDER-states, and that it still floors to zero on a runt.
    if ( OpenedSize ( kSealOverheadV1 )     != 0 )  bOk = false;
    if ( OpenedSize ( kSealOverheadV1 - 1 ) != 0 )  bOk = false;
    if ( OpenedSize ( cbSealed ) < cbPlain )        bOk = false;

    // 3. Round trip
    if ( bOk && Seal ( oIdA, aAgrC, pA, pC, szSecret, cbPlain,
                       pSealed, cbSealed, &cbGot ) != SealOk )
        bOk = false;
    if ( bOk && cbGot != cbSealed ) bOk = false;

    // 4. The plaintext must not appear anywhere in the sealed body. This is
    //    the assertion the intermediate hub relies on.
    if ( bOk )
    {
        bool bFound = false;
        for ( size_t i = 0; i + cbPlain <= cbSealed; ++i )
            if ( std::memcmp ( pSealed + i, szSecret, cbPlain ) == 0 )
                { bFound = true; break; }
        if ( bFound ) bOk = false;
    }

    if ( bOk && Open ( oAgrC, aPubA, pA, pC, pSealed, cbSealed,
                       pOpened, cbPlain, &cbGot ) != SealOk )
        bOk = false;
    if ( bOk && ( cbGot != cbPlain ||
                  std::memcmp ( pOpened, szSecret, cbPlain ) != 0 ) )
        bOk = false;

    // 5. Sealing twice never produces the same bytes - the ephemeral pair is
    //    per message, so an observer cannot even tell two sends are identical.
    if ( bOk )
    {
        unsigned char *pAgain = new unsigned char[cbSealed];
        if ( Seal ( oIdA, aAgrC, pA, pC, szSecret, cbPlain,
                    pAgain, cbSealed, 0 ) != SealOk )
            bOk = false;
        if ( bOk && std::memcmp ( pAgain, pSealed, cbSealed ) == 0 )
            bOk = false;
        delete [] pAgain;
    }

    // 6. The wrong recipient cannot open it, even holding a valid key.
    //    UNDER v2 THE ANSWER IS SHARPER THAN IT WAS. This asserted SealErrTag
    //    while there was one recipient and no way to ask who a body was for:
    //    the wrong key derived the wrong secret and the GCM tag failed. v2
    //    looks for a slot tag first and finds none, so it can say NOT-A-READER
    //    - and the difference is load-bearing rather than cosmetic, because a
    //    relay carrying a body it was not named a reader of has to tell that
    //    apart from a damaged one to know whether to forward it.
    if ( bOk && Open ( oAgrOther, aPubA, pA, pC, pSealed, cbSealed,
                       pOpened, cbPlain, 0 ) != SealErrNotAReader )
        bOk = false;

    // 7. A different sender's identity does not verify it.
    if ( bOk && Open ( oAgrC, aPubX, pA, pC, pSealed, cbSealed,
                       pOpened, cbPlain, 0 ) != SealErrSignature )
        bOk = false;

    // 8. Moved to another address pair - the body is refused at the signature,
    //    because the addresses are inside the signed transcript as well as the
    //    AAD. Belt and braces on purpose: either alone would do.
    if ( bOk && Open ( oAgrC, aPubA, pC, pA, pSealed, cbSealed,
                       pOpened, cbPlain, 0 ) != SealErrSignature )
        bOk = false;
    if ( bOk && Open ( oAgrC, aPubA, pA, L"VNet1:Root.B.OTHER",
                       pSealed, cbSealed, pOpened, cbPlain, 0 ) != SealErrSignature )
        bOk = false;

    // 9. One flipped bit in each region, each restored afterwards.
    if ( bOk )
    {
        //  v2 OFFSETS. These were written against the v1 layout, where the
        //  block began at the ephemeral point - so every one of them named
        //  the wrong region once the version, the time and the recipient
        //  block went in front. They still FAILED to open, which is why the
        //  test stayed green through the change and why the labels are worth
        //  correcting rather than trusting: a probe that says "nonce" and
        //  lands on a slot tag is not testing what it claims.
        const size_t kOffEph  = kSealVerLen + kSealTimeLen;
        const size_t kOffSlot = kOffEph + kSealEphLen + kSealCountLen;
        const size_t kOffBody = kOffSlot + kSealSlotLen;     // n == 1 here
        const size_t anProbe[] = { 0,                        // version byte
                                   kOffEph,                  // ephemeral point
                                   kOffSlot,                 // reader slot tag
                                   kOffSlot + kSealRTagLen,  // wrapped key
                                   kOffBody,                 // nonce
                                   kOffBody + kSealNonceLen, // ciphertext
                                   cbSealed - kSealSigLen - 1,    // tag
                                   cbSealed - 1 };           // signature
        for ( size_t i = 0; bOk && i < sizeof(anProbe)/sizeof(anProbe[0]); ++i )
        {
            pSealed[anProbe[i]] ^= 0x01;
            if ( Open ( oAgrC, aPubA, pA, pC, pSealed, cbSealed,
                        pOpened, cbPlain, 0 ) == SealOk )
                bOk = false;                // accepted a forgery
            pSealed[anProbe[i]] ^= 0x01;
        }
    }

    // 10. Truncation, and a body too short to be sealed at all.
    if ( bOk && Open ( oAgrC, aPubA, pA, pC, pSealed, kSealOverhead - 1,
                       pOpened, cbPlain, 0 ) != SealErrFormat )
        bOk = false;

    // 11. A verify-only identity cannot seal.
    if ( bOk )
    {
        p2pcng::EcdsaP256 oPubOnly;
        if ( !oPubOnly.ImportPublic ( aPubA ) ) bOk = false;
        if ( bOk && Seal ( oPubOnly, aAgrC, pA, pC, szSecret, cbPlain,
                           pSealed, cbSealed, 0 ) != SealErrNoIdentity )
            bOk = false;
    }

    delete [] pSealed;
    delete [] pOpened;
    return bOk;
}

} // namespace p2pseal
