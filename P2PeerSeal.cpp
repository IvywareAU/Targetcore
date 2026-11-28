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
#include <vector>    // v3 context caches

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
    //  v3 (T1d). New labels only where a v3 value could otherwise equal a v2
    //  one: the slot tag and the wrapping key are derived from inputs a v2
    //  body also has, so they get their own. The AAD, wrap and signature
    //  transcripts keep their labels - they bind the version byte and, in
    //  v3, a seq field v2 does not have, so the two can never coincide.
    const char kLabelRcp3[] = "P2P-seal-rcp-v3";  // reader slot tag, with seq
    const char kLabelKek3[] = "P2P-seal-kek-v3";  // per-context wrapping key

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
                        std::string &sOut,
                        const unsigned char *pSeq = 0 )
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
        //  v3 only: the sequence number, straight after the point it numbers
        //  messages under. ABSENT, not empty, for v2 - an empty field would
        //  still add its two length bytes and change every v2 transcript, and
        //  v2 bodies on disk and in seal_interop's vectors must keep opening.
        if ( pSeq )
            AppendField ( sOut, pSeq, kSealSeqLen );
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

    //  v3: the per-context wrapping key. DeriveKek's construction with its own
    //  label, salted by the context point - which both ends hold before the
    //  key is needed, exactly as the ephemeral point is under v2.
    bool DeriveKek3 ( const unsigned char *pSecret,
                      const unsigned char *pCtx,
                      unsigned char *pKeyOut )
    {
        return p2pcng::HkdfSha256 ( pSecret, kEcdhSecLen,
                                    pCtx,    kSealEphLen,
                                    (const unsigned char *)kLabelKek3,
                                    sizeof(kLabelKek3) - 1,
                                    pKeyOut, kAesKeyLen );
    }

    //  v3 slot tag. SealSlotTag's construction plus the seq, so a reader's
    //  tag still changes from one message to the next although the context
    //  point does not. Without the seq every message in a context would carry
    //  the same tag per reader - linkable by anyone, not just by anyone who
    //  already knows the reader's public point.
    bool SlotTagV3 ( const unsigned char *pCtx, const unsigned char *pSeq,
                     const unsigned char *pReaderPub, unsigned char *pTagOut )
    {
        std::string sIn;
        AppendField ( sIn, kLabelRcp3, sizeof(kLabelRcp3) - 1 );
        AppendField ( sIn, pCtx,       kSealEphLen );
        AppendField ( sIn, pSeq,       kSealSeqLen );
        AppendField ( sIn, pReaderPub, kEcdhPubLen );

        unsigned char aHash[p2pcng::kSha256Len];
        if ( !p2pcng::Sha256 ( (const unsigned char *)sIn.data ( ), sIn.size ( ),
                               aHash ) )
            return false;
        std::memcpy ( pTagOut, aHash, kSealRTagLen );
        return true;
    }
}   // anonymous namespace

// ---- v3 state ----------------------------------------------------------
//  Both structs hold key material, so both wipe it on every path that drops
//  it: Reset, eviction, rotation and destruction.
struct SealContext::Impl
{
    struct Reader
    {
        unsigned char aPub[kEcdhPubLen];
        unsigned char aKek[kAesKeyLen];
    };

    //  A bound on the per-context reader cache, not on readers per message
    //  (that is kSealMaxReaders). A sender that seals to more distinct
    //  destinations than this within one context re-derives for the oldest;
    //  correctness is unaffected, only the saving.
    static const size_t kMaxReaders = 64;

    p2pcng::EcdhP256   *pEph      = nullptr;
    unsigned char       aCtx[kSealEphLen];
    unsigned long long  ullNext   = 0;          // seq of the next message
    long long           llBorn    = 0;
    unsigned            nMaxMsgs  = kSealCtxMaxMsgsDefault;
    unsigned            nMaxSecs  = kSealCtxMaxSecsDefault;
    unsigned long long  ullGen    = 0;
    std::vector<Reader> vReaders;

    void Drop ( )
    {
        for ( size_t i = 0; i < vReaders.size ( ); ++i )
            Wipe ( vReaders[i].aKek, sizeof(vReaders[i].aKek) );
        vReaders.clear ( );
        delete pEph;                 // EcdhP256's destructor frees the key
        pEph    = nullptr;
        ullNext = 0;
        llBorn  = 0;
        Wipe ( aCtx, sizeof(aCtx) );
    }

    //  Rotation, decided by the message's own stamp so a test can drive it.
    //  A clock that went BACKWARDS past the context's birth also rotates: the
    //  age check would otherwise read a negative age as "young" for as long as
    //  the clock stayed behind.
    bool Due ( long long llWhen ) const
    {
        return !pEph
            || ullNext >= nMaxMsgs
            || llWhen < llBorn
            || llWhen - llBorn >= (long long)nMaxSecs;
    }

    bool Start ( long long llWhen )
    {
        Drop ( );
        pEph = new p2pcng::EcdhP256;
        if ( !pEph->Generate ( ) || !pEph->ExportPublic ( aCtx ) )
        {
            Drop ( );
            return false;
        }
        llBorn = llWhen;
        ++ullGen;
        return true;
    }
};

SealContext::SealContext ( ) : m_p ( new Impl ) { }
SealContext::~SealContext ( ) { m_p->Drop ( ); delete m_p; }

void SealContext::SetBounds ( unsigned nMaxMsgs, unsigned nMaxSecs )
{
    if ( nMaxMsgs < 1 ) nMaxMsgs = 1;
    if ( nMaxMsgs > kSealCtxMaxMsgsCap ) nMaxMsgs = kSealCtxMaxMsgsCap;
    if ( nMaxSecs < 1 ) nMaxSecs = 1;
    if ( nMaxSecs > kSealCtxMaxSecsCap ) nMaxSecs = kSealCtxMaxSecsCap;
    m_p->nMaxMsgs = nMaxMsgs;
    m_p->nMaxSecs = nMaxSecs;
}
unsigned SealContext::MaxMsgs ( ) const { return m_p->nMaxMsgs; }
unsigned SealContext::MaxSecs ( ) const { return m_p->nMaxSecs; }
void     SealContext::Reset   ( )       { m_p->Drop ( ); }
unsigned long long SealContext::Generations ( ) const { return m_p->ullGen; }
size_t   SealContext::CachedReaders ( ) const { return m_p->vReaders.size ( ); }

struct OpenContextCache::Impl
{
    struct Entry
    {
        unsigned char      aCtx[kSealEphLen];
        unsigned char      aKek[kAesKeyLen];
        unsigned long long ullTop;      // highest seq opened in this context
        unsigned long long ullMask;     // bit i: seq ullTop - i was opened
        unsigned long long ullUsed;     // LRU tick
    };

    std::vector<Entry> v;
    unsigned long long ullTick = 0, ullHits = 0, ullMisses = 0;
    bool               bWindow = true;

    void Drop ( )
    {
        for ( size_t i = 0; i < v.size ( ); ++i )
            Wipe ( v[i].aKek, sizeof(v[i].aKek) );
        v.clear ( );
    }

    Entry *Find ( const unsigned char *pCtx )
    {
        for ( size_t i = 0; i < v.size ( ); ++i )
            if ( std::memcmp ( v[i].aCtx, pCtx, kSealEphLen ) == 0 )
                return &v[i];
        return nullptr;
    }

    //  The replay window, IPsec's shape: 64 back from the highest seq seen.
    //  A seq more than 63 behind the top is refused as a replay, because the
    //  window can no longer say it was not seen - the price is that a body
    //  overtaken by 64 later ones from the same context is lost, which on a
    //  route that keeps order (every transport here does) does not happen.
    static bool Seen ( const Entry &e, unsigned long long ullSeq )
    {
        if ( ullSeq > e.ullTop ) return false;
        const unsigned long long d = e.ullTop - ullSeq;
        if ( d >= 64 ) return true;
        return ( e.ullMask >> d ) & 1u;
    }

    static void Mark ( Entry &e, unsigned long long ullSeq )
    {
        if ( ullSeq > e.ullTop )
        {
            const unsigned long long s = ullSeq - e.ullTop;
            e.ullMask = s >= 64 ? 0 : ( e.ullMask << s );
            e.ullTop  = ullSeq;
            e.ullMask |= 1u;
        }
        else
            e.ullMask |= ( 1ull << ( e.ullTop - ullSeq ) );
    }

    void Insert ( const unsigned char *pCtx, const unsigned char *pKek,
                  unsigned long long ullSeq )
    {
        Entry *pE = nullptr;
        if ( v.size ( ) < kSealOpenCacheMax )
        {
            v.push_back ( Entry ( ) );
            pE = &v.back ( );
        }
        else
        {
            size_t iOld = 0;
            for ( size_t i = 1; i < v.size ( ); ++i )
                if ( v[i].ullUsed < v[iOld].ullUsed ) iOld = i;
            pE = &v[iOld];
            Wipe ( pE->aKek, sizeof(pE->aKek) );
        }
        std::memcpy ( pE->aCtx, pCtx, kSealEphLen );
        std::memcpy ( pE->aKek, pKek, kAesKeyLen );
        pE->ullTop  = ullSeq;
        pE->ullMask = 1u;
        pE->ullUsed = ++ullTick;
    }
};

OpenContextCache::OpenContextCache ( ) : m_p ( new Impl ) { }
OpenContextCache::~OpenContextCache ( ) { m_p->Drop ( ); delete m_p; }
void   OpenContextCache::Reset   ( )       { m_p->Drop ( ); }
void   OpenContextCache::SetReplayWindow ( bool bOn ) { m_p->bWindow = bOn; }
bool   OpenContextCache::IsReplayWindowOn ( ) const   { return m_p->bWindow; }
size_t OpenContextCache::Entries ( ) const { return m_p->v.size ( ); }
unsigned long long OpenContextCache::Hits   ( ) const { return m_p->ullHits; }
unsigned long long OpenContextCache::Misses ( ) const { return m_p->ullMisses; }

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
      //  The two v2 outcomes were missing here since they were added and read
      //  "unknown" in every log line that printed one; added with v3's.
      case SealErrReaders:     return "reader count out of range, or a reader named twice";
      case SealErrNotAReader:  return "this peer is not a reader of the sealed body";
      case SealErrContextRefused:
                               return "context-mode sealed body refused by this reader's policy";
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
    if ( !p || cb < kSealVerLen ) return 0;

    //  v3 has the count kSealSeqLen further in, and kSealSeqLen more overhead;
    //  otherwise the same bound. v1 has no reader block at all.
    const bool   bV3   = p[0] == kSealVersion3;
    if ( p[0] != kSealVersion && !bV3 ) return 0;
    const size_t offN  = kSealVerLen + kSealTimeLen + kSealEphLen
                       + ( bV3 ? kSealSeqLen : 0 );
    if ( cb < offN + kSealCountLen ) return 0;

    const size_t n = (size_t)p[offN];
    if ( n == 0 || n > kSealMaxReaders ) return 0;
    if ( cb < ( bV3 ? SealOverheadV3 ( n ) : SealOverhead ( n ) ) ) return 0;
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
    return SealToKeyed ( oSender, pReaders, nullptr, nReaders, pSrc, pDst,
                         pPlain, cbPlain, pOut, cbOut, pcbOut, llWhen );
}

SealResult
SealToKeyed ( p2pcng::EcdsaP256 &oSender,
              const unsigned char *pReaders,
              p2pcng::EcdhP256 *const *apReaderKeys, size_t nReaders,
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
        p2pcng::EcdhP256 *pKey = apReaderKeys ? apReaderKeys[r] : nullptr;
        if ( !( pKey ? oEph.DeriveRawSecret ( *pKey, aSecret )
                     : oEph.DeriveRawSecret ( pRdr, aSecret ) ) )
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

// ---- Seal, version 3: the context mode (T1d) ---------------------------
//  SealToKeyed with the per-message ephemeral pair replaced by the context's,
//  and the per-reader ECDH replaced by a cached wrapping key. Everything else
//  - a random content key per message, the slot order, the duplicate check,
//  encrypt-then-sign over the whole slot region - is the same, and is the
//  same on purpose: the two differ in where a key comes from, not in what a
//  body binds.
SealResult
SealToContext ( SealContext &oCtx,
                p2pcng::EcdsaP256 &oSender,
                const unsigned char *pReaders,
                p2pcng::EcdhP256 *const *apReaderKeys, size_t nReaders,
                const wchar_t *pSrc, const wchar_t *pDst,
                const void *pPlain, size_t cbPlain,
                unsigned char *pOut, size_t cbOut, size_t *pcbOut,
                long long llWhen )
{
    if ( pcbOut ) *pcbOut = 0;
    if ( !pReaders || !pSrc || !pDst || !pOut )        return SealErrArgs;
    if ( cbPlain && !pPlain )                          return SealErrArgs;
    if ( nReaders == 0 || nReaders > kSealMaxReaders ) return SealErrReaders;
    if ( cbOut < SealedSizeV3 ( cbPlain, nReaders ) )  return SealErrArgs;

    for ( size_t a = 0; a < nReaders; ++a )
      for ( size_t b = a + 1; b < nReaders; ++b )
        if ( std::memcmp ( pReaders + a * kEcdhPubLen,
                           pReaders + b * kEcdhPubLen, kEcdhPubLen ) == 0 )
          return SealErrReaders;

    if ( llWhen == 0 ) llWhen = (long long)std::time ( 0 );

    SealContext::Impl &c = *oCtx.Get ( );
    if ( c.Due ( llWhen ) && !c.Start ( llWhen ) )
        return SealErrInternal;

    //  The seq is TAKEN before anything can fail, so a seal that fails half
    //  way never leaves a number that a later message reuses. A gap costs
    //  nothing; a repeat would be a replay the receiver is right to refuse.
    const unsigned long long ullSeq = c.ullNext++;
    unsigned char aSeq[kSealSeqLen];
    PutTime ( aSeq, (long long)ullSeq );

    //  Layout: ver(1) | when(8) | ctx(64) | seq(8) | n(1) | slots(68n) | body | sig(64)
    unsigned char *const pHdr   = pOut;
    unsigned char *const pCtxW  = pOut + kSealVerLen + kSealTimeLen;
    unsigned char *const pSeqW  = pCtxW + kSealEphLen;
    unsigned char *const pCntW  = pSeqW + kSealSeqLen;
    unsigned char *const pSlotW = pCntW + kSealCountLen;
    unsigned char *const pBodyW = pSlotW + kSealSlotLen * nReaders;

    unsigned char aTags[kSealMaxReaders * kSealRTagLen];
    for ( size_t r = 0; r < nReaders; ++r )
        if ( !SlotTagV3 ( c.aCtx, aSeq, pReaders + r * kEcdhPubLen,
                          aTags + r * kSealRTagLen ) )
            return SealErrInternal;

    unsigned char aCek[kSealCekLen];
    if ( !p2pcng::CngRandom ( aCek, (unsigned long)sizeof(aCek) ) )
        return SealErrInternal;

    std::string sAad;
    if ( !TranscriptV2 ( kLabelAad, pSrc, pDst, kSealVersion3, llWhen,
                         c.aCtx, nReaders, aTags, 0, 0, 0, sAad, aSeq ) )
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

    for ( size_t r = 0; r < nReaders; ++r )
    {
        const unsigned char *pRdr = pReaders + r * kEcdhPubLen;
        unsigned char *pTagW  = pSlotW + r * kSealSlotLen;
        unsigned char *pWrapW = pTagW  + kSealRTagLen;

        std::memcpy ( pTagW, aTags + r * kSealRTagLen, kSealRTagLen );

        //  The wrapping key for this reader in this context: cached, or
        //  derived once and cached. The only ECDH v3 does, and it does it
        //  once per reader per context rather than once per message.
        const unsigned char *pKek = nullptr;
        for ( size_t i = 0; i < c.vReaders.size ( ); ++i )
            if ( std::memcmp ( c.vReaders[i].aPub, pRdr, kEcdhPubLen ) == 0 )
            { pKek = c.vReaders[i].aKek; break; }

        if ( !pKek )
        {
            unsigned char aSecret[kEcdhSecLen];
            p2pcng::EcdhP256 *pKey = apReaderKeys ? apReaderKeys[r] : nullptr;
            if ( !( pKey ? c.pEph->DeriveRawSecret ( *pKey, aSecret )
                         : c.pEph->DeriveRawSecret ( pRdr, aSecret ) ) )
            {
                Wipe ( aCek, sizeof(aCek) );
                return SealErrNoAgreement;      // not a point on P-256
            }

            SealContext::Impl::Reader oNew;
            const bool bKek = DeriveKek3 ( aSecret, c.aCtx, oNew.aKek );
            Wipe ( aSecret, sizeof(aSecret) );
            if ( !bKek )
            {
                Wipe ( oNew.aKek, sizeof(oNew.aKek) );
                Wipe ( aCek, sizeof(aCek) );
                return SealErrInternal;
            }
            std::memcpy ( oNew.aPub, pRdr, kEcdhPubLen );

            if ( c.vReaders.size ( ) >= SealContext::Impl::kMaxReaders )
            {
                Wipe ( c.vReaders.front ( ).aKek, kAesKeyLen );
                c.vReaders.erase ( c.vReaders.begin ( ) );
            }
            c.vReaders.push_back ( oNew );
            Wipe ( oNew.aKek, sizeof(oNew.aKek) );
            pKek = c.vReaders.back ( ).aKek;
        }

        std::string sWrapAad;
        if ( !TranscriptV2 ( kLabelWrp, pSrc, pDst, kSealVersion3, llWhen,
                             c.aCtx, nReaders, aTags, 0,
                             pTagW, kSealRTagLen, sWrapAad, aSeq ) )
        {
            Wipe ( aCek, sizeof(aCek) );
            return SealErrInternal;
        }

        //  The wrap's GCM nonce is random, as under v2, but now many wraps
        //  share one key: at most kSealCtxMaxMsgsCap (2^20) per reader per
        //  context, against a 2^32 budget for random 96-bit nonces.
        p2pcng::AesGcm oWrap;
        size_t cbWrap = 0;
        const bool bWrapped =
            oWrap.SetKey ( pKek, kAesKeyLen ) &&
            oWrap.Seal ( aCek, sizeof(aCek),
                         (const unsigned char *)sWrapAad.data ( ),
                         sWrapAad.size ( ),
                         pWrapW, kSealWrapLen, &cbWrap );
        if ( !bWrapped || cbWrap != kSealWrapLen )
        {
            Wipe ( aCek, sizeof(aCek) );
            return SealErrInternal;
        }
    }
    Wipe ( aCek, sizeof(aCek) );

    pHdr[0] = kSealVersion3;
    PutTime ( pHdr + kSealVerLen, llWhen );
    std::memcpy ( pCtxW, c.aCtx, kSealEphLen );
    std::memcpy ( pSeqW, aSeq, kSealSeqLen );
    pCntW[0] = (unsigned char)nReaders;

    std::string sSig;
    if ( !TranscriptV2 ( kLabelSig, pSrc, pDst, kSealVersion3, llWhen,
                         c.aCtx, nReaders, aTags, 0,
                         pBodyW, cbSealed, sSig, aSeq ) )
        return SealErrInternal;
    AppendField ( sSig, pSlotW, kSealSlotLen * nReaders );

    if ( !oSender.Sign ( (const unsigned char *)sSig.data ( ), sSig.size ( ),
                         pBodyW + cbSealed ) )
        return SealErrNoIdentity;

    if ( pcbOut ) *pcbOut = SealedSizeV3 ( cbPlain, nReaders );
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
       p2pcng::EcdsaP256 *pSenderKey,      // T1g: pre-imported, or null
       const wchar_t *pSrc, const wchar_t *pDst,
       const unsigned char *pIn, size_t cbIn,
       void *pOut, size_t cbOut, size_t *pcbOut,
       long long *pllWhenOut )
{
    if ( pcbOut )    *pcbOut    = 0;
    if ( pllWhenOut ) *pllWhenOut = 0;
    if ( ( !pSenderId && !pSenderKey ) || !pSrc || !pDst || !pIn )
        return SealErrArgs;
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
        p2pcng::EcdsaP256 *pPeer = pSenderKey;
        if ( !pPeer )
        {
            if ( !oPeer.ImportPublic ( pSenderId ) ) return SealErrInternal;
            pPeer = &oPeer;
        }
        if ( !pPeer->Verify ( (const unsigned char *)sSig.data ( ), sSig.size ( ),
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
         p2pcng::EcdsaP256 *pSenderKey,    // T1g: pre-imported, or null
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
        p2pcng::EcdsaP256 *pPeer = pSenderKey;
        if ( !pPeer )
        {
            if ( !oPeer.ImportPublic ( pSenderId ) ) return SealErrInternal;
            pPeer = &oPeer;
        }
        if ( !pPeer->Verify ( (const unsigned char *)sSig.data ( ), sSig.size ( ),
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

// ---- Open, version 3 ---------------------------------------------------
//  OpenV2's order, step for step: count bounded first, signature before any
//  work with our private key, our slot by hash, unwrap, open. What v3 adds is
//  where the wrapping key comes from - the cache when this context has opened
//  before, one ECDH when it has not - and the replay window on seq, which is
//  CONSULTED before the unwrap and WRITTEN only after the body has opened.
namespace {
SealResult
OpenV3 ( p2pcng::EcdhP256 &oRecipAgree,
         const unsigned char *pSenderId,
         p2pcng::EcdsaP256 *pSenderKey,
         OpenContextCache *pCache,
         const wchar_t *pSrc, const wchar_t *pDst,
         const unsigned char *pIn, size_t cbIn,
         void *pOut, size_t cbOut, size_t *pcbOut,
         long long *pllWhenOut )
{
    const size_t nReaders = SealReaderCount ( pIn, cbIn );
    if ( nReaders == 0 ) return SealErrFormat;

    const long long llWhen = GetTime ( pIn + kSealVerLen );

    const unsigned char *pCtx   = pIn + kSealVerLen + kSealTimeLen;
    const unsigned char *pSeq   = pCtx + kSealEphLen;
    const unsigned char *pSlots = pSeq + kSealSeqLen + kSealCountLen;
    const unsigned char *pBody  = pSlots + kSealSlotLen * nReaders;
    const unsigned long long ullSeq = (unsigned long long)GetTime ( pSeq );

    const size_t cbPlain  = cbIn - SealOverheadV3 ( nReaders );
    const size_t cbSealed = p2pcng::AesGcm::SealedSize ( cbPlain );
    const unsigned char *pSig = pBody + cbSealed;
    if ( cbOut < cbPlain ) return SealErrArgs;

    unsigned char aTags[kSealMaxReaders * kSealRTagLen];
    for ( size_t r = 0; r < nReaders; ++r )
        std::memcpy ( aTags + r * kSealRTagLen,
                      pSlots + r * kSealSlotLen, kSealRTagLen );

    std::string sSig;
    if ( !TranscriptV2 ( kLabelSig, pSrc, pDst, pIn[0], llWhen,
                         pCtx, nReaders, aTags, 0, pBody, cbSealed, sSig, pSeq ) )
        return SealErrInternal;
    AppendField ( sSig, pSlots, kSealSlotLen * nReaders );
    {
        p2pcng::EcdsaP256 oPeer;
        p2pcng::EcdsaP256 *pPeer = pSenderKey;
        if ( !pPeer )
        {
            if ( !oPeer.ImportPublic ( pSenderId ) ) return SealErrInternal;
            pPeer = &oPeer;
        }
        if ( !pPeer->Verify ( (const unsigned char *)sSig.data ( ), sSig.size ( ),
                              pSig ) )
            return SealErrSignature;
    }

    unsigned char aOurPub[kEcdhPubLen];
    if ( !oRecipAgree.ExportPublic ( aOurPub ) ) return SealErrNoAgreement;

    unsigned char aWant[kSealRTagLen];
    if ( !SlotTagV3 ( pCtx, pSeq, aOurPub, aWant ) ) return SealErrInternal;

    size_t iSlot = nReaders;
    for ( size_t r = 0; r < nReaders; ++r )
        if ( p2pcng::ConstTimeEqual ( aTags + r * kSealRTagLen, aWant,
                                      kSealRTagLen ) )
        { iSlot = r; break; }
    if ( iSlot == nReaders ) return SealErrNotAReader;

    const unsigned char *pWrap = pSlots + iSlot * kSealSlotLen + kSealRTagLen;

    //  The wrapping key. A cached entry is keyed by the context point alone,
    //  and that is enough: the key is derived from that point and OUR static
    //  half, so nobody without the context's private half or ours can make a
    //  wrap it opens - another allow-listed sender reusing the point gets as
    //  far as the unwrap and fails there, without touching the entry.
    OpenContextCache::Impl *pC = pCache ? pCache->Get ( ) : nullptr;
    OpenContextCache::Impl::Entry *pE = pC ? pC->Find ( pCtx ) : nullptr;

    if ( pE && pC->bWindow && OpenContextCache::Impl::Seen ( *pE, ullSeq ) )
        return SealErrReplay;

    unsigned char aKek[kAesKeyLen];
    if ( pE )
        std::memcpy ( aKek, pE->aKek, kAesKeyLen );
    else
    {
        unsigned char aSecret[kEcdhSecLen];
        if ( !oRecipAgree.DeriveRawSecret ( pCtx, aSecret ) )
            return SealErrNoAgreement;
        const bool bKek = DeriveKek3 ( aSecret, pCtx, aKek );
        Wipe ( aSecret, sizeof(aSecret) );
        if ( !bKek ) { Wipe ( aKek, sizeof(aKek) ); return SealErrInternal; }
    }

    std::string sWrapAad;
    if ( !TranscriptV2 ( kLabelWrp, pSrc, pDst, pIn[0], llWhen,
                         pCtx, nReaders, aTags, 0,
                         aTags + iSlot * kSealRTagLen, kSealRTagLen,
                         sWrapAad, pSeq ) )
    { Wipe ( aKek, sizeof(aKek) ); return SealErrInternal; }

    unsigned char aCek[kSealCekLen];
    size_t cbCek = 0;
    p2pcng::AesGcm oWrap;
    const bool bUnwrapped =
        oWrap.SetKey ( aKek, sizeof(aKek) ) &&
        oWrap.Open ( pWrap, kSealWrapLen,
                     (const unsigned char *)sWrapAad.data ( ), sWrapAad.size ( ),
                     aCek, sizeof(aCek), &cbCek );
    if ( !bUnwrapped || cbCek != kSealCekLen )
    {
        Wipe ( aCek, sizeof(aCek) );
        Wipe ( aKek, sizeof(aKek) );
        return SealErrTag;
    }

    std::string sAad;
    if ( !TranscriptV2 ( kLabelAad, pSrc, pDst, pIn[0], llWhen,
                         pCtx, nReaders, aTags, 0, 0, 0, sAad, pSeq ) )
    {
        Wipe ( aCek, sizeof(aCek) );
        Wipe ( aKek, sizeof(aKek) );
        return SealErrInternal;
    }

    p2pcng::AesGcm oGcm;
    size_t cbGot = 0;
    const bool bOpened =
        oGcm.SetKey ( aCek, sizeof(aCek) ) &&
        oGcm.Open ( pBody, cbSealed,
                    (const unsigned char *)sAad.data ( ), sAad.size ( ),
                    (unsigned char *)pOut, cbOut, &cbGot );
    Wipe ( aCek, sizeof(aCek) );

    if ( !bOpened || cbGot != cbPlain )
    {
        Wipe ( aKek, sizeof(aKek) );
        return SealErrTag;
    }

    //  Opened. Only now does the cache learn anything.
    if ( pC )
    {
        if ( pE )
        {
            OpenContextCache::Impl::Mark ( *pE, ullSeq );
            pE->ullUsed = ++pC->ullTick;
            ++pC->ullHits;
        }
        else
        {
            pC->Insert ( pCtx, aKek, ullSeq );
            ++pC->ullMisses;
        }
    }
    Wipe ( aKek, sizeof(aKek) );

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
namespace {
SealResult
OpenAny ( p2pcng::EcdhP256 &oRecipAgree,
          const unsigned char *pSenderId,
          p2pcng::EcdsaP256 *pSenderKey,
          const wchar_t *pSrc, const wchar_t *pDst,
          const unsigned char *pIn, size_t cbIn,
          void *pOut, size_t cbOut, size_t *pcbOut,
          long long *pllWhenOut,
          OpenContextCache *pCache = nullptr,
          bool bAcceptContext = true )
{
    if ( pcbOut )     *pcbOut     = 0;
    if ( pllWhenOut ) *pllWhenOut = 0;
    if ( ( !pSenderId && !pSenderKey ) || !pSrc || !pDst || !pIn )
        return SealErrArgs;
    if ( cbIn < kSealVerLen )                   return SealErrFormat;

    switch ( pIn[0] )
    {
      case kSealVersion3:
        //  Refused by policy before a byte past the version is parsed and
        //  before any key is touched - the same place SealErrVersion is
        //  decided, because from a refusing reader's side it is the same
        //  question: is this a body I open at all.
        if ( !bAcceptContext ) return SealErrContextRefused;
        return OpenV3 ( oRecipAgree, pSenderId, pSenderKey, pCache, pSrc, pDst,
                        pIn, cbIn, pOut, cbOut, pcbOut, pllWhenOut );
      case kSealVersion:
        return OpenV2 ( oRecipAgree, pSenderId, pSenderKey, pSrc, pDst,
                        pIn, cbIn, pOut, cbOut, pcbOut, pllWhenOut );
      case kSealVersion1:
        return OpenV1 ( oRecipAgree, pSenderId, pSenderKey, pSrc, pDst,
                        pIn, cbIn, pOut, cbOut, pcbOut, pllWhenOut );
    }
    //  Includes every v0 body, which began with a uniformly distributed
    //  coordinate and so lands here 254 times in 256.
    return SealErrVersion;
}
}   // anonymous namespace

SealResult
Open ( p2pcng::EcdhP256 &oRecipAgree,
       const unsigned char *pSenderId,
       const wchar_t *pSrc, const wchar_t *pDst,
       const unsigned char *pIn, size_t cbIn,
       void *pOut, size_t cbOut, size_t *pcbOut,
       long long *pllWhenOut )
{
    //  pSenderId checked HERE as well as in OpenAny: the raw-point entry point
    //  must keep refusing a null point with SealErrArgs, and OpenAny alone
    //  would accept it whenever a key was passed - which here it never is.
    if ( pcbOut )     *pcbOut     = 0;
    if ( pllWhenOut ) *pllWhenOut = 0;
    if ( !pSenderId ) return SealErrArgs;
    return OpenAny ( oRecipAgree, pSenderId, nullptr, pSrc, pDst,
                     pIn, cbIn, pOut, cbOut, pcbOut, pllWhenOut );
}

SealResult
OpenKeyed ( p2pcng::EcdhP256 &oRecipAgree,
            p2pcng::EcdsaP256 &oSenderKey,
            const wchar_t *pSrc, const wchar_t *pDst,
            const unsigned char *pIn, size_t cbIn,
            void *pOut, size_t cbOut, size_t *pcbOut,
            long long *pllWhenOut )
{
    return OpenAny ( oRecipAgree, nullptr, &oSenderKey, pSrc, pDst,
                     pIn, cbIn, pOut, cbOut, pcbOut, pllWhenOut );
}

SealResult
OpenKeyedCtx ( p2pcng::EcdhP256 &oRecipAgree,
               p2pcng::EcdsaP256 &oSenderKey,
               OpenContextCache *pCache, bool bAcceptContext,
               const wchar_t *pSrc, const wchar_t *pDst,
               const unsigned char *pIn, size_t cbIn,
               void *pOut, size_t cbOut, size_t *pcbOut,
               long long *pllWhenOut )
{
    return OpenAny ( oRecipAgree, nullptr, &oSenderKey, pSrc, pDst,
                     pIn, cbIn, pOut, cbOut, pcbOut, pllWhenOut,
                     pCache, bAcceptContext );
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

    // 12. VERSION 3, the context mode (T1d). Same refusals as v2, plus what
    //     the context adds: one ECDH per context at each end, a seq that is
    //     bound and replay-checked, rotation, and a reader that may refuse.
    if ( bOk )
    {
        const size_t cb3 = SealedSizeV3 ( cbPlain );
        std::vector<unsigned char> v1 ( cb3 ), v2b ( cb3 ), vO ( cbPlain );
        p2pcng::EcdsaP256 oKeyA;                    // sender, public only
        if ( !oKeyA.ImportPublic ( aPubA ) ) bOk = false;

        SealContext      oCtx;
        OpenContextCache oCache;
        const long long  llT = 1800000000;          // a fixed stamp
        size_t cbGot3 = 0;

        //  a) Two seals, one context: same point, seq 0 then 1, v3 sizes.
        if ( bOk && ( SealToContext ( oCtx, oIdA, aAgrC, 0, 1, pA, pC,
                                      szSecret, cbPlain, &v1[0], cb3,
                                      &cbGot3, llT ) != SealOk
                      || cbGot3 != cb3 || v1[0] != kSealVersion3 ) )
            bOk = false;
        if ( bOk && SealToContext ( oCtx, oIdA, aAgrC, 0, 1, pA, pC,
                                    szSecret, cbPlain, &v2b[0], cb3,
                                    0, llT ) != SealOk )
            bOk = false;
        const size_t kOffCtx = kSealVerLen + kSealTimeLen;
        const size_t kOffSeq = kOffCtx + kSealEphLen;
        if ( bOk && ( std::memcmp ( &v1[kOffCtx], &v2b[kOffCtx], kSealEphLen ) != 0
                      || GetTime ( &v1[kOffSeq] ) != 0
                      || GetTime ( &v2b[kOffSeq] ) != 1
                      || oCtx.Generations ( ) != 1
                      || oCtx.CachedReaders ( ) != 1
                      || SealReaderCount ( &v1[0], cb3 ) != 1 ) )
            bOk = false;
        //  ... and the reader's slot tag still differs between the two,
        //  although the context point is the same: the seq is in the tag. A
        //  round trip cannot show this - both ends would agree on a tag
        //  without the seq just as well - so it is asserted on the bytes.
        //  (Mutation-checked 2026-11-28: dropping the seq from SlotTagV3
        //  passed every other case here.)
        const size_t kOffTag = kOffSeq + kSealSeqLen + kSealCountLen;
        if ( bOk && std::memcmp ( &v1[kOffTag], &v2b[kOffTag], kSealRTagLen ) == 0 )
            bOk = false;

        //  b) The plaintext appears nowhere in a v3 body either.
        for ( size_t i = 0; bOk && i + cbPlain <= cb3; ++i )
            if ( std::memcmp ( &v1[i], szSecret, cbPlain ) == 0 ) bOk = false;

        //  c) Both open through the cache: one derive, then one hit.
        if ( bOk && ( OpenKeyedCtx ( oAgrC, oKeyA, &oCache, true, pA, pC,
                                     &v1[0], cb3, &vO[0], cbPlain, &cbGot3 )
                        != SealOk
                      || cbGot3 != cbPlain
                      || std::memcmp ( &vO[0], szSecret, cbPlain ) != 0 ) )
            bOk = false;
        if ( bOk && OpenKeyedCtx ( oAgrC, oKeyA, &oCache, true, pA, pC,
                                   &v2b[0], cb3, &vO[0], cbPlain, 0 ) != SealOk )
            bOk = false;
        if ( bOk && ( oCache.Misses ( ) != 1 || oCache.Hits ( ) != 1
                      || oCache.Entries ( ) != 1 ) )
            bOk = false;

        //  d) A replay inside the context is refused WITH a cache, and opens
        //     without one - the stateless path leaves replay to the
        //     signature-keyed cache one layer up, as v2 does.
        if ( bOk && OpenKeyedCtx ( oAgrC, oKeyA, &oCache, true, pA, pC,
                                   &v1[0], cb3, &vO[0], cbPlain, 0 )
                      != SealErrReplay )
            bOk = false;
        if ( bOk && OpenKeyedCtx ( oAgrC, oKeyA, 0, true, pA, pC,
                                   &v1[0], cb3, &vO[0], cbPlain, 0 ) != SealOk )
            bOk = false;
        //  ... and the raw-point Open every older caller uses reads v3 too.
        if ( bOk && Open ( oAgrC, aPubA, pA, pC, &v1[0], cb3,
                           &vO[0], cbPlain, 0 ) != SealOk )
            bOk = false;

        //  e) A reader that refuses context bodies says so, by policy.
        if ( bOk && OpenKeyedCtx ( oAgrC, oKeyA, 0, false, pA, pC,
                                   &v1[0], cb3, &vO[0], cbPlain, 0 )
                      != SealErrContextRefused )
            bOk = false;

        //  f) Wrong reader, wrong sender, moved addresses: v2's answers.
        if ( bOk && OpenKeyedCtx ( oAgrOther, oKeyA, 0, true, pA, pC,
                                   &v1[0], cb3, &vO[0], cbPlain, 0 )
                      != SealErrNotAReader )
            bOk = false;
        if ( bOk && Open ( oAgrC, aPubX, pA, pC, &v1[0], cb3,
                           &vO[0], cbPlain, 0 ) != SealErrSignature )
            bOk = false;
        if ( bOk && Open ( oAgrC, aPubA, pC, pA, &v1[0], cb3,
                           &vO[0], cbPlain, 0 ) != SealErrSignature )
            bOk = false;

        //  g) Downgrade: a v3 body relabelled v2 (or v1) never opens. The
        //     version is bound in both transcripts, and v2's offsets read the
        //     seq as the start of the reader block.
        for ( unsigned char ucTo = 1; bOk && ucTo <= 2; ++ucTo )
        {
            v1[0] = ucTo;
            if ( Open ( oAgrC, aPubA, pA, pC, &v1[0], cb3,
                        &vO[0], cbPlain, 0 ) == SealOk )
                bOk = false;
            v1[0] = kSealVersion3;
        }

        //  h) One flipped bit in each v3 region, stateless so a replay
        //     refusal cannot stand in for the forgery being caught.
        if ( bOk )
        {
            const size_t kOffSlot = kOffSeq + kSealSeqLen + kSealCountLen;
            const size_t kOffBody = kOffSlot + kSealSlotLen;
            const size_t anProbe[] = { kSealVerLen,               // sealed_at
                                       kOffCtx,                   // context point
                                       kOffSeq + kSealSeqLen - 1, // seq, low byte
                                       kOffSeq + kSealSeqLen,     // reader count
                                       kOffSlot,                  // slot tag
                                       kOffSlot + kSealRTagLen,   // wrapped key
                                       kOffBody,                  // nonce
                                       kOffBody + kSealNonceLen,  // ciphertext
                                       cb3 - kSealSigLen - 1,     // tag
                                       cb3 - 1 };                 // signature
            for ( size_t i = 0; bOk && i < sizeof(anProbe)/sizeof(anProbe[0]); ++i )
            {
                v1[anProbe[i]] ^= 0x01;
                if ( OpenKeyedCtx ( oAgrC, oKeyA, 0, true, pA, pC,
                                    &v1[0], cb3, &vO[0], cbPlain, 0 ) == SealOk )
                    bOk = false;
                v1[anProbe[i]] ^= 0x01;
            }
        }

        //  i) Rotation by count: bounds of 2 messages, and the third seal
        //     starts a new context with a new point and seq 0.
        oCtx.SetBounds ( 2, 300 );
        if ( bOk && SealToContext ( oCtx, oIdA, aAgrC, 0, 1, pA, pC,
                                    szSecret, cbPlain, &v2b[0], cb3,
                                    0, llT ) != SealOk )
            bOk = false;
        if ( bOk && ( oCtx.Generations ( ) != 2
                      || GetTime ( &v2b[kOffSeq] ) != 0
                      || std::memcmp ( &v1[kOffCtx], &v2b[kOffCtx],
                                       kSealEphLen ) == 0 ) )
            bOk = false;
        //  ... and the new context costs the receiver one more derive.
        if ( bOk && ( OpenKeyedCtx ( oAgrC, oKeyA, &oCache, true, pA, pC,
                                     &v2b[0], cb3, &vO[0], cbPlain, 0 ) != SealOk
                      || oCache.Misses ( ) != 2 || oCache.Entries ( ) != 2 ) )
            bOk = false;

        //  j) Rotation by time, forwards past the bound and backwards past
        //     the context's birth.
        if ( bOk && SealToContext ( oCtx, oIdA, aAgrC, 0, 1, pA, pC,
                                    szSecret, cbPlain, &v2b[0], cb3,
                                    0, llT + 300 ) != SealOk )
            bOk = false;
        if ( bOk && oCtx.Generations ( ) != 3 ) bOk = false;
        if ( bOk && SealToContext ( oCtx, oIdA, aAgrC, 0, 1, pA, pC,
                                    szSecret, cbPlain, &v2b[0], cb3,
                                    0, llT ) != SealOk )
            bOk = false;
        if ( bOk && oCtx.Generations ( ) != 4 ) bOk = false;

        //  k) Reset drops the context and the cache: the next seal starts a
        //     new one, and the receiver derives again.
        oCtx.Reset ( );
        oCache.Reset ( );
        if ( bOk && ( oCtx.CachedReaders ( ) != 0 || oCache.Entries ( ) != 0 ) )
            bOk = false;
        if ( bOk && SealToContext ( oCtx, oIdA, aAgrC, 0, 1, pA, pC,
                                    szSecret, cbPlain, &v2b[0], cb3,
                                    0, llT ) != SealOk )
            bOk = false;
        if ( bOk && ( oCtx.Generations ( ) != 5
                      || OpenKeyedCtx ( oAgrC, oKeyA, &oCache, true, pA, pC,
                                        &v2b[0], cb3, &vO[0], cbPlain, 0 ) != SealOk
                      || oCache.Misses ( ) != 3 ) )
            bOk = false;

        //  l) Two readers in one context body: each opens its own slot.
        if ( bOk )
        {
            unsigned char aTwo[2 * kEcdhPubLen];
            std::memcpy ( aTwo, aAgrC, kEcdhPubLen );
            std::memcpy ( aTwo + kEcdhPubLen, aAgrOther, kEcdhPubLen );
            const size_t cb3b = SealedSizeV3 ( cbPlain, 2 );
            std::vector<unsigned char> vTwo ( cb3b );
            if ( SealToContext ( oCtx, oIdA, aTwo, 0, 2, pA, pC,
                                 szSecret, cbPlain, &vTwo[0], cb3b,
                                 0, llT ) != SealOk )
                bOk = false;
            if ( bOk && ( OpenKeyedCtx ( oAgrC, oKeyA, 0, true, pA, pC,
                                         &vTwo[0], cb3b, &vO[0], cbPlain, 0 ) != SealOk
                          || OpenKeyedCtx ( oAgrOther, oKeyA, 0, true, pA, pC,
                                            &vTwo[0], cb3b, &vO[0], cbPlain, 0 ) != SealOk
                          || SealReaderCount ( &vTwo[0], cb3b ) != 2 ) )
                bOk = false;
        }

        //  m) A verify-only identity cannot seal in context mode either.
        if ( bOk )
        {
            p2pcng::EcdsaP256 oPubOnly;
            if ( !oPubOnly.ImportPublic ( aPubA )
                 || SealToContext ( oCtx, oPubOnly, aAgrC, 0, 1, pA, pC,
                                    szSecret, cbPlain, &v2b[0], cb3, 0, llT )
                      != SealErrNoIdentity )
                bOk = false;
        }
    }

    delete [] pSealed;
    delete [] pOpened;
    return bOk;
}

} // namespace p2pseal
