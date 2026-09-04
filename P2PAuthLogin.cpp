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
//  P2PAuthLogin.cpp - proof of peer identity at login.
//
//  See P2PAuthLogin.h for the wire format and the threat statement.
//
//  ONE TU, BOTH PLATFORMS, and deliberately no stdafx.h - as with
//  P2PIdentityStore.cpp. Everything here is platform-independent (the
//  transcript, the block layout, the caches) except the temp directory the
//  self-test writes into, and those are exactly the parts that must not drift
//  between the CNG and OpenSSL backends: a transcript that differs by one byte
//  between them is a login that works only within one operating system, which
//  is the failure the session-5 cross-backend vectors exist to catch.
//
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include "P2PAuthLogin.h"
#include "P2PCngCrypto.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

namespace p2pauth
{

using p2pcng::EcdsaP256;
using p2pcng::kEcdsaPubLen;
using p2pcng::kEcdsaSigLen;
using p2pcng::kEcdhPubLen;      // the allow-list's optional agreement column

// -----------------------------------------------------------------------
//  Local helpers
// -----------------------------------------------------------------------
namespace
{
    const unsigned char kMagic0 = 'P';
    const unsigned char kMagic1 = 'A';
    //  Version 2 adds the channel binding to the transcript (not to the wire -
    //  the block layout is unchanged). A v1 peer and a v2 peer do not
    //  interoperate, and that is deliberate: a security upgrade with a
    //  negotiation is a security upgrade an attacker can decline.
    const unsigned char kVersion = 2;

    const char kLabelLogin[] = "P2P-login-v2";
    const char kLabelAck  [] = "P2P-ack-v2";
    const char kLabelBind [] = "P2P-kx-v1";

    // Offsets into the login block.
    const size_t kOffNonce = 3;
    const size_t kOffTs    = 19;
    const size_t kOffSig   = 27;
    // Offset into the ack block.
    const size_t kOffAckSig = 3;

    // Cap on the nonce cache when freshness is disabled (window == 0). With a
    // window the cache is trimmed by time; without one there is nothing to trim
    // by, so it is bounded by count and an evicted nonce becomes replayable.
    // Said plainly in the header rather than discovered.
    const size_t kSeenMax = 4096;

    struct AllowEntry
    {
        std::string   sIdentity;              // UTF-8, as written in the file
        unsigned char pub[kEcdsaPubLen];
        // The optional third column: the peer's static agreement point, which a
        // sender needs in order to seal a body to it. Absent for every entry
        // written before end-to-end sealing existed, hence the flag rather than
        // an all-zero point standing in for "none" - zero is a value a caller
        // could try to use.
        unsigned char agree[kEcdhPubLen];
        bool          bAgree;
    };

    //  Named NonceMark rather than SeenNonce: AuthPolicy has a member function
    //  of that name, which would hide the type inside every member body.
    struct NonceMark
    {
        unsigned char n[kAuthNonceLen];
        time_t        t;
    };

    //  A revoked point, raw. Both key kinds are 64 bytes and one list holds
    //  both, so this carries no kind tag - see P2PIdentityStore.h for why that
    //  is the safer shape rather than a shortcut.
    struct RevPoint
    {
        unsigned char p[p2pcng::kIdRevokePointLen];
    };

    //  The relay cache's entry. Keyed on the signature rather than on any
    //  identity of the message, because the signature is the one field that is
    //  unique per SEND: two legitimate sends of identical content differ here
    //  and nowhere else. See SetRelayReplayRefused in the header for why that
    //  is the property the design needs, and AuthSelfTest section 17 for the
    //  case that holds it.
    struct SigMark
    {
        unsigned char s[p2pcng::kEcdsaSigLen];
        time_t        t;
    };

    typedef std::vector<AllowEntry> AllowVec;
    typedef std::vector<NonceMark>  SeenVec;
    typedef std::vector<SigMark>    SeenSigVec;
    typedef std::vector<RevPoint>   RevVec;
    //  Configured extra readers, by ADDRESS. Resolved through the allow-list
    //  at seal time rather than stored as points, so revoking a reader's
    //  agreement key takes effect without anyone editing this list.
    typedef std::vector<std::wstring> ReaderVec;

    inline AllowVec   *Allow  ( void *p ) { return (AllowVec   *)p; }
    inline SeenVec    *Seen   ( void *p ) { return (SeenVec    *)p; }
    inline SeenSigVec *SeenRel( void *p ) { return (SeenSigVec *)p; }
    inline RevVec     *Revs   ( void *p ) { return (RevVec     *)p; }
    inline ReaderVec  *Readers( void *p ) { return (ReaderVec  *)p; }

    void PutU16 ( std::string &s, unsigned int v )
    {
        s.push_back ( (char)(unsigned char)( ( v >> 8 ) & 0xFF ) );
        s.push_back ( (char)(unsigned char)(   v        & 0xFF ) );
    }

    void PutI64 ( unsigned char *p, long long v )
    {
        for ( int i = 7; i >= 0; i-- )
        {
            p[i] = (unsigned char)( (unsigned long long)v & 0xFF );
            v = (long long)( (unsigned long long)v >> 8 );
        }
    }

    long long GetI64 ( const unsigned char *p )
    {
        unsigned long long v = 0;
        for ( int i = 0; i < 8; i++ )
            v = ( v << 8 ) | (unsigned long long)p[i];
        return (long long)v;
    }

    //  wchar_t -> UTF-8. Not a convenience: wchar_t is 2 bytes under MSVC and
    //  4 under GCC, so signing the raw wide bytes would make a Windows peer and
    //  a Linux peer disagree about what they signed. UTF-8 is the only encoding
    //  of a P2Paddr that both ends can agree on.
    //
    //  Unpaired surrogates are refused rather than substituted: this feeds a
    //  signature, and quietly mapping bad input to U+FFFD would let two
    //  different addresses produce one transcript.
    bool Utf8FromWide ( const wchar_t *pw, std::string &sOut )
    {
        if ( !pw ) return false;
        for ( ; *pw; ++pw )
        {
            unsigned long cp = (unsigned long)(unsigned int)*pw;

            if ( sizeof(wchar_t) < 4 )
            {
                if ( cp >= 0xD800 && cp <= 0xDBFF )          // high surrogate
                {
                    unsigned long lo = (unsigned long)(unsigned int)pw[1];
                    if ( lo < 0xDC00 || lo > 0xDFFF ) return false;
                    cp = 0x10000 + ( ( cp - 0xD800 ) << 10 ) + ( lo - 0xDC00 );
                    ++pw;
                }
                else if ( cp >= 0xDC00 && cp <= 0xDFFF )     // lone low
                    return false;
            }
            else if ( cp >= 0xD800 && cp <= 0xDFFF )
                return false;

            if ( cp > 0x10FFFF ) return false;

            if ( cp < 0x80 )
                sOut.push_back ( (char)cp );
            else if ( cp < 0x800 )
            {
                sOut.push_back ( (char)(unsigned char)( 0xC0 | ( cp >> 6 ) ) );
                sOut.push_back ( (char)(unsigned char)( 0x80 | ( cp & 0x3F ) ) );
            }
            else if ( cp < 0x10000 )
            {
                sOut.push_back ( (char)(unsigned char)( 0xE0 | ( cp >> 12 ) ) );
                sOut.push_back ( (char)(unsigned char)( 0x80 | ( ( cp >> 6 ) & 0x3F ) ) );
                sOut.push_back ( (char)(unsigned char)( 0x80 | ( cp & 0x3F ) ) );
            }
            else
            {
                sOut.push_back ( (char)(unsigned char)( 0xF0 | ( cp >> 18 ) ) );
                sOut.push_back ( (char)(unsigned char)( 0x80 | ( ( cp >> 12 ) & 0x3F ) ) );
                sOut.push_back ( (char)(unsigned char)( 0x80 | ( ( cp >> 6 ) & 0x3F ) ) );
                sOut.push_back ( (char)(unsigned char)( 0x80 | ( cp & 0x3F ) ) );
            }
        }
        return true;
    }

    void AppendField ( std::string &s, const void *p, size_t n )
    {
        PutU16 ( s, (unsigned int)n );
        //  append(nullptr, 0) is undefined even though it copies nothing, and
        //  an absent field (a null channel binding) takes exactly that path.
        if ( n )
            s.append ( (const char *)p, n );
    }

    //  T(label, src, dst, nonce [, ts]) - every field length-prefixed, so no
    //  two different tuples can produce the same byte string.
    bool Transcript ( const char *pszLabel,
                      const wchar_t *pSrc, const wchar_t *pDst,
                      const unsigned char *pNonce,
                      const long long *pTs,
                      const unsigned char *pBind,
                      std::string &sOut )
    {
        std::string sSrc, sDst;
        if ( !Utf8FromWide ( pSrc, sSrc ) ) return false;
        if ( !Utf8FromWide ( pDst, sDst ) ) return false;

        sOut.clear ( );
        AppendField ( sOut, pszLabel, std::strlen ( pszLabel ) );
        AppendField ( sOut, sSrc.data ( ), sSrc.size ( ) );
        AppendField ( sOut, sDst.data ( ), sDst.size ( ) );
        AppendField ( sOut, pNonce, kAuthNonceLen );
        if ( pTs )
        {
            unsigned char ts[8];
            PutI64 ( ts, *pTs );
            AppendField ( sOut, ts, sizeof(ts) );
        }
        //  Always appended, so an unbound login and a bound one are different
        //  transcripts rather than the same one read two ways. A null binding
        //  contributes a zero-length field; a 32-byte binding of all zeroes
        //  contributes a 32-byte field. The length prefix keeps them distinct.
        AppendField ( sOut, pBind, pBind ? kAuthBindLen : 0 );
        return true;
    }

    bool HeaderOk ( const unsigned char *p, AuthResult *peOut )
    {
        if ( p[0] != kMagic0 || p[1] != kMagic1 ) { *peOut = AuthErrFormat;  return false; }
        if ( p[2] != kVersion )                   { *peOut = AuthErrVersion; return false; }
        return true;
    }

    // ---- Relay attestation -------------------------------------------------
    //  A DIFFERENT magic from the login block's. The two never share a carrier -
    //  the login block is prepended to a payload, this one is a named field -
    //  so they cannot be confused by position; they are separated anyway,
    //  because "these can never meet" is the assumption every type-confusion
    //  bug is written against.
    const unsigned char kRelayMagic0  = 'P';
    const unsigned char kRelayMagic1  = 'R';
    const unsigned char kRelayVersion = 1;

    const char kLabelRelay[] = "P2P-relay-v1";

    // Offsets into the relay block. The attester is variable-length, so
    // everything after it is addressed relative to its end.
    const size_t kOffRelayAlen = 3;                    // u16 big-endian
    const size_t kOffRelayAddr = 5;
    inline size_t OffRelayTs  ( size_t cbAddr ) { return kOffRelayAddr + cbAddr; }
    inline size_t OffRelaySig ( size_t cbAddr ) { return OffRelayTs ( cbAddr ) + 8; }
    inline size_t RelayLen    ( size_t cbAddr ) { return kRelayFixedLen + cbAddr; }

    // ---- Revocation list ---------------------------------------------------
    //  A third magic, for the third thing this file signs. Same argument as the
    //  relay block's: these travel in different carriers and could not be
    //  confused by position, and they are separated anyway.
    const unsigned char kRevMagic0  = 'P';
    const unsigned char kRevMagic1  = 'V';
    const unsigned char kRevVersion = 1;

    const char kLabelRevList[] = "P2P-revlist-v1";

    const size_t kOffRevEpoch   = 3;                   // i64 big-endian
    const size_t kOffRevCount   = 11;                  // u16 big-endian
    const size_t kOffRevEntries = 13;
    inline size_t OffRevIssuer ( size_t n ) { return kOffRevEntries + n * kRevEntryLen; }
    inline size_t OffRevSig    ( size_t n ) { return OffRevIssuer ( n ) + 64; }

    //  T("P2P-revlist-v1", epoch, count, H(entries), issuer) - every field
    //  length-prefixed, as everywhere else in this file. The entry array is
    //  folded in as its SHA-256 so the transcript stays fixed-size whatever the
    //  list holds, exactly as RelayTranscript does with the body.
    //
    //  COUNT IS SIGNED SEPARATELY from the hash it describes. Hashing only the
    //  bytes would let a block declare a different count from the one that was
    //  signed, and the receiver would then read the issuer and signature from
    //  the wrong offsets - a parse the signature never covered.
    bool RevListTranscript ( long long llEpoch, size_t nCount,
                             const unsigned char *pEntries,
                             const unsigned char *pIssuer,
                             std::string &sOut )
    {
        unsigned char aHash[p2pcng::kSha256Len];
        static const unsigned char aNil = 0;
        if ( !p2pcng::Sha256 ( nCount ? pEntries : &aNil,
                               nCount * kRevEntryLen, aHash ) )
            return false;

        unsigned char ep[8], ct[8];
        PutI64 ( ep, llEpoch );
        PutI64 ( ct, (long long)nCount );

        sOut.clear ( );
        AppendField ( sOut, kLabelRevList, std::strlen ( kLabelRevList ) );
        AppendField ( sOut, ep, sizeof(ep) );
        AppendField ( sOut, ct, sizeof(ct) );
        AppendField ( sOut, aHash, sizeof(aHash) );
        AppendField ( sOut, pIssuer, 64 );
        return true;
    }

    //  UTF-8 -> wchar_t, the inverse of Utf8FromWide and refusing everything it
    //  refuses. This decodes an address that arrived on the wire, so it is
    //  strict on purpose: overlong encodings, surrogates encoded as if they were
    //  characters, and truncated sequences are all rejected rather than repaired.
    //  A repaired address is a DIFFERENT address that would then be handed to
    //  IsRable as though the signature had covered it.
    bool WideFromUtf8 ( const char *pIn, size_t cbIn,
                        wchar_t *pOut, size_t cchOut )
    {
        if ( !pIn || !pOut || cchOut == 0 ) return false;

        size_t w = 0;
        for ( size_t i = 0; i < cbIn; )
        {
            unsigned char c0 = (unsigned char)pIn[i];
            unsigned long cp = 0;
            size_t        n  = 0;

            if      ( c0 < 0x80 ) { cp = c0;         n = 1; }
            else if ( ( c0 & 0xE0 ) == 0xC0 ) { cp = c0 & 0x1Fu; n = 2; }
            else if ( ( c0 & 0xF0 ) == 0xE0 ) { cp = c0 & 0x0Fu; n = 3; }
            else if ( ( c0 & 0xF8 ) == 0xF0 ) { cp = c0 & 0x07u; n = 4; }
            else return false;

            if ( i + n > cbIn ) return false;
            for ( size_t k = 1; k < n; k++ )
            {
                unsigned char ck = (unsigned char)pIn[i + k];
                if ( ( ck & 0xC0 ) != 0x80 ) return false;
                cp = ( cp << 6 ) | (unsigned long)( ck & 0x3Fu );
            }
            //  Overlong: the shortest form is the only form, or two byte
            //  strings decode to one address.
            if ( n == 2 && cp < 0x80    ) return false;
            if ( n == 3 && cp < 0x800   ) return false;
            if ( n == 4 && cp < 0x10000 ) return false;
            if ( cp > 0x10FFFF ) return false;
            if ( cp >= 0xD800 && cp <= 0xDFFF ) return false;
            //  An embedded NUL would truncate the address at the C-string level
            //  while the signature covered the whole of it.
            if ( cp == 0 ) return false;

            if ( sizeof(wchar_t) < 4 && cp >= 0x10000 )
            {
                if ( w + 2 >= cchOut ) return false;      // +2 and the terminator
                cp -= 0x10000;
                pOut[w++] = (wchar_t)( 0xD800 + ( cp >> 10 ) );
                pOut[w++] = (wchar_t)( 0xDC00 + ( cp & 0x3FF ) );
            }
            else
            {
                if ( w + 1 >= cchOut ) return false;
                pOut[w++] = (wchar_t)cp;
            }
            i += n;
        }
        pOut[w] = 0;
        return true;
    }

    //  T("P2P-relay-v1", attester, src, dst, msgname, ts, H(body)) - every field
    //  length-prefixed, exactly as Transcript() does it and for the same reason.
    //  The body is folded in as its SHA-256 so the transcript is fixed-size
    //  whatever the message carries.
    bool RelayTranscript ( const wchar_t *pAttester,
                           const wchar_t *pSrc, const wchar_t *pDst,
                           const wchar_t *pMsgName,
                           const void *pBody, size_t cbBody,
                           long long llTs,
                           std::string &sOut )
    {
        std::string sAtt, sSrc, sDst, sMsg;
        if ( !Utf8FromWide ( pAttester, sAtt ) ) return false;
        if ( !Utf8FromWide ( pSrc,      sSrc ) ) return false;
        if ( !Utf8FromWide ( pDst,      sDst ) ) return false;
        //  A message with no name is a message with no handler, so an empty
        //  string here is a real value rather than a missing one - and the
        //  length prefix keeps it distinct from any non-empty name.
        if ( !Utf8FromWide ( pMsgName ? pMsgName : L"", sMsg ) ) return false;

        //  Sha256 of nothing is still a defined value, but the backend is not
        //  asked to hash a null pointer.
        unsigned char aHash[p2pcng::kSha256Len];
        static const unsigned char aNil = 0;
        if ( !p2pcng::Sha256 ( cbBody ? (const unsigned char *)pBody : &aNil,
                               cbBody, aHash ) )
            return false;

        unsigned char ts[8];
        PutI64 ( ts, llTs );

        sOut.clear ( );
        AppendField ( sOut, kLabelRelay, std::strlen ( kLabelRelay ) );
        AppendField ( sOut, sAtt.data ( ), sAtt.size ( ) );
        AppendField ( sOut, sSrc.data ( ), sSrc.size ( ) );
        AppendField ( sOut, sDst.data ( ), sDst.size ( ) );
        AppendField ( sOut, sMsg.data ( ), sMsg.size ( ) );
        AppendField ( sOut, ts, sizeof(ts) );
        AppendField ( sOut, aHash, sizeof(aHash) );
        return true;
    }

    //  Collector for p2pcng::LoadAllowList.
    struct AllowLoad
    {
        AllowVec *pVec;
        bool      bBad;
    };

    void AllowSink ( void *pCtx, const char *pszIdentity, const unsigned char *pPub,
                     const unsigned char *pAgree )
    {
        AllowLoad *pLoad = (AllowLoad *)pCtx;
        if ( !pLoad || !pLoad->pVec || !pszIdentity || !pPub ) { if (pLoad) pLoad->bBad = true; return; }
        AllowEntry oEntry;
        oEntry.sIdentity = pszIdentity;
        std::memcpy ( oEntry.pub, pPub, kEcdsaPubLen );
        std::memset ( oEntry.agree, 0, sizeof(oEntry.agree) );
        oEntry.bAgree = ( pAgree != nullptr );
        if ( pAgree ) std::memcpy ( oEntry.agree, pAgree, kEcdhPubLen );
        pLoad->pVec->push_back ( oEntry );
    }

} // anonymous namespace

// -----------------------------------------------------------------------
//  Result text
// -----------------------------------------------------------------------
const char *AuthResultText ( AuthResult eResult )
{
    switch ( eResult )
    {
      case AuthOk:             return "ok";
      case AuthOff:            return "authentication not configured";
      case AuthErrArgs:        return "bad arguments";
      case AuthErrNoIdentity:  return "no identity key loaded (cannot sign)";
      case AuthErrFormat:      return "no auth block, or malformed";
      case AuthErrVersion:     return "unsupported auth block version";
      case AuthErrUnknownPeer: return "claimed address is not in the allow-list";
      case AuthErrSignature:   return "signature does not verify";
      case AuthErrSkew:        return "timestamp outside the freshness window";
      case AuthErrReplay:      return "nonce already seen (replay)";
      case AuthErrRevoked:     return "key is revoked (or the revocation list "
                                      "is configured and unreadable)";
      case AuthErrInternal:    return "internal error";
    }
    return "unknown";
}

// -----------------------------------------------------------------------
//  AuthPolicy
// -----------------------------------------------------------------------
AuthPolicy::AuthPolicy ( )
    : m_pIdentity ( nullptr )
    , m_bHaveIdentity ( false )
    , m_pAgreement ( nullptr )
    , m_bHaveAgreement ( false )
    //  ON by default since Stage 3 step 8 - see
    //  SetRequired in the header for what that breaks and how to migrate.
    , m_bRequired ( true )
    //  ON by default since Stage 3 step 9. Separate switch,
    //  separate default, and deliberately NOT part of the arming gate - see
    //  SetRelayRequired in the header for why the asymmetry with m_bRequired
    //  is the correct one rather than an oversight.
    , m_bRelayRequired ( true )
    //  Both ON by default since Stage 3 step 10 - see
    //  SetRelayReplayRefused and SetSealReplayRefused in the header for what
    //  changed the argument, which for the seal half was the wire format.
    , m_bRelayReplay ( true )
    , m_bSealReplay ( true )
    //  ON by default since 2026-08-21. A body that will cross an intermediate
    //  hub is sealed to its destination or it is NOT SENT - see
    //  SetSealRequired in the header for what that breaks and the two ways to
    //  migrate.
    , m_bSealRequired ( true )
    //  ON by default too, so a broadcast on a sealing hub is REFUSED rather
    //  than quietly sent in clear. Turning it off is a deployment writing down
    //  that its broadcasts are not confidential - see the header.
    , m_bSealBroadcastRequired ( true )
    , m_pSealReaders ( nullptr )
    , m_nWindow ( kAuthWindowDefault )
    , m_nSealWindow ( kSealWindowDefault )
    , m_llSealFloor ( 0 )
    , m_pAllow ( nullptr )
    , m_pSeen ( nullptr )
    , m_pSeenRel ( nullptr )
    , m_pSeenSeal ( nullptr )
    , m_nSealNext ( 0 )
    , m_pszAllowPath ( nullptr )
    //  Meaningless until a path is configured; IsAllowUsable() reads it only
    //  when one is, so the initial value is never the answer to anything.
    , m_bAllowUsable ( false )
    , m_pRevoked ( nullptr )
    , m_pszRevokePath ( nullptr )
    , m_bRevokeConfigured ( false )
    //  True until a list is configured: "no revocation list" is a valid
    //  deployment and must not read as the fail-closed state.
    , m_bRevokeUsable ( true )
    //  ON by default since 2026-08-21 - a hub that requires auth must hold a
    //  revocation POSITION before it arms. See SetRevocationRequired in the
    //  header for the break, the two migrations, and why this one does not
    //  rest on the same argument as m_bRequired even though it looks like it.
    , m_bRevokeRequired ( true )
    //  Declaration order, not logical order - a mismatch is a -Wreorder
    //  warning and, for anything with a real constructor, a lie about what
    //  ran first.
    , m_bHaveAuthority ( false )
    , m_llRevEpoch ( 0 )
    , m_tRevApplied ( 0 )
    , m_nRevMaxStale ( 0 )
{
    std::memset ( m_aAuthority, 0, sizeof(m_aAuthority) );

    //  Every trust class gets the FULL link posture until an operator names
    //  one and relaxes it, so a hub configured against the tree as it was
    //  behaves byte for byte as it did. Zeroed rather than assigned per index:
    //  0 is P2PeerLinkPolicy_Full, and a fourth class added later inherits the
    //  strict default by existing rather than by being remembered here.
    std::memset ( m_aLinkPolicy, 0, sizeof(m_aLinkPolicy) );

    //  ...and no fence.  0 is P2PeerConTrust_Wire, which is the class every
    //  transport that has vouched for nothing answers, so a floor there
    //  refuses nothing - which is exactly what an unconfigured hub must do.
    m_nTrustFloor = 0;

    m_pAllow    = new AllowVec   ( );
    m_pSealReaders = new ReaderVec ( );
    m_pSeen     = new SeenVec    ( );
    m_pSeenRel  = new SeenSigVec ( );
    m_pSeenSeal = new SeenSigVec ( );
    m_pRevoked  = new RevVec     ( );
}

AuthPolicy::~AuthPolicy ( )
{
    delete m_pIdentity;
    delete m_pAgreement;
    delete Allow  ( m_pAllow );
    delete Seen   ( m_pSeen  );
    delete SeenRel( m_pSeenRel );
    delete SeenRel( m_pSeenSeal );
    delete Revs   ( m_pRevoked );
    delete Readers( m_pSealReaders );
    if ( m_pszAllowPath )  std::free ( m_pszAllowPath );
    if ( m_pszRevokePath ) std::free ( m_pszRevokePath );
}

p2pcng::IdResult
AuthPolicy::SetIdentity ( const char *pszPathUtf8, bool bCreate,
                          p2pcng::IdProtection eProtect )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 ) return p2pcng::IdErrArgs;

    EcdsaP256 *pKey = new EcdsaP256 ( );
    p2pcng::IdResult eResult = bCreate
        ? p2pcng::LoadOrCreateIdentity ( pszPathUtf8, *pKey, nullptr, eProtect )
        : p2pcng::LoadIdentity         ( pszPathUtf8, *pKey );

    if ( eResult != p2pcng::IdOk )
    {
        delete pKey;
        return eResult;
    }

    //  Refuse to arm with a key that is already revoked. Unlike the check in
    //  SetRevocationList, this one does not install: there is no reason to hold
    //  a key we have just established nobody will accept, and leaving it unset
    //  makes the follow-on failure "no identity" rather than a mystery.
    unsigned char selfPub[kEcdsaPubLen];
    if ( pKey->ExportPublic ( selfPub ) && IsRevokedPoint ( selfPub ) )
    {
        delete pKey;
        return p2pcng::IdErrRevoked;
    }

    delete m_pIdentity;
    m_pIdentity     = pKey;
    m_bHaveIdentity = true;
    return p2pcng::IdOk;
}

p2pcng::IdResult
AuthPolicy::SetAllowList ( const char *pszPathUtf8 )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 ) return p2pcng::IdErrArgs;

    if ( m_pszAllowPath ) std::free ( m_pszAllowPath );
    size_t cb = std::strlen ( pszPathUtf8 ) + 1;
    m_pszAllowPath = (char *)std::malloc ( cb );
    if ( !m_pszAllowPath ) return p2pcng::IdErrIo;
    std::memcpy ( m_pszAllowPath, pszPathUtf8, cb );

    return ReloadAllowList ( );
}

p2pcng::IdResult
AuthPolicy::ReloadAllowList ( )
{
    if ( !m_pszAllowPath ) return p2pcng::IdErrArgs;

    //  Built to the side and swapped in only on success, so a bad edit to the
    //  file leaves the hub running on the list it already validated rather
    //  than on a half-loaded one.
    AllowVec  vNew;
    AllowLoad oLoad;
    oLoad.pVec = &vNew;
    oLoad.bBad = false;

    //  m_bAllowUsable tracks THIS load, not the list currently in force, and
    //  the two differ on purpose. A failed reload leaves the previously
    //  validated list in memory - the whole reason it is built to the side -
    //  so the hub keeps working on what it already had. But it must not go on
    //  claiming it is provisioned: a hub whose allow-list has been deleted is
    //  one restart away from having nothing, and Arm() is what says so.
    p2pcng::IdResult eResult =
        p2pcng::LoadAllowList ( m_pszAllowPath, AllowSink, &oLoad );
    if ( eResult != p2pcng::IdOk ) { m_bAllowUsable = false; return eResult; }
    if ( oLoad.bBad )              { m_bAllowUsable = false; return p2pcng::IdErrFormat; }

    Allow ( m_pAllow )->swap ( vNew );
    m_bAllowUsable = true;
    return p2pcng::IdOk;
}

//
//  Can this policy enforce what it is set to require?
//  NOTES: Stage 3 step 8. Order matters and is the order an
//         operator has to do the work in: there is no point naming an empty
//         allow-list to someone who has not generated a key yet.
//       : Identity first because it is the one file this library can create
//         for the operator (P2PeerHub::ProvisionAuth), and the allow-list is
//         the one it cannot - who to trust is not a thing software knows.
//
ArmResult
AuthPolicy::Arm ( ) const
{
    if ( !m_bRequired )      return ArmNotRequired;

    //  ...and the second way to have nothing to enforce, which unlike the
    //  first is arrived at rather than declared.  A hub that has fenced out
    //  every class it will not carry and opened every class it will can never
    //  demand a signature, so the files it would demand one WITH are files it
    //  will never open.  Refer ArmNotRequiredByPolicy for why this passes the
    //  same test SetRequired(false) passes.
    //
    //  ASKED BEFORE THE PROVISIONING CHECKS AND NOT AFTER, because the whole
    //  point is a hub that holds none of those files.  Asked after
    //  m_bRequired, because a hub that turned auth off outright has already
    //  said so in the one place an operator and a posture reader both look.
    if ( LinkPolicyOpensAllHeld ( ) ) return ArmNotRequiredByPolicy;

    if ( !m_bHaveIdentity )  return ArmNoIdentity;
    if ( !m_pszAllowPath )   return ArmNoAllowList;
    if ( !m_bAllowUsable )   return ArmAllowUnusable;
    if ( AllowCount ( ) == 0 ) return ArmEmptyAllow;

    //  Revocation last, because the order is the order the operator works in
    //  and there is no point asking who to distrust before there is anybody
    //  to trust.
    //
    //  m_bRevokeUsable and NOT IsRevocationUsable(), which folds in staleness
    //  as well. Deliberate: a hub with a maximum staleness set is stale from
    //  startup until its first list ARRIVES, so gating on the folded
    //  predicate would refuse to start every hub configured for distribution
    //  - turning a partition into an outage at the one moment there is not
    //  yet anything to be partitioned from. Staleness is a running-state
    //  refusal and stays one; this is a provisioning check.
    if ( m_bRevokeConfigured && !m_bRevokeUsable ) return ArmRevocationUnusable;
    if ( m_bRevokeRequired && !m_bRevokeConfigured ) return ArmNoRevocation;

    //  SEALING IS DELIBERATELY NOT ASKED ABOUT HERE. See the note at the end
    //  of ArmResult: a hub that requires sealing and holds no agreement key
    //  refuses a shape of traffic rather than all of it, and a relay
    //  legitimately holds no keys at all.
    return ArmOk;
}

//
//  Render an ArmResult
//  NOTES: Exported for the same reason AuthResultText is - an out-of-tree
//         caller handed one of these has no other way to name it.
//       : Phrased as what to DO, not as what is wrong. The caller pairs it
//         with AllowListPath() when there is a path to name.
//       : KEPT SHORT ON PURPOSE, and the limit is not a style preference.
//         P2Pevent::Message and ::Advice both VERIFY that the FORMATTED
//         result is under 255 characters (Msgcore/Msgexception.cpp), which in
//         a Debug build is an abort and in a Release build is silence. The
//         first draft of these strings was ~90 characters each; with a hub
//         address in front and a temp path behind, the arming refusal aborted
//         the process it was trying to explain. Anything added here has to
//         leave room for both.
//
const char *
AuthArmText ( ArmResult eResult )
{
    switch ( eResult )
    {
      case ArmOk:            return "armed - identity loaded, allow-list has peers";
      case ArmNotRequired:   return "armed - auth not required";
      case ArmNoIdentity:    return "no identity key - SetIdentity(path,true) or ProvisionAuth()";
      case ArmNoAllowList:   return "no allow-list - SetAllowList(path) names who may log in";
      case ArmAllowUnusable: return "allow-list unreadable - missing, or a line that will not parse";
      case ArmEmptyAllow:    return "allow-list names nobody - this hub would refuse every peer";
      case ArmNoRevocation:  return "no revocation list - SetRevocationList(path), or RequireRevocation(false)";
      case ArmRevocationUnusable: return "revocation list unreadable - missing, or a line that will not parse";
      case ArmNotRequiredByPolicy: return "armed - every class this hub will hold is open";
    }
    return "unknown arm result";
}

void AuthPolicy::SetWindow   ( int nSeconds ) { m_nWindow  = nSeconds < 0 ? 0 : nSeconds; }
void AuthPolicy::SetRequired ( bool bRequire ) { m_bRequired = bRequire; }

//  What a link of the given trust class must do - refer the header.
//  NOTES: An out-of-range class is IGNORED rather than clamped. Clamping would
//         write a relaxation onto whichever class happened to sit at the
//         boundary, and a caller passing a class this build does not have is
//         asking about something that cannot reach the gate anyway
//       : Class 0 - the wire - is refused, silently and by design. It is not
//         an error a caller can do anything about beyond not making the call:
//         a wire is what every transport that has vouched for nothing answers,
//         so opening it would relax the whole tree through a call that reads
//         as though it named one kind of link. RequireAuth(false) is the way
//         to open a wire, it is hub-wide, and both the posture and the arming
//         gate already report it
//       : Anything that is not "full" is stored as "open". There are two
//         states and there is no third to fall into
void AuthPolicy::SetLinkPolicy ( int nTrustClass, int nPolicy )
{
    if ( nTrustClass <= 0 ||
         nTrustClass >= (int)( sizeof(m_aLinkPolicy) / sizeof(m_aLinkPolicy[0]) ) )
      return;
    m_aLinkPolicy[nTrustClass] = (unsigned char)( nPolicy == 0 ? 0 : 1 );
}

//  ...and what it is now.
//  NOTES: An out-of-range class answers 0 - full - which is the fail-closed
//         reading and the same answer the wire gets. A policy that cannot see
//         its subject demands everything of it
int AuthPolicy::GetLinkPolicy ( int nTrustClass ) const
{
    if ( nTrustClass < 0 ||
         nTrustClass >= (int)( sizeof(m_aLinkPolicy) / sizeof(m_aLinkPolicy[0]) ) )
      return 0;
    return (int)m_aLinkPolicy[nTrustClass];
}

//  The lowest class this hub will hold a link of - refer the header.
//  NOTES: Out of range is IGNORED, as SetLinkPolicy ignores it, and for the
//         same reason: a caller naming a class this build does not have is
//         asking about something that cannot reach the gate anyway.  Clamping
//         would fence on whichever class happened to sit at the boundary,
//         which is a policy nobody asked for
//       : Class 0 IS accepted here, unlike SetLinkPolicy, and the asymmetry is
//         deliberate.  0 is "no fence" - it is the value the constructor sets
//         and the one an operator uses to say they do not want one.  Refusing
//         it would leave the default unreachable by name
//       : It is a plain assignment and not a max().  A fence is a statement
//         about what this hub is FOR, made once before it arms, alongside the
//         other settings in the same block; a hub that raises it and then
//         lowers it has changed its mind, not lost a guarantee, because
//         nothing below the old floor was ever admitted while it stood.  That
//         is the opposite of P2PeerCon::DemoteTrust, which only tightens
//         because it is per-object state that AcceptSpawn carries onward
void AuthPolicy::SetTrustFloor ( int nTrustClass )
{
    if ( nTrustClass < 0 ||
         nTrustClass >= (int)( sizeof(m_aLinkPolicy) / sizeof(m_aLinkPolicy[0]) ) )
      return;
    m_nTrustFloor = (unsigned char)nTrustClass;
}

int AuthPolicy::GetTrustFloor ( ) const
{
    return (int)m_nTrustFloor;
}

//  Can this policy ever demand a signature from anybody?
//  NOTES: Two halves and BOTH are needed.  Without a floor there is no class
//         this hub refuses to hold, so a link of a class it never opened can
//         arrive at the next PostP2PeerCon - "everything I hold is open" is
//         then not a property, it is a coincidence with a deadline
//       : The loop starts AT the floor rather than at 1, so a floor of 0 asks
//         about the wire, m_aLinkPolicy[0] is pinned Full, and the answer is
//         false.  That is the no-fence case falling out of the arithmetic
//         rather than out of a second test that could disagree with the first
bool AuthPolicy::LinkPolicyOpensAllHeld ( ) const
{
    if ( m_nTrustFloor == 0 )
      return false;
    const int nClasses = (int)( sizeof(m_aLinkPolicy) / sizeof(m_aLinkPolicy[0]) );
    for ( int i = (int)m_nTrustFloor; i < nClasses; ++i )
      if ( m_aLinkPolicy[i] == 0 )
        return false;
    return true;
}

void AuthPolicy::SetRelayRequired ( bool bRequire ) { m_bRelayRequired = bRequire; }
//  Intent only. It never reaches a verification path - a configured list is
//  loaded, enforced and fails closed whatever this says - so turning it off
//  cannot weaken a hub that HAS revocation, only permit one that has none.
void AuthPolicy::SetRevocationRequired ( bool bRequire ) { m_bRevokeRequired = bRequire; }
//  Intent only, like the two above it. It decides whether the SEND path seals
//  by itself; SealFor() works either way, and a hub that turns this off has
//  not turned sealing off, only the automatic use of it.
void AuthPolicy::SetSealRequired ( bool bRequire ) { m_bSealRequired = bRequire; }
//  Independent of the switch above and deliberately so. Turning this off does
//  not weaken relayed unicast by one byte, and turning the one above off makes
//  this one moot - there is no ordering to get wrong.
void AuthPolicy::SetSealBroadcastRequired ( bool bRequire )
                                          { m_bSealBroadcastRequired = bRequire; }
//  Turning the refusal OFF does not empty the cache. Nothing reads it while
//  the switch is off, and keeping it means a hub toggled off and on again does
//  not hand an attacker a window in which everything it captured is fresh.
void AuthPolicy::SetRelayReplayRefused ( bool bRefuse ) { m_bRelayReplay = bRefuse; }
void AuthPolicy::SetSealReplayRefused  ( bool bRefuse ) { m_bSealReplay  = bRefuse; }
//  Negative is nonsense rather than "very short", and clamping to 0 would
//  silently DISABLE the check - so it clamps to 0 explicitly and the header
//  says 0 means disabled, rather than leaving a caller to discover that a
//  typo'd -1 turned freshness off.
void AuthPolicy::SetSealWindow ( int nSeconds ) { m_nSealWindow = nSeconds < 0 ? 0 : nSeconds; }

size_t AuthPolicy::AllowCount ( ) const
{
    return Allow ( m_pAllow )->size ( );
}

// -----------------------------------------------------------------------
//  Revocation
// -----------------------------------------------------------------------
namespace
{
    void RevokeSink ( void *pCtx, const unsigned char *pPoint, long long )
    {
        RevPoint oEntry;
        std::memcpy ( oEntry.p, pPoint, p2pcng::kIdRevokePointLen );
        ( (RevVec *)pCtx )->push_back ( oEntry );
    }
}

p2pcng::IdResult
AuthPolicy::SetRevocationList ( const char *pszPathUtf8 )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 ) return p2pcng::IdErrArgs;

    if ( m_pszRevokePath ) std::free ( m_pszRevokePath );
    size_t cb = std::strlen ( pszPathUtf8 ) + 1;
    m_pszRevokePath = (char *)std::malloc ( cb );
    if ( !m_pszRevokePath )
    {
        //  Configured but unloadable, which is precisely the fail-closed state.
        //  Marking it here rather than returning quietly means an ignored error
        //  refuses logins instead of running with revocation silently off.
        m_bRevokeConfigured = true;
        m_bRevokeUsable     = false;
        return p2pcng::IdErrIo;
    }
    std::memcpy ( m_pszRevokePath, pszPathUtf8, cb );
    m_bRevokeConfigured = true;

    return ReloadRevocationList ( );
}

p2pcng::IdResult
AuthPolicy::ReloadRevocationList ( )
{
    if ( !m_pszRevokePath ) return p2pcng::IdErrArgs;

    //  Built to the side and swapped in only on success, as ReloadAllowList
    //  does - but the failure branch is the opposite one. A bad allow-list edit
    //  leaves the previously validated list running, which is safe because that
    //  list only GRANTS. A bad revocation edit cannot leave the old list
    //  running and call that safe: the file may have been truncated by the very
    //  thing being defended against. So a failure disarms into refuse-all.
    RevVec vNew;
    p2pcng::IdResult eResult =
        p2pcng::LoadRevocationList ( m_pszRevokePath, RevokeSink, &vNew );
    if ( eResult != p2pcng::IdOk )
    {
        m_bRevokeUsable = false;
        return eResult;
    }

    Revs ( m_pRevoked )->swap ( vNew );
    m_bRevokeUsable = true;

    //  Reported last, and it does NOT undo the load: the list is in force
    //  either way. See the header - this says "do not start", not "ignore me".
    if ( SelfKeyRevoked ( ) ) return p2pcng::IdErrRevoked;
    return p2pcng::IdOk;
}

size_t AuthPolicy::RevokedCount ( ) const
{
    return Revs ( m_pRevoked )->size ( );
}

// ---- Revocation distribution ----------------------------------------------

const char *RevResultText ( RevResult eResult )
{
    switch ( eResult )
    {
        case RevOk:             return "ok";
        case RevErrArgs:        return "bad arguments";
        case RevErrFormat:      return "not a revocation list block";
        case RevErrVersion:     return "unsupported revocation list version";
        case RevErrNoAuthority: return "no revocation authority configured";
        case RevErrIssuer:      return "not signed by the configured authority";
        case RevErrSignature:   return "revocation list signature did not verify";
        case RevErrStale:       return "revocation list epoch is not newer";
        case RevErrNoIdentity:  return "no identity to sign a revocation list with";
        case RevErrNoList:      return "no revocation list file configured";
        case RevErrInternal:    return "internal error";
    }
    return "unknown";
}

p2pcng::IdResult
AuthPolicy::SetRevocationAuthority ( const unsigned char *pIssuerPub )
{
    if ( !pIssuerPub )
    {
        std::memset ( m_aAuthority, 0, sizeof(m_aAuthority) );
        m_bHaveAuthority = false;
        return p2pcng::IdOk;
    }

    //  Checked before it is stored, not after. Naming a revoked key as the one
    //  key allowed to withdraw trust is exactly the mistake this should catch
    //  at configuration time rather than at the first list that arrives.
    //
    //  The MEMBERSHIP question, deliberately, not the policy one. IsRevokedPoint
    //  fails closed - it answers true for EVERY point while the list is unusable
    //  or past its staleness limit - and asking it here would mean a hub in
    //  either of those states cannot name a new authority, because the perfectly
    //  good key it is being handed reads back as revoked. That is precisely the
    //  moment an operator needs to rotate: the stale hub has to be able to name
    //  someone who will feed it, and the hub whose file will not load has to be
    //  able to name someone who will replace it. IdErrRevoked would also be a
    //  lie about a key that is on no list at all. Same distinction, and the same
    //  reason, as the merge in ApplyRevocationList - refer IsRevokedPointRaw.
    if ( IsRevokedPointRaw ( pIssuerPub ) ) return p2pcng::IdErrRevoked;

    //  It must at least be a point, or every list from it fails at import and
    //  the operator learns about a typo from a silence.
    {
        p2pcng::EcdsaP256 oTest;
        if ( !oTest.ImportPublic ( pIssuerPub ) ) return p2pcng::IdErrKey;
    }

    std::memcpy ( m_aAuthority, pIssuerPub, sizeof(m_aAuthority) );
    m_bHaveAuthority = true;
    return p2pcng::IdOk;
}

void AuthPolicy::SetMaxRevocationStaleness ( int nSeconds )
{
    m_nRevMaxStale = nSeconds < 0 ? 0 : nSeconds;
}

bool AuthPolicy::AddRevokedPoint ( const unsigned char *pPoint, long long llAt )
{
    //  Durable first. If the append fails the in-memory set is left alone, so
    //  the hub's answer to "is this revoked" is the same before and after a
    //  restart - a yes that a restart turns back into a no is worse than a
    //  refusal to apply, because nobody looks again.
    if ( !m_pszRevokePath ) return false;
    if ( p2pcng::AppendRevocationList ( m_pszRevokePath, pPoint, llAt,
                                        "distributed" ) != p2pcng::IdOk )
        return false;

    RevPoint rp;
    std::memcpy ( rp.p, pPoint, p2pcng::kIdRevokePointLen );
    Revs ( m_pRevoked )->push_back ( rp );
    return true;
}

RevResult
AuthPolicy::IssueRevocationList ( long long llEpoch,
                                  unsigned char *pOut, size_t cbOut,
                                  size_t *pcbOut )
{
    if ( !pOut || !pcbOut ) return RevErrArgs;
    if ( !m_bHaveIdentity || !m_pIdentity ) return RevErrNoIdentity;
    if ( !m_bRevokeConfigured )             return RevErrNoList;

    const RevVec *pVec  = Revs ( m_pRevoked );
    const size_t  nCount = pVec->size ( );
    if ( nCount > kRevMaxEntries ) return RevErrInternal;

    const size_t cbBlock = RevListLen ( nCount );
    if ( cbOut < cbBlock ) return RevErrArgs;

    //  0 means "use the count", which is monotonic while the list only grows -
    //  and growing is the only way it is meant to change. An operator who edits
    //  a line out by hand has to pass an epoch explicitly, which is the right
    //  amount of friction for the one edit that widens trust.
    const long long llUse = llEpoch != 0 ? llEpoch : (long long)nCount;

    std::memset ( pOut, 0, cbBlock );
    pOut[0] = kRevMagic0;
    pOut[1] = kRevMagic1;
    pOut[2] = kRevVersion;
    PutI64 ( pOut + kOffRevEpoch, llUse );
    pOut[kOffRevCount    ] = (unsigned char)( ( nCount >> 8 ) & 0xFF );
    pOut[kOffRevCount + 1] = (unsigned char)(   nCount        & 0xFF );

    for ( size_t i = 0; i < nCount; i++ )
    {
        unsigned char *pE = pOut + kOffRevEntries + i * kRevEntryLen;
        std::memcpy ( pE, (*pVec)[i].p, p2pcng::kIdRevokePointLen );
        //  The in-memory set does not carry the epoch column - it never needed
        //  it, because revocation is absolute and the column is for humans. It
        //  is republished as 0, which the file format already defines as "not
        //  recorded" rather than "revoked at the epoch".
        PutI64 ( pE + kRevPointLen, 0 );
    }

    if ( !m_pIdentity->ExportPublic ( pOut + OffRevIssuer ( nCount ) ) )
        return RevErrInternal;

    std::string sTr;
    if ( !RevListTranscript ( llUse, nCount, pOut + kOffRevEntries,
                              pOut + OffRevIssuer ( nCount ), sTr ) )
        return RevErrInternal;

    if ( !m_pIdentity->Sign ( (const unsigned char *)sTr.data ( ), sTr.size ( ),
                              pOut + OffRevSig ( nCount ) ) )
        return RevErrInternal;

    *pcbOut = cbBlock;
    return RevOk;
}

RevResult
AuthPolicy::ApplyRevocationList ( const unsigned char *pIn, size_t cbIn,
                                  size_t *pnAdded )
{
    if ( pnAdded ) *pnAdded = 0;
    if ( !pIn ) return RevErrArgs;

    //  Shape before anything else, and the count is validated against the
    //  actual length BEFORE it is used to address the issuer and signature.
    //  A declared count that the buffer cannot hold would otherwise read them
    //  from past the end.
    if ( cbIn < kRevFixedLen ) return RevErrFormat;
    if ( pIn[0] != kRevMagic0 || pIn[1] != kRevMagic1 ) return RevErrFormat;
    if ( pIn[2] != kRevVersion ) return RevErrVersion;

    const size_t nCount = ( (size_t)pIn[kOffRevCount] << 8 ) | pIn[kOffRevCount + 1];
    if ( nCount > kRevMaxEntries )   return RevErrFormat;
    if ( cbIn != RevListLen ( nCount ) ) return RevErrFormat;

    if ( !m_bHaveAuthority ) return RevErrNoAuthority;
    //  Somewhere to put it, checked before the crypto: a hub that would have to
    //  forget this at the next restart should not apply it at all.
    if ( !m_bRevokeConfigured || !m_pszRevokePath ) return RevErrNoList;

    const unsigned char *pIssuer = pIn + OffRevIssuer ( nCount );

    //  Whose list is this? Answered by comparing the point, not by trying keys.
    //  A list from a perfectly valid signer that is not THIS hub's authority is
    //  not a weaker list, it is someone else's, and treating it as an attack on
    //  the signature would send an operator to look at the wrong thing.
    if ( std::memcmp ( pIssuer, m_aAuthority, sizeof(m_aAuthority) ) != 0 )
        return RevErrIssuer;

    const long long llEpoch = GetI64 ( pIn + kOffRevEpoch );

    std::string sTr;
    if ( !RevListTranscript ( llEpoch, nCount, pIn + kOffRevEntries, pIssuer, sTr ) )
        return RevErrInternal;

    {
        p2pcng::EcdsaP256 oIss;
        if ( !oIss.ImportPublic ( pIssuer ) ) return RevErrInternal;
        if ( !oIss.Verify ( (const unsigned char *)sTr.data ( ), sTr.size ( ),
                            pIn + OffRevSig ( nCount ) ) )
            return RevErrSignature;
    }

    //  Only now, with the signature good, is the epoch worth reading. Checking
    //  it earlier would let an unsigned block move this hub's high-water mark
    //  and lock out the real list that follows.
    if ( llEpoch <= m_llRevEpoch ) return RevErrStale;

    size_t nAdded = 0;
    for ( size_t i = 0; i < nCount; i++ )
    {
        const unsigned char *pE = pIn + kOffRevEntries + i * kRevEntryLen;
        if ( IsRevokedPointRaw ( pE ) ) continue;       // union: already known
        if ( !AddRevokedPoint ( pE, GetI64 ( pE + kRevPointLen ) ) )
        {
            //  Could not be made durable. What was added before this point
            //  stays added - it is on disk and in memory, and un-adding a
            //  revocation to tidy up a failure would be the one rollback this
            //  design refuses to perform.
            m_bRevokeUsable = false;
            return RevErrInternal;
        }
        nAdded++;
    }

    m_llRevEpoch  = llEpoch;
    m_tRevApplied = std::time ( nullptr );
    if ( pnAdded ) *pnAdded = nAdded;

    //  Did this list revoke the authority that signed it? Checked after the
    //  apply, because the entry has to take effect like any other before the
    //  hub stops listening to its source.
    if ( IsRevokedPointRaw ( m_aAuthority ) )
    {
        std::memset ( m_aAuthority, 0, sizeof(m_aAuthority) );
        m_bHaveAuthority = false;
    }

    return RevOk;
}

bool AuthPolicy::IsRevocationFresh ( ) const
{
    //  Only ever false for a hub that opted into expiry AND expects to be fed:
    //  with no authority there is nothing to be stale RELATIVE TO, and a purely
    //  file-driven deployment must not start refusing because a knob it never
    //  uses defaulted to something.
    if ( m_nRevMaxStale <= 0 || !m_bHaveAuthority ) return true;

    //  No list applied yet counts as stale, deliberately - see the header. The
    //  alternative reads "trust indefinitely until the first list arrives",
    //  which is the exact window an attacker would hold open.
    if ( m_tRevApplied == 0 ) return false;

    const time_t tNow = std::time ( nullptr );
    //  A clock that went backwards leaves the difference negative, which is
    //  fresh. Refusing on it would make a time step a self-inflicted outage,
    //  and staleness is not a security boundary that a backwards clock helps
    //  an attacker cross - going FORWARD is what expires things, and that
    //  direction still works.
    if ( tNow < m_tRevApplied ) return true;
    return ( tNow - m_tRevApplied ) <= (time_t)m_nRevMaxStale;
}

bool AuthPolicy::IsRevocationUsable ( ) const
{
    if ( !m_bRevokeConfigured ) return true;
    return m_bRevokeUsable && IsRevocationFresh ( );
}

bool AuthPolicy::IsRevokedPointRaw ( const unsigned char *pPoint ) const
{
    if ( !pPoint ) return false;
    const RevVec *pVec = Revs ( m_pRevoked );
    for ( size_t i = 0; i < pVec->size ( ); i++ )
        if ( std::memcmp ( (*pVec)[i].p, pPoint,
                           p2pcng::kIdRevokePointLen ) == 0 )
            return true;
    return false;
}

bool AuthPolicy::IsRevokedPoint ( const unsigned char *pPoint ) const
{
    if ( !pPoint || !m_bRevokeConfigured ) return false;
    //  Unusable list => treat every key as revoked. Every caller already has to
    //  handle "revoked", so failing closed needs no extra path at any call site.
    //  Stale-past-the-limit takes the same path for the same reason: the
    //  operator asked to refuse rather than run on old knowledge, and that has
    //  to mean the same thing here as it does at IsRevocationUsable.
    if ( !m_bRevokeUsable || !IsRevocationFresh ( ) ) return true;

    const RevVec *pVec = Revs ( m_pRevoked );
    for ( size_t i = 0; i < pVec->size ( ); i++ )
        if ( std::memcmp ( (*pVec)[i].p, pPoint,
                           p2pcng::kIdRevokePointLen ) == 0 )
            return true;
    return false;
}

bool AuthPolicy::SelfKeyRevoked ( ) const
{
    if ( !m_bRevokeConfigured || !m_bRevokeUsable ) return false;

    if ( m_bHaveIdentity && m_pIdentity )
    {
        unsigned char pub[kEcdsaPubLen];
        if ( m_pIdentity->ExportPublic ( pub ) && IsRevokedPoint ( pub ) )
            return true;
    }
    if ( m_bHaveAgreement && m_pAgreement )
    {
        unsigned char pub[kEcdhPubLen];
        if ( m_pAgreement->ExportPublic ( pub ) && IsRevokedPoint ( pub ) )
            return true;
    }
    return false;
}

// -----------------------------------------------------------------------
//  Allow-list lookups - every key for an address, not just the first
// -----------------------------------------------------------------------
bool AuthPolicy::PeerKeyAt ( const wchar_t *pAddr, size_t nIndex,
                             unsigned char *pPubOut )
{
    if ( !pAddr || !pPubOut ) return false;

    std::string sAddr;
    if ( !Utf8FromWide ( pAddr, sAddr ) ) return false;

    const AllowVec *pVec = Allow ( m_pAllow );
    size_t nSeen = 0;
    for ( size_t i = 0; i < pVec->size ( ); i++ )
    {
        //  Exact match. A P2Paddr comparison elsewhere in the library is
        //  pattern-based; an allow-list entry is not a pattern and must not
        //  become one by accident - "AuthPsk.*" as an identity would otherwise
        //  admit the whole domain, which is the hole this file closes.
        if ( (*pVec)[i].sIdentity != sAddr ) continue;
        if ( IsRevokedPoint ( (*pVec)[i].pub ) ) continue;
        if ( nSeen++ != nIndex ) continue;
        std::memcpy ( pPubOut, (*pVec)[i].pub, kEcdsaPubLen );
        return true;
    }
    return false;
}

size_t AuthPolicy::PeerKeyCount ( const wchar_t *pAddr, bool *pbAllRevoked )
{
    if ( pbAllRevoked ) *pbAllRevoked = false;
    if ( !pAddr ) return 0;

    std::string sAddr;
    if ( !Utf8FromWide ( pAddr, sAddr ) ) return 0;

    const AllowVec *pVec = Allow ( m_pAllow );
    size_t nListed = 0, nLive = 0;
    for ( size_t i = 0; i < pVec->size ( ); i++ )
    {
        if ( (*pVec)[i].sIdentity != sAddr ) continue;
        nListed++;
        if ( !IsRevokedPoint ( (*pVec)[i].pub ) ) nLive++;
    }
    //  Listed but nothing usable is a DIFFERENT operator problem from never
    //  having been listed - one is a key that was withdrawn, the other is a
    //  peer that was never provisioned - so the caller gets to tell them apart.
    if ( pbAllRevoked ) *pbAllRevoked = ( nListed > 0 && nLive == 0 );
    return nLive;
}

AuthResult
AuthPolicy::VerifyAgainstPeer ( const wchar_t *pAddr,
                                const unsigned char *pTr, size_t cbTr,
                                const unsigned char *pSig )
{
    bool   bAllRevoked = false;
    size_t nLive       = PeerKeyCount ( pAddr, &bAllRevoked );

    //  Order matters and is the same as it always was: "I do not know you" and
    //  "your key was withdrawn" are both settled before any signature maths, so
    //  neither is reachable by guessing at signatures.
    if ( bAllRevoked ) return AuthErrRevoked;
    if ( nLive == 0 )  return AuthErrUnknownPeer;

    unsigned char pub[kEcdsaPubLen];
    for ( size_t i = 0; i < nLive; i++ )
    {
        if ( !PeerKeyAt ( pAddr, i, pub ) ) break;
        EcdsaP256 oPeer;
        if ( !oPeer.ImportPublic ( pub ) ) return AuthErrInternal;
        if ( oPeer.Verify ( pTr, cbTr, pSig ) ) return AuthOk;
    }
    //  Every listed key was tried and none of them signed this. During a
    //  rollover that is still just a bad signature - there is no "wrong key of
    //  the two" outcome to report, because both were the peer's own.
    return AuthErrSignature;
}

bool AuthPolicy::FindPeer ( const wchar_t *pAddr, unsigned char *pPubOut )
{
    return PeerKeyAt ( pAddr, 0, pPubOut );
}

// -----------------------------------------------------------------------
//  End-to-end sealing
// -----------------------------------------------------------------------
p2pcng::IdResult
AuthPolicy::SetAgreement ( const char *pszPathUtf8, bool bCreate,
                           p2pcng::IdProtection eProtect )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 ) return p2pcng::IdErrArgs;

    p2pcng::EcdhP256 *pKey = new p2pcng::EcdhP256 ( );
    p2pcng::IdResult eResult = bCreate
        ? p2pcng::LoadOrCreateAgreement ( pszPathUtf8, *pKey, nullptr, eProtect )
        : p2pcng::LoadAgreement         ( pszPathUtf8, *pKey );

    if ( eResult != p2pcng::IdOk )
    {
        //  The old key is kept on failure, exactly as SetIdentity does: a
        //  mistyped path at reconfiguration must not silently disarm a peer
        //  that was working.
        delete pKey;
        return eResult;
    }

    //  Same refusal as SetIdentity: a revoked agreement key is one nobody will
    //  seal to, so arming with it only delays the discovery.
    unsigned char selfPub[kEcdhPubLen];
    if ( pKey->ExportPublic ( selfPub ) && IsRevokedPoint ( selfPub ) )
    {
        delete pKey;
        return p2pcng::IdErrRevoked;
    }

    delete m_pAgreement;
    m_pAgreement     = pKey;
    m_bHaveAgreement = true;
    return p2pcng::IdOk;
}

bool AuthPolicy::GetAgreementPublic ( unsigned char *pOut )
{
    if ( !pOut || !m_bHaveAgreement || !m_pAgreement ) return false;
    return m_pAgreement->ExportPublic ( pOut );
}

p2pcng::IdResult
AuthPolicy::AddSealReader ( const wchar_t *pAddr )
{
    if ( !pAddr || !*pAddr ) return p2pcng::IdErrArgs;

    ReaderVec *pVec = Readers ( m_pSealReaders );
    if ( !pVec ) return p2pcng::IdErrArgs;

    //  One slot is the destination's, so the configured list can hold at most
    //  kSealMaxReaders - 1. Refused here rather than at seal time, because a
    //  configuration error found at startup is worth more than the same error
    //  found on the first relayed message.
    if ( pVec->size ( ) + 1 >= p2pseal::kSealMaxReaders )
        return p2pcng::IdErrFormat;

    //  Duplicates refused for the reason p2pseal::SealTo refuses them: naming
    //  a reader twice costs a slot and an ECDH and means nothing.
    for ( size_t i = 0; i < pVec->size ( ); i++ )
        if ( (*pVec)[i] == pAddr ) return p2pcng::IdErrFormat;

    pVec->push_back ( pAddr );
    return p2pcng::IdOk;
}

void
AuthPolicy::ClearSealReaders ( )
{
    ReaderVec *pVec = Readers ( m_pSealReaders );
    if ( pVec ) pVec->clear ( );
}

size_t
AuthPolicy::SealReaderCount ( ) const
{
    const ReaderVec *pVec = Readers ( m_pSealReaders );
    return pVec ? pVec->size ( ) : 0;
}

p2pseal::SealResult
AuthPolicy::Seal ( const wchar_t *pSrc, const wchar_t *pDst,
                   const void *pPlain, size_t cbPlain,
                   unsigned char *pOut, size_t cbOut, size_t *pcbOut,
                   long long llWhen )
{
    if ( !pSrc || !pDst ) return p2pseal::SealErrArgs;
    if ( !m_bHaveIdentity || !m_pIdentity ) return p2pseal::SealErrNoIdentity;

    //  The destination's agreement key comes from the allow-list and nowhere
    //  else. If it is not there we refuse - there is deliberately no path here
    //  that sends the body in clear because the directory was incomplete.
    unsigned char agree[kEcdhPubLen];
    if ( !FindAgreement ( pDst, agree ) )
    {
        //  Separate the two reasons FindAgreement can say no. A key that was
        //  revoked is an operator decision that has taken effect; a key that
        //  was never published is a provisioning gap. Reporting both as
        //  "no agreement key" would send someone to fix the wrong file.
        if ( !IsRevocationUsable ( ) ) return p2pseal::SealErrRevoked;
        bool bAllRevoked = false;
        PeerKeyCount ( pDst, &bAllRevoked );
        if ( bAllRevoked ) return p2pseal::SealErrRevoked;
        return p2pseal::SealErrNoAgreement;
    }

    //  ---- the reader set -------------------------------------------------
    //  Slot 0 is the destination, always. The configured readers follow, in
    //  the order they were added, and every one of them must resolve NOW - a
    //  seal that quietly dropped a reader would produce a body the hub that
    //  needed it cannot open, for a reason nothing reports.
    unsigned char aReaders[p2pseal::kSealMaxReaders * kEcdhPubLen];
    size_t        nReaders = 0;

    std::memcpy ( aReaders, agree, kEcdhPubLen );
    nReaders = 1;

    const ReaderVec *pExtra = Readers ( m_pSealReaders );
    for ( size_t i = 0; pExtra && i < pExtra->size ( ); i++ )
    {
        const wchar_t *pName = (*pExtra)[i].c_str ( );

        //  A configured reader that IS the destination is not an error and not
        //  a duplicate slot: it is an operator naming a hub that happens to be
        //  where this message is going. Skipped, because p2pseal::SealTo
        //  refuses duplicates outright and this is the one duplicate that
        //  arises from a correct configuration rather than a mistaken one.
        unsigned char aOne[kEcdhPubLen];
        if ( !FindAgreement ( pName, aOne ) )
        {
            //  Same split as the destination above: withdrawn is an operator
            //  action, never published is a provisioning gap.
            if ( !IsRevocationUsable ( ) ) return p2pseal::SealErrRevoked;
            bool bGone = false;
            PeerKeyCount ( pName, &bGone );
            return bGone ? p2pseal::SealErrRevoked : p2pseal::SealErrNoAgreement;
        }

        bool bDup = false;
        for ( size_t k = 0; k < nReaders; k++ )
            if ( std::memcmp ( aReaders + k * kEcdhPubLen, aOne,
                               kEcdhPubLen ) == 0 )
            { bDup = true; break; }
        if ( bDup ) continue;

        if ( nReaders >= p2pseal::kSealMaxReaders )
            return p2pseal::SealErrReaders;

        std::memcpy ( aReaders + nReaders * kEcdhPubLen, aOne, kEcdhPubLen );
        nReaders++;
    }

    return p2pseal::SealTo ( *m_pIdentity, aReaders, nReaders, pSrc, pDst,
                             pPlain, cbPlain, pOut, cbOut, pcbOut, llWhen );
}

p2pseal::SealResult
AuthPolicy::Open ( const wchar_t *pSrc, const wchar_t *pDst,
                   const unsigned char *pIn, size_t cbIn,
                   void *pOut, size_t cbOut, size_t *pcbOut )
{
    if ( !pSrc || !pDst ) return p2pseal::SealErrArgs;
    if ( !m_bHaveAgreement || !m_pAgreement ) return p2pseal::SealErrNoAgreement;

    //  Whose signature we demand is decided by the address the message
    //  DECLARES, before anything in the body is believed. An unknown sender is
    //  refused for the same reason an unknown peer cannot log in.
    bool   bAllRevoked = false;
    size_t nLive       = PeerKeyCount ( pSrc, &bAllRevoked );
    if ( bAllRevoked )              return p2pseal::SealErrRevoked;
    if ( !IsRevocationUsable ( ) )  return p2pseal::SealErrRevoked;
    if ( nLive == 0 )               return p2pseal::SealErrNoIdentity;

    //  Every key the sender might have signed with is tried, which is what lets
    //  a body sealed just before a rollover still open just after it. The extra
    //  attempts cost a full Open each, so this is bounded by how many keys that
    //  ONE address has listed - one in steady state, two mid-rollover.
    p2pseal::SealResult eFirst = p2pseal::SealErrSignature;
    unsigned char sender[kEcdsaPubLen];
    for ( size_t i = 0; i < nLive; i++ )
    {
        if ( !PeerKeyAt ( pSrc, i, sender ) ) break;
        long long llWhen = 0;
        p2pseal::SealResult e = p2pseal::Open ( *m_pAgreement, sender, pSrc, pDst,
                                                pIn, cbIn, pOut, cbOut, pcbOut,
                                                &llWhen );
        if ( e == p2pseal::SealOk )
        {
            //  Everything below runs only for a body that actually OPENED - so
            //  a forged one cannot fill the cache, evict a real entry or move
            //  the floor, which is the same order VerifyRelay uses. The cost of
            //  deciding here rather than earlier is that the plaintext exists
            //  by the time a refusal is reached, so it is wiped rather than
            //  handed back: a caller that ignores the return value must not
            //  find the message sitting in its buffer.
            const unsigned char *pSig = pIn + cbIn - p2pseal::kSealSigLen;
            p2pseal::SealResult eRefuse = p2pseal::SealOk;

            //  FRESHNESS, and it is independent of the replay switch. The
            //  stamp is a property of the block; the cache is a thing this
            //  recipient remembers. Symmetric, because a clock ahead of ours is
            //  the same evidence as one behind it.
            if ( m_nSealWindow > 0 )
            {
                const long long llNow = (long long)std::time ( 0 );
                const long long llOff = llNow > llWhen ? llNow - llWhen
                                                       : llWhen - llNow;
                if ( llOff > (long long)m_nSealWindow )
                    eRefuse = p2pseal::SealErrStale;
            }

            if ( eRefuse == p2pseal::SealOk && m_bSealReplay )
            {
                //  The floor first. A body older than the newest entry the
                //  cache has had to evict is one this recipient can no longer
                //  say anything about, so it is refused rather than admitted -
                //  which is the whole of what closes the old count-eviction
                //  window. It reports SealErrReplay because that is what it is
                //  defending against; SealReplayFloor() is how a diagnostic
                //  tells this apart from an actual cache hit.
                //  STRICT. sealed_at has one-second resolution, so <= would
                //  refuse a body sealed in the same second as the evicted one -
                //  which under the burst that caused the eviction is ordinary
                //  live traffic, not a replay. The residual is stated rather
                //  than hidden: a body sealed in the SAME SECOND as the entry
                //  the cache last evicted can be replayed, and buying that
                //  costs an attacker kSeenMax genuinely sealed bodies through
                //  the same recipient inside that second. The old bound was
                //  "everything older than the last kSeenMax"; this one is one
                //  second wide.
                if ( m_llSealFloor && llWhen < m_llSealFloor )
                    eRefuse = p2pseal::SealErrReplay;
                else if ( SeenSealSig ( pSig ) )
                    eRefuse = p2pseal::SealErrReplay;
            }

            if ( eRefuse != p2pseal::SealOk )
            {
                if ( pOut )
                {
                    volatile unsigned char *pw = (volatile unsigned char *)pOut;
                    const size_t cbWipe = pcbOut && *pcbOut <= cbOut
                                        ? *pcbOut : cbOut;
                    for ( size_t k = 0; k < cbWipe; k++ ) pw[k] = 0;
                }
                if ( pcbOut ) *pcbOut = 0;
                return eRefuse;
            }

            if ( m_bSealReplay ) NoteSealSig ( pSig, llWhen );
            return e;
        }
        //  A signature failure is the only outcome another key could fix. Any
        //  other - malformed body, bad GCM tag, too small an output buffer - is
        //  a property of the body itself, so report the first one and stop
        //  rather than burn an Open per key on a message that cannot open.
        if ( e != p2pseal::SealErrSignature ) return e;
        if ( i == 0 ) eFirst = e;
    }
    return eFirst;
}

bool AuthPolicy::FindAgreement ( const wchar_t *pAddr, unsigned char *pAgreeOut )
{
    if ( !pAddr || !pAgreeOut ) return false;

    std::string sAddr;
    if ( !Utf8FromWide ( pAddr, sAddr ) ) return false;

    const AllowVec *pVec = Allow ( m_pAllow );
    for ( size_t i = 0; i < pVec->size ( ); i++ )
    {
        if ( (*pVec)[i].sIdentity != sAddr ) continue;      // exact, as FindPeer
        //  Found, but the entry may predate the agreement column. Keep looking
        //  rather than returning false: with a rollover in progress the older
        //  line can be two-column and the newer one three, and giving up at the
        //  first columnless entry would report a peer as unsealable when its
        //  current key is right there on the next line.
        if ( !(*pVec)[i].bAgree ) continue;
        //  A revoked agreement key is skipped, not fatal - the next line may
        //  carry the replacement. Only running out of lines is a refusal.
        if ( IsRevokedPoint ( (*pVec)[i].agree ) ) continue;
        std::memcpy ( pAgreeOut, (*pVec)[i].agree, kEcdhPubLen );
        return true;
    }
    return false;
}

bool AuthPolicy::FindIdentity ( const wchar_t *pAddr, unsigned char *pPubOut )
{
    if ( !pAddr || !pPubOut ) return false;
    return FindPeer ( pAddr, pPubOut );
}

bool AuthPolicy::SeenRelaySig ( const unsigned char *pSig ) const
{
    const SeenSigVec *pVec = SeenRel ( m_pSeenRel );
    for ( size_t i = 0; i < pVec->size ( ); i++ )
        if ( p2pcng::ConstTimeEqual ( (*pVec)[i].s, pSig, p2pcng::kEcdsaSigLen ) )
            return true;
    return false;
}

bool AuthPolicy::NoteRelaySig ( const unsigned char *pSig, time_t tNow )
{
    SeenSigVec *pVec = SeenRel ( m_pSeenRel );

    //  Trimmed by age on exactly the terms NoteNonce is, and for the same
    //  reason: an entry has to outlive every timestamp that could still be
    //  accepted, so twice the window.
    if ( m_nWindow > 0 )
    {
        const double dKeep = 2.0 * (double)m_nWindow;
        size_t w = 0;
        for ( size_t i = 0; i < pVec->size ( ); i++ )
        {
            double dAge = difftime ( tNow, (*pVec)[i].t );
            if ( dAge < 0 ) dAge = -dAge;
            if ( dAge <= dKeep )
            {
                if ( w != i ) (*pVec)[w] = (*pVec)[i];
                w++;
            }
        }
        pVec->resize ( w );
    }

    //  AND BY COUNT, in BOTH cases - not only when there is no window to trim
    //  by. Age bounds how long an entry is kept; it says nothing about how
    //  many arrive meanwhile, and relay is the hot path. A hub carrying r
    //  blocks a second holds 2*window*r of them and linear-scans every one on
    //  every block, so the cost grows with the SQUARE of the traffic the hub
    //  was already carrying: at the default window, a thousand blocks a second
    //  is 600k entries and tens of megabytes of comparison per block. Left
    //  uncapped, turning this protection on is its own denial of service.
    //
    //  The cap has a real cost and it is stated rather than buried: past
    //  kSeenMax entries inside one window the oldest is evicted, so it becomes
    //  replayable again BEFORE its timestamp would have expired. What that
    //  costs an attacker is pushing kSeenMax genuinely signed, freshly
    //  timestamped blocks through the same hub to flush the one they held -
    //  far harder to arrange than the unbounded growth it replaces, and unlike
    //  that growth it degrades the guarantee instead of the hub.
    //
    //  A range erase, though at steady state it always drops exactly one entry:
    //  the cap runs on every insert, so the size never gets above kSeenMax to
    //  begin with. It is written this way to stay correct if it ever does -
    //  a smaller kSeenMax, or entries added by some future path that does not
    //  come through here - rather than because a loop would cost more today.
    //
    //  It does NOT avoid the shift. Dropping the front entry moves everything
    //  behind it, and that is a real per-block cost. It is worn here, unlike in
    //  NoteSealSig which rings instead, because this cache cannot: the age trim
    //  above walks the entries in order, so their order has to mean something.
    if ( pVec->size ( ) >= kSeenMax )
        pVec->erase ( pVec->begin ( ),
                      pVec->begin ( ) + ( pVec->size ( ) - kSeenMax + 1 ) );

    SigMark m;
    std::memcpy ( m.s, pSig, p2pcng::kEcdsaSigLen );
    m.t = tNow;
    pVec->push_back ( m );
    return true;
}

bool AuthPolicy::SeenSealSig ( const unsigned char *pSig ) const
{
    const SeenSigVec *pVec = SeenRel ( m_pSeenSeal );
    for ( size_t i = 0; i < pVec->size ( ); i++ )
        if ( p2pcng::ConstTimeEqual ( (*pVec)[i].s, pSig, p2pcng::kEcdsaSigLen ) )
            return true;
    return false;
}

bool AuthPolicy::NoteSealSig ( const unsigned char *pSig, long long llWhen )
{
    SeenSigVec *pVec = SeenRel ( m_pSeenSeal );

    //  STILL BOUNDED BY COUNT ONLY - but that is no longer the whole story,
    //  and the reason it used to be is worth keeping because it explains the
    //  shape. A sealed body carried no timestamp until 2026-08-18, so nothing
    //  refused an old one, so an entry dropped for age handed back exactly the
    //  replay it was holding. Ageing this cache would not have bounded the
    //  memory; it would have published the waiting time.
    //
    //  The wire change (Stage 3 step 10) put a signed
    //  sealed_at in the block, and what that buys is not an age trim but a
    //  FLOOR: when the ring overwrites an entry, that entry's stamp becomes
    //  the oldest sealed_at this recipient can still say anything about, so
    //  everything at or before it is refused from then on. The count bound
    //  stops being a replay window and becomes a staleness horizon.
    //
    //  A RING once full, rather than dropping the front entry. Erasing the
    //  oldest out of the front of a vector moves the other kSeenMax-1 down
    //  behind it - a quarter of a megabyte memmoved for every sealed body
    //  opened, doubling the per-open cost of a cache that already has to be
    //  scanned. Overwriting the oldest slot in place is one store.
    //
    //  The ring index is what makes the floor correct without an age trim:
    //  slots are overwritten in insertion order, so the entry being evicted is
    //  the oldest INSERTED. That is not the same as the oldest SEALED - a body
    //  can arrive out of order - which is why the floor takes a maximum rather
    //  than assuming the evicted stamp is the largest so far. Going backwards
    //  would reopen exactly the window this closes.
    SigMark m;
    std::memcpy ( m.s, pSig, p2pcng::kEcdsaSigLen );
    m.t = (time_t)llWhen;

    if ( pVec->size ( ) < kSeenMax )
    {
        //  Still filling, so append and leave the ring at the front: index 0 is
        //  the oldest entry the moment it becomes full, which is where eviction
        //  has to start.
        pVec->push_back ( m );
        m_nSealNext = 0;
        return true;
    }

    if ( m_nSealNext >= kSeenMax ) m_nSealNext = 0;

    const long long llEvicted = (long long)(*pVec)[m_nSealNext].t;
    if ( llEvicted > m_llSealFloor ) m_llSealFloor = llEvicted;

    (*pVec)[m_nSealNext++] = m;
    return true;
}

bool AuthPolicy::SeenNonce ( const unsigned char *pNonce ) const
{
    const SeenVec *pVec = Seen ( m_pSeen );
    for ( size_t i = 0; i < pVec->size ( ); i++ )
        if ( p2pcng::ConstTimeEqual ( (*pVec)[i].n, pNonce, kAuthNonceLen ) )
            return true;
    return false;
}

bool AuthPolicy::NoteNonce ( const unsigned char *pNonce, time_t tNow )
{
    SeenVec *pVec = Seen ( m_pSeen );

    if ( m_nWindow > 0 )
    {
        //  Trimmed by time. Twice the window, because an entry has to outlive
        //  every timestamp that could still be accepted - a login may arrive
        //  with a timestamp a full window in the past.
        const double dKeep = 2.0 * (double)m_nWindow;
        size_t w = 0;
        for ( size_t i = 0; i < pVec->size ( ); i++ )
        {
            double dAge = difftime ( tNow, (*pVec)[i].t );
            if ( dAge < 0 ) dAge = -dAge;
            if ( dAge <= dKeep )
            {
                if ( w != i ) (*pVec)[w] = (*pVec)[i];
                w++;
            }
        }
        pVec->resize ( w );
    }
    else
    {
        //  No window, so nothing to trim by: bounded by count, oldest first.
        while ( pVec->size ( ) >= kSeenMax )
            pVec->erase ( pVec->begin ( ) );
    }

    NonceMark oNew;
    std::memcpy ( oNew.n, pNonce, kAuthNonceLen );
    oNew.t = tNow;
    pVec->push_back ( oNew );
    return true;
}

bool AuthPolicy::LooksLikeBlock ( const void *pv, size_t cb )
{
    const unsigned char *p = (const unsigned char *)pv;
    return p && cb >= 3 && p[0] == kMagic0 && p[1] == kMagic1;
}

// ---- Channel binding ---------------------------------------------------
//  H = SHA-256 ( "P2P-kx-v1" | client_pub | server_pub )
//
//  The label is inside the hash so this value cannot be confused with any
//  other SHA-256 the protocol computes. The two points are fixed-width, so no
//  length prefix is needed to keep the concatenation unambiguous - a 64-byte
//  field cannot borrow bytes from its neighbour.
bool
AuthChannelBind ( const unsigned char *pClientPub,
                  const unsigned char *pServerPub,
                  unsigned char *pBindOut )
{
    if ( !pClientPub || !pServerPub || !pBindOut )
        return false;

    unsigned char aIn[ sizeof(kLabelBind) - 1 + 2 * p2pcng::kEcdhPubLen ];
    size_t n = 0;
    std::memcpy ( aIn + n, kLabelBind, sizeof(kLabelBind) - 1 );
    n += sizeof(kLabelBind) - 1;
    std::memcpy ( aIn + n, pClientPub, p2pcng::kEcdhPubLen );
    n += p2pcng::kEcdhPubLen;
    std::memcpy ( aIn + n, pServerPub, p2pcng::kEcdhPubLen );
    n += p2pcng::kEcdhPubLen;

    return p2pcng::Sha256 ( aIn, n, pBindOut );
}

// ---- Login -------------------------------------------------------------
AuthResult
AuthPolicy::BuildLogin ( const wchar_t *pSrc, const wchar_t *pDst,
                         unsigned char *pOut, size_t cbOut,
                         unsigned char *pNonceOut,
                         const unsigned char *pBind )
{
    if ( !pSrc || !pDst || !pOut || !pNonceOut || cbOut < kAuthLoginLen )
        return AuthErrArgs;
    if ( !m_bHaveIdentity || !m_pIdentity )
        return AuthErrNoIdentity;

    unsigned char nonce[kAuthNonceLen];
    if ( !p2pcng::CngRandom ( nonce, (unsigned long)sizeof(nonce) ) )
        return AuthErrInternal;

    const long long llTs = (long long)std::time ( nullptr );

    std::string sTr;
    if ( !Transcript ( kLabelLogin, pSrc, pDst, nonce, &llTs, pBind, sTr ) )
        return AuthErrInternal;

    pOut[0] = kMagic0;
    pOut[1] = kMagic1;
    pOut[2] = kVersion;
    std::memcpy ( pOut + kOffNonce, nonce, kAuthNonceLen );
    PutI64 ( pOut + kOffTs, llTs );

    if ( !m_pIdentity->Sign ( (const unsigned char *)sTr.data ( ), sTr.size ( ),
                              pOut + kOffSig ) )
        return AuthErrInternal;

    std::memcpy ( pNonceOut, nonce, kAuthNonceLen );
    return AuthOk;
}

AuthResult
AuthPolicy::VerifyLogin ( const wchar_t *pSrc, const wchar_t *pDst,
                          const unsigned char *pIn, size_t cbIn,
                          unsigned char *pNonceOut, long *pnSkewOut,
                          const unsigned char *pBind )
{
    if ( pnSkewOut ) *pnSkewOut = 0;
    if ( !pSrc || !pDst || !pIn || !pNonceOut ) return AuthErrArgs;
    if ( cbIn < kAuthLoginLen )                 return AuthErrFormat;

    AuthResult eHdr = AuthOk;
    if ( !HeaderOk ( pIn, &eHdr ) ) return eHdr;

    //  The allow-list lookup comes first, so "I do not know you" stays
    //  distinguishable from "your signature is wrong". An unlisted peer never
    //  reaches the signature maths - and neither does a revoked one.
    bool   bAllRevoked = false;
    size_t nLive       = PeerKeyCount ( pSrc, &bAllRevoked );
    if ( bAllRevoked ) return AuthErrRevoked;
    if ( nLive == 0 )  return AuthErrUnknownPeer;

    const time_t    tNow = std::time ( nullptr );
    const long long llTs = GetI64 ( pIn + kOffTs );
    const long      nSkew = (long)( (long long)tNow - llTs );
    if ( pnSkewOut ) *pnSkewOut = nSkew;

    if ( m_nWindow > 0 )
    {
        long nAbs = nSkew < 0 ? -nSkew : nSkew;
        if ( nAbs > (long)m_nWindow ) return AuthErrSkew;
    }

    if ( SeenNonce ( pIn + kOffNonce ) ) return AuthErrReplay;

    std::string sTr;
    if ( !Transcript ( kLabelLogin, pSrc, pDst, pIn + kOffNonce, &llTs, pBind, sTr ) )
        return AuthErrInternal;

    AuthResult eVerify = VerifyAgainstPeer ( pSrc,
                                             (const unsigned char *)sTr.data ( ),
                                             sTr.size ( ), pIn + kOffSig );
    if ( eVerify != AuthOk ) return eVerify;

    //  Recorded only now. Recording before the signature verified would let
    //  anyone who can send bytes fill the cache with nonces of their choosing
    //  and block the logins that legitimately use them.
    NoteNonce ( pIn + kOffNonce, tNow );
    std::memcpy ( pNonceOut, pIn + kOffNonce, kAuthNonceLen );
    return AuthOk;
}

// ---- Ack ---------------------------------------------------------------
AuthResult
AuthPolicy::BuildAck ( const wchar_t *pSrc, const wchar_t *pDst,
                       const unsigned char *pNonce,
                       unsigned char *pOut, size_t cbOut,
                       const unsigned char *pBind )
{
    if ( !pSrc || !pDst || !pNonce || !pOut || cbOut < kAuthAckLen )
        return AuthErrArgs;
    if ( !m_bHaveIdentity || !m_pIdentity )
        return AuthErrNoIdentity;

    std::string sTr;
    if ( !Transcript ( kLabelAck, pSrc, pDst, pNonce, nullptr, pBind, sTr ) )
        return AuthErrInternal;

    pOut[0] = kMagic0;
    pOut[1] = kMagic1;
    pOut[2] = kVersion;

    if ( !m_pIdentity->Sign ( (const unsigned char *)sTr.data ( ), sTr.size ( ),
                              pOut + kOffAckSig ) )
        return AuthErrInternal;
    return AuthOk;
}

AuthResult
AuthPolicy::VerifyAck ( const wchar_t *pSrc, const wchar_t *pDst,
                        const unsigned char *pNonce,
                        const unsigned char *pIn, size_t cbIn,
                        const unsigned char *pBind )
{
    if ( !pSrc || !pDst || !pNonce || !pIn ) return AuthErrArgs;
    if ( cbIn < kAuthAckLen )                return AuthErrFormat;

    AuthResult eHdr = AuthOk;
    if ( !HeaderOk ( pIn, &eHdr ) ) return eHdr;

    std::string sTr;
    if ( !Transcript ( kLabelAck, pSrc, pDst, pNonce, nullptr, pBind, sTr ) )
        return AuthErrInternal;

    //  Same key set as the login, via the same helper. A server whose key
    //  rotated between the login it verified and the ack it signs would
    //  otherwise be accepted one way and refused the other.
    AuthResult eVerify = VerifyAgainstPeer ( pSrc,
                                             (const unsigned char *)sTr.data ( ),
                                             sTr.size ( ), pIn + kOffAckSig );
    if ( eVerify != AuthOk ) return eVerify;

    //  No nonce cache and no timestamp here, and neither is an omission: the
    //  ack signs the nonce THIS connection just generated, so a replayed ack
    //  is an ack for a nonce no live connection is waiting on.
    return AuthOk;
}

// ---- Relay attestation -------------------------------------------------
bool AuthPolicy::LooksLikeRelayBlock ( const void *pv, size_t cb )
{
    const unsigned char *p = (const unsigned char *)pv;
    return p && cb >= kRelayFixedLen
             && p[0] == kRelayMagic0 && p[1] == kRelayMagic1;
}

AuthResult
AuthPolicy::BuildRelay ( const wchar_t *pAttester,
                         const wchar_t *pSrc, const wchar_t *pDst,
                         const wchar_t *pMsgName,
                         const void *pBody, size_t cbBody,
                         unsigned char *pOut, size_t cbOut, size_t *pcbOut )
{
    if ( pcbOut ) *pcbOut = 0;
    if ( !pAttester || !pSrc || !pDst || !pOut || !pcbOut ) return AuthErrArgs;
    if ( !m_bHaveIdentity || !m_pIdentity )                 return AuthErrNoIdentity;

    std::string sAtt;
    if ( !Utf8FromWide ( pAttester, sAtt ) )       return AuthErrArgs;
    if ( sAtt.empty ( ) )                          return AuthErrArgs;
    if ( sAtt.size ( ) > kRelayAttesterMax )       return AuthErrArgs;

    const size_t cbBlock = RelayLen ( sAtt.size ( ) );
    if ( cbOut < cbBlock ) return AuthErrArgs;

    //  Signing with a revoked key is refused here rather than left to the far
    //  end. The far end WILL refuse it, and the same reasoning as
    //  SetRevocationList's own return value applies: finding out at the point
    //  of use beats finding out once per message, at every peer.
    if ( SelfKeyRevoked ( ) ) return AuthErrRevoked;
    if ( !m_bRevokeUsable )   return AuthErrRevoked;

    const long long llTs = (long long)std::time ( nullptr );

    std::string sTr;
    if ( !RelayTranscript ( pAttester, pSrc, pDst, pMsgName,
                            pBody, cbBody, llTs, sTr ) )
        return AuthErrInternal;

    pOut[0] = kRelayMagic0;
    pOut[1] = kRelayMagic1;
    pOut[2] = kRelayVersion;
    pOut[kOffRelayAlen    ] = (unsigned char)( ( sAtt.size ( ) >> 8 ) & 0xFF );
    pOut[kOffRelayAlen + 1] = (unsigned char)(   sAtt.size ( )        & 0xFF );
    std::memcpy ( pOut + kOffRelayAddr, sAtt.data ( ), sAtt.size ( ) );
    PutI64 ( pOut + OffRelayTs ( sAtt.size ( ) ), llTs );

    if ( !m_pIdentity->Sign ( (const unsigned char *)sTr.data ( ), sTr.size ( ),
                              pOut + OffRelaySig ( sAtt.size ( ) ) ) )
        return AuthErrInternal;

    *pcbOut = cbBlock;
    return AuthOk;
}

AuthResult
AuthPolicy::VerifyRelay ( const wchar_t *pSrc, const wchar_t *pDst,
                          const wchar_t *pMsgName,
                          const void *pBody, size_t cbBody,
                          const unsigned char *pIn, size_t cbIn,
                          wchar_t *pAttesterOut, size_t cchAttesterOut,
                          long *pnSkewOut )
{
    if ( pnSkewOut ) *pnSkewOut = 0;
    //  Emptied first, so every early return leaves the caller with no name
    //  rather than with whatever was in its buffer.
    if ( pAttesterOut && cchAttesterOut ) pAttesterOut[0] = 0;

    if ( !pSrc || !pDst || !pIn || !pAttesterOut || cchAttesterOut == 0 )
        return AuthErrArgs;
    if ( cbIn < kRelayFixedLen ) return AuthErrFormat;

    if ( pIn[0] != kRelayMagic0 || pIn[1] != kRelayMagic1 ) return AuthErrFormat;
    if ( pIn[2] != kRelayVersion )                          return AuthErrVersion;

    const size_t cbAddr = ( (size_t)pIn[kOffRelayAlen] << 8 )
                        |   (size_t)pIn[kOffRelayAlen + 1];
    //  Length checked against the buffer BEFORE it is used to index it. The
    //  attester length is attacker-chosen and the block arrived off the wire.
    if ( cbAddr == 0 || cbAddr > kRelayAttesterMax ) return AuthErrFormat;
    if ( cbIn < RelayLen ( cbAddr ) )                return AuthErrFormat;

    //  Decoded into a bounded local. kRelayAttesterMax UTF-8 bytes can be at
    //  most kRelayAttesterMax code units under either wchar_t width, so this is
    //  sized for the worst case and WideFromUtf8 refuses to overrun it anyway.
    wchar_t wszAtt[kRelayAttesterMax + 1];
    if ( !WideFromUtf8 ( (const char *)( pIn + kOffRelayAddr ), cbAddr,
                         wszAtt, sizeof(wszAtt) / sizeof(wszAtt[0]) ) )
        return AuthErrFormat;

    //  Allow-list first, so "I do not know that attester" stays distinguishable
    //  from "the signature is wrong" - and so an unlisted or revoked name never
    //  reaches the signature maths.
    bool   bAllRevoked = false;
    size_t nLive       = PeerKeyCount ( wszAtt, &bAllRevoked );
    if ( bAllRevoked ) return AuthErrRevoked;
    if ( nLive == 0 )  return AuthErrUnknownPeer;

    const time_t    tNow  = std::time ( nullptr );
    const long long llTs  = GetI64 ( pIn + OffRelayTs ( cbAddr ) );
    const long      nSkew = (long)( (long long)tNow - llTs );
    if ( pnSkewOut ) *pnSkewOut = nSkew;

    //  The hub's freshness window, the same one the login uses. It bounds how
    //  long a captured attested message stays replayable; it is not a replay
    //  DEFENCE, and the header says so rather than leaving that to be assumed.
    if ( m_nWindow > 0 )
    {
        long nAbs = nSkew < 0 ? -nSkew : nSkew;
        if ( nAbs > (long)m_nWindow ) return AuthErrSkew;
    }

    std::string sTr;
    if ( !RelayTranscript ( wszAtt, pSrc, pDst, pMsgName,
                            pBody, cbBody, llTs, sTr ) )
        return AuthErrInternal;

    AuthResult eVerify = VerifyAgainstPeer ( wszAtt,
                                             (const unsigned char *)sTr.data ( ),
                                             sTr.size ( ),
                                             pIn + OffRelaySig ( cbAddr ) );
    if ( eVerify != AuthOk ) return eVerify;

    //  Replay, and only now that the signature has verified. Consulting the
    //  cache earlier would let anyone who can send bytes fill it, and noting
    //  an unverified signature would let them evict real entries out of it.
    //  Off by default; see SetRelayReplayRefused for why that judgement is the
    //  operator's rather than this function's.
    if ( m_bRelayReplay )
    {
        const unsigned char *pSig = pIn + OffRelaySig ( cbAddr );
        if ( SeenRelaySig ( pSig ) ) return AuthErrReplay;
        NoteRelaySig ( pSig, tNow );
    }

    //  Published to the caller only now: before this line the name is a claim,
    //  after it the claim has been checked against the key listed under it.
    size_t cch = 0;
    while ( wszAtt[cch] ) cch++;
    if ( cch + 1 > cchAttesterOut ) return AuthErrArgs;
    std::memcpy ( pAttesterOut, wszAtt, ( cch + 1 ) * sizeof(wchar_t) );
    return AuthOk;
}

// -----------------------------------------------------------------------
//  Self-test
// -----------------------------------------------------------------------
namespace
{
    std::string AuthTempFile ( const char *pszLeaf )
    {
        std::string sDir;
#ifdef _WIN32
        char szDir[MAX_PATH * 4 + 8];
        wchar_t wszDir[MAX_PATH + 2];
        DWORD n = GetTempPathW ( MAX_PATH + 1, wszDir );
        if ( n == 0 || n > MAX_PATH ||
             WideCharToMultiByte ( CP_UTF8, 0, wszDir, -1, szDir,
                                   (int)sizeof(szDir), nullptr, nullptr ) <= 0 )
            sDir = ".\\";
        else
            sDir = szDir;
        unsigned long nPid = (unsigned long)GetCurrentProcessId ( );
#else
        sDir = "/tmp/";
        unsigned long nPid = (unsigned long)::getpid ( );
#endif
        char szPid[32];
        std::snprintf ( szPid, sizeof(szPid), "%lu", nPid );
        return sDir + "p2pauth_" + pszLeaf + "_" + szPid + ".tmp";
    }

    struct AuthScrub
    {
        std::vector<std::string> vPaths;
        void Add ( const std::string &s ) { vPaths.push_back ( s ); }
        ~AuthScrub ( )
        {
            for ( size_t i = 0; i < vPaths.size ( ); i++ )
#ifdef _WIN32
                DeleteFileA ( vPaths[i].c_str ( ) );
#else
                ::unlink ( vPaths[i].c_str ( ) );
#endif
        }
    };

    //  Section 18's battery, lifted out of AuthSelfTest for one reason: it
    //  needs a sealing fixture the rest of the function has no use for (a
    //  recipient agreement key, and a sender directory carrying the third
    //  column), and it reports WHICH case failed. The other sections return a
    //  bare false and are diagnosable by reading; this one has four policies
    //  in play and a silent false costs a build to locate.
    bool SealReplayBattery ( const std::string &sSenderKey,
                             const std::string &sRecipKey,
                             const std::string &sRecipAcl,
                             const unsigned char *pRecipIdPub,
                             AuthScrub &oScrub )
    {
        const char *pszWhere = "start";
        #define SEALCASE(w) pszWhere = (w)
        #define SEALFAIL()  do { std::fprintf ( stderr,                       \
                                  "[p2pauth] seal-replay case failed: %s\n",  \
                                  pszWhere ); std::fflush ( stderr );         \
                                return false; } while ( 0 )

        const std::string sRecipAgr = AuthTempFile ( "recipagr" );
        const std::string sSendAcl  = AuthTempFile ( "sendacl" );
        oScrub.Add ( sRecipAgr ); oScrub.Add ( sSendAcl );

        //  The recipient's static agreement half, and its public point copied
        //  into the sender's directory - sealing reads the recipient's key from
        //  the allow-list, which is the only directory this library has.
        unsigned char agrPub[kEcdhPubLen];
        {
            SEALCASE ( "generate recipient agreement key" );
            p2pcng::EcdhP256 oAgr;
            if ( !oAgr.Generate ( ) ) SEALFAIL ( );
            SEALCASE ( "save recipient agreement key" );
            if ( p2pcng::SaveAgreement ( sRecipAgr.c_str ( ), oAgr ) != p2pcng::IdOk )
                SEALFAIL ( );
            SEALCASE ( "export recipient agreement point" );
            if ( !oAgr.ExportPublic ( agrPub ) ) SEALFAIL ( );
        }

        //  The sender lists the recipient WITH an agreement column; the
        //  recipient lists the sender's identity so it knows whose signature to
        //  demand. Two directories, two different columns, and neither is the
        //  other's mirror.
        SEALCASE ( "write sender allow-list with agreement column" );
        if ( p2pcng::AppendAllowList ( sSendAcl.c_str ( ), "Auth.Server",
                                       pRecipIdPub, agrPub ) != p2pcng::IdOk )
            SEALFAIL ( );

        AuthPolicy oSender;
        SEALCASE ( "sender identity" );
        if ( oSender.SetIdentity  ( sSenderKey.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
        SEALCASE ( "sender allow-list" );
        if ( oSender.SetAllowList ( sSendAcl.c_str ( ) )   != p2pcng::IdOk ) SEALFAIL ( );

        AuthPolicy oRecip;
        SEALCASE ( "recipient allow-list" );
        if ( oRecip.SetAllowList ( sRecipAcl.c_str ( ) )  != p2pcng::IdOk ) SEALFAIL ( );
        SEALCASE ( "recipient agreement key" );
        if ( oRecip.SetAgreement ( sRecipAgr.c_str ( ) )  != p2pcng::IdOk ) SEALFAIL ( );
        SEALCASE ( "recipient can open / sender can seal" );
        if ( !oRecip.CanOpen ( ) || !oSender.CanSeal ( ) ) SEALFAIL ( );

        const wchar_t *pFrom = L"Auth.Client";
        const wchar_t *pTo   = L"Auth.Server";
        const char     szMsg[] = "a body the hubs in between cannot read";

        unsigned char aSealed[p2pseal::kSealOverhead + sizeof(szMsg)];
        size_t        cbSealed = 0;
        SEALCASE ( "seal" );
        if ( oSender.Seal ( pFrom, pTo, szMsg, sizeof(szMsg),
                            aSealed, sizeof(aSealed), &cbSealed ) != p2pseal::SealOk )
            SEALFAIL ( );

        unsigned char aOpen[sizeof(szMsg) + 32];
        size_t        cbOpen = 0;

        //  DEFAULT ON since Stage 3 step 10 - asserted as a
        //  BEHAVIOUR and not just as a flag read, which is why the explicit
        //  SetSealReplayRefused(false) below is still here rather than deleted
        //  along with the old default: turning it off must go on restoring the
        //  pre-2026-08-18 behaviour exactly, or the change is an outage for
        //  every deployment that legitimately re-delivers a signed body.
        SEALCASE ( "default is ON" );
        if ( !oRecip.IsSealReplayRefused ( ) ) SEALFAIL ( );
        oRecip.SetSealReplayRefused ( false );
        SEALCASE ( "open once with refusal off" );
        if ( oRecip.Open ( pFrom, pTo, aSealed, cbSealed,
                           aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
            SEALFAIL ( );
        SEALCASE ( "opened plaintext matches" );
        if ( cbOpen != sizeof(szMsg) ) SEALFAIL ( );
        if ( std::memcmp ( aOpen, szMsg, sizeof(szMsg) ) != 0 ) SEALFAIL ( );
        SEALCASE ( "open twice with refusal off" );
        if ( oRecip.Open ( pFrom, pTo, aSealed, cbSealed,
                           aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
            SEALFAIL ( );

        //  ON: the second delivery is a replay.
        AuthPolicy oOnce;
        SEALCASE ( "refusing recipient setup" );
        if ( oOnce.SetAllowList ( sRecipAcl.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
        if ( oOnce.SetAgreement ( sRecipAgr.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
        oOnce.SetSealReplayRefused ( true );

        std::memset ( aOpen, 0, sizeof(aOpen) );
        SEALCASE ( "first open with refusal on" );
        if ( oOnce.Open ( pFrom, pTo, aSealed, cbSealed,
                          aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
            SEALFAIL ( );
        if ( std::memcmp ( aOpen, szMsg, sizeof(szMsg) ) != 0 ) SEALFAIL ( );

        SEALCASE ( "second open is refused as a replay" );
        if ( oOnce.Open ( pFrom, pTo, aSealed, cbSealed,
                          aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealErrReplay )
            SEALFAIL ( );

        //  THE PART THAT IS EASY TO GET WRONG. A replay is recognised only
        //  after the body has decrypted, so the plaintext exists for a moment.
        //  It must not be left in the caller's buffer for code that checks the
        //  length, or nothing, instead of the result.
        SEALCASE ( "refused replay leaves no plaintext behind" );
        if ( cbOpen != 0 ) SEALFAIL ( );
        for ( size_t k = 0; k < sizeof(szMsg); k++ )
            if ( aOpen[k] != 0 ) SEALFAIL ( );

        //  A SECOND SEAL of identical plaintext still opens - the premise
        //  section 17 pins, holding twice over here: the ephemeral key and the
        //  GCM nonce are fresh per seal, so even the ciphertext differs.
        {
            unsigned char aSealed2[sizeof(aSealed)];
            size_t        cbSealed2 = 0;
            SEALCASE ( "second seal of identical plaintext" );
            if ( oSender.Seal ( pFrom, pTo, szMsg, sizeof(szMsg),
                                aSealed2, sizeof(aSealed2), &cbSealed2 ) != p2pseal::SealOk )
                SEALFAIL ( );
            SEALCASE ( "two seals of one plaintext differ on the wire" );
            if ( cbSealed2 == cbSealed &&
                 std::memcmp ( aSealed2, aSealed, cbSealed ) == 0 )
                SEALFAIL ( );
            SEALCASE ( "second seal still opens under refusal" );
            if ( oOnce.Open ( pFrom, pTo, aSealed2, cbSealed2,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
                SEALFAIL ( );
        }

        //  Per recipient, like the relay cache is per hub: a body opened at one
        //  recipient is not a replay at another. Same agreement key, because
        //  that is the sharper case - it is the CACHE that has to be separate,
        //  not the key material.
        {
            AuthPolicy oElse;
            SEALCASE ( "second recipient setup" );
            if ( oElse.SetAllowList ( sRecipAcl.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
            if ( oElse.SetAgreement ( sRecipAgr.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
            oElse.SetSealReplayRefused ( true );
            SEALCASE ( "one body is not a replay at a second recipient" );
            if ( oElse.Open ( pFrom, pTo, aSealed, cbSealed,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
                SEALFAIL ( );
        }

        //  A body that does NOT open must not reach the cache: flip a
        //  ciphertext byte so it fails, then check the genuine body still gets
        //  its first sight.
        {
            AuthPolicy oPoison;
            SEALCASE ( "poison recipient setup" );
            if ( oPoison.SetAllowList ( sRecipAcl.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
            if ( oPoison.SetAgreement ( sRecipAgr.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
            oPoison.SetSealReplayRefused ( true );

            unsigned char aBad[sizeof(aSealed)];
            std::memcpy ( aBad, aSealed, cbSealed );
            aBad[p2pseal::kSealEphLen + 1] ^= 0xFF;
            SEALCASE ( "tampered body is refused" );
            if ( oPoison.Open ( pFrom, pTo, aBad, cbSealed,
                                aOpen, sizeof(aOpen), &cbOpen ) == p2pseal::SealOk )
                SEALFAIL ( );
            SEALCASE ( "a refused body did not poison the cache" );
            if ( oPoison.Open ( pFrom, pTo, aSealed, cbSealed,
                                aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
                SEALFAIL ( );
        }

        //  THE COUNT BOUND, AND THE ORDER IT EVICTS IN. This cache rings once
        //  full rather than shifting every entry down on each insert, and a ring
        //  that overwrote the wrong slot would go on refusing a body it should
        //  have forgotten while forgetting one it should still refuse. Both look
        //  identical from any single open, so both ends are checked here.
        {
            AuthPolicy oRing;
            SEALCASE ( "ring recipient setup" );
            if ( oRing.SetAllowList ( sRecipAcl.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
            if ( oRing.SetAgreement ( sRecipAgr.c_str ( ) ) != p2pcng::IdOk ) SEALFAIL ( );
            oRing.SetSealReplayRefused ( true );

            //  The CAPTURED body, sealed an hour before everything that
            //  follows. The hour is what makes the floor observable at all:
            //  sealed_at has one-second resolution, so a body sealed in the
            //  same second as the fillers would sit exactly ON the floor rather
            //  than below it, and the case below would prove nothing about
            //  eviction. It is well inside the 24-hour freshness window, so
            //  nothing here is measuring staleness by accident.
            const long long llHourAgo = (long long)std::time ( 0 ) - 3600;
            unsigned char aOld[sizeof(aSealed)];
            size_t        cbOld = 0;
            SEALCASE ( "seal a body an hour ago" );
            if ( oSender.Seal ( pFrom, pTo, szMsg, sizeof(szMsg),
                                aOld, sizeof(aOld), &cbOld, llHourAgo ) != p2pseal::SealOk )
                SEALFAIL ( );

            SEALCASE ( "the oldest body opens, and is then held" );
            if ( oRing.Open ( pFrom, pTo, aOld, cbOld,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
                SEALFAIL ( );
            if ( oRing.Open ( pFrom, pTo, aOld, cbOld,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealErrReplay )
                SEALFAIL ( );

            //  kSeenMax + 1 more. kSeenMax alone would evict the first body and
            //  prove almost nothing: it makes the ring overwrite exactly ONCE,
            //  and a ring that always overwrote slot zero would do the identical
            //  thing. The extra one forces a SECOND overwrite, which is the
            //  first moment a correct ring and a stuck one disagree.
            unsigned char aFirstFill[sizeof(aSealed)], aMidFill[sizeof(aSealed)],
                          aLast[sizeof(aSealed)];
            size_t        cbFirstFill = 0, cbMidFill = 0, cbLast = 0;
            for ( size_t i = 0; i < kSeenMax + 1; i++ )
            {
                unsigned char aFill[sizeof(aSealed)];
                size_t        cbFill = 0;
                SEALCASE ( "seal a filler body" );
                if ( oSender.Seal ( pFrom, pTo, szMsg, sizeof(szMsg),
                                    aFill, sizeof(aFill), &cbFill ) != p2pseal::SealOk )
                    SEALFAIL ( );
                SEALCASE ( "open a filler body" );
                if ( oRing.Open ( pFrom, pTo, aFill, cbFill,
                                  aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
                    SEALFAIL ( );
                if ( i == 0 ) { std::memcpy ( aFirstFill, aFill, cbFill ); cbFirstFill = cbFill; }
                //  One from the middle, untouched by every overwrite this case
                //  performs - so it is still held if and only if the cache kept
                //  the entries between its ends.
                if ( i == kSeenMax / 2 ) { std::memcpy ( aMidFill, aFill, cbFill ); cbMidFill = cbFill; }
                std::memcpy ( aLast, aFill, cbFill );
                cbLast = cbFill;
            }

            //  THE CASE STAGE 3 STEP 10 INVERTED, AND THE ONE THE PLAN NAMES
            //  AS ITS FALSIFICATION. Until 2026-08-18 this read "the oldest
            //  body was evicted and opens again", and that was correct: with no
            //  timestamp on the wire, a body flushed out of the cache by
            //  kSeenMax newer ones became replayable, and the honest bound was
            //  "the most recent kSeenMax and no further".
            //
            //  It now carries a signed sealed_at, and evicting an entry raises
            //  a FLOOR at that entry's stamp. The captured body was sealed an
            //  hour before the fillers, so it is below the floor and is refused
            //  - permanently, and without the cache having to remember it.
            SEALCASE ( "an evicted body older than the floor is REFUSED" );
            if ( oRing.Open ( pFrom, pTo, aOld, cbOld,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealErrReplay )
                SEALFAIL ( );
            SEALCASE ( "the floor was actually raised" );
            if ( oRing.SealReplayFloor ( ) == 0 )
                SEALFAIL ( );

            //  THE RESIDUAL, ASSERTED RATHER THAN LEFT TO BE DISCOVERED. The
            //  floor comparison is STRICT because sealed_at has one-second
            //  resolution and a non-strict one would refuse live traffic sealed
            //  in the same second as the eviction. So a filler - sealed in the
            //  same second as the entry that set the floor - is evicted and
            //  does open again. That is the whole of what is left of the old
            //  hole: one second wide, and costing an attacker kSeenMax
            //  genuinely sealed bodies through this recipient inside it.
            //
            //  It doubles as the case that pins WHICH slot the ring picks: a
            //  ring stuck on one slot would leave this body in the cache and
            //  refuse it here for the wrong reason.
            SEALCASE ( "the one-second residual: a same-second evicted body opens" );
            if ( oRing.Open ( pFrom, pTo, aFirstFill, cbFirstFill,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
                SEALFAIL ( );

            //  AND THE FLOOR MUST NOT REFUSE LIVE TRAFFIC. A body sealed NOW,
            //  never seen, has to open with the floor standing - otherwise the
            //  protection above is indistinguishable from a recipient that has
            //  stopped accepting anything.
            {
                unsigned char aFresh[sizeof(aSealed)];
                size_t        cbFresh = 0;
                SEALCASE ( "seal a body after the floor was raised" );
                if ( oSender.Seal ( pFrom, pTo, szMsg, sizeof(szMsg),
                                    aFresh, sizeof(aFresh), &cbFresh ) != p2pseal::SealOk )
                    SEALFAIL ( );
                SEALCASE ( "a new body still opens with the floor standing" );
                if ( oRing.Open ( pFrom, pTo, aFresh, cbFresh,
                                  aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealOk )
                    SEALFAIL ( );
            }

            //  The other end, and what makes the two above mean something: the
            //  cache still HOLDS what it should. The newest body alone does not
            //  show that - an implementation that threw the whole cache away
            //  whenever it filled would keep the newest and pass - so a body
            //  from the middle is checked too, and that one is only there if
            //  everything between the two ends survived.
            SEALCASE ( "the newest body is still refused" );
            if ( oRing.Open ( pFrom, pTo, aLast, cbLast,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealErrReplay )
                SEALFAIL ( );
            SEALCASE ( "a body from the middle is still refused" );
            if ( oRing.Open ( pFrom, pTo, aMidFill, cbMidFill,
                              aOpen, sizeof(aOpen), &cbOpen ) != p2pseal::SealErrReplay )
                SEALFAIL ( );

            //  NOT covered here: the wrap of the ring index itself, which needs
            //  a second full lap - 2*kSeenMax seal/open round trips - and would
            //  roughly double what this battery costs on every build. The guard
            //  that performs it is one comparison immediately before the
            //  indexing, and ASan on the Linux side would catch it going wrong.
        }

        (void)sRecipKey;
        #undef SEALCASE
        #undef SEALFAIL
        return true;
    }

    //  Section 19's battery. Lifted out for the same reason as 18's: it needs a
    //  fixture nobody else wants (an authority identity, two revocation files
    //  and a victim whose login is checked either side of the revocation), and
    //  it has enough cases that a bare false would cost a build to locate.
    //
    //  Writes an empty revocation file rather than letting SetRevocationList
    //  fail: a missing file is the FAIL-CLOSED state, so starting from one
    //  would test the wrong thing everywhere below.
    bool RevDistBattery ( AuthScrub &oScrub )
    {
        const char *pszWhere = "start";
        #define REVCASE(w) pszWhere = (w)
        #define REVFAIL()  do { std::fprintf ( stderr,                        \
                                 "[p2pauth] rev-dist case failed: %s\n",      \
                                 pszWhere ); std::fflush ( stderr );          \
                             return false; } while ( 0 )

        const std::string sAuthKey  = AuthTempFile ( "rdauth" );
        const std::string sRogueKey = AuthTempFile ( "rdrogue" );
        const std::string sVicKey   = AuthTempFile ( "rdvic" );
        const std::string sIssRev   = AuthTempFile ( "rdissrev" );
        const std::string sIss2Rev  = AuthTempFile ( "rdiss2rev" );
        const std::string sRogueRev = AuthTempFile ( "rdroguerev" );
        const std::string sRecvRev  = AuthTempFile ( "rdrecvrev" );
        const std::string sRecvAcl  = AuthTempFile ( "rdrecvacl" );
        oScrub.Add ( sAuthKey  ); oScrub.Add ( sRogueKey ); oScrub.Add ( sVicKey );
        oScrub.Add ( sIssRev   ); oScrub.Add ( sIss2Rev  ); oScrub.Add ( sRogueRev );
        oScrub.Add ( sRecvRev  ); oScrub.Add ( sRecvAcl  );

        const wchar_t *pVic  = L"Auth.Client";
        const wchar_t *pRecv = L"Auth.Server";

        EcdsaP256 oAuth, oRogue, oVic, oSpare;
        REVCASE ( "generate fixture keys" );
        if ( !oAuth.Generate ( ) || !oRogue.Generate ( ) ||
             !oVic .Generate ( ) || !oSpare.Generate ( ) ) REVFAIL ( );

        unsigned char pubAuth[kEcdsaPubLen], pubRogue[kEcdsaPubLen];
        unsigned char pubVic [kEcdsaPubLen], pubSpare[kEcdsaPubLen];
        REVCASE ( "export fixture points" );
        if ( !oAuth .ExportPublic ( pubAuth  ) ||
             !oRogue.ExportPublic ( pubRogue ) ||
             !oVic  .ExportPublic ( pubVic   ) ||
             !oSpare.ExportPublic ( pubSpare ) ) REVFAIL ( );

        REVCASE ( "save fixture keys" );
        if ( p2pcng::SaveIdentity ( sAuthKey .c_str ( ), oAuth  ) != p2pcng::IdOk ||
             p2pcng::SaveIdentity ( sRogueKey.c_str ( ), oRogue ) != p2pcng::IdOk ||
             p2pcng::SaveIdentity ( sVicKey  .c_str ( ), oVic   ) != p2pcng::IdOk )
            REVFAIL ( );

        //  An empty but PRESENT revocation file. See the note above.
        REVCASE ( "seed empty receiver revocation file" );
        {
            std::FILE *fp = std::fopen ( sRecvRev.c_str ( ), "wb" );
            if ( !fp ) REVFAIL ( );
            std::fputs ( "# empty\n", fp );
            std::fclose ( fp );
        }

        REVCASE ( "seed receiver allow-list" );
        if ( p2pcng::AppendAllowList ( sRecvAcl.c_str ( ), "Auth.Client",
                                       pubVic ) != p2pcng::IdOk )
            REVFAIL ( );

        //  The issuer's list holds the victim. Appending CREATES the file, so
        //  this is also how the issuer's own list comes into existence.
        REVCASE ( "seed issuer revocation file" );
        if ( p2pcng::AppendRevocationList ( sIssRev.c_str ( ), pubVic, 0,
                                            "compromised" ) != p2pcng::IdOk )
            REVFAIL ( );

        AuthPolicy oIssuer;
        REVCASE ( "issuer setup" );
        if ( oIssuer.SetIdentity       ( sAuthKey.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
        if ( oIssuer.SetRevocationList ( sIssRev .c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
        if ( oIssuer.RevokedCount ( ) != 1 ) REVFAIL ( );

        unsigned char aList[2048];
        size_t        cbList = 0;
        REVCASE ( "issue a list" );
        if ( oIssuer.IssueRevocationList ( 10, aList, sizeof(aList), &cbList ) != RevOk )
            REVFAIL ( );
        REVCASE ( "issued length matches RevListLen(1)" );
        if ( cbList != RevListLen ( 1 ) ) REVFAIL ( );

        AuthPolicy oRecv;
        REVCASE ( "receiver setup" );
        if ( oRecv.SetAllowList      ( sRecvAcl.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
        if ( oRecv.SetRevocationList ( sRecvRev.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
        if ( oRecv.RevokedCount ( ) != 0 ) REVFAIL ( );

        AuthPolicy oVicPol;
        REVCASE ( "victim setup" );
        if ( oVicPol.SetIdentity ( sVicKey.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );

        //  BEFORE: the victim logs in fine. Without this the "after" case below
        //  would pass even if the login were broken for some unrelated reason.
        {
            unsigned char n[kAuthNonceLen], b[kAuthLoginLen];
            long nSkew = 0;
            REVCASE ( "victim logs in before the revocation" );
            if ( oVicPol.BuildLogin ( pVic, pRecv, b, sizeof(b), n ) != AuthOk ) REVFAIL ( );
            if ( oRecv.VerifyLogin ( pVic, pRecv, b, sizeof(b), n, &nSkew ) != AuthOk )
                REVFAIL ( );
        }

        //  ---- No authority: a perfectly good list is refused ----------------
        REVCASE ( "default has no authority" );
        if ( oRecv.HasRevocationAuthority ( ) ) REVFAIL ( );
        REVCASE ( "a list is refused with no authority configured" );
        if ( oRecv.ApplyRevocationList ( aList, cbList ) != RevErrNoAuthority ) REVFAIL ( );

        REVCASE ( "configure the authority" );
        if ( oRecv.SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk ) REVFAIL ( );
        if ( !oRecv.HasRevocationAuthority ( ) ) REVFAIL ( );

        //  ---- Wrong issuer --------------------------------------------------
        {
            REVCASE ( "seed rogue issuer list" );
            if ( p2pcng::AppendRevocationList ( sRogueRev.c_str ( ), pubVic, 0,
                                                "rogue" ) != p2pcng::IdOk )
                REVFAIL ( );
            AuthPolicy oRogueIss;
            if ( oRogueIss.SetIdentity       ( sRogueKey.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
            if ( oRogueIss.SetRevocationList ( sRogueRev.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );

            unsigned char aRogue[2048];
            size_t        cbRogue = 0;
            REVCASE ( "rogue issues a well-formed list" );
            if ( oRogueIss.IssueRevocationList ( 99, aRogue, sizeof(aRogue), &cbRogue ) != RevOk )
                REVFAIL ( );
            //  A VALID signature by a key that simply is not the authority. Not
            //  a signature failure - someone else's list, which is a different
            //  thing to tell an operator.
            REVCASE ( "a list from a non-authority is refused as wrong issuer" );
            if ( oRecv.ApplyRevocationList ( aRogue, cbRogue ) != RevErrIssuer ) REVFAIL ( );
            REVCASE ( "the rogue list revoked nothing" );
            if ( oRecv.RevokedCount ( ) != 0 ) REVFAIL ( );
        }

        //  ---- Tampering -----------------------------------------------------
        {
            unsigned char aBad[2048];
            std::memcpy ( aBad, aList, cbList );
            aBad[cbList - 1] ^= 0x01;                   // last byte of the sig
            REVCASE ( "a flipped signature bit is refused" );
            if ( oRecv.ApplyRevocationList ( aBad, cbList ) != RevErrSignature ) REVFAIL ( );

            std::memcpy ( aBad, aList, cbList );
            aBad[kOffRevEntries] ^= 0x01;               // first byte of entry 0
            REVCASE ( "a flipped entry bit is refused" );
            if ( oRecv.ApplyRevocationList ( aBad, cbList ) != RevErrSignature ) REVFAIL ( );

            std::memcpy ( aBad, aList, cbList );
            aBad[kOffRevEpoch + 7] ^= 0x01;             // the epoch is signed too
            REVCASE ( "a flipped epoch bit is refused" );
            if ( oRecv.ApplyRevocationList ( aBad, cbList ) != RevErrSignature ) REVFAIL ( );

            REVCASE ( "no tampered list revoked anything" );
            if ( oRecv.RevokedCount ( ) != 0 ) REVFAIL ( );
        }

        //  ---- Malformed -----------------------------------------------------
        {
            REVCASE ( "a truncated block is refused as format" );
            if ( oRecv.ApplyRevocationList ( aList, kRevFixedLen - 1 ) != RevErrFormat )
                REVFAIL ( );

            unsigned char aBad[2048];
            std::memcpy ( aBad, aList, cbList );
            //  Declares more entries than the buffer holds. The count is used to
            //  address the issuer and the signature, so believing it would read
            //  past the end - this is the case that pins that it is checked
            //  against the actual length FIRST.
            aBad[kOffRevCount    ] = 0x01;
            aBad[kOffRevCount + 1] = 0x00;              // 256 entries, not 1
            REVCASE ( "a count larger than the buffer is refused as format" );
            if ( oRecv.ApplyRevocationList ( aBad, cbList ) != RevErrFormat ) REVFAIL ( );

            std::memcpy ( aBad, aList, cbList );
            aBad[0] = 'X';
            REVCASE ( "a bad magic is refused as format" );
            if ( oRecv.ApplyRevocationList ( aBad, cbList ) != RevErrFormat ) REVFAIL ( );

            std::memcpy ( aBad, aList, cbList );
            aBad[2] = 0x7F;
            REVCASE ( "an unknown version is refused as version" );
            if ( oRecv.ApplyRevocationList ( aBad, cbList ) != RevErrVersion ) REVFAIL ( );
        }

        //  ---- The good path, and what it is FOR -----------------------------
        {
            size_t nAdded = 0;
            REVCASE ( "the authority's list applies" );
            if ( oRecv.ApplyRevocationList ( aList, cbList, &nAdded ) != RevOk ) REVFAIL ( );
            REVCASE ( "one point was added" );
            if ( nAdded != 1 || oRecv.RevokedCount ( ) != 1 ) REVFAIL ( );
            REVCASE ( "the epoch was recorded" );
            if ( oRecv.RevocationEpoch ( ) != 10 ) REVFAIL ( );

            //  The headline: a hub nobody edited now refuses the key.
            unsigned char n[kAuthNonceLen], b[kAuthLoginLen];
            long nSkew = 0;
            REVCASE ( "the victim is refused after the distributed revocation" );
            if ( oVicPol.BuildLogin ( pVic, pRecv, b, sizeof(b), n ) != AuthOk ) REVFAIL ( );
            if ( oRecv.VerifyLogin ( pVic, pRecv, b, sizeof(b), n, &nSkew ) != AuthErrRevoked )
                REVFAIL ( );
        }

        //  ---- Durability: it survives a restart -----------------------------
        {
            //  A fresh policy over the same FILE. If the apply had only touched
            //  memory this reads back 0 and the revocation was "until reboot".
            AuthPolicy oAfterRestart;
            REVCASE ( "applied points are on disk" );
            if ( oAfterRestart.SetRevocationList ( sRecvRev.c_str ( ) ) != p2pcng::IdOk )
                REVFAIL ( );
            if ( oAfterRestart.RevokedCount ( ) != 1 ) REVFAIL ( );
        }

        //  ---- Replay and rollback -------------------------------------------
        REVCASE ( "the same list again is stale" );
        if ( oRecv.ApplyRevocationList ( aList, cbList ) != RevErrStale ) REVFAIL ( );
        {
            unsigned char aOld[2048];
            size_t        cbOld = 0;
            REVCASE ( "issue an older epoch" );
            if ( oIssuer.IssueRevocationList ( 9, aOld, sizeof(aOld), &cbOld ) != RevOk )
                REVFAIL ( );
            REVCASE ( "a lower epoch is refused as stale" );
            if ( oRecv.ApplyRevocationList ( aOld, cbOld ) != RevErrStale ) REVFAIL ( );
        }

        //  ---- UNION: a later list that OMITS a point does not un-revoke it --
        //  The load-bearing property of the whole design. A newer, correctly
        //  signed list that simply does not mention the victim must not restore
        //  it - otherwise an authority with a truncated file, or an attacker who
        //  won a race to publish, silently widens trust.
        {
            REVCASE ( "seed a second issuer list without the victim" );
            if ( p2pcng::AppendRevocationList ( sIss2Rev.c_str ( ), pubSpare, 0,
                                                "other" ) != p2pcng::IdOk )
                REVFAIL ( );
            AuthPolicy oIssuer2;
            if ( oIssuer2.SetIdentity       ( sAuthKey.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
            if ( oIssuer2.SetRevocationList ( sIss2Rev.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
            REVCASE ( "the second list does not contain the victim" );
            if ( oIssuer2.RevokedCount ( ) != 1 ) REVFAIL ( );

            unsigned char aNew[2048];
            size_t        cbNew = 0;
            REVCASE ( "issue a newer list" );
            if ( oIssuer2.IssueRevocationList ( 20, aNew, sizeof(aNew), &cbNew ) != RevOk )
                REVFAIL ( );

            size_t nAdded = 0;
            REVCASE ( "the newer list applies" );
            if ( oRecv.ApplyRevocationList ( aNew, cbNew, &nAdded ) != RevOk ) REVFAIL ( );
            REVCASE ( "it added its own point" );
            if ( nAdded != 1 ) REVFAIL ( );
            //  TWO, not one: merged, not substituted.
            REVCASE ( "the omitted point was NOT un-revoked" );
            if ( oRecv.RevokedCount ( ) != 2 ) REVFAIL ( );

            unsigned char n[kAuthNonceLen], b[kAuthLoginLen];
            long nSkew = 0;
            REVCASE ( "the victim is still refused after the omitting list" );
            if ( oVicPol.BuildLogin ( pVic, pRecv, b, sizeof(b), n ) != AuthOk ) REVFAIL ( );
            if ( oRecv.VerifyLogin ( pVic, pRecv, b, sizeof(b), n, &nSkew ) != AuthErrRevoked )
                REVFAIL ( );

            //  Re-applying it is a no-op rather than a duplicate.
            REVCASE ( "a re-issued identical set adds nothing" );
            unsigned char aAgain[2048];
            size_t        cbAgain = 0;
            if ( oIssuer2.IssueRevocationList ( 21, aAgain, sizeof(aAgain), &cbAgain ) != RevOk )
                REVFAIL ( );
            nAdded = 1;
            if ( oRecv.ApplyRevocationList ( aAgain, cbAgain, &nAdded ) != RevOk ) REVFAIL ( );
            if ( nAdded != 0 || oRecv.RevokedCount ( ) != 2 ) REVFAIL ( );
        }

        //  ---- No durable store is a refusal, not an accept-and-forget -------
        {
            AuthPolicy oNoFile;
            REVCASE ( "authority with no revocation file" );
            if ( oNoFile.SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk ) REVFAIL ( );
            REVCASE ( "a list with nowhere durable to go is refused" );
            if ( oNoFile.ApplyRevocationList ( aList, cbList ) != RevErrNoList ) REVFAIL ( );
        }

        //  ---- An authority that revokes itself stops being one --------------
        {
            const std::string sSelfRev = AuthTempFile ( "rdselfrev" );
            const std::string sIss3Rev = AuthTempFile ( "rdiss3rev" );
            oScrub.Add ( sSelfRev ); oScrub.Add ( sIss3Rev );

            REVCASE ( "seed self-revoking issuer list" );
            if ( p2pcng::AppendRevocationList ( sIss3Rev.c_str ( ), pubAuth, 0,
                                                "authority compromised" ) != p2pcng::IdOk )
                REVFAIL ( );
            AuthPolicy oIssuer3;
            //  SetIdentity AFTER the list would report IdErrRevoked - the
            //  issuer's own key is on it. That is the documented "do not start"
            //  and is not what this case is about, so the list goes on last and
            //  its return is taken as-is.
            if ( oIssuer3.SetIdentity ( sAuthKey.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
            if ( oIssuer3.SetRevocationList ( sIss3Rev.c_str ( ) ) != p2pcng::IdErrRevoked )
                REVFAIL ( );

            unsigned char aSelf[2048];
            size_t        cbSelf = 0;
            REVCASE ( "issue the self-revoking list" );
            if ( oIssuer3.IssueRevocationList ( 30, aSelf, sizeof(aSelf), &cbSelf ) != RevOk )
                REVFAIL ( );

            {
                std::FILE *fp = std::fopen ( sSelfRev.c_str ( ), "wb" );
                if ( !fp ) REVFAIL ( );
                std::fputs ( "# empty\n", fp );
                std::fclose ( fp );
            }
            AuthPolicy oVictimHub;
            REVCASE ( "self-revoke receiver setup" );
            if ( oVictimHub.SetRevocationList     ( sSelfRev.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
            if ( oVictimHub.SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk ) REVFAIL ( );

            REVCASE ( "the self-revoking list applies" );
            if ( oVictimHub.ApplyRevocationList ( aSelf, cbSelf ) != RevOk ) REVFAIL ( );
            REVCASE ( "and the authority is gone" );
            if ( oVictimHub.HasRevocationAuthority ( ) ) REVFAIL ( );
            REVCASE ( "so the next list from it is refused" );
            if ( oVictimHub.ApplyRevocationList ( aList, cbList ) != RevErrNoAuthority )
                REVFAIL ( );
            //  And it cannot be reinstated by naming it again.
            REVCASE ( "a revoked point cannot be named as the authority" );
            if ( oVictimHub.SetRevocationAuthority ( pubAuth ) != p2pcng::IdErrRevoked )
                REVFAIL ( );
        }

        //  ---- Staleness ------------------------------------------------------
        //  NOT covered here: the elapsed-time branch, which needs the clock to
        //  move and is not worth a sleep in a test that runs on every build.
        //  What IS covered is every branch that decides WHETHER to look at the
        //  clock, and the refusal path they feed.
        {
            REVCASE ( "staleness is off by default" );
            if ( oRecv.GetMaxRevocationStaleness ( ) != 0 ) REVFAIL ( );
            if ( !oRecv.IsRevocationFresh ( ) ) REVFAIL ( );

            AuthPolicy oStale;
            const std::string sStaleRev = AuthTempFile ( "rdstalerev" );
            oScrub.Add ( sStaleRev );
            //  Seeded with the victim rather than left empty, unlike the other
            //  fixtures here: the rotation cases below have to tell "refused
            //  because this key is genuinely on the list" apart from "refused
            //  because the hub is stale and fails everything closed", and an
            //  empty list cannot distinguish them.
            REVCASE ( "seed the stale policy's revocation file" );
            if ( p2pcng::AppendRevocationList ( sStaleRev.c_str ( ), pubVic, 0,
                                                "compromised" ) != p2pcng::IdOk )
                REVFAIL ( );
            REVCASE ( "stale-policy receiver setup" );
            if ( oStale.SetRevocationList ( sStaleRev.c_str ( ) ) != p2pcng::IdOk ) REVFAIL ( );
            if ( oStale.RevokedCount ( ) != 1 ) REVFAIL ( );

            //  A limit with no authority must not refuse anything - there is
            //  nothing to be stale relative to.
            oStale.SetMaxRevocationStaleness ( 3600 );
            REVCASE ( "a limit with no authority does not refuse" );
            if ( !oStale.IsRevocationFresh ( ) )   REVFAIL ( );
            if ( !oStale.IsRevocationUsable ( ) )  REVFAIL ( );

            //  With an authority and nothing applied yet, it is stale from
            //  startup - the documented behaviour, and the sharp edge of
            //  turning this on.
            if ( oStale.SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk ) REVFAIL ( );
            REVCASE ( "an authority and no list yet is stale" );
            if ( oStale.IsRevocationFresh ( ) )   REVFAIL ( );
            REVCASE ( "and that makes revocation unusable" );
            if ( oStale.IsRevocationUsable ( ) )  REVFAIL ( );

            //  ROTATION OUT OF THE STALE STATE. A stale hub refuses every peer,
            //  because IsRevokedPoint fails closed and answers true for all of
            //  them. Naming a new authority must NOT go through that predicate:
            //  the fresh key would read back as revoked and the operator would
            //  be locked into the state they were trying to leave, told
            //  IdErrRevoked about a key that is on no list anywhere. Rotating
            //  is the way out, so it stays available while stale.
            REVCASE ( "a stale hub can still be pointed at a new authority" );
            if ( oStale.SetRevocationAuthority ( pubSpare ) != p2pcng::IdOk ) REVFAIL ( );
            if ( !oStale.HasRevocationAuthority ( ) ) REVFAIL ( );
            //  Still stale - rotating names a new source, it does not invent
            //  knowledge from one.
            if ( oStale.IsRevocationFresh ( ) ) REVFAIL ( );
            //  And a point that is genuinely ON the list is still refused, so
            //  the relaxation above is about the fail-closed answer only.
            REVCASE ( "a genuinely revoked point is still refused while stale" );
            if ( oStale.SetRevocationAuthority ( pubVic ) != p2pcng::IdErrRevoked ) REVFAIL ( );
            REVCASE ( "put the real authority back" );
            if ( oStale.SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk ) REVFAIL ( );

            //  Applying one clears it.
            REVCASE ( "applying a list makes it fresh" );
            if ( oStale.ApplyRevocationList ( aList, cbList ) != RevOk ) REVFAIL ( );
            if ( !oStale.IsRevocationFresh ( ) )  REVFAIL ( );
            if ( !oStale.IsRevocationUsable ( ) ) REVFAIL ( );

            //  And turning the limit back off clears it whatever the clock says.
            oStale.SetMaxRevocationStaleness ( 0 );
            REVCASE ( "zero disables the check" );
            if ( !oStale.IsRevocationFresh ( ) )  REVFAIL ( );
            //  Negative is clamped rather than treated as an enormous window.
            oStale.SetMaxRevocationStaleness ( -5 );
            REVCASE ( "a negative limit clamps to off" );
            if ( oStale.GetMaxRevocationStaleness ( ) != 0 ) REVFAIL ( );
        }

        //  ---- Clearing the authority turns distribution off ------------------
        REVCASE ( "a null authority clears it" );
        if ( oRecv.SetRevocationAuthority ( nullptr ) != p2pcng::IdOk ) REVFAIL ( );
        if ( oRecv.HasRevocationAuthority ( ) ) REVFAIL ( );

        (void)pubRogue;
        #undef REVCASE
        #undef REVFAIL
        return true;
    }
}

bool AuthSelfTest ( )
{
    const wchar_t *pServer = L"Auth.Server";
    const wchar_t *pClient = L"Auth.Client";
    const wchar_t *pAdmin  = L"Auth.Admin";
    const wchar_t *pOther  = L"Auth.Other";

    const std::string sSrvKey = AuthTempFile ( "srvkey" );
    const std::string sCliKey = AuthTempFile ( "clikey" );
    const std::string sRogue  = AuthTempFile ( "rogue"  );
    const std::string sSrvAcl = AuthTempFile ( "srvacl" );
    const std::string sCliAcl = AuthTempFile ( "cliacl" );

    AuthScrub oScrub;
    oScrub.Add ( sSrvKey ); oScrub.Add ( sCliKey ); oScrub.Add ( sRogue );
    oScrub.Add ( sSrvAcl ); oScrub.Add ( sCliAcl );

    //  Three identities: a server, a legitimate client, and a peer holding a
    //  perfectly valid key that simply is not the one the allow-list names.
    EcdsaP256 oSrv, oCli, oRogue;
    if ( !oSrv.Generate ( ) || !oCli.Generate ( ) || !oRogue.Generate ( ) ) return false;
    if ( p2pcng::SaveIdentity ( sSrvKey.c_str ( ), oSrv   ) != p2pcng::IdOk ) return false;
    if ( p2pcng::SaveIdentity ( sCliKey.c_str ( ), oCli   ) != p2pcng::IdOk ) return false;
    if ( p2pcng::SaveIdentity ( sRogue .c_str ( ), oRogue ) != p2pcng::IdOk ) return false;

    unsigned char pubSrv[kEcdsaPubLen], pubCli[kEcdsaPubLen];
    if ( !oSrv.ExportPublic ( pubSrv ) || !oCli.ExportPublic ( pubCli ) ) return false;

    //  The server trusts exactly one peer, under exactly one name.
    if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "Auth.Client", pubCli ) != p2pcng::IdOk )
        return false;
    //  The client trusts the server, so the ack can be checked.
    if ( p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "Auth.Server", pubSrv ) != p2pcng::IdOk )
        return false;

    AuthPolicy oServer, oClient, oImpostor;
    if ( oServer.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
    if ( oServer.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
    if ( oClient.SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ) return false;
    if ( oClient.SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
    if ( oImpostor.SetIdentity ( sRogue.c_str ( ) ) != p2pcng::IdOk ) return false;

    if ( oServer.AllowCount ( ) != 1 ) return false;
    if ( !oServer.CanSign ( ) || !oClient.CanSign ( ) ) return false;

    unsigned char blk[kAuthLoginLen];
    unsigned char ack[kAuthAckLen];
    unsigned char nonceCli[kAuthNonceLen], nonceSrv[kAuthNonceLen];
    long nSkew = 0;

    //  1. The honest round trip, both directions.
    if ( oClient.BuildLogin ( pClient, pServer, blk, sizeof(blk), nonceCli ) != AuthOk )
        return false;
    if ( oServer.VerifyLogin ( pClient, pServer, blk, sizeof(blk), nonceSrv, &nSkew ) != AuthOk )
        return false;
    if ( std::memcmp ( nonceCli, nonceSrv, kAuthNonceLen ) != 0 ) return false;
    if ( oServer.BuildAck ( pServer, pClient, nonceSrv, ack, sizeof(ack) ) != AuthOk )
        return false;
    if ( oClient.VerifyAck ( pServer, pClient, nonceCli, ack, sizeof(ack) ) != AuthOk )
        return false;

    //  2. Replay of the very same block. This is the property the nonce cache
    //     exists for, and it must hold whatever the clock says.
    {
        unsigned char n2[kAuthNonceLen];
        if ( oServer.VerifyLogin ( pClient, pServer, blk, sizeof(blk), n2, &nSkew ) != AuthErrReplay )
            return false;
    }

    //  3. A peer with a real key claiming a name the allow-list gives to
    //     someone else. THE test: the impostor's own signature is perfectly
    //     valid, so only the binding of name to key can refuse it.
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oImpostor.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSignature )
            return false;
    }

    //  4. A peer claiming a name that is in nobody's list at all.
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oImpostor.BuildLogin ( pAdmin, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pAdmin, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrUnknownPeer )
            return false;
    }

    //  5. A login for a DIFFERENT server, presented to this one. The signature
    //     is valid and the peer is trusted; only the bound destination refuses
    //     it. This is what stops a login captured at one hub being replayed at
    //     another.
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oClient.BuildLogin ( pClient, pOther, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSignature )
            return false;
    }

    //  6. One flipped bit in the signature, and one in the nonce (which is
    //     covered by the transcript, so it must break the signature too).
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        b2[kOffSig] ^= 0x01;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSignature )
            return false;
        b2[kOffSig] ^= 0x01;
        b2[kOffNonce] ^= 0x01;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSignature )
            return false;
    }

    //  7. Malformed headers.
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, kAuthLoginLen - 1, n2, &nSkew ) != AuthErrFormat )
            return false;
        b2[0] ^= 0xFF;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrFormat )
            return false;
        b2[0] ^= 0xFF;
        b2[2] = 99;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrVersion )
            return false;
    }

    //  8. Skew. The timestamp is signed, so a stale one cannot simply be
    //     edited - it has to be signed stale, which is what a narrow window
    //     forces an attacker to do live. Built here by moving the window to
    //     zero-tolerance instead, which tests the same comparison.
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        PutI64 ( b2 + kOffTs, (long long)std::time ( nullptr ) - 100000 );
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSkew )
            return false;
        if ( nSkew < 99000 ) return false;          // and it reports how far out

        //  Window 0 disables the check, so the same block now gets as far as
        //  the signature - which fails, because the timestamp was edited.
        oServer.SetWindow ( 0 );
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSignature )
            return false;
        oServer.SetWindow ( kAuthWindowDefault );
    }

    //  9. A hub with no identity cannot sign, and one with no list knows nobody.
    {
        AuthPolicy oEmpty;
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oEmpty.CanSign ( ) ) return false;
        if ( oEmpty.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthErrNoIdentity )
            return false;
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oEmpty.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrUnknownPeer )
            return false;
    }

    // 10. The block sniffer, used for diagnostics only.
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( !AuthPolicy::LooksLikeBlock ( b2, sizeof(b2) ) ) return false;
        const char *pszNot = "hello";
        if ( AuthPolicy::LooksLikeBlock ( pszNot, 5 ) ) return false;
    }

    // 11. Channel binding. This is the p2p_authrelay defence, so the checks
    //     that matter are the refusals: a proof made for one channel must be
    //     worthless on any other, and an unbound proof must be worthless on a
    //     bound one (otherwise stripping the exchange is a downgrade).
    {
        unsigned char aClientPub[p2pcng::kEcdhPubLen];
        unsigned char aServerPub[p2pcng::kEcdhPubLen];
        unsigned char aOtherPub [p2pcng::kEcdhPubLen];
        for ( size_t i = 0; i < p2pcng::kEcdhPubLen; ++i )
        {
            aClientPub[i] = (unsigned char)( i + 1 );
            aServerPub[i] = (unsigned char)( i + 101 );
            aOtherPub [i] = (unsigned char)( i + 201 );
        }

        unsigned char aBindA[kAuthBindLen], aBindB[kAuthBindLen];
        if ( !AuthChannelBind ( aClientPub, aServerPub, aBindA ) ) return false;
        if ( !AuthChannelBind ( aClientPub, aOtherPub,  aBindB ) ) return false;

        //  Deterministic, and different channels hash differently.
        unsigned char aAgain[kAuthBindLen];
        if ( !AuthChannelBind ( aClientPub, aServerPub, aAgain ) ) return false;
        if ( std::memcmp ( aBindA, aAgain, kAuthBindLen ) != 0 ) return false;
        if ( std::memcmp ( aBindA, aBindB, kAuthBindLen ) == 0 ) return false;

        //  Role order is part of the hash: swapping the two points is a
        //  different channel, not the same one seen from the other end.
        unsigned char aSwapped[kAuthBindLen];
        if ( !AuthChannelBind ( aServerPub, aClientPub, aSwapped ) ) return false;
        if ( std::memcmp ( aBindA, aSwapped, kAuthBindLen ) == 0 ) return false;

        if ( AuthChannelBind ( 0, aServerPub, aBindA ) ) return false;
        if ( !AuthChannelBind ( aClientPub, aServerPub, aBindA ) ) return false;

        //  A login bound to channel A verifies on channel A...
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2, aBindA ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew, aBindA ) != AuthOk )
            return false;

        //  ...and nowhere else. This is the relay, in one line: the proof is
        //  genuine, fresh and correctly addressed, and it is refused because
        //  it was not made for this channel.
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2, aBindA ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew, aBindB ) != AuthErrSignature )
            return false;

        //  Neither direction of the downgrade works: bound proof on an
        //  unbound channel, or unbound proof on a bound one.
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2, aBindA ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew, 0 ) != AuthErrSignature )
            return false;
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2, 0 ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew, aBindA ) != AuthErrSignature )
            return false;

        //  The ack binds the same channel, and refuses a different one.
        unsigned char aAck[kAuthAckLen];
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2, aBindA ) != AuthOk )
            return false;
        if ( oServer.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew, aBindA ) != AuthOk )
            return false;
        if ( oServer.BuildAck ( pServer, pClient, n2, aAck, sizeof(aAck), aBindA ) != AuthOk )
            return false;
        if ( oClient.VerifyAck ( pServer, pClient, n2, aAck, sizeof(aAck), aBindA ) != AuthOk )
            return false;
        if ( oClient.VerifyAck ( pServer, pClient, n2, aAck, sizeof(aAck), aBindB ) != AuthErrSignature )
            return false;
        if ( oClient.VerifyAck ( pServer, pClient, n2, aAck, sizeof(aAck), 0 ) != AuthErrSignature )
            return false;
    }

    // 12. ROTATION - two keys listed for one address, both accepted.
    //
    //     This is the whole overlap story in one block. Before it, FindPeer
    //     returned the first matching line and the second was dead weight, so
    //     replacing a peer's key meant every server it talks to being edited in
    //     the same instant it cut over. A fresh server policy is used so the
    //     earlier one's nonce cache and window are left alone.
    const std::string sCliKey2 = AuthTempFile ( "clikey2" );
    const std::string sSrvAcl2 = AuthTempFile ( "srvacl2" );
    const std::string sRevoke  = AuthTempFile ( "revoke"  );
    oScrub.Add ( sCliKey2 ); oScrub.Add ( sSrvAcl2 ); oScrub.Add ( sRevoke );

    EcdsaP256 oCli2;
    if ( !oCli2.Generate ( ) ) return false;
    if ( p2pcng::SaveIdentity ( sCliKey2.c_str ( ), oCli2 ) != p2pcng::IdOk ) return false;

    unsigned char pubCli2[kEcdsaPubLen];
    if ( !oCli2.ExportPublic ( pubCli2 ) ) return false;

    //  Old line first, new line second - the order an operator produces by
    //  appending, and the order that would hide the new key behind the old one
    //  if only the first match were tried.
    if ( p2pcng::AppendAllowList ( sSrvAcl2.c_str ( ), "Auth.Client", pubCli ) != p2pcng::IdOk )
        return false;
    if ( p2pcng::AppendAllowList ( sSrvAcl2.c_str ( ), "Auth.Client", pubCli2 ) != p2pcng::IdOk )
        return false;

    AuthPolicy oSrv2, oClient2;
    if ( oSrv2.SetIdentity   ( sSrvKey.c_str ( )  ) != p2pcng::IdOk ) return false;
    if ( oSrv2.SetAllowList  ( sSrvAcl2.c_str ( ) ) != p2pcng::IdOk ) return false;
    if ( oClient2.SetIdentity ( sCliKey2.c_str ( ) ) != p2pcng::IdOk ) return false;
    if ( oSrv2.AllowCount ( ) != 2 ) return false;
    if ( !oSrv2.IsRevocationUsable ( ) ) return false;   // none configured yet
    if ( oSrv2.RevokedCount ( ) != 0 ) return false;
    {
        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];

        //  The OLD key still logs in - a peer mid-rollover is not locked out.
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv2.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthOk )
            return false;

        //  The NEW key logs in too, which is the half that did not work before.
        if ( oClient2.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv2.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthOk )
            return false;

        //  And trust did not widen to anyone else in the process. Two listed
        //  keys means two keys, not "any key claiming this address".
        if ( oImpostor.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv2.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSignature )
            return false;
    }

    // 13. REVOCATION - the list that overrides the allow-list.
    {
        //  Withdraw the OLD key. The allow-list still names it; that must stop
        //  mattering, which is the entire point of the file.
        if ( p2pcng::AppendRevocationList ( sRevoke.c_str ( ), pubCli, 0,
                                            "rotated out" ) != p2pcng::IdOk )
            return false;
        if ( oSrv2.SetRevocationList ( sRevoke.c_str ( ) ) != p2pcng::IdOk ) return false;
        if ( oSrv2.RevokedCount ( ) != 1 ) return false;
        if ( !oSrv2.IsRevocationUsable ( ) ) return false;

        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];

        //  The old key is now refused. It reports AuthErrSignature rather than
        //  AuthErrRevoked, and that is correct: the address still has a live
        //  key, so what happened is that nothing which could sign for it did.
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv2.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrSignature )
            return false;

        //  The new key is untouched. Revoking one line does not disable a peer.
        if ( oClient2.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv2.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthOk )
            return false;

        //  Revoke the second one as well, and the address goes dark. THIS is
        //  where AuthErrRevoked appears, and it must not collapse into
        //  AuthErrUnknownPeer - "withdrawn" and "never provisioned" send an
        //  operator to two different files.
        if ( p2pcng::AppendRevocationList ( sRevoke.c_str ( ), pubCli2, 0,
                                            "compromised" ) != p2pcng::IdOk )
            return false;
        if ( oSrv2.ReloadRevocationList ( ) != p2pcng::IdOk ) return false;
        if ( oSrv2.RevokedCount ( ) != 2 ) return false;
        if ( oClient2.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv2.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrRevoked )
            return false;

        //  An address nobody ever listed still reports unknown, not revoked.
        if ( oImpostor.BuildLogin ( pAdmin, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv2.VerifyLogin ( pAdmin, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrUnknownPeer )
            return false;
    }

    // 14. FAIL CLOSED - a configured revocation list that cannot be read
    //     refuses everyone, rather than quietly reverting to "nothing is
    //     revoked". The failure mode this rules out is the dangerous one: an
    //     operator deletes the file to "turn revocation off" and silently
    //     re-admits every key they had withdrawn.
    {
        const std::string sBadRev = AuthTempFile ( "revbad" );
        oScrub.Add ( sBadRev );

        AuthPolicy oSrv3;
        if ( oSrv3.SetIdentity  ( sSrvKey.c_str ( )  ) != p2pcng::IdOk ) return false;
        if ( oSrv3.SetAllowList ( sSrvAcl.c_str ( )  ) != p2pcng::IdOk ) return false;

        unsigned char n2[kAuthNonceLen], b2[kAuthLoginLen];

        //  Baseline: this login works before revocation is configured at all.
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv3.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthOk )
            return false;

        //  A path that does not exist is a configuration error, not an empty
        //  list, and it latches the policy closed.
        if ( oSrv3.SetRevocationList ( sBadRev.c_str ( ) ) != p2pcng::IdErrNotFound )
            return false;
        if ( oSrv3.IsRevocationUsable ( ) ) return false;
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv3.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrRevoked )
            return false;

        //  A file that exists but has a garbled line is the same verdict. A
        //  half-parsed deny-list is the one thing that must never be honoured.
        {
            std::FILE *fp = std::fopen ( sBadRev.c_str ( ), "wb" );
            if ( !fp ) return false;
            std::fputs ( "not-a-hex-point\n", fp );
            std::fclose ( fp );
        }
        if ( oSrv3.ReloadRevocationList ( ) != p2pcng::IdErrFormat ) return false;
        if ( oSrv3.IsRevocationUsable ( ) ) return false;
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv3.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthErrRevoked )
            return false;

        //  Repair the file and the policy recovers on reload - fail-closed is a
        //  latch, not a one-way door.
        {
            std::FILE *fp = std::fopen ( sBadRev.c_str ( ), "wb" );
            if ( !fp ) return false;
            std::fputs ( "# empty but valid\n", fp );
            std::fclose ( fp );
        }
        if ( oSrv3.ReloadRevocationList ( ) != p2pcng::IdOk ) return false;
        if ( !oSrv3.IsRevocationUsable ( ) ) return false;
        if ( oSrv3.RevokedCount ( ) != 0 ) return false;
        if ( oClient.BuildLogin ( pClient, pServer, b2, sizeof(b2), n2 ) != AuthOk )
            return false;
        if ( oSrv3.VerifyLogin ( pClient, pServer, b2, sizeof(b2), n2, &nSkew ) != AuthOk )
            return false;
    }

    // 15. SELF-REVOCATION - a peer told that its own key is withdrawn finds out
    //     at startup rather than one refused connection at a time.
    {
        const std::string sSelfRev = AuthTempFile ( "revself" );
        oScrub.Add ( sSelfRev );
        if ( p2pcng::AppendRevocationList ( sSelfRev.c_str ( ), pubSrv, 0,
                                            "server key retired" ) != p2pcng::IdOk )
            return false;

        //  Identity first, then the list that condemns it.
        AuthPolicy oDoomed;
        if ( oDoomed.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
        if ( oDoomed.SetRevocationList ( sSelfRev.c_str ( ) ) != p2pcng::IdErrRevoked )
            return false;
        //  ...and the list is still IN FORCE, which is the part worth pinning:
        //  the error says "do not start", it does not say "I ignored this".
        if ( !oDoomed.IsRevocationUsable ( ) ) return false;
        if ( oDoomed.RevokedCount ( ) != 1 ) return false;

        //  The other order - list first, then the key - refuses to arm at all.
        AuthPolicy oDoomed2;
        if ( oDoomed2.SetRevocationList ( sSelfRev.c_str ( ) ) != p2pcng::IdOk )
            return false;
        if ( oDoomed2.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdErrRevoked )
            return false;
        if ( oDoomed2.CanSign ( ) ) return false;
    }

    // 16. RELAY ATTESTATION - origin authorship, which is what closes the
    //     ancestor exemption in P2PeerCon::GateAppMsgInbound.
    //
    //     The interesting checks are all refusals, and they are the ones that
    //     say a relaying hop cannot edit what it forwards: every field the
    //     receiver acts on - both addresses, the message name, the body - is in
    //     the transcript, so changing any of them breaks the signature rather
    //     than changing what the receiver does.
    {
        const wchar_t *pOrigin = L"Auth.Client";           // the attester
        const wchar_t *pSubSrc = L"Auth.Client.Widget";    // its sub-target
        const wchar_t *pDest   = L"Auth.Leaf";
        const wchar_t *pName   = L"P2PmsgBCast";
        const char     szBody[] = "transiting down from another branch";

        unsigned char blkRel[kRelayMaxLen];
        size_t        cbRel = 0;
        wchar_t       wszAtt[kRelayAttesterMax + 1];
        long          nRelSkew = 0;

        //  The honest round trip. Note the source is BELOW the attester: a hub
        //  posting for its own sub-target is the ordinary case, not an edge.
        if ( oClient.BuildRelay ( pOrigin, pSubSrc, pDest, pName,
                                  szBody, sizeof(szBody), blkRel, sizeof(blkRel),
                                  &cbRel ) != AuthOk )
            return false;
        if ( cbRel < kRelayFixedLen || cbRel > kRelayMaxLen ) return false;
        if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                   blkRel, cbRel, wszAtt,
                                   sizeof(wszAtt)/sizeof(wszAtt[0]),
                                   &nRelSkew ) != AuthOk )
            return false;
        //  And it names the signer, which is the value the gate's scope test
        //  is then applied to.
        if ( std::wcscmp ( wszAtt, pOrigin ) != 0 ) return false;

        //  THE SPLIT, pinned. VerifyRelay deliberately does NOT decide whether
        //  the attester may speak for the source - it reports who signed and
        //  stops. Here Auth.Client attests for a source in nobody's subtree and
        //  the CRYPTOGRAPHY is still satisfied. If this ever starts returning a
        //  refusal, the scope test has migrated into this layer and the one in
        //  P2PeerCon::GateRelayInbound is no longer the only thing standing
        //  between a listed peer and laundering any source it likes.
        {
            const wchar_t *pForeign = L"Somewhere.Else";
            unsigned char  b3[kRelayMaxLen];
            size_t         cb3 = 0;
            if ( oClient.BuildRelay ( pOrigin, pForeign, pDest, pName,
                                      szBody, sizeof(szBody), b3, sizeof(b3),
                                      &cb3 ) != AuthOk )
                return false;
            if ( oServer.VerifyRelay ( pForeign, pDest, pName, szBody,
                                       sizeof(szBody), b3, cb3, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthOk )
                return false;
            if ( std::wcscmp ( wszAtt, pOrigin ) != 0 ) return false;
        }

        //  The body is bound in. A relay that keeps a valid block and swaps the
        //  payload is the same forgery wearing the origin's name.
        {
            char szEdited[sizeof(szBody)];
            std::memcpy ( szEdited, szBody, sizeof(szBody) );
            szEdited[0] ^= 0x20;
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szEdited,
                                       sizeof(szEdited), blkRel, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrSignature )
                return false;
            //  ...and a body of a different LENGTH, which a hash over the bytes
            //  alone would still catch but which is worth having a case for.
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody,
                                       sizeof(szBody) - 1, blkRel, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrSignature )
                return false;
        }

        //  The message NAME is bound in. It selects the handler, so a relay
        //  that could re-label a signed body would still be choosing what the
        //  application does with it.
        if ( oServer.VerifyRelay ( pSubSrc, pDest, L"P2PmsgUCast", szBody,
                                   sizeof(szBody), blkRel, cbRel, wszAtt,
                                   sizeof(wszAtt)/sizeof(wszAtt[0]),
                                   &nRelSkew ) != AuthErrSignature )
            return false;

        //  Both addresses are bound in. The destination matters as much as the
        //  source: without it an attested message could be lifted off one
        //  delivery and re-aimed at another hub entirely.
        if ( oServer.VerifyRelay ( L"Auth.Client.Other", pDest, pName, szBody,
                                   sizeof(szBody), blkRel, cbRel, wszAtt,
                                   sizeof(wszAtt)/sizeof(wszAtt[0]),
                                   &nRelSkew ) != AuthErrSignature )
            return false;
        if ( oServer.VerifyRelay ( pSubSrc, L"Auth.Elsewhere", pName, szBody,
                                   sizeof(szBody), blkRel, cbRel, wszAtt,
                                   sizeof(wszAtt)/sizeof(wszAtt[0]),
                                   &nRelSkew ) != AuthErrSignature )
            return false;

        //  A valid key that is not the one listed under that name. This is the
        //  relaying ancestor's position exactly: it holds a real identity, and
        //  it is not the origin's.
        {
            unsigned char b3[kRelayMaxLen];
            size_t        cb3 = 0;
            if ( oImpostor.BuildRelay ( pOrigin, pSubSrc, pDest, pName,
                                        szBody, sizeof(szBody), b3, sizeof(b3),
                                        &cb3 ) != AuthOk )
                return false;
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody,
                                       sizeof(szBody), b3, cb3, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrSignature )
                return false;
            //  ...and the name it fails under is not published to the caller.
            if ( wszAtt[0] != 0 ) return false;

            //  Signing under its OWN name instead is refused earlier, and the
            //  distinction is the operator's: "not provisioned" and "wrong key"
            //  send you to two different files.
            if ( oImpostor.BuildRelay ( L"Auth.Rogue", L"Auth.Rogue", pDest, pName,
                                        szBody, sizeof(szBody), b3, sizeof(b3),
                                        &cb3 ) != AuthOk )
                return false;
            if ( oServer.VerifyRelay ( L"Auth.Rogue", pDest, pName, szBody,
                                       sizeof(szBody), b3, cb3, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrUnknownPeer )
                return false;
        }

        //  Malformed blocks, including the attacker-chosen length field. The
        //  attester length is read off the wire and then used to index the
        //  buffer, so it gets its own cases.
        {
            unsigned char b3[kRelayMaxLen];
            std::memcpy ( b3, blkRel, cbRel );

            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, kRelayFixedLen - 1, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrFormat )
                return false;

            b3[0] ^= 0xFF;                                    // magic
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrFormat )
                return false;
            b3[0] ^= 0xFF;

            b3[2] = 99;                                       // version
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrVersion )
                return false;
            b3[2] = blkRel[2];

            //  A length longer than the block. Refused on the buffer bound,
            //  before it is used as an offset.
            b3[kOffRelayAlen] = 0xFF; b3[kOffRelayAlen + 1] = 0xFF;
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrFormat )
                return false;

            //  Zero-length: an anonymous attester is not a thing.
            b3[kOffRelayAlen] = 0; b3[kOffRelayAlen + 1] = 0;
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrFormat )
                return false;

            //  A length that fits, but shifts everything after it. The name it
            //  then decodes to is a truncation of the real one, so this lands
            //  on the allow-list rather than the maths.
            b3[kOffRelayAlen] = 0; b3[kOffRelayAlen + 1] = 4;
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrUnknownPeer )
                return false;

            //  A non-UTF-8 attester. Refused rather than repaired: a repaired
            //  address is a DIFFERENT address that would then be handed to the
            //  scope test as though the signature had covered it.
            std::memcpy ( b3, blkRel, cbRel );
            b3[kOffRelayAddr] = 0xC0;                         // lead byte, no tail
            b3[kOffRelayAddr + 1] = 0x41;
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, cbRel, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrFormat )
                return false;
        }

        //  An empty body is a real message, not a missing one.
        {
            unsigned char b3[kRelayMaxLen];
            size_t        cb3 = 0;
            if ( oClient.BuildRelay ( pOrigin, pOrigin, pDest, pName,
                                      nullptr, 0, b3, sizeof(b3), &cb3 ) != AuthOk )
                return false;
            if ( oServer.VerifyRelay ( pOrigin, pDest, pName, nullptr, 0,
                                       b3, cb3, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthOk )
                return false;
        }

        //  A hub with no identity cannot attest, and the login block and the
        //  relay block are not mistaken for one another in either direction.
        {
            AuthPolicy oEmpty;
            unsigned char b3[kRelayMaxLen];
            size_t        cb3 = 0;
            if ( oEmpty.BuildRelay ( pOrigin, pSubSrc, pDest, pName,
                                     szBody, sizeof(szBody), b3, sizeof(b3),
                                     &cb3 ) != AuthErrNoIdentity )
                return false;

            if ( !AuthPolicy::LooksLikeRelayBlock ( blkRel, cbRel ) ) return false;
            if ( AuthPolicy::LooksLikeRelayBlock ( blk, sizeof(blk) ) ) return false;
            if ( AuthPolicy::LooksLikeBlock ( blkRel, cbRel ) ) return false;
        }

        //  Skew, and the same shape as the login's: the timestamp is signed, so
        //  it is tested by moving the window rather than by editing the block.
        {
            unsigned char b3[kRelayMaxLen];
            size_t        cb3 = 0;
            if ( oClient.BuildRelay ( pOrigin, pSubSrc, pDest, pName,
                                      szBody, sizeof(szBody), b3, sizeof(b3),
                                      &cb3 ) != AuthOk )
                return false;
            PutI64 ( b3 + OffRelayTs ( cb3 - kRelayFixedLen ),
                     (long long)std::time ( nullptr ) - 100000 );
            if ( oServer.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                       b3, cb3, wszAtt,
                                       sizeof(wszAtt)/sizeof(wszAtt[0]),
                                       &nRelSkew ) != AuthErrSkew )
                return false;
            if ( nRelSkew < 99000 ) return false;
        }

        // 17. RELAY REPLAY. The switch that refuses a signed block this hub has
        //     already accepted. Everything here is about not contradicting the
        //     argument on kRelayFixedLen: a broadcast that legitimately reaches
        //     many hubs must still reach them, and two legitimate sends of the
        //     same content must both land.
        {
            unsigned char b4[kRelayMaxLen], b5[kRelayMaxLen];
            size_t        cb4 = 0, cb5 = 0;

            if ( oClient.BuildRelay ( pOrigin, pSubSrc, pDest, pName,
                                      szBody, sizeof(szBody), b4, sizeof(b4),
                                      &cb4 ) != AuthOk )
                return false;

            //  THE PREMISE, pinned rather than trusted. Identical inputs, and
            //  the two blocks differ - because ECDSA signing is randomised on
            //  both backends. The whole cache design rests on this: it is what
            //  makes "same signature" mean "same send" rather than "same
            //  content". Move this tree to deterministic (RFC 6979) signing and
            //  this case fails, which is the intended warning - the cache would
            //  otherwise start refusing legitimate repeat sends.
            if ( oClient.BuildRelay ( pOrigin, pSubSrc, pDest, pName,
                                      szBody, sizeof(szBody), b5, sizeof(b5),
                                      &cb5 ) != AuthOk )
                return false;
            if ( cb4 != cb5 ) return false;
            if ( std::memcmp ( b4 + OffRelaySig ( cb4 - kRelayFixedLen ),
                               b5 + OffRelaySig ( cb5 - kRelayFixedLen ),
                               p2pcng::kEcdsaSigLen ) == 0 )
                return false;

            //  DEFAULT ON since Stage 3 step 10. The
            //  behaviour held still here is now the MIGRATION rather than the
            //  default: with the switch explicitly off the same block is
            //  accepted twice, exactly as it was before the switch existed,
            //  which is what a DAG deployment needs and what makes turning it
            //  on by default a default rather than an outage.
            AuthPolicy oOff;
            if ( oOff.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
            if ( oOff.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
            if ( !oOff.IsRelayReplayRefused ( ) ) return false;
            oOff.SetRelayReplayRefused ( false );
            if ( oOff.IsRelayReplayRefused ( ) ) return false;
            if ( oOff.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                    b4, cb4, wszAtt,
                                    sizeof(wszAtt)/sizeof(wszAtt[0]),
                                    &nRelSkew ) != AuthOk )
                return false;
            if ( oOff.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                    b4, cb4, wszAtt,
                                    sizeof(wszAtt)/sizeof(wszAtt[0]),
                                    &nRelSkew ) != AuthOk )
                return false;

            //  ON: the first delivery is the message, the second is a replay.
            AuthPolicy oOn;
            if ( oOn.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
            if ( oOn.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
            oOn.SetRelayReplayRefused ( true );
            if ( !oOn.IsRelayReplayRefused ( ) ) return false;

            if ( oOn.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                   b4, cb4, wszAtt,
                                   sizeof(wszAtt)/sizeof(wszAtt[0]),
                                   &nRelSkew ) != AuthOk )
                return false;
            if ( oOn.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                   b4, cb4, wszAtt,
                                   sizeof(wszAtt)/sizeof(wszAtt[0]),
                                   &nRelSkew ) != AuthErrReplay )
                return false;
            //  A refused replay publishes no attester, the same way every other
            //  refusal in this function does not.
            if ( wszAtt[0] != 0 ) return false;

            //  ...and the SECOND send of identical content still lands, which is
            //  the case the premise above exists to protect. If this ever fails
            //  the cache has started keying on content.
            if ( oOn.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                   b5, cb5, wszAtt,
                                   sizeof(wszAtt)/sizeof(wszAtt[0]),
                                   &nRelSkew ) != AuthOk )
                return false;

            //  THE FAN-OUT CASE, which is the objection this design had to
            //  answer. The cache is per policy - so per hub - and one broadcast
            //  reaching a second hub is not a replay at that hub. b4 has been
            //  accepted at oOn and is accepted here on its own first sight.
            AuthPolicy oOther;
            if ( oOther.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
            if ( oOther.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
            oOther.SetRelayReplayRefused ( true );
            if ( oOther.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                      b4, cb4, wszAtt,
                                      sizeof(wszAtt)/sizeof(wszAtt[0]),
                                      &nRelSkew ) != AuthOk )
                return false;

            //  A block that does NOT verify must not reach the cache in either
            //  direction: it cannot be refused as a replay, and it cannot make
            //  the genuine block that follows it look like one. Tampered body,
            //  so the signature fails while the signature BYTES are untouched -
            //  which is precisely the input that would poison a cache consulted
            //  before verification.
            {
                AuthPolicy oPoison;
                if ( oPoison.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
                if ( oPoison.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
                oPoison.SetRelayReplayRefused ( true );

                char szEdit[sizeof(szBody)];
                std::memcpy ( szEdit, szBody, sizeof(szBody) );
                szEdit[0] = 'X';
                if ( oPoison.VerifyRelay ( pSubSrc, pDest, pName, szEdit, sizeof(szEdit),
                                           b4, cb4, wszAtt,
                                           sizeof(wszAtt)/sizeof(wszAtt[0]),
                                           &nRelSkew ) != AuthErrSignature )
                    return false;
                //  The real one, same signature bytes, still gets its first sight.
                if ( oPoison.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                           b4, cb4, wszAtt,
                                           sizeof(wszAtt)/sizeof(wszAtt[0]),
                                           &nRelSkew ) != AuthOk )
                    return false;
            }

            //  Window 0 disables freshness, and the cache then has nothing to
            //  trim by - so the refusal has to keep working on count alone,
            //  which is the configuration where it matters most: with no
            //  freshness bound, the cache is the ONLY thing standing between a
            //  captured block and unlimited redelivery.
            {
                AuthPolicy oNoWin;
                if ( oNoWin.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
                if ( oNoWin.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
                oNoWin.SetRelayReplayRefused ( true );
                oNoWin.SetWindow ( 0 );
                if ( oNoWin.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                          b4, cb4, wszAtt,
                                          sizeof(wszAtt)/sizeof(wszAtt[0]),
                                          &nRelSkew ) != AuthOk )
                    return false;
                if ( oNoWin.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                          b4, cb4, wszAtt,
                                          sizeof(wszAtt)/sizeof(wszAtt[0]),
                                          &nRelSkew ) != AuthErrReplay )
                    return false;
            }

            //  THE COUNT BOUND, WITH A WINDOW STILL SET. This one is here
            //  because the opposite was believed and written down: that the
            //  freshness window bounded the memory, so no count cap was needed
            //  while a window was configured. It does not. A window bounds how
            //  LONG an entry is kept, not how many arrive meanwhile, and the
            //  cache is scanned once per block - so age alone let a busy hub
            //  grow it without limit and pay for it quadratically.
            //
            //  What this pins is the cap that replaced that, and honestly: past
            //  kSeenMax the oldest entry is evicted even though its timestamp is
            //  still perfectly fresh, so it can be replayed again inside the
            //  window it was supposed to cover. That is the price of the bound,
            //  and it costs an attacker kSeenMax genuinely signed blocks pushed
            //  through this same hub to collect.
            {
                AuthPolicy oCap;
                if ( oCap.SetIdentity ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ) return false;
                if ( oCap.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ) return false;
                oCap.SetRelayReplayRefused ( true );
                //  Default window, left alone deliberately: every block below is
                //  seconds old, so NOTHING here is evicted by age. If the count
                //  cap were absent this case could not pass.

                if ( oCap.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                        b4, cb4, wszAtt,
                                        sizeof(wszAtt)/sizeof(wszAtt[0]),
                                        &nRelSkew ) != AuthOk )
                    return false;
                //  Held, for now.
                if ( oCap.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                        b4, cb4, wszAtt,
                                        sizeof(wszAtt)/sizeof(wszAtt[0]),
                                        &nRelSkew ) != AuthErrReplay )
                    return false;

                //  kSeenMax fresh blocks, each a real signature over the same
                //  content - which is also the fan-out premise exercised four
                //  thousand times rather than twice.
                for ( size_t i = 0; i < kSeenMax; i++ )
                {
                    unsigned char bN[kRelayMaxLen];
                    size_t        cbN = 0;
                    if ( oClient.BuildRelay ( pOrigin, pSubSrc, pDest, pName,
                                              szBody, sizeof(szBody),
                                              bN, sizeof(bN), &cbN ) != AuthOk )
                        return false;
                    if ( oCap.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                            bN, cbN, wszAtt,
                                            sizeof(wszAtt)/sizeof(wszAtt[0]),
                                            &nRelSkew ) != AuthOk )
                        return false;
                }

                //  Flushed out of the cache, and therefore accepted again.
                if ( oCap.VerifyRelay ( pSubSrc, pDest, pName, szBody, sizeof(szBody),
                                        b4, cb4, wszAtt,
                                        sizeof(wszAtt)/sizeof(wszAtt[0]),
                                        &nRelSkew ) != AuthOk )
                    return false;
            }
        }
    }

    // 18. SEAL REPLAY. The same switch for a sealed body, and it is a WEAKER
    //     guarantee than section 17's for a reason worth stating where the
    //     cases are: a relay block carries a signed timestamp and a sealed body
    //     does not, so that cache can trim by time and this one cannot.
    if ( !SealReplayBattery ( sCliKey, sSrvKey, sSrvAcl, pubSrv, oScrub ) )
        return false;

    // 19. REVOCATION DISTRIBUTION. Sections 1-18 all assume the deny-list got
    //     to the hub somehow. This one is about that "somehow": a signed,
    //     versioned list carried between hubs, verified against a named
    //     authority rather than against whoever handed it over, and MERGED so
    //     that nothing which arrives can ever un-revoke a key. The case that
    //     matters most is the one asserting exactly that - a newer, validly
    //     signed list which omits a revoked point leaves it revoked.
    if ( !RevDistBattery ( oScrub ) )
        return false;

    return true;
}

} // namespace p2pauth
