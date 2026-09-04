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
//  P2PeerConWsa implementation
//  NOTES: Manages Microsoft WSA connections
//

#include "stdafx.h"
#include "MSWSock.h"
#include "Ws2tcpip.h"

#include "P2PeerConWsa.h"
#include "P2PeerioDmx.h"
#include "P2Pwin32.h"

#include <vector>              // P2PeerConWsaSourceFilter
#include <cstdio>              // std::snprintf - the portable form, as used by
                               // P2PAuthLogin.cpp and P2PIdentityStore.cpp

///////////////////////////////////////////////////////////////////////
//  Accept source allow-list
//  NOTES: Defined here rather than in the header for the reason
//         P2PeerConSourceTally is defined in P2PeerCon.cpp - a container in a
//         shipped header is a dependency every consumer inherits whether it
//         uses the feature or not
//       : A prefix is 16 RAW BYTES in network order plus a family and a bit
//         count, and NOT the two ULONGs it was until 2026-08-28.  The mask
//         arithmetic that shape allowed does not reach 128 bits, and the
//         alternative - a second parallel list for the second family - would
//         let the two drift.  One list, one comparison, and the family is a
//         field of the rule rather than a property of where it is kept
//       : Network order throughout, which is the order the addresses arrive in
//         and the order a prefix is written in.  A v4 rule kept in host order
//         had to be converted at the boundary; a byte-wise prefix compare has
//         no order to be in, so the conversion is gone rather than doubled
//       : A rule matches only its own family.  There is no v4 rule that can
//         admit a v6 peer and none the other way, and the one place the
//         families could have been confused - a v4 peer arriving on a
//         dual-stack socket as ::ffff:a.b.c.d - is normalised to AF_INET
//         before it is ever tested.  Refer AcceptSourceAddress()
//       : No lock.  The list is written by SetListenScope()'s neighbours
//         before the service is posted and read on the pump thread afterwards,
//         which is the same configure-before-arm rule RequireAuth states.  A
//         list mutated under a live service is not supported and would need
//         the tally's critical section to be
struct P2PeerConWsaSourceFilter
{
    struct Prefix
    {
        int    nFamily;                    // AF_INET or AF_INET6
        int    nBits;                      // 0..32 or 0..128
        UCHAR  ucNetwork[16];              // network order, already masked
    };
    std::vector<Prefix>  m_oPrefixes;

    //  Compares the leading nBits of two network-order addresses
    //  NOTES: The trailing partial byte is masked rather than shifted, so a
    //         prefix that does not end on a byte boundary - /12 and /7 both
    //         appear in AllowAcceptPrivate() - is compared exactly and not
    //         rounded up to the next byte, which would silently narrow it, nor
    //         down, which would silently widen it
    static bool
      BitsEqual ( const UCHAR *pucLeft, const UCHAR *pucRight, int nBits )
      {
        const int nWhole = nBits / 8;
        const int nRest  = nBits % 8;
        if ( nWhole && memcmp ( pucLeft, pucRight, (size_t)nWhole ) != 0 )
          return false;
        if ( nRest )
        {
          const UCHAR ucMask = (UCHAR)( 0xFF << ( 8 - nRest ) );
          if ( ( pucLeft[nWhole] & ucMask ) != ( pucRight[nWhole] & ucMask ) )
            return false;
        }
        return true;
      }

    void
      Add ( int nFamily, const UCHAR *pucNetwork, int nBits )
      {
        Prefix oPrefix;
        oPrefix.nFamily = nFamily;
        oPrefix.nBits   = nBits;
        //  Stored MASKED, so a rule written "10.1.2.3/8" holds 10.0.0.0 and
        //  reads back as the rule it is rather than as the address it was
        //  typed from
        memset ( oPrefix.ucNetwork, 0, sizeof(oPrefix.ucNetwork) );
        const int nWhole = nBits / 8;
        const int nRest  = nBits % 8;
        if ( nWhole )
          memcpy ( oPrefix.ucNetwork, pucNetwork, (size_t)nWhole );
        if ( nRest )
          oPrefix.ucNetwork[nWhole] =
            (UCHAR)( pucNetwork[nWhole] & (UCHAR)( 0xFF << ( 8 - nRest ) ) );
        m_oPrefixes.push_back ( oPrefix );
      }

    bool
      Matches ( int nFamily, const UCHAR *pucAddress ) const
      {
        for ( std::vector<Prefix>::const_iterator it = m_oPrefixes.begin ( )
            ; it != m_oPrefixes.end ( ); ++it )
          if ( it->nFamily == nFamily &&
               BitsEqual ( pucAddress, it->ucNetwork, it->nBits ) )
            return true;
        return false;
      }
};

//  The longest legal prefix text, plus room for a terminator
//  NOTES: "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128" is 49 characters
//         and is the longest thing either parser below can accept.  A string
//         longer than this cannot be a prefix, so the bound is a rejection
//         rather than a truncation - truncating "10.0.0.0/8xxxxx" to something
//         that parses is exactly the class of silent misreading these parsers
//         exist to refuse
#define MAX_P2PeerConPrefix   64

//
//  Description: Splits "address[/bits]" into its two halves
//
//               NOTES: Works on a plain char buffer and NOT on CStringA, which
//                      is why it exists.  The Linux shim's CStringA carries
//                      construction, GetString(), GetLength() and IsEmpty() and
//                      nothing else - no Find(), Mid(), Left(), Trim() or
//                      operator[] - so a parser written against those compiles
//                      on Windows and cannot compile on Linux.  This one did
//                      not, from the day the allow-list landed (2026-08-27)
//                      until the dual-stack port was measured on Linux, because
//                      nothing had built this file there in between
//                    : A parser needs no string class.  Narrowing the caller's
//                      text once at the door and then reading bytes is smaller
//                      than either alternative - a second string class or a
//                      widened shim - and it is the version that cannot be
//                      broken again by whichever class the platform lends us
//                    : A bare address answers the family's FULL width, so
//                      "10.0.0.0" and "10.0.0.0/32" are the same rule and the
//                      bind check one screen down - which refuses anything
//                      narrower than a host address - reads them alike without
//                      having to ask which was written
//
//  Returns:     bool
//               Whether the text is well-formed enough to hand on
//
static bool
SplitP2PeerConPrefix ( LPCTSTR lpszPrefix, char *szAddr, size_t cchAddr
                     , int nMaxBits, int &rnBits )
{
    rnBits = nMaxBits;
    if ( cchAddr )
      szAddr[0] = 0;

    // To be sure, to be sure
    if ( lpszPrefix == 0 || cchAddr == 0 )
      return false;

    //  Narrowed once, here, and read as bytes from this point on.  An address
    //  is ASCII by construction, so the conversion cannot lose anything a
    //  prefix could legitimately contain
    const CStringA csPrefix ( lpszPrefix );
    const char    *pszText = (LPCSTR)csPrefix;
    if ( pszText == 0 )
      return false;

    //  Leading and trailing whitespace, which a config file will have
    while ( *pszText == ' ' || *pszText == '\t' )
      ++pszText;
    size_t cchText = strlen ( pszText );
    while ( cchText && ( pszText[cchText-1] == ' '  ||
                         pszText[cchText-1] == '\t' ||
                         pszText[cchText-1] == '\r' ||
                         pszText[cchText-1] == '\n'    ) )
      --cchText;
    if ( cchText == 0 || cchText >= cchAddr )
      return false;                    // empty, or too long to be a prefix

    //  ONE '/' at most.  "1.2.3.4/8/8" is refused outright rather than read as
    //  its first half, which is the same rule the octet parser follows: a rule
    //  nobody can be sure of is not a rule to narrow a filter by
    size_t cchAddrPart = cchText;
    for ( size_t i = 0; i < cchText; ++i )
      if ( pszText[i] == '/' )
      {
        if ( cchAddrPart != cchText )
          return false;                // a second '/' - refuse rather than pick
        cchAddrPart = i;
      }

    if ( cchAddrPart != cchText )
    {
      const char  *pszBits = pszText + cchAddrPart + 1;
      const size_t cchBits = cchText - cchAddrPart - 1;
      if ( cchBits == 0 || cchBits > 3 )
        return false;
      int nBits = 0;
      for ( size_t i = 0; i < cchBits; ++i )
      {
        if ( pszBits[i] < '0' || pszBits[i] > '9' )
          return false;
        nBits = nBits * 10 + ( pszBits[i] - '0' );
      }
      if ( nBits < 0 || nBits > nMaxBits )
        return false;
      rnBits = nBits;
    }

    if ( cchAddrPart == 0 )
      return false;                    // "/24" with nothing in front of it
    memcpy ( szAddr, pszText, cchAddrPart );
    szAddr[cchAddrPart] = 0;
    return true;
}

//
//  Description: Parses "a.b.c.d" into 4 network-order bytes
//
//               NOTES: Hand-parsed rather than handed to inet_addr(), which
//                      accepts "10.1" as 10.0.0.1 and "0x0a000001" as an
//                      address.  Those are conveniences for a user typing at a
//                      prompt and hazards for a POLICY read from a config
//                      file: they turn a typo in a rule into a valid rule
//                      about somewhere else, silently
//                    : inet_pton(AF_INET) would also reject those, and IS what
//                      the v6 half below uses.  This half is kept hand-written
//                      because it is the half that has been shipping and
//                      because its rejections are the ones the gate test names
//                      one by one
//                    : Rejects everything it is not certain of.  The caller
//                      reports the rejection and adds no prefix, so the failure
//                      mode of a malformed rule is a narrower filter that is
//                      complained about, never a wider one that is not
//
//  Returns:     bool
//               Whether the address parsed
//
static bool
ParseP2PeerConAddr4 ( const char *pszAddr, UCHAR *pucAddr )
{
    // Four octets, each present, each 0..255
    // NOTES: The loop synthesises a terminating '.' one past the end so the
    //        last octet is closed by the same code as the first three
    const size_t cchAddr = strlen ( pszAddr );
    ULONG ulAddr  = 0;
    int   nOctet  = 0;
    int   nDigits = 0;
    int   nValue  = 0;
    for ( size_t i = 0; ; ++i )
    {
      const char c = ( i < cchAddr ) ? pszAddr[i] : '.';
      if ( c >= '0' && c <= '9' )
      {
        if ( ++nDigits > 3 )
          return false;
        nValue = nValue * 10 + ( c - '0' );
        if ( nValue > 255 )
          return false;
      }
      else if ( c == '.' )
      {
        if ( nDigits == 0 || nOctet > 3 )
          return false;
        ulAddr  = ( ulAddr << 8 ) | (ULONG)nValue;
        nDigits = 0;
        nValue  = 0;
        if ( ++nOctet == 4 && i >= cchAddr )
          break;
      }
      else
        return false;
    }
    if ( nOctet != 4 )
      return false;

    //  Network order, which is the order the octets were written in
    pucAddr[0] = (UCHAR)( ( ulAddr >> 24 ) & 0xFF );
    pucAddr[1] = (UCHAR)( ( ulAddr >> 16 ) & 0xFF );
    pucAddr[2] = (UCHAR)( ( ulAddr >>  8 ) & 0xFF );
    pucAddr[3] = (UCHAR)(   ulAddr         & 0xFF );
    return true;
}

//
//  Description: Parses "xxxx::yyyy" into 16 network-order bytes
//
//               NOTES: inet_pton() rather than a hand parser, and the reason is
//                      the opposite of the v4 case above.  There is no
//                      shorthand for it to accept: RFC4291 text is exact, the
//                      platform parser is the one everything else on the host
//                      agrees with, and a second implementation of :: elision
//                      would be a second opinion about what an operator wrote
//                    : A zone index - "fe80::1%eth0" - is REFUSED, because
//                      inet_pton() does not take one and a rule that dropped
//                      the zone would be a rule about every link rather than
//                      the one named.  A link-local allow-list is spelt
//                      "fe80::/10" and means what it says
//
//  Returns:     bool
//               Whether the address parsed
//
static bool
ParseP2PeerConAddr6 ( const char *pszAddr, UCHAR *pucAddr )
{
    //  The NARROW form deliberately.  InetPton is a macro naming the WIDE one
    //  on the Linux shim, and the text here is already narrow
    return InetPtonA ( AF_INET6, pszAddr, pucAddr ) == 1;
}

//
//  Description: Parses one allow-list rule of either family
//
//               NOTES: A ':' anywhere decides IPv6 and its absence IPv4.  It is
//                      not a guess - ':' cannot occur in a v4 prefix and cannot
//                      be absent from a v6 one - and it means a caller never
//                      has to say which family a rule is in, so a rule and its
//                      family cannot be written to disagree
//                    : The family has to be decided BEFORE the bit count can be
//                      range-checked, because /64 is legal in one family and
//                      not in the other.  So the text is scanned for ':' first
//                      and split second
//
//  Returns:     bool
//               Whether the prefix parsed
//
static bool
ParseP2PeerConPrefix ( LPCTSTR lpszPrefix, int &rnFamily
                     , UCHAR *pucAddr, int &rnBits )
{
    rnFamily = AF_INET;
    rnBits   = 0;
    memset ( pucAddr, 0, 16 );

    // To be sure, to be sure
    if ( lpszPrefix == 0 )
      return false;

    //  Narrowed once to decide the family, then split against that family's
    //  width.  Two conversions of the same short string is not worth an
    //  out-parameter to avoid
    const CStringA csFamily ( lpszPrefix );
    const char    *pszText = (LPCSTR)csFamily;
    if ( pszText == 0 )
      return false;
    rnFamily = ( strchr ( pszText, ':' ) != 0 ) ? AF_INET6 : AF_INET;

    char szAddr[MAX_P2PeerConPrefix];
    if ( !SplitP2PeerConPrefix ( lpszPrefix, szAddr, sizeof(szAddr)
                               , rnFamily == AF_INET6 ? 128 : 32
                               , rnBits ) )
      return false;

    return rnFamily == AF_INET6 ? ParseP2PeerConAddr6 ( szAddr, pucAddr )
                                : ParseP2PeerConAddr4 ( szAddr, pucAddr );
}

//
//  Description: The address bytes inside a sockaddr, and how many of them
//               there are
//
//               NOTES: One place that knows where a family keeps its address,
//                      so the filter, the key and the diagnostic all read the
//                      same bytes.  Answers 0 for a family this transport does
//                      not open, which every caller treats as "unnameable"
//
//  Returns:     int
//               4, 16, or 0
//
static int
P2PeerConAddrBytes ( const sockaddr *pName, int nNameLen
                   , const UCHAR *&rpucAddr )
{
    rpucAddr = 0;
    if ( pName == 0 )
      return 0;
    if ( pName->sa_family == AF_INET )
    {
      if ( nNameLen < (int)sizeof(sockaddr_in) )
        return 0;
      rpucAddr = (const UCHAR *)&((const sockaddr_in *)pName)->sin_addr;
      return 4;
    }
    if ( pName->sa_family == AF_INET6 )
    {
      if ( nNameLen < (int)sizeof(sockaddr_in6) )
        return 0;
      rpucAddr = (const UCHAR *)
                 ((const sockaddr_in6 *)pName)->sin6_addr.s6_addr;
      return 16;
    }
    return 0;
}

//
//  Description: Rewrites a v4-MAPPED IPv6 address in place as the AF_INET
//               address it stands for
//
//               NOTES: ::ffff:a.b.c.d is how a dual-stack socket reports a peer
//                      that arrived over IPv4, and it is the ONE place the two
//                      address spaces touch.  Left alone it would make a v4
//                      peer's origin depend on which socket carried it - an
//                      operator's "10.0.0.0/8" would admit it on a v4 service
//                      and refuse it on a dual one, for no reason the operator
//                      can see
//                    : The 12-byte prefix is tested by hand rather than with
//                      IN6_IS_ADDR_V4MAPPED, whose argument conventions differ
//                      between the platform headers this builds against.
//                      Twelve bytes is not worth a portability question
//                    : The PORT is carried across.  Nothing here reads it, but
//                      an address that lost half of itself in a normalisation
//                      is a trap for whatever reads it next
//
//  Returns:     int
//               The new address length, or the one passed in if untouched
//
static int
NormaliseP2PeerConSockaddr ( SOCKADDR_STORAGE &rAddr, int nLen )
{
    if ( rAddr.ss_family != AF_INET6 || nLen < (int)sizeof(sockaddr_in6) )
      return nLen;

    const sockaddr_in6 *p6    = (const sockaddr_in6 *)&rAddr;
    const UCHAR        *pucIn = (const UCHAR *)p6->sin6_addr.s6_addr;

    static const UCHAR ucMappedPrefix[12] =
      { 0,0,0,0, 0,0,0,0, 0,0,0xFF,0xFF };
    if ( memcmp ( pucIn, ucMappedPrefix, sizeof(ucMappedPrefix) ) != 0 )
      return nLen;

    UCHAR        ucV4[4];
    const u_short usPort = p6->sin6_port;
    memcpy ( ucV4, pucIn + 12, sizeof(ucV4) );

    sockaddr_in oV4;
    memset ( &oV4, 0, sizeof(oV4) );
    oV4.sin_family = AF_INET;
    oV4.sin_port   = usPort;
    memcpy ( &oV4.sin_addr, ucV4, sizeof(ucV4) );

    memset ( &rAddr, 0, sizeof(rAddr) );
    memcpy ( &rAddr, &oV4, sizeof(oV4) );
    return (int)sizeof(sockaddr_in);
}

//
//  Description: Is this address on THIS machine's loopback?
//
//               NOTES: The whole of 127.0.0.0/8 and ::1/128 - exactly the two
//                      prefixes AllowAcceptLoopback() writes into the accept
//                      allow-list, and deliberately the same two.  v4 has a
//                      loopback NET and v6 has a single loopback ADDRESS, so
//                      the asymmetry is the standards' and not a shortcut
//                    : Reads the BYTES through P2PeerConAddrBytes(), so an
//                      address family this transport does not open answers
//                      false rather than being interpreted as something it is
//                      not.  A length without a meaning is worse than none
//                    : The caller must have normalised first.  A v4-mapped
//                      ::ffff:127.0.0.1 is sixteen bytes here and would NOT
//                      match ::1 - which is the correct reading of the bytes
//                      and the wrong answer about the host, and is why every
//                      call site runs NormaliseP2PeerConSockaddr() ahead of
//                      this one
//
//  Parameters:  const sockaddr *pName, int nNameLen
//               The address, normalised
//
//  Returns:     bool
//               Whether the kernel can reach that address without a network
//
static bool
IsP2PeerConSockaddrLoopback ( const sockaddr *pName, int nNameLen )
{
    const UCHAR *pucAddr = 0;
    const int    nBytes  = P2PeerConAddrBytes ( pName, nNameLen, pucAddr );

    if ( nBytes == 4 )
      return pucAddr[0] == 127;                 // 127.0.0.0/8

    if ( nBytes == 16 )
    {
      static const UCHAR ucV6Loopback[16] =
        { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
      return memcmp ( pucAddr, ucV6Loopback, sizeof(ucV6Loopback) ) == 0;
    }

    return false;                               // unnameable - refer above
}

//
//  Description: Renders a socket address as text, for a diagnostic
//
//               NOTES: getnameinfo(NI_NUMERICHOST) rather than four %u and a
//                      shift, which cannot render sixteen bytes and cannot
//                      elide a run of zeroes the way every other tool on the
//                      host will.  An operator matching a refusal line against
//                      an allow-list needs the two spelt the same way
//                    : NUMERIC deliberately - NEVER a reverse lookup.  This is
//                      called on the refusal path for a peer that has said
//                      nothing and may be hostile; a DNS round trip per refused
//                      connection is an amplifier pointed at the operator's own
//                      resolver.  Refer THREAT_MODEL.md B1
//                    : Always leaves a printable string.  A diagnostic that
//                      failed to render its subject would report the refusal
//                      without the one fact it exists to carry
//
static void
RenderP2PeerConAddr ( const sockaddr *pName, int nNameLen
                    , char *szOut, size_t cchOut )
{
    if ( cchOut == 0 )
      return;
    szOut[0] = 0;
    if ( pName != 0 && nNameLen > 0 &&
         getnameinfo ( pName, (socklen_t)nNameLen
                     , szOut, (DWORD)cchOut, 0, 0, NI_NUMERICHOST ) == 0 &&
         szOut[0] != 0 )
      return;
    std::snprintf ( szOut, cchOut, "%s", "(unnameable)" );
}

//
//  Description: Folds an IPv6 origin into the 64-bit accounting key
//
//               NOTES: The /64 PREFIX and not the whole address, and that is
//                      the substantive decision here rather than the hash.  A
//                      v6 host is routinely delegated an entire /64 - one
//                      subscriber line, one machine's privacy addresses - so
//                      keying on 128 bits would let a single source mint 2^64
//                      keys and walk straight through the per-source bound the
//                      key exists to serve.  Two hosts in one /64 sharing a key
//                      is the intended reading of "one source"
//                    : FNV-1a, which is a fold and not a security primitive.
//                      Nothing here resists a chosen-prefix collision and
//                      nothing needs to: the consequence of one is that two
//                      subnets share an accept budget, which is the same
//                      consequence a /64 already has by design
//                    : Bit 63 is SET, unconditionally.  A v4 key is the 32-bit
//                      address and can never reach it, so the two families
//                      cannot collide in the tally's map - and ::1, whose /64
//                      prefix is all zeroes, cannot fold to 0, which is the
//                      value reserved for "the kernel would not name it"
//
//  Returns:     P2PsourceKey
//               The key, never 0
//
static P2PsourceKey
FoldP2PeerConV6Key ( const UCHAR *pucAddr )
{
    unsigned long long ullHash = 14695981039346656037ull;   // FNV-1a offset
    for ( int i = 0; i < 8; ++i )                           // the /64 prefix
    {
      ullHash ^= (unsigned long long)pucAddr[i];
      ullHash *= 1099511628211ull;                          // FNV-1a prime
    }
    return (P2PsourceKey)( ullHash | ( 1ull << 63 ) );
}

//
//  Description: The accounting key for one already-read origin
//
//               NOTES: Takes an address rather than reading a socket, so the
//                      accept path can read the socket ONCE and derive both the
//                      key and the allow-list decision from the same bytes.
//                      Two readings of a socket that is being torn down can
//                      disagree, and an accept refused by one answer while
//                      being counted by the other is the kind of inconsistency
//                      that only shows up in production
//                    : The address is expected NORMALISED - refer
//                      AcceptSourceAddress().  A v4-mapped peer reaching here
//                      unrewritten would be keyed as a v6 /64 and so would take
//                      a different share from the same peer on a v4 service
//
//  Returns:     P2PsourceKey
//               The key, or 0 for an origin that cannot be named
//
static P2PsourceKey
KeyP2PeerConSource ( const SOCKADDR_STORAGE &rAddr, int nLen )
{
    const UCHAR *pucAddr = 0;
    const int    nBytes  = P2PeerConAddrBytes ( (const sockaddr *)&rAddr
                                              , nLen, pucAddr );
    //  IPv4 IS its address, in network order, exactly as it has always been.
    //  The key is an identity and not a number: nothing compares it for
    //  magnitude, so normalising the order would buy nothing
    if ( nBytes == 4 )
      return (P2PsourceKey)(unsigned int)
             ((const sockaddr_in *)&rAddr)->sin_addr.s_addr;
    if ( nBytes == 16 )
      return FoldP2PeerConV6Key ( pucAddr );
    return 0;
}

//
//  Description: Resolves a host name or an address literal to a socket address
//
//               NOTES: getaddrinfo(), replacing an InetPton() call with a
//                      gethostbyname() fallback that COULD NOT RUN.  The
//                      fallback was written for inet_addr(), which signals
//                      failure by returning INADDR_NONE; the PostVS2015 move to
//                      InetPton() changed the signal and not the test.
//                      InetPton() answers 0 for a string it cannot parse and
//                      WRITES NOTHING, so after the memset the address stayed
//                      0.0.0.0 and `== INADDR_NONE` could only ever fire for
//                      the literal "255.255.255.255".  Every host NAME - and
//                      the self-connection path, which feeds gethostname()'s
//                      output straight into this - therefore resolved to
//                      0.0.0.0 and failed in ConnectEx with
//                      WSAEADDRNOTAVAIL rather than with the "Unable to
//                      resolve server" this code plainly meant to report.
//                      Nothing in the suite noticed because every test in it
//                      dials the literal "127.0.0.1", which parses
//                    : One call now does both jobs.  getaddrinfo() takes a name
//                      OR a literal, so there is no failure signal to
//                      misread and no second path to leave unreachable
//                    : gethostbyname() is also the one API here that COULD NOT
//                      be carried to IPv6 - it is A-records only.  Replacing it
//                      was the first step of the dual-stack port, taken before
//                      the port was
//                    : ai_family is the CALLER's, and since 2026-08-28 it can
//                      be AF_UNSPEC.  It was the literal AF_INET while every
//                      socket this class opened was AF_INET, because resolving
//                      a name to an AAAA record would have answered an address
//                      the connect could not use.  Connect() now opens the
//                      socket in whichever family this answers, so the
//                      constraint has moved off this line and onto the family
//                      the caller set - refer P2PeerConFamily_e
//
//  Returns:     int
//               0 on success; otherwise the getaddrinfo() result, which is a
//               WSA error code on Windows and an EAI_ code on Linux
//
static int
ResolveP2PeerConHost ( LPCSTR lpszHost, short nIPort, int nAiFamily
                     , SOCKADDR_STORAGE &rAddr, int &rnLen )
{
    memset ( &rAddr, 0, sizeof(rAddr) );
    rnLen = 0;

    if ( lpszHost == 0 || *lpszHost == 0 )
      return EAI_NONAME;

    //  The port travels as the SERVICE argument rather than being stamped in
    //  afterwards, so the one structure getaddrinfo() fills is complete and
    //  there is no second place for the port to be forgotten
    char szPort[16];
    std::snprintf ( szPort, sizeof(szPort), "%u"
                  , (unsigned)(unsigned short)nIPort );

    addrinfo  oHints;
    addrinfo *pResult = 0;
    memset ( &oHints, 0, sizeof(oHints) );
    oHints.ai_family   = nAiFamily;            // refer the note above
    oHints.ai_socktype = SOCK_STREAM;
    oHints.ai_protocol = IPPROTO_TCP;

    const int nResult = getaddrinfo ( lpszHost, szPort, &oHints, &pResult );
    if ( nResult != 0 )
      return nResult;
    if ( pResult == 0 )
      return EAI_NONAME;                       // success with no answer (SNHappen)

    //  The FIRST answer, which is what the resolver ordered for us.  A host
    //  with several records is answered in the order the platform prefers -
    //  under AF_UNSPEC that is RFC6724, which puts a reachable AAAA ahead of an
    //  A - and this connects to that one; trying the rest in turn is a
    //  different behaviour from the one being restored here and would change
    //  what a failed connect MEANS to the caller
    int nAnswer = 0;
    if ( ( pResult->ai_family != AF_INET && pResult->ai_family != AF_INET6 ) ||
           pResult->ai_addrlen == 0                                          ||
           pResult->ai_addrlen > (size_t)sizeof(SOCKADDR_STORAGE)               )
      nAnswer = EAI_FAMILY;                    // not a family we open (SNHappen)
    else
    {
      memcpy ( &rAddr, pResult->ai_addr, (size_t)pResult->ai_addrlen );
      rnLen = (int)pResult->ai_addrlen;
    }

    freeaddrinfo ( pResult );
    return nAnswer;
}

///////////////////////////////////////////////////////////////////////
//  Constructors, destructor and factories

const __time64_t
iLoginTimeoutSeconds = 20;             // Login sequences must be
                                       //   processed within this time

P2PeerConWsa::P2PeerConWsa ( )
{
    // Firstly
    RenderThisSafe ( );
}

//
//  Parameters:  P2PaddrSTR strThisP2Paddr
//               Identification address for this end
//
//               P2PaddrSTR strThatP2Paddr
//               Identification address for that, or the other end
//
//               DWORD oSocket
//               Socket upon which connection accepted
//
P2PeerConWsa::P2PeerConWsa ( P2PaddrSTR pThatP2PaddrSTR
                           , SOCKET   oSocket )
            : P2PeerCon ( pThatP2PaddrSTR )
{
    // Firstly
    RenderThisSafe ( );
    m_oSocket        =         oSocket;
    m_hFile          = (HANDLE)oSocket;

    m_eP2PeerConMode = P2PeerCon_Accept;
}

//
//               LPCTSTR lpszIPaddress
//               Connection address
//
//               short nIPort
//               Connection port.
//
P2PeerConWsa::P2PeerConWsa ( P2PaddrSTR pThatP2PaddrSTR
                           , LPCTSTR lpszIPaddress, short nIPort )
            : P2PeerCon ( pThatP2PaddrSTR )
{
    // Firstly
    RenderThisSafe ( );
    m_sIPaddress     = lpszIPaddress;
    m_nIPort         =    nIPort;
    m_eP2PeerConMode = P2PeerCon_CLIENT;
}

//
//               short nIPort
//               Listening port
//
P2PeerConWsa::P2PeerConWsa ( P2PaddrSTR pThatP2PaddrSTR
                           , short nIPort )
            : P2PeerCon ( pThatP2PaddrSTR )
{
    // Firstly
    RenderThisSafe ( );
    m_nIPort         =    nIPort;
    m_eP2PeerConMode = P2PeerCon_SERVICE;
}

P2PeerConWsa::~P2PeerConWsa ( )
{
    // Resource collection
    Drop ( 0 );
}

void
P2PeerConWsa::RenderThisSafe ( )
{
    // Properties
    m_nIPort        = 0;

    m_oSocket       = INVALID_SOCKET;
    m_oSocketAccept = INVALID_SOCKET;
    m_xBacklog      = DEF_P2PeerConBacklog;

    //  IPv4, every interface, and no source filter.  The behaviour of every
    //  caller written before these existed, which is the point: the mechanism
    //  is always present, what is opt-in is the restriction - and a family the
    //  caller did not ask for is a restriction like any other
    m_eFamily       = P2PeerConFamily_IPv4;
    m_eListenScope  = P2PeerConScope_Any;
    m_sListenAddress.Empty ( );
    m_pxSourceFilter.reset ( );
}

//
//  Sets the listen backlog for this SERVICE
//  NOTES: Takes effect at the next Listen(); a socket already listening keeps
//         the backlog it was given
//       : SOMAXCONN asks the stack for its maximum
//
void
P2PeerConWsa::SetBacklog ( int nBacklog )
{
    m_xBacklog = nBacklog > 0 ? nBacklog : DEF_P2PeerConBacklog;
}

//
//  Chooses the address family this connection opens in
//  NOTES: Takes effect at the next Listen() or Connect(), the same rule the
//         backlog and the scope state.  A socket already open keeps the family
//         it was opened in, because a family is not something a socket can be
//         talked into afterwards
//       : NOT validated against the host's stack here, and there is nowhere it
//         could usefully be.  A machine with IPv6 disabled fails at socket() or
//         at bind() with the stack's own reason, which names the problem better
//         than a guess made at configure time - and a probe here would be a
//         second opinion that could disagree with the one that matters
//
void
P2PeerConWsa::SetFamily ( P2PeerConFamily_e eFamily )
{
    m_eFamily = eFamily;
}

//
//  Description: AF_INET or AF_INET6 for the configured family
//               NOTES: The two v6 modes differ by IPV6_V6ONLY and not by
//                      family, so they answer the same thing here.  Listen()
//                      is where they part
//
//  Returns:     int
//               AF_INET or AF_INET6
//
int
P2PeerConWsa::SocketFamily ( ) const
{
    return IsFamilyIPv6 ( ) ? AF_INET6 : AF_INET;
}

//
//  Narrows where this SERVICE's listening socket binds
//  NOTES: The address is kept only for P2PeerConScope_Address and cleared for
//         the other two, so GetListenAddress() cannot describe an address that
//         is not the one bound
//       : Not validated here.  It is validated at Listen(), by
//         ListenBindSockaddr(), because that is where a failure can drop the
//         service - a setter that threw would put the decision in the caller's
//         constructor path, where this library has no way to report it
//       : Which FAMILY the address is read in is decided by SetFamily(), not by
//         the text.  A v6 literal on an IPv4 service is refused rather than
//         quietly promoting the service to v6: a scope says which of the host's
//         addresses to bind and has no business changing what is opened
//
void
P2PeerConWsa::SetListenScope ( P2PeerConScope_e eScope, LPCTSTR lpszIpAddress )
{
    m_eListenScope = eScope;
    if ( eScope == P2PeerConScope_Address && lpszIpAddress != 0 )
      m_sListenAddress = lpszIpAddress;
    else
      m_sListenAddress.Empty ( );
}

//
//  Adds one prefix, of either family, to the accept allow-list
//  NOTES: The FIRST call is what arms the filter.  Until one succeeds there is
//         no list and no restriction, so a service that never calls this is
//         the service that shipped before it existed
//       : Reports and answers false for an unparsable prefix rather than
//         throwing.  A rule is configuration, usually read from a file, and a
//         bad line in a config file is something an operator fixes - not
//         something that should take the process with it.  Answering false is
//         how the caller finds out, and the caller is expected to look
//       : The rule's family comes from its own text - refer
//         ParseP2PeerConPrefix().  It is NOT constrained to the family this
//         connection opens in, deliberately: an operator writing a policy file
//         should not have to re-order it when a service is dual-stacked, and a
//         rule for a family nothing opens can only ever fail to match
//
//  Returns:     bool
//               Whether the prefix was understood and added
//
bool
P2PeerConWsa::AllowAcceptFrom ( LPCTSTR lpszPrefix )
{
    int   nFamily = AF_INET;
    int   nBits   = 0;
    UCHAR ucAddr[16];
    if ( !ParseP2PeerConPrefix ( lpszPrefix, nFamily, ucAddr, nBits ) )
    {
      EVERR->Module (_N("%hs[%s]"), __FUNCTION__
                    , GetP2PaddrHub().c_wstr() )
           ->Message(_N("Unparsable accept prefix '%s'")
                    , lpszPrefix ? lpszPrefix : _T("(null)") )
           ->Advice_T("Dotted IPv4 with an optional /bits - \"192.168.1.0/24\", "
                      "\"10.0.0.0/8\", or \"10.1.2.3\" for one host")
           //  Advice_T is a FORMAT function, so the zone suffix is named
           //  rather than shown - a literal per cent sign here was eaten as a
           //  conversion and printed the advice as nonsense
           ->Advice_T("Or RFC4291 IPv6 with an optional /bits - "
                      "\"2001:db8::/32\", \"fd00::/8\", or \"::1\" for one "
                      "host.  A ':' is what makes it v6, and a per-cent zone "
                      "suffix is not accepted in a rule - a link-local "
                      "allow-list is spelt \"fe80::/10\"")
           ->Cancel ( );
      return false;
    }

    if ( !m_pxSourceFilter )
           m_pxSourceFilter = std::make_shared<P2PeerConWsaSourceFilter> ( );
    m_pxSourceFilter -> Add ( nFamily, ucAddr, nBits );
    return true;
}

//
//  This machine only
//  NOTES: The whole of 127.0.0.0/8 rather than 127.0.0.1, because the loopback
//         net is entirely local on both platforms and the suite's own tests
//         dial 127.0.0.2 and 127.0.0.3 to be two sources on one host
//       : ::1/128 and not ::1/8, because v6 has no loopback NET - the whole of
//         it is one address, and a wider v6 rule here would admit the
//         unspecified address and everything else in ::/8 along with it
//
void
P2PeerConWsa::AllowAcceptLoopback ( )
{
    AllowAcceptFrom ( _T("127.0.0.0/8") );      // IPv4 loopback net
    AllowAcceptFrom ( _T("::1")         );      // IPv6 loopback, /128
}

//
//  This machine and the private address space around it
//  NOTES: RFC1918 plus loopback plus link-local, and their v6 counterparts.  It
//         is the nearest an address test gets to "the LAN" and it is not a
//         proof of locality: anything upstream that rewrites a source address -
//         a NAT, a proxy, a load balancer - can present a public peer under a
//         private address, and this will admit it.  What it does buy is that a
//         host on the open internet, addressing this service directly, is
//         refused before it can speak.  Refer THREAT_MODEL.md B1
//       : fc00::/7 covers both halves of the unique-local space.  Only fd00::/8
//         is defined for self-assignment and fc00::/8 is reserved, but a
//         reserved half that arrives at all has been forged, and a rule that
//         admitted the defined half while a peer forged the reserved one would
//         be a distinction drawn on the wrong side
//       : NAT66 is rare and NPTv6 rarer, so a v6 peer's source address is far
//         more likely to be the one it really holds than a v4 peer's is.  That
//         makes this test STRONGER in v6 and is worth knowing, but it is still
//         a restriction rather than a proof
//
void
P2PeerConWsa::AllowAcceptPrivate ( )
{
    AllowAcceptFrom ( _T("127.0.0.0/8")    );   // this machine
    AllowAcceptFrom ( _T("10.0.0.0/8")     );   // RFC1918
    AllowAcceptFrom ( _T("172.16.0.0/12")  );   // RFC1918
    AllowAcceptFrom ( _T("192.168.0.0/16") );   // RFC1918
    AllowAcceptFrom ( _T("169.254.0.0/16") );   // RFC3927 link-local
    AllowAcceptFrom ( _T("::1")            );   // this machine, v6
    AllowAcceptFrom ( _T("fc00::/7")       );   // RFC4193 unique-local
    AllowAcceptFrom ( _T("fe80::/10")      );   // RFC4291 link-local
}

//
//  Removes the filter entirely, restoring "anyone who can reach the port"
//  NOTES: Distinct from a filter that matches nothing, and deliberately: there
//         is no way to spell an empty allow-list that admits everybody, so
//         clearing has to be its own verb
//
void
P2PeerConWsa::ClearAcceptSourceFilter ( )
{
    m_pxSourceFilter.reset ( );
}

bool
P2PeerConWsa::HasAcceptSourceFilter ( ) const
{
    return m_pxSourceFilter && !m_pxSourceFilter -> m_oPrefixes.empty ( );
}

//
//  May a peer at this origin be accepted?
//  NOTES: No filter means yes.  This is the ONLY answer that can be given to
//         an unconfigured service, and it is why arming the filter is the
//         operator's act rather than a default - refer DEF_P2PeerConAcceptSource
//         for the same argument made about the per-source bound
//       : An origin the transport cannot name means NO once a filter exists,
//         which is the opposite of SourceAtCapacity() and is argued at the
//         declaration.  Short version: a bound that cannot see its subject must
//         refuse nobody, and a policy that cannot see its subject must refuse it
//       : This is the form AcceptSpawn() asks, and the only one a v6 origin can
//         be put to.  It takes the address rather than the key because a prefix
//         match needs the bytes the key is a fold of
//       : A v4-MAPPED address is normalised here as well as in
//         AcceptSourceAddress(), which is a second normalisation of an address
//         that has already had one and is deliberate.  This is a PUBLIC
//         pre-flight - an application asking whether its own rules would admit
//         an address it holds - and an answer that differed from the accept
//         path's by the form the caller happened to write the address in would
//         be worse than no answer.  Normalising twice costs a compare; the two
//         paths disagreeing costs a production incident
//
//  Returns:     bool
//               Whether an accept from this origin is permitted
//
bool
P2PeerConWsa::IsAcceptSourceAllowed ( const struct sockaddr *pName
                                    , int nNameLen ) const
{
    if ( !HasAcceptSourceFilter ( ) )
      return true;
    if ( pName == 0 || nNameLen <= 0 ||
         nNameLen > (int)sizeof(SOCKADDR_STORAGE) )
      return false;                    // unnameable - refer the note above

    SOCKADDR_STORAGE oAddr;
    memset ( &oAddr, 0, sizeof(oAddr) );
    memcpy ( &oAddr, pName, (size_t)nNameLen );
    const int nAddr = NormaliseP2PeerConSockaddr ( oAddr, nNameLen );

    const UCHAR *pucAddr = 0;
    if ( P2PeerConAddrBytes ( (const sockaddr *)&oAddr, nAddr, pucAddr ) == 0 )
      return false;                    // unnameable - refer the note above

    return m_pxSourceFilter -> Matches ( oAddr.ss_family, pucAddr );
}

//
//  The IPv4 form, kept because it is what this class answered before there was
//  a second family
//  NOTES: The key holds a v4 address in NETWORK order - refer AcceptSourceKey()
//         - so it rebuilds the sockaddr the real test wants and asks that.  One
//         decision, reached two ways, rather than two decisions that could come
//         to differ
//       : A key with bit 63 set is a v6 FOLD, and an address cannot be
//         recovered from a fold.  Answers false, which is the same fail-closed
//         rule a zero key gets and for the same reason: a policy that cannot
//         see its subject refuses it.  A caller holding a v6 origin has the
//         sockaddr the key was made from and should ask with that
//
//  Returns:     bool
//               Whether an accept from this origin is permitted
//
bool
P2PeerConWsa::IsAcceptSourceAllowed ( P2PsourceKey xSource ) const
{
    if ( !HasAcceptSourceFilter ( ) )
      return true;
    if ( !xSource || ( xSource & ( 1ull << 63 ) ) )
      return false;

    sockaddr_in oPeer;
    memset ( &oPeer, 0, sizeof(oPeer) );
    oPeer.sin_family      = AF_INET;
    oPeer.sin_addr.s_addr = (u_long)(unsigned int)xSource;
    return IsAcceptSourceAllowed ( (const sockaddr *)&oPeer
                                 , (int)sizeof(oPeer) );
}

//
//  Description: The socket address this SERVICE's listening socket binds
//               NOTES: Throws for a scope it cannot honour rather than falling
//                      back to "every interface".  A restriction that silently
//                      becomes no restriction is asset S9 in THREAT_MODEL.md -
//                      a protection that is off and looks exactly like one that
//                      is on - and a listen scope is nothing but a restriction,
//                      so a scope that cannot be honoured has no honest
//                      fallback
//                    : A mask narrower than the family's full width is refused.
//                      "192.168.1.0/24" is a sensible thing to write in
//                      AllowAcceptFrom() and a meaningless thing to bind, and
//                      accepting it here would bind 192.168.1.0 - an address
//                      the host does not hold, failing later and for a reason
//                      that does not name the mistake
//                    : A literal of the WRONG family is refused too, and this
//                      is the one worth reading twice.  "127.0.0.1" on an
//                      AF_INET6 service could be bound as ::ffff:127.0.0.1,
//                      which is legal and would silently turn a dual-stack
//                      service into a v4-only one listening on one interface.
//                      An operator who wrote a v4 address and got a v4-only
//                      service back would have no way to see it happen
//                    : DUAL cannot express P2PeerConScope_Loopback and this
//                      refuses the pair.  ::1 is NOT the v4-mapped form of
//                      127.0.0.1 - the mapped form is ::ffff:127.0.0.1, a
//                      different address - so one socket cannot bind both
//                      loopbacks and there is no choice here that is not a
//                      silent narrowing.  Two loopbacks want two services, or
//                      one family named outright
//
//  Parameters:  SOCKADDR_STORAGE &rAddr
//               Filled with the bind address
//
//  Returns:     int
//               The address length, for bind()
//
int
P2PeerConWsa::ListenBindSockaddr ( SOCKADDR_STORAGE &rAddr )
{
    memset ( &rAddr, 0, sizeof(rAddr) );
    const int nFamily = SocketFamily ( );

    if ( m_eListenScope == P2PeerConScope_Loopback &&
         m_eFamily      == P2PeerConFamily_Dual       )
      EVERR->Module (_N("%hs[%s]"), __FUNCTION__
                    , GetP2PaddrHub().c_wstr() )
           ->Message(_N("P2PeerConFamily_Dual cannot bind a loopback scope") )
           ->Advice_T("::1 is not the v4-mapped form of 127.0.0.1, so one "
                      "socket cannot serve both loopbacks and either choice "
                      "here would silently narrow the other")
           ->Advice_T("SetFamily(P2PeerConFamily_IPv4) for 127.0.0.1, or "
                      "SetFamily(P2PeerConFamily_IPv6) for ::1")
           ->Advice_T("Both at once wants two SERVICE connections, one per "
                      "family")
           ->Throw ( );

    //  The nominated address, parsed once and checked for both the things that
    //  can be wrong with it - the width and the family
    UCHAR ucAddr[16];
    int   nAddrFamily = nFamily;
    int   nBits       = 0;
    memset ( ucAddr, 0, sizeof(ucAddr) );
    if ( m_eListenScope == P2PeerConScope_Address )
    {
      const int nFull = ( nFamily == AF_INET6 ) ? 128 : 32;
      if ( !ParseP2PeerConPrefix ( m_sListenAddress, nAddrFamily
                                 , ucAddr, nBits )   ||
            nBits       != nFull                     ||
            nAddrFamily != nFamily                      )
        EVERR->Module (_N("%hs[%s]"), __FUNCTION__
                      , GetP2PaddrHub().c_wstr() )
             ->Message(_N("Listen scope address '%s' is not a host address of "
                          "the configured family")
                      , (LPCTSTR)m_sListenAddress )
             ->Advice_T("SetListenScope(P2PeerConScope_Address,\"a.b.c.d\") "
                        "for P2PeerConFamily_IPv4, naming one interface THIS "
                        "host holds")
             ->Advice_T("SetListenScope(P2PeerConScope_Address,\"xxxx::yyyy\") "
                        "for P2PeerConFamily_IPv6 or _Dual - a v4 literal is "
                        "refused there rather than bound as ::ffff:a.b.c.d, "
                        "which would quietly make a dual service v4-only")
             ->Advice_T("P2PeerConScope_Loopback for this machine only")
             ->Throw ( );
    }

    if ( nFamily == AF_INET )
    {
      sockaddr_in *p4 = (sockaddr_in *)&rAddr;
      p4->sin_family = AF_INET;
      p4->sin_port   = htons ( m_nIPort );
      if ( m_eListenScope == P2PeerConScope_Loopback )
        p4->sin_addr.s_addr = htonl ( INADDR_LOOPBACK );
      else if ( m_eListenScope == P2PeerConScope_Address )
        memcpy ( &p4->sin_addr, ucAddr, 4 );
      else
        p4->sin_addr.s_addr = htonl ( INADDR_ANY );
      return (int)sizeof(sockaddr_in);
    }

    //  AF_INET6.  The two constant addresses are written byte-wise rather than
    //  taken from in6addr_any / in6addr_loopback, which are extern globals that
    //  a static or import-library arrangement has to resolve; sixteen zero
    //  bytes and a trailing 1 need nothing linked to be right
    sockaddr_in6 *p6 = (sockaddr_in6 *)&rAddr;
    p6->sin6_family = AF_INET6;
    p6->sin6_port   = htons ( m_nIPort );
    if ( m_eListenScope == P2PeerConScope_Loopback )
      p6->sin6_addr.s6_addr[15] = 1;                    // ::1
    else if ( m_eListenScope == P2PeerConScope_Address )
      memcpy ( p6->sin6_addr.s6_addr, ucAddr, 16 );
    // else :: - the memset above already wrote it
    return (int)sizeof(sockaddr_in6);
}

P2PeerConWsa*
P2PeerConWsa::ServiceFactory ( P2PaddrSTR strP2PaddrThat
                             , short nIPort )
{
    // Instanciate
    P2PeerConWsa *pCon = new P2PeerConWsa ( );

    // Attributes
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_oP2Padomain    = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_SERVICE;
    pCon -> m_nIPort         = nIPort;

    // Protocol
    // NOTES: Instance is cloned for accepted connections
    pCon -> SetP2Peerio ( new P2Peerio( ) );

    // Done
    return pCon;
}

P2PeerConWsa*
P2PeerConWsa::ClientFactory ( P2PaddrSTR strP2PaddrThat
                            , LPCTSTR lpszIPaddress, short nIPort )
{
    // Instanciate
    P2PeerConWsa *pCon = new P2PeerConWsa ( );

    // Attributes
    pCon -> m_oThatP2Paddr   = strP2PaddrThat;
    pCon -> m_eP2PeerConMode = P2PeerCon_CLIENT;
    pCon -> m_sIPaddress     = lpszIPaddress;
    pCon -> m_nIPort         = nIPort;

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
//
//  Description: The origin of the endpoint this SERVICE has just accepted,
//               whole
//               NOTES: Read from the ACCEPTED socket, which this object still
//                      owns at the moment AcceptSpawn() runs and hands away one
//                      statement later
//                    : getpeername() rather than anything the peer told us.  A
//                      peer has said nothing at this point - it has not logged
//                      in, and the whole reason a per-source bound is needed is
//                      that it may never intend to - so the only trustworthy
//                      origin is the one the kernel reports
//                    : SOCKADDR_STORAGE and not sockaddr_in.  A dual-stack
//                      service reports every peer as AF_INET6, and a v4-sized
//                      buffer handed to getpeername() would be told the address
//                      did not fit - answering "unnameable" for every peer of
//                      a service that was working perfectly
//                    : A v4-MAPPED origin is rewritten to the AF_INET address
//                      it stands for before it is answered, so everything above
//                      this line sees a v4 peer as a v4 peer whichever socket
//                      carried it.  Refer NormaliseP2PeerConSockaddr()
//
//  Parameters:  SOCKADDR_STORAGE &rAddr
//               Filled with the origin
//
//  Returns:     int
//               The address length, or 0 if the origin cannot be named
//
int
P2PeerConWsa::AcceptSourceAddress ( SOCKADDR_STORAGE &rAddr ) const
{
    memset ( &rAddr, 0, sizeof(rAddr) );
    if ( m_oSocketAccept == INVALID_SOCKET )
      return 0;

    socklen_t nLen = (socklen_t)sizeof(rAddr);
    if ( getpeername ( m_oSocketAccept, (sockaddr *)&rAddr, &nLen )
         == SOCKET_ERROR )
      return 0;
    if ( nLen <= 0 || nLen > (socklen_t)sizeof(rAddr) )
      return 0;                        // (SNHappen)

    const int nNormalised = NormaliseP2PeerConSockaddr ( rAddr, (int)nLen );

    //  Anything that is not one of the two families this transport opens is
    //  answered as unnameable rather than passed on.  Nothing downstream knows
    //  where such a thing keeps its address, and a length without a meaning is
    //  worse than none
    const UCHAR *pucAddr = 0;
    if ( P2PeerConAddrBytes ( (const sockaddr *)&rAddr, nNormalised, pucAddr )
         == 0 )
    {
      memset ( &rAddr, 0, sizeof(rAddr) );
      return 0;
    }
    return nNormalised;
}

//
//  Names the origin of the endpoint this SERVICE has just accepted, as one
//  accounting key
//  NOTES: A fold of AcceptSourceAddress(), which is the one call that reads the
//         socket.  Two answers derived from one reading cannot come to disagree
//         about who connected
//       : An IPv4 origin IS its address, in network byte order, exactly as it
//         has always been.  The key is an identity, not a number: nothing
//         compares it for magnitude, so normalising the order would buy
//         nothing.  The one place it IS rendered no longer reads the key at all
//       : An IPv6 origin is a hash of its /64 PREFIX with bit 63 set - refer
//         FoldP2PeerConV6Key() for why the prefix and why the bit
//       : A failure answers 0, which means "unbounded" rather than "refused".
//         The failure mode of an admission control that cannot identify its
//         subject has to be admitting, not refusing: the alternative is a
//         service that stops accepting the moment a getpeername() goes wrong.
//         The accept ALLOW-LIST reads the same 0 the other way, and that
//         difference is deliberate - refer IsAcceptSourceAllowed()
//
P2PsourceKey
P2PeerConWsa::AcceptSourceKey ( ) const
{
    SOCKADDR_STORAGE oPeer;
    const int        nLen = AcceptSourceAddress ( oPeer );
    return KeyP2PeerConSource ( oPeer, nLen );
}

//
//  Description: What this socket can vouch for about where its frames go
//
//               NOTES: Refer the block comment on the declaration in
//                      P2PeerConWsa.h for the argument.  The code is the
//                      argument in three lines: ask the kernel who the peer
//                      is, and if there is no peer to ask about, answer from
//                      the bind
//                    : m_oSocket and NOT m_oSocketAccept.  The second is the
//                      half-accepted endpoint a SERVICE holds for the instant
//                      between accept and AcceptSpawn(); by the time anything
//                      asks a connection what class it is, that socket has
//                      been handed to the child and is the child's m_oSocket
//                    : A getpeername() that FAILS falls through to the listen
//                      scope rather than answering Wire outright, because the
//                      commonest failure here is ENOTCONN on a service's
//                      listening socket - which is precisely the case the
//                      fallback exists for.  Every other failure lands on
//                      Wire, which is the fail-closed direction
//
//  Returns:     P2PeerConTrust_e
//               P2PeerConTrust_Local for a link the kernel keeps on this
//               machine, P2PeerConTrust_Wire otherwise
//
P2PeerConTrust_e
P2PeerConWsa::TrustClass ( ) const
{
    if ( m_oSocket != INVALID_SOCKET )
    {
      SOCKADDR_STORAGE oPeer;
      memset ( &oPeer, 0, sizeof(oPeer) );
      socklen_t nLen = (socklen_t)sizeof(oPeer);
      if ( getpeername ( m_oSocket, (sockaddr *)&oPeer, &nLen ) != SOCKET_ERROR
           && nLen > 0 && nLen <= (socklen_t)sizeof(oPeer) )
      {
        const int nNormalised = NormaliseP2PeerConSockaddr ( oPeer, (int)nLen );
        return IsP2PeerConSockaddrLoopback ( (const sockaddr *)&oPeer
                                           , nNormalised )
                 ? P2PeerConTrust_Local
                 : P2PeerConTrust_Wire;
      }
    }

    //  No peer to name: a SERVICE, or a client that has not dialled.  What it
    //  BOUND is then the only kernel fact available, and it is the honest
    //  answer for a posture reading of an object that carries no traffic
    if ( m_eListenScope == P2PeerConScope_Loopback )
      return P2PeerConTrust_Local;

    return P2PeerConTrust_Wire;
}

P2PeerCon*
P2PeerConWsa::AcceptSpawn ( P2PeerCon *pConSpawn )
{
    // To be sure, to be sure
    if ( m_oSocketAccept == INVALID_SOCKET )
      return 0;

    // Accept admission control
    // NOTES: Refused HERE, before the connection object is allocated, because
    //        this is the last point that still owns the accepted socket and
    //        can close it.  The base AcceptSpawn() cannot refuse: this
    //        override ignores its return and assigns the socket afterwards
    //      : Returning 0 is an established outcome, not a new one - the
    //        INVALID_SOCKET guard above has always returned it, and
    //        P2PeerTarget::On_ConAccept() tests the spawn for NULL and then
    //        re-arms the SERVICE unconditionally.  So a refusal costs the
    //        refused peer its connection and costs the service nothing
    //      : Closed rather than left pending. A refused peer must see the
    //        connection go, or a bound on accepted connections would just move
    //        the unbounded growth into the backlog
    //      : THREE tests, checked in this order and reported apart, because
    //        which one refused is the whole diagnostic.  "At capacity" on a
    //        service holding two of a thousand slots is not a service that is
    //        full - it is one source that has taken its share, and an operator
    //        told the wrong one of those will raise the wrong number
    //      : The allow-list is asked FIRST, and not because it is cheaper.  A
    //        peer that is not permitted here is not permitted whether or not
    //        there was room for it, and reporting "at capacity" to a source
    //        that would have been refused by an empty service is the same
    //        wrong-number failure one paragraph up.  It also keeps a refused
    //        origin out of the per-source tally, which exists to account for
    //        peers the service is carrying
    //      : ONE reading of the socket, then two answers derived from it.  The
    //        key and the allow-list decision both used to call getpeername()
    //        for themselves, which was affordable while both wanted the same
    //        four bytes and is not now that one wants the address and the other
    //        wants a fold of it.  Two readings could also disagree - a socket
    //        can be torn down between them - and an accept refused by one
    //        answer and counted by the other is the kind of inconsistency that
    //        is only ever found in production
    SOCKADDR_STORAGE   oSource;
    const int          nSource = AcceptSourceAddress ( oSource );
    const P2PsourceKey xSource = KeyP2PeerConSource   ( oSource, nSource );
    const bool bNotAllowed     = !IsAcceptSourceAllowed ( (const sockaddr *)
                                                          &oSource, nSource );
    const bool bServiceFull    = !bNotAllowed && AcceptAtCapacity ( );
    const bool bSourceFull     = !bNotAllowed && !bServiceFull &&
                                 SourceAtCapacity ( xSource );
    if ( bNotAllowed || bServiceFull || bSourceFull )
    {
      if ( IsEVTRC )
      {
        //  Rendered from the ADDRESS rather than from the key, which since
        //  2026-08-28 is a fold for a v6 origin and cannot be printed back as
        //  one.  getnameinfo() also spells an address the way every other tool
        //  on the host spells it, which is what an operator needs when they go
        //  to compare a refusal line against the allow-list that caused it
        //  NOTES: 64 rather than NI_MAXHOST, which is 1025 on Windows, is
        //         guarded behind a feature macro on some Linux headers, and is
        //         sized for a DNS name this deliberately never asks for.  The
        //         longest NUMERIC form is 45 characters, so 64 holds every
        //         answer this call can produce with room to spare
        char szSource[64];
        RenderP2PeerConAddr ( (const sockaddr *)&oSource, nSource
                            , szSource, sizeof(szSource) );
        if ( bNotAllowed )
          EVTRC->Module (_N("%hs[%s]"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr() )
               ->Message(_N("Accept refused, source %hs is not on the "
                            "allow-list"), szSource )
               ->Advice_T("P2PeerConWsa::AllowAcceptFrom() to admit it, or "
                          "ClearAcceptSourceFilter() to admit anyone")
               ->Advice_T("An unnameable origin is refused by design, and so "
                          "is a peer of a family no rule was written for - a "
                          "list of v4 prefixes refuses every v6 source")
               ->Cancel ( );
        else if ( bServiceFull )
          EVTRC->Module (_N("%hs[%s]"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr() )
               ->Message(_T("Accept refused, at capacity %i"), m_xMaxAccepted )
               ->Advice_T("Raise P2PeerCon::SetMaxAccepted(), or 0 to unbound")
               ->Cancel ( );
        else
          EVTRC->Module (_N("%hs[%s]"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr() )
               ->Message(_N("Accept refused, source %hs at its share %i of %i")
                        , szSource
                        , m_xMaxAcceptedPerSource, m_xMaxAccepted )
               ->Advice_T("Raise P2PeerCon::SetMaxAcceptedPerSource(), or 0 "
                          "to unbound.  The SERVICE is not full - this one "
                          "source is")
               ->Advice_T("An IPv6 source is accounted by its /64, which is "
                          "the block one host is delegated - two addresses in "
                          "one /64 share this share deliberately")
               ->Cancel ( );
      }

      closesocket ( m_oSocketAccept );
      m_oSocketAccept = INVALID_SOCKET;
      return 0;
    }

    // Instanciation etc
    if ( pConSpawn == NULL )
      pConSpawn = new P2PeerConWsa ( );

    // Settlement
    // NOTES: Accept removes the allocated socket
    //      : The FAMILY travels with it, and is the one thing on this object a
    //        child does inherit.  It is not a policy - the caps and the
    //        allow-list are, and a child governs nothing so it is handed
    //        neither - it is a FACT about the socket being handed over, which
    //        this SERVICE opened and the child now owns.  A child left at the
    //        default would report IPv4 in a diagnostic dump while holding an
    //        AF_INET6 socket, which is the wrong kind of wrong to leave in a
    //        dump an operator reads to find out what is open
    P2PeerConWsa *pConSpawnWsa = (P2PeerConWsa *)pConSpawn;
    P2PeerCon::AcceptSpawn ( pConSpawn );
    pConSpawnWsa -> m_eFamily =         m_eFamily;
    pConSpawnWsa -> m_oSocket =         m_oSocketAccept;
    pConSpawnWsa -> m_hFile   = (HANDLE)m_oSocketAccept;
                                        m_oSocketAccept = INVALID_SOCKET;

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
bool
P2PeerConWsa::On_QueuedCompletionStatus ( DWORD dwError
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
        //        notification        releaseOVERLAPPED ( pOVERLAPPEDcon );
        releaseOVERLAPPED ( pOVERLAPPEDcon );
        if ( hr )
          EVERR->Module (_N("%hs[%s-%s]"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , (P2PaddrSTR)m_oThatP2Paddr )
               ->Message("Overlapped accept failed")
               ->HResult( hr ) -> Throw();

        // Accept the new connection
        // NOTES: Depending upon machine load several connections
        //        may be waiting to be accepted
        if ( m_oSocketAccept != INVALID_SOCKET )
        {
          //  NOTES: The three lengths MUST be the ones AcceptEx() was given
          //         or the two pointers below address the wrong offsets in the
          //         buffer.  They were 16 and 16 while AcceptEx() has been
          //         called with sizeof(SOCKADDR_STORAGE)+16 - harmless only
          //         because nothing has ever read the results: the origin of an
          //         accepted connection is taken from getpeername() instead,
          //         in AcceptSourceAddress(), which needs no buffer arithmetic
          //         to be right.  Corrected in the same week the dual-stack
          //         port was taken rather than deleted, because a v6 peer
          //         parsed at a v4 offset is the kind of wrong that looks right
          //       : getpeername() remains the origin even now that a v6 peer
          //         can arrive, and deliberately.  It reads the socket the
          //         kernel has already finished with, so it cannot be told the
          //         wrong offset by anything - which is the whole reason the
          //         defect above was harmless and the reason it stays unused
          //       : The receive length is 0 here and 0 there.  No data is taken
          //         with the accept, so nothing unauthenticated is buffered
          //         before the login gate - refer THREAT_MODEL.md B1
          LPSOCKADDR pSockaddrLocal;
          int        iSizeLocal = 0;
          LPSOCKADDR pSockaddrRemote;
          int        iSizeRemote = 0;
          GetAcceptExSockaddrs ( pOVERLAPPEDcon->pBuffer
                               , 0//pOVERLAPPEDcon->dwBytesMax -16 -16
                               , sizeof(SOCKADDR_STORAGE) + 16
                               , sizeof(SOCKADDR_STORAGE) + 16
                               ,&pSockaddrLocal, &iSizeLocal
                               ,&pSockaddrRemote, &iSizeRemote );

          if ( setsockopt( m_oSocketAccept, SOL_SOCKET
                         , SO_UPDATE_ACCEPT_CONTEXT
                         , (char *)&m_oSocket, sizeof(m_oSocket) ) )
          {
            EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                          , GetP2PaddrHub().c_wstr()
                          , m_oThatP2Paddr.c_wstr() )
                 ->Message("setsockopt() failed")
                 ->HResult( WSAGetLastError() )->Throw();
          }

          // Configure non-blocking mode
          DWORD dwArg = 1;
          if ( ioctlsocket ( m_oSocketAccept, FIONBIO, &dwArg ) )
            EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                           , GetP2PaddrHub().c_wstr()
                           , m_oThatP2Paddr.c_wstr() )
                 ->Message ("ioctlsocket(FIONBIO) failed")
                 ->Group("WSA")->HResult(WSAGetLastError() )->Throw();
          // Split into listening, usually this, and accepted P2PeerCon
          // NOTES: The underlying P2PeerCon objects have different styles
          //        according to the derived type.
          //P2PeerCon *pConAccept = 0, *pConListen = 0;
          //AcceptSplit ( &pConListen, &pConAccept );

          // ON_P2PeerOLD_ACCEPT() notification
          // NOTES: Accepted P2PeerCon is spawned within the handler
          PostP2Pmsg ( GetP2Paddress(), CN_P2PeerCon, P2P_Accept
                     , this, 0, m_hCPortP2PumpID );

          // ON_P2PeerCon_LISTEN() notification
          // NOTES: Listen for new connection
          //PostP2Pmsg ( pConListen->GetP2Paddress(), CN_P2PeerCon, P2P_Listen
          //           , pConListen, 0 );
        }

        // Observe expectations
        /*else
          EVERR->Module (_N("%hs[%s-%s]"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , m_oThatP2Paddr.c_wstr() )
               ->Message("Overlapped accept without assigned socket")
               ->Throw ( );*/
      }

      // Connect
      // NOTES: Perform On_P2PeerWsa_CONNECT() notification.  At which
      //        point the intercepting handler will initiate the
      //        appropriate state changes.
      else if ( pOVERLAPPEDcon == m_pOVERLAPPEDconnect )
      {
        releaseOVERLAPPED ( pOVERLAPPEDcon );
        if ( hr )
          EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                         , GetP2PaddrHub().c_wstr()
                         , m_oThatP2Paddr.c_wstr() )
               ->Message ("Overlapped ConnectEx failed")
               ->HResult ( hr ) -> Throw();

        // Retrieve socket options
        if ( setsockopt( m_oSocket, SOL_SOCKET
                       , SO_UPDATE_CONNECT_CONTEXT
                       , NULL, 0 ) )
          EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , m_oThatP2Paddr.c_wstr() )
               ->Message ("setsockopt() failed")
               ->HResult ( WSAGetLastError() )->Throw();

        // ON_P2PeerCon_CONNECT() notification
        // NOTES: Send() and Recv() buffers required beyond this point
        if ( m_pOVERLAPPEDsend == NULL )
          m_pOVERLAPPEDsend = MakeOVERLAPPED (  );
        if ( m_pOVERLAPPEDrecv == NULL )
          m_pOVERLAPPEDrecv = MakeOVERLAPPED ( m_pP2Peerio->GetMaxRecvSize() );

        PostP2Pmsg  ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Connect
                    , this, (P2PeerMsg *)0, m_hCPortP2PumpID );
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
    return true;
}

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
P2PeerConWsa::Drop ( P2Pevent *pEVENT )
{
    // Firstly drop socket
    // NOTES: Cancels all outstanding overlapped IO
    if ( m_oSocket != INVALID_SOCKET )
    {
      if (   closesocket(m_oSocket) &&
           !pEVENT                     )
        pEVENT =
         EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , m_oThatP2Paddr.c_wstr() )
              ->Message ("closesocket(connect) failed" )
              ->Advice  ("Bug (SNHappen)" )
              ->HResult ( GetLastError() );
      m_hFile      = 0;
      m_hFileCPort = 0;
      m_oSocket    = INVALID_SOCKET;
    }

    // Secondly drop accept socket
    // NOTES: Cancels all outstanding overlapped IO
    if ( m_oSocketAccept != INVALID_SOCKET )
    {
      if (   closesocket(m_oSocketAccept) &&
           !pEVENT                           )
        pEVENT =
         EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                        , GetP2PaddrHub().c_wstr()
                        , m_oThatP2Paddr.c_wstr() )
              ->Message ("closesocket(accept) failed" )
              ->Advice  ("Bug (SNHappen)" )
              ->HResult ( GetLastError() );
      m_oSocketAccept = INVALID_SOCKET;
    }

    // Always delegate
    P2PeerCon::Drop ( pEVENT );
}

///////////////////////////////////////////////////////////////////////
//  Connection state management 
//  NOTES: Referenced from P2PeerCon_MAP handlers only

//
//  Description: Initiates listening state processing for object.
//               NOTES: Referenced from On_P2PeerCon_STARTUP handlers
//                      for listening type objects.
//
//
//  Returns:     bool
//               Previous listening status
//                 true... Already listening
//                 false.. Not listening
//
bool
P2PeerConWsa::Listen ( )
{
    // Introduce locals
    ASSERT(m_nIPort>100);

    // To be sure, to be sure
    if ( m_oSocket != INVALID_SOCKET )
      return true;

    // Because this is all problematic, we
    try
    {
      // Create socket
      // NOTES: The family is the one SetFamily() asked for - refer
      //        P2PeerConFamily_e.  AF_INET remains the default and remains what
      //        a caller that never sets a family gets, so this opens nothing
      //        that was not already open
      m_oSocket = WSASocket ( SocketFamily ( ), SOCK_STREAM, IPPROTO_IP
                            , 0//&oWsaProtocolInfo
                            , 0
                            , WSA_FLAG_OVERLAPPED );
      if ( m_oSocket == INVALID_SOCKET )
        EVERR->Module  (_N("%hs(%s)"), __FUNCTION__
                       , GetP2PaddrHub().c_wstr() )
             ->Message ("WSASocket() failed" )
             ->Advice  ("No free sockets?" )
             ->Advice  ("Network problem?)")
             ->Advice  ("An IPv6 family on a host whose stack is disabled?" )
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();

      // Dual stack, or not
      // NOTES: Set EXPLICITLY in BOTH directions and never left to the
      //        platform, because the platforms disagree: Windows defaults
      //        IPV6_V6ONLY on and most Linux distributions default it off, so a
      //        socket that did not say would be v6-only on one build and
      //        dual-stack on the other from identical source.  A dual-stack
      //        service that quietly is not one, and a v6-only service that
      //        quietly admits v4, are both asset S9 in THREAT_MODEL.md - a
      //        protection whose real state cannot be read off the code
      //      : FATAL rather than best-effort, unlike the TCP_NODELAY calls
      //        elsewhere here.  Nagle is a performance setting and this is the
      //        boundary of what the service will talk to; a service that came
      //        up meaning something other than what it was told is worse than
      //        one that did not come up
      if ( IsFamilyIPv6 ( ) )
      {
        DWORD dwV6Only = ( m_eFamily == P2PeerConFamily_Dual ) ? 0 : 1;
        if ( setsockopt ( m_oSocket, IPPROTO_IPV6, IPV6_V6ONLY
                        , (const char *)&dwV6Only, sizeof dwV6Only ) )
          EVERR->MODULE
               ->Message ("setsockopt(IPV6_V6ONLY,%u) failed"
                         , (unsigned)dwV6Only )
               ->Advice  ("The family cannot be honoured, and a listening "
                          "socket that admits a different set of peers from "
                          "the one it was configured for must not be stood up")
               ->Group("WSA")->HResult(WSAGetLastError() )->Throw();
      }

      // Bind socket
      // NOTES: The bind address is the listen SCOPE in the configured FAMILY -
      //        refer P2PeerConScope_e and P2PeerConFamily_e.  "Every
      //        interface" remains the default and remains what a caller that
      //        never sets a scope gets, so this narrows nothing that already
      //        exists
      //      : Zeroed, and by ListenBindSockaddr() rather than here.  sin_zero
      //        was left uninitialised at this site from the import; bind() has
      //        never read it on either platform, but a sockaddr this code
      //        computes a field of is not one to hand over part-filled - and a
      //        sockaddr_in6 has two more fields that MUST be zero
      SOCKADDR_STORAGE oSockAddr;
      const int        nSockAddr = ListenBindSockaddr ( oSockAddr );

      if ( bind ( m_oSocket
                , (PSOCKADDR)&oSockAddr, nSockAddr ) )
        EVERR->MODULE
             ->Message ("Bind(%i) failed", m_nIPort )
             ->Advice  ("Network problem?" )
             ->Advice  ("A listen scope naming an address this host does "
                        "not hold?" )
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();

      // Associate with IO Completion Port
      // NOTES: All subsequent notifications received via queued
      //        IO Completion Packets
      CreateIOCP ( (HANDLE)m_oSocket );
      //m_hFileCPort = CreateIoCompletionPort ( (HANDLE)m_oSocket
      //                                      , m_hCPort
      //                                      ,(ULONG_PTR)(P2PeerCon *)this
      //                                      , 0 );
      //if ( m_hFileCPort == 0 )
      //  EVERR->Module  ("%s(%s-%s)", __FUNCTION__
      //                 , EncodeP2PeerID(m_oThisP2Paddr)
      //                 , EncodeP2PeerID(m_oThatP2Paddr) )
      //       ->Message ("CreateIoCompletionPort() failed")
      //       ->WSAGROUP( WSAGetLastError() )->Throw();

      // Listen
      if ( listen ( m_oSocket, m_xBacklog ) )
        EVERR->MODULE
             ->Message ("listen() failed" )
             ->Advice  ("Network problem? (SNHappen)" )
             ->Group("WSA")->HResult(WSAGetLastError() )
             ->Throw();

      // On_P2PeerCon_LISTEN() notification
      PostP2Pmsg ( m_oThatP2Paddr, CN_P2PeerCon, P2P_Listen
                 , this, (P2PeerMsg *)0, m_hCPortP2PumpID );
    }

    // Exceptions
    // NOTES: Perform P2PeerCon_CLOSE notification
    catch ( P2Pevent *pEVENT )
    {
      Drop ( pEVENT->Isolate() );
    }

    // Tidy up and
    return false;
}

//
//  Description: Completes listening state processing for object.
//               NOTES: Referenced from On_P2PeerCon_LISTEN handlers
//                      for listening type objects.
//
void
P2PeerConWsa::OnListen ( )
{
    // Always delegate
    P2PeerCon::OnListen();
}

//
//  Description: Initiates accept facility for object.
//               NOTES: Referenced from On_P2PeerCon_LISTEN handlers
//                      for listening type objects.
//                    : Accepted connections are processed via
//                      ON_P2PeerOLD_ACCEPT handlers
//
//
//  Returns:     bool
//
bool
P2PeerConWsa::Accept ( )
{
    // Always delegate
    P2PeerCon::Accept ( );

    // To be sure, to be sure
    if ( m_oSocketAccept != INVALID_SOCKET )
      return true;

    // Because this is all problematic, we
    try
    {
      // To be sure, to be sure
      if ( GetMode() != P2PeerCon_SERVICE )
        EVERR->Module (_N("%hs[%s-%s]"), __FUNCTION__
                      , GetP2PaddrHub().c_wstr()
                      , m_oThatP2Paddr.c_wstr() )
             ->Message("Operation only valid for listening type sockets" )
             ->Advice ("Bug (SNHappen)" )
             ->Throw();

      // To be sure, to be sure
      if ( m_oSocket == INVALID_SOCKET )
        EVERR->Module (_N("%hs[%s-%s]"), __FUNCTION__
                      , GetP2PaddrHub().c_wstr()
                      , m_oThatP2Paddr.c_wstr() )
             ->Message("Listening socket has not been assigned" )
             ->Advice ("Bug (SNHappen)" )
             ->Throw();

      // To be sure, to be sure
      if (   m_oSocketAccept != INVALID_SOCKET ||
           ( m_pOVERLAPPEDaccept          &&
             m_pOVERLAPPEDaccept->bQueued    )     )
        EVERR->Module (_N("%hs[%s-%s]"), __FUNCTION__
                      , GetP2PaddrHub().c_wstr()
                      , m_oThatP2Paddr.c_wstr() )
             ->Message("Duplicate accepts attempted on single socket" )
             ->Advice ("Bug (SNHappen)" )
             ->Throw();

      // Create socket
      // NOTES: Pre-allocated socket is required to accept connection
      //      : The family MUST be the LISTENING socket's, which is what
      //        SocketFamily() answers on this same SERVICE object.  AcceptEx()
      //        refuses a pair that does not match, so a dual-stack service with
      //        an AF_INET accept socket would fail every accept - and fail it
      //        at the arm, where the diagnostic names AcceptEx and not the
      //        family
      m_oSocketAccept = WSASocket ( SocketFamily ( ), SOCK_STREAM, IPPROTO_TCP //changed from IPPROTO_IP for Webwerver
                                  , 0//&oWsaProtocolInfo
                                  , 0
                                  , WSA_FLAG_OVERLAPPED );
      if ( m_oSocketAccept == INVALID_SOCKET )
        EVERR->Module  (_N("%hs(%s)"), __FUNCTION__
                       , GetP2PaddrHub().c_wstr() )
             ->Message ("WSASocket() failed" )
             ->Advice  ("No free sockets?" )
             ->Advice  ("Network problem?" )
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();

      // Disable Nagle on the data socket: P2Pmsg frames are small and latency-
      // sensitive; Nagle + delayed-ACK otherwise adds hundreds of microseconds
      // per hop and throttles small-message throughput (measured A/B).
      // Best-effort — a failure here is not fatal to the connection.
      { DWORD dwNoDelay = 1;
        setsockopt ( m_oSocketAccept, IPPROTO_TCP, TCP_NODELAY
                   , (const char*)&dwNoDelay, sizeof dwNoDelay ); }

      // Configure non-blocking mode
      DWORD dwArg = 1;
      if ( ioctlsocket ( m_oSocketAccept, FIONBIO, &dwArg ) )
        EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                       , GetP2PaddrHub().c_wstr()
                       , m_oThatP2Paddr.c_wstr() )
             ->Message ("ioctlsocket(FIONBIO) failed")
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();

      // Accept
      // NOTES: AcceptEx returns TRUE on SYNCHRONOUS completion (a connection was already
      //        waiting in the backlog — routine when a remote dialer retried while no accept
      //        was pended). WSAGetLastError() is STALE in that case; testing it without the
      //        return value misdiagnosed the sync success as failure and dropped the SERVICE
      //        con. The IOCP-bound listen socket still queues the completion packet
      //        (FILE_SKIP_COMPLETION_PORT_ON_SUCCESS is never set), so sync success needs no
      //        further action here.
      //  NOTES: The +16+16 dated from the 16-byte address lengths this call
      //         no longer passes.  Sized to what AcceptEx is actually told, so
      //         the buffer and the three lengths cannot drift apart again -
      //         MAX_P2Psize alone was already far more than the 288 bytes of
      //         address space needed, but a size that happens to be enough is
      //         not a size that says why
      if ( m_pOVERLAPPEDaccept == NULL )
        m_pOVERLAPPEDaccept = MakeOVERLAPPED ( MAX_P2Psize
                                             + 2 * ( sizeof(SOCKADDR_STORAGE)
                                                   + 16 ) );
      //DWORD dwBytesReceived = 0;
      prepareOVERLAPPED ( m_pOVERLAPPEDaccept );
      BOOL bAccepted =
      AcceptEx ( m_oSocket
               , m_oSocketAccept
               , m_pOVERLAPPEDaccept->pBuffer // lpOutputBuffer,
               , 0//m_pOVERLAPPEDaccept->dwBytesMax - 16 - 16//DWORD dwReceiveDataLength,
               , sizeof(SOCKADDR_STORAGE) + 16//DWORD dwLocalAddressLength,
               , sizeof(SOCKADDR_STORAGE) + 16//DWORD dwRemoteAddressLength,
               ,&m_pOVERLAPPEDaccept->dwBytes
               , (OVERLAPPED *)m_pOVERLAPPEDaccept );
      if ( !bAccepted                             &&
            WSAGetLastError() != ERROR_IO_PENDING    )
      {
        releaseOVERLAPPED ( m_pOVERLAPPEDaccept );
        EVERR->MODULE
             ->Message ("AcceptEx() failed" )
             ->Advice  ("Network problem?" )
             ->Advice  ("Firewall configuration" )
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();
      }
    }

    // Exceptions
    // NOTES: Perform P2PeerCon_CLOSE notification
    catch ( P2Pevent *pEVENT )
    {
      Drop ( pEVENT->Isolate() );
    }

    // Tidy up and
    return false;
}

//
//  Description: Initiates connection processing for object.
//               NOTES: Referenced from On_P2PeerCon_STARTUP handlers
//                      for connection type objects.
//
//
//  Returns:
//
bool
P2PeerConWsa::Connect ( )
{
    // Always delegate
    P2PeerCon::Connect ( );

    // Introduce locals
    ASSERT(m_nIPort>100);

    // To be sure, to be sure
    if ( m_oSocket != INVALID_SOCKET )
      return true;

    // Because this is all problematic, we
    try
    {
      // Resolve host name
      // NOTES: Empty address flags self connection
      //      : BEFORE the socket, which is the order this has to be done in
      //        since 2026-08-28 and was not before.  The family the socket is
      //        opened in is the family the resolver ANSWERED - under
      //        P2PeerConFamily_Dual that can be either - so the socket cannot
      //        be created until the answer is in.  Resolving first costs
      //        nothing: it touches no socket and needs none
      CStringA csIpAddress = m_sIPaddress.GetString();
      if ( csIpAddress.IsEmpty() )
      {
        char szIpAddress[512];
        if ( gethostname( szIpAddress, sizeof(szIpAddress) ) )
          EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                         , GetP2PaddrHub().c_wstr()
                         , m_oThatP2Paddr.c_wstr() )
               ->Message("gethostname() failed" )
               ->Advice ("Local host has no name")
               ->Group("WSA")->HResult(WSAGetLastError())->Throw();
        csIpAddress = szIpAddress;
      }

      // Prepare address details
      // NOTES: One resolver call for both a literal and a name - refer
      //        ResolveP2PeerConHost(), and the defect it closes
      //      : The name reported is the one actually RESOLVED, which for a self
      //        connection is gethostname()'s answer and not m_sIPaddress.
      //        Reporting the member would name an empty string in exactly the
      //        case the operator most needs to see what was looked up
      //      : The family asked for is the CONFIGURED one - A records for
      //        IPv4, AAAA for IPv6, and either for Dual.  A name that holds
      //        only the other kind is unreachable and says so, which is the
      //        honest answer: silently widening the question would dial a host
      //        the caller did not ask to be able to reach
      SOCKADDR_STORAGE oSockaddr;
      int              nSockaddr = 0;
      const int        nAiFamily =
        ( m_eFamily == P2PeerConFamily_Dual ) ? AF_UNSPEC : SocketFamily ( );

      const CString csResolved ( csIpAddress );
      const int     nResolved = ResolveP2PeerConHost ( (LPCSTR)csIpAddress
                                                     , m_nIPort, nAiFamily
                                                     , oSockaddr, nSockaddr );
      if ( nResolved != 0 )
        EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                       , GetP2PaddrHub().c_wstr()
                       , m_oThatP2Paddr.c_wstr() )
             ->Message (_N("getaddrinfo(%s) failed"), (LPCTSTR)csResolved )
             ->Advice  ("Unable to resolve server" )
             ->Advice  ("A name with no record of the configured family?  "
                        "P2PeerConFamily_IPv4 asks for A records only and "
                        "_IPv6 for AAAA only; SetFamily(P2PeerConFamily_Dual) "
                        "takes either" )
             ->Group("WSA")->HResult( nResolved )->Throw();

      // Create socket
      // NOTES: Opportunity to define our own protocol here
      //      : WSA_FLAG_OVERLAPPED is mandatory when using IO
      //        completion ports
      //      : The family is the RESOLVED address's and not the configured
      //        one, which are the same thing except under Dual - where the
      //        resolver has just chosen between them on this host's own
      //        RFC6724 preference.  A socket opened in the configured family
      //        and then handed an address of the other is the failure this
      //        ordering exists to make impossible
      m_oSocket = WSASocket ( oSockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP //changed from IPPROTO_IP for Webwerver
                            , 0//&oWsaProtocolInfo
                            , 0
                            , WSA_FLAG_OVERLAPPED );
      if ( m_oSocket == INVALID_SOCKET )
        EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                       , GetP2PaddrHub().c_wstr()
                       , m_oThatP2Paddr.c_wstr() )
             ->Message ("WSAsocket() failed")
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();

      // Disable Nagle (see the accept-socket path above): small latency-sensitive
      // frames must flush immediately. Best-effort — non-fatal on failure.
      { DWORD dwNoDelay = 1;
        setsockopt ( m_oSocket, IPPROTO_TCP, TCP_NODELAY
                   , (const char*)&dwNoDelay, sizeof dwNoDelay ); }

      // Associate with IO Completion Port
      // NOTES: All subsequent notifications received via queued
      //        IO Completion Packets
      CreateIOCP ( (HANDLE)m_oSocket );
      //m_hFileCPort = CreateIoCompletionPort ( (HANDLE)m_oSocket
      //                                      , m_hCPort
      //                                      ,(ULONG_PTR)(P2PeerCon *)this
      //                                      , 0 );
      //if ( m_hFileCPort == 0 )
      //  EVERR->Module  ("%s(%s-%s)", __FUNCTION__
      //                 , EncodeP2PeerID(m_oThisP2Paddr)
      //                 , EncodeP2PeerID(m_oThatP2Paddr) )
      //       ->Message ("CreateIoCompletionPort() failed")
      //       ->WSAGROUP( WSAGetLastError() )->Throw();
      //m_hFile = (HANDLE)m_oSocket;

      // Configure non-blocking mode
      DWORD dwArg = 1;
      if ( ioctlsocket ( m_oSocket, FIONBIO, &dwArg ) )
        EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                       , GetP2PaddrHub().c_wstr()
                       , m_oThatP2Paddr.c_wstr() )
             ->Message ("ioctlsocket(FIONBIO) failed")
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();

      // Overlapped preparation
      if ( m_pOVERLAPPEDconnect == NULL )
        m_pOVERLAPPEDconnect = MakeOVERLAPPED ( 0 );

      // ConnectEx implementation
      // NOTES: Notification occurs via IO Completion Port
      //      : Operation must return ERROR_IO_PENDING state
      DWORD dwBytes = 0;
      prepareOVERLAPPED ( m_pOVERLAPPEDconnect );
      ConnectEx ( m_oSocket
                ,(struct sockaddr *)&oSockaddr, nSockaddr
                , NULL, 0, &dwBytes
                , m_pOVERLAPPEDconnect );
      if ( WSAGetLastError() != ERROR_IO_PENDING )
      {
        releaseOVERLAPPED ( m_pOVERLAPPEDconnect );
        EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                      , GetP2PaddrHub().c_wstr()
                      , m_oThatP2Paddr.c_wstr() )
             ->Message ("ConnectEx() failed\n" )
             ->Group("WSA")->HResult(WSAGetLastError() )->Throw();
      }
    }

    // Exceptions
    // NOTES: Perform P2PeerCon_CLOSE notification
    catch ( P2Pevent *pEVENT )
    {
      Drop ( pEVENT->Isolate() );
    }

    // Tidy up and
    return false;
}

void
P2PeerConWsa::Close  ( )
{
    // Delegate
    P2PeerCon::Close ( );
}

//
//  Performs default ON_P2PeerCon_CLOSE() handler processing
//  NOTES: Non-accepted connections may be Restart()'ed
//       : Usually performed in the ON_P2PeerCon_CLOSE() handlers
//
//
//  Returns:     conRESULT
//               Connection handler result code
//
conRESULT
P2PeerConWsa::OnClose ( )
{
    // Primary resource recovery
    // NOTES: Sockets are a little different and need to be tidied
    //        up before delegation to the base class
    if ( m_oSocket != INVALID_SOCKET )
    {
      closesocket ( m_oSocket );
      m_oSocket    = INVALID_SOCKET;
      m_hFile      = 0;                // P2PeerCon attribute
      m_hFileCPort = 0;                // P2PeerCon attribute
    }

    // Seconday resource recovery
    if ( m_oSocketAccept != INVALID_SOCKET )
    {
      closesocket ( m_oSocketAccept );
      m_oSocketAccept = INVALID_SOCKET;
    }

    // Always delegate
    // NOTES: Accepted connections MUST always be destroyed and any 
    //        form of restart blocked
    if ( GetMode() == P2PeerCon_Accept )
      Destroy ( );
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
P2PeerConWsa::HasDroppedOut ( HRESULT hr )
{
    // Default action
    if ( hr == ERROR_NETNAME_DELETED )
      return true;
    return false;
}

///////////////////////////////////////////////////////////////////////
//  System
//  NOTES: Win32 extensions and packaging

#ifdef _WIN32
// Windows-only: the detached-thread ConnectEx emulation's carrier. On Linux the connect is
// submitted through io_uring (see the ConnectEx overload below), so there is no helper thread
// and this struct is unused.
typedef struct
{
    SOCKET               oSocket;
    // SECURITY_REVIEW H1: was a bare 16-byte `struct sockaddr`, memcpy'd into with the
    // caller's namelen. Any sockaddr larger than IPv4 (a 28-byte sockaddr_in6) overran the
    // fields below -- including pThis, which ConnectExThread then dereferences. Widened to
    // SOCKADDR_STORAGE (the OS-provided "large enough for any family" type) and the copy is
    // now bounds-checked in ConnectEx() below, so neither half of the pair can regress alone.
    SOCKADDR_STORAGE     name;
    int                  namelen;
    HANDLE               hCPort;
    OVERLAPPEDcon       *pOVERLAPPEDcon;
    DWORD_PTR           dwCompletionKey;
    // LIFETIME. pThis, and the completion port and OVERLAPPED reached through
    // it, belong to the con. The thread below outlives neither by accident: it
    // holds a reference on the con for its whole run (taken in ConnectEx,
    // dropped on the way out), which is what makes the "attempt to delete this
    // object may be made" the comments there warn about harmless. Without it a
    // hub closed with a dial in flight left the thread reporting into a freed
    // con -- an access violation, or a garbled address in the error text when
    // the freed memory still looked plausible.
    P2PeerConWsa        *pThis;
} ConnectExThreadData;
#endif

//
//  Windows ConnectEx() implementation
//  NOTES: Tidies up convoluted implementation
//
//
//  Parameters:  SOCKET oSocket
//               Unconnected, unbound socket.
//               NOTES: Win32 implementation requires socket to be
//                      bound to address provided
//
//               const struct sockaddr FAR *name
//               Name of the socket to which to connect
//
//               int namelen
//               Length of name, in bytes.
//
//               PVOID lpSendBuffer
//               Pointer to the buffer to be transferred upon
//               connection establishment. This parameter is optional
//
//               DWORD dwSendDataLength
//               Size of data in lpSendBuffer.
//
//               LPDWORD lpdwBytesSent
//               Number of bytes sent from lpSendBuffer.
//
//               LPOVERLAPPED lpOverlapped
//               An OVERLAPPED structure used to process the request.
//               The lpOverlapped parameter must be specified, and
//               cannot be NULL
//
//  Returns:     BOOL
//                 TRUE... Connection made
//                 FALSE.. Use WSAGetLastError() to retrieve code
//                         Refer Windows API for further details
BOOL
P2PeerConWsa::ConnectEx ( SOCKET oSocket
                        , const struct sockaddr FAR *name
                        , int namelen
                        , PVOID lpSendBuffer OPTIONAL
                        , DWORD dwSendDataLength
                        , LPDWORD lpdwBytesSent
                        , LPOVERLAPPED lpOverlapped )
{
    // Assume XP implementation available
    ASSERT(oSocket==m_oSocket);
    LPFN_CONNECTEX pfnConnectEx = NULL;
    GUID           gufn = WSAID_CONNECTEX;
    DWORD          dwBytes = 0;
    if ( WSAIoctl ( oSocket
                  , SIO_GET_EXTENSION_FUNCTION_POINTER
                  , &gufn, sizeof(gufn)
                  , &pfnConnectEx, sizeof(pfnConnectEx)
                  , &dwBytes, NULL, NULL ) )
    {
      EVERR->Module  (_N("%hs(%s-%s)"), __FUNCTION__
                     , GetP2PaddrHub().c_wstr()
                     , m_oThatP2Paddr.c_wstr() )
           ->Message (_N("WSAIoctl(%s) failed"), (LPCTSTR)m_sIPaddress )
           ->Advice  ("ConnectEx requires XP or better" )
           ->Group("WSA")->HResult(WSAGetLastError())->Display();
      return FALSE;
    }

    // Bind socket to address
    if ( bind(oSocket,name,namelen) == SOCKET_ERROR )
    {
      EVERR->Module (_N("%hs(%s-%s)"), __FUNCTION__
                    , GetP2PaddrHub().c_wstr()
                    , m_oThatP2Paddr.c_wstr() )
           ->Message ("bind() failed")
           ->Group("WSA")->HResult(WSAGetLastError() )->Display();
      return FALSE;
    }

    // ConnectEx implementation
    // NOTES: Notification occurs via IO Completion Port
    dwBytes = 0;
    ASSERT(dwSendDataLength==0);
    ASSERT(lpOverlapped==&m_pOVERLAPPEDconnect->oOverlapped);
    if (    pfnConnectEx &&
         !(*pfnConnectEx)( oSocket
                         , name, namelen
                         , lpSendBuffer, dwSendDataLength
                         , lpdwBytesSent
                         , lpOverlapped ) )
      return FALSE;

    // Tidy up, and
    return TRUE;
}

//
//  Description: Windows ConnectEx() implementation
//               NOTES: Provides alternative ConnectEx implementation
//
//
//  Parameters:  SOCKET oSocket
//               Unconnected, unbound socket.
//               NOTES: Win32 implementation requires socket to be
//                      bound to address provided
//
//               const struct sockaddr FAR *name
//               Name of the socket to which to connect
//
//               int namelen
//               Length of name, in bytes.
//
//               PVOID lpSendBuffer
//               Pointer to the buffer to be transferred upon
//               connection establishment. This parameter is optional
//
//               DWORD dwSendDataLength
//               Size of data in lpSendBuffer.
//
//               LPDWORD lpdwBytesSent
//               Number of bytes sent from lpSendBuffer.
//
//               LPOVERLAPPED lpOverlapped
//               An OVERLAPPED structure used to process the request.
//               The lpOverlapped parameter must be specified, and
//               cannot be NULL
//
//  Returns:     BOOL
//                 TRUE... Connection made
//                 FALSE.. Use WSAGetLastError() to retrieve code
//                         Refer Windows API for further details
BOOL
P2PeerConWsa::ConnectEx ( SOCKET oSocket
                        , const struct sockaddr FAR *name
                        , int namelen
                        , PVOID lpSendBuffer OPTIONAL
                        , DWORD dwSendDataLength
                        , LPDWORD lpdwBytesSent
                        , OVERLAPPEDcon *pOVERLAPPEDcon )
{
#if !defined(_WIN32)
    // Linux: no detached ConnectExThread. Route to the io_uring-backed
    // ConnectEx shim (resolved on Windows via WSAID_CONNECTEX). io_uring prep_connect needs
    // no pre-bind (unlike Windows ConnectEx, the reason the thread emulation existed at all),
    // completes through the con's owning ring, and is cancelled by cancel_fd on con teardown
    // -- so an in-flight connect can no longer outlive its con/ring, which was the detached
    // helper's use-after-free under the Phase-5 teardown stress. p2p_wsa_connectex submits the
    // connect and reports ERROR_IO_PENDING, exactly the async response Connect() checks for.
    return p2p_wsa_connectex ( oSocket, name, namelen, lpSendBuffer,
                               dwSendDataLength, lpdwBytesSent,
                               &pOVERLAPPEDcon->oOverlapped );
#else
    UNREFERENCED_PARAMETER(lpSendBuffer);
    UNREFERENCED_PARAMETER(dwSendDataLength);
    UNREFERENCED_PARAMETER(lpdwBytesSent);
    // Validate the address before it is copied anywhere
    // NOTES: SECURITY_REVIEW H1. The copy below is driven by the caller's namelen into a
    //        fixed-size field; an oversized (or negative) length overruns the rest of
    //        ConnectExThreadData, whose tail holds hCPort, pOVERLAPPEDcon and pThis --
    //        pointers ConnectExThread dereferences on another thread. Reject out-of-range
    //        lengths here, before the allocation, and fail the way every other failure in
    //        this function does (WSA error + FALSE) rather than throwing: Connect() above
    //        tests WSAGetLastError() for ERROR_IO_PENDING and treats anything else as a
    //        failed arm.
    if ( name == NULL                                  ||
         namelen < (int)sizeof(struct sockaddr)        ||
         namelen > (int)sizeof(((ConnectExThreadData *)0)->name) )
    {
      WSASetLastError ( WSAEFAULT );
      return FALSE;
    }

    // Preparation
    // NOTES: Must persist across life cycle of ConnectExThread
    ConnectExThreadData *pData = new ConnectExThreadData;
    pData -> dwCompletionKey = m_dwCompletionKey;
    pData -> hCPort          = m_hCPort;
    memcpy ( &pData->name, name, namelen );
    pData->  namelen         = namelen;
    pData -> oSocket         = oSocket;
    pData -> pOVERLAPPEDcon  = pOVERLAPPEDcon;
    pData -> pThis           = this;

    // Lend the thread a reference for the duration of the dial
    // NOTES: prepareOVERLAPPED()'s AddRef covers the OVERLAPPED, not the
    //        thread: the pump releases that one the moment the completion is
    //        handled, which can be while the thread is still inside connect().
    //        This one is the thread's own, dropped as the last thing it does,
    //        so the con cannot be deleted out from under it however the hub is
    //        torn down. Drop()'s closesocket() unblocks the connect promptly,
    //        so the extra reference is short-lived.
    AddRef ( );

    // Threaded emulation
    DWORD nThreadID;
    if ( CreateThread ( 0
                      , 0
                      , P2PeerConWsa::ConnectExThread
                      , pData
                      , 0
                      ,&nThreadID ) == NULL )
    {
      Release ( );                     // Thread never ran; give its reference back
      delete pData;                    // Garbage collection
      return FALSE;                    // Failed
    }

    // Tidy up, and
    // NOTES: Emulate expected and documented win32 response
    WSASetLastError ( ERROR_IO_PENDING );
    return FALSE;
#endif   // !_WIN32
}

//
//  Description: ConnectEx implementation thread
//               NOTES: Emulates ConnectEx implementation.  Overcomes
//                      problem whereby a bind() must be performed prior
//                      to the ConnectEx() call.  Works OK for remote
//                      connections but gives WSAEADDRINUSE for local.
//                    : Thread drops out upon the completion of the
//                      connect() call.
//
//
//  Parameters:  void *pvData
//               Thread data passed via CreateThread()
//
//  Returns:     DWORD
//               Completion code
//
#ifdef _WIN32   // Linux submits the connect through io_uring (see ConnectEx above); no thread.
DWORD WINAPI
P2PeerConWsa::ConnectExThread ( void *pvData )
{
    // Locals
    // NOTES: pThis is safe to hold for the whole of this function -- ConnectEx
    //        took a reference on the con for exactly that purpose, and it is
    //        given back at the bottom. Before that reference existed, a hub
    //        closed mid-dial freed the con here and everything below read
    //        through the hole.
    HRESULT                hr  = S_OK;
    ConnectExThreadData *pData = (ConnectExThreadData *)pvData;
    P2PeerConWsa           *pThis = pData -> pThis;

    // Because this is all problematic, we
    try
    {
      // Disable non-blocking mode
      // NOTES: Sockets must be configured as blocking.  But our
      //        ConnectEx() implementation requires blocking
      DWORD dwDisable = 0;               // Disable non-blocking mode
      if ( hr == S_OK                                         &&
           ioctlsocket ( pData->oSocket, FIONBIO, &dwDisable )    )
        hr = WSAGetLastError();

      // Perform connection
      // NOTES: May take a considerable period of time.  During which
      //        attempt to delete this object may be made.
      //      : Errors are expected here and as such are passed back
      //        via the IO Completion Port
      if ( hr == S_OK                                    &&
           connect ( pData->oSocket
                   , (struct sockaddr *)&pData->name
                   ,                     pData->namelen )    )
        hr = GetLastError();

      // Enable non-blocking mode
      // NOTES: Sockets must be configured as blocking.  But our
      //        ConnectEx() implementation requires blocking
      DWORD dwEnable = 1;                // Enable non-blocking mode
      if ( hr == S_OK                                         &&
           ioctlsocket ( pData->oSocket, FIONBIO, &dwEnable )    )
        hr = WSAGetLastError();

      // Post IO Completion Port
      // NOTES: Confirm completion port still exists.  Object may be
      //        in the process of being deleted.
      //      : Simply report errors
      pData -> pOVERLAPPEDcon -> hr = hr;
      OVERLAPPED *pOVERLAPPED = (OVERLAPPED *)pData->pOVERLAPPEDcon;
      if ( !PostQueuedCompletionStatus ( pData->hCPort
                                       , 0 // bytes transferred
                                       , pData->dwCompletionKey
                                       , pOVERLAPPED )  )
      {
        pThis -> releaseOVERLAPPED(pData->pOVERLAPPEDcon);
        EVERR->Module ("%s(%s-%s)", __FUNCTION__
                      , (P2PaddrSTR)pThis->GetP2PaddrHub()
                      , (P2PaddrSTR)pThis->GetP2Paddress() )
             ->Message ("PostQueuedCompletionStatus() failed")
             ->HResult ( GetLastError() )->Display()->Throw();
      }
    }

    // Exceptions
    // NOTES: Simply tidy up and, ignore
    catch ( P2Pevent *pEVENT )
    {
      pThis -> Drop ( pEVENT->Isolate() );
      ASSERT(!pData->pOVERLAPPEDcon->bQueued);
    }
    catch ( ... )
    {
      ASSERT(!pData->pOVERLAPPEDcon->bQueued);
    }

    // Tidy up, and
    // NOTES: Release() is the last thing this thread does with the con -- it
    //        may be the reference that deletes it, so nothing below may touch
    //        pThis, pData->pOVERLAPPEDcon or anything else reached through it.
    delete pData;
    pThis -> Release ( );
    return 0;
}
#endif   // _WIN32 (ConnectExThread)

///////////////////////////////////////////////////////////////////////
//  Troubleshooting

void
P2PeerConWsa::AssertValid ( ) const
{
    // Firstly delegate
    __super::AssertValid ( );

    // TODO: Additional validation
}


//
//  Generates state snapshot for this P2PeerCon instance
//  NOTES: Such summaries are used to inject P2PeerCon state information
//         P2PeerMsg's and P2Pevent's etc
//
//  Parameters:  LPCTSTR lpszVar
//               Name assigned to the generated P3PmsgNode
//
//  Returns:     P3PmsgNode
//               Snapshot instance
//
P3PmsgItem
P2PeerConWsa::SetP2PeventFParams ( LPCTNAM lpszVar )
{
    // Create a placeholder for receipt of P2PeerConWsa details
    // NOTES: This will be passed by value back up the stack
    if ( lpszVar == nullptr )
      lpszVar = _N("P2PeerConWsa");
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData(m_nP2PconID)) );

    // Convention is to delegate to base class first
    oNodeVar += P2PeerCon::SetP2PeventFParams ( 0 );

    // Append state summary to node
    oNodeVar += P3PmsgField ( L"m_oSocket", P3PmsgData(m_oSocket) );
    oNodeVar += P3PmsgField ( L"m_oSocketAccept", P3PmsgData(m_oSocketAccept) );
    oNodeVar += P3PmsgField ( L"m_sIPaddress", DataBSTR16(m_sIPaddress) );
    oNodeVar += P3PmsgField ( L"m_nIPort", P3PmsgData(m_nIPort) );
    //  Asset S9 in THREAT_MODEL.md - the operator's knowledge of which
    //  protection is in force.  A family, a listen scope and an allow-list that
    //  cannot be read back are three more settings a deployment is secured by
    //  belief in - and the family is the one that decides what the other two
    //  MEAN, so a dump carrying the scope without it says less than it appears
    //  to
    oNodeVar += P3PmsgField ( L"m_eFamily"
                            , P3PmsgData((int)m_eFamily) );
    oNodeVar += P3PmsgField ( L"m_eListenScope"
                            , P3PmsgData((int)m_eListenScope) );
    oNodeVar += P3PmsgField ( L"m_sListenAddress"
                            , DataBSTR16(m_sListenAddress) );
    oNodeVar += P3PmsgField ( L"AcceptPrefixes"
                            , P3PmsgData( m_pxSourceFilter
                                        ? (int)m_pxSourceFilter->m_oPrefixes.size ( )
                                        : 0 ) );

    // Tidy up and
    return oNodeVar;
}
P3PmsgItem
P2PeerConWsa::Serialise ( LPCTNAM lpszVar )
{
    // Locals
    bool bDsc = true;

    // Create a placeholder for receipt of P2PeerConWsa details
    // NOTES: This will be passed by value back up the stack
    P3PmsgItem oNodeVar ( P3PmsgField(lpszVar,P3PmsgData(m_nP2PconID)) );
    if ( lpszVar == 0 || _tcslen(lpszVar) <= 0 )
      (P3PmsgField&)oNodeVar = P3PmsgName ( _N("{P2PeerConWsa}") );
    else
      oNodeVar.r_data() = P3PmsgData ( _N("{P2PeerConWsa}") );

    // Append our state to node
    P3PmsgField_SERIALISE ( oNodeVar, _N("IPaddress"), (LPCTSTR)m_sIPaddress, bDsc
                          , _T("Allocated IP connection address") );
    P3PmsgField_SERIALISE ( oNodeVar, _N("IPort"), m_nIPort, bDsc
                          , _T("Allocated IP port") );
    P3PmsgField_SERIALISE ( oNodeVar, _N("Family"), (int)m_eFamily, bDsc
                          , _T("Address family opened - refer "
                               "P2PeerConFamily_e.  0 IPv4, 1 IPv6, 2 dual") );
    P3PmsgField_SERIALISE ( oNodeVar, _N("ListenScope"), (int)m_eListenScope, bDsc
                          , _T("Interfaces the SERVICE binds - refer "
                               "P2PeerConScope_e") );
    P3PmsgField_SERIALISE ( oNodeVar, _N("ListenAddress")
                          , (LPCTSTR)m_sListenAddress, bDsc
                          , _T("Nominated bind interface, P2PeerConScope_Address "
                               "only") );
    P3PmsgField_SERIALISE ( oNodeVar, _N("AcceptPrefixes")
                          , m_pxSourceFilter
                          ? (int)m_pxSourceFilter->m_oPrefixes.size ( ) : 0, bDsc
                          , _T("Accept allow-list rules - 0 admits any source") );

    // Tidy up and
    oNodeVar += P2PeerCon::Serialise ( 0 );
    return oNodeVar;
}

///////////////////////////////////////////////////////////////////////
//  Properties
