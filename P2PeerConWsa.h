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
//  P2PeerConWsa definitions and prototypes
//  NOTES: Asynchronously manages WSA TCP/IP connections and
//         facilitates IO Completion port integration
//                      
#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2PeerCon.h"

#include <memory>   // std::shared_ptr m_pxSourceFilter - the same rule the
                    // base header states for m_pxAccepted: the container the
                    // pointer names is defined in the .cpp, so a consumer of
                    // this header inherits no dependency on <vector>

///////////////////////////////////////////////////////////////////////
//  Where a SERVICE binds its listening socket
//  NOTES: Listen() bound INADDR_ANY unconditionally until 2026-08-27 and gave
//         a caller no way to say otherwise, so every service this library has
//         ever stood up has been reachable from every interface its host
//         routes.  A deployment could only narrow that from OUTSIDE the
//         process, in a firewall, and could not read it back from inside one
//       : This is the one restriction the KERNEL enforces.  A socket bound to
//         the loopback address cannot be reached from another machine at all -
//         an off-host SYN is refused by the stack, and nothing in this library
//         ever sees the bytes.  Refer THREAT_MODEL.md B1/B2: everything before
//         the login gate runs on bytes with no provenance, so the cheapest
//         defence available is the one that stops them arriving
//       : It is a BIND and not a source test, and the two answer different
//         questions.  Refer AllowAcceptFrom() below for why "only the LAN"
//         cannot be expressed here
//       : The addresses named below are IPv4 or IPv6 according to the FAMILY
//         set alongside them - refer P2PeerConFamily_e.  A scope says WHICH of
//         the host's addresses to bind; a family says which address SPACE the
//         question is being asked in, and neither answers the other
enum P2PeerConScope_e
{ P2PeerConScope_Any      = 0        // every interface (default)
, P2PeerConScope_Loopback            // this machine only - 127.0.0.1 or ::1
, P2PeerConScope_Address             // one nominated local interface address
};

///////////////////////////////////////////////////////////////////////
//  Which address family a connection opens in
//  NOTES: IPv4 is the default, and is what every caller written before this
//         existed keeps.  This transport was AF_INET at all three socket sites
//         until 2026-08-28; a v6 peer could not reach a service and a client
//         could not dial one.  What made that a DEFAULT rather than a
//         limitation is that nothing said so and nothing could be told
//         otherwise
//       : Dual is one socket, not two.  AF_INET6 with IPV6_V6ONLY cleared
//         accepts a v4 peer as the v4-mapped ::ffff:a.b.c.d the kernel reports,
//         which this class normalises back to AF_INET at the one boundary that
//         reads it - refer AcceptSourceAddress().  So an allow-list written in
//         v4 prefixes keeps working against v4 peers arriving on a v6 socket,
//         which is the whole reason the normalisation is not optional
//       : IPV6_V6ONLY is set EXPLICITLY for both v6 modes rather than left to
//         the platform, because the platforms disagree: Windows defaults it on
//         and most Linux distributions default it off, so a socket that did not
//         say would mean two different things on the two builds.  A dual-stack
//         setting that quietly is not one is asset S9 in THREAT_MODEL.md, and
//         so is a v6-only setting that quietly admits v4
//       : Dual cannot express P2PeerConScope_Loopback and Listen() refuses the
//         pair rather than picking one.  ::1 is not the v4-mapped form of
//         127.0.0.1, so one bind cannot cover both loopbacks - refer the throw
//         in ListenBindSockaddr(), and note that the honest failure is the
//         point
enum P2PeerConFamily_e
{ P2PeerConFamily_IPv4 = 0           // AF_INET  - what has always shipped
, P2PeerConFamily_IPv6               // AF_INET6, IPV6_V6ONLY on
, P2PeerConFamily_Dual               // AF_INET6, IPV6_V6ONLY off
};

//  The accept-time source allow-list.  Declared here and defined in
//  P2PeerConWsa.cpp for the reason P2PeerConSourceTally is defined in
//  P2PeerCon.cpp - a container in a shipped header is a dependency every
//  consumer inherits whether it uses the feature or not
struct P2PeerConWsaSourceFilter;

///////////////////////////////////////////////////////////////////////
//  P2PeerConWsa connection management
//  NOTES: Instances of these objects wholly manage single WSA
//         connections.  Collections of P2PeerConWsa objects are collated
//         and supervised by P2PeerHub's
//       : P2PeerHub's pump P2PeerConWsa objects through P2PeerCon_MAP's
//         in response to state changes.
//
class Targetcore_EXT P2PeerConWsa : public P2PeerCon
{
      void
        RenderThisSafe();

    // Constructors, destructor and factories
    public:
        P2PeerConWsa ( );
        P2PeerConWsa ( P2PaddrSTR strThatP2Paddr
                     , LPCTSTR  lpszIpAddress, short nIpPort );
        P2PeerConWsa ( P2PaddrSTR strThatP2Paddr
                     , SOCKET   oSocket );
        P2PeerConWsa ( P2PaddrSTR strThatP2Paddr
                     , short nIpPort );
      virtual
       ~P2PeerConWsa ( );

      static P2PeerConWsa*
        ServiceFactory( P2PaddrSTR strP2PaddrThat
                      , short nIpPort );
      static P2PeerConWsa*
        ClientFactory ( P2PaddrSTR strP2PaddrThat
                      , LPCTSTR lpszIpAddress, short nIpPort );
      virtual P2PeerCon*
        AcceptSpawn ( P2PeerCon *pCon );
      //  The origin of the socket this SERVICE has just accepted, folded into
      //  one accounting key, or 0 if there is no such socket or the kernel will
      //  not name it.
      //  NOTES: The PORT is deliberately not in the key.  A source's port
      //         changes on every connection it opens, so keying on the pair
      //         would give every connection a key of its own and bound nothing
      //       : An IPv4 origin IS its address, in network byte order, exactly
      //         as it has always been - so it occupies the low 32 bits and a v4
      //         key is still readable as the address it names
      //       : An IPv6 address does not fit.  128 bits into 64 has to lose
      //         something, and what it loses is chosen rather than truncated:
      //         the key is a hash of the /64 PREFIX, which is the unit a v6
      //         host is actually delegated - a single subscriber line is handed
      //         a whole /64, so keying on the full address would let one peer
      //         mint 2^64 keys and defeat the per-source bound it is here to
      //         serve.  Two hosts in one /64 sharing a key is the intended
      //         reading of "one source", not an approximation of it
      //       : Bit 63 is SET on a v6 key and can never be set on a v4 one,
      //         which is what keeps the two spaces from meeting in the tally's
      //         map.  Without it ::1 - whose /64 prefix is all zeroes - would
      //         key as 0, the value that means "the kernel would not name it"
      //       : A v4-MAPPED origin on a dual-stack socket keys as the v4
      //         address it is, not as a v6 one.  Refer AcceptSourceAddress()
      virtual P2PsourceKey
        AcceptSourceKey ( ) const;
      //  The origin of that same socket, whole, as the kernel reports it.
      //  NOTES: This is what the accept ALLOW-LIST is tested against, because a
      //         prefix match needs the address and the key is a fold of it.
      //         AcceptSourceKey() is built from this and not the other way
      //         round
      //       : A v4-mapped ::ffff:a.b.c.d is rewritten to the AF_INET address
      //         it stands for before it is answered.  A v4 peer that reached a
      //         dual-stack service is a v4 peer, and an operator's "10.0.0.0/8"
      //         must mean the same thing whichever socket carried it
      //  Returns: the address length, or 0 if the origin cannot be named
      int
        AcceptSourceAddress ( SOCKADDR_STORAGE &rAddr ) const;

    // IOCP Integration
    public:
      // A zero-byte read completion on a stream socket is FIN.  Refer
      // P2PeerCon::RecvZeroIsOrderlyClose and F-S4-1
      bool
        RecvZeroIsOrderlyClose ( ) const override { return true; }
      virtual bool
        On_QueuedCompletionStatus ( DWORD dwError
                                  , DWORD dwBytes
                                  , OVERLAPPEDcon *pOVERLAPPEDcon );
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
      virtual bool
          Connect ( );
      virtual void
          Close   ( );
      virtual conRESULT
        OnClose  ( );

    // Utilities
    public:
      virtual bool
        HasDroppedOut ( HRESULT hr );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
      virtual P3PmsgItem
        SetP2PeventFParams ( LPCTNAM lpszVar );
      virtual P3PmsgItem
        Serialise ( LPCTNAM lpszVar );

    // System
    // NOTES: Win32 extensions and packaging
    protected:
      BOOL
        ConnectEx ( SOCKET oSocket
                  , const struct sockaddr FAR *name
                  , int namelen
                  , PVOID lpSendBuffer OPTIONAL
                  , DWORD dwSendDataLength
                  , LPDWORD lpdwBytesSent
                  , LPOVERLAPPED lpOVERLAPPED );
      BOOL
        ConnectEx ( SOCKET oSocket
                  , const struct sockaddr FAR *name
                  , int namelen
                  , PVOID lpSendBuffer OPTIONAL
                  , DWORD dwSendDataLength
                  , LPDWORD lpdwBytesSent
                  , OVERLAPPEDcon *pOVERLAPPEDcon );
      static DWORD WINAPI
        ConnectExThread ( void *pvData );
      //  The socket address this SERVICE's listening socket binds, filled for
      //  the configured family and scope.  Throws for a scope it cannot honour
      //  rather than falling back to "every interface" - refer the enum above
      //  Returns: the address length, for bind()
      int
        ListenBindSockaddr ( SOCKADDR_STORAGE &rAddr );
      //  AF_INET or AF_INET6 for the configured family.  One place, so the
      //  three socket sites and the bind cannot disagree about what is open
      int
        SocketFamily ( ) const;

    // Listen backlog
    // NOTES: Set on the SERVICE before Listen(). The backlog bounds connections
    //        the kernel has completed but this service has not accepted yet -
    //        a different queue from the one SetMaxAccepted() bounds, and worth
    //        keeping distinct: the backlog is how much burst is tolerated, the
    //        cap is how many peers are carried at once
    //      : listen() took a literal 32 until 2026-08-16, beside a comment
    //        naming an m_xConnections that does not exist and never did, so a
    //        service had no way to say otherwise.  32 remains the default, so
    //        nothing changes for a caller that does not set it
    public:
      void
        SetBacklog ( int nBacklog );
      int
        GetBacklog ( ) const { return m_xBacklog; }

    // Address family
    // NOTES: Set on a SERVICE before Listen() and on a CLIENT before Connect(),
    //        and takes effect at the next one - a socket already open keeps the
    //        family it was opened in, the same rule the backlog and the scope
    //        state
    //      : P2PeerConFamily_IPv4 is the default and is what every caller
    //        written before 2026-08-28 gets.  Nothing about an existing
    //        deployment changes unless it asks
    //      : On a CLIENT the family also chooses what the RESOLVER is allowed
    //        to answer.  IPv4 asks for A records, IPv6 for AAAA, and Dual for
    //        either - so a name with only one kind of record is reachable under
    //        Dual and unreachable under the family that does not match it, and
    //        says which it could not find
    public:
      void
        SetFamily ( P2PeerConFamily_e eFamily );
      P2PeerConFamily_e
        GetFamily ( ) const { return m_eFamily; }
      // Whether this connection opens an AF_INET6 socket at all.  The two v6
      // modes answer this the same way and part only at IPV6_V6ONLY, which is
      // why the socket sites ask this and Listen() asks the family
      bool
        IsFamilyIPv6 ( ) const
        { return m_eFamily == P2PeerConFamily_IPv6 ||
                 m_eFamily == P2PeerConFamily_Dual; }

    // Listen scope
    // NOTES: Set on the SERVICE before Listen(), and takes effect at the next
    //        Listen() - a socket already listening keeps the address it was
    //        bound to, the same rule the backlog above states
    //      : P2PeerConScope_Address takes a LOCAL INTERFACE address, one this
    //        host itself holds, never a peer's.  An address the host does not
    //        hold makes bind() fail and drops the service, which is the
    //        intended outcome: a scope that cannot be honoured must not
    //        quietly widen to ANY.  Not widening IS the setting
    //      : The address is read in the FAMILY this connection opens in - a
    //        dotted quad for _IPv4, an RFC4291 literal for _IPv6 or _Dual - and
    //        a literal of the other family is refused rather than converted.
    //        "127.0.0.1" on an AF_INET6 service could be bound as
    //        ::ffff:127.0.0.1, which is legal and would silently turn a
    //        dual-stack service into a v4-only one listening on one interface,
    //        with nothing anywhere to say it had happened
    //      : P2PeerConFamily_Dual cannot express P2PeerConScope_Loopback at
    //        all and Listen() refuses the pair - refer P2PeerConFamily_e
    public:
      void
        SetListenScope     ( P2PeerConScope_e eScope
                           , LPCTSTR lpszIpAddress = 0 );
      P2PeerConScope_e
        GetListenScope     ( ) const { return m_eListenScope; }
      // The address P2PeerConScope_Address was given.  Empty for the other two
      // scopes, which name their address rather than carry one
      const CString&
        GetListenAddress   ( ) const { return m_sListenAddress; }

      //  P2PeerConTrust_Local when the KERNEL says this link cannot leave the
      //  machine, and P2PeerConTrust_Wire otherwise.
      //  NOTES: Asked of the SOCKET first, not of m_eListenScope, and that is
      //         the whole of the design.  getpeername() on a connected socket
      //         is the kernel's own answer to "who is on the other end", it is
      //         the same reading the accept allow-list is tested against, and
      //         it is true for a CLIENT that dialled loopback, for a SERVICE's
      //         accepted CHILD, and for a connection nobody configured -
      //         uniformly and with nothing copied
      //       : The listen scope is only the fallback, and only for a socket
      //         with no peer: a service object, or a client before it dials.
      //         Neither carries traffic, so what it answers is a posture
      //         reading rather than a gate input.  It matters that the CHILD
      //         does not depend on it - AcceptSpawn does not copy
      //         m_eListenScope, and a class that needed it copied would have
      //         put back exactly the hazard SECURITY.md:205 is about
      //       : A loopback PEER is a kernel fact and not a claim on the wire.
      //         An off-host packet whose source is 127.0.0.0/8 is a martian
      //         and is dropped by the stack before anything here sees it, and
      //         a v4-mapped ::ffff:127.0.0.1 is normalised to the v4 address
      //         it stands for first - refer NormaliseP2PeerConSockaddr()
      //       : Local says no NETWORK adversary can reach this link.  It says
      //         nothing about another PRINCIPAL on the same host (A7), who
      //         reaches a loopback port exactly as easily as this process
      //         does; that is what the accept allow-list and the peer's own
      //         login are for, and it is why relaxing Local is a decision an
      //         operator takes rather than one this class takes for them
      virtual P2PeerConTrust_e
        TrustClass         ( ) const;

    // Accept source admission - WHO may connect, as against WHERE we listen
    // NOTES: An allow-list of IPv4 prefixes, tested at accept against the
    //        origin the KERNEL reports - AcceptSourceKey(), getpeername(), a
    //        peer that has said nothing yet and may never intend to.  An empty
    //        list is no restriction, which is the default and is what every
    //        existing caller keeps
    //      : It exists because a BIND cannot express "the LAN".  Binding to a
    //        LAN interface's address restricts which INTERFACE accepts, not
    //        which SOURCE reaches it: a packet forwarded in from the internet
    //        by a NAT or a port-forward arrives on that same interface and is
    //        accepted.  The two settings are complementary, and a service that
    //        faces a network it does not own is expected to set both
    //      : A configured filter FAILS CLOSED on a source the transport cannot
    //        name, and is deliberately the opposite of SourceAtCapacity() one
    //        line away in AcceptSpawn(), which fails open.  That bound is
    //        ACCOUNTING - refusing a peer it cannot identify would stop a
    //        service on one getpeername() failure, and admitting one costs a
    //        slot.  This is POLICY - an operator who has written down who may
    //        connect has thereby said that everyone else may not, and an
    //        origin nothing can name is not on the list
    public:
      // "192.168.1.0/24", "10.0.0.0/8", or a bare "10.1.2.3" meaning /32 -
      // and since 2026-08-28 "2001:db8::/32", "fd00::/8" or a bare "::1"
      // meaning /128.  The form decides the family: a prefix containing ':' is
      // read as IPv6 and anything else as IPv4, so the two spaces are never
      // guessed between
      // NOTES: A v4 rule tests a v4 origin and a v6 rule a v6 one; neither
      //        matches across.  A v4 peer that reached a DUAL service is
      //        normalised out of its ::ffff: form before it is tested, so
      //        "10.0.0.0/8" means the same thing on either socket - refer
      //        AcceptSourceAddress().  Write BOTH families' rules on a dual
      //        service: a list holding only v4 prefixes refuses every v6 peer,
      //        which is a restriction that will be believed to be about
      //        addresses and is really about which lines were written
      // Answers false for a prefix it cannot parse, having added nothing, and
      // the caller MUST test it: a filter that silently dropped a malformed
      // rule would be narrower in the operator's belief than in the socket
      bool
        AllowAcceptFrom         ( LPCTSTR lpszPrefix );
      // 127.0.0.0/8 and ::1/128 - this machine, in both families.  The
      // companion to SetListenScope(P2PeerConScope_Loopback), never a
      // substitute for it: the bind stops the packet, this refuses the
      // connection
      void
        AllowAcceptLoopback     ( );
      // RFC1918 (10/8, 172.16/12, 192.168/16) plus loopback and link-local
      // 169.254/16, and their v6 counterparts - ::1/128, fc00::/7 unique-local
      // and fe80::/10 link-local.  "The LAN" as an address range, which is as
      // near the idea as an address test reaches - a routed packet whose source
      // was rewritten to a private address upstream still passes, so this is a
      // restriction and not a proof of locality
      // NOTES: Both families unconditionally, whatever family this connection
      //        is in.  A rule for a family no socket here opens costs a
      //        comparison that cannot match, and the alternative - a list whose
      //        contents depend on the order the setters were called in - is the
      //        kind of configuration that is right until someone reorders two
      //        lines
      void
        AllowAcceptPrivate      ( );
      void
        ClearAcceptSourceFilter ( );
      bool
        HasAcceptSourceFilter   ( ) const;
      // The decision itself, exposed so a gate test can measure it without
      // opening a socket and an application can pre-flight its own rules.
      // NOTES: The sockaddr form is the real one - it is what AcceptSpawn()
      //        asks, and the only one a v6 origin can be put to
      bool
        IsAcceptSourceAllowed   ( const struct sockaddr *pName
                                , int nNameLen ) const;
      // The IPv4 convenience form, kept because it is what this class answered
      // before there was a second family and what the gate test measures.
      // NOTES: A key with bit 63 set is a v6 FOLD - refer AcceptSourceKey() -
      //        and an address cannot be recovered from it, so this answers
      //        false for one.  Failing closed on a source it cannot reconstruct
      //        is the same rule a zero key gets, and for the same reason
      bool
        IsAcceptSourceAllowed   ( P2PsourceKey xSource ) const;

    // Attributes
    protected:
      SOCKET         m_oSocket;
      SOCKET         m_oSocketAccept;

      CString        m_sIPaddress;
      short          m_nIPort;
      int            m_xBacklog;

      // Address family.  Held on both roles - a SERVICE binds in it, a CLIENT
      // resolves and dials in it - and NOT inherited by an accepted child,
      // which is handed an already-open socket and has no family to choose
      P2PeerConFamily_e m_eFamily;
      // Listen scope.  m_sListenAddress is meaningful only for
      // P2PeerConScope_Address and is cleared by every other scope, so the two
      // cannot disagree about what is bound
      P2PeerConScope_e m_eListenScope;
      CString          m_sListenAddress;
      // The accept allow-list.  Held on the SERVICE and NOT inherited by an
      // accepted child, for the reason the accept caps are not: a child
      // accepts nothing, and a policy on it would govern nothing
      std::shared_ptr<P2PeerConWsaSourceFilter>
                       m_pxSourceFilter;
};
