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
//  Global P2Peer datatypes, definitions and prototypes
//

#pragma once
#include "TargetCore.h"

//
//  TargetCore data types
//  NOTES: Sit on top of the Msgcore data types and in particular keep
//         T_ADDR synchronised with T_NAME
typedef TCHAR          T_ADDR;         // P2Paddr type, keep synchronised with T_NAME
typedef const T_ADDR * LPCTADDR;       // P2PmsgHub address string
typedef const T_ADDR * P2PaddrSTR;     // P2PmsgHub address string
typedef const T_ADDR * P2PaddrTemplateSTR;
typedef const T_ADDR * P2PadomSTR;     // P2Peer domain string
typedef CString        CStringADDR;    // Compatible CStringA or CStringW
typedef DWORD          P2PmsgHubID;    // P2PmsgHub identification
typedef DWORD          P2PumpID;       // Pump  identification
typedef DWORD_PTR      P2PconID;       // P2PeerCon identification
typedef DWORD          P2PexpumpID;    // P2Pexplorer pump identification
typedef unsigned int   P2PsigID;       // OVERLAPPED IO signal
typedef unsigned int   P2PeventID;     // Event identification
typedef __time64_t     P2Pmsecs_t;     // Time in milliseconds
//  Identifies the ORIGIN of an inbound connection for accept accounting.
//  NOTES: 0 means "no source, or none this transport can name", and is never
//         counted and never refused - a bound that cannot identify who it is
//         bounding must not guess
//       : Today it carries an IPv4 address in network byte order, which is the
//         only family this tree opens (AF_INET throughout P2PeerConWsa).  It is
//         64 bits so that a v6 address can be folded into it later without
//         changing a public signature, and it is opaque to everything except
//         the transport that mints it - refer P2PeerCon::AcceptSourceKey()
typedef unsigned long long P2PsourceKey;
typedef UINT           PITimerID;      // Programmable interval timer ID
typedef BOOL           mapRESULT;      // Map result
typedef const T_ADDR * P2PmsgID;       // P2PeerMsg identification
typedef unsigned int   P2PsysID;       // P2PeerSys identification
typedef unsigned short P2Pmsg_t;       // P2PeerMsg type
typedef unsigned int   P2Psize_t;      // P2PeerMsg size
                                       // NOTES: 32-bit.  It was unsigned short,
                                       //        and every size crossing the
                                       //        message API wrapped at 64 KB
                                       //        SILENTLY.  P2PeerMsg::Sizeof()
                                       //        narrows P3PmsgBSTR::Sizeof()
                                       //        (VBLsize/UINT_PTR) into this, so
                                       //        a 66292-byte message measured
                                       //        756 and every bound built on it
                                       //        read green exactly when the
                                       //        thing it guarded had happened
                                       //        (TargetCoreSuite cascade hook)
                                       //      : MAX_P2Psize (32768) is
                                       //        unchanged - this widens the
                                       //        MEASUREMENT, not the message
                                       //        limit, so an oversize message
                                       //        is now reported at its real
                                       //        size and refused instead of
                                       //        wrapping under the cap
typedef unsigned int   P2PmsgCN;       // Control notification
typedef short          P2Pri_t;        // P2PeerMsg priority
typedef void *         P2PmsgHANDLE;   // P2Pmsg handle
typedef unsigned char  P2Pmsgnn_t;     // P2Pmsg 08, 16, 32, 64 addressing
typedef unsigned int   P2PmsgSinkID;   // Generic P2PmsgSink identification code

//
//  Limits
const UINT MAX_P2PmsgHub = 256;        // Maximum P2PmsgHub's within application
                                       // NOTES: P2Pmsg networks have no limit
const UINT MAX_P2PmsgPump= 256;        // Maximum P2PmsgPump's within P2PmsgHub
                                       // NOTES: P2Pmsg networks have no limit

//
//  Accept admission control defaults
//  NOTES: Applied to a SERVICE connection at construction; both are settable
//         per service (P2PeerCon::SetMaxAccepted / SetLoginDeadline) and both
//         take 0 to mean "no limit"
const long DEF_P2PeerConAccept = 1024; // Concurrent accepted connections per
                                       // SERVICE
                                       // NOTES: There was NO bound before
                                       //        2026-08-16 - a service accepted
                                       //        until the machine ran out of
                                       //        descriptors, and the peer doing
                                       //        it had not logged in yet
                                       //      : 1024 is chosen to be far above
                                       //        any deployment this tree has
                                       //        been run in and far below a
                                       //        descriptor table.  A service
                                       //        that genuinely needs more is
                                       //        expected to say so; a service
                                       //        that hits it unexpectedly has
                                       //        found the thing this bounds
const long DEF_P2PeerConAcceptSource = 0;
                                       // Concurrent accepted connections per
                                       // SOURCE, per SERVICE.  0 = DISABLED
                                       // NOTES: Off by default, deliberately,
                                       //        and for a different reason than
                                       //        the cap above is on.  A source
                                       //        is an IP address, and the two
                                       //        topologies this library is
                                       //        actually run in both collapse
                                       //        many peers onto ONE of them:
                                       //        loopback (every test in the
                                       //        suite dials 127.0.0.1) and NAT
                                       //        (a whole site behind one
                                       //        address).  A default that bound
                                       //        would refuse legitimate traffic
                                       //        in exactly those cases, and it
                                       //        would do it silently at accept
                                       //      : So this is armed by a
                                       //        deployment that knows its own
                                       //        topology, which is the same
                                       //        judgement DEF_P2PeerConLogin
                                       //        makes below.  The MECHANISM is
                                       //        always present - what is opt-in
                                       //        is the number, not the code
                                       //      : It bounds a SHARE of the
                                       //        service cap, so set it below
                                       //        DEF_P2PeerConAccept or it can
                                       //        never bind
const int  DEF_P2PeerConBacklog = 32;  // listen() backlog for a SERVICE
                                       // NOTES: The value listen() was called
                                       //        with as a literal before it was
                                       //        settable.  Kept, so making it
                                       //        configurable changes no
                                       //        existing behaviour - refer
                                       //        P2PeerConWsa::SetBacklog()
const P2Pmsecs_t DEF_P2PeerConThrottlePoll = 100;
                                       // Milliseconds between re-checks of the
                                       // budget while a connection is holding
                                       // its read (Stage 4 step 12)
                                       // NOTES: The resume cannot be an event,
                                       //        because the message that
                                       //        relieves the budget is
                                       //        RELEASED on some other pump
                                       //        and knows nothing about which
                                       //        connections are waiting on it.
                                       //        So it is a poll, and the
                                       //        number is the worst-case
                                       //        latency a peer sees before its
                                       //        window reopens
                                       //      : One timer per HELD connection,
                                       //        never per message, and a timer
                                       //        is itself a P2Pmsg - which is
                                       //        why SetP2PmsgBudgetMarks
                                       //        refuses a high mark at the
                                       //        ceiling
const P2Pmsecs_t DEF_P2PeerConLogin = 0;
                                       // Milliseconds an accepted connection
                                       // has to complete its login.
                                       // 0 = DISABLED, and disabled is the
                                       // default DELIBERATELY - refer below
                                       // NOTES: The timer itself has always
                                       //        worked; the call arming it was
                                       //        commented out, so the deadline
                                       //        never ran.  Refer
                                       //        P2PeerCon::ArmLoginDeadline()
                                       //      : *** OFF BY DEFAULT BECAUSE IT
                                       //        IS BROKEN ON LINUX. *** Arming
                                       //        it works on Windows and is
                                       //        guarded by p2p_logindeadline.
                                       //        On Linux the drop that follows
                                       //        the timeout ALSO cancels the
                                       //        listening socket's pending
                                       //        accept (ERROR_OPERATION_ABORTED
                                       //        995), the SERVICE treats that
                                       //        as an accept failure and drops
                                       //        itself, and every subsequent
                                       //        connect is refused - one
                                       //        timed-out peer takes the whole
                                       //        listener down.  The accepted fd
                                       //        inherits the listen socket's
                                       //        completion key in
                                       //        p2piocp.cpp's accept completion
                                       //        (r->assoc[res] = k), which is
                                       //        where to start looking
                                       //      : Measured 2026-08-16 by
                                       //        p2p_acceptcap, which reported
                                       //        CONNECT REFUSED for its
                                       //        liveness control on Linux while
                                       //        Windows was green
                                       //      : Turn it on per service with
                                       //        SetLoginDeadline(ms).  30000 is
                                       //        a sensible value where the
                                       //        platform supports it; the
                                       //        original (disabled) intent was
                                       //        1000

//
//  Triggers
//const UINT TRIGGER_INSERT =  1;
//const UINT TRIGGER_UPDATE =  2;
//const UINT TRIGGER_DELETE =  4;
//const UINT TRIGGER_IUD    = (TRIGGER_INSERT|TRIGGER_UPDATE|TRIGGER_DELETE);
//const UINT TRIGGER_ACTIVE =  8;
//const UINT TRIGGER_ALL    = ~0u;

//
//  Handy definitions
#define sizeof_t(object) (sizeof(object)/sizeof(TCHAR))

//
//  P2Pmsg address object
//  NOTES: Supports Virtual P2Peer Network addresses of the form
//         [VNetname:]RootHubname.Hubname[i]. . .Hubname etc
class TargetCore_EXT P2Paddr
{
    // Constructors and destructors
    public:
        P2Paddr ( );
        P2Paddr ( const P2Paddr& rhs );
        P2Paddr ( LPCTSTR strP2Paddr );
        P2Paddr ( LPCTSTR strP2PaddrHub
                , const T_ADDR *pszFormatCon, ... );
        P2Paddr ( GUID *pGUID );
       ~P2Paddr ( );

    // Overloaded operators
    public:
      P2Paddr&
        operator  = ( const P2Paddr& rhs );
      P2Paddr&
        operator  = ( LPCTADDR rhs );
      bool
        operator != ( const P2Paddr& rhs ) const;
      bool
        operator != ( LPCTADDR rhs ) const;
      bool
        operator == ( LPCTADDR rhs ) const;
      bool
        operator == ( const P2Paddr& rhs ) const;

        operator LPCTADDR ( ) const;

    // Operations
    public:
      void
        Empty ( );

    // Routing
    public:
      bool
        IsChild ( LPCTADDR strP2Paddr ) const;
      bool
        IsRable ( LPCTADDR strP2Paddr ) const;
      bool
        IsMapped( LPCTADDR strP2Paddr ) const;

    // Troubleshooting
    public:
      //virtual void
      //  AssertValid ( ) const;
      //virtual bool
      //  IsValid ( ) const;

    // Properties
    public:
      P2Psize_t
        Sizeof ( ) const;
      bool
        IsNull ( ) const;
      LPCTSTR
        GetVNet ( );
      //LPCTSTR
      //  GetPath ( );
      LPCTADDR
        c_hopname ( int nHop ) const;
      LPCTADDR
        c_name ( ) const;
      LPCTADDR
        c_wstr ( ) const;
      BOOL
        IsEmpty ( );

    // Attributes
    // NOTES: There is deliberately NO scratch member for c_name()/c_hopname().
    //        They used to build their result in one, through a const_cast, which
    //        raced whenever a single P2Paddr was read from two threads. The name
    //        now goes to a per-thread ring in P2Peer.cpp - see P2PaddrNameSlot.
    private:
      CString  m_strP2Paddr;
      CString  m_strVNetname;
      CString  m_strVNetaddr;
};
typedef CList<P2Paddr*> CListP2Paddr;
typedef const P2Paddr CP2Paddress;
#define       strP2PaddrNULL _N("\0")

//
//  P2Padomain
//  NOTES: Supports Virtual P2Peer Network addresses of the form
//         [VNetname:]RootHubname.Hubname[i]. . .Hubname etc
#define P2Padom P2Padomain
class TargetCore_EXT P2Padomain
{
    // Constructors
    public:
        P2Padomain ( );
        P2Padomain ( LPCTADDR strP2Padomain );
       ~P2Padomain ( );

      P2PaddrSTR
        Expand  ( LPCTADDR strP2Paddr, bool bSkip );

    // Overloaded operators
    public:
	  P2Padomain&
	    operator = ( const P2Padomain& rhs );
      P2Padomain&
        operator = ( LPCTADDR rhs );

        operator P2PadomSTR ( ) const;

    // Activities
    public:
      bool
        GetNextP2Paddr ( LPCTADDR strDomain
                       , P2Paddr& oP2PaddrNext, long& nState ) const;

    // Routing
    public:
      bool
        IsMapped ( P2PaddrSTR strP2Paddr ) const;

    // Troubleshooting
    public:
      //virtual void
      //  AssertValid ( ) const;
      //virtual bool
      //  IsValid ( ) const;

    // Properties
    public:
      P2Psize_t
        Sizeof ( ) const;
      bool
        IsNull ( ) const;
      LPCTADDR
        c_wstr ( ) const;

    // Helpers
    private:
      void
        RebuildDomains ( );   // (re)tokenise m_strDomain -> m_oCListDomains + m_bWildcard

    // Attributes
    private:
      CStringADDR  m_strDomain;
      mutable
      P2Paddr      m_oP2PaddrWork;
      POSITION     m_oPos;
      CList<CStringADDR*>
                   m_oCListDomains;
      CListP2Paddr m_oCListP2Paddr;
      bool         m_bWildcard;
};
typedef const P2Padomain CP2Padomain;

//
//  P2PaddrTemplate
//  NOTES: Supports Virtual P2Peer Network addresses of the form
//         [VNetname:]RootHubname.Hubname[i]. . .Hubname etc
//         that may or may not contain wildcards
/*class P2PaddrTemplate
{
    // Constructors
    public:
        P2PaddrTemplate ( P2PaddrTemplateSTR strP2PaddrTemplate );
       ~P2PaddrTemplate ( );

    // Routing
    public:
      bool
        IsMapped ( P2PaddrSTR strP2Paddr ) const;

    // Troubleshooting
    public:
      //virtual void
      //  AssertValid ( ) const;
      //virtual bool
      //  IsValid ( ) const;

    // Properties
    public:
      LPCTSTR
        c_wstr ( ) const;

    // Attributes
    private:
      CString  m_sP2PaddrTemplate;
};
typedef const P2PaddrTemplate CP2PaddrTemplate ;*/

//
//  Prototypes
//
//TargetCore_EXT DWORD
//GetHostID ( );

//
//  P2Pevent definitions
//  NOTES: Assigned to P2Pmsg_Exceptions thrown by the framework
const P2PeventID P2Pevent_OFFSET = 0x01000000;

const P2PeventID                       // Undeliverable P2PeerMsg
P2Pevent_UNDELIVERABLE = P2Pevent_OFFSET+0x01;
const P2PeventID                       // Unknown to destination
P2Pevent_UNKNOWN       = P2Pevent_OFFSET+0x02;
const P2PeventID                       // Invalid P2PeerMsg version
P2Pevent_VERSION       = P2Pevent_OFFSET+0x03;
const P2PeventID                       // P2Pump queue full
P2Pevent_QUEFULL       = P2Pevent_OFFSET+0x04;

