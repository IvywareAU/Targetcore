// Copyright © 2001-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerHub definitions and prototypes
//  NOTES: Within a virtual P2Peer network P2PeerMsg's are only exchanged
//         between objects derived from P2PeerHub's.  However, such
//         P2PeerMsg's may be routed through a heirarchy of P2PeerTarget
//         derived objects registered with a particular P2PeerHub
//         
#pragma once

#include "P2PeerTarget.h"
#include "P2PeerExplorer.h"

//  Peer login authentication. Pulled in for the p2pcng::IdResult and
//  p2pauth::AuthResult names on the hub's own surface; both headers are
//  dependency-free (<cstddef>/<ctime>) and add nothing to what this one
//  already drags in.
#include "P2PAuthLogin.h"

namespace p2pauth { class AuthPolicy; }

///////////////////////////////////////////////////////////////////////
//  What a link of a given TRUST CLASS must do
//  NOTES: The other half of P2PeerConTrust_e (P2PeerCon.h). The connection
//         states a FACT about where its frames can go; this is what the hub
//         DEMANDS of a link that stated it, and it stays on the hub - one
//         object, one lock, one place to read - which is the property
//         SECURITY.md's "no per-connection override" sentence exists to hold
//       : Full is what every link gets today: an ephemeral ECDH agreement, the
//         session cypher installed on the io object, and a login signed at one
//         end and verified at the other. Open is none of those three
//       : They are a PAIR and they move together. A link that skips the
//         agreement has no channel binding, so a signature on its login would
//         name no connection - which is F-S6-1's state - and a link that
//         signs without a cypher is the same finding from the other side. The
//         one thing this must never offer is a way to take one of the three
//         and leave the others
typedef enum
{
    P2PeerLinkPolicy_Full = 0,         // agreement, cypher, signed login
    P2PeerLinkPolicy_Open = 1,         // none of the three
} P2PeerLinkPolicy_e;

typedef void (P2PeerHub::*RUN_HUB)(void);
#define RUN_HUB_cast(method) ((RUN_HUB)(RUN_HUB) \
		(static_cast<void (P2P_MSG_CALL P2PeerHub::*)(void)>(method)))

//
//  P2PeerHub base class
//  NOTES: Manages the routing of P2PeerMsg's between hubs and implements
//         the P2PeerSys_MAP, P2PeerCon_MAP and P2PeerMsg_MAP's
//
class Targetcore_EXT P2PeerHub : public P2PeerTarget
{
      void
        RenderHubSafe();

    // Constructors and destructor
    public:
        P2PeerHub ( P2PaddrSTR strP2PaddrHub );
      virtual
       ~P2PeerHub ( );

    // P2PmsgHub management
    // NOTES: Hub's exist in the context of the thread under which 
    //        they are created
    public:
      virtual HANDLE
        SpawnHub ( LPTHREAD_START_ROUTINE pfnHubProc = 0
                 , RUN_HUB  pfnRunHub = 0 );
      virtual BOOL
        CreateHub( P2PaddrSTR strP2PaddrHub
                 , UINT nPumpsMax = 1 );
      virtual void
        PauseHub ( );
      virtual void
        WakeupHub ( );
      virtual void
        CloseHub ( );
      static DWORD WINAPI
        ProcHub  ( void *pvData );
      virtual void
        RunHub   ( );
      virtual void
        PostDestroyHub ( );
    // The arming gate CreateHub()/SpawnHub() share (Stage 3 step 8). True
    // when the hub may arm; false after it has reported, by name, the file
    // that is missing. Protected rather than private so a derived hub that
    // overrides CreateHub can keep the check instead of losing it.
    protected:
      bool
        AuthArmOrRefuse ( LPCTSTR lpszCaller );
    public:

    // P2PeerSys management
    public:
      UINT
        PostP2PeerSys ( P2PsysID nP2PsysID, WPARAM wParam, LPARAM lParam );

    // P2PeerCon management
    public:
      BOOL
        PostP2PeerCon ( P2PeerCon *pCon, P2PumpID nPumpID = 0 );
      BOOL
        ConExists  ( P2PaddrSTR strP2Paddress );
      bool
        ConQuery   ( P2PaddrSTR strP2Paddress, SafeP2PeerCon& rSafeCon );
      BOOL
        ConSignal  ( P2PaddrSTR strP2Paddress
                   , P2PsigID nSigConID
                   , void *pvData = 0, int iDataSize = 0 );
      BOOL
        ConSignal  ( P2PconID nConID
                   , P2PsigID nSigConID
                   , void *pvData = 0, int iDataSize = 0 );

    // P2PeerMsg management
    public:
      msgRESULT
        RouteP2PeerMsg ( P2PeerMsg *pMsg );
      P2PeerMsg*
        PostP2PeerMsg  ( P2PeerMsg *pMsg );
      // W6 (p2p_PumpPerf.md) - additive batch producer handoff (see P2Pwin32.h)
      void
        PostP2PeerMsgBatch ( P2PeerMsg **apMsg, size_t nCount );

    // P2PeerExpump management
    public:
      P2PeerTarget*
        PostP2PeerExpump ( P2PeerTarget *pP2PeerExpump );
      BOOL
        DropP2PeerExpump ( );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
      virtual P3PmsgItem
        Serialise ( LPCTNAM lpszVar, bool bDsc = false );

    // P2PmsgSink integration
    // NOTES: Manages P2PmsgSink's in the P2PeerTarget domain context.  Which
    //        in turn facilitates the direct injection of pumped objects into 
    //        the P2PeerCon_MAP, P2PeerSys_MAP and P2PeerMsg_MAP's.
    public:
      void
        RegisterWithHubSink ( P2PmsgSinkID nSinkID, P2PeerTarget *pTarget, P2PsysID nP2PsysID );
      void
        CancelHubSinkRegistration ( P2PmsgSinkID nSinkID, P2PeerTarget *pTarget, P2PsysID nP2PsysID = 0 );
      P2PmsgSinkID
        CreateHubSink ( LPCTSTR lpszSinkname );
      void
        CloseHubSink ( P2PmsgSinkID nTargetSinkId );
      P2PmsgSinkID
        LookupHubSink ( LPCTSTR lpszSinkname );

    // Peer login authentication
    // NOTES: OPT-IN. A hub with no identity signs nothing and a hub that does
    //        not require auth verifies nothing, so a tree that calls none of
    //        this behaves exactly as it did before the feature existed.
    //      : The hub is the home for all of it - see P2PAuthLogin.h. An
    //        accepted P2PeerCon is built by AcceptSpawn from a HAND-MAINTAINED
    //        list of copied fields, so a security setting living on the
    //        connection is one forgotten line away from silently not applying;
    //        the hub link is propagated because the connection cannot work
    //        without it.
    //      : Configure BEFORE SpawnHub()/CreateHub(). ReloadAllowList() is the
    //        one call that is valid on a running hub, and it takes the hub
    //        critical section like everything else here.
    //      : The IdResult return is deliberate: a wrong path, a group-readable
    //        key file or a DPAPI blob from another machine becomes a NAMED
    //        startup failure instead of a login that fails mysteriously later.
    public:
      p2pcng::IdResult
        SetIdentity      ( const char *pszIdentityFileUtf8
                         , bool bCreateIfAbsent = false
                         , p2pcng::IdProtection eProtect
                               = p2pcng::IdProtect_Default );
      p2pcng::IdResult
        SetAllowList     ( const char *pszAllowListFileUtf8 );
      p2pcng::IdResult
        ReloadAllowList  ( );
      // Rotation is the allow-list carrying more than one line for the same
      // address - every key listed is tried, so a peer can be issued its next
      // key before it uses one and cut over without a flag day. Revocation is
      // the file that overrides the allow-list and is what stops rotation from
      // only ever adding trust. Both are described in full in P2PAuthLogin.h.
      // ReloadRevocationList is, like ReloadAllowList, valid on a running hub.
      p2pcng::IdResult
        SetRevocationList    ( const char *pszRevocationFileUtf8 );
      p2pcng::IdResult
        ReloadRevocationList ( );
      bool
        IsRevocationUsable   ( );
      // Whether a list is CONFIGURED, which IsRevocationUsable() cannot say:
      // that one is true for a hub with no list. Refer AuthPolicy.
      bool
        IsRevocationConfigured ( );

      // Must this hub hold a revocation POSITION before it arms?
      //
      // ON BY DEFAULT since 2026-08-21, and a BREAKING CHANGE in the same
      // shape as Stage 3 step 8: a hub that requires auth and has never named
      // a revocation list no longer starts. CreateHub() returns FALSE,
      // SpawnHub() returns 0, and the refusal names RequireRevocation and the
      // file it wanted rather than the allow-list, which is fine.
      //
      // Two migrations, both one line, and the second is a real answer rather
      // than a defeat: SetRevocationList(path), or RequireRevocation(false)
      // for a closed tree whose keys are provisioned once and never
      // withdrawn. What is no longer reachable is a hub that cannot withdraw
      // a compromised key and never said that was the intention.
      //
      // It does NOT turn revocation off, and it cannot: a list configured
      // anyway is loaded, enforced and fails closed whatever this says. It
      // governs only whether the ABSENCE of one is permitted. Full argument,
      // including where it departs from step 8's, at p2pauth::ArmResult.
      void
        RequireRevocation      ( bool bRequire );
      bool
        IsRevocationRequired   ( );

    // The whole security posture, read WITHOUT EVER BLOCKING.
    // NOTES: F-S6-2. This exists instead of ten accessor
    //        calls from Serialise(), and the reason is a lock order, not
    //        tidiness.
    //      : Every accessor above takes m_oCSectionHub. Serialise() is called
    //        by QueryP2PmsgExp_Hub() while it holds BOTH process-wide statics
    //        (s_oCSectionP2PmsgHub and s_oCSectionP2PmsgPump - see the note in
    //        P2Pwin32.cpp, which took them in that order deliberately at Stage
    //        4 step 13). And the LOGIN path runs the other way: OnLogin() ->
    //        SetP2PaddrHub() takes m_oCSectionHub and then calls
    //        SetP2PmsgHubAddr(), which takes a static. So a hub answering an
    //        explorer query at the moment one of its own peers logs in has
    //        the two orders in flight at once, and a blocking read of the
    //        posture inside Serialise() would close that cycle.
    //      : A snapshot must never be able to hang the hub it describes. So
    //        this TRIES the section and gives up rather than waiting: it
    //        returns false when the hub is busy, and the caller reports the
    //        posture as UNREADABLE rather than guessing or blocking. A
    //        diagnostic that occasionally says "ask again" is worth more than
    //        one that can stop a pump, and far more than one that lies.
    //      : It is a genuine read of the live policy - NOT a cached copy
    //        refreshed by the setters. A copy would be one forgotten line away
    //        from reporting a posture the hub does not have, which is the
    //        defect this whole finding is about.
    public:
      struct Posture
      {
        bool      bAuthRequired;      // RequireAuth()
        bool      bAuthCanSign;       // an identity key is loaded
        int       nAuthArm;           // p2pauth::ArmResult
        bool      bRelayAuth;         // RequireRelayAuth()
        bool      bRelayReplay;       // RefuseRelayReplay()
        bool      bSealReplay;        // RefuseSealReplay()
        bool      bSealRequired;      // RequireSeal() - INTENT
        bool      bSealBcast;         // RequireSealBroadcast() - INTENT
        bool      bSealCanOpen;       // an agreement key is loaded
        bool      bRevocRequired;     // RequireRevocation() - INTENT
        bool      bRevocConfigured;   // a revocation list is configured
        bool      bRevocOk;           // revocation is not refusing logins
        bool      bRevocFresh;        // ...and what it knows is current
        long long llRevocEpoch;       // epoch of the applied list
        //  Per-trust-class link policy, indexed by P2PeerConTrust_e, values
        //  P2PeerLinkPolicy_e. [0] is the wire and is always Full.
        //
        //  It is here for the reason OffProcess was added to the CONNECTION
        //  snapshot closing F-S6-3: without it, a connection reporting
        //  Cypher=0 on a hub reporting AuthRequired=1 is unreadable. That pair
        //  is a defect on a wire, the tree's one legitimate exemption on DMX,
        //  and now also a stated decision - and an operator must be able to
        //  tell the three apart without reading the source. The connection's
        //  half is its Trust field; this is the hub's.
        int       anLinkPolicy[3];
        //  RequireTrustAtLeast(), as a P2PeerConTrust_e.  0 - the wire - is
        //  "no fence" and is what an unconfigured hub reads.
        //
        //  It is rendered beside the three above it because the pair is what
        //  makes an opened class legible: anLinkPolicy says which classes may
        //  skip the handshake, and this says which classes this hub will
        //  accept a connection of at all.  A hub reading InProcess/Open with
        //  nTrustFloor 0 has relaxed its in-process links and can still be
        //  handed a socket; the same hub reading nTrustFloor 2 cannot, and
        //  the difference between those two is not visible anywhere else.
        int       nTrustFloor;
        //  WaiveEndToEndInProcess() - INTENT, and the one field here that
        //  reports an ASSUMPTION rather than a mechanism. An operator reading
        //  SealRequired=1 with this also 1 is looking at a hub that requires
        //  sealing and does not always do it, which is not deducible from any
        //  other field and must not have to be inferred from the source.
        //
        //  APPENDED, like anLinkPolicy and nTrustFloor before it, and not
        //  grouped with the seal fields it belongs with. Inserting a member
        //  moves every field after it, so a consumer compiled against the
        //  previous header would read this one where bSealCanOpen used to be.
        //  Appending leaves every existing offset alone and costs only that
        //  the struct no longer reads in topic order.
        bool      bWaiveE2E;
      };
      bool
        TryReadPosture ( Posture& rOut );
      // Revocation DISTRIBUTION. The list above is only ever as current as the
      // last operator who edited this hub's copy of it, which for a mesh of any
      // size means a compromised key is refused where someone remembered and
      // honoured everywhere else. These carry a signed list between hubs so it
      // does not have to be typed N times.
      //
      // A received list is verified against the ONE authority point configured
      // here - not against the allow-list - and is MERGED, never substituted,
      // so nothing that arrives can un-revoke anything. Full rationale, and the
      // reason both of those are the way round they are, in P2PAuthLogin.h.
      //
      // Carrying a list is unprivileged: any peer may relay one, and the hub
      // needs no trust in the courier because the signature is the trust. There
      // is deliberately no automatic gossip here - WHEN to publish and WHO to
      // hand it to are routing decisions this layer does not own.
      p2pcng::IdResult
        SetRevocationAuthority ( const unsigned char *pIssuerPub );
      bool
        HasRevocationAuthority ( );
      p2pauth::RevResult
        IssueRevocationList  ( long long llEpoch,
                               unsigned char *pOut, size_t cbOut, size_t *pcbOut );
      p2pauth::RevResult
        ApplyRevocationList  ( const unsigned char *pIn, size_t cbIn,
                               size_t *pnAdded = nullptr );
      long long
        RevocationEpoch      ( );
      // 0 = never expire, and the default. Setting it means "refuse rather than
      // run on knowledge older than this", which also refuses from startup
      // until the first list arrives - refer P2PAuthLogin.h before turning it
      // on, because expiring on silence turns a partition into an outage.
      void
        SetMaxRevocationStaleness ( int nSeconds );
      bool
        IsRevocationFresh    ( );
      void
        SetAuthWindow    ( int nSeconds );          // 0 disables freshness
      // ON BY DEFAULT since Stage 3 step 8. A hub that
      // requires auth and cannot enforce it REFUSES TO ARM - CreateHub() and
      // SpawnHub() both fail, loudly and by name, rather than starting and
      // then refusing every peer that arrives. See AuthArm() below.
      //
      // RequireAuth(false) is the supported migration for a hub that does not
      // want any of this, and it must be called BEFORE CreateHub/SpawnHub
      // like every other setting here.
      void
        RequireAuth      ( bool bRequire );         // enforcement - hub only
      bool
        IsAuthRequired   ( );
      bool
        CanAuthSign      ( );

      // What a link of the given TRUST CLASS must do, when RequireAuth is on.
      //
      // This is the answer to "a DMX connection is a pointer handoff between
      // two objects on one heap, and it runs an ECDH agreement, installs a
      // BCrypt key object nothing ever consults, and signs four ECDSA
      // operations onto a login, to protect a channel that has no wire".
      // RequireAuth(false) was the only way to say so and it is all or
      // nothing: a hub with three DMX links and one TCP link either paid on
      // all four or authenticated none of them.
      //
      // THE POLICY IS STILL THE HUB'S AND THERE IS STILL NO PER-CONNECTION
      // OVERRIDE. What the connection contributes is P2PeerConTrust_e - a
      // fact about its transport, a virtual on the class, and nothing
      // AcceptSpawn can fail to copy. What must a link of that class do is
      // answered here, once, under this hub's lock, and is reported by
      // TryReadPosture. Refer the note on the AcceptSpawn hazard above: it is
      // about a security SETTING living on the connection, and this puts none
      // there.
      //
      // P2PeerConTrust_Wire CANNOT BE OPENED and this refuses to. Wire is
      // what every transport that has vouched for nothing answers - a serial
      // line, a socket that is not on loopback, and as coded a named pipe,
      // which accepts a client arriving over SMB from another host. Opening
      // it would relax the entire tree through a call that reads as though it
      // named one kind of link. RequireAuth(false) is how a wire is opened;
      // it is hub-wide, and the posture and the arming gate both say so.
      //
      // BOTH ENDS OF A LINK NEED THE SAME ANSWER. The initiating end reads
      // this to decide whether to run the agreement and sign; the accepting
      // end reads it to decide whether to demand one. A client that skipped
      // the agreement against a server that wanted it is refused exactly as it
      // is today - that refusal is F-S6-1's fix and this change is routed
      // through the same single predicate so it cannot come apart.
      //
      // Every class defaults to P2PeerLinkPolicy_Full, so a hub nobody has
      // configured is byte-for-byte what it was. Configure BEFORE
      // CreateHub()/SpawnHub(), like everything else here.
      //
      // WHAT THIS DOES NOT DO. It is a per-LINK policy and it does not touch
      // the two per-MESSAGE protections. Relay attestation and end-to-end
      // sealing are properties of an ORIGIN and a DESTINATION, not of one
      // hop: a DMX first hop says nothing about a TCP third one, so an
      // in-process link under Open still signs and still seals. Those are
      // gated on whether the destination is in this process, which is a
      // separate change and is not this one.
      void
        SetLinkPolicy    ( P2PeerConTrust_e   eClass
                         , P2PeerLinkPolicy_e ePolicy );
      P2PeerLinkPolicy_e
        GetLinkPolicy    ( P2PeerConTrust_e   eClass );

      // THE FENCE, and it is the other half of SetLinkPolicy rather than a
      // separate feature. Refuse to hold a connection whose EffectiveTrust()
      // is below eClass: a hub that exists to route inside a process says
      // P2PeerConTrust_InProcess here, and a P2PeerConWsa posted to it later
      // is refused at PostP2PeerCon with a diagnostic naming the class,
      // rather than authenticated in full and quietly making the hub a
      // network endpoint.
      //
      // THIS IS WHAT MAKES THE OPT-OUT SAFER THAN THE OLD ONE AND NOT MERELY
      // CHEAPER. RequireAuth(false) opens every link the hub will ever hold,
      // including one posted an hour later by code that never read the
      // setting. SetLinkPolicy(InProcess, Open) with RequireTrustAtLeast
      // (InProcess) opens the links that cannot leave the process and refuses
      // the rest outright.
      //
      // P2PeerConTrust_Wire is the default and means NO fence - it is the
      // class every transport that has vouched for nothing answers, so a
      // floor there refuses nothing. Configure before CreateHub()/SpawnHub(),
      // like everything else here.
      //
      // WHAT IT IS MEASURED AGAINST is EffectiveTrust(), not TrustClass(): a
      // connection an operator demoted is refused on the class they demoted
      // it to, which is the reading every other gate in this feature takes.
      // The check is made where the connection joins the hub, so it covers
      // the object the caller posts. An ACCEPTED child does not pass through
      // here - it is spawned by its service, which was fenced when IT was
      // posted, and it inherits both the class (a virtual) and the ceiling
      // (the one copied field), so it cannot read higher than the service the
      // fence already admitted.
      void
        RequireTrustAtLeast ( P2PeerConTrust_e eClass );
      P2PeerConTrust_e
        GetRequiredTrust    ( );

      // Can this hub enforce what it is set to require? Pure query, valid at
      // any time, and what CreateHub()/SpawnHub() consult before arming.
      // ArmNotRequired means auth is off - deliberately NOT ArmOk, so nothing
      // can read "this hub armed" as "this hub authenticates".
      //
      // Call it yourself before arming if you would rather report the failure
      // in your own words; the hub reports it through the P2Pevent channel
      // either way, and the two say the same thing because they come from the
      // same p2pauth::AuthArmText.
      p2pauth::ArmResult
        AuthArm          ( );
      // The allow-list path as configured, or null. Pair it with
      // p2pauth::AuthArmText(AuthArm()) to name the file in a diagnostic.
      const char *
        AuthAllowListPath ( );
      // The revocation list path as configured, or null. The twin of the
      // above, and which of the two a refusal names depends on which file
      // the ArmResult is about.
      const char *
        AuthRevocationListPath ( );

      // FIRST RUN. Creates this hub's identity if the file is not there,
      // loads it if it is, and writes the publishable half next to it as
      // <pszIdentityFileUtf8>.pub - the file whose single line an operator
      // pastes into every peer's allow-list.
      //
      // pszFingerprintOut (optional, p2pcng::kIdFingerprintLen bytes) receives
      // the human-checkable fingerprint of the point, which is what an
      // operator reads down a phone line to confirm the key that arrived is
      // the key that was sent. pbCreated (optional) reports whether this run
      // generated the key or found one.
      //
      // It deliberately does NOT create the allow-list. An empty allow-list
      // arms nothing - a hub that requires auth and trusts nobody refuses
      // every peer - and a library that silently created one would be turning
      // "who do you trust" into a file the operator never saw. Naming the
      // peers is the one part of provisioning that is not mechanical, and it
      // is the part this returns to the operator rather than guessing at.
      p2pcng::IdResult
        ProvisionAuth    ( const char *pszIdentityFileUtf8
                         , char       *pszFingerprintOut = 0
                         , size_t      cchFingerprintOut = 0
                         , bool       *pbCreated = 0
                         , p2pcng::IdProtection eProtect
                               = p2pcng::IdProtect_Default );

    // Downward relay - origin attestation
    // NOTES: Closes the one documented exemption in the source-binding rule.
    //        A link to an ANCESTOR carried no source check at all, because a
    //        message transiting down legitimately declares a source from
    //        another branch and the address alone cannot tell that apart from
    //        the parent inventing it. With this on, it is told apart by the
    //        ORIGIN's signature: the relaying peer does not hold that key, and
    //        the same at-or-below test is then applied to the identity that
    //        signed rather than to the peer that delivered.
    //      : Independent of RequireAuth(). "Who is on the other end of this
    //        connection" and "who wrote this message" are different claims, a
    //        deployment can want either alone, and making one imply the other
    //        would turn on failure modes nobody asked for.
    //      : Both ends need configuration and they are not the same
    //        configuration. The ORIGIN needs SetIdentity() so it can sign; the
    //        RECEIVER needs the origin in its SetAllowList() so it can verify,
    //        and RequireRelayAuth(true) so it insists. A receiver that requires
    //        it and does not list the origin refuses that origin's traffic -
    //        which is the correct failure, and it is a provisioning error.
    //      : Links to a descendant and to an unrelated peer are untouched:
    //        those never reached the exemption, and are still bound to the
    //        logged-in identity exactly as before.
    public:
      void
        RequireRelayAuth   ( bool bRequire );
      bool
        IsRelayAuthRequired( );

    //  Refuse an attested relay block this hub has already accepted.
    //  NOTES: Only has an effect with RequireRelayAuth(true) - it is a property
    //         of the attestation, and a hub that does not verify one has
    //         nothing to remember. Turning it on alone is not an error and not
    //         a protection either; it is inert.
    //       : Hub scope, and the cache is bounded by age AND by count: entries
    //         are kept for twice SetWindow() and dropped after, and past
    //         kSeenMax the oldest goes whatever its age. The window alone does
    //         NOT bound the memory - it bounds how long an entry lives, not how
    //         many arrive meanwhile - so on a busy hub the count is the bound
    //         that binds, and an evicted signature is replayable again. Stated
    //         in p2pauth's header at the cache rather than left to be found.
    //       : ON BY DEFAULT since Stage 3 step 10, which is
    //         where the wire change and the defaults landed together. This
    //         comment said "default off" until 2026-08-20 - the reading the
    //         gate test for F-S6-2 contradicted by printing a 1 out of an
    //         unconfigured hub. The argument for the OTHER default, and what
    //         turning it off costs, is at AuthPolicy::SetRelayReplayRefused:
    //         a hub that legitimately receives the same signed block twice
    //         sees the second refused.
      void
        RefuseRelayReplay  ( bool bRefuse );
      bool
        IsRelayReplayRefused( );

    //  Refuse a sealed body this hub has already opened.
    //  NOTES: A WEAKER guarantee than the relay one above, and the difference
    //         is not a detail: a relay block carries a signed timestamp and a
    //         sealed body does not, so the relay cache expires entries and this
    //         one cannot. It holds the most recent bodies by count, and one
    //         older than that is replayable again. See
    //         AuthPolicy::SetSealReplayRefused for the whole argument
    //       : Independent of sealing being used at all - a hub that never opens
    //         a sealed body is unaffected
    //       : ON BY DEFAULT since Stage 3 step 10, alongside
    //         RefuseRelayReplay above and for the same reason
      void
        RefuseSealReplay   ( bool bRefuse );
      bool
        IsSealReplayRefused ( );

    //  Signals that this hub's spawned pump thread has finished.
    //  NOTES: Public because ProcHub is a static trampoline and calls it
    //         through the P2ProcContext's hub pointer, not because a host has
    //         any business calling it - it is the pump thread's own last act
    //         and calling it from anywhere else tells CloseHub() a lie.
    //       : Refer m_hHubExit and CloseHub for what it is for.
      void
        SignalHubExit      ( );

    //  How old a sealed body may be before it is refused as SealErrStale.
    //  NOTES: New with the v1 seal wire format (Stage 3
    //         step 10) - a sealed body carries a signed sealed_at now, and
    //         this is what a recipient does about it. Default 24 hours.
    //       : Deliberately much larger than SetAuthWindow's 300 seconds, and
    //         for the opposite reason. A login happens between two peers that
    //         are both up; a sealed body is built for a recipient that has
    //         never connected, so this is a bound on store-and-forward and
    //         not on clock skew.
    //       : 0 disables the check. That is the right answer for a courier
    //         network measured in weeks, and it gives up the guarantee that an
    //         ancient body is refused - see AuthPolicy::SetSealWindow.
    //       : Independent of RefuseSealReplay. Freshness is a property of the
    //         block; the replay cache is something this recipient remembers.
      void
        SetSealWindow      ( int nSeconds );
      int
        GetSealWindow      ( );
      p2pauth::AuthResult
        AttestRelay ( const wchar_t *pAttester
                    , const wchar_t *pSrc, const wchar_t *pDst
                    , const wchar_t *pMsgName
                    , const void *pBody, size_t cbBody
                    , unsigned char *pOut, size_t cbOut, size_t *pcbOut );
      p2pauth::AuthResult
        VerifyRelay ( const wchar_t *pSrc, const wchar_t *pDst
                    , const wchar_t *pMsgName
                    , const void *pBody, size_t cbBody
                    , const unsigned char *pIn, size_t cbIn
                    , wchar_t *pAttesterOut, size_t cchAttesterOut
                    , long *pnSkewOut );

    // Peer login authentication - handshake internals
    // NOTES: Called by P2PeerCon on the pump/IO threads. Every one of these
    //        takes m_oCSectionHub, which the nonce cache needs anyway. A
    //        signature is tens of microseconds and happens once per
    //        connection, so serialising here costs nothing measurable - and it
    //        makes the thread safety of a shared key handle a non-question
    //        rather than a dependency on what the crypto provider promises.
    public:
      p2pauth::AuthResult
        AuthBuildLogin  ( const wchar_t *pSrc, const wchar_t *pDst
                        , unsigned char *pOut, size_t cbOut
                        , unsigned char *pNonceOut
                        , const unsigned char *pBind = 0 );
      p2pauth::AuthResult
        AuthVerifyLogin ( const wchar_t *pSrc, const wchar_t *pDst
                        , const unsigned char *pIn, size_t cbIn
                        , unsigned char *pNonceOut, long *pnSkewOut
                        , const unsigned char *pBind = 0 );
      p2pauth::AuthResult
        AuthBuildAck    ( const wchar_t *pSrc, const wchar_t *pDst
                        , const unsigned char *pNonce
                        , unsigned char *pOut, size_t cbOut
                        , const unsigned char *pBind = 0 );
      p2pauth::AuthResult
        AuthVerifyAck   ( const wchar_t *pSrc, const wchar_t *pDst
                        , const unsigned char *pNonce
                        , const unsigned char *pIn, size_t cbIn
                        , const unsigned char *pBind = 0 );

    // End-to-end sealing
    // NOTES: Hides a message BODY from every hub that carries it, which the
    //        connection cypher cannot do: an intermediate hub decides where to
    //        forward from the destination address, so it must be able to read
    //        the frame. The addresses stay in clear and the body does not.
    //      : Independent of RequireAuth(). Sealing needs an identity key (to
    //        sign) and the destination's agreement key (from the allow-list);
    //        it does not need the login to have run, and a test that seals
    //        with auth OFF is the only kind that proves the body is protected
    //        by the seal rather than by the link.
    //      : pSrc/pDst must be the addresses the carrying message declares -
    //        they are bound into the seal, so a body lifted onto a different
    //        message does not open.
    //      : Buffer sizes are p2pseal::SealedSize/OpenedSize. There is no
    //        in-place form: sealing grows the payload by kSealOverhead.
    public:
      p2pcng::IdResult
        SetAgreementKey    ( const char *pszAgreementFileUtf8
                           , bool bCreateIfAbsent = false
                           , p2pcng::IdProtection eProtect
                                 = p2pcng::IdProtect_Default );
      bool
        CanSeal            ( );

      // Seal a body that will cross an intermediate hub, or do not send it.
      //
      // ON BY DEFAULT since 2026-08-21, and it is REFUSE rather than
      // DOWNGRADE. A message whose destination is not the peer on the far end
      // of the link is sealed to that destination before it goes; if this hub
      // holds no agreement key for the destination the message is DROPPED and
      // said so, loudly. It does not travel in clear.
      //
      // The break is wide and there is no pretending otherwise: a tree that
      // has never published agreement keys stops carrying relayed traffic the
      // moment this is on. RequireSeal(false) is the migration and it restores
      // exactly what the tree did before - SealFor() still works, nothing
      // seals by itself. A hub that requires sealing must hold its own
      // agreement key, or AuthArm() reports ArmNoAgreement and it does not
      // start.
      //
      // Configure before CreateHub()/SpawnHub(), like everything else here.
      void
        RequireSeal        ( bool bRequire );
      bool
        IsSealRequired     ( );

      // Does the requirement above extend to BROADCASTS? On by default.
      //
      // A broadcast has an AUDIENCE, not a destination. On_P2PeerBCast sends a
      // copy per link and the scope they carry names a SUBTREE, which no
      // single agreement key opens - so a broadcast on a hub that requires
      // sealing is refused, every time. There is nothing to seal it to.
      //
      // RequireSealBroadcast(false) is how a deployment records that its
      // broadcasts are not confidential. It exempts fanned-out copies ONLY;
      // relayed unicast is untouched, and the exempt copies still carry the
      // origin's attestation over their scope - unencrypted, still
      // unforgeable. For traffic whose audience is positional that is the
      // honest posture, and this is what lets it be stated rather than assumed.
      //
      // Confidential broadcast is NOT what this switch provides and is a
      // design question that is still open - three shapes were analysed
      // and none of them is built.
      //
      // Configure before CreateHub()/SpawnHub(), like everything else here,
      // and TryReadPosture reports it as SealBcast.
      void
        RequireSealBroadcast    ( bool bRequire );
      bool
        IsSealBroadcastRequired ( );

      // Waive the two END-TO-END protections - relay attestation and the seal
      // - for a destination that is a hub in THIS process. OFF by default.
      //
      // READ THE ASSUMPTION BEFORE TURNING IT ON. It holds only if a message
      // to an in-process hub never transits an out-of-process one. That is
      // true of a tree whose in-process hubs form one subtree, and it is NOT
      // guaranteed otherwise.
      //
      // THE FAILURE MODE, in full, because a paraphrase of it is not enough to
      // decide by: hubs A and C in this process, hub B on another host, wired
      // A-B-C. A sends to C. C is a hub in this process, so with this on A
      // neither seals nor attests - and the body then crosses the wire to B
      // IN CLEAR, unsigned, because B is where the route actually goes. The
      // waiver's condition was true and its assumption was false, and nothing
      // in the library can tell the two apart: the destination is a fact this
      // process knows, the ROUTE is not.
      //
      // So this is the one setting here whose correctness cannot be made
      // fail-closed by construction. Everything else in this class refuses
      // when it cannot prove something; this one is an operator asserting a
      // deployment property the library cannot check - the same shape as
      // RequireAuth(false) and RequireSealBroadcast(false), and like those it
      // is opt-in so that the assumption is something somebody WROTE DOWN
      // rather than something the library assumed on their behalf.
      //
      // WHAT IT IS WORTH, measured rather than estimated (securityRevision.md
      // §8.4, and the p2p_linkcost harness): the two end-to-end protections
      // are 93% of the per-message CPU on a default hub - 1 080 us of 1 298 -
      // and the per-LINK relaxations (SetLinkPolicy) recover none of it,
      // because they are not properties of a link. This is the only switch
      // that reaches that number.
      //
      // WHAT IT DOES NOT WAIVE, and each is deliberate:
      //   - a BROADCAST. A scope names a subtree, and a subtree cannot be
      //     established to be in this process even when its root is. Use
      //     RequireSealBroadcast for that decision, which is a different one.
      //   - anything on the RECEIVE side keyed on the link. GateRelayInbound's
      //     matching exemption keys on the same registry lookup, never on the
      //     link's trust class: keyed on the class, a REMOTE ancestor could
      //     forward an unattested message down an in-process link and be
      //     admitted.
      //   - the per-hop protections. Key agreement, the signed login and the
      //     link cypher are gated by SetLinkPolicy and are untouched here.
      //
      // Configure before CreateHub()/SpawnHub(), like everything else here,
      // and TryReadPosture reports it as WaiveE2E so the choice stays visible
      // afterwards.
      void
        WaiveEndToEndInProcess     ( bool bWaive );
      bool
        IsEndToEndWaivedInProcess  ( );

      // Name a hub that may ALSO read what this hub seals - the answer to
      // "an intermediate hub has to see the body".
      //
      // The sender decides, and only the sender: the reader set is bound into
      // the sealed body's additional data and its signature, so no relay can
      // add itself and no policy on a relay can add it. Everything named here
      // can read every body this hub seals, which is a trust decision - read
      // the recipient-block note in P2PeerSeal.h first.
      //
      // At most p2pseal::kSealMaxReaders-1 of them, resolved through the
      // allow-list at seal time. A name that cannot be resolved then REFUSES
      // the send rather than sealing to fewer readers.
      p2pcng::IdResult
        AddSealReader      ( const wchar_t *pAddr );
      void
        ClearSealReaders   ( );
      bool
        CanOpen            ( );
      bool
        GetAgreementPublic ( unsigned char *pOut /*kEcdhPubLen*/ );

      p2pseal::SealResult
        SealFor  ( const wchar_t *pSrc, const wchar_t *pDst
                 , const void *pPlain, size_t cbPlain
                 , unsigned char *pOut, size_t cbOut, size_t *pcbOut );
      p2pseal::SealResult
        OpenFrom ( const wchar_t *pSrc, const wchar_t *pDst
                 , const unsigned char *pIn, size_t cbIn
                 , void *pOut, size_t cbOut, size_t *pcbOut );

    // Properties
    public:
      virtual const P2Paddr&
        SetP2PaddrHub ( P2PaddrSTR strP2PaddrHub );
      const P2Paddr&
        GetP2PaddrHub ( );
      P2PeerHub*
        GetP2PeerHub  ( );
      P2PmsgHubID
        GetHubID ( ) const;
      P2PeerTarget*
        GetP2PeerExpump ( ) const;

    // Attributes
    public:
      P2PmsgHubID       m_nHubID;
      P2Paddr           m_oP2PaddrHub;
      CRITICAL_SECTION  m_oCSectionHub;
	    P2PeerTarget     *m_pP2PeerExpump;
      //  How CloseHub() knows the spawned pump thread has actually LEFT,
      //  rather than inferring it from m_nHubID going to zero.  That inference
      //  was wrong: the zero is stored by RunHub() as its own last act, so a
      //  derived RunHub()'s tail and then ProcHub()'s CloseP2PmsgHub() both
      //  still run afterwards - refer CloseHub().
      //
      //  A MANUAL-RESET EVENT, set by ProcHub as its very last statement, and
      //  NOT a duplicate of the thread handle SpawnHub() returns.  The thread
      //  handle was the first implementation and does not port: on Linux a
      //  thread HANDLE wraps ONE std::thread, WaitForSingleObject(INFINITE)
      //  JOINS it, and std::thread::join may be called once - so "two owners
      //  who each wait and then close" is not expressible there at all, and
      //  DuplicateHandle is not in the shim because there is nothing sensible
      //  for it to do.  An event is the same guarantee with no ownership
      //  question: the caller keeps its handle, the hub keeps its event, and
      //  neither can double-close the other's.
      //
      //  It is also the more honest signal.  A thread handle answers "has the
      //  OS thread object been signalled"; this answers "has ProcHub finished
      //  its epilogue", which is the proposition CloseHub actually needs.
      HANDLE            m_hHubExit;
      DWORD             m_nHubThreadID;  // The same thread's id, to refuse a self-wait
      //  Login policy: the identity, the allow-list, the freshness window and
      //  the nonce cache. Allocated with the hub and guarded by
      //  m_oCSectionHub above - never touched without it.
      p2pauth::AuthPolicy *m_pAuthPolicy;

    // P2PeerSys_MAP handlers
    // NOTES: Placemarker for map
    protected:
    DECLARE_P2PeerSys_MAP()

    // P2PeerCon_MAP handlers
    // NOTES: Placemarker for map.  Default set of handlers reside
    //        in P2PeerTarget.
    protected:
    DECLARE_P2PeerCon_MAP()

    // P2PeerMsg_MAP handlers
    // NOTES: Placemarker for map.  Default set of handlers reside
    //        in P2PeerTarget.
    protected:
	  DECLARE_P2PeerMsg_MAP()
	  //virtual msgRESULT
	  //  On_P2PexpumpCtrl( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PeerBCast  ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PeerUCast  ( P2PeerMsg *pMsg );
      virtual msgRESULT
        On_P2PeerError  ( P2PeerMsg *pMsg );
};

//
//  P2Psys notification messages for P2PeerSys_MAP handlers
//  NOTES: Definition sequence is designed to trap use of the
//         message number elsewhere
//       : Use windows standard windows conventions etc.  Prudent
//         to be unique in Windows context
const DWORD    WM_APP_0x00b1           = WM_APP + 0x00b1;
const P2PsysID P2Psys_Win32ServiceCtrl = WM_APP_0x00b1;