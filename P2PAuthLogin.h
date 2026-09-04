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
//  P2PAuthLogin.h - proof of peer identity at login.
//
//  The problem this closes (p2p_authpsk): a P2Paddr claimed at login is
//  believed. The only policing is the P2Padomain pattern, and a server that
//  accepts more than one peer needs a broad pattern - so every peer matching
//  it may claim every address matching it. Peers can impersonate one another,
//  which in a multi-peer deployment is the entire population.
//
//  The fix is an ECDSA P-256 signature over the login, verified against a
//  public point the server already trusts (P2PIdentityStore's allow-list). The
//  private half never leaves the peer that generated it, so a compromised
//  server lets nobody impersonate anybody.
//
//  WIRE FORMAT
//
//      Login block  (91 bytes)  magic(2) | ver(1) | nonce(16) | ts(8) | sig(64)
//      Ack   block  (67 bytes)  magic(2) | ver(1) | sig(64)
//
//      login sig = ECDSA-P256( id, T("P2P-login-v1", src, dst, nonce, ts) )
//      ack   sig = ECDSA-P256( id, T("P2P-ack-v1",   src, dst, nonce)     )
//
//  src and dst are the message's OWN source and destination addresses as they
//  appear on the wire - not "this" and "that", which are opposite words on the
//  two ends of one connection. Binding the destination stops a login captured
//  at one server being replayed at another.
//
//  T() length-prefixes every field (u16 big-endian) and encodes addresses as
//  UTF-8. Both matter. Without the prefixes, ("A","BC") and ("AB","C") hash
//  alike; without UTF-8, the transcript would be wchar_t, which is 2 bytes on
//  Windows and 4 on Linux, and the two backends would disagree on the wire -
//  the class of defect the session-5 short-r/s vectors exist to catch.
//
//  FRESHNESS - and which half of it is the security property
//
//  The NONCE CACHE is the replay defence: a replayed login carries a nonce the
//  server has already seen and is refused, whatever the clock says. The
//  TIMESTAMP only bounds how long the cache must remember. So the window is a
//  memory-and-clock parameter, not a security one, and a tight window buys
//  nothing while costing deployability. Default +/-300s, per hub. Peers need
//  loosely synchronised clocks; skew is logged with its sign so a wrong clock
//  is a one-line diagnosis, and is deliberately NOT echoed to the peer (the
//  cure is NTP, not a parsed pre-auth response on a cleartext wire).
//
//  A window of 0 disables the freshness check for peers with no clock -
//  RTC-less hardware on the serial and DMX buses is the realistic case. The
//  cache can then no longer be trimmed by time, so it becomes capacity-bounded
//  and a nonce evicted by capacity is replayable. Not the default, and it says
//  so in the log.
//
//  OPT-IN, AND THAT IS NOT NEGOTIABLE
//
//  A hub with no identity signs nothing and a hub that does not require auth
//  verifies nothing, so behaviour is byte-identical to a tree without this
//  file. Enforcement is a HUB property with no per-connection override, because
//  it is the one thing that must not be losable.
//
#pragma once

#include "P2PIdentityStore.h"
#include "P2PeerSeal.h"      // SealResult, for the sealing half of the keyring

#include <cstddef>
#include <ctime>

namespace p2pauth
{
    // ---- Block sizes (bytes) -------------------------------------------
    const size_t kAuthNonceLen = 16;
    const size_t kAuthLoginLen = 91;   // 2 + 1 + 16 + 8 + 64
    const size_t kAuthAckLen   = 67;   // 2 + 1 + 64
    const size_t kAuthBindLen  = 32;   // SHA-256 channel binding

    // ---- Relay attestation ---------------------------------------------
    //  ORIGIN AUTHORSHIP, which is the thing the source-binding rule could not
    //  establish on a link to an ancestor.
    //
    //  The rule in P2PeerCon::GateAppMsgInbound binds a message's declared
    //  source to the identity its CONNECTION logged in as. On a link to a
    //  descendant that is exactly right - a child speaks for itself and its own
    //  sub-targets. On a link to an ANCESTOR it cannot hold, because a message
    //  transiting DOWN legitimately carries a source from some other branch
    //  entirely, and the address alone cannot tell that apart from the parent
    //  making the source up. So the link was exempted, and the exemption was the
    //  outstanding half of SECURITY.md roadmap item 1.
    //
    //  This closes it by changing WHAT the source is bound against rather than
    //  by weakening or removing the binding. On an ancestor link the source is
    //  bound to the identity that SIGNED the message - which the relaying peer
    //  cannot forge, because it does not hold that private key. The predicate
    //  itself is unchanged: attester.IsRable(source), the same "at or below"
    //  test the descendant link applies to its logged-in peer.
    //
    //  WIRE FORMAT - carried as a named message field, NOT prepended to the
    //  payload (see P2PeerMsg::SetRelayAttest for why that difference matters)
    //
    //      magic(2)='P','R' | ver(1) | alen(2) | attester(alen) | ts(8) | sig(64)
    //
    //      sig = ECDSA-P256( id,
    //              T("P2P-relay-v1", attester, src, dst, msgname, ts, H(body)) )
    //
    //  H(body) is SHA-256 of the message payload. The body is hashed rather than
    //  signed directly so the transcript stays a fixed size whatever the message
    //  carries; it is in the transcript at all because otherwise a relay could
    //  keep a valid attestation and swap the body underneath it, which is the
    //  same forgery wearing the origin's name.
    //
    //  The MESSAGE NAME is bound too. It is what selects the handler, so a relay
    //  that could re-label a signed body as another message type would still be
    //  choosing what the application does with it.
    //
    //  The ATTESTER is on the wire because it is not derivable from the source:
    //  a hub posts for its own sub-targets, so "Root.A" legitimately signs a
    //  message sourced "Root.A.Widget" - the same latitude IsRable already gives
    //  a logged-in peer. It is named, verified against the allow-list entry for
    //  that name, and only then tested against the source. Reading it as trusted
    //  before the signature verifies would make it a free-text claim.
    //
    //  WHAT THIS DOES NOT DO, BY DEFAULT. An attested message is valid for as
    //  long as its timestamp is inside the hub's freshness window and can be
    //  delivered twice inside it. The argument this note used to end on stands
    //  and is worth keeping: a nonce cache is not the answer here the way it is
    //  at login, because one broadcast legitimately reaches many hubs and the
    //  same hub may see a message it must not treat as a duplicate. Ordering
    //  and liveness belong to the layer that knows what a duplicate means for
    //  its own messages.
    //
    //  What that argument does NOT rule out is refusing the same signed block
    //  twice at one hub, which is a narrower claim than "no duplicates" and is
    //  exactly what a replay is. SetRelayReplayRefused(true) does that, keyed
    //  on the signature and per hub, so a broadcast still reaches every hub and
    //  two legitimate sends of identical content still both land - see that
    //  member for the premise it rests on. Off by default, because a hub that
    //  legitimately receives one signed block twice would see the second
    //  refused, and only the deployment knows whether it does.
    //
    //  Still absent either way: freshness is the only bound on how long a
    //  captured block stays interesting, and the cache is bounded by COUNT as
    //  well as by age, so a signature evicted by kSeenMax newer ones becomes
    //  replayable again even inside the window. The count bound is what stops
    //  the protection costing more than the traffic it protects - refer
    //  SetRelayReplayRefused, and NoteRelaySig for the arithmetic.
    const size_t kRelayAttesterMax = 255;             // UTF-8 bytes
    const size_t kRelayFixedLen    = 77;              // 2 + 1 + 2 + 8 + 64
    const size_t kRelayMaxLen      = kRelayFixedLen + kRelayAttesterMax;

    // ---- Channel binding -----------------------------------------------
    //  H = SHA-256 ( "P2P-kx-v1" | client_pub(64) | server_pub(64) )
    //
    //  This is the answer to p2p_authrelay. A signature over addresses, a nonce
    //  and a timestamp proves WHO connected; it says nothing about WHICH
    //  connection, so a relay that forwards the proof untouched inherits the
    //  trust it establishes. Folding H into the signed transcript ties the
    //  proof to one specific key agreement, and a relay holds neither private
    //  half of it.
    //
    //  H is NEVER transmitted. Both ends compute it from the two ephemeral
    //  public keys they already exchanged, so there is nothing on the wire for
    //  an attacker to substitute - a wrong H is simply a signature that does
    //  not verify.
    //
    //  The two keys go in by ROLE, not by arrival order: the connecting peer's
    //  key first, the accepting peer's second. Ordering by role rather than by
    //  who-spoke-first is what stops the same transcript being read two ways.
    bool AuthChannelBind ( const unsigned char *pClientPub,   // kEcdhPubLen
                           const unsigned char *pServerPub,   // kEcdhPubLen
                           unsigned char *pBindOut );         // kAuthBindLen

    // Default freshness window, seconds either side. Kerberos's figure, for
    // Kerberos's reason: the point where a machine that merely runs NTP
    // occasionally passes and a machine whose clock is wrong still fails.
    const int    kAuthWindowDefault = 300;

    //  The SEAL freshness window, and it is deliberately three orders of
    //  magnitude larger than the login one. A login happens between two peers
    //  that are both up, so 300 seconds is generous. A sealed body is built
    //  for the opposite case - a recipient that has never connected, and store
    //  and forward - so the window is what says how long it may sit in a queue
    //  or on a disk. 24 hours covers an overnight outage without covering an
    //  attacker who captured a body last month.
    //
    //  It is a POLICY knob and not a wire constant, so a deployment that needs
    //  longer says so (AuthPolicy::SetSealWindow) rather than changing the
    //  format again. 0 disables the staleness test entirely, which is the
    //  right answer for a courier network measured in weeks - and costs what
    //  the block comment on SetSealWindow says it costs.
    const int    kSealWindowDefault = 86400;

    // ---- Outcomes ------------------------------------------------------
    // Distinguishable because they want different operator responses: an
    // unknown peer is a provisioning error, a skew is a clock, a bad signature
    // is an attack or a mismatched key, and a replay is an attack outright.
    enum AuthResult
    {
        AuthOk = 0,
        AuthOff,              // no policy configured - nothing was checked
        AuthErrArgs,
        AuthErrNoIdentity,    // asked to sign with no identity loaded
        AuthErrFormat,        // too short, or the magic is not ours
        AuthErrVersion,
        AuthErrUnknownPeer,   // claimed address is not in the allow-list
        AuthErrSignature,
        AuthErrSkew,
        AuthErrReplay,
        AuthErrRevoked,       // listed, but every key it could use is revoked -
                              //   or a revocation list was configured and could
                              //   not be read, which refuses everyone
        AuthErrInternal
    };

    // NOTES: Exported, like p2pseal::SealResultText. It was not until
    //        2026-08-16, which made the enum useless across the DLL boundary:
    //        a caller could be handed an AuthResult and had no way to render
    //        it, so every out-of-tree diagnostic would have had to keep its own
    //        copy of the list and drift from it
    P2PCNG_EXT const char *AuthResultText ( AuthResult eResult );

    ///////////////////////////////////////////////////////////////////////
    //  ARMING - can this hub actually enforce what it is set to require
    //
    //  Stage 3 step 8 turned SetRequired ON by default.
    //  That flip is only half a protection on its own: a hub that requires
    //  auth and holds no keys does not refuse an attacker, it refuses
    //  EVERYONE, and it does so at the first peer's login rather than at
    //  startup. The operator finds out when the first connection fails,
    //  which in practice means at 3am and not during the deployment.
    //
    //  So a hub that requires auth is checked BEFORE it arms, and refuses to
    //  arm at all if the check fails. The result says which file is missing,
    //  and AuthArmText renders it - so the failure names the thing the
    //  operator has to go and create rather than saying "not configured".
    //
    //  ArmEmptyAllow is a distinct result and not folded into ArmNoAllowList
    //  on purpose. A file that exists and parses to zero peers is the state
    //  an operator most easily reaches by accident (created the file, has
    //  not filled it in yet), and it is indistinguishable at runtime from a
    //  correctly provisioned hub whose peers all happen to be refused. It is
    //  the same refuse-everyone outcome, so it is the same refusal to arm.
    //
    //  REVOCATION JOINED THE GATE ON 2026-08-21, and the two results it adds
    //  do NOT rest on the same argument as each other. Saying so matters,
    //  because the argument above is the one this file uses to decide what
    //  belongs here at all, and only one of the two inherits it.
    //
    //  ArmRevocationUnusable IS the step 8 case exactly. A configured list
    //  that will not load fails closed - IsRevokedPoint() returns true for
    //  every point - so the hub refuses EVERY peer, at the first login,
    //  having started perfectly happily. That is the 3am failure step 8 was
    //  written to move, in a state reached by deleting one file.
    //
    //  ArmNoRevocation does NOT, and the honest version is that the step 8
    //  reasoning runs the other way here. A hub with no revocation list
    //  refuses nobody extra; it works, and it goes on working. By the test
    //  SetRelayRequired uses below - does the unprovisioned state refuse
    //  everyone, or one narrow shape? - this would be a warning and not a
    //  gate.
    //
    //  It is a gate anyway, for a different reason. Revocation is the only
    //  mechanism in this tree by which trust already granted can be
    //  WITHDRAWN: rotation only ever adds keys, and an allow-list only ever
    //  adds lines. A hub that requires auth and has no revocation position
    //  cannot answer "this key is compromised" at all - and unlike the relay
    //  in SetRelayRequired, which legitimately holds no keys because it is
    //  not being asked to vouch for anything, this hub IS the verifier. The
    //  deployment where a withdrawal will one day be needed is exactly the
    //  one that never thought about revocation, which is the same shape of
    //  argument as step 8 even though it is not the same argument.
    //
    //  The break is REAL and larger than step 8's, because the state it
    //  refuses is a working one rather than a broken one. Every hub that
    //  requires auth and has never named a revocation list stops starting.
    //  The migration is one line and there are two of them, both honest:
    //  name a list, or SetRevocationRequired(false) and mean it.
    //
    enum ArmResult
    {
        ArmOk = 0,
        ArmNotRequired,       // SetRequired(false) - nothing to check, arms
        ArmNoIdentity,        // SetIdentity() never succeeded: cannot prove
                              //   this hub to a peer that requires auth
        ArmNoAllowList,       // SetAllowList() never called at all
        ArmAllowUnusable,     // configured, and the last load of it FAILED -
                              //   deleted, unreadable, or one bad line
        ArmEmptyAllow,        // loads, parses, and lists nobody
        //  The two revocation results are APPENDED rather than slotted in
        //  beside the allow-list results they mirror, so every value above
        //  keeps the number it has always had - the same rule SealErrReplay
        //  and SealErrVersion follow in P2PeerSeal.h.
        ArmNoRevocation,      // no revocation list, and no SetRevocationRequired
                              //   (false) to say that was deliberate
        ArmRevocationUnusable,// configured, and the last load of it FAILED -
                              //   which refuses every peer, so it refuses at
                              //   startup instead of at the first login

        //  APPENDED, not slotted in beside the results it belongs with, for
        //  the same reason the two revocation values were: every value above
        //  keeps the number it has always had.
        //
        //  SetTrustFloor names a class this hub will not hold a link below,
        //  and every class at or above that floor is Open.  So this hub can
        //  never demand a signature from anybody: PostP2PeerCon refuses the
        //  classes under the floor, and the policy for the classes over it
        //  asks for no agreement, no cypher and no signature.
        //
        //  It passes the SAME test this enum is governed by - does the
        //  unprovisioned state refuse EVERYONE, or one narrow shape?  It
        //  refuses nobody, which is the identical verdict SetRequired(false)
        //  gets, and it arms for the identical reason.
        //
        //  What it is NOT is quiet.  The posture still reads AuthRequired=1,
        //  beside TrustFloor and the three LinkPol fields, so an operator
        //  reading it sees a hub that asked for authentication and then
        //  described a set of links on which there is none of it left to do.
        //  That is a decision.  ArmNoIdentity exists to catch an omission,
        //  and this is not one.
        ArmNotRequiredByPolicy

        //  THERE IS NO ArmNoAgreement, AND THERE WAS ONE FOR AN HOUR ON
        //  2026-08-21. Recorded because the reasoning that removed it is the
        //  reasoning this enum is supposed to be governed by, and it was got
        //  wrong first.
        //
        //  Sealing became required by default in the same sitting, so the
        //  obvious companion was to refuse to arm a hub that requires sealing
        //  and holds no agreement key - it could never open a body addressed
        //  to it. That is true, and it is not the test. The test, written out
        //  at SetRelayRequired below, is whether the unprovisioned state
        //  refuses EVERYONE or one narrow shape - and this one refuses a
        //  shape: relayed traffic. Point-to-point sending, receiving and
        //  login all still work.
        //
        //  And the second half of that same note settles it outright: a relay
        //  LEGITIMATELY HOLDS NO KEYS. A hub in the middle of a tree neither
        //  originates nor terminates sealed bodies - it forwards blocks it
        //  cannot read, which is the entire point of the module - so gating
        //  on an agreement key would force every router in every tree to be
        //  keyed or opted out in order to carry traffic it is not a party to.
        //  That is the larger break, and it is the one the relay-auth note
        //  already refused to make.
        //
        //  What stands in for the gate is the same thing that stands in for it
        //  there: the refusal is LOUD and it is per-message.
        //  P2PeerCon::SealAppMsgOutbound names the message, the destination
        //  and the reason, and DOES NOT SEND. A warning at arm time
        //  (AuthPolicy::WarnSealPosture) says the same thing once at startup
        //  for the operator who would rather not find out from the first
        //  relayed message.
    };

    P2PCNG_EXT const char *AuthArmText ( ArmResult eResult );

    ///////////////////////////////////////////////////////////////////////
    //  REVOCATION DISTRIBUTION - getting a revocation to hubs that did not
    //  hear it from an operator
    //
    //  The revocation list in P2PIdentityStore.h is a local file. It works,
    //  and it is only as current as the last operator who edited THAT hub's
    //  copy. A compromised key is therefore refused exactly where someone
    //  remembered to type it and honoured everywhere else, which for a mesh of
    //  any size is the same as not being revoked at all. This block is the
    //  transport-independent half of closing that: a signed, versioned list
    //  object that one hub can hand another, and that a receiver can verify
    //  without trusting the peer that carried it.
    //
    //  A DENY-LIST THAT ANY PEER CAN INJECT IS A DENIAL OF SERVICE
    //  -----------------------------------------------------------
    //  This is the whole reason the object is signed by a NAMED authority
    //  rather than by whoever sent it. If an allow-listed peer could say
    //  "revoke X" and be believed, then one compromised peer revokes every
    //  key in the mesh and the deny-list becomes the attack. So a receiver
    //  applies a list only when it is signed by the ONE point the operator
    //  configured as its authority (SetRevocationAuthority). Carrying a list
    //  is unprivileged - any peer can relay one, including a peer that is
    //  itself revoked - because the signature, not the courier, is the trust.
    //
    //  MERGED, NEVER REPLACED - AND THAT IS THE LOAD-BEARING CHOICE
    //  ------------------------------------------------------------
    //  An applied list is UNIONED into what the hub already knows. Nothing a
    //  received list can say will ever un-revoke a key. The epoch below stops
    //  rollback, but epochs are exactly the kind of thing that goes wrong -
    //  a hub restored from a backup, a fresh hub with no epoch at all, a
    //  reissued authority that restarted its counter - and every one of those
    //  failures would otherwise be a way to silently WIDEN trust. With union
    //  semantics the worst a stale, replayed or rolled-back list can do is
    //  fail to add something, which is the direction a security failure is
    //  allowed to point. It also matches what the store already says: there
    //  is no removal API, and un-revoking is a deliberate manual edit.
    //
    //  THE EPOCH IS A COUNTER, NOT A CLOCK
    //  -----------------------------------
    //  The issuer picks a value that only ever increases; a receiver refuses
    //  anything not strictly greater than the highest it has applied. It is
    //  not compared against the wall clock, for the same reason the epoch
    //  column in the file is not: a peer with no clock (the window-0 case
    //  below) must still be able to evaluate it, and anything time-shaped is
    //  a way to move trust by moving time. Its job is to stop an attacker
    //  replaying yesterday's shorter list, and to let a receiver skip work it
    //  has already done. Because of union semantics, an epoch check that
    //  fails open is an inefficiency rather than a hole.
    //
    enum RevResult
    {
        RevOk = 0,
        RevErrArgs,
        RevErrFormat,        // too short, bad magic, or count and length disagree
        RevErrVersion,
        RevErrNoAuthority,   // no authority configured, or the configured one is
                             //   itself revoked - see SetRevocationAuthority
        RevErrIssuer,        // signed by a valid key that is not THE authority
        RevErrSignature,
        RevErrStale,         // epoch is not greater than the highest applied
        RevErrNoIdentity,    // asked to issue with no identity loaded
        RevErrNoList,        // asked to issue with no revocation list configured
        RevErrInternal
    };

    P2PCNG_EXT const char *RevResultText ( RevResult eResult );

    // ---- Wire sizes (bytes) --------------------------------------------
    //
    //     'P','V' | ver(1) | epoch(8) | count(2) | entries | issuer(64) | sig(64)
    //
    //  where each entry is point(64) | revokedAt(8), the same two columns the
    //  text file carries, so publishing a list is a re-encoding rather than a
    //  translation. The issuer point travels in the clear inside the signed
    //  region: a receiver must be able to say "not my authority" without
    //  having to try every key it knows, and binding it into the signature
    //  stops the block being re-attributed to a different issuer.
    const size_t kRevPointLen   = 64;
    const size_t kRevEntryLen   = 72;                  // point(64) | revokedAt(8)
    const size_t kRevFixedLen   = 2 + 1 + 8 + 2 + 64 + 64;   // 141
    const size_t kRevMaxEntries = 4096;                // bounds a hostile count

    inline size_t RevListLen ( size_t nCount )
    { return kRevFixedLen + nCount * kRevEntryLen; }

    ///////////////////////////////////////////////////////////////////////
    //  Login policy - one per hub
    //  NOTES: NOT internally locked. The hub owns the instance and calls
    //         every method under m_oCSectionHub, which it must hold anyway
    //         for the nonce cache. Login is a once-per-connection event, so
    //         serialising it there costs nothing measurable and makes the
    //         thread-safety of a shared key handle a non-question rather
    //         than a dependency on the crypto provider's guarantees.
    //
    class AuthPolicy
    {
      public:
        AuthPolicy ( );
       ~AuthPolicy ( );

        // ---- Configuration ---------------------------------------------
        // Loads (or creates) this peer's own identity. Returns an IdResult so
        // a bad path, a group-readable key file or a blob from another machine
        // is a NAMED startup failure rather than a login that mysteriously
        // fails later.
        p2pcng::IdResult SetIdentity ( const char *pszPathUtf8,
                                       bool bCreate = false,
                                       p2pcng::IdProtection eProtect
                                             = p2pcng::IdProtect_Default );

        // Loads the peers this hub will accept. Cached: the allow-list is read
        // here and not again per login, because a login runs on a pump thread
        // and a pump thread must not do file IO.
        p2pcng::IdResult SetAllowList  ( const char *pszPathUtf8 );
        p2pcng::IdResult ReloadAllowList ( );

        // ---- Rotation and revocation ------------------------------------
        //
        //  ROTATION is the allow-list carrying MORE THAN ONE line for the same
        //  identity. Every key listed for an address is tried, so a peer can be
        //  provisioned with its next key before it starts using it, cut over on
        //  its own schedule, and have the old line removed afterwards - with no
        //  flag day and no window where one side has rotated and the other has
        //  not. Before this, the first matching line won and a second was, in
        //  the store header's own words, dead weight.
        //
        //  The cost is honest and worth stating: N listed keys means up to N
        //  signature verifications for a failed login. N is 1 in steady state
        //  and 2 across a rollover, login is once per connection, and the work
        //  only happens for a peer that is already in the allow-list.
        //
        //  REVOCATION is a separate file that OVERRIDES the allow-list. A
        //  revoked point is refused at login and refused as a seal target, and
        //  it does not matter which file still lists it or which of the two key
        //  kinds it is. Rotation without revocation only ever ADDS trust; the
        //  two are one feature and are why both landed together.
        //
        //  FAIL CLOSED. Once a revocation list is configured, a load that fails
        //  - deleted file, bad line, unreadable - does NOT fall back to "nothing
        //  is revoked". Every verification returns AuthErrRevoked and every seal
        //  refuses, until a reload succeeds. An operator who wants no revocation
        //  list configures none; an operator who configured one and lost it has
        //  a broken deployment, and the safe reading of a missing deny-list is
        //  never "deny nothing".
        //
        //  Returns IdErrRevoked if THIS peer's own identity or agreement key is
        //  on the list. The list is still loaded and in force - the error says
        //  the hub should not start, because a peer signing with a revoked key
        //  is refused by every correctly configured peer it meets anyway, and
        //  finding that out at startup beats finding it out per connection.
        p2pcng::IdResult SetRevocationList    ( const char *pszPathUtf8 );
        p2pcng::IdResult ReloadRevocationList ( );

        size_t RevokedCount ( ) const;

        // False once a revocation list has been configured and the most recent
        // load of it failed - the fail-closed state above. Always true when no
        // revocation list is configured at all. Also false when a maximum
        // staleness is configured and the last applied list is older than it,
        // which is the one way distribution can tighten this predicate; see
        // SetMaxRevocationStaleness.
        bool   IsRevocationUsable ( ) const;

        // Is a revocation list configured on this hub AT ALL.
        // NOTES: The other half of IsRevocationUsable(), and separate because
        //        that one answers TRUE for a hub with no list - correctly, it
        //        is "revocation is not refusing anything" - which makes it
        //        useless as an answer to "is there a list". A snapshot that
        //        reported the first as the second would tell an operator with
        //        no revocation configured that their revocation was fine
        //        (TargetCore F-S6-2, found by the gate test
        //        reading 1 out of a hub that had never seen a list)
        bool   IsRevocationConfigured ( ) const { return m_bRevokeConfigured; }

        // Must this hub hold a revocation POSITION before it will arm?
        //
        // ON BY DEFAULT since 2026-08-21. "Position" is the word and not
        // "list", because there are two of them and both are positions: name
        // a revocation list, or say SetRevocationRequired(false). What is no
        // longer possible is arriving at "this hub can never withdraw a key"
        // by saying nothing, which is what the old default made the easy path
        // - the same sentence step 8 wrote about SetRequired.
        //
        // Read the ArmResult block above before turning this off. The short
        // version: rotation and the allow-list only ever ADD trust, so a hub
        // with no revocation position has no mechanism for withdrawing any,
        // and it is the verifier rather than a relay carrying traffic it does
        // not vouch for.
        //
        // SetRevocationRequired(false) is a real and supported answer - a
        // closed tree whose keys are provisioned once and never withdrawn, an
        // in-process router, a test that is not about revocation. It does NOT
        // turn revocation off: a list configured anyway is still loaded, still
        // enforced and still fails closed. It says only that the ABSENCE of
        // one is deliberate.
        //
        // It has no effect on ArmRevocationUnusable. A list that is configured
        // and will not load refuses every peer whatever this is set to, and a
        // switch that said "require no position" cannot sensibly also mean
        // "and run on a broken one".
        void SetRevocationRequired ( bool bRequire );
        bool IsRevocationRequired  ( ) const { return m_bRevokeRequired; }

        // ---- Revocation distribution -----------------------------------
        //
        // The point whose signature this hub will believe on a revocation
        // list, kEcdsaPubLen bytes. Null clears it, which turns distribution
        // off and leaves the local file as the only source.
        //
        // Configuring an authority does NOT by itself refuse anything. It
        // arms ApplyRevocationList and nothing else, so a deployment can
        // enable distribution without any flag day.
        //
        // The authority is deliberately a SEPARATE key from the allow-list,
        // not a peer address flagged as trusted. Being able to speak on the
        // network and being able to withdraw trust from the whole mesh are
        // different powers, and a compromise of a routing peer should not
        // confer the second. It also lets the authority key live offline and
        // sign lists that are then carried by peers that never hold it.
        //
        // IdErrRevoked if the point is actually ON this hub's revocation list -
        // a revoked key is not a candidate for the authority. That is the only
        // thing it means: naming an authority stays possible when the list is
        // unusable or past its staleness limit, even though those states make
        // the hub refuse every peer. Rotating the authority is how an operator
        // gets OUT of both, so refusing it there would strand the hub in the
        // state it was trying to leave.
        p2pcng::IdResult SetRevocationAuthority ( const unsigned char *pIssuerPub );
        bool             HasRevocationAuthority ( ) const { return m_bHaveAuthority; }

        // Sign this hub's CURRENT revocation list for publication. Signs with
        // this hub's identity key, so the result is only accepted by peers
        // that named this hub's point as their authority.
        //
        // llEpoch must be greater than any previously issued, and choosing it
        // is the operator's job because only they know what they published
        // last - this library has no durable place to keep a counter that
        // survives a reinstall, and inventing one from the clock would make
        // the epoch a clock. Pass 0 to use the count of entries, which is
        // monotonic for as long as the list only grows, which is the only way
        // it is meant to change.
        //
        // pOut needs RevListLen(RevokedCount()) bytes.
        RevResult IssueRevocationList ( long long llEpoch,
                                        unsigned char *pOut, size_t cbOut,
                                        size_t *pcbOut );

        // Verify a received list and MERGE it in. Union only: an entry this
        // hub already has is skipped, and nothing is ever removed. On RevOk,
        // pnAdded (optional) receives how many points were new.
        //
        // Additions are appended to the configured revocation FILE as well as
        // to the in-memory set, so they survive a restart. A hub with an
        // authority but no revocation file configured has nowhere durable to
        // put them and is refused with RevErrNoList rather than accepting a
        // list it will forget - "revoked until reboot" is not a thing this
        // should be able to mean.
        //
        // Applying a list that revokes the configured AUTHORITY's own point
        // succeeds - revocation is absolute and applies to the authority like
        // anyone else - and then latches HasRevocationAuthority to false, so
        // every later list is refused with RevErrNoAuthority until an
        // operator names a new one. An authority that has revoked itself is
        // not an authority, and continuing to believe it would make the one
        // key that can withdraw trust the one key that cannot lose it.
        RevResult ApplyRevocationList ( const unsigned char *pIn, size_t cbIn,
                                        size_t *pnAdded = nullptr );

        // Highest epoch applied, or 0 if none. Persisted nowhere: a restarted
        // hub accepts the next list it is offered whatever its epoch, which
        // union semantics make safe and which is what stops a rebuilt hub
        // from being permanently unable to catch up.
        long long RevocationEpoch    ( ) const { return m_llRevEpoch; }

        // When the last list was applied, or 0 if none has been.
        time_t    RevocationAppliedAt ( ) const { return m_tRevApplied; }

        // How old the last applied list may get before IsRevocationUsable()
        // goes false and the hub refuses everyone. 0 (the default) means
        // never.
        //
        // OFF BY DEFAULT ON PURPOSE. Expiring on silence turns "I cannot
        // reach the authority" into "I refuse all traffic", which hands an
        // attacker a total outage for the price of cutting one link - a
        // strictly better attack than whatever the revocation was protecting
        // against. Because applied lists are merged and never replaced, a hub
        // that has heard nothing for a week has not FORGOTTEN anything; it is
        // only missing whatever was published since. Running on the last
        // known-good deny-list is the right default.
        //
        // An operator who would rather refuse than run on possibly-stale
        // knowledge sets this, and it is a real choice with a real cost
        // rather than a safety default: note that with an authority
        // configured and no list yet applied the hub is stale from startup,
        // so this also means "refuse until the first list arrives".
        void SetMaxRevocationStaleness ( int nSeconds );
        int  GetMaxRevocationStaleness ( ) const { return m_nRevMaxStale; }

        // False only when a maximum staleness is configured and exceeded.
        bool IsRevocationFresh ( ) const;

        void SetWindow   ( int nSeconds );          // 0 disables freshness
        int  GetWindow   ( ) const { return m_nWindow; }

        // ON BY DEFAULT since Stage 3 step 8. It was off
        // from the day the feature landed until 2026-08-18, and off meant a
        // hub verified nothing unless someone remembered to ask it to - so
        // the deployments that most needed it were exactly the ones that
        // never called this.
        //
        // The flip is a BREAKING CHANGE and is meant to be. A hub that is not
        // provisioned no longer starts (see Arm() and P2PeerHub::CreateHub),
        // so a deployment that has never configured auth finds out at startup
        // rather than at the first peer's login. The migration is one line -
        // either provision the hub, or say RequireAuth(false) and mean it.
        //
        // SetRequired(false) is a real and supported answer. A hub on a
        // trusted segment, an in-process router, a test that is not about
        // authentication: all of those turn it off and arm as they always
        // did. What is no longer possible is turning it off BY SAYING
        // NOTHING, which is what the old default made the easy path.
        void SetRequired ( bool bRequire );
        bool IsRequired  ( ) const { return m_bRequired; }

        // What a link of a given TRUST CLASS must do, when SetRequired is on.
        //
        // 0 is "full" - the key agreement, the link cypher and a signed,
        // verified login, which is what every link gets today. 1 is "open" -
        // none of the three. The class is P2PeerConTrust_e: 0 wire, 1 local,
        // 2 in-process.
        //
        // WHY THIS IS INTS AND NOT THE TWO ENUMS. Both of them live in
        // P2PeerCon.h, which reaches stdafx.h and MFC; this translation unit
        // is one of the three that deliberately compiles without either,
        // because the login transcript IS the wire and a byte of drift
        // between the CNG and OpenSSL builds is a login that works only
        // within one operating system. P2PeerHub's typed surface is where the
        // enums belong and it is the only caller.
        //
        // CLASS 0 CANNOT BE OPENED and this refuses to do it. A wire is the
        // answer for every transport that has not vouched for anything, so
        // opening class 0 would relax every link in the tree through a call
        // that reads as though it relaxed one kind - and RequireAuth(false)
        // already says that, hub-wide, loudly, and in one place an operator
        // and a posture reader both already know to look.
        //
        // Both classes default to full, so a hub nobody has configured
        // behaves exactly as it did before this existed.
        void SetLinkPolicy ( int nTrustClass, int nPolicy );
        int  GetLinkPolicy ( int nTrustClass ) const;

        // THE FENCE.  The lowest trust class this hub will hold a link of;
        // P2PeerHub::PostP2PeerCon refuses anything below it.  0 - the wire -
        // is the default and means NO fence, because a wire is what every
        // transport that has vouched for nothing answers and a floor there
        // would refuse nothing.
        //
        // It is the half of SetLinkPolicy that keeps a relaxation from
        // becoming an exposure.  A hub that opens its in-process class is one
        // PostP2PeerCon away from carrying a socket it did not plan for.  The
        // socket would authenticate in full - the wire's policy is Full and
        // cannot be set otherwise - so nothing is WEAKENED; what happens is
        // that a hub which exists to route inside a process quietly becomes a
        // network endpoint.  SetTrustFloor(2) says out loud that it is not
        // one, and the refusal names the class it refused.
        //
        // Ints and not the enum, for the reason written out over
        // SetLinkPolicy.  An out-of-range class is ignored.
        void SetTrustFloor ( int nTrustClass );
        int  GetTrustFloor ( ) const;

        // Is there a fence, and is every class at or above it Open?  Then
        // this policy can never demand a signature from anybody, which is
        // what ArmNotRequiredByPolicy reports.
        //
        // FALSE WHEN THERE IS NO FENCE, whatever the classes say, and that is
        // the load-bearing half.  Without a floor, a link of a class this hub
        // has NOT opened can still be posted to it, so "everything held is
        // open" is not a property the hub has - it is one it happens to have
        // until the next PostP2PeerCon.
        bool LinkPolicyOpensAllHeld ( ) const;

        // Can this policy enforce what it is set to require? Pure query - it
        // loads nothing, changes nothing, and is safe to call at any time.
        // Returns ArmNotRequired (not ArmOk) when auth is off, so a caller
        // cannot read "armed" as "authenticating".
        ArmResult Arm ( ) const;

        // The allow-list path as configured, or null if none ever was. This is
        // what the arming diagnostic names, so it is the string an operator is
        // told to go and fix. Valid until the next SetAllowList.
        const char *AllowListPath ( ) const { return m_pszAllowPath; }

        // The revocation list path as configured, or null if none ever was -
        // the twin of AllowListPath, and it exists for the same one reason:
        // ArmRevocationUnusable has to be able to name the file it lost.
        const char *RevocationListPath ( ) const { return m_pszRevokePath; }

        // False once an allow-list has been configured and the most recent
        // load of it failed. True when none is configured at all - "no
        // allow-list" is a state Arm() reports separately, and folding the two
        // together here would make a hub that never had one look broken.
        bool IsAllowUsable ( ) const { return !m_pszAllowPath || m_bAllowUsable; }

        // Require origin attestation on a message admitted by the ancestor
        // exemption. SEPARATE from SetRequired, and not implied by it: login
        // authentication proves who is on the other end of a connection, which
        // is a different claim from who wrote a message that peer is relaying.
        // A deployment can want either without the other, and collapsing them
        // would make turning one on silently turn on the other's failure modes.
        //
        // ON BY DEFAULT since Stage 3 step 9. A hub refuses a
        // message arriving down an ancestor link whose source is outside that
        // ancestor's subtree unless the message carries an attestation that
        // verifies AND whose attester is entitled to the source.
        // SetRelayRequired(false) restores the pre-existing exemption exactly,
        // and is the documented migration.
        //
        // WHY THIS IS NOT PART OF THE ARMING GATE, when SetRequired is.
        // Not an oversight, and the asymmetry is the whole judgement:
        //
        //   * An unprovisioned hub that REQUIRES LOGIN AUTH refuses every peer.
        //     There is no traffic it can carry, so refusing to arm loses
        //     nothing and moves the failure to the deployment. That is step 8.
        //
        //   * An unprovisioned hub that REQUIRES RELAY AUTH refuses one shape
        //     of message: arriving down an ancestor link, sourced outside that
        //     ancestor's subtree. A hub with no ancestor link never reaches it,
        //     and a tree shallower than four levels cannot produce it at all
        //     (see p2p_authancestor on why four).
        //
        //   * And a RELAY LEGITIMATELY HOLDS NO KEYS. "A router being unable to
        //     forge what it forwards is the whole claim" - so gating on
        //     provisioning would force every router in every tree to be either
        //     keyed or opted out, to carry traffic it is not being asked to
        //     vouch for. That is a larger break than the one being closed, and
        //     it would make "carries downward traffic with no switch set"
        //     impossible to satisfy.
        //
        // What stands in for the gate is that the refusal is LOUD: the message
        // is dropped, the connection with it, and GateRelayInbound names the
        // relaying peer, the claimed source, the AuthResult, and which of "no
        // attestation attached", "attester not in this allow-list" or a clock
        // skew it was. There is no silent-refusal path here to move earlier.
        void SetRelayRequired ( bool bRequire );
        bool IsRelayRequired  ( ) const { return m_bRelayRequired; }

        // Refuse an attested relay block that this hub has already accepted.
        //
        // WHY THIS IS A SWITCH AND NOT THE DEFAULT. The block comment on
        // kRelayFixedLen argues that a nonce cache is the wrong shape here,
        // because one broadcast legitimately reaches many hubs. That argument
        // survives, and this cache is built so as not to contradict it: it is
        // keyed on the SIGNATURE, it is per-policy - so per hub - and a
        // broadcast fanning out to many hubs presents each of them with the
        // block once. What it refuses is the same signed block delivered twice
        // to the SAME hub, which is what a replay is.
        //
        // Two legitimate sends of byte-identical content do NOT collide,
        // because ECDSA signing is randomised on both backends: the same
        // transcript signed twice yields two different signatures. That is the
        // premise the whole design rests on, so AuthSelfTest asserts it
        // outright rather than trusting it - if anyone moves this tree to
        // deterministic (RFC 6979) signing, that case fails and says why.
        //
        // ON BY DEFAULT since Stage 3 step 10. What it
        // still does not do: a hub that legitimately receives one signed block
        // twice - a DAG topology rather than a tree, or an application that
        // re-delivers deliberately - will see the second copy refused.
        //
        // That was the argument for leaving it off, and the argument that
        // overturned it is that the shape being described is NARROW and the
        // exposure it was traded against is not. A duplicate only collides if
        // the same hub is handed the same SIGNATURE twice, which a tree cannot
        // do at all; and freshness already refuses a block older than twice
        // the window, so what "off" bought was a replay window for every
        // deployment in order to keep one topology working for the few that
        // have it. A DAG deployment turns it off in one line and knows it has
        // one; a tree deployment cannot know it had a replay window.
        //
        // HOW FAR BACK IT REMEMBERS is bounded twice over, by age AND by count,
        // and the count bound is the one with teeth. Entries older than twice
        // SetWindow() are dropped because freshness would refuse them anyway;
        // beyond kSeenMax entries the oldest is evicted whatever its age. Age
        // alone would not bound anything a busy hub cares about - it caps how
        // long an entry lives, not how many arrive meanwhile, and this cache is
        // scanned once per block, so an uncapped one makes the protection cost
        // grow with the square of the relayed traffic. The price of the cap is
        // that a signature flushed by kSeenMax newer ones is replayable again
        // inside the window it should have covered; buying that back costs an
        // attacker kSeenMax genuinely signed blocks through the same hub.
        void SetRelayReplayRefused ( bool bRefuse );
        bool IsRelayReplayRefused  ( ) const { return m_bRelayReplay; }

        // Refuse a sealed body this recipient has already opened. Same shape as
        // the relay switch above and the same premise - keyed on the sender's
        // signature, which is unique per seal - but it is bounded DIFFERENTLY,
        // and the difference is the whole reason this is a weaker guarantee.
        //
        // The relay cache trims by time, because a relay block carries a signed
        // timestamp and the freshness window refuses an old one: an entry only
        // has to outlive what freshness would still accept. A SEALED BODY
        // CARRIES NO TIMESTAMP AND NEVER EXPIRES, so nothing refuses an old one
        // and an entry that ages out restores exactly the replay it was there
        // to stop. Trimming this cache by time would therefore not bound the
        // memory - it would tell an attacker how long to wait.
        //
        // THAT WAS TRUE UNTIL 2026-08-18. The wire change in Stage 3 step 10
        // put a signed sealed_at in the block, and with it the
        // gap closes rather than narrows. This is now ON BY DEFAULT and the
        // honest statement is different:
        //
        //   * A body outside the freshness window is refused as SealErrStale,
        //     whether or not it has ever been seen. See SetSealWindow.
        //   * Inside the window, a body this recipient has already opened is
        //     refused as SealErrReplay from the cache.
        //   * And when the cache evicts by COUNT, the evicted entry's stamp
        //     becomes a FLOOR: everything sealed at or before it is refused
        //     from then on. That is what closes the old hole. Previously a
        //     signature flushed by kSeenMax newer ones became replayable
        //     again; now flushing it makes it, and everything as old as it,
        //     permanently unacceptable instead.
        //
        // The floor is the part with a cost, and it is a cost in the honest
        // direction: under cache pressure a LEGITIMATE body that has been
        // sitting in a queue longer than kSeenMax newer bodies took to arrive
        // is refused as a replay. It has never been seen; it is simply older
        // than the recipient can still prove anything about. Refusing it is
        // the safe reading, and raising kSeenMax or shortening the queue are
        // the answers - not accepting it.
        void SetSealReplayRefused ( bool bRefuse );
        bool IsSealReplayRefused  ( ) const { return m_bSealReplay; }

        // How old a sealed body may be, in seconds, before Open refuses it as
        // SealErrStale. Symmetric: a body stamped that far in the FUTURE is
        // refused too, because a clock ahead of ours is the same evidence as a
        // clock behind it. Default kSealWindowDefault (24 hours).
        //
        // This is independent of SetSealReplayRefused. Freshness is a property
        // of the block since it started carrying a stamp; the replay cache is
        // a thing this recipient remembers. Turning the cache off does not
        // make an ancient body acceptable.
        //
        // 0 DISABLES IT, and that is a real option with a real price rather
        // than a lax setting. A courier network that measures delivery in
        // weeks needs it. What it gives up: the cache's age-independent
        // guarantee is all that is left, so a body older than the floor is
        // still refused but one that has simply been waiting a very long time
        // is accepted - which is exactly the store-and-forward case, and
        // exactly what an attacker who captured a body a year ago also has.
        void SetSealWindow ( int nSeconds );
        int  GetSealWindow ( ) const { return m_nSealWindow; }

        // The floor described above: the newest sealed_at that has been
        // EVICTED from the replay cache, or 0 if nothing has been. Exposed
        // because "why was that refused" is otherwise unanswerable from
        // outside - a refusal at the floor and a refusal from the cache are
        // both SealErrReplay, and only one of them means someone replayed
        // something.
        long long SealReplayFloor ( ) const { return m_llSealFloor; }
        bool CanSign     ( ) const { return m_bHaveIdentity; }
        size_t AllowCount ( ) const;

        // ---- Directory lookups the sealing layer needs -----------------
        // The allow-list is the only directory this library has, so the
        // end-to-end seal reads its keys from here. Public, unlike the private
        // FindPeer the login uses, because sealing happens above the login and
        // not inside it.
        //
        // false from FindAgreement means "not in the allow-list, in it with no
        // agreement column, or in it with every agreement key revoked". All
        // three are a refusal to seal - never a fallback to sending the body in
        // clear.
        //
        // With a rollover in progress this returns the FIRST non-revoked
        // agreement key, which is the older one until the operator revokes it.
        // That is the intended order: the recipient still holds both private
        // halves, so the old key still opens, and revoking it is the single
        // edit that moves every sender onto the new one at once.
        bool FindAgreement ( const wchar_t *pAddr, unsigned char *pAgreeOut );

        // The peer's first non-revoked identity point. Kept for callers that
        // want one key; Open() does NOT use it, because a sealed body has to be
        // tried against every key the sender might have signed with.
        bool FindIdentity  ( const wchar_t *pAddr, unsigned char *pPubOut );

        // ---- Login (client side builds, server side verifies) -----------
        // pNonceOut receives the nonce that was signed; the caller keeps it to
        // check the ack against.
        //
        // pBind is the kAuthBindLen channel binding from AuthChannelBind(), or
        // null when no key agreement has run. Null and all-zeroes are NOT the
        // same transcript - every field is length-prefixed, so "absent" and
        // "present and zero" cannot collide. Both ends must pass the same
        // thing or the signature does not verify, which is the point: there is
        // no negotiation and therefore nothing to downgrade.
        AuthResult BuildLogin  ( const wchar_t *pSrc, const wchar_t *pDst,
                                 unsigned char *pOut, size_t cbOut,
                                 unsigned char *pNonceOut,
                                 const unsigned char *pBind = nullptr );
        AuthResult VerifyLogin ( const wchar_t *pSrc, const wchar_t *pDst,
                                 const unsigned char *pIn, size_t cbIn,
                                 unsigned char *pNonceOut, long *pnSkewOut,
                                 const unsigned char *pBind = nullptr );

        // ---- Ack (server side builds, client side verifies) -------------
        AuthResult BuildAck  ( const wchar_t *pSrc, const wchar_t *pDst,
                               const unsigned char *pNonce,
                               unsigned char *pOut, size_t cbOut,
                               const unsigned char *pBind = nullptr );
        AuthResult VerifyAck ( const wchar_t *pSrc, const wchar_t *pDst,
                               const unsigned char *pNonce,
                               const unsigned char *pIn, size_t cbIn,
                               const unsigned char *pBind = nullptr );

        // Is there an auth block at the front of this buffer? Cheap magic and
        // length test, used only for diagnostics - never to decide whether to
        // strip, which follows verification and nothing else.
        static bool LooksLikeBlock ( const void *pv, size_t cb );

        // ---- Relay attestation (origin builds, every hop may verify) ----
        //  See the block comment on kRelayFixedLen above for the format and for
        //  what this is closing.
        //
        //  pAttester is the address this hub signs AS - its own hub address.
        //  The identity key loaded by SetIdentity is what signs, so a hub whose
        //  key is listed in the receiver's allow-list under another name will
        //  build a block that verifies against nothing. That is provisioning,
        //  and it fails loudly at the far end rather than quietly here.
        //
        //  pcbOut receives the block length, which varies with the attester's
        //  UTF-8 length. cbOut must be at least kRelayMaxLen, or the exact
        //  length a previous call reported for the same attester.
        AuthResult BuildRelay  ( const wchar_t *pAttester,
                                 const wchar_t *pSrc, const wchar_t *pDst,
                                 const wchar_t *pMsgName,
                                 const void *pBody, size_t cbBody,
                                 unsigned char *pOut, size_t cbOut,
                                 size_t *pcbOut );

        //  Verifies the signature and reports WHO made it. It deliberately does
        //  NOT decide whether that attester may speak for pSrc: that is an
        //  address-tree question (P2Paddr::IsRable), this namespace has no
        //  P2Paddr, and splitting it keeps the cryptography and the routing rule
        //  from being able to drift into disagreeing. AuthOk here means "this
        //  block was made by the named identity over exactly this message" and
        //  nothing more - the caller must still apply the scope test.
        //
        //  pAttesterOut receives the name the block claims, AFTER it has been
        //  verified against the allow-list entry of that name. It is written on
        //  AuthOk only; on every failure path it is left as an empty string, so
        //  a caller that ignores the return value cannot pick up an unverified
        //  address.
        AuthResult VerifyRelay ( const wchar_t *pSrc, const wchar_t *pDst,
                                 const wchar_t *pMsgName,
                                 const void *pBody, size_t cbBody,
                                 const unsigned char *pIn, size_t cbIn,
                                 wchar_t *pAttesterOut, size_t cchAttesterOut,
                                 long *pnSkewOut );

        // Cheap magic-and-length test, for diagnostics only - never a trust
        // decision, for the same reason LooksLikeBlock is not one.
        static bool LooksLikeRelayBlock ( const void *pv, size_t cb );

        // ---- End-to-end sealing ----------------------------------------
        //  This class is where the two keys and the directory already live, so
        //  it is where sealing is driven from. It stays a policy object: the
        //  cryptography is p2pseal's, and what is added here is only the part
        //  that needs the keyring - "which agreement key does that address
        //  have", "sign as us".
        //
        //  Independent of the login. A hub may seal without requiring auth (the
        //  three-hub test does exactly that, so a pass cannot be credited to
        //  link crypto), and may require auth without ever sealing anything.

        // Load (or create) this peer's static agreement key - the half others
        // seal to. Distinct from SetIdentity by design; see P2PIdentityStore.h.
        p2pcng::IdResult SetAgreement ( const char *pszPathUtf8,
                                        bool bCreate = false,
                                        p2pcng::IdProtection eProtect
                                              = p2pcng::IdProtect_Default );

        // Sealing needs the identity (to sign); opening needs the agreement
        // key (to derive). A peer can be able to do one and not the other, and
        // the distinction is worth reporting rather than collapsing.
        bool CanSeal ( ) const { return m_bHaveIdentity; }
        bool CanOpen ( ) const { return m_bHaveAgreement; }

        // This peer's agreement point, for publishing into others' allow-lists.
        bool GetAgreementPublic ( unsigned char *pOut /*kEcdhPubLen*/ );

        // pSrc and pDst must be the addresses the carrying message will
        // declare: they are bound into the seal, so a body that arrives on a
        // different pair does not open.
        // llWhen: seconds since the epoch to stamp the body with, 0 for now.
        // Only a test proving the freshness window or the replay floor has any
        // business passing a value - see p2pseal::Seal.
        // Must a body that will cross an intermediate hub be sealed?
        //
        // ON BY DEFAULT since 2026-08-21, and it is REFUSE rather than
        // DOWNGRADE: a message whose destination is not the peer on the other
        // end of the link is sealed to that destination, and if this hub
        // holds no agreement key for it the message is NOT SENT. It does not
        // go in clear with a warning. The whole finding F-S6-3 was about a
        // protection that was inherited rather than enforced, and a seal that
        // silently becomes cleartext when the directory is incomplete is that
        // defect with a different name.
        //
        // What it costs is real and is the reason this is a switch at all: a
        // tree that has not published agreement keys stops carrying relayed
        // traffic the moment this is on. SetSealRequired(false) restores the
        // old behaviour exactly - sealing stays available through SealFor,
        // and nothing seals by itself.
        //
        // A hub that requires sealing and holding no agreement key of its own
        // cannot open a body addressed to it. That is NOT an arming refusal -
        // see the note in ArmResult for why, which is the same reason
        // SetRelayRequired is not one - but it is warned about once at arm
        // time and refused loudly per message at the send path.
        void SetSealRequired ( bool bRequire );
        bool IsSealRequired  ( ) const { return m_bSealRequired; }

        // Does the seal requirement above extend to BROADCASTS? On by
        // default, so it does.
        //
        // A broadcast is not a message with a destination, it is a message
        // with an AUDIENCE. P2PeerHub::On_P2PeerBCast sends a copy per link,
        // and the scope those copies carry (TMsg_Scp) names a SUBTREE - which
        // no single agreement key opens. So a broadcast on a hub that requires
        // sealing is refused, every time, and that is correct: there is
        // nothing to seal it to.
        //
        // SetSealBroadcastRequired(false) is how a deployment says, on the
        // record, that its broadcasts are not confidential. It exempts ONLY
        // fanned-out copies - relayed unicast is untouched - and it does NOT
        // exempt them from attestation: an exempt broadcast still carries the
        // origin's signature over its scope, so it is unencrypted and still
        // unforgeable. That is the honest position for traffic whose audience
        // is positional, and it is available here rather than assumed.
        //
        // WHY A SWITCH AND NOT A DEFAULT EITHER WAY. Before TMsg_Scp existed
        // the fan-out re-addressed every copy to its own link peer, which made
        // SealAppMsgOutbound's last-hop exemption true at every hop: broadcast
        // was exempt from sealing entirely, silently, and nobody had decided
        // it. The defect was never that a broadcast went unencrypted - it was
        // that the exemption was INHERITED FROM AN ACCIDENT rather than
        // chosen. This is what makes choosing it possible, and TryReadPosture
        // reports it so the choice is visible afterwards.
        void SetSealBroadcastRequired ( bool bRequire );
        bool IsSealBroadcastRequired  ( ) const
             { return m_bSealBroadcastRequired; }

        // Waive the two END-TO-END protections - relay attestation and the
        // seal - for a destination that is a hub in THIS process. OFF by
        // default, and it is the one setting in this class whose correctness
        // rests on a deployment assumption rather than on a mechanism.
        //
        // Refer P2PeerHub::WaiveEndToEndInProcess for the assumption, the
        // failure mode, and why it is opt-in. This class only holds the bit;
        // P2PeerCon applies it, and the registry lookup that keys it lives in
        // P2Pwin32.
        void SetEndToEndWaivedInProcess ( bool bWaive );
        bool IsEndToEndWaivedInProcess  ( ) const
             { return m_bWaiveE2EInProcess; }

        // Hubs this peer will name as ADDITIONAL readers on everything it
        // seals - the answer to "we need an intermediate hub to read the
        // body". Empty by default, which is the v1 behaviour: only the
        // destination can open it.
        //
        // THIS IS SENDER-SIDE CONFIGURATION AND THAT IS THE POINT. A relay
        // cannot add itself, and policy on the relay cannot add it either;
        // the reader set is bound into the body's additional data and the
        // signed transcript, so only the operator of the SENDING hub decides
        // who may read what it sends. Read the recipient-block note in
        // P2PeerSeal.h before using it: every name here is a party that can
        // read every body this hub seals, which is a trust decision and not a
        // routing one.
        //
        // Addresses, not keys - each is resolved through the allow-list at
        // seal time, so revoking a reader's agreement key removes its access
        // without editing this list. A name that resolves to nothing at seal
        // time REFUSES the seal rather than quietly sealing to fewer readers:
        // a body that silently loses a reader is one the hub that needed it
        // cannot process, for a reason nobody can see.
        p2pcng::IdResult AddSealReader   ( const wchar_t *pAddr );
        void             ClearSealReaders ( );
        size_t           SealReaderCount ( ) const;

        p2pseal::SealResult Seal ( const wchar_t *pSrc, const wchar_t *pDst,
                                   const void *pPlain, size_t cbPlain,
                                   unsigned char *pOut, size_t cbOut,
                                   size_t *pcbOut, long long llWhen = 0 );

        p2pseal::SealResult Open ( const wchar_t *pSrc, const wchar_t *pDst,
                                   const unsigned char *pIn, size_t cbIn,
                                   void *pOut, size_t cbOut, size_t *pcbOut );

      private:
        p2pcng::EcdsaP256 *m_pIdentity;      // this peer's own key
        bool               m_bHaveIdentity;
        p2pcng::EcdhP256  *m_pAgreement;     // this peer's static ECDH key
        bool               m_bHaveAgreement;
        bool               m_bRequired;
        //  Per-trust-class link policy, indexed by P2PeerConTrust_e. Three
        //  entries because the enum has three members; [0] is the wire and is
        //  pinned to "full" by SetLinkPolicy, so the array is uniform and the
        //  refusal lives in one place rather than in every reader.
        unsigned char      m_aLinkPolicy[3];
        //  The fence - refer SetTrustFloor.  0 is P2PeerConTrust_Wire and is
        //  "no fence": it is what an unconfigured hub has and what every
        //  transport that vouches for nothing answers, so a floor there
        //  refuses nothing and changes nothing.
        unsigned char      m_nTrustFloor;
        bool               m_bRelayRequired;
        bool               m_bRelayReplay;
        bool               m_bSealReplay;
        //  Sealing (2026-08-21). Intent, and the reader list the intent uses.
        bool               m_bSealRequired;
        //  Does that intent extend to broadcasts (2026-08-25)? Separate
        //  because a broadcast has an audience rather than a destination, so
        //  it is a different question with a different answer.
        bool               m_bSealBroadcastRequired;
        //  The end-to-end waiver (securityRevision.md §6.3, 2026-09-04). OFF,
        //  and the default is the whole of its safety: every other member here
        //  fails closed on a mechanism, this one fails closed on being unset.
        bool               m_bWaiveE2EInProcess;
        //  std::vector<std::wstring> behind a void*, the same pimpl shape the
        //  allow-list and the caches use - this header is included by TUs that
        //  must not pull in <vector>.
        void              *m_pSealReaders;
        int                m_nWindow;
        //  Seal freshness (Stage 3 step 10). Separate from m_nWindow because
        //  the two answer different questions on different timescales - see
        //  kSealWindowDefault.
        int                m_nSealWindow;
        //  The newest sealed_at evicted from m_pSeenSeal. Everything at or
        //  before it is refused, which is what makes the count bound safe.
        long long          m_llSealFloor;

        void              *m_pAllow;         // vector<AllowEntry>
        void              *m_pSeen;          // vector<SeenNonce>
        // vector<SigMark>, and deliberately NOT the same container as m_pSeen:
        // a login nonce and a relay signature are different lengths, and one
        // cache holding both would make an evicted login nonce depend on how
        // much relay traffic a hub carried.
        void              *m_pSeenRel;
        // vector<SigMark> again, and a third container rather than a shared
        // one: this cache is trimmed by a different rule from m_pSeenRel (see
        // SetSealReplayRefused), so merging them would force one rule on both.
        void              *m_pSeenSeal;
        // Next slot to overwrite once m_pSeenSeal is full. It is a RING rather
        // than a queue because it is bounded by count alone, so nothing ever
        // asks which entry is oldest - refer NoteSealSig. m_pSeenRel has no
        // equivalent on purpose: its age trim needs arrival order.
        size_t             m_nSealNext;
        char              *m_pszAllowPath;
        // Did the LAST load of that path succeed? SetAllowList keeps the path
        // even when the load fails, so the path alone cannot answer "is there
        // a usable allow-list" - and that is the exact case Stage 3 step 8
        // falsifies with: delete the file, and the hub must refuse to arm.
        bool               m_bAllowUsable;

        void              *m_pRevoked;       // vector<RevPoint>
        char              *m_pszRevokePath;
        bool               m_bRevokeConfigured;
        bool               m_bRevokeUsable;
        //  Whether a revocation POSITION is required to arm (2026-08-21).
        //  Intent, not capability - it is never consulted by a verification,
        //  only by Arm().
        bool               m_bRevokeRequired;

        // ---- Revocation distribution -----------------------------------
        // A fixed array rather than a heap point, so no allocation can fail
        // between deciding to trust an authority and being able to name it.
        unsigned char      m_aAuthority[64];   // kEcdsaPubLen
        bool               m_bHaveAuthority;
        long long          m_llRevEpoch;
        time_t             m_tRevApplied;
        int                m_nRevMaxStale;

        // Append one point to the configured revocation FILE and to the
        // in-memory set. Returns false if it could not be made durable, which
        // ApplyRevocationList turns into a refusal of the whole list rather
        // than a partial apply that a restart would silently undo.
        bool  AddRevokedPoint ( const unsigned char *pPoint, long long llAt );

        // Enumerates the non-revoked identity keys listed for pAddr, in file
        // order: call with nIndex 0, 1, 2 ... until it returns false. Index
        // based rather than returning a container so this header keeps its STL
        // out of the ABI, the same reason m_pAllow is a void*.
        bool  PeerKeyAt  ( const wchar_t *pAddr, size_t nIndex,
                           unsigned char *pPubOut );

        // How many entries pAddr has at all, revoked or not. The difference
        // between this and "no key verified" is what separates AuthErrRevoked
        // from AuthErrUnknownPeer.
        size_t PeerKeyCount ( const wchar_t *pAddr, bool *pbAllRevoked );

        // Verify pSig over the transcript against every key listed for pAddr.
        // Shared by VerifyLogin and VerifyAck so the two cannot drift apart on
        // which keys they are willing to accept.
        AuthResult VerifyAgainstPeer ( const wchar_t *pAddr,
                                       const unsigned char *pTr, size_t cbTr,
                                       const unsigned char *pSig );

        // The POLICY question: should this point be refused. Fails closed, so
        // it answers true for everything when the list is unusable or stale.
        bool  IsRevokedPoint ( const unsigned char *pPoint ) const;

        // The MEMBERSHIP question: is this point actually in the set. Never
        // fails closed. Separate from IsRevokedPoint because the merge in
        // ApplyRevocationList asks "do I already have this" - and if that
        // question were answered by the fail-closed one, a hub whose list was
        // unusable would skip every entry it was being sent and report a
        // successful apply that added nothing.
        bool  IsRevokedPointRaw ( const unsigned char *pPoint ) const;

        bool  SelfKeyRevoked ( ) const;

        bool  FindPeer   ( const wchar_t *pAddr, unsigned char *pPubOut );
        bool  NoteNonce  ( const unsigned char *pNonce, time_t tNow );
        bool  SeenNonce  ( const unsigned char *pNonce ) const;

        // The relay half of the two above, keyed on the 64-byte signature.
        // Consulted and populated only AFTER a block's signature verifies, so
        // a forged block cannot fill the cache - the same order VerifyLogin
        // uses for the nonce.
        bool  NoteRelaySig ( const unsigned char *pSig, time_t tNow );
        bool  SeenRelaySig ( const unsigned char *pSig ) const;

        // The seal pair. Deliberately no tNow parameter, unlike the two above:
        // this cache is never trimmed by time, and taking a timestamp it does
        // not use would invite someone to add the trim that breaks it.
        //  llWhen is the body's signed sealed_at, which the ring needs so an
        //  evicted entry can raise the floor. It used to take no time at all,
        //  and the comment where it is defined explained at length why it
        //  could not - that reasoning was correct for a block with no stamp
        //  and is what the wire change removed.
        bool  NoteSealSig  ( const unsigned char *pSig, long long llWhen );
        bool  SeenSealSig  ( const unsigned char *pSig ) const;

        AuthPolicy ( const AuthPolicy & );
        AuthPolicy &operator= ( const AuthPolicy & );
    };

    // ---- Self-test -----------------------------------------------------
    // Round-trips both blocks through real files, and checks every refusal
    // path: unknown peer, wrong key, tampered signature, replay, skew, and a
    // login bound to a different destination.
    P2PCNG_EXT bool AuthSelfTest ( );

} // namespace p2pauth
