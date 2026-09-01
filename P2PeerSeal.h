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
//  P2PeerSeal - END-TO-END payload confidentiality between two hubs
//
//  DIFFERENT FROM THE CONNECTION CYPHER, AND DELIBERATELY SO
//
//  The session cypher (P2PeerioGcm, installed by the key agreement in
//  P2PeerCon) protects one HOP. An intermediate hub necessarily decrypts it:
//  routing decisions are made on the message's destination address, so a hub
//  that could not read the frame could not forward it. Hub B on the path
//  A -> B -> C therefore sees A's plaintext, and no amount of link crypto
//  changes that - it is what "routing" means.
//
//  This module seals the PAYLOAD to the destination itself. The addresses stay
//  in clear so every hub on the path can still route, and the body is opaque
//  to all of them. The two compose: link crypto hides the addressing from a
//  wire tapper, end-to-end hides the body from the hubs.
//
//  CONSTRUCTION - ECIES with a sender signature
//
//     ver(1) | sealed_at(8) | eph_pub(64) | nonce(12) | ciphertext(n) | tag(16) | sig(64)
//
//  VERSION 1, and the two leading fields are new as of 2026-08-18
//  (Stage 3 step 10). Before that the block began at the
//  ephemeral point and carried neither a version nor a time.
//
//  THE VERSION BYTE IS THE POINT OF THE CHANGE AS MUCH AS THE TIMESTAMP IS.
//  Without one, every later change to this format is a flag day, and the
//  project is pre-1.0 exactly once. It is first so a reader can dispatch on
//  it before parsing anything else.
//
//  THIS IS A HARD BREAK AND CANNOT BE ANYTHING ELSE. A v0 block began with
//  the ephemeral X coordinate, which is a uniformly distributed byte - so
//  "version 0" is not a value that can be recognised, and old and new bodies
//  are not distinguishable by inspection. There is no compatible coexistence
//  to design; a v0 body fails as SealErrVersion, or (once in 256, when its
//  first byte happens to be 1) as SealErrSignature. It never opens. That is
//  why the change had to land before 1.0 and why it lands all at once.
//
//  sealed_at is seconds since the Unix epoch, big-endian, and is bound into
//  BOTH the GCM additional data and the signed transcript - so it cannot be
//  edited by anyone, including the recipient, without failing the tag and the
//  signature. p2pseal does NOT decide what to do about it: Open reports it
//  and the policy layer (p2pauth::AuthPolicy) applies a window. Cryptography
//  here, judgement there, the same split as everywhere else in this pair.
//
//  The sender generates a throwaway ECDH pair per message and agrees with the
//  recipient's STATIC agreement key from the allow-list, so a secret can be
//  sent to a peer that has never connected and survives store-and-forward.
//  HKDF-SHA256 turns the raw secret into an AES-256-GCM key.
//
//  Encrypt-then-sign: the signature covers the ciphertext, so a verifier
//  rejects a forgery before doing any asymmetric work on attacker-chosen
//  plaintext. It is made with the sender's ECDSA IDENTITY key - the same key
//  the login proves - so confidentiality and authorship rest on the two
//  different key types they each need.
//
//  The source and destination addresses are bound in twice: as GCM additional
//  authenticated data, and inside the signed transcript. A sealed body lifted
//  off one message and pasted onto another therefore fails, rather than
//  decrypting happily under a forged sender.
//
//  WHAT FRESHNESS BOUGHT, AND WHAT IT COST
//
//  Until 2026-08-18 there was none: a sealed body was valid forever, so the
//  replay cache one layer up could only be bounded by COUNT - an entry dropped
//  for age would have handed back exactly the replay it was holding. The
//  honest statement then was "the most recent bodies cannot be replayed to a
//  given recipient and an older one can", which stops capture-and-redeliver
//  and does not stop a patient attacker.
//
//  With sealed_at in the transcript, AuthPolicy::SetSealReplayRefused(true) -
//  now the DEFAULT - closes it completely inside its window: an entry may be
//  dropped for age because freshness refuses that body anyway, and an entry
//  dropped for COUNT raises a floor that refuses everything older than it. See
//  SetSealWindow there for the window, and for the price.
//
//  THE PRICE IS STORE-AND-FORWARD, and it is real. A body sealed to a peer
//  that has never connected is one of the reasons this layer exists, and a
//  window puts a clock on how long it may sit. The default is deliberately
//  generous rather than tight for that reason, and it is a policy knob rather
//  than a wire constant so a deployment that needs longer can say so without
//  changing the format again.
//
//  WHAT THIS STILL DOES NOT DO
//
//  Ordering and liveness still belong to the layer above, which knows what a
//  duplicate means for its own messages. The
//  ephemeral half gives forward secrecy against later compromise of the
//  SENDER, but not of the recipient: whoever holds the recipient's static
//  agreement key can open every message ever sent to it.
//
#pragma once

#include "P2PIdentityStore.h"

#include <cstddef>

namespace p2pseal
{
    // ---- Wire version ---------------------------------------------------
    //  Bump this and the format changes; everything that parses a block reads
    //  it first. A block whose version is not understood is refused with
    //  SealErrVersion and no further parsing - which is the whole reason for
    //  having the byte, and the reason it costs one byte per message.
    const unsigned char kSealVersion  = 2;
    //  Version 1 is still OPENED, and that is the difference between this
    //  change and the v0 -> v1 one. A v1 block began with a version byte, so
    //  a v2 reader can dispatch on it and take the old path; a v0 block began
    //  with a uniformly distributed coordinate and could not be recognised at
    //  all. The byte introduced at v1 is what makes v2 a soft break, which is
    //  exactly the argument written down when it was added.
    //
    //  NOTHING WRITES V1 ANY MORE. Seal always emits v2, single-reader when
    //  no readers are named. The cost is 69 bytes a message (165 -> 234) and
    //  it is charged to every sealed body whether or not it names a reader,
    //  which is a deliberate refusal to carry two code paths through the most
    //  security-sensitive function in this module.
    const unsigned char kSealVersion1 = 1;

    // ---- Wire sizes (bytes) --------------------------------------------
    const size_t kSealVerLen   = 1;    // format version, first so it can be read alone
    const size_t kSealTimeLen  = 8;    // sealed_at, seconds since epoch, big-endian
    const size_t kSealEphLen   = 64;   // ephemeral public point X||Y
    const size_t kSealNonceLen = 12;   // GCM nonce
    const size_t kSealTagLen   = 16;   // GCM tag
    const size_t kSealSigLen   = 64;   // ECDSA r||s

    //  ---- v2: the recipient block ---------------------------------------
    //  WHY THERE IS ONE AT ALL. A hub on the path A -> B -> C routes on the
    //  DESTINATION address, so B must be able to read the addresses; v1 made
    //  the body opaque to B and that is the whole point of the module. But a
    //  deployment sometimes needs B to read the BODY too - content routing, a
    //  filter, a store-and-forward broker - and v1 offered exactly one answer
    //  to that: don't seal. Which is not an answer.
    //
    //  So the body is encrypted once under a random CONTENT KEY, and that key
    //  is wrapped once per reader. The destination is a reader; so is every
    //  intermediate hub the SENDER named. Adding a reader costs one slot,
    //  not another copy of the body.
    //
    //  THE SENDER NAMES THE READERS AND NOTHING ELSE CAN. Not the relay, not
    //  policy on the relay. The recipient set is bound into the body's
    //  additional data AND into the signed transcript, so a hub that strips a
    //  slot or splices its own in fails the tag and the signature. That is
    //  what lets the Readme go on saying "a relaying hub carries what it
    //  cannot read" - with the qualifier that the sender may decide otherwise,
    //  per message, and no one else may decide it for them.
    const size_t kSealCountLen = 1;    // reader count, 1..kSealMaxReaders
    const size_t kSealRTagLen  = 8;    // reader slot tag - see SealSlotTag
    const size_t kSealCekLen   = 32;   // content key, AES-256
    const size_t kSealWrapLen  = kSealNonceLen + kSealCekLen + kSealTagLen; // 60
    const size_t kSealSlotLen  = kSealRTagLen + kSealWrapLen;               // 68

    //  A ceiling rather than an unbounded list, because the count is read off
    //  the wire before anything is allocated on the strength of it. Eight is
    //  a destination plus seven hubs, which is deeper than any tree this
    //  library has been run in; the cost of raising it is one byte of format
    //  and a bigger buffer, not a redesign.
    const size_t kSealMaxReaders = 8;

    //  v1 overhead, kept because v1 bodies are still opened.
    const size_t kSealOverheadV1 = kSealVerLen + kSealTimeLen + kSealEphLen
                                 + kSealNonceLen + kSealTagLen + kSealSigLen; // 165

    inline size_t SealOverhead ( size_t nReaders )
    {
        return kSealVerLen + kSealTimeLen + kSealEphLen + kSealCountLen
             + kSealSlotLen * nReaders
             + kSealNonceLen + kSealTagLen + kSealSigLen;      // 234 at n=1
    }

    //  The single-reader overhead, which is what every caller that does not
    //  name readers is paying. KEPT UNDER ITS OLD NAME because a dozen call
    //  sites size buffers with it and the meaning has not changed - "what one
    //  sealed body costs" - only the number, 165 -> 234.
    const size_t kSealOverhead = kSealVerLen + kSealTimeLen + kSealEphLen
                               + kSealCountLen + kSealSlotLen
                               + kSealNonceLen + kSealTagLen + kSealSigLen; // 234

    inline size_t SealedSize ( size_t cbPlain, size_t nReaders = 1 )
    { return cbPlain + SealOverhead ( nReaders ); }

    //  AN UPPER BOUND, not the exact length, and the difference matters at
    //  every call site. The plaintext length depends on the reader count,
    //  which is inside the block - so a caller sizes its buffer from this and
    //  reads the TRUTH from Open's *pcbOut. Sizing a buffer from it is always
    //  safe; treating it as the answer is not.
    //
    //  IT BOUNDS ACROSS VERSIONS, WHICH IS WHY IT SUBTRACTS THE V1 OVERHEAD
    //  AND NOT SealOverhead(1). This was wrong for about an hour on
    //  2026-08-21 and seal_interop is what found it. The first version
    //  reasoned "more readers means more overhead means less plaintext, so
    //  n=1 bounds every other" - true WITHIN v2, and false across the version
    //  boundary. A v1 body carries 165 bytes of overhead against v2's 234, so
    //  its plaintext is 69 bytes LARGER than the v2 bound, and every caller
    //  that sized a buffer this way got SealErrArgs opening a stored v1
    //  vector. The smallest overhead of any version this build opens is the
    //  only safe subtrahend; a v2 body simply over-allocates by 69 bytes.
    inline size_t OpenedSize ( size_t cbSealed )
    {
        return cbSealed >= kSealOverheadV1 ? cbSealed - kSealOverheadV1 : 0;
    }

    //  Where a reader finds ITS slot, without doing any asymmetric work and
    //  without the block naming anybody. tag = SHA-256(label | eph | reader
    //  point) truncated - computable from the ephemeral point on the wire and
    //  the reader's OWN public half, so a lookup is a hash and a compare
    //  rather than a trial decryption per slot.
    //
    //  It is keyed on the ephemeral point, so the same reader gets a
    //  different tag in every message: the block does not leak WHO may read
    //  it, only how many. Truncation to 8 bytes is a collision risk of 2^-64
    //  between two readers of ONE message, and a collision costs a wasted
    //  unwrap that fails its GCM tag - not a disclosure.
    P2PCNG_EXT bool SealSlotTag ( const unsigned char *pEph,
                                  const unsigned char *pReaderPub,
                                  unsigned char *pTagOut /*kSealRTagLen*/ );

    // ---- Outcomes ------------------------------------------------------
    // Separated because they want different responses: a missing directory
    // entry is provisioning, a bad signature is an attack or a stale key, and
    // a tag failure is tampering.
    enum SealResult
    {
        SealOk = 0,
        SealErrArgs,
        SealErrNoIdentity,     // no sender identity key to sign with
        SealErrNoAgreement,    // no recipient agreement key / no own private half
        SealErrFormat,         // too short to be a sealed body
        SealErrSignature,      // sender signature did not verify
        SealErrTag,            // GCM tag did not verify
        SealErrRevoked,        // the key this would have used is revoked, or a
                               //   revocation list was configured and could not
                               //   be read. Distinct from SealErrNoAgreement:
                               //   "withdrawn" is an operator action and "never
                               //   published" is a provisioning gap, and they
                               //   want different responses
        SealErrInternal,
        // A body this recipient has already opened, refused because
        // AuthPolicy::SetSealReplayRefused(true) is set. Added at the END of
        // this enum on purpose: every value above it keeps the number it has
        // always had, so a caller built against the older header still reads
        // the same outcomes. A replayed body is decrypted before it is
        // recognised - the cache is keyed on the signature and consulted only
        // once the body has opened - so the plaintext is wiped and the output
        // length zeroed before this is returned.
        SealErrReplay,
        // The version byte is not one this build understands - which is what a
        // pre-2026-08-18 body looks like from here, since those began at the
        // ephemeral point and carried no version at all. Appended at the END
        // for the same reason SealErrReplay was: every value above it keeps
        // the number it has always had.
        SealErrVersion,
        // Sealed outside the recipient's freshness window. Distinct from
        // SealErrReplay on purpose - "too old to accept" and "I have seen this
        // one before" are different facts about a body, and an operator
        // chasing the first is usually looking at a clock or at
        // AuthPolicy::SetSealWindow, not at an attacker.
        SealErrStale,
        //  v2, and appended for the reason every value above was: a caller
        //  built against the older header keeps reading the same outcomes.
        //
        //  More readers named than kSealMaxReaders, or none at all. Distinct
        //  from SealErrArgs because it is the one argument error an operator
        //  can cause from a configuration file rather than from code.
        SealErrReaders,
        //  This peer's agreement key matches no slot in the block. NOT a
        //  failure of the cryptography and deliberately not folded into
        //  SealErrNoAgreement: the body is intact and somebody can open it,
        //  just not us. A hub relaying a body it was not named a reader of
        //  gets this and must carry it on unopened rather than treat it as
        //  damage.
        SealErrNotAReader
    };

    P2PCNG_EXT const char *SealResultText ( SealResult eResult );

    // ---- Seal ----------------------------------------------------------
    //  oSender     this peer's ECDSA identity, able to sign
    //  pRecipAgree the destination's static agreement point, from the
    //              allow-list (kEcdhPubLen bytes)
    //  pSrc/pDst   the addresses the carrying message will declare; bound in
    //              so the body cannot be moved to another message
    //  pOut        SealedSize(cbPlain) bytes
    //  llWhen      seconds since the epoch to stamp the body with. 0 - the
    //              default, and what every caller outside a test should pass -
    //              means "now". It is a parameter at all because a freshness
    //              window is untestable without one: proving a body is refused
    //              for being old otherwise means a test that waits.
    P2PCNG_EXT SealResult Seal ( p2pcng::EcdsaP256 &oSender,
                      const unsigned char *pRecipAgree,
                      const wchar_t *pSrc, const wchar_t *pDst,
                      const void *pPlain, size_t cbPlain,
                      unsigned char *pOut, size_t cbOut, size_t *pcbOut,
                      long long llWhen = 0 );

    // ---- Seal to SEVERAL readers ---------------------------------------
    //  The v2 entry point, and the one above is now a thin call into this
    //  with nReaders == 1.
    //
    //  pReaders    nReaders agreement points, kEcdhPubLen each, laid end to
    //              end. Reader 0 is by convention the DESTINATION and the
    //              rest are the intermediate hubs the sender is choosing to
    //              let read; nothing here enforces that convention, because
    //              this layer does not know the topology and a layer that
    //              guesses at one would be wrong in the deployment that most
    //              needed it. p2pauth::AuthPolicy::Seal applies the meaning.
    //
    //  DUPLICATES ARE REFUSED rather than de-duplicated. A repeated reader is
    //  a provisioning mistake - the same hub named twice, or a hub that IS
    //  the destination named again - and silently collapsing it would make
    //  the wire disagree with what the caller asked for. It also costs a slot
    //  and an ECDH for nothing.
    //
    //  ORDER IS PRESERVED AND BOUND IN. The slots go on the wire in the order
    //  given and the whole recipient block is covered by the body's AAD and
    //  the signature, so nothing on the path can reorder, add or drop one.
    P2PCNG_EXT SealResult SealTo ( p2pcng::EcdsaP256 &oSender,
                      const unsigned char *pReaders, size_t nReaders,
                      const wchar_t *pSrc, const wchar_t *pDst,
                      const void *pPlain, size_t cbPlain,
                      unsigned char *pOut, size_t cbOut, size_t *pcbOut,
                      long long llWhen = 0 );

    // How many readers a sealed block names, without opening it and without
    // any key at all. 0 if the buffer is not a block this build understands.
    // For diagnostics and for buffer sizing on a relay - never a trust
    // decision, since the count is only authenticated once something opens.
    P2PCNG_EXT size_t SealReaderCount ( const void *pv, size_t cb );

    // ---- Open ----------------------------------------------------------
    //  oRecipAgree this peer's STATIC agreement key, private half loaded
    //  pSenderId   the sender's ECDSA identity point, from the allow-list
    //  pOut        OpenedSize(cbIn) bytes
    //  pllWhenOut  (optional) receives the sealed_at the body carries, once it
    //              has VERIFIED - so it is a signed fact, not a claim. Written
    //              on SealOk only. Open applies no window of its own: what
    //              counts as too old is policy, and policy lives in
    //              p2pauth::AuthPolicy.
    P2PCNG_EXT SealResult Open ( p2pcng::EcdhP256 &oRecipAgree,
                      const unsigned char *pSenderId,
                      const wchar_t *pSrc, const wchar_t *pDst,
                      const unsigned char *pIn, size_t cbIn,
                      void *pOut, size_t cbOut, size_t *pcbOut,
                      long long *pllWhenOut = 0 );

    // Cheap shape test for diagnostics only - never a trust decision.
    P2PCNG_EXT bool LooksSealed ( const void *pv, size_t cb );

    // ---- Self-test -----------------------------------------------------
    // Round trip plus every refusal: wrong recipient, wrong sender, moved to
    // another address pair, and a bit flipped in each region.
    P2PCNG_EXT bool SealSelfTest ( );
}
