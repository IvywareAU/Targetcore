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
//  P2PIdentityStore.h - at-rest storage for the TargetCore peer identity.
//
//  EcdsaP256 (P2PCngCrypto.h) can generate, sign and verify, but it holds a key
//  only in memory: the key a peer authenticates with must survive a restart, or
//  its identity changes on every launch and no allow-list can name it. This is
//  that layer, and nothing more - it stores keys, it does not use them. The
//  login protocol that consumes them is separate work.
//
//  Four kinds of file, and the distinction is the whole design:
//
//    identity file   the peer's own PRIVATE key. Secret. Protected at rest and
//                    written with a restrictive ACL / mode 0600.
//    public key file the peer's own PUBLIC point, hex. Publishable anywhere -
//                    this is what an operator sends to whoever must trust them.
//    allow-list      other peers' public points, one identity per line. Public
//                    data; its integrity matters, its confidentiality does not.
//    revocation list public points that must no longer be honoured, whatever
//                    the allow-list still says. Same integrity story, and it
//                    OVERRIDES the allow-list rather than being consulted
//                    alongside it - see the revocation section below.
//
//  TWO KEYS PER PEER, AND THEY ARE NOT INTERCHANGEABLE
//  ---------------------------------------------------
//  A peer holds an ECDSA IDENTITY key, which proves who it is at login, and an
//  ECDH AGREEMENT key, which lets anyone seal a body to it (P2PeerSeal.h). Both
//  are P-256 and both persist as the same 96-byte X||Y||d blob, which is exactly
//  why they are kept apart deliberately rather than by luck:
//
//    * different container magic - an agreement file cannot load as an identity
//      or the reverse, so a swapped or renamed file fails loudly instead of
//      quietly making a peer sign with the key it agrees with;
//    * different DPAPI entropy - the protected payloads are not interchangeable
//      either, so lifting the blob out of one container and dropping it into the
//      other does not work.
//
//  Using one key for two algorithms is a classic way to turn a signing oracle
//  into a decryption oracle. The cost of keeping them separate is one more file.
//
//  Protection at rest (identity file only)
//  ---------------------------------------
//  Windows: DPAPI (CryptProtectData), MACHINE scope by default, with a fixed
//  application entropy value. Understand what that boundary is:
//
//    * Machine scope means ANY code running on the same machine can unprotect
//      the blob. It defends against the file being copied off the box - a stolen
//      disk, a backup, a misconfigured share - and against nothing local.
//    * The entropy is compiled into this binary. It binds the blob to this
//      application; it is NOT a secret, because anyone holding the binary holds
//      it too.
//    * IdProtect_DpapiUser is strictly stronger where it is usable: the blob is
//      then bound to one user profile as well as the machine. Use it when the
//      service runs as a fixed account and never as SYSTEM or as a machine
//      account whose profile is not loaded. Machine scope is the default only
//      because it is the one that always works, including for a service started
//      before any user logs on.
//
//  POSIX: no OS-level blob protection is used. The file is created 0600 and
//  LoadIdentity REFUSES to read an identity file that is group- or
//  world-accessible (IdErrPerms), the way ssh refuses a loose private key. A
//  tolerated bad mode is how key files leak.
//
//  Container format (identity file), all integers little-endian:
//
//     off  len  field
//       0    8  magic     "P2PIDKY\x1A" (identity) / "P2PAGKY\x1A" (agreement)
//       8    2  version   currently 1
//      10    2  protection  0 none | 1 DPAPI machine | 2 DPAPI user
//      12    4  cbPayload
//      16   32  digest    SHA-256 over bytes [0,16) of this header || payload
//      48    N  payload   the protected (or, for method 0, raw) 96-byte
//                         EcdsaP256 / EcdhP256 private blob X||Y||d
//
//  The digest covers the payload AS STORED, never the plaintext key - hashing
//  the private scalar would hand an offline attacker a way to confirm a guess.
//  It is a corruption check, not a MAC: whoever can rewrite the file can rewrite
//  the digest. Authenticity of the identity file comes from the filesystem
//  permissions above, and, on Windows, from DPAPI's own integrity check.
//
#pragma once

#include "P2PCngCrypto.h"

namespace p2pcng
{
    // ---- Result codes --------------------------------------------------
    // Storage fails in many more distinguishable ways than a primitive does -
    // "no such file" and "wrong machine" and "corrupt" want different operator
    // responses - so these functions return a code rather than a bool.
    enum IdResult
    {
        IdOk = 0,
        IdErrArgs,          // null / empty / oversized argument
        IdErrIo,            // open, read, write or rename failed
        IdErrNotFound,      // the file does not exist
        IdErrExists,        // exclusive create, and the file is already there
        IdErrFormat,        // bad magic, truncated, or an unparsable text line
        IdErrVersion,       // container version this build does not know
        IdErrIntegrity,     // digest mismatch - the file was corrupted
        IdErrProtect,       // CryptProtectData failed
        IdErrUnprotect,     // CryptUnprotectData failed (wrong machine or user,
                            //   wrong entropy, or the blob was tampered with)
        IdErrKey,           // the key material is not a valid P-256 identity
        IdErrPerms,         // POSIX: identity file is group/world accessible
        IdErrUnsupported,   // e.g. a DPAPI-protected file read on POSIX
        IdErrRevoked        // the key is on the revocation list
    };

    // Stable one-line English text for a code. Never null.
    P2PCNG_EXT const char *IdResultText ( IdResult eResult );

    // ---- Protection method ---------------------------------------------
    enum IdProtection
    {
        IdProtect_Default      = -1,  // Windows -> DPAPI machine; POSIX -> none+0600
        IdProtect_None         = 0,   // raw blob on disk. Tests, and provisioning
                                      //   where the transport is already protected.
                                      //   Never a good resting state.
        IdProtect_DpapiMachine = 1,
        IdProtect_DpapiUser    = 2
    };

    // ---- Sizes ---------------------------------------------------------
    const size_t kIdHeaderLen      = 48;   // container header, bytes
    const size_t kIdPubHexChars    = 128;  // kEcdsaPubLen * 2, excluding NUL
    const size_t kIdFingerprintLen = 40;   // buffer size incl. NUL: 8 groups of 4
    const size_t kIdMaxIdentity    = 255;  // longest allow-list identity string

    // All paths are UTF-8 on both platforms; the Windows implementations widen
    // internally, so a non-ASCII path works without the caller caring.

    // ---- The peer's own identity (private) -----------------------------

    // Write oKey's private half to pszPathUtf8, protected as eProtect says.
    // The write is atomic (temp file + rename) so a crash cannot leave a
    // half-written identity. With bOverwrite false the create is exclusive and
    // an existing file yields IdErrExists - no TOCTOU window.
    // Fails IdErrKey if oKey holds only a public point.
    P2PCNG_EXT IdResult SaveIdentity ( const char *pszPathUtf8, EcdsaP256 &oKey,
                                       IdProtection eProtect  = IdProtect_Default,
                                       bool         bOverwrite = true );

    // Load an identity file into oKey, which can sign afterwards. oKey is left
    // untouched unless the whole load succeeds.
    P2PCNG_EXT IdResult LoadIdentity ( const char *pszPathUtf8, EcdsaP256 &oKey );

    // First-run convenience: load the identity if it is there, otherwise
    // generate one and save it. *pbCreated (optional) reports which happened.
    // Racing processes are safe - the loser of an exclusive create loads the
    // winner's key rather than overwriting it.
    P2PCNG_EXT IdResult LoadOrCreateIdentity ( const char *pszPathUtf8, EcdsaP256 &oKey,
                                              bool        *pbCreated = nullptr,
                                              IdProtection eProtect  = IdProtect_Default );

    // ---- The peer's own public key (publishable) -----------------------

    // Write the public point as a hex line with a fingerprint comment. This is
    // the file an operator hands to whoever must trust this peer.
    P2PCNG_EXT IdResult SavePublicKey ( const char *pszPathUtf8, EcdsaP256 &oKey );

    // Load a public point into oKey. Verify-only afterwards: Sign() will fail.
    // Accepts a bare hex line or an "<identity> <hex>" allow-list line.
    P2PCNG_EXT IdResult LoadPublicKey ( const char *pszPathUtf8, EcdsaP256 &oKey );

    // ---- The peer's own agreement key (private) ------------------------
    //
    //  The static ECDH key others seal to. Same container, same protection, same
    //  atomicity as the identity above - only the magic and the DPAPI entropy
    //  differ, so the two files can never be confused for one another.
    //
    //  Why static, when the connection handshake agrees an ephemeral pair per
    //  connection: a sealed body must be openable by a destination that was
    //  offline when it was sent, and must survive being carried by hubs that
    //  hold no keys at all. Nothing ephemeral can do that. The price is that
    //  this key has no forward secrecy - see P2PeerSeal.h.

    P2PCNG_EXT IdResult SaveAgreement ( const char *pszPathUtf8, EcdhP256 &oKey,
                                        IdProtection eProtect  = IdProtect_Default,
                                        bool         bOverwrite = true );

    P2PCNG_EXT IdResult LoadAgreement ( const char *pszPathUtf8, EcdhP256 &oKey );

    P2PCNG_EXT IdResult LoadOrCreateAgreement ( const char *pszPathUtf8, EcdhP256 &oKey,
                                                bool        *pbCreated = nullptr,
                                                IdProtection eProtect  = IdProtect_Default );

    // The publishable half, same shape of file as SavePublicKey.
    P2PCNG_EXT IdResult SaveAgreementPublicKey ( const char *pszPathUtf8, EcdhP256 &oKey );
    P2PCNG_EXT IdResult LoadAgreementPublicKey ( const char *pszPathUtf8, EcdhP256 &oKey );

    // ---- Peer allow-list (public) --------------------------------------
    //
    //  Text, one peer per line:
    //
    //      <identity><ws><128 hex: identity point>[<ws><128 hex: agreement point>]
    //
    //  '#' comments and blank lines are ignored. Identity comparison is exact -
    //  no case folding, no normalisation, because a trust decision should not
    //  depend on locale rules.
    //
    //  The third column is OPTIONAL, and that is a compatibility promise, not
    //  laziness: every allow-list written before end-to-end sealing existed
    //  keeps working unchanged, and a peer that has no agreement key published
    //  can still log in. What it cannot do is receive a sealed body - the sender
    //  has nothing to seal to, and gets SealErrNoAgreement rather than a
    //  silently unprotected message.
    //
    //  A line that does not parse fails the whole load (IdErrFormat) rather than
    //  being skipped: a half-read allow-list silently denies peers that should
    //  be allowed, or - worse, if the file is ever inverted into a deny-list -
    //  allows peers that should not be.

    // Called once per entry. pPub points at kEcdsaPubLen bytes; pAgree at
    // kEcdhPubLen bytes, or is NULL when the line carries no third column.
    // Both are valid only for the duration of the call.
    typedef void ( *IdAllowFn ) ( void *pCtx, const char *pszIdentity,
                                  const unsigned char *pPub,
                                  const unsigned char *pAgree );

    P2PCNG_EXT IdResult LoadAllowList ( const char *pszPathUtf8,
                                        IdAllowFn pfnEntry, void *pCtx );

    // Append one entry, creating the file if needed. Rejects an identity that is
    // empty, over kIdMaxIdentity, or contains whitespace or '#'. Duplicate
    // identities are NOT rejected here - LoadAllowList / FindAllowed take the
    // first match, so a duplicate line is dead weight rather than a hazard.
    // pAgree may be null, which writes the two-column form.
    P2PCNG_EXT IdResult AppendAllowList ( const char *pszPathUtf8,
                                          const char *pszIdentity,
                                          const unsigned char *pPub,
                                          const unsigned char *pAgree = nullptr );

    // Look one identity up. IdOk and pPubOut filled on a hit; IdErrNotFound if
    // the file exists but holds no such identity. pAgreeOut, when given, is
    // filled only if the entry has a third column - *pbHasAgree says which, and
    // a caller that ignores it and reads the buffer anyway gets zeros, not a
    // stale key from a previous lookup.
    P2PCNG_EXT IdResult FindAllowed ( const char *pszPathUtf8, const char *pszIdentity,
                                      unsigned char *pPubOut /*kEcdsaPubLen*/,
                                      unsigned char *pAgreeOut  = nullptr /*kEcdhPubLen*/,
                                      bool          *pbHasAgree = nullptr );

    // ---- Revocation list (public) --------------------------------------
    //
    //  Text, one revoked key per line:
    //
    //      <128 hex: the revoked public point>[<ws><epoch seconds>]   # why
    //
    //  '#' comments and blank lines are ignored, exactly as in the allow-list.
    //
    //  KEYED ON THE FULL POINT, NOT THE FINGERPRINT
    //  --------------------------------------------
    //  The obvious column here is the human-friendly fingerprint below, and it
    //  is the wrong one. Fingerprint() is 16 bytes of a SHA-256 and its contract
    //  says, in as many words, never as an identifier the code trusts. Deciding
    //  whether to refuse a peer IS the code trusting an identifier, so this file
    //  carries the whole 64-byte point - the same 128 hex characters the
    //  allow-list already uses, so an operator revokes a key by copying the
    //  column they already have. AppendRevocationList writes the fingerprint
    //  into the trailing comment, which is where a value meant for human eyes
    //  belongs.
    //
    //  ONE LIST FOR BOTH KEY KINDS
    //  ---------------------------
    //  An ECDSA identity point and an ECDH agreement point are both 64 raw
    //  bytes, so one file holds both and a lookup never has to know which kind
    //  it was handed. That is not an economy, it is the safer shape: with two
    //  files an operator can revoke a compromised peer on the list that governs
    //  login and forget the one that governs sealing, and the key keeps working
    //  for exactly the half nobody checked.
    //
    //  REVOCATION IS ABSOLUTE, AND THE TIMESTAMP IS NOT A SCOPE
    //  --------------------------------------------------------
    //  A listed point is refused. Full stop - there is no "revoked as of" window
    //  and no grace period, because a key is revoked precisely when its holder
    //  can no longer be trusted with anything it already had. The optional epoch
    //  column records WHEN for the operator and for logs; it is parsed strictly
    //  so a typo is caught, and it is never compared against the clock. Anything
    //  that reads as a scope would be a way to un-revoke a key by moving time,
    //  and a peer with no clock at all (the window-0 case in P2PAuthLogin.h) has
    //  no way to evaluate one.
    //
    //  There is no removal API. Un-revoking is deleting a line by hand, which is
    //  deliberate friction: it is the one edit to this file that can only ever
    //  widen trust.

    const size_t kIdRevokePointLen = 64;   // kEcdsaPubLen == kEcdhPubLen

    // Called once per entry. pPoint is kIdRevokePointLen bytes, valid only for
    // the duration of the call. llRevokedAt is the epoch column, or 0 when the
    // line carries none - 0 means "not recorded", never "revoked at the epoch".
    typedef void ( *IdRevokeFn ) ( void *pCtx, const unsigned char *pPoint,
                                   long long llRevokedAt );

    P2PCNG_EXT IdResult LoadRevocationList ( const char *pszPathUtf8,
                                             IdRevokeFn pfnEntry, void *pCtx );

    // Append one revoked point, creating the file if needed. llRevokedAt of 0
    // means "now". pszReason is free text written into the trailing comment; it
    // may contain anything except a newline, and nothing reads it back.
    // Appending a point that is already listed is allowed and harmless - the
    // answer to "is this revoked" does not get more true.
    P2PCNG_EXT IdResult AppendRevocationList ( const char *pszPathUtf8,
                                               const unsigned char *pPoint,
                                               long long   llRevokedAt = 0,
                                               const char *pszReason   = nullptr );

    // One-shot lookup. IdOk with *pbRevoked set either way; IdErrNotFound if the
    // file itself is missing, which the CALLER must treat as fail-closed rather
    // than as "nothing is revoked" - see AuthPolicy::SetRevocationList, which
    // does exactly that.
    P2PCNG_EXT IdResult IsRevoked ( const char *pszPathUtf8,
                                    const unsigned char *pPoint,
                                    bool *pbRevoked );

    // ---- Fingerprint ---------------------------------------------------
    // First 16 bytes of SHA-256(public point) as "ABCD-EF01-...", 8 groups of
    // 4 uppercase hex. For humans comparing a key over a phone call, and for
    // logs - never as an identifier the code trusts.
    P2PCNG_EXT bool Fingerprint ( const unsigned char *pPub /*kEcdsaPubLen*/,
                                  char *pszOut /*kIdFingerprintLen*/ );

    // ---- Self-test -----------------------------------------------------
    // Round-trips every path above through real files in the temp directory,
    // including the failure cases (corruption, truncation, wrong protection)
    // and - on Windows - a check that the stored bytes are genuinely NOT the
    // plaintext key. Cleans up after itself. Returns true iff all pass.
    P2PCNG_EXT bool StoreSelfTest ( );

} // namespace p2pcng
