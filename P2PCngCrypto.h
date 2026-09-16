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
//  P2PCngCrypto.h - CNG (Windows BCrypt) cryptographic primitives for the
//  Targetcore secure channel.
//
//  Replaces the legacy hand-rolled crypto (custom Rijndael + Buint Diffie-
//  Hellman), which was insecure (rand()-seeded keys, 256-bit unvalidated DH,
//  ECB, static IV, no MAC) AND dormant (never wired into the live path).
//
//  This module provides only vetted OS primitives:
//    - CngRandom      : CSPRNG (BCryptGenRandom)
//    - Sha256         : FIPS 180-4 SHA-256 digest
//    - AesGcm         : AES-256-GCM authenticated encryption (AEAD)
//    - EcdhP256       : ephemeral ECDH on NIST P-256 key agreement
//    - EcdsaP256      : ECDSA on NIST P-256 - peer IDENTITY (sign/verify)
//    - HkdfSha256     : RFC 5869 key derivation
//    - HmacSha256     : RFC 2104 HMAC (transcript authentication / PSK)
//    - ConstTimeEqual : constant-time buffer comparison
//
//  EcdhP256 and EcdsaP256 answer different questions and are not
//  interchangeable. ECDH establishes a shared secret with whoever is at the
//  other end - it says nothing about who that is. ECDSA proves that the peer
//  holds the private half of a public key you already trust. Peer identity
//  needs the second; confidentiality needs the first.
//
//  Handles are kept as void* so this header pulls in no BCrypt dependency;
//  <bcrypt.h> is confined to the .cpp.
//
#pragma once

#include <cstddef>

// Export linkage for the few symbols a test or a consumer outside this DLL
// needs. Declared locally rather than by including Targetcore.h so this header
// keeps its "no dependencies" property - Targetcore.h's macro expands to
// __declspec unconditionally, which does not compile under GCC for the Linux
// backend that shares this header.
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32)
#  if defined(Targetcore_STATIC)
//  A static library exports nothing and imports nothing, so the macro is empty --
//  the same arm Targetcore.h and Targetcore_c.h already carry for Targetcore_STATIC.
//  It was written here as `_WIN32 && !Targetcore_STATIC`, which does not select an
//  empty macro for a Windows static build: it falls through to the GCC branch below
//  and hands MSVC __attribute__((visibility("default"))), which is a syntax error.
//  That arm had never been compiled. It is not only the CMake msgcore_static target
//  that hits it -- the vcxproj's own DebugLib/ReleaseLib configurations define
//  Targetcore_STATIC, so 4 of the 8 configurations the .sln declares could not build
//  this header either (verified 2026-08-22 by compiling DebugLib|x64 directly).
#    define P2PCNG_EXT
#  elif defined(Targetcore_EXPORTS)
#    define P2PCNG_EXT __declspec(dllexport)
#  else
#    define P2PCNG_EXT __declspec(dllimport)
#  endif
#else
//  Not empty: the shared objects are built -fvisibility=hidden (top-level
//  CMakeLists), so an unmarked symbol is resolvable inside libtargetcore.so and
//  invisible to everything else. That is the right default for the library's
//  internals and wrong for this header, whose whole content is the public
//  surface the test harnesses and applications link against. The attribute is
//  spelled out rather than pulled from Platform/p2pexport.h to keep this
//  header's "no dependencies" property intact.
#  define P2PCNG_EXT __attribute__((visibility("default")))
#endif

namespace p2pcng
{
    // ---- Sizes (bytes) -------------------------------------------------
    const size_t kAesKeyLen   = 32;    // AES-256 key
    const size_t kGcmNonceLen = 12;    // 96-bit GCM nonce (per message)
    const size_t kGcmTagLen   = 16;    // 128-bit GCM tag
    const size_t kEcdhPubLen  = 64;    // raw P-256 public point: X(32) || Y(32)
    const size_t kEcdhSecLen  = 32;    // raw ECDH shared secret (X coordinate)
    // Private agreement blob: X(32) || Y(32) || d(32). Same shape and the same
    // reason as kEcdsaPrivLen below - CNG imports an EC private key only as a
    // complete point-plus-scalar blob. A STATIC agreement key needs this;
    // ephemeral use (the per-connection handshake) never persists anything.
    const size_t kEcdhPrivLen = 96;
    const size_t kSha256Len   = 32;    // SHA-256 / HMAC-SHA256 output

    // ECDSA P-256 identity keys.
    const size_t kEcdsaPubLen  = 64;   // raw public point: X(32) || Y(32)
    const size_t kEcdsaSigLen  = 64;   // raw signature: r(32) || s(32), big-endian
    // Private key blob: X(32) || Y(32) || d(32). CNG imports a private EC key
    // only as a complete point-plus-scalar blob, so the public half is carried
    // alongside rather than recomputed. This is the on-disk identity format.
    const size_t kEcdsaPrivLen = 96;

    // ---- CSPRNG --------------------------------------------------------
    // Fills pBuffer with cbBuffer cryptographically-strong random bytes.
    bool CngRandom ( void *pBuffer, unsigned long cbBuffer );

    // ---- SHA-256 -------------------------------------------------------
    bool Sha256 ( const unsigned char *pData, size_t cbData,
                  unsigned char pHashOut[/*kSha256Len*/] );

    // ---- AES-256-GCM (AEAD) -------------------------------------------
    // Sealed layout on the wire: [ nonce(12) | ciphertext(cbPlain) | tag(16) ]
    class AesGcm
    {
      public:
        AesGcm ( );
       ~AesGcm ( );

        // Install a 256-bit key (cbKey must equal kAesKeyLen).
        bool SetKey ( const unsigned char *pKey, size_t cbKey );

        // Number of output bytes Seal() produces for cbPlain input bytes.
        static size_t SealedSize ( size_t cbPlain )
        { return cbPlain + kGcmNonceLen + kGcmTagLen; }

        // Plaintext bytes recoverable from a cbSealed-byte sealed buffer.
        static size_t OpenedSize ( size_t cbSealed )
        { return cbSealed >= (kGcmNonceLen + kGcmTagLen)
               ? cbSealed - (kGcmNonceLen + kGcmTagLen) : 0; }

        // Encrypt-then-authenticate. A fresh random nonce is generated per call.
        // pAad/cbAad is optional additional authenticated data (may be null/0).
        // pOut must have room for SealedSize(cbPlain). *pcbOut receives the
        // sealed length. Returns false on any error.
        bool Seal ( const unsigned char *pPlain, size_t cbPlain,
                    const unsigned char *pAad,   size_t cbAad,
                    unsigned char *pOut, size_t cbOutBuf, size_t *pcbOut );

        // Verify-then-decrypt. Returns false if the tag does not verify (the
        // output is not used in that case). pOut must have room for
        // OpenedSize(cbIn). *pcbOut receives the plaintext length.
        bool Open ( const unsigned char *pIn, size_t cbIn,
                    const unsigned char *pAad, size_t cbAad,
                    unsigned char *pOut, size_t cbOutBuf, size_t *pcbOut );

      private:
        void          *m_hAlg;         // BCRYPT_ALG_HANDLE
        void          *m_hKey;         // BCRYPT_KEY_HANDLE
        unsigned char *m_pKeyObj;      // key object backing store
        size_t         m_cbKeyObj;

        AesGcm ( const AesGcm & );             // no copy
        AesGcm &operator= ( const AesGcm & );
    };

    // ---- ECDH P-256 key agreement -------------------------------------
    //
    //  Two lifetimes, one class. The connection handshake uses it EPHEMERALLY -
    //  Generate() per connection, never persisted. End-to-end sealing
    //  (P2PeerSeal.h) also needs a STATIC agreement key per peer: published in
    //  the allow-list so a body can be sealed to a destination that has never
    //  connected, and therefore provisioned, exported and imported like an
    //  identity. That second use is why this class is exported and why it grew
    //  ImportPrivate/ExportPrivate.
    //
    class EcdhP256
    {
      public:
        P2PCNG_EXT  EcdhP256 ( );
        P2PCNG_EXT ~EcdhP256 ( );

        // Generate a fresh key pair.
        P2PCNG_EXT bool Generate ( );

        // Export this party's public point as raw X||Y (kEcdhPubLen bytes).
        P2PCNG_EXT bool ExportPublic ( unsigned char pOut[/*kEcdhPubLen*/] );

        // Persist / restore a STATIC agreement key as X||Y||d. Needed because a
        // peer's agreement key must outlive the process to be publishable in an
        // allow-list - unlike the ephemeral pair the connection handshake uses,
        // which exists only for one connection and is never written anywhere.
        P2PCNG_EXT bool ExportPrivate ( unsigned char pOut[/*kEcdhPrivLen*/] );
        P2PCNG_EXT bool ImportPrivate ( const unsigned char pIn[/*kEcdhPrivLen*/] );

        // Load a peer's public point for agreement. Verify the pairing only -
        // DeriveRawSecret() needs OUR private half, so a public-only instance
        // cannot agree; this exists so a point can be validated on the curve
        // before it is trusted as a directory entry.
        P2PCNG_EXT bool ImportPublic ( const unsigned char pIn[/*kEcdhPubLen*/] );

        // Compute the raw ECDH shared secret (kEcdhSecLen bytes) from the
        // peer's raw X||Y public point. Do NOT use the raw secret as a key -
        // run it through HkdfSha256 first.
        P2PCNG_EXT bool DeriveRawSecret ( const unsigned char pPeerPub[/*kEcdhPubLen*/],
                                          unsigned char pSecretOut[/*kEcdhSecLen*/] );

      private:
        void *m_hAlg;                  // BCRYPT_ALG_HANDLE
        void *m_hKey;                  // BCRYPT_KEY_HANDLE (our pair)
        //  Does m_hKey carry a private half? Tracked rather than inferred: a
        //  public-only handle passed to BCryptSecretAgreement as the private
        //  party does not fail, it CRASHES the process, and "the caller will
        //  not do that" stopped being true the moment ImportPublic existed for
        //  validating directory entries.
        bool  m_bPrivate;

        EcdhP256 ( const EcdhP256 & );
        EcdhP256 &operator= ( const EcdhP256 & );
    };

    // ---- ECDSA P-256 identity (sign / verify) -------------------------
    //
    //  A peer's LONG-LIVED identity key, as distinct from EcdhP256's
    //  per-session ephemeral. The private half never leaves the machine that
    //  generated it; a verifier holds only the public point, so a compromised
    //  verifier cannot impersonate anyone. That asymmetry is the entire point:
    //  it is what a shared secret cannot give you.
    //
    //  Typical use:
    //      own identity   Generate() once -> ExportPrivate() -> protect at rest
    //                     ImportPrivate() at startup -> Sign()
    //      a peer's key   ImportPublic() from the allow-list -> Verify()
    //
    //  This class is EXPORTED from the DLL, as EcdhP256 now is for the same
    //  reason. The rest are internal by design (see crypto_kat.cpp) because
    //  only the secure channel inside the library uses them. An identity key is
    //  different: P2PIdentityStore's exported functions take one by reference,
    //  so an exported storage API that referenced a non-exported type would be
    //  unusable - and the tooling that has to exist around an identity (create
    //  a key, print its public half for an allow-list) lives outside the DLL by
    //  nature. Protecting the private half is the store's job, not the linker's.
    //
    class EcdsaP256
    {
      public:
        P2PCNG_EXT  EcdsaP256 ( );
        P2PCNG_EXT ~EcdsaP256 ( );

        // Generate a fresh identity key pair.
        P2PCNG_EXT bool Generate ( );

        // Export the public point as raw X||Y (kEcdsaPubLen bytes). Safe to
        // publish - this is what goes in a peer allow-list.
        P2PCNG_EXT bool ExportPublic ( unsigned char pOut[/*kEcdsaPubLen*/] );

        // Export the private key blob (kEcdsaPrivLen bytes). SECRET: the
        // caller must protect it at rest - see P2PIdentityStore.h, which does
        // exactly that - and zero the buffer after use. Fails on a verify-only
        // key loaded via ImportPublic().
        P2PCNG_EXT bool ExportPrivate ( unsigned char pOut[/*kEcdsaPrivLen*/] );

        // Load a previously exported private key blob. Signing and verifying
        // are both available afterwards.
        P2PCNG_EXT bool ImportPrivate ( const unsigned char pIn[/*kEcdsaPrivLen*/] );

        // Load a peer's public point. Verify-only: Sign() will fail.
        P2PCNG_EXT bool ImportPublic ( const unsigned char pIn[/*kEcdsaPubLen*/] );

        // Sign cbData bytes. The message is SHA-256'd internally; pass the
        // full transcript, not a digest. Signatures are randomised, so two
        // signatures over the same input differ - do not compare them.
        P2PCNG_EXT bool Sign ( const unsigned char *pData, size_t cbData,
                               unsigned char pSigOut[/*kEcdsaSigLen*/] );

        // Verify a signature over cbData bytes. Returns false on a bad
        // signature, a wrong key, or any error - the caller must treat false
        // as "not authenticated" and never as "try again".
        P2PCNG_EXT bool Verify ( const unsigned char *pData, size_t cbData,
                                 const unsigned char pSig[/*kEcdsaSigLen*/] );

      private:
        void *m_hAlg;                  // BCRYPT_ALG_HANDLE
        void *m_hKey;                  // BCRYPT_KEY_HANDLE

        bool  EnsureAlg ( );

        EcdsaP256 ( const EcdsaP256 & );
        EcdsaP256 &operator= ( const EcdsaP256 & );
    };

    // ---- HKDF-SHA256 (RFC 5869) ---------------------------------------
    // Derives cbOkm bytes of key material. salt/info may be null/0.
    bool HkdfSha256 ( const unsigned char *pIkm,  size_t cbIkm,
                      const unsigned char *pSalt, size_t cbSalt,
                      const unsigned char *pInfo, size_t cbInfo,
                      unsigned char *pOkm, size_t cbOkm );

    // ---- HMAC-SHA256 (RFC 2104) ---------------------------------------
    bool HmacSha256 ( const unsigned char *pKey,  size_t cbKey,
                      const unsigned char *pData, size_t cbData,
                      unsigned char pMacOut[/*kSha256Len*/] );

    // ---- Constant-time comparison -------------------------------------
    // Returns true iff the first n bytes of a and b are equal, without
    // early-out timing leakage. Use for tag/MAC/secret comparison.
    bool ConstTimeEqual ( const void *a, const void *b, size_t n );

    // ---- Self-test ----------------------------------------------------
    // Runs known-answer and round-trip checks over every primitive above.
    // Returns true iff all pass. Intended for a startup/debug assertion.
    // Exported so a test outside this DLL can actually run it - the KATs are
    // worth nothing if nothing invokes them.
    P2PCNG_EXT bool SelfTest ( );

} // namespace p2pcng
