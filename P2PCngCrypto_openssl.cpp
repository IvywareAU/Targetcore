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
//  P2PCngCrypto_openssl.cpp - OpenSSL 3 backend for the p2pcng primitives
//  (Risk #5). Same header/namespace/ABI as the CNG (BCrypt)
//  backend in P2PCngCrypto.cpp; the two are mutually exclusive per platform:
//
//     Windows -> P2PCngCrypto.cpp          (BCrypt)      [ #ifdef _WIN32 ]
//     Linux   -> P2PCngCrypto_openssl.cpp  (this file)   [ #ifndef _WIN32 ]
//
//  Wire compatibility with the CNG peer is a hard requirement:
//    * AES-256-GCM sealed layout is byte-identical: [ nonce(12) | ct | tag(16) ].
//    * The ECDH public point is the raw uncompressed P-256 point X||Y (64 bytes,
//      big-endian) — the same bytes CNG's BCRYPT_ECCPUBLIC_BLOB carries after its
//      header, so a CNG public and an OpenSSL public interoperate on the wire.
//    * The ECDH raw shared secret is the P-256 X coordinate. CNG's
//      BCRYPT_KDF_RAW_SECRET returns it LITTLE-ENDIAN (see P2PCngCrypto.cpp:318);
//      OpenSSL's EVP_PKEY_derive returns it BIG-endian. This backend REVERSES to
//      little-endian so both peers feed HKDF the identical IKM (Risk #5). The
//      reversal is harmless for same-backend agreement (both sides reverse).
//
//  The whole file compiles to nothing on Windows so it can sit in a cross-platform
//  build without perturbing the MSVC binary.
//
#ifndef _WIN32

#include "P2PCngCrypto.h"

#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <vector>
#include <cstring>

namespace p2pcng
{
    // -------------------------------------------------------------------
    //  CSPRNG
    // -------------------------------------------------------------------
    bool CngRandom ( void *pBuffer, unsigned long cbBuffer )
    {
        if ( !pBuffer && cbBuffer ) return false;
        if ( cbBuffer == 0 ) return true;
        return RAND_bytes ( (unsigned char *)pBuffer, (int)cbBuffer ) == 1;
    }

    // -------------------------------------------------------------------
    //  SHA-256
    // -------------------------------------------------------------------
    bool Sha256 ( const unsigned char *pData, size_t cbData,
                  unsigned char pHashOut[] )
    {
        if ( !pHashOut ) return false;
        unsigned int len = 0;
        if ( EVP_Digest ( pData, cbData, pHashOut, &len, EVP_sha256(), nullptr ) != 1 )
            return false;
        return len == kSha256Len;
    }

    // -------------------------------------------------------------------
    //  HMAC-SHA256 (RFC 2104) — OpenSSL one-shot HMAC()
    // -------------------------------------------------------------------
    bool HmacSha256 ( const unsigned char *pKey,  size_t cbKey,
                      const unsigned char *pData, size_t cbData,
                      unsigned char pMacOut[] )
    {
        //  HMAC() tolerates a null/empty message but wants a non-null key ptr even
        //  for a zero-length key; pass a dummy byte in that (unused) case.
        unsigned char dummy = 0;
        const unsigned char *key = ( pKey && cbKey ) ? pKey : &dummy;
        unsigned int len = 0;
        unsigned char *r = HMAC ( EVP_sha256(), key, (int)cbKey,
                                  pData, cbData, pMacOut, &len );
        return r != nullptr && len == (unsigned int)kSha256Len;
    }

    // -------------------------------------------------------------------
    //  HKDF-SHA256 (RFC 5869). Backend-agnostic — the identical extract/expand
    //  the CNG file uses, so both backends produce the same OKM bit-for-bit.
    // -------------------------------------------------------------------
    bool HkdfSha256 ( const unsigned char *pIkm,  size_t cbIkm,
                      const unsigned char *pSalt, size_t cbSalt,
                      const unsigned char *pInfo, size_t cbInfo,
                      unsigned char *pOkm, size_t cbOkm )
    {
        unsigned char zeroSalt[kSha256Len] = { 0 };
        const unsigned char *salt = ( pSalt && cbSalt ) ? pSalt : zeroSalt;
        size_t saltLen = ( pSalt && cbSalt ) ? cbSalt : sizeof(zeroSalt);

        unsigned char prk[kSha256Len];
        if ( !HmacSha256 ( salt, saltLen, pIkm, cbIkm, prk ) )
            return false;

        unsigned char t[kSha256Len];
        size_t tLen = 0, done = 0;
        unsigned int counter = 1;
        std::vector<unsigned char> block;
        bool bOk = true;

        while ( done < cbOkm )
        {
            if ( counter > 255 ) { bOk = false; break; }   // RFC 5869 limit
            block.clear();
            block.insert ( block.end(), t, t + tLen );      // T(i-1) (empty first)
            if ( pInfo && cbInfo )
                block.insert ( block.end(), pInfo, pInfo + cbInfo );
            block.push_back ( (unsigned char)counter );
            if ( !HmacSha256 ( prk, kSha256Len, block.data(), block.size(), t ) )
                { bOk = false; break; }
            tLen = kSha256Len;
            size_t n = ( cbOkm - done < kSha256Len ) ? ( cbOkm - done ) : kSha256Len;
            memcpy ( pOkm + done, t, n );
            done += n;
            counter++;
        }

        OPENSSL_cleanse ( prk, sizeof(prk) );
        OPENSSL_cleanse ( t,   sizeof(t) );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  Constant-time comparison — CRYPTO_memcmp (§6.2). Returns 0 iff equal.
    // -------------------------------------------------------------------
    bool ConstTimeEqual ( const void *a, const void *b, size_t n )
    {
        if ( n == 0 ) return true;
        return CRYPTO_memcmp ( a, b, n ) == 0;
    }

    // -------------------------------------------------------------------
    //  AES-256-GCM. m_hAlg holds the EVP_CIPHER_CTX; m_hKey holds the 32-byte
    //  key (stashed on SetKey; a fresh context is initialised per Seal/Open so a
    //  single AesGcm object can process many messages).
    // -------------------------------------------------------------------
    AesGcm::AesGcm ( )
        : m_hAlg(nullptr), m_hKey(nullptr), m_pKeyObj(nullptr), m_cbKeyObj(0)
    { }

    AesGcm::~AesGcm ( )
    {
        if ( m_pKeyObj )
        {
            OPENSSL_cleanse ( m_pKeyObj, m_cbKeyObj );
            free ( m_pKeyObj );
        }
    }

    bool AesGcm::SetKey ( const unsigned char *pKey, size_t cbKey )
    {
        if ( cbKey != kAesKeyLen || !pKey ) return false;
        if ( !m_pKeyObj )
        {
            m_pKeyObj = (unsigned char *)malloc ( kAesKeyLen );
            if ( !m_pKeyObj ) return false;
            m_cbKeyObj = kAesKeyLen;
        }
        memcpy ( m_pKeyObj, pKey, kAesKeyLen );
        return true;
    }

    bool AesGcm::Seal ( const unsigned char *pPlain, size_t cbPlain,
                        const unsigned char *pAad,   size_t cbAad,
                        unsigned char *pOut, size_t cbOutBuf, size_t *pcbOut )
    {
        if ( !m_pKeyObj || !pOut ) return false;
        size_t need = SealedSize ( cbPlain );
        if ( cbOutBuf < need ) return false;

        unsigned char *pNonce  = pOut;
        unsigned char *pCipher = pOut + kGcmNonceLen;
        unsigned char *pTag    = pOut + kGcmNonceLen + cbPlain;

        if ( !CngRandom ( pNonce, (unsigned long)kGcmNonceLen ) ) return false;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if ( !ctx ) return false;
        bool bOk = false;
        int outl = 0;
        do {
            if ( EVP_EncryptInit_ex ( ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr ) != 1 ) break;
            if ( EVP_CIPHER_CTX_ctrl ( ctx, EVP_CTRL_GCM_SET_IVLEN, (int)kGcmNonceLen, nullptr ) != 1 ) break;
            if ( EVP_EncryptInit_ex ( ctx, nullptr, nullptr, m_pKeyObj, pNonce ) != 1 ) break;
            if ( cbAad && pAad &&
                 EVP_EncryptUpdate ( ctx, nullptr, &outl, pAad, (int)cbAad ) != 1 ) break;
            if ( cbPlain &&
                 EVP_EncryptUpdate ( ctx, pCipher, &outl, pPlain, (int)cbPlain ) != 1 ) break;
            if ( EVP_EncryptFinal_ex ( ctx, pCipher + outl, &outl ) != 1 ) break;   // GCM: no extra bytes
            if ( EVP_CIPHER_CTX_ctrl ( ctx, EVP_CTRL_GCM_GET_TAG, (int)kGcmTagLen, pTag ) != 1 ) break;
            bOk = true;
        } while ( 0 );
        EVP_CIPHER_CTX_free ( ctx );
        if ( bOk && pcbOut ) *pcbOut = need;
        return bOk;
    }

    bool AesGcm::Open ( const unsigned char *pIn, size_t cbIn,
                        const unsigned char *pAad, size_t cbAad,
                        unsigned char *pOut, size_t cbOutBuf, size_t *pcbOut )
    {
        if ( !m_pKeyObj ) return false;
        if ( cbIn < kGcmNonceLen + kGcmTagLen ) return false;
        size_t cbCipher = cbIn - kGcmNonceLen - kGcmTagLen;
        if ( cbOutBuf < cbCipher ) return false;
        if ( cbCipher && !pOut )  return false;

        const unsigned char *pNonce  = pIn;
        const unsigned char *pCipher = pIn + kGcmNonceLen;
        const unsigned char *pTag    = pIn + kGcmNonceLen + cbCipher;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if ( !ctx ) return false;
        bool bOk = false;
        int outl = 0;
        do {
            if ( EVP_DecryptInit_ex ( ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr ) != 1 ) break;
            if ( EVP_CIPHER_CTX_ctrl ( ctx, EVP_CTRL_GCM_SET_IVLEN, (int)kGcmNonceLen, nullptr ) != 1 ) break;
            if ( EVP_DecryptInit_ex ( ctx, nullptr, nullptr, m_pKeyObj, pNonce ) != 1 ) break;
            if ( cbAad && pAad &&
                 EVP_DecryptUpdate ( ctx, nullptr, &outl, pAad, (int)cbAad ) != 1 ) break;
            if ( cbCipher &&
                 EVP_DecryptUpdate ( ctx, pOut, &outl, pCipher, (int)cbCipher ) != 1 ) break;
            //  Set expected tag, then Final verifies it — returns <=0 on mismatch.
            if ( EVP_CIPHER_CTX_ctrl ( ctx, EVP_CTRL_GCM_SET_TAG, (int)kGcmTagLen,
                                       (void *)pTag ) != 1 ) break;
            if ( EVP_DecryptFinal_ex ( ctx, pOut ? pOut + outl : nullptr, &outl ) != 1 ) break;
            bOk = true;
        } while ( 0 );
        EVP_CIPHER_CTX_free ( ctx );
        if ( bOk && pcbOut ) *pcbOut = cbCipher;
        return bOk;
    }

    // -------------------------------------------------------------------
    //  ECDH P-256. m_hKey holds our EVP_PKEY*; m_hAlg is unused.
    // -------------------------------------------------------------------
    EcdhP256::EcdhP256 ( ) : m_hAlg(nullptr), m_hKey(nullptr), m_bPrivate(false) { }

    EcdhP256::~EcdhP256 ( )
    {
        if ( m_hKey ) EVP_PKEY_free ( (EVP_PKEY *)m_hKey );
    }

    bool EcdhP256::Generate ( )
    {
        if ( m_hKey ) { EVP_PKEY_free ( (EVP_PKEY *)m_hKey ); m_hKey = nullptr; }
        EVP_PKEY *pkey = EVP_EC_gen ( "P-256" );   // OpenSSL 3.0+
        if ( !pkey ) return false;
        m_hKey     = pkey;
        m_bPrivate = true;
        return true;
    }

    bool EcdhP256::ExportPublic ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut ) return false;
        //  Uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes for P-256.
        unsigned char pub[65];
        size_t len = 0;
        if ( EVP_PKEY_get_octet_string_param ( (EVP_PKEY *)m_hKey,
                 OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &len ) != 1 )
            return false;
        if ( len != sizeof(pub) || pub[0] != 0x04 ) return false;
        memcpy ( pOut, pub + 1, kEcdhPubLen );     // strip the 0x04 -> raw X||Y
        return true;
    }

    //  Static agreement key persistence. Byte-for-byte the same blob layout as
    //  EcdsaP256's (X||Y||d), because both are P-256 and the on-disk container
    //  is shared - a key written by the CNG backend must load here and agree to
    //  the same secret, or a Windows peer and a Linux peer cannot talk.
    bool EcdhP256::ExportPrivate ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut || !m_bPrivate ) return false;

        //  bn2binpad, not bn2bin: a scalar with leading zero bytes would emit
        //  a short buffer and silently shift the blob layout.
        if ( !ExportPublic ( pOut ) ) return false;

        BIGNUM *priv = nullptr;
        if ( EVP_PKEY_get_bn_param ( (EVP_PKEY *)m_hKey,
                                     OSSL_PKEY_PARAM_PRIV_KEY, &priv ) != 1 )
            return false;                          // public-only key: no scalar
        bool bOk = BN_bn2binpad ( priv, pOut + kEcdhPubLen, 32 ) == 32;
        BN_clear_free ( priv );
        return bOk;
    }

    bool EcdhP256::ImportPrivate ( const unsigned char pIn[] )
    {
        if ( !pIn ) return false;
        if ( m_hKey ) { EVP_PKEY_free ( (EVP_PKEY *)m_hKey ); m_hKey = nullptr; }
        m_bPrivate = false;

        unsigned char pt[65];
        pt[0] = 0x04;
        memcpy ( pt + 1, pIn, kEcdhPubLen );

        BIGNUM         *priv   = BN_bin2bn ( pIn + kEcdhPubLen, 32, nullptr );
        OSSL_PARAM_BLD *bld    = OSSL_PARAM_BLD_new();
        OSSL_PARAM     *params = nullptr;
        EVP_PKEY_CTX   *fctx   = nullptr;
        EVP_PKEY       *pkey   = nullptr;
        bool bOk = false;

        do {
            if ( !priv || !bld ) break;
            if ( OSSL_PARAM_BLD_push_utf8_string ( bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                                   "P-256", 0 ) != 1 ) break;
            //  Both halves supplied rather than derived, so a corrupted key
            //  file is caught here instead of producing a key that agrees to
            //  a secret nobody else computes.
            if ( OSSL_PARAM_BLD_push_octet_string ( bld, OSSL_PKEY_PARAM_PUB_KEY,
                                                    pt, sizeof(pt) ) != 1 ) break;
            if ( OSSL_PARAM_BLD_push_BN ( bld, OSSL_PKEY_PARAM_PRIV_KEY, priv ) != 1 ) break;
            params = OSSL_PARAM_BLD_to_param ( bld );
            if ( !params ) break;

            fctx = EVP_PKEY_CTX_new_from_name ( nullptr, "EC", nullptr );
            if ( !fctx || EVP_PKEY_fromdata_init ( fctx ) != 1 ) break;
            if ( EVP_PKEY_fromdata ( fctx, &pkey, EVP_PKEY_KEYPAIR, params ) != 1 ) break;

            {
                EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_pkey ( nullptr, pkey, nullptr );
                int chk = cctx ? EVP_PKEY_pairwise_check ( cctx ) : 0;
                if ( cctx ) EVP_PKEY_CTX_free ( cctx );
                if ( chk != 1 ) break;
            }

            m_hKey     = pkey;
            pkey       = nullptr;                  // ownership transferred
            m_bPrivate = true;
            bOk        = true;
        } while ( 0 );

        if ( pkey )   EVP_PKEY_free ( pkey );
        if ( fctx )   EVP_PKEY_CTX_free ( fctx );
        if ( params ) OSSL_PARAM_free ( params );
        if ( bld )    OSSL_PARAM_BLD_free ( bld );
        if ( priv )   BN_clear_free ( priv );
        return bOk;
    }

    bool EcdhP256::ImportPublic ( const unsigned char pIn[] )
    {
        if ( !pIn ) return false;
        if ( m_hKey ) { EVP_PKEY_free ( (EVP_PKEY *)m_hKey ); m_hKey = nullptr; }
        m_bPrivate = false;      // a directory entry, not a key we can agree with

        unsigned char pt[65];
        pt[0] = 0x04;
        memcpy ( pt + 1, pIn, kEcdhPubLen );

        EVP_PKEY_CTX *fctx = nullptr;
        EVP_PKEY     *pkey = nullptr;
        bool bOk = false;

        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_utf8_string (
                        (char *)OSSL_PKEY_PARAM_GROUP_NAME, (char *)"P-256", 0 );
        params[1] = OSSL_PARAM_construct_octet_string (
                        (char *)OSSL_PKEY_PARAM_PUB_KEY, pt, sizeof(pt) );
        params[2] = OSSL_PARAM_construct_end();

        do {
            fctx = EVP_PKEY_CTX_new_from_name ( nullptr, "EC", nullptr );
            if ( !fctx || EVP_PKEY_fromdata_init ( fctx ) != 1 ) break;
            if ( EVP_PKEY_fromdata ( fctx, &pkey, EVP_PKEY_PUBLIC_KEY, params ) != 1 ) break;
            m_hKey = pkey;
            pkey   = nullptr;
            bOk    = true;
        } while ( 0 );

        if ( pkey ) EVP_PKEY_free ( pkey );
        if ( fctx ) EVP_PKEY_CTX_free ( fctx );
        return bOk;
    }

    bool EcdhP256::DeriveRawSecret ( const unsigned char pPeerPub[],
                                     unsigned char pSecretOut[] )
    {
        //  Refused for a public-only key on both backends, so the two agree on
        //  the behaviour rather than one crashing and the other erroring.
        if ( !m_hKey || !m_bPrivate || !pPeerPub || !pSecretOut ) return false;

        //  Rebuild the peer's uncompressed point (0x04 || X || Y) and import it.
        unsigned char peerPt[65];
        peerPt[0] = 0x04;
        memcpy ( peerPt + 1, pPeerPub, kEcdhPubLen );

        EVP_PKEY_CTX *fctx = nullptr;
        EVP_PKEY     *peer = nullptr;
        EVP_PKEY_CTX *dctx = nullptr;
        bool bOk = false;

        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_utf8_string (
                        (char *)OSSL_PKEY_PARAM_GROUP_NAME, (char *)"P-256", 0 );
        params[1] = OSSL_PARAM_construct_octet_string (
                        (char *)OSSL_PKEY_PARAM_PUB_KEY, peerPt, sizeof(peerPt) );
        params[2] = OSSL_PARAM_construct_end();

        do {
            fctx = EVP_PKEY_CTX_new_from_name ( nullptr, "EC", nullptr );
            if ( !fctx ) break;
            if ( EVP_PKEY_fromdata_init ( fctx ) != 1 ) break;
            if ( EVP_PKEY_fromdata ( fctx, &peer, EVP_PKEY_PUBLIC_KEY, params ) != 1 ) break;

            dctx = EVP_PKEY_CTX_new ( (EVP_PKEY *)m_hKey, nullptr );
            if ( !dctx ) break;
            if ( EVP_PKEY_derive_init ( dctx ) != 1 ) break;
            if ( EVP_PKEY_derive_set_peer ( dctx, peer ) != 1 ) break;

            size_t slen = kEcdhSecLen;
            unsigned char be[kEcdhSecLen];
            if ( EVP_PKEY_derive ( dctx, be, &slen ) != 1 || slen != kEcdhSecLen ) break;

            //  OpenSSL returns the X coordinate big-endian; CNG's raw-secret KDF is
            //  little-endian. Reverse so a CNG peer and an OpenSSL peer feed HKDF the
            //  identical IKM (Risk #5).
            for ( size_t i = 0; i < kEcdhSecLen; ++i )
                pSecretOut[i] = be[kEcdhSecLen - 1 - i];
            OPENSSL_cleanse ( be, sizeof(be) );
            bOk = true;
        } while ( 0 );

        if ( dctx ) EVP_PKEY_CTX_free ( dctx );
        if ( peer ) EVP_PKEY_free ( peer );
        if ( fctx ) EVP_PKEY_CTX_free ( fctx );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  ECDSA P-256 identity. m_hKey holds our EVP_PKEY*; m_hAlg is unused.
    //
    //  WIRE CONTRACT with the CNG backend — the whole reason this class is
    //  hand-rolled rather than left to OpenSSL's defaults:
    //
    //    * Public point: raw uncompressed X||Y (64 bytes, big-endian), the
    //      0x04 prefix stripped — identical to EcdhP256 above and to what
    //      CNG's BCRYPT_ECCPUBLIC_BLOB carries after its header.
    //    * Signature: raw r||s (32+32, big-endian). CNG emits exactly this.
    //      OpenSSL emits and consumes DER SEQUENCE{INTEGER r, INTEGER s}, so
    //      this backend converts in BOTH directions. DER must never reach the
    //      wire, or a CNG peer will reject every signature we produce.
    //    * Private blob: X||Y||d (96 bytes), the CNG import format. OpenSSL
    //      does not need the public half, but the on-disk identity file is
    //      shared between platforms, so we carry and CHECK it.
    // -------------------------------------------------------------------
    EcdsaP256::EcdsaP256 ( ) : m_hAlg(nullptr), m_hKey(nullptr) { }

    EcdsaP256::~EcdsaP256 ( )
    {
        if ( m_hKey ) EVP_PKEY_free ( (EVP_PKEY *)m_hKey );
    }

    // m_hAlg is unused on this backend (OpenSSL has no algorithm handle to
    // cache); the method exists so the class layout matches the CNG twin.
    bool EcdsaP256::EnsureAlg ( ) { return true; }

    bool EcdsaP256::Generate ( )
    {
        if ( m_hKey ) { EVP_PKEY_free ( (EVP_PKEY *)m_hKey ); m_hKey = nullptr; }
        EVP_PKEY *pkey = EVP_EC_gen ( "P-256" );   // OpenSSL 3.0+
        if ( !pkey ) return false;
        m_hKey = pkey;
        return true;
    }

    bool EcdsaP256::ExportPublic ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut ) return false;
        unsigned char pub[65];                     // 0x04 || X(32) || Y(32)
        size_t len = 0;
        if ( EVP_PKEY_get_octet_string_param ( (EVP_PKEY *)m_hKey,
                 OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &len ) != 1 )
            return false;
        if ( len != sizeof(pub) || pub[0] != 0x04 ) return false;
        memcpy ( pOut, pub + 1, kEcdsaPubLen );    // strip 0x04 -> raw X||Y
        return true;
    }

    bool EcdsaP256::ExportPrivate ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut ) return false;

        //  X||Y first, then the scalar padded to a fixed 32 bytes (BN_bn2bin
        //  would emit a SHORT buffer for a scalar with leading zero bytes,
        //  silently shifting the blob layout — bn2binpad is mandatory here).
        if ( !ExportPublic ( pOut ) ) return false;

        BIGNUM *priv = nullptr;
        if ( EVP_PKEY_get_bn_param ( (EVP_PKEY *)m_hKey,
                                     OSSL_PKEY_PARAM_PRIV_KEY, &priv ) != 1 )
            return false;                          // verify-only key: no scalar
        bool bOk = BN_bn2binpad ( priv, pOut + kEcdsaPubLen, 32 ) == 32;
        BN_clear_free ( priv );
        return bOk;
    }

    bool EcdsaP256::ImportPrivate ( const unsigned char pIn[] )
    {
        if ( !pIn ) return false;
        if ( m_hKey ) { EVP_PKEY_free ( (EVP_PKEY *)m_hKey ); m_hKey = nullptr; }

        unsigned char pt[65];
        pt[0] = 0x04;
        memcpy ( pt + 1, pIn, kEcdsaPubLen );

        BIGNUM         *priv   = BN_bin2bn ( pIn + kEcdsaPubLen, 32, nullptr );
        OSSL_PARAM_BLD *bld    = OSSL_PARAM_BLD_new();
        OSSL_PARAM     *params = nullptr;
        EVP_PKEY_CTX   *fctx   = nullptr;
        EVP_PKEY       *pkey   = nullptr;
        bool bOk = false;

        do {
            if ( !priv || !bld ) break;
            if ( OSSL_PARAM_BLD_push_utf8_string ( bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                                   "P-256", 0 ) != 1 ) break;
            //  Both halves are supplied rather than letting OpenSSL derive the
            //  point, so a corrupted identity file is caught here instead of
            //  producing a key that signs as somebody else.
            if ( OSSL_PARAM_BLD_push_octet_string ( bld, OSSL_PKEY_PARAM_PUB_KEY,
                                                    pt, sizeof(pt) ) != 1 ) break;
            if ( OSSL_PARAM_BLD_push_BN ( bld, OSSL_PKEY_PARAM_PRIV_KEY, priv ) != 1 ) break;
            params = OSSL_PARAM_BLD_to_param ( bld );
            if ( !params ) break;

            fctx = EVP_PKEY_CTX_new_from_name ( nullptr, "EC", nullptr );
            if ( !fctx || EVP_PKEY_fromdata_init ( fctx ) != 1 ) break;
            if ( EVP_PKEY_fromdata ( fctx, &pkey, EVP_PKEY_KEYPAIR, params ) != 1 ) break;

            //  Explicit consistency check: d and X||Y must belong together.
            //  EVP_PKEY_fromdata does not necessarily validate the pair.
            {
                EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_pkey ( nullptr, pkey, nullptr );
                int chk = cctx ? EVP_PKEY_pairwise_check ( cctx ) : 0;
                if ( cctx ) EVP_PKEY_CTX_free ( cctx );
                if ( chk != 1 ) break;
            }

            m_hKey = pkey;
            pkey   = nullptr;                      // ownership transferred
            bOk    = true;
        } while ( 0 );

        if ( pkey )   EVP_PKEY_free ( pkey );
        if ( fctx )   EVP_PKEY_CTX_free ( fctx );
        if ( params ) OSSL_PARAM_free ( params );
        if ( bld )    OSSL_PARAM_BLD_free ( bld );
        if ( priv )   BN_clear_free ( priv );
        return bOk;
    }

    bool EcdsaP256::ImportPublic ( const unsigned char pIn[] )
    {
        if ( !pIn ) return false;
        if ( m_hKey ) { EVP_PKEY_free ( (EVP_PKEY *)m_hKey ); m_hKey = nullptr; }

        unsigned char pt[65];
        pt[0] = 0x04;
        memcpy ( pt + 1, pIn, kEcdsaPubLen );

        EVP_PKEY_CTX *fctx = nullptr;
        EVP_PKEY     *pkey = nullptr;
        bool bOk = false;

        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_utf8_string (
                        (char *)OSSL_PKEY_PARAM_GROUP_NAME, (char *)"P-256", 0 );
        params[1] = OSSL_PARAM_construct_octet_string (
                        (char *)OSSL_PKEY_PARAM_PUB_KEY, pt, sizeof(pt) );
        params[2] = OSSL_PARAM_construct_end();

        do {
            fctx = EVP_PKEY_CTX_new_from_name ( nullptr, "EC", nullptr );
            if ( !fctx || EVP_PKEY_fromdata_init ( fctx ) != 1 ) break;
            if ( EVP_PKEY_fromdata ( fctx, &pkey, EVP_PKEY_PUBLIC_KEY, params ) != 1 ) break;
            m_hKey = pkey;
            pkey   = nullptr;
            bOk    = true;
        } while ( 0 );

        if ( pkey ) EVP_PKEY_free ( pkey );
        if ( fctx ) EVP_PKEY_CTX_free ( fctx );
        return bOk;
    }

    bool EcdsaP256::Sign ( const unsigned char *pData, size_t cbData,
                           unsigned char pSigOut[] )
    {
        if ( !m_hKey || !pSigOut ) return false;

        EVP_MD_CTX  *mdctx = EVP_MD_CTX_new();
        ECDSA_SIG   *es    = nullptr;
        std::vector<unsigned char> der;
        bool bOk = false;

        do {
            if ( !mdctx ) break;
            if ( EVP_DigestSignInit ( mdctx, nullptr, EVP_sha256(), nullptr,
                                      (EVP_PKEY *)m_hKey ) != 1 ) break;
            size_t cbDer = 0;
            if ( EVP_DigestSign ( mdctx, nullptr, &cbDer, pData, cbData ) != 1 ) break;
            der.resize ( cbDer );
            if ( EVP_DigestSign ( mdctx, der.data(), &cbDer, pData, cbData ) != 1 ) break;
            der.resize ( cbDer );

            //  DER -> raw r||s. Both are re-emitted at a fixed 32 bytes, since
            //  DER INTEGERs are minimal-length and may be shorter (leading zero
            //  bytes dropped) or longer (a 0x00 sign byte prepended).
            const unsigned char *p = der.data();
            es = d2i_ECDSA_SIG ( nullptr, &p, (long)der.size() );
            if ( !es ) break;
            const BIGNUM *r = nullptr, *s = nullptr;
            ECDSA_SIG_get0 ( es, &r, &s );
            if ( !r || !s ) break;
            if ( BN_bn2binpad ( r, pSigOut,      32 ) != 32 ) break;
            if ( BN_bn2binpad ( s, pSigOut + 32, 32 ) != 32 ) break;
            bOk = true;
        } while ( 0 );

        if ( es )    ECDSA_SIG_free ( es );
        if ( mdctx ) EVP_MD_CTX_free ( mdctx );
        return bOk;
    }

    bool EcdsaP256::Verify ( const unsigned char *pData, size_t cbData,
                             const unsigned char pSig[] )
    {
        if ( !m_hKey || !pSig ) return false;

        //  raw r||s -> DER for OpenSSL's verifier.
        BIGNUM      *r     = BN_bin2bn ( pSig,      32, nullptr );
        BIGNUM      *s     = BN_bin2bn ( pSig + 32, 32, nullptr );
        ECDSA_SIG   *es    = ECDSA_SIG_new();
        EVP_MD_CTX  *mdctx = nullptr;
        unsigned char *der = nullptr;
        bool bOk = false;

        do {
            if ( !r || !s || !es ) break;
            //  Takes ownership of r and s on success — do not free them below.
            if ( ECDSA_SIG_set0 ( es, r, s ) != 1 ) break;
            r = s = nullptr;

            int cbDer = i2d_ECDSA_SIG ( es, &der );
            if ( cbDer <= 0 || !der ) break;

            mdctx = EVP_MD_CTX_new();
            if ( !mdctx ) break;
            if ( EVP_DigestVerifyInit ( mdctx, nullptr, EVP_sha256(), nullptr,
                                        (EVP_PKEY *)m_hKey ) != 1 ) break;
            bOk = EVP_DigestVerify ( mdctx, der, (size_t)cbDer, pData, cbData ) == 1;
        } while ( 0 );

        if ( der )   OPENSSL_free ( der );
        if ( mdctx ) EVP_MD_CTX_free ( mdctx );
        if ( es )    ECDSA_SIG_free ( es );        // frees r/s once set0 succeeded
        if ( r )     BN_free ( r );                // only reached if set0 failed
        if ( s )     BN_free ( s );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  Test-only hook (Linux backend TU only; NOT in the shared header, so no ABI /
    //  Windows impact). Derives the raw ECDH secret from a FIXED private key + peer
    //  public point, running the exact same import/derive/LE-reverse path as
    //  DeriveRawSecret. Lets a KAT drive a published P-256 vector (RFC 5903 §8.1)
    //  through our conventions — raw X||Y big-endian point, little-endian secret —
    //  which is the cross-backend agreement contract with CNG (Risk #5).
    //    privBE : 32-byte big-endian private scalar
    //    peerXY : 64-byte peer public point X||Y (big-endian)
    //    outLE  : 32-byte shared secret X coordinate, little-endian (CNG format)
    // -------------------------------------------------------------------
    namespace test
    {
        bool EcdhDeriveKAT ( const unsigned char privBE[/*32*/],
                             const unsigned char peerXY[/*64*/],
                             unsigned char outLE[/*32*/] )
        {
            BIGNUM         *priv   = BN_bin2bn ( privBE, (int)kEcdhSecLen, nullptr );
            OSSL_PARAM_BLD *bld    = OSSL_PARAM_BLD_new();
            OSSL_PARAM     *params = nullptr;
            EVP_PKEY_CTX   *fctx   = nullptr;  EVP_PKEY *mykey = nullptr;
            EVP_PKEY_CTX   *pfctx  = nullptr;  EVP_PKEY *peer  = nullptr;
            EVP_PKEY_CTX   *dctx   = nullptr;
            bool bOk = false;

            unsigned char peerPt[65];
            peerPt[0] = 0x04;
            memcpy ( peerPt + 1, peerXY, kEcdhPubLen );

            do {
                if ( !priv || !bld ) break;
                if ( OSSL_PARAM_BLD_push_utf8_string ( bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                                       "P-256", 0 ) != 1 ) break;
                if ( OSSL_PARAM_BLD_push_BN ( bld, OSSL_PKEY_PARAM_PRIV_KEY, priv ) != 1 ) break;
                params = OSSL_PARAM_BLD_to_param ( bld );
                if ( !params ) break;

                fctx = EVP_PKEY_CTX_new_from_name ( nullptr, "EC", nullptr );
                if ( !fctx || EVP_PKEY_fromdata_init ( fctx ) != 1 ) break;
                //  Import as a keypair from the private scalar (OpenSSL derives the
                //  public point); the derive uses only the private key anyway.
                if ( EVP_PKEY_fromdata ( fctx, &mykey, EVP_PKEY_KEYPAIR, params ) != 1 ) break;

                OSSL_PARAM pp[3];
                pp[0] = OSSL_PARAM_construct_utf8_string (
                            (char *)OSSL_PKEY_PARAM_GROUP_NAME, (char *)"P-256", 0 );
                pp[1] = OSSL_PARAM_construct_octet_string (
                            (char *)OSSL_PKEY_PARAM_PUB_KEY, peerPt, sizeof(peerPt) );
                pp[2] = OSSL_PARAM_construct_end();
                pfctx = EVP_PKEY_CTX_new_from_name ( nullptr, "EC", nullptr );
                if ( !pfctx || EVP_PKEY_fromdata_init ( pfctx ) != 1 ) break;
                if ( EVP_PKEY_fromdata ( pfctx, &peer, EVP_PKEY_PUBLIC_KEY, pp ) != 1 ) break;

                dctx = EVP_PKEY_CTX_new ( mykey, nullptr );
                if ( !dctx || EVP_PKEY_derive_init ( dctx ) != 1 ) break;
                if ( EVP_PKEY_derive_set_peer ( dctx, peer ) != 1 ) break;

                size_t slen = kEcdhSecLen;
                unsigned char be[kEcdhSecLen];
                if ( EVP_PKEY_derive ( dctx, be, &slen ) != 1 || slen != kEcdhSecLen ) break;
                for ( size_t i = 0; i < kEcdhSecLen; ++i )
                    outLE[i] = be[kEcdhSecLen - 1 - i];
                OPENSSL_cleanse ( be, sizeof(be) );
                bOk = true;
            } while ( 0 );

            if ( dctx )   EVP_PKEY_CTX_free ( dctx );
            if ( peer )   EVP_PKEY_free ( peer );
            if ( pfctx )  EVP_PKEY_CTX_free ( pfctx );
            if ( mykey )  EVP_PKEY_free ( mykey );
            if ( fctx )   EVP_PKEY_CTX_free ( fctx );
            if ( params ) OSSL_PARAM_free ( params );
            if ( bld )    OSSL_PARAM_BLD_free ( bld );
            if ( priv )   BN_free ( priv );
            return bOk;
        }
    } // namespace test

    // -------------------------------------------------------------------
    //  Self-test — identical body to the CNG backend (same published KATs),
    //  so passing it on Linux proves the OpenSSL primitives against the same
    //  RFC 4231 / RFC 5869 vectors the Windows build validates.
    // -------------------------------------------------------------------
    bool SelfTest ( )
    {
        // --- HMAC-SHA256 KAT: RFC 4231 test case 2 --------------------
        {
            const unsigned char key[]  = { 'J','e','f','e' };
            const char          data[] = "what do ya want for nothing?";
            const unsigned char expect[kSha256Len] = {
                0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
                0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43 };
            unsigned char mac[kSha256Len];
            if ( !HmacSha256 ( key, sizeof(key),
                               (const unsigned char *)data, sizeof(data) - 1, mac ) )
                return false;
            if ( !ConstTimeEqual ( mac, expect, kSha256Len ) ) return false;
        }

        // --- HKDF-SHA256 KAT: RFC 5869 test case 1 --------------------
        {
            unsigned char ikm[22];  memset ( ikm, 0x0b, sizeof(ikm) );
            const unsigned char salt[] = {
                0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c };
            const unsigned char info[] = {
                0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };
            const unsigned char expect[42] = {
                0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
                0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
                0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65 };
            unsigned char okm[42];
            if ( !HkdfSha256 ( ikm, sizeof(ikm), salt, sizeof(salt),
                               info, sizeof(info), okm, sizeof(okm) ) )
                return false;
            if ( !ConstTimeEqual ( okm, expect, sizeof(okm) ) ) return false;
        }

        // --- AES-256-GCM round-trip + tamper detection ----------------
        {
            unsigned char key[kAesKeyLen];
            if ( !CngRandom ( key, sizeof(key) ) ) return false;
            AesGcm cipher;
            if ( !cipher.SetKey ( key, sizeof(key) ) ) return false;

            const char    msg[]  = "TargetCore secure channel self-test payload";
            const unsigned char aad[] = { 'h','d','r' };
            size_t cbPlain = sizeof(msg) - 1;

            std::vector<unsigned char> sealed ( AesGcm::SealedSize ( cbPlain ) );
            size_t cbSealed = 0;
            if ( !cipher.Seal ( (const unsigned char *)msg, cbPlain,
                                aad, sizeof(aad),
                                sealed.data(), sealed.size(), &cbSealed ) )
                return false;
            if ( cbSealed != sealed.size() ) return false;

            std::vector<unsigned char> opened ( AesGcm::OpenedSize ( cbSealed ) + 1 );
            size_t cbOpened = 0;
            if ( !cipher.Open ( sealed.data(), cbSealed, aad, sizeof(aad),
                                opened.data(), opened.size(), &cbOpened ) )
                return false;
            if ( cbOpened != cbPlain ) return false;
            if ( !ConstTimeEqual ( opened.data(), msg, cbPlain ) ) return false;

            std::vector<unsigned char> bad = sealed;
            bad[kGcmNonceLen] ^= 0x01;
            if ( cipher.Open ( bad.data(), bad.size(), aad, sizeof(aad),
                               opened.data(), opened.size(), &cbOpened ) )
                return false;   // must NOT succeed
            const unsigned char aadBad[] = { 'H','D','R' };
            if ( cipher.Open ( sealed.data(), cbSealed, aadBad, sizeof(aadBad),
                               opened.data(), opened.size(), &cbOpened ) )
                return false;   // must NOT succeed
        }

        // --- ECDH P-256 agreement symmetry ----------------------------
        {
            EcdhP256 a, b;
            if ( !a.Generate() || !b.Generate() ) return false;
            unsigned char pa[kEcdhPubLen], pb[kEcdhPubLen];
            if ( !a.ExportPublic ( pa ) || !b.ExportPublic ( pb ) ) return false;
            unsigned char sa[kEcdhSecLen], sb[kEcdhSecLen];
            if ( !a.DeriveRawSecret ( pb, sa ) ) return false;
            if ( !b.DeriveRawSecret ( pa, sb ) ) return false;
            if ( !ConstTimeEqual ( sa, sb, kEcdhSecLen ) ) return false;

            EcdhP256 c;
            if ( !c.Generate() ) return false;
            unsigned char pc[kEcdhPubLen], sc[kEcdhSecLen];
            if ( !c.ExportPublic ( pc ) ) return false;
            if ( !a.DeriveRawSecret ( pc, sc ) ) return false;
            if ( ConstTimeEqual ( sa, sc, kEcdhSecLen ) ) return false;   // must differ
        }

        // --- ECDSA P-256: fixed cross-implementation vector -----------
        // BYTE-IDENTICAL to the block in P2PCngCrypto.cpp. That is the point:
        // the same pinned key, message and signature must verify on both
        // backends, so a green run on each proves they agree on the encoding
        // contract — raw X||Y point, raw r||s signature, big-endian, no DER on
        // the wire. This backend converts DER<->raw internally; if that
        // conversion is wrong in either direction, this KAT fails here while
        // still passing on Windows, which is exactly the drift it exists to
        // catch. Keep the two blocks in sync.
        {
            const char msg[] = "TargetCore identity KAT";
            const size_t cbMsg = sizeof(msg) - 1;

            const unsigned char pub[kEcdsaPubLen] = {
                0x85,0x85,0xd3,0xd1,0xa8,0xc1,0x09,0x14,0x4f,0x12,0x83,0x3f,0xac,0x06,0x96,0x8d,
                0x07,0xe7,0xd5,0x56,0x06,0x02,0xd1,0xf9,0xf4,0xe1,0xe5,0x6e,0x71,0x75,0xab,0x65,
                0xca,0x54,0x05,0x48,0x91,0xe0,0x72,0x37,0x8d,0x98,0x38,0x1a,0xee,0x4c,0xcc,0x95,
                0x7b,0xff,0xeb,0x7c,0x2e,0xe0,0xe2,0x60,0x9a,0x49,0xa2,0x96,0x51,0x17,0x2e,0xa6 };
            const unsigned char sig[kEcdsaSigLen] = {
                0xd6,0x63,0xbf,0x26,0xa5,0xb1,0x4e,0x3f,0x26,0x00,0xec,0x0e,0xa9,0xa4,0x81,0x8d,
                0x6a,0x22,0x8e,0x69,0x0d,0x78,0xef,0x6c,0x1a,0x8f,0xd0,0xfd,0xa1,0x21,0x3c,0x1c,
                0x6e,0x09,0x54,0x77,0x55,0x4e,0xe2,0xb8,0x70,0xfa,0x22,0x76,0xd6,0xeb,0x75,0xb4,
                0xcf,0x08,0x99,0x60,0x76,0xe9,0xfc,0xb1,0x63,0xd5,0xb6,0x38,0x66,0x03,0x2e,0x04 };
            const unsigned char priv_d[32] = {
                0xd8,0x9b,0xe5,0x7d,0x64,0x82,0xaf,0xbf,0xd0,0x66,0xc4,0x8c,0x34,0x76,0x43,0xbe,
                0x6e,0xe2,0xb5,0xf0,0xf4,0xd3,0x88,0x03,0x27,0x4d,0x8b,0x7e,0x88,0xbc,0x78,0x22 };

            EcdsaP256 v;
            if ( !v.ImportPublic ( pub ) ) return false;
            if ( !v.Verify ( (const unsigned char *)msg, cbMsg, sig ) ) return false;

            const char msgBad[] = "TargetCore identity KAU";
            if ( v.Verify ( (const unsigned char *)msgBad, sizeof(msgBad) - 1, sig ) )
                return false;

            unsigned char sigBad[kEcdsaSigLen];
            memcpy ( sigBad, sig, sizeof(sigBad) );
            sigBad[0] ^= 0x01;
            if ( v.Verify ( (const unsigned char *)msg, cbMsg, sigBad ) ) return false;

            unsigned char privBlob[kEcdsaPrivLen];
            memcpy ( privBlob,      pub,    kEcdsaPubLen );
            memcpy ( privBlob + 64, priv_d, sizeof(priv_d) );

            EcdsaP256 s;
            if ( !s.ImportPrivate ( privBlob ) ) return false;
            unsigned char pubRT[kEcdsaPubLen];
            if ( !s.ExportPublic ( pubRT ) ) return false;
            if ( !ConstTimeEqual ( pubRT, pub, kEcdsaPubLen ) ) return false;

            unsigned char sigRT[kEcdsaSigLen];
            if ( !s.Sign ( (const unsigned char *)msg, cbMsg, sigRT ) ) return false;
            if ( !v.Verify ( (const unsigned char *)msg, cbMsg, sigRT ) ) return false;

            //  Backend-specific: a corrupted identity file (public half not
            //  matching the scalar) must be REJECTED, not silently accepted as
            //  a key that signs as somebody else. CNG rejects this in
            //  BCryptImportKeyPair; here it is the explicit pairwise check.
            unsigned char privBad[kEcdsaPrivLen];
            memcpy ( privBad, privBlob, sizeof(privBad) );
            privBad[0] ^= 0x01;
            EcdsaP256 bad;
            if ( bad.ImportPrivate ( privBad ) ) return false;   // must NOT load

            OPENSSL_cleanse ( privBlob, sizeof(privBlob) );
        }

        // --- ECDSA P-256: short r / short s, from THIS backend ---------
        // Byte-identical to the block in P2PCngCrypto.cpp. Produced by this
        // backend's own Sign() and pinned in both, so each must verify the
        // other's real output for the two shapes that break a naive DER->raw
        // conversion: a leading zero byte in r or s shortens that DER INTEGER
        // below 32 bytes, and BN_bn2bin would emit a short buffer, shifting
        // the raw layout. sigShortR carries TWO leading zeros. Keep in sync.
        {
            const char msg[] = "TargetCore identity KAT";
            const size_t cbMsg = sizeof(msg) - 1;

            const unsigned char pubShortR[kEcdsaPubLen] = {
                0x68,0xb5,0xd9,0xb2,0x47,0x83,0x71,0xd9,0xf1,0x01,0x68,0x38,0x85,0x2c,0x08,0xdd,
                0xe1,0x6d,0xa4,0x95,0x1a,0x46,0x72,0xcf,0x30,0xff,0xd8,0x9c,0xc3,0x39,0x39,0xd3,
                0x00,0x74,0x9e,0xfa,0x4c,0x47,0x01,0x5b,0x91,0x83,0x05,0xf0,0x16,0x48,0x84,0x93,
                0x66,0x61,0x4a,0xf7,0xd2,0x0d,0x33,0x88,0x28,0x03,0x93,0x07,0x0d,0xe4,0x13,0x56 };
            const unsigned char sigShortR[kEcdsaSigLen] = {
                0x00,0x00,0x3f,0x5f,0x17,0x8a,0xa0,0x70,0x6c,0x42,0x31,0xeb,0x6e,0x54,0x95,0xaa,
                0x16,0x42,0xc5,0xb8,0xa9,0x94,0x12,0x7c,0x89,0x46,0x5f,0x22,0x99,0x4a,0x42,0xf9,
                0x4c,0x34,0xda,0xab,0x8f,0xf5,0xa2,0xad,0x32,0x79,0x9f,0x70,0x34,0xd0,0x52,0x3a,
                0x64,0xe3,0x42,0x22,0xed,0xe5,0xf0,0x78,0x44,0x31,0x02,0x9e,0x09,0xaa,0xf7,0x8e };

            const unsigned char pubShortS[kEcdsaPubLen] = {
                0xc6,0x23,0x94,0x31,0xb9,0xf8,0x99,0xd1,0x73,0x2b,0xf8,0xc1,0xd1,0x12,0x11,0xc9,
                0x91,0x24,0x1e,0x96,0xb9,0xc8,0x4e,0xab,0x2f,0xae,0x38,0xd0,0xeb,0x4f,0x82,0xe0,
                0x5c,0x87,0xc1,0x90,0xc2,0x45,0x33,0x60,0x5d,0xf3,0x8c,0xe2,0xc7,0xf0,0xb3,0x7f,
                0x69,0x2c,0xa4,0x57,0x14,0xf1,0x2f,0x07,0x94,0x0f,0xaa,0xa4,0x5b,0x3e,0x31,0x70 };
            const unsigned char sigShortS[kEcdsaSigLen] = {
                0x25,0x50,0xf3,0xa0,0xdd,0x55,0x1f,0x08,0x70,0x9a,0x58,0xb3,0x63,0x04,0x5e,0x1f,
                0xfc,0xb0,0xaf,0xec,0xdd,0x45,0x53,0xfc,0xdb,0xb9,0xb8,0x1d,0x47,0x8b,0xd8,0x5b,
                0x00,0x60,0x4f,0x29,0xb9,0x0b,0xe4,0xb7,0x0c,0x17,0x16,0x4e,0xfe,0xd5,0xa7,0x1e,
                0xd0,0x8e,0xd3,0x26,0x3a,0x80,0xf7,0x33,0x78,0x49,0x18,0x54,0x61,0x65,0x03,0x0a };

            EcdsaP256 vR;
            if ( !vR.ImportPublic ( pubShortR ) ) return false;
            if ( !vR.Verify ( (const unsigned char *)msg, cbMsg, sigShortR ) ) return false;

            EcdsaP256 vS;
            if ( !vS.ImportPublic ( pubShortS ) ) return false;
            if ( !vS.Verify ( (const unsigned char *)msg, cbMsg, sigShortS ) ) return false;
        }

        // --- ECDSA P-256: identity isolation --------------------------
        // Holding key A must not let you produce a signature that verifies
        // under key B. If this ever passes, peers can impersonate each other
        // and the login gate is worthless.
        {
            EcdsaP256 a, b;
            if ( !a.Generate() || !b.Generate() ) return false;

            unsigned char pubA[kEcdsaPubLen], pubB[kEcdsaPubLen];
            if ( !a.ExportPublic ( pubA ) || !b.ExportPublic ( pubB ) ) return false;
            if ( ConstTimeEqual ( pubA, pubB, kEcdsaPubLen ) ) return false;

            const char msg[] = "identity isolation";
            const size_t cbMsg = sizeof(msg) - 1;

            unsigned char sigA[kEcdsaSigLen];
            if ( !a.Sign ( (const unsigned char *)msg, cbMsg, sigA ) ) return false;

            EcdsaP256 vA, vB;
            if ( !vA.ImportPublic ( pubA ) || !vB.ImportPublic ( pubB ) ) return false;
            if ( !vA.Verify ( (const unsigned char *)msg, cbMsg, sigA ) ) return false;
            if (  vB.Verify ( (const unsigned char *)msg, cbMsg, sigA ) ) return false;  // must NOT

            unsigned char sigTmp[kEcdsaSigLen];
            if ( vA.Sign ( (const unsigned char *)msg, cbMsg, sigTmp ) ) return false;

            unsigned char blobA[kEcdsaPrivLen];
            if ( !a.ExportPrivate ( blobA ) ) return false;
            EcdsaP256 aClone;
            if ( !aClone.ImportPrivate ( blobA ) ) return false;
            unsigned char sigClone[kEcdsaSigLen];
            if ( !aClone.Sign ( (const unsigned char *)msg, cbMsg, sigClone ) ) return false;
            if ( !vA.Verify ( (const unsigned char *)msg, cbMsg, sigClone ) ) return false;
            OPENSSL_cleanse ( blobA, sizeof(blobA) );
        }

        return true;
    }

} // namespace p2pcng

#endif // !_WIN32
