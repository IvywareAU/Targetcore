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
//  P2PCngCrypto.cpp - implementation of the CNG (Windows BCrypt) primitives.
//  See P2PCngCrypto.h for the rationale. <bcrypt.h> is confined to this file.
//
#include "stdafx.h"
#include "P2PCngCrypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace p2pcng
{
    // BCrypt returns NTSTATUS (a LONG); success is >= 0. We keep our own
    // status variables typed as LONG so this translation unit never depends
    // on the NTSTATUS typedef being in scope.
    static inline bool ok ( LONG s ) { return s >= 0; }

    // -------------------------------------------------------------------
    //  CSPRNG
    // -------------------------------------------------------------------
    bool CngRandom ( void *pBuffer, unsigned long cbBuffer )
    {
        if ( !pBuffer && cbBuffer ) return false;
        return ok ( BCryptGenRandom ( nullptr, (PUCHAR)pBuffer, cbBuffer,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG ) );
    }

    // -------------------------------------------------------------------
    //  SHA-256
    // -------------------------------------------------------------------
    bool Sha256 ( const unsigned char *pData, size_t cbData,
                  unsigned char pHashOut[] )
    {
        if ( !pHashOut ) return false;

        BCRYPT_ALG_HANDLE  hAlg  = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool bOk = false;

        if ( !ok ( BCryptOpenAlgorithmProvider ( &hAlg, BCRYPT_SHA256_ALGORITHM,
                                                 nullptr, 0 ) ) )
            return false;
        if ( !ok ( BCryptCreateHash ( hAlg, &hHash, nullptr, 0, nullptr, 0, 0 ) ) )
            goto done;
        if ( cbData &&
             !ok ( BCryptHashData ( hHash, (PUCHAR)pData, (ULONG)cbData, 0 ) ) )
            goto done;
        if ( !ok ( BCryptFinishHash ( hHash, pHashOut, (ULONG)kSha256Len, 0 ) ) )
            goto done;
        bOk = true;

    done:
        if ( hHash ) BCryptDestroyHash ( hHash );
        if ( hAlg )  BCryptCloseAlgorithmProvider ( hAlg, 0 );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  HMAC-SHA256
    // -------------------------------------------------------------------
    bool HmacSha256 ( const unsigned char *pKey,  size_t cbKey,
                      const unsigned char *pData, size_t cbData,
                      unsigned char pMacOut[] )
    {
        BCRYPT_ALG_HANDLE  hAlg  = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool bOk = false;

        if ( !ok ( BCryptOpenAlgorithmProvider ( &hAlg, BCRYPT_SHA256_ALGORITHM,
                                                 nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG ) ) )
            return false;

        // pbHashObject == NULL lets CNG manage the object store (Win8.1+).
        if ( !ok ( BCryptCreateHash ( hAlg, &hHash, nullptr, 0,
                                      (PUCHAR)pKey, (ULONG)cbKey, 0 ) ) )
            goto done;
        if ( cbData &&
             !ok ( BCryptHashData ( hHash, (PUCHAR)pData, (ULONG)cbData, 0 ) ) )
            goto done;
        if ( !ok ( BCryptFinishHash ( hHash, pMacOut, (ULONG)kSha256Len, 0 ) ) )
            goto done;
        bOk = true;

    done:
        if ( hHash ) BCryptDestroyHash ( hHash );
        if ( hAlg )  BCryptCloseAlgorithmProvider ( hAlg, 0 );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  HKDF-SHA256 (RFC 5869)
    // -------------------------------------------------------------------
    bool HkdfSha256 ( const unsigned char *pIkm,  size_t cbIkm,
                      const unsigned char *pSalt, size_t cbSalt,
                      const unsigned char *pInfo, size_t cbInfo,
                      unsigned char *pOkm, size_t cbOkm )
    {
        // Extract: PRK = HMAC(salt, IKM); default salt is HashLen zero bytes.
        unsigned char zeroSalt[kSha256Len] = { 0 };
        const unsigned char *salt = ( pSalt && cbSalt ) ? pSalt : zeroSalt;
        size_t saltLen = ( pSalt && cbSalt ) ? cbSalt : sizeof(zeroSalt);

        unsigned char prk[kSha256Len];
        if ( !HmacSha256 ( salt, saltLen, pIkm, cbIkm, prk ) )
            return false;

        // Expand
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

        SecureZeroMemory ( prk, sizeof(prk) );
        SecureZeroMemory ( t,   sizeof(t) );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  Constant-time comparison
    // -------------------------------------------------------------------
    bool ConstTimeEqual ( const void *a, const void *b, size_t n )
    {
        const volatile unsigned char *pa = (const volatile unsigned char *)a;
        const volatile unsigned char *pb = (const volatile unsigned char *)b;
        unsigned char d = 0;
        for ( size_t i = 0; i < n; i++ )
            d = (unsigned char)( d | ( pa[i] ^ pb[i] ) );
        return d == 0;
    }

    // -------------------------------------------------------------------
    //  AES-256-GCM
    // -------------------------------------------------------------------
    AesGcm::AesGcm ( )
        : m_hAlg(nullptr), m_hKey(nullptr), m_pKeyObj(nullptr), m_cbKeyObj(0)
    { }

    AesGcm::~AesGcm ( )
    {
        if ( m_hKey )    BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey );
        if ( m_pKeyObj ) { SecureZeroMemory ( m_pKeyObj, m_cbKeyObj ); free ( m_pKeyObj ); }
        if ( m_hAlg )    BCryptCloseAlgorithmProvider ( (BCRYPT_ALG_HANDLE)m_hAlg, 0 );
    }

    bool AesGcm::SetKey ( const unsigned char *pKey, size_t cbKey )
    {
        if ( cbKey != kAesKeyLen || !pKey ) return false;

        // Drop any previous key material.
        if ( m_hKey ) { BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey ); m_hKey = nullptr; }
        if ( m_pKeyObj )
        {
            SecureZeroMemory ( m_pKeyObj, m_cbKeyObj );
            free ( m_pKeyObj ); m_pKeyObj = nullptr; m_cbKeyObj = 0;
        }

        BCRYPT_ALG_HANDLE hAlg = (BCRYPT_ALG_HANDLE)m_hAlg;
        if ( !hAlg )
        {
            if ( !ok ( BCryptOpenAlgorithmProvider ( &hAlg, BCRYPT_AES_ALGORITHM,
                                                     nullptr, 0 ) ) )
                return false;
            if ( !ok ( BCryptSetProperty ( hAlg, BCRYPT_CHAINING_MODE,
                                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0 ) ) )
            {
                BCryptCloseAlgorithmProvider ( hAlg, 0 );
                return false;
            }
            m_hAlg = hAlg;
        }

        DWORD cbObj = 0, cbData = 0;
        if ( !ok ( BCryptGetProperty ( hAlg, BCRYPT_OBJECT_LENGTH,
                                       (PUCHAR)&cbObj, sizeof(cbObj), &cbData, 0 ) ) )
            return false;

        m_pKeyObj = (unsigned char *)malloc ( cbObj );
        if ( !m_pKeyObj ) return false;
        m_cbKeyObj = cbObj;

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if ( !ok ( BCryptGenerateSymmetricKey ( hAlg, &hKey, m_pKeyObj, cbObj,
                                                (PUCHAR)pKey, (ULONG)cbKey, 0 ) ) )
        {
            SecureZeroMemory ( m_pKeyObj, m_cbKeyObj );
            free ( m_pKeyObj ); m_pKeyObj = nullptr; m_cbKeyObj = 0;
            return false;
        }
        m_hKey = hKey;
        return true;
    }

    bool AesGcm::Seal ( const unsigned char *pPlain, size_t cbPlain,
                        const unsigned char *pAad,   size_t cbAad,
                        unsigned char *pOut, size_t cbOutBuf, size_t *pcbOut )
    {
        if ( !m_hKey || !pOut ) return false;
        size_t need = SealedSize ( cbPlain );
        if ( cbOutBuf < need ) return false;

        unsigned char *pNonce  = pOut;
        unsigned char *pCipher = pOut + kGcmNonceLen;
        unsigned char *pTag    = pOut + kGcmNonceLen + cbPlain;

        if ( !CngRandom ( pNonce, (ULONG)kGcmNonceLen ) ) return false;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO ( info );
        info.pbNonce    = pNonce;              info.cbNonce    = (ULONG)kGcmNonceLen;
        info.pbAuthData = (PUCHAR)pAad;        info.cbAuthData = (ULONG)cbAad;
        info.pbTag      = pTag;                info.cbTag      = (ULONG)kGcmTagLen;

        ULONG cbResult = 0;
        LONG s = BCryptEncrypt ( (BCRYPT_KEY_HANDLE)m_hKey,
                                 (PUCHAR)pPlain, (ULONG)cbPlain,
                                 &info, nullptr, 0,
                                 pCipher, (ULONG)cbPlain, &cbResult, 0 );
        if ( !ok ( s ) ) return false;
        if ( pcbOut ) *pcbOut = need;
        return true;
    }

    bool AesGcm::Open ( const unsigned char *pIn, size_t cbIn,
                        const unsigned char *pAad, size_t cbAad,
                        unsigned char *pOut, size_t cbOutBuf, size_t *pcbOut )
    {
        if ( !m_hKey ) return false;
        if ( cbIn < kGcmNonceLen + kGcmTagLen ) return false;
        size_t cbCipher = cbIn - kGcmNonceLen - kGcmTagLen;
        if ( cbOutBuf < cbCipher ) return false;
        if ( cbCipher && !pOut )  return false;

        const unsigned char *pNonce  = pIn;
        const unsigned char *pCipher = pIn + kGcmNonceLen;
        const unsigned char *pTag    = pIn + kGcmNonceLen + cbCipher;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO ( info );
        info.pbNonce    = (PUCHAR)pNonce;      info.cbNonce    = (ULONG)kGcmNonceLen;
        info.pbAuthData = (PUCHAR)pAad;        info.cbAuthData = (ULONG)cbAad;
        info.pbTag      = (PUCHAR)pTag;        info.cbTag      = (ULONG)kGcmTagLen;

        ULONG cbResult = 0;
        LONG s = BCryptDecrypt ( (BCRYPT_KEY_HANDLE)m_hKey,
                                 (PUCHAR)pCipher, (ULONG)cbCipher,
                                 &info, nullptr, 0,
                                 pOut, (ULONG)cbCipher, &cbResult, 0 );
        if ( !ok ( s ) ) return false;         // includes tag-mismatch rejection
        if ( pcbOut ) *pcbOut = cbResult;
        return true;
    }

    // -------------------------------------------------------------------
    //  ECDH P-256
    // -------------------------------------------------------------------
    EcdhP256::EcdhP256 ( ) : m_hAlg(nullptr), m_hKey(nullptr), m_bPrivate(false) { }

    EcdhP256::~EcdhP256 ( )
    {
        if ( m_hKey ) BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey );
        if ( m_hAlg ) BCryptCloseAlgorithmProvider ( (BCRYPT_ALG_HANDLE)m_hAlg, 0 );
    }

    bool EcdhP256::Generate ( )
    {
        BCRYPT_ALG_HANDLE hAlg = (BCRYPT_ALG_HANDLE)m_hAlg;
        if ( !hAlg )
        {
            if ( !ok ( BCryptOpenAlgorithmProvider ( &hAlg, BCRYPT_ECDH_P256_ALGORITHM,
                                                     nullptr, 0 ) ) )
                return false;
            m_hAlg = hAlg;
        }
        if ( m_hKey ) { BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey ); m_hKey = nullptr; }

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if ( !ok ( BCryptGenerateKeyPair ( hAlg, &hKey, 256, 0 ) ) )
            return false;
        if ( !ok ( BCryptFinalizeKeyPair ( hKey, 0 ) ) )
        {
            BCryptDestroyKey ( hKey );
            return false;
        }
        m_hKey     = hKey;
        m_bPrivate = true;
        return true;
    }

    bool EcdhP256::ExportPublic ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut ) return false;
        // BCRYPT_ECCKEY_BLOB = { ULONG dwMagic; ULONG cbKey; } then X||Y.
        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdhPubLen ];
        ULONG cb = 0;
        if ( !ok ( BCryptExportKey ( (BCRYPT_KEY_HANDLE)m_hKey, nullptr,
                                     BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &cb, 0 ) ) )
            return false;
        if ( cb != sizeof(blob) ) return false;
        memcpy ( pOut, blob + sizeof(BCRYPT_ECCKEY_BLOB), kEcdhPubLen );
        return true;
    }

    bool EcdhP256::ExportPrivate ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut || !m_bPrivate ) return false;
        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdhPrivLen ];
        ULONG cb  = 0;
        bool  bOk = false;
        if ( ok ( BCryptExportKey ( (BCRYPT_KEY_HANDLE)m_hKey, nullptr,
                                    BCRYPT_ECCPRIVATE_BLOB, blob, sizeof(blob), &cb, 0 ) ) &&
             cb == sizeof(blob) )
        {
            memcpy ( pOut, blob + sizeof(BCRYPT_ECCKEY_BLOB), kEcdhPrivLen );
            bOk = true;
        }
        SecureZeroMemory ( blob, sizeof(blob) );   // private scalar was in here
        return bOk;
    }

    bool EcdhP256::ImportPrivate ( const unsigned char pIn[] )
    {
        if ( !pIn ) return false;
        BCRYPT_ALG_HANDLE hAlg = (BCRYPT_ALG_HANDLE)m_hAlg;
        if ( !hAlg )
        {
            if ( !ok ( BCryptOpenAlgorithmProvider ( &hAlg, BCRYPT_ECDH_P256_ALGORITHM,
                                                     nullptr, 0 ) ) )
                return false;
            m_hAlg = hAlg;
        }
        if ( m_hKey ) { BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey ); m_hKey = nullptr; }
        m_bPrivate = false;

        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdhPrivLen ];
        BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
        hdr->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        hdr->cbKey   = 32;                          // per-coordinate size
        memcpy ( blob + sizeof(BCRYPT_ECCKEY_BLOB), pIn, kEcdhPrivLen );

        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool bOk = ok ( BCryptImportKeyPair ( hAlg, nullptr,
                                              BCRYPT_ECCPRIVATE_BLOB, &hKey,
                                              blob, sizeof(blob), 0 ) );
        SecureZeroMemory ( blob, sizeof(blob) );
        if ( !bOk ) return false;
        m_hKey     = hKey;
        m_bPrivate = true;
        return true;
    }

    bool EcdhP256::ImportPublic ( const unsigned char pIn[] )
    {
        if ( !pIn ) return false;
        BCRYPT_ALG_HANDLE hAlg = (BCRYPT_ALG_HANDLE)m_hAlg;
        if ( !hAlg )
        {
            if ( !ok ( BCryptOpenAlgorithmProvider ( &hAlg, BCRYPT_ECDH_P256_ALGORITHM,
                                                     nullptr, 0 ) ) )
                return false;
            m_hAlg = hAlg;
        }
        if ( m_hKey ) { BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey ); m_hKey = nullptr; }
        m_bPrivate = false;      // a directory entry, not a key we can agree with

        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdhPubLen ];
        BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
        hdr->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        hdr->cbKey   = 32;
        memcpy ( blob + sizeof(BCRYPT_ECCKEY_BLOB), pIn, kEcdhPubLen );

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if ( !ok ( BCryptImportKeyPair ( hAlg, nullptr,
                                         BCRYPT_ECCPUBLIC_BLOB, &hKey,
                                         blob, sizeof(blob), 0 ) ) )
            return false;                  // not a point on P-256
        m_hKey = hKey;
        return true;
    }

    bool EcdhP256::DeriveRawSecret ( const unsigned char pPeerPub[],
                                     unsigned char pSecretOut[] )
    {
        //  !m_bPrivate is the important one: BCryptSecretAgreement given a
        //  public-only handle as the private party takes the process down
        //  rather than returning an error.
        if ( !m_hKey || !m_hAlg || !m_bPrivate || !pPeerPub || !pSecretOut )
            return false;

        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdhPubLen ];
        BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
        hdr->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        hdr->cbKey   = (ULONG)kEcdhSecLen;
        memcpy ( blob + sizeof(BCRYPT_ECCKEY_BLOB), pPeerPub, kEcdhPubLen );

        BCRYPT_KEY_HANDLE    hPeer   = nullptr;
        BCRYPT_SECRET_HANDLE hSecret = nullptr;
        bool bOk = false;

        if ( !ok ( BCryptImportKeyPair ( (BCRYPT_ALG_HANDLE)m_hAlg, nullptr,
                                         BCRYPT_ECCPUBLIC_BLOB, &hPeer,
                                         blob, sizeof(blob), 0 ) ) )
            goto done;
        if ( !ok ( BCryptSecretAgreement ( (BCRYPT_KEY_HANDLE)m_hKey, hPeer,
                                           &hSecret, 0 ) ) )
            goto done;
        {
            // Raw secret is the P-256 X coordinate (returned little-endian by
            // CNG). Both peers obtain identical bytes, so it is a valid IKM for
            // HKDF; never use it directly as a key.
            ULONG cb = 0;
            if ( !ok ( BCryptDeriveKey ( hSecret, BCRYPT_KDF_RAW_SECRET, nullptr,
                                         pSecretOut, (ULONG)kEcdhSecLen, &cb, 0 ) ) ||
                 cb != kEcdhSecLen )
                goto done;
        }
        bOk = true;

    done:
        if ( hSecret ) BCryptDestroySecret ( hSecret );
        if ( hPeer )   BCryptDestroyKey ( hPeer );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  ECDSA P-256 identity
    // -------------------------------------------------------------------
    EcdsaP256::EcdsaP256 ( ) : m_hAlg(nullptr), m_hKey(nullptr) { }

    EcdsaP256::~EcdsaP256 ( )
    {
        if ( m_hKey ) BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey );
        if ( m_hAlg ) BCryptCloseAlgorithmProvider ( (BCRYPT_ALG_HANDLE)m_hAlg, 0 );
    }

    bool EcdsaP256::EnsureAlg ( )
    {
        if ( m_hAlg ) return true;
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if ( !ok ( BCryptOpenAlgorithmProvider ( &hAlg, BCRYPT_ECDSA_P256_ALGORITHM,
                                                 nullptr, 0 ) ) )
            return false;
        m_hAlg = hAlg;
        return true;
    }

    bool EcdsaP256::Generate ( )
    {
        if ( !EnsureAlg() ) return false;
        if ( m_hKey ) { BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey ); m_hKey = nullptr; }

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if ( !ok ( BCryptGenerateKeyPair ( (BCRYPT_ALG_HANDLE)m_hAlg, &hKey, 256, 0 ) ) )
            return false;
        if ( !ok ( BCryptFinalizeKeyPair ( hKey, 0 ) ) )
        {
            BCryptDestroyKey ( hKey );
            return false;
        }
        m_hKey = hKey;
        return true;
    }

    bool EcdsaP256::ExportPublic ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut ) return false;
        // BCRYPT_ECCKEY_BLOB = { ULONG dwMagic; ULONG cbKey; } then X||Y.
        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdsaPubLen ];
        ULONG cb = 0;
        if ( !ok ( BCryptExportKey ( (BCRYPT_KEY_HANDLE)m_hKey, nullptr,
                                     BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &cb, 0 ) ) )
            return false;
        if ( cb != sizeof(blob) ) return false;
        memcpy ( pOut, blob + sizeof(BCRYPT_ECCKEY_BLOB), kEcdsaPubLen );
        return true;
    }

    bool EcdsaP256::ExportPrivate ( unsigned char pOut[] )
    {
        if ( !m_hKey || !pOut ) return false;
        // BCRYPT_ECCPRIVATE_BLOB = header then X||Y||d.
        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdsaPrivLen ];
        ULONG cb   = 0;
        bool  bOk  = false;
        if ( ok ( BCryptExportKey ( (BCRYPT_KEY_HANDLE)m_hKey, nullptr,
                                    BCRYPT_ECCPRIVATE_BLOB, blob, sizeof(blob), &cb, 0 ) ) &&
             cb == sizeof(blob) )
        {
            memcpy ( pOut, blob + sizeof(BCRYPT_ECCKEY_BLOB), kEcdsaPrivLen );
            bOk = true;
        }
        SecureZeroMemory ( blob, sizeof(blob) );   // private scalar was in here
        return bOk;
    }

    bool EcdsaP256::ImportPrivate ( const unsigned char pIn[] )
    {
        if ( !pIn || !EnsureAlg() ) return false;
        if ( m_hKey ) { BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey ); m_hKey = nullptr; }

        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdsaPrivLen ];
        BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
        hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        hdr->cbKey   = 32;                          // per-coordinate size
        memcpy ( blob + sizeof(BCRYPT_ECCKEY_BLOB), pIn, kEcdsaPrivLen );

        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool bOk = ok ( BCryptImportKeyPair ( (BCRYPT_ALG_HANDLE)m_hAlg, nullptr,
                                              BCRYPT_ECCPRIVATE_BLOB, &hKey,
                                              blob, sizeof(blob), 0 ) );
        SecureZeroMemory ( blob, sizeof(blob) );
        if ( !bOk ) return false;
        m_hKey = hKey;
        return true;
    }

    bool EcdsaP256::ImportPublic ( const unsigned char pIn[] )
    {
        if ( !pIn || !EnsureAlg() ) return false;
        if ( m_hKey ) { BCryptDestroyKey ( (BCRYPT_KEY_HANDLE)m_hKey ); m_hKey = nullptr; }

        unsigned char blob[ sizeof(BCRYPT_ECCKEY_BLOB) + kEcdsaPubLen ];
        BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
        hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        hdr->cbKey   = 32;
        memcpy ( blob + sizeof(BCRYPT_ECCKEY_BLOB), pIn, kEcdsaPubLen );

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if ( !ok ( BCryptImportKeyPair ( (BCRYPT_ALG_HANDLE)m_hAlg, nullptr,
                                         BCRYPT_ECCPUBLIC_BLOB, &hKey,
                                         blob, sizeof(blob), 0 ) ) )
            return false;
        m_hKey = hKey;
        return true;
    }

    bool EcdsaP256::Sign ( const unsigned char *pData, size_t cbData,
                           unsigned char pSigOut[] )
    {
        if ( !m_hKey || !pSigOut ) return false;

        unsigned char hash[kSha256Len];
        if ( !Sha256 ( pData, cbData, hash ) ) return false;

        // ECDSA takes no padding info. CNG emits the raw r||s pair, which is
        // what goes on the wire - no DER anywhere in this codebase.
        ULONG cb = 0;
        bool bOk = ok ( BCryptSignHash ( (BCRYPT_KEY_HANDLE)m_hKey, nullptr,
                                         hash, (ULONG)kSha256Len,
                                         pSigOut, (ULONG)kEcdsaSigLen, &cb, 0 ) ) &&
                   cb == kEcdsaSigLen;
        SecureZeroMemory ( hash, sizeof(hash) );
        return bOk;
    }

    bool EcdsaP256::Verify ( const unsigned char *pData, size_t cbData,
                             const unsigned char pSig[] )
    {
        if ( !m_hKey || !pSig ) return false;

        unsigned char hash[kSha256Len];
        if ( !Sha256 ( pData, cbData, hash ) ) return false;

        bool bOk = ok ( BCryptVerifySignature ( (BCRYPT_KEY_HANDLE)m_hKey, nullptr,
                                                hash, (ULONG)kSha256Len,
                                                (PUCHAR)pSig, (ULONG)kEcdsaSigLen, 0 ) );
        SecureZeroMemory ( hash, sizeof(hash) );
        return bOk;
    }

    // -------------------------------------------------------------------
    //  Self-test (known-answer + round-trip)
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

            const char    msg[]  = "Targetcore secure channel self-test payload";
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

            // Tamper: flip one ciphertext byte -> Open must fail.
            std::vector<unsigned char> bad = sealed;
            bad[kGcmNonceLen] ^= 0x01;
            if ( cipher.Open ( bad.data(), bad.size(), aad, sizeof(aad),
                               opened.data(), opened.size(), &cbOpened ) )
                return false;   // must NOT succeed
            // Tamper: alter AAD -> Open must fail.
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

            // Two independent agreements must differ (sanity vs. constant output).
            EcdhP256 c;
            if ( !c.Generate() ) return false;
            unsigned char pc[kEcdhPubLen], sc[kEcdhSecLen];
            if ( !c.ExportPublic ( pc ) ) return false;
            if ( !a.DeriveRawSecret ( pc, sc ) ) return false;
            if ( ConstTimeEqual ( sa, sc, kEcdhSecLen ) ) return false;   // must differ
        }

        // --- ECDSA P-256: fixed cross-implementation vector -----------
        // Generated with OpenSSL 3 and verified there before being pinned
        // here, so a green run proves CNG agrees with an INDEPENDENT
        // implementation on the wire encoding - raw X||Y public point and raw
        // r||s signature, both big-endian, no DER. That encoding contract is
        // the thing most likely to drift; the ECDSA maths is the OS's problem.
        //
        // Reproduce with:
        //   printf 'Targetcore identity KAT' > msg.bin
        //   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
        //   openssl dgst -sha256 -sign key.pem -out sig.der msg.bin
        //   openssl ec -in key.pem -text -noout          # pub point, priv scalar
        // then strip the 0x04 prefix from the point and convert the DER
        // SEQUENCE{INTEGER r, INTEGER s} to fixed-width 32-byte r||s.
        {
            const char msg[] = "Targetcore identity KAT";
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

            // 1. The reference signature must verify under the reference key.
            EcdsaP256 v;
            if ( !v.ImportPublic ( pub ) ) return false;
            if ( !v.Verify ( (const unsigned char *)msg, cbMsg, sig ) ) return false;

            // 2. A one-character change in the message must NOT verify.
            const char msgBad[] = "Targetcore identity KAU";
            if ( v.Verify ( (const unsigned char *)msgBad, sizeof(msgBad) - 1, sig ) )
                return false;

            // 3. A one-bit change in the signature must NOT verify.
            unsigned char sigBad[kEcdsaSigLen];
            memcpy ( sigBad, sig, sizeof(sigBad) );
            sigBad[0] ^= 0x01;
            if ( v.Verify ( (const unsigned char *)msg, cbMsg, sigBad ) ) return false;

            // 4. The same key imported as a PRIVATE blob (X||Y||d) must yield
            //    the identical public point - proves ImportPrivate/ExportPublic
            //    round-trip against externally generated key material, and that
            //    the on-disk identity format is what we think it is.
            unsigned char privBlob[kEcdsaPrivLen];
            memcpy ( privBlob,      pub,    kEcdsaPubLen );
            memcpy ( privBlob + 64, priv_d, sizeof(priv_d) );

            EcdsaP256 s;
            if ( !s.ImportPrivate ( privBlob ) ) return false;
            unsigned char pubRT[kEcdsaPubLen];
            if ( !s.ExportPublic ( pubRT ) ) return false;
            if ( !ConstTimeEqual ( pubRT, pub, kEcdsaPubLen ) ) return false;

            // 5. And a signature it produces must verify under the public key.
            unsigned char sigRT[kEcdsaSigLen];
            if ( !s.Sign ( (const unsigned char *)msg, cbMsg, sigRT ) ) return false;
            if ( !v.Verify ( (const unsigned char *)msg, cbMsg, sigRT ) ) return false;

            // 6. A corrupted identity file - public half not matching the
            //    scalar - must be REJECTED, not loaded as a key that signs as
            //    somebody else. CNG enforces this inside BCryptImportKeyPair;
            //    the OpenSSL backend needs an explicit pairwise check, so this
            //    case is what keeps the two honest with each other.
            unsigned char privBad[kEcdsaPrivLen];
            memcpy ( privBad, privBlob, sizeof(privBad) );
            privBad[0] ^= 0x01;
            EcdsaP256 bad;
            if ( bad.ImportPrivate ( privBad ) ) return false;   // must NOT load

            SecureZeroMemory ( privBlob, sizeof(privBlob) );
        }

        // --- ECDSA P-256: short r / short s, from the OpenSSL BACKEND --
        // Produced by P2PCngCrypto_openssl.cpp's own Sign() on Linux (not by
        // the openssl CLI), then pinned here so CNG must verify signatures the
        // other backend actually emits. This is the wire contract in the
        // direction that matters.
        //
        // These two shapes are what break a naive DER->raw conversion.
        // OpenSSL signs into DER, where INTEGERs are minimal-length: a leading
        // zero byte in r or s makes that INTEGER shorter than 32 bytes, and
        // BN_bn2bin would emit a short buffer, silently shifting the 64-byte
        // raw layout. BN_bn2binpad is what prevents it. sigShortR carries TWO
        // leading zeros.
        //
        // Roughly 1 signature in 128 has this shape, so getting it wrong
        // yields a backend disagreement that appears intermittently, depends
        // on the random k, and would be miserable to diagnose in the field.
        {
            const char msg[] = "Targetcore identity KAT";
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
        // The property the whole identity design rests on: holding key A does
        // not let you produce a signature that verifies under key B. If this
        // check ever passes, peers can impersonate each other and the login
        // gate is worthless.
        {
            EcdsaP256 a, b;
            if ( !a.Generate() || !b.Generate() ) return false;

            unsigned char pubA[kEcdsaPubLen], pubB[kEcdsaPubLen];
            if ( !a.ExportPublic ( pubA ) || !b.ExportPublic ( pubB ) ) return false;
            if ( ConstTimeEqual ( pubA, pubB, kEcdsaPubLen ) ) return false;  // distinct keys

            const char msg[] = "identity isolation";
            const size_t cbMsg = sizeof(msg) - 1;

            unsigned char sigA[kEcdsaSigLen];
            if ( !a.Sign ( (const unsigned char *)msg, cbMsg, sigA ) ) return false;

            EcdsaP256 vA, vB;
            if ( !vA.ImportPublic ( pubA ) || !vB.ImportPublic ( pubB ) ) return false;
            if ( !vA.Verify ( (const unsigned char *)msg, cbMsg, sigA ) ) return false;
            if (  vB.Verify ( (const unsigned char *)msg, cbMsg, sigA ) ) return false;  // must NOT

            // A verify-only key cannot sign.
            unsigned char sigTmp[kEcdsaSigLen];
            if ( vA.Sign ( (const unsigned char *)msg, cbMsg, sigTmp ) ) return false;

            // Private blob round-trip preserves signing identity.
            unsigned char blobA[kEcdsaPrivLen];
            if ( !a.ExportPrivate ( blobA ) ) return false;
            EcdsaP256 aClone;
            if ( !aClone.ImportPrivate ( blobA ) ) return false;
            unsigned char sigClone[kEcdsaSigLen];
            if ( !aClone.Sign ( (const unsigned char *)msg, cbMsg, sigClone ) ) return false;
            if ( !vA.Verify ( (const unsigned char *)msg, cbMsg, sigClone ) ) return false;
            SecureZeroMemory ( blobA, sizeof(blobA) );
        }

        return true;
    }

} // namespace p2pcng
