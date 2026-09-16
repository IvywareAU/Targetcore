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
//  P2PIdentityStore.cpp - implementation of the identity storage layer.
//  See P2PIdentityStore.h for the format and the threat boundary.
//
//  One TU for both platforms, unlike the p2pcng primitives (CNG vs OpenSSL
//  backends in separate files): the container format, the atomic-write dance,
//  the text parsing and every validation rule here are platform-independent,
//  and duplicating them into two files would be duplicating exactly the parts
//  that must not drift apart. Only three things differ per platform - protect,
//  unprotect, and how a file is created with restrictive permissions - and each
//  is isolated below.
//
//  Deliberately does NOT include stdafx.h. It needs no MFC and no Platform
//  shim, which is what lets the Linux crypto_kat target compile it standalone
//  next to the OpenSSL backend TU. The vcxproj marks it PrecompiledHeader
//  NotUsing for the same reason.
//
#include "stdafx.h"
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <wincrypt.h>
#  include <dpapi.h>
#  include <sddl.h>
#  pragma comment(lib, "crypt32.lib")     // CryptProtectData / CryptUnprotectData
#  pragma comment(lib, "advapi32.lib")    // ConvertStringSecurityDescriptorToSecurityDescriptorW
#else
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <cerrno>
#endif

#include "P2PIdentityStore.h"

#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <ctime>

namespace p2pcng
{
namespace
{
    // -------------------------------------------------------------------
    //  Container constants
    // -------------------------------------------------------------------
    // Which of the two P-256 keys a container holds. Both blobs are 96 bytes of
    // X||Y||d, so nothing about the payload distinguishes them - the container
    // has to, or a renamed file silently crosses a signing key with an agreement
    // key. See the header.
    enum KeyKind { KindIdentity = 0, KindAgreement = 1 };

    const unsigned char kMagic[8]      = { 'P','2','P','I','D','K','Y', 0x1A };
    const unsigned char kMagicAgree[8] = { 'P','2','P','A','G','K','Y', 0x1A };
    const unsigned int  kVersion      = 1;
    const size_t        kMaxPayload   = 64u * 1024u;    // a DPAPI blob over 96
                                                        // bytes is ~300; this is
                                                        // slack, not a budget
    const size_t        kMaxTextFile  = 4u * 1024u * 1024u;
    const size_t        kMaxLine      = 4096;

    const unsigned char *MagicOf ( KeyKind eKind )
    {
        return eKind == KindAgreement ? kMagicAgree : kMagic;
    }

#ifdef _WIN32
    // DPAPI optional entropy. Binds the blob to this application. NOT a secret -
    // see the header. Byte values are fixed here so a future build cannot
    // silently change them and orphan every deployed identity file.
    //
    // Windows-only: POSIX protects the file with its mode, not with a blob, so
    // off Windows these are dead weight and gcc rightly says so.
    const char kEntropy[]      = "Targetcore.identity.v1";
    const char kEntropyAgree[] = "Targetcore.agreement.v1";

    // Returns the entropy bytes and, through pcb, their length. Separate values
    // per kind so the DPAPI layer refuses the swap too, not only the header.
    const char *EntropyOf ( KeyKind eKind, size_t *pcb )
    {
        if ( eKind == KindAgreement )
        {
            *pcb = sizeof(kEntropyAgree) - 1;
            return kEntropyAgree;
        }
        *pcb = sizeof(kEntropy) - 1;
        return kEntropy;
    }
#endif

    // -------------------------------------------------------------------
    //  Small helpers
    // -------------------------------------------------------------------
    void ZeroMem ( void *pMem, size_t cbMem )
    {
        // Not SecureZeroMemory: this TU compiles on Linux too. A volatile
        // pointer is the portable form the optimiser may not elide.
        volatile unsigned char *p = (volatile unsigned char *)pMem;
        while ( cbMem-- ) *p++ = 0;
    }

    void ZeroVec ( std::vector<unsigned char> &v )
    {
        if ( !v.empty() ) ZeroMem ( &v[0], v.size() );
    }

    void PutU16 ( unsigned char *p, unsigned int v )
    {
        p[0] = (unsigned char)( v        & 0xFF );
        p[1] = (unsigned char)( (v >> 8) & 0xFF );
    }

    unsigned int GetU16 ( const unsigned char *p )
    {
        return (unsigned int)p[0] | ( (unsigned int)p[1] << 8 );
    }

    void PutU32 ( unsigned char *p, unsigned long v )
    {
        p[0] = (unsigned char)( v         & 0xFF );
        p[1] = (unsigned char)( (v >>  8) & 0xFF );
        p[2] = (unsigned char)( (v >> 16) & 0xFF );
        p[3] = (unsigned char)( (v >> 24) & 0xFF );
    }

    unsigned long GetU32 ( const unsigned char *p )
    {
        return (unsigned long)p[0]         | ( (unsigned long)p[1] <<  8 ) |
             ( (unsigned long)p[2] << 16 ) | ( (unsigned long)p[3] << 24 );
    }

    bool HexEncode ( const unsigned char *pIn, size_t cbIn, std::string &sOut )
    {
        static const char *pszDigits = "0123456789abcdef";
        if ( !pIn ) return false;
        sOut.clear();
        sOut.reserve ( cbIn * 2 );
        for ( size_t i = 0; i < cbIn; i++ )
        {
            sOut.push_back ( pszDigits[ pIn[i] >> 4  ] );
            sOut.push_back ( pszDigits[ pIn[i] & 0x0F] );
        }
        return true;
    }

    int HexNibble ( char c )
    {
        if ( c >= '0' && c <= '9' ) return c - '0';
        if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
        if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
        return -1;
    }

    // Exactly cbOut bytes from exactly cbOut*2 hex chars. A short or long token
    // is a format error, never a partial decode.
    bool HexDecodeExact ( const char *pszHex, size_t cchHex,
                          unsigned char *pOut, size_t cbOut )
    {
        if ( !pszHex || !pOut || cchHex != cbOut * 2 ) return false;
        for ( size_t i = 0; i < cbOut; i++ )
        {
            int hi = HexNibble ( pszHex[i * 2] );
            int lo = HexNibble ( pszHex[i * 2 + 1] );
            if ( hi < 0 || lo < 0 ) return false;
            pOut[i] = (unsigned char)( ( hi << 4 ) | lo );
        }
        return true;
    }

    bool IsSpace ( char c )
    { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'; }

    // Epoch seconds, decimal, non-negative, no sign and no leading '+'. Written
    // by AppendRevocationList and read back by LoadRevocationList.
    //
    // Decimal rather than ISO-8601 deliberately: an ISO parser needs a
    // timegm/_mkgmtime split across the two platforms and a decision about what
    // a missing 'Z' means, all to validate a field that is never compared to a
    // clock (P2PIdentityStore.h, "revocation is absolute"). The readable form of
    // the date is written into the same line's comment instead, which is where
    // the fingerprint already goes.
    bool ParseEpoch ( const char *psz, size_t cch, long long *pllOut )
    {
        if ( !psz || !pllOut || cch == 0 || cch > 19 ) return false;
        long long ll = 0;
        for ( size_t i = 0; i < cch; i++ )
        {
            if ( psz[i] < '0' || psz[i] > '9' ) return false;
            ll = ll * 10 + ( psz[i] - '0' );
        }
        *pllOut = ll;
        return true;
    }

    // -------------------------------------------------------------------
    //  Platform: file I/O
    //
    //  bSecret selects the private-key treatment: a restrictive ACL / mode
    //  0600 on write, and a refusal to read a group- or world-accessible file
    //  on POSIX.
    // -------------------------------------------------------------------
#ifdef _WIN32

    bool Widen ( const char *pszUtf8, std::wstring &wOut )
    {
        if ( !pszUtf8 || !*pszUtf8 ) return false;
        int n = MultiByteToWideChar ( CP_UTF8, MB_ERR_INVALID_CHARS, pszUtf8, -1,
                                      nullptr, 0 );
        if ( n <= 1 ) return false;                 // n counts the NUL
        wOut.assign ( (size_t)n, L'\0' );           // room for the NUL...
        if ( MultiByteToWideChar ( CP_UTF8, MB_ERR_INVALID_CHARS, pszUtf8, -1,
                                   &wOut[0], n ) != n )
            return false;
        wOut.resize ( (size_t)n - 1 );              // ...which std::wstring keeps
        return true;                                //    for itself
    }

    IdResult ReadWholeFile ( const char *pszPathUtf8, std::vector<unsigned char> &vOut,
                             bool /*bSecret*/, size_t cbMax )
    {
        std::wstring wPath;
        if ( !Widen ( pszPathUtf8, wPath ) ) return IdErrArgs;

        HANDLE hFile = CreateFileW ( wPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                     nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                     nullptr );
        if ( hFile == INVALID_HANDLE_VALUE )
        {
            DWORD dwErr = GetLastError();
            return ( dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND )
                   ? IdErrNotFound : IdErrIo;
        }

        // No POSIX-style mode check here: on Windows the file's protection is
        // the DACL written at creation (below) plus DPAPI, and a DACL is not
        // reducible to a mode word worth testing.
        LARGE_INTEGER liSize;
        if ( !GetFileSizeEx ( hFile, &liSize ) )
        {
            CloseHandle ( hFile );
            return IdErrIo;
        }
        if ( liSize.QuadPart < 0 || (unsigned long long)liSize.QuadPart > cbMax )
        {
            CloseHandle ( hFile );
            return IdErrFormat;
        }

        vOut.assign ( (size_t)liSize.QuadPart, 0 );
        size_t cbDone = 0;
        bool   bOk    = true;
        while ( cbDone < vOut.size() )
        {
            DWORD cbRead = 0;
            DWORD cbWant = (DWORD)( vOut.size() - cbDone );
            if ( !ReadFile ( hFile, &vOut[cbDone], cbWant, &cbRead, nullptr ) ||
                 cbRead == 0 )
                { bOk = false; break; }
            cbDone += cbRead;
        }
        CloseHandle ( hFile );
        if ( !bOk ) { ZeroVec ( vOut ); vOut.clear(); return IdErrIo; }
        return IdOk;
    }

    // Creates the temp file with an explicit DACL when bSecret: SYSTEM,
    // Administrators and the owner, protected from inheritance. This is the
    // Windows counterpart of 0600, and it matters MORE here than on POSIX
    // precisely because machine-scope DPAPI does not restrict local readers -
    // the ACL is what keeps an ordinary local account away from the blob.
    IdResult WriteWholeFile ( const char *pszPathUtf8, const unsigned char *pData,
                              size_t cbData, bool bSecret, bool bExclusive )
    {
        std::wstring wPath;
        if ( !Widen ( pszPathUtf8, wPath ) ) return IdErrArgs;

        wchar_t szSuffix[32];
        swprintf ( szSuffix, 32, L".%lu.tmp", (unsigned long)GetCurrentProcessId() );
        std::wstring wTemp = wPath + szSuffix;

        SECURITY_ATTRIBUTES  sa;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        LPSECURITY_ATTRIBUTES pSA = nullptr;
        if ( bSecret )
        {
            //  D:P            DACL, protected (no inherited ACEs)
            //  (A;;FA;;;SY)   LocalSystem      - full
            //  (A;;FA;;;BA)   Administrators   - full (they can take ownership
            //                                    regardless; denying is theatre)
            //  (A;;FA;;;OW)   Owner Rights     - full, so the creating account
            //                                    can still read its own key
            if ( !ConvertStringSecurityDescriptorToSecurityDescriptorW (
                     L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)",
                     SDDL_REVISION_1, &pSD, nullptr ) )
                return IdErrIo;                 // fail closed: no ACL, no key file
            sa.nLength              = sizeof(sa);
            sa.lpSecurityDescriptor = pSD;
            sa.bInheritHandle       = FALSE;
            pSA = &sa;
        }

        // CREATE_NEW, not CREATE_ALWAYS: a security descriptor passed to
        // CreateFile is applied only when the file is actually created, so
        // reusing a stale temp file would silently inherit the directory's ACL.
        DeleteFileW ( wTemp.c_str() );
        HANDLE hFile = CreateFileW ( wTemp.c_str(), GENERIC_WRITE, 0, pSA,
                                     CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr );
        if ( pSD ) LocalFree ( pSD );
        if ( hFile == INVALID_HANDLE_VALUE ) return IdErrIo;

        bool   bOk    = true;
        size_t cbDone = 0;
        while ( cbDone < cbData )
        {
            DWORD cbWrote = 0;
            DWORD cbWant  = (DWORD)( cbData - cbDone );
            if ( !WriteFile ( hFile, pData + cbDone, cbWant, &cbWrote, nullptr ) ||
                 cbWrote == 0 )
                { bOk = false; break; }
            cbDone += cbWrote;
        }
        if ( bOk ) bOk = ( FlushFileBuffers ( hFile ) != FALSE );
        CloseHandle ( hFile );

        if ( !bOk )
        {
            DeleteFileW ( wTemp.c_str() );
            return IdErrIo;
        }

        // Without MOVEFILE_REPLACE_EXISTING the move IS the exclusive create,
        // and it is atomic - there is no check-then-act window for a second
        // process to slip through.
        DWORD dwFlags = MOVEFILE_WRITE_THROUGH |
                        ( bExclusive ? 0 : MOVEFILE_REPLACE_EXISTING );
        if ( !MoveFileExW ( wTemp.c_str(), wPath.c_str(), dwFlags ) )
        {
            DWORD dwErr = GetLastError();
            DeleteFileW ( wTemp.c_str() );
            if ( bExclusive &&
                 ( dwErr == ERROR_ALREADY_EXISTS || dwErr == ERROR_FILE_EXISTS ) )
                return IdErrExists;
            return IdErrIo;
        }
        return IdOk;
    }

    bool FileExists ( const char *pszPathUtf8 )
    {
        std::wstring wPath;
        if ( !Widen ( pszPathUtf8, wPath ) ) return false;
        return GetFileAttributesW ( wPath.c_str() ) != INVALID_FILE_ATTRIBUTES;
    }

    void DeleteOneFile ( const char *pszPathUtf8 )
    {
        std::wstring wPath;
        if ( Widen ( pszPathUtf8, wPath ) ) DeleteFileW ( wPath.c_str() );
    }

#else   // ---- POSIX ----------------------------------------------------

    IdResult ReadWholeFile ( const char *pszPathUtf8, std::vector<unsigned char> &vOut,
                             bool bSecret, size_t cbMax )
    {
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return IdErrArgs;

        int fd = ::open ( pszPathUtf8, O_RDONLY | O_CLOEXEC );
        if ( fd < 0 )
            return ( errno == ENOENT || errno == ENOTDIR ) ? IdErrNotFound : IdErrIo;

        struct stat st;
        if ( ::fstat ( fd, &st ) != 0 ) { ::close ( fd ); return IdErrIo; }

        // ssh's rule, and for ssh's reason: a private key readable by the group
        // or the world is not a private key, and tolerating it once means
        // tolerating it forever.
        if ( bSecret && ( st.st_mode & ( S_IRWXG | S_IRWXO ) ) != 0 )
        {
            ::close ( fd );
            return IdErrPerms;
        }
        if ( !S_ISREG ( st.st_mode ) )   { ::close ( fd ); return IdErrFormat; }
        if ( (unsigned long long)st.st_size > cbMax )
                                         { ::close ( fd ); return IdErrFormat; }

        vOut.assign ( (size_t)st.st_size, 0 );
        size_t cbDone = 0;
        bool   bOk    = true;
        while ( cbDone < vOut.size() )
        {
            ssize_t n = ::read ( fd, &vOut[cbDone], vOut.size() - cbDone );
            if ( n < 0 ) { if ( errno == EINTR ) continue; bOk = false; break; }
            if ( n == 0 ) { bOk = false; break; }
            cbDone += (size_t)n;
        }
        ::close ( fd );
        if ( !bOk ) { ZeroVec ( vOut ); vOut.clear(); return IdErrIo; }
        return IdOk;
    }

    void FsyncDirOf ( const std::string &sPath )
    {
        // The rename is only durable once the DIRECTORY entry is on disk.
        std::string sDir = sPath;
        size_t iSlash = sDir.find_last_of ( '/' );
        if ( iSlash == std::string::npos ) sDir = ".";
        else if ( iSlash == 0 )            sDir = "/";
        else                               sDir.erase ( iSlash );
        int fd = ::open ( sDir.c_str(), O_RDONLY | O_CLOEXEC );
        if ( fd >= 0 ) { ::fsync ( fd ); ::close ( fd ); }
    }

    IdResult WriteWholeFile ( const char *pszPathUtf8, const unsigned char *pData,
                              size_t cbData, bool bSecret, bool bExclusive )
    {
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return IdErrArgs;

        std::string sPath = pszPathUtf8;
        char szSuffix[32];
        std::snprintf ( szSuffix, sizeof(szSuffix), ".%ld.tmp", (long)::getpid() );
        std::string sTemp = sPath + szSuffix;

        ::unlink ( sTemp.c_str() );
        // O_EXCL so a symlink planted at the temp path cannot redirect the
        // write; the mode is applied at creation, before a byte is written.
        int fd = ::open ( sTemp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                          bSecret ? 0600 : 0644 );
        if ( fd < 0 ) return IdErrIo;

        bool   bOk    = true;
        size_t cbDone = 0;
        while ( cbDone < cbData )
        {
            ssize_t n = ::write ( fd, pData + cbDone, cbData - cbDone );
            if ( n < 0 ) { if ( errno == EINTR ) continue; bOk = false; break; }
            cbDone += (size_t)n;
        }
        if ( bOk ) bOk = ( ::fsync ( fd ) == 0 );
        ::close ( fd );

        if ( !bOk ) { ::unlink ( sTemp.c_str() ); return IdErrIo; }

        if ( bExclusive )
        {
            // rename() would silently replace. link() is the atomic
            // create-if-absent: it fails EEXIST rather than clobbering a key
            // another process just wrote.
            if ( ::link ( sTemp.c_str(), sPath.c_str() ) != 0 )
            {
                int nErr = errno;
                ::unlink ( sTemp.c_str() );
                return ( nErr == EEXIST ) ? IdErrExists : IdErrIo;
            }
            ::unlink ( sTemp.c_str() );
        }
        else if ( ::rename ( sTemp.c_str(), sPath.c_str() ) != 0 )
        {
            ::unlink ( sTemp.c_str() );
            return IdErrIo;
        }

        FsyncDirOf ( sPath );
        return IdOk;
    }

    bool FileExists ( const char *pszPathUtf8 )
    {
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return false;
        struct stat st;
        return ::stat ( pszPathUtf8, &st ) == 0;
    }

    void DeleteOneFile ( const char *pszPathUtf8 )
    {
        if ( pszPathUtf8 && *pszPathUtf8 ) ::unlink ( pszPathUtf8 );
    }

#endif  // _WIN32

    // -------------------------------------------------------------------
    //  Platform: protect / unprotect
    // -------------------------------------------------------------------
    IdProtection ResolveProtection ( IdProtection eProtect )
    {
        if ( eProtect != IdProtect_Default ) return eProtect;
#ifdef _WIN32
        return IdProtect_DpapiMachine;
#else
        return IdProtect_None;              // the 0600 mode is the protection
#endif
    }

    IdResult ProtectPayload ( IdProtection eProtect, KeyKind eKind,
                              const unsigned char *pIn, size_t cbIn,
                              std::vector<unsigned char> &vOut )
    {
        if ( eProtect == IdProtect_None )
        {
            vOut.assign ( pIn, pIn + cbIn );
            return IdOk;
        }
#ifdef _WIN32
        size_t      cbEnt = 0;
        const char *pEnt  = EntropyOf ( eKind, &cbEnt );

        DATA_BLOB blobIn;
        DATA_BLOB blobEnt;
        DATA_BLOB blobOut;
        blobIn.cbData  = (DWORD)cbIn;
        blobIn.pbData  = (BYTE *)pIn;
        blobEnt.cbData = (DWORD)cbEnt;
        blobEnt.pbData = (BYTE *)pEnt;
        blobOut.cbData = 0;
        blobOut.pbData = nullptr;

        // CRYPTPROTECT_UI_FORBIDDEN unconditionally: this runs on service and
        // IOCP pump threads, where a prompt would hang the process rather than
        // ask anybody anything.
        DWORD dwFlags = CRYPTPROTECT_UI_FORBIDDEN;
        if ( eProtect == IdProtect_DpapiMachine ) dwFlags |= CRYPTPROTECT_LOCAL_MACHINE;

        if ( !CryptProtectData ( &blobIn,
                                 eKind == KindAgreement ? L"Targetcore agreement"
                                                        : L"Targetcore identity",
                                 &blobEnt, nullptr, nullptr, dwFlags, &blobOut ) )
            return IdErrProtect;
        if ( blobOut.cbData == 0 || blobOut.cbData > kMaxPayload )
        {
            if ( blobOut.pbData ) LocalFree ( blobOut.pbData );
            return IdErrProtect;
        }
        vOut.assign ( blobOut.pbData, blobOut.pbData + blobOut.cbData );
        LocalFree ( blobOut.pbData );
        return IdOk;
#else
        (void)pIn; (void)cbIn; (void)vOut; (void)eKind;
        return IdErrUnsupported;            // no DPAPI off Windows
#endif
    }

    IdResult UnprotectPayload ( IdProtection eProtect, KeyKind eKind,
                                const unsigned char *pIn, size_t cbIn,
                                std::vector<unsigned char> &vOut )
    {
        if ( eProtect == IdProtect_None )
        {
            vOut.assign ( pIn, pIn + cbIn );
            return IdOk;
        }
#ifdef _WIN32
        size_t      cbEnt = 0;
        const char *pEnt  = EntropyOf ( eKind, &cbEnt );

        DATA_BLOB blobIn;
        DATA_BLOB blobEnt;
        DATA_BLOB blobOut;
        blobIn.cbData  = (DWORD)cbIn;
        blobIn.pbData  = (BYTE *)pIn;
        blobEnt.cbData = (DWORD)cbEnt;
        blobEnt.pbData = (BYTE *)pEnt;
        blobOut.cbData = 0;
        blobOut.pbData = nullptr;

        // The scope flag is not repeated on the way in - DPAPI reads it from
        // the blob. A machine-scope blob moved to another machine, or a
        // user-scope blob read by another account, fails HERE, which is the
        // protection doing its job and not an error to retry.
        if ( !CryptUnprotectData ( &blobIn, nullptr, &blobEnt, nullptr, nullptr,
                                   CRYPTPROTECT_UI_FORBIDDEN, &blobOut ) )
            return IdErrUnprotect;
        if ( blobOut.cbData == 0 || blobOut.cbData > kMaxPayload )
        {
            if ( blobOut.pbData )
            {
                ZeroMem ( blobOut.pbData, blobOut.cbData );
                LocalFree ( blobOut.pbData );
            }
            return IdErrUnprotect;
        }
        vOut.assign ( blobOut.pbData, blobOut.pbData + blobOut.cbData );
        ZeroMem ( blobOut.pbData, blobOut.cbData );
        LocalFree ( blobOut.pbData );
        return IdOk;
#else
        (void)pIn; (void)cbIn; (void)vOut; (void)eKind;
        return IdErrUnsupported;
#endif
    }

    // -------------------------------------------------------------------
    //  Container build / parse
    // -------------------------------------------------------------------
    bool DigestOf ( const unsigned char *pHdr16, const unsigned char *pPayload,
                    size_t cbPayload, unsigned char pOut[kSha256Len] )
    {
        std::vector<unsigned char> v;
        v.reserve ( 16 + cbPayload );
        v.insert ( v.end(), pHdr16, pHdr16 + 16 );
        if ( cbPayload ) v.insert ( v.end(), pPayload, pPayload + cbPayload );
        return Sha256 ( v.empty() ? nullptr : &v[0], v.size(), pOut );
    }

    IdResult BuildContainer ( IdProtection eProtect, KeyKind eKind,
                              const std::vector<unsigned char> &vPayload,
                              std::vector<unsigned char> &vOut )
    {
        if ( vPayload.empty() || vPayload.size() > kMaxPayload ) return IdErrArgs;

        vOut.assign ( kIdHeaderLen + vPayload.size(), 0 );
        memcpy ( &vOut[0], MagicOf ( eKind ), sizeof(kMagic) );
        PutU16 ( &vOut[8],  kVersion );
        PutU16 ( &vOut[10], (unsigned int)eProtect );
        PutU32 ( &vOut[12], (unsigned long)vPayload.size() );

        unsigned char digest[kSha256Len];
        if ( !DigestOf ( &vOut[0], &vPayload[0], vPayload.size(), digest ) )
            return IdErrIo;
        memcpy ( &vOut[16], digest, kSha256Len );
        memcpy ( &vOut[kIdHeaderLen], &vPayload[0], vPayload.size() );
        return IdOk;
    }

    IdResult ParseContainer ( const std::vector<unsigned char> &vFile, KeyKind eKind,
                              IdProtection *peProtect,
                              std::vector<unsigned char> &vPayload )
    {
        if ( vFile.size() < kIdHeaderLen ) return IdErrFormat;
        // The magic must be the one for the kind the CALLER asked for. An
        // agreement file offered to LoadIdentity fails here, which is the point.
        if ( memcmp ( &vFile[0], MagicOf ( eKind ), sizeof(kMagic) ) != 0 )
            return IdErrFormat;

        unsigned int  nVersion = GetU16 ( &vFile[8] );
        unsigned int  nProtect = GetU16 ( &vFile[10] );
        unsigned long cbClaim  = GetU32 ( &vFile[12] );

        if ( nVersion != kVersion ) return IdErrVersion;
        if ( nProtect != (unsigned int)IdProtect_None         &&
             nProtect != (unsigned int)IdProtect_DpapiMachine &&
             nProtect != (unsigned int)IdProtect_DpapiUser )
            return IdErrFormat;
        if ( cbClaim == 0 || cbClaim > kMaxPayload ) return IdErrFormat;
        // The length field must match the file exactly. A shorter file is a
        // truncated write; a longer one is trailing garbage that a digest over
        // only cbClaim bytes would not notice.
        if ( vFile.size() != kIdHeaderLen + (size_t)cbClaim ) return IdErrFormat;

        unsigned char digest[kSha256Len];
        if ( !DigestOf ( &vFile[0], &vFile[kIdHeaderLen], (size_t)cbClaim, digest ) )
            return IdErrIo;
        if ( !ConstTimeEqual ( digest, &vFile[16], kSha256Len ) ) return IdErrIntegrity;

        *peProtect = (IdProtection)nProtect;
        vPayload.assign ( vFile.begin() + kIdHeaderLen, vFile.end() );
        return IdOk;
    }

    // -------------------------------------------------------------------
    //  Line-oriented text parsing (public key + allow-list)
    // -------------------------------------------------------------------
    struct Token { const char *psz; size_t cch; };

    // Splits one line into up to nMax whitespace-delimited tokens. Everything
    // from an unquoted '#' onward is a comment.
    size_t Tokenise ( const char *pLine, size_t cchLine, Token *pTok, size_t nMax )
    {
        size_t nTok = 0, i = 0;
        while ( i < cchLine && nTok < nMax )
        {
            while ( i < cchLine && IsSpace ( pLine[i] ) ) i++;
            if ( i >= cchLine || pLine[i] == '#' ) break;
            size_t iStart = i;
            while ( i < cchLine && !IsSpace ( pLine[i] ) && pLine[i] != '#' ) i++;
            pTok[nTok].psz = pLine + iStart;
            pTok[nTok].cch = i - iStart;
            nTok++;
        }
        return nTok;
    }

    // Calls pfnLine(pCtx, tokens, count) per non-empty, non-comment line.
    // pfnLine returns an IdResult; anything but IdOk aborts the walk.
    template <class F>
    IdResult ForEachLine ( const std::vector<unsigned char> &vText, F pfnLine )
    {
        size_t i = 0;
        while ( i < vText.size() )
        {
            size_t iEnd = i;
            while ( iEnd < vText.size() && vText[iEnd] != '\n' ) iEnd++;
            size_t cchLine = iEnd - i;
            if ( cchLine > kMaxLine ) return IdErrFormat;

            const char *pLine = (const char *)&vText[i];
            Token  aTok[4];
            size_t nTok = Tokenise ( pLine, cchLine, aTok, 4 );
            if ( nTok )
            {
                IdResult r = pfnLine ( aTok, nTok );
                if ( r != IdOk ) return r;
            }
            i = ( iEnd < vText.size() ) ? iEnd + 1 : iEnd;
        }
        return IdOk;
    }

    // -------------------------------------------------------------------
    //  Private-key files - one implementation, both kinds
    // -------------------------------------------------------------------
    //  EcdsaP256 and EcdhP256 are unrelated types that happen to share three
    //  method names and a 96-byte blob shape, so the file dance - export,
    //  protect, digest, atomic write - is written once here instead of twice
    //  with a chance to drift apart. The KeyKind decides the magic and the DPAPI
    //  entropy, and nothing else differs.
    template <class K>
    IdResult SaveKeyFile ( const char *pszPathUtf8, K &oKey, KeyKind eKind,
                           size_t cbPriv, IdProtection eProtect, bool bOverwrite )
    {
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return IdErrArgs;

        IdProtection eUse = ResolveProtection ( eProtect );
        if ( eUse != IdProtect_None &&
             eUse != IdProtect_DpapiMachine &&
             eUse != IdProtect_DpapiUser )
            return IdErrArgs;

        std::vector<unsigned char> vPriv ( cbPriv, 0 );
        if ( !oKey.ExportPrivate ( &vPriv[0] ) ) { ZeroVec ( vPriv ); return IdErrKey; }

        std::vector<unsigned char> vPayload;
        IdResult r = ProtectPayload ( eUse, eKind, &vPriv[0], vPriv.size(), vPayload );
        ZeroVec ( vPriv );
        if ( r != IdOk ) return r;

        std::vector<unsigned char> vFile;
        r = BuildContainer ( eUse, eKind, vPayload, vFile );
        ZeroVec ( vPayload );
        if ( r != IdOk ) { ZeroVec ( vFile ); return r; }

        r = WriteWholeFile ( pszPathUtf8, &vFile[0], vFile.size(), true, !bOverwrite );
        ZeroVec ( vFile );
        return r;
    }

    template <class K>
    IdResult LoadKeyFile ( const char *pszPathUtf8, K &oKey, KeyKind eKind,
                           size_t cbPriv )
    {
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return IdErrArgs;

        std::vector<unsigned char> vFile;
        IdResult r = ReadWholeFile ( pszPathUtf8, vFile, true,
                                     kIdHeaderLen + kMaxPayload );
        if ( r != IdOk ) return r;

        IdProtection eProtect = IdProtect_None;
        std::vector<unsigned char> vPayload;
        r = ParseContainer ( vFile, eKind, &eProtect, vPayload );
        ZeroVec ( vFile );
        if ( r != IdOk ) { ZeroVec ( vPayload ); return r; }

        std::vector<unsigned char> vPriv;
        r = UnprotectPayload ( eProtect, eKind, &vPayload[0], vPayload.size(), vPriv );
        ZeroVec ( vPayload );
        if ( r != IdOk ) { ZeroVec ( vPriv ); return r; }

        if ( vPriv.size() != cbPriv ) { ZeroVec ( vPriv ); return IdErrFormat; }

        // ImportPrivate rejects a blob whose public half does not belong to the
        // scalar, so a doctored file cannot load as a key that acts as somebody
        // else. oKey is only touched here, at the last step - a failed load
        // leaves the caller's existing key intact.
        bool bImported = oKey.ImportPrivate ( &vPriv[0] );
        ZeroVec ( vPriv );
        return bImported ? IdOk : IdErrKey;
    }

    template <class K>
    IdResult LoadOrCreateKeyFile ( const char *pszPathUtf8, K &oKey, KeyKind eKind,
                                   size_t cbPriv, bool *pbCreated,
                                   IdProtection eProtect )
    {
        if ( pbCreated ) *pbCreated = false;
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return IdErrArgs;

        IdResult r = LoadKeyFile ( pszPathUtf8, oKey, eKind, cbPriv );
        if ( r != IdErrNotFound ) return r;   // loaded, or failed for a real reason

        if ( !oKey.Generate() ) return IdErrKey;

        r = SaveKeyFile ( pszPathUtf8, oKey, eKind, cbPriv, eProtect,
                          /*bOverwrite*/ false );
        if ( r == IdErrExists )
            return LoadKeyFile ( pszPathUtf8, oKey, eKind, cbPriv );  // another
                                        // process got there first; its key wins
        if ( r != IdOk ) return r;

        if ( pbCreated ) *pbCreated = true;
        return IdOk;
    }

    // -------------------------------------------------------------------
    //  Public-point files - one implementation, both kinds
    // -------------------------------------------------------------------
    template <class K>
    IdResult SavePublicFile ( const char *pszPathUtf8, K &oKey, const char *pszWhat,
                              const char *pszCannot )
    {
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return IdErrArgs;

        unsigned char pub[kEcdsaPubLen];        // == kEcdhPubLen
        if ( !oKey.ExportPublic ( pub ) ) return IdErrKey;

        char szPrint[kIdFingerprintLen];
        if ( !Fingerprint ( pub, szPrint ) ) return IdErrKey;

        std::string sHex;
        HexEncode ( pub, sizeof(pub), sHex );

        std::string sText;
        sText  = "# Targetcore ";
        sText += pszWhat;
        sText += " public key - P-256, raw X||Y, hex.\n";
        sText += "# Publishable: this is the half a peer needs in order to\n";
        sText += "# ";
        sText += pszCannot;
        sText += "\n# fingerprint: ";
        sText += szPrint;
        sText += "\n";
        sText += sHex;
        sText += "\n";

        return WriteWholeFile ( pszPathUtf8, (const unsigned char *)sText.data(),
                                sText.size(), false, false );
    }

    template <class K>
    IdResult LoadPublicFile ( const char *pszPathUtf8, K &oKey )
    {
        if ( !pszPathUtf8 || !*pszPathUtf8 ) return IdErrArgs;

        std::vector<unsigned char> vText;
        IdResult r = ReadWholeFile ( pszPathUtf8, vText, false, kMaxTextFile );
        if ( r != IdOk ) return r;

        unsigned char pub[kEcdsaPubLen];
        bool bFound = false;

        // The first token that is exactly 128 hex characters wins, so a bare hex
        // line and an "<identity> <hex>" allow-list line both load.
        r = ForEachLine ( vText, [&] ( const Token *pTok, size_t nTok ) -> IdResult
        {
            if ( bFound ) return IdOk;
            for ( size_t i = 0; i < nTok; i++ )
            {
                if ( pTok[i].cch != kIdPubHexChars ) continue;
                if ( !HexDecodeExact ( pTok[i].psz, pTok[i].cch, pub, sizeof(pub) ) )
                    continue;
                bFound = true;
                return IdOk;
            }
            return IdOk;
        } );
        if ( r != IdOk ) return r;
        if ( !bFound )   return IdErrFormat;

        return oKey.ImportPublic ( pub ) ? IdOk : IdErrKey;
    }

} // anonymous namespace

// -----------------------------------------------------------------------
//  Result text
// -----------------------------------------------------------------------
const char *IdResultText ( IdResult eResult )
{
    switch ( eResult )
    {
    case IdOk:             return "ok";
    case IdErrArgs:        return "invalid argument";
    case IdErrIo:          return "file I/O failed";
    case IdErrNotFound:    return "file not found";
    case IdErrExists:      return "file already exists";
    case IdErrFormat:      return "malformed file";
    case IdErrVersion:     return "unsupported container version";
    case IdErrIntegrity:   return "integrity check failed (file corrupted)";
    case IdErrProtect:     return "DPAPI protect failed";
    case IdErrUnprotect:   return "DPAPI unprotect failed (wrong machine, wrong "
                                  "user, or tampered)";
    case IdErrKey:         return "invalid or unusable key material";
    case IdErrPerms:       return "identity file permissions are too permissive";
    case IdErrUnsupported: return "not supported on this platform";
    case IdErrRevoked:     return "key is on the revocation list";
    }
    return "unknown error";
}

// -----------------------------------------------------------------------
//  Identity file (private)
// -----------------------------------------------------------------------
IdResult SaveIdentity ( const char *pszPathUtf8, EcdsaP256 &oKey,
                        IdProtection eProtect, bool bOverwrite )
{
    return SaveKeyFile ( pszPathUtf8, oKey, KindIdentity, kEcdsaPrivLen,
                         eProtect, bOverwrite );
}

IdResult LoadIdentity ( const char *pszPathUtf8, EcdsaP256 &oKey )
{
    return LoadKeyFile ( pszPathUtf8, oKey, KindIdentity, kEcdsaPrivLen );
}

IdResult LoadOrCreateIdentity ( const char *pszPathUtf8, EcdsaP256 &oKey,
                                bool *pbCreated, IdProtection eProtect )
{
    return LoadOrCreateKeyFile ( pszPathUtf8, oKey, KindIdentity, kEcdsaPrivLen,
                                 pbCreated, eProtect );
}

// -----------------------------------------------------------------------
//  Agreement file (private)
// -----------------------------------------------------------------------
IdResult SaveAgreement ( const char *pszPathUtf8, EcdhP256 &oKey,
                         IdProtection eProtect, bool bOverwrite )
{
    return SaveKeyFile ( pszPathUtf8, oKey, KindAgreement, kEcdhPrivLen,
                         eProtect, bOverwrite );
}

IdResult LoadAgreement ( const char *pszPathUtf8, EcdhP256 &oKey )
{
    return LoadKeyFile ( pszPathUtf8, oKey, KindAgreement, kEcdhPrivLen );
}

IdResult LoadOrCreateAgreement ( const char *pszPathUtf8, EcdhP256 &oKey,
                                 bool *pbCreated, IdProtection eProtect )
{
    return LoadOrCreateKeyFile ( pszPathUtf8, oKey, KindAgreement, kEcdhPrivLen,
                                 pbCreated, eProtect );
}

// -----------------------------------------------------------------------
//  Public key file (publishable)
// -----------------------------------------------------------------------
IdResult SavePublicKey ( const char *pszPathUtf8, EcdsaP256 &oKey )
{
    return SavePublicFile ( pszPathUtf8, oKey, "identity",
                            "trust this identity. It cannot sign anything." );
}

IdResult LoadPublicKey ( const char *pszPathUtf8, EcdsaP256 &oKey )
{
    return LoadPublicFile ( pszPathUtf8, oKey );
}

IdResult SaveAgreementPublicKey ( const char *pszPathUtf8, EcdhP256 &oKey )
{
    return SavePublicFile ( pszPathUtf8, oKey, "agreement",
                            "seal a body to this peer. It cannot open one." );
}

IdResult LoadAgreementPublicKey ( const char *pszPathUtf8, EcdhP256 &oKey )
{
    return LoadPublicFile ( pszPathUtf8, oKey );
}

// -----------------------------------------------------------------------
//  Allow-list (public)
// -----------------------------------------------------------------------
IdResult LoadAllowList ( const char *pszPathUtf8, IdAllowFn pfnEntry, void *pCtx )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 || !pfnEntry ) return IdErrArgs;

    std::vector<unsigned char> vText;
    IdResult r = ReadWholeFile ( pszPathUtf8, vText, false, kMaxTextFile );
    if ( r != IdOk ) return r;

    return ForEachLine ( vText, [&] ( const Token *pTok, size_t nTok ) -> IdResult
    {
        // Fail the whole load on a bad line rather than skipping it: a
        // silently short allow-list is a trust decision made by a typo.
        if ( nTok < 2 )                            return IdErrFormat;
        if ( pTok[0].cch > kIdMaxIdentity )        return IdErrFormat;
        if ( pTok[1].cch != kIdPubHexChars )       return IdErrFormat;

        unsigned char pub[kEcdsaPubLen];
        if ( !HexDecodeExact ( pTok[1].psz, pTok[1].cch, pub, sizeof(pub) ) )
            return IdErrFormat;

        // The agreement column is optional, but a MALFORMED one is not
        // tolerated: a typo there would otherwise read as "this peer published
        // no agreement key", and the sender would decline to seal for a reason
        // that is not true. Absent is a state; garbled is an error.
        unsigned char  agree[kEcdhPubLen];
        unsigned char *pAgree = nullptr;
        if ( nTok >= 3 )
        {
            if ( pTok[2].cch != kIdPubHexChars ) return IdErrFormat;
            if ( !HexDecodeExact ( pTok[2].psz, pTok[2].cch, agree, sizeof(agree) ) )
                return IdErrFormat;
            pAgree = agree;
        }

        std::string sIdentity ( pTok[0].psz, pTok[0].cch );
        pfnEntry ( pCtx, sIdentity.c_str(), pub, pAgree );
        return IdOk;
    } );
}

IdResult AppendAllowList ( const char *pszPathUtf8, const char *pszIdentity,
                           const unsigned char *pPub, const unsigned char *pAgree )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 || !pszIdentity || !pPub ) return IdErrArgs;

    size_t cchIdentity = strlen ( pszIdentity );
    if ( cchIdentity == 0 || cchIdentity > kIdMaxIdentity ) return IdErrArgs;
    for ( size_t i = 0; i < cchIdentity; i++ )
    {
        // Whitespace would split the identity into two tokens on the way back
        // in, and '#' would truncate the line - either way the entry that came
        // out would not be the entry that went in.
        if ( IsSpace ( pszIdentity[i] ) || pszIdentity[i] == '#' ) return IdErrArgs;
    }

    std::vector<unsigned char> vText;
    IdResult r = ReadWholeFile ( pszPathUtf8, vText, false, kMaxTextFile );
    if ( r == IdErrNotFound )
    {
        vText.clear();
        const char szHead[] =
            "# Targetcore peer allow-list:\n"
            "#   <identity> <identity key, hex> [<agreement key, hex>]\n";
        vText.assign ( (const unsigned char *)szHead,
                       (const unsigned char *)szHead + sizeof(szHead) - 1 );
    }
    else if ( r != IdOk )
        return r;

    if ( !vText.empty() && vText.back() != '\n' ) vText.push_back ( '\n' );

    std::string sHex;
    HexEncode ( pPub, kEcdsaPubLen, sHex );
    std::string sLine = std::string ( pszIdentity ) + "\t" + sHex;
    if ( pAgree )
    {
        std::string sAgree;
        HexEncode ( pAgree, kEcdhPubLen, sAgree );
        sLine += "\t";
        sLine += sAgree;
    }
    sLine += "\n";
    vText.insert ( vText.end(), sLine.begin(), sLine.end() );

    return WriteWholeFile ( pszPathUtf8, &vText[0], vText.size(), false, false );
}

IdResult FindAllowed ( const char *pszPathUtf8, const char *pszIdentity,
                       unsigned char *pPubOut, unsigned char *pAgreeOut,
                       bool *pbHasAgree )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 || !pszIdentity || !pPubOut ) return IdErrArgs;

    if ( pbHasAgree ) *pbHasAgree = false;
    // Cleared up front, so a caller that ignores pbHasAgree reads zeros rather
    // than whatever the buffer held before - a stale key from an earlier lookup
    // would be the worst possible thing to seal to.
    if ( pAgreeOut ) memset ( pAgreeOut, 0, kEcdhPubLen );

    struct Hunt
    {
        const char    *pszWant;
        unsigned char *pOut;
        unsigned char *pAgreeOut;
        bool           bFound;
        bool           bAgree;
    } oHunt = { pszIdentity, pPubOut, pAgreeOut, false, false };

    IdResult r = LoadAllowList ( pszPathUtf8,
        [] ( void *pCtx, const char *pszEntry, const unsigned char *pPub,
             const unsigned char *pAgree )
        {
            Hunt *p = (Hunt *)pCtx;
            if ( p->bFound ) return;                       // first match wins
            if ( strcmp ( pszEntry, p->pszWant ) != 0 ) return;   // exact, no folding
            memcpy ( p->pOut, pPub, kEcdsaPubLen );
            if ( pAgree )
            {
                if ( p->pAgreeOut ) memcpy ( p->pAgreeOut, pAgree, kEcdhPubLen );
                p->bAgree = true;
            }
            p->bFound = true;
        }, &oHunt );

    if ( r != IdOk ) return r;
    if ( !oHunt.bFound ) return IdErrNotFound;
    if ( pbHasAgree ) *pbHasAgree = oHunt.bAgree;
    return IdOk;
}

// -----------------------------------------------------------------------
//  Revocation list (public)
// -----------------------------------------------------------------------
IdResult LoadRevocationList ( const char *pszPathUtf8, IdRevokeFn pfnEntry,
                              void *pCtx )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 || !pfnEntry ) return IdErrArgs;

    std::vector<unsigned char> vText;
    IdResult r = ReadWholeFile ( pszPathUtf8, vText, false, kMaxTextFile );
    if ( r != IdOk ) return r;

    return ForEachLine ( vText, [&] ( const Token *pTok, size_t nTok ) -> IdResult
    {
        //  Whole-file-fails, as the allow-list does, and here the argument is
        //  one step stronger. A skipped allow-list line denies a peer that
        //  should have been allowed, which is loud. A skipped REVOCATION line
        //  allows a key that should have been refused, which is silent, and is
        //  the exact failure this file exists to prevent.
        if ( nTok < 1 )                          return IdErrFormat;
        if ( pTok[0].cch != kIdPubHexChars )     return IdErrFormat;

        unsigned char point[kIdRevokePointLen];
        if ( !HexDecodeExact ( pTok[0].psz, pTok[0].cch, point, sizeof(point) ) )
            return IdErrFormat;

        //  The epoch column is optional; a MALFORMED one is not tolerated, on
        //  the same reasoning as the allow-list's agreement column. Any token
        //  after it is a reason someone wrote without a '#', which would have
        //  parsed as a timestamp had it been in that slot - refuse it rather
        //  than let the shape of a comment depend on how many words it has.
        long long llWhen = 0;
        if ( nTok >= 2 )
        {
            if ( !ParseEpoch ( pTok[1].psz, pTok[1].cch, &llWhen ) )
                return IdErrFormat;
        }
        if ( nTok >= 3 )                         return IdErrFormat;

        pfnEntry ( pCtx, point, llWhen );
        return IdOk;
    } );
}

IdResult AppendRevocationList ( const char *pszPathUtf8,
                                const unsigned char *pPoint,
                                long long llRevokedAt, const char *pszReason )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 || !pPoint ) return IdErrArgs;

    if ( llRevokedAt == 0 ) llRevokedAt = (long long)std::time ( nullptr );
    if ( llRevokedAt < 0 )  return IdErrArgs;

    std::vector<unsigned char> vText;
    IdResult r = ReadWholeFile ( pszPathUtf8, vText, false, kMaxTextFile );
    if ( r == IdErrNotFound )
    {
        vText.clear();
        const char szHead[] =
            "# Targetcore revocation list:\n"
            "#   <public point, hex> [<revoked-at, epoch seconds>]  # why\n"
            "# A listed point is refused wherever it appears - login and\n"
            "# sealing, identity keys and agreement keys alike. The timestamp\n"
            "# is a record, not a window: it is never compared to the clock.\n";
        vText.assign ( (const unsigned char *)szHead,
                       (const unsigned char *)szHead + sizeof(szHead) - 1 );
    }
    else if ( r != IdOk )
        return r;

    if ( !vText.empty() && vText.back() != '\n' ) vText.push_back ( '\n' );

    std::string sHex;
    HexEncode ( pPoint, kIdRevokePointLen, sHex );

    char szLine[64];
    std::snprintf ( szLine, sizeof(szLine), "\t%lld", llRevokedAt );
    std::string sLine = sHex + szLine;

    //  The human-readable half goes in the comment, which is where the
    //  fingerprint belongs: visible when an operator opens the file, invisible
    //  to the parser, and impossible to mistake for the field that is trusted.
    char szFp[kIdFingerprintLen];
    sLine += "\t# ";
    if ( Fingerprint ( pPoint, szFp ) ) { sLine += szFp; sLine += " "; }
    if ( pszReason && *pszReason )
    {
        for ( const char *p = pszReason; *p; p++ )
            if ( *p != '\n' && *p != '\r' ) sLine += *p;
    }
    sLine += "\n";
    vText.insert ( vText.end(), sLine.begin(), sLine.end() );

    return WriteWholeFile ( pszPathUtf8, &vText[0], vText.size(), false, false );
}

IdResult IsRevoked ( const char *pszPathUtf8, const unsigned char *pPoint,
                     bool *pbRevoked )
{
    if ( !pszPathUtf8 || !*pszPathUtf8 || !pPoint || !pbRevoked ) return IdErrArgs;
    *pbRevoked = false;

    struct Hunt
    {
        const unsigned char *pWant;
        bool                 bHit;
    } oHunt = { pPoint, false };

    IdResult r = LoadRevocationList ( pszPathUtf8,
        [] ( void *pCtx, const unsigned char *pEntry, long long )
        {
            Hunt *p = (Hunt *)pCtx;
            //  Constant time is not the concern - a revocation list is public
            //  data and the point being tested is already on the wire. Reading
            //  every entry rather than stopping at the first hit costs nothing
            //  at these sizes and keeps the callback total.
            if ( std::memcmp ( pEntry, p->pWant, kIdRevokePointLen ) == 0 )
                p->bHit = true;
        }, &oHunt );

    if ( r != IdOk ) return r;
    *pbRevoked = oHunt.bHit;
    return IdOk;
}

// -----------------------------------------------------------------------
//  Fingerprint
// -----------------------------------------------------------------------
bool Fingerprint ( const unsigned char *pPub, char *pszOut )
{
    if ( !pPub || !pszOut ) return false;

    unsigned char hash[kSha256Len];
    if ( !Sha256 ( pPub, kEcdsaPubLen, hash ) ) return false;

    static const char *pszDigits = "0123456789ABCDEF";
    size_t o = 0;
    for ( size_t i = 0; i < 16; i++ )
    {
        if ( i && ( i % 2 ) == 0 ) pszOut[o++] = '-';
        pszOut[o++] = pszDigits[ hash[i] >> 4  ];
        pszOut[o++] = pszDigits[ hash[i] & 0x0F];
    }
    pszOut[o] = '\0';                       // 32 hex + 7 dashes + NUL = 40
    return true;
}

// -----------------------------------------------------------------------
//  Self-test
// -----------------------------------------------------------------------
namespace
{
    std::string TempDir ( )
    {
#ifdef _WIN32
        wchar_t wszDir[MAX_PATH + 2];
        DWORD n = GetTempPathW ( MAX_PATH + 1, wszDir );
        if ( n == 0 || n > MAX_PATH ) return ".\\";
        char szDir[ ( MAX_PATH + 2 ) * 4 ];
        int cb = WideCharToMultiByte ( CP_UTF8, 0, wszDir, -1, szDir,
                                       (int)sizeof(szDir), nullptr, nullptr );
        if ( cb <= 0 ) return ".\\";
        return std::string ( szDir );
#else
        return std::string ( "/tmp/" );
#endif
    }

    std::string TempFile ( const char *pszLeaf )
    {
#ifdef _WIN32
        unsigned long nPid = (unsigned long)GetCurrentProcessId();
#else
        unsigned long nPid = (unsigned long)::getpid();
#endif
        char szPid[32];
        std::snprintf ( szPid, sizeof(szPid), "%lu", nPid );
        return TempDir() + "p2pid_" + pszLeaf + "_" + szPid + ".tmp";
    }

    // Every failure returns immediately, so the file names are collected up
    // front and removed by this guard however the test exits.
    struct Scrub
    {
        std::vector<std::string> vPaths;
        void Add ( const std::string &s ) { vPaths.push_back ( s ); }
        ~Scrub ( )
        {
            for ( size_t i = 0; i < vPaths.size(); i++ )
                DeleteOneFile ( vPaths[i].c_str() );
        }
    };

    struct AllowTally
    {
        int  nSeen;
        bool bClientOk;
        bool bAdminOk;
        int  nWithAgree;               // entries that carried a third column
        unsigned char pubClient[kEcdsaPubLen];
        unsigned char pubAdmin [kEcdsaPubLen];
    };

    void TallyEntry ( void *pCtx, const char *pszIdentity, const unsigned char *pPub,
                      const unsigned char *pAgree )
    {
        AllowTally *p = (AllowTally *)pCtx;
        p->nSeen++;
        if ( pAgree ) p->nWithAgree++;
        if ( strcmp ( pszIdentity, "SelfTest.Client" ) == 0 )
            p->bClientOk = ConstTimeEqual ( pPub, p->pubClient, kEcdsaPubLen );
        else if ( strcmp ( pszIdentity, "SelfTest.Admin" ) == 0 )
            p->bAdminOk  = ConstTimeEqual ( pPub, p->pubAdmin,  kEcdsaPubLen );
    }
}

bool StoreSelfTest ( )
{
    Scrub oScrub;

    const std::string sId       = TempFile ( "id"       );
    const std::string sPub      = TempFile ( "pub"      );
    const std::string sAllow    = TempFile ( "allow"    );
    const std::string sNone     = TempFile ( "none"     );
    const std::string sAgree    = TempFile ( "agree"    );
    const std::string sAgree2   = TempFile ( "agree2"   );
    const std::string sAgreePub = TempFile ( "agreepub" );
    const std::string sAllow2   = TempFile ( "allow2"   );
    const std::string sRevoke   = TempFile ( "revoke"   );
    oScrub.Add ( sId ); oScrub.Add ( sPub ); oScrub.Add ( sAllow ); oScrub.Add ( sNone );
    oScrub.Add ( sAgree ); oScrub.Add ( sAgree2 );
    oScrub.Add ( sAgreePub ); oScrub.Add ( sAllow2 ); oScrub.Add ( sRevoke );

    // Start clean even if a previous run died mid-way.
    DeleteOneFile ( sId.c_str() );  DeleteOneFile ( sPub.c_str() );
    DeleteOneFile ( sAllow.c_str() ); DeleteOneFile ( sNone.c_str() );
    DeleteOneFile ( sAgree.c_str() ); DeleteOneFile ( sAgree2.c_str() );
    DeleteOneFile ( sAgreePub.c_str() ); DeleteOneFile ( sAllow2.c_str() );
    DeleteOneFile ( sRevoke.c_str() );

    // --- Missing file reports missing, not corrupt ---------------------
    {
        EcdsaP256 k;
        if ( LoadIdentity ( sId.c_str(), k ) != IdErrNotFound ) return false;
        if ( LoadPublicKey ( sPub.c_str(), k ) != IdErrNotFound ) return false;
    }

    // --- Save / load round-trip preserves the signing identity ---------
    unsigned char pubOrig[kEcdsaPubLen];
    {
        EcdsaP256 oOrig;
        if ( !oOrig.Generate() ) return false;
        if ( !oOrig.ExportPublic ( pubOrig ) ) return false;
        if ( SaveIdentity ( sId.c_str(), oOrig ) != IdOk ) return false;

        EcdsaP256 oBack;
        if ( LoadIdentity ( sId.c_str(), oBack ) != IdOk ) return false;

        unsigned char pubBack[kEcdsaPubLen];
        if ( !oBack.ExportPublic ( pubBack ) ) return false;
        if ( !ConstTimeEqual ( pubBack, pubOrig, kEcdsaPubLen ) ) return false;

        // The point of the whole layer: the key that comes back off disk can
        // still sign as the key that went on.
        const char msg[] = "identity store round-trip";
        unsigned char sig[kEcdsaSigLen];
        if ( !oBack.Sign ( (const unsigned char *)msg, sizeof(msg) - 1, sig ) )
            return false;
        EcdsaP256 oVerify;
        if ( !oVerify.ImportPublic ( pubOrig ) ) return false;
        if ( !oVerify.Verify ( (const unsigned char *)msg, sizeof(msg) - 1, sig ) )
            return false;
    }

    // --- The stored bytes must not BE the key --------------------------
    // On Windows this is the check that proves DPAPI actually ran rather than
    // being assumed: the header must say "machine scope", and the 32-byte
    // private scalar must not appear anywhere in the file. Under
    // IdProtect_None it is the opposite assertion - the scalar IS there - so
    // the same code proves the check can distinguish the two.
    {
        std::vector<unsigned char> vFile;
        if ( ReadWholeFile ( sId.c_str(), vFile, true,
                             kIdHeaderLen + kMaxPayload ) != IdOk ) return false;
        if ( vFile.size() <= kIdHeaderLen ) return false;
        if ( memcmp ( &vFile[0], kMagic, sizeof(kMagic) ) != 0 ) return false;
        if ( GetU16 ( &vFile[8] ) != kVersion ) return false;

        unsigned int nProtect = GetU16 ( &vFile[10] );
#ifdef _WIN32
        if ( nProtect != (unsigned int)IdProtect_DpapiMachine ) return false;
#else
        if ( nProtect != (unsigned int)IdProtect_None ) return false;
#endif
        // Recover the scalar the honest way, then hunt for it in the file.
        EcdsaP256 oKey;
        if ( LoadIdentity ( sId.c_str(), oKey ) != IdOk ) return false;
        unsigned char priv[kEcdsaPrivLen];
        if ( !oKey.ExportPrivate ( priv ) ) return false;
        const unsigned char *pScalar = priv + 64;      // X||Y||d -> d

        bool bScalarOnDisk = false;
        for ( size_t i = 0; i + 32 <= vFile.size(); i++ )
            if ( memcmp ( &vFile[i], pScalar, 32 ) == 0 ) { bScalarOnDisk = true; break; }
        ZeroMem ( priv, sizeof(priv) );

        if ( nProtect == (unsigned int)IdProtect_None )
        {
            if ( !bScalarOnDisk ) return false;        // must be there, unprotected
        }
        else if ( bScalarOnDisk )
            return false;                              // DPAPI did not protect it
    }

#ifndef _WIN32
    // --- POSIX: 0600 on write, and a loosened file is refused ----------
    // The mode IS the protection on this platform, so both halves of that
    // sentence have to be executed rather than asserted in a comment.
    {
        struct stat st;
        if ( ::stat ( sId.c_str(), &st ) != 0 ) return false;
        if ( ( st.st_mode & 0777 ) != 0600 ) return false;

        if ( ::chmod ( sId.c_str(), 0644 ) != 0 ) return false;
        EcdsaP256 oLoose;
        if ( LoadIdentity ( sId.c_str(), oLoose ) != IdErrPerms ) return false;

        if ( ::chmod ( sId.c_str(), 0600 ) != 0 ) return false;
        EcdsaP256 oTight;
        if ( LoadIdentity ( sId.c_str(), oTight ) != IdOk ) return false;
    }
#endif

    // --- Corruption is caught, and named correctly ---------------------
    {
        std::vector<unsigned char> vFile;
        if ( ReadWholeFile ( sId.c_str(), vFile, true,
                             kIdHeaderLen + kMaxPayload ) != IdOk ) return false;

        // A flipped payload bit -> integrity, not a crypto error.
        std::vector<unsigned char> vBad = vFile;
        vBad[kIdHeaderLen] ^= 0x01;
        if ( WriteWholeFile ( sNone.c_str(), &vBad[0], vBad.size(), true, false ) != IdOk )
            return false;
        EcdsaP256 k1;
        if ( LoadIdentity ( sNone.c_str(), k1 ) != IdErrIntegrity ) return false;

        // Truncation -> format. (The length field no longer matches the file.)
        vBad.assign ( vFile.begin(), vFile.begin() + kIdHeaderLen + 1 );
        if ( WriteWholeFile ( sNone.c_str(), &vBad[0], vBad.size(), true, false ) != IdOk )
            return false;
        EcdsaP256 k2;
        if ( LoadIdentity ( sNone.c_str(), k2 ) != IdErrFormat ) return false;

        // Wrong magic -> format, before anything else is believed.
        vBad = vFile;
        vBad[0] ^= 0xFF;
        if ( WriteWholeFile ( sNone.c_str(), &vBad[0], vBad.size(), true, false ) != IdOk )
            return false;
        EcdsaP256 k3;
        if ( LoadIdentity ( sNone.c_str(), k3 ) != IdErrFormat ) return false;

        // Trailing garbage -> format. A digest over only the claimed length
        // would happily ignore appended bytes.
        vBad = vFile;
        vBad.push_back ( 0x00 );
        if ( WriteWholeFile ( sNone.c_str(), &vBad[0], vBad.size(), true, false ) != IdOk )
            return false;
        EcdsaP256 k4;
        if ( LoadIdentity ( sNone.c_str(), k4 ) != IdErrFormat ) return false;

        // An unknown version is refused rather than guessed at.
        vBad = vFile;
        PutU16 ( &vBad[8], kVersion + 1 );
        {
            unsigned char digest[kSha256Len];
            if ( !DigestOf ( &vBad[0], &vBad[kIdHeaderLen],
                             vBad.size() - kIdHeaderLen, digest ) ) return false;
            memcpy ( &vBad[16], digest, kSha256Len );   // keep the digest honest
        }
        if ( WriteWholeFile ( sNone.c_str(), &vBad[0], vBad.size(), true, false ) != IdOk )
            return false;
        EcdsaP256 k5;
        if ( LoadIdentity ( sNone.c_str(), k5 ) != IdErrVersion ) return false;

        DeleteOneFile ( sNone.c_str() );
    }

    // --- Unprotected storage still round-trips -------------------------
    // The provisioning path, and the negative control for the DPAPI check
    // above: same container, protection 0, scalar visible on disk.
    {
        EcdsaP256 oPlain;
        if ( !oPlain.Generate() ) return false;
        if ( SaveIdentity ( sNone.c_str(), oPlain, IdProtect_None ) != IdOk ) return false;

        EcdsaP256 oBack;
        if ( LoadIdentity ( sNone.c_str(), oBack ) != IdOk ) return false;
        unsigned char a[kEcdsaPubLen], b[kEcdsaPubLen];
        if ( !oPlain.ExportPublic ( a ) || !oBack.ExportPublic ( b ) ) return false;
        if ( !ConstTimeEqual ( a, b, kEcdsaPubLen ) ) return false;

        std::vector<unsigned char> vFile;
        if ( ReadWholeFile ( sNone.c_str(), vFile, true,
                             kIdHeaderLen + kMaxPayload ) != IdOk ) return false;
        if ( GetU16 ( &vFile[10] ) != (unsigned int)IdProtect_None ) return false;
        if ( vFile.size() != kIdHeaderLen + kEcdsaPrivLen ) return false;

        DeleteOneFile ( sNone.c_str() );
    }

    // --- A verify-only key cannot be saved as an identity --------------
    {
        EcdsaP256 oPubOnly;
        if ( !oPubOnly.ImportPublic ( pubOrig ) ) return false;
        if ( SaveIdentity ( sNone.c_str(), oPubOnly ) != IdErrKey ) return false;
        if ( FileExists ( sNone.c_str() ) ) return false;   // and wrote nothing
    }

    // --- Exclusive create refuses to clobber an existing identity ------
    {
        EcdsaP256 oOther;
        if ( !oOther.Generate() ) return false;
        if ( SaveIdentity ( sId.c_str(), oOther, IdProtect_Default,
                            /*bOverwrite*/ false ) != IdErrExists ) return false;

        // ...and the original is still the one on disk.
        EcdsaP256 oStill;
        if ( LoadIdentity ( sId.c_str(), oStill ) != IdOk ) return false;
        unsigned char pubStill[kEcdsaPubLen];
        if ( !oStill.ExportPublic ( pubStill ) ) return false;
        if ( !ConstTimeEqual ( pubStill, pubOrig, kEcdsaPubLen ) ) return false;
    }

    // --- LoadOrCreate: creates once, then loads the same key -----------
    {
        DeleteOneFile ( sNone.c_str() );

        EcdsaP256 oFirst;
        bool bCreated = false;
        if ( LoadOrCreateIdentity ( sNone.c_str(), oFirst, &bCreated ) != IdOk ) return false;
        if ( !bCreated ) return false;

        EcdsaP256 oSecond;
        bool bCreated2 = true;
        if ( LoadOrCreateIdentity ( sNone.c_str(), oSecond, &bCreated2 ) != IdOk ) return false;
        if ( bCreated2 ) return false;

        unsigned char a[kEcdsaPubLen], b[kEcdsaPubLen];
        if ( !oFirst.ExportPublic ( a ) || !oSecond.ExportPublic ( b ) ) return false;
        if ( !ConstTimeEqual ( a, b, kEcdsaPubLen ) ) return false;

        DeleteOneFile ( sNone.c_str() );
    }

    // --- Public key file round-trip, and it really is public only ------
    {
        EcdsaP256 oKey;
        if ( LoadIdentity ( sId.c_str(), oKey ) != IdOk ) return false;
        if ( SavePublicKey ( sPub.c_str(), oKey ) != IdOk ) return false;

        EcdsaP256 oPub;
        if ( LoadPublicKey ( sPub.c_str(), oPub ) != IdOk ) return false;
        unsigned char pubBack[kEcdsaPubLen];
        if ( !oPub.ExportPublic ( pubBack ) ) return false;
        if ( !ConstTimeEqual ( pubBack, pubOrig, kEcdsaPubLen ) ) return false;

        // Loaded from the public file, it must be unable to sign.
        unsigned char sig[kEcdsaSigLen];
        if ( oPub.Sign ( (const unsigned char *)"x", 1, sig ) ) return false;

        // The published file must not contain the private scalar.
        std::vector<unsigned char> vText;
        if ( ReadWholeFile ( sPub.c_str(), vText, false, kMaxTextFile ) != IdOk )
            return false;
        unsigned char priv[kEcdsaPrivLen];
        if ( !oKey.ExportPrivate ( priv ) ) return false;
        bool bLeak = false;
        for ( size_t i = 0; i + 32 <= vText.size(); i++ )
            if ( memcmp ( &vText[i], priv + 64, 32 ) == 0 ) { bLeak = true; break; }
        ZeroMem ( priv, sizeof(priv) );
        if ( bLeak ) return false;
    }

    // --- Fingerprint is stable, shaped, and key-specific ---------------
    {
        char szA[kIdFingerprintLen], szB[kIdFingerprintLen];
        if ( !Fingerprint ( pubOrig, szA ) ) return false;
        if ( !Fingerprint ( pubOrig, szB ) ) return false;
        if ( strcmp ( szA, szB ) != 0 ) return false;
        if ( strlen ( szA ) != kIdFingerprintLen - 1 ) return false;
        if ( szA[4] != '-' || szA[9] != '-' ) return false;

        unsigned char pubOther[kEcdsaPubLen];
        memcpy ( pubOther, pubOrig, sizeof(pubOther) );
        pubOther[0] ^= 0x01;
        char szC[kIdFingerprintLen];
        if ( !Fingerprint ( pubOther, szC ) ) return false;
        if ( strcmp ( szA, szC ) == 0 ) return false;
    }

    // --- Allow-list: append, enumerate, look up ------------------------
    {
        AllowTally oTally;
        memset ( &oTally, 0, sizeof(oTally) );

        EcdsaP256 oClient, oAdmin;
        if ( !oClient.Generate() || !oAdmin.Generate() ) return false;
        if ( !oClient.ExportPublic ( oTally.pubClient ) ) return false;
        if ( !oAdmin.ExportPublic  ( oTally.pubAdmin  ) ) return false;

        if ( AppendAllowList ( sAllow.c_str(), "SelfTest.Client",
                               oTally.pubClient ) != IdOk ) return false;
        if ( AppendAllowList ( sAllow.c_str(), "SelfTest.Admin",
                               oTally.pubAdmin ) != IdOk ) return false;

        if ( LoadAllowList ( sAllow.c_str(), TallyEntry, &oTally ) != IdOk ) return false;
        if ( oTally.nSeen != 2 ) return false;
        if ( !oTally.bClientOk || !oTally.bAdminOk ) return false;
        // Two-column entries: the callback must be told there is no agreement
        // key rather than handed a buffer of something.
        if ( oTally.nWithAgree != 0 ) return false;

        unsigned char pubFound[kEcdsaPubLen];
        if ( FindAllowed ( sAllow.c_str(), "SelfTest.Admin", pubFound ) != IdOk )
            return false;
        if ( !ConstTimeEqual ( pubFound, oTally.pubAdmin, kEcdsaPubLen ) ) return false;

        // The same lookup asked for an agreement key it cannot have: found, but
        // flagged absent, and the buffer left zeroed.
        unsigned char agreeFound[kEcdhPubLen];
        bool bHasAgree = true;
        memset ( agreeFound, 0xEE, sizeof(agreeFound) );
        if ( FindAllowed ( sAllow.c_str(), "SelfTest.Admin", pubFound,
                           agreeFound, &bHasAgree ) != IdOk ) return false;
        if ( bHasAgree ) return false;
        for ( size_t i = 0; i < sizeof(agreeFound); i++ )
            if ( agreeFound[i] != 0 ) return false;

        // A miss is a miss - including one that differs only in case, because
        // an allow-list that folds case is an allow-list with entries nobody
        // wrote.
        if ( FindAllowed ( sAllow.c_str(), "SelfTest.Nobody", pubFound ) != IdErrNotFound )
            return false;
        if ( FindAllowed ( sAllow.c_str(), "selftest.admin", pubFound ) != IdErrNotFound )
            return false;

        // An identity that would not survive the round-trip is refused up front.
        if ( AppendAllowList ( sAllow.c_str(), "has space",
                               oTally.pubAdmin ) != IdErrArgs ) return false;
        if ( AppendAllowList ( sAllow.c_str(), "", oTally.pubAdmin ) != IdErrArgs )
            return false;

        // A malformed line fails the whole load rather than silently
        // shortening the allow-list.
        std::vector<unsigned char> vText;
        if ( ReadWholeFile ( sAllow.c_str(), vText, false, kMaxTextFile ) != IdOk )
            return false;
        const char szBad[] = "SelfTest.Broken deadbeef\n";
        vText.insert ( vText.end(), (const unsigned char *)szBad,
                       (const unsigned char *)szBad + sizeof(szBad) - 1 );
        if ( WriteWholeFile ( sAllow.c_str(), &vText[0], vText.size(),
                              false, false ) != IdOk ) return false;
        AllowTally oIgnored;
        memset ( &oIgnored, 0, sizeof(oIgnored) );
        if ( LoadAllowList ( sAllow.c_str(), TallyEntry, &oIgnored ) != IdErrFormat )
            return false;
    }

    // --- Agreement key: same container, and it agrees after a round trip ---
    unsigned char agreeOrig[kEcdhPubLen];
    {
        EcdhP256 oOrig;
        if ( LoadAgreement ( sAgree.c_str(), oOrig ) != IdErrNotFound ) return false;
        if ( !oOrig.Generate() ) return false;
        if ( !oOrig.ExportPublic ( agreeOrig ) ) return false;
        if ( SaveAgreement ( sAgree.c_str(), oOrig ) != IdOk ) return false;

        EcdhP256 oBack;
        if ( LoadAgreement ( sAgree.c_str(), oBack ) != IdOk ) return false;
        unsigned char agreeBack[kEcdhPubLen];
        if ( !oBack.ExportPublic ( agreeBack ) ) return false;
        if ( !ConstTimeEqual ( agreeBack, agreeOrig, kEcdhPubLen ) ) return false;

        // The point of persisting it: a peer that generates a fresh ephemeral
        // pair must reach the same secret against the key that came off disk as
        // against the key that went on. Nothing else proves the scalar survived.
        EcdhP256 oSender;
        if ( !oSender.Generate() ) return false;
        unsigned char senderPub[kEcdhPubLen];
        if ( !oSender.ExportPublic ( senderPub ) ) return false;

        unsigned char secA[kEcdhSecLen], secB[kEcdhSecLen];
        if ( !oSender.DeriveRawSecret ( agreeOrig, secA ) ) return false;
        if ( !oBack.DeriveRawSecret   ( senderPub, secB ) ) return false;
        if ( !ConstTimeEqual ( secA, secB, kEcdhSecLen ) ) return false;

        // The stored bytes must not be the scalar, exactly as for an identity.
        std::vector<unsigned char> vFile;
        if ( ReadWholeFile ( sAgree.c_str(), vFile, true,
                             kIdHeaderLen + kMaxPayload ) != IdOk ) return false;
        if ( memcmp ( &vFile[0], kMagicAgree, sizeof(kMagicAgree) ) != 0 ) return false;
#ifdef _WIN32
        unsigned char priv[kEcdhPrivLen];
        if ( !oBack.ExportPrivate ( priv ) ) return false;
        bool bScalarOnDisk = false;
        for ( size_t i = 0; i + 32 <= vFile.size(); i++ )
            if ( memcmp ( &vFile[i], priv + 64, 32 ) == 0 ) { bScalarOnDisk = true; break; }
        ZeroMem ( priv, sizeof(priv) );
        if ( bScalarOnDisk ) return false;
#endif
    }

    // --- The two kinds are not interchangeable --------------------------
    // Both blobs are 96 bytes of X||Y||d on the same curve, so without the
    // separation an agreement file would load happily as a signing identity.
    // This is the check that the separation is real and not a comment.
    {
        EcdsaP256 oId;
        if ( LoadIdentity ( sAgree.c_str(), oId ) != IdErrFormat ) return false;

        EcdhP256 oAgree;
        if ( LoadAgreement ( sId.c_str(), oAgree ) != IdErrFormat ) return false;
    }

    // --- LoadOrCreateAgreement: creates once, then loads the same key ---
    {
        DeleteOneFile ( sAgree2.c_str() );

        EcdhP256 oFirst;
        bool bCreated = false;
        if ( LoadOrCreateAgreement ( sAgree2.c_str(), oFirst, &bCreated ) != IdOk )
            return false;
        if ( !bCreated ) return false;

        EcdhP256 oSecond;
        bool bCreated2 = true;
        if ( LoadOrCreateAgreement ( sAgree2.c_str(), oSecond, &bCreated2 ) != IdOk )
            return false;
        if ( bCreated2 ) return false;

        unsigned char a[kEcdhPubLen], b[kEcdhPubLen];
        if ( !oFirst.ExportPublic ( a ) || !oSecond.ExportPublic ( b ) ) return false;
        if ( !ConstTimeEqual ( a, b, kEcdhPubLen ) ) return false;

        DeleteOneFile ( sAgree2.c_str() );
    }

    // --- Agreement public file publishes the point, not the scalar ------
    {
        EcdhP256 oKey;
        if ( LoadAgreement ( sAgree.c_str(), oKey ) != IdOk ) return false;
        if ( SaveAgreementPublicKey ( sAgreePub.c_str(), oKey ) != IdOk ) return false;

        EcdhP256 oPub;
        if ( LoadAgreementPublicKey ( sAgreePub.c_str(), oPub ) != IdOk ) return false;
        unsigned char back[kEcdhPubLen];
        if ( !oPub.ExportPublic ( back ) ) return false;
        if ( !ConstTimeEqual ( back, agreeOrig, kEcdhPubLen ) ) return false;

        // Public-only: it holds no private half, so it cannot agree with anyone.
        EcdhP256 oOther;
        if ( !oOther.Generate() ) return false;
        unsigned char otherPub[kEcdhPubLen], sec[kEcdhSecLen];
        if ( !oOther.ExportPublic ( otherPub ) ) return false;
        if ( oPub.DeriveRawSecret ( otherPub, sec ) ) return false;
    }

    // --- Allow-list third column: optional, round-trips, and is checked --
    {
        DeleteOneFile ( sAllow2.c_str() );

        EcdsaP256 oId;
        EcdhP256  oAgree;
        if ( !oId.Generate() || !oAgree.Generate() ) return false;
        unsigned char pubId[kEcdsaPubLen], pubAgree[kEcdhPubLen];
        if ( !oId.ExportPublic ( pubId ) || !oAgree.ExportPublic ( pubAgree ) )
            return false;

        // One peer with an agreement key, one without - the mixed file is the
        // realistic case during a rollout, and both forms must load together.
        if ( AppendAllowList ( sAllow2.c_str(), "SelfTest.Sealed",
                               pubId, pubAgree ) != IdOk ) return false;
        if ( AppendAllowList ( sAllow2.c_str(), "SelfTest.Plain", pubId ) != IdOk )
            return false;

        AllowTally oTally;
        memset ( &oTally, 0, sizeof(oTally) );
        if ( LoadAllowList ( sAllow2.c_str(), TallyEntry, &oTally ) != IdOk ) return false;
        if ( oTally.nSeen != 2 ) return false;
        if ( oTally.nWithAgree != 1 ) return false;

        unsigned char pubBack[kEcdsaPubLen], agreeBack[kEcdhPubLen];
        bool bHasAgree = false;
        if ( FindAllowed ( sAllow2.c_str(), "SelfTest.Sealed", pubBack,
                           agreeBack, &bHasAgree ) != IdOk ) return false;
        if ( !bHasAgree ) return false;
        if ( !ConstTimeEqual ( pubBack,   pubId,    kEcdsaPubLen ) ) return false;
        if ( !ConstTimeEqual ( agreeBack, pubAgree, kEcdhPubLen  ) ) return false;

        bHasAgree = true;
        if ( FindAllowed ( sAllow2.c_str(), "SelfTest.Plain", pubBack,
                           agreeBack, &bHasAgree ) != IdOk ) return false;
        if ( bHasAgree ) return false;

        // A garbled third column is an error, NOT "this peer published none":
        // silently downgrading to unsealed is the failure mode worth refusing.
        std::vector<unsigned char> vText;
        if ( ReadWholeFile ( sAllow2.c_str(), vText, false, kMaxTextFile ) != IdOk )
            return false;
        std::string sHexId;
        HexEncode ( pubId, sizeof(pubId), sHexId );
        std::string sBad = "SelfTest.Garbled\t" + sHexId + "\tdeadbeef\n";
        vText.insert ( vText.end(), sBad.begin(), sBad.end() );
        if ( WriteWholeFile ( sAllow2.c_str(), &vText[0], vText.size(),
                              false, false ) != IdOk ) return false;

        AllowTally oIgnored;
        memset ( &oIgnored, 0, sizeof(oIgnored) );
        if ( LoadAllowList ( sAllow2.c_str(), TallyEntry, &oIgnored ) != IdErrFormat )
            return false;
    }

    // --- Revocation list ------------------------------------------------
    {
        EcdsaP256 oIdA, oIdB;
        EcdhP256  oAgreeC;
        if ( !oIdA.Generate() || !oIdB.Generate() || !oAgreeC.Generate() )
            return false;
        unsigned char pubA[kEcdsaPubLen], pubB[kEcdsaPubLen], pubC[kEcdhPubLen];
        if ( !oIdA.ExportPublic ( pubA ) || !oIdB.ExportPublic ( pubB ) ||
             !oAgreeC.ExportPublic ( pubC ) ) return false;

        // Missing file is NOT "nothing is revoked". Callers are required to
        // treat this as fail-closed, and it has to be distinguishable to do so.
        bool bRevoked = true;
        if ( IsRevoked ( sRevoke.c_str(), pubA, &bRevoked ) != IdErrNotFound )
            return false;

        // An IDENTITY key and an AGREEMENT key go in the same file. That is the
        // whole point of keying on the raw point: an operator revoking a
        // compromised peer cannot revoke it for login and forget sealing.
        if ( AppendRevocationList ( sRevoke.c_str(), pubA, 0, "rotated out" ) != IdOk )
            return false;
        if ( AppendRevocationList ( sRevoke.c_str(), pubC,
                                    1760000000LL, "compromised" ) != IdOk )
            return false;

        if ( IsRevoked ( sRevoke.c_str(), pubA, &bRevoked ) != IdOk ) return false;
        if ( !bRevoked ) return false;
        if ( IsRevoked ( sRevoke.c_str(), pubC, &bRevoked ) != IdOk ) return false;
        if ( !bRevoked ) return false;
        // ...and a key that was never listed is not revoked by association.
        if ( IsRevoked ( sRevoke.c_str(), pubB, &bRevoked ) != IdOk ) return false;
        if ( bRevoked ) return false;

        // The timestamp round-trips, and 0 means "not recorded" rather than
        // "revoked at the epoch".
        struct RevTally
        {
            size_t    nSeen;
            long long llLast;
        } oTally = { 0, -1 };
        if ( LoadRevocationList ( sRevoke.c_str(),
                [] ( void *pCtx, const unsigned char *, long long llWhen )
                {
                    RevTally *p = (RevTally *)pCtx;
                    p->nSeen++;
                    p->llLast = llWhen;
                }, &oTally ) != IdOk ) return false;
        if ( oTally.nSeen != 2 ) return false;
        if ( oTally.llLast != 1760000000LL ) return false;

        // Appending the same point twice is harmless - "is it revoked" does not
        // get more true - and must not break the parse.
        if ( AppendRevocationList ( sRevoke.c_str(), pubA, 0, 0 ) != IdOk ) return false;
        if ( IsRevoked ( sRevoke.c_str(), pubA, &bRevoked ) != IdOk ) return false;
        if ( !bRevoked ) return false;

        // A garbled line fails the WHOLE load. Skipping it would silently
        // un-revoke a key, which is the one error this file cannot afford.
        std::vector<unsigned char> vText;
        if ( ReadWholeFile ( sRevoke.c_str(), vText, false, kMaxTextFile ) != IdOk )
            return false;
        std::vector<unsigned char> vGood = vText;

        const char szTruncated[] = "deadbeef\n";
        vText.insert ( vText.end(), (const unsigned char *)szTruncated,
                       (const unsigned char *)szTruncated + sizeof(szTruncated) - 1 );
        if ( WriteWholeFile ( sRevoke.c_str(), &vText[0], vText.size(),
                              false, false ) != IdOk ) return false;
        if ( IsRevoked ( sRevoke.c_str(), pubA, &bRevoked ) != IdErrFormat )
            return false;

        // So does a non-numeric second column - which is what a reason written
        // without a leading '#' looks like to the parser.
        {
            std::string sHexA;
            HexEncode ( pubA, sizeof(pubA), sHexA );
            std::string sBad = sHexA + "\tyesterday\n";
            std::vector<unsigned char> v = vGood;
            v.insert ( v.end(), sBad.begin(), sBad.end() );
            if ( WriteWholeFile ( sRevoke.c_str(), &v[0], v.size(),
                                  false, false ) != IdOk ) return false;
            if ( IsRevoked ( sRevoke.c_str(), pubA, &bRevoked ) != IdErrFormat )
                return false;
        }

        // Restore, and confirm the good file still parses - so the two checks
        // above failed on the edit rather than on something left behind.
        if ( WriteWholeFile ( sRevoke.c_str(), &vGood[0], vGood.size(),
                              false, false ) != IdOk ) return false;
        if ( IsRevoked ( sRevoke.c_str(), pubA, &bRevoked ) != IdOk ) return false;
        if ( !bRevoked ) return false;
    }

    return true;
}

} // namespace p2pcng
