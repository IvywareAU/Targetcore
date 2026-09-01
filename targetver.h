//  Windows platform floor.
//  NOTES: Windows 8.1 is the lowest this code can build against.
//         P2PCngCrypto.cpp derives the ECDH shared secret with
//         BCRYPT_KDF_RAW_SECRET, which bcrypt.h gates on NTDDI_WINBLUE.
//       : BCryptDeriveKey itself IS present on Windows 7, so hard-coding the
//         string would link and load there, then fail at key agreement with
//         STATUS_NOT_SUPPORTED. The pin turns that into a compile error.
//       : Compile-time gate only. It does not change the PE minimum OS version
//         (linker default, 6.00) and it cannot see APIs resolved dynamically
//         through WSAIoctl/SIO_GET_EXTENSION_FUNCTION_POINTER, as ConnectEx is.
//       : Msgcore/targetver.h is kept in step; this project links Msgcore.dll.
//
#pragma once

#include <WinSDKVer.h>
#define _WIN32_WINNT _WIN32_WINNT_WINBLUE
#include <SDKDDKVer.h>
