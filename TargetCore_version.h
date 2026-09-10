// Copyright © 2000-2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  TargetCore_version.h - the single source of version identity.
//
//  NOTES: This header is the ONLY place a version number is written. It is
//         consumed by three parties that must never disagree:
//           - TargetCore.rc       -> the DLL's VERSIONINFO resource
//           - TargetCore.h        -> the macros a C++ consumer tests against
//           - TargetCore_c.h      -> the same, for the flat C / Panama surface
//         Bump it here and all of them move together. Before this header the
//         number was spelled out five separate times inside TargetCore.rc.
//       : It must stay preprocessor-only above the RC_INVOKED guard. rc.exe
//         compiles this file as well as the C++ compiler, and rc.exe
//         understands #define and nothing else - no types, no enums, no
//         inline functions, no const. Anything that is not a macro belongs
//         below the guard or in another header.
//       : It carries version identity and NOTHING else. The Windows platform
//         floor lives in targetver.h, which stdafx.h includes and nothing else
//         does. It stays out of here on purpose: the version macros are PUBLIC
//         - TargetCore.h and TargetCore_c.h both include this file, rc.exe
//         compiles it, and jextract reads it - and a Windows SDK pin is not
//         something to push into every consumer translation unit.
//       : Modelled on Msgcore\Msgcore_version.h, which does the same job for
//         the sibling component. The two version identities are deliberately
//         INDEPENDENT - TargetCore links Msgcore but does not ship as it, and
//         a shared number would force a lockstep release neither wants.
//       : Keep the release tag and this file in step: version 3.0.0 is tag
//         v3.0.0. A build whose DLL reports a version no tag matches cannot
//         be traced back to a source state, which defeats the point.
//       : WHAT THIS NUMBER PROMISES is written down in the versioning policy,
//         and has been a policy rather than a habit since 0.10.0. The short
//         form: the flat C ABI is the covered surface, the C++ classes are
//         not, and each wire format versions on its own byte. Do not bump
//         MAJOR here without reading it - the number is the promise, and this
//         file is where the promise is made.
//       : This is the build identity of the binary. It is NOT the wire
//         version. Whether two hubs can talk is decided by the auth block's
//         own version byte (P2PAuthLogin.cpp, kVersion) and by the identity
//         store's container version (P2PIdentityStore.cpp) - both of which
//         version independently and on purpose. Do not derive one from the
//         other.
//
#pragma once

//  Component version. MAJOR.MINOR.PATCH is the released identity; BUILD is
//  reserved for a CI build counter and is 0 for a hand-built binary.
//
//  3.0.0.0, the identity chosen for the first PUBLIC release. That number
//  was set by the project rather than derived from this tree's own release
//  history: the development identities that preceded it here were 0.9.0 and
//  then 0.10.0, and no binary carrying either of them was published.
//
//  The covered surface has GROWN since that tag: the security revision added
//  eight symbols to the flat C ABI - the per-class link policy, the trust
//  fence and the end-to-end waiver, with their getters - and changed the
//  meaning of none. Under the versioning policy that earns a MINOR, and this
//  file does not take it yet. The number moves when a release is tagged, not
//  when the surface that will carry it lands, so master sits at 3.0.0 with
//  unreleased work on top - the normal state between two tags.
//
//  WHAT THE MAJOR DOES NOT CLAIM, stated plainly because a 3 invites the
//  assumption. The flat C ABI is the covered surface - 101 symbols,
//  enumerated in .github/ci/abi-flat.manifest and gated - and it is the only
//  surface this number speaks for. The MESSAGE IMAGE is not versioned at
//  all: that image header has no version field and no spare bit (24 bits
//  size, 2 addressing, 6 endian sentinel), so a peer meeting a re-laid-out
//  message does not report a mismatch, it parses garbage. Releasing 3.0.0
//  neither freezes that image nor makes it safe to change.
#define TARGETCORE_VERSION_MAJOR  3
#define TARGETCORE_VERSION_MINOR  0
#define TARGETCORE_VERSION_PATCH  0
#define TARGETCORE_VERSION_BUILD  0

//  Comma form, for the FILEVERSION / PRODUCTVERSION resource statements,
//  which take four comma-separated words and cannot take a macro expression.
#define TARGETCORE_VERSION_COMMAS 3,0,0,0

//  String form. Kept spelled out rather than stringised from the parts above:
//  rc.exe's preprocessor has no reliable ## / # operator support, and a
//  VERSIONINFO string that silently expands to "TARGETCORE_VERSION_MAJOR.0.0"
//  would ship without anyone noticing.
#define TARGETCORE_VERSION_STRING "3.0.0.0"

//  Packed form, for a consumer that wants to compare rather than display.
//  0x03000000 is 3.0.0.0; the byte order is MAJOR, MINOR, PATCH, BUILD -- one
//  byte each.
#define TARGETCORE_VERSION_HEX    0x03000000

//  Fixed identity strings shared by the resource and any consumer that wants
//  to display provenance.
#define TARGETCORE_COMPANY_NAME   "Ivyware Pty Ltd, Khrustal & Mann"
#define TARGETCORE_PRODUCT_NAME   "P2Pmsg messaging core"
#define TARGETCORE_COPYRIGHT      "Copyright \251 2000-2026 Ivyware Pty Ltd, Khrustal & Mann. " \
                                  "Licensed under the Apache License, Version 2.0."

#ifndef RC_INVOKED

//  Wide form. The kernel's own string type is wchar_t throughout (P3PmsgData
//  takes LPCWSTR), so a hub reporting its version needs this rather than the
//  narrow spelling the resource compiler wants. Spelled out for the same
//  reason as TARGETCORE_VERSION_STRING - no stringising, nothing to drift
//  silently. Not available to rc.exe, which has no L"" in a VALUE statement.
#define TARGETCORE_VERSION_STRINGW L"3.0.0.0"

//  Compile-time guard for a consumer that needs a minimum version. Not
//  available to rc.exe, which cannot evaluate a function-like macro.
//
//    #if !TARGETCORE_VERSION_AT_LEAST(3,0,0)
//    #  error TargetCore 3.0.0 or later is required
//    #endif
//
#define TARGETCORE_VERSION_AT_LEAST(maj,min,pat) \
    ( ( (maj) << 24 | (min) << 16 | (pat) << 8 ) <= TARGETCORE_VERSION_HEX )

#endif  // RC_INVOKED
