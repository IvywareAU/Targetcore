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
// ---------------------------------------------------------------------------
// crypto_selftest.cpp -- CI driver, and the ONLY thing in this repository that
// can be compiled and RUN without a sibling checkout.
//
// It is four function calls. It implements no cryptography, asserts no vectors
// of its own, and duplicates nothing: the known-answer tests, round-trips and
// refusal paths already live inside the library, exported precisely so that
// something outside it can invoke them (P2PCngCrypto.h:288-291 -- "the KATs are
// worth nothing if nothing invokes them"). This is that invoker for CI.
//
// WHY THIS BUILDS STANDALONE, WHEN NOTHING ELSE HERE DOES
//   Four translation units in this repository include no sibling header and no
//   stdafx.h -- P2PCngCrypto_openssl.cpp, P2PIdentityStore.cpp, P2PAuthLogin.cpp
//   and P2PeerSeal.cpp. Their only external dependency is OpenSSL 3. That is a
//   deliberate property (CMakeLists.txt:32-39: the login transcript and block
//   layout ARE the wire, so they are one #ifdef-free TU), and it is what lets
//   the security-critical core be verified by anyone who clones only this repo.
//
//   The CNG half of the same core canNOT be built this way: P2PCngCrypto.cpp:20
//   includes "stdafx.h", which pulls <afx.h>/<afxwin.h> and ../Platform/platform.h.
//   So this driver covers the OpenSSL backend only, and the Windows CNG backend
//   is verified solely by the sibling-complete build (see solution-build.yml).
//
// WHAT A PASS PROVES
//   AES-256-GCM, ECDH P-256, ECDSA P-256, HKDF-SHA256, HMAC-SHA256 and the
//   constant-time compare behave as specified on the OpenSSL backend; the
//   identity container round-trips through real files including its corruption
//   and truncation refusals; the login block round-trips and refuses unknown
//   peers, wrong keys, tampered signatures, replays, clock skew and a login
//   bound to a different destination; and the end-to-end seal round-trips and
//   refuses the wrong recipient, the wrong sender, a moved address pair and a
//   bit flipped in each region.
//
// WHAT A PASS DOES NOT PROVE
//   * Nothing about the CNG backend, and therefore NOTHING about whether a
//     Windows peer and a Linux peer agree on the wire. That is seal_interop's
//     job, and seal_interop needs the sibling MscsUnitTests checkout for its
//     vectors. Both backends passing their own self-tests is exactly the
//     "it mirrors the other backend" reasoning that has shipped bugs before.
//   * Nothing about the transport, the hub, the routing kernel, or whether any
//     of this crypto is reachable from a live connection. This links four TUs
//     out of thirty.
//   * Nothing about the security posture. These are the vendor's own tests of
//     the vendor's own code; SECURITY.md's "Independent security audit: not
//     done" is unaffected by a green run here.
// ---------------------------------------------------------------------------

#include "P2PCngCrypto.h"      // p2pcng::SelfTest
#include "P2PIdentityStore.h"  // p2pcng::StoreSelfTest
#include "P2PeerSeal.h"        // p2pseal::SealSelfTest
#include "P2PAuthLogin.h"      // p2pauth::AuthSelfTest

#include <cstdio>

namespace
{
    struct Case { const char *pszName; bool ( *pfn ) ( ); };

    const Case k_aoCases[] =
    {
        { "p2pcng::SelfTest       (AES-GCM / ECDH / ECDSA / HKDF / HMAC KATs)", &p2pcng::SelfTest      },
        { "p2pcng::StoreSelfTest  (identity container + allow-list refusals)",  &p2pcng::StoreSelfTest },
        { "p2pseal::SealSelfTest  (end-to-end seal round-trip + refusals)",     &p2pseal::SealSelfTest },
        { "p2pauth::AuthSelfTest  (signed login round-trip + refusals)",        &p2pauth::AuthSelfTest },
    };
}

int main ( )
{
    std::printf ( "TargetCore standalone crypto self-test (OpenSSL backend)\n"
                  "-------------------------------------------------------\n" );

    int nFailed = 0;
    for ( const Case &oCase : k_aoCases )
    {
        const bool bOk = oCase.pfn ( );
        std::printf ( "%-8s %s\n", bOk ? "PASS" : "FAIL", oCase.pszName );
        if ( !bOk ) ++nFailed;
    }

    std::printf ( "-------------------------------------------------------\n"
                  "%d of %d self-tests passed.\n",
                  int ( sizeof k_aoCases / sizeof *k_aoCases ) - nFailed,
                  int ( sizeof k_aoCases / sizeof *k_aoCases ) );

    if ( nFailed == 0 )
        std::printf ( "\nScope: OpenSSL backend only, 4 of 30 translation units. "
                      "This says nothing\nabout the CNG backend, the wire compatibility "
                      "between them, or the transport.\n" );

    return nFailed == 0 ? 0 : 1;
}
