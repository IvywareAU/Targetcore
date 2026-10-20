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
//  Targetcore_version.h - the single source of version identity.
//
//  NOTES: This header is the ONLY place a version number is written. It is
//         consumed by three parties that must never disagree:
//           - Targetcore.rc       -> the DLL's VERSIONINFO resource
//           - Targetcore.h        -> the macros a C++ consumer tests against
//           - Targetcore_c.h      -> the same, for the flat C / Panama surface
//         Bump it here and all of them move together. Before this header the
//         number was spelled out five separate times inside Targetcore.rc.
//       : It must stay preprocessor-only above the RC_INVOKED guard. rc.exe
//         compiles this file as well as the C++ compiler, and rc.exe
//         understands #define and nothing else - no types, no enums, no
//         inline functions, no const. Anything that is not a macro belongs
//         below the guard or in another header.
//       : It carries version identity and NOTHING else. The Windows platform
//         floor lives in targetver.h, which stdafx.h includes and nothing else
//         does. It stays out of here on purpose: the version macros are PUBLIC
//         - Targetcore.h and Targetcore_c.h both include this file, rc.exe
//         compiles it, and jextract reads it - and a Windows SDK pin is not
//         something to push into every consumer translation unit.
//       : Modelled on Msgcore\Msgcore_version.h, which does the same job for
//         the sibling component. The two version identities are deliberately
//         INDEPENDENT - Targetcore links Msgcore but does not ship as it, and
//         a shared number would force a lockstep release neither wants.
//       : Keep the release tag and this file in step: version 3.4.7 is tag
//         v3.4.7. A build whose DLL reports a version no tag matches cannot
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
//  3.4.7.0, a PATCH on 3.4.6. The covered surface did not move (103 symbols,
//  abi-flat.manifest unchanged), no class layout moved and nothing on the wire
//  changed. Added to the C++ surface, which the policy does not cover, as
//  3.4.3's ConState_AcceptUnnamed was: IdProtect_External (3) and
//  SetExternalProtector, a host-supplied wrap/unwrap for the private-key
//  payload of identity.key and agreement.key. P2PeerLan's Android app (A2)
//  registers AES-GCM under an Android Keystore key, so the plaintext keys exist
//  only in memory there, as DPAPI keeps them on Windows. Without a protector an
//  External save or load fails IdErrUnsupported; a refusing one gives
//  IdErrProtect / IdErrUnprotect. Pinned by StoreSelfTest.
//  ONE COMPATIBILITY NOTE: the identity container's version byte did not move,
//  but a 3.4.6-or-older build refuses a file with protection 3 as IdErrFormat.
//  Only a host that registers a protector writes one, so nothing existing is
//  affected; an External file is not portable to a build without the protector
//  anyway, by design.
//  BELOW IS THE 3.4.6 RATIONALE.
//  3.4.6.0, a PATCH on 3.4.5. The covered surface did not move (103 symbols,
//  abi-flat.manifest unchanged), no class layout moved, nothing on the wire
//  changed, and a Windows build compiles to the same code. It carries ANDROID:
//  the cores build with the NDK (clang, libc++, bionic; arm64-v8a and x86_64,
//  API 29+) for P2PeerLan's Android app (P2PeerLanAndroid, phase A0), which runs
//  them natively.
//  - P2P_IO_BACKEND (uring|epoll) picks the p2piocp backend; epoll is Msgcore
//    3.4.1's Platform/p2piocp_epoll.cpp, the default on ANDROID, where seccomp
//    blocks io_uring for apps. liburing is required only for uring.
//  - P2PmsgMaps.h: clang rejects the unqualified &Handler the BEGIN_*_MAP macros
//    wrote, even with -fms-extensions. Off MSVC each map's table now lives in a
//    static member function that typedefs P2PThisClass, and P2P_MEMFN_ADDR
//    qualifies with it; none of the 154 map sites changed, and the MSVC
//    expansion is byte-for-byte what it was. P2PeerTarget.h gives its
//    hand-written root maps the same typedef.
//  - P2PIdentityStore: Android's SELinux denies link(), which the exclusive
//    write used; it falls back to renameat2(RENAME_NOREPLACE) -- atomic, never
//    overwrites -- and still fsyncs the directory.
//  - WSA_Ext.h defines SOCKET only under _WIN32.
//  Box ctest 101/101 (uring) and 100/101 (epoll, a timing flake that passes
//  alone); Windows 96/96; P2PeerLan's native suite 11/12 on an Android 14
//  emulator (lan_ctl_test needs an app context for its socket file).
//  BELOW IS THE 3.4.5 RATIONALE.
//  3.4.5.0, a PATCH on 3.4.4: a performance change and nothing else. The
//  covered surface did not move (103 symbols, abi-flat.manifest unchanged), no
//  class layout moved and nothing on the wire changed. F-L4-2 (P2PeerLan L4):
//  a sealed, attested message cost ~2.5 ms. Measured again on 3.4.4 (Release,
//  loopback, through one relay) it is ~0.8 ms - 3.4.4's compaction took the
//  rest - and what remains is the EC work itself: the sender's ephemeral key,
//  the agreement and two signatures, the receiver's two verifies and the
//  agreement. That is the security and it stays. What this removes is the
//  one cost that bought nothing: every EC key object opened its own CNG
//  provider, ~33 us each, and the default seal + attest path makes one per
//  sender ephemeral and one per verifier. The ECDH and ECDSA providers are now
//  opened once per process and shared (SharedAlg in P2PCngCrypto.cpp; CNG
//  documents algorithm handles as thread-safe for key creation and import).
//  Ephemeral key 176 -> 138 us, peer-key import 69 -> 36 us, Open 400 -> 360
//  us. The lever that matters is message SIZE, since the cost is per message:
//  12 KB sealed bodies run at 15 MB/s, 28 KB at 32 MB/s, and 3.4.4 is what made
//  28 KB possible. Windows only; the OpenSSL backend has no provider objects.
//  BELOW IS THE 3.4.4 RATIONALE.
//  3.4.4.0, a PATCH on 3.4.3, and a SECURITY fix. The covered surface did not
//  move: .github/ci/abi-flat.manifest and Targetcore_c.h are unchanged, still
//  103 symbols, no class layout moved, and nothing on the wire changed format -
//  a 3.4.3 peer reads a 3.4.4 frame and the reverse. F-L4-1 (P2PeerLan L4,
//  2026-10-12): an end-to-end SEALED message carried its own PLAINTEXT. The
//  seal swaps the body in with SetData, which grows it inside the message's
//  heap and frees the old block without clearing it, and the send path puts
//  the whole heap in the frame - so any relay, holding no keys, could read the
//  body beside its ciphertext; the link cypher only hid it from the cable. The
//  same mechanism made a sealed frame ~2x its body, so a body over ~15 KB
//  broke the 32768-byte frame cap and the next hub dropped the LINK. Now
//  SealAppMsgOutbound zeroes the plaintext before the swap, and the send path
//  replaces a freshly sealed message with a copy in a heap sized to what is
//  live (CompactSealed in P2PeerCon.cpp). Guarded by p2p_sealwire, which reads
//  the FRAME at a keyless relay rather than Data(): red before (plaintext in a
//  6541-byte frame for a 2282-byte sealed body; 20 KB refused at 42445 bytes),
//  green after (3800 bytes; 20 KB delivered in 21752), and red again with the
//  compaction alone disabled. P2PeerLan's sealed-body workaround (13312) is
//  now conservative rather than necessary.
//  BELOW IS THE 3.4.3 RATIONALE.
//  3.4.3.0, a PATCH on 3.4.2. The covered surface did not move:
//  .github/ci/abi-flat.manifest and Targetcore_c.h are unchanged, still 103
//  symbols, and no class layout or vtable moved. Added to the C++ surface,
//  which the policy does not cover: ConState_AcceptUnnamed, a SERVICE bit.
//  P2PeerCon::AcceptSpawn copies the listener's peer address into every
//  accepted child, and OnAccept(addr) refuses to replace an address already
//  set, so a service that names its children after accept - _OldExamples
//  AKAserva, whose browsers become Webserver.<n> - had to clear the copy in its
//  own AcceptSpawn override, after the base had published the child to the hub
//  list and outside ThatAddrLock. With the bit set on the listener the base
//  gives the child an empty address before publishing it, and does not pass
//  the bit on. Guarded by p2p_acceptunnamed (positive control + the bit;
//  mutation-checked: red with the branch disabled).
//  BELOW IS THE 3.4.2 RATIONALE.
//  3.4.2.0, a PATCH on 3.4.1. The covered surface did not move:
//  .github/ci/abi-flat.manifest and Targetcore_c.h are unchanged, still 103
//  symbols, and no class layout moved. What it carries is a data race fix.
//  P2PeerHub::PostP2PeerCon walks the hub's posted connections on the
//  POSTER's thread and compared each one's address through GetP2Paddress(),
//  an unlocked reference, while that connection's pump rewrites
//  m_oThatP2Paddr in P2PeerCon::Login under ThatAddrLock. ConSignal(addr),
//  ConExists and ConQuery read it the same way, and so do P2PeerExpump's four
//  twins in P2PeerExplorer.cpp - the sites 3.3.2's CopyP2Paddress() work
//  missed. All eight now take the copy. TSan on the box: red by run 31 of
//  p2p_vnetmount without it, clean for 100 runs with it. (The libcrypto report
//  seen beside it on OpenSSL 3.5 is a false positive of an uninstrumented
//  libcrypto: never reported in 131 runs against a TSan-built OpenSSL 3.5.5.)
//  BELOW IS THE 3.4.1 RATIONALE.
//  3.4.1.0, a PATCH on 3.4.0. The covered surface did not move:
//  .github/ci/abi-flat.manifest and Targetcore_c.h are unchanged, still 103
//  symbols, and no class layout moved. What it carries is a defect fix.
//  ~P2PeerHub's F-TSAN-2 report - a hub destroyed with its spawned pump still
//  running - exists to REPORT rather than assert, but it was one
//  P2Pevent::Message() of ~320 characters, and Msgcore VERIFYs each formatted
//  line is under 255. So in every Debug build the report itself aborted the
//  process (exit code 3) at shutdown, which is how _OldExamples\AKAssms found
//  it. The text is now one Message() plus Advice() lines. Two refusals in
//  P2PeerConPipe had the same shape (324 and 310 characters) and are split
//  the same way. Guarded by p2p_hubdtorreport (red on 3.4.0), and by a new
//  repo invariant [8] that fails on any Message()/Advice() literal over 253.
//  And a data race the 3.4.1 CI found: P2PeerConDmx::Accept() read m_pConThat
//  and created the accept OVERLAPPED with no lock, while Listen() had already
//  published the service to clients whose Connect() reads both under
//  g_oCSectP2PeerConDmx. TSan, four reports in Connect(); first exercised by
//  p2p_vnetmount, which 3.4.0's CI never ran. Now under that lock - red on the
//  first TSan run without it, clean for 20 runs with it.
//  BELOW IS THE 3.4.0 RATIONALE.
//  3.4.0.0, a MINOR on 3.3.2, earned by a BEHAVIOURAL break that no symbol
//  records, as 3.2.0's was. The covered surface did not move:
//  .github/ci/abi-flat.manifest and Targetcore_c.h are unchanged, still 103
//  symbols. VERSIONING.md records it as the ninth break: a ':' in an address
//  is now a hop boundary. Until now nothing parsed it, so "VNetA:Root.X" named
//  a hub whose first hop was literally "VNetA:Root". Now V:x is x inside the
//  network MOUNTED at hub V, and a message to it routes towards V. An address
//  with no colon compares byte for byte as before; a mixed 3.3/3.4 tree
//  disagrees only about an address that has one.
//  What it carries:
//  - VNet mounts. P2Paddr::GetVNet / GetVNetAddr / HasVNet, and ':' in
//    IsChild / IsRable. P2PeerCon::SetVNetMount makes a link a gateway between
//    two trees: it rewrites H:x -> x and s -> P:s, opens seals and drops the
//    origin's attestation (P2PeerMsg::ClearRelayAttest), so end-to-end sealing
//    and attestation stop at a mount by design. RouteP2PeerMsg routes into a
//    mount. Guarded by p2p_vnetmount, which is mutation-checked.
//  - F-L7-2. An auto-restarted authenticated link skipped the key agreement
//    and was refused for good. Restart() now calls KeyXReset(). Guarded by
//    p2p_restartkeyx.
//  The C++ class layout DID change, which the policy does not cover but a
//  consumer will feel: P2Paddr lost m_strVNetname / m_strVNetaddr (never set),
//  P2PeerCon gained m_oVNetPeer, and GetVNet() is now const and returns
//  LPCTADDR. Rebuild every C++ consumer against this header.
//  BELOW IS THE 3.3.2 RATIONALE.
//  3.3.2.0, a PATCH on 3.3.1. The covered surface did not move:
//  .github/ci/abi-flat.manifest and Targetcore_c.h are unchanged, still 103
//  symbols. It carries the races ThreadSanitizer found once P2PeerWeb W4 ran
//  under it against 3.3.1 -- none in 3.3.1's own fix, all older:
//  - g_oCSectP2PeerConDmx was initialised lazily by the first DMX
//    constructor behind an unguarded flag; two threads building their first
//    DMX connections could both initialise it. Now once, at load.
//  - the thread-id -> pump registry was looked up under whatever lock each
//    caller held while pumps were inserted under another; it has its own.
//  - AcceptSpawn posted the child to the hub list BEFORE settling its mode,
//    address and the rest, so walkers on other threads read a half-built
//    connection. It now posts last.
//  - login rewrites a connection's peer address on its pump while walkers
//    elsewhere compared it. P2PeerCon::CopyP2Paddress() copies it under the
//    lock those rewrites now take (striped, outside the object).
//  - P2PeerConDmx::Connect read m_pConThat unlocked while the service's
//    AcceptSpawn rewired it; it reads under g_oCSectP2PeerConDmx.
//  Added to the C++ surface: P2PeerCon::CopyP2Paddress. The class layout did
//  not change.
//  BELOW IS THE 3.3.1 RATIONALE.
//  3.3.1.0, a PATCH on 3.3.0. The covered surface did not move:
//  .github/ci/abi-flat.manifest and Targetcore_c.h are unchanged, still 103
//  symbols. What it carries is a defect fix. P2PeerHub::ConSignal walked a
//  hub's connections as raw pointers and Signal()ed them; called off the pump
//  (P2PeerWeb's session-close worker), the pump's last Release() could delete
//  one between the walk and the Signal -- an m_cRef==0 abort in ~P2PeerConPlc,
//  or a use-after-free, intermittent on Linux. Release() now claims a dying
//  connection before unlinking it, and ConSignal signals only connections it
//  retained under the lock the delete path unlinks under (TryAddRef,
//  RetainP2PmsgCons). ConQuery, ConExists and PostP2PeerCon's duplicate check
//  walked the same raw pointers from callers' threads and now retain too --
//  ConQuery's SafeP2PeerCon assignment was the very same revive-a-dying-object
//  AddRef. Added to the C++ surface, which the policy does not cover:
//  P2PeerConPlc::TryAddRef, the exported RetainP2PmsgCons, and the
//  header-only P2PretainedCons scope that P2PeerWeb and TargetFacade now walk
//  with. The class layout did not change.
//  BELOW IS THE 3.3.0 RATIONALE.
//  3.3.0.0, a MINOR on 3.2.1, and this time BECAUSE the covered surface grew:
//  .github/ci/abi-flat.manifest goes 101 -> 103 symbols with
//  p2peerconwsa_set_family / p2peerconwsa_get_family, and none moved. That
//  is the policy's definition of a MINOR, not a judgement call.
//
//  What it carries is IPv6 for every caller. P2PeerConWsa::SetFamily has
//  existed since 2026-08-28 but only on the C++ class, so no binding could
//  reach it; the two entry points expose it (0 IPv4, 1 IPv6, 2 Dual, range
//  checked at the boundary). And one inference: a CLIENT constructed with an
//  IPv6 literal starts in IPv6, because under the IPv4 default it could never
//  resolve its own target. Nothing that connected before changes -- IPv4 is
//  still the default for every service and every client given a name or a
//  dotted quad.
//
//  BELOW IS THE 3.2.1 RATIONALE.
//
//  3.2.1.0, a PATCH on 3.2.0. The covered surface did not move:
//  .github/ci/abi-flat.manifest and Targetcore_c.h are byte-identical to
//  v3.2.0, still 101 symbols, and no behaviour a peer can observe broke.
//
//  What it carries is a defect fix and a header. The fix: a DMX connection
//  dropped its PEER from its own pump -- OnClose() and Close() called
//  pConThat->Drop(0) from the other hub's thread, which raced that hub's pump
//  over the peer's recv OVERLAPPED and freed it twice, the intermittent
//  0xC0000005 at teardown of every DMX harness; and the accept-at-capacity
//  refusal did the same to a client mid-connect. The peer is now told on its
//  own pump (P2PeerConDmx_BREAK_PAIR), and a refused client fails its connect
//  with ERROR_CONNECTION_REFUSED and closes itself. The header is
//  P2PeerAppFields.hpp -- AppFields(msg), named fields on a P2PeerMsg in the
//  facade's own wire format, so a direct client and a facade client read each
//  other's fields. Header-only C++ surface, which the policy does not cover:
//  it informs a MINOR without compelling one.
//
//  BELOW IS THE 3.2.0 RATIONALE.
//
//  3.2.0.0, the fourth PUBLIC release and a MINOR on 3.1.1.
//
//  MINOR, and NOT because the covered surface grew - it did not.
//  .github/ci/abi-flat.manifest is byte-identical to v3.1.1 and still
//  enumerates 101 symbols; nothing was added, removed or redefined. The bump
//  is earned by a BEHAVIOURAL break that no symbol records, and PATCH would
//  hide it: the session cypher now derives TWO keys, one per direction, under
//  the info strings "P2P-session-v1-c2s" and "P2P-session-v1-s2c" instead of
//  one under "P2P-session-v1". A peer running the old derivation and one
//  running the new derive different keys and open NOTHING of each other's -
//  not some messages, the first one. Both ends must upgrade together.
//  VERSIONING.md records it as the eighth break; no wire byte changed, which
//  is exactly why the number has to carry it.
//
//  What else this release carries, none of it on the covered surface: the
//  accept bound is enforced on the pipe and DMX transports rather than
//  documented at them, an accepted DMX connection is destroyed so its accept
//  slot returns, the Linux pipe refusal no longer orphans its completion
//  port, and the upcast relay is dispatched for the first time - a
//  P2Pmsg_UCast ID, a map entry and a RequireSealUpcast switch of its own.
//  Those last are C++ class surface, which section 3 of the policy does not
//  cover, so they inform the MINOR without compelling it.
//
//  BELOW IS THE 3.1.1 RATIONALE, kept because the compatibility note in it
//  still points backwards at a build that is still out there.
//
//  3.1.1.0, the third PUBLIC release and a PATCH on 3.1.0. The MAJOR was not
//  derived from this tree's own release history: 3.0.0 was the identity the
//  project chose for the first public release, and the development identities
//  that preceded it here were 0.9.0 and then 0.10.0, neither of which was
//  ever published.
//
//  The MINOR is what the security revision earned. That pass ADDED eight
//  symbols to the flat C ABI - the per-class link policy, the trust fence and
//  the end-to-end waiver, with their getters - and changed the meaning of
//  none, which is a MINOR under the versioning policy and nothing more. It
//  was left unbumped while the work sat on master unreleased, because the
//  number moves when a release is tagged rather than when the surface that
//  will carry it lands. v3.1.0 took it.
//
//  The PATCH is what 3.1.0 needed. Every workflow that would have caught it
//  was billing-blocked on the day it was tagged, so v3.1.0 shipped with no CI
//  run at all - zero steps executed, across all four jobs - carrying three
//  defects the gates exist to stop: the Linux build did not compile, the
//  ECDSA P-256 known-answer vectors did not verify, and the DPAPI entropy had
//  been recased. The covered surface is untouched - still 101 symbols, none
//  added, removed or redefined - so this is a PATCH and nothing more.
//
//  ONE COMPATIBILITY NOTE, and it points BACKWARDS rather than forwards: an
//  identity file written by a 3.1.0 binary, and only by one of those, cannot
//  be read here. The recased entropy is an input to CryptUnprotectData, so
//  3.1.0 is the build that disagreed with every other; 3.0.0 and 3.1.1 agree.
//
//  WHAT THE MAJOR DOES NOT CLAIM, stated plainly because a 3 invites the
//  assumption. The flat C ABI is the covered surface - 101 symbols,
//  enumerated in .github/ci/abi-flat.manifest and gated - and it is the only
//  surface this number speaks for. The MESSAGE IMAGE is not versioned at
//  all: that image header has no version field and no spare bit (24 bits
//  size, 2 addressing, 6 endian sentinel), so a peer meeting a re-laid-out
//  message does not report a mismatch, it parses garbage. Releasing 3.1.1
//  neither freezes that image nor makes it safe to change.
#define TARGETCORE_VERSION_MAJOR  3
#define TARGETCORE_VERSION_MINOR  4
#define TARGETCORE_VERSION_PATCH  7
#define TARGETCORE_VERSION_BUILD  0

//  Comma form, for the FILEVERSION / PRODUCTVERSION resource statements,
//  which take four comma-separated words and cannot take a macro expression.
#define TARGETCORE_VERSION_COMMAS 3,4,7,0

//  String form. Kept spelled out rather than stringised from the parts above:
//  rc.exe's preprocessor has no reliable ## / # operator support, and a
//  VERSIONINFO string that silently expands to "TARGETCORE_VERSION_MAJOR.0.0"
//  would ship without anyone noticing.
#define TARGETCORE_VERSION_STRING "3.4.7.0"

//  Packed form, for a consumer that wants to compare rather than display.
//  0x03040700 is 3.4.7.0; the byte order is MAJOR, MINOR, PATCH, BUILD -- one
//  byte each.
#define TARGETCORE_VERSION_HEX    0x03040700

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
#define TARGETCORE_VERSION_STRINGW L"3.4.7.0"

//  Compile-time guard for a consumer that needs a minimum version. Not
//  available to rc.exe, which cannot evaluate a function-like macro.
//
//    #if !TARGETCORE_VERSION_AT_LEAST(3,0,0)
//    #  error Targetcore 3.0.0 or later is required
//    #endif
//
#define TARGETCORE_VERSION_AT_LEAST(maj,min,pat) \
    ( ( (maj) << 24 | (min) << 16 | (pat) << 8 ) <= TARGETCORE_VERSION_HEX )

#endif  // RC_INVOKED
