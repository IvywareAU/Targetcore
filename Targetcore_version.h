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
//       : Keep the release tag and this file in step: version 3.6.0 is tag
//         v3.6.0. A build whose DLL reports a version no tag matches cannot
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
//  3.11.2.0, a PATCH on 3.11.1; runs on Msgcore 3.7.1. The flat C API, every
//  exported class layout and every wire format are unchanged.
//
//  A LOST WAKE IN THE SHARED-MEMORY TRANSPORT (p2p_performance F-P4-12a).
//  P2PeerioShm::Service could sleep with a write and a read both pending and no
//  wake to come: the write found the ring full, then withdrew its park because
//  the peer had drained it meanwhile (WriterPark false = "retry", not "sleep"),
//  and in the same pass the read parked. The pass slept; the write's word was
//  already 0, so the peer never signalled, and the peer was waiting for this
//  write. Two shm connections then hung until their timeout. A pass now sleeps
//  only when every pending side actually parked; otherwise it goes round again.
//  When the 64-pass guard runs out with work pending, the side signals its own
//  wake (SignalSelf) so the pump comes straight back instead of sleeping.
//  RESULT: MscsUnitTests shm_xproc on the Linux VM, base 4 hangs in 150 runs,
//  fixed 0 in 450. Windows never showed it; shm tests x20 green there.
//
//  BELOW IS THE 3.11.1 RATIONALE.
//
//  3.11.1.0, a PATCH on 3.11.0; runs on Msgcore 3.7.1. The flat C API, every
//  exported class layout and every wire format are unchanged.
//
//  A HUB-ADDRESS INDEX (p2p_performance F-P4-11). IsP2PmsgHubInProcess and
//  IsP2PmsgHubSealWaivedInProcess walked every hub in the process under the
//  process hub lock; the first is asked for every message not on its last hop.
//  A map of address to registry entries, under that same lock, now answers.
//  P2PmsgHubMgr::SetAddr is the only writer of a hub's registry address. Two
//  hubs on one address fall back to the walk, so the registry's order still
//  decides. Debug builds, and P2P_ROUTE_CHECK, compare each answer with the walk
//  and abort on a disagreement.
//  THE CHECK MARKERS PRINT ON LINUX. HUB-ADDR-MISMATCH (new) and 3.11.0's
//  ROUTE-INDEX-MISMATCH used a narrow fprintf, silent once stderr is wide.
//  RESULT (perf_fanout fan, p50 medians, thr_last, all hubs in one process):
//  Linux VM C=250 +66% and +74%, C=64 +11% to +14%, flat from C=1 to 250.
//  Windows: no throughput gain; C=250 latency -2.6/-2.7%; C=16 and 64 throughput
//  0.3% to 2.1% lower, cause not known.
//
//  BELOW IS THE 3.11.0 RATIONALE.
//
//  3.11.0.0, a MINOR on 3.10.1; runs on Msgcore 3.7.1. The flat C API, every
//  exported class layout and every wire format are unchanged.
//
//  A ROUTE INDEX (p2p_performance F-P4-10). RouteP2PeerMsg asked every
//  connection of the hub in list order. P2PmsgHubMgr now also files a connection
//  strictly below the hub under its one segment below the hub, and a pick asks
//  that bucket and a walk list holding everything else. The predicate is
//  unchanged and the first match in list order still wins. A connection is
//  bucketed only once its address was assigned through AssignP2PmsgConAddr,
//  which writes and re-files in one hold of the lock the pick takes.
//  ONE RULE: a P2PeerCon subclass must not write m_oThatP2Paddr directly after
//  login, or its messages may be mis-routed. Before login it may. Hence MINOR.
//  Debug builds repeat the full walk and throw on a disagreement; Linux, where
//  _DEBUG is never defined, needs -DP2P_ROUTE_CHECK. (For the same reason
//  3.9.1's RouteHub_PickRef check never ran on Linux.)
//  RESULT (perf_fanout fan, p50 medians, C=250 thr_last): +41.5% Windows
//  (7 rounds), +36.4% Linux VM (10 rounds). Still falls with C: from C=1 to 250
//  by 7% on Windows and 38% on Linux.
//
//  BELOW IS THE 3.10.1 RATIONALE.
//
//  3.10.1.0, a PATCH on 3.10.0, paired with Msgcore 3.7.1. The flat C API, every
//  class layout and every wire format are unchanged.
//
//  A RECEIVED MESSAGE IS STRUCTURALLY CHECKED AT THE GATE (MSCS performance log
//  F-P6-6). 3.10.0 said received messages were verified as before - that was
//  wrong on one path. The ingress heap walk proves a frame's BLOCK structure but
//  not the OBJECT GRAPH those blocks form, and the whole-tree check that would
//  (P2PeerMsg::AssertValid) was not run on the receive path at all: the inline
//  recv->dispatch (W3) never called it, and so a frame carrying a forged sibling
//  cycle hung the pump thread inside GetSource() - a one-frame denial of service
//  from any logged-in peer - while a forged descendant cycle overflowed the
//  stack. GateAppMsgInbound now calls AssertValid on every inbound application
//  message, before the source is read, unconditionally (the untrusted path; the
//  g_bP2Pmsg_AssertValid switch governs our OWN outbound posts, not this). That
//  walk is bounded against forged graphs by Msgcore 3.7.1, which this requires;
//  a corrupt frame is refused and the connection dropped, as any bad frame is.
//  PATCH: a bug fix, no surface change.
//
//  BELOW IS THE 3.10.0 RATIONALE.
//
//  3.10.0.0, a MINOR on 3.9.1, paired with Msgcore 3.7.0 (its Platform/p2pshm.h
//  is compiled in, so this does not build on an older Msgcore).
//
//  (1) A SHARED-MEMORY TRANSPORT (p2p_performance 6.3a): P2PeerConShm and
//  P2PeerioShm. A named pipe (AF_UNIX socket on Linux) stays the rendezvous,
//  access control, accept cap, trust class and death watch; the bytes go
//  through two rings in a shared mapping. Windows wakes the pump with
//  NtAssociateWaitCompletionPacket and IsSupported() is false without it.
//  P2Peerio gains FIVE VIRTUALS - HasQueuedOwnOVERLAPPED, ForgetOwnOVERLAPPED,
//  IoWrite, IoRead, IoGathers - so its VTABLE CHANGES and every subclass must
//  be recompiled. The C++ classes are not the covered surface; the flat C ABI
//  does not move.
//
//  (2) THE ROUND TRIP (F-P6-5), which profiling put in the message object model
//  (61% of the CPU) and not in the transport (0.5%). (a) PutP2Pmsg takes
//  bVerify; the hub's own posts pass g_bP2Pmsg_AssertValid, whose Release
//  default Msgcore 3.7.0 makes false. Every other producer, the receive
//  fallback included, verifies as before. (b) Dispatch compares the
//  destination once, GateAppMsgInbound reads the source once, the send path
//  skips the seal chain when the hub does not seal, and WaivedBodyLeavesProcess
//  asks its last-hop test before its field reads. (c) P2PeerMsg::InitNetAddr
//  (new, protected, non-virtual) builds the Net item in one pass; the
//  P2PeerMsgnn constructor template calls it, so a program compiled against
//  this header needs this DLL. Images byte-identical (unit_suite, 72 compared).
//  RESULT (perf_ab, two processes, posture A, 5 rounds, medians of p50, 64 B
//  and 4 KB, wsa / pipe / shm): RTT -28..-36% Windows, -8..-26% Linux VM;
//  pipelined +61..+83% and +41..+65%.
//
//  BELOW IS THE 3.9.1 RATIONALE.
//
//  3.9.1.0, a PATCH on 3.9.0: the route walk measures each address once
//  (p2p_performance F-P4-9, option (a)). P2PeerHub::RouteP2PeerMsg tests the
//  hub's connections in list order (T4, 3.7.2), and every test re-ran wcslen
//  on the destination, the hub and the connection and compared the full
//  strings: at 250 connections the walk was ~85% of the router pump's extra
//  time, ~35 us per message (Linux perf). RouteHub_Ask now carries the hub's
//  and the destination's lengths and hub.IsRable(dst), once per message, and
//  each connection's address is measured once; RouteHub_IsChild / _IsRable
//  are P2Paddr::IsChild / IsRable test for test on those lengths (the hop
//  boundary kept in step with P2PaddrIsHopBoundary). Same tests, same order,
//  first match wins. Assumes no embedded NUL in an address. Debug builds
//  check every answer against the 3.9.0 predicate (RouteHub_PickRef) and
//  throw on a disagreement; a mutant inverting the parent test was caught by
//  it in p2p_e2ewaive.
//  RESULT (perf_fanout fan C 500 10000, p50 medians; Windows 7 rounds, Linux
//  VM 5): thr_last at C=250 19.8k -> 25.8k msg/s (+30%) and 10.3k -> 13.0k
//  (+26%); C=1 and 64 within 5% (Linux C=64 +11%); all_round at 250 -8% and
//  -12.5%; latency unchanged (10-round recheck). Still O(C): throughput still
//  falls with C. The covered surface and the export table do not move.
//  CI (a563c0a), first exercised by this tag: a push to master
//  no longer re-runs the sanitizer and solution-build workflows for a commit
//  that already went green on its branch, tags trigger no CI at all, and the
//  release workflow names the newest run that actually TESTED the commit
//  rather than the newest one that merely succeeded (a skipped run concludes
//  success too).
//    : Two P3 levers were tried on top of 3.9.0 and dropped, so they are not
//      here either: T3 step 2 (direct idle send) and GetQueuedCompletionStatusEx
//      batching (p2p_performance_progress.md, F-P3-6 - the pump must drain its
//      FIFO between completions).
//
//  BELOW IS THE 3.9.0 RATIONALE.
//
//  3.9.0.0, a MINOR on 3.8.0: gather send (p2p_performance.md T3, step 1).
//  A connection wrote ONE frame per transport write and took the next message
//  off its queue only when that write completed. On the stock transport
//  (P2Peerio exactly - TCP, named pipe, serial) the send completion now stages
//  every queued message it can, up to 64 frames or 64 KB, and writes them with
//  ONE write, in queue order. Each is still prepared alone - IF transform,
//  VNet, end-to-end seal, attestation, trim, frame cap, link cypher - by the
//  same code (P2Peerio::PrepareSendFrame, factored out of SendP2PeerMsg), so
//  the wire is the frames that would have gone out one by one, back to back;
//  any receiver reads them. A lone frame is written from where it lies, no
//  copy; the pending frame is copied BEFORE the next is prepared, because the
//  cypher's swap buffer is overwritten by the next encryption. State lives in
//  the send OVERLAPPEDcon's pUserDB1 (P2PeerioSendGather), so no exported class
//  changes layout. Subclasses (P2PeerioDmx, P2PeerioBSTR, P2PeerWeb's
//  WebIoHttp) keep one SendP2PeerMsg per message. P2P_SEND_GATHER=0 turns it
//  off. MINOR, not PATCH: P2Peerio gains public non-virtual methods (new
//  exports: CanGatherSend, ResetStaged, StageP2PeerMsg, GatherFull,
//  SendStaged) and P2Peerio.h the gather layout; no vtable slot moves.
//
//  RESULT (5 rounds alternated, same binaries, P2P_SEND_GATHER=0 vs on):
//  pipelined perf_ab throughput +56.6% Windows / +43.9% Linux, CPU per message
//  -38% / -32%; fan C=64 thr_last +84.0% / +26.5%; one-way latency flat. Linux
//  syscalls -73% (io_uring_enter -95%). MscsUnitTests p2p_sendgather is the
//  correctness gate, shown red on a copy-too-late mutation.
//
//  BELOW IS THE 3.8.0 RATIONALE.
//
//  3.8.0.0, a MINOR on 3.7.6: one bulk read, many frames (p2p_performance.md
//  T2). P2Peerio::RecvP2PeerMsg read every frame in two transport reads - the
//  8-byte oSync header, then the body into a buffer sized from it - so two
//  submissions and two completions per message however many frames the
//  transport already held. A 16 KB receive ring per connection now takes
//  whatever the transport has in one read, and every complete frame in it is
//  handed out before the next read; a frame bigger than the ring finishes in a
//  buffer of its own, as before. Same checks, same refusal messages, at the
//  same point in a frame's arrival; a read request is never empty, so a
//  zero-byte completion is still only FIN. MINOR, not PATCH: P2Peerio.h gains
//  the ring layout and its helpers (P2PeerioRecvRing, P2PeerioRecvRequest,
//  P2PeerioRecvPending - inline, no export added or removed), and a subclass
//  or harness that wrote into a receive OVERLAPPEDcon's buffers itself must
//  use them; MscsUnitTests' three such harnesses do. Memory: +16 KB per
//  connection that has received.
//
//  RESULT (5 rounds alternated, base 3.7.6, only the libraries swapped):
//  Linux VM io_uring_enter one fewer per message, total syscalls -27%.
//  One-way latency -6.1% Windows, -5.7% Linux; fan C=64 thr_last +14.2% /
//  +10.2%. Pipelined perf_ab throughput -1.5% Windows (5/5 rounds), +2.0%
//  Linux - that path reads as sender-bound (T3). Allocations unchanged.
//
//  Also: TARGETCORE_VERSION_COMMAS was left at 3,7,5,0 in 3.7.6, so the 3.7.6
//  DLL's binary FILEVERSION/PRODUCTVERSION resource read 3.7.5.0 (its strings
//  read 3.7.6.0). Every form reads 3.8.0.0 here.
//
//  BELOW IS THE 3.7.6 RATIONALE.
//
//  3.7.6.0, a PATCH on 3.7.5: timers in milliseconds (p2p_performance.md
//  T8). Every PITimer deadline was _time64(0)*1000 + delay - wall-clock
//  SECONDS scaled to milliseconds - and PollTimer compared against the same
//  clock, so "now" moved once a second: a timer with a delay under 1000 ms
//  fired when the second turned, anywhere from ~0 to 1000 ms after it was set,
//  and a wall-clock step moved every deadline with it. The deadlines use
//  P2PtimerNowMs() now, steady_clock in milliseconds: monotonic, millisecond
//  resolution. They are only ever compared with each other and with that
//  clock, so nothing outside the timer queue sees the change. The connect
//  wait in P2PeerConDmx had the same shape (0..1000 ms for "one second") and
//  is a steady_clock deadline 1000 ms ahead. Left alone on purpose:
//  P2PeerCon's iRestartTime (an informational value no caller reads; the
//  restart timer itself is relative) and P2PeerService's 5 s waits.
//
//  RESULT: MscsUnitTests p2p_timerres (50 ms timer, re-armed ten times, each
//  fire in [49, 250] ms) is red on 3.7.5 - 10 of 10 fires at 708..1014 ms -
//  and green here: 49..51 ms Windows, 50..64 ms Linux VM. Flat C API,
//  exports, layouts and wire formats unchanged; runs on Msgcore 3.5.1 or later.
//
//  BELOW IS THE 3.7.5 RATIONALE.
//
//  3.7.5.0, a PATCH on 3.7.4: the address getters read in one lookup
//  (p2p_performance.md T7, step 2). P2PeerMsg::GetSource, GetDestin and
//  GetScopeOrDestin asked Exists(name) and then fetched through operator[]:
//  two walks of the network node's fields, and the fetch gave the node item a
//  heap descriptor and a heap cursor. They read through NetAddrRead now - one
//  SelectObject(name), whose descriptor and cursor are on the stack since
//  Msgcore 3.6.1, and c_wstr() off a field built over the object it found.
//  Present-but-empty still answers present. Same answers; on an older Msgcore
//  the lookup allocates as it did, nothing else changes.
//
//  RESULT (5 rounds alternated, base 3.7.3 on Msgcore 3.6.1, same binaries):
//  allocations per message, Linux perf_ab 34 -> 30, B5 fan C=64 51 -> 44.
//  Linux VM perf_ab throughput +9.5% (CPU/msg -7.1%), one-way latency -5.3%;
//  fan C=64 thr_last +8.7%. Windows perf_ab one-way -1.7% (CPU -13%),
//  throughput +0.5%; fan C=64 -2% latency, +2% throughput - the Windows heap
//  costs less per allocation than glibc malloc across two threads. Flat C API,
//  exports, layouts and wire formats unchanged.
//
//  BELOW IS THE 3.7.4 RATIONALE.
//
//  3.7.4.0, a PATCH on 3.7.3: BUILD SETTINGS ONLY, no source change. The
//  Visual Studio project's Release and ReleaseLib configurations were
//  compiled /Ob1 (InlineFunctionExpansion=OnlyExplicitInline) where the CMake
//  build is /Ob2; they are /Ob2 (AnySuitable) now. /Ob1 alone made the
//  msbuild DLLs ~20% slower than the CMake DLLs of the same code (MSCS
//  performance log F-P4-8: perf_ab throughput 22.1k against 27.9k msg/s).
//  With Msgcore 3.6.2 the msbuild DLLs read one-way ~94 us and ~26.4k msg/s,
//  ~4% from CMake (Msgcore keeps /sdl). Exports, layouts, wire formats same;
//  runs on Msgcore 3.5.1 or later as before.
//
//  BELOW IS THE 3.7.3 RATIONALE.
//
//  3.7.3.0, a PATCH on 3.7.2: a pump visit takes no process-wide lock
//  (p2p_performance.md T5). PumpP2Pmsg and WaitForP2Pmsg found their own pump
//  under s_oCSectionP2PmsgPump, the lock every thread posting to that pump
//  also takes; strace -k put the contended waits there, pump against poster.
//  Each pump thread now finds its pump through t_pP2PmsgPumpSelf (set and
//  cleared on that thread), and a visit holds only the pump's own m_oCSection.
//  THE DEFECT ALONG THE WAY: the timer queue was read under
//  s_oCSectionP2PmsgPump while SetP2PmsgTimer for a P2Peerio or a P2PeerTarget,
//  and NextP2PmsgTimer, wrote and read it under s_oCSectionP2Pmsg - two locks
//  around one CList. Latent: those two overloads only ever act on their own
//  thread's pump, so it needed a connection timer armed off the pump at the
//  same moment. Every timer-queue access (the four SetP2PmsgTimer overloads,
//  NextP2PmsgTimer, KillP2PmsgTimer, CancelP2PmsgTimer, the pump's visit) is
//  now under the pump's m_oCSection, nested inside the lock each already took.
//  Cross-thread posts and signals keep the global lock, which is also what
//  keeps their target pump alive.
//  RESULT: no throughput or latency change outside noise (profiled ceiling:
//  all mutex time ~1.6% of library CPU); futex calls -28% at the median. TSan
//  clean (ten timer-heavy gates and teardown_stress). The covered surface,
//  every exported symbol and class layout, and every wire format are
//  unchanged. Runs on Msgcore 3.5.1 and later.
//
//  BELOW IS THE 3.7.2 RATIONALE.
//
//  3.7.2.0, a PATCH on 3.7.1: the router picks its connection in one walk
//  (p2p_performance.md T4). P2PeerHub::RouteP2PeerMsg walked the hub with
//  EnumP2PmsgCon, and every EnumP2PmsgCon step re-took the process-wide
//  s_oCSectionP2PmsgHub, looked the hub up again and re-scanned the list from
//  the head: routing to the C-th connection was C lock acquisitions and
//  ~C^2/2 list steps. It now asks PickP2PmsgCon (P2Pwin32.cpp, internal to the
//  DLL), one walk under one acquisition, with the old loop body as its
//  predicate: same list, same order, first match wins, so no routing answer
//  changes. The pick stays a raw pointer, as it was, because SwapP2PmsgContext
//  holds it raw past the route. A walk that lost its place when the connection
//  it stood on was dropped no longer ends early.
//  RESULT (perf_fanout fan, posture A, Wsa loopback, p50): at 250 connections
//  the extra cost of reaching the last one 75.4 -> 17.9 us on Windows (7
//  rounds) and 131.4 -> 28.1 us on the Linux VM (5 rounds); lat_last 240 ->
//  183 us and 340 -> 240 us; throughput to it +54% and +75%. Unchanged at 1-8
//  connections. TSan clean (p2p_conreap, p2p_vnetmount, p2p_sealhop,
//  p2p_e2ewaive, p2p_ucastgate, teardown_stress, the fan at 64).
//  The covered surface, every exported symbol and class layout, and every
//  wire format are unchanged. Runs on Msgcore 3.5.1 and later, as 3.7.1 did.
//
//  BELOW IS THE 3.7.1 RATIONALE.
//
//  3.7.1.0, a PATCH on 3.7.0: a wrapped message is embedded at its live bytes.
//  WrapFactory and WrappedResponseFactory (exception and error reports, timer
//  wraps) quote a message's whole image, and that image is its heap, so they
//  now trim it first, as SendP2PeerMsg has since 3.7.0. Paired with Msgcore
//  3.5.1, whose message heaps double when they grow: untrimmed, a report
//  would have quoted up to half its message in slack and reached the
//  MAX_P2PmsgWrapEmbed elision bound sooner. Runs on Msgcore 3.5.0 as well
//  (no new call). The covered surface and every wire format are unchanged;
//  UnwrapFactory reads a trimmed embedded image as any receiver reads one.
//
//  BELOW IS THE 3.7.0 RATIONALE.
//
//  3.7.0.0, a MINOR on 3.6.0: an unsealed frame carries its message's live
//  bytes, not its whole heap (p2p_performance.md M1). NEEDS MSGCORE 3.5.0,
//  whose P3PmsgBSTR::TrimP2Piomage it calls; built against older headers it
//  does not compile, so the floor cannot be missed silently. Nothing exported
//  moved (abi-flat.manifest unchanged) and no receive path changed.
//  P2Peerio::SendP2PeerMsg and P2PeerioDmx::SendP2PeerMsg trim before they
//  prepare, so the frame-cap check and the link cypher both see the short
//  frame. Measured (perf_fanout chain 4, 64 B, both platforms identical):
//  unsealed 2,032 -> 629 bytes, sealed 1,344 -> 1,058 (CompactSealed's margin
//  is what the trim takes there); latency and CPU per message flat on
//  loopback. The frame overhead over the payload is 565 bytes, not ~2,082, so the largest unsealed
//  payload that fits a 32,768-byte frame rises from 30,686 to 32,203 bytes
//  (p2p_oversize now MEASURES its sizes instead of carrying the old constants).
//  AN OLD RECEIVER TAKES THE SHORT FRAME: the image carries only its length,
//  and what is left of the free list is exact - the shape the C++23 bridge
//  already sends old peers. Run, not argued: perf_ab's B7 roles with a
//  3.6.0/3.4.7 build on one end and this on the other, both ways round,
//  plain and with the link cypher, all four exit 0; and the C++23 bridge
//  (679591e4) against this old line, tools/ci/bridge-smoke.sh all green.
//  BELOW IS THE 3.6.0 RATIONALE.
//  3.6.0.0, a MINOR on 3.5.1, earned by a BEHAVIOURAL change no symbol
//  records, as 3.4.0's and 3.2.0's were: WaiveEndToEndInProcess is now ON BY
//  DEFAULT (p2p_performance.md decision 2). The covered surface did not move
//  (103 symbols, abi-flat.manifest unchanged; Targetcore_c.h changed in a
//  comment only), no exported class layout moved (AuthPolicy's two bools
//  became std::atomic<bool>, same size, held by pointer and not exported) and
//  nothing on the wire changed. Added, exported and non-virtual:
//  IsP2PmsgHubSealWaivedInProcess, P2PeerHub::IsSealWaivedInProcessNoLock,
//  P2PeerCon::StaysInProcess and P2PeerCon::WaivedBodyLeavesProcess.
//  Until now the waiver was opt-in because it rested on a deployment rule
//  (in-process hubs form one subtree): hubs A and C here, B on another host,
//  wired A-B-C, sent A's body to C across the wire in clear. The default is
//  safe because the waiver is now applied PER HOP, keyed on whether that
//  hop's link leaves the process (P2Peerio::LeavesProcess; only DMX says no):
//  (1) a hub waives only on a link that stays, and only when source AND
//  destination are hubs in this process (the receive side's key; without it
//  a VNet gateway skipped signing for a rewritten source and p2p_vnetmount
//  went red - a defect opt-in users with a mount already had); (2) GateRelayInbound
//  exempts an in-process source only when it also arrived on such a link;
//  (3) a relay refuses an unsealed body whose origin waived it rather than
//  put it on a link that leaves. A deployment that broke the old rule now
//  loses DELIVERY for those messages, not confidentiality;
//  WaiveEndToEndInProcess(false) on the origin restores the old behaviour.
//  It reaches the 93% of per-message CPU the two end-to-end protections cost
//  on a default hub (p2p_linkcost) for every in-process destination.
//  Guarded by p2p_e2ewaive phases 5 (A-B-C) and 6 (A-A2-B-C), TCP loopback
//  standing in for a leaving link; mutation-checked - guards 1 and 3 both off
//  reproduce the clear-text leak.
//  BELOW IS THE 3.5.1 RATIONALE.
//  3.5.1.0, a PATCH on 3.5.0. Nothing exported, no layout and nothing on the
//  wire moved; one file, P2Pwin32.cpp. T6 (p2p_performance P1): the pump
//  verified every message TWICE in Release - VerifyP2Pmsg ends in
//  P2PeerMsg::AssertValid, Msgcore's recursive walk of the whole message tree
//  - once in PutP2Pmsg and again at dispatch, with nothing touching the
//  message in between (PutP2Pmsg is the only way into the FIFO). The dispatch
//  repeat, and SwapP2PmsgContext's target check, now run only in Debug or when
//  P2P_PUMP_VERIFY is set (read once). THE PutP2Pmsg WALK STAYS ON: every
//  message received off the wire passes it after ingress, its tree checks are
//  not obviously covered by the ingress heap walk, and no fuzz harness reaches
//  it - so it is not removed from the untrusted path. Also gone: two
//  P2PeerTarget::AssertValid calls in PutP2Pmsg that duplicated the one inside
//  VerifyP2Pmsg and ran ahead of its null test. Windows posture A +7.5%
//  throughput, -6 us CPU per message; Linux within noise.
//  BELOW IS THE 3.5.0 RATIONALE.
//  3.5.0.0, a MINOR on 3.4.9, informed - not compelled - by an ADDITIVE
//  exported C++ surface. The covered surface did not move (103 symbols,
//  abi-flat.manifest and Targetcore_c.h unchanged), no exported class layout
//  moved (AuthPolicy gained m_pKeyCache, but it is held by pointer and not
//  exported; AesGcm keeps its four members, which P2PeerioGcm embeds), no
//  virtual was added and nothing on the wire changed. Added, all exported and
//  non-virtual: p2pcng::EcdhP256::DeriveRawSecret(const EcdhP256&) (agree
//  with an already-imported peer key), p2pseal::SealToKeyed and
//  p2pseal::OpenKeyed (seal/open with pre-imported reader/sender keys).
//  It is the p2p_performance P1 security fast path, same decisions, same
//  bytes:
//  - T1j: the relay and seal replay caches are indexed (SipHash-keyed hash
//    set beside the ordered vector/ring; age trim and eviction order as
//    before) instead of a linear scan of up to 4,096 x 64 B per message.
//  - T1g: AuthPolicy caches imported STATIC public keys (identity and
//    agreement), cleared on every allow-list reload; full = stops growing,
//    never evicts, because Seal holds the pointers.
//    T1j+T1g: posture D CPU/msg -10/-11% Windows, -15/-17% Linux (B5).
//  - T1h (CNG): SHA-256, HMAC and AES-GCM providers are shared per process
//    like ECDH/ECDSA since 3.4.5; AES-GCM was opened per AesGcm object.
//    HKDF -46%, ~11-16 us per seal/open.
//  - T1i: SealAppMsgOutbound reads the scope once and tests the last hop
//    first; the waived seal's cost on a direct link -52% Windows, -69% Linux.
//  - T1a (OpenSSL): AesGcm caches one EVP_CIPHER_CTX per direction inside its
//    key block (try-lock, fresh-context fallback, so one object may still be
//    driven from two threads), re-keying only the nonce per operation: link
//    seal -1.0 us, open -0.9 us; allocation counts unchanged.
//  BELOW IS THE 3.4.9 RATIONALE.
//  3.4.9.0, a PATCH on 3.4.8. The covered surface did not move (103 symbols,
//  abi-flat.manifest unchanged; Targetcore_c.h changed in a comment only), no
//  class layout moved and nothing on the wire changed. Added to the C++
//  surface: P2Peerio::kSendRefusedFrame (a static const, 0xE00F0015, not a
//  Win32 code), P2Peerio::MeasureSendFrame, the private P2Peerio::FrameSizeOf
//  and the private P2PeerCon::RefuseOversizedOutbound - all non-virtual, so no
//  vtable slot moved. It fixes F-P0-15: a message whose frame exceeded the
//  link's m_dwMaxSendSize (32,768 - about 30,680 B of payload unsealed) was
//  sent anyway, the receiver threw on m_dwMaxRecvSize and DROPPED THE LINK,
//  with no report to the sender. Base P2Peerio::SendP2PeerMsg now measures the
//  frame (cyphered size when the link cypher is on) before encrypting and
//  returns kSendRefusedFrame; the P2PeerCon send funnel, now a loop, reports
//  the message to its sender as P2Pevent_UNDELIVERABLE (source = the hub, as
//  F-S9-1), deletes it and sends the next one. The link stays up. The check is
//  in the base framing path ON PURPOSE: transports with their own framing
//  (P2PeerioDmx, P2PeerioBSTR, P2PeerWeb's WebIoHttp) override SendP2PeerMsg
//  and keep their own limits - a first version that asked a virtual from
//  P2PeerCon refused P2PeerWeb's 34 KB HTTP frames. The loop also cures an
//  idle stall: a message refused by the VNet gate or the seal left the send
//  side idle until something else was posted; it now takes the next one.
//  BEHAVIOUR NOTE: a caller of SendP2PeerMsg on a stock transport can now see
//  kSendRefusedFrame where it used to see success (and a dropped link).
//  BELOW IS THE 3.4.8 RATIONALE.
//  3.4.8.0, a PATCH on 3.4.7. The covered surface did not move (103 symbols,
//  abi-flat.manifest unchanged), no class layout moved and nothing on the wire
//  changed. Added to the C++ surface, which the policy does not cover, as
//  3.4.3's ConState_AcceptUnnamed was: the state bits ConState_LoginHold and
//  ConState_LoginParked, and four non-virtual P2PeerCon members -
//  ParkForLogin, ReleaseLoginHold, PostHandshakeP2PeerMsg and
//  GetSendableP2PeerMsg. Bits, not members, so the exported layout is the same.
//  It fixes the login handshake, in two halves. SEND: a CLIENT connection sent
//  application messages queued while its link was down or still dialling
//  ahead of the Login that opens it - the send path took them as soon as the
//  transport connected, before the connect handler called Login(), and on a
//  restarted link even before OnConnect() - so the far end refused them
//  ("Application message received before login") and dropped the link, and
//  every redial met the same queue. Now a CLIENT sends handshake messages only
//  until ConState_Login, and Login/LoginAck go to the front of the queue.
//  RECEIVE: the loop posted a Login/LoginAck to the pump and read straight on,
//  so a message behind it in the same completion met GateAppMsgInbound()
//  before OnLogin()/OnLoginAck() set the state it tests. Now the loop parks
//  until the pump has applied the login; a refused login drops the connection
//  with that message unread. Found by P2PeerLan's lan_join_test (an in-process
//  Dmx link that failed nearly every Release run, 0 of 20 after).
//  ONE BEHAVIOUR NOTE: a CLIENT whose peer never answers its Login now keeps
//  its application messages queued instead of sending them to be refused.
//  Every connect handler in these repositories logs in.
//  BELOW IS THE 3.4.7 RATIONALE.
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
#define TARGETCORE_VERSION_MINOR  11
#define TARGETCORE_VERSION_PATCH  2
#define TARGETCORE_VERSION_BUILD  0

//  Comma form, for the FILEVERSION / PRODUCTVERSION resource statements,
//  which take four comma-separated words and cannot take a macro expression.
#define TARGETCORE_VERSION_COMMAS 3,11,2,0

//  String form. Kept spelled out rather than stringised from the parts above:
//  rc.exe's preprocessor has no reliable ## / # operator support, and a
//  VERSIONINFO string that silently expands to "TARGETCORE_VERSION_MAJOR.0.0"
//  would ship without anyone noticing.
#define TARGETCORE_VERSION_STRING "3.11.2.0"

//  Packed form, for a consumer that wants to compare rather than display.
//  0x030B0200 is 3.11.2.0; the byte order is MAJOR, MINOR, PATCH, BUILD -- one
//  byte each.
#define TARGETCORE_VERSION_HEX    0x030B0200

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
#define TARGETCORE_VERSION_STRINGW L"3.11.2.0"

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
