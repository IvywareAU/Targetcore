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
// TargetCore_c.h  –  extern "C" wrapper for Java Panama FFI
// Exposes: P2Paddr, P2PeerMsg, P2PeerConWsa, P2PeerHub
// String convention: all TCHAR/wchar_t strings are wchar_t* (Windows UNICODE build).
// Ownership: strings returned by getters point to internal C++ object storage;
//            they are valid only while the owning handle is alive.
//
// ── Handle validity, and what every entry point does with a bad one ──────────
// The four handle types below are all void*, so nothing in the C type system
// stops a caller passing a pointer this library never issued, one it issued and
// has since freed, or one of the wrong kind. Every entry point therefore looks
// its handle up in an internal registry of live handles BEFORE using it, and
// refuses if it is absent or of the wrong kind. The lookup never dereferences
// the caller's pointer, which is why it is a registry and not a magic word
// inside the object: reading a tag through a hostile pointer is the same defect
// the tag was supposed to fix. (SECURITY_REVIEW M1.)
//
// Every entry point also swallows the P2Pevent exceptions the kernel throws to
// signal failure. A C++ exception unwinding across this extern "C" boundary is
// undefined behaviour for an FFI caller — a Panama downcall has no landing pad —
// so a throw is reported through the return value instead.
//
// A refusal is reported in the shape of the return type, following Msgcore_c.h:
//   * handle- or string-returning  -> NULL
//   * int-returning success/predicate -> 0 ("no", "did not happen")
//     ...except p2paddr_is_null / p2paddr_is_empty, which answer 1: for those
//     the conservative reading is the one that makes a caller STOP.
//   * numeric getters              -> 0
//   * void-returning               -> nothing happens
//   * p2peerhub_post_msg / p2peerconwsa_post_msg -> the message handle back,
//     since non-NULL already means "not delivered" for those two.
// A refusal is therefore indistinguishable from a legitimate zero/NULL answer.
// That is deliberate: the C ABI has no error channel, and an FFI caller that
// needs to tell them apart must not have lost track of its handles.
//
// NOT covered: destroying a handle on one thread while another thread is inside
// a call holding it. Closing that would mean refcounting every handle and
// changing the ownership rules stated below. Handles are safe to USE from any
// thread; they must outlive the calls made on them.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Export/import decoration. Kept self-contained (no dependency on the Platform
// __declspec shim) so any consumer -- the TreeFS/FUSE frontend, Java Panama /
// jextract, etc. -- can include this header directly on either toolchain. Mirrors
// Msgcore_c.h's MSGCORE_C_API. Windows behaviour is byte-identical to before.
#if defined(_WIN32)
#  if defined(TargetCore_EXPORTS)
#    define P2PC_API __declspec(dllexport)
#  elif defined(TargetCore_STATIC)
#    define P2PC_API
#  else
#    define P2PC_API __declspec(dllimport)
#  endif
#else                                   // GCC/Clang (Linux port)
#  if defined(TargetCore_EXPORTS)
#    define P2PC_API __attribute__((visibility("default")))
#  else
#    define P2PC_API               // imports need no decoration on ELF
#  endif
#endif

#include <stdint.h>
#include <wchar.h>

// The component's version identity, so an FFI consumer can test what it
// compiled against without a second copy of the number. Preprocessor-only, so
// it costs jextract nothing and adds no symbol to the ABI.
#include "TargetCore_version.h"

// ── Opaque handles ────────────────────────────────────────────────────────────
typedef void* P2PAddrHandle;
typedef void* P2PeerMsgHandle;
typedef void* P2PeerConWsaHandle;
typedef void* P2PeerHubHandle;

// ── Lifecycle (P2Pmsg environment) ────────────────────────────────────────────
// targetcore_startup MUST be called once per process BEFORE any P2PeerHub
// operation (it initialises the shared hub/pump critical sections and the hub
// manager table); targetcore_cleanup once at shutdown. This mirrors the native
// StartupP2Pmsg/CleanupP2Pmsg contract every C++ consumer already follows.
// P2Paddr and P2PeerMsg (pure object model) do NOT require startup.
// Returns 1 on success, 0 on failure (incl. "already started").
P2PC_API int            targetcore_startup    (unsigned int nMaxHubs);
P2PC_API void           targetcore_cleanup    (void);

// ── P2Paddr ───────────────────────────────────────────────────────────────────
P2PC_API P2PAddrHandle  p2paddr_create        (void);
P2PC_API P2PAddrHandle  p2paddr_create_str    (const wchar_t* strAddr);
P2PC_API void           p2paddr_destroy       (P2PAddrHandle h);
P2PC_API const wchar_t* p2paddr_c_name        (P2PAddrHandle h);
P2PC_API int            p2paddr_is_null       (P2PAddrHandle h);
P2PC_API int            p2paddr_is_empty      (P2PAddrHandle h);
P2PC_API uint32_t       p2paddr_sizeof        (P2PAddrHandle h);
P2PC_API int            p2paddr_is_child      (P2PAddrHandle h, const wchar_t* strAddr);
P2PC_API int            p2paddr_is_rable      (P2PAddrHandle h, const wchar_t* strAddr);

// ── P2PeerMsg ─────────────────────────────────────────────────────────────────
// Sizes on this surface are uint32_t, matching the kernel's P2Psize_t. They were
// `unsigned short`, which put a silent 64 KB wrap in front of every FFI caller:
// a Java/Panama binding that handed over a 70000-byte payload got a 4464-byte
// message and no error, because the truncation happened in the ABI itself before
// any kernel check could see the real number. The message cap is still
// MAX_P2Psize (32768) and an over-cap size is refused downstream — but it is now
// refused at the size the caller actually passed.
P2PC_API P2PeerMsgHandle  p2peermsg_create         (void);
P2PC_API P2PeerMsgHandle  p2peermsg_create_full    (const wchar_t* src,
                                                     const wchar_t* dst,
                                                     const wchar_t* msgID,
                                                     const void*    data,
                                                     uint32_t       dataSize);
P2PC_API P2PeerMsgHandle  p2peermsg_create_msgid   (const wchar_t* msgID);
P2PC_API void             p2peermsg_destroy        (P2PeerMsgHandle h);

// The three wide string getters below (get_source / get_destin / c_name) each
// return a pointer to a per-thread buffer of their own, valid until the NEXT
// call to that same getter on this thread — the same contract the _u8 twins
// document at the bottom of this header. They must never hand back the raw
// accessor result: off Win32 that is a slot of a 16-entry thread-local widening
// ring recycled by any handful of further accessor calls (Platform/p2pstr.h).
P2PC_API const wchar_t*   p2peermsg_get_source     (P2PeerMsgHandle h);
P2PC_API void             p2peermsg_set_source     (P2PeerMsgHandle h, const wchar_t* src);
P2PC_API const wchar_t*   p2peermsg_get_destin     (P2PeerMsgHandle h);
P2PC_API void             p2peermsg_set_destin     (P2PeerMsgHandle h, const wchar_t* dst);
P2PC_API const wchar_t*   p2peermsg_c_name         (P2PeerMsgHandle h);
P2PC_API const char*      p2peermsg_data           (P2PeerMsgHandle h);
P2PC_API int64_t          p2peermsg_data_size      (P2PeerMsgHandle h);
P2PC_API unsigned char    p2peermsg_priority       (P2PeerMsgHandle h);
P2PC_API unsigned char    p2peermsg_set_priority   (P2PeerMsgHandle h, unsigned char pri);
P2PC_API uint32_t         p2peermsg_sizeof         (P2PeerMsgHandle h);
P2PC_API int              p2peermsg_is_wrapped     (P2PeerMsgHandle h);
P2PC_API int              p2peermsg_is_reflected   (P2PeerMsgHandle h);
// Returns a newly allocated P2PeerMsg that the caller is responsible for destroying.
P2PC_API P2PeerMsgHandle  p2peermsg_response_factory    (P2PeerMsgHandle h,
                                                          const wchar_t* msgID,
                                                          const void* data,
                                                          uint32_t    dataSize);
P2PC_API P2PeerMsgHandle  p2peermsg_redirect_factory    (P2PeerMsgHandle h,
                                                          const wchar_t* dstAddr);

// ── P2PeerConWsa ──────────────────────────────────────────────────────────────
// Client connection: active outbound TCP connect
P2PC_API P2PeerConWsaHandle p2peerconwsa_client_factory   (const wchar_t* strThatAddr,
                                                            const wchar_t* ipAddress,
                                                            short          port);
// Service connection: passive inbound TCP listen
P2PC_API P2PeerConWsaHandle p2peerconwsa_service_factory  (const wchar_t* strThatAddr,
                                                            short          port);
P2PC_API void               p2peerconwsa_destroy          (P2PeerConWsaHandle h);
P2PC_API int                p2peerconwsa_connect          (P2PeerConWsaHandle h);
P2PC_API int                p2peerconwsa_listen           (P2PeerConWsaHandle h);
P2PC_API void               p2peerconwsa_close            (P2PeerConWsaHandle h);
P2PC_API unsigned long      p2peerconwsa_get_state        (P2PeerConWsaHandle h, unsigned long mask);
P2PC_API int                p2peerconwsa_has_state        (P2PeerConWsaHandle h, unsigned long mask);
// Returns P2PeerConMode_e: 0=Unknown,1=CLIENT,2=SERVICE,3=Accept -- and 0 for a
// handle that was refused, which is the one failure value here that is already
// part of the published enum rather than a convention.
P2PC_API int                p2peerconwsa_get_mode         (P2PeerConWsaHandle h);
P2PC_API const wchar_t*     p2peerconwsa_get_address      (P2PeerConWsaHandle h);
// What this socket can vouch for about where its frames go, and what the hub's
// per-class link policy (p2peerhub_set_link_policy) is read with for it:
//   0 wire   1 local (the kernel keeps it on this machine)   2 in-process
//
// A socket answers 1 when the kernel says its peer is on loopback -- which is
// true for a client that dialled 127.0.0.1 or ::1 and for a service's accepted
// child alike, because the answer is getpeername()'s and not a copied setting.
// Everything else is 0, including a socket with no peer yet unless it was bound
// with the loopback listen scope. 0 for a refused handle.
//
// demote_trust holds a connection to NO BETTER than the class given. It only
// ever tightens: a call naming a higher class does nothing, and there is no
// promote, because a class this library cannot verify is an intention rather
// than a fact and a policy must not read one as the other.
P2PC_API int                p2peerconwsa_get_trust_class  (P2PeerConWsaHandle h);
P2PC_API void               p2peerconwsa_demote_trust     (P2PeerConWsaHandle h,
                                                            int                trustClass);
// PostP2PeerMsg takes ownership of msgHandle; do not destroy it after this call.
// NULL back means delivered to the queue. Non-NULL is msgHandle returned as "not
// delivered": the message is spent either way, and destroying the handle after
// this call is a no-op rather than a double free.
P2PC_API P2PeerMsgHandle    p2peerconwsa_post_msg         (P2PeerConWsaHandle h,
                                                            P2PeerMsgHandle    msg);

// ── P2PeerHub ─────────────────────────────────────────────────────────────────
P2PC_API P2PeerHubHandle    p2peerhub_create         (const wchar_t* strAddr);
P2PC_API void               p2peerhub_destroy        (P2PeerHubHandle h);
P2PC_API int                p2peerhub_create_hub     (P2PeerHubHandle h,
                                                       const wchar_t* strAddr,
                                                       unsigned int   pumpsMax);
// Spawns the hub thread; returns a Win32 HANDLE (cast to void*), or NULL if
// the hub refused to arm (refer the RequireAuth note below).
//
// THE HANDLE IS YOURS AND YOU DO NOT NEED IT.  It is returned for the same
// reasons the C++ SpawnHub() returns one - thread affinity, priority, a
// diagnostic - and if you take it you own it and must release it with your
// platform's API.  You do NOT need it to shut down: p2peerhub_close_hub JOINS
// the thread it spawned, so when that call returns the pump thread has left,
// not merely flagged that it is leaving.  Ignoring the return value entirely
// is a leaked thread handle, not a leaked thread.
//
// That join is why there is no p2peerhub_join.  Until 2026-08-20 close_hub
// returned with the hub down but the pump thread still running its epilogue,
// and a C consumer holding an opaque void* had no portable way to wait -
// finding F-S5-7, found by install-check/consumer.c, the first code in the
// tree to drive a hub through this surface alone.  Closing it inside
// CloseHub() rather than by adding an entry point gives the guarantee to every
// caller instead of to the ones who read this paragraph.
P2PC_API void*              p2peerhub_spawn_hub      (P2PeerHubHandle h);
P2PC_API void               p2peerhub_close_hub      (P2PeerHubHandle h);
P2PC_API void               p2peerhub_pause_hub      (P2PeerHubHandle h);
P2PC_API void               p2peerhub_wakeup_hub     (P2PeerHubHandle h);
// PostP2PeerCon passes ownership of the connection to the hub -- but only on a 1
// return. A 0 is a refusal taken BEFORE the hub accepted it (hub not running, or
// a connection with that address already posted), so the connection is still
// yours to destroy.
P2PC_API int                p2peerhub_post_con       (P2PeerHubHandle    hub,
                                                       P2PeerConWsaHandle con,
                                                       unsigned int       pumpID);
P2PC_API int                p2peerhub_con_exists     (P2PeerHubHandle h, const wchar_t* addr);
// PostP2PeerMsg takes ownership; do not destroy msg after this call. Same
// NULL/non-NULL contract as p2peerconwsa_post_msg above.
P2PC_API P2PeerMsgHandle    p2peerhub_post_msg       (P2PeerHubHandle h, P2PeerMsgHandle msg);
P2PC_API unsigned long      p2peerhub_get_hub_id     (P2PeerHubHandle h);
P2PC_API const wchar_t*     p2peerhub_get_address    (P2PeerHubHandle h);

// ── P2PeerHub peer authentication ─────────────────────────────────────────────
// ADDED 2026-08-18 (Stage 3 step 8), and the reason it had to
// be added rather than left to the C++ surface: RequireAuth now defaults to ON,
// and a hub that requires auth and cannot enforce it REFUSES TO ARM -
// p2peerhub_create_hub returns 0 and p2peerhub_spawn_hub returns NULL. Without
// these entry points that flip would have been a hard break with no migration
// available at all through this header, which is the only surface a
// redistributed build offers.
//
// Every one of these must be called BEFORE p2peerhub_create_hub /
// p2peerhub_spawn_hub, like every other hub setting.
//
// Paths are UTF-8 on both platforms.

// The migration: 0 turns peer authentication off for this hub, exactly as the
// tree behaved before 2026-08-18. A trusted segment, an in-process router. Say
// it deliberately; what is no longer possible is turning it off by saying
// nothing.
P2PC_API void               p2peerhub_require_auth   (P2PeerHubHandle h, int require);
P2PC_API int                p2peerhub_is_auth_required(P2PeerHubHandle h);

// What a link of a given TRUST CLASS must do, when require_auth is on.
//
// trustClass is what the TRANSPORT vouches for about where its frames can go:
//   0 wire       leaves the machine, or nothing can say it does not
//   1 local      cannot leave the machine; the kernel enforces it
//   2 in-process cannot leave the process; construction enforces it
// policy is what this hub demands of a link in that class:
//   0 full       key agreement, link cypher, signed and verified login
//   1 open       none of the three
//
// This is the answer to paying for a handshake on a link that cannot benefit
// from one. An in-process connection is a pointer handoff between two objects
// on one heap; before this, requiring authentication on the hub made it run an
// ECDH agreement, hold a key object nothing consults, and sign four ECDSA
// operations onto its login, and the only way to say otherwise was
// p2peerhub_require_auth(h, 0) — which opens every link the hub will ever
// hold, including a socket posted to it later.
//
// TRUST CLASS 0 CANNOT BE OPENED. The call is accepted and ignored. A wire is
// what every transport that has vouched for nothing answers — a serial line, a
// socket that is not on loopback, and as coded a named pipe, which accepts a
// client arriving over SMB from another host — so opening it would relax the
// whole tree through a call that reads as though it named one kind of link.
// p2peerhub_require_auth(h, 0) is how a wire is opened, and the posture and
// the arming gate both report it.
//
// BOTH ENDS OF A LINK NEED THE SAME SETTING, exactly as require_auth does. A
// peer that skipped the agreement against a hub that wanted one is refused.
//
// Every class defaults to 0 (full), so a consumer that never calls this gets
// what it has always had. Call it before p2peerhub_create_hub /
// p2peerhub_spawn_hub, like every other hub setting.
//
// It is a per-LINK setting and does not touch the per-MESSAGE protections:
// relay attestation and end-to-end sealing are properties of an origin and a
// destination rather than of one hop, and an opened link still signs and still
// seals. p2peerhub_require_seal is where those live.
P2PC_API void               p2peerhub_set_link_policy(P2PeerHubHandle h,
                                                       int             trustClass,
                                                       int             policy);
P2PC_API int                p2peerhub_get_link_policy(P2PeerHubHandle h,
                                                       int             trustClass);

// THE FENCE: the lowest trust class this hub will hold a link of. A connection
// whose class is below it is refused at p2peerhub_post_con, which returns 0 and
// names the class it refused.
//
// It is the other half of p2peerhub_set_link_policy rather than a separate
// feature, and it is what makes the relaxation safer than the old opt-out and
// not merely cheaper. p2peerhub_require_auth(h, 0) opens every link the hub
// will ever hold, including one posted an hour later by code that never read
// the setting; set_link_policy(h, 2, 1) with require_trust_at_least(h, 2) opens
// the links that cannot leave the process and refuses the rest outright.
//
// 0 - the wire - is the default and means NO fence: it is the class every
// transport that has vouched for nothing answers, so a floor there refuses
// nothing. Call it before p2peerhub_create_hub / p2peerhub_spawn_hub, like
// every other hub setting. A class this build does not have is ignored.
//
// IT ALSO CHANGES WHAT ARMING MEANS FOR ONE SHAPE OF HUB. A hub that requires
// auth, has fenced out every class it will not carry, and has opened every
// class it will, can never demand a signature from anybody - so it arms with
// no identity and no allow-list, reporting p2pauth::ArmNotRequiredByPolicy (8)
// rather than refusing. The posture still reads AuthRequired=1 beside
// TrustFloor and the three LinkPol fields, which is what makes that a stated
// decision rather than the omission the arming gate exists to catch.
P2PC_API void               p2peerhub_require_trust_at_least(P2PeerHubHandle h,
                                                       int             trustClass);
P2PC_API int                p2peerhub_get_required_trust(P2PeerHubHandle h);

// Load (create, with createIfAbsent non-zero) this hub's own identity key, and
// the file naming the peers it will accept. Both return a p2pcng::IdResult as
// an int; 0 is IdOk.
P2PC_API int                p2peerhub_set_identity   (P2PeerHubHandle h,
                                                       const char*     pathUtf8,
                                                       int             createIfAbsent);
P2PC_API int                p2peerhub_set_allow_list (P2PeerHubHandle h,
                                                       const char*     pathUtf8);
P2PC_API int                p2peerhub_reload_allow_list (P2PeerHubHandle h);

// First run: create the identity if it is not there, write the publishable half
// beside it as "<pathUtf8>.pub", and copy the fingerprint an operator reads
// aloud into fingerprintOut (which needs 40 bytes). pCreated, when non-NULL,
// receives 1 if this call generated the key and 0 if it found one. Returns an
// IdResult; 0 is IdOk.
//
// It does NOT create the allow-list, and the hub still will not arm until one
// exists with at least one peer in it. Who to trust is not a thing a library
// can supply, and one that wrote an empty allow-list would be answering it
// with "nobody" - which refuses every peer.
P2PC_API int                p2peerhub_provision_auth (P2PeerHubHandle h,
                                                       const char*     pathUtf8,
                                                       char*           fingerprintOut,
                                                       unsigned long   cchFingerprintOut,
                                                       int*            pCreated);

// Would this hub arm? Pure query, safe at any time. Returns a
// p2pauth::ArmResult as an int:
//   0 ArmOk            provisioned
//   1 ArmNotRequired   auth is off - NOT the same as armed-and-authenticating
//   2 ArmNoIdentity    no identity key
//   3 ArmNoAllowList   no allow-list configured
//   4 ArmAllowUnusable configured, and the last load of it failed
//   5 ArmEmptyAllow    loads, and names nobody
//   6 ArmNoRevocation       no revocation list, and none declared unwanted
//   7 ArmRevocationUnusable configured, and the last load of it failed
// p2peerhub_auth_arm_text renders any of them; p2peerhub_auth_allow_list_path
// and p2peerhub_auth_revocation_list_path return the configured paths (or
// NULL), so a caller can name the file the same way the library's own
// diagnostic does - and which of the two to name depends on which result it
// is. The returned pointers are owned by the library - copy, do not free.
P2PC_API int                p2peerhub_auth_arm       (P2PeerHubHandle h);
P2PC_API const char*        p2peerhub_auth_arm_text  (int armResult);
P2PC_API const char*        p2peerhub_auth_allow_list_path (P2PeerHubHandle h);
P2PC_API const char*        p2peerhub_auth_revocation_list_path (P2PeerHubHandle h);

// ── P2PeerHub revocation ──────────────────────────────────────────────────────
// ADDED 2026-08-21, and for the same reason the block above was added on
// 2026-08-18 rather than left to the C++ surface. RequireRevocation now
// defaults to ON: a hub that requires auth and has never named a revocation
// list REFUSES TO ARM. Without these three, that flip would be a hard break
// with no migration reachable through this header at all - which is exactly
// the defect the 2026-08-18 block records, and repeating it four days later
// with the file open would be hard to explain.
//
// Note which three. Not just the opt-out: a surface that could only turn the
// requirement OFF would make "satisfy it" the one thing a C caller cannot do,
// so p2peerhub_set_revocation_list is here as well - it had no flat-C entry
// point before this, which is why the gate needed one.
//
// The migration is one line and there are two of them: name a list, or pass 0
// to p2peerhub_require_revocation and mean it. Turning the requirement off
// does NOT turn revocation off - a list named anyway is still loaded, still
// enforced, and still fails closed.
P2PC_API void               p2peerhub_require_revocation (P2PeerHubHandle h,
                                                       int             require);
P2PC_API int                p2peerhub_is_revocation_required (P2PeerHubHandle h);
// Returns a p2pcng::IdResult as an int; 0 is IdOk. Path is UTF-8 on both
// platforms, like every other path here.
P2PC_API int                p2peerhub_set_revocation_list (P2PeerHubHandle h,
                                                       const char*     pathUtf8);

// ── P2PeerHub end-to-end sealing ──────────────────────────────────────────────
// ADDED 2026-08-21, and for the third time the same reason: a default that
// refuses to arm, or refuses to send, has to be both SATISFIABLE and
// REFUSABLE through this header or a redistributed build has no migration at
// all.
//
// p2peerhub_require_seal(h, 0) is the migration. With it on - the default - a
// message whose destination is not the peer on the far end of the link is
// sealed to that destination, and if this hub holds no agreement key for the
// destination the message is DROPPED rather than sent in clear.
//
// p2peerhub_set_agreement_key is the other half: a hub that requires sealing
// and holds no agreement key cannot OPEN a body addressed to it. That is not
// an arming refusal - a relay legitimately holds no keys - but it is warned
// about at startup and refused per message at the send path.
//
// p2peerhub_add_seal_reader names a hub that may ALSO read what this hub
// seals - the answer to "an intermediate hub has to see the body". The SENDER
// decides and only the sender: the reader set is bound into the sealed body's
// additional data and its signature, so no relay can add itself. Everything
// named can read every body this hub seals. Addresses are wide strings here
// because an address is a P2Paddr, not a path; the _u8 twin takes UTF-8.
P2PC_API void               p2peerhub_require_seal   (P2PeerHubHandle h,
                                                       int             require);
P2PC_API int                p2peerhub_is_seal_required(P2PeerHubHandle h);
// Waive the two END-TO-END protections - relay attestation and the seal - for
// a destination that is a hub in THIS process. 0 is the default and is off.
//
// This is the one call in this header whose correctness rests on a DEPLOYMENT
// ASSUMPTION rather than on a mechanism, and an FFI consumer cannot read the
// C++ header's block comment, so the assumption is written out here too: it
// holds only if a message to an in-process hub never transits an
// out-of-process one. Hubs A and C in this process with B on another host,
// wired A-B-C, sends A's body to C over the wire IN CLEAR with this on -
// because the destination being in this process is a fact, and the route
// staying in this process is not.
//
// It waives nothing for a BROADCAST, and nothing on a per-hop path: key
// agreement, the signed login and the link cypher are p2peerhub_set_link_policy's
// decision and are untouched. Refer P2PeerHub::WaiveEndToEndInProcess.
P2PC_API void               p2peerhub_waive_end_to_end_in_process
                                                      (P2PeerHubHandle h,
                                                       int             waive);
P2PC_API int                p2peerhub_is_end_to_end_waived_in_process
                                                      (P2PeerHubHandle h);
P2PC_API int                p2peerhub_set_agreement_key (P2PeerHubHandle h,
                                                       const char*     pathUtf8,
                                                       int             createIfAbsent);
P2PC_API int                p2peerhub_add_seal_reader (P2PeerHubHandle h,
                                                       const wchar_t*  addr);
P2PC_API int                p2peerhub_add_seal_reader_u8 (P2PeerHubHandle h,
                                                       const char*     addrUtf8);
P2PC_API void               p2peerhub_clear_seal_readers (P2PeerHubHandle h);

// ── P2PeerHub receive sink ────────────────────────────────────────────────────
// The receive half of the flat C surface. Everything above is post-only: this is
// how an FFI consumer (Java Panama, a PHP extension, the TreeFS frontend) learns
// that a P2PeerMsg was DELIVERED to its hub, without needing TargetFacade's
// IP2PHubEvents sink (which is MFC/HRESULT and Windows-only).
//
// The sink fires from P2PeerHub::On_P2PeerMsg, the seam the pump reaches only
// when the message's destination equals this hub's address (P2Pwin32.cpp:3105) —
// so it sees deliveries, never the pass-through hops that PeekP2PeerMsg also
// sees on the routing path.
//
// THREAD: the sink is called on the HUB PUMP thread, not the registering thread.
// It must not block; a host with thread affinity (PHP, or a Panama upcall on an
// unattached thread) should do nothing in the callback but copy the bytes into
// its own queue and return.
//
// LIFETIME: src/dst/msgID/data point at storage owned by the message and are
// valid ONLY for the duration of the call. Copy anything you keep.
//
// RETURN: non-zero = consumed. The hub's compiled P2PeerMsg_MAP is then skipped
// (including the default broadcast-forward and error handlers) and the framework
// does not manufacture an undeliverable bounce — which is what an FFI peer with
// no compiled map wants; returning 0 for every message makes the framework bounce
// each one back as undeliverable, and that flood is what wedges CloseHub.
//
// dst is the hub's FULL address ("Root.WebSocket.php-app"), not the leaf name
// that p2peerhub_get_address returns. It is read from the HUB, not from the
// message, and is exact rather than an approximation (see the destination guard
// above). The reason for not reading it off the message is heap discipline:
// each P2PeerMsg field accessor allocates on the message's bounded 65535-byte
// heap, and calling all four (Data/DataSize/GetSource/GetDestin) leaves no room
// for the reply a sink is most likely to post (P2PeerFs spike 14.2b; see
// PeerFsMirror.h "Heap budget").
//
// REGISTRATION: set the sink before p2peerhub_spawn_hub and clear it (fn = NULL)
// after p2peerhub_close_hub. Registering and clearing are safe against a running
// pump; swapping one live sink for another is not.
//
// Returns 1 if the sink was registered, 0 if the handle was not produced by
// p2peerhub_create/_u8. Both sinks may be set at once (the wide one runs first);
// the message counts as consumed if either returns non-zero.
typedef int (*P2PeerHubSinkFn)   (void*          ctx,
                                   const wchar_t* srcAddr,
                                   const wchar_t* dstAddr,
                                   const wchar_t* msgID,
                                   const void*    data,
                                   int64_t        dataSize);

P2PC_API int  p2peerhub_set_sink (P2PeerHubHandle h, P2PeerHubSinkFn fn, void* ctx);

// ── UTF-8 (_u8) parallel entry points ─────────────────────────────────────────
// The recommended cross-platform FFI surface. The
// wchar_t entry points above use each platform's native wide layout (UTF-16 on
// Windows, UTF-32 on Linux) and cannot carry a string portably through Panama.
// These _u8 twins take/return UTF-8 (const char*), converting at the boundary,
// and are ABI-identical on both OSes. Only string-bearing functions get a twin.
// Returned const char* points at a thread-local buffer valid until the next _u8
// string-returning call on the same thread (mirrors the wchar_t getters). Note
// p2peermsg_data() is an opaque binary payload, not text — it has no _u8 twin.

// P2Paddr
P2PC_API P2PAddrHandle  p2paddr_create_str_u8 (const char* strAddr);
P2PC_API const char*    p2paddr_c_name_u8     (P2PAddrHandle h);
P2PC_API int            p2paddr_is_child_u8   (P2PAddrHandle h, const char* strAddr);
P2PC_API int            p2paddr_is_rable_u8   (P2PAddrHandle h, const char* strAddr);

// P2PeerMsg
P2PC_API P2PeerMsgHandle p2peermsg_create_full_u8 (const char* src, const char* dst,
                                                   const char* msgID, const void* data,
                                                   uint32_t    dataSize);
P2PC_API P2PeerMsgHandle p2peermsg_create_msgid_u8(const char* msgID);
P2PC_API const char*     p2peermsg_get_source_u8  (P2PeerMsgHandle h);
P2PC_API void            p2peermsg_set_source_u8  (P2PeerMsgHandle h, const char* src);
P2PC_API const char*     p2peermsg_get_destin_u8  (P2PeerMsgHandle h);
P2PC_API void            p2peermsg_set_destin_u8  (P2PeerMsgHandle h, const char* dst);
P2PC_API const char*     p2peermsg_c_name_u8      (P2PeerMsgHandle h);
P2PC_API P2PeerMsgHandle p2peermsg_response_factory_u8(P2PeerMsgHandle h, const char* msgID,
                                                       const void* data, uint32_t    dataSize);
P2PC_API P2PeerMsgHandle p2peermsg_redirect_factory_u8(P2PeerMsgHandle h, const char* dstAddr);

// P2PeerConWsa
P2PC_API P2PeerConWsaHandle p2peerconwsa_client_factory_u8 (const char* strThatAddr,
                                                            const char* ipAddress, short port);
P2PC_API P2PeerConWsaHandle p2peerconwsa_service_factory_u8(const char* strThatAddr, short port);
P2PC_API const char*        p2peerconwsa_get_address_u8    (P2PeerConWsaHandle h);

// P2PeerHub
P2PC_API P2PeerHubHandle p2peerhub_create_u8     (const char* strAddr);
P2PC_API int             p2peerhub_create_hub_u8 (P2PeerHubHandle h, const char* strAddr, unsigned int pumpsMax);
P2PC_API int             p2peerhub_con_exists_u8 (P2PeerHubHandle h, const char* addr);
P2PC_API const char*     p2peerhub_get_address_u8(P2PeerHubHandle h);

// The receive sink's UTF-8 twin — the form Panama/jextract and a PHP extension
// should bind. Same contract as p2peerhub_set_sink above (pump thread, borrowed
// pointers, non-zero = consumed); the three strings arrive as UTF-8, converted at
// the boundary, and `data` stays an opaque binary payload in both variants.
// Unlike the other _u8 twins it is implemented in TargetCore_c.cpp, because it
// shares the hub's sink storage rather than delegating to the wchar_t entry point.
typedef int (*P2PeerHubSinkFnU8) (void*       ctx,
                                   const char* srcAddr,
                                   const char* dstAddr,
                                   const char* msgID,
                                   const void* data,
                                   int64_t     dataSize);

P2PC_API int  p2peerhub_set_sink_u8 (P2PeerHubHandle h, P2PeerHubSinkFnU8 fn, void* ctx);

#ifdef __cplusplus
}  // extern "C"
#endif
