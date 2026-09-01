/* Copyright © 2026 Khrustal & Mann
 *              MELBOURNE, VICTORIA, AUSTRALIA, 3000
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * consumer.c -- the stranger.  Stage 5 step 14.
 *
 * This program is the whole point of the install tree, and everything about it
 * is chosen to make it a witness rather than a demonstration:
 *
 *   * It is C, not C++.  The flat C header is the only surface that ships, and
 *     the reason it ships is that it can be consumed without this solution's
 *     toolchain.  A C++ probe would have compiled through MSVC's C++ front end
 *     and proved a weaker thing.
 *
 *   * It includes exactly TWO headers of ours plus three from the C standard
 *     library.  If either installed header needed anything that is not staged
 *     -- as TargetCore_c.h needed TargetCore_version.h, which was NOT staged
 *     until step 14 -- this file does not preprocess, and that is the failure
 *     the gate is there to catch.
 *
 *   * It never mentions Windows, MFC, io_uring or OpenSSL.  Those are what the
 *     library is built from; a consumer that had to know about them would mean
 *     the export was lying about its dependencies.
 *
 *   * It exercises BOTH shipped libraries, and Msgcore directly rather than
 *     only through TargetCore.  Reaching libmsgcore only transitively would
 *     leave the sibling header and import library untested, and those are
 *     exactly the parts an install tree is prone to forget.
 *
 * The hub sequence mirrors MscsUnitTests/TargetCoreSuite.cpp Test_CApiHubSink,
 * which is the in-tree version of the same probe: create, opt out of auth, spawn,
 * post, wait for the sink, close.  RequireAuth defaults ON since Stage 3 step 8
 * and an unprovisioned hub refuses to arm, so the opt-out is not a convenience --
 * without it p2peerhub_spawn_hub returns NULL and the probe measures nothing.
 *
 * The wait is a bounded spin on a volatile flag rather than a wait primitive,
 * because there is no portable one in C89/C11 that MSVC and glibc both offer,
 * and pulling in <windows.h> or <pthread.h> would put a platform header back
 * into a file whose whole claim is that it needs none.  The sink normally fires
 * in under a millisecond, so the spin costs nothing when it passes and bounds
 * the failure when it does not.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <Msgcore_c.h>
#include <TargetCore_c.h>

static int g_failures = 0;

static void check(int cond, const char* what)
{
    if (cond) { printf("  ok    %s\n", what); return; }
    printf("  FAIL  %s\n", what);
    ++g_failures;
}

/* Separate from check() so a string mismatch reports BOTH strings. A gate that
 * says only "the address was wrong" makes the next person re-run it under a
 * debugger to find out what it actually was. */
static void check_str(const char* got, const char* want, const char* what)
{
    if (got && strcmp(got, want) == 0) { printf("  ok    %s\n", what); return; }
    printf("  FAIL  %s (wanted \"%s\", got \"%s\")\n",
           what, want, got ? got : "(null)");
    ++g_failures;
}

/* ---- the sink, called on the hub's pump thread ------------------------- */

typedef struct SinkCapture
{
    volatile int nCalls;
    char         szSrc [64];
    char         szDst [64];
    char         szId  [64];
    long         cbData;
} SinkCapture;

static void copy_bounded(char* dst, size_t cap, const char* src)
{
    size_t n;
    if (!src) { dst[0] = '\0'; return; }
    n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int sink_probe(void*       ctx,
                      const char* srcAddr,
                      const char* dstAddr,
                      const char* msgID,
                      const void* data,
                      int64_t     dataSize)
{
    SinkCapture* pCap = (SinkCapture*)ctx;
    (void)data;
    copy_bounded(pCap->szSrc, sizeof pCap->szSrc, srcAddr);
    copy_bounded(pCap->szDst, sizeof pCap->szDst, dstAddr);
    copy_bounded(pCap->szId,  sizeof pCap->szId,  msgID);
    pCap->cbData = (long)dataSize;
    pCap->nCalls = pCap->nCalls + 1;
    return 1;                       /* consumed */
}

static int wait_for_sink(const SinkCapture* pCap, double dSeconds)
{
    clock_t tStart = clock();
    while (pCap->nCalls == 0)
    {
        if ((double)(clock() - tStart) / (double)CLOCKS_PER_SEC > dSeconds)
            return 0;
    }
    return 1;
}

/* ---- the probe --------------------------------------------------------- */

int main(void)
{
    static const char szPayload[] = "install-probe";
    const unsigned    cbPayload   = (unsigned)sizeof szPayload;

    MsgMgrHandle     hMgr  = NULL;
    P2PeerMsgHandle  hMsg  = NULL;
    P2PeerHubHandle  hHub  = NULL;
    void*            pvThread = NULL;
    const char*      szAddr = NULL;
    SinkCapture      oCap;

    memset(&oCap, 0, sizeof oCap);

    printf("install-check consumer\n");
    printf("  compiled against Msgcore %s, TargetCore %s\n",
           MSGCORE_VERSION_STRING, TARGETCORE_VERSION_STRING);

    /* 1. The sibling library, called directly.  If Msgcore_c.h or the Msgcore
     *    import library were missing from the install tree, this file would not
     *    have linked; if the runtime library were missing, we are not running. */
    printf("[1] Msgcore\n");
    hMgr = msgcore_mgr_create();
    check(hMgr != NULL,               "msgcore_mgr_create returned a manager");
    check(msgcore_mgr_is_valid(hMgr), "msgcore_mgr_is_valid on a fresh manager");
    msgcore_mgr_destroy(hMgr);

    /* 2. TargetCore's object model -- no environment, no threads.  Separated
     *    from the hub phase on purpose: if this passes and the hub phase does
     *    not, the library loaded and the failure is in the kernel, not the
     *    install. */
    printf("[2] TargetCore object model\n");
    hMsg = p2peermsg_create_full_u8("Install.Sender", "Install.Probe",
                                    "InstallProbe", szPayload, cbPayload);
    check(hMsg != NULL, "p2peermsg_create_full_u8 returned a message");
    if (hMsg)
    {
        check_str(p2peermsg_get_source_u8(hMsg), "Install.Sender",
                  "p2peermsg_get_source_u8 round-trips the source address");
        p2peermsg_destroy(hMsg);
        hMsg = NULL;
    }

    /* 3. A live hub: a spawned pump thread, a posted message, and a callback
     *    that crosses back over the ABI into this program. */
    printf("[3] TargetCore hub\n");
    check(targetcore_startup(4) == 1, "targetcore_startup(4)");

    hHub = p2peerhub_create_u8("Install.Probe");
    check(hHub != NULL, "p2peerhub_create_u8 returned a hub");
    if (hHub)
    {
        check(p2peerhub_set_sink_u8(hHub, sink_probe, &oCap) == 1,
              "p2peerhub_set_sink_u8 registered the callback");

        /* Stage 3 step 8: auth is on by default and an unprovisioned hub will
         * not arm.  This probe is in-process and has no peer to authenticate. */
        p2peerhub_require_auth(hHub, 0);
        check(p2peerhub_is_auth_required(hHub) == 0,
              "p2peerhub_require_auth(0) took effect");

        pvThread = p2peerhub_spawn_hub(hHub);
        check(pvThread != NULL, "p2peerhub_spawn_hub started the pump thread");
        check(p2peerhub_get_hub_id(hHub) != 0, "p2peerhub_get_hub_id is non-zero");

        /* The LEAF, not the full address.  p2peerhub_get_address_u8 returns
         * P2Paddr::c_name(), which for "Install.Probe" is "Probe", while the
         * destination the sink is handed below is the full "Install.Probe" --
         * the two disagree on purpose and MscsUnitTests/TargetCoreSuite.cpp
         * says so in as many words.  Asserted here because a consumer reading
         * only this header would guess the other way, as the first draft of
         * this file did. */
        szAddr = p2peerhub_get_address_u8(hHub);
        check_str(szAddr, "Probe",
                  "p2peerhub_get_address_u8 reports the hub address leaf");

        if (pvThread)
        {
            hMsg = p2peermsg_create_full_u8("Install.Sender", "Install.Probe",
                                            "InstallProbe", szPayload, cbPayload);
            check(hMsg != NULL, "p2peermsg_create_full_u8 for the hub post");
            /* Ownership passes to the hub; NULL back means posted. */
            check(p2peerhub_post_msg(hHub, hMsg) == NULL,
                  "p2peerhub_post_msg accepted the message");
            hMsg = NULL;

            check(wait_for_sink(&oCap, 5.0), "the sink fired within 5 s");
            check(oCap.nCalls == 1,                          "the sink fired once");
            check_str(oCap.szSrc, "Install.Sender", "sink source address");
            check_str(oCap.szDst, "Install.Probe",  "sink destination address");
            check_str(oCap.szId,  "InstallProbe",   "sink message id");
            check(oCap.cbData == (long)cbPayload,            "sink payload size");
        }

        /* NO SETTLE, AND THE ABSENCE IS THE POINT.  p2peerhub_close_hub used
         * to leave the pump THREAD running its epilogue after the hub was
         * down, and the flat C surface had no join to pair with the raw OS
         * thread handle p2peerhub_spawn_hub hands back -- so this file slept
         * 0.2s and said in a comment that it was a workaround rather than a
         * fix (step 14, finding F-S5-7).
         *
         * F-S5-7 is closed, and NOT by adding p2peerhub_join.  CloseHub()
         * itself now joins the thread it spawned (C-4), which was the same
         * question asked from the other end and is answered once for both:
         * every caller gets the guarantee instead of only the ones who read
         * the header and remembered to ask for it, and the flat surface stays
         * at 83 entry points rather than growing one whose only job is to
         * repair the contract of another.
         *
         * So when close_hub returns, the thread is GONE and the two calls
         * below are safe with nothing between them.  Deleting the sleep is
         * also what makes this file a gate rather than a demonstration: if the
         * join is ever lost, clearing the sink and destroying the hub start
         * racing a live pump thread here, with no timer papering over it. */
        p2peerhub_close_hub(hHub);
        p2peerhub_set_sink_u8(hHub, NULL, NULL);
        p2peerhub_destroy(hHub);
    }

    targetcore_cleanup();

    if (g_failures)
    {
        printf("INSTALL TREE CONSUMER FAILED (%d checks)\n", g_failures);
        return 1;
    }
    printf("INSTALL TREE CONSUMER OK\n");
    return 0;
}
