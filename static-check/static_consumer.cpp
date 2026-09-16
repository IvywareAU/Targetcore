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
 * static_consumer.cpp -- the gate for the DebugLib/ReleaseLib shape.
 *
 * WHY THIS FILE EXISTS. Until 2026-08-22 nothing anywhere linked a static build
 * of these cores. The vcxproj declares four such configurations
 * (DebugLib/ReleaseLib x Win32/x64) and CMake now declares the targets, but a
 * target that only ever gets ARCHIVED is barely tested: the compiler has seen
 * every TU, and nothing has ever resolved a symbol across the archive boundary
 * or run a line of it. Both defects found on that date were in exactly such a
 * path, so this file links the archives and RUNS them.
 *
 * It is deliberately narrow. The full behaviour of the cores is MscsUnitTests'
 * job and that suite runs against the shared libraries. What can only be
 * measured here is what changes when Msgcore_STATIC / Targetcore_STATIC are
 * defined and the code arrives by archive rather than by import library, so
 * this covers exactly the two things that were broken:
 *
 *   [1] P2PCngCrypto.h under Targetcore_STATIC. Its export macro was guarded
 *       `_WIN32 && !defined(Targetcore_STATIC)`, so a Windows static build fell
 *       through to the GCC arm and MSVC was handed
 *       __attribute__((visibility("default"))). That is a COMPILE failure, so
 *       merely including the header here would catch a regression -- but
 *       including a header proves only that it parses. Calling SelfTest()
 *       proves the declaration and the definition agreed about linkage, which
 *       is the half a syntax check cannot see.
 *
 *   [2] The nested-vector deep copy. P2PmsgVect_SizeofItem allocated the item
 *       block by one rule and P2PmsgVect_InitItem laid it out by another; on
 *       Win32 the name was sized at 27 bytes and 127 were written, so the
 *       VBLockData landed past the end of its block. The case below is the one
 *       from MscsUnitTests/MsgcoreSuite.cpp that failed, plus the descriptor
 *       PushBack from golden_utf16 that failed beside it -- both reached
 *       through the archive.
 *
 * A NOTE ON WHAT A PASS HERE MEANS. It means the archives link and the paths
 * below run. It does not mean the static configuration is as well covered as
 * the shared one; it is not, and the row in Readme.md says so. This is the
 * first thing that has ever linked them, not the last thing that should.
 */

#include "stdafx.h"

#include "P2Pmsg.h"
#include "MsgDesc.h"
#include "MsgVect.h"
#include "Msgexception.h"
#include "P2PmsgMgr.h"
#include "P2PCngCrypto.h"

#include <cstdio>

static int g_failures = 0;

static void check ( bool bCond, const char *szWhat )
{
    if ( bCond ) { std::printf("  ok    %s\n", szWhat); return; }
    std::printf("  FAIL  %s\n", szWhat);
    ++g_failures;
}

static void check_eq ( long nGot, long nWant, const char *szWhat )
{
    if ( nGot == nWant ) { std::printf("  ok    %s\n", szWhat); return; }
    std::printf("  FAIL  %s (wanted %ld, got %ld)\n", szWhat, nWant, nGot);
    ++g_failures;
}

int main ( void )
{
    std::printf("static-check consumer\n");

    //  The whole point of the file: if these are not defined, the build system
    //  wired the shared libraries in and everything below would measure the
    //  wrong artifact while passing.
#if !defined(Msgcore_STATIC)
    std::printf("  FAIL  Msgcore_STATIC is not defined -- this is not a static build\n");
    return 2;
#endif
#if !defined(Targetcore_STATIC)
    std::printf("  FAIL  Targetcore_STATIC is not defined -- this is not a static build\n");
    return 2;
#endif
    std::printf("  ok    Msgcore_STATIC and Targetcore_STATIC are both defined\n");

    //  [1] The crypto backend, reached through the header whose static arm had
    //      never been compiled. SelfTest runs the RFC 4231 / RFC 5869 KATs.
    std::printf("[1] P2PCngCrypto under Targetcore_STATIC\n");
    try
    {
        check ( p2pcng::SelfTest(), "p2pcng::SelfTest() passes from the archive" );
    }
    catch ( ... )
    {
        check ( false, "p2pcng::SelfTest() threw" );
    }

    //  [2] The vect paths that corrupted memory at 32 bits. Two of them: the
    //      nested InsertAt from MsgcoreSuite, and the descriptor PushBack from
    //      golden_utf16. They fail differently -- the first trips the
    //      containment ASSERT, the second throws a P2Pevent -- so both are here.
    std::printf("[2] nested vector deep copy\n");
    try
    {
        P3PmsgVect oInner ( 2, L"Inner", P3PmsgData((int)0) );
        oInner.r_data(0).c_int(7);
        oInner.r_data(1).c_int(8);

        P3PmsgVect oOuter ( 0, L"Outer", P3PmsgData((int)0) );
        oOuter.InsertAt ( 0, P3PmsgField(L"scalar", P3PmsgData((int)1)) );
        oOuter.InsertAt ( 1, oInner );              // element 1 is itself a vect

        check_eq ( (long)oOuter.GetCount(), 2, "outer vect holds two elements" );
        check    ( oOuter.IsVect(1),           "element 1 is a vect" );
        check_eq ( (long)oOuter.r_vect(1).GetCount(), 2, "inner vect kept its count" );
        check_eq ( (long)oOuter.r_vect(1).r_data(1).c_int(), 8, "inner element value survived the copy" );

        //  Independence: the copy must not alias the source.
        oInner.r_data(1).c_int(99);
        check_eq ( (long)oOuter.r_vect(1).r_data(1).c_int(), 8,
                   "mutating the source leaves the copy alone" );
    }
    catch ( P2Pevent *pEv )
    {
        check ( false, "nested vector copy raised a P2Pevent" );
        if ( pEv ) pEv->Cancel(true);
    }
    catch ( ... )
    {
        check ( false, "nested vector copy threw" );
    }

    //  [3] The descriptor PushBack path -- this is the one golden_utf16 died in,
    //      and it is a different entry point into the same block arithmetic.
    std::printf("[3] descriptor PushBack of a vect\n");
    try
    {
        P2PmsgMgr  oMgr;
        P3PmsgVect oVect ( 2, L"Persisted", P3PmsgData((int)0) );
        oVect.r_data(0).c_int(1);
        oVect.r_data(1).c_int(2);

        oMgr.r_Desc() += oVect;

        //  Selecting it back is the same shape golden_utf16 uses, and it checks
        //  the CONTENT rather than merely that a handle came back: the block
        //  under-allocation this gate is here for produced an object that
        //  existed and held the wrong bytes.
        P3PmsgVect oBack ( oMgr.r_Desc().SelectVect(L"Persisted").r_Object() );
        check_eq ( (long)oBack.GetCount(), 2, "the pushed vect round-trips with both elements" );
        check_eq ( (long)oBack.r_data(1).c_int(), 2, "second element value survived PushBack" );
    }
    catch ( P2Pevent *pEv )
    {
        check ( false, "descriptor PushBack raised a P2Pevent" );
        if ( pEv ) pEv->Cancel(true);
    }
    catch ( ... )
    {
        check ( false, "descriptor PushBack threw" );
    }

    if ( g_failures )
    {
        std::printf("STATIC CONSUMER FAILED (%d checks)\n", g_failures);
        return 1;
    }
    std::printf("STATIC CONSUMER OK\n");
    return 0;
}
