// Copyright © 2005-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerioDmx definitions and prototypes
//  NOTES: Performs in-process P2PeerMsg image exchanges with direct
//         use of the IO Completion Port
//                      

#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2Peerio.h"

//
//  P2PeerioDmx protocol management
//  NOTES: Performs in-process P2PeerMsg image exchange
class Targetcore_EXT P2PeerioDmx : public P2Peerio
{
      void
        RenderThisSafe();

    // Constructors and destructor
    public:
        P2PeerioDmx ( );
       ~P2PeerioDmx ( );

      virtual P2Peerio*
        Clone ( );

    // P2PeerMsg exchange
    protected:
      virtual DWORD
        SendP2PeerMsg ( HANDLE hFile
                      , P2PeerMsg *pMsg
                      , OVERLAPPEDcon *pOVERLAPPEDsend );
      virtual P2PeerMsg*
        RecvP2PeerMsg ( HANDLE hFile
                      , OVERLAPPEDcon *pOVERLAPPEDrecv );

    // THE ONE EXEMPTION FROM THE CYPHER RULE IN P2Peerio.h, DECLARED HERE
    // NOTES: Both message methods above are overridden and neither consults
    //        the base class's cypher hooks.  For any other transport that is
    //        the F-S6-3 defect; for this one it is correct, and the answer to
    //        LeavesProcess() below is what makes the difference a DECLARATION
    //        rather than a property of which class the factory happened to
    //        construct
    //      : Why it is correct.  The DMX handoff is a pointer between two
    //        objects in ONE process - SendP2PeerMsg does
    //        pThat = (P2PeerioDmx *)hFile and the receiver copies out of this
    //        object's memory.  Nothing is serialised, nothing is written to a
    //        socket, a pipe or a port, and no third party is ever positioned
    //        between the two ends.  There is no wire, so there is nothing for
    //        a cypher to protect: it would encrypt a buffer and decrypt it
    //        again a few instructions later, for a reader who by construction
    //        already has the plaintext
    //      : THIS PARAGRAPH IS THE POINT OF F-S6-3.  The reasoning was true
    //        before and appeared nowhere in the tree - it had to be
    //        reconstructed by reading the transport for THREAT_MODEL.md, and
    //        a reader who found the omission without it would reasonably have
    //        called it a bug.  An exemption that is only obvious to whoever
    //        wrote it is not an exemption, it is a coincidence
    //      : Anyone adding a SECOND exemption reads this first.  The test is
    //        not "is encrypting this awkward", it is "can anything outside
    //        this process observe the bytes".  If it can, the answer to
    //        LeavesProcess() is true and the hooks are not optional
    public:
      virtual bool
        IsCypherActive ( ) const { return false; }
      virtual bool
        LeavesProcess  ( ) const { return false; }

    // Specialisation
    public:
      virtual void
        Reset ( );

      //  Hands a PARKED read back to the completion port, carrying hrPost
      //  NOTES: The one path by which a parked read leaves the park.  RecvP2PeerMsg
      //         parks a buffer when the peer has nothing to say, and the park holds
      //         a reference on the owning connection (OVERLAPPEDcon::bParked).  This
      //         posts the buffer - which takes the port's own reference - and then
      //         releases the park's, so the owner is never last-released from here
      //         and the completion arrives on the OWNER'S pump: S_OK from the peer's
      //         send (data is waiting), ERROR_OPERATION_ABORTED from the peer's
      //         Drop() or this object's Reset() (the partner is gone, and the
      //         owner's own hub closes it).  Idempotent: false when nothing is parked
      //       : Under g_oCSectP2PeerConDmx, because the peer's send and the owner's
      //         drop can race for the same park from two pumps
      //       : Refer OpenCodeWork.md item 7 for why the park holds a reference at
      //         all, and P2PeerConDmx::Drop() for the six designs that failed before
      //         it did
      bool
        UnparkRecv ( HRESULT hrPost );

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;

    // Attributes
    protected:
      OVERLAPPEDcon *m_pOVERLAPPEDrecv;
      OVERLAPPEDcon *m_pOVERLAPPEDsend;
};
