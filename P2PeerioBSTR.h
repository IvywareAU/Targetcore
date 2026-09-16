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
//  P2PeerioBSTR definitions and prototypes
//  NOTES: Manages data translation between P2PeerMsg's and BSTR type
//         formats
//       : BSTR allows data to be passed anonymously between P2PeerHub's
//         or legacy applications
//                      

#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2Peerio.h"

//
//  P2PeerioBSTR protocol management
//  NOTES: Prefixes P2PeerMsg data with size of data.  Common in
//         3rd Party type protocols
class Targetcore_EXT P2PeerioBSTR : protected P2Peerio
{
      void
        RenderThisSafe();

    // Constructors and destructor
    public:
        P2PeerioBSTR ( );
       ~P2PeerioBSTR ( );

      virtual P2Peerio*
        Clone ( );

    // BSTR - P2PeerMsg translation
    protected:
      virtual DWORD
        SendP2PeerMsg ( HANDLE hFile
                      , P2PeerMsg *pMsg
                      , OVERLAPPEDcon *pOVERLAPPEDsend );
      virtual P2PeerMsg*
        RecvP2PeerMsg ( HANDLE hFile
                      , OVERLAPPEDcon *pOVERLAPPEDrecv );

    // NOT EXEMPT FROM THE CYPHER RULE IN P2Peerio.h - AND IT IS THE REASON
    // THE RULE EXISTS
    // NOTES: Both methods above are overridden and neither consults the base
    //        class's cypher hooks.  Unlike P2PeerioDmx that is not defensible:
    //        a BSTR is a length-prefixed byte buffer handed to something else,
    //        which is a wire whatever carries it.  So LeavesProcess() is TRUE
    //        and IsCypherActive() is FALSE, and that pair is exactly what
    //        P2PeerCon::KeyXDerive refuses to arm
    //      : What that costs, concretely.  Nothing in this tree constructs
    //        this class - its Clone() returns a fresh one and no factory calls
    //        it - so the day a transport IS wired to it, that transport would
    //        have been in clear on a hub whose operator set RequireAuth(true).
    //        F-S6-1's fix does not catch it and cannot: the agreement WILL
    //        have completed and the cypher WILL be installed, and the override
    //        simply would not have consulted it.  F-S6-3
    //      : Which is why the declaration is here rather than the class being
    //        deleted.  Deleted, it takes the only worked example of the trap
    //        with it and breaks an exported surface for a class that costs
    //        nothing to keep.  Declared, a hub that requires authentication
    //        refuses to key a connection carrying it, and the constructor says
    //        so out loud - see P2PeerioBSTR.cpp
    public:
      virtual bool
        IsCypherActive ( ) const { return false; }
      virtual bool
        LeavesProcess  ( ) const { return true;  }

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
};
