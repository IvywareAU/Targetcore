// Copyright © 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerioXBee definitions and prototypes
//
//  ####################################################################
//  ##  DESIGN SKETCH.  NOT COMPILED, NOT WIRED TO ANY FACTORY.       ##
//  ##  Deliberately outside the source list in CMakeLists.txt and    ##
//  ##  the .vcxproj.  Nothing constructs it.  Refer                  ##
//  ##  MeshTransports.md for why this transport was chosen first.    ##
//  ####################################################################
//
//  NOTES: Carries P2PeerMsg images across a Digi XBee / DigiMesh radio
//         mesh by wrapping them in XBee API frames on the serial line
//         to a locally attached module.  Aggregated within a
//         P2PeerCon232, which supplies the COM handle and knows
//         nothing about this framing
//       : SHAPE A of MeshTransports.md - the mesh routes BELOW this
//         class.  One instance addresses exactly ONE remote 64-bit
//         node, so at the P2Paddr layer the link is point to point and
//         the tree-not-a-mesh constraint never binds.  Multi-hop, route
//         discovery and repair are the module's problem and are
//         invisible here
//

#pragma once

#ifndef NO_DEBUG_NEW
#define new DEBUG_NEW
#endif

#include "P2Peerio.h"

//
//  XBee API frame constants
//  NOTES: API mode 1 (ATAP=1, no escaping).  Refer the escaping note on
//         the class below before changing this
#define XBeeAPI_Delimiter     0x7E   // Start of every API frame
#define XBeeAPI_TxRequest     0x10   // Host -> module, addressed transmit
#define XBeeAPI_TxStatus      0x8B   // Module -> host, per-frame delivery result
#define XBeeAPI_RxPacket      0x90   // Module -> host, received data
#define XBeeAPI_ModemStatus   0x8A   // Module -> host, join/leave/reset
#define XBeeAPI_ATResponse    0x88   // Module -> host, AT command result

// Overhead of a 0x10 TX Request: frame type, frame ID, dest64, dest16,
// broadcast radius, options.  Payload follows
#define XBeeAPI_TxOverhead      14
// Overhead of a 0x90 RX Packet: frame type, src64, src16, options
#define XBeeAPI_RxOverhead      12
// Delimiter + 16-bit length + trailing checksum
#define XBeeAPI_FrameOverhead    4

//
//  P2PeerioXBee fragment header
//  NOTES: Prefixes the P2Piomage bytes carried in EACH API frame's RF
//         payload.  Four bytes, and every one of them is load bearing
//       : WHY A FRAGMENT HEADER IS NEEDED AT ALL, given that the
//         VBListIOmage already carries its own total size and the base
//         class reassembles a stream from it with no help.  Because
//         this is NOT a stream.  TCP, the named pipe and the bare
//         serial line all deliver bytes in order, so the base class can
//         treat "the next byte" as unambiguous.  A mesh delivers
//         FRAMES, and Zigbee and DigiMesh both reorder them - a
//         retried frame arrives after one that was not retried, and the
//         local module emits RX packets in arrival order.  Concatenating
//         RF payloads in arrival order therefore produces a corrupt
//         image, and it corrupts it in the worst available way: the
//         VBListIOmage sync complement still passes, because the header
//         bytes usually arrive first
#pragma pack(push,1)
typedef struct
{
    unsigned char ucSeq;               // Message sequence, wraps at 256
    unsigned char ucIndex;             // 0-based fragment index
    unsigned char ucCount;             // Total fragments in this message
    unsigned char ucFlags;             // Reserved, must be zero
} P2PxbeeFragHdr;
#pragma pack(pop)

//
//  P2PeerioXBee protocol management
//  NOTES: Translates between P2PeerMsg images and XBee API frames
class Targetcore_EXT P2PeerioXBee : public P2Peerio
{
      void
        RenderThisSafe();

    // Constructors and destructor
    public:
        P2PeerioXBee ( );
        P2PeerioXBee ( unsigned __int64 u64RemoteAddr );
       ~P2PeerioXBee ( );

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

    // THIS CLASS IS NOT EXEMPT FROM THE CYPHER RULE, AND DOES NOT ASK TO BE
    // NOTES: Both message methods above are overridden, which is what
    //        P2PeerioBSTR does and is the shape F-S6-3 warns about.  The
    //        difference is what the overrides DO: SendP2PeerMsg below calls
    //        EncryptP2PiomageSwap and mints m_bSealDecided exactly as the base
    //        does, and RecvP2PeerMsg calls DecryptP2PiomageSwap before it
    //        constructs the P2PeerMsg.  The hooks are consulted, so
    //        IsCypherActive() is deliberately NOT overridden - the base class
    //        pointer test is the truthful answer and overriding it to say
    //        anything else would be a lie in the snapshot
    //      : LeavesProcess() is stated rather than inherited even though the
    //        base already answers true.  The bytes go out a COM port to a
    //        radio and then over the air to a mesh whose intermediate hops
    //        this process does not own and cannot see.  Of every transport in
    //        the tree this is the one with the most third parties positioned
    //        between the two ends, and a reader should not have to derive that
    //        from a default
    //      : THE ORDER MATTERS AND IT IS THE OPPOSITE OF THE OBVIOUS ONE.
    //        Seal the WHOLE image once, then fragment the sealed bytes.  Not
    //        fragment first and seal each fragment: that is N nonces and N
    //        tags for one message, it leaks the fragment boundaries, and it
    //        gives an attacker a per-fragment oracle.  Fragmentation is
    //        transport framing and belongs OUTSIDE the seal
    public:
      virtual bool
        LeavesProcess ( ) const { return true; }

    // Specialisation
    public:
      virtual void
        Reset ( );

    // Properties
    public:
      unsigned __int64
        SetRemoteAddr64 ( unsigned __int64 u64RemoteAddr );
      unsigned __int64
        GetRemoteAddr64 ( ) const;
      // Maximum RF payload the attached module will accept in one frame.
      // MUST be set from the module's ATNP response at startup rather than
      // assumed: it varies by firmware (Zigbee is commonly 84 bytes with
      // encryption off, DigiMesh up to 256) and a value larger than the
      // module's own is rejected frame by frame, which presents as a mesh
      // that carries small messages and silently drops large ones
      // : Throws outside 1+sizeof(P2PxbeeFragHdr)..256.  The upper bound is
      //   the largest NP any current firmware reports and is what lets
      //   SendP2PeerMsg build frames in a fixed buffer; the lower bound stops
      //   nPerFrame underflowing to a value that would allocate the whole
      //   address space one fragment at a time
      UINT
        SetMaxRFPayload ( UINT nBytes );
      UINT
        GetMaxRFPayload ( ) const;

    // Troubleshooting
    public:
      virtual void
        AssertValid ( ) const;
      virtual P3PmsgItem
        SetP2PeventFParams ( LPCTNAM lpszVar );

    // Implementation helpers
    protected:
      // Builds one 0x10 TX Request into pBuffer, returns bytes written
      UINT
        BuildTxRequest ( char *pBuffer
                       , const void *pvPayload, UINT nPayloadSize
                       , unsigned char ucFrameID );
      // 0xFF minus the 8-bit sum of the frame data bytes
      unsigned char
        Checksum ( const char *pcFrameData, UINT nSize ) const;
      // Accepts one complete inbound API frame.  Returns the reassembled
      // P2Piomage when this frame completed a message, otherwise 0
      P2Piomage*
        On_APIframe ( const char *pcFrameData, UINT nSize );
      void
        DropReassembly ( );

    // Attributes
    protected:
      unsigned __int64  m_u64RemoteAddr; // The one node this instance addresses
      UINT              m_nMaxRFPayload; // ATNP, see SetMaxRFPayload above
      unsigned char     m_ucSeqSend;     // Outbound message sequence
      char             *m_pSendFrames;   // Scratch: ALL API frames for one
                                         //   message, contiguous, so the whole
                                         //   message is ONE overlapped write
      UINT              m_nSendFramesMax;

      // Reassembly, one message deep
      char             *m_pReasm;        // Reassembled P2Piomage bytes
      UINT              m_nReasmSize;    // Bytes committed so far
      UINT              m_nReasmMax;     // Allocation
      unsigned char     m_ucSeqRecv;     // Sequence being reassembled
      unsigned char     m_ucFragSeen;    // Count of distinct fragments taken
      unsigned char     m_ucFragCount;   // Expected, from the first fragment
      PITimerID         m_nPITimerReasm; // Abandons a message whose remaining
                                         //   fragments never arrive
};
