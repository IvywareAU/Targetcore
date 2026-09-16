// Copyright © 2002-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2Pmsg_MAP definitions and prototypes
//  NOTES: Contains definitions and prototypes for the P2PeerSys,
//         P2PeerCon and P2PeerMsg_MAP's
//       : Such map's are supported by any class derived from
//         P2PeerTarget
//
#pragma   once

#include "MsgCollectors.h"

//  Post VS2005 Microsoft introduced requirement that ATL/MFC code should use
//  standard pointer to member with syntax &MyClass::MyMethod, instead
//  of the legacy non-standard syntax - MyMethod.
//  Example: BEGIN_P2PeerMsg_MAP(P2PeerHub, P2PeerTarget)
//             Pre-VS2005 style  (less verbose)
//             ON_P2PeerMsg(P2Pmsg_BCast, On_P2PeerBCast)
//             Post-VS2005 style (more verbose)
//             ON_P2PeerMsg(P2Pmsg_BCast, &P2PeerTarget::On_P2PeerBCast)
//           END_P2PeerMsg_MAP()
//         : Subsequent definition introduced to P2Peer<Sys, Con, Msg>_MAP's
//           to facilitate a common code base between pre-VS2005 and
//           post-VS2005 implementations.  Both styles accomodated.
#ifndef  PTM_WARNING_DISABLE
  #define PTM_WARNING_DISABLE
  #define PTM_WARNING_RESTORE
#endif
  #ifdef _MSC_VER
  #define P2P_MEMFN_CAST      static_cast          // MSVC: legacy bare-name form (PTM warning suppressed)
  #define P2P_MEMFN_ADDR(FXN) (FXN)
  #else
  #define P2P_MEMFN_CAST      reinterpret_cast     // GCC/Clang: &Class::Fxn (formed under -fpermissive) + member-ptr reinterpret
  #define P2P_MEMFN_ADDR(FXN) (&FXN)
  #endif

P2PmsgCN const 
CN_P2PeerCon =  1;                     // P2PeerCon_MAP interceptions
P2PmsgCN const
CN_P2PeerMsg =  2;                     // P2PeerMsg_MAP interception
P2PmsgCN const
CN_P2PeerSys =  4;                     // P2PeerSys_MAP interception
P2PmsgCN const
CN_P2PeerSnc =  8;                     // P2PeerSnk_MAP interception
P2PmsgCN const
CN_P2PeerExp = 16;                     // P2PeerExp_MAP interception
P2PmsgCN const
CN_P2Pevent  = 32;                     // P2Pevent interception
P2PmsgCN const
CN_Mask      = CN_P2PeerCon | CN_P2PeerMsg | CN_P2PeerSys | CN_P2PeerSnc;

// Command moderators
// NOTES: Used by the P2Pmsg internals to transparently moderate
//        the behaviour of command notifications
P2PmsgCN const
CM_Mapcast   = 0x80000000;             // Map casting modifier (last bit)
P2PmsgCN const
CM_Mask      = CM_Mapcast;             // Moderators mask

// P2PeerCon modes
// NOTES: Used to moderate behaviour of P2PeerCon_MAP's
P2PmsgCN const
CM_ALL       =  0;
P2PmsgCN const
CM_SERVER    =  1;
P2PmsgCN const
CM_CLIENT    =  2;
P2PmsgCN const
CM_ACCEPT    =  4;

/////////////////////////////////////////////////////////////////////////////
//  P2Peer<Msg,Sys,Con>_MAP signatures
//  NOTES: Subject to ammendment between releases
enum P2PSig
{
	  P2PSig_End    = 0,       // End of message map
    P2PSig_Unwrap = 1,       // Unwrap entry directive

                             // P2PeerMsg_MAP signatures
    P2PSig_Msg,              // msgRESULT (P2PeerMsg*)
    P2PSig_MsgPeek,          // msgRESULT (P2PeerMsg*)
    P2PSig_MsgMapcast,       // msgRESULT (P2PeerMsg*)
    P2PSig_MsgCatch,         // msgRESULT (P2PeerMsg*)
    P2PSig_MsgReflect,       // msgRESULT (P2PeerMsg*)
    P2PSig_MsgReflectCatch,  // msgRESULT (P2PeerMsg*)
    P2PSig_MsgAck,           // msgRESULT (P2PeerMsg*)
    P2PSig_MsgAckCatch,      // msgRESULT (P2PeerMsg*)
    P2PSig_MsgTimer,         // msgRESULT (P2PeerMsg*)
    P2PSig_MsgTimerCatch,    // msgRESULT (P2PeerMsg*)
    P2PSig_MsgNotify,        // msgRESULT (P2PeerMsg*)
    P2PSig_MsgNotifyCatch,   // msgRESULT (P2PeerMsg*)
    P2PSig_MsgBroadcast,     // msgRESULT (P2PeerMsg*,P2PeerMsg**)
    P2PSig_MsgEvent,         // msgRESULT (P2PeerMsg*)
    P2PSig_MsgEventCatch,    // msgRESULT (P2PeerMsg*)

                             // P2PeerSys_MAP signatures
    P2PSig_Sys,              // sysRESULT (WPARAM,LPARAM)

                             // P2PeerSnk_MAP signatures
    P2PSig_Snc,              // sncRESULT (WPARAM,LPARAM)
    P2PSig_SnkP2PeerMsg,     // sncRESULT (P2PeerMsg*)
    P2PSig_SncP2PmsgItem,    // sncRESULT (P3PmsgItem*,WPARAM,LPARAM)
    P2PSig_SncP2PmsgNode,    // sncRESULT (P3PmsgNode*,WPARAM,LPARAM)

                             // P2PeerCon_MAP signatures
    P2PSig_Con,              // conRESULT (P2PeerCon*)
    P2PSig_ConLogin,         // conRESULT (P2PeerCon*,void*,P2Psize_t)
    P2PSig_ConLoginAck,      // conRESULT (P2PeerCon*,P2Paddr&,P2Paddr&,void*,P2Psize_t)
    P2PSig_ConPeek,          // conRESULT (P2PeerCon*,UINT,nMsg );
    P2PSig_ConPKeyXChange,   // conRESULT (P2PeerCon*,void*,P2Psize_t)
    P2PSig_ConPKeyXChangeAck,// conRESULT (P2PeerCon*,void*,P2Psize_t)
    P2PSig_ConCypherEx,      // conRESULT (P2PeerCon*,P2Pmsg*);
};

///////////////////////////////////////////////////////////////////////
//  P2PeerMsg_MAP definitions
//
struct P2P_MSGMAP_ENTRY;     // Forward declaration

struct P2P_MSGMAP
{
	const P2P_MSGMAP        *pBaseMap;
	const P2P_MSGMAP_ENTRY *lpEntries;
};

//
//  P2Peer message map
//  NOTES: Required declaration within any class implementing
//         mapping for P2PeerMsg's
#define DECLARE_P2PeerMsg_MAP() \
    private: \
	    static const P2P_MSGMAP_ENTRY _P2PeerMsgEntries[]; \
    protected: \
	    static  const P2P_MSGMAP  P2PeerMsgMap; \
	    virtual const P2P_MSGMAP* \
        GetP2PeerMsgMap() const; \
      LPCTSTR \
        GetThisClassName() const; \

//
//  P2Peer message map wrappers
//  NOTES: P2Peer message mapping macros must be encapsulated
//         by the following two wrappers
#define BEGIN_P2PeerMsg_MAP(theClass, baseClass) \
PTM_WARNING_DISABLE \
const P2P_MSGMAP* \
theClass::GetP2PeerMsgMap() const \
{ return &theClass::P2PeerMsgMap; } \
LPCTSTR \
theClass::GetThisClassName() const \
{ return L#theClass; } \
AFX_COMDAT const P2P_MSGMAP theClass::P2PeerMsgMap \
   = { &baseClass::P2PeerMsgMap, &theClass::_P2PeerMsgEntries[0] }; \
AFX_COMDAT const P2P_MSGMAP_ENTRY theClass::_P2PeerMsgEntries[] \
   = { \

#define END_P2PeerMsg_MAP() \
{ 0, 0, 0, 0, 0, 0, 0, P2PSig_End, (P2P_PMSG)0 } \
  }; \
  PTM_WARNING_RESTORE

// pointer to afx_msg member function
class   P2PeerTarget;
#ifndef P2P_MSG_CALL
#define P2P_MSG_CALL
#endif
typedef void (P2P_MSG_CALL P2PeerTarget::*P2P_PMSG)(void);

//
//  P2Peer message map entries
//  NOTES: Wrapper for each P2PeerMsg_MAP entry 
#pragma warning( disable: 4121 )
struct P2P_MSGMAP_ENTRY
{
    LPCWSTR  sMsg;           // P2Pmsg identifer
    LPCWSTR  lpszHandler;    // Handler name
    USHORT nMessage;         // P2Peer message number
    USHORT uMsgState;        //                state;
    UINT   nCode;            // Control code or WM_NOTIFY code
    UINT   nID;              // control ID (or 0 for windows messages)
                             // Source hub P2PeerAddr (Lower range address)
    UINT nLastID;            // used for entries specifying a range of control id's
                             // Source hub P2PeerAddr (Upper range address)
    UINT_PTR nSig;           // Signature type (action) or pointer to message #
    P2P_PMSG pfn;            // routine to call (or special value)
    BOOL     bMapcast;       // Map casting flag
    BYTE     nOSets;         // Map navigation offsets
};
#pragma warning( default: 4121 )

///////////////////////////////////////////////////////////////////////
//  P2PeerSnk map handling
//  NOTES: Definitions supports map P2PeerTarget sink message handlers
//
struct P2P_SNKMAP_ENTRY;     // Forward declaration

struct P2P_SNKMAP
{
	  const P2P_SNKMAP        *pBaseMap;
	  const P2P_SNKMAP_ENTRY *lpEntries;
};

//
//  P2PeerSnk map
//  NOTES: Required declaration within any class implementing
//         mapping for SNK notifications
#define DECLARE_P2PeerSnk_MAP() \
    private: \
	    static const P2P_SNKMAP_ENTRY _P2PeerSnkEntries[]; \
    protected: \
	    static  const P2P_SNKMAP  P2PeerSnkMap; \
	    virtual const P2P_SNKMAP* \
        GetP2PeerSnkMap() const; \

//
//  P2PeerSnk map wrappers
//  NOTES: P2PeerSNK mapping macros must be encapsulated
//         by the following two wrappers.  Such P2PeerSNK's are internal to the
//         P2PeerTarget and are not intended to be used by external clients.  The
//         appropriate mechanism for external clients to post P2PeerSnk messages
//         to a target sink is via the P2PeerTarget::PostP2PeerSnk() function.
//       : Refer P2PeerTarget::PostP2PeerSnk() for posting P2PeerSnk messages
//         to the target sink
//       : Refer P2PeerTarget::RegisterWithTargetSink () for registering with
//         the target sink and obtaining the P2PmsgSinkID for posting P2PeerSnk
//         messages to the target sink	
//       : Refer P2PeerTarget::CreateTargetSink () for creating a new target
//         sink and obtaining the P2PmsgSinkID for posting P2PeerSnk messages
//         to the target sink.
//       : Refer P2PeerTarget::CancelTargetSinkRegistration () for cancelling
//         registration with the target sink and releasing the P2PmsgSinkID
//         for posting P2PeerSnk messages to the target sink

#define BEGIN_P2PeerSnk_MAP(theClass, baseClass) \
PTM_WARNING_DISABLE \
const P2P_SNKMAP* \
theClass::GetP2PeerSnkMap() const \
{ return &theClass::P2PeerSnkMap; } \
AFX_COMDAT const P2P_SNKMAP theClass::P2PeerSnkMap \
   = { &baseClass::P2PeerSnkMap, &theClass::_P2PeerSnkEntries[0] }; \
AFX_COMDAT const P2P_SNKMAP_ENTRY theClass::_P2PeerSnkEntries[] \
   = { \

#define END_P2PeerSnk_MAP() \
{ 0, 0, 0, 0, P2PSig_End, (P2P_PSNK)0, 0, 0 } }; \
  PTM_WARNING_RESTORE

// pointer to afx_msg member function
class   P2PeerTarget;
#ifndef P2P_SNK_CALL
#define P2P_SNK_CALL
#endif
typedef void (P2P_SNK_CALL P2PeerTarget::*P2P_PSNK)(void);

//
//  P2PeerSnk map entries
//  NOTES: Wrapper for each P2PeerSnk_MAP entry 
#pragma warning( disable: 4121 )
struct P2P_SNKMAP_ENTRY
{
    USHORT   nMessage;       // P2Peer message number
    UINT     nCode;          // Control code or WM_NOTIFY code
    UINT     nID;            // control ID (or 0 for windows messages)
                             // Source hub P2PeerID (Lower range address)
    UINT     nLastID;        // used for entries specifying a range of control id's
                             // Source hub P2PeerID (Upper range address)
    UINT_PTR nSig;           // signature type (action) or pointer to message #
    P2P_PSNK pfn;            // routine to call (or special value)
    BOOL     bMapcast;       // Map casting
    BYTE     nOSets;         // Map navigation offsets
};
#pragma warning( default: 4121 )

///////////////////////////////////////////////////////////////////////
//  P2PeerSys map handling

struct P2P_SYSMAP_ENTRY;     // Forward declaration

struct P2P_SYSMAP
{
	const P2P_SYSMAP        *pBaseMap;
	const P2P_SYSMAP_ENTRY *lpEntries;
};

//
//  P2PeerSys map
//  NOTES: Required declaration within any class implementing
//         mapping for SYS notifications
#define DECLARE_P2PeerSys_MAP() \
    private: \
	    static const P2P_SYSMAP_ENTRY _P2PeerSysEntries[]; \
    protected: \
	    static  const P2P_SYSMAP  P2PeerSysMap; \
	    virtual const P2P_SYSMAP* \
        GetP2PeerSysMap() const; \

//
//  P2PeerSys map wrappers
//  NOTES: P2PeerSYS mapping macros must be encapsulated
//         by the following two wrappers
#define BEGIN_P2PeerSys_MAP(theClass, baseClass) \
PTM_WARNING_DISABLE \
const P2P_SYSMAP* \
theClass::GetP2PeerSysMap() const \
{ return &theClass::P2PeerSysMap; } \
AFX_COMDAT const P2P_SYSMAP theClass::P2PeerSysMap \
   = { &baseClass::P2PeerSysMap, &theClass::_P2PeerSysEntries[0] }; \
AFX_COMDAT const P2P_SYSMAP_ENTRY theClass::_P2PeerSysEntries[] \
   = { \

#define END_P2PeerSys_MAP() \
{ 0, 0, 0, 0, P2PSig_End, (P2P_PSYS)0, 0, 0 } }; \
  PTM_WARNING_RESTORE \


// pointer to afx_msg member function
class   P2PeerTarget;
#ifndef P2P_SYS_CALL
#define P2P_SYS_CALL
#endif
typedef void (P2P_SYS_CALL P2PeerTarget::*P2P_PSYS)(void);

//
//  P2PeerSys map entries
//  NOTES: Wrapper for each P2PeerSys_MAP entry 
#pragma warning( disable: 4121 )
struct P2P_SYSMAP_ENTRY
{
    USHORT   nMessage;       // P2Peer message number
    UINT     nCode;          // Control code or WM_NOTIFY code
    UINT     nID;            // control ID (or 0 for windows messages)
                             // Source hub P2PeerID (Lower range address)
    UINT     nLastID;        // used for entries specifying a range of control id's
                             // Source hub P2PeerID (Upper range address)
    UINT_PTR nSig;           // signature type (action) or pointer to message #
    P2P_PSYS pfn;            // routine to call (or special value)
    BOOL     bMapcast;       // Map casting
    BYTE     nOSets;         // Map navigation offsets
};
#pragma warning( default: 4121 )

///////////////////////////////////////////////////////////////////////
//  P2PeerCon_MAP handling
//  NOTES: Definitions and prototypes

//  P2PeerCon_MAP handler
//  NOTES: Definited as void function pointer.  Cast dynamically at
//         run time according to signature type 
class   P2PeerTarget;
#ifndef P2P_CON_CALL
#define P2P_CON_CALL
#endif
typedef void (P2P_CON_CALL P2PeerTarget::*P2P_PCON)(void);

//
//  P2PeerCon_MAP entries
//  NOTES: Wrapper for each P2PeerCon_MAP entry 
#pragma warning( disable: 4121 )
struct P2P_CONMAP_ENTRY
{
    USHORT   nMessage;       // P2Peer message number
    UINT     nCode;          // Control code or WM_NOTIFY code
    LPCWSTR  strP2Padom;     // P2Padomain for map entries
                             // Eg: "*"    all P2Paddr's
                             //     "A.<B,C,D>" P2Paddr's "A.B", "A.C", "A.D"
    UINT     nMode;          // Connection mode
                             //   CM_STARTUP
                             //   CM_ACCEPT
                             //   CM_CONNECT
                             //   CM_CLOSE
    UINT_PTR nSig;           // signature type (action) or pointer to message #
    P2P_PCON pfn;            // routine to call (or special value)
    BYTE     nOSets;         // P2PeerCon_MAP navigation offsets
};
#pragma warning( default: 4121 )

//
//  P2PeerCon_MAP container
//  NOTES: 
struct P2P_CONMAP
{
	const P2P_CONMAP        *pBaseMap;
	const P2P_CONMAP_ENTRY *lpEntries;
};

//
//  P2PeerCon_MAP declaration (.h)
//  NOTES: Required declaration within any P2PeerTarget derived class
//         propogating P2PeerCON_MAP's
#define DECLARE_P2PeerCon_MAP() \
    private: \
	    static const P2P_CONMAP_ENTRY _P2PeerConEntries[]; \
    protected: \
	    static  const P2P_CONMAP  P2PeerConMap; \
	    virtual const P2P_CONMAP* \
        GetP2PeerConMap() const; \

//
//  P2PeerCon_MAP implementation (.cpp)
//  NOTES: P2PeerCon_MAP macros must be encapsulated by the following
//         two wrappers
#define BEGIN_P2PeerCon_MAP(theClass, baseClass) \
PTM_WARNING_DISABLE \
const P2P_CONMAP* \
theClass::GetP2PeerConMap() const \
{ return &theClass::P2PeerConMap; } \
AFX_COMDAT const P2P_CONMAP theClass::P2PeerConMap \
   = { &baseClass::P2PeerConMap, &theClass::_P2PeerConEntries[0] }; \
AFX_COMDAT const P2P_CONMAP_ENTRY theClass::_P2PeerConEntries[] \
   = { \

#define END_P2PeerCon_MAP() \
{ 0, 0, L"", 0, P2PSig_End, (P2P_PCON)0, 0 } }; \
  PTM_WARNING_RESTORE \

/////////////////////////////////////////////////////////////////////////////
// User extensions for message map entries

//
//  Intercepts P2PeerMsg
//  NOTES: Use ON_P2PeerMsg_REFLECT map entry to intercept reflected
//         P2PeerMsg's of nominated type
#define ON_P2PeerMsg(message, memberFxn) \
{ message, _T(#memberFxn), 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Msg, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },
//
//  Intercepts P2PeerMsg
//  NOTES: 
//       : Use ON_P2PeerMsg_MAPCAST map entry to intercept
//         P2PeerMsg's of nominated type and subsequently map cast
//         to all registered P2PeerTarget derived children
#define ON_P2PeerMsg_MAPCAST(message, memberFxn) \
	 { message, _T(#memberFxn), 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Msg, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(memberFxn)), TRUE, 1 },

//
//  Catches exception containing P2PeerMsg
//  NOTES: Catches exceptions containing messages of the nominated
//         type.  Precipitating P2PeerMsg is wrapped within the
//         exception
//       : Use ON_P2PeerMsg_REFLECT_CATCH map entry to catch
//         reflected P2PeerMsg's of nominated type
#define ON_P2PeerMsg_CATCH(message, catchFxn) \
   { P2Pmsg_Exception, _T(#catchFxn), 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 2 }, \
	 { message, _T(#catchFxn), 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_MsgCatch, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
    P2P_MEMFN_ADDR(catchFxn)), FALSE, 1 },

//
//  Catches exception containing P2PeerMsg exception
//  NOTES: Used ON_P2PeerMsg_CATCH map entry to catch single level
//         exceptions of the nominated type
//       : Use ON_P2PeerMsg_REFLECT_CATCH_CATCH map entry to catch
//         single level exceptions of nominated reflected type
#define ON_P2PeerMsg_CATCH_CATCH(message,catchFxn) \
   { P2Pmsg_Exception, _T(#catchFxn), 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 3 }, \
   { P2Pmsg_Exception, _T(#catchFxn), 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 2 }, \
	 { message, _T(#catchFxn), 0, false, CN_P2PeerMsg, 0, 0, P2PSig_MsgCatch, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
    P2P_MEMFN_ADDR(catchFxn)), FALSE, 1 },

//
//  Intercepts P2PeerMsg in reflected state
//  NOTES: Use ON_P2PeerMsg map entry to intercept non-reflected
//         P2PeerMsg's of nominated type
#define ON_P2PeerMsg_REFLECT(message, memberFxn) \
	 { message, _T(#memberFxn), 0, P2P_Reflected, CN_P2PeerMsg, 0, 0, P2PSig_MsgReflect, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },

//
//  Catches exception containing P2PeerMsg in reflected state
//  NOTES: Use ON_P2PeerMsg_CATCH map entry to catch non-reflected
//         P2PeerMsg's of nominated type
#define ON_P2PeerMsg_REFLECT_CATCH(message, catchFxn) \
   { P2Pmsg_Exception, _T(#catchFxn), 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 2 }, \
	 { message, _T(#catchFxn), 0, P2P_Reflected, CN_P2PeerMsg, 0, 0, P2PSig_MsgReflectCatch, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(catchFxn)), FALSE, 1 },

//
//  Intercepts P2PeerMsg in acknowledgement state
//  NOTES: Use ON_P2PeerMsg map entry to intercept non-acknowledgement
//         P2PeerMsg's of nominated type
#define ON_P2PeerMsg_ACK(message, memberFxn) \
	 { message, _T(#memberFxn), 0, P2P_Reflected, CN_P2PeerMsg, 0, 0, P2PSig_MsgAck, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },

//
//  Catches exception containing P2PeerMsg in acknowledgement state
//  NOTES: Use ON_P2PeerMsg_CATCH map entry to catch non-acknowledgement
//         P2PeerMsg's of nominated type
#define ON_P2PeerMsg_ACK_CATCH(message, catchFxn) \
   { P2Pmsg_Exception, #catchFxn, 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 2 }, \
	 { message, #catchFxn, 0, P2P_Ack, CN_P2PeerMsg, 0, 0, P2PSig_MsgAckCatch, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(catchFxn)), FALSE, 1 },

//
//  Intercepts timer containing P2PeerMsg
//  NOTES: Intercepts timers containing messages of the nominated
//         type.  Original P2PeerMsg is wrapped within the timer
//       : Use ON_P2PeerMsg_TIMER_CATCH map entry to catch
//         reflected timer P2PeerMsg's of nominated type
#define ON_P2PeerMsg_TIMER(message, memberFxn) \
   { P2PmsgTimer, #memberFxn, 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 2 }, \
	 { message, #memberFxn, 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_MsgTimer, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
    P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },

//
//  Catches exception containing timer P2PeerMsg
//  NOTES: Use ON_P2PeerMsg_CATCH map entry to catch P2PeerMsg's
//         exceptions of all timer types
#define ON_P2PeerMsg_TIMER_CATCH(message,catchFxn) \
   { P2Pmsg_Exception, #catchFxn, 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 3 }, \
   { P2PmsgTimer, #catchFxn, 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_Unwrap, 0, FALSE, 2 }, \
	 { message, #catchFxn, 0, false, CN_P2PeerMsg, 0, 0, P2PSig_MsgTimerCatch, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
    P2P_MEMFN_ADDR(catchFxn)), FALSE, 1 },

//
//  Intercepts P2PeerMsg in notification state
//  NOTES: P2PeerMsg's of nominated type in any other state
//         are ignored
#define ON_P2PeerMsg_NOTIFY(message, memberFxn) \
	 { 0, message, #memberFxn, 0, CN_P2PeerMsg, 0, 0, P2PSig_MsgNotify, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },

//
//  Catches exception containing P2PeerMsg in notification state
//  NOTES: Encapsulated P2PeerMsg's of nominated type in any other
//         state are ignored
#define ON_P2PeerMsg_NOTIFY_CATCH(message, catchFxn) \
	 { 0, message, #catchFxn, 0, CN_P2PeerMsg, 0, 0, P2PSig_MsgNotifyCatch, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(catchFxn)), FALSE, 1 },

//
//  Intercepts P2PeerMsg, unwaps and propogates contents
//  NOTES: Use ON_P2PeerMsg_REFLECT map entry to intercept reflected
//         P2PeerMsg's of nominated type
#define ON_P2PeerMsg_BCAST(message, memberFxn) \
	 { message, #memberFxn, 0, 0, CN_P2PeerMsg, 0, 0, P2PSig_MsgUnwrap, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*,P2PeerMsg**) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },
//
//  Intercepts all P2PeerMsg's
//  NOTES: Use ON_P2PeerMsg map entry to intercept P2PeerMsg's
//         of nominated type
#define ON_P2PeerMsg_PEEK(wildcard,memberFxn) \
	 { wildcard,  #memberFxn, 0, ~0, CN_P2PeerMsg, 0, 0, P2PSig_Msg, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },
//
//  Intercepts P2PeerSYS
//  NOTES: Use ON_P2PeerMsg_REFLECT map entry to intercept reflected
//         P2PeerMsg's of nominated type
#define ON_P2PeerSys(message, memberFxn) \
	 { message, CN_P2PeerSys, 0, 0, P2PSig_Sys, \
		(P2P_PMSG)(P2P_PMSG) \
		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(WPARAM,LPARAM) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },
//
//  Intercepts P2PeerSNK
//  NOTES: Use ON_P2PeerSnk map entry to intercept reflected
//         P2PeerMsg's of nominated type
#define ON_P2PeerSnk(message, memberFxn) \
	 { message, CN_P2PeerSnc, 0, 0, P2PSig_Snc, \
		(P2P_PSNK)(P2P_PSNK) \
		(P2P_MEMFN_CAST<sncRESULT (P2P_MSG_CALL P2PeerTarget::*)(WPARAM,LPARAM) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },
//
//  Intercepts P2PmsgItem's
//  NOTES: Use ON_P2PeerSnk map entry to intercept routed P3PmsgItem's
#define ON_SncP2PmsgItem(message, memberFxn) \
	 { message, CN_P2PeerSnc, 0, 0, P2PSig_SncP2PmsgItem, \
		(P2P_PSNK)(P2P_PSNK) \
		(P2P_MEMFN_CAST<sncRESULT (P2P_MSG_CALL P2PeerTarget::*)(P3PmsgItem*,WPARAM,LPARAM) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },
//
//  Intercepts P2PmsgNodes's
//  NOTES: Use ON_P2PeerSnk map entry to intercept routed P2PmsgNode's
#define ON_SncP2PmsgNode(message, memberFxn) \
	 { message, CN_P2PeerSnc, 0, 0, P2PSig_SncP2PmsgNode, \
		(P2P_PSNK)(P2P_PSNK) \
		(P2P_MEMFN_CAST<sncRESULT (P2P_MSG_CALL P2PeerTarget::*)(P3PmsgNode*,WPARAM,LPARAM) > \
		P2P_MEMFN_ADDR(memberFxn)), FALSE, 1 },

// DELETE-ME no longer required
//#define ON_P2PeerUnd_CATCH(message, memberFxn) \
//	{ 0, MSG_P2PeerUnd, false, message, 0, 0, P2PSig_MsgCatch, \
//		(P2P_PMSG)(P2P_PMSG) \
//		(P2P_MEMFN_CAST<msgRESULT (P2P_MSG_CALL P2PeerTarget::*)(P2PeerMsg*) > \
//		(memberFxn)), 1 },

/////////////////////////////////////////////////////////////////////////////
//  User extensions for P2PeerCon_MAP entries

//  Intercepts P2PeerCon connection object notification
//  NOTES: Use P2Paddr_ALL for interception of all closure
//         notifications
#define ON_P2PeerCon(strP2PaddrWC, memberFxn) \
	 { P2P_Notify, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon startup notifications for servers and clients
//  NOTES: Use ON_P2PeerCON_STARTUP to intercept CLIENT connections.
//        
//       : Use ON_P2PeerSVR_STARTUP to intercept SERVER connections.
//         are managed through ON_P2PeerSVR_STARTUP
#define ON_P2PeerCon_STARTUP(strP2PaddrWC, memberFxn) \
	 { P2P_Startup, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
#define ON_P2PeerSVR_STARTUP(strP2Padom, memberFxn) \
	 { P2P_Startup, CN_P2PeerCon, strP2Padom, CM_SERVER, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon service notifications
//  NOTES: Facilitates P2P_Startup, P2P_Accept and P2P_Close state
//         notifications.
//       : P2PeerCon services passively listen for remote P2PeerHub
//         connections.
#define ON_P2PeerCon_SERVICE(strP2PaddrDomain, P2Pcon_msg, memberFxn) \
	 { P2Pcon_msg, CN_P2PeerCon, strP2PaddrDomain, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon client notifications
//  NOTES: Facilitates P2P_Startup, P2P_Connect and P2P_Close state
//         notifications.
//       : A P2PeerCon client actively seeks out remote a P2PeerHub
//         connections
#define ON_P2PeerCon_CLIENT(strP2PaddrDomain, P2Pcon_msg, memberFxn) \
	 { P2Pcon_msg, CN_P2PeerCon, strP2PaddrDomain, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon connect notification
//  NOTES: Use P2PeerID_ALL for interception of all connection
//         notifications
#define ON_P2PeerCon_CONNECT(strP2PaddrWC, memberFxn) \
	 { P2P_Connect, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon accept notification
//  NOTES: Use P2PeerID_ALL for interception of all accept
//         notifications
#define ON_P2PeerOLD_ACCEPT(strP2PaddrWC, memberFxn) \
	 { P2P_Accept, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
#define ON_P2PeerCon_ACCEPT(strP2PaddrWC, memberFxn) \
	 { P2P_Accept, CN_P2PeerCon, strP2PaddrWC, CM_ACCEPT, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
#define ON_P2PeerSVR_ACCEPT(strServerTag, memberFxn) \
	 { P2P_Accept, CN_P2PeerCon, strServerTag, CM_SERVER, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon reject notification
//  NOTES: Use P2PeerID_ALL for interception of all accept
//         notifications
#define ON_P2PeerCon_REJECT(strP2PaddrWC, memberFxn) \
	 { P2P_Reject, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon login notification
//  NOTES: Received in response to to successful P2P_Login
//         sequence
//       : Use P2PeerID_ALL for interception of all login
//         notifications
#define ON_P2PeerCon_LOGIN(strP2PaddrWC, memberFxn) \
	 { P2P_Login, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_ConLogin, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*,P2PaddrSTR,const void*,P2Psize_t) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon logon notification
//  NOTES: Received in response to to successful P2P_Logon
//         sequence
//       : Use P2PeerID_ALL for interception of all logon
//         notifications
#define ON_P2PeerCon_LOGINACK(strP2PaddrWC, memberFxn) \
	 { P2P_LoginAck, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_ConLoginAck, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*,P2PaddrSTR,P2PaddrSTR,const void*,P2Psize_t) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon connection closed notification
//  NOTES: Use P2PeerID_ALL for interception of all closure
//         notifications
#define ON_P2PeerCon_CLOSE(strP2PaddrWC, memberFxn) \
	 { P2P_Close, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
#define ON_P2PeerSVR_CLOSE(strP2PaddrWC, memberFxn) \
	 { P2P_Close, CN_P2PeerCon, strP2PaddrWC, CM_SERVER, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon shutdown notifications
//  NOTES: Use P2PeerID_ALL for interception of all closure
//         notifications
#define ON_P2PeerCon_SHUTDOWN(strP2PaddrWC, memberFxn) \
	 { P2P_Shutdown, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
#define ON_P2PeerSVR_SHUTDOWN(strP2PaddrWC, memberFxn) \
	 { P2P_Shutdown, CN_P2PeerCon, strP2PaddrWC, CM_SERVER, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon logon notification
//  NOTES: Received in response to to successful P2P_Logon
//         sequence
//       : Use P2PeerID_ALL for interception of all logon
//         notifications
#define ON_P2PeerCon_NOTIFY(strP2PaddrWC, memberFxn) \
	 { P2P_Notify, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon logon notification
//  NOTES: Received in response to to successful P2P_Logon
//         sequence
//       : Use P2PeerID_ALL for interception of all logon
//         notifications
#define ON_P2PeerCon_IDLENOTIFY(strP2PaddrWC, memberFxn) \
	 { P2P_IdleNotify, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerSVR listen notifications
//  NOTES: Received in response to successful P2P_Listen
//         sequence
//       : Use P2PeerID_ALL for interception of all listen
//         notifications
#define ON_P2PeerCon_LISTEN(strP2PaddrWC, memberFxn) \
	 { P2P_Listen, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
#define ON_P2PeerSVR_LISTEN(strP2Padom, memberFxn) \
	 { P2P_Listen, CN_P2PeerCon, strP2Padom, CM_SERVER, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon block listening notification
//  NOTES: Received in response to discontinuation of listening
//         sequence
//       : Only listening type P2PeerCon's are mapped through
//         such handlers
#define ON_P2PeerCon_MUTE(strP2PaddrWC, memberFxn) \
	 { P2P_Mute, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon timer notification
//  NOTES: Received in response to to successful P2P_Timer
//         sequence
//       : Use P2PeerID_MFC for interception of all listen
//         notifications
#define ON_P2PeerCon_TIMER(strP2PaddrWC, memberFxn) \
	 { P2P_PITimer, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
#define ON_P2PeerSVR_TIMER(strP2PaddrWC, memberFxn) \
	 { P2P_PITimer, CN_P2PeerCon, strP2PaddrWC, CM_SERVER, P2PSig_Con, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon PKeyXChange requests
//  NOTES: Received as part of remote PKey exchange request
//       : Use P2PeerID_ALL for interception of all P2P_PKeyXChange requests
#define ON_P2PeerCon_PKEYXCHANGE(strP2PaddrWC, memberFxn) \
	 { P2P_PKeyXChange, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_ConPKeyXchange, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*,const void*,P2Psize_t) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon PKeyXChangeAck response
//  NOTES: Received as part of remote PKey exchange response
//       : Use P2PeerID_ALL for interception of all P2P_PKeyXChange requests
#define ON_P2PeerCon_PKEYXCHANGEACK(strP2PaddrWC, memberFxn) \
	 { P2P_PKeyXChangeAck, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_ConPKeyXchangeAck, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*,const void*,P2Psize_t) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },
//
//  Intercepts P2PeerCon cypher exceptions
//  NOTES: Received in response to failed message decryption for connection
//       : Use P2PeerID_ALL for interception of all logon
//         notifications
#define ON_P2PeerCon_CYPHEREX(strP2PaddrWC, memberFxn) \
	 { P2P_CypherEx, CN_P2PeerCon, strP2PaddrWC, 0, P2PSig_ConCypherEx, \
		(P2P_PCON)(P2P_PCON) \
		(P2P_MEMFN_CAST<BOOL (P2P_CON_CALL P2PeerTarget::*)(P2PeerCon*,P2PeerMsg*) > \
		P2P_MEMFN_ADDR(memberFxn)), 1 },

/////////////////////////////////////////////////////////////////////////////
//  Implementation of command routing

#pragma warning( disable: 4121 )
struct P2P_MSGHANDLERINFO
{
	P2PeerTarget* pTarget;
	void (P2P_MSG_CALL P2PeerTarget::*pmf)(void);
};
#pragma warning( default: 4121 )

#pragma warning( disable: 4121 )
struct P2P_SNKHANDLERINFO
{
	P2PeerTarget* pTarget;
	void (P2P_SNK_CALL P2PeerTarget::*pmf)(void);
};
#pragma warning( default: 4121 )

#pragma warning( disable: 4121 )
struct P2P_SYSHANDLERINFO
{
	P2PeerTarget* pTarget;
	void (P2P_SYS_CALL P2PeerTarget::*pmf)(void);
};
#pragma warning( default: 4121 )

#pragma warning( disable: 4121 )
struct P2P_CONHANDLERINFO
{
	P2PeerTarget* pTarget;
	void (P2P_CON_CALL P2PeerTarget::*pwf)(void);
};
#pragma warning( default: 4121 )

