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
//  Description: P2PeerMsgQue implementation
//               NOTES: Optimised for queues of P2PeerMsg's
//

#include "stdafx.h"

#include "Kernel32_Ext.h"
#include "P2PeerMsgQue.h"

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor

//
//  Constructor and destructor
//
//
//  Parameters:  HANDLE  hNotnEvent
//               Event issued whenever P2PeerMsg is appended to
//               queue.
//
P2PeerMsgQue::P2PeerMsgQue ( HANDLE hNotnEvent )
{
    // Firstly
    RenderQueSafe();

    // Persist
    m_hNotnEvent = hNotnEvent;
}

P2PeerMsgQue::~P2PeerMsgQue ( )
{
    // Garbage collection
    Flush();
    DeleteCriticalSection ( &m_oCSectionQue );
}

void
P2PeerMsgQue::RenderQueSafe ( )
{
    // Attributes
    m_hNotnEvent  = 0;
    m_hThreadPump = 0;

    // Resources
    InitializeCriticalSection ( &m_oCSectionQue );
}

///////////////////////////////////////////////////////////////////////
//  Operations

//
//  Appends passed P2PeerMsg to P2PeerMsgQue
//  NOTES: Client should use the referenced version if control over
//         message life cycle is to be retained.
//       : Queue assumes control over life cycle of passed P2PeerMsg
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be appended
//
//  Returns:     P2PeerMsg*
//                 0.. Message appended to queue
//
P2PeerMsg*
P2PeerMsgQue::Append ( P2PeerMsg *pMsg )
{
    // Isolation
    P2PsafeCS oSafeCS = m_oCSectionQue;

    // Observe priority
ASSERT(::AfxIsValidAddress(pMsg,sizeof(P2PeerMsg)));
//ASSERT(pMsg->Type());//DELETE-ME
    if ( m_oCListP2PeerMsg.GetCount() > 1 )
    {
      POSITION pos = m_oCListP2PeerMsg.GetTailPosition();

      while ( pos )
      {
        if ( m_oCListP2PeerMsg.GetAt(pos)->Priority()
                                  > pMsg->Priority() )
        {
          m_oCListP2PeerMsg.GetPrev (pos);
          continue;
        }
        m_oCListP2PeerMsg.InsertAfter ( pos, pMsg );
        pMsg = 0;
        break;
      };

      if ( pMsg )
        m_oCListP2PeerMsg.AddHead ( pMsg );
      pMsg = 0;
    }
    else
      m_oCListP2PeerMsg.AddTail ( pMsg );

    // Perform notification
    if ( m_hNotnEvent )
      SetEvent ( m_hNotnEvent );

    // Finally
    return (P2PeerMsg *)0;
}

//
//  Description: Pre-pends passed P2PeerMsg to queue.
//               NOTES: Client should use the referenced version
//                      if control over message life cycle is to
//                      be retained.
//
//
//  Parameters:  P2PeerMsg *pMsg
//               Message to be pre-appended
//               NOTES: Queue assumes control over object life
//                      cycle
//
//  Returns:     P2PeerMsg*
//               Message queued flag
//
P2PeerMsg*
P2PeerMsgQue::Preppend ( P2PeerMsg *pMsg )
{
    // Isolation
    P2PsafeCS oSafeCS = m_oCSectionQue;

    // Add to head by default
    if ( pMsg )
      m_oCListP2PeerMsg.AddHead ( pMsg );

    // Perform notification
    if ( m_hNotnEvent )
      SetEvent ( m_hNotnEvent );

    // Finally
    return (P2PeerMsg *)0;
}

//
//  Description: Appends passed P2PeerMsg to queue.
//               NOTES: Client should use the pointer version
//                      of control over message if life cycle is
//                      to be conceeded.
//
//
//  Parameters:  P2PeerMsg& rMsg
//               Message to be appended
//               NOTES: Queue makes a copy
//
//
//  Returns:     int
//               Queued message count
//
INT_PTR
P2PeerMsgQue::Append ( P2PeerMsg& oMsg )
{
    // Delegation with copy
    Append ( new P2PeerMsg(oMsg) );
    return GetCount();
}

//
//  Description: Removes next highest priority message from
//               queue.
//               NOTES: Client assumes responsibility for life
//                      cycle of retrieved P2PeerMsg
//
//
//  Returns:     P2PeerMsg*
//               Retrieved message
//                 0.. No entries on the queue
//               
P2PeerMsg*
P2PeerMsgQue::Remove ( )
{
    // Isolation
    P2PsafeCS oSafeCS = m_oCSectionQue;

    // To be sure, to be sure
    if ( m_oCListP2PeerMsg.GetCount() <= 0 )
      return 0;

    // Then simply
    return m_oCListP2PeerMsg.RemoveHead ();
}

///////////////////////////////////////////////////////////////////////
//  Utilities

//
//  Description: Flushes queue contents
//
void
P2PeerMsgQue::Flush ( )
{
    // Isolation
    P2PsafeCS oSafeCS = m_oCSectionQue;

    // Simply delete all entries
    while ( m_oCListP2PeerMsg.GetCount() > 0 )
      delete m_oCListP2PeerMsg.RemoveHead();
}

///////////////////////////////////////////////////////////////////////
//  Property management

//
//  Queued entries count
//
//  Returns:     int
//               Number of queued entries
INT_PTR
P2PeerMsgQue::GetCount ( )
{
    // Delegate
    return m_oCListP2PeerMsg.GetCount();
}

//
//  Summarizes queued entries status
//
//  Returns:     bool
//               Queued entries summary
//                 true... Entries exist
//                 false.. Empty
bool
P2PeerMsgQue::IsEmpty  ( )
{
    // Delegate
    return m_oCListP2PeerMsg.IsEmpty() ? true : false;
}

//
//  Description: Exposes P2PeerMsgQue notification event
//               NOTES: This event is raised every time an entry
//                      is added to the queue
//
//
//  Returns:     HANDLE
//               Allocated P2PeerMsgQue event
//
HANDLE
P2PeerMsgQue::GetEvent ( )
{
    // Simply
    return m_hNotnEvent;
}
