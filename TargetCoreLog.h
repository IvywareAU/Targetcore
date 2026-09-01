// Copyright © 2000-2011, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  MsgexceptionLog declarations
//
#pragma once
#include "Msgexception.h"


//
//  MsgexceptionLog implementation
//  NOTES: Logs Msgexceptions
//
class TargetCore_EXT MsgexceptionLog : public P3PmsgItem
{
    // Constructors and destructor
    public:
        MsgexceptionLog ( LPCWSTR lpszLognamePrefix );
      virtual
       ~MsgexceptionLog ( );
      BOOL
        Startup ( );
      void
        Shutdown ( );
      static void WINAPI
        MsgexceptionCB ( P2PeventSinkID  nSinkID    // Sink identification code
                       , DWORD_PTR      dwCBKey     // User definied callback key
                       , const P2Pevent& oEvent );  // Notification event
      void
        LogFileP2PeventCB ( P2Pevent *pP2Pevent );

    // Utilities
    protected:
      BOOL
        LogfileOpen ( COleDateTime &dtCurrentTime );
      BOOL
        LogfileClose ( ) noexcept;
      int
        LogfileWrite ( int nSubrecord, CString& strMessage );
      BOOL
        LogfileRollover ( COleDateTime& dtCurrentTime );
     public: 
      void
        LogfileP2PeventCB ( P2Pevent *pP2Pevent );

    // Overloaded operators
    public:

    // Associated P2Pevent function parameters
    // NOTES: Variable parameter set associated with P2Pevent
    public:

    // Configuration
    // NOTES: Logging defaults and settings
    public:
      LPCWSTR
        SetFirstentryPrefix ( LPCWSTR lpszFormat, ... );
      int
        Breakpoint ( LPCWSTR lpBreakpointMsg );

    // Properties
    public:

    // Attributes
    private:
      char              m_caMessageBuffer[8096];
      int               m_nBufferSize{0};
      P2PeventSinkID    m_nCBSinkID{0};
      CString           m_strLocalAppDataFolder;
      CString           m_strDestinPath;
      CString           m_strLogfilePrefix;
      CString           m_strFirstentryPrefix;
      CString           m_strRollover;
      int               m_fdExceptionLog{-1};
      int               m_nLogentries{0};
      COleDateTime      m_dtStartup;
};
