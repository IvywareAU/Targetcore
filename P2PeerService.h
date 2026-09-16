// Copyright © 2009-2013, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  P2PeerService definitions and prototypes
//  NOTES: Base class from which service implementations of P2PeerHub's
//         can be derived.
//       : Supports both service and console implementation for debugging
//
#pragma once

#include <windows.h>
#include <WinSvc.h>
#include "P2Peer.h"
#include "P2PeerHub.h"

//
//  P2PeerService base class
//  NOTES: Placeholder for bridging between the Windows Service Control
//         Manager and a P2PeerHub.
//
class Targetcore_EXT P2PeerService
{
      void
        RenderThisSafe ( );
    // Constructors and destructor
    // NOTES: Default and copy constructors blocked
    private:
        P2PeerService ( );
        P2PeerService ( const P2PeerService& );
    public:
        P2PeerService ( LPCTSTR lpszServicename
                      , LPSERVICE_MAIN_FUNCTION fptrServiceMain
                      , LPHANDLER_FUNCTION fptrServiceControl );
      virtual
       ~P2PeerService ( );

    // Service implementation
    public:
      virtual bool
        DefaultMainArgs ( LPTSTR argv[], DWORD& argn, bool bImplement = true );
      virtual bool
        HelpMainArgs    ( LPTSTR argv[], DWORD& argn, bool bImplement = true );
      virtual bool
        DefaultDebugArgs( LPTSTR argv[], DWORD& argn, bool bImplement = true );
        
      virtual DWORD
        Init ( DWORD argc, LPTSTR *argv );
      virtual int
        Run ( );
      virtual int
        RunConsoleModeAttachment ( );

    // Standard Win32 Service control operations
    public:
      virtual DWORD
        OnPause ( );
      virtual DWORD
        OnContinue ( );
      virtual void
        OnStop ( );
      virtual void
        OnShutdown ( );
      virtual void
        OnInterrogate ( );
      virtual void
        OnUserControl ( DWORD dwUserCmd );

    // Configuration and operational control
    public:
      virtual DWORD
        Startup ( );
      virtual DWORD
        StartDispatcher ( const SERVICE_TABLE_ENTRY *pServiceTable );
      virtual int
        Service( DWORD argc, LPTSTR* argv );    
      virtual void
        ServiceCtrlHandler ( DWORD opcode );

      virtual BOOL
        Install ( );
      virtual void
        PostInstall ( );
      virtual BOOL
        UnInstall ( );
      virtual void
        PostUnInstall (  );

    // Service configuration
    public:
      void
        SetUserArgsFptr ( );
      void
        SetServiceCtrlHandler ( LPHANDLER_FUNCTION pServiceCtrlHandler );
      LPCTSTR
        SetServiceName ( LPCTSTR lpszServiceName );
      LPCTSTR
        GetServiceName ( );
      LPCTSTR
        SetDisplayName ( LPCTSTR lpszDisplayName );
      LPCTSTR
        GetDisplayName ( );
      LPCTSTR
        SetServiceDesc ( LPCTSTR lpszServiceDesc );
      LPCTSTR
        GetServiceDesc ( );
      virtual void
        SetAcceptedControls ( DWORD dwControls );
      virtual void
        ChangeStatus ( DWORD dwServiceState 
                     , DWORD dwCheckpoint = 0 
                     , DWORD dwWaitHint = 0 );
        
    // P2PeerHub integration (single)
    public:
      P2PeerHub*
        PostP2PeerHub ( P2PeerHub *pHub );
      P2PeerHub*
        GetP2PeerHub ( );

    // Trouble shooting and serialisation
    public:

    // Properties
    public:
      virtual bool
        IsInstalled ( LPCTSTR lpszServiceName );
      bool
        IsServiceMode ( );
      bool
        IsConsoleMode ( );
      bool
        IsDebugMode ( );
      bool
        IsExitMode ( );
      virtual DWORD
        SetExitMode ( DWORD dwExitCode );
      virtual
        DWORD GetExitCode ( );   

    // Attributes
    private:
      P2PeerHub              *m_pP2PeerHub;
      CString                 m_strServiceName;
      CString                 m_strDisplayName;
      CString                 m_strServiceDesc;
      bool                    m_bStarted;
      bool                    m_bPaused;
      bool                    m_bConsole;
      bool                    m_bService;
      bool                    m_bSystem;
      bool                    m_bDebug;
      bool                    m_bExitMode;
    protected:
      UINT                    m_nMaxHubs;
      UINT                    m_nMaxPumps;
      CStringADDR             m_strP2PaddrHub;
      TCHAR                   m_szServiceName[36];

      LPSERVICE_MAIN_FUNCTION m_fptrServiceMain;
      LPHANDLER_FUNCTION      m_fptrServiceCtrlHandler;

      SERVICE_TABLE_ENTRY     m_oDispatchTable[2];
      SERVICE_STATUS          m_oServiceStatus;
      SERVICE_STATUS_HANDLE   m_hServiceStatus;
};

///////////////////////////////////////////////////////////////////////
//  Safe SC_HANDLE container
//  NOTES: Service control handle is managed within the life cycle
//         of this object.
//
class SafeSCHandle
{
    public:
        SafeSCHandle ( );
        SafeSCHandle ( SC_HANDLE hSC );
       ~SafeSCHandle ( );

      SafeSCHandle&
        operator = ( SC_HANDLE hSC );
        operator SC_HANDLE ( );
 
      SC_HANDLE
        Dereference();

    private:
        SC_HANDLE m_hSC;
};

