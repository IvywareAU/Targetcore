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
//  P2PeerService definitions and prototypes
//  NOTES: Windows service container for the deployment of P2PeerHub's
//         P2PeerMsg's between objects derived from this base class
//       : Only P2PeerHub derived network objects may be assigned
//         network P2Paddress's

#include "stdafx.h"

#include <windows.h>
#include "P2Pwin32.h"
#include "P2PeerService.h"
#include "Msgexception.h"
#if defined(_WIN32)
#include "TargetcoreEvt.h"             // generated from TargetcoreEvt.mc, committed.
                                       // Guarded so the Linux build needs no
                                       // mc.exe output: everything it declares
                                       // is used only from Windows-only code.
#endif

using namespace std;

//
//  ServiceStart() definitions
/*VOID WINAPI
P2PeerService_ServiceStart1 ( DWORD argc, LPTSTR *argv )
{
    // Firstly globals
    CexGlobalsInit ( );

    // Delegate
    MscsServiceStart ( argc, argv );
}*/
//extern
//P2PeerService *g_pP2PeerService1;
//VOID WINAPI
//P2PeerService_ServiceStart2 ( DWORD argc, LPTSTR *argv );
//extern
//P2PeerService *g_pP2PeerService2;
//VOID WINAPI
//P2PeerService_ServiceStart3 ( DWORD argc, LPTSTR *argv );
//extern
//P2PeerService *g_pP2PeerService3;

//
//  Win32 Service Control handler
//  NOTES: Default implementation template 
//
//  Parameters: DWORD dwCtrlCode
//              Control code as passed to the registered handler
//              Refer RegisterServiceCtrlHandler() for further
//              details
P2PeerService *g_pP2PeerService = 0;
VOID WINAPI
Win32ServiceServiceMain ( DWORD argc, LPTSTR *argv )
{
    // Delegate to global P2PeerService instance
    g_pP2PeerService -> Service ( argc, argv );
}
VOID WINAPI
Win32ServiceControlHandler ( DWORD dwCtrlCode )
{
    // Delegate to global P2PeerService instance
    g_pP2PeerService -> ServiceCtrlHandler ( dwCtrlCode );
}

///////////////////////////////////////////////////////////////////////////////
//  Contructors and destructor
P2PeerService::P2PeerService ( LPCTSTR lpszServiceName 
                             , LPSERVICE_MAIN_FUNCTION fptrServiceMain 
                             , LPHANDLER_FUNCTION fptrServiceCtrlHandler )
{
    // Firstly
    RenderThisSafe ( );
    m_fptrServiceMain        = fptrServiceMain;
    m_fptrServiceCtrlHandler = fptrServiceCtrlHandler;
   _tcscpy_s ( m_szServiceName, ARRAYSIZE(m_szServiceName), lpszServiceName );

    // Customised function pointers
    //m_pServiceRun = 0;
}

P2PeerService::~P2PeerService( void )
{
    // Garbage collection
    // NOTES: CloseHub() first, and the delete second. Run() already closes the
    //        hub on the way out, so on the ordinary path this finds nothing to
    //        do - but a service destroyed without Run() having returned (a
    //        SpawnHub from SERVICE_CONTROL_CONTINUE, a constructor that throws
    //        after the spawn) would otherwise delete a hub whose pump thread
    //        is still dispatching virtuals through it. ~P2PeerHub cannot close
    //        that window from where it sits; the owner has to, and here the
    //        owner is us. Refer the note on ~P2PeerHub.
    if ( m_pP2PeerHub )
    {
      m_pP2PeerHub -> CloseHub ( );
      delete m_pP2PeerHub;
    }
}

void
P2PeerService::RenderThisSafe ( )
{
    m_pP2PeerHub     =  0;
    m_nMaxHubs       = 16;             // Within service address space
    m_nMaxPumps      =  8;             // Default hub pump count; subclasses override
    m_bDebug         = false;          // Was left uninitialised: IsDebugMode() and the
                                       // hub-less service Run() path both read it
    memset(  m_szServiceName, 0, ARRAYSIZE(m_szServiceName) );
    memset( &m_oServiceStatus, 0, sizeof(m_oServiceStatus) );
    memset( &m_oDispatchTable[0], 0, sizeof(m_oDispatchTable) );
    m_hServiceStatus =  0;

    // Interbal status and mode flags
    m_bStarted  = false;
    m_bPaused   = false;
    m_bConsole  = false;
    m_bSystem   = false;
    m_bService  = false;
    m_bExitMode = false;

    // Default service control status
    m_oServiceStatus.dwServiceType      = SERVICE_WIN32; 
    m_oServiceStatus.dwCurrentState     = SERVICE_START_PENDING; 
    m_oServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP 
                                        | SERVICE_ACCEPT_PAUSE_CONTINUE
                                        | SERVICE_ACCEPT_SHUTDOWN; 
}

//
//  Connects the main thread of a service process to the service
//  control manager, which causes the thread to be the service control
//  dispatcher thread for the calling process. 
//  NOTES: Delegates to StartServiceCtrlDispatcher()
//
//
//  Parameters: const SERVICE_TABLE_ENTRY *pServiceTable
//              Refer StartServiceCtrlDispatcher() for further details
//
DWORD
P2PeerService::StartDispatcher ( const SERVICE_TABLE_ENTRY *pServiceTable )
{
    // Direct delegation
    ASSERT ( IsServiceMode() );
    BOOL bResult = StartServiceCtrlDispatcher ( pServiceTable );
    if ( !bResult )
      EVERR->MODULE
           ->Message("StartServiceCtrlDispatcher() failed" )
           ->HResult( GetLastError() )
           ->SetLast( );
    return bResult;
}

DWORD P2PeerService::Startup( void )
{
    //== initialize the dispatch table
    m_oDispatchTable[0].lpServiceName = m_szServiceName; 
    m_oDispatchTable[0].lpServiceProc = m_fptrServiceMain;

    //== starts the service
    if( !StartServiceCtrlDispatcher( m_oDispatchTable ) )
    {
      DWORD dwError = GetLastError();
      EVERR->MODULE
           ->Message("StartServiceCtrlDispatcher() failed" )
           ->HResult( dwError )
           ->SetLast( );
      return dwError;
    }

    return NO_ERROR;
}

int P2PeerService::Service ( DWORD argc, LPTSTR* argv )
{
    m_hServiceStatus
      = RegisterServiceCtrlHandler ( m_szServiceName
                                   , m_fptrServiceCtrlHandler );
    if( (SERVICE_STATUS_HANDLE)0 == m_hServiceStatus )
    {
        DWORD dwError = GetLastError();
        EVERR->MODULE
             ->Message("RegisterServiceCtrlHandler() failed" )
             ->HResult( dwError )
             ->SetLast( );
        return dwError;
    }
    
    if( Init( argc, argv ) != NO_ERROR )
    {
        ChangeStatus( SERVICE_STOPPED );
        return GetLastError();
    }
    
    ChangeStatus( SERVICE_RUNNING );
    return Run ( );
}

//
//  Service control handler
//  NOTES: Default handler for all P2PeerService derived objects
//
//
//  Parameters:  DWORD dwOpcode
//               Operations code passed from the service control
//               manager.
//
void
P2PeerService::ServiceCtrlHandler ( DWORD dwOpcode )
{
    switch ( dwOpcode )
    {
      case SERVICE_CONTROL_PAUSE:
        ChangeStatus( SERVICE_PAUSE_PENDING );
        if ( OnPause() == NO_ERROR )
        {
          m_bPaused = true;
          ChangeStatus( SERVICE_PAUSED );
        }
        break;

      case SERVICE_CONTROL_CONTINUE:
        ChangeStatus( SERVICE_CONTINUE_PENDING );
        if ( OnContinue() == NO_ERROR )
        {
          m_bPaused = false;
          ChangeStatus( SERVICE_RUNNING );
        }
        break;

      case SERVICE_CONTROL_STOP:
        ChangeStatus( SERVICE_STOP_PENDING );
        OnStop();
        ChangeStatus( SERVICE_STOPPED );
        break;

      case SERVICE_CONTROL_SHUTDOWN:
        ChangeStatus( SERVICE_STOP_PENDING );
        OnShutdown();
        ChangeStatus( SERVICE_STOPPED );
        break;

      case SERVICE_CONTROL_INTERROGATE:
        OnInterrogate();
        SetServiceStatus( m_hServiceStatus, &m_oServiceStatus );
        break;

      default:
        OnUserControl( dwOpcode );
        SetServiceStatus( m_hServiceStatus, &m_oServiceStatus );
        break;
    };
}

//
//  Checks for and processes default service arguments
//  NOTES: This default argument set defines the default P2PeerService
//         environment
//
//  Parameters: LPTSTR *argv
//              Argument to be processed
//
//              bool bImplement
//                true... Implement decoded option
//                false.. Validation and object synchronisation
bool
P2PeerService::DefaultMainArgs ( LPTSTR argv[], DWORD& argn, bool bImplement )
{
    // Locals
    bool bResult = false;
    int    a = argn, b = argn;
    size_t iSize   = _tcslen ( argv[a] );

    // Because users are involved
    try
    {
      // Debug mode
      if ( _tcsnicmp ( argv[a], _T("-Debug"), max(2,iSize) ) == 0 ||
           _tcsnicmp ( argv[a], _T("/Debug"), max(2,iSize) ) == 0    )
      {
        m_bDebug = true;
        if ( bImplement )
          P2Pevent::Configure ( P2Pevent::ADDMASK
                              , P2Pevotn_ERROR | P2Pevotn_DEBUG );
        bResult = true;
      }

      // Console mode
      // NOTES: Flags execution from Visual Studio or from a DOS Window,
      //        negates StartServiceCtrlDispatcher() call
      //      : Implementation -C[onsole] or /C[onsole]
      else if ( _tcsnicmp ( argv[a], _T("-Console"), max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/Console"), max(2,iSize) ) == 0    )
      {
        m_bConsole = true;
        bResult    = true;
      }

      // Service mode
      // NOTES: Flags execution as a formal service for which a
      //        StartServiceCtrlDispatcher() call is ultimately performed
      //      : Implementation -S[ervice] or /S[ervice]
      else if ( _tcsnicmp ( argv[a], _T("-Service"), max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/Service"), max(2,iSize) ) == 0    )
      {
        m_bService = true;
        bResult    = true;
      }

      // Register as service
      // NOTES: Activates system mode and negates operation as a service
      else if ( _tcsnicmp ( argv[a], _T("-Install"),   max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/Install"),   max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/REGSERVER"), max(4,iSize) ) == 0    )
      {
        if ( bImplement )
          Install ( );
        m_bSystem = true;
        bResult   = true;
      }

      // Unregister as service
      // NOTES: /REGSERVER is a special case in which the
      //        service is automatically removed
      //      : Activates system mode and negates operation as a service
      else if ( _tcsnicmp ( argv[a], _T("-Remove"),      max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/Remove"),      max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/UNREGSERVER"), max(2,iSize) ) == 0    )
      {
        if ( bImplement )
          UnInstall ( );
        m_bSystem = true;
        bResult   = true;
      }

      // Exit mode
      // NOTES: Used for setting registry parameters and negates operation
      //        as either a console application or service
      else if ( _tcsnicmp ( argv[a], _T("-Xit"),  max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/Xit"),  max(2,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("-eXit"), max(3,iSize) ) == 0 ||
                _tcsnicmp ( argv[a], _T("/eXit"), max(3,iSize) ) == 0    )
      {
        m_bExitMode = true;
        bResult     = true;
      }
    }

    // Exceptions
    catch ( P2Pevent *pEVT )
    {
      pEVT -> SetLast();
    }
    catch ( ... )
    {
      EVERR->Module ( __FUNCTION__ )
           ->Message("Unknown exception")
           ->SetLast();
    }

    // Tidy up and
    if ( bResult )
      argn = b;                        // Comsumed arguments
    return bResult;                    // Consumed arguments
}

//
//  Checks for and processes -Help service arguments
//  NOTES: The contained argument set defines the default P2PeerService
//         -Help environment
//
//  Parameters: LPTSTR argv[]
//              Argument to be processed
//
//              DWORD& argn
//              Primary argument to be checked
//
//              bool bImplement
//                true... Implement decoded option
//                false.. Validation and object synchronisation
bool
P2PeerService::HelpMainArgs ( LPTSTR argv[], DWORD& argn, bool bImplement )
{
    // Locals
    bool bResult = false;
    int     a = argn, b = argn;
    size_t  iSize   = _tcslen ( argv[a] );

    // Because users are involved
    try
    {
      // Help
      // NOTES: Simple TTY expression of default set of execution arguments
      if ( _tcsnicmp ( argv[a], _T("-Help"), max(2,iSize) ) == 0 ||
           _tcsnicmp ( argv[a], _T("/Help"), max(2,iSize) ) == 0 ||
           _tcsnicmp ( argv[a], _T("-?"), 2 )               == 0 ||
           _tcsnicmp ( argv[a], _T("/?"), 2 )               == 0    )
      {
        m_bConsole = true;
        if ( bImplement )
        {
          _tprintf ( _T("\n") );
          _tprintf ( _T("  -C[onsole]\n") );
          _tprintf ( _T("   Run from a DOS window or Visual Studio\n") );
          _tprintf ( _T("  -S[ervice]\n") );
          _tprintf ( _T("   Run as a Windows service\n") );
          _tprintf ( _T("  -I[nstall]\n") );
          _tprintf ( _T("   Windows service installation (also REGSERVER)\n") );
          _tprintf ( _T("  -R[emove]\n") );
          _tprintf ( _T("   Windows service removal (also UNREGISTER)\n") );
          _tprintf ( _T("  -[e]X[it]\n") );
          _tprintf ( _T("  -Exit application immediately after processing command arguments\n") );
        }
        bResult = true;
      }
    }

    // Exceptions
    catch ( ... )
    {
      EVERR->Module ( __FUNCTION__ )
           ->AFP(*argv)->AFP(argn)->AFP(bImplement)
           ->Message(_T("Unknown exception"))
           ->SetLast();
    }

    // Tidy up and
    if ( bResult )
      argn = b;                        // Comsumed arguments
    return bResult;                    // Consumed arguments
}

//
//  Checks for and processes default service arguments
//  NOTES: This default argument set defines the default P2PeerService
//         environment
//
//  Parameters: LPTSTR argv
//              Argument to be processed
//
//              DWORD argn
//              Processed argument list position
//
//              bool bImplement
//                true... Implement decoded option
//                false.. Validation and object synchronisation
//
//  Returns:    bool
//              Processing summary
//                true... Argument identified and processed 
//                        GetP2Pevent() summarises processing result
//                false.. Argument NOT identified
bool
P2PeerService::DefaultDebugArgs ( LPTSTR argv[], DWORD& argn, bool bImplement )
{
    // Locals
    bool   bResult = false;
    int    a = argn, b = argn;
    size_t iSize   = _tcslen ( argv[a] );

    // Debug mode
    if ( wmemicmp ( argv[a], L"-Debug", max(2,iSize) ) == 0 ||
         wmemicmp ( argv[a], L"/Debug", max(2,iSize) ) == 0    )
    {
      m_bDebug = true;
      if ( bImplement )
        P2Pevent::Configure ( P2Pevent::ADDMASK
                            , P2Pevotn_ERROR | P2Pevotn_DEBUG );
      bResult = true;
    }

    // Tidy up, and
    if ( bResult )
      argn = b + 1;
    return bResult;
}

///////////////////////////////////////////////////////////////////////
//  Diagnostic destination for a hosted hub
//  NOTES: A service under the SCM has no console, no standard error and no
//         viewable desktop.  Before this, a P2Pevent in that shape became a
//         modal MessageBox on whichever thread raised it - the hub's own PUMP
//         for anything reached through P2PeerCon::OnClose - and CloseHub()
//         then waited on that pump without a bound, deliberately, because
//         bounding it would trade a hang for a use-after-free.  A service
//         could therefore deadlock its own teardown on any diagnostic.
//       : Msgcore now refuses the dialog by itself wherever nobody could
//         dismiss one (refer P2PeventDialogViewable in Msgexception.cpp), so
//         the hang is closed without configuration.  Refusing it is only half
//         the problem: the text then goes to a standard error that is not
//         there, and a defect that used to hang loudly would vanish quietly.
//         This is the other half - the destination.
//       : WINDOWS ONLY, and not an oversight.  This translation unit is common
//         to both platforms - the SCM is shimmed to no-op on Linux - but the
//         event log is not a portable concept, and the Platform shim carries
//         neither RegisterEventSource nor a registry.  Neither is there a
//         defect to answer off Windows: MessageBoxEx is a stub there, text is
//         unconditional, and a daemon keeps a writable stderr.  Routing to
//         syslog or the journal is its own decision, not this one's.
//
#if defined(_WIN32)

static HANDLE          s_hP2PeventLog   = 0;
static P2PeventTextFnc s_pfnP2PeventWas = nullptr;

//
//  Writes one event to the Windows application log
//  NOTES: Installed as the P2Pevent text sink for the duration of a service
//         mode Run().  Refer P2PeventTextFnc for the thread contract: this is
//         called on the thread that RAISED the event, so it must not block.
//       : IT MUST NOT RAISE A P2Pevent, ever, however it fails.  Display()
//         reaches this function, so an event raised from here would re-enter
//         Display() and recurse until the stack is gone.  Every failure below
//         is therefore silent by construction, not by oversight.
//
//  Parameters:  P2Pevent_e eClass
//               Class of the event being reported.
//
//               LPCWSTR lpszOrigin
//               "[service]module(parameters)" - insertion %1.
//
//               LPCWSTR lpszText
//               Assembled message body - insertion %2.
//
static void WINAPI
P2PeerServiceEventLogSink ( P2Pevent_e eClass
                          , LPCWSTR    lpszOrigin
                          , LPCWSTR    lpszText )
{
    // Read the handle ONCE.  The teardown in Run() unhooks this sink before it
    // deregisters the source, but a thread already inside here holds whatever
    // it read on entry rather than racing the store.
    HANDLE hLog = s_hP2PeventLog;
    if ( !hLog )
      return;

    // Class to catalogue entry.  The catalogue's message ids ARE the
    // P2Pevent_e values - P2Pevent_ERROR is 1 and P2PMSG_EVT_ERROR is 0x...0001
    // - which is why this is written out rather than computed: an enum that
    // gains a class gets a compiler-visible gap here instead of silently
    // reporting under a neighbour's id.  Anything unlisted, including
    // P2Pevent_UNDEF and the P2Pevent_USERn range, still renders its text
    // under P2PMSG_EVT_UNCLASSED.
    DWORD dwEventID = P2PMSG_EVT_UNCLASSED;
    WORD  wType     = EVENTLOG_WARNING_TYPE;
    switch ( eClass )
    {
      case P2Pevent_ERROR:
        dwEventID = P2PMSG_EVT_ERROR;   wType = EVENTLOG_ERROR_TYPE;       break;
      case P2Pevent_WARNING:
        dwEventID = P2PMSG_EVT_WARNING; wType = EVENTLOG_WARNING_TYPE;     break;
      case P2Pevent_INFO:
        dwEventID = P2PMSG_EVT_INFO;    wType = EVENTLOG_INFORMATION_TYPE; break;
      case P2Pevent_DEBUG:
        dwEventID = P2PMSG_EVT_DEBUG;   wType = EVENTLOG_INFORMATION_TYPE; break;
      case P2Pevent_TRACE:
        dwEventID = P2PMSG_EVT_TRACE;   wType = EVENTLOG_INFORMATION_TYPE; break;
      case P2Pevent_LOG:
        dwEventID = P2PMSG_EVT_LOG;     wType = EVENTLOG_INFORMATION_TYPE; break;
      case P2Pevent_REPORT:
        dwEventID = P2PMSG_EVT_REPORT;  wType = EVENTLOG_INFORMATION_TYPE; break;
      default:
        break;
    }

    // Both insertions are always supplied, empty rather than absent, because
    // the catalogue references %1 and %2 unconditionally and a missing
    // insertion renders as the literal placeholder.
    LPCWSTR apszInsert[2] = { lpszOrigin ? lpszOrigin : L""
                            , lpszText   ? lpszText   : L"" };
    ::ReportEventW ( hLog, wType, 0, dwEventID, 0, 2, 0, apszInsert, 0 );
}

//
//  Names the module that carries the event message table
//  NOTES: NOT the host executable.  GetModuleFileName(0) would name the .exe,
//         which carries no message table, and the Event Viewer would then
//         report every entry as unformattable.  The table is linked into THIS
//         module (Targetcore, from TargetcoreEvt.mc), so the module is found
//         from the address of code that lives in it.
//
//  Parameters:  CStringW& strModule
//               Receives the full path on success, untouched on failure.
//
//  Returns:     bool
//               true ... path resolved
static bool
P2PeerServiceEventModule ( CStringW& strModule )
{
    HMODULE hThis = 0;
    if ( !::GetModuleHandleExW ( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
                              , (LPCWSTR)&P2PeerServiceEventLogSink
                              , &hThis ) )
      return false;

    WCHAR szModule[MAX_PATH] = { 0 };
    DWORD dwLength = ::GetModuleFileNameW ( hThis, szModule, ARRAYSIZE(szModule) );
    if ( dwLength == 0 || dwLength >= ARRAYSIZE(szModule) )
      return false;                    // failed, or truncated - do not register a partial path

    strModule = szModule;
    return true;
}

#endif  // _WIN32 - event log destination

//
//  Service installation
//  NOTES: Skips operation if service already installed
//       : Usually activated by one of following execution arguments
//           -I[nstall]
//           /I[nstall]
//           /REG[SERVER]
//       : Refer complimentary UnInstall() for removal of installed
//         services
//
//  Returns:    BOOL
//              Operation summary
//                TRUE... Successful
//                FALSE.. Failed, refer GetP2Pevent() for details
BOOL
P2PeerService::Install (  )
{
    // Check existing state
    if ( IsInstalled ( m_szServiceName ) )
        return TRUE;

    // Open the Service Control Manager
    SafeSCHandle shSCMgr
      = OpenSCManager ( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if ( shSCMgr == NULL )
    {
      EVERR->MODULE
           ->Message("OpenSCManager() failed" )
           ->HResult( GetLastError() )
           ->SetLast( );
      return FALSE;
    }

    // Fetch full path of this executable
    TCHAR szFilePath[_MAX_PATH];
    ::GetModuleFileName ( NULL, szFilePath, ARRAYSIZE(szFilePath) );

    // Win32 implementation
    SafeSCHandle shSrv
      = CreateService ( shSCMgr
                      , m_szServiceName
                      , m_szServiceName
                      , SERVICE_ALL_ACCESS
                      , SERVICE_WIN32_OWN_PROCESS
                      , SERVICE_DEMAND_START
                      , SERVICE_ERROR_NORMAL
                      , szFilePath
                      , NULL
                      , NULL
                      , NULL
                      , NULL
                      , NULL );
    if ( shSrv == NULL )
    {
      EVERR->MODULE
           ->Message(L"CreateService(%s) failed", m_szServiceName )
           ->HResult( GetLastError() )
           ->SetLast( );
      return FALSE;
    }
    
    // Tidy up, and
    // NOTES: Observe post Install() management of registry entries etc
    PostInstall ( );
    shSrv   = 0;
    shSCMgr = 0;
    return TRUE;
}

//
//  Registers this service as an event log source
//  NOTES: Reached from Install(), which the SCM already requires to be
//         elevated - so this is the one point in the life cycle where HKLM is
//         writable and the registration can be made.
//       : Without it ReportEvent still succeeds and the text is still present,
//         but the Event Viewer has no message table to format it with and
//         shows "The description for Event ID (1) ... cannot be found" with
//         the text demoted to raw insertion data.  So a failure here degrades
//         the presentation and loses nothing.
//       : EventMessageFile names THIS module rather than the host .exe; refer
//         P2PeerServiceEventModule().
//
void
P2PeerService::PostInstall ( )
{
#if !defined(_WIN32)
    return;                            // no event log to register against
#else
    CStringW strModule;
    if ( !P2PeerServiceEventModule ( strModule ) )
    {
      EVERR->MODULE
           ->Message("Could not resolve the module carrying the event message table" )
           ->Advice_(_T("Service diagnostics will be written to the application log "
                        "but the Event Viewer will not be able to format them.") )
           ->Cancel();
      return;
    }

    CStringW strKey;
    strKey.Format ( L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s"
                  , (LPCWSTR)CStringW(m_szServiceName) );

    HKEY hKey = 0;
    LONG lResult = ::RegCreateKeyExW ( HKEY_LOCAL_MACHINE, strKey, 0, 0
                                     , REG_OPTION_NON_VOLATILE, KEY_SET_VALUE
                                     , 0, &hKey, 0 );
    if ( lResult != ERROR_SUCCESS )
    {
      EVERR->MODULE
           ->Message(L"RegCreateKeyEx(HKLM\\%s) failed", (LPCWSTR)strKey )
           ->HResult( lResult )
           ->Advice_(L"Run the install elevated to register the event log source." )
           ->Cancel();
      return;
    }

    // REG_EXPAND_SZ is what the log reader expects here, and costs nothing for
    // a path that happens to contain no variables to expand.
    ::RegSetValueExW ( hKey, L"EventMessageFile", 0, REG_EXPAND_SZ
                     , (const BYTE*)(LPCWSTR)strModule
                     , (DWORD)((strModule.GetLength() + 1) * sizeof(WCHAR)) );

    DWORD dwTypes = EVENTLOG_ERROR_TYPE
                  | EVENTLOG_WARNING_TYPE
                  | EVENTLOG_INFORMATION_TYPE;
    ::RegSetValueExW ( hKey, L"TypesSupported", 0, REG_DWORD
                     , (const BYTE*)&dwTypes, sizeof(dwTypes) );

    ::RegCloseKey ( hKey );
#endif  // _WIN32
}

//
//  Service removal
//  NOTES: Skips operation if service already installed
//       : Usually activated by one of following execution arguments
//           -R[nstall]
//           /R[nstall]
//           /UNREG[SERVER]
//       : Refer complimentary UnInstall() for removal of installed
//         services
//
//  Returns:    BOOL
//              Operation summary
//                TRUE... Successful
//                FALSE.. Failed, refer GetP2Pevent() for details
BOOL
P2PeerService::UnInstall ( )
{
    // Redundancy check
    if ( !IsInstalled(m_szServiceName) )
        return TRUE;

    // Open the Service Control Manager
    SetLastError ( 0 );                // Clear failure flag
    SafeSCHandle shSCMgr
      = OpenSCManager ( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if ( shSCMgr == NULL )
    {
      EVERR->MODULE
           ->Message("OpenSCManager() failed" )
           ->HResult( GetLastError() )
           ->SetLast( );
      return FALSE;
    }

    // Isloate service
    SafeSCHandle shSrv = OpenService ( shSCMgr, m_szServiceName, DELETE );
    if ( shSrv == NULL )
    {
      EVERR->MODULE
           ->Message("OpenService() failed" )
           ->HResult( GetLastError() )
           ->SetLast( );
      return FALSE;
    }

    // Delete service
    if ( !DeleteService(shSrv) )
    {
      EVERR->MODULE
           ->Message("DeleteService() failed" )
           ->HResult( GetLastError() )
           ->SetLast( );
      return FALSE;
    }

    // Tidy up, and
    // NOTES: Observe post UnInstall() management of registry entries etc
    PostUnInstall ( );
    shSrv   = 0;
    shSCMgr = 0;
    return TRUE;
}

//
//  Removes the event log source registration
//  NOTES: Complements PostInstall().  Leaving the key behind would name a
//         module that uninstall may have removed, and the Event Viewer would
//         then fail to format entries already in the log.
//       : The key carries values only, never subkeys, so RegDeleteKey is
//         sufficient and its failure is not worth reporting: an uninstall that
//         has already removed the service should not fail over a stale
//         presentation hint, and the common failure here is simply that the
//         key was never registered because the install was not elevated.
//
void
P2PeerService::PostUnInstall ( )
{
#if defined(_WIN32)
    CStringW strKey;
    strKey.Format ( L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s"
                  , (LPCWSTR)CStringW(m_szServiceName) );
    ::RegDeleteKeyW ( HKEY_LOCAL_MACHINE, strKey );
#endif
}

//
//  Summarise installed status of passed service name
//  NOTES: Passed service name resolves to the "Name" column in
//         the Windows Service Control Manager
//
//  Parameters: LPCTSTR lpszServiceName
//              Name of the service to be checked for installation
//
//  Returns:    bool
//              Installed service summary
//                true... Installed
//                false.. Not installed or error
bool
P2PeerService::IsInstalled ( LPCTSTR lpszServiceName )
{
    // Locals
    bool bResult = false;

    // Open the Service Control Manager
    SetLastError ( 0 );                // Clear failure flag
    SafeSCHandle shSCMgr = ::OpenSCManager ( NULL, NULL
                                           , SC_MANAGER_ALL_ACCESS );
    if ( shSCMgr == NULL )
    {
      EVERR->MODULE->AFP(lpszServiceName)
           ->Message ("OpenSCManager() failed" )
           ->HResult( GetLastError() )
           ->SetLast ( );
      return false;
    }

    // Now open the service
    SafeSCHandle shSrv = OpenService ( shSCMgr, lpszServiceName
                                     , SERVICE_QUERY_CONFIG );
    if ( shSrv != NULL ) 
      bResult = true;

    // Tidy up, and
    shSrv   = 0;
    shSCMgr = 0;
    return bResult;
}

DWORD 
P2PeerService::Init ( DWORD argc, LPTSTR* argv )
{
    argc;
    argv;
    return NO_ERROR;
}


///////////////////////////////////////////////////////////////////////
//  Service operation

//
//  Service execution entry point
//  NOTES: For consistency -C[onsole] mode also utilises this entry point
//         but spawns the hub off into its own context and runs a console
//         from this context
int
P2PeerService::Run ( )
{
    // Environmental
    // NOTES: Demand initialisation of P2Pmsg'ing environment
    int iResult = 0;
    //ASSERT(m_nMaxHubs>0);
    //StartupP2Pmsg ( m_nMaxHubs );
    //P3PmsgBSTR::SetDefaultP2Pmsgnn ( VBLock_Addr32 );
    WSADATA oWsaData;
    WORD    wVersionRequested = MAKEWORD( 2, 0 );
    if ( WSAStartup ( wVersionRequested, &oWsaData ) )
    {
      EVERR->MODULE
           ->Message("WSAStartup() failed" ) 
           ->HResult( WSAGetLastError() )
           ->Cancel();
      return 1;
    }

    // Initiate and run contained hub as service
    // NOTES: In Service mode the hub locks up this processing context
    //        Console mode spawns hub off into another context
    //      : Hence the Service and Console threading models are subtly
    //        different
    if ( IsServiceMode() )
    {
      // Diagnostics FIRST, before anything that can raise one.  CreateHub()
      // below is perfectly capable of failing, and the point of this is that
      // its failure is reported rather than raised at a desktop nobody is
      // looking at.
      // ForceTextOutput() is belt and braces: Msgcore already refuses a dialog
      // where none could be dismissed, and this states the same intent at the
      // deployment boundary, where a reader of THIS file can see it.  It also
      // covers a host that has somehow arranged a viewable station for itself.
      P2Pevent::ForceTextOutput ( true );
#if defined(_WIN32)
      s_hP2PeventLog = ::RegisterEventSourceW ( 0, CStringW(m_szServiceName) );
      if ( s_hP2PeventLog )
        s_pfnP2PeventWas = P2Pevent::SetTextSink ( &P2PeerServiceEventLogSink );
#endif

      ASSERT(m_pP2PeerHub);
      ASSERT(m_pP2PeerHub->GetHubID()<=0);
      ASSERT(m_nMaxPumps>0);
      m_pP2PeerHub -> CreateHub ( m_strP2PaddrHub, m_nMaxPumps );
      if ( m_pP2PeerHub->GetHubID() > 0 )
        m_pP2PeerHub -> RunHub ( );
    }

    // Initiate and run contained hub as console
    // NOTES: In Console mode the hub is spawned off into its own
    //        processing context and this context by default becomes
    //        the operator console
    //      : Hence the Service and Console threading models are subtly
    //        different
    else if ( IsConsoleMode() )
    {
      ASSERT(m_pP2PeerHub);
      ASSERT(m_pP2PeerHub->GetHubID()<=0);
      m_pP2PeerHub -> SpawnHub ( );
      iResult = RunConsoleModeAttachment ( );
    }
    
    // Tidy up
    // NOTES: Common to both Service and Console modes
    m_pP2PeerHub -> CloseHub ( );

    // Retire the event log sink, in this order and only AFTER CloseHub().
    // Unhooking before deregistering means no thread can pick the sink up once
    // the handle is closed; and CloseHub() has already retired every pump, so
    // there is no thread left inside it holding the handle it read on entry.
    // Doing this before CloseHub() would drop exactly the diagnostics teardown
    // is most likely to raise.
#if defined(_WIN32)
    if ( s_hP2PeventLog )
    {
      P2Pevent::SetTextSink ( s_pfnP2PeventWas );
      s_pfnP2PeventWas = nullptr;
      ::DeregisterEventSource ( s_hP2PeventLog );
      s_hP2PeventLog = 0;
    }
#endif

    CleanupP2Pmsg ( );
    return 0;
}

int
P2PeerService::RunConsoleModeAttachment ( )
{
    // Locals
    int   nRetCode = 0;
    TCHAR cOption = 0;
    
    // Assume problematic environment
TOP:try
    {
      // Until terminated
      while ( cOption != 'Q' &&
              cOption != 'q'    )
      {
        UINT nHubID = m_pP2PeerHub -> GetHubID();
        UINT nPause = nHubID > 0 ? GetP2PmsgHubConCount ( nHubID ) : 0;
        cout << std::endl;
        cout << "(P2PeerService) Select option from:" << std::endl;
        if ( nHubID <= 0 )
          cout << " 1. Start Hub" << std::endl;
        if ( nHubID > 0 )
          cout << " 2. Stop Hub [" << nHubID << "]" << std::endl;
        if ( nPause )
          cout << " 3. Pause Hub" << std::endl;
        if ( nPause == 0 )
          cout << " 4. Continue Hub" << std::endl;
        //cout << " 5. Spare5 [" << szSpare2 << "]" << std::endl;
        //cout << " 6. Spare6" << std::endl;
        //cout << " 7. Spare7" << std::endl;
        cout << " 8. Toggle debug" << std::endl;
        cout << " R. Refresh" << std::endl;
        cout << " Q. Quit application" << std::endl;

        cout << "Option:";
        wcin >> cOption;
        cout << std::endl;
        nHubID = m_pP2PeerHub -> GetHubID();
        nPause = nHubID > 0 ? GetP2PmsgHubConCount ( nHubID ) : 0;

        // Start hub
        if ( cOption == _T('1') &&
             nHubID  <=  0         )
          m_pP2PeerHub -> SpawnHub ( );

        // Stop hub
        if ( cOption == _T('2') )
          m_pP2PeerHub -> CloseHub ( );

        // Pause hub by delegating to service equivalent
        if (  cOption == _T('3') &&
              nHubID  >      0   &&
              nPause                 )
        {
          nPause = 1;
          m_pP2PeerHub -> PauseHub ( );
        }

        // Continue hub by delegating to service equivalent
        if (  cOption == _T('4') &&
              nHubID  >      0   &&
             !nPause                 )
          m_pP2PeerHub -> WakeupHub ( );

        // Toggle debug mode
        // NOTES: Results are asynchronously displayed in the
        //        P2PeerSQLconsole hub.  Since the main() thread does
        //        not integrate seamlessly into a P2PeerHub virtual
        //        network
        if ( cOption == '8' )
        {
          P2Pevent::Configure ( P2Pevent::ADDMASK
                              , P2Pevotn_ERROR | P2Pevotn_DEBUG );
        }
      }
    }

    // Exceptions
    catch ( P2Pevent *pEVT )
    {
      pEVT->Cancel ( );
      goto TOP;
    }

    // Tidy up, and
	  return nRetCode;
}

///////////////////////////////////////////////////////////////////////
//  Standard Win32 Service control operations
//  NOTES: Referenced from the P2PeerService::ServiceCtrlHandler(),
//         and usually in the context of a Win32 system callback and
//         as such we NOT processing within hub context
//       : Default behaviour is to signal P2PeerHub.  At which
//         point implementation occurs in the context of the hub
DWORD
P2PeerService::OnPause ( void )
{
    if ( m_pP2PeerHub             == 0 ||
         m_pP2PeerHub->GetHubID() <= 0    )
      return NO_ERROR;
    m_pP2PeerHub -> PauseHub ( );
    return NO_ERROR;
}
DWORD
 P2PeerService::OnContinue ( void )
{
    if ( m_pP2PeerHub             == 0 ||
         m_pP2PeerHub->GetHubID() <= 0    )
      return NO_ERROR;
    m_pP2PeerHub -> WakeupHub ( );
    return NO_ERROR;
}
void
P2PeerService::OnStop ( void )
{
    if ( m_pP2PeerHub             == 0 ||
         m_pP2PeerHub->GetHubID() <= 0    )
      return;
    SignalP2PmsgHub ( m_pP2PeerHub->GetHubID(), P2PsigHub_CLOSEONIDLE );
  __time64_t tms = _time64 ( 0 ) + 5;
    while ( m_pP2PeerHub->GetHubID() > 0 &&
            tms <= _time64(0)               )
        Sleep ( 10 );
    return;
}
void
P2PeerService::OnShutdown ( void )
{   
    if ( m_pP2PeerHub             == 0 ||
         m_pP2PeerHub->GetHubID() <= 0    )
      return;
    SignalP2PmsgHub ( m_pP2PeerHub->GetHubID(), P2PsigHub_CLOSE );
  __time64_t tms = _time64 ( 0 ) + 5;
    while ( m_pP2PeerHub->GetHubID() > 0 &&
            tms <= _time64(0)               )
        Sleep ( 10 );
    return;
}
void
P2PeerService::OnInterrogate ( void )
{
}
void
P2PeerService::OnUserControl ( DWORD )
{
}

///////////////////////////////////////////////////////////////////////
//  Properties

LPCTSTR
P2PeerService::SetServiceName ( LPCTSTR lpszServiceName )
{
    m_strServiceName = lpszServiceName;
    return m_strServiceName;
}
LPCTSTR
P2PeerService::GetServiceName ( )
{
    return m_strServiceName;
}
LPCTSTR
P2PeerService::SetDisplayName ( LPCTSTR lpszDisplayName )
{
    m_strDisplayName = lpszDisplayName;
    return m_strDisplayName;
}
LPCTSTR
P2PeerService::GetDisplayName ( )
{
    return m_strDisplayName;
}
LPCTSTR
P2PeerService::SetServiceDesc ( LPCTSTR lpszServiceDesc )
{
    m_strServiceDesc = lpszServiceDesc;
    return m_strServiceDesc;
}
LPCTSTR
P2PeerService::GetServiceDesc ( )
{
    return m_strServiceDesc;
}
void
P2PeerService::SetAcceptedControls ( DWORD controls )
{
    m_oServiceStatus.dwControlsAccepted = controls;
}

void
P2PeerService::ChangeStatus ( DWORD state, DWORD checkpoint
                            , DWORD waithint )
{
    m_oServiceStatus.dwCurrentState  = state;
    m_oServiceStatus.dwCheckPoint    = checkpoint;
    m_oServiceStatus.dwWaitHint      = waithint;
    
    SetServiceStatus( m_hServiceStatus, &m_oServiceStatus );
}

DWORD
P2PeerService::SetExitMode ( DWORD nExitCode )
{
    if (  m_bExitMode                      &&
         !m_oServiceStatus.dwWin32ExitCode    )
      m_oServiceStatus.dwWin32ExitCode = (int)nExitCode;
    m_bExitMode = true;
    return m_oServiceStatus.dwWin32ExitCode;
}
DWORD
P2PeerService::GetExitCode ( )
{
    return m_oServiceStatus.dwWin32ExitCode;
}

///////////////////////////////////////////////////////////////////////        
//  P2PeerHub integration

P2PeerHub*
P2PeerService::PostP2PeerHub ( P2PeerHub *pHub )
{
    if ( m_pP2PeerHub == pHub )
      return m_pP2PeerHub;
    if ( m_pP2PeerHub )
      delete m_pP2PeerHub;
    m_pP2PeerHub = pHub;
    return m_pP2PeerHub;
}

P2PeerHub*
P2PeerService::GetP2PeerHub ( )
{
    return m_pP2PeerHub;
}

///////////////////////////////////////////////////////////////////////
//  Property and state exposure
//
bool
P2PeerService::IsServiceMode ( )
{
    if (  m_bService  &&
         !m_bSystem   &&
         !m_bConsole     )
      return true;
    if ( !m_bSystem   &&
         !m_bConsole  &&
         !m_bExitMode    )
      return true;
    return false;
}

bool
P2PeerService::IsConsoleMode ( )
{
    return m_bConsole;
}

bool
P2PeerService::IsDebugMode ( )
{
    return m_bDebug;
}

bool
P2PeerService::IsExitMode() 
{
    return m_bExitMode;
}

///////////////////////////////////////////////////////////////////////
//  Safe SERVICE CONTROL MANAGER handle implementation
//  NOTES: HANDLE is managed within the life cycle of this object.
//
SafeSCHandle::SafeSCHandle ( )
{
    m_hSC = NULL;
}
SafeSCHandle::SafeSCHandle ( SC_HANDLE hSC )
{   
    m_hSC = hSC;
}
SafeSCHandle::~SafeSCHandle ( )
{   
    if ( m_hSC != NULL )
      CloseServiceHandle ( m_hSC );
}
SafeSCHandle&
SafeSCHandle::operator = ( SC_HANDLE hSC )
{   
    if ( m_hSC != hSC  &&
         m_hSC != NULL    )
      CloseServiceHandle ( m_hSC );
    m_hSC = hSC;
    return *this;
}
SafeSCHandle::operator SC_HANDLE ( )
{   
    return m_hSC;
}
SC_HANDLE
SafeSCHandle::Dereference()
{   
    SC_HANDLE hSC = m_hSC;
    m_hSC = NULL;
    return hSC;
}
