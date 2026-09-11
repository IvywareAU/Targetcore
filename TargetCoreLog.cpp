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
//  MsgexceptionLog definitions
//
#include "stdafx.h"
#include "afxwin.h"
//#include <sys\timeb.h>
#include "P2Peer.h"
#include "Msgexception.h"
#include "P2Pwin32.h"

#include "TargetCoreLog.h"
#include <fcntl.h>
#include <corecrt_io.h>
#include <ShlObj_core.h>
#include <psapi.h>
#include <io.h>
#include <stdio.h>

/*#include "stdafx.h"
#include <afxmt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <math.h>
#include <stdio.h>
#include <psapi.h>*/

///////////////////////////////////////////////////////////////////////
//  VMSevents log file life cycle management structures
//  NOTES: Private to VMSevents library
//       : Functions with "_" preceeding the name are not thread safe
//         and only intended to be called internally

#define LOGOPENFILE -1000
#ifdef _DEBUG
#define MAX_DEBUGLOG_ENTRIES 3000// Kept shorterto test sequences
#else
#define MAX_DEBUGLOG_ENTRIES 3000
#endif
#define DEBUGLOG_AUDIT_MONTHS 1

//  Filesystem path separator for the log destination path. The LocalAppData base
//  (SHGetKnownFolderPath) is native to each OS: backslash on Windows, forward-slash
//  on the Linux shim ($XDG_DATA_HOME / $HOME/.local/share). Hard-coding "\\" embedded
//  literal backslashes into the Linux filename (the whole "<Prefix>\Logs\" subtree
//  collapsed into one garbage name). Windows keeps "\\" byte-identical; Linux uses "/".
#ifdef _WIN32
#define P2P_LOG_PATHSEP L"\\"
#else
#define P2P_LOG_PATHSEP L"/"
#endif

CString      g_csDebugLogFolder;
BOOL         g_bVMSevents_TRACE  = TRUE;
BOOL         g_bVMSevents_MEMORY = TRUE;
//extern list<BookMarkItem *> g_listBKItem;
CString      g_csLocalUserFolder;
CString      g_strDebuglogFilePrefix;
//CString      g_strRollover;
//extern IniFile g_initFile;	
BOOL         g_bLogEnd = FALSE;
//int          g_nDebuglogFD      = -1;
//int          m_nLogentries =  0;
COleDateTime m_dtStartup;

//
//  VMSevents thread life cycle management functions
//  NOTES: Forms the basis upon which all VMSevents are posted throughout
//         to FreedomVMS applications and DLL's
// 
CMutex g_hVMSeventsMutex;
typedef struct
{
    UINT           nSinkID;            // Sink identification code
    HWND           hWnd;               // Registered window, or
    DWORD          nThreadID;          //            thread, or
    //P2PumpID       nPumpID;            //            P2Pump, or
    //P2PeventCBFnc  pP2PeventCBFnc;     //            callback

    DWORD_PTR     dwCBKey;             // Call back key
    DWORD         dwNotifications;     // Registered Notifications.
	  CString       strThreadTag;
	  CString       strThreadDesc;
	  CTime         dtStartup;
} VMSevent;
static CMap<DWORD, DWORD, VMSevent*, VMSevent*&> s_ThreadID_VMSevents;
static CRITICAL_SECTION                          s_oCSectionP2Pevent;
static BOOL           s_bStartupVMSevents  = FALSE;
static BOOL           s_bShutdownVMSevents = FALSE;
static BOOL           g_bTranscodeServerCheck = FALSE;

typedef struct
{   // Enque'd messages
    DWORD          nThreadID;          //            thread, or
	  COleDateTime   dtVMSevent;
	  char           cDebuglogType;
	  CString        strMessage;
} VMSenque;
static CList<VMSenque*> s_CListVMSenque;
int	  _TranscodeServerCheck ( );

//
//  VMSevents trace message types
//  NOTES: Placeholder for VMSevents_TRACE types.
// 
typedef struct
{
    UINT           nTraceID;           // Sink identification code

	CStringA     strTraceTag;
	int            nRefcount;
} VMSeventrace;
const  int VMSeventrace_MAX = 32;      // Maximum number of trace types
static VMSeventrace s_aVMSeventrace[VMSeventrace_MAX+1];

///////////////////////////////////////////////////////////////////////
//  Constructors and destructor
//
MsgexceptionLog::MsgexceptionLog ( LPCWSTR lpszLognamePrefix )
{
    m_strLogfilePrefix = lpszLognamePrefix;
}

MsgexceptionLog::~MsgexceptionLog ( )
{
    Shutdown ( );
}

//
//  Registered P2Pevent callbacks
//  NOTES: Receives and formats P2Pevents for logging
//
//  Parameters:  P2PeventSinkID  nSinkID
//               
//               DWORD_PTR dwUserData
//               Point to this instance of MsgexceptionLog
// 
//               P2Pevent *pP2Pevent
//               Msgexception to be formated
//
//
void
MsgexceptionCB ( P2PeventSinkID  nSinkID    // Sink identification code
               , DWORD_PTR      dwCBKey     // User definied callback key
               , const P2Pevent& oEvent )   // Notification event
{
    MsgexceptionLog *pThis = (MsgexceptionLog *)dwCBKey;
    pThis -> LogfileP2PeventCB ( const_cast<P2Pevent*>(&oEvent) );
}

BOOL
MsgexceptionLog::Startup ( )
{
    ASSERT(m_fdExceptionLog<0);
    // Local app "MsgexceptionLog" destination folder
    // NOTES: "C:\users\<user>\AppData\"
    WCHAR *pwszPathname;
    SHGetKnownFolderPath ( FOLDERID_LocalAppData, 0, NULL, &pwszPathname );
    m_strLocalAppDataFolder = pwszPathname;
    CoTaskMemFree(pwszPathname);

    // MsgexceptionLog file open
    m_dtStartup = COleDateTime::GetCurrentTime();
    LogfileOpen ( m_dtStartup );

    // Register for P2Pevent's
    P2Pevent::Register4P2Pevents ( 9999, &MsgexceptionLog::MsgexceptionCB
                             , ~0u, reinterpret_cast<DWORD_PTR>(this) );
    //m_nCBSinkID = CreateP2PeventSinkdebug ( reinterpret_cast<DWORD_PTR>(this)
    //                                 , &MsgexceptionLog::MsgexceptionCB, TRUE );

    // Tidy up, and
    return TRUE;
}

void
MsgexceptionLog::Shutdown ( )
{
    // Close P2Pevent's sink
    // NOTES: First operation to pause P2Pevent's flow
    if ( m_nCBSinkID )
      CloseP2PeventSink ( m_nCBSinkID );
    m_nCBSinkID = 0;
    // Flush file contents
    // Close out log
    LogfileClose ( );
}

    // Factories
//
//  CWndApp application file helpers
//  NOTES: Static functions are just simpler
//
//  Parameters:  LPCTSTR lpszDataFileName
//               Folder/file path to be appended to FOLDERID_LocalAppData
//
//  Returns:     CString
//               Constructed FOLDERID_LocalAppData file path
CString
MsgexceptionLog_LocalAppDataFilePath( LPCTSTR lpszDataFileName )
{
    USES_CONVERSION;
    WCHAR *pwszPathname;
    SHGetKnownFolderPath ( FOLDERID_LocalAppData, 0, NULL, &pwszPathname);
    CString strLocalAppDataFile(pwszPathname);
    CoTaskMemFree(pwszPathname);
    strLocalAppDataFile += P2P_LOG_PATHSEP;
    strLocalAppDataFile += lpszDataFileName;
    return strLocalAppDataFile;
}

//
//  Opens MsgexceptionLog file according to specified time
//
//  Parameters:  lpszFilenamePrefix
//               Debuglog filename prefix "FreedomServer32", "FreedomClient64"
//
//               CTime dtCurrentTime
//               Current VMSevents time
//
//  Result:      BOOL
//               Success code
BOOL
MsgexceptionLog::LogfileOpen ( COleDateTime &dtCurrentTime )
{
    // Full "MsgexceptionLog" file path
	  m_dtStartup = dtCurrentTime;
    m_strDestinPath.Format ( L"%s" P2P_LOG_PATHSEP L"%s" P2P_LOG_PATHSEP L"Logs" P2P_LOG_PATHSEP L"%s_%04d%02d%02d_%02d%02d%02d.txt"
		            , (LPCWSTR)m_strLocalAppDataFolder
                , (LPCWSTR)m_strLogfilePrefix, (LPCWSTR)m_strLogfilePrefix
			          , m_dtStartup.GetYear(), m_dtStartup.GetMonth(), m_dtStartup.GetDay() 
		            , m_dtStartup.GetHour(), m_dtStartup.GetMinute(), m_dtStartup.GetSecond() );
    // Open
    CStringA strMsgexceptionLog = CStringA(m_strDestinPath);
    m_fdExceptionLog = _open ( strMsgexceptionLog
                             , _O_CREAT |_O_APPEND| _O_BINARY | _O_WRONLY, _S_IREAD | _S_IWRITE );
	  if( m_fdExceptionLog <= -1 )
	  {
		  m_fdExceptionLog = LOGOPENFILE;
		  return FALSE;
	  }
    // Tidy up, and
    m_nLogentries = 0;
	  return TRUE;
}
//
//  Close log file
//
BOOL
MsgexceptionLog::LogfileClose ( ) noexcept
{
	  if ( m_fdExceptionLog >= 0 )
	  {
	    _close(m_fdExceptionLog);
	     m_fdExceptionLog = -1;
	  }
    return TRUE;
}

//
//  Internal MsgexceptionLog file write utility (one and only)
// 
//  Parameters:  int nSubrecord
//               Sub-record number in logging sequence
//                 0.. First record in sequence
//
//               CString& strMessage
//               Message to be logged
//
//  Return:      int
//               
int
MsgexceptionLog::LogfileWrite ( int nSubrecord, CString& strMessage )
{
	  // Variable argument lists can be problematic
	  // NOTES: CSingleLock exception safe, Unlock() called in destructor.
    try
	  {
	    int    iSize = 0;
	    char  szMessage[2048];
      COleDateTime dtDebuglog = COleDateTime::GetCurrentTime();
      char cDebuglogType   = 'L';
      CString strThreadTag = L"Main";

	    // Message prefix preparation
      if ( nSubrecord <= 0 ) {
	      iSize = _snprintf_s ( szMessage, sizeof(szMessage), _TRUNCATE
	                          , "%02i:%02i:%02i[%12s]%c "
		                        , dtDebuglog.GetHour(), dtDebuglog.GetMinute(), dtDebuglog.GetSecond()
						  , (LPCSTR)CStringA(strThreadTag), cDebuglogType );
      } else {
	      iSize = _snprintf_s ( szMessage, sizeof(szMessage), _TRUNCATE
                            , "%24s", " " );
      }

	    // Append actual message
      CStringA strMessageA = CStringA(strMessage);
      LPCSTR pszMessage = (LPCSTR)strMessageA;
      int iMsgsize = strMessage.GetLength();
	    iMsgsize = min ( iMsgsize, (int)sizeof(szMessage)-iSize-2 );
	    if ( pszMessage && iSize > 0 )
	    {
	      memcpy ( &szMessage[iSize], pszMessage,iMsgsize );
	      iSize += iMsgsize;
		    ASSERT(iSize>0&&iSize<sizeof(szMessage));
	    }

	    // Tidy up trailing delimiters
	    // NOTES: Check for DebuglogFile rollover immediately before write only
      //        initial sub-records
      //      : Keep initial record
	    while (   iSize > 0                   &&
		        ( szMessage[iSize-1] == '\r' ||
		          szMessage[iSize-1] == '\n' ||
			  	szMessage[iSize-1] == ' '     )      )
	      iSize--;
	    szMessage[iSize++] = '\r';
	    szMessage[iSize++] = '\n';
	    szMessage[iSize]   = 0;
	    if ( m_fdExceptionLog >= 0 )
	    {
	      LogfileRollover(dtDebuglog);
	      m_nLogentries++;
	     _write ( m_fdExceptionLog, szMessage, iSize );
	    }
	    //else
	    // _DebuglogEnque ( pVMSevent, dtDebuglog, cDebuglogType, pszMessage, iMsgsize );

	    // Tidy up, and
	    return iSize;
	  }
	  // Exceptions
  	// NOTES: Historically this would have propagated up through the stack
  	catch ( ... )
  	{
      ASSERT(0);
	  }
	  return ++nSubrecord;
}

BOOL
MsgexceptionLog::LogfileRollover ( COleDateTime& dtCurrent )
{
	  // Precautions against recursion
	  // NOTES: Issues with rollovers withing rollovers
	  static BOOL s_bRecursion = FALSE;
	  if ( s_bRecursion )
		  return TRUE;
	  try
	  {
    	// Day or logged entries rollover
		  // NOTES: Debug option tests an houly rollover
#ifdef _DEBUG
	    if ( m_dtStartup.GetHour() != dtCurrent.GetHour() ||
	         m_nLogentries >= MAX_DEBUGLOG_ENTRIES            )
#else
	    if ( m_dtStartup.GetDay() != dtCurrent.GetDay() ||
	         m_nLogentries >= MAX_DEBUGLOG_ENTRIES          )
#endif
	    {
		    s_bRecursion = TRUE;
	      // Rollover message trailer
	      // NOTES: Encode locally since thread has been already locked
	      //      : Absense of "Shutdown" or "Rollover" message flags program crash
	      m_nLogentries--;            // Otherwise we end up with recursion
	      //VMSevent *pVMSevent = GetpVMSevent();
	      LogfileWrite ( 0, m_strRollover );

	      // Date changed
	      LogfileClose();
	      if ( !LogfileOpen(dtCurrent) )
	      {
	        ASSERT(0);
		      return FALSE;
	      }

	      // Rollover message header
	      // NOTES: Encod locally since thread has been already locked
	      LogfileWrite ( 0, m_strRollover );

	      // Logfile audit time
        // NOTES: Deletes expired logfiles
	      //VMSevents_DebuglogAudit();
	    }

#ifdef _DEBUG
	    // Debug code for testing debuglog garbage collection
	    //if ( m_nLogentries%20 == 0 )
	      //VMSevents_DebuglogAudit();
#endif
	  }
	  catch (...)
	  {
		  ASSERT(0);
	  }
	  // Tidy up, and
	  s_bRecursion = FALSE;
	  return TRUE;
}

/*    public:

    // Overloaded operators
    public:

    // Associated P2Pevent function parameters
    // NOTES: Variable parameter set associated with P2Pevent
    public:*/

//  Configuration
//  NOTES: Logging defaults and settings
LPCWSTR
MsgexceptionLog::SetFirstentryPrefix ( LPCWSTR lpszFormatTag, ... )
{
	  // Variable argument lists can be problematic
	  // NOTES: CSingleLock exception safe, Unlock() called in destructor.
    try
	  {
      int nThreadId = GetCurrentThreadId();
	    m_strRollover = "Rollover ";  // Used later for rollover's

	    // Message prefix preparation
	    m_strFirstentryPrefix = "Startup ";
	    va_list  vaArgs;
	    if ( lpszFormatTag )
	    {
	      char szMessage[2048] = {0};
		    int   iSize = 0;
	      va_start ( vaArgs, lpszFormatTag ); 
	      iSize = vsprintf_s ( szMessage, sizeof(szMessage)-128, (LPCSTR)CStringA(lpszFormatTag), vaArgs );
	      va_end   ( vaArgs );
        m_strFirstentryPrefix += szMessage;
		    m_strRollover         += szMessage;
	    }
	  }
    // Exceptions
    catch_pP2Pevent_Cancel
    catch_pCException_Cancel
    catch_ALL_Cancel
    return m_strLogfilePrefix;
}

//
//  Adds a break point to the Logfile
//
//  Parameters:  LPCWSTR lpBreakPointMsg
//               Breakpoint message
//
//  Returns:     int
//               Number of entries in current Logfile
int
MsgexceptionLog::Breakpoint ( LPCWSTR lpBreakpointMsg )
{
	  // Variable argument lists can be problematic
	  // NOTES: CSingleLock exception safe, Unlock() called in destructor.
    try
	  {
	    int    iSize = 0;
	    char  szMessage[2048], szSpacer[80];
      memset ( szSpacer, '=', sizeof(szSpacer)-1 ); szSpacer[sizeof(szSpacer)-1] = 0;
      COleDateTime dtDebuglog = COleDateTime::GetCurrentTime();
      char cDebuglogType   = 'B';
      CString strThreadTag = L"Main";

	    // Message prefix preparation
	    iSize = _snprintf_s ( szMessage, sizeof(szMessage), _TRUNCATE
	                        , "%02i:%02i:%02i[%12s]%c %50s"
		                      , dtDebuglog.GetHour(), dtDebuglog.GetMinute(), dtDebuglog.GetSecond()
				  , (LPCSTR)CStringA(strThreadTag), cDebuglogType, szSpacer );

	    // Tidy up trailing delimiters
	    // NOTES: Check for DebuglogFile rollover immediately before write only
      //        initial sub-records
      //      : Keep initial record
	    szMessage[iSize++] = '\r';
	    szMessage[iSize++] = '\n';
	    szMessage[iSize]   = 0;
	    if ( m_fdExceptionLog >= 0 )
	    {
	      LogfileRollover(dtDebuglog);
	      m_nLogentries++;
	     _write ( m_fdExceptionLog, szMessage, iSize );
	    }
	    //else
	    // _DebuglogEnque ( pVMSevent, dtDebuglog, cDebuglogType, pszMessage, iMsgsize );

	    // Tidy up, and
	    return iSize;
	  }
	  // Exceptions
  	// NOTES: Historically this would have propagated up through the stack
  	catch ( ... )
  	{
      ASSERT(0);
	  }
	  return m_nLogentries;
}

    // Properties
/*    public:

    // Attributes
    private:
      CString           m_strLogfilePrefix;
      CString           m_strFirstentryPrefix;
};*/


//
//  Replace tabs with spaces within string
//
//  Parameters:  const CString& oCString
//               String in which tabs are to be replaced
//
//               UINT nTabSize
//               Tab size
//
//  Returns:     CString
//               Resultant string
//
static CString
CString_ReplaceTabs ( const CString& oCString, UINT uiTabSize )
{
    CString  strString;
    LPCTSTR lpszString = oCString;
    int      k = 0;
    while ( *lpszString )
    {
      if ( *lpszString != L'\t') {
        strString += *lpszString++;
        k++;
        continue;
      }
      lpszString++;
      do {
        strString += L' ';
        k++;
      } while ( k % uiTabSize);
    }
    return strString;
}
//
//  WM_P2PeventNOTN message handler
//  NOTES: P2Pevent notifications from P2Peer API received at random
//
//
//  Parameters:  P2PeventSinkID  nSinkID
//               Sink identification code
// 
//               DWORD_PTR      dwCBKey
//               User definied callback key, this object
// 
//               const P2Pevent& oEvent );
//               Notification event to be logged
//
void
MsgexceptionLog::MsgexceptionCB ( P2PeventSinkID   nSinkID
                                , DWORD_PTR       dwCBKey
                                , const P2Pevent&  oEvent )
{
    MsgexceptionLog *pThis = (MsgexceptionLog*)dwCBKey;
    ASSERT(nSinkID==9999);
    pThis -> LogfileP2PeventCB ( const_cast<P2Pevent*>(&oEvent) );
}
void
MsgexceptionLog::LogfileP2PeventCB ( P2Pevent *pP2Pevent )
{
    // Introduce locals
    if ( pP2Pevent == NULL )           // SNHappen, but
      return;
    int nSubrecord = 0;
    // Manage 

    // Header
    CString strSummary;
    CString strP2Peventype  = pP2Pevent -> GetClassText ( );
            strP2Peventype += L":\t";
    //m_wndP2PeventsLog.AddString ( strSummary );
    //hItemHeader = m_pP2PeventTreeCtrl -> InsertItem ( strSummary, TVI_ROOT, TVI_LAST );

    // Module
    if ( _tcslen(pP2Pevent->GetModule()) > 0 )
    {
      //CString strModule( L"Module: ");
      strSummary  = strP2Peventype;
      //strSummary += L":\t";
      strSummary += pP2Pevent->GetModule();
    }
    strSummary = CString_ReplaceTabs ( strSummary, 7 );
    if ( !strSummary.IsEmpty() ) {
      nSubrecord = LogfileWrite ( nSubrecord, strSummary );
      //m_wndP2PeventsLog.AddString ( strSummary );
      strP2Peventype = L"";
    }

    // Message
    if ( pP2Pevent->Exists(TEvent__Dsc) )
    {
      CString strMessage  = strP2Peventype;
      P3PmsgList& oList = dynamic_cast<P3PmsgList&>((*pP2Pevent)[TEvent__Dsc]);
      VBLaddr aEntry = oList.GetHeadPos();
      while ( aEntry )
      {
        P3PmsgData& oEntry = oList.GetNext ( aEntry );
        strMessage += oEntry.c_wstr();
        strMessage  = CString_ReplaceTabs ( strMessage, 7 );
        nSubrecord  = LogfileWrite ( nSubrecord, strMessage);
        //m_wndP2PeventsLog.AddString ( strMessage );
        strP2Peventype = L"";
        strMessage  = strP2Peventype;
      }
    }

    // HRESULT
    if ( pP2Pevent->GetHRESULT() != 0 )
    {
      CString strHRESULT = strP2Peventype;
      strHRESULT.Format ( L"HRESULT: [%i] ", pP2Pevent->GetHRESULT() );
      strHRESULT = strP2Peventype + strHRESULT;
      //strHRESULT += pP2Pevent->GetHRESULText();
      //strHRESULT  = strP2Peventype + strHRESULT;
      strHRESULT = CString_ReplaceTabs ( strHRESULT, 7 );
      nSubrecord = LogfileWrite ( nSubrecord, strHRESULT );
      //m_wndP2PeventsLog.AddString ( strHRESULT );
      strP2Peventype = L"";
    }

    // Advice
    if ( pP2Pevent->Exists(TEvent__Adv) )
    {
      CString strAdvice  = L"\tAdvice: ";
      P3PmsgList& oList = dynamic_cast<P3PmsgList&>((*pP2Pevent)[TEvent__Adv]);
      VBLaddr aEntry = oList.GetHeadPos();
      while ( aEntry )
      {
        P3PmsgData& oEntry = oList.GetNext ( aEntry );
        strAdvice += oEntry.c_wstr();
        strAdvice  = CString_ReplaceTabs ( strAdvice, 7 );
        nSubrecord = LogfileWrite ( nSubrecord, strAdvice );
        //m_wndP2PeventsLog.AddString ( strAdvice );
        strAdvice  = L"";
      }
    }

    // Tidy up and
    return;
}

