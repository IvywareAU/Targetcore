// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
// Windows Header Files:
//#include <windows.h>

#ifdef _WIN32
//  The Windows platform floor. This must stay the first Windows-facing include
//  in the PCH, or the floor lands after a Windows header has already fixed the
//  platform.
#include "targetver.h"

// TODO: Added by LJM to minimise compiler warning
#pragma warning(disable:4251)

#include <afx.h>
#include <afxwin.h>
#include <comutil.h>

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxole.h>         // MFC OLE classes
#include <afxodlgs.h>       // MFC OLE dialog classes
#include <afxdisp.h>        // MFC Automation classes
#endif // _AFX_NO_OLE_SUPPORT
#endif // _WIN32

// Linux port: the Win32 socket/IOCP/file surface is routed through the platform
// shim layer. On _WIN32 platform.h is pure pass-through (WinSock2/ws2tcpip/mswsock/
// windows + atlstr), so the Windows build is unchanged.
#include "../Platform/platform.h"

#ifdef _WIN32
#include <AfxMt.h>                     // Multi-tasking
#include <AfxTempl.h>                  // Templates
#else
#include "../Platform/mfcshim.h"       // CObject/CList/CMap/CString/ASSERT on Linux
#endif // _WIN32

// TODO: reference additional headers your program requires here
#define _CRT_RAND_S
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <map>
#include <list>
#include <vector>
#ifdef _WIN32
#include <xstring>                     // Added for VS2019 - preceedes <string> (MSVC only)
#endif
#include <string>
#include <iostream>

//
//  P2Peer Visual Studio 2002, 2005, 2008 langauge extensions to faciltate
//  backwards compatiblity for VS2010+
//  NOTES: VS2002, 2005, 2008 release requirement, may be dropped from
//         subsequent code base and VS2010+ implementations
#ifdef _WIN32
#if _MFC_VER <= 0x0999
#define   nullptr NULL
#endif
#endif // _WIN32
