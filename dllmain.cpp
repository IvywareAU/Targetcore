// Copyright © 2022, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  Defines the initialization routines for the DLL.
//       : Initialising MFC extension DLL's
//         http://msdn.microsoft.com/en-us/library/h5f7ck28.aspx
//       : Introducing AFX_MANAGE_STATE() produces following link error
//         error LNK2005: _DllMain@12 already defined in dllmain.obj
//         P2PresourceState class has been introduce to negate such
//       : Contents audited against VS2019 wizard 

#include "stdafx.h"
#include "Targetcore.h"

//  The whole of this file is DLL-only. The DebugLib/ReleaseLib configurations
//  archive Targetcore straight into the consumer, where there is no module to
//  attach: no DllMain runs, AfxInitExtensionModule has nothing to initialise and
//  CDynLinkLibrary has no resource chain to join. The consumer's own module owns
//  all of that. The Lib configurations therefore also mark this file
//  ExcludedFromBuild, so this guard is belt-and-braces -- it keeps the file honest
//  for any other build system (CMake) that might compile it into a static target.
//
//  Nothing is lost by dropping it: MANAGE_RESOURCE_STATE is never used anywhere in
//  the tree, and Targetcore.rc holds only a VERSIONINFO block and one IDS_APP_TITLE
//  string -- there are no dialogs, menus or bitmaps needing a resource handle swap.
#if !defined (Targetcore_STATIC)

#include <afxwin.h>
#include <afxdllx.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

static AFX_EXTENSION_MODULE Targetcore_DLL = { false, nullptr };

extern "C" int APIENTRY
DllMain ( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved )
{
    // Remove this if you use lpReserved
    UNREFERENCED_PARAMETER(lpReserved);

    if ( dwReason == DLL_PROCESS_ATTACH )
    {
      TRACE0("Targetcore.DLL Initializing!\n");
      // Extension DLL one-time initialization
      if ( !AfxInitExtensionModule(Targetcore_DLL,hInstance) )
        return 0;

      // Insert this DLL into the resource chain
      // NOTE: If this Extension DLL is being implicitly linked to by
      //  an MFC Regular DLL (such as an ActiveX Control)
      //  instead of an MFC application, then you will want to
      //  remove this line from DllMain and put it in a separate
      //  function exported from this Extension DLL.  The Regular DLL
      //  that uses this Extension DLL should then explicitly call that
      //  function to initialize this Extension DLL.  Otherwise,
      //  the CDynLinkLibrary object will not be attached to the
      //  Regular DLL's resource chain, and serious problems will
      //  result.
      new CDynLinkLibrary(Targetcore_DLL);
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
      TRACE0("Targetcore.DLL Terminating!\n");
      // Terminate the library before destructors are called
      AfxTermExtensionModule(Targetcore_DLL);
    }
    return 1;   // ok
}

//
//  Manages MFC resource state for this P2PmsgCharts DLL
//  NOTES: Each extension DLL requires its own private implementation
//         based around the Targetcore_DLL equivalent external.
//       : Code ia duplicated for each MFC extension DLL.  Not unlike
//         the way Dllmain() is replicated
P2PresourceState::P2PresourceState()
{
    m_hRestore = AfxGetResourceHandle();
    if ( m_hRestore != Targetcore_DLL.hModule )
      AfxSetResourceHandle(Targetcore_DLL.hModule);
    else           // We are our own state
      m_hRestore = NULL;
}
P2PresourceState::~P2PresourceState()
{
    if ( m_hRestore )
      AfxSetResourceHandle(m_hRestore);
}

#endif  // !Targetcore_STATIC
