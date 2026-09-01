// Copyright © 2006-2010, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  Implements the TargetCore.DLL export linkage macro and the DLL-private
//  MFC resource-state guard
//  NOTES: To be included with the definitions for any object exported
//         from the TargetCore.DLL  Follows the MFC_EXT_CLASS pattern
//       : Either the TargetCore project or the StdAfx.h file MUST
//         contain the TargetCore_EXPORTS definition.  For further
//         Developer Studio details refer Project Properties >> Config >>
//         C/C++ Preprocessor
//

#pragma once

//  The component's version identity. Included here rather than left to the
//  consumer because this header is the one every exported object already
//  pulls in, so TARGETCORE_VERSION_* is available anywhere TargetCore_EXT is.
#include "TargetCore_version.h"

//  Static-library variant (DebugLib/ReleaseLib) carries NO __declspec at all: the
//  objects are archived straight into the consumer, so there is nothing to export
//  and nothing to import. Mirrors Msgcore.h's Msgcore_STATIC branch and the
//  TargetCore_STATIC branch already present in TargetCore_c.h. This arm MUST come
//  first -- the Lib configurations define neither TargetCore_EXPORTS nor anything
//  else, so without it every TargetCore_EXT class would be decorated dllimport and
//  the archive would reference import thunks that no DLL provides.
#if defined (TargetCore_STATIC)
  #define TargetCore_EXT
#elif defined (TargetCore_EXPORTS)
  #define TargetCore_EXT __declspec(dllexport)
#else
  #define TargetCore_EXT __declspec(dllimport)
#endif

//
//  Manages MFC resource state for the TargetCore DLL
//  NOTES: Not to be exported, MUST remain private to DLL for which it's instanciated
//       : Each MFC extension DLL requires it's own specialised implementation
//         for its own resource instance
//       : MANAGE_RESOURCE_STATE preceeds any local resource reference. Stack
//         implementation restores previous state upon exit
//       : CDialog derived classes require DoModal_EoD() to be overridden with
//         int <name>Dlg::DoModal_EoD()
//         {
//           MANAGE_RESOURCE_STATE;
//           return CDialog::DoModal_EoD();
//         }
#if defined (TargetCore_EXPORTS)
class P2PresourceState                 // Do not export
{
    public:
      P2PresourceState();
     ~P2PresourceState();
    protected:
      HINSTANCE m_hRestore;
};
#define MANAGE_RESOURCE_STATE P2PresourceState oP2Pstate
#endif
