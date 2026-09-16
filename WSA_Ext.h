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
//  Definitions for the Microsoft Ws2_32.dll library extensions
//
#pragma once
#include "Targetcore.h"

//
//  Safe SOCKET container
//  NOTES: SOCKET is managed within the life cycle of this object.
//
#ifndef SOCKET
#define SOCKET UINT_PTR
#endif
class SafeSOCKET
{
    public:
        SafeSOCKET ( );
        SafeSOCKET ( SOCKET oSocket );
       ~SafeSOCKET ( );

      SafeSOCKET&
        operator = ( SOCKET oSocket );
        operator SOCKET ( );
 
      SOCKET
        Dereference();

    private:
        SOCKET m_oSocket;
};

//
//  WS extensions
Targetcore_EXT CString
WSA_GetHostName ( );
