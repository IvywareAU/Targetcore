// Copyright © 2006-2009, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  Implementation for the Microsoft Ws2_32.dll library extensions
//
#include "stdafx.h"
#include "WSA_Ext.h"

///////////////////////////////////////////////////////////////////////
//  Safe SOCKET implementation
//  NOTES: SOCKET is managed within the life cycle of this object.
//
SafeSOCKET::SafeSOCKET ( )
{   
    m_oSocket = INVALID_SOCKET;
}
SafeSOCKET::SafeSOCKET ( SOCKET oSocket )
{
    m_oSocket = oSocket;
}
SafeSOCKET::~SafeSOCKET ( )
{   
    if ( m_oSocket != INVALID_SOCKET )
      closesocket ( m_oSocket );
}
SafeSOCKET&
SafeSOCKET::operator = ( SOCKET oSocket )
{
    if ( m_oSocket != oSocket        &&
         m_oSocket != INVALID_SOCKET    )
      closesocket ( m_oSocket );
    m_oSocket = oSocket;
    return *this;
}
SafeSOCKET::operator SOCKET ( )
{   
    return m_oSocket;
}
SOCKET
SafeSOCKET::Dereference()
{   
    SOCKET oSocket = m_oSocket;
    m_oSocket = INVALID_SOCKET;
    return oSocket;
}

///////////////////////////////////////////////////////////////////////
//  WSA extensions

CString
WSA_GetHostName ( )
{
    char szHostName[MAX_PATH];
    if ( gethostname(szHostName,ARRAYSIZE(szHostName)) )
      return _T("Error");
    CString strHostName = szHostName;
    return strHostName;
}
