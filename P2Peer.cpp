// Copyright © 2002-2007, 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  Description: P2Peer implementation.
//

#include "stdafx.h"
#include "P2Peer.h"
#include "Ws2tcpip.h"

#include <string>            // the per-thread name ring - see P2PaddrNameSlot

//
//  Description:
//
//
//  Parameters:  char *szHostname
//               Name of host whose IP address is to be determined
//
//  Returns:     DWORD
//               IP address
//
/*DWORD
GetHostID ( )
{
   char szLclHost[120];
   LPHOSTENT lpstHostent;
   SOCKADDR_IN stLclAddr;
   SOCKADDR_IN stRmtAddr;
   int nAddrSize = sizeof(SOCKADDR);
   SOCKET hSock;
   int nRet;
   
   // Init local address (to zero) 
   stLclAddr.sin_addr.s_addr = INADDR_ANY;

   // Get the local hostname 
   nRet = gethostname(szLclHost, sizeof(szLclHost));
   if (nRet != SOCKET_ERROR)
      {
      // Resolve hostname for local address 
      lpstHostent = gethostbyname((LPSTR)szLclHost);
      if (lpstHostent)
         stLclAddr.sin_addr.s_addr = *((u_long FAR*)(lpstHostent->h_addr));
      }
   
    // If still not resolved, then try second strategy
    if (stLclAddr.sin_addr.s_addr == INADDR_ANY)
    {
      // Get a UDP socket 
      hSock = socket(AF_INET, SOCK_DGRAM, 0);
      if (hSock != INVALID_SOCKET)
      {
        // Connect to arbitrary port and address (NOT loopback)
        // NOTES: PostVS2015 inet_addr((LPCSTR)csIpAddress) displaced by InetPton(...)
        stRmtAddr.sin_family = AF_INET;
        stRmtAddr.sin_port   = htons(IPPORT_ECHO);
        InetPton(AF_INET, L"128.127.50.1", &stRmtAddr.sin_addr.s_addr);
      //stRmtAddr.sin_addr.s_addr = inet_addr("128.127.50.1");
        nRet = connect(hSock, (LPSOCKADDR)&stRmtAddr,sizeof(SOCKADDR));
        if (nRet != SOCKET_ERROR)
        {
          // Get local address 
          getsockname(hSock, (LPSOCKADDR)&stLclAddr, (int FAR*)&nAddrSize);
        }
        closesocket(hSock);   // we're done with the socket 
      }
    }
    return stLclAddr.sin_addr.s_addr;
}*/

//
//
//  Description: Static function for the retrieval of WSA error
//               descriptions
//               NOTES: WSABASEEER
//
//  Parameters:  HRESULT hr
//               WSA error code.
//
//
//  Returns:     LPCTSTR
//               Error text associated with above code
//                 0.. Text not located
//
//LPCTSTR
//P2PeerWSAEDesc ( HRESULT hr )
//{
//    if ( hr == WSAEINTR )
//      return "Interrupted function call";
//    if ( hr == WSAEBADF )
//      return "WSAEBADF";
//    if ( hr == WSAEACCES )
//      return "Permission denied";
//    if ( hr == WSAEFAULT )
//      return "Bad address";
//    if ( hr == WSAEINVAL )
//      return "Invalid argument";
//    if ( hr == WSAEMFILE )
//      return "Too many open files";
//
//    // Windows Sockets definitions of regular Berkeley
//    // error constants
//    if ( hr == WSAEWOULDBLOCK )
//      return "Resource temporarily unavailable";
//    if ( hr == WSAEINPROGRESS )
//      return "Operation now in progress";
//    if ( hr == WSAEALREADY )
//      return "Operation already in progress";
//    if ( hr == WSAENOTSOCK )
//      return "Socket operation on non-socket";
//    if ( hr == WSAEDESTADDRREQ )
//      return "Destination address required";
//    if ( hr == WSAEMSGSIZE )
//      return "Message too long";
//    if ( hr == WSAEPROTOTYPE )
//      return "Protocol wrong type for socket";
//    if ( hr == WSAENOPROTOOPT )
//      return "Bad protocol option";
//    if ( hr == WSAEPROTONOSUPPORT )
//      return "Protocol not supported";
//    if ( hr == WSAESOCKTNOSUPPORT )
//      return "Socket type not supported";
//    if ( hr == WSAEOPNOTSUPP )
//      return "Operation not supported";
//    if ( hr == WSAEPFNOSUPPORT )
//      return "Protocol family not supported";
//    if ( hr == WSAEAFNOSUPPORT )
//      return "Address family not supported by protocol family";
//    if ( hr == WSAEADDRINUSE )
//      return "Address already in use";
//    if ( hr == WSAEADDRNOTAVAIL )
//      return "Cannot assign requested address";
//    if ( hr == WSAENETDOWN )
//      return "Network is down";
//    if ( hr == WSAENETUNREACH )
//      return "Network is unreachable";
//    if ( hr == WSAENETRESET )
//      return "Network dropped connection on reset";
//    if ( hr == WSAECONNABORTED )
//      return "Software caused connection abort";
//    if ( hr == WSAECONNRESET )
//      return "Connection reset by peer";
//    if ( hr == WSAENOBUFS )
//      return "No buffer space available";
//    if ( hr == WSAEISCONN )
//      return "Socket is already connected";
//    if ( hr == WSAENOTCONN )
//      return "Socket is not connected";
//    if ( hr == WSAESHUTDOWN )
//      return "Cannot send after socket shutdown";
//    if ( hr == WSAETOOMANYREFS )
//      return "WSATOOMANYREFS";
//    if ( hr == WSAETIMEDOUT )
//      return "Connection timed out";
//    if ( hr == WSAECONNREFUSED )
//      return "Connection refused";
//    if ( hr == WSAELOOP )
//      return "WSAELOOP";
//    if ( hr == WSAENAMETOOLONG )
//      return "WSAENAMETOOLONG";
//    if ( hr == WSAEHOSTDOWN )
//      return "Host is down";
//    if ( hr == WSAEHOSTUNREACH )
//      return "No route to host";
//    if ( hr == WSAENOTEMPTY )
//      return "WSAENOTEMPTY";
//    if ( hr == WSAEPROCLIM )
//      return "Too many processes";
//    if ( hr == WSAEUSERS )
//      return "WSAEUSERS";
//    if ( hr == WSAEDQUOT )
//      return "WSAEDQUOT";
//    if ( hr == WSAESTALE )
//      return "WSAESTALE";
//    if ( hr == WSAEREMOTE )
//      return "WSAEREMOTE";
//    if ( hr == WSAEDISCON )
//      return "WSAEDISCON";
//
////  Extended Windows Sockets error constant definitions
//    if ( hr == WSASYSNOTREADY )
//      return "WSASYSNOTREADY";
//    if ( hr == WSAVERNOTSUPPORTED )
//      return "WINSOCK.DLL version out of range";
//    if ( hr == WSANOTINITIALISED )
//      return "Successful WSAStartup not yet performed";
//    if ( hr == WSAEDISCON )
//      return "Graceful shutdown in progress";
//
//    // Whatever
//    if ( hr == WSATYPE_NOT_FOUND )
//      return "Class type not found";
//    if ( hr == WSAHOST_NOT_FOUND )
//      return "Host not found";
//    if ( hr == WSA_INVALID_HANDLE )
//      return "Specified event object handle is invalid";
//    if ( hr == WSA_INVALID_PARAMETER )
//      return "One or more parameters are invalid";
////  if ( hr == WSAINVALIDPROCTABLE )
////    return "Invalid procedure table from service provider";
////  if ( hr == WSAINVALIDPROVIDER )
////    return "Invalid service provider version number";
//    if ( hr == WSA_IO_INCOMPLETE )
//      return "Overlapped I/O event object not in signaled state";
//    if ( hr == WSA_IO_PENDING )
//      return "Overlapped operations will complete later";
//    if ( hr == WSA_NOT_ENOUGH_MEMORY )
//      return "Insufficient memory available";
//    if ( hr == WSANO_DATA )
//      return "Valid name, no data record of requested type";
//    if ( hr == WSANO_RECOVERY )
//      return "This is a non-recoverable error";
////  if ( hr == WSAPROVIDERFAILEDINIT )
////    return "Unable to initialize a service provider";
//    if ( hr == WSASYSCALLFAILURE )
//      return "System call failure";
//    if ( hr == WSASYSNOTREADY )
//      return "Network subsystem is unavailable";
//    if ( hr == WSATRY_AGAIN )
//      return "Non-authoritative host not found";
//    if ( hr == WSA_OPERATION_ABORTED )
//      return "Overlapped operation aborted";
//
//    // Tidy up and
//    return 0;
//}
//
//


///////////////////////////////////////////////////////////////////////
//  P2Paddr implementation
//  NOTES: Support formats of the form
//         VNetname:Hubname.Hubname[i]. . .Hubname etc

//  Constructors and destructors
P2Paddr::P2Paddr ( )
{ }
P2Paddr::P2Paddr ( const P2Paddr& rhs )
{   m_strP2Paddr = rhs.m_strP2Paddr; }
P2Paddr::P2Paddr ( P2PaddrSTR strP2Paddr )
{   m_strP2Paddr = strP2Paddr; }
P2Paddr::P2Paddr ( LPCTADDR strP2PaddrHub
                 , const T_ADDR *pszFormatCon, ... )
{
    va_list       ap;
    T_ADDR       szBuffer[256];
    va_start ( ap, pszFormatCon );
    vswprintf_s ( szBuffer, ARRAYSIZE(szBuffer), pszFormatCon, ap );
    va_end ( ap );
    m_strP2Paddr  = strP2PaddrHub;
    m_strP2Paddr += ".";
    m_strP2Paddr += szBuffer;
}
P2Paddr::~P2Paddr ( )
{ }

//  Operators
P2Paddr&
P2Paddr::operator = ( const P2Paddr& rhs )
{
    Empty();
    m_strP2Paddr = rhs.m_strP2Paddr;
    return *this;
}
P2Paddr&
P2Paddr::operator = ( LPCTADDR strP2Paddr )
{
    Empty();
    m_strP2Paddr = strP2Paddr;
    return *this;
}
P2Paddr::operator LPCTADDR ( ) const
{
    // NB: cast both branches to LPCTADDR so the ?: does NOT materialise a
    // temporary CString (whose buffer would be returned then destroyed).
    // MFC CString is ref-counted so the old form happened to work on Windows;
    // std::wstring (Linux CString shim) is not COW, so it returned a pointer
    // into a freed heap block. Behaviour is identical on Windows.
    return m_strP2Paddr.GetLength()>0 ? (LPCTADDR)m_strP2Paddr : _T("\0");
}
bool
P2Paddr::operator == ( const P2Paddr& rhs ) const
{   
    return m_strP2Paddr == rhs.m_strP2Paddr;
}
bool
P2Paddr::operator == ( P2PaddrSTR rhs ) const
{   
    return m_strP2Paddr == rhs;
}
bool
P2Paddr::operator != ( const P2Paddr& rhs ) const
{
    return m_strP2Paddr != rhs.m_strP2Paddr;
}
bool
P2Paddr::operator != ( P2PaddrSTR rhs ) const
{
    return m_strP2Paddr != rhs;
}

//  Operations
void
P2Paddr::Empty ( )
{
    m_strP2Paddr.Empty();
    m_strVNetname.Empty();
    m_strVNetaddr.Empty();
}

///////////////////////////////////////////////////////////////////////
//  Routing

//  Child address comparison
//  NOTES: An equivalent address is not a child
//       : The prefix must end on a hop boundary, so CEXTRA is not a
//         child of CEX
//
//  Returns:     bool
//                 true... strP2Paddr is a direct child of the
//                         contained address
//                 false.. Not a child
//
bool
P2Paddr::IsChild ( LPCTADDR strP2PaddrChild ) const
{
    size_t lenP2PaddrThis = m_strP2Paddr.GetLength();
    if ( lenP2PaddrThis >= _tcslen(strP2PaddrChild) )
      return false;
    // GetLength() counts T_ADDRs, memcmp() counts bytes
    if ( memcmp(strP2PaddrChild,m_strP2Paddr,lenP2PaddrThis*sizeof(T_ADDR)) )
      return false;
    return strP2PaddrChild[lenP2PaddrThis] == '.';
}
//  Routable address comparison
//  NOTES: Both equivalent and child addresses are routable
//       : CEX.SDrvs.AAD is routable through CEX.SDrvs
//         CEX.XDrvs is routable through CEX
//         CEX.XDrvs is NOT routable through CEX.SDrvs
//         CEX is routable through CEX
//         CEX is not routable through CEX.SDrvs
//         CEX.SDrvsX is NOT routable through CEX.SDrvs
//
//
//  Parameters:  P2PaddrSTR strP2PaddrDestin
//               Destination address to be checked
//  Returns:     bool
//                 true... strP2Paddr is routable through the
//                         contained address
//                 false.. Not a routable address
//
bool
P2Paddr::IsRable ( LPCTADDR strP2PaddrDestin ) const
{
    size_t lenP2PaddrThis = m_strP2Paddr.GetLength();
    if ( lenP2PaddrThis>_tcslen(strP2PaddrDestin) )
      return false;
    // GetLength() counts T_ADDRs, memcmp() counts bytes
    if ( memcmp(strP2PaddrDestin,m_strP2Paddr,lenP2PaddrThis*sizeof(T_ADDR)) )
      return false;
    // Equivalent, or a prefix ending on a hop boundary
    return strP2PaddrDestin[lenP2PaddrThis] == '\0' ||
           strP2PaddrDestin[lenP2PaddrThis] == '.';
}

//  Property exposure

//  P2PaddrNameSlot - where c_name()/c_hopname() put the name they build
//
//  NOTES: Both accessors are const and both hand back a POINTER, so the text
//         has to outlive the call and cannot live on their stack.  They used
//         to build it in the object's own m_strHubname through a const_cast,
//         which is a DATA RACE the moment one P2Paddr is read by two threads:
//         the build clears the string and appends one character at a time, so
//         a concurrent reader sees a half-built name, and CString's reallocation
//         can free the buffer the reader is holding.  That is not hypothetical
//         here - GetP2PmsgHubName() (P2Pwin32.cpp) returns c_name() taken from
//         the process-wide hub record, and every pump thread calls it.  The hub
//         critical section around the write does not help: the pointer is used
//         by the caller after the section is released.
//       : So the scratch is per-THREAD rather than per-object.  A RING rather
//         than one buffer, for the reason Platform/p2pstr.h:637-644 gives about
//         its own: several results are commonly live at once, most obviously as
//         two arguments of one diagnostic (P2PeerTarget.cpp:1481 passes three
//         wide accessors to a single Message()).  Eight slots covers every call
//         site in the tree - the widest passes three - and the lifetime rule is
//         the one the tree already documents for wide accessors: valid until the
//         next few calls ON THIS THREAD.
//       : Strictly better than what it replaces, which held exactly ONE result
//         per object and shared it across all threads.
//       : m_strHubname is gone from the class; nothing else read it.
//       : The slots are std::basic_string, NOT CString, and that is measured
//         rather than stylistic: a thread_local array of CString handed back a
//         DANGLING pointer on the very first case below - the slot written by
//         one call was freed by the next, printing as garbage where "Leaf" had
//         been. MFC's string data carries its own allocator/refcount state, and
//         it does not survive being parked in thread-local storage in a DLL and
//         written from threads MFC did not create. basic_string has no such
//         state, so the ring owns its bytes outright.
static P2PaddrSTR
P2PaddrNameSlot ( const std::basic_string<T_ADDR>& strName )
{
    enum { RING = 8 };
    static thread_local std::basic_string<T_ADDR> s_aRing[RING];
    static thread_local int                       s_nNext = 0;

    std::basic_string<T_ADDR>& strSlot = s_aRing[s_nNext];
    s_nNext = ( s_nNext + 1 ) % RING;
    strSlot = strName;
    return strSlot.c_str();
}

bool
P2Paddr::IsNull ( ) const
{   return m_strP2Paddr.IsEmpty() ? true : false; }
P2PaddrSTR
P2Paddr::c_wstr ( ) const
{   
    return m_strP2Paddr;
}
P2PaddrSTR
P2Paddr::c_name ( ) const
{
    std::basic_string<T_ADDR> strHubname;
    for ( int i = 0; i < m_strP2Paddr.GetLength(); i++ )
    {
      strHubname += m_strP2Paddr[i];
      if ( m_strP2Paddr[i] == '.' )
        strHubname.clear();
    }
    return P2PaddrNameSlot ( strHubname );
}
P2PaddrSTR
P2Paddr::c_hopname ( int nLevel ) const
{
    std::basic_string<T_ADDR> strHubname;
    for ( int i = 0; i < m_strP2Paddr.GetLength(); i++ )
    {
      if ( m_strP2Paddr[i] != '.' )
      {
        strHubname += m_strP2Paddr[i];
        continue;
      }
      if ( nLevel <= 0 )
        break;
      nLevel--;
      strHubname.clear();
    }
    if ( nLevel > 0 )
      strHubname.clear();
    return P2PaddrNameSlot ( strHubname );
}
P2Psize_t
P2Paddr::Sizeof ( ) const
{   
    return (P2Psize_t)m_strP2Paddr.GetLength();
}
BOOL
P2Paddr::IsEmpty ( )
{
    return m_strP2Paddr.IsEmpty();
}

//LPCTSTR
//P2Paddr::GetName ( );
//LPCTSTR
//P2Paddr::GetPath ( );  
//
//  Description: P2PeerCon_MAP name matching utility
//               NOTES: Internal P2Peer path is matched against the
//                      passed P2PeerCon_MAP wildcard
//                    : Example 1 (Backwards connection)
//                        Hub1/Hub2/whatever, matches wildcards
//                           */Hub2/whatever, and
//                                */whatever, and
//
//
//  Parameters:  P2PaddrSTR pszMapWildcard
//               P2PeerHub name wildcard
//
//  Returns:     bool
//                 true... Connection matches wildcard
//                 false.. No match
//
bool
P2Paddr::IsMapped ( P2PaddrSTR strP2Paddr ) const
{
    // Preparation
    const T_ADDR *pszMapWildcard = m_strP2Paddr;
    bool  star   = false;
    const T_ADDR *pszHub = strP2Paddr;

    // Implmentation
Top:
    const T_ADDR *p, *s;
    for ( s = pszHub, p = pszMapWildcard; *s; ++s, ++p )
    {
      switch (*p) {
         case '?':
            if (*s == '.') goto starCheck;
            break;
         case '*':
            star = TRUE;
            pszHub = s, pszMapWildcard = p;
            if (!*++pszMapWildcard) return TRUE;
            goto Top;
         case '#':
            if ( !isdigit(*s) )
              goto starCheck;
            while ( isdigit(*(s+1)) )
              s++;
            break;
         default:
            //if (mapCaseTable[*s] != mapCaseTable[*p])
            if (*s != *p )
               goto starCheck;
            break;
      } /* endswitch */
   } /* endfor */
   if (*p == '*') ++p;
   return (!*p);

starCheck:
   if (!star) return FALSE;
   pszHub++;
   goto Top;
}

///////////////////////////////////////////////////////////////////////
//  P2Padomain implementation
//  NOTES: Supports Virtual P2Peer Network addresses of the form
//         [VNetname:]RootHubname.Hubname[i]. . .Hubname etc

//  Constructors and destructor
P2Padomain::P2Padomain ( )
{
    // NB: m_bWildcard / m_oPos have no in-class initialiser; leaving them
    // uninitialised is UB. On the Windows debug heap the 0xCD fill made
    // m_bWildcard read true (IsMapped() short-circuits to permissive); on
    // Linux it reads 0 and the domain check fails non-deterministically.
    m_bWildcard = false;
    m_oPos      = 0;
}

P2Padomain::P2Padomain ( LPCTADDR strP2PaddrDomainTP )
{
    m_oPos      = 0;
    m_strDomain = strP2PaddrDomainTP;
    RebuildDomains ( );
}

//  (Re)tokenise m_strDomain into the m_oCListDomains match list and recompute
//  the wildcard flag. Mirrors the string ctor. Both operator='s call this — the
//  old operator='s set only m_strDomain, leaving m_oCListDomains empty and
//  m_bWildcard stale, so IsMapped() over an *assigned* domain silently relied on
//  the uninitialised wildcard (worked on Windows debug via 0xCD, not on Linux).
void
P2Padomain::RebuildDomains ( )
{
    // Discard any previous match list
    while ( !m_oCListDomains.IsEmpty() )
      delete m_oCListDomains.RemoveHead();

    // Retokenise
    m_bWildcard = false;
    int nToken = 0;
    CStringADDR strDomain = m_strDomain.Tokenize ( L"|", nToken );
    while ( !strDomain.IsEmpty() )
    {
      if ( strDomain == ("*") )
        m_bWildcard = true;
      m_oCListDomains.AddTail ( new CStringADDR(strDomain) );
      strDomain = m_strDomain.Tokenize( L"|", nToken );
    }
}

P2Padomain::~P2Padomain ( )
{
    // Garbage collection
    while ( !m_oCListDomains.IsEmpty() )
      delete m_oCListDomains.RemoveHead();
}

//  Operators
P2Padomain&
P2Padomain::operator = ( const P2Padomain& rhs )
{
	m_strDomain = rhs.m_strDomain;
	RebuildDomains ( );
	return *this;
}
P2Padomain&
P2Padomain::operator = ( P2PadomSTR rhs )
{
	m_strDomain = rhs;
	RebuildDomains ( );
    return *this;
}
P2Padomain::operator P2PadomSTR ( ) const
{   
	return m_strDomain;
}

//
//  Maps strP2Paddr against the encapsulated domain
//
//
//  Parameters:  P2PaddrSTR strP2Paddr
//               Address to be mapped against domain
//
//  Returns:     bool
//               Mapping result
//                 true... Mapped within domain
//                 false.. Not within domain
bool
P2Padomain::IsMapped ( P2PaddrSTR strP2Paddr ) const
{
    // Optimisation
    if ( m_bWildcard )
      return true;

    // Domains
    // NOTES: Multiple ";" delimitered domains may have been
    //        specified
    POSITION pos = m_oCListDomains.GetHeadPosition ( );
    while ( pos )
    {
      CStringADDR *pDomain = m_oCListDomains.GetNext ( pos );
      if ( (*pDomain) == strP2Paddr )
        return true;

      // Itemize LHS domain into individual P2Paddr's
      long    nStateLHS = 0;
      P2Paddr oP2PaddrLHS;
      while ( GetNextP2Paddr(*pDomain,oP2PaddrLHS,nStateLHS) )
      {
        // Itemize RHS domain into individual P2Paddr's
        if ( oP2PaddrLHS.IsMapped(strP2Paddr) )
          return true;
      }
    }

    // Mapping failed
    return false;
}

int
GetNextItem ( LPCTADDR lpszDomain, long& nState, int nSet, CStringADDR& csSetItem )
{
    // Locals
    UCHAR   *pucSets = reinterpret_cast<UCHAR *>(&nState);
    int nSetItem;

    // Initialise
TOP:nSetItem = 0;

    // Each domain character
	int n;
    for ( n = 1; lpszDomain[n]; n++ )
    {
      // Domain set, recursive
      if ( lpszDomain[n] == '<' )
      {
        CStringADDR csSetRecurs;
        int      nSetRecurs = nSet + 1;
        n += GetNextItem ( &lpszDomain[n], nState, nSetRecurs, csSetRecurs );
        if ( pucSets[nSetRecurs] != 255 )
        {
          nSet++;
          csSetItem += csSetItem;
          continue;
        }
        if ( nSetRecurs == 0 )
          return false;
        memset (&pucSets[nSetRecurs], 0, sizeof(nState)-nSetRecurs );
                 pucSets[nSetRecurs-1]++;
        goto TOP;
      }

      // Set delimiter
      else if ( lpszDomain[n] == ',' )
      {
        nSetItem++;
      }

      // End of set
      else if ( lpszDomain[n] == '>' )
      {
        if ( nSetItem < pucSets[nSet] )
          pucSets[nSet] = 255;
        else
          pucSets[nSet]++;
        break;
      }
      
      // Address component
      else
      {
        if ( pucSets[nSet] == nSetItem )
          csSetItem += lpszDomain[n];
      }
    }

    // Tidy up, and
    return n;
}
bool
P2Padomain::GetNextP2Paddr ( LPCTADDR strDomain
                           , P2Paddr& oP2Paddr, long& nState ) const
{
    CStringADDR csWork;
    UCHAR   *pucSets = reinterpret_cast<UCHAR *>(&nState);
    int      nSet    = 0;

    // Initialise
    if ( pucSets[0] == 255 )
      return false;
TOP:csWork.Empty ( );
    nSet = 0;

    // Synchronise
    for ( int n = 0; strDomain[n]; n++ )
    {
      // Domain set
      if ( strDomain[n] == '<' )
      {
        CStringADDR csSetItem;
        n += GetNextItem ( &strDomain[n], nState, nSet, csSetItem );
        if ( pucSets[nSet] != 255 )
        {
          nSet++;
          csWork += csSetItem;
          continue;
        }
        if ( nSet == 0 )
          return false;
        memset (&pucSets[nSet], 0, sizeof(nState)-nSet );
                 pucSets[nSet-1]++;
        goto TOP;
      }

      // Illegals
      else if ( strDomain[n] == ',' ||
                strDomain[n] == '>'    )
      {
        ASSERT(0);
        return false;
      }

      // Address
      else
        csWork += strDomain[n];
    }

    // Tidy up, and
    // NOTES: Provide single shot monitoring
    if ( pucSets[0] == 0 )
      pucSets[0] = 255;
    oP2Paddr = csWork;
    return csWork.IsEmpty() ? false : true;
}

//  Property exposure
bool
P2Padomain::IsNull ( ) const
{   return m_strDomain.IsEmpty() ? true : false; }
LPCTADDR
P2Padomain::c_wstr ( ) const
{   return m_strDomain; }
P2Psize_t
P2Padomain::Sizeof ( ) const
{   return (P2Psize_t)m_strDomain.GetLength(); }

///////////////////////////////////////////////////////////////////////
//  P2Parser

//  Constructors and destructor
/*P2Parser::P2Parser ()
{   RenderThisSafe(); }

P2Parser::P2Parser ( char *pCommand )
{   RenderThisSafe();
    m_pCommand    = pCommand;
    m_pCompleted  = pCommand;
    m_pCheckpoint = pCommand; }
P2Parser::~P2Parser ()
{   delete m_pP2ParserPrev;
    m_pP2ParserPrev = 0; }
void
P2Parser::RenderThisSafe ( )
{   m_nLevel      =  0;
    m_bSkip       = false;
    m_bOptional   = false;
    m_eFCF;
    m_nEnumItem   = -1;
    m_eSeqNum     = -1;
    m_pCommand    =  0;
    m_pCompleted  =  0;
    m_pCheckpoint =  0;
    m_pP2ParserPrev =  0; }

//  Stack management
P2Parser*
P2Parser::Push ( char *pCheckpoint, char *pCompleted, char *pCommand )
{   P2Parser *pP2Parser = new P2Parser ( );
    pP2Parser -> m_pP2ParserPrev = this;

    // Attribute transfer
    pP2Parser -> m_nLevel      = m_nLevel + 1;
    pP2Parser -> m_bSkip       = m_bSkip;
    pP2Parser -> m_bOptional   = m_bOptional;
    pP2Parser -> m_eFCF        = m_eFCF;
    pP2Parser -> m_nEnumItem   = -1;
    pP2Parser -> m_eSeqNum     = m_eSeqNum;
    pP2Parser -> m_pCommand    = m_pCommand;
    pP2Parser -> m_pCompleted  = m_pCompleted;
    pP2Parser -> m_pCheckpoint = m_pCheckpoint;


    // Initialise new level
    if ( pCheckpoint )
      pP2Parser -> m_pCheckpoint = pCheckpoint;
    if ( pCompleted )
      pP2Parser -> m_pCompleted  = pCompleted;
    if ( pCommand )
      pP2Parser -> m_pCommand    = pCommand;

    // Tidy up and
    return pP2Parser;
}

P2Parser*
P2Parser::Pop ( char *pCheckpoint, char *pCompleted, char *pCommand )
{
    // Introduce locals
    P2Parser   *pP2ParserPrev = m_pP2ParserPrev;
    m_pP2ParserPrev         = 0;
    
    // Manage command decode position on previous level
    if ( pCheckpoint )
      pP2ParserPrev -> m_pCheckpoint = pCheckpoint;
    if ( pCompleted )
      pP2ParserPrev -> m_pCompleted  = pCompleted;
    if ( pCommand )
      pP2ParserPrev -> m_pCommand    = pCommand;
    // Tidy up and
    delete this;
    return pP2ParserPrev;
}

//  Operations
bool
P2Parser::GetINT ( int& iValue )
{
    char *pCommand = m_pCommand;
    iValue = strtol ( m_pCommand, &m_pCommand, 10 );
    return (m_pCommand==pCommand)?false:true;
}*/