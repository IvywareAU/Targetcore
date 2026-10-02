// Copyright © 2026 Khrustal & Mann
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
// P2PeerAppFields.hpp
//
// A message's APPLICATION fields, for a direct-API client -- the same fields a
// TargetFacade client sets with IP2PMessage::SetField and reads with
// p2pf::Message::field, so the two read each other's:
//
//     P2PeerMsg32 *pMsg = new P2PeerMsg32 ( src, dst, L"telemetry", pv, cb );
//     AppField ( *pMsg, L"device" ) = L"sensor-04";
//
//     MsgViewOf<Telemetry> msg ( AppFields ( *pMsg ) );    // MsgFieldRef.hpp
//     msg->uptime = 86400;
//
// NEVER THE ROOT. The message root holds the routing envelope -- the Src/Dst
// address item, Tag, Att, Sld, Scp -- and a view that could write `Dst` would
// rewrite routing and break the relay attestation digest. Every name here is
// resolved under one sub-item, so the envelope is unreachable by construction,
// not by a list of forbidden names that the next envelope field would be
// missing from.
//
// WHERE, AND IN WHAT SHAPE. Both are TargetFacade's (src/FacadeHub.cpp,
// kFieldsItem and kNamesItem, ABI 8), copied rather than invented:
//
//   * the fields are the children of the root item "P2PF$Fields";
//   * each value is a blob -- MsgFieldCoding::Bytes, whose table is in
//     MsgFieldRef.hpp -- because the facade reads a field with c_vBlob() and
//     that refuses every scalar tag. A typed INT32 written here would be an
//     absent field (P2PF_E_NO_FIELD) to every facade receiver;
//   * the names, in insertion order, are kept in the root item "P2PF$Names",
//     tab-separated UTF-16 with a terminator. The field item has no child
//     count and no cursor a receiver can walk, so without the index a facade
//     receiver could look a field up by name and could never list them;
//   * the facade's limits: at most 64 fields, a name of 1..63 characters not
//     starting "P2PF", a value of at most 8192 bytes. A write past one throws
//     here rather than producing a message the far end would refuse.
//
// If FacadeHub.cpp's names or limits ever change, these must change with them;
// the facade's own source carries no reference back, so this note is the
// whole of the link.
//
// HEADER-ONLY: no export, no change to P2PeerMsg's layout.

#pragma once

#include "P2PeerMsg.h"
#include "MsgFieldRef.hpp"

#include <cwchar>
#include <string>
#include <vector>

namespace P2PeerAppFieldsDetail {

const wchar_t  kFieldsItem[] = L"P2PF$Fields";      // FacadeHub.cpp kFieldsItem
const wchar_t  kNamesItem [] = L"P2PF$Names";       // FacadeHub.cpp kNamesItem
const wchar_t  kReserved  [] = L"P2PF";             // FacadeMessage.cpp IsReservedField
const size_t   kMaxFields    = 64;                  // p2pf::MAX_FIELDS
const size_t   kMaxName      = 63;                  // p2pf::MAX_FIELD_NAME
const size_t   kMaxSize      = 8192;                // p2pf::MAX_FIELD_SIZE

[[noreturn]] inline void Refuse ( LPCWSTR lpszFormat, LPCWSTR lpszName )
{
    EVERR -> Module ( L"AppFields" )
          -> Message ( lpszFormat, lpszName ? lpszName : L"" )
          -> Throw ( );
    for ( ;; ) { }
}

inline P3PmsgItem& Root ( void *pvCtx )
{
    return static_cast<P2PeerMsg*>(pvCtx)->r_item ( VBLockBSTR_ROOT );
}

// The root item is the BSTR's own member, so `root` holds still. What its
// SelectItem hands back does not -- it is the root's CURSOR item -- which is
// exactly why a ref re-resolves rather than keeping this.
inline P3PmsgItem* Resolve ( void *pvCtx, bool bCreate )
{
    P3PmsgItem& root = Root ( pvCtx );
    if ( !root.Exists ( kFieldsItem ) )
    {
      if ( !bCreate )
        return nullptr;
      root.DeclareItem ( kFieldsItem, P3PmsgData() );
    }
    return &root.SelectItem ( kFieldsItem );
}

inline std::vector<std::wstring> ReadNames ( P3PmsgItem& root )
{
    std::vector<std::wstring> out;
    if ( !root.Exists ( kNamesItem ) )
      return out;
    P3PmsgData& d = root.SelectItem ( kNamesItem ).r_data();
    if ( !MsgFieldDetail::IsBlobTag ( d.DataType() ) )
      return out;
    std::vector<unsigned char> b ( d.c_size() );
    if ( b.size() < sizeof(P2PWCHAR) )
      return out;
    b.resize ( d.c_vBlobCopy ( &b[0], b.size() ) );
    // To the terminator, never past it -- the facade's FieldNames does the same.
    size_t nUnits = b.size() / sizeof(P2PWCHAR), nLen = 0;
    for ( ; nLen < nUnits; ++nLen )
    {
      P2PWCHAR u; std::memcpy ( &u, &b[nLen * sizeof(P2PWCHAR)], sizeof u );
      if ( !u ) break;
    }
    std::wstring all = MsgFieldDetail::UnitsToText ( &b[0], nLen );
    size_t nPos = 0;
    while ( nPos <= all.size() )
    {
      size_t nTab = all.find ( L'\t', nPos );
      if ( nTab == std::wstring::npos ) nTab = all.size();
      if ( nTab > nPos ) out.push_back ( all.substr ( nPos, nTab - nPos ) );
      nPos = nTab + 1;
    }
    return out;
}

inline void WriteNames ( P3PmsgItem& root, const std::vector<std::wstring>& names )
{
    std::wstring all;
    for ( size_t i = 0; i < names.size(); ++i )
    {
      if ( i ) all += L'\t';
      all += names[i];
    }
    std::vector<unsigned char> units = MsgFieldDetail::TextToUnits ( all );
    root.DeclareItem ( kNamesItem
                     , P3PmsgData ( (const void*)&units[0], (VBLsize)units.size()
                                  , VBLockData_BLOB16 )
                     , TRUE );
}

inline bool Listed ( const std::vector<std::wstring>& names, LPCWSTR lpszName )
{
    for ( size_t i = 0; i < names.size(); ++i )
      if ( names[i] == lpszName )
        return true;
    return false;
}

inline void Admit ( void *pvCtx, LPCWSTR lpszName, size_t cbValue, bool bLeaf )
{
    if ( !lpszName || !*lpszName )
      Refuse ( L"An application field needs a name%ls", L"" );
    if ( std::wcsncmp ( lpszName, kReserved, 4 ) == 0 )
      Refuse ( L"Field [%ls]: the P2PF prefix is reserved for the facade's own bookkeeping", lpszName );
    if ( std::wcslen ( lpszName ) > kMaxName )
      Refuse ( L"Field [%ls]: a name is at most 63 characters", lpszName );
    if ( !bLeaf )
      return;
    if ( cbValue > kMaxSize )
      Refuse ( L"Field [%ls]: a value is at most 8192 bytes", lpszName );
    std::vector<std::wstring> names = ReadNames ( Root ( pvCtx ) );
    if ( !Listed ( names, lpszName ) && names.size() >= kMaxFields )
      Refuse ( L"Field [%ls]: a message carries at most 64 fields", lpszName );
}

// Insertion order is what IP2PHub::GetFieldName promises, so a rewrite of a
// field already listed leaves the index alone -- as FacadeMessage::SetField
// keeps a replaced field in its original position.
inline void Index ( void *pvCtx, LPCWSTR lpszName, bool bAdded )
{
    P3PmsgItem& root = Root ( pvCtx );
    std::vector<std::wstring> names = ReadNames ( root );
    if ( bAdded )
    {
      if ( Listed ( names, lpszName ) )
        return;
      names.push_back ( lpszName );
    }
    else
    {
      std::vector<std::wstring> keep;
      for ( size_t i = 0; i < names.size(); ++i )
        if ( names[i] != lpszName )
          keep.push_back ( names[i] );
      if ( keep.size() == names.size() )
        return;
      names.swap ( keep );
    }
    WriteNames ( root, names );
}

} // namespace P2PeerAppFieldsDetail

// The anchor every app-field ref and view is built on. Holds &msg, unowned:
// the message must outlive what is made from it -- and a message handed to
// PostP2PeerMsg is no longer the caller's, so finish the fields first.
inline MsgFieldAnchor AppFields ( P2PeerMsg& msg )
{
    MsgFieldAnchor a;
    a.pfnResolve = &P2PeerAppFieldsDetail::Resolve;
    a.pvCtx      = &msg;
    a.eCoding    = MsgFieldCoding::Bytes;
    a.pfnAdmit   = &P2PeerAppFieldsDetail::Admit;
    a.pfnIndex   = &P2PeerAppFieldsDetail::Index;
    return a;
}

inline MsgFieldRef AppField ( P2PeerMsg& msg, LPCWSTR lpszName )
{
    return MsgFieldRef ( AppFields ( msg ), lpszName );
}

// Does this message carry an application-field item at all? (What the
// facade reports as P2PF_MSG_FIELDS.)
inline bool HasAppFields ( P2PeerMsg& msg )
{
    return msg.r_item ( VBLockBSTR_ROOT ).Exists ( P2PeerAppFieldsDetail::kFieldsItem );
}

// The field names, in the order they were first set.
inline std::vector<std::wstring> AppFieldNames ( P2PeerMsg& msg )
{
    return P2PeerAppFieldsDetail::ReadNames ( msg.r_item ( VBLockBSTR_ROOT ) );
}
