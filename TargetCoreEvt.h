// Copyright © 2026 Ivyware Pty Ltd, Khrustal & Mann
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
//  TargetCore Windows event log catalogue
//  NOTES: Read by the Event Viewer, NOT by this library.  A hub hosted
//         inside a Windows service has no console and no standard error, so
//         P2PeerService installs an event log sink (refer P2Pevent::
//         SetTextSink) and its diagnostics arrive here instead.
//       : Without a registered EventMessageFile pointing at the module that
//         carries this table, the Event Viewer renders every entry as "The
//         description for Event ID ... cannot be found" with the text
//         demoted to raw insertion data.  P2PeerService::PostInstall()
//         performs that registration; PostUnInstall() removes it.
//
//  REGENERATION.  The generated files are COMMITTED so that neither CMake
//  nor the .vcxproj needs mc.exe, and so a build never depends on which
//  Windows SDK happens to be installed.  That trades a build step for the
//  risk of the committed output drifting from this source, which
//  tools/check_evt_catalogue.py closes by regenerating and comparing.  To
//  change the catalogue, edit THIS file and run:
//
//    mc.exe -U -n -h . -r . TargetCoreEvt.mc
//
//  which writes TargetCoreEvt.h, TargetCoreEvt.rc and MSG00001.bin.  Commit
//  all four.  -U (UTF-16LE messages) is mc's default and is stated anyway so
//  the command is reproducible; -n NUL-terminates every string.
//
//  MESSAGE IDS ARE THE P2Pevent_e CLASS VALUES.  P2Pevent_ERROR is 1 and
//  this catalogue's error is 1, WARNING is 2 and so on, up to REPORT at 7.
//  That is deliberate: the mapping in P2PeerService's sink is then a bounds
//  check rather than a lookup table that can fall out of step with the enum.
//  0x9 catches anything outside the range, including P2Pevent_UNDEF and the
//  P2Pevent_USERn classes, so an unrecognised class still renders its text.
//
//  Both insertions are always supplied by the sink: %1 is the origin
//  ("[service]module(parameters)") and %2 the assembled message body.
//
// -------------------------------------------------------------------------
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_P2PMSG                  0x1


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: P2PMSG_EVT_ERROR
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_ERROR                 ((DWORD)0xC0010001L)

//
// MessageId: P2PMSG_EVT_WARNING
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_WARNING               ((DWORD)0x80010002L)

//
// MessageId: P2PMSG_EVT_INFO
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_INFO                  ((DWORD)0x40010003L)

//
// MessageId: P2PMSG_EVT_DEBUG
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_DEBUG                 ((DWORD)0x40010004L)

//
// MessageId: P2PMSG_EVT_TRACE
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_TRACE                 ((DWORD)0x40010005L)

//
// MessageId: P2PMSG_EVT_LOG
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_LOG                   ((DWORD)0x40010006L)

//
// MessageId: P2PMSG_EVT_REPORT
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_REPORT                ((DWORD)0x40010007L)

//
// MessageId: P2PMSG_EVT_UNCLASSED
//
// MessageText:
//
// %1
// %2
//
#define P2PMSG_EVT_UNCLASSED             ((DWORD)0x80010009L)

