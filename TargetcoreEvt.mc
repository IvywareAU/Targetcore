;// Copyright © 2026 Ivyware Pty Ltd, Khrustal & Mann
;//              MELBOURNE, VICTORIA, AUSTRALIA, 3000
;//
;// Licensed under the Apache License, Version 2.0 (the "License");
;// you may not use this file except in compliance with the License.
;// You may obtain a copy of the License at
;//
;//     http://www.apache.org/licenses/LICENSE-2.0
;//
;// Unless required by applicable law or agreed to in writing, software
;// distributed under the License is distributed on an "AS IS" BASIS,
;// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
;// implied. See the License for the specific language governing
;// permissions and limitations under the License.
;//
;//
;//  Targetcore Windows event log catalogue
;//  NOTES: Read by the Event Viewer, NOT by this library.  A hub hosted
;//         inside a Windows service has no console and no standard error, so
;//         P2PeerService installs an event log sink (refer P2Pevent::
;//         SetTextSink) and its diagnostics arrive here instead.
;//       : Without a registered EventMessageFile pointing at the module that
;//         carries this table, the Event Viewer renders every entry as "The
;//         description for Event ID ... cannot be found" with the text
;//         demoted to raw insertion data.  P2PeerService::PostInstall()
;//         performs that registration; PostUnInstall() removes it.
;//
;//  REGENERATION.  The generated files are COMMITTED so that neither CMake
;//  nor the .vcxproj needs mc.exe, and so a build never depends on which
;//  Windows SDK happens to be installed.  That trades a build step for the
;//  risk of the committed output drifting from this source, which
;//  tools/check_evt_catalogue.py closes by regenerating and comparing.  To
;//  change the catalogue, edit THIS file and run:
;//
;//    mc.exe -U -n -h . -r . TargetcoreEvt.mc
;//
;//  which writes TargetcoreEvt.h, TargetcoreEvt.rc and MSG00001.bin.  Commit
;//  all four.  -U (UTF-16LE messages) is mc's default and is stated anyway so
;//  the command is reproducible; -n NUL-terminates every string.
;//
;//  MESSAGE IDS ARE THE P2Pevent_e CLASS VALUES.  P2Pevent_ERROR is 1 and
;//  this catalogue's error is 1, WARNING is 2 and so on, up to REPORT at 7.
;//  That is deliberate: the mapping in P2PeerService's sink is then a bounds
;//  check rather than a lookup table that can fall out of step with the enum.
;//  0x9 catches anything outside the range, including P2Pevent_UNDEF and the
;//  P2Pevent_USERn classes, so an unrecognised class still renders its text.
;//
;//  Both insertions are always supplied by the sink: %1 is the origin
;//  ("[service]module(parameters)") and %2 the assembled message body.
;//

MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

FacilityNames=(P2Pmsg=0x1:FACILITY_P2PMSG)

LanguageNames=(English=0x409:MSG00001)

;// -------------------------------------------------------------------------

MessageId=0x1
Severity=Error
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_ERROR
Language=English
%1
%2
.

MessageId=0x2
Severity=Warning
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_WARNING
Language=English
%1
%2
.

MessageId=0x3
Severity=Informational
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_INFO
Language=English
%1
%2
.

MessageId=0x4
Severity=Informational
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_DEBUG
Language=English
%1
%2
.

MessageId=0x5
Severity=Informational
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_TRACE
Language=English
%1
%2
.

MessageId=0x6
Severity=Informational
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_LOG
Language=English
%1
%2
.

MessageId=0x7
Severity=Informational
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_REPORT
Language=English
%1
%2
.

MessageId=0x9
Severity=Warning
Facility=P2Pmsg
SymbolicName=P2PMSG_EVT_UNCLASSED
Language=English
%1
%2
.
