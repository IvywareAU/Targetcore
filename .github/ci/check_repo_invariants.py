# Copyright © 2026 Khrustal & Mann
#              MELBOURNE, VICTORIA, AUSTRALIA, 3000
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# ---------------------------------------------------------------------------
# check_repo_invariants.py -- the checks this repository can make about ITSELF,
# with no sibling checkout, no compiler and no CMake.
#
# WHAT THIS PROVES
#   1. The legal/release files a public repo is expected to carry are present.
#   2. Every relative link in the shipped Markdown resolves to a file that
#      exists -- a README that points at a deleted document is the exact defect
#      class Ahtung_Disaster.md Part 1 is about, only cheaper to catch.
#   3. THE TWO BUILD SYSTEMS DESCRIBE THE SAME LIBRARY. TargetCore is built by
#      TargetCore(2022).vcxproj (authoritative on Windows) AND by CMakeLists.txt
#      (authoritative on Linux, parity path on Windows). Nothing else in the
#      tree compares them, so a .cpp added to one and not the other silently
#      ships in one shape and not the other. MscsUnitTests/CMakeLists.txt:23-25
#      records the same failure mode costing 14 days on a test suite.
#   4. The deleted legacy crypto (DHKeyXChanger / Rijndael, Ahtung_Disaster.md
#      Part 1 and Part 5 Track A item 5) has not come back as a build input.
#   5. The event log catalogue's committed output still regenerates byte for
#      byte from its .mc source.
#   6. THE COVERED ABI SURFACE MATCHES ITS MANIFEST. The versioning policy
#      names abi-flat.manifest as the enumeration of the one surface this
#      project promises anything about; this is what compares the two. The
#      other half -- manifest against the symbols a BUILT library exports --
#      is ctest's p2p_abisurface, because it needs a compiler and this file
#      does not.
#   7. The wire format versions are the ones the manifest records. Each
#      format versions on its own byte, independently of the component
#      version, so no release number reveals that one moved; a one-character
#      edit to kVersion stops interoperation with every deployed peer and
#      this is the only thing that would say so.
#
# WHAT THIS DOES NOT PROVE
#   Nothing here compiles, links, or runs anything. A source file can be listed
#   by both build systems, exist on disk, and still not compile. This checks
#   BOOKKEEPING, and says nothing whatsoever about correctness.
# ---------------------------------------------------------------------------

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

VCXPROJ = ROOT / "TargetCore(2022).vcxproj"
CMAKE = ROOT / "CMakeLists.txt"

# stdafx.cpp is the classic /Yc precompiled-header TU. The vcxproj compiles it;
# the CMake build deliberately does not (it lets each TU include stdafx.h with
# no target-wide PCH, so the clean Linux-only p2piocp.cpp is not polluted).
# CMakeLists.txt:83-84 and :131-132 state exactly this. It is the ONE file
# allowed to be in the vcxproj and not in CMake.
DOCUMENTED_VCXPROJ_ONLY = {"stdafx.cpp"}

# Sources CMake reaches outside this repository. This is the sibling coupling
# Readme.md "The sibling dependencies" documents (binding 4); the check below
# pins the count so a NEW cross-repo source cannot appear without a reviewer
# noticing that the standalone-build story got worse.
#
# The path moved on 2026-09-03 and the count did not: the Platform repository was
# retired and its tree vendored into Msgcore, so the io_uring shim is now reached
# at ../Msgcore/Platform/p2piocp.cpp. One sibling source, one sibling repository --
# it is the SAME coupling, spelled through the repository that owns it now.
EXPECTED_SIBLING_SOURCES = {"../Msgcore/Platform/p2piocp.cpp"}

REQUIRED_FILES = [
    "LICENSE",       # Apache-2.0, referenced from Readme.md "License"
    "NOTICE",        # third-party + non-Apache files, referenced from Readme.md
    "Readme.md",
    "SECURITY.md",   # private disclosure channel (Ahtung Part 5 Track A item 4)
]

# Identifiers of the deleted legacy crypto. These may still appear in COMMENTS
# and in the .md post-mortems -- that is deliberate, so nobody re-adopts them
# (CMakeLists.txt:27-30 explains the deletion in a comment, and must keep
# passing this check). What must never happen is one of them becoming a BUILD
# INPUT again, so comments are stripped before the search.
LEGACY_TOKENS = ["DHKeyXChanger", "DHPKeyXChanger", "CRijndael", "Rijndael"]
BUILD_INPUT_FILES = ["TargetCore(2022).vcxproj",
                     "TargetCore(2022).vcxproj.filters",
                     "CMakeLists.txt"]

failures: list[str] = []
notes: list[str] = []


def fail(check: str, message: str) -> None:
    failures.append(f"{check}: {message}")
    print(f"  FAIL  {message}")


def ok(message: str) -> None:
    print(f"  ok    {message}")


def read(path: Path) -> str:
    # The Visual Studio project files are UTF-8 with a BOM.
    return path.read_text(encoding="utf-8-sig")


# ---------------------------------------------------------------------------
# 1. Release-engineering / legal files
# ---------------------------------------------------------------------------
def check_required_files() -> None:
    print("[1] release files")
    for name in REQUIRED_FILES:
        if (ROOT / name).is_file():
            ok(f"{name} present")
        else:
            fail("required-files", f"{name} is missing")

    # NOT a failure. Whether this repo wants a CONTRIBUTING.md is a maintainer
    # decision, not an invariant -- the contribution policy currently lives in
    # the Readme.md tail ("Contributing -- we need your help"), which is a
    # legitimate choice. Recorded so the state is visible in the log rather
    # than silently assumed either way.
    if not (ROOT / "CONTRIBUTING.md").is_file():
        notes.append("CONTRIBUTING.md absent; contribution policy is in Readme.md "
                     "(Ahtung_Disaster.md Part 4 lists this as open)")
        print("  note  CONTRIBUTING.md absent (policy lives in Readme.md)")


# ---------------------------------------------------------------------------
# 2. Relative Markdown links resolve
# ---------------------------------------------------------------------------
LINK_RE = re.compile(r"\[[^\]]*\]\(\s*(<[^>]*>|[^()\s]*(?:\([^()]*\)[^()\s]*)*)\s*\)")


def check_markdown_links() -> None:
    print("[2] markdown links resolve to files that exist")
    checked = 0
    for md in sorted(ROOT.glob("*.md")):
        text = read(md)
        for raw in LINK_RE.findall(text):
            target = raw.strip()
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            target = target.split("#", 1)[0].strip()
            if not target:
                continue                                   # pure anchor
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue                                   # http:, mailto:, ...
            if target.startswith("../") or target.startswith("/"):
                continue                                   # GitHub repo-relative (../../issues)
            checked += 1
            if not (md.parent / target).exists():
                fail("md-links", f"{md.name} links to '{target}', which does not exist")
    ok(f"{checked} relative links checked")


# ---------------------------------------------------------------------------
# 3. vcxproj <-> CMakeLists <-> disk source parity
# ---------------------------------------------------------------------------
def cmake_set_block(text: str, name: str, start_at: int = 0) -> tuple[str, int]:
    """Return the body of `set(<name> ... )` and the index just past it.

    The name is matched to a word boundary on purpose: `set(TARGETCORE_SOURCES`
    must not match `set(TARGETCORE_SOURCES_COMMON`.
    """
    m = re.compile(r"\bset\(" + re.escape(name) + r"(?=[\s)])").search(text, start_at)
    if m is None:
        raise LookupError(f"set({name} ...) not found in CMakeLists.txt")
    i = m.start()
    depth = 0
    j = text.index("(", i)
    for k in range(j, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return text[j + 1:k], k + 1
    raise LookupError(f"unbalanced parentheses in set({name} ...)")


CPP_TOKEN_RE = re.compile(r"[^\s()]+\.cpp")


def cmake_sources(body: str) -> set[str]:
    out = set()
    for line in body.splitlines():
        line = line.split("#", 1)[0]
        for tok in CPP_TOKEN_RE.findall(line):
            tok = tok.replace("${CMAKE_CURRENT_SOURCE_DIR}/", "")
            out.add(tok)
    return out


def check_source_parity() -> None:
    print("[3] vcxproj / CMakeLists / disk source parity")
    vcx = read(VCXPROJ)
    vcx_sources = set(re.findall(r'<ClCompile\s+Include="([^"]+\.cpp)"', vcx))
    if not vcx_sources:
        fail("parity", "no <ClCompile Include=...> entries found -- parser is broken, "
                       "not the project")
        return

    cm = read(CMAKE)
    common, _ = cmake_set_block(cm, "TARGETCORE_SOURCES_COMMON")
    win_body, past = cmake_set_block(cm, "TARGETCORE_SOURCES")
    lin_body, _ = cmake_set_block(cm, "TARGETCORE_SOURCES", past)

    common_s = cmake_sources(common)
    win_s = common_s | cmake_sources(win_body)
    lin_s = common_s | cmake_sources(lin_body)

    sibling = {s for s in (win_s | lin_s) if "/" in s}
    win_s -= sibling
    lin_s -= sibling

    # 3a. Everything either build system names must exist where it says.
    for name in sorted(win_s | lin_s | vcx_sources):
        if not (ROOT / name).is_file():
            fail("parity", f"a build system lists '{name}', which is not in this repo")

    # 3b. The Windows CMake set and the vcxproj set must agree, modulo the one
    #     documented exclusion. This is the check with teeth.
    only_vcx = vcx_sources - win_s - DOCUMENTED_VCXPROJ_ONLY
    only_cmake = win_s - vcx_sources
    for name in sorted(only_vcx):
        fail("parity", f"'{name}' is compiled by TargetCore(2022).vcxproj but NOT by the "
                       f"Windows CMake build -- the two builds produce different libraries")
    for name in sorted(only_cmake):
        fail("parity", f"'{name}' is compiled by the Windows CMake build but NOT by "
                       f"TargetCore(2022).vcxproj -- the two builds produce different libraries")
    missing_documented = DOCUMENTED_VCXPROJ_ONLY - vcx_sources
    for name in sorted(missing_documented):
        fail("parity", f"'{name}' is recorded here as a documented vcxproj-only source, "
                       f"but the vcxproj no longer compiles it -- update this script")
    if not only_vcx and not only_cmake and not missing_documented:
        ok(f"vcxproj ({len(vcx_sources)}) == CMake/WIN32 ({len(win_s)}) + "
           f"{sorted(DOCUMENTED_VCXPROJ_ONLY)}")

    # 3c. No .cpp may sit in the repo unclaimed by any build system. An orphan
    #     TU reads as live code and is not.
    on_disk = {p.name for p in ROOT.glob("*.cpp")}
    claimed = win_s | lin_s | DOCUMENTED_VCXPROJ_ONLY | vcx_sources
    for name in sorted(on_disk - claimed):
        fail("parity", f"'{name}' is in the repository but no build system compiles it")
    if not (on_disk - claimed):
        ok(f"all {len(on_disk)} .cpp files on disk are claimed by a build system "
           f"({len(lin_s - win_s)} Linux-only, {len(win_s - lin_s)} Windows-only)")

    # 3d. The cross-repo source list is pinned.
    if sibling != EXPECTED_SIBLING_SOURCES:
        fail("parity",
             f"the set of sources compiled from OUTSIDE this repository changed: "
             f"expected {sorted(EXPECTED_SIBLING_SOURCES)}, found {sorted(sibling)}. "
             f"This is the standalone-build contract in Readme.md 'The sibling "
             f"dependencies' -- update that section with the change.")
    else:
        ok(f"cross-repo sources unchanged: {sorted(sibling)}")


# ---------------------------------------------------------------------------
# 4. The deleted legacy crypto has not returned as a build input
# ---------------------------------------------------------------------------
def check_legacy_crypto_stays_deleted() -> None:
    print("[4] deleted legacy crypto stays deleted")
    for stem in ("DHKeyXChanger", "Rijndael"):
        for suffix in (".cpp", ".h"):
            if (ROOT / f"{stem}{suffix}").exists():
                fail("legacy-crypto", f"{stem}{suffix} is back in the tree; it was deleted "
                                      f"for cause (see SECURITY.md and Ahtung_Disaster.md)")
    for name in BUILD_INPUT_FILES:
        path = ROOT / name
        if not path.is_file():
            continue
        text = read(path)
        if name.endswith(".txt"):                       # CMake: strip # comments
            text = "\n".join(l.split("#", 1)[0] for l in text.splitlines())
        else:                                           # MSBuild XML: strip <!-- -->
            text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
        for token in LEGACY_TOKENS:
            if token in text:
                fail("legacy-crypto", f"{name} references '{token}' -- the legacy crypto "
                                      f"must not be a build input again")
    # #include is the other way it could come back into a live TU.
    for src in sorted(list(ROOT.glob("*.cpp")) + list(ROOT.glob("*.h"))):
        for line in read(src).splitlines():
            if line.lstrip().startswith("#") and "include" in line:
                for token in LEGACY_TOKENS:
                    if token in line:
                        fail("legacy-crypto", f"{src.name} #includes '{token}'")
    ok("no DHKeyXChanger/Rijndael source, build entry or #include")


# ---------------------------------------------------------------------------
# 5. The event log catalogue, and its committed generated output
# ---------------------------------------------------------------------------
# TargetCoreEvt.mc is compiled by mc.exe into a header, a resource script and a
# binary message table, and all three are COMMITTED so that neither build
# system needs mc.exe and a build never depends on which Windows SDK happens to
# be installed. That is a deliberate trade, and the thing it trades away is the
# guarantee that the committed output still corresponds to its source. This
# check buys that back.
#
# Two tiers, because the interesting one cannot always run:
#   STRUCTURAL, always -- every artifact present, the generated script actually
#     included by TargetCore.rc, and every symbolic value in the committed
#     header equal to the value implied by the .mc's own MessageId/Severity/
#     Facility declarations. That last one is the real content: it is what
#     catches a MessageId edited in the .mc and not regenerated, which is the
#     drift that would otherwise log under the wrong event id.
#   BYTE-EXACT, when mc.exe can be found -- regenerate into a temporary
#     directory and compare all three files byte for byte.
#
# Skipping the second tier is reported as a NOTE, never as a pass: this check
# runs on a Linux runner where no message compiler exists, and "ok" there would
# be a claim nobody verified.
EVT_MC = "TargetCoreEvt.mc"
EVT_GENERATED = ["TargetCoreEvt.h", "TargetCoreEvt.rc", "MSG00001.bin"]
EVT_SEVERITY_BITS = {"Success": 0x0, "Informational": 0x1,
                     "Warning": 0x2, "Error": 0x3}


def find_message_compiler() -> Path | None:
    # Newest SDK first, so a regeneration matches what a current toolchain
    # produces rather than whichever ancient kit sorts first.
    for root in [Path(r"C:\Program Files (x86)\Windows Kits\10\bin"),
                 Path(r"C:\Program Files\Windows Kits\10\bin")]:
        if not root.is_dir():
            continue
        found = sorted(root.glob("*/x64/mc.exe"), reverse=True)
        if found:
            return found[0]
    return None


def parse_mc_catalogue(text: str) -> tuple[dict[str, int], dict[str, int]]:
    """Returns (facility name -> value, symbolic name -> expected DWORD)."""
    facilities: dict[str, int] = {}
    for name, value in re.findall(r"(\w+)\s*=\s*(0x[0-9A-Fa-f]+)\s*:\s*FACILITY_\w+",
                                  text):
        facilities[name] = int(value, 16)

    expected: dict[str, int] = {}
    code = severity = facility = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(";"):
            continue
        m = re.match(r"MessageId\s*=\s*(0x[0-9A-Fa-f]+|\d+)$", line)
        if m:
            code = int(m.group(1), 16) if m.group(1).lower().startswith("0x") \
                else int(m.group(1))
            severity = facility = None
            continue
        m = re.match(r"Severity\s*=\s*(\w+)$", line)
        if m:
            severity = m.group(1)
            continue
        m = re.match(r"Facility\s*=\s*(\w+)$", line)
        if m:
            facility = m.group(1)
            continue
        m = re.match(r"SymbolicName\s*=\s*(\w+)$", line)
        if m and code is not None and severity and facility:
            # The layout mc.exe encodes: severity in bits 30-31, the customer
            # bit 29 clear because -c is not used, facility in bits 16-27, and
            # the message id itself in the low 16. The low 16 bits are what the
            # Event Viewer shows in its "Event ID" column.
            expected[m.group(1)] = ((EVT_SEVERITY_BITS[severity] << 30)
                                    | (facilities[facility] << 16)
                                    | code)
    return facilities, expected


def check_evt_catalogue() -> None:
    print("[5] event log catalogue")
    mc_path = ROOT / EVT_MC
    if not mc_path.is_file():
        fail("evt-catalogue", f"{EVT_MC} is missing")
        return

    missing = [n for n in EVT_GENERATED if not (ROOT / n).is_file()]
    if missing:
        fail("evt-catalogue",
             f"generated output missing: {', '.join(missing)} "
             f"(regenerate: mc.exe -U -n -h . -r . {EVT_MC})")
        return
    ok(f"{EVT_MC} and its {len(EVT_GENERATED)} generated artifacts present")

    # The table is only in the DLL if the generated script is included.
    rc_text = read(ROOT / "TargetCore.rc")
    if 'TargetCoreEvt.rc' in rc_text:
        ok("TargetCore.rc includes the generated message table script")
    else:
        fail("evt-catalogue",
             "TargetCore.rc does not #include TargetCoreEvt.rc, so the message "
             "table is absent from the DLL and the Event Viewer cannot format "
             "a hosted service's diagnostics")

    # Every symbolic value in the committed header must equal what the .mc says.
    mc_text = mc_path.read_text(encoding="utf-8")
    _, expected = parse_mc_catalogue(mc_text)
    if not expected:
        fail("evt-catalogue", f"parsed no messages out of {EVT_MC}")
        return

    header = read(ROOT / "TargetCoreEvt.h")
    committed = {name: int(value, 16) for name, value in
                 re.findall(r"#define\s+(P2PMSG_EVT_\w+)\s+\(\(DWORD\)(0x[0-9A-Fa-f]+)L\)",
                            header)}
    drifted = []
    for name, want in expected.items():
        got = committed.get(name)
        if got is None:
            drifted.append(f"{name} declared in {EVT_MC} but absent from the header")
        elif got != want:
            drifted.append(f"{name} is 0x{got:08X} in the header, "
                           f"0x{want:08X} per {EVT_MC}")
    for name in committed:
        if name not in expected:
            drifted.append(f"{name} is in the header but no longer in {EVT_MC}")
    if drifted:
        for d in drifted:
            fail("evt-catalogue", d)
        fail("evt-catalogue",
             f"committed output has drifted; regenerate with "
             f"mc.exe -U -n -h . -r . {EVT_MC}")
        return
    ok(f"all {len(expected)} symbolic values agree with {EVT_MC}")

    # Byte-exact, when there is a compiler to be exact against.
    mc_exe = find_message_compiler()
    if mc_exe is None:
        notes.append("event log catalogue: mc.exe not found, so the committed "
                     "generated output was checked STRUCTURALLY only -- not "
                     "regenerated and byte-compared. Run this check on a "
                     "machine with a Windows SDK to close that gap.")
        return

    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run([str(mc_exe), "-U", "-n", "-h", tmp, "-r", tmp,
                               str(mc_path)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            fail("evt-catalogue",
                 f"mc.exe failed on {EVT_MC}: "
                 f"{(proc.stderr or proc.stdout).strip()}")
            return
        identical = True
        for name in EVT_GENERATED:
            fresh = Path(tmp) / name
            if not fresh.is_file():
                fail("evt-catalogue",
                     f"mc.exe did not produce {name}; the committed copy may be "
                     f"from a catalogue that declared different output")
                identical = False
                continue
            if fresh.read_bytes() != (ROOT / name).read_bytes():
                fail("evt-catalogue",
                     f"{name} differs from what mc.exe produces from {EVT_MC} "
                     f"-- committed output has drifted from its source")
                identical = False
        # Only claim this when it is true of every file. Reporting a FAIL and an
        # "ok, byte-identical" from the same pass is how a check gets ignored.
        if identical:
            ok(f"regenerated with {mc_exe.parent.parent.name} and byte-identical")



# ---------------------------------------------------------------------------
# 6. The covered ABI surface matches its manifest
#
# The versioning policy says the flat C ABI is the one surface this project
# promises anything about, and names abi-flat.manifest as the enumeration. An
# enumeration nothing compares to anything is a list, not a promise -- so this
# compares it to the header that declares the symbols.
#
# It deliberately does NOT look at a built binary. That is the OTHER half of the
# check and it lives in ctest (p2p_abisurface), because it needs a compiler and
# this file's whole contract is that it needs none. The two catch different
# things: this one catches a symbol appearing in or vanishing from the header
# without a deliberate manifest edit; that one catches a header promise the
# library does not actually export.
# ---------------------------------------------------------------------------
C_HEADER = ROOT / "TargetCore_c.h"
ABI_MANIFEST = ROOT / ".github" / "ci" / "abi-flat.manifest"

# P2PC_API must start the line. In the macro's own #define block it does not,
# and matching there would put __declspec and __attribute__ in the surface.
ABI_DECL_RE = re.compile(r"^[ 	]*P2PC_API\b", re.M)
ABI_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
LINE_COMMENT_RE = re.compile(r"//.*$", re.M)


def abi_names_from_header() -> set[str]:
    # Comments are stripped first: the header discusses its own entry points in
    # prose above them, and a mention is not a declaration.
    text = LINE_COMMENT_RE.sub("", read(C_HEADER))
    names: set[str] = set()
    for m in ABI_DECL_RE.finditer(text):
        # A declaration can wrap over several lines before its parameter list,
        # so take the first identifier followed by "(" after the marker.
        hit = ABI_NAME_RE.search(text, m.end(), m.end() + 400)
        if hit:
            names.add(hit.group(1))
    return names


def abi_names_from_manifest() -> set[str]:
    names: set[str] = set()
    for line in ABI_MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.add(line)
    return names


def check_abi_surface() -> None:
    print("[6] the covered C ABI surface matches its manifest")
    if not ABI_MANIFEST.is_file():
        fail("abi-surface", f"{ABI_MANIFEST.name} is missing -- the versioning "
                            f"policy names it as the enumeration of the "
                            f"covered surface")
        return

    declared = abi_names_from_header()
    promised = abi_names_from_manifest()

    if not declared:
        fail("abi-surface", "no P2PC_API declarations found in TargetCore_c.h -- "
                            "the parser is broken, not the header")
        return

    for name in sorted(declared - promised):
        fail("abi-surface",
             f"'{name}' is declared P2PC_API in TargetCore_c.h but is NOT in "
             f"abi-flat.manifest. A new entry point is a promise; add it to the "
             f"manifest in the same commit, or take it off the shipped header")
    for name in sorted(promised - declared):
        fail("abi-surface",
             f"'{name}' is in abi-flat.manifest but is no longer declared in "
             f"TargetCore_c.h. Removing a covered symbol is a MAJOR bump once "
             f"this project is 1.0 -- see the versioning policy")

    if declared == promised:
        ok(f"{len(declared)} flat C symbols; header and manifest agree")

    # The manifest must stay sorted and unique, because its diff IS the review.
    body = [l.strip() for l in ABI_MANIFEST.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")]
    if body != sorted(set(body)):
        fail("abi-surface", "abi-flat.manifest is not sorted-unique; regenerate it "
                            "with --regenerate-abi. An unsorted manifest makes an "
                            "addition and a move look the same in a diff")
    else:
        ok("manifest is sorted and free of duplicates")


# ---------------------------------------------------------------------------
# 7. The wire format versions are where the manifest says they are
#
# Each wire format versions on its OWN byte, independently of the component
# version (the versioning policy), which is right and which means no release
# number reveals that one of them moved. A one-character edit to kVersion is a
# decision to stop interoperating with every deployed peer. This is the only
# thing anywhere that would report it.
# ---------------------------------------------------------------------------
WIRE_MANIFEST = ROOT / ".github" / "ci" / "wire-versions.manifest"


def check_wire_versions() -> None:
    print("[7] wire format versions match the manifest")
    if not WIRE_MANIFEST.is_file():
        fail("wire-versions", f"{WIRE_MANIFEST.name} is missing")
        return

    rows = 0
    for raw in WIRE_MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 4:
            fail("wire-versions", f"malformed manifest row: {line!r} "
                                  f"(expected: name value file constant)")
            continue
        name, expected, filename, constant = parts
        src = ROOT / filename
        if not src.is_file():
            fail("wire-versions", f"{name}: {filename} does not exist")
            continue
        # "const <type...> <constant> = <n>;" -- the type is not pinned because
        # it differs between the three (unsigned char / unsigned int) and the
        # width is not what this check is about.
        m = re.search(r"\bconst\s+[A-Za-z_][A-Za-z0-9_ ]*\b"
                      + re.escape(constant) + r"\s*=\s*(\d+)\s*;", read(src))
        if not m:
            fail("wire-versions",
                 f"{name}: could not find 'const ... {constant} = <n>;' in "
                 f"{filename}. Either the constant was renamed -- in which case "
                 f"the manifest must follow it -- or the format stopped carrying "
                 f"a version, which is a much larger change")
            continue
        if m.group(1) != expected:
            fail("wire-versions",
                 f"{name}: {filename} has {constant} = {m.group(1)}, manifest "
                 f"says {expected}. A wire version moved. This is not a silent "
                 f"change: say in the commit what stops talking to what, and "
                 f"update the versioning policy in the same commit")
            continue
        rows += 1
        ok(f"{name}: {constant} = {expected} ({filename})")

    if rows == 0:
        fail("wire-versions", "no rows checked -- the manifest is empty or "
                              "entirely comments")


def regenerate_abi_manifest() -> int:
    """Rewrite abi-flat.manifest from the header, keeping its comment banner.

    Deliberately preserves the leading comment block rather than regenerating
    it: that banner is where the promise is explained, and a generator that
    rewrote it would let the explanation drift out with a routine bump.
    """
    names = sorted(abi_names_from_header())
    if not names:
        print("refusing to regenerate: no P2PC_API declarations found")
        return 1
    banner = []
    for line in ABI_MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.strip().startswith("#"):
            break
        banner.append(line)
    while banner and not banner[-1].strip():
        banner.pop()
    nl = chr(10)
    body = nl.join(banner) + nl + nl + nl.join(names) + nl
    ABI_MANIFEST.write_text(body, encoding="utf-8", newline=nl)
    print(f"{ABI_MANIFEST.name}: {len(names)} symbols")
    return 0


def main() -> int:
    if "--regenerate-abi" in sys.argv:
        return regenerate_abi_manifest()
    print(f"repo: {ROOT}")
    check_required_files()
    check_markdown_links()
    check_source_parity()
    check_legacy_crypto_stays_deleted()
    check_evt_catalogue()
    check_abi_surface()
    check_wire_versions()

    print()
    for note in notes:
        print(f"NOTE: {note}")
    if failures:
        print(f"\n{len(failures)} invariant(s) violated:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nAll repository invariants hold. "
          "NOTE: nothing was compiled -- see the header of this file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
