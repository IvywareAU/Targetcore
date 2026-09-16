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
# check_abi_exports.py -- the half of the ABI check that needs a compiler.
#
# ctest -R p2p_abisurface runs this. It asks the BUILT library what it actually
# exports and compares that to abi-flat.manifest, which the versioning policy
# names as the enumeration of the covered surface.
#
# WHY THIS IS SEPARATE from check_repo_invariants.py's check [6]. That one
# compares the manifest to the HEADER, with no compiler involved, and catches a
# symbol appearing or vanishing in the declaration. It cannot catch either of
# the two failures that only a binary can show:
#
#   * A header promise the library does not keep. Targetcore_c.h can declare an
#     entry point whose definition was never compiled in -- the header is a
#     promise, the export table is the delivery -- and the consumer finds out at
#     link time, which is the worst place to find out.
#   * An accidental widening. A stray dllexport or a default-visibility
#     attribute puts a name in the covered namespace that nobody decided to
#     promise, and once shipped it is a promise anyway.
#
# WHAT IT DOES NOT CHECK, said plainly: signatures. An export table carries
# names, not types, so a parameter that changes from int to long long is
# invisible here and to every other check in this repository. That is a real
# gap in the mechanism, not an oversight -- the compiler is the only thing that
# could see it, and only from the consumer's side. install-check/consumer.c is
# the nearest thing: it compiles against the shipped header and links, so a
# signature change that breaks a caller breaks that gate.
# ---------------------------------------------------------------------------

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)
    print(f"  FAIL  {message}")


def ok(message: str) -> None:
    print(f"  ok    {message}")


def note(message: str) -> None:
    print(f"  note  {message}")


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------
def read_manifest(path: Path) -> set[str]:
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.add(line)
    return names


def covered_prefixes(names: set[str]) -> set[str]:
    """The namespace the manifest claims, derived from the manifest itself.

    Hardcoding the prefix list here would make this file a second place the
    surface is described, and the second place is always the one that goes
    stale. Anything under one of these prefixes is meant to be covered, so an
    export under one that the manifest does not list is a widening. Anything
    outside them -- p2p_iocp_* from the Platform shim on Linux, for instance --
    is not this policy's business and is reported as a note.
    """
    return {n.split("_", 1)[0] + "_" for n in names if "_" in n}


# ---------------------------------------------------------------------------
# The binary
# ---------------------------------------------------------------------------
# Flat C names are all-lowercase with underscores; every C++ export is mangled
# (Itanium names start with _Z, MSVC names contain '@'), so neither can be
# mistaken for the other. Matched by SHAPE, not by a name prefix. This used to
# read ^p2p[a-z0-9_]*$, which quietly stopped seeing a symbol the moment the
# component was renamed and its entry points stopped being spelled p2p*: the
# manifest promised them, the DLL exported them, and the two could not be
# compared because this line did not recognise them as flat C names at all.
# A prefix is a fact about today's naming; being unmangled is a fact about the
# ABI, and the ABI is what this file is for. Anything that matches but sits
# outside the manifest's namespace is reported as a note, so widening the
# shape cannot turn an unrelated export into a failure.
FLAT_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")

# dumpbin /EXPORTS:  ordinal  hint  RVA  name
DUMPBIN_RE = re.compile(r"^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)")
# nm -D --defined-only:  address type name   (type T = text, D/B = data)
NM_RE = re.compile(r"^[0-9A-Fa-f]*\s+[A-Za-z]\s+(\S+)$")


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed ({proc.returncode}): "
                           f"{(proc.stderr or proc.stdout).strip()[:400]}")
    return proc.stdout


def exports_windows(library: Path, dumpbin: Path) -> set[str]:
    out = run([str(dumpbin), "/EXPORTS", str(library)])
    return {m.group(1) for m in (DUMPBIN_RE.match(l) for l in out.splitlines()) if m}


def exports_posix(library: Path, nm: str) -> set[str]:
    out = run([nm, "-D", "--defined-only", str(library)])
    return {m.group(1) for m in (NM_RE.match(l) for l in out.splitlines()) if m}


# ---------------------------------------------------------------------------
# The version resource (Windows only)
#
# The versioning policy tells a consumer to read a DLL's FileVersion and check
# out the tag of the same number. That instruction is only worth giving if the
# resource really does come from the header, so this checks it rather than
# trusting the build wiring. There is no ELF equivalent -- a .so carries no
# version resource -- so on Linux this is a note, not a silent pass.
# ---------------------------------------------------------------------------
def check_file_version(library: Path, expected: str) -> None:
    if sys.platform != "win32":
        note(f"no version resource on this platform; the header says {expected}")
        return
    ps = ("$ErrorActionPreference='Stop';"
          f"(Get-Item -LiteralPath '{library}').VersionInfo.FileVersion")
    try:
        got = run(["powershell", "-NoProfile", "-Command", ps]).strip()
    except (RuntimeError, FileNotFoundError) as exc:
        note(f"could not read the version resource: {exc}")
        return
    # FileVersion renders as "0.10.0.0"; some toolchains render "0, 10, 0, 0".
    got_norm = got.replace(" ", "").replace(",", ".")
    if got_norm == expected:
        ok(f"the DLL's FileVersion is {got_norm}, matching Targetcore_version.h")
    else:
        fail(f"the DLL reports FileVersion {got!r} but Targetcore_version.h "
             f"declares {expected!r}. The versioning policy tells a consumer "
             f"to find the source of a binary by that number, and it would "
             f"send them to the wrong tag")


def header_version(repo: Path) -> str:
    text = (repo / "Targetcore_version.h").read_text(encoding="utf-8-sig")
    m = re.search(r'#define\s+TARGETCORE_VERSION_STRING\s+"([0-9.]+)"', text)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", required=True, type=Path)
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--dumpbin", type=Path, default=None,
                    help="path to dumpbin.exe (Windows)")
    ap.add_argument("--nm", default="nm", help="nm binary (POSIX)")
    args = ap.parse_args()

    print(f"library:  {args.library}")
    print(f"manifest: {args.manifest}")

    if not args.library.is_file():
        fail(f"{args.library} does not exist")
        return 1
    if not args.manifest.is_file():
        fail(f"{args.manifest} does not exist")
        return 1

    promised = read_manifest(args.manifest)
    if not promised:
        fail("the manifest lists no symbols")
        return 1

    try:
        if sys.platform == "win32":
            if args.dumpbin is None or not args.dumpbin.is_file():
                fail(f"dumpbin not found at {args.dumpbin}; pass --dumpbin")
                return 1
            every = exports_windows(args.library, args.dumpbin)
        else:
            every = exports_posix(args.library, args.nm)
    except (RuntimeError, FileNotFoundError) as exc:
        fail(str(exc))
        return 1

    flat = {n for n in every if FLAT_RE.match(n)}
    prefixes = covered_prefixes(promised)
    covered = {n for n in flat if any(n.startswith(p) for p in prefixes)}
    outside = sorted(flat - covered)

    print(f"  {len(every)} exported symbols, {len(flat)} flat, "
          f"{len(covered)} in the covered namespace")

    for name in sorted(promised - covered):
        fail(f"'{name}' is in abi-flat.manifest but the built library does NOT "
             f"export it. The header promises it; a consumer that calls it gets "
             f"an unresolved external")
    for name in sorted(covered - promised):
        fail(f"'{name}' is exported by the library but is NOT in "
             f"abi-flat.manifest. An export nobody declared is a promise nobody "
             f"decided to make -- add it to the manifest deliberately, or stop "
             f"exporting it")

    if covered == promised:
        ok(f"all {len(promised)} covered symbols exported, and nothing else "
           f"in that namespace")

    if outside:
        # Not a failure. These are below the covered surface -- the Platform
        # io_uring shim on Linux, for instance -- and this policy says nothing
        # about them. Printed so the set is visible rather than assumed empty.
        note(f"{len(outside)} other flat exports, outside the covered "
             f"namespace: {', '.join(outside[:8])}"
             + (" ..." if len(outside) > 8 else ""))

    expected = header_version(args.manifest.parents[2])
    if expected:
        check_file_version(args.library, expected)
    else:
        fail("could not read TARGETCORE_VERSION_STRING from Targetcore_version.h")

    print()
    if failures:
        print(f"{len(failures)} ABI surface violation(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("The built library's covered surface matches abi-flat.manifest.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
