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
#  release_notes.py -- the GitHub release body for one version.
#
#      python3 .github/ci/release_notes.py 3.4.7 [RELEASE_NOTES.md] > body.txt
#
#  Prints the "## X.Y.Z" section of RELEASE_NOTES.md without its heading,
#  UNWRAPPED: RELEASE_NOTES.md is hard-wrapped at ~95 columns for reading in a
#  terminal, but a GitHub release body renders every single newline as a line
#  break, so each paragraph and list item is joined back onto one line. Code
#  fences, headings, tables and blank lines are kept as they are; a list item's
#  indentation is kept, so nested lists survive.
#
#  Shared with Msgcore (tools/ci/release_notes.py there), where it reproduces
#  the hand-made 3.4.0 release body byte for byte. Targetcore's hand-made 3.4.6
#  release pasted the section still wrapped, and GitHub rendered it with nine
#  <br> breaks mid-sentence. Unwrapping that body gives exactly this output,
#  less a "Build checks" section that was added to the release by hand and is
#  not in RELEASE_NOTES.md -- a release made here says only what that file says.
#
#  Exit status 3 when the file is missing or has no section for the version,
#  so the caller can decide what to fall back to. Not 2: that is what python3
#  itself exits with when it cannot open the script, and a release workflow
#  that read 2 as "no section" once published a tag message instead of failing
#  because the script was not in the checkout it ran from.

import re
import sys


def section(text, version):
    m = re.search(r'^## ' + re.escape(version) + r'[ \t]*\n(.*?)(?=^## |\Z)',
                  text, re.S | re.M)
    return m.group(1).strip() if m else None


def unwrap(md):
    out, buf, fence = [], None, False

    def flush():
        nonlocal buf
        if buf is not None:
            out.append(buf)
            buf = None

    for line in md.split('\n'):
        if line.startswith('```'):
            flush()
            out.append(line)
            fence = not fence
            continue
        if fence:
            out.append(line)
            continue
        if line.strip() == '':
            flush()
            out.append('')
            continue
        if (line.startswith('#') or line.startswith('|')
                or re.match(r'^\s*([-*+]|\d+\.)\s', line)):
            flush()
            buf = line.rstrip()
            continue
        buf = line.rstrip() if buf is None else buf + ' ' + line.strip()
    flush()
    return '\n'.join(out)


def main(argv):
    if len(argv) < 2:
        sys.stderr.write('usage: release_notes.py VERSION [RELEASE_NOTES.md]\n')
        return 1
    version = argv[1].lstrip('v')
    path = argv[2] if len(argv) > 2 else 'RELEASE_NOTES.md'
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read().replace('\r\n', '\n')
    except FileNotFoundError:
        return 3
    body = section(text, version)
    if not body:
        return 3
    sys.stdout.reconfigure(newline='\n')
    sys.stdout.write(unwrap(body) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
