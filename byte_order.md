# Byte order in MSCS

> Status: current as of 2026-08-09. Companion to the Linux port plan, which pins the
> *width* of persisted types (`P2PWCHAR`, pointer size). This document pins the remaining
> axis — the **order of the bytes within** those types.

## 1. Summary

MSCS is byte-order-correct everywhere it currently matters, and byte-order-*undefined* in
one place: the core VBLock/VBHeap binary format.

Every MSCS target is little-endian (x86-64 Windows, x86-64 Linux, ARM64), so there is no
live defect. The purpose of this document is to record which parts of the system carry a
real byte-order contract, which parts merely inherit the host's, and what a big-endian
target would break if one ever appeared.

| Layer | Contract | Correct on a BE host? |
|---|---|---|
| Socket address fields | `htons`/`htonl` | Yes |
| ECDH raw-secret interop (CNG ↔ OpenSSL) | LE, explicit | Yes |
| Utility-hub framing (`TreeMsg`) | LE, byte-at-a-time | Yes |
| WAV / RIFF I/O (`DspWav`) | LE, byte-at-a-time | Yes |
| DSP frame header (`DspFrameHdr`) | Host order | No — but **detected** (magic) |
| **VBLock / VBHeap image (`oSync`)** | **Host order** | **No — now detected (§4)** |
| **VBLock / VBHeap file (`VBListBSTRio`)** | **Host order** | **No — undetected (§6)** |

## 2. Handled correctly, deliberately

### 2.1 Socket address fields

`P2PeerConWsa.cpp:459-460,738` set `sin_addr.s_addr` and `sin_port` through `htonl`/`htons`,
and parse dotted-quad addresses with `InetPton`. These fields are big-endian by definition of
the sockets API regardless of host, so this is the one place byte order bites even on an
all-little-endian fleet. It is right.

### 2.2 ECDH raw-secret interop — the hard one

This is a genuine cross-endian interop problem that MSCS solves rather than inherits:

- Windows CNG's `BCRYPT_KDF_RAW_SECRET` returns the P-256 shared X coordinate **little-endian**.
- OpenSSL's `EVP_PKEY_derive` returns the same value **big-endian**.

Left alone, a Windows peer and a Linux peer would feed HKDF different input keying material
and silently fail to agree on a session key. `P2PCngCrypto_openssl.cpp:311-333` reverses the
OpenSSL output so both backends converge on the CNG convention. It is pinned by a known-answer
test against RFC 5903 §8.1 (`MscsUnitTests/crypto_kat.cpp:127`), which reverses the RFC's
big-endian expected value to little-endian before comparing.

Note this is a *convention* difference between two crypto libraries, not a host-endianness
difference. It would need the same treatment on a big-endian host.

### 2.3 Genuinely portable framing

Two subsystems serialise integers a byte at a time and are therefore correct on any host:

- `P2PeerUtilityHubs/TreeMsg.h:38` — *"little-endian on the wire (written byte-by-byte, so no
  host-endianness assumption)"*. `PutU32`/`GetU32`.
- `DspChain/DspWav.cpp:12-21` — `rd16`/`rd32`/`wr16`/`wr32` shift explicitly. RIFF is
  little-endian by specification, so this is spec-correct, not just host-correct. (The file's
  own header comment says "little-endian host assumed"; the code is stronger than the comment.)

**These are the pattern to copy for any new wire format.**

## 3. Host order by construction

### 3.1 DSP frame header

`DspChain/DspFrame.h` is a `#pragma pack(1)` struct written and read as raw memory. It is
documented little-endian and is host-order in fact.

It does, however, carry an accidental but effective guard: `uMagic` is compared as a
`uint32_t`, so a frame produced by a byte-swapped host fails the magic check and is rejected
at the door rather than being misinterpreted. This is the behaviour §4 gives `oSync`.

### 3.2 The VBLock / VBHeap image — the core format

`VBListIOmage` (`Msgcore/P2PmsgBSTR.h`) is the P2P **wire** format: a packed header followed by
the heap image, `memcpy`'d straight to the socket (`P2Peerio.cpp:837`). Everything inside it —
`VBLaddr` offsets, `VBLockData` scalars (`INT16`…`INT64`, `FLOAT`, `DOUBLE`), name and blob
length fields — is host order.

The header is two words:

```c
struct {
    UINT32 uiSync1;   // size (bits 0-23) | uAddrType (bits 24-25)
    UINT32 uiSync2;   // complement of uiSync1
} oSync;
```

Historically the only validity test was the complement relation
(`MsgVBHeap.cpp` `P2PmsgHeap_IsIOMAGE`):

```c
(uiSync1 & uiSync2) == 0 && (uiSync1 | uiSync2) == ~0
```

**That test cannot detect a byte-order mismatch.** Bitwise complement is per-bit and byte-swap
is a bit permutation; the two commute, so a complement pair stays a complement pair under
byte-swap. A big-endian peer's header passed `IsIOMAGE` cleanly, after which the declared size
was read byte-swapped — `0x02000050` (80 bytes, `Addr32`) becomes `0x50000202`, i.e. a claimed
size of 514 and an addressing mode of `0x50`. The failure surfaced much later as a corrupt
block walk, with nothing pointing at endianness as the cause.

§4 closes this.

## 4. The `oSync` endian sentinel

### 4.1 Where the bits came from

`Msgcore.h` defines `VBLock_AddrMask 0x03` — the addressing mode occupies only **bits 0-1** of
`uiSync1`'s top byte. Bits 2-7 were always zero and never read. The sentinel lives there, so
`sizeof(VBListIOmage)` is unchanged and the complement invariant is preserved intact:

```c
#define VBLock_SyncMask   0xFC   // bits 2-7 of the oSync top byte
#define VBLock_SyncGen1   0xA4   // layout generation 1 - the pattern written there
#define VBLock_SyncGenNow VBLock_SyncGen1   // the generation this build stamps
```

**Those bits later took a second job, and it is the more important one.** Six bits hold 64 codes;
a sentinel needs one. The rest are a **layout generation** field — the message image's only version
story, since bits 0-23 are the size and 24-25 the addressing mode. The versioning policy
carries that argument; what follows here is only the byte-order half.

**Exactly one code is defined, and that is a decision rather than a starting point.** An earlier
draft of this reserved a second code (`VBLock_SyncGen2` = `0xA8`, never written) so the
"known other generation" branch would be reachable. It was dropped: an enumerated registry names
the codes somebody remembered to reserve and says nothing about the rest, and it charges 1/64 of
the diagnosis below for each one it names. The classifier now treats **any** non-current non-zero
pattern as a generation this build does not implement, which covers all 62 free codes and costs
nothing — §4.4.

A current image therefore has top byte `0xA4 | uAddrType`, i.e. `0xA4`–`0xA7`.

### 4.2 Why it detects a swap

The top byte of `uiSync1` is its *most significant*, so it is the **last** byte in memory on a
little-endian host. A big-endian reader of those same bytes lands it in the *least* significant
position. So for an image written by a little-endian peer and read by a big-endian one:

- the top byte reads as the size's low byte — arbitrary, and almost never a valid sentinel;
- the **low** byte reads as exactly `VBLock_SyncBits | uAddrType`.

That second property is what makes the mismatch *diagnosable* rather than merely detectable.
`VBLock_SyncForm()` classifies a header:

| Form | Condition | Meaning |
|---|---|---|
| `Native` | `(uiSync1 >> 24) & 0xFC == VBLock_SyncGenNow` | written by a current build, same endianness |
| `Legacy` | `(uiSync1 >> 24) & 0xFC == 0` | pre-sentinel image, same endianness |
| `Swapped` | the **current** code found in the LOW byte | foreign endianness |
| `Gen` | otherwise (any other non-zero high pattern) | a layout generation this build does not implement |

The order of those tests is deliberate: `Native` → `Legacy` → `Swapped` → `Gen`. `Native` is
first so that this build's own code is never reported as foreign. Checking `Legacy` before
`Swapped` guarantees that **no valid pre-sentinel image is ever misdiagnosed** as byte-swapped,
which would be a regression on existing data. And `Gen` is **last because it is the fallback**:
placed any earlier it swallows every byte-swapped image, since a swapped word's top byte is the
size's low byte and is non-zero far more often than not. The cost is that a swapped image whose
size low byte happens to fall in `0x00`–`0x03` or `0xA4`–`0xA7` is misclassified rather than
reported — see §4.4.

`Invalid` is **not in that table and cannot be returned by `VBLock_SyncForm`**, because every
pattern is now classified. It belongs to `P2PmsgHeap_IOMAGEform`, which fails the complement pair
first and means one thing only: *this is not an image*. A word reaches the classifier at all only
by already being a valid complement pair, which random bytes manage 2⁻³² of the time — so the
enumeration the old `Invalid` arm performed was never the structural filter, and dropping it costs
no rejection. What it costs is a *diagnostic*: crafted bytes that do form a valid pair are now
reported as an unimplemented generation rather than as corruption. Both are refusals.

### 4.3 Compatibility

- **Reading is backward compatible.** Pre-sentinel images are classified `Legacy` and accepted
  unchanged. No stored data is invalidated and no migration is required.
- **Writing is a one-way upgrade.** Images written by a current build carry the sentinel, and a
  *pre-sentinel* build reading one will compute an addressing mode of `0xA4`–`0xA7` and reject
  it. Mixed-version peer meshes and any consumer pinned to an older Msgcore must be upgraded
  together. This is inherent to adding a sentinel at all, not to this particular design.
- **That last sentence is now ENFORCED on the wire rather than assumed.** `RecvP2PeerMsg` stage 2
  refuses a frame whose generation is not the current one, pre-sentinel images included, before it
  allocates. **Reading a FILE is unaffected and deliberately so:**
  `P2PmsgMgr::Load` still accepts a pre-sentinel image and warns, because a file is data somebody
  already has. The first bullet above therefore still holds for the store and no longer holds for
  the wire, which is the asymmetry `p2p_imagegen` exists to hold in place.
- **The on-disk store format is untouched** — see §6. `MscsUnitTests/golden_ref.p2p` and the
  `golden_utf16_bytes` cross-OS byte-identity gate are unaffected, because that file is a
  `VBListBSTRio` image, not an `oSync` one.

### 4.4 What this is and is not

It is a **diagnostic guard**, not a checksum. A byte-swapped image is correctly reported in
**62 of 64** cases; in the remaining 2/64 the swapped top byte coincidentally reads as a valid
`Native` or `Legacy` sentinel, and the image then fails on the size bounds
check instead
(`nSizeof <= sizeof(oSync)`, and `nDeclared > nBufferLen` on the length-validated path), which
in practice catches essentially all of the remainder — just with a less specific message.

**The figure is 62 of 64 and stays there however many generations are defined**, which is the
whole reason the generation field is a fallback rather than a registry of reserved codes. A
registry would have had to look for every code it listed in the low byte, at exactly 1/64 each: it
briefly stood at 61 of 64 while a second code was reserved. The fallback recognises only the code
this build writes, so the swap arm tests one value and the miss set is the two ranges above no
matter how far the format's layout eventually moves.

The residual it accepts instead is narrower and does not compound: a byte-swapped image of a
**future** generation is reported as an unimplemented layout rather than as an endianness
mismatch, because the swap arm looks for a code this build would have written. That is
cross-endian *and* cross-generation at once, and it is a refusal either way.

Closing that last gap would need an asymmetric relation between the two words, e.g.
`uiSync2 = ~uiSync1 ^ MAGIC` with a non-palindromic `MAGIC`, which detects a swap with
certainty (since `swap(MAGIC) != MAGIC`) but breaks the complement invariant that the rest of
the heap code and `Msgcore/tests/C4LoadTest.cpp` rely on. Not worth it for a platform
combination that does not exist; recorded here in case one ever does.

## 5. Two conventions in the wider ecosystem

The C++ core is host-order/little-endian. The `P2PeerHub` peers written in other languages are
explicitly **big-endian**, following Java conventions — a 2-byte big-endian length prefix, Netty
`LengthFieldPrepender` framing, as used by the PHP and browser hub peers.

These are different protocol legs and do not conflict, but do not assume one when reading the
other. If a C++ peer ever speaks the `P2PeerHub` protocol directly it must convert explicitly.

## 6. Known remaining gap: the store file format

`P2PmsgMgr` heaps are created with `P2PmsgHeap_CreateBSTRio`, so `Save`/`Load` persist a
`VBListBSTRio`, **not** a `VBListIOmage`. Its header carries the same idiom and the same
weakness:

```c
struct { UINT32 uDefs1;    UINT32 uComp2; } oDefs;   // complement pair
struct { VBLsize32 aSize1; VBLsize32 aComp2; } oSize; // complement pair
```

The header is a **mix** of byte-addressed and word-addressed fields, and the distinction is the
whole design problem:

- `oDefs.uDefs1` is only ever touched a byte at a time, on both write
  (`P2PmsgHeap_InitBSTRio` sets `pDefs[0]` = type tag, `pDefs[1]` = addressing mode,
  `pDefs[2]`/`pDefs[3]` = spare, zeroed) and read (`P2PmsgHeap_IsBSTRio` checks `pDefs[0]`,
  `P2PmsgHeap_AddnnBSTRio` returns `pDefs[1]`). Byte offsets do not move with endianness, so
  these fields are endian-**neutral**: they round-trip correctly on any host, and cross-host.
- `oSize.aSize1`/`aComp2` and every field of `oKeys` (`VBLaddr32`, `VBLelem`) are written and
  read as **words**, and are therefore endian-**sensitive** — as is every VBLock in the heap
  body that follows.

So on a big-endian host reading a little-endian store, *every check in `IsBSTRio` passes*: the
type tag is byte-addressed and matches, the addressing mode is byte-addressed and matches, and
both complement pairs survive the swap for the reason given in §3.2. The caller then proceeds
on a byte-swapped allocation size. A foreign-endian store file is exactly as undetectable today
as a foreign-endian wire image was before §4.

### 6.1 The §4 design does **not** transfer here

`oSync`'s sentinel works because `uiSync1` is a *word*-written field — the sentinel rides the
endian-sensitive path, so a swap moves it. `uDefs1` is byte-written, so a sentinel written
byte-wise into the spare `pDefs[2]`/`pDefs[3]` would land at the same offsets on either host and
detect nothing at all. Copying §4 literally would produce a guard that is always satisfied.

Mixing the two within one word is worse than useless: writing the tag byte-wise and a magic
word-wise into the same `UINT32` puts the magic in the high half on a little-endian host and the
low half on a big-endian one, where it collides with the tag.

### 6.2 What to do instead — a byte-order mark

The spare bytes are already reserved and zeroed, which makes the classic move available: write a
two-byte **order mark** byte-at-a-time, then read it back as a `UINT16`. The write is
endian-neutral; the read is endian-sensitive; the disagreement between them is the signal.

```c
pDefs[2] = 0xFE;  pDefs[3] = 0xFF;                  // written byte-wise
UINT16 uMark = *(const UINT16 *)&pDefs[2];          // read as a word
//   0xFFFE -> same endianness as the writer
//   0xFEFF -> foreign endianness
//   0x0000 -> pre-mark file (legacy), accept
```

This is **certain**, not probabilistic — unlike §4 there is no residual, because the mark is a
fixed constant rather than a pattern competing with data bits. It changes no struct size, leaves
both complement invariants alone, and keeps every existing store readable via the `0x0000`
legacy case. `P2PmsgHeap_IsBSTRio` gains the classification and `Load` reports a byte-order
mismatch by name.

### 6.3 Why it has not been done

Unlike `oSync`, this changes the **on-disk** format, so it requires:

1. regenerating the checked-in `MscsUnitTests/golden_ref.p2p`, and
2. re-running `golden_utf16_bytes` — the cross-OS byte-identity gate — on **both** toolchains,
   since that test exists precisely to fail on serialised-format drift.

The blast radius is also real in a way the wire change was not: stores written by a new build
will not load on an older one, and Chartboard ships `.p2p` workspaces to users. That makes it a
release-sequencing decision, not just a code change.


## 7. Rules for new code

1. **Any new wire or file format serialises integers byte-at-a-time.** Copy `TreeMsg.h`'s
   `PutU32`/`GetU32` or `DspWav.cpp`'s `rd32`/`wr32`. Do not `memcpy` a packed struct and call
   it a format.
2. **Every format header gets a byte-order-asymmetric guard**, whether a magic word
   (`DspFrameHdr::uMagic`) or a sentinel (`oSync`). A header that cannot be distinguished from
   its own byte-swapped image will fail as memory corruption, far from the cause.
3. **Socket address fields always go through `htons`/`htonl`**, on every host.
4. **Do not widen a persisted type.** The Linux port plan pins `P2PWCHAR` to 16 bits and
   `P2Pmsg.h:315` records that persisted values are not compatible across 32/64-bit pointer
   builds. Byte order is the third axis of that same constraint.

## 8. Incidental defect found during this audit

`MakeIOmage` (`Msgcore/P2PmsgBSTR.cpp`) built its header as:

```c
pIOmage->oSync.uiSync1 = nSizeofIOmage;
pIOmage->oSync.uiSync2 = ~pIOmage->oSync.uiSync2;   // reads uninitialised memory
```

The second line complements `uiSync2` against *itself* rather than against `uiSync1`, reading
uninitialised bytes from `new char[]`. It also never set the addressing-mode byte. Any image it
produced would fail every validity check.

It was unreachable: its only caller, `P2Peerio::PKeyXChangeAck` (`Targetcore/P2Peerio.cpp:926`),
sits behind `ASSERT(0)` with the dispatch commented out — an unfinished code path. Corrected as
part of the §4 change, since that function had to learn to write the sentinel regardless.

Whoever finishes the `PKeyXChangeAck` path should note it now produces a well-formed header.
