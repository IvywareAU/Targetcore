# Targetcore — Memory-leak & Crash Fixes

Fixes for the acknowledged memory leaks and crashes flagged in the repo-root
`TODO.md`. Each change was verified with a clean MSBuild
(`Targetcore(2026).sln`, `Debug|x64`, exit 0).

| # | Symptom | File / site | Commit |
|---|---------|-------------|--------|
| 1 | Decryption buffer leak | `P2Peerio.cpp` `DecryptP2PiomageSwap()` | `947e31d` |
| 2 | Sink-notification message leak | `P2Pwin32.cpp` `~P2PmsgPump()` | `cdeadcb` |
| 3 | Crash in `GetP2Pmsg()` | `P2Pwin32.cpp` `PumpP2Pmsg()` | `bc328fa` |
| 4 | `Signal(P2PsigCon_RECV)` throws instead of restarting receipt | `P2PeerCon.cpp` `Signal()` → `PostOVERLAPPED()` | `765c4d7` |

---

## 1. `P2Peerio::DecryptP2PiomageSwap` — leak on cypher-exception path

**Was:** `// TODO:LJM pP2PiomageDecrypted memory leak`

`pP2PiomageDecrypted` is allocated with `P2Piomage_Alloc()`. When `Decrypt()`
signals a cypher exception, the method posts a `P2P_CypherEx` message built from
the *original* encrypted `cpP2PiomageRecv` and returns `nullptr` — so the
freshly allocated decryption buffer is never propagated and never freed. It
leaked on **every** failed decrypt.

**Fix:** release the buffer with `P2Piomage_Release()` before returning `nullptr`
on that path. The normal (success) path is unchanged — it still returns the
buffer for the caller to manage.

## 2. `~P2PmsgPump` — undispatched messages leaked at teardown

**Was:** `// TODO-LJM MEMORY-LEEK` at the `CN_P2PeerSnc` manufacture site in
`PostP2PmsgSink()`.

Investigation showed the manufacture site is **not** where to fix it: on the
normal path `PumpP2Pmsg → DispatchP2Pmsg → ReleaseP2Pmsg` frees the message
*and* its `pP3PmsgItem`, so a delete at the manufacture site would double-free.

The genuine leak is at pump teardown. `PostP2PmsgSink()` manufactures one
`P2Pmsg` per registered sink client (`nCode == CN_P2PeerSnc`, `pCon == 0`) and
hands ownership to the target pump. Any such message still sitting in the queue
when the pump is destroyed was leaked, because:

- `~P2PmsgPump()` never drained `m_oCListP2Pmsg` / `m_oCListP2PmsgPit`, and
- `FlushP2Pmsg()` only releases messages that carry a `pCon`; the `pCon == 0`
  notifications are re-queued, never freed.

**Fix:** drain both pump-owned queues in `~P2PmsgPump()` via `ReleaseP2Pmsg()`
(a forward declaration was added since the function is defined later in the TU).
These messages were never dispatched, so releasing them cannot double-free. The
stale `MEMORY-LEEK` marker at the manufacture site was replaced with an
ownership note.

## 3. `PumpP2Pmsg` — data race crashing `GetP2Pmsg()`

**Was:** `//TODO:LJM Crash is occuring in next statement` above
`pP2Pmsg = pP2PmsgPump -> GetP2Pmsg();`

`m_oCListP2Pmsg` is a plain MFC `CList` (not thread-safe). Producers
(`PostP2Pmsg` and friends) enqueue under the **pump's own** `m_oCSection`,
reached via the established "downgrade" from the global registry lock
(`oSafeCS = pP2PmsgPump->m_oCSection;`, see ~line 2434). But `PumpP2Pmsg` read
the queue while still holding only the **global** `s_oCSectionP2PmsgPump`. Two
different critical sections guarding the same list let `AddTail` race
`RemoveHead`, corrupting the list and crashing inside `GetP2Pmsg()`.

**Fix:** apply the same downgrade to `m_oCSection` immediately before
`GetP2Pmsg()`, so reader and writers serialise on one lock. The timer queue
(`PollTimer`/`GetTimer`) deliberately stays under the global lock, matching its
own producers (`Set`/`KillTimer`). Verified: `P2PsafeCS::operator=` enters the
new CS before leaving the old, and no per-pump→global lock ordering exists, so
the change introduces no deadlock.

**Confidence:** diagnosed statically and build-verified; not reproduced under
concurrent load in this environment. An actual crash stack trace (expected to
land in `CList::RemoveHead`) would confirm the diagnosis.

---

## 4. `Signal(P2PsigCon_RECV)` — the restart that could never restart

**Symptom.** `P2Pevent` *"Corrupted OVERLAPPEDcon configuration — Bug(SNHappen)"*
thrown out of `P2PeerCon::PostOVERLAPPED()`, on any attempt to restart message
receipt on a connection that had already received a message. Because the throw
propagates to the connection's catch, the connection is **dropped** rather than
resumed — so the observable failure is silent message loss, not a crash.

**Site.** `P2PeerCon::Signal()`, the `P2PsigCon_RECV` interception, which called
`PostOVERLAPPED(m_pOVERLAPPEDrecv)`. That function refuses any buffer with
`dwBytesMax > 0` and a null `pBuffer`.

**Why it could never have worked.** `P2Peerio::RecvP2PeerMsg()`'s stage 0 runs
once per connection, on the first call: it moves the connection onto its own
`pUserDB1`/`pUserDB2` buffer pair, `delete[]`s `pOVERLAPPEDrecv->pBuffer` and
sets it to 0, while `dwBytesMax` stays non-zero. That is the **permanent** state
of a recv buffer from its first read onward. The guard is correct for a buffer
the transport is about to fill — the initial post from `Accept()`/`OnConnect()`
is exactly that case, and it is why the signal appears to work if you only ever
test it before any traffic. It is simply not the right guard for this buffer.

**Why nobody noticed.** Nothing in the tree ever signalled `P2PsigCon_RECV`. The
constant, the interception and its comment (*"Start P2PeerMsg receipt"*) have
been there since the import with no caller — an untested claim rather than a
facility. It was found by the first code that needed it: the backpressure resume
added for the inbound brake threw out of it on its first armed
run, in `p2p_backpressure` phase 3.

**The wrong fix.** Loosening `PostOVERLAPPED()`'s guard. It is load-bearing for
the send/accept/connect buffers, where a null `pBuffer` with a non-zero size
really is corruption, and relaxing it there would trade a reachable defect for an
unreachable one.

**The fix.** A separate `P2PeerCon::RearmRecv()` that posts `m_pOVERLAPPEDrecv`
with `PostQueuedCompletionStatus` and asserts only what a *re-arm* needs — a
recv buffer that exists, is not already in flight, is not being deleted, and a
live completion port. It arms a read rather than performing one, exactly as the
initial post does, and the completion re-enters
`On_QueuedCompletionStatus`. `Signal(P2PsigCon_RECV)` now routes through it, so
the one path that claimed to restart receipt does.

**Guarded by.** `p2p_backpressure` (`MscsUnitTests`), whose third phase requires
every message held under backpressure to arrive once the pressure is released.
With `RearmRecv()` removed it reports *"THE HELD MESSAGES WERE LOST (20 of 40)"*.

---

## Related mirror bugs (sibling module `Msgcore\`)

`Msgcore\` is a sibling copy and carried the same issues. Fixed in Msgcore
commit `0f0b221`. **The file those line numbers point into no longer exists**: `Msgcorewin32.cpp`
was deleted from `Msgcore` on 2026-07-17 at `3a6d0b0` — *"a dead, stale clone of
Targetcore/P2Pwin32.cpp"* — so every `Msgcorewin32.cpp` reference below is readable only against
`0f0b221`, and the surviving copy of each fix is the one in this repository.

- `Msgcorewin32.cpp:6068` (leak) and `:4127` (crash) — same two fixes as #2/#3.
- `:5856` — `CleanupP2PmsgSink()` could spin forever when passed a hub other
  than the thread-current one (`P2PmsgSinkClose()` resolves the sink via the
  current hub); added a forward-progress guard.
- `:3032` — the commented-out `//ReleaseP2Pmsg` in the catch path is a **false
  positive**: the unconditional release at the function tail already covers
  every path, so activating it would double-free. Left disabled, comment
  clarified. The identical mirror lives here at `P2Pwin32.cpp:3745`.
