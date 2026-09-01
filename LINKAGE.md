# TargetCore linkage: all static or all dynamic

TargetCore builds in two shapes, and **a single process must commit to exactly one of
them**. Mixing them inside one process is the one way to use this library that compiles,
links, starts up, and then silently misbehaves.

| Shape | Configurations | Output | Macro |
|---|---|---|---|
| MFC extension DLL | `Debug` / `Release` × `Win32` / `x64` | `TargetCore.dll` + import lib | `TargetCore_EXPORTS` |
| Static archive | `DebugLib` / `ReleaseLib` × `Win32` / `x64` | `TargetCore.lib` | `TargetCore_STATIC` |

Both land in `out\<Platform>\<Configuration>\` and are staged to
`$(WDMSCS_LIB)` = `MSCS\lib\<Platform>\<Configuration>\`.

---

## The rule

> Every module in a process that touches TargetCore must reach it the same way.
> Either they all import it from one `TargetCore.dll`, or there is exactly one module
> in the process and it absorbs the archive.

The moment two modules in one process each link `TargetCore.lib` statically — say
`Chartboard.exe` and `P2PmsgCharts.dll` — the process contains **two complete, mutually
invisible copies of TargetCore**, each with its own hub table and its own locks.

## Why: the state is process-wide, not per-object

TargetCore keeps genuinely global state at file scope. With the DLL there is one copy
per process no matter how many modules import it, because there is one module holding
it. With the archive there is one copy **per linking module**:

| State | Where | What it holds |
|---|---|---|
| `s_oCSectionP2Pmsg` | `P2Pwin32.cpp` | master P2Pmsg environment lock |
| `s_oCSectionP2PmsgPump` | `P2Pwin32.cpp` | pump registry lock |
| `s_oCSectionP2PmsgHub` | `P2Pwin32.cpp` | hub manager table lock |
| `s_oCSectionP2PmsgSink` | `P2Pwin32.cpp` | event-sink table lock |
| `s_oCSectionP2Pevent` | `P2Pwin32.cpp` | event queue lock |
| `g_oCListP2PeerConDmx`, `g_oCSectP2PeerConDmx` | `P2PeerConDmx.cpp` | the in-process Dmx connection list and its lock |
| `g_pP2PeerEvents` | `P2PeerEvents.h` | the event dispatcher singleton |
| `g_P2PeerMsgInstances` | `P2PeerMsg.h` | live-message instance counter |

`StartupP2Pmsg` / `targetcore_startup` initialises that set. It is a **once per process**
contract, and the code has no way to notice that it has been satisfied twice in two
disjoint copies.

## What mixing actually does

- **Hubs go blind to each other.** A hub created through module A is in A's hub table.
  Module B enumerates its own table and does not see it. Routing between them fails with
  no error, because from each side the other peer simply does not exist.
- **The Dmx in-process transport breaks.** It is built entirely on
  `g_oCListP2PeerConDmx`; two lists means two disjoint in-process meshes.
- **The locks stop protecting anything.** Two `CRITICAL_SECTION`s guarding what the
  developer believed was one structure is a data race, not mutual exclusion. It will
  present as rare, load-dependent corruption, not a clean failure.
- **Instance accounting drifts**, so leak checks and shutdown ordering report nonsense.
- **Teardown double-frees or under-frees**, depending on which copy runs
  `CleanupP2Pmsg` first.

None of this shows up as a link error. That is the entire problem: the mixed build is
well-formed. Pick a shape per process and hold it.

## Corollaries

**1. Static TargetCore requires static Msgcore.** TargetCore sits on Msgcore, and
Msgcore has its own process-wide state (see `Msgcore/LINKAGE.md`). Linking the
TargetCore archive against `Msgcore.dll` puts two Msgcore heaps in the process for the
same reason. Pair `DebugLib`↔`DebugLib`, `ReleaseLib`↔`ReleaseLib`.

**2. A consumer of the archives must define BOTH macros:**

```
/DMsgcore_STATIC /DTargetCore_STATIC
```

Not just `TargetCore_STATIC`. Omitting `Msgcore_STATIC` compiles Msgcore's headers in
`dllimport` mode. Most symbols still resolve against the static Msgcore, but only behind
a wall of `LNK4217`, and **inline members of `dllimport`-decorated classes do not resolve
at all** — `P2Pevent::SetFParam(LPCTNAM, const P3PmsgItem&)` is defined inline in
`Msgcore/Msgexception.h`, so the `dllimport` view emits a call to an export the static
Msgcore never produced, and the link dies on `LNK2001`. TargetCore's own Lib
configurations define both for exactly this reason.

**3. A static archive records no dependencies.** The consumer links them:

```
MsWsock.lib ws2_32.lib comsuppw.lib Propsys.lib Bcrypt.lib      (comsuppwd.lib in Debug)
```

**4. MFC and CRT must match.** The Lib configurations keep `UseOfMfc=Dynamic` and `/MD`,
so the archive must be absorbed by a `/MD` consumer using shared MFC. A consumer that
includes `<afx.h>` under `/MD` also needs `/D_AFXDLL`.

**5. `_AFXEXT` is not defined in the Lib configurations.** It declares an MFC *extension
DLL*; an archive is not a module, runs no `DllMain` and joins no `CDynLinkLibrary`
resource chain. `dllmain.cpp` is excluded from those configurations and guards its own
body with `#if !defined(TargetCore_STATIC)`. Nothing is lost — `MANAGE_RESOURCE_STATE` is
unused across the tree, and `TargetCore.rc` holds only a `VERSIONINFO` block and one
`IDS_APP_TITLE` string.

## Choosing

**Static** fits a single-module process: CLI tools, test harnesses, a self-contained
daemon. It removes DLL deployment and staging entirely, allows cross-boundary inlining,
and lets the linker drop unreferenced code.

**Dynamic** is required whenever more than one module in the process touches the cores,
and for every non-C++ consumer — COM / ATL, the facade, .NET and PowerShell, the PHP
extension, Java Panama, the Python SDK. Those bind to an exported surface at runtime; an
archive gives them nothing.

When in doubt, use the DLL. It is the shape everything in this tree was built against,
and it is the only shape that is safe by construction.
