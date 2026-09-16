# Contributing to Targetcore

Thank you for looking. This file is the authoritative version of the contribution policy that the
[README](Readme.md) summarises.

**Security vulnerabilities do not go here.** Follow [SECURITY.md](SECURITY.md) and use the private
channel it names. Do not open a public issue for anything with a security consequence.

---

## What is being accepted right now

**Bug reports and feedback. Not pull requests.**

That is a deliberate scope rather than a lack of interest. This is an active modernisation of a 2002
codebase: interfaces are still moving, and several long-running threads of work touch the same files
at once. An unsolicited code change is likely to collide with something already in flight, and
declining it after you have written it wastes your time more than ours.

If you want to change code, **open an issue first** and say what you intend. If it fits, you will be
told so and the collision risk gets sorted out before you start.

---

## Reporting a bug

[**Open a bug report →**](../../issues/new)

Concurrency and lifetime defects dominate this codebase — [BUGFIXES.md](BUGFIXES.md) is three worked
examples of exactly that shape. A report that says **which thread** is worth ten that do not.

A report we can act on has:

| | |
|---|---|
| **What happened** | What you did, what you expected, what happened instead |
| **Build identity** | Configuration and platform (`Release\|x64`), toolset, OS version, and whether you built the `.vcxproj` or CMake |
| **Transport** | `P2PeerConWsa`, `P2PeerConPipe`, `P2PeerCon232`, `P2PeerConDmx` |
| **Addresses** | The hub addresses involved and the message ids in play — routing bugs are almost always an addressing story |
| **Handler trace** | `On_ConStartup → On_ConConnect → …` if you have it. It pins down where the state machine stopped |
| **For a crash** | The call stack, and whether the pump thread or the caller's thread was on it |
| **For a leak** | The CRT leak dump, and whether teardown ran `CloseHub()` before `CleanupP2Pmsg()` |

### Before you file a build failure

The single most common inbound report will be a build that cannot find `Msgcore`, or the
`Platform` shim layer inside it. `Msgcore` is a **sibling directory, not a submodule** — and
since 2026-09-03 it carries `Platform\`, so there is one checkout to get right rather than
two. `WDMSCS_LIB` is an environment variable — the
README's [build section](Readme.md#building) documents the contract in full, including which of the
four distinct bindings fails in which way. Please read it first. A build report is still welcome if
the contract is satisfied and it still fails; say which of the four bindings broke.

---

## Sending feedback

[**Open a feedback issue →**](../../issues/new)

Especially welcome:

- **Does the model make sense?** Dotted-address routing, the priority queue, the handler maps. If
  the mental model did not land from the README, that is a documentation defect and we want it.
- **API friction.** Anything in the C++ surface or the flat C surface (`Targetcore_c.h`) that
  fought you. FFI reports are especially welcome — the C surface exists for consumers we cannot
  see, so friction there is invisible to us until someone says so.
- **Docs that lie.** A comment, a table or a grammar that describes something the code does not do.
  The `VNetname:` qualifier was found exactly this way, and a README row claiming an unconditional
  source-binding guarantee that had a documented exemption was found the same way. This is the most
  valuable report you can send, because it is the one class of defect that can lead someone into a
  bad deployment decision.
- **Platform reports.** Built it somewhere the README does not list? Say what broke.
- **Use cases.** Serial and DMX are lightly exercised. If you are driving hardware with this, your
  experience shapes where the work goes next.

Not a bug and not quite feedback? Open an issue anyway — the tracker is the front door.

---

## The standard this project holds itself to

Worth knowing if you plan to engage with the codebase, because it shapes what a useful report looks
like and what an answer to one will look like.

**A finding that has not been executed is a hypothesis.** This project has more than once recorded a
security finding that turned out to be already fixed, and more than once "fixed" something whose
test was measuring a stale binary. So:

- A claim about behaviour is backed by a command that was run and its output, not by reading.
- A fix ships with a check that **fails when the fix is removed** — and preferably fails the way the
  defect actually failed, not an approximation of it.
- A green test run is evidence about a **binary**, not about a source tree. Both are verified.
- Both platforms are built and run. "It mirrors the other backend" has shipped a bug here.

You are not being asked to meet that standard in a bug report. But if you say "I ran X and got Y",
that is worth far more than a diagnosis, and it is what will be asked for if you send a diagnosis
without one.

---

## Continuous integration

Two workflows, and the difference between them matters more than the fact that they exist.

[**`repo-invariants.yml`**](.github/workflows/repo-invariants.yml) runs on every push and pull
request. It is scoped to what this repository can verify *about itself*, because Targetcore does
not build on its own — `../Msgcore`, which carries the `Platform` shim layer, is a sibling in a
parent solution that is not published here. **It never compiles the library.** A green tick means the build-system
bookkeeping holds, the OpenSSL crypto core (4 of 30 translation units) passes its known-answer
vectors and its refusal paths, and `CMakeLists.txt` generates. The routing kernel, the hubs, the
pumps, all four transports and the `.vcxproj` build the README calls authoritative are not
covered. The workflow's own header lists the gaps in full; it is worth reading before you rely
on a green result.

[**`solution-build.yml`**](.github/workflows/solution-build.yml) is the one that verifies the
real build contract — configure, build and the full CTest suite across all four repositories. It
is `workflow_dispatch`-only and has no default `solution_repo`, so it fails rather than skipping
when the siblings are not supplied. That is deliberate: a job that goes green for having verified
nothing is worse than no job, and it would be a direct violation of the standard below.

[**`tools/hooks/pre-push`**](tools/hooks/README.md) keeps unverified commits, force-pushes and
deletions off `master`. It is a local hook, not branch protection — install it with
`git config core.hooksPath tools/hooks`, and read that README for what it does and does not
guarantee.

---

## Licence

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the licence this project is distributed under.
