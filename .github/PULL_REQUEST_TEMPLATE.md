<!--
  Read this before you write the code, not after.
-->

## ⚠️ Pull requests are not being accepted right now

[CONTRIBUTING.md](../CONTRIBUTING.md) is the authoritative version of this, and it is a deliberate
scope rather than a lack of interest: this is an active modernisation of a 2002 codebase, interfaces
are still moving, and several long-running threads of work touch the same files at once. An
unsolicited change is likely to collide with something already in flight, and declining it after you
have written it wastes your time more than ours.

**[Open an issue first →](../../issues/new/choose)** and say what you intend. If it fits, you will be
told so and the collision risk gets sorted out before you start.

If you were invited to send this PR, delete everything above and fill in what follows.

---

**Issue this implements:** #

### What changed, and why

<!-- What the defect or gap was, and what this does about it. -->

### Evidence

This project holds that **a finding that has not been executed is a hypothesis** — see *The standard
this project holds itself to* in [CONTRIBUTING.md](../CONTRIBUTING.md). So:

- [ ] I ran the build. Configuration, platform and toolset:
- [ ] There is a check that **fails when this change is removed** — and it fails the way the defect
      actually failed, not an approximation of it. Which check:
- [ ] I pasted the command I ran and its output below, rather than describing what it would do.
- [ ] Both platforms built and run, or I have said which one I could not do and why.
      ("It mirrors the other backend" has shipped a bug here.)

```
paste the command and its output here
```

### Surface

- [ ] This changes the flat C ABI (`Targetcore_c.h` / its `_u8` twins). If ticked,
      `.github/ci/abi-flat.manifest` is updated in the same commit.
- [ ] This changes a wire format or a version constant. If ticked,
      `.github/ci/wire-versions.manifest` is updated in the same commit.
- [ ] This changes the event catalogue (`TargetcoreEvt.mc`). If ticked, the regenerated
      `TargetcoreEvt.h` / `.rc` / `MSG00001.bin` are committed alongside it.
- [ ] This adds or removes a source file. If ticked, both `Targetcore(2026).vcxproj` and
      `CMakeLists.txt` are updated — `check_repo_invariants.py` enforces the parity.
- [ ] None of the above.

### Security consequence

- [ ] This change has none.
- [ ] This change has one, and I have **not** described it here. A flaw does not go in a public pull
      request — follow [SECURITY.md](../SECURITY.md) and use the private channel it names.

### Licence

- [ ] I agree that this contribution is licensed under the [Apache License 2.0](../LICENSE), the
      licence this project is distributed under.
