# tools/hooks

Git hooks for this repository, tracked so they can be reviewed and so a fresh clone can
install them. Git does not run anything from here until you point it at this directory —
`.git/hooks/` is what Git executes, and it is not version-controlled.

## Install

```sh
git config core.hooksPath tools/hooks
```

Per clone, and per developer. There is no way to make a hook install itself; a repository
that could run code on clone would be a supply-chain hole, not a feature.

To uninstall: `git config --unset core.hooksPath`.

## `pre-push`

Keeps three things off `master`: deletion, non-fast-forward pushes, and any commit whose
exact SHA has not already gone green in the [`repo-invariants.yml`](../../.github/workflows/repo-invariants.yml)
workflow. Other branches push freely, which is deliberate — pushing a branch is how CI gets
to run at all.

The third rule implies the workflow a server-side required-status-check would have forced:

```sh
git switch -c fix-something
git push -u origin fix-something      # CI runs on this SHA
# ... wait for green ...
git switch master
git merge --ff-only fix-something     # SHA preserved, so it stays green
git push
```

`--ff-only` is load-bearing. A merge commit is a new SHA that CI has never seen, and the
hook refuses it exactly as it refuses any other unverified commit.

## What green actually means here

Read this before treating a passed hook as "master builds". It does not mean that, and the
gap is much wider in this repository than in the sibling `Msgcore` one this hook is adapted
from.

`repo-invariants.yml` is the only workflow that runs on a push, and **it never compiles the
library.** Targetcore does not build on its own: `../Msgcore` — which carries the `Platform`
shim layer inside it since 2026-09-03 — is a peer directory in a parent solution that is not
published alongside this repository. So a green
run is exactly three claims:

| Job | What it establishes |
|---|---|
| `invariants` | The `.vcxproj` and `CMakeLists.txt` name the same sources, no `.cpp` is orphaned, the shipped Markdown links resolve, the deleted legacy crypto has not returned. Nothing is compiled. |
| `crypto-selftest` | 4 of 30 translation units — the OpenSSL crypto/identity/login/seal core — compile and pass their KATs and refusal paths. Says nothing about the CNG backend, and so nothing about whether the two backends agree on the wire. |
| `cmake-parse` | `CMakeLists.txt` parses and generates against stub siblings. Configure only. |

What that leaves uncovered is on the record in the header of
[`repo-invariants.yml`](../../.github/workflows/repo-invariants.yml): the routing kernel, the
hubs, the pumps, all four transports and the C API are never parsed; the `.vcxproj` build the
[README](../../Readme.md) calls authoritative is never invoked; the `MscsUnitTests` suite lives
in a sibling repository.

[`solution-build.yml`](../../.github/workflows/solution-build.yml) is the workflow that would
verify the real build contract, and this hook deliberately does **not** gate on it. It is
`workflow_dispatch`-only because the siblings it needs are not in this repository, so it can
never produce a run against an arbitrary pushed SHA — gating on it would refuse every push
forever. Run it by hand from the Actions tab, supplying a `solution_repo`, when you want a
real answer.

So the hook enforces *"the checks that exist were run and passed on this exact SHA"*. That is
worth having. It is not *"this commit builds"*.

## What this is not

**It is not branch protection.** It is a script on one machine, and it fails open in every
direction that matters:

- it runs only for someone who ran the install command above;
- `git push --no-verify` skips it entirely — by design, as the escape hatch standing in for
  the admin bypass GitHub would have provided;
- anyone who can push can edit or delete it.

It exists because server-side enforcement is unavailable: GitHub Free does not offer branch
protection or rulesets on **private** repositories, and both APIs answer
`403 Upgrade to GitHub Pro or make this repository public`. The options for real enforcement
are GitHub Pro, or making the repository public — and [`SECURITY.md`](../../SECURITY.md) puts
publication behind work that is not finished.

When server-side rules do become available, **replace this hook rather than keeping both**.
Two enforcement points that can disagree are worse than one that cannot be bypassed.
