---
name: Something else
about: Not a bug and not quite feedback. The tracker is the front door — use it.
title: ''
labels: ''
assignees: ''
---

<!--
  NOT for security vulnerabilities. A flaw with a security consequence does not go in a public
  issue: https://github.com/IvywareAU/Targetcore/security/policy names a private channel.

  If it IS a defect, the bug form asks for the things that make one actionable (build identity,
  transport, addresses, which thread):
  https://github.com/IvywareAU/Targetcore/issues/new?template=bug_report.yml

  If it is about the model, the API surface, the docs or a platform, the feedback form sorts it:
  https://github.com/IvywareAU/Targetcore/issues/new?template=feedback.yml

  Neither fits? You are in the right place. Delete this comment and write.
-->

### What this is about

<!-- A question, a design discussion, an integration you are attempting, something the docs do not
     cover, or something that does not have a name yet. -->

### What you have already looked at

<!-- Readme.md, SECURITY.md, THREAT_MODEL.md, Architecture(IOCP).md, examples.md, the worked
     examples, the docs site. Saying where you looked and did not find it is itself a report: if
     the answer was there and you did not find it, that is a documentation defect and worth
     knowing about. -->

### Context, if any of it applies

<!-- Delete what does not.

     - Version or commit
     - Platform and toolset
     - Transport: P2PeerConWsa / P2PeerConPipe / P2PeerCon232 / P2PeerConDmx
     - Whether you are on the C++ surface or the flat C surface (Targetcore_c.h)
     - What you are building on top of it -->

<!--
  Wanting to change code counts as something else, and it belongs here rather than in a pull
  request. CONTRIBUTING.md asks you to open an issue FIRST and say what you intend: interfaces are
  still moving and several long-running threads of work touch the same files at once, so an
  unsolicited change is likely to collide with something already in flight. Say what you mean to
  do and the collision risk gets sorted out before you write it.
  https://github.com/IvywareAU/Targetcore/blob/master/CONTRIBUTING.md
-->
