---
name: Bug report
about: Report a bug, regression, or unexpected behaviour
title: "[bug] "
labels: bug
assignees: ''
---

**Do NOT file security-sensitive findings here.** Use the private disclosure
workflow in the [security policy](https://github.com/NexusOne23/noid-privacy-workstation/security/policy)
instead.

## Describe the bug

<!-- Clear description of what went wrong. -->

## To reproduce

Exact steps to reproduce:

1. `...`
2. `...`
3. `...`

## Expected behaviour

<!-- What you expected to happen. -->

## Actual behaviour

<!-- What actually happened. Include error messages, exit codes. -->

## Environment

- Build tag / commit SHA: `vX.Y[.Z]` or git `abc1234`
- Host OS (if building): Fedora 44 (other build hosts are unsupported)
- Build tooling version: `livemedia-creator -V` output
- Target hardware (if installing): Intel Nth gen or AMD, chipset,
  dGPU presence, LUKS yes/no, RAM/disk size

## Diagnostic data

Relevant logs (redact user names, host names, addresses and other
identifiers before posting):

```
# Installed system: journalctl -b -p warning
# Installer problems: /tmp/anaconda.log and /tmp/program.log in the Live
#   session, before rebooting (the installed system removes installer logs)
# Posture overview: noid-status
```

Test output:

```
# bash tests/run-all.sh
```

## Affected Module

<!-- If applicable, e.g. "Module 16 (Firefox)". -->

## Additional context

<!-- Workarounds already tried, related issues/PRs, references. -->
