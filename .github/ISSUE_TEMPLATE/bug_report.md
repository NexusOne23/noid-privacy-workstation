---
name: Bug report
about: Report a bug, regression, or unexpected behaviour
title: "[bug] "
labels: bug
assignees: ''
---

**Do NOT file security-sensitive findings here.** Use the private disclosure
workflow in [`SECURITY.md`](../../SECURITY.md) instead.

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

- Build tag / commit SHA: `vX.Y.Z` or git `abc1234`
- Host OS (if building): Fedora ... or Ubuntu ...
- Build tooling version: `livemedia-creator -V` output
- Target hardware (if installing): Intel Nth gen or AMD, chipset,
  dGPU presence, LUKS yes/no, RAM/disk size

## Diagnostic data

Relevant logs:

```
# /var/log/ks-NN-modulename.log (from %post)
```

Test output:

```
# bash tests/run-all.sh
```

## Affected Module

<!-- If applicable, e.g. "Module 16 (Firefox)". -->

## Additional context

<!-- Workarounds already tried, related issues/PRs, references. -->
