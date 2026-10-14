## Change

Describe the problem and the resulting behavior. Link any relevant issue.

## Validation

List the checks run and their results; identify the tested ISO when applicable.

- [ ] `bash tests/run-all.sh` passes (89/89 structural)
- [ ] Applicable helper smoke tests pass (4/4 smoke; prepared rootfs required;
      run locally as described in [the smoke-test guide](../tests/smoke/README.md))
- [ ] Relevant documentation and user-visible changes are updated

## Security and compatibility

Describe any changed protection, privacy, compatibility or dependency behavior.
For external downloads, include the pinned identity and authenticity check.
Preserve component licenses from [LICENSING.md](../LICENSING.md), and exclude
private credentials and machine-specific information from public files.
