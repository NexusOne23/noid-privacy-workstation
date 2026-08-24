## Summary

<!-- 1–3 sentences: what changes and why. -->

## Pre-LOCK gate checklist

### Code gate
- [ ] `bash tests/run-all.sh` passes (84/84 structural)
- [ ] `sudo bash tests/smoke/run-all.sh` passes (4/4 smoke; prepared rootfs required — local-only gate, NOT executed by CI; see `tests/smoke/README.md`)
- [ ] `bash -n` clean on `kickstart/master.ks` and every
      `kickstart/snippets/*.ks`
- [ ] `pykickstart` clean: `ksflatten -c kickstart/master.ks -o /var/tmp/master-flat.ks && ksvalidator -v F44 /var/tmp/master-flat.ks` (if applicable)

### Docs gate
- [ ] `CHANGELOG.md` updated with user-visible changes
- [ ] `INDEX.md` updated if Module was added/removed
- [ ] Per-Module user doc heredoc shipped to
      `/usr/share/doc/noid-privacy/NN-*.md`
- [ ] `docs/known-failures.md` reviewed and updated if the change adds or
      changes a known limitation

### Supply-chain gate
- [ ] If an external download was added: exact content identity (for example,
      immutable commit or expected size + SHA-256), maintained authenticity
      check where available, and a fail-closed verifier
- [ ] Trust anchor documented in `docs/gpg-trust-chain.md`

### Privacy gate
- [ ] No author-host PII (hostnames, MACs, UUIDs, IPs, VPN keys) in
      public files

## Change classification

- [ ] New Module
- [ ] Update to existing Module (bump the dated/versioned `# Status:` line)
- [ ] Hardening regression fix
- [ ] Documentation only
- [ ] CI / test infrastructure

## Security impact

<!-- If this touches hardening behaviour, explicitly state: what attacker
class does it defend against? What does it weaken? -->

## Reproducibility impact

<!-- Does this change affect deterministic build controls, pinned inputs or
variance evidence? Do not assume the complete ISO is byte-reproducible; see
docs/build-reproducibility.md. -->

## Test plan

- [ ] `tests/run-all.sh` (required)
- [ ] New structural assertions added for new invariants (required
      for new Module)
- [ ] VM smoke test (recommended for hardening-touching changes)
- [ ] Reproducibility smoke test (required before release)

## Related issues / PRs

<!-- Reference ticket numbers, audit findings (NF-XX), CVE IDs. -->

---

By submitting this PR, I agree to:
- Preserve existing SPDX identifiers and apply the component-specific license
  documented in `LICENSING.md`; this is a multi-license repository.
- Follow the Code of Conduct.
- Ensure no PII or private credentials leak in committed code.
