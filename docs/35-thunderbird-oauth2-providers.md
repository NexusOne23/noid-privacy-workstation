# Thunderbird OAuth2 Providers — Gmail, Office365, Microsoft Entra

OAuth2 providers require an interactive browser-style authorization flow.
NoID Privacy disables JavaScript globally in Thunderbird by default, which can also
affect that embedded flow. Provider behavior and token policy are volatile.

## Profile Changes for Interactive Authorization

The NoID Privacy profile `user.js` re-applies `javascript.enabled=false` at every
startup, so an `about:config` change alone is not persistent. Append this after
the repository settings in the OAuth profile's `user.js`:

```
user_pref("javascript.enabled", true);
user_pref("network.cookie.cookieBehavior", 1);
```

Restart Thunderbird and retry the provider's current authorization flow. The
cookie relaxation is only needed for flows that depend on it; remove it and
test again after authorization if the provider works without it. Re-running
`noid-thunderbird-harden-profile` replaces `user.js` after making a backup, so
reapply deliberate profile overrides afterward.

## Optional Hardening

After interactive authorization, you can test reverting `javascript.enabled`
to `false`. Ordinary refresh-token exchange does not itself require a rendered
JavaScript page, but an interactive reauthorization will. No fixed token
lifetime is claimed.

Practical approach: leave `javascript.enabled = true` for OAuth-using profiles.

## Profile-Isolation Tip

If you have multiple accounts (e.g., Proton Mail + Gmail), consider **separate Thunderbird profiles**:

```bash
thunderbird -P -no-remote
# Click "Create Profile..." → name it "gmail" or similar
```

Then in `~/.thunderbird/<profile-gmail>/user.js`:

```javascript
// Per-profile override for OAuth2 — JS enabled only here
user_pref("javascript.enabled", true);
user_pref("network.cookie.cookieBehavior", 1);
```

The other profile (e.g. Proton) keeps NoID Privacy defaults strict.

## Troubleshooting

- **"Authentication failed"**: verify the selected authentication method,
  provider policy, account identity, authorization result and the persistent
  profile overrides above; the message does not identify one universal cause.
- **"Couldn't connect to authentication server"**: inspect the actual URL,
  DNS result, VPN/WAN-strict state and certificate error. Do not weaken the
  resolver or TLS policy on the assumption that it is the cause.
- **Interactive authorization requested again**: temporarily enable JavaScript
  in that isolated profile and repeat the provider's current flow.

## See Also

- `docs/35-thunderbird-mail-setup.md` — General first-time setup
- `kickstart/snippets/35-thunderbird.ks` — Canonical AutoConfig and
  user-overridable preference architecture
