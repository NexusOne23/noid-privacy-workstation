# Thunderbird OAuth2 Providers — Gmail, Office365, Microsoft Entra

OAuth2 providers require an interactive browser-style authorization flow.
NoID Privacy disables JavaScript globally in Thunderbird by default, which can also
affect that embedded flow. Provider behavior and token policy are volatile.

## Profile Changes for Interactive Authorization

The NoID Privacy profile `user.js` re-applies `javascript.enabled=false` at every
startup, so an `about:config` change alone is not persistent. Put this line in
the OAuth profile's `user-overrides.js`:

```
user_pref("javascript.enabled", true);
```

With Thunderbird closed, run
`noid-thunderbird-harden-profile <registered-profile-name>`; it appends the file
after the NoID Privacy values, and every later Update All keeps it. Then retry
the provider's current authorization flow. NoID Privacy does not change
Thunderbird's cookie policy; cookies are cleared on a clean exit
(`privacy.clearOnShutdown.cookies=true`), so an interactive authorization may
be requested again after a restart.

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

Then create `~/.thunderbird/<profile-gmail>/user-overrides.js`:

```javascript
// Per-profile override for OAuth2 — JS enabled only here
user_pref("javascript.enabled", true);
```

and apply the hardening plus that override once with
`noid-thunderbird-harden-profile gmail`. Ordinary launches (app grid,
`thunderbird`, mailto links) always open `default-release`; start the isolated
profile explicitly with `thunderbird -P gmail`. The other profile (e.g. Proton)
keeps NoID Privacy defaults strict.

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
