// NoID Privacy Workstation 44 — Thunderbird AutoConfig pointer
// sandbox_enabled=true: NoID Privacy's mozilla.cfg uses only defaultPref()
// calls, which work in sandbox-enabled mode. The sandbox prevents AutoConfig
// JavaScript from reading environment variables, files, the network or
// privileged Components APIs.
pref("general.config.filename", "mozilla.cfg");
pref("general.config.obscure_value", 0);
pref("general.config.sandbox_enabled", true);
