/******
*    name: NoID Privacy Workstation — Firefox Hardening
* version: 1.0.0 (derived from arkenfox user.js v144.0)
*   image: NoID Privacy Workstation 44 — LAN-isolated, WAN-only
*    repo: https://github.com/NexusOne23/noid-privacy-workstation
* copyright: Copyright (c) 2026 NoID Privacy contributors
* license: MIT (combined derivative; full notice retained below)
*
* UPSTREAM ATTRIBUTION:
*   Derived from arkenfox/user.js v144.0 (2026-04-20)
*   Upstream: https://github.com/arkenfox/user.js
*   Upstream license: MIT (full notice retained below and installed at
*   /usr/share/licenses/noid-privacy/arkenfox-user.js-MIT.txt)
*   Upstream maintainers: @Thorin-Oakenpants, @earthlng (credited in full)
*
* NoID Privacy MODIFICATIONS:
*   - Consolidated arkenfox base + NoID Privacy image-scope overrides into
*     one single file (no separate user-overrides.js). Merge happens at
*     image build time, not at browser startup.
*   - Eliminated arkenfox updater.sh dependency — image ships this file
*     directly. System updates (noid-update-all.sh) re-apply from image.
*   - Rebranded parrot marker values to distinguish from upstream arkenfox
*     (the pref key `_user.js.parrot` is unchanged for tool compatibility;
*     only its START/COMPLETE values identify as NoID Privacy — visible in
*     `about:support`).
*   - ETP-Strict compatibility allowlist disabled by default (tighter than
*     Mozilla Strict Mode). This can improve tracker blocking but may break
*     compatibility on allowlisted sites; rationale is documented inline.
*   - NoID Privacy-specific overrides: FPP with Canvas/WebGL randomization active,
*     provider-compatible system/VPN DNS by default, Firefox's native site
*     isolation retained, current Mozilla AI enhancements blocked through
*     their maintained controls, extension-provided ML disabled, Nimbus
*     experiments neutralized, and the Normandy user_id cleared.
*
* MAINTENANCE MODEL:
*   This file is maintained by the NoID Privacy project. Firefox release notes,
*   source defaults and affected runtime behavior are reviewed for each image
*   update. The image consumes no live GitHub dependency at browser startup;
*   source changes remain reviewable in repository history.
*
* NO WARRANTY — this hardening is best-effort. Always read through changes
* before applying to a profile you care about. Backup prefs.js before any
* major Firefox version upgrade. The absorbed arkenfox v144 base is supplemented
* by the NoID Privacy-owned POST-v144 section below and release-note review recorded in
* repository history. Firefox 152 review added explicit GMP/Widevine updater
* suppression because the browser-idle task can otherwise fetch metadata before
* DRM consent. Firefox 153 review added the Section 9003 ASRouter provider
* defaults; its Local Network Access default is already explicit and stricter
* here, while Smart Window remains covered by Module 16's
* browser.ai.control.default="blocked" AutoConfig master. Firefox 154
* release-note review added the explicit LNA WebSocket arm
* (network.lna.websocket.enabled); the release's other additions (smart tab
* groups, AI quick action, profile backup, iframe translations) were verified
* already covered by the existing AI-control and translation blocks.
*
* README / USAGE:
*   Consider using Tor Browser or Mullvad Browser if your threat model
*   requires anonymity (not just privacy) — see docs/threat-model.md of
*   NoID Privacy Workstation for the distinction. This hardening targets
*   privacy and fingerprinting resistance within that documented threat model,
*   NOT anonymity.
*
* INDEX (inherited from arkenfox v144):
*   0100: STARTUP                    2000: PLUGINS / MEDIA / WEBRTC
*   0200: GEOLOCATION                2400: DOM (DOCUMENT OBJECT MODEL)
*   0300: QUIETER FOX                2600: MISCELLANEOUS
*   0400: SAFE BROWSING              2700: ETP (ENHANCED TRACKING)
*   0600: BLOCK IMPLICIT OUTBOUND    2800: SHUTDOWN & SANITIZING
*   0700: DNS / DoH / PROXY / SOCKS  4000: FPP (fingerprintingProtection)
*   0800: LOCATION BAR / SEARCH      4500: OPTIONAL RFP (resistFingerprint)
*   0900: PASSWORDS / PASSKEYS       5000: OPTIONAL OPSEC
*   1000: DISK AVOIDANCE             5500: OPTIONAL HARDENING
*   1200: HTTPS (SSL/TLS / OCSP)     6000: DON'T TOUCH
*   1600: REFERERS                   7000: DON'T BOTHER
*   1700: CONTAINERS                 8000: DON'T BOTHER: FP
*                                    8500: TELEMETRY
*                                    9000: NON-PROJECT RELATED
*                                    9999: DEPRECATED / RENAMED
*   NOID: sections beyond 9999 = NoID Privacy specific overrides
******/

/* ARKENFOX MIT NOTICE BEGIN
MIT License

Copyright (c) 2020 arkenfox

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
ARKENFOX MIT NOTICE END */

user_pref("_user.js.parrot", "START: NoID Privacy Workstation — derived from arkenfox v144");

/* 0000: disable about:config warning ***/
user_pref("browser.aboutConfig.showWarning", false);

/*** [SECTION 0100]: STARTUP ***/
user_pref("_user.js.parrot", "0100 syntax error: the parrot's dead!");
/* 0102: set startup page [SETUP-CHROME]
 * 0=blank, 1=home, 2=last visited page, 3=resume previous session
 * [NOTE] Session Restore is cleared if history is also cleared (2811+), and not used in Private Browsing mode
 * [SETTING] General>Startup>Restore previous session
 * NoID Privacy's initial value is an AutoConfig default in Module 16 so a
 * later user choice survives Firefox restarts and Update All. ***/
/* 0103: set HOME+NEWWINDOW page
 * about:home=Firefox Home (default, see 0105), custom URLs..., Blank Page
 * [SETTING] Home>New Windows and Tabs>Homepage and new windows
 * The initial about:home value is supplied by Module 16, not profile user.js. ***/
/* 0104: set NEWTAB page
 * true=Firefox Home (default, see 0105), false=blank page
 * [SETTING] Home>New Windows and Tabs>New tabs
 * The initial enabled value is supplied by Module 16, not profile user.js. ***/
/* 0105: disable sponsored content on Firefox Home (Activity Stream)
 * [SETTING] Home>Firefox Home Content
 * Module 16 supplies the three off-state defaults without overriding a later
 * explicit choice in Firefox Home settings. ***/
/* 0106: clear default topsites
 * [NOTE] This does not block you from adding your own ***/
user_pref("browser.newtabpage.activity-stream.default.sites", "");

/*** [SECTION 0200]: GEOLOCATION ***/
user_pref("_user.js.parrot", "0200 syntax error: the parrot's definitely deceased!");
/* 0202: disable Fedora's OS geolocation service ***/
user_pref("geo.provider.use_geoclue", false); // [FF102+] [LINUX]

/*** [SECTION 0300]: QUIETER FOX ***/
user_pref("_user.js.parrot", "0300 syntax error: the parrot's not pinin' for the fjords!");
/** RECOMMENDATIONS ***/
/* 0320: disable recommendation pane in about:addons (uses Google Analytics) ***/
user_pref("extensions.getAddons.showPane", false); // [HIDDEN PREF]
/* 0321: disable recommendations in about:addons' Extensions and Themes panes [FF68+] ***/
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
/* 0322: disable personalized Extension Recommendations in about:addons and AMO [FF65+]
 * [NOTE] This pref has no effect when Health Reports (8501) are disabled
 * [SETTING] Privacy & Security>Firefox Data Collection and Use>Allow personalized extension recommendations
 * [1] https://support.mozilla.org/kb/personalized-extension-recommendations ***/
user_pref("browser.discovery.enabled", false);

/** ACTIVITY STREAM ***/
/* 0335: disable Firefox Home (Activity Stream) telemetry ***/
user_pref("browser.newtabpage.activity-stream.telemetry", false);

/** STUDIES ***/
/* 0340: disable Studies
 * [SETTING] Privacy & Security>Firefox Data Collection and Use>Install and run studies ***/
user_pref("app.shield.optoutstudies.enabled", false);
/* 0341: disable Normandy/Shield [FF60+]
 * Shield is a telemetry system that can push and test "recipes"
 * [1] https://mozilla.github.io/normandy/ ***/
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

/** CRASH REPORTS ***/
/* 0350: disable Crash Reports ***/
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false); // [FF44+]
   // user_pref("browser.crashReports.unsubmittedCheck.enabled", false); // [FF51+] [DEFAULT: false]
/* 0351: enforce no submission of backlogged Crash Reports [FF58+]
 * [SETTING] Privacy & Security>Firefox Data Collection and Use>Send backlogged crash reports  ***/
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // [DEFAULT: false]

/** OTHER ***/
/* 0360: disable Captive Portal detection
 * [1] https://www.eff.org/deeplinks/2017/08/how-captive-portals-interfere-wireless-security-and-privacy ***/
user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false); // [FF52+]
/* 0361: disable Network Connectivity checks [FF65+]
 * [1] https://bugzilla.mozilla.org/1460537 ***/
user_pref("network.connectivity-service.enabled", false);

/*** [SECTION 0400]: SAFE BROWSING (SB)
   Firefox uses locally updated URL-classifier lists for phishing, malware,
   blocked-URI and download checks. Some Safe Browsing mechanisms can request
   hash completions or use privacy-preserving real-time transport; the separate
   per-download application-reputation request is controlled independently.

   [1] https://searchfox.org/firefox-main/source/toolkit/components/url-classifier/SafeBrowsing.sys.mjs
   [2] https://support.mozilla.org/kb/how-does-phishing-and-malware-protection-work
   [3] https://developers.google.com/safe-browsing/reference
***/
user_pref("_user.js.parrot", "0400 syntax error: the parrot's passed on!");
/* 0401: disable SB (Safe Browsing)
 * [WARNING] Do this at your own risk! These are the master switches
 * [SETTING] Privacy & Security>Security>... Block dangerous and deceptive content ***/
   // user_pref("browser.safebrowsing.malware.enabled", false);
   // user_pref("browser.safebrowsing.phishing.enabled", false);
/* 0402: disable SB checks for downloads (both local lookups + remote)
 * This is the master switch for the safebrowsing.downloads* prefs (0403, 0404)
 * [SETTING] Privacy & Security>Security>... "Block dangerous downloads" ***/
   // user_pref("browser.safebrowsing.downloads.enabled", false);
/* 0403: disable SB checks for downloads (remote)
 * To verify the safety of certain executable files, Firefox may submit some information about the
 * file, including the name, origin, size and a cryptographic hash of the contents, to the Google
 * Safe Browsing service which helps Firefox determine whether or not the file should be blocked
 * [SETUP-SECURITY] If you do not understand this, or you want this protection, then override this ***/
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
   // user_pref("browser.safebrowsing.downloads.remote.url", ""); // Defense-in-depth
/* Keep local malware/phishing, blocked-URI and download-list protection active.
 * The separate full per-download reputation request above remains disabled.
 * List-update control stays at Mozilla's maintained default (enabled). ***/
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.downloads.enabled", true);
user_pref("browser.safebrowsing.blockedURIs.enabled", true);
/* 0404: disable SB checks for unwanted software
 * [SETTING] Privacy & Security>Security>... "Warn you about unwanted and uncommon software" ***/
   // user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", false);
   // user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);
/* 0405: disable "ignore this warning" on SB warnings [FF45+]
 * If clicked, it bypasses the block for that session. This is a means for admins to enforce SB
 * [TEST] see https://github.com/arkenfox/user.js/wiki/Appendix-A-Test-Sites#-mozilla
 * [1] https://bugzilla.mozilla.org/1226490 ***/
   // user_pref("browser.safebrowsing.allowOverride", false);

/*** [SECTION 0600]: BLOCK IMPLICIT OUTBOUND [not explicitly asked for - e.g. clicked on] ***/
user_pref("_user.js.parrot", "0600 syntax error: the parrot's no more!");
/* 0601: disable link prefetching
 * [1] https://developer.mozilla.org/docs/Web/HTTP/Link_prefetching_FAQ ***/
user_pref("network.prefetch-next", false);
/* 0602: disable DNS prefetching
 * [1] https://developer.mozilla.org/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control ***/
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
/* 0604: disable link-mouseover opening connection to linked server
 * [1] https://news.slashdot.org/story/15/08/14/2321202/how-to-quash-firefoxs-silent-requests ***/
user_pref("network.http.speculative-parallel-limit", 0);
/* 0605: disable mousedown speculative connections on bookmarks and history [FF98+] ***/
user_pref("browser.places.speculativeConnect.enabled", false);
/* 0610: enforce no "Hyperlink Auditing" (click tracking)
 * [1] https://www.bleepingcomputer.com/news/software/major-browsers-to-prevent-disabling-of-click-tracking-privacy-risk/ ***/
   // user_pref("browser.send_pings", false); // [DEFAULT: false]

/*** [SECTION 0700]: DNS / DoH / PROXY / SOCKS ***/
user_pref("_user.js.parrot", "0700 syntax error: the parrot's given up the ghost!");
/* 0702: set the proxy server to do any DNS lookups when using SOCKS
 * e.g. in Tor, this stops your local DNS server from knowing your Tor destination
 * as a remote Tor node will handle the DNS request
 * [1] https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers ***/
user_pref("network.proxy.socks_remote_dns", true);
/* 0703: disable using UNC (Uniform Naming Convention) paths [FF61+]
 * [SETUP-CHROME] Can break extensions for profiles on network shares
 * [1] https://bugzilla.mozilla.org/1413868 ***/
user_pref("network.file.disable_unc_paths", true); // [HIDDEN PREF]
/* 0705: disable proxy direct failover for system requests [FF91+]
 * [WARNING] Default true is a security feature against malicious extensions [1]
 * [SETUP-CHROME] If you use a proxy and you trust your extensions
 * [1] https://blog.mozilla.org/security/2021/10/25/securing-the-proxy-api-for-firefox-add-ons/ ***/
   // user_pref("network.proxy.failover_direct", false);
/* 0706: disable proxy bypass for system request failures [FF95+]
 * RemoteSettings, UpdateService, Telemetry [1]
 * [WARNING] If false, this will break the fallback for some security features
 * [SETUP-CHROME] If you use a proxy and you understand the security impact
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1732792,1733994,1733481 ***/
   // user_pref("network.proxy.allow_bypass", false);
/* 0710: enable DNS-over-HTTPS (DoH) [FF60+]
 * 0=default, 2=increased (TRR (Trusted Recursive Resolver) first), 3=max (TRR only), 5=off (no rollout)
 * see "doh-rollout.home-region": USA 2019, Canada 2021, Russia/Ukraine 2022 [3]
 * [SETTING] Privacy & Security>DNS over HTTPS
 * [1] https://hacks.mozilla.org/2018/05/a-cartoon-intro-to-dns-over-https/
 * [2] https://wiki.mozilla.org/Security/DOH-resolver-policy
 * [3] https://support.mozilla.org/kb/firefox-dns-over-https
 * [4] https://www.eff.org/deeplinks/2020/12/dns-doh-and-odoh-oh-my-year-review-2020 ***/
   // user_pref("network.trr.mode", 3);
/* 0712: set DoH provider
 * The custom uri is the value shown when you "Choose provider>Custom>"
 * [NOTE] If you USE custom then "network.trr.uri" should be set the same
 * [SETTING] Privacy & Security>DNS over HTTPS>Increased/Max>Choose provider ***/
   // user_pref("network.trr.uri", "https://example.dns");
   // user_pref("network.trr.custom_uri", "https://example.dns");

/*** [SECTION 0800]: LOCATION BAR / SEARCH BAR / SUGGESTIONS / HISTORY / FORMS ***/
user_pref("_user.js.parrot", "0800 syntax error: the parrot's ceased to be!");
/* 0801: disable location bar making speculative connections [FF56+]
 * [1] https://bugzilla.mozilla.org/1348275 ***/
user_pref("browser.urlbar.speculativeConnect.enabled", false);
/* 0802: disable location bar contextual suggestions
 * [NOTE] The UI is controlled by the .enabled pref
 * [SETTING] Search>Address Bar>Suggestions from...
 * [1] https://blog.mozilla.org/data/2021/09/15/data-and-firefox-suggest/ ***/
user_pref("browser.urlbar.quicksuggest.enabled", false); // [FF92+]
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false); // [FF95+]
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false); // [FF92+]
/* 0803: disable live search suggestions
 * [NOTE] Both must be true for live search to work in the location bar
 * [SETUP-CHROME] Override these if you trust and use a privacy respecting search engine
 * [SETTING] Search>Show search suggestions | Show search suggestions in address bar results ***/
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
/* 0805: disable urlbar trending search suggestions [FF118+]
 * [SETTING] Search>Search Suggestions>Show trending search suggestions (FF119) ***/
user_pref("browser.urlbar.trending.featureGate", false);
/* 0806: disable urlbar suggestions ***/
user_pref("browser.urlbar.addons.featureGate", false); // [FF115+]
user_pref("browser.urlbar.amp.featureGate", false); // [FF141+] adMarketplace
user_pref("browser.urlbar.importantDates.featureGate", false); // [FF143+]
user_pref("browser.urlbar.market.featureGate", false); // [FF143+] stock market
user_pref("browser.urlbar.mdn.featureGate", false); // [FF117+]
   // NoID Privacy's user-overridable weather default is supplied by Module 16
user_pref("browser.urlbar.wikipedia.featureGate", false); // [FF141+]
user_pref("browser.urlbar.yelp.featureGate", false); // [FF124+]
user_pref("browser.urlbar.yelpRealtime.featureGate", false); // [FF144+]
/* 0807: disable urlbar clipboard suggestions [FF118+] ***/
   // user_pref("browser.urlbar.clipboard.featureGate", false);
/* 0808: disable recent searches [FF120+]
 * [NOTE] Recent searches are cleared if history is cleared (2811+)
 * [1] https://support.mozilla.org/kb/search-suggestions-firefox ***/
   // user_pref("browser.urlbar.recentsearches.featureGate", false);
/* 0810: disable search and form history
 * [NOTE] We also clear formdata on exit (2811+)
 * [SETUP-WEB] Be aware that autocomplete form data can be read by third parties [1][2]
 * [SETTING] Privacy & Security>History>Custom Settings>Remember search and form history
 * [1] https://blog.mindedsecurity.com/2011/10/autocompleteagain.html
 * [2] https://bugzilla.mozilla.org/381681 ***/
user_pref("browser.formfill.enable", false);
/* 0815: disable tab-to-search [FF85+]
 * Alternatively, you can exclude on a per-engine basis by unchecking them in Options>Search
 * [SETTING] Search>Address Bar>When using the address bar, suggest>Search engines ***/
   // user_pref("browser.urlbar.suggest.engines", false);
/* 0820: disable coloring of visited links
 * [SETUP-HARDEN] Bulk rapid history sniffing was mitigated in 2010 [1][2]. Slower and more expensive
 * redraw timing attacks were largely mitigated in FF77+ [3]. Using RFP (4501) further hampers timing
 * attacks. History can also be cleared on exit (2811+). However, social engineering [2#limits][4][5]
 * and advanced targeted timing attacks could still produce usable results
 * [1] https://developer.mozilla.org/docs/Web/CSS/Privacy_and_the_:visited_selector
 * [2] https://dbaron.org/mozilla/visited-privacy
 * [3] https://bugzilla.mozilla.org/1632765
 * [4] https://earthlng.github.io/testpages/visited_links.html (see github wiki APPENDIX A on how to use)
 * [5] https://lcamtuf.blogspot.com/2016/08/css-mix-blend-mode-is-bad-for-keeping.html ***/
   // user_pref("layout.css.visited_links_enabled", false);
/* 0830: enable separate default search engine in Private Windows and its UI setting
 * [SETTING] Search>Default Search Engine>Choose a different default search engine for Private Windows only
 * Module 16 seeds both as user-overridable defaults. ***/

/*** [SECTION 0900]: PASSWORDS / PASSKEYS
   [1] https://support.mozilla.org/kb/use-primary-password-protect-stored-logins-and-pas
***/
user_pref("_user.js.parrot", "0900 syntax error: the parrot's expired!");
/* 0903: disable auto-filling username & password form fields
 * can leak in cross-site forms *and* be spoofed
 * [NOTE] Username & password is still available when you enter the field
 * [SETTING] Privacy & Security>Passwords>Autofill logins and passwords
 * [1] https://freedom-to-tinker.com/2017/12/27/no-boundaries-for-user-identities-web-trackers-exploit-browser-login-managers/
 * [2] https://homes.esat.kuleuven.be/~asenol/leaky-forms/ ***/
user_pref("signon.autofillForms", false);
/* 0904: disable formless login capture for Password Manager [FF51+] ***/
user_pref("signon.formlessCapture.enabled", false);
/* 0905: limit (or disable) HTTP authentication credentials dialogs triggered by sub-resources [FF41+]
 * hardens against potential credentials phishing
 * 0 = don't allow sub-resources to open HTTP authentication credentials dialogs
 * 1 = don't allow cross-origin sub-resources to open HTTP authentication credentials dialogs
 * 2 = allow sub-resources to open HTTP authentication credentials dialogs (default) ***/
user_pref("network.auth.subresource-http-auth-allow", 1);
/* 0906: enforce no automatic authentication on Microsoft sites [FF91+] [WINDOWS 10+]
 * [SETTING] Privacy & Security>Logins and Passwords>Allow Windows single sign-on for...
 * [1] https://support.mozilla.org/kb/windows-sso ***/
   // user_pref("network.http.windows-sso.enabled", false); // [DEFAULT: false]
/* 0907: enforce no automatic authentication on Microsoft sites [FF131+] [MAC]
 * On macOS, SSO only works on corporate devices ***/
   // user_pref("network.http.microsoft-entra-sso.enabled", false); // [DEFAULT: false]
/* 0910: enforce no direct attestation in passkeys [FF144+]
   // [1] https://bugzilla.mozilla.org/show_bug.cgi?id=1981587 ***/
user_pref("security.webauthn.always_allow_direct_attestation", false); // [DEFAULT: false]

/*** [SECTION 1000]: DISK AVOIDANCE ***/
user_pref("_user.js.parrot", "1000 syntax error: the parrot's gone to meet 'is maker!");
/* 1001: disable disk cache
 * [NOTE] We also clear cache on exit (2811+)
 * [SETUP-CHROME] If you think disk cache helps perf, then feel free to override this ***/
user_pref("browser.cache.disk.enable", false);
/* 1002: set media cache in Private Browsing to in-memory and increase its maximum size
 * [NOTE] MSE (Media Source Extensions) are already stored in-memory in PB ***/
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true); // [FF75+]
user_pref("media.memory_cache_max_size", 65536);
/* 1003: disable storing extra session data [SETUP-CHROME]
 * define on which sites to save extra session data such as form content, cookies and POST data
 * 0=everywhere, 1=unencrypted sites, 2=nowhere ***/
user_pref("browser.sessionstore.privacy_level", 2);
/*** [SECTION 1200]: HTTPS (SSL/TLS / OCSP / CERTS / HPKP)
   Your cipher and other settings can be used in server side fingerprinting
   [TEST] https://www.ssllabs.com/ssltest/viewMyClient.html
   [TEST] https://browserleaks.com/ssl
   [TEST] https://ja3er.com/
   [1] https://www.securityartwork.es/2017/02/02/tls-client-fingerprinting-with-bro/
***/
user_pref("_user.js.parrot", "1200 syntax error: the parrot's a stiff!");
/** SSL (Secure Sockets Layer) / TLS (Transport Layer Security) ***/
/* 1201: require safe negotiation
 * Blocks connections to servers that don't support RFC 5746 [2] as they're potentially vulnerable to a
 * MiTM attack [3]. A server without RFC 5746 can be safe from the attack if it disables renegotiations
 * but the problem is that the browser can't know that. Setting this pref to true is the only way for the
 * browser to ensure there will be no unsafe renegotiations on the channel between the browser and the server
 * [SETUP-WEB] SSL_ERROR_UNSAFE_NEGOTIATION: is it worth overriding this for that one site?
 * [STATS] SSL Labs (Nov 2025) reports almost 99.85% of top sites have secure renegotiation [4]
 * [1] https://wiki.mozilla.org/Security:Renegotiation
 * [2] https://datatracker.ietf.org/doc/html/rfc5746
 * [3] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3555
 * [4] https://www.ssllabs.com/ssl-pulse/ ***/
user_pref("security.ssl.require_safe_negotiation", true);
/* 1206: disable TLS1.3 0-RTT (round-trip time) [FF51+]
 * This data is not forward secret, as it is encrypted solely under keys derived using
 * the offered PSK. There are no guarantees of non-replay between connections
 * [1] https://github.com/tlswg/tls13-spec/issues/1001
 * [2] https://www.rfc-editor.org/rfc/rfc9001.html#name-replay-attacks-with-0-rtt
 * [3] https://blog.cloudflare.com/tls-1-3-overview-and-q-and-a/ ***/
user_pref("security.tls.enable_0rtt_data", false);

/** CERTS / HPKP (HTTP Public Key Pinning) ***/
/* 1223: enable strict PKP (Public Key Pinning)
 * 0=disabled, 1=allow user MiTM (default; such as your antivirus), 2=strict
 * [SETUP-WEB] MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE ***/
user_pref("security.cert_pinning.enforcement_level", 2);
/* 1224: enable CRLite [FF73+]
 * 0 = disabled
 * 1 = consult CRLite but only collect telemetry
 * 2 = consult CRLite and enforce both "Revoked" and "Not Revoked" results (default)
 * 3 = consult CRLite and enforce "Not Revoked" results, but defer to OCSP for "Revoked" (removed FF145)
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1429800,1670985,1753071
 * [2] https://blog.mozilla.org/security/tag/crlite/
 * [3] https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/ ***/
user_pref("security.remote_settings.crlite_filters.enabled", true); // [DEFAULT: true]
user_pref("security.pki.crlite_mode", 2); // [DEFAULT: 2 FF142+]

/** MIXED CONTENT ***/
/* 1241: disable insecure passive content (such as images) on https pages ***/
   // user_pref("security.mixed_content.block_display_content", true); // Defense-in-depth (see 1244)
/* 1244: enable HTTPS-Only mode in all windows
 * When the top-level is HTTPS, insecure subresources are also upgraded (silent fail)
 * [SETTING] to add site exceptions: Padlock>HTTPS-Only mode>On (after "Continue to HTTP Site")
 * [SETTING] Privacy & Security>HTTPS-Only Mode (and manage exceptions)
 * [TEST] http://example.com [upgrade]
 * [TEST] http://httpforever.com/ | http://http.rip [no upgrade] ***/
user_pref("dom.security.https_only_mode", true); // [FF76+]
   // user_pref("dom.security.https_only_mode_pbm", true); // [FF80+]
/* 1245: enable HTTPS-Only mode for local resources [FF77+] ***/
   // user_pref("dom.security.https_only_mode.upgrade_local", true);
/* 1246: disable HTTP background requests [FF82+]
 * When attempting to upgrade, if the server doesn't respond within 3 seconds, Firefox sends
 * a top-level HTTP request without path in order to check if the server supports HTTPS or not
 * This is done to avoid waiting for a timeout which takes 90 seconds
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1642387,1660945 ***/
user_pref("dom.security.https_only_mode_send_http_background_request", false);

/** UI (User Interface) ***/
/* 1270: display warning on the padlock for "broken security" (if 1201 is false)
 * Bug: warning padlock not indicated for subresources on a secure page! [2]
 * [1] https://wiki.mozilla.org/Security:Renegotiation
 * [2] https://bugzilla.mozilla.org/1353705 ***/
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
/* 1272: display advanced information on Insecure Connection warning pages
 * only works when it's possible to add an exception
 * i.e. it doesn't work for HSTS discrepancies (https://subdomain.preloaded-hsts.badssl.com/)
 * [TEST] https://expired.badssl.com/ ***/
user_pref("browser.xul.error_pages.expert_bad_cert", true);

/*** [SECTION 1600]: REFERERS
                  full URI: https://example.com:8888/foo/bar.html?id=1234
     scheme+host+port+path: https://example.com:8888/foo/bar.html
          scheme+host+port: https://example.com:8888
   [1] https://feeding.cloud.geek.nz/posts/tweaking-referrer-for-privacy-in-firefox/
***/
user_pref("_user.js.parrot", "1600 syntax error: the parrot rests in peace!");
/* 1602: control the amount of cross-origin information to send [FF52+]
 * 0=send full URI (default), 1=scheme+host+port+path, 2=scheme+host+port ***/
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

/*** [SECTION 1700]: CONTAINERS ***/
user_pref("_user.js.parrot", "1700 syntax error: the parrot's bit the dust!");
/* 1701: enable Container Tabs and its UI setting [FF50+]
 * [SETTING] General>Tabs>Enable Container Tabs
 * https://wiki.mozilla.org/Security/Contextual_Identity_Project/Containers ***/
user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.ui.enabled", true);
/* 1702: set behavior on "+ Tab" button to display container menu on left click [FF74+]
 * [NOTE] The menu is always shown on long press and right click
 * [SETTING] General>Tabs>Enable Container Tabs>Settings>Select a container for each new tab ***/
   // user_pref("privacy.userContext.newTabContainerOnLeftClick.enabled", true);
/* 1703: set external links to open in site-specific containers [FF123+]
 * [SETUP-WEB] Depending on your container extension(s) and their settings
 * true=Firefox will not choose a container (so your extension can)
 * false=Firefox will choose the container/no-container (default)
 * [1] https://bugzilla.mozilla.org/1874599 ***/
   // user_pref("browser.link.force_default_user_context_id_for_external_opens", true);

/*** [SECTION 2000]: PLUGINS / MEDIA / WEBRTC ***/
user_pref("_user.js.parrot", "2000 syntax error: the parrot's snuffed it!");
/* 2002: force WebRTC inside the proxy [FF70+] ***/
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
/* 2003: force a single network interface for ICE candidates generation [FF42+]
 * When using a system-wide proxy, it uses the proxy interface
 * [1] https://developer.mozilla.org/docs/Web/API/RTCIceCandidate
 * [2] https://wiki.mozilla.org/Media/WebRTC/Privacy ***/
user_pref("media.peerconnection.ice.default_address_only", true);
/* 2004: force exclusion of private IPs from ICE candidates [FF51+]
 * [SETUP-HARDEN] This will protect your private IP even in TRUSTED scenarios after you
 * grant device access, but often results in breakage on video-conferencing platforms ***/
   // user_pref("media.peerconnection.ice.no_host", true);
/* 2020: disable GMP (Gecko Media Plugins)
 * [1] https://wiki.mozilla.org/GeckoMediaPlugins ***/
   // user_pref("media.gmp-provider.enabled", false);

/*** [SECTION 2400]: DOM (DOCUMENT OBJECT MODEL) ***/
user_pref("_user.js.parrot", "2400 syntax error: the parrot's kicked the bucket!");
/* 2402: prevent scripts from moving and resizing open windows ***/
user_pref("dom.disable_window_move_resize", true);

/*** [SECTION 2600]: MISCELLANEOUS ***/
user_pref("_user.js.parrot", "2600 syntax error: the parrot's run down the curtain!");
/* 2603: remove temp files opened from non-PB windows with an external application
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=302433,1738574 ***/
user_pref("browser.download.start_downloads_in_tmp_dir", true); // [FF102+]
user_pref("browser.helperApps.deleteTempFileOnExit", true);
/* 2606: disable UITour backend so there is no chance that a remote page can use it ***/
user_pref("browser.uitour.enabled", false);
   // user_pref("browser.uitour.url", ""); // Defense-in-depth
/* 2608: reset remote debugging to disabled
 * [1] https://gitlab.torproject.org/tpo/applications/tor-browser/-/issues/16222 ***/
user_pref("devtools.debugger.remote-enabled", false); // [DEFAULT: false]
/* 2615: disable websites overriding Firefox's keyboard shortcuts [FF58+]
 * 0 (default) or 1=allow, 2=block
 * [SETTING] to add site exceptions: Ctrl+I>Permissions>Override Keyboard Shortcuts ***/
   // user_pref("permissions.default.shortcuts", 2);
/* 2616: remove special permissions for certain mozilla domains [FF35+]
 * [1] resource://app/defaults/permissions ***/
user_pref("permissions.manager.defaultsUrl", "");
/* 2619: use Punycode in Internationalized Domain Names to eliminate possible spoofing
 * [SETUP-WEB] Might be undesirable for non-latin alphabet users since legitimate IDN's are also punycoded
 * [TEST] https://www.xn--80ak6aa92e.com/ (www.apple.com)
 * [1] https://wiki.mozilla.org/IDN_Display_Algorithm
 * [2] https://en.wikipedia.org/wiki/IDN_homograph_attack
 * [3] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=punycode+firefox
 * [4] https://www.xudongz.com/blog/2017/idn-phishing/ ***/
user_pref("network.IDN_show_punycode", true);
/* 2620: enforce PDFJS, disable PDFJS scripting
 * This setting controls if the option "Display in Firefox" is available in the setting below
 *   and by effect controls whether PDFs are handled in-browser or externally ("Ask" or "Open With")
 * [WHY] The built-in viewer avoids handing an untrusted PDF to another desktop
 *   application and stays inside Firefox's content-process isolation. Disabling
 *   PDF scripting reduces its active-content surface. Users may still save a
 *   document or select a separate reader when their workflow requires it.
 * [NOTE] JS can still force a pdf to open in-browser by bundling its own code
 * [SETUP-CHROME] You may prefer a different pdf reader for security/workflow reasons
 * [SETTING] General>Applications>Portable Document Format (PDF)
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=pdf.js+firefox ***/
user_pref("pdfjs.disabled", false); // [DEFAULT: false]
user_pref("pdfjs.enableScripting", false); // [FF86+]
/* 2624: disable middle click on new tab button opening URLs or searches using clipboard [FF115+] ***/
user_pref("browser.tabs.searchclipboardfor.middleclick", false); // [DEFAULT: false NON-LINUX]
/* 2630: disable content analysis by DLP (Data Loss Prevention) agents
 * DLP agents are background processes on managed computers that allow enterprises to monitor locally running
 * applications for data exfiltration events, which they can allow/block based on customer defined DLP policies.
 * 0=Block all requests, 1=Warn on all requests (which lets the user decide), 2=Allow all requests
 * [1] https://github.com/chromium/content_analysis_sdk ***/
user_pref("browser.contentanalysis.enabled", false); // [FF121+] [DEFAULT: false]
user_pref("browser.contentanalysis.default_result", 0); // [FF127+] [DEFAULT: 0]
/* 2635: disable referrer and storage access for resources injected by content scripts [FF139+] ***/
user_pref("privacy.antitracking.isolateContentScriptResources", true);
/* 2640: disable CSP Level 2 Reporting [FF140+] ***/
user_pref("security.csp.reporting.enabled", false);

/** DOWNLOADS ***/
/* 2651: enable user interaction for security by always asking where to download
 * [SETUP-CHROME] On Android this blocks longtapping and saving images
 * [SETTING] General>Downloads>Always ask you where to save files ***/
user_pref("browser.download.useDownloadDir", false);
/* 2652: disable downloads panel opening on every download [FF96+] ***/
user_pref("browser.download.alwaysOpenPanel", false);
/* 2653: disable adding downloads to the system's "recent documents" list ***/
user_pref("browser.download.manager.addToRecentDocs", false);
/* 2654: enable user interaction for security by always asking how to handle new mimetypes [FF101+]
 * [SETTING] General>Files and Applications>What should Firefox do with other files ***/
user_pref("browser.download.always_ask_before_handling_new_types", true);

/** EXTENSIONS ***/
/* 2660: limit allowed extension directories
 * 1=profile, 2=user, 4=application, 8=system, 16=temporary, 31=all
 * The pref value represents the sum: e.g. 5 would be profile and application directories
 * [SETUP-CHROME] Breaks usage of files which are installed outside allowed directories
 * [1] https://archive.is/DYjAM ***/
user_pref("extensions.enabledScopes", 5); // [HIDDEN PREF]
/* Permit profile-scope extensions installed by the reviewed NoID Privacy helper and
 * application-scope Fedora language packs; keep user- and system-scope
 * extensions auto-disabled. 10 = User (2) + System (8). The locale default in
 * noid-locale.js then lets Firefox select the installed application langpack
 * from the process locale. ***/
user_pref("extensions.autoDisableScopes", 10);
/* 2661: disable bypassing 3rd party extension install prompts [FF82+]
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1659530,1681331 ***/
user_pref("extensions.postDownloadThirdPartyPrompt", false);
/* 2662: disable webextension restrictions on certain mozilla domains (you also need 4503) [FF60+]
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1384330,1406795,1415644,1453988 ***/
   // user_pref("extensions.webextensions.restrictedDomains", "");

/*** [SECTION 2700]: ETP (ENHANCED TRACKING PROTECTION) ***/
user_pref("_user.js.parrot", "2700 syntax error: the parrot's joined the bleedin' choir invisible!");
/* 2701: enable ETP Strict Mode [FF86+]
 * ETP Strict Mode enables Total Cookie Protection (TCP)
 * [NOTE] Adding site exceptions disables all ETP protections for that site and increases the risk of
 * cross-site state tracking e.g. exceptions for SiteA and SiteB means PartyC on both sites is shared
 * [1] https://blog.mozilla.org/security/2021/02/23/total-cookie-protection/
 * [SETTING] to add site exceptions: Urlbar>ETP Shield
 * [SETTING] to manage site exceptions: Options>Privacy & Security>Enhanced Tracking Protection>Manage Exceptions ***/
user_pref("browser.contentblocking.category", "strict"); // [HIDDEN PREF]
/* 2702: disable ETP web compat features (about:compat) [FF93+]
 * [SETUP-HARDEN] Includes skip lists, heuristics (SmartBlock) and automatic grants
 * Opener and redirect heuristics are granted for 30 days, see [3]
 * [1] https://blog.mozilla.org/security/2021/07/13/smartblock-v2/
 * [2] https://hg.mozilla.org/mozilla-central/rev/e5483fd469ab#l4.12
 * [3] https://developer.mozilla.org/docs/Web/Privacy/State_Partitioning#storage_access_heuristics ***/
   // user_pref("privacy.antitracking.enableWebcompat", false);
/* 2705: set ETP Strict/Custom exception lists (FF141+)
 [SETTING] Options>Privacy & Security>Enhanced Tracking Protection>Strict/Custom>Fix major [baseline] | minor [convenience]
 [1] https://support.mozilla.org/en-US/kb/manage-enhanced-tracking-protection-exceptions
 [2] https://etp-exceptions.mozilla.org/ ***/
user_pref("privacy.trackingprotection.allow_list.baseline.enabled", true); // [DEFAULT: true]
   // NoID Privacy's user-overridable convenience default is supplied by Module 16

/*** [SECTION 2800]: SHUTDOWN & SANITIZING
   The productive profile clears cache and form data on shutdown while retaining
   cookies, history, downloads and site permissions. Module 34 overrides all five
   current categories for the separate private-session profile.
***/
user_pref("_user.js.parrot", "2800 syntax error: the parrot's bleedin' demised!");
/* 2810: enable Firefox to clear items on shutdown
 * [SETTING] Privacy & Security>History>Custom Settings>Clear history when Firefox closes | Settings
 *
 * NoID Privacy default-release keeps this enabled so cache and form data are
 * cleared between sessions. The current category flags below retain cookies,
 * history, downloads and site permissions for productive-profile usability.
 * Playground re-overrides the current categories as part of Module 34's
 * private-session cleanup. */
user_pref("privacy.sanitize.sanitizeOnShutdown", true);

/* Firefox 153's Sanitizer reads the five clearOnShutdown_v2 categories below.
 * Pin the current v3 migration marker so a first shutdown cannot overwrite
 * these explicit values from legacy v1 preferences. Keep the legacy cookie
 * and offline-data values aligned for maintained policy/UI compatibility.
 * Source:
 * https://searchfox.org/mozilla-central/source/browser/modules/Sanitizer.sys.mjs */
user_pref("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs3", true);
user_pref("privacy.clearOnShutdown.cookies", false);
user_pref("privacy.clearOnShutdown.offlineApps", false);

/** SANITIZE ON SHUTDOWN: IGNORES "ALLOW" SITE EXCEPTIONS ***/
/* 2811: current clearOnShutdown items (if 2810 is true) [SETUP-CHROME] ***/
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", false);
user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", false);
user_pref("privacy.clearOnShutdown_v2.cache", true);
user_pref("privacy.clearOnShutdown_v2.formdata", true);
user_pref("privacy.clearOnShutdown_v2.siteSettings", false);
/* 2813: set Session Restore to clear on shutdown (if 2810 is true) [FF34+]
 * [NOTE] Not needed if Session Restore is not used (0102) or it is already cleared with history (2811+)
 * [NOTE] If true, this prevents resuming from crashes (also see 5008) ***/
   // user_pref("privacy.clearOnShutdown.openWindows", true);

/** SANITIZE SITE DATA: IGNORES "ALLOW" SITE EXCEPTIONS ***/
/* 2820: set current manual "Clear Data" items [SETUP-CHROME]
 * Firefox remembers your last choices. This will reset them when you start Firefox
 * [SETTING] Privacy & Security>Browser Privacy>Cookies and Site Data>Clear Data ***/
user_pref("privacy.clearSiteData.cache", true);
user_pref("privacy.clearSiteData.cookiesAndStorage", false);
user_pref("privacy.clearSiteData.browsingHistoryAndDownloads", false);
user_pref("privacy.clearSiteData.formdata", true);
user_pref("privacy.clearSiteData.siteSettings", false);

/** SANITIZE HISTORY: IGNORES "ALLOW" SITE EXCEPTIONS ***/
/* 2830: set current manual "Clear History" items, also via Ctrl-Shift-Del [SETUP-CHROME]
 * Firefox remembers your last choices. This will reset them when you start Firefox
 * [SETTING] Privacy & Security>History>Custom Settings>Clear History ***/
user_pref("privacy.sanitize.cpd.hasMigratedToNewPrefs3", true);
user_pref("privacy.clearHistory.cache", true);
user_pref("privacy.clearHistory.cookiesAndStorage", false);
user_pref("privacy.clearHistory.browsingHistoryAndDownloads", false);
user_pref("privacy.clearHistory.formdata", true);
user_pref("privacy.clearHistory.siteSettings", false);

/** SANITIZE MANUAL: TIMERANGE ***/
/* 2840: set "Time range to clear" for "Clear Data" (2820+) and "Clear History" (2830+)
 * Firefox remembers your last choice. This will reset the value when you start Firefox
 * 0=everything, 1=last hour, 2=last two hours, 3=last four hours, 4=today,
 * 5=last five minutes, 6=last 24 hours ***/
user_pref("privacy.sanitize.timeSpan", 0);

/*** [SECTION 4000]: FPP (fingerprintingProtection)
   RFP (4501) overrides FPP

   In FF118+ FPP is on by default in private windows (4001) and in FF119+ is controlled
   by ETP (2701). FPP will also use Remote Services in future to relax FPP protections
   on a per site basis for compatibility (4004).

   https://searchfox.org/mozilla-central/source/toolkit/components/resistfingerprinting/RFPTargetsDefault.inc
   https://support.mozilla.org/en-US/kb/firefox-protection-against-fingerprinting#w_how-does-each-protection-work

   [NOTE] RFPTargets + granular overrides are somewhat experimental and may produce unexpected results
   - e.g. FrameRate can only be controlled per process, not per origin

   1826408 - restrict to system fonts (kBaseFonts + kLangPackFonts) (Windows, Mac, some Linux) (FF119+)
      1928705: android (FF134+)
      https://searchfox.org/mozilla-central/search?path=StandardFonts*.inc
   1858181 - subtly randomize canvas per eTLD+1, per session and per window-mode (FF120+)
   1887682 - use fdlibm's sin, cos and tan in jsmath (FF134+)
   1954194 - available screen resolution: return a fixed offset height from screen per platform when not full screen (FF143+)
   1984333 - hardwareConcurrency: less than 8 return 4 else return 8 (FF143+)
   1977836 - maxTouchPoints: return multi-touch as 5 (FF143+)
   1917607 - subtly randomize WebGL's readPixels (FF145+)
***/
user_pref("_user.js.parrot", "4000 syntax error: the parrot's bereft of life!");
/* 4001: enable FPP in PB mode [FF114+]
 * [NOTE] In FF119+, FPP for all modes (7016) is enabled with ETP Strict (2701) ***/
   // user_pref("privacy.fingerprintingProtection.pbmode", true); // [DEFAULT: true]
/* 4002: set global FPP overrides [FF114+]
 * uses "RFPTargets" [1] which despite the name these are not used by RFP
 * e.g. "+AllTargets,-CSSPrefersColorScheme,-JSDateTimeUTC" = all targets but allow prefers-color-scheme and do not change timezone
 * e.g. "-AllTargets,+CanvasRandomization,+JSDateTimeUTC" = no targets but do use FPP canvas and change timezone
 * [NOTE] Not supported by arkenfox. Either use RFP or FPP at defaults
 * [1] https://searchfox.org/mozilla-central/source/toolkit/components/resistfingerprinting/RFPTargets.inc ***/
   // user_pref("privacy.fingerprintingProtection.overrides", "");
/* 4003: set granular FPP overrides
 * JSON format: e.g."[{\"firstPartyDomain\": \"netflix.com\", \"overrides\": \"-CanvasRandomization,-FrameRate,\"}]"
 * [NOTE] Not supported by arkenfox. Either use RFP or FPP at defaults ***/
   // user_pref("privacy.fingerprintingProtection.granularOverrides", "");
/* 4004: disable remote FPP overrides [FF127+] ***/
   // user_pref("privacy.fingerprintingProtection.remoteOverrides.enabled", false);

/*** [SECTION 4500]: OPTIONAL RFP (resistFingerprinting)
   RFP overrides FPP (4000)

   FF128+ Arkenfox by default uses FPP (automatically enabled with ETP Strict). For most people
   this is all you need. To use RFP instead, add RFP (4501) to your overrides, and optionally
   add letterboxing (4504), spoof_english (4506), and WebGL (4520).

   RFP is an all-or-nothing buy in: you cannot pick and choose what parts you want

   [WARNING] DO NOT USE extensions to alter RFP protected metrics

    418986 - limit window.screen & CSS media queries (FF41)
 FF56
   1333651 - spoof User Agent & Navigator API
      JS: spoofed as Windows 10, OS X 10.15, Android 10, or Linux
      HTTP Header: spoofed as Windows 10 or Android 10 until FF136 then matches JS spoof
   1369319 - disable device sensor API
   1369357 - disable site specific zoom
   1337161 - hide gamepads from content
   1372072 - spoof network information API as "unknown" when dom.netinfo.enabled = true
   1333641 - reduce fingerprinting in WebSpeech API
 FF57
   1369309 - spoof media statistics
   1382499 - reduce screen co-ordinate fingerprinting in Touch API
   1217290 & 1409677 - enable some fingerprinting resistance for WebGL
   1354633 - limit MediaError.message to a whitelist
 FF58+
   1372073 - spoof/block fingerprinting in MediaDevices API (FF59)
      Spoof: enumerate devices as one "Internal Camera" and one "Internal Microphone"
      Block: suppresses the ondevicechange event
   1039069 - warn when language prefs are not set to "en*" (FF59)
   1222285 & 1433592 - spoof keyboard events and suppress keyboard modifier events (FF59)
      Spoofing mimics the content language of the document. Currently it only supports en-US.
      Modifier events suppressed are SHIFT and both ALT keys. Chrome is not affected.
   1459089 - disable OS locale in HTTP Accept-Language headers (ANDROID) (FF62)
   1479239 - return "no-preference" with prefers-reduced-motion (FF63)
   1492766 - spoof pointerEvent.pointerid (FF65)
   1485266 - disable exposure of system colors to CSS or canvas (FF67)
   1494034 - return "light" with prefers-color-scheme (FF67)
   1564422 - spoof audioContext outputLatency (FF70)
   1595823 - return audioContext sampleRate as 44100 (FF72)
   1607316 - spoof pointer as coarse and hover as none (ANDROID) (FF74)
   1621433 - randomize canvas (previously FF58+ returned an all-white canvas) (FF78)
   1506364 - return "no-preference" with prefers-contrast (FF80)
   1653987 - limit font visibility to bundled and "Base Fonts" (Windows, Mac, some Linux) (FF80)
   1461454 - spoof smooth=true and powerEfficient=false for supported media in MediaCapabilities (FF82)
    531915 - use fdlibm's sin, cos and tan in jsmath (FF93, ESR91.1)
   1692609 - reduce JS timing precision to 16.67ms (previously FF55+ was 100ms) (FF102)
   1422237 - return "srgb" with color-gamut (FF110)
   1794628 - return "none" with inverted-colors (FF114)
   1787790 - normalize system fonts (FF128)
   1835987 - spoof timezone as Atlantic/Reykjavik (previously FF55+ was UTC) (FF128)
   1656377 - spoof pointerEvents azimuthAngle and altitudeAngle (FF131)
   1826051 & 1957658 & 2021715 - spoof/suppress Pointer Events, spoof maxTouchPoints (FF132, FF143/ESR140.2, FF150)
      previously FF64+ (1363508) it always returned maxTouchPoints as 0
      FF132: 0 = mac | 10 = windows, linux, mobile
      FF143: 0 = mac, linux | 10 = windows | 5 = mobile | no longer spoof touch PointerEvents | backported to ESR140.2
      FF150: 5 = linux
   1834307 - always use smooth scrolling (FF132)
   1918202 - spoof screen orientation based on spoofed screen size and platform (FF132)
      previously FF50+ it always returned landscape-primary and an angle of 0
   1390465 - load all subtitles in WebVTT (Video Text Tracks) (FF133)
   1873382 - make spoofed devicePixelRatio and CSS media queries match (FF133)
      previously FF41+ devicePixelRatio was hardcoded as 1 and FF127+ as 2
      previously FF41+ CSS media queries were spoofed as zoom level at a devicePixelRatio of 1
   1955425 - return 128 for WebGPU subgroupMaxSize (FF138)
   1966860 - spoof WebGL debug renderer info (FF140)
      previously FF60+ it was disabled
   1781277 - return 10GiB for storage estimate until persistent-storage granted (FF142, ESR140.1)
   1972600 - spoof network connection for HTMLMediaElement preload (FF142, ESR140.1)
   1975851 - return true for navigator.onLine (FF142, ESR140.1)
   1973265 - disable WebCodecs API (FF142)
   1984333 - spoof navigator.hardwareConcurrency as 4 except mac return 8 (FF143)
       previously FF55+ it returned 2
   1999126 - enforce navigator.pdfViewerEnabled as true and plugins/mimeTypes as hard-coded values (FF147)
***/
user_pref("_user.js.parrot", "4500 syntax error: the parrot's popped 'is clogs");
/* 4501: enable RFP
 * [NOTE] pbmode applies if true and the original pref is false
 * [SETUP-WEB] RFP can cause some website breakage: mainly canvas, use a canvas site exception via the urlbar.
 * RFP also has a few side effects: mainly that timezone is GMT, and websites will prefer light theme ***/
   // user_pref("privacy.resistFingerprinting", true); // [FF41+]
   // user_pref("privacy.resistFingerprinting.pbmode", true); // [FF114+]
/* 4502: set RFP new window size max rounded values [FF55+]
 * [SETUP-CHROME] sizes round down in hundreds: width to 200s and height to 100s, to fit your screen
 * [1] https://bugzilla.mozilla.org/1330882 ***/
user_pref("privacy.window.maxInnerWidth", 1600);
user_pref("privacy.window.maxInnerHeight", 900);
/* 4503: disable mozAddonManager Web API [FF57+]
 * [NOTE] To allow extensions to work on AMO, you also need 2662
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1384330,1406795,1415644,1453988 ***/
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);
/* 4504: enable letterboxing [FF67+]
 * Dynamically resizes the inner window by applying margins in stepped ranges [2]
 * If you use the dimension pref, then it will only apply those resolutions.
 * The format is "width1xheight1, width2xheight2, ..." (e.g. "800x600, 1000x1000")
 * [SETUP-WEB] This is independent of RFP (4501). If you're using RFP, but dislike the
 * margins, then don't enable this pref, keeping in mind that it is effectively fingerprintable
 * [WARNING] DO NOT USE: the dimension pref is only meant for testing
 * [1] https://bugzilla.mozilla.org/1407366
 * [2] https://hg.mozilla.org/mozilla-central/rev/7211cb4f58ff#l5.13 ***/
   // user_pref("privacy.resistFingerprinting.letterboxing", true); // [HIDDEN PREF]
   // user_pref("privacy.resistFingerprinting.letterboxing.dimensions", ""); // [HIDDEN PREF]
/* 4505: disable RFP by domain [FF91+]
 * [NOTE]: The pref takes comma separated values: e.g. "*domain1.tld, *domain2.tld"
 * Working domain examples: "arkenfox.github.io", "*github.io"
 * Non-working domain examples: "https://arkenfox.github.io", "github.io", "*arkenfox.github.io" ***/
   // user_pref("privacy.resistFingerprinting.exemptedDomains", "*.example.invalid");
/* 4506: disable RFP spoof english prompt [FF59+]
 * 0=prompt, 1=disabled, 2=enabled
 * [NOTE] When changing from value 2, preferred languages ('intl.accept_languages') is not reset.
 * [SETUP-WEB] when enabled, sets 'en-US, en' for displaying pages and 'en-US' as locale.
 * [SETTING] General>Language>Choose your preferred language for displaying pages>Choose>Request English... ***/
user_pref("privacy.spoof_english", 1);
/* 4507: skip browser.startup.blankWindow if RFP is used [FF136+] ***/
   // user_pref("privacy.resistFingerprinting.skipEarlyBlankFirstPaint", true); // [DEFAULT: true]
/* 4510: enforce Contrast Control off [FF138+]
 * 0=automatic, 1=off, 2=custom
 * [SETTING] General>Language and Appearance>Contrast Control ***/
   // user_pref("browser.display.document_color_use", 1); // [DEFAULT: 1 NON-WINDOWS]
/* 4511: disable using system accent colors ***/
user_pref("widget.non-native-theme.use-theme-accent", false); // [DEFAULT: false WINDOWS]
/* 4512: enforce links targeting new windows to open in a new tab instead
 * 1=most recent window or tab, 2=new window, 3=new tab
 * Stops malicious window sizes and some screen resolution leaks.
 * You can still right-click a link and open in a new window
 * [SETTING] General>Tabs>Open links in tabs instead of new windows
 * [1] https://gitlab.torproject.org/tpo/applications/tor-browser/-/issues/9881 ***/
user_pref("browser.link.open_newwindow", 3); // [DEFAULT: 3]
/* 4513: set all open window methods to abide by "browser.link.open_newwindow" (4512)
 * [1] https://searchfox.org/mozilla-central/source/dom/tests/browser/browser_test_new_window_from_content.js ***/
user_pref("browser.link.open_newwindow.restriction", 0);
/* 4520: disable WebGL (Web Graphics Library) ***/
   // user_pref("webgl.disabled", true);

/*** [SECTION 5000]: OPTIONAL OPSEC
   Disk avoidance, application data isolation, eyeballs...
***/
user_pref("_user.js.parrot", "5000 syntax error: the parrot's taken 'is last bow");
/* 5001: start Firefox in PB (Private Browsing) mode
 * [NOTE] In this mode all windows are "private windows" and the PB mode icon is not displayed
 * [NOTE] The P in PB mode can be misleading: it means no "persistent" disk state such as history,
 * caches, searches, cookies, localStorage, IndexedDB etc (which you can achieve in normal mode).
 * In fact, PB mode limits or removes the ability to control some of these, and you need to quit
 * Firefox to clear them. PB is best used as a one off window (Menu>New Private Window) to provide
 * a temporary self-contained new session. Close all private windows to clear the PB session.
 * [SETTING] Privacy & Security>History>Custom Settings>Always use private browsing mode
 * [1] https://wiki.mozilla.org/Private_Browsing
 * [2] https://support.mozilla.org/kb/common-myths-about-private-browsing ***/
   // user_pref("browser.privatebrowsing.autostart", true);
/* 5002: disable memory cache
 * capacity: -1=determine dynamically (default), 0=none, n=memory capacity in kibibytes ***/
   // user_pref("browser.cache.memory.enable", false);
   // user_pref("browser.cache.memory.capacity", 0);
/* 5003: disable saving passwords
 * [NOTE] This does not clear any passwords already saved
 * [SETTING] Privacy & Security>Logins and Passwords>Ask to save logins and passwords for websites ***/
/* 5004: disable permissions manager from writing to disk [FF41+] [RESTART]
 * [NOTE] This means any permission changes are session only
 * [1] https://bugzilla.mozilla.org/967812 ***/
   // user_pref("permissions.memory_only", true); // [HIDDEN PREF]
/* 5005: disable intermediate certificate caching [FF41+] [RESTART]
 * [NOTE] This affects login/cert/key dbs. The effect is all credentials are session-only.
 * Saved logins and passwords are not available. Reset the pref and restart to return them ***/
   // user_pref("security.nocertdb", true);
/* 5006: disable favicons in history and bookmarks
 * [NOTE] Stored as data blobs in favicons.sqlite, these don't reveal anything that your
 * actual history (and bookmarks) already do. Your history is more detailed, so
 * control that instead; e.g. disable history, clear history on exit, use PB mode
 * [NOTE] favicons.sqlite is sanitized on Firefox close ***/
   // user_pref("browser.chrome.site_icons", false);
/* 5007: exclude "Undo Closed Tabs" in Session Restore ***/
   // user_pref("browser.sessionstore.max_tabs_undo", 0);
/* 5008: disable resuming session from crash
 * [TEST] about:crashparent ***/
   // user_pref("browser.sessionstore.resume_from_crash", false);
/* 5009: disable "open with" in download dialog [FF50+]
 * Application data isolation [1]
 * [1] https://bugzilla.mozilla.org/1281959 ***/
   // user_pref("browser.download.forbid_open_with", true);
/* 5010: disable location bar suggestion types
 * [SETTING] Search>Address Bar>When using the address bar, suggest ***/
   // user_pref("browser.urlbar.suggest.history", false);
   // user_pref("browser.urlbar.suggest.bookmark", false);
   // user_pref("browser.urlbar.suggest.openpage", false);
   // user_pref("browser.urlbar.suggest.topsites", false); // [FF78+]
/* 5011: disable location bar dropdown
 * This value controls the total number of entries to appear in the location bar dropdown ***/
   // user_pref("browser.urlbar.maxRichResults", 0);
/* 5012: disable location bar autofill
 * [1] https://support.mozilla.org/kb/address-bar-autocomplete-firefox#w_url-autocomplete ***/
   // user_pref("browser.urlbar.autoFill", false);
/* 5013: disable browsing and download history
 * [NOTE] We also clear history and downloads on exit (2811+)
 * [SETTING] Privacy & Security>History>Custom Settings>Remember browsing and download history ***/
   // user_pref("places.history.enabled", false);
/* 5014: disable Windows jumplist [WINDOWS] ***/
   // user_pref("browser.taskbar.lists.enabled", false);
   // user_pref("browser.taskbar.lists.frequent.enabled", false);
   // user_pref("browser.taskbar.lists.recent.enabled", false);
   // user_pref("browser.taskbar.lists.tasks.enabled", false);
/* 5016: discourage downloading to desktop
 * 0=desktop, 1=downloads (default), 2=custom
 * [SETTING] To set your custom default "downloads": General>Downloads>Save files to ***/
   // user_pref("browser.download.folderList", 2);
/* 5017: disable Form Autofill
 * If .supportedCountries includes your region (browser.search.region) and .supported
 * is "detect" (default), then the UI will show. Stored data is not secure, uses JSON
 * [SETTING] Privacy & Security>Forms and Autofill>Autofill addresses
 * [1] https://wiki.mozilla.org/Firefox/Features/Form_Autofill ***/
   // user_pref("extensions.formautofill.addresses.enabled", false); // [FF55+]
   // user_pref("extensions.formautofill.creditCards.enabled", false); // [FF56+]
/* 5018: limit events that can cause a pop-up ***/
   // user_pref("dom.popup_allowed_events", "click dblclick mousedown pointerdown");
/* 5019: disable page thumbnail collection ***/
   // user_pref("browser.pagethumbnails.capturing_disabled", true); // [HIDDEN PREF]
/* 5020: disable Windows native notifications and use app notications instead [FF111+] [WINDOWS] ***/
   // user_pref("alerts.useSystemBackend.windows.notificationserver.enabled", false);

/*** [SECTION 5500]: OPTIONAL HARDENING
   Not recommended. Overriding these can cause breakage and performance issues,
   they are mostly fingerprintable, and the threat model is practically nonexistent
***/
user_pref("_user.js.parrot", "5500 syntax error: this is an ex-parrot!");
/* 5501: disable MathML (Mathematical Markup Language) [FF51+]
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=mathml ***/
   // user_pref("mathml.disabled", true); // 1173199
/* 5502: disable in-content SVG (Scalable Vector Graphics) [FF53+]
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=firefox+svg ***/
   // user_pref("svg.disabled", true); // 1216893
/* 5503: disable graphite
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=firefox+graphite
 * [2] https://en.wikipedia.org/wiki/Graphite_(SIL) ***/
   // user_pref("gfx.font_rendering.graphite.enabled", false);
/* 5504: disable asm.js [FF22+]
 * [1] http://asmjs.org/
 * [2] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=asm.js
 * [3] https://rh0dev.github.io/blog/2017/the-return-of-the-jit/ ***/
   // user_pref("javascript.options.asmjs", false);
/* 5505: disable Ion and baseline JIT to harden against JS exploits [RESTART]
 * [NOTE] When both Ion and JIT are disabled, and trustedprincipals
 * is enabled, then Ion can still be used by extensions (1599226)
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=firefox+jit
 * [2] https://microsoftedge.github.io/edgevr/posts/Super-Duper-Secure-Mode/ ***/
   // user_pref("javascript.options.ion", false);
   // user_pref("javascript.options.baselinejit", false);
   // user_pref("javascript.options.jit_trustedprincipals", true); // [FF75+] [HIDDEN PREF]
/* 5506: optionally disable WebAssembly [FF52+]
 * This removes a web execution surface but breaks legitimate applications;
 * arkenfox and NoID Privacy therefore leave it enabled in the main browser. ***/
   // user_pref("javascript.options.wasm", false);
/* 5507: disable rendering of SVG OpenType fonts ***/
   // user_pref("gfx.font_rendering.opentype_svg.enabled", false);
/* 5508: disable all DRM (Digital Rights Management) content (EME: Encryption Media Extension)
 * Optionally hide the UI setting which also disables the DRM prompt
 * [SETTING] General>DRM Content>Play DRM-controlled content
 * [TEST] https://bitmovin.com/demos/drm
 * [1] https://www.eff.org/deeplinks/2017/10/drms-dead-canary-how-we-just-lost-web-what-we-learned-it-and-what-we-need-do-next ***/
   // user_pref("media.eme.enabled", false);
   // user_pref("browser.eme.ui.enabled", false);
/* 5509: disable IPv6 if using a VPN
 * This is an application level fallback. Disabling IPv6 is best done at an OS/network
 * level, and/or configured properly in system wide VPN setups.
 * [NOTE] PHP defaults to IPv6 with "localhost". Use "php -S 127.0.0.1:PORT"
 * [SETUP-WEB] PR_CONNECT_RESET_ERROR
 * [TEST] https://ipleak.org/
 * [1] https://www.internetsociety.org/tag/ipv6-security/ (Myths 2,4,5,6) ***/
   // user_pref("network.dns.disableIPv6", true);
/* 5510: control when to send a cross-origin referer
 * 0=always (default), 1=only if base domains match, 2=only if hosts match
 * [NOTE] Will cause breakage: older modems/routers and some sites e.g banks, vimeo, icloud, instagram ***/
   // user_pref("network.http.referer.XOriginPolicy", 2);
/* 5511: set DoH bootstrap address [FF89+]
 * Firefox uses the system DNS to initially resolve the IP address of your DoH server.
 * When set to a valid, working value that matches your "network.trr.uri" (0712) Firefox
 * won't use the system DNS. If the IP doesn't match then DoH won't work ***/
   // user_pref("network.trr.bootstrapAddr", "10.0.0.1"); // [HIDDEN PREF]

/*** [SECTION 6000]: DON'T TOUCH ***/
user_pref("_user.js.parrot", "6000 syntax error: the parrot's 'istory!");
/* 6001: enforce Firefox blocklist
 * [WHY] It includes updates for "revoked certificates"
 * [1] https://blog.mozilla.org/security/2015/03/03/revoking-intermediate-certificates-introducing-onecrl/ ***/
user_pref("extensions.blocklist.enabled", true); // [DEFAULT: true]
/* 6002: enforce no referer spoofing
 * [WHY] Spoofing can affect CSRF (Cross-Site Request Forgery) protections ***/
user_pref("network.http.referer.spoofSource", false); // [DEFAULT: false]
/* 6004: enforce a security delay on some confirmation dialogs such as install, open/save
 * [1] https://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/ ***/
user_pref("security.dialog_enable_delay", 1000); // [DEFAULT: 1000]
/* 6008: enforce no First Party Isolation [FF51+]
 * [WARNING] Replaced with network partitioning (FF85+) and TCP (2701), and enabling FPI
 * disables those. FPI is no longer maintained except at Tor Project for Tor Browser's config ***/
user_pref("privacy.firstparty.isolate", false); // [DEFAULT: false]
/* 6009: enforce SmartBlock shims (about:compat) [FF81+]
 * [1] https://blog.mozilla.org/security/2021/03/23/introducing-smartblock/ ***/
user_pref("extensions.webcompat.enable_shims", true); // [HIDDEN PREF] [DEFAULT: true]
/* 6010: enforce no TLS 1.0/1.1 downgrades
 * [TEST] https://tls-v1-1.badssl.com:1010/ ***/
user_pref("security.tls.version.enable-deprecated", false); // [DEFAULT: false]
/* 6011: enforce disabling of Web Compatibility Reporter [FF56+]
 * Web Compatibility Reporter adds a "Report Site Issue" button to send data to Mozilla
 * [WHY] To prevent wasting Mozilla's time with a custom setup ***/
user_pref("extensions.webcompat-reporter.enabled", false); // [DEFAULT: false]
/* 6012: enforce Quarantined Domains [FF115+]
 * [WHY] https://support.mozilla.org/kb/quarantined-domains ***/
user_pref("extensions.quarantinedDomains.enabled", true); // [DEFAULT: true]
/* 6050: prefsCleaner: reset previously active items removed from arkenfox FF140+ ***/
   // user_pref("browser.display.use_system_colors", "");
   // user_pref("browser.urlbar.fakespot.featureGate", "");
   // user_pref("security.OCSP.enabled", "");
   // user_pref("security.OCSP.require", "");

/*** [SECTION 7000]: DON'T BOTHER ***/
user_pref("_user.js.parrot", "7000 syntax error: the parrot's pushing up daisies!");
/* 7001: disable APIs
 * Location-Aware Browsing, Full Screen
 * [WHY] The API state is easily fingerprintable.
 * Geo is behind a prompt (7002). Full screen requires user interaction ***/
   // user_pref("geo.enabled", false);
   // user_pref("full-screen-api.enabled", false);
/* 7002: set default permissions
 * Location, Camera, Microphone, Notifications [FF58+] Virtual Reality [FF73+]
 * 0=always ask (default), 1=allow, 2=block
 * [WHY] These are fingerprintable via Permissions API, except VR. Just add site
 * exceptions as allow/block for frequently visited/annoying sites: i.e. not global
 * [SETTING] to add site exceptions: Ctrl+I>Permissions>
 * [SETTING] to manage site exceptions: Options>Privacy & Security>Permissions>Settings ***/
   // user_pref("permissions.default.geo", 0);
   // user_pref("permissions.default.camera", 0);
   // user_pref("permissions.default.microphone", 0);
   // user_pref("permissions.default.desktop-notification", 0);
   // user_pref("permissions.default.xr", 0); // Virtual Reality
/* 7003: disable non-modern cipher suites [1]
 * [WHY] Passive fingerprinting. Minimal/non-existent threat of downgrade attacks
 * [1] https://browserleaks.com/ssl ***/
   // user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);
   // user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha", false);
   // user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
   // user_pref("security.ssl3.ecdhe_rsa_aes_256_sha", false);
   // user_pref("security.ssl3.rsa_aes_128_gcm_sha256", false); // no PFS
   // user_pref("security.ssl3.rsa_aes_256_gcm_sha384", false); // no PFS
   // user_pref("security.ssl3.rsa_aes_128_sha", false); // no PFS
   // user_pref("security.ssl3.rsa_aes_256_sha", false); // no PFS
/* 7004: control TLS versions
 * [WHY] Passive fingerprinting and security ***/
   // user_pref("security.tls.version.min", 3); // [DEFAULT: 3]
   // user_pref("security.tls.version.max", 4);
/* 7005: disable SSL session IDs [FF36+]
 * [WHY] Passive fingerprinting and perf costs. These are session-only
 * and isolated with network partitioning (FF85+) and/or containers ***/
   // user_pref("security.ssl.disable_session_identifiers", true);
/* 7007: referers
 * [WHY] Only cross-origin referers (1602, 5510) matter ***/
   // user_pref("network.http.sendRefererHeader", 2);
   // user_pref("network.http.referer.trimmingPolicy", 0);
/* 7008: set the default Referrer Policy [FF59+]
 * 0=no-referer, 1=same-origin, 2=strict-origin-when-cross-origin, 3=no-referrer-when-downgrade
 * [WHY] Defaults are fine. They can be overridden by a site-controlled Referrer Policy ***/
   // user_pref("network.http.referer.defaultPolicy", 2); // [DEFAULT: 2]
   // user_pref("network.http.referer.defaultPolicy.pbmode", 2); // [DEFAULT: 2]
/* 7010: disable HTTP Alternative Services [FF37+]
 * [WHY] Already isolated with network partitioning (FF85+) ***/
   // user_pref("network.http.altsvc.enabled", false);
/* 7011: disable website control over browser right-click context menu
 * [WHY] Just use Shift-Right-Click ***/
   // user_pref("dom.event.contextmenu.enabled", false);
/* 7012: disable icon fonts (glyphs) and local fallback rendering
 * [WHY] Breakage, font fallback is equivalency, also RFP
 * [1] https://bugzilla.mozilla.org/789788
 * [2] https://gitlab.torproject.org/legacy/trac/-/issues/8455 ***/
   // user_pref("gfx.downloadable_fonts.enabled", false); // [FF41+]
   // user_pref("gfx.downloadable_fonts.fallback_delay", -1);
/* 7013: disable Clipboard API
 * [WHY] Fingerprintable. Breakage. Cut/copy/paste require user
 * interaction, and paste is limited to focused editable fields ***/
   // user_pref("dom.event.clipboardevents.enabled", false);
/* 7014: disable System Add-on updates
 * [WHY] It can compromise security. System addons ship with prefs, use those ***/
   // user_pref("extensions.systemAddon.update.enabled", false); // [FF62+]
   // user_pref("extensions.systemAddon.update.url", ""); // [FF44+]
/* 7015: enable the DNT (Do Not Track) HTTP header
 * [WHY] Fingerprintable. In FF141+ DNT is never enabled. DNT is slated for deprecation [1]
   [NOTE] In FF140, DNT is enforced with Tracking Protection which is used in ETP Strict (2701)
   [1] https://bugzilla.mozilla.org/1967420 ***/
   // user_pref("privacy.donottrackheader.enabled", true);
/* 7016: customize ETP settings
 * [NOTE] FPP (fingerprintingProtection) is ignored when RFP (4501) is enabled
 * [WHY] Arkenfox only supports strict (2701) which sets these at runtime ***/
   // user_pref("network.cookie.cookieBehavior", 5); // [DEFAULT: 5]
   // user_pref("network.cookie.cookieBehavior.optInPartitioning", true); // [ETP FF132+]
   // user_pref("network.http.referer.disallowCrossSiteRelaxingDefault", true);
   // user_pref("network.http.referer.disallowCrossSiteRelaxingDefault.top_navigation", true); // [FF100+]
   // user_pref("privacy.bounceTrackingProtection.mode", 1); // [FF131+] [ETP FF133+]
   // user_pref("privacy.fingerprintingProtection", true); // [FF114+] [ETP FF119+]
   // user_pref("privacy.partition.network_state.ocsp_cache", true); // [DEFAULT: true]
   // user_pref("privacy.query_stripping.enabled", true); // [FF101+]
   // user_pref("privacy.trackingprotection.enabled", true);
   // user_pref("privacy.trackingprotection.socialtracking.enabled", true);
   // user_pref("privacy.trackingprotection.cryptomining.enabled", true); // [DEFAULT: true]
   // user_pref("privacy.trackingprotection.fingerprinting.enabled", true); // [DEFAULT: true]
/* 7017: disable service workers
 * [WHY] Already isolated with TCP (2701) behind a pref ***/
   // user_pref("dom.serviceWorkers.enabled", false);
/* 7018: disable Web Notifications [FF22+]
 * [WHY] Web Notifications are behind a prompt (7002)
 * [1] https://blog.mozilla.org/en/products/firefox/block-notification-requests/ ***/
   // user_pref("dom.webnotifications.enabled", false);
/* 7019: disable Push Notifications [FF44+]
 * [WHY] Website "push" requires subscription, and the API is required for CRLite (1224)
 * [NOTE] To remove all subscriptions, reset "dom.push.userAgentID"
 * [1] https://support.mozilla.org/kb/push-notifications-firefox ***/
   // user_pref("dom.push.enabled", false);
/* 7020: disable WebRTC (Web Real-Time Communication)
 * [WHY] Firefox desktop normally uses mDNS hostname obfuscation for local
 * candidates before device permission, but that is not a general IP-leak
 * guarantee across routes, proxies and VPN configurations. Use the granular
 * ICE controls in section 2000 when WebRTC must remain enabled.
 * [TEST] https://browserleaks.com/webrtc
 * [1] https://groups.google.com/g/discuss-webrtc/c/6stQXi72BEU/m/2FwZd24UAQAJ
 * [2] https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates#section-3.1.1 ***/
   // user_pref("media.peerconnection.enabled", false);
/* 7021: enable GPC (Global Privacy Control) in non-PB windows
 * [WHY] Passive and active fingerprinting. Mostly redundant with Tracking Protection
 * in ETP Strict (2701) and sanitizing on close (2800s) ***/
   // user_pref("privacy.globalprivacycontrol.enabled", true);
/* 7022: bFPP (baselineFingerprintingProtection) [FF139+]
 * [WHY] Arkenfox only supports ETP Strict (2701) which enables FPP browser-wide (normal and private
 * browsing window contexts). If FPP is enabled in the same context as bFPP, FPP takes precedence. ***/
   // user_pref("privacy.baselineFingerprintingProtection", true);
   // user_pref("privacy.baselineFingerprintingProtection.granularOverrides", "");
   // user_pref("privacy.baselineFingerprintingProtection.overrides", "");

/*** [SECTION 8000]: DON'T BOTHER: FINGERPRINTING
   [WHY] They are insufficient for fingerprinting protection and do more harm than good
   [WARNING] DO NOT USE: they can interfere with built-in solutions such as RFP and FPP
***/
user_pref("_user.js.parrot", "8000 syntax error: the parrot's crossed the Jordan");
/* 8001: prefsCleaner: reset items useless for anti-fingerprinting ***/
   // user_pref("browser.display.use_document_fonts", "");
   // user_pref("browser.zoom.siteSpecific", "");
   // user_pref("device.sensors.enabled", "");
   // user_pref("dom.enable_performance", "");
   // user_pref("dom.enable_resource_timing", "");
   // user_pref("dom.gamepad.enabled", "");
   // user_pref("dom.maxHardwareConcurrency", "");
   // user_pref("dom.w3c_touch_events.enabled", "");
   // user_pref("dom.webaudio.enabled", "");
   // user_pref("font.system.whitelist", "");
   // user_pref("general.appname.override", "");
   // user_pref("general.appversion.override", "");
   // user_pref("general.buildID.override", "");
   // user_pref("general.oscpu.override", "");
   // user_pref("general.platform.override", "");
   // user_pref("general.useragent.override", "");
   // user_pref("media.navigator.enabled", "");
   // user_pref("media.video_stats.enabled", "");
   // user_pref("media.webspeech.synth.enabled", "");
   // user_pref("ui.use_standins_for_native_colors", "");
   // user_pref("webgl.enable-debug-renderer-info", "");

/*** [SECTION 8500]: TELEMETRY
   NoID Privacy disables application telemetry and data submission by default.
   Firefox exposes locally recorded telemetry at about:telemetry and its data
   controls under Settings > Privacy & Security.
***/
user_pref("_user.js.parrot", "8500 syntax error: the parrot's off the twig!");
/* 8500: disable new data submission [FF41+]
 * If disabled, no policy is shown or upload takes place, ever
 * [1] https://bugzilla.mozilla.org/1195552 ***/
user_pref("datareporting.policy.dataSubmissionEnabled", false);
/* 8501: disable Health Reports
 * [SETTING] Privacy & Security>Firefox Data Collection and Use>Send technical... data ***/
user_pref("datareporting.healthreport.uploadEnabled", false);
/* 8501b: disable Daily Usage Ping [FF130+]
 * Mozilla added a separate ping for Daily Active Users metrics, distinct from
 * healthreport.uploadEnabled (technical/interaction data). Without this pref the
 * UI checkbox "Send daily usage ping to Mozilla" stays ON even when other
 * telemetry knobs are off. Arkenfox v144 gap.
 * [SETTING] Privacy & Security>Firefox Data Collection and Use>Send daily usage ping ***/
user_pref("datareporting.usage.uploadEnabled", false);
/* 8502: disable telemetry
 * The "unified" pref affects the behavior of the "enabled" pref
 * - If "unified" is false then "enabled" controls the telemetry module
 * - If "unified" is true then "enabled" only controls whether to record extended data
 * [NOTE] "toolkit.telemetry.enabled" is now LOCKED to reflect prerelease (true) or release builds (false) [2]
 * [1] https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/telemetry/internals/preferences.html
 * [2] https://medium.com/georg-fritzsche/data-preference-changes-in-firefox-58-2d5df9c428b5 ***/
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false); // see [NOTE]
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false); // [FF55+]
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false); // [FF55+]
user_pref("toolkit.telemetry.updatePing.enabled", false); // [FF56+]
user_pref("toolkit.telemetry.bhrPing.enabled", false); // [FF57+] Background Hang Reporter
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false); // [FF57+]
/* 8503: disable Telemetry Coverage
 * [1] https://blog.mozilla.org/data/2018/08/20/effectively-measuring-search-in-firefox/ ***/
user_pref("toolkit.coverage.opt-out", true); // [FF64+] [HIDDEN PREF]
user_pref("toolkit.coverage.endpoint.base", "");

/*** [SECTION 9000]: NON-PROJECT RELATED ***/
user_pref("_user.js.parrot", "9000 syntax error: the parrot's cashed in 'is chips!");
/* 9001: disable welcome notices ***/
user_pref("browser.startup.homepage_override.mstone", "ignore"); // [HIDDEN PREF]
/* 9001b: disable Mozilla "Get started with Firefox" about:welcome page on first
 * launch. Without this, default-release shows the Firefox onboarding flow
 * (asks to set Firefox-as-default, sign in to Firefox Sync, install Pocket, etc.)
 * which conflicts with NoID Privacy's pre-configured hardening. Playground had this
 * disabled via overrides; it is also disabled in base for default-release. ***/
user_pref("browser.aboutwelcome.enabled", false);
/* 9002: disable General>Browsing>Recommend extensions/features as you browse [FF67+] ***/
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
/* 9003: disable all Firefox Messaging System providers [FF153]
 * Firefox 153's ASRouter can query TelemetrySession metadata even when legacy
 * unified telemetry is disabled. That session is intentionally uninitialized,
 * so the provider path throws TelemetryUtils' date-is-undefined error at every
 * normal UI launch. NoID Privacy does not use Mozilla's local onboarding, CFR,
 * remote message-group or messaging-experiment providers. Disabling the exact
 * four Firefox 153 providers avoids the invalid call and their background work
 * without enabling in-memory base telemetry as a workaround. Firefox Home Top
 * Sites are a separate Activity Stream feed and remain available.
 * [1] https://searchfox.org/firefox-main/source/browser/app/profile/firefox.js
 * [2] https://searchfox.org/firefox-main/source/browser/components/asrouter/modules/ASRouterPreferences.sys.mjs ***/
user_pref("browser.newtabpage.activity-stream.asrouter.providers.message-groups", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.onboarding", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.cfr", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.messaging-experiments", "null");
/* 9004: disable search terms [FF110+]
 * [SETTING] Search>Search Bar>Use the address bar for search and navigation>Show search terms instead of URL... ***/
user_pref("browser.urlbar.showSearchTerms.enabled", false);

/*** [SECTION 9999]: DEPRECATED / RENAMED ***/
user_pref("_user.js.parrot", "9999 syntax error: the parrot's shuffled off 'is mortal coil!");
/* ESR140.x still uses all the following prefs
// [NOTE] replace the * with a slash in the line above to re-enable active ones
// FF148
// 0603: disable predictor / prefetching
  // [-] https://bugzilla.mozilla.org/2006028
user_pref("network.predictor.enabled", false); // [DEFAULT: false FF144+]
user_pref("network.predictor.enable-prefetch", false); // [FF48+] [DEFAULT: false]
// ***/

/* END: internal custom pref to test for syntax errors ***/
user_pref("_user.js.parrot", "SUCCESS: NoID Privacy — hardening fully applied");


/*****************************************************************************
 *                                                                           *
 *  =========================================================                *
 *  NoID Privacy — IMAGE-SCOPE OVERRIDES (below this line)                   *
 *  =========================================================                *
 *                                                                           *
 *  Everything below this marker is NoID Privacy-specific — NOT from arkenfox.       *
 *  Maintained by the NoID Privacy Workstation project.                      *
 *                                                                           *
 *****************************************************************************/

/*** USER OVERRIDES – NoID Privacy Workstation 44 | Generic Image ***/
/*** Module 16 | NoID Privacy Firefox Hardening (derived from arkenfox v144.0) ***/

/*** [SECTION: SECURITY] ***/

/* OCSP: keep hard-fail off. Firefox 142 put CRLite into production as its
 * comprehensive on-device revocation path; mode 2 remains enabled above.
 * `security.OCSP.require=false` does not disable Firefox's maintained
 * revocation flow. It avoids turning an unavailable OCSP fallback responder
 * into a connection failure. */
user_pref("security.OCSP.require", false);

/* DNS follows the OS resolver by image default. Module 16 supplies the
 * user-overridable network.trr.mode=5 default through AutoConfig rather than
 * user.js, so NetworkManager/systemd-resolved can honor VPN and private-link
 * DNS. A user-selected Firefox Secure DNS provider therefore survives browser
 * restarts and the supported Update All reconciliation. */

/* Keep IPv6 answers usable inside an active VPN. The system network boundary,
 * not the application, blocks unqualified physical-WAN IPv6; disabling IPv6
 * here would also suppress a provider's legitimate tunnel IPv6/NAT64 path. */
user_pref("network.dns.disableIPv6", false);

/* WebRTC DISABLED — prevents Firefox from generating WebRTC ICE/STUN
 * candidates, including candidate addresses that could bypass VPN assumptions. */
user_pref("media.peerconnection.enabled", false);

/* Encrypted Client Hello (ECH) — encrypts SNI where the target site supports it */
user_pref("network.dns.echconfig.enabled", true);
user_pref("network.dns.http3_echconfig.enabled", true);

/* TLS 1.3 hybrid X25519MLKEM768 client capability. The historical pref name
 * says "kyber"; current NSS uses the final FIPS 203 ML-KEM construction.
 * Endpoint coverage remains negotiation-dependent. */
user_pref("security.tls.enable_kyber", true);

/* Password manager, payment data, addresses — disabled by the NoID Privacy defaults.
 * Target audience uses an external password manager or a deliberate airgap strategy. */
user_pref("signon.rememberSignons", false);
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("extensions.formautofill.addresses.enabled", false);

/* Firefox Sync stays user opt-in (no account pre-configured). When a user
 * does sign in, stock Firefox enables every engine by default — these two
 * pre-seed the documented NoID Privacy posture: Passwords and Open Tabs stay
 * out of Sync unless the user re-enables them under "Choose what to sync"
 * (a user change wins). Module 16 owns these AutoConfig defaults; keeping them
 * out of profile user.js is what makes that promise true. */

/*** [SECTION: STABILITY] ***/

/* FPP instead of RFP — granular protection, less breakage than RFP letterboxing.
 * All FPP targets are active except the breakage exclusions below. A local
 * three-session check produced distinct WebGL and Canvas image hashes; that
 * observation is not a universal anonymity or uniqueness guarantee.
 *
 * Excluded (cause breakage):
 * - CSSPrefersColorScheme: allow real dark/light theme
 * - JSDateTimeUTC: real timezone instead of UTC
 * - RoundWindowSize: real window size
 * - Navigator*: real browser identity (counterproductive to spoof on Linux)
 * - KeyboardEvents: real keyboard layout
 * - SiteSpecificZoom: site-specific zoom allowed
 *
 * ACTIVE: Font restriction, AudioContext, JSMath, screen spoofing, Canvas+WebGL
 * randomization, HW-Concurrency, MediaDevices, touch points, WebGPU limits. */
user_pref("privacy.resistFingerprinting", false);
user_pref("privacy.fingerprintingProtection", true);
user_pref("privacy.fingerprintingProtection.overrides", "+AllTargets,-CSSPrefersColorScheme,-JSDateTimeUTC,-RoundWindowSize,-NavigatorPlatform,-NavigatorOscpu,-NavigatorUserAgent,-HttpUserAgent,-NavigatorAppVersion,-KeyboardEvents,-SiteSpecificZoom");

/* Disable remote FPP overrides — prevents Mozilla from relaxing FPP via remote */
user_pref("privacy.fingerprintingProtection.remoteOverrides.enabled", false);

/* clearOnShutdown_v2.cookiesAndStorage has one authoritative assignment in
 * Section 2811 above. */

/* WebGL enabled — FPP WebGL targets protect separately (vendor/renderer spoofing,
 * WebGL limits at spec minimum, debug_renderer_info neutralized) */
user_pref("webgl.disabled", false);

/* DRM/Widevine: explicit consent before proprietary code or GMP metadata.
 * Firefox 152 schedules GMPInstallManager from a browser-idle task even when
 * no DRM site was opened; media.eme.enabled=false alone therefore does not
 * close the metadata path.  The paired updater + Widevine controls keep a
 * pristine profile offline and uninstalled.  Users who need DRM opt in with
 * `noid-firefox-drm enable` after closing Firefox; the helper appends the
 * reviewed inverse overlay and survives Update-All re-application. */
user_pref("media.eme.enabled", false);
user_pref("media.gmp-manager.updateEnabled", false);
user_pref("media.gmp-widevinecdm.enabled", false);
user_pref("media.gmp-widevinecdm.allow-chromium-update", false);

/*** [SECTION: NOID-HW-DECODE]: Hardware Video Acceleration
 * NoID Privacy deliberately leaves Firefox's hardware-video and WebRender
 * force switches at their native defaults. Fedora Firefox enables supported
 * Intel/AMD VA-API paths by default; Firefox's GPU blocklist, VA-API probe and
 * failed-sanity-test state must remain authoritative on every other driver.
 *
 * Do not set `media.hardware-video-decoding.force-enabled` or
 * `gfx.webrender.all` as image defaults: both are blocklist overrides, not
 * normal enablement switches. Software fallback remains available and the RDD
 * media sandbox is never disabled to make an unsupported decoder work. ***/

/*** [SECTION: USABILITY] ***/

/* Smooth Scrolling — Module 16 seeds a user-overridable accessibility default. */

/* Home / New Tab page: Module 16 defaults to the clean Firefox Home page
 * without resetting a user-selected homepage or startup behavior. */

/*** [SECTION: MOZILLA AI / CLOUD-VPN / NIMBUS BLOCK] ***/

/* Firefox IP Protection (Mozilla Cloud-VPN via Fastly MASQUE, FF143+).
 * System addon ipp-activator@mozilla.com pulls VPN server list in the background
 * → users use their own VPN solution, Mozilla VPN is undesired by default.
 * Module 16 supplies the complete user-overridable off-state. */
/* FF145/146/149 added per-mode sub-toggles (Mozilla VPN "location selection" +
 * auto-start, surfaced in the FF151 UI). The master .enabled=false already gates
 * them (verified FF151 default of each sub-pref = false); set explicit as
 * belt-and-suspenders defaults against a future Mozilla default-flip. */

/* Firefox AI Controls are the maintained user-facing master and feature
 * switches in Firefox 153. Module 16 defaults browser.ai.control.* to blocked
 * and extensions.ml.enabled to false. It deliberately does not override the
 * legacy browser.ml.enable engine gate: Firefox's current AI Controls do not
 * write that pref, so forcing it off would leave features broken after the
 * user explicitly unblocks them. Feature-specific defaults below still close
 * chatbot and smart-tab-grouping entry points until that native choice. */

/* Firefox 148+ "AI Controls" UI panel (Settings > AI Controls).
 * The "Block AI enhancements" master toggle reads browser.ai.control.default.
 * Setting this to "blocked" flips the master toggle ON, blocking ALL current
 * and future AI enhancements (including ones Mozilla hasn't shipped yet).
 * Per Mozilla support docs (Feb 2026): values are "allowed" or "blocked".
 * Module 16's user-overridable defaults cover the master and all six current
 * individual controls. */

/* Clear Nimbus experiment enrollment — stale A/B test strings act as FP vector */
user_pref("nimbus.profileId", "");
user_pref("browser.ml.chat.nimbus", "");
user_pref("sidebar.nimbus", "");
/* Nimbus config-ROLLOUTS (FF148, verified FF151 default=true) — Mozilla-pushed
 * config changes delivered via Remote Settings, NOT gated by app.normandy.enabled=
 * false (that only covers the legacy Normandy/Shield study client). Close the
 * remote-config rollout channel so nothing is silently applied to the browser. */
user_pref("nimbus.rollouts.enabled", false);

/* Sidebar: aichat is absent initially and the sidebar stays functional.
 * The toolbar composition is browser-owned state, so Module 16 supplies only
 * user-overridable defaults. */

/* Captcha detection telemetry — Firefox sends captcha metadata to Mozilla
 * (arkenfox v144 gap). The component's enable-gate is the ACTOR pref
 * (ActorManagerParent.sys.mjs enablePreference; same kill-switch Tor Browser
 * sets) — disabling it stops the collection actor entirely. */
user_pref("captchadetection.actor.enabled", false);

/* Clear persistent identifiers — disabled features retain runtime UUIDs.
 * This clear forces UUID rotation on every Firefox start → ephemeral state. */
user_pref("app.normandy.user_id", "");
user_pref("dom.push.userAgentID", "");

/*** [SECTION: NEW TAB PAGE CLEANUP] ***/

/* Pocket Stories ("Recommended Stories") start off through Module 16's
 * user-overridable Firefox Home defaults. */

/* Default Top Sites empty — Mozilla regional defaults (Wikipedia/YouTube/
 * Reddit/Amazon per locale) are dynamically generated by
 * ActivityStream.sys.mjs's getValue() function and OVERRIDE this user_pref
 * at startup. The actual block is via lockPref() in mozilla.cfg (Module 16
 * Step 3b.3). Canonical section 0106 above carries the single profile-level
 * defense-in-depth value for code readers. */

/* Top Sites grid stays visible. mozilla.cfg blocks Mozilla's generated default
 * tiles and seeds the curated NoID Privacy pins and row count as defaults, so
 * later user customization and grid visibility remain user-owned. */

/* Weather/location (FF152 classic + Nova widget paths). Disable the feed as
 * well as every current presentation gate by default: showWeather alone does
 * not stop the feed from resolving country/city and querying
 * Merino/AccuWeather. Module 16 keeps the whole set user-overridable. */

/* RegionDetector otherwise performs an idle country lookup against Mozilla's
 * location service when browser.search.region is absent. Keep web-requested
 * geolocation itself available; only the browser's unsolicited regional
 * customization lookup and periodic refresh are disabled by default. */

/* Firefox 152 wallpapers are a Remote Settings feed backed by the
 * newtab-wallpapers-v2 collection and attachment CDN. Both the feature and
 * feed stay off until a user explicitly changes them. Module 16 carries the
 * user-overridable off-state. */

/* TopSites falls back from a missing rich icon to BackgroundPageThumbs, which
 * anonymously navigates to the pinned URL before the user clicks it.  The
 * hidden maintained kill-switch short-circuits captureIfMissing() before any
 * load; M16 also supplies local data-URI favicons for all shipped pins. */
user_pref("browser.pagethumbnails.capturing_disabled", true);

/* Highlights (recently visited pages on Home) start off through Module 16's
 * user-overridable Firefox Home defaults. */

/* FF148 newtab "private ping" — DAP/OHTTP privacy-preserving newtab measurement
 * (verified FF151 default=true). Closes the DAP telemetry transport. */
user_pref("browser.newtabpage.activity-stream.telemetry.privatePing.enabled", false);


/*** [SECTION: ETP-STRICT TIGHTEN] ***/

/* Disable ETP Strict "Fix minor site issues" compatibility allowlist.
 * The baseline exceptions remain enabled to preserve login and payment
 * compatibility. Disabling the convenience list can block more tracker-backed
 * embeds but can also break comments, videos or other allowlisted site content.
 * Mozilla allowlist: https://etp-exceptions.mozilla.org/
 * Module 16 supplies the user-overridable false default. */


/*** [SECTION: PRIVACY/TELEMETRY TIGHTENING] ***/

/* Beacon API — fire-and-forget tracking-pings — anti-tracking */
user_pref("beacon.enabled", false);

/* Mozilla VPN advertising in UI */
user_pref("browser.vpn_promo.enabled", false);

/* Firefox View feature-tour advertising — UI cleanup */
user_pref("browser.firefox-view.feature-tour", "");

/* Recent-Search suggestions in URL bar — privacy */
user_pref("browser.urlbar.suggest.recentsearches", false);

/* Global Privacy Control header — DISABLED.
 * Sending the GPC header is a unique signal that fingerprints privacy-aware
 * users and lifts them out of the anonymity crowd. Better to blend in with
 * the Firefox-default behavior (no header). User can manually enable in
 * Settings > Privacy if they consciously want the CCPA/GDPR opt-out signal.
 * Module 16 supplies a user-overridable false default so that choice persists. */


/*** [SECTION: USER-STARTED UPDATES ONLY] ***/

/* Fedora owns the browser package through DNF; executable add-ons are owned
 * exclusively by the explicit NoID Privacy Update All workflow. Keep every
 * native background binary/add-on updater off. Security/blocklist content is
 * a separate data feed and remains governed by its dedicated privacy policy. */
user_pref("app.update.auto", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.update.autoUpdateDefault", false);
user_pref("extensions.systemAddon.update.enabled", false);


/*** [SECTION: POST-v144 PRIVACY (NoID Privacy-maintained arkenfox v144 gap)] ***/

/* Privacy-Preserving Attribution (PPA) — Mozilla's ad-conversion measurement.
 * Firefox 152's PrivateAttributionService reads only this submission gate;
 * the retired dom.private-attribution.enabled name is deliberately omitted. */
user_pref("dom.private-attribution.submission.enabled", false);

/* Local Network Access (LNA) restricts web content reaching localhost and LAN
 * resources. Keep the feature and prompt gate active, and silently block
 * third-party trackers from local-resource access. Legitimate first-party
 * localhost development remains available through the Allow/Block prompt. */
user_pref("network.lna.enabled", true);
user_pref("network.lna.blocking", true);
user_pref("network.lna.block_trackers", true);

/* WebSockets were exempted from the LNA gate while the specification and the
 * cross-browser implementations settled. Bug 1996551 documents that temporary
 * exemption and its opt-in pref; Bug 2042339 enables the gate for Firefox 154.
 * Firefox 153 already carries the pref but defaults it to false (verified on
 * the running build), so setting it explicitly closes the ws:// path to
 * localhost/LAN one release early and pins the behavior against a later
 * upstream revert. Module 05 LAN isolation does not make this redundant:
 * it drops RFC1918 egress on the physical links, while loopback and the
 * libvirt bridge stay reachable by design, and noid-lan-allow grants open a
 * single LAN peer outright. Top-level navigation to localhost is unaffected
 * (network.lna.allow_top_level_navigation), and local-to-local pages keep
 * their own WebSockets; only a remote origin reaching in gets the prompt. */
user_pref("network.lna.websocket.enabled", true);

/* Firefox 153 maps security.qwacs.enabled to @IS_NOT_ANDROID@ (true on
 * desktop, false on Android). Keep that native desktop verification/display
 * behavior: NoID Privacy neither overrides the switch nor enables QWAC test
 * trust anchors, and ordinary WebPKI validation remains authoritative.
 * Source: mozilla-release FIREFOX_153_0_RELEASE StaticPrefList.yaml. */

/* SPOOF-ENGLISH = 1 (disabled) — arkenfox 4506 default, kept deliberately.
 * Values (arkenfox 4506, verified vs Mozilla source + live FF): 0 = startup
 * prompt, 1 = disabled, 2 = enabled. NoID Privacy uses FPP not RFP, so the language
 * spoof itself is moot here — BUT the "request English versions" prompt fires
 * at value 0 regardless of RFP (locale-init, Tor-Browser heritage), popping a
 * dialog at every launch on a non-English UI locale. Value 0 must NOT be set
 * here; canonical section 4506 above sets 1 once, disabling both the spoof and
 * the prompt. intl.accept_languages is left to the system-locale flow (see
 * noid-locale.js). */


/*** [SECTION: NEW PROFILE MANAGER DISABLE] ***/

/* Firefox 138+ introduced a NEW toolbar-based profile manager that operates
 * via SQLite database in ~/.config/mozilla/firefox/Profile Groups/ and is
 * INCOMPATIBLE with the legacy profiles.ini / `firefox -P <name>` system
 * we rely on for default-release + playground dual-profile setup.
 *
 * FF150 default: browser.profiles.enabled=true → users see empty Profile
 * Picker dialog when clicking Firefox launcher (because new system has no
 * profiles registered, while our legacy profiles.ini has them but new
 * system ignores it).
 *
 * Both systems coexist but don't communicate (Bugzilla mass-reports 2026).
 * For NoID Privacy's `firefox -P default-release` and `firefox -P playground`
 * launcher pattern to work reliably, we MUST disable the new system.
 *
 * Defense-in-depth: also locked at system level via mozilla.cfg lockPref
 * (Module 16 Step 3b) — covers user-created profiles which lack this user.js.
 *
 * Refs:
 *   https://connect.mozilla.org/t5/discussions/the-new-profile-management-system-is-fundamentally-broken
 *   https://support.mozilla.org/en-US/kb/profile-manager-create-remove-switch-firefox-profiles
 */
user_pref("browser.profiles.enabled", false);
user_pref("browser.profiles.created", false);


/* The initial uBlock Origin toolbar placement is deliberately absent here.
 * Module 16 seeds it once as an AutoConfig defaultPref, so Firefox's
 * browser-managed prefs.js can retain every later user customization. */


/* NoID Privacy end-of-file parrot — signals full consolidated file applied */
user_pref("_user.js.parrot", "NOID-COMPLETE: full hardening applied");
