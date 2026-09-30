# Alpha 2 experiments: blocking with Connectivity Assist

Run on iOS 27 or later with a SIM that has cellular data, after installing the build under
test as in the M2 checklist (`docs/experiments/m2.md`). Record the date, iOS version, CI
run and outcome for each.

Connectivity Assist (Settings, Wi-Fi: a main switch, and one on each network's page) races
a browser's connections: when the attempt over Wi-Fi, which goes through Tollgate's proxy,
fails or is not ready after about 350 ms, iOS starts a second attempt over cellular data
that uses the carrier's DNS and no proxy. An attempt through the proxy is ready once the
`CONNECT` answer and the TLS handshake (including the browser's certificate check) are
done. Tollgate used to answer a `CONNECT` to a blocked host with `403`; iOS then started
the cellular attempt at once and the blocked host loaded over cellular. Now it answers
`200`, completes TLS with its own certificate for that host and fails every request on the
connection without a response, so the attempt through the proxy is ready and wins, and
the page sees a network error for each blocked request, as before. At most 64 blocked
connections are open at once; when all are taken, the one idle longest is closed to make
room. Blocked hosts that are passed through (Never filtered, the built-in list, Learned
certificate pins) still get `403`, and so do blocked hosts while the tunnel is low on
memory, or while all 64 blocked connections are open and none of them becomes idle within
150 ms. Blocks made by DNS alone (HTTPS filtering off, or apps that do not use the proxy)
still answer with `0.0.0.0` or `::`, so the connection fails, which iOS can retry over
cellular; the Home notice asks the owner to turn Connectivity Assist off for that.

E23 to E30 check the filtering changes made after E18 to E22: lists compiled again after
an app update, a fifth built-in list, wildcard rules in the DNS lists, blocked requests
that fail instead of loading, passed-through hosts answered at once, DNS connections
kept through idle time, certificate pins learned from apps that hang up without an alert,
hosts files recognized by their content, and learned pins kept when HTTPS filtering is
turned off and on. Run E23 right after installing the build, since it checks what its
first launch does.

E31 to E35 check the changes made after E30: two more built-in DNS lists that leave the
hosts of banks and sensitive services alone, two hosts Tollgate blocks on its own, browser
requests that fail when a server's certificate is bad, and pins learned from an app that
keeps refusing Tollgate's certificate for a host that other apps trust it for. Run E31
right after installing the build, for the same reason as E23. E36 checks the apps behind
the hosts added to the built-in passthrough list.

## Logs

In a second terminal, stream Tollgate's lines (as `tooling/scripts/logs.sh` does) together
with Network.framework's lines about the race and the proxy:

    tooling/scripts/device.sh syslog live --label -e 'dev\.tollgate\.' -e 'fallback:(start|finish)_' -e 'http connect Proxy received status'

Network.framework names hosts only as `Hostname#<hash>`; each line carries a connection id
such as `[C28.1]`, which ties the lines of one connection together (`[C28.1.1.1.1:3]`
belongs to `C28`). The process name follows the time.

Safari makes its page connections, blocked ad and tracker requests included, in WebKit's
networking process (`com.apple.WebKit.Networking`, one for each browser, shortened to
`com.apple.WebKit` in some logs), not in `MobileSafari`; so does Chrome for much of what
its pages load. In the captures so far that process wrote nothing to this stream, so the
log shows only the connections `MobileSafari` and `Chrome` make in their own processes
(for Safari, a handful), plus `mDNSResponder` for DNS. Each check below says what its log
part proves when WebKit's lines are missing.

- `event: fallback:start_fallback @0.420s`: iOS started the cellular attempt, that long
  after the connection began. At about 0.35 s or later the attempt through the proxy was
  slow; earlier, it had failed (for example a `403` on the same connection just before).
- `event: fallback:finish_primary`: the attempt over Wi-Fi, through Tollgate, was used.
- `event: fallback:finish_fallback`: the cellular attempt was used, around Tollgate.
- `http connect Proxy received status: HTTP/1.1 403 Forbidden`: the proxy answered a
  `CONNECT` with something other than `200`. A `200` is logged as `http connect proxy
  connected` for every proxied connection, too many to follow, so the command leaves it
  out.
- `blocked <host>: refused with 403, ...` (Tollgate, `dev.tollgate.core`): the tunnel
  refused a blocked host its blocked connection, because it was low on memory
  (`... bytes of memory available`) or all 64 blocked connections were open and none became
  idle in time (`... blocked connections open and none could be closed in time`).
  `refused by closing the connection` is the same for a blocked server name behind another
  host. Each of the two causes is logged at most once a minute, so one line can stand for
  several refusals. A blocked host that is passed through gets its `403` without a
  Tollgate line.

## E18: blocked hosts with Connectivity Assist on

1. Wi-Fi and cellular data both on; Settings, Wi-Fi, Connectivity Assist on (the main
   switch and the current network's). Protection on, HTTPS filtering on. Start the log
   command above. Load any page in Safari and note whether any `fallback:start_primary`
   line comes from a process whose name starts with `com.apple.WebKit`. If none does,
   WebKit's lines are missing: the log parts of steps 3 and 4 then prove nothing for
   Safari and cover Chrome only in part, and Safari passes or fails on the score, the ads
   and the error page alone.
2. In Safari, open an ad-block test page (one that tries to reach known ad and tracker
   hosts and reports a score), then three or four sites with heavy advertising (news,
   recipes). Do the same in Chrome. Pass: the test page reports the ad and tracker hosts
   as blocked, with the same score as in E19; the sites show no ads; the pages themselves
   load normally, with nothing missing that shows with protection off and no noticeable
   extra delay; the Activity tab lists the blocked hosts as domain blocks.
3. Pass, in the log for the same time: no `fallback:finish_fallback` from `MobileSafari`,
   `Chrome` or any process whose name starts with `com.apple.WebKit`, and few or no
   `http connect Proxy received status` lines from them. Where a status comes from:
   a `403` from a blocked host that is passed through (Never filtered, the built-in list,
   Learned certificate pins), or from any blocked host while the tunnel is low on memory
   or has 64 blocked connections open with none idle (Tollgate's `refused with 403` line
   appears at about the same time); a `503` from too many passthrough tunnels. A
   passed-through host that cannot be reached gets `200` and then its connection closed
   (see E26), so it shows no status line. `fallback:start_fallback` may still
   appear for slow connections, followed by `fallback:finish_primary` for the same
   connection; note how many. Note every `finish_fallback` and every `403` with its
   connection id, process and time, and what the page was loading. For each `403` whose
   host can be told (the log names hosts only by hash, so from what the page was loading),
   note whether the host is under Never filtered, the built-in list or Learned certificate
   pins; a `403` for a host on none of them points to low memory or the blocked-connection
   cap, so also note every Tollgate `refused with 403` line and how many tabs and pages
   were open.
4. Take a host from the Activity tab's domain blocks and open `https://<that host>/` in
   Safari, then in Chrome. Pass: the browser shows its own error page (for example "the
   network connection was lost"), never a certificate warning, an empty white page or the
   host's content. For Chrome, and for Safari only if step 1 found WebKit's lines, also
   pass: the log shows no `finish_fallback` for it.

Result:

## E19: blocked hosts with Connectivity Assist off

1. Settings, Wi-Fi: turn off Connectivity Assist (the main switch and the current
   network's). Everything else as in E18.
2. Repeat E18 steps 2 to 4. Pass: the same results; this run is the reference for E18.
   Record the test page score. Note whether any `fallback:` lines appear at all for
   `MobileSafari`, `Chrome` or a `com.apple.WebKit` process (without WebKit's lines, the
   browsers' page loads are mostly not in the log).

Result:

## E20: DNS-only blocking with Connectivity Assist on

1. Turn off HTTPS filtering (the tunnel restarts). Connectivity Assist on, Wi-Fi and
   cellular data both on.
2. Load the same test page and sites in Safari and Chrome. Record the test page score and
   the number of `fallback:finish_fallback` lines, from the browsers (`MobileSafari`,
   `Chrome` and any `com.apple.WebKit` process) and from `mDNSResponder` (a DNS query
   retried over cellular). Without WebKit's lines (E18 step 1), the browser counts miss
   most page connections; the scores then carry the comparison.
3. Turn Connectivity Assist off and repeat step 2. Record the score. The difference between
   the two scores is what blocking by DNS alone loses to Connectivity Assist, which the
   Home notice (E21) is for.
4. Optional: turn HTTPS filtering on again and use two or three apps with ads, first with
   Connectivity Assist on, then off. Note any app whose ads show only with it on: apps
   that do not use the proxy are blocked by DNS alone even with HTTPS filtering on.

Result:

## E21: Connectivity Assist notice

1. Open Tollgate on iOS 27. Pass: Home shows "Turn off Connectivity Assist" right after the
   protection section, with text that names Settings, Wi-Fi, the main switch and each
   network's page, and says Tollgate cannot read the setting. It shows whether or not
   Connectivity Assist is already off.
2. Tap "I turned it off". Pass: the notice disappears, and stays gone after closing the app
   from the app switcher and opening it again.
3. Settings. Pass: a Connectivity Assist section at the end with the same text below
   "Show the notice on Home". Tap it. Pass: the button is disabled and Home shows the
   notice again. Dismiss it again.
4. Settings, Accessibility, Display and Text Size, Larger Text at a large size. Pass: the
   notice's text wraps and nothing is cut off. Set the size back.
5. If a phone on iOS 26 or earlier is at hand: Pass: no notice on Home and no Connectivity
   Assist section in Settings.

Result:

## E22: apps that pin certificates and blocked hosts

1. Connectivity Assist off, HTTPS filtering on. In Settings, Learned certificate pins, pick
   a host of an app you can test (note both). Add `||<that host>^` to My rules and Save.
2. Use the app. Pass: what needs the host fails, and the log shows `http connect Proxy
   received status: HTTP/1.1 403 Forbidden` from the app's process (a blocked host that is
   passed through still gets `403`).
3. In Learned certificate pins, swipe the host to forget it, then use the app again for a
   minute. Pass: what needs the host still fails; the host does not come back under
   Learned certificate pins, and no other blocked host appears there (the app rejects
   Tollgate's certificate on the blocked connection, which teaches no pin).
4. Turn Connectivity Assist on and use the app again as in step 3. Pass: the host still
   does not appear under Learned certificate pins. Note whether the app now reaches the
   host: the rejected certificate fails the attempt through the proxy, which iOS can
   retry over cellular (look for `fallback:finish_fallback` from the app's process).
5. Remove the rule from My rules, Save, and use the app. Pass: it works again, after
   failing at most once or twice while its host is learned again; the host is listed under
   Learned certificate pins again.

Result:

## E23: first launch after the update

1. Before installing the build under test, note in Tollgate: Settings, Filter lists (the
   built-in lists that are on, and each list under Added by you with its type), and
   Settings, Learned certificate pins. If a log of the previous build's last list update
   is at hand, note its `lists compiled: <rules> rules, <domains> domains` line.
2. Start the log command above; it includes the app's own lines (`dev.tollgate.app`).
   Install the build, open Tollgate and stay on Home for a minute without tapping
   anything. Pass: one `lists compiled: <rules> rules, <domains> domains` line appears
   within that minute. `<domains>` is about 34,000 higher than before the update, unless
   the StevenBlack hosts list was already compiled as a hosts file under Added by you.
   Settings shows Filter lists with one more list enabled than before, or the same number
   if Added by you has a list with the StevenBlack address (it is no longer counted, see
   step 3); Filter lists shows StevenBlack hosts as the fifth built-in list, switched on;
   the button below the lists reads "Update now" and the status line under it does not
   say "Changes are not applied yet."
3. If Added by you has a list with the StevenBlack address: Pass: the log line of step 2
   comes after `StevenBlack hosts starts from the cached copy of <its name>`, and the
   list's row says "Not used: the same list as the built-in StevenBlack hosts. You can
   delete it.". If its type was Request rules, the Filter lists status says "<its name> is
   a hosts file, so its type was changed from Request rules to Hosts file.", its row now
   shows Hosts file, and `<rules>` is about 75,000 lower than before; otherwise the log
   line of step 2 also comes after `<its name> skipped: same address as StevenBlack
   hosts`. Delete it and tap "Apply changes now". Pass: `lists compiled` with the same
   numbers as in step 2.
4. Switch StevenBlack hosts off and tap "Apply changes now". Pass: `<domains>` drops by
   about 34,000 and `<rules>` stays the same. Switch it on again and apply.
5. Close Tollgate from the app switcher and open it again. Pass: no `lists compiled` line
   in the first minute: the lists are compiled once for each build.
6. When a later build is installed (any change), open it as in step 2. Pass: one
   `lists compiled` line within a minute, with the same numbers when the lists did not
   change, and the Filter lists status keeps its "Updated" time: the lists were compiled
   from the copies already downloaded.

Result:

## E24: wildcard rules in the DNS lists

1. Protection on; HTTPS filtering either way (run it once with it on and once off). In
   Settings, My rules, add these two lines and Save; the log shows `lists compiled`:

       ||tollgate-wild*.example.com^
       @@||tollgate-wild-ok*.example.com^

2. In Safari, open each of these; none of the names exists, so every page fails, and the
   Activity tab (Domains) tells a block from the rest:
   - `https://tollgate-wild1.example.com/` and `https://a.tollgate-wild1.example.com/`:
     Pass: both are listed as domain blocks.
   - `https://tollgate-wild-ok1.example.com/` (the exception) and
     `https://xtollgate-wild1.example.com/` (the match must start at a label): Pass:
     neither is listed.
3. Optional, with a real list: on the workstation, pick from the AdGuard DNS filter two
   or three rules that start with `||` followed by a letter or digit (not `||*`), end with
   `^` and have a `*` in the name, and whose domain after the last `*` is not blocked on
   its own (search the list for `||<that domain>^` and for its parents: a rule such as
   `||ad.*.tracker.example^` is no good when the list also has `||tracker.example^`). For
   each, make up a name the rule matches (put a few letters in place of the `*`) and one
   it does not (put a letter before the first label), and repeat step 2 with them. Pass:
   the same. The Activity tab shows the names, so do not use names you would not want
   listed there.
4. Remove the two lines from My rules and Save. Pass: after `lists compiled`,
   `https://tollgate-wild2.example.com/` is no longer listed as a domain block.

Result:

## E25: blocked requests fail instead of loading

With HTTPS filtering on, a request that the filter lists block used to get an empty `403`,
which a page sees as loaded. Now a browser's request gets no response (the page sees a
network error), except a top-level page, which gets a short page saying Tollgate blocked
it; requests from apps, which do not say what they are for, still get the empty `403`.

1. HTTPS filtering on, Connectivity Assist off. In Safari, open the ad-block test page used
   in E18. Pass: every host the page lists that the Activity tab shows as blocked, as a
   domain or as a request, is reported blocked; record the score, which should be at least
   E19's. Before this build, hosts that only request rules blocked were reported as
   loaded.
2. The same in Chrome. Pass: the same.
3. In My rules, add `||example.com/tollgate-check/$document` and Save. In Safari, open
   `https://example.com/tollgate-check/`. Pass: a plain text page that starts with
   "Tollgate blocked this page." and says how to allow it from Activity; the Activity tab
   lists a request block for that address. Remove the line, Save, and reload the page.
   Pass: the site's own "Example Domain" page (example.com answers this address with
   status 404 but shows its usual page), not Tollgate's.
4. Open three or four sites with heavy advertising in Safari and Chrome, as in E18. Pass:
   no ads; the pages load normally, with nothing missing that shows with protection off;
   Tollgate's blocked page never appears inside a page (in a frame), only in place of a
   whole page.
5. Use two or three apps with ads for a few minutes. Pass: they work as before, and in the
   Activity tab no request block from them climbs by more than a few a minute (an app
   that retried its blocked requests without end would show here).

Result:

## E26: passed-through hosts answered at once

A `CONNECT` to a host that is passed through (Never filtered, the built-in list, Learned
certificate pins) is now answered `200` at once, while the proxy looks the host up and
connects to it; before, the answer waited for both, about 40 ms. A host that cannot be
reached gets its connection closed after the `200`, which the client sees as a failed
TLS handshake, instead of a `502`.

1. Add `-e 'Sent http connect request to proxy' -e 'http connect proxy connected'` to the
   log command above. HTTPS filtering on.
2. Use the App Store and open an Apple website in Safari (Apple's hosts are on the
   built-in passthrough list). Pass: for each connection id, `http connect proxy
   connected` follows `Sent http connect request to proxy` within 10 ms for nearly every
   connection, also in processes such as `appstored`, `cloudd` and `itunesstored`, which
   reach Apple's passed-through hosts (about 40 ms before this build). The App Store and
   the site work.
3. Use an app whose host is under Learned certificate pins. Pass: it works as before.
4. Settings, Never filtered: add `tollgate-down.example.com` (a name that does not exist).
   In Safari, open `https://tollgate-down.example.com/`. Pass: within a few seconds Safari
   shows its own error page, never a certificate warning or an empty page, and the log
   shows no `http connect Proxy received status` for it. Remove the entry.

Result:

## E27: DNS after idle time and after sleep

The tunnel now keeps using its DNS over HTTPS connection after up to two minutes without
queries while the phone is awake (it used to reconnect after 30 s, costing about 40 to
60 ms on the next lookup), and still opens a new one after the phone slept. Tollgate logs
this only at debug level, so the check is what the browser does.

1. Wi-Fi, HTTPS filtering on. Settings, Display and Brightness, Auto-Lock: Never. Note
   Diagnostics, DNS failures. In Safari, open a site not visited today, leave the phone
   untouched with the screen on for 90 s, then open another site not visited today.
   Repeat five times. Pass: every site starts loading without a pause (compare with a site
   opened right after another), and DNS failures has not grown.
2. Lock the phone for at least 5 minutes, unlock it and open a site not visited today at
   once. Pass: as in step 1.
3. Repeat steps 1 and 2 on cellular data with Wi-Fi off. Pass: the same. Note the time of
   any site that paused for a second or more before loading: a network that drops idle
   connections in under two minutes without telling either end costs that pause, once,
   after each idle time. Set Auto-Lock back.

Result:

## E28: apps that hang up on the Tollgate certificate

Some apps that pin their certificates reject Tollgate's without a TLS alert: they close
the connection during the handshake. Tollgate now counts that as a silent refusal
(Diagnostics, Silent certificate refusals) and passes the host through once refusals
of it come in three different seconds within 10 minutes, unless a client completed a
handshake for that host in the last 10 minutes, or refusals hit four or more hosts within
10 s (a common cause such as a network change, which also takes back pins learned from
refusals in that time).

1. HTTPS filtering on, Connectivity Assist off. Note Diagnostics, Certificate rejections
   and Silent certificate refusals, and the hosts under Settings, Learned certificate pins.
   Start the log command above.
2. Browse in Safari and Chrome for 10 minutes: several sites, switching tabs, locking the
   phone once while a page loads, and turning Wi-Fi off and on once. Pass: no host of the
   sites visited appears under Learned certificate pins, and Tollgate's log has no
   `learned certificate pin for <host> after 3 silent refusals` line for one. Silent
   certificate refusals may grow (browsers drop connections they no longer need). Note any
   `silent refusals on <n> hosts within 10 s have a common cause` line and what happened
   at that time.
3. Turn Connectivity Assist on and repeat step 2 for 5 minutes. Pass: the same.
4. Use the apps you use daily for a few minutes each, especially any that failed with
   HTTPS filtering on in earlier builds (showed no content or could not connect). Pass:
   an app that fails at first works after pulling to refresh or retrying for about ten
   seconds, and stays working (a part of the app that uses another host, such as uploads
   or media, may fail until it has been tried again a few times within 10 minutes); for
   its host the log shows `<host> hangs up on our certificate without an alert; passing
   it through from now on`, and the host appears under Learned certificate pins. Note
   each such app and host.
5. Forget one of those hosts in Learned certificate pins and use its app again, on Wi-Fi
   with cellular data on. Pass: it fails briefly and the host is learned again (a new
   `learned certificate pin for <host>` line). Within about 30 s of that line, turn Wi-Fi
   off in Control Center. Pass: within 60 s of that line the log shows `network path
   changed` and then `network changed: dropped 1 certificate pins learned from silent
   refusals in the last 60 s`, and the app gets its host learned again when it next
   fails. A `network path changed` line more than 60 s after the learned line keeps the
   pin by design, so repeat the step. Airplane mode is no substitute: it can stop the
   tunnel, and a pin is saved when the tunnel stops and kept after it restarts. Turn Wi-Fi
   back on afterwards.

Result:

## E29: hosts files added with the wrong type

The built-in lists' addresses are in `ios/Shared/FilterLists.swift`.

1. Settings, Filter lists: switch StevenBlack hosts off. Add a list with the StevenBlack
   address, named "Hosts check", with the type Request rules, and tap "Apply changes now".
   Pass: after `lists compiled`, the status shows "Hosts check is a hosts file, so its
   type was changed from Request rules to Hosts file."; the row shows Hosts file, also
   after leaving the screen and coming back; `<rules>` is the same as in E23 and
   `<domains>` the same as with StevenBlack hosts on.
2. Switch EasyPrivacy off. Add a list with the EasyPrivacy address, named "Adblock check",
   with the type Hosts file, and apply. Pass: the status shows "Adblock check is written in
   adblock syntax, so its type was changed from Hosts file to Domain rules."; the row shows
   Domain rules; `<rules>` drops by EasyPrivacy's request rules, since it now feeds only
   the DNS blocklist.
3. Delete both lists, switch StevenBlack hosts and EasyPrivacy on again, and apply. Pass:
   the numbers of E23 step 2, and no warning.

Result:

## E30: learned pins when HTTPS filtering is turned off and on

1. With at least one host under Settings, Learned certificate pins (from E28 or earlier),
   turn HTTPS filtering off, wait for Protected, then turn it on. Pass: the same hosts are
   still listed.
2. In Settings, General, About, Certificate Trust Settings, turn full trust for the
   Tollgate certificate off. Open Tollgate. Pass: HTTPS filtering turns itself off; the
   learned pins are still listed.
3. Turn full trust on again, open Tollgate and turn HTTPS filtering on. Pass: Learned
   certificate pins shows "None yet": pins learned while the certificate was not trusted
   may be wrong, so they are cleared. Apps that pin are learned again as they are used.
4. Once an app's host is learned again, turn HTTPS filtering off and on. Pass: that host is
   still listed.

Result:

## E31: two more built-in DNS lists

HaGeZi Multi LIGHT and OISD small (addresses in `ios/Shared/FilterLists.swift`) are now
built-in DNS lists, on for existing installs. Their maintainers build them not to break
anything, but they also list telemetry hosts of banking apps, so the compile leaves out
each of their blocks that covers a host of the built-in passthrough groups for sensitive
services and banks (`BundledGroup::Sensitive` and `BundledGroup::Banks` in
`core/crates/policy/src/bundled.rs`). The other lists still block what they list.

1. Before installing the build under test, note in Tollgate: Settings, Filter lists (the
   built-in lists that are on, and each list under Added by you with its address and
   type). If a log of the previous build's last list update is at hand, note its
   `lists compiled: <rules> rules, <domains> domains` line.
2. Start the log command above; it includes the core's lines in the app
   (`dev.tollgate.core`) and the app's own (`dev.tollgate.app`). Install the build, open
   Tollgate and stay on Home for a minute without tapping anything. Pass: within that
   minute, in this order: `HaGeZi Multi LIGHT: left out <n> blocks of exempt hosts` and
   `OISD small: left out <n> blocks of exempt hosts` (about 115 and 22 when this was
   written, never 0), and no such line for any other list; `Tollgate extras: skipped 0
   lines for the DNS blocklist` (see E33); `compiled filter lists: CompileReport {...}`
   with `domain_exempted` the sum of the two `<n>`; then one `lists compiled: <rules>
   rules, <domains> domains` line, with `<rules>` as before the update and `<domains>`
   about 21,800 higher (about 232,000 in all when this was written). Settings, Filter
   lists shows HaGeZi Multi LIGHT and OISD small as the sixth and seventh built-in lists,
   switched on; the button below the lists reads "Update now" and the status line under
   it does not say "Changes are not applied yet." A new list that could not be downloaded
   is named in the status and left out; tap "Update now" later and check again.
3. If Added by you has a list with the address of either new list (for OISD small, with
   or without a `/` at the end) typed Domain rules or Hosts file: Pass: the log line of
   step 2 comes after `<its name> skipped: same address as <built-in name>`, and the
   list's row says "Not used: the same list as the built-in <built-in name>. You can
   delete it." (a copy used in place of the built-in list would block the bank hosts the
   built-in list leaves out). Delete it and tap "Apply changes now". Pass: `lists
   compiled` with the numbers of step 2.
4. Switch HaGeZi Multi LIGHT and OISD small off and tap "Apply changes now". Pass: no
   `left out` line; `<domains>` drops by about 21,800 and `<rules>` stays the same.
   Switch both on again and apply. Pass: the numbers of step 2.

Result:

## E32: banks and sensitive services with the new lists

1. HTTPS filtering on. Use each banking, card, payment, brokerage, identity and password
   manager app you use: sign in, open the screens you use most (balances, statements,
   cards, a transfer screen without sending anything). Pass: every app works as with the
   previous build: no failed sign-in, no screen that stays empty or says it cannot
   connect, no new security or device warning.
2. Activity, Domains: look for blocks of hosts under those apps' own domains. For each,
   switch HaGeZi Multi LIGHT and OISD small off, tap "Apply changes now" and use the app
   again. Pass: the same host is blocked again (a newer entry in Activity), so the block
   comes from a list the previous build had too, not from the new lists. Switch both on
   again and apply.
3. Turn HTTPS filtering off and repeat step 1. Pass: the same.
4. The exemption does not cover Apple's hosts, so the new lists block a few of them: ad
   and attribution hosts, and hosts of Apple's feedback service. Use the App Store
   (search, an app's page, an update), iCloud (Photos, Notes), Wallet, and the Feedback
   Assistant app if it is installed (open your feedback list). Pass: everything works as
   with the previous build. Note each Apple host that Activity lists as a domain block and
   what, if anything, failed at that time.

Result:

## E33: hosts Tollgate blocks on its own

Every compile of the DNS blocklist now adds the rules of `TOLLGATE_EXTRAS`
(`core/crates/tollgate-ffi/src/lists.rs`, each with the reason it is there) as a list
named "Tollgate extras", after the other lists: an ad platform's host with its
subdomains, and an analytics service's own name alone, whose subdomains run the
service's site and stay open. No default list blocks either. An exception in any list,
My rules included, still wins.

1. Protection on, HTTPS filtering on. In Safari, open `https://<host>/` for each of the
   two rules' hosts. Pass: both fail with Safari's own error page, and Activity, Domains
   lists both as domain blocks.
2. Open `https://www.<host>/` for the second rule's host. Pass: the site loads normally
   and is not listed in Activity.
3. In My rules, add `@@||<host>^` for the second rule's host and Save. Pass: after
   `lists compiled`, `https://<host>/` loads (it redirects to the `www.` name) and
   Activity lists no new block for it. Remove the line and Save. Pass: it is blocked
   again.
4. Turn HTTPS filtering off and repeat steps 1 and 2. Pass: the same.

Result:

## E34: browser requests to servers with bad certificates

With HTTPS filtering on, a request to an intercepted host whose server presents a
certificate a browser would refuse (for another name, expired, not yet valid, revoked),
or one Tollgate cannot verify with its built-in roots while pin learning is paused by
several such failures at once (as behind a Wi-Fi sign-in page or a network filter that
intercepts HTTPS), used to get a short text `502` from Tollgate, which a page sees as
loaded. Now a browser's request that is not a top-level page gets no response, so the
page sees a network error, as without Tollgate, where the browser refuses the
certificate itself. A top-level page still gets the text, and requests from apps, which
do not say what they are for, still get the `502`. Tollgate logs these failures at debug
level only, so the checks are what the browsers show.

1. HTTPS filtering on, Connectivity Assist off. In Safari, open the ad-block test page
   used in E18, then do the same in Chrome. Pass: the score is at least E25's. For each
   host the page still reports as loaded, open `https://<that host>/` in Safari. Pass:
   none shows a plain text page that starts with "Tollgate: the server's certificate"
   (a host that does was counted as loaded only because of the `502`). Learned
   certificate pins may gain hosts of the page whose certificates Tollgate could not
   verify with its built-in roots (or that it could not make a secure connection to),
   each with `<host>: upstream TLS failed (...); passing it through from now on` in the
   log; note them. Once a host is passed through, the browser checks its certificate
   itself and may trust it and load it, so such a host can count as loaded without any
   fault in this change.
2. Find a host whose server's certificate is for another name (sites that demonstrate
   certificate errors have one) and open `https://<that host>/` in Safari. Pass: a plain
   text page "Tollgate: the server's certificate is for another name, so this site was
   not loaded." (a top-level page keeps the text).
3. Open three or four sites with heavy advertising in Safari and Chrome, and use two or
   three apps for a few minutes. Pass: the pages load normally, with nothing missing that
   shows with protection off, and the apps work as before.

Result:

## E35: an app that refuses the certificate for a host other apps trust

E28's rule learns nothing while any client has completed a handshake with Tollgate's
certificate for the host in the last 10 minutes. An app that pins a host shared with
apps of the same company that do trust the certificate (a messaging app uploading a
video to a host the company's main app also uses) was refused hundreds of times within
a minute and never learned. Now a flood of refusals makes the host a pin despite that
trust: refusals in 10 different seconds within the last 60 s, at least 5 times the
handshakes clients completed for that host in the same 60 s. Refusals the guard holds
back are logged at info level with the host's name once they fall in 3 different seconds
within 60 s, at most once per host every 5 minutes, so the log names the host an app
pins (Network.framework names hosts only by hash).

1. HTTPS filtering on, Connectivity Assist off. Note Diagnostics, Silent certificate
   refusals, and the hosts under Settings, Learned certificate pins. Start the log command
   above.
2. Use an app that failed this way before (for example one that could not send videos or
   uploads with HTTPS filtering on while the rest of it worked), and its company's main
   app if it has one. Use the main app for a minute first, send it to the background, then
   within 10 minutes do in the pinning app what failed before. Pass: it fails or stalls
   for at most about 30 s, then succeeds by itself or on retry, and keeps working. The
   log shows, for one host: first `not learning a certificate pin for <host> yet: <n>
   silent refusals in <s> different seconds within 60 s, but a client trusted our
   certificate for it <t> s ago, with <h> handshakes within 60 s (a flood of refusals in
   10 different seconds, 5 times the handshakes, would make it a pin)`, then `learned
   certificate pin for <host> after a flood of <n> silent refusals in <s> different
   seconds within 60 s, against <h> handshakes; a client trusted our certificate for it
   <t> s ago` and `<host> hangs up on our certificate without an alert; passing it through
   from now on`; the host appears under Learned certificate pins. Note the host, the
   numbers in the lines and how long the app failed. If the host is learned with
   `learned certificate pin for <host> after 3 silent refusals` instead, no client had
   trusted it within 10 minutes: note it and repeat the step with more use of the main
   app, since the flood was not tested. If the app keeps failing, note every `not
   learning a certificate pin` line and every `silent refusals on <n> hosts within 10 s
   have a common cause` line, with the time.
3. Use the main app again. Pass: it works as before.
4. Forget the host in Learned certificate pins, and repeat step 2 on Wi-Fi with cellular
   data on (its `not learning` line is left out if the last one came less than 5 minutes
   before). Within about 30 s of the flood line, turn Wi-Fi off in Control Center. Pass:
   within 60 s of the flood line the log shows `network path changed` and then `network
   changed: dropped 1 certificate pins learned from silent refusals in the last 60 s`, and
   the host is learned again (another `learned certificate pin for <host>` line) when the
   app next keeps retrying. A `network path changed` line more than 60 s after the flood
   line keeps the pin by design, so repeat the step. Airplane mode is no substitute: it
   can stop the tunnel, and a pin is saved when the tunnel stops and kept after it
   restarts. Turn Wi-Fi back on afterwards.
5. Browse in Safari and Chrome for 10 minutes as in E28 step 2. Pass: no `learned
   certificate pin for <host> after a flood` line for a host of the sites visited, and
   none of their hosts appears under Learned certificate pins. Note each `not learning a
   certificate pin for <host> yet` line with its numbers; a browser should cause few, and
   each names a host some client trusted within 10 minutes.

Result:

## E36: apps behind the newer built-in passthrough hosts

The built-in list (`core/crates/policy/src/bundled.rs`) now also passes through, without
decrypting or filtering them: the Microsoft Intune, Entra ID and Enterprise SSO plug-in
hosts that Microsoft says must not be TLS-inspected, hosts that apps pin in their
Info.plist or that vendors list as pinning, Meta's OHTTP relay, and the hosts of two
payment services, Google Pay and Braintree. The DNS lists still block what they list
under them. Tollgate logs no line for a built-in passthrough.

1. Only on a phone enrolled in Microsoft Intune; skip it otherwise. HTTPS filtering on.
   Add `-e 'mdmd'` to the log command above. In Company Portal, open Devices, this
   device, and tap Check status. Pass: the check finishes without an error and the device
   is shown as compliant (or as before the build, with the same reasons), and mdmd logs no
   `Could not send response to MDM server`.
2. HTTPS filtering on. Use the apps whose hosts the new groups list (the comment at the
   head of each group names them; in a messaging app, send and open a photo), and make a
   payment through Google Pay or Braintree if an app offers one: sign in and open the
   screens you use. Pass: each works as with HTTPS filtering off, and the log shows no
   `learned certificate pin` line for their hosts.
3. Settings, Learned certificate pins. Pass: none of the hosts of step 2 is added, and
   `meta-ohttp-relay-prod.fastly-edge.com` is not added again once forgotten and the
   Facebook app is used.

Result:
