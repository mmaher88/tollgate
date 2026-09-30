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
   appears at about the same time); a `502` from a passed-through host that cannot be
   reached; a `503` from too many passthrough tunnels. `fallback:start_fallback` may still
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
