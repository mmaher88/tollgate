# M1 devproxy checks

Manual end-to-end check of the Rust core on the Linux workstation: the DNS responder and the
filtering proxy from `tools/devproxy`, driven by `dig`, `curl`, `openssl s_client` and
Firefox. Record the date, the commit and the outcome of each step. Commands run from the
repo root and need the network. The data directory is `/tmp/tollgate-dev`.

## 1. Build and start with the default lists

1. `(cd core && cargo build --release -p devproxy)`
2. `rm -rf /tmp/tollgate-dev && RUST_LOG=info core/target/release/devproxy --data-dir /tmp/tollgate-dev --default-lists`
3. Pass: five `bytes` lines (one per list), a `compiled ... network rules ... DNS names` line
   with more than 100,000 network rules and more than 200,000 DNS names, a `generated a new
   root CA` line, and the "Tollgate devproxy is running." block naming `127.0.0.1:8080`,
   `127.0.0.1:5353` and `/tmp/tollgate-dev/ca.pem`.
4. `ls -l /tmp/tollgate-dev`. Pass: `ca.key` and `ca.pem` are `-rw-------`; `engine.dat` is
   about 5 MB and `domains.bin` about 1.7 MB.

If step 2 fails with `DNS listener 127.0.0.1:5353: Address already in use`, another program
holds 5353 without `SO_REUSEADDR`; add `--dns 127.0.0.1:5354` and use port 5354 below.

Result: pass (2026-09-25, m1d at 70f138a, release build; data directory under the repo's gitignored build/ instead of /tmp; ports 5354 and 18080). 114,319 network rules (engine.dat 5,040,405 bytes), 216,760 DNS names (domains.bin 1,734,112 bytes), new root CA; ca.key and ca.pem are -rw-------.

## 2. DNS

1. `dig @127.0.0.1 -p 5353 doubleclick.net A +short`. Pass: `0.0.0.0`.
2. `dig @127.0.0.1 -p 5353 doubleclick.net AAAA +short`. Pass: `::`.
3. `dig @127.0.0.1 -p 5353 example.com A +short`. Pass: one or more public IPv4 addresses.
4. Run step 3 again. Pass: the same addresses, answered at once (cache).
5. `dig @127.0.0.1 -p 5353 example.com HTTPS`. Pass: `status: NOERROR` and `ANSWER: 0`.

Result: pass. doubleclick.net A 0.0.0.0, AAAA ::, stats.g.doubleclick.net 0.0.0.0; example.com resolved through DoH, the repeat answered from cache in 9 ms; example.com HTTPS NOERROR with ANSWER 0.

## 3. Proxy with curl

1. `curl -sS -x http://127.0.0.1:8080 -o /dev/null -w '%{http_code}\n' http://example.com/`.
   Pass: `200`.
2. `curl -sS -v -x http://127.0.0.1:8080 --cacert /tmp/tollgate-dev/ca.pem -o /dev/null -w '%{http_code} HTTP/%{http_version}\n' https://example.com/ 2>&1 | grep -E 'issuer|HTTP/'`.
   Pass: the output contains `issuer: CN=Tollgate Root CA; O=Tollgate` and ends with
   `200 HTTP/2`.
3. `curl -sS -x http://127.0.0.1:8080 --cacert /tmp/tollgate-dev/ca.pem -o /dev/null -w '%{http_code}\n' https://securepubads.g.doubleclick.net/tag/js/gpt.js`.
   Pass: `403`.
4. `curl -sS -v -x http://127.0.0.1:8080 -o /dev/null https://www.apple.com/ 2>&1 | grep issuer`.
   Pass: an Apple issuer, not Tollgate (bundled passthrough; no `--cacert` needed).
5. `ps -o rss= -C devproxy`. Pass: below 40,000 (KiB). The release build measured about
   16,000 on the workstation after three intercepted HTTPS pages; the phone's budget for the
   engine and the blocklist alone is about 10 MiB.

Result: pass. http://example.com 200; https://example.com intercepted (issuer CN=Tollgate Root CA; O=Tollgate) 200 over HTTP/2; gpt.js and adsbygoogle.js 403; www.apple.com passed through with Apple's own certificate. Memory, measured as RssAnon because RSS includes the 26 MB unstripped binary: 5.6 MB after loading the compiled lists, 7.0 MB after intercepting eight real sites over HTTP/2 (including a 6.4 MB page); peak VmHWM 17 MB. A run that also downloads and compiles the lists peaks higher (compile happens in the app on iOS, not in the tunnel).

## 4. Pin learning

1. Run twice: `echo | openssl s_client -proxy 127.0.0.1:8080 -connect example.net:443 -servername example.net -verify_return_error 2>&1 | grep 'Verify return code'`.
   Pass: both print `Verify return code: 20 (unable to get local issuer certificate)`, and the
   devproxy log shows `learned certificate pin for example.net after UnknownCa` after the
   second run.
2. Run it a third time. Pass: `Verify return code: 0 (ok)`; the certificate is the site's own
   (passthrough).
3. Observation only (E4 decides how iOS clients fail): run
   `curl -sS -x http://127.0.0.1:8080 -o /dev/null https://example.org/` twice and note
   whether the counters printed at exit (step 6) grow `tls_client_rejections` or
   `tls_abandoned_after_handshake`. On the workstation used for this plan, curl 8.22 with
   OpenSSL 3.6 grew `tls_abandoned_after_handshake`, so curl alone never teaches a pin.

Result: pass. Runs 1 and 2: Verify return code 20; the log shows "learned certificate pin for example.net after UnknownCa"; run 3: Verify return code 0 (passthrough).

## 5. Firefox

1. `firefox -P tollgate-dev --no-remote` (create the profile when asked). Apply the three
   settings devproxy printed: manual proxy `127.0.0.1` port `8080` also for HTTPS, import
   `/tmp/tollgate-dev/ca.pem` under Authorities with "Trust this CA to identify websites",
   and in `about:config` `network.trr.mode` = 5 and `network.dns.echconfig.enabled` = false.
2. Open `https://example.com`. Pass: the page loads; the padlock's certificate viewer shows
   the issuer `Tollgate Root CA`.
3. Open a news site with ads, for example `https://www.theguardian.com/international`. Pass:
   the page loads and works; the network panel (F12) shows requests answered `403` for ad and
   tracker hosts; restart devproxy with `RUST_LOG=debug` to see `blocked ...` lines.
4. Open `https://www.icloud.com`. Pass: it loads with an Apple certificate (passthrough).
5. Log in to one site you use and click through a few pages. Pass: nothing breaks; if
   something does, note the URL and the blocked requests from the debug log.

Result:

## 6. Stop

1. Press Ctrl-C in the devproxy terminal. Pass: it prints the `StatsSnapshot` counters and
   exits; `/tmp/tollgate-dev/learned-pins.json` lists `example.net`.
2. Start it again without list options:
   `core/target/release/devproxy --data-dir /tmp/tollgate-dev`. Pass: no download or compile
   lines, no `generated a new root CA` line, and step 4.2 still passes at once (the pin was
   loaded).

Result:
