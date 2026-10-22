# nginx-php2shell-monitor

Live detection of **PHP2Shell** attack attempts (CVE-2026-109618, CVE-2026-109619) based on
the **full POST body**, for servers running nginx in front of PHP (php-fpm).

nginx mirrors every POST that is handed to PHP to a small Python daemon on `127.0.0.1`. The
daemon inspects the body and stores suspicious requests byte-exact as individual files, so you
can see whether - and how - your server is being attacked.

> **This is monitoring, not protection.** The monitor only sees copies and cannot block
> anything. The fix for PHP2Shell is updating PHP (8.2.35, 8.3.36, 8.4.27, 8.5.12 or your
> distribution's patched package) and restarting php-fpm.

- Python 3 standard library only, no packages to install
- nginx built-in `mirror` module, no extra nginx modules
- The site is unaffected if the monitor is down

## Background

PHP2Shell is the name for two PHP core flaws disclosed in October 2026 that can lead to
unauthenticated remote code execution with the privileges of the PHP worker. The publicly
described trigger paths act while PHP starts up the request, before application code runs -
so PHP applications behind an affected PHP version are exposed regardless of the framework.

Public analyses describe two trigger paths:

- **CVE-2026-109618**: a crafted `application/x-www-form-urlencoded` POST that drives PHP into
  `memory_limit` during POST parsing - a field without a name holding binary data / NUL bytes,
  and a field name of about 3.5 MB ending in `[x]=1`.
- **CVE-2026-109619**: stale global state after fatal errors, reachable via the session upload
  progress feature (`session.upload_progress.enabled`, on by default) - multipart POSTs with
  `PHP_SESSION_UPLOAD_PROGRESS`.

The default access log does not contain request bodies, which is why this monitor looks at
the bodies themselves.

## How it works

```
client ── POST ──> nginx ─────────────────> php-fpm (unchanged)
                     │
                     └─ mirror (copy incl. body) ──> monitor.py on 127.0.0.1:9777
                                                       ├─ answers 204 immediately
                                                       ├─ analysis in a worker thread
                                                       └─ suspicious -> captures/*.req + *.json
```

- The `mirror` directives go into the location(s) that call `fastcgi_pass`. The copy is sent to
  the internal location `/__php2shell_monitor` (`nginx/php2shell-mirror.conf`), which forwards only
  POST requests to the monitor.
- The client IP is passed in `X-Php2shell-Client-Ip`. nginx's `proxy_set_header` replaces a
  client-sent header of the same name, so the IP cannot be spoofed.

## Detection rules

Each rule has a level. A request is `php2shell` as soon as at least one `php2shell` rule fires,
otherwise `generic`. **Both are stored**; the level appears in the log, the file name and the
`.json`. `generic` also catches other attacks, bots and legitimate large uploads.

| Rule | Level | Fires on | Relation |
|---|---|---|---|
| `long_field_name` | php2shell | field name longer than `max_field_name_length` (urlencoded and multipart) | CVE-2026-109618: ~3.5 MB field name ending in `[x]` |
| `upload_progress_field` | php2shell | `PHP_SESSION_UPLOAD_PROGRESS` in the body (raw or URL-decoded) | CVE-2026-109619 / session upload progress variants |
| `empty_field_name` | generic | urlencoded field without a name | part of CVE-2026-109618, but also bots/spam |
| `nul_byte` | generic | NUL byte in a field name/value or part header | part of CVE-2026-109618, but also generic scanners |
| `too_many_fields` | generic | more than `max_fields` fields | unusual field count |
| `large_body` | generic | body of `large_body_bytes` or more, except below `large_body_ignore_paths` | large payloads |
| `multipart_without_boundary` | generic | multipart without boundary | malformed / crafted requests |

Thresholds live in `config.ini` (`[rules]`), the level mapping in `PHP2SHELL_RULES` in
`monitor.py`.

The rules match the **shape** of the attacks known from the first public analyses, not working
exploits. Modified variants may avoid them. Contributions with new indicators are welcome.

## Output

- Console and log file: one `HIT` line per suspicious request plus details, a `STATUS` line
  every `stats_interval` seconds. If the number of checked POSTs in the `STATUS` line does not
  grow, nginx is not delivering copies.
- `captures/` (mode 0700, files 0600):
  - `2026-10-22_15-04-05_php2shell_203.0.113.7_123f550a1b.req` (date_level_ip_hash):
    request line, headers as forwarded by nginx, empty line, body byte-exact and untruncated.
  - matching `.json`: time, level, IP, host, URL, size, SHA-256, findings with details.
  - An identical body from the same IP is stored only once, repetitions are only logged.
  - Once `max_total_mb` is reached, only `.json` files are written. Nothing is ever deleted.
- Mail: optional via `[mail] to`, at most one mail per IP within `min_interval`.

## Installation

Requirements: nginx with php-fpm, Python 3.8+ (tested with 3.9 and 3.12). Tested in production
on Ubuntu 24.04 with nginx 1.24 and PHP 8.3 (php-fpm).

### 1. Monitor

```bash
sudo mkdir -p /opt/nginx-php2shell-monitor
sudo cp monitor.py config.ini test_requests.py /opt/nginx-php2shell-monitor/
```

Adjust `config.ini` (capture directory, log file, `large_body_ignore_paths` for upload routes
of your application, optional mail). The monitor needs no root privileges (port > 1024,
127.0.0.1 only) - run it as a user that can write the capture and log directories.

Start in the foreground first so errors are visible (stop with Ctrl+C):

```bash
cd /opt/nginx-php2shell-monitor
python3 monitor.py -c config.ini
```

Then in the background, either with screen (the shell keeps the window open if the monitor
exits, so the error stays readable; detach with Ctrl+A, D):

```bash
screen -dmS php2shell bash -c 'python3 monitor.py -c config.ini; echo "monitor exited with code $?"; exec bash'
```

or as a systemd service, e.g. `/etc/systemd/system/nginx-php2shell-monitor.service`:

```ini
[Unit]
Description=nginx-php2shell-monitor
After=network.target

[Service]
User=php2shell
WorkingDirectory=/opt/nginx-php2shell-monitor
ExecStart=/usr/bin/python3 /opt/nginx-php2shell-monitor/monitor.py -c /opt/nginx-php2shell-monitor/config.ini
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Function test without nginx (in a second shell, hits appear in the monitor output):

```bash
python3 test_requests.py
```

### 2. nginx

```bash
sudo cp nginx/php2shell-mirror.conf /etc/nginx/snippets/
```

In every server block to monitor (see `nginx/example-site.conf`):

1. `include /etc/nginx/snippets/php2shell-mirror.conf;` inside the `server` block.
2. `mirror /__php2shell_monitor;` and `mirror_request_body on;` in each location that calls
   `fastcgi_pass` - **only there**. If a location with `try_files` redirects internally to
   `/index.php`, a mirror in both locations mirrors every request twice. Named locations
   (`@php`) work as well.

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Test through nginx (the IP in the hit must be your real one):

```bash
python3 test_requests.py --url https://example.com
```

The test requests are sent to your real application and will get whatever responses it gives
(e.g. 404/405). They contain no exploit.

### Notes

- With `mirror_request_body on`, nginx reads the complete body before passing the request on.
  For typical POST sizes this is not noticeable.
- Bodies larger than `client_max_body_size` are rejected with 413 before mirroring and only
  show up in the access log.
- Requests rejected in the access phase (`allow`/`deny`, auth) are not mirrored.
- Only POST is inspected - PHP only parses POST bodies automatically.

## Privacy

Captured requests contain everything the client sent: cookies, session IDs and possibly
personal data or credentials. This is especially true for `generic` hits, which can be caused
by regular visitors. Keep the capture directory restricted, delete captures you no longer need
and check whether running this is compatible with your privacy obligations (e.g. GDPR).

## Uninstall

Remove the `include` and `mirror` lines, `sudo rm /etc/nginx/snippets/php2shell-mirror.conf`,
`sudo nginx -t && sudo systemctl reload nginx`, stop the monitor.

## References

- [Datadog Security Labs: PHP2Shell - detection, analysis, and remediation](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Amazon Threat Intelligence: PHP2Shell exploitation prior to public disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [Imperva: PHP2Shell - when PHP runs out of memory at the wrong moment](https://www.imperva.com/blog/php2shell-vulnerability-updates/)
- [Tenable: PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [watchTowr: PHP2Shell](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/)

## Credits

Developed by **Claude** (Anthropic, Claude Opus 5.5) together with **Andreas Boldt**.

## License

MIT, see [LICENSE](LICENSE).
