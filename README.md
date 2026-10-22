# nginx-php2shell-monitor

See whether anyone is trying to exploit **PHP2Shell** (CVE-2026-109618, CVE-2026-109619) on
your server - by looking at the **full POST body** of every request that reaches PHP.

nginx sends a copy of each POST to a small Python daemon listening on `127.0.0.1`. The daemon
checks the body for the patterns seen in PHP2Shell attacks and saves any suspicious request
exactly as it arrived, so you can see what was sent, when, and from where.

> **This tool detects, it does not protect.** It only ever sees copies of requests, so it
> can't block anything. To fix PHP2Shell, update PHP (8.2.35, 8.3.36, 8.4.27, 8.5.12, or your
> distribution's patched package) and restart php-fpm.

- Pure Python 3 standard library - nothing to install
- Uses nginx's built-in `mirror` module - no extra nginx modules
- If the daemon is down, your site keeps working as before

## Background

PHP2Shell is a pair of flaws in PHP itself, disclosed in October 2026. They can let an
unauthenticated attacker run code with the privileges of the PHP worker. The trigger paths
described so far fire while PHP is still setting up the request, before your application gets
to run - so it doesn't matter which framework or CMS you use.

Public write-ups describe two ways in:

- **CVE-2026-109618**: a crafted `application/x-www-form-urlencoded` POST that pushes PHP past
  `memory_limit` while it parses the form data. The known payload contains a field with no
  name and a binary value (including NUL bytes), followed by a field name of roughly 3.5 MB
  that ends in `[x]=1`.
- **CVE-2026-109619**: stale global state left behind after a fatal error, reachable through
  PHP's session upload progress feature (`session.upload_progress.enabled`, on by default).
  The tell-tale sign is a multipart POST containing `PHP_SESSION_UPLOAD_PROGRESS`.

Your access log won't help here: it doesn't record request bodies. That's the gap this tool
fills.

## How it works

```
client ── POST ──> nginx ─────────────────────────> php-fpm (untouched)
                     │
                     └─ mirror: copy with full body ──> monitor.py on 127.0.0.1:9777
                                                          ├─ replies 204 right away
                                                          ├─ inspects the body in a worker thread
                                                          └─ if suspicious: captures/*.req + *.json
```

- You add the `mirror` directives to the location(s) that call `fastcgi_pass`. nginx sends
  the copy to an internal location, `/__php2shell_monitor` (`nginx/php2shell-mirror.conf`),
  which passes POST requests on to the daemon and drops everything else.
- The client's IP travels in the `X-Php2shell-Client-Ip` header. Because nginx's
  `proxy_set_header` overrides any header of the same name sent by the client, the IP can't be
  spoofed.

## Detection rules

Every rule belongs to one of two levels. If any `php2shell` rule matches, the request is
classed as `php2shell`; otherwise it's `generic`. **Both levels are saved** - the level shows
up in the log, in the file name and in the `.json`. Expect `generic` hits from other kinds of
attacks, from bots, and from legitimate large uploads.

| Rule | Level | Matches when | Why it matters |
|---|---|---|---|
| `long_field_name` | php2shell | a field name is longer than `max_field_name_length` (urlencoded or multipart) | CVE-2026-109618: ~3.5 MB field name ending in `[x]` |
| `upload_progress_field` | php2shell | the body contains `PHP_SESSION_UPLOAD_PROGRESS` (raw or URL-encoded) | CVE-2026-109619 and other upload-progress variants |
| `empty_field_name` | generic | a urlencoded field has no name | part of CVE-2026-109618, but bots and spammers do this too |
| `nul_byte` | generic | a field name, value or part header contains a NUL byte | part of CVE-2026-109618, but also common in generic scanners |
| `too_many_fields` | generic | there are more than `max_fields` fields | unusually large forms |
| `large_body` | generic | the body is at least `large_body_bytes`, outside `large_body_ignore_paths` | oversized payloads |
| `multipart_without_boundary` | generic | a multipart request has no boundary | malformed or hand-crafted requests |

Thresholds are set in the `[rules]` section of `config.ini`. Which rules count as `php2shell`
is defined by `PHP2SHELL_RULES` in `monitor.py`.

These rules look for the **shape** of the attacks described in the first public analyses -
they don't check whether a payload would actually work. A modified attack may slip past them.
If you spot new indicators, pull requests are welcome.

## Output

- **Console and log file**: a `HIT` line for every suspicious request, followed by the details,
  and a `STATUS` summary every `stats_interval` seconds. If the POST count in `STATUS` stays at
  zero, nginx isn't sending any copies.
- **`captures/`** (directory mode 0700, files 0600):
  - `2026-10-22_15-04-05_php2shell_203.0.113.7_123f550a1b.req` (date_level_ip_hash): the
    request line, the headers as nginx forwarded them, a blank line, then the body exactly as
    received - nothing is cut off.
  - A `.json` file with the same name: time, level, IP, host, URL, size, SHA-256 and the
    matching rules with details.
  - If the same IP sends the same body again, it's logged but not saved a second time.
  - Once the directory reaches `max_total_mb`, only `.json` files are written. Nothing is ever
    deleted automatically.
- **Email** (optional): set `[mail] to`. You'll get at most one email per IP every
  `min_interval` seconds.

## Installation

You'll need nginx with php-fpm and Python 3.8 or newer (tested with 3.9 and 3.12). Running in
production on Ubuntu 24.04 with nginx 1.24 and PHP 8.3 (php-fpm).

### 1. The daemon

```bash
sudo git clone https://github.com/rootone-it/nginx-php2shell-monitor.git /opt/nginx-php2shell-monitor
cd /opt/nginx-php2shell-monitor
sudo cp config.example.ini config.ini
```

Edit `config.ini`: where to store captures and logs, which upload routes of your application
to exempt via `large_body_ignore_paths`, and optionally an email address.
`config.ini` isn't tracked by git, so `git pull` won't overwrite your settings - after an
update, check `config.example.ini` for new options.

The daemon doesn't need root: it only listens on `127.0.0.1` on a port above 1024. Run it as
any user that can write to the capture and log directories.

Start it in the foreground first, so you see any errors straight away (Ctrl+C to stop):

```bash
cd /opt/nginx-php2shell-monitor
python3 monitor.py -c config.ini
```

Once that works, run it in the background. With screen (wrapping it in a shell keeps the
window open if the daemon exits, so you can still read the error; detach with Ctrl+A, then D):

```bash
screen -dmS php2shell bash -c 'python3 monitor.py -c config.ini; echo "monitor exited with code $?"; exec bash'
```

Or as a systemd service, e.g. `/etc/systemd/system/nginx-php2shell-monitor.service`:

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

Quick check without nginx - run this in a second shell and watch the hits come in:

```bash
python3 test_requests.py
```

### 2. nginx

```bash
sudo cp /opt/nginx-php2shell-monitor/nginx/php2shell-mirror.conf /etc/nginx/snippets/
```

Then, in every server block you want to watch (see `nginx/example-site.conf`):

1. Add `include /etc/nginx/snippets/php2shell-mirror.conf;` inside the `server` block.
2. Add `mirror /__php2shell_monitor;` and `mirror_request_body on;` to each location that
   calls `fastcgi_pass` - **and nowhere else**. A typical `location /` with `try_files` hands
   the request over to `/index.php` internally; with a mirror in both places, every request
   would be copied twice. Named locations (`@php`) work fine.

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Now test through nginx. The IP in the hits should be your real one, not the fake IP the script
sends:

```bash
python3 test_requests.py --url https://example.com
```

These requests hit your real application, so expect whatever it normally answers (404, 405,
...). They mimic the shape of the attacks but contain no exploit.

### Good to know

- With `mirror_request_body on`, nginx reads the whole body before passing the request to PHP.
  At normal POST sizes you won't notice.
- Requests larger than `client_max_body_size` are rejected with a 413 before they're mirrored.
  You'll only find them in the access log.
- Requests blocked earlier on (`allow`/`deny`, auth) are never mirrored.
- Only POST requests are checked - PHP only parses POST bodies on its own.

## Privacy

A capture contains everything the client sent: cookies, session IDs, and possibly personal
data or passwords. That applies especially to `generic` hits, which regular visitors can
trigger too. Keep the capture directory locked down, delete captures you no longer need, and
make sure running this fits your privacy obligations (GDPR, for example).

## Uninstall

Remove the `include` and `mirror` lines, run `sudo rm /etc/nginx/snippets/php2shell-mirror.conf`
and `sudo nginx -t && sudo systemctl reload nginx`, then stop the daemon.

## References

- [Datadog Security Labs: PHP2Shell - detection, analysis, and remediation](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Amazon Threat Intelligence: PHP2Shell exploitation prior to public disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [Imperva: PHP2Shell - when PHP runs out of memory at the wrong moment](https://www.imperva.com/blog/php2shell-vulnerability-updates/)
- [Tenable: PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [watchTowr: PHP2Shell](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/)

## Credits

Written by **Claude** (Anthropic, Claude Opus 5.5) together with **Andreas Boldt**.

## License

MIT - see [LICENSE](LICENSE).
