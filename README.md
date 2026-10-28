# nginx-php2shell-monitor

Detection of **PHP2Shell** exploitation attempts (CVE-2026-109618, CVE-2026-109619) on servers
running nginx and PHP-FPM. PHP2Shell refers to two critical remote code execution (RCE)
vulnerabilities in PHP. nginx-php2shell-monitor inspects the HTTP POST request body of every
request passed to PHP, detects the known exploit patterns and stores suspicious requests for
analysis. It works with any PHP application, for example WordPress, Laravel, Symfony, Shopware or
Magento.

nginx sends a copy of each POST request to a Python daemon listening on `127.0.0.1`. The daemon
checks the request body for the patterns of the known exploits and stores each suspicious request
unchanged in a separate file. An event log with one JSON object per line can easily be processed
by other scripts.

The monitor is particularly useful **behind a web application firewall (WAF)**, for example the
CrowdSec WAF or a CDN. Requests that the WAF blocks are not mirrored. The monitor therefore shows
exactly the PHP2Shell requests that **get past your WAF** and reach PHP. See
[Using the monitor with a WAF](#using-the-monitor-with-a-waf).

**What's new (2026-10-28):** the monitor now supports hooks, for example to block the IP address
of an attacker in the firewall (examples in Python and PHP for nftables and CrowdSec included). It writes an
event log in JSON Lines format, rates complete exploit chains with the new request level
`php2shell-chain`, parses the multipart variants that PHP accepts, and has many new detection rules based
on the published exploit tools. Existing installations must update the nginx snippet. See the
[Changelog](#changelog) for details.

> [!IMPORTANT]
> **This tool detects attacks, it does not fix the vulnerability.** It cannot block the inspected
> request, because it only receives copies. An optional hook can block the IP address for further
> requests. To fix PHP2Shell, update PHP to 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or install the
> patched package of your distribution) and restart php-fpm.

Features:

- Uses only the Python 3 standard library
- Uses the nginx `mirror` module, which is included in nginx
- The website is not affected if the daemon is stopped
- Shows the PHP2Shell requests that get past a WAF
- Optional hook command for each detection, for example to block the IP address in the firewall
  or with CrowdSec

## Background

PHP2Shell refers to two vulnerabilities in PHP, published in October 2026. They allow
unauthenticated remote code execution with the privileges of the PHP process. The known attack
methods take effect while PHP processes the request, before the application code is executed.
All PHP applications on an affected PHP version are therefore vulnerable, regardless of the
framework.

The published analyses describe two attack methods:

- **CVE-2026-109618**: a crafted request that exceeds `memory_limit` while PHP parses the form
  data. The known exploit is an `application/x-www-form-urlencoded` request with a field without
  a name with binary content (including NUL bytes) and a field name of about 3.5 MB ending in
  `[x]=1`. Published tools also exhaust the memory with multipart requests, for example with many
  header lines in one part.
- **CVE-2026-109619**: use of stale data after a fatal error, triggered through the session upload
  progress feature (`session.upload_progress.enabled`, enabled by default). The request is a
  multipart POST request containing the field `PHP_SESSION_UPLOAD_PROGRESS`.

Web server access logs do not contain request bodies and cannot be used to detect these attacks.

## How it works

```
client ── POST ──> nginx ───────────────────────> php-fpm (unchanged)
                     │
                     └─ mirror (copy with body) ──> monitor.py on 127.0.0.1:9777
                                                      ├─ responds with 204 immediately
                                                      ├─ inspects the body in a worker thread
                                                      └─ suspicious: captures/*.req + *.json,
                                                         event log, email, hook (optional)
```

- The `mirror` directives are added to the location blocks that contain `fastcgi_pass`. nginx
  sends the copy to the internal location `/__php2shell_monitor` (`nginx/php2shell-mirror.conf`),
  which forwards POST requests to the daemon and ignores all other methods.
- nginx passes the client IP in the header `X-Php2shell-Client-Ip`. Because `proxy_set_header`
  replaces a header with the same name sent by the client, the IP cannot be spoofed.

## Using the monitor with a WAF

nginx processes a request in phases. A WAF that is integrated into nginx, such as the CrowdSec
nginx bouncer with AppSec, checks the request in the access phase and blocks it there. The
`mirror` directive takes effect later, in the precontent phase, just before the request is passed
to PHP. A WAF in front of nginx, such as a CDN, blocks the request before it reaches nginx at all.
In both cases:

- Requests blocked by the WAF are **not** mirrored. They appear in the logs of the WAF, not in the
  monitor.
- Requests allowed by the WAF are mirrored with their body. The monitor reports those that have
  the structure of a PHP2Shell exploit. These are the requests that the WAF rules do not cover.

WAF rules for PHP2Shell are usually written for specific variants. For example, the CrowdSec
virtual patches for PHP2Shell block multipart requests with deeply nested field names, many file
parts or the upload progress field. Other variants, such as the urlencoded request with a very
long field name, are not described for these rules. The monitor shows whether such variants reach
your server. Use both sources together: the WAF for blocked attempts, the monitor for attempts that
got through.

The mirrored copy is an nginx subrequest. nginx skips the access phase for subrequests, so the WAF
does not inspect the copy a second time.

After you enable a WAF, check that the monitor still receives the complete body. Send a regular,
large POST request (for example an upload in the admin area of your application) and compare the
size in the `.json` file of the monitor, or use a path that is not listed in
`large_body_ignore_paths` and check the `large_body` hit. If you test with `test_requests.py`
through nginx, add your IP address to the allowlist of the WAF first: the test requests are blocked
by the WAF, and the WAF may block your IP address after several blocked requests.

## Detection rules

There are two kinds of levels:

- **Rule level:** each rule is either `php2shell` (specific to PHP2Shell) or `generic` (also
  caused by other attacks, by bots or by legitimate requests). The rule level is shown in the
  table below.
- **Request level:** from the matched rules, each suspicious request receives one of three
  levels:
  - `php2shell-chain`: the request carries the structure of a complete exploit chain - a trigger
    rule (`upload_progress_field`) together with an injection or preparation rule
    (`serialized_object_in_filename`, `php_code_in_filename`, `session_id_in_body`,
    `probe_filename`, `suspicious_filename` or `array_spray`), or at least two rules with the
    rule level `php2shell`. `exploit_tool_user_agent` and `exploit_tool_marker` count as one rule
    here, because several fingerprints in one request usually come from the same tool. This is a
    fully formed exploitation attempt rather than a scan. It does not mean the attempt would have
    succeeded; that depends on the target's PHP version and configuration, which are not visible
    in the request.
  - `php2shell`: at least one rule with the rule level `php2shell` matched.
  - `generic`: only rules with the rule level `generic` matched.

Requests of all request levels are stored. The request level is included in the log, in the file
name, in the `.json` file and in the event log. The trigger and injection rules of the chain level are defined by
`PHP2SHELL_TRIGGER_RULES` and `PHP2SHELL_PAYLOAD_RULES` in `monitor.py`.

The column "Counts for php2shell-chain" shows how a rule contributes to the request level
`php2shell-chain`: a request with a *trigger* and a *payload* rule, or with at least two *signal*
rules, receives this level. The two rules marked *signal (shared)* count as one signal together.

| Rule | Rule level | Counts for php2shell-chain | Condition | Relation to PHP2Shell |
|---|---|---|---|---|
| `long_field_name` | php2shell | signal | A field name is longer than `max_field_name_length` (urlencoded or multipart) | CVE-2026-109618: field name of about 3.5 MB ending in `[x]` |
| `upload_progress_field` | php2shell | trigger, signal | A multipart field is named exactly `upload_progress_marker` (case-sensitive, as compared by PHP) | CVE-2026-109619 and other upload progress variants. Applications with an upload progress bar send this field legitimately. |
| `multipart_header_flood` | php2shell | signal | A multipart part has more than `max_part_headers` header lines or a duplicate header name | CVE-2026-109618: memory amplification closed by the PHP fix |
| `serialized_object_in_filename` | php2shell | payload, signal | An upload file name or the field name of a file part contains a serialized PHP object or array | Session injection through the upload progress handler, which stores both names |
| `exploit_tool_user_agent` | php2shell | signal (shared) | The User-Agent matches `tool_user_agent_regex` | User-Agent of published exploit tools. This is a weak indicator: most tool requests do not send it, and it is easy to change. Boundary markers are more stable. |
| `exploit_tool_marker` | php2shell | signal (shared) | The body or the Content-Type contains a string from `tool_markers`, or the Content-Type contains a string from `tool_content_type_markers` | Fixed strings and multipart boundaries of published exploit tools |
| `probe_filename` | php2shell | payload, signal | An upload file name matches `tool_filename_regex` | File names of published screening tools for session injection |
| `empty_boundary_probe` | php2shell | signal | `empty_boundary` together with `large_body` or `deep_nested_field_name` | Memory exhaustion probe of a published screening tool, also with a replaced User-Agent |
| `empty_field_name` | generic | - | A urlencoded field has no name | Part of CVE-2026-109618, also used by bots |
| `nul_byte` | generic | - | A urlencoded field name or value, or a multipart part header contains a NUL byte | Part of CVE-2026-109618, also used by vulnerability scanners |
| `serialized_object_in_field` | generic | - | A urlencoded field value or a multipart field name starts with a serialized PHP object or array | Observed in exploitation attempts, also used by some applications |
| `deep_nested_field_name` | generic | - | A field name has more than `max_field_nesting` array levels | Observed in requests with up to 200 levels |
| `session_id_in_body` | generic | payload | A multipart field is named exactly like the session cookie (`session_name`) | Session fixation used in published attack chains. PHP takes the session ID from this field if the request has no session cookie. |
| `php_code_in_filename` | generic | payload | An upload file name or the field name of a file part contains `<?` | Session injection, also used in other upload attacks |
| `suspicious_filename` | generic | payload | An upload file name matches `suspicious_filename_regex` | Short file names from exploit chains (for example `p2s.txt`) that regular visitors could also use. |
| `upload_progress_text` | generic | - | The body contains `upload_progress_marker` (any case, plain or URL-encoded), but no multipart field has exactly this name | No effect in PHP. Scans with a wrong spelling, or free text such as a support request about the vulnerability. |
| `long_filename` | generic | - | An upload file name is longer than `max_filename_length` | Session inflation through the upload progress handler |
| `array_spray` | generic | payload | At least `max_same_array_fields` fields have the same array name (for example `t[]`) | Sent by a published exploit tool. The purpose of these fields is unverified. |
| `chunked_multipart` | generic | - | A multipart request was sent with `Transfer-Encoding: chunked` | Bypass of the `post_max_size` check |
| `too_many_fields` | generic | - | The request has more than `max_fields` fields | Unusually large forms. The confirmed exploit chain sends 973 to 998 parts, just below the PHP default `max_input_vars = 1000`; the default threshold is therefore 500. |
| `large_body` | generic | - | The body has at least `large_body_bytes` bytes and the path is not listed in `large_body_ignore_paths` | Unusually large requests |
| `multipart_without_boundary` | generic | - | A multipart request has no boundary | Malformed or crafted requests |
| `empty_boundary` | generic | - | The Content-Type of a multipart request contains `boundary=` with an empty value | Sent by a published screening tool. Browsers and common HTTP libraries never send it. |
| `repeated_char_boundary` | generic | - | The multipart boundary consists of one character other than `-`, repeated at least eight times | Observed in the confirmed exploit chain. Easy to change. |
| `bare_lf_multipart` | generic | - | A multipart delimiter line or header block contains a line break without CR | Sent by a published screening tool. Browsers always send CRLF. |
| `malformed_content_disposition` | generic | - | A `Content-Disposition` does not start with `form-data`, or a part header has continuation lines | PHP accepts both, browsers send neither. Hides field and file names from simple parsers. |
| `upload_progress_without_user_agent` | generic | - | `upload_progress_field` matched and the request has no User-Agent | The confirmed exploit chain and several scanners send no User-Agent |
| `scanner_user_agent` | generic | - | The User-Agent matches `scanner_user_agent_regex` | Self-named version checkers. These are scans, not exploits. |
| `other_campaign_marker` | generic | - | The Content-Type contains a string from `other_content_type_markers` | Other campaigns with a similar request shape (for example `wp2shell`), logged to separate them from PHP2Shell |
| `react2shell_lookalike` | generic | - | The request has a `Next-Action` header | React2Shell requests (Next.js Server Actions), which also use chunked multipart bodies |

The thresholds are configured in the `[rules]` section of `config.ini`. The rules with the rule
level `php2shell` are defined in `PHP2SHELL_RULES` in `monitor.py`. Options added after the first
release have default values, so existing `config.ini` files continue to work.

`chunked_multipart` requires the header `X-Php2shell-Transfer-Encoding`, which is set in
`nginx/php2shell-mirror.conf`. Update the snippet on existing installations.

Multipart bodies are parsed with the variants that PHP accepts: lines may end with CRLF or LF
only, the boundary may be empty, `name=` and `filename=` are also found directly after the colon
of `Content-Disposition`, and continuation lines are joined before the search. The handling of an
empty boundary is derived from the behavior of a published screening tool and has not been
compared with the PHP parser in detail.

`session_name` and `upload_progress_marker` must match the values of `session.name` and
`session.upload_progress.name` in `php.ini` or the php-fpm pool. A session name that the
application sets at run time (for example with `session_name()`) is not set yet when PHP parses
the request body.

`react2shell_lookalike` uses the original request headers, which nginx passes to the mirror
location by default.

`max_body_bytes` in the `[server]` section must be at least as large as `client_max_body_size` of
the monitored sites. Otherwise, content after this limit is not inspected.

The rules check the structure of the exploits described in the published analyses and detection
rules (see References). They do not verify whether a request would exploit the vulnerability.
Modified exploits may not be detected. Pull requests with additional indicators are welcome.

## Output

- **Console and log file:** one `HIT` line with details for each suspicious request, a `STATUS`
  line every `stats_interval` seconds, and `HOOK`, `WARNING` and `ERROR` lines. If the number of
  checked POST requests in the `STATUS` line does not increase, nginx does not send any copies.
- **`captures/`** (directory permissions 0700, file permissions 0600):
  - `2026-10-22_15-04-05_php2shell_203.0.113.7_123f550a1b.req` (date, level, IP, hash): request
    line, headers as forwarded by nginx, an empty line and the complete, unmodified body.
  - A `.json` file with the same name: time, request level, IP, host, URL, Content-Type, size,
    SHA-256, nginx request ID and the matched rules.
  - If the same IP sends the same body again, the request is logged but not stored again.
  - When the directory reaches `max_total_mb`, only `.json` files are written. Files are never
    deleted automatically.
- **Event log** (`events_file`): one JSON object per line for each suspicious request, including
  repeated requests. The file can easily be processed by other scripts.
- **Email** (optional): configured with `[mail] to`. Emails are only sent for requests with at
  least the request level `min_level` (default `php2shell`). At most one email per IP is sent
  within `min_interval`. Repeated requests do not send an email.
- **Hook** (optional): a command that is run for each suspicious request, for example to block
  the IP address in the firewall. See [Hook](#hook).

## Hook

The `[hook]` section of `config.ini` configures a command that the monitor runs for each
suspicious request with at least the level `min_level`. The command receives the event on stdin
as one JSON object, the same as in the event log:

```json
{"time": "2026-10-22T13:04:05Z", "ip": "203.0.113.7", "level": "php2shell-chain",
 "rules": "upload_progress_field,probe_filename", "method": "POST", "host": "example.com",
 "path": "/index.php", "user_agent": "", "body_bytes": 1234,
 "capture": "2026-10-22_15-04-05_php2shell-chain_203.0.113.7_123f550a1b", "repeat": false}
```

- The command is started without a shell. Request data is never inserted into the command line.
  `host`, `path` and `user_agent` are sent by the client and must be treated as untrusted input.
  `ip` is set by nginx (`$remote_addr`), and the monitor checks that it is a valid IP address
  before it runs the command. `method` is always `POST`.
- The commands run one after another in a separate thread with a maximum run time of `timeout`
  seconds. A slow command does not delay the inspection of further requests. If `queue_size`
  events are waiting, further events are dropped and a warning is logged.
- At most one command per IP is run within `min_interval` seconds. Repeated requests are not
  skipped, so that an IP address whose block has expired is blocked again.
- Output of the command is written to the log (`HOOK` line). A non-zero exit code or a timeout
  is logged as `ERROR`.

### Example: block the IP address with nftables

`hooks/` contains two example hooks, each in Python and PHP:

- `php2shell-ban.py` / `php2shell-ban.php`: add the IP address to an nftables set for 24 hours
  (`BAN_TIMEOUT`).
- `php2shell-ban-crowdsec.py` / `php2shell-ban-crowdsec.php`: add a CrowdSec ban decision for
  24 hours (`BAN_DURATION`). See [Example: block the IP address with
  CrowdSec](#example-block-the-ip-address-with-crowdsec).

Addresses on the `ALLOWLIST` in the scripts are never blocked; add the addresses of your own
servers, monitoring and office there.

1. Load the nftables table, which drops packets from the blocked addresses:

   ```bash
   sudo nft -f /opt/nginx-php2shell-monitor/hooks/php2shell-nftables.conf
   ```

   To load it at boot, add `include "/opt/nginx-php2shell-monitor/hooks/php2shell-nftables.conf"`
   to `/etc/nftables.conf`. Loading the file again removes all blocked addresses.

2. Install one of the scripts as root, so that the monitor user can run it but cannot change it:

   ```bash
   sudo install -o root -g root -m 0755 /opt/nginx-php2shell-monitor/hooks/php2shell-ban.py /usr/local/sbin/php2shell-ban
   ```

   For the PHP version, install `php2shell-ban.php` instead (requires the PHP CLI 7.4 or later).

3. Allow the monitor user (`php2shell` in the systemd example) to run exactly this script as
   root, without arguments, with `sudo visudo -f /etc/sudoers.d/php2shell-ban`:

   ```
   php2shell ALL=(root) NOPASSWD: /usr/local/sbin/php2shell-ban ""
   ```

   The empty string `""` forbids arguments. Do not allow the monitor user to run `nft` directly:
   nft accepts several commands in one call, so a sudo rule for nft would allow any change to the
   firewall.

4. Configure the hook in `config.ini` and restart the monitor:

   ```ini
   [hook]
   command = sudo -n /usr/local/sbin/php2shell-ban
   min_level = php2shell
   ```

   `sudo -n` fails instead of asking for a password. The systemd service must not set
   `NoNewPrivileges=true`, because sudo would not work then.

5. Test the script without the monitor:

   ```bash
   echo '{"ip": "192.0.2.1", "level": "php2shell", "rules": "test"}' | sudo -u php2shell sudo -n /usr/local/sbin/php2shell-ban
   sudo nft list set inet php2shell blocked4
   sudo nft delete element inet php2shell blocked4 '{ 192.0.2.1 }'
   ```

### Example: block the IP address with CrowdSec

If CrowdSec is installed, the hook can add a decision instead of an nftables entry. All CrowdSec
remediation components then block the IP address, for example the firewall bouncer, the nginx
bouncer and the CrowdSec WAF. No separate nftables table is needed.

1. Install one of the scripts as root, so that the monitor user can run it but cannot change it:

   ```bash
   sudo install -o root -g root -m 0755 /opt/nginx-php2shell-monitor/hooks/php2shell-ban-crowdsec.py /usr/local/sbin/php2shell-ban
   ```

   For the PHP version, install `php2shell-ban-crowdsec.php` instead (requires the PHP CLI 7.4 or
   later). The scripts call `/usr/bin/cscli`; change `CSCLI` if it is installed elsewhere.

2. Allow the monitor user to run exactly this script as root, and configure the hook. Both steps
   are the same as steps 3 and 4 of the nftables example.

3. Test the script without the monitor:

   ```bash
   echo '{"ip": "192.0.2.1", "level": "php2shell", "rules": "test"}' | sudo -u php2shell sudo -n /usr/local/sbin/php2shell-ban
   sudo cscli decisions list --ip 192.0.2.1
   sudo cscli decisions delete --ip 192.0.2.1
   ```

The decisions have the reason `nginx-php2shell-monitor: <request level>` and appear in
`cscli decisions list` and in the CrowdSec Console.

Choose `min_level` according to your risk assessment. `php2shell-chain` blocks only complete
exploit attempts. `php2shell` also blocks scanners that send a single PHP2Shell-specific request.
`generic` is not recommended, because these rules also match requests of regular visitors.

> [!WARNING]
> `test_requests.py` sends requests with the request level `php2shell`. If the hook is enabled,
> running it through nginx blocks your own IP address. Add your address to the `ALLOWLIST` first,
> or test before you enable the hook.

## Installation

Requirements: nginx with php-fpm and Python 3.8 or later (tested with 3.9 and 3.12). The monitor
is used in production on Ubuntu 24.04 with nginx 1.24 and PHP 8.3 (php-fpm).

### 1. Daemon

```bash
sudo git clone https://github.com/rootone-it/nginx-php2shell-monitor.git /opt/nginx-php2shell-monitor
cd /opt/nginx-php2shell-monitor
sudo cp config.example.ini config.ini
```

Edit `config.ini`. Set the directories for captures and logs, add upload paths of your application
to `large_body_ignore_paths` and, if required, an email address or a hook (see [Hook](#hook)). `config.ini` is not tracked by
git, so `git pull` does not overwrite it. After an update, check `config.example.ini` for new
options.

The daemon does not require root privileges. It listens on `127.0.0.1` on a port above 1024. Run
it as a user with write access to the capture and log directories.

Start the daemon in the foreground first to see any errors (stop it with Ctrl+C):

```bash
cd /opt/nginx-php2shell-monitor
python3 monitor.py -c config.ini
```

Then run it in the background, either with screen or as a systemd service.

With screen (the shell keeps the window open if the daemon exits, so the error message remains
visible; detach with Ctrl+A, D):

```bash
screen -dmS php2shell bash -c 'python3 monitor.py -c config.ini; echo "monitor exited with code $?"; exec bash'
```

As a systemd service, for example `/etc/systemd/system/nginx-php2shell-monitor.service`:

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

To test the daemon without nginx, run the following command in a second shell. The detected
requests appear in the daemon output.

```bash
python3 test_requests.py
```

### 2. nginx

```bash
sudo cp /opt/nginx-php2shell-monitor/nginx/php2shell-mirror.conf /etc/nginx/snippets/
```

Make the following changes in each server block you want to monitor (see
`nginx/example-site.conf`):

1. Add `include /etc/nginx/snippets/php2shell-mirror.conf;` to the `server` block.
2. Add `mirror /__php2shell_monitor;` and `mirror_request_body on;` to each location block that
   contains `fastcgi_pass`, and to no other location block. A `location /` block with `try_files`
   usually redirects requests internally to `/index.php`. If both location blocks contain the
   `mirror` directive, each request is mirrored twice. Named locations (`@php`) are supported.

Shortened example of a server block (the complete file is `nginx/example-site.conf`):

```nginx
server {
    server_name example.com;
    root /var/www/example.com/public;
    ...

    # nginx-php2shell-monitor: internal mirror location, once per server block
    include /etc/nginx/snippets/php2shell-mirror.conf;

    location / {
        # no mirror here: try_files passes the request on to /index.php
        try_files $uri /index.php$is_args$args;
    }

    location ~ \.php$ {
        # nginx-php2shell-monitor: only in location blocks with fastcgi_pass
        mirror /__php2shell_monitor;
        mirror_request_body on;

        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        ...
    }
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Test the setup through nginx. The detected requests must show your own IP address, not the IP
address sent by the script. If the hook is enabled, read the warning in [Hook](#hook) first:

```bash
python3 test_requests.py --url https://example.com
```

The test requests are sent to your application and receive its normal responses (for example
404 or 405). They have the structure of the known exploits but do not contain a working payload.

### Notes

- With `mirror_request_body on`, nginx reads the complete request body before it passes the
  request to PHP. For typical POST requests, this has no noticeable effect.
- Requests larger than `client_max_body_size` are rejected with status 413 before they are
  mirrored. These requests appear only in the access log.
- Requests rejected by access rules (`allow`/`deny`, authentication) are not mirrored.
- Only POST requests are inspected, because PHP parses only POST request bodies automatically.

## Privacy

Stored requests contain all data sent by the client, including cookies, session IDs and possibly
personal data or passwords. This also applies to requests with the level `generic`, which can be
sent by regular visitors. Restrict access to the capture directory, delete captures that are no
longer needed, and check whether the operation complies with your data protection obligations
(for example GDPR).

## Uninstallation

1. Remove the `include` and `mirror` lines from the nginx configuration.
2. Delete the snippet: `sudo rm /etc/nginx/snippets/php2shell-mirror.conf`
3. Reload nginx: `sudo nginx -t && sudo systemctl reload nginx`
4. Stop the daemon.
5. If you use the nftables example hook: delete the table (`sudo nft delete table inet php2shell`),
   the `include` line in `/etc/nftables.conf`, `/usr/local/sbin/php2shell-ban` and
   `/etc/sudoers.d/php2shell-ban`.
6. If you use the CrowdSec example hook: delete `/usr/local/sbin/php2shell-ban` and
   `/etc/sudoers.d/php2shell-ban`. Existing decisions expire automatically.

## References

- [Datadog Security Labs: PHP2Shell - detection, analysis, and remediation](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Amazon Threat Intelligence: PHP2Shell exploitation prior to public disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [Imperva: PHP2Shell - when PHP runs out of memory at the wrong moment](https://www.imperva.com/blog/php2shell-vulnerability-updates/)
- [Tenable: PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [watchTowr: PHP2Shell](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/)
- [Sansec: PHP2Shell](https://sansec.io/research/php2shell)
- [rjmendez/phpup-2026: analysis of the PHP fix and detection rules](https://github.com/rjmendez/phpup-2026)
- [ikow/php2shell-poc: detection rules](https://github.com/ikow/php2shell-poc/tree/main/detection)
- [darkfibr/php2shell-detect: request signatures](https://github.com/darkfibr/php2shell-detect)
- [Telekom Security: PHP2Shell honeypot observations](https://github.security.telekom.com/2026/10/php2shell-honeypot-observations.html)
- [SOCRadar: PHP2Shell exploit tooling on an exposed attacker server](https://socradar.io/blog/php2shell-exploit-tooling-attacker-server/)
- [VulnCheck: PHP2Shell vulnerabilities](https://www.vulncheck.com/blog/php2shell-vulnerabilities)
- [Zscaler ThreatLabz: CVE-2026-109618 and CVE-2026-109619](https://www.zscaler.com/blogs/security-research/cve-2026-109618-and-cve-2026-109619-php-vulnerable-unauthenticated-rce)
- [Upwind: initial assessment of PHP2Shell](https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619)
- [Imunify360: PHP2Shell](https://blog.imunify360.com/php-cve-2026-109618-cve-2026-109619/)
- [CISA: Sigma rule for PHP2Shell](https://github.com/cisagov/SIGMA_Rules/blob/develop/CISA_SIGMA_261429_CVE_2026_109618-109619_PHP2Shell_TLP_CLEAR.yaml)
- [0x4d31/honeypot-data: confirmed RCE in a honeypot](https://github.com/0x4d31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md)
- [assetnote/php2shell-scanner: screening tool](https://github.com/assetnote/php2shell-scanner)
- [Defused: upload progress probes](https://x.com/DefusedCyber/status/2114241665972011513)
- [CrowdSec: virtual patching for PHP2Shell](https://www.crowdsec.net/blog/php2shell-virtual-patching)
- [CrowdSec documentation: virtual patching and CRS](https://docs.crowdsec.net/docs/v1.6/appsec/vpatch_and_crs)

## Changelog

### 2026-10-28

Upgrade notes:

- Copy `nginx/php2shell-mirror.conf` to `/etc/nginx/snippets/` again and reload nginx. The
  snippet now passes the original `Transfer-Encoding` header, which `chunked_multipart` requires.
- Compare your `config.ini` with `config.example.ini`. New options have default values and do
  not have to be added. `max_fields` is set in existing `config.ini` files and keeps its old value
  1000; set it to 500, the new value in `config.example.ini`.
- `upload_progress_field` now matches only a multipart field with exactly the configured name.
  Other occurrences are reported as `upload_progress_text` with the level `generic`.
- Emails are only sent for requests with at least the request level `php2shell` (new option
  `[mail] min_level`). Set `min_level = generic` to receive emails for all suspicious requests
  as before.

New:

- Hook: optional command that receives each event as JSON on stdin (`[hook]` section), with
  example scripts in Python and PHP that block the IP address with nftables or CrowdSec
  (`hooks/`).
- README: use behind a WAF, such as the CrowdSec WAF.
- Event log with one JSON object per line (`events_file`).
- Minimum request level for emails (`[mail] min_level`).
- Request level `php2shell-chain` for requests with the structure of a complete exploit chain.
  Fingerprints of the same tool count as one signal.
- New rules with the rule level `php2shell`: `multipart_header_flood`, `serialized_object_in_filename`,
  `exploit_tool_user_agent`, `exploit_tool_marker`, `probe_filename`, `empty_boundary_probe`.
- New rules with the rule level `generic`: `serialized_object_in_field`, `deep_nested_field_name`,
  `session_id_in_body`, `php_code_in_filename`, `long_filename`, `suspicious_filename`,
  `array_spray`, `chunked_multipart`, `empty_boundary`, `repeated_char_boundary`,
  `bare_lf_multipart`, `malformed_content_disposition`, `upload_progress_text`,
  `upload_progress_without_user_agent`, `scanner_user_agent`, `other_campaign_marker`,
  `react2shell_lookalike`.
- Fixed strings, boundaries and file names of published exploit and screening tools as default
  markers.

Changed:

- Multipart bodies are parsed with the variants that PHP accepts: LF-only line breaks, empty boundaries,
  `Content-Disposition` without `form-data` and folded header lines are supported. Before, such
  bodies were not inspected or field and file names were not found.
- `upload_progress_field` compares the field name exactly and case-sensitively, as PHP does.
  Before, the marker was searched anywhere in the body.
- The `STATUS` line also counts requests with the request level `php2shell-chain`.
- `test_requests.py` sends an additional request with LF-only line breaks.
- README and comments revised.

### 2026-10-22

- Initial release.

## Credits

Developed by Claude (Anthropic, Claude Opus 5.5) and Andreas Boldt.

## License

MIT, see [LICENSE](LICENSE).
