#!/usr/bin/env python3
"""
nginx-php2shell-monitor - live detection of PHP2Shell attack attempts
(CVE-2026-109618, CVE-2026-109619) based on full POST bodies.

nginx mirrors every POST that is handed to PHP to this daemon (see
nginx/php2shell-mirror.conf). The daemon inspects the body and stores
suspicious requests byte-exact as individual files.

Monitoring only: the monitor sees copies, it cannot block anything.

Python standard library only, tested with Python 3.9 and 3.12.

Usage:  python3 monitor.py -c config.ini
"""

import argparse
import configparser
import datetime
import hashlib
import http.server
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from urllib.parse import unquote_to_bytes


# ---------------------------------------------------------------------------
# Logging: console (for screen) + optional log file, thread-safe
# ---------------------------------------------------------------------------

class Log:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.fh = None
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.fh = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, msg):
        line = "%s %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
        with self.lock:
            print(line, flush=True)
            if self.fh:
                self.fh.write(line + "\n")


# ---------------------------------------------------------------------------
# Body analysis
# ---------------------------------------------------------------------------

# PHP accepts the field name in Content-Disposition with and without quotes.
MULTIPART_NAME_RE = re.compile(rb';\s*name=(?:"([^"]*)"|([^;\s]*))', re.IGNORECASE)
BOUNDARY_RE = re.compile(r'boundary=(?:"([^"]+)"|([^;\s]+))', re.IGNORECASE)

# Rules that target PHP2Shell closely. Hits of all other rules are stored just the
# same, but classified as "generic" (other attacks, bots, large uploads, ...).
# A request is "php2shell" as soon as at least one of these rules fires.
PHP2SHELL_RULES = ("long_field_name", "upload_progress_field")


def request_level(findings):
    return "php2shell" if any(f["level"] == "php2shell" for f in findings) else "generic"


def short(value, limit=80):
    """Shortened, printable representation of a field name for log and JSON."""
    text = repr(value[:limit])[2:-1]
    if len(value) > limit:
        text += "...(%d bytes)" % len(value)
    return text


def parse_urlencoded(body):
    """
    Splits an application/x-www-form-urlencoded body the way PHP does: separator
    '&', name and value at the first '=', '+' as space, %XX decoded.
    Returns a list of (name, value) as bytes.
    """
    fields = []
    for pair in body.split(b"&"):
        if not pair:
            continue
        name, sep, value = pair.partition(b"=")
        name = unquote_to_bytes(name.replace(b"+", b" "))
        value = unquote_to_bytes(value.replace(b"+", b" "))
        fields.append((name, value))
    return fields


def parse_multipart(body, content_type):
    """
    Returns a list of (name, part_headers) of the multipart parts. Deliberately
    simple: only as much as the rules need (field names and count).
    """
    match = BOUNDARY_RE.search(content_type)
    if not match:
        return None
    boundary = (match.group(1) or match.group(2)).encode("latin-1")

    fields = []
    for part in body.split(b"--" + boundary):
        part = part.lstrip(b"\r\n")
        if not part or part.startswith(b"--"):
            continue
        headers, _, _ = part.partition(b"\r\n\r\n")
        name_match = MULTIPART_NAME_RE.search(headers)
        name = b""
        if name_match:
            name = name_match.group(1) if name_match.group(1) is not None else name_match.group(2)
        fields.append((name, headers))
    return fields


def analyze(req, rules):
    """
    Checks a mirrored request. Returns a list of findings
    [{"rule": ..., "detail": ..., "count": ..., "level": ...}], empty = clean.
    """
    findings = []
    body = req["body"]
    content_type = req["content_type"].lower()

    # Upload progress field: trigger of the session based variants (CVE-2026-109619).
    # Searched in the raw and the URL-decoded body, regardless of the content type.
    marker = rules["upload_progress_marker"].lower().encode()
    if marker in body.lower() or marker in unquote_to_bytes(body).lower():
        findings.append({"rule": "upload_progress_field",
                         "detail": "%s in body" % rules["upload_progress_marker"]})

    fields = None
    if content_type.startswith("application/x-www-form-urlencoded"):
        fields = parse_urlencoded(body)
        for name, value in fields:
            # Known attack (CVE-2026-109618): field without a name, binary value / NUL bytes.
            if name == b"":
                findings.append({"rule": "empty_field_name",
                                 "detail": "field without name, value %d bytes" % len(value)})
            if b"\x00" in name or b"\x00" in value:
                findings.append({"rule": "nul_byte",
                                 "detail": "NUL byte in field '%s'" % short(name)})
    elif content_type.startswith("multipart/form-data"):
        fields = parse_multipart(body, req["content_type"])
        if fields is None:
            findings.append({"rule": "multipart_without_boundary",
                             "detail": "multipart/form-data without boundary"})
            fields = []
        for name, headers in fields:
            if b"\x00" in name or b"\x00" in headers:
                findings.append({"rule": "nul_byte",
                                 "detail": "NUL byte in part header '%s'" % short(name)})

    if fields:
        # Known attack (CVE-2026-109618): field name of ~3.5 MB ending in [x].
        for name, _ in fields:
            if len(name) > rules["max_field_name_length"]:
                findings.append({"rule": "long_field_name",
                                 "detail": "field name %d bytes, ends with '%s'" % (
                                     len(name), short(name[-40:]))})

        if len(fields) > rules["max_fields"]:
            findings.append({"rule": "too_many_fields",
                             "detail": "%d fields" % len(fields)})

    # Large bodies outside of the paths where uploads are expected.
    if len(body) >= rules["large_body_bytes"]:
        path = req["path"]
        if not any(path.startswith(prefix) for prefix in rules["large_body_ignore_paths"]):
            findings.append({"rule": "large_body",
                             "detail": "%d bytes to %s" % (len(body), path.split("?")[0])})

    # Merge repeated hits of the same rule (e.g. thousands of NUL byte fields).
    merged = OrderedDict()
    for finding in findings:
        if finding["rule"] in merged:
            merged[finding["rule"]]["count"] += 1
        else:
            merged[finding["rule"]] = dict(
                finding, count=1,
                level="php2shell" if finding["rule"] in PHP2SHELL_RULES else "generic")
    return list(merged.values())


# ---------------------------------------------------------------------------
# Storage of suspicious requests
# ---------------------------------------------------------------------------

class CaptureStore:
    def __init__(self, directory, max_total_bytes, log):
        self.dir = directory
        self.max_total_bytes = max_total_bytes
        self.log = log
        self.limit_warned = False
        # (ip, sha256) -> file name, so identical repetitions are stored only once
        self.seen = OrderedDict()

        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.total_bytes = sum(
            os.path.getsize(os.path.join(self.dir, f)) for f in os.listdir(self.dir))

    def _write(self, path, data):
        # O_EXCL: never overwrite an existing file
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.total_bytes += len(data)

    def save(self, req, findings):
        """Returns (file_name_without_extension, is_duplicate)."""
        sha = hashlib.sha256(req["body"]).hexdigest()
        key = (req["ip"], sha)
        if key in self.seen:
            return self.seen[key], True

        ts = datetime.datetime.fromtimestamp(req["time"]).strftime("%Y-%m-%d_%H-%M-%S")
        ip_safe = re.sub(r"[^0-9A-Za-z.]", "-", req["ip"])
        level = request_level(findings)
        base = "%s_%s_%s_%s" % (ts, level, ip_safe, sha[:10])

        # Request as received from nginx: request line, headers, empty line, body (byte-exact)
        raw = "%s %s %s\r\n" % (req["method"], req["path"], req["version"])
        raw += "".join("%s: %s\r\n" % (k, v) for k, v in req["headers"])
        raw = raw.encode("latin-1", "replace") + b"\r\n" + req["body"]

        body_saved = self.total_bytes + len(raw) <= self.max_total_bytes
        meta = {
            "time": datetime.datetime.fromtimestamp(req["time"]).isoformat(),
            "level": level,
            "ip": req["ip"],
            "method": req["method"],
            "host": req["host"],
            "path": req["path"],
            "content_type": req["content_type"],
            "body_bytes": len(req["body"]),
            "body_truncated": req["truncated"],
            "body_sha256": sha,
            "body_saved": body_saved,
            "nginx_request_id": req["request_id"],
            "findings": findings,
        }

        if body_saved:
            self._write(os.path.join(self.dir, base + ".req"), raw)
        elif not self.limit_warned:
            self.log.write("WARNING capture limit reached (%d MB), writing .json without body from now on"
                           % (self.max_total_bytes // 1048576))
            self.limit_warned = True

        self._write(os.path.join(self.dir, base + ".json"),
                    json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8"))

        self.seen[key] = base
        if len(self.seen) > 10000:
            self.seen.popitem(last=False)
        return base, False


# ---------------------------------------------------------------------------
# Mail notification (optional)
# ---------------------------------------------------------------------------

class Mailer:
    def __init__(self, to, sender, min_interval, log):
        self.to = to
        self.sender = sender
        self.min_interval = min_interval
        self.log = log
        self.last_by_ip = {}

    def notify(self, req, findings, capture_name):
        if not self.to:
            return
        now = time.time()
        if now - self.last_by_ip.get(req["ip"], 0) < self.min_interval:
            return
        self.last_by_ip[req["ip"]] = now

        lines = [
            "Suspicious POST request (PHP2Shell patterns)",
            "",
            "Time:  %s" % datetime.datetime.fromtimestamp(req["time"]).isoformat(),
            "IP:    %s" % req["ip"],
            "URL:   %s%s" % (req["host"], req["path"]),
            "Size:  %d bytes" % len(req["body"]),
            "File:  %s" % capture_name,
            "",
            "Findings:",
        ] + ["  - %s (%s): %s" % (f["rule"], f["level"], f["detail"]) for f in findings] + [
            "",
            "Further hits from the same IP within %d minutes are only logged."
            % (self.min_interval // 60),
        ]
        message = "From: %s\nTo: %s\nSubject: [nginx-php2shell-monitor] %s %s %s\n" \
                  "Content-Type: text/plain; charset=utf-8\n\n%s\n" % (
                      self.sender, self.to, request_level(findings), req["host"], req["ip"],
                      "\n".join(lines))
        try:
            subprocess.run(["/usr/sbin/sendmail", "-t"], input=message.encode("utf-8"),
                           timeout=30, check=True)
        except Exception as e:
            self.log.write("ERROR sending mail: %s" % e)


# ---------------------------------------------------------------------------
# HTTP endpoint for the mirrored requests
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.posts = 0
        self.suspicious = 0
        self.level_php2shell = 0
        self.level_generic = 0
        self.saved = 0
        self.duplicates = 0
        self.dropped = 0

    def inc(self, name):
        with self.lock:
            setattr(self, name, getattr(self, name) + 1)


class MirrorHandler(http.server.BaseHTTPRequestHandler):
    # Set in main()
    work_queue = None
    max_body_bytes = 0
    stats = None

    protocol_version = "HTTP/1.0"
    server_version = "nginx-php2shell-monitor"

    def log_message(self, fmt, *args):
        # No per-request access log
        pass

    def _respond(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        # nginx only mirrors POST (see the if in php2shell-mirror.conf), ignore everything else
        self._respond()

    do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_GET

    def do_POST(self):
        received = time.time()
        length = int(self.headers.get("Content-Length") or 0)

        # Read the full body before answering; nginx sends it completely anyway.
        body = self.rfile.read(min(length, self.max_body_bytes))
        rest = length - len(body)
        while rest > 0:
            chunk = self.rfile.read(min(rest, 65536))
            if not chunk:
                break
            rest -= len(chunk)

        # Answer immediately, analysis runs in the worker thread
        self._respond()

        self.stats.inc("posts")
        req = {
            "time": received,
            "ip": self.headers.get("X-Php2shell-Client-Ip") or self.client_address[0],
            "request_id": self.headers.get("X-Php2shell-Request-Id", ""),
            "method": self.command,
            "version": self.request_version,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "content_type": self.headers.get("Content-Type", ""),
            "headers": list(self.headers.items()),
            "body": body,
            "truncated": length > len(body),
        }
        try:
            self.work_queue.put_nowait(req)
        except queue.Full:
            self.stats.inc("dropped")


def worker(work_queue, rules, store, mailer, stats, log):
    while True:
        req = work_queue.get()
        if req is None:
            return
        try:
            findings = analyze(req, rules)
            if not findings:
                continue
            stats.inc("suspicious")
            level = request_level(findings)
            stats.inc("level_" + level)
            name, duplicate = store.save(req, findings)
            summary = ", ".join(
                "%s%s" % (f["rule"], " x%d" % f["count"] if f["count"] > 1 else "") for f in findings)
            if duplicate:
                stats.inc("duplicates")
                log.write("HIT %s %s %s%s %s -> repetition of %s"
                          % (level, req["ip"], req["host"], req["path"], summary, name))
            else:
                stats.inc("saved")
                log.write("HIT %s %s %s%s %d bytes [%s] -> %s"
                          % (level, req["ip"], req["host"], req["path"], len(req["body"]), summary, name))
                for f in findings:
                    log.write("    %s (%s): %s" % (f["rule"], f["level"], f["detail"]))
                mailer.notify(req, findings, name)
        except Exception as e:
            log.write("ERROR analyzing %s %s: %r" % (req.get("ip"), req.get("path"), e))


def stats_loop(interval, stats, work_queue, log):
    while True:
        time.sleep(interval)
        log.write("STATUS %d POSTs checked, %d suspicious (%d php2shell, %d generic; "
                  "%d saved, %d repetitions), %d dropped (queue full), queue %d"
                  % (stats.posts, stats.suspicious, stats.level_php2shell, stats.level_generic,
                     stats.saved, stats.duplicates, stats.dropped, work_queue.qsize()))


def main():
    parser = argparse.ArgumentParser(description="PHP2Shell monitor for POST requests mirrored by nginx")
    parser.add_argument("-c", "--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config, encoding="utf-8"):
        sys.exit("Config not found: %s (copy config.example.ini to config.ini first)" % args.config)

    log = Log(cfg.get("log", "file", fallback="").strip())

    rules = {
        "max_field_name_length": cfg.getint("rules", "max_field_name_length"),
        "max_fields": cfg.getint("rules", "max_fields"),
        "large_body_bytes": cfg.getint("rules", "large_body_bytes"),
        "large_body_ignore_paths": [p.strip() for p in cfg.get("rules", "large_body_ignore_paths").split(",") if p.strip()],
        "upload_progress_marker": cfg.get("rules", "upload_progress_marker").strip(),
    }

    store = CaptureStore(cfg.get("capture", "dir"), cfg.getint("capture", "max_total_mb") * 1048576, log)
    mailer = Mailer(cfg.get("mail", "to", fallback="").strip(), cfg.get("mail", "from").strip(),
                    cfg.getint("mail", "min_interval"), log)
    stats = Stats()
    work_queue = queue.Queue(maxsize=cfg.getint("server", "queue_size"))

    MirrorHandler.work_queue = work_queue
    MirrorHandler.max_body_bytes = cfg.getint("server", "max_body_bytes")
    MirrorHandler.stats = stats

    host = cfg.get("server", "listen_host")
    port = cfg.getint("server", "listen_port")
    http.server.ThreadingHTTPServer.daemon_threads = True
    server = http.server.ThreadingHTTPServer((host, port), MirrorHandler)

    threading.Thread(target=worker, args=(work_queue, rules, store, mailer, stats, log), daemon=True).start()
    interval = cfg.getint("log", "stats_interval")
    if interval > 0:
        threading.Thread(target=stats_loop, args=(interval, stats, work_queue, log), daemon=True).start()

    # Remember why the monitor stopped for the STOP line. SIGTERM (systemd) and
    # SIGHUP (terminal closed) shut down cleanly like Ctrl+C.
    stop_reason = ["serve_forever returned"]

    def on_signal(signum, _frame):
        stop_reason[0] = "signal %s" % signal.Signals(signum).name
        threading.Thread(target=server.shutdown).start()

    signal.signal(signal.SIGTERM, on_signal)
    if hasattr(signal, "SIGHUP"):  # not available on Windows
        signal.signal(signal.SIGHUP, on_signal)

    log.write("START listening on %s:%d, captures in %s (%d MB used), mail to: %s"
              % (host, port, store.dir, store.total_bytes // 1048576, mailer.to or "-"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_reason[0] = "Ctrl+C (SIGINT)"
    server.server_close()
    log.write("STOP (%s) %d POSTs checked, %d suspicious, %d saved"
              % (stop_reason[0], stats.posts, stats.suspicious, stats.saved))


if __name__ == "__main__":
    main()
