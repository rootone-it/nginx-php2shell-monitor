#!/usr/bin/env python3
"""
nginx-php2shell-monitor - detects exploitation attempts of PHP2Shell
(CVE-2026-109618, CVE-2026-109619) by inspecting POST request bodies.

nginx sends a copy of each POST request passed to PHP to this daemon (see
nginx/php2shell-mirror.conf). The daemon inspects the request body and stores
each suspicious request unchanged in a separate file.

The daemon only receives copies of the requests and cannot block them. An
optional hook command can block the IP address for further requests.

Requires only the Python standard library. Tested with Python 3.9 and 3.12.

Usage:  python3 monitor.py -c config.ini
"""

import argparse
import configparser
import datetime
import hashlib
import http.server
import ipaddress
import json
import shlex
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from collections import Counter, OrderedDict
from urllib.parse import unquote_to_bytes


# ---------------------------------------------------------------------------
# Logging to the console and optionally to a log file
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


class EventLog:
    """
    Writes one JSON object per line for each suspicious request, including
    repeated requests. It can easily be processed by other scripts. Disabled
    if no path is configured.
    """

    def __init__(self, path):
        self.lock = threading.Lock()
        self.fh = None
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.fh = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, req, findings, capture_name, repeat):
        if not self.fh:
            return
        line = json.dumps(event_dict(req, findings, capture_name, repeat), ensure_ascii=False)
        with self.lock:
            self.fh.write(line + "\n")


def event_dict(req, findings, capture_name, repeat):
    """Event as written to the event log and passed to the hook command."""
    return {
        # UTC in RFC 3339 format
        "time": datetime.datetime.fromtimestamp(req["time"], datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip": req["ip"],
        "level": request_level(findings),
        "rules": ",".join(f["rule"] for f in findings),
        "method": req["method"],
        "host": req["host"],
        "path": req["path"],
        "user_agent": req["user_agent"],
        "body_bytes": len(req["body"]),
        "capture": capture_name,
        "repeat": repeat,
    }


# ---------------------------------------------------------------------------
# Body inspection
# ---------------------------------------------------------------------------

# PHP accepts quoted and unquoted field names in Content-Disposition. It also
# accepts a Content-Disposition without "form-data", so that "name=" directly
# follows the colon (e.g. "Content-Disposition:name=a"), as sent by a published
# screening tool.
MULTIPART_NAME_RE = re.compile(rb'[;:]\s*name=(?:"([^"]*)"|([^;\s]*))', re.IGNORECASE)
MULTIPART_FILENAME_RE = re.compile(rb'[;:]\s*filename=(?:"([^"]*)"|([^;\r\n]*))', re.IGNORECASE)
# The boundary may be empty ("boundary="). Browsers never send that, but a
# published screening tool does. PHP then uses "--" as delimiter line.
BOUNDARY_RE = re.compile(r'boundary=(?:"([^"]*)"|([^;\s]*))', re.IGNORECASE)
# Line break within a multipart header block that is not preceded by CR.
BARE_LF_RE = re.compile(rb'(?<!\r)\n')
# Folded header line (continuation line starting with a space or a tab).
FOLDED_HEADER_RE = re.compile(rb'\r?\n[ \t]+')

# Serialized PHP object or array as used in session injection, e.g. |O:8:"stdClass"
SERIALIZED_RE = re.compile(rb'(?:\||^)[OCa]:\d+:')

# Serialized PHP object or array at the start of a field value or after "|",
# e.g. O:8:"stdClass" or a:2:{. Stricter than SERIALIZED_RE, because field
# values contain more free text than file names.
SERIALIZED_VALUE_RE = re.compile(rb'(?:^|\|)(?:[OC]:\d+:"|a:\d+:\{)')

# Rules with the rule level "php2shell" (specific to PHP2Shell). All other
# rules have the rule level "generic". A request receives the request level
# "php2shell" if at least one of these rules matches, "php2shell-chain" under
# the conditions below, otherwise "generic". Requests of all levels are stored.
PHP2SHELL_RULES = (
    "long_field_name",
    "upload_progress_field",
    "multipart_header_flood",
    "serialized_object_in_filename",
    "exploit_tool_user_agent",
    "exploit_tool_marker",
    "probe_filename",
    "empty_boundary_probe",
)

# The known exploit chains need two steps: a trigger that reaches the vulnerable
# code path, and a payload that is injected there. A request that carries both
# has the shape of a complete exploit attempt, not of a scan. It receives the
# level "php2shell-chain". This does not mean the attempt succeeded - that
# depends on the PHP version and configuration, which the request does not show.
# array_spray is not an injection step, but published detection rules rate it
# together with the upload progress field as a strong signal of an exploit tool.
PHP2SHELL_TRIGGER_RULES = ("upload_progress_field",)
PHP2SHELL_PAYLOAD_RULES = (
    "serialized_object_in_filename",
    "php_code_in_filename",
    "session_id_in_body",
    "probe_filename",
    "suspicious_filename",
    "array_spray",
)

# Fingerprints of exploit tools. Several of them in one request usually come
# from the same tool, so they count as one signal for the level
# "php2shell-chain".
TOOL_FINGERPRINT_RULES = ("exploit_tool_user_agent", "exploit_tool_marker")


def request_level(findings):
    rules_hit = {f["rule"] for f in findings}
    php2shell_hits = rules_hit.intersection(PHP2SHELL_RULES)
    trigger = rules_hit.intersection(PHP2SHELL_TRIGGER_RULES)
    payload = rules_hit.intersection(PHP2SHELL_PAYLOAD_RULES)
    signals = len(php2shell_hits.difference(TOOL_FINGERPRINT_RULES))
    if php2shell_hits.intersection(TOOL_FINGERPRINT_RULES):
        signals += 1
    # Complete chain: trigger plus injection step, or at least two independent
    # PHP2Shell-specific signals in one request.
    if (trigger and payload) or signals >= 2:
        return "php2shell-chain"
    if php2shell_hits:
        return "php2shell"
    return "generic"


def short(value, limit=80):
    """Returns a printable, shortened field name for the log and the JSON file."""
    text = repr(value[:limit])[2:-1]
    if len(value) > limit:
        text += "...(%d bytes)" % len(value)
    return text


def parse_urlencoded(body):
    """
    Splits an application/x-www-form-urlencoded body like PHP: pairs are
    separated by '&', name and value by the first '=', '+' is converted to a
    space and %XX is decoded. Returns a list of (name, value) byte strings.
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


def multipart_boundary(content_type):
    """Returns the boundary as bytes (possibly empty), or None if it is missing."""
    match = BOUNDARY_RE.search(content_type)
    if not match:
        return None
    return (match.group(1) if match.group(1) is not None else match.group(2)).encode("latin-1")


def parse_multipart(body, boundary):
    """
    Returns one dict per multipart part with the keys "name", "filename" (None
    for regular fields), "headers" (raw header block), "header_names" (list of
    the lowercased header names in the order of the request), "bare_lf" (the
    delimiter line or the header block contains a line break without CR),
    "folded" (the header block contains continuation lines) and
    "disposition" (value of Content-Disposition, None if missing). The part
    content is not extracted, because the rules do not need it.

    Like PHP, lines may end with CRLF or with LF only. A delimiter is
    "--" + boundary at the start of a line.
    """
    delimiter = re.compile(rb'(?:^|\n)--' + re.escape(boundary))

    parts = []
    # The first element is the preamble before the first delimiter.
    for part in delimiter.split(body)[1:]:
        # Closing delimiter "--boundary--"
        if part.startswith(b"--"):
            continue
        # The rest of the delimiter line (normally only the line break).
        delimiter_line, sep, part = part.partition(b"\n")
        bare_lf = bool(sep) and not delimiter_line.endswith(b"\r")

        # If the empty line is missing (e.g. a part that consists of headers
        # only), the whole part is treated as header block.
        headers = re.split(rb'\r?\n\r?\n', part, 1)[0]
        if BARE_LF_RE.search(headers):
            bare_lf = True
        lines = [line.rstrip(b"\r") for line in headers.split(b"\n")]
        # Continuation lines are counted as separate header lines, like the
        # other lines without a colon.
        header_names = [line.split(b":", 1)[0].strip().lower() for line in lines if line.strip()]
        folded = any(line[:1] in (b" ", b"\t") for line in lines if line.strip())

        # Name and file name are searched in the unfolded header block, because
        # continuation lines can move parameters to a new line.
        unfolded = FOLDED_HEADER_RE.sub(b" ", headers)
        disposition = None
        for line in unfolded.split(b"\n"):
            key, colon, value = line.partition(b":")
            if colon and key.strip().lower() == b"content-disposition":
                disposition = value.strip()
                break

        name = b""
        name_match = MULTIPART_NAME_RE.search(unfolded)
        if name_match:
            name = name_match.group(1) if name_match.group(1) is not None else name_match.group(2)
        filename = None
        filename_match = MULTIPART_FILENAME_RE.search(unfolded)
        if filename_match:
            filename = filename_match.group(1) if filename_match.group(1) is not None else filename_match.group(2)
            filename = filename.rstrip(b"\r")

        parts.append({"name": name, "filename": filename, "headers": headers,
                      "header_names": header_names, "bare_lf": bare_lf, "folded": folded,
                      "disposition": disposition})
    return parts


def analyze(req, rules):
    """
    Inspects a mirrored request. Returns a list of findings as dicts with the
    keys "rule", "detail", "count" and "level". An empty list means that
    nothing suspicious was found.
    """
    findings = []
    body = req["body"]
    content_type = req["content_type"].lower()
    lower_body = body.lower()
    decoded_body = unquote_to_bytes(body).lower()

    # The upload progress field triggers the session based variants
    # (CVE-2026-109619). PHP only reacts to a multipart field whose name is
    # exactly upload_progress_marker (case-sensitive); that is checked below
    # as upload_progress_field. Any other occurrence (other spelling,
    # urlencoded body, file content, free text) has no effect in PHP, but is
    # logged with the level generic. The raw and the URL-decoded body are
    # searched, regardless of the content type.
    marker = rules["upload_progress_marker"].lower().encode()
    upload_progress_text = marker in lower_body or marker in decoded_body

    # Fingerprints of published exploit tools: User-Agent (e.g. "php2shell-109619",
    # the number is incremented per request) and fixed strings from the PoC
    # (multipart boundary, command output marker). The User-Agent is a weak
    # indicator, because most tool requests do not send it.
    if rules["tool_user_agent_re"] and rules["tool_user_agent_re"].search(req["user_agent"]):
        findings.append({"rule": "exploit_tool_user_agent",
                         "detail": "User-Agent '%s'" % req["user_agent"][:100]})
    # User-Agents of self-named version checkers. They are scanners and not
    # exploits, therefore generic.
    if rules["scanner_user_agent_re"] and rules["scanner_user_agent_re"].search(req["user_agent"]):
        findings.append({"rule": "scanner_user_agent",
                         "detail": "User-Agent '%s'" % req["user_agent"][:100]})
    # Markers of other campaigns with a similar request shape (for example
    # "wp2shell"). They are only logged to separate them from PHP2Shell.
    # They are removed from the Content-Type before the tool markers are
    # searched, because a short tool marker can be part of them: "wp2shell"
    # contains the tool marker "p2shell".
    tool_content_type = content_type
    for other_marker in rules["other_content_type_markers"]:
        if other_marker.lower() in content_type:
            findings.append({"rule": "other_campaign_marker",
                             "detail": "'%s' found in Content-Type" % other_marker})
            tool_content_type = tool_content_type.replace(other_marker.lower(), "")
    for tool_marker in rules["tool_markers"]:
        needle = tool_marker.lower().encode()
        if needle in lower_body or needle in tool_content_type.encode():
            findings.append({"rule": "exploit_tool_marker",
                             "detail": "'%s' found in request" % tool_marker})
    # Markers that are only searched in the Content-Type header (multipart
    # boundaries of exploit tools). Words like "php2shell" can also appear in
    # regular form text, for example in a support request about the vulnerability.
    for tool_marker in rules["tool_content_type_markers"]:
        if tool_marker.lower() in tool_content_type:
            findings.append({"rule": "exploit_tool_marker",
                             "detail": "'%s' found in Content-Type" % tool_marker})

    # Next.js Server Actions header used by React2Shell. These requests also
    # use chunked multipart bodies and are separated from PHP2Shell this way.
    if any(key.lower() == "next-action" for key, _ in req["headers"]):
        findings.append({"rule": "react2shell_lookalike",
                         "detail": "Next-Action header present"})

    # Chunked request body: removes the Content-Length that PHP checks against
    # post_max_size. nginx passes the original Transfer-Encoding in a separate
    # header, because the mirrored copy always has a Content-Length.
    if "chunked" in req["transfer_encoding"].lower() and content_type.startswith("multipart/form-data"):
        findings.append({"rule": "chunked_multipart",
                         "detail": "multipart/form-data with Transfer-Encoding: %s" % req["transfer_encoding"]})

    names = []
    if content_type.startswith("application/x-www-form-urlencoded"):
        fields = parse_urlencoded(body)
        names = [name for name, _ in fields]
        for name, value in fields:
            # Part of the known CVE-2026-109618 exploit: a field without a name
            # with binary content including NUL bytes.
            if name == b"":
                findings.append({"rule": "empty_field_name",
                                 "detail": "field without a name, value has %d bytes" % len(value)})
            if b"\x00" in name or b"\x00" in value:
                findings.append({"rule": "nul_byte",
                                 "detail": "NUL byte in field '%s'" % short(name)})
            # Serialized PHP data in a field value. Observed in exploitation
            # attempts, but also used by some applications, therefore generic.
            if SERIALIZED_VALUE_RE.search(value):
                findings.append({"rule": "serialized_object_in_field",
                                 "detail": "field '%s'" % short(name)})
    elif content_type.startswith("multipart/form-data"):
        boundary = multipart_boundary(req["content_type"])
        if boundary is None:
            findings.append({"rule": "multipart_without_boundary",
                             "detail": "multipart/form-data without boundary"})
            parts = []
        else:
            # Empty boundary: never sent by browsers or common HTTP libraries,
            # but by the probes of a published screening tool.
            if boundary == b"":
                findings.append({"rule": "empty_boundary",
                                 "detail": "multipart/form-data with empty boundary"})
            # Boundary of one repeated character (e.g. "AAAAAAAAAA"), as in the
            # confirmed exploit chain. Browsers and HTTP libraries use random
            # or hexadecimal boundaries.
            elif len(boundary) >= 8 and len(set(boundary)) == 1 and boundary[:1] != b"-":
                findings.append({"rule": "repeated_char_boundary",
                                 "detail": "boundary '%s'" % short(boundary)})
            parts = parse_multipart(body, boundary)
        names = [p["name"] for p in parts]
        # PHP compares both names exactly and case-sensitively.
        session_name = rules["session_name"].encode()
        progress_name = rules["upload_progress_marker"].encode()
        if any(p["name"] == progress_name for p in parts):
            findings.append({"rule": "upload_progress_field",
                             "detail": "multipart field '%s'" % rules["upload_progress_marker"]})
            # The confirmed exploit chain and several published scanners send
            # no User-Agent. Browsers with an upload progress bar always send one.
            # Some Python tools send the literal string "None" instead, when the
            # header value is not set.
            if req["user_agent"].strip() in ("", "None"):
                findings.append({"rule": "upload_progress_without_user_agent",
                                 "detail": "multipart field '%s', no User-Agent" % rules["upload_progress_marker"]})
            upload_progress_text = False
        # Line breaks without CR: browsers always send CRLF in multipart
        # headers, a published screening tool sends LF only.
        if any(p["bare_lf"] for p in parts):
            findings.append({"rule": "bare_lf_multipart",
                             "detail": "%d of %d parts with LF-only line breaks" % (
                                 sum(1 for p in parts if p["bare_lf"]), len(parts))})
        for p in parts:
            if b"\x00" in p["name"] or b"\x00" in p["headers"]:
                findings.append({"rule": "nul_byte",
                                 "detail": "NUL byte in part header '%s'" % short(p["name"])})

            # Content-Disposition without "form-data" or with continuation
            # lines. PHP accepts both, browsers send neither.
            disposition = p["disposition"]
            if p["folded"] or (disposition is not None
                               and not disposition.lower().startswith(b"form-data")):
                findings.append({"rule": "malformed_content_disposition",
                                 "detail": "part '%s': %s" % (
                                     short(p["name"]),
                                     "folded header lines" if p["folded"] else
                                     "Content-Disposition '%s'" % short(disposition, 40))})

            # CVE-2026-109618 amplification: before the fix, PHP stored every
            # header line of a part. Many or duplicate header lines in one part
            # drive PHP into memory_limit at low cost. Browsers send two or three
            # different headers per part.
            header_count = len(p["header_names"])
            duplicates = header_count - len(set(p["header_names"]))
            if header_count > rules["max_part_headers"] or duplicates > 0:
                findings.append({"rule": "multipart_header_flood",
                                 "detail": "part '%s' has %d header lines, %d duplicates" % (
                                     short(p["name"]), header_count, duplicates)})

            # Session ID sent as form field: lets the upload progress handler
            # write into a session chosen by the attacker (session fixation).
            if p["name"] == session_name:
                findings.append({"rule": "session_id_in_body",
                                 "detail": "multipart field '%s'" % rules["session_name"]})

            if SERIALIZED_VALUE_RE.search(p["name"]):
                findings.append({"rule": "serialized_object_in_field",
                                 "detail": "field name '%s'" % short(p["name"])})

            # The upload progress handler stores the file name and the field
            # name of each file part unchanged in the session. Published attack
            # chains use the file name to inject PHP code or serialized
            # objects, or to inflate the session. The field name of a file part
            # is checked the same way, because PHP stores it as well. Long field
            # names are already reported by long_field_name.
            filename = p["filename"]
            if filename is not None:
                for label, value in (("filename", filename), ("field name of file part", p["name"])):
                    if SERIALIZED_RE.search(value):
                        findings.append({"rule": "serialized_object_in_filename",
                                         "detail": "%s '%s'" % (label, short(value))})
                    if b"<?" in value:
                        findings.append({"rule": "php_code_in_filename",
                                         "detail": "%s '%s'" % (label, short(value))})
                if len(filename) > rules["max_filename_length"]:
                    findings.append({"rule": "long_filename",
                                     "detail": "filename has %d bytes" % len(filename)})
                # File name patterns of published screening tools that test
                # whether file names end up in the session.
                if rules["tool_filename_re"] and rules["tool_filename_re"].search(filename):
                    findings.append({"rule": "probe_filename",
                                     "detail": "filename '%s'" % short(filename)})
                # File names from exploit chains that are short enough to be
                # used by regular visitors as well (e.g. "p2s.txt").
                if rules["suspicious_filename_re"] and rules["suspicious_filename_re"].search(filename):
                    findings.append({"rule": "suspicious_filename",
                                     "detail": "filename '%s'" % short(filename)})

    if upload_progress_text:
        findings.append({"rule": "upload_progress_text",
                         "detail": "%s found in body, but not as multipart field name"
                                   % rules["upload_progress_marker"]})

    if names:
        # Known CVE-2026-109618 exploit: field name of about 3.5 MB ending in [x].
        for name in names:
            if len(name) > rules["max_field_name_length"]:
                findings.append({"rule": "long_field_name",
                                 "detail": "field name has %d bytes, ends with '%s'" % (
                                     len(name), short(name[-40:]))})

        if len(names) > rules["max_fields"]:
            findings.append({"rule": "too_many_fields",
                             "detail": "%d fields" % len(names)})

        # Deeply nested array names, e.g. a[b][b][b]... with 200 levels. Regular
        # forms use fewer than five levels.
        for name in names:
            depth = name.count(b"[")
            if depth > rules["max_field_nesting"]:
                findings.append({"rule": "deep_nested_field_name",
                                 "detail": "field name with %d levels" % depth})

        # Many fields with the same array name, as sent by a published PoC
        # (149 parts named "t[]"). The purpose of these fields is unverified.
        counts = Counter(name for name in names if name.endswith(b"[]"))
        if counts:
            top_name, top_count = counts.most_common(1)[0]
            if top_count >= rules["max_same_array_fields"]:
                findings.append({"rule": "array_spray",
                                 "detail": "%d fields named '%s'" % (top_count, short(top_name))})

    # Large bodies, except on paths where large uploads are expected.
    if len(body) >= rules["large_body_bytes"]:
        path = req["path"]
        if not any(path.startswith(prefix) for prefix in rules["large_body_ignore_paths"]):
            findings.append({"rule": "large_body",
                             "detail": "%d bytes to %s" % (len(body), path.split("?")[0])})

    # Probe of a published screening tool that checks for CVE-2026-109618 by
    # memory exhaustion: empty boundary together with a large body or deeply
    # nested field names. Matches even if the default User-Agent was replaced.
    rules_hit = {f["rule"] for f in findings}
    if "empty_boundary" in rules_hit and rules_hit.intersection(("large_body", "deep_nested_field_name")):
        findings.append({"rule": "empty_boundary_probe",
                         "detail": "empty boundary with %s" % ", ".join(sorted(
                             rules_hit.intersection(("large_body", "deep_nested_field_name"))))})

    # Merge repeated matches of the same rule (for example many NUL bytes).
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
        # (ip, sha256) -> file name; the same body from the same IP is stored only once
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
        """Returns the file name without extension and whether the request was a repeat."""
        sha = hashlib.sha256(req["body"]).hexdigest()
        key = (req["ip"], sha)
        if key in self.seen:
            return self.seen[key], True

        ts = datetime.datetime.fromtimestamp(req["time"]).strftime("%Y-%m-%d_%H-%M-%S")
        ip_safe = re.sub(r"[^0-9A-Za-z.]", "-", req["ip"])
        level = request_level(findings)
        base = "%s_%s_%s_%s" % (ts, level, ip_safe, sha[:10])

        # Request as forwarded by nginx: request line, headers, empty line and
        # the unmodified body.
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
            self.log.write("WARNING capture limit of %d MB reached, only .json files are written from now on"
                           % (self.max_total_bytes // 1048576))
            self.limit_warned = True

        self._write(os.path.join(self.dir, base + ".json"),
                    json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8"))

        self.seen[key] = base
        if len(self.seen) > 10000:
            self.seen.popitem(last=False)
        return base, False


# ---------------------------------------------------------------------------
# Email notification (optional)
# ---------------------------------------------------------------------------

# Order of the request levels, used for the minimum level of emails and of the
# hook.
LEVEL_ORDER = ("generic", "php2shell", "php2shell-chain")


class Mailer:
    def __init__(self, to, sender, min_level, min_interval, log):
        self.to = to
        self.sender = sender
        self.min_level = LEVEL_ORDER.index(min_level)
        self.min_interval = min_interval
        self.log = log
        self.last_by_ip = {}

    def notify(self, req, findings, capture_name):
        if not self.to:
            return
        # Checked before the interval, so that a request below the minimum
        # level does not suppress the email of a following request.
        if LEVEL_ORDER.index(request_level(findings)) < self.min_level:
            return
        now = time.time()
        if now - self.last_by_ip.get(req["ip"], 0) < self.min_interval:
            return
        self.last_by_ip[req["ip"]] = now

        lines = [
            "A POST request matched the PHP2Shell detection rules.",
            "",
            "Time:  %s" % datetime.datetime.fromtimestamp(req["time"]).isoformat(),
            "IP:    %s" % req["ip"],
            "URL:   %s%s" % (req["host"], req["path"]),
            "Size:  %d bytes" % len(req["body"]),
            "File:  %s" % capture_name,
            "",
            "Matched rules:",
        ] + ["  - %s (%s): %s" % (f["rule"], f["level"], f["detail"]) for f in findings] + [
            "",
            "Further requests from this IP within %d minutes are only logged."
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
            self.log.write("ERROR sending email failed: %s" % e)


# ---------------------------------------------------------------------------
# Hook command (optional)
# ---------------------------------------------------------------------------


class Hook:
    """
    Runs a command for each suspicious request, for example to block the IP
    address in the firewall.

    The request data is controlled by the attacker. It is therefore never
    inserted into the command line: the command is started without a shell,
    and the event (the same JSON object as in the event log) is passed on
    stdin. The commands run in a separate thread, so that a slow command does
    not delay the inspection of further requests.
    """

    def __init__(self, command, min_level, timeout, min_interval, queue_size, log):
        self.command = command
        self.min_level = LEVEL_ORDER.index(min_level)
        self.timeout = timeout
        self.min_interval = min_interval
        self.log = log
        self.last_by_ip = {}
        self.queue = queue.Queue(maxsize=queue_size)
        self.dropped_warned = False
        if self.command:
            threading.Thread(target=self._run_loop, daemon=True).start()

    def notify(self, req, findings, capture_name, repeat):
        if not self.command:
            return
        level = request_level(findings)
        if LEVEL_ORDER.index(level) < self.min_level:
            return
        # nginx sets the IP address ($remote_addr). It is checked anyway,
        # because hook scripts typically pass it on to other programs.
        try:
            ipaddress.ip_address(req["ip"])
        except ValueError:
            self.log.write("WARNING hook skipped, invalid IP address %r" % req["ip"][:60])
            return
        # Repeats are not skipped, so that an IP address that is blocked for
        # a limited time is blocked again if it sends the same request later.
        # min_interval limits the number of commands per IP.
        now = time.time()
        if now - self.last_by_ip.get(req["ip"], 0) < self.min_interval:
            return
        self.last_by_ip[req["ip"]] = now
        if len(self.last_by_ip) > 10000:
            self.last_by_ip = {ip: t for ip, t in self.last_by_ip.items() if now - t < self.min_interval}

        event = json.dumps(event_dict(req, findings, capture_name, repeat), ensure_ascii=False)
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            if not self.dropped_warned:
                self.log.write("WARNING hook queue full, hook commands are dropped")
                self.dropped_warned = True

    def _run_loop(self):
        while True:
            event = self.queue.get()
            ip = json.loads(event)["ip"]
            try:
                result = subprocess.run(self.command, input=(event + "\n").encode("utf-8"),
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        timeout=self.timeout)
                output = result.stdout.decode("utf-8", "replace").strip()[:500]
                if result.returncode != 0:
                    self.log.write("ERROR hook for %s exited with code %d: %s" % (ip, result.returncode, output))
                elif output:
                    self.log.write("HOOK %s: %s" % (ip, output))
            except subprocess.TimeoutExpired:
                self.log.write("ERROR hook for %s timed out after %d seconds" % (ip, self.timeout))
            except Exception as e:
                self.log.write("ERROR hook for %s failed: %s" % (ip, e))


# ---------------------------------------------------------------------------
# HTTP server for the mirrored requests
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.posts = 0
        self.suspicious = 0
        self.level_php2shell_chain = 0
        self.level_php2shell = 0
        self.level_generic = 0
        self.saved = 0
        self.duplicates = 0
        self.dropped = 0

    def inc(self, name):
        # Level names contain a hyphen (php2shell-chain); map it to the attribute name.
        name = name.replace("-", "_")
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
        # Disable the default request log
        pass

    def _respond(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        # nginx only forwards POST requests (see php2shell-mirror.conf). Other
        # methods are ignored.
        self._respond()

    do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_GET

    def do_POST(self):
        received = time.time()
        length = int(self.headers.get("Content-Length") or 0)

        # Read the complete body before responding. nginx sends the complete body
        # in any case.
        body = self.rfile.read(min(length, self.max_body_bytes))
        rest = length - len(body)
        while rest > 0:
            chunk = self.rfile.read(min(rest, 65536))
            if not chunk:
                break
            rest -= len(chunk)

        # Respond immediately. The worker thread inspects the request.
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
            "user_agent": self.headers.get("User-Agent", ""),
            "transfer_encoding": self.headers.get("X-Php2shell-Transfer-Encoding", ""),
            "headers": list(self.headers.items()),
            "body": body,
            "truncated": length > len(body),
        }
        try:
            self.work_queue.put_nowait(req)
        except queue.Full:
            self.stats.inc("dropped")


def worker(work_queue, rules, store, mailer, hook, events, stats, log):
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
            events.write(req, findings, name, duplicate)
            hook.notify(req, findings, name, duplicate)
            summary = ", ".join(
                "%s%s" % (f["rule"], " x%d" % f["count"] if f["count"] > 1 else "") for f in findings)
            if duplicate:
                stats.inc("duplicates")
                log.write("HIT %s %s %s%s %s -> repeat of %s"
                          % (level, req["ip"], req["host"], req["path"], summary, name))
            else:
                stats.inc("saved")
                log.write("HIT %s %s %s%s %d bytes [%s] -> %s"
                          % (level, req["ip"], req["host"], req["path"], len(req["body"]), summary, name))
                for f in findings:
                    log.write("    %s (%s): %s" % (f["rule"], f["level"], f["detail"]))
                mailer.notify(req, findings, name)
        except Exception as e:
            log.write("ERROR inspecting %s %s: %r" % (req.get("ip"), req.get("path"), e))


def stats_loop(interval, stats, work_queue, log):
    while True:
        time.sleep(interval)
        log.write("STATUS %d POST requests checked, %d suspicious (%d php2shell-chain, %d php2shell, "
                  "%d generic), %d stored, %d repeats, %d dropped (queue full), %d queued"
                  % (stats.posts, stats.suspicious, stats.level_php2shell_chain, stats.level_php2shell,
                     stats.level_generic, stats.saved, stats.duplicates, stats.dropped, work_queue.qsize()))


def main():
    parser = argparse.ArgumentParser(description="Detects PHP2Shell exploitation attempts in POST requests mirrored by nginx")
    parser.add_argument("-c", "--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config, encoding="utf-8"):
        sys.exit("Config file not found: %s (copy config.example.ini to config.ini first)" % args.config)

    log = Log(cfg.get("log", "file", fallback="").strip())
    events = EventLog(cfg.get("log", "events_file", fallback="").strip())

    rules = {
        "max_field_name_length": cfg.getint("rules", "max_field_name_length"),
        "max_fields": cfg.getint("rules", "max_fields"),
        "large_body_bytes": cfg.getint("rules", "large_body_bytes"),
        "large_body_ignore_paths": [p.strip() for p in cfg.get("rules", "large_body_ignore_paths").split(",") if p.strip()],
        "upload_progress_marker": cfg.get("rules", "upload_progress_marker").strip(),
        # Options added after the first release have defaults, so that older
        # config.ini files keep working.
        "session_name": cfg.get("rules", "session_name", fallback="PHPSESSID").strip(),
        "max_part_headers": cfg.getint("rules", "max_part_headers", fallback=10),
        "max_filename_length": cfg.getint("rules", "max_filename_length", fallback=1024),
        "max_same_array_fields": cfg.getint("rules", "max_same_array_fields", fallback=100),
        "tool_markers": [m.strip() for m in cfg.get(
            "rules", "tool_markers",
            fallback="JACKALPOC, B7kQpoc, p2s-rider, neosc4n, neo_obj_inject, sf618_, xqsuvwz3n97wu8j3emz1axuo5y"
        ).split(",") if m.strip()],
        "tool_content_type_markers": [m.strip() for m in cfg.get(
            "rules", "tool_content_type_markers",
            fallback="p2sBoundary, p2shell, p2s9rdme2st6guc9g0rafic, SCANBOUND, WRITEBOUND, NeoMM2026, "
                     "BNDRY12345, BGCTXBOUNDARY, CHKBND"
        ).split(",") if m.strip()],
        "max_field_nesting": cfg.getint("rules", "max_field_nesting", fallback=32),
    }
    tool_ua = cfg.get("rules", "tool_user_agent_regex", fallback="php2shell|^B8RAT/").strip()
    rules["tool_user_agent_re"] = re.compile(tool_ua, re.IGNORECASE) if tool_ua else None
    tool_filename = cfg.get(
        "rules", "tool_filename_regex",
        fallback=r"^MARKER_[0-9a-f]{8}|^___PHP2SHELL_PROBE_[0-9a-f]{8}___$").strip()
    rules["tool_filename_re"] = re.compile(tool_filename.encode(), re.IGNORECASE) if tool_filename else None
    suspicious_filename = cfg.get("rules", "suspicious_filename_regex",
                                  fallback=r"^(p2s|probe|[atx])\.txt$").strip()
    rules["suspicious_filename_re"] = re.compile(suspicious_filename.encode(), re.IGNORECASE) \
        if suspicious_filename else None
    scanner_ua = cfg.get("rules", "scanner_user_agent_regex",
                         fallback="Company-PHP-Audit|trap-test-rev|php-cve-version-check").strip()
    rules["scanner_user_agent_re"] = re.compile(scanner_ua, re.IGNORECASE) if scanner_ua else None
    rules["other_content_type_markers"] = [
        m.strip() for m in cfg.get("rules", "other_content_type_markers",
                                   fallback="wp2shell, php2shell-golang").split(",") if m.strip()]

    store = CaptureStore(cfg.get("capture", "dir"), cfg.getint("capture", "max_total_mb") * 1048576, log)
    mail_level = cfg.get("mail", "min_level", fallback="php2shell").strip()
    if mail_level not in LEVEL_ORDER:
        sys.exit("Invalid [mail] min_level: %s (allowed: %s)" % (mail_level, ", ".join(LEVEL_ORDER)))
    mailer = Mailer(cfg.get("mail", "to", fallback="").strip(), cfg.get("mail", "from").strip(),
                    mail_level, cfg.getint("mail", "min_interval"), log)
    # The [hook] section is optional, so that older config.ini files keep working.
    hook_level = cfg.get("hook", "min_level", fallback="php2shell").strip()
    if hook_level not in LEVEL_ORDER:
        sys.exit("Invalid [hook] min_level: %s (allowed: %s)" % (hook_level, ", ".join(LEVEL_ORDER)))
    hook = Hook(shlex.split(cfg.get("hook", "command", fallback="")), hook_level,
                cfg.getint("hook", "timeout", fallback=30), cfg.getint("hook", "min_interval", fallback=300),
                cfg.getint("hook", "queue_size", fallback=100), log)
    stats = Stats()
    work_queue = queue.Queue(maxsize=cfg.getint("server", "queue_size"))

    MirrorHandler.work_queue = work_queue
    MirrorHandler.max_body_bytes = cfg.getint("server", "max_body_bytes")
    MirrorHandler.stats = stats

    host = cfg.get("server", "listen_host")
    port = cfg.getint("server", "listen_port")
    http.server.ThreadingHTTPServer.daemon_threads = True
    server = http.server.ThreadingHTTPServer((host, port), MirrorHandler)

    threading.Thread(target=worker, args=(work_queue, rules, store, mailer, hook, events, stats, log), daemon=True).start()
    interval = cfg.getint("log", "stats_interval")
    if interval > 0:
        threading.Thread(target=stats_loop, args=(interval, stats, work_queue, log), daemon=True).start()

    # Stop reason for the STOP line. SIGTERM (for example from systemd) and
    # SIGHUP (terminal closed) shut down the daemon like Ctrl+C.
    stop_reason = ["serve_forever returned"]

    def on_signal(signum, _frame):
        stop_reason[0] = "signal %s" % signal.Signals(signum).name
        threading.Thread(target=server.shutdown).start()

    signal.signal(signal.SIGTERM, on_signal)
    if hasattr(signal, "SIGHUP"):  # not available on Windows
        signal.signal(signal.SIGHUP, on_signal)

    log.write("START listening on %s:%d, captures in %s (%d MB used), email to: %s, hook: %s"
              % (host, port, store.dir, store.total_bytes // 1048576, mailer.to or "-",
                 " ".join(hook.command) if hook.command else "-"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_reason[0] = "Ctrl+C (SIGINT)"
    server.server_close()
    log.write("STOP (%s), %d POST requests checked, %d suspicious, %d stored"
              % (stop_reason[0], stats.posts, stats.suspicious, stats.saved))


if __name__ == "__main__":
    main()
