#!/usr/bin/env python3
"""
Sends test requests to the monitor, the way nginx would mirror them, or to a
site through nginx.

The "suspicious" requests only mimic the shape of the known attacks (overlong
field name, field without a name containing NUL bytes, upload progress field).
They contain no exploit.

Usage:
    python3 test_requests.py                                # monitor directly
    python3 test_requests.py --url https://example.com      # through nginx

Expected: the first two requests stay silent, all others produce a HIT
("too many fields" as generic, the others as php2shell), the last one as a
repetition. Through nginx, the IP in the HIT must be your real one, not the
test IP from this script - nginx overwrites the header.
"""

import argparse
import http.client
import urllib.parse

BOUNDARY = "----php2shelltest"


def multipart(fields):
    body = b""
    for name, value in fields:
        body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n" % (BOUNDARY, name)).encode()
        body += value + b"\r\n"
    return body + ("--%s--\r\n" % BOUNDARY).encode()


def long_field_name_body():
    # Shape as described in the public analyses: field without a name with a binary
    # value, a=1, then a ~3.5 MB field name ending in [x]=1. Filler is arbitrary.
    return b"=" + urllib.parse.quote_from_bytes(b"\x00\x01\x02\xff" * 16).encode() \
        + b"&a=1&" + b"A" * 3500000 + b"[x]=1"


TESTS = [
    ("clean: login", "/login", "application/x-www-form-urlencoded",
     b"username=test%40example.org&password=secret&redirect=%2F", "10.0.0.1"),
    ("clean: contact form multipart", "/contact", "multipart/form-data; boundary=" + BOUNDARY,
     multipart([("email", b"test@example.org"), ("comment", b"Hello")]), "10.0.0.1"),
    ("overlong field name + nameless field with NUL bytes", "/", "application/x-www-form-urlencoded",
     long_field_name_body(), "203.0.113.7"),
    ("upload progress field", "/login", "multipart/form-data; boundary=" + BOUNDARY,
     multipart([("PHP_SESSION_UPLOAD_PROGRESS", b"x" * 64), ("file", b"y" * 128)]), "2001:db8::7"),
    ("too many fields", "/cart", "application/x-www-form-urlencoded",
     "&".join("f%d=1" % i for i in range(1500)).encode(), "198.51.100.9"),
    ("repetition of the upload progress request", "/login", "multipart/form-data; boundary=" + BOUNDARY,
     multipart([("PHP_SESSION_UPLOAD_PROGRESS", b"x" * 64), ("file", b"y" * 128)]), "2001:db8::7"),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:9777",
                        help="monitor directly (default) or a site through nginx, e.g. https://example.com")
    args = parser.parse_args()
    target = urllib.parse.urlparse(args.url)

    for title, path, content_type, body, ip in TESTS:
        if target.scheme == "https":
            conn = http.client.HTTPSConnection(target.hostname, target.port or 443, timeout=30)
        else:
            conn = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=30)
        conn.request("POST", path, body=body, headers={
            "Host": target.netloc,
            "Content-Type": content_type,
            "Cookie": "PHPSESSID=testsession",
            "User-Agent": "nginx-php2shell-monitor-test",
            "X-Php2shell-Client-Ip": ip,
            "X-Php2shell-Request-Id": "test",
        })
        status = conn.getresponse().status
        conn.close()
        print("%-55s %8d bytes -> HTTP %d" % (title, len(body), status))


if __name__ == "__main__":
    main()
