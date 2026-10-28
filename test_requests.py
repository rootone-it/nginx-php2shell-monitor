#!/usr/bin/env python3
"""
Sends test requests either directly to the monitor, in the same format as the
copies sent by nginx, or to a website through nginx.

The suspicious test requests have the structure of the known exploits (long
field name, field without a name containing NUL bytes, upload progress field).
They do not contain a working payload.

Usage:
    python3 test_requests.py                                # directly to the monitor
    python3 test_requests.py --url https://example.com      # through nginx

Expected result: the first two requests are not reported. All other requests
produce a HIT line ("too many fields" and "multipart with LF-only lines" with
the level generic, the others with the level php2shell). The last request is reported as a repeat. When the
requests are sent through nginx, the HIT lines show your own IP address and not
the IP address sent by this script, because nginx replaces the header.
"""

import argparse
import http.client
import urllib.parse

# Boundary and User-Agent must not contain "php2shell", because that is a
# configured tool marker.
BOUNDARY = "----selftestboundary7f3a"


def multipart(fields):
    body = b""
    for name, value in fields:
        body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n" % (BOUNDARY, name)).encode()
        body += value + b"\r\n"
    return body + ("--%s--\r\n" % BOUNDARY).encode()


def long_field_name_body():
    # Structure as described in the published analyses: a field without a name with
    # binary content, a=1 and a field name of about 3.5 MB ending in [x]=1. The
    # filler characters are arbitrary.
    return b"=" + urllib.parse.quote_from_bytes(b"\x00\x01\x02\xff" * 16).encode() \
        + b"&a=1&" + b"A" * 3500000 + b"[x]=1"


TESTS = [
    ("clean: login", "/login", "application/x-www-form-urlencoded",
     b"username=test%40example.org&password=secret&redirect=%2F", "10.0.0.1"),
    ("clean: contact form multipart", "/contact", "multipart/form-data; boundary=" + BOUNDARY,
     multipart([("email", b"test@example.org"), ("comment", b"Hello")]), "10.0.0.1"),
    ("long field name + field without name with NUL bytes", "/", "application/x-www-form-urlencoded",
     long_field_name_body(), "203.0.113.7"),
    ("upload progress field", "/login", "multipart/form-data; boundary=" + BOUNDARY,
     multipart([("PHP_SESSION_UPLOAD_PROGRESS", b"x" * 64), ("file", b"y" * 128)]), "2001:db8::7"),
    ("too many fields", "/cart", "application/x-www-form-urlencoded",
     "&".join("f%d=1" % i for i in range(1500)).encode(), "198.51.100.9"),
    ("multipart with LF-only lines, no form-data", "/contact", "multipart/form-data; boundary=" + BOUNDARY,
     ("--%s\nContent-Disposition:name=\"email\"\n\ntest@example.org\n--%s--\n" % (BOUNDARY, BOUNDARY)).encode(),
     "192.0.2.44"),
    ("upload progress field (repeat)", "/login", "multipart/form-data; boundary=" + BOUNDARY,
     multipart([("PHP_SESSION_UPLOAD_PROGRESS", b"x" * 64), ("file", b"y" * 128)]), "2001:db8::7"),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:9777",
                        help="target URL: the monitor (default) or a website behind nginx, for example https://example.com")
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
            "User-Agent": "nginx-monitor-selftest",
            "X-Php2shell-Client-Ip": ip,
            "X-Php2shell-Request-Id": "test",
        })
        status = conn.getresponse().status
        conn.close()
        print("%-55s %8d bytes -> HTTP %d" % (title, len(body), status))


if __name__ == "__main__":
    main()
