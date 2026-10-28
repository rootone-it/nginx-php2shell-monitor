#!/usr/bin/env python3
"""
Example hook for nginx-php2shell-monitor: blocks the IP address of a
suspicious request with a CrowdSec decision.

The monitor passes the event as one JSON object on stdin (see README, section
"Hook"). The script adds a ban decision for the IP address with cscli. All
CrowdSec remediation components (firewall bouncer, nginx bouncer, WAF) then
block the address until the decision expires after BAN_DURATION.

The script needs root privileges for cscli. Install it so that the monitor
user can run it with sudo, but cannot change it:

    sudo install -o root -g root -m 0755 hooks/php2shell-ban-crowdsec.py /usr/local/sbin/php2shell-ban

The event is controlled by the attacker. The script therefore only uses the
IP address and the request level, checks both and calls cscli with an
argument list, without a shell.
"""

import ipaddress
import json
import subprocess
import sys

# Duration of the decision, in cscli notation (for example 4h, 24h, 168h).
BAN_DURATION = "24h"

# Networks that are never blocked. Add the addresses of your own servers,
# monitoring and office here.
ALLOWLIST = [
    "127.0.0.0/8",
    "::1/128",
]

CSCLI = "/usr/bin/cscli"
LEVELS = ("generic", "php2shell", "php2shell-chain")


def main():
    try:
        event = json.loads(sys.stdin.read())
        ip = ipaddress.ip_address(event["ip"])
    except (ValueError, KeyError, TypeError) as e:
        print("invalid event: %s" % e, file=sys.stderr)
        return 1
    level = event.get("level") if event.get("level") in LEVELS else "unknown"

    # IPv4-mapped IPv6 addresses (::ffff:203.0.113.7) are blocked as IPv4.
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if any(ip in ipaddress.ip_network(net) for net in ALLOWLIST):
        print("%s is on the allowlist, not blocked" % ip)
        return 0

    try:
        result = subprocess.run(
            [CSCLI, "decisions", "add", "--ip", str(ip), "--duration", BAN_DURATION,
             "--type", "ban", "--reason", "nginx-php2shell-monitor: %s" % level],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        print("cscli could not be run: %s" % e, file=sys.stderr)
        return 1
    if result.returncode != 0:
        print("cscli failed: %s" % result.stdout.decode("utf-8", "replace").strip(), file=sys.stderr)
        return 1

    print("%s blocked with CrowdSec for %s (level %s)" % (ip, BAN_DURATION, level))
    return 0


if __name__ == "__main__":
    sys.exit(main())
