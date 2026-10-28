#!/usr/bin/env python3
"""
Example hook for nginx-php2shell-monitor: blocks the IP address of a
suspicious request with nftables.

The monitor passes the event as one JSON object on stdin (see README, section
"Hook"). The script adds the IP address to the set blocked4 or blocked6 of the
table "inet php2shell" (see php2shell-nftables.conf). The entry expires after
BAN_TIMEOUT.

The script needs root privileges for nft. Install it so that the monitor user
can run it with sudo, but cannot change it:

    sudo install -o root -g root -m 0755 hooks/php2shell-ban.py /usr/local/sbin/php2shell-ban

The event is controlled by the attacker. The script therefore only uses the
IP address, checks it with the ipaddress module and calls nft with an
argument list, without a shell.
"""

import ipaddress
import json
import subprocess
import sys

# Duration of the block, in nft notation (for example 1h, 24h, 7d).
BAN_TIMEOUT = "24h"

# Networks that are never blocked. Add the addresses of your own servers,
# monitoring and office here.
ALLOWLIST = [
    "127.0.0.0/8",
    "::1/128",
]

NFT = "/usr/sbin/nft"
TABLE = ("inet", "php2shell")


def main():
    try:
        event = json.loads(sys.stdin.read())
        ip = ipaddress.ip_address(event["ip"])
    except (ValueError, KeyError, TypeError) as e:
        print("invalid event: %s" % e, file=sys.stderr)
        return 1

    # IPv4-mapped IPv6 addresses (::ffff:203.0.113.7) are blocked as IPv4.
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if any(ip in ipaddress.ip_network(net) for net in ALLOWLIST):
        print("%s is on the allowlist, not blocked" % ip)
        return 0

    set_name = "blocked4" if ip.version == 4 else "blocked6"
    # "add element" does not fail if the address is already in the set.
    try:
        result = subprocess.run(
            [NFT, "add", "element", TABLE[0], TABLE[1], set_name,
             "{ %s timeout %s }" % (ip, BAN_TIMEOUT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        print("nft could not be run: %s" % e, file=sys.stderr)
        return 1
    if result.returncode != 0:
        print("nft failed: %s" % result.stdout.decode("utf-8", "replace").strip(), file=sys.stderr)
        return 1

    print("%s blocked for %s (level %s, rules %s)" % (ip, BAN_TIMEOUT, event.get("level"), event.get("rules")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
