#!/usr/bin/env php
<?php
/*
 * Example hook for nginx-php2shell-monitor: blocks the IP address of a
 * suspicious request with nftables. Same function as php2shell-ban.py.
 *
 * The monitor passes the event as one JSON object on stdin (see README,
 * section "Hook"). The script adds the IP address to the set blocked4 or
 * blocked6 of the table "inet php2shell" (see php2shell-nftables.conf). The
 * entry expires after BAN_TIMEOUT.
 *
 * Requires the PHP CLI 7.4 or later. The script needs root privileges for nft.
 * Install it so that the monitor user can run it with sudo, but cannot change it:
 *
 *     sudo install -o root -g root -m 0755 hooks/php2shell-ban.php /usr/local/sbin/php2shell-ban
 *
 * The event is controlled by the attacker. The script therefore only uses the
 * IP address, checks it with filter_var and calls nft with an argument array,
 * without a shell.
 */

// Duration of the block, in nft notation (for example 1h, 24h, 7d).
const BAN_TIMEOUT = '24h';

// Networks that are never blocked. Add the addresses of your own servers,
// monitoring and office here.
const ALLOWLIST = [
    '127.0.0.0/8',
    '::1/128',
];

const NFT = '/usr/sbin/nft';

// Returns true if $ip is in the network $cidr (IPv4 or IPv6).
function ip_in_network(string $ip, string $cidr): bool
{
    [$net, $bits] = explode('/', $cidr, 2);
    $ip_bin = inet_pton($ip);
    $net_bin = inet_pton($net);
    if ($ip_bin === false || $net_bin === false || strlen($ip_bin) !== strlen($net_bin)) {
        return false;
    }
    $bits = (int) $bits;
    $bytes = intdiv($bits, 8);
    if (substr($ip_bin, 0, $bytes) !== substr($net_bin, 0, $bytes)) {
        return false;
    }
    $rest = $bits % 8;
    if ($rest === 0) {
        return true;
    }
    $mask = (0xff << (8 - $rest)) & 0xff;
    return (ord($ip_bin[$bytes]) & $mask) === (ord($net_bin[$bytes]) & $mask);
}

$event = json_decode(stream_get_contents(STDIN), true);
$ip = is_array($event) && is_string($event['ip'] ?? null) ? filter_var($event['ip'], FILTER_VALIDATE_IP) : false;
if ($ip === false) {
    fwrite(STDERR, "invalid event\n");
    exit(1);
}

// IPv4-mapped IPv6 addresses (::ffff:203.0.113.7) are blocked as IPv4.
if (stripos($ip, '::ffff:') === 0 && filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    $ip = substr($ip, 7);
}

foreach (ALLOWLIST as $cidr) {
    if (ip_in_network($ip, $cidr)) {
        echo "$ip is on the allowlist, not blocked\n";
        exit(0);
    }
}

$set = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'blocked4' : 'blocked6';

// An array command is started without a shell. "add element" does not fail
// if the address is already in the set.
$process = proc_open(
    [NFT, 'add', 'element', 'inet', 'php2shell', $set, '{ ' . $ip . ' timeout ' . BAN_TIMEOUT . ' }'],
    [1 => ['pipe', 'w'], 2 => ['redirect', 1]],
    $pipes
);
if (!is_resource($process)) {
    fwrite(STDERR, "nft could not be started\n");
    exit(1);
}
$output = trim(stream_get_contents($pipes[1]));
fclose($pipes[1]);
if (proc_close($process) !== 0) {
    fwrite(STDERR, "nft failed: $output\n");
    exit(1);
}

printf("%s blocked for %s (level %s, rules %s)\n", $ip, BAN_TIMEOUT,
    $event['level'] ?? '?', $event['rules'] ?? '?');
exit(0);
