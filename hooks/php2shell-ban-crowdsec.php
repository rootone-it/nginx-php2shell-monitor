#!/usr/bin/env php
<?php
/*
 * Example hook for nginx-php2shell-monitor: blocks the IP address of a
 * suspicious request with a CrowdSec decision. Same function as
 * php2shell-ban-crowdsec.py.
 *
 * The monitor passes the event as one JSON object on stdin (see README,
 * section "Hook"). The script adds a ban decision for the IP address with
 * cscli. All CrowdSec remediation components (firewall bouncer, nginx bouncer,
 * WAF) then block the address until the decision expires after BAN_DURATION.
 *
 * Requires the PHP CLI 7.4 or later. The script needs root privileges for
 * cscli. Install it so that the monitor user can run it with sudo, but cannot
 * change it:
 *
 *     sudo install -o root -g root -m 0755 hooks/php2shell-ban-crowdsec.php /usr/local/sbin/php2shell-ban
 *
 * The event is controlled by the attacker. The script therefore only uses the
 * IP address and the request level, checks both and calls cscli with an
 * argument array, without a shell.
 */

// Duration of the decision, in cscli notation (for example 4h, 24h, 168h).
const BAN_DURATION = '24h';

// Networks that are never blocked. Add the addresses of your own servers,
// monitoring and office here.
const ALLOWLIST = [
    '127.0.0.0/8',
    '::1/128',
];

const CSCLI = '/usr/bin/cscli';
const LEVELS = ['generic', 'php2shell', 'php2shell-chain'];

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
$level = in_array($event['level'] ?? null, LEVELS, true) ? $event['level'] : 'unknown';

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

// An array command is started without a shell.
$process = proc_open(
    [CSCLI, 'decisions', 'add', '--ip', $ip, '--duration', BAN_DURATION,
     '--type', 'ban', '--reason', 'nginx-php2shell-monitor: ' . $level],
    [1 => ['pipe', 'w'], 2 => ['redirect', 1]],
    $pipes
);
if (!is_resource($process)) {
    fwrite(STDERR, "cscli could not be started\n");
    exit(1);
}
$output = trim(stream_get_contents($pipes[1]));
fclose($pipes[1]);
if (proc_close($process) !== 0) {
    fwrite(STDERR, "cscli failed: $output\n");
    exit(1);
}

printf("%s blocked with CrowdSec for %s (level %s)\n", $ip, BAN_DURATION, $level);
exit(0);
