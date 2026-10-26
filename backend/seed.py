import random
from datetime import datetime, timedelta, timezone

from backend.engine import simulate


SEED_RULES = [
    ("Allow established web return", "ALLOW", "OUT", "TCP", "0.0.0.0/0", "0.0.0.0/0", "443", "any", "Outbound TLS responses"),
    ("Allow SSH from admin subnet", "ALLOW", "IN", "TCP", "192.168.10.0/24", "10.0.0.0/24", "22", "eth0", "Administrator access only"),
    ("Allow HTTPS from office", "ALLOW", "IN", "TCP", "10.0.0.0/16", "10.0.0.0/24", "443", "eth0", "Encrypted web traffic"),
    ("Allow HTTP from office", "ALLOW", "IN", "TCP", "10.0.0.0/16", "10.0.0.0/24", "80", "eth0", "Redirect handled by the web service"),
    ("Allow DNS queries", "ALLOW", "OUT", "UDP", "10.0.0.0/24", "0.0.0.0/0", "53", "any", "DNS resolver traffic"),
    ("Allow DNS over TCP", "ALLOW", "OUT", "TCP", "10.0.0.0/24", "0.0.0.0/0", "53", "any", "Large DNS responses"),
    ("Block Telnet", "DENY", "IN", "TCP", "0.0.0.0/0", "10.0.0.0/24", "23", "any", "Legacy plaintext service"),
    ("Block known-bad subnet", "REJECT", "IN", "ANY", "203.0.113.0/24", "0.0.0.0/0", "any", "any", "Documentation-range threat feed example"),
    ("Allow NTP", "ALLOW", "OUT", "UDP", "10.0.0.0/24", "0.0.0.0/0", "123", "any", "Time synchronization"),
    ("Allow monitoring agent", "ALLOW", "OUT", "TCP", "10.0.0.0/24", "192.0.2.0/24", "9090", "eth0", "Metrics collector"),
    ("Allow ICMP diagnostics", "ALLOW", "IN", "ICMP", "10.0.0.0/16", "10.0.0.0/24", "any", "any", "Internal network diagnostics"),
    ("Allow application pool", "ALLOW", "IN", "TCP", "10.0.0.0/16", "10.0.0.0/24", "8000-8080", "eth0", "Internal application services"),
    ("Reject direct database access", "REJECT", "IN", "TCP", "0.0.0.0/0", "10.0.0.0/24", "5432", "any", "Database access is restricted"),
    ("Allow loopback service", "ALLOW", "IN", "ANY", "127.0.0.0/8", "127.0.0.0/8", "any", "lo", "Local host traffic"),
    ("Default inbound deny", "DENY", "IN", "ANY", "0.0.0.0/0", "0.0.0.0/0", "any", "any", "Default inbound policy"),
]


def seed_database(connection):
    if connection.execute("SELECT COUNT(*) FROM rules").fetchone()[0]:
        return
    for position, values in enumerate(SEED_RULES, start=1):
        name, action, direction, protocol, src, dst, port, interface, comment = values
        connection.execute(
            """INSERT INTO rules
               (position, name, action, direction, protocol, src_cidr, dst_cidr,
                dst_port, interface, enabled, comment)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
            (position, name, action, direction, protocol, src, dst, port, interface, comment),
        )

    rules = [dict(row) for row in connection.execute("SELECT * FROM rules ORDER BY position")]
    randomizer = random.Random(42)
    now = datetime.now(timezone.utc)
    for index in range(200):
        packet = {
            "src": randomizer.choice([
                "10.0.1.25", "10.0.2.18", "192.168.10.44", "203.0.113.7",
                "198.51.100.62", "10.0.0.53", "127.0.0.1",
            ]),
            "dst": randomizer.choice(["10.0.0.10", "10.0.0.20", "192.0.2.15"]),
            "port": randomizer.choice([22, 23, 53, 80, 123, 443, 5432, 8080, 9090]),
            "proto": randomizer.choice(["TCP", "TCP", "UDP", "ICMP"]),
            "direction": randomizer.choice(["IN", "IN", "OUT", "FORWARD"]),
        }
        if packet["proto"] == "ICMP":
            packet["port"] = None
        matched, _ = simulate(rules, packet)
        action = matched["action"] if matched else "DENY"
        timestamp = now - timedelta(minutes=randomizer.randint(0, 24 * 60))
        connection.execute(
            """INSERT INTO logs (timestamp, src, dst, port, proto, matched_rule_id, action)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp.isoformat(timespec="seconds"),
                packet["src"],
                packet["dst"],
                str(packet["port"]) if packet["port"] is not None else "n/a",
                packet["proto"],
                matched["id"] if matched else None,
                action,
            ),
        )
        if matched:
            connection.execute(
                "UPDATE rules SET hits = hits + 1 WHERE id = ?", (matched["id"],)
            )
