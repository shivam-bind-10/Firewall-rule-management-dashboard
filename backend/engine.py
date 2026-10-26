import ipaddress


def _port_matches(rule_port, packet_port):
    if rule_port == "any":
        return True
    port = int(packet_port)
    parts = rule_port.split("-", 1)
    start = int(parts[0])
    end = int(parts[1]) if len(parts) == 2 else start
    return start <= port <= end


def explain(rule, packet):
    if not rule["enabled"]:
        return "Rule is disabled."
    if rule["direction"] != packet["direction"]:
        return f"Direction differs ({rule['direction']} != {packet['direction']})."
    if rule["protocol"] not in ("ANY", packet["proto"]):
        return f"Protocol differs ({rule['protocol']} != {packet['proto']})."
    src_net = ipaddress.IPv4Network(rule["src_cidr"], strict=False)
    if ipaddress.IPv4Address(packet["src"]) not in src_net:
        return f"Source is outside {rule['src_cidr']}."
    dst_net = ipaddress.IPv4Network(rule["dst_cidr"], strict=False)
    if ipaddress.IPv4Address(packet["dst"]) not in dst_net:
        return f"Destination is outside {rule['dst_cidr']}."
    if rule["dst_port"] != "any":
        if packet["proto"] == "ICMP":
            return "ICMP packets do not have a destination port."
        if not _port_matches(rule["dst_port"], packet["port"]):
            return f"Port {packet['port']} is outside {rule['dst_port']}."
    return "All conditions matched."


def simulate(rules, packet):
    trace = []
    for rule in sorted(rules, key=lambda item: item["position"]):
        reason = explain(rule, packet)
        matched = reason == "All conditions matched."
        trace.append({
            "rule_id": rule["id"],
            "name": rule["name"],
            "position": rule["position"],
            "action": rule["action"],
            "matched": matched,
            "reason": reason,
        })
        if matched:
            return rule, trace
    return None, trace
