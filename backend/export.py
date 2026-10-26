def _action_target(action):
    return {"ALLOW": "ACCEPT", "DENY": "DROP", "REJECT": "REJECT"}[action]


def _chain(direction):
    return {"IN": "INPUT", "OUT": "OUTPUT", "FORWARD": "FORWARD"}[direction]


def _protocol_variants(rule):
    if rule["protocol"] == "ANY" and rule["dst_port"] != "any":
        return ("TCP", "UDP")
    return (rule["protocol"],)


def iptables_lines(rule):
    lines = []
    for protocol in _protocol_variants(rule):
        lines.append(_iptables_line(rule, protocol))
    return lines


def _iptables_line(rule, protocol):
    parts = ["iptables", "-A", _chain(rule["direction"])]
    if protocol != "ANY":
        parts.extend(["-p", protocol.lower()])
    if rule["interface"] != "any":
        parts.extend(["-o" if rule["direction"] == "OUT" else "-i", rule["interface"]])
    if rule["src_cidr"] != "0.0.0.0/0":
        parts.extend(["-s", rule["src_cidr"]])
    if rule["dst_cidr"] != "0.0.0.0/0":
        parts.extend(["-d", rule["dst_cidr"]])
    if protocol in ("TCP", "UDP") and rule["dst_port"] != "any":
        parts.extend(["--dport", rule["dst_port"].replace("-", ":")])
    parts.extend(["-j", _action_target(rule["action"])])
    return " ".join(parts)


def nftables_lines(rule):
    lines = []
    for protocol in _protocol_variants(rule):
        lines.append(_nftables_line(rule, protocol))
    return lines


def _nftables_line(rule, protocol):
    parts = ["nft", "add", "rule", "ip", "filter", _chain(rule["direction"])]
    if rule["interface"] != "any":
        parts.extend(
            ["oifname" if rule["direction"] == "OUT" else "iifname", f'"{rule["interface"]}"']
        )
    if rule["src_cidr"] != "0.0.0.0/0":
        parts.extend(["ip", "saddr", rule["src_cidr"]])
    if rule["dst_cidr"] != "0.0.0.0/0":
        parts.extend(["ip", "daddr", rule["dst_cidr"]])
    if protocol in ("TCP", "UDP"):
        parts.append(protocol.lower())
        if rule["dst_port"] != "any":
            parts.extend(["dport", rule["dst_port"]])
    elif protocol == "ICMP":
        parts.extend(["ip", "protocol", "icmp"])
    parts.append({"ALLOW": "accept", "DENY": "drop", "REJECT": "reject"}[rule["action"]])
    return " ".join(parts)


def export_rules(rules, output_format):
    enabled = sorted((rule for rule in rules if rule["enabled"]), key=lambda item: item["position"])
    renderer = {"iptables": iptables_lines, "nftables": nftables_lines}[output_format]
    lines = [line for rule in enabled for line in renderer(rule)]
    return "\n".join(lines) + ("\n" if lines else "")
