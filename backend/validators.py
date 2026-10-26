import ipaddress
import re


ACTIONS = {"ALLOW", "DENY", "REJECT"}
DIRECTIONS = {"IN", "OUT", "FORWARD"}
PROTOCOLS = {"TCP", "UDP", "ICMP", "ANY"}
PORT_PATTERN = re.compile(r"^(\d+)(?:-(\d+))?$")
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def validate_rule(data):
    errors = {}
    required = ("name", "action", "direction", "protocol", "src_cidr", "dst_cidr")
    for field in required:
        if not isinstance(data.get(field), str) or not data[field].strip():
            errors[field] = "This field is required."

    for field in ("src_cidr", "dst_cidr"):
        value = data.get(field)
        if isinstance(value, str) and value.strip():
            try:
                ipaddress.IPv4Network(value.strip(), strict=False)
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                errors[field] = "Enter a valid IPv4 address or CIDR, such as 192.168.1.0/24."

    for field, allowed in (
        ("action", ACTIONS),
        ("direction", DIRECTIONS),
        ("protocol", PROTOCOLS),
    ):
        value = data.get(field)
        if isinstance(value, str) and value.strip() and value.strip().upper() not in allowed:
            errors[field] = f"Choose one of: {', '.join(sorted(allowed))}."

    protocol = str(data.get("protocol", "")).strip().upper()
    port = data.get("dst_port", "any")
    if not isinstance(port, str):
        errors["dst_port"] = 'Use "any", a port (443), or a range (8000-8080).'
    elif protocol == "ICMP" and port.strip().lower() != "any":
        errors["dst_port"] = "ICMP rules do not use destination ports."
    elif port.strip().lower() != "any":
        match = PORT_PATTERN.fullmatch(port.strip())
        if not match:
            errors["dst_port"] = 'Use "any", a port (443), or a range (8000-8080).'
        else:
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if not 1 <= start <= 65535 or not 1 <= end <= 65535:
                errors["dst_port"] = "Ports must be between 1 and 65535."
            elif start > end:
                errors["dst_port"] = "The first port must be less than or equal to the last port."

    name = data.get("name")
    if isinstance(name, str) and len(name.strip()) > 100:
        errors["name"] = "Name must be 100 characters or fewer."
    interface = data.get("interface", "any")
    if not isinstance(interface, str) or (
        interface.strip().lower() != "any" and not INTERFACE_PATTERN.fullmatch(interface.strip())
    ):
        errors["interface"] = "Use any or a Linux interface name (1-15 letters, numbers, . _ : or -)."
    comment = data.get("comment", "")
    if not isinstance(comment, str) or len(comment) > 500:
        errors["comment"] = "Comment must be 500 characters or fewer."
    if "enabled" in data and type(data["enabled"]) is not bool:
        errors["enabled"] = "Enabled must be true or false."
    return errors


def validate_packet(data):
    errors = {}
    for field in ("src", "dst"):
        value = data.get(field)
        try:
            if not isinstance(value, str):
                raise ValueError
            ipaddress.IPv4Address(value.strip())
        except (ipaddress.AddressValueError, ValueError):
            errors[field] = "Enter a valid IPv4 address."
    protocol = data.get("proto")
    if not isinstance(protocol, str) or protocol.upper() not in PROTOCOLS - {"ANY"}:
        errors["proto"] = "Choose TCP, UDP, or ICMP."
    direction = data.get("direction")
    if not isinstance(direction, str) or direction.upper() not in DIRECTIONS:
        errors["direction"] = f"Choose one of: {', '.join(sorted(DIRECTIONS))}."
    port = data.get("port")
    if str(protocol).upper() == "ICMP":
        if port not in (None, "", "any"):
            errors["port"] = "ICMP packets do not use destination ports."
    elif isinstance(port, bool) or not str(port).isdigit() or not 1 <= int(port) <= 65535:
        errors["port"] = "Enter a destination port between 1 and 65535."
    return errors
