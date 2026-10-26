import tempfile
import unittest
from pathlib import Path

from app import create_app
from backend.validators import validate_packet, validate_rule


def rule_payload(**overrides):
    payload = {
        "name": "Test policy",
        "action": "ALLOW",
        "direction": "IN",
        "protocol": "TCP",
        "src_cidr": "192.168.1.0/24",
        "dst_cidr": "10.0.0.0/24",
        "dst_port": "443",
        "interface": "eth0",
        "enabled": True,
        "comment": "",
    }
    payload.update(overrides)
    return payload


class ValidatorTests(unittest.TestCase):
    def test_rejects_invalid_cidr(self):
        errors = validate_rule(rule_payload(src_cidr="999.2.3.4/99"))
        self.assertIn("src_cidr", errors)
        self.assertIn("valid IPv4", errors["src_cidr"])

    def test_rejects_zero_and_reversed_port_range(self):
        self.assertIn("between 1 and 65535", validate_rule(rule_payload(dst_port="0"))["dst_port"])
        self.assertIn("less than or equal", validate_rule(rule_payload(dst_port="8000-100"))["dst_port"])

    def test_rejects_port_for_icmp(self):
        self.assertIn("ICMP", validate_rule(rule_payload(protocol="ICMP", dst_port="53"))["dst_port"])

    def test_packet_requires_valid_ipv4_and_port(self):
        errors = validate_packet({
            "src": "bad", "dst": "10.0.0.1", "port": 0, "proto": "TCP", "direction": "IN",
        })
        self.assertIn("src", errors)
        self.assertIn("port", errors)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = str(Path(self.temp_dir.name) / "test.sqlite")
        self.app = create_app({"TESTING": True, "DATABASE": database})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def find_rule(self, name):
        return next(rule for rule in self.client.get("/api/rules").get_json() if rule["name"] == name)

    def test_seed_and_page_load_do_not_change_hit_counts(self):
        rules_before = self.client.get("/api/rules").get_json()
        self.assertEqual(len(rules_before), 15)
        self.assertEqual(len(self.client.get("/api/logs?limit=500").get_json()), 200)
        self.client.get("/").close()
        rules_after = self.client.get("/api/rules").get_json()
        self.assertEqual([r["hits"] for r in rules_before], [r["hits"] for r in rules_after])

    def test_rejects_invalid_rule_fields(self):
        response = self.client.post("/api/rules", json=rule_payload(dst_port="0"))
        self.assertEqual(response.status_code, 422)
        self.assertIn("dst_port", response.get_json()["errors"])

    def test_live_validation_does_not_save_rules(self):
        response = self.client.post("/api/rules/validate", json=rule_payload(src_cidr="invalid"))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["valid"])
        self.assertIn("src_cidr", response.get_json()["errors"])
        self.assertEqual(len(self.client.get("/api/rules").get_json()), 15)

    def test_reordering_and_disabling_change_simulator_decisions(self):
        packet = {"src": "192.168.10.44", "dst": "10.0.0.10", "port": 22, "proto": "TCP", "direction": "IN"}
        first = self.client.post("/api/simulate", json=packet).get_json()
        self.assertEqual(first["action"], "ALLOW")
        self.assertEqual(first["matched_rule"]["name"], "Allow SSH from admin subnet")

        default = self.find_rule("Default inbound deny")
        rules = self.client.get("/api/rules").get_json()
        ids = [rule["id"] for rule in rules]
        ids.remove(default["id"])
        ids.insert(0, default["id"])
        reordered = self.client.post("/api/rules/reorder", json=ids)
        self.assertEqual(reordered.status_code, 200)
        second = self.client.post("/api/simulate", json=packet).get_json()
        self.assertEqual(second["action"], "DENY")
        self.assertEqual(second["matched_rule"]["name"], "Default inbound deny")

        self.client.patch(f"/api/rules/{default['id']}/toggle", json={"enabled": False})
        third = self.client.post("/api/simulate", json=packet).get_json()
        self.assertFalse(third["trace"][0]["matched"])
        self.assertIn("disabled", third["trace"][0]["reason"])

    def test_implicit_deny_and_simulation_only_hits(self):
        before = self.client.get("/api/rules").get_json()
        packet = {"src": "198.51.100.1", "dst": "198.51.100.2", "port": 4444, "proto": "TCP", "direction": "FORWARD"}
        response = self.client.post("/api/simulate", json=packet)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["implicit_deny"])
        self.assertEqual(response.get_json()["action"], "DENY")
        after = self.client.get("/api/rules").get_json()
        self.assertEqual([r["hits"] for r in before], [r["hits"] for r in after])

    def test_successful_simulation_increments_only_the_matched_rule(self):
        ssh = self.find_rule("Allow SSH from admin subnet")
        before = ssh["hits"]
        packet = {"src": "192.168.10.44", "dst": "10.0.0.10", "port": 22, "proto": "TCP", "direction": "IN"}
        self.client.post("/api/simulate", json=packet)
        after = self.find_rule("Allow SSH from admin subnet")
        self.assertEqual(after["hits"], before + 1)

    def test_export_contains_only_enabled_syntax_and_no_commands_are_executed(self):
        rule = self.find_rule("Allow HTTPS from office")
        response = self.client.get("/api/export?format=iptables")
        self.assertIn(b"iptables -A INPUT -p tcp", response.data)
        self.assertIn(b"--dport 443 -j ACCEPT", response.data)
        self.assertIn(b"-i eth0 -s 10.0.0.0/16", response.data)
        self.assertIn(b"--dport 8000:8080", response.data)
        nft = self.client.get("/api/export?format=nftables")
        self.assertIn(b"nft add rule ip filter INPUT", nft.data)
        self.assertIn(b"tcp dport 443 accept", nft.data)
        self.client.patch(f"/api/rules/{rule['id']}/toggle", json={"enabled": False})
        self.assertNotIn(
            b"iptables -A INPUT -p tcp -s 10.0.0.0/16 -d 10.0.0.0/24 --dport 443 -j ACCEPT",
            self.client.get("/api/export?format=iptables").data,
        )
        self.assertEqual(self.client.get("/api/export?format=unknown").status_code, 400)

    def test_any_protocol_port_exports_valid_tcp_and_udp_rules(self):
        payload = rule_payload(
            name="Any transport port", protocol="ANY", dst_port="9000-9010", interface="any",
        )
        self.assertEqual(self.client.post("/api/rules", json=payload).status_code, 201)
        iptables = self.client.get("/api/export?format=iptables").get_data(as_text=True)
        self.assertIn(
            "iptables -A INPUT -p tcp -s 192.168.1.0/24 -d 10.0.0.0/24 --dport 9000:9010 -j ACCEPT",
            iptables,
        )
        self.assertIn(
            "iptables -A INPUT -p udp -s 192.168.1.0/24 -d 10.0.0.0/24 --dport 9000:9010 -j ACCEPT",
            iptables,
        )
        nftables = self.client.get("/api/export?format=nftables").get_data(as_text=True)
        self.assertIn("tcp dport 9000-9010 accept", nftables)
        self.assertIn("udp dport 9000-9010 accept", nftables)

    def test_rejects_unsafe_interface_text(self):
        errors = validate_rule(rule_payload(interface='eth0"; drop'))
        self.assertIn("interface", errors)

    def test_delete_all_rules_keeps_stats_and_export_healthy(self):
        for rule in self.client.get("/api/rules").get_json():
            self.assertEqual(self.client.delete(f"/api/rules/{rule['id']}").status_code, 200)
        stats = self.client.get("/api/stats").get_json()
        self.assertEqual((stats["total"], stats["active"], stats["hits"]), (0, 0, 0))
        self.assertEqual(self.client.get("/api/export").data, b"")
        result = self.client.post("/api/simulate", json={
            "src": "192.0.2.1", "dst": "198.51.100.1", "port": 443, "proto": "TCP", "direction": "IN",
        }).get_json()
        self.assertTrue(result["implicit_deny"])
        self.assertEqual(result["trace"], [])

    def test_reorder_requires_exact_permutation(self):
        response = self.client.post("/api/rules/reorder", json=[1, 1])
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
