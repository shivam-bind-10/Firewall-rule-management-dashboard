import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from backend.db import connect, initialize_database
from backend.export import export_rules
from backend.seed import seed_database
from backend.engine import simulate
from backend.validators import validate_packet, validate_rule


ROOT = Path(__file__).resolve().parent
RULE_FIELDS = (
    "name", "action", "direction", "protocol", "src_cidr", "dst_cidr",
    "dst_port", "interface", "enabled", "comment",
)


def create_app(test_config=None):
    app = Flask(__name__, static_folder="frontend", static_url_path="")
    app.config.from_mapping(
        DATABASE=os.environ.get("FWDASH_DATABASE", str(ROOT / "instance" / "fwdash.sqlite")),
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)

    initialize_database(app.config["DATABASE"])
    connection = connect(app.config["DATABASE"])
    try:
        seed_database(connection)
        connection.commit()
    finally:
        connection.close()

    def database():
        return connect(app.config["DATABASE"])

    def json_error(message, status, errors=None):
        body = {"error": message}
        if errors:
            body["errors"] = errors
        return jsonify(body), status

    def normalized_rule(data):
        return {
            "name": data["name"].strip(),
            "action": data["action"].upper(),
            "direction": data["direction"].upper(),
            "protocol": data["protocol"].upper(),
            "src_cidr": data["src_cidr"].strip(),
            "dst_cidr": data["dst_cidr"].strip(),
            "dst_port": data.get("dst_port", "any").strip().lower(),
            "interface": (
                "any" if data.get("interface", "any").strip().lower() == "any"
                else data.get("interface", "any").strip()
            ),
            "enabled": int(data.get("enabled", True) is not False),
            "comment": data.get("comment", "").strip(),
        }

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/rules")
    def list_rules():
        connection = database()
        try:
            rules = connection.execute("SELECT * FROM rules ORDER BY position, id").fetchall()
            return jsonify([dict(rule) for rule in rules])
        finally:
            connection.close()

    @app.post("/api/rules")
    def create_rule():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error("Expected a JSON rule object.", 400)
        errors = validate_rule(data)
        if errors:
            return json_error("Rule validation failed.", 422, errors)
        rule = normalized_rule(data)
        connection = database()
        try:
            position = connection.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM rules").fetchone()[0]
            columns = ", ".join(("position",) + RULE_FIELDS)
            placeholders = ", ".join("?" for _ in range(len(RULE_FIELDS) + 1))
            cursor = connection.execute(
                f"INSERT INTO rules ({columns}) VALUES ({placeholders})",
                (position,) + tuple(rule[field] for field in RULE_FIELDS),
            )
            connection.commit()
            created = connection.execute("SELECT * FROM rules WHERE id = ?", (cursor.lastrowid,)).fetchone()
            return jsonify(dict(created)), 201
        finally:
            connection.close()

    @app.post("/api/rules/validate")
    def validate_rule_fields():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error("Expected a JSON rule object.", 400)
        errors = validate_rule(data)
        return jsonify({"valid": not errors, "errors": errors})

    @app.put("/api/rules/<int:rule_id>")
    def update_rule(rule_id):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error("Expected a JSON rule object.", 400)
        errors = validate_rule(data)
        if errors:
            return json_error("Rule validation failed.", 422, errors)
        rule = normalized_rule(data)
        connection = database()
        try:
            if connection.execute("SELECT 1 FROM rules WHERE id = ?", (rule_id,)).fetchone() is None:
                return json_error("Rule not found.", 404)
            assignments = ", ".join(f"{field} = ?" for field in RULE_FIELDS)
            connection.execute(
                f"UPDATE rules SET {assignments}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                tuple(rule[field] for field in RULE_FIELDS) + (rule_id,),
            )
            connection.commit()
            updated = connection.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
            return jsonify(dict(updated))
        finally:
            connection.close()

    @app.delete("/api/rules/<int:rule_id>")
    def delete_rule(rule_id):
        connection = database()
        try:
            existing = connection.execute(
                "SELECT position FROM rules WHERE id = ?", (rule_id,)
            ).fetchone()
            if existing is None:
                return json_error("Rule not found.", 404)
            connection.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
            connection.execute("UPDATE rules SET position = position - 1 WHERE position > ?", (existing["position"],))
            connection.commit()
            return jsonify({"deleted": rule_id})
        finally:
            connection.close()

    @app.post("/api/rules/reorder")
    def reorder_rules():
        rule_ids = request.get_json(silent=True)
        if not isinstance(rule_ids, list) or any(type(item) is not int for item in rule_ids):
            return json_error("Expected a JSON array of rule IDs.", 400)
        connection = database()
        try:
            current = [row["id"] for row in connection.execute("SELECT id FROM rules ORDER BY position, id")]
            if len(rule_ids) != len(set(rule_ids)) or set(rule_ids) != set(current):
                return json_error("Order must contain every current rule ID exactly once.", 422)
            connection.executemany(
                "UPDATE rules SET position = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                ((position, rule_id) for position, rule_id in enumerate(rule_ids, start=1)),
            )
            connection.commit()
            return jsonify({"ordered": rule_ids})
        finally:
            connection.close()

    @app.patch("/api/rules/<int:rule_id>/toggle")
    def toggle_rule(rule_id):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or ("enabled" in data and type(data["enabled"]) is not bool):
            return json_error("enabled must be a boolean.", 400)
        connection = database()
        try:
            row = connection.execute("SELECT enabled FROM rules WHERE id = ?", (rule_id,)).fetchone()
            if row is None:
                return json_error("Rule not found.", 404)
            enabled = int(data["enabled"]) if "enabled" in data else 1 - row["enabled"]
            connection.execute(
                "UPDATE rules SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (enabled, rule_id),
            )
            connection.commit()
            updated = connection.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
            return jsonify(dict(updated))
        finally:
            connection.close()

    @app.post("/api/simulate")
    def simulate_packet():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error("Expected a JSON packet object.", 400)
        errors = validate_packet(data)
        if errors:
            return json_error("Packet validation failed.", 422, errors)
        packet = {
            "src": data["src"].strip(),
            "dst": data["dst"].strip(),
            "port": int(data["port"]) if data.get("port") not in (None, "", "any") else None,
            "proto": data["proto"].upper(),
            "direction": data["direction"].upper(),
        }
        connection = database()
        try:
            rules = [dict(row) for row in connection.execute("SELECT * FROM rules ORDER BY position, id")]
            matched, trace = simulate(rules, packet)
            action = matched["action"] if matched else "DENY"
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            if matched:
                connection.execute("UPDATE rules SET hits = hits + 1 WHERE id = ?", (matched["id"],))
            connection.execute(
                """INSERT INTO logs
                   (timestamp, src, dst, port, proto, matched_rule_id, action)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    now, packet["src"], packet["dst"],
                    str(packet["port"]) if packet["port"] is not None else "n/a",
                    packet["proto"], matched["id"] if matched else None, action,
                ),
            )
            connection.commit()
            return jsonify({
                "action": action,
                "matched_rule": matched,
                "implicit_deny": matched is None,
                "trace": trace,
            })
        finally:
            connection.close()

    @app.get("/api/stats")
    def stats():
        connection = database()
        try:
            counts = connection.execute(
                """SELECT COUNT(*) AS total,
                          COALESCE(SUM(enabled), 0) AS active,
                          COALESCE(SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END), 0) AS allow,
                          COALESCE(SUM(CASE WHEN action IN ('DENY', 'REJECT') THEN 1 ELSE 0 END), 0) AS deny,
                          COALESCE(SUM(hits), 0) AS hits
                   FROM rules"""
            ).fetchone()
            blocked = connection.execute(
                """SELECT COUNT(*) FROM logs
                   WHERE action IN ('DENY', 'REJECT')
                     AND timestamp >= ?""",
                (datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat(),),
            ).fetchone()[0]
            top_rules = connection.execute(
                "SELECT id, name, action, hits FROM rules ORDER BY hits DESC, position LIMIT 8"
            ).fetchall()
            recent = connection.execute(
                """SELECT logs.*, rules.name AS rule_name FROM logs
                   LEFT JOIN rules ON rules.id = logs.matched_rule_id
                   ORDER BY timestamp DESC, id DESC LIMIT 8"""
            ).fetchall()
            return jsonify({
                **dict(counts),
                "blocked_today": blocked,
                "top_rules": [dict(row) for row in top_rules],
                "recent": [dict(row) for row in recent],
            })
        finally:
            connection.close()

    @app.get("/api/logs")
    def list_logs():
        limit = request.args.get("limit", default=100, type=int)
        limit = min(max(limit or 100, 1), 500)
        connection = database()
        try:
            rows = connection.execute(
                """SELECT logs.*, rules.name AS rule_name FROM logs
                   LEFT JOIN rules ON rules.id = logs.matched_rule_id
                   ORDER BY timestamp DESC, id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return jsonify([dict(row) for row in rows])
        finally:
            connection.close()

    @app.get("/api/export")
    def export():
        output_format = request.args.get("format", "iptables")
        if output_format not in ("iptables", "nftables"):
            return json_error("format must be iptables or nftables.", 400)
        connection = database()
        try:
            rules = [dict(row) for row in connection.execute("SELECT * FROM rules ORDER BY position, id")]
            return app.response_class(
                export_rules(rules, output_format),
                mimetype="text/plain",
                headers={"Content-Disposition": f'attachment; filename="fwdash-{output_format}.txt"'},
            )
        finally:
            connection.close()

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
