"""
LLM Gateway – main Flask application.
Provides:
  - OpenAI-compatible API  (/v1/chat/completions, /v1/models)
  - Admin REST API         (/api/admin/*)
  - Admin Web UI           (/)
"""

import os
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

import yaml
import jwt
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS

from database import Database
from gateway import LLMGateway, GatewayError
from filter_engine import FilterEngine


# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static")
CORS(app)

CONFIG_PATH = os.environ.get("GATEWAY_CONFIG", "config.yaml")

with open(CONFIG_PATH, "r") as fh:
    config = yaml.safe_load(fh)

db = Database(config.get("database", {}).get("path", "gateway.db"))
gw = LLMGateway(db, config)
fe = FilterEngine(db)

SECRET_KEY: str = config["admin"]["secret_key"]
ADMIN_HASH: str = config["admin"]["password_hash"]


# ── Auth helpers ──────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "No token"}), 401
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)

    return decorated


def _bearer_key() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""


# ── OpenAI-compatible API ─────────────────────────────────────────────────────

@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    client_key = _bearer_key()
    if not client_key:
        return _api_err("Authentication required", "auth_error", 401)

    key_record = db.get_api_key(client_key)
    if not key_record:
        return _api_err("Invalid API key", "auth_error", 401)
    if key_record["status"] != "active":
        return _api_err("API key is disabled", "auth_error", 403)
    if not db.check_rate_limit(key_record["id"], key_record["rpm_limit"]):
        return _api_err(
            f"Rate limit exceeded ({key_record['rpm_limit']} RPM)", "rate_limit_error", 429
        )

    body = request.get_json(silent=True)
    if not body:
        return _api_err("Request body must be valid JSON", "invalid_request_error", 400)

    model = body.get("model", "")
    if not model:
        return _api_err("Field 'model' is required", "invalid_request_error", 400)

    # ── Content Security Filter ───────────────────────────────────────────────
    messages = body.get("messages", [])
    filter_result = fe.check(messages, model)
    if filter_result:
        db.log_filter_event(
            key_id=key_record["id"],
            model=model,
            rule_name=filter_result.rule_name,
            action=filter_result.action,
            severity=filter_result.severity,
            matched_text=filter_result.matched_text,
        )
        if filter_result.blocked:
            db.log_request(
                key_id=key_record["id"], model=model, status=451,
                duration_ms=0, error_msg=f"Blocked by: {filter_result.rule_name}"
            )
            return _api_err(
                f"Request blocked by security policy: {filter_result.rule_name}. "
                f"Standard: {filter_result.standard}",
                "content_filter_error", 451
            )

    t0 = time.time()
    try:
        result = gw.route(model, body, key_record)
        duration_ms = int((time.time() - t0) * 1000)
        usage = result.get("usage", {})
        db.log_request(
            key_id=key_record["id"],
            model=model,
            status=200,
            duration_ms=duration_ms,
            tokens_in=usage.get("prompt_tokens", 0),
            tokens_out=usage.get("completion_tokens", 0),
        )
        return jsonify(result)

    except GatewayError as e:
        duration_ms = int((time.time() - t0) * 1000)
        db.log_request(
            key_id=key_record["id"],
            model=model,
            status=502,
            duration_ms=duration_ms,
            error_msg=str(e),
        )
        return _api_err(str(e), "gateway_error", 502)

    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        db.log_request(
            key_id=key_record["id"],
            model=model,
            status=500,
            duration_ms=duration_ms,
            error_msg=str(e),
        )
        return _api_err(f"Internal error: {e}", "server_error", 500)


@app.route("/v1/models", methods=["GET"])
def list_models():
    client_key = _bearer_key()
    if not client_key or not db.get_api_key(client_key):
        return _api_err("Unauthorized", "auth_error", 401)
    models = db.get_all_models()
    return jsonify(
        {
            "object": "list",
            "data": [
                {"id": m["model_id"], "object": "model", "owned_by": m["provider"]}
                for m in models
            ],
        }
    )


# ── Admin: Auth ───────────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if pw_hash != ADMIN_HASH:
        return jsonify({"error": "Invalid password"}), 401
    token = jwt.encode(
        {"sub": "admin", "exp": datetime.utcnow() + timedelta(hours=24)},
        SECRET_KEY,
        algorithm="HS256",
    )
    return jsonify({"token": token})


# ── Admin: Dashboard ──────────────────────────────────────────────────────────

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def get_stats():
    return jsonify(db.get_stats())


@app.route("/api/admin/logs", methods=["GET"])
@admin_required
def get_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    return jsonify(db.get_logs(limit, offset))


# ── Admin: API Keys ───────────────────────────────────────────────────────────

@app.route("/api/admin/keys", methods=["GET"])
@admin_required
def list_keys():
    return jsonify(db.list_api_keys())


@app.route("/api/admin/keys", methods=["POST"])
@admin_required
def create_key():
    data = request.get_json(silent=True) or {}
    name = data.get("name") or "Unnamed"
    rpm_limit = int(data.get("rpm_limit", 60))
    key = "sk-gw-" + secrets.token_urlsafe(32)
    db.create_api_key(key, name, rpm_limit)
    return jsonify({"key": key, "name": name}), 201


@app.route("/api/admin/keys/<int:key_id>", methods=["PUT"])
@admin_required
def update_key(key_id):
    data = request.get_json(silent=True) or {}
    db.update_api_key(key_id, data)
    return jsonify({"success": True})


@app.route("/api/admin/keys/<int:key_id>", methods=["DELETE"])
@admin_required
def delete_key(key_id):
    db.delete_api_key(key_id)
    return jsonify({"success": True})


# ── Admin: Providers ──────────────────────────────────────────────────────────

@app.route("/api/admin/providers", methods=["GET"])
@admin_required
def list_providers():
    return jsonify(db.list_providers())


@app.route("/api/admin/providers", methods=["POST"])
@admin_required
def create_provider():
    data = request.get_json(silent=True) or {}
    for required in ("name", "type", "base_url"):
        if not data.get(required):
            return jsonify({"error": f"Field '{required}' is required"}), 400
    db.create_provider(data)
    gw.reload_providers()
    return jsonify({"success": True}), 201


@app.route("/api/admin/providers/<int:provider_id>", methods=["PUT"])
@admin_required
def update_provider(provider_id):
    data = request.get_json(silent=True) or {}
    db.update_provider(provider_id, data)
    gw.reload_providers()
    return jsonify({"success": True})


@app.route("/api/admin/providers/<int:provider_id>", methods=["DELETE"])
@admin_required
def delete_provider(provider_id):
    db.delete_provider(provider_id)
    gw.reload_providers()
    return jsonify({"success": True})


# ── Admin: Routes ─────────────────────────────────────────────────────────────

@app.route("/api/admin/routes", methods=["GET"])
@admin_required
def list_routes():
    return jsonify(db.list_routes())


@app.route("/api/admin/routes", methods=["POST"])
@admin_required
def create_route():
    data = request.get_json(silent=True) or {}
    for required in ("model_id", "provider_id", "upstream_model"):
        if not data.get(required):
            return jsonify({"error": f"Field '{required}' is required"}), 400
    db.create_route(data)
    gw.reload_providers()
    return jsonify({"success": True}), 201


@app.route("/api/admin/routes/<int:route_id>", methods=["DELETE"])
@admin_required
def delete_route(route_id):
    db.delete_route(route_id)
    gw.reload_providers()
    return jsonify({"success": True})


# ── Admin: Filter Rules ───────────────────────────────────────────────────────

@app.route("/api/admin/filter/rules", methods=["GET"])
@admin_required
def list_filter_rules():
    return jsonify(db.list_filter_rules())


@app.route("/api/admin/filter/rules", methods=["POST"])
@admin_required
def create_filter_rule():
    data = request.get_json(silent=True) or {}
    for required in ("name", "category", "pattern"):
        if not data.get(required):
            return jsonify({"error": f"Field '{required}' is required"}), 400
    db.create_filter_rule(data)
    return jsonify({"success": True}), 201


@app.route("/api/admin/filter/rules/<int:rule_id>", methods=["PUT"])
@admin_required
def update_filter_rule(rule_id):
    data = request.get_json(silent=True) or {}
    db.update_filter_rule(rule_id, data)
    return jsonify({"success": True})


@app.route("/api/admin/filter/rules/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_filter_rule(rule_id):
    data = request.get_json(silent=True) or {}
    db.toggle_filter_rule(rule_id, bool(data.get("enabled", True)))
    return jsonify({"success": True})


@app.route("/api/admin/filter/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_filter_rule(rule_id):
    db.delete_filter_rule(rule_id)
    return jsonify({"success": True})


@app.route("/api/admin/filter/logs", methods=["GET"])
@admin_required
def get_filter_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    return jsonify(db.get_filter_logs(limit, offset))


@app.route("/api/admin/filter/stats", methods=["GET"])
@admin_required
def get_filter_stats():
    return jsonify(db.get_filter_stats())


# ── Static / SPA ──────────────────────────────────────────────────────────────

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _api_err(message: str, error_type: str = "error", status: int = 400):
    return jsonify({"error": {"message": message, "type": error_type}}), status


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    srv = config.get("server", {})
    app.run(
        host=srv.get("host", "0.0.0.0"),
        port=srv.get("port", 8080),
        debug=srv.get("debug", False),
    )
