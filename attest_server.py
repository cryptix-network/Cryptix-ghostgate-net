import os, base64, hmac, hashlib, time, re, threading
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax")

MEMBER_SECRET = os.getenv("MEMBER_SECRET", "dev-member-secret")

ID_RE = re.compile(r"^[A-Za-z0-9:\-]+$")
B64_STD = re.compile(r"^[A-Za-z0-9+/=]+$")

rate = {}
rlock = threading.Lock()

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sanitize_id(v: str):
    if not isinstance(v, str) or not ID_RE.fullmatch(v):
        raise ValueError("Invalid ID")
    return v

def sanitize_pubkey(v: str):
    if not isinstance(v, str) or not B64_STD.fullmatch(v):
        raise ValueError("Invalid pubkey format")
    try:
        if len(base64.b64decode(v, validate=True)) != 32:
            raise ValueError("Invalid pubkey length")
    except Exception:
        raise ValueError("Invalid pubkey length")
    return v

def sanitize_network_id(v: str):
    if not isinstance(v, str) or not ID_RE.fullmatch(v):
        raise ValueError("Invalid network_id")
    return v

def allow_rate(ip, capacity=10, period=60):
    now = time.time()
    with rlock:
        ts, tokens = rate.get(ip, (now, capacity))
        if now - ts > period:
            ts, tokens = now, capacity
        if tokens <= 0:
            rate[ip] = (ts, tokens)
            return False
        tokens -= 1
        rate[ip] = (ts, tokens)
        return True

@app.route("/mesh/attest-node", methods=["POST"])
def mesh_attest_node():
    client_ip = request.remote_addr or "unknown"
    if not allow_rate(client_ip, 10, 60):
        return jsonify({"error": "rate limit"}), 429
    user_id = session.get("user_id")
    if not user_id or not ID_RE.fullmatch(str(user_id)):
        return jsonify({"error": "Not logged in"}), 401
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"error": "bad json"}), 400
    try:
        network_id = sanitize_network_id(data.get("network_id", ""))
        node_id = sanitize_id(data.get("node_id", ""))
        pubkey = sanitize_pubkey(data.get("pubkey", ""))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if any(len(x) > 256 for x in (network_id, node_id, pubkey)):
        return jsonify({"error": "input too long"}), 400
    exp = int(time.time()) + 3600
    payload = f"{user_id}|{network_id}|{node_id}|{pubkey}|{exp}".encode()
    mac = hmac.new(MEMBER_SECRET.encode(), payload, hashlib.sha256).digest()
    token = b64u_encode(payload + b"|" + mac)
    return jsonify({"attestation": token,"user_id": user_id,"network_id": network_id,"expires": exp})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("FLASK_PORT","5000")))
