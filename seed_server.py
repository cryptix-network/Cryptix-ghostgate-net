import asyncio
import time
import os
import re
import base64
import hmac
import hashlib
import sqlite3
import threading
from typing import Dict, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI()

MEMBER_SECRET = os.getenv("MEMBER_SECRET", "dev-member-secret")

_db_name = os.getenv("MESH_DB", "mesh.db")
if not re.fullmatch(r"[A-Za-z0-9._-]+", _db_name):
    _db_name = "mesh.db"

_db = sqlite3.connect(_db_name, check_same_thread=False)
_db.execute("PRAGMA journal_mode=WAL")
_db.execute("CREATE TABLE IF NOT EXISTS nodes (network_id TEXT,node_id TEXT,pubkey TEXT,user_id TEXT,udp_ip TEXT,udp_port INTEGER,last_seen REAL,PRIMARY KEY(network_id,node_id))")
_db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_net_seen ON nodes(network_id,last_seen)")
_db.commit()
db_lock = threading.Lock()

ID_RE = re.compile(r"^[A-Za-z0-9:\-]+$")
B64_STD = re.compile(r"^[A-Za-z0-9+/=]+$")
B64URL_STRICT = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

def safe_commit(query, params=()):
    with db_lock:
        cur = _db.execute(query, params)
        _db.commit()
    return cur

def db_upsert(network_id,node_id,pubkey,user_id,last_seen,udp_addr=None):
    if udp_addr:
        ip,port = udp_addr
        safe_commit(
            "INSERT INTO nodes (network_id,node_id,pubkey,user_id,udp_ip,udp_port,last_seen) VALUES (?,?,?,?,?,?,?) ON CONFLICT(network_id,node_id) DO UPDATE SET pubkey=excluded.pubkey,user_id=excluded.user_id,udp_ip=excluded.udp_ip,udp_port=excluded.udp_port,last_seen=excluded.last_seen",
            (network_id,node_id,pubkey,user_id,ip,port,last_seen)
        )
    else:
        safe_commit(
            "INSERT INTO nodes (network_id,node_id,pubkey,user_id,last_seen) VALUES (?,?,?,?,?) ON CONFLICT(network_id,node_id) DO UPDATE SET pubkey=excluded.pubkey,user_id=excluded.user_id,last_seen=excluded.last_seen",
            (network_id,node_id,pubkey,user_id,last_seen)
        )

def db_get_peers(network_id,node_id,limit=500):
    with db_lock:
        cur=_db.execute(
            "SELECT node_id,pubkey,udp_ip,udp_port,user_id,last_seen FROM nodes WHERE network_id=? AND node_id<>? ORDER BY last_seen DESC LIMIT ?",
            (network_id,node_id,limit)
        )
        rows = cur.fetchall()
    out={}
    for nid,pub,ip,port,uid,ts in rows:
        if not ID_RE.fullmatch(nid or ""): continue
        if not B64_STD.fullmatch(pub or ""): continue
        try:
            if len(base64.b64decode(pub, validate=True)) != 32: continue
        except Exception:
            continue
        if uid and not ID_RE.fullmatch(uid): uid = None
        addr=(ip,port) if ip and port else None
        out[nid]={"pubkey":pub,"udp_addr":addr,"user_id":uid}
    return out

def b64u_decode(s: str) -> bytes:
    if not B64URL_STRICT.fullmatch(s or ""):
        raise ValueError("bad b64url")
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

def verify_attestation_token(token: str) -> dict:
    raw = b64u_decode(token)
    payload, mac = raw.rsplit(b"|", 1)
    parts = payload.decode().split("|")
    if len(parts) != 5: raise ValueError("bad payload")
    user_id, network_id, node_id, pubkey_b64, exp_s = parts
    exp = int(exp_s)
    if time.time() > exp: raise ValueError("expired")
    expected = hmac.new(MEMBER_SECRET.encode(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac): raise ValueError("bad mac")
    if not ID_RE.fullmatch(user_id): raise ValueError("bad user_id")
    if not ID_RE.fullmatch(network_id): raise ValueError("bad network_id")
    if not ID_RE.fullmatch(node_id): raise ValueError("bad node_id")
    if not B64_STD.fullmatch(pubkey_b64): raise ValueError("bad pubkey format")
    try:
        if len(base64.b64decode(pubkey_b64, validate=True)) != 32: raise ValueError("bad pubkey length")
    except Exception:
        raise ValueError("bad pubkey length")
    return {"user_id": user_id,"network_id": network_id,"node_id": node_id,"pubkey": pubkey_b64,"exp": exp}

register_rate: Dict[str, Tuple[float,int]] = {}
udp_rate: Dict[str, Tuple[float,int]] = {}
RATE_LOCK = threading.Lock()

def allow_rate(bucket: Dict[str, Tuple[float,int]], ip: str, capacity: int, period: int):
    now = time.time()
    with RATE_LOCK:
        ts,tokens = bucket.get(ip,(now,capacity))
        if now - ts > period:
            ts = now; tokens = capacity
        if tokens <= 0:
            bucket[ip] = (ts,tokens)
            return False
        tokens -= 1
        bucket[ip] = (ts,tokens)
        return True

@app.post("/register")
async def register(req: Request):
    client_ip = req.client.host if req.client else "unknown"
    if not allow_rate(register_rate, client_ip, 5, 60):
        return JSONResponse({"status":"error","err":"rate limit"},status_code=429)
    data = await req.json()
    try:
        network_id = data["network_id"]; node_id = data["node_id"]
        pubkey = data["pubkey"]; token = data["attestation"]
    except KeyError:
        return JSONResponse({"status":"error","err":"missing fields"},status_code=400)
    if not ID_RE.fullmatch(network_id or ""): return JSONResponse({"status":"error","err":"bad network_id"},status_code=400)
    if not ID_RE.fullmatch(node_id or ""): return JSONResponse({"status":"error","err":"bad node_id"},status_code=400)
    if not B64_STD.fullmatch(pubkey or ""): return JSONResponse({"status":"error","err":"bad pubkey format"},status_code=400)
    try:
        if len(base64.b64decode(pubkey, validate=True)) != 32: return JSONResponse({"status":"error","err":"bad pubkey length"},status_code=400)
    except Exception:
        return JSONResponse({"status":"error","err":"bad pubkey length"},status_code=400)
    if not token: return JSONResponse({"status":"error","err":"missing attestation"},status_code=400)
    try: info = verify_attestation_token(token)
    except Exception as e: return JSONResponse({"status":"error","err":str(e)},status_code=403)
    if info["node_id"] != node_id: return JSONResponse({"status":"error","err":"attestation node mismatch"},status_code=403)
    if info["pubkey"] != pubkey: return JSONResponse({"status":"error","err":"attestation pubkey mismatch"},status_code=403)
    if info["network_id"] != network_id: return JSONResponse({"status":"error","err":"attestation network mismatch"},status_code=403)
    db_upsert(network_id,node_id,pubkey,info["user_id"],time.time())
    return {"status":"ok","peers":db_get_peers(network_id,node_id)}

@app.get("/debug")
def debug(secret: str = None):
    if secret != MEMBER_SECRET:
        with db_lock:
            cur=_db.execute("SELECT network_id,COUNT(*) FROM nodes GROUP BY network_id")
            rows = cur.fetchall()
        return {"counts": {r[0]: r[1] for r in rows}}
    with db_lock:
        cur=_db.execute("SELECT * FROM nodes")
        return cur.fetchall()

async def udp_observer(host: str = "0.0.0.0", port: int = 7777):
    loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(lambda: HelloProtocol(), local_addr=(host, port))
    await asyncio.Future()

class HelloProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        ip = addr[0]
        if not allow_rate(udp_rate, ip, 20, 60): return
        try:
            msg = data.decode("utf-8", errors="ignore").strip()
            if not msg.startswith("HELLO_ATTEST "): return
            parts = msg.split(" ", 3)
            if len(parts) != 4: return
            _, network_id, node_id, token = parts
            if not ID_RE.fullmatch(network_id): return
            if not ID_RE.fullmatch(node_id): return
            try: info = verify_attestation_token(token)
            except Exception: return
            if info["node_id"] != node_id: return
            if info["network_id"] != network_id: return
            db_upsert(network_id,node_id,info["pubkey"],info["user_id"],time.time(),addr)
        except Exception:
            pass

def prune_loop(max_age=300):
    while True:
        now = time.time()
        with db_lock:
            _db.execute("DELETE FROM nodes WHERE ? - last_seen > ?",(now,max_age))
            _db.commit()
        time.sleep(60)

@app.on_event("startup")
async def on_start():
    asyncio.create_task(udp_observer())
    threading.Thread(target=prune_loop, daemon=True).start()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
