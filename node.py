import asyncio, json, os, socket, time, base64, threading, hmac, hashlib, re, uuid
from typing import Dict, Tuple, Optional

import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.bindings import crypto_scalarmult

SEED_URL    = os.getenv("SEED_URL", "http://127.0.0.1:8000")
NETWORK_ID  = os.getenv("NETWORK_ID", "home-net-123")
JOIN_KEY    = os.getenv("JOIN_KEY", "secret-abc")
ATT_TOKEN   = os.getenv("ATT_TOKEN")
LOCAL_API   = int(os.getenv("LOCAL_API", "9000"))
UDP_PORT    = int(os.getenv("UDP_PORT", "0"))
USER_ID     = os.getenv("USER_ID")
MEMBER_SECRET = os.getenv("MEMBER_SECRET", "dev-member-secret")

ID_RE  = re.compile(r"^[A-Za-z0-9:\-]+$")
B64_STD = re.compile(r"^[A-Za-z0-9+/=]+$")
B64URL_STRICT = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

def safe_id(v: str):
    if not isinstance(v, str) or not ID_RE.fullmatch(v):
        raise ValueError("Invalid ID")
    return v

def safe_b64_32(v: str):
    if not isinstance(v, str) or not B64_STD.fullmatch(v):
        raise ValueError("Invalid base64")
    try:
        if len(base64.b64decode(v, validate=True)) != 32:
            raise ValueError("Invalid base64 length")
    except Exception:
        raise ValueError("Invalid base64 length")
    return v

def b64(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())

if USER_ID: safe_id(USER_ID)
safe_id(NETWORK_ID)
if ATT_TOKEN and not B64URL_STRICT.fullmatch(ATT_TOKEN):
    raise ValueError("Invalid ATT_TOKEN encoding")

KEY_FILE = "node_key.bin"
def load_or_create_key():
    try:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f: raw = f.read()
            return PrivateKey(raw)
    except Exception:
        pass
    sk = PrivateKey.generate()
    try:
        with open(KEY_FILE, "wb") as f: f.write(bytes(sk))
    except Exception:
        pass
    return sk

sk = load_or_create_key()
pk = sk.public_key

def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def hkdf_expand(prk, info, L):
    T=b""; out=b""
    for ctr in range(1, 1 + (L+31)//32):
        T = hmac.new(prk, T + info + bytes([ctr]), hashlib.sha256).digest()
        out += T
    return out[:L]

def hkdf(salt, ikm, info, L=32):
    return hkdf_expand(hkdf_extract(salt, ikm), info, L)

def hmac256(key: bytes, *parts: bytes) -> bytes:
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()

def shared_key(peer_pub_b64: str) -> bytes:
    safe_b64_32(peer_pub_b64)
    peer_pk = PublicKey(b64d(peer_pub_b64))
    return crypto_scalarmult(bytes(sk), bytes(peer_pk))

NODE_ID = safe_id(f"node-{int(time.time()*1000)}")
PUBLIC_KEY_B64 = b64(bytes(pk))

peers: Dict[str, dict] = {}
connected: Dict[str, dict] = {}
handshakes: Dict[str, dict] = {}
replay_hello: Dict[Tuple[str,int,bytes], float] = {}
replay_welcome: Dict[Tuple[str,int,bytes], float] = {}
peers_lock = threading.Lock()
connected_lock = threading.Lock()
handshakes_lock = threading.Lock()
replay_lock = threading.Lock()

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("0.0.0.0", UDP_PORT))
LOCAL_UDP_ADDR = udp_sock.getsockname()

def udp_send(addr, payload: dict, key: Optional[bytes], from_id: Optional[str]=None):
    if not isinstance(payload, dict): return
    if from_id and "from" not in payload:
        payload = dict(payload); payload["from"] = from_id
    try:
        data = json.dumps(payload, separators=(",",":"), ensure_ascii=False)
    except Exception:
        return
    if len(data) > 4096: return
    data_b = data.encode()
    if key:
        box = SecretBox(key); nonce = os.urandom(SecretBox.NONCE_SIZE)
        ct = box.encrypt(data_b, nonce).ciphertext
        hdr = b"FROM:" + (from_id or "unknown").encode() + b"\n"
        frame = b"\x01" + hdr + nonce + ct
    else:
        frame = b"\x00" + data_b
    if len(frame) > 1200: return
    try: udp_sock.sendto(frame, addr)
    except Exception: return

MAX_PKT = 2048
udp_rate: Dict[str, Tuple[float,int]] = {}
rate_lock = threading.Lock()

def allow_rate(ip: str, capacity: int, period: int):
    now = time.time()
    with rate_lock:
        ts,tokens = udp_rate.get(ip,(now,capacity))
        if now - ts > period:
            ts = now; tokens = capacity
        if tokens <= 0:
            udp_rate[ip] = (ts,tokens)
            return False
        tokens -= 1
        udp_rate[ip] = (ts,tokens)
        return True

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

def replay_seen(cache: Dict, key: Tuple, ttl: int) -> bool:
    now = time.time()
    with replay_lock:
        ts = cache.get(key)
        if ts and now - ts < ttl: return True
        cache[key] = now
        for k,v in list(cache.items()):
            if now - v > ttl: cache.pop(k, None)
        return False

def derive_session_key(nid_a: str, nid_b: str, nA: bytes, nB: bytes, tA: int, tB: int, peer_pub_b64: str, att_peer: str, att_self: str) -> bytes:
    z = shared_key(peer_pub_b64)
    transcript = b"|".join([NETWORK_ID.encode(),nid_a.encode(),nid_b.encode(),nA,nB,str(tA).encode(),str(tB).encode(),att_peer.encode(),att_self.encode()])
    salt = hmac256(JOIN_KEY.encode(), transcript)
    return hkdf(salt, z, b"marmot/enc")

def udp_recv_loop():
    while True:
        try: data, addr = udp_sock.recvfrom(MAX_PKT)
        except Exception: continue
        if not data: continue
        ip = addr[0]
        if not allow_rate(ip, 100, 60): continue
        try:
            if len(data) > MAX_PKT: continue
            enc = data[:1]; rest = data[1:]; msg = None; sender = None
            if enc == b"\x00":
                text = rest.decode(errors="strict")
                if len(text) > 4096: continue
                obj = json.loads(text)
                if not isinstance(obj, dict): continue
                msg = obj
            else:
                if not rest.startswith(b"FROM:"): continue
                idx = rest.index(b"\n"); sender = rest[5:idx].decode()
                if not ID_RE.fullmatch(sender): continue
                body = rest[idx+1:]
                if len(body) < SecretBox.NONCE_SIZE: continue
                nonce = body[:SecretBox.NONCE_SIZE]; ct = body[SecretBox.NONCE_SIZE:]
                with connected_lock: info = connected.get(sender)
                if not info: continue
                try:
                    box = SecretBox(info["symkey"]); text = box.decrypt(nonce + ct).decode()
                except Exception: continue
                if len(text) > 4096: continue
                obj = json.loads(text)
                if not isinstance(obj, dict): continue
                if obj.get("from") and obj.get("from") != sender: continue
                msg = obj
            handle_msg(msg, addr, sender)
        except Exception:
            continue

def handle_msg(msg, addr, sender_hint):
    m = msg.get("type")
    if m == "hello1":
        nid = msg.get("node_id"); npub = msg.get("pubkey"); net = msg.get("network")
        tA = msg.get("tA"); nA = msg.get("nA"); mac = msg.get("mac_psk"); att = msg.get("attestation")
        if net != NETWORK_ID or not (nid and npub and nA and mac and att): return
        try: safe_id(nid); safe_b64_32(npub)
        except: return
        try:
            tA = int(tA)
            if abs(int(time.time()*1000) - tA) > 120000: return
        except: return
        try: nA_b = b64d(nA); mac_b = b64d(mac)
        except: return
        try:
            info = verify_attestation_token(att)
        except Exception:
            return
        if info["network_id"] != NETWORK_ID or info["node_id"] != nid or info["pubkey"] != npub: return
        if replay_seen(replay_hello, (nid,tA,nA_b), 180): return
        exp = hmac256(JOIN_KEY.encode(),NETWORK_ID.encode(),nid.encode(),npub.encode(),str(tA).encode(),nA_b,att.encode())
        if not hmac.compare_digest(exp, mac_b): return
        with peers_lock:
            p = peers.setdefault(nid, {}); p["pubkey"] = npub; p["udp_addr"] = addr; p["last_seen"] = time.time(); p["attestation"] = att
        nB = os.urandom(24); tB = int(time.time()*1000)
        mac_b = hmac256(JOIN_KEY.encode(),NETWORK_ID.encode(),NODE_ID.encode(),PUBLIC_KEY_B64.encode(),str(tB).encode(),nB,ATT_TOKEN.encode() if ATT_TOKEN else b"")
        k_enc = derive_session_key(nid, NODE_ID, nA_b, nB, int(tA), tB, npub, att, ATT_TOKEN or "")
        with connected_lock:
            connected[nid] = {"addr": addr,"symkey": k_enc,"last_seen": time.time()}
        udp_send(addr,{
            "type":"welcome1","network":NETWORK_ID,"from":NODE_ID,
            "pubkey":PUBLIC_KEY_B64,"tB":tB,"nB":b64(nB),"mac_psk":b64(mac_b),"attestation":ATT_TOKEN
        }, None)
    elif m == "welcome1":
        fr = msg.get("from"); net = msg.get("network"); att = msg.get("attestation")
        if net != NETWORK_ID or not fr or not att: return
        try: safe_id(fr); safe_b64_32(msg.get("pubkey",""))
        except: return
        try: nB = b64d(msg.get("nB","")); mac_b = b64d(msg.get("mac_psk","")); tB = int(msg.get("tB"))
        except: return
        try:
            info = verify_attestation_token(att)
        except Exception:
            return
        if info["network_id"] != NETWORK_ID or info["node_id"] != fr or info["pubkey"] != msg["pubkey"]: return
        if replay_seen(replay_welcome, (fr,tB,nB), 180): return
        exp = hmac256(JOIN_KEY.encode(),NETWORK_ID.encode(),fr.encode(),msg["pubkey"].encode(),str(tB).encode(),nB,att.encode())
        if not hmac.compare_digest(exp, mac_b): return
        with peers_lock:
            peers.setdefault(fr,{})["pubkey"] = msg["pubkey"]
            peers[fr]["udp_addr"] = addr; peers[fr]["last_seen"] = time.time(); peers[fr]["attestation"] = att
        with handshakes_lock:
            hs = handshakes.get(fr)
        if not hs: return
        k_enc = derive_session_key(NODE_ID, fr, hs["nA"], nB, hs["tA"], tB, msg["pubkey"], att, ATT_TOKEN or "")
        with connected_lock:
            connected[fr] = {"addr": addr, "symkey": k_enc, "last_seen": time.time()}
        with handshakes_lock:
            handshakes.pop(fr, None)
    elif m == "task":
        cmd = msg.get("cmd"); args = msg.get("args", [])
        if not isinstance(cmd, str): return
        if not isinstance(args, list) or len(args) > 16: return
        if sum(len(str(a)) for a in args) > 2048: return
        out = run_task(cmd, args)
        sender = sender_hint or next((i for i,v in connected.items() if v["addr"] == addr), None)
        if sender:
            with connected_lock:
                key = connected[sender]["symkey"]; connected[sender]["last_seen"] = time.time()
            udp_send(addr,{"type":"task_result","task_id":str(msg.get("task_id"))[:64],"result":out,"from":NODE_ID}, key, from_id=NODE_ID)
    elif m == "task_result":
        fr = msg.get("from")
        if isinstance(fr, str):
            with connected_lock:
                if fr in connected: connected[fr]["last_seen"] = time.time()
        tid = str(msg.get("task_id"))[:64]; res = msg.get("result")
        try: print(f"[TASK RESULT] from {msg.get('from')}: {tid} => {res}")
        except Exception: pass

def run_task(cmd, args):
    if cmd == "ping": return "pong"
    if cmd == "echo": return " ".join(map(str,args))
    if cmd == "time": return time.ctime()
    return "ERR: command not allowed"

def register_loop():
    if not ATT_TOKEN: print("WARNING: ATT_TOKEN missing")
    while True:
        try:
            r = requests.post(f"{SEED_URL}/register",json={
                "network_id":NETWORK_ID,"node_id":NODE_ID,"pubkey":PUBLIC_KEY_B64,"attestation":ATT_TOKEN
            },timeout=5)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    peers_map = data.get("peers",{})
                    if isinstance(peers_map, dict):
                        for pid,info in list(peers_map.items())[:500]:
                            try: safe_id(pid)
                            except: continue
                            with peers_lock:
                                p = peers.setdefault(pid,{})
                                v_pub = info.get("pubkey")
                                if isinstance(v_pub, str) and B64_STD.fullmatch(v_pub or ""):
                                    try:
                                        if len(base64.b64decode(v_pub, validate=True))==32: p["pubkey"]=v_pub
                                    except Exception:
                                        pass
                                v_addr = info.get("udp_addr")
                                if isinstance(v_addr, (list,tuple)) and len(v_addr)==2:
                                    ip,port = v_addr
                                    if isinstance(ip,str) and isinstance(port,int) and 0<port<65536: p["udp_addr"]=(ip,port)
                                v_uid = info.get("user_id")
                                if isinstance(v_uid,str) and ID_RE.fullmatch(v_uid or ""): p["user_id"]=v_uid
                                p["last_seen"]=time.time()
            else:
                print("register fail", r.status_code)
        except Exception:
            pass
        time.sleep(5)

def punch_seed():
    try:
        host_port = SEED_URL.split("//",1)[1].split("/",1)[0]; seed = host_port.split(":")[0]
    except Exception:
        return
    addr=(seed,7777)
    msg = f"HELLO_ATTEST {NETWORK_ID} {NODE_ID} {ATT_TOKEN}".encode() if ATT_TOKEN else f"HELLO {NETWORK_ID} {NODE_ID}".encode()
    if len(msg) > 1024: return
    while True:
        try: udp_sock.sendto(msg, addr)
        except: pass
        time.sleep(3)

def try_connect():
    while True:
        now = time.time()
        with peers_lock: peers_items = list(peers.items())
        for pid,info in peers_items[:1000]:
            try: safe_id(pid)
            except: continue
            if pid==NODE_ID: continue
            addr = info.get("udp_addr"); npub = info.get("pubkey")
            if not addr or not npub: continue
            with connected_lock:
                recent = pid in connected and now-connected[pid]["last_seen"]<30
            if recent: continue
            nA=os.urandom(24); tA=int(time.time()*1000)
            mac = hmac256(JOIN_KEY.encode(),NETWORK_ID.encode(),NODE_ID.encode(),PUBLIC_KEY_B64.encode(),str(tA).encode(),nA,ATT_TOKEN.encode() if ATT_TOKEN else b"")
            with handshakes_lock: handshakes[pid] = {"nA": nA, "tA": tA}
            udp_send(tuple(addr),{"type":"hello1","network":NETWORK_ID,"node_id":NODE_ID,"pubkey":PUBLIC_KEY_B64,"tA":tA,"nA":b64(nA),"mac_psk":b64(mac),"attestation":ATT_TOKEN},None)
        with handshakes_lock:
            for k,v in list(handshakes.items()):
                if time.time() - (v.get("ts") or 0) > 180: handshakes.pop(k,None)
        time.sleep(2)

app = FastAPI()

@app.get("/mesh")
def mesh():
    with peers_lock: peers_copy = {pid:i.copy() for pid,i in peers.items()}
    with connected_lock: connected_copy = set(connected.keys())
    out_peers = {}
    for pid,i in list(peers_copy.items())[:1000]:
        try: safe_id(pid)
        except: continue
        u = i.get("udp_addr")
        if isinstance(u,(list,tuple)) and len(u)==2:
            ip,port = u
            if not (isinstance(ip,str) and isinstance(port,int) and 0<port<65536): u=None
        out_peers[pid]={
            "udp_addr":u,
            "has_key":pid in connected_copy,
            "last_seen":int(i.get("last_seen",0)),
            "pubkey":i.get("pubkey") if isinstance(i.get("pubkey"),str) and B64_STD.fullmatch(i.get("pubkey") or "") else None,
            "user_id":i.get("user_id") if isinstance(i.get("user_id"),str) and ID_RE.fullmatch(i.get("user_id") or "") else None
        }
    return {"node_id":NODE_ID,"user_id":USER_ID,"udp_local":LOCAL_UDP_ADDR,"peers": out_peers}

@app.post("/task")
async def task(req: Request):
    try: body = await req.json()
    except Exception: return {"ok":False,"err":"bad json"}
    target = body.get("target"); cmd = body.get("cmd"); args = body.get("args",[])
    try: safe_id(str(target))
    except: return {"ok":False,"err":"bad target"}
    if not isinstance(cmd,str): return {"ok":False,"err":"bad cmd"}
    if cmd not in ("ping","echo","time"): return {"ok":False,"err":"cmd not allowed"}
    if not isinstance(args,list) or len(args)>16: return {"ok":False,"err":"bad args"}
    if sum(len(str(a)) for a in args) > 2048: return {"ok":False,"err":"args too large"}
    with connected_lock: ok = target in connected
    if not ok: return {"ok":False,"err":"not connected"}
    with connected_lock: addr = connected[target]["addr"]; key = connected[target]["symkey"]
    udp_send(addr,{"type":"task","task_id":str(uuid.uuid4()),"cmd":cmd,"args":args,"from":NODE_ID}, key, from_id=NODE_ID)
    return {"ok":True}

def start_threads():
    threading.Thread(target=register_loop,daemon=True).start()
    threading.Thread(target=punch_seed,daemon=True).start()
    threading.Thread(target=try_connect,daemon=True).start()
    threading.Thread(target=udp_recv_loop,daemon=True).start()

BANNER = r"""
            _____ _    _  ____   _____ _______ 
            / ____| |  | |/ __ \ / ____|__   __|
            | |  __| |__| | |  | | (___    | |   
            | | |_ |  __  | |  | |\___ \   | |   
            | |__| | |  | | |__| |____) |  | |   
            \_____|_|  |_|\____/|_____/   |_|   

             C R Y P T I X   G H O S T G A T E   N E T
"""

if __name__=="__main__":
    print(BANNER)
    print(f"[+] Node ID       : {NODE_ID}")
    print(f"[+] Network       : {NETWORK_ID}")
    print(f"[+] Local API     : 127.0.0.1:{LOCAL_API}")
    print(f"[+] UDP Bind      : {LOCAL_UDP_ADDR}")
    print(f"[+] Attestation   : {'loaded' if ATT_TOKEN else 'missing'}")
    print("\n[BOOT] Launching Cryptix GhostGate Net node...\n")

    start_threads()
    uvicorn.run(app, host="127.0.0.1", port=LOCAL_API)


