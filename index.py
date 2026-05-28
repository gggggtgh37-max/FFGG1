import hmac
import hashlib
import httpx
import random
import json
from datetime import datetime
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = FastAPI()

# --- Config ---
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = bytes.fromhex(HEX_KEY)

# --- Helpers ---
def aes_encrypt(data_hex):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(data_hex), AES.block_size)).hex()

async def simple_proto_encode(fields):
    p = bytearray()
    for f, v in fields.items():
        if isinstance(v, str):
            e = v.encode()
            n = (f << 3) | 2
            while True:
                p.append((n & 0x7F) | (0x80 if n > 0x7F else 0x00))
                n >>= 7
                if n == 0: break
            l = len(e)
            while True:
                p.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
                l >>= 7
                if l == 0: break
            p.extend(e)
    return p

# --- API Routes ---
@app.get("/")
async def health():
    return {"status": "ok", "message": "NOTA Gen is Active"}

@app.get("/gen")
async def generate(region: str = "IND", name: str = "NOTA"):
    try:
        async with httpx.AsyncClient(verify=False) as client:
            pwd = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
            
            # 1. Register Guest
            reg_p = json.dumps({"app_id": 100067, "client_type": 2, "password": pwd, "source": 2}, separators=(',', ':'))
            sig_r = hmac.new(API_KEY, reg_p.encode(), hashlib.sha256).hexdigest()
            res_r = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest:register", 
                                     content=reg_p, 
                                     headers={"Authorization": f"Signature {sig_r}", "Content-Type": "application/json"})
            
            reg_j = res_r.json()
            if reg_j.get("code") != 0:
                return {"status": "error", "msg": "Garena limit reached", "details": reg_j}
            
            uid = reg_j['data']['uid']

            # 2. Grant Token
            tok_p = json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':'))
            sig_t = hmac.new(API_KEY, tok_p.encode(), hashlib.sha256).hexdigest()
            res_t = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", 
                                     content=tok_p, 
                                     headers={"Authorization": f"Signature {sig_t}", "Content-Type": "application/json"})
            
            tok_j = res_t.json()
            acc_token = tok_j['data']['access_token']
            open_id = tok_j['data']['open_id']

            # 3. Major Register
            full_name = f"{name}{random.randint(100,999)}"
            proto_b = await simple_proto_encode({1: full_name, 2: acc_token, 3: open_id})
            enc_p = aes_encrypt(proto_b.hex())
            
            await client.post("https://loginbp.ggpolarbear.com/MajorRegister", 
                             content=bytes.fromhex(enc_p), 
                                 headers={"ReleaseVersion": "OB53", "Content-Type": "application/x-www-form-urlencoded"})

            return {
                "status": "success",
                "data": {
                    "uid": uid,
                    "password": pwd,
                    "name": full_name,
                    "region": region,
                    "open_id": open_id,
                    "access_token": acc_token
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}