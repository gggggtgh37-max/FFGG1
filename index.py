import hmac
import hashlib
import httpx
import random
import json
import base64
import re
from datetime import datetime
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = FastAPI()

# --- Config ---
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = bytes.fromhex(HEX_KEY)

# --- Encryption Helpers ---
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

def extract_account_id_from_jwt(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            decoded = json.loads(base64.b64decode(payload).decode('utf-8'))
            return decoded.get('account_id') or decoded.get('external_id')
    except:
        return "N/A"

# --- API Routes ---
@app.get("/")
async def health():
    return {"status": "ok", "msg": "Real ID Generator Active"}

@app.get("/gen")
async def generate(region: str = "IND", name: str = "NOTA"):
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            pwd = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
            
            # 1. Guest Register
            reg_p = json.dumps({"app_id": 100067, "client_type": 2, "password": pwd, "source": 2}, separators=(',', ':'))
            sig_r = hmac.new(API_KEY, reg_p.encode(), hashlib.sha256).hexdigest()
            res_r = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest:register", 
                                     content=reg_p, headers={"Authorization": f"Signature {sig_r}", "Content-Type": "application/json"})
            
            reg_j = res_r.json()
            if reg_j.get("code") != 0: return {"status": "error", "msg": "Registration Failed"}
            uid = reg_j['data']['uid']

            # 2. Token Grant
            tok_p = json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':'))
            sig_t = hmac.new(API_KEY, tok_p.encode(), hashlib.sha256).hexdigest()
            res_t = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", 
                                     content=tok_p, headers={"Authorization": f"Signature {sig_t}", "Content-Type": "application/json"})
            
            tok_j = res_t.json()
            acc_token = tok_j['data']['access_token']
            open_id = tok_j['data']['open_id']

            # 3. Major Register (Character creation)
            full_name = f"{name}{random.randint(1000,9999)}"
            reg_proto = await simple_proto_encode({1: full_name, 2: acc_token, 3: open_id})
            await client.post("https://loginbp.ggpolarbear.com/MajorRegister", 
                             content=bytes.fromhex(aes_encrypt(reg_proto.hex())), 
                             headers={"ReleaseVersion": "OB53", "Content-Type": "application/x-www-form-urlencoded"})

            # 4. Major Login (Fetching Real Account ID)
            # Standard OB53 Login Binary Payload (Condensed)
            login_hex = "1a13323032342d31312d30352031383a31353a3332220966726565206669726528013a07312e3132302e32"
            login_proto = bytes.fromhex(login_hex) + await simple_proto_encode({20: open_id, 24: acc_token})
            
            res_l = await client.post("https://loginbp.ggpolarbear.com/MajorLogin", 
                                     content=bytes.fromhex(aes_encrypt(login_proto.hex())), 
                                     headers={"ReleaseVersion": "OB53", "Content-Type": "application/x-www-form-urlencoded"})

            # Response માંથી JWT Token અને Real ID શોધવું
            real_id = "Not Found"
            token_text = res_l.text
            match = re.search(r'eyJ[a-zA-Z0-9\._\-]+', token_text)
            if match:
                jwt = match.group(0)
                real_id = extract_account_id_from_jwt(jwt)

            return {
                "status": "success",
                "data": {
                    "real_id": real_id,
                    "uid": uid,
                    "password": pwd,
                    "name": full_name,
                    "region": region,
                    "jwt_token": jwt if match else "N/A"
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}