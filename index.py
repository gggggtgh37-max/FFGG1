import hmac
import hashlib
import httpx
import random
import json
import asyncio
from datetime import datetime
from fastapi import FastAPI, Query
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = FastAPI()

class Config:
    HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
    API_KEY = bytes.fromhex(HEX_KEY)
    REGISTER_URL = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
    TOKEN_URL = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    MAJOR_REGISTER_URL = "https://loginbp.ggpolarbear.com/MajorRegister"

# --- Encryption ---
def aes_encrypt(data_hex):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(data_hex), AES.block_size)).hex()

# --- Proto Encoding (No Loop Error Here) ---
async def create_proto_bytes(fields):
    p = bytearray()
    for f, v in fields.items():
        if isinstance(v, str):
            e = v.encode()
            # Varint Tag
            n = (f << 3) | 2
            while True:
                p.append((n & 0x7F) | (0x80 if n > 0x7F else 0x00))
                n >>= 7
                if n == 0: break
            # Length
            l = len(e)
            while True:
                p.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
                l >>= 7
                if l == 0: break
            p.extend(e)
    return p

# --- Main Logic ---
async def generate_ff_account(region, prefix):
    async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
        password = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))

        # 1. Register
        reg_data = json.dumps({"app_id": 100067, "client_type": 2, "password": password, "source": 2}, separators=(',', ':'))
        sig_reg = hmac.new(Config.API_KEY, reg_data.encode(), hashlib.sha256).hexdigest()
        res_reg = await client.post(Config.REGISTER_URL, content=reg_data, headers={"Authorization": f"Signature {sig_reg}", "Content-Type": "application/json"})
        
        reg_json = res_reg.json()
        if reg_json.get("code") != 0:
            return {"error": "Garena Registration Failed", "msg": reg_json}
        
        uid = reg_json['data']['uid']

        # 2. Token
        tok_data = json.dumps({"client_id": 100067, "client_secret": Config.HEX_KEY, "client_type": 2, "password": password, "response_type": "token", "uid": uid}, separators=(',', ':'))
        sig_tok = hmac.new(Config.API_KEY, tok_data.encode(), hashlib.sha256).hexdigest()
        res_tok = await client.post(Config.TOKEN_URL, content=tok_data, headers={"Authorization": f"Signature {sig_tok}", "Content-Type": "application/json"})
        
        tok_json = res_tok.json()
        access_token = tok_json['data']['access_token']
        open_id = tok_json['data']['open_id']

        # 3. Major Register (Major part where loop error usually happens)
        name = f"{prefix}{random.randint(100,999)}"
        fields = {1: name, 2: access_token, 3: open_id}
        
        # અહિંયા 'await' વાપર્યું છે, 'run_async' નહીં
        proto_data = await create_proto_bytes(fields)
        encrypted_payload = aes_encrypt(proto_data.hex())
        
        major_headers = {
            "ReleaseVersion": "OB53",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG)"
        }
        await client.post(Config.MAJOR_REGISTER_URL, content=bytes.fromhex(encrypted_payload), headers=major_headers)

        return {
            "uid": uid,
            "password": password,
            "name": name,
            "region": region,
            "jwt_token": "Use MajorLogin for JWT",
            "timestamp": datetime.now().isoformat()
        }

# --- Routes ---

@app.get("/")
async def index():
    return {"status": "running", "dev": "NOA FF"}

@app.get("/gen")
async def gen_api(region: str = "IND", name: str = "NOA"):
    try:
        result = await generate_ff_account(region, name)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}