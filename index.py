import hmac
import hashlib
import httpx  # Async requests ke liye
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

# --- Encryption Helpers ---
def aes_encrypt(data_hex):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(data_hex), AES.block_size)).hex()

async def encode_proto_async(fields):
    """Asynchronous minimal proto encoder"""
    p = bytearray()
    for f, v in fields.items():
        if isinstance(v, str):
            e = v.encode()
            # Tag/Wire type
            h = bytearray()
            n = (f << 3) | 2
            while True:
                b = n & 0x7F
                n >>= 7
                if n: b |= 0x80
                h.append(b)
                if not n: break
            # Length
            l = len(e)
            lh = bytearray()
            while True:
                b = l & 0x7F
                l >>= 7
                if l: b |= 0x80
                lh.append(b)
                if not l: break
            p.extend(h + lh + e)
    return p

# --- Async Account Generation Logic ---
async def create_account_async(region, custom_name):
    async with httpx.AsyncClient(verify=False) as client:
        password = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))

        # 1. Register Guest
        payload_reg = json.dumps({"app_id": 100067, "client_type": 2, "password": password, "source": 2}, separators=(',', ':'))
        sig_reg = hmac.new(Config.API_KEY, payload_reg.encode(), hashlib.sha256).hexdigest()
        
        headers_reg = {"Authorization": f"Signature {sig_reg}", "Content-Type": "application/json"}
        resp_reg = await client.post(Config.REGISTER_URL, content=payload_reg, headers=headers_reg)
        res_reg = resp_reg.json()

        if res_reg.get("code") != 0:
            return {"error": "Register failed", "details": res_reg}

        uid = res_reg['data']['uid']

        # 2. Grant Token
        payload_tok = json.dumps({"client_id": 100067, "client_secret": Config.HEX_KEY, "client_type": 2, "password": password, "response_type": "token", "uid": uid}, separators=(',', ':'))
        sig_tok = hmac.new(Config.API_KEY, payload_tok.encode(), hashlib.sha256).hexdigest()
        
        headers_tok = {"Authorization": f"Signature {sig_tok}", "Content-Type": "application/json"}
        resp_tok = await client.post(Config.TOKEN_URL, content=payload_tok, headers=headers_tok)
        res_tok = resp_tok.json()

        access_token = res_tok['data']['access_token']
        open_id = res_tok['data']['open_id']

        # 3. Major Register (Simplified)
        name = f"{custom_name}{random.randint(100,999)}"
        fields = {1: name, 2: access_token, 3: open_id}
        
        proto_bytes = await encode_proto_async(fields)
        encrypted_payload = aes_encrypt(proto_bytes.hex())
        
        headers_major = {
            "ReleaseVersion": "OB53", 
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)"
        }
        await client.post(Config.MAJOR_REGISTER_URL, content=bytes.fromhex(encrypted_payload), headers=headers_major)

        return {
            "uid": uid,
            "password": password,
            "name": name,
            "region": region,
            "account_id": "Generated", # Note: Real Account ID needs MajorLogin response parsing
            "access_token": access_token,
            "open_id": open_id,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

# --- FastAPI Endpoints ---

@app.get("/")
async def root():
    return {"status": "online", "message": "TUFAN FF Gen API (Async Fixed)"}

@app.get("/gen")
async def generate(region: str = "IND", name: str = "NOA"):
    try:
        # Ab koi loop error nahi aayega kyunki hum 'await' use kar rahe hain
        account = await create_account_async(region, name)
        return {"status": "success", "account": account}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Vercel entry point
app = app