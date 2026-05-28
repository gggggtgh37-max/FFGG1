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

def aes_encrypt(data_bytes):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

async def encode_field(field_num, value):
    tag = (field_num << 3) | 2
    tag_b = bytearray()
    while True:
        tag_b.append((tag & 0x7F) | (0x80 if tag > 0x7F else 0x00))
        tag >>= 7
        if tag == 0: break
    
    val_b = value.encode() if isinstance(value, str) else value
    len_b = bytearray()
    l = len(val_b)
    while True:
        len_b.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
        l >>= 7
        if l == 0: break
    return bytes(tag_b + len_b + val_b)

def get_acc_id_from_jwt(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            decoded = json.loads(base64.b64decode(payload).decode('utf-8'))
            return str(decoded.get('account_id') or decoded.get('external_id', 'N/A'))
    except:
        return "N/A"

@app.get("/")
async def root():
    return {"status": "ok", "service": "Real ID Generator"}

@app.get("/gen")
async def generate(region: str = "IND", name: str = "NOTA"):
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            pwd = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
            
            # 1. Register Guest
            reg_p = json.dumps({"app_id": 100067, "client_type": 2, "password": pwd, "source": 2}, separators=(',', ':'))
            sig_r = hmac.new(API_KEY, reg_p.encode(), hashlib.sha256).hexdigest()
            res_r = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest:register", 
                                     content=reg_p, headers={"Authorization": f"Signature {sig_r}", "Content-Type": "application/json"})
            reg_json = res_r.json()
            if reg_json.get("code") != 0:
                return {"status": "error", "message": "Garena Registration Failed"}
            uid = reg_json['data']['uid']

            # 2. Grant Token
            tok_p = json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':'))
            sig_t = hmac.new(API_KEY, tok_p.encode(), hashlib.sha256).hexdigest()
            res_t = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", 
                                     content=tok_p, headers={"Authorization": f"Signature {sig_t}", "Content-Type": "application/json"})
            token_data = res_t.json()['data']
            access_token = token_data['access_token']
            open_id = token_data['open_id']

            # 3. Major Register (Create Character)
            full_name = f"{name}{random.randint(1000,9999)}"
            # Proto Fields for Register
            reg_proto = await encode_field(1, full_name) + await encode_field(2, access_token) + await encode_field(3, open_id)
            await client.post("https://loginbp.ggpolarbear.com/MajorRegister", 
                             content=aes_encrypt(reg_proto), 
                             headers={"ReleaseVersion": "OB53", "Content-Type": "application/x-www-form-urlencoded"})

            # 4. Major Login (Fetching Numeric ID)
            # Binary Payload for OB53 Login (Stable Version)
            login_prefix = bytes.fromhex("1a13323032352d30312d30312030303a30303a3031220966726565206669726528013a07312e3132302e32")
            login_body = await encode_field(20, open_id) + await encode_field(24, access_token)
            login_proto = login_prefix + login_body
            
            headers_login = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12)",
                "ReleaseVersion": "OB53",
                "X-GA": "v1 1",
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "Keep-Alive"
            }
            
            res_l = await client.post("https://loginbp.ggpolarbear.com/MajorLogin", 
                                     content=aes_encrypt(login_proto), headers=headers_login)

            # Response માંથી JWT શોધવું (eyJ...)
            jwt_token = "N/A"
            real_id = "Not Found"
            
            # Binary response ને string માં ફેરવીને regex વાપરવું
            resp_text = res_l.text
            match = re.search(r'eyJ[a-zA-Z0-9\._\-]+', resp_text)
            
            if match:
                jwt_token = match.group(0)
                real_id = get_acc_id_from_jwt(jwt_token)

            return {
                "status": "success",
                "data": {
                    "real_id": real_id,
                    "uid": uid,
                    "password": pwd,
                    "name": full_name,
                    "region": region,
                    "jwt_token": jwt_token
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}