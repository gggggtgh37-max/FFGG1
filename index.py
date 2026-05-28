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
def aes_encrypt(data_bytes):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

async def encode_field(field_num, value, wire_type=2):
    """Proto Field Encoder"""
    tag = (field_num << 3) | wire_type
    tag_b = bytearray()
    while True:
        tag_b.append((tag & 0x7F) | (0x80 if tag > 0x7F else 0x00))
        tag >>= 7
        if tag == 0: break
    
    if wire_type == 2: # Length-delimited
        val_b = value.encode() if isinstance(value, str) else value
        l = len(val_b)
        len_b = bytearray()
        while True:
            len_b.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
            l >>= 7
            if l == 0: break
        return bytes(tag_b + len_b + val_b)
    else: # Varint
        val_b = bytearray()
        while True:
            val_b.append((value & 0x7F) | (0x80 if value > 0x7F else 0x00))
            value >>= 7
            if value == 0: break
        return bytes(tag_b + val_b)

def get_id_from_jwt(jwt):
    try:
        p = jwt.split('.')[1]
        p += '=' * (4 - len(p) % 4)
        data = json.loads(base64.b64decode(p).decode())
        return str(data.get('account_id') or data.get('external_id', 'N/A'))
    except: return "N/A"

# --- Main Logic ---
async def generate_ff_full_account(region_str, prefix):
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        pwd = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
        
        # 1. Register Guest
        reg_p = json.dumps({"app_id": 100067, "client_type": 2, "password": pwd, "source": 2}, separators=(',', ':'))
        sig_r = hmac.new(API_KEY, reg_p.encode(), hashlib.sha256).hexdigest()
        res_r = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest:register", 
                                 content=reg_p, headers={"Authorization": f"Signature {sig_r}"})
        uid = res_r.json()['data']['uid']

        # 2. Grant Token
        tok_p = json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':'))
        sig_t = hmac.new(API_KEY, tok_p.encode(), hashlib.sha256).hexdigest()
        res_t = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", 
                                 content=tok_p, headers={"Authorization": f"Signature {sig_t}"})
        t_data = res_t.json()['data']
        access_token, open_id = t_data['access_token'], t_data['open_id']

        # 3. Major Register (Create Name)
        full_name = f"{prefix}{random.randint(1000,9999)}"
        reg_proto = await encode_field(1, full_name) + await encode_field(2, access_token) + await encode_field(3, open_id)
        await client.post("https://loginbp.ggpolarbear.com/MajorRegister", 
                         content=aes_encrypt(reg_proto), headers={"ReleaseVersion": "OB53"})

        # 4. Choose Region (Critical for Real ID)
        region_proto = await encode_field(1, region_str)
        res_reg = await client.post("https://loginbp.ggpolarbear.com/ChooseRegion", 
                                   content=aes_encrypt(region_proto), 
                                   headers={"Authorization": f"Bearer {access_token}", "ReleaseVersion": "OB53"})

        # 5. Major Login (Get the JWT and Real ID)
        login_base = bytes.fromhex("1a13323032352d30312d30312030303a30303a3031220966726565206669726528013a07312e3132302e32")
        login_proto = login_base + await encode_field(20, open_id) + await encode_field(24, access_token)
        
        headers_login = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12)",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        res_l = await client.post("https://loginbp.ggpolarbear.com/MajorLogin", 
                                 content=aes_encrypt(login_proto), headers=headers_login)

        # Parsing Real ID from response
        jwt_token = "N/A"
        real_id = "Not Found"
        match = re.search(r'eyJ[a-zA-Z0-9\._\-]+', res_l.text)
        if match:
            jwt_token = match.group(0)
            real_id = get_id_from_jwt(jwt_token)

        return {
            "real_id": real_id,
            "uid": uid,
            "password": pwd,
            "name": full_name,
            "region": region_str,
            "jwt_token": jwt_token
        }

# --- Routes ---
@app.get("/")
async def index(): return {"status": "ok", "dev": "NOTA FF"}

@app.get("/gen")
async def gen_api(region: str = "IND", name: str = "NOTA"):
    try:
        data = await generate_ff_full_account(region.upper(), name)
        return {"status": "success", "data": data}
    except Exception as e:
        return {"status": "error", "message": str(e)}