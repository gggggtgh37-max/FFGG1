import hmac
import hashlib
import httpx
import random
import json
import base64
import re
import asyncio
from datetime import datetime
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = FastAPI()

# --- Config ---
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = bytes.fromhex(HEX_KEY)

# IND Region માટે આ સર્વર બેસ્ટ છે
MAJOR_HOST = "https://loginbp.common.ggbluefox.com" 

def aes_encrypt(data_bytes):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

async def encode_field(field_num, value, wire_type=2):
    tag = (field_num << 3) | wire_type
    tag_b = bytearray()
    while True:
        tag_b.append((tag & 0x7F) | (0x80 if tag > 0x7F else 0x00))
        tag >>= 7
        if tag == 0: break
    
    if wire_type == 2: # String/Bytes
        val_b = value.encode() if isinstance(value, str) else value
        l = len(val_b)
        len_b = bytearray()
        while True:
            len_b.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
            l >>= 7
            if l == 0: break
        return bytes(tag_b) + len_b + val_b
    else: # Varint
        val_b = bytearray()
        while True:
            val_b.append((value & 0x7F) | (0x80 if value > 0x7F else 0x00))
            value >>= 7
            if value == 0: break
        return bytes(tag_b) + val_b

def decode_id(jwt):
    try:
        p = jwt.split('.')[1]
        p += '=' * (4 - len(p) % 4)
        data = json.loads(base64.b64decode(p).decode())
        return str(data.get('account_id') or data.get('external_id', 'N/A'))
    except: return "N/A"

@app.get("/gen")
async def generate(region: str = "IND", name: str = "NOTA"):
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            # 1. Credentials
            pwd = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
            
            # 2. Register
            reg_payload = json.dumps({"app_id": 100067, "client_type": 2, "password": pwd, "source": 2}, separators=(',', ':'))
            sig_r = hmac.new(API_KEY, reg_payload.encode(), hashlib.sha256).hexdigest()
            res_r = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest:register", 
                                     content=reg_payload, headers={"Authorization": f"Signature {sig_r}"})
            uid = res_r.json()['data']['uid']

            # 3. Token
            tok_payload = json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':'))
            sig_t = hmac.new(API_KEY, tok_payload.encode(), hashlib.sha256).hexdigest()
            res_t = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", 
                                     content=tok_payload, headers={"Authorization": f"Signature {sig_t}"})
            t_data = res_t.json()['data']
            access_token, open_id = t_data['access_token'], t_data['open_id']

            # 4. Major Register (Create Name)
            full_name = f"{name}{random.randint(100,999)}"
            # Field 14 is Encoded OpenID for Character Creation
            reg_proto = await encode_field(1, full_name) + await encode_field(2, access_token) + await encode_field(3, open_id)
            await client.post(f"{MAJOR_HOST}/MajorRegister", content=aes_encrypt(reg_proto), headers={"ReleaseVersion": "OB53"})

            # રીજન સેટ કરવા માટે થોડી સેકન્ડ રાહ જુઓ (Sync)
            await asyncio.sleep(1)

            # 5. Choose Region
            region_proto = await encode_field(1, region.upper())
            await client.post(f"{MAJOR_HOST}/ChooseRegion", content=aes_encrypt(region_proto), 
                             headers={"Authorization": f"Bearer {access_token}", "ReleaseVersion": "OB53"})

            # 6. Major Login (Get Numeric ID)
            # OB53 Full Payload Requirement
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            login_proto = (
                await encode_field(1, ts) + 
                await encode_field(2, "free fire") + 
                await encode_field(3, 1, wire_type=0) + # Platform ID: 1 (Android)
                await encode_field(20, open_id) + 
                await encode_field(23, "4") +           # OpenID Type: 4 (Guest)
                await encode_field(24, access_token) +
                await encode_field(32, "7428b253defc164018c604a1ebbfebdf") # OB53 Signature Hash
            )
            
            headers_l = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B)",
                "ReleaseVersion": "OB53",
                "X-GA": "v1 1",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            res_l = await client.post(f"{MAJOR_HOST}/MajorLogin", content=aes_encrypt(login_proto), headers=headers_l)

            # JWT Parsing - Binary Safe
            jwt_token, real_id = "N/A", "Not Found"
            match = re.search(b'eyJ[a-zA-Z0-9\._\-]+', res_l.content)
            if match:
                jwt_token = match.group(0).decode()
                real_id = decode_id(jwt_token)

            return {
                "status": "success",
                "data": {
                    "real_id": real_id,
                    "uid": uid,
                    "password": pwd,
                    "name": full_name,
                    "region": region,
                    "jwt_token": jwt_token[:40] + "..." if jwt_token != "N/A" else "N/A"
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}