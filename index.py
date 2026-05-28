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
    
    if wire_type == 2: # String / Bytes
        val_b = value.encode() if isinstance(value, str) else value
        l = len(val_b)
        len_b = bytearray()
        while True:
            len_b.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
            l >>= 7
            if l == 0: break
        return bytes(tag_b) + len_b + val_b
    else: # Varint (Integer)
        val_b = bytearray()
        while True:
            val_b.append((value & 0x7F) | (0x80 if value > 0x7F else 0x00))
            value >>= 7
            if value == 0: break
        return bytes(tag_b) + val_b

def decode_real_id(jwt):
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
            pwd = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
            
            # 1. Register Guest
            reg_json = (await client.post("https://100067.connect.garena.com/api/v2/oauth/guest:register", 
                        content=json.dumps({"app_id": 100067, "client_type": 2, "password": pwd, "source": 2}, separators=(',', ':')), 
                        headers={"Authorization": f"Signature {hmac.new(API_KEY, json.dumps({'app_id': 100067, 'client_type': 2, 'password': pwd, 'source': 2}, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()}"})).json()
            
            if reg_json.get('code') != 0: return {"status": "error", "message": "Garena Registration Failed"}
            uid = reg_json['data']['uid']

            # 2. Grant Token
            tok_json = (await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", 
                        content=json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':')), 
                        headers={"Authorization": f"Signature {hmac.new(API_KEY, json.dumps({'client_id': 100067, 'client_secret': HEX_KEY, 'client_type': 2, 'password': pwd, 'response_type': 'token', 'uid': uid}, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()}"})).json()
            
            access_token, open_id = tok_json['data']['access_token'], tok_json['data']['open_id']

            # 3. Major Register
            full_name = f"{name}{random.randint(1000,9999)}"
            reg_proto = await encode_field(1, full_name) + await encode_field(2, access_token) + await encode_field(3, open_id)
            await client.post(f"{MAJOR_HOST}/MajorRegister", content=aes_encrypt(reg_proto), headers={"ReleaseVersion": "OB53"})

            # 4. Region Selection (Real ID generating step)
            region_proto = await encode_field(1, region.upper())
            await client.post(f"{MAJOR_HOST}/ChooseRegion", content=aes_encrypt(region_proto), 
                             headers={"Authorization": f"Bearer {access_token}", "ReleaseVersion": "OB53"})

            await asyncio.sleep(1) # Wait for server to sync

            # 5. Major Login (Fetching Numeric ID)
            # OB53 Full Binary Payload Construction
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            login_proto = (
                await encode_field(1, ts) +               # Time
                await encode_field(2, "free fire") +       # Game
                await encode_field(3, 1, wire_type=0) +    # Platform: Android
                await encode_field(20, open_id) +          # OpenID
                await encode_field(23, "4") +              # Type: Guest
                await encode_field(24, access_token) +     # Token
                await encode_field(32, "7428b253defc164018c604a1ebbfebdf") # Signature
            )
            
            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B)",
                "ReleaseVersion": "OB53",
                "X-GA": "v1 1",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            res_login = await client.post(f"{MAJOR_HOST}/MajorLogin", content=aes_encrypt(login_proto), headers=headers)

            # JWT Parsing from Binary Response
            jwt_token, real_id = "N/A", "Not Found"
            binary_content = res_login.content
            
            # Search for 'eyJ' inside binary data
            match = re.search(b'eyJ[a-zA-Z0-9\._\-]+', binary_content)
            if match:
                jwt_token = match.group(0).decode('utf-8', errors='ignore')
                real_id = decode_real_id(jwt_token)
            else:
                # If binary regex fails, try text search as fallback
                text_match = re.search(r'eyJ[a-zA-Z0-9\._\-]+', res_login.text)
                if text_match:
                    jwt_token = text_match.group(0)
                    real_id = decode_real_id(jwt_token)

            return {
                "status": "success",
                "data": {
                    "real_id": real_id,
                    "uid": uid,
                    "password": pwd,
                    "name": full_name,
                    "region": region,
                    "jwt_token": jwt_token if jwt_token != "N/A" else "Server rejected Login"
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}