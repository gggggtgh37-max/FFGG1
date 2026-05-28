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

def aes_encrypt(data_bytes):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

async def encode_field(field_num, value, wire_type=2):
    if wire_type == 2: # String/Bytes
        tag = (field_num << 3) | 2
        val_b = value.encode() if isinstance(value, str) else value
        l = len(val_b)
        len_b = bytearray()
        while True:
            len_b.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
            l >>= 7
            if l == 0: break
        return bytes([tag]) + len_b + val_b
    elif wire_type == 0: # Integer (Varint)
        tag = (field_num << 3) | 0
        val_b = bytearray()
        while True:
            val_b.append((value & 0x7F) | (0x80 if value > 0x7F else 0x00))
            value >>= 7
            if value == 0: break
        return bytes([tag]) + val_b

def get_id_from_jwt(jwt_token):
    try:
        p = jwt_token.split('.')[1]
        p += '=' * (4 - len(p) % 4)
        data = json.loads(base64.b64decode(p).decode())
        return str(data.get('account_id') or data.get('external_id', 'N/A'))
    except: return "N/A"

@app.get("/gen")
async def generate(region: str = "IND", name: str = "NOTA"):
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            pwd = ''.join(random.choice('0123456789ABCDEF') for _ in range(64))
            
            # 1. Guest Register
            reg_p = json.dumps({"app_id": 100067, "client_type": 2, "password": pwd, "source": 2}, separators=(',', ':'))
            sig_r = hmac.new(API_KEY, reg_p.encode(), hashlib.sha256).hexdigest()
            res_r = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest:register", content=reg_p, headers={"Authorization": f"Signature {sig_r}"})
            uid = res_r.json()['data']['uid']

            # 2. MSDK Token
            tok_p = json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':'))
            sig_t = hmac.new(API_KEY, tok_p.encode(), hashlib.sha256).hexdigest()
            res_t = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", content=tok_p, headers={"Authorization": f"Signature {sig_t}"})
            t_data = res_t.json()['data']
            access_token, open_id = t_data['access_token'], t_data['open_id']

            # 3. Major Register (Character Name)
            full_name = f"{name}{random.randint(100,999)}"
            reg_proto = await encode_field(1, full_name) + await encode_field(2, access_token) + await encode_field(3, open_id)
            await client.post("https://loginbp.ggpolarbear.com/MajorRegister", content=aes_encrypt(reg_proto), headers={"ReleaseVersion": "OB53"})

            # 4. Choose Region (CRITICAL STEP)
            # આ સ્ટેપ વગર Numeric ID નહી મળે
            region_proto = await encode_field(1, region.upper())
            await client.post("https://loginbp.ggpolarbear.com/ChooseRegion", 
                             content=aes_encrypt(region_proto), 
                             headers={"Authorization": f"Bearer {access_token}", "ReleaseVersion": "OB53"})

            # 5. Active Beginner Guide (Veteran Step)
            vet_proto = await encode_field(1, 3, wire_type=0) # Option 3 = Veteran
            await client.post("https://loginbp.ggpolarbear.com/ActiveBeginnerGuide", 
                             content=aes_encrypt(vet_proto), 
                             headers={"Authorization": f"Bearer {access_token}", "ReleaseVersion": "OB53"})

            # 6. Major Login (Get Real ID)
            login_prefix = bytes.fromhex("1a13323032352d30352d32302031303a30303a3030220966726565206669726528013a07312e3132302e32")
            login_body = await encode_field(20, open_id) + await encode_field(24, access_token)
            res_l = await client.post("https://loginbp.ggpolarbear.com/MajorLogin", 
                                     content=aes_encrypt(login_prefix + login_body), 
                                     headers={"ReleaseVersion": "OB53", "Content-Type": "application/x-www-form-urlencoded"})

            # JWT Parsing
            jwt_token = "N/A"
            real_id = "Not Found"
            content = res_l.content
            start = content.find(b'eyJ')
            if start != -1:
                end = content.find(b'\x00', start)
                if end == -1: end = len(content)
                jwt_token = content[start:end].decode('utf-8', errors='ignore')
                jwt_token = re.sub(r'[^a-zA-Z0-9\._\-]', '', jwt_token)
                real_id = get_id_from_jwt(jwt_token)

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