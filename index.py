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

async def encode_field(field_num, value):
    tag = (field_num << 3) | 2
    tag_b = bytearray()
    while True:
        tag_b.append((tag & 0x7F) | (0x80 if tag > 0x7F else 0x00))
        tag >>= 7
        if tag == 0: break
    
    val_b = value.encode() if isinstance(value, str) else value
    l = len(val_b)
    len_b = bytearray()
    while True:
        len_b.append((l & 0x7F) | (0x80 if l > 0x7F else 0x00))
        l >>= 7
        if l == 0: break
    return bytes(tag_b + len_b + val_b)

def extract_id_from_jwt(jwt_token):
    try:
        payload = jwt_token.split('.')[1]
        payload += '=' * (4 - len(payload) % 4)
        data = json.loads(base64.b64decode(payload).decode('utf-8'))
        return str(data.get('account_id') or data.get('external_id', 'N/A'))
    except:
        return "N/A"

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

            # 2. Grant Token
            tok_p = json.dumps({"client_id": 100067, "client_secret": HEX_KEY, "client_type": 2, "password": pwd, "response_type": "token", "uid": uid}, separators=(',', ':'))
            sig_t = hmac.new(API_KEY, tok_p.encode(), hashlib.sha256).hexdigest()
            res_t = await client.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant", content=tok_p, headers={"Authorization": f"Signature {sig_t}"})
            t_data = res_t.json()['data']
            access_token, open_id = t_data['access_token'], t_data['open_id']

            # 3. Major Register (Create Character)
            full_name = f"{name}{random.randint(1000,9999)}"
            reg_proto = await encode_field(1, full_name) + await encode_field(2, access_token) + await encode_field(3, open_id)
            await client.post("https://loginbp.ggpolarbear.com/MajorRegister", content=aes_encrypt(reg_proto), headers={"ReleaseVersion": "OB53"})

            # સર્વરને ડેટા સેવ કરવા માટે ૧ સેકન્ડનો સમય આપો
            await asyncio.sleep(1)

            # 4. Major Login (Get JWT & ID)
            # OB53 Payload logic
            login_prefix = bytes.fromhex("1a13323032352d30352d32302031303a30303a3030220966726565206669726528013a07312e3132302e32")
            # Field 20: OpenID, Field 24: AccessToken, Field 32: Signature
            login_body = await encode_field(20, open_id) + await encode_field(24, access_token)
            login_payload = aes_encrypt(login_prefix + login_body)

            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12)",
                "ReleaseVersion": "OB53",
                "X-GA": "v1 1",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            res_l = await client.post("https://loginbp.ggpolarbear.com/MajorLogin", content=login_payload, headers=headers)

            # --- JWT એક્સટ્રેક્ટ કરવાની નવી અને મજબૂત રીત ---
            jwt_token = "N/A"
            real_id = "Not Found"
            
            # રિસ્પોન્સ બાઈનરી હોઈ શકે છે, તેથી content માંથી 'eyJ' શોધો
            try:
                # Raw bytes માં 'eyJ' (JWT ની શરૂઆત) શોધો
                content_bytes = res_l.content
                start_idx = content_bytes.find(b'eyJ')
                if start_idx != -1:
                    # JWT ટોકન શોધો (આશરે 500-1000 કેરેક્ટર)
                    extracted = content_bytes[start_idx:].split(b'\x00')[0]
                    jwt_token = extracted.decode('utf-8', errors='ignore')
                    # ફક્ત વેલિડ કેરેક્ટર જ રાખો
                    jwt_token = re.sub(r'[^a-zA-Z0-9\._\-]', '', jwt_token)
                    real_id = extract_id_from_jwt(jwt_token)
            except:
                pass

            return {
                "status": "success",
                "data": {
                    "real_id": real_id,
                    "uid": uid,
                    "password": pwd,
                    "name": full_name,
                    "region": region,
                    "jwt_token": jwt_token[:50] + "..." if jwt_token != "N/A" else "N/A"
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}