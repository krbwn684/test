
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import hashlib
from secret import*
import uid_generator_pb2
import requests
import struct
import datetime
from flask import Flask, jsonify
import json

app = Flask(__name__)
class BufferReader:
    def __init__(self, buffer):
        self.buffer = buffer
        self.offset = 0

    def read_varint(self):
        value, length = decode_varint(self.buffer, self.offset)
        self.offset += length
        return value

    def read_buffer(self, length):
        self.check_byte(length)
        result = self.buffer[self.offset:self.offset + length]
        self.offset += length
        return result

    def try_skip_grpc_header(self):
        backup_offset = self.offset

        if self.buffer[self.offset] == 0 and self.left_bytes() >= 5:
            self.offset += 1
            length = struct.unpack(">I", self.buffer[self.offset:self.offset + 4])[0]
            self.offset += 4

            if length > self.left_bytes():
                self.offset = backup_offset

    def left_bytes(self):
        return len(self.buffer) - self.offset

    def check_byte(self, length):
        bytes_available = self.left_bytes()
        if length > bytes_available:
            raise ValueError(f"Not enough bytes left. Requested: {length}, left: {bytes_available}")

    def checkpoint(self):
        self.saved_offset = self.offset

    def reset_to_checkpoint(self):
        self.offset = self.saved_offset


TYPES = {
    "VARINT": 0,
    "FIXED64": 1,
    "LENDELIM": 2,
    "FIXED32": 5
}


def decode_varint(buffer, offset):
    value = 0
    shift = 0
    length = 0

    while True:
        byte = buffer[offset]
        length += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        offset += 1

    return value, length


def decode_proto(buffer):
    reader = BufferReader(buffer)
    parts = []

    reader.try_skip_grpc_header()

    try:
        while reader.left_bytes() > 0:
            reader.checkpoint()

            index_type = reader.read_varint()
            type_ = index_type & 0b111
            index = index_type >> 3

            if type_ == TYPES["VARINT"]:
                value = reader.read_varint()
            elif type_ == TYPES["LENDELIM"]:
                length = reader.read_varint()
                value = reader.read_buffer(length)
            elif type_ == TYPES["FIXED32"]:
                value = reader.read_buffer(4)
            elif type_ == TYPES["FIXED64"]:
                value = reader.read_buffer(8)
            else:
                raise ValueError(f"Unknown type: {type_}")

            parts.append({
                "index": index,
                "type": type_,
                "value": value
            })
    except Exception as err:
        reader.reset_to_checkpoint()

    return {
        "parts": parts,
        "leftOver": reader.read_buffer(reader.left_bytes())
    }


def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(saturn_, garena):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = saturn_
    message.garena = garena
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()
    
def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()
def apis(idd):
    headers = {
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
    'Connection': 'Keep-Alive',
    'Expect': '100-continue',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjo4NjY5NDQ2NDMwLCJuaWNrbmFtZSI6IlJheXMzQjZQMSIsIm5vdGlfcmVnaW9uIjoiUlUiLCJsb2NrX3JlZ2lvbiI6IlJVIiwiZXh0ZXJuYWxfaWQiOiI0NTAyNzhhZDc0YjA0MmQ0ZjVhYzVhY2RmOTUwYmM3ZSIsImV4dGVybmFsX3R5cGUiOjQsInBsYXRfaWQiOjEsImNsaWVudF92ZXJzaW9uIjoiMS4xMDUuOCIsImVtdWxhdG9yX3Njb3JlIjoxMDAsImlzX2VtdWxhdG9yIjp0cnVlLCJjb3VudHJ5X2NvZGUiOiJVUyIsImV4dGVybmFsX3VpZCI6MzAyNDM3MTg1OCwicmVnX2F2YXRhciI6MTAyMDAwMDA1LCJzb3VyY2UiOjAsImxvY2tfcmVnaW9uX3RpbWUiOjE3MDQxNjYxNDgsImNsaWVudF90eXBlIjoyLCJzaWduYXR1cmVfbWQ1IjoiNzQyOGIyNTNkZWZjMTY0MDE4YzYwNGExZWJiZmViZGYiLCJ1c2luZ192ZXJzaW9uIjoxLCJyZWxlYXNlX2NoYW5uZWwiOiJhbmRyb2lkIiwicmVsZWFzZV92ZXJzaW9uIjoiT0I0NiIsImV4cCI6MTcyNzQ5NzYxNX0.TS6F0rAuyVbdXqlJhiRl5Gcoa1NU_-bMFDcsUPkfV_M',
    'X-Unity-Version': '2018.4.11f1',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB46',
    'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = bytes.fromhex(idd)
    response = requests.post('https://clientbp.ggblueshark.com/GetAccountInfoByAccountID', headers=headers, data=data)

    # Convert response to hexadecimal
    hex_response = response.content.hex()

    return hex_response
@app.route('/<uid>', methods=['GET'])
def main(uid):
    saturn_ = int(uid)
    garena = 1
    protobuf_data = create_protobuf(saturn_, garena)
    hex_data = protobuf_to_hex(protobuf_data)
    aes_key = (key)
    aes_iv = (iv)
    encrypted_hex = encrypt_aes(hex_data, aes_key, aes_iv)
    infoo = apis(encrypted_hex)
    hex_input = infoo
    buffer = hex_to_bytes(hex_input)
    decoded_data = decode_proto(buffer)
    output = {}
    user = None
    level = None
    region = None
    like = None
    clan = "Not in clan"  # Default to "Not in clan"
    rank = None
    last = None
    realses = None
    avatar = "Default"
    banner = "Default"
    create = None
    # Loop through the decoded_data['parts'] to extract values
    for part in decoded_data['parts']:
        if part['type'] == 2 and part['index'] in [3, 5, 13, 50]:
            decoded_value = part['value'].decode('utf-8', errors='replace')
            if part['index'] == 3:
                user = decoded_value
            elif part['index'] == 5:
                region = decoded_value
            elif part['index'] == 13:
                clan = decoded_value if decoded_value else "Not in clan"
            elif part['index'] == 50:
                realses = decoded_value
        elif part['type'] == 0 and part['index'] in [6, 11, 12, 15, 21, 24, 44]:
            if part['index'] == 6:
                level = part['value']
            elif part['index'] == 15:
                rank = part['value']
            elif part['index'] == 21:
                like = part['value']
            elif part['index'] == 24:
                dt_object = datetime.datetime.fromtimestamp(part['value'])
                last = dt_object
            elif part['index'] == 44:
                ssss = datetime.datetime.fromtimestamp(part['value'])
                create = ssss
            elif part['index'] == 11:
                banner = output['banner'] = part['value']  # Banner extraction
            elif part['index'] == 12:
                avatar = output['avatar'] = part['value']


    # Print the formatted output
    json_output = json.dumps(output, default=str, indent=4)
    return {"username": user, "level":level, "region": region, "likes": like, "clan": clan, "brrank": rank, "lastlogin": last, "createat": create, "ob": realses, "banner": banner, "avatar": avatar, "Owners": "Zitado , Redzed"}
if __name__ == "__main__":
    app.run(debug=True)
    
