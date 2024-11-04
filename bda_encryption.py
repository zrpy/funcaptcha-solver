from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from funcap_reversed import FunCap
from Crypto.Cipher import AES
import base64, binascii, json

class Encryption:
    def __init__(self, user_agent: str) -> None:
        self.user_agent = user_agent + FunCap.x_ark_value()

    def decrypt(self, data: str, iv: str, s: str) -> str:
        ct = base64.b64decode(data)
        key = FunCap.genkey(self.user_agent, s)
        iv = binascii.unhexlify(iv)
        cipher = AES.new(bytes(key), AES.MODE_CBC, iv)
        text = unpad(cipher.decrypt(ct), AES.block_size)
        return text.decode()

    def encrypt(self, data: str) -> str:
        s = get_random_bytes(8).hex()
        iv = get_random_bytes(16)
        key = FunCap.genkey(self.user_agent, s)
        cipher = AES.new(bytes(key), AES.MODE_CBC, iv)
        text = pad(data.encode(), AES.block_size)
        text = base64.b64encode(cipher.encrypt(text)).decode()
        return text, binascii.hexlify(iv).decode(), s

bda = ""
x = json.loads(base64.b64decode(bda))
inst = Encryption(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
print(inst.decrypt(x["ct"], x["iv"], x["s"]))