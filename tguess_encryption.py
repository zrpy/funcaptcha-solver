from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from Crypto.Cipher import AES
import binascii
import hashlib
import struct
import base64
import json

class Utils:
    @staticmethod
    def convert_salt(words: list, sig_bytes: list) -> list:
        salt = b''
        for word in words:
            salt += struct.pack('>I', word & 0xFFFFFFFF)
        return salt[:sig_bytes]

    @staticmethod
    def int_to_bytes(n: str, length: int) -> bytes:
        return n.to_bytes(length, byteorder='big', signed=True)

    @staticmethod
    def to_sigbytes(words: list, sigBytes: int) -> list:
        result = b''.join(Utils.int_to_bytes(word, 4) for word in words)
        return result[:sigBytes]

    @staticmethod
    def key_to_sigbytes(key: bytes) -> list:
        key_words = []
        for i in range(0, len(key), 4):
            word = struct.unpack('>i', key[i:i+4])[0]
            key_words.append(word)
        return key_words

    @staticmethod
    def from_sigbytes(byte: bytes) -> list:
        padded_length = (len(byte) + 3) // 4 * 4
        padded_bytes = byte.ljust(padded_length, b'\0')

        words = [int.from_bytes(padded_bytes[i:i+4], byteorder='big') for i in range(0, len(padded_bytes), 4)]
        return words

class Encryption:
    @staticmethod
    def generate_key(password: str, salt: bytes, key_size: int, iterations: int) -> bytes:
        hasher = hashlib.md5()
        key = b''
        block = None
        
        while len(key) < key_size:
            if block:
                hasher.update(block)
            hasher.update(password.encode())
            hasher.update(salt)
            block = hasher.digest()
            hasher = hashlib.md5()
            
            for _ in range(1, iterations):
                hasher.update(block)
                block = hasher.digest()
                hasher = hashlib.md5()
            
            key += block
        
        return key[:key_size]
    
    @staticmethod
    def generate_other_key(data: str, salt: list) -> list:
        sig_bytes = 8
        key_size = 48
        iterations = 1
        salt = Utils.convert_salt(salt, sig_bytes)
        key = Encryption.generate_key(data, salt, key_size, iterations)
        return Utils.key_to_sigbytes(key)

    def decrypt(data: str, main: str) -> bytes:
        data = json.loads(data)
        ciphertext = base64.b64decode(data['ct'])
        iv_bytes = binascii.unhexlify(data['iv'])
        salt_bytes = binascii.unhexlify(data['s'])
        salt_words = Utils.from_sigbytes(salt_bytes)
        key_words = Encryption.generate_other_key(main, salt_words)
        key_bytes = Utils.to_sigbytes(key_words, 32)
        iv_bytes = Utils.to_sigbytes(key_words[-4:], 16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()

    def encrypt(plaintext: str, main: str) -> str:
        salt = get_random_bytes(8)
        salt_words = Utils.from_sigbytes(salt)
        key_words = Encryption.generate_other_key(main, salt_words)
        key_bytes = Utils.to_sigbytes(key_words, 32)
        iv_bytes = Utils.to_sigbytes(key_words[-4:], 16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        ciphertext = base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size)))
        return json.dumps({
            'ct': ciphertext.decode(),
            'iv': binascii.hexlify(iv_bytes).decode(),
            's': binascii.hexlify(salt).decode()
        })
    
sessiontoken = '30717f9d16c739a32.6572443605'
guess = '{"ct":"zD2isDRbgZ7MYSHffHif5qYCc2NdumaOAIk/3vl9YBdpF/PZLON/aWVzEwzzRkUp","iv":"43a2a646edb1619a3c6c46746656a94a","s":"70d51865c43d1101"}'
print(Encryption.decrypt(guess, sessiontoken))
