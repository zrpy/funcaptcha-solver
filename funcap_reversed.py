import random, hashlib, time

class FunCap:
    @staticmethod
    def x64hash128(key: str, seed: int = 0) -> str:
        mask = 0xFFFFFFFFFFFFFFFF
        remainder, key_length = len(key) % 16, len(key) - len(key) % 16
        hash1 = hash2 = seed & mask
        const1, const2 = 0x87c37b91114253d5, 0x4cf5ad432745937f
        hex1, hex2 = 0xff51afd7ed558ccd, 0xc4ceb9fe1a85ec53

        def mix(k: int, c1: int, c2: int, shift1: int, shift2: int) -> int:
            return (((((k * c1) & mask) << shift1) | (((k * c1) & mask) >> (64 - shift1))) & mask) * c2 & mask

        for i in range(0, key_length, 16):
            k1 = sum((ord(key[i + j]) & 0xff) << (8 * j) for j in range(8)) & mask
            k2 = sum((ord(key[i + j + 8]) & 0xff) << (8 * j) for j in range(8)) & mask
            hash1 = (((hash1 ^ mix(k1, const1, const2, 31, 27)) << 27) | ((hash1 ^ mix(k1, const1, const2, 31, 27)) >> (64 - 27))) & mask
            hash1 = (hash1 + hash2) * 5 + 0x52dce729 & mask
            hash2 = (((hash2 ^ mix(k2, const2, const1, 33, 31)) << 31) | ((hash2 ^ mix(k2, const2, const1, 33, 31)) >> (64 - 31))) & mask
            hash2 = (hash2 + hash1) * 5 + 0x38495ab5 & mask

        k1 = k2 = 0
        for j in range(remainder):
            shift = 8 * (j - 8 if j >= 8 else j)
            value = (ord(key[key_length + j]) & 0xff) << shift
            if j >= 8: k2 ^= value
            else: k1 ^= value
        if remainder > 8: hash2 ^= mix(k2, const2, const1, 33, 31)
        if remainder > 0: hash1 ^= mix(k1, const1, const2, 31, 27)

        hash1 ^= len(key)
        hash2 ^= len(key)
        hash1 = (hash1 + hash2) & mask
        hash2 = (hash2 + hash1) & mask

        hash1 ^= hash1 >> 33
        hash1 = (hash1 * hex1) & mask
        hash1 ^= hash1 >> 33
        hash1 = (hash1 * hex2) & mask
        hash1 ^= hash1 >> 33

        hash2 ^= hash2 >> 33
        hash2 = (hash2 * hex1) & mask
        hash2 ^= hash2 >> 33
        hash2 = (hash2 * hex2) & mask
        hash2 ^= hash2 >> 33

        hash1 = (hash1 + hash2) & mask
        hash2 = (hash2 + hash1) & mask

        return ("%016x%016x" % (hash1, hash2)).lower()
    
    @staticmethod
    def randsigbyte(count: int) -> list:
        state = 987654321
        max = 0xFFFFFFFF
        bytes = []

        for _ in range(0, count, 4):
            seed = int(4294967296 * random.random())
            state = (36969 * (state & 0xFFFF) + (state >> 16)) & max
            seed = (18000 * (seed & 0xFFFF) + (seed >> 16)) & max
            combined = ((state << 16) + seed) & max
            combined /= 4294967296
            rand = (combined + 0.5) * (1 if random.random() > 0.5 else -1)
            seed = int(987654071 * rand)
            bytes.append(int(4294967296 * rand))

        return bytes

    @staticmethod
    def genkey(t: str, e: str) -> list:
        data = {chr(i): i - ord('0') for i in range(ord('0'), ord('9') + 1)}
        data.update({chr(i): i - ord('a') + 10 for i in range(ord('a'), ord('f') + 1)})
        data.update({chr(i): i - ord('A') + 10 for i in range(ord('A'), ord('F') + 1)})

        u = t + ''.join(chr((data[e[i]] << 4) + data[e[i + 1]]) for i in range(0, len(e), 2))
        s_prev = hashlib.md5(u.encode('latin1')).digest()
        f = s_prev
        for _ in range(1, 3):
            s_curr = hashlib.md5(s_prev + u.encode('latin1')).digest()
            f += s_curr
            s_prev = s_curr

        f = f[:32]
        return list(f)
    
    @staticmethod
    def x_ark_value() -> str:
        now = int(time.time())
        return str(now - (now % 21600))