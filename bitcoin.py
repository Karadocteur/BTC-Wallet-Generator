import os
import hashlib



def sha256(data):
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()

def ripemd160(data):
    digest = hashlib.new("ripemd160")
    digest.update(data)
    return digest.digest()

def b58(data):
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if data[0] == 0:
        return "1" + b58(data[1:])
    x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
    ret = ""
    while x > 0:
        ret = B58[x % 58] + ret
        x = x // 58
    return ret



class ECDSAPoint:
    def __init__(self,
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        p=2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1):
        self.x = x
        self.y = y
        self.p = p

    def __add__(self, other):
        return self.__radd__(other)

    def __mul__(self, other):
        return self.__rmul__(other)

    def __rmul__(self, other):
        n = self
        q = None
        for i in range(256):
            if other & (1 << i):
                q = q + n
            n = n + n
        return q

    def __radd__(self, other):
        if other is None:
            return self
        x1 = other.x
        y1 = other.y
        x2 = self.x
        y2 = self.y
        p = self.p
        if self == other:
            l = pow(2 * y2 % p, p-2, p) * (3 * x2 * x2) % p
        else:
            l = pow(x1 - x2, p-2, p) * (y1 - y2) % p
        newX = (l ** 2 - x2 - x1) % p
        newY = (l * x2 - l * newX - y2) % p
        return ECDSAPoint(newX, newY)

    def toBytes(self, compressed):
        x = self.x.to_bytes(32, "big")
        y = self.y.to_bytes(32, "big")
        if compressed:
            if (self.y % 2) == 0:
                return b"\x02" + x
            else:
                return b"\x03" + x
        else:
            return b"\x04" + x + y
        


class Wallet:

    def __init__(self, private_key = None):
        if private_key == None:
            self.private_key = self.new_private_key()
        else:
            self.private_key = private_key
        self.address_uncompressed = None
        self.address_compressed = None
        self.wif_uncompressed = None
        self.wif_compressed = None

    def new_private_key(self):
        return os.urandom(32)

    def get_address(self, compressed):
        SPEC256k1 = ECDSAPoint()
        pk = int.from_bytes(self.private_key, "big")
        hash160 = ripemd160(sha256((SPEC256k1 * pk).toBytes(compressed)))
        address = b"\x00" + hash160
        address = b58(address + sha256(sha256(address))[:4])
        return address

    def get_wif(self, compressed):
        if compressed:
            wif = b"\x80" + self.private_key + b"\x01"
        else:
            wif = b"\x80" + self.private_key
        wif = b58(wif + sha256(sha256(wif))[:4])
        return wif

    def get_address_uncompressed(self):
        if self.address_uncompressed == None:
            self.address_uncompressed = self.get_address(compressed = False)
        return self.address_uncompressed

    def get_address_compressed(self):
        if self.address_compressed == None:
            self.address_compressed = self.get_address(compressed = True)
        return self.address_compressed

    def get_wif_uncompressed(self):
        if self.wif_uncompressed == None:
            self.wif_uncompressed = self.get_wif(compressed = False)
        return self.wif_uncompressed

    def get_wif_compressed(self):
        if self.wif_compressed == None:
            self.wif_compressed = self.get_wif(compressed = True)
        return self.wif_compressed



if __name__ == "__main__":
    wallet = Wallet()
    print("----------")
    print("     Bitcoin Wallet Generator")
    print("----------")
    print("     WIF uncompressed     :", wallet.get_wif_uncompressed())
    print("     Address uncompressed :", wallet.get_address_uncompressed())
    print("----------")
    print("     WIF compressed       :", wallet.get_wif_compressed())
    print("     Address compressed   :", wallet.get_address_compressed())
    print("----------")
    print("     Karadocteur, from https://karadocteur.fr")
    print("----------")
    os.system("pause")