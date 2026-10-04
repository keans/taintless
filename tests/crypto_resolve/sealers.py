from Crypto.Cipher import AES
import hashlib

class Encryptor:
    def seal(self, cipher, data):
        return cipher.encrypt(data)

class Decryptor:
    def seal(self, cipher, data):
        return cipher.decrypt(data)

def run(data, k):
    e = Encryptor()
    e.seal(AES.new(k, AES.MODE_ECB), data)
    d = Decryptor()
    d.seal(AES.new(k, AES.MODE_GCM), data)
