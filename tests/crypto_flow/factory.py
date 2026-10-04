from Crypto.Cipher import AES
import hashlib

def make_cipher(key):
    return AES.new(key, AES.MODE_ECB)

def make_hash():
    return hashlib.new("md5")

def encrypt_with(cipher, data):
    return cipher.encrypt(data)

def digest_with(h, data):
    h.update(data)
    return h.hexdigest()
