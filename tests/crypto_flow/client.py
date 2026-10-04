from factory import make_cipher, make_hash, encrypt_with, digest_with
from Crypto.Cipher import AES

def run(data):
    c = make_cipher(b"k" * 16)
    c.encrypt(data)
    h = make_hash()
    h.update(data)
    encrypt_with(AES.new(b"k" * 16, AES.MODE_CBC, b"i" * 16), data)
    return digest_with(h, data)
