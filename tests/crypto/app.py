import hashlib
from cryptography.fernet import Fernet
def f(d):
    k = Fernet.generate_key()
    return Fernet(k).encrypt(d), hashlib.sha256(d).hexdigest(), hashlib.md5(d)
from Crypto.Cipher import AES
def g(k):
    return AES.new(k, AES.MODE_ECB)
