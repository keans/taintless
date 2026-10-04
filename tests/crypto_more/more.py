from cryptography.hazmat.primitives import hashes
import ssl
from Crypto.Hash import MD5
def f(d):
    hashes.SHA1()
    hashes.SHA256()
    ssl._create_unverified_context()
    MD5.new(d)
