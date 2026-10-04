import hashlib as h
from hashlib import md5, sha256 as s2
from hashlib import *
from cryptography.fernet import Fernet as F
import cryptography.hazmat.primitives.hashes as hs
def f(d):
    h.md5(d)
    md5(d)
    s2(d)
    sha1(d)
    F(b"k")
    hs.SHA1()
