from Crypto.Cipher import AES
import hashlib
def copies(d, k):
    c = AES.new(k, AES.MODE_ECB)
    z = c
    z.encrypt(d)
def lists(d, k):
    xs = [AES.new(k, AES.MODE_ECB), AES.new(k, AES.MODE_ECB)]
    xs[1].encrypt(d)
    for h in xs:
        h.encrypt(d)
def appended(d, k):
    ys = []
    ys.append(hashlib.md5())
    ys[0].update(d)
def mixed(d, k):
    ms = [AES.new(k, AES.MODE_ECB), AES.new(k, AES.MODE_GCM)]
    ms[0].encrypt(d)
