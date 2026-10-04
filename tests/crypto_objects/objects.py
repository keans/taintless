from Crypto.Cipher import AES, DES


def reassigned(key):
    c = DES.new(key, DES.MODE_ECB)
    c.encrypt(b"x")
    c = AES.new(key, AES.MODE_GCM)
    c.encrypt(b"y")


def branch(key, flag):
    if flag:
        c = DES.new(key, DES.MODE_ECB)
    else:
        c = AES.new(key, AES.MODE_GCM)
    c.encrypt(b"z")


def mixed(key):
    ciphers = [AES.new(key, AES.MODE_GCM), DES.new(key, DES.MODE_ECB)]
    for c in ciphers:
        c.encrypt(b"m")


def dictionary(key):
    d = {"fast": DES.new(key, DES.MODE_ECB), "safe": AES.new(key, AES.MODE_GCM)}
    d["fast"].encrypt(b"a")
    d["safe"].encrypt(b"b")


def filled(key):
    d = {}
    d["old"] = DES.new(key, DES.MODE_ECB)
    d["new"] = AES.new(key, AES.MODE_GCM)
    d["old"].encrypt(b"c")
    d["new"].encrypt(b"d")
