import hashlib

PREFIX = "sha"
NAME = "md" + "5"
SECRET = "pass" + "word"


def algorithm():
    return "sha" + "1"


def safe():
    return "sha256"


def run(data, suffix):
    a = hashlib.new("MD" + "5", data)
    b = hashlib.new(NAME, data)
    c = hashlib.new(algorithm(), data)
    d = hashlib.new(safe(), data)
    e = hashlib.new("sha" + suffix, data)
    return a, b, c, d, e
