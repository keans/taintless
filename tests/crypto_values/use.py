import hashlib
from helpers import default_algorithm, strong_algorithm

BITS = 1
LEVEL = "5"
ALGS = {"fast": "md5", "safe": "sha256"}
ORDER = ["sha256", "sha1"]


def run(data):
    hashlib.new(default_algorithm(), data)
    hashlib.new(strong_algorithm(), data)
    hashlib.new(f"sha{BITS}", data)
    hashlib.new(f"md{LEVEL}", data)
    hashlib.new(ALGS["fast"], data)
    hashlib.new(ALGS["safe"], data)
    hashlib.new(ORDER[1], data)
    hashlib.new(ORDER[0], data)
