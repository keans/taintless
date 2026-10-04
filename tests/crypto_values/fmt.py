import hashlib
from tables import TABLE

BITS = 1
NAME = "md"
ALGS = {}
ALGS["fast"] = "md5"
ALGS["safe"] = "sha256"
ORDER = []
ORDER.append("sha256")
ORDER.append("sha1")


def run(data, other):
    hashlib.new("sha%d" % BITS, data)
    hashlib.new("%s5" % NAME, data)
    hashlib.new("sha{}".format(256), data)
    hashlib.new("{n}{v}".format(n="md", v=5), data)
    hashlib.new("sha%s" % other, data)
    hashlib.new(ALGS["fast"], data)
    hashlib.new(ALGS["safe"], data)
    hashlib.new(ORDER[1], data)
    hashlib.new(TABLE["legacy"], data)


MIXED = {}
MIXED["x"] = "md5"
MIXED["x"] = "sha256"


def mixed(data):
    hashlib.new(MIXED["x"], data)
