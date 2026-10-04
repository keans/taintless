import hashlib


def run(data):
    hashlib.new("md%1d" % 5, data)
    hashlib.new("sha{:03d}".format(1), data)
    hashlib.new("%.3s" % "md5xyz", data)
