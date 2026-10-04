import hashlib

def digest_with(name, data):
    return hashlib.new(name, data)

def use(data):
    digest_with("sha1", data)
