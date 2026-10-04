import hashlib, os
from flask import request
from Crypto.Cipher import AES
def algo():
    name = request.args.get("alg")
    return hashlib.new(name)
def iv():
    iv = request.args.get("iv").encode()
    return AES.new(KEY, AES.MODE_CBC, iv)
def key():
    k = request.form.get("key").encode()
    return AES.new(k, AES.MODE_GCM)
def env_key():
    k = os.environ["APP_KEY"].encode()
    return AES.new(k, AES.MODE_GCM)
def fixed():
    return hashlib.new("sha256")
