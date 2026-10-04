import hashlib, hmac, jwt
from flask import request
from Crypto.Cipher import AES
def by_name():
    return hashlib.new(name=request.args.get("alg"))
def jwt_algorithms(tok):
    return jwt.decode(tok, KEY, algorithms=[request.args.get("alg")])
def by_iv_keyword():
    return AES.new(KEY, AES.MODE_CBC, iv=request.args.get("iv"))
def by_key_keyword():
    return AES.new(key=request.form.get("k"), mode=AES.MODE_GCM)
def constant():
    return hashlib.new(name="sha256")
