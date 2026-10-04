from flask import request
from Crypto.Cipher import AES
KEY = b"0" * 16
def iv_by_keyword():
    return AES.new(mode=AES.MODE_CBC, iv=request.args.get("iv"), key=KEY)
def key_by_keyword():
    return AES.new(mode=AES.MODE_GCM, key=request.form.get("k"))
def clean():
    return AES.new(mode=AES.MODE_GCM, key=KEY, nonce=b"1" * 12)
