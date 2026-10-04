from Crypto.Cipher import AES

def encrypt_inner(cipher, data):
    return cipher.encrypt(data)

def encrypt_middle(handle, data):
    return encrypt_inner(handle, data)

def encrypt_outer(c, data):
    return encrypt_middle(c, data)

def run(data, k):
    encrypt_outer(AES.new(k, AES.MODE_ECB), data)
