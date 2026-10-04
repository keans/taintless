from Crypto.PublicKey import RSA
import oqs
def f():
    RSA.generate(1024)
    oqs.KeyEncapsulation("ML-KEM-768")
