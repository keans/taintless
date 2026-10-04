import xxhash, mmh3, zlib
from argon2 import PasswordHasher
import siphash
def f(d, key):
    xxhash.xxh64(d)
    mmh3.hash(d)
    zlib.crc32(d)
    siphash.SipHash_2_4(b"0123456789abcdef", d)
    siphash.SipHash_2_4(key, d)
    PasswordHasher(time_cost=3, memory_cost=1024)
    PasswordHasher(time_cost=3, memory_cost=65536)
