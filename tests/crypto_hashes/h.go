package main
import (
	"hash/crc32"
	"hash/fnv"
	"golang.org/x/crypto/argon2"
)
func f(p, s []byte) {
	crc32.ChecksumIEEE(p)
	fnv.New32a()
	argon2.IDKey(p, s, 1, 8*1024, 4, 32)
	argon2.IDKey(p, s, 1, 4096, 4, 32)
	argon2.Key(p, s, 3, 65536, 4, 32)
}
