package main
import (
	farm "github.com/dgryski/go-farm"
	"github.com/minio/highwayhash"
	"golang.org/x/crypto/argon2"
)
func f(p, s, key []byte) {
	argon2.IDKey(p, s, 1, 64*1024, 4, 32)
	argon2.IDKey(p, s, 1, 8*1024, 4, 32)
	farm.Hash64(p)
	highwayhash.Sum64(p, key)
}
