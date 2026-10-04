package main
import (
  m "crypto/md5"
  "crypto/sha1"
)
func f(b []byte) { m.Sum(b); sha1.Sum(b) }
