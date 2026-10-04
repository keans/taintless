package main
import ("crypto/md5"; "crypto/aes"; "net/http")
func h(b []byte) { md5.Sum(b); aes.NewCipher(b) }
