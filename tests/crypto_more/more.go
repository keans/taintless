package main
import (
  "crypto/dsa"
  "golang.org/x/crypto/blowfish"
  "golang.org/x/crypto/ssh"
)
func f(k []byte) {
  blowfish.NewCipher(k)
  ssh.InsecureIgnoreHostKey()
  var p dsa.Parameters
  dsa.GenerateKey(nil, nil)
}
