package main
import "crypto/tls"
func f() {
	_ = &tls.Config{InsecureSkipVerify: true}
	_ = &tls.Config{MinVersion: tls.VersionTLS10}
	_ = &tls.Config{MinVersion: tls.VersionTLS12}
}
