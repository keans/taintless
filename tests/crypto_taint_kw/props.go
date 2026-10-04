package main

import (
	"crypto/tls"
	"net/http"
)

func fromRequest(r *http.Request) {
	v := r.URL.Query().Get("v")
	tls.Dial("tcp", "example.org:443", &tls.Config{MinVersion: v})
}

func other(r *http.Request) {
	tls.Dial("tcp", "example.org:443", &tls.Config{ServerName: r.URL.Query().Get("h"), MinVersion: tls.VersionTLS12})
}
