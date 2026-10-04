package main

import (
	"github.com/dgryski/go-metro"
	"github.com/dgryski/go-spooky"
)

func f(p []byte) {
	metro.Hash64(p, 0)
	spooky.Hash64(p)
}
