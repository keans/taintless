package main

import (
	"example.com/lib"
	"example.com/lib/sub"
	"example.com/x"
	"example.com/nope"
)

func main() { lib.Do(); sub.S(); x.X(); nope.N() }
