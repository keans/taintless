package main

import (
	"example.com/app/pkg2"
	"os"
)

func main() {
	pkg2.Run(os.Args[1])
}
