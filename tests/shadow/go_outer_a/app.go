package main

import (
	"os"
	"os/exec"
)

type A struct{}

func (a A) Run(c string) {
	exec.Command("sh", "-c", c).Run()
}

type B struct{}

func (b B) Run(c string) {}

func f() {
	var x A
	{
		var x B
		x.Run(os.Args[1])
	}
	x.Run(os.Args[2])
}
