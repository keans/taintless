package main

import "os"

type Runner interface {
	Run(cmd string)
}

type Quiet struct{}

func (q Quiet) Run(cmd string) {}

type Shell struct{}

func (s Shell) Exec(cmd string) {}

func use(r Runner) {
	r.Run(os.Args[1])
}
