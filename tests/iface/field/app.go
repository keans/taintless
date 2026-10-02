package main

import (
	"os"
	"os/exec"
)

type Runner interface {
	Run(cmd string)
}

type Shell struct{}

func (s Shell) Run(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

type Svc struct {
	r Runner
}

func (s *Svc) work() {
	s.r.Run(os.Args[1])
}
