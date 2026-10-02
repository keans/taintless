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

type Quiet struct{}

func (q Quiet) Run(cmd string) {}

type Other struct{}

func (o Other) Exec(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

func use(r Runner) {
	r.Run(os.Args[1])
}
