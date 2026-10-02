package main

import (
	"os"
	"os/exec"
)

type Runner struct{}

func (r *Runner) Go(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

type Safe struct{}

func (s *Safe) Go(cmd string) {
	println(cmd)
}

type Svc struct {
	run  *Runner
	safe *Safe
}

func (s *Svc) bad() {
	s.run.Go(os.Getenv("C"))
}

func (s *Svc) good() {
	s.safe.Go(os.Getenv("C"))
}
