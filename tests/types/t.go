package main

import "os/exec"

type Runner struct{}

func (r *Runner) Go(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

type Safe struct{}

func (s *Safe) Go(cmd string) {
	println(cmd)
}

func NewRunner() *Runner {
	return &Runner{}
}

func viaFactory(c string) {
	r := NewRunner()
	r.Go(os.Getenv("C"))
}

func viaParam(r *Runner, s *Safe) {
	r.Go(os.Getenv("C"))
	s.Go(os.Getenv("C"))
}
