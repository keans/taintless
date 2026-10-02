package main

type Runner struct{}

func (r *Runner) run() {}

type Other struct{}

func (o *Other) run() {}

type Svc struct {
	r *Runner
}

func (s *Svc) go_() {
	s.r.run()
}

func (s *Svc) local() {
	var x Runner
	x.run()
}
