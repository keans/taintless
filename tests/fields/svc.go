package main

type S struct {
	c string
	n string
}

func (s *S) Load(r *http.Request) {
	s.c = r.FormValue("c")
}

func (s *S) Run() {
	exec.Command(s.c).Run()
	exec.Command(s.n).Run()
}
