package main

func (s *Svc) viaField() {
	s.r.run()
}

func (s *Svc) viaAlias() {
	s.r2.run()
}

func (s *Svc) shadowed() {
	var x Runner
	{
		var x Other
		x.run()
	}
	x.run()
}

func viaAliasParam(a R) {
	a.run()
}

func (h *H) viaDefined() {
	h.r.run()
}
