package shapes

type Runner interface {
	Run()
	Stop()
}

type Closer interface {
	Close()
}

type Both interface {
	Closer
	Run()
}

type A struct{}

func (a A) Run()   {}
func (a A) Stop()  {}
func (a A) Close() {}

type B struct{}

func (b B) Run() {}

type C struct{}

func (c C) Run()   {}
func (c C) Close() {}

type Svc struct {
	r Runner
}

// the interface is only declared on the field; nothing here is called on a parameter of that type
func (s *Svc) Go() {
	s.r.Run()
}

// B has Run but not Stop: it does not satisfy Runner
func local() {
	var r Runner
	r.Run()
}

func embedded(b Both) {
	b.Run()
}
