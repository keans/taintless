package shapes

type Runner interface {
	Run()
}

type A struct{}

func (a A) Run()  {}
func (a A) Stop() {}

type B struct{}

func (b B) Run() {}

type C struct{}

func (c C) Stop() {}

func use(r Runner) {
	r.Run()
}
