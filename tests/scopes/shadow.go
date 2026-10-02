package scopes

type A struct{}
type B struct{}

func (a *A) Run() {}
func (b *B) Run() {}

func NewA() *A { return &A{} }
func NewB() *B { return &B{} }

func outerResumes() {
	x := NewA()
	{
		x := NewB()
		x.Run()
	}
	x.Run()
}
