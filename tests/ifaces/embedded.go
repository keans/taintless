package shapes

type Base struct{}

func (b Base) Wake() {}

type Waker interface {
	Wake()
	Sleep()
}

type Dog struct {
	Base
}

func (d Dog) Sleep() {}

type Rock struct{}

func (r Rock) Sleep() {}

// Dog gets Wake from the embedded Base, Rock has none: only Dog is a Waker
func alarm(w Waker) {
	w.Wake()
}

func direct(d Dog) {
	d.Wake()
}

type Silent struct {
	Base
}

func embedded_only(s Silent) {
	s.Wake()
}
