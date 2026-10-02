package main

func up()   {}
func down() {}

func dispatch(name string) {
	handlers := map[string]func(){"up": up, "down": down}
	handlers[name]()
}

func each() {
	hs := []func(){up}
	hs = append(hs, down)
	for _, h := range hs {
		h()
	}
}
