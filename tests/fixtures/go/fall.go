package main

func a(x int) int {
	switch x {
	case 1:
		x++
		fallthrough
	case 2:
		x += 2
	default:
		x = 0
	}
	return x
}

func b() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = nil
		}
	}()
	panic("boom")
}

func c(v interface{}) int {
	switch v.(type) {
	case int, int64:
		return 1
	}
	return 0
}

func d(ch chan int) {
	select {
	case <-ch:
	}
}
