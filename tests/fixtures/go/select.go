package main

func s(ch chan int, v interface{}) int {
	select {
	case x := <-ch:
		return x
	case ch <- 1:
		return 2
	default:
	}
	switch t := v.(type) {
	case int:
		return t
	case string, bool:
		return 0
	}
	return -1
}
