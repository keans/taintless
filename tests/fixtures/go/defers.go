package main

func f(x int) int {
	defer a()
	if x > 0 {
		defer b()
		return 1
	}
	defer c()
	return 2
}
