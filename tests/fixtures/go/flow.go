package main

import "fmt"

func run(xs []int, mode string) int {
	total := 0
outer:
	for i, x := range xs {
		for j := 0; j < x; j++ {
			if j == 3 {
				continue outer
			}
			if total > 100 {
				break outer
			}
			total += j
		}
		_ = i
	}
	for total > 10 {
		total -= 10
	}
	for {
		total++
		if total > 20 {
			break
		}
	}
	switch mode {
	case "a":
		total++
	case "b", "c":
		total += 2
	default:
		defer fmt.Println("done")
		return -1
	}
	if err := check(total); err != nil {
		panic(err)
	}
	goto end
end:
	return total
}

type T struct{}

func (t T) Method(v int) int {
	if v > 0 {
		return v
	}
	f := func() int { return 1 }
	return f()
}
