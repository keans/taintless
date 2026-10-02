package main

type Runner struct{}

type Other struct{}

// an alias: calls on an R are calls on a Runner
type R = Runner

type Svc struct {
	r  *Runner
	r2 R
}

// a defined type: has Holder's fields, not its methods
type Holder struct {
	r *Runner
}

type H Holder
