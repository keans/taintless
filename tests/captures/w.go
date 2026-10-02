package main

import (
	"os"
	"os/exec"
)

func run() {
	cmd := ""
	load := func() { cmd = os.Getenv("C") }
	load()
	exec.Command("sh", "-c", cmd).Run()
}

func shadow() {
	cmd := ""
	load := func() { cmd := os.Getenv("C"); _ = cmd }
	load()
	exec.Command("sh", "-c", cmd).Run()
}
