package elements
import ("os"; "os/exec")
func cleanMap() {
  d := map[string]string{"a": "ls", "b": os.Getenv("CMD")}
  exec.Command(d["a"])
}
func taintedMap() {
  d := map[string]string{"a": "ls", "b": os.Getenv("CMD")}
  exec.Command(d["b"])
}
func cleanSlice() {
  xs := []string{"ls", os.Getenv("CMD")}
  exec.Command(xs[0])
}
func taintedSlice() {
  xs := []string{"ls", os.Getenv("CMD")}
  exec.Command(xs[1])
}
