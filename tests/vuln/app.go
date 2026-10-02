package main

func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.FormValue("name")
	exec.Command("sh", "-c", name).Run()
	db.Query("SELECT * FROM t WHERE n='" + name + "'")
	n, _ := strconv.Atoi(r.FormValue("n"))
	db.Query(fmt.Sprintf("SELECT %d", n))
	os.Open(name)
}
