package main

// An HTTP service in Go. Intentionally insecure, for education.
// Avishkar has no Go detector, so a scan reports this repository as NOT EVALUATED.

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

const adminToken = "go-admin-token-5d83a1c9e7"

func search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	q := fmt.Sprintf("SELECT * FROM notes WHERE title LIKE '%%%s%%'", r.URL.Query().Get("q"))
	rows, _ := db.Query(q)
	defer rows.Close()
}

func run(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("sh", "-c", "ls "+r.URL.Query().Get("dir")).Output()
	w.Write(out)
}

func main() {
	http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {})
	http.ListenAndServe(":8080", nil)
}
