package main

// A small notes service in Go. Intentionally insecure, for education.

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

const adminToken = "go-admin-token-5d83a1c9e7"

func search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("q")
	q := fmt.Sprintf("SELECT id, title FROM notes WHERE title LIKE '%%%s%%'", term)
	rows, _ := db.Query(q)
	defer rows.Close()
}

func listDir(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("sh", "-c", "ls "+r.FormValue("dir")).Output()
	w.Write(out)
}

func hashPassword(password string) []byte {
	sum := md5.Sum([]byte(password))
	return sum[:]
}

func newSessionToken() int {
	return rand.Int()
}

func download(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile("/srv/notes/" + r.FormValue("name"))
	w.Write(data)
}

func greet(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello %s</h1>", r.FormValue("name"))
}

func fetch(url string) (*http.Response, error) {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	return client.Get(url)
}

func main() {
	http.ListenAndServe(":8080", nil)
}
