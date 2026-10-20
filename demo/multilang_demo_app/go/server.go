package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

type Server struct{ db *sql.DB }

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	rows, err := s.db.Query(fmt.Sprintf("SELECT title FROM posts WHERE title LIKE '%%%s%%'", term))
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	defer rows.Close()
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("sh", "-c", "nslookup "+host).Output()
	w.Write(out)
}

func (s *Server) handleSearchSafe(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	rows, err := s.db.Query("SELECT title FROM posts WHERE title LIKE $1", "%"+term+"%")
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	defer rows.Close()
}

func insecureClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}
