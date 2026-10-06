package main

import (
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

//go:embed web
var webFiles embed.FS

const (
	maxBodyBytes = 16 << 10
	maxLifetime  = 15 * time.Minute
	pollWait     = 25 * time.Second
)

// A request id is 128 random bits, base64url without padding. It doubles as
// the capability in the phone's URL, so anything shorter is refused.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

type server struct {
	store *store
	token []byte
	page  []byte
	now   func() time.Time
}

func newServer(st *store, token string) (*server, error) {
	page, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		return nil, err
	}
	return &server{store: st, token: []byte(token), page: page, now: time.Now}, nil
}

func (s *server) routes() http.Handler {
	static, _ := fs.Sub(webFiles, "web")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /r/{id}", s.handlePage)
	mux.HandleFunc("POST /api/requests", s.requireToken(s.handleCreate))
	mux.HandleFunc("GET /api/requests/{id}", s.handleGet)
	mux.HandleFunc("POST /api/requests/{id}/response", s.handleRespond)
	mux.HandleFunc("POST /api/requests/{id}/deny", s.handleDeny)
	mux.HandleFunc("GET /api/requests/{id}/result", s.requireToken(s.handleResult))
	return securityHeaders(mux)
}

// securityHeaders applies to every response. Capability URLs must not leak
// through Referer or caches, and the page loads nothing from anywhere else.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), s.token) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or wrong relay token")
			return
		}
		next(w, r)
	}
}

func (s *server) handlePage(w http.ResponseWriter, r *http.Request) {
	if !idPattern.MatchString(r.PathValue("id")) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(s.page)
}

// requestFields are the parts of a request the relay reads. It needs the id,
// kind and expiry to store the request, and ignores everything else.
type requestFields struct {
	V    int    `json:"v"`
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Exp  int64  `json:"exp"`
}

func (s *server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Request string `json:"request"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Request)
	if err != nil {
		writeError(w, http.StatusBadRequest, "request is not base64url")
		return
	}
	var f requestFields
	if err := json.Unmarshal(raw, &f); err != nil {
		writeError(w, http.StatusBadRequest, "request is not JSON")
		return
	}
	now := s.now()
	exp := time.Unix(f.Exp, 0)
	switch {
	case f.V != 1:
		writeError(w, http.StatusBadRequest, "unsupported request version")
		return
	case !idPattern.MatchString(f.ID):
		writeError(w, http.StatusBadRequest, "request id must be 22 base64url characters")
		return
	case f.Kind != "approve" && f.Kind != "enroll":
		writeError(w, http.StatusBadRequest, "request kind must be approve or enroll")
		return
	case !exp.After(now) || exp.Sub(now) > maxLifetime:
		writeError(w, http.StatusBadRequest, "request expiry must be in the next 15 minutes")
		return
	}
	switch err := s.store.create(f.ID, f.Kind, raw, exp); {
	case errors.Is(err, errExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, errFull):
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	log.Printf("created %s request %s… expiring in %s", f.Kind, f.ID[:6], exp.Sub(now).Round(time.Second))
	writeJSON(w, http.StatusCreated, map[string]string{"status": statusPending})
}

func (s *server) handleGet(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "request not found or expired")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"request": base64.RawURLEncoding.EncodeToString(snap.raw),
		"status":  snap.status,
	})
}

// handleRespond stores whatever the phone sent, as long as it is a JSON
// object. keymaster verifies it; the relay can't tell a good assertion from
// a bad one and doesn't try.
func (s *server) handleRespond(w http.ResponseWriter, r *http.Request) {
	var response map[string]json.RawMessage
	if err := decodeBody(w, r, &response); err != nil || response == nil {
		writeError(w, http.StatusBadRequest, "response must be a JSON object")
		return
	}
	raw, _ := json.Marshal(response)
	s.finish(w, r, s.store.respond(r.PathValue("id"), raw), "response")
}

// handleDeny needs no proof from the phone. A forged deny only blocks a
// request, which anyone holding the relay could do anyway.
func (s *server) handleDeny(w http.ResponseWriter, r *http.Request) {
	s.finish(w, r, s.store.deny(r.PathValue("id")), "deny")
}

func (s *server) finish(w http.ResponseWriter, r *http.Request, err error, what string) {
	switch {
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "request not found or expired")
	case errors.Is(err, errNotOpen):
		writeError(w, http.StatusConflict, "request already answered")
	default:
		log.Printf("%s for request %s…", what, r.PathValue("id")[:6])
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleResult long-polls: it answers as soon as the request leaves pending,
// or with "pending" after pollWait so keymaster can poll again.
func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap, err := s.store.get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "request not found or expired")
		return
	}
	if snap.status == statusPending {
		timer := time.NewTimer(min(pollWait, time.Until(snap.exp)))
		defer timer.Stop()
		select {
		case <-snap.done:
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
		if snap, err = s.store.get(id); err != nil {
			writeError(w, http.StatusNotFound, "request not found or expired")
			return
		}
	}
	result := map[string]any{"status": snap.status}
	if snap.response != nil {
		result["response"] = snap.response
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(v); err != nil {
		return errors.New("body must be a JSON object under 16 KiB")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
