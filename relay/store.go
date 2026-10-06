package main

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Status values a request moves through. "pending" is the only state that
// accepts a response or a deny; every other state is final.
const (
	statusPending   = "pending"
	statusResponded = "responded"
	statusDenied    = "denied"
)

var (
	errExists   = errors.New("request already exists")
	errFull     = errors.New("too many pending requests")
	errNotFound = errors.New("request not found")
	errNotOpen  = errors.New("request is no longer pending")
)

// entry is one request as the relay holds it. raw is the exact request bytes
// keymaster sent. The page hashes those bytes for the WebAuthn challenge, so
// the relay never re-encodes them.
type entry struct {
	id       string
	kind     string
	raw      []byte
	exp      time.Time
	status   string
	response json.RawMessage
	// done is closed when status leaves pending, waking long-polls.
	done chan struct{}
}

// store keeps requests in memory only. A request lives a few minutes at most,
// so a restart drops in-flight requests and nothing else.
type store struct {
	mu      sync.Mutex
	entries map[string]*entry
	max     int
	now     func() time.Time
}

func newStore(max int) *store {
	return &store{entries: map[string]*entry{}, max: max, now: time.Now}
}

func (s *store) create(id, kind string, raw []byte, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if _, ok := s.entries[id]; ok {
		return errExists
	}
	if len(s.entries) >= s.max {
		return errFull
	}
	s.entries[id] = &entry{
		id:     id,
		kind:   kind,
		raw:    raw,
		exp:    exp,
		status: statusPending,
		done:   make(chan struct{}),
	}
	return nil
}

// snapshot is a copy of an entry that is safe to use without the lock.
type snapshot struct {
	kind     string
	raw      []byte
	exp      time.Time
	status   string
	response json.RawMessage
	done     <-chan struct{}
}

func (s *store) get(id string) (snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok || !s.now().Before(e.exp) {
		return snapshot{}, errNotFound
	}
	return snapshot{kind: e.kind, raw: e.raw, exp: e.exp, status: e.status, response: e.response, done: e.done}, nil
}

// respond stores the phone's response. Only the first response or deny
// counts, so a second submission can't replace an assertion keymaster may
// already be verifying.
func (s *store) respond(id string, response json.RawMessage) error {
	return s.finish(id, statusResponded, response)
}

func (s *store) deny(id string) error {
	return s.finish(id, statusDenied, nil)
}

func (s *store) finish(id, status string, response json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok || !s.now().Before(e.exp) {
		return errNotFound
	}
	if e.status != statusPending {
		return errNotOpen
	}
	e.status = status
	e.response = response
	close(e.done)
	return nil
}

func (s *store) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *store) sweepLocked() {
	now := s.now()
	for id, e := range s.entries {
		if !now.Before(e.exp) {
			delete(s.entries, id)
		}
	}
}
