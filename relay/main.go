// Command relay passes keymaster remote-approval requests to a phone and the
// phone's WebAuthn responses back. It holds no keys and approves nothing:
// keymaster verifies every response itself. See docs/remote-approval.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const maxPending = 256

func main() {
	listen := flag.String("listen", envOr("RELAY_LISTEN", ":8080"), "address to listen on (RELAY_LISTEN)")
	healthcheck := flag.Bool("healthcheck", false, "check that the relay on -listen answers, then exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck(*listen))
	}

	token, err := loadToken()
	if err != nil {
		log.Fatal(err)
	}
	st := newStore(maxPending)
	srv, err := newServer(st, token)
	if err != nil {
		log.Fatal(err)
	}
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Long-polls hold a response open for up to pollWait.
		WriteTimeout: pollWait + 10*time.Second,
		IdleTimeout:  2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				st.sweep()
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()

	log.Printf("keymaster relay %s listening on %s", version, *listen)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// loadToken reads the relay token from RELAY_TOKEN_FILE (for Docker secrets)
// or RELAY_TOKEN. keymaster sends it to create requests and read results.
func loadToken() (string, error) {
	token := os.Getenv("RELAY_TOKEN")
	if path := os.Getenv("RELAY_TOKEN_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading RELAY_TOKEN_FILE: %w", err)
		}
		token = strings.TrimSpace(string(data))
	}
	if len(token) < 32 {
		return "", errors.New("set RELAY_TOKEN or RELAY_TOKEN_FILE to a token of at least 32 characters")
	}
	return token, nil
}

func runHealthcheck(listen string) int {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthz returned", resp.Status)
		return 1
	}
	return 0
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
