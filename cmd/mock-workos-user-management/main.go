package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tower/mock-workos-user-management/internal/handler"
	mockjwt "github.com/tower/mock-workos-user-management/internal/jwt"
	"github.com/tower/mock-workos-user-management/internal/seed"
	"github.com/tower/mock-workos-user-management/internal/store"
)

type stringSlice []string

func (s *stringSlice) String() string  { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	addr := flag.String("addr", envOr("MOCK_WORKOS_ADDR", ":8092"), "listen address")
	var seedPaths stringSlice
	if v := envOr("MOCK_WORKOS_SEED", ""); v != "" {
		seedPaths = append(seedPaths, v)
	}
	flag.Var(&seedPaths, "seed", "path to seed JSON file (repeatable; files that don't exist are silently skipped)")
	signingKey := flag.String("signing-key", envOr("MOCK_WORKOS_SIGNING_KEY", ""), "JWT signing key")
	flag.Parse()

	s := store.New()
	issuer := mockjwt.NewIssuer(*signingKey)

	for _, path := range seedPaths {
		loaded, err := seed.LoadIfExists(path, s)
		if err != nil {
			log.Fatalf("failed to load seed %s: %v", path, err)
		}
		if loaded {
			log.Printf("loaded seed from %s", path)
		} else {
			log.Printf("seed file not found, skipping: %s", path)
		}
	}

	h := handler.New(s, issuer)

	srv := &http.Server{Addr: *addr, Handler: h}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down")
		srv.Shutdown(context.Background())
	}()

	log.Printf("mock-workos-user-management listening on %s", *addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
