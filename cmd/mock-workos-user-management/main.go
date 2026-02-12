package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/tower/mock-workos-user-management/internal/handler"
	mockjwt "github.com/tower/mock-workos-user-management/internal/jwt"
	"github.com/tower/mock-workos-user-management/internal/seed"
	"github.com/tower/mock-workos-user-management/internal/store"
)

func main() {
	addr := flag.String("addr", envOr("MOCK_WORKOS_ADDR", ":8091"), "listen address")
	seedPath := flag.String("seed", envOr("MOCK_WORKOS_SEED", ""), "path to seed JSON file")
	signingKey := flag.String("signing-key", envOr("MOCK_WORKOS_SIGNING_KEY", ""), "JWT signing key")
	flag.Parse()

	s := store.New()
	issuer := mockjwt.NewIssuer(*signingKey)

	if *seedPath != "" {
		if err := seed.Load(*seedPath, s); err != nil {
			log.Fatalf("failed to load seed: %v", err)
		}
		log.Printf("loaded seed from %s", *seedPath)
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
