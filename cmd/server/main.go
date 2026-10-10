package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zlci7/bannerlens/internal/api"
	"github.com/zlci7/bannerlens/internal/fingerprint"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	rules := flag.String("rules", "rules/fingerprints.json", "fingerprint rules file")
	healthcheck := flag.Bool("healthcheck", false, "perform an HTTP health probe and exit")
	healthURL := flag.String("health-url", "http://127.0.0.1:8080/health", "HTTP health probe URL")
	maxBody := flag.Int64("max-body-bytes", api.DefaultMaxBodyBytes, "maximum request body size in bytes")
	maxBatch := flag.Int("max-batch", api.DefaultMaxBatch, "maximum records per request")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *healthcheck {
		return probe(*healthURL)
	}
	if *maxBody <= 0 || *maxBatch <= 0 {
		return errors.New("max-body-bytes and max-batch must be positive")
	}
	engine, err := fingerprint.Load(*rules)
	if err != nil {
		return fmt.Errorf("load fingerprint rules: %w", err)
	}
	server := &http.Server{
		Addr: *listen, Handler: api.NewHandler(engine, *maxBody, *maxBatch),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serving := make(chan error, 1)
	go func() { serving <- server.ListenAndServe() }()
	log.Printf("BannerLens listening on %s", *listen)
	select {
	case err := <-serving:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-signalCtx.Done():
		// Restore signal handling so a second interrupt can force termination.
		stop()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shutdown: %w", err)
		}
		err := <-serving
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func probe(url string) error {
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health probe: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned HTTP %d", response.StatusCode)
	}
	return nil
}
