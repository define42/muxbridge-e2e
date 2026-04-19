package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestClientRunClosesAfterContextCancellation(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	svc := &stubService{
		wait: done,
	}
	client := &Client{svc: svc}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := client.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if svc.startCalls != 1 {
		t.Fatalf("Start() calls = %d, want %d", svc.startCalls, 1)
	}
	if svc.closeCalls != 1 {
		t.Fatalf("Close() calls = %d, want %d", svc.closeCalls, 1)
	}
}

func TestClientRunReturnsStartError(t *testing.T) {
	t.Parallel()

	client := &Client{svc: &stubService{
		wait:     make(chan struct{}),
		startErr: errors.New("start failed"),
	}}

	err := client.Run(context.Background())
	if err == nil || err.Error() != "start failed" {
		t.Fatalf("Run() error = %v, want %q", err, "start failed")
	}
}

func TestClientRunReturnsCloseError(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	close(done)
	client := &Client{svc: &stubService{
		wait:     done,
		closeErr: context.DeadlineExceeded,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestNewWithProvidedTLSConfigAllowsEmptyDataDirAtStart(t *testing.T) {
	t.Parallel()

	client, err := New(Config{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		Handler:      http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Hostnames:    []string{"demo.example.test"},
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := client.svc.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type stubService struct {
	wait <-chan struct{}

	startCalls int
	closeCalls int

	startErr error
	closeErr error
}

func (s *stubService) Start(context.Context) error {
	s.startCalls++
	return s.startErr
}

func (s *stubService) Wait() <-chan struct{} {
	return s.wait
}

func (s *stubService) Close(context.Context) error {
	s.closeCalls++
	return s.closeErr
}
