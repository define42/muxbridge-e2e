package main

import (
	"flag"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRemoteIPFromRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "ipv4 host port",
			remoteAddr: "192.0.2.10:443",
			want:       "192.0.2.10",
		},
		{
			name:       "ipv6 host port",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			name:       "invalid remote addr falls back",
			remoteAddr: "not-a-host-port",
			want:       "not-a-host-port",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "https://demo.example.com/", nil)
			req.RemoteAddr = tt.remoteAddr

			if got := remoteIPFromRequest(req); got != tt.want {
				t.Fatalf("remoteIPFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}

	if got := remoteIPFromRequest(nil); got != "" {
		t.Fatalf("remoteIPFromRequest(nil) = %q, want empty string", got)
	}
}

func TestMainStartsAndStops(t *testing.T) {
	t.Parallel()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessEmbeddedClientMain")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "GO_WANT_EMBEDDED_CLIENT_MAIN_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if code := helperExitCode(t, err); code != 0 {
			t.Fatalf("exit code = %d, want %d", code, 0)
		}
		return
	case <-time.After(300 * time.Millisecond):
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("cmd.Process.Signal() error = %v", err)
	}

	select {
	case err := <-done:
		if code := helperExitCode(t, err); code != 0 {
			t.Fatalf("exit code = %d, want %d", code, 0)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper process did not exit after interrupt")
	}
}

func TestHelperProcessEmbeddedClientMain(t *testing.T) {
	if os.Getenv("GO_WANT_EMBEDDED_CLIENT_MAIN_HELPER") != "1" {
		return
	}

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	main()
}

func helperExitCode(t *testing.T, err error) int {
	t.Helper()

	if err == nil {
		return 0
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("helper error = %v", err)
	}
	return exitErr.ExitCode()
}
