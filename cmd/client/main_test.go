package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMainRequiresConfigFlag(t *testing.T) {
	t.Parallel()

	exitCode := runMainHelper(t, "")
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want %d", exitCode, 2)
	}
}

func TestMainFailsForMissingConfigFile(t *testing.T) {
	t.Parallel()

	exitCode := runMainHelper(t, "-config /tmp/definitely-missing-client-config.yaml")
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want %d", exitCode, 1)
	}
}

func TestMainStartsAndStops(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "client.yaml")
	configBody := fmt.Sprintf(`edge_addr: "127.0.0.1:1"
signature_hex: "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
data_dir: %q
acme_email: "ops@example.test"
reconnect_min: "10ms"
reconnect_max: "20ms"
routes:
  demo.example.test: "http://127.0.0.1:8080"
`, filepath.Join(t.TempDir(), "client-data"))
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	exitCode := runMainHelperWithInterrupt(t, "-config "+configPath)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want %d", exitCode, 0)
	}
}

func TestHelperProcessClientMain(t *testing.T) {
	if os.Getenv("GO_WANT_CLIENT_MAIN_HELPER") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	args := strings.Fields(os.Getenv("CLIENT_MAIN_ARGS"))
	os.Args = append([]string{os.Args[0]}, args...)
	main()
}

func runMainHelper(t *testing.T, args string) int {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessClientMain")
	cmd.Env = append(os.Environ(),
		"GO_WANT_CLIENT_MAIN_HELPER=1",
		"CLIENT_MAIN_ARGS="+args,
	)
	return runHelper(t, cmd)
}

func runMainHelperWithInterrupt(t *testing.T, args string) int {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessClientMain")
	cmd.Env = append(os.Environ(),
		"GO_WANT_CLIENT_MAIN_HELPER=1",
		"CLIENT_MAIN_ARGS="+args,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return helperExitCode(t, err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("cmd.Process.Signal() error = %v", err)
	}

	select {
	case err := <-done:
		return helperExitCode(t, err)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper process did not exit after interrupt")
		return 0
	}
}

func runHelper(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()

	err := cmd.Run()
	return helperExitCode(t, err)
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
