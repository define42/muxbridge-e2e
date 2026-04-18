package main

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
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
	err := cmd.Run()
	if err == nil {
		return 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("cmd.Run() error = %v", err)
	}
	return exitErr.ExitCode()
}
