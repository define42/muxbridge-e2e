package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
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

	exitCode := runMainHelper(t, "-config /tmp/definitely-missing-edge-config.yaml")
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want %d", exitCode, 1)
	}
}

func TestMainStartsAndStops(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath, keyPath := writeTestCertificateFiles(t, tempDir, "edge.example.test")
	configPath := filepath.Join(tempDir, "edge.yaml")
	configBody := fmt.Sprintf(`public_domain: "example.test"
edge_domain: "edge.example.test"
listen_https: "127.0.0.1:0"
listen_http: "127.0.0.1:0"
data_dir: %q
tls_cert_file: %q
tls_key_file: %q
auth_public_key_hex: "0000000000000000000000000000000000000000000000000000000000000000"
`, filepath.Join(tempDir, "edge-data"), certPath, keyPath)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	exitCode := runMainHelperWithInterrupt(t, "-config "+configPath)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want %d", exitCode, 0)
	}
}

func TestHelperProcessEdgeMain(t *testing.T) {
	if os.Getenv("GO_WANT_EDGE_MAIN_HELPER") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	args := strings.Fields(os.Getenv("EDGE_MAIN_ARGS"))
	os.Args = append([]string{os.Args[0]}, args...)
	main()
}

func runMainHelper(t *testing.T, args string) int {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessEdgeMain")
	cmd.Env = append(os.Environ(),
		"GO_WANT_EDGE_MAIN_HELPER=1",
		"EDGE_MAIN_ARGS="+args,
	)
	return runHelper(t, cmd)
}

func runMainHelperWithInterrupt(t *testing.T, args string) int {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessEdgeMain")
	cmd.Env = append(os.Environ(),
		"GO_WANT_EDGE_MAIN_HELPER=1",
		"EDGE_MAIN_ARGS="+args,
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

func writeTestCertificateFiles(t *testing.T, dir string, dnsName string) (string, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	return certPath, keyPath
}
