package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/define42/muxbridge-e2e/internal/auth"
)

func TestRunSignsDomain(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	err := run([]string{"-domain", " Demo.Example.Test. "}, func(key string) string {
		if key == privateSeedEnv {
			return "4242424242424242424242424242424242424242424242424242424242424242"
		}
		return ""
	}, &stdout)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	want, err := auth.SignHostname(bytes.Repeat([]byte{0x42}, 32), "demo.example.test")
	if err != nil {
		t.Fatalf("SignHostname() error = %v", err)
	}
	if got != auth.SignatureHex(want) {
		t.Fatalf("stdout = %q, want %q", got, auth.SignatureHex(want))
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		env     string
		wantErr string
	}{
		{
			name:    "missing env",
			args:    []string{"-domain", "demo.example.test"},
			wantErr: privateSeedEnv,
		},
		{
			name:    "bad env",
			args:    []string{"-domain", "demo.example.test"},
			env:     "zz",
			wantErr: "decode private seed hex",
		},
		{
			name:    "bad domain",
			args:    []string{"-domain", "localhost"},
			env:     "4242424242424242424242424242424242424242424242424242424242424242",
			wantErr: "hostname must contain a dot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := run(tt.args, func(key string) string {
				if key == privateSeedEnv {
					return tt.env
				}
				return ""
			}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("run() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
