package main

import (
	"net/http/httptest"
	"testing"
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
