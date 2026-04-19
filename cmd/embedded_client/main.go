package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"

	"github.com/define42/muxbridge-e2e/tunnel"
)

var helloPage = template.Must(template.New("hello").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>muxbridge-e2e embedded client</title>
</head>
<body>
  <h1>Hello world</h1>
  <p>Remote IP: {{.RemoteIP}}</p>
</body>
</html>
`))

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := helloPage.Execute(w, struct{ RemoteIP string }{
			RemoteIP: remoteIPFromRequest(r),
		}); err != nil {
			http.Error(w, fmt.Sprintf("render hello page: %v", err), http.StatusInternalServerError)
		}
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client, err := tunnel.New(tunnel.Config{
		EdgeAddr:     "edge.example.com:443",
		SignatureHex: "709b40665c0788fbbc5aeb4f8c7b293b7bdcb138c916436999eb81d453881b78bcaa85d4c92d2af0e63b145c78f8e680a784515b15f20f2de2cac13f4b9c0809",
		Hostnames:    []string{"demo.example.com"},
		Handler:      mux,
		DataDir:      "./certs",
		AcmeEmail:    "ops@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func remoteIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}

	if host, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return host.Addr().String()
	}
	return r.RemoteAddr
}
