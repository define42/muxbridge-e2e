package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/define42/muxbridge-e2e/tunnel"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "hello world")
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client, err := tunnel.New(tunnel.Config{
		EdgeAddr:  "edge.example.com:443",
		Token:     "demo-token",
		Hostnames: []string{"demo.example.com"},
		Handler:   mux,
		DataDir:   "./certs",
		AcmeEmail: "ops@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
