package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/define42/muxbridge-e2e/internal/client"
	"github.com/define42/muxbridge-e2e/internal/config"
)

func main() {
	configPath := flag.String("config", "", "path to client config yaml")
	flag.Parse()
	if *configPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		slog.Error("load config failed", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	service, err := client.New(cfg, client.Options{Logger: logger})
	if err != nil {
		logger.Error("create client failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := service.Start(ctx); err != nil {
		logger.Error("start client failed", "error", err)
		os.Exit(1)
	}
	logger.Info("client started", "edge_addr", cfg.EdgeAddr)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := service.Close(shutdownCtx); err != nil {
		logger.Error("client shutdown failed", "error", err)
		os.Exit(1)
	}
}
