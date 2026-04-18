package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/define42/muxbridge-e2e/internal/config"
	"github.com/define42/muxbridge-e2e/internal/edge"
)

func main() {
	configPath := flag.String("config", "", "path to edge config yaml")
	flag.Parse()
	if *configPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.LoadEdgeConfig(*configPath)
	if err != nil {
		slog.Error("load config failed", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	service := edge.New(cfg, edge.Options{Logger: logger})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := service.Start(ctx); err != nil {
		logger.Error("start edge failed", "error", err)
		os.Exit(1)
	}
	logger.Info("edge started", "https_addr", service.HTTPSAddr(), "http_addr", service.HTTPAddr())

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := service.Close(shutdownCtx); err != nil {
		logger.Error("edge shutdown failed", "error", err)
		os.Exit(1)
	}
}
