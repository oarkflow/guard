package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/oarkflow/guard"
	"github.com/oarkflow/guard/pkg/config"
)

func main() {
	// Add flag for config file
	configFile := flag.String("config", "testdata/system_config.json", "Path to configuration file")
	flag.StringVar(configFile, "c", "testdata/system_config.json", "Path to configuration file (shorthand)")
	flag.Parse()

	// Ensure config file exists, create default if missing
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		log.Printf("Config file %s does not exist, creating default...", *configFile)
		cfg := config.CreateDefaultConfig()
		if err := config.SaveConfig(cfg, *configFile); err != nil {
			log.Fatalf("Failed to create default config file: %v", err)
		}
		log.Printf("Default config file created: %s", *configFile)
	}

	// Create application
	app, err := guard.NewApplication(*configFile)
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}

	// Initialize application
	if err := app.Initialize(); err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Received shutdown signal...")
		app.Shutdown()
		os.Exit(0)
	}()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start application
	if err := app.Start(ctx); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}
}
