package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oarkflow/guard/pkg/config"
	"github.com/oarkflow/log"
)

func main() {
	var (
		sourceFile = flag.String("source", "", "Source configuration file to migrate")
		targetDir  = flag.String("target", "config", "Target directory for modular configuration")
		validate   = flag.Bool("validate", false, "Validate configuration files after migration")
		help       = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *sourceFile == "" {
		fmt.Fprintf(os.Stderr, "Error: source file is required\n")
		showHelp()
		os.Exit(1)
	}

	// Check if source file exists
	if _, err := os.Stat(*sourceFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: source file %s does not exist\n", *sourceFile)
		os.Exit(1)
	}

	// Convert relative paths to absolute
	absSource, err := filepath.Abs(*sourceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get absolute path for source: %v\n", err)
		os.Exit(1)
	}

	absTarget, err := filepath.Abs(*targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get absolute path for target: %v\n", err)
		os.Exit(1)
	}

	log.Info().Str("source", absSource).Str("target", absTarget).Msg("Starting configuration migration")

	// Perform migration
	migrator := config.NewConfigMigrator(absSource, absTarget)
	if err := migrator.MigrateToModular(); err != nil {
		fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Successfully migrated configuration from %s to %s\n", absSource, absTarget)

	// Validate migrated configuration if requested
	if *validate {
		log.Info().Msg("Validating migrated configuration...")
		validator := config.NewValidationManager()
		if err := validator.ValidateConfigDirectory(absTarget); err != nil {
			fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Configuration validation passed")
	}

	// Show next steps
	fmt.Println("\n📋 Next steps:")
	fmt.Printf("1. Review the migrated configuration files in: %s\n", absTarget)
	fmt.Println("2. Update your application to use the new config directory")
	fmt.Println("3. Test the application with the new configuration")
	fmt.Printf("4. Remove the old configuration file: %s (after testing)\n", absSource)
}

func showHelp() {
	fmt.Println("Guard Configuration Migration Tool")
	fmt.Println()
	fmt.Println("This tool migrates single-file configuration to modular configuration structure.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  migrate -source <config-file> [-target <config-dir>] [-validate]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -source string")
	fmt.Println("        Source configuration file to migrate (required)")
	fmt.Println("  -target string")
	fmt.Println("        Target directory for modular configuration (default: config)")
	fmt.Println("  -validate")
	fmt.Println("        Validate configuration files after migration")
	fmt.Println("  -help")
	fmt.Println("        Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  migrate -source system_config.json")
	fmt.Println("  migrate -source testdata/system_config.json -target ./config -validate")
	fmt.Println()
	fmt.Println("The tool will create the following structure:")
	fmt.Println("  config/")
	fmt.Println("  ├── server.json")
	fmt.Println("  ├── global.json")
	fmt.Println("  ├── detectors/")
	fmt.Println("  │   ├── sql-injection-rules.json")
	fmt.Println("  │   ├── rate-limit-rules.json")
	fmt.Println("  │   └── ...")
	fmt.Println("  ├── actions/")
	fmt.Println("  │   ├── block-action-rules.json")
	fmt.Println("  │   └── ...")
	fmt.Println("  ├── handlers/")
	fmt.Println("  ├── tcp-protection/")
	fmt.Println("  └── security/")
}
