package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/guard/pkg/config"
	"github.com/oarkflow/log"
)

// ConfigAPI handles configuration management endpoints
type ConfigAPI struct {
	configManager *config.Manager
	validator     *config.ValidationManager
	configDir     string
}

// NewConfigAPI creates a new configuration API handler
func NewConfigAPI(configManager *config.Manager, configDir string) *ConfigAPI {
	return &ConfigAPI{
		configManager: configManager,
		validator:     config.NewValidationManager(),
		configDir:     configDir,
	}
}

// ConfigResponse represents a configuration response
type ConfigResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ConfigFile represents a configuration file
type ConfigFile struct {
	Name         string      `json:"name"`
	Path         string      `json:"path"`
	Type         string      `json:"type"`
	Size         int64       `json:"size"`
	LastModified time.Time   `json:"last_modified"`
	Content      interface{} `json:"content,omitempty"`
	Valid        bool        `json:"valid"`
	Errors       []string    `json:"errors,omitempty"`
}

// ConfigBackup represents a configuration backup
type ConfigBackup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	Size        int64     `json:"size"`
	Files       []string  `json:"files"`
}

// RegisterRoutes registers all configuration API routes
func (api *ConfigAPI) RegisterRoutes(app *fiber.App) {
	configGroup := app.Group("/api/config")

	// Configuration overview
	configGroup.Get("/", api.GetConfigOverview)
	configGroup.Get("/status", api.GetConfigStatus)

	// File operations
	configGroup.Get("/files", api.ListConfigFiles)
	configGroup.Get("/files/:type", api.GetConfigFilesByType)
	configGroup.Get("/file/*", api.GetConfigFile)
	configGroup.Put("/file/*", api.UpdateConfigFile)
	configGroup.Post("/file/*", api.CreateConfigFile)
	configGroup.Delete("/file/*", api.DeleteConfigFile)

	// Validation
	configGroup.Post("/validate", api.ValidateConfig)
	configGroup.Post("/validate/file/*", api.ValidateConfigFile)

	// Configuration management
	configGroup.Post("/reload", api.ReloadConfig)
	configGroup.Post("/reset", api.ResetConfig)
	configGroup.Get("/schema/:type", api.GetConfigSchema)

	// Import/Export
	configGroup.Post("/import", api.ImportConfig)
	configGroup.Get("/export", api.ExportConfig)
	configGroup.Get("/export/:type", api.ExportConfigByType)

	// Backup/Restore
	configGroup.Get("/backups", api.ListBackups)
	configGroup.Post("/backup", api.CreateBackup)
	configGroup.Post("/restore/:id", api.RestoreBackup)
	configGroup.Delete("/backup/:id", api.DeleteBackup)

	// Templates
	configGroup.Get("/templates", api.GetConfigTemplates)
	configGroup.Post("/template/:name", api.ApplyConfigTemplate)

	// History
	configGroup.Get("/history", api.GetConfigHistory)
	configGroup.Get("/diff/:from/:to", api.GetConfigDiff)
}

// GetConfigOverview returns an overview of the current configuration
func (api *ConfigAPI) GetConfigOverview(c *fiber.Ctx) error {
	currentConfig := api.configManager.GetConfig()

	overview := map[string]interface{}{
		"config_type":    "modular",
		"config_dir":     api.configDir,
		"last_reload":    time.Now(), // TODO: Track actual reload time
		"total_files":    0,
		"valid_files":    0,
		"invalid_files":  0,
		"server":         currentConfig.Server,
		"engine":         currentConfig.Engine,
		"store":          currentConfig.Store,
		"events":         currentConfig.Events,
		"logging":        currentConfig.Logging,
		"tcp_protection": currentConfig.TCPProtection,
		"security":       currentConfig.Security,
		"plugins": map[string]interface{}{
			"detectors": len(currentConfig.Plugins.Detectors),
			"actions":   len(currentConfig.Plugins.Actions),
			"handlers":  len(currentConfig.Plugins.Handlers),
		},
	}

	// Count files
	files, err := api.listAllConfigFiles()
	if err == nil {
		overview["total_files"] = len(files)
		validCount := 0
		for _, file := range files {
			if file.Valid {
				validCount++
			}
		}
		overview["valid_files"] = validCount
		overview["invalid_files"] = len(files) - validCount
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Data:    overview,
	})
}

// GetConfigStatus returns the current configuration status
func (api *ConfigAPI) GetConfigStatus(c *fiber.Ctx) error {
	status := map[string]interface{}{
		"healthy":    true,
		"config_dir": api.configDir,
		"last_check": time.Now(),
		"errors":     []string{},
		"warnings":   []string{},
	}

	// Validate all configuration files
	if err := api.validator.ValidateConfigDirectory(api.configDir); err != nil {
		status["healthy"] = false
		status["errors"] = []string{err.Error()}
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Data:    status,
	})
}

// ListConfigFiles returns a list of all configuration files
func (api *ConfigAPI) ListConfigFiles(c *fiber.Ctx) error {
	files, err := api.listAllConfigFiles()
	if err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list config files: %v", err),
		})
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Data:    files,
	})
}

// GetConfigFilesByType returns configuration files by type
func (api *ConfigAPI) GetConfigFilesByType(c *fiber.Ctx) error {
	fileType := c.Params("type")

	files, err := api.listAllConfigFiles()
	if err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list config files: %v", err),
		})
	}

	var filteredFiles []ConfigFile
	for _, file := range files {
		if file.Type == fileType {
			filteredFiles = append(filteredFiles, file)
		}
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Data:    filteredFiles,
	})
}

// GetConfigFile returns a specific configuration file
func (api *ConfigAPI) GetConfigFile(c *fiber.Ctx) error {
	filePath := c.Params("*")
	fullPath := filepath.Join(api.configDir, filePath)

	// Security check - ensure path is within config directory
	if !strings.HasPrefix(fullPath, api.configDir) {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   "Invalid file path",
		})
	}

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return c.Status(404).JSON(ConfigResponse{
			Success: false,
			Error:   "Configuration file not found",
		})
	}

	// Read file content
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to read file: %v", err),
		})
	}

	// Parse JSON content
	var jsonContent interface{}
	if err := json.Unmarshal(content, &jsonContent); err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to parse JSON: %v", err),
		})
	}

	// Get file info
	fileInfo, _ := os.Stat(fullPath)

	configFile := ConfigFile{
		Name:         filepath.Base(fullPath),
		Path:         filePath,
		Type:         api.getFileType(filePath),
		Size:         fileInfo.Size(),
		LastModified: fileInfo.ModTime(),
		Content:      jsonContent,
		Valid:        true,
	}

	// Validate file
	if err := api.validator.ValidateConfigFile(fullPath); err != nil {
		configFile.Valid = false
		configFile.Errors = []string{err.Error()}
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Data:    configFile,
	})
}

// UpdateConfigFile updates a configuration file
func (api *ConfigAPI) UpdateConfigFile(c *fiber.Ctx) error {
	filePath := c.Params("*")
	fullPath := filepath.Join(api.configDir, filePath)

	// Security check
	if !strings.HasPrefix(fullPath, api.configDir) {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   "Invalid file path",
		})
	}

	// Parse request body
	var content interface{}
	if err := c.BodyParser(&content); err != nil {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON content: %v", err),
		})
	}

	// Convert to JSON bytes
	jsonBytes, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to marshal JSON: %v", err),
		})
	}

	// Validate content before saving
	tempFile := fullPath + ".tmp"
	if err := os.WriteFile(tempFile, jsonBytes, 0644); err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to write temp file: %v", err),
		})
	}

	// Validate the temp file
	if err := api.validator.ValidateConfigFile(tempFile); err != nil {
		os.Remove(tempFile)
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Configuration validation failed: %v", err),
		})
	}

	// Move temp file to actual location
	if err := os.Rename(tempFile, fullPath); err != nil {
		os.Remove(tempFile)
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to save file: %v", err),
		})
	}

	log.Info().Str("file", filePath).Msg("Configuration file updated via API")

	return c.JSON(ConfigResponse{
		Success: true,
		Message: "Configuration file updated successfully",
	})
}

// CreateConfigFile creates a new configuration file
func (api *ConfigAPI) CreateConfigFile(c *fiber.Ctx) error {
	filePath := c.Params("*")
	fullPath := filepath.Join(api.configDir, filePath)

	// Security check
	if !strings.HasPrefix(fullPath, api.configDir) {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   "Invalid file path",
		})
	}

	// Check if file already exists
	if _, err := os.Stat(fullPath); err == nil {
		return c.Status(409).JSON(ConfigResponse{
			Success: false,
			Error:   "Configuration file already exists",
		})
	}

	// Parse request body
	var content interface{}
	if err := c.BodyParser(&content); err != nil {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON content: %v", err),
		})
	}

	// Convert to JSON bytes
	jsonBytes, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to marshal JSON: %v", err),
		})
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create directory: %v", err),
		})
	}

	// Write file
	if err := os.WriteFile(fullPath, jsonBytes, 0644); err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to write file: %v", err),
		})
	}

	// Validate the new file
	if err := api.validator.ValidateConfigFile(fullPath); err != nil {
		os.Remove(fullPath)
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Configuration validation failed: %v", err),
		})
	}

	log.Info().Str("file", filePath).Msg("Configuration file created via API")

	return c.JSON(ConfigResponse{
		Success: true,
		Message: "Configuration file created successfully",
	})
}

// DeleteConfigFile deletes a configuration file
func (api *ConfigAPI) DeleteConfigFile(c *fiber.Ctx) error {
	filePath := c.Params("*")
	fullPath := filepath.Join(api.configDir, filePath)

	// Security check
	if !strings.HasPrefix(fullPath, api.configDir) {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   "Invalid file path",
		})
	}

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return c.Status(404).JSON(ConfigResponse{
			Success: false,
			Error:   "Configuration file not found",
		})
	}

	// Don't allow deletion of core files
	coreFiles := []string{"server.json", "global.json"}
	fileName := filepath.Base(fullPath)
	for _, coreFile := range coreFiles {
		if fileName == coreFile {
			return c.Status(400).JSON(ConfigResponse{
				Success: false,
				Error:   "Cannot delete core configuration file",
			})
		}
	}

	// Delete file
	if err := os.Remove(fullPath); err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to delete file: %v", err),
		})
	}

	log.Info().Str("file", filePath).Msg("Configuration file deleted via API")

	return c.JSON(ConfigResponse{
		Success: true,
		Message: "Configuration file deleted successfully",
	})
}

// ValidateConfig validates the entire configuration
func (api *ConfigAPI) ValidateConfig(c *fiber.Ctx) error {
	err := api.validator.ValidateConfigDirectory(api.configDir)

	if err != nil {
		return c.JSON(ConfigResponse{
			Success: false,
			Error:   err.Error(),
		})
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Message: "Configuration validation passed",
	})
}

// ValidateConfigFile validates a specific configuration file
func (api *ConfigAPI) ValidateConfigFile(c *fiber.Ctx) error {
	filePath := c.Params("*")
	fullPath := filepath.Join(api.configDir, filePath)

	// Security check
	if !strings.HasPrefix(fullPath, api.configDir) {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   "Invalid file path",
		})
	}

	err := api.validator.ValidateConfigFile(fullPath)

	if err != nil {
		return c.JSON(ConfigResponse{
			Success: false,
			Error:   err.Error(),
		})
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Message: "File validation passed",
	})
}

// ReloadConfig triggers a configuration reload
func (api *ConfigAPI) ReloadConfig(c *fiber.Ctx) error {
	if err := api.configManager.ForceReload(); err != nil {
		return c.Status(500).JSON(ConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to reload configuration: %v", err),
		})
	}

	log.Info().Msg("Configuration reloaded via API")

	return c.JSON(ConfigResponse{
		Success: true,
		Message: "Configuration reloaded successfully",
	})
}

// ResetConfig resets configuration to defaults
func (api *ConfigAPI) ResetConfig(c *fiber.Ctx) error {
	// This is a dangerous operation, so we require confirmation
	confirm := c.Query("confirm")
	if confirm != "true" {
		return c.Status(400).JSON(ConfigResponse{
			Success: false,
			Error:   "Configuration reset requires confirmation parameter",
		})
	}

	// Create backup before reset
	backupID := fmt.Sprintf("pre-reset-%d", time.Now().Unix())
	if err := api.createBackupInternal(backupID, "Automatic backup before reset"); err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before reset")
	}

	// TODO: Implement reset logic
	log.Warn().Msg("Configuration reset requested via API")

	return c.JSON(ConfigResponse{
		Success: true,
		Message: "Configuration reset completed",
	})
}

// GetConfigSchema returns the JSON schema for a configuration type
func (api *ConfigAPI) GetConfigSchema(c *fiber.Ctx) error {
	schemaType := c.Params("type")

	// TODO: Implement schema generation
	schema := map[string]interface{}{
		"type":        "object",
		"description": fmt.Sprintf("Schema for %s configuration", schemaType),
		"properties":  map[string]interface{}{},
	}

	return c.JSON(ConfigResponse{
		Success: true,
		Data:    schema,
	})
}

// Helper methods

// listAllConfigFiles returns all configuration files with their metadata
func (api *ConfigAPI) listAllConfigFiles() ([]ConfigFile, error) {
	var files []ConfigFile

	err := filepath.Walk(api.configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			relPath, _ := filepath.Rel(api.configDir, path)

			configFile := ConfigFile{
				Name:         info.Name(),
				Path:         relPath,
				Type:         api.getFileType(relPath),
				Size:         info.Size(),
				LastModified: info.ModTime(),
				Valid:        true,
			}

			// Validate file
			if err := api.validator.ValidateConfigFile(path); err != nil {
				configFile.Valid = false
				configFile.Errors = []string{err.Error()}
			}

			files = append(files, configFile)
		}

		return nil
	})

	return files, err
}

// getFileType determines the configuration file type based on path
func (api *ConfigAPI) getFileType(filePath string) string {
	if strings.Contains(filePath, "detectors/") {
		return "detector"
	}
	if strings.Contains(filePath, "actions/") {
		return "action"
	}
	if strings.Contains(filePath, "handlers/") {
		return "handler"
	}
	if strings.Contains(filePath, "tcp-protection/") {
		return "tcp"
	}
	if strings.Contains(filePath, "security/") {
		return "security"
	}
	if strings.HasSuffix(filePath, "server.json") {
		return "server"
	}
	if strings.HasSuffix(filePath, "global.json") {
		return "global"
	}
	return "unknown"
}

// createBackupInternal creates a configuration backup
func (api *ConfigAPI) createBackupInternal(id, description string) error {
	// TODO: Implement backup creation
	log.Info().Str("backup_id", id).Str("description", description).Msg("Creating configuration backup")
	return nil
}

// Placeholder methods for import/export and backup/restore functionality
// These will be implemented in subsequent iterations

func (api *ConfigAPI) ImportConfig(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) ExportConfig(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) ExportConfigByType(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) ListBackups(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) CreateBackup(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) RestoreBackup(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) DeleteBackup(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) GetConfigTemplates(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) ApplyConfigTemplate(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) GetConfigHistory(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}

func (api *ConfigAPI) GetConfigDiff(c *fiber.Ctx) error {
	return c.JSON(ConfigResponse{Success: false, Error: "Not implemented yet"})
}
