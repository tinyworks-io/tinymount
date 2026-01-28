package machine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const machineIDFile = "machine_id"

// GetID returns a persistent machine ID for this device.
// The ID is generated once and stored in ~/.tinymount/machine_id
func GetID() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(home, ".tinymount")
	idPath := filepath.Join(configDir, machineIDFile)

	// Check if we already have a machine ID
	if data, err := os.ReadFile(idPath); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id, nil
		}
	}

	// Generate a new machine ID
	id, err := generateMachineID()
	if err != nil {
		return "", err
	}

	// Save it
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(idPath, []byte(id), 0600); err != nil {
		return "", err
	}

	return id, nil
}

// generateMachineID creates a unique machine identifier
func generateMachineID() (string, error) {
	// Try to use system-specific identifiers first
	hostname, _ := os.Hostname()

	// Combine with a UUID for uniqueness
	// This ensures even VMs or containers get unique IDs
	uniquePart := uuid.New().String()

	// Create a deterministic hash from hostname + unique part
	combined := fmt.Sprintf("%s:%s", hostname, uniquePart)
	hash := sha256.Sum256([]byte(combined))

	// Use first 16 bytes (32 hex chars) for the machine ID
	return hex.EncodeToString(hash[:16]), nil
}

// GetName returns a human-readable name for this machine
func GetName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
