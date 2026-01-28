package sync

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tinyworks-io/tinymount/internal/api"
)

const (
	machineIDFile      = "machine_id"
	heartbeatInterval  = 10 * time.Minute // Refresh lock every 10 minutes
)

// Manager handles SQLite metadata sync for Free/PAYG volumes
type Manager struct {
	client    *api.Client
	machineID string
	dataDir   string

	// Heartbeat management
	heartbeats   map[string]chan struct{} // volumeID -> stop channel
	heartbeatsMu sync.Mutex
}

// NewManager creates a new sync manager
func NewManager(client *api.Client) (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not find home directory: %w", err)
	}

	dataDir := filepath.Join(home, ".tinymount", "sync")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("could not create sync directory: %w", err)
	}

	machineID, err := getOrCreateMachineID(dataDir)
	if err != nil {
		return nil, err
	}

	return &Manager{
		client:     client,
		machineID:  machineID,
		dataDir:    dataDir,
		heartbeats: make(map[string]chan struct{}),
	}, nil
}

// MachineID returns the unique machine identifier
func (m *Manager) MachineID() string {
	return m.machineID
}

// MachineName returns a friendly name for this machine
func (m *Manager) MachineName() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return fmt.Sprintf("%s (%s)", hostname, runtime.GOOS)
}

// AcquireLock acquires a mount lock for a volume
func (m *Manager) AcquireLock(volumeID string, force bool) (*api.LockResponse, error) {
	return m.client.AcquireLock(volumeID, api.AcquireLockRequest{
		MachineID:   m.machineID,
		MachineName: m.MachineName(),
		Force:       force,
	})
}

// ReleaseLock releases a mount lock for a volume
func (m *Manager) ReleaseLock(volumeID string) error {
	m.StopHeartbeat(volumeID)
	return m.client.ReleaseLock(volumeID, m.machineID)
}

// StartHeartbeat starts a background goroutine to refresh the lock
func (m *Manager) StartHeartbeat(volumeID string) {
	m.heartbeatsMu.Lock()
	defer m.heartbeatsMu.Unlock()

	// Stop existing heartbeat if any
	if stopCh, exists := m.heartbeats[volumeID]; exists {
		close(stopCh)
	}

	stopCh := make(chan struct{})
	m.heartbeats[volumeID] = stopCh

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				_, err := m.client.RefreshLock(volumeID, m.machineID)
				if err != nil {
					// Log but don't fail - lock will expire eventually
					fmt.Fprintf(os.Stderr, "Warning: Could not refresh lock: %v\n", err)
				}
			}
		}
	}()
}

// StopHeartbeat stops the heartbeat for a volume
func (m *Manager) StopHeartbeat(volumeID string) {
	m.heartbeatsMu.Lock()
	defer m.heartbeatsMu.Unlock()

	if stopCh, exists := m.heartbeats[volumeID]; exists {
		close(stopCh)
		delete(m.heartbeats, volumeID)
	}
}

// MetadataPath returns the path where local metadata is stored for a volume
func (m *Manager) MetadataPath(volumeID string) string {
	return filepath.Join(m.dataDir, volumeID, "metadata.db")
}

// DownloadMetadata downloads the metadata dump from R2 and saves locally
func (m *Manager) DownloadMetadata(volumeID string) (bool, error) {
	resp, err := m.client.DownloadMetadata(volumeID)
	if err != nil {
		return false, err
	}

	if !resp.Exists {
		// No metadata yet - volume is new
		return false, nil
	}

	// Save to local file
	metaPath := m.MetadataPath(volumeID)
	if err := os.MkdirAll(filepath.Dir(metaPath), 0700); err != nil {
		return false, fmt.Errorf("could not create metadata directory: %w", err)
	}

	if err := os.WriteFile(metaPath, resp.Data, 0600); err != nil {
		return false, fmt.Errorf("could not write metadata file: %w", err)
	}

	return true, nil
}

// UploadMetadata reads local metadata and uploads to R2
func (m *Manager) UploadMetadata(volumeID string) error {
	metaPath := m.MetadataPath(volumeID)

	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No metadata to upload
		}
		return fmt.Errorf("could not read metadata file: %w", err)
	}

	_, err = m.client.UploadMetadata(volumeID, data)
	return err
}

// ExportMetadata exports JuiceFS metadata to a dump file
func (m *Manager) ExportMetadata(volumeID, metaURL string) error {
	// Use juicefs dump command
	juicePath, err := exec.LookPath("juicefs")
	if err != nil {
		return fmt.Errorf("juicefs not found: %w", err)
	}

	metaPath := m.MetadataPath(volumeID)
	if err := os.MkdirAll(filepath.Dir(metaPath), 0700); err != nil {
		return err
	}

	cmd := exec.Command(juicePath, "dump", metaURL, metaPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// ImportMetadata imports JuiceFS metadata from a dump file
func (m *Manager) ImportMetadata(volumeID, metaURL string) error {
	metaPath := m.MetadataPath(volumeID)

	// Check if metadata file exists
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		return nil // No metadata to import
	}

	// Use juicefs load command
	juicePath, err := exec.LookPath("juicefs")
	if err != nil {
		return fmt.Errorf("juicefs not found: %w", err)
	}

	cmd := exec.Command(juicePath, "load", metaURL, metaPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// getOrCreateMachineID gets or creates a unique machine identifier
func getOrCreateMachineID(dataDir string) (string, error) {
	idPath := filepath.Join(dataDir, machineIDFile)

	// Try to read existing ID
	if data, err := os.ReadFile(idPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Generate new ID
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("could not generate machine ID: %w", err)
	}
	machineID := "mach_" + hex.EncodeToString(bytes)

	// Save ID
	if err := os.WriteFile(idPath, []byte(machineID), 0600); err != nil {
		return "", fmt.Errorf("could not save machine ID: %w", err)
	}

	return machineID, nil
}
