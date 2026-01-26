package keyring

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const (
	keyDirName  = "keys"
	keyFileMode = 0600
)

// Store manages encryption keys/passwords for volumes
type Store struct {
	baseDir string
}

// NewStore creates a new key store
func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not find home directory: %w", err)
	}

	baseDir := filepath.Join(home, ".tinymount", keyDirName)
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("could not create key directory: %w", err)
	}

	return &Store{baseDir: baseDir}, nil
}

// PromptPassword prompts the user for a password (hidden input)
func PromptPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// Try to read password with hidden input
	if term.IsTerminal(int(syscall.Stdin)) {
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // Add newline after hidden input
		if err != nil {
			return "", fmt.Errorf("could not read password: %w", err)
		}
		return string(password), nil
	}

	// Fallback for non-terminal (e.g., piped input)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("could not read password: %w", err)
	}
	return strings.TrimSpace(password), nil
}

// PromptNewPassword prompts for a new password with confirmation
func PromptNewPassword() (string, error) {
	password, err := PromptPassword("🔐 Create encryption password: ")
	if err != nil {
		return "", err
	}

	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}

	confirm, err := PromptPassword("🔐 Confirm password: ")
	if err != nil {
		return "", err
	}

	if password != confirm {
		return "", fmt.Errorf("passwords do not match")
	}

	return password, nil
}

// Save stores a password for a volume
func (s *Store) Save(volumeID, password string) error {
	path := s.keyPath(volumeID)
	if err := os.WriteFile(path, []byte(password), keyFileMode); err != nil {
		return fmt.Errorf("could not save key: %w", err)
	}
	return nil
}

// Load retrieves a password for a volume
func (s *Store) Load(volumeID string) (string, error) {
	path := s.keyPath(volumeID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("key not found for volume %s", volumeID)
		}
		return "", fmt.Errorf("could not read key: %w", err)
	}
	return string(data), nil
}

// Exists checks if a key exists for a volume
func (s *Store) Exists(volumeID string) bool {
	path := s.keyPath(volumeID)
	_, err := os.Stat(path)
	return err == nil
}

// Delete removes a key for a volume
func (s *Store) Delete(volumeID string) error {
	path := s.keyPath(volumeID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not delete key: %w", err)
	}
	return nil
}

// Export copies a key to a specified path (for backup)
func (s *Store) Export(volumeID, destPath string) error {
	password, err := s.Load(volumeID)
	if err != nil {
		return err
	}

	if err := os.WriteFile(destPath, []byte(password), keyFileMode); err != nil {
		return fmt.Errorf("could not export key: %w", err)
	}
	return nil
}

// Import copies a key from a specified path
func (s *Store) Import(volumeID, srcPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("could not read key file: %w", err)
	}

	return s.Save(volumeID, string(data))
}

// Path returns the path to a volume's key file (for user reference)
func (s *Store) Path(volumeID string) string {
	return s.keyPath(volumeID)
}

// keyPath returns the path to a volume's key file
func (s *Store) keyPath(volumeID string) string {
	return filepath.Join(s.baseDir, volumeID+".key")
}

// List returns all stored volume IDs
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, fmt.Errorf("could not read key directory: %w", err)
	}

	var volumeIDs []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".key" {
			volumeID := entry.Name()[:len(entry.Name())-4] // Remove .key extension
			volumeIDs = append(volumeIDs, volumeID)
		}
	}
	return volumeIDs, nil
}
