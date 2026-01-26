package gocryptfs

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Client wraps gocryptfs operations
type Client struct {
	binPath string
}

// NewClient creates a new gocryptfs client
func NewClient() (*Client, error) {
	path, err := findBinary()
	if err != nil {
		return nil, err
	}
	return &Client{binPath: path}, nil
}

// findBinary locates the gocryptfs binary
func findBinary() (string, error) {
	// Check PATH first
	if path, err := exec.LookPath("gocryptfs"); err == nil {
		return path, nil
	}

	// Check common locations
	locations := []string{
		"/usr/local/bin/gocryptfs",
		"/usr/bin/gocryptfs",
		filepath.Join(os.Getenv("HOME"), ".local/bin/gocryptfs"),
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc, nil
		}
	}

	return "", fmt.Errorf("gocryptfs not found. Install with: apt install gocryptfs (Linux) or brew install gocryptfs (macOS)")
}

// InitOptions contains options for initializing an encrypted directory
type InitOptions struct {
	CipherDir string // Directory to store encrypted files
	Password  string // Encryption password
}

// Init initializes a new encrypted directory
func (c *Client) Init(opts InitOptions) error {
	// Create the cipher directory if it doesn't exist
	if err := os.MkdirAll(opts.CipherDir, 0700); err != nil {
		return fmt.Errorf("failed to create cipher directory: %w", err)
	}

	args := []string{
		"-init",
		"-q", // Quiet mode
		opts.CipherDir,
	}

	cmd := exec.Command(c.binPath, args...)

	// Provide password via stdin
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	// Write password twice (password + confirmation)
	io.WriteString(stdin, opts.Password+"\n")
	stdin.Close()

	return cmd.Wait()
}

// MountOptions contains options for mounting an encrypted directory
type MountOptions struct {
	CipherDir  string // Directory with encrypted files
	MountPoint string // Where to mount decrypted view
	Password   string // Encryption password
	AllowOther bool   // Allow other users to access mount
}

// Mount mounts an encrypted directory
func (c *Client) Mount(opts MountOptions) error {
	// Create mount point if it doesn't exist
	if err := os.MkdirAll(opts.MountPoint, 0700); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}

	args := []string{
		"-q", // Quiet mode
		opts.CipherDir,
		opts.MountPoint,
	}

	if opts.AllowOther {
		args = append(args, "-allow_other")
	}

	cmd := exec.Command(c.binPath, args...)

	// Provide password via stdin
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	io.WriteString(stdin, opts.Password+"\n")
	stdin.Close()

	if err := cmd.Wait(); err != nil {
		return err
	}

	// Wait for mount to be ready
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		if isMounted(opts.MountPoint) {
			return nil
		}
	}

	return fmt.Errorf("mount timed out")
}

// Unmount unmounts an encrypted directory
func (c *Client) Unmount(mountPoint string) error {
	// Try fusermount first (Linux)
	if path, err := exec.LookPath("fusermount"); err == nil {
		cmd := exec.Command(path, "-u", mountPoint)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// Fall back to umount (macOS and others)
	cmd := exec.Command("umount", mountPoint)
	return cmd.Run()
}

// IsInitialized checks if a directory is initialized for gocryptfs
func (c *Client) IsInitialized(cipherDir string) bool {
	configPath := filepath.Join(cipherDir, "gocryptfs.conf")
	_, err := os.Stat(configPath)
	return err == nil
}

// isMounted checks if a path is a mount point
func isMounted(path string) bool {
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), " on "+path+" ") ||
		strings.Contains(string(output), " on "+path+"\n")
}
