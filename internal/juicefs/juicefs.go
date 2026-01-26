package juicefs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Client wraps JuiceFS operations
type Client struct {
	binPath string
}

// NewClient creates a new JuiceFS client
func NewClient() (*Client, error) {
	path, err := findBinary()
	if err != nil {
		return nil, err
	}
	return &Client{binPath: path}, nil
}

// findBinary locates the juicefs binary
func findBinary() (string, error) {
	// Check PATH first
	if path, err := exec.LookPath("juicefs"); err == nil {
		return path, nil
	}

	// Check common locations
	locations := []string{
		"/usr/local/bin/juicefs",
		"/usr/bin/juicefs",
		filepath.Join(os.Getenv("HOME"), ".local/bin/juicefs"),
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc, nil
		}
	}

	return "", fmt.Errorf("juicefs not found. Install with: curl -sSL https://d.juicefs.com/install | sh -")
}

// FormatOptions contains options for formatting a volume
type FormatOptions struct {
	MetaURL       string // Redis URL like redis://host:port/db
	VolName       string // Volume name
	Storage       string // Storage type (s3, file, etc.)
	Bucket        string // Bucket URL
	AccessKey     string // S3 access key
	SecretKey     string // S3 secret key
	EncryptKeyPEM string // Path to RSA private key PEM file for encryption (optional)
}

// Format creates a new JuiceFS volume
func (c *Client) Format(opts FormatOptions) error {
	args := []string{
		"format",
		opts.MetaURL,
		opts.VolName,
		"--storage", opts.Storage,
		"--bucket", opts.Bucket,
	}

	// Enable encryption if key provided
	if opts.EncryptKeyPEM != "" {
		args = append(args, "--encrypt-rsa-key", opts.EncryptKeyPEM)
	}

	// Enable LZ4 compression - fast with minimal CPU overhead
	// Reduces R2 transfer time for compressible data
	args = append(args, "--compress", "lz4")

	// Add hash prefix to object keys to prevent hot-sharding in R2
	// Without this, all chunks start with "chunks/0/..." causing hotspots
	args = append(args, "--hash-prefix")

	cmd := exec.Command(c.binPath, args...)
	cmd.Env = append(os.Environ(),
		"ACCESS_KEY="+opts.AccessKey,
		"SECRET_KEY="+opts.SecretKey,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// MountOptions contains options for mounting a volume
type MountOptions struct {
	MetaURL    string // Redis URL
	MountPoint string // Where to mount
	AccessKey  string // S3 access key
	SecretKey  string // S3 secret key
	Background bool   // Run in background
	CacheDir   string // Local cache directory
	CacheSize  string // Cache size (e.g., "1G")
	Writeback  bool   // Enable async writes (faster but less safe)
	// Note: Encryption key is stored in Redis metadata during format, not needed for mount
}

// Mount mounts a JuiceFS volume
func (c *Client) Mount(opts MountOptions) error {
	args := []string{
		"mount",
		opts.MetaURL,
		opts.MountPoint,
	}

	if opts.Background {
		args = append(args, "-d")
	}

	if opts.CacheDir != "" {
		args = append(args, "--cache-dir", opts.CacheDir)
	}

	if opts.CacheSize != "" {
		args = append(args, "--cache-size", opts.CacheSize)
	}

	if opts.Writeback {
		// Async writes - data is written to cache first, then uploaded in background
		// Much faster for interactive use, but data could be lost on crash
		args = append(args, "--writeback")
	}

	// Performance tuning
	args = append(args,
		"--buffer-size", "300",    // 300MB buffer for writes
		"--max-uploads", "20",     // Parallel uploads to R2
		"--prefetch", "3",         // Prefetch 3 blocks ahead for reads
	)

	// Metadata caching - makes repeated reads/ls instant
	// Tradeoff: may show stale metadata for up to 60s
	// Safe: doesn't affect write durability
	args = append(args,
		"--attr-cache", "60",       // Cache file attributes for 60s
		"--entry-cache", "60",      // Cache file entries for 60s
		"--dir-entry-cache", "60",  // Cache directory listings for 60s
		"--open-cache", "60",       // Reuse open file handles for 60s
		"--readdir-cache",          // Enable kernel readdir caching
	)

	cmd := exec.Command(c.binPath, args...)
	cmd.Env = append(os.Environ(),
		"ACCESS_KEY="+opts.AccessKey,
		"SECRET_KEY="+opts.SecretKey,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	if opts.Background {
		// Wait for mount to be ready
		for i := 0; i < 30; i++ {
			time.Sleep(500 * time.Millisecond)
			if isMounted(opts.MountPoint) {
				return nil
			}
		}
		return fmt.Errorf("mount timed out")
	}

	return cmd.Wait()
}

// Unmount unmounts a JuiceFS volume
func (c *Client) Unmount(mountPoint string) error {
	cmd := exec.Command(c.binPath, "umount", mountPoint)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Status returns volume status
func (c *Client) Status(metaURL string) (string, error) {
	cmd := exec.Command(c.binPath, "status", metaURL)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// ConfigOptions contains options for configuring a volume
type ConfigOptions struct {
	MetaURL   string // Metadata URL
	AccessKey string // S3 access key
	SecretKey string // S3 secret key
}

// Config updates the configuration of a JuiceFS volume
// This is needed after loading a metadata dump since secrets are stripped
func (c *Client) Config(opts ConfigOptions) error {
	args := []string{
		"config",
		opts.MetaURL,
		"--access-key", opts.AccessKey,
		"--secret-key", opts.SecretKey,
		"--yes", // Non-interactive
	}

	cmd := exec.Command(c.binPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
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
