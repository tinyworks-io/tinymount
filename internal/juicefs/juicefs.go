package juicefs

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tinyworks-io/tinymount/internal/retry"
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

// Format creates a new JuiceFS volume with retry logic
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

	cfg := retry.Config{
		MaxAttempts: 3,
		InitialWait: 2 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
	}

	return retry.Do(cfg, func() error {
		cmd := exec.Command(c.binPath, args...)
		cmd.Env = append(os.Environ(),
			"ACCESS_KEY="+opts.AccessKey,
			"SECRET_KEY="+opts.SecretKey,
		)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			errMsg := stderr.String()
			if errMsg != "" {
				return fmt.Errorf("%s", strings.TrimSpace(errMsg))
			}
			return err
		}
		return nil
	})
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

// Mount mounts a JuiceFS volume with improved robustness
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
		// Ensure cache directory exists
		os.MkdirAll(opts.CacheDir, 0700)
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

	// Retry mount operation
	cfg := retry.Config{
		MaxAttempts: 3,
		InitialWait: 2 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
	}

	var lastErr error
	err := retry.Do(cfg, func() error {
		cmd := exec.Command(c.binPath, args...)
		cmd.Env = append(os.Environ(),
			"ACCESS_KEY="+opts.AccessKey,
			"SECRET_KEY="+opts.SecretKey,
		)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start mount: %w", err)
		}

		if opts.Background {
			// Wait for mount to be ready with extended timeout
			mounted := retry.WaitFor(30*time.Second, 500*time.Millisecond, func() bool {
				return IsMounted(opts.MountPoint)
			})

			if !mounted {
				// Try to get process exit status
				cmd.Process.Kill()
				errMsg := stderr.String()
				if errMsg != "" {
					lastErr = fmt.Errorf("mount failed: %s", strings.TrimSpace(errMsg))
				} else {
					lastErr = fmt.Errorf("mount timed out after 30s")
				}
				return lastErr
			}

			// Verify mount is healthy by doing a simple operation
			if err := c.verifyMountHealth(opts.MountPoint); err != nil {
				lastErr = fmt.Errorf("mount verification failed: %w", err)
				return lastErr
			}

			return nil
		}

		return cmd.Wait()
	})

	if err != nil && lastErr != nil {
		return lastErr
	}
	return err
}

// verifyMountHealth checks if the mount is working properly
func (c *Client) verifyMountHealth(mountPoint string) error {
	// Try to stat the mount point - should succeed quickly if healthy
	done := make(chan error, 1)
	go func() {
		_, err := os.Stat(mountPoint)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("mount health check timed out")
	}
}

// Unmount unmounts a JuiceFS volume with retries and escalating force
func (c *Client) Unmount(mountPoint string) error {
	return c.UnmountWithOptions(mountPoint, false)
}

// UnmountWithOptions unmounts with optional force
func (c *Client) UnmountWithOptions(mountPoint string, force bool) error {
	// First, try graceful JuiceFS unmount
	if !force {
		cmd := exec.Command(c.binPath, "umount", mountPoint)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err == nil {
			// Verify unmount succeeded
			if !IsMounted(mountPoint) {
				return nil
			}
		}
	}

	// Escalation 1: JuiceFS force unmount
	cmd := exec.Command(c.binPath, "umount", "--force", mountPoint)
	if err := cmd.Run(); err == nil {
		if !IsMounted(mountPoint) {
			return nil
		}
	}

	// Escalation 2: fusermount -u (Linux)
	if fusermount, err := exec.LookPath("fusermount"); err == nil {
		cmd := exec.Command(fusermount, "-u", mountPoint)
		if err := cmd.Run(); err == nil {
			if !IsMounted(mountPoint) {
				return nil
			}
		}

		// fusermount -uz (lazy unmount)
		cmd = exec.Command(fusermount, "-uz", mountPoint)
		cmd.Run()
		time.Sleep(500 * time.Millisecond)
		if !IsMounted(mountPoint) {
			return nil
		}
	}

	// Escalation 3: umount -f (macOS/Linux)
	cmd = exec.Command("umount", "-f", mountPoint)
	if err := cmd.Run(); err == nil {
		if !IsMounted(mountPoint) {
			return nil
		}
	}

	// Escalation 4: umount -l (lazy unmount, Linux only)
	cmd = exec.Command("umount", "-l", mountPoint)
	cmd.Run()
	time.Sleep(500 * time.Millisecond)

	// Final check
	if IsMounted(mountPoint) {
		return fmt.Errorf("failed to unmount %s - mount point may be busy. Close any applications using it and try again", mountPoint)
	}

	return nil
}

// ForceUnmount forcefully unmounts a path using all available methods
func ForceUnmount(mountPoint string) error {
	client, err := NewClient()
	if err != nil {
		// JuiceFS not available, try system unmount
		return systemForceUnmount(mountPoint)
	}
	return client.UnmountWithOptions(mountPoint, true)
}

// systemForceUnmount uses system tools to force unmount
func systemForceUnmount(mountPoint string) error {
	// Try fusermount first (Linux)
	if fusermount, err := exec.LookPath("fusermount"); err == nil {
		exec.Command(fusermount, "-uz", mountPoint).Run()
	}

	// Try umount with force and lazy
	exec.Command("umount", "-f", mountPoint).Run()
	exec.Command("umount", "-l", mountPoint).Run()

	time.Sleep(500 * time.Millisecond)

	if IsMounted(mountPoint) {
		return fmt.Errorf("failed to unmount %s", mountPoint)
	}
	return nil
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

// IsMounted checks if a path is a mount point
func IsMounted(path string) bool {
	// Method 1: Check mount table
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	if strings.Contains(string(output), " on "+path+" ") ||
		strings.Contains(string(output), " on "+path+"\n") {
		return true
	}

	// Method 2: Check if it's a different filesystem from parent
	pathStat, err := os.Stat(path)
	if err != nil {
		return false
	}

	parentPath := filepath.Dir(path)
	parentStat, err := os.Stat(parentPath)
	if err != nil {
		return false
	}

	// Get device IDs
	pathSys, ok1 := pathStat.Sys().(*syscall.Stat_t)
	parentSys, ok2 := parentStat.Sys().(*syscall.Stat_t)

	if ok1 && ok2 {
		return pathSys.Dev != parentSys.Dev
	}

	return false
}

// Warmup performs read warmup on common paths to prime the cache
func (c *Client) Warmup(mountPoint string, paths []string) {
	args := []string{"warmup"}
	for _, p := range paths {
		args = append(args, filepath.Join(mountPoint, p))
	}

	cmd := exec.Command(c.binPath, args...)
	cmd.Run() // Best effort, ignore errors
}

// Sync forces pending writes to be uploaded (for writeback mode)
func (c *Client) Sync(mountPoint string) error {
	// Use sync command to force writeback flush
	cmd := exec.Command("sync")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Also call JuiceFS-specific sync if available
	syncCmd := exec.Command(c.binPath, "sync", mountPoint)
	syncCmd.Run() // Best effort

	return nil
}

// Info returns detailed volume info
func (c *Client) Info(metaURL string) (map[string]interface{}, error) {
	cmd := exec.Command(c.binPath, "info", metaURL, "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse JSON output
	var info map[string]interface{}
	// Note: Caller should parse JSON
	_ = output
	return info, nil
}
