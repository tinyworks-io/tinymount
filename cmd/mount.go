package cmd

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const rcloneVersion = "v1.65.2"

// mountLegacyCmd mounts a volume to a local path using rclone (legacy)
var mountLegacyCmd = &cobra.Command{
	Use:   "mount-legacy <volume-id> <path>",
	Short: "Mount a volume using rclone (legacy, use 'mount' instead)",
	Long: `Mount a volume to a local path.

On macOS, uses WebDAV (no kernel extensions or sudo required).
On Linux, uses FUSE.

Examples:
  tinymount mount vol_abc123 /mnt/mydata
  tinymount mount vol_abc123 ~/mydata`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		volumeID := args[0]
		mountPath := args[1]

		// Expand ~ to home directory
		if strings.HasPrefix(mountPath, "~") {
			home, err := os.UserHomeDir()
			if err != nil {
				fail("Could not expand home directory: %v", err)
			}
			mountPath = filepath.Join(home, mountPath[1:])
		}

		// Make path absolute
		absPath, err := filepath.Abs(mountPath)
		if err != nil {
			fail("Could not resolve path: %v", err)
		}
		mountPath = absPath

		// Check platform
		if runtime.GOOS == "windows" {
			fail("Windows is not supported yet. Use WSL2 instead.")
		}

		// Get or download rclone
		rclonePath, err := ensureRclone()
		if err != nil {
			fail("Could not get rclone: %v", err)
		}

		// Get volume credentials
		resp, err := client.GetVolume(volumeID)
		if err != nil {
			fail("Could not get volume: %v", err)
		}

		// Create mount point if it doesn't exist
		if err := os.MkdirAll(mountPath, 0755); err != nil {
			fail("Could not create mount point: %v", err)
		}

		// Check if already mounted
		if isMounted(mountPath) {
			fail("%s is already mounted. Unmount first with: tinymount unmount %s", mountPath, mountPath)
		}

		// Build credentials struct
		creds := MountCredentials{
			Endpoint:        resp.Mount.Endpoint,
			Bucket:          resp.Mount.Bucket,
			AccessKeyID:     resp.Mount.AccessKeyID,
			SecretAccessKey: resp.Mount.SecretAccessKey,
			SessionToken:    resp.Mount.SessionToken,
			SizeBytes:       resp.Volume.SizeBytes,
		}

		if runtime.GOOS == "darwin" {
			// macOS: Use NFS serve + native mount (requires sudo but no FUSE/kernel extensions)
			mountViaNFS(rclonePath, mountPath, volumeID, creds)
		} else {
			// Linux: Use FUSE mount
			mountViaFUSE(rclonePath, mountPath, volumeID, creds)
		}
	},
}

// mountViaWebDAV mounts using rclone serve webdav + Finder (macOS)
// No sudo required, no kernel extensions needed
func mountViaWebDAV(rclonePath, mountPath, volumeID string, creds MountCredentials) {
	// Find an available port for WebDAV server
	port := findAvailablePort(20000, 30000)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Build a simple remote - use only provider inline, rest via env vars
	// This avoids URL parsing issues with colons
	simpleRemote := fmt.Sprintf(":s3,provider=Cloudflare:%s", creds.Bucket)

	// Start rclone WebDAV server in background
	webdavArgs := []string{
		"serve", "webdav",
		simpleRemote,
		"--addr", addr,
		"--vfs-cache-mode", "off", // Disable cache to avoid path length issues
	}

	webdavCmd := exec.Command(rclonePath, webdavArgs...)

	// Pass all credentials via environment variables to avoid parsing issues
	webdavCmd.Env = append(os.Environ(),
		"RCLONE_S3_ACCESS_KEY_ID="+creds.AccessKeyID,
		"RCLONE_S3_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
		"RCLONE_S3_ENDPOINT="+creds.Endpoint,
	)
	if creds.SessionToken != "" {
		webdavCmd.Env = append(webdavCmd.Env, "RCLONE_S3_SESSION_TOKEN="+creds.SessionToken)
	}

	// Write logs to a file for debugging
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".tinymount", "logs")
	os.MkdirAll(logDir, 0755)
	logFile, _ := os.Create(filepath.Join(logDir, fmt.Sprintf("webdav-%s.log", volumeID)))
	if logFile != nil {
		webdavCmd.Stdout = logFile
		webdavCmd.Stderr = logFile
	}

	if err := webdavCmd.Start(); err != nil {
		fail("Could not start WebDAV server: %v", err)
	}

	// Save the PID for later unmounting
	mountsDir := filepath.Join(home, ".tinymount", "mounts")
	os.MkdirAll(mountsDir, 0755)

	pidFile := filepath.Join(mountsDir, volumeID+".pid")
	os.WriteFile(pidFile, []byte(strconv.Itoa(webdavCmd.Process.Pid)), 0644)

	portFile := filepath.Join(mountsDir, volumeID+".port")
	os.WriteFile(portFile, []byte(strconv.Itoa(port)), 0644)

	// Wait for WebDAV server to be ready
	fmt.Print("Starting WebDAV server...")
	ready := false
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
	}
	if !ready {
		webdavCmd.Process.Kill()
		os.Remove(pidFile)
		os.Remove(portFile)
		fail("WebDAV server failed to start. Check logs at ~/.tinymount/logs/")
	}
	fmt.Println(" ready")

	// On macOS, mount_webdav is finicky. Use osascript to mount via Finder instead
	script := fmt.Sprintf(`
		tell application "Finder"
			mount volume "http://127.0.0.1:%d/"
		end tell
	`, port)

	appleScript := exec.Command("osascript", "-e", script)
	output, err := appleScript.CombinedOutput()
	if err != nil {
		// Finder mount failed, fall back to manual instructions
		fmt.Printf("\nWebDAV server running at: http://127.0.0.1:%d/\n", port)
		fmt.Println("\nTo mount in Finder:")
		fmt.Println("  1. Press Cmd+K (Connect to Server)")
		fmt.Printf("  2. Enter: http://127.0.0.1:%d/\n", port)
		fmt.Println("  3. Click Connect")
		fmt.Printf("\nOr create a symlink after mounting:\n")
		fmt.Printf("  ln -s /Volumes/127.0.0.1 %s\n", mountPath)
		fmt.Println("\nTo stop the server:")
		fmt.Printf("  tinymount unmount %s\n", volumeID)
		return
	}

	// Finder mounted it - it'll be at /Volumes/127.0.0.1 or similar
	_ = output

	// Create symlink from user's requested path to the actual mount
	finderMountPath := "/Volumes/127.0.0.1"
	if _, err := os.Stat(finderMountPath); err == nil {
		// Remove the directory we created (it's empty) and replace with symlink
		os.RemoveAll(mountPath)
		if err := os.Symlink(finderMountPath, mountPath); err != nil {
			fmt.Printf("\nNote: Could not create symlink at %s: %v\n", mountPath, err)
			fmt.Printf("Volume is available at %s\n", finderMountPath)
		} else {
			success("Mounted %s at %s", volumeID, mountPath)
			fmt.Printf("\n(Symlinked to %s)\n", finderMountPath)
		}
	} else {
		success("Mounted %s", volumeID)
		fmt.Println("\nVolume available in Finder and at /Volumes/")
	}

	// Save the mount path for unmounting
	pathFile := filepath.Join(mountsDir, volumeID+".path")
	os.WriteFile(pathFile, []byte(mountPath), 0644)

	fmt.Println("\nTo unmount:")
	fmt.Printf("  tinymount unmount %s\n", volumeID)
}

// MountCredentials holds R2 credentials
type MountCredentials struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	SizeBytes       int64
}

// mountViaNFS mounts using rclone serve nfs + native mount_nfs (macOS)
// Requires sudo but no FUSE or kernel extensions
func mountViaNFS(rclonePath, mountPath, volumeID string, creds MountCredentials) {
	// Find an available port for NFS server
	port := findAvailablePort(20000, 30000)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Build remote string
	simpleRemote := fmt.Sprintf(":s3,provider=Cloudflare:%s", creds.Bucket)

	// Format size for rclone with suffix (e.g., "1G", "500M")
	sizeStr := formatSizeForRclone(creds.SizeBytes)

	// Start rclone NFS server in background
	nfsArgs := []string{
		"serve", "nfs",
		simpleRemote,
		"--addr", addr,
		"--vfs-cache-mode", "full",
		"--vfs-disk-space-total-size", sizeStr,
		"--vfs-used-is-size",
	}

	nfsCmd := exec.Command(rclonePath, nfsArgs...)

	// Pass all credentials via environment variables
	nfsCmd.Env = append(os.Environ(),
		"RCLONE_S3_ACCESS_KEY_ID="+creds.AccessKeyID,
		"RCLONE_S3_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
		"RCLONE_S3_ENDPOINT="+creds.Endpoint,
	)
	if creds.SessionToken != "" {
		nfsCmd.Env = append(nfsCmd.Env, "RCLONE_S3_SESSION_TOKEN="+creds.SessionToken)
	}

	// Write logs to a file for debugging
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".tinymount", "logs")
	os.MkdirAll(logDir, 0755)
	logFile, _ := os.Create(filepath.Join(logDir, fmt.Sprintf("nfs-%s.log", volumeID)))
	if logFile != nil {
		nfsCmd.Stdout = logFile
		nfsCmd.Stderr = logFile
	}

	if err := nfsCmd.Start(); err != nil {
		fail("Could not start NFS server: %v", err)
	}

	// Save the PID for later unmounting
	mountsDir := filepath.Join(home, ".tinymount", "mounts")
	os.MkdirAll(mountsDir, 0755)

	pidFile := filepath.Join(mountsDir, volumeID+".pid")
	os.WriteFile(pidFile, []byte(strconv.Itoa(nfsCmd.Process.Pid)), 0644)

	portFile := filepath.Join(mountsDir, volumeID+".port")
	os.WriteFile(portFile, []byte(strconv.Itoa(port)), 0644)

	// Wait for NFS server to be ready
	fmt.Print("Starting NFS server...")
	ready := false
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		// Try to connect to the port
		conn, err := exec.Command("nc", "-z", "127.0.0.1", strconv.Itoa(port)).CombinedOutput()
		_ = conn
		if err == nil {
			ready = true
			break
		}
	}
	if !ready {
		nfsCmd.Process.Kill()
		os.Remove(pidFile)
		os.Remove(portFile)
		fail("NFS server failed to start. Check logs at ~/.tinymount/logs/")
	}
	fmt.Println(" ready")

	// Mount using mount_nfs with sudo
	// Format: sudo mount_nfs -o port=PORT,mountport=PORT 127.0.0.1:/ /path
	mountArgs := []string{
		"mount_nfs",
		"-o", fmt.Sprintf("port=%d,mountport=%d,nfsvers=3,tcp,nolocks", port, port),
		"127.0.0.1:/",
		mountPath,
	}

	fmt.Println("Mounting (requires sudo)...")
	mountExec := exec.Command("sudo", mountArgs...)
	mountExec.Stdout = os.Stdout
	mountExec.Stderr = os.Stderr
	mountExec.Stdin = os.Stdin

	if err := mountExec.Run(); err != nil {
		nfsCmd.Process.Kill()
		os.Remove(pidFile)
		os.Remove(portFile)
		fail("Could not mount NFS: %v", err)
	}

	// Save mount path for unmounting
	pathFile := filepath.Join(mountsDir, volumeID+".path")
	os.WriteFile(pathFile, []byte(mountPath), 0644)

	success("Mounted %s at %s", volumeID, mountPath)
	fmt.Println("\nTo unmount:")
	fmt.Printf("  tinymount unmount %s\n", volumeID)
}

// mountViaFUSE mounts using rclone mount with FUSE (Linux)
func mountViaFUSE(rclonePath, mountPath, volumeID string, creds MountCredentials) {
	// Check if FUSE is available on Linux
	if _, err := os.Stat("/dev/fuse"); os.IsNotExist(err) {
		fail("FUSE not available. Install fuse: sudo apt install fuse")
	}

	// Build remote string - use only provider inline, rest via env vars
	remote := fmt.Sprintf(":s3,provider=Cloudflare:%s", creds.Bucket)

	// Format size for rclone with suffix (e.g., "1G", "500M")
	sizeStr := formatSizeForRclone(creds.SizeBytes)

	rcloneArgs := []string{
		"mount",
		remote,
		mountPath,
		"--vfs-cache-mode", "full",
		"--vfs-disk-space-total-size", sizeStr,
		"--vfs-used-is-size",
		"--daemon",
	}

	rcloneCmd := exec.Command(rclonePath, rcloneArgs...)

	// Pass all credentials via environment variables
	rcloneCmd.Env = append(os.Environ(),
		"RCLONE_S3_ACCESS_KEY_ID="+creds.AccessKeyID,
		"RCLONE_S3_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
		"RCLONE_S3_ENDPOINT="+creds.Endpoint,
	)
	if creds.SessionToken != "" {
		rcloneCmd.Env = append(rcloneCmd.Env, "RCLONE_S3_SESSION_TOKEN="+creds.SessionToken)
	}

	rcloneCmd.Stdout = os.Stdout
	rcloneCmd.Stderr = os.Stderr

	if err := rcloneCmd.Start(); err != nil {
		fail("Could not start rclone: %v", err)
	}

	success("Mounted %s at %s", volumeID, mountPath)
	fmt.Println("\nUnmount with:")
	fmt.Printf("  tinymount unmount %s\n", mountPath)
}

// unmountLegacyCmd unmounts a volume (legacy rclone-based)
var unmountLegacyCmd = &cobra.Command{
	Use:     "unmount-legacy <volume-id-or-path>",
	Aliases: []string{"umount-legacy"},
	Short:   "Unmount a volume (legacy, use 'unmount' instead)",
	Long: `Unmount a volume.

On macOS, provide the volume ID to stop the WebDAV server.
On Linux, provide the mount path.

Examples:
  tinymount unmount vol_abc123
  tinymount unmount /mnt/mydata`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		home, _ := os.UserHomeDir()
		mountsDir := filepath.Join(home, ".tinymount", "mounts")

		// Check if it's a volume ID (macOS style)
		pidFile := filepath.Join(mountsDir, target+".pid")
		if _, err := os.Stat(pidFile); err == nil {
			// It's a volume ID - first unmount the NFS mount, then kill the server
			pathFile := filepath.Join(mountsDir, target+".path")
			if pathData, err := os.ReadFile(pathFile); err == nil {
				mountedPath := string(pathData)
				// Resolve symlinks (e.g., /tmp -> /private/tmp on macOS)
				resolvedPath := mountedPath
				if resolved, err := filepath.EvalSymlinks(mountedPath); err == nil {
					resolvedPath = resolved
				}
				// Check if it's actually mounted (not just a symlink)
				if info, err := os.Lstat(mountedPath); err == nil {
					if info.Mode()&os.ModeSymlink != 0 {
						// It's a symlink (WebDAV style) - just remove it
						os.Remove(mountedPath)
					} else if isMounted(mountedPath) {
						// It's a real mount (NFS style) - unmount with sudo using resolved path
						fmt.Println("Unmounting (requires sudo)...")
						umountCmd := exec.Command("sudo", "umount", resolvedPath)
						umountCmd.Stdout = os.Stdout
						umountCmd.Stderr = os.Stderr
						umountCmd.Stdin = os.Stdin
						if err := umountCmd.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "Warning: unmount may have failed: %v\n", err)
						}
						// Give the system a moment to clean up
						time.Sleep(500 * time.Millisecond)
					}
				}
			}
			os.Remove(pathFile)

			// Kill the server process
			if pidData, err := os.ReadFile(pidFile); err == nil {
				if pid, err := strconv.Atoi(string(pidData)); err == nil {
					if proc, err := os.FindProcess(pid); err == nil {
						proc.Kill()
						proc.Wait()
					}
				}
			}

			os.Remove(pidFile)
			os.Remove(filepath.Join(mountsDir, target+".port"))

			// Also try to unmount from /Volumes if it's there (WebDAV fallback)
			volumePath := "/Volumes/127.0.0.1"
			if _, err := os.Stat(volumePath); err == nil {
				exec.Command("umount", volumePath).Run()
			}

			success("Stopped %s", target)
			return
		}

		// It's a path - unmount it directly
		mountPath := target

		// Expand ~ to home directory
		if strings.HasPrefix(mountPath, "~") {
			mountPath = filepath.Join(home, mountPath[1:])
		}

		// Make path absolute
		absPath, err := filepath.Abs(mountPath)
		if err != nil {
			fail("Could not resolve path: %v", err)
		}
		mountPath = absPath

		// Unmount the filesystem
		var umountCmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			umountCmd = exec.Command("umount", mountPath)
		case "linux":
			umountCmd = exec.Command("fusermount", "-u", mountPath)
		default:
			fail("Unsupported platform: %s", runtime.GOOS)
		}

		umountCmd.Stdout = os.Stdout
		umountCmd.Stderr = os.Stderr

		if err := umountCmd.Run(); err != nil {
			fail("Could not unmount: %v", err)
		}

		success("Unmounted %s", mountPath)
	},
}

func init() {
	rootCmd.AddCommand(mountLegacyCmd)
	rootCmd.AddCommand(unmountLegacyCmd)
}

// isMounted checks if a path is already a mount point
func isMounted(path string) bool {
	// Use mount command to check
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	// Check if path appears in mount output
	// Also check the resolved path (e.g., /tmp -> /private/tmp on macOS)
	if strings.Contains(string(output), " on "+path+" ") {
		return true
	}
	// Try resolving symlinks (handles /tmp -> /private/tmp)
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
		return strings.Contains(string(output), " on "+resolved+" ")
	}
	return false
}

// sanitizePath converts a path to a safe filename
func sanitizePath(path string) string {
	return strings.ReplaceAll(strings.ReplaceAll(path, "/", "_"), ":", "_")
}

// findAvailablePort finds an available TCP port in the given range
func findAvailablePort(start, end int) int {
	// For simplicity, just use a hash of the current time
	// In production, you'd actually check if the port is available
	return start + int(time.Now().UnixNano()%int64(end-start))
}

// formatSizeForRclone converts bytes to rclone's SizeSuffix format (e.g., "1G", "500M")
func formatSizeForRclone(bytes int64) string {
	const (
		_        = iota
		kilobyte = 1 << (10 * iota)
		megabyte
		gigabyte
		terabyte
	)

	switch {
	case bytes >= terabyte:
		return fmt.Sprintf("%dT", bytes/terabyte)
	case bytes >= gigabyte:
		return fmt.Sprintf("%dG", bytes/gigabyte)
	case bytes >= megabyte:
		return fmt.Sprintf("%dM", bytes/megabyte)
	case bytes >= kilobyte:
		return fmt.Sprintf("%dK", bytes/kilobyte)
	default:
		return fmt.Sprintf("%d", bytes)
	}
}

// ensureRclone checks if rclone is available, downloading it if necessary
func ensureRclone() (string, error) {
	// First check if rclone is in PATH
	if path, err := exec.LookPath("rclone"); err == nil {
		return path, nil
	}

	// Check our local cache
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	binDir := filepath.Join(home, ".tinymount", "bin")
	rclonePath := filepath.Join(binDir, "rclone")
	if runtime.GOOS == "windows" {
		rclonePath += ".exe"
	}

	// Check if already downloaded
	if _, err := os.Stat(rclonePath); err == nil {
		return rclonePath, nil
	}

	// Download rclone
	fmt.Println("Downloading rclone (one-time setup)...")

	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", fmt.Errorf("could not create bin directory: %w", err)
	}

	// Determine platform
	var platform string
	switch runtime.GOOS {
	case "darwin":
		if runtime.GOARCH == "arm64" {
			platform = "osx-arm64"
		} else {
			platform = "osx-amd64"
		}
	case "linux":
		if runtime.GOARCH == "arm64" {
			platform = "linux-arm64"
		} else {
			platform = "linux-amd64"
		}
	default:
		return "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Download URL
	url := fmt.Sprintf("https://downloads.rclone.org/%s/rclone-%s-%s.zip", rcloneVersion, rcloneVersion, platform)

	// Download
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("could not download rclone: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("could not download rclone: HTTP %d", resp.StatusCode)
	}

	// Save to temp file
	tmpFile, err := os.CreateTemp("", "rclone-*.zip")
	if err != nil {
		return "", fmt.Errorf("could not create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return "", fmt.Errorf("could not save download: %w", err)
	}
	tmpFile.Close()

	// Extract rclone binary from zip
	if err := extractRcloneFromZip(tmpFile.Name(), rclonePath, platform); err != nil {
		return "", fmt.Errorf("could not extract rclone: %w", err)
	}

	// Make executable
	if err := os.Chmod(rclonePath, 0755); err != nil {
		return "", fmt.Errorf("could not make rclone executable: %w", err)
	}

	fmt.Println("rclone downloaded successfully")
	return rclonePath, nil
}

// extractRcloneFromZip extracts the rclone binary from a downloaded zip
func extractRcloneFromZip(zipPath, destPath, platform string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	// The rclone zip contains a folder like "rclone-v1.65.2-osx-arm64/rclone"
	rcloneName := "rclone"
	if runtime.GOOS == "windows" {
		rcloneName = "rclone.exe"
	}

	expectedPath := fmt.Sprintf("rclone-%s-%s/%s", rcloneVersion, platform, rcloneName)

	for _, f := range r.File {
		if f.Name == expectedPath {
			src, err := f.Open()
			if err != nil {
				return err
			}
			defer src.Close()

			dst, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer dst.Close()

			_, err = io.Copy(dst, src)
			return err
		}
	}

	return fmt.Errorf("rclone binary not found in zip")
}
