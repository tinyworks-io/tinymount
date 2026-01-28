package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinyworks-io/tinymount/internal/api"
	"github.com/tinyworks-io/tinymount/internal/crypto"
	"github.com/tinyworks-io/tinymount/internal/juicefs"
	"github.com/tinyworks-io/tinymount/internal/keyring"
	"github.com/tinyworks-io/tinymount/internal/machine"
	"github.com/tinyworks-io/tinymount/internal/retry"
)

// MountState tracks the state of a mounted volume
type MountState struct {
	VolumeID      string `json:"volume_id"`
	VolumeName    string `json:"volume_name,omitempty"`
	MountPoint    string `json:"mount_point"`
	JFSMountPoint string `json:"jfs_mount_point"` // Internal JuiceFS mount
	Encrypted     bool   `json:"encrypted"`
	MetaURL       string `json:"meta_url"` // Redis URL (without credentials for safety)
	MountedAt     int64  `json:"mounted_at"`
	MountID       string `json:"mount_id,omitempty"` // API mount ID for heartbeat/unregister
	MachineID     string `json:"machine_id,omitempty"`
}

// Active heartbeat goroutines
var (
	heartbeatContexts = make(map[string]context.CancelFunc)
	heartbeatMutex    sync.Mutex
)

// mountV2Cmd mounts a volume using JuiceFS with built-in encryption
var mountV2Cmd = &cobra.Command{
	Use:   "mount <volume-id-or-name> <path>",
	Short: "Mount a volume to a local path",
	Long: `Mount a volume to a local path.

The volume is mounted using JuiceFS for POSIX compliance.
Encrypted volumes use JuiceFS built-in AES-256-GCM encryption.

All volumes use shared Redis for metadata, enabling real-time
sync across multiple devices (based on your plan's mount limit).

Examples:
  tinymount mount my-data ~/data
  tinymount mount vol_abc123 /mnt/mydata`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		volumeIDOrName := args[0]
		mountPoint := args[1]

		// Expand ~ to home directory
		if len(mountPoint) > 0 && mountPoint[0] == '~' {
			home, err := os.UserHomeDir()
			if err != nil {
				fail("Could not expand home directory: %v", err)
			}
			mountPoint = filepath.Join(home, mountPoint[1:])
		}

		// Make path absolute
		absPath, err := filepath.Abs(mountPoint)
		if err != nil {
			fail("Could not resolve path: %v", err)
		}
		mountPoint = absPath

		// Check platform requirements
		if runtime.GOOS == "windows" {
			fail("Windows is not supported. Use WSL2 instead.")
		}

		// Check for required tools
		jfs, err := juicefs.NewClient()
		if err != nil {
			fail("%v", err)
		}

		// Get machine ID
		machineID, err := machine.GetID()
		if err != nil {
			fail("Could not get machine ID: %v", err)
		}
		machineName := machine.GetName()

		// Set up directories
		home, _ := os.UserHomeDir()
		keysDir := filepath.Join(home, ".tinymount", "keys")

		if err := os.MkdirAll(keysDir, 0700); err != nil {
			fail("Could not create keys directory: %v", err)
		}

		// Check if already mounted
		if juicefs.IsMounted(mountPoint) {
			fail("%s is already mounted. Unmount first with: tinymount unmount %s", mountPoint, mountPoint)
		}

		// Get volume details from API with retry
		fmt.Print("Fetching volume info...")
		var resp *api.VolumeDetailsResponse

		err = retry.Do(retry.Config{MaxAttempts: 3, InitialWait: 2 * time.Second}, func() error {
			var apiErr error
			resp, apiErr = client.GetVolume(volumeIDOrName)
			return apiErr
		})
		if err != nil {
			fmt.Println(" failed")
			fail("Could not get volume: %v", err)
		}
		fmt.Println(" done")

		volumeID := resp.Volume.ID

		// Check mount limits before proceeding
		fmt.Print("Checking mount limits...")
		limits, err := client.GetMountLimits()
		if err != nil {
			fmt.Println(" failed")
			fail("Could not check mount limits: %v", err)
		}
		if limits.Available <= 0 {
			fmt.Println(" exceeded")
			fail("Mount limit exceeded. Your %s plan allows %d concurrent mount(s). You have %d active.\nUpgrade your plan or unmount another volume first.", limits.Plan, limits.Limit, limits.Current)
		}
		fmt.Printf(" done (%d/%d used)\n", limits.Current, limits.Limit)

		// Set up mount directory
		mountsDir := filepath.Join(home, ".tinymount", "mounts", volumeID)
		if err := os.MkdirAll(mountsDir, 0700); err != nil {
			fail("Could not create mount directory: %v", err)
		}

		// Acquire lock to prevent concurrent mount attempts
		lockFile := filepath.Join(mountsDir, "mount.lock")
		if err := acquireLock(lockFile); err != nil {
			fail("Another mount operation is in progress for this volume: %v", err)
		}
		defer releaseLock(lockFile)

		// Get Redis metadata URL from API
		if resp.Mount.RedisURL == "" {
			fail("Redis URL not provided by API")
		}
		metaURL := resp.Mount.RedisURL

		// Pre-flight: Check Redis connectivity
		fmt.Print("Checking metadata server...")
		err = retry.Do(retry.Config{MaxAttempts: 3, InitialWait: 1 * time.Second}, func() error {
			return retry.CheckRedis(metaURL, 10*time.Second)
		})
		if err != nil {
			fmt.Println(" failed")
			fail("Cannot connect to metadata server: %v\n\nThis may be a temporary network issue. Please try again in a few moments.", err)
		}
		fmt.Println(" done")

		// Handle encryption
		var keyPath string
		if resp.Mount.Encrypted {
			if resp.Mount.EncryptedKey == nil || *resp.Mount.EncryptedKey == "" {
				fail("Volume is encrypted but no key found. The volume may have been created with an older CLI version.")
			}

			// Check if we have the key cached locally
			keyPath = filepath.Join(keysDir, volumeID+".pem")
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				// Need to decrypt the key
				keys, err := keyring.NewStore()
				if err != nil {
					fail("Could not access keyring: %v", err)
				}

				var password string
				if keys.Exists(volumeID) {
					password, err = keys.Load(volumeID)
					if err != nil {
						fail("Could not load cached password: %v", err)
					}
					fmt.Println("Using saved password")
				} else {
					password, err = keyring.PromptPassword("Enter encryption password: ")
					if err != nil {
						fail("Could not read password: %v", err)
					}
				}

				// Decrypt the RSA key
				fmt.Print("Decrypting key...")
				privateKey, err := crypto.DecryptKey(*resp.Mount.EncryptedKey, password)
				if err != nil {
					fmt.Println(" failed")
					fail("Could not decrypt key (wrong password?): %v", err)
				}
				fmt.Println(" done")

				// Save the decrypted key locally
				if err := crypto.SaveKeyToFile(privateKey, keyPath); err != nil {
					fail("Could not save key: %v", err)
				}

				// Ask to save password
				if !keys.Exists(volumeID) {
					fmt.Print("Save password locally for future mounts? [y/N] ")
					var save string
					fmt.Scanln(&save)
					if save == "y" || save == "Y" {
						if err := keys.Save(volumeID, password); err != nil {
							fmt.Printf("Warning: Could not save password: %v\n", err)
						} else {
							fmt.Printf("Password saved\n")
						}
					}
				}
			} else {
				fmt.Println("Using cached key")
			}
		}

		// Format JuiceFS if this is a new volume
		// JuiceFS only allows alphanumeric and dashes, 3-63 chars
		jfsVolName := strings.ReplaceAll(volumeID, "_", "-")

		// Check if already formatted by trying to get status
		_, err = jfs.Status(metaURL)
		needsFormat := err != nil

		if needsFormat {
			fmt.Print("Initializing filesystem...")
			err := jfs.Format(juicefs.FormatOptions{
				MetaURL:       metaURL,
				VolName:       jfsVolName,
				Storage:       "s3",
				Bucket:        fmt.Sprintf("%s/%s", resp.Mount.Endpoint, resp.Mount.Bucket),
				AccessKey:     resp.Mount.AccessKeyID,
				SecretKey:     resp.Mount.SecretAccessKey,
				EncryptKeyPEM: keyPath, // Empty string if not encrypted
			})
			if err != nil {
				fmt.Println(" failed")
				fail("Could not format filesystem: %v", err)
			}
			fmt.Println(" done")
		} else {
			fmt.Println("Filesystem ready")
		}

		// Create mount point
		if err := os.MkdirAll(mountPoint, 0755); err != nil {
			fail("Could not create mount point: %v", err)
		}

		// Set up signal handler for graceful cleanup
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			fmt.Println("\nInterrupted. Cleaning up...")
			// Attempt cleanup
			if juicefs.IsMounted(mountPoint) {
				jfs.Unmount(mountPoint)
			}
			deleteMountState(volumeID)
			os.Exit(1)
		}()

		// Mount JuiceFS directly to the user's mount point
		fmt.Print("Mounting filesystem...")
		err = jfs.Mount(juicefs.MountOptions{
			MetaURL:    metaURL,
			MountPoint: mountPoint,
			AccessKey:  resp.Mount.AccessKeyID,
			SecretKey:  resp.Mount.SecretAccessKey,
			Background: true,
			CacheDir:   filepath.Join(mountsDir, "cache"),
			CacheSize:  "1G",
			Writeback:  true, // Async writes for better performance
		})
		if err != nil {
			fmt.Println(" failed")
			// Cleanup on failure
			deleteMountState(volumeID)
			fail("Could not mount filesystem: %v", err)
		}
		fmt.Println(" done")

		// Stop signal handler for mount phase
		signal.Stop(sigChan)

		// Register mount with API
		fmt.Print("Registering mount...")
		var mountID string
		registerResp, err := client.RegisterMount(volumeID, api.RegisterMountRequest{
			MachineID:   machineID,
			MachineName: machineName,
		})
		if err != nil {
			fmt.Println(" warning")
			fmt.Printf("Warning: Could not register mount with API: %v\n", err)
			fmt.Println("Mount will work but won't be tracked for limit enforcement.")
		} else {
			mountID = registerResp.MountID
			fmt.Println(" done")

			// Start heartbeat goroutine
			startHeartbeat(mountID, volumeID)
		}

		// Save mount state
		volumeName := ""
		if resp.Volume.Name != nil {
			volumeName = *resp.Volume.Name
		}

		// Sanitize Redis URL for storage (remove password)
		sanitizedMetaURL := sanitizeRedisURL(metaURL)

		saveMountStateV2(MountState{
			VolumeID:      volumeID,
			VolumeName:    volumeName,
			MountPoint:    mountPoint,
			JFSMountPoint: mountPoint,
			Encrypted:     resp.Mount.Encrypted,
			MetaURL:       sanitizedMetaURL,
			MountedAt:     time.Now().Unix(),
			MountID:       mountID,
			MachineID:     machineID,
		})

		success("Mounted %s at %s", getName(resp.Volume), mountPoint)

		fmt.Println("\nTo unmount:")
		fmt.Printf("  tinymount unmount %s\n", mountPoint)
	},
}

var forceUnmount bool

// unmountV2Cmd unmounts a volume
var unmountV2Cmd = &cobra.Command{
	Use:     "unmount <path>",
	Aliases: []string{"umount"},
	Short:   "Unmount a volume",
	Long: `Unmount a volume from the specified path.

Use --force to forcefully unmount even if the volume is busy.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mountPoint := args[0]

		// Expand ~ to home directory
		if len(mountPoint) > 0 && mountPoint[0] == '~' {
			home, _ := os.UserHomeDir()
			mountPoint = filepath.Join(home, mountPoint[1:])
		}

		// Make path absolute
		absPath, _ := filepath.Abs(mountPoint)
		mountPoint = absPath

		// Check if actually mounted
		if !juicefs.IsMounted(mountPoint) {
			// Check if we have state for it
			state, err := loadMountStateV2(mountPoint)
			if err == nil {
				// State exists but not mounted - clean up stale state
				if state.MountID != "" {
					// Try to unregister with API
					client.UnregisterMount(state.MountID)
				}
				stopHeartbeat(state.VolumeID)
				deleteMountState(state.VolumeID)
				fmt.Println("Cleaned up stale mount state")
			} else {
				fmt.Printf("%s is not mounted\n", mountPoint)
			}
			return
		}

		// Load mount state
		state, err := loadMountStateV2(mountPoint)
		if err != nil {
			fmt.Printf("Warning: Could not load mount state: %v\n", err)
			if forceUnmount {
				fmt.Println("Attempting force unmount...")
				if err := juicefs.ForceUnmount(mountPoint); err != nil {
					fail("Force unmount failed: %v", err)
				}
				success("Unmounted %s", mountPoint)
				return
			}
			fail("Use --force to attempt unmount anyway")
		}

		jfs, err := juicefs.NewClient()
		if err != nil {
			// JuiceFS not available, use system unmount
			fmt.Print("Unmounting filesystem...")
			if err := juicefs.ForceUnmount(mountPoint); err != nil {
				fmt.Println(" failed")
				fail("Could not unmount: %v", err)
			}
			fmt.Println(" done")

			// Unregister and cleanup
			if state.MountID != "" {
				client.UnregisterMount(state.MountID)
			}
			stopHeartbeat(state.VolumeID)
			deleteMountState(state.VolumeID)
			success("Unmounted %s", mountPoint)
			return
		}

		// Sync before unmount to flush any pending writes
		fmt.Print("Syncing data...")
		jfs.Sync(mountPoint)
		fmt.Println(" done")

		// Unmount JuiceFS
		fmt.Print("Unmounting filesystem...")
		if forceUnmount {
			err = jfs.UnmountWithOptions(mountPoint, true)
		} else {
			err = jfs.Unmount(mountPoint)
		}

		if err != nil {
			fmt.Println(" failed")
			if !forceUnmount {
				fmt.Println("The mount point may be in use. Close any applications accessing it and try again.")
				fmt.Println("Or use --force to forcefully unmount.")
			}
			fail("Could not unmount: %v", err)
		}
		fmt.Println(" done")

		// Verify unmount
		if juicefs.IsMounted(mountPoint) {
			fail("Unmount appeared to succeed but mount point is still active")
		}

		// Unregister mount with API
		if state.MountID != "" {
			fmt.Print("Unregistering mount...")
			if _, err := client.UnregisterMount(state.MountID); err != nil {
				fmt.Println(" warning")
				fmt.Printf("Warning: Could not unregister mount: %v\n", err)
			} else {
				fmt.Println(" done")
			}
		}

		// Stop heartbeat and clean up state
		stopHeartbeat(state.VolumeID)
		deleteMountState(state.VolumeID)

		success("Unmounted %s", mountPoint)
	},
}

// statusCmd shows active mounts
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active mounts",
	Run: func(cmd *cobra.Command, args []string) {
		home, _ := os.UserHomeDir()
		mountsDir := filepath.Join(home, ".tinymount", "mounts")

		entries, err := os.ReadDir(mountsDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No active mounts")
				return
			}
			fail("Could not read mounts directory: %v", err)
		}

		found := false
		stale := []MountState{}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			stateFile := filepath.Join(mountsDir, entry.Name(), "state.json")
			data, err := os.ReadFile(stateFile)
			if err != nil {
				continue
			}

			var state MountState
			if err := json.Unmarshal(data, &state); err != nil {
				continue
			}

			// Check if actually mounted
			if !juicefs.IsMounted(state.MountPoint) {
				stale = append(stale, state)
				continue
			}

			found = true
			name := state.VolumeID
			if state.VolumeName != "" {
				name = state.VolumeName
			}

			// Calculate uptime
			uptime := ""
			if state.MountedAt > 0 {
				duration := time.Since(time.Unix(state.MountedAt, 0))
				uptime = fmt.Sprintf(" (up %s)", formatDuration(duration))
			}

			fmt.Printf("%s -> %s%s\n", name, state.MountPoint, uptime)
			if state.Encrypted {
				fmt.Println("  Encryption: enabled")
			}
			if state.MountID != "" {
				fmt.Println("  Tracked: yes")
			}
		}

		// Clean up stale mounts
		for _, state := range stale {
			if state.MountID != "" {
				client.UnregisterMount(state.MountID)
			}
			stopHeartbeat(state.VolumeID)
			deleteMountState(state.VolumeID)
		}
		if len(stale) > 0 {
			fmt.Printf("\nCleaned up %d stale mount(s)\n", len(stale))
		}

		if !found {
			fmt.Println("No active mounts")
		}
	},
}

func init() {
	rootCmd.AddCommand(mountV2Cmd)

	unmountV2Cmd.Flags().BoolVarP(&forceUnmount, "force", "f", false, "Force unmount even if busy")
	rootCmd.AddCommand(unmountV2Cmd)

	rootCmd.AddCommand(statusCmd)
}

// Heartbeat management

func startHeartbeat(mountID, volumeID string) {
	heartbeatMutex.Lock()
	defer heartbeatMutex.Unlock()

	// Cancel existing heartbeat if any
	if cancel, exists := heartbeatContexts[volumeID]; exists {
		cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	heartbeatContexts[volumeID] = cancel

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := client.SendHeartbeat(mountID); err != nil {
					// Log but don't fail - mount still works
					fmt.Printf("Warning: Heartbeat failed: %v\n", err)
				}
			}
		}
	}()
}

func stopHeartbeat(volumeID string) {
	heartbeatMutex.Lock()
	defer heartbeatMutex.Unlock()

	if cancel, exists := heartbeatContexts[volumeID]; exists {
		cancel()
		delete(heartbeatContexts, volumeID)
	}
}

// Mount state management (v2 - JSON based)
func saveMountStateV2(state MountState) {
	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".tinymount", "mounts", state.VolumeID)
	os.MkdirAll(stateDir, 0700)

	stateFile := filepath.Join(stateDir, "state.json")
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(stateFile, data, 0600)
}

func loadMountStateV2(userMount string) (*MountState, error) {
	home, _ := os.UserHomeDir()
	mountsDir := filepath.Join(home, ".tinymount", "mounts")

	entries, err := os.ReadDir(mountsDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		stateFile := filepath.Join(mountsDir, entry.Name(), "state.json")
		data, err := os.ReadFile(stateFile)
		if err != nil {
			continue
		}

		var state MountState
		if err := json.Unmarshal(data, &state); err != nil {
			continue
		}

		if state.MountPoint == userMount {
			return &state, nil
		}
	}

	return nil, fmt.Errorf("mount state not found for %s", userMount)
}

func deleteMountState(volumeID string) {
	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".tinymount", "mounts", volumeID)
	os.RemoveAll(stateDir)
}

// Lock file management
func acquireLock(lockFile string) error {
	// Check if lock exists and is stale
	if info, err := os.Stat(lockFile); err == nil {
		// Lock exists - check if it's stale (older than 5 minutes)
		if time.Since(info.ModTime()) > 5*time.Minute {
			os.Remove(lockFile)
		} else {
			return fmt.Errorf("lock file exists and is recent")
		}
	}

	// Create lock file
	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	f.WriteString(fmt.Sprintf("%d", os.Getpid()))
	f.Close()
	return nil
}

func releaseLock(lockFile string) {
	os.Remove(lockFile)
}

// sanitizeRedisURL removes password from Redis URL for safe storage
func sanitizeRedisURL(url string) string {
	// redis://:password@host:port/db -> redis://host:port/db
	if idx := strings.Index(url, "@"); idx != -1 {
		prefix := "redis://"
		if strings.HasPrefix(url, "rediss://") {
			prefix = "rediss://"
		}
		return prefix + url[idx+1:]
	}
	return url
}

// formatDuration formats a duration in human-readable form
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		mins := int(d.Minutes()) % 60
		if mins > 0 {
			return fmt.Sprintf("%dh%dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if hours > 0 {
		return fmt.Sprintf("%dd%dh", days, hours)
	}
	return fmt.Sprintf("%dd", days)
}
