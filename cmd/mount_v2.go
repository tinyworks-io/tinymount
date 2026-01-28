package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinyworks-io/tinymount/internal/crypto"
	"github.com/tinyworks-io/tinymount/internal/juicefs"
	"github.com/tinyworks-io/tinymount/internal/keyring"
)

// MountState tracks the state of a mounted volume
type MountState struct {
	VolumeID       string `json:"volume_id"`
	VolumeName     string `json:"volume_name,omitempty"`
	MountPoint     string `json:"mount_point"`
	JFSMountPoint  string `json:"jfs_mount_point"` // Internal JuiceFS mount
	Encrypted      bool   `json:"encrypted"`
	MetaURL        string `json:"meta_url"` // Redis URL
}

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

		// Get volume details from API
		resp, err := client.GetVolume(volumeIDOrName)
		if err != nil {
			fail("Could not get volume: %v", err)
		}

		volumeID := resp.Volume.ID

		// Check platform requirements
		if runtime.GOOS == "windows" {
			fail("Windows is not supported. Use WSL2 instead.")
		}

		// Check for required tools
		jfs, err := juicefs.NewClient()
		if err != nil {
			fail("%v", err)
		}

		// Set up directories
		home, _ := os.UserHomeDir()
		mountsDir := filepath.Join(home, ".tinymount", "mounts", volumeID)
		keysDir := filepath.Join(home, ".tinymount", "keys")

		if err := os.MkdirAll(mountsDir, 0700); err != nil {
			fail("Could not create mount directory: %v", err)
		}
		if err := os.MkdirAll(keysDir, 0700); err != nil {
			fail("Could not create keys directory: %v", err)
		}

		// Check if already mounted
		if isMountedV2(mountPoint) {
			fail("%s is already mounted. Unmount first with: tinymount unmount %s", mountPoint, mountPoint)
		}

		// Get Redis metadata URL from API
		if resp.Mount.RedisURL == "" {
			fail("Redis URL not provided by API")
		}
		metaURL := resp.Mount.RedisURL

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
			fail("Could not mount filesystem: %v", err)
		}
		fmt.Println(" done")

		// Save mount state
		volumeName := ""
		if resp.Volume.Name != nil {
			volumeName = *resp.Volume.Name
		}
		saveMountStateV2(MountState{
			VolumeID:      volumeID,
			VolumeName:    volumeName,
			MountPoint:    mountPoint,
			JFSMountPoint: mountPoint, // Same as mount point now (no gocryptfs layer)
			Encrypted:     resp.Mount.Encrypted,
			MetaURL:       metaURL,
		})

		success("Mounted %s at %s", getName(resp.Volume), mountPoint)

		fmt.Println("\nTo unmount:")
		fmt.Printf("  tinymount unmount %s\n", mountPoint)
	},
}

// unmountV2Cmd unmounts a volume
var unmountV2Cmd = &cobra.Command{
	Use:     "unmount <path>",
	Aliases: []string{"umount"},
	Short:   "Unmount a volume",
	Long:    `Unmount a volume from the specified path.`,
	Args:    cobra.ExactArgs(1),
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

		// Load mount state
		state, err := loadMountStateV2(mountPoint)
		if err != nil {
			fmt.Printf("Warning: Could not load mount state: %v\n", err)
			fmt.Println("Attempting force unmount...")
			forceUnmount(mountPoint)
			return
		}

		jfs, _ := juicefs.NewClient()

		// Unmount JuiceFS
		fmt.Print("Unmounting filesystem...")
		if jfs != nil {
			jfs.Unmount(mountPoint)
		}
		fmt.Println(" done")

		// Clean up state
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
			if !isMountedV2(state.MountPoint) {
				continue
			}

			found = true
			name := state.VolumeID
			if state.VolumeName != "" {
				name = state.VolumeName
			}
			fmt.Printf("%s -> %s\n", name, state.MountPoint)
			if state.Encrypted {
				fmt.Println("  Encryption: enabled")
			}
		}

		if !found {
			fmt.Println("No active mounts")
		}
	},
}

func init() {
	rootCmd.AddCommand(mountV2Cmd)
	rootCmd.AddCommand(unmountV2Cmd)
	rootCmd.AddCommand(statusCmd)
}

// isMountedV2 checks if a path is a mount point
func isMountedV2(path string) bool {
	// Check if it's a symlink
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}

	// Check mount table
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), " on "+path+" ") ||
		strings.Contains(string(output), " on "+path+"\n")
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

func forceUnmount(path string) {
	// Try fusermount first (Linux)
	if fusermount, err := exec.LookPath("fusermount"); err == nil {
		exec.Command(fusermount, "-u", path).Run()
	}

	// Try umount
	exec.Command("umount", path).Run()

	// Try JuiceFS umount
	if jfs, err := juicefs.NewClient(); err == nil {
		jfs.Unmount(path)
	}
}
