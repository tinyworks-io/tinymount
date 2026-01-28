package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/tinyworks-io/tinymount/internal/keyring"
)

// keyCmd is the parent command for key management
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage encryption keys",
	Long: `Manage encryption keys for your volumes.

Keys are stored locally at ~/.tinymount/keys/ and are required
to decrypt your data. If you lose your key, your data cannot be recovered.

Commands:
  tinymount key list              List all stored keys
  tinymount key export <vol> <path>  Export a key for backup
  tinymount key import <vol> <path>  Import a key from backup
  tinymount key backup            Interactive backup guide`,
}

// keyListCmd lists all stored keys
var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored encryption keys",
	Run: func(cmd *cobra.Command, args []string) {
		store, err := keyring.NewStore()
		if err != nil {
			fail("Could not access keyring: %v", err)
		}

		volumeIDs, err := store.List()
		if err != nil {
			fail("Could not list keys: %v", err)
		}

		if len(volumeIDs) == 0 {
			fmt.Println("No encryption keys stored.")
			fmt.Println("Keys are created when you mount an encrypted volume for the first time.")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "VOLUME ID\tKEY PATH")
		for _, id := range volumeIDs {
			fmt.Fprintf(w, "%s\t%s\n", id, store.Path(id))
		}
		w.Flush()

		fmt.Println("\nBack up your keys! Run: tinymount key backup")
	},
}

// keyExportCmd exports a key to a file
var keyExportCmd = &cobra.Command{
	Use:   "export <volume-id> <path>",
	Short: "Export an encryption key to a file",
	Long: `Export an encryption key to a file for backup.

Example:
  tinymount key export vol_abc123 ~/backup/vol_abc123.key`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		volumeID := args[0]
		destPath := args[1]

		// Expand ~ to home directory
		if len(destPath) > 0 && destPath[0] == '~' {
			home, _ := os.UserHomeDir()
			destPath = filepath.Join(home, destPath[1:])
		}

		store, err := keyring.NewStore()
		if err != nil {
			fail("Could not access keyring: %v", err)
		}

		if !store.Exists(volumeID) {
			fail("No key found for volume %s", volumeID)
		}

		if err := store.Export(volumeID, destPath); err != nil {
			fail("Could not export key: %v", err)
		}

		success("Key exported to %s", destPath)
		fmt.Println("\nStore this file securely! Recommended locations:")
		fmt.Println("  - Password manager (1Password, Bitwarden)")
		fmt.Println("  - Encrypted USB drive")
		fmt.Println("  - Printed paper in a safe")
	},
}

// keyImportCmd imports a key from a file
var keyImportCmd = &cobra.Command{
	Use:   "import <volume-id> <path>",
	Short: "Import an encryption key from a backup",
	Long: `Import an encryption key from a backup file.

This is needed when accessing a volume from a new machine.

Example:
  tinymount key import vol_abc123 ~/backup/vol_abc123.key`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		volumeID := args[0]
		srcPath := args[1]

		// Expand ~ to home directory
		if len(srcPath) > 0 && srcPath[0] == '~' {
			home, _ := os.UserHomeDir()
			srcPath = filepath.Join(home, srcPath[1:])
		}

		store, err := keyring.NewStore()
		if err != nil {
			fail("Could not access keyring: %v", err)
		}

		if store.Exists(volumeID) {
			fmt.Printf("A key already exists for %s. Overwrite? [y/N] ", volumeID)
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "y" && confirm != "Y" {
				fmt.Println("Cancelled")
				return
			}
		}

		if err := store.Import(volumeID, srcPath); err != nil {
			fail("Could not import key: %v", err)
		}

		success("Key imported for %s", volumeID)
		fmt.Println("\nYou can now mount this volume:")
		fmt.Printf("  tinymount mount %s ~/your-mountpoint\n", volumeID)
	},
}

// keyBackupCmd provides an interactive backup guide
var keyBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Interactive guide to back up your encryption keys",
	Run: func(cmd *cobra.Command, args []string) {
		store, err := keyring.NewStore()
		if err != nil {
			fail("Could not access keyring: %v", err)
		}

		volumeIDs, err := store.List()
		if err != nil {
			fail("Could not list keys: %v", err)
		}

		if len(volumeIDs) == 0 {
			fmt.Println("No encryption keys to back up.")
			return
		}

		fmt.Println("╔═══════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  ENCRYPTION KEY BACKUP                                                 ║")
		fmt.Println("║                                                                        ║")
		fmt.Println("║  Your encryption keys are the ONLY way to decrypt your data.          ║")
		fmt.Println("║  We do not have copies. If you lose them, your data is GONE.          ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════════════════╝")
		fmt.Println()

		fmt.Printf("You have %d key(s) to back up:\n\n", len(volumeIDs))

		for i, id := range volumeIDs {
			fmt.Printf("  %d. %s\n", i+1, id)
			fmt.Printf("     Path: %s\n", store.Path(id))
		}

		fmt.Println("\n--- BACKUP OPTIONS ---\n")

		fmt.Println("Option 1: Copy to password manager")
		fmt.Println("  Open your password manager and create an entry for each key.")
		fmt.Println("  Store the contents of the key file as a secure note.")
		fmt.Println()

		fmt.Println("Option 2: Copy to encrypted USB drive")
		for _, id := range volumeIDs {
			fmt.Printf("  cp %s /path/to/usb/\n", store.Path(id))
		}
		fmt.Println()

		fmt.Println("Option 3: Export to a backup directory")
		home, _ := os.UserHomeDir()
		backupDir := filepath.Join(home, "tinymount-key-backup")
		fmt.Printf("  mkdir -p %s\n", backupDir)
		for _, id := range volumeIDs {
			fmt.Printf("  tinymount key export %s %s/%s.key\n", id, backupDir, id)
		}
		fmt.Println()

		fmt.Println("--- IMPORTANT ---")
		fmt.Println("After backing up, verify you can restore by running:")
		fmt.Println("  tinymount key list")
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyListCmd)
	keyCmd.AddCommand(keyExportCmd)
	keyCmd.AddCommand(keyImportCmd)
	keyCmd.AddCommand(keyBackupCmd)
}
