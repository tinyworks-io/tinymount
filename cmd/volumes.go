package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/tinyworks/tinymount/internal/api"
	"github.com/tinyworks/tinymount/internal/crypto"
	"github.com/tinyworks/tinymount/internal/keyring"
)

var (
	createSize      string
	createType      string
	createTTL       string
	createEncrypted bool
	createNoEncrypt bool
	createRegion    string
	destroyYes      bool
)

// volumesCmd lists all volumes
var volumesCmd = &cobra.Command{
	Use:     "volumes",
	Aliases: []string{"ls", "list"},
	Short:   "List your volumes",
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		volumes, err := client.ListVolumes()
		if err != nil {
			fail("Could not list volumes: %v", err)
		}

		if len(volumes) == 0 {
			fmt.Println("No volumes. Create one with: tinymount create --size 10GB myvolume")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tSIZE\tTYPE\tREGION\tEXPIRES")
		for _, v := range volumes {
			name := "-"
			if v.Name != nil {
				name = *v.Name
			}
			expires := "-"
			if v.ExpiresIn != nil {
				expires = *v.ExpiresIn
			}
			region := v.Region
			if region == "" {
				region = "weur"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", v.ID, name, v.Size, v.Type, region, expires)
		}
		w.Flush()
	},
}

// createCmd creates a new volume
var createCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new volume",
	Long: `Create a new volume.

Volumes are encrypted by default. Use --no-encryption to disable.

Available regions:
  wnam  - Western North America (Los Angeles)
  enam  - Eastern North America (Ashburn, VA)
  weur  - Western Europe (Amsterdam) [default]
  eeur  - Eastern Europe (Helsinki)
  apac  - Asia Pacific (Singapore)

Examples:
  tinymount create my-data                           # Encrypted (default), weur region
  tinymount create my-data --region wnam             # Western North America
  tinymount create my-data --no-encryption           # Not encrypted
  tinymount create --type ephemeral --ttl 24h cache  # Ephemeral volume`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		// Validate region
		validRegions := map[string]bool{"wnam": true, "enam": true, "weur": true, "eeur": true, "apac": true}
		if !validRegions[createRegion] {
			fail("Invalid region '%s'. Valid regions: wnam, enam, weur, eeur, apac", createRegion)
		}

		// Determine encryption setting
		encrypted := !createNoEncrypt

		req := api.CreateVolumeRequest{
			Size:      createSize,
			Type:      createType,
			Encrypted: encrypted,
			Region:    createRegion,
		}

		if len(args) > 0 {
			req.Name = args[0]
		}

		if createType == "ephemeral" {
			if createTTL == "" {
				fail("--ttl is required for ephemeral volumes (e.g., --ttl 24h)")
			}
			req.TTL = createTTL
		}

		// If encrypted, prompt for password and generate key
		if encrypted {
			fmt.Println("🔐 Setting up encryption...")
			fmt.Println()

			// Prompt for password
			password, err := keyring.PromptPassword("Enter encryption password: ")
			if err != nil {
				fail("Could not read password: %v", err)
			}

			if len(password) < 8 {
				fail("Password must be at least 8 characters")
			}

			// Confirm password
			confirm, err := keyring.PromptPassword("Confirm password: ")
			if err != nil {
				fail("Could not read password: %v", err)
			}

			if password != confirm {
				fail("Passwords do not match")
			}

			// Generate RSA keypair
			fmt.Print("Generating encryption key...")
			privateKey, err := crypto.GenerateRSAKeyPair()
			if err != nil {
				fail("Could not generate key: %v", err)
			}
			fmt.Println(" done")

			// Encrypt the private key with the password
			fmt.Print("Encrypting key...")
			encryptedKey, err := crypto.EncryptKey(privateKey, password)
			if err != nil {
				fail("Could not encrypt key: %v", err)
			}
			fmt.Println(" done")

			req.EncryptedKey = encryptedKey
		}

		resp, err := client.CreateVolume(req)
		if err != nil {
			fail("Could not create volume: %v", err)
		}

		success("Created volume '%s' (%s)", getName(resp.Volume), resp.Volume.ID)
		fmt.Printf("  Type: %s\n", resp.Volume.Type)
		fmt.Printf("  Region: %s\n", resp.Volume.Region)
		if encrypted {
			fmt.Println("  Encryption: enabled 🔐")
		} else {
			fmt.Println("  Encryption: disabled")
		}
		if resp.Volume.ExpiresIn != nil {
			fmt.Printf("  Expires in: %s\n", *resp.Volume.ExpiresIn)
		}
		fmt.Printf("  Estimated cost: %s\n", resp.EstimatedCost)

		fmt.Println()
		if encrypted {
			fmt.Println("To mount this volume, you'll need to create a password:")
			fmt.Printf("  tinymount mount %s ~/your-mountpoint\n", getName(resp.Volume))
			fmt.Println()
			fmt.Println("Use the same password on any machine to access your data.")
			fmt.Println("If you forget your password, your data cannot be recovered.")
		} else {
			fmt.Printf("Mount with: tinymount mount %s ~/your-mountpoint\n", getName(resp.Volume))
		}
	},
}

// destroyCmd deletes a volume
var destroyCmd = &cobra.Command{
	Use:     "destroy <volume-id>",
	Aliases: []string{"rm", "delete"},
	Short:   "Destroy a volume",
	Long:    "Permanently delete a volume and all its data.",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		volumeID := args[0]

		// Confirm unless --yes flag is provided
		if !destroyYes {
			fmt.Printf("Are you sure you want to destroy %s? This cannot be undone. [y/N] ", volumeID)
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "y" && confirm != "Y" {
				fmt.Println("Cancelled")
				return
			}
		}

		if err := client.DestroyVolume(volumeID); err != nil {
			fail("Could not destroy volume: %v", err)
		}

		success("Destroyed volume %s", volumeID)
	},
}

// infoCmd shows volume details
var infoCmd = &cobra.Command{
	Use:   "info <volume-id>",
	Short: "Show volume details and mount credentials",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		volumeID := args[0]

		resp, err := client.GetVolume(volumeID)
		if err != nil {
			fail("Could not get volume: %v", err)
		}

		fmt.Printf("Volume: %s\n", resp.Volume.ID)
		if resp.Volume.Name != nil {
			fmt.Printf("Name: %s\n", *resp.Volume.Name)
		}
		fmt.Printf("Size: %s\n", resp.Volume.Size)
		fmt.Printf("Type: %s\n", resp.Volume.Type)
		region := resp.Volume.Region
		if region == "" {
			region = "weur"
		}
		fmt.Printf("Region: %s\n", region)
		if resp.Volume.ExpiresIn != nil {
			fmt.Printf("Expires in: %s\n", *resp.Volume.ExpiresIn)
		}
		fmt.Printf("Created: %s\n", resp.Volume.CreatedAt)

		fmt.Println("\nMount credentials:")
		fmt.Printf("  Endpoint: %s\n", resp.Mount.Endpoint)
		fmt.Printf("  Bucket: %s\n", resp.Mount.Bucket)
		fmt.Printf("  Access Key ID: %s\n", resp.Mount.AccessKeyID)
		fmt.Printf("  Secret Access Key: %s\n", resp.Mount.SecretAccessKey)
		fmt.Printf("  Region: %s\n", resp.Mount.Region)

		fmt.Println("\nMount with rclone:")
		fmt.Printf("  rclone mount :s3,provider=Cloudflare,access_key_id=%s,secret_access_key=%s,endpoint=%s:%s /mnt/%s\n",
			resp.Mount.AccessKeyID, resp.Mount.SecretAccessKey, resp.Mount.Endpoint, resp.Mount.Bucket, volumeID)
	},
}

// usageCmd shows billing usage
var usageCmd = &cobra.Command{
	Use:   "usage",
	Short: "Show current billing usage",
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		usage, err := client.GetUsage()
		if err != nil {
			fail("Could not get usage: %v", err)
		}

		fmt.Println("Current billing period usage:")
		fmt.Printf("  Persistent storage: %.2f GB\n", usage.CurrentStorage.PersistentGB)
		fmt.Printf("  Ephemeral storage: %.2f GB\n", usage.CurrentStorage.EphemeralGB)
		fmt.Println()
		fmt.Printf("  Billable persistent: %.2f GB-hours\n", usage.Billable.PersistentGBHours)
		fmt.Printf("  Billable ephemeral: %.2f GB-hours\n", usage.Billable.EphemeralGBHours)
		fmt.Printf("  Estimated bill: %s\n", usage.Billable.EstimatedDollars)

		if !usage.HasPaymentMethod {
			fmt.Println("\nNo payment method configured (using free tier)")
			fmt.Println("Add one at: https://tinymount.com/billing")
		}
	},
}

func init() {
	rootCmd.AddCommand(volumesCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(destroyCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(usageCmd)

	createCmd.Flags().StringVar(&createSize, "size", "", "Volume size (e.g., 10GB, 500MB, 1TB)")
	createCmd.Flags().StringVar(&createType, "type", "persistent", "Volume type: persistent or ephemeral")
	createCmd.Flags().StringVar(&createTTL, "ttl", "", "Time to live for ephemeral volumes (e.g., 1h, 24h, 7d)")
	createCmd.Flags().BoolVar(&createNoEncrypt, "no-encryption", false, "Disable encryption (not recommended)")
	createCmd.Flags().StringVar(&createRegion, "region", "weur", "Region: wnam, enam, weur, eeur, apac")

	destroyCmd.Flags().BoolVarP(&destroyYes, "yes", "y", false, "Skip confirmation prompt")
}

func getName(v api.Volume) string {
	if v.Name != nil {
		return *v.Name
	}
	return v.ID
}
