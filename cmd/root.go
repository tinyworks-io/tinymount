package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tinyworks-io/tinymount/internal/api"
	"github.com/tinyworks-io/tinymount/internal/config"
)

var (
	cfgFile string
	cfg     *config.Config
	client  *api.Client
	version = "dev"
	commit  = "none"
)

// SetVersion sets the version info (called from main)
func SetVersion(v, c string) {
	version = v
	commit = c
}

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "tinymount",
	Short: "Mount cloud storage anywhere",
	Long: `tinymount gives you FUSE-mountable filesystems backed by Cloudflare R2.
Create a volume, run one command, and it's mounted.

Get started:
  tinymount register    Create an account
  tinymount login       Authenticate
  tinymount create      Create a volume
  tinymount mount       Mount a volume`,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// versionCmd prints version info
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("tinymount %s (commit: %s)\n", version, commit)
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.AddCommand(versionCmd)
}

// initConfig loads the configuration
func initConfig() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Endpoint from TINYMOUNT_API env var (local/dev/prod or full URL)
	endpoint := config.GetEndpoint()

	client = api.NewClient(endpoint, cfg.APIKey)
}

// requireAuth checks if the user is logged in
func requireAuth() {
	if !cfg.IsLoggedIn() {
		fmt.Fprintln(os.Stderr, "Not logged in. Run 'tinymount login' first.")
		os.Exit(1)
	}
}

// success prints a success message
func success(format string, args ...interface{}) {
	fmt.Printf("✓ "+format+"\n", args...)
}

// fail prints an error and exits
func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "✗ "+format+"\n", args...)
	os.Exit(1)
}
