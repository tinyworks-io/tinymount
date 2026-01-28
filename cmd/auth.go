package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tinyworks-io/tinymount/internal/config"
	"golang.org/x/term"
)

// registerCmd creates a new account
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Create a new tinymount account",
	Run: func(cmd *cobra.Command, args []string) {
		email := prompt("Email: ")
		password := promptPassword("Password: ")
		confirmPassword := promptPassword("Confirm password: ")

		if password != confirmPassword {
			fail("Passwords do not match")
		}

		if len(password) < 8 {
			fail("Password must be at least 8 characters")
		}

		resp, err := client.Register(email, password)
		if err != nil {
			fail("Registration failed: %v", err)
		}

		// Save credentials
		cfg.APIKey = resp.User.APIKey
		cfg.Email = resp.User.Email
		if err := config.Save(cfg); err != nil {
			fail("Could not save config: %v", err)
		}

		success("Account created!")
		fmt.Println(resp.Message)
		fmt.Printf("\nYour API key: %s\n", resp.User.APIKey)
		fmt.Println("Stored in ~/.tinymount/config.json")
	},
}

// loginCmd authenticates an existing user
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to your tinymount account",
	Run: func(cmd *cobra.Command, args []string) {
		email := prompt("Email: ")
		password := promptPassword("Password: ")

		resp, err := client.Login(email, password)
		if err != nil {
			fail("Login failed: %v", err)
		}

		// Save credentials
		cfg.APIKey = resp.User.APIKey
		cfg.Email = resp.User.Email
		if err := config.Save(cfg); err != nil {
			fail("Could not save config: %v", err)
		}

		success("Logged in as %s", resp.User.Email)
		fmt.Printf("API key stored in ~/.tinymount/config.json\n")
	},
}

// logoutCmd clears stored credentials
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out and clear stored credentials",
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.Clear(); err != nil {
			fail("Could not clear config: %v", err)
		}
		success("Logged out")
	},
}

// whoamiCmd shows current user info
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current user info",
	Run: func(cmd *cobra.Command, args []string) {
		requireAuth()

		user, err := client.GetMe()
		if err != nil {
			fail("Could not get user info: %v", err)
		}

		fmt.Printf("Email: %s\n", user.Email)
		fmt.Printf("User ID: %s\n", user.ID)
		fmt.Printf("API Key: %s\n", user.APIKey)
		if user.HasPaymentMethod {
			fmt.Println("Payment method: configured")
		} else {
			fmt.Println("Payment method: not configured (using free tier)")
		}
	},
}

func init() {
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
}

// prompt reads a line from stdin
func prompt(label string) string {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fail("Could not read input: %v", err)
	}
	return strings.TrimSpace(input)
}

// promptPassword reads a password without echoing
func promptPassword(label string) string {
	fmt.Print(label)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add newline after password input
	if err != nil {
		fail("Could not read password: %v", err)
	}
	return string(password)
}
