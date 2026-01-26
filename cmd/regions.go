package cmd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// Region represents an available region
type Region struct {
	Code        string
	Name        string
	Location    string
	TestHost    string // Hostname to test latency against
}

// Available regions with test endpoints
// Using AWS EC2 regional endpoints for latency testing (reliable, globally accessible)
var availableRegions = []Region{
	{Code: "wnam", Name: "US West", Location: "Hillsboro, OR", TestHost: "ec2.us-west-2.amazonaws.com"},
	{Code: "weur", Name: "Europe", Location: "Nuremberg, DE", TestHost: "ec2.eu-central-1.amazonaws.com"},
}

var testLatency bool

// regionsCmd lists available regions
var regionsCmd = &cobra.Command{
	Use:   "regions",
	Short: "List available storage regions",
	Long: `List available regions for volume storage.

Each region has co-located Redis metadata storage for optimal performance.
Choose a region close to where you'll primarily access your data.

Use --test-latency to measure network latency to each region and see
which one will give you the best performance.`,
	Run: func(cmd *cobra.Command, args []string) {
		if testLatency {
			showRegionsWithLatency()
		} else {
			showRegions()
		}
	},
}

func init() {
	rootCmd.AddCommand(regionsCmd)
	regionsCmd.Flags().BoolVar(&testLatency, "test-latency", false, "Test network latency to each region")
}

func showRegions() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CODE\tNAME\tLOCATION")
	fmt.Fprintln(w, "----\t----\t--------")
	for _, r := range availableRegions {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Code, r.Name, r.Location)
	}
	w.Flush()

	fmt.Println()
	fmt.Println("Create a volume in a specific region:")
	fmt.Println("  tinymount create my-data --region wnam")
	fmt.Println()
	fmt.Println("Test latency to find your best region:")
	fmt.Println("  tinymount regions --test-latency")
}

type latencyResult struct {
	Region  Region
	Latency time.Duration
	Error   error
}

func showRegionsWithLatency() {
	fmt.Println("Testing latency to each region...")
	fmt.Println()

	results := make([]latencyResult, len(availableRegions))

	// Test each region
	for i, region := range availableRegions {
		latency, err := testTCPLatency(region.TestHost, 443)
		results[i] = latencyResult{
			Region:  region,
			Latency: latency,
			Error:   err,
		}
	}

	// Sort by latency (errors at the end)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Error != nil && results[j].Error != nil {
			return false
		}
		if results[i].Error != nil {
			return false
		}
		if results[j].Error != nil {
			return true
		}
		return results[i].Latency < results[j].Latency
	})

	// Find best region
	var bestRegion string
	for _, r := range results {
		if r.Error == nil {
			bestRegion = r.Region.Code
			break
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CODE\tNAME\tLOCATION\tLATENCY\t")
	fmt.Fprintln(w, "----\t----\t--------\t-------\t")
	for _, r := range results {
		latencyStr := "error"
		recommendation := ""
		if r.Error == nil {
			latencyStr = fmt.Sprintf("%dms", r.Latency.Milliseconds())
			if r.Region.Code == bestRegion {
				recommendation = "← recommended"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.Region.Code, r.Region.Name, r.Region.Location, latencyStr, recommendation)
	}
	w.Flush()

	if bestRegion != "" {
		fmt.Println()
		fmt.Printf("Based on your network latency, '%s' is recommended.\n", bestRegion)
		fmt.Println()
		fmt.Printf("Create a volume in this region:\n")
		fmt.Printf("  tinymount create my-data --region %s\n", bestRegion)
	}
}

// testTCPLatency measures TCP connection time to a host:port
func testTCPLatency(host string, port int) (time.Duration, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Do 3 tests and take the median
	var latencies []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			if i == 2 { // All attempts failed
				return 0, err
			}
			continue
		}
		latency := time.Since(start)
		conn.Close()
		latencies = append(latencies, latency)
	}

	if len(latencies) == 0 {
		return 0, fmt.Errorf("all connection attempts failed")
	}

	// Sort and return median
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	return latencies[len(latencies)/2], nil
}
