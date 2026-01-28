package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Config defines retry behavior
type Config struct {
	MaxAttempts int           // Maximum number of attempts (default: 3)
	InitialWait time.Duration // Initial wait between retries (default: 1s)
	MaxWait     time.Duration // Maximum wait between retries (default: 30s)
	Multiplier  float64       // Backoff multiplier (default: 2.0)
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		MaxAttempts: 3,
		InitialWait: 1 * time.Second,
		MaxWait:     30 * time.Second,
		Multiplier:  2.0,
	}
}

// Do executes fn with retries using exponential backoff
// Returns the last error if all attempts fail
func Do(cfg Config, fn func() error) error {
	return DoWithContext(context.Background(), cfg, fn)
}

// DoWithContext executes fn with retries, respecting context cancellation
func DoWithContext(ctx context.Context, cfg Config, fn func() error) error {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.InitialWait <= 0 {
		cfg.InitialWait = 1 * time.Second
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 30 * time.Second
	}
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = 2.0
	}

	var lastErr error
	wait := cfg.InitialWait

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Don't retry on non-retryable errors
		if !IsRetryable(lastErr) {
			return lastErr
		}

		if attempt < cfg.MaxAttempts {
			// Add jitter: +/- 20%
			jitter := wait / 5
			actualWait := wait + time.Duration(rand.Int63n(int64(jitter*2))) - jitter

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(actualWait):
			}

			// Exponential backoff
			wait = time.Duration(float64(wait) * cfg.Multiplier)
			if wait > cfg.MaxWait {
				wait = cfg.MaxWait
			}
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", cfg.MaxAttempts, lastErr)
}

// IsRetryable determines if an error is worth retrying
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Network errors are generally retryable
	if _, ok := err.(net.Error); ok {
		return true
	}

	// Connection errors
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"connection timed out",
		"no such host",
		"i/o timeout",
		"EOF",
		"broken pipe",
		"network is unreachable",
		"temporary failure",
		"too many open files",
		"resource temporarily unavailable",
		"transport endpoint is not connected",
		"503",
		"502",
		"504",
		"429", // Rate limited
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(pattern)) {
			return true
		}
	}

	// Non-retryable patterns
	nonRetryable := []string{
		"permission denied",
		"not found",
		"404",
		"401",
		"403",
		"invalid",
		"already exists",
		"already mounted",
	}

	for _, pattern := range nonRetryable {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(pattern)) {
			return false
		}
	}

	// Default to retryable for unknown errors
	return true
}

// WithProgress wraps a retry operation with progress output
func WithProgress(cfg Config, name string, fn func() error) error {
	attempt := 0
	return Do(cfg, func() error {
		attempt++
		if attempt > 1 {
			fmt.Printf("  Retry %d/%d: %s...\n", attempt, cfg.MaxAttempts, name)
		}
		return fn()
	})
}

// CheckRedis tests Redis connectivity with timeout
func CheckRedis(redisURL string, timeout time.Duration) error {
	// Extract host:port from redis://[:password@]host:port/db
	url := redisURL
	url = strings.TrimPrefix(url, "redis://")

	// Remove password if present
	if idx := strings.LastIndex(url, "@"); idx != -1 {
		url = url[idx+1:]
	}

	// Remove database suffix
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	conn, err := net.DialTimeout("tcp", url, timeout)
	if err != nil {
		return fmt.Errorf("cannot connect to Redis at %s: %w", url, err)
	}
	conn.Close()
	return nil
}

// WaitFor polls a condition until it returns true or timeout
func WaitFor(timeout time.Duration, interval time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(interval)
	}
	return false
}

// Backoff calculates exponential backoff duration
func Backoff(attempt int, initial, max time.Duration) time.Duration {
	if attempt <= 0 {
		return initial
	}

	wait := float64(initial) * math.Pow(2, float64(attempt-1))
	if wait > float64(max) {
		wait = float64(max)
	}

	// Add jitter
	jitter := wait * 0.2
	wait = wait + (rand.Float64()*jitter*2 - jitter)

	return time.Duration(wait)
}
