package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the tinymount API client
type Client struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient(endpoint, apiKey string) *Client {
	return &Client{
		endpoint: endpoint,
		apiKey:   apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// APIError represents an error from the API
type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// User represents a user response
type User struct {
	ID               string `json:"id"`
	Email            string `json:"email"`
	APIKey           string `json:"api_key"`
	HasPaymentMethod bool   `json:"has_payment_method"`
}

// RegisterResponse is the response from /auth/register
type RegisterResponse struct {
	User    User   `json:"user"`
	Message string `json:"message"`
}

// LoginResponse is the response from /auth/login
type LoginResponse struct {
	User User `json:"user"`
}

// Volume represents a volume
type Volume struct {
	ID        string  `json:"id"`
	Name      *string `json:"name"`
	Size      string  `json:"size"`
	SizeBytes int64   `json:"size_bytes"`
	Type      string  `json:"type"`
	Encrypted bool    `json:"encrypted"`
	Region    string  `json:"region"`
	ExpiresIn *string `json:"expires_in"`
	CreatedAt string  `json:"created_at"`
}

// CreateVolumeRequest is the request body for creating a volume
type CreateVolumeRequest struct {
	Name         string `json:"name,omitempty"`
	Size         string `json:"size"`
	Type         string `json:"type"`
	TTL          string `json:"ttl,omitempty"`
	Encrypted    bool   `json:"encrypted"`
	EncryptedKey string `json:"encrypted_key,omitempty"` // Password-encrypted RSA key (base64)
	Region       string `json:"region,omitempty"`
}

// CreateVolumeResponse is the response from POST /volumes
type CreateVolumeResponse struct {
	Volume        Volume `json:"volume"`
	EstimatedCost string `json:"estimated_cost"`
	MountCommand  string `json:"mount_command"`
}

// VolumeDetailsResponse is the response from GET /volumes/:id
type VolumeDetailsResponse struct {
	Volume Volume     `json:"volume"`
	Mount  MountCreds `json:"mount"`
}

// MountCreds contains S3-compatible credentials for mounting
type MountCreds struct {
	Endpoint        string  `json:"endpoint"`
	Bucket          string  `json:"bucket"`
	AccessKeyID     string  `json:"access_key_id"`
	SecretAccessKey string  `json:"secret_access_key"`
	SessionToken    string  `json:"session_token,omitempty"`
	Region          string  `json:"region"`
	VolumeID        string  `json:"volume_id"`
	Encrypted       bool    `json:"encrypted"`
	RedisURL        string  `json:"redis_url"`
	EncryptedKey    *string `json:"encrypted_key"` // Password-encrypted RSA key (base64)
}

// VolumesResponse is the response from GET /volumes
type VolumesResponse struct {
	Volumes []Volume `json:"volumes"`
}

// UsageResponse is the response from GET /billing/usage
type UsageResponse struct {
	Period struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"period"`
	CurrentStorage struct {
		PersistentGB float64 `json:"persistent_gb"`
		EphemeralGB  float64 `json:"ephemeral_gb"`
	} `json:"current_storage"`
	Billable struct {
		PersistentGBHours float64 `json:"persistent_gb_hours"`
		EphemeralGBHours  float64 `json:"ephemeral_gb_hours"`
		EstimatedDollars  string  `json:"estimated_dollars"`
	} `json:"billable"`
	HasPaymentMethod bool `json:"has_payment_method"`
}

// doRequest performs an HTTP request and decodes the response
func (c *Client) doRequest(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("could not encode request: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.endpoint+path, bodyReader)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err == nil && apiErr.Error != "" {
			if apiErr.Message != "" {
				return fmt.Errorf("%s: %s", apiErr.Error, apiErr.Message)
			}
			return fmt.Errorf("%s", apiErr.Error)
		}
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("could not decode response: %w", err)
		}
	}

	return nil
}

// Register creates a new account
func (c *Client) Register(email, password string) (*RegisterResponse, error) {
	var resp RegisterResponse
	err := c.doRequest("POST", "/auth/register", map[string]string{
		"email":    email,
		"password": password,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Login authenticates and returns user info
func (c *Client) Login(email, password string) (*LoginResponse, error) {
	var resp LoginResponse
	err := c.doRequest("POST", "/auth/login", map[string]string{
		"email":    email,
		"password": password,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetMe returns the current user info
func (c *Client) GetMe() (*User, error) {
	var resp struct {
		User User `json:"user"`
	}
	err := c.doRequest("GET", "/auth/me", nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp.User, nil
}

// ListVolumes returns all volumes for the current user
func (c *Client) ListVolumes() ([]Volume, error) {
	var resp VolumesResponse
	err := c.doRequest("GET", "/volumes", nil, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Volumes, nil
}

// CreateVolume creates a new volume
func (c *Client) CreateVolume(req CreateVolumeRequest) (*CreateVolumeResponse, error) {
	var resp CreateVolumeResponse
	err := c.doRequest("POST", "/volumes", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetVolume returns details for a specific volume
func (c *Client) GetVolume(id string) (*VolumeDetailsResponse, error) {
	var resp VolumeDetailsResponse
	err := c.doRequest("GET", "/volumes/"+id, nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// DestroyVolume deletes a volume
func (c *Client) DestroyVolume(id string) error {
	return c.doRequest("DELETE", "/volumes/"+id, nil, nil)
}

// GetUsage returns current billing usage
func (c *Client) GetUsage() (*UsageResponse, error) {
	var resp UsageResponse
	err := c.doRequest("GET", "/billing/usage", nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
