package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// Encryption versions:
// 0x01 = PBKDF2 (web) - version (1) + salt (16) + iv (12) + ciphertext
// 0x02 = Argon2id (CLI) - version (1) + salt (16) + nonce (12) + ciphertext
// Legacy (no version byte) = Argon2id - salt (16) + nonce (12) + ciphertext
const (
	versionPBKDF2  = 0x01
	versionArgon2  = 0x02
)

// Argon2 parameters (OWASP recommended)
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32 // AES-256
	saltLen       = 16
	nonceLen      = 12 // GCM standard
)

// PBKDF2 parameters (matching web crypto)
const (
	pbkdf2Iterations = 100000
)

// GenerateRSAKeyPair generates a new RSA-2048 keypair
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// EncodePrivateKey encodes an RSA private key to PEM format
func EncodePrivateKey(key *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})
}

// DecodePrivateKey decodes a PEM-encoded RSA private key
// Supports both PKCS1 ("RSA PRIVATE KEY") and PKCS8 ("PRIVATE KEY") formats
func DecodePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS1 first (RSA PRIVATE KEY)
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	// Try PKCS8 (PRIVATE KEY) - used by Web Crypto API
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
		return rsaKey, nil
	}

	// Fallback: try PKCS1 regardless of type
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 as last resort
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse key: PKCS1 error: %v, PKCS8 error: %v", err, err2)
		}
		rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
		return rsaKey, nil
	}
	return key, nil
}

// EncryptKey encrypts an RSA private key with a password using Argon2 + AES-256-GCM
// Returns base64-encoded ciphertext: salt (16) + nonce (12) + ciphertext
func EncryptKey(privateKey *rsa.PrivateKey, password string) (string, error) {
	// Encode the private key to PEM
	pemData := EncodePrivateKey(privateKey)

	// Generate random salt
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key using Argon2id
	derivedKey := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the PEM data
	ciphertext := gcm.Seal(nil, nonce, pemData, nil)

	// Combine: salt + nonce + ciphertext
	combined := make([]byte, 0, saltLen+nonceLen+len(ciphertext))
	combined = append(combined, salt...)
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// DecryptKey decrypts a password-encrypted RSA private key
// Supports multiple versions:
// - 0x01: PBKDF2 (web) - version (1) + salt (16) + iv (12) + ciphertext
// - 0x02: Argon2id with version - version (1) + salt (16) + nonce (12) + ciphertext
// - Legacy: Argon2id without version - salt (16) + nonce (12) + ciphertext
func DecryptKey(encryptedBase64 string, password string) (*rsa.PrivateKey, error) {
	// Decode base64
	combined, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(combined) < saltLen+nonceLen+1 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	var derivedKey []byte
	var salt, nonce, ciphertext []byte

	// Check version byte
	version := combined[0]
	if version == versionPBKDF2 {
		// Version 1: PBKDF2 (from web UI)
		if len(combined) < 1+saltLen+nonceLen+1 {
			return nil, fmt.Errorf("encrypted data too short for v1")
		}
		salt = combined[1 : 1+saltLen]
		nonce = combined[1+saltLen : 1+saltLen+nonceLen]
		ciphertext = combined[1+saltLen+nonceLen:]
		derivedKey = pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, argon2KeyLen, sha256.New)
	} else if version == versionArgon2 {
		// Version 2: Argon2id with version byte (future CLI)
		if len(combined) < 1+saltLen+nonceLen+1 {
			return nil, fmt.Errorf("encrypted data too short for v2")
		}
		salt = combined[1 : 1+saltLen]
		nonce = combined[1+saltLen : 1+saltLen+nonceLen]
		ciphertext = combined[1+saltLen+nonceLen:]
		derivedKey = argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	} else {
		// Legacy: Argon2id without version byte (old CLI)
		salt = combined[:saltLen]
		nonce = combined[saltLen : saltLen+nonceLen]
		ciphertext = combined[saltLen+nonceLen:]
		derivedKey = argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt
	pemData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	// Decode PEM to RSA key
	return DecodePrivateKey(pemData)
}

// SaveKeyToFile saves an RSA private key to a file
func SaveKeyToFile(key *rsa.PrivateKey, path string) error {
	pemData := EncodePrivateKey(key)
	return writeFileSecure(path, pemData, 0600)
}

// LoadKeyFromFile loads an RSA private key from a file
func LoadKeyFromFile(path string) (*rsa.PrivateKey, error) {
	pemData, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return DecodePrivateKey(pemData)
}

// Helper to write file with secure permissions
func writeFileSecure(path string, data []byte, perm uint32) error {
	// Import os inline to avoid circular deps
	return writeFileImpl(path, data, perm)
}

func readFile(path string) ([]byte, error) {
	return readFileImpl(path)
}
