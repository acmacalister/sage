package sage

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// EncryptValue encrypts a plaintext value for multiple age recipients.
// Returns a base64-encoded ciphertext string.
func EncryptValue(plaintext string, recipients []age.Recipient) (string, error) {
	if len(recipients) == 0 {
		return "", fmt.Errorf("no recipients specified for encryption")
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return "", fmt.Errorf("failed to create encryption writer: %w", err)
	}

	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", fmt.Errorf("failed to write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to close encryption writer: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// DecryptValue decrypts a base64-encoded ciphertext string using the provided identities.
func DecryptValue(ciphertext string, identities []age.Identity) (string, error) {
	if len(identities) == 0 {
		return "", fmt.Errorf("no identities specified for decryption")
	}

	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 ciphertext: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(decoded), identities...)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return string(plaintext), nil
}

// ParsePublicKey parses an age public key string and returns a Recipient.
func ParsePublicKey(publicKey string) (age.Recipient, error) {
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid age public key: %w", err)
	}
	return recipient, nil
}

// ValidatePublicKey checks if a string is a valid age public key.
func ValidatePublicKey(publicKey string) error {
	if !strings.HasPrefix(publicKey, "age1") {
		return fmt.Errorf("age public key must start with 'age1'")
	}
	_, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return fmt.Errorf("invalid age public key format: %w", err)
	}
	return nil
}

// LoadIdentityFromFile loads an age identity (private key) from a file.
// Supports the standard age key file format.
func LoadIdentityFromFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open identity file: %w", err)
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identities: %w", err)
	}

	return identities, nil
}

// GetDefaultIdentityPath returns the default path for the age identity file.
func GetDefaultIdentityPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sage", "key.txt")
}

// GetIdentities loads age identities from the default location or SAGE_AGE_KEY_FILE env var.
func GetIdentities() ([]age.Identity, error) {
	// Check for key in environment variable first
	if keyData := os.Getenv("SAGE_AGE_KEY"); keyData != "" {
		identities, err := age.ParseIdentities(strings.NewReader(keyData))
		if err != nil {
			return nil, fmt.Errorf("failed to parse SAGE_AGE_KEY: %w", err)
		}
		return identities, nil
	}

	// Check for key file path in environment
	keyFile := os.Getenv("SAGE_AGE_KEY_FILE")
	if keyFile == "" {
		keyFile = GetDefaultIdentityPath()
	}

	return LoadIdentityFromFile(keyFile)
}

// GenerateKeyPair generates a new age X25519 key pair.
// Returns the identity (private key) and its corresponding public key string.
func GenerateKeyPair() (*age.X25519Identity, string, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate key pair: %w", err)
	}
	return identity, identity.Recipient().String(), nil
}
