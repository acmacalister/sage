package sage

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptValue(t *testing.T) {
	t.Parallel()

	// Generate a key pair for testing
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	recipient := identity.Recipient()

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple string",
			plaintext: "hello world",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "special characters",
			plaintext: "p@ssw0rd!#$%^&*(){}[]",
		},
		{
			name:      "unicode",
			plaintext: "こんにちは世界 🔐",
		},
		{
			name:      "multiline",
			plaintext: "line1\nline2\nline3",
		},
		{
			name:      "long string",
			plaintext: string(make([]byte, 10000)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Encrypt
			ciphertext, err := EncryptValue(tt.plaintext, []age.Recipient{recipient})
			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)
			assert.NotEqual(t, tt.plaintext, ciphertext)

			// Decrypt
			decrypted, err := DecryptValue(ciphertext, []age.Identity{identity})
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestEncryptValueMultipleRecipients(t *testing.T) {
	t.Parallel()

	// Generate multiple key pairs
	identity1, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	identity2, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	identity3, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	recipients := []age.Recipient{
		identity1.Recipient(),
		identity2.Recipient(),
		identity3.Recipient(),
	}

	plaintext := "secret message for multiple recipients"

	// Encrypt with all recipients
	ciphertext, err := EncryptValue(plaintext, recipients)
	require.NoError(t, err)

	// Each identity should be able to decrypt
	t.Run("identity1 can decrypt", func(t *testing.T) {
		t.Parallel()
		decrypted, err := DecryptValue(ciphertext, []age.Identity{identity1})
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("identity2 can decrypt", func(t *testing.T) {
		t.Parallel()
		decrypted, err := DecryptValue(ciphertext, []age.Identity{identity2})
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("identity3 can decrypt", func(t *testing.T) {
		t.Parallel()
		decrypted, err := DecryptValue(ciphertext, []age.Identity{identity3})
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

func TestEncryptValueNoRecipients(t *testing.T) {
	t.Parallel()

	_, err := EncryptValue("test", []age.Recipient{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no recipients")
}

func TestDecryptValueNoIdentities(t *testing.T) {
	t.Parallel()

	// First create valid ciphertext
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	ciphertext, err := EncryptValue("test", []age.Recipient{identity.Recipient()})
	require.NoError(t, err)

	// Try to decrypt with no identities
	_, err = DecryptValue(ciphertext, []age.Identity{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no identities")
}

func TestDecryptValueWrongIdentity(t *testing.T) {
	t.Parallel()

	// Generate two different key pairs
	identity1, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	identity2, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	// Encrypt with identity1's public key
	ciphertext, err := EncryptValue("secret", []age.Recipient{identity1.Recipient()})
	require.NoError(t, err)

	// Try to decrypt with identity2's private key
	_, err = DecryptValue(ciphertext, []age.Identity{identity2})
	assert.Error(t, err)
}

func TestDecryptValueInvalidBase64(t *testing.T) {
	t.Parallel()

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	_, err = DecryptValue("not-valid-base64!!!", []age.Identity{identity})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode base64")
}

func TestParsePublicKey(t *testing.T) {
	t.Parallel()

	// Generate a valid key to get a valid public key string
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	publicKeyStr := identity.Recipient().String()

	t.Run("valid key", func(t *testing.T) {
		t.Parallel()
		recipient, err := ParsePublicKey(publicKeyStr)
		require.NoError(t, err)
		assert.NotNil(t, recipient)
	})

	t.Run("invalid key", func(t *testing.T) {
		t.Parallel()
		_, err := ParsePublicKey("invalid-key")
		assert.Error(t, err)
	})

	t.Run("empty key", func(t *testing.T) {
		t.Parallel()
		_, err := ParsePublicKey("")
		assert.Error(t, err)
	})
}

func TestValidatePublicKey(t *testing.T) {
	t.Parallel()

	// Generate a valid key
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	publicKeyStr := identity.Recipient().String()

	tests := []struct {
		name      string
		key       string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid key",
			key:       publicKeyStr,
			wantError: false,
		},
		{
			name:      "missing age1 prefix",
			key:       "notage1xyz",
			wantError: true,
			errorMsg:  "must start with 'age1'",
		},
		{
			name:      "invalid format",
			key:       "age1invalidkey",
			wantError: true,
			errorMsg:  "invalid age public key format",
		},
		{
			name:      "empty string",
			key:       "",
			wantError: true,
			errorMsg:  "must start with 'age1'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePublicKey(tt.key)
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadIdentityFromFile(t *testing.T) {
	t.Parallel()

	t.Run("valid key file", func(t *testing.T) {
		t.Parallel()

		// Create a temporary key file
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "key.txt")

		identity, err := age.GenerateX25519Identity()
		require.NoError(t, err)

		content := "# created: test\n# public key: " + identity.Recipient().String() + "\n" + identity.String() + "\n"
		err = os.WriteFile(keyFile, []byte(content), 0600)
		require.NoError(t, err)

		identities, err := LoadIdentityFromFile(keyFile)
		require.NoError(t, err)
		assert.Len(t, identities, 1)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()

		_, err := LoadIdentityFromFile("/nonexistent/path/key.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open")
	})

	t.Run("invalid key content", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "invalid.txt")

		err := os.WriteFile(keyFile, []byte("not a valid key"), 0600)
		require.NoError(t, err)

		_, err = LoadIdentityFromFile(keyFile)
		assert.Error(t, err)
	})
}

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()

	identity, publicKey, err := GenerateKeyPair()
	require.NoError(t, err)

	assert.NotNil(t, identity)
	assert.NotEmpty(t, publicKey)
	assert.True(t, len(publicKey) > 0)
	assert.Equal(t, "age1", publicKey[:4])

	// Verify the public key matches the identity
	assert.Equal(t, publicKey, identity.Recipient().String())
}

func TestGetDefaultIdentityPath(t *testing.T) {
	t.Parallel()

	path := GetDefaultIdentityPath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, ".config")
	assert.Contains(t, path, "sage")
	assert.Contains(t, path, "key.txt")
}

func TestGetIdentitiesFromEnv(t *testing.T) {
	// Not parallel because we're modifying environment variables

	// Generate a test identity
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	keyContent := identity.String()

	t.Run("from SAGE_AGE_KEY env var", func(t *testing.T) {
		// Set the environment variable
		originalKey := os.Getenv("SAGE_AGE_KEY")
		originalKeyFile := os.Getenv("SAGE_AGE_KEY_FILE")
		defer func() {
			os.Setenv("SAGE_AGE_KEY", originalKey)
			os.Setenv("SAGE_AGE_KEY_FILE", originalKeyFile)
		}()

		os.Setenv("SAGE_AGE_KEY", keyContent)
		os.Unsetenv("SAGE_AGE_KEY_FILE")

		identities, err := GetIdentities()
		require.NoError(t, err)
		assert.Len(t, identities, 1)
	})

	t.Run("from SAGE_AGE_KEY_FILE env var", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "key.txt")

		content := "# test key\n" + keyContent + "\n"
		err := os.WriteFile(keyFile, []byte(content), 0600)
		require.NoError(t, err)

		// Set the environment variable
		originalKey := os.Getenv("SAGE_AGE_KEY")
		originalKeyFile := os.Getenv("SAGE_AGE_KEY_FILE")
		defer func() {
			os.Setenv("SAGE_AGE_KEY", originalKey)
			os.Setenv("SAGE_AGE_KEY_FILE", originalKeyFile)
		}()

		os.Unsetenv("SAGE_AGE_KEY")
		os.Setenv("SAGE_AGE_KEY_FILE", keyFile)

		identities, err := GetIdentities()
		require.NoError(t, err)
		assert.Len(t, identities, 1)
	})
}
