package sage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyValidation(t *testing.T) {
	t.Parallel()

	keyPair := generateTestKeyPair(t)

	t.Run("valid key passes validation", func(t *testing.T) {
		t.Parallel()
		err := ValidatePublicKey(keyPair.publicKey)
		assert.NoError(t, err)
	})

	t.Run("invalid key fails validation", func(t *testing.T) {
		t.Parallel()
		err := ValidatePublicKey("invalid-key")
		assert.Error(t, err)
	})

	t.Run("key without age1 prefix fails", func(t *testing.T) {
		t.Parallel()
		err := ValidatePublicKey("notage1xyz")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must start with 'age1'")
	})
}

func TestKeyGeneration(t *testing.T) {
	t.Parallel()

	t.Run("generates valid key pair", func(t *testing.T) {
		t.Parallel()

		identity, publicKey, err := GenerateKeyPair()
		require.NoError(t, err)

		assert.NotNil(t, identity)
		assert.NotEmpty(t, publicKey)
		assert.True(t, len(publicKey) > 0)
		assert.Equal(t, "age1", publicKey[:4])
		assert.Equal(t, publicKey, identity.Recipient().String())
	})
}

func TestKeyFileOperations(t *testing.T) {
	t.Parallel()

	t.Run("loads identity from valid key file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "key.txt")

		identity, publicKey, err := GenerateKeyPair()
		require.NoError(t, err)

		content := "# created: test\n# public key: " + publicKey + "\n" + identity.String() + "\n"
		err = os.WriteFile(keyFile, []byte(content), 0600)
		require.NoError(t, err)

		identities, err := LoadIdentityFromFile(keyFile)
		require.NoError(t, err)
		assert.Len(t, identities, 1)
	})

	t.Run("errors on nonexistent file", func(t *testing.T) {
		t.Parallel()

		_, err := LoadIdentityFromFile("/nonexistent/path/key.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open")
	})

	t.Run("errors on invalid key content", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "invalid.txt")

		err := os.WriteFile(keyFile, []byte("not a valid key"), 0600)
		require.NoError(t, err)

		_, err = LoadIdentityFromFile(keyFile)
		assert.Error(t, err)
	})
}

func TestDefaultIdentityPath(t *testing.T) {
	t.Parallel()

	path := GetDefaultIdentityPath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, ".config")
	assert.Contains(t, path, "sage")
	assert.Contains(t, path, "key.txt")
}

func TestConfigKeyManagement(t *testing.T) {
	t.Parallel()

	keyPair := generateTestKeyPair(t)

	t.Run("adds key to config", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{}
		err := config.AddKey("alice", keyPair.publicKey)

		require.NoError(t, err)
		assert.Equal(t, keyPair.publicKey, config.Keys["alice"])
	})

	t.Run("rejects invalid key", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{}
		err := config.AddKey("bob", "invalid-key")

		assert.Error(t, err)
	})

	t.Run("removes key from config", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Keys: map[string]string{
				"alice": keyPair.publicKey,
				"bob":   keyPair.publicKey,
			},
		}

		err := config.RemoveKey("alice")
		require.NoError(t, err)
		assert.NotContains(t, config.Keys, "alice")
		assert.Contains(t, config.Keys, "bob")
	})

	t.Run("errors removing nonexistent key", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Keys: map[string]string{"alice": keyPair.publicKey},
		}

		err := config.RemoveKey("nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("gets recipients from keys", func(t *testing.T) {
		t.Parallel()

		keyPair2 := generateTestKeyPair(t)

		config := &SageConfig{
			Keys: map[string]string{
				"alice": keyPair.publicKey,
				"bob":   keyPair2.publicKey,
			},
		}

		recipients, err := config.GetRecipients()
		require.NoError(t, err)
		assert.Len(t, recipients, 2)
	})

	t.Run("errors when no keys configured", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{Keys: map[string]string{}}
		_, err := config.GetRecipients()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no keys configured")
	})
}
