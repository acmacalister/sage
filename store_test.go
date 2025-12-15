package sage

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeyPair holds a generated key pair for testing
type testKeyPair struct {
	identity  *age.X25519Identity
	publicKey string
}

// generateTestKeyPair creates a new key pair for testing
func generateTestKeyPair(t *testing.T) testKeyPair {
	t.Helper()
	identity, publicKey, err := GenerateKeyPair()
	require.NoError(t, err)
	return testKeyPair{identity: identity, publicKey: publicKey}
}

// setupTestEnv sets up a test environment with a temporary config and key file
func setupTestEnv(t *testing.T) (configPath string, keyPath string, keyPair testKeyPair) {
	t.Helper()

	tmpDir := t.TempDir()
	configPath = filepath.Join(tmpDir, ".sage.yaml")
	keyPath = filepath.Join(tmpDir, "key.txt")

	// Generate and save a key
	keyPair = generateTestKeyPair(t)
	keyContent := "# test key\n# public key: " + keyPair.publicKey + "\n" + keyPair.identity.String() + "\n"
	err := os.WriteFile(keyPath, []byte(keyContent), 0600)
	require.NoError(t, err)

	// Set env var to use this key
	t.Setenv("SAGE_AGE_KEY_FILE", keyPath)

	return configPath, keyPath, keyPair
}

func TestLoadConfigNonexistent(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.yaml")

	config, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotNil(t, config.Keys)
	assert.NotNil(t, config.Environments)
	assert.Empty(t, config.Keys)
	assert.Empty(t, config.Environments)
}

func TestLoadConfigEmpty(t *testing.T) {
	t.Parallel()

	config, err := LoadConfig("")
	require.NoError(t, err)
	assert.NotNil(t, config)
}

func TestSaveAndLoadConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".sage.yaml")

	// Create a config with some data
	config := &SageConfig{
		Keys: map[string]string{
			"alice": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
			"bob":   "age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6",
		},
		Environments: map[string]*Environment{
			"default": {
				Secrets: map[string]string{
					"SECRET1": "encrypted1",
					"SECRET2": "encrypted2",
				},
			},
			"production": {
				Secrets: map[string]string{
					"SECRET1": "encrypted3",
				},
			},
		},
	}

	// Save
	err := SaveConfig(config, configPath)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(configPath)
	require.NoError(t, err)

	// Load
	loaded, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, config.Keys, loaded.Keys)
	assert.Len(t, loaded.Environments, 2)
	assert.Equal(t, config.Environments["default"].Secrets, loaded.Environments["default"].Secrets)
	assert.Equal(t, config.Environments["production"].Secrets, loaded.Environments["production"].Secrets)
}

func TestSageConfigGetEnvironment(t *testing.T) {
	t.Parallel()

	t.Run("creates new environment", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{}
		env := config.GetEnvironment("production")

		assert.NotNil(t, env)
		assert.NotNil(t, env.Secrets)
		assert.Contains(t, config.Environments, "production")
	})

	t.Run("returns existing environment", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"staging": {
					Secrets: map[string]string{"KEY": "value"},
				},
			},
		}

		env := config.GetEnvironment("staging")
		assert.Equal(t, "value", env.Secrets["KEY"])
	})

	t.Run("initializes nil secrets map", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"test": {Secrets: nil},
			},
		}

		env := config.GetEnvironment("test")
		assert.NotNil(t, env.Secrets)
	})
}

func TestSageConfigAddKey(t *testing.T) {
	t.Parallel()

	// Generate a valid key for testing
	keyPair := generateTestKeyPair(t)

	t.Run("adds valid key", func(t *testing.T) {
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

	t.Run("initializes nil keys map", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{Keys: nil}
		err := config.AddKey("charlie", keyPair.publicKey)

		require.NoError(t, err)
		assert.NotNil(t, config.Keys)
	})
}

func TestSageConfigRemoveKey(t *testing.T) {
	t.Parallel()

	keyPair := generateTestKeyPair(t)

	t.Run("removes existing key", func(t *testing.T) {
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

	t.Run("errors on nonexistent key", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Keys: map[string]string{"alice": keyPair.publicKey},
		}

		err := config.RemoveKey("nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("errors on nil keys map", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{Keys: nil}
		err := config.RemoveKey("alice")
		assert.Error(t, err)
	})
}

func TestSageConfigGetRecipients(t *testing.T) {
	t.Parallel()

	keyPair1 := generateTestKeyPair(t)
	keyPair2 := generateTestKeyPair(t)

	t.Run("returns recipients for valid keys", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Keys: map[string]string{
				"alice": keyPair1.publicKey,
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

	t.Run("errors on invalid key", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Keys: map[string]string{
				"alice": "invalid-key-format",
			},
		}

		_, err := config.GetRecipients()
		assert.Error(t, err)
	})
}

func TestSageConfigSetAndGetSecret(t *testing.T) {
	// Not parallel because we're modifying environment variables
	configPath, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	t.Run("set and get secret", func(t *testing.T) {
		plaintext := "my-secret-value"

		err := config.SetSecret("default", "API_KEY", plaintext)
		require.NoError(t, err)

		// Verify the secret is encrypted
		env := config.Environments["default"]
		assert.NotEqual(t, plaintext, env.Secrets["API_KEY"])

		// Get the secret back
		retrieved, err := config.GetSecret("default", "API_KEY")
		require.NoError(t, err)
		assert.Equal(t, plaintext, retrieved)
	})

	t.Run("get secret from nonexistent environment", func(t *testing.T) {
		_, err := config.GetSecret("nonexistent", "KEY")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "environment")
	})

	t.Run("get nonexistent secret", func(t *testing.T) {
		config.GetEnvironment("empty") // Create empty env
		_, err := config.GetSecret("empty", "NONEXISTENT")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	// Save and reload to test persistence
	t.Run("persists after save/load", func(t *testing.T) {
		err := config.SetSecret("default", "PERSISTENT", "test-value")
		require.NoError(t, err)

		err = SaveConfig(config, configPath)
		require.NoError(t, err)

		loaded, err := LoadConfig(configPath)
		require.NoError(t, err)

		value, err := loaded.GetSecret("default", "PERSISTENT")
		require.NoError(t, err)
		assert.Equal(t, "test-value", value)
	})
}

func TestSageConfigDeleteSecret(t *testing.T) {
	t.Parallel()

	t.Run("deletes existing secret", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"default": {
					Secrets: map[string]string{
						"KEY1": "value1",
						"KEY2": "value2",
					},
				},
			},
		}

		err := config.DeleteSecret("default", "KEY1")
		require.NoError(t, err)
		assert.NotContains(t, config.Environments["default"].Secrets, "KEY1")
		assert.Contains(t, config.Environments["default"].Secrets, "KEY2")
	})

	t.Run("errors on nonexistent environment", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{Environments: map[string]*Environment{}}
		err := config.DeleteSecret("nonexistent", "KEY")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "environment")
	})

	t.Run("errors on nonexistent secret", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"default": {Secrets: map[string]string{}},
			},
		}

		err := config.DeleteSecret("default", "NONEXISTENT")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestSageConfigListSecrets(t *testing.T) {
	t.Parallel()

	t.Run("lists secrets in environment", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"default": {
					Secrets: map[string]string{
						"KEY1": "value1",
						"KEY2": "value2",
						"KEY3": "value3",
					},
				},
			},
		}

		keys := config.ListSecrets("default")
		assert.Len(t, keys, 3)
		assert.Contains(t, keys, "KEY1")
		assert.Contains(t, keys, "KEY2")
		assert.Contains(t, keys, "KEY3")
	})

	t.Run("returns nil for nonexistent environment", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{Environments: map[string]*Environment{}}
		keys := config.ListSecrets("nonexistent")
		assert.Nil(t, keys)
	})

	t.Run("returns nil for environment with nil secrets", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"empty": {Secrets: nil},
			},
		}

		keys := config.ListSecrets("empty")
		assert.Nil(t, keys)
	})
}

func TestSageConfigReencryptSecrets(t *testing.T) {
	// Not parallel because we're modifying environment variables
	_, _, keyPair1 := setupTestEnv(t)

	// Generate a second key pair
	keyPair2 := generateTestKeyPair(t)

	config := &SageConfig{
		Keys: map[string]string{
			"alice": keyPair1.publicKey,
		},
	}

	// Set a secret with just alice's key
	err := config.SetSecret("default", "SECRET", "original-value")
	require.NoError(t, err)

	originalCiphertext := config.Environments["default"].Secrets["SECRET"]

	// Add bob's key
	err = config.AddKey("bob", keyPair2.publicKey)
	require.NoError(t, err)

	// Re-encrypt
	err = config.ReencryptSecrets()
	require.NoError(t, err)

	newCiphertext := config.Environments["default"].Secrets["SECRET"]

	// Ciphertext should be different (re-encrypted)
	assert.NotEqual(t, originalCiphertext, newCiphertext)

	// Value should still be the same when decrypted
	value, err := config.GetSecret("default", "SECRET")
	require.NoError(t, err)
	assert.Equal(t, "original-value", value)
}

func TestSaveConfigCreatesDirectory(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	nestedPath := filepath.Join(tmpDir, "nested", "dir", ".sage.yaml")

	config := &SageConfig{
		Keys: map[string]string{"test": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"},
	}

	err := SaveConfig(config, nestedPath)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(nestedPath)
	require.NoError(t, err)
}

func TestDefaultConfigPath(t *testing.T) {
	t.Parallel()

	path := DefaultConfigPath()
	assert.Equal(t, ".sage.yaml", path)
}
