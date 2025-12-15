package sage

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestDecryptAllSecrets(t *testing.T) {
	// Not parallel due to env var modification
	_, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	t.Run("decrypts all secrets in environment", func(t *testing.T) {
		err := config.SetSecret("test-env", "API_KEY", "sk_test_123")
		require.NoError(t, err)
		err = config.SetSecret("test-env", "DB_URL", "postgres://localhost")
		require.NoError(t, err)

		secrets, err := decryptAllSecrets(config, "test-env")
		require.NoError(t, err)

		assert.Len(t, secrets, 2)
		assert.Equal(t, "sk_test_123", secrets["API_KEY"])
		assert.Equal(t, "postgres://localhost", secrets["DB_URL"])
	})

	t.Run("errors on empty environment", func(t *testing.T) {
		_, err := decryptAllSecrets(config, "empty-env")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no secrets found")
	})
}

func TestGenerateOutputFormats(t *testing.T) {
	// Not parallel due to env var modification
	_, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	// Set up test secrets
	err := config.SetSecret("format-test", "API_KEY", "sk_test_12345")
	require.NoError(t, err)
	err = config.SetSecret("format-test", "DATABASE_URL", "postgres://user:pass@localhost/db")
	require.NoError(t, err)

	secrets, err := decryptAllSecrets(config, "format-test")
	require.NoError(t, err)

	t.Run("generates valid kubernetes secret format", func(t *testing.T) {
		// Build k8s secret manually like the command does
		var result strings.Builder
		result.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: test-secret\n  namespace: default\ntype: Opaque\ndata:\n")

		for _, key := range getSortedKeys(secrets) {
			encoded := base64.StdEncoding.EncodeToString([]byte(secrets[key]))
			result.WriteString("  " + key + ": " + encoded + "\n")
		}

		output := result.String()
		assert.Contains(t, output, "apiVersion: v1")
		assert.Contains(t, output, "kind: Secret")
		assert.Contains(t, output, "type: Opaque")
		assert.Contains(t, output, "API_KEY:")
		assert.Contains(t, output, "DATABASE_URL:")

		// Verify base64 encoding
		expectedAPIKey := base64.StdEncoding.EncodeToString([]byte("sk_test_12345"))
		assert.Contains(t, output, expectedAPIKey)
	})

	t.Run("generates valid env format", func(t *testing.T) {
		var result strings.Builder
		for _, key := range getSortedKeys(secrets) {
			result.WriteString(key + "=" + secrets[key] + "\n")
		}

		output := result.String()
		assert.Contains(t, output, "API_KEY=sk_test_12345")
		assert.Contains(t, output, "DATABASE_URL=postgres://user:pass@localhost/db")
	})

	t.Run("generates valid JSON format", func(t *testing.T) {
		jsonBytes, err := json.MarshalIndent(secrets, "", "  ")
		require.NoError(t, err)

		output := string(jsonBytes)

		// Verify it's valid JSON by parsing it back
		var parsed map[string]string
		err = json.Unmarshal([]byte(output), &parsed)
		require.NoError(t, err)

		assert.Equal(t, "sk_test_12345", parsed["API_KEY"])
		assert.Equal(t, "postgres://user:pass@localhost/db", parsed["DATABASE_URL"])
	})

	t.Run("generates compact JSON format", func(t *testing.T) {
		jsonBytes, err := json.Marshal(secrets)
		require.NoError(t, err)

		output := string(jsonBytes)

		// Compact JSON should be on one line
		assert.NotContains(t, output, "\n")

		// Verify it's valid JSON
		var parsed map[string]string
		err = json.Unmarshal([]byte(output), &parsed)
		require.NoError(t, err)
	})

	t.Run("generates valid YAML format", func(t *testing.T) {
		yamlBytes, err := yaml.Marshal(secrets)
		require.NoError(t, err)

		output := string(yamlBytes)

		// Verify it's valid YAML by parsing it back
		var parsed map[string]string
		err = yaml.Unmarshal([]byte(output), &parsed)
		require.NoError(t, err)

		assert.Equal(t, "sk_test_12345", parsed["API_KEY"])
		assert.Equal(t, "postgres://user:pass@localhost/db", parsed["DATABASE_URL"])
	})
}

func TestGetSortedKeys(t *testing.T) {
	t.Parallel()

	t.Run("returns keys in alphabetical order", func(t *testing.T) {
		t.Parallel()

		m := map[string]string{
			"zebra":    "1",
			"apple":    "2",
			"mango":    "3",
			"DATABASE": "4",
		}

		keys := getSortedKeys(m)
		assert.Equal(t, []string{"DATABASE", "apple", "mango", "zebra"}, keys)
	})

	t.Run("handles single key", func(t *testing.T) {
		t.Parallel()

		m := map[string]string{"only": "one"}
		keys := getSortedKeys(m)
		assert.Equal(t, []string{"only"}, keys)
	})

	t.Run("handles empty map", func(t *testing.T) {
		t.Parallel()

		m := map[string]string{}
		keys := getSortedKeys(m)
		assert.Empty(t, keys)
	})
}
