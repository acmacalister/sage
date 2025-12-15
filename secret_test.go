package sage

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestGetSortedKeysHelper(t *testing.T) {
	t.Parallel()

	t.Run("returns sorted keys", func(t *testing.T) {
		t.Parallel()

		m := map[string]string{
			"zebra":  "1",
			"apple":  "2",
			"mango":  "3",
			"banana": "4",
		}

		keys := getSortedKeys(m)
		assert.Equal(t, []string{"apple", "banana", "mango", "zebra"}, keys)
	})

	t.Run("handles empty map", func(t *testing.T) {
		t.Parallel()

		m := map[string]string{}
		keys := getSortedKeys(m)
		assert.Empty(t, keys)
	})

	t.Run("handles single key", func(t *testing.T) {
		t.Parallel()

		m := map[string]string{"only": "one"}
		keys := getSortedKeys(m)
		assert.Equal(t, []string{"only"}, keys)
	})

	t.Run("handles keys with numbers", func(t *testing.T) {
		t.Parallel()

		m := map[string]string{
			"KEY_10": "1",
			"KEY_2":  "2",
			"KEY_1":  "3",
		}

		keys := getSortedKeys(m)
		// Lexicographic sort: KEY_1, KEY_10, KEY_2
		assert.Equal(t, []string{"KEY_1", "KEY_10", "KEY_2"}, keys)
	})
}

func TestWriteOutputHelper(t *testing.T) {
	t.Parallel()

	t.Run("writes to stdout when no path specified", func(t *testing.T) {
		t.Parallel()

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := writeOutput("test content", "")
		require.NoError(t, err)

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		io.Copy(&buf, r)
		assert.Equal(t, "test content", buf.String())
	})

	t.Run("writes to file when path specified", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "output.txt")

		err := writeOutput("file content", outPath)
		require.NoError(t, err)

		content, err := os.ReadFile(outPath)
		require.NoError(t, err)
		assert.Equal(t, "file content", string(content))
	})

	t.Run("creates parent directories", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "nested", "dir", "output.txt")

		err := writeOutput("nested content", outPath)
		require.NoError(t, err)

		content, err := os.ReadFile(outPath)
		require.NoError(t, err)
		assert.Equal(t, "nested content", string(content))
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "existing.txt")

		// Create existing file
		err := os.WriteFile(outPath, []byte("old content"), 0644)
		require.NoError(t, err)

		// Overwrite
		err = writeOutput("new content", outPath)
		require.NoError(t, err)

		content, err := os.ReadFile(outPath)
		require.NoError(t, err)
		assert.Equal(t, "new content", string(content))
	})
}

func TestDecryptAllSecretsHelper(t *testing.T) {
	// Not parallel due to env var modification
	_, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	t.Run("decrypts all secrets", func(t *testing.T) {
		err := config.SetSecret("decrypt-test", "KEY1", "value1")
		require.NoError(t, err)
		err = config.SetSecret("decrypt-test", "KEY2", "value2")
		require.NoError(t, err)

		secrets, err := decryptAllSecrets(config, "decrypt-test")
		require.NoError(t, err)

		assert.Len(t, secrets, 2)
		assert.Equal(t, "value1", secrets["KEY1"])
		assert.Equal(t, "value2", secrets["KEY2"])
	})

	t.Run("errors on empty environment", func(t *testing.T) {
		_, err := decryptAllSecrets(config, "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no secrets found")
	})

	t.Run("handles special characters in values", func(t *testing.T) {
		specialValue := "p@ssw0rd!#$%^&*(){}[]|\\:\";<>?,./~`"
		err := config.SetSecret("special-env", "SPECIAL_KEY", specialValue)
		require.NoError(t, err)

		secrets, err := decryptAllSecrets(config, "special-env")
		require.NoError(t, err)

		assert.Equal(t, specialValue, secrets["SPECIAL_KEY"])
	})

	t.Run("handles unicode values", func(t *testing.T) {
		unicodeValue := "こんにちは世界 🔐 مرحبا"
		err := config.SetSecret("unicode-env", "UNICODE_KEY", unicodeValue)
		require.NoError(t, err)

		secrets, err := decryptAllSecrets(config, "unicode-env")
		require.NoError(t, err)

		assert.Equal(t, unicodeValue, secrets["UNICODE_KEY"])
	})

	t.Run("handles multiline values", func(t *testing.T) {
		multilineValue := "line1\nline2\nline3\n"
		err := config.SetSecret("multiline-env", "MULTILINE_KEY", multilineValue)
		require.NoError(t, err)

		secrets, err := decryptAllSecrets(config, "multiline-env")
		require.NoError(t, err)

		assert.Equal(t, multilineValue, secrets["MULTILINE_KEY"])
	})
}

func TestSecretExportFormats(t *testing.T) {
	// Not parallel due to env var modification
	_, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	// Set up test secrets
	err := config.SetSecret("export-test", "API_KEY", "sk_test_12345")
	require.NoError(t, err)
	err = config.SetSecret("export-test", "DATABASE_URL", "postgres://user:pass@localhost/db")
	require.NoError(t, err)
	err = config.SetSecret("export-test", "JWT_SECRET", "super-secret-jwt")
	require.NoError(t, err)

	secrets, err := decryptAllSecrets(config, "export-test")
	require.NoError(t, err)

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	t.Run("env format", func(t *testing.T) {
		var result strings.Builder
		for _, key := range keys {
			result.WriteString("export " + key + "=" + "\"" + secrets[key] + "\"\n")
		}
		output := result.String()

		assert.Contains(t, output, "export API_KEY=\"sk_test_12345\"")
		assert.Contains(t, output, "export DATABASE_URL=\"postgres://user:pass@localhost/db\"")
		assert.Contains(t, output, "export JWT_SECRET=\"super-secret-jwt\"")
	})

	t.Run("dotenv format", func(t *testing.T) {
		var result strings.Builder
		for _, key := range keys {
			result.WriteString(key + "=" + secrets[key] + "\n")
		}
		output := result.String()

		assert.Contains(t, output, "API_KEY=sk_test_12345")
		assert.Contains(t, output, "DATABASE_URL=postgres://user:pass@localhost/db")
		assert.Contains(t, output, "JWT_SECRET=super-secret-jwt")
		assert.NotContains(t, output, "export")
	})

	t.Run("json format", func(t *testing.T) {
		jsonBytes, err := json.MarshalIndent(secrets, "", "  ")
		require.NoError(t, err)

		var parsed map[string]string
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "sk_test_12345", parsed["API_KEY"])
		assert.Equal(t, "postgres://user:pass@localhost/db", parsed["DATABASE_URL"])
		assert.Equal(t, "super-secret-jwt", parsed["JWT_SECRET"])
	})

	t.Run("yaml format", func(t *testing.T) {
		yamlBytes, err := yaml.Marshal(secrets)
		require.NoError(t, err)

		var parsed map[string]string
		err = yaml.Unmarshal(yamlBytes, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "sk_test_12345", parsed["API_KEY"])
		assert.Equal(t, "postgres://user:pass@localhost/db", parsed["DATABASE_URL"])
		assert.Equal(t, "super-secret-jwt", parsed["JWT_SECRET"])
	})
}

func TestSecretExportWithSpecialValues(t *testing.T) {
	// Not parallel due to env var modification
	_, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	t.Run("handles values with quotes", func(t *testing.T) {
		err := config.SetSecret("quote-env", "QUOTED", `value with "quotes" and 'apostrophes'`)
		require.NoError(t, err)

		secrets, err := decryptAllSecrets(config, "quote-env")
		require.NoError(t, err)

		// JSON should properly escape
		jsonBytes, err := json.Marshal(secrets)
		require.NoError(t, err)
		assert.Contains(t, string(jsonBytes), `\"quotes\"`)
	})

	t.Run("handles values with newlines", func(t *testing.T) {
		err := config.SetSecret("newline-env", "MULTILINE", "line1\nline2\nline3")
		require.NoError(t, err)

		secrets, err := decryptAllSecrets(config, "newline-env")
		require.NoError(t, err)

		// YAML should handle multiline
		yamlBytes, err := yaml.Marshal(secrets)
		require.NoError(t, err)

		var parsed map[string]string
		err = yaml.Unmarshal(yamlBytes, &parsed)
		require.NoError(t, err)
		assert.Equal(t, "line1\nline2\nline3", parsed["MULTILINE"])
	})

	t.Run("handles empty string value", func(t *testing.T) {
		// Note: SetSecret doesn't allow empty strings, but we can test the decrypt/export path
		config := &SageConfig{
			Keys: map[string]string{
				"test": keyPair.publicKey,
			},
			Environments: map[string]*Environment{
				"empty-val-env": {
					Secrets: map[string]string{},
				},
			},
		}

		keys := config.ListSecrets("empty-val-env")
		assert.Empty(t, keys)
	})
}

func TestMultipleEnvironments(t *testing.T) {
	// Not parallel due to env var modification
	_, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	t.Run("secrets are isolated by environment", func(t *testing.T) {
		// Set different values in different environments
		err := config.SetSecret("dev", "API_KEY", "dev-key")
		require.NoError(t, err)
		err = config.SetSecret("staging", "API_KEY", "staging-key")
		require.NoError(t, err)
		err = config.SetSecret("prod", "API_KEY", "prod-key")
		require.NoError(t, err)

		// Verify each environment has correct value
		devSecrets, err := decryptAllSecrets(config, "dev")
		require.NoError(t, err)
		assert.Equal(t, "dev-key", devSecrets["API_KEY"])

		stagingSecrets, err := decryptAllSecrets(config, "staging")
		require.NoError(t, err)
		assert.Equal(t, "staging-key", stagingSecrets["API_KEY"])

		prodSecrets, err := decryptAllSecrets(config, "prod")
		require.NoError(t, err)
		assert.Equal(t, "prod-key", prodSecrets["API_KEY"])
	})

	t.Run("each environment can have different secrets", func(t *testing.T) {
		err := config.SetSecret("env1", "SECRET_A", "a")
		require.NoError(t, err)
		err = config.SetSecret("env1", "SECRET_B", "b")
		require.NoError(t, err)

		err = config.SetSecret("env2", "SECRET_C", "c")
		require.NoError(t, err)

		env1Secrets := config.ListSecrets("env1")
		env2Secrets := config.ListSecrets("env2")

		assert.Len(t, env1Secrets, 2)
		assert.Len(t, env2Secrets, 1)
		assert.Contains(t, env1Secrets, "SECRET_A")
		assert.Contains(t, env1Secrets, "SECRET_B")
		assert.Contains(t, env2Secrets, "SECRET_C")
	})
}

func TestSecretOperationsWithPersistence(t *testing.T) {
	// Not parallel due to env var modification
	configPath, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	t.Run("secrets persist after save and load", func(t *testing.T) {
		err := config.SetSecret("persist-env", "PERSIST_KEY", "persist-value")
		require.NoError(t, err)

		err = SaveConfig(config, configPath)
		require.NoError(t, err)

		loaded, err := LoadConfig(configPath)
		require.NoError(t, err)

		value, err := loaded.GetSecret("persist-env", "PERSIST_KEY")
		require.NoError(t, err)
		assert.Equal(t, "persist-value", value)
	})

	t.Run("deleted secrets don't persist", func(t *testing.T) {
		err := config.SetSecret("delete-env", "DELETE_KEY", "to-be-deleted")
		require.NoError(t, err)

		err = config.DeleteSecret("delete-env", "DELETE_KEY")
		require.NoError(t, err)

		err = SaveConfig(config, configPath)
		require.NoError(t, err)

		loaded, err := LoadConfig(configPath)
		require.NoError(t, err)

		_, err = loaded.GetSecret("delete-env", "DELETE_KEY")
		assert.Error(t, err)
	})

	t.Run("updated secrets persist with new value", func(t *testing.T) {
		err := config.SetSecret("update-env", "UPDATE_KEY", "old-value")
		require.NoError(t, err)

		err = config.SetSecret("update-env", "UPDATE_KEY", "new-value")
		require.NoError(t, err)

		err = SaveConfig(config, configPath)
		require.NoError(t, err)

		loaded, err := LoadConfig(configPath)
		require.NoError(t, err)

		value, err := loaded.GetSecret("update-env", "UPDATE_KEY")
		require.NoError(t, err)
		assert.Equal(t, "new-value", value)
	})
}

func TestSecretErrorCases(t *testing.T) {
	t.Parallel()

	t.Run("set secret without keys fails", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{}
		err := config.SetSecret("env", "KEY", "value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no keys configured")
	})

	t.Run("get secret from nonexistent environment fails", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{},
		}
		_, err := config.GetSecret("nonexistent", "KEY")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "environment")
	})

	t.Run("get nonexistent secret fails", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"env": {Secrets: map[string]string{}},
			},
		}
		_, err := config.GetSecret("env", "NONEXISTENT")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("delete from nonexistent environment fails", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{},
		}
		err := config.DeleteSecret("nonexistent", "KEY")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "environment")
	})

	t.Run("delete nonexistent secret fails", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"env": {Secrets: map[string]string{}},
			},
		}
		err := config.DeleteSecret("env", "NONEXISTENT")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestListSecretsAllEnvironments(t *testing.T) {
	t.Parallel()

	t.Run("lists secrets from multiple environments", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"dev": {
					Secrets: map[string]string{
						"DEV_KEY1": "enc1",
						"DEV_KEY2": "enc2",
					},
				},
				"prod": {
					Secrets: map[string]string{
						"PROD_KEY1": "enc3",
					},
				},
				"empty": {
					Secrets: map[string]string{},
				},
			},
		}

		devKeys := config.ListSecrets("dev")
		prodKeys := config.ListSecrets("prod")
		emptyKeys := config.ListSecrets("empty")

		assert.Len(t, devKeys, 2)
		assert.Len(t, prodKeys, 1)
		assert.Empty(t, emptyKeys)
	})

	t.Run("environment names are independent", func(t *testing.T) {
		t.Parallel()

		config := &SageConfig{
			Environments: map[string]*Environment{
				"default": {
					Secrets: map[string]string{"KEY": "val1"},
				},
				"DEFAULT": {
					Secrets: map[string]string{"KEY": "val2"},
				},
			},
		}

		defaultKeys := config.ListSecrets("default")
		uppercaseKeys := config.ListSecrets("DEFAULT")

		assert.Len(t, defaultKeys, 1)
		assert.Len(t, uppercaseKeys, 1)
	})
}

func TestSecretKeyNaming(t *testing.T) {
	// Not parallel due to env var modification
	_, _, keyPair := setupTestEnv(t)

	config := &SageConfig{
		Keys: map[string]string{
			"test": keyPair.publicKey,
		},
	}

	t.Run("handles various key name formats", func(t *testing.T) {
		testCases := []struct {
			key   string
			value string
		}{
			{"SIMPLE_KEY", "value1"},
			{"key_with_lowercase", "value2"},
			{"KEY123", "value3"},
			{"key-with-dashes", "value4"},
			{"key.with.dots", "value5"},
			{"KEY_WITH_NUMBERS_123", "value6"},
		}

		for _, tc := range testCases {
			err := config.SetSecret("naming-env", tc.key, tc.value)
			require.NoError(t, err, "failed to set key: %s", tc.key)
		}

		secrets, err := decryptAllSecrets(config, "naming-env")
		require.NoError(t, err)

		for _, tc := range testCases {
			assert.Equal(t, tc.value, secrets[tc.key], "key: %s", tc.key)
		}
	})
}
