package sage

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"
)

// SageConfig represents the .sage.yaml configuration file structure.
type SageConfig struct {
	// Keys maps contributor names to their age public keys
	Keys map[string]string `yaml:"keys"`
	// Environments maps environment names to their secrets
	Environments map[string]*Environment `yaml:"environments"`
}

// Environment represents secrets for a specific environment.
type Environment struct {
	// Secrets maps secret names to their encrypted values
	Secrets map[string]string `yaml:"secrets"`
}

// DefaultConfigPath returns the default path for the sage config file.
func DefaultConfigPath() string {
	return ".sage.yaml"
}

// LoadConfig loads the sage configuration from the specified path.
// If the file doesn't exist, returns an empty config.
func LoadConfig(path string) (*SageConfig, error) {
	if path == "" {
		path = DefaultConfigPath()
	}

	config := &SageConfig{
		Keys:         make(map[string]string),
		Environments: make(map[string]*Environment),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Initialize nil maps
	if config.Keys == nil {
		config.Keys = make(map[string]string)
	}
	if config.Environments == nil {
		config.Environments = make(map[string]*Environment)
	}

	return config, nil
}

// SaveConfig saves the sage configuration to the specified path.
func SaveConfig(config *SageConfig, path string) error {
	if path == "" {
		path = DefaultConfigPath()
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetEnvironment returns the environment with the given name, creating it if it doesn't exist.
func (c *SageConfig) GetEnvironment(name string) *Environment {
	if c.Environments == nil {
		c.Environments = make(map[string]*Environment)
	}

	env, exists := c.Environments[name]
	if !exists {
		env = &Environment{
			Secrets: make(map[string]string),
		}
		c.Environments[name] = env
	}

	if env.Secrets == nil {
		env.Secrets = make(map[string]string)
	}

	return env
}

// AddKey adds a new contributor's age public key.
func (c *SageConfig) AddKey(name, publicKey string) error {
	if err := ValidatePublicKey(publicKey); err != nil {
		return err
	}

	if c.Keys == nil {
		c.Keys = make(map[string]string)
	}

	c.Keys[name] = publicKey
	return nil
}

// RemoveKey removes a contributor's age public key.
func (c *SageConfig) RemoveKey(name string) error {
	if c.Keys == nil {
		return fmt.Errorf("key '%s' not found", name)
	}

	if _, exists := c.Keys[name]; !exists {
		return fmt.Errorf("key '%s' not found", name)
	}

	delete(c.Keys, name)
	return nil
}

// GetRecipients returns all configured public keys as age Recipients.
func (c *SageConfig) GetRecipients() ([]age.Recipient, error) {
	if len(c.Keys) == 0 {
		return nil, fmt.Errorf("no keys configured; add at least one key with 'sage key add'")
	}

	recipients := make([]age.Recipient, 0, len(c.Keys))
	for name, key := range c.Keys {
		recipient, err := ParsePublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid key for '%s': %w", name, err)
		}
		recipients = append(recipients, recipient)
	}

	return recipients, nil
}

// SetSecret encrypts and stores a secret value for the given environment.
func (c *SageConfig) SetSecret(envName, key, plaintext string) error {
	recipients, err := c.GetRecipients()
	if err != nil {
		return err
	}

	encrypted, err := EncryptValue(plaintext, recipients)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	env := c.GetEnvironment(envName)
	env.Secrets[key] = encrypted
	return nil
}

// GetSecret decrypts and returns a secret value for the given environment.
func (c *SageConfig) GetSecret(envName, key string) (string, error) {
	env, exists := c.Environments[envName]
	if !exists {
		return "", fmt.Errorf("environment '%s' not found", envName)
	}

	encrypted, exists := env.Secrets[key]
	if !exists {
		return "", fmt.Errorf("secret '%s' not found in environment '%s'", key, envName)
	}

	identities, err := GetIdentities()
	if err != nil {
		return "", fmt.Errorf("failed to load age identity: %w", err)
	}

	plaintext, err := DecryptValue(encrypted, identities)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return plaintext, nil
}

// DeleteSecret removes a secret from the given environment.
func (c *SageConfig) DeleteSecret(envName, key string) error {
	env, exists := c.Environments[envName]
	if !exists {
		return fmt.Errorf("environment '%s' not found", envName)
	}

	if _, exists := env.Secrets[key]; !exists {
		return fmt.Errorf("secret '%s' not found in environment '%s'", key, envName)
	}

	delete(env.Secrets, key)
	return nil
}

// ListSecrets returns all secret keys for the given environment.
func (c *SageConfig) ListSecrets(envName string) []string {
	env, exists := c.Environments[envName]
	if !exists || env.Secrets == nil {
		return nil
	}

	keys := make([]string, 0, len(env.Secrets))
	for k := range env.Secrets {
		keys = append(keys, k)
	}
	return keys
}

// ReencryptSecrets re-encrypts all secrets with the current set of recipients.
// This should be called after adding or removing keys.
func (c *SageConfig) ReencryptSecrets() error {
	identities, err := GetIdentities()
	if err != nil {
		return fmt.Errorf("failed to load age identity for re-encryption: %w", err)
	}

	recipients, err := c.GetRecipients()
	if err != nil {
		return err
	}

	for envName, env := range c.Environments {
		if env.Secrets == nil {
			continue
		}

		for key, encrypted := range env.Secrets {
			// Decrypt with current identity
			plaintext, err := DecryptValue(encrypted, identities)
			if err != nil {
				return fmt.Errorf("failed to decrypt secret '%s' in environment '%s': %w", key, envName, err)
			}

			// Re-encrypt with all recipients
			newEncrypted, err := EncryptValue(plaintext, recipients)
			if err != nil {
				return fmt.Errorf("failed to re-encrypt secret '%s' in environment '%s': %w", key, envName, err)
			}

			env.Secrets[key] = newEncrypted
		}
	}

	return nil
}
