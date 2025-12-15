package sage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage age encryption keys",
	Long:  `Add, remove, and list age public keys for contributors.`,
}

var keyAddCmd = &cobra.Command{
	Use:   "add [name] [public-key]",
	Short: "Add a contributor's age public key",
	Long: `Add a new age public key for a contributor. The key will be used to encrypt
secrets they should have access to. After adding a key, existing secrets will be
re-encrypted to include the new recipient.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		publicKey := args[1]

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Check if key already exists
		if existingKey, exists := config.Keys[name]; exists {
			return fmt.Errorf("key '%s' already exists with value: %s", name, existingKey)
		}

		// Validate and add the key
		if err := config.AddKey(name, publicKey); err != nil {
			return err
		}

		// Re-encrypt secrets if there are existing secrets and we have the identity
		hasSecrets := false
		for _, env := range config.Environments {
			if len(env.Secrets) > 0 {
				hasSecrets = true
				break
			}
		}

		if hasSecrets {
			if err := config.ReencryptSecrets(); err != nil {
				return fmt.Errorf("failed to re-encrypt secrets with new key: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Re-encrypted all secrets with new key\n")
		}

		if err := SaveConfig(config, viper.ConfigFileUsed()); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Added age public key for '%s'\n", name)
		return nil
	},
}

var keyRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a contributor's age public key",
	Long: `Remove an age public key for a contributor. Secrets will be re-encrypted
without this key, revoking the contributor's access to future secret values.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Remove the key
		if err := config.RemoveKey(name); err != nil {
			return err
		}

		// Re-encrypt secrets without the removed key
		hasSecrets := false
		for _, env := range config.Environments {
			if len(env.Secrets) > 0 {
				hasSecrets = true
				break
			}
		}

		if hasSecrets && len(config.Keys) > 0 {
			if err := config.ReencryptSecrets(); err != nil {
				return fmt.Errorf("failed to re-encrypt secrets: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Re-encrypted all secrets without removed key\n")
		}

		if err := SaveConfig(config, viper.ConfigFileUsed()); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Removed age public key for '%s'\n", name)
		return nil
	},
}

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured age public keys",
	Long:  `Display all age public keys currently configured for secret encryption.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if len(config.Keys) == 0 {
			fmt.Println("No keys configured. Add one with 'sage key add [name] [public-key]'")
			return nil
		}

		// Sort keys by name for consistent output
		names := make([]string, 0, len(config.Keys))
		for name := range config.Keys {
			names = append(names, name)
		}
		sort.Strings(names)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tPUBLIC KEY")
		for _, name := range names {
			key := config.Keys[name]
			// Truncate key for display
			displayKey := key
			if len(key) > 40 {
				displayKey = key[:37] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\n", name, displayKey)
		}
		w.Flush()

		return nil
	},
}

var keyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new age key pair",
	Long: `Generate a new age X25519 key pair. The private key will be saved to the
default location (~/.config/sage/key.txt) or the path specified by SAGE_AGE_KEY_FILE.
The public key will be printed to stdout for sharing with your team.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath == "" {
			outputPath = GetDefaultIdentityPath()
		}

		// Check if key already exists
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("key file already exists at %s; remove it first or specify a different path with --output", outputPath)
		}

		// Generate key pair
		identity, publicKey, err := GenerateKeyPair()
		if err != nil {
			return err
		}

		// Ensure directory exists
		dir := filepath.Dir(outputPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}

		// Write private key to file
		f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("failed to create key file: %w", err)
		}
		defer f.Close()

		fmt.Fprintf(f, "# created: sage key generate\n")
		fmt.Fprintf(f, "# public key: %s\n", publicKey)
		fmt.Fprintln(f, identity.String())

		fmt.Fprintf(os.Stderr, "Private key saved to: %s\n", outputPath)
		fmt.Fprintf(os.Stderr, "\nPublic key (share this with your team):\n")
		fmt.Println(publicKey)

		return nil
	},
}

var keyInitCmd = &cobra.Command{
	Use:   "init [name]",
	Short: "Initialize sage with a new key",
	Long: `Generate a new age key pair and add it to the sage configuration. This is a
convenience command that combines 'key generate' and 'key add'.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath == "" {
			outputPath = GetDefaultIdentityPath()
		}

		// Check if key already exists
		var identity *age.X25519Identity
		var publicKey string

		if _, err := os.Stat(outputPath); err == nil {
			// Key exists, load and extract public key
			identities, err := LoadIdentityFromFile(outputPath)
			if err != nil {
				return fmt.Errorf("failed to load existing key: %w", err)
			}
			if len(identities) == 0 {
				return fmt.Errorf("no identities found in key file")
			}
			// Get public key from the first identity
			if x25519, ok := identities[0].(*age.X25519Identity); ok {
				publicKey = x25519.Recipient().String()
			} else {
				return fmt.Errorf("unsupported identity type")
			}
			fmt.Fprintf(os.Stderr, "Using existing key from: %s\n", outputPath)
		} else {
			// Generate new key
			var err error
			identity, publicKey, err = GenerateKeyPair()
			if err != nil {
				return err
			}

			// Ensure directory exists
			dir := filepath.Dir(outputPath)
			if err := os.MkdirAll(dir, 0700); err != nil {
				return fmt.Errorf("failed to create key directory: %w", err)
			}

			// Write private key to file
			f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
			if err != nil {
				return fmt.Errorf("failed to create key file: %w", err)
			}

			fmt.Fprintf(f, "# created: sage key init\n")
			fmt.Fprintf(f, "# public key: %s\n", publicKey)
			fmt.Fprintln(f, identity.String())
			f.Close()

			fmt.Fprintf(os.Stderr, "Generated new key at: %s\n", outputPath)
		}

		// Load or create config
		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Add the key to config
		if err := config.AddKey(name, publicKey); err != nil {
			return err
		}

		configPath := viper.ConfigFileUsed()
		if configPath == "" {
			configPath = DefaultConfigPath()
		}

		if err := SaveConfig(config, configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Added key '%s' to %s\n", name, configPath)
		fmt.Fprintf(os.Stderr, "\nPublic key (share this with your team):\n")
		fmt.Println(publicKey)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyAddCmd)
	keyCmd.AddCommand(keyRemoveCmd)
	keyCmd.AddCommand(keyListCmd)
	keyCmd.AddCommand(keyGenerateCmd)
	keyCmd.AddCommand(keyInitCmd)

	keyGenerateCmd.Flags().StringP("output", "o", "", "output path for the private key")
	keyInitCmd.Flags().StringP("output", "o", "", "output path for the private key")
}
