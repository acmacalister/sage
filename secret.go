package sage

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	Long:  `Set, get, delete, and list encrypted secrets.`,
}

var secretSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a secret value",
	Long: `Encrypt and store a secret value. The value will be encrypted with all
configured age keys. If value is omitted, it will be read from stdin.`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		var value string

		if len(args) > 1 {
			value = args[1]
		} else {
			// Read from stdin
			fromStdin, _ := cmd.Flags().GetBool("stdin")
			if fromStdin || len(args) == 1 {
				fmt.Fprint(os.Stderr, "Enter secret value: ")
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
				value = strings.TrimSuffix(input, "\n")
			}
		}

		if value == "" {
			return fmt.Errorf("secret value cannot be empty")
		}

		env := viper.GetString("env")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if len(config.Keys) == 0 {
			return fmt.Errorf("no keys configured; add at least one key with 'sage key add' or 'sage key init'")
		}

		// Encrypt and store the secret
		if err := config.SetSecret(env, key, value); err != nil {
			return fmt.Errorf("failed to set secret: %w", err)
		}

		configPath := viper.ConfigFileUsed()
		if configPath == "" {
			configPath = DefaultConfigPath()
		}

		if err := SaveConfig(config, configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Set secret '%s' in environment '%s'\n", key, env)
		return nil
	},
}

var secretGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get a secret value",
	Long:  `Decrypt and display a secret value.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		env := viper.GetString("env")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		value, err := config.GetSecret(env, key)
		if err != nil {
			return err
		}

		// Check if we should show just the value (for piping)
		quiet, _ := cmd.Flags().GetBool("quiet")
		if quiet {
			fmt.Print(value)
		} else {
			fmt.Println(value)
		}

		return nil
	},
}

var secretDeleteCmd = &cobra.Command{
	Use:   "delete [key]",
	Short: "Delete a secret",
	Long:  `Remove a secret from the configuration.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		env := viper.GetString("env")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if err := config.DeleteSecret(env, key); err != nil {
			return err
		}

		configPath := viper.ConfigFileUsed()
		if configPath == "" {
			configPath = DefaultConfigPath()
		}

		if err := SaveConfig(config, configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Deleted secret '%s' from environment '%s'\n", key, env)
		return nil
	},
}

var secretListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Long:  `Display all secret keys (not values) for the specified environment.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		env := viper.GetString("env")
		allEnvs, _ := cmd.Flags().GetBool("all")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if allEnvs {
			// List secrets from all environments
			if len(config.Environments) == 0 {
				fmt.Println("No secrets configured in any environment.")
				return nil
			}

			// Sort environment names
			envNames := make([]string, 0, len(config.Environments))
			for name := range config.Environments {
				envNames = append(envNames, name)
			}
			sort.Strings(envNames)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ENVIRONMENT\tKEY")

			for _, envName := range envNames {
				environment := config.Environments[envName]
				if len(environment.Secrets) == 0 {
					continue
				}

				// Sort secret keys
				keys := make([]string, 0, len(environment.Secrets))
				for k := range environment.Secrets {
					keys = append(keys, k)
				}
				sort.Strings(keys)

				for _, key := range keys {
					fmt.Fprintf(w, "%s\t%s\n", envName, key)
				}
			}
			w.Flush()
		} else {
			// List secrets from specified environment
			keys := config.ListSecrets(env)
			if len(keys) == 0 {
				fmt.Printf("No secrets in environment '%s'.\n", env)
				return nil
			}

			sort.Strings(keys)

			fmt.Printf("Secrets in environment '%s':\n", env)
			for _, key := range keys {
				fmt.Printf("  %s\n", key)
			}
		}

		return nil
	},
}

var secretExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets in various formats",
	Long: `Export decrypted secrets in various formats for use in different contexts.
Supported formats: env (shell export), dotenv (.env file), json, yaml.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		env := viper.GetString("env")
		format, _ := cmd.Flags().GetString("format")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		keys := config.ListSecrets(env)
		if len(keys) == 0 {
			return fmt.Errorf("no secrets in environment '%s'", env)
		}

		sort.Strings(keys)

		// Decrypt all secrets
		secrets := make(map[string]string)
		for _, key := range keys {
			value, err := config.GetSecret(env, key)
			if err != nil {
				return fmt.Errorf("failed to decrypt '%s': %w", key, err)
			}
			secrets[key] = value
		}

		switch format {
		case "env", "shell":
			for _, key := range keys {
				fmt.Printf("export %s=%q\n", key, secrets[key])
			}
		case "dotenv":
			for _, key := range keys {
				fmt.Printf("%s=%s\n", key, secrets[key])
			}
		case "json":
			fmt.Println("{")
			for i, key := range keys {
				comma := ","
				if i == len(keys)-1 {
					comma = ""
				}
				fmt.Printf("  %q: %q%s\n", key, secrets[key], comma)
			}
			fmt.Println("}")
		case "yaml":
			for _, key := range keys {
				fmt.Printf("%s: %q\n", key, secrets[key])
			}
		default:
			return fmt.Errorf("unsupported format '%s'; use: env, dotenv, json, or yaml", format)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(secretCmd)
	secretCmd.AddCommand(secretSetCmd)
	secretCmd.AddCommand(secretGetCmd)
	secretCmd.AddCommand(secretDeleteCmd)
	secretCmd.AddCommand(secretListCmd)
	secretCmd.AddCommand(secretExportCmd)

	secretSetCmd.Flags().Bool("stdin", false, "read secret value from stdin")
	secretGetCmd.Flags().BoolP("quiet", "q", false, "output only the value (no newline)")
	secretListCmd.Flags().BoolP("all", "a", false, "list secrets from all environments")
	secretExportCmd.Flags().StringP("format", "f", "env", "output format: env, dotenv, json, yaml")
}
