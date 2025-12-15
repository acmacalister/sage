package sage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

var (
	outputFile string
	namespace  string
	secretName string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate secret outputs in various formats",
	Long:  `Generate decrypted secrets in different formats: Kubernetes secrets, env files, YAML, or JSON.`,
}

// decryptAllSecrets decrypts all secrets for the given environment and returns them as a map.
func decryptAllSecrets(config *SageConfig, envName string) (map[string]string, error) {
	keys := config.ListSecrets(envName)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no secrets found in environment '%s'", envName)
	}

	secrets := make(map[string]string)
	for _, key := range keys {
		value, err := config.GetSecret(envName, key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt '%s': %w", key, err)
		}
		secrets[key] = value
	}

	return secrets, nil
}

// writeOutput writes content to file or stdout.
func writeOutput(content string, outputPath string) error {
	if outputPath == "" {
		fmt.Print(content)
		return nil
	}

	// Create parent directories if they don't exist
	if dir := filepath.Dir(outputPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Output written to: %s\n", outputPath)
	return nil
}

// getSortedKeys returns sorted keys from a map.
func getSortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var generateK8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Generate Kubernetes Secret manifest",
	Long:  `Generate a Kubernetes Secret YAML manifest with base64-encoded values.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		env := viper.GetString("env")
		output, _ := cmd.Flags().GetString("output")
		ns, _ := cmd.Flags().GetString("namespace")
		name, _ := cmd.Flags().GetString("name")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		secrets, err := decryptAllSecrets(config, env)
		if err != nil {
			return err
		}

		// Build the Kubernetes Secret manifest
		var result string
		result = fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
data:
`, name, ns)

		// Add base64-encoded secrets
		for _, key := range getSortedKeys(secrets) {
			encoded := base64.StdEncoding.EncodeToString([]byte(secrets[key]))
			result += fmt.Sprintf("  %s: %s\n", key, encoded)
		}

		return writeOutput(result, output)
	},
}

var generateEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Generate .env file",
	Long:  `Generate a .env file with decrypted key=value pairs.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		env := viper.GetString("env")
		output, _ := cmd.Flags().GetString("output")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		secrets, err := decryptAllSecrets(config, env)
		if err != nil {
			return err
		}

		var result string
		for _, key := range getSortedKeys(secrets) {
			result += fmt.Sprintf("%s=%s\n", key, secrets[key])
		}

		return writeOutput(result, output)
	},
}

var generateYamlCmd = &cobra.Command{
	Use:   "yaml",
	Short: "Generate YAML output",
	Long:  `Generate decrypted secrets as YAML.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		env := viper.GetString("env")
		output, _ := cmd.Flags().GetString("output")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		secrets, err := decryptAllSecrets(config, env)
		if err != nil {
			return err
		}

		yamlBytes, err := yaml.Marshal(secrets)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}

		return writeOutput(string(yamlBytes), output)
	},
}

var generateJsonCmd = &cobra.Command{
	Use:   "json",
	Short: "Generate JSON output",
	Long:  `Generate decrypted secrets as JSON.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		env := viper.GetString("env")
		output, _ := cmd.Flags().GetString("output")
		compact, _ := cmd.Flags().GetBool("compact")

		config, err := LoadConfig(viper.ConfigFileUsed())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		secrets, err := decryptAllSecrets(config, env)
		if err != nil {
			return err
		}

		var jsonBytes []byte
		if compact {
			jsonBytes, err = json.Marshal(secrets)
		} else {
			jsonBytes, err = json.MarshalIndent(secrets, "", "  ")
		}
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		return writeOutput(string(jsonBytes)+"\n", output)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generateK8sCmd)
	generateCmd.AddCommand(generateEnvCmd)
	generateCmd.AddCommand(generateYamlCmd)
	generateCmd.AddCommand(generateJsonCmd)

	// Flags for k8s generation
	generateK8sCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	generateK8sCmd.Flags().StringVarP(&namespace, "namespace", "n", "default", "Kubernetes namespace")
	generateK8sCmd.Flags().StringVar(&secretName, "name", "app-secrets", "Secret resource name")

	// Flags for other formats
	generateEnvCmd.Flags().StringP("output", "o", "", "output file (default: stdout)")
	generateYamlCmd.Flags().StringP("output", "o", "", "output file (default: stdout)")
	generateJsonCmd.Flags().StringP("output", "o", "", "output file (default: stdout)")
	generateJsonCmd.Flags().BoolP("compact", "c", false, "output compact JSON (no indentation)")
}
