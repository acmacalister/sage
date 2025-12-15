package sage

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "sage",
	Short: "SOPS + AGE secret management for GitOps",
	Long: `sage is a CLI tool for managing age keys and SOPS-encrypted secrets.
It provides unified secret management across environments with support for
multiple output formats (Kubernetes secrets, env vars, YAML, JSON).`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .sage.yaml)")
	rootCmd.PersistentFlags().String("env", "default", "environment to operate on")

	viper.BindPFlag("env", rootCmd.PersistentFlags().Lookup("env"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName(".sage")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
