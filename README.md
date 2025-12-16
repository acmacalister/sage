# sage

**S**OPS + **AGE** secret management for GitOps workflows.

A unified CLI tool for managing age encryption keys and SOPS-encrypted secrets across multiple environments with support for various output formats.

## Features

- 🔑 **Key Management**: Add/remove age public keys for team members
- 🔐 **Secret Management**: Encrypt, decrypt, and manage secrets per environment
- 📦 **Multiple Output Formats**: Export as shell env, .env files, YAML, or JSON
- 🌍 **Environment Support**: Manage secrets across dev, staging, production, etc.
- 🔄 **GitOps Ready**: Store encrypted secrets in version control safely
- 🔒 **Age Encryption**: Modern, secure encryption with age (X25519)

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap acmacalister/tap
brew install --cask sage
```

### Scoop (Windows)

```powershell
scoop bucket add acmacalister https://github.com/acmacalister/scoop-bucket.git
scoop install sage
```

### APT (Debian/Ubuntu)

```bash
# Download the .deb file from the latest release
curl -LO https://github.com/acmacalister/sage/releases/latest/download/sage_linux_amd64.deb
sudo dpkg -i sage_linux_amd64.deb
```

### RPM (Fedora/RHEL/CentOS)

```bash
# Download the .rpm file from the latest release
curl -LO https://github.com/acmacalister/sage/releases/latest/download/sage_linux_amd64.rpm
sudo rpm -i sage_linux_amd64.rpm
```

### APK (Alpine Linux)

```bash
# Download the .apk file from the latest release
curl -LO https://github.com/acmacalister/sage/releases/latest/download/sage_linux_amd64.apk
sudo apk add --allow-untrusted sage_linux_amd64.apk
```

### AUR (Arch Linux)

```bash
# Using yay
yay -S sage-bin

# Or using paru
paru -S sage-bin
```

### Docker

```bash
docker pull ghcr.io/acmacalister/sage:latest

# Run with docker
docker run --rm -v $(pwd):/workdir -w /workdir ghcr.io/acmacalister/sage --help
```

### Go Install

```bash
go install github.com/acmacalister/sage/cmd@latest
```

### Build from Source

```bash
git clone https://github.com/acmacalister/sage.git
cd sage
go build -o sage ./cmd/main.go
```

## Quick Start

### 1. Initialize sage with your key

```bash
# Generate an age key and add it to sage config in one step
sage key init myname

# This creates:
# - ~/.config/sage/key.txt (your private key - keep secret!)
# - .sage.yaml (config file with your public key)
```

### 2. Add team members' public keys

```bash
# Team members share their public keys (from their key init output)
sage key add alice age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
sage key add bob age1234...

# List all configured keys
sage key list
```

### 3. Set secrets

```bash
# Set secrets for default environment
sage secret set DATABASE_URL "postgres://localhost/mydb"
sage secret set API_KEY "sk_test_123"

# Set secrets for specific environment
sage --env production secret set DATABASE_URL "postgres://prod-host/mydb"
sage --env production secret set API_KEY "sk_live_456"

# Read secret value from stdin (for sensitive values)
sage secret set JWT_SECRET
```

### 4. Retrieve secrets

```bash
# Get a single secret
sage secret get DATABASE_URL

# Get secret without newline (for piping)
sage secret get API_KEY -q | pbcopy

# List all secrets in an environment
sage secret list
sage --env production secret list

# List secrets from all environments
sage secret list --all
```

### 5. Export secrets

```bash
# Export as shell commands (for eval)
sage secret export --format env
# Output: export DATABASE_URL="postgres://localhost/mydb"

# Export as .env file format
sage secret export --format dotenv > .env

# Export as JSON
sage secret export --format json

# Export as YAML
sage --env production secret export --format yaml
```

## Usage Example

```bash
# Initialize with a new key
sage key init alice

# Add a secret
sage secret set DATABASE_URL "postgres://localhost/mydb"

# Get a secret
sage secret get DATABASE_URL

# Use different environments
sage --env production secret set API_KEY "prod-key-123"

# Export secrets
sage secret export --format dotenv > .env
```

## Command Reference

### Key Management

```bash
sage key init [name]                  # Generate key and add to config
sage key generate                     # Generate a new age key pair
sage key add [name] [public-key]      # Add a contributor's age public key
sage key remove [name]                # Remove a key (re-encrypts secrets)
sage key list                         # List all configured keys
```

### Secret Management

```bash
sage secret set [key] [value]         # Set a secret (encrypted with all keys)
sage secret set [key]                 # Set a secret (read value from stdin)
sage secret get [key]                 # Get a secret (decrypted)
sage secret get [key] -q              # Get without trailing newline
sage secret delete [key]              # Delete a secret
sage secret list                      # List all secret keys
sage secret list --all                # List secrets from all environments
sage secret export --format [fmt]     # Export secrets (env/dotenv/json/yaml)
```

### Global Flags

- `--config string`: Config file (default: .sage.yaml)
- `--env string`: Environment to operate on (default: "default")

## Configuration

### Config File

sage uses a `.sage.yaml` file to store encrypted secrets and key mappings:

```yaml
keys:
  alice: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  bob: age1234...

environments:
  default:
    secrets:
      DATABASE_URL: YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...
  production:
    secrets:
      DATABASE_URL: YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...
      API_KEY: YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...
```

### Private Key Location

Your age private key is stored at (in order of precedence):

1. `SAGE_AGE_KEY` environment variable (the key content itself)
2. `SAGE_AGE_KEY_FILE` environment variable (path to key file)
3. `~/.config/sage/key.txt` (default location)

## Security

- Private keys are stored with `0600` permissions
- Secrets are encrypted with age (X25519 + ChaCha20-Poly1305)
- All configured public keys can decrypt secrets
- When a key is removed, secrets are re-encrypted without that key

## Development

```bash
# Run locally
go run ./cmd/main.go --help

# Build
go build -o sage ./cmd/main.go

# Run tests
go test -v ./...

# Install
go install ./cmd
```

## License

MIT
