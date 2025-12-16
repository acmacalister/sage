#!/usr/bin/env fish

# release.fish - Create a tagged release and push to trigger GitHub Actions
#
# Usage:
#   ./scripts/release.fish <version>
#   ./scripts/release.fish v1.0.0
#   ./scripts/release.fish 1.0.0      # 'v' prefix added automatically

set -l version $argv[1]

if test -z "$version"
    echo "Usage: release.fish <version>"
    echo "Example: release.fish v1.0.0"
    echo "         release.fish 1.0.0"
    exit 1
end

# Add 'v' prefix if not present
if not string match -q 'v*' $version
    set version "v$version"
end

# Validate semver format
if not string match -qr '^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' $version
    echo "Error: Invalid version format '$version'"
    echo "Expected format: v1.0.0 or v1.0.0-beta.1"
    exit 1
end

echo "Preparing release $version..."

# Check for uncommitted changes
if test -n (git status --porcelain)
    echo "Error: You have uncommitted changes. Please commit or stash them first."
    git status --short
    exit 1
end

# Check if tag already exists
if git tag -l | grep -q "^$version\$"
    echo "Error: Tag $version already exists"
    exit 1
end

# Get current branch
set -l branch (git branch --show-current)
echo "Current branch: $branch"

# Confirm with user
echo ""
echo "This will:"
echo "  1. Create tag: $version"
echo "  2. Push tag to origin"
echo "  3. Trigger GitHub Actions release workflow"
echo ""
read -P "Continue? [y/N] " -l confirm

if test "$confirm" != "y" -a "$confirm" != "Y"
    echo "Aborted."
    exit 0
end

# Create the tag
echo "Creating tag $version..."
git tag -a $version -m "Release $version"

if test $status -ne 0
    echo "Error: Failed to create tag"
    exit 1
end

# Push the tag
echo "Pushing tag to origin..."
git push origin $version

if test $status -ne 0
    echo "Error: Failed to push tag"
    echo "Removing local tag..."
    git tag -d $version
    exit 1
end

echo ""
echo "Release $version created and pushed!"
echo "GitHub Actions will now build and publish the release."
echo ""
echo "Monitor the release at:"
echo "  https://github.com/acmacalister/sage/actions"
echo ""
echo "View the release at:"
echo "  https://github.com/acmacalister/sage/releases/tag/$version"
