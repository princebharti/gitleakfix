#!/bin/bash
set -e

# ─── Config ───────────────────────────────────────────────
LEAKFIX_DIR=~/Desktop/leakfix
TAP_DIR=~/Desktop/homebrew-tap
GITHUB_USER=princebharti
REPO=leakfix
# ──────────────────────────────────────────────────────────

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}==>${NC} $1"; }
warn() { echo -e "${YELLOW}==>${NC} $1"; }
die()  { echo -e "${RED}ERROR:${NC} $1"; exit 1; }

# ─── Get new version ──────────────────────────────────────
CURRENT=$(grep '__version__' "$LEAKFIX_DIR/leakfix/__init__.py" | cut -d'"' -f2)
log "Current version: $CURRENT"
read -p "New version (e.g. 1.2.0): " NEW_VERSION
[[ -z "$NEW_VERSION" ]] && die "Version cannot be empty"
[[ "$NEW_VERSION" == "$CURRENT" ]] && die "New version must differ from current"

# ─── Confirm ──────────────────────────────────────────────
echo ""
warn "About to release v$NEW_VERSION"
warn "This will: bump version, commit, tag, push, update tap"
read -p "Continue? [y/N]: " CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && die "Aborted"

# ─── Step 1: Bump versions ────────────────────────────────
log "Bumping versions..."
cd "$LEAKFIX_DIR"
sed -i '' "s/__version__ = \"$CURRENT\"/__version__ = \"$NEW_VERSION\"/" leakfix/__init__.py
sed -i '' "s/version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" pyproject.toml

# ─── Step 2: Commit and push ──────────────────────────────
log "Committing..."
git add leakfix/__init__.py pyproject.toml
git add -A
git commit -m "chore: release v$NEW_VERSION"
git push origin main

# ─── Step 3: Tag ──────────────────────────────────────────
log "Tagging v$NEW_VERSION..."
git tag "v$NEW_VERSION"
git push origin "v$NEW_VERSION"

# ─── Step 4: Wait for GitHub to generate tarball ──────────
log "Waiting for GitHub to generate tarball..."
sleep 5

# ─── Step 5: Get sha256 ───────────────────────────────────
log "Getting sha256..."
TARBALL_URL="https://github.com/$GITHUB_USER/$REPO/archive/refs/tags/v$NEW_VERSION.tar.gz"
SHA256=$(curl -sL "$TARBALL_URL" | shasum -a 256 | cut -d' ' -f1)
[[ -z "$SHA256" ]] && die "Failed to get sha256"
log "sha256: $SHA256"

# ─── Step 6: Update tap ───────────────────────────────────
log "Updating homebrew-tap..."
cd "$TAP_DIR"
git pull origin main

OLD_VERSION=$CURRENT
# Update URL
sed -i '' "s|refs/tags/v$OLD_VERSION|refs/tags/v$NEW_VERSION|g" Formula/leakfix.rb
# Update sha256 (replace any 64-char hex string)
sed -i '' "s/sha256 \"[a-f0-9]\{64\}\"/sha256 \"$SHA256\"/" Formula/leakfix.rb

git add Formula/leakfix.rb
git commit -m "chore: bump leakfix to v$NEW_VERSION"
git push origin main

# ─── Step 7: Verify install ───────────────────────────────
log "Reinstalling to verify..."
brew uninstall leakfix 2>/dev/null || true
brew update
brew install princebharti/tap/leakfix

INSTALLED=$(leakfix --version | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
if [[ "$INSTALLED" == "$NEW_VERSION" ]]; then
    echo ""
    echo -e "${GREEN}✅ v$NEW_VERSION shipped successfully!${NC}"
else
    die "Version mismatch after install. Expected $NEW_VERSION, got $INSTALLED"
fi
