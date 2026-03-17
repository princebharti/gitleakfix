#!/bin/bash
set -e

# ─── Config ───────────────────────────────────────────────
LEAKFIX_DIR=~/Desktop/leakfix
TAP_DIR=~/Desktop/homebrew-tap
GITHUB_USER=princebharti
REPO=gitleakfix
# ──────────────────────────────────────────────────────────

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}==>${NC} $1"; }
warn() { echo -e "${YELLOW}==>${NC} $1"; }
die()  { echo -e "${RED}ERROR:${NC} $1"; exit 1; }

# ─── Parse flags ──────────────────────────────────────────
FORCE=false
for arg in "$@"; do
  [[ "$arg" == "--force" ]] && FORCE=true
done

# ─── Preflight checks ─────────────────────────────────────
log "Running preflight checks..."
[[ -d "$LEAKFIX_DIR" ]] || die "LEAKFIX_DIR not found: $LEAKFIX_DIR"
[[ -d "$TAP_DIR" ]]     || die "TAP_DIR not found: $TAP_DIR"
command -v curl    >/dev/null 2>&1 || die "curl is required"
command -v shasum  >/dev/null 2>&1 || die "shasum is required"
command -v brew    >/dev/null 2>&1 || die "brew is required"

cd "$LEAKFIX_DIR"

# Must be on main branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
[[ "$BRANCH" == "main" ]] || die "Must be on main branch (currently on: $BRANCH)"

# Working tree must be clean (unless --force)
if [[ "$FORCE" != "true" ]]; then
    [[ -z "$(git status --porcelain)" ]] || die "Working tree is dirty — commit or stash changes first"
fi

# ─── Get new version ──────────────────────────────────────
CURRENT=$(grep '__version__' "$LEAKFIX_DIR/leakfix/__init__.py" | cut -d'"' -f2)
log "Current version: $CURRENT"
read -p "New version (e.g. 1.2.0) [enter to reuse $CURRENT]: " NEW_VERSION
[[ -z "$NEW_VERSION" ]] && NEW_VERSION=$CURRENT
if [[ "$NEW_VERSION" == "$CURRENT" && "$FORCE" != "true" ]]; then
    die "New version must differ from current (or use --force to re-release same version)"
fi

# ─── Confirm ──────────────────────────────────────────────
echo ""
warn "About to release v$NEW_VERSION"
warn "This will: bump version, commit, tag, push, update tap"
read -p "Continue? [y/N]: " CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && die "Aborted"

# ─── Step 1: Bump versions ────────────────────────────────
log "Bumping versions..."
sed -i '' "s/__version__ = \"$CURRENT\"/__version__ = \"$NEW_VERSION\"/" leakfix/__init__.py
sed -i '' "s/version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" pyproject.toml

# ─── Step 2: Commit and push ──────────────────────────────
log "Committing..."
git add leakfix/__init__.py pyproject.toml
git add -A
# Only commit if there's something to commit
if [[ -n "$(git status --porcelain)" ]]; then
    git commit -m "chore: release v$NEW_VERSION"
else
    warn "Nothing to commit — skipping commit step"
fi
git push origin main

# ─── Step 3: Tag ──────────────────────────────────────────
if git tag | grep -q "^v$NEW_VERSION$"; then
    if [[ "$FORCE" == "true" ]]; then
        warn "Tag v$NEW_VERSION already exists — deleting and re-tagging (--force)"
        git tag -d "v$NEW_VERSION"
        git push origin ":refs/tags/v$NEW_VERSION"
    else
        die "Tag v$NEW_VERSION already exists. Use --force to re-release."
    fi
fi
log "Tagging v$NEW_VERSION..."
git tag "v$NEW_VERSION"
git push origin "v$NEW_VERSION"

# ─── Step 4: Wait for GitHub to generate tarball ──────────
log "Waiting for GitHub to generate tarball..."
TARBALL_URL="https://github.com/$GITHUB_USER/$REPO/archive/refs/tags/v$NEW_VERSION.tar.gz"
for i in {1..10}; do
    HTTP_CODE=$(curl -sL -o /dev/null -w "%{http_code}" "$TARBALL_URL")
    if [[ "$HTTP_CODE" == "200" ]]; then
        log "Tarball is ready"
        break
    fi
    warn "Tarball not ready yet (attempt $i/10, HTTP $HTTP_CODE) — waiting 5s..."
    sleep 5
    [[ $i -eq 10 ]] && die "Tarball never became available after 50s"
done

# ─── Step 5: Get sha256 ───────────────────────────────────
log "Getting sha256..."
SHA256=$(curl -sL "$TARBALL_URL" | shasum -a 256 | cut -d' ' -f1)
[[ -z "$SHA256" ]] && die "Failed to get sha256"
# Validate it looks like a real sha256 (64 hex chars)
[[ ${#SHA256} -eq 64 ]] || die "sha256 looks invalid (got: $SHA256)"
log "sha256: $SHA256"

# ─── Step 6: Update tap ───────────────────────────────────
log "Updating homebrew-tap..."
cd "$TAP_DIR"
git pull origin main

# Read actual version from formula file to avoid drift
OLD_VERSION=$(grep -o 'refs/tags/v[0-9][0-9.]*[0-9]' Formula/leakfix.rb | head -1 | sed 's|refs/tags/v||')
[[ -z "$OLD_VERSION" ]] && die "Could not read current version from Formula/leakfix.rb"
log "Tap is currently at v$OLD_VERSION"

# Update URL and sha256 — include .tar.gz in pattern to avoid partial matches
sed -i '' "s|refs/tags/v${OLD_VERSION}.tar.gz|refs/tags/v${NEW_VERSION}.tar.gz|g" Formula/leakfix.rb
sed -i '' "s/^  sha256 \"[a-f0-9]*\"/  sha256 \"${SHA256}\"/" Formula/leakfix.rb

# Verify the update landed
grep "v$NEW_VERSION" Formula/leakfix.rb > /dev/null || die "URL update failed in formula"
grep "$SHA256" Formula/leakfix.rb > /dev/null || die "sha256 update failed in formula"

git add Formula/leakfix.rb
# Only commit if there's something to commit
if [[ -n "$(git status --porcelain)" ]]; then
    git commit -m "chore: bump leakfix to v$NEW_VERSION"
    git push origin main
else
    warn "Tap already up to date — skipping commit step"
fi

# ─── Step 7: Clean reinstall to verify ───────────────────
log "Cleaning up existing installation..."
brew uninstall leakfix 2>/dev/null || true
brew untap princebharti/tap 2>/dev/null || true
rm -rf $(brew --cache)/downloads/*leakfix*
rm -f /opt/homebrew/bin/leakfix

log "Tapping and installing fresh..."
brew tap princebharti/tap
brew install princebharti/tap/leakfix

log "Verifying installation..."
command -v leakfix || die "leakfix binary not found after install"
leakfix --help > /dev/null 2>&1 || die "leakfix --help failed"
leakfix scan --help > /dev/null 2>&1 || die "leakfix scan --help failed"

INSTALLED=$(leakfix --version | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
if [[ "$INSTALLED" == "$NEW_VERSION" ]]; then
    echo ""
    echo -e "${GREEN}✅ v$NEW_VERSION shipped successfully!${NC}"
else
    die "Version mismatch after install. Expected $NEW_VERSION, got $INSTALLED"
fi
