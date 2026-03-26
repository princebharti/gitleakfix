# leakfix — Detect, Fix & Prevent Secrets in Git Repositories

[![PyPI version](https://img.shields.io/pypi/v/leakfix.svg)](https://pypi.org/project/leakfix/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/princebharti/gitleakfix)
[![Runs 100% locally](https://img.shields.io/badge/runs-100%25%20locally-brightgreen.svg)](https://github.com/princebharti/gitleakfix)

**leakfix** is an open-source CLI tool that scans your git repositories for hardcoded secrets (API keys, passwords, tokens), intelligently fixes them using a local LLM, and rewrites your entire git history — all without sending any data to external servers.

> **No cloud. No subscriptions. No data leaks. Just security.**

---

## The Problem leakfix Solves

You accidentally committed an AWS access key, OpenAI API key, or database password to git. Now it's in your history forever — even if you delete the file. Tools like `git log -S "secret"` can still find it. Attackers scan GitHub for exactly these patterns.

**leakfix fixes this in one command:**

```bash
leakfix fix --all
```

It scans every commit, replaces secrets with context-aware placeholders, rewrites history, and optionally force-pushes — all locally.

---

## Key Features

- **Automatic secret detection** — Powered by [gitleaks](https://github.com/gitleaks/gitleaks) with extended rules for OpenAI, Figma, Jira, Twilio, and more
- **AI-powered smart fixes** — Uses a local LLM (via [Ollama](https://ollama.com)) to generate context-aware replacements:
  - Python: `api_key = "sk-..."` → `api_key = os.environ.get('OPENAI_API_KEY', '')`
  - JavaScript: `const token = 'ghp_...'` → `const token = process.env.GITHUB_TOKEN`
  - Go: `const secret = "..."` → `const secret = os.Getenv("JWT_SECRET")`
  - YAML: `password: mysecret` → `password: ${DATABASE_PASSWORD}`
  - `.env` files: `OPENAI_API_KEY=sk-...` → `OPENAI_API_KEY=` *(template-safe)*
- **Full git history rewrite** — Uses [git-filter-repo](https://github.com/newren/git-filter-repo) to permanently erase secrets from all commits
- **False positive filtering** — Smart classifier distinguishes real credentials from test fixtures and example values
- **100% local** — The LLM runs on your machine via Ollama; nothing is sent to any cloud service
- **Pre-commit hook** — Prevent secrets from being committed in the first place (`leakfix install-hook`)
- **.env.example generation** — Automatically creates a safe `.env.example` template when your `.env` file is cleaned
- **Multi-language aware** — Generates syntactically correct replacements for Python, JavaScript, TypeScript, Go, Ruby, Java, Shell, YAML, and more

---

## Installation

### macOS (Homebrew — recommended)

```bash
brew tap princebharti/tap
brew install gitleakfix
```

### pip

```bash
pip install leakfix
```

### Requirements

leakfix automatically installs its dependencies, but you'll need:

- [gitleaks](https://github.com/gitleaks/gitleaks) — secret detection engine: `brew install gitleaks`
- [git-filter-repo](https://github.com/newren/git-filter-repo) — git history rewriter: `brew install git-filter-repo`
- [Ollama](https://ollama.com) *(optional, for AI-powered fixes)*: `brew install ollama`

---

## Quick Start

```bash
# 1. Smart scan — staged files + git history (ignores unstaged/gitignored)
leakfix scan

# 1b. Full scan — everything including unstaged and untracked files
leakfix scan --all

# 2. Preview what would be fixed (dry run, LLM-generated replacements shown)
leakfix fix --dry-run

# 3. Fix confirmed secrets only (smart mode) — rewrites files AND git history
leakfix fix --no-push

# 4. Fix everything including false positives, then force-push
leakfix fix --all
```

---

## AI-Powered Smart Fix (Recommended)

leakfix integrates with [Ollama](https://ollama.com) to use a local LLM that understands your code context and generates real fixes — not just `REDACTED`.

### Setup

```bash
# Install Ollama
brew install ollama
brew services start ollama

# Pull a code-aware model (~2GB)
ollama pull qwen2.5-coder:3b

# Enable LLM in leakfix
leakfix setup
```

Or create `~/.leakfix/config.json` manually:

```json
{
  "llm_enabled": true,
  "llm_provider": "ollama",
  "llm_model": "qwen2.5-coder:3b",
  "llm_base_url": "http://localhost:11434",
  "llm_fix_timeout": 60
}
```

### What the AI generates

| File type | Before | After |
|---|---|---|
| `.env` | `OPENAI_API_KEY=sk-proj-abc123` | `OPENAI_API_KEY=` |
| Python | `api_key = "sk-proj-abc123"` | `api_key = os.environ.get('OPENAI_API_KEY', '')` |
| JavaScript | `const key = 'ghp_abc123'` | `const key = process.env.GITHUB_TOKEN` |
| Go | `const secret = "jwt-secret"` | `const secret = os.Getenv("JWT_SECRET")` |
| YAML | `password: mypassword` | `password: ${DATABASE_PASSWORD}` |
| Shell | `export AWS_KEY="AKIA..."` | `export AWS_KEY=$AWS_ACCESS_KEY_ID` |

**Benchmark result: 10/10 scenarios pass with 100% LLM usage and ~4s average latency on a 3B model.**

---

## All Commands

```bash
leakfix scan                    # Scan working directory (current files)
leakfix scan --history          # Scan git history only (past commits)
leakfix scan --all              # Scan both working directory and git history
leakfix scan --llm              # Use LLM to filter false positives

leakfix fix                     # Fix confirmed secrets only
leakfix fix --all               # Fix everything (including probable false positives)
leakfix fix --dry-run           # Preview changes without applying
leakfix fix --no-push           # Fix locally, skip force-push to remote
leakfix fix --files-only        # Fix working files only, skip history rewrite
leakfix fix --history-only      # Rewrite history only, skip working files

leakfix install-hook            # Install pre-commit hook to block future leaks
leakfix uninstall-hook          # Remove pre-commit hook
leakfix setup                   # Interactive setup wizard
leakfix gitignore               # Audit and fix .gitignore for secret-related patterns
leakfix guard                   # Watch for dangerous files in real-time
```

---

## Supported Secret Types

leakfix detects secrets from 100+ rules including:

| Provider | Secret Type |
|---|---|
| AWS | Access keys, secret keys, session tokens |
| GitHub | Personal access tokens (ghp_, gho_, ghs_) |
| GitLab | Personal/project access tokens |
| OpenAI | API keys (sk-proj-, sk-) |
| Stripe | Live and test secret keys |
| Slack | Bot tokens, webhook URLs |
| Twilio | Auth tokens, account SIDs |
| SendGrid | API keys |
| Google | API keys, OAuth tokens, service accounts |
| Azure | Storage keys, connection strings |
| Heroku | API keys |
| Figma | Personal access tokens |
| Jira/Atlassian | API tokens |
| Generic | High-entropy strings, passwords, private keys (RSA, EC, DSA) |

---

## How It Works

```
┌─────────────┐    ┌─────────────────┐    ┌──────────────────────┐
│  git repo   │───▶│  gitleaks scan  │───▶│  LLM classifier      │
│  (all       │    │  (detect        │    │  (filter false       │
│  commits)   │    │  secrets)       │    │  positives)          │
└─────────────┘    └─────────────────┘    └──────────┬───────────┘
                                                      │
                        ┌─────────────────────────────▼──────────┐
                        │  LLM fixer (qwen2.5-coder:3b / Ollama) │
                        │  • Reads code context                   │
                        │  • Selects fix strategy:                │
                        │    env_ref / empty / placeholder        │
                        │  • Generates language-native fix        │
                        └───────────────────┬────────────────────┘
                                            │
               ┌────────────────────────────▼────────────────────────────┐
               │                    Apply fixes                           │
               │  1. Replace secrets in working files (strip_quotes fix)  │
               │  2. Rewrite all git history (git-filter-repo)            │
               │  3. Generate .env.example template                       │
               │  4. Force-push cleaned branches                          │
               └─────────────────────────────────────────────────────────┘
```

---

## Why leakfix Instead of Just gitleaks?

| Feature | gitleaks | truffleHog | detect-secrets | **leakfix** |
|---|:---:|:---:|:---:|:---:|
| Detect secrets | ✅ | ✅ | ✅ | ✅ |
| Fix secrets in code | ❌ | ❌ | ❌ | ✅ |
| Rewrite git history | ❌ | ❌ | ❌ | ✅ |
| AI-powered context-aware fix | ❌ | ❌ | ❌ | ✅ |
| Runs 100% locally (no cloud) | ✅ | ❌ | ✅ | ✅ |
| Pre-commit hook | ✅ | ✅ | ✅ | ✅ |
| False positive filtering | ⚠️ | ✅ | ✅ | ✅ |
| .env.example generation | ❌ | ❌ | ❌ | ✅ |
| Language-aware replacements | ❌ | ❌ | ❌ | ✅ |

**leakfix is the only tool that both detects AND fixes secrets — end-to-end.**

---

## Real-World Example

```bash
$ leakfix fix --all --no-push

✓ LLM fix [env-ref]: "ghp_16C***" → "process.env.GITHUB_TOKEN"
  (GitHub token should be stored in an environment variable for security.)

✓ LLM fix [env-ref]: "sk-proj***" → "os.environ.get('OPENAI_API_KEY', '')"
  (OpenAI API key should be read from the environment variable.)

✓ LLM fix [env-ref]: "https://hooks***" → "process.env.SLACK_WEBHOOK_URL"
  (Slack webhook URL should be stored in an environment variable.)

Phase 1/3  Scanning for secrets...   ━━━━━━━━━━━━━━━━━━━━━━ 0:00:02
Phase 2/3  Fixing files...           ━━━━━━━━━━━━━━━━━━━━━━ 0:00:18
Phase 3/3  Rewriting git history...  ━━━━━━━━━━━━━━━━━━━━━━ 0:00:04

✅ 4 secret(s) removed from 3 file(s) across 3 commit(s)
```

---

## Configuration

leakfix stores configuration in `~/.leakfix/config.json`:

```json
{
  "llm_enabled": true,
  "llm_provider": "ollama",
  "llm_model": "qwen2.5-coder:3b",
  "llm_base_url": "http://localhost:11434",
  "llm_fix_timeout": 60
}
```

### Ignoring Files

Create `.leakfixignore` in your repo root (same syntax as `.gitignore`):

```
tests/fixtures/
*.example
docs/
```

---

## Pre-commit Hook

Block secrets from ever reaching git history:

```bash
leakfix install-hook
```

This installs a pre-commit hook that runs `leakfix scan --staged --hook-mode` before every `git commit`. If secrets are found, the commit is rejected with a helpful error message.

---

## FAQ

**Q: Will this break my git history / force me to re-clone?**
A: Yes — rewriting history is a destructive operation. All collaborators must `git clone` fresh after a history rewrite. Plan accordingly, especially for shared repos.

**Q: Does leakfix send my code to any server?**
A: No. Detection uses gitleaks locally. Classification and fixing uses Ollama locally. Zero network calls to external services.

**Q: What if I don't want to use a local LLM?**
A: leakfix works without a LLM. It falls back to descriptive placeholders like `your-openai-api-key-here` instead of `REDACTED`.

**Q: Can I use a different LLM model?**
A: Yes. Any Ollama-compatible model works. Recommended: `qwen2.5-coder:3b` (1.9GB, fast), `qwen2.5-coder:7b` (4.7GB, more accurate). Set `llm_model` in config.

**Q: What is the difference between `leakfix scan` and `leakfix fix`?**
A: `scan` only reports secrets. `fix` reports AND applies replacements in working files + git history.

**Q: What is the difference between `leakfix scan` and `leakfix scan --all`?**
A: `leakfix scan` (smart mode) scans staged files and git history only — the files that are already in or about to enter version control. It ignores unstaged changes and untracked/gitignored files. `leakfix scan --all` scans everything: all files on disk (including untracked and gitignored) plus full git history.

**Q: What is the difference between `leakfix fix` and `leakfix fix --all`?**
A: `leakfix fix` (smart mode) only fixes secrets the classifier identifies as real (CONFIRMED). False positives — test fixtures, example values, template strings — are left alone. `leakfix fix --all` fixes everything the scanner finds, including probable false positives. Both modes use the LLM to generate context-aware replacements (env var references, template values) rather than simple redaction.

**Q: How does leakfix compare to running `git filter-branch` manually?**
A: `git filter-branch` only replaces exact strings you specify. leakfix finds all secrets automatically, generates smart replacements using an LLM, and handles the entire workflow including re-adding remotes.

**Q: Does leakfix work on Windows?**
A: leakfix is primarily tested on macOS and Linux. Windows support is not officially guaranteed.

---

## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/princebharti/gitleakfix).

```bash
git clone https://github.com/princebharti/gitleakfix
cd gitleakfix
pip install -e ".[effects]"

# Run benchmarks
python benchmarks/bench_fix.py --model qwen2.5-coder:3b
```

---

## Related Tools

- [gitleaks](https://github.com/gitleaks/gitleaks) — the secret detection engine leakfix uses under the hood
- [git-filter-repo](https://github.com/newren/git-filter-repo) — fast, safe git history rewriting
- [Ollama](https://ollama.com) — run large language models locally
- [truffleHog](https://github.com/trufflesecurity/trufflehog) — another popular secret scanner
- [detect-secrets](https://github.com/Yelp/detect-secrets) — Yelp's secret scanning library

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*leakfix — because `REDACTED` is not a fix.*
