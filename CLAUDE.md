# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install in editable mode (required for development)
pip install -e ".[effects]"

# Run the CLI
leakfix --help

# Run the benchmark suite (primary test mechanism — no unit test suite exists)
python benchmarks/bench_fix.py
python benchmarks/bench_fix.py --model qwen2.5-coder:3b --no-llm

# Release (PyPI + Homebrew tap + GitHub)
./release.sh
./release.sh --force   # unattended
```

## Architecture

**leakfix** is a Python CLI that detects, fixes, and prevents secrets in git repositories — entirely locally. The fix workflow is: scan → classify → LLM-generate replacement → rewrite git history via `git-filter-repo`.

### Entry point
`leakfix/cli.py` — Click-based CLI. All top-level commands (`scan`, `fix`, `install-hook`, `classify`, `setup`, `scan-org`, `report`, `guard`, `gitignore`) are defined here and delegate to their respective modules.

### Core pipeline

| Module | Role |
|--------|------|
| `scanner.py` | Runs `gitleaks`/`ggshield` (external CLIs), parses `Finding` dataclasses |
| `classifier.py` | Filters false positives via heuristics + optional LLM; returns `Classification` enum (CONFIRMED / LIKELY_FALSE_POSITIVE / REVIEW_NEEDED) |
| `fixer.py` | Orchestrates fix workflow; calls Ollama LLM with `prompts/fix_secret.txt`; applies one of three strategies; rewrites history with `git-filter-repo` |
| `setup_wizard.py` | Manages `~/.leakfix/config.json`; checks dependencies (gitleaks, git-filter-repo, ollama) |
| `reporter.py` | HTML/JSON report generation |
| `ui.py` | Rich console output, colored banners |
| `wizard_app.py` | Textual-based interactive TUI for guided workflows |

### Fix strategies (LLM-selected)
- **`env_ref`** — Replace with language-appropriate env var lookup (`os.environ.get('KEY')`, `process.env.KEY`, `os.Getenv("KEY")`, etc.)
- **`empty`** — For `.env` files: leaves `KEY=` as template
- **`placeholder`** — For config files: uses `${VAR_NAME}` or descriptive text

The LLM prompt lives in `prompts/fix_secret.txt` and contains all strategy selection rules, language-specific syntax, and JSON output format.

### External dependencies required at runtime
- `gitleaks` — secret detection
- `git-filter-repo` — history rewrite
- `ollama` (optional) — local LLM for smart fix generation; default model `qwen2.5-coder:3b`

### Configuration
Stored at `~/.leakfix/config.json`. Key fields: `llm_enabled`, `llm_model`, `llm_base_url`, `llm_fix_timeout` (default 60s).
