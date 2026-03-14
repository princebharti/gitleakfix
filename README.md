# Homebrew Tap for leakfix

This is the official Homebrew tap for [leakfix](https://github.com/princebharti/leakfix) — a CLI tool to detect, remove, and prevent secrets in git repositories.

## Installation

```bash
brew tap princebharti/tap
brew install leakfix
```

## Usage

After installation, run:

```bash
leakfix --help
leakfix setup      # Interactive setup wizard
leakfix scan       # Scan current repo for secrets
```

## Requirements

leakfix requires these external tools (installed automatically as dependencies):

- [gitleaks](https://github.com/gitleaks/gitleaks) — for secret detection
- [git-filter-repo](https://github.com/newren/git-filter-repo) — for history rewriting

## More Information

- [leakfix on GitHub](https://github.com/princebharti/leakfix)
- [leakfix on PyPI](https://pypi.org/project/leakfix/)

## License

MIT License
