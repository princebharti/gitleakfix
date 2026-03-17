# GitLeakFix (CLI: leakfix)

GitLeakFix is a CLI tool to detect, remove, and prevent secrets in git repositories.

Note: Repository name is gitleakfix, CLI command remains leakfix.

## Installation

```bash
brew tap princebharti/tap
brew install gitleakfix
```

## Usage

After installation, run:

```bash
leakfix --help
leakfix setup      # Interactive setup wizard
leakfix scan       # Scan current repo for secrets
```

You can also use `gitleakfix` as an alias to `leakfix`:

```bash
gitleakfix --help
```

## Requirements

leakfix requires these external tools (installed automatically as dependencies):

- [gitleaks](https://github.com/gitleaks/gitleaks) — for secret detection
- [git-filter-repo](https://github.com/newren/git-filter-repo) — for history rewriting

## More Information

- [GitLeakFix on GitHub](https://github.com/princebharti/gitleakfix)
- [leakfix on PyPI](https://pypi.org/project/leakfix/)

## License

MIT License
