"""Setup wizard for leakfix - interactive configuration and dependency checks."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

LEAKFIX_HOME = Path.home() / ".leakfix"
CONFIG_FILE = LEAKFIX_HOME / "config.json"

DEFAULT_CONFIG = {
    "llm_enabled": False,
    "llm_model": None,
    "setup_complete": False,
}

LLM_MODELS = [
    ("qwen3:0.6b", "fastest, 2GB RAM", True),
    ("llama3.2:3b", "balanced, 4GB RAM", False),
    ("phi4", "best quality, 10GB RAM", False),
]


def load_config() -> dict:
    """Load config from ~/.leakfix/config.json or return defaults."""
    if not CONFIG_FILE.exists():
        return dict(DEFAULT_CONFIG)
    try:
        data = json.loads(CONFIG_FILE.read_text())
        return {**DEFAULT_CONFIG, **data}
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save_config(config: dict) -> None:
    """Save config to ~/.leakfix/config.json. Creates directory if needed."""
    LEAKFIX_HOME.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def check_dependency(name: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(name) is not None


def _check_ollama_importable() -> bool:
    """Check if ollama Python package is importable for current Python."""
    result = subprocess.run(
        [sys.executable, "-c", "import ollama; print('ok')"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def check_dependencies_only() -> dict:
    """Check core dependencies and return status dict. For --check flag."""
    return {
        "gitleaks": check_dependency("gitleaks"),
        "git-filter-repo": check_dependency("git-filter-repo"),
        "python3": check_dependency("python3"),
        "ollama": check_dependency("ollama"),
        "ollama_pip": _check_ollama_importable(),
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
    }


def _print_header() -> None:
    print("\n🔐 leakfix Setup")
    print("─" * 42)
    print()


def _print_deps(status: dict) -> bool:
    """Print dependency status. Returns True if all core deps OK."""
    print("Checking core dependencies...")
    print(f"  Python: {status.get('python_version', '?')} ({status.get('python_executable', '?')})")
    print(f"  ollama (Python): {'✅' if status.get('ollama_pip') else '❌'}")
    ok = True
    for name, found in [
        ("gitleaks", status["gitleaks"]),
        ("git-filter-repo", status["git-filter-repo"]),
        ("python3", status["python3"]),
    ]:
        if found:
            print(f"  ✅ {name}")
        else:
            print(f"  ❌ {name}")
            ok = False
    ollama_cli = status.get("ollama", False)
    print(f"  {'✅' if ollama_cli else '❌'} ollama (CLI)")
    if not status["gitleaks"]:
        print("\n  Install: brew install gitleaks")
    if not status["git-filter-repo"]:
        print("  Install: brew install git-filter-repo")
    if not status["python3"]:
        print("  Install: python3 is required (usually pre-installed on macOS)")
    if not status.get("ollama_pip"):
        print("  Install ollama Python: leakfix setup --llm")
    print()
    return ok


def _install_ollama() -> bool:
    """Install ollama via brew on macOS. Returns True if installed or already present."""
    if check_dependency("ollama"):
        return True
    if sys.platform != "darwin":
        print("  Ollama must be installed manually on non-macOS.")
        print("  See: https://ollama.ai")
        return False
    print("  Installing ollama via brew...")
    try:
        result = subprocess.run(
            ["brew", "install", "ollama"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("  ❌ brew not found. Install Homebrew first: https://brew.sh")
        return False
    if result.returncode != 0:
        print(f"  ❌ brew install ollama failed: {result.stderr or result.stdout}")
        return False
    return check_dependency("ollama")


def _install_ollama_pip() -> bool:
    """Install ollama Python package using same Python that runs leakfix. Returns True on success."""
    current_python = sys.executable
    if _check_ollama_importable():
        print(f"  ✅ ollama installed for {current_python}")
        return True
    print(f"  Installing ollama Python package for {current_python}...")
    result = subprocess.run(
        [current_python, "-m", "pip", "install", "ollama", "--break-system-packages"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  ❌ pip install ollama failed: {result.stderr or result.stdout}")
        return False
    verify = subprocess.run(
        [current_python, "-c", "import ollama; print('ok')"],
        capture_output=True,
        text=True,
    )
    if verify.returncode != 0:
        print("  ❌ ollama install failed")
        return False
    print(f"  ✅ ollama installed for {current_python}")
    return True


def _start_ollama_serve() -> bool:
    """Start ollama serve in background. Returns True if started or already running."""
    # Try to run ollama serve; it may already be running
    proc = subprocess.Popen(
        ["ollama", "serve"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Give it a moment to start
    time.sleep(2)
    # Check if process is still alive (serve runs until killed)
    if proc.poll() is not None:
        # Process exited - might mean ollama was already running
        pass
    return True


def _pull_model(model: str) -> bool:
    """Pull ollama model. Returns True on success."""
    print(f"  Pulling {model}... (this may take a few minutes)")
    result = subprocess.run(
        ["ollama", "pull", model],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  ❌ ollama pull {model} failed: {result.stderr or result.stdout}")
        return False
    return True


def _ask_llm_install() -> bool:
    """Ask user if they want to install LLM enhancement. Returns True for yes."""
    prompt = "Install LLM enhancement? [Y/n]: "
    try:
        ans = input(prompt).strip().lower()
        return ans != "n" and ans != "no"
    except (EOFError, KeyboardInterrupt):
        return False


def _ask_llm_change(config: dict) -> bool:
    """Show current LLM config and ask if user wants to change. Returns True for yes."""
    if config.get("llm_enabled") and config.get("llm_model"):
        print(f"LLM: currently enabled ({config['llm_model']})")
    else:
        print("LLM: currently disabled")
    prompt = "Change? [y/N]: "
    try:
        ans = input(prompt).strip().lower()
        return ans in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _ask_model_choice() -> str:
    """Ask user to select model. Returns model name."""
    print("\nSelect model (recommended: qwen3:0.6b):")
    for i, (model, desc, recommended) in enumerate(LLM_MODELS, 1):
        rec = "  ← recommended" if recommended else ""
        print(f"  {i}. {model}   — {desc}{rec}")
    prompt = "Choice [1]: "
    try:
        ans = input(prompt).strip() or "1"
        idx = int(ans)
        if 1 <= idx <= len(LLM_MODELS):
            return LLM_MODELS[idx - 1][0]
    except (ValueError, EOFError, KeyboardInterrupt):
        pass
    return LLM_MODELS[0][0]


def _get_installed_ollama_models() -> list[str]:
    """Get list of installed ollama models."""
    import subprocess
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return []
        models = []
        for line in result.stdout.strip().split('\n')[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if parts:
                    models.append(parts[0])
        return models
    except Exception:
        return []


def _print_quick_start() -> None:
    print("\n✅ leakfix ready!")
    print()
    print("Quick start:")
    print("  leakfix scan                 # scan current repo")
    print("  leakfix scan --smart         # with false positive filter")
    print("  leakfix scan --smart --llm   # with LLM enhancement")
    print("  leakfix fix                  # auto-fix all secrets")
    print("  leakfix --help               # all commands")
    print()


def _run_questionary_wizard(llm_only: bool = False, reset: bool = False, check_only: bool = False) -> bool:
    """
    Run the questionary-based setup wizard. Returns True on success.
    This is the fallback when Textual is not available.
    """
    if check_only:
        _print_header()
        status = check_dependencies_only()
        if not _print_deps(status):
            return False
        _print_quick_start()
        return True

    if reset:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
        config = dict(DEFAULT_CONFIG)
    else:
        config = load_config()

    status = check_dependencies_only()

    if llm_only:
        _print_header()
        print("LLM setup")
        print("─" * 42)
        print(
            "Improves accuracy by using a local AI model to classify uncertain secrets.\n"
            "Runs 100% on your machine — no data ever leaves your device.\n"
        )
    else:
        _print_header()
        if not _print_deps(status):
            return False

    # LLM section: always show when explicit setup (not check_only)
    # For llm_only: run LLM flow directly
    # For explicit setup: show state + Change? prompt; for first-time: Install? prompt
    show_llm_section = llm_only or not check_only
    if show_llm_section:
        if not llm_only:
            print("Optional: LLM-enhanced false positive detection")
            print("─" * 48)
            print(
                "Improves accuracy by using a local AI model to\n"
                "classify uncertain secrets. Runs 100% on your\n"
                "machine — no data ever leaves your device.\n"
                "Requires ~2GB disk space.\n"
            )

        if llm_only:
            do_llm = _ask_llm_install()
        elif config.get("setup_complete"):
            do_llm = _ask_llm_change(config)
        else:
            do_llm = _ask_llm_install()

        if do_llm:
            if not _install_ollama():
                config["llm_enabled"] = False
                config["setup_complete"] = True
                save_config(config)
                print("⏭️  LLM setup skipped due to install failure.")
                _print_quick_start()
                return True

            if not _install_ollama_pip():
                config["llm_enabled"] = False
                config["setup_complete"] = True
                save_config(config)
                print("⏭️  LLM setup skipped due to ollama Python install failure.")
                _print_quick_start()
                return True

            _start_ollama_serve()
            model = _ask_model_choice()
            if not _pull_model(model):
                config["llm_enabled"] = False
                config["setup_complete"] = True
                save_config(config)
                print("⏭️  LLM setup skipped due to pull failure.")
                _print_quick_start()
                return True

            config["llm_enabled"] = True
            config["llm_model"] = model
            config["python_executable"] = sys.executable
            config["python_version"] = sys.version
            config["setup_complete"] = True
            save_config(config)
            print(f"✅ LLM enhancement configured ({model})")
        else:
            if config.get("setup_complete"):
                # User chose N to "Change?" - keep existing config
                pass
            else:
                config["llm_enabled"] = False
                config["setup_complete"] = True
                save_config(config)
                print("⏭️  Skipped. You can enable later with: leakfix setup --llm")

    _print_quick_start()
    return True


def run_setup(llm_only: bool = False, reset: bool = False, check_only: bool = False) -> bool:
    """
    Run the setup wizard. Returns True on success.
    - llm_only: Skip to LLM setup only
    - reset: Clear config and re-run full setup
    - check_only: Skip LLM prompt (dependencies + quick start only)
    
    Tries Textual wizard first, falls back to questionary if unavailable.
    """
    # Try Textual wizard first
    try:
        from leakfix.wizard_app import LeakfixWizardApp
        
        current_config = load_config()
        if reset:
            if CONFIG_FILE.exists():
                CONFIG_FILE.unlink()
            current_config = dict(DEFAULT_CONFIG)
        
        app = LeakfixWizardApp(
            reset=reset,
            llm_only=llm_only,
            check_only=check_only,
            current_config=current_config
        )
        result = app.run()
        if result is not None:
            save_config(result)
            _print_quick_start()
            return True
        return False
    except ImportError:
        pass
    except Exception as e:
        raise
    
    # Fallback to existing questionary wizard
    return _run_questionary_wizard(llm_only=llm_only, reset=reset, check_only=check_only)
