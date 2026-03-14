"""File watcher for leakfix - guard mode to prevent accidental secret leaks."""

from __future__ import annotations

import fnmatch
import os
import platform
import signal
import sys
from pathlib import Path

from leakfix.utils import get_repo_root, is_git_repo

# Dangerous file patterns to watch
DANGEROUS_PATTERNS = [
    ".env*",
    "*.bak",
    "*secret*",
    "*credential*",
    "*token*",
    "firebase*.json",
    "*adminsdk*",
    "*.pem",
    "*.p12",
    "*.key",
    "*password*",
    "*.pfx",
    "*.cert",
]

LEAKFIX_HOME = Path.home() / ".leakfix"
GUARD_PID_FILE = LEAKFIX_HOME / "guard.pid"
GUARD_LOG_FILE = LEAKFIX_HOME / "guard.log"


class Watcher:
    """Watch repository for dangerous file creation/modification."""

    def __init__(self, source: Path | str | None = None):
        self.source = Path(source or ".").resolve()
        self.repo_root = get_repo_root(self.source) or self.source
        self._observer = None
        self._handler = None

    def start(self, daemon: bool = False) -> None:
        """Start watching the repository."""
        if not is_git_repo(self.source):
            raise ValueError("Not a git repository")

        try:
            from watchdog.events import FileSystemEventHandler

            # On macOS, prefer FSEventsObserver for reliable file system events
            if platform.system() == "Darwin":
                try:
                    from watchdog.observers.fsevents import FSEventsObserver

                    self._observer = FSEventsObserver()
                except ImportError:
                    from watchdog.observers import Observer

                    self._observer = Observer()
            else:
                from watchdog.observers import Observer

                self._observer = Observer()
        except ImportError:
            raise ImportError("watchdog is required. pip install watchdog")

        class LeakfixHandler(FileSystemEventHandler):
            def __init__(self, watcher: Watcher):
                self.watcher = watcher

            def on_created(self, event):
                if event.is_directory:
                    return
                self.watcher._on_file_created(event)

            def on_modified(self, event):
                if event.is_directory:
                    return
                self.watcher._on_file_modified(event)

        self._handler = LeakfixHandler(self)
        watch_path = str(Path(self.repo_root).resolve())
        self._observer.schedule(
            self._handler,
            watch_path,
            recursive=True,
        )

        # Log which directory is being watched (both daemon and interactive write to guard.log)
        self._log_warning(f"Guard watching directory: {watch_path}")

        if daemon:
            self._daemon_start()
        else:
            self._observer.start()
            try:
                self._observer.join()
            except KeyboardInterrupt:
                self._observer.stop()
                self._observer.join()

    def _daemon_start(self) -> None:
        """Run as background daemon."""
        LEAKFIX_HOME.mkdir(parents=True, exist_ok=True)
        pid = os.fork()
        if pid > 0:
            # Parent: write PID and exit
            GUARD_PID_FILE.write_text(str(pid))
            self._log_warning(f"Guard started in daemon mode (PID {pid})")
            return
        # Child: detach and run observer
        os.setsid()
        os.chdir("/")
        sys.stdin.close()
        sys.stdout.close()
        sys.stderr.close()
        self._observer.start()
        while True:
            try:
                import time
                time.sleep(60)
            except Exception:
                pass

    def stop(self) -> bool:
        """Stop the daemon. Returns True if stopped successfully."""
        if not GUARD_PID_FILE.exists():
            return False
        try:
            pid = int(GUARD_PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            GUARD_PID_FILE.unlink(missing_ok=True)
            self._log_warning(f"Guard stopped (was PID {pid})")
            return True
        except (ProcessLookupError, ValueError, OSError):
            GUARD_PID_FILE.unlink(missing_ok=True)
            return False

    def status(self) -> dict:
        """Check if guard is running. Returns dict with 'running' and optional 'pid'."""
        if not GUARD_PID_FILE.exists():
            return {"running": False}
        try:
            pid = int(GUARD_PID_FILE.read_text().strip())
            os.kill(pid, 0)  # Check if process exists
            return {"running": True, "pid": pid}
        except (ProcessLookupError, ValueError, OSError):
            GUARD_PID_FILE.unlink(missing_ok=True)
            return {"running": False}

    def _on_file_created(self, event) -> None:
        """Handle file creation."""
        path = getattr(event, "src_path", str(event))
        filename = Path(path).name
        if self._is_dangerous_file(filename) or self._is_dangerous_file(path):
            if not self._check_gitignore(path):
                self._warn_user(f"Dangerous file created (not in .gitignore): {path}")
                self._log_warning(f"Dangerous file created: {path}")

    def _on_file_modified(self, event) -> None:
        """Handle file modification."""
        path = getattr(event, "src_path", str(event))
        filename = Path(path).name
        if self._is_dangerous_file(filename) or self._is_dangerous_file(path):
            if not self._check_gitignore(path):
                self._warn_user(f"Dangerous file modified (not in .gitignore): {path}")
                self._log_warning(f"Dangerous file modified: {path}")

    def _is_dangerous_file(self, filename: str) -> bool:
        """Check if filename matches dangerous patterns."""
        name = Path(filename).name
        name_lower = name.lower()
        path_lower = str(filename).lower()
        for pattern in DANGEROUS_PATTERNS:
            if fnmatch.fnmatch(name_lower, pattern.lower()):
                return True
            if fnmatch.fnmatch(path_lower, pattern.lower()):
                return True
            if fnmatch.fnmatch(path_lower, f"**/{pattern.lower()}"):
                return True
            pat_clean = pattern.replace("*", "").lower()
            if pat_clean and pat_clean in name_lower:
                return True
        return False

    def _check_gitignore(self, filename: str) -> bool:
        """Check if file would be ignored by .gitignore (simplified check)."""
        gitignore_path = self.repo_root / ".gitignore"
        if not gitignore_path.exists():
            return False
        try:
            rel = Path(filename).relative_to(self.repo_root)
        except ValueError:
            return False
        rel_str = str(rel).replace("\\", "/")
        name = rel.name
        content = gitignore_path.read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pat = line.rstrip("/")
            if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_str, pat):
                return True
            if fnmatch.fnmatch(rel_str, f"**/{pat}"):
                return True
        return False

    def _warn_user(self, message: str) -> None:
        """Show warning to user (stdout when not daemon)."""
        # When daemon, stdout is closed; log only
        try:
            print(f"\n⚠️  leakfix guard: {message}", flush=True)
        except OSError:
            pass

    def _log_warning(self, message: str) -> None:
        """Log to ~/.leakfix/guard.log."""
        LEAKFIX_HOME.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with GUARD_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
