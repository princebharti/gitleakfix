"""
Textual-based wizard app for leakfix setup.

Apple Intelligence themed UI with animated shimmer header.
This file is completely self-contained — no imports from setup_wizard.py.
"""
from __future__ import annotations

import re
import subprocess
import threading
from textual.app import App, ComposeResult
from textual.widgets import Static, Button, Input, Label
from textual.containers import VerticalScroll, Horizontal, Vertical
from textual.reactive import reactive
from textual.timer import Timer

from rich.text import Text
from rich.align import Align
from rich.console import RenderableType

# ═══════════════════════════════════════════════════════════════════════════════
# APPLE INTELLIGENCE COLOR PALETTE
# ═══════════════════════════════════════════════════════════════════════════════

APPLE_PURPLE = "#BC82F3"
APPLE_BLUE_PURPLE = "#8D9FFF"
APPLE_PINK = "#F5B9EA"
APPLE_VIOLET = "#AA6EEE"
APPLE_BRIGHT_PURPLE = "#C686FF"
APPLE_DIM = "#6E6E73"
APPLE_DARK_BG = "#1C1C1E"
APPLE_CARD_BG = "#2C2C2E"
APPLE_CARD_BORDER = "#3A3A3C"
APPLE_WHITE = "#F5F5F7"
APPLE_ERROR = "#FF6778"
APPLE_SUCCESS = "#30D158"
APPLE_WARNING = "#FFBA71"

# Gradient stops for animations
SHIMMER_WAVE = [APPLE_PURPLE, APPLE_VIOLET, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_PURPLE]
BORDER_CYCLE = [APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET]


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_id(name: str) -> str:
    """
    Sanitize a string to be a valid Textual widget ID.
    Replaces colons, dots, spaces, and other invalid characters with hyphens.
    """
    return re.sub(r'[^a-zA-Z0-9_-]', '-', name)


def _validate_model_name(name: str) -> str | None:
    """
    Validate an Ollama model name format.
    Returns error message or None if valid format.
    """
    if not name.strip():
        return "Model name cannot be empty"
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*(:[\w.-]+)?$', name.strip()):
        return "Invalid format. Use: modelname or modelname:tag (e.g. qwen3:0.6b)"
    return None


def _is_model_installed_locally(model: str) -> bool:
    """Check if model is already installed locally via `ollama list`."""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return False
        # Parse output - model names are in first column
        for line in result.stdout.strip().split('\n')[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if parts and parts[0].lower() == model.lower():
                    return True
                # Also check without tag (e.g. "qwen3" matches "qwen3:0.6b")
                if parts and ':' in parts[0]:
                    base_name = parts[0].split(':')[0]
                    if base_name.lower() == model.lower():
                        return True
        return False
    except Exception:
        return False


def _verify_model_exists_in_registry(model: str) -> bool:
    """Check if model exists in ollama library by attempting manifest pull."""
    try:
        # Ensure ollama serve is running before checking
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        import time; time.sleep(1)
        result = subprocess.run(
            ["ollama", "show", model],
            capture_output=True,
            text=True,
            timeout=15
        )
        return result.returncode == 0
    except Exception:
        return False


def _strip_ansi(text: str) -> str:
    """Strip all ANSI escape sequences and non-printable characters."""
    # Strip DEC private mode sequences like ?2026h ?25l
    text = re.sub(r'\x1b\[\?[0-9;]*[a-zA-Z]', '', text)
    # Strip standard ANSI escape sequences
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    text = re.sub(r'\x1b[PX^_].*?\x1b\\', '', text)
    text = re.sub(r'\x1b.', '', text)
    # Strip carriage returns
    text = re.sub(r'\r', '', text)
    text = re.sub(r'\x0f|\x0e', '', text)
    # Strip non-printable characters except newline and tab
    text = re.sub(r'[^\x09\x0a\x20-\x7e]', '', text)
    text = re.sub(r' {2,}', ' ', text)
    return text.strip()


def _interpolate_hex(c1: str, c2: str, t: float) -> str:
    """Interpolate between two hex colors."""
    r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
    r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    return f"#{int(r1 + (r2 - r1) * t):02X}{int(g1 + (g2 - g1) * t):02X}{int(b1 + (b2 - b1) * t):02X}"


def _make_shimmer_title(text: str, frame: int) -> Text:
    """
    Returns Rich Text with per-character colors.
    Wave sweeps left→right: position = (char_index/total + frame*0.02) % 1.0
    """
    n = len(text)
    result = Text(justify="left")
    
    for i, ch in enumerate(text):
        position = ((i / max(n - 1, 1)) + frame * 0.02) % 1.0
        ts = position * (len(SHIMMER_WAVE) - 1)
        seg = min(int(ts), len(SHIMMER_WAVE) - 2)
        local_t = ts - seg
        color = _interpolate_hex(SHIMMER_WAVE[seg], SHIMMER_WAVE[seg + 1], local_t)
        result.append(ch, style=f"bold {color}")
    
    return result


def _border_color(frame: int) -> str:
    """
    Cycles through Apple palette, full cycle = 60 frames (3 seconds at 20fps).
    """
    cycle_length = 60
    t = (frame % cycle_length) / cycle_length
    idx_f = t * len(BORDER_CYCLE)
    seg = int(idx_f) % len(BORDER_CYCLE)
    nxt = (seg + 1) % len(BORDER_CYCLE)
    local_t = idx_f - int(idx_f)
    return _interpolate_hex(BORDER_CYCLE[seg], BORDER_CYCLE[nxt], local_t)


def _make_gradient_separator(width: int = 30) -> Text:
    """Create a gradient separator line."""
    result = Text()
    for i in range(width):
        t = i / max(width - 1, 1)
        color = _interpolate_hex(APPLE_PURPLE, APPLE_CARD_BORDER, t)
        result.append("─", style=color)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# NON-FOCUSABLE WIDGETS (prevent Tab distortion)
# ═══════════════════════════════════════════════════════════════════════════════

class NFStatic(Static):
    """Non-focusable Static widget - Tab key skips this."""
    can_focus = False


class NFLabel(Label):
    """Non-focusable Label widget - Tab key skips this."""
    can_focus = False


# ═══════════════════════════════════════════════════════════════════════════════
# NON-FOCUSABLE SCROLL CONTAINER
# ═══════════════════════════════════════════════════════════════════════════════

class NFVerticalScroll(VerticalScroll):
    """Non-focusable VerticalScroll — Tab skips container but reaches children."""
    can_focus = False


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM OPTION LIST (replaces RadioSet - no circles, pure Apple style)
# ═══════════════════════════════════════════════════════════════════════════════

from textual.widget import Widget
from textual.message import Message

class OptionList(Widget):
    """Custom arrow-key selectable list with no radio circles."""
    
    DEFAULT_CSS = """
    OptionList {
        height: auto;
        width: 1fr;
        background: transparent;
    }
    OptionList > .option-item {
        height: 1;
        padding: 0 1;
        color: #F5F5F7;
        background: transparent;
    }
    OptionList > .option-item.selected {
        background: #2C1F45;
        color: #F5B9EA;
    }
    OptionList:focus > .option-item.selected {
        background: #2C1F45;
        color: #F5B9EA;
    }
    """
    
    class Changed(Message):
        """Posted when selection changes."""
        def __init__(self, option_list: "OptionList", index: int) -> None:
            super().__init__()
            self.option_list = option_list
            self.index = index
    
    selected_index: reactive[int] = reactive(0)
    
    def __init__(self, *options: str, id: str | None = None, **kwargs):
        super().__init__(id=id, **kwargs)
        self._options = list(options)
        self.can_focus = True
    
    def compose(self) -> ComposeResult:
        for i, option in enumerate(self._options):
            classes = "option-item selected" if i == 0 else "option-item"
            yield NFStatic(f"  {option}", classes=classes, id=f"opt-{i}")
    
    def watch_selected_index(self, old_index: int, new_index: int) -> None:
        """Update visual selection when index changes."""
        try:
            old_widget = self.query_one(f"#opt-{old_index}")
            old_widget.remove_class("selected")
            # Re-render without selection indicator
            old_text = self._options[old_index]
            old_widget.update(f"  {old_text}")
        except Exception:
            pass
        try:
            new_widget = self.query_one(f"#opt-{new_index}")
            new_widget.add_class("selected")
            # Re-render with selection indicator
            new_text = self._options[new_index]
            new_widget.update(f"❯ {new_text}")
        except Exception:
            pass
        self.post_message(self.Changed(self, new_index))
    
    def on_mount(self) -> None:
        """Set initial selection indicator."""
        try:
            widget = self.query_one(f"#opt-{self.selected_index}")
            widget.add_class("selected")
            text = self._options[self.selected_index]
            widget.update(f"❯ {text}")
        except Exception:
            pass
    
    def on_key(self, event) -> None:
        """Handle arrow key navigation and Enter to proceed."""
        if event.key == "up":
            if self.selected_index > 0:
                self.selected_index -= 1
            event.stop()
        elif event.key == "down":
            if self.selected_index < len(self._options) - 1:
                self.selected_index += 1
            event.stop()
        elif event.key == "enter":
            self.post_message(self.Changed(self, self.selected_index))
            self.app._handle_continue()
            event.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# SHIMMER HEADER WIDGET
# ═══════════════════════════════════════════════════════════════════════════════

class ShimmerHeader(Static):
    """Animated Apple Intelligence header — Claude Code terminal style, left-aligned."""
    can_focus = False
    frame: reactive[int] = reactive(0)

    def __init__(
        self,
        title: str = "Setup",
        subtitle: str = "AI-powered secret detection & remediation",
        **kwargs
    ):
        super().__init__(**kwargs)
        self._title = title
        self._subtitle = subtitle

    def on_mount(self) -> None:
        self.set_interval(1 / 20, self._tick)

    def _tick(self) -> None:
        self.frame += 1
        self.refresh(layout=False)

    def render(self) -> RenderableType:
        frame = self.frame  # MUST be first line for reactive tracking

        # Animate bottom border color
        self.styles.border_bottom = ("heavy", _border_color(frame))

        # Left-aligned shimmer title (leading spaces via the string itself)
        shimmer = _make_shimmer_title(f"  ◆  leakfix  ◆  {self._title}", frame)
        shimmer.justify = "left"

        # Subtitle line
        sub = Text(f"  {self._subtitle}", style=APPLE_DIM, justify="left")

        from rich.console import Group
        return Group(shimmer, sub)


# ═══════════════════════════════════════════════════════════════════════════════
# LLM MODEL OPTIONS
# ═══════════════════════════════════════════════════════════════════════════════

LLM_MODELS = [
    ("qwen3:0.6b", "fastest, 2GB RAM", True),
    ("llama3.2:3b", "balanced, 4GB RAM", False),
    ("phi4", "best quality, 10GB RAM", False),
]


# ═══════════════════════════════════════════════════════════════════════════════
# LEAKFIX WIZARD APP
# ═══════════════════════════════════════════════════════════════════════════════

class LeakfixWizardApp(App[dict | None]):
    """Textual wizard app for leakfix LLM setup."""
    
    # For tracking installed models (used by button handler to skip download)
    _installed_models: list[str]
    _models_list: list[str]
    
    CSS = """
$primary: #BC82F3;
$accent: #BC82F3;
$accent-lighten-1: #C686FF;
$accent-lighten-2: #D4A8FF;
$accent-darken-1: #AA6EEE;
$background: #1C1C1E;
$surface: #2C2C2E;
$panel: #2C2C2E;
$foreground: #F5F5F7;
$error: #FF6778;
$success: #30D158;
$warning: #FFBA71;

Screen {
    background: #1C1C1E;
    layout: vertical;
}

VerticalScroll {
    scrollbar-size: 0 0;
}

ShimmerHeader {
    width: 100%;
    height: 5;
    background: #1C1C1E;
    border-bottom: heavy #BC82F3;
    padding: 1 2;
    margin: 0;
    text-align: left;
    content-align: left middle;
    dock: top;
}

#content-panel {
    background: #1C1C1E;
    padding: 0 2;
    height: 1fr;
    overflow-y: auto;
    overflow-x: hidden;
    align: left top;
    &:focus { background: #1C1C1E; }
}

.section-label {
    color: #8D9FFF;
    text-style: bold;
    padding: 1 0 0 0;
}

.separator {
    color: #3A3A3C;
    padding: 0 0 1 0;
}

.question-text {
    color: #F5F5F7;
    text-style: bold;
    padding: 1 0;
}

.hint-text {
    color: #6E6E73;
    padding: 0 0 1 0;
}

.error-text {
    color: #FF6778;
    padding: 0 0 1 0;
}

OptionList {
    height: auto;
    width: 1fr;
    background: transparent;
    border: none;
    padding: 0;
}

OptionList:focus {
    background: transparent;
}

OptionList > .option-item {
    height: 1;
    padding: 0 1;
    color: #F5F5F7;
    background: transparent;
    width: auto;
}

OptionList > .option-item.selected {
    background: #2C1F45;
    color: #F5B9EA;
    width: auto;
}

.button-row {
    layout: horizontal;
    height: auto;
    margin: 1 0 1 0;
    padding: 0;
    background: transparent;
}

#cancel-download {
    margin: 0 0 0 0;
}

.bottom-spacer {
    height: 3;
}

Button {
    background: #BC82F3;
    color: #1C1C1E;
    border: heavy #BC82F3;
    min-width: 18;
    max-width: 24;
    width: auto;
    height: 3;
    margin: 1 1 0 0;
    text-style: bold;
}

Button:hover {
    background: #C686FF;
}

Button:focus {
    background: #C686FF;
    border: heavy #F5B9EA;
    width: auto;
    height: 3;
}

Button.-active {
    background: #C686FF;
    border: none;
}

Button.secondary {
    background: transparent;
    color: #6E6E73;
    border: heavy transparent;
    text-style: none;
    width: auto;
    min-width: 10;
    height: 3;
}

Button.secondary:focus {
    color: #F5F5F7;
    border: heavy #3A3A3C;
    background: transparent;
    width: auto;
    height: 3;
}

Button.secondary:hover {
    background: transparent;
    color: #F5F5F7;
    border: none;
}

Button.secondary.-active {
    background: transparent;
    border: none;
}

Button.cancel-btn {
    color: #FF6778;
    border: heavy transparent;
}

Button.cancel-btn:focus {
    color: #FF6778;
    border: heavy #FF6778;
}

Button.cancel-btn:hover {
    color: #FF6778;
    background: transparent;
}

Input {
    background: #2C2C2E;
    border: heavy #3A3A3C;
    color: #F5F5F7;
    padding: 0 2;
    height: 3;
    width: 25%;
    margin: 0 0 1 2;
}

Input:focus {
    border: heavy #BC82F3;
}

Input.-invalid {
    border: heavy #FF6778;
}

Label {
    color: #F5F5F7;
    text-style: bold;
    padding: 1 0 1 0;
}

#progress-bar {
    padding: 2 0 1 0;
    height: auto;
}

#progress-status {
    padding: 0 0 1 0;
    color: #8D9FFF;
}

#progress-detail {
    color: #6E6E73;
    padding: 0 0;
}

#progress-hint {
    color: #6E6E73;
    padding: 0 0 0 0;
    margin: 0;
}
"""
    
    def __init__(
        self,
        reset: bool = False,
        llm_only: bool = False,
        check_only: bool = False,
        current_config: dict | None = None
    ):
        super().__init__()
        self.reset = reset
        self.llm_only = llm_only
        self.check_only = check_only
        self.config = current_config or {}
        self._selected_provider: str | None = None
        self._selected_model: str | None = None
        self._validation_error_widget: Static | None = None
        self._current_screen: str = ""  # Track current screen for RadioSet handling
        self._screen_count: int = 0  # Counter for unique widget IDs
        # Progress tracking for model download
        self._pull_complete: bool = False
        self._pull_success: bool = False
        self._pull_error: str = ""
        self._progress_frame: int = 0
        self._progress_timer: Timer | None = None
        self._pull_process = None
        # Track installed models and model list for button handler
        self._installed_models: list[str] = []
        self._models_list: list[str] = []
    
    def on_exception(self, error: Exception) -> None:
        import traceback, sys
        with open("/tmp/wizard_crash.log", "a") as f:
            traceback.print_exc(file=f)
        self.exit()

    def compose(self) -> ComposeResult:
        yield ShimmerHeader()
        scroll = NFVerticalScroll(id="content-panel")
        yield scroll
    
    def on_mount(self) -> None:
        if self.llm_only:
            self._show_provider_choice()
        else:
            self._show_enable_llm()
    
    def _clear_content(self) -> None:
        """Clear the content panel and stop any running timers."""
        # Stop any running progress timer before wiping the DOM
        if self._progress_timer is not None:
            try:
                self._progress_timer.stop()
            except Exception:
                pass
            self._progress_timer = None
        
        # Mark pull as complete to prevent timer callbacks from running
        self._pull_complete = True
        
        self._screen_count += 1
        try:
            panel = self.query_one("#content-panel")
            for child in list(panel.children):
                try:
                    child.remove()
                except Exception:
                    pass
        except Exception:
            pass
        self._validation_error_widget = None
    
    def _option_id(self) -> str:
        """Generate unique option list ID for this screen."""
        return f"wizard-options-{self._screen_count}"
    
    def _mount_section_header(self, panel, title: str) -> None:
        """Mount a section header with gradient separator."""
        panel.mount(NFStatic(f"[bold #8D9FFF]  {title}[/bold #8D9FFF]", classes="section-label", markup=True))
        panel.mount(NFStatic(_make_gradient_separator(30), classes="separator"))
    
    def _show_enable_llm(self) -> None:
        """Ask if user wants to enable LLM enhancement."""
        self._clear_content()
        self._current_screen = "enable"
        self._selected_provider = 0  # Default selection index
        panel = self.query_one("#content-panel")
        
        self._mount_section_header(panel, "LLM Enhancement")
        
        panel.mount(NFStatic("  How would you like to configure LLM enhancement?", classes="question-text"))
        panel.mount(NFStatic("  Runs 100% on your machine — no data leaves your device.", classes="hint-text"))
        
        panel.mount(OptionList(
            "◆  Use a model from my local ollama",
            "◆  Enter a custom ollama model name",
            "◆  Use a custom OpenAI-compatible server",
            "◆  Skip LLM — use heuristics only",
            id=self._option_id()
        ))
        
        panel.mount(Horizontal(
            Button("Continue →", id="enable-continue"),
            Button("Cancel", id="cancel", classes="secondary"),
            classes="button-row"
        ))
        
        self.set_timer(0.1, self._focus_options)
    
    def _show_provider_choice(self) -> None:
        """Show LLM provider selection."""
        self._clear_content()
        self._current_screen = "provider"
        self._selected_provider = 0  # Default selection index
        panel = self.query_one("#content-panel")
        
        self._mount_section_header(panel, "LLM Enhancement")
        
        panel.mount(NFStatic("  How would you like to configure LLM enhancement?", classes="question-text"))
        panel.mount(NFStatic("  Runs 100% on your machine — no data leaves your device.", classes="hint-text"))
        
        panel.mount(OptionList(
            "◆  Use a model from my local ollama",
            "◆  Enter a custom ollama model name",
            "◆  Use a custom OpenAI-compatible server",
            "◆  Skip LLM — use heuristics only",
            id=self._option_id()
        ))
        
        panel.mount(Horizontal(
            Button("Continue →", id="provider-continue"),
            Button("Cancel", id="cancel", classes="secondary"),
            classes="button-row"
        ))
        
        self.set_timer(0.1, self._focus_options)
    
    def _show_local_ollama_models(self) -> None:
        """Show Ollama model selection with async loading."""
        self._clear_content()
        self._current_screen = "model"
        self._selected_model = 0  # Default to first model index
        panel = self.query_one("#content-panel")
        
        self._mount_section_header(panel, "Local Ollama Models")
        panel.mount(NFStatic("  Select a model:", classes="question-text"))
        
        # Step 1: Show loading state immediately (on main thread)
        panel.mount(NFStatic("  [◆] Loading models...", id="models-loading"))
        
        # Step 2: Fetch data off the main thread
        def _fetch_models():
            installed_models: list[str] = []
            fetched_models: list[tuple[str, str]] = []  # (name, description)
            
            # Try to get locally installed models via `ollama list`
            try:
                result = subprocess.run(
                    ["ollama", "list"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:  # Skip header line
                        if line.strip():
                            parts = line.split()
                            if parts:
                                installed_models.append(parts[0])
            except Exception:
                pass
            
            # If installed models exist, use that list
            if installed_models:
                for model in installed_models:
                    fetched_models.append((model, ""))
            else:
                # No installed models - try to fetch from ollama.com/library
                try:
                    import urllib.request
                    import json
                    
                    req = urllib.request.Request(
                        "https://ollama.com/library",
                        headers={"User-Agent": "Mozilla/5.0"}
                    )
                    with urllib.request.urlopen(req, timeout=10) as response:
                        html = response.read().decode('utf-8')
                        # Parse model names from the HTML
                        # Look for patterns like href="/library/modelname"
                        import re
                        model_pattern = re.compile(r'href="/library/([a-zA-Z0-9._-]+)"')
                        found_models = model_pattern.findall(html)
                        # Get unique models, preserve order
                        seen = set()
                        for m in found_models:
                            if m not in seen and m not in ('', 'search'):
                                seen.add(m)
                                fetched_models.append((m, ""))
                                if len(fetched_models) >= 10:  # Limit to top 10
                                    break
                except Exception:
                    pass
                
                # If HTTP fetch also failed, fall back to hardcoded LLM_MODELS
                if not fetched_models:
                    for model, desc, _ in LLM_MODELS:
                        fetched_models.append((model, desc))
            
            # Step 3: Back on main thread, build and mount the OptionList
            self.call_from_thread(
                self._mount_model_options,
                installed_models,
                fetched_models
            )
        
        threading.Thread(target=_fetch_models, daemon=True).start()
    
    def _mount_model_options(
        self,
        installed_models: list[str],
        fetched_models: list[tuple[str, str]]
    ) -> None:
        """Mount the model OptionList after fetching (called from main thread)."""
        # Store installed models for button handler
        self._installed_models = installed_models
        
        # Remove the loading widget
        try:
            loading_widget = self.query_one("#models-loading")
            loading_widget.remove()
        except Exception:
            pass
        
        panel = self.query_one("#content-panel")
        current_model = self.config.get("llm_model", "")
        
        # Build option labels and model list
        options: list[str] = []
        self._models_list = []
        
        for model_name, description in fetched_models:
            self._models_list.append(model_name)
            
            # Check if this is an installed model or fetched/fallback
            if model_name in installed_models:
                label = f"◆  {model_name}"
                if model_name.lower() == current_model.lower():
                    label += "   ← current"
            else:
                label = f"◆  {model_name}"
                if description:
                    label += f"   {description}"
            
            options.append(label)
        
        # Always append the "Enter a different model name..." option
        options.append("◆  Enter a different model name...")
        self._models_list.append("")  # Empty string for custom option
        
        # Mount OptionList and buttons
        panel.mount(OptionList(*options, id=self._option_id()))
        panel.mount(Horizontal(
            Button("Back", id="back-to-provider", classes="secondary"),
            Button("Select →", id="model-continue"),
            classes="button-row"
        ))
        
        self.set_timer(0.1, self._focus_options)
    
    def _show_custom_model_input(self, came_from: str = "provider") -> None:
        """Show custom model name input.
        
        Args:
            came_from: Where the user navigated from ("provider" or "model")
        """
        self._clear_content()
        self._current_screen = "custom-model"
        self._custom_model_came_from = came_from  # Store for back button
        panel = self.query_one("#content-panel")
        
        self._mount_section_header(panel, "Custom Ollama Model")
        
        panel.mount(NFStatic("  Enter the model name from https://ollama.com/library", classes="question-text"))
        panel.mount(NFStatic("  Format: modelname or modelname:tag", classes="hint-text"))
        
        panel.mount(NFLabel("  Model name:"))
        panel.mount(Input(placeholder="e.g. qwen3:0.6b", id="custom-model-input"))
        
        # Placeholder for validation error
        self._validation_error_widget = NFStatic("", classes="error-text", id="validation-error")
        panel.mount(self._validation_error_widget)
        
        # Back button goes to model list if came from there, otherwise provider
        back_id = "back-to-model" if came_from == "model" else "back-to-provider"
        panel.mount(Horizontal(
            Button("Back", id=back_id, classes="secondary"),
            Button("Pull & Configure →", id="custom-model-continue"),
            classes="button-row"
        ))
        self.set_timer(0.1, lambda: self.query_one("#custom-model-input", Input).focus())
    
    def _show_openai_config(self) -> None:
        """Show OpenAI-compatible API configuration."""
        self._clear_content()
        self._current_screen = "openai"
        panel = self.query_one("#content-panel")
        
        self._mount_section_header(panel, "OpenAI-Compatible API")
        
        panel.mount(NFStatic("  Configure your local AI server (LM Studio, Jan, LocalAI)", classes="question-text"))
        
        panel.mount(NFLabel("  Base URL:"))
        panel.mount(Input(
            placeholder="http://localhost:11434/v1",
            id="openai-url-input",
            value=self.config.get("openai_base_url", "http://localhost:11434/v1")
        ))
        
        panel.mount(NFLabel("  Model name:"))
        panel.mount(Input(
            placeholder="local-model",
            id="openai-model-input",
            value=self.config.get("openai_model", "")
        ))
        
        panel.mount(NFLabel("  API Key (optional):"))
        api_key_input = Input(
            placeholder="sk-...",
            id="openai-key-input",
            password=True,
            value=self.config.get("openai_api_key", "")
        )
        panel.mount(api_key_input)
        
        # Placeholder for validation error
        self._validation_error_widget = NFStatic("", classes="error-text", id="validation-error")
        panel.mount(self._validation_error_widget)
        
        panel.mount(Horizontal(
            Button("Configure →", id="openai-continue"),
            Button("Back", id="back-to-provider", classes="secondary"),
            classes="button-row"
        ))
        
        # Add spacer at bottom to ensure button is visible when scrolling
        panel.mount(NFStatic("", classes="bottom-spacer"))
        self.set_timer(0.1, lambda: self.query_one("#openai-url-input", Input).focus())
    
    def _focus_options(self) -> None:
        """Focus the wizard option list after mounting."""
        try:
            self.query_one(f"#{self._option_id()}").focus()
        except Exception:
            pass
    
    def _show_validation_error(self, message: str) -> None:
        """Display a validation error message."""
        if self._validation_error_widget:
            self._validation_error_widget.update(f"  {message}")
    
    def _clear_validation_error(self) -> None:
        """Clear the validation error message."""
        if self._validation_error_widget:
            self._validation_error_widget.update("")
    
    def _finish(self, config: dict) -> None:
        """Exit the wizard with the final configuration."""
        self.exit(result=config)
    
    def _finish_with_config(self, config: dict) -> None:
        """Save config and exit - used by download progress screen."""
        config["setup_complete"] = True
        self._finish(config)
    
    def _show_ollama_install_progress(self, model_name: str) -> None:
        """Show animated progress screen while installing ollama via brew."""
        self._clear_content()
        self._current_screen = "ollama-install"
        panel = self.query_one("#content-panel")

        panel.mount(NFStatic("[bold #8D9FFF]  Installing ollama[/bold #8D9FFF]", classes="section-label", markup=True))
        panel.mount(NFStatic(_make_gradient_separator(30), classes="separator"))
        panel.mount(NFStatic("  ollama not found — installing via Homebrew...", classes="question-text"))
        panel.mount(NFStatic("  Sit tight, this usually takes 30–60 seconds.", classes="hint-text"))
        panel.mount(NFStatic("", id="install-bar"))
        panel.mount(NFStatic("", id="install-status"))
        panel.mount(NFStatic("", id="install-detail"))

        self._progress_frame = 0
        self._pull_complete = False
        self._install_pct = 0
        self._install_step = "Step 1/3  Downloading ollama via Homebrew..."

        def _do_install():
            import subprocess as sp, time, shutil
            try:
                self._install_step = "Step 1/3  Downloading ollama via Homebrew..."
                self._install_pct = 5
                result = sp.run(["brew", "install", "ollama"], capture_output=True)
                if result.returncode != 0:
                    raise Exception("brew install failed")

                self._install_step = "Step 2/3  Starting ollama server..."
                self._install_pct = 75
                sp.Popen(["ollama", "serve"], stdout=sp.DEVNULL, stderr=sp.DEVNULL, start_new_session=True)
                time.sleep(2)

                self._install_step = "Step 3/3  Verifying installation..."
                self._install_pct = 90
                time.sleep(1)
                success = shutil.which("ollama") is not None
            except Exception:
                success = False
            self._pull_complete = True
            self._pull_success = success
            self.call_from_thread(self._on_ollama_install_complete, model_name, success)

        threading.Thread(target=_do_install, daemon=True).start()
        self._progress_timer = self.set_interval(1/10, self._tick_install_progress)

    def _tick_install_progress(self) -> None:
        """Animate progress bar during ollama install."""
        if self._pull_complete:
            if self._progress_timer:
                self._progress_timer.stop()
            return

        self._progress_frame += 1
        frame = self._progress_frame

        WAVE = ["#BC82F3", "#AA6EEE", "#8D9FFF", "#F5B9EA", "#BC82F3"]
        bar_width = 40
        pct = getattr(self, "_install_pct", 0)
        filled = int(bar_width * pct / 100)

        bar_text = Text()
        bar_text.append("  ")
        for i in range(filled):
            t = (i / max(bar_width - 1, 1) + frame * 0.03) % 1.0
            ts = t * (len(WAVE) - 1)
            seg = min(int(ts), len(WAVE) - 2)
            color = _interpolate_hex(WAVE[seg], WAVE[seg + 1], ts - seg)
            bar_text.append("━", style=color)
        bar_text.append("░" * (bar_width - filled), style="#3A3A3C")
        bar_text.append(f"  {pct}%", style="bold #BC82F3")

        spinners = ["◆", "◈", "◇", "◈"]
        spinner = spinners[frame % len(spinners)]
        step = getattr(self, "_install_step", "Preparing...")

        try:
            self.query_one("#install-bar").update(bar_text)
            self.query_one("#install-status").update(f"  [{spinner}] {step}")
        except Exception:
            pass

    def _on_ollama_install_complete(self, model_name: str, success: bool) -> None:
        """Called when ollama install finishes."""
        if success:
            try:
                self.query_one("#install-bar").update(
                    Text("  " + "━" * 40 + "  100%", style="bold #30D158")
                )
                self.query_one("#install-status").update(
                    Text("  ✓ ollama installed! Starting model download...", style="bold #30D158")
                )
            except Exception:
                pass
            self.set_timer(1.5, lambda: self._show_download_progress(model_name))
        else:
            try:
                self.query_one("#install-bar").update(
                    Text("  ✗ Installation failed", style="bold #FF6778")
                )
                self.query_one("#install-status").update(
                    Text("  Try manually: brew install ollama", style="#FF6778")
                )
            except Exception:
                pass

    def _show_already_installed(self, model: str) -> None:
        """Show message that model is already installed and save config."""
        self._clear_content()
        self._current_screen = "already-installed"
        panel = self.query_one("#content-panel")

        panel.mount(NFStatic("[bold #8D9FFF]  Model Ready[/bold #8D9FFF]", classes="section-label", markup=True))
        panel.mount(NFStatic(_make_gradient_separator(), classes="separator"))
        panel.mount(NFStatic(f"  [bold #30D158]✓ Model already installed — no download needed[/bold #30D158]", classes="question-text", markup=True))
        panel.mount(NFStatic(f"  {model} is ready to use.", classes="hint-text"))
        panel.mount(NFStatic("", classes="hint-text"))
        panel.mount(NFStatic("  Saving configuration...", classes="hint-text", id="saving-status"))

        # Save config and exit after brief pause
        self.set_timer(1.5, lambda: self._finish_with_config({
            **self.config,
            "llm_enabled": True,
            "llm_provider": "ollama",
            "llm_model": model,
            "llm_base_url": "http://localhost:11434",
            "llm_api_key": "",
        }))

    def _show_download_progress(self, model: str) -> None:
        """Show animated download progress screen."""
        # Store model for use in timer callback
        self._current_download_model = model
        
        self._clear_content()
        self._current_screen = "download"
        panel = self.query_one("#content-panel")

        panel.mount(NFStatic("[bold #8D9FFF]  Downloading Model[/bold #8D9FFF]", classes="section-label", markup=True))
        panel.mount(NFStatic(_make_gradient_separator(), classes="separator"))
        panel.mount(NFStatic(f"  Pulling {model} from ollama library...", classes="question-text"))
        panel.mount(NFStatic("  Runs 100% locally — no data leaves your device.", classes="hint-text"))
        panel.mount(NFStatic("", id="progress-bar"))
        panel.mount(NFStatic("", id="progress-status"))
        panel.mount(NFStatic("", id="progress-detail"))
        panel.mount(NFStatic("  (this may take a few minutes)", classes="hint-text", id="progress-hint"))
        panel.mount(Horizontal(
            Button("✕  Cancel", id="cancel-download", classes="secondary cancel-btn"),
            classes="button-row"
        ))

        # Reset progress state
        self._pull_complete = False
        self._pull_success = False
        self._pull_error = ""
        self._progress_frame = 0

        def _do_pull():
            try:
                result = subprocess.run(
                    ["ollama", "pull", model],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                self._pull_success = result.returncode == 0
                if not self._pull_success:
                    raw = result.stderr or result.stdout or "Unknown error"
                    cleaned = _strip_ansi(raw)
                    error_lines = [l.strip() for l in cleaned.split("\n") if l.strip()]
                    self._pull_error = error_lines[0] if error_lines else "Model not found or network error"
            except subprocess.TimeoutExpired:
                self._pull_success = False
                self._pull_error = "Download timed out after 10 minutes"
            except FileNotFoundError:
                self._pull_success = False
                self._pull_error = "ollama not found. Please install ollama first."
            except Exception as e:
                self._pull_success = False
                self._pull_error = _strip_ansi(str(e))
            finally:
                self._pull_complete = True
                self.call_from_thread(self._on_pull_complete, model)

        threading.Thread(target=_do_pull, daemon=True).start()

        # Start progress animation timer (10fps) - use method reference instead of lambda
        self._progress_timer = self.set_interval(1/10, self._tick_progress_safe)


    def _tick_progress_safe(self) -> None:
        """Safe wrapper for progress tick that handles exceptions."""
        try:
            # Check if we're still on the download screen
            if self._current_screen != "download":
                if self._progress_timer:
                    self._progress_timer.stop()
                    self._progress_timer = None
                return
            
            model = getattr(self, '_current_download_model', 'model')
            self._tick_progress(model)
        except Exception as e:
            # Log error but don't crash
            import traceback
            with open("/tmp/wizard_crash.log", "a") as f:
                f.write(f"_tick_progress_safe error: {e}\n")
                traceback.print_exc(file=f)
            # Stop the timer on error
            if self._progress_timer:
                try:
                    self._progress_timer.stop()
                except Exception:
                    pass
                self._progress_timer = None

    def _tick_progress(self, model: str) -> None:
        """Animate the progress bar while download is running."""
        if self._pull_complete:
            if self._progress_timer:
                try:
                    self._progress_timer.stop()
                except Exception:
                    pass
                self._progress_timer = None
            return
        
        self._progress_frame += 1
        frame = self._progress_frame
        
        # Animated progress bar — simulates progress
        # Fast to 30% in first 10s, slow crawl to 92%, jumps to 100% when done
        elapsed = frame / 10  # seconds (10fps)
        if elapsed < 10:
            pct = min(30, int(elapsed * 3))
        elif elapsed < 60:
            pct = min(92, 30 + int((elapsed - 10) * 1.2))
        else:
            pct = 92
        
        # Build Apple-style progress bar using Unicode blocks
        WAVE = ["#BC82F3", "#AA6EEE", "#8D9FFF", "#F5B9EA", "#BC82F3"]
        bar_width = 40
        filled = int(bar_width * pct / 100)
        empty = bar_width - filled
        
        # Build gradient filled portion
        bar_text = Text()
        bar_text.append("  ")
        for i in range(filled):
            t = (i / max(bar_width - 1, 1) + frame * 0.03) % 1.0
            ts = t * (len(WAVE) - 1)
            seg = min(int(ts), len(WAVE) - 2)
            color = _interpolate_hex(WAVE[seg], WAVE[seg + 1], ts - seg)
            bar_text.append("━", style=color)
        bar_text.append("░" * empty, style="#3A3A3C")
        bar_text.append(f"  {pct}%", style="bold #BC82F3")
        
        # Spinning status indicator
        spinners = ["◆", "◈", "◇", "◈"]
        spinner = spinners[frame % len(spinners)]
        
        # Status messages cycle
        messages = [
            "Downloading layers...",
            "Verifying checksums...",
            "Extracting model...",
            "Downloading layers...",
        ]
        msg = messages[(frame // 15) % len(messages)]
        
        # Update UI - check widgets exist before updating
        try:
            progress_bar = self.query_one("#progress-bar", NFStatic)
            progress_status = self.query_one("#progress-status", NFStatic)
            progress_bar.update(bar_text)
            progress_status.update(f"  [{spinner}] {msg}")
        except Exception:
            # Widgets may have been removed - stop timer
            if self._progress_timer:
                try:
                    self._progress_timer.stop()
                except Exception:
                    pass
                self._progress_timer = None

    def _on_pull_complete(self, model: str) -> None:
        """Called when pull finishes — show success or error."""
        # Stop timer first
        if self._progress_timer:
            try:
                self._progress_timer.stop()
            except Exception:
                pass
            self._progress_timer = None
        
        # Verify we're still on the download screen
        if self._current_screen != "download":
            return
        
        if self._pull_success:
            # Show success briefly then finish
            try:
                progress_bar = self.query_one("#progress-bar", NFStatic)
                progress_status = self.query_one("#progress-status", NFStatic)
                progress_detail = self.query_one("#progress-detail", NFStatic)
                
                progress_bar.update(
                    Text("  " + "━" * 40 + "  100%", style="bold #30D158")
                )
                progress_status.update(
                    Text(f"  ✓ {model} ready", style="bold #30D158")
                )
                progress_detail.update("")
            except Exception as e:
                import traceback
                with open("/tmp/wizard_crash.log", "a") as f:
                    f.write(f"_on_pull_complete success UI error: {e}\n")
                    traceback.print_exc(file=f)
            
            # Save config and exit after brief pause
            config_to_save = {
                **self.config,
                "llm_enabled": True,
                "llm_provider": "ollama",
                "llm_model": model,
                "llm_base_url": "http://localhost:11434",
                "llm_api_key": "",
            }
            self.set_timer(1.5, lambda: self._finish_with_config(config_to_save))
        else:
            # Show error
            try:
                # Hide cancel button on failure
                try:
                    cancel_btn = self.query_one("#cancel-download", Button)
                    cancel_btn.display = False
                except Exception:
                    pass
                
                progress_bar = self.query_one("#progress-bar", NFStatic)
                progress_status = self.query_one("#progress-status", NFStatic)
                progress_detail = self.query_one("#progress-detail", NFStatic)
                
                progress_bar.update(
                    Text("  ✗ Download failed", style="bold #FF6778")
                )
                error_short = self._pull_error[:100] if self._pull_error else "Unknown error"
                progress_status.update(
                    Text(f"  {error_short}", style="#FF6778")
                )
                progress_detail.update(
                    Text("  Press Escape to go back", style="#6E6E73")
                )
                # Hide the "(this may take a few minutes)" hint on failure
                try:
                    hint = self.query_one("#progress-hint", NFStatic)
                    hint.display = False
                except Exception:
                    pass
            except Exception as e:
                import traceback
                with open("/tmp/wizard_crash.log", "a") as f:
                    f.write(f"_on_pull_complete error UI error: {e}\n")
                    traceback.print_exc(file=f)
    
    def _handle_continue(self) -> None:
        """Trigger the continue/select button for the current screen."""
        button_id_map = {
            "enable": "enable-continue",
            "provider": "provider-continue",
            "model": "model-continue",
        }
        target_id = button_id_map.get(self._current_screen)
        if target_id:
            try:
                btn = self.query_one(f"#{target_id}", Button)
                btn.press()
            except Exception:
                pass

    def on_input_changed(self, event: Input.Changed) -> None:
        """Clear validation error when user starts typing."""
        self._clear_validation_error()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle all button presses."""
        button_id = event.button.id
        
        # Enable LLM screen (initial screen when not llm_only)
        if button_id == "enable-continue":
            idx = self._selected_provider if isinstance(self._selected_provider, int) else 0
            if idx == 0:  # Use local ollama
                self._show_local_ollama_models()
            elif idx == 1:  # Custom model name
                self._show_custom_model_input()
            elif idx == 2:  # OpenAI-compatible
                self._show_openai_config()
            elif idx == 3:  # Skip LLM
                self.config["llm_enabled"] = False
                self.config["setup_complete"] = True
                self._finish(self.config)
            else:
                self._show_local_ollama_models()
        
        # Provider choice screen
        elif button_id == "provider-continue":
            idx = self._selected_provider if isinstance(self._selected_provider, int) else 0
            if idx == 0:  # Use local ollama
                self._show_local_ollama_models()
            elif idx == 1:  # Custom model name
                self._show_custom_model_input()
            elif idx == 2:  # OpenAI-compatible
                self._show_openai_config()
            elif idx == 3:  # Skip LLM
                self.config["llm_enabled"] = False
                self.config["setup_complete"] = True
                self._finish(self.config)
            else:
                self._show_local_ollama_models()
        
        elif button_id == "back-to-provider":
            if self.llm_only:
                self._show_provider_choice()
            else:
                self._show_enable_llm()
        
        elif button_id == "back-to-model":
            self._show_local_ollama_models()
        
        elif button_id == "model-continue":
            idx = self._selected_model if isinstance(self._selected_model, int) else 0
            
            # Check if it's the last option (Enter a different model name...)
            if idx >= len(self._models_list) - 1 or self._models_list[idx] == "":
                self._show_custom_model_input(came_from="model")
                return
            
            # Look up the selected model name from _models_list
            model = self._models_list[idx]
            
            # If model is in the locally installed list, skip download
            if model in self._installed_models:
                self._finish_with_config({
                    **self.config,
                    "llm_enabled": True,
                    "llm_provider": "ollama",
                    "llm_model": model,
                    "llm_base_url": "http://localhost:11434",
                    "llm_api_key": "",
                })
            else:
                # Model not installed, show download progress
                self._show_download_progress(model)
        
        elif button_id == "custom-model-continue":
            try:
                input_widget = self.query_one("#custom-model-input", Input)
                model_name = input_widget.value.strip()

                # Step 1: Validate format
                error = _validate_model_name(model_name)
                if error:
                    self._show_validation_error(error)
                    return

                # Step 2: Ensure ollama is installed before doing anything
                import shutil
                if not shutil.which("ollama"):
                    self._show_ollama_install_progress(model_name)
                    return

                # Step 3: Check locally + proceed — all off the main thread
                def _check_and_proceed():
                    try:
                        if _is_model_installed_locally(model_name):
                            # Model already installed - show success message and save config
                            self.call_from_thread(
                                self._show_already_installed,
                                model_name
                            )
                        else:
                            self.call_from_thread(self._show_download_progress, model_name)
                    except Exception as e:
                        import traceback
                        with open("/tmp/wizard_crash.log", "a") as f:
                            traceback.print_exc(file=f)
                        self.call_from_thread(
                            self._show_validation_error,
                            f"Error: {str(e)[:50]}"
                        )

                threading.Thread(target=_check_and_proceed, daemon=True).start()

            except Exception:
                self._show_validation_error("An error occurred. Please try again.")
        
        elif button_id == "openai-continue":
            try:
                url_input = self.query_one("#openai-url-input", Input)
                model_input = self.query_one("#openai-model-input", Input)
                key_input = self.query_one("#openai-key-input", Input)
                
                base_url = url_input.value.strip()
                model_name = model_input.value.strip()
                api_key = key_input.value.strip()
                
                # Validate inputs
                if not base_url:
                    self._show_validation_error("Base URL is required")
                    return
                if not model_name:
                    self._show_validation_error("Model name is required")
                    return
                
                self.config["llm_enabled"] = True
                self.config["llm_provider"] = "openai"
                self.config["openai_base_url"] = base_url
                self.config["openai_model"] = model_name
                if api_key:
                    self.config["openai_api_key"] = api_key
                self.config["setup_complete"] = True
                self._finish(self.config)
            except Exception:
                self._show_validation_error("An error occurred. Please try again.")
        
        elif button_id == "cancel-download":
            try:
                if getattr(self, "_pull_process", None):
                    self._pull_process.terminate()
                    self._pull_process = None
                if getattr(self, "_progress_timer", None):
                    self._progress_timer.stop()
                self._pull_complete = True
            except Exception:
                pass
            if self.llm_only:
                self._show_provider_choice()
            else:
                self._show_enable_llm()

        elif button_id == "cancel":
            self.exit(result=None)
    
    def on_option_list_changed(self, event: OptionList.Changed) -> None:
        """Handle option list selection changes."""
        if not event.option_list.id or not event.option_list.id.startswith("wizard-options"):
            return
        
        index = event.index
        
        if self._current_screen == "enable":
            self._selected_provider = index
        elif self._current_screen == "provider":
            self._selected_provider = index
        elif self._current_screen == "model":
            self._selected_model = index
    
    def on_key(self, event) -> None:
        """Handle key presses."""
        if event.key == "escape":
            if self._current_screen == "download" and self._pull_complete and not self._pull_success:
                # Go back to provider selection on download failure
                if self.llm_only:
                    self._show_provider_choice()
                else:
                    self._show_enable_llm()
