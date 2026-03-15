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
    # Strip all ANSI escape sequences
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    text = re.sub(r'\x1b[PX^_].*?\x1b\\', '', text)
    text = re.sub(r'\x1b.', '', text)  # catch any remaining ESC sequences
    # Strip non-printable characters except newline and tab
    text = re.sub(r'[^\x09\x0a\x20-\x7e]', '', text)
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
    """Animated Apple Intelligence header panel with left-aligned content."""
    
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
        
        # Update border color via styles
        self.styles.border = ("heavy", _border_color(frame))
        
        # Return just the text content - no Panel wrapper
        result = Text()
        result.append_text(_make_shimmer_title(f"◆  leakfix  ◆  {self._title}", frame))
        result.append("\n")
        result.append(self._subtitle, style=APPLE_DIM)
        
        return result


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

ShimmerHeader {
    width: 60%;
    content-align: center middle;
    height: 7;
    background: #2C2C2E;
    border: heavy #BC82F3;
    padding: 1 4;
    margin: 0 0 1 0;
    align: center middle;
    text-align: center;
    content-align: center middle;
    dock: top;
}

#content-panel {
    background: #1C1C1E;
    padding: 0 2;
    height: 1fr;
    overflow-y: auto;
    overflow-x: hidden;
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
    margin: 2 0 3 0;
    padding: 0;
    background: transparent;
}

.bottom-spacer {
    height: 3;
}

Button {
    background: #BC82F3;
    color: #1C1C1E;
    border: none;
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
    border: tall #F5B9EA;
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
    border: none;
    text-style: none;
    width: auto;
    min-width: 10;
    height: 3;
}

Button.secondary:focus {
    color: #F5F5F7;
    border: tall #3A3A3C;
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

Input {
    background: #2C2C2E;
    border: tall #3A3A3C;
    color: #F5F5F7;
    padding: 0 2;
    height: 3;
    width: 1fr;
    margin: 0 0 1 0;
}

Input:focus {
    border: heavy #BC82F3;
}

Input.-invalid {
    border: tall #FF6778;
}

Label {
    color: #F5F5F7;
    text-style: bold;
    padding: 1 0 0 0;
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
    padding: 1 0;
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
    
    def compose(self) -> ComposeResult:
        yield ShimmerHeader()
        yield VerticalScroll(id="content-panel")
    
    def on_mount(self) -> None:
        if self.llm_only:
            self._show_provider_choice()
        else:
            self._show_enable_llm()
    
    def _clear_content(self) -> None:
        self._screen_count += 1
        panel = self.query_one("#content-panel")
        for child in list(panel.children):
            child.remove()
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
        """Show Ollama model selection."""
        self._clear_content()
        self._current_screen = "model"
        self._selected_model = 0  # Default to first model index
        panel = self.query_one("#content-panel")
        
        self._mount_section_header(panel, "Local Ollama Models")
        
        panel.mount(NFStatic("  Select a model:", classes="question-text"))
        
        options = []
        for i, (model, desc, recommended) in enumerate(LLM_MODELS):
            label = f"◆  {model}   {desc}"
            if recommended:
                label += "  ← fastest"
            options.append(label)
        
        options.append("◆  Enter a different model name...")
        
        panel.mount(OptionList(*options, id=self._option_id()))
        
        panel.mount(Horizontal(
            Button("Select →", id="model-continue"),
            Button("Back", id="back-to-provider", classes="secondary"),
            classes="button-row"
        ))
        
        self.set_timer(0.1, self._focus_options)
    
    def _show_custom_model_input(self) -> None:
        """Show custom model name input."""
        self._clear_content()
        self._current_screen = "custom-model"
        panel = self.query_one("#content-panel")
        
        self._mount_section_header(panel, "Custom Ollama Model")
        
        panel.mount(NFStatic("  Enter the model name from https://ollama.com/library", classes="question-text"))
        panel.mount(NFStatic("  Format: modelname or modelname:tag", classes="hint-text"))
        
        panel.mount(NFLabel("  Model name:"))
        panel.mount(Input(placeholder="e.g. qwen3:0.6b", id="custom-model-input"))
        
        # Placeholder for validation error
        self._validation_error_widget = NFStatic("", classes="error-text", id="validation-error")
        panel.mount(self._validation_error_widget)
        
        panel.mount(Horizontal(
            Button("Pull & Configure →", id="custom-model-continue"),
            Button("Back", id="back-to-provider", classes="secondary"),
            classes="button-row"
        ))
    
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
    
    def _show_download_progress(self, model: str) -> None:
        """Show animated download progress screen."""
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
                    # Use improved ANSI stripping
                    cleaned = _strip_ansi(raw)
                    # Get first meaningful line only
                    error_lines = [l.strip() for l in cleaned.split('\n') if l.strip()]
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
        
        # Start progress animation timer (10fps)
        self._progress_timer = self.set_interval(1/10, lambda: self._tick_progress(model))

    def _tick_progress(self, model: str) -> None:
        """Animate the progress bar while download is running."""
        if self._pull_complete:
            if self._progress_timer:
                self._progress_timer.stop()
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
        
        try:
            self.query_one("#progress-bar").update(bar_text)
            self.query_one("#progress-status").update(f"  [{spinner}] {msg}")
        except Exception:
            pass

    def _on_pull_complete(self, model: str) -> None:
        """Called when pull finishes — show success or error."""
        if self._progress_timer:
            try:
                self._progress_timer.stop()
            except Exception:
                pass
        
        if self._pull_success:
            # Show success briefly then finish
            try:
                self.query_one("#progress-bar").update(
                    Text("  " + "━" * 40 + "  100%", style="bold #30D158")
                )
                self.query_one("#progress-status").update(
                    Text(f"  ✓ {model} ready", style="bold #30D158")
                )
                self.query_one("#progress-detail").update("")
            except Exception:
                pass
            
            # Save config and exit after brief pause
            self.set_timer(1.5, lambda: self._finish_with_config({
                **self.config,
                "llm_enabled": True,
                "llm_provider": "ollama",
                "llm_model": model,
                "llm_base_url": "http://localhost:11434",
                "llm_api_key": "",
            }))
        else:
            # Show error
            try:
                self.query_one("#progress-bar").update(
                    Text("  ✗ Download failed", style="bold #FF6778")
                )
                error_short = self._pull_error[:100] if self._pull_error else "Unknown error"
                self.query_one("#progress-status").update(
                    Text(f"  {error_short}", style="#FF6778")
                )
                self.query_one("#progress-detail").update(
                    Text("  Press Escape to go back", style="#6E6E73")
                )
                # Hide the "(this may take a few minutes)" hint on failure
                try:
                    self.query_one("#progress-hint").display = False
                except Exception:
                    pass
            except Exception:
                pass
    
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
        
        elif button_id == "model-continue":
            idx = self._selected_model if isinstance(self._selected_model, int) else 0
            if idx < len(LLM_MODELS):
                model = LLM_MODELS[idx][0]
                self._show_download_progress(model)
            else:
                # Last option is "Enter a different model name..."
                self._show_custom_model_input()
        
        elif button_id == "custom-model-continue":
            try:
                input_widget = self.query_one("#custom-model-input", Input)
                model_name = input_widget.value.strip()
                
                # Step 1: Validate format
                error = _validate_model_name(model_name)
                if error:
                    self._show_validation_error(error)
                    return
                
                # Step 2: Check if already installed locally
                if _is_model_installed_locally(model_name):
                    # Skip download, go straight to config save
                    self._finish_with_config({
                        **self.config,
                        "llm_enabled": True,
                        "llm_provider": "ollama",
                        "llm_model": model_name,
                        "llm_base_url": "http://localhost:11434",
                        "llm_api_key": "",
                    })
                    return
                
                # Step 3: Check if model exists in ollama registry
                if not _verify_model_exists_in_registry(model_name):
                    self._show_validation_error(
                        f"✗ Model '{model_name}' not found in ollama library.\n"
                        "  Check https://ollama.com/library for available models.\n"
                        "  Try: qwen3:0.6b, llama3.2:3b, phi4, deepseek-r1:7b"
                    )
                    return
                
                # Step 4: Model exists, proceed to download
                self._show_download_progress(model_name)
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
