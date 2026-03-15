"""
leakfix UI components — Apple Intelligence themed terminal interface.

Design System: Apple Intelligence (iOS 18 Writing Tools aesthetic)
- Dark, rich backgrounds (#1C1C1E app, #2C2C2E cards)
- Glowing gradient borders cycling purple → blue → pink → violet
- Shimmer text with color wave animation
- Generous spacing, minimal chrome
- NO cyan, NO default blue — only Apple Intelligence palette

All effects are optional and degrade gracefully to plain Rich output.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich import box as rich_box
from rich.align import Align
from rich.text import Text

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# APPLE INTELLIGENCE COLOR PALETTE
# Exact values matching Apple's iOS 18 design language
# ═══════════════════════════════════════════════════════════════════════════════

# Primary brand colors
APPLE_PURPLE = "#BC82F3"        # Primary brand, selected state, glow
APPLE_BLUE_PURPLE = "#8D9FFF"   # Secondary accent, section labels
APPLE_PINK = "#F5B9EA"          # Highlight, hover state
APPLE_VIOLET = "#AA6EEE"        # Border accent, subtle glow
APPLE_BRIGHT_PURPLE = "#C686FF" # Peak shimmer color

# Semantic colors
APPLE_WHITE = "#F5F5F7"         # Primary text
APPLE_DIM = "#6E6E73"           # Subtitles, hints, disabled text
APPLE_ERROR = "#FF6778"         # Errors only
APPLE_SUCCESS = "#30D158"       # Success only
APPLE_PINK_RED = "#FF6778"      # Alias for error (backward compat)
APPLE_ORANGE = "#FFBA71"        # Warnings

# Background colors
APPLE_DARK_BG = "#1C1C1E"       # App background
APPLE_CARD_BG = "#2C2C2E"       # Panel/card background
APPLE_CARD_BORDER = "#3A3A3C"   # Subtle card border (non-glowing)
APPLE_HIGHLIGHT_BG = "#2C1F45"  # Selection/focus background

# Gradient stops for animations
GLOW_GRADIENT = [APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET]
BORDER_GRADIENT = [APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET, APPLE_PURPLE]
SHIMMER_WAVE = [APPLE_PURPLE, APPLE_VIOLET, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_PURPLE]


def print_banner(subtitle: str = "intelligent secret detection") -> None:
    """
    Print the leakfix banner.
    Tries terminaltexteffects beams animation first.
    Falls back to rich-gradient static version.
    Falls back to plain Rich if neither available.
    """
    banner_text = f"  ◆  leakfix  ◆  {subtitle}  "

    # Try TTE animated version first
    try:
        _print_tte_banner(banner_text)
        return
    except (ImportError, Exception):
        pass

    # Try rich-gradient version
    try:
        _print_gradient_banner(subtitle)
        return
    except (ImportError, Exception):
        pass

    # Try shimmer animation (Rich Live only — no extra deps)
    try:
        _print_shimmer_banner(subtitle, duration=1.5)
        return
    except Exception:
        pass

    # Plain Rich fallback
    _print_plain_banner(subtitle)


def _print_tte_banner(text: str) -> None:
    """Apple Intelligence beams effect banner via terminaltexteffects."""
    from terminaltexteffects.effects.effect_beams import Beams

    effect = Beams(text)
    # Apple Intelligence gradient colors for the beam sweep
    effect.effect_config.beam_gradient_stops = (
        "BC82F3",  # purple
        "8D9FFF",  # blue-purple
        "F5B9EA",  # pink
        "AA6EEE",  # violet
        "FFFFFF",  # white reveal
    )
    effect.effect_config.final_gradient_stops = (
        "BC82F3",
        "8D9FFF",
        "F5B9EA",
    )
    effect.effect_config.final_gradient_direction = "horizontal"

    with effect.terminal_output() as terminal:
        for frame in effect:
            terminal.print(frame)


def _print_gradient_banner(subtitle: str) -> None:
    """Rich-gradient glowing panel banner."""
    from rich_gradient import Gradient
    from rich.console import Group

    title = Gradient(
        "◆  leakfix  ◆",
        colors=[APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET],
        justify="center",
        expand=False,
        animated=True,
    )
    sub = Gradient(
        subtitle,
        colors=[APPLE_BLUE_PURPLE, APPLE_PURPLE],
        justify="center",
        expand=False,
    )
    tagline = Gradient(
        "✦  runs 100% locally  ·  no data leaves your machine  ✦",
        colors=[APPLE_VIOLET, APPLE_PINK],
        justify="center",
        expand=False,
    )

    panel = Panel(
        Align.center(
            Group(Text("\n"), title, Text("\n"), sub, Text("\n"), tagline, Text("\n"))
        ),
        border_style=APPLE_PURPLE,
        box=rich_box.ROUNDED,
        padding=(0, 4),
    )

    console.print()
    console.print(Align.center(panel))
    console.print()



def _print_shimmer_banner(subtitle: str, duration: float = 1.5) -> None:
    import time
    from rich.live import Live
    from rich.console import Group
    stops = [APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET, APPLE_BRIGHT_PURPLE]
    banner_str = "◆  leakfix  ◆"

    def _frame(offset: int):
        rot = stops[offset % len(stops):] + stops[:offset % len(stops)]
        title = _make_gradient_text(banner_str, rot, bold=True)
        sub   = _make_gradient_text(subtitle, [rot[1], rot[2]], bold=False)
        sep = Text()
        chunk = 53 // len(rot)
        for c in rot:
            sep.append("─" * chunk, style=c)
        return Group(Text(""), title, sub, sep, Text(""))

    try:
        fps = 12
        with Live(_frame(0), console=console, refresh_per_second=fps, transient=False) as live:
            for i in range(1, int(duration * fps) + 1):
                time.sleep(1.0 / fps)
                live.update(_frame(i))
    except Exception:
        _print_plain_banner(subtitle)

def _print_plain_banner(subtitle: str) -> None:
    """Plain Rich fallback banner."""
    dots = Text()
    dots.append("  ◆ ", style=f"bold {APPLE_PURPLE}")
    dots.append("◆ ", style=f"bold {APPLE_BLUE_PURPLE}")
    dots.append("◆ ", style=f"bold {APPLE_PINK}")
    dots.append("◆  ", style=f"bold {APPLE_VIOLET}")
    dots.append("leakfix", style="bold white")
    dots.append(f"  {subtitle}", style=f"dim {APPLE_DIM}")

    sep = Text()
    colors = [APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET, APPLE_BRIGHT_PURPLE]
    chunk = 53 // len(colors)
    for color in colors:
        sep.append("─" * chunk, style=color)

    console.print()
    console.print(dots)
    console.print(sep)
    console.print()



def _interpolate_hex(c1: str, c2: str, t: float) -> str:
    r1,g1,b1 = int(c1[1:3],16),int(c1[3:5],16),int(c1[5:7],16)
    r2,g2,b2 = int(c2[1:3],16),int(c2[3:5],16),int(c2[5:7],16)
    return f"#{int(r1+(r2-r1)*t):02X}{int(g1+(g2-g1)*t):02X}{int(b1+(b2-b1)*t):02X}"

def _make_gradient_text(text: str, colors: list, bold: bool = False) -> Text:
    result = Text(justify="center")
    n = len(text)
    segs = len(colors) - 1
    for i, ch in enumerate(text):
        tg = i / max(n-1, 1)
        seg = min(int(tg * segs), segs - 1)
        tl = (tg * segs) - seg
        color = _interpolate_hex(colors[seg], colors[seg+1], tl)
        result.append(ch, style=f"bold {color}" if bold else color)
    return result

class ShimmerLive:
    """
    Apple Intelligence shimmer animation using Rich Live.
    
    Runs in the main thread with Rich handling all cursor management.
    The entire wizard runs inside this context manager, with questionary
    prompts working correctly alongside the animated panel.
    
    Usage:
        with ShimmerLive("Setup", "AI-powered secret detection") as shimmer:
            # shimmer.update() is called automatically at 20fps
            # run questionary prompts here
            result = questionary.select(...).ask()
            # animation continues throughout
    """
    
    def __init__(self, title: str = "Setup", subtitle: str | None = None):
        self.title = title
        self.subtitle = subtitle
        self.frame = 0
        self.live = None
        self._stop_requested = False
        self._update_thread = None
        
        self.WAVE = [APPLE_PURPLE, APPLE_VIOLET, APPLE_BLUE_PURPLE, APPLE_PINK,
                     APPLE_BLUE_PURPLE, APPLE_VIOLET, APPLE_PURPLE]
        self.BORDER_CYCLE = [APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET]
        self.FPS = 20
        self.BORDER_FRAMES = self.FPS * 3
    
    def _make_title(self) -> Text:
        """Generate animated gradient title text."""
        from rich.console import Group
        
        title_text = f"◆  leakfix  ◆  {self.title}"
        n = len(title_text)
        result = Text(justify="center")
        
        for i, ch in enumerate(title_text):
            t = ((i / max(n - 1, 1)) - self.frame * 0.04) % 1.0
            ts = t * (len(self.WAVE) - 1)
            seg = min(int(ts), len(self.WAVE) - 2)
            color = _interpolate_hex(self.WAVE[seg], self.WAVE[seg + 1], ts - seg)
            result.append(ch, style=f"bold {color}")
        
        return result
    
    def _border_color(self) -> str:
        """Calculate animated border color."""
        t = (self.frame / self.BORDER_FRAMES) % 1.0
        idx_f = t * len(self.BORDER_CYCLE)
        seg = int(idx_f) % len(self.BORDER_CYCLE)
        nxt = (seg + 1) % len(self.BORDER_CYCLE)
        return _interpolate_hex(self.BORDER_CYCLE[seg], self.BORDER_CYCLE[nxt],
                                idx_f - int(idx_f))
    
    def _make_panel(self) -> Panel:
        """Generate the animated panel for current frame."""
        from rich.console import Group
        from rich import box as _box
        
        lines = [Text("\n"), self._make_title()]
        if self.subtitle:
            lines.append(Text("\n"))
            lines.append(Text(self.subtitle, style=f"dim {APPLE_DIM}", justify="center"))
        lines.append(Text("\n"))
        
        return Panel(
            Align.center(Group(*lines)),
            border_style=self._border_color(),
            box=_box.HEAVY,
            padding=(0, 4),
            width=64,
        )
    
    def _update_loop(self):
        """Background thread that updates the Live display."""
        import time
        while not self._stop_requested and self.live is not None:
            time.sleep(1.0 / self.FPS)
            self.frame += 1
            try:
                self.live.update(self._make_panel())
            except Exception:
                break
    
    def __enter__(self):
        from rich.live import Live
        import threading
        
        self.live = Live(
            self._make_panel(),
            console=console,
            refresh_per_second=self.FPS,
            vertical_overflow="visible",
            transient=False,
        )
        self.live.__enter__()
        
        self._stop_requested = False
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop_requested = True
        if self._update_thread is not None:
            self._update_thread.join(timeout=0.5)
        if self.live is not None:
            self.live.__exit__(exc_type, exc_val, exc_tb)
        return False
    
    def stop(self):
        """Stop the animation (for compatibility with old API)."""
        self._stop_requested = True


def create_shimmer_live(title: str = "Setup", subtitle: str | None = None) -> ShimmerLive:
    """
    Create a ShimmerLive context manager for animated wizard panels.
    
    Usage:
        with create_shimmer_live("Setup", "subtitle") as shimmer:
            # run wizard prompts here
            pass
    """
    return ShimmerLive(title, subtitle)


def print_section_header(title: str, color: str = APPLE_BLUE_PURPLE) -> None:
    """Print a styled section header with gradient separator."""
    console.print()
    console.print(f"[bold {color}]  {title}[/bold {color}]")

    # Gradient separator
    sep = Text()
    colors = [APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK, APPLE_VIOLET, APPLE_BRIGHT_PURPLE]
    chunk = 53 // len(colors)
    for c in colors:
        sep.append("─" * chunk, style=c)
    console.print(sep)


def print_success(message: str) -> None:
    """Print success message with Apple Intelligence styling."""
    console.print(f"\n[bold {APPLE_SUCCESS}]✓[/bold {APPLE_SUCCESS}]  {message}")


def print_error(message: str) -> None:
    """Print error message."""
    console.print(f"\n[bold {APPLE_PINK_RED}]✗[/bold {APPLE_PINK_RED}]  {message}")


def print_warning(message: str) -> None:
    """Print warning message."""
    console.print(f"[{APPLE_ORANGE}]⚠[/{APPLE_ORANGE}]  [dim]{message}[/dim]")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"  [dim {APPLE_DIM}]{message}[/dim {APPLE_DIM}]")


def glow_progress_kwargs() -> dict:
    """
    Return kwargs for Rich Progress that give it an Apple Intelligence glow look.
    Usage: with Progress(**glow_progress_kwargs()) as progress: ...
    """
    from rich.progress import (
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeElapsedColumn,
    )

    return {
        "columns": [
            SpinnerColumn(spinner_name="dots", style=f"bold {APPLE_PURPLE}"),
            TextColumn(f"[bold {APPLE_BLUE_PURPLE}]{{task.description}}[/bold {APPLE_BLUE_PURPLE}]"),
            BarColumn(
                bar_width=40,
                style=APPLE_PURPLE,
                complete_style=APPLE_BLUE_PURPLE,
                finished_style=APPLE_PINK,
            ),
            TaskProgressColumn(style=f"bold {APPLE_PINK}"),
            TimeElapsedColumn(),
        ],
        "transient": True,
    }


def get_questionary_style():
    """Apple Intelligence themed questionary style."""
    try:
        from questionary import Style
        return Style([
            ("qmark", "fg:#BC82F3 bold"),           # ? mark — purple
            ("question", "bold"),                   # question text
            ("answer", "fg:#8D9FFF bold"),          # selected answer — blue-purple
            ("pointer", "fg:#BC82F3 bold noinherit"),  # » pointer — purple (noinherit prevents style bleeding)
            ("highlighted", "fg:#F5B9EA bold"),     # highlighted choice — pink
            ("selected", "fg:#AA6EEE noinherit"),   # selected checkbox item
            ("separator", "fg:#6E6E73"),            # separator
            ("instruction", "fg:#6E6E73 italic"),   # (Use arrow keys)
            ("text", ""),                           # normal text
            ("disabled", "fg:#6E6E73 italic"),      # disabled choices
        ])
    except ImportError:
        return None
