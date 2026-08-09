"""Terminal presentation for the CLI: wordmark, welcome screen, styled
errors/warnings, and Rich-rendered reports. Replaces the old hand-rolled
ANSI banner/mascot.

`markup=False` on every Console is load-bearing, not cosmetic: finding
summaries, skill descriptions, and source strings come from scanned skill
content, which is adversarial input. Rich's default bracket markup
(`[bold red]...[/]`, and `[link=...]` in particular — a known OSC-8
hyperlink-injection vector) must not be live on attacker-controlled text,
the same reason report.py's HTML renderer runs everything through
html.escape().
"""

from __future__ import annotations

import importlib.metadata
import math
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from rich.console import Console
from rich.live import Live
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn, TextColumn
from rich.progress_bar import ProgressBar
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from sentinel.findings import Severity
from sentinel.report import DIAGNOSTIC_CATEGORIES, Report, collection_risk, risk_guidance

SEVERITY_STYLE = {
    Severity.LOW: "green",
    # gold3, not the default ANSI "yellow" — reads as amber against a dark
    # terminal background instead of a harsh caution-siren yellow.
    Severity.MEDIUM: "gold3",
    Severity.HIGH: "dark_orange",
    Severity.CRITICAL: "bold red",
}

# figlet "ansi_shadow" font, generated once (`pyfiglet.Figlet(font="ansi_shadow").renderText("SKILLTRACE")`)
# and pasted as a literal constant — a fixed word never needs a runtime ASCII-art
# generator dependency.
_WORDMARK_ART = "\n".join(
    line.rstrip()
    for line in r"""
███████╗██╗  ██╗██╗██╗     ██╗  ████████╗██████╗  █████╗  ██████╗███████╗
██╔════╝██║ ██╔╝██║██║     ██║  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
███████╗█████╔╝ ██║██║     ██║     ██║   ██████╔╝███████║██║     █████╗
╚════██║██╔═██╗ ██║██║     ██║     ██║   ██╔══██╗██╔══██║██║     ██╔══╝
███████║██║  ██╗██║███████╗███████╗██║   ██║  ██║██║  ██║╚██████╗███████╗
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
""".strip("\n").splitlines()
)
_WORDMARK_WIDTH = max(len(line) for line in _WORDMARK_ART.splitlines())


def _package_version() -> str:
    try:
        return importlib.metadata.version("skilltrace")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


_QUICKSTART = [
    ("skilltrace scan ./my-skill", "scan a local skill directory"),
    ("skilltrace scan <git-url>", "scan a skill, or a whole collection repo, from git"),
    ("skilltrace scan ./my-skill --static", "static-only scan, no Docker required"),
    ("skilltrace scan ./my-skill --html", "also write a self-contained HTML report"),
]


def make_console(*, stderr: bool, no_color: bool = False) -> Console:
    # No `file=` kwarg: leaving it unset makes Rich resolve sys.stdout/sys.stderr
    # dynamically on every write (via Console.file's property), not a reference
    # captured at construction time — matters for pytest's capsys, which swaps
    # the streams after the test body starts.
    #
    # no_color=None (not False) when --no-color wasn't passed: Rich only reads
    # the NO_COLOR env var itself when no_color is None — passing an explicit
    # False, even as a default, would silently defeat NO_COLOR support.
    #
    # color_system=None (not just no_color=True) when --no-color *was* passed:
    # Rich's no_color only strips color codes and leaves attribute codes (bold,
    # dim, ...) in place, which isn't what a user asking for --no-color expects.
    # color_system=None disables ANSI rendering entirely, the same code path
    # Rich itself takes for a non-terminal/non-color-capable stream.
    return Console(
        stderr=stderr,
        no_color=True if no_color else None,
        color_system=None if no_color else "auto",
        markup=False,
        highlight=False,
    )


def maybe_print_banner(console: Console) -> None:
    if not console.is_terminal:
        return
    try:
        console.print(_WORDMARK_ART, style="bold cyan")
        version_line = f"v{_package_version()} — behavioral scanner for agent skills (Claude, Cursor, Codex)"
        capability_line = "Static heuristics · Dynamic sandbox tracing · Semantic review (opt-in)"
        console.print(version_line.center(_WORDMARK_WIDTH), style="white")
        console.print(capability_line.center(_WORDMARK_WIDTH), style="cyan")
        console.print()
    except UnicodeEncodeError:
        # Rich's legacy-Windows console writer (old cmd.exe / non-VT-capable
        # consoles) talks to the Win32 console API directly rather than through
        # sys.stdout, bypassing the UTF-8 stream reconfigure in cli.main() — it
        # can fail outright on some non-VT consoles regardless of content.
        # Plain builtin print() sidesteps that code path entirely. A purely
        # decorative banner must never crash the CLI over it.
        print(f"SKILLTRACE v{_package_version()}")


def print_welcome(console: Console) -> None:
    console.print("Get started", style="bold")
    console.print()
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="cyan")
    grid.add_column()
    for cmd, blurb in _QUICKSTART:
        grid.add_row(cmd, blurb)
    console.print(grid)
    console.print()
    console.print("Run 'skilltrace scan --help' for the full list of options.")


def print_error(console: Console, message: str) -> None:
    console.print(f"error: {message}", style="bold red")


def print_warning(console: Console, message: str) -> None:
    console.print(f"warning: {message}", style="yellow")


@dataclass
class SkillProgress:
    name: str
    status: str = "Queued"  # "Queued" | "Scanning" | "Skipped" | "Done"
    risk_level: Severity | None = None
    risk_score: int | None = None
    files_done: int = 0
    files_total: int = 0
    issues: int = 0
    spinner: Spinner | None = None
    creep_start: float | None = None


class _CreepingProgressBar:
    """A percentage bar for the stretch of a skill's scan with no fractional
    signal left to report (the file pass is done, but candidate-building,
    semantic review, or the sandbox run itself may still be ahead — none of
    which report incremental progress). Climbs quickly at first, then eases
    toward (never quite reaching) 99%, so the bar keeps visibly moving in
    step with the still-active "Scanning" status instead of sitting frozen
    at a 100% that would falsely claim this skill is done. Recomputed fresh
    on every repaint (including Live's own background refresh ticks, not
    just our explicit updates), the same self-animating pattern rich.spinner.
    Spinner uses — real elapsed time, not a fixed step sequence."""

    def __init__(self, start_time: float, tau: float = 2.5, width: int = 18):
        self.start_time = start_time
        self.tau = tau
        self.width = width

    def _grid(self, pct: int):
        grid = Table.grid(padding=(0, 1))
        grid.add_column()
        grid.add_column(justify="right", width=4)
        grid.add_row(
            ProgressBar(total=100, completed=pct, width=self.width, complete_style="green", finished_style="green"),
            f"{pct}%",
        )
        return grid

    def __rich_console__(self, console, options):
        elapsed = monotonic() - self.start_time
        pct = min(99, int(100 * (1 - math.exp(-elapsed / self.tau))))
        yield self._grid(pct)

    def __rich_measure__(self, console, options):
        # Without this, Rich falls back to measuring this frame's actual
        # rendered text — "3%" is narrower than "42%" — and the outer table's
        # Progress column visibly resizes frame to frame as the live
        # percentage's digit count changes. Measure a fixed reference (same
        # column widths _progress_cell uses) so it doesn't.
        return self._grid(0).__rich_measure__(console, options)


def _status_cell(row: SkillProgress):
    # A live rich.spinner.Spinner, not a static "⟳" glyph — its render() reads
    # the wall clock on every repaint, so it visibly spins on Live's own
    # refresh_per_second ticks even while this skill's row hasn't changed
    # (e.g. mid-sandbox-run, well past the static file-scan pass — "Scanning"
    # covers the whole per-skill pipeline start to finish, not just the static
    # file pass, so the row doesn't relabel itself partway through).
    if row.status == "Scanning" and row.spinner is not None:
        return row.spinner
    text, style = {
        "Queued": ("◦ Queued", "dim"),
        "Skipped": ("- Skipped", "dim"),
        "Done": ("✓ Done", "green"),
    }[row.status]
    return Text(text, style=style)


def _progress_cell(done: int, total: int):
    # A grid (not a bare ProgressBar) so the bar and its percentage render
    # side by side in one cell, matching the fill-as-it-scans look of the
    # single-skill file_scan_progress bar above.
    if total <= 0:
        return Text("·", style="dim")
    grid = Table.grid(padding=(0, 1))
    grid.add_column()
    grid.add_column(justify="right", width=4)
    grid.add_row(
        ProgressBar(total=total, completed=done, width=18, complete_style="green", finished_style="green"),
        f"{int(done / total * 100)}%",
    )
    return grid


def _build_progress_table(rows: list[SkillProgress]) -> Table:
    table = Table(show_header=True, header_style="bold cyan", border_style="dim", pad_edge=True, expand=False)
    table.add_column("Skill")
    table.add_column("Status")
    table.add_column("Files")
    table.add_column("Issues")
    table.add_column("Risk")
    table.add_column("Progress")
    for row in rows:
        files_text = Text(f"{row.files_done}/{row.files_total}" if row.files_total else "·", style="dim")
        if row.status in ("Scanning", "Done"):
            issues_text = Text(str(row.issues), style="dark_orange" if row.issues else "dim")
        else:
            issues_text = Text("·", style="dim")
        if row.risk_level is not None:
            risk_text = Text(f"{row.risk_level.value.upper()} ({row.risk_score})", style=SEVERITY_STYLE[row.risk_level])
        else:
            risk_text = Text("·", style="dim")
        if row.status == "Scanning" and row.creep_start is not None:
            progress_cell = _CreepingProgressBar(row.creep_start)
        elif row.status == "Done" and row.files_total == 0:
            # A finished skill with no bundled files never advances
            # files_done/files_total past 0/0 - _progress_cell(0, 0) would
            # read that as "no fractional signal" and show "·" forever,
            # even though the scan is complete. Show a full bar instead.
            progress_cell = _progress_cell(1, 1)
        else:
            progress_cell = _progress_cell(row.files_done, row.files_total)
        table.add_row(row.name, _status_cell(row), files_text, issues_text, risk_text, progress_cell)
    if rows:
        table.add_section()
        done_files = sum(r.files_done for r in rows)
        total_files = sum(r.files_total for r in rows)
        pct = f"{int(done_files / total_files * 100)}%" if total_files else "0%"
        table.add_row(
            Text("Overall", style="bold"),
            Text(pct, style="bold cyan"),
            Text(f"{done_files}/{total_files}" if total_files else "·", style="bold"),
            Text(str(sum(r.issues for r in rows)), style="bold"),
            Text("·", style="dim"),
            _progress_cell(done_files, total_files),
        )
    return table


class CollectionProgress:
    """Live-updating stderr table for a multi-skill collection scan. Only
    meaningful on a real terminal — callers should check `console.is_terminal`
    themselves and fall back to plain print lines otherwise (Live is silent
    off-TTY anyway when transient, so this doesn't guard against that itself).

    file_counts is required upfront (not discovered lazily per-row) so every
    row — including ones still Queued — shows a real "done/total" and the
    Overall row's aggregate is accurate from the very first frame, rather than
    growing as each skill starts."""

    def __init__(self, console: Console, skill_names: list[str], file_counts: list[int]):
        self._rows = [
            SkillProgress(name, files_total=total) for name, total in zip(skill_names, file_counts)
        ]
        self._live = Live(_build_progress_table(self._rows), console=console, transient=True, refresh_per_second=12)

    def __enter__(self) -> "CollectionProgress":
        self._live.__enter__()
        return self

    def __exit__(self, *exc_info) -> None:
        self._live.__exit__(*exc_info)

    def _refresh(self) -> None:
        # refresh=True: without it, Live only repaints on its own timer, and a
        # skill with a handful of tiny files can finish scanning faster than
        # that tick — every intermediate state gets skipped and the bar jumps
        # straight to 100% having never shown the real fill in between.
        self._live.update(_build_progress_table(self._rows), refresh=True)

    def start(self, idx: int, name: str) -> None:
        row = self._rows[idx]
        row.name = name
        row.status = "Scanning"
        row.files_done = 0
        row.issues = 0
        # A skill with no bundled files (pure prose, no scripts) never gets
        # an advance_file() call to trigger the creep bar below - start it
        # immediately, since there's no file phase to show first either way.
        row.creep_start = monotonic() if row.files_total == 0 else None
        row.spinner = Spinner("dots", text=Text("Scanning", style="gold3"))
        self._refresh()

    def advance_file(self, idx: int, running_issues: int) -> None:
        row = self._rows[idx]
        row.files_done += 1
        row.issues = running_issues
        if row.files_done >= row.files_total:
            # File pass just finished but the skill isn't done yet (finish()
            # hasn't landed) — start the creeping bar for whatever's left
            # (candidate-building, semantic review, the sandbox run itself).
            row.creep_start = monotonic()
        self._refresh()

    def skip(self, idx: int) -> None:
        self._rows[idx].status = "Skipped"
        self._refresh()

    def finish(self, idx: int, risk_level: Severity, risk_score: int, issues: int) -> None:
        row = self._rows[idx]
        row.status = "Done"
        row.risk_level = risk_level
        row.risk_score = risk_score
        row.files_done = row.files_total
        row.issues = issues
        row.spinner = None
        row.creep_start = None
        self._refresh()


@contextmanager
def busy_status(console: Console, message: str, *, quiet: bool):
    """Spinner (TTY) or a single plain line (non-TTY) around a step that can
    take a while with otherwise zero feedback (git clone, sandbox run).
    Suppressed entirely under --quiet, same as other progress chatter."""
    if quiet:
        yield
    elif console.is_terminal:
        with console.status(message):
            yield
    else:
        console.print(message)
        yield


@contextmanager
def file_scan_progress(console: Console, total: int, *, quiet: bool):
    """Real percentage bar over a skill's bundled files during the static
    pass — total is known upfront (discover_bundled_files has already run),
    so this is an honest count, not a fake/simulated fill. Yields a callback
    to advance it; a no-op callback when there's nothing to show (--quiet,
    non-terminal, zero files, or nested inside a collection scan's own Live
    table — Rich doesn't support two Live displays at once, same constraint
    busy_status already works around for the sandbox spinner).

    markup=False on every TextColumn here, not just the Console: a scanned
    file's own relative path — attacker-controlled content — is interpolated
    directly into the filename column, and Rich's TextColumn has its own
    independent markup flag (default True) that Console's markup=False does
    not implicitly override."""
    if quiet or not console.is_terminal or total == 0:
        yield lambda _filename: None
        return
    progress = Progress(
        TextColumn("Scanning files", markup=False),
        BarColumn(complete_style="green", finished_style="green"),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TextColumn("{task.fields[filename]}", markup=False, style="dim"),
        console=console,
        transient=True,
    )
    with progress:
        task_id = progress.add_task("scan", total=total, filename="")

        def advance(filename: str) -> None:
            progress.update(task_id, filename=filename)
            progress.advance(task_id)

        yield advance


def _findings_table(findings: list) -> Table:
    # show_lines + vertical="middle": the Summary column often wraps to several
    # lines while Severity/Category/Confidence/ATT&CK don't, which without a
    # row separator and middle alignment reads as one cramped, undifferentiated
    # block of text rather than distinct rows.
    table = Table(show_lines=True)
    table.add_column("Severity", vertical="middle")
    table.add_column("Category", overflow="fold", vertical="middle")
    table.add_column("Summary", ratio=1, overflow="fold", vertical="middle")
    table.add_column("Confidence", vertical="middle")
    table.add_column("ATT&CK", vertical="middle")
    for f in findings:
        table.add_row(
            f.severity.value.upper(),
            f.category,
            f.summary,
            f.confidence.value,
            f.mitre_technique or "-",
            style=SEVERITY_STYLE.get(f.severity),
        )
    return table


def _scan_summary_grid(report: Report) -> Table:
    # Context that's always worth showing, findings or not — otherwise a
    # clean result ("Risk score: 0, No findings.") looks identical to the
    # tool having done nothing at all, rather than having checked thoroughly.
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Sandbox:", "ran" if report.sandbox_ran else "not run (--static)")
    grid.add_row(
        "Semantic review:", "ran" if report.semantic_review_ran else "not run (--semantic-review to enable)"
    )
    grid.add_row("Invocations:", ", ".join(report.invocations) if report.invocations else "none attempted")
    if report.allowed_tools:
        grid.add_row("Allowed tools:", ", ".join(report.allowed_tools))
    return grid


def print_report(console: Console, report: Report) -> None:
    console.print(report.skill_name or report.skill_path, style="bold")
    if report.skill_description:
        console.print(report.skill_description, style="dim")
    console.print(
        f"Risk score: {report.risk_score} ",
        style=SEVERITY_STYLE.get(report.risk_level),
        end="",
    )
    console.print(f"({report.risk_level.value.upper()})", style=SEVERITY_STYLE.get(report.risk_level))
    console.print(risk_guidance(report), style="white")
    console.print()
    console.print(_scan_summary_grid(report))
    console.print()
    if report.findings:
        console.print(_findings_table(report.findings))
    else:
        console.print("No findings.", style="green")


def print_summary_table(console: Console, reports: list[Report]) -> None:
    table = Table(show_lines=False)
    table.add_column("Skill")
    table.add_column("Risk")
    table.add_column("Score")
    for r in reports:
        table.add_row(
            r.skill_name or r.skill_path,
            r.risk_level.value.upper(),
            str(r.risk_score),
            style=SEVERITY_STYLE.get(r.risk_level),
        )
    console.print(table)

    worst = collection_risk(reports)
    console.print()
    console.print(f"Overall risk score: {worst.risk_score} ", style=SEVERITY_STYLE.get(worst.risk_level), end="")
    console.print(
        f"({worst.risk_level.value.upper()}, driven by {worst.skill_name or worst.skill_path})",
        style=SEVERITY_STYLE.get(worst.risk_level),
    )
    console.print(risk_guidance(worst), style="white")

    real_findings = sorted(
        (f for f in worst.findings if f.category not in DIAGNOSTIC_CATEGORIES),
        key=lambda f: f.severity.rank,
        reverse=True,
    )
    if real_findings:
        shown = real_findings[:3]
        console.print()
        console.print(_findings_table(shown))
        remaining = len(real_findings) - len(shown)
        if remaining > 0:
            console.print(f"...and {remaining} more finding(s) for {worst.skill_name or worst.skill_path} — see the full report.", style="dim")


def file_link(path: str) -> Text:
    # A real OSC-8 hyperlink, not markup=True: the path string is ours (an
    # auto-generated report filename), never attacker-controlled skill
    # content, so this doesn't run into the injection risk markup=False
    # guards against elsewhere in this module - it never touches Rich's
    # bracket-markup parser at all. Falls back to plain text for a path
    # Path.as_uri() can't handle (e.g. relative to a missing drive on
    # Windows) rather than crash the report we're just trying to announce.
    try:
        uri = Path(path).resolve().as_uri()
    except (ValueError, OSError):
        return Text(path)
    return Text(path, style=f"link {uri}")


def print_reports_generated(console: Console, *, html: str, json: str, markdown: str) -> None:
    # Not gated on --quiet, same reasoning as the existing --html "written to"
    # line: this is the only record of where the auto-written files landed.
    console.print()
    console.print("Reports generated:", style="bold")
    console.print("Click a path below to open it — HTML gives the full interactive report.", style="dim")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="cyan")
    grid.add_column()
    grid.add_row("HTML", file_link(html))
    grid.add_row("JSON", file_link(json))
    grid.add_row("Markdown", file_link(markdown))
    console.print(grid)


def print_scan_complete(
    console: Console,
    *,
    skills_scanned: int,
    files_scanned: int,
    findings_by_severity: dict[Severity, int],
    elapsed_s: float,
    animation_s: float = 0.0,
) -> None:
    console.print()
    console.print("Scan complete", style="bold green")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Skills scanned:", str(skills_scanned))
    grid.add_row("Files scanned:", str(files_scanned))
    total_findings = sum(findings_by_severity.values())
    grid.add_row("Findings:", str(total_findings))
    if total_findings:
        grid.add_row("", "")
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            count = findings_by_severity.get(severity, 0)
            if count:
                grid.add_row(f"{severity.value.capitalize()} severity:", Text(str(count), style=SEVERITY_STYLE[severity]))
    if animation_s > 0:
        # --static can genuinely finish in single-digit milliseconds — split
        # out so the reported time doesn't quietly include deliberate pacing
        # (see cli.py's STATIC_ANIMATION_DWELL_S) as if it were real scan work.
        grid.add_row("Scan time:", f"{max(elapsed_s - animation_s, 0):.2f}s")
        grid.add_row("Animation time:", f"{animation_s:.2f}s")
    else:
        grid.add_row("Time:", f"{elapsed_s:.2f}s")
    console.print(grid)
