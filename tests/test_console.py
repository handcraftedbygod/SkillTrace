"""Unit tests for sentinel.console: wordmark/welcome rendering, and the
markup=False guard against skill-content that looks like Rich markup."""

import io
from time import monotonic

from rich.console import Console

from sentinel.console import (
    CollectionProgress,
    busy_status,
    file_link,
    file_scan_progress,
    maybe_print_banner,
    print_report,
    print_reports_generated,
    print_scan_complete,
    print_summary_table,
    print_welcome,
)
from sentinel.findings import Confidence, Finding, Severity
from sentinel.report import Report, risk_guidance


def _console(*, no_color=False):
    buf = io.StringIO()
    console = Console(
        file=buf,
        force_terminal=True,
        width=200,
        no_color=no_color,
        color_system=None if no_color else "auto",
        markup=False,
        highlight=False,
    )
    return console, buf


def _report(summary: str, skill_name: str = "test-skill") -> Report:
    finding = Finding(
        category="network_request",
        severity=Severity.HIGH,
        summary=summary,
        confidence=Confidence.HIGH,
        mitre_technique="T1071",
    )
    return Report(
        skill_path="/tmp/skill",
        skill_name=skill_name,
        skill_description="A test skill.",
        findings=[finding],
        risk_score=10,
        risk_level=Severity.HIGH,
        invocations=["python run.py"],
    )


def test_banner_color_has_ansi_when_forced_terminal():
    console, buf = _console()
    maybe_print_banner(console)
    out = buf.getvalue()
    assert "\x1b[" in out
    assert "Static heuristics" in out


def test_banner_no_color_flag_suppresses_ansi():
    console, buf = _console(no_color=True)
    maybe_print_banner(console)
    out = buf.getvalue()
    assert "\x1b[" not in out
    assert "Static heuristics" in out


def test_banner_hidden_when_not_a_terminal():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, markup=False, highlight=False)
    maybe_print_banner(console)
    assert buf.getvalue() == ""


class _ExplodingFile:
    """Simulates Rich's legacy-Windows-console writer, which can raise
    UnicodeEncodeError regardless of content — the banner must degrade to a
    plain print(), never crash the CLI over purely decorative output."""

    def write(self, text):
        raise UnicodeEncodeError("cp1252", text, 0, 1, "simulated legacy console")

    def flush(self):
        pass

    def isatty(self):
        return True


def test_banner_falls_back_when_console_write_raises_unicode_error(capsys):
    console = Console(file=_ExplodingFile(), force_terminal=True, markup=False, highlight=False)
    maybe_print_banner(console)
    assert "SKILLTRACE" in capsys.readouterr().out


def test_welcome_lists_quickstart_commands():
    console, buf = _console(no_color=True)
    print_welcome(console)
    out = buf.getvalue()
    assert "Get started" in out
    assert "skilltrace scan ./my-skill" in out


def test_report_table_does_not_interpret_bracket_markup_in_skill_content():
    console, buf = _console()
    report = _report("[bold red]injected[/bold red] via skill content")
    print_report(console, report)
    out = buf.getvalue()
    assert "[bold red]injected[/bold red] via skill content" in out


def test_summary_table_lists_all_skills():
    console, buf = _console(no_color=True)
    reports = [_report("finding one", "skill-one"), _report("finding two", "skill-two")]
    print_summary_table(console, reports)
    out = buf.getvalue()
    assert "skill-one" in out
    assert "skill-two" in out


def test_summary_table_shows_overall_risk_score_and_guidance():
    low_report = _report("minor thing", "quiet-skill")
    low_report.risk_score = 1
    low_report.risk_level = Severity.LOW
    critical_report = _report("bad thing", "dangerous-skill")
    critical_report.risk_score = 30
    critical_report.risk_level = Severity.CRITICAL

    console, buf = _console(no_color=True)
    print_summary_table(console, [low_report, critical_report])
    out = buf.getvalue()
    assert "Overall risk score: 30 (CRITICAL, driven by dangerous-skill)" in out
    assert risk_guidance(critical_report) in out


def test_summary_table_elaborates_on_the_worst_skills_findings():
    critical_report = _report("bad thing", "dangerous-skill")
    critical_report.risk_score = 30
    critical_report.risk_level = Severity.CRITICAL

    console, buf = _console(no_color=True)
    print_summary_table(console, [critical_report])
    out = buf.getvalue()
    assert "bad thing" in out


def test_summary_table_caps_elaboration_and_notes_the_remainder():
    many_findings = [
        Finding(category="network_request", severity=Severity.CRITICAL, summary=f"finding {i}")
        for i in range(5)
    ]
    critical_report = Report(
        skill_path="/tmp/skill",
        skill_name="dangerous-skill",
        skill_description="A test skill.",
        findings=many_findings,
        risk_score=30,
        risk_level=Severity.CRITICAL,
        invocations=["python run.py"],
    )

    console, buf = _console(no_color=True)
    print_summary_table(console, [critical_report])
    out = buf.getvalue()
    assert "finding 0" in out
    assert "finding 1" in out
    assert "finding 2" in out
    assert "finding 3" not in out
    assert "...and 2 more finding(s) for dangerous-skill" in out


def test_collection_progress_transitions_and_shows_file_progress():
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a", "skill-b", "skill-c"], [4, 3, 2]) as progress:
        progress.start(0, "skill-a")
        progress.advance_file(0, 0)
        progress.advance_file(0, 1)
        progress.skip(1)
        progress.start(2, "skill-c")
        progress.finish(2, Severity.CRITICAL, 30, 5)
    out = buf.getvalue()
    assert "skill-a" in out
    assert "Skipped" in out
    assert "Done" in out
    assert "CRITICAL (30)" in out
    assert "2/4" in out  # skill-a's file progress as of its last update
    assert "50%" in out  # skill-a: 2/4 files
    assert "Overall" in out


def test_collection_progress_shows_totals_upfront_for_queued_rows():
    # A row that hasn't started scanning yet should still show its real file
    # total (known via the file_counts pre-pass), not a bare placeholder — the
    # Overall row's own total must be accurate from the very first frame too.
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a", "skill-b"], [4, 6]):
        pass
    out = buf.getvalue()
    assert "0/4" in out
    assert "0/6" in out
    assert "0/10" in out  # Overall: 0 done out of 4+6 total


def test_scan_complete_splits_scan_and_animation_time_when_animated():
    console, buf = _console(no_color=True)
    print_scan_complete(
        console,
        skills_scanned=3,
        files_scanned=5,
        findings_by_severity={},
        elapsed_s=1.5,
        animation_s=1.2,
    )
    out = buf.getvalue()
    assert "Scan time:" in out
    assert "0.30s" in out  # 1.5 - 1.2
    assert "Animation time:" in out
    assert "1.20s" in out
    assert "Time:" not in out


def test_scan_complete_shows_plain_time_when_not_animated():
    console, buf = _console(no_color=True)
    print_scan_complete(
        console,
        skills_scanned=1,
        files_scanned=2,
        findings_by_severity={},
        elapsed_s=0.05,
    )
    out = buf.getvalue()
    assert "Time:" in out
    assert "Animation time:" not in out


def test_collection_progress_stays_scanning_through_the_sandbox_wait():
    # "Scanning" covers the whole per-skill pipeline (static pass + sandbox
    # run), not just the file pass - the row must not relabel itself to some
    # other status once files hit 100%; it stays "Scanning" (spinner still
    # animating) all the way until finish() actually lands.
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a"], [2]) as progress:
        progress.start(0, "skill-a")
        progress.advance_file(0, 0)
        progress.advance_file(0, 0)
        # Simulates the sandbox-run gap: no further progress calls for a
        # while, but the row must still report "Scanning" if queried now.
        assert progress._rows[0].status == "Scanning"
        progress.finish(0, Severity.LOW, 0, 0)
    out = buf.getvalue()
    assert "2/2" in out
    assert "Done" in out


def test_collection_progress_starts_creeping_bar_once_files_finish():
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a"], [2]) as progress:
        progress.start(0, "skill-a")
        assert progress._rows[0].creep_start is None
        progress.advance_file(0, 0)
        assert progress._rows[0].creep_start is None  # 1/2 - file pass not done yet
        progress.advance_file(0, 0)
        assert progress._rows[0].creep_start is not None  # 2/2 - nothing left to report, creep begins
        progress.finish(0, Severity.LOW, 0, 0)
        assert progress._rows[0].creep_start is None  # cleared once truly done


def test_collection_progress_zero_file_skill_creeps_immediately():
    # A pure-prose skill (no bundled scripts) never triggers advance_file() at
    # all - it must still get the creeping bar, not sit on a static "·".
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a"], [0]) as progress:
        progress.start(0, "skill-a")
        assert progress._rows[0].creep_start is not None


def test_creeping_progress_bar_never_shows_100_percent():
    from sentinel.console import _CreepingProgressBar

    console, buf = _console(no_color=True)
    console.print(_CreepingProgressBar(start_time=monotonic() - 1000))
    out = buf.getvalue()
    assert "99%" in out
    assert "100%" not in out


def test_busy_status_quiet_suppresses_output(capsys):
    console, buf = _console()
    ran = False
    with busy_status(console, "Running in sandbox...", quiet=True):
        ran = True
    assert ran
    assert buf.getvalue() == ""
    assert capsys.readouterr().out == ""


def test_busy_status_non_tty_prints_plain_line():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, markup=False, highlight=False)
    ran = False
    with busy_status(console, "Running in sandbox...", quiet=False):
        ran = True
    assert ran
    assert "Running in sandbox..." in buf.getvalue()


def test_busy_status_terminal_uses_spinner_without_crashing():
    console, buf = _console()
    ran = False
    with busy_status(console, "Running in sandbox...", quiet=False):
        ran = True
    assert ran


def test_file_scan_progress_quiet_yields_noop_callback():
    console, buf = _console()
    with file_scan_progress(console, 3, quiet=True) as advance:
        advance("a.py")
    assert buf.getvalue() == ""


def test_file_scan_progress_zero_files_yields_noop_callback():
    console, buf = _console()
    with file_scan_progress(console, 0, quiet=False) as advance:
        advance("a.py")
    assert buf.getvalue() == ""


def test_file_scan_progress_non_tty_yields_noop_callback():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, markup=False, highlight=False)
    with file_scan_progress(console, 3, quiet=False) as advance:
        advance("a.py")
    assert buf.getvalue() == ""


def test_file_scan_progress_terminal_advances_without_crashing():
    console, buf = _console()
    with file_scan_progress(console, 2, quiet=False) as advance:
        advance("a.py")
        advance("b.py")
    assert "Scanning files" in buf.getvalue()


def test_file_scan_progress_does_not_interpret_bracket_markup_in_filename():
    # A scanned file's relative path is attacker-controlled content — must
    # render literally, not be parsed as Rich markup (same guard as
    # test_report_table_does_not_interpret_bracket_markup_in_skill_content).
    console, buf = _console()
    with file_scan_progress(console, 1, quiet=False) as advance:
        advance("[bold red]evil[/bold red].py")
    assert "[bold red]evil[/bold red].py" in buf.getvalue()


def _link_console():
    # legacy_windows=False, forced color_system: Rich's auto color-system
    # detection falls back to the legacy Windows console renderer (which
    # silently drops OSC-8 hyperlinks) whenever it can't confirm a real
    # VT-capable terminal - true in this sandboxed test process even though
    # a real Windows Terminal session, like a user actually running
    # skilltrace, is correctly detected and unaffected.
    buf = io.StringIO()
    console = Console(
        file=buf, force_terminal=True, legacy_windows=False, width=200, color_system="truecolor", markup=False
    )
    return console, buf


def test_file_link_wraps_path_in_an_osc8_hyperlink():
    link = file_link("sentinel/console.py")
    assert link.style.startswith("link file://")
    assert link.style.endswith("sentinel/console.py")
    assert str(link) == "sentinel/console.py"


def test_reports_generated_links_are_clickable_and_guide_the_user():
    console, buf = _link_console()
    print_reports_generated(console, html="a.html", json="a.json", markdown="a.md")
    out = buf.getvalue()
    assert "Reports generated:" in out
    assert "Click a path below to open it" in out
    assert "\x1b]8;" in out
    assert "a.html" in out
