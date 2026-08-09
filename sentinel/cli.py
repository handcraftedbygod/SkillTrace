"""skilltrace CLI: scan <path|git-url> [--invoke CMD] [--allow-network] [--json]"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from collections import Counter
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich_argparse import RichHelpFormatter

from sentinel.console import (
    CollectionProgress,
    busy_status,
    file_scan_progress,
    make_console,
    maybe_print_banner,
    print_error,
    print_report,
    print_reports_generated,
    print_scan_complete,
    print_summary_table,
    print_warning,
    print_welcome,
)
from sentinel.findings import Finding, Severity
from sentinel.heuristics import run_heuristics
from sentinel.report import build_report, diff_sandbox_results, render_html_multi, render_json_multi, render_markdown_multi
from sentinel.sandbox import (
    DIFFERENTIAL_ENV,
    DIFFERENTIAL_HOSTNAME,
    DockerUnavailableError,
    SentinelError,
    build_invocation_candidates,
    ensure_docker_available,
    resolve_skill_source,
    run_skill_in_sandbox,
)
from sentinel.semantic_review import SemanticReviewError, review_skill_instructions
from sentinel.skillmd import (
    SkillMdNotFoundError,
    SkillMdParseError,
    SkillMetadata,
    discover_bundled_files,
    discover_skill_directories,
    parse_skill_md,
)

FAIL_THRESHOLD_CHOICES = ["low", "medium", "high", "critical"]

DEFAULT_HTML_REPORT = "skilltrace-report.html"

# --static can genuinely finish scanning a small skill in single-digit
# milliseconds — real per-file progress at that speed reads as a single
# instant jump to 100% rather than motion. STATIC_ANIMATION_DWELL_S floors
# how little time passes between file updates so it's actually visible;
# STATIC_ANIMATION_BUDGET_S caps how much total wall-clock time this adds
# across the whole scan, so a large collection isn't padded into a crawl —
# once spent, remaining files advance at full real speed.
STATIC_ANIMATION_DWELL_S = 0.09
STATIC_ANIMATION_BUDGET_S = 2.0

_SCAN_EXAMPLES = [
    ("skilltrace scan ./my-skill", "scan a local skill directory"),
    ("skilltrace scan ./my-skill --static", "static-only, no Docker required"),
    ("skilltrace scan <git-url>", "scan a skill (or a whole collection repo) from git"),
    ("skilltrace scan ./my-skill --fail-threshold high", "exit non-zero for CI gating"),
    ("skilltrace scan ./my-skill --json -o report.json", "machine-readable output to a file"),
]

_EXIT_CODES = [
    (0, "Success (no findings at/above --fail-threshold, or no threshold set)"),
    (1, "Findings at/above --fail-threshold"),
    (2, "Could not resolve the skill source (bad path/URL), or every SKILL.md found failed to parse"),
    (3, "Docker unavailable"),
    (4, "Sandbox error"),
    (5, "--semantic-review requested without ANTHROPIC_API_KEY set"),
]

_EXIT_CODES_NOTE = (
    "A repo with no SKILL.md anywhere is no longer a hard failure: it's scanned as a "
    "single unlabeled directory instead (see the no_skill_md finding)."
)


def _make_scan_help_action(console: Console) -> type[argparse.Action]:
    # A custom nargs=0 Action (mirroring argparse's own -h) rather than
    # add_help's default: that default calls parser.print_help(), which uses
    # RichHelpFormatter's two-column wrapped-text layout - the exact "wall of
    # text" this replaces with a real Rich table. Must subclass Action (not
    # store_true) so help still short-circuits before path_or_url's
    # required-positional check, same as real -h does.
    class _ScanHelpAction(argparse.Action):
        def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
            super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

        def __call__(self, parser, namespace, values, option_string=None):
            _print_scan_help(console, parser)
            parser.exit()

    return _ScanHelpAction


def _print_scan_help(console: Console, parser: argparse.ArgumentParser) -> None:
    format_invocation = argparse.HelpFormatter(parser.prog)._format_action_invocation
    # Not parser.format_usage(): argparse wraps its own bracketed [--flag VALUE]
    # synopsis to a width it detects itself, then Rich re-wraps that already-
    # wrapped text to the width *it* detects - two layout engines fighting
    # produces broken mid-flag line breaks ("[--invoke\nCMD]") with misaligned
    # continuation indents. Every flag is fully documented in the table below
    # anyway, so the synopsis only needs to show the invocation shape, which is
    # short enough to never wrap.
    positionals = " ".join(format_invocation(a) for a in parser._get_positional_actions())
    console.print(f"Usage: {parser.prog} [OPTIONS] {positionals}", style="bold")
    console.print()
    if parser.description:
        console.print(parser.description)
        console.print()

    table = Table(show_header=True, header_style="bold cyan", border_style="dim", pad_edge=True, expand=False)
    table.add_column("Flag")
    table.add_column("Description", ratio=1, overflow="fold")
    first_group = True
    for group in parser._action_groups:
        actions = [a for a in group._group_actions if a.help != argparse.SUPPRESS]
        if not actions:
            continue
        if not first_group:
            table.add_section()
        first_group = False
        table.add_row(Text(f"{(group.title or '').capitalize()}:", style="bold cyan"), "")
        for action in actions:
            table.add_row(format_invocation(action), action.help or "")
    console.print(table)
    console.print()

    console.print("Examples:", style="bold cyan")
    examples = Table.grid(padding=(0, 2))
    examples.add_column(style="cyan", no_wrap=True)
    examples.add_column(style="dim")
    for cmd, blurb in _SCAN_EXAMPLES:
        examples.add_row(cmd, f"# {blurb}")
    console.print(examples)
    console.print()

    console.print("Exit codes:", style="bold cyan")
    codes = Table.grid(padding=(0, 2))
    codes.add_column(justify="right", style="bold")
    codes.add_column()
    for code, meaning in _EXIT_CODES:
        codes.add_row(str(code), meaning)
    console.print(codes)
    console.print()
    console.print(_EXIT_CODES_NOTE, style="dim")


def _common_flags_parser() -> argparse.ArgumentParser:
    # add_help=False: argparse's parents= mechanism errors on a duplicate -h/--help
    # if the parent parser defines its own. This parser exists only to be shared
    # (via parents=[...]) by both the top-level parser and the scan subparser, so
    # flags like --quiet work in either position: `skilltrace --quiet scan ...`
    # or `skilltrace scan --quiet ...`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress the startup banner and per-skill progress messages on stderr. "
        "Errors, warnings, and the report itself are unaffected.",
    )
    common.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in terminal output. Also respected automatically via "
        "the NO_COLOR env var, or whenever stdout/stderr isn't a real terminal.",
    )
    return common


def _build_arg_parser(*, no_color: bool = False) -> argparse.ArgumentParser:
    common = _common_flags_parser()
    parser = argparse.ArgumentParser(
        prog="skilltrace",
        description="A behavioral scanner for agent skills (Claude, Cursor, Codex) — "
        "sandboxes a skill and reports what it actually does, instead of trusting its "
        "description.",
        parents=[common],
        formatter_class=RichHelpFormatter,
    )
    # Not required: a bare `skilltrace` invocation shows the welcome screen
    # (see sentinel.console.print_welcome) instead of an argparse usage error.
    subparsers = parser.add_subparsers(dest="command", required=False)

    scan = subparsers.add_parser(
        "scan",
        help="Scan a skill directory or git URL",
        parents=[common],
        formatter_class=RichHelpFormatter,
        add_help=False,
    )
    scan.add_argument(
        "-h",
        "--help",
        action=_make_scan_help_action(make_console(stderr=False, no_color=no_color)),
        help="show this help message and exit",
    )
    scan.add_argument("path_or_url", help="Local path to a skill directory, or a git URL")

    behavior = scan.add_argument_group("Scan behavior")
    behavior.add_argument("--invoke", metavar="CMD", help="An explicit command to run inside the sandbox")
    behavior.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow real network egress instead of the DNS/TLS sinkhole (no decrypted traffic visibility this run)",
    )
    behavior.add_argument("--timeout", type=int, default=60, help="Per-invocation sandbox timeout in seconds")
    behavior.add_argument(
        "--static",
        "--no-sandbox",
        dest="no_sandbox",
        action="store_true",
        help="Static-only scan: skip the Docker sandbox, heuristics only (no Docker required; "
        "--no-sandbox is a kept alias)",
    )
    behavior.add_argument(
        "--fail-threshold",
        choices=FAIL_THRESHOLD_CHOICES,
        default=None,
        help="Exit non-zero if risk is at or above this severity (for CI gating)",
    )

    output = scan.add_argument_group("Output")
    output.add_argument("--json", action="store_true", help="Output the report as JSON instead of Markdown")
    output.add_argument("-o", "--output", metavar="FILE", help="Write the report to FILE instead of stdout")
    output.add_argument(
        "--html",
        metavar="FILE",
        nargs="?",
        const=DEFAULT_HTML_REPORT,
        help=f"Also write a self-contained HTML report to FILE (default: {DEFAULT_HTML_REPORT})",
    )

    advanced = scan.add_argument_group("Advanced (opt-in)")
    advanced.add_argument(
        "--semantic-review",
        action="store_true",
        help="Send skill instructions to Claude for adversarial review (one API call per "
        "skill, needs ANTHROPIC_API_KEY, opt-in)",
    )
    advanced.add_argument(
        "--differential",
        action="store_true",
        help="Re-run with a varied hostname/env and flag behavior that differs — a real "
        "sandbox-evasion signal (opt-in, ~2x runtime)",
    )

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    start_time = time.time()
    stderr_console = make_console(stderr=True, no_color=args.no_color)

    # Checked once, up front — not per skill_dir in the loop below. A missing key
    # is a one-time configuration problem; printing the same "set ANTHROPIC_API_KEY"
    # warning once per skill in a multi-hundred-skill collection scan would be noise
    # a user could easily miss, then wrongly assume --semantic-review actually ran.
    if args.semantic_review and not os.environ.get("ANTHROPIC_API_KEY"):
        print_error(
            stderr_console,
            "--semantic-review requires ANTHROPIC_API_KEY to be set "
            "(get a key at https://console.anthropic.com/)",
        )
        return 5

    with tempfile.TemporaryDirectory(prefix="skilltrace-") as tmpdir:
        try:
            # For a git URL this is a real `git clone`, which can take several
            # seconds with otherwise zero feedback — the same "silent wait"
            # problem the sandbox spinner solves, just earlier in the pipeline.
            with busy_status(stderr_console, "Resolving skill source...", quiet=args.quiet):
                source_dir = resolve_skill_source(args.path_or_url, Path(tmpdir))
        except SentinelError as exc:
            print_error(stderr_console, str(exc))
            return 2

        # Most sources are a single skill (SKILL.md at source_dir's own root).
        # Some are collections — one repo bundling many skills, each in its own
        # subdirectory, with no root SKILL.md at all — see
        # skillmd.discover_skill_directories.
        skill_dirs = discover_skill_directories(source_dir)
        # Zero anywhere in the tree usually means this isn't an agent skill at
        # all (wrong path/URL, or an ordinary code repo) — worth a best-effort
        # static read of what's actually there rather than a hard stop, since
        # that's exactly the shape of "point SkillTrace at some repo to see if
        # it's safe to install" triage.
        raw_directory_scan = not skill_dirs
        if raw_directory_scan:
            skill_dirs = [source_dir]

        reports = []
        total = len(skill_dirs)
        total_files_scanned = 0
        # Deliberate pacing only makes sense where there's a live animation
        # to smooth out in the first place — --quiet and non-terminal output
        # have none, so there's nothing to gain from slowing the scan down.
        animate_static = args.no_sandbox and not args.quiet and stderr_console.is_terminal
        animation_time_s = 0.0
        last_file_time = time.time()
        # Discovered once upfront (not lazily per-skill in the loop below) so
        # a collection scan's progress table can show every row's real
        # "done/total" — including still-Queued ones — from the very first
        # frame, instead of totals only appearing once each skill starts.
        bundled_files_by_dir = {d: discover_bundled_files(d) for d in skill_dirs}
        # A collection scan gets a live-updating progress table on a real
        # terminal; everything else (non-TTY/CI, --quiet, or a single skill)
        # keeps the plain print-line fallback below.
        show_live_progress = total > 1 and not args.quiet and stderr_console.is_terminal
        progress_cm = (
            CollectionProgress(
                stderr_console,
                [d.name for d in skill_dirs],
                [len(bundled_files_by_dir[d]) for d in skill_dirs],
            )
            if show_live_progress
            else nullcontext()
        )
        with progress_cm as progress:
            for idx, skill_dir in enumerate(skill_dirs, start=1):
                if raw_directory_scan:
                    metadata = SkillMetadata(
                        name=None,
                        description=None,
                        license=None,
                        allowed_tools=None,
                        when_to_use=None,
                        paths=None,
                        raw_frontmatter={},
                        body="",
                        path=skill_dir,
                    )
                else:
                    try:
                        metadata = parse_skill_md(skill_dir)
                    except (SkillMdNotFoundError, SkillMdParseError) as exc:
                        print_warning(stderr_console, f"skipping {skill_dir}: {exc}")
                        if progress:
                            progress.skip(idx - 1)
                        continue

                skill_label = metadata.name or skill_dir.name
                bundled_files = bundled_files_by_dir[skill_dir]

                # Only for collection scans (total > 1) — a single-skill scan doesn't
                # need progress noise, but scanning a repo with dozens or hundreds of
                # skills with zero visibility into where it is was a real pain point
                # while building this tool. --quiet suppresses this chatter but never
                # errors/warnings.
                if progress:
                    progress.start(idx - 1, skill_label)
                elif total > 1 and not args.quiet:
                    stderr_console.print(f"[{idx}/{total}] scanning {skill_label}...")

                def _on_file(filename: str, running_issues: int) -> None:
                    nonlocal total_files_scanned, animation_time_s, last_file_time
                    total_files_scanned += 1
                    if animate_static and animation_time_s < STATIC_ANIMATION_BUDGET_S:
                        since_last = time.time() - last_file_time
                        if since_last < STATIC_ANIMATION_DWELL_S:
                            pad = STATIC_ANIMATION_DWELL_S - since_last
                            time.sleep(pad)
                            animation_time_s += pad
                    last_file_time = time.time()
                    if progress:
                        progress.advance_file(idx - 1, running_issues)
                    else:
                        advance_file(filename)

                # A collection scan's Live table already shows per-file progress in
                # its own Progress column — Rich doesn't support two Live displays
                # at once, so the standalone bar only renders for a single-skill scan.
                with file_scan_progress(
                    stderr_console, len(bundled_files), quiet=args.quiet or progress is not None
                ) as advance_file:
                    heuristic_findings = run_heuristics(skill_dir, metadata, on_file=_on_file)

                if raw_directory_scan:
                    heuristic_findings = heuristic_findings + [
                        Finding(
                            category="no_skill_md",
                            severity=Severity.MEDIUM,
                            summary=f"No SKILL.md found anywhere under {skill_dir} — this doesn't look "
                            "like an agent skill (Claude, Cursor, or Codex). Static checks still ran "
                            "against the raw directory contents, but there's no declared usage example "
                            "or metadata to sandbox-run or evaluate against.",
                            source="cli",
                        )
                    ]
                candidates = build_invocation_candidates(skill_dir, bundled_files, metadata.body, args.invoke)

                semantic_review_ran = False
                if args.semantic_review:
                    try:
                        heuristic_findings = heuristic_findings + review_skill_instructions(
                            metadata.name,
                            metadata.description,
                            metadata.body,
                            when_to_use=metadata.when_to_use,
                            source=str(skill_dir),
                        )
                        semantic_review_ran = True
                    except SemanticReviewError as exc:
                        print_warning(stderr_console, f"semantic review skipped for {skill_dir}: {exc}")

                sandbox_results = None
                if not args.no_sandbox:
                    # run_skill_in_sandbox() below also calls ensure_docker_available()
                    # itself (it's a public function other callers may use directly) —
                    # this call exists only to fail fast with a distinct exit code
                    # before doing any candidate-building work, not to avoid the
                    # (cheap, subprocess-level) check that follows.
                    try:
                        ensure_docker_available()
                    except DockerUnavailableError as exc:
                        print_error(stderr_console, str(exc))
                        return 3

                    if not candidates:
                        # A pure-prose skill (no bundled scripts, no --invoke, no
                        # SKILL.md usage examples) has nothing for the sandbox to run —
                        # exactly the attack shape this project's own threat model
                        # names first. Without this, the report renders identically to
                        # a genuinely clean sandboxed run; static heuristics still ran
                        # against the SKILL.md body, but dynamic behavior was never observed.
                        heuristic_findings = heuristic_findings + [
                            Finding(
                                category="sandbox_not_attempted",
                                severity=Severity.MEDIUM,
                                summary="No invocable candidate found (no bundled script, --invoke flag, or "
                                "SKILL.md usage example) — the sandbox never ran, so dynamic behavior was not "
                                "observed; only the static pass applies to this result",
                                source="sandbox",
                            )
                        ]
                    if candidates:
                        # A single-skill scan has no other progress indicator during
                        # what can be a --timeout-second wait; a collection scan
                        # already printed "[idx/total] scanning ..." for this skill,
                        # so a spinner on top of that per skill would just be noise.
                        quiet_busy_status = args.quiet or total > 1
                        try:
                            with busy_status(stderr_console, "Running in sandbox...", quiet=quiet_busy_status):
                                sandbox_results = run_skill_in_sandbox(
                                    skill_dir,
                                    candidates,
                                    allow_network=args.allow_network,
                                    timeout_s=args.timeout,
                                )
                            if args.differential:
                                with busy_status(
                                    stderr_console, "Running differential pass...", quiet=quiet_busy_status
                                ):
                                    varied_results = run_skill_in_sandbox(
                                        skill_dir,
                                        candidates,
                                        allow_network=args.allow_network,
                                        timeout_s=args.timeout,
                                        hostname=DIFFERENTIAL_HOSTNAME,
                                        env_overrides=DIFFERENTIAL_ENV,
                                    )
                                for baseline_result, varied_result in zip(sandbox_results, varied_results):
                                    heuristic_findings = heuristic_findings + diff_sandbox_results(
                                        baseline_result, varied_result
                                    )
                        except SentinelError as exc:
                            print_error(stderr_console, str(exc))
                            return 4

                report = build_report(
                    skill_dir,
                    metadata,
                    heuristic_findings,
                    sandbox_results,
                    candidates,
                    semantic_review_ran,
                    sandbox_ran=not args.no_sandbox,
                )
                reports.append(report)
                if progress:
                    progress.finish(idx - 1, report.risk_level, report.risk_score, len(report.findings))
                elif total > 1 and not args.quiet:
                    stderr_console.print(f"    -> {report.risk_level.value.upper()} ({report.risk_score})")

        if not reports:
            print_error(stderr_console, f"No valid SKILL.md could be parsed under {source_dir}")
            return 2

    if args.html:
        Path(args.html).write_text(render_html_multi(reports), encoding="utf-8")
        # Not gated on --quiet: the only indication of where --html's output
        # landed (the filename can be an implicit default), so it's useful
        # signal rather than progress noise.
        stderr_console.print(f"HTML report written to {args.html}")

    if args.output:
        output = render_json_multi(reports) if args.json else render_markdown_multi(reports)
        Path(args.output).write_text(output, encoding="utf-8")
    elif args.json:
        sys.stdout.buffer.write(render_json_multi(reports).encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
    else:
        stdout_console = make_console(stderr=False, no_color=args.no_color)
        if stdout_console.is_terminal:
            if len(reports) > 1:
                print_summary_table(stdout_console, reports)
            else:
                print_report(stdout_console, reports[0])
        else:
            # Not print(): a scanned skill's own description/findings can contain
            # arbitrary Unicode (em dashes, non-English text, ...), and the console's
            # default encoding (e.g. cp1252 on Windows) can't represent all of it —
            # print() would crash the whole scan over the skill's own text content.
            output = render_markdown_multi(reports)
            sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")

    # Always written, independent of --html/-o/--json: those give explicit
    # control over one output for scripting, this gives every format as a
    # standing artifact without needing to remember a flag (mirrors medusa's
    # .medusa/reports/ convention). A write failure (read-only CWD in some CI
    # setups) is a warning, not a scan failure — the real result above already
    # printed successfully.
    try:
        reports_dir = Path(".skilltrace") / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        auto_html = reports_dir / f"skilltrace-scan-{stamp}.html"
        auto_json = reports_dir / f"skilltrace-scan-{stamp}.json"
        auto_md = reports_dir / f"skilltrace-scan-{stamp}.md"
        auto_html.write_text(render_html_multi(reports), encoding="utf-8")
        auto_json.write_text(render_json_multi(reports), encoding="utf-8")
        auto_md.write_text(render_markdown_multi(reports), encoding="utf-8")
        print_reports_generated(stderr_console, html=str(auto_html), json=str(auto_json), markdown=str(auto_md))
    except OSError as exc:
        print_warning(stderr_console, f"could not write auto-generated reports: {exc}")

    findings_by_severity = Counter(f.severity for r in reports for f in r.findings)
    print_scan_complete(
        stderr_console,
        skills_scanned=len(reports),
        files_scanned=total_files_scanned,
        findings_by_severity=findings_by_severity,
        elapsed_s=time.time() - start_time,
        animation_s=animation_time_s,
    )

    if args.fail_threshold:
        threshold = Severity(args.fail_threshold)
        if any(r.risk_level.rank >= threshold.rank for r in reports):
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows picks the console's ambient codepage (often cp1252) for stdout/stderr
    # regardless of the source file's own UTF-8 encoding — an em-dash then encodes
    # as a single cp1252 byte that's invalid UTF-8, rendering as mojibake on any
    # UTF-8 terminal. Force UTF-8 so output is correct independent of the caller's
    # environment. errors="replace" (not the reconfigure default of "strict") keeps
    # this crash-safe for the same reason the -o/--json byte-write path below is:
    # scanned skill content can contain arbitrary Unicode. Guarded: test doubles
    # for sys.stdout may lack reconfigure().
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    # -h/--help exits during parser.parse_args() below, before args.no_color
    # exists — a raw argv pre-scan is the only way to make --no-color affect
    # --help output too. Always (re)assigned, not just when --no-color is
    # present: RichHelpFormatter.console is a class attribute, so leaving a
    # prior no-color override in place would leak into later main() calls in
    # the same process (e.g. across tests) that didn't pass --no-color.
    argv_list = list(sys.argv[1:]) if argv is None else list(argv)
    no_color = "--no-color" in argv_list
    RichHelpFormatter.console = Console(no_color=True, color_system=None) if no_color else Console()

    parser = _build_arg_parser(no_color=no_color)
    args = parser.parse_args(argv)

    # After parse_args(): -h/--help exits during parsing, so this naturally
    # never prints before help text.
    if not args.quiet:
        maybe_print_banner(make_console(stderr=True, no_color=args.no_color))

    if args.command == "scan":
        return _run_scan(args)

    print_welcome(make_console(stderr=False, no_color=args.no_color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
