"""Merge static heuristics + sandbox findings into a Markdown/JSON report with
a risk score — framed as "what a skill actually did" vs. "what it claims to do"."""

from __future__ import annotations

import base64
import html
import importlib.metadata
import json
import posixpath
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sentinel.findings import Confidence, Finding, Severity
from sentinel.sandbox import (
    SandboxRunResult,
    SentinelError,
    strace_connect_events,
    strace_notable_execve_events,
    strace_notable_openat_events,
)
from sentinel.skillmd import SkillMetadata, normalize_allowed_tools

# Explicit, auditable weights — used to compute a single numeric score on top
# of the per-finding severities, so two reports are comparable at a glance.
SEVERITY_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 15,
}

SECRET_LOOKING_RE_PARTS = ("key", "token", "secret", "password", "credential", "api_key")

# Findings that come from reading file content, not from running the skill —
# grouped under "Static red flags" in both the Markdown and HTML renderers.
STATIC_FINDING_CATEGORIES = (
    "base64_blob",
    "eval_exec_decode",
    "hidden_executable",
    "skill_md_exfil_instruction",
    "skill_md_remote_exec_instruction",
    "skill_md_decode_exec_instruction",
    "frontmatter_broad_tool_grant",
    "frontmatter_sensitive_path_scope",
    "hidden_unicode_content",
    "hardcoded_secret",
    "dependency_typosquat",
)

# Confidence: how certain the detection method itself is (deterministic AST/regex
# match vs. a probabilistic entropy check vs. LLM judgment), not how bad the
# finding is if true. MITRE ATT&CK technique IDs are omitted ("") for categories
# that are scan-infrastructure diagnostics (sandbox_timeout, sandbox_no_trace_data,
# sandbox_not_attempted, no_skill_md, tls_handshake_failed) or LLM judgment (semantic_review):
# no real attacker TTP maps cleanly onto either, and a stretched mapping would be
# less honest than none.
CATEGORY_METADATA: dict[str, tuple[Confidence, str]] = {
    "base64_blob": (Confidence.MEDIUM, "T1027"),
    "eval_exec_decode": (Confidence.HIGH, "T1140"),
    "hidden_executable": (Confidence.HIGH, "T1564.001"),
    "skill_md_decode_exec_instruction": (Confidence.HIGH, "T1140"),
    "skill_md_remote_exec_instruction": (Confidence.MEDIUM, "T1059"),
    "skill_md_exfil_instruction": (Confidence.HIGH, "T1041"),
    "frontmatter_broad_tool_grant": (Confidence.MEDIUM, "T1059"),
    "frontmatter_sensitive_path_scope": (Confidence.MEDIUM, "T1552.001"),
    "hidden_unicode_content": (Confidence.HIGH, "T1027"),
    "hardcoded_secret": (Confidence.HIGH, "T1552.001"),
    "dependency_typosquat": (Confidence.MEDIUM, "T1195.001"),
    "sandbox_timeout": (Confidence.HIGH, ""),
    "sandbox_no_trace_data": (Confidence.HIGH, ""),
    "sandbox_not_attempted": (Confidence.HIGH, ""),
    "no_skill_md": (Confidence.HIGH, ""),
    "network_request": (Confidence.HIGH, "T1041"),
    "tls_handshake_failed": (Confidence.MEDIUM, ""),
    "out_of_scope_file_access": (Confidence.HIGH, "T1005"),
    "unexpected_subprocess": (Confidence.HIGH, "T1059"),
    "differential_behavior_change": (Confidence.MEDIUM, "T1497"),
    "network_connection": (Confidence.LOW, "T1071"),
    "semantic_review": (Confidence.MEDIUM, ""),
}

# Plain-language names for what each category means, used to tell a reader
# what specifically was flagged (see risk_guidance()) instead of leaving them
# to decode category slugs like "skill_md_remote_exec_instruction" themselves.
FINDING_CATEGORY_LABELS: dict[str, str] = {
    "base64_blob": "long base64-looking strings",
    "eval_exec_decode": "exec()/eval() of decoded content",
    "hidden_executable": "a hidden executable file",
    "skill_md_remote_exec_instruction": "instructions to pipe a remote download into a shell",
    "skill_md_exfil_instruction": "instructions to exfiltrate data",
    "skill_md_decode_exec_instruction": "instructions to decode and execute content",
    "frontmatter_broad_tool_grant": "an overly broad tool grant",
    "frontmatter_sensitive_path_scope": "declared access to sensitive file paths",
    "hidden_unicode_content": "invisible/bidi Unicode characters hidden in skill text",
    "hardcoded_secret": "a hardcoded credential/API key",
    "dependency_typosquat": "a possibly typosquatted dependency",
    "network_request": "unexpected outbound network requests",
    "network_connection": "unexpected outbound connection attempts",
    "out_of_scope_file_access": "file access outside the skill's own directory",
    "unexpected_subprocess": "an unexpected subprocess",
    "tls_handshake_failed": "a failed TLS handshake (possible certificate pinning)",
    "sandbox_timeout": "a sandbox timeout",
    "sandbox_no_trace_data": "a sandbox run that produced no trace data",
    "sandbox_not_attempted": "no dynamic behavior observed",
    "no_skill_md": "no SKILL.md found",
    "differential_behavior_change": "behavior that changed under different sandbox conditions",
    "semantic_review": "a concern flagged by semantic instruction review",
}

# Below this many near-identical findings (same directory for file opens, same
# method+host+path for network requests), list each individually — still useful
# detail. At or above it, collapse into one finding — otherwise a bulk/retry
# operation (a self-installer copying its own N bundled files to ~/.claude/
# skills/<name>/; pip retrying the same blocked URL after the sandbox's network
# sinkhole) emits one finding per event. Found on real skills during the launch
# scan: 3388 near-identical file-access findings inflated one score to 23719 —
# nonsensically above any genuine hidden_executable/exfil finding — while also
# making the report unreadable.
NEAR_DUPLICATE_THRESHOLD = 3

NOT_CHECKED_STATIC_ONLY = "Not checked (--static)."

OPENAT_PATH_RE = re.compile(r'^AT_FDCWD,\s*"([^"]*)"')


def _openat_path(raw_args: str) -> str:
    match = OPENAT_PATH_RE.match(raw_args)
    return match.group(1) if match else raw_args


EXECVE_PATH_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"')


def _execve_command_name(raw_args: str) -> str:
    match = EXECVE_PATH_RE.match(raw_args)
    path = match.group(1) if match else raw_args
    return posixpath.basename(path)


EXECVE_PATH_AND_ARGV_RE = re.compile(r'^(".*?",\s*\[.*?\])')


def _execve_path_and_argv(raw_args: str) -> str:
    """Path + argv only, dropping the trailing envp pointer/var-count. Used for
    --differential's signature, not the near-duplicate grouping above: the two
    runs intentionally carry a different env var count (DIFFERENTIAL_ENV adds
    two), so including that count would make every execve look different
    between runs regardless of what the skill actually did."""
    match = EXECVE_PATH_AND_ARGV_RE.match(raw_args)
    return match.group(1) if match else raw_args


def _body_looks_like_secret(body_base64: str) -> bool:
    try:
        decoded = base64.b64decode(body_base64).decode("utf-8", errors="ignore").lower()
    except Exception:
        return False
    return any(part in decoded for part in SECRET_LOOKING_RE_PARTS)


def sandbox_result_findings(result: SandboxRunResult) -> list[Finding]:
    """Turn one sandboxed run's raw observations into report-ready Findings."""
    findings: list[Finding] = []
    source = f"invocation: {result.invocation}"

    if result.timed_out:
        findings.append(
            Finding(
                category="sandbox_timeout",
                severity=Severity.MEDIUM,
                summary=f"`{result.invocation}` did not finish within the sandbox timeout",
                source=source,
            )
        )
    elif not result.strace_events:
        # Zero events at all (not even the traced process's own execve) almost
        # always means the trace never actually captured anything — a broken
        # mount, a container that failed to start, etc. — not a skill that
        # legitimately did nothing. Surfacing this distinctly matters: without
        # it, a broken sandbox and a genuinely clean run render identically.
        findings.append(
            Finding(
                category="sandbox_no_trace_data",
                severity=Severity.HIGH,
                summary=f"`{result.invocation}` produced no trace data at all — the sandbox "
                "likely failed to run rather than the skill being clean; treat this result as "
                "inconclusive, not as a clean bill of health",
                source=source,
            )
        )

    by_request: dict[tuple, list] = {}
    for flow in result.http_flows:
        if flow.kind != "http_request":
            continue
        by_request.setdefault((flow.method, flow.host, flow.path), []).append(flow)

    for (method, host, path), flows in by_request.items():
        looks_secret = any(_body_looks_like_secret(f.body_base64) for f in flows)
        secret_suffix = " (request body looks like it may contain a secret)" if looks_secret else ""
        if len(flows) < NEAR_DUPLICATE_THRESHOLD:
            for flow in flows:
                flow_looks_secret = _body_looks_like_secret(flow.body_base64)
                findings.append(
                    Finding(
                        category="network_request",
                        severity=Severity.CRITICAL if flow_looks_secret else Severity.HIGH,
                        summary=f"{flow.method} https://{flow.host}{flow.path}"
                        + (" (request body looks like it may contain a secret)" if flow_looks_secret else ""),
                        detail=f"headers={flow.headers}",
                        source=source,
                        extra={"host": flow.host, "path": flow.path, "body_base64": flow.body_base64},
                    )
                )
        else:
            findings.append(
                Finding(
                    category="network_request",
                    severity=Severity.CRITICAL if looks_secret else Severity.HIGH,
                    summary=f"{method} https://{host}{path} ({len(flows)}x — likely retried after "
                    f"the sandbox's network sinkhole){secret_suffix}",
                    detail=f"headers={flows[0].headers}",
                    source=source,
                    extra={"host": host, "path": path, "body_base64": flows[0].body_base64},
                )
            )

    for flow in result.http_flows:
        if flow.kind == "tls_handshake_failed":
            findings.append(
                Finding(
                    category="tls_handshake_failed",
                    severity=Severity.MEDIUM,
                    summary=f"TLS handshake failed for SNI={flow.sni} (possible certificate pinning)",
                    source=source,
                )
            )

    by_directory: dict[str, list] = {}
    for event in strace_notable_openat_events(result.strace_events):
        directory = posixpath.dirname(_openat_path(event.raw_args))
        by_directory.setdefault(directory, []).append(event)

    for directory, group in by_directory.items():
        if len(group) < NEAR_DUPLICATE_THRESHOLD:
            for event in group:
                findings.append(
                    Finding(
                        category="out_of_scope_file_access",
                        severity=Severity.HIGH,
                        summary=f"Opened a file outside the skill's own directory: {event.raw_args}",
                        source=source,
                    )
                )
        else:
            sample = ", ".join(_openat_path(e.raw_args) for e in group[:3])
            findings.append(
                Finding(
                    category="out_of_scope_file_access",
                    severity=Severity.HIGH,
                    summary=f"Opened {len(group)} files outside the skill's own directory, all "
                    f"under `{directory}/` (e.g. {sample}, ...)",
                    source=source,
                )
            )

    by_command: dict[str, list] = {}
    for event in strace_notable_execve_events(result.strace_events, result.invocation):
        by_command.setdefault(_execve_command_name(event.raw_args), []).append(event)

    for command_name, group in by_command.items():
        if len(group) < NEAR_DUPLICATE_THRESHOLD:
            for event in group:
                findings.append(
                    Finding(
                        category="unexpected_subprocess",
                        severity=Severity.MEDIUM,
                        summary=f"Spawned a subprocess beyond the invoked command: {command_name}",
                        detail=event.raw_args,
                        source=source,
                    )
                )
        else:
            findings.append(
                Finding(
                    category="unexpected_subprocess",
                    severity=Severity.MEDIUM,
                    summary=f"Spawned {command_name} {len(group)}x, beyond the invoked command",
                    source=source,
                )
            )

    observed_hosts = {f.host for f in result.http_flows if f.host}
    raw_connects = strace_connect_events(result.strace_events)
    if raw_connects and not observed_hosts:
        # A connect() attempt strace saw but mitmproxy never turned into a
        # flow — e.g. a hardcoded-IP attempt that skipped DNS and never
        # completed a handshake mitmproxy could decrypt.
        findings.append(
            Finding(
                category="network_connection",
                severity=Severity.MEDIUM,
                summary=f"{len(raw_connects)} outbound network connection attempt(s) observed "
                "with no decrypted request captured",
                source=source,
            )
        )

    return findings


def sandbox_result_signature(result: SandboxRunResult) -> frozenset:
    """A normalized, comparable summary of what one sandbox run actually did,
    used by --differential to spot a skill that behaves differently between two
    runs of the same candidate under different-looking conditions. Built from
    the same extraction functions sandbox_result_findings() uses, at a higher
    level than raw strace_events, which vary run-to-run on PIDs and timestamps
    alone, even for a totally deterministic skill."""
    signature: set = set()

    for flow in result.http_flows:
        if flow.kind == "http_request":
            signature.add(("network", flow.method, flow.host, flow.path))

    for event in strace_notable_openat_events(result.strace_events):
        directory = posixpath.dirname(_openat_path(event.raw_args))
        signature.add(("file", directory))

    for event in strace_notable_execve_events(result.strace_events, result.invocation):
        signature.add(("subprocess", _execve_path_and_argv(event.raw_args)))

    return frozenset(signature)


def diff_sandbox_results(baseline: SandboxRunResult, varied: SandboxRunResult) -> list[Finding]:
    """Compare a candidate's default-conditions run against the same candidate
    re-run with a different hostname/env (--differential, see sandbox.py's
    DIFFERENTIAL_HOSTNAME/DIFFERENTIAL_ENV). Behavior that shows up in only one
    of the two runs is the signal real sandbox-evasion checks produce: a skill
    branching on what it detects about its environment, rather than doing the
    same thing regardless of it. Either direction is reported: "worse when it
    looks like a real machine" is the classic case, but "worse specifically
    under the default sandbox signature" is the same underlying signal viewed
    from the other side."""
    baseline_sig = sandbox_result_signature(baseline)
    varied_sig = sandbox_result_signature(varied)
    source = f"invocation: {baseline.invocation}"

    findings = []
    for kind, *detail in sorted(varied_sig - baseline_sig):
        findings.append(
            Finding(
                category="differential_behavior_change",
                severity=Severity.MEDIUM,
                summary=f"Only observed when hostname/env were varied, not under the default "
                f"sandbox conditions: {kind} {' '.join(str(d) for d in detail)}",
                source=source,
            )
        )
    for kind, *detail in sorted(baseline_sig - varied_sig):
        findings.append(
            Finding(
                category="differential_behavior_change",
                severity=Severity.MEDIUM,
                summary=f"Only observed under the default sandbox conditions, not when "
                f"hostname/env were varied: {kind} {' '.join(str(d) for d in detail)}",
                source=source,
            )
        )
    return findings


@dataclass
class Report:
    skill_path: str
    skill_name: str | None
    skill_description: str | None
    findings: list[Finding]
    risk_score: int
    risk_level: Severity
    invocations: list[str]
    generated_at: float = field(default_factory=time.time)
    semantic_review_ran: bool = False
    sandbox_ran: bool = False
    allowed_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "skill_path": self.skill_path,
            "skill_name": self.skill_name,
            "skill_description": self.skill_description,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "invocations": self.invocations,
            "generated_at": self.generated_at,
            "semantic_review_ran": self.semantic_review_ran,
            "sandbox_ran": self.sandbox_ran,
            "allowed_tools": self.allowed_tools,
            "findings": [f.to_dict() for f in self.findings],
        }


def load_prior_reports(path: Path) -> list[dict]:
    """Load a --compare-to file: a single-skill scan's JSON is a bare dict
    (render_json), a collection scan's is a list (render_json_multi) — always
    return a list so callers don't need to know which."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SentinelError(f"Could not read --compare-to file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SentinelError(f"--compare-to file {path} is not valid JSON: {exc}") from exc
    return data if isinstance(data, list) else [data]


def match_prior_reports(current_reports: list[Report], prior_reports: list[dict]) -> dict[int, dict]:
    """Maps each index in current_reports to its matching prior report dict.

    Matched by skill_name, the one identifier stable across two separate
    git-clone runs of the same skill (skill_path is a fresh temp directory
    every time resolve_skill_source clones a URL, see sandbox.py). If both
    this run and the prior file scanned exactly one skill, they're paired
    unconditionally regardless of name — covers the common single-skill scan
    even when a skill declares no name at all."""
    if len(current_reports) == 1 and len(prior_reports) == 1:
        return {0: prior_reports[0]}
    prior_by_name = {p["skill_name"]: p for p in prior_reports if p.get("skill_name")}
    return {
        i: prior_by_name[r.skill_name]
        for i, r in enumerate(current_reports)
        if r.skill_name and r.skill_name in prior_by_name
    }


def _normalize_source(source: str, skill_path: str) -> str:
    """Strip a Finding's own skill_path prefix so two separate scans of the
    same skill (e.g. two git-clone temp dirs) produce a comparable source
    instead of two different absolute paths. Non-path sources ("sandbox",
    "invocation: ...") aren't under skill_path and pass through unchanged."""
    try:
        return str(Path(source).relative_to(Path(skill_path)))
    except ValueError:
        return source


def _finding_signature(finding: dict, skill_path: str) -> tuple:
    return (finding["category"], _normalize_source(finding.get("source", ""), skill_path), finding["summary"])


@dataclass
class ReportComparison:
    new_findings: list[Finding]
    resolved_count: int
    prior_generated_at: float


def compare_to_prior(current: Report, prior: dict) -> ReportComparison:
    """Diff current's findings against a prior scan of the same skill (see
    match_prior_reports), matched by _finding_signature rather than raw
    equality so a re-scan of a git-sourced skill doesn't report every
    finding as "new" just because the temp clone path changed."""
    prior_sigs = {_finding_signature(f, prior.get("skill_path", "")) for f in prior.get("findings", [])}
    current_dicts = [f.to_dict() for f in current.findings]
    current_sigs = {_finding_signature(f, current.skill_path) for f in current_dicts}

    new_findings = [
        f
        for f, d in zip(current.findings, current_dicts)
        if _finding_signature(d, current.skill_path) not in prior_sigs
    ]
    resolved_count = len(prior_sigs - current_sigs)
    return ReportComparison(
        new_findings=new_findings,
        resolved_count=resolved_count,
        prior_generated_at=prior.get("generated_at", 0.0),
    )


def compute_risk(findings: list[Finding]) -> tuple[int, Severity]:
    if not findings:
        return 0, Severity.LOW
    score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    level = max((f.severity for f in findings), key=lambda s: s.rank)
    return score, level


def collection_risk(reports: list[Report]) -> Report:
    """The single riskiest skill in a multi-skill scan — summing scores across
    dozens/hundreds of skills would scale with collection size rather than with
    how bad any one skill actually is, so "overall" here means worst-case, the
    same reasoning NEAR_DUPLICATE_THRESHOLD above uses to avoid inflated totals."""
    return max(reports, key=lambda r: (r.risk_level.rank, r.risk_score))


def _join_with_and(items: list[str], limit: int = 4) -> str:
    if len(items) > limit:
        items = items[:limit] + [f"{len(items) - limit} more"]
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f", and {items[-1]}"


_RISK_LEVEL_VERDICT = {
    Severity.LOW: "this skill looks safe to use",
    Severity.MEDIUM: "worth a human look before you trust this skill, but nothing found should block normal use",
    Severity.HIGH: "review these findings before trusting this skill with real data or credentials — not "
    "confirmed safe to use",
    Severity.CRITICAL: "do not use this skill until these findings have been investigated",
}

# Categories that describe a gap in what could be checked, not something the
# skill actually did - same distinction CATEGORY_METADATA's own comment above
# already draws (no ATT&CK technique maps onto scan-infrastructure diagnostics).
# A report with only these must not read as "flagged" the same way a real
# finding does - "no dynamic behavior observed" is "we don't have data",
# not "we found something bad".
DIAGNOSTIC_CATEGORIES = {
    "sandbox_timeout",
    "sandbox_no_trace_data",
    "sandbox_not_attempted",
    "no_skill_md",
    "tls_handshake_failed",
}

# Purpose-built per-category explanations — a single generic "static checks
# only" trailer was factually wrong for most of these: sandbox_not_attempted,
# sandbox_timeout, sandbox_no_trace_data, and tls_handshake_failed only ever
# fire on a full (non-static) scan where the sandbox WAS attempted, each for
# a different reason. Only actually say "static" where that's what happened.
DIAGNOSTIC_EXPLANATIONS = {
    "sandbox_not_attempted": "no bundled script, --invoke flag, or usage example was found to run, "
    "so dynamic behavior wasn't observed",
    "sandbox_timeout": "the sandboxed run didn't finish within the timeout, so this result is "
    "inconclusive rather than a clean pass",
    "sandbox_no_trace_data": "the sandbox produced no trace data, so this result is inconclusive "
    "rather than a clean pass",
    "no_skill_md": "no SKILL.md was found, so this doesn't look like a real agent skill",
    "tls_handshake_failed": "a TLS handshake failed during the scan (possibly certificate pinning), "
    "so that connection's traffic couldn't be inspected",
}


def _labels_for(findings: list[Finding]) -> str:
    labels = sorted({FINDING_CATEGORY_LABELS.get(f.category, f.category.replace("_", " ")) for f in findings})
    return _join_with_and(labels)


def risk_guidance(report: Report) -> str:
    """One line naming what actually drove the risk verdict and stating,
    plainly, whether the skill looks safe to use — a bare "MEDIUM (3)" or an
    unlabeled findings table leaves the reader to work both of those out for
    themselves."""
    if not report.findings:
        return "No concerning behavior found — this skill looks safe to use."
    real_findings = [f for f in report.findings if f.category not in DIAGNOSTIC_CATEGORIES]
    if not real_findings:
        categories = sorted({f.category for f in report.findings})
        explanations = [DIAGNOSTIC_EXPLANATIONS.get(c, "coverage was limited") for c in categories]
        verdict = _RISK_LEVEL_VERDICT[report.risk_level]
        return f"No malicious behavior found — {'; '.join(explanations)}. {verdict[0].upper()}{verdict[1:]}."
    return f"Flagged for {_labels_for(real_findings)} — {_RISK_LEVEL_VERDICT[report.risk_level]}."


def build_report(
    skill_dir: Path,
    metadata: SkillMetadata,
    heuristic_findings: list[Finding],
    sandbox_results: list[SandboxRunResult] | None,
    invocations: list[str],
    semantic_review_ran: bool = False,
    sandbox_ran: bool = False,
) -> Report:
    all_findings = list(heuristic_findings)
    for result in sandbox_results or []:
        all_findings.extend(sandbox_result_findings(result))

    for f in all_findings:
        f.confidence, f.mitre_technique = CATEGORY_METADATA.get(f.category, (Confidence.MEDIUM, ""))

    score, level = compute_risk(all_findings)

    return Report(
        skill_path=str(skill_dir),
        skill_name=metadata.name,
        skill_description=metadata.description,
        findings=all_findings,
        risk_score=score,
        risk_level=level,
        invocations=invocations,
        semantic_review_ran=semantic_review_ran,
        sandbox_ran=sandbox_ran,
        allowed_tools=normalize_allowed_tools(metadata.allowed_tools),
    )


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def _confidence_suffix(f: Finding) -> str:
    if f.mitre_technique:
        return f" _(confidence: {f.confidence.value} · ATT&CK {f.mitre_technique})_"
    return f" _(confidence: {f.confidence.value})_"


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# SkillTrace report: {report.skill_name or report.skill_path}")
    lines.append("")
    if report.skill_description:
        lines.append(f"> {report.skill_description}")
        lines.append("")
    lines.append(f"**Risk score:** {report.risk_score} ({report.risk_level.value.upper()})")
    lines.append("")
    lines.append(f"_{risk_guidance(report)}_")
    lines.append("")
    lines.append(f"**Invocations attempted:** {', '.join(f'`{i}`' for i in report.invocations) or '(none)'}")
    lines.append("")
    lines.append(
        f"**Pre-authorized tools (allowed-tools):** "
        f"{', '.join(f'`{t}`' for t in report.allowed_tools) or '(none declared)'}"
    )
    lines.append("")

    network_findings = [f for f in report.findings if f.category in ("network_request", "network_connection")]
    lines.append("## Network activity")
    if network_findings:
        for f in network_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}{_confidence_suffix(f)}")
    else:
        lines.append("- No network activity observed." if report.sandbox_ran else f"- {NOT_CHECKED_STATIC_ONLY}")
    lines.append("")

    subprocess_findings = [
        f
        for f in report.findings
        if f.category in ("sandbox_timeout", "sandbox_no_trace_data", "sandbox_not_attempted", "unexpected_subprocess")
    ]
    lines.append("## Subprocess / execution")
    if subprocess_findings:
        for f in subprocess_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}{_confidence_suffix(f)}")
    else:
        lines.append("- Nothing unusual observed." if report.sandbox_ran else f"- {NOT_CHECKED_STATIC_ONLY}")
    lines.append("")

    file_findings = [f for f in report.findings if f.category == "out_of_scope_file_access"]
    lines.append("## Out-of-scope file access")
    if file_findings:
        for f in file_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}{_confidence_suffix(f)}")
    else:
        lines.append(
            "- No file access outside the skill's own directory observed."
            if report.sandbox_ran
            else f"- {NOT_CHECKED_STATIC_ONLY}"
        )
    lines.append("")

    static_findings = [f for f in report.findings if f.category in STATIC_FINDING_CATEGORIES]
    lines.append("## Static red flags")
    if static_findings:
        for f in static_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}{_confidence_suffix(f)} ({f.source})")
    else:
        lines.append("- None found.")
    lines.append("")

    semantic_findings = [f for f in report.findings if f.category == "semantic_review"]
    lines.append("## Semantic / instruction review")
    if semantic_findings:
        for f in semantic_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}{_confidence_suffix(f)}")
            if f.detail:
                lines.append(f'  > "{f.detail}"')
    elif report.semantic_review_ran:
        lines.append("- Ran, nothing found.")
    else:
        lines.append("- Not run (use `--semantic-review`, requires `ANTHROPIC_API_KEY`).")
    lines.append("")

    other_findings = [
        f
        for f in report.findings
        if f
        not in network_findings + subprocess_findings + file_findings + static_findings + semantic_findings
    ]
    if other_findings:
        lines.append("## Other findings")
        for f in other_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}{_confidence_suffix(f)}")
        lines.append("")

    return "\n".join(lines)


def render_json_multi(reports: list[Report]) -> str:
    """A repo with one skill renders identically to render_json(); a collection
    repo (multiple SKILL.md subdirectories, see skillmd.discover_skill_directories)
    renders as a JSON array instead of silently reporting only the first one."""
    if len(reports) == 1:
        return render_json(reports[0])
    return json.dumps([r.to_dict() for r in reports], indent=2)


def render_markdown_multi(reports: list[Report]) -> str:
    if len(reports) == 1:
        return render_markdown(reports[0])
    worst = collection_risk(reports)
    header = (
        f"# SkillTrace: {len(reports)} skills found in this repository\n\n"
        f"**Overall risk score:** {worst.risk_score} ({worst.risk_level.value.upper()}, driven by "
        f"{worst.skill_name or worst.skill_path})\n\n"
        f"_{risk_guidance(worst)}_"
    )
    parts = [header]
    parts.extend(render_markdown(r) for r in reports)
    return "\n\n---\n\n".join(parts)


# --- HTML rendering ---------------------------------------------------------
#
# Self-contained: no CDN/external assets, so the file works offline and as a
# CI artifact. Everything embedded here (skill names/descriptions, syscall
# args, semantic-review quotes) ultimately comes from a scanned skill's own,
# potentially adversarial, content — html.escape() every dynamic value rather
# than trust it, or a malicious skill's own text becomes a stored-XSS payload
# in the very report meant to warn about it.

SEVERITY_COLOR = {
    "low": "#4caf50",
    "medium": "#e8a300",
    "high": "#ff8f00",
    "critical": "#e53935",
}

PROJECT_URL = "https://github.com/handcraftedbygod/SkillTrace"


def _package_version() -> str:
    # Not sentinel.__version__: that's a hand-maintained string in
    # __init__.py that's drifted out of sync with pyproject.toml before
    # (see sentinel.console's own _package_version, which this mirrors
    # rather than imports — importing from console would be circular,
    # since console.py already imports from this module).
    try:
        return importlib.metadata.version("skilltrace")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


# Hardcoded dark, not `color-scheme: light dark` deferring to the OS/browser
# — a report opened on an otherwise light-themed machine rendered fully
# white, clashing with every other SkillTrace surface (terminal, demo/README
# screenshots), which are all dark. GitHub-dark-ish palette, both because
# it reads well and because it matches the project's own GitHub presence
# linked from the masthead below.
HTML_STYLE = """<style>
  :root {
    color-scheme: dark;
    --bg: #0d1117;
    --bg-alt: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --link: #58a6ff;
  }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; max-width: 900px;
         margin: 2rem auto; padding: 0 1rem 3rem; line-height: 1.5;
         background: var(--bg); color: var(--text); }
  a { color: var(--link); }
  h1 { font-size: 1.6rem; margin-bottom: .25rem; }
  h2 { font-size: 1.25rem; border-bottom: 1px solid var(--border); padding-bottom: .25rem; }
  h3 { font-size: 1rem; margin-bottom: .5rem; }
  .masthead { color: var(--text-dim); font-size: .85rem; margin: 0 0 1.5rem; }
  .masthead a { color: var(--text-dim); text-decoration: none; font-weight: 600; }
  .masthead a:hover { color: var(--link); }
  .risk-badge { display: inline-block; color: #fff; font-weight: 700; padding: .25rem .75rem;
                border-radius: .25rem; margin: .5rem 0; }
  .stats { margin: .75rem 0 1.25rem; }
  .finding { border-left: 4px solid #888; padding: .5rem .75rem; margin: .5rem 0;
             background: var(--bg-alt); border: 1px solid var(--border); border-left-width: 4px;
             border-radius: 0 .25rem .25rem 0; }
  .badge { display: inline-block; color: #fff; font-size: .75rem; font-weight: 700;
           padding: .1rem .4rem; border-radius: .2rem; margin-right: .5rem; }
  .detail { font-family: ui-monospace, monospace; font-size: .85rem; margin-top: .25rem;
            color: var(--text-dim); word-break: break-all; }
  .source { font-size: .8rem; color: var(--text-dim); margin-top: .25rem; }
  .empty { color: var(--text-dim); font-style: italic; }
  .description { color: var(--text-dim); }
  .invocations code { background: var(--bg-alt); border: 1px solid var(--border);
                       padding: .1rem .3rem; border-radius: .2rem; }
  table.summary { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  table.summary th, table.summary td { text-align: left; padding: .4rem .6rem;
                                        border-bottom: 1px solid var(--border); }
  table.summary th { color: var(--text-dim); font-weight: 600; }
  table.summary tbody tr:hover { background: var(--bg-alt); }
  details { border: 1px solid var(--border); border-radius: .25rem; margin: .5rem 0; padding: 0 .75rem; }
  details > summary { cursor: pointer; font-weight: 600; padding: .5rem 0; }
</style>"""


def _finding_html(f: Finding) -> str:
    color = SEVERITY_COLOR[f.severity.value]
    detail = f'<div class="detail">{html.escape(f.detail)}</div>' if f.detail else ""
    source = f'<div class="source">{html.escape(f.source)}</div>' if f.source else ""
    confidence_text = f"confidence: {html.escape(f.confidence.value)}"
    if f.mitre_technique:
        confidence_text += f" &middot; ATT&amp;CK {html.escape(f.mitre_technique)}"
    confidence = f'<div class="source">{confidence_text}</div>'
    return (
        f'<div class="finding" style="border-left-color:{color}">'
        f'<span class="badge" style="background:{color}">{f.severity.value.upper()}</span>'
        f"{html.escape(f.summary)}{detail}{source}{confidence}</div>"
    )


def _section_html(title: str, findings: list[Finding], empty_message: str) -> str:
    body = "".join(_finding_html(f) for f in findings) if findings else f'<p class="empty">{empty_message}</p>'
    return f"<section><h3>{html.escape(title)}</h3>{body}</section>"


def _report_body_html(report: Report) -> str:
    network = [f for f in report.findings if f.category in ("network_request", "network_connection")]
    subprocess_findings = [
        f
        for f in report.findings
        if f.category in ("sandbox_timeout", "sandbox_no_trace_data", "sandbox_not_attempted", "unexpected_subprocess")
    ]
    file_findings = [f for f in report.findings if f.category == "out_of_scope_file_access"]
    static_findings = [f for f in report.findings if f.category in STATIC_FINDING_CATEGORIES]
    semantic_findings = [f for f in report.findings if f.category == "semantic_review"]
    other_findings = [
        f
        for f in report.findings
        if f not in network + subprocess_findings + file_findings + static_findings + semantic_findings
    ]

    semantic_empty = "Ran, nothing found." if report.semantic_review_ran else "Not run (use --semantic-review)."
    not_checked = NOT_CHECKED_STATIC_ONLY
    description = f'<p class="description">{html.escape(report.skill_description)}</p>' if report.skill_description else ""
    invocations = ", ".join(f"<code>{html.escape(i)}</code>" for i in report.invocations) or "(none)"
    allowed_tools = ", ".join(f"<code>{html.escape(t)}</code>" for t in report.allowed_tools) or "(none declared)"
    risk_color = SEVERITY_COLOR[report.risk_level.value]

    sections = [
        _section_html("Network activity", network, "No network activity observed." if report.sandbox_ran else not_checked),
        _section_html(
            "Subprocess / execution", subprocess_findings, "Nothing unusual observed." if report.sandbox_ran else not_checked
        ),
        _section_html(
            "Out-of-scope file access",
            file_findings,
            "No file access outside the skill's own directory observed." if report.sandbox_ran else not_checked,
        ),
        _section_html("Static red flags", static_findings, "None found."),
        _section_html("Semantic / instruction review", semantic_findings, semantic_empty),
    ]
    if other_findings:
        sections.append(_section_html("Other findings", other_findings, ""))

    return (
        f"{description}"
        f'<div class="risk-badge" style="background:{risk_color}">'
        f"{report.risk_level.value.upper()} ({report.risk_score})</div>"
        f'<p class="description">{html.escape(risk_guidance(report))}</p>'
        f'<p class="invocations">Invocations attempted: {invocations}</p>'
        f'<p class="invocations">Pre-authorized tools (allowed-tools): {allowed_tools}</p>'
        f"{''.join(sections)}"
    )


def _masthead_html(reports: list[Report]) -> str:
    generated = datetime.fromtimestamp(reports[0].generated_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        '<p class="masthead">'
        f'<a href="{PROJECT_URL}">\U0001f6e1️ SkillTrace</a> '
        f"v{html.escape(_package_version())} &middot; generated {generated}"
        "</p>"
    )


def _severity_stats_html(reports: list[Report]) -> str:
    counts = Counter(r.risk_level for r in reports)
    chips = "".join(
        f'<span class="badge" style="background:{SEVERITY_COLOR[level.value]}">{counts[level]} {level.value.upper()}</span>'
        for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if counts[level]
    )
    return f'<p class="stats">{chips}</p>'


def render_html(report: Report) -> str:
    return render_html_multi([report])


def render_html_multi(reports: list[Report]) -> str:
    """A repo with one skill renders as a single full report; a collection repo
    renders a summary table plus a collapsible <details> section per skill —
    plain HTML, no JavaScript, so it still works as a static CI artifact."""
    masthead = _masthead_html(reports)
    if len(reports) == 1:
        r = reports[0]
        title = r.skill_name or r.skill_path
        body = f"<h1>{html.escape(title)}</h1>{masthead}{_report_body_html(r)}"
    else:
        title = f"SkillTrace: {len(reports)} skills"
        worst = collection_risk(reports)
        overall_risk = (
            f'<div class="risk-badge" style="background:{SEVERITY_COLOR[worst.risk_level.value]}">'
            f"Overall: {worst.risk_level.value.upper()} ({worst.risk_score}), driven by "
            f"{html.escape(worst.skill_name or worst.skill_path)}</div>"
            f'<p class="description">{html.escape(risk_guidance(worst))}</p>'
            f"{_severity_stats_html(reports)}"
        )
        # Worst-first, matching collection_risk's own sort key: a reviewer
        # opening this report wants the riskiest skills at the top of both
        # the table and the <details> list, not buried in discovery order.
        ranked = sorted(reports, key=lambda r: (r.risk_level.rank, r.risk_score), reverse=True)
        rows = "".join(
            f"<tr><td>{html.escape(r.skill_name or r.skill_path)}</td>"
            f'<td><span class="badge" style="background:{SEVERITY_COLOR[r.risk_level.value]}">'
            f"{r.risk_level.value.upper()}</span></td><td>{r.risk_score}</td></tr>"
            for r in ranked
        )
        summary_table = (
            '<table class="summary"><thead><tr><th>Skill</th><th>Risk</th><th>Score</th></tr>'
            f"</thead><tbody>{rows}</tbody></table>"
        )
        details = "".join(
            f"<details{' open' if r is ranked[0] else ''}><summary>{html.escape(r.skill_name or r.skill_path)} — "
            f"{r.risk_level.value.upper()} ({r.risk_score})</summary>{_report_body_html(r)}</details>"
            for r in ranked
        )
        body = f"<h1>{html.escape(title)}</h1>{masthead}{overall_risk}{summary_table}{details}"

    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(title)}</title>{HTML_STYLE}</head><body>{body}</body></html>"
    )
