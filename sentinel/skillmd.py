"""Parse SKILL.md and discover a skill's bundled files."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?\n)---\s*\n?(.*)", re.DOTALL)

SCRIPT_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".rb", ".pl"}

USAGE_HEADING_RE = re.compile(r"^#{1,6}\s*(usage|examples?)\b", re.IGNORECASE)
FENCED_CODE_RE = re.compile(r"```(?:[\w+-]*)\n(.*?)```", re.DOTALL)
SHELL_PROMPT_RE = re.compile(r"^\s*\$\s+(.+)$", re.MULTILINE)

# Doc-style fill-in-the-blank placeholders (<owner>, __REPO__, {baseDir}) are
# never valid literal shell/URL syntax — running them as-is either fails
# immediately (a "sandbox broke" false alarm) or, worse, resolves against the
# sandbox's own DNS sinkhole and gets logged as a real network_request finding
# for a URL that was never actually reachable. ${VAR} is deliberately not
# matched here — real shell env-var expansion, ambiguous whether the author
# meant it literally. Found independently twice during the launch scan
# (baoyu-skills' "${BUN_X} {baseDir}/scripts/main.ts", punkscience/agent-skills'
# "https://__OWNER__.github.io/__REPO__/apt/__KEYRING__").
PLACEHOLDER_TOKEN_RE = re.compile(r"<[A-Za-z_][\w-]*>|__[A-Z][A-Z0-9_]*__|(?<!\$)\{[A-Za-z_]\w*\}")


# Dot-directories that are *conventional install locations* for real,
# independently-installable skills across various agent tools (Claude Code,
# other agent CLIs, Gemini, Cursor, Codex, OpenClaw), as opposed to VCS
# internals / CI mirrors / build output. Found via snyk-labs/toxicskills-goof
# (a third-party security research sample): every skill in that repo —
# including the actual malicious demo — lives under .agents/skills/ or
# .gemini/skills/, both blanket-excluded by the original "skip all dot-dirs"
# rule. That rule was right for .git/, .github/, .codex-marketplace/ (VCS/CI/
# mirror content) and wrong for these — a real, evidence-based correction, not
# a broadening for its own sake.
KNOWN_SKILL_INSTALL_DIRS = {".claude", ".agents", ".gemini", ".cursor", ".codex", ".openclaw", ".clawhub"}

# Conventional test-scaffolding directory names, not real skill collections.
# A SKILL.md that lives here belongs to some other project's own test suite -
# e.g. a coding-agent package's own .../test/fixtures/skills/invalid-yaml/
# SKILL.md, deliberately malformed to test *its* parser's error handling, is
# never something a real agent loads. Treating it as a scan candidate did
# nothing but produce a "malformed YAML" warning about content that was never
# meant to be valid — noise repeated on every repo that vendors that package.
TEST_SCAFFOLDING_DIR_NAMES = {"test", "tests", "__tests__", "fixtures", "testdata", "spec", "__mocks__"}

# Standard, independently-documented credential-file conventions — .env
# (dotenv/12-factor), .npmrc (npm's own auth-token docs), .pypirc (twine/PyPI
# upload credentials), .netrc (curl(1)/git basic-auth) — carved out of the
# blanket dot-exclusion below so a real hardcoded secret sitting in one of
# these isn't invisible to the scanner. Unlike KNOWN_SKILL_INSTALL_DIRS, this
# isn't from a specific skill found during this project's own scan; it's the
# standard credential-file surface these tools document themselves. See
# discover_bundled_files()'s executable/shebang guard for why this carve-out
# doesn't also open a way to hide an actual script behind one of these names.
KNOWN_SECRET_DOTFILES = {".env", ".npmrc", ".pypirc", ".netrc"}


def has_shebang(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


class SkillMdNotFoundError(Exception):
    """Raised when a candidate skill directory has no SKILL.md."""

    def __init__(self, skill_dir: Path):
        super().__init__(
            f"No SKILL.md found in {skill_dir}. "
            "SkillTrace expects an agent skill directory (Claude, Cursor, or Codex) "
            "containing a SKILL.md file."
        )
        self.skill_dir = skill_dir


class SkillMdParseError(Exception):
    """Raised when SKILL.md's YAML frontmatter is present but malformed."""


def _yaml_error_summary(exc: yaml.YAMLError) -> str:
    """PyYAML's str() on a parse error is its own multi-line snippet-plus-caret
    block (context line, quoted source excerpt, `^` pointer, repeated for a
    second mark) - fine in isolation, but dumped into a scrolling per-skill
    progress log via print_warning it reads like a crash. Collapse it to the
    one line a user actually needs: what went wrong and where."""
    problem = getattr(exc, "problem", None)
    if problem is None:
        # Some YAMLError subtypes don't set problem/problem_mark - fall back to
        # a single-line version of the full message rather than a bare repr.
        return " ".join(str(exc).split())
    context = getattr(exc, "context", None)
    summary = "; ".join(part for part in (context, problem) if part)
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        summary += f" (line {mark.line + 1})"
    return summary


@dataclass
class SkillMetadata:
    name: str | None
    description: str | None
    license: str | None
    allowed_tools: list | None
    # Drives skill *activation* matching but, unlike description, is never shown
    # in a skill-picker UI — invisible-instruction attacks hide here instead of
    # in description (HiddenLayer research, "What's the matter with Skills",
    # 2026-07-09).
    when_to_use: str | None
    # Cursor-specific: scopes auto-invocation to files matching these globs
    # (cursor.com/docs/skills). Absent on Claude/Codex skills, harmlessly None.
    paths: object
    raw_frontmatter: dict
    body: str
    path: Path


def _split_tool_tokens(text: str) -> list[str]:
    """Split on whitespace, except inside a scoped grant's parens — a real
    documented shape (found in a real skill-registry's own AGENTS.md/
    CONTRIBUTING.md during this project's launch scan) is a single
    space-separated string of multiple tool names, e.g. "Read Write Edit
    Bash" — treating that whole string as one opaque token would silently
    miss an unscoped Bash grant hiding among several space-separated tools.
    A scoped grant can legitimately contain its own internal space (e.g.
    "Bash(git commit -m:*)"), which must stay one token, not get shredded."""
    tokens: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch.isspace() and depth == 0:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def normalize_allowed_tools(raw: object) -> list[str]:
    """allowed-tools is commonly a YAML list, but a single space-separated
    string (possibly naming several tools at once) is also a real documented
    shape — tolerate both rather than silently dropping either."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return _split_tool_tokens(raw)
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    return []


def normalize_paths(raw: object) -> list[str]:
    """Cursor's `paths` field is documented as a comma-separated string or a
    list (cursor.com/docs/skills) — tolerate both, same as allowed-tools."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [p.strip() for p in raw.split(",") if p.strip()]
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    return []


def find_skill_md_file(skill_dir: Path) -> Path | None:
    """Case-insensitive lookup — found "skill.md" (lowercase) used in the wild
    by a real skill in snyk-labs/toxicskills-goof, plausibly specifically to
    evade tools that hardcode the exact-case "SKILL.md" filename."""
    if not skill_dir.is_dir():
        return None
    for entry in skill_dir.iterdir():
        if entry.is_file() and entry.name.lower() == "skill.md":
            return entry
    return None


def parse_skill_md(skill_dir: Path) -> SkillMetadata:
    """Read and parse <skill_dir>/SKILL.md's (case-insensitive) YAML frontmatter
    and body."""
    skill_md_path = find_skill_md_file(skill_dir)
    if skill_md_path is None:
        raise SkillMdNotFoundError(skill_dir)

    text = skill_md_path.read_text(encoding="utf-8", errors="replace")
    match = FRONTMATTER_RE.match(text)

    if match is None:
        # No frontmatter delimiters at all — tolerate it as metadata-less.
        return SkillMetadata(
            name=None,
            description=None,
            license=None,
            allowed_tools=None,
            when_to_use=None,
            paths=None,
            raw_frontmatter={},
            body=text,
            path=skill_md_path,
        )

    frontmatter_text, body = match.group(1), match.group(2)
    try:
        raw_frontmatter = yaml.safe_load(frontmatter_text) or {}
    except yaml.YAMLError as exc:
        raise SkillMdParseError(
            f"Malformed YAML frontmatter in {skill_md_path}: {_yaml_error_summary(exc)}"
        ) from exc

    if not isinstance(raw_frontmatter, dict):
        raise SkillMdParseError(
            f"Expected a YAML mapping for frontmatter in {skill_md_path}, got {type(raw_frontmatter).__name__}"
        )

    return SkillMetadata(
        name=raw_frontmatter.get("name"),
        description=raw_frontmatter.get("description"),
        license=raw_frontmatter.get("license"),
        allowed_tools=raw_frontmatter.get("allowed-tools") or raw_frontmatter.get("allowed_tools"),
        when_to_use=raw_frontmatter.get("when-to-use") or raw_frontmatter.get("when_to_use"),
        paths=raw_frontmatter.get("paths"),
        raw_frontmatter=raw_frontmatter,
        body=body,
        path=skill_md_path,
    )


def discover_skill_directories(root: Path) -> list[Path]:
    """Find every directory under root that directly contains a SKILL.md
    (case-insensitive), skipping hidden/dot directories — except the known
    agent-tool skill-install conventions (KNOWN_SKILL_INSTALL_DIRS), which are
    real installed-skill locations, not VCS/CI/build-artifact noise — and
    skipping conventional test-scaffolding directories (TEST_SCAFFOLDING_DIR_NAMES),
    which hold some other project's own test fixtures, not real skills.

    Most repos are a single skill (SKILL.md at root, returned as a 1-item list).
    Some are collections — one repo bundling many skills, each in its own
    subdirectory — and have no root SKILL.md at all; without this, those are
    invisible to the scanner entirely.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d
            for d in dirnames
            if (not d.startswith(".") or d in KNOWN_SKILL_INSTALL_DIRS)
            and d.lower() not in TEST_SCAFFOLDING_DIR_NAMES
        ]
        if any(f.lower() == "skill.md" for f in filenames):
            found.append(Path(dirpath))
    return sorted(found)


@dataclass
class BundledFile:
    path: Path
    relative_path: str
    is_script: bool
    is_executable: bool


def discover_bundled_files(skill_dir: Path) -> list[BundledFile]:
    """Walk skill_dir's visible surface (excluding SKILL.md and dotfiles/dot-dirs,
    with one narrow exception below), classifying scripts vs. resources.

    Dot-prefixed paths are deliberately excluded here — that's the skill's normal,
    visible inventory. Hidden paths are a separate signal handled by
    heuristics.scan_for_hidden_executable_content(). Exception: a leaf file whose
    exact name is a known credential-dotfile convention (KNOWN_SECRET_DOTFILES) is
    treated as bundled — but only when it's neither executable nor shebang'd, so a
    script disguised behind one of these names still falls through to the
    hidden-executable check untouched.
    """
    results: list[BundledFile] = []
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file():
            continue
        # .lower(): a lowercase "skill.md" is still the skill's own root file
        # (see find_skill_md_file) — without case-insensitivity here, it'd be
        # treated as an ordinary bundled file and scanned twice.
        if path.name.lower() == "skill.md" and path.parent == skill_dir:
            continue
        # .as_posix(), not str(): these paths get shell-quoted and run inside a
        # Linux container. A bare str() gives backslash separators on Windows
        # hosts (e.g. "scripts\\format.py"), which isn't a valid path on Linux —
        # the candidate silently fails to open the real file instead of testing it.
        relative_path = path.relative_to(skill_dir).as_posix()
        parts = Path(relative_path).parts
        if any(part.startswith(".") for part in parts[:-1]):
            continue
        is_executable = bool(path.stat().st_mode & 0o111)
        if path.name.startswith(".") and (
            path.name.lower() not in KNOWN_SECRET_DOTFILES or is_executable or has_shebang(path)
        ):
            continue
        is_script = path.suffix in SCRIPT_EXTENSIONS or is_executable
        results.append(
            BundledFile(
                path=path,
                relative_path=relative_path,
                is_script=is_script,
                is_executable=is_executable,
            )
        )
    return results


def extract_usage_examples(body: str) -> list[str]:
    """Pull example invocation commands out of SKILL.md's own Usage/Examples section."""
    examples: list[str] = []

    lines = body.splitlines()
    in_usage_section = False
    section_lines: list[str] = []
    for line in lines:
        if line.startswith("#"):
            if USAGE_HEADING_RE.match(line):
                in_usage_section = True
                continue
            elif in_usage_section:
                break
        if in_usage_section:
            section_lines.append(line)

    section_text = "\n".join(section_lines)
    if not section_text:
        return examples

    for code_block in FENCED_CODE_RE.findall(section_text):
        for line in code_block.splitlines():
            line = line.strip()
            prompt_match = SHELL_PROMPT_RE.match(line)
            if prompt_match:
                line = prompt_match.group(1).strip()
            if line and not line.startswith("#") and not PLACEHOLDER_TOKEN_RE.search(line):
                examples.append(line)

    # De-duplicate while preserving order.
    seen = set()
    deduped = []
    for example in examples:
        if example not in seen:
            seen.add(example)
            deduped.append(example)
    return deduped
