"""Docker CLI orchestration: builds the sandbox image, runs a skill inside it,
and parses the strace/dnsmasq/mitmproxy logs it produces.

Shells out to the `docker` CLI rather than using the docker-py SDK — the CLI
is the already-installed dependency, per docs/SPEC.md.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.allowlist import is_benign_path
from sentinel.skillmd import BundledFile, extract_usage_examples

DOCKER_DIR = Path(__file__).resolve().parent.parent / "docker"
IMAGE_TAG = "skilltrace-sandbox"

INTERPRETER_BY_SUFFIX = {
    ".py": "python3",
    ".js": "node",
    ".sh": "sh",
}


class SentinelError(Exception):
    """Base class for sentinel's own operational errors (as opposed to bugs)."""


class DockerUnavailableError(SentinelError):
    pass


class SandboxTimeoutError(SentinelError):
    def __init__(self, timeout_s: int):
        super().__init__(f"Skill did not finish running inside the sandbox within {timeout_s}s")
        self.timeout_s = timeout_s


def ensure_docker_available() -> None:
    if shutil.which("docker") is None:
        raise DockerUnavailableError(
            "The `docker` command was not found on PATH. SkillTrace's sandbox "
            "requires Docker — install it from https://docs.docker.com/get-docker/ "
            "and make sure `docker` is on your PATH. Or skip the sandbox entirely: "
            "add --static for a Docker-free static-only scan."
        )
    result = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode != 0:
        raise DockerUnavailableError(
            "Docker is installed but the daemon isn't reachable (`docker info` failed). "
            "Make sure the Docker daemon is running (e.g. start Docker Desktop, or "
            "`sudo systemctl start docker` on Linux) and that your user can access it. "
            "Or skip the sandbox entirely: add --static for a Docker-free static-only scan.\n"
            f"docker info said: {result.stderr.strip()}"
        )


def _docker_dir_hash(docker_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(docker_dir.rglob("*")):
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def build_sandbox_image(docker_dir: Path = DOCKER_DIR, tag: str = IMAGE_TAG) -> str:
    """Build (or reuse a cached build of) the sandbox image. Returns the tag used."""
    content_hash = _docker_dir_hash(docker_dir)
    tagged = f"{tag}:{content_hash}"

    inspect = subprocess.run(
        ["docker", "image", "inspect", tagged], capture_output=True, text=True
    )
    if inspect.returncode == 0:
        return tagged

    cmd = ["docker", "build", "-t", tagged, str(docker_dir)]
    result = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode != 0:
        raise SentinelError(f"Failed to build the sandbox image:\n{result.stderr}")
    return tagged


def resolve_skill_source(path_or_url: str, workdir: Path) -> Path:
    """Return a local directory for the skill: clones path_or_url if it looks like a
    git URL, otherwise treats it as an existing local path."""
    if re.match(r"^(https?://|git@|ssh://)", path_or_url):
        dest = workdir / "skill-source"
        result = subprocess.run(
            ["git", "clone", "--depth", "1", path_or_url, str(dest)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            raise SentinelError(f"Failed to clone {path_or_url}:\n{result.stderr}")
        return dest

    local_path = Path(path_or_url).expanduser().resolve()
    if not local_path.is_dir():
        raise SentinelError(f"{local_path} is not a directory")
    return local_path


# --- invocation candidates -------------------------------------------------


def build_invocation_candidates(
    skill_dir: Path,
    bundled_files: list[BundledFile],
    skill_body: str,
    invoke_cmd: str | None,
    max_candidates: int = 5,
) -> list[str]:
    """No-args, --invoke, and SKILL.md usage examples — run all applicable ones,
    since each is a different chance to trigger load-time/import-time behavior."""
    candidates: list[str] = []

    if invoke_cmd:
        candidates.append(invoke_cmd)

    candidates.extend(extract_usage_examples(skill_body))

    for bundled_file in bundled_files:
        if not bundled_file.is_script:
            continue
        # A file under a templates/ directory is explicitly signaling "not meant
        # to run as-is" — found containing a literal, unresolved placeholder URL
        # (templates/install.sh, punkscience/agent-skills) that produced a
        # nonsensical network_request finding when run directly. Content-level
        # placeholder detection (PLACEHOLDER_TOKEN_RE, skillmd.py) only covers
        # SKILL.md's own usage examples, not arbitrary bundled file contents.
        if "templates" in Path(bundled_file.relative_path).parts[:-1]:
            continue
        interpreter = INTERPRETER_BY_SUFFIX.get(bundled_file.path.suffix)
        if interpreter:
            candidates.append(f"{interpreter} {shlex.quote(bundled_file.relative_path)}")
        elif bundled_file.is_executable:
            candidates.append(f"./{shlex.quote(bundled_file.relative_path)}")

    seen = set()
    deduped = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            deduped.append(candidate)
    return deduped[:max_candidates]


# --- running the sandbox ----------------------------------------------------


@dataclass
class StraceEvent:
    pid: str
    timestamp: str
    syscall: str
    raw_args: str
    result: str


@dataclass
class DnsQuery:
    timestamp: str
    qtype: str
    name: str
    answer: str


@dataclass
class HttpFlow:
    kind: str
    host: str | None = None
    port: int | None = None
    method: str | None = None
    path: str | None = None
    headers: dict = field(default_factory=dict)
    body_base64: str = ""
    body_truncated: bool = False
    status_code: int | None = None
    sni: str | None = None
    timestamp: float | None = None


@dataclass
class SandboxRunResult:
    invocation: str
    exit_code: int | None
    timed_out: bool
    strace_events: list[StraceEvent]
    dns_queries: list[DnsQuery]
    http_flows: list[HttpFlow]


STRACE_LINE_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<timestamp>\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<rest>.*)$"
)
STRACE_CALL_RE = re.compile(r"^(?P<syscall>\w+)\((?P<args>.*)\)\s*=\s*(?P<result>.*)$")
STRACE_UNFINISHED_RE = re.compile(r"^(?P<syscall>\w+)\((?P<args>.*)\s*<unfinished \.\.\.>$")
STRACE_RESUMED_RE = re.compile(r"^<\.\.\. (?P<syscall>\w+) resumed>(?P<rest>.*)$")


def parse_strace_log(path: Path) -> list[StraceEvent]:
    """Parse strace -f -tt output, stitching <unfinished ...>/<... resumed> pairs
    (which -f interleaving produces) back into single events per pid."""
    if not path.is_file():
        return []

    events: list[StraceEvent] = []
    pending: dict[str, tuple[str, str, str]] = {}  # pid -> (timestamp, syscall, partial_args)

    for line in path.read_text(errors="replace").splitlines():
        match = STRACE_LINE_RE.match(line)
        if not match:
            continue
        pid, timestamp, rest = match.group("pid"), match.group("timestamp"), match.group("rest")

        resumed = STRACE_RESUMED_RE.match(rest)
        if resumed:
            prior = pending.pop(pid, None)
            if prior is None:
                continue
            prior_timestamp, syscall, partial_args = prior
            call_match = re.match(r"^(?P<args>.*)\)\s*=\s*(?P<result>.*)$", resumed.group("rest"))
            if call_match:
                events.append(
                    StraceEvent(
                        pid=pid,
                        timestamp=prior_timestamp,
                        syscall=syscall,
                        raw_args=partial_args + call_match.group("args"),
                        result=call_match.group("result"),
                    )
                )
            continue

        unfinished = STRACE_UNFINISHED_RE.match(rest)
        if unfinished:
            pending[pid] = (timestamp, unfinished.group("syscall"), unfinished.group("args"))
            continue

        call = STRACE_CALL_RE.match(rest)
        if call:
            events.append(
                StraceEvent(
                    pid=pid,
                    timestamp=timestamp,
                    syscall=call.group("syscall"),
                    raw_args=call.group("args"),
                    result=call.group("result"),
                )
            )

    return events


def strace_connect_events(events: list[StraceEvent]) -> list[StraceEvent]:
    return [
        e
        for e in events
        if e.syscall == "connect" and ("AF_INET" in e.raw_args)
    ]


def strace_execve_events(events: list[StraceEvent]) -> list[StraceEvent]:
    return [e for e in events if e.syscall == "execve"]


EXECVE_PATH_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"')


def _execve_path(raw_args: str) -> str:
    match = EXECVE_PATH_RE.match(raw_args)
    return match.group(1) if match else raw_args


def strace_notable_execve_events(events: list[StraceEvent], invocation: str) -> list[StraceEvent]:
    """Successful execve calls beyond the sandbox's own harness and the declared
    invocation itself, a skill spawning something it wasn't asked to run.

    Two layers are always present and are never skill behavior. docker/entrypoint.sh
    traces `sh -c "<invocation>"` directly as the container's CMD, so the first
    successful execve is always that wrapper; the next is always sh forking or
    exec-replacing into the declared invocation itself. Confirmed against real
    sandbox runs (not assumed): both showed up in that exact order with no
    leading noise before the wrapper. Failed execve attempts (result starting
    "-1") are dropped first, since a plain subprocess.run(["echo", ...]) generates
    one failed attempt per PATH directory tried before the one that succeeds,
    which would otherwise quadruple-count a single logical spawn.

    If a candidate's first whitespace token doesn't match what actually got
    exec'd (an unusual invocation shape, e.g. one with a leading env var
    assignment), the declared invocation itself can show up as a false-positive
    finding here rather than being silently swallowed, the safer failure mode
    for a security tool.
    """
    successful = [e for e in strace_execve_events(events) if not e.result.startswith("-1")]
    if not successful:
        return []
    successful = successful[1:]

    first_token = invocation.split()[0] if invocation.strip() else None
    expected_name = posixpath.basename(first_token) if first_token else None
    if successful and expected_name and posixpath.basename(_execve_path(successful[0].raw_args)) == expected_name:
        successful = successful[1:]

    return successful


PACKAGE_BOUNDARY_FILES = {"/package.json", "/pyproject.toml"}


def _is_package_boundary_probe(path: str, result: str) -> bool:
    """Node's module resolver walks every ancestor directory above cwd looking for
    the nearest package.json (package-boundary / ESM "type" detection); Python's
    packaging tools (setuptools/poetry/uv/tomllib-based project-root detection)
    do the same for pyproject.toml. Both fire on essentially any node/python
    invocation, not something the skill did. WORKDIR is always /skill, so the
    only such probe landing outside /skill is the root-level lookup, and it's
    always ENOENT (the sandbox image ships neither file at /). Only the failed
    probe is allowlisted — a real, present file outside /skill would still be
    notable. Found independently for both files during the launch scan.
    """
    return path in PACKAGE_BOUNDARY_FILES and "ENOENT" in result


def strace_notable_openat_events(events: list[StraceEvent]) -> list[StraceEvent]:
    notable = []
    for e in events:
        path_match = re.match(r'^AT_FDCWD,\s*"([^"]*)"', e.raw_args)
        if not path_match:
            continue
        raw_path = path_match.group(1)
        if not raw_path.startswith("/"):
            # AT_FDCWD-relative: the traced process's cwd is always /skill (the
            # container's WORKDIR), so resolve against that before judging scope.
            # Without this, a plain in-skill read like "sample.txt" gets flagged
            # as "outside the skill's own directory" purely because the literal
            # string doesn't start with /skill/ — a false positive on the tool's
            # own "should scan clean" example. A path that escapes via ../.. still
            # normalizes outside /skill and is correctly flagged (path traversal).
            raw_path = posixpath.normpath(posixpath.join("/skill", raw_path))
        if is_benign_path(raw_path):
            continue
        if _is_package_boundary_probe(raw_path, e.result):
            continue
        notable.append(e)
    return notable


DNSMASQ_QUERY_RE = re.compile(
    r"query\[(?P<qtype>\w+)\]\s+(?P<name>\S+)\s+from\s+\S+"
)
DNSMASQ_ANSWER_RE = re.compile(r"(?:config|reply)\s+(?P<name>\S+)\s+is\s+(?P<answer>\S+)")


def parse_dnsmasq_log(path: Path) -> list[DnsQuery]:
    if not path.is_file():
        return []

    queries: list[DnsQuery] = []
    pending_name: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        query_match = DNSMASQ_QUERY_RE.search(line)
        if query_match:
            pending_name[query_match.group("name")] = query_match.group("qtype")
            queries.append(
                DnsQuery(
                    timestamp=line.split(" ", 1)[0] if " " in line else "",
                    qtype=query_match.group("qtype"),
                    name=query_match.group("name"),
                    answer="",
                )
            )
            continue
        answer_match = DNSMASQ_ANSWER_RE.search(line)
        if answer_match and queries:
            for q in reversed(queries):
                if q.name == answer_match.group("name") and not q.answer:
                    q.answer = answer_match.group("answer")
                    break
    return queries


def parse_mitm_log(path: Path) -> list[HttpFlow]:
    if not path.is_file():
        return []

    flows: list[HttpFlow] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Tolerate a truncated last line (e.g. the container was killed on timeout).
            continue
        flows.append(
            HttpFlow(
                kind=record.get("kind", "unknown"),
                host=record.get("host"),
                port=record.get("port"),
                method=record.get("method"),
                path=record.get("path"),
                headers=record.get("headers", {}),
                body_base64=record.get("body_base64", ""),
                body_truncated=record.get("body_truncated", False),
                status_code=record.get("status_code"),
                sni=record.get("sni"),
                timestamp=record.get("timestamp"),
            )
        )
    return flows


# --- top-level orchestration -------------------------------------------------

DEFAULT_TIMEOUT_S = 60


# A container's default hostname is docker's own randomized hex ID, nothing
# like a real machine. --differential's "varied" pass overrides it to something
# a real desktop/CI box would plausibly have, plus one interactive-session env
# var (TERM, unset by default since `docker run` here has no pseudo-TTY) that's
# a common, well-documented sandbox-vs-real-environment check target. Not meant
# to defeat a determined, deliberate evasion check (see the README's roadmap),
# just cheap enough to catch a skill that branches on the most obvious signals.
DIFFERENTIAL_HOSTNAME = "build-worker-04"
DIFFERENTIAL_ENV = {"TERM": "xterm-256color", "SSH_CONNECTION": "10.0.0.5 52341 10.0.0.2 22"}

# The baseline pass's resource limits (below) are deliberately tight, a real
# sandbox/CI box's usual footprint. A skill checking os.cpu_count() or
# /proc/meminfo and only acting up once resources look like a real desktop
# is the same class of check hostname/env above catches — --differential's
# "varied" pass gives it that desktop-plausible headroom instead.
DIFFERENTIAL_CPUS = "4"
DIFFERENTIAL_MEMORY = "8g"
DIFFERENTIAL_PIDS_LIMIT = "4096"


def run_skill_in_sandbox(
    skill_dir: Path,
    candidates: list[str],
    allow_network: bool = False,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    image_tag: str | None = None,
    hostname: str | None = None,
    env_overrides: dict[str, str] | None = None,
    cpus: str = "1",
    memory: str = "512m",
    pids_limit: str = "256",
) -> list[SandboxRunResult]:
    """Run each invocation candidate in its own container lifetime, each with its
    own strace pass, and return one SandboxRunResult per candidate.

    hostname/env_overrides/cpus/memory/pids_limit exist for --differential's
    second, "varied" pass; left unset, every run uses docker's own default
    hostname, no extra env, and the tight default resource limits below."""
    ensure_docker_available()
    tag = image_tag or build_sandbox_image()

    results: list[SandboxRunResult] = []
    for candidate in candidates:
        results.append(
            _run_one_candidate(
                skill_dir, candidate, tag, allow_network, timeout_s,
                hostname, env_overrides, cpus, memory, pids_limit,
            )
        )
    return results


def _run_one_candidate(
    skill_dir: Path,
    candidate: str,
    tag: str,
    allow_network: bool,
    timeout_s: int,
    hostname: str | None = None,
    env_overrides: dict[str, str] | None = None,
    cpus: str = "1",
    memory: str = "512m",
    pids_limit: str = "256",
) -> SandboxRunResult:
    container_name = f"sentinel-run-{uuid.uuid4().hex[:12]}"
    skill_dir = skill_dir.resolve()
    # tempfile.gettempdir(), not a hardcoded "/tmp/...": an unresolved driveless
    # Path("/tmp/...") stringifies without a drive letter on Windows (e.g.
    # "\tmp\foo"), which Docker Desktop can't bind-mount — the container ends up
    # writing its logs nowhere the host can see, and every run looks silently
    # clean instead of erroring.
    scratch_dir = Path(tempfile.gettempdir()) / f"sentinel-scratch-{uuid.uuid4().hex[:12]}"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--init",  # real PID 1 (tini); see docker/entrypoint.sh for why this matters
        "--name",
        container_name,
        "--cap-add=SYS_PTRACE",
        f"--memory={memory}",
        f"--pids-limit={pids_limit}",
        f"--cpus={cpus}",
        "-v",
        f"{skill_dir}:/skill:ro",
        "-v",
        f"{scratch_dir}:/scratch:rw",
    ]

    if hostname:
        docker_cmd += ["--hostname", hostname]
    for key, value in (env_overrides or {}).items():
        docker_cmd += ["-e", f"{key}={value}"]

    if allow_network:
        # No sinkhole, no interception — strace still runs, but there is no
        # decrypted host/path/body for this run (documented tradeoff of
        # --allow-network: it opts into real egress for deeper testing).
        docker_cmd += ["--network", "bridge"]
    else:
        docker_cmd += ["--network", "none", "--cap-add=NET_ADMIN"]

    docker_cmd += [tag, "sh", "-c", candidate]

    timed_out = False
    exit_code: int | None = None
    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    strace_events = parse_strace_log(scratch_dir / "strace.log")
    dns_queries = parse_dnsmasq_log(scratch_dir / "dnsmasq.log")
    http_flows = parse_mitm_log(scratch_dir / "mitm.log")

    shutil.rmtree(scratch_dir, ignore_errors=True)

    return SandboxRunResult(
        invocation=candidate,
        exit_code=exit_code,
        timed_out=timed_out,
        strace_events=strace_events,
        dns_queries=dns_queries,
        http_flows=http_flows,
    )
