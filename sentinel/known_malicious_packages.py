"""Curated, version-pinned known-malicious package incidents.

Every entry is sourced from a real, human-reviewed GitHub Security Advisory
(github.com/advisories, `type: reviewed`) — not from memory — so each is
independently verifiable via its GHSA ID. Deliberately small and hand-picked,
same character as heuristics.POPULAR_PYPI_PACKAGES/POPULAR_NPM_PACKAGES: not
a bulk import of GHSA's full `type:malware` corpus (~46,000 npm+pip entries
as of 2026-08, overwhelmingly automated typosquat/dependency-confusion spam
caught within hours) or OpenSSF's malicious-packages database (235,000+
reports across all ecosystems, same character) — both are the wrong shape
for a hand-curated, individually-explained list.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnownMaliciousPackage:
    # None means every published version is malicious (a compromised abandoned
    # name, or a pure namesquat vehicle with no legitimate release ever) -
    # matches on name alone. Otherwise matches only an exact pinned version
    # equal to one of these - never the bare name, so a name later
    # re-registered by an unrelated legitimate maintainer won't match.
    versions: frozenset[str] | None
    advisory: str


KNOWN_MALICIOUS_PACKAGES: dict[tuple[str, str], KnownMaliciousPackage] = {
    ("npm", "event-stream"): KnownMaliciousPackage(frozenset({"3.3.6"}), "GHSA-mh6f-8j2x-4483"),
    ("npm", "flatmap-stream"): KnownMaliciousPackage(None, "GHSA-mh6f-8j2x-4483"),
    ("npm", "ua-parser-js"): KnownMaliciousPackage(
        frozenset({"0.7.29", "0.8.0", "1.0.0"}), "GHSA-pjwm-rvh2-c87w"
    ),
    ("npm", "coa"): KnownMaliciousPackage(
        frozenset({"2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"}), "GHSA-73qr-pfmq-6rp8"
    ),
    ("npm", "rc"): KnownMaliciousPackage(frozenset({"1.2.9", "1.3.9", "2.3.9"}), "GHSA-g2q5-5433-rhrf"),
    ("npm", "node-ipc"): KnownMaliciousPackage(frozenset({"10.1.1", "10.1.2"}), "GHSA-97m3-w2cp-4xx6"),
    ("npm", "eslint-config-prettier"): KnownMaliciousPackage(
        frozenset({"8.10.1", "9.1.1", "10.1.6", "10.1.7"}), "GHSA-f29h-pxvx-f335"
    ),
    ("npm", "eslint-plugin-prettier"): KnownMaliciousPackage(
        frozenset({"4.2.2", "4.2.3"}), "GHSA-f29h-pxvx-f335"
    ),
    ("npm", "synckit"): KnownMaliciousPackage(frozenset({"0.11.9"}), "GHSA-f29h-pxvx-f335"),
    ("npm", "@pkgr/core"): KnownMaliciousPackage(frozenset({"0.2.8"}), "GHSA-f29h-pxvx-f335"),
    ("npm", "napi-postinstall"): KnownMaliciousPackage(frozenset({"0.3.1"}), "GHSA-f29h-pxvx-f335"),
    ("npm", "got-fetch"): KnownMaliciousPackage(frozenset({"5.1.11", "5.1.12"}), "GHSA-f29h-pxvx-f335"),
    ("PyPI", "ctx"): KnownMaliciousPackage(None, "GHSA-67r3-h899-9w95, GHSA-4g82-3jcr-q52w"),
    ("PyPI", "guardrails-ai"): KnownMaliciousPackage(frozenset({"0.10.1"}), "GHSA-xmpw-2vmm-p4p6"),
    ("PyPI", "mistralai"): KnownMaliciousPackage(frozenset({"2.4.6"}), "GHSA-wx9m-wx4f-4cmg"),
    ("PyPI", "telnyx"): KnownMaliciousPackage(frozenset({"4.87.1", "4.87.2"}), "GHSA-955r-262c-33jc"),
    ("PyPI", "litellm"): KnownMaliciousPackage(frozenset({"1.82.7", "1.82.8"}), "GHSA-5mg7-485q-xm76"),
    ("PyPI", "spam"): KnownMaliciousPackage(frozenset({"2.0.2", "4.0.2"}), "GHSA-2r6g-7r83-jg72"),
    ("PyPI", "exotel"): KnownMaliciousPackage(frozenset({"0.1.6"}), "GHSA-x6xg-3fj2-4pq3"),
    ("PyPI", "cipherbcrypt"): KnownMaliciousPackage(None, "GHSA-5grr-72f9-678v"),
}
