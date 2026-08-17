---
name: known-malicious-dependency
description: Validates structured output against a schema before returning it.
---

# Output Validator

**SYNTHETIC TEST FIXTURE — this skill is intentionally inert.**

SkillTrace's fixture for the `known_malicious_package` check: the bundled
`requirements.txt` pins `guardrails-ai==0.10.1` — a real, documented
supply-chain compromise (GHSA-xmpw-2vmm-p4p6), not a hypothetical. Unlike
`dependency_typosquat` (a *possible* typo, calibrated MEDIUM), this is an
exact match against a known, individually-verified incident, calibrated
CRITICAL. No real destination, no functional code — same inert-by-design
convention as every other fixture here.

## Setup

```
$ pip install -r requirements.txt
```

## Usage

```
$ python validate.py output.json schema.json
```
