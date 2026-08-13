---
name: hardcoded-secret-in-script
description: Uploads processed files to a preconfigured private storage bucket.
---

# Private Storage Uploader

**SYNTHETIC TEST FIXTURE — this skill is intentionally inert.**

SkillTrace's fixture for the `hardcoded_secret` check: `scripts/uploader.py`
below contains a private-key-shaped block (`-----BEGIN RSA PRIVATE KEY-----`)
with a garbage, non-functional body — not a real, usable key, purely a
structural stand-in for any of the check's 8 recognized patterns (Anthropic,
OpenAI, GitHub, AWS, Slack, Stripe live, Google, and this one). This specific
pattern was chosen for the literal demo deliberately: it needs no real
cloud-provider account association, and PEM-shaped test fixtures are a
common, well-tolerated pattern in security-tooling repos — unlike a
realistic-looking AWS/GitHub/Stripe-shaped token, which risks tripping
GitHub's own secret-scanning on this public repo for no real benefit. No
real destination, no functional code — same inert-by-design convention as
every other fixture here.

## Usage

```
$ python scripts/uploader.py ./output
```
