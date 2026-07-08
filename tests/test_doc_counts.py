"""Single-source-of-truth guard for the headline numbers in public docs.

A security tool whose whole pitch is "don't trust me, read the regexes" loses
all credibility the moment a reader greps and finds the count is wrong. These
tests pin the one number the README states about the code (the vendor secret
pattern count) so prose and implementation can never silently drift apart
(audit #5/#31/#44). The audit-entry and test counts are intentionally phrased
durably in the docs ("32k+", "1030") and are not asserted here, since they
move every run and a brittle assertion would be worse than the drift.
"""

from __future__ import annotations

import re
from pathlib import Path

from nota import secrets

REPO_ROOT = Path(__file__).resolve().parent.parent

# The canonical count of vendor-format secret patterns. If you add or remove a
# pattern in secrets._PATTERNS, this is the single place the new number is
# recorded, and the README assertion below proves the prose was updated too.
EXPECTED_VENDOR_PATTERN_COUNT = 26


def test_vendor_pattern_count_is_pinned() -> None:
    assert len(secrets._PATTERNS) == EXPECTED_VENDOR_PATTERN_COUNT


def test_readme_secret_count_matches_code() -> None:
    """Every '<N> ... secret pattern' / '<N>-pattern' mention in the README must
    equal the real count, so the doc cannot claim 18 in one place and 26 in
    another (the exact contradiction audit #31 caught)."""
    readme = (REPO_ROOT / "README.md").read_text()
    mentions = re.findall(
        r"(\d+)[ -](?:vendor-format secret patterns|secret patterns?|pattern secret)",
        readme,
    )
    assert mentions, "README no longer states a secret-pattern count; update this guard"
    for n in mentions:
        assert int(n) == EXPECTED_VENDOR_PATTERN_COUNT, (
            f"README says {n} secret patterns but secrets._PATTERNS has "
            f"{EXPECTED_VENDOR_PATTERN_COUNT}"
        )
