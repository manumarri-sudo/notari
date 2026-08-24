"""Every compliance control must be backed by an event Notari can actually emit.

Why this exists.

`controls.toml` is a crosswalk from compliance frameworks (AIUC-1, SOC 2, and
friends) to Notari's audit events, and `exports.py` loads it into the evidence
pack a customer or auditor reads. A control listed there is a claim that Notari
implements the control and can produce evidence for it.

Two entries were found claiming Permission Decay, mapped to a `policy.decayed`
event. No code in any version of this repository ever emitted that event: the
only mention was a docstring in decay.py asserting that it did, and the live
77,575-entry audit chain contained zero of them. The evidence pack had been
asserting an unevidenced control since it shipped, and nothing caught it,
because nothing checked that a control's cited event type was real.

So this asserts the property that would have caught it: every event type named
in controls.toml is a type Notari actually declares. It does not, and cannot,
prove the control is implemented well. It only closes the gap where a control
cites evidence that can never exist.
"""

from __future__ import annotations

from notari import events as ev
from notari.exports import CONTROLS


def test_every_control_cites_only_real_event_types() -> None:
    known = set(ev.ALL_EVENT_TYPES)
    assert known, "precondition: ALL_EVENT_TYPES must be non-empty or this proves nothing"

    offenders: list[str] = []
    for control in CONTROLS:
        for etype in getattr(control, "notari_event_types", ()) or ():
            if etype not in known:
                offenders.append(f"{control.code} cites {etype!r}")

    assert not offenders, (
        "controls.toml cites event types Notari cannot emit, so the evidence pack "
        "claims controls it cannot evidence: " + "; ".join(sorted(offenders))
    )


def test_controls_actually_loaded() -> None:
    """Guard against the whole file above passing vacuously.

    If `CONTROLS` were ever empty (a parse change, a moved file), the offender
    loop would iterate zero times and report success while checking nothing.
    That is the exact failure shape this repo keeps hitting, so it is asserted
    rather than assumed.
    """
    assert len(CONTROLS) > 20, f"expected the full crosswalk, got {len(CONTROLS)} controls"
    assert any(getattr(c, "notari_event_types", ()) for c in CONTROLS), (
        "no control cites any event type; the check above would be vacuous"
    )


def test_no_control_claims_permission_decay() -> None:
    """Permission Decay is gone, and it never enforced anything while present.

    Pinned by name because this is a compliance claim rather than an internal
    detail: reinstating it in the crosswalk should require reinstating the
    feature AND an event that gets emitted, not just editing prose.
    """
    for control in CONTROLS:
        blob = f"{control.title} {control.description}".lower()
        assert "permission decay" not in blob, (
            f"{control.code} claims Permission Decay, which is not implemented. "
            f"If it is reinstated, it needs an emitted event before it belongs here."
        )
