"""A single reported finding."""

from dataclasses import dataclass, field

from .severity import Severity


@dataclass(frozen=True)
class Finding:
    """One thing the auditor noticed about the host.

    ``check`` names the rule that produced it, ``message`` is the one-line
    human summary, ``remedy`` says what to do about it, and ``evidence`` holds
    the raw values that justified the finding so a report can show its work.
    """

    check: str
    severity: Severity
    message: str
    remedy: str = ""
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        """Return a JSON-serialisable view of the finding."""
        return {
            "check": self.check,
            "severity": self.severity.value,
            "message": self.message,
            "remedy": self.remedy,
            "evidence": self.evidence,
        }
