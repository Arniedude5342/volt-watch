"""Finding severity levels."""

from enum import Enum


class Severity(str, Enum):
    """How bad a finding is.

    Ordered from least to most urgent so callers can sort and filter with a
    plain comparison on the enum's definition order.
    """

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
