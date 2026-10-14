"""Exceptions raised by dp_advice.

The pipeline lets DPAdviceError subclasses through as they are and masks anything else.
"""


class DPAdviceError(Exception):
    """Base class for everything dp_advice raises on purpose."""


class UnknownPrivacyParametersError(DPAdviceError, RuntimeError):
    """We could not work out epsilon/delta for a call, so it was refused."""


class ParameterMismatchError(DPAdviceError, ValueError):
    """The caller's epsilon/delta disagrees with what the mechanism actually uses."""


class SanitizedExecutionError(DPAdviceError, RuntimeError):
    """Stands in for an unexpected exception so its message can't leak data."""
