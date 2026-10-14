"""Trust-model check, exception masking and output rounding.

The W3C in the names is historical. Only the central/local trust model appears in a
W3C document (the draft note "Considerations for Reviewing Differential Privacy
Systems", sec 4.1). Masking and rounding are our own design choices; neither that
draft nor the W3C Privacy Principles mentions them.
"""

import math
import numpy as np
from typing import Any

from dp_advice.errors import DPAdviceError, SanitizedExecutionError

class W3CViolationError(DPAdviceError, RuntimeError):
    """The call doesn't fit the declared trust model."""

class W3CEnforcer:
    def __init__(self, trust_model: str = "central"):
        self.trust_model = trust_model.lower()

    def enforce_trust_boundary(self, data_source: str) -> None:
        """In the local model, raw client data must not reach the server.

        cf. W3C DP guidance draft sec 4.1 and NIST SP 800-226 sec 4.2.2.
        """
        if self.trust_model == "local" and data_source == "unperturbed_server_raw":
            raise W3CViolationError(
                "[DP-Advice] Trust Boundary Violation: Local DP model forbids sending raw unperturbed client data to central server."
            )

    def round_output(self, value: Any, precision_bits: int = 40) -> Any:
        """Round floats to a grid of step 2**-precision_bits.

        Ints, bools and anything non-numeric come back untouched.

        This is not Mironov's snapping mechanism and does nothing against floating-point
        attacks: the grid isn't tied to the noise scale, and above roughly
        2**(52 - precision_bits) the rounding is a no-op. For real snapping use a
        mechanism that samples accordingly, e.g. diffprivlib.mechanisms.Snapping.
        """
        step = 2.0 ** (-precision_bits)

        if isinstance(value, (bool, np.bool_)):
            return value
        if isinstance(value, (float, np.floating)):
            val = float(value)
            if math.isnan(val) or math.isinf(val):
                return val
            return round(val / step) * step
        if isinstance(value, np.ndarray) and np.issubdtype(value.dtype, np.floating):
            rounded = np.round(value / step) * step
            return np.where(np.isfinite(value), rounded, value)
        return value

    def sanitize_exception_traceback(self, exc: Exception) -> SanitizedExecutionError:
        """Replace an exception with one that only carries its type name."""
        safe_msg = f"[DP-Advice Sanitized Error] Execution failed safely without exposing raw tracebacks: {type(exc).__name__}"
        return SanitizedExecutionError(safe_msg)

default_w3c_enforcer = W3CEnforcer(trust_model="central")
