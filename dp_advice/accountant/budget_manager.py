"""Privacy accountant.

Plain sequential composition: the epsilons and deltas of successive releases add up
(NIST SP 800-226 sec 2.2). No parallel or advanced composition, so the total can be
loose. Everything is in memory, so the budget is gone when the process restarts.
"""

import math
import threading
from numbers import Real
from typing import Tuple, Dict, Any, Optional

from dp_advice.errors import DPAdviceError

_EPS_TOL = 1e-9
_DELTA_TOL = 1e-15


class BudgetExhaustedError(DPAdviceError, RuntimeError):
    """A release would take us past the total budget."""


def _check_number(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number, got {value!r}.")
    return float(value)


class GlobalPrivacyAccountant:
    def __init__(self, total_epsilon: float = 5.0, total_delta: float = 1e-5):
        self.total_epsilon = _check_number("total_epsilon", total_epsilon)
        self.total_delta = _check_number("total_delta", total_delta)
        if self.total_epsilon <= 0:
            raise ValueError(f"total_epsilon must be > 0, got {total_epsilon}.")
        if not 0 <= self.total_delta < 1:
            raise ValueError(f"total_delta must be in [0, 1), got {total_delta}.")
        self.consumed_epsilon = 0.0
        self.consumed_delta = 0.0
        self.query_count = 0
        self._lock = threading.Lock()

    def set_budget(self, epsilon: float, delta: Optional[float] = None):
        """Set a new total budget and start counting from zero.

        delta=None keeps the current delta budget. delta=0 means pure epsilon-DP only.
        """
        epsilon = _check_number("epsilon", epsilon)
        if epsilon <= 0:
            raise ValueError(f"Total epsilon must be > 0, got {epsilon}.")
        if delta is not None:
            delta = _check_number("delta", delta)
            if not 0 <= delta < 1:
                raise ValueError(f"Total delta must be in [0, 1), got {delta}.")
        with self._lock:
            self.total_epsilon = epsilon
            if delta is not None:
                self.total_delta = delta
            self.consumed_epsilon = 0.0
            self.consumed_delta = 0.0
            self.query_count = 0

    def check_and_consume(self, epsilon: float, delta: float = 0.0) -> Tuple[float, float]:
        """Take (epsilon, delta) out of the budget, or raise BudgetExhaustedError and take nothing."""
        epsilon = _check_number("epsilon", epsilon)
        delta = _check_number("delta", delta)
        if epsilon <= 0:
            raise ValueError(f"Epsilon must be strictly positive (> 0), got {epsilon}.")
        if delta < 0:
            raise ValueError(f"Delta cannot be negative, got {delta}.")

        with self._lock:
            new_eps = self.consumed_epsilon + epsilon
            new_del = self.consumed_delta + delta

            if new_eps > self.total_epsilon + _EPS_TOL:
                raise BudgetExhaustedError(
                    f"Privacy budget allocation exceeded! Requested epsilon={epsilon:.4f} (total would be {new_eps:.4f}), "
                    f"but maximum total budget is epsilon={self.total_epsilon:.4f}."
                )

            if new_del > self.total_delta + _DELTA_TOL:
                raise BudgetExhaustedError(
                    f"Privacy budget delta allocation exceeded! Requested delta={delta} (total would be {new_del}), "
                    f"but maximum total delta is {self.total_delta}."
                )

            self.consumed_epsilon = new_eps
            self.consumed_delta = new_del
            self.query_count += 1

            return (self.consumed_epsilon, self.consumed_delta)

    reserve = check_and_consume

    def refund(self, epsilon: float, delta: float = 0.0) -> None:
        """Give back a reservation whose mechanism never released anything.

        Only sound when the failure didn't depend on the data: a data-dependent failure
        is an observable signal in its own right (NIST SP 800-226 sec 4.3, p. 59).
        """
        with self._lock:
            self.consumed_epsilon = max(0.0, self.consumed_epsilon - epsilon)
            self.consumed_delta = max(0.0, self.consumed_delta - delta)
            self.query_count = max(0, self.query_count - 1)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_epsilon": self.total_epsilon,
                "total_delta": self.total_delta,
                "consumed_epsilon": self.consumed_epsilon,
                "consumed_delta": self.consumed_delta,
                "remaining_epsilon": max(0.0, self.total_epsilon - self.consumed_epsilon),
                "remaining_delta": max(0.0, self.total_delta - self.consumed_delta),
                "query_count": self.query_count
            }

    def reset(self):
        with self._lock:
            self.consumed_epsilon = 0.0
            self.consumed_delta = 0.0
            self.query_count = 0

default_accountant = GlobalPrivacyAccountant(total_epsilon=5.0, total_delta=1e-5)
