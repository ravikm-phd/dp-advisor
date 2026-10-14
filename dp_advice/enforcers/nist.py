"""Parameter checks based on NIST SP 800-226.

The numeric thresholds are our defaults. NIST doesn't prescribe any for epsilon.
"""

import math
from numbers import Real
import numpy as np
from typing import Any, Tuple, Optional, Set

from dp_advice.errors import DPAdviceError

class NISTValidationError(DPAdviceError, ValueError):
    """A mechanism call failed a parameter check."""

class NISTEnforcer:
    def __init__(self, max_epsilon: float = 10.0):
        self.max_epsilon = max_epsilon
        self.used_seeds: Set[int] = set()

    def verify_parameter_bounds(self, epsilon: float, delta: float = 0.0, dataset_size: Optional[int] = None) -> None:
        """Check 0 < epsilon <= max_epsilon, 0 <= delta < 1 and, if n is given, delta <= 1/n^2.

        max_epsilon is ours; NIST sets no cap (sec 2.2, p. 14). delta <= 1/n^2 is NIST's
        "common recommendation" (sec 2.3, p. 17), though it says this doesn't suit small n.
        Under unbounded DP n is itself sensitive (sec 2.4.1, p. 21), so only pass
        dataset_size when n is public.
        """
        for name, value in (("epsilon", epsilon), ("delta", delta)):
            if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value):
                raise NISTValidationError(f"[NIST SP 800-226] Invalid {name}={value!r}. Must be a finite number.")

        if epsilon <= 0:
            raise NISTValidationError(f"[NIST SP 800-226] Invalid epsilon={epsilon}. Epsilon must be strictly positive (> 0).")

        if epsilon > self.max_epsilon:
            raise NISTValidationError(
                f"[NIST SP 800-226] Dangerously large epsilon={epsilon} exceeds configured max_epsilon={self.max_epsilon}."
            )

        if delta < 0:
            raise NISTValidationError(f"[NIST SP 800-226] Delta cannot be negative ({delta}).")

        if delta >= 1:
            raise NISTValidationError(f"[NIST SP 800-226] Delta={delta} must be less than 1.")

        if dataset_size and dataset_size > 0:
            max_delta = 1.0 / (float(dataset_size) ** 2)
            if delta > max_delta:
                raise NISTValidationError(
                    f"[NIST SP 800-226] Delta={delta} is too large for dataset size n={dataset_size}. "
                    f"Must satisfy delta <= 1/n^2 (i.e. <= {max_delta})."
                )

    def clamp_dataset_bounds(self, data: Any, lower: float, upper: float) -> Tuple[np.ndarray, bool]:
        """Clip data to [lower, upper]; also says whether anything was out of range.

        See NIST SP 800-226 sec 3.4.2, p. 43.
        """
        if lower >= upper:
            raise NISTValidationError(f"[NIST SP 800-226] Invalid bounds: lower ({lower}) must be strictly less than upper ({upper}).")

        arr = np.asarray(data, dtype=np.float64)
        out_of_bounds = np.any((arr < lower) | (arr > upper))

        clamped_arr = np.clip(arr, lower, upper)
        return clamped_arr, out_of_bounds

    def check_prng_seed(self, seed: Optional[int]) -> None:
        """Refuse a seed we've already seen (same seed, same noise).

        Doesn't record the seed; call record_prng_seed once the release went through.
        This is ordinary RNG hygiene. NIST SP 800-226 says nothing about seeds.
        """
        if seed is not None and seed in self.used_seeds:
            raise NISTValidationError(
                f"[DP-Advice] PRNG seed reuse detected! Seed {seed} has already been used in a previous query."
            )

    def record_prng_seed(self, seed: Optional[int]) -> None:
        if seed is not None:
            self.used_seeds.add(seed)

    def audit_prng_seed(self, seed: Optional[int]) -> None:
        """check_prng_seed + record_prng_seed in one go."""
        self.check_prng_seed(seed)
        self.record_prng_seed(seed)

default_nist_enforcer = NISTEnforcer(max_epsilon=10.0)
