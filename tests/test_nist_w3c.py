"""Tests for the parameter checks, output rounding, exception masking and the accountant."""

import numpy as np
import pytest
from dp_advice import (
    NISTEnforcer, NISTValidationError,
    W3CEnforcer,
    GlobalPrivacyAccountant, BudgetExhaustedError
)

def test_nist_parameter_bounds():
    nist = NISTEnforcer(max_epsilon=10.0)

    # fine: 1e-11 <= 1/n^2 = 1e-10
    nist.verify_parameter_bounds(epsilon=1.5, delta=1e-11, dataset_size=100000)

    with pytest.raises(NISTValidationError, match="must be strictly positive"):
        nist.verify_parameter_bounds(epsilon=0.0)

    with pytest.raises(NISTValidationError, match="Dangerously large epsilon"):
        nist.verify_parameter_bounds(epsilon=15.0)

    # 1e-6 > 1/n^2 = 1e-10
    with pytest.raises(NISTValidationError, match="Must satisfy delta <= 1/n\\^2"):
        nist.verify_parameter_bounds(epsilon=1.0, delta=1e-6, dataset_size=100000)

    with pytest.raises(NISTValidationError, match="must be less than 1"):
        nist.verify_parameter_bounds(epsilon=1.0, delta=1.0)
    with pytest.raises(NISTValidationError, match="finite number"):
        nist.verify_parameter_bounds(epsilon=float("nan"))

def test_nist_clamping_and_prng():
    nist = NISTEnforcer()

    raw_data = [ -10.0, 5.0, 15.0, 2.0 ]
    clamped, out_of_bounds = nist.clamp_dataset_bounds(raw_data, lower=0.0, upper=10.0)
    assert bool(out_of_bounds) is True
    assert list(clamped) == [0.0, 5.0, 10.0, 2.0]

    nist.audit_prng_seed(12345)
    with pytest.raises(NISTValidationError, match="Seed 12345 has already been used"):
        nist.audit_prng_seed(12345)

def test_output_rounding():
    w3c = W3CEnforcer()

    raw_val = 3.141592653589793238462643383279
    rounded = w3c.round_output(raw_val, precision_bits=30)
    assert isinstance(rounded, float)
    assert abs(rounded - raw_val) <= 2.0 ** -31
    assert (rounded * 2 ** 30).is_integer()

    # ints, bools and strings are left alone
    assert w3c.round_output(7) == 7 and isinstance(w3c.round_output(7), int)
    assert w3c.round_output(True) is True
    assert w3c.round_output("text") == "text"

    # arrays are rounded element-wise, inf/nan survive
    arr = w3c.round_output(np.array([0.1, np.inf, np.nan]), precision_bits=4)
    assert arr[0] == 0.125 and np.isinf(arr[1]) and np.isnan(arr[2])

def test_w3c_traceback_masking():
    w3c = W3CEnforcer()
    raw_exc = KeyError("Confidential column 'SSN' missing from raw DataFrame!")
    sanitized = w3c.sanitize_exception_traceback(raw_exc)

    assert isinstance(sanitized, RuntimeError)
    assert "KeyError" in str(sanitized)
    assert "SSN" not in str(sanitized)

def test_accountant_delta_budget_and_refund():
    accountant = GlobalPrivacyAccountant(total_epsilon=2.0, total_delta=1e-6)

    # set_budget without delta must keep the delta budget (it used to switch it off)
    accountant.set_budget(4.0)
    assert accountant.get_status()["total_delta"] == 1e-6
    with pytest.raises(BudgetExhaustedError, match="delta"):
        accountant.check_and_consume(0.1, delta=0.5)
    assert accountant.get_status()["consumed_epsilon"] == 0.0

    accountant.check_and_consume(1.0, delta=1e-6)
    accountant.refund(1.0, delta=1e-6)
    status = accountant.get_status()
    assert status["consumed_epsilon"] == 0.0 and status["consumed_delta"] == 0.0 and status["query_count"] == 0

    with pytest.raises(ValueError):
        accountant.check_and_consume(float("nan"))
    with pytest.raises(ValueError):
        accountant.set_budget(-1.0)

def test_global_privacy_accountant_exhaustion():
    accountant = GlobalPrivacyAccountant(total_epsilon=2.0)

    accountant.check_and_consume(1.0)
    accountant.check_and_consume(0.8)
    assert accountant.get_status()["consumed_epsilon"] == pytest.approx(1.8)

    with pytest.raises(BudgetExhaustedError, match="Privacy budget allocation exceeded"):
        accountant.check_and_consume(0.5)
