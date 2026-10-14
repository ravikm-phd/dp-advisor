"""The interception pipeline, exercised on real diffprivlib mechanisms."""

import json
import pytest
import numpy as np
import diffprivlib.mechanisms as dp_mech

from dp_advice import (
    patch_dp_mechanism, unpatch_dp_mechanism, is_patched, defadvice, global_registry,
    DPCall, run_dp_call, execute_advice_chain, register_standard_dp_advices,
    default_accountant, default_logger,
    GlobalPrivacyAccountant, InMemoryAuditLogger,
    BudgetExhaustedError, NISTValidationError,
    ParameterMismatchError, UnknownPrivacyParametersError, SanitizedExecutionError,
)

KEY = "diffprivlib.mechanisms.Laplace.randomise"


def consumed():
    return default_accountant.get_status()["consumed_epsilon"]


def read_log():
    with open(default_logger.log_file, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def test_laplace_interception_and_budget_exhaustion():
    patch_dp_mechanism(dp_mech.Laplace, "randomise", KEY)
    mech = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0)

    res1 = mech.randomise(10.0)
    assert isinstance(res1, float)
    assert consumed() == pytest.approx(1.0)

    mech.randomise(15.0)
    mech.randomise(20.0)
    assert consumed() == pytest.approx(3.0)

    # budget is 3.0: the fourth one is refused and costs nothing
    with pytest.raises(BudgetExhaustedError):
        mech.randomise(25.0)
    assert consumed() == pytest.approx(3.0)
    assert [e["status"] for e in read_log()] == ["SUCCESS", "SUCCESS", "SUCCESS", "BLOCKED"]


def test_epsilon_is_read_from_the_instance_not_the_caller():
    patch_dp_mechanism(dp_mech.Laplace, "randomise", KEY)
    mech = dp_mech.Laplace(epsilon=2.0, sensitivity=1.0)

    # can't claim a smaller epsilon than the mechanism really uses
    with pytest.raises(ParameterMismatchError):
        mech.randomise(0.0, epsilon=0.01)
    assert consumed() == 0.0

    # a matching keyword is fine
    mech.randomise(0.0, epsilon=2.0)
    assert consumed() == pytest.approx(2.0)


def test_fails_closed_when_epsilon_is_unknown():
    class NoParams:
        def release(self, value):
            return value

    patch_dp_mechanism(NoParams, "release", "test.NoParams.release")
    with pytest.raises(UnknownPrivacyParametersError):
        NoParams().release(1.0)

    class BadParams(NoParams):
        epsilon = "one"

    patch_dp_mechanism(BadParams, "release", "test.BadParams.release")
    with pytest.raises(UnknownPrivacyParametersError):
        BadParams().release(1.0)


def test_standard_advices_refuse_to_run_without_a_dp_call():
    register_standard_dp_advices("test.bare")
    with pytest.raises(UnknownPrivacyParametersError):
        execute_advice_chain("test.bare", lambda: 1.0)


def test_validation_happens_before_reservation():
    default_accountant.set_budget(epsilon=20.0)
    patch_dp_mechanism(dp_mech.Laplace, "randomise", KEY)

    # 15 is over the per-query cap but would fit the budget; it must not be charged
    with pytest.raises(NISTValidationError, match="Dangerously large epsilon"):
        dp_mech.Laplace(epsilon=15.0, sensitivity=1.0).randomise(0.0)
    assert consumed() == 0.0
    assert default_accountant.get_status()["query_count"] == 0


def test_budget_is_refunded_when_the_mechanism_fails():
    patch_dp_mechanism(dp_mech.Geometric, "randomise", "diffprivlib.mechanisms.Geometric.randomise")
    mech = dp_mech.Geometric(epsilon=1.0, sensitivity=1)

    # Geometric raises TypeError on a float; we expect a masked error and a refund
    with pytest.raises(SanitizedExecutionError) as excinfo:
        mech.randomise(5.5)
    assert "TypeError" in str(excinfo.value)
    assert "5.5" not in str(excinfo.value)
    assert consumed() == 0.0
    assert read_log()[-1]["status"] == "FAILED"

    assert isinstance(mech.randomise(5), int)
    assert consumed() == pytest.approx(1.0)


def test_delta_is_accounted_and_limited():
    patch_dp_mechanism(dp_mech.GaussianAnalytic, "randomise", "diffprivlib.mechanisms.GaussianAnalytic.randomise")
    default_accountant.set_budget(epsilon=3.0, delta=2e-6)
    mech = dp_mech.GaussianAnalytic(epsilon=1.0, delta=1e-6, sensitivity=1.0)

    mech.randomise(0.0)
    mech.randomise(0.0)
    assert default_accountant.get_status()["consumed_delta"] == pytest.approx(2e-6)
    with pytest.raises(BudgetExhaustedError, match="delta"):
        mech.randomise(0.0)

    # delta budget of 0 = pure DP only
    default_accountant.set_budget(epsilon=3.0, delta=0.0)
    with pytest.raises(BudgetExhaustedError, match="delta"):
        mech.randomise(0.0)
    assert consumed() == 0.0


def test_dataset_size_tightens_the_delta_check():
    patch_dp_mechanism(dp_mech.GaussianAnalytic, "randomise", "diffprivlib.mechanisms.GaussianAnalytic.randomise")
    mech = dp_mech.GaussianAnalytic(epsilon=1.0, delta=1e-6, sensitivity=1.0)
    # 1/n^2 = 1e-8 < delta
    with pytest.raises(NISTValidationError, match="1/n\\^2"):
        mech.randomise(0.0, dataset_size=10_000)
    assert consumed() == 0.0
    # 1/n^2 = 1e-4, fine. dataset_size must not reach the mechanism
    mech.randomise(0.0, dataset_size=100)


def test_seed_reuse_is_detected_from_the_instance():
    patch_dp_mechanism(dp_mech.Laplace, "randomise", KEY)
    dp_mech.Laplace(epsilon=0.5, sensitivity=1.0, random_state=7).randomise(1.0)
    with pytest.raises(NISTValidationError, match="Seed 7 has already been used"):
        dp_mech.Laplace(epsilon=0.5, sensitivity=1.0, random_state=7).randomise(1.0)
    assert consumed() == pytest.approx(0.5)


def test_patching_is_idempotent_and_reversible():
    original = dp_mech.Laplace.__dict__["randomise"]
    for _ in range(5):
        patch_dp_mechanism(dp_mech.Laplace, "randomise", KEY)
    assert is_patched(dp_mech.Laplace, "randomise")
    assert dp_mech.Laplace.__dict__["randomise"].__wrapped__ is original

    with pytest.raises(ValueError):
        patch_dp_mechanism(dp_mech.Laplace, "randomise", "another.key")

    assert unpatch_dp_mechanism(dp_mech.Laplace, "randomise") is True
    assert dp_mech.Laplace.__dict__["randomise"] is original
    assert unpatch_dp_mechanism(dp_mech.Laplace, "randomise") is False

    dp_mech.Laplace(epsilon=1.0, sensitivity=1.0).randomise(0.0)
    assert consumed() == 0.0


def test_patch_survives_registry_clear():
    patch_dp_mechanism(dp_mech.Laplace, "randomise", KEY)
    global_registry.clear()
    dp_mech.Laplace(epsilon=1.0, sensitivity=1.0).randomise(0.0)
    assert consumed() == pytest.approx(1.0)


def test_user_advice_runs_alongside_standard_advices():
    seen = []
    patch_dp_mechanism(dp_mech.Laplace, "randomise", KEY)

    @defadvice(KEY, name="custom_before", advice_type=":before")
    def custom_before(value, *args, **kwargs):
        seen.append(("before", value))

    @defadvice(KEY, name="custom_after", advice_type=":after")
    def custom_after(result, value, *args, **kwargs):
        seen.append(("after", value))

    dp_mech.Laplace(epsilon=1.0, sensitivity=1.0).randomise(4.0)
    assert seen == [("before", 4.0), ("after", 4.0)]


def test_kwargs_param_source_for_function_style_apis():
    import types
    module = types.ModuleType("fake_tools")
    module.noisy_mean = lambda data, epsilon=1.0: float(np.mean(data))  # stand-in target, not a DP function

    patch_dp_mechanism(module, "noisy_mean", "test.fake_tools.noisy_mean", param_source="kwargs")
    with pytest.raises(UnknownPrivacyParametersError):
        module.noisy_mean([1.0, 2.0])
    module.noisy_mean([1.0, 2.0], epsilon=0.5)
    assert consumed() == pytest.approx(0.5)


def test_run_dp_call_uses_supplied_accountant_and_records_a_trace():
    accountant = GlobalPrivacyAccountant(total_epsilon=1.0, total_delta=0.0)
    logger = InMemoryAuditLogger()
    mech = dp_mech.Laplace(epsilon=0.75, sensitivity=1.0)

    call = DPCall(key="test.direct", epsilon=mech.epsilon, delta=mech.delta, accountant=accountant, logger=logger)
    run_dp_call(call, mech.randomise, 1.0)
    assert [s["stage"] for s in call.trace] == ["validate", "reserve", "target", "after"]
    assert accountant.get_status()["consumed_epsilon"] == pytest.approx(0.75)
    assert consumed() == 0.0

    blocked = DPCall(key="test.direct", epsilon=mech.epsilon, delta=mech.delta, accountant=accountant, logger=logger)
    with pytest.raises(BudgetExhaustedError):
        run_dp_call(blocked, mech.randomise, 1.0)
    assert blocked.trace[-1]["stage"] == "reserve" and blocked.trace[-1]["status"] == "BLOCKED"
    assert [e["status"] for e in logger.entries] == ["SUCCESS", "BLOCKED"]
