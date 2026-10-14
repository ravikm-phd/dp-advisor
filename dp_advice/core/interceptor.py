"""Patches DP mechanisms (via wrapt) so every call goes through the advice pipeline.

What happens on a call:

    :around  control      outermost; on failure refunds the budget and masks the exception
    :before  validate     parameter checks, nothing reserved yet
    :before  reserve      take (epsilon, delta) from the accountant
    target                the mechanism
    :after   round, log   round float output, write the audit entry

epsilon and delta are read off the mechanism instance, never from the caller's kwargs.
If we can't tell what they are, the call is refused.
"""

import math
import threading
import wrapt
from dataclasses import dataclass, field
from numbers import Real
from typing import Any, Callable, Dict, List, Optional, Tuple

from dp_advice.core.advice import execute_advice_chain, call_next_advice, global_registry
from dp_advice.accountant.budget_manager import default_accountant
from dp_advice.enforcers.nist import default_nist_enforcer
from dp_advice.enforcers.w3c import default_w3c_enforcer
from dp_advice.auditing.logger import default_logger
from dp_advice.errors import (
    DPAdviceError, UnknownPrivacyParametersError, ParameterMismatchError
)

_state = threading.local()


@dataclass
class DPCall:
    """State for one intercepted call; the standard advices read and update it."""
    key: str
    epsilon: Any
    delta: Any = 0.0
    dataset_size: Optional[int] = None
    seed: Optional[int] = None
    accountant: Any = None
    nist: Any = None
    hygiene: Any = None
    logger: Any = None
    reserved: bool = False
    phase: str = "validate"
    trace: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.accountant is None:
            self.accountant = default_accountant
        if self.nist is None:
            self.nist = default_nist_enforcer
        if self.hygiene is None:
            self.hygiene = default_w3c_enforcer
        if self.logger is None:
            self.logger = default_logger


def current_dp_call() -> Optional[DPCall]:
    stack = getattr(_state, "calls", None)
    return stack[-1] if stack else None


def _require_call() -> DPCall:
    call = current_dp_call()
    if call is None:
        raise UnknownPrivacyParametersError(
            "[DP-Advice] No privacy parameters are known for this call. "
            "Run it through a patched mechanism or run_dp_call()."
        )
    return call


def _is_number(value: Any) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool) and math.isfinite(value)


def _dp_validate_parameters(*args, **kwargs):
    call = _require_call()
    call.nist.verify_parameter_bounds(call.epsilon, call.delta, call.dataset_size)
    call.nist.check_prng_seed(call.seed)
    call.trace.append({
        "stage": "validate", "status": "PASSED",
        "epsilon": call.epsilon, "delta": call.delta,
        "dataset_size": call.dataset_size, "max_epsilon": call.nist.max_epsilon,
    })
    call.phase = "reserve"


def _dp_reserve_budget(*args, **kwargs):
    call = _require_call()
    consumed_eps, consumed_delta = call.accountant.check_and_consume(call.epsilon, call.delta)
    call.reserved = True
    call.trace.append({
        "stage": "reserve", "status": "PASSED",
        "requested_epsilon": call.epsilon, "requested_delta": call.delta,
        "consumed_cumulative": consumed_eps, "consumed_delta_cumulative": consumed_delta,
        "total_epsilon": call.accountant.total_epsilon,
    })
    call.phase = "target"


def _abort(call: DPCall, status: str, message: str, error_type: str) -> None:
    refunded = call.reserved
    if call.reserved:
        call.accountant.refund(call.epsilon, call.delta)
        call.reserved = False
    call.trace.append({"stage": call.phase, "status": status, "error": message, "refunded": refunded})
    call.logger.log_release(
        target_name=call.key,
        epsilon=float(call.epsilon) if _is_number(call.epsilon) else 0.0,
        delta=float(call.delta) if _is_number(call.delta) else 0.0,
        dataset_size=int(call.dataset_size or 0),
        status=status,
        metadata={"stage": call.phase, "error_type": error_type},
    )


def _dp_control(*args, **kwargs):
    call = _require_call()
    try:
        return call_next_advice(*args, **kwargs)
    except DPAdviceError as e:
        _abort(call, "BLOCKED", str(e), type(e).__name__)
        raise
    except Exception as e:
        # the message could contain data values, so keep only the exception type
        sanitized = call.hygiene.sanitize_exception_traceback(e)
        _abort(call, "FAILED", str(sanitized), type(e).__name__)
        raise sanitized from None


def _dp_round_and_audit(result, *args, **kwargs):
    call = _require_call()
    call.phase = "after"
    rounded = call.hygiene.round_output(result)
    call.nist.record_prng_seed(call.seed)
    call.logger.log_release(
        target_name=call.key,
        epsilon=float(call.epsilon),
        delta=float(call.delta),
        dataset_size=int(call.dataset_size or 0),
        status="SUCCESS",
    )
    call.trace.append({"stage": "after", "status": "PASSED"})
    return rounded


_STANDARD_ADVICES = (
    ("dp_validate_parameters", ":before", _dp_validate_parameters, ":start"),
    ("dp_reserve_budget", ":before", _dp_reserve_budget, ":end"),
    ("dp_control", ":around", _dp_control, ":start"),
    ("dp_round_and_audit", ":after", _dp_round_and_audit, ":end"),
)


def _has_standard_dp_advices(target_key: str) -> bool:
    chains = global_registry.get_chains(target_key)
    present = {getattr(fn, "__advice_name__", None) for chain in chains.values() for fn in chain}
    return all(name in present for name, _, _, _ in _STANDARD_ADVICES)


def register_standard_dp_advices(target_key: str):
    """Register the validate / reserve / control / audit advices for a key.

    Safe to call again; it just puts them back in their usual places.
    """
    for name, advice_type, fn, where in _STANDARD_ADVICES:
        global_registry.register_advice(target_key, name, advice_type, _named_copy(fn), where)


def _named_copy(fn: Callable) -> Callable:
    # the registry sets __advice_name__ on the function, so each key needs its own object
    def advice(*args, **kwargs):
        return fn(*args, **kwargs)
    advice.__name__ = fn.__name__
    return advice


def run_dp_call(call: DPCall, target_fn: Callable, *args, **kwargs) -> Any:
    """Run target_fn(*args, **kwargs) through the advice registered for call.key.

    call.trace lists the stages that ran, whether this returns or raises.
    """
    if not _has_standard_dp_advices(call.key):
        register_standard_dp_advices(call.key)

    def _target(*a, **kw):
        result = target_fn(*a, **kw)
        call.trace.append({"stage": "target", "status": "PASSED"})
        return result

    stack = getattr(_state, "calls", None)
    if stack is None:
        stack = _state.calls = []
    stack.append(call)
    was_in_advice = getattr(_state, "in_advice", False)
    _state.in_advice = True
    try:
        return execute_advice_chain(call.key, _target, *args, **kwargs)
    finally:
        _state.in_advice = was_in_advice
        stack.pop()


_ADVICE_KWARGS = ("epsilon", "delta", "dataset_size")


def _params_from_instance(instance: Any, kwargs: Dict[str, Any], key_name: str) -> Tuple[DPCall, Dict[str, Any]]:
    if instance is None or not hasattr(instance, "epsilon"):
        raise UnknownPrivacyParametersError(
            f"[DP-Advice] Cannot determine epsilon for '{key_name}': the patched callable has no "
            "mechanism instance with an 'epsilon' attribute. Call refused."
        )
    epsilon = getattr(instance, "epsilon")
    delta = getattr(instance, "delta", 0.0)
    if delta is None:
        delta = 0.0
    if not _is_number(epsilon) or not _is_number(delta):
        raise UnknownPrivacyParametersError(
            f"[DP-Advice] Mechanism for '{key_name}' has non-numeric privacy parameters "
            f"(epsilon={epsilon!r}, delta={delta!r}). Call refused."
        )

    clean_kwargs = dict(kwargs)
    for name, actual in (("epsilon", epsilon), ("delta", delta)):
        if name in clean_kwargs:
            claimed = clean_kwargs.pop(name)
            if not _is_number(claimed) or not math.isclose(claimed, actual, rel_tol=1e-12, abs_tol=0.0):
                raise ParameterMismatchError(
                    f"[DP-Advice] Caller passed {name}={claimed!r} but the mechanism uses {name}={actual!r}. "
                    "The mechanism's own parameters are authoritative; set them on the mechanism."
                )
    dataset_size = clean_kwargs.pop("dataset_size", None)
    if dataset_size is not None and (isinstance(dataset_size, bool) or not isinstance(dataset_size, int) or dataset_size <= 0):
        raise ParameterMismatchError(f"[DP-Advice] dataset_size must be a positive integer, got {dataset_size!r}.")

    seed = getattr(instance, "random_state", None)
    if isinstance(seed, bool) or not isinstance(seed, int):
        seed = None

    return DPCall(key=key_name, epsilon=epsilon, delta=delta, dataset_size=dataset_size, seed=seed), clean_kwargs


def _params_from_kwargs(kwargs: Dict[str, Any], key_name: str) -> Tuple[DPCall, Dict[str, Any]]:
    if "epsilon" not in kwargs or not _is_number(kwargs["epsilon"]):
        raise UnknownPrivacyParametersError(
            f"[DP-Advice] Cannot determine epsilon for '{key_name}': pass a numeric 'epsilon' keyword. Call refused."
        )
    delta = kwargs.get("delta", 0.0)
    if not _is_number(delta):
        raise UnknownPrivacyParametersError(
            f"[DP-Advice] Non-numeric delta={delta!r} for '{key_name}'. Call refused."
        )
    seed = kwargs.get("random_state")
    if isinstance(seed, bool) or not isinstance(seed, int):
        seed = None
    # kwargs go through as-is: here they're what the function itself uses
    return DPCall(key=key_name, epsilon=kwargs["epsilon"], delta=delta, seed=seed), dict(kwargs)


@dataclass
class _Patch:
    target_obj: Any
    method_name: str
    key_name: str
    had_own_attribute: bool
    original: Any


_patches: Dict[Tuple[int, str], _Patch] = {}
_patch_lock = threading.Lock()


def patch_dp_mechanism(target_obj: Any, method_name: str, key_name: str, param_source: str = "instance"):
    """Wrap a method on a class, module or instance so calls go through the pipeline.

    param_source="instance" (default): epsilon/delta come from the bound mechanism at
    call time. An epsilon= or delta= keyword that disagrees is an error. dataset_size=
    is accepted as metadata for the delta check and is not passed on.

    param_source="kwargs": for function-style APIs such as diffprivlib.tools.mean,
    where the epsilon keyword really is what the function uses. It is required and
    passed through untouched.

    Patching twice with the same key does nothing. Undo with unpatch_dp_mechanism.
    """
    if param_source not in ("instance", "kwargs"):
        raise ValueError(f"param_source must be 'instance' or 'kwargs', got {param_source!r}.")

    with _patch_lock:
        patch_id = (id(target_obj), method_name)
        existing = _patches.get(patch_id)
        if existing is not None:
            if existing.key_name != key_name:
                raise ValueError(
                    f"{method_name!r} is already patched with key {existing.key_name!r}; unpatch it first."
                )
            return

        own_attributes = getattr(target_obj, "__dict__", {})
        had_own = method_name in own_attributes
        original = own_attributes[method_name] if had_own else getattr(target_obj, method_name)

        @wrapt.decorator
        def wrapper(wrapped, instance, args, kwargs):
            # a mechanism called from inside an intercepted call is part of that call
            if getattr(_state, "in_advice", False):
                return wrapped(*args, **kwargs)

            if param_source == "instance":
                call, clean_kwargs = _params_from_instance(instance, kwargs, key_name)
            else:
                call, clean_kwargs = _params_from_kwargs(kwargs, key_name)
            return run_dp_call(call, wrapped, *args, **clean_kwargs)

        register_standard_dp_advices(key_name)
        setattr(target_obj, method_name, wrapper(original))
        _patches[patch_id] = _Patch(target_obj, method_name, key_name, had_own, original)


def is_patched(target_obj: Any, method_name: str) -> bool:
    return (id(target_obj), method_name) in _patches


def unpatch_dp_mechanism(target_obj: Any, method_name: str) -> bool:
    """Put the original attribute back. Returns False if it wasn't patched."""
    with _patch_lock:
        patch = _patches.pop((id(target_obj), method_name), None)
        if patch is None:
            return False
        if patch.had_own_attribute:
            setattr(patch.target_obj, patch.method_name, patch.original)
        else:
            delattr(patch.target_obj, patch.method_name)
        return True


def unpatch_all() -> int:
    """Undo every patch; returns how many there were."""
    with _patch_lock:
        patches = list(_patches.values())
    return sum(1 for p in patches if unpatch_dp_mechanism(p.target_obj, p.method_name))
