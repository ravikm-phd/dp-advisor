"""
DP-Advice (DP-Guard): A Dynamic Privacy Advice Framework for Differential Privacy Libraries.
Runtime checks informed by NIST SP 800-226, built on an advice pipeline modelled on LispWorks 'defadvice'.
"""

from dp_advice.errors import (
    DPAdviceError, UnknownPrivacyParametersError, ParameterMismatchError, SanitizedExecutionError
)
from dp_advice.core.advice import defadvice, call_next_advice, global_registry, execute_advice_chain
from dp_advice.core.interceptor import (
    DPCall, run_dp_call, current_dp_call,
    patch_dp_mechanism, unpatch_dp_mechanism, unpatch_all, is_patched,
    register_standard_dp_advices,
)
from dp_advice.accountant.budget_manager import GlobalPrivacyAccountant, default_accountant, BudgetExhaustedError
from dp_advice.enforcers.nist import NISTEnforcer, default_nist_enforcer, NISTValidationError
from dp_advice.enforcers.w3c import W3CEnforcer, default_w3c_enforcer, W3CViolationError
from dp_advice.auditing.logger import ComplianceAuditLogger, InMemoryAuditLogger, default_logger

__version__ = "1.1.0"
__all__ = [
    "DPAdviceError",
    "UnknownPrivacyParametersError",
    "ParameterMismatchError",
    "SanitizedExecutionError",
    "defadvice",
    "call_next_advice",
    "global_registry",
    "execute_advice_chain",
    "DPCall",
    "run_dp_call",
    "current_dp_call",
    "patch_dp_mechanism",
    "unpatch_dp_mechanism",
    "unpatch_all",
    "is_patched",
    "register_standard_dp_advices",
    "GlobalPrivacyAccountant",
    "default_accountant",
    "BudgetExhaustedError",
    "NISTEnforcer",
    "default_nist_enforcer",
    "NISTValidationError",
    "W3CEnforcer",
    "default_w3c_enforcer",
    "W3CViolationError",
    "ComplianceAuditLogger",
    "InMemoryAuditLogger",
    "default_logger",
]
