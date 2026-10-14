"""Every test gets a fresh budget, no remembered seeds, no patches, and an audit log in tmp_path."""

import os
import pytest

from dp_advice import default_accountant, default_nist_enforcer, default_logger, unpatch_all


@pytest.fixture(autouse=True)
def isolated_dp_state(tmp_path):
    original_dir, original_file = default_logger.log_dir, default_logger.log_file
    default_logger.log_dir = str(tmp_path)
    default_logger.log_file = os.path.join(str(tmp_path), "dp_compliance_audit.jsonl")
    default_accountant.set_budget(epsilon=3.0, delta=1e-5)
    default_nist_enforcer.used_seeds.clear()
    default_nist_enforcer.max_epsilon = 10.0
    yield
    unpatch_all()
    default_logger.log_dir, default_logger.log_file = original_dir, original_file
