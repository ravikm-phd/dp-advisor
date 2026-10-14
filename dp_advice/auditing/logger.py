"""JSONL audit log of DP calls.

Just an append-only file. Nothing protects it from being edited, and on its own it
proves nothing about regulatory compliance.
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def _make_entry(target_name: str, epsilon: float, delta: float, dataset_size: int,
                status: str, metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target_name,
        "consumed_epsilon": epsilon,
        "consumed_delta": delta,
        "dataset_size": dataset_size,
        "status": status,
        "metadata": metadata or {}
    }


class ComplianceAuditLogger:
    """One JSON line per intercepted call. The directory is created on first write."""

    def __init__(self, log_dir: str = "audit_logs"):
        self.log_dir = log_dir
        self.log_file = os.path.join(self.log_dir, "dp_compliance_audit.jsonl")
        self._lock = threading.Lock()

    def log_release(self, target_name: str, epsilon: float, delta: float,
                    dataset_size: int, status: str = "SUCCESS",
                    metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        entry = _make_entry(target_name, epsilon, delta, dataset_size, status, metadata)
        with self._lock:
            os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry


class InMemoryAuditLogger:
    """Keeps the last few entries in memory, for throwaway sessions like the web demo."""

    def __init__(self, max_entries: int = 100):
        self.max_entries = max_entries
        self.entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def log_release(self, target_name: str, epsilon: float, delta: float,
                    dataset_size: int, status: str = "SUCCESS",
                    metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        entry = _make_entry(target_name, epsilon, delta, dataset_size, status, metadata)
        with self._lock:
            self.entries.append(entry)
            del self.entries[:-self.max_entries]
        return entry


default_logger = ComplianceAuditLogger()
