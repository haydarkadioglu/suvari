"""
DEPRECATED — Use failure.py instead.
Unified failure attribution lives in suvari/failure.py.
"""
from .failure import FailureLevel, classify_failure, get_recovery_strategy

__all__ = ["FailureLevel", "classify_failure", "get_recovery_strategy"]
