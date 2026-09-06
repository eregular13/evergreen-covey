"""Evergreen Covey — SCOPE-gated sharded BYO scanner orchestration."""

__version__ = "0.1.0"

from covey.errors import CoveyError, RunnerError, ScopeError, ShardError

__all__ = [
    "CoveyError",
    "RunnerError",
    "ScopeError",
    "ShardError",
    "__version__",
]
