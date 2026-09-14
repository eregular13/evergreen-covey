"""Evergreen Covey — SCOPE-gated sharded BYO scanner orchestration."""

__version__ = "0.2.0"

from covey.errors import (
    CoveyError,
    ExportError,
    GateError,
    RunnerError,
    ScopeError,
    ShardError,
)

__all__ = [
    "CoveyError",
    "ExportError",
    "GateError",
    "RunnerError",
    "ScopeError",
    "ShardError",
    "__version__",
]
