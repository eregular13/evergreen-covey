"""Fail-closed errors. Nothing here is advisory."""


class CoveyError(Exception):
    """Base error for Evergreen Covey."""


class ScopeError(CoveyError):
    """SCOPE missing, unsigned, expired, or spray-unsafe."""


class ShardError(CoveyError):
    """CIDR tile math refused or malformed."""


class RunnerError(CoveyError):
    """Worker execution or scanner resolution failed."""


class AdapterError(CoveyError):
    """Adapter argv / artifact handling refused."""


class ExportError(CoveyError):
    """Pack export refused or run artifacts are incomplete."""
