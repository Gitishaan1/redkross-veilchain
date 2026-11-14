"""Exception types. Each carries the process exit code the CLI should use."""

from __future__ import annotations

# Exit codes (documented in README):
EXIT_OK = 0
EXIT_VERIFY_FAILED = 1
EXIT_RESTRICTED_FOUND = 2  # run finished, but Restricted material was found and removed
EXIT_USAGE = 3


class VeilChainError(Exception):
    """Base class for all expected, user-facing errors."""

    exit_code = EXIT_USAGE


class PolicyError(VeilChainError):
    """The classification policy file is missing or malformed."""


class RulesError(VeilChainError):
    """The VeilChain rules file is missing, malformed, or inconsistent with the policy."""


class InputError(VeilChainError):
    """The input data cannot be processed (empty, unreadable, malformed)."""


class KeyMaterialError(VeilChainError):
    """Key material is missing, too weak, or unsafe to write."""


class OutputError(VeilChainError):
    """The output location is unsafe (for example, would overwrite existing evidence)."""
