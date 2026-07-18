"""ConfigDNA public API."""

from .core import Change, Comparison, Statement, compare, fingerprint, normalize

__all__ = ["Change", "Comparison", "Statement", "compare", "fingerprint", "normalize"]
__version__ = "0.2.0"
