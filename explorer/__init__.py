"""
Explorer module for OP-TEE Trusted Application Analysis

This module contains exploration techniques, hooks, memory management,
and plugins for analyzing TrustZone Trusted Applications.
"""

# Re-export from submodules for backward compatibility
from .exploration_techniques import *
from .hooks import *
from .memory import *
from .plugins import *

__all__ = []

