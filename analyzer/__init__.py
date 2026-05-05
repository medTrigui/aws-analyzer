"""
Main analyzer package.
"""

from .analyzer import IAMAnalyzer
from .cli import app, main

__all__ = [
    "IAMAnalyzer",
    "app",
    "main",
]
