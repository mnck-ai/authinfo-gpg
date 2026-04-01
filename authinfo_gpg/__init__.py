"""
authinfo-gpg: Read GPG-encrypted .authinfo credentials

A simple Python library to read credentials from GPG-encrypted .authinfo files.
"""

from .core import AuthInfoGPG, AuthEntry, get_entry, find_gpg_binary

__version__ = "0.1.1"
__all__ = ["AuthInfoGPG", "AuthEntry", "get_entry", "find_gpg_binary"]
