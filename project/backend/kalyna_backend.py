"""
Kalyna Backend - High-level interface for Kalyna cipher operations.
"""

import os
from pathlib import Path
from typing import Optional
import secrets

from .kalyna_adapter import KalynaAdapter, make_default_adapter


class KalynaBackend:

    def __init__(self, adapter: Optional[KalynaAdapter] = None):
        self.adapter = adapter if adapter is not None else make_default_adapter()

    def random_key(self) -> bytes:
        """Generate a random key of the appropriate size."""
        return secrets.token_bytes(self.adapter.config.key_size_bytes)

    def random_block(self) -> bytes:
        """Generate a random block of the appropriate size."""
        return secrets.token_bytes(self.adapter.config.block_size_bytes)

    def encrypt_rounds(self, plaintext: bytes, key: bytes, rounds: int) -> bytes:
        """Encrypt plaintext with key for specified number of rounds."""
        return self.adapter.encrypt_rounds(plaintext, key, rounds)

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt plaintext with key for full number of rounds."""
        return self.adapter.encrypt_block(plaintext, key)

    @property
    def block_size_bytes(self) -> int:
        return self.adapter.config.block_size_bytes

    @property
    def block_size_bits(self) -> int:
        return self.adapter.config.block_size_bytes * 8

    @property
    def key_size_bytes(self) -> int:
        return self.adapter.config.key_size_bytes