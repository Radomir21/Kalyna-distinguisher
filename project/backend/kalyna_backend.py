from __future__ import annotations
import os
from typing import Tuple
import numpy as np
from project.backend.kalyna_adapter import KalynaAdapter, make_default_adapter


class KalynaBackend:
    def __init__(self, adapter: KalynaAdapter | None = None):
        self.adapter = adapter if adapter is not None else make_default_adapter()
        self.block_size_bytes = self.adapter.config.block_size_bytes
        self.key_size_bytes = self.adapter.config.key_size_bytes
        self.block_size_bits = self.adapter.config.block_size_bits

    def random_block(self) -> bytes:
        return os.urandom(self.block_size_bytes)

    def random_key(self) -> bytes:
        return os.urandom(self.key_size_bytes)

    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        if len(a) != len(b):
            raise ValueError("Inputs must have the same length for XOR")
        return bytes(x ^ y for x, y in zip(a, b))

    def make_related_pair(self, plaintext: bytes, input_diff: bytes) -> Tuple[bytes, bytes]:
        if len(plaintext) != self.block_size_bytes:
            raise ValueError(
                f"plaintext must be {self.block_size_bytes} bytes, got {len(plaintext)}"
            )
        if len(input_diff) != self.block_size_bytes:
            raise ValueError(
                f"input_diff must be {self.block_size_bytes} bytes, got {len(input_diff)}"
            )
        paired = self.xor_bytes(plaintext, input_diff)
        return plaintext, paired

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        return self.adapter.encrypt_block(plaintext, key)

    def encrypt_rounds(self, plaintext: bytes, key: bytes, rounds: int) -> bytes:
        return self.adapter.encrypt_rounds(plaintext, key, rounds)

    def encrypt_pair_rounds(
        self,
        pt0: bytes,
        pt1: bytes,
        key: bytes,
        rounds: int,
    ) -> Tuple[bytes, bytes]:
        ct0 = self.encrypt_rounds(pt0, key, rounds)
        ct1 = self.encrypt_rounds(pt1, key, rounds)
        return ct0, ct1

    @staticmethod
    def bytes_to_bits(x: bytes) -> np.ndarray:
        arr = np.frombuffer(x, dtype=np.uint8)
        return np.unpackbits(arr)

    def vectorize_pair(self, ct0: bytes, ct1: bytes) -> np.ndarray:
  
        if len(ct0) != self.block_size_bytes or len(ct1) != self.block_size_bytes:
            raise ValueError("Ciphertexts have invalid length")

        diff = self.xor_bytes(ct0, ct1)

        v0 = self.bytes_to_bits(ct0)
        v1 = self.bytes_to_bits(ct1)
        vd = self.bytes_to_bits(diff)

        return np.concatenate([v0, v1, vd]).astype(np.uint8)

    def feature_size(self) -> int:
        return self.block_size_bits * 3