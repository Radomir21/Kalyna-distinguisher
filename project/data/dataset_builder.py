from __future__ import annotations

from typing import Sequence

import numpy as np

from project.backend.kalyna_backend import KalynaBackend


def generate_dataset_selected_bytes(
    backend: KalynaBackend,
    n_samples: int,
    input_diff: bytes,
    rounds: int,
    byte_indices: Sequence[int],
    fixed_key: bool = False,
):
    """
    AES-like dataset generation:
    - label=1: pt1 = pt0 xor input_diff
    - label=0: pt1 random
    - encrypt both for `rounds`
    - keep only selected ciphertext bytes from ct0 and ct1
    - convert to bits
    """
    if n_samples <= 0:
        raise ValueError("n_samples must be > 0")
    if len(byte_indices) == 0:
        raise ValueError("byte_indices must not be empty")

    X = []
    y = []

    master_key = backend.random_key() if fixed_key else None

    for _ in range(n_samples):
        label = np.random.randint(0, 2)

        key = master_key if fixed_key else backend.random_key()
        pt0 = backend.random_block()

        if label == 1:
            pt0, pt1 = backend.make_related_pair(pt0, input_diff)
        else:
            pt1 = backend.random_block()

        ct0, ct1 = backend.encrypt_pair_rounds(pt0, pt1, key, rounds)
        features = backend.vectorize_selected_bytes(ct0, ct1, byte_indices)

        X.append(features)
        y.append(label)

    X = np.stack(X).astype(np.float32)
    y = np.array(y, dtype=np.float32)

    return X, y