import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from project.backend.kalyna_backend import KalynaBackend
from project.data.dataset_builder import (
    generate_dataset, feature_size, SubsetType, DEFAULT_INPUT_DIFF,
)


def main():
    backend = KalynaBackend()

    X, y = generate_dataset(
        backend=backend,
        n_samples=8,
        input_diff=DEFAULT_INPUT_DIFF,
        rounds=2,
        subset=SubsetType.FULL,
        fixed_key=False,
    )

    print("X shape:", X.shape)
    print("y shape:", y.shape)
    print("feature size:", feature_size(SubsetType.FULL))
    print("first label:", y[0])
    print("first sample first 32 bits:", X[0][:32])


if __name__ == "__main__":
    main()
