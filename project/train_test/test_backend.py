from project.backend.kalyna_backend import KalynaBackend
from project.data.dataset_builder import generate_dataset


def main():
    backend = KalynaBackend()

    input_diff = bytes.fromhex("00000000000000000000000000000001")

    X, y = generate_dataset(
        backend=backend,
        n_samples=8,
        input_diff=input_diff,
        rounds=2,
        fixed_key=False,
    )

    print("X shape:", X.shape)
    print("y shape:", y.shape)
    print("feature size:", backend.feature_size())
    print("first label:", y[0])
    print("first sample first 32 bits:", X[0][:32])


if __name__ == "__main__":
    main()