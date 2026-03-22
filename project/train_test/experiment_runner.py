from __future__ import annotations

import csv
import random
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset, random_split

from project.backend.kalyna_backend import KalynaBackend
from project.data.dataset_builder import generate_dataset_selected_bytes
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher


SEED = 42
N_SAMPLES = 30000
BATCH_SIZE = 512
EPOCHS = 8
LEARNING_RATE = 1e-3

ROUNDS_LIST = [1, 2]
BYTE_INDICES_LIST = [
    [0, 13],
    [0, 1],
    [14, 15],
]
FIXED_KEY_LIST = [False, True]

RESULTS_DIR = Path("project/results")
RESULTS_CSV = RESULTS_DIR / "experiment_results.csv"


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    total_correct = 0
    total = 0

    with torch.no_grad():
        for xb, yb in loader:
            xb = xb.to(device)
            yb = yb.to(device)

            logits = model(xb)
            loss = criterion(logits, yb)

            total_loss += loss.item() * xb.size(0)

            preds = (torch.sigmoid(logits) >= 0.5).float()
            total_correct += (preds == yb).sum().item()
            total += yb.size(0)

    return total_loss / total, total_correct / total


def run_single_experiment(
    backend: KalynaBackend,
    device: torch.device,
    rounds: int,
    byte_indices: list[int],
    fixed_key: bool,
    n_samples: int = N_SAMPLES,
    epochs: int = EPOCHS,
    batch_size: int = BATCH_SIZE,
    learning_rate: float = LEARNING_RATE,
):
    input_diff = bytes.fromhex("00000000000000000000000000000001")

    print("=" * 80)
    print(
        f"Running experiment: rounds={rounds}, "
        f"byte_indices={byte_indices}, fixed_key={fixed_key}"
    )

    X, y = generate_dataset_selected_bytes(
        backend=backend,
        n_samples=n_samples,
        input_diff=input_diff,
        rounds=rounds,
        byte_indices=byte_indices,
        fixed_key=fixed_key,
    )

    print("Dataset generated:")
    print("  X shape:", X.shape)
    print("  y shape:", y.shape)

    X_tensor = torch.tensor(X, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.float32)

    dataset = TensorDataset(X_tensor, y_tensor)

    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    word_size_bits = len(byte_indices) * 8

    model = AESLikeResNetDistinguisher(
        num_blocks=2,
        word_size_bits=word_size_bits,
        num_filters=16,
        depth=5,
        dense1=64,
        dense2=64,
        kernel_size=3,
    ).to(device)

    criterion = torch.nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)

    best_val_acc = 0.0
    best_val_loss = float("inf")

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss_sum = 0.0
        train_correct = 0
        train_total = 0

        for xb, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)

            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()

            train_loss_sum += loss.item() * xb.size(0)

            preds = (torch.sigmoid(logits) >= 0.5).float()
            train_correct += (preds == yb).sum().item()
            train_total += yb.size(0)

        train_loss = train_loss_sum / train_total
        train_acc = train_correct / train_total

        val_loss, val_acc = evaluate(model, val_loader, criterion, device)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
        if val_loss < best_val_loss:
            best_val_loss = val_loss

        print(
            f"Epoch {epoch:02d} | "
            f"train_loss={train_loss:.4f} train_acc={train_acc:.4f} | "
            f"val_loss={val_loss:.4f} val_acc={val_acc:.4f}"
        )

    return {
        "rounds": rounds,
        "byte_indices": str(byte_indices),
        "fixed_key": fixed_key,
        "n_samples": n_samples,
        "epochs": epochs,
        "best_val_acc": round(best_val_acc, 6),
        "best_val_loss": round(best_val_loss, 6),
    }


def save_results_to_csv(results: list[dict], csv_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "rounds",
        "byte_indices",
        "fixed_key",
        "n_samples",
        "epochs",
        "best_val_acc",
        "best_val_loss",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_summary(results: list[dict]) -> None:
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    header = (
        f"{'rounds':<8}"
        f"{'byte_indices':<18}"
        f"{'fixed_key':<12}"
        f"{'best_val_acc':<14}"
        f"{'best_val_loss':<14}"
    )
    print(header)
    print("-" * len(header))

    for row in results:
        print(
            f"{str(row['rounds']):<8}"
            f"{str(row['byte_indices']):<18}"
            f"{str(row['fixed_key']):<12}"
            f"{str(row['best_val_acc']):<14}"
            f"{str(row['best_val_loss']):<14}"
        )


def main():
    set_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("device:", device)

    backend = KalynaBackend()
    results = []

    for rounds in ROUNDS_LIST:
        for byte_indices in BYTE_INDICES_LIST:
            for fixed_key in FIXED_KEY_LIST:
                result = run_single_experiment(
                    backend=backend,
                    device=device,
                    rounds=rounds,
                    byte_indices=byte_indices,
                    fixed_key=fixed_key,
                )
                results.append(result)

                save_results_to_csv(results, RESULTS_CSV)
                print(f"Intermediate results saved to: {RESULTS_CSV}")

    print_summary(results)
    save_results_to_csv(results, RESULTS_CSV)

    print("\nDone.")
    print(f"Results saved to: {RESULTS_CSV}")


if __name__ == "__main__":
    main()