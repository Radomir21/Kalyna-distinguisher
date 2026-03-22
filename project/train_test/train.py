from __future__ import annotations

import random
import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset, random_split

from project.backend.kalyna_backend import KalynaBackend
from project.data.dataset_builder import generate_dataset_selected_bytes
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher


SEED = 42
N_SAMPLES = 50000
ROUNDS = 1
FIXED_KEY = False
BYTE_INDICES = [0, 13]   # как в AES-репозитории стартуем с 2 байтов
BATCH_SIZE = 512
EPOCHS = 15
LEARNING_RATE = 1e-3


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


def main():
    set_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("device:", device)

    backend = KalynaBackend()

    # AES-like: локальная фиксированная входная разность
    input_diff = bytes.fromhex("00000000000000000000000000000001")

    X, y = generate_dataset_selected_bytes(
        backend=backend,
        n_samples=N_SAMPLES,
        input_diff=input_diff,
        rounds=ROUNDS,
        byte_indices=BYTE_INDICES,
        fixed_key=FIXED_KEY,
    )

    print("X shape:", X.shape)
    print("y shape:", y.shape)

    X_tensor = torch.tensor(X, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.float32)

    dataset = TensorDataset(X_tensor, y_tensor)

    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)

    word_size_bits = len(BYTE_INDICES) * 8

    model = AESLikeResNetDistinguisher(
        num_blocks=2,           # ct0 и ct1
        word_size_bits=word_size_bits,
        num_filters=16,
        depth=5,
        dense1=64,
        dense2=64,
        kernel_size=3,
    ).to(device)

    criterion = torch.nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    best_val_acc = 0.0
    best_path = "kalyna_aes_like_resnet_best.pt"

    for epoch in range(1, EPOCHS + 1):
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
            torch.save(model.state_dict(), best_path)

        print(
            f"Epoch {epoch:02d} | "
            f"train_loss={train_loss:.4f} train_acc={train_acc:.4f} | "
            f"val_loss={val_loss:.4f} val_acc={val_acc:.4f}"
        )

    print("Best val_acc:", round(best_val_acc, 6))
    print("Best model saved to:", best_path)


if __name__ == "__main__":
    main()