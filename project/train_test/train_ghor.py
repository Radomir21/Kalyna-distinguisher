"""
train_gohr_exact.py

Навчання нейро-розрізнювача з точними гіперпараметрами зі статей:

  Gohr (CRYPTO 2019), Section 4.3 "Basic Training Pipeline":
    - N = 10^7 тренувальних зразків
    - Validation: останні 10^6 зразків з тренувального набору
    - Test set: окремі 10^6 зразків (не використовувались під час навчання)
    - Batch size = 5000
    - Epochs = 200
    - Loss = MSE + L2 (c = 10^-5)
    - Optimizer = Adam (default parameters)
    - Cyclic LR: l_i = α + ((n-i) mod (n+1) / n) * (β-α)
                 α = 10^-4, β = 2*10^-3, n = 9
    - Зберігається модель з найменшим validation loss

  Zhang et al. (IEICE 2024), Section 2.3:
    - N = 10^7, M = 10^6 test
    - Batch size = 1000
    - Epochs = 20
    - Loss = MSE + L2 (λ = 10^-5)
    - Той самий cyclic LR
    - Зберігається модель з найменшим validation loss

Ми реалізуємо обидва режими через параметр MODE.
За замовчуванням використовуємо Zhang (20 епох, batch=1000) — швидший,
але з повним N=10^7.

ПРИМІТКА щодо MSE vs BCE:
  Gohr та Zhang використовують MSE (mean squared error) з мітками {0, 1}.
  Математично при бінарній класифікації та sigmoid-виході:
    BCE = -[y*log(p) + (1-y)*log(1-p)]
    MSE = (y - p)^2
  MSE є більш м'якою (менш агресивною) функцією — градієнти менші,
  навчання стабільніше. Саме тому Gohr обрав MSE.
"""

from __future__ import annotations

import csv
import random
import sys
import time
from pathlib import Path
from typing import List, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from project.backend.kalyna_backend import KalynaBackend
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher
from project.data.dataset_builder import (
    SubsetType,
    generate_dataset,
    model_input_params,
    DEFAULT_INPUT_DIFF,
)

# ---------------------------------------------------------------------------
# Конфігурація — вибери MODE = "zhang" або "gohr"
# ---------------------------------------------------------------------------

MODE = "zhang"          # "zhang" = 20 epoch, batch=1000 | "gohr" = 200 epoch, batch=5000

if MODE == "zhang":
    # Zhang et al. (IEICE 2024), Section 2.3
    N_TRAIN      = 10_000   # 10^7
    N_VAL        = 1_000    # 10^6 (частина тренувального набору)
    N_TEST       = 1_000    # 10^6 окремий тестовий набір
    BATCH_SIZE   = 1_00
    EPOCHS       = 10
else:
    # Gohr (CRYPTO 2019), Section 4.3
    N_TRAIN      = 10_000
    N_VAL        = 1_000
    N_TEST       = 1_000
    BATCH_SIZE   = 1_000
    EPOCHS       = 100

# Cyclic LR параметри (однакові у Gohr та Zhang)
LR_ALPHA     = 1e-4     # мінімальний LR
LR_BETA      = 2e-3     # максимальний LR
LR_N         = 9        # цикл кожні n+1=10 епох

# L2 regularization
L2_LAMBDA    = 1e-5

SEED         = 42
RESULTS_DIR  = Path("results_gohr")

# ---------------------------------------------------------------------------
# Конфігурації для запуску (починаємо з найкращих підмножин)
# ---------------------------------------------------------------------------

CONFIGS = [
    # (subset, byte_indices, description, rounds)
    # --- 1 раунд: перевірка коректності ---
    (SubsetType.TWO_BYTES, [14, 15], "2bytes_14_15", 1),
    (SubsetType.ONE_BYTE,  [15],     "1byte_15",     1),
    # --- 2 раунди: головне питання ---
    (SubsetType.FULL,      None,     "full_ct",      2),
    (SubsetType.TWO_BYTES, [14, 15], "2bytes_14_15", 2),
    (SubsetType.ROW_3,     None,     "row3",         2),
    (SubsetType.COL_3,     None,     "col3",         2),
    # --- 3 раунди ---
    (SubsetType.FULL,      None,     "full_ct",      3),
    (SubsetType.ROW_3,     None,     "row3",         3),
]


# ---------------------------------------------------------------------------
# Cyclic Learning Rate (точна формула з Gohr / Zhang)
# ---------------------------------------------------------------------------

def cyclic_lr(epoch_idx: int, alpha: float, beta: float, n: int) -> float:
    """
    Cyclic learning rate schedule (Gohr, Section 4.3; Zhang, Section 2.3).

    Формула:
        l_i = alpha + ((n - i) mod (n+1)) / n * (beta - alpha)

    де i — номер епохи (0-based), n = 9.

    Поведінка:
        epoch 0:  l = beta        = 2e-3  (максимум)
        epoch 1:  l = beta - step
        ...
        epoch 9:  l = alpha       = 1e-4  (мінімум)
        epoch 10: l = beta        = 2e-3  (знову максимум — новий цикл)
    """
    return alpha + ((n - epoch_idx) % (n + 1)) / n * (beta - alpha)


def make_lr_scheduler(optimizer, alpha, beta, n):
    """LambdaLR wrapper для cyclic LR."""
    def lr_lambda(epoch_idx):
        target_lr = cyclic_lr(epoch_idx, alpha, beta, n)
        return target_lr / LR_BETA  # повертаємо множник відносно base_lr=LR_BETA
    return torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)


# ---------------------------------------------------------------------------
# MSE + L2 Loss (точна конфігурація з Gohr / Zhang)
# ---------------------------------------------------------------------------

class MSEWithL2Loss(nn.Module):
    """
    MSE loss + L2 weight regularization.

    Gohr, Section 4.3: "mean square error loss plus a small penalty based
    on L2 weights regularization (with regularization parameter c = 10^-5)"

    Формула:
        L = MSE(y_pred, y_true) + c * sum(w^2 for w in model.parameters())

    Примітка: в PyTorch L2-регуляризацію можна передати через weight_decay
    в оптимізаторі, що є еквівалентним. Ми реалізуємо явно для прозорості.
    """

    def __init__(self, model: nn.Module, l2_lambda: float = 1e-5):
        super().__init__()
        self.model = model
        self.l2_lambda = l2_lambda
        self.mse = nn.MSELoss()

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        # Застосовуємо sigmoid, щоб отримати ймовірності p ∈ (0,1)
        probs = torch.sigmoid(logits)
        # MSE між передбаченими ймовірностями та мітками {0, 1}
        mse_loss = self.mse(probs, targets)
        # L2 regularization: sum of squared weights
        l2_penalty = sum(p.pow(2).sum() for p in self.model.parameters())
        return mse_loss + self.l2_lambda * l2_penalty


# ---------------------------------------------------------------------------
# Генерація даних великого розміру частинами (для економії RAM)
# ---------------------------------------------------------------------------

def generate_large_dataset(
    backend: KalynaBackend,
    n_total: int,
    rounds: int,
    subset: SubsetType,
    byte_indices,
    chunk_size: int = 50_000,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Генерує датасет великого розміру частинами, щоб не перевищувати RAM.

    10^7 зразків × 32 bits × float32 = ~1.2 GB RAM — прийнятно для
    сучасних систем, але генеруємо чанками для відображення прогресу.
    """
    X_parts, y_parts = [], []
    generated = 0
    t_start = time.time()

    while generated < n_total:
        n_chunk = min(chunk_size, n_total - generated)
        X_chunk, y_chunk = generate_dataset(
            backend=backend,
            n_samples=n_chunk,
            input_diff=DEFAULT_INPUT_DIFF,
            rounds=rounds,
            subset=subset,
            byte_indices=byte_indices,
            fixed_key=False,
        )
        X_parts.append(X_chunk)
        y_parts.append(y_chunk)
        generated += n_chunk

        elapsed = time.time() - t_start
        speed = generated / elapsed
        eta = (n_total - generated) / speed if speed > 0 else 0
        print(
            f"\r  Generating: {generated:>9,} / {n_total:,} "
            f"({100*generated/n_total:.1f}%)  "
            f"ETA: {eta:.0f}s  ",
            end="", flush=True,
        )

    print()  # новий рядок після прогрес-бару
    X = np.concatenate(X_parts, axis=0).astype(np.float32)
    y = np.concatenate(y_parts, axis=0).astype(np.float32)
    return X, y


# ---------------------------------------------------------------------------
# Оцінка моделі
# ---------------------------------------------------------------------------

def evaluate(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
) -> Tuple[float, float, float, float]:
    """
    Повертає (loss, acc, tpr, tnr).

    TPR (True Positive Rate) = sensitivity = P(predict=1 | label=1)
    TNR (True Negative Rate) = specificity = P(predict=0 | label=0)

    Zhang et al. звітують саме TPR і TNR у Таблицях 1-5.
    """
    model.eval()
    total_loss = 0.0
    tp = fp = tn = fn = 0

    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            loss = criterion(logits, yb)
            total_loss += loss.item() * xb.size(0)

            probs = torch.sigmoid(logits)
            preds = (probs >= 0.5).float()

            tp += ((preds == 1) & (yb == 1)).sum().item()
            fp += ((preds == 1) & (yb == 0)).sum().item()
            tn += ((preds == 0) & (yb == 0)).sum().item()
            fn += ((preds == 0) & (yb == 1)).sum().item()

    n = tp + fp + tn + fn
    acc = (tp + tn) / n if n > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    return total_loss / n, acc, tpr, tnr


# ---------------------------------------------------------------------------
# Один повний цикл навчання
# ---------------------------------------------------------------------------

def train_one_config(
    backend: KalynaBackend,
    device: torch.device,
    subset: SubsetType,
    byte_indices,
    desc: str,
    rounds: int,
) -> dict:
    print(f"\n{'='*70}")
    print(f"Config: {desc} | rounds={rounds} | mode={MODE}")
    print(f"N_train={N_TRAIN:,} | N_val={N_VAL:,} | N_test={N_TEST:,}")
    print(f"Batch={BATCH_SIZE} | Epochs={EPOCHS}")
    print(f"LR cyclic α={LR_ALPHA} β={LR_BETA} n={LR_N}")
    print(f"L2 λ={L2_LAMBDA}")

    # --- Генерація тренувального + валідаційного набору ---
    print(f"\nGenerating train+val ({N_TRAIN + N_VAL:,} samples)...")
    t0 = time.time()
    X_all, y_all = generate_large_dataset(
        backend, N_TRAIN + N_VAL, rounds, subset, byte_indices
    )
    print(f"  Done in {time.time()-t0:.1f}s. Shape: {X_all.shape}")

    # Розбиваємо: перші N_TRAIN — тренування, останні N_VAL — валідація
    # (Gohr: "The last 10^6 samples were withheld for validation")
    X_train, y_train = X_all[:N_TRAIN], y_all[:N_TRAIN]
    X_val,   y_val   = X_all[N_TRAIN:], y_all[N_TRAIN:]
    del X_all, y_all  # звільняємо RAM

    # --- Генерація тестового набору ---
    print(f"Generating test ({N_TEST:,} samples)...")
    t0 = time.time()
    X_test, y_test = generate_large_dataset(
        backend, N_TEST, rounds, subset, byte_indices
    )
    print(f"  Done in {time.time()-t0:.1f}s.")

    # --- DataLoader ---
    train_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train)),
        batch_size=BATCH_SIZE, shuffle=True, num_workers=0, pin_memory=True,
    )
    val_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_val), torch.from_numpy(y_val)),
        batch_size=BATCH_SIZE * 4, shuffle=False,
    )
    test_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_test), torch.from_numpy(y_test)),
        batch_size=BATCH_SIZE * 4, shuffle=False,
    )

    # --- Ініціалізація моделі ---
    num_blocks, word_size_bits = model_input_params(subset, byte_indices)
    model = AESLikeResNetDistinguisher(
        num_blocks=num_blocks,
        word_size_bits=word_size_bits,
        num_filters=16,
        depth=5,
        dense1=64,
        dense2=64,
        kernel_size=3,
    ).to(device)

    # --- Loss: MSE + L2 (як у Gohr та Zhang) ---
    criterion = MSEWithL2Loss(model, l2_lambda=L2_LAMBDA)

    # --- Optimizer: Adam з base_lr = LR_BETA (scheduler помножить на lambda) ---
    optimizer = torch.optim.Adam(model.parameters(), lr=LR_BETA)
    scheduler = make_lr_scheduler(optimizer, LR_ALPHA, LR_BETA, LR_N)

    # --- Навчання ---
    best_val_loss = float("inf")
    best_epoch = 0
    best_state = None
    history = []

    save_dir = RESULTS_DIR / "models"
    save_dir.mkdir(parents=True, exist_ok=True)
    best_path = save_dir / f"best_{desc}_r{rounds}.pt"

    total_t = time.time()

    for epoch in range(EPOCHS):
        current_lr = scheduler.get_last_lr()[0] if epoch > 0 else LR_BETA

        model.train()
        train_loss_sum, train_correct, train_n = 0.0, 0, 0

        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()

            with torch.no_grad():
                train_loss_sum += loss.item() * xb.size(0)
                preds = (torch.sigmoid(logits) >= 0.5).float()
                train_correct += (preds == yb).sum().item()
                train_n += yb.size(0)

        scheduler.step()

        train_loss = train_loss_sum / train_n
        train_acc  = train_correct / train_n
        val_loss, val_acc, val_tpr, val_tnr = evaluate(model, val_loader, criterion, device)

        # Зберігаємо найкращу модель за validation loss
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_epoch = epoch + 1
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            torch.save(best_state, best_path)

        history.append({
            "epoch": epoch + 1,
            "lr": round(current_lr, 6),
            "train_loss": round(train_loss, 6),
            "train_acc": round(train_acc, 6),
            "val_loss": round(val_loss, 6),
            "val_acc": round(val_acc, 6),
            "val_tpr": round(val_tpr, 6),
            "val_tnr": round(val_tnr, 6),
        })

        print(
            f"  Epoch {epoch+1:03d}/{EPOCHS} | "
            f"lr={current_lr:.4f} | "
            f"train_loss={train_loss:.5f} acc={train_acc:.4f} | "
            f"val_loss={val_loss:.5f} acc={val_acc:.4f} "
            f"TPR={val_tpr:.4f} TNR={val_tnr:.4f}"
            + (" ← best" if epoch + 1 == best_epoch else "")
        )

    total_time = time.time() - total_t

    # --- Оцінка найкращої моделі на тестовому наборі ---
    print(f"\nLoading best model (epoch {best_epoch})...")
    model.load_state_dict(best_state)
    test_loss, test_acc, test_tpr, test_tnr = evaluate(model, test_loader, criterion, device)

    print(f"\nTEST RESULTS (best model, epoch {best_epoch}):")
    print(f"  Acc={test_acc:.6f}  TPR={test_tpr:.6f}  TNR={test_tnr:.6f}")
    print(f"  Total training time: {total_time:.0f}s")

    # --- Зберігаємо epoch history ---
    hist_path = RESULTS_DIR / f"history_{desc}_r{rounds}.csv"
    with hist_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(history[0].keys()))
        writer.writeheader()
        writer.writerows(history)

    return {
        "config": desc,
        "rounds": rounds,
        "mode": MODE,
        "N_train": N_TRAIN,
        "N_val": N_VAL,
        "N_test": N_TEST,
        "best_epoch": best_epoch,
        "test_acc": round(test_acc, 6),
        "test_tpr": round(test_tpr, 6),
        "test_tnr": round(test_tnr, 6),
        "best_val_loss": round(best_val_loss, 6),
        "train_time_sec": round(total_time, 1),
    }


# ---------------------------------------------------------------------------
# Головна функція
# ---------------------------------------------------------------------------

def main():
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    print(f"Mode: {MODE} | Epochs: {EPOCHS} | Batch: {BATCH_SIZE} | N: {N_TRAIN:,}")

    if device.type == "cuda":
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"GPU RAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    backend = KalynaBackend()
    all_results = []

    for subset, byte_idx, desc, rounds in CONFIGS:
        result = train_one_config(
            backend=backend,
            device=device,
            subset=subset,
            byte_indices=byte_idx,
            desc=desc,
            rounds=rounds,
        )
        all_results.append(result)

        # Зберігаємо проміжні результати
        results_path = RESULTS_DIR / "results_gohr_exact.csv"
        with results_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_results[0].keys()))
            writer.writeheader()
            writer.writerows(all_results)
        print(f"Saved → {results_path}")

    # --- Фінальний звіт у форматі таблиць Zhang et al. ---
    print(f"\n{'='*70}")
    print(f"FINAL RESULTS (mode={MODE}, N={N_TRAIN:,})")
    print(f"{'Config':<20} {'R':>3} {'Acc':>8} {'TPR':>8} {'TNR':>8} {'BestEp':>7}")
    print("-" * 60)
    for r in all_results:
        print(
            f"{r['config'][:19]:<20} "
            f"{r['rounds']:>3} "
            f"{r['test_acc']:>8.4f} "
            f"{r['test_tpr']:>8.4f} "
            f"{r['test_tnr']:>8.4f} "
            f"{r['best_epoch']:>7}"
        )


if __name__ == "__main__":
    main()