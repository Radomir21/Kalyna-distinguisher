"""
experiment_runner_full.py

Повний набір експериментів для магістерської роботи:
"Нейро-розрізнювач для блокового шифру Калина"

Охоплює завдання 1-5 дипломної роботи:
  1. Різні підмножини шифрованих даних (повний шифротекст, рядок, стовпець, байти)
  2. Навчання для 1, 2 і 3 раундів
  3. Залежність точності від кількості зразків
  4. Порівняння fixed_key vs random_key
  5. Збереження результатів для звіту

Архітектура мережі (Gohr 2019 → Zhang et al. 2024):
  Вхід: бітовий вектор пари (C0_sel || C1_sel), довжина = |indices| * 2 * 8
  
  Input [batch, 2*|idx|] 
    → reshape [batch, 2, |idx|*8]
    → permute [batch, |idx|*8, 2]      ← word_size_bits channels, num_blocks=2 sequence
    → Conv1d(1×1, Nf=16) + BN + ReLU
    → 5 × ResBlock(Nf=16, kernel=3)
    → Flatten → Dense(64) → Dense(64) → Dense(1) → sigmoid
"""

from __future__ import annotations

import csv
import random
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset, random_split

# Додаємо корінь проєкту до шляху, якщо запускається безпосередньо
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from project.backend.kalyna_backend import KalynaBackend
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher
from project.data.dataset_builder import (
    SubsetType,
    generate_dataset,
    model_input_params,
    DEFAULT_INPUT_DIFF,
    EXPERIMENT_CONFIGS,
)

# ---------------------------------------------------------------------------
# Глобальні гіперпараметри
# ---------------------------------------------------------------------------

SEED = 42
BATCH_SIZE = 512
LEARNING_RATE = 1e-3
TRAIN_RATIO = 0.8

RESULTS_DIR = Path("results")

# ---------------------------------------------------------------------------
# Структура результату одного експерименту
# ---------------------------------------------------------------------------

@dataclass
class ExperimentResult:
    subset_desc: str
    rounds: int
    n_samples: int
    epochs: int
    fixed_key: bool
    best_val_acc: float
    best_val_loss: float
    final_val_acc: float
    train_time_sec: float


# ---------------------------------------------------------------------------
# Допоміжні функції
# ---------------------------------------------------------------------------

def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def evaluate(model, loader, criterion, device) -> Tuple[float, float]:
    """Обчислює loss і accuracy на вибірці без оновлення градієнтів."""
    model.eval()
    total_loss = 0.0
    total_correct = 0
    total = 0
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            loss = criterion(logits, yb)
            total_loss += loss.item() * xb.size(0)
            preds = (torch.sigmoid(logits) >= 0.5).float()
            total_correct += (preds == yb).sum().item()
            total += yb.size(0)
    return total_loss / total, total_correct / total


# ---------------------------------------------------------------------------
# Один експеримент
# ---------------------------------------------------------------------------

def run_experiment(
    backend: KalynaBackend,
    device: torch.device,
    subset: SubsetType,
    byte_indices,
    subset_desc: str,
    rounds: int,
    n_samples: int,
    epochs: int,
    fixed_key: bool,
) -> ExperimentResult:
    """Повний цикл одного експерименту: генерація даних → навчання → оцінка."""

    print(f"\n{'='*70}")
    print(f"Subset: {subset_desc}")
    print(f"Rounds: {rounds} | N: {n_samples} | Epochs: {epochs} | FixedKey: {fixed_key}")

    # --- Генерація датасету ---
    X, y = generate_dataset(
        backend=backend,
        n_samples=n_samples,
        input_diff=DEFAULT_INPUT_DIFF,
        rounds=rounds,
        subset=subset,
        byte_indices=byte_indices,
        fixed_key=fixed_key,
    )
    print(f"  X shape: {X.shape}, y shape: {y.shape}, pos rate: {y.mean():.3f}")

    # --- Побудова DataLoader ---
    X_t = torch.tensor(X, dtype=torch.float32)
    y_t = torch.tensor(y, dtype=torch.float32)
    dataset = TensorDataset(X_t, y_t)
    train_size = int(TRAIN_RATIO * len(dataset))
    val_size = len(dataset) - train_size
    train_ds, val_ds = random_split(dataset, [train_size, val_size])
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)

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

    criterion = torch.nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    # --- Навчання ---
    best_val_acc = 0.0
    best_val_loss = float("inf")
    final_val_acc = 0.0
    t0 = time.time()

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss_sum, train_correct, train_total = 0.0, 0, 0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
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
        final_val_acc = val_acc

        print(
            f"  Epoch {epoch:02d} | "
            f"train_loss={train_loss:.4f} acc={train_acc:.4f} | "
            f"val_loss={val_loss:.4f} acc={val_acc:.4f}"
        )

    elapsed = time.time() - t0

    return ExperimentResult(
        subset_desc=subset_desc,
        rounds=rounds,
        n_samples=n_samples,
        epochs=epochs,
        fixed_key=fixed_key,
        best_val_acc=round(best_val_acc, 6),
        best_val_loss=round(best_val_loss, 6),
        final_val_acc=round(final_val_acc, 6),
        train_time_sec=round(elapsed, 1),
    )


# ---------------------------------------------------------------------------
# Збереження результатів
# ---------------------------------------------------------------------------

def save_csv(results: List[ExperimentResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    print(f"Results saved → {path}")


def print_summary(results: List[ExperimentResult]) -> None:
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"{'Subset':<35} {'R':>3} {'N':>7} {'Ep':>4} {'FixK':>5} {'BestAcc':>9} {'FinalAcc':>9}")
    print("-" * 80)
    for r in results:
        print(
            f"{r.subset_desc[:34]:<35} "
            f"{r.rounds:>3} "
            f"{r.n_samples:>7} "
            f"{r.epochs:>4} "
            f"{str(r.fixed_key):>5} "
            f"{r.best_val_acc:>9.4f} "
            f"{r.final_val_acc:>9.4f}"
        )


# ---------------------------------------------------------------------------
# Профіль відповіді на неправильний ключ (WKRP)
# Wrong Key Response Profile — Section 4 у Zhang et al. (2024).
#
# Ідея: для пари шифротекстів (C0, C1), зашифрованих на r+1 раундах,
# ми перебираємо всі можливі підключі delta і частково дешифруємо
# E^{-1}_{k XOR delta}(C0), E^{-1}_{k XOR delta}(C1),
# після чого подаємо на r-раундовий розрізнювач.
# 
# Правильний ключ (delta=0) дасть найвищий середній score ~ 1.
# Неправильні ключі (delta≠0) дадуть score ~ 0.5.
# ---------------------------------------------------------------------------

def compute_wkrp_profile(
    backend: KalynaBackend,
    model: torch.nn.Module,
    device: torch.device,
    n_pairs: int = 200,
    rounds_inner: int = 1,
    byte_indices: List[int] = None,
) -> None:
    """
    Обчислює Wrong Key Response Profile (WKRP) для 2 байтів підключа.
    
    Реалізація відповідає рис. 5 у Zhang et al. (2024):
      - генеруємо n_pairs пар, зашифрованих на rounds_inner+1 раундах
      - для кожного delta від 0 до 2^16 - 1 (якщо 2 байти):
          частково дешифруємо і подаємо на розрізнювач
          mu_delta = mean(D(E^{-1}_{k XOR delta}(C0), E^{-1}_{k XOR delta}(C1)))
    
    Увага: повна реалізація потребує API часткового дешифрування,
    яке ще не реалізоване. Тут ми показуємо структуру.
    """
    raise NotImplementedError(
        "WKRP потребує часткового дешифрування одного раунду Калини. "
        "Буде реалізовано після додавання kalyna_decrypt_rounds_api до DLL."
    )


# ---------------------------------------------------------------------------
# Дослідження залежності точності від розміру датасету (Завдання 4)
# ---------------------------------------------------------------------------

def sample_size_study(
    backend: KalynaBackend,
    device: torch.device,
    subset: SubsetType,
    byte_indices,
    subset_desc: str,
    rounds: int = 1,
    n_samples_list: Optional[List[int]] = None,
    epochs: int = 10,
) -> List[ExperimentResult]:
    """
    Вивчає залежність між точністю розрізнювача та кількістю зразків.
    
    Відповідає Завданню 4 дипломної роботи.
    """
    if n_samples_list is None:
        # Логарифмічна шкала від 1000 до 100000
        n_samples_list = [1000, 2000, 5000, 10000, 20000, 50000, 100000]

    results = []
    for n in n_samples_list:
        r = run_experiment(
            backend=backend,
            device=device,
            subset=subset,
            byte_indices=byte_indices,
            subset_desc=subset_desc,
            rounds=rounds,
            n_samples=n,
            epochs=epochs,
            fixed_key=False,
        )
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Головна функція
# ---------------------------------------------------------------------------

def main():
    set_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    backend = KalynaBackend()
    all_results: List[ExperimentResult] = []

    # -----------------------------------------------------------------------
    # ЧАСТИНА 1: Основна матриця експериментів
    #   Всі типи підмножин × раунди 1-3 × fixed_key=False
    # -----------------------------------------------------------------------
    print("\n" + "="*70)
    print("PART 1: All subsets × rounds 1-3")
    print("="*70)

    rounds_list = [1, 2, 3]
    n_samples_main = 30000
    epochs_main = 10

    for rounds in rounds_list:
        for subset, byte_idx, desc in EXPERIMENT_CONFIGS:
            r = run_experiment(
                backend=backend,
                device=device,
                subset=subset,
                byte_indices=byte_idx,
                subset_desc=desc,
                rounds=rounds,
                n_samples=n_samples_main,
                epochs=epochs_main,
                fixed_key=False,
            )
            all_results.append(r)
            save_csv(all_results, RESULTS_DIR / "part1_all_subsets.csv")

    # -----------------------------------------------------------------------
    # ЧАСТИНА 2: Вплив фіксованого ключа (fixed_key)
    # -----------------------------------------------------------------------
    print("\n" + "="*70)
    print("PART 2: Fixed key vs random key")
    print("="*70)

    best_configs = [
        (SubsetType.TWO_BYTES, [14, 15], "2 bytes [14,15]"),
        (SubsetType.TWO_BYTES, [0, 13],  "2 bytes [0,13]"),
    ]
    for rounds in [1, 2]:
        for subset, byte_idx, desc in best_configs:
            for fk in [False, True]:
                r = run_experiment(
                    backend=backend,
                    device=device,
                    subset=subset,
                    byte_indices=byte_idx,
                    subset_desc=desc,
                    rounds=rounds,
                    n_samples=n_samples_main,
                    epochs=epochs_main,
                    fixed_key=fk,
                )
                all_results.append(r)
    save_csv(all_results, RESULTS_DIR / "part2_fixed_key.csv")

    # -----------------------------------------------------------------------
    # ЧАСТИНА 3: Залежність від розміру датасету (Завдання 4)
    # -----------------------------------------------------------------------
    print("\n" + "="*70)
    print("PART 3: Sample size study (best subset, 1 round)")
    print("="*70)

    sample_results = sample_size_study(
        backend=backend,
        device=device,
        subset=SubsetType.TWO_BYTES,
        byte_indices=[14, 15],
        subset_desc="2 bytes [14,15]",
        rounds=1,
        n_samples_list=[1000, 2000, 5000, 10000, 20000, 50000, 100000],
        epochs=10,
    )
    all_results.extend(sample_results)
    save_csv(all_results, RESULTS_DIR / "part3_sample_size.csv")

    # -----------------------------------------------------------------------
    # Фінальний звіт
    # -----------------------------------------------------------------------
    print_summary(all_results)
    save_csv(all_results, RESULTS_DIR / "all_experiments.csv")
    print("\nDone.")


if __name__ == "__main__":
    main()