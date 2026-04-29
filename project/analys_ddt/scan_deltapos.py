#!/usr/bin/env python3
"""
=============================================================================
Шаг 1. Скрининг однобайтовых входных разностей для Калины-128/128
=============================================================================

Цель: перебрать все 16 байтовых позиций состояния Калины с несколькими
значениями ΔI и быстро определить, какие позиции дают accuracy > 50%.

Опирается на:
  - project.backend.kalyna_backend.KalynaBackend
  - project.data.dataset_builder.generate_dataset_selected_bytes
  - project.models.neuro_distinguisher.AESLikeResNetDistinguisher

Логика по статьям:
  - Gohr (CRYPTO 2019): базовый подход "real vs random"
  - Zhang et al. (Diff_Neuro): однобайтовая разность Δ=0x80 для AES
  - Chen et al.: перебор однобитовых разностей Δ[i] для крупноблочных шифров
  - Адаптация для Калины: Δ=0x01 (малое значение из-за Add64 pre-whitening)

Схема Калины-128/128 (ДСТУ 7624:2014):
  Состояние: матрица 8×2 (8 строк, 2 столбца = 16 байт)
  Нумерация байт (column-major, как в стандарте):
    col 0: байты [0, 1, 2, 3, 4, 5, 6, 7]
    col 1: байты [8, 9, 10, 11, 12, 13, 14, 15]

  Pre-whitening: Add64 (mod 2^64 по 64-битным словам, а не XOR!)
  Раунды 1..Nr-1: SB → SR → MC → XOR_key
  Раунд Nr:       SB → SR → MC → Add64_key

  MDS-матрица 8×8 (Branch Number = 9):
    Один активный байт в столбце → все 8 байт столбца после MixColumns

Почему Δ=0x01, а не Δ=0x80:
  Pre-whitening в Калине — это модульное сложение (Add64), а не XOR.
  Вероятность сохранения XOR-разности после Add64:
    P(сохранение) ≈ 1 - δ/256
  Для δ=0x01: P ≈ 255/256 ≈ 99.6%  ← отлично
  Для δ=0x80: P ≈ 128/256 = 50%    ← плохо!
  Поэтому используем малые значения Δ-байта.
=============================================================================
"""

from __future__ import annotations

import csv
import json
import os
import random
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

# Гарантировать доступ к пакету project при запуске из поддиректории.
# (Структура: Kalyna-distinguisher/project/analys_ddt/scan_deltapos.py)
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# ─── Импорты из вашего проекта ───────────────────────────────────────────────
from project.backend.kalyna_backend import KalynaBackend
from project.data.dataset_builder import generate_dataset_selected_bytes
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher


# =============================================================================
# Конфигурация скрининга
# =============================================================================

BLOCK_SIZE_BYTES = 16          # Калина-128: 16 байт
KEY_SIZE_BYTES = 16            # Ключ 128 бит

# Значения Δ-байта для перебора
# 0x01 — минимальное, сохраняется через Add64 с P≈99.6%
# 0x02, 0x03 — тоже малые, P > 99%
# 0x80 — для сравнения (ожидаем худший результат из-за Add64)
DELTA_VALUES = [0x80,0x01, 0x02, 0x03]

# Позиции байт для перебора (все 16)
BYTE_POSITIONS = list(range(BLOCK_SIZE_BYTES))

# Раунды для тестирования
ROUNDS_LIST = [2]

# Какие байты шифртекста подавать различителю
# По аналогии с Zhang et al.: пары связанных байт
# Для Калины-128 (8×2 state, column-major):
#   Столбец 0: байты 0-7
#   Столбец 1: байты 8-15
# После 1 раунда: Δ в байте i (столбец j) → все 8 байт столбца j
# После SR+MC на 2-м раунде — распространение в оба столбца
CIPHERTEXT_BYTE_PAIRS = [
    [0, 1],     # первые 2 байта столбца 0
    [0, 8],     # по 1 байту из каждого столбца
    list(range(8))     # весь столбец 0    # полный шифртекст
]

# Параметры обучения (быстрый скрининг — малый датасет, мало эпох)
SCREENING_SAMPLES = 500_000    # 5×10^5 (быстро, но достаточно для скрининга)
SCREENING_EPOCHS = 5
SCREENING_BATCH_SIZE = 1000
SCREENING_LR = 1e-3

# Полное обучение лучших кандидатов
FULL_SAMPLES = 5_000_000       # 5×10^6
FULL_EPOCHS = 20
FULL_BATCH_SIZE = 1000

SEED = 42
RESULTS_DIR = Path("results/delta_screening")


# =============================================================================
# Вспомогательные функции
# =============================================================================

def set_seed(seed: int):
    """Фиксация генератора для воспроизводимости."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def make_input_diff(byte_pos: int, delta_val: int, block_size: int = 16) -> bytes:
    """
    Создать входную разность: delta_val в позиции byte_pos, нули в остальных.

    Пример для byte_pos=0, delta_val=0x01:
      b'\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'

    Для Калины-128 состояние заполняется column-major:
      байт 0 → state[0,0] (строка 0, столбец 0) — младший байт 1-го слова
      байт 7 → state[7,0] (строка 7, столбец 0) — старший байт 1-го слова
      байт 8 → state[0,1] (строка 0, столбец 1) — младший байт 2-го слова

    Важно: малый delta_val (0x01) в младших байтах слова (pos=0 или pos=8)
    минимизирует влияние переноса в Add64 pre-whitening.
    """
    diff = bytearray(block_size)
    diff[byte_pos] = delta_val
    return bytes(diff)


def get_device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


# =============================================================================
# Обучение и оценка (адаптировано из вашего experiment_runner.py)
# =============================================================================

def train_and_evaluate(
    backend: KalynaBackend,
    device: torch.device,
    input_diff: bytes,
    rounds: int,
    ct_byte_indices: List[int],
    n_samples: int,
    epochs: int,
    batch_size: int,
    lr: float,
) -> dict:
    """
    Обучить различитель и вернуть метрики.

    Реализует схему из Gohr (CRYPTO 2019), Sec. 4.3:
      - Генерация данных: real (label=1) vs random (label=0)
      - ResNet с MSE loss + L2 regularization
      - Циклический learning rate

    Возвращает: {acc, tpr, tnr, loss, time_sec}
    """
    # ── Генерация данных ──────────────────────────────────────────────────
    t0 = time.time()

    X, y = generate_dataset_selected_bytes(
        backend=backend,
        n_samples=n_samples,
        input_diff=input_diff,
        rounds=rounds,
        byte_indices=ct_byte_indices,
        fixed_key=False,  # случайные ключи — как у Gohr
    )

    data_time = time.time() - t0

    # ── Разделение train/val (90/10) ──────────────────────────────────────
    n_val = max(n_samples // 10, 1000)
    n_train = n_samples - n_val

    X_train, X_val = X[:n_train], X[n_train:]
    y_train, y_val = y[:n_train], y[n_train:]

    train_ds = TensorDataset(
        torch.from_numpy(X_train).float(),
        torch.from_numpy(y_train),
    )
    val_ds = TensorDataset(
        torch.from_numpy(X_val).float(),
        torch.from_numpy(y_val),
    )

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

    # ── Модель ────────────────────────────────────────────────────────────
    # Модель принимает (batch, num_blocks * word_size_bits)
    # и делает reshape → (batch, num_blocks, word_size_bits)
    # ct0_selected + ct1_selected: 2 * len(ct_byte_indices) байт, по 8 бит каждый
    num_blocks = 2 * len(ct_byte_indices)
    word_size_bits = 8

    model = AESLikeResNetDistinguisher(
        num_blocks=num_blocks,
        word_size_bits=word_size_bits,
        num_filters=32,
        depth=5,
        dense1=64,
        dense2=64,
    ).to(device)

    # MSE loss + L2 regularization (как у Gohr, λ=10^-5)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)

    # Циклический LR (из Gohr):
    # li = α + ((n-i) mod (n+1)) / n * (β - α)
    # α=10^-4, β=2×10^-3, n=9
    def cyclic_lr(epoch):
        alpha, beta, n = 1e-4, 2e-3, 9
        return (alpha + ((n - epoch % (n + 1)) / n) * (beta - alpha)) / lr

    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, cyclic_lr)

    # ── Обучение ──────────────────────────────────────────────────────────
    t0 = time.time()
    best_val_acc = 0.0
    best_metrics = {}

    for epoch in range(epochs):
        model.train()
        for xb, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)

            pred = torch.sigmoid(model(xb))
            loss = criterion(pred, yb)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        scheduler.step()

        # ── Валидация ─────────────────────────────────────────────────────
        model.eval()
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for xb, yb in val_loader:
                xb = xb.to(device)
                pred = torch.sigmoid(model(xb)).cpu().numpy().flatten()
                all_preds.append(pred)
                all_labels.append(yb.numpy())

        preds = np.concatenate(all_preds)
        labels = np.concatenate(all_labels)

        binary_preds = (preds >= 0.5).astype(float)
        acc = np.mean(binary_preds == labels)

        # TPR = recall на положительном классе
        pos_mask = labels == 1
        neg_mask = labels == 0
        tpr = np.mean(binary_preds[pos_mask] == 1) if pos_mask.sum() > 0 else 0.0
        tnr = np.mean(binary_preds[neg_mask] == 0) if neg_mask.sum() > 0 else 0.0
        mse = np.mean((preds - labels) ** 2)

        if acc > best_val_acc:
            best_val_acc = acc
            best_metrics = {
                "acc": float(acc),
                "tpr": float(tpr),
                "tnr": float(tnr),
                "mse": float(mse),
                "best_epoch": epoch + 1,
            }

    train_time = time.time() - t0

    best_metrics["data_gen_sec"] = data_time
    best_metrics["train_sec"] = train_time
    best_metrics["total_sec"] = data_time + train_time

    return best_metrics


# =============================================================================
# Фаза 1: Быстрый скрининг всех позиций
# =============================================================================

def run_screening(backend: KalynaBackend, device: torch.device) -> List[dict]:
    """
    Для каждой комбинации (byte_pos, delta_val, rounds, ct_bytes):
      - Обучить лёгкую модель
      - Записать accuracy

    Это аналог процедуры из Chen et al. (Sec. 4.1):
      "Train b neural distinguishers with input difference Δ[i]
       for i ∈ [0, b-1]"
    Только мы перебираем не только позиции, но и значения Δ,
    потому что для Калины Add64 делает не все значения равноценными.
    """

    results = []
    total_experiments = (
        len(BYTE_POSITIONS)
        * len(DELTA_VALUES)
        * len(ROUNDS_LIST)
        * len(CIPHERTEXT_BYTE_PAIRS)
    )
    current = 0

    print("=" * 80)
    print("ФАЗА 1: СКРИНИНГ ВХОДНЫХ РАЗНОСТЕЙ ДЛЯ КАЛИНЫ-128/128")
    print(f"Всего экспериментов: {total_experiments}")
    print(f"Образцов на эксперимент: {SCREENING_SAMPLES:,}")
    print(f"Эпох: {SCREENING_EPOCHS}")
    print(f"Устройство: {device}")
    print("=" * 80)

    for rounds in ROUNDS_LIST:
        for delta_val in DELTA_VALUES:
            for byte_pos in BYTE_POSITIONS:
                input_diff = make_input_diff(byte_pos, delta_val)

                for ct_bytes in CIPHERTEXT_BYTE_PAIRS:
                    current += 1
                    exp_name = (
                        f"r={rounds} "
                        f"Δ_pos={byte_pos} "
                        f"Δ_val=0x{delta_val:02x} "
                        f"ct_bytes={ct_bytes}"
                    )
                    print(f"\n[{current}/{total_experiments}] {exp_name}")

                    set_seed(SEED)

                    try:
                        metrics = train_and_evaluate(
                            backend=backend,
                            device=device,
                            input_diff=input_diff,
                            rounds=rounds,
                            ct_byte_indices=ct_bytes,
                            n_samples=SCREENING_SAMPLES,
                            epochs=SCREENING_EPOCHS,
                            batch_size=SCREENING_BATCH_SIZE,
                            lr=SCREENING_LR,
                        )
                    except Exception as e:
                        print(f"  ОШИБКА: {e}")
                        metrics = {"acc": -1, "tpr": -1, "tnr": -1, "error": str(e)}

                    row = {
                        "rounds": rounds,
                        "delta_byte_pos": byte_pos,
                        "delta_byte_val": f"0x{delta_val:02x}",
                        "ct_byte_indices": str(ct_bytes),
                        "n_ct_bytes": len(ct_bytes),
                        **metrics,
                    }
                    results.append(row)

                    acc_str = f"{metrics['acc']:.4f}" if metrics['acc'] >= 0 else "ERROR"
                    tpr_str = f"{metrics.get('tpr', 0):.4f}"
                    tnr_str = f"{metrics.get('tnr', 0):.4f}"
                    print(f"  → Acc={acc_str}  TPR={tpr_str}  TNR={tnr_str}")

                    # Ранний стоп: если accuracy > 0.90, это очень хороший кандидат
                    if metrics.get("acc", 0) > 0.90:
                        print("  ★ ОТЛИЧНЫЙ КАНДИДАТ!")

    return results


# =============================================================================
# Фаза 2: Анализ результатов и выбор лучших кандидатов
# =============================================================================

def analyze_results(results: List[dict]) -> List[dict]:
    """
    Отсортировать результаты по accuracy, показать топ-10.

    Критерии отбора (по Chen et al., Sec. 3.1):
    1. Accuracy значительно выше 50% (чем выше — тем лучше)
    2. Предпочтение малым ct_byte_indices (меньше бит → легче multi-stage)
    3. Предпочтение малым delta_val (устойчивость к Add64)
    """

    # Отсортировать по accuracy (убывание)
    valid = [r for r in results if r.get("acc", -1) > 0]
    ranked = sorted(valid, key=lambda r: r["acc"], reverse=True)

    print("\n" + "=" * 80)
    print("ТОП-10 ЛУЧШИХ КОМБИНАЦИЙ (ΔI, позиция, байты шифртекста)")
    print("=" * 80)
    print(f"{'#':>3} {'Rounds':>6} {'Δ_pos':>6} {'Δ_val':>8} "
          f"{'CT bytes':>18} {'Acc':>8} {'TPR':>8} {'TNR':>8}")
    print("-" * 80)

    for i, row in enumerate(ranked[:10]):
        print(
            f"{i+1:>3} "
            f"{row['rounds']:>6} "
            f"{row['delta_byte_pos']:>6} "
            f"{row['delta_byte_val']:>8} "
            f"{row['ct_byte_indices']:>18} "
            f"{row['acc']:>8.4f} "
            f"{row.get('tpr', 0):>8.4f} "
            f"{row.get('tnr', 0):>8.4f}"
        )

    # Лучшие кандидаты для полного обучения
    top_candidates = ranked[:5]

    print("\n" + "=" * 80)
    print("РЕКОМЕНДАЦИИ ДЛЯ ПОЛНОГО ОБУЧЕНИЯ:")
    print("=" * 80)

    for i, row in enumerate(top_candidates):
        pos = row["delta_byte_pos"]
        col = pos // 8  # столбец Калины (0 или 1)
        row_in_state = pos % 8  # строка в состоянии

        print(f"\n  Кандидат {i+1}:")
        print(f"    Входная разность: байт {pos} (state[{row_in_state},{col}]), "
              f"значение={row['delta_byte_val']}")
        print(f"    Раундов: {row['rounds']}")
        print(f"    Байты шифртекста: {row['ct_byte_indices']}")
        print(f"    Скрининг accuracy: {row['acc']:.4f}")

        # Анализ влияния Add64
        delta_int = int(row["delta_byte_val"], 16)
        add64_preserve_prob = (256 - delta_int) / 256
        byte_in_word = pos % 8  # позиция внутри 64-битного слова
        print(f"    P(Δ сохраняется через Add64): {add64_preserve_prob:.3f}")
        if byte_in_word > 0:
            print(f"    ⚠ Байт {pos} не младший в 64-бит слове "
                  f"(pos_in_word={byte_in_word})")

    return top_candidates


# =============================================================================
# Сохранение результатов
# =============================================================================

def save_results(results: List[dict], phase: str = "screening"):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # CSV
    csv_path = RESULTS_DIR / f"{phase}_{timestamp}.csv"
    if results:
        keys = results[0].keys()
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        print(f"\nCSV сохранён: {csv_path}")

    # JSON (для программного анализа)
    json_path = RESULTS_DIR / f"{phase}_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"JSON сохранён: {json_path}")


# =============================================================================
# Главная функция
# =============================================================================

def main():
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  Скрининг входных разностей для Калины-128/128                 ║")
    print("║  Дифференциально-нейронный криптоанализ (ДСТУ 7624:2014)       ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    set_seed(SEED)
    device = get_device()
    print(f"Устройство: {device}")

    # Инициализация бэкенда Калины (ваш C binding)
    backend = KalynaBackend()
    print(f"Размер блока: {backend.block_size_bytes} байт "
          f"({backend.block_size_bits} бит)")
    print(f"Размер ключа: {backend.key_size_bytes} байт")

    # ── Фаза 1: Скрининг ─────────────────────────────────────────────────
    results = run_screening(backend, device)
    save_results(results, phase="screening")

    # ── Анализ ────────────────────────────────────────────────────────────
    top_candidates = analyze_results(results)
    save_results(top_candidates, phase="top_candidates")

    print("\n✓ Скрининг завершён!")
    print("  Следующий шаг: запустить полное обучение лучших кандидатов")
    print("  с N_SAMPLES=5×10^6, EPOCHS=20")


if __name__ == "__main__":
    main()