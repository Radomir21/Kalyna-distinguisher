"""
train_diff_neuro.py  (ВИПРАВЛЕНА ВЕРСІЯ)

Точна репліка конфігурації з Diff_Neuro.pdf (Zhang et al., IEICE 2024)
для блокового шифру Калина-128/128.

Параметри взяті дослівно з Section 2.3:
  N        = 1_000_000   (у статті 10^7 -- тут зменшено у 10 разів)
  M (test) =   100_000   (у статті 10^6)
  Bs       = 1_000
  Epochs   = 10
  Loss     = MSE + L2(lambda = 10^-5)
  LR       = cyclic: beta=0.002, alpha=0.0001, n=9
  Save     = best model by validation loss
  Metrics  = Acc, TPR, TNR  (як у Таблицях 1-5 статті)


Конфігурації таблиць з Diff_Neuro.pdf -> адаптовано для Калини:
  Table 1: 2-round, 3-round -- повний шифротекст
  Table 2: 3-round -- один стовпець (= 8 байтів = половина блоку)
  Table 3: 3-round -- два байти (cross-word та same-word)
  Table 4: 2-round -- один байт
  Table 5: 2-round -- два байти (cross-word = головний результат)
"""

from __future__ import annotations

import csv
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

# --- шлях до проєкту ---
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent.parent))

from project.backend.kalyna_backend import KalynaBackend
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher
from project.data.dataset_builder import SubsetType, model_input_params
from project.training_utils import (
    MSEWithL2Loss,
    make_lr_scheduler,
    evaluate,
    generate_chunked_dataset,
)

# ============================================================
# ПАРАМЕТРИ
# ============================================================

N_TRAIN   = 1_000_000   # у статті 10_000_000
N_VAL     =   100_000   # у статті  1_000_000
N_TEST    =   100_000   # у статті  1_000_000

BATCH     = 1_000       # Bs = 1000  (Section 2.3)
EPOCHS    = 10           # у статті 20 epochs  (Section 2.3)

# Cyclic LR (Section 2.3)
LR_BETA   = 2e-3        # beta = 0.002
LR_ALPHA  = 1e-4        # alpha = 0.0001
LR_N      = 9           # n = 9  -> цикл кожні 10 епох

L2_LAM    = 1e-5        # lambda = 10^-5  (Section 2.3)

SEED      = 42
OUT_DIR   = Path("results_diff_neuro")

# ============================================================
# Конфігурації (ВИПРАВЛЕНІ для Калини-128 з матрицею 8×2)
#
# Калина-128: state = uint64_t[2], INDEX(table, row, col) = table[row + col*8]
#   col 0 = bytes 0-7  (word 0)
#   col 1 = bytes 8-15 (word 1)
#   row r = bytes [r, r+8]
#
# delta = 0x00..01 (byte 15 = row 7, col 1)
# Після 1 раунду: ShiftRows переносить row 7 з col 1 → col 0,
#   MixColumns поширює на весь col 0. Col 1 = нуль.
# Після 2 раундів: обидва стовпці активні, cross-word пари [r, r+8]
#   мають максимальну кореляцію (аналог AES Table 5).
#
# (subset, byte_indices, label, rounds)
# ============================================================

CONFIGS = [
    # --- Table 1: повний шифротекст ---
    (SubsetType.FULL,      None,     "T1_full_2r",             2),
    (SubsetType.FULL,      None,     "T1_full_3r",             3),

    # --- Table 2: 3-round, один стовпець (= 8 байтів = 64 біти) ---
    # Col 0 (bytes 0-7): після 1 раунду з delta=byte15 тут ВСЯ різниця
    # Col 1 (bytes 8-15): після 1 раунду тут НУЛЬ різниці
    (SubsetType.COL_0,     None,     "T2_col0_3r",             3),
    (SubsetType.COL_1,     None,     "T2_col1_3r",             3),

    # --- Table 3: 3-round, два байти ---
    # Cross-word пара (по 1 байту з кожного слова, один рядок)
    (SubsetType.TWO_BYTES, [0, 8],   "T3_2b_0_8_xword_3r",    3),
    (SubsetType.TWO_BYTES, [7, 15],  "T3_2b_7_15_xword_3r",   3),
    # Same-word пара (обидва з col 0) для порівняння
    (SubsetType.TWO_BYTES, [0, 1],   "T3_2b_0_1_sword_3r",    3),

    # --- Table 4: 2-round, один байт ---
    (SubsetType.ONE_BYTE,  [0],      "T4_1b_0_2r",            2),
    (SubsetType.ONE_BYTE,  [15],     "T4_1b_15_2r",           2),
    (SubsetType.ONE_BYTE,  [8],      "T4_1b_8_2r",            2),

    # --- Table 5: 2-round, два байти <- головний результат ---
    # Cross-word пара: один рядок матриці = [r, r+8]
    # Це прямий аналог AES Table 5 де {0,1} давав ~100% accuracy
    (SubsetType.TWO_BYTES, [0, 8],   "T5_2b_0_8_xword_2r",   2),
    (SubsetType.TWO_BYTES, [1, 9],   "T5_2b_1_9_xword_2r",   2),
    (SubsetType.TWO_BYTES, [7, 15],  "T5_2b_7_15_xword_2r",  2),
    # Same-word пара для порівняння (очікуємо слабший результат)
    (SubsetType.TWO_BYTES, [0, 1],   "T5_2b_0_1_sword_2r",   2),
    (SubsetType.TWO_BYTES, [8, 9],   "T5_2b_8_9_sword_2r",   2),

    # --- Бонус: 1-round ---
    # Після 1 раунду різниця тільки в col 0 (байти 0-7)
    (SubsetType.TWO_BYTES, [0, 1],   "Bonus_2b_0_1_1r",      1),
    (SubsetType.COL_0,     None,     "Bonus_col0_1r",         1),
    # Col 1 для 1-round ПОВИНЕН дати ~50% (нуль різниці!) — контрольний тест
    (SubsetType.COL_1,     None,     "Bonus_col1_1r_CONTROL", 1),
]


# ============================================================
# Один запуск
# ============================================================

def run(backend, device, subset, byte_indices, label, rounds):

    print(f"\n{'='*65}")
    print(f"  {label}  |  rounds={rounds}")
    print(f"  N_train={N_TRAIN:,}  N_val={N_VAL:,}  N_test={N_TEST:,}")
    print(f"  Batch={BATCH}  Epochs={EPOCHS}")
    print(f"  Loss=MSE+L2(lambda={L2_LAM})  LR cyclic beta={LR_BETA} alpha={LR_ALPHA} n={LR_N}")

    # --- дані ---
    print("\n[1/3] Generating train + val...")
    t0 = time.time()
    X_tv, y_tv = generate_chunked_dataset(
        backend, N_TRAIN + N_VAL, rounds, subset, byte_indices, "train+val"
    )
    X_tr, y_tr = X_tv[:N_TRAIN], y_tv[:N_TRAIN]
    X_vl, y_vl = X_tv[N_TRAIN:], y_tv[N_TRAIN:]
    del X_tv, y_tv
    print(f"  train shape: {X_tr.shape}  |  {time.time()-t0:.1f}s")

    print("[2/3] Generating test set...")
    X_te, y_te = generate_chunked_dataset(
        backend, N_TEST, rounds, subset, byte_indices, "test   "
    )

    # --- loaders ---
    def mk_loader(X, y, shuffle):
        return DataLoader(
            TensorDataset(torch.from_numpy(X), torch.from_numpy(y)),
            batch_size=BATCH, shuffle=shuffle, pin_memory=(device.type=="cuda"),
        )
    train_loader = mk_loader(X_tr, y_tr, True)
    val_loader   = mk_loader(X_vl, y_vl, False)
    test_loader  = mk_loader(X_te, y_te, False)

    # --- модель ---
    nb, ws = model_input_params(subset, byte_indices)
    model  = AESLikeResNetDistinguisher(
        num_blocks=nb, word_size_bits=ws,
        num_filters=16, depth=5, dense1=64, dense2=64, kernel_size=3,
    ).to(device)

    criterion = MSEWithL2Loss(model, L2_LAM)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR_BETA)
    scheduler = make_lr_scheduler(optimizer, LR_ALPHA, LR_BETA, LR_N)

    # --- навчання ---
    print(f"[3/3] Training ({EPOCHS} epochs)...")
    best_val_loss = float("inf")
    best_state    = None
    best_epoch    = 0
    history       = []
    t_train       = time.time()

    for ep in range(EPOCHS):
        lr_now = scheduler.get_last_lr()[0] if ep > 0 else LR_BETA

        model.train()
        tr_loss_sum = tr_correct = tr_n = 0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            logits = model(xb)
            loss   = criterion(logits, yb)
            loss.backward()
            optimizer.step()
            with torch.no_grad():
                tr_loss_sum += loss.item() * xb.size(0)
                tr_correct  += ((torch.sigmoid(logits)>=0.5)==yb.bool()).sum().item()
                tr_n        += yb.size(0)
        scheduler.step()

        vl_loss, vl_acc, vl_tpr, vl_tnr = evaluate(model, val_loader, criterion, device)

        if vl_loss < best_val_loss:
            best_val_loss = vl_loss
            best_epoch    = ep + 1
            best_state    = {k: v.cpu().clone() for k, v in model.state_dict().items()}

        row = dict(
            epoch=ep+1, lr=round(lr_now,6),
            tr_loss=round(tr_loss_sum/tr_n,6), tr_acc=round(tr_correct/tr_n,6),
            vl_loss=round(vl_loss,6), vl_acc=round(vl_acc,6),
            vl_tpr=round(vl_tpr,6),  vl_tnr=round(vl_tnr,6),
        )
        history.append(row)
        marker = " <-" if ep+1 == best_epoch else ""
        print(
            f"  ep {ep+1:02d}/{EPOCHS}  lr={lr_now:.4f}  "
            f"tr_loss={tr_loss_sum/tr_n:.5f} tr_acc={tr_correct/tr_n:.4f}  "
            f"vl_loss={vl_loss:.5f} vl_acc={vl_acc:.4f}  "
            f"TPR={vl_tpr:.4f} TNR={vl_tnr:.4f}{marker}"
        )

    elapsed = time.time() - t_train

    # --- тест на найкращій моделі ---
    model.load_state_dict(best_state)
    te_loss, te_acc, te_tpr, te_tnr = evaluate(model, test_loader, criterion, device)

    print(f"\n  * TEST (best ep={best_epoch}):  "
          f"Acc={te_acc:.4f}  TPR={te_tpr:.4f}  TNR={te_tnr:.4f}  "
          f"(time={elapsed:.0f}s)")

    # --- збереження ---
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    hist_path = OUT_DIR / f"history_{label}.csv"
    with hist_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(history[0].keys()))
        w.writeheader(); w.writerows(history)

    mdl_path = OUT_DIR / f"model_{label}.pt"
    torch.save(best_state, mdl_path)

    return dict(
        label=label, rounds=rounds, N_train=N_TRAIN,
        best_epoch=best_epoch,
        test_acc=round(te_acc,6), test_tpr=round(te_tpr,6), test_tnr=round(te_tnr,6),
        best_val_loss=round(best_val_loss,6), time_sec=round(elapsed,1),
    )


# ============================================================
# Main
# ============================================================

def main():
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device : {device}")
    print(f"N_train: {N_TRAIN:,}  (paper: 10,000,000)")
    print(f"N_val  : {N_VAL:,}    (paper:  1,000,000)")
    print(f"N_test : {N_TEST:,}    (paper:  1,000,000)")
    print(f"Batch  : {BATCH}  Epochs: {EPOCHS}")
    print(f"Loss   : MSE + L2(lambda={L2_LAM})")
    print(f"LR     : cyclic beta={LR_BETA} alpha={LR_ALPHA} n={LR_N}")

    backend = KalynaBackend()
    all_results = []

    for subset, byte_idx, label, rounds in CONFIGS:
        r = run(backend, device, subset, byte_idx, label, rounds)
        all_results.append(r)

        # зберігаємо після кожного запуску
        out_csv = OUT_DIR / "results_diff_neuro.csv"
        with out_csv.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(all_results[0].keys()))
            w.writeheader(); w.writerows(all_results)
        print(f"  -> saved {out_csv}")

    # --- фінальна таблиця у форматі статті ---
    print(f"\n{'='*65}")
    print(f"РЕЗУЛЬТАТИ  (N={N_TRAIN:,})")
    print(f"{'Label':<30} {'R':>2}  {'Acc':>7}  {'TPR':>7}  {'TNR':>7}  {'Ep':>3}")
    print("-"*65)
    for r in all_results:
        print(
            f"{r['label'][:29]:<30} {r['rounds']:>2}  "
            f"{r['test_acc']:>7.4f}  {r['test_tpr']:>7.4f}  "
            f"{r['test_tnr']:>7.4f}  {r['best_epoch']:>3}"
        )


if __name__ == "__main__":
    main()