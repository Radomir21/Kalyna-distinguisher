"""
train_diff_neuro.py

Точна репліка конфігурації з Diff_Neuro.pdf (Zhang et al., IEICE 2024)
для блокового шифру Калина.

Параметри взяті дослівно з Section 2.3:
  N        = 1_000_000   (у статті 10^7 — тут зменшено у 10 разів)
  M (test) =   100_000   (у статті 10^6)
  Bs       = 1_000
  Epochs   = 20
  Loss     = MSE + L2(λ = 10^-5)
  LR       = cyclic: β=0.002, α=0.0001, n=9
  Save     = best model by validation loss
  Metrics  = Acc, TPR, TNR  (як у Таблицях 1-5 статті)

Конфігурації таблиць з Diff_Neuro.pdf → адаптовано для Калини:
  Table 1: 2-round, 3-round — повний шифротекст
  Table 2: 3-round — один рядок, один стовпець
  Table 3: 3-round — два байти
  Table 4: 2-round — один байт
  Table 5: 2-round — два байти  ← головний результат статті (≈100% для AES)
"""

from __future__ import annotations

import csv
import os
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# --- шлях до проєкту ---
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent.parent))

from project.backend.kalyna_backend import KalynaBackend
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher
from project.data.dataset_builder import (
    SubsetType, generate_dataset, model_input_params, DEFAULT_INPUT_DIFF,
)

# ============================================================
# ПАРАМЕТРИ — змінюй тільки тут
# ============================================================

N_TRAIN   = 1_000_000   # у статті 10_000_000
N_VAL     =   100_000   # у статті  1_000_000
N_TEST    =   100_000   # у статті  1_000_000

BATCH     = 1_000       # Bs = 1000  (Section 2.3)
EPOCHS    = 10          # у статті 20 epochs  (Section 2.3)

# Cyclic LR (Section 2.3)
LR_BETA   = 2e-3        # β = 0.002
LR_ALPHA  = 1e-4        # α = 0.0001
LR_N      = 9           # n = 9  → цикл кожні 10 епох

L2_LAM    = 1e-5        # λ = 10^-5  (Section 2.3)

SEED      = 42
OUT_DIR   = Path("results_diff_neuro")

# ============================================================
# Конфігурації таблиць із Diff_Neuro.pdf
# (subset, byte_indices, label, rounds)
# ============================================================

CONFIGS = [
    # --- Table 1: повний шифротекст ---
    (SubsetType.FULL,      None,    "Table1_full_2r",   2),
    (SubsetType.FULL,      None,    "Table1_full_3r",   3),

    # --- Table 2: 3-round, один рядок / один стовпець ---
    (SubsetType.ROW_3,     None,    "Table2_row3_3r",   3),
    (SubsetType.COL_3,     None,    "Table2_col3_3r",   3),

    # --- Table 3: 3-round, два байти ---
    (SubsetType.TWO_BYTES, [14,15], "Table3_2b_14_15_3r", 3),
    (SubsetType.TWO_BYTES, [0, 1],  "Table3_2b_0_1_3r",   3),

    # --- Table 4: 2-round, один байт ---
    (SubsetType.ONE_BYTE,  [15],    "Table4_1b_15_2r",  2),
    (SubsetType.ONE_BYTE,  [14],    "Table4_1b_14_2r",  2),

    # --- Table 5: 2-round, два байти ← головний результат ---
    (SubsetType.TWO_BYTES, [14,15], "Table5_2b_14_15_2r", 2),
    (SubsetType.TWO_BYTES, [0, 1],  "Table5_2b_0_1_2r",   2),
    (SubsetType.TWO_BYTES, [0,13],  "Table5_2b_0_13_2r",  2),

    # --- Додатково: 1-round (вже відомий хороший результат) ---
    (SubsetType.TWO_BYTES, [14,15], "Bonus_2b_14_15_1r",  1),
    (SubsetType.ONE_BYTE,  [15],    "Bonus_1b_15_1r",     1),
]


# ============================================================
# Loss: MSE + L2  (Section 2.3 дослівно)
# ============================================================

class MSEwithL2(nn.Module):
    """
    Zhang et al. Section 2.3:
    'cost function comprising mean square error loss augmented by
    an L2 regularization term with a parameter λ = 10^-5'

    L(θ) = MSE(σ(logits), y) + λ · Σ||w||²
    """
    def __init__(self, model: nn.Module, lam: float = 1e-5):
        super().__init__()
        self.model = model
        self.lam   = lam
        self.mse   = nn.MSELoss()

    def forward(self, logits: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        probs    = torch.sigmoid(logits)
        mse_part = self.mse(probs, y)
        l2_part  = sum(p.pow(2).sum() for p in self.model.parameters())
        return mse_part + self.lam * l2_part


# ============================================================
# Cyclic LR  (Section 2.3 дослівно)
# ============================================================

def cyclic_lr_factor(epoch: int) -> float:
    """
    lᵢ = α + ((n−i) mod (n+1) / n) · (β − α)

    Повертає множник відносно base_lr=LR_BETA,
    щоб LambdaLR дав правильне значення.
    """
    lr = LR_ALPHA + ((LR_N - epoch) % (LR_N + 1)) / LR_N * (LR_BETA - LR_ALPHA)
    return lr / LR_BETA


# ============================================================
# Генерація даних з прогрес-баром
# ============================================================

def gen_data(
    backend: KalynaBackend,
    n: int,
    rounds: int,
    subset: SubsetType,
    byte_indices,
    label: str = "",
    chunk: int = 100_000,
) -> tuple[np.ndarray, np.ndarray]:

    parts_X, parts_y = [], []
    done = 0
    t0 = time.time()

    while done < n:
        nc = min(chunk, n - done)
        X, y = generate_dataset(
            backend=backend, n_samples=nc, input_diff=DEFAULT_INPUT_DIFF,
            rounds=rounds, subset=subset, byte_indices=byte_indices,
        )
        parts_X.append(X);  parts_y.append(y)
        done += nc
        elapsed = time.time() - t0
        eta     = (n - done) / (done / elapsed) if done else 0
        print(f"\r  {label} {done:>9,}/{n:,}  ETA {eta:.0f}s   ", end="", flush=True)

    print()
    return (
        np.concatenate(parts_X).astype(np.float32),
        np.concatenate(parts_y).astype(np.float32),
    )


# ============================================================
# Оцінка: Acc, TPR, TNR  (як у Таблицях 1-5 статті)
# ============================================================

def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = tp = fp = tn = fn = 0
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            logits  = model(xb)
            total_loss += criterion(logits, yb).item() * xb.size(0)
            preds   = (torch.sigmoid(logits) >= 0.5).float()
            tp += ((preds==1)&(yb==1)).sum().item()
            fp += ((preds==1)&(yb==0)).sum().item()
            tn += ((preds==0)&(yb==0)).sum().item()
            fn += ((preds==0)&(yb==1)).sum().item()

    n    = tp + fp + tn + fn
    acc  = (tp + tn) / n
    tpr  = tp / (tp + fn) if (tp+fn) > 0 else 0.0
    tnr  = tn / (tn + fp) if (tn+fp) > 0 else 0.0
    return total_loss / n, acc, tpr, tnr


# ============================================================
# Один запуск
# ============================================================

def run(backend, device, subset, byte_indices, label, rounds):

    print(f"\n{'='*65}")
    print(f"  {label}  |  rounds={rounds}")
    print(f"  N_train={N_TRAIN:,}  N_val={N_VAL:,}  N_test={N_TEST:,}")
    print(f"  Batch={BATCH}  Epochs={EPOCHS}")
    print(f"  Loss=MSE+L2(λ={L2_LAM})  LR cyclic β={LR_BETA} α={LR_ALPHA} n={LR_N}")

    # --- дані ---
    print("\n[1/3] Generating train + val...")
    t0 = time.time()
    X_tv, y_tv = gen_data(backend, N_TRAIN + N_VAL, rounds, subset, byte_indices, "train+val")
    X_tr, y_tr = X_tv[:N_TRAIN], y_tv[:N_TRAIN]
    X_vl, y_vl = X_tv[N_TRAIN:], y_tv[N_TRAIN:]
    del X_tv, y_tv
    print(f"  train shape: {X_tr.shape}  |  {time.time()-t0:.1f}s")

    print("[2/3] Generating test set...")
    X_te, y_te = gen_data(backend, N_TEST, rounds, subset, byte_indices, "test   ")

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

    criterion = MSEwithL2(model, L2_LAM)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR_BETA)
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, cyclic_lr_factor)

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
        marker = " ←" if ep+1 == best_epoch else ""
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

    print(f"\n  ★ TEST (best ep={best_epoch}):  "
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
    print(f"Loss   : MSE + L2(λ={L2_LAM})")
    print(f"LR     : cyclic β={LR_BETA} α={LR_ALPHA} n={LR_N}")

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
        print(f"  → saved {out_csv}")

    # --- фінальна таблиця у форматі статті ---
    print(f"\n{'='*65}")
    print(f"РЕЗУЛЬТАТИ  (N={N_TRAIN:,} — в 10 разів менше ніж у статті)")
    print(f"{'Label':<28} {'R':>2}  {'Acc':>7}  {'TPR':>7}  {'TNR':>7}  {'Ep':>3}")
    print("-"*60)
    for r in all_results:
        print(
            f"{r['label'][:27]:<28} {r['rounds']:>2}  "
            f"{r['test_acc']:>7.4f}  {r['test_tpr']:>7.4f}  "
            f"{r['test_tnr']:>7.4f}  {r['best_epoch']:>3}"
        )


if __name__ == "__main__":
    main()