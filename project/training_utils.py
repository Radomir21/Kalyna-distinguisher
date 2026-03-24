"""
training_utils.py

Спільні утиліти для навчання нейро-розрізнювача Калини.

  - Gohr (CRYPTO 2019), Section 4.3
  - Zhang et al. (IEICE 2024), Section 2.3
"""

from __future__ import annotations

import time

import numpy as np
import torch
import torch.nn as nn

from project.data.dataset_builder import generate_dataset, DEFAULT_INPUT_DIFF


# ---------------------------------------------------------------------------
# MSE + L2 Loss 
# ---------------------------------------------------------------------------

class MSEWithL2Loss(nn.Module):
    """
    MSE loss + L2 weight regularization.

    Gohr: 'mean square error loss plus a small penalty based on L2 weights
    regularization (with regularization parameter c = 10^-5)'

    L(theta) = MSE(sigmoid(logits), y) + lambda * sum(w^2)
    """

    def __init__(self, model: nn.Module, l2_lambda: float = 1e-5):
        super().__init__()
        self.model = model
        self.l2_lambda = l2_lambda
        self.mse = nn.MSELoss()

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        probs = torch.sigmoid(logits)
        mse_loss = self.mse(probs, targets)
        l2_penalty = sum(p.pow(2).sum() for p in self.model.parameters())
        return mse_loss + self.l2_lambda * l2_penalty


# ---------------------------------------------------------------------------
# Cyclic Learning Rate (Gohr Section 4.3; Zhang Section 2.3)
# ---------------------------------------------------------------------------

def cyclic_lr(epoch_idx: int, alpha: float, beta: float, n: int) -> float:
    """
    l_i = alpha + ((n - i) mod (n+1) / n) * (beta - alpha)

    epoch 0:  lr = beta  (max)
    epoch n:  lr = alpha (min)
    epoch n+1: lr = beta (new cycle)
    """
    return alpha + ((n - epoch_idx) % (n + 1)) / n * (beta - alpha)


def make_lr_scheduler(optimizer, alpha: float, beta: float, n: int):
    """LambdaLR wrapper for cyclic LR."""
    def lr_lambda(epoch_idx):
        return cyclic_lr(epoch_idx, alpha, beta, n) / beta
    return torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)


# ---------------------------------------------------------------------------
# Evaluate: Acc, TPR, TNR (Tables 1-5 of Zhang et al.)
# ---------------------------------------------------------------------------

def evaluate(model, loader, criterion, device):
    """
    Returns (loss, acc, tpr, tnr).

    TPR = sensitivity = P(predict=1 | label=1)
    TNR = specificity = P(predict=0 | label=0)
    """
    model.eval()
    total_loss = tp = fp = tn = fn = 0
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            total_loss += criterion(logits, yb).item() * xb.size(0)
            preds = (torch.sigmoid(logits) >= 0.5).float()
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
# Chunked dataset generation with progress bar
# ---------------------------------------------------------------------------

def generate_chunked_dataset(
    backend,
    n_total: int,
    rounds: int,
    subset,
    byte_indices,
    label: str = "",
    chunk_size: int = 100_000,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate large dataset in chunks with progress display."""
    X_parts, y_parts = [], []
    done = 0
    t0 = time.time()

    while done < n_total:
        nc = min(chunk_size, n_total - done)
        X, y = generate_dataset(
            backend=backend, n_samples=nc, input_diff=DEFAULT_INPUT_DIFF,
            rounds=rounds, subset=subset, byte_indices=byte_indices,
        )
        X_parts.append(X)
        y_parts.append(y)
        done += nc
        elapsed = time.time() - t0
        eta = (n_total - done) / (done / elapsed) if done else 0
        print(f"\r  {label} {done:>9,}/{n_total:,}  ETA {eta:.0f}s   ", end="", flush=True)

    print()
    return (
        np.concatenate(X_parts).astype(np.float32),
        np.concatenate(y_parts).astype(np.float32),
    )
