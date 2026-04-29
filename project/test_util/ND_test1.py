"""Швидкий тест: 1 і 2 раунди з аддитивною різницею."""
import sys, time, random
from pathlib import Path
import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from project.backend.kalyna_adapter import make_default_adapter
from project.models.neuro_distinguisher import AESLikeResNetDistinguisher
from project.data.dataset_builder import SubsetType, model_input_params, generate_dataset, DEFAULT_INPUT_DIFF
from project.train_test.training_utils import MSEWithL2Loss, make_lr_scheduler, evaluate

random.seed(42); np.random.seed(42); torch.manual_seed(42)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
backend = make_default_adapter()

TESTS = [
    # (rounds, subset, byte_idx, label)
    (1, SubsetType.ONE_BYTE, [0],   "1r_byte0"),
    (1, SubsetType.ONE_BYTE, [8],   "1r_byte8"),
    (2, SubsetType.ONE_BYTE, [0],   "2r_byte0"),
    (2, SubsetType.ONE_BYTE, [8],   "2r_byte8"),
    (1, SubsetType.ONE_BYTE, [15], "1r_byte15"),
    (2, SubsetType.ONE_BYTE, [15], "2r_byte15"),
    (1, SubsetType.ROW_0,     None,   "1r_row0"),
    (2, SubsetType.ROW_0,     None,   "2r_row0"),
    (1, SubsetType.ROW_1,     None,   "1r_row1"),
    (2, SubsetType.ROW_1,     None,   "2r_row1"),
    (1, SubsetType.ROW_2,     None,   "1r_row2"),
    (2, SubsetType.ROW_2,     None,   "2r_row2"),
    (1, SubsetType.ROW_3,     None,   "1r_row3"),
    (2, SubsetType.ROW_3,     None,   "2r_row3"),
    (1, SubsetType.ROW_4,     None,   "1r_row4"),
    (2, SubsetType.ROW_4,     None,   "2r_row4"),
    (1, SubsetType.ROW_5,     None,   "1r_row5"),
    (2, SubsetType.ROW_5,     None,   "2r_row5"),
    (1, SubsetType.ROW_6,     None,   "1r_row6"),
    (2, SubsetType.ROW_6,     None,   "2r_row6"),
    (1, SubsetType.ROW_7,     None,   "1r_row7"),
    (2, SubsetType.ROW_7,     None,   "2r_row7"),
    (1, SubsetType.COL_0,     None,   "1r_col0"),
    (1, SubsetType.COL_1,     None,   "1r_col1"),
    (2, SubsetType.TWO_BYTES, [0, 8], "2r_xword_0_8")
]

for rounds, subset, byte_idx, label in TESTS:
    print(f"\n{'='*50}\n  {label}  rounds={rounds}")
    
    N_TR, N_TE = 500_000, 50_000
    X_tr, y_tr = generate_dataset(backend, N_TR, DEFAULT_INPUT_DIFF, rounds, subset, byte_idx)
    X_te, y_te = generate_dataset(backend, N_TE, DEFAULT_INPUT_DIFF, rounds, subset, byte_idx)
    
    tr_loader = DataLoader(TensorDataset(torch.from_numpy(X_tr), torch.from_numpy(y_tr)), batch_size=1000, shuffle=True)
    te_loader = DataLoader(TensorDataset(torch.from_numpy(X_te), torch.from_numpy(y_te)), batch_size=1000)
    
    nb, ws = model_input_params(subset, byte_idx)
    model = AESLikeResNetDistinguisher(num_blocks=nb, word_size_bits=ws, num_filters=16, depth=5).to(device)
    criterion = MSEWithL2Loss(model, 1e-5)
    optimizer = torch.optim.Adam(model.parameters(), lr=2e-3)
    scheduler = make_lr_scheduler(optimizer, 1e-4, 2e-3, 9)
    
    EP = 20 

    for ep in range(EP):
        t0 = time.time()
        model.train()
        for xb, yb in tr_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()
        scheduler.step()
        _, acc, tpr, tnr = evaluate(model, te_loader, criterion, device)
        print(f"  ep {ep+1:02d}  Acc={acc:.4f}  TPR={tpr:.4f}  TNR={tnr:.4f}  [{time.time()-t0:.1f}s]")