import os
import sys
from pathlib import Path

# Гарантировать доступ к пакету project при запуске из поддиректории.
# (Структура: Kalyna-distinguisher/project/test_util/1.py)
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from project.backend.kalyna_backend import KalynaBackend
import numpy as np

backend = KalynaBackend()
pt = backend.random_block()
key = backend.random_key()

print(f"[TRACE] pt = {pt.hex()}")
print(f"        key = {key.hex()}\n")

for r in range(1, 11):
    ct = backend.adapter.encrypt_rounds(pt, key, rounds=r)
    print(f"round {r:2d}: {ct.hex()}")