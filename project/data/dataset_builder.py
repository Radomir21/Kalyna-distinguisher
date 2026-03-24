"""

Генерація датасетів для нейро-розрізнювача блокового шифру Калина.

Підтримує всі типи підмножин шифротексту, що описані у статтях:
  - Zhang et al. "Differential-Neural Cryptanalysis on AES" (IEICE 2024)
  - Gohr "Improving Attacks on Round-Reduced Speck32/64 Using Deep Learning" (CRYPTO 2019)
  - Chen et al. "A Deep Learning aided Key-Recovery Framework for Large-State Block Ciphers"

Математика задачі:
  Розрізнювач навчається класифікувати пари шифротекстів (C0, C1):
    label=1 (реальна пара):  C0 = E_k(P0),  C1 = E_k(P0 XOR delta)
    label=0 (випадкова пара): C0 = E_k(P0),  C1 = E_k'(P1)  де P1 — випадковий

  Для 128-бітного блоку (Kalyna-128/AES) матриця стану 4×4 байти:
  
    байт  0  1  2  3   <- рядок 0
          4  5  6  7   <- рядок 1
          8  9 10 11   <- рядок 2
         12 13 14 15   <- рядок 3
  
    Стовпці: {0,4,8,12}, {1,5,9,13}, {2,6,10,14}, {3,7,11,15}
"""

from __future__ import annotations

from enum import Enum, auto
from typing import List, Sequence, Tuple

import numpy as np


BLOCK_BYTES = 16        # розмір блоку в байтах
STATE_ROWS = 4          # кількість рядків матриці стану
STATE_COLS = 4          # кількість стовпців матриці стану
BITS_PER_BYTE = 8


def _row_indices(row: int) -> List[int]:
    """Байтові індекси одного рядка матриці стану (0..3)."""
    assert 0 <= row < STATE_ROWS
    return [row * STATE_COLS + col for col in range(STATE_COLS)]


def _col_indices(col: int) -> List[int]:
    """Байтові індекси одного стовпця матриці стану (0..3)."""
    assert 0 <= col < STATE_COLS
    return [row * STATE_COLS + col for row in range(STATE_ROWS)]


"""Для Kalyna-128-128 з вхідною різницею delta = 0x00..001
ShiftRows зсуває рядки: рядок i зсувається на i байтів вліво.
Після одного раунду (SubBytes → ShiftRows → MixColumns) різниця
у байті 15 (рядок 3, стовпець 3) поширюється на стовпець 3 → {3,7,11,15}.

Zhang et al. (Table 5) для AES виявили, що байти з ОДНАКОВИМИ
позиціями у C0 і C1, залежно від обраної різниці delta, дають
100% точність для 2-раундового розрізнювача.

Для delta = 0x00000000000000000000000000000001 (байт 15):
після 1 раунду: найсильніший сигнал у байтах 14,15 (Zhang et al., Table 5)
BEST_2_BYTES_FOR_DELTA_LSB = [14, 15]
"""

"""Типи підмножин шифротексту, що вивчаються у роботі.
    
    Відповідають розділам 3.1 і 3.2 Zhang et al. (2024):
      FULL         — повний шифротекст (128 біт)    ознак 2*128=256 біт
      ROW_i        — рядок i матриці стану (32 біт)  ознак 2*32=64 біт
      COL_j        — стовпець j (32 біти)            ознак 2*32=64 біт
      TWO_BYTES    — довільна пара байтів (16 біт)   ознак 2*16=32 біти
      ONE_BYTE     — один байт (8 біт)               ознак 2*8=16 біт
"""
class SubsetType(Enum):

    FULL = auto()
    ROW_0 = auto()
    ROW_1 = auto()
    ROW_2 = auto()
    ROW_3 = auto()
    COL_0 = auto()
    COL_1 = auto()
    COL_2 = auto()
    COL_3 = auto()
    TWO_BYTES = auto()
    ONE_BYTE = auto()

"""Повертає список байтових індексів для вибраного типу підмножини.
    
    Args:
        subset: тип підмножини.
        byte_indices: для SubsetType.TWO_BYTES або ONE_BYTE — конкретні індекси.
    
    Returns:
        Список байтових індексів у межах [0, 15].
"""
def get_byte_indices(subset: SubsetType, byte_indices: Sequence[int] | None = None) -> List[int]:

    if subset == SubsetType.FULL:
        return list(range(BLOCK_BYTES))
    elif subset == SubsetType.ROW_0:
        return _row_indices(0)
    elif subset == SubsetType.ROW_1:
        return _row_indices(1)
    elif subset == SubsetType.ROW_2:
        return _row_indices(2)
    elif subset == SubsetType.ROW_3:
        return _row_indices(3)
    elif subset == SubsetType.COL_0:
        return _col_indices(0)
    elif subset == SubsetType.COL_1:
        return _col_indices(1)
    elif subset == SubsetType.COL_2:
        return _col_indices(2)
    elif subset == SubsetType.COL_3:
        return _col_indices(3)
    elif subset == SubsetType.TWO_BYTES:
        if byte_indices is None or len(byte_indices) != 2:
            raise ValueError("For TWO_BYTES, provide exactly 2 byte indices.")
        return list(byte_indices)
    elif subset == SubsetType.ONE_BYTE:
        if byte_indices is None or len(byte_indices) != 1:
            raise ValueError("For ONE_BYTE, provide exactly 1 byte index.")
        return list(byte_indices)
    else:
        raise ValueError(f"Unknown subset type: {subset}")


def feature_size(subset: SubsetType, byte_indices: Sequence[int] | None = None) -> int:
    """Розмір вектора ознак (у бітах) для пари шифротекстів.
    
    Формула: len(byte_indices) * 2 * 8
    Множник 2 — бо ми конкатенуємо байти з C0 і C1.
    """
    indices = get_byte_indices(subset, byte_indices)
    return len(indices) * 2 * BITS_PER_BYTE



# Векторизація
"""Перетворює пару шифротекстів у бітовий вектор ознак.
    
    Алгоритм (відповідає Zhang et al., Section 2.2):
      1. Вибираємо байти ct0[indices] та ct1[indices].
      2. Конкатенуємо: [ct0_sel || ct1_sel].
      3. Розпаковуємо у біти (MSB-first через numpy.unpackbits).
    
    Args:
        ct0: перший шифротекст (BLOCK_BYTES байтів).
        ct1: другий шифротекст (BLOCK_BYTES байтів).
        indices: список байтових індексів для вибору.
    
    Returns:
        np.ndarray dtype=uint8, форма (len(indices)*2*8,).
"""

def vectorize_subset(
    ct0: bytes,
    ct1: bytes,
    indices: Sequence[int],
) -> np.ndarray:

    ct0_sel = bytes(ct0[i] for i in indices)
    ct1_sel = bytes(ct1[i] for i in indices)
    merged = ct0_sel + ct1_sel
    return np.unpackbits(np.frombuffer(merged, dtype=np.uint8)).astype(np.float32)



# Основна функція генерації датасету
"""Генерує датасет для навчання нейро-розрізнювача.
    
    Процедура генерації (Gohr, Algorithm 1; Zhang et al., Section 2.3):
    
    Для кожного зразка i:
      1. Обираємо label_i ~ Bernoulli(0.5).
      2. Генеруємо ключ k_i (або використовуємо master_key при fixed_key=True).
      3. Генеруємо випадковий відкритий текст P0.
      4. Якщо label=1: P1 = P0 XOR input_diff   (диференціальна пара)
         Якщо label=0: P1 = random_block()        (незалежний шифротекст)
      5. C0 = E_k(P0, rounds),  C1 = E_k(P1, rounds)  (зашифрування за rounds раундів)
      6. Вибираємо підмножину байтів з C0 та C1 і перетворюємо у бітовий вектор.
    
    Args:
        backend: KalynaBackend з методами random_block, random_key, encrypt_rounds.
        n_samples: кількість зразків.
        input_diff: вхідна різниця delta (bytes, довжина = BLOCK_BYTES).
        rounds: кількість раундів шифрування.
        subset: тип підмножини шифротексту.
        byte_indices: конкретні байти для ONE_BYTE або TWO_BYTES.
        fixed_key: якщо True — всі зразки шифруються одним ключем.
    
    Returns:
        X: np.ndarray float32, форма (n_samples, feature_size).
        y: np.ndarray float32, форма (n_samples,), значення 0 або 1.
"""

def generate_dataset(
    backend,
    n_samples: int,
    input_diff: bytes,
    rounds: int,
    subset: SubsetType,
    byte_indices: Sequence[int] | None = None,
    fixed_key: bool = False,
) -> Tuple[np.ndarray, np.ndarray]:

    if n_samples <= 0:
        raise ValueError("n_samples must be > 0")
    if len(input_diff) != BLOCK_BYTES:
        raise ValueError(f"input_diff must be {BLOCK_BYTES} bytes, got {len(input_diff)}")

    indices = get_byte_indices(subset, byte_indices)

    master_key = backend.random_key() if fixed_key else None

    X_list = []
    y_list = []

    for _ in range(n_samples):
        label = int(np.random.randint(0, 2))
        key = master_key if fixed_key else backend.random_key()
        pt0 = backend.random_block()

        if label == 1:
            pt1 = bytes(a ^ b for a, b in zip(pt0, input_diff))
        else:
            pt1 = backend.random_block()

        ct0 = backend.encrypt_rounds(pt0, key, rounds)
        ct1 = backend.encrypt_rounds(pt1, key, rounds)

        features = vectorize_subset(ct0, ct1, indices)
        X_list.append(features)
        y_list.append(label)

    X = np.stack(X_list).astype(np.float32)
    y = np.array(y_list, dtype=np.float32)
    return X, y


# Допоміжна функція для визначення num_blocks і word_size_bits
# для моделі AESLikeResNetDistinguisher
"""Повертає (num_blocks, word_size_bits) для ініціалізації моделі.
    
    Мережа AESLikeResNetDistinguisher очікує:
      - num_blocks  = 2  (завжди, бо ми подаємо пару C0, C1)
      - word_size_bits = len(byte_indices) * 8
    
    Returns:
        (num_blocks=2, word_size_bits)
"""
def model_input_params(
    subset: SubsetType,
    byte_indices: Sequence[int] | None = None,
) -> Tuple[int, int]:

    indices = get_byte_indices(subset, byte_indices)
    return 2, len(indices) * BITS_PER_BYTE


# Конфігурації для систематичних експериментів (відповідають Таблицям 1-5
# у Zhang et al., 2024)
# Стандартна вхідна різниця для Kalyna-128 (аналог delta=0x80 для AES-128)
# Різниця в останньому байті (байт 15): позиція [рядок 3, стовпець 3].
DEFAULT_INPUT_DIFF: bytes = bytes(15 * [0x00] + [0x01])

# Набір конфігурацій для повного дослідження 
EXPERIMENT_CONFIGS = [
    # (subset, byte_indices, description)
    (SubsetType.FULL,      None,    "Full ciphertext (128 bits)"),
    (SubsetType.ROW_3,     None,    "Row 3 of state (bytes 12-15)"),
    (SubsetType.ROW_0,     None,    "Row 0 of state (bytes 0-3)"),
    (SubsetType.COL_3,     None,    "Column 3 of state (bytes 3,7,11,15)"),
    (SubsetType.COL_0,     None,    "Column 0 of state (bytes 0,4,8,12)"),
    (SubsetType.TWO_BYTES, [14, 15], "2 bytes [14,15] (best for delta_LSB)"),
    (SubsetType.TWO_BYTES, [0, 1],   "2 bytes [0,1]"),
    (SubsetType.TWO_BYTES, [0, 13],  "2 bytes [0,13] (AES-style)"),
    (SubsetType.ONE_BYTE,  [15],     "1 byte [15] (LSB position)"),
    (SubsetType.ONE_BYTE,  [14],     "1 byte [14]"),
]