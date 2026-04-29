"""
 Генерація датасетів для нейро-розрізнювача блокового шифру Калина-128/128.

  Калина-128 має матрицю стану 8×2 (8 рядків, 2 стовпці)
  
  Внутрішнє представлення: state = uint64_t[2]  (nb = 2 слова по 64 біт).
  
  
  Матриця стану Калини-128:
  
            col 0      col 1
            (word 0)   (word 1)
  row 0:   byte  0    byte  8
  row 1:   byte  1    byte  9
  row 2:   byte  2    byte 10
  row 3:   byte  3    byte 11
  row 4:   byte  4    byte 12
  row 5:   byte  5    byte 13
  row 6:   byte  6    byte 14
  row 7:   byte  7    byte 15
  
  ShiftRows для nb=2:
    rows 0-3: shift = 0  (без зсуву)
    rows 4-7: shift = 1  (зсув на 1 стовпець)

Підтримує типи підмножин, адаптовані для Калини:
  - Zhang et al. "Differential-Neural Cryptanalysis on AES" (IEICE 2024)
  - Gohr "Improving Attacks on Round-Reduced Speck32/64" (CRYPTO 2019)
  - Chen et al. "A Deep Learning aided Key-Recovery Framework for Large-State Block Ciphers"
"""

from __future__ import annotations

from enum import Enum, auto
from typing import List, Sequence, Tuple

import numpy as np


# ---------------------------------------------------------------------------
# Параметри блоку Калини-128
# ---------------------------------------------------------------------------

BLOCK_BYTES  = 16       # розмір блоку в байтах
BITS_PER_BYTE = 8

#
STATE_ROWS   = 8        # кількість рядків матриці стану (байтів у слові)
STATE_COLS   = 2        # кількість стовпців (64-бітних слів, nb=2)
BYTES_PER_WORD = 8      # sizeof(uint64_t)

# Аддитивна різниця: +1 у word 0 (молодше 64-бітне слово)
# Представлена як пара (delta_word0, delta_word1) для модулярного додавання
ADDITIVE_DELTA_WORDS: Tuple[int, int] = (1, 0)

# Для зворотної сумісності зберігаємо DEFAULT_INPUT_DIFF як bytes
# (використовується тільки для підпису, реальна різниця — аддитивна)
DEFAULT_INPUT_DIFF: bytes = (1).to_bytes(8, 'little') + (0).to_bytes(8, 'little')

MOD64 = 2**64

# Найкращі 2 байти для 2-round distinguisher: один рядок = [r, r+8].
BEST_2_BYTES_2ROUND = [0, 8]
BEST_2_BYTES_1ROUND = [0, 1]

# ---------------------------------------------------------------------------
# Індексація байтів у матриці стану Калини
# ---------------------------------------------------------------------------

def _col_indices(col: int) -> List[int]:
    """Байтові індекси одного стовпця (слова) матриці стану.
    
    Для Калини-128: стовпець = одне 64-бітне слово = 8 байтів.
      col 0 → [0, 1, 2, 3, 4, 5, 6, 7]   (state[0])
      col 1 → [8, 9, 10, 11, 12, 13, 14, 15] (state[1])
    """
    assert 0 <= col < STATE_COLS, f"col must be 0..{STATE_COLS-1}, got {col}"
    return [col * BYTES_PER_WORD + row for row in range(STATE_ROWS)]


def _row_indices(row: int) -> List[int]:
    """Байтові індекси одного рядка матриці стану.
    
    Для Калини-128: рядок = 2 байти (по одному з кожного слова).
      row 0 → [0, 8]
      row 7 → [7, 15]
    
    INDEX(table, row, col) = table[row + col * 8]
    """
    assert 0 <= row < STATE_ROWS, f"row must be 0..{STATE_ROWS-1}, got {row}"
    return [row + col * BYTES_PER_WORD for col in range(STATE_COLS)]


def _byte_to_matrix_pos(byte_idx: int) -> Tuple[int, int]:
    """Повертає (row, col) позицію байта в матриці стану Калини."""
    assert 0 <= byte_idx < BLOCK_BYTES
    col = byte_idx // BYTES_PER_WORD   # 0..7 → col 0,  8..15 → col 1
    row = byte_idx % BYTES_PER_WORD    # позиція всередині слова
    return row, col


# ---------------------------------------------------------------------------
# Аддитивна вхідна різниця для Калини
# ---------------------------------------------------------------------------

"""

  
  Тому для Калини потрібна АДДИТИВНА різниця:
    (P + Δ) + K = (P + K) + Δ  (mod 2^64)  ← зберігається ідеально!

  Обираємо Δ = +1 у word 0 (аддитивна різниця в молодшому слові).
  
  Після AddRoundKey(0): різниця +1 зберігається у word 0.
  Байт 0 змінюється на +1 (з ймовірністю ~255/256 без перенесення).
  Після SubBytes: один активний байт (byte 0, row 0, col 0).
  Після ShiftRows: row 0 має shift=0, залишається в col 0.
  Після MixColumns: MDS 8×8 поширює на весь стовпець 0.
  
  Після 1 раунду: col 0 (bytes 0-7) активний, col 1 (bytes 8-15) = нуль.
  Після 2 раундів: всі 16 байтів активні. Cross-word пари [r, r+8]
  мають максимальну кореляцію.
"""




def make_additive_pair(pt0: bytes, delta_words: Tuple[int, int] = ADDITIVE_DELTA_WORDS) -> bytes:
    """Створює пару відкритих текстів з АДДИТИВНОЮ різницею (mod 2^64).
    
    Це критично для Калини, де AddRoundKey(0) = додавання mod 2^64.
    XOR-різниця НЕ зберігається через mod-додавання, аддитивна — зберігається.
    
    Args:
        pt0: перший відкритий текст (16 байтів).
        delta_words: (delta_word0, delta_word1) — аддитивні різниці для кожного слова.
    
    Returns:
        pt1: другий відкритий текст = pt0 + delta (mod 2^64 по словах).
    """
    w0 = int.from_bytes(pt0[:8], 'little')
    w1 = int.from_bytes(pt0[8:], 'little')
    
    w0_new = (w0 + delta_words[0]) % MOD64
    w1_new = (w1 + delta_words[1]) % MOD64
    
    return w0_new.to_bytes(8, 'little') + w1_new.to_bytes(8, 'little')


# ---------------------------------------------------------------------------
# Типи підмножин шифротексту
# ---------------------------------------------------------------------------

class SubsetType(Enum):
    """Типи підмножин шифротексту для Калини-128.
    
    Адаптовано з Zhang et al. (2024) для матриці 8×2 (а не 4×4 як в AES):
    
      FULL       — повний шифротекст (128 біт)        ознак 2*128=256 біт
      COL_0/1    — стовпець (слово) стану (64 біти)    ознак 2*64=128 біт
      ROW_r      — рядок r матриці стану (16 біт)      ознак 2*16=32 біти
      TWO_BYTES  — довільна пара байтів (16 біт)       ознак 2*16=32 біти
      ONE_BYTE   — один байт (8 біт)                   ознак 2*8=16 біт
    
    Зверніть увагу: рядок Калини-128 містить лише 2 байти (а не 4 як в AES),
    а стовпець — 8 байтів (а не 4). Тому ROW дає таку ж кількість ознак,
    як TWO_BYTES, а COL еквівалентний "half ciphertext".
    """
    FULL       = auto()
    COL_0      = auto()   # стовпець 0 = word 0 = байти 0-7
    COL_1      = auto()   # стовпець 1 = word 1 = байти 8-15
    ROW_0      = auto()   # рядок 0 = [0, 8]
    ROW_1      = auto()
    ROW_2      = auto()
    ROW_3      = auto()
    ROW_4      = auto()
    ROW_5      = auto()
    ROW_6      = auto()
    ROW_7      = auto()
    TWO_BYTES  = auto()   # довільна пара байтів
    ONE_BYTE   = auto()   # один байт


def get_byte_indices(
    subset: SubsetType, 
    byte_indices: Sequence[int] | None = None,
) -> List[int]:
    """Повертає список байтових індексів для вибраного типу підмножини.
    
    Індекси відповідають порядку байтів у пам'яті:
      [0..7] = word 0 (state[0]), [8..15] = word 1 (state[1]).
    """
    if subset == SubsetType.FULL:
        return list(range(BLOCK_BYTES))
    
    # Стовпці (слова) — 8 байтів кожен
    elif subset == SubsetType.COL_0:
        return _col_indices(0)
    elif subset == SubsetType.COL_1:
        return _col_indices(1)
    
    # Рядки — 2 байти кожен (по 1 з кожного слова)
    elif subset == SubsetType.ROW_0:
        return _row_indices(0)
    elif subset == SubsetType.ROW_1:
        return _row_indices(1)
    elif subset == SubsetType.ROW_2:
        return _row_indices(2)
    elif subset == SubsetType.ROW_3:
        return _row_indices(3)
    elif subset == SubsetType.ROW_4:
        return _row_indices(4)
    elif subset == SubsetType.ROW_5:
        return _row_indices(5)
    elif subset == SubsetType.ROW_6:
        return _row_indices(6)
    elif subset == SubsetType.ROW_7:
        return _row_indices(7)
    
    # Довільні підмножини
    elif subset == SubsetType.TWO_BYTES:
        if byte_indices is None or len(byte_indices) != 2:
            raise ValueError("For TWO_BYTES, provide exactly 2 byte indices.")
        for idx in byte_indices:
            if not (0 <= idx < BLOCK_BYTES):
                raise ValueError(f"Byte index {idx} out of range [0, {BLOCK_BYTES-1}]")
        return list(byte_indices)
    elif subset == SubsetType.ONE_BYTE:
        if byte_indices is None or len(byte_indices) != 1:
            raise ValueError("For ONE_BYTE, provide exactly 1 byte index.")
        if not (0 <= byte_indices[0] < BLOCK_BYTES):
            raise ValueError(f"Byte index {byte_indices[0]} out of range")
        return list(byte_indices)
    else:
        raise ValueError(f"Unknown subset type: {subset}")


def feature_size(
    subset: SubsetType, 
    byte_indices: Sequence[int] | None = None,
) -> int:
    """Розмір вектора ознак (у бітах) для пари шифротекстів.
    
    Формула: len(byte_indices) * 2 * 8
    Множник 2 — бо ми конкатенуємо байти з C0 і C1.
    """
    indices = get_byte_indices(subset, byte_indices)
    return len(indices) * 2 * BITS_PER_BYTE


# ---------------------------------------------------------------------------
# Векторизація
# ---------------------------------------------------------------------------

def vectorize_subset(
    ct0: bytes,
    ct1: bytes,
    indices: Sequence[int],
) -> np.ndarray:
    """Перетворює пару шифротекстів у бітовий вектор ознак.

    Алгоритм (відповідає Zhang et al., Section 2.2):
      1. Вибираємо байти ct0[indices] та ct1[indices].
      2. Конкатенуємо: [ct0_sel || ct1_sel].
      3. Розпаковуємо у біти (MSB-first через numpy.unpackbits).

    Повертає uint8 (0/1) для економії пам'яті (×4 менше ніж float32).
    Конвертуйте у float32 при передачі в PyTorch: tensor.float()
    """
    ct0_sel = bytes(ct0[i] for i in indices)
    ct1_sel = bytes(ct1[i] for i in indices)
    merged = ct0_sel + ct1_sel
    return np.unpackbits(np.frombuffer(merged, dtype=np.uint8))


# ---------------------------------------------------------------------------
# Генерація датасету
# ---------------------------------------------------------------------------

def generate_dataset(
    backend,
    n_samples: int,
    input_diff: bytes,
    rounds: int,
    subset: SubsetType,
    byte_indices: Sequence[int] | None = None,
    fixed_key: bool = False,
) -> Tuple[np.ndarray, np.ndarray]:
    """Генерує датасет для навчання нейро-розрізнювача Калини.
    
    КЛЮЧОВА ВІДМІННІСТЬ від AES-версії (Zhang et al.):
      Для Калини пари генеруються з АДДИТИВНОЮ різницею (mod 2^64),
      а не XOR-різницею. Це необхідно, бо AddRoundKey(0) у Калині
      використовує додавання mod 2^64, яке зберігає аддитивну різницю:
        (P + Δ) + K = (P + K) + Δ  (mod 2^64)
    
    Процедура генерації:
      1. label ~ Bernoulli(0.5)
      2. Випадковий ключ k
      3. Випадковий відкритий текст P0
      4. label=1: P1 = P0 + delta (mod 2^64 по словах)  ← АДДИТИВНА різниця
         label=0: P1 = random
      5. C0 = E_k(P0, rounds),  C1 = E_k(P1, rounds)
      6. Вибір підмножини байтів → бітовий вектор
    """
    if n_samples <= 0:
        raise ValueError("n_samples must be > 0")
    if len(input_diff) != BLOCK_BYTES:
        raise ValueError(f"input_diff must be {BLOCK_BYTES} bytes, got {len(input_diff)}")

    indices = get_byte_indices(subset, byte_indices)
    master_key = backend.random_key() if fixed_key else None

    feat_size = len(indices) * 2 * BITS_PER_BYTE
    # uint8 замість float32: 0/1 бити не потребують float → ×4 менше пам'яті
    X = np.empty((n_samples, feat_size), dtype=np.uint8)
    y = np.empty(n_samples, dtype=np.float32)

    for i in range(n_samples):
        label = int(np.random.randint(0, 2))
        key = master_key if fixed_key else backend.random_key()
        pt0 = backend.random_block()

        if label == 1:
            # АДДИТИВНА різниця (mod 2^64 по словах) замість XOR!
            pt1 = make_additive_pair(pt0, ADDITIVE_DELTA_WORDS)
        else:
            pt1 = backend.random_block()

        ct0 = backend.encrypt_rounds(pt0, key, rounds)
        ct1 = backend.encrypt_rounds(pt1, key, rounds)

        X[i] = vectorize_subset(ct0, ct1, indices)
        y[i] = label

    return X, y


def generate_dataset_selected_bytes(
    backend,
    n_samples: int,
    input_diff: bytes,
    rounds: int,
    byte_indices: Sequence[int],
    fixed_key: bool = False,
) -> Tuple[np.ndarray, np.ndarray]:
    """Генерує датасет для довільної множини вибраних байтів шифротексту."""
    if not byte_indices:
        raise ValueError("byte_indices must be a non-empty sequence")
    if any(not (0 <= idx < BLOCK_BYTES) for idx in byte_indices):
        raise ValueError(f"byte_indices must be in range 0..{BLOCK_BYTES-1}")

    if n_samples <= 0:
        raise ValueError("n_samples must be > 0")
    if len(input_diff) != BLOCK_BYTES:
        raise ValueError(f"input_diff must be {BLOCK_BYTES} bytes, got {len(input_diff)}")

    master_key = backend.random_key() if fixed_key else None

    feat_size = len(list(byte_indices)) * 2 * BITS_PER_BYTE
    # uint8 замість float32: 0/1 бити не потребують float → ×4 менше пам'яті
    X = np.empty((n_samples, feat_size), dtype=np.uint8)
    y = np.empty(n_samples, dtype=np.float32)

    for i in range(n_samples):
        label = int(np.random.randint(0, 2))
        key = master_key if fixed_key else backend.random_key()
        pt0 = backend.random_block()

        if label == 1:
            pt1 = make_additive_pair(pt0, ADDITIVE_DELTA_WORDS)
        else:
            pt1 = backend.random_block()

        ct0 = backend.encrypt_rounds(pt0, key, rounds)
        ct1 = backend.encrypt_rounds(pt1, key, rounds)

        X[i] = vectorize_subset(ct0, ct1, list(byte_indices))
        y[i] = label

    return X, y


# ---------------------------------------------------------------------------
# Параметри моделі
# ---------------------------------------------------------------------------

def model_input_params(
    subset: SubsetType,
    byte_indices: Sequence[int] | None = None,
) -> Tuple[int, int]:
    """Повертає (num_blocks, word_size_bits) для ініціалізації моделі.
    
    Мережа AESLikeResNetDistinguisher очікує:
      - num_blocks  = 2  (завжди, бо ми подаємо пару C0, C1)
      - word_size_bits = len(byte_indices) * 8
    """
    indices = get_byte_indices(subset, byte_indices)
    return 2, len(indices) * BITS_PER_BYTE


# ---------------------------------------------------------------------------
# Конфігурації для систематичних експериментів
# ---------------------------------------------------------------------------

EXPERIMENT_CONFIGS = [
    # (subset, byte_indices, description)
    
    # Повний шифротекст
    (SubsetType.FULL,      None,    "Full ciphertext (128 bits)"),
    
    # Стовпці (слова) — аналог "half ciphertext"
    (SubsetType.COL_0,     None,    "Column 0 / Word 0 (bytes 0-7, 64 bits)"),
    (SubsetType.COL_1,     None,    "Column 1 / Word 1 (bytes 8-15, 64 bits)"),
    
    # Рядки — по 2 байти (по одному з кожного слова)
    (SubsetType.ROW_0,     None,    "Row 0 (bytes 0,8)"),
    (SubsetType.ROW_7,     None,    "Row 7 (bytes 7,15)"),
    
    # 2 байти з одного рядка (= cross-word pair, аналог Table 5 у Zhang et al.)
    (SubsetType.TWO_BYTES, [0, 8],  "2 bytes [0,8] (row 0, cross-word)"),
    (SubsetType.TWO_BYTES, [7, 15], "2 bytes [7,15] (row 7, cross-word)"),
    (SubsetType.TWO_BYTES, [3, 11], "2 bytes [3,11] (row 3, cross-word)"),
    
    # 2 байти з одного стовпця (слова)
    (SubsetType.TWO_BYTES, [0, 1],  "2 bytes [0,1] (col 0, same word)"),
    (SubsetType.TWO_BYTES, [8, 9],  "2 bytes [8,9] (col 1, same word)"),
    
    # 1 байт
    (SubsetType.ONE_BYTE,  [0],     "1 byte [0] (col 0, row 0)"),
    (SubsetType.ONE_BYTE,  [15],    "1 byte [15] (col 1, row 7)"),
]