from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import sys
from typing import Dict, List
import statistics



ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from project.backend.kalyna_backend import KalynaBackend


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Inputs must have same length")
    return bytes(x ^ y for x, y in zip(a, b))


def make_single_byte_diff(byte_pos: int, value: int, block_size_bytes: int = 16) -> bytes:
    """
    Создаёт разность, где активен один бит в одном байте:
        diff[byte_pos] = value
    где value ∈ {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80}
    """
    if not (0 <= byte_pos < block_size_bytes):
        raise ValueError(f"byte_pos must be in 0..{block_size_bytes - 1}")

    allowed = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    if value not in allowed:
        raise ValueError(f"value must be one of: {[hex(x) for x in allowed]}")

    diff = bytearray(block_size_bytes)
    diff[byte_pos] = value
    return bytes(diff)


def count_active_bytes(x: bytes) -> int:
    return sum(1 for b in x if b != 0)


def count_active_bits(x: bytes) -> int:
    return sum(bin(b).count("1") for b in x)


def to_hex(x: bytes) -> str:
    return " ".join(f"{b:02x}" for b in x)


def analyze_one_difference(
    backend: KalynaBackend,
    diff: bytes,
    samples: int = 300,
    fixed_key: bool = True,
) -> Dict[str, Any]:
    """
    Анализирует одну XOR-разность после 1 раунда:
      pt1 = pt0 XOR diff
      out_diff = ct0 XOR ct1
    """
    if len(diff) != backend.block_size_bytes:
        raise ValueError("diff size mismatch")

    key = backend.random_key() if fixed_key else None

    active_bytes_list: List[int] = []
    active_bits_list: List[int] = []
    byte_hits = [0] * backend.block_size_bytes

    for _ in range(samples):
        if not fixed_key:
            key = backend.random_key()

        pt0 = backend.random_block()
        pt1 = xor_bytes(pt0, diff)

        ct0 = backend.encrypt_rounds(pt0, key, 1)
        ct1 = backend.encrypt_rounds(pt1, key, 1)

        out_diff = xor_bytes(ct0, ct1)

        ab = count_active_bytes(out_diff)
        abit = count_active_bits(out_diff)

        active_bytes_list.append(ab)
        active_bits_list.append(abit)

        for j, b in enumerate(out_diff):
            if b != 0:
                byte_hits[j] += 1

    avg_active_bytes = statistics.mean(active_bytes_list)
    avg_active_bits = statistics.mean(active_bits_list)
    byte_rates = [hits / samples for hits in byte_hits]

    return {
        "avg_active_bytes": avg_active_bytes,
        "avg_active_bits": avg_active_bits,
        "min_active_bytes": min(active_bytes_list),
        "max_active_bytes": max(active_bytes_list),
        "min_active_bits": min(active_bits_list),
        "max_active_bits": max(active_bits_list),
        "byte_rates": byte_rates,
    }


def print_example_for_one_diff(
    byte_pos: int = 0,
    value: int = 0x80,
    fixed_key: bool = True,
    n_examples: int = 3,
) -> None:
    backend = KalynaBackend()
    diff = make_single_byte_diff(byte_pos, value, backend.block_size_bytes)
    key = backend.random_key() if fixed_key else None

    print()
    print("=" * 100)
    print(f"EXAMPLES FOR XOR DIFF: diff[byte_pos={byte_pos}] = 0x{value:02x}")
    print("=" * 100)
    print(f"Input diff: {to_hex(diff)}")
    print()

    for i in range(n_examples):
        if not fixed_key:
            key = backend.random_key()

        pt0 = backend.random_block()
        pt1 = xor_bytes(pt0, diff)

        ct0 = backend.encrypt_rounds(pt0, key, 1)
        ct1 = backend.encrypt_rounds(pt1, key, 1)
        out_diff = xor_bytes(ct0, ct1)

        print(f"[Example {i + 1}]")
        print(f"pt0    : {to_hex(pt0)}")
        print(f"pt1    : {to_hex(pt1)}")
        print(f"ct0    : {to_hex(ct0)}")
        print(f"ct1    : {to_hex(ct1)}")
        print(f"Δ_out  : {to_hex(out_diff)}")
        print(f"active bytes = {count_active_bytes(out_diff)}, active bits = {count_active_bits(out_diff)}")
        print("-" * 100)


def sweep_all_single_bit_byte_differences(
    samples: int = 300,
    fixed_key: bool = True,
) -> List[Dict[str, Any]]:
    """
    Перебирает:
      byte_pos = 0..15
      value ∈ {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80}

    и считает diffusion после 1 раунда через XOR-разность.
    """
    backend = KalynaBackend()

    if backend.block_size_bytes != 16:
        raise ValueError("This script expects Kalyna-128 (16-byte block)")

    bit_values = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    results: List[Dict[str, Any]] = []

    print("=" * 100)
    print("KALYNA-128 / ROUND 1 / XOR DIFFUSION SWEEP")
    print("=" * 100)
    print(f"Samples   : {samples}")
    print(f"Fixed key : {fixed_key}")
    print()

    for byte_pos in range(backend.block_size_bytes):
        for value in bit_values:
            diff = make_single_byte_diff(byte_pos, value, backend.block_size_bytes)
            stats = analyze_one_difference(
                backend=backend,
                diff=diff,
                samples=samples,
                fixed_key=fixed_key,
            )

            row = {
                "byte_pos": byte_pos,
                "value": value,
                "diff": diff,
                **stats,
            }
            results.append(row)

            print(
                f"byte={byte_pos:02d} | diff=0x{value:02x} | "
                f"avg_bytes={stats['avg_active_bytes']:6.3f} | "
                f"avg_bits={stats['avg_active_bits']:7.3f}"
            )

    return results


def print_matrix_avg_bytes(results: List[Dict[str, Any]]) -> None:
    print()
    print("=" * 100)
    print("MATRIX: AVERAGE ACTIVE BYTES AFTER 1 ROUND (XOR)")
    print("rows = byte position, cols = diff value")
    print("=" * 100)

    bit_values = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    print("      " + " ".join(f"{v:>6s}" for v in ["01", "02", "04", "08", "10", "20", "40", "80"]))

    for byte_pos in range(16):
        vals = []
        for value in bit_values:
            match = next(r for r in results if r["byte_pos"] == byte_pos and r["value"] == value)
            vals.append(match["avg_active_bytes"])
        print(f"{byte_pos:02d} | " + " ".join(f"{v:6.2f}" for v in vals))


def print_matrix_avg_bits(results: List[Dict[str, Any]]) -> None:
    print()
    print("=" * 100)
    print("MATRIX: AVERAGE ACTIVE BITS AFTER 1 ROUND (XOR)")
    print("rows = byte position, cols = diff value")
    print("=" * 100)

    bit_values = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    print("      " + " ".join(f"{v:>6s}" for v in ["01", "02", "04", "08", "10", "20", "40", "80"]))

    for byte_pos in range(16):
        vals = []
        for value in bit_values:
            match = next(r for r in results if r["byte_pos"] == byte_pos and r["value"] == value)
            vals.append(match["avg_active_bits"])
        print(f"{byte_pos:02d} | " + " ".join(f"{v:6.2f}" for v in vals))


def print_top_best_and_worst(results: List[Dict[str, Any]], top_n: int = 10) -> None:
    print()
    print("=" * 100)
    print(f"TOP {top_n} BEST DIFFUSING DIFFERENCES (XOR, by avg active bytes)")
    print("=" * 100)

    best = sorted(results, key=lambda x: (x["avg_active_bytes"], x["avg_active_bits"]), reverse=True)[:top_n]
    for r in best:
        print(
            f"byte={r['byte_pos']:02d} | diff=0x{r['value']:02x} | "
            f"avg_bytes={r['avg_active_bytes']:.3f} | avg_bits={r['avg_active_bits']:.3f}"
        )

    print()
    print("=" * 100)
    print(f"TOP {top_n} WEAKEST DIFFUSING DIFFERENCES (XOR, by avg active bytes)")
    print("=" * 100)

    worst = sorted(results, key=lambda x: (x["avg_active_bytes"], x["avg_active_bits"]))[:top_n]
    for r in worst:
        print(
            f"byte={r['byte_pos']:02d} | diff=0x{r['value']:02x} | "
            f"avg_bytes={r['avg_active_bytes']:.3f} | avg_bits={r['avg_active_bits']:.3f}"
        )


def print_byte_rate_map_for_one_case(results: List[Dict[str, Any]], byte_pos: int, value: int) -> None:
    match = next(r for r in results if r["byte_pos"] == byte_pos and r["value"] == value)

    print()
    print("=" * 100)
    print(f"BYTE ACTIVITY RATE MAP FOR byte={byte_pos:02d}, diff=0x{value:02x}")
    print("=" * 100)

    rates = match["byte_rates"]
    print("index :", " ".join(f"{i:02d}" for i in range(len(rates))))
    print("rate  :", " ".join(f"{r:0.2f}" for r in rates))


def main():
    print_example_for_one_diff(
        byte_pos=0,
        value=0x80,
        fixed_key=True,
        n_examples=3,
    )

    results = sweep_all_single_bit_byte_differences(
        samples=300,
        fixed_key=True,
    )

    print_matrix_avg_bytes(results)
    print_matrix_avg_bits(results)
    print_top_best_and_worst(results, top_n=10)

    # Карта активности для одного конкретного случая
    print_byte_rate_map_for_one_case(results, byte_pos=0, value=0x80)


if __name__ == "__main__":
    main()