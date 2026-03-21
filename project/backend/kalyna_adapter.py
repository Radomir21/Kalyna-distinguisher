from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KalynaConfig:
    name: str
    block_size_bits: int
    key_size_bits: int
    rounds: int

    @property
    def block_size_bytes(self) -> int:
        return self.block_size_bits // 8

    @property
    def key_size_bytes(self) -> int:
        return self.key_size_bits // 8


class KalynaAdapterError(Exception):
    pass


class KalynaAdapter:
    """
    Python adapter to compiled Kalyna DLL via ctypes.

    Expected exported C functions:

    int kalyna_encrypt_block_api(
        const uint8_t* plaintext,
        const uint8_t* key,
        int block_size_bits,
        int key_size_bits,
        uint8_t* ciphertext
    );

    int kalyna_encrypt_rounds_api(
        const uint8_t* plaintext,
        const uint8_t* key,
        int block_size_bits,
        int key_size_bits,
        int rounds,
        uint8_t* ciphertext
    );
    """

    def __init__(self, config: KalynaConfig, dll_path: str | os.PathLike[str]):
        self.config = config
        self.dll_path = Path(dll_path).resolve()

        if not self.dll_path.exists():
            raise FileNotFoundError(f"DLL not found: {self.dll_path}")

        self.lib = ctypes.CDLL(str(self.dll_path))
        self._bind_functions()

    def _bind_functions(self) -> None:
        try:
            self._encrypt_block = self.lib.kalyna_encrypt_block_api
            self._encrypt_rounds = self.lib.kalyna_encrypt_rounds_api
        except AttributeError as exc:
            raise KalynaAdapterError(
                "Required exported functions not found in DLL"
            ) from exc

        self._encrypt_block.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # plaintext
            ctypes.POINTER(ctypes.c_uint8),  # key
            ctypes.c_int,                    # block_size_bits
            ctypes.c_int,                    # key_size_bits
            ctypes.POINTER(ctypes.c_uint8),  # ciphertext
        ]
        self._encrypt_block.restype = ctypes.c_int

        self._encrypt_rounds.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # plaintext
            ctypes.POINTER(ctypes.c_uint8),  # key
            ctypes.c_int,                    # block_size_bits
            ctypes.c_int,                    # key_size_bits
            ctypes.c_int,                    # rounds
            ctypes.POINTER(ctypes.c_uint8),  # ciphertext
        ]
        self._encrypt_rounds.restype = ctypes.c_int

    @staticmethod
    def _to_c_buffer(data: bytes):
        return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)

    @staticmethod
    def _make_output_buffer(size: int):
        return (ctypes.c_uint8 * size)()

    @staticmethod
    def _buffer_to_bytes(buf, size: int) -> bytes:
        return bytes(buf[:size])

    def _validate_plaintext(self, plaintext: bytes) -> None:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes or bytearray")
        if len(plaintext) != self.config.block_size_bytes:
            raise ValueError(
                f"Plaintext must be {self.config.block_size_bytes} bytes, "
                f"got {len(plaintext)}"
            )

    def _validate_key(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")
        if len(key) != self.config.key_size_bytes:
            raise ValueError(
                f"Key must be {self.config.key_size_bytes} bytes, "
                f"got {len(key)}"
            )

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        self._validate_plaintext(plaintext)
        self._validate_key(key)

        pt_buf = self._to_c_buffer(bytes(plaintext))
        key_buf = self._to_c_buffer(bytes(key))
        out_buf = self._make_output_buffer(self.config.block_size_bytes)

        status = self._encrypt_block(
            pt_buf,
            key_buf,
            self.config.block_size_bits,
            self.config.key_size_bits,
            out_buf,
        )

        if status != 0:
            raise KalynaAdapterError(
                f"kalyna_encrypt_block_api failed with status={status}"
            )

        return self._buffer_to_bytes(out_buf, self.config.block_size_bytes)

    def encrypt_rounds(self, plaintext: bytes, key: bytes, rounds: int) -> bytes:
        self._validate_plaintext(plaintext)
        self._validate_key(key)

        if not isinstance(rounds, int):
            raise TypeError("rounds must be int")

        if rounds < 1 or rounds > self.config.rounds:
            raise ValueError(
                f"rounds must be in range 1..{self.config.rounds}, got {rounds}"
            )

        pt_buf = self._to_c_buffer(bytes(plaintext))
        key_buf = self._to_c_buffer(bytes(key))
        out_buf = self._make_output_buffer(self.config.block_size_bytes)

        status = self._encrypt_rounds(
            pt_buf,
            key_buf,
            self.config.block_size_bits,
            self.config.key_size_bits,
            rounds,
            out_buf,
        )

        if status != 0:
            raise KalynaAdapterError(
                f"kalyna_encrypt_rounds_api failed with status={status}"
            )

        return self._buffer_to_bytes(out_buf, self.config.block_size_bytes)


def get_default_dll_path() -> Path:
    """
    Ищем DLL здесь:
    1) рядом с reference implementation
    2) fallback: project/build/kalyna_ref.dll
    """
    current_file = Path(__file__).resolve()

    # .../project/backend/kalyna_adapter.py
    project_dir = current_file.parent.parent
    repo_root = project_dir.parent

    candidate_1 = repo_root / "Kalyna-ref" / "Kalyna-reference" / "kalyna_ref.dll"
    candidate_2 = project_dir / "build" / "kalyna_ref.dll"

    if candidate_1.exists():
        return candidate_1
    if candidate_2.exists():
        return candidate_2

    return candidate_1


def make_default_adapter() -> KalynaAdapter:
    config = KalynaConfig(
        name="Kalyna-128-128",
        block_size_bits=128,
        key_size_bits=128,
        rounds=10,
    )
    return KalynaAdapter(config=config, dll_path=get_default_dll_path())