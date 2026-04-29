import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from project.backend.kalyna_adapter import make_default_adapter


def main():
    adapter = make_default_adapter()

    pt = bytes.fromhex("4BFCAEBF8930B26C7923FD85A38604DC")
    key = bytes.fromhex("44506E0515255CE8FE13AC1630051442")

    ct_full = adapter.encrypt_block(pt, key)
    ct_r1 = adapter.encrypt_rounds(pt, key, 1)
    ct_r2 = adapter.encrypt_rounds(pt, key, 2)
    ct_r10 = adapter.encrypt_rounds(pt, key, 10)

    print("full:", ct_full.hex())
    print("r1  :", ct_r1.hex())
    print("r2  :", ct_r2.hex())
    print("r10 :", ct_r10.hex())


if __name__ == "__main__":
    main()
