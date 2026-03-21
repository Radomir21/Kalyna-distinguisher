from backend.kalyna_adapter import make_default_adapter


def main():
    adapter = make_default_adapter()

    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    ct_full = adapter.encrypt_block(pt, key)
    ct_r1 = adapter.encrypt_rounds(pt, key, 1)
    ct_r2 = adapter.encrypt_rounds(pt, key, 2)

    print("full:", ct_full.hex())
    print("r1  :", ct_r1.hex())
    print("r2  :", ct_r2.hex())


if __name__ == "__main__":
    main()