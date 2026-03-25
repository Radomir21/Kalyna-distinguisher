from project.backend.kalyna_backend import KalynaBackend
import numpy as np



from project.backend.kalyna_backend import KalynaBackend

backend = KalynaBackend()
pt = backend.random_block()
key = backend.random_key()

print(f"[TRACE] pt = {pt.hex()}")
print(f"        key = {key.hex()}\n")

for r in range(1, 11):
    ct = backend.adapter.encrypt_rounds(pt, key, rounds=r)
    print(f"round {r:2d}: {ct.hex()}")