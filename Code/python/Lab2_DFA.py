#
# Lab2_DFA.py
#
# Differential Fault Analysis workflow for AES-128 sample ciphertext pairs.
# Recovers round-10 key-byte candidates, validates candidate combinations,
# and reconstructs the AES-128 master key from the surviving K10 values.
#
# Usage:
#   python Lab2_DFA.py
#
# Description:
#   - Uses correct and faulty ciphertext pairs to derive K10 byte candidates.
#   - Validates candidate combinations against a known plaintext/ciphertext pair.
#   - Reconstructs the master key via inverse key expansion.
#   - Retains the sample vectors used in the bundled lab exercise.
#
# CHANGE LOG
#
# 2025-11-15 uzair:
#     Removed fixed candidate-count assumptions and validated all surviving
#     K10 candidate combinations against the known AES test pair.
#

import numpy as np
from itertools import product
from aes128 import (
    ArrayToMatrix,
    MatrixToArray,
    MixColumns,
    InvShiftRows,
    InvSubBytes,
    InvKeyExpansion,
    Cipher,
    InvCipher,
)

# All numpy arrays will print in hex without the 0x prefix.
np.set_printoptions(formatter={"int": lambda x: '%02x' % x})

# Converts a hex string like "01 02 03" into a numpy array.
def HexToArray(h):
    h = h.replace(" ", "")
    N = len(h)
    assert N % 2 == 0
    return np.array([int(h[i:i+2], 16) for i in range(0, N, 2)], dtype="uint8")

# Test AES encoding and decoding on a small example.
def Test_AES():
    key = HexToArray("03 93 00 df 6d 21 7a 87 27 ff 29 b8 90 72 47 71")
    msg = HexToArray("48 65 6c 6c 6f 2c 20 6d 79 20 77 6f 72 6c 64 21")

    print("Key")
    print(key)

    print("Message")
    print(msg)

    # Set debug=True to see intermediate steps (verbose!)
    # Compare with: https://legacy.cryptool.org/en/cto/aes-step-by-step
    c = Cipher(key, msg, debug=True)
    print("Ciphertext")
    print(c)

    decoded = InvCipher(key, c)
    print("Decoded")
    print(decoded)

#==============================================================================#

# Ma = [00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f]
# Ca = [50 fe 67 cc 99 6d 32 b6 da 09 37 e9 9b af ec 60]
# Da = [df 48 31 0c 72 3b b3 63 f6 de 95 26 45 e7 ae c3]
Ma = HexToArray("000102030405060708090a0b0c0d0e0f")  # Ma: 1st Plaintext
Ca = HexToArray("50fe67cc996d32b6da0937e99bafec60")  # Ca: Correct ciphertext
Da = HexToArray("df48310c723bb363f6de952645e7aec3")  # Da: Faulty ciphertext

Mb = HexToArray("3243f6a8885a308d313198a2e0370734")  # Mb: 2nd Plaintext
Cb = HexToArray("3925841d02dc09fbdc118597196a0b32")  # Cb: Correct ciphertext
Db = HexToArray("577abf0e3ba2c205acaf4610218fcf33")  # Db: Faulty ciphertext

Mc = HexToArray("ffeeddccbbaa99887766554433221100")  # Mc: 3rd Plaintext
Cc = HexToArray("2f49671c7ab81b2f435d9b650e35b8c1")  # Cc: Correct ciphertext
Dc = HexToArray("378da346dc567473c462386312d232ce")  # Dc: Faulty ciphertext

def pos_after_shiftrows(pos):
    row = pos % 4
    col = pos // 4
    new_col = (col + row) % 4
    return new_col * 4 + row

def compute_reverse(D1, D2):
    return MatrixToArray(MixColumns(ArrayToMatrix(D1 ^ D2)))

def test_equations(C1, C2, C3, D1, D2, D3):
    reverse_1 = compute_reverse(D1, D2)
    reverse_2 = compute_reverse(D1, D3)

    candidates = [[] for _ in range(16)]
    key = [[] for _ in range(16)]

    for pos in range(16):
        candidates[pos] = []

        for k in range(256):
            # C1: correct one
            state_1 = C1.copy()
            state_1[pos] ^= k 
            state_1 = ArrayToMatrix(state_1)
            state_1 = InvShiftRows(state_1)
            state_1 = InvSubBytes(state_1)
            out_1 = MatrixToArray(state_1)

            # C2: with fault
            state_2 = C2.copy()
            state_2[pos] ^= k
            state_2 = ArrayToMatrix(state_2)
            state_2 = InvShiftRows(state_2)
            state_2 = InvSubBytes(state_2)
            out_2 = MatrixToArray(state_2)

            shifted_pos = pos_after_shiftrows(pos)

            xor = out_1[shifted_pos] ^ out_2[shifted_pos]

            if xor == reverse_1[shifted_pos]:
                candidates[pos].append(k)

    for pos in range(16):
        key[pos] = []
        for candidate in candidates[pos]:
            # C1: correct one
            state_1 = C1.copy()
            state_1[pos] ^= candidate
            state_1 = ArrayToMatrix(state_1)
            state_1 = InvShiftRows(state_1)
            state_1 = InvSubBytes(state_1)
            out_1 = MatrixToArray(state_1)

            # C3: with fault
            state_3 = C3.copy()
            state_3[pos] ^= candidate
            state_3 = ArrayToMatrix(state_3)
            state_3 = InvShiftRows(state_3)
            state_3 = InvSubBytes(state_3)
            out_3 = MatrixToArray(state_3)

            shifted_pos = pos_after_shiftrows(pos)

            xor = out_1[shifted_pos] ^ out_3[shifted_pos]

            if xor == reverse_2[shifted_pos]:   
                key[pos].append(candidate)

    return key

def DFA():

    K10_candidates = test_equations(Ca, Cb, Cc, Da, Db, Dc)
    
    print("Candidates for each byte of K10 in hexadecimal:")
    for byte_idx, byte_candidates in enumerate(K10_candidates):
        print("Byte #{}: {}".format(byte_idx, [f"{k:02x}" for k in byte_candidates]))

    if any(len(candidates_for_byte) == 0 for candidates_for_byte in K10_candidates):
        raise ValueError("At least one key byte has no valid K10 candidates.")

    recovered_master_key = None
    recovered_ciphertext = None

    for candidate_tuple in product(*K10_candidates):
        k10_test = np.array(candidate_tuple, dtype=np.uint8)
        master_key_from_k10 = np.array(InvKeyExpansion(k10_test, 10), dtype=np.uint8)
        ciphertext_test = Cipher(master_key_from_k10, Ma)

        if (ciphertext_test == Ca).all():
            recovered_master_key = master_key_from_k10
            recovered_ciphertext = ciphertext_test
            break

    if recovered_master_key is not None:
        print("\nRecovered master key:")
        print(recovered_master_key)
        print("Ciphertext with recovered key:")
        print(recovered_ciphertext)
    else:
        print("\nNo valid master key found from candidate combinations.")

# Test_AES()
DFA()
