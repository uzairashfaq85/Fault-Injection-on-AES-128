# Cryptanalysis of AES-128 with a faulted round modification. [1]
# TP created by Amir-Pasha Mirbaha 
# This Python implementation by Sébastien Michelland.
# [1]: https://ieeexplore.ieee.org/abstract/document/6224334 (§IV.B)

import numpy as np
from aes128 import *

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

    i = InvCipher(key, c)
    print("Decoded")
    print(i)

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

    candidates = []
    key = []

    for i in range(16):
        candidates.append([])  # empty list
        key.append([])

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
        for k in range (2):
            # C1: correct one
            state_1 = C1.copy()
            state_1[pos] ^= candidates[pos][k]
            state_1 = ArrayToMatrix(state_1)
            state_1 = InvShiftRows(state_1)
            state_1 = InvSubBytes(state_1)
            out_1 = MatrixToArray(state_1)

            # C3: with fault
            state_3 = C3.copy()
            state_3[pos] ^= candidates[pos][k]
            state_3 = ArrayToMatrix(state_3)
            state_3 = InvShiftRows(state_3)
            state_3 = InvSubBytes(state_3)
            out_3 = MatrixToArray(state_3)

            shifted_pos = pos_after_shiftrows(pos)

            xor = out_1[shifted_pos] ^ out_3[shifted_pos]

            if xor == reverse_2[shifted_pos]:   
                key[pos].append(candidates[pos][k])

    return key

def DFA():

    K10_candidates = test_equations(Ca, Cb, Cc, Da, Db, Dc)
    
    print("Candidates for each byte of K10 in hexadecimal:")
    for i in range(16):
        print("Byte #{}: {}".format(i, [f"{k:02x}" for k in K10_candidates[i]]))

    # catch the first candidate for each byte
    K10_test_1 = np.array([c[0] for c in K10_candidates])
    master_key_from_k10 = InvKeyExpansion(K10_test_1, 10)
    master_key_from_k10 = np.array(master_key_from_k10, dtype=np.uint8)

    c_test_1 = Cipher(master_key_from_k10, Ma)

    if (c_test_1 == Ca).all():
        print("\nFirst candidate is correct:")
        print(master_key_from_k10)
        print("Ciphertext with recovered key:")
        print(c_test_1)

    # for the test_2, only byte 2 has two candidates in the example
    K10_test_2 = K10_test_1.copy()
    K10_test_2[2] = K10_candidates[2][1]
    master_key_from_k10 = InvKeyExpansion(K10_test_2, 10)
    master_key_from_k10 = np.array(master_key_from_k10, dtype=np.uint8)
    c_test_2 = Cipher(master_key_from_k10, Ma)

    if (c_test_2 == Ca).all():
        print("\nSecond candidate is correct:")
        print(master_key_from_k10)
        print("Ciphertext with recovered key:")
        print(c_test_2)

# Test_AES()
DFA()
