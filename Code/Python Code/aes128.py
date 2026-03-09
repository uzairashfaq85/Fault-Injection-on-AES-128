# Naive AES128 implementation by Sébastien Michelland

import numpy as np

AES_SBOX = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
], dtype="uint8")

AES_INV_SBOX = np.zeros(256, dtype="uint8")
for i in range(256):
    AES_INV_SBOX[AES_SBOX[i]] = i

# Converts a 16-length array into a 4x4 column-major matrix for Rijndael.
def ArrayToMatrix(a):
    return a.reshape((4, 4)).T

# Converts a 4x4 column-major matrix from Rijndael back into a 16-length array.
def MatrixToArray(m):
    return m.T.flatten()

def SubBytes(state):
    return AES_SBOX[state]

def InvSubBytes(state):
    return AES_INV_SBOX[state]

def ShiftRows(state):
    result = state[:]
    result[1,:] = np.roll(result[1,:], -1)
    result[2,:] = np.roll(result[2,:], -2)
    result[3,:] = np.roll(result[3,:], -3)
    return result

def InvShiftRows(state):
    result = state[:]
    result[1,:] = np.roll(result[1,:], +1)
    result[2,:] = np.roll(result[2,:], +2)
    result[3,:] = np.roll(result[3,:], +3)
    return result

# Multiplication in the Galois group
def _gmul(x, c):
    a = 0
    if x & 1:
        a = c
    x >>= 1
    while x > 0:
        c = ((c << 1) & 0xff) ^ ((c >> 7) * 0x1b)
        if x & 1:
            a ^= c
        x >>= 1
    return a

def MixOneColumn(r):
    result = np.zeros(4, dtype="uint8")
    result[0] = _gmul(r[0], 2) ^ _gmul(r[1], 3) ^ r[2] ^ r[3]
    result[1] = _gmul(r[1], 2) ^ _gmul(r[2], 3) ^ r[3] ^ r[0]
    result[2] = _gmul(r[2], 2) ^ _gmul(r[3], 3) ^ r[0] ^ r[1]
    result[3] = _gmul(r[3], 2) ^ _gmul(r[0], 3) ^ r[1] ^ r[2]
    return result

def InvMixOneColumn(r):
    result = np.zeros(4, dtype="uint8")
    result[0] = _gmul(r[0], 0x0e) ^ _gmul(r[1], 0x0b) ^ _gmul(r[2], 0x0d) ^ _gmul(r[3], 0x09)
    result[1] = _gmul(r[0], 0x09) ^ _gmul(r[1], 0x0e) ^ _gmul(r[2], 0x0b) ^ _gmul(r[3], 0x0d)
    result[2] = _gmul(r[0], 0x0d) ^ _gmul(r[1], 0x09) ^ _gmul(r[2], 0x0e) ^ _gmul(r[3], 0x0b)
    result[3] = _gmul(r[0], 0x0b) ^ _gmul(r[1], 0x0d) ^ _gmul(r[2], 0x09) ^ _gmul(r[3], 0x0e)
    return result

def MixColumns(state):
    result = state[:]
    for i in range(4):
        result[:,i] = MixOneColumn(result[:,i])
    return result

def InvMixColumns(state):
    result = state[:]
    for i in range(4):
        result[:,i] = InvMixOneColumn(result[:,i])
    return result

# key: 16-length array
# Returns expanded 4x44 matrix where each vertical 4x4 slice is a round key
def KeyExpansion(key):
    w = np.zeros((4, 44), dtype="uint8")
    w[:,:4] = key.reshape((4,4)).T
    for i in range(1*4, 11*4):
        temp = w[:,i-1]
        if i % 4 == 0:
            temp = SubBytes(np.roll(temp, -1))
            rcon = 1
            for m in range(i // 4 - 1):
                rcon = _gmul(2, rcon)
            temp[0] ^= rcon
        w[:,i] = w[:,i-4] ^ temp
    return w

# Regenerate the main key from a given round key Ki
# Ki: 4x4 matrix
# i: round number of Ki (0≤i≤10 ; i=0 means Ki is already the main key)
# Returns K as a 16-length array.
def InvKeyExpansion(Ki, i):
    key = ArrayToMatrix(Ki)

    Rcon = np.zeros((4, 10), dtype="uint8")
    Rcon[0,:] = [1,2,4,8,16,32,64,128,27,54]

    for i in range(i, 1-1, -1):
        prev_key = np.zeros((4, 4), dtype="uint8")
        for j in range(3, 1-1, -1):
            prev_key[:,j] = key[:,j-1] ^ key[:,j]

        temp = SubBytes(np.roll(prev_key[:,3],-1))
        prev_key[:,0] = key[:,0] ^ temp ^ Rcon[:,i-1]
        key = prev_key

    return MatrixToArray(key)

def AddRoundKey(state, w):
    return state ^ w

# key, In: 16-length array
# debug: if True, prints intermediate computation steps
# Returns a 16-length array
def Cipher(key, In, debug=False):
    w = KeyExpansion(key)
    if debug:
        print("Expanded keys")
        for i in range(11):
            print("w{}".format(i))
            print(w[:,4*i:4*i+4])

    state = ArrayToMatrix(In.copy())
    if debug:
        print("Message")
        print(state)
    roundKeyOff = 0
    state = AddRoundKey(state, w[:,roundKeyOff:roundKeyOff+4])
    roundKeyOff += 4

    for k in range(1, 9+1):
        if debug:
            print("Round", k)
            print("Input")
            print(state)
        state = SubBytes(state)
        if debug:
            print("After SubBytes")
            print(state)
        state = ShiftRows(state)
        if debug:
            print("After ShiftRows")
            print(state)
        state = MixColumns(state)
        if debug:
            print("After MixColumns")
            print(state)
        state = AddRoundKey(state, w[:,roundKeyOff:roundKeyOff+4])
        roundKeyOff += 4

    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, w[:,roundKeyOff:roundKeyOff+4])
    return MatrixToArray(state)

# key, In: 16-length arrays
# Returns 16-length array
def InvCipher(key, In):
    w = KeyExpansion(key)
    state = ArrayToMatrix(In)
    roundKeyOff = 40

    state = AddRoundKey(state, w[:,roundKeyOff:roundKeyOff+4])
    roundKeyOff -= 4

    for k in range(1, 9+1):
        state = InvShiftRows(state)
        state = InvSubBytes(state)
        state = AddRoundKey(state, w[:,roundKeyOff:roundKeyOff+4])
        roundKeyOff -= 4
        state = InvMixColumns(state)

    state = InvShiftRows(state)
    state = InvSubBytes(state)
    state = AddRoundKey(state, w[:,roundKeyOff:roundKeyOff+4])
    return MatrixToArray(state)
