#!/usr/bin/env python3
"""
unitycipher_decrypt.py - Decrypt save/config files made with the "UnityCipher"
library (namespace UnityCipher.RijndaelEncryption), as reverse-engineered from
a real game's Assembly-CSharp.dll (confirmed working on Baldi's Basics
Classic Remastered's PlayerFile_!UnassignedFile.sav).

Format produced by UnityCipher.RijndaelEncryption.Encrypt(bytes, password):
    base64( salt[N] + IV[N] + ciphertext )
  where N = BufferKeySize (default 32 bytes), and:
    - key  = Rfc2898DeriveBytes(password, salt).GetBytes(N)
             -> PBKDF2-HMAC-SHA1, 1000 iterations (the .NET Rfc2898DeriveBytes
                defaults when iterations/hash aren't specified), N-byte output
    - cipher = Rijndael, BlockSize = N*8 bits (NOT standard 128-bit AES — this
               is RijndaelManaged's variable block size, hence a custom
               Rijndael implementation is required; PyCryptodome's AES class
               cannot do this), KeySize = N*8 bits, CBC mode, PKCS7 padding.

The password is typically the save file's own filename (e.g.
"!UnassignedFile" for "PlayerFile_!UnassignedFile.sav" / "..cfg"), per
UnityCipher's typical usage pattern in shipped games -- but isn't guaranteed;
pass --password to override if a game names its slots differently (profile
name, a hardcoded string, etc).

Usage:
    python3 unitycipher_decrypt.py save.sav
    python3 unitycipher_decrypt.py save.sav --password "!UnassignedFile"
    python3 unitycipher_decrypt.py save.sav -o decoded.json
    python3 unitycipher_decrypt.py save.sav --buffer-key-size 16 --iterations 1000

Everything runs locally, stdlib + nothing exotic beyond hashlib.pbkdf2_hmac
(stdlib) for the KDF and the bundled pure-Python Rijndael core for the
block cipher (no third-party crypto dependency required).
"""

import argparse
import base64
import copy
import hashlib
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Pure-Python Rijndael core (variable block size: 16/24/32 bytes), ported
# from the classic Bram Cohen public-domain reference implementation.
# Standard AES libraries (PyCryptodome, cryptography, etc.) only implement
# the fixed 128-bit-block AES variant and CANNOT decrypt UnityCipher's
# default 256-bit-block Rijndael output -- this is why that's bundled here
# instead of just calling out to PyCryptodome.
# --------------------------------------------------------------------------

_shifts = [[[0, 0], [1, 3], [2, 2], [3, 1]],
           [[0, 0], [1, 5], [2, 4], [3, 3]],
           [[0, 0], [1, 7], [3, 5], [4, 4]]]

_num_rounds = {16: {16: 10, 24: 12, 32: 14},
               24: {16: 12, 24: 12, 32: 14},
               32: {16: 14, 24: 14, 32: 14}}


def _build_tables():
    A = [[1, 1, 1, 1, 1, 0, 0, 0],
         [0, 1, 1, 1, 1, 1, 0, 0],
         [0, 0, 1, 1, 1, 1, 1, 0],
         [0, 0, 0, 1, 1, 1, 1, 1],
         [1, 0, 0, 0, 1, 1, 1, 1],
         [1, 1, 0, 0, 0, 1, 1, 1],
         [1, 1, 1, 0, 0, 0, 1, 1],
         [1, 1, 1, 1, 0, 0, 0, 1]]

    alog = [1]
    for _ in range(255):
        j = (alog[-1] << 1) ^ alog[-1]
        if j & 0x100:
            j ^= 0x11B
        alog.append(j)
    log = [0] * 256
    for i in range(1, 255):
        log[alog[i]] = i

    def mul(a, b):
        if a == 0 or b == 0:
            return 0
        return alog[(log[a & 0xFF] + log[b & 0xFF]) % 255]

    box = [[0] * 8 for _ in range(256)]
    box[1][7] = 1
    for i in range(2, 256):
        j = alog[255 - log[i]]
        for t in range(8):
            box[i][t] = (j >> (7 - t)) & 0x01

    B = [0, 1, 1, 0, 0, 0, 1, 1]
    cox = [[0] * 8 for _ in range(256)]
    for i in range(256):
        for t in range(8):
            cox[i][t] = B[t]
            for j in range(8):
                cox[i][t] ^= A[t][j] * box[i][j]

    S = [0] * 256
    Si = [0] * 256
    for i in range(256):
        S[i] = cox[i][0] << 7
        for t in range(1, 8):
            S[i] ^= cox[i][t] << (7 - t)
        Si[S[i] & 0xFF] = i

    G = [[2, 1, 1, 3], [3, 2, 1, 1], [1, 3, 2, 1], [1, 1, 3, 2]]
    AA = [[0] * 8 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            AA[i][j] = G[i][j]
        AA[i][i + 4] = 1
    for i in range(4):
        pivot = AA[i][i]
        if pivot == 0:
            t = i + 1
            while AA[t][i] == 0 and t < 4:
                t += 1
            for j in range(8):
                AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
            pivot = AA[i][i]
        for j in range(8):
            if AA[i][j] != 0:
                AA[i][j] = alog[(255 + log[AA[i][j] & 0xFF] - log[pivot & 0xFF]) % 255]
        for t in range(4):
            if i != t:
                for j in range(i + 1, 8):
                    AA[t][j] ^= mul(AA[i][j], AA[t][i])
                AA[t][i] = 0

    iG = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            iG[i][j] = AA[i][j + 4]

    def mul4(a, bs):
        if a == 0:
            return 0
        r = 0
        for b in bs:
            r <<= 8
            if b != 0:
                r |= mul(a, b)
        return r

    T1, T2, T3, T4, T5, T6, T7, T8 = [], [], [], [], [], [], [], []
    U1, U2, U3, U4 = [], [], [], []
    for t in range(256):
        s = S[t]
        T1.append(mul4(s, G[0])); T2.append(mul4(s, G[1]))
        T3.append(mul4(s, G[2])); T4.append(mul4(s, G[3]))
        s = Si[t]
        T5.append(mul4(s, iG[0])); T6.append(mul4(s, iG[1]))
        T7.append(mul4(s, iG[2])); T8.append(mul4(s, iG[3]))
        U1.append(mul4(t, iG[0])); U2.append(mul4(t, iG[1]))
        U3.append(mul4(t, iG[2])); U4.append(mul4(t, iG[3]))

    rcon = [1]
    r = 1
    for _ in range(1, 30):
        r = mul(2, r)
        rcon.append(r)

    return dict(S=S, Si=Si, T1=T1, T2=T2, T3=T3, T4=T4, T5=T5, T6=T6, T7=T7, T8=T8,
                U1=U1, U2=U2, U3=U3, U4=U4, rcon=rcon)


_TABLES = _build_tables()


class Rijndael:
    def __init__(self, key: bytes, block_size: int):
        if block_size not in (16, 24, 32):
            raise ValueError("block_size must be 16, 24 or 32")
        if len(key) not in (16, 24, 32):
            raise ValueError("key length must be 16, 24 or 32")
        self.block_size = block_size
        S, rcon = _TABLES['S'], _TABLES['rcon']
        U1, U2, U3, U4 = _TABLES['U1'], _TABLES['U2'], _TABLES['U3'], _TABLES['U4']

        ROUNDS = _num_rounds[len(key)][block_size]
        BC = block_size // 4
        Ke = [[0] * BC for _ in range(ROUNDS + 1)]
        Kd = [[0] * BC for _ in range(ROUNDS + 1)]
        ROUND_KEY_COUNT = (ROUNDS + 1) * BC
        KC = len(key) // 4

        tk = []
        for i in range(KC):
            tk.append((key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3])

        t = 0
        j = 0
        while j < KC and t < ROUND_KEY_COUNT:
            Ke[t // BC][t % BC] = tk[j]
            Kd[ROUNDS - (t // BC)][t % BC] = tk[j]
            j += 1
            t += 1
        rconpointer = 0
        while t < ROUND_KEY_COUNT:
            tt = tk[KC - 1]
            tk[0] ^= (((S[(tt >> 16) & 0xFF] & 0xFF) << 24) ^
                      ((S[(tt >> 8) & 0xFF] & 0xFF) << 16) ^
                      ((S[tt & 0xFF] & 0xFF) << 8) ^
                      (S[(tt >> 24) & 0xFF] & 0xFF) ^
                      ((rcon[rconpointer] & 0xFF) << 24))
            tk[0] &= 0xFFFFFFFF
            rconpointer += 1
            if KC != 8:
                for i in range(1, KC):
                    tk[i] = (tk[i] ^ tk[i-1]) & 0xFFFFFFFF
            else:
                for i in range(1, KC // 2):
                    tk[i] = (tk[i] ^ tk[i-1]) & 0xFFFFFFFF
                tt = tk[KC // 2 - 1]
                tk[KC // 2] ^= ((S[tt & 0xFF] & 0xFF) ^
                                ((S[(tt >> 8) & 0xFF] & 0xFF) << 8) ^
                                ((S[(tt >> 16) & 0xFF] & 0xFF) << 16) ^
                                ((S[(tt >> 24) & 0xFF] & 0xFF) << 24))
                tk[KC // 2] &= 0xFFFFFFFF
                for i in range(KC // 2 + 1, KC):
                    tk[i] = (tk[i] ^ tk[i-1]) & 0xFFFFFFFF
            j = 0
            while j < KC and t < ROUND_KEY_COUNT:
                Ke[t // BC][t % BC] = tk[j]
                Kd[ROUNDS - (t // BC)][t % BC] = tk[j]
                j += 1
                t += 1

        for r in range(1, ROUNDS):
            for j in range(BC):
                tt = Kd[r][j]
                Kd[r][j] = (U1[(tt >> 24) & 0xFF] ^ U2[(tt >> 16) & 0xFF] ^
                            U3[(tt >> 8) & 0xFF] ^ U4[tt & 0xFF])
        self.Ke = Ke
        self.Kd = Kd

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != self.block_size:
            raise ValueError("wrong block length")
        Kd = self.Kd
        T5, T6, T7, T8, Si = (_TABLES['T5'], _TABLES['T6'], _TABLES['T7'],
                               _TABLES['T8'], _TABLES['Si'])
        BC = self.block_size // 4
        ROUNDS = len(Kd) - 1
        SC = 0 if BC == 4 else (1 if BC == 6 else 2)
        s1 = _shifts[SC][1][1]
        s2 = _shifts[SC][2][1]
        s3 = _shifts[SC][3][1]
        t = [0] * BC
        for i in range(BC):
            t[i] = ((ciphertext[i*4] << 24) | (ciphertext[i*4+1] << 16) |
                    (ciphertext[i*4+2] << 8) | ciphertext[i*4+3]) ^ Kd[0][i]
        a = [0] * BC
        for r in range(1, ROUNDS):
            for i in range(BC):
                a[i] = (T5[(t[i] >> 24) & 0xFF] ^
                        T6[(t[(i+s1) % BC] >> 16) & 0xFF] ^
                        T7[(t[(i+s2) % BC] >> 8) & 0xFF] ^
                        T8[t[(i+s3) % BC] & 0xFF]) ^ Kd[r][i]
            t = copy.copy(a)
        result = bytearray()
        for i in range(BC):
            tt = Kd[ROUNDS][i]
            result.append((Si[(t[i] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Si[(t[(i+s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Si[(t[(i+s2) % BC] >> 8) & 0xFF] ^ (tt >> 8)) & 0xFF)
            result.append((Si[t[(i+s3) % BC] & 0xFF] ^ tt) & 0xFF)
        return bytes(result)


# --------------------------------------------------------------------------
# UnityCipher-specific chain: salt+IV-prefixed CBC with PKCS7 padding
# --------------------------------------------------------------------------

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > block_size or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding (wrong password/key/salt?)")
    return data[:-pad]


def cbc_decrypt(cipher: Rijndael, iv: bytes, ciphertext: bytes) -> bytes:
    bs = cipher.block_size
    if len(ciphertext) % bs != 0:
        raise ValueError(f"ciphertext length {len(ciphertext)} is not a multiple of block size {bs}")
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), bs):
        block = ciphertext[i:i+bs]
        dec = cipher.decrypt(block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


def decrypt_unitycipher(raw: bytes, password: str, buffer_key_size: int = 32,
                         iterations: int = 1000) -> bytes:
    """
    raw: the base64-decoded file content (salt + IV + ciphertext).
    Returns the plaintext (UTF-8 encoded in the original game, usually JSON).
    """
    n = buffer_key_size
    if len(raw) < 2 * n:
        raise ValueError("file too short to contain a salt+IV header of this size")
    salt = raw[:n]
    iv = raw[n:2*n]
    ct = raw[2*n:]
    key = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), salt, iterations, n)
    cipher = Rijndael(key, n)
    pt = cbc_decrypt(cipher, iv, ct)
    return pkcs7_unpad(pt, n)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Decrypt UnityCipher.RijndaelEncryption-protected save/config files."
    )
    ap.add_argument("input", help="Path to the file (base64 text, e.g. PlayerFile_!X.sav)")
    ap.add_argument("--password", default=None,
                     help="Password used for encryption. Defaults to the input file's "
                          "stem (text between the first and last underscore-delimited "
                          "segment is NOT auto-stripped -- pass explicitly if unsure). "
                          "UnityCipher games commonly use the save filename itself, "
                          "e.g. '!UnassignedFile' for 'PlayerFile_!UnassignedFile.sav'.")
    ap.add_argument("-o", "--out", help="Write decrypted plaintext to this path")
    ap.add_argument("--buffer-key-size", type=int, default=32,
                     help="Salt/IV/key size in bytes (UnityCipher default: 32)")
    ap.add_argument("--iterations", type=int, default=1000,
                     help="PBKDF2 iteration count (.NET Rfc2898DeriveBytes default: 1000)")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"error: file not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if password is None:
        # Best-effort default: the filename's stem with a leading "PlayerFile_" /
        # "PlayerConfig_" (or similar) prefix stripped, if present -- this matches
        # the one confirmed real-world case (Baldi's Basics Classic Remastered).
        # Always verify with --password if this guess is wrong for your game.
        stem = in_path.stem
        for prefix in ("PlayerFile_", "PlayerConfig_", "Player_", "Save_"):
            if stem.startswith(prefix):
                stem = stem[len(prefix):]
                break
        password = stem
        print(f"[*] no --password given; guessing from filename: {password!r}")

    raw_b64 = in_path.read_text(encoding="utf-8", errors="strict").strip()
    raw = base64.b64decode(raw_b64)
    print(f"[*] {in_path.name}  ({len(raw):,} bytes decoded from base64)")

    try:
        pt = decrypt_unitycipher(raw, password, args.buffer_key_size, args.iterations)
    except Exception as e:
        print(f"[!] decrypt failed: {e}", file=sys.stderr)
        print("    (wrong --password, --buffer-key-size, or this file isn't "
              "UnityCipher-encrypted at all)", file=sys.stderr)
        sys.exit(2)

    text = pt.decode('utf-8', errors='replace')
    print(f"[+] decrypted {len(pt):,} bytes")
    print(text if len(text) < 2000 else text[:2000] + "\n... (truncated, see output file)")

    if args.out:
        out_path = Path(args.out)
    else:
        out_path = in_path.with_suffix('.decrypted.json' if text.lstrip().startswith('{') else '.decrypted.txt')
    out_path.write_text(text, encoding='utf-8')
    print(f"[+] wrote plaintext -> {out_path}")


if __name__ == "__main__":
    main()
