"""
=============================================================
 MLDSC — Multi-Layer Dynamic Shift Cipher
 CC6004 Network and Cloud Security — Group Coursework
 London Metropolitan University, 2025-26
=============================================================
 Group Members:
   Shivas Pillai         (22008121)
   Oluwademilade Soyoye  (23055423)
   Halima Khan           (21007961)
   Muzhgan Kharoti       (22001222)
   Maarya Raja           (21003926)
   Muhammad Abdullah Farooq (21052267)
   Gemechu Jule          (23020721)
   Sabeeh Tayyab         (22008777)
   Dumitru Doris Tanase  (22041369)
   Ryan                  (TBC)
=============================================================

HOW THE CIPHER WORKS — Plain English
--------------------------------------
The MLDSC encrypts text through three sequential layers:

  Layer 1 — Dynamic Shift
    Each character is shifted by a number derived from the key.
    Like the Caesar Cipher but the shift is DIFFERENT for every
    single character, making frequency analysis useless.

  Layer 2 — Position Transform
    Each character is nudged again based on WHERE it sits in
    the message. Even positions shift right, odd shift left.
    This means the same character at position 0 and position 5
    will produce DIFFERENT ciphertext values.

  Layer 3 — XOR with Key Byte
    Each byte is XOR'd with the key schedule byte.
    XOR is self-inverse, so decryption just applies XOR again.
    This is the same fundamental operation used in AES.

  Key Schedule
    The user's password is passed through SHA-256 (a one-way
    cryptographic hash function). The output is chained
    repeatedly to produce as many key bytes as needed.
    This means the key stream never repeats in practice.

=============================================================
"""

import hashlib


# ─────────────────────────────────────────────────────────
#  KEY SCHEDULE
# ─────────────────────────────────────────────────────────

def derive_key_schedule(key: str, length: int) -> list:
    """
    Derive a deterministic byte stream from the user key.

    Process:
        D0 = SHA256(key)
        D1 = SHA256(D0)
        D2 = SHA256(D1)  ... and so on until we have enough bytes.

    Returns a list of integers (0-255) of the requested length.
    """
    digest = hashlib.sha256(key.encode('utf-8')).digest()
    schedule = list(digest)
    while len(schedule) < length:
        digest = hashlib.sha256(digest).digest()
        schedule.extend(list(digest))
    return schedule[:length]


# ─────────────────────────────────────────────────────────
#  ENCRYPTION
# ─────────────────────────────────────────────────────────

def encrypt(plaintext: str, key: str, verbose: bool = False) -> str:
    """
    Encrypt plaintext using MLDSC.
    Returns ciphertext as a hex string.

    Encryption formula per byte i:
        shift  = key_schedule[i] mod 26
        b1     = (plaintext_byte + shift) mod 256          [Layer 1]
        pos    = i mod 16
        b2     = (b1 + pos) mod 256  if i is even          [Layer 2]
               = (b1 - pos) mod 256  if i is odd
        cipher = b2 XOR key_schedule[i]                    [Layer 3]
    """
    key_schedule = derive_key_schedule(key, len(plaintext))
    ciphertext_bytes = []

    if verbose:
        print()
        print("=" * 74)
        print("  MLDSC ENCRYPTION — Step-by-Step Walkthrough")
        print("=" * 74)
        print(f"  Plaintext : {plaintext!r}")
        print(f"  Key       : {key!r}")
        print("=" * 74)
        print(f"  {'i':>3}  {'Ch':>4}  {'ASCII':>5}  "
              f"{'Shift':>5}  {'L1':>5}  {'Pos':>4}  "
              f"{'L2':>5}  {'XOR-K':>6}  {'L3':>5}  {'Hex':>4}")
        print(f"  {'-'*3}  {'-'*4}  {'-'*5}  "
              f"{'-'*5}  {'-'*5}  {'-'*4}  "
              f"{'-'*5}  {'-'*6}  {'-'*5}  {'-'*4}")

    for i, char in enumerate(plaintext):
        original = ord(char)
        k        = key_schedule[i]
        shift    = k % 26
        pos      = i % 16

        b1 = (original + shift) % 256
        b2 = (b1 + pos) % 256 if i % 2 == 0 else (b1 - pos) % 256
        b3 = b2 ^ k

        ciphertext_bytes.append(b3)

        if verbose:
            print(f"  {i:>3}  {repr(char):>4}  {original:>5}  "
                  f"{shift:>5}  {b1:>5}  {pos:>4}  "
                  f"{b2:>5}  {k:>6}  {b3:>5}  {b3:02x}")

    result = ''.join(f'{b:02x}' for b in ciphertext_bytes)

    if verbose:
        print("=" * 74)
        print(f"  Ciphertext (hex): {result}")
        print("=" * 74)
        print()

    return result


# ─────────────────────────────────────────────────────────
#  DECRYPTION
# ─────────────────────────────────────────────────────────

def decrypt(ciphertext_hex: str, key: str, verbose: bool = False) -> str:
    """
    Decrypt a hex-encoded MLDSC ciphertext.
    Returns the original plaintext string.

    Decryption formula per byte i (reverse of encryption):
        b2     = cipher XOR key_schedule[i]                [Rev Layer 3]
        pos    = i mod 16
        b1     = (b2 - pos) mod 256  if i is even          [Rev Layer 2]
               = (b2 + pos) mod 256  if i is odd
        shift  = key_schedule[i] mod 26
        plain  = (b1 - shift) mod 256                      [Rev Layer 1]
    """
    raw_bytes    = [int(ciphertext_hex[j:j+2], 16)
                    for j in range(0, len(ciphertext_hex), 2)]
    key_schedule = derive_key_schedule(key, len(raw_bytes))
    plaintext    = []

    if verbose:
        print()
        print("=" * 74)
        print("  MLDSC DECRYPTION — Step-by-Step Walkthrough")
        print("=" * 74)
        print(f"  Ciphertext (hex): {ciphertext_hex}")
        print(f"  Key             : {key!r}")
        print("=" * 74)
        print(f"  {'i':>3}  {'Hex':>4}  {'Cipher':>6}  "
              f"{'RevL3':>6}  {'RevL2':>6}  {'RevL1':>6}  {'Char':>5}")
        print(f"  {'-'*3}  {'-'*4}  {'-'*6}  "
              f"{'-'*6}  {'-'*6}  {'-'*6}  {'-'*5}")

    for i, b in enumerate(raw_bytes):
        k     = key_schedule[i]
        pos   = i % 16
        shift = k % 26

        rev3 = b ^ k
        rev2 = (rev3 - pos) % 256 if i % 2 == 0 else (rev3 + pos) % 256
        rev1 = (rev2 - shift) % 256

        plaintext.append(chr(rev1))

        if verbose:
            print(f"  {i:>3}  {b:02x}  {b:>6}  "
                  f"{rev3:>6}  {rev2:>6}  {rev1:>6}  {repr(chr(rev1)):>5}")

    result = ''.join(plaintext)

    if verbose:
        print("=" * 74)
        print(f"  Plaintext : {result!r}")
        print("=" * 74)
        print()

    return result


# ─────────────────────────────────────────────────────────
#  SELF TEST
# ─────────────────────────────────────────────────────────

def run_tests():
    print()
    print("=" * 74)
    print("  MLDSC SELF-TEST — Encryption / Decryption Round-Trip")
    print("=" * 74)

    tests = [
        ("Hello World",                    "SecretKey123"),
        ("Network Security",               "CC6004"),
        ("London Metropolitan University", "CyberSec2026"),
        ("The quick brown fox",            "muzhgan"),
        ("MLDSC Cipher Test 123!@#",       "shivas22008121"),
    ]

    all_pass = True
    for pt, key in tests:
        ct        = encrypt(pt, key)
        recovered = decrypt(ct, key)
        ok        = recovered == pt
        if not ok:
            all_pass = False
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}]  key={key!r:<18}  "
              f"plain={pt!r:<35}  hex_len={len(ct)}")

    print("-" * 74)
    print(f"  Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 74)
    print()

    # Show a verbose walkthrough of one example
    print("  Verbose walkthrough — 'Hello World' / key='CC6004':")
    ct = encrypt("Hello World", "CC6004", verbose=True)
    decrypt(ct, "CC6004", verbose=True)


# ─────────────────────────────────────────────────────────
#  INTERACTIVE MENU
# ─────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 74)
    print("   MLDSC — Multi-Layer Dynamic Shift Cipher")
    print("   CC6004 Network and Cloud Security | London Metropolitan University")
    print("=" * 74)

    while True:
        print("\n  Options:")
        print("    [1]  Encrypt a message")
        print("    [2]  Decrypt a message")
        print("    [3]  Run automated tests")
        print("    [4]  Exit")
        choice = input("\n  Enter choice: ").strip()

        if choice == '1':
            pt      = input("  Plaintext : ")
            key     = input("  Key       : ")
            show    = input("  Show step-by-step? (y/n): ").strip().lower() == 'y'
            ct      = encrypt(pt, key, verbose=show)
            if not show:
                print(f"\n  Ciphertext (hex): {ct}")

        elif choice == '2':
            ct_hex  = input("  Ciphertext (hex): ").strip()
            key     = input("  Key              : ")
            show    = input("  Show step-by-step? (y/n): ").strip().lower() == 'y'
            try:
                pt  = decrypt(ct_hex, key, verbose=show)
                if not show:
                    print(f"\n  Plaintext: {pt!r}")
            except Exception:
                print("\n  ERROR: Invalid hex input. Make sure ciphertext is a valid hex string.")

        elif choice == '3':
            run_tests()

        elif choice == '4':
            print("\n  Goodbye.\n")
            break
        else:
            print("  Invalid option.")


if __name__ == "__main__":
    main()
