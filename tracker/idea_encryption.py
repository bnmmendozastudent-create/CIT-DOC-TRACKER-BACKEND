"""
=============================================================================
INTERNATIONAL DATA ENCRYPTION ALGORITHM (IDEA)
=============================================================================

IDEA is a symmetric-key block cipher that operates on 64-bit blocks of data
using a 128-bit key. It was designed by Xuejia Lai and James Massey in 1991.

KEY CHARACTERISTICS:
- Block size: 64 bits (8 bytes)
- Key size:   128 bits (16 bytes)
- Rounds:     8 full rounds + 1 output transformation
- Operations: XOR, addition mod 2^16, multiplication mod (2^16 + 1)

The strength of IDEA comes from mixing three algebraic groups:
  1. XOR (⊕)                  — addition mod 2
  2. ADD (+)                  — addition mod 2^16
  3. MUL (*)                  — multiplication mod 2^16 + 1 = 65537

These three operations are "incompatible" — no two share distributive law,
which makes the cipher resistant to linear and differential cryptanalysis.
=============================================================================
"""

import os
import base64


# ─────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────

MODULUS   = 65536       # 2^16 — used for addition mod 2^16
MUL_MOD   = 65537       # 2^16 + 1 — used for multiplication mod (2^16+1)
MASK_16   = 0xFFFF      # Bitmask to keep values in 16-bit range


# ─────────────────────────────────────────────────────────
# LOW-LEVEL ARITHMETIC OPERATIONS
# ─────────────────────────────────────────────────────────

def mul(a: int, b: int) -> int:
    """
    Multiplication modulo (2^16 + 1) — IDEA's unique operation.
    
    Special rule: 0 is treated as 2^16 = 65536 in this group.
    This ensures every element has a multiplicative inverse, forming
    a proper mathematical group.
    
    Args:
        a: First 16-bit operand
        b: Second 16-bit operand
    Returns:
        Product modulo 65537, as a 16-bit value
    """
    # Treat 0 as 2^16 (65536) — the identity adjustment for IDEA
    if a == 0:
        a = 65536
    if b == 0:
        b = 65536
    
    result = (a * b) % MUL_MOD
    
    # Map 65536 back to 0 for 16-bit representation
    if result == 65536:
        return 0
    return result


def mul_inv(a: int) -> int:
    """
    Compute the multiplicative inverse of 'a' modulo 65537.
    
    Uses the Extended Euclidean Algorithm to find x such that:
        a * x ≡ 1 (mod 65537)
    
    This inverse is needed during IDEA decryption to reverse
    the multiplication steps from encryption.
    
    Args:
        a: Value to find inverse of (16-bit, where 0 means 65536)
    Returns:
        Multiplicative inverse as a 16-bit value
    """
    if a <= 1:
        return a  # 0 → 0, 1 → 1 (trivial cases)
    
    # Extended Euclidean Algorithm
    # We want to find x where: a*x + 65537*y = 1
    t, newt = 0, 1
    r, newr = MUL_MOD, a
    
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    
    if t < 0:
        t += MUL_MOD
    
    return t % MASK_16


def add_inv(a: int) -> int:
    """
    Compute the additive inverse of 'a' modulo 2^16.
    
    The additive inverse of x is simply (65536 - x) mod 65536.
    Used in IDEA decryption to reverse addition steps.
    
    Args:
        a: 16-bit value
    Returns:
        Additive inverse
    """
    return (-a) % MODULUS


# ─────────────────────────────────────────────────────────
# KEY SCHEDULE (SUBKEY GENERATION)
# ─────────────────────────────────────────────────────────

def generate_subkeys(key: bytes) -> list:
    """
    Generate 52 subkeys from a 128-bit (16 byte) key.
    
    KEY SCHEDULE PROCESS:
    1. Treat the 128-bit key as eight 16-bit subkeys (Z1..Z8)
    2. For the next group of 8 subkeys, cyclically rotate the
       128-bit key left by 25 bits, then extract 8 more subkeys
    3. Repeat until 52 subkeys are generated (6 per round × 8 rounds + 4 output)
    
    The cyclic rotation ensures that every bit of the original key
    contributes to multiple subkeys, improving diffusion.
    
    Args:
        key: 16-byte (128-bit) encryption key
    Returns:
        List of 52 sixteen-bit subkeys
    """
    if len(key) != 16:
        raise ValueError("IDEA key must be exactly 16 bytes (128 bits)")
    
    subkeys = []
    
    # Convert 16 bytes into a 128-bit integer for easy rotation
    key_int = int.from_bytes(key, byteorder='big')
    
    # We need 52 subkeys total (6 per round × 8 rounds + 4 output transform)
    for i in range(52):
        # Extract the top 16 bits as the next subkey
        subkey = (key_int >> 112) & MASK_16
        subkeys.append(subkey)
        
        # Once we extract 8 subkeys, rotate left by 25 bits
        if (i + 1) % 8 == 0:
            # Rotate the 128-bit key left by 25 positions
            key_int = ((key_int << 25) | (key_int >> 103)) & ((1 << 128) - 1)
        else:
            # Shift left by 16 to bring the next 16-bit block to the top
            key_int = ((key_int << 16) | (key_int >> 112)) & ((1 << 128) - 1)
    
    return subkeys


def generate_decrypt_subkeys(encrypt_subkeys: list) -> list:
    """
    Derive the 52 decryption subkeys from the encryption subkeys.
    
    IDEA decryption uses the same structure as encryption, but with
    modified subkeys derived from the encryption subkeys:
    - Multiplicative subkeys → their multiplicative inverses
    - Additive subkeys → their additive inverses (negatives mod 2^16)
    - The order is reversed for each round
    
    Args:
        encrypt_subkeys: 52 subkeys from generate_subkeys()
    Returns:
        List of 52 decryption subkeys
    """
    # Reference the encryption subkeys by round groups
    # Each round uses 6 subkeys; output transform uses 4
    K = encrypt_subkeys
    DK = [0] * 52  # Decryption subkeys
    
    # Output transform becomes the first decryption "round" subkeys
    # Use inverses of the last 4 encryption subkeys
    DK[0]  = mul_inv(K[48])     # Multiplicative inverse of Z49
    DK[1]  = add_inv(K[49])     # Additive inverse of Z50
    DK[2]  = add_inv(K[50])     # Additive inverse of Z51
    DK[3]  = mul_inv(K[51])     # Multiplicative inverse of Z52
    DK[4]  = K[46]              # XOR subkeys (no inverse needed)
    DK[5]  = K[47]
    
    # Reverse and invert subkeys for rounds 1–7
    for i in range(1, 8):
        base_enc = 48 - i * 6
        base_dec = i * 6
        DK[base_dec]     = mul_inv(K[base_enc])
        DK[base_dec + 1] = add_inv(K[base_enc + 2])
        DK[base_dec + 2] = add_inv(K[base_enc + 1])
        DK[base_dec + 3] = mul_inv(K[base_enc + 3])
        DK[base_dec + 4] = K[base_enc - 2]
        DK[base_dec + 5] = K[base_enc - 1]
    
    # Last round (round 8) decryption subkeys
    DK[48] = mul_inv(K[0])
    DK[49] = add_inv(K[1])
    DK[50] = add_inv(K[2])
    DK[51] = mul_inv(K[3])
    
    return DK


# ─────────────────────────────────────────────────────────
# CORE ENCRYPTION / DECRYPTION OF A SINGLE 64-BIT BLOCK
# ─────────────────────────────────────────────────────────

def idea_crypt_block(block: bytes, subkeys: list) -> bytes:
    """
    Encrypt or Decrypt a single 64-bit (8-byte) block using IDEA.
    
    IDEA ROUND STRUCTURE (repeated 8 times):
    ┌─────────────────────────────────────────────────────┐
    │  X1 = MUL(X1, Z1)    X2 = ADD(X2, Z2)              │
    │  X3 = ADD(X3, Z3)    X4 = MUL(X4, Z4)              │
    │  t0 = MUL(X1 XOR X3, Z5)                           │
    │  t1 = ADD(t0, MUL(X2 XOR X4, Z6))                  │
    │  t2 = ADD(t0, t1)  ← wait, let me re-describe      │
    │  [MA-box mixing using Z5 and Z6]                    │
    │  Output: XOR blocks with MA results & swap X2↔X3   │
    └─────────────────────────────────────────────────────┘
    
    OUTPUT TRANSFORMATION (after round 8):
      Y1 = MUL(X1, Z49)   Y2 = ADD(X2, Z50)
      Y3 = ADD(X3, Z51)   Y4 = MUL(X4, Z52)
    
    The same function handles both encryption and decryption —
    only the subkeys differ (enc vs dec subkeys).
    
    Args:
        block:   Exactly 8 bytes of plaintext or ciphertext
        subkeys: 52 subkeys (from generate_subkeys or generate_decrypt_subkeys)
    Returns:
        8-byte encrypted or decrypted block
    """
    if len(block) != 8:
        raise ValueError("IDEA block must be exactly 8 bytes (64 bits)")
    
    # Split 64-bit block into four 16-bit sub-blocks: X1, X2, X3, X4
    X1 = (block[0] << 8) | block[1]
    X2 = (block[2] << 8) | block[3]
    X3 = (block[4] << 8) | block[5]
    X4 = (block[6] << 8) | block[7]
    
    # ── 8 ROUNDS ─────────────────────────────────────────
    for r in range(8):
        z = subkeys[r * 6 : r * 6 + 6]  # Extract 6 subkeys for this round
        
        # Step 1: Apply round subkeys to sub-blocks
        X1 = mul(X1, z[0])              # MUL with Z1
        X2 = (X2 + z[1]) % MODULUS     # ADD with Z2
        X3 = (X3 + z[2]) % MODULUS     # ADD with Z3
        X4 = mul(X4, z[3])              # MUL with Z4
        
        # Step 2: MA (Multiplication-Addition) Box
        # This is the diffusion layer — mixes all four sub-blocks together
        t0 = mul(X1 ^ X3, z[4])         # MUL (X1⊕X3) with Z5
        t1 = mul((X2 ^ X4) + t0, z[5])  # MUL ((X2⊕X4)+t0) with Z6, then ADD t0
        t2 = t0 + t1                     # ADD the two MA results
        t2 %= MODULUS
        
        # Step 3: XOR sub-blocks with MA outputs and swap X2 ↔ X3
        # The swap ensures data crosses between sub-blocks each round
        new_X1 = X1 ^ t1
        new_X2 = X3 ^ t1
        new_X3 = X2 ^ t2
        new_X4 = X4 ^ t2
        
        # Apply swap: X2 and X3 are exchanged (except after round 8)
        if r < 7:
            X1, X2, X3, X4 = new_X1, new_X2, new_X3, new_X4
        else:
            # After the last round, do NOT swap X2 and X3
            X1, X2, X3, X4 = new_X1, new_X3, new_X2, new_X4
    
    # ── OUTPUT TRANSFORMATION ────────────────────────────
    # Final mixing with the last 4 subkeys
    Y1 = mul(X1, subkeys[48])           # MUL with Z49
    Y2 = (X2 + subkeys[49]) % MODULUS  # ADD with Z50
    Y3 = (X3 + subkeys[50]) % MODULUS  # ADD with Z51
    Y4 = mul(X4, subkeys[51])           # MUL with Z52
    
    # Reassemble into 8 bytes
    return bytes([
        (Y1 >> 8) & 0xFF, Y1 & 0xFF,
        (Y2 >> 8) & 0xFF, Y2 & 0xFF,
        (Y3 >> 8) & 0xFF, Y3 & 0xFF,
        (Y4 >> 8) & 0xFF, Y4 & 0xFF,
    ])


# ─────────────────────────────────────────────────────────
# PADDING (PKCS#7)
# ─────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Apply PKCS#7 padding to make data length a multiple of block_size.
    
    PKCS#7 pads with N bytes, each having value N.
    Example: 3 bytes of padding → b'\\x03\\x03\\x03'
    If data is already aligned, a full block of padding is added.
    
    Args:
        data:       Input bytes
        block_size: Block size in bytes (8 for IDEA)
    Returns:
        Padded bytes
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding.
    
    Reads the last byte to determine how many padding bytes to remove.
    
    Args:
        data: Padded bytes (length must be multiple of block size)
    Returns:
        Original bytes without padding
    """
    if not data:
        return data
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 8:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


# ─────────────────────────────────────────────────────────
# HIGH-LEVEL ENCRYPT / DECRYPT (CBC MODE)
# ─────────────────────────────────────────────────────────

def idea_encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt a string using IDEA in CBC (Cipher Block Chaining) mode.
    
    CBC MODE EXPLANATION:
    In CBC, each plaintext block is XORed with the previous ciphertext block
    before encryption. This ensures identical plaintext blocks produce
    different ciphertext blocks, hiding patterns.
    
        C[i] = IDEA_Encrypt(P[i] XOR C[i-1])
        C[0] is the IV (Initialization Vector)
    
    The random IV is prepended to the ciphertext and stored with it.
    
    Args:
        plaintext: The string to encrypt
        key:       16-byte IDEA encryption key
    Returns:
        Base64-encoded ciphertext (IV + encrypted data)
    """
    # Convert plaintext to bytes and pad to 8-byte blocks
    data = pkcs7_pad(plaintext.encode('utf-8'))
    
    # Generate subkeys from the provided key
    subkeys = generate_subkeys(key)
    
    # Generate a random IV (Initialization Vector) — 8 bytes = one IDEA block
    # The IV ensures the same plaintext encrypts to different ciphertexts each time
    iv = os.urandom(8)
    
    ciphertext = b''
    prev_block = iv  # Start CBC chain with IV
    
    # Process each 8-byte block
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        
        # CBC: XOR plaintext block with previous ciphertext block
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        
        # Encrypt the XORed block using IDEA
        encrypted_block = idea_crypt_block(xored, subkeys)
        
        ciphertext += encrypted_block
        prev_block = encrypted_block  # Update CBC chain
    
    # Prepend IV to ciphertext and encode as Base64 for storage
    return base64.b64encode(iv + ciphertext).decode('utf-8')


def idea_decrypt(ciphertext_b64: str, key: bytes) -> str:
    """
    Decrypt a Base64-encoded IDEA CBC ciphertext back to plaintext.
    
    CBC DECRYPTION:
    Decryption is the reverse of encryption:
        P[i] = IDEA_Decrypt(C[i]) XOR C[i-1]
        C[0] is the IV (extracted from the beginning of the ciphertext)
    
    Args:
        ciphertext_b64: Base64-encoded string (IV + ciphertext)
        key:            16-byte IDEA encryption key (same as used for encryption)
    Returns:
        Decrypted plaintext string
    """
    # Decode from Base64 to raw bytes
    raw = base64.b64decode(ciphertext_b64.encode('utf-8'))
    
    # Extract IV (first 8 bytes) and actual ciphertext
    iv = raw[:8]
    ciphertext = raw[8:]
    
    # Generate DECRYPTION subkeys (inverted order from encryption subkeys)
    enc_subkeys = generate_subkeys(key)
    dec_subkeys = generate_decrypt_subkeys(enc_subkeys)
    
    plaintext = b''
    prev_block = iv  # Start CBC chain with IV
    
    # Process each 8-byte block in reverse
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        
        # Decrypt the block using IDEA decryption subkeys
        decrypted_block = idea_crypt_block(block, dec_subkeys)
        
        # CBC: XOR decrypted block with previous ciphertext block
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        
        plaintext += plain_block
        prev_block = block  # Update CBC chain
    
    # Remove PKCS#7 padding and decode to string
    return pkcs7_unpad(plaintext).decode('utf-8')


def idea_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """
    Encrypt raw bytes using IDEA in CBC mode and return IV + ciphertext.
    """
    padded = pkcs7_pad(data)
    subkeys = generate_subkeys(key)
    iv = os.urandom(8)
    ciphertext = b''
    prev_block = iv

    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted_block = idea_crypt_block(xored, subkeys)
        ciphertext += encrypted_block
        prev_block = encrypted_block

    return iv + ciphertext


def idea_decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt raw IDEA CBC data (IV + ciphertext) and return plaintext bytes.
    """
    iv = ciphertext[:8]
    body = ciphertext[8:]
    enc_subkeys = generate_subkeys(key)
    dec_subkeys = generate_decrypt_subkeys(enc_subkeys)
    plaintext = b''
    prev_block = iv

    for i in range(0, len(body), 8):
        block = body[i:i+8]
        decrypted_block = idea_crypt_block(block, dec_subkeys)
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        plaintext += plain_block
        prev_block = block

    return pkcs7_unpad(plaintext)


# ─────────────────────────────────────────────────────────
# DOCUMENT ENCRYPTION HELPERS
# ─────────────────────────────────────────────────────────


DOCUMENT_KEY = b'CIT_IDEA_KEY2024' 


def encrypt_document_field(value: str) -> str:
    """
    Encrypt a document field value using IDEA with the system key.
    
    Args:
        value: Plaintext field value
    Returns:
        Base64-encoded encrypted string
    """
    if not value:
        return value
    return idea_encrypt(value, DOCUMENT_KEY)


def decrypt_document_field(value: str) -> str:
    """
    Decrypt an IDEA-encrypted document field.
    
    Args:
        value: Base64-encoded encrypted string
    Returns:
        Original plaintext value
    """
    if not value:
        return value
    try:
        return idea_decrypt(value, DOCUMENT_KEY)
    except Exception:
        # If decryption fails, return as-is (may already be plaintext)
        return value