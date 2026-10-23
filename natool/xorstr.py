"""Rolling-XOR string decryption.

A very common string obfuscation in native Android code is:

    dst[i] = src[i] ^ ((key + step * i) & 0xff)

with a per-string ``key`` and a fixed ``step`` (usually 1, 2 or 3). Once the
formula and ``step`` are recovered (for example from a single known plaintext
pair), every encrypted string in the binary can be decrypted statically.
"""


def decrypt(raw, key, step=3):
    """Decrypt ``raw`` bytes with the rolling-XOR formula above."""
    return bytes((b ^ ((key + step * i) & 0xFF)) for i, b in enumerate(raw))


def brute_step(cipher, known_plaintext):
    """Recover ``(key, step)`` from one known ``(cipher, plaintext)`` pair.

    ``step`` is guessed over a small range; ``key`` is the low 8 bits of
    ``cipher[0] ^ plaintext[0]``. Returns the first ``(key, step)`` that
    reproduces the full known plaintext, or ``None``.
    """
    if not cipher or len(cipher) < len(known_plaintext):
        return None
    for step in range(0, 16):
        key = cipher[0] ^ known_plaintext[0]
        if decrypt(cipher[: len(known_plaintext)], key, step) == known_plaintext:
            return key, step
    return None


def is_printable(data):
    """True if every byte is printable ASCII or a common whitespace char."""
    return all(32 <= b < 127 or b in (9, 10, 13) for b in data)
