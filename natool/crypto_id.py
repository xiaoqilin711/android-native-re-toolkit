"""Known crypto constant fingerprints and in-memory scanning.

Identifying which hash/cipher a binary implements is mostly a matter of
scanning for its IVs and round constants. All values here are the public,
standard constants of each algorithm (they carry no secret).

Two scanning modes are provided:

* ``scan_offsets`` — find byte offsets where a fingerprint appears, with
  endianness control (constants are usually stored little-endian on ARM64,
  but a few codecs store them big-endian).
* ``count_occurrences`` — a quick existence check.

A subtlety that keeps biting: some algorithms *share* constants, so a byte
search cannot tell them apart. The table below deliberately collapses those
cases into a single, explicitly-named entry rather than shipping duplicate
bytes under two names (which would double-report the same hit):

* ``SHA1_IV_FIRST4`` — SHA-1's first four IV words equal MD5's IV, so the full
  SHA-1 IV is deliberately *not* shipped; a "full SHA-1 IV" search would
  false-match MD5.
* ``SHA256_IV`` — BLAKE2s reuses SHA-256's IV verbatim, so there is no separate
  BLAKE2s entry. A hit means "SHA-256 or BLAKE2s"; disambiguate with other
  evidence.
* ``CHACHA20_SALSA20_CONST`` — ChaCha20 and Salsa20 share the same
  "expand 32-byte k" constant, so they are one entry.
"""

# Standard IVs / round constants (public algorithm constants).
FINGERPRINTS = {
    "MD5_IV": bytes.fromhex("67452301efcdab8998badcfe10325476"),
    "SHA1_IV_FIRST4": bytes.fromhex("67452301efcdab8998badcfe10325476"),
    "SHA256_IV": bytes.fromhex(
        "6a09e667bb67ae853c6ef372a54ff53a"
        "510e527f9b05688c1f83d9ab5be0cd19"
    ),  # also BLAKE2s's IV (BLAKE2s reuses SHA-256's IV)
    "SHA256_K": bytes.fromhex(
        "428a2f9871374491b5c0fbcf"
    ),  # first 3 of 64 round constants, enough to confirm
    "SHA512_IV": bytes.fromhex(
        "6a09e667f3bcc908bb67ae8584caa73b"
        "3c6ef372fe94f82ba54ff53a5f1d36f1"
        "510e527fade682d19b05688c2b3e6c1f"
        "1f83d9abfb41bd6b5be0cd19137e2179"
    ),
    "AES_SBOX": bytes.fromhex(
        "637c777bf26b6fc53001672bfed7ab76"
        "ca82c97dfa5947f0add4a2af9ca472c0"
    ),
    "CHACHA20_SALSA20_CONST": b"expand 32-byte k",
}


def find_offsets(data, needle):
    """All offsets of ``needle`` inside ``data``."""
    offs = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return offs
        offs.append(i)
        start = i + 1


def scan_offsets(data, fp, endian="little"):
    """Return file offsets where fingerprint ``fp`` (a name or raw bytes) occurs."""
    raw = FINGERPRINTS[fp] if isinstance(fp, str) else fp
    if raw is None:
        return []
    if endian == "big":
        # constants are byte-reversed in the other endianness
        raw = raw[::-1]
    return find_offsets(data, raw)


def count_occurrences(data, fp, endian="little"):
    return len(scan_offsets(data, fp, endian))
