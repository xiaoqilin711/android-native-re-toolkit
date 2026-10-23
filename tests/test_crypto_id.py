from natool import crypto_id


def test_count_and_offsets():
    data = b"\x00" * 100 + crypto_id.FINGERPRINTS["SHA256_IV"] + b"\xff" * 50
    assert crypto_id.count_occurrences(data, "SHA256_IV") == 1
    assert crypto_id.scan_offsets(data, "SHA256_IV") == [100]


def test_md5_and_sha1_first4_share_iv():
    # Documented trap: SHA-1's first four IV words equal MD5's IV, so a byte
    # search for "the SHA-1 IV" false-matches MD5. The table exposes only the
    # shared first-four as an explicit fingerprint.
    assert crypto_id.FINGERPRINTS["MD5_IV"] == crypto_id.FINGERPRINTS["SHA1_IV_FIRST4"]


def test_big_endian_scan():
    needle = b"\x01\x02\x03\x04"
    data = b"\x00" + needle[::-1] + b"\x00"
    assert crypto_id.count_occurrences(data, needle, endian="big") == 1
    assert crypto_id.count_occurrences(data, needle, endian="little") == 0


def test_no_duplicate_fingerprint_values():
    # Shared constants are collapsed into one entry, never shipped as two equal
    # bytes under two names. The only deliberate equality is MD5_IV ==
    # SHA1_IV_FIRST4 (a documented trap, see the module docstring).
    seen = {}
    for name, raw in crypto_id.FINGERPRINTS.items():
        assert raw is not None, f"{name} is a dead None entry"
        if raw in seen and name != "SHA1_IV_FIRST4":
            raise AssertionError(f"{name} duplicates {seen[raw]}")
        seen[raw] = name
