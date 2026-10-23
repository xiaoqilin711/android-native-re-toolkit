from natool import xorstr


def test_decrypt_identity():
    # key=0, step=1 turns 0,1,2,... into zeros
    assert xorstr.decrypt(b"\x00\x01\x02", key=0, step=1) == b"\x00\x00\x00"


def test_decrypt_roundtrip():
    plain = b"hello"
    key, step = 7, 3
    cipher = bytes((b ^ ((key + step * i) & 0xFF)) for i, b in enumerate(plain))
    assert xorstr.decrypt(cipher, key, step) == plain


def test_brute_step_recovers_key_and_step():
    plain = b"com.example.Class"
    key, step = 2, 3
    cipher = bytes((b ^ ((key + step * i) & 0xFF)) for i, b in enumerate(plain))
    assert xorstr.brute_step(cipher, plain) == (key, step)


def test_is_printable():
    assert xorstr.is_printable(b"hello world")
    assert not xorstr.is_printable(b"\x00\xff")
