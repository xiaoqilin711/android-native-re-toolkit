import struct

from natool import vmtables


def _segments():
    # one writable load segment: off=0x1000, vaddr=0x1000, filesz=0x200
    return [(1, 6, 0x1000, 0x1000, 0x200, 0x200)]


def test_find_pointer_pairs():
    text_start, text_end = 0x2000, 0x3000
    data = bytearray(0x1200)
    # put two adjacent pointers inside .data, both pointing into .text
    struct.pack_into("<Q", data, 0x1000, 0x2100)
    struct.pack_into("<Q", data, 0x1008, 0x2200)

    pairs = vmtables.find_pointer_pairs(data, _segments(), text_start, text_end)
    assert pairs == [(0x1000, 0x2100, 0x2200)]


def test_find_pointer_pairs_ignores_non_text():
    text_start, text_end = 0x2000, 0x3000
    data = bytearray(0x1200)
    struct.pack_into("<Q", data, 0x1000, 0x2100)  # inside text
    struct.pack_into("<Q", data, 0x1008, 0x9999)  # outside text

    pairs = vmtables.find_pointer_pairs(data, _segments(), text_start, text_end)
    assert pairs == []
