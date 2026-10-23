import struct

from natool import elf


def make_minimal_elf(segments):
    """Build the smallest ELF64 that :func:`natool.elf.load_segments` accepts.

    ``segments`` is a list of ``(p_offset, p_vaddr, p_filesz, p_memsz, p_flags)``.
    """
    ehsize = 64
    phentsize = 56
    phoff = ehsize
    phnum = len(segments)

    hdr = bytearray(ehsize)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # ELFCLASS64
    hdr[5] = 1  # little-endian
    hdr[6] = 1  # EV_CURRENT
    struct.pack_into("<H", hdr, 16, 2)    # ET_EXEC
    struct.pack_into("<H", hdr, 18, 183)  # EM_AARCH64
    struct.pack_into("<I", hdr, 20, 1)    # e_version
    struct.pack_into("<Q", hdr, 32, phoff)  # e_phoff
    struct.pack_into("<H", hdr, 52, ehsize)
    struct.pack_into("<H", hdr, 54, phentsize)
    struct.pack_into("<H", hdr, 56, phnum)

    ph = bytearray()
    max_end = phoff + phnum * phentsize
    for p_offset, p_vaddr, p_filesz, p_memsz, p_flags in segments:
        ph += struct.pack(
            "<IIQQQQQQ",
            1, p_flags, p_offset, p_vaddr, p_vaddr,
            p_filesz, p_memsz, 0x1000,
        )
        max_end = max(max_end, p_offset + p_filesz)

    data = bytearray(max_end)
    data[0:ehsize] = hdr
    data[phoff : phoff + len(ph)] = ph
    return bytes(data)


def test_va_to_off_delta():
    # seg2 has vaddr = off + 0x1000 (the classic second-LOAD padding trap)
    data = make_minimal_elf(
        [
            (0x0, 0x0, 0x1000, 0x1000, 5),      # RX
            (0x1000, 0x2000, 0x100, 0x100, 6),  # RW, delta +0x1000
        ]
    )
    segments = elf.parse_segments(data)

    assert elf.va_to_off(segments, 0x0) == 0x0
    assert elf.va_to_off(segments, 0x2000) == 0x1000  # delta applied
    assert elf.va_to_off(segments, 0x1500) is None     # gap between segments
    assert elf.va_to_off(segments, 0x2100) is None     # past memsz


def test_va_to_off_bss():
    data = make_minimal_elf(
        [(0x0, 0x0, 0x100, 0x200, 5)]  # filesz < memsz -> .bss tail
    )
    segments = elf.parse_segments(data)
    assert elf.va_to_off(segments, 0x50) == 0x50    # inside file
    assert elf.va_to_off(segments, 0x150) is None    # in .bss (zero-filled)


def test_hexdump_rows():
    dump = elf.hexdump(b"AB\x00\xff", base=0)
    assert "00000000" in dump
    assert "41 42 00 ff" in dump
    assert "AB" in dump  # ascii column renders printable bytes
