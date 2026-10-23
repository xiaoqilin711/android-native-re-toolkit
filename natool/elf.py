"""ELF64 segment parsing and virtual-address <-> file-offset translation.

A recurring trap when reading constants out of a stripped Android ``.so`` is
that the second ``PT_LOAD`` segment usually maps ``vaddr = p_offset + 0x1000``
(one page of padding). Reading a constant by file offset without accounting for
that delta silently points at the wrong bytes. The helpers here centralize the
translation so every constant read goes through one reviewed code path.
"""

import struct

PT_LOAD = 1


def parse_segments(data):
    """Parse ELF64 program headers from ``data`` bytes into a segment list.

    Each segment is the tuple
    ``(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz)``.
    Only ELF64 little-endian is supported (the ARM64 Android case).
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 2:  # ELFCLASS64
        raise ValueError("only ELF64 is supported")

    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, _p_paddr = struct.unpack_from("<QQQ", data, off + 8)
        p_filesz, p_memsz, _p_align = struct.unpack_from("<QQQ", data, off + 32)
        segments.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

    return segments


def load_segments(path):
    """Read an ELF64 file and return ``(data, segments)``."""
    with open(path, "rb") as f:
        data = f.read()
    return data, parse_segments(data)


def va_to_off(segments, va):
    """Translate a virtual address to a file offset, or ``None``.

    Returns ``None`` both for addresses outside every load segment and for
    addresses that fall in the zero-filled ``.bss`` tail of a segment.
    """
    for p_type, _flags, p_offset, p_vaddr, p_filesz, p_memsz in segments:
        if p_type != PT_LOAD:
            continue
        if p_vaddr <= va < p_vaddr + p_memsz:
            if va - p_vaddr >= p_filesz:
                return None  # .bss (zero-filled, not present in file)
            return p_offset + (va - p_vaddr)
    return None


def read_va(data, segments, va, size):
    """Read ``size`` bytes at virtual address ``va``, or ``None`` if unmapped."""
    off = va_to_off(segments, va)
    if off is None:
        return None
    return data[off : off + size]


def load_segments_by_va(segments):
    """Return the PT_LOAD segments sorted by ``p_vaddr``."""
    return sorted((s for s in segments if s[0] == PT_LOAD), key=lambda s: s[3])


def hexdump(data, base=0):
    """Render bytes as a ``hex + ascii`` dump, one 16-byte row per line."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hx = " ".join("{:02x}".format(b) for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("{:08x}  {:<48}  {}".format(base + i, hx, asc))
    return "\n".join(lines)
