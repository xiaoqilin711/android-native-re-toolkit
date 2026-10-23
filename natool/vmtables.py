"""Method-table discovery by scanning for adjacent text pointers.

Obfuscated binaries often expose crypto routines through a *method table*:
a struct in ``.data`` holding two adjacent function pointers (init / update,
or compress / finalize) followed by an IV and round constants. Finding those
tables is a reliable way to locate hash implementations without depending on
IDA's cross-references — which OLLVM's jump thunks have already broken.

The heuristic here is deliberately simple: walk the loadable data segments
8-byte-aligned, and flag every pair of consecutive little-endian qwords that
both point inside ``.text``. Callers then decide which candidates are real
tables (e.g. by checking whether an IV follows).
"""

import struct

PT_LOAD = 1


def _iter_data_ranges(segments):
    """Yield ``(data, file_offset_of_data_start, vaddr_of_data_start)`` for
    the writable, file-backed part of each load segment."""
    for p_type, _flags, p_offset, p_vaddr, p_filesz, _memsz in segments:
        if p_type != PT_LOAD:
            continue
        yield p_offset, p_vaddr, p_filesz


def find_pointer_pairs(data, segments, text_start, text_end):
    """Return ``(file_offset, ptr_a, ptr_b)`` for every adjacent pair of qwords
    that both point inside ``[text_start, text_end)``."""
    results = []
    for p_offset, _p_vaddr, p_filesz in _iter_data_ranges(segments):
        end = p_offset + p_filesz - 8  # need room for two qwords
        for off in range(p_offset, end, 8):
            a = struct.unpack_from("<Q", data, off)[0]
            b = struct.unpack_from("<Q", data, off + 8)[0]
            if text_start <= a < text_end and text_start <= b < text_end:
                results.append((off, a, b))
    return results


def find_method_tables(data, segments, text_start, text_end, iv_bytes=None):
    """Find pointer pairs; optionally keep only those whose trailing data
    contains ``iv_bytes`` (e.g. a SHA-256 IV), which strongly indicates a real
    hash method table."""
    pairs = find_pointer_pairs(data, segments, text_start, text_end)
    if iv_bytes is None:
        return pairs
    kept = []
    for off, a, b in pairs:
        # look a little beyond the two pointers for the IV
        window = data[off + 16 : off + 16 + len(iv_bytes) * 4]
        if iv_bytes in window:
            kept.append((off, a, b))
    return kept
