"""End-to-end example: run natool's helpers over an ARM64 ``.so``.

Usage::

    python examples/analyze_so.py path/to/lib.so 0xd2a0 0x714ec

The two hex arguments are the ``.text`` virtual address and size. Every helper
is site-agnostic — point it at any obfuscated native library.
"""

import sys

from natool import crypto_id, disasm, elf, ollvm, vmtables


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 1

    so = sys.argv[1]
    text_va = int(sys.argv[2], 16)
    text_size = int(sys.argv[3], 16)

    data, segments = elf.load_segments(so)

    print("== load segments ==")
    for seg in elf.load_segments_by_va(segments):
        _t, _f, off, vaddr, filesz, memsz = seg
        print("  vaddr=0x{:x} off=0x{:x} filesz=0x{:x} memsz=0x{:x}".format(
            vaddr, off, filesz, memsz))

    insns = disasm.scan_text(data, segments, text_va, text_size)

    print("\n== OLLVM heuristics ==")
    summary = ollvm.summarize(insns)
    print("  {}".format(summary))

    print("\n== direct-call graph ==")
    edges = disasm.collect_bl_edges(insns)
    _cg, entries = disasm.build_callgraph(edges)
    print("  bl edges: {}  approx entries: {}".format(len(edges), len(entries)))

    print("\n== crypto constants ==")
    for name in crypto_id.FINGERPRINTS:
        print("  {:18s} {}".format(name, crypto_id.count_occurrences(data, name)))

    print("\n== method-table pointer pairs ==")
    pairs = vmtables.find_pointer_pairs(data, segments, text_va, text_va + text_size)
    print("  found: {}".format(len(pairs)))
    for off, a, b in pairs[:10]:
        print("  off=0x{:x} -> 0x{:x}, 0x{:x}".format(off, a, b))

    return 0


if __name__ == "__main__":
    sys.exit(main())
