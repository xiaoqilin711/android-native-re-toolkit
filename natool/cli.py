"""Command-line entry point for natool.

Subcommands (run ``natool <cmd> --help`` for details):

* ``segments`` — dump the ELF64 program headers of a ``.so``.
* ``dump``     — hex+ascii dump at a virtual address.
* ``xor``      — rolling-XOR decrypt a hex string.
* ``crypto``   — scan a ``.so`` for known crypto constants.
* ``callgraph``— direct-call graph and BFS reachability from a root address.
* ``ollvm``    — OLLVM heuristics summary over ``.text``.
* ``vmtables`` — scan for adjacent function-pointer pairs (method tables).
"""

import argparse
import sys

from . import crypto_id, disasm, elf, ollvm, vmtables, xorstr


def _load(so):
    return elf.load_segments(so)


def cmd_segments(args):
    _data, segments = _load(args.so)
    for p_type, flags, off, vaddr, filesz, memsz in segments:
        print(
            "type={} flags=0x{:x} off=0x{:x} vaddr=0x{:x} "
            "filesz=0x{:x} memsz=0x{:x}".format(
                p_type, flags, off, vaddr, filesz, memsz
            )
        )
    return 0


def cmd_dump(args):
    data, segments = _load(args.so)
    raw = elf.read_va(data, segments, args.va, args.size)
    if raw is None:
        print("virtual address not mapped in any load segment", file=sys.stderr)
        return 1
    print(elf.hexdump(raw, args.va))
    return 0


def cmd_xor(args):
    raw = bytes.fromhex(args.hex)
    out = xorstr.decrypt(raw, args.key, args.step)
    print(out.hex())
    if xorstr.is_printable(out):
        print(out.decode("latin-1"))
    return 0


def cmd_crypto(args):
    data, _segments = _load(args.so)
    for name in crypto_id.FINGERPRINTS:
        print("{:18s} {}".format(name, crypto_id.count_occurrences(data, name)))
    return 0


def cmd_callgraph(args):
    data, segments = _load(args.so)
    insns = disasm.scan_text(data, segments, args.text_va, args.text_size)
    edges = disasm.collect_bl_edges(insns)
    roots = [args.root] if args.root else []
    callgraph, entries = disasm.build_callgraph(edges, roots=roots)
    print("bl edges: {}  function entries: {}".format(len(edges), len(entries)))
    if args.root:
        reach = disasm.reachable(callgraph, args.root)
        print("reachable from 0x{:x}: {}".format(args.root, len(reach)))
        for f in sorted(reach):
            print("  0x{:x}".format(f))
    return 0


def cmd_ollvm(args):
    data, segments = _load(args.so)
    insns = disasm.scan_text(data, segments, args.text_va, args.text_size)
    summary = ollvm.summarize(insns)
    print(
        "instructions={instructions} bl={bl_calls} "
        "indirect_branches={indirect_branches} bcf_stores={bcf_stores}".format(
            **summary
        )
    )
    for off, count in summary["bcf_top_offsets"]:
        print("  bcf offset {} x{}".format(off, count))
    return 0


def cmd_vmtables(args):
    data, segments = _load(args.so)
    pairs = vmtables.find_pointer_pairs(data, segments, args.text_va, args.text_va + args.text_size)
    print("pointer pairs: {}".format(len(pairs)))
    for off, a, b in pairs:
        print("  off=0x{:x} -> 0x{:x}, 0x{:x}".format(off, a, b))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="natool", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_so(sp):
        sp.add_argument("so", help="path to the ELF64 .so")

    def add_text(sp):
        sp.add_argument("--text-va", type=lambda s: int(s, 16), required=True)
        sp.add_argument("--text-size", type=lambda s: int(s, 16), required=True)

    sp = sub.add_parser("segments")
    add_so(sp)

    sp = sub.add_parser("dump")
    add_so(sp)
    sp.add_argument("--va", type=lambda s: int(s, 16), required=True)
    sp.add_argument("--size", type=lambda s: int(s, 16), required=True)

    sp = sub.add_parser("xor")
    sp.add_argument("--hex", required=True)
    sp.add_argument("--key", type=lambda s: int(s, 0), required=True)
    sp.add_argument("--step", type=int, default=3)

    sp = sub.add_parser("crypto")
    add_so(sp)

    sp = sub.add_parser("callgraph")
    add_so(sp)
    add_text(sp)
    sp.add_argument("--root", type=lambda s: int(s, 16), default=None)

    sp = sub.add_parser("ollvm")
    add_so(sp)
    add_text(sp)

    sp = sub.add_parser("vmtables")
    add_so(sp)
    add_text(sp)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    handler = {
        "segments": cmd_segments,
        "dump": cmd_dump,
        "xor": cmd_xor,
        "crypto": cmd_crypto,
        "callgraph": cmd_callgraph,
        "ollvm": cmd_ollvm,
        "vmtables": cmd_vmtables,
    }[args.cmd]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
