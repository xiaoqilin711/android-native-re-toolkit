"""Full linear-sweep ARM64 disassembly and bl-callgraph reachability.

Under OLLVM, function entries are jump thunks (``adrp + add + br x9``) and calls
are indirect, so IDA's function-boundary detection and cross-references break.
The pragmatic workaround is a *full linear sweep*: ARM64 instructions are a
fixed 4 bytes, so disassembling every 4-byte slot over ``.text`` never "falls
off" an instruction the way a variable-length ISA (x86) would.

Two traps the helpers here avoid:

1. ``capstone``'s one-shot ``disasm`` stops at the first invalid instruction;
   disassembling 4 bytes at a time (with ``skipdata=False`` but a fresh call per
   slot) avoids that early stop.
2. A naive ``bl``-edge scan undercounts calls because indirect calls
   (``blr xN`` / ``br x9`` thunks) are invisible. The callgraph is therefore
   "direct calls only" — treat absence as *unknown*, never as *dead code*.
"""

import bisect

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM

from .elf import read_va


def iter_arm64(data, base, size):
    """Yield capstone instructions, one 4-byte slot at a time, over ``[base, base+size)``."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    end = base + size
    for va in range(base, end, 4):
        insns = list(md.disasm(data[va : va + 4], va))
        if insns:
            yield insns[0]


def collect_bl_edges(insns):
    """Collect ``(caller_va, target_va)`` for every direct ``bl``."""
    edges = []
    for ins in insns:
        if (
            ins.mnemonic == "bl"
            and ins.operands
            and ins.operands[0].type == ARM64_OP_IMM
        ):
            edges.append((ins.address, ins.operands[0].imm))
    return edges


def build_callgraph(edges, roots=()):
    """Build a function-level call graph from ``bl`` edges.

    Function entries are approximated as "every bl target plus the supplied
    roots". Each ``bl`` edge is attributed to the nearest entry at or below the
    caller address. Returns ``(callgraph, entries)`` where ``callgraph`` maps an
    entry to the set of entries it calls.
    """
    entries = sorted(set(t for _, t in edges) | set(roots))
    if not entries:
        return {}, []

    def func_of(va):
        idx = bisect.bisect_right(entries, va) - 1
        return entries[idx] if idx >= 0 else None

    callgraph = {}
    for caller, target in edges:
        cf, tf = func_of(caller), func_of(target)
        if cf is None or tf is None:
            continue
        callgraph.setdefault(cf, set()).add(tf)
    return callgraph, entries


def reachable(callgraph, start):
    """BFS the set of entries reachable from ``start`` (inclusive)."""
    if start not in callgraph:
        return {start}
    seen = set()
    queue = [start]
    while queue:
        node = queue.pop()
        if node in seen:
            continue
        seen.add(node)
        for nxt in callgraph.get(node, ()):
            if nxt not in seen:
                queue.append(nxt)
    return seen


def scan_text(data, segments, text_va, text_size):
    """Read the ``.text`` bytes (or any VA range) and disassemble it."""
    raw = read_va(data, segments, text_va, text_size)
    if raw is None:
        raise ValueError("text range not fully mapped in file")
    return list(iter_arm64(raw, text_va, text_size))
