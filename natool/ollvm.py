"""Heuristics for recognizing OLLVM obfuscation in a linear-swept binary.

These are *recognition* helpers, not a deobfuscator. They answer the practical
question "am I looking at OLLVM, and where?", so you can decide up-front that
pure static reading is unreliable and switch to a dynamic/black-box strategy.

Recognized signals (all observed in the wild):

* **Bogus Control Flow (BCF)** — ``str wzr, [xN, #imm]`` stores to a fixed stack
  offset repeated across nearly every basic block. The store writes zero to a
  slot nobody reads; it exists only to add dead branches.
* **Jump thunks** — functions whose "entry" is a short ``adrp + add + br x9``
  trampoline. The indirect ``br`` defeats IDA's function-boundary detection and
  hides the real callee graph.
"""

from collections import Counter


def _is_bcf_store(ins):
    """A ``str wzr, [xN, #imm]`` bogus store."""
    return (
        ins.mnemonic == "str"
        and "wzr" in ins.op_str
        and "#0x" in ins.op_str
    )


def _is_indirect_branch(ins):
    """An indirect branch ``br xN`` / ``blr xN`` (jump-thunk / indirect call)."""
    return ins.mnemonic in ("br", "blr")


def bcf_store_offsets(insns):
    """Count ``str wzr`` targets per stack offset (a high, concentrated count
    is the BCF signature)."""
    counter = Counter()
    for ins in insns:
        if not _is_bcf_store(ins):
            continue
        # op_str looks like "wzr, [x20, #0x154]"; keep the offset token.
        tok = ins.op_str.split("#", 1)[-1].strip()
        counter[tok] += 1
    return counter


def indirect_branch_count(insns):
    """Total indirect ``br``/``blr`` instructions (thunk / indirect-call signal)."""
    return sum(1 for ins in insns if _is_indirect_branch(ins))


def summarize(insns):
    """One-line-ish summary dict for an instruction stream.

    Returns counts of: total instructions, direct ``bl`` calls, indirect
    branches, and BCF stores.
    """
    n_bl = sum(1 for ins in insns if ins.mnemonic == "bl")
    bcf = bcf_store_offsets(insns)
    return {
        "instructions": len(insns),
        "bl_calls": n_bl,
        "indirect_branches": indirect_branch_count(insns),
        "bcf_stores": sum(bcf.values()),
        "bcf_top_offsets": bcf.most_common(3),
    }
