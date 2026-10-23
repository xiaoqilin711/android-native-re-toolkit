"""natool — static-analysis helpers for obfuscated Android native libraries.

The toolkit bundles small, dependency-light building blocks that are commonly
needed when reversing an ARM64 ``.so`` that is protected with OLLVM and/or a
custom VM bytecode interpreter:

* :mod:`natool.elf`       — ELF64 segment parsing and VA<->file-offset mapping.
* :mod:`natool.xorstr`    — rolling-XOR string decryption (a common string obfuscation).
* :mod:`natool.disasm`    — full linear-sweep ARM64 disassembly and bl-callgraph reachability.
* :mod:`natool.crypto_id` — known crypto constant fingerprints and scanning.
* :mod:`natool.ollvm`     — OLLVM obfuscation heuristics (BCF stores, jump thunks).
* :mod:`natool.vmtables`  — method-table discovery by scanning adjacent text pointers.
* :mod:`natool.vmdisasm`  — generic VM bytecode disassembler framework.

Every module is site-agnostic: no hardcoded offsets, package names or keys.
"""

__version__ = "0.1.0"

__all__ = [
    "elf",
    "xorstr",
    "disasm",
    "crypto_id",
    "ollvm",
    "vmtables",
    "vmdisasm",
]
