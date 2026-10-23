"""Generic bytecode disassembler for custom VM interpreters.

Some protections move their real logic into a custom stack-machine bytecode
interpreted by a native dispatcher. To reverse it you first need a disassembler
for *that* VM. The opcode set is different for every binary, so this module is
a framework: you supply the ``{opcode: (mnemonic, immediate_length)}`` table,
and it handles decoding, immediates, branch targets and relocation markers.

The ``immediate_length`` of an opcode is the number of bytes (0, 4 or 8) that
follow the opcode and encode its operand.
"""

import struct


class Disassembler:
    def __init__(self, insn_table):
        """``insn_table``: ``{opcode_int: (mnemonic_str, imm_len_int)}``."""
        self.table = insn_table

    def disasm(self, code, relocs=()):
        """Disassemble ``code`` into a list of strings.

        ``relocs`` is an optional iterable of byte offsets (into ``code``) that
        mark the *immediate* of an 8-byte push as a relocated function pointer;
        matching instructions get a ``; RELOC(off)`` annotation.
        """
        lines = []
        i, n = 0, len(code)
        while i < n:
            op = code[i]
            if op not in self.table:
                lines.append("{:04x}: db 0x{:02x}  <unknown>".format(i, op))
                i += 1
                continue

            mnemonic, ilen = self.table[op]
            raw = code[i + 1 : i + 1 + ilen] if ilen else b""
            imm = None
            if ilen == 4 and len(raw) == 4:
                imm = struct.unpack("<i", raw)[0]
            elif ilen == 8 and len(raw) == 8:
                imm = struct.unpack("<Q", raw)[0]

            rel_tag = ""
            if ilen == 8 and (i + 1) in relocs:
                rel_tag = "  ; RELOC({:x}) -> function pointer!".format(i + 1)

            lines.append(self._format(i, mnemonic, imm, ilen, rel_tag))
            i += 1 + ilen
        return lines

    @staticmethod
    def _format(off, mnemonic, imm, ilen, rel_tag):
        if ilen == 0:
            return "{:04x}: {}".format(off, mnemonic)
        if mnemonic in ("brz", "brnz", "jmp"):
            # relative branch: target = next_instr + imm
            return "{:04x}: {:<16} -> {:04x}".format(
                off, mnemonic, (off + 5 + imm) & 0xFFFF
            )
        if mnemonic == "syscall":
            return "{:04x}: {:<16} #{}{}".format(off, mnemonic, imm, rel_tag)
        if ilen == 8:
            return "{:04x}: {:<16} 0x{:x}{}".format(off, mnemonic, imm, rel_tag)
        return "{:04x}: {:<16} {} (0x{:x})".format(
            off, mnemonic, imm, imm & 0xFFFFFFFF
        )
