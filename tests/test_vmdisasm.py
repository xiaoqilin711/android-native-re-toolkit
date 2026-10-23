from natool.vmdisasm import Disassembler


TABLE = {
    0x00: ("nop", 0),
    0x07: ("push_i32", 4),
    0x08: ("push_i64", 8),
    0x46: ("jmp", 4),
    0x4F: ("syscall", 4),
    0x50: ("halt", 0),
}


def dis(*ops):
    code = bytearray()
    for op in ops:
        code.append(op)
    return code


def test_unknown_opcode():
    d = Disassembler(TABLE)
    lines = d.disasm(bytes([0xEE]))
    assert len(lines) == 1
    assert "unknown" in lines[0]


def test_push_i32_immediate():
    d = Disassembler(TABLE)
    code = dis(0x07) + (1234).to_bytes(4, "little", signed=True)
    lines = d.disasm(bytes(code))
    assert "push_i32" in lines[0]
    assert "1234" in lines[0]


def test_jmp_relative_target():
    d = Disassembler(TABLE)
    code = dis(0x46) + (10).to_bytes(4, "little", signed=True)
    lines = d.disasm(bytes(code))
    # jmp at offset 0, next_instr = 5, target = 5 + 10
    assert "-> 000f" in lines[0]


def test_syscall_immediate():
    d = Disassembler(TABLE)
    code = dis(0x4F) + (11).to_bytes(4, "little", signed=True)
    lines = d.disasm(bytes(code))
    assert "#11" in lines[0]


def test_reloc_marker():
    d = Disassembler(TABLE)
    code = dis(0x08) + (0).to_bytes(8, "little")  # push_i64, imm at offset 1
    lines = d.disasm(bytes(code), relocs={1})
    assert "RELOC" in lines[0]
