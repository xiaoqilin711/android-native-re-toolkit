# natool — static-analysis helpers for obfuscated Android native libraries

[English](README.md) | [中文](README.zh-CN.md)

Small, dependency-light Python building blocks for reversing ARM64 Android `.so`
files that are protected with **OLLVM**, **string-XOR obfuscation**, or a
**custom VM bytecode interpreter**.

These are the tools I kept re-writing by hand every time I hit a protected
native library. They do not deobfuscate anything for you — they answer the
recurring, mechanical questions ("where is this constant?", "is this OLLVM?",
"which hash is this?") so you can spend your time on the part that actually
requires judgment.

A fully de-identified walkthrough of a real engagement is in
[docs/case-study.md](docs/case-study.md).

## Why this exists

IDA's default pipeline assumes *clean* binaries. On an OLLVM binary it breaks
in predictable ways:

* Function entries are `adrp + add + br x9` trampolines, so **function-boundary
  detection splits and merges functions incorrectly**.
* Calls are indirect (`blr xN`), so **cross-references and `bl`-edge caller
  analysis silently undercount** — "no caller" starts meaning "no *direct*
  caller", not "dead code".
* A one-shot capstone `disasm` **stops at the first invalid instruction**, so
  naive linear sweeps undercount instructions.

This toolkit gives you the primitives to work around those three traps, plus a
few more (ELF offset→VA translation, crypto identification, method-table
discovery, VM bytecode disassembly).

## Install

```bash
pip install -e .
```

Requires Python 3.8+ and `capstone`. The browser/device side of a dynamic
workflow (Frida etc.) is intentionally **not** a dependency — this package is
static-analysis only.

## Features

| Module | What it does |
|--------|--------------|
| `natool.elf` | ELF64 program-header parsing and VA ↔ file-offset translation (handles the classic `+0x1000` second-LOAD delta) |
| `natool.xorstr` | Rolling-XOR string decryption (`dst[i] = src[i] ^ ((key + step·i) & 0xff)`), plus key/step recovery from one known plaintext |
| `natool.disasm` | Full linear-sweep ARM64 disassembly (4-byte slots, no early-stop) and a direct-call graph with BFS reachability |
| `natool.crypto_id` | Known crypto constant fingerprints (MD5/SHA-1/SHA-256/AES/ChaCha20/Blake2s) and endianness-aware scanning |
| `natool.ollvm` | OLLVM heuristics: BCF `str wzr` stores and indirect-branch counts |
| `natool.vmtables` | Method-table discovery by scanning adjacent function-pointer pairs in `.data` |
| `natool.vmdisasm` | Generic VM bytecode disassembler framework (you supply the opcode table) |

## Quick start

```bash
# dump the program headers (watch for a vaddr/off delta on the RW segment)
natool segments libfoo.so

# hex+ascii dump at a virtual address
natool dump libfoo.so --va 0x9e5b0 --size 0x40

# decrypt a rolling-XOR string
natool xor --hex 63676b --key 2 --step 3

# scan for known crypto constants
natool crypto libfoo.so

# OLLVM heuristics over .text
natool ollvm libfoo.so --text-va 0xd2a0 --text-size 0x714ec

# find method tables (adjacent function-pointer pairs)
natool vmtables libfoo.so --text-va 0xd2a0 --text-size 0x714ec
```

Or as a library:

```python
from natool import elf, disasm, ollvm

data, segments = elf.load_segments("libfoo.so")
insns = disasm.scan_text(data, segments, text_va=0xd2a0, text_size=0x714ec)
print(ollvm.summarize(insns))
```

An end-to-end example is in [examples/analyze_so.py](examples/analyze_so.py).

## Honest boundaries

* **This is not a deobfuscator.** It locates and classifies; it does not
  reconstruct control flow, lift VM bytecode to semantics, or recover keys.
* The call graph in `natool.disasm` contains **direct `bl` edges only**.
  Indirect calls are invisible to a static sweep — treat "no caller" as
  "unknown", never as "dead code".
* `natool.crypto_id` scans for **standard public constants**. An algorithm
  whose IV is constructed from immediates, or decrypted at runtime, will not be
  found — which is itself a signal (see the case study's "SHA-1 looked
  missing" episode).
* `natool.vmdisasm` needs **you** to supply the opcode table; opcode semantics
  are binary-specific and cannot be auto-inferred.
* Everything here is static. A dynamic layer (Frida hooks, controlled
  differential testing) is where the real conclusions come from; this toolkit
  only gets you to a good hooking offset.

## Project layout

```
natool/
  elf.py        ELF64 segments + VA/offset
  xorstr.py     rolling-XOR strings
  disasm.py     linear sweep + callgraph
  crypto_id.py  crypto fingerprints
  ollvm.py      OLLVM heuristics
  vmtables.py   method-table discovery
  vmdisasm.py   generic VM disassembler
  cli.py        CLI entry point
examples/       end-to-end analyze_so.py
tests/          pure-logic tests (17, no network/device needed)
docs/           de-identified case study
```

## License

MIT. See [LICENSE](LICENSE).
