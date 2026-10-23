# Case study: reversing an OLLVM + custom-VM protected native signing module

[English](case-study.md) | [中文](case-study.zh-CN.md)

> **De-identification note.** This write-up is deliberately anonymous: no
> vendor name, package name, real offsets, keys or sample values appear. The
> target was a large e-commerce app's native signing library (a single ARM64
> `.so`). Every address below is illustrative, not the real one.

## What we were up against

The app computed a request signature in native code, behind a library that was:

1. **Stripped** — one exported symbol (`JNI_OnLoad`), everything else registered
   dynamically via `RegisterNatives`.
2. **OLLVM-obfuscated** — bogus control flow, jump thunks, and a flattened main
   dispatcher.
3. **Custom-VM protected** — the actual hash transform lived in bytecode run by
   an 85-instruction stack machine, with a final "post-processing" that made the
   result match *no* standard hash.
4. **Anti-debug guarded** — seccomp + `TracerPid` + anti-Frida strings.

The goal was to reproduce the signature offline, given the device-specific root
secret. This document is about the *method* — the tooling lessons are what got
turned into `natool`.

## Round 1 — recognizing OLLVM (and why IDA lied to us)

The first thing that jumps out is a pair of instructions repeated at the top of
nearly every basic block:

```asm
str wzr, [x20, #0x154]
str wzr, [x21, #0x150]
```

Writes of zero to a fixed stack offset nobody reads. That is OLLVM's **bogus
control flow (BCF)** — dead stores used only to fabricate dead branches so that
decompilers drown in `if (v20 == 0x154)` noise.

The second signature is the **jump thunk**. Almost every function's "entry" was
a trampoline:

```asm
; "entry" of a function
;   save x0-x2
;   adrp + add  -> real body address
;   br x9       -> indirect jump to the real body
```

The indirect `br x9` defeats IDA's function-boundary detection: functions get
split and merged incorrectly, and cross-references disappear.

### Three consequences we had to internalize

1. **Function boundaries are unreliable.** `bl`-edge scanning and xrefs are cut
   by the thunks.
2. **Caller analysis lies by omission.** We initially concluded "HMAC-SHA1 has
   no caller → dead code" from a `bl` scan. Wrong. Under OLLVM every hash entry
   is a `br x9` thunk and calls are indirect, so a `bl` scan *necessarily*
   misses them. "No direct caller" ≠ "dead".
3. **Pure static reading is a dead end.** F5 output is garbage. Conclusions must
   come from dynamic verification.

> **Lesson 1: under OLLVM, "who calls whom" is not "who participates in the
> algorithm".** A function called on the signing path may be a pre-sign
> environment check, not a signing step. The only reliable way to know is to
> observe its inputs/outputs dynamically, not to read who calls it.

## Round 2 — the four-step workaround

**Step 1: full linear sweep with capstone, one 4-byte slot at a time.**

ARM64 is fixed-width, so a linear sweep is safe. The trap is that capstone's
one-shot `disasm` stops at the first invalid byte; disassembling 4 bytes at a
time avoids that early stop. Our first sweep reported 719 `bl` instructions;
the corrected full sweep found **6,971** — nearly 10× more. Every "caller
analysis" built on the 719 was operating on a broken graph.

**Step 2: enumerate method tables instead of guessing entries.**

Each hash ships with a *method table*: `{func_ptr_0, func_ptr_1} + IV + round
constants` in `.data`. Scanning for adjacent qwords that both point into
`.text` surfaced the SHA-256 table immediately. One candidate turned out to be
an anti-detection module, not a hash — its trailing data decrypted to an
environment string (`.build.version.sdk`), and a sweep for references to the
table found zero.

**Step 3: unwrap the jump thunks.**

The function pointers *inside* the table are themselves thunks. Manually
following `br x9` gives the real body:

```
ptr_a -> 0x...:  cbz x0, ret  /  b 0x...     (one hash entry)
ptr_b -> 0x...:  b 0x...                     (another)
```

**Step 4: static locates, dynamic concludes.**

Static work gets you *method tables, entries, and a good hooking offset*. It
does not get you the algorithm. The rest came from dynamic hooks + controlled
differential testing.

## Round 3 — "SHA-1 doesn't exist" (the best trap in the whole engagement)

To confirm which hashes the signing path actually used, we scanned the `.so` at
runtime for known IVs and round constants. Result:

```
MD5_IV     -> 1 hit   (positive control)
SHA256_IV  -> 1 hit   (positive control)
SHA1_IV    -> 0 hits
SHA1_K     -> 0 hits
```

Byte-searching the file for AES/ChaCha20/Salsa20/Blake2s constants also came up
empty. Conclusion: "only MD5 and SHA-256 exist; the 160-bit output must be
custom." **That conclusion was wrong.**

The real answer: **SHA-1's first four IV words are identical to MD5's IV**, and
the fifth word (`0xC3D2E1F0`) was constructed from `mov/movk` immediates, not
stored as a constant. A byte search for "the SHA-1 IV" false-matches MD5, and
the one word that would disambiguate it isn't in memory as a constant at all.

> **Lesson 2: absence of a constant is not absence of an algorithm.** Byte
> search is a *positive* test only. Constants can be built from immediates,
> obfuscated, or decrypted at runtime. This is exactly why `natool.crypto_id`
> only ships the *shared* MD5/SHA-1 first-four, and documents the trap instead
> of pretending a "full SHA-1 IV" search is meaningful.

## Round 4 — cracking the custom VM

The transform that made the output match no standard hash was a custom stack
machine. Its table header carried a magic (`0xB3????1B`, masked), two length fields,
and a relocation list; the bytecode followed. Reversing it was three steps:

1. Recover the opcode → semantics mapping by reading the interpreter's dispatch
   loop (85 opcodes: pushes, loads/stores at 8/16/32/64-bit, arithmetic,
   compares, branches, and a `syscall` opcode that called out to external
   functions via `BLR X9`).
2. Write a disassembler for that opcode set — this is `natool.vmdisasm`, with
   the table made a parameter because it differs per binary.
3. Re-assemble the semantics offline and confirm the output matched the
   device's, byte for byte.

The interpreter itself did almost no math — every real operation was a `syscall`
into a native SHA-256 compress function. The VM existed to hide the *orchestration*
and to add a post-processing layer (`out[i] = (sha[i] + t1[i]) ^ t2[i]`) that
broke naive black-box matching against stock SHA-256.

## Round 5 — controlled differential testing (the real workhorse)

The signature had several inputs. The decisive technique was **change one
variable at a time** and watch the output:

* Same canonical string, called twice → field `s1` identical, `s2`/`s4`
  different → `s1` is a pure function of the canonical string; the others
  include a timestamp.
* Flipping one byte of a hash output → the final value avalanches → it's a hash,
  not a linear combination.
* Fault-injecting a known hash input → confirms which intermediate feeds which
  field.

A small trap worth recording: one input field that looked like a "version
number" was actually an **algorithm selector**. Setting it to a different value
switched the whole pipeline to a *simpler* code path (plain SHA-256 with a
fixed key), which leaked the fact that the key was constant across sessions —
a free conclusion that would have taken much longer to reach through the
obfuscated main path.

## What shipped

The reusable pieces became `natool` (this repository). The site-specific
findings — the exact field layout, the root-secret derivation chain, and the
anti-debug bypass — are **not** published, by design.

## Honest boundaries

* The **root secret's provenance** (where the device key comes from) was not
  fully resolved — only that it is device-level and stable.
* The **canonical-string construction** was reproduced only approximately; the
  exact URL-encoding / ordering rules live in the app's Java layer.
* The **VM was understood, not auto-reversed** — the opcode table had to be
  recovered by hand.
* This work is for **defensive research and interoperability**. Re-signing a
  third-party service's requests in production raises legal questions that are
  entirely outside the scope of this repository.

## Takeaways

1. Under OLLVM, static analysis is *unreliable by default*; use it to locate,
   and dynamic testing to conclude.
2. "Constant not found" is a positive-only test; never a proof of absence.
3. One variable at a time. Controlled differential testing beats hand-reading
   obfuscated control flow almost every time.
4. "Who calls it" is not "what it does". Observe data, not call edges.
