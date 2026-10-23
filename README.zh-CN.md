# natool — 混淆 Android native 库的静态分析辅助工具

[English](README.md) | [中文](README.zh-CN.md)

一组轻量、少依赖的 Python 构建块，用于逆向那些被 **OLLVM**、**字符串滚动 XOR 混淆**或**自定义 VM 字节码解释器**保护的 ARM64 Android `.so`。

这些是我每次遇到受保护的 native 库时都要手工重写一遍的机械性工具。它们**不会替你反混淆**——只回答那些反复出现的机械问题（"这个常量在哪？""这是不是 OLLVM？""这是哪个哈希？"），让你把精力留给真正需要判断力的部分。

一次完全脱敏的真实项目复盘见 [docs/case-study.md](docs/case-study.md)。

## 为什么需要它

IDA 的默认流水线假设二进制是"干净的"。在 OLLVM 二进制上它会以可预期的方式失效：

* 函数入口是 `adrp + add + br x9` 跳板，**函数边界识别会把函数切碎或粘错**。
* 调用是间接的（`blr xN`），**交叉引用和 `bl` 边调用者分析会静默漏算**——"无调用者"开始变成"无*直接*调用者"，而不是"死代码"。
* 一次性 capstone `disasm` **遇到第一条非法指令就停**，天真的线性扫描会漏算指令。

这个工具集给你绕过这三个坑的原语，外加几个（ELF 偏移→VA 换算、密码学识别、方法表发现、VM 字节码反汇编）。

## 安装

```bash
pip install -e .
```

需要 Python 3.8+ 和 `capstone`。动态工作流的浏览器/设备侧（Frida 等）**故意不**作为依赖——本包只做静态分析。

## 功能

| 模块 | 作用 |
|------|------|
| `natool.elf` | ELF64 程序头解析 + VA ↔ 文件偏移换算（处理经典的 `+0x1000` 第二 LOAD 段 delta） |
| `natool.xorstr` | 滚动 XOR 字符串解密（`dst[i] = src[i] ^ ((key + step·i) & 0xff)`），以及从一个已知明文恢复 key/step |
| `natool.disasm` | 全量线性扫描 ARM64 反汇编（逐 4 字节槽位，不提前停）+ 直接调用图 + BFS 可达性 |
| `natool.crypto_id` | 已知密码学常量指纹（MD5/SHA-1/SHA-256/AES/ChaCha20/Blake2s）+ 按字节序扫描 |
| `natool.ollvm` | OLLVM 启发式：BCF `str wzr` 存储 + 间接跳转计数 |
| `natool.vmtables` | 通过扫描 `.data` 中相邻函数指针对发现方法表 |
| `natool.vmdisasm` | 通用 VM 字节码反汇编框架（opcode 表由你提供） |

## 快速开始

```bash
# dump 程序头（注意 RW 段的 vaddr/off 差）
natool segments libfoo.so

# 虚拟地址处的 hex+ascii dump
natool dump libfoo.so --va 0x9e5b0 --size 0x40

# 解密一个滚动 XOR 字符串
natool xor --hex 63676b --key 2 --step 3

# 扫描已知密码学常量
natool crypto libfoo.so

# .text 上的 OLLVM 启发式
natool ollvm libfoo.so --text-va 0xd2a0 --text-size 0x714ec

# 找方法表（相邻函数指针对）
natool vmtables libfoo.so --text-va 0xd2a0 --text-size 0x714ec
```

或作为库使用：

```python
from natool import elf, disasm, ollvm

data, segments = elf.load_segments("libfoo.so")
insns = disasm.scan_text(data, segments, text_va=0xd2a0, text_size=0x714ec)
print(ollvm.summarize(insns))
```

端到端示例见 [examples/analyze_so.py](examples/analyze_so.py)。

## 诚实边界

* **这不是反混淆器。** 它负责定位和分类；不负责重建控制流、把 VM 字节码提升成语义、或恢复密钥。
* `natool.disasm` 的调用图**只含直接 `bl` 边**。间接调用对静态扫描不可见——把"无调用者"当作"未知"，永远不要当作"死代码"。
* `natool.crypto_id` 只扫**标准公开常量**。IV 用立即数构造、或运行时才解密的算法，是扫不到的——而这本身就是个信号（见案例研究中"SHA-1 看起来不存在"那一节）。
* `natool.vmdisasm` 需要**你**提供 opcode 表；opcode 语义是二进制特定的，无法自动推断。
* 这里的一切都是静态的。真正的结论来自动态层（Frida hook、受控差分测试）；本工具集只帮你走到一个好的 hook 偏移。

## 项目结构

```
natool/
  elf.py        ELF64 段 + VA/offset
  xorstr.py     滚动 XOR 字符串
  disasm.py     线性扫描 + 调用图
  crypto_id.py  密码学指纹
  ollvm.py      OLLVM 启发式
  vmtables.py   方法表发现
  vmdisasm.py   通用 VM 反汇编器
  cli.py        CLI 入口
examples/       端到端 analyze_so.py
tests/          纯逻辑测试（17 个，无需网络/设备）
docs/           脱敏案例研究
```

## 许可

MIT。见 [LICENSE](LICENSE)。
