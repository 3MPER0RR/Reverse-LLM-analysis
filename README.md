# BinProbe

LLM-assisted static reverse engineering tool. Disassembles ELF and PE binaries, identifies interesting code patterns, and uses an LLM to explain what the code does in plain English.

Drop an unknown binary, get a markdown report.

```
[*] loading test.exe
[*] format=PE  arch=x86-64  entry=0x1400011ab
[*] 312 symbols/imports resolved
[*] .text: 255676 bytes at 0x140001000
[*] 566 strings
[*] 65249 instructions disassembled
[*] 47 unique hotspots

[*] block 0: indirect_call (40 insns @ 0x1400011ab)
...
[+] summary : Windows API call sequence, likely involved in initialization
[+] detail  : The code sets up a stack frame and calls two indirect functions
               via RIP-relative addressing, consistent with MSVC-compiled code
               interacting with COM or shell components.
[+] patterns: Windows API invocation, stack frame setup, indirect call
[+] symbols : KERNEL32!AcquireSRWLockExclusive, USER32, COMCTL32

[+] report written: binprobe_out/test.exe_a788dd22.md
```

---

## Features

- **Auto-detection** — detects ELF or PE from magic signature, no flags needed
- **PE support** — parses Import Directory Table, resolves imports as `KERNEL32!VirtualAlloc`
- **ELF support** — parses `.dynsym`/`.dynstr`, resolves libc imports, fallback on stripped binaries
- **Raw struct parsing** — no pyelftools, no pefile — just `struct`
- **Hotspot detection** — finds code regions worth analyzing: external calls, branch conditions, bulk memory ops, indirect calls, struct access
- **Multi-backend LLM** — Groq (default), Claude, OpenRouter — swap in one line
- **Markdown report** — one file per binary with strings, disassembly, and LLM analysis per block

---

## Install

```bash
git clone https://github.com/youruser/binprobe
cd binprobe
python3 -m venv env
source env/bin/activate
pip install capstone requests
```

Tested on Python 3.10+, macOS and Linux.

---

## Usage

```bash
# analyze a PE
python3 binprobe.py target.exe --backend groq

# analyze an ELF
python3 binprobe.py target_elf --backend groq

# use Claude instead of Groq
python3 binprobe.py target.exe --backend claude
```

Report is written to `binprobe_out/<binary>_<md5[:8]>.md`.

---

## Configuration

Edit the top of `binprobe.py`:

```python
API_KEYS = {
    "claude":     "sk-ant-...",
    "groq":       "gsk_...",
    "openrouter": "sk-or-...",
}

ACTIVE_BACKEND = "groq"   # default backend

BLOCK_WINDOW = 40         # instructions around each hotspot
MAX_BLOCKS   = 3          # max blocks sent to LLM per run (cost control)
OUTPUT_DIR   = "./binprobe_out"
```

For Groq free tier, keep `MAX_BLOCKS` at 3-6 and add a sleep between calls to avoid rate limits:

```python
import time
# in run(), after report.write_block(...)
time.sleep(1.5)
```

---

## Supported formats

| format | arch | symbols |
|--------|------|---------|
| ELF64  | x86-64, AArch64 | `.dynsym` / `.dynstr` |
| PE32+  | x86-64 | Import Directory Table |

Stripped ELF binaries fall back to PT_LOAD segment for code extraction.
Packed PE binaries (UPX, Themida) are not supported — unpack first.

---

## Hotspot types

| type | description |
|------|-------------|
| `call:<name>` | call to a known external function (read, recv, malloc, ...) |
| `indirect_call` | call via register or memory — function pointer, vtable |
| `branch_condition` | cmp/test + conditional jump chain — parser or validation logic |
| `bulk_memop` | rep movs/stos — buffer copy or initialization |
| `struct_access` | lea with scaled index — struct or array traversal |

---

## Output

The report contains:

- binary metadata (MD5, arch, .text size, instruction count)
- strings extracted from `.rodata` / `.rdata`
- for each block: one-line summary, technical explanation, patterns, symbols referenced, full disassembly

---

## Limitations

- PE32 (x86 32-bit) not supported yet, only PE32+ (x86-64)
- no inter-procedural analysis — blocks are analyzed in isolation
- internal calls (`call 0x140001234`) are not resolved to function names
- packed or obfuscated binaries require manual unpacking first

---

## Dependencies

```
capstone >= 5.0
requests >= 2.28
python  >= 3.10
```

No other dependencies. ELF and PE parsing is done with stdlib `struct`.

---


