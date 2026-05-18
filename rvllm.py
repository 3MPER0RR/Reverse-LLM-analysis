#!/usr/bin/env python3
# rvllm.py - LLM-assisted reverse engineering tool
# disassembles ELF and PE binaries, identifies interesting code patterns,
# and uses an LLM to explain what the code does in plain english
#
# use case: drop an unknown binary in a VM, run this,
#           get a markdown report of what it does
#
# deps: pip install capstone requests
# tested: python 3.10+, ELF x86-64/aarch64 + PE32/PE32+, Ubuntu 22.04 / Wine VM

import sys
import os
import json
import struct
import hashlib
import argparse
import requests
from capstone import *
from capstone.x86 import *

# ----------------------------------------------------------------
# config — edit here, not scattered in the code
# ----------------------------------------------------------------
API_KEYS = {
    "claude":     "sk-ant-...",
    "groq":       "gsk-...",
    "openrouter": "sk-or-...",
}

ACTIVE_BACKEND = "groq"

# instructions around a hotspot to pull into context
BLOCK_WINDOW = 40

# max blocks sent to LLM per run (cost control)
MAX_BLOCKS = 7

# output dir for reports
OUTPUT_DIR = "./rvllm_out"


# ----------------------------------------------------------------
# ELF parser — raw struct, no pyelftools
# handles ELF64 x86-64 and AArch64
# ----------------------------------------------------------------
class ELFParser:
    EM_X86_64  = 0x3e
    EM_AARCH64 = 0xb7

    def __init__(self, data: bytes):
        self.data     = data
        self.arch     = None
        self.mode     = None
        self.sections = {}   # name -> (file_offset, size, vaddr)
        self.segments = []   # list of (type, offset, vaddr, filesz)
        self.entry    = 0

    def parse(self):
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if d[4] != 2:
            raise NotImplementedError("ELF32 not supported")

        e_machine = struct.unpack_from("<H", d, 18)[0]
        self.entry = struct.unpack_from("<Q", d, 24)[0]

        if e_machine == self.EM_X86_64:
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_64
        elif e_machine == self.EM_AARCH64:
            self.arch = CS_ARCH_ARM64
            self.mode = CS_MODE_ARM
        else:
            raise ValueError(f"unsupported machine type: {hex(e_machine)}")

        self._parse_sections()
        self._parse_segments()

    def _parse_sections(self):
        d = self.data
        e_shoff     = struct.unpack_from("<Q", d, 40)[0]
        e_shentsize = struct.unpack_from("<H", d, 58)[0]
        e_shnum     = struct.unpack_from("<H", d, 60)[0]
        e_shstrndx  = struct.unpack_from("<H", d, 62)[0]

        if e_shoff == 0 or e_shnum == 0:
            return  # stripped binary

        strtab_sh  = e_shoff + e_shstrndx * e_shentsize
        st_fileoff = struct.unpack_from("<Q", d, strtab_sh + 24)[0]

        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            sh_name   = struct.unpack_from("<I", d, base)[0]
            sh_addr   = struct.unpack_from("<Q", d, base + 16)[0]
            sh_offset = struct.unpack_from("<Q", d, base + 24)[0]
            sh_size   = struct.unpack_from("<Q", d, base + 32)[0]

            name = d[st_fileoff + sh_name : st_fileoff + sh_name + 64]
            name = name.split(b"\x00")[0].decode("ascii", errors="replace")
            self.sections[name] = (sh_offset, sh_size, sh_addr)

    def _parse_segments(self):
        d = self.data
        e_phoff     = struct.unpack_from("<Q", d, 32)[0]
        e_phentsize = struct.unpack_from("<H", d, 54)[0]
        e_phnum     = struct.unpack_from("<H", d, 56)[0]

        for i in range(e_phnum):
            base     = e_phoff + i * e_phentsize
            p_type   = struct.unpack_from("<I", d, base)[0]
            p_offset = struct.unpack_from("<Q", d, base + 8)[0]
            p_vaddr  = struct.unpack_from("<Q", d, base + 16)[0]
            p_filesz = struct.unpack_from("<Q", d, base + 32)[0]
            self.segments.append((p_type, p_offset, p_vaddr, p_filesz))

    def get_text(self):
        if ".text" in self.sections:
            off, sz, vaddr = self.sections[".text"]
            return self.data[off:off+sz], vaddr

        for p_type, p_offset, p_vaddr, p_filesz in self.segments:
            if p_type == 1:  # PT_LOAD
                return self.data[p_offset:p_offset+p_filesz], p_vaddr

        raise RuntimeError("cannot find executable code section")

    def get_strings(self, min_len=5):
        if ".rodata" in self.sections:
            off, sz, _ = self.sections[".rodata"]
            data = self.data[off:off+sz]
        else:
            data = self.data

        strings, cur = [], []
        for b in data:
            if 0x20 <= b < 0x7f:
                cur.append(chr(b))
            else:
                if len(cur) >= min_len:
                    strings.append("".join(cur))
                cur = []
        return strings


# ----------------------------------------------------------------
# PE parser — raw struct, no pefile dependency
# handles PE32 (x86) and PE32+ (x86-64)
# ----------------------------------------------------------------
class PEParser:
    IMAGE_FILE_MACHINE_I386  = 0x014c
    IMAGE_FILE_MACHINE_AMD64 = 0x8664

    def __init__(self, data: bytes):
        self.data       = data
        self.arch       = None
        self.mode       = None
        self.sections   = {}
        self.entry      = 0
        self.image_base = 0
        self.bits       = 64
        self.imports    = {}   # RVA -> "DLL!func"

    def parse(self):
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("not a PE file")

        e_lfanew = struct.unpack_from("<I", d, 0x3c)[0]
        if d[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            raise ValueError("PE signature not found")

        coff_base    = e_lfanew + 4
        machine      = struct.unpack_from("<H", d, coff_base)[0]
        num_sections = struct.unpack_from("<H", d, coff_base + 2)[0]
        opt_hdr_size = struct.unpack_from("<H", d, coff_base + 16)[0]

        if machine == self.IMAGE_FILE_MACHINE_AMD64:
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_64
            self.bits = 64
        elif machine == self.IMAGE_FILE_MACHINE_I386:
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_32
            self.bits = 32
        else:
            raise ValueError(f"unsupported PE machine: {hex(machine)}")

        opt_base = coff_base + 20
        magic    = struct.unpack_from("<H", d, opt_base)[0]

        if magic == 0x20b:  # PE32+
            self.image_base = struct.unpack_from("<Q", d, opt_base + 24)[0]
            self.entry      = struct.unpack_from("<I", d, opt_base + 16)[0]
            dd_offset       = opt_base + 112
        elif magic == 0x10b:  # PE32
            self.image_base = struct.unpack_from("<I", d, opt_base + 28)[0]
            self.entry      = struct.unpack_from("<I", d, opt_base + 16)[0]
            dd_offset       = opt_base + 96
        else:
            raise ValueError(f"unknown optional header magic: {hex(magic)}")

        sect_base = opt_base + opt_hdr_size
        self._parse_sections(sect_base, num_sections)

        import_rva  = struct.unpack_from("<I", d, dd_offset + 8)[0]
        import_size = struct.unpack_from("<I", d, dd_offset + 12)[0]
        if import_rva and import_size:
            self._parse_imports(import_rva)

    def _parse_sections(self, base: int, count: int):
        d = self.data
        for i in range(count):
            off      = base + i * 40
            name     = d[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize    = struct.unpack_from("<I", d, off + 8)[0]
            vaddr    = struct.unpack_from("<I", d, off + 12)[0]
            raw_size = struct.unpack_from("<I", d, off + 16)[0]
            raw_off  = struct.unpack_from("<I", d, off + 20)[0]
            self.sections[name] = (raw_off, min(vsize, raw_size), vaddr)

    def _parse_imports(self, import_rva: int):
        d      = self.data
        offset = self._rva_to_offset(import_rva)
        if offset is None:
            return

        while True:
            orig_thunk = struct.unpack_from("<I", d, offset)[0]
            name_rva   = struct.unpack_from("<I", d, offset + 12)[0]
            iat_rva    = struct.unpack_from("<I", d, offset + 16)[0]

            if name_rva == 0:
                break

            dll_off  = self._rva_to_offset(name_rva)
            dll_name = ""
            if dll_off is not None:
                dll_name = d[dll_off:dll_off+128].split(b"\x00")[0].decode("ascii", errors="replace")
                dll_name = dll_name.upper().replace(".DLL", "").replace(".EXE", "")

            thunk_rva = orig_thunk if orig_thunk else iat_rva
            thunk_off = self._rva_to_offset(thunk_rva)
            iat_off   = self._rva_to_offset(iat_rva)

            if thunk_off is not None and iat_off is not None:
                thunk_size   = 8 if self.bits == 64 else 4
                fmt          = "<Q" if self.bits == 64 else "<I"
                ordinal_flag = 0x8000000000000000 if self.bits == 64 else 0x80000000

                i = 0
                while True:
                    thunk_val = struct.unpack_from(fmt, d, thunk_off + i * thunk_size)[0]
                    if thunk_val == 0:
                        break

                    if thunk_val & ordinal_flag:
                        func_name = f"ord_{thunk_val & 0xffff}"
                    else:
                        hint_off = self._rva_to_offset(thunk_val & 0x7fffffff)
                        if hint_off is not None:
                            func_name = d[hint_off+2:hint_off+130].split(b"\x00")[0].decode("ascii", errors="replace")
                        else:
                            func_name = "unknown"

                    iat_slot_rva = iat_rva + i * thunk_size
                    self.imports[iat_slot_rva] = f"{dll_name}!{func_name}"
                    i += 1

            offset += 20

    def _rva_to_offset(self, rva: int):
        for name, (raw_off, sz, vaddr) in self.sections.items():
            if vaddr <= rva < vaddr + sz:
                return raw_off + (rva - vaddr)
        return None

    def get_text(self):
        if ".text" in self.sections:
            raw_off, sz, vaddr = self.sections[".text"]
            return self.data[raw_off:raw_off+sz], self.image_base + vaddr

        for name, (raw_off, sz, vaddr) in self.sections.items():
            if sz > 0:
                return self.data[raw_off:raw_off+sz], self.image_base + vaddr

        raise RuntimeError("cannot find executable section in PE")

    def get_strings(self, min_len=5):
        target = ".rdata"
        if target in self.sections:
            raw_off, sz, _ = self.sections[target]
            data = self.data[raw_off:raw_off+sz]
        else:
            data = self.data

        strings, cur = [], []
        for b in data:
            if 0x20 <= b < 0x7f:
                cur.append(chr(b))
            else:
                if len(cur) >= min_len:
                    strings.append("".join(cur))
                cur = []
        return strings


# ----------------------------------------------------------------
# PE symbol resolver
# ----------------------------------------------------------------
class PESymbolResolver:
    def __init__(self, pe: PEParser):
        self.pe   = pe
        self.syms = {}

    def load(self):
        for rva, name in self.pe.imports.items():
            va = self.pe.image_base + rva
            self.syms[va] = name

    def resolve(self, addr: int) -> str:
        return self.syms.get(addr, "")


# ----------------------------------------------------------------
# ELF symbol resolver
# ----------------------------------------------------------------
class SymbolResolver:
    def __init__(self, elf: ELFParser):
        self.elf  = elf
        self.syms = {}

    def load(self):
        d = self.elf.data
        if ".dynsym" not in self.elf.sections or ".dynstr" not in self.elf.sections:
            return

        sym_off, sym_sz, _ = self.elf.sections[".dynsym"]
        str_off, _,      _ = self.elf.sections[".dynstr"]

        entry_size = 24
        for i in range(sym_sz // entry_size):
            base     = sym_off + i * entry_size
            st_name  = struct.unpack_from("<I", d, base)[0]
            st_value = struct.unpack_from("<Q", d, base + 8)[0]
            if st_value == 0:
                continue
            name = d[str_off + st_name : str_off + st_name + 128]
            name = name.split(b"\x00")[0].decode("ascii", errors="replace")
            if name:
                self.syms[st_value] = name

    def resolve(self, addr: int) -> str:
        return self.syms.get(addr, "")


# ----------------------------------------------------------------
# disassembler + hotspot detector
# ----------------------------------------------------------------
class Disassembler:
    INTERESTING_CALLS = {
        "read", "fread", "recv", "recvfrom", "recvmsg",
        "fgets", "gets", "scanf", "sscanf", "fscanf",
        "memcpy", "memmove", "strcpy", "strncpy", "strcat",
        "sprintf", "snprintf", "vsprintf",
        "malloc", "calloc", "realloc", "free",
        "strtol", "strtoul", "atoi", "atol",
        "connect", "bind", "accept", "send", "sendto",
        "open", "fopen", "mmap", "pread",
    }

    def __init__(self, code: bytes, base: int, arch, mode, resolver):
        self.code     = code
        self.base     = base
        self.resolver = resolver
        self.md       = Cs(arch, mode)
        self.md.detail = True
        self.insns    = []
        self.hotspots = []

    def disassemble(self):
        for insn in self.md.disasm(self.code, self.base):
            self.insns.append(insn)

    def find_hotspots(self):
        for i, insn in enumerate(self.insns):
            reason = self._classify(i, insn)
            if reason:
                self.hotspots.append((reason, i))

    def _classify(self, i: int, insn) -> str:
        mn = insn.mnemonic.lower()
        op = insn.op_str.lower()

        if mn == "call":
            target = self._call_target(insn)
            sym    = self.resolver.resolve(target)
            if sym and any(fn in sym for fn in self.INTERESTING_CALLS):
                return f"call:{sym}"
            if "[" in op or (op and op[0] == "r"):
                return "indirect_call"

        if mn in ("cmp", "test"):
            ahead = self.insns[i+1 : i+6]
            if any(j.mnemonic.startswith("j") and j.mnemonic != "jmp" for j in ahead):
                return "branch_condition"

        if "rep" in mn and any(x in mn for x in ("movs", "stos", "cmps")):
            return "bulk_memop"

        if mn == "lea" and "+" in op and "*" in op:
            return "struct_access"

        return ""

    def _call_target(self, insn) -> int:
        try:
            if insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM:
                    return op.imm
        except Exception:
            pass
        return 0

    def extract_block(self, center: int) -> list:
        start = max(0, center - BLOCK_WINDOW // 2)
        end   = min(len(self.insns), center + BLOCK_WINDOW // 2)
        return self.insns[start:end]

    def format_block(self, insns: list, reason: str) -> str:
        lines = [f"; hotspot type: {reason}"]
        for insn in insns:
            sym   = self.resolver.resolve(insn.address)
            label = f"<{sym}>:" if sym else ""
            lines.append(f"  {label:20s} 0x{insn.address:08x}  {insn.mnemonic:<10} {insn.op_str}")
        return "\n".join(lines)

    def dedup_hotspots(self) -> list:
        used, out = set(), []
        for reason, center in self.hotspots:
            if not any(abs(center - c) < BLOCK_WINDOW // 2 for c in used):
                out.append((reason, center))
                used.add(center)
        return out


# ----------------------------------------------------------------
# LLM backend
# ----------------------------------------------------------------
class LLMAnalyzer:
    SYSTEM = (
        "You are a reverse engineering assistant helping a security researcher "
        "understand an unknown binary. "
        "Given a disassembly block, explain in plain English: "
        "what this code does, what data it operates on, the control flow logic, "
        "and any notable patterns (parsing loop, state machine, crypto primitive, "
        "string processing, network protocol, etc). "
        "Be concise and technical. Do not speculate beyond what the code shows. "
        "Respond ONLY with valid JSON in this exact format: "
        '{"summary": "one line description", '
        '"detail": "2-4 sentence technical explanation", '
        '"patterns": ["list", "of", "identified", "patterns"], '
        '"symbols_seen": ["external", "functions", "referenced"]}'
    )

    def __init__(self, backend: str):
        self.backend = backend
        self.key     = API_KEYS[backend]

    def analyze(self, block_text: str, strings: list) -> dict:
        ctx = ""
        if strings:
            ctx = "\n\nStrings found in binary (may be referenced by this code):\n"
            ctx += "\n".join(f"  {s}" for s in strings[:20])

        prompt = f"Analyze this disassembly block:{ctx}\n\n```asm\n{block_text}\n```"
        raw    = self._dispatch(prompt)
        return self._parse(raw)

    def _dispatch(self, prompt: str) -> str:
        if self.backend == "claude":
            return self._claude(prompt)
        if self.backend == "groq":
            return self._groq(prompt)
        if self.backend == "openrouter":
            return self._openrouter(prompt)
        raise ValueError(f"unknown backend: {self.backend}")

    def _claude(self, prompt: str) -> str:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 1024,
                "system": self.SYSTEM,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=45,
        )
        r.raise_for_status()
        return r.json()["content"][0]["text"]

    def _groq(self, prompt: str) -> str:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": self.SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                "max_tokens": 1024,
            },
            timeout=45,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def _openrouter(self, prompt: str) -> str:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "deepseek/deepseek-chat",
                "messages": [
                    {"role": "system", "content": self.SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
            },
            timeout=45,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def _parse(self, text: str) -> dict:
        text = text.strip()
        # strip markdown fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        # find first { and last } to extract the JSON object
        start = text.find("{")
        end   = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start:end+1]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "summary": "LLM response not parseable as JSON",
                "detail": text,
                "patterns": [],
                "symbols_seen": [],
            }

    def _parse(self, text: str) -> dict:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "summary": "LLM response not parseable as JSON",
                "detail": text,
                "patterns": [],
                "symbols_seen": [],
            }


# ----------------------------------------------------------------
# report writer
# ----------------------------------------------------------------
class ReportWriter:
    def __init__(self, binary_path: str):
        raw          = open(binary_path, "rb").read()
        self.md5     = hashlib.md5(raw).hexdigest()
        self.name    = os.path.basename(binary_path)
        self.lines   = []
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.outpath = f"{OUTPUT_DIR}/{self.name}_{self.md5[:8]}.md"

    def write_header(self, arch: str, text_size: int, n_insns: int, strings: list):
        self.lines += [
            f"# RVLLM: {self.name}",
            "",
            f"| field | value |",
            f"|-------|-------|",
            f"| md5   | `{self.md5}` |",
            f"| arch  | {arch} |",
            f"| .text | {text_size} bytes / {n_insns} instructions |",
            "",
            f"## strings ({len(strings)} extracted)",
            "",
        ]
        for s in strings[:30]:
            self.lines.append(f"- `{s}`")
        self.lines.append("")

    def write_block(self, idx: int, reason: str, asm: str, analysis: dict):
        summary  = analysis.get("summary", "")
        detail   = analysis.get("detail", "")
        patterns = analysis.get("patterns", [])
        syms     = analysis.get("symbols_seen", [])

        self.lines += [
            f"---",
            f"## block {idx} — `{reason}`",
            "",
            f"**{summary}**",
            "",
            detail,
            "",
        ]
        if patterns:
            self.lines.append("patterns: " + ", ".join(f"`{p}`" for p in patterns))
        if syms:
            self.lines.append("symbols: " + ", ".join(f"`{s}`" for s in syms))
        self.lines += [
            "",
            "```asm",
            asm,
            "```",
            "",
        ]

    def flush(self) -> str:
        open(self.outpath, "w").write("\n".join(self.lines))
        return self.outpath


# ----------------------------------------------------------------
# main
# ----------------------------------------------------------------
def _load_binary(raw: bytes):
    if raw[:4] == b"\x7fELF":
        fmt      = "ELF"
        parser   = ELFParser(raw)
        parser.parse()
        resolver = SymbolResolver(parser)
        resolver.load()
    elif raw[:2] == b"MZ":
        fmt      = "PE"
        parser   = PEParser(raw)
        parser.parse()
        resolver = PESymbolResolver(parser)
        resolver.load()
    else:
        raise ValueError("unknown binary format (not ELF or PE)")
    return fmt, parser, resolver


def run(binary_path: str, backend: str):
    print(f"[*] loading {binary_path}")
    raw = open(binary_path, "rb").read()

    fmt, parser, resolver = _load_binary(raw)

    if parser.arch == CS_ARCH_X86:
        arch_name = "x86-64" if getattr(parser, "bits", 64) == 64 else "x86-32"
    else:
        arch_name = "aarch64"

    print(f"[*] format={fmt}  arch={arch_name}  entry=0x{parser.entry:x}")
    print(f"[*] {len(resolver.syms)} symbols/imports resolved")

    code, base = parser.get_text()
    print(f"[*] .text: {len(code)} bytes at 0x{base:x}")

    strings = parser.get_strings()
    print(f"[*] {len(strings)} strings")

    dis = Disassembler(code, base, parser.arch, parser.mode, resolver)
    dis.disassemble()
    print(f"[*] {len(dis.insns)} instructions disassembled")

    dis.find_hotspots()
    spots = dis.dedup_hotspots()
    print(f"[*] {len(spots)} unique hotspots (from {len(dis.hotspots)} raw)")

    if not spots:
        print("[-] no hotspots — binary may be stripped or have no external calls")
        return

    llm    = LLMAnalyzer(backend)
    report = ReportWriter(binary_path)
    report.write_header(f"{fmt} {arch_name}", len(code), len(dis.insns), strings)

    for i, (reason, center) in enumerate(spots[:MAX_BLOCKS]):
        block_insns = dis.extract_block(center)
        block_text  = dis.format_block(block_insns, reason)

        print(f"\n[*] block {i}: {reason} ({len(block_insns)} insns @ 0x{dis.insns[center].address:x})")
        print(block_text)

        print(f"\n[*] querying {backend}...")
        analysis = llm.analyze(block_text, strings)
        print(f"\n[+] summary : {analysis.get('summary', '(no summary)')}")
        print(f"[+] detail  : {analysis.get('detail', '')}")
        patterns = analysis.get('patterns', [])
        symbols  = analysis.get('symbols_seen', [])
        if patterns:
            print(f"[+] patterns: {', '.join(patterns)}")
        if symbols:
            print(f"[+] symbols : {', '.join(symbols)}")

        report.write_block(i, reason, block_text, analysis)

    out = report.flush()
    print(f"\n[+] report written: {out}")


def main():
    ap = argparse.ArgumentParser(
        description="RVLLM — LLM-assisted static reverse engineering (PE and ELF)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  python3 rvllm.py ./target.exe --backend groq\n  python3 rvllm.py ./target_elf --backend groq",
    )
    ap.add_argument("binary",    help="PE or ELF binary to analyze")
    ap.add_argument("--backend", default=ACTIVE_BACKEND,
                    choices=["claude", "groq", "openrouter"],
                    help=f"LLM backend to use (default: {ACTIVE_BACKEND})")
    args = ap.parse_args()

    if not os.path.isfile(args.binary):
        print(f"[-] not found: {args.binary}")
        sys.exit(1)

    run(args.binary, args.backend)


if __name__ == "__main__":
    main()
