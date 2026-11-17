#!/usr/bin/env python3
"""Second witness: the 1.00 build (disc install) of the same source, compared with the 1.01 target.

Both executables keep their .reloc section, so absolute operands are masked exactly; calls and jumps that
leave the function are masked by disassembly. Each 1.01 game function is located in 1.00 and classified:
  same     byte-identical after masking
  numbers  same instructions, only constants / offsets differ (a layout change elsewhere)
  changed  located, instructions differ (source edited between the builds)
  none     not located (new or rewritten)

usage: v100.py --build         classify every function -> build/v100.json (about 5 minutes)
       v100.py --list          class of every NONMATCHING function
       v100.py 0xADDR...       normalised instruction diff 1.00 -> 1.01 of one function
Why it matters: see analysis/NOTES.md, "Global-cause audit".
"""
import bisect
import csv
import difflib
import glob
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V101 = os.path.join(ROOT, "orig", "RallyTrophy.exe")
V100 = os.path.join(ROOT, "extracted", "Program Files", "JoWooD", "Rally Trophy", "RallyTrophy.exe")
CACHE = os.path.join(ROOT, "build", "v100.json")
BASE = 0x400000


class PE:
    def __init__(self, path):
        d = open(path, "rb").read()
        pe = struct.unpack_from("<I", d, 0x3c)[0]
        opt = pe + 24
        first = opt + struct.unpack_from("<H", d, pe + 20)[0]
        secs = [struct.unpack_from("<IIII", d, first + 40 * i + 8) for i in range(struct.unpack_from("<H", d, pe + 6)[0])]

        def off(rva):
            return next(rp + rva - va for vs, va, rs, rp in secs if va <= rva < va + max(vs, rs))
        rva, size = struct.unpack_from("<II", d, opt + 96 + 8 * 5)  # base relocation directory
        pos, end, relocs = off(rva), off(rva) + size, []
        while pos < end:
            page, block = struct.unpack_from("<II", d, pos)
            if not block:
                break
            relocs += [page + (e & 0xfff) for e in struct.unpack_from(f"<{(block - 8) // 2}H", d, pos + 8) if e >> 12 == 3]
            pos += block
        vs, self.va, rs, rp = secs[0]  # .text
        self.raw = d[rp:rp + min(vs, rs)]
        self.rel = sorted(r - self.va for r in relocs if 0 <= r - self.va <= len(self.raw) - 4)
        text = bytearray(self.raw)
        for r in self.rel:
            text[r:r + 4] = b"\0\0\0\0"
        self.text = bytes(text)

    def mask(self, addr, size):
        o = addr - BASE - self.va
        m = bytearray(b"\xff" * size)
        for r in self.rel[bisect.bisect_left(self.rel, o - 3):bisect.bisect_left(self.rel, o + size)]:
            for p in range(max(r - o, 0), min(r - o + 4, size)):
                m[p] = 0
        return m


def disasm(code, vma):
    """[(address, length, text)]"""
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(code)
        f.flush()
        out = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386", "-M", "intel", f"--adjust-vma=0x{vma:x}",
                              f.name], check=True, capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(.*))?$", line)
        if m and m.group(3):
            res.append([int(m.group(1), 16), len(m.group(2).split()), m.group(3).strip()])
        elif m and res:  # continuation line of a long instruction
            res[-1][1] += len(m.group(2).split())
    return res


def norm(pe, addr, size):
    """Instruction texts with relocated operands -> ADDR and branch targets -> +offset / EXT."""
    o = addr - BASE - pe.va
    mask, out = pe.mask(addr, size), []
    for a, n, t in disasm(pe.raw[o:o + size], addr):
        m = re.match(r"(call|j\w+)\s+0x([0-9a-f]+)$", t)
        if m:
            tgt = int(m.group(2), 16)
            t = f"{m.group(1)} +{tgt - addr:x}" if addr <= tgt < addr + size else f"{m.group(1)} EXT"
        elif 0 in mask[a - addr:a - addr + n]:
            t = re.sub(r"(?:[def]s:)?0x[0-9a-f]{5,8}", "ADDR", t)
        out.append(t)
    return out


def numberless(ins):
    return [re.sub(r"0x[0-9a-f]+|\b\d+\b|\+[0-9a-f]+$", "N", t) for t in ins]


def functions():
    sizes = {}
    for name in ("functions.csv", "functions_extra.csv"):
        for r in csv.DictReader(open(os.path.join(ROOT, "analysis", name))):
            sizes[int(r["entry"], 16)] = int(r["size"])
    return sorted((a, s) for a, s in sizes.items() if 0x401000 <= a < 0x4bcfc6 and s > 0)


def build():
    A, B = PE(V101), PE(V100)
    index = {}
    for o in range(0, len(B.text) - 16, 16):  # game functions are 16-byte aligned
        index.setdefault(B.text[o:o + 3], []).append(o)
    out, exact = {}, []
    for addr, size in functions():
        o = addr - BASE - A.va
        mask = A.mask(addr, size)
        for a, n, t in disasm(A.raw[o:o + size], addr):
            m = re.match(r"(call|j\w+)\s+0x([0-9a-f]+)$", t)
            if m and n >= 5 and not addr <= int(m.group(2), 16) < addr + size and a - addr + n <= size:
                mask[a - addr + n - 4:a - addr + n] = b"\0\0\0\0"
        want = int.from_bytes(bytes(c & k for c, k in zip(A.text[o:o + size], mask)), "little")
        keep = int.from_bytes(bytes(mask), "little")
        cands = index.get(A.text[o:o + 3], []) if all(mask[:3]) else range(0, len(B.text) - 16, 16)
        hits = [BASE + B.va + c for c in cands if int.from_bytes(B.text[c:c + size], "little") & keep == want]
        out[addr] = dict(size=size, cls="same" if hits else "none", hits=hits)
        if len(hits) == 1:
            exact.append((addr, hits[0]))
    # anchors = unique exact hits in increasing order (longest increasing subsequence)
    tails, tail_i, prev = [], [], []
    for i, (_, b) in enumerate(exact):
        p = bisect.bisect_left(tails, b)
        tails[p:p + 1], tail_i[p:p + 1] = [b], [i]
        prev.append(tail_i[p - 1] if p else None)
    anchors, k = [], tail_i[-1]
    while k is not None:
        anchors.append(exact[k])
        k = prev[k]
    anchors.reverse()
    keys = [a for a, _ in anchors]
    starts = [BASE + B.va + o for o in range(0, len(B.raw) - 16, 16)
              if o == 0 or B.raw[o - 1] in (0x90, 0xcc, 0xc3) or B.raw[o - 3] == 0xc2]
    for addr, v in out.items():
        i = bisect.bisect_right(keys, addr) - 1
        lo = anchors[i] if i >= 0 else (0x401000, 0x401000)
        hi = anchors[i + 1][1] if i + 1 < len(anchors) else BASE + B.va + len(B.raw)
        if v["hits"]:
            v["b"] = min(v.pop("hits"), key=lambda h: abs((h - lo[1]) - (addr - lo[0])))
            continue
        del v["hits"]
        mine = numberless(norm(A, addr, v["size"]))
        best = (0, None, 0, None)
        for b in starts[bisect.bisect_right(starts, lo[1]):bisect.bisect_left(starts, hi)][:400]:
            j = bisect.bisect_right(starts, b)
            size = min((starts[j] if j < len(starts) else b + v["size"]) - b, v["size"] + 4096)
            size = len(B.raw[b - BASE - B.va:][:size].rstrip(b"\x90\xcc"))
            theirs = numberless(norm(B, b, size))
            r = difflib.SequenceMatcher(None, mine, theirs, autojunk=False).ratio()
            if r > best[0]:
                best = (r, b, size, theirs)
        r, b, size, theirs = best
        if r >= 0.5:
            v.update(b=b, bsize=size, ratio=round(r, 4), cls="numbers" if mine == theirs else "changed")
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    json.dump({hex(k): v for k, v in out.items()}, open(CACHE, "w"))
    return out


def load():
    if not os.path.exists(CACHE):
        sys.exit("run tools/v100.py --build first")
    return {int(k, 16): v for k, v in json.load(open(CACHE)).items()}


def main(argv):
    if argv == ["--build"]:
        counts = {}
        for v in build().values():
            counts[v["cls"]] = counts.get(v["cls"], 0) + 1
        print(counts)
    elif argv == ["--list"]:
        table = load()
        for path in sorted(glob.glob(os.path.join(ROOT, "src", "*.c*"))):
            for a in re.findall(r"NONMATCHING: RALLYTROPHY (0x[0-9a-f]+)", open(path).read()):
                v = table.get(int(a, 16), {})
                print(a, os.path.relpath(path, ROOT), v.get("cls"), v.get("ratio", ""))
    else:
        table, A, B = load(), PE(V101), PE(V100)
        for a in argv:
            v = table[int(a, 16)]
            print(f"== {a}: {v['cls']}" + (f", 1.00 at 0x{v['b']:x}" if v.get("b") else ""))
            if v["cls"] in ("numbers", "changed"):
                print("\n".join(difflib.unified_diff(norm(B, v["b"], v["bsize"]), norm(A, int(a, 16), v["size"]),
                                                     "1.00", "1.01", n=2, lineterm="")))


if __name__ == "__main__":
    main(sys.argv[1:] or ["--list"])
