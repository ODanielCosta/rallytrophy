#!/usr/bin/env python3
"""Safe statement-order hill climber for one marked function.

Finds blocks of consecutive simple statements (expression statements and declarations with
initialisers, same indent, one `{}` block, no control flow), builds a conservative dependency graph
between them and hill-climbs over the dependency-respecting orders, scoring with try_variants.py.
Because every order it tries preserves behaviour (under the assumptions below), any improvement
can be applied to the source, unlike permute.py. SOURCE is never edited; the best definition is
written to build/reorder/<addr>/best.cpp and a unified diff to best.diff.

Dependency model (identifier level, see analyze()):
  * writes: LHS of `=`, `op=`, `++`, `--` and declared names; reads: every other identifier.
  * accesses through `->`, `.`, `[..]`, `*p` are memory accesses keyed by their text; two accesses
    commute only if both are reads, or they share a base and differ in a constant field / literal
    index (`p->x` / `p->y`, `w[3]` / `w[4]`), or both bases are distinct named objects (`A.x` / `B.y`,
    neither a reference/pointer). Non-local plain identifiers (members, globals, address-taken
    locals) count as memory cells.
  * any call (identifier followed by `(`, except casts / sizeof / --pure names), `__asm`, `new`,
    `delete`, nested assignments or unrecognised lvalues are barriers that never move.
  * `volatile` accesses never reorder with each other.
Not modelled: operator overloads with hidden effects, faults (null deref / division) changing
order, named objects aliasing through `this`, macros that look like lvalues (they count as calls).

usage: reorder.py [-r ROUNDS] [-n PER_ROUND] [-s SEED] [-j JOBS] [--lines A-B] [--pure N,..] SOURCE ADDRESS
       reorder.py --selftest
  --lines A-B  only statements on file lines A..B (as `grep -n` shows them)
"""
import argparse
import difflib
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from permute import score  # noqa: E402
from try_variants import split_function  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STMT = re.compile(r"^(\s*)([^{}\n]*;)[ \t]*$")
KEYWORD = re.compile(r"^\s*(return|break|continue|goto|case|default|if|else|for|while|do|switch|__asm|#)")
BUILTIN = {"int", "float", "double", "char", "short", "long", "unsigned", "signed", "void", "const", "volatile",
           "struct", "class", "bool", "BYTE", "WORD", "DWORD", "UINT", "ULONG", "HRESULT", "BOOL", "LONG", "DWORD_PTR"}
SKIP = {"true", "false", "this", "NULL", "nullptr", "sizeof"}
BARRIER_WORDS = {"__asm", "new", "delete", "throw", "operator"}
QUAL = r"(?:(?:const|unsigned|signed|static|volatile|register|struct|class)\s+)*"
TYPE = r"[A-Za-z_][\w:]*(?:\s+(?:int|long|char|short))*"
DECL = re.compile(rf"^\s*(?:for\s*\(\s*)?{QUAL}({TYPE})((?:\s*[*&]+\s*(?:(?:const|volatile)\s+)*|\s+))((?:volatile\s+)?)"
                  r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*(=(?!=)\s*(.*?))?\s*(;|,|\)|$)")
DECL_INIT = re.compile(DECL.pattern.replace(r"(=(?!=)\s*(.*?))?\s*(;|,|\)|$)", r"(=(?!=)\s*(.*))\s*(;)\s*$"))
ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
TOK = re.compile(r"\s*(?:(0[xX][0-9a-fA-F]+[uUlL]*|\d+\.\d*(?:[eE][-+]?\d+)?[fFlL]?|\.\d+(?:[eE][-+]?\d+)?[fF]?|\d+(?:[eE][-+]?\d+)?[fFuUlL]*)"
                 r"|([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)|(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
                 r"|(<<=|>>=|->|\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|==|!=|<=|>=|&&|\|\||<<|>>|.))")


def is_type(name):
    return name in BUILTIN or bool(re.match(r"[A-Z][a-z]", name))


def tokenize(text):
    out, pos = [], 0
    while True:
        m = TOK.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        kind = "num" if m.group(1) else "id" if m.group(2) else "str" if m.group(3) else "op"
        out.append((kind, m.group(m.lastindex)))
    return out


class Ctx:
    """Function-wide facts: declared locals, address-taken names, reference/array names, volatile names."""

    def __init__(self, text="", pure=(), locals_=(), escaped=(), vol=()):
        self.pure = set(pure)
        self.locals, self.escaped, self.vol = set(locals_), set(escaped), set(vol)
        self.nonobj, self.arrays = set(), set()
        if text:
            self._scan(text)

    def _scan(self, text):
        head = text[:text.index("{")] if "{" in text else text
        sig = head[head.index("(") + 1:head.rindex(")")] if "(" in head and ")" in head else ""
        for part in sig.split(","):
            m = re.search(r"([*&]*)\s*([A-Za-z_]\w*)\s*$", part.strip())
            if m and part.strip() not in ("void", ""):
                self.locals.add(m.group(2))
                if m.group(1) or "&" in part or "*" in part:
                    self.nonobj.add(m.group(2))
        for line in text.splitlines():
            if KEYWORD.match(line) and not line.lstrip().startswith("for"):
                continue
            m = DECL.match(line)
            if m and m.group(1) not in ("return", "delete", "new", "goto", "else", "throw") and (m.group(6) or m.group(8) in (";", ",", ")", "")):
                name = m.group(4)
                self.locals.add(name)
                if "*" in m.group(2) or "&" in m.group(2):
                    self.nonobj.add(name)
                if m.group(5):
                    self.arrays.add(name)
                if "volatile" in line:
                    self.vol.add(name)
        self.escaped |= set(re.findall(r"(?<!&)&(?!&)\s*([A-Za-z_]\w*)", text))

    def cell(self, name):
        return name not in self.locals or name in self.escaped


class Info:
    def __init__(self):
        self.ws, self.rs, self.acc = set(), set(), []  # acc: (write, base|None, path, obj)
        self.barrier = False
        self.vol = False


def chain(toks, i):
    """Parse `id (.f | ->f | [..])*` at i. Returns (path, end index) or None."""
    path, j = [], i + 1
    while j < len(toks):
        if toks[j][1] in (".", "->") and j + 1 < len(toks) and toks[j + 1][0] == "id":
            path.append((toks[j][1], toks[j + 1][1]))
            j += 2
        elif toks[j][1] == "[":
            depth, k = 0, j
            while k < len(toks):
                depth += {"[": 1, "]": -1}.get(toks[k][1], 0)
                if depth == 0:
                    break
                k += 1
            if k >= len(toks):
                return None
            inner = toks[j + 1:k]
            lit = inner[0][1] if len(inner) == 1 and inner[0][0] == "num" and re.fullmatch(r"\d+|0[xX][0-9a-fA-F]+", inner[0][1]) else "?"
            path.append(("[]", int(lit, 0) if lit != "?" else "?"))
            j = k + 1
        else:
            break
    return tuple(path), j


def match_paren(toks, i):
    depth = 0
    for k in range(i, len(toks)):
        depth += {"(": 1, ")": -1}.get(toks[k][1], 0)
        if depth == 0:
            return k
    return None


def unary_star(toks, i):
    if i == 0:
        return True
    k, t = toks[i - 1]
    if t == ")":
        # a cast `(Type *)` before the star keeps it unary
        o = max(j for j in range(i) if toks[j][1] == "(" and match_paren(toks, j) == i - 1) if any(
            toks[j][1] == "(" and match_paren(toks, j) == i - 1 for j in range(i)) else None
        inner = [x for x in toks[o + 1:i - 1]] if o is not None else []
        return bool(inner) and all(x[1] in ("*", "&") or (x[0] == "id" and is_type(x[1])) for x in inner) and any(x[0] == "id" for x in inner)
    return k == "op" and t not in ("]",)


def analyze(stmt, ctx):
    """Dependency summary of one statement (a line, possibly holding several `;`-separated ones)."""
    info = Info()
    stmt = stmt.strip()
    info.vol = bool(re.search(r"\bvolatile\b", stmt))
    declared = None
    m = DECL_INIT.match(stmt)
    if m and not (KEYWORD.match(stmt)) and m.group(1) not in ("return", "delete", "new", "goto", "else", "throw") \
            and m.group(6) and m.group(8) == ";":
        declared = m.group(4)
        info.ws.add(declared)
        body = m.group(7)
        if "," in re.sub(r"\([^()]*\)", "", body):
            info.barrier = True
    else:
        body = stmt.rstrip(";")
    toks = tokenize(body)
    if body.count(";") or any(t[1] == "," for t in toks) and declared:
        info.barrier = info.barrier or body.count(";") > 0
    # assignment structure: segments split by top-level assignment operators
    depth, cuts = 0, []
    for i, (k, t) in enumerate(toks):
        depth += {"(": 1, ")": -1, "[": 1, "]": -1}.get(t, 0)
        if t in ASSIGN_OPS:
            if depth:
                info.barrier = True
            else:
                cuts.append(i)
    lvalues = {}  # token index of lvalue start -> reads_too
    star_writes = []
    bounds = [-1] + cuts
    for n, c in enumerate(cuts):
        seg = toks[bounds[n] + 1:c]
        s = bounds[n] + 1
        if not seg:
            info.barrier = True
        elif seg[0][1] == "*" and unary_star(toks, s):
            star_writes.append(re.sub(r"\s+", "", " ".join(t for _, t in seg)))
        elif seg[0][0] == "id":
            r = chain(toks, s)
            if r and r[1] == c:
                lvalues[s] = toks[c][1] != "="
            else:
                info.barrier = True
        else:
            info.barrier = True
    for key in star_writes:
        info.acc.append((True, None, (key,), False))
    # main scan
    for i, (k, t) in enumerate(toks):
        if t in BARRIER_WORDS:
            info.barrier = True
        if k == "id" and i + 1 < len(toks) and toks[i + 1][1] == "(" and not is_type(t.split("::")[-1]) and t != "sizeof":
            if t.split("::")[-1] not in ctx.pure:
                info.barrier = True
        if t == "*" and unary_star(toks, i):
            info.acc.append((False, None, ("*",), False))
        if t in ("++", "--"):
            nxt = toks[i + 1] if i + 1 < len(toks) else None
            prv = toks[i - 1] if i else None
            if not ((nxt and nxt[0] == "id") or (prv and (prv[0] == "id" or prv[1] == "]"))):
                info.barrier = True
        if k != "id" or t in SKIP or is_type(t) or (i and toks[i - 1][1] in (".", "->")):
            continue
        if i + 1 < len(toks) and toks[i + 1][1] == "(":
            continue  # call name (or cast-like functional type) handled above
        r = chain(toks, i)
        if r is None:
            info.barrier = True
            continue
        path, end = r
        postfix = end < len(toks) and toks[end][1] in ("++", "--")
        prefix = i > 0 and toks[i - 1][1] in ("++", "--")
        wr = i in lvalues or postfix or prefix
        rd = (i not in lvalues) or lvalues[i] or postfix or prefix
        if t in ctx.vol:
            info.vol = True
        if wr and not path:
            info.ws.add(t)
        if rd or path:
            info.rs.add(t)
        if path:
            obj = (path[0][0] == "." and t not in ctx.nonobj) or (t in ctx.arrays and t not in ctx.nonobj)
            info.acc.append((wr, t, path, obj))
        elif ctx.cell(t) and t != declared:
            if wr:
                info.acc.append((True, t, (), True))
            if rd:
                info.acc.append((False, t, (), True))
    return info


def acc_conflict(a, b):
    (wa, ba, pa, oa), (wb, bb, pb, ob) = a, b
    if not (wa or wb):
        return False
    if ba is None or bb is None:
        return True
    if ba != bb:
        return not (oa and ob)
    for x, y in zip(pa, pb):
        if x != y:
            if x[0] == y[0] and x[0] in (".", "->") or (x[0] == y[0] == "[]" and "?" not in (x[1], y[1])):
                return False
            return True
    return True  # equal or one a prefix of the other


def depends(a, b):
    """True if statements with summaries a and b may not swap."""
    if a.barrier or b.barrier or (a.vol and b.vol):
        return True
    if a.ws & (b.rs | b.ws) or b.ws & a.rs:
        return True
    return any(acc_conflict(x, y) for x in a.acc for y in b.acc)


def find_blocks(lines, lo, hi):
    """Lists of line indices (inside lo..hi) forming runs of simple statements at one indent."""
    def simple(i):
        m = STMT.match(lines[i])
        if not m or KEYWORD.match(lines[i]) or "//" in lines[i] or "/*" in lines[i]:
            return None
        s = lines[i]
        if s.count("(") != s.count(")") or s.count("[") != s.count("]"):
            return None
        d = DECL.match(s)
        if d and not d.group(6) and d.group(1) not in ("return", "delete", "new", "goto", "else", "throw") and d.group(8) == ";" and not re.search(r"[=(]", s):
            return None  # declaration without initialiser
        prev = next((lines[j].strip() for j in range(i - 1, -1, -1) if lines[j].strip()), "")
        if prev and not prev.endswith((";", "{", "}")):
            return None
        return m.group(1)

    blocks, cur, ind = [], [], None
    for i in range(max(lo, 0), min(hi + 1, len(lines))):
        g = simple(i)
        if g is not None and (g == ind or not cur):
            cur.append(i)
            ind = g
        else:
            if len(cur) > 1:
                blocks.append(cur)
            cur, ind = ([i], g) if g is not None else ([], None)
    if len(cur) > 1:
        blocks.append(cur)
    return blocks


class Block:
    def __init__(self, lines, idx, ctx):
        self.idx = idx
        self.texts = [lines[i] for i in idx]
        infos = [analyze(t, ctx) for t in self.texts]
        n = len(idx)
        self.dep = [[depends(infos[a], infos[b]) for b in range(n)] for a in range(n)]
        self.order = list(range(n))

    def movable(self):
        n = len(self.idx)
        return any(not self.dep[a][b] for a in range(n) for b in range(a + 1, n))

    def move(self, order, rng):
        """Move one statement to a random other legal position; None if it cannot move."""
        order = list(order)
        x = rng.randrange(len(order))
        s = order[x]
        lo = x
        while lo > 0 and not self.dep[order[lo - 1]][s]:
            lo -= 1
        hi = x
        while hi + 1 < len(order) and not self.dep[s][order[hi + 1]]:
            hi += 1
        if lo == hi:
            return None
        new = rng.choice([p for p in range(lo, hi + 1) if p != x])
        order.pop(x)
        order.insert(new, s)
        return order

    def legal(self, order):
        pos = {s: p for p, s in enumerate(order)}
        n = len(order)
        return all(not self.dep[a][b] or pos[a] < pos[b] for a in range(n) for b in range(a + 1, n))


def render(lines, blocks, orders):
    out = list(lines)
    for b, order in zip(blocks, orders):
        for slot, s in zip(b.idx, order):
            out[slot] = b.texts[s]
    return out


def selftest():
    c = Ctx(locals_={"a", "b", "c", "d", "e"}, pure={"fab"})
    sw = lambda x, y: not depends(analyze(x, c), analyze(y, c))
    assert sw("a = b + 1;", "c = d + 2;")
    assert not sw("a = 1;", "b = a;")
    assert not sw("a = 1;", "a = 2;")
    assert not sw("b = a;", "a = 3;")
    assert not sw("foo(1);", "a = 2;") and not sw("a = 2;", "foo(1);")
    assert not sw("a = foo(b);", "c = 1;")
    assert sw("a = fab(b);", "c = 1;")
    assert not sw("a = (float)foo(b);", "c = 1;")
    assert sw("a = (float)(b + 1);", "c = sizeof(int);")
    assert sw("p->x = 1;", "p->y = 2;")
    assert not sw("p->x = 1;", "q->x = 2;")
    assert not sw("p->x = 1;", "p->x = 2;")
    assert not sw("p->x = 1;", "a = p->x;")
    assert sw("a = p->x;", "b = q->y;")
    assert not sw("a = q->y;", "p->x = 1;")
    assert sw("w[3] = 1;", "w[4] = 2;")
    assert not sw("w[i] = 1;", "w[4] = 2;")
    assert not sw("p->x = 1;", "p->x.y = 2;")
    assert sw("A.x = B.m[0];", "C.y = B.m[1];")
    assert not sw("*(int*)q = 1;", "a = p->x;")
    assert not sw("a++;", "b = a;")
    assert sw("a += b;", "c -= d;")
    assert not sw("a += b;", "a -= d;")
    assert not sw("flags |= 1;", "p->x = 2;")
    v = Ctx(locals_={"a", "b", "self"}, vol={"self"})
    assert depends(analyze("self->cur = 0;", v), analyze("self->n = 0;", v))
    assert depends(analyze("a = *(volatile int*)p;", v), analyze("b = *(volatile int*)q;", v))
    d = Ctx(text="void f(int x)\n{\n    float t = x;\n    float u = t * 2;\n    float w = x;\n}")
    assert depends(analyze("float t = x;", d), analyze("float u = t * 2;", d))
    assert not depends(analyze("float u = x * 2;", d), analyze("float w = x;", d))
    print("selftest OK")


def main():
    ap = argparse.ArgumentParser(usage=__doc__)
    ap.add_argument("-r", type=int, default=30)
    ap.add_argument("-n", type=int, default=24)
    ap.add_argument("-s", type=int)
    ap.add_argument("-j", type=int, default=min(os.cpu_count() or 4, 12))
    ap.add_argument("--lines")
    ap.add_argument("--pure", default="")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("source", nargs="?")
    ap.add_argument("address", nargs="?")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.source or not a.address:
        ap.error("SOURCE and ADDRESS required")
    source, address = os.path.abspath(a.source), int(a.address, 16)
    rng = random.Random(a.s)
    text = open(source).read()
    start, end = split_function(text, address)
    body = text[start:end]
    first = text.count("\n", 0, start) + 1  # file line of the marker line
    lines = body.split("\n")
    lo, hi = 0, len(lines) - 1
    if a.lines:
        x, y = map(int, a.lines.split("-"))
        lo, hi = x - first, y - first
    ctx = Ctx(body, pure=[p for p in a.pure.split(",") if p])
    blocks = [Block(lines, idx, ctx) for idx in find_blocks(lines, lo, hi)]
    blocks = [b for b in blocks if b.movable()]
    for b in blocks:
        assert b.legal(b.order)
    print(f"{len(blocks)} reorderable blocks: " + ", ".join(f"{first + b.idx[0]}-{first + b.idx[-1]}" for b in blocks), flush=True)
    if not blocks:
        return
    out = os.path.join(ROOT, "build", "reorder", f"{address:x}")
    os.makedirs(out, exist_ok=True)
    work = os.path.join(out, "work")
    cur = [list(b.order) for b in blocks]
    base = score(source, address, [body], work, a.j)
    if not base:
        sys.exit("baseline did not compile or compare")
    best_score = base[0][0]
    print(f"baseline {best_score}", flush=True)
    seen = {tuple(map(tuple, cur))}
    best_orders, best_body = cur, body
    for r in range(a.r):
        cands = {}
        for _ in range(a.n * 4):
            if len(cands) >= a.n:
                break
            new = [list(o) for o in cur]
            for _ in range(rng.choice((1, 1, 2, 3))):
                k = rng.randrange(len(blocks))
                o = blocks[k].move(new[k], rng)
                if o is not None:
                    new[k] = o
            key = tuple(map(tuple, new))
            if key not in seen:
                seen.add(key)
                cands[key] = "\n".join(render(lines, blocks, new))
        if not cands:
            print("search space exhausted")
            break
        keys = list(cands)
        results = score(source, address, [cands[k] for k in keys], work, a.j)
        # score() returns the body, so map back through the text
        by_body = {cands[k]: k for k in keys}
        print(f"round {r}: {len(results)}/{len(cands)} compiled, best {min([x[0] for x in results] or [None])}", flush=True)
        if results:
            s, b = min(results, key=lambda x: x[0])
            if s < best_score or (s == best_score and rng.random() < 0.3):
                if s < best_score:
                    print(f"round {r}: {best_score} -> {s}", flush=True)
                    best_score, best_body = s, b
                    open(os.path.join(out, "best.cpp"), "w").write(b + "\n")
                cur = [list(o) for o in by_body[b]]
        if best_score == (0, 0):
            print("MATCH")
            break
    if best_body == body:
        open(os.path.join(out, "best.cpp"), "w").write(body + "\n")
    diff = "".join(difflib.unified_diff((body + "\n").splitlines(1), (best_body + "\n").splitlines(1), "HEAD", "best", n=0))
    open(os.path.join(out, "best.diff"), "w").write(diff)
    print(diff or "(no change from source order)")
    print(f"best {best_score}: {os.path.join(out, 'best.cpp')}")


if __name__ == "__main__":
    main()
