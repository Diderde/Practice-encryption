# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""passes 差分与模糊测试（OBsmith 先例）。

- 构造变体语料（控制流/异常/with/match/推导式/闭包/类/装饰器/walrus/global），
  每变体 × 三档 profile × 多 seed 进程内快照等价（输出与 main() 返回一致）；
- global 声明变体：control 跳过计数入 stats（成功标准第 4 条），产物仍等价；
- 确定性变异模糊：对基础样本做 AST 级变异（常量增减、运算符对换、语句复制），
  变异体混淆后必须与变异体原样等价（构建恒成功，语义等价优先）；
- 随机性全部注入确定性随机源 KasumiToyama（同种子可复现）。
"""
import ast
import contextlib
import importlib.util
import io
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from tests.deterministic_rng import KasumiToyama
from tests.scratch import scratch
from pyshroud.pipeline import kageyama_shien, yukina_minato

_VARIANTS = {
    "branch_chain": """
def classify(v):
    if v % 3 == 0:
        return "fizz"
    elif v % 5 == 0:
        return "buzz"
    return "plain"

def main():
    print(",".join(classify(n) for n in range(1, 16)))
""",
    "loops_jumps": """
def sieve(limit):
    out = []
    for n in range(2, limit):
        if n % 2 == 0 and n > 2:
            continue
        ok = True
        for d in range(2, n):
            if n % d == 0:
                ok = False
                break
        if ok:
            out.append(n)
    return out

def spin(limit):
    n = 0
    while n < limit:
        n += 3
    return n

def main():
    print(sieve(20))
    print(spin(10))
""",
    "try_finally": """
def escaper(v):
    try:
        z = 10 // v
    except ZeroDivisionError:
        return "zero"
    finally:
        pass
    return "big" if z > 4 else "small"

def main():
    print([escaper(v) for v in (0, 2, 5)])
""",
    "with_resource": """
class Door:
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        print("closed")
        return False

def main():
    with Door() as d:
        print("inside")
    print("after")
""",
    "match_stmt": """
def route(cmd):
    match cmd:
        case "go" | "run":
            return 1
        case "stop":
            return 2
        case _:
            return 0

def main():
    print([route(c) for c in ("go", "stop", "else")])
""",
    "closures_walrus": """
def make(base):
    def apply(xs):
        total = 0
        out = []
        for x in xs:
            if (d := x - base) > 0:
                total += d
                out.append(d)
        return out, total
    return apply

def main():
    print(make(3)([1, 5, 9, 2]))
""",
    "class_hierarchy": """
class Animal:
    kind = "generic"
    def __init__(self, name):
        self.name = name
    def speak(self):
        return f"{self.name}: ..."

class Dog(Animal):
    kind = "dog"
    def speak(self):
        return f"{self.name}: woof"

def main():
    zoo = [Animal("thing"), Dog("rex")]
    print([a.speak() for a in zoo])
""",
    "decorators_kwargs": """
def twice(fn):
    def wrapper(x):
        return fn(fn(x))
    return wrapper

def scaled(v, *, k=3):
    return v * k

@twice
def bump(x):
    return x + 1

def main():
    print(bump(5), scaled(4), scaled(4, k=10))
""",
    "global_decl": """
COUNTER = 0

def bump_global():
    global COUNTER
    COUNTER += 2

def main():
    bump_global()
    bump_global()
    print(COUNTER)
""",
    "comprehensions": """
def main():
    xs = [i * i for i in range(6)]
    dd = {k: v for k, v in zip("abc", xs) if v > 1}
    ss = {v % 4 for v in xs}
    gen = sum(v for v in xs if v % 2)
    print(xs, dd, sorted(ss), gen)
""",
}


def _run_main(source, modname):
    """进程内加载并运行 main()：返回 (退出码, stdout)。"""
    with scratch() as tmp:
        path = Path(tmp) / f"{modname}.py"
        path.write_text(source, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(modname, path)
        module = importlib.util.module_from_spec(spec)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            spec.loader.exec_module(module)
            rc = module.main()
        return (0 if rc is None else int(rc)), buf.getvalue()


def elu():
    """变体语料 × 三档 × 双 seed：快照等价 + global 变体跳过计数入 stats。"""
    checked = 0
    for vname, source in _VARIANTS.items():
        base_rc, base_out = _run_main(source, f"diff_orig_{vname}")
        for profile in ("minimal", "standard", "max"):
            for seed in (42, 7):
                stats = {}
                obf = yukina_minato(source, seed, passes=kageyama_shien(profile), stats=stats)
                rc, out = _run_main(obf, f"diff_{vname}_{profile}_{seed}")
                if (base_rc, base_out) != (rc, out):
                    raise AssertionError(f"variant {vname} {profile} seed={seed}: {base_out!r} vs {out!r}")
                checked += 1
        if "global_decl" in vname:
            stats = {}
            yukina_minato(source, 42, passes=kageyama_shien("standard"), stats=stats)
            if stats.get("control_skipped", 0) < 1:
                raise AssertionError("global variant must register control_skipped")
    print(f"  [PASS] {len(_VARIANTS)} variants x 3 profiles x 2 seeds: snapshots identical ({checked} builds)")


def yuki_chihiro():
    """确定性变异模糊：变异体混淆后与变异体原样等价（三档抽二，双 seed）。"""
    base = _VARIANTS["loops_jumps"]
    rng = KasumiToyama(0xBEEF)
    mutants = 0
    for _ in range(12):
        tree = ast.parse(base)
        nodes = [n for n in ast.walk(tree) if isinstance(n, ast.BinOp)]
        if not nodes:
            continue
        target = nodes[rng.below(len(nodes))]
        swap = {ast.Add: ast.Sub, ast.Sub: ast.Add,
                ast.Mult: ast.Add, ast.BitAnd: ast.BitOr}
        if type(target.op) in swap:
            target.op = swap[type(target.op)]()
        elif isinstance(target.op, ast.Add):
            target.op = ast.BitOr()
        else:
            target.op = ast.Add()
        mutated = ast.unparse(tree) + "\n"
        rc0, out0 = _run_main(mutated, "fuzz_orig")
        for profile in ("minimal", "max"):
            obf = yukina_minato(mutated, 7, passes=kageyama_shien(profile))
            rc1, out1 = _run_main(obf, "fuzz_obf")
            if (rc0, out0) != (rc1, out1):
                raise AssertionError(f"mutant {mutants} {profile}: {out0!r} vs {out1!r}")
        mutants += 1
    print(f"  [PASS] {mutants} deterministic mutants: obfuscated == mutated-original on minimal/max")


def suzuya_aki():
    """边界构造压测：空体/pass-only/嵌套类/链式比较/星号解包/默认值表达式。"""
    edges = {
        "empty_fn": "def hole():\n    pass\n\ndef main():\n    print(hole() is None)\n",
        "nested_class": """
def make():
    class Inner:
        v = 9
    return Inner

def main():
    print(make().v)
""",
        "chain_cmp": "def main():\n    print([1 < x < 4 for x in range(6)])\n",
        "star_unpack": """
def head_tail(*args, **kw):
    return args, sorted(kw)

def main():
    a, b = head_tail(1, 2, 3, k=4, m=5)
    print(a, b)
""",
        "default_expr": """
def f(n, acc=[]):
    acc.append(n)
    return list(acc)

def main():
    print(f(1), f(2))
""",
    }
    for vname, source in edges.items():
        rc0, out0 = _run_main(source, f"edge_orig_{vname}")
        for profile in ("minimal", "standard"):
            obf = yukina_minato(source, 99, passes=kageyama_shien(profile))
            rc1, out1 = _run_main(obf, f"edge_{vname}_{profile}")
            if (rc0, out0) != (rc1, out1):
                raise AssertionError(f"edge {vname} {profile}: {out0!r} vs {out1!r}")
    print(f"  [PASS] {len(edges)} edge constructs: snapshots identical on minimal/standard")


def ienaga_mugi() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("differential_variants", elu),
        ("mutation_fuzz", yuki_chihiro),
        ("edge_constructs", suzuya_aki),
    ]
    failed = 0
    for name, fn in cases:
        t0 = time.perf_counter()
        try:
            fn()
            print(f"[PASS] {name} ({time.perf_counter() - t0:.1f}s)")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if ienaga_mugi() else 0)
