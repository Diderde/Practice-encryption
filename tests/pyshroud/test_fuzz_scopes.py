# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""属性模糊（作用域分裂面）：专抓"构建期静默、运行期崩坏"的坏产物。

起因是一类真实缺陷：lambda 参数漏保护 + `_walk_scoped` 不按外层作用域遍历
lambda defaults，两处协同产出"构建成功、一跑 NameError"的产物；当时 22 个
套件全绿——因为已有语料里没有 `lambda k=base: k+1` 这种写法。手写对抗用例
只能覆盖"已想到的形态"，本套件把"想到了才测"换成"随机组合也测"。

性质（每份程序 × 每档 profile 都必须成立）：

    (退出态, stdout) 产物 == (退出态, stdout) 原程序

判据取**相等**而不是"产物能跑起来"：混淆不得改变行为是全部改动的前提，
"能跑"是弱判据（跑出别的答案也算能跑）。

语料：19 种"最可能把读取与绑定拆开"的构造（walrus、for 目标、推导式、
lambda 默认值/参数、except-as、with、match 捕获、闭包读、类体闭包、aug-assign、
del、f-string 字段……）随机组合进函数体，外套 3 种模块骨架（含 `__main__` 守卫）。
`_FIXED_PROGRAMS` 是固定的必跑前缀（历史缺陷形态及其邻居），保证迭代次数被
调低时套件也不会退化成空转。

确定性：BINDERS/骨架表固定，随机源是项目自带的 KasumiToyama（测试不碰 random），
迭代数与种子可由命令行或 PYSHROUD_FUZZ_ITER 覆盖。

执行方式——**进程内 exec**，理由是实测成本：同一批语料，进程内 0.038s/程序、
真子进程 0.49s/程序（13×）；120 轮在进程内约 5s，子进程要 60s 以上，CI 的
快速作业跑不起后者。代价是两条不覆盖的面：解释器冷启动、sys.modules 复用
（少验"缺 import"类故障）——这两条由真子进程套件（loader/m4、tree-level、
realprojects）负责，本套件不重复承担。

产物侧仍走**文件级真入口**：每轮经 `sayo_hikawa` 落盘（含 profile 壳层与壳后
编译自检）——不是绕过壳的旁路。"同 seed 逐字节一致"在随机语料上**抽样**复核
（每 `_REPEAT_EVERY` 份语料一次，三档各一份）。抽样而非全量是成本决定的：
实测构建 0.031s/次、执行 0.002s/次，省下的应是构建；全量复核由
test_release_surface 在固定样本上承担，这里换的是**语料宽度**。

深挖用法（默认 120 份，够 CI 快速作业；手工压测可加宽）：

    python tests/pyshroud/test_fuzz_scopes.py 400
    python tests/pyshroud/test_fuzz_scopes.py 400 0x1234
    python tests/pyshroud/test_fuzz_scopes.py 40 --exec=subprocess   # 核验用

`--exec=subprocess` 让同一份语料改走真子进程（脚本态、0.5s/程序量级）：
它是上面"进程内等价"这条假设的**反证口**——两种执行面在同一语料上结论不一致，
就说明进程内捷径漏了故障面（实测 3 档 × 多批语料两面结论一致，故 CI 用进程内）。
"""
import ast
import contextlib
import io
import os
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.pipeline import sayo_hikawa
from tests.deterministic_rng import KasumiToyama
from tests.scratch import scratch

_PROFILES = ("minimal", "standard", "max")
_SEED_BASE = 42               # 管线内部测试惯用小种子（不取真随机：结果要可复现）
_DEFAULT_SEED = 0xF0CC
_DEFAULT_ITERS = 120
_MAX_REPORT = 3
_MODE_INPROC = "inproc"
_MODE_SUBPROC = "subprocess"
_REPEAT_EVERY = 4             # 每 4 份语料复核一次"同 seed 逐字节一致"（成本实测：构建占 0.031s/次，
                              # 执行只占 0.002s/次——省的是构建，不是覆盖面；全量复核在 test_release_surface）

# 必跑前缀：历史缺陷形态 + 紧邻邻居（把"曾经漏过"钉死在语料里）
_FIXED_PROGRAMS = (
    "base = 7\nf = lambda k=base: k + 1\nprint(f(), f(10))\n",
    "def main():\n"
    "    n = 3\n"
    "    g = lambda k=n: k * 2\n"
    "    m = lambda a, b=n: a + b\n"
    "    return [g(), m(1), (lambda z=0: z + n)()]\n"
    "\n"
    "\n"
    "print(main())\n",
    "def main():\n"
    "    acc = []\n"
    "    for i in range(3):\n"
    "        acc.append((lambda v=i: v * v)())\n"
    "    return acc\n"
    "\n"
    "\n"
    "if __name__ == '__main__':\n"
    "    print(main())\n",
)

# --- 构造块：每条都"绑定一个局部名并在同体内读它"，{n}=新名, {i}=新整数 ---
BINDERS = (
    ("    {n} = {i}\n    acc.append({n} * 2)\n", "plain assign"),
    ("    if ({n} := {i}) >= 0:\n        acc.append({n} + 1)\n", "walrus in if"),
    ("    for {n} in range({i} % 3 + 1):\n        acc.append({n})\n", "for target"),
    ("    {n} = [q * 2 for q in range({i} % 3 + 1)]\n    acc.append(sum({n}))\n", "comprehension"),
    ("    {n} = [lambda v={i}: v + 1][0]()\n    acc.append({n})\n", "lambda with constant default"),
    ("    {n} = {i}\n    g = lambda k={n}: k + 1\n    acc.append(g())\n", "lambda default from local"),
    ("    {n} = {i}\n    acc.append((lambda a, b: a + b)({n}, 1))\n", "lambda params"),
    ("    {n} = {i}\n"
     "    try:\n"
     "        raise ValueError('x')\n"
     "    except ValueError as exc:\n"
     "        acc.append(len(str(exc)) + {n})\n", "except-as + local"),
    ("    import contextlib\n"
     "    {n} = {i}\n"
     "    with contextlib.suppress(Exception):\n"
     "        raise ValueError('y')\n"
     "    acc.append({n})\n", "with + local"),
    ("    {n} = {i}\n    del {n}\n    acc.append(1)\n", "del"),
    ("    {n} = {i}\n    {n} += 2\n    acc.append({n})\n", "aug-assign"),
    ("    {n} = {i}\n    acc.append(f\"v={{{n}}}\")\n", "f-string field"),
    ("    {n} = {i}\n    acc.append(f\"lit {{{n}}} tail\")\n", "f-string literal+field"),
    ("    {n} = {i}\n"
     "    match [{n}]:\n"
     "        case [z]:\n"
     "            acc.append(z)\n"
     "        case _:\n"
     "            acc.append(0)\n", "match capture"),
    ("    if True:\n        {n}: int = {i}\n        acc.append({n})\n", "nested ann-assign"),
    ("    {n} = {i}\n"
     "    def inner():\n"
     "        return {n} + 1\n"
     "    acc.append(inner())\n", "closure read"),
    ("    {n} = {i}\n"
     "    class C:\n"
     "        val = {n}\n"
     "    acc.append(C.val)\n", "class body closure"),
    ("    {n} = {i}\n    acc.append([(m := {n} + q) for q in range(2)][0])\n", "walrus in comprehension"),
    ("    {n} = {i}\n"
     "    def outer():\n"
     "        return lambda k={n}: k - 1\n"
     "    acc.append(outer()())\n", "nested def -> lambda default"),
)

MODULE_TEMPLATES = (
    ("import contextlib\n\n\ndef main():\n    acc = []\n", "\n    return acc\n\n\nprint(main())\n"),
    ("\ndef main():\n    acc = []\n", "\n    return acc\n\n\nif __name__ == '__main__':\n    print(main())\n"),
    # 尾句用 map(repr, ...) 而不是 sorted(acc)：acc 里混有 f-string 产出的 str 与
    # 算术产出的 int，直接排序会 TypeError 自我崩坏，那类程序只能被跳过（覆盖率漏）。
    ("\ndef main():\n    acc = []\n", "\n    return sorted(map(repr, acc))\n\n\nprint(main())\n"),
)


def make_program(rng):
    """随机组合一份模块级程序（骨架 + 若干绑定块）。"""
    header, footer = MODULE_TEMPLATES[rng.below(len(MODULE_TEMPLATES))]
    body = []
    used = set()
    for _ in range(2 + rng.below(4)):
        tmpl, _note = BINDERS[rng.below(len(BINDERS))]
        while True:
            name = "v%d" % rng.below(1000)   # 每块一个新名，避免同名互扰
            if name not in used:
                used.add(name)
                break
        body.append(tmpl.format(n=name, i=rng.below(50)))
    return header + "".join(body) + footer


def _run_inproc(src, tag):
    """进程内执行源码：返回 (退出态, stdout)。异常/退出也归一成可比字符串。

    `__name__` 必须给 `"__main__"`：骨架里有 `if __name__ == '__main__':`
    的形态，随手编个别的名字会让它与产物**双双**不打印，两边都是空输出、
    判据退化成恒真——那正是本套件要防的空转。"""
    ns = {"__name__": "__main__"}
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            exec(compile(src, "<%s>" % tag, "exec"), ns)
    except SystemExit as exc:
        return "exit:%s" % exc, buf.getvalue()
    except Exception as exc:  # noqa: BLE001 - 退出态本身是要比较的值
        return "exc:%s:%s" % (type(exc).__name__, exc), buf.getvalue()
    return "ok", buf.getvalue()


def _artifact(tmp, idx, profile, tag, seed, src_path):
    """经文件级真入口落盘一个产物，返回 (文本, 路径)。"""
    out = Path(tmp) / ("%s%d_%s.py" % (tag, idx, profile))
    sayo_hikawa(str(src_path), str(out), seed, profile=profile)
    return out.read_text(encoding="utf-8"), out


def _run_subprocess(path):
    """真子进程跑脚本态：返回 (退出态, stdout)。"""
    proc = subprocess.run([sys.executable, str(path)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", shell=False)
    if proc.returncode < 0:
        return "signal:%d" % -proc.returncode, proc.stdout
    return "rc:%d" % proc.returncode, proc.stdout


def _exec_mode(argv):
    """执行面：默认进程内；`--exec=subprocess` 换真子进程（核验用，见模块 docstring）。"""
    for arg in argv[1:]:
        if arg.startswith("--exec="):
            mode = arg.split("=", 1)[1]
            if mode not in (_MODE_INPROC, _MODE_SUBPROC):
                raise SystemExit("unknown exec mode: %r" % mode)
            return mode
    return _MODE_INPROC


def _run_program(src, path, mode):
    """按执行面跑一份源码：进程内用文本，子进程用文件（脚本态）。"""
    if mode == _MODE_SUBPROC:
        return _run_subprocess(path)
    return _run_inproc(src, path.name)


def _positionals(argv):
    """去掉 `--flag=...` 后的位置参数（写法自由：`12 --exec=subprocess` 与
    `12 0x1234` 都按位次取——位置参数与开关的先后顺序不影响解析）。"""
    return [a for a in argv[1:] if not a.startswith("--")]


def _iterations(pos):
    raw = pos[0] if pos else os.environ.get("PYSHROUD_FUZZ_ITER")
    return int(raw, 0) if raw else _DEFAULT_ITERS


def _seed(pos):
    raw = pos[1] if len(pos) > 1 else os.environ.get("PYSHROUD_FUZZ_SEED")
    return int(raw, 0) if raw else _DEFAULT_SEED


def ushimi_ichigo():
    """性质模糊：产物行为 == 原程序行为，三档全覆盖，语料随机组合。"""
    pos = _positionals(sys.argv)
    iters = _iterations(pos)
    seed = _seed(pos)
    mode = _exec_mode(sys.argv)
    rng = KasumiToyama(seed)
    programs = list(_FIXED_PROGRAMS)
    while len(programs) < iters:
        programs.append(make_program(rng))

    counts = {"checked": 0, "skipped": 0, "empty": 0, "unbuildable": 0,
              "mismatch": 0, "unstable": 0}
    bad = []
    t0 = time.perf_counter()

    with scratch("fuzz-") as tmp:
        for idx, src in enumerate(programs):
            try:
                compile(src, "<corpus>", "exec")
            except SyntaxError as exc:
                counts["skipped"] += 1
                print("  [note] corpus #%d not compilable (%s) - generator defect" % (idx, exc))
                continue
            src_path = Path(tmp) / ("src%d.py" % idx)
            src_path.write_text(src, encoding="utf-8", newline="\n")
            status0, out0 = _run_program(src, src_path, mode)
            if status0 not in ("ok", "rc:0"):
                counts["skipped"] += 1          # 原程序自身就崩：不是被混淆工具搞坏的
                continue
            if not out0.strip():
                counts["empty"] += 1
                bad.append((idx, "corpus", "empty stdout - program prints nothing, comparison would be vacuous"))
                continue

            for profile in _PROFILES:
                art_seed = _SEED_BASE + idx
                try:
                    first, first_path = _artifact(tmp, idx, profile, "a", art_seed, src_path)
                    second, _ = (_artifact(tmp, idx, profile, "b", art_seed, src_path)
                                 if idx % _REPEAT_EVERY == 0 else (None, None))
                except Exception as exc:  # noqa: BLE001 - 构建期异常按失败计
                    counts["unbuildable"] += 1
                    bad.append((idx, profile, "build raised %s: %s" % (type(exc).__name__, exc), src))
                    continue
                if second is not None and first != second:
                    counts["unstable"] += 1
                    bad.append((idx, profile, "same seed produced different bytes", src))
                    continue
                counts["checked"] += 1
                status1, out1 = _run_program(first, first_path, mode)
                if (status1, out1) != (status0, out0):
                    counts["mismatch"] += 1
                    bad.append((idx, profile,
                                "corpus=%s/%r | artifact=%s/%r" % (status0, out0.strip()[:70],
                                                                   status1, out1.strip()[:70]),
                                src))
                if len(bad) >= _MAX_REPORT:
                    break
            if len(bad) >= _MAX_REPORT:
                break

    elapsed = time.perf_counter() - t0
    print("  corpus: %d programs (seed=0x%X, fixed prefix %d), profiles %s, exec %s"
          % (len(programs), seed, len(_FIXED_PROGRAMS), "/".join(_PROFILES), mode))
    print("  checked: %d artifact runs | skipped(self-crashing): %d | %.1fs (%.3fs/program)"
          % (counts["checked"], counts["skipped"], elapsed, elapsed / max(len(programs), 1)))

    if bad:
        for idx, profile, why, src in bad[: _MAX_REPORT]:
            print("  [FAIL] corpus #%d [%s]: %s" % (idx, profile, why))
            for line in src.splitlines()[:20]:
                print("         | %s" % line)
        raise AssertionError("%d problems (unbuildable=%d mismatch=%d unstable=%d empty=%d)"
                             % (len(bad), counts["unbuildable"], counts["mismatch"],
                                counts["unstable"], counts["empty"]))
    if counts["empty"] or counts["skipped"] == len(programs):
        raise AssertionError("corpus degraded to a no-op: empty=%d skipped=%d/%d"
                             % (counts["empty"], counts["skipped"], len(programs)))
    print("  [PASS] every artifact matched its source on all %d profiles" % len(_PROFILES))


def yuuhi_riri() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [("fuzz_scope_split", ushimi_ichigo)]
    failed = 0
    for name, fn in cases:
        t0 = time.perf_counter()
        try:
            fn()
            print("[PASS] %s (%.1fs)" % (name, time.perf_counter() - t0))
        except AssertionError as exc:
            failed += 1
            print("[FAIL] %s: %s" % (name, exc))
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print("[FAIL] %s: unexpected %s: %s" % (name, type(exc).__name__, exc))
    print("summary: %d passed, %d failed" % (len(cases) - failed, failed))
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if yuuhi_riri() else 0)
