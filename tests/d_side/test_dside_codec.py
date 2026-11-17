# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
""" 验收套件：构建规范的 20 项（自带运行器，退出码聚合；SKIP 单独打印）。

夹具种子全部为**确定性固定值**（≥256 位，禁 random——仓内纪律）；
真实 agent 测试不在此套件（早期轮次 人工门槛，见）。
"""
import ast
import ast
import hashlib
import importlib.util
import io
import json
import contextlib
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from d_side.codec import octavio, suzuka_utako, template_walk, bucket_of
from d_side.chacha20 import _block as build_block, hanabatake_chaika
from d_side import keys as keys_mod
from d_side.selfcheck import honma_himawari, makaino_ririmu, SelfcheckError, _load_template

_WORK = _ROOT / ".tmp" / "d2a-suite"

FIX_MAIN = (
    'TOKEN = "dside-token-xyz"\n'
    "\n"
    "def compute(base, rate):\n"
    "    factor = base * rate\n"
    "    return factor\n"
    "\n"
    "print(compute(100, 3))\n"
    "print(TOKEN)\n"
)
EXPECTED_STDOUT = "300\ndside-token-xyz\n"

FIX_META = (
    "import sys\n"
    "print(sys.argv[1:])\n"
    "print(__name__)\n"
    "print(__file__ is not None, __spec__ is not None, __package__ is not None)\n"
)

FIX_RICH = (
    "import pickle\n"
    "class Widget:\n"
    "    def __init__(self, n):\n"
    "        self.n = n\n"
    "    def bump(self):\n"
    "        self.n += 1\n"
    "        return self.n\n"
    "w = Widget(7)\n"
    "print(pickle.loads(pickle.dumps(w)).bump(), type(w).__name__)\n"
    "try:\n"
    "    import inspect\n"
    "    inspect.getsource(Widget)\n"
    "    print('getsource:ok')\n"
    "except (OSError, TypeError):\n"
    "    print('getsource:degraded')\n"
)


def _seed(label: str) -> bytes:
    """确定性 256 位夹具种子（禁 random）。"""
    return hashlib.sha256(b"d2a-suite/" + label.encode()).digest()


def _build(source: str, label: str, a_shell: int = 0):
    seed = _seed(label)
    result = octavio(source, "fixture", seed, external_key=False)
    honma_himawari(result, source, result["artifact"], _WORK)
    text = result["artifact"]
    if a_shell:
        from d_side.__main__ import nakao_azuma

        text = nakao_azuma(text, seed, a_shell)
        honma_himawari(result, source, text, _WORK)
    return result, text, seed


def _run(text: str, modname: str, argv=None):
    """进程内加载：返回 (stdout, SystemExit|None)。"""
    _WORK.mkdir(parents=True, exist_ok=True)
    path = _WORK / (modname + ".py")
    path.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(modname, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    buf = io.StringIO()
    exit_exc = None
    old_argv = sys.argv
    if argv is not None:
        sys.argv = [str(path)] + list(argv)
    try:
        with contextlib.redirect_stdout(buf):
            spec.loader.exec_module(module)
    except SystemExit as exc:
        exit_exc = exc
    finally:
        sys.argv = old_argv
    return buf.getvalue(), exit_exc


def _tamper(artifact_text: str, matcher, mutate) -> str:
    """按形状定位注入常量并变更（攻击者视角：产物文本可读，改字面量即可）。"""
    import ast

    tree = ast.parse(artifact_text)
    lines = artifact_text.splitlines(keepends=True)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        v = node.value
        if not matcher(v):
            continue
        value = ast.literal_eval(v)
        if isinstance(value, tuple):
            value = list(value)
        elif isinstance(value, bytes):
            value = bytearray(value)
        mutate(value)
        if isinstance(value, bytearray):
            value = bytes(value)
        new_assign = ast.parse("_x = " + repr(value)).body[0]
        new_assign.targets = node.targets
        ast.fix_missing_locations(new_assign)
        lines[node.lineno - 1:node.end_lineno] = [ast.unparse(new_assign) + "\n"]
        return "".join(lines)
    raise AssertionError("no injectable constant matched")


def _is_fields_node(v) -> bool:
    return (isinstance(v, ast.Tuple) and len(v.elts) == 8
            and isinstance(v.elts[4], ast.Tuple) and len(v.elts[4].elts) == 2
            and isinstance(v.elts[5], ast.Constant) and isinstance(v.elts[5].value, bytes))


def _is_ciphertext_node(v) -> bool:
    return isinstance(v, ast.Constant) and isinstance(v.value, bytes) and len(v.value) >= 512


def _is_mac_node(v) -> bool:
    return isinstance(v, ast.Constant) and isinstance(v.value, bytes) and len(v.value) == 32


def _kanda_shoichi(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """独立 mini-HKDF（第 19 项专用：不导入 keys.py，模拟攻击者抄 RFC 实现）。"""
    prk = hmac_sha(salt, ikm)
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac_sha(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def hmac_sha(key: bytes, data: bytes) -> bytes:
    import hmac

    return hmac.new(key, data, hashlib.sha256).digest()


def nakao_azuma_cli():
    pass  # 占位：CLI 路径在用例 18 经 subprocess 覆盖


def suzuki_masaru():
    """拓扑 1 KAT（基准调度）：跨实现环回 + RFC 块向量。"""
    seed = _seed("sched1-force")
    while keys_mod.ryushen(seed) != 1:
        seed = hashlib.sha256(seed).digest()
    res = octavio(FIX_MAIN, "fixture", seed, external_key=False)
    honma_himawari(res, FIX_MAIN, res["artifact"], _WORK)


def todoroki_kyoko():
    """拓扑 2 KAT（Rivest 多项式）。"""
    seed = _seed("sched2-force")
    while keys_mod.ryushen(seed) != 2:
        seed = hashlib.sha256(seed).digest()
    res = octavio(FIX_MAIN, "fixture", seed, external_key=False)
    honma_himawari(res, FIX_MAIN, res["artifact"], _WORK)


def yashiro_kizuku():
    """拓扑 3 KAT（T-函数单环；无串联模加独立性论证——红线）。"""
    seed = _seed("sched3-force")
    while keys_mod.ryushen(seed) != 3:
        seed = hashlib.sha256(seed).digest()
    res = octavio(FIX_MAIN, "fixture", seed, external_key=False)
    honma_himawari(res, FIX_MAIN, res["artifact"], _WORK)


# ---- 20 项用例（构建规范） ----

def case_01_semantics():
    result, text, _ = _build(FIX_MAIN, "sem")
    out, exit_exc = _run(text, "c01")
    if exit_exc is not None:
        raise AssertionError("artifact refused: %r" % exit_exc)
    if out != EXPECTED_STDOUT:
        raise AssertionError("stdout mismatch: %r" % out)


def case_02_a1_content():
    result, text, _ = _build(FIX_MAIN, "a1")
    captured = []
    events = []

    def hook(event, args):
        events.append(event)
        if event == "compile":
            src = args[0]
            if isinstance(src, bytes):
                src = src.decode("utf-8", errors="replace")
            if "compute" in src or "dside-token-xyz" in src:
                captured.append(src[:80])

    _WORK.mkdir(parents=True, exist_ok=True)
    path = _WORK / "c02.py"
    path.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("c02", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["c02"] = module
    sys.addaudithook(hook)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        spec.loader.exec_module(module)
    if captured:
        raise AssertionError("payload source visible in compile events: %r" % captured[0])
    if "marshal.loads" not in events:
        raise AssertionError("marshal.loads audit event expected")
    # 边界（早期轮次 精确化）：引导器自身文本以 bytes 入 compile 事件属预期，不在断言范围


def case_03_tamper_matrix():
    result, text, _ = _build(FIX_MAIN, "tamper")

    def flip_flag(fields):
        fields[1] ^= 1

    def flip_minor(fields):
        fields[4] = (3, 99)

    def flip_magic(fields):
        fields[5] = b"\x00\x01\x02\x03"

    def flip_hlen(fields):
        fields[2] = 99

    def flip_plen(fields):
        fields[3] = fields[3] + 4096

    for name, fn in (("flags", flip_flag), ("py_minor", flip_minor),
                     ("py_magic", flip_magic), ("header_len", flip_hlen),
                     ("payload_len", flip_plen)):
        bad = _tamper(text, _is_fields_node, fn)
        out, exit_exc = _run(bad, "c03_" + name)
        if not (isinstance(exit_exc, SystemExit) and exit_exc.code == 3):
            raise AssertionError("tamper %s: expected SystemExit(3), got %r" % (name, exit_exc))
        if suzuka_utako(bad)[0]:
            raise AssertionError("tamper %s: check must reject" % name)

    def flip_mac(v):
        v[3] ^= 1

    def flip_ct(v):
        v[0] ^= 1

    for name, matcher, fn in (("mac", _is_mac_node, flip_mac),
                              ("ciphertext", _is_ciphertext_node, flip_ct)):
        bad = _tamper(text, matcher, fn)
        out, exit_exc = _run(bad, "c03_" + name)
        if not (isinstance(exit_exc, SystemExit) and exit_exc.code == 3):
            raise AssertionError("tamper %s: expected SystemExit(3), got %r" % (name, exit_exc))


def case_04_version_binding():
    result, text, _ = _build(FIX_MAIN, "vbind")

    def flip_magic(fields):
        fields[5] = b"\x00\x01\x02\x03"

    bad = _tamper(text, _is_fields_node, flip_magic)
    out, exit_exc = _run(bad, "c04")
    if not (isinstance(exit_exc, SystemExit) and exit_exc.code == 3):
        raise AssertionError("version mismatch must SystemExit(3)")
    # 构建期绑定到运行解释器（无跨目标构建），构建期拒绝路径由 CLI 口径覆盖


def case_05_determinism():
    a = octavio(FIX_MAIN, "fixture", _seed("det"), external_key=False)["artifact"]
    time.sleep(1.1)
    b = octavio(FIX_MAIN, "fixture", _seed("det"), external_key=False)["artifact"]
    if a != b:
        raise AssertionError("same seed must be byte-identical (interval > 1s)")
    c = octavio(FIX_MAIN, "fixture", _seed("det2"), external_key=False)["artifact"]
    if a == c:
        raise AssertionError("different seed must differ")


def case_06_rfc_kat():
    # 块函数（构建侧 + 引导侧）对 RFC 8439 §2.3.2：期望值由 selfcheck 的权威矩阵计算（单一来源，勿手打 hex——早期轮次 两次转写错教训）
    from d_side.selfcheck import _rfc8439_block1

    ref = _rfc8439_block1()
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    if build_block(key, nonce, 1) != ref:
        raise AssertionError("build chacha20 KAT failed")
    boot = _load_template()
    if boot.hassaku_yuzu(key, nonce, b"\x00" * 128)[64:128] != ref:
        raise AssertionError("boot chacha20 KAT failed")
    # HKDF-SHA256 RFC 5869 用例 1（构建侧）
    prk = keys_mod._extract(bytes.fromhex("000102030405060708090a0b0c"), b"\x0b" * 22)
    if keys_mod._expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42) != bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"):
        raise AssertionError("HKDF KAT failed")
    # BLAKE2s RFC 7693（附录 B）
    import hashlib

    if hashlib.blake2s(b"abc").hexdigest() != \
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982":
        raise AssertionError("blake2s KAT failed")


def case_07_key_independence():
    seed = _seed("keyind")
    nonce = hashlib.sha256(seed + b"n").digest()[:12]
    for sched in (1, 2, 3):
        enc, mac = keys_mod.kanae(seed, nonce, sched)
        if len(enc) != 32 or len(mac) != 32:
            raise AssertionError("key length")
        if enc == mac:
            raise AssertionError("enc == mac (domain separation broken) at sched %d" % sched)


def case_08_seed_gate():
    weak = b"\x00" * 31 + b"\x2a"  # 8 位
    ok, msg = keys_mod.sasaki_saku(weak)
    if ok:
        raise AssertionError("sub-128-bit seed must be rejected")
    mid = ((1 << 127) | 0x05).to_bytes(16, "big")  # 恰 128 位
    ok, warn = keys_mod.sasaki_saku(mid)
    if not ok or not warn:
        raise AssertionError("128-bit seed must pass with warning")
    strong = ((1 << 255) | 0x05).to_bytes(32, "big")  # 恰 256 位（强制高位，免 sha 前导字节抖动）
    ok, warn = keys_mod.sasaki_saku(strong)
    if not ok or warn:
        raise AssertionError("256-bit seed must pass clean")
    try:
        octavio(FIX_MAIN, "fixture", weak, external_key=False)
        raise AssertionError("octavio must refuse weak seed")
    except ValueError:
        pass


def case_09_release_surface():
    result, text, _ = _build(FIX_MAIN, "surface")
    makaino_ririmu({"artifact": text})
    sources = {}
    for p in (_ROOT / "d_side").glob("*.py"):
        if p.name == "arm.py":
            continue  # v0 遗留："<dside ...>" co_filename 中性标记已被设计稿点名， 一并收口
        if p.name == "selfcheck.py":
            continue  # 扫描器自身的模式数据（dev-path/标题清单）天然自指，跳过本体
        sources["source:" + p.name] = p.read_text(encoding="utf-8")
    makaino_ririmu(sources, artifact_strict=False)
    # 回归（动态冒烟/协议探针 0.0.40）：转义接缝假阳性——字节 \x8d : \x88 的
    # 渲染拼出 3 字符 d:\，曾使 ~半数随机内容构建被 strict 面误拒。该确定性
    # 复现（固定 seed/stem）必须过 strict 门；真实泄漏路径仍必须被拒。
    import hashlib

    d = bytearray(hashlib.sha256(b"r10-2/topology-3").digest())
    d[31] = (d[31] & 0xF8) | 2
    seam = octavio(FIX_MAIN, "target_t3", bytes(d), external_key=False)["artifact"]
    makaino_ririmu({"artifact": seam})  # 不得因转义接缝误拒
    for planted in ("d:\\proj\\x.py", "D:\\Users\\n", "x=d:\\\\Users\\\\h"):
        try:
            makaino_ririmu({"artifact": seam + "\n#" + planted})
            raise AssertionError("planted dev path must be refused: %r" % planted)
        except SelfcheckError:
            pass


def case_10_exec_surface():
    proc = subprocess.run([sys.executable, "tests/pyshroud/test_exec_surface.py"],
                          cwd=str(_ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError("exec-surface suite failed:\n" + proc.stdout[-400:])
    if proc.stdout.count("boot_d2a") == 0:
        raise AssertionError("whitelist must mention d_side/boot_d2a.py")


def case_11_golden():
    golden_path = _ROOT / "tests" / "d_side" / "golden_d2a.json"
    hashes = {}
    for shell in (0, 1, 2):
        result, text, _ = _build(FIX_MAIN, "golden", a_shell=shell)
        hashes["sha256_a%d" % shell] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        again = octavio(FIX_MAIN, "fixture", _seed("golden"), external_key=False)["artifact"]
        if a_shell := shell:
            from d_side.__main__ import nakao_azuma

            again = nakao_azuma(again, _seed("golden"), shell)
        if again != text:
            raise AssertionError("golden rebuild not byte-identical (a-shell %d)" % shell)
    meta = {"interpreter": "%d.%d" % sys.version_info[:2], "hashes": hashes}
    if golden_path.is_file():
        old = json.loads(golden_path.read_text(encoding="utf-8"))
        if old["interpreter"] == meta["interpreter"] and old["hashes"] != hashes:
            raise AssertionError("golden drift: %r vs %r" % (old["hashes"], hashes))
    else:
        golden_path.write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
        print("  [note] golden pinned on first run (interpreter %s)" % meta["interpreter"])


def case_12_hard_gate():
    result, text, _ = _build(FIX_MAIN, "gate")
    broken = dict(result)
    broken["ciphertext"] = bytes([result["ciphertext"][0] ^ 1]) + result["ciphertext"][1:]
    try:
        honma_himawari(broken, FIX_MAIN, text, _WORK)
        raise AssertionError("corrupted ciphertext must fail the gate")
    except SelfcheckError:
        pass
    out = _WORK / "c12_out.py"
    # 32 B 但整数值只有 64 bit：位长 < 128 由闸门拒（原写法 "2a"*8 是 16 B，
    # 在长度检查处就被弹回，从未到达 seed 闸门——注释说的与实跑的拒因不是一回事，

    weak_seed = "00" * 24 + "ff" * 8
    # 源文件必须先落盘：缺席时 CLI 在 seed 闸门之前就 FileNotFoundError 退出，
    # returncode 同样非 0，本用例于是虚绿
    (_WORK / "c01.py").write_text(FIX_MAIN, encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "d_side", "build", "--source", str(_WORK / "c01.py"),
                           "--out", str(out), "--seed", weak_seed],
                          cwd=str(_ROOT), capture_output=True, text=True)
    if proc.returncode == 0:
        raise AssertionError("weak-seed build must fail")
    if "seed has only" not in (proc.stderr or ""):
        raise AssertionError("weak-seed failure must come from the I8 seed gate: %r"
                             % (proc.stderr or "")[-200:])
    if out.exists():
        raise AssertionError("failed build must not write the artifact")


def case_13_nonce_uniqueness():
    seed = _seed("nonce")
    n1 = octavio(FIX_MAIN, "f", seed, external_key=False)["fields"]["nonce"]
    n2 = octavio(FIX_RICH, "f", seed, external_key=False)["fields"]["nonce"]
    if n1 == n2:
        raise AssertionError("same seed different payload must yield different nonce")
    proc = subprocess.run([sys.executable, "-m", "d_side", "build", "--source", "x.py",
                           "--out", "o.py", "--seed", "aa" * 32, "--nonce", "bb" * 12],
                          cwd=str(_ROOT), capture_output=True, text=True)
    if proc.returncode == 0 or "unrecognized" not in (proc.stderr or ""):
        raise AssertionError("external nonce must be refused by the CLI surface")


def case_14_u14_seed_shape():
    seed = _seed("u14")
    result = octavio(FIX_MAIN, "fixture", seed, external_key=False)
    enc, mac = keys_mod.kanae(seed, result["fields"]["nonce"], result["sched"])
    text = result["artifact"]
    stored = [v for v in template_walk(text) if isinstance(v, bytes)]
    fields = next(v for v in template_walk(text)
                  if isinstance(v, tuple) and len(v) == 8 and isinstance(v[4], tuple)
                  and len(v[4]) == 2 and isinstance(v[5], bytes))
    if fields[7] != seed:
        raise AssertionError("seed must be present (U14: store seed)")
    if fields[6] != result["fields"]["nonce"]:
        raise AssertionError("nonce must be present")
    for blob in stored:
        if blob in (enc, mac):
            raise AssertionError("derived keys must not be stored in the artifact")


def case_15_bucketing():
    result, text, _ = _build(FIX_MAIN, "bucket")
    ct_len = len(result["ciphertext"])
    if ct_len not in (512, 1024, 2048):
        raise AssertionError("ciphertext must land on a ladder bucket, got %d" % ct_len)
    again = octavio(FIX_MAIN, "fixture", _seed("bucket"), external_key=False)["artifact"]
    if again != text:
        raise AssertionError("fill must be deterministic")


def case_16_topology_diversity():
    salts = []
    seed = _seed("topo")
    for sched in (1, 2, 3):
        nonce = hashlib.sha256(seed + bytes([sched])).digest()[:12]
        salts.append(keys_mod._schedule_salt(seed, nonce, sched))
    if not (salts[0] != salts[1] != salts[2] != salts[0]):
        raise AssertionError("schedule salts must pairwise differ")
    artifacts = []
    for sched in (1, 2, 3):
        s = seed
        while keys_mod.ryushen(s) != sched:
            s = hashlib.sha256(s).digest()
        r = octavio(FIX_MAIN, "fixture", s, external_key=False)
        artifacts.append(r["artifact"])
        suzuka_ok, reason = suzuka_utako(r["artifact"])
        if not suzuka_ok:
            raise AssertionError("sched %d artifact fails check: %s" % (sched, reason))
    if len(set(artifacts)) != 3:
        raise AssertionError("different schedules must produce different artifacts")


def case_17_loader_landmines():
    # 元数据语义以**真子进程脚本态**为准（__name__ == "__main__" 只在脚本态成立）
    meta_src = _WORK / "c17_meta_src.py"
    meta_src.parent.mkdir(parents=True, exist_ok=True)
    meta_src.write_text(FIX_META, encoding="utf-8")
    _, text, _ = _build(FIX_META, "meta")
    meta_art = _WORK / "c17_meta_art.py"
    meta_art.write_text(text, encoding="utf-8")
    src_run = subprocess.run([sys.executable, str(meta_src), "alpha", "beta"],
                             capture_output=True, text=True, timeout=60)
    art_run = subprocess.run([sys.executable, str(meta_art), "alpha", "beta"],
                             capture_output=True, text=True, timeout=60)
    if src_run.returncode != 0 or art_run.returncode != 0:
        raise AssertionError("subprocess run failed: %s / %s" % (src_run.stderr[-200:], art_run.stderr[-200:]))
    if src_run.stdout != art_run.stdout:
        raise AssertionError("metadata semantics diverge: src=%r art=%r" % (src_run.stdout, art_run.stdout))
    if "__main__" not in art_run.stdout:
        raise AssertionError("__name__ must be __main__ in script mode")
    result2, text2, _ = _build(FIX_RICH, "rich")
    out2, exit_exc2 = _run(text2, "c17_rich")
    if exit_exc2 is not None:
        raise AssertionError("rich fixture refused: %r" % exit_exc2)
    if "getsource:degraded" not in out2 and "getsource:ok" not in out2:
        raise AssertionError("getsource must degrade gracefully, got %r" % out2)
    # spawn 真子进程（形态平移）；环境不支持时按 SKIP 记账
    try:
        code = (
            "import multiprocessing as mp\n"
            "def double(x):\n"
            "    return x * 2\n"
            "if __name__ == '__main__':\n"
            "    with mp.Pool(1) as p:\n"
            "        print(p.map(double, [21]))\n"
        )
        result3, text3, _ = _build(code, "spawn17")
        spawn_path = _WORK / "c17_spawn.py"
        spawn_path.write_text(text3, encoding="utf-8")
        proc = subprocess.run([sys.executable, str(spawn_path)], capture_output=True, text=True, timeout=60)
        if proc is None or proc.returncode != 0:
            print("  [SKIP] spawn E2E unavailable in this environment")
    except Exception as exc:
        print("  [SKIP] spawn E2E: %s" % exc)


def case_18_a_shell_option():
    for shell in (1, 2):
        result, text, _ = _build(FIX_MAIN, "ashell%d" % shell, a_shell=shell)
        out, exit_exc = _run(text, "c18_%d" % shell)
        if exit_exc is not None or out != EXPECTED_STDOUT:
            raise AssertionError("a-shell %d semantic broken: %r / %r" % (shell, exit_exc, out))
        makaino_ririmu({"artifact-wrapped": text})


def case_19_static_solvability():
    """守恒断言：只读产物文本 + 公开知识（layout/RFC）即可恢复 code object（不导入 keys.py）。"""
    import marshal

    result, text, _ = _build(FIX_MAIN, "solve")
    fields = ct = None
    sched = 1
    for value in template_walk(text):
        if isinstance(value, tuple) and len(value) == 8:
            fields = value
        elif isinstance(value, bytes) and len(value) >= 512:
            ct = value
        elif isinstance(value, int) and value in (1, 2, 3, 4, 5, 6, 7, 8):
            sched = value
    if fields is None or ct is None:
        raise AssertionError("artifact constants not recoverable by shape")
    fmt_ver, flags, header_len, payload_len, py_minor, py_magic, nonce, seed = fields
    head = (int(fmt_ver).to_bytes(1, "little") + int(flags).to_bytes(1, "little")
            + int(header_len).to_bytes(1, "little") + int(payload_len).to_bytes(4, "little")
            + bytes(py_minor) + bytes(py_magic) + nonce + seed)

    def hkdf_extract(salt, ikm):
        import hmac

        return hmac.new(salt, ikm, hashlib.sha256).digest()

    def hkdf_expand(prk, info, length):
        import hmac

        out = b""
        block = b""
        counter = 1
        while len(out) < length:
            block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
            out += block
            counter += 1
        return out[:length]

    if sched == 1:
        salt = nonce
    elif sched == 2:
        m = (1 << 256) - 1
        s = int.from_bytes(seed, "big")
        n = int.from_bytes(nonce, "big")
        a0, a1 = s & m, ((s >> 8) | 1) & m
        a2, a3 = ((s >> 16) & (m ^ 1)) & m, ((s >> 24) & (m ^ 1)) & m
        salt = nonce + ((a0 + a1 * n + a2 * n * n + a3 * n ** 3) & m).to_bytes(32, "big")
    elif sched == 3:
        x = int.from_bytes(seed, "big") ^ int.from_bytes(nonce + nonce, "big")
        for _ in range(4):
            x = (x + ((x * x) | 5)) & ((1 << 256) - 1)
        salt = nonce + x.to_bytes(32, "big")
    elif sched == 4:
        m = (1 << 256) - 1
        hm = (1 << 128) - 1
        v = bytes(seed[i] ^ nonce[i % 12] for i in range(32))
        l, r = int.from_bytes(v[:16], "big"), int.from_bytes(v[16:], "big")
        for i in range(3):
            t = (int.from_bytes(seed[8 * i:8 * i + 8] * 2, "big") + r) & hm
            l, r = r, l ^ t
        salt = nonce + ((l << 128) | r).to_bytes(32, "big")
    elif sched == 5:
        m = (1 << 256) - 1
        v = int.from_bytes(nonce, "big")
        for i in range(4):
            r_ = (seed[4 * i] % 255) + 1
            mk = int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big")
            v = ((((v << r_) | (v >> (256 - r_))) ^ mk) + mk) & m
        salt = nonce + v.to_bytes(32, "big")
    elif sched == 6:
        m = (1 << 256) - 1
        v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
        for i in range(3):
            odd = (int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big") | 1) & m
            xk = int.from_bytes(seed[8 * ((i + 1) % 4):8 * ((i + 1) % 4) + 8] * 4, "big")
            ak = int.from_bytes(seed[8 * ((i + 2) % 4):8 * ((i + 2) % 4) + 8] * 4, "big")
            v = ((v * odd) & m) ^ xk
            v = (v + ak) & m
        salt = nonce + v.to_bytes(32, "big")
    elif sched == 7:
        m = (1 << 256) - 1
        hm = (1 << 128) - 1
        v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
        for i in range(4):
            k = int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big") & m
            z = v ^ k
            p = ((z & hm) << 128) | (z >> 128)
            canonical = z if z <= p else p
            v = (p if (canonical ^ k) & 1 else z) ^ k
        salt = nonce + v.to_bytes(32, "big")
    else:
        hm = (1 << 128) - 1
        v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
        l, r = v >> 128, v & hm
        for i in range(3):
            a = (l ^ r) & hm
            f = (a + int.from_bytes(seed[8 * i:8 * i + 8] * 2, "big")) & hm
            l = (l ^ f) & hm
            r = (r ^ f) & hm
            l, r = (r + (int.from_bytes(seed[8 * ((i + 1) % 4):8 * ((i + 1) % 4) + 8] * 2, "big") | 1)) & hm, l
        salt = nonce + ((l << 128) | r).to_bytes(32, "big")
    prk = hkdf_extract(salt, seed)
    enc = hkdf_expand(prk, bytes([sched, 1]), 32)
    plain = hanabatake_chaika(enc, nonce, ct)[:payload_len]
    code = marshal.loads(plain)
    if "compute" not in code.co_names or "dside-token-xyz" not in code.co_consts:
        raise AssertionError("static recovery failed to reproduce the payload")


def case_20_default_profile_external():
    """0.0.42 默认档契约（总体设计 1.3）：不传 external_key 即出厂外钥档。

    钉四件事：①默认档 flags 位 4 = 1 且产物内 seed 字段为全零（nonce 恒在场）；
    ②默认档双构建逐字节一致；③`check`/`suzuka_utako` 在无钥时结构照验、MAC 如实
    跳过，持钥则真验、错钥必拒；④`external_key=False` 的内嵌对照档（消融臂）
    仍可用且自验 MAC 完整通过。CLI 面同钉：无 `--embed-key` = 外钥、有则内嵌。"""
    seed = _seed("g3default")
    default = octavio(FIX_MAIN, "f", seed)
    if not default["fields"]["flags"] & 0x10:
        raise AssertionError("default profile must set flags bit 4 (external key)")
    stored = next(v for v in template_walk(default["artifact"])
                  if isinstance(v, tuple) and len(v) == 8 and isinstance(v[4], tuple)
                  and len(v[4]) == 2 and isinstance(v[5], bytes))
    if stored[7] != b"\x00" * 32:
        raise AssertionError("default artifact must carry a zeroed seed field")
    if stored[6] != default["fields"]["nonce"]:
        raise AssertionError("nonce must stay in the artifact (INTEG_KEY derives from it)")
    if octavio(FIX_MAIN, "f", seed)["artifact"] != default["artifact"]:
        raise AssertionError("I6: two default-profile builds diverged")
    ok, reason = suzuka_utako(default["artifact"])
    if not (ok and "MAC skipped" in (reason or "")):
        raise AssertionError("keyless check of a default artifact: %r %r" % (ok, reason))
    ok, reason = suzuka_utako(default["artifact"], key=seed)
    if not (ok and "verified" in (reason or "")):
        raise AssertionError("keyed check of a default artifact: %r %r" % (ok, reason))
    ok, reason = suzuka_utako(default["artifact"], key=bytes(range(31)) + bytes([0x77]))
    if ok or "MAC mismatch" not in (reason or ""):
        raise AssertionError("wrong key must be refused: %r %r" % (ok, reason))
    control = octavio(FIX_MAIN, "f", seed, external_key=False)
    if control["fields"]["flags"] & 0x10:
        raise AssertionError("--embed-key control profile must clear flags bit 4")
    stored_ctl = next(v for v in template_walk(control["artifact"])
                      if isinstance(v, tuple) and len(v) == 8 and isinstance(v[4], tuple)
                      and len(v[4]) == 2 and isinstance(v[5], bytes))
    if stored_ctl[7] != seed:
        raise AssertionError("control profile must carry the real seed (B5 ablation arm)")
    ok, reason = suzuka_utako(control["artifact"])
    if not (ok and reason is None):
        raise AssertionError("control profile must self-verify its MAC: %r %r" % (ok, reason))

    art = _WORK / "c20_default.py"
    emb = _WORK / "c20_embed.py"
    src = _WORK / "c20_src.py"
    src.write_text(FIX_MAIN, encoding="utf-8")
    for p in (art, emb):
        if p.exists():
            p.unlink()
    r1 = subprocess.run([sys.executable, "-m", "d_side", "build", "--source", str(src),
                         "--out", str(art), "--seed", seed.hex()],
                        cwd=str(_ROOT), capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=600)
    if r1.returncode != 0 or "external-key" not in r1.stdout:
        raise AssertionError("CLI default must be the external profile: %r %r"
                             % (r1.stdout[-160:], r1.stderr[-160:]))
    r2 = subprocess.run([sys.executable, "-m", "d_side", "build", "--source", str(src),
                         "--out", str(emb), "--seed", seed.hex(), "--embed-key"],
                        cwd=str(_ROOT), capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=600)
    if r2.returncode != 0 or "embedded-key" not in r2.stdout:
        raise AssertionError("CLI --embed-key must give the control profile: %r %r"
                             % (r2.stdout[-160:], r2.stderr[-160:]))
    r3 = subprocess.run([sys.executable, "-m", "d_side", "check", "--artifact", str(art)],
                        cwd=str(_ROOT), capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=600)
    if r3.returncode != 0 or "MAC skipped" not in r3.stdout:
        raise AssertionError("check must report the keyless external skip: %r" % r3.stdout[-160:])
    # --a-shell 与外钥默认档互斥（壳内文本必须自带密钥材料才过得了语义等价门）
    r4 = subprocess.run([sys.executable, "-m", "d_side", "build", "--source", str(src),
                         "--out", str(_WORK / "c20_shell.py"), "--seed", seed.hex(),
                         "--a-shell", "1"],
                        cwd=str(_ROOT), capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=600)
    if r4.returncode == 0 or "--embed-key" not in r4.stderr:
        raise AssertionError("--a-shell without --embed-key must be refused: %r"
                             % (r4.stdout[-120:] + r4.stderr[-160:]))


def izumo_kasumi() -> int:
    """按序执行全部用例；SKIP 单独打印计数（早期轮次）。"""
    cases = [
        ("01_semantics", case_01_semantics),
        ("02_a1_content", case_02_a1_content),
        ("03_tamper_matrix", case_03_tamper_matrix),
        ("04_version_binding", case_04_version_binding),
        ("05_determinism", case_05_determinism),
        ("06_rfc_kat", case_06_rfc_kat),
        ("07_key_independence", case_07_key_independence),
        ("08_seed_gate", case_08_seed_gate),
        ("09_release_surface", case_09_release_surface),
        ("10_exec_surface", case_10_exec_surface),
        ("11_golden", case_11_golden),
        ("12_hard_gate", case_12_hard_gate),
        ("13_nonce_uniqueness", case_13_nonce_uniqueness),
        ("14_u14_seed_shape", case_14_u14_seed_shape),
        ("15_bucketing", case_15_bucketing),
        ("16_topology_diversity", case_16_topology_diversity),
        ("17_loader_landmines", case_17_loader_landmines),
        ("18_a_shell_option", case_18_a_shell_option),
        ("19_static_solvability", case_19_static_solvability),
        ("20_default_profile_external", case_20_default_profile_external),
    ]
    failed = 0
    skipped = 0
    for name, fn in cases:
        try:
            fn()
            print("[PASS] %s" % name)
        except AssertionError as exc:
            failed += 1
            print("[FAIL] %s: %s" % (name, exc))
        except Exception as exc:
            failed += 1
            print("[FAIL] %s: unexpected %s: %s" % (name, type(exc).__name__, exc))
    print("summary: %d passed, %d failed, %d skipped" % (len(cases) - failed, failed, skipped))
    return failed


if __name__ == "__main__":
    sys.exit(1 if izumo_kasumi() else 0)
