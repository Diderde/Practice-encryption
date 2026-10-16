# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""selfcheck：构建期硬门——不过绝不写盘（"不产坏产物"）。

`honma_himawari`： 跨实现解密环回（引导侧独立实现解构建侧密文，字节级比对）+
 marshal 往返 + 语义等价（原样 vs 产物进程内运行）+ RFC 官方向量 KAT（双侧）+
KPA 自问（早期轮次 审计教训：v0 XOR 仿射流周期 ≤256 B 的制度化防线）。
`makaino_ririmu`：发布面扫描（开发机绝对路径/工具身份串/仓外文档标题零命中）；
"boot" 子串只对**产物**严格（d_side 源码内的模板文件名属结构引用，见 早期轮次 完工记录）。
"""
import contextlib
import importlib.util
import io
import re
import struct
import sys
from pathlib import Path

_SELF_DIR = Path(__file__).resolve().parent
_DEV_PATH_MARKS = ("d:\\", "c:\\users\\", "/home/", "/users/")
_IDENTITY_STRICT = ("pyshroud", "dside")
_DOC_TITLES = ("D 侧加密工具架构", "目标函数与文献对照", "DSH上下文压缩")

# RFC 8439 §2.3.2（块函数向量，nonce=000000090000004a00000000，counter=1）。
# 注意：§2.4.2 的 AEAD 密文（6e2e359a…）用的是另一个 nonce，不得错配（早期轮次 实施期勘误）。
# 期望终态 = after20 矩阵（官方转写，经双实现交叉验证）+ 初始状态在代码内求和——
# 手抄的中间量经两侧同向量 KAT 交叉钉死（早期轮次 两次转写错误的教训）。
_RFC8439_KEY = bytes(range(32))
_RFC8439_NONCE = bytes.fromhex("000000090000004a00000000")
_RFC8439_AFTER20 = (0x837778AB, 0xE238D763, 0xA67AE21E, 0x5950BB2F,
                    0xC4F2D0C7, 0xFC62BB2F, 0x8FA018FC, 0x3F5EC7B7,
                    0x335271C2, 0xF29489F3, 0xEABDA8FC, 0x82E46EBD,
                    0xD19C12B4, 0xB04E16DE, 0x9E83D0CB, 0x4E3C50A2)
_RFC8439_INITIAL = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
                    0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C,
                    0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C,
                    0x00000001, 0x09000000, 0x4A000000, 0x00000000)


def _rfc8439_block1() -> bytes:
    """§2.3.2 官方终态 = after20 + initial（逐字 mod 2^32），LE 序列化即 keystream。"""
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF
                                 for a, b in zip(_RFC8439_AFTER20, _RFC8439_INITIAL)])
# RFC 7693 附录 B：BLAKE2s-256("abc")
_RFC7693_DIGEST = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
# RFC 5869 测试用例 1（SHA-256）：OKM
_RFC5869_IKM = b"\x0b" * 22
_RFC5869_SALT = bytes.fromhex("000102030405060708090a0b0c")
_RFC5869_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
_RFC5869_OKM = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")


class SelfcheckError(AssertionError):
    """任一硬门失败——构建必须中止且不写盘。"""


def _load_template():
    spec = importlib.util.spec_from_file_location("_d2a_boot_selfcheck", _SELF_DIR / "boot_d2a.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        pass  # 防御分支：裸模板无尾部调用，正常不触发；真被触发也只说明模板损坏
    return module


def _run_output(text: str, modname: str, work_dir: Path) -> str:
    """进程内加载一段产物/源码并捕获 stdout（不设 trace——模板守卫语义不在此测）。"""
    path = work_dir / ("%s.py" % modname)
    path.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(modname, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            spec.loader.exec_module(module)
        except SystemExit as exc:
            if exc.code not in (0, None):
                raise
    return buf.getvalue()


def _code_eq(a, b) -> bool:
    if a.co_code != b.co_code or a.co_names != b.co_names or a.co_varnames != b.co_varnames:
        return False
    if a.co_argcount != b.co_argcount or a.co_flags != b.co_flags:
        return False
    if len(a.co_consts) != len(b.co_consts):
        return False
    for ca, cb in zip(a.co_consts, b.co_consts):
        if hasattr(ca, "co_code") and hasattr(cb, "co_code"):
            if not _code_eq(ca, cb):
                return False
        elif ca != cb:
            return False
    return True


def honma_himawari(result: dict, source_text: str, artifact_text: str, work_dir: Path) -> dict:
    """全部构建期硬门。`result` = codec.octavio 的返回值。失败 raise SelfcheckError。"""
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    from d_side import chacha20 as build_chacha
    from d_side import keys as keys_mod

    # ----：marshal 往返（构建侧） ----
    code = compile(source_text, "<selfcheck>", "exec")
    if marshal_roundtrip(code) is False:
        raise SelfcheckError("I2: marshal round-trip diverged")

    # ----：跨实现解密环回（引导侧独立实现解构建侧密文，字节级） ----
    template = _load_template()
    template._SCHED = result["sched"]
    template._FIELDS = tuple(result["fields"][name] for name, _ in _spec_pairs())
    template._PAYLOAD = result["ciphertext"]
    enc_key, mac_key = keys_mod.kanae(result["fields"]["seed"], result["fields"]["nonce"],
                                      result["sched"])
    plain = template.hassaku_yuzu(enc_key, result["fields"]["nonce"], result["ciphertext"])
    plain = plain[:result["fields"]["payload_len"]]
    if plain != result["marshal"]:
        raise SelfcheckError("I1: boot-side implementation cannot reproduce the payload bytes")

    # ---- 语义等价：原样 vs 产物 ----
    expected = _run_output(source_text, "d2a_ref", work_dir)
    artifact = artifact_text if artifact_text.endswith("\n") else artifact_text + "\n"
    got = _run_output(artifact, "d2a_art", work_dir)
    got = got.replace("d2a_art", "d2a_ref")  # __name__ 等 loader 上下文差异归一（用例 17 真子进程臂专管）
    # 雷区 #4：inspect.getsource 在产物中优雅降级属设计内分歧——按行剥离后再比较（用例 17 显式断言降级形态）
    expected = "\n".join(l for l in expected.split("\n") if not l.startswith("getsource:"))
    got = "\n".join(l for l in got.split("\n") if not l.startswith("getsource:"))
    if got != expected:
        raise SelfcheckError("semantic mismatch:\n  expected %r\n  got      %r" % (expected, got))

    # ---- RFC 8439 §2.3.2：构建侧 + 引导侧同向量（counter=1 块，keystream 全 64 B） ----
    expected_block1 = _rfc8439_block1()
    ct_build = build_chacha._block(_RFC8439_KEY, _RFC8439_NONCE, 1)
    ct_boot = template.hassaku_yuzu(_RFC8439_KEY, _RFC8439_NONCE, b"\x00" * 128)[64:128]
    if ct_build != expected_block1 or ct_boot != expected_block1:
        raise SelfcheckError("RFC 8439 2.3.2 KAT failed (build/boot)")

    # ---- RFC 7693 附录 B：BLAKE2s-256 ----
    import hashlib

    if hashlib.blake2s(b"abc").hexdigest() != _RFC7693_DIGEST:
        raise SelfcheckError("RFC 7693 blake2s KAT failed")

    # ---- RFC 5869 用例 1：HKDF-SHA256 ----
    prk = keys_mod._extract(_RFC5869_SALT, _RFC5869_IKM)
    if keys_mod._expand(prk, _RFC5869_INFO, 42) != _RFC5869_OKM:
        raise SelfcheckError("RFC 5869 TC1 KAT failed")

    # ---- KPA 自问（早期轮次 教训）：keystream 无短周期 ----
    ks = build_chacha.hanabatake_chaika(b"\x00" * 32, b"\x00" * 12, b"\x00" * 512)
    for period in (16, 32, 64, 128, 256):
        if ks[:512 - period] == ks[period:]:
            raise SelfcheckError("KPA self-question: keystream shows period %d" % period)

    return {"ok": True, "checks": ["I1", "I2", "semantic", "rfc8439", "rfc7693", "rfc5869", "kpa"]}


def mashiro_meme(result: dict, source_text: str, artifact_text: str, work_dir: Path) -> dict:
    """ v2（VM blob 载荷）的构建期硬门——`honma_himawari` 的 v1 门在此不适用。

    替换关系（如实登记，避免"v2 也过了 v1 那套门"的错觉）：
       marshal 往返 → **不适用**（v2 产物里没有 marshal，这正是的承诺）；
      语义等价（跑文本壳）→ **改由 VM 权威端跑**：CPython 直跑 stdout == vm_interp stdout；
       跨实现解密环回 → 容器流解回 blob 字节级一致 + blob 自身结构自洽
      （Rust 侧的逐式等价由 native VM 套件用真实产物钉，不在构建期跑 Rust）；
      RFC 官方向量 KAT / KPA 自问 / 发布面扫描 → 与 v1 同（容器层未变）。
    失败一律 raise SelfcheckError（不过不写盘）。"""
    from d_side.builder import vm_blob, vm_compiler, vm_interp
    from d_side.chacha20 import hanabatake_chaika

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    enc_key, _mac_key = result["keys"]
    seed = bytes(result["fields"]["seed"])
    nonce = bytes(result["fields"]["nonce"])
    blob = result["payload"]

    # （容器层）：用构建侧密文按 boot 的顺序解回 blob，逐字节一致
    plain = hanabatake_chaika(enc_key, nonce, result["ciphertext"])
    if plain[:len(blob)] != blob:
        raise SelfcheckError("I1(v2): container round-trip cannot reproduce the VM blob")

    # blob 结构自洽（内含流 MAC 校验；失败即拒）
    try:
        info = vm_blob.shirayuki_tomoe(blob, vm_blob.matsukai_mao(enc_key))
        meta = vm_blob.meta_unpack(info, vm_blob.matsukai_mao(enc_key))
    except vm_blob.RanMitake as exc:
        raise SelfcheckError("blob(v2) rejected: %s" % exc)
    if info["nmeta"] + len(meta["ir_used"]) != info["nchunks"]:
        raise SelfcheckError("blob(v2): chunk accounting inconsistent")
    if meta["entry_fid"] >= len(meta["funcs"]):
        raise SelfcheckError("blob(v2): entry_fid outside func table")

    # 语义等价：CPython 直跑 vs VM 权威端逐字节
    if result["fields"]["flags"] & 0b100000:
        # 早期轮次 输入依赖档：main(argv, stdin) 没有"无输入的一次性输出"可比，
        # 语义等价改由 4 组探针输入的 copy-bot 门承担（ponto_nei 内含同款等价判据）

        # 契约必须**跟着走**：这里原来漏传 iface，`_caps(None)` 静默回落到库默认 64/64。
        # 在 uniform 档下"恰好对"（旧契约本来就是 64/64），所以一直看不出来；
        # `hardening.iface.mode` 一旦翻成 per_cell（或样机用 iface_mode 覆盖），CLI 构建的
        # 门就在量一个产品并不持有的接口——正是本轮明令不许再犯的"验收测的不是出厂的东西"

        gate = ponto_nei(source_text, blob, enc_key, seed, work_dir, nonce,
                         _require_iface(result))
        return {"ok": True, "checks": ["I1-vm", "blob-structure", "b1-input-dependence"],
                "nchunks": info["nchunks"], "nfuncs": len(meta["funcs"]), "b1": gate}
    expected = _run_output(source_text, "v2_source", work_dir)
    try:
        got = vm_interp.gwelu_os_gar(blob, enc_key, seed).decode("utf-8")
    except vm_interp.SaayaYamabuki as exc:
        raise SelfcheckError("vm(v2) execution faulted: %s" % exc)
    if got != expected:
        raise SelfcheckError("semantic mismatch (v2):\n  expected %r\n  got      %r"
                             % (expected[:200], got[:200]))

    # 发布面：产物文本不得带开发机路径/身份串（与 v1 同门，由调用方跑 makaino_ririmu）
    return {"ok": True, "checks": ["I1-vm", "blob-structure", "semantic-vm"],
            "nchunks": info["nchunks"], "nfuncs": len(meta["funcs"])}


def hyakumantenbara_salome(seed: bytes, nonce: bytes, n: int = 4,
                           caps: tuple = (64, 64)) -> list:
    """构建期探针输入（早期轮次 copy-bot 门用）→ [(argv_bytes, stdin_bytes)]。

    确定性派生（HMAC/blake2s 计数器流），**不用 random 模块**（仓内纪律），且随
    seed/nonce 逐格不同——攻击者不能把某一格的探针答案硬编码进回放脚本。
    形态覆盖：空输入 / 单字节 / 非 ASCII（0x80、0xFF 走字节通道）/ NUL 分隔多参数 /
    **本格上限**边界长度（早期轮次 Phase 2：cap 逐格，探针必须贴着本格上限取，
    超上限的探针会被 VM 正当拒绝，测不出任何产物性质）。
    """
    import hashlib

    from d_side import keys

    ap, sp = caps
    out = []
    for i in range(n):
        stream = keys._expand(hashlib.blake2s(b"probe" + seed + nonce).digest(),
                              ("p%d\x01" % i).encode("ascii"), 128)
        if i == 0:
            out.append((b"", b""))
            continue
        if i == 1:
            out.append((b"a", b"z"))
            continue
        if i == 2:
            out.append((b"\xff\x80" + stream[:2], bytes([0x80, 0xFF]) + stream[2:4]))
            continue
        # 顶格档：argv 取满 ap（含一枚分隔符的 31+1+32 形态按比例缩放），stdin 取满 sp
        left = max(ap - 1, 1)
        head = stream[:min(31, left)]
        tail = stream[31:31 + max(ap - len(head) - 1, 0)]
        out.append((head + b"\x00" + tail if tail else head, stream[64:64 + sp]))
    return out


def ponto_nei(source_text: str, blob: bytes, enc_key: bytes, seed: bytes,
              work_dir: Path, nonce: bytes = b"", iface: dict = None) -> dict:
    """早期轮次 的输入依赖门：CPython 参考 ↔ VM 逐字节等价 ×4 探针，再加 copy-bot 失格判据。

    三条判据（任一不过即 SelfcheckError、不写盘）：
    ①**等价**：同一组输入下 `main(argv, stdin)` 在 CPython 里跑出的 stdout 与 VM 的
      字节流逐字相同——两侧共用同一份扁平化口径（argv 以 0x00 分隔、stdin 原字节）；
    ②**互异**：4 组探针的输出一律两两不同（这是产物**准入**要求，不是普适真理：
      分类粒度粗到把 4 组探针落进同一类的样本，本来就没有区分力）；
    ③**回放必错**（copy-bot 门）：模拟一个"只记录已见输入→输出、未见过的输入答众数"
      的黑盒脚本——它只见过前 2 组，对后 2 组必须答错。全对即说明输出可由查表得到，
      该产物失格（仓外文档§1.1：让"理解"成为必需品）。
      口径注：②成立时③是逻辑推论（互异 ⇒ 众数回放必不可能连对后两格），③
      作为 ② 被放宽时的后备断言保留，不构成独立判据。
    """
    from d_side.builder import vm_blob, vm_interp

    caps = _caps(iface)
    probes = hyakumantenbara_salome(seed, nonce, caps=caps)
    # 参考腿的装载/绑定/补齐只有一条出口（_ref_caller）：这里过去自己抄了一遍 importlib
    # 与内建绑定，升代时两处各改一半就是"探针绿、出厂门红"那类分叉。
    # root 取自容器 enc_key——与 VM 腿建 VM 时算的是同一个值（vm_blob.matsukai_mao 单源）。
    root = vm_blob.matsukai_mao(enc_key)["root"]
    call = _ref_caller(source_text, Path(work_dir), root, caps)
    outs = []
    for argv, stdin in probes:
        ref = call(argv, stdin)
        try:
            got = vm_interp.gwelu_os_gar(blob, enc_key, seed, argv=argv, stdin=stdin,
                                         argv_cap=caps[0], stdin_cap=caps[1])
        except vm_interp.SaayaYamabuki as exc:
            raise SelfcheckError("B1 门：VM 在探针输入上故障：%s" % exc)
        if got != ref:
            raise SelfcheckError("B1 门：CPython 与 VM 输出分叉\n  ref %r\n  vm  %r"
                                 % (ref[:160], got[:160]))
        outs.append(got)
    if len({o for o in outs}) != len(outs):
        raise SelfcheckError("B1 门：探针输出未两两互异（%r）——退化产物，不得出厂"
                             % [o[:40] for o in outs])
    seen = outs[:2]
    mode = max(set(seen), key=seen.count)
    if [mode, mode] == outs[2:]:
        raise SelfcheckError("B1 门：纯回放脚本（答众数）在 验收 探针上全对——"
                             "输出未真正依赖输入，该产物失格")
    return {"probes": len(probes), "caps": [caps[0], caps[1]],
            "outputs": [len(o) for o in outs]}


def marshal_roundtrip(code) -> bool:
    import marshal

    return _code_eq(code, marshal.loads(marshal.dumps(code)))


# ---------------- 早期轮次+C：三道行为门（雪崩 / B-结构否定 / 神谕拟合齿） ----------------

# 为什么放生产侧：工作书要求"任一失败拒构建、不写盘"，而构建入口是 codec.octavio——
# 门只在探针脚本里跑就等于没有门（库调用绕得过去，与 早期轮次 把 copy-bot 门放进
# octavio 是同一个理由）。
# 为什么取样走 CPython 参考腿而不是 vm_interp：这三道门断言的是"输入函数"这个数学对象
# 的性质（雪崩、位置依赖、不可拟合）；参考腿与 VM 腿的等价由 `ponto_nei` 逐字节钉 +
# native 套件钉，两条判据分开。同一套门在 vm_interp 上实测 233 s/靶（128 B 满窗一次
# 求值 14k VM 步），进不了构建路径；走参考腿 0.3 s/靶。
# 阈值单源在 layout.json > hardening（本文件只读表），探针脚本 import 这里的实现——
# 两侧共用一份代码，"出厂前自证"与"出厂门"不可能各说各话。


def _hardening():
    import json

    layout = json.loads((_SELF_DIR / "layout.json").read_text(encoding="utf-8"))
    if "hardening" not in layout:
        raise SelfcheckError("layout.json 缺 hardening 表（三新门的阈值单源）")
    return layout["hardening"]


def _caps(iface: dict) -> tuple:
    """本格窗上限 (ap, sp)。`iface=None` 回落到库默认 `vm_isa.INPUT_WINDOW`——
    只服务不带契约的调用（旧形态载荷与既有夹具），产品路径由 codec.octavio 把
    逐格契约传进来（早期轮次 Phase 2：上限本身已经是逐格量）。"""
    from d_side.builder import vm_isa

    if not iface:
        return (vm_isa.INPUT_WINDOW, vm_isa.INPUT_WINDOW)
    return (int(iface["ap"]), int(iface["sp"]))


def _require_iface(result: dict) -> dict:
    """从构建报告里取**出厂那一格**的契约，取不到就当场失败。

    这里不许用 `_caps(None)` 的库默认：输入依赖档的构建报告一定带 iface（octavio 在门
    分支里算好后回带），缺了只可能是接线掉了——那种情况下静默按 64/64 取样，报的是
    "门过了"，量的却是另一个接口。"""
    iface = result.get("iface")
    if not iface:
        raise SelfcheckError("构建报告里没有 iface（逐格契约）——输入依赖档的门必须按出厂"
                             "那格的上限取样，缺契约即不可判，不许回落到库默认")
    return iface


def _ref_caller(source_text: str, work_dir: Path, root: bytes = None,
                caps: tuple = None):
    """把目标源码装载一次，返回"按**未补齐**的窗字节调用"的函数——CPython 参考腿的唯一出口。

    与 `ponto_nei` 同一白名单路径（importlib，不自起 exec）。两件事必须在这里一次做对：
    ①内建绑定走 `vm_isa.usami_rito`——`rotl32` 用闭式，`hstep` 是**逐格剖面依赖**的，
      没有 root 就当场 raise（宁可构建失败，也不让参考腿在没有剖面的情况下静默算出
      另一个答案）；
    ②定长吸收（早期轮次）：VM 腿在建 VM 时把两窗补齐到上限，参考腿因此**也**要补齐
      （共用 `vm_isa.hibachi_mana` 那一条表达式）——否则两条腿看到的是不同的输入，
      "等价"就成了一句空话。
    """
    from d_side.builder import vm_isa

    acap, scap = caps if caps else (vm_isa.INPUT_WINDOW, vm_isa.INPUT_WINDOW)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    path = work_dir / "b1_reference.py"
    path.write_text(source_text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("b1_reference", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["b1_reference"] = module
    prf = vm_isa.kaburaki_roco(root) if root is not None else None
    vm_isa.usami_rito(module.__dict__, root)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(module)

    def call(argv: bytes, stdin: bytes) -> bytes:
        if prf is not None:
            argv = vm_isa.hibachi_mana(prf, argv, acap)
            stdin = vm_isa.hibachi_mana(prf, stdin, scap)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            module.main(argv, stdin)
        return buf.getvalue().encode("utf-8")

    return call


def _chain_root(seed: bytes, nonce: bytes) -> bytes:
    """(seed, nonce) → VM 根密钥。与构建侧 `vm_blob.matsukai_mao(enc_key)` 和运行期
    boot 的 `machita_chima(container_key, i3)` 算的是同一个值——链剖面三腿同源的前提
    （拓扑 id 由 seed 现算，两侧都走 `keys.ryushen`，没有第二份配方）。"""
    from d_side import keys
    from d_side.builder import vm_blob

    enc, _mac = keys.kanae(seed, nonce, keys.ryushen(seed))
    return vm_blob.matsukai_mao(enc)["root"]


def _gate_inputs(seed: bytes, nonce: bytes, n: int, domain: str,
                 caps: tuple = (64, 64)) -> list:
    """行为门的确定性取样：n 组 (argv 扁平字节, stdin 字节)，域与构建探针、验收
    验收 都不同（互不重叠——门用的样本不能是验收样本，也不能是产物里已有的形态）。
    两通道都给**贴到本格上限**附近的长度，雪崩才有意义；字节全取可打印集，避免任何
    一侧的编码差异混进判据。早期轮次 Phase 2：上限逐格，取样长度必须落在上限之内——
    超上限的样本会被正当拒绝，测不出产物性质。"""
    import hashlib as _hl

    from d_side import keys

    printable = tuple(range(0x21, 0x7F))
    ap, sp = caps
    out = []
    prk = keys._extract(b"g1", _hl.blake2s(domain.encode("ascii") + seed + nonce).digest())
    for i in range(n):
        # 160 B：cap 逐格化到 80 之后，argv 取 [2:82]、stdin 取 [64:144]——原来只展开
        # 128 B，stdin 会被静默截短到 64，取样长度与请求值不符
        stream = keys._expand(prk, ("%s%d\x03" % (domain, i)).encode("ascii"), 160)
        lo = min(8, ap)
        alen = lo + (stream[0] % max(ap - lo + 1, 1))
        slo = min(8, sp)
        slen = slo + (stream[1] % max(sp - slo + 1, 1))
        argv = bytes(printable[b % len(printable)] for b in stream[2:2 + alen])
        stdin = bytes(printable[b % len(printable)] for b in stream[64:64 + slen])
        out.append((argv, stdin))
    return out


def _bits_flipped(x: int, y: int) -> int:
    return bin(x ^ y).count("1")


def _three_cols(text: bytes) -> tuple:
    parts = text.decode("ascii").split()
    if len(parts) < 3:
        raise SelfcheckError("载荷输出不是'三个整数'形态：%r" % (text[:60],))
    return int(parts[0]), int(parts[1]), int(parts[2])


def gate_avalanche(call, seed, nonce, th: dict, domain="av",
                   caps: tuple = (64, 64)) -> dict:
    """雪崩门：≥inputs 组派生输入，逐个翻位测 col1/col2 的翻转位数。

    判据与工作书字面口径（"每次翻转位数 ≥16"）的偏离要如实登记：32 位输出上的
    **理想**雪崩服从 Binomial(32, 1/2)——均值恰为 16、标准差 2.83，所以"每一次都 ≥16"
    连理想随机函数都过不了（640 样本的最小值按分布就该落在 6~8），"平均 ≥16"则是拿
    样本均值去卡一个恰好在 16 的期望（SEM≈0.2，会误杀一半合格靶）。改成三条带状判据：
      ①平均 ∈ [mean_lo, mean_hi]（低=扩散不足；高=翻转计数或值域不对）；
      ②绝对最小 ≥ floor；③低于 tail_below 的样本占比 ≤ tail_budget。
    实测分层干净：上一代线性靶平均 3.0、纯 B 臂 8.4（①就红），/B+ 15.9~16.1。"""
    stats = [[], []]
    for argv, stdin in _gate_inputs(seed, nonce, th["inputs"], domain, caps):
        base = _three_cols(call(argv, stdin))
        for chan, arr, other, col in ((0, bytearray(argv), stdin, 0),
                                      (1, bytearray(stdin), argv, 1)):
            for pos in (0, 1, 2, len(arr) // 2, len(arr) - 1):
                for flip in th["flips"]:
                    if pos >= len(arr):
                        continue
                    mut = bytearray(arr)
                    mut[pos] ^= flip
                    if col:                             # chan=1：stdin 被翻，argv 保持原样
                        got = _three_cols(call(bytes(other), bytes(mut)))
                    else:                               # chan=0：argv 被翻
                        got = _three_cols(call(bytes(mut), bytes(other)))
                    stats[chan].append(_bits_flipped(base[col], got[col]))
    rep = {}
    for chan, key in ((0, "col1"), (1, "col2")):
        vals = stats[chan]
        if len(vals) < th["min_samples"]:
            raise SelfcheckError("雪崩样本不足（%s）：%d < %d"
                                 % (key, len(vals), th["min_samples"]))
        mean = sum(vals) / float(len(vals))
        low = min(vals)
        tail = sum(1 for v in vals if v < th["tail_below"]) / float(len(vals))
        rep[key] = {"samples": len(vals), "mean": round(mean, 2), "min": low,
                    "below_%d_pct" % th["tail_below"]: round(100 * tail, 2)}
        if not th["mean_lo"] <= mean <= th["mean_hi"]:
            raise SelfcheckError("%s 平均翻转 %.2f 位不在 [%s, %s] 带内"
                                 % (key, mean, th["mean_lo"], th["mean_hi"]))
        if low < th["floor"]:
            raise SelfcheckError("%s 最小翻转 %d 位 < %d" % (key, low, th["floor"]))
        if tail > th["tail_budget"]:
            raise SelfcheckError("%s 有 %.2f%% 的翻位只动 <%d 位（预算 %.0f%%）——"
                                 "存在几乎不影响输出的位置"
                                 % (key, 100 * tail, th["tail_below"],
                                    100 * th["tail_budget"]))
    return rep


def gate_structure_negation(call, th: dict) -> dict:
    """B-结构否定门：同一枚字节放在位置 0/1/2（其余固定）的 col1 必须两两不同。
    可加/位置无关的形状（a = ΣW(b_i) 那一族）三处给同一个值——这一道把"意外退化回
    线性"钉死（设计稿）。"""
    filler = bytes(th["filler"])
    outs = []
    for pos in (0, 1, 2):
        seq = list(filler)
        seq.insert(pos, th["probe_byte"])
        flat = bytes(seq)
        if len(flat) != len(filler) + 1:
            raise SelfcheckError("结构门夹具被截断，位置对照失真")
        outs.append(_three_cols(call(flat, b""))[0])
    if len(set(outs)) != 3:
        raise SelfcheckError("单字节在位置 0/1/2 的贡献只有 %d 种（%r）——"
                             "形状退化为位置无关的线性求和，不得出厂" % (len(set(outs)), outs))
    return {"positions": 3, "distinct": 3}


def gate_fitting(call, seed, nonce, th: dict, domain="ft",
                 caps: tuple = (64, 64)) -> dict:
    """神谕拟合齿：复现 既有审计的方法（256 单字节标定 + 排列探针 + 可加族规则拟合），
    返回各模型的 验收 错误率。断言由调用方下——`sophia_valentine` 要求全部为 1.0
    （"上一轮攻击者的办法对本代必败"），而齿的**阳性对照**要求打在上一代线性靶上
    "add" 模型错误率为 0：那条不成立就说明齿本身空转（设计稿的风险登记）。

    标定写法：base = 空输入 col1，W[v] = 单字节 argv 的 col1 − base（干净形态）。
    上一版把探针写成"单字节 + 固定后缀"，模型里既算后缀又算分隔符，双重计数——
    那样连真线性的靶都拟不上，齿就成了假齿。"""
    def col1(argv, stdin=b""):
        return _three_cols(call(argv, stdin))[0]

    base = col1(b"")
    w = [col1(bytes([v])) - base for v in range(th["calib"])]
    models = {
        "add": lambda flat: base + sum(w[b] for b in flat),
        "pos+": lambda flat: base + sum((k + 1) * w[b] for k, b in enumerate(flat)),
        "pos-": lambda flat: base + sum((len(flat) - k) * w[b]
                                        for k, b in enumerate(flat)),
        "add+len": lambda flat: base + sum(w[b] for b in flat) + len(flat) * w[0],
    }
    rates = {}
    for mname, fn in models.items():
        wrong = 0
        for argv, _stdin in _gate_inputs(seed, nonce, th["holdout"], domain, caps):
            if fn(argv) != col1(argv):
                wrong += 1
        rates[mname] = wrong / float(th["holdout"])
    perm_same = 0
    for argv, _stdin in _gate_inputs(seed, nonce, th["perm_samples"], domain, caps):
        if len(argv) > 3 and col1(argv) == col1(bytes(reversed(argv))):
            perm_same += 1
    return {"error_rate": rates, "calib": th["calib"], "holdout": th["holdout"],
            "order_invariant_samples": "%d/%d" % (perm_same, th["perm_samples"])}


def saiki_ittetsu(stream, op_names, root, th: dict) -> dict:
    """早期轮次 / 门（构建侧那半边）：链常量不下字节码 + 链步进确实在原生操作码里。

    两条判据：
    ①本格 16 枚有效链常量（由 VM root 现算，见 vm_isa.kaburaki_roco）在**明文 IR 流**里
      一枚都不许出现（4 字节小端形态）——出现了就等于"抄一张表就能重建步进"；
    ②声明了本门的形状，其 IR 必须含 HSTEP：结构搬离字节码这件事要可断言，不能靠叙述。
    入参取的是**摊平的 IR 字节流 + 操作码名集合**而不是 funcs：这样验收齿能直接喂一段
    造出来的流来证明①真的会拒（喂 funcs 就只能依赖"恰好有个能表达 4 字节常量的指令形"，
    而 i16 立即数根本表达不了——那条分支就成了没牙的空断言）。
    内存那一半边在 tests/d_side/test_native_vm.py（要活进程 + hold 齿），与本门共用
    同一份"哪些值不许在场"的算法——两处各算一遍就是分叉。
    """
    from d_side.builder import vm_isa

    words = chain_words(root)
    if len(words) != th["chain_words"]:
        raise SelfcheckError("链常量枚数与 layout 登记不符：%d != %d（扩剖面轴必须同步表）"
                             % (len(words), th["chain_words"]))
    hits = {}
    for w in words:
        pat = (w & 0xFFFFFFFF).to_bytes(th["word_bytes"], "little")
        if pat in stream:
            hits[hex(w)] = stream.find(pat)
    if th["require_hstep"] and "HSTEP" not in op_names:
        raise SelfcheckError("声明了 constants_table 门却没有 HSTEP——步进仍在字节码里"
                             "（%r）——内存取证照旧能读结构" % (sorted(op_names)[:12],))
    if hits:
        raise SelfcheckError("链常量以可抄字面量出现在明文 IR 流里：%r" % (hits,))
    return {"ir_bytes": len(stream), "chain_words_hidden": len(words),
            "hstep_present": "HSTEP" in op_names}


def chain_words(root: bytes) -> list:
    """本格全部有效链常量（16 枚）——`saiki_ittetsu` 与内存齿共用的唯一出处。"""
    from d_side.builder import vm_isa

    prf = vm_isa.kaburaki_roco(root)
    words = [prf["kadd"][i] for i in range(vm_isa._CHAIN_ROUNDS_MAX)]
    words += [prf["iv"], prf["km"]]
    words += list(prf["tbl"]) + [prf["tbl_mod"]]
    words += list(prf["mul"])
    words += [prf["kend"], prf["kf"]]
    return words


def murakumo_kagetsu(blob, enc_key, seed, th: dict, caps: tuple = (64, 64)) -> dict:
    """早期轮次门：运行步数对输入长度不敏感（定长吸收是否真在生效）。

    在权威腿（vm_interp）上量——步数是精确量，不必借道有噪声的墙钟；耗时那一面由
    测试套件的端到端实测登记。判据：空输入到满窗的**每一档**（两通道各自单独扫）步数
    极差 ≤ band_steps。band=0 不是装饰：吸收把两窗都补到上限，任何残差都说明还有东西
    在读真实长度。
    配套结构齿：全局表里 kind 3/4 两槽取到的值必须等于上限——只看步数的话，一个不循环
    到 len() 的载荷根本测不出吸收有没有生效。
    """
    from d_side.builder import vm_interp, vm_isa

    ap, sp = caps
    # 档位**按本格上限算**（0 / 1 / 2 / ¼ / ½ / cap-1 / cap）：写死 64 那一套在
    # cap=48 的格上会把超上限的档全滤掉，样本数掉到门底下——那是门自己失效，不是靶子失格
    #。指导稿"空输入到满窗多档实测"的口径由此落地成逐格形式。
    ladders = {"argv": [0, 1, 2, max(ap // 4, 1), ap // 2, ap - 1, ap],
               "stdin": [0, 1, 2, max(sp // 4, 1), sp // 2, sp - 1, sp]}
    rows = []
    for chan in ("argv", "stdin"):
        for length in ladders[chan]:
            argv = b"Y" * length if chan == "argv" else b""
            stdin = b"Y" * length if chan == "stdin" else b""
            try:
                vm = vm_interp.RimiUshigome(blob, enc_key, seed, argv=argv, stdin=stdin,
                                            argv_cap=ap, stdin_cap=sp)
                vm.run()
            except vm_interp.SaayaYamabuki as exc:
                raise SelfcheckError("平坦度门在 %s=%d 档上 VM 故障：%s" % (chan, length, exc))
            rows.append((chan, length, vm.steps))
    if len(rows) < th["min_samples"]:
        raise SelfcheckError("平坦度取样档数不足：%d < %d" % (len(rows), th["min_samples"]))
    steps = [s for _c, _l, s in rows]
    spread = max(steps) - min(steps)
    if spread > th["band_steps"]:
        raise SelfcheckError("运行步数随输入长度变化（极差 %d 步 > 带宽 %d）：%r —— "
                             "定长吸收没有生效，输入长度又回到时序面了"
                             % (spread, th["band_steps"], rows[:6]))
    # 结构齿：吸收后的窗长 = 上限。全局表里凡是 kind 3/4 的槽，取到的值必须是 cap——
    # "摘掉吸收"这种回退会在这里当场变红（只有步数比较的话，一个不读 len() 的载荷
    # 根本测不出差别）
    from d_side.builder import vm_blob

    mao = vm_blob.matsukai_mao(enc_key)
    gtable = vm_blob.meta_unpack(vm_blob.shirayuki_tomoe(blob, mao), mao)["gtable"]
    probe = vm_interp.RimiUshigome(blob, enc_key, seed, argv=b"ab\x00c", stdin=b"z",
                                   argv_cap=ap, stdin_cap=sp)
    probe.run()
    seen_len_slots = 0
    for i, (kind, _v) in enumerate(gtable):
        if kind in (vm_isa.G_ARGV_LEN, vm_isa.G_STDIN_LEN):
            want = caps[0] if kind == vm_isa.G_ARGV_LEN else caps[1]
            seen_len_slots += 1
            if probe.globals[i] != want:
                raise SelfcheckError("全局槽 %d（kind %d）报的是 %r 而不是吸收后的本格上限 "
                                     "%d —— 定长没有生效"
                                     % (i, kind, probe.globals[i], want))
    return {"samples": len(rows), "steps": steps[0], "spread": spread,
            "band": th["band_steps"], "caps": [ap, sp], "ladder": ladders,
            "len_slots_checked": seen_len_slots}


def inami_rai(specs: list, th: dict) -> dict:
    """早期轮次 Phase 2 门（关）：跨格**接口指纹**不全同。

    上一代的互异断言只查"空输入摘要互不相同"——那是**常量**逐格化的证据，
    接口形态照样八格全同（既有审计因此能各自独立还原出同一份契约并一次摊销八格）。
    这条门查的是形态：窗上限 / 项数上限 / 连接字节 / argv[0] 档 / key-file 剥离档 /
    超限退出码这六轴组成的指纹，一组格子里不得全同。

    它是**场景级**判据（一次构建看不到"跨格"），所以实现放在这里、由场景构建器与
    测试套件调用；单格构建路径不跑它（没有可比对象）。"""
    if len(specs) < th["min_cells"]:
        raise SelfcheckError("接口互异门需要至少 %d 格，实得 %d"
                             % (th["min_cells"], len(specs)))
    fps = [(s["ap"], s["sp"], s["argmax"], s["join"], s["argv0"], s["keystrip"],
            s["reject_exit"]) for s in specs]
    if len(set(fps)) == 1:
        raise SelfcheckError("整组格子的接口指纹全同（%r）——逐格化没有生效，"
                             "攻击者仍可读一次用八格" % (fps[0],))
    axes = {}
    for k, idx in (("ap", 0), ("sp", 1), ("argmax", 2), ("join", 3), ("argv0", 4),
                   ("keystrip", 5), ("reject_exit", 6)):
        axes[k] = len({f[idx] for f in fps})
    for k in th["min_distinct"]:
        if axes[k] < th["min_distinct"][k]:
            raise SelfcheckError("轴 %r 只有 %d 种取值（要求 ≥%d）——那条不变量实际上"
                                 "没有逐格化" % (k, axes[k], th["min_distinct"][k]))
    return {"cells": len(specs), "fingerprints": len(set(fps)), "axes": axes}


def hoshirube_sho(call, th: dict) -> dict:
    """早期轮次 Phase 3 门：两通道不可分离（bcx 消融臂的判据）。

    bc 代里 col1 只依赖 argv、col2 只依赖 stdin，攻击者的第一步实验就是"固定一个通道扫
    另一个"，二维问题当场降成两个一维（既有审计结论一致）。这里断言：只动 stdin 时 col1
    必须变、只动 argv 时 col2 必须变——通道的定义域真的交叉了才算交叉。"""
    argv = bytes(th["argv_probe"])
    stdin = bytes(th["stdin_probe"])
    base = _three_cols(call(argv, stdin))
    only_stdin = _three_cols(call(argv, b""))
    only_argv = _three_cols(call(b"", stdin))
    if only_stdin[0] == base[0]:
        raise SelfcheckError("col1 对 stdin 无响应（%r）——通道仍可分离，"
                             "攻击者把二维问题劈成两个一维" % (base[0],))
    if only_argv[1] == base[1]:
        raise SelfcheckError("col2 对 argv 无响应（%r）——通道仍可分离" % (base[1],))
    return {"col1_moves_with_stdin": True, "col2_moves_with_argv": True}


def sophia_valentine(source_text: str, work_dir, seed: bytes, nonce: bytes,
                     shape: str, blob: bytes = None, enc_key: bytes = None,
                     iface: dict = None) -> dict:
    """早期轮次+C / 早期轮次 的出厂门入口：按形状声明的门逐条跑，任一失败 raise SelfcheckError。

    门集单源在 layout.json > hardening.shapes；消融臂如实声明自己不受哪道门（linear 是
    "硬化前基线"，雪崩门对它天然不成立），未知形状直接拒——不许"忘了声明就当过了"。
    `blob`/`enc_key` 是 早期轮次 新增两门的输入：flatness 要在权威腿上量运行步数，
    constants_table 要读明文 IR——声明了却没给输入属参数矛盾，直接拒，不静默跳过那条门
。"""
    hard = _hardening()
    if shape not in hard["shapes"]:
        raise SelfcheckError("未知 shape=%r（hardening.shapes 里没有这一档）" % (shape,))
    declared = hard["shapes"][shape]
    if not declared:
        return {"shape": shape, "gates": {}, "note": "消融臂：本代不声明新门（%s）" % shape}
    root = _chain_root(seed, nonce)
    caps = _caps(iface)
    call = _ref_caller(source_text, Path(work_dir), root, caps)
    rep = {"shape": shape, "gates": {}, "gate_caps": [caps[0], caps[1]]}
    if iface:
        rep["iface"] = {"ap": caps[0], "sp": caps[1], "join": iface["join"],
                        "col3": iface["col3"]}
    for gname in declared:
        th = hard["gates"][gname]
        if gname == "avalanche":
            rep["gates"][gname] = gate_avalanche(call, seed, nonce, th, caps=caps)
        elif gname == "structure":
            rep["gates"][gname] = gate_structure_negation(call, th)
        elif gname == "fitting":
            fr = gate_fitting(call, seed, nonce, th, caps=caps)
            bad = [k for k, v in fr["error_rate"].items() if v < 1.0]
            if bad:
                raise SelfcheckError("拟合模型 %r 在 验收 上没有全错（错误率 %r）——"
                                     "形状退化回可加族，攻击者又能在 %d 次查询内配钥匙"
                                     % (bad, fr["error_rate"], th["calib"]))
            rep["gates"][gname] = fr
        elif gname == "constants_table":
            from d_side.builder import vm_compiler, vm_isa

            funcs, _gt, _st = vm_compiler.yamagami_karuta(
                compile(source_text, "<gate>", "exec"), input_mode=True)
            stream, _tbl = vm_isa.shellin_burgundy(funcs, vm_isa.hayase_sou(seed))
            names = {ins[0] for _n, instrs in funcs for ins in instrs}
            rep["gates"][gname] = saiki_ittetsu(stream, names, root, th)
        elif gname == "flatness":
            if blob is None or enc_key is None:
                raise SelfcheckError("形状 %s 声明了 flatness 门但没有 blob/enc_key——"
                                     "这条门量的是权威腿的运行步数，缺输入即不可跑，"
                                     "不许静默跳过" % shape)
            rep["gates"][gname] = murakumo_kagetsu(blob, enc_key, seed, th, caps)
        elif gname == "channel_coupling":
            rep["gates"][gname] = hoshirube_sho(call, th)
        else:
            raise SelfcheckError("hardening.shapes 里声明了不存在的门 %r" % (gname,))
    return rep


def _spec_pairs():
    import json

    layout = json.loads((_SELF_DIR / "layout.json").read_text(encoding="utf-8"))
    return layout["header_field_spec"]


def _strip_docstrings(text: str) -> str:
    """剥 docstring 后再扫描：docstring 引用仓内路径/守卫名是 早期轮次 允许的合法引用。"""
    import ast

    lines = text.splitlines(keepends=True)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and node.body and isinstance(node.body[0], ast.Expr) \
                and isinstance(node.body[0].value, ast.Constant) \
                and isinstance(node.body[0].value.value, str):
            start = node.body[0].lineno - 1
            end = node.body[0].end_lineno
            for i in range(start, min(end, len(lines))):
                lines[i] = ""
    # 本模块对 pyshroud 的既有合法依赖（seeding 派生 /  壳生成器）：
    # import 行不参与身份串扫描；其余内容照扫。
    lines = [ln for ln in lines
             if not ln.lstrip().startswith(("from pyshroud", "import pyshroud"))]
    return "".join(lines)


def makaino_ririmu(targets: dict, artifact_strict: bool = True) -> None:
    """发布面扫描：`targets` = {标签: 文本}。`artifact_strict` 的目标额外查 "boot" 子串与文档标题。

    开发机绝对路径 / 工具身份串 / 仓外文档标题零命中。命中即 raise（构建期硬门）。
    源码目标应先经 `_strip_docstrings`（docstring 引用仓内路径合法）。"""
    for label, text in targets.items():
        strict = artifact_strict and label.startswith("artifact")
        scanned = _strip_docstrings(text) if not strict else text
        lowered = scanned.lower()
        if strict:
            # 工件字节字面量的转义接缝会拼出 3 字符盘符标记（实测 \x8d + : + \x88
            # 的渲染即命中 d:\，~半数随机内容构建被误拒——动态冒烟/协议探针
            # 0.0.40 捕获）。\xNN 片段中性化后再扫：明文真实
            # 路径不受影响、字节面真实泄漏（渲染为双反斜杠）不受影响、接缝归零。
            lowered = re.sub(r"\\x[0-9a-f]{2}", "?", lowered)
        for mark in _DEV_PATH_MARKS:
            if mark in lowered:
                raise SelfcheckError("release surface [%s]: dev path mark %r" % (label, mark))
        for word in _IDENTITY_STRICT:
            if word in lowered:
                raise SelfcheckError("release surface [%s]: identity string %r" % (label, word))
        if strict:
            if "boot" in lowered:
                raise SelfcheckError("release surface [%s]: identity string 'boot'" % label)
            for title in _DOC_TITLES:
                if title in text:
                    raise SelfcheckError("release surface [%s]: external doc title %r" % (label, title))
