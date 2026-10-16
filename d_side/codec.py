# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""codec： 打包与校验（格式单一来源 = layout.json）。

`octavio`（打包）：compile（中性 co_filename）→ marshal →  分桶+诱饵填充 →
ChaCha20（counter=0）→ BLAKE2s-MAC → 引导模板改名装配（字面 exec 路径，列白见
tests/pyshroud/test_exec_surface.py）。
`suzuka_utako`（校验入口，`check` 子命令）：解析产物 → 结构自洽 → 版本绑定 → MAC，
只校验不运行。
不通过硬门绝不写盘（纪律在 `__main__`/`selfcheck` 执行）。
"""
import ast
import hashlib
import hmac
import json
import marshal
import sys
from pathlib import Path

from d_side.chacha20 import hanabatake_chaika
from d_side.keys import akabane_youko, kanae, ryushen, sasaki_saku
from pyshroud.notice import artifact_header

_LAYOUT = json.loads((Path(__file__).resolve().parent / "layout.json").read_text(encoding="utf-8"))
_SPEC = tuple((name, size) for name, size in _LAYOUT["header_field_spec"])
_HEADER_LEN = sum(size for _, size in _SPEC)
_LADDER = tuple(_LAYOUT["bucket_ladder"])
_FORMAT_VERSION = int(_LAYOUT["format_version"])
# 早期轮次 出厂门的参考端落盘处（importlib 装载需要真文件；与 CLI 的 .tmp/d2a-build 分开，
# 免得库调用把 CLI 的工作目录搅脏）
_B1_GATE_WORK = Path(__file__).resolve().parent.parent / ".tmp" / "d2a-b1-gate"

_TEMPLATE_SYMBOLS = (
    "_HLEN", "_VER", "_SCHED", "_FIELDS", "_PAYLOAD", "_MAC",
    "_exit3", "_rotl", "hassaku_yuzu", "_expand", "umiyashano_kami", "dola", "setsuna",
)


def bucket_of(length: int) -> int:
    """：不小于 `length` 的最小桶；超出桶梯上限即拒绝（如实边界见设计稿）。"""
    for step in _LADDER:
        if length <= step:
            return step
    raise ValueError("payload %d bytes exceeds the largest bucket (%d)" % (length, _LADDER[-1]))


def _fill_stream(seed: bytes, nonce: bytes, length: int) -> bytes:
    """构建侧诱饵流（确定性， 安全；引导侧按 payload_len 切片、永不触碰）。"""
    prk = hmac.new(b"", seed + nonce, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    info = b"fill\x01"
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _header_bytes(fields: dict) -> bytes:
    head = b""
    for name, size in _SPEC:
        v = fields[name]
        if name == "py_minor":
            head += bytes(v)
        elif isinstance(v, int):
            head += int(v).to_bytes(size, "little")
        else:
            head += bytes(v)
    return head


def octavio(source: str, module_name: str, seed: bytes, external_key: bool = True,
            vm: bool = False, psiv: bool = False, input_dependent: bool = False,
            gate_work=None, shape: str = None, iface_mode: str = None) -> dict:
    """源码文本 →  产物文本。同 seed 逐字节一致。

    external_key=True（外部档，**0.0.42 起为默认档**）：flags 位 4 置 1、
    产物内 seed 字段置零——密钥材料不随产物分发，运行方须以同 seed 经
    --key-file/环境变量提供；MAC 仍覆盖**真实 seed** 的头，boot 以提供的密钥
    重建头部后先验 MAC。既有审计实证"内嵌档下内存提取比破密码便宜"，故默认
    翻转成 fail-closed 方向：忘记传参不会出厂一个带 seed 的产物。
    external_key=False 为内嵌对照档（消融继续需要它，显式传参即得）。
    vm=True（v2）：载荷 = VM blob v2（源码在构建期编译成 VM IR，逐块加密），
    `fmt_ver=2`；该档**只能出 native 产物**——文本壳里没有 CPython 可跑的 marshal，
    子集外的源码在构建期即被编译器拒绝（fail-closed，不静默回落到 v1）。
    v2 的 nonce 摘要取"载荷源码摘要"：VM blob 是源码的确定性函数，摘要先于加密可算，
     的"同 (seed, nonce) 不用于两个不同载荷"语义不变。
    shape=（早期轮次+C 消融 pin，只对 `vm=True, input_dependent=True` 有意义）：声明本靶
    用的输入函数形状，同时**声明它必须过的行为门**（表在 layout.json > hardening.shapes：
    linear=无新门／b*-=结构否定+拟合齿／c1|bc=雪崩+结构否定+拟合齿）。任一不过
    raise SelfcheckError，构建中止不写盘。未知形状直接拒；不声明 shape 就只跑 早期轮次
    那三条（既有产物与既有套件的口径），所以**出厂用的构建必须显式传 shape**。
    返回 {"artifact": 产物文本, "marshal": 明文 marshal 字节（v2 为 None）,
    "payload": 载荷明文（v1=marshal / v2=VM blob）, "fields": 字段 dict,
    "ciphertext": 密文（含填充）, "sched": 拓扑 id, "keys": (enc, mac), "warnings": [...]}。
    不写盘；硬门在 selfcheck / `__main__`。"""
    ok, message = sasaki_saku(seed)
    if not ok:
        raise ValueError("seed rejected: %s" % message)
    warnings = [message] if message else []

    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")

    if input_dependent and not vm:
        raise ValueError("input_dependent 只对 --vm 载荷有意义：v1 走真 CPython，"
                         "argv/stdin 本来就是进程的输入（早期轮次 的输入原语在 VM 里）")
    sched = ryushen(seed)
    enc_key, mac_key = None, None  # 真实密钥在 nonce 派生后计算

    neutral_name = "<m%s>" % hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    code = compile(source, neutral_name, "exec")
    if shape is not None and not (vm and input_dependent):
        # 库级与 CLI 同规：shape 是消融臂/门集声明，只对读输入的 VM 产物有意义；
        # 其余组合属参数矛盾，硬拒不静默忽略
        raise ValueError("shape requires vm=True and input_dependent=True "
                         "（三新门采样的是输入函数的性质，不读输入的载荷没有可采样的输入）")
    if vm:
        # v2 的载荷明文摘要 = 载荷源码摘要（VM blob 是源码的确定性函数，摘要先于加密可算）
        payload_digest = hashlib.sha256(source.encode("utf-8")).digest()
    else:
        marshal_payload = marshal.dumps(code)
        payload_digest = hashlib.sha256(marshal_payload).digest()
    nonce = akabane_youko(seed, payload_digest)
    enc_key, mac_key = kanae(seed, nonce, sched)
    payload = _vm_payload(code, seed, nonce, sched,
                          aead=psiv, input_mode=input_dependent) if vm else marshal_payload
    hardening_rep = None
    # 非 VM / 非输入依赖档不跑出厂门，也就没有契约可回带；先置 None 再进分支，
    # 否则函数末尾的 "iface": iface 对这些路径是 UnboundLocalError——门没跑是口径，
    # 让构建在返回值组装处炸掉则是另一回事。
    iface = None
    if vm and input_dependent:
        # 出厂门**放在打包里**而不是只放在 CLI 门里：库调用（测量代场景脚本）
        # 同样绕不过去——忘记传 work_dir 就用默认的 .tmp 子目录
        from d_side.builder.native_build import iface_mode_default, koyanagi_rou
        from d_side.selfcheck import ponto_nei, sophia_valentine

        # 早期轮次 Phase 2：出厂门必须量**出厂的那一格**。窗上限/连接字节已经逐格化，门若还
        # 按 64/64 取样，测的就是一个不存在的接口（指导稿 §10.2 "验收测的不是出厂的东西"
        # 的同一类错误，这次不让自己再犯）。
        # 惰性导入：native_build 顶层 import codec，反向 import 只能在函数内。
        # 调用方（样机/验收齿）可用 `iface_mode` 强制某一形态（"uniform"/"per_cell"）；
        # 不传就走 layout 的铺开开关。构建报告把实际用的契约回带在 res["iface"]，
        # 下游 azuchi_momo 经 pins_override 拿同一份，两侧不可能各算一遍。
        iface = koyanagi_rou(seed, nonce, iface_mode)
        if iface_mode is not None and iface_mode != iface_mode_default():
            # 覆盖档是**样机档**：门量的是这一份契约，而 native 构建不接 override 时
            # `asuka_hina` 会按 layout 档重新发钉——那时产物折的窗与门量的窗就不是同一个
            # 接口（实测：两腿各自完全自洽，只有互相不等，看不出根因在喂给构建器的契约上）。
            # 不在这里报错是因为库调用方有权只跑门不出货；但这条必须挂在报告里，
            # 不许靠"记得传 override"的记忆力。
            warnings.append(
                "iface_mode=%s 覆盖 layout 的 %s：出厂门按覆盖档取样，构建 exe 时必须把 "
                "res['iface'] 经 pins_override={'iface': ...} 传给 azuchi_momo，"
                "否则产物按 layout 档折窗，门与产品量的不是同一个接口"
                % (iface_mode, iface_mode_default()))
        _gate_dir = Path(gate_work or _B1_GATE_WORK)
        ponto_nei(source, payload, enc_key, seed, _gate_dir, nonce, iface)
        if shape is not None:
            # 早期轮次+C：消融 pin 同时是**门集声明**（layout.json > hardening.shapes）。
            # 三新门（雪崩 / B-结构否定 / 神谕拟合齿）任一不过即 SelfcheckError，
            # 构建中止、不写盘。shape=None 保持 早期轮次 的老口径（只跑那三条），
            # 这样既有套件与既有产物不因升代而被打死——但**默认出厂必须显式声明形状**，
            # 场景构建器一律传 shape。
            hardening_rep = sophia_valentine(source, _gate_dir, seed, nonce, shape,
                                            payload, enc_key, iface)

    bucket = bucket_of(len(payload))
    fill = _fill_stream(seed, nonce, bucket - len(payload))
    ciphertext = hanabatake_chaika(enc_key, nonce, payload + fill)

    fields = {
        "fmt_ver": 2 if vm else _FORMAT_VERSION,
        "flags": 0b011 | (0b10000 if external_key else 0)
                 | (0b100000 if input_dependent else 0),
        # 位0=载荷是可执行对象（v1=marshal code object，v2=VM blob——由 fmt_ver 分派）；
        # 位1=标准 GIL；位2 debug 由运行时决定（本构建非 debug）；位4=外部密钥档；
        # 位5=输入依赖档（早期轮次）：boot 据此才去取 argv/stdin——不置位就绝不读 stdin
        # （读会把交互式启动挂住，这是一条真实的行为分叉）
        "header_len": _HEADER_LEN,
        "payload_len": len(payload),
        "py_minor": tuple(sys.version_info[:2]),
        "py_magic": importlib_magic(),
        "nonce": nonce,
        "seed": seed,
    }
    head = _header_bytes(fields)
    if len(head) != _HEADER_LEN:
        raise ValueError("header length mismatch: %d" % len(head))
    mac = hashlib.blake2s(head + ciphertext, key=mac_key, digest_size=32).digest()

    stored_fields = dict(fields)
    if external_key:
        stored_fields["seed"] = b"\x00" * 32  # key_material 置零（产物不携带密钥材料）
    artifact = _assemble(stored_fields, ciphertext, mac, sched, seed)
    return {
        "artifact": artifact,
        "marshal": None if vm else payload,
        "payload": payload,
        "fields": fields,
        "ciphertext": ciphertext,
        "sched": sched,
        "keys": (enc_key, mac_key),
        "warnings": warnings,
        "hardening": hardening_rep,
        "iface": iface,
    }


def _vm_payload(code, seed: bytes, nonce: bytes, sched: int, aead: bool = False,
                input_mode: bool = False) -> bytes:
    """code object → VM blob 字节串（aead=False → fmt_ver=2；True → 3/PSIV）。

    容器 enc_key 由 (seed, nonce, 拓扑) 现算并作为 VM 材料根，**blob 里不写任何密钥**；
    ISA 物理映射由同一 seed 派生（同源），boot 侧用同样的两步现算——构建期与运行期
    共享的只有 seed/nonce 这两个容器层已有的量。子集外的源码在这里被编译器硬拒。

    `input_mode=True`（早期轮次）：载荷必须是 `main(argv, stdin)` 形态，入口号指向 main，
    且 IR 必须真的消费输入（`vm_isa.lain_paterson`）——不消费即拒绝出厂，
    绝不允许"常量输出的退化产物"混进测量代（早期轮次 验收偏差②的根治）。"""
    from d_side.builder import vm_blob, vm_compiler, vm_isa

    try:
        funcs, gtable, strings = vm_compiler.yamagami_karuta(code, input_mode=input_mode)
    except vm_compiler.TaeHanazono as exc:
        # 子集外载荷必须走构建器的"硬门失败、不写盘"出口（CLI 捕 ValueError），
        # 而不是把编译器异常裸抛给用户（实测：裸 traceback + 退出码 1）
        raise ValueError("VM subset rejection: %s（--vm 子集界定见 layout.json "
                         "vm.subset_rejects）" % (exc,)) from None
    if input_mode and not vm_isa.lain_paterson(funcs):
        raise ValueError("强制输入依赖失败：载荷编译后 IR 里没有 ARGV/STDIN——"
                         "该样本不消费输入，不得出厂进测量（早期轮次）")
    mapping = vm_isa.hayase_sou(seed)
    enc_key, _mac = kanae(seed, nonce, sched)
    mao = vm_blob.matsukai_mao(enc_key)
    entry = vm_compiler.umise_yotsuha(code, input_mode)
    return vm_blob.luis_cammy(funcs, mapping, gtable, mao, strings=strings, aead=aead,
                              entry_fid=entry)


def importlib_magic() -> bytes:
    import importlib.util

    return importlib.util.MAGIC_NUMBER


def _assemble(fields: dict, ciphertext: bytes, mac: bytes, sched: int, seed: bytes) -> str:
    """读引导模板 → 剥 docstring → 按 seed 改名 → 注入常量 → 尾接入口调用。"""
    from pyshroud.seeding.derive import moona_hoshinova, tomoe_udagawa, tsugumi_hazawa

    template_path = Path(__file__).resolve().parent / "boot_d2a.py"
    boot_src = template_path.read_text(encoding="utf-8")
    # 模板自己的两行头部不进产物（会让产物自称 GPL 作品）；措辞单点在 源码混淆侧 notice 模块，
    # 三处注入点共用同一函数
    header = artifact_header()

    template = ast.parse(boot_src)
    _verify_template_spec(template)

    ctx = moona_hoshinova(int.from_bytes(seed, "big") ^ 0x0D51C0DE)
    renames = {}
    for sym in _TEMPLATE_SYMBOLS:
        renames[sym] = tsugumi_hazawa(ctx, ctx.taken)
    for node in ast.walk(template):
        if isinstance(node, ast.Name):
            if node.id in renames:
                node.id = renames[node.id]
        elif isinstance(node, ast.FunctionDef):
            if node.name in renames:
                node.name = renames[node.name]
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:]

    def store(sym):
        return ast.Name(id=renames[sym], ctx=ast.Store())

    def load(sym):
        return ast.Name(id=renames[sym], ctx=ast.Load())

    def const(value):
        return ast.Constant(value=value)

    field_values = (fields["fmt_ver"], fields["flags"], fields["header_len"], fields["payload_len"],
                    tuple(fields["py_minor"]), fields["py_magic"], fields["nonce"], fields["seed"])
    template.body += [
        ast.Assign(targets=[store("_SCHED")], value=const(sched)),
        ast.Assign(targets=[store("_FIELDS")], value=ast.Tuple(
            elts=[const(v) for v in field_values[:4]]
                 + [ast.Tuple(elts=[const(x) for x in field_values[4]], ctx=ast.Load()),
                    const(field_values[5]), const(field_values[6]), const(field_values[7])],
            ctx=ast.Load())),
        ast.Assign(targets=[store("_PAYLOAD")], value=const(ciphertext)),
        ast.Assign(targets=[store("_MAC")], value=const(mac)),
        ast.Expr(value=ast.Call(func=load("setsuna"), args=[], keywords=[])),
    ]
    ast.fix_missing_locations(template)
    return header + ast.unparse(template) + "\n"


def _verify_template_spec(template: ast.Module) -> None:
    """layout.json 是字段表单一来源：模板内嵌 `_SPEC` 必须与之相等（构建期断言， 同源纪律）。"""
    for node in ast.walk(template):
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Tuple, ast.List)) \
                and getattr(node.targets[0], "id", "") == "_SPEC":
            got = tuple(
                (elt.elts[0].value,)
                for elt in node.value.elts
            )
            want = tuple((size,) for _, size in _SPEC)
            if got != want:
                raise ValueError("boot template _SPEC diverges from layout.json: %r vs %r" % (got, want))
            return
    raise ValueError("boot template has no _SPEC")


def suzuka_utako(artifact_text: str, key: bytes = None) -> tuple:
    """`check` 子命令的校验入口：解析产物文本 → 结构自洽 → 版本绑定 → MAC。

    外部密钥档（flags 位 4）产物：`key` 提供时做完整 MAC 校验（以 key 重建
    真实头部）；未提供时结构/版本绑定照验、MAC 如实跳过（ok=True，reason
    返回跳过说明）。只校验，不运行、不执行载荷。"""
    try:
        tree = ast.parse(artifact_text)
    except SyntaxError as exc:
        return False, "artifact is not valid python: %s" % exc
    constants = []
    for node in template_walk(artifact_text):
        constants.append(node)
    fields_const = payload = mac_const = sched = None
    for value in constants:
        if isinstance(value, tuple) and len(value) == 8 and isinstance(value[4], tuple) \
                and len(value[4]) == 2 and isinstance(value[5], bytes) and len(value[5]) == 4 \
                and isinstance(value[6], bytes) and len(value[6]) == 12 \
                and isinstance(value[7], bytes) and len(value[7]) == 32:
            fields_const = value
        elif isinstance(value, bytes) and len(value) >= _LADDER[0]:
            payload = value
        elif isinstance(value, bytes) and len(value) == 32:
            mac_const = value
        elif isinstance(value, int) and not isinstance(value, bool) and value in (1, 2, 3, 4, 5, 6, 7, 8):
            sched = value
    if fields_const is None:
        return False, "field tuple missing or malformed"
    if not isinstance(payload, bytes) or not isinstance(mac_const, bytes) or not isinstance(sched, int):
        return False, "payload/mac/schedule constants missing"
    fmt_ver, flags, header_len, payload_len, py_minor, py_magic, nonce, seed = fields_const
    if fmt_ver not in (1, 2):
        # 1 = marshal 载荷（现产品）；2 = VM blob 载荷（v2，native 专用）
        return False, "format version mismatch"
    if flags & 0xC8 or not flags & 1:
        # 位 3（压缩）与 6/7（保留）必须为 0；位 5 = 输入依赖档（早期轮次）自 0.0.42
        # 起合法（此前与保留位一起被拒）
        return False, "flags violate the layout policy"
    if header_len != _HEADER_LEN:
        return False, "header_len mismatch"
    if not isinstance(payload_len, int) or payload_len < 1 or payload_len > len(payload):
        return False, "payload_len out of range"
    if bytes(py_minor) != bytes(sys.version_info[:2]) or bytes(py_magic) != importlib_magic():
        return False, "version binding mismatch"
    external = bool(flags & 0x10)
    if external:
        if key is None:
            return True, "external-key artifact: structure/version verified; MAC skipped (no key)"
        seed = key
    import d_side.keys as keys_mod

    try:
        enc_key, mac_key = keys_mod.kanae(seed, nonce, sched)
    except ValueError as exc:
        return False, str(exc)
    head = _header_bytes({
        "fmt_ver": fmt_ver, "flags": flags, "header_len": header_len, "payload_len": payload_len,
        "py_minor": py_minor, "py_magic": py_magic, "nonce": nonce, "seed": seed,
    })
    tag = hashlib.blake2s(head + payload, key=mac_key, digest_size=32).digest()
    if not hmac.compare_digest(tag, mac_const):
        return False, "MAC mismatch"
    if external:
        return True, "external-key artifact: MAC verified with supplied key"
    return True, None


def template_walk(artifact_text: str):
    """按形状收集产物顶层常量值（构建期符号已按 seed 改名，不能按名索引——早期轮次 审计同款方法）。"""
    for node in ast.parse(artifact_text).body:
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if isinstance(value, ast.Constant):
            yield value.value
            continue
        try:
            yield ast.literal_eval(value)
        except (ValueError, SyntaxError, MemoryError):
            continue
