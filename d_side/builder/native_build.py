# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""builder： 产物 → 独立 native exe（端到端正式化，早期轮次；D-3 守卫 0.0.39）。

链路（`azuchi_momo`）：`suzuka_utako` 硬门 → `kanda_shoichi` 形解析 →
KAT/HKDF/BLAKE2s 期望值由 Python 权威侧现算（零手抄）→ `asuka_hina` 写
pins/payload/rc → rc.exe（RCDATA）→ rustc（`/Brepro + /DEBUG:NONE` 确定性
链接）→ `hayama_marin` post-link 摘要入槽（patcher）→ exe。
`embed_home` 档在 rc 阶段额外打进 RT_RCDATA "home"（B 方案单文件：CPython
home 打包 + pins 哈希，boot 首启释放到本地缓存；见 `_build_home_pack`）。
boot 源（`boot.rs`）与 BLAKE2s 端口为仓内静态文件，构建机路径只出现在
临时工作目录的生成文件里，不进产物源、不入版控。
"""
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

from d_side import chacha20, codec, keys
from d_side.builder import decoy_faces
from d_side.builder.patcher import hayama_marin, kaida_haru, nui_sociere

_BUILDER_DIR = Path(__file__).resolve().parent
# +（既有审计结论）：产物内错误短码折叠为单数字 0~9。既有审计
# 均把 E-NN 编号区间当结构指纹使用（审计中据 E-56..E-61 反推根块校验链字段顺序）。
# 折叠规则：digit = blake2s("E-NN" + nonce)[:1] % 10——同构建恒定（自验可断
# 言），跨构建随 nonce 漂移（跨代际差分失效）；105 个短码落入 10 个桶是**有
# 意的语义粗化**：差分测绘只能到达桶边界，不可到达具体原因。对照表（短码→
# 数字→构建位点）随构建写 workdir/errcode_map.json——只存在维护者本地工作
# 目录，不进产物、不进仓内源码
_ERRCODE_RE = re.compile(r"E-(\d{2,3})\b")  # \b：E-109 的"09"不得二次匹配
# vm_ops 是 vm.rs 的嵌套 #[path] 依赖，必须一起物化 + 改名 + 折叠（漏一处就是
# "workdir 里找不到那个 .rs" 的构建失败）
_FOLDED_MODS = ("blake2s", "vm", "vm_ops", "psiv", "visprobe")

# 批2-2.1 变体池的热操作码（顺序即注册顺序）。选池依据不是拍脑袋：
# `.tmp/opstats_dyn.py` 用 vm_interp 的 trace 齿把套件真实跑过的 v2 载荷
# （r10 fib 靶 / 混合循环 / 早期轮次 canonical 输入依赖源）跑一遍，按**执行次数**排：
#   MOVE 42.8% / ADD 9.3% / LOADK 8.7% / LOADG 7.9% / JMP 4.6% / LT 4.4% /
#   JZ 4.4% / LOADN 4.3% / STOREG 2.4% / MUL 2.0%（前八覆盖 86.4%）
# JMP/JZ/JN/CALL/RET 不入选池：控制流的可写实现只有"改 pc / 换帧"一种，
# 排成三份是同一件事的三种排版，没有可测的语义差异（如实登记，不做凑数变体）。
# 早期轮次扩池：XOR/ROTL32 是 ISA v5 才加的两码，此前**各只有一条实现**——链被保护
# 之后它们仍是"反汇编一次、八格通用"的公共知识，与逐格化的总目标直接冲突；
# HSTEP是新的热码，步进结构全在它里面，不入池等于把刚收起来的结构再摊开一次。
HOT_OPS = ("MOVE", "ADD", "LOADK", "LOADG", "LT", "LOADN", "STOREG", "MUL",
           "XOR", "ROTL32", "HSTEP")
_VARIANTS = 3
_PERM_MUT = b"i14"          # 选择流的 HKDF 域标签（续中性短码序列）


def kuramochi_meruto(seed: bytes, nonce: bytes, mutate: bool = True) -> dict:
    """构建期变体选择：每个热操作码从 0/1/2 里定一条路径（seed, nonce 确定性派生）。

    `mutate=False` 是消融档：全部落 0 号变体（= 参考实现）并关掉运行期建表，
    给测量轮做"变异层开 / 关"的归因矩阵。**boot 侧的选择轴是编译期常量**
    （`pins::V_<OP>`），所以未选变体不生成代码——这条断言由产物标签扫描齿钉。
    运行期零随机：本函数没有任何环境依赖，同 (seed, nonce) 必然同选择。"""
    prk = keys._extract(nonce, bytes(seed) + bytes(nonce))
    stream = keys._expand(prk, _PERM_MUT, len(HOT_OPS) + 8)
    sel = {op: (0 if not mutate else stream[i] % _VARIANTS)
           for i, op in enumerate(HOT_OPS)}
    return {"mutate": bool(mutate), "sel": sel,
            "distinct": len(set(sel.values())), "stream": stream[:len(HOT_OPS)]}  # boot.rs 的 #[path] 依赖


def _fold_errcodes(text: str, nonce: bytes) -> tuple:
    """把 text 中全部 "E-NN" 字面量折叠为一位数字，返回 (新文本, 映射)。"""
    mapping = {}

    def _sub(m):
        code = m.group(0)
        if code not in mapping:
            mapping[code] = str(hashlib.blake2s(
                code.encode("ascii") + nonce, digest_size=1).digest()[0] % 10)
        return mapping[code]

    return _ERRCODE_RE.sub(_sub, text), mapping


# ---------- 批2-1.1/2-1.2：子检查顺序置换 + 拒绝时序垫（构建侧权威） ----------
# 与 boot.rs 的 `fura_kanato` / `amagi_yuni` 逐字同式（域标签 i10..i13 续用中性短码
# 序列；A 组提取/展开 = i10/i11，B 组 = i12/i13）。两侧不一致的后果不是"顺序不同"
# 而是**运行期封印不符即静默 exit 3**——真跑用例全部致死，所以这条齿是机械的。
# 诚实边界：顺序不是保密量（120/6 种置换可枚举），本件的价值是把"检查排成一条
# 直线"这条静态可读事实从代码里抹掉（对策来源：早期轮次 §5 校验时序/顺序侧信道）。
_PERM_A_SALT, _PERM_A_INFO, _PERM_A_N = b"i10", b"i11", 5     # 守卫 1a 五枚
_PERM_B_SALT, _PERM_B_INFO, _PERM_B_N = b"i12", b"i13", 3     # 解密前三枚
_PAD_DOMAIN = b"pad\x01"
_PAD_MIN, _PAD_SPAN = 8192, 16384


def _perm_mirror(ikm: bytes, salt: bytes, info: bytes, n: int) -> list:
    """ikm → 0..n 的确定性置换。Fisher-Yates 的游标纪律与 `vm_isa.hayase_sou`
    一致：j 先取本轮交换目标，再 j += 1 作为下一轮游标，越界回绕——把它"整理"成
    独立变量会改写取字节序列（实测双端分叉）。"""
    prk = keys._extract(salt, ikm)
    stream = keys._expand(prk, info, n * 4 + 4)
    order = list(range(n))
    j = 0
    for i in range(n - 1, 0, -1):
        j = stream[j] % (i + 1)
        order[i], order[j] = order[j], order[i]
        j += 1
        if j >= len(stream):
            j = 0
    return order


def seraph_dazzlegarden(mac: bytes, nonce: bytes) -> dict:
    """→ {"order_a", "order_b", "seal_a", "seal_b", "reject_pad"}。

    A 组只吃 nonce：守卫 1a 整体在**任何密钥材料被读取之前**跑（外钥档此刻还
    没有 seed），而 nonce 本身 = HKDF(payload_digest, seed)——"seed 派生"经此传递
    成立。B 组吃 **MAC 钉 ‖ nonce**：MAC 由含 seed 的整头部算出、本就钉在 .rdata，
    所以顺序仍是 seed 的函数，但**不把裸 seed 送进任何新的 HKDF**。首版这里用
    seed‖nonce，HMAC/SHA-256 的内部分块缓冲把一份完整 seed 留在已释放堆里，被
    步骤 3 的内存自证当场抓红（实测）。
    封印 = keyed blake2s(置换字节 ‖ 枚数, key=INTEG_KEY) 前 16 B——双端一致性齿，
    不是保密边界（持产物者可枚举全部置换撞它，见上方诚实边界）。"""
    mac, nonce = bytes(mac), bytes(nonce)
    order_a = _perm_mirror(nonce, _PERM_A_SALT, _PERM_A_INFO, _PERM_A_N)
    order_b = _perm_mirror(mac + nonce, _PERM_B_SALT, _PERM_B_INFO, _PERM_B_N)

    def _seal(order, n):
        msg = bytes(order) + bytes([n])
        return hashlib.blake2s(msg, key=kaida_haru(nonce)).digest()[:16]

    pad_seed = hashlib.blake2s(_PAD_DOMAIN + mac + nonce, digest_size=4).digest()
    return {"order_a": order_a, "order_b": order_b,
            "seal_a": _seal(order_a, _PERM_A_N), "seal_b": _seal(order_b, _PERM_B_N),
            "reject_pad": _PAD_MIN + int.from_bytes(pad_seed, "big") % _PAD_SPAN}


# ---------- 早期轮次 Phase 2（指导稿 §2）：接口不变量逐格化 ----------

# 既有审计的缺口不是"被算出来了"，而是"只算了一次"：多次独立审计互不知情却收敛到**同一份**
# 行为契约（64 上界 / 0x00 连接 / argv[0] 不参与 / 空格式 --key-file 被剥 / 超限
# exit 3 全空 / col3 = 字节和），因为那份契约在 boot.rs 里是全局常量——读一次就能
# 用八格、跨代还能用。这一节把它换成**构建期逐格派生**（运行期零随机， 不破），
# 派生渠道沿用既有层级：extract(i22) over seed‖nonce → expand(i23)。
# 首版曾想用 `sha256("r12g5/<zone>/<name>/...")` 那种"按格子名派生"的写法，但产品
# 侧只有 seed/nonce，格子名是**测量场景**的概念；把它接进 boot 就等于新增一条
# "名字→行为"的公开查表面。改走 seed‖nonce 派生后，逐格性由"每格一份 seed"保证，
# 与 /chunk 置换/变体选择完全同构（登记为对指导稿字面口径的偏离）。
IFACE_SALT, IFACE_INFO = b"i22", b"i23"
IFACE_BYTES = 24
IFACE_AP_LO, IFACE_AP_SPAN = 48, 33      # ap/sp ∈ 48..80
IFACE_ARG_LO, IFACE_ARG_SPAN = 8, 33     # argv 项数上限 ∈ 8..40
IFACE_JOIN_NONE = 256                    # "无连接符"档（直接拼接）
IFACE_COL3 = ("nonzero", "lines", "highbit", "pairs", "printable")
# 第三列语义族：**全部是"吸收后窗口上的无分支归约"**，没有一项是输入长度本身。
# 理由有两条：①定长吸收之后真实长度在载荷侧已不可得（kind 3/4 报的是上限），
# 而"字节数"这一族成员正好要靠它——指导稿那张表写在前一代的口径上；②col3 是
# 载荷算出来的，不是 boot 算出来的，boot 侧替载荷打一行输出等于新增一种可观察行为，
# 与静默拒绝契约直接冲突。所以这里给的是"免费线性神谕"被拿掉之后的替代族
# （登记为对指导稿字面口径的偏离，成员全部可由既有操作码无分支算出）。
# --key-file 剥离四档：0 只剥空格式（= 上一代全局行为）/ 1 只剥等号式 /
# 2 两种都剥 / 3 都不剥。注意 1/3 会把旗标本身留在载荷可见窗里——那是**故意的**
# （接口逐格化的全部意义就是"每格的可见面不一样"），代价是这些格er的输出随密钥文件
# 路径变化，验收侧必须按本格契约供钥并记录同一个 argv 序列（写进 验收输入表）。
KEYSTRIP_NAMES = ("space", "equals", "both", "none")
# 铺开节奏（指导稿 §10.5 与工作书"先做一区样机，再全量铺开"）：契约形态开关的单一来源
# 是 layout.json > hardening.iface.mode。"uniform" 逐格退化为上一代的全局形态
# （64/64/64/0x00/跳过 argv[0]/只剥空格式/超限 exit 3），"per_cell" 才派生逐格值。
# 两套形态**共用同一条代码路径**（boot 与 VM 都只读 pins::IFACE_*），差别只在算出来的
# 值上——所以样机跑绿之后全量铺开是改一行 layout，不是改一条分支。
IFACE_MODE_UNIFORM = "uniform"
IFACE_MODE_PER_CELL = "per_cell"
_UNIFORM = {"ap": 64, "sp": 64, "argmax": 64, "join": 0, "argv0": False,
            "keystrip": 0b01, "reject_exit": 3, "col3": "len-sum"}


def iface_mode_default() -> str:
    """契约形态的单一来源：layout.json > hardening.iface.mode（缺省按 per_cell）。"""
    mode = codec._LAYOUT.get("hardening", {}).get("iface", {}).get("mode")
    return mode or IFACE_MODE_PER_CELL


def koyanagi_rou(seed: bytes, nonce: bytes = None, mode: str = None) -> dict:
    """seed → 本格接口契约。构建期唯一出处：boot 的 pins、验收契约表、验收门都从
    这里取，任何一处自己另算一份就是分叉面。

    派生**只吃 seed、不吃 nonce**（`nonce` 形参保留是给调用方对齐签名用的，不参与
    派生）。理由不是省事：目标源码的第三列语义取自本契约，而 nonce 又是目标源码摘要的函数——
    带 nonce 就成"契约←源←契约"的自指回环，场景生成器只能两趟构建且第二趟的 nonce
    又会改掉契约。逐格性由"每格一份 seed"提供，与 nonce 无关（登记为对指导稿
    "sha256(zone/name/iface/param)" 字面写法的一处偏离）。

    `mode` 缺省时读 layout（见上面的铺开节奏）；显式传值给样机与验收齿用。"""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    if mode is None:
        mode = iface_mode_default()
    if mode == IFACE_MODE_UNIFORM:
        spec = dict(_UNIFORM)
        spec["mode"] = mode
        spec["fingerprint"] = "uniform"
        return spec
    if mode != IFACE_MODE_PER_CELL:
        raise ValueError("unknown iface mode %r" % (mode,))
    s = keys._expand(keys._extract(IFACE_SALT, bytes(seed)), IFACE_INFO, IFACE_BYTES)
    join = IFACE_JOIN_NONE if s[4] % 8 == 0 else s[4]
    return {
        "mode": mode,
        "ap": IFACE_AP_LO + s[0] % IFACE_AP_SPAN,          # argv 扁平窗上限
        "sp": IFACE_AP_LO + s[1] % IFACE_AP_SPAN,          # stdin 窗上限
        "argmax": IFACE_ARG_LO + s[2] % IFACE_ARG_SPAN,    # argv 项数上限
        "argv0": bool(s[3] & 1),                           # argv[0] 是否参与
        "join": join,                                      # 连接字节 / 256=无连接符
        "keystrip": s[5] % 4,                              # --key-file 剥离四档
        "reject_exit": 3 + s[6] % 2,                       # 超限拒绝码 ∈ {3,4}
        "col3": IFACE_COL3[s[7] % len(IFACE_COL3)],        # 第三列语义族
        "fingerprint": "%d/%d/%d/%d/%s/%d/%d/%s" % (
            s[0], s[1], s[2], s[3], str(join), s[5], s[6], str(s[7])),
    }


# ---------- 批2-1.3：错误码对照表加密落盘 ----------
# 表是"短码→数字→构建位点"的唯一真相；明文躺在维护者工作目录里，表一失窃
# 整条折叠就即时可解（早期轮次 §5  项）。改为 scrypt(口令, salt=nonce) 派生键 +
# HMAC-SHA256 计数器流 XOR 写盘；口令缺失时退回明文（老工作流不中断），
# 报告里如实标 "plaintext"。参数取 n=2^15/r=8/p=1（≈33 MB，落在 hashlib
# 默认 maxmem 内——2^17 需要显式抬高 maxmem，那是口令档 KEM 的口径，见 §1.1）。
_MAP_MAGIC = "ECM1"
_MAP_N, _MAP_R, _MAP_P = 2 ** 15, 8, 1
_MAP_PASS_ENV = "PRACTICE_ERRCODE_PASS"
_MAP_DOMAIN = b"ks2"          # 与守卫流的 ks1 域分开（同一 keystream 形，不同用途）
_MAP_FILE = "errcode_map.json"
_MAP_ENC_FILE = "errcode_map.enc.json"


def _map_scrypt(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """hashlib.scrypt + 显式 maxmem。OpenSSL 的默认上限是 4 MiB，而 scrypt 的
    工作内存是 128·r·N 字节——不显式抬 maxmem 时 n=2^15/r=8 直接
    "[digital envelope routines] memory limit exceeded"（首版实测踩中，
）。参数写在文件头里，解码侧照抄同一公式。"""
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=32, maxmem=128 * r * n + 1024 * 1024)


def _map_key(passphrase: str, nonce: bytes) -> bytes:
    return _map_scrypt(passphrase, bytes(nonce), _MAP_N, _MAP_R, _MAP_P)


def _map_stream_xor(data: bytes, key: bytes) -> bytes:
    """HMAC-SHA256 计数器 keystream XOR（自逆；域 b"ks2" 与守卫的 ks1 分离）。"""
    out = bytearray()
    for i in range(0, len(data), 32):
        ks = hmac.new(_MAP_DOMAIN + key + i.to_bytes(8, "little"), b"",
                      hashlib.sha256).digest()
        out.extend(c ^ k for c, k in zip(data[i:i + 32], ks))
    return bytes(out)


def igarashi_rika(path: Path, mapping: dict, passphrase: str, nonce: bytes) -> dict:
    """对照表加密写盘（确定性：json sort_keys + 固定参数头）。返回头部摘要供报告。"""
    text = json.dumps({k: {"digit": v} for k, v in sorted(mapping.items())},
                      ensure_ascii=False, indent=1, sort_keys=True)
    key = _map_key(passphrase, nonce)
    body = _map_stream_xor(text.encode("utf-8"), key)
    doc = {"format": _MAP_MAGIC, "kdf": "scrypt", "n": _MAP_N, "r": _MAP_R,
           "p": _MAP_P, "cipher": "hmac-sha256-ctr", "salt": bytes(nonce).hex(),
           "check": hashlib.blake2s(text.encode("utf-8"), digest_size=16).hexdigest(),
           "entries": len(mapping), "data": body.hex()}
    path.write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n", encoding="ascii")
    return {"entries": len(mapping), "check": doc["check"]}


def koshimizu_toru(path: Path, passphrase: str) -> dict:
    """读回并解密对照表（口令错 ⇒ `check` 不符 ⇒ ValueError，不吐半解密文）。"""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("format") != _MAP_MAGIC:
        raise ValueError("not an %s errcode map: %s" % (_MAP_MAGIC, path))
    salt = bytes.fromhex(doc["salt"])
    plain = _map_stream_xor(bytes.fromhex(doc["data"]),
                            _map_scrypt(passphrase, salt, int(doc["n"]),
                                        int(doc["r"]), int(doc["p"])))
    if hashlib.blake2s(plain, digest_size=16).hexdigest() != doc["check"]:
        raise ValueError("errcode map passphrase mismatch (or table corrupted)")
    return json.loads(plain.decode("utf-8"))


def _materialize_folded_sources(workdir: Path, nonce: bytes,
                                map_pass: str = None) -> dict:
    """把仓内 .rs 物化到 workdir 并折叠错误短码，返回短码→数字映射。

    仓内 boot.rs/blake2s.rs/vm.rs/psiv.rs/visprobe.rs 保持 E-NN 原文（维护者
    可读）；参与编译的是 workdir 下的折叠副本：boot 的四个 #[path] 相对引用
    改指随机化副本名（早期轮次 2.4：原 w_<mod>.rs 文件名与仓内源一一对应，是弱源
    指纹——副本名改 nonce 派生随机 hex，产物 panic 路径只暴露无语义名），
    native_main.rs 的 boot 绝对路径改指同名随机化副本，d2a_pins.rs（内嵌
    Python 守卫的诊断桶码字面量）一并折叠。"""
    # 随机化名按**不重叠**的 4 字节窗口切：第一版用 `rng[i:i+4]` 步进 1，
    # 第 5 个模块（加 vm_ops 后才有）的窗口正好撞上 boot 副本自己的名字
    # `rng[4:8]` ⇒ boot 的 `mod visprobe` 指向它自己 = circular modules
    rng = hashlib.blake2s(b"modname\x03" + nonce, digest_size=32).digest()
    mod_alias = {mod: "m" + rng[4 * i:4 * i + 4].hex()
                 for i, mod in enumerate(_FOLDED_MODS)}
    boot_alias = "m" + rng[4 * len(_FOLDED_MODS):4 * len(_FOLDED_MODS) + 4].hex()
    boot_txt, mapping = _fold_errcodes(
        (_BUILDER_DIR / "boot.rs").read_text(encoding="utf-8"), nonce)
    for mod in _FOLDED_MODS:
        src, m = _fold_errcodes(
            (_BUILDER_DIR / (mod + ".rs")).read_text(encoding="utf-8"), nonce)
        mapping.update(m)
        # 嵌套依赖：vm.rs 里 `#[path = "vm_ops.rs"] mod ops;` 指的也是 workdir 副本，
        # 所以别名改写要对**每个 mod 的文本**做一遍，不只是 boot（首版只改 boot，
        # vm_ops 留在 workdir 外 ⇒ rustc "file not found for module"）
        for other in _FOLDED_MODS:
            src = src.replace('#[path = "%s.rs"]' % other,
                              '#[path = "%s.rs"]' % mod_alias[other])
        (workdir / (mod_alias[mod] + ".rs")).write_text(src, encoding="utf-8")
        boot_txt = boot_txt.replace(
            '#[path = "%s.rs"]' % mod, '#[path = "%s.rs"]' % mod_alias[mod])
    (workdir / (boot_alias + ".rs")).write_text(boot_txt, encoding="utf-8")
    nm = workdir / "native_main.rs"
    nm.write_text(nm.read_text(encoding="utf-8").replace(
        str(_BUILDER_DIR / "boot.rs").replace("\\", "/"), boot_alias + ".rs"),
        encoding="utf-8")
    pins_rs = workdir / "d2a_pins.rs"
    pins_txt, m3 = _fold_errcodes(
        pins_rs.read_text(encoding="utf-8"), nonce)
    mapping.update(m3)
    pins_rs.write_text(pins_txt, encoding="utf-8")
    # 批2-1.3：对照表落盘形态——有口令则加密（明文绝不落盘），无口令退回明文并在
    # 构建报告里标 "plaintext"（老工作流不中断，但差异是可见的、可断言的）。
    if map_pass:
        igarashi_rika(workdir / _MAP_ENC_FILE, mapping, map_pass, nonce)
    else:
        (workdir / _MAP_FILE).write_text(
            json.dumps({k: {"digit": v} for k, v in sorted(mapping.items())},
                       ensure_ascii=False, indent=1, sort_keys=True),
            encoding="ascii")
    return mapping
# KAT 固定输入（boot.rs 逐字一致；期望值构建期现算，禁止手抄）
# 值取随机形（既有审计结论）：原 'salt-fixed-01'/'input-key-material'/
# 'info-tag' 是原语确认通道——外部分析者据其判定 BLAKE2s-HMAC/HKDF 结构
_KAT_HKDF_SALT = bytes.fromhex("9f2c7a41d8e63b05")
_KAT_HKDF_IKM = bytes.fromhex("c4e1a8f2b67d0935ad41c2f8")
_KAT_HKDF_INFO = bytes.fromhex("73bd9e4c")
# T7 Authenticode action GUID（SDK SoftPub.h 权威值，勿手抄他处）
_GENERIC_VERIFY_V2 = (0x00AAC56B, 0xCD44, 0x11D0,
                      (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
# D-3 守卫 1b 快照（单一源，经 pins 进 boot；快照只用 sys、不 import os——
# 隔离启动下 os 本不在 sys.modules，导入它会制造可观测分叉）。命中路径
# raise SystemExit(3)：PyErr_Print 语义内直接以 3 退出且无回溯。
_PY_GUARD_MODULES = "{'pdb', 'debugpy', 'ptvsd', 'pydevd', 'pydevd_tracing', 'frida'}"
_PY_GUARD_SNIPPET = (
    "import sys as _s\n"
    "_t = _s.gettrace()\n"
    "_p = _s.getprofile()\n"
    "_e = " + _PY_GUARD_MODULES + "\n"
    "_f = _e.intersection(_s.modules)\n"
    "if _t is not None or _p is not None or _f:\n"
    "    raise SystemExit(3)\n"
    "del _s, _t, _p, _e, _f\n"
)
_PY_GUARD_SNIPPET_DIAG = (
    "import sys as _s\n"
    "_t = _s.gettrace()\n"
    "_p = _s.getprofile()\n"
    "_e = " + _PY_GUARD_MODULES + "\n"
    "_f = _e.intersection(_s.modules)\n"
    "if _t is not None or _p is not None:\n"
    "    _s.stderr.write('E-109\\n')\n"
    "    raise SystemExit(3)\n"
    "if _f:\n"
    "    _s.stderr.write('E-110\\n')\n"
    "    raise SystemExit(3)\n"
    "del _s, _t, _p, _e, _f\n"
)
# 1b 快照的 DIAG 文案也进产物（`pins::PY_GUARD_SNIPPET_DIAG` 是 &str 常量），
# 所以两条原因同样改短码——语义只在私有解码表（E-109/E-110）。
# +（既有审计结论）：快照是"单一源"——测试直接 import 本常量经
# `python -c` 执行，产物内则经 pins 字面量内嵌，两路必须看到**同一个**折叠后
# 文本，故折叠在常量定义处做（模块级固定折叠键；诊断桶码跨构建恒定——桶化
# 粗化已使编号区间不可指认，固定映射即可）。产物侧 d2a_pins.rs 的折叠对本
# 文本幂等（数字串不再匹配 E-NN 正则）。
_DIAG_FOLD_KEY = b"py-guard-diag-fold-v1"
_PY_GUARD_SNIPPET_DIAG, _PY_GUARD_DIAG_MAP = _fold_errcodes(
    _PY_GUARD_SNIPPET_DIAG, _DIAG_FOLD_KEY)
# 早期轮次 步骤 2.1：守卫快照编码化——明文守卫曾被 外部还原
# （实证）。产物只存密文字节常量；解码键构建期确定性派生（**只由 nonce 派生
# 的 INTEG_KEY 域**，步骤 3 修正：早期版本用 seed‖nonce，等于把真实 seed 明文
# 钉进外钥档产物），boot 侧 Rust 解码后喂 PyRun_SimpleString。仓内明文快照仍是
# 单一源（测试直接 import），编码只在 pins 组装时发生。


def _rustc_sysroot() -> str:
    """rustc sysroot（早期轮次 2.4 remap 条目用；探测失败返回空串=不加该条目）。"""
    try:
        rustc = shutil.which("rustc")
        if not rustc:
            return ""
        r = subprocess.run([rustc, "--print", "sysroot"], capture_output=True,
                           text=True, timeout=30, shell=False)
        return r.stdout.strip()
    except Exception:
        return ""


def _guard_stream_key(nonce: bytes) -> bytes:
    """守卫解码流键——与 boot.rs guard_decode 逐字同式：HMAC-SHA256（即 boot
    的 joe_rikiichi/rindou_mikoto 对），key=域‖INTEG_KEY‖，msg 空。**不是
    blake2s**（首版用 blake2s 曾双端分叉——自查抓获）。
    早期轮次 2.4：域串中性化（b"dk1"——原 b"guard-decode-key" 是语义提示，且明文
    随 HMAC key 进产物可被串扫描发现），双端同步。
    早期轮次 步骤 3（严重修正）：键材料从 **seed‖nonce 改成只由
    nonce 派生的 INTEG_KEY**。上一版把真实 seed 以 PY_GUARD_SEED 钉写进
    d2a_pins.rs，等于在**外钥档产物**里明文携带 seed——"真实 seed 不进 exe"
    被这条钉直接击穿（内嵌档本就带 seed，只有外钥档受害）。改为 nonce 派生后
    产物内不再有任何 seed 载体；守卫文本的保密口径不变（仍是拖延档：持产物者
    可复算 INTEG_KEY）。"""
    return hmac.new(b"dk1" + kaida_haru(nonce), b"", hashlib.sha256).digest()


def _guard_encode(text: str, key: bytes) -> bytes:
    """确定性流编码：HMAC-SHA256 计数器 keystream XOR（自逆，boot 侧同式解码）；
    32B 分块，计数器 u64 LE 追加在 HMAC key 尾。域串 b"ks1" 同批中性化。"""
    data = text.encode("utf-8")
    out = bytearray()
    for i in range(0, len(data), 32):
        ks = hmac.new(b"ks1" + key + i.to_bytes(8, "little"), b"",
                      hashlib.sha256).digest()
        out.extend(c ^ k for c, k in zip(data[i:i + 32], ks))
    return bytes(out)


# ---------- B 方案：单文件 home（内嵌 CPython home → 首启释放到本地缓存） ----------
_EMBED_HOME_MODES = ("lean", "std", "full")
_HOME_PACK_MAGIC = b"PHM1"
_HOME_CACHE_SUBDIR = "PracticeEncryption"
_HOME_STDLIB_SKIP_TOP = {"site-packages", "test", "tests", "__pycache__", "idlelib",
                         "turtledemo", "lib2to3", "ensurepip", "tkinter"}
_HOME_COMMON_PYD = ("_asyncio.pyd", "_bz2.pyd", "_ctypes.pyd", "_decimal.pyd",
                    "_elementtree.pyd", "_hashlib.pyd", "_lzma.pyd",
                    "_multiprocessing.pyd", "_overlapped.pyd", "_queue.pyd",
                    "_socket.pyd", "_uuid.pyd", "select.pyd", "unicodedata.pyd",
                    "pyexpat.pyd", "winsound.pyd", "_msi.pyd")
_HOME_COMMON_DLL = ("libffi-8.dll",)
_HOME_FULL_EXTRA_PYD = ("_ssl.pyd", "_sqlite3.pyd")
_HOME_FULL_EXTRA_DLL = ("libssl-3.dll", "libcrypto-3.dll", "sqlite3.dll")


_VC_REDIST_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

# 随产物分发的许可文本（名单与 Licenses/README.md §1.2 的档位映射逐条对应；改动其
# 一时必须同改另一处——文本文件名带版本，升级 CPython 时这里会指不到文件，即报错）
_LICENSES_DIR = _BUILDER_DIR.parents[1] / "Licenses" / "native-product"
_NOTICE_RUST = ("rust-std-1.98.1-LICENSE-MIT.txt", "rust-std-1.98.1-LICENSE-APACHE.txt")
_NOTICE_PY_HOME = ("CPython-3.12.10-PSF-License.txt", "zlib-1.3.1-license.txt")
_NOTICE_STD_EXTRA = ("bzip2-1.0.8-LICENSE.txt", "liblzma-5.2.5-xz-COPYING.txt",
                     "mpdecimal-2.5.1-BSD-2-Clause.txt", "libexpat-2.7.1-MIT-COPYING.txt",
                     "libffi-3.4.4-MIT-LICENSE.txt",
                     "unicodedata-UCD-15.0.0-unicode-license.txt")
_NOTICE_FULL_EXTRA = ("openssl-3.0.16-Apache-2.0-LICENSE.txt",
                      "sqlite-3.49.1-public-domain.txt")


def _notice_set(mode):
    """embed_home 档 → 该产物需随附的许可文本文件名（None = 未内嵌 home）。"""
    if not mode:
        return list(_NOTICE_RUST)
    files = list(_NOTICE_PY_HOME) + list(_NOTICE_RUST)
    if mode in ("std", "full"):
        files += list(_NOTICE_STD_EXTRA)
    if mode == "full":
        files += list(_NOTICE_FULL_EXTRA)
    return files


def _copy_notices(mode, out_exe):
    """把该档文本复制到产物旁 `<exe 名>.licenses/`，返回 (落盘路径, 缺席名单)。

    缺席不静默：名单原样交给调用方报出——"随附齐了"这件事必须是可断言的，
    少一份文本与没做这一步在分发侧是同一个后果。"""
    dest_dir = Path(out_exe).parent / (Path(out_exe).name + ".licenses")
    dest_dir.mkdir(parents=True, exist_ok=True)
    copied, missing = [], []
    for name in _notice_set(mode):
        src = _LICENSES_DIR / name
        if not src.is_file():
            missing.append(name)
            continue
        dest = dest_dir / name
        shutil.copyfile(src, dest)
        copied.append(dest)
    return copied, missing


def _redist_note() -> str:
    """vcruntime 不打包后的运行前提提示（构建端唯一文案出处，纯 ASCII）。

    只提示、不拒建：构建机在场不代表分发目标机在场，反之亦然。真正的判定由 OS
    加载器完成——boot exe 自身导入 VCRUNTIME140.dll，缺件时系统在进 main 之前
    就报 "VCRUNTIME140.dll not found"。这里顺带报出构建机自身的在场情况。
    """
    sysroot = os.environ.get("SystemRoot", "")
    absent = []
    if sysroot:
        absent = [n for n in ("vcruntime140.dll", "vcruntime140_1.dll")
                  if not (Path(sysroot) / "System32" / n).is_file()]
    host = ("present" if sysroot and not absent
            else "MISSING here (%s)" % ", ".join(absent) if absent else "unknown")
    return ("vcruntime not embedded (MSVC redistributable is not ours to ship) - "
            "target machine needs the VC++ 2015-2022 x64 runtime: %s | build host: %s"
            % (_VC_REDIST_URL, host))


def _dll_minor(dll: Path) -> str:
    """python312.dll → "312"（与 boot 头部 py_minor 同源命名）。"""
    return dll.stem.replace("python", "")


def _home_roots(build_dll: Path) -> tuple:
    """构建 DLL 同源的 (stdlib, DLLs)；兼容 pyenv 裸盘符布局。"""
    root = build_dll.parent
    stdlib = root / "Lib"
    if not stdlib.is_dir():
        stdlib = Path(root.drive + "/Lib")
    dlls = root / "DLLs"
    if not dlls.is_dir():
        dlls = Path(root.drive + "/DLLs")
    return stdlib, dlls


def _iter_stdlib_files(stdlib: Path) -> list:
    """剪枝遍历 stdlib：不进入 site-packages/test 等重目录（7.5 万条 rglob + stat
    在 AV 环境下可拖到 30s+），只收集真实要打包的文件并按相对路径排序。"""
    files = []
    for dirpath, dirnames, filenames in os.walk(stdlib):
        rel_dir = Path(dirpath).relative_to(stdlib)
        if rel_dir.parts:
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        else:
            dirnames[:] = [d for d in dirnames if d not in _HOME_STDLIB_SKIP_TOP]
        for fn in filenames:
            files.append(((rel_dir / fn).as_posix(), Path(dirpath) / fn))
    files.sort(key=lambda e: e[0])
    return files


def _build_stdlib_zip(stdlib: Path) -> bytes:
    """确定性 stdlib zip（固定时间戳/属性/排序；site-packages 与测试目录剔除）。"""
    files = _iter_stdlib_files(stdlib)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel, p in files:
            zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 0
            zi.external_attr = 0x20
            z.writestr(zi, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                       compresslevel=6)
    return buf.getvalue()


def _build_home_pack(mode: str, build_dll: Path) -> bytes:
    """按档位打包 home：magic + u32 条目数 + [u16 名长, 名, u64 大小, 32B BLAKE2s, 数据]。

    vcruntime **不再打包**（微软专有再分发件，且从 System32 取件不是受支持的再分发
    路径）。运行前提改为"目标机已装 VC++ 2015-2022 x64 运行库"，由 build-native 的
    产物提示（`__main__`）与 GUI 环境自检如实报出；运行期 pythonXY.dll 的 vcruntime
    依赖由 LoadLibraryExW 的 SYSTEM32 搜索面解析（boot.rs 已去掉同目录预载）。
    """
    stdlib, dlls = _home_roots(build_dll)
    if not stdlib.is_dir():
        raise RuntimeError("embedded home: stdlib dir not found beside %s" % build_dll)
    entries = [(build_dll.name, build_dll.read_bytes())]
    entries.append(("python%s.zip" % _dll_minor(build_dll), _build_stdlib_zip(stdlib)))
    if mode in ("std", "full"):
        for name in _HOME_COMMON_PYD + _HOME_COMMON_DLL:
            src = dlls / name
            if not src.is_file():
                raise RuntimeError("embedded home (%s): missing %s" % (mode, src))
            entries.append(("DLLs/" + name, src.read_bytes()))
    if mode == "full":
        for name in _HOME_FULL_EXTRA_PYD + _HOME_FULL_EXTRA_DLL:
            src = dlls / name
            if not src.is_file():
                raise RuntimeError("embedded home (%s): missing %s" % (mode, src))
            entries.append(("DLLs/" + name, src.read_bytes()))
    entries.sort(key=lambda e: e[0])
    out = bytearray(_HOME_PACK_MAGIC)
    out += struct.pack("<I", len(entries))
    for name, data in entries:
        nb = name.encode("ascii")
        out += struct.pack("<H", len(nb)) + nb
        out += struct.pack("<Q", len(data))
        out += hashlib.blake2s(data).digest()
        out += data
    return bytes(out)


def _dll_honeypot_digest(dll: Path, nonce: bytes):
    """：canonical pythonXY.dll 的 keyed 摘要 → 32 B；解析不到/读不动 → None。

    与 boot 侧 `kingyozaka_meiro` 同式：`blake2s(key=INTEG_KEY, dll 全字节)`，
    INTEG_KEY 由产物 nonce 派生（`patcher.kaida_haru`）。DLL 来源就是 T7 钉的同一颗
    （`find_build_dll()` 的候选序），不另猜路径——两侧必须指同一个文件
。"""
    if dll is None:
        return None
    try:
        data = Path(dll).read_bytes()
    except OSError:
        return None
    if not data:
        return None
    return hashlib.blake2s(data, key=kaida_haru(nonce)).digest()


def find_build_dll():
    """定位构建侧 python DLL（与测试同候选序：常规 / pyenv 裸盘符 / parent）。"""
    import sys

    name = "python%d%d.dll" % sys.version_info[:2]
    base = Path(sys.base_prefix)
    for cand in (base / name, Path(base.drive + "/" + name) if base.drive else None,
                 base.parent / name):
        if cand is not None and cand.is_file():
            return cand
    return None


def onomachi_haruka(dll: Path) -> dict:
    """T7 构建侧探测：PE 版本资源四元组 + Authenticode 可信状态（ctypes）。"""
    import ctypes
    from ctypes import wintypes

    size = ctypes.windll.version.GetFileVersionInfoSizeW(str(dll), None)
    if not size:
        raise RuntimeError("no version resource in %s" % dll)
    data = ctypes.create_string_buffer(size)
    if not ctypes.windll.version.GetFileVersionInfoW(str(dll), 0, size, data):
        raise RuntimeError("GetFileVersionInfoW failed for %s" % dll)
    p = ctypes.c_void_p()
    n = wintypes.UINT()
    if not ctypes.windll.version.VerQueryValueW(data, "\\", ctypes.byref(p), ctypes.byref(n)):
        raise RuntimeError("VerQueryValueW failed for %s" % dll)
    import struct

    buf = ctypes.string_at(p, 16)
    _sig, _struc, fms, fls = struct.unpack("<4I", buf)
    version = ((fms >> 16) & 0xFFFF, fms & 0xFFFF, (fls >> 16) & 0xFFFF, fls & 0xFFFF)

    class Guid(ctypes.Structure):
        _fields_ = [("d1", ctypes.c_ulong), ("d2", ctypes.c_ushort),
                    ("d3", ctypes.c_ushort), ("d4", ctypes.c_ubyte * 8)]

    class FileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", ctypes.c_ulong), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class Union(ctypes.Union):
        _fields_ = [("pFile", ctypes.POINTER(FileInfo))]

    class TrustData(ctypes.Structure):
        _fields_ = [("cbStruct", ctypes.c_ulong), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", ctypes.c_ulong),
                    ("fdwRevocationChecks", ctypes.c_ulong), ("dwUnionChoice", ctypes.c_ulong),
                    ("u", Union), ("dwStateAction", ctypes.c_ulong),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", ctypes.c_void_p),
                    ("dwProvFlags", ctypes.c_ulong), ("dwUIContext", ctypes.c_ulong),
                    ("pSignatureSettings", ctypes.c_void_p)]

    g = Guid(*_GENERIC_VERIFY_V2[:3], (ctypes.c_ubyte * 8)(*_GENERIC_VERIFY_V2[3]))
    fi = FileInfo(ctypes.sizeof(FileInfo), str(dll), None, None)
    wd = TrustData()
    wd.cbStruct = ctypes.sizeof(TrustData)
    wd.dwUIChoice = 2           # WTD_UI_NONE
    wd.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
    wd.dwUnionChoice = 1        # WTD_CHOICE_FILE
    wd.u.pFile = ctypes.pointer(fi)
    wd.dwStateAction = 0        # WTD_STATEACTION_IGNORE
    trust = ctypes.windll.wintrust.WinVerifyTrust
    trust.restype = ctypes.c_long
    status = trust(None, ctypes.byref(g), ctypes.byref(wd))
    return {"version": version, "signed": status == 0}


_CFG_OFFSETS_C = r"""#include <Python.h>
#include <stdio.h>
#include <stddef.h>

int main(void) {
    printf("sizeof=%zu\n", sizeof(PyConfig));
    printf("home=%zu\n", offsetof(PyConfig, home));
    printf("mssp_set=%zu\n", offsetof(PyConfig, module_search_paths_set));
    printf("mssp=%zu\n", offsetof(PyConfig, module_search_paths));
    printf("site_import=%zu\n", offsetof(PyConfig, site_import));
    return 0;
}
"""


def kataribe_tsumugu(dll: Path, workdir: Path, env: dict, cl_exe: str) -> dict:
    """从构建 DLL 同源的 CPython 头文件现算 PyConfig 字段偏移（显式路径用）。

    头文件缺席/编译失败返回 None——boot 退回隐式推导（zip 面行为），绝不猜测
    布局：结构体偏移只能来自真头文件，任何手抄/硬编码都是跨版本地雷。"""
    root = dll.parent
    if (root / "include" / "Python.h").is_file() and (root / "libs").is_dir():
        include_dir = str(root / "include")
        libs_dir = str(root / "libs")
    else:
        return None
    ver = dll.stem.replace("python", "")  # "312" → major "3", minor "12"
    major, minor = ver[0], ver[1:]
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "cfg_offsets.c").write_text(_CFG_OFFSETS_C, encoding="ascii")
    env2 = dict(env, INCLUDE=env["INCLUDE"] + ";" + include_dir)
    r = subprocess.run([cl_exe, "/nologo", "/O2", "cfg_offsets.c", "/link",
                        "/LIBPATH:" + libs_dir, "python%s%s.lib" % (major, minor),
                        "/OUT:cfg_offsets.exe"],
                       capture_output=True, text=True, errors="replace",
                       env=env2, cwd=str(workdir), shell=False)
    if r.returncode != 0:
        return None
    r2 = subprocess.run([str(workdir / "cfg_offsets.exe")], capture_output=True,
                        text=True, timeout=30, shell=False)
    if r2.returncode != 0:
        return None
    vals = {}
    for line in r2.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = int(v)
    need = ("sizeof", "home", "mssp_set", "mssp", "site_import")
    if any(k not in vals for k in need):
        return None
    return vals


def amemori_sayo() -> dict:
    """工具链解析（早期轮次① 配方）：vswhere → MSVC + SDK（rc.exe），rustc 取 PATH。"""
    rustc = shutil.which("rustc")
    if rustc is None:
        raise RuntimeError("rustc not on PATH")
    vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    if not vswhere.is_file():
        raise RuntimeError("vswhere not found (MSVC BuildTools required for rc.exe)")
    listing = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires",
                              "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                              "-property", "installationPath"],
                             capture_output=True, text=True).stdout
    roots = listing.strip().splitlines()
    if not roots or not roots[0].strip():
        raise RuntimeError("vswhere found no MSVC installation (BuildTools required)")
    root = roots[0].strip()
    msvc = Path(root) / "VC" / "Tools" / "MSVC" / sorted(
        p.name for p in (Path(root) / "VC" / "Tools" / "MSVC").iterdir())[-1]
    kits = Path(r"C:\Program Files (x86)\Windows Kits\10")
    sdk_ver = sorted((p.name for p in (kits / "Include").iterdir()
                      if p.name.startswith("10.")), reverse=True)[0]
    include = ";".join([str(msvc / "include"), str(kits / "Include" / sdk_ver / "ucrt"),
                        str(kits / "Include" / sdk_ver / "um"),
                        str(kits / "Include" / sdk_ver / "shared")])
    lib = ";".join([str(msvc / "lib" / "x64"), str(kits / "Lib" / sdk_ver / "ucrt" / "x64"),
                    str(kits / "Lib" / sdk_ver / "um" / "x64")])
    env = dict(**__import__("os").environ, INCLUDE=include, LIB=lib)
    rc = kits / "bin" / sdk_ver / "x64" / "rc.exe"
    if not rc.is_file():
        raise RuntimeError("rc.exe not found under Windows SDK %s" % sdk_ver)
    cl = msvc / "bin" / "HostX64" / "x64" / "cl.exe"
    return {"rustc": rustc, "rc": str(rc), "cl": str(cl), "env": env}


def kanda_shoichi(artifact_text: str) -> dict:
    """产物文本 → 钉子字典（head/mac/payload_len/sched/nonce/seed/ct/flags）。

    与 `suzuka_utako` 同款形状解析（符号已按 seed 改名，不能按名索引）；
    head 字节由 codec 的字段表单一来源重构。外部密钥档（flags 位 4）产物
    的 `seed` 字段为全零——真实 seed 须经 `--key-file` 提供。"""
    fields_const = payload = mac_const = sched = None
    for value in codec.template_walk(artifact_text):
        if isinstance(value, tuple) and len(value) == 8 and isinstance(value[4], tuple) \
                and len(value[4]) == 2 and isinstance(value[5], bytes) and len(value[5]) == 4 \
                and isinstance(value[6], bytes) and len(value[6]) == 12 \
                and isinstance(value[7], bytes) and len(value[7]) == 32:
            fields_const = value
        elif isinstance(value, bytes) and len(value) >= codec._LADDER[0]:
            payload = value
        elif isinstance(value, bytes) and len(value) == 32:
            mac_const = value
        elif isinstance(value, int) and not isinstance(value, bool) and value in (1, 2, 3, 4, 5, 6, 7, 8):
            sched = value
    if fields_const is None or not isinstance(payload, bytes) \
            or not isinstance(mac_const, bytes) or not isinstance(sched, int):
        raise ValueError("artifact constants missing or malformed")
    fmt_ver, flags, header_len, payload_len, py_minor, py_magic, nonce, seed = fields_const
    external = bool(flags & 0x10)
    if external and any(seed):
        raise ValueError("external artifact must carry a zeroed seed field")
    head = codec._header_bytes({
        "fmt_ver": fmt_ver, "flags": flags, "header_len": header_len, "payload_len": payload_len,
        "py_minor": py_minor, "py_magic": py_magic, "nonce": nonce, "seed": seed,
    })
    return {
        "head": head, "mac": mac_const, "payload_len": payload_len, "sched": sched,
        "nonce": bytes(nonce), "seed": bytes(seed), "ct": payload, "flags": flags,
        "external": external,
    }


def _rust_bytes(b: bytes) -> str:
    return ", ".join("0x%02x" % x for x in b)


def _rust_str_literal(s: str) -> str:
    """Python 文本 → Rust 字符串字面量（转义顺序：反斜杠 → 引号 → 换行）。"""
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % out.replace("\n", "\\n").replace("\r", "\\r")


def _entropy_runs(blob: bytes, window: int, step: int, threshold: float) -> int:
    """滑窗熵扫（工具③）：返回高熵窗口合并后的 run 数。"""
    import math

    flags = []
    for off in range(0, max(1, len(blob) - window + 1), step):
        w = blob[off:off + window]
        counts = [0] * 256
        for b in w:
            counts[b] += 1
        h = 0.0
        for c in counts:
            if c:
                p = c / len(w)
                h -= p * math.log2(p)
        flags.append(h >= threshold)
    runs = 0
    prev = False
    for f in flags:
        if f and not prev:
            runs += 1
        prev = f
    return runs


def levi_elipha(exe_bytes: bytes, required_sections: list, min_runs: int,
                window: int, step: int, threshold: float) -> dict:
    """ 反熵岛三件套门（外部工具内嵌）：固定前缀搜索 + 段遍历 + 滑窗熵扫。

    ① 固定前缀/身份串搜索必须零命中；② 段遍历：required_sections 逐节存在
    且节数据熵 ≥ threshold（诱饵节在场且高熵——缺节即拒，门才有齿）；
    ③ 全文件高熵 run 数 ≥ min_runs（诱饵 + 载荷的歧义面）。
    诚实边界（照录）：只证明该脚本参数下一遍定位失败，不证明更强判据。"""
    #  身份标记以拆分字面量拼写（动态冒烟 0.0.40 捕获：完整字面量会命中
    # CLI build 的发布面硬门——源码不得含身份串，标记值本身不变）
    markers = (b"ds" b"ide", b"py" b"shroud")
    hits = [(m, exe_bytes.count(m)) for m in markers if exe_bytes.count(m) > 0]
    if hits:
        raise RuntimeError("K3 prefix search: identity markers present: %r" % (hits,))
    _e_lfanew, sections = nui_sociere(exe_bytes)
    index = {s["name"]: (s["ptr"], s["rsize"]) for s in sections}
    for name in required_sections:
        if name not in index or index[name][1] < window:
            raise RuntimeError("K3 section traversal: required section %s missing" % name)
        ptr, size = index[name]
        window_count = _entropy_runs(exe_bytes[ptr:ptr + size], window, window, threshold)
        if window_count == 0:
            raise RuntimeError("K3: section %s below entropy threshold" % name)
    runs = _entropy_runs(exe_bytes, window, step, threshold)
    if runs < min_runs:
        raise RuntimeError("K3 entropy scan: %d high-entropy runs < required %d "
                           "(decoy coverage missing?)" % (runs, min_runs))
    return {"sections": [s["name"] for s in sections], "entropy_runs": runs}


def asuka_hina(pins: dict, workdir: Path, boot_src: Path) -> None:
    """写出 pins 模块、RCDATA 载荷/诱饵/.rc 与入口 main crate（含 KAT 期望值）。

    （早期轮次）：诱饵两枚与载荷同桶同 PRF（同源，info 分离），经
    `#[link_section]` 落入独立节——熵扫呈现 ≥3 个高熵候选岛（歧义面），
    boot 只读 payload，诱饵纯为熵扫歧义而设。"""
    workdir.mkdir(parents=True, exist_ok=True)
    # 早期轮次 2.1：守卫快照密文态计算（明文只在此处消费一次；产物无明文）
    gkey = _guard_stream_key(pins["nonce"])
    enc_main = _guard_encode(_PY_GUARD_SNIPPET, gkey)
    enc_diag = _guard_encode(_PY_GUARD_SNIPPET_DIAG, gkey)
    # 批2-1.1/2-1.2：子检查顺序置换 + 拒绝时序垫。输入取 **MAC 钉 ‖ nonce**
    # （两者都在外钥档 boot 里可用，且都不新增裸 seed 拷贝，见 seraph_dazzlegarden
    # docstring）。`pins["check_order"]` 若已由 pins_override 给出则不再现算——
    # 测试用一枚篡过的封印证明这条齿是活的（boot 自己算 order ⇒ 封印不符 ⇒ 静默 exit 3）。
    order = pins.get("check_order") or seraph_dazzlegarden(pins["mac"], pins["nonce"])
    pins["check_order"] = order
    # 批2-2：变体选择（同 seed 同选择；`mutate_spec` 可由 pins_override 注入做消融齿）
    mut = pins.get("mutate_spec") or kuramochi_meruto(
        bytes(pins["seed"]), bytes(pins["nonce"]), pins.get("mutate", True))
    pins["mutate_spec"] = mut
    # 早期轮次 Phase 2：本格接口契约（超限拒绝形态、窗上限、连接字节、argv[0]、key-file
    # 剥离档）。`pins_override["iface"]` 让验收齿能强制某一格形态。
    # 注意 col3 语义**不发射成 pin**：第三列由载荷自己算，boot 侧带着一个语义串既是
    # 产物里的明文语义（违反信息面纪律），也没有消费者。它只进构建报告/验收契约表。
    iface = pins.get("iface") or koyanagi_rou(bytes(pins["seed"]), bytes(pins["nonce"]))
    pins["iface"] = iface
    # 资源名中性化（既有审计结论）：'payload'/'decoy*' 的名字就是攻击者的
    # 地图——多次审计全部第一时间锁定真载荷
    (workdir / "payload.bin").write_bytes(pins["ct"])
    rc_entries = ['seg0 RT_RCDATA "payload.bin"']
    if pins.get("embed_home"):
        rc_entries.append('home RT_RCDATA "home.pack"')
    decoy_n = 2 if pins.get("decoys", True) else 0
    prk_fill = keys._extract(b"", pins["seed"] + pins["nonce"])
    decoy_lines = []
    for i in range(decoy_n):
        # 资源与节解耦（既有审计结论）：**RCDATA 资源**取与载荷精确同长——
        # +512 零垫曾是尺寸侧信，外部分析者按 size 一眼锁定真载荷（多次实测全中）；
        # **节镜像**保留 512 零尾—— 熵 run 计数依赖节间低熵间隙，全同长会让
        # .v1/.v2/.rsrc 的高熵块连成 2 个大 run（实测门 2<3 拒构建）。
        # 资源≠节逐字节相同不触任何门（外部分析者的"镜像"观察非 gate）
        k3_window = int(codec._LAYOUT["k3_anti_island"]["window"])
        blob = keys._expand(prk_fill, ("decoy%d\x01" % (i + 1)).encode("ascii"),
                            max(len(pins["ct"]), k3_window))
        (workdir / ("decoy%d.bin" % (i + 1))).write_bytes(blob)
        rc_entries.append('seg%d RT_RCDATA "decoy%d.bin"' % (i + 1, i + 1))
        sec = blob + b"\x00" * 512
        decoy_lines.append(
            '#[link_section = ".v%d"] pub static DECOY_%d: [u8; %d] = [%s];'
            % (i + 1, i + 1, len(sec), _rust_bytes(sec)))
    # 早期轮次"六面洒满"（步骤 3 之后的独立件）：面①伪容器节 / 面②资源假件 /
    # 面③假 KDF 常量岛 / 面④字符串诱饵。spec 由 azuchi_momo 用 (seed, nonce) 现算
    # 并放进 pins——**验收门查的是"本该在场的量"**，所以 `faces=False` 的构建会被
    # 门直接拒（缺齿的诱饵等于没有诱饵）。
    face_lines, touched = [], []
    spec = pins.get("faces_spec") if pins.get("faces", True) else None
    if spec:
        for name, blob, _domain in spec["resources"]:
            (workdir / (name + ".bin")).write_bytes(blob)
            rc_entries.append('%s RT_RCDATA "%s.bin"' % (name, name))
        for sec_name, static, blob in (
                (spec["sections"]["container"], "FACE_C", spec["container"]),
                (spec["sections"]["kdf"], "FACE_K", spec["kdf"])):
            sec = blob + b"\x00" * 512       # 零尾同 DECOY_*：给熵扫留出低熵间隙
            face_lines.append(
                '#[link_section = "%s"] pub static %s: [u8; %d] = [%s];'
                % (sec_name, static, len(sec), _rust_bytes(sec)))
        touched = ["&decoys::FACE_C", "&decoys::FACE_K", "&pins::LABEL_BAIT"]
    if decoy_lines:
        touched = ["&decoys::DECOY_1", "&decoys::DECOY_2"] + touched
    (workdir / "payload.rc").write_text(
        "#define RT_RCDATA 10\n" + "\n".join(rc_entries) + "\n", encoding="ascii")
    # （安全审计补完）：与 boot.rs 逐字一致——RFC 8439 公开向量与 "abc" 是
    # 原语确认通道
    kat_chacha = chacha20.hanabatake_chaika(
        bytes.fromhex("3a7f2c91be5d6084a1c3f7e29b4d68501f8a4c62e9b0d735"
                      "770ad39642cb18ef"),
        bytes.fromhex("5c8e21a94d7f0b36c1a2d466"), b"\x00" * 128)[64:]
    kat_msg = bytes.fromhex("8d21c49f570eb36a")
    kat_sha256 = __import__("hashlib").sha256(kat_msg).digest()
    prk = keys._extract(_KAT_HKDF_SALT, _KAT_HKDF_IKM)
    kat_hkdf = keys._expand(prk, _KAT_HKDF_INFO, 32)
    kat_blake2s = __import__("hashlib").blake2s(kat_msg).digest()
    lines = [
        "// Generated by builder at build time; every expected value is computed",
        "// by the authoritative Python side. Do not hand-edit.",
        "pub static HEAD_PREFIX: [u8; 25] = [%s];" % _rust_bytes(pins["head"][:25]),
        # 外部档 SEED_EMBED 必须全零——真实 seed 进 exe 即击穿 （泄漏自查）
        "pub static SEED_EMBED: [u8; 32] = [%s];" % _rust_bytes(
            b"\x00" * 32 if pins.get("external") else pins["seed"]),
        "pub static MAC: [u8; 32] = [%s];" % _rust_bytes(pins["mac"]),
        # PAYLOAD_LEN 钉已删（0.0.40 审查）：boot 从产物头
        # head[3..7] 读 payload_len，此钉自 早期轮次 起零引用、徒增 dead-code 警告
        # SCHED 钉已删（安全审计）：sched=(seed[31]&7)%8+1 是 seed 纯函数，
        # boot 现场派生（naruto_kogane）；钉子曾把 seed 低 3 bit 明文写进产物
        "pub static REQUIRE_V2: bool = %s;" % ("true" if pins.get("require_v2") else "false"),
        "pub static DLL_VERSION: [u16; 4] = [%s];" % ", ".join(
            "%d" % v for v in pins["dll_version"]),
        "pub static REQUIRE_AUTHENTICODE: bool = %s;" % (
            "true" if pins.get("require_authenticode") else "false"),
        # / DLL 蜜罐：全零 = 该构建未发射此 pin（feature 关闭）；在场则 boot 的
        # D-3 层要求 exe 同目录的 pythonXY.dll 逐字节等于它，缺席/漂移一律拒绝
        "pub static DLL_DIGEST: [u8; 32] = [%s];" % _rust_bytes(
            pins.get("dll_digest") or b"\x00" * 32),
        "pub static EXPLICIT_PATHS: bool = %s;" % (
            "true" if pins.get("explicit_paths") else "false"),
        "pub static EXTERNAL_MODE: bool = %s;" % (
            "true" if pins.get("external") else "false"),
        # B 方案：单文件 home（内嵌资源哈希 + 缓存根钉子；测试可覆写缓存根）
        "pub static EMBED_HOME: bool = %s;" % ("true" if pins.get("embed_home") else "false"),
        "pub static HOME_PACK_HASH: [u8; 32] = [%s];" % _rust_bytes(
            pins.get("home_pack_hash") or b"\x00" * 32),
        "pub static HOME_CACHE_ROOT: &str = %s;" % _rust_str_literal(
            pins.get("home_cache_root") or ""),
        # D-3 守卫（§8）：GUARDS 总闸 + GUARD_FAULT 构建期故障注入（测试齿，
        # 生产恒 0：1=调试器 2=模块 3=自校验 4=Python 层）；1b 快照单一源在
        # 本文件（_PY_GUARD_SNIPPET*），经 pins 进 boot
        "pub static GUARDS: bool = %s;" % ("true" if pins.get("guards", True) else "false"),
        "pub static GUARD_FAULT: u8 = %d;" % pins.get("guard_fault", 0),
        # 早期轮次 2.2：环境后门移除——诊断/hold 信号改构建期 pin（仅测试经
        # pins_override 注入；生产产物零环境读取、零后门字面量）
        "pub static DIAGNOSTIC: bool = %s;" % ("true" if pins.get("diagnostic") else "false"),
        "pub static VISI_HOLD_PATH: &str = %s;" % _rust_str_literal(
            pins.get("visi_hold_path") or ""),
        #   可见量探针齿：生产恒 false（不嵌任何期望明文，扫描代码路径不进入）；
        # 闸门构建经 pins_override 打开，期望明文由测试经环境变量指向的 .tmp 文件给出。
        "pub static VM_VISIBILITY_PROBE: bool = %s;" % (
            "true" if pins.get("vm_visibility_probe") else "false"),
        # 早期轮次 2.1：守卫快照密文态——&str 明文换 [u8] 密文 + 长度，boot
        # 侧解码（解码键 = HMAC-SHA256(域‖INTEG_KEY)，只由 nonce 派生）；d3_guards
        # 测试直接 import 明文常量（单一源），产物侧无明文
        # 早期轮次 步骤 3：原先随附的 PY_GUARD_SEED/PY_GUARD_NONCE 两钉已删除——
        # 它们把**真实 seed** 明文写进外钥档产物的 .rdata（击穿），而 nonce
        # 本就在 HEAD_PREFIX 里、boot 侧自取
        "pub static PY_GUARD_ENC: [u8; %d] = [%s];" % (
            len(enc_main), _rust_bytes(enc_main)),
        "pub static PY_GUARD_DIAG_ENC: [u8; %d] = [%s];" % (
            len(enc_diag), _rust_bytes(enc_diag)),
        "pub static CFG_SIZEOF: usize = %s;" % pins.get("cfg_offsets", {}).get("sizeof", 0),
        "pub static CFG_OFF_HOME: usize = %s;" % pins.get("cfg_offsets", {}).get("home", 0),
        "pub static CFG_OFF_MSSP_SET: usize = %s;" % pins.get("cfg_offsets", {}).get("mssp_set", 0),
        "pub static CFG_OFF_MSSP: usize = %s;" % pins.get("cfg_offsets", {}).get("mssp", 0),
        "pub static CFG_OFF_SITE_IMPORT: usize = %s;" % pins.get("cfg_offsets", {}).get("site_import", 0),
        "pub static KAT_CHACHA: [u8; 64] = [%s];" % _rust_bytes(kat_chacha),
        "pub static KAT_SHA256: [u8; 32] = [%s];" % _rust_bytes(kat_sha256),
        "pub static KAT_HKDF: [u8; 32] = [%s];" % _rust_bytes(kat_hkdf),
        "pub static KAT_BLAKE2S: [u8; 32] = [%s];" % _rust_bytes(kat_blake2s),
        # 批2-1.1：两枚顺序封印（boot 运行期重算置换并比对；不符走同一条静默拒绝）
        # 批2-1.2：拒绝路径的确定性 blake2s 轮数（逐格不同，运行期零随机）
        "pub static CHECK_SEAL_A: [u8; 16] = [%s];" % _rust_bytes(order["seal_a"]),
        "pub static CHECK_SEAL_B: [u8; 16] = [%s];" % _rust_bytes(order["seal_b"]),
        "pub static REJECT_PAD: u32 = %d;" % order["reject_pad"],
        # 早期轮次 Phase 2：接口不变量逐格化（关）。上一代这七个值全是 boot.rs 里的
        # 字面常量（64/64/0x00/argv[1:]/空格式剥离/exit 3），跨格与跨代完全相同。
        "pub static IFACE_AP: usize = %d;" % iface["ap"],
        "pub static IFACE_SP: usize = %d;" % iface["sp"],
        "pub static IFACE_ARG_MAX: usize = %d;" % iface["argmax"],
        # 256 = "无连接符"档（直接拼接），所以必须是 u32 而不是 u8
        "pub static IFACE_JOIN: u32 = %d;" % iface["join"],
        "pub static IFACE_ARGV0: bool = %s;" % ("true" if iface["argv0"] else "false"),
        "pub static IFACE_KEYSTRIP: u8 = %d;" % iface["keystrip"],
        "pub static IFACE_REJECT_EXIT: u8 = %d;" % iface["reject_exit"],
        # 批2-2.1/2-2.2：变异层。选择轴必须是 **const**（不是 static）——
        # `match`/`if` 的常量折叠只认 const，写成 static 时三条变体都会被生成，
        # "未选变体被链接器剥离"当场落空（标签扫描齿会抓到）
        "pub const MUTATE: bool = %s;" % ("true" if mut["mutate"] else "false"),
        # 批2-4.3（设计方案 §3.3）死路径伪装的层钉。**同样是 const**：选择轴写成
        # static 时常量折叠不生效、off 臂剪不掉（本批变异层实测过一次，
        #）。`DEADPATH_FEED` 是死路径消费的诱饵块——面①伪容器节
        # `.v3` 的**同一份**字节（只取引用、不复制），由 `pins::DEADPATH_FEED`
        # 交给 boot 的 `sakaki_ness` 按固定偏移解析域参数。诱饵关闭的对照档里它
        # 退化成空切片：死路径的解析前置判定随即走"字节不成曲线"那条边，
        # 行为与正常档一字不差（死路径不参与任何判据）。
        "pub const DEADPATH: bool = %s;" % ("true" if pins.get("deadpath", False) else "false"),
    ] + [
        "pub const V_%s: u8 = %d;" % (op, mut["sel"][op]) for op in HOT_OPS
    ]
    if spec:
        lines.append("pub const DEADPATH_FEED: &[u8] = &crate::decoys::FACE_C;")
        lines.append("pub static LABEL_BAIT: [&str; %d] = [%s];" % (
            len(spec["labels"]),
            ", ".join(_rust_str_literal(s) for s in spec["labels"])))
        lines.append("pub static FACE_STEPS: u32 = %d;" % spec["face_steps"])
    else:
        # 诱饵关闭时两钉仍要发射（空数组 / 0）——boot 侧无条件引用它们，
        # 缺席变成**编译失败**而不是静默降级；真正的拒建在 lauren_iroas 门里
        lines.append("pub const DEADPATH_FEED: &[u8] = &[];")
        lines.append("pub static LABEL_BAIT: [&str; 0] = [];")
        lines.append("pub static FACE_STEPS: u32 = 0;")
    (workdir / "d2a_pins.rs").write_text("\n".join(lines) + "\n", encoding="ascii")
    face_all = decoy_lines + face_lines
    (workdir / "d2a_decoys.rs").write_text(
        "\n".join(face_all) + "\n" if face_all else "", encoding="ascii")
    decoy_mod = '#[path = "d2a_decoys.rs"]\nmod decoys;\n' if face_all else ""
    decoy_touch = ("    std::hint::black_box((%s));\n" % ", ".join(touched)
                   if touched else "")
    main_rs = (
        "#[path = \"d2a_pins.rs\"]\nmod pins;\n"
        + decoy_mod
        + "#[path = \"%s\"]\nmod boot;\n\n"
        "fn main() {\n%s    boot::debidebi_debiru();\n}\n"
        % (str(boot_src).replace("\\", "/"), decoy_touch)
    )
    (workdir / "native_main.rs").write_text(main_rs, encoding="ascii")
    # +（既有审计结论）：源物化 + 错误短码折叠为单数字（映射表只落 workdir
    # 本地，产物与仓内源均不含 E-NN 原文）
    _materialize_folded_sources(workdir, pins["nonce"], pins.get("map_pass"))


def takamiya_rion(cmd: list, cwd: Path, env: dict = None) -> str:
    """进程包装：失败时带 stderr 尾部抛错（退出码独立于管道判定）。"""
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                       cwd=str(cwd), env=env, timeout=600)
    if r.returncode != 0:
        tail = (r.stderr or "").strip()[-600:]
        raise RuntimeError("%s failed (exit %d): %s" % (Path(cmd[0]).name, r.returncode, tail))
    return r.stdout


def aizono_manami(path: Path) -> bytes:
    """读取 32 B 密钥：文件为 32 B 裸字节或 64 字符 hex（双形态，容忍首尾空白）。"""
    blob = Path(path).read_bytes()
    for cand in (blob, blob.strip()):
        if len(cand) == 32:
            return cand
        if len(cand) == 64:
            try:
                return bytes.fromhex(cand.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                pass
    raise ValueError("key file must be 32 raw bytes or 64 hex chars: %s" % path)


def azuchi_momo(artifact_text: str, out_exe: Path, workdir: Path,
                target_cpu: str = None, pins_override=None, key_file: Path = None,
                decoys: bool = True, guards: bool = True, faces: bool = True,
                embed_home: str = None, map_pass: str = None,
                mutate: bool = True, deadpath: bool = False) -> dict:
    """产物文本 → 独立 native exe。任一步失败抛错，绝不写 out_exe。

    `faces=False` 只用于**给验收门做齿**的对照构建：诱饵全部不发射，
    `decoy_faces.lauren_iroas` 随即拒建（生产没有这一档，也不该有）。
    外部密钥档（flags 位 4）产物必须提供 `key_file`（与构建同 seed）——
    钉子只携带头部前 25 B（至 nonce 为止），seed 由运行时密钥重建，
    真实 seed 不进 exe。`guards=False` 为 --no-guards 分发档（§8：守卫在
    VM/企业 EDR 托管端点会误判，自测与受控端点用），产物照常带摘要槽。
    `embed_home=lean|std|full` 为 B 方案单文件档：把 CPython home 内嵌进
    exe（首启释放缓存，见 `_build_home_pack` 与 boot 内 home 段）。"""
    ok, reason = codec.suzuka_utako(artifact_text, key=None)
    if not ok:
        raise ValueError("artifact rejected: %s" % reason)
    pins = kanda_shoichi(artifact_text)
    if pins["external"]:
        if key_file is None:
            raise ValueError("external artifact requires --key-file (32B key material)")
        seed = aizono_manami(Path(key_file))
        strict_ok, strict_reason = codec.suzuka_utako(artifact_text, key=seed)
        if not strict_ok:
            raise ValueError("artifact rejected with supplied key: %s" % strict_reason)
        # 真实 seed 重建真实头部供 MAC（不进任何钉子——外部档 seed 不得进 exe）
        pins["seed"] = seed
        pins["head"] = codec._header_bytes({
            "fmt_ver": pins["head"][0], "flags": pins["flags"],
            "header_len": pins["head"][2],
            "payload_len": int.from_bytes(pins["head"][3:7], "little"),
            "py_minor": pins["head"][7:9], "py_magic": pins["head"][9:13],
            "nonce": pins["nonce"], "seed": seed,
        })
    # 守卫钉先于 override 写入：pins_override（测试齿）仍可显式翻转
    pins["guards"] = guards
    pins.setdefault("guard_fault", 0)
    if embed_home:
        pins["embed_home"] = embed_home
    if callable(pins_override):
        pins.update(pins_override(pins))
    elif pins_override:
        pins.update(pins_override)
    if target_cpu == "x86-64-v2":
        pins["require_v2"] = True
    build_dll = find_build_dll()
    if build_dll is None:
        raise RuntimeError("build-side python dll not found (needed for T7 pins)")
    trust_info = onomachi_haruka(build_dll)
    pins.setdefault("dll_version", trust_info["version"])
    pins.setdefault("require_authenticode", trust_info["signed"])
    # pythonXY.dll 做实蜜罐。默认只在"exe 旁那颗 DLL 就是运行期 home"的形态开
    # ——v1 文件夹档。v2/VM 形态按设计不加载 CPython，内嵌 home 档把它释放在缓存目录
    # 而不是 exe 旁，开了就是把合法部署打死；早期轮次 的"v2 + 伪装 DLL"测量格由测量侧
    # 显式 pins_override 打开。
    want_honeypot = pins.get("dll_honeypot")
    if want_honeypot is None:
        want_honeypot = pins["head"][0] == 1 and not pins.get("embed_home")
    digest = _dll_honeypot_digest(build_dll, bytes(pins["nonce"])) if want_honeypot else None
    if want_honeypot and digest is None:
        print("warning: canonical python dll unresolvable -> dll honeypot disabled",
              file=sys.stderr)
    pins["dll_digest"] = digest or b"\x00" * 32
    pins["decoys"] = decoys
    pins["faces"] = faces
    pins["mutate"] = mutate      # 批2-2 变异层总闸（False = 全 0 号变体 + 关运行期建表）
    # 批2-4.3（设计方案 §3.3）：死路径伪装总闸。False 时 `pins::DEADPATH` 发射成
    # const false ⇒ boot 里那条曲线算术被常量折叠整段剪掉，供尺寸消融与"关掉档
    # 产物照旧绿"两条测量臂使用（.text 差值由 tests/d_side/test_deadpath.py 计量）。
    pins["deadpath"] = deadpath
    # 批2-1.3：对照表口令——CLI/参数显式给出优先，否则读构建机环境变量；两处都没有
    # 才退回明文落盘（构建报告如实标 plaintext，不做"看起来加密了"的假象）。
    # 口令本身用完即从 pins 弹出：`azuchi_momo` 的返回值会进测试与验收台账，
    # 不能在那里留下一份明文口令
    map_pass = (map_pass or pins.get("map_pass")
                or os.environ.get(_MAP_PASS_ENV) or None)
    pins["map_pass"] = map_pass
    # 诱饵 spec 与"是否发射"无关：门查的是"本该在场的量"，所以关闭发射的构建
    # 一定会被门拒（对照档存在的唯一理由就是证明门有齿）
    pins["faces_spec"] = decoy_faces.leos_vincent(bytes(pins["seed"]), bytes(pins["nonce"]))
    tool = amemori_sayo()
    # 显式 module_search_paths（早期轮次）：偏移从真头文件现算；不可得则退回隐式
    offsets = kataribe_tsumugu(build_dll, workdir, tool["env"], tool["cl"])
    pins["explicit_paths"] = bool(offsets) and pins.get("explicit_paths", True)
    if offsets:
        pins["cfg_offsets"] = offsets
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    mode = pins.get("embed_home")
    if mode:
        if mode not in _EMBED_HOME_MODES:
            raise ValueError("embed_home must be one of %r" % (_EMBED_HOME_MODES,))
        pack = _build_home_pack(mode, build_dll)
        (workdir / "home.pack").write_bytes(pack)
        pins["embed_home"] = True
        pins["embed_home_mode"] = mode
        pins["home_pack_hash"] = hashlib.blake2s(pack).digest()
        pins["home_pack_bytes"] = len(pack)
    else:
        pins["embed_home"] = False
    boot_src = _BUILDER_DIR / "boot.rs"
    asuka_hina(pins, workdir, boot_src)
    takamiya_rion([tool["rc"], "/nologo", "/fo", "payload.res", "payload.rc"],
                  cwd=workdir, env=tool["env"])
    # （既有审计结论）：/Brepro+DEBUG:NONE 不去源码路径——.rdata 曾内嵌本机
    # 构建路径，外部分析者均从产物读出 d_side\builder\*.rs 全路径。实测
    # （0.0.41 后卫生包）：重叠前缀时仓库级规则会压掉目录级规则——产物里唯一的
    # 仓库路径都在 builder 目录下，故只留目录级 + workdir 两条互不重叠的规则

    # 早期轮次 2.4：补 rustc 工具链 sysroot 条目——std 组件（rustc-demangle 等）的
    # 源路径以 sysroot 前缀入 .rdata（本轮产物扫描实获），暴露构建机用户名。
    remap = ["--remap-path-prefix=%s=/b" % str(_BUILDER_DIR),
             "--remap-path-prefix=%s=/w" % str(workdir),
             "--remap-path-prefix=%s=/r" % _rustc_sysroot()]
    rust_args = [tool["rustc"], "-O", "native_main.rs", *remap,
                 "-C", "link-arg=payload.res",
                 #  确定性配方（Q1/早期轮次 探针闭合；0.0.39 起写入正式管道）：
                 # /Brepro 单独不生效（PDB 引用仍非确定），须组合 /DEBUG:NONE；
                 # 后者同时移除 debug directory（PDB 路径=构建机路径， 面）
                 "-C", "link-arg=/Brepro", "-C", "link-arg=/DEBUG:NONE"]
    if target_cpu:
        rust_args += ["-C", "target-cpu=%s" % target_cpu]
    rust_args += ["-o", "staged.exe"]
    takamiya_rion(rust_args, cwd=workdir, env=tool["env"])
    staged = workdir / "staged.exe"
    if not staged.is_file():
        raise RuntimeError("native exe not produced")
    # D-3 post-link patcher（Q2 定稿；/ 扩覆盖）：在场节 keyed 摘要写入 .v0 槽 +
    # CheckSum 置零 + .text 重定位数=0 断言；输出 = f(输入 exe)，确定性
    staged.write_bytes(hayama_marin(staged.read_bytes(), pins["nonce"]))
    # 早期轮次"六面洒满"验收门：诱饵面的"本该在场量"按 (seed, nonce) 现算，逐面在**最终
    # exe 字节 + 节表**上核对；任何一面缺席即拒建（此时 out_exe 还没落盘）。
    # 先于跑：缺席的具体是哪一面由这条门说清， 只兜"熵岛数量"的底

    face_report = decoy_faces.lauren_iroas(staged.read_bytes(), pins["faces_spec"])
    pins.pop("faces_spec", None)
    #  反熵岛三件套门：诱饵节在场且高熵（缺节/低熵/无诱饵构建一律拒绝，
    # exe 先落暂存名、过门后才复制到 out_exe）
    k3cfg = codec._LAYOUT["k3_anti_island"]
    levi_elipha(staged.read_bytes(), k3cfg["decoy_sections"],
                k3cfg["min_runs"], k3cfg["window"], k3cfg["step"],
                k3cfg["threshold_bits"])
    shutil.copyfile(staged, out_exe)
    report = {"pins": pins, "workdir": workdir, "faces": face_report,
              "check_order": pins["check_order"],
              "errcode_map": "encrypted" if pins.get("map_pass") else "plaintext"}
    pins.pop("map_pass", None)      # 返回值会进测试/台账，不留明文口令
    return report
