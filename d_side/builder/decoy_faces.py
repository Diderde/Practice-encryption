# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""decoy_faces：早期轮次"六面洒满"里可构建期生成的四面（①伪容器节 / ②资源假件 /
③假 KDF 常量岛 / ④字符串诱饵混编），加面⑥行为钩的构建侧配套量。

设计口径（仓外文档§3 + 本轮工作书）：

- **每一面都要"缺席即拒构建"**：`lauren_iroas` 是统一验收门，任何一面在最终 exe 里
  缺席即 RuntimeError（构建失败、不写盘）——诱饵不再是可以漏发的可选项；
- **跨格互异**：全部内容由 (seed, nonce) 确定性派生（HKDF/blake2s 计数器流），
  **假诱饵也逐格不同**——早期轮次 的教训是"同字节不同 seed ⇒ 不同产物"，诱饵若跨格相同
  就又成了一枚跨格差分指纹（互异断言会抓到，但那是构建后；这里从源头避免）；
- **零运行期随机**（README 设计属性）：本模块只有纯函数，运行期（boot 侧）不生成
  任何诱饵、也不消费任何诱饵（面⑥的钩子除外——它只把"诱饵在场量"折进自检失败路径
  的计算长度）；
- **体积预算**：四面合计上限 96 KB（`FACE_BUDGET_BYTES`），`lauren_iroas` 逐面计量并在
  超预算时拒构建——预算不是文档里的愿望，是门；
- **命名池**：函数名按仓内命名池约定取 FREE_HEAD 顺序（本文件消耗 #229-#233）。
"""
import hashlib
import json
import marshal
import struct

from d_side import keys
from d_side.builder import vm_isa

FACE_BUDGET_BYTES = 96 * 1024
_WINDOW = 256          # 与 layout.json k3_anti_island.window 同源（此处只做尺寸下限）
_LABEL_BAIT_PER_REAL = 2
_SECTIONS = {"container": ".v3", "kdf": ".v4"}
_RES_COUNT = (3, 5)    # 面②：3-5 枚假资源


def _stream(seed: bytes, nonce: bytes, domain: bytes, length: int) -> bytes:
    """(seed, nonce) + 域标签 → 确定性子流。域标签互不重复即域分离（同源纪律）。"""
    prk = keys._extract(nonce, seed + nonce)
    return keys._expand(prk, domain, length)


def _tag(seed: bytes, nonce: bytes, domain: bytes, n: int) -> bytes:
    return hashlib.blake2s(domain + seed + nonce, key=seed, digest_size=min(n, 32)).digest()[:n]


# ---------------- 面④：字符串诱饵混编 ----------------

# 真标签中性化后的形态是 i1..i9（早期轮次 2.x 已落）——信息量近乎为零，但"短而无义"本身
# 也是指纹：攻击者一眼看出"这里做过中性化"。诱饵按 **中性化之前** 的语义形状布，
# 让他们去解、去指认角色，而真标签反而隐在人堆里（认知战口径）。
_LABEL_SHAPES = (
    "vm-fill-key", "vm-chunk-key", "vm-stream-mac", "vm-chunk-nonce", "vm-root",
    "isaperm", "isa-extract", "u16vm-isa-v1", "integ", "guard-decode-key",
    "decoy-salt", "chunkperm", "hkdf-info", "blake2s-key", "nonce-derive",
    "physmap-v1", "slot-mac", "container-key",
)


def kitakoji_hisui(seed: bytes, nonce: bytes) -> list:
    """面④：9 枚真标签（i1..i9）旁各布 2 枚"更像真标签"的假标签 → 18 条字符串。

    值形如 `vm-fill-key-v3-a17f`：形状取自公开 KDF/容器词汇（值得读、也值得误读），
    版本段与 4 位十六进制尾由 (seed, nonce) 派生 ⇒ **逐格不同**、同格确定。
    返回 [str]，由构建侧写进 `pins::LABEL_BAIT` 并被入口 black_box 引用
    （不被引用会被链接器整组弃置——实测坑，见 native_build 的 decoy_touch）。"""
    out = []
    for i in range(9 * _LABEL_BAIT_PER_REAL):
        shape = _LABEL_SHAPES[i % len(_LABEL_SHAPES)]
        tail = _tag(seed, nonce, b"bait%02d" % i, 2).hex()
        ver = (_tag(seed, nonce, b"baitver", 1)[0] % 4) + 1
        out.append("%s-v%d-%s" % (shape, ver, tail))
    return out


# ---------------- 面①：伪容器节 ----------------


def nishizono_chigusa(seed: bytes, nonce: bytes, body: int = 1024) -> bytes:
    """面①：一节"看起来就是根块"的伪容器（VMB1 形 64 B 头 + PRF 体）。

    头部字段全部**取自真格式**（偏移/宽度/自报几何），值全部派生——按真值偏移摆放，
    所以按偏移读会得到自洽的几何，但这些几何不指向任何真载荷（真 blob 在 RCDATA
    资源里、魔数以 XOR 0x5A 异态存储，见 vm_blob.BLOB_MAGIC_STORED）。
    """
    h = bytearray()
    h += b"VMB1"                                   # 明文魔数：真产物里反而没有
    # 头部字段一律**从真格式取**（vm_isa 是单源）：手抄常量在 ISA 升代时会悄悄过期，
    # 而过期的自报几何正好给了"对比两枚头、认出哪节才是诱饵"的把手。
    h += struct.pack("<H", 2)                      # fmt_ver
    h += struct.pack("<H", vm_isa.ISA_VER)         # isa_ver（随档位走）
    h += struct.pack("<H", vm_isa.PHYSMAP_VER)     # physmap_ver
    h += struct.pack("<H", len(vm_isa.LOGICAL_OPS))   # op_count（随扩表走）
    h += struct.pack("<H", 64)                     # header_len（自报，与真格式同值）
    h += bytes([2, 0, 0, 0])                       # resident_slots / align 位
    h += struct.pack("<I", 64 + body)              # 自报总长
    h += struct.pack("<H", 256)                    # chunk_size
    h += struct.pack("<H", (64 + body) // 256)     # nchunks（与自报总长自洽）
    h += _stream(seed, nonce, b"pc-key", 32)       # "密钥字段"位（真产物此处无密钥）
    h += _stream(seed, nonce, b"pc-tail", 6)
    assert len(h) == 64, "fake root header must stay 64 B, got %d" % len(h)
    h += _stream(seed, nonce, b"pc-body", body)
    return bytes(h)


# ---------------- 面③：假 KDF 常量岛 ----------------

_SHA256_K_HEAD = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1)
_BLAKE2S_IV_HEAD = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)


def asahina_akane(seed: bytes, nonce: bytes, tail: int = 1024) -> bytes:
    """面③：两枚假 KDF 常量岛 + 高熵尾巴（早期轮次 的 c/d 多次审计栽在"认出哈希常量"上）。

    岛上放**真常量的前缀**（SHA-256 K 前 6 项、BLAKE2s IV 前 4 项——这些值公开且
    确实出现在产物里，藏它们没有意义），后面接**逐格派生的伪轮常量表**：形状是
    64 项 u32（= SHA-256 消息扩展表 / AES round key 的通用长相），值与任何真密钥
    无关。尾巴是纯 PRF，保证整节在滑窗熵扫下是高熵岛（结构性常量会让熵掉下去）。
    """
    out = bytearray()
    for w in _SHA256_K_HEAD:
        out += struct.pack("<I", w)
    for w in _BLAKE2S_IV_HEAD:
        out += struct.pack("<I", w)
    fake = _stream(seed, nonce, b"island-round", 64 * 4)
    out += fake                                   # 64 项 u32 伪轮常量
    out += struct.pack("<I", 0x9E3779B9)           # 万能常数，出现在一切"看起来像"的地方
    out += _tag(seed, nonce, b"island-tag", 16)
    out += _stream(seed, nonce, b"island-tail", tail)
    return bytes(out)


# ---------------- 面②：资源假件 ----------------

_PYC_MAGIC_312 = bytes([0x0D, 0x0D, 0xCB, 0x69])   # 3.12 source-magic 的低字节形态


def _fake_pyc(seed: bytes, nonce: bytes) -> bytes:
    head = _PYC_MAGIC_312 + struct.pack("<I", 0) + struct.pack("<I", 0x5E0A1D2B) + \
        struct.pack("<I", 4096)
    return head + _stream(seed, nonce, b"res-pyc", 512)


def _fake_marshal(seed: bytes, nonce: bytes) -> bytes:
    """真 marshal 结构 + 假内容：一个自洽的"模块 code object"，解出来什么都不是。"""
    fake_src = "r12_module_token_%s" % _tag(seed, nonce, b"res-name", 3).hex()
    code = compile(fake_src, "<m%s>" % _tag(seed, nonce, b"res-file", 4).hex(), "eval")
    body = bytearray(marshal.dumps(code))
    body += _stream(seed, nonce, b"res-marsh", 256)
    return bytes(body)


def _fake_config(seed: bytes, nonce: bytes) -> bytes:
    cfg = {
        "kdf": "hkdf-sha256",
        "labels": kitakoji_hisui(seed, nonce)[:4],
        "chunk_bytes": 256 + int.from_bytes(_tag(seed, nonce, b"res-cfg-a", 1), "big") % 4,
        "resident_slots": 2,
        "isa_ver": vm_isa.ISA_VER,
        "physmap": _tag(seed, nonce, b"res-phys", 8).hex(),
        "integ_key": _tag(seed, nonce, b"res-integ", 16).hex(),
        "blob_magic": "56 4d 42 31",
        "sections": sorted(_SECTIONS.values()) + [".v1", ".v2"],
        "notes": "container parameters, big-endian, key material elided",
    }
    return json.dumps(cfg, sort_keys=True, indent=1).encode("ascii")


def todo_kohaku(seed: bytes, nonce: bytes) -> list:
    """面②：3-5 枚"值得读"的假资源 → [(资源名, 字节)]，名字 seed 派生且乱序。

    资源名不能再是 'payload/seg0/decoy1' 这种地图（：审计中凭名字第一时间锁定
    真载荷）。这里全部用 `r<hex6>` 中性名 + **按派生值排序**（乱序，非按类型或长度），
    真载荷资源在同一条 rc 里形状一致，尺寸侧信道已由"同桶同长"关闭。
    """
    items = [("res-pyc", _fake_pyc(seed, nonce)),
             ("res-marsh", _fake_marshal(seed, nonce)),
             ("res-config", _fake_config(seed, nonce))]
    if len(items) < _RES_COUNT[0]:
        raise AssertionError("face2 needs >= %d resources" % _RES_COUNT[0])
    out = []
    for i, (domain, blob) in enumerate(items):
        name = "r" + _tag(seed, nonce, b"resname%02d" % i, 3).hex()
        out.append((name, blob, domain))
    out.sort(key=lambda e: (e[0], e[2]))
    return out


# ---------------- 总装 + 面⑥配套量 ----------------


def leos_vincent(seed: bytes, nonce: bytes) -> dict:
    """总装四面 → spec（native_build 据此写 pins/rc/decoys 静态，并交给验收门）。

    `face_steps` 是面⑥的配套量：boot 在**自检失败路径**上跑的诱饵链步数
    （2048~4095，逐格不同）。删除任一诱饵 ⇒ 在场节集合变 ⇒ keyed 摘要变 ⇒ 走
    失败路径 ⇒ 这条链被跑一遍——"证伪=删除实验"就此变成"删除会留下行为痕迹"
    （的通道），而痕迹只有时长与内存足迹，不透露删了哪一枚（静默拒绝的
    契约、14 处 `stderr == ""` 断言都不破）。
    """
    container = nishizono_chigusa(seed, nonce)
    kdf = asahina_akane(seed, nonce)
    return {
        "labels": kitakoji_hisui(seed, nonce),
        "resources": todo_kohaku(seed, nonce),
        "container": container,
        "kdf": kdf,
        "face_steps": 2048 + int.from_bytes(_tag(seed, nonce, b"face-steps", 2), "big") % 2048,
        "sections": dict(_SECTIONS),
    }


# ---------------- 统一验收门：缺席即拒 ----------------


def lauren_iroas(exe: bytes, spec: dict) -> dict:
    """全部诱饵面的"在场"验收：任何一面缺席 ⇒ RuntimeError（构建失败、不写盘）。

    `spec` = `leos_vincent(...)` 的返回。逐面查的是**最终 exe 字节 + 节表**（不是
    中间产物），所以"物化时忘了接线 / 链接器把 static 弃置 / 资源没进 rc"这三类
    真事故都会被抓。同时量总体积，超 `FACE_BUDGET_BYTES` 直接拒。
    """
    from d_side.builder.patcher import nui_sociere

    missing = []
    for label in spec["labels"]:
        if label.encode("ascii") not in exe:
            missing.append("face4-label:%s" % label)
    for name, blob, _domain in spec["resources"]:
        if blob not in exe:
            missing.append("face2-resource:%s" % name)
    if spec["container"] not in exe:
        missing.append("face1-container-section-body")
    if spec["kdf"] not in exe:
        missing.append("face3-kdf-island-body")
    present = {s["name"] for s in nui_sociere(exe)[1]}
    for face, section in spec["sections"].items():
        if section not in present:
            missing.append("section:%s(%s)" % (section, face))
    if len(spec["labels"]) != 9 * _LABEL_BAIT_PER_REAL:
        missing.append("face4-label-count=%d" % len(spec["labels"]))
    if not _RES_COUNT[0] <= len(spec["resources"]) <= _RES_COUNT[1]:
        missing.append("face2-resource-count=%d" % len(spec["resources"]))
    total = sum(len(b) for _n, b, _d in spec["resources"])
    total += len(spec["container"]) + len(spec["kdf"])
    total += sum(len(s.encode("ascii")) for s in spec["labels"])
    if total > FACE_BUDGET_BYTES:
        raise RuntimeError("decoy faces exceed the size budget: %d > %d B"
                           % (total, FACE_BUDGET_BYTES))
    if missing:
        raise RuntimeError("decoy face(s) absent in final image (build refused): %r"
                           % (missing[:6],))
    return {"faces_bytes": total, "labels": len(spec["labels"]),
            "resources": len(spec["resources"]), "face_steps": spec["face_steps"],
            "sections": sorted(spec["sections"].values())}
