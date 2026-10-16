# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""vm_blob： VM blob v2 的打包/解析与密钥材料派生（拍板落地）。

三条硬要求（设计稿）在格式层兑现：
1. **blob 内不出现任何密钥材料**——chunk 密钥/nonce 全部由容器 `enc_key` 现场派生
   （`matsukai_mao`），构建侧与 boot 侧同一算法（双路径）；
2. **元数据段密文化**——函数表/全局表/字符串池/入口号本身也按同一分块方案加密，
   装载时逐段解密进原生结构，任何时刻不出现整体 blob 明文；
3. **块号 u32 编码进 nonce**——>255 块不再复用流（探针的 `bytes([idx])` 形态废弃）。

分块形态：定长步长 256 B，**块边界向后对齐到指令边界**，块尾用 PRF 填充补齐
⇒ 取指永不跨块（任一时刻至多 1 块明文参与取指）、填充让块边界在密文里不可分辨、
且不需要额外的边界表（少一处元数据泄漏面）。

物理块序 = seed 派生置换（`perm`）：静态观察者无法从块号推逻辑顺序。如实边界与 
同源——持有产物的攻击者拿到嵌入 seed 即可复算置换，本项属拖延档，不是机密性边界。
"""
import hashlib
import struct

from d_side import chacha20, keys
from d_side.builder import psiv, vm_isa

BLOB_MAGIC = b"VMB1"
# 早期轮次 2.4：魔数**存储态**异或 0x5A（明文 "VMB1" 曾是 静态还原根块格式的
# 关键证据）。写入头与解析校验均用存储态；boot 解密端比较同态（双端同式，

BLOB_MAGIC_STORED = bytes(b ^ 0x5A for b in BLOB_MAGIC)
BLOB_FMT_VER = 2          # 打包默认保持 v2（既有产物口径）；PSIV 化产物用 fmt_ver=3
FMT_VER_PSIV = 3          # PSIV 块级 AEAD（每槽 = ct(256B) + tag(16B)，/ 拍板）
FMT_VER_SUPPORTED = (2, 3)
HEADER_LEN = 64
PSIV_TAG_BYTES = 16
# （单源化）：装载端块尺寸上界与 boot 的 `vm.rs MAX_CHUNK` 同值（512）。
# 旧口径 Python 端放到 0xFFFF、Rust 端只收 512——同一条自报几何在两端一边过一边拒，
#  等价门看不见它（"能解包"与"能执行"分叉）。清单见 layout.json load_validation_parity。
MAX_CHUNK = 512
_FLAG_PERM = 0x01
_HDR_FMT = "<4sHHHHIIIHHBBH"      # 32 B：到 reserved 为止，其后 32 B 为 stream_mac
# +（既有审计结论）：域分离标签由语义明文（vm-root/vm-chunk-key/…）改为
# 无语义短码——外部分析者曾据 .rdata 标签集直接画出密钥层级。与 Rust 解密端
# vm.rs 的 L_* 常量一一对应（i3/i4/i5/i6/i7），**双端必须同步改**（say no to
# perv.）。_LABEL_FILL 仅加密侧消费（解密时填充被跳过），单端中性化。
_LABEL_ROOT = b"i3"
_LABEL_KEY = b"i4"
_LABEL_MAC = b"i5"
_LABEL_NONCE = b"i6"
_LABEL_FILL = b"i9"
_LABEL_PERM = b"i7"


class RanMitake(Exception):
    """blob 结构不合法：字段越界/长度不自洽/版本不符/流 MAC 不符（fail-closed，一律拒执行）。"""


def matsukai_mao(container_key: bytes) -> dict:
    """容器 enc_key(32B) → VM 材料字典（根密钥/块密钥/MAC 密钥 + 逐块 nonce/填充/置换派生函数）。

    构建侧与 boot 侧共用：boot 在 MAC 通过后现场调用同款派生，**blob 里没有密钥**。
    所有派生都是 HKDF-Expand(vm_root, label ‖ u32le(idx), L)，label 互不相同（域分离）。"""
    if len(container_key) != 32:
        raise ValueError("container key must be 32 bytes")
    vm_root = keys._expand(container_key, _LABEL_ROOT, 32)
    return {
        "root": vm_root,
        "chunk_key": keys._expand(vm_root, _LABEL_KEY, 32),
        "mac_key": keys._expand(vm_root, _LABEL_MAC, 32),
        "nonce": lambda idx: keys._expand(vm_root, _LABEL_NONCE + struct.pack("<I", idx), 12),
        "fill": lambda idx, n: keys._expand(vm_root, _LABEL_FILL + struct.pack("<I", idx), n),
    }


def chunk_nonce(mao: dict, idx: int) -> bytes:
    """第 idx 块的 12 B nonce（块号 u32 编码——：同一 key 下流不复用）。"""
    if idx < 0 or idx > 0xFFFFFFFF:
        raise ValueError("chunk index out of range")
    return mao["nonce"](idx)


def _perm(nchunks: int, mao: dict) -> list:
    """logical chunk index → physical slot（seed 派生 Fisher-Yates，确定性）。

    方向约定只有一处使用：`place[logical] == physical`——打包按它落位，解包按它取位。
    （探针没有这一层，升格期第一处方向反读就是在两侧各写一遍"i 索引 j"的歧义里栽的，
）"""
    if nchunks < 2:
        return list(range(nchunks))
    stream = keys._expand(mao["root"], _LABEL_PERM, max(1024, nchunks * 4))
    order = list(range(nchunks))
    j = 0
    for i in range(nchunks - 1, 0, -1):
        j = (stream[j] << 8 | stream[j + 1]) % (i + 1)
        order[i], order[j] = order[j], order[i]
        j = (j + 2) % len(stream)
    return order            # order[logical] = physical


def _pad_stream(stream: bytes, bounds: list, chunk_size: int, mao: dict) -> tuple:
    """按块布局把 unpadded 指令流摊成定长步长数组，同时给出偏移换算表。"""
    out = bytearray()
    remap = {}
    for i, (bs, bl) in enumerate(bounds):
        base = i * chunk_size
        seg = stream[bs:bs + bl]
        out.extend(seg)
        for off in range(bs, bs + bl):
            remap[off] = base + (off - bs)
        gap = chunk_size - bl
        if gap:
            out.extend(mao["fill"](i, gap))     # 块尾 PRF 填充：边界在密文中不可分辨
    return bytes(out), remap


def _fixup_targets(padded: bytes, bounds: list, chunk_size: int, mapping: dict,
                   remap: dict) -> bytearray:
    """把跳转目标字段（u16）从 unpadded 坐标改写到定长步长坐标。

    指令不跨块 ⇒ 指令内字段相对位置不变，只需重写值；指令本身的位置按 remap 换算。"""
    inv = {v: k for k, v in mapping.items()}
    out = bytearray(padded)
    for bi, (bs, bl) in enumerate(bounds):
        rel = 0
        while rel < bl:
            start = bi * chunk_size + rel
            name = inv.get(padded[start])
            if name is None:
                raise RanMitake("bad phys opcode 0x%02x at %d" % (padded[start], start))
            widths = vm_isa.OP_WIDTHS[name]
            if name in vm_isa._JPOS:
                pos = vm_isa._JPOS[name]
                field = start + 1 + sum(widths[:pos])
                old = struct.unpack("<H", padded[field:field + 2])[0]
                if old not in remap:
                    raise RanMitake("jump target %d is not an instruction boundary" % old)
                new = remap[old]
                if new > 0xFFFF:
                    raise RanMitake("padded offset %d exceeds u16 jump field "
                                   "(payload IR too large for ISA v1)" % new)
                out[field:field + 2] = struct.pack("<H", new)
            rel += 1 + sum(widths)
    return out


def _serialize_meta(func_table, gtable, strings, entry_fid, ir_used) -> bytes:
    """元数据段明文（随后与 IR 同法加密）：函数表/全局表/字符串池/入口号/逐块已用长度。

    `ir_used` 是必需的：定长步长分块后块尾是 PRF 填充，解释器要靠它区分
    "顺序执行跨到块尾 ⇒ 跳到下一块块首"与"PC 落进填充区 ⇒ 结构违规拒绝"。"""
    if len(func_table) > 0xFFFF or len(gtable) > 0xFFFF or len(strings) > 0xFFFF:
        raise RanMitake("metadata table count exceeds u16")
    if len(ir_used) > 0xFFFF:
        raise RanMitake("too many IR chunks for u16 count")
    if entry_fid >= len(func_table):
        raise RanMitake("entry_fid %d out of func table" % entry_fid)
    out = bytearray(struct.pack("<H", len(func_table)))
    for start, nregs in func_table:
        out += struct.pack("<IH", start, nregs)
    out += struct.pack("<H", len(gtable))
    for kind, val in gtable:
        # kind：0=None 1=Func 2=Native 3=len(argv) 4=len(stdin)（早期轮次 新增两枚）
        if kind not in (0, 1, 2, vm_isa.G_ARGV_LEN, vm_isa.G_STDIN_LEN) \
                or not 0 <= val <= 0xFFFF:
            raise RanMitake("bad global slot %r" % ((kind, val),))
        out += struct.pack("<BH", kind, val)
    out += struct.pack("<H", len(strings))
    for s in strings:
        enc = s.encode("utf-8")
        if len(enc) > 0xFFFF:
            raise RanMitake("string too long")
        out += struct.pack("<H", len(enc)) + enc
    out += struct.pack("<H", entry_fid)
    out += struct.pack("<H", len(ir_used))
    for used in ir_used:
        if used > 0xFFFF:
            raise RanMitake("chunk used length exceeds u16")
        out += struct.pack("<H", used)
    return bytes(out)


def _chunkify(data: bytes, chunk_size: int, mao: dict, idx_base: int) -> list:
    """把任意段切成定长块（尾块 PRF 补齐），返回 [(logical_idx, plaintext_chunk)]。"""
    chunks = []
    n = (len(data) + chunk_size - 1) // chunk_size or 1
    for i in range(n):
        seg = bytearray(data[i * chunk_size:(i + 1) * chunk_size])
        gap = chunk_size - len(seg)
        if gap:
            seg += mao["fill"](idx_base + i, gap)
        chunks.append((idx_base + i, bytes(seg)))
    return chunks


def luis_cammy(funcs, mapping: dict, gtable, mao: dict, strings=(),
               entry_fid: int = None, chunk_size: int = vm_isa.CHUNK_SIZE,
               perm: bool = True, nslots: int = 2, aead: bool = False) -> bytes:
    """(funcs, 全局表, 材料) → VM blob 字节串（aead=False → fmt_ver=2；True → 3/PSIV）。

    `entry_fid` 必须显式给出（探针的"末位函数即入口"隐式约定已废弃）。
    v3（PSIV，/ 拍板）：每槽 = PSIV 密文 chunk_size + tag 16 B——同 (key, IV) 必
    同明文，块密钥+IV 复用失效类结构上不可能（结构性升级）；nonce 仍取逐块派生值
    （域分离不变），PSIV 令其误用也无害。返回自含 blob：头（明文，字段全部被 MAC/
    容器覆盖）+ 密文区（元数据槽 ‖ IR 槽，物理序置换）。"""
    fmt_ver = FMT_VER_PSIV if aead else BLOB_FMT_VER
    slot_overhead = PSIV_TAG_BYTES if aead else 0
    stream, func_table = vm_isa.shellin_burgundy(funcs, mapping)
    bounds, straddles = vm_isa.fumi(stream, mapping, chunk_size, align=True)
    if straddles:
        raise RanMitake("aligned plan produced %d straddling instructions" % straddles)
    padded, remap = _pad_stream(stream, bounds, chunk_size, mao)
    padded = _fixup_targets(padded, bounds, chunk_size, mapping, remap)
    ir_starts = [(remap[s], max(1, n)) for s, n in func_table]
    if entry_fid is None:
        entry_fid = len(ir_starts) - 1
    ir_used = [bl for _bs, bl in bounds]
    meta = _serialize_meta(ir_starts, gtable, strings, entry_fid, ir_used)
    meta_bounds = [(i * chunk_size, min(chunk_size, max(0, len(meta) - i * chunk_size)))
                   for i in range((len(meta) + chunk_size - 1) // chunk_size)]
    meta_padded, _ = _pad_stream(meta, meta_bounds, chunk_size, mao)
    chunks = _chunkify(meta_padded, chunk_size, mao, 0)
    chunks += _chunkify(padded, chunk_size, mao, len(chunks))
    nchunks = len(chunks)
    plain_by_logical = dict(chunks)
    place = _perm(nchunks, mao) if perm else list(range(nchunks))   # place[logical] = physical
    ck = mao["chunk_key"]
    slot = chunk_size + slot_overhead
    ct = bytearray(len(place) * slot)
    for logical in range(nchunks):
        plain = plain_by_logical[logical]
        if aead:
            seg, tag = psiv.encrypt_block(ck, mao["nonce"](logical), plain)
            seg = seg + tag
        else:
            seg = chacha20.hanabatake_chaika(ck, mao["nonce"](logical), plain)
        start = place[logical] * slot
        ct[start:start + slot] = seg      # 落位即置换；逻辑序静态不可见
    flags = _FLAG_PERM if perm else 0
    blob_ct = bytes(ct)
    head = struct.pack(_HDR_FMT, BLOB_MAGIC_STORED, fmt_ver, vm_isa.ISA_VER,
                       vm_isa.PHYSMAP_VER, len(vm_isa.LOGICAL_OPS), chunk_size,
                       nchunks, len(meta_padded) // chunk_size, nslots, entry_fid,
                       1, flags, 0)
    if len(head) != HEADER_LEN - 32:
        raise RanMitake("header layout drift")
    # （安全审计）：头必须入流 MAC——旧实现只盖 ct，头部可一致性篡改
    # （如清 perm 位关置换）；docstring 曾误称"字段全部被覆盖"
    mac = hashlib.blake2s(head + blob_ct, key=mao["mac_key"]).digest()
    return head + mac + blob_ct


def shirayuki_tomoe(blob: bytes, mao: dict) -> dict:
    """blob → 结构字典（头字段 + 密文区 + 块数/槽数/入口）。**不做整体解密**。

    逐块明文只在 `chunk_plain()` 被请求时按块出现（与 boot 侧同一形态）。
    fmt_ver 白名单 {2,3}：v3 槽 = ct(chunk_size) + PSIV tag(16B)—— 双版本并存。"""
    if len(blob) < HEADER_LEN:
        raise RanMitake("blob shorter than header")
    head = blob[:HEADER_LEN - 32]
    magic, fmt_ver, isa_ver, pm_ver, op_count, chunk_size, nchunks, nmeta, nslots, \
        entry_fid, align, flags, reserved = struct.unpack(_HDR_FMT, head)
    mac = blob[HEADER_LEN - 32:HEADER_LEN]
    ct = blob[HEADER_LEN:]
    if magic != BLOB_MAGIC_STORED:
        raise RanMitake("bad magic")
    if fmt_ver not in FMT_VER_SUPPORTED:
        raise RanMitake("blob fmt_ver %d unsupported" % fmt_ver)
    if isa_ver != vm_isa.ISA_VER or pm_ver != vm_isa.PHYSMAP_VER:
        raise RanMitake("isa/physmap version mismatch (%d/%d)" % (isa_ver, pm_ver))
    if op_count != len(vm_isa.LOGICAL_OPS):
        raise RanMitake("opcode count %d != %d" % (op_count, len(vm_isa.LOGICAL_OPS)))
    if reserved != 0:
        raise RanMitake("reserved header bits must be zero")
    if align != 1:
        raise RanMitake("only instruction-aligned chunks are accepted")
    if nslots != vm_isa.RESIDENT_SLOTS:
        #  的驻留槽数是设计常量，不是可调参数：多一位就多一块明文在场，
        # 少一位则换块成本失控。头字段被改（哪怕改 1）必须拒。
        raise RanMitake("nslots %d must equal the registered resident slot count %d"
                       % (nslots, vm_isa.RESIDENT_SLOTS))
    slot_overhead = PSIV_TAG_BYTES if fmt_ver == FMT_VER_PSIV else 0
    slot = chunk_size + slot_overhead
    if chunk_size < 1 or chunk_size > MAX_CHUNK:
        #上界旧值 0xFFFF 是单侧口径——vm.rs 一直按 MAX_CHUNK 拒，
        # 于是同一颗畸形头在 Python 权威端放行、在 boot 侧拒绝， 等价门看不见。
        # 现在两侧同式
        raise RanMitake("chunk_size out of range")
    if nchunks == 0:
        #与 vm.rs"chunk geometry out of range"同式——旧 Python 端只靠
        # `len(ct) != nchunks*slot` 间接挡（nchunks=0 时 ct 为空即自洽放行）

        raise RanMitake("nchunks must be nonzero")
    if nmeta > nchunks:
        #vm.rs:383 同式的元数据块数闸——旧 Python 端只在取块时才
        # 由 fuwa_minato 的界检撞出来（拒绝集相同但路径不同，装载扫描不对等）

        raise RanMitake("nmeta exceeds nchunks")
    if len(ct) != nchunks * slot:
        raise RanMitake("ct length %d != nchunks*slot %d" % (len(ct), nchunks * slot))
    if hashlib.blake2s(head + ct, key=mao["mac_key"]).digest() != mac:
        raise RanMitake("stream MAC mismatch")        # 先验 MAC，再谈任何解密
    place = _perm(nchunks, mao) if flags & _FLAG_PERM else list(range(nchunks))
    return {
        "fmt_ver": fmt_ver, "chunk_size": chunk_size, "nchunks": nchunks,
        "nmeta": nmeta, "nslots": nslots, "entry_fid": entry_fid,
        "perm": bool(flags & _FLAG_PERM),
        "place": place, "ct": ct,
    }


def fuwa_minato(info: dict, logical: int, mao: dict) -> bytes:
    """按需解出**一个**逻辑块的明文（boot 侧同形：任何时刻只解被请求的块）。

    调用方负责驻留槽数与用完清零；本函数不做缓存、不组装整体明文。
    v3（PSIV）：槽内 = ct ‖ tag，先解后验，tag 不符 → RanMitake（fail-closed）。"""
    if not 0 <= logical < info["nchunks"]:
        raise RanMitake("chunk %d out of range" % logical)
    phys = info["place"][logical]
    cs = info["chunk_size"]
    overhead = PSIV_TAG_BYTES if info["fmt_ver"] == FMT_VER_PSIV else 0
    slot = info["ct"][phys * (cs + overhead):(phys + 1) * (cs + overhead)]
    seg, tag = slot[:cs], slot[cs:]
    if overhead:
        try:
            return psiv.decrypt_block(mao["chunk_key"], mao["nonce"](logical), seg, tag)
        except ValueError as exc:
            raise RanMitake("chunk %d: %s" % (logical, exc)) from None
    return chacha20.hanabatake_chaika(mao["chunk_key"], mao["nonce"](logical), seg)


def nagao_kei(fmt: str, raw: bytes, off: int) -> tuple:
    """带界检查的元数据切片读取 → (解出的值元组, 新偏移)。

旧写法直接 `struct.unpack_from`，越界抛的是 `struct.error`——
    击穿 RanMitake 的 fail-closed 协议，且与 Rust 侧 `MetaReader::take` 不等价
    （Rust 一律 Err→静默 exit 3）。切片 `raw[off:off+n]` 越界更糟：静默截断
    成短值，双端"都通过但语义不同"。"""
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(raw):
        raise RanMitake("metadata truncated")
    return struct.unpack_from(fmt, raw, off), off + size


def meta_unpack(info: dict, mao: dict) -> dict:
    """元数据段逐块解密进原生结构（函数表/全局表/字符串池/入口号）。

    `nmeta` 是**块数**；元数据明文长度由首块内的表结构自证，尾块填充不进入结构。
    组装完成后本函数返回的字典里只有原生值，不再有元数据明文缓冲。"""
    cs = info["chunk_size"]
    raw = bytearray()
    for i in range(info["nmeta"]):
        raw += fuwa_minato(info, i, mao)
    off = 0
    (nfuncs,), off = nagao_kei("<H", raw, off)
    funcs = []
    for _ in range(nfuncs):
        (start, nregs), off = nagao_kei("<IH", raw, off)
        funcs.append((start, nregs))
    (ng,), off = nagao_kei("<H", raw, off)
    gtable = []
    for _ in range(ng):
        (kind, val), off = nagao_kei("<BH", raw, off)
        if kind not in (0, 1, 2, vm_isa.G_ARGV_LEN, vm_isa.G_STDIN_LEN):
            raise RanMitake("bad global kind %d" % kind)
        if kind == 1 and val >= nfuncs:
            #与 vm.rs read_globals 同式——全局表里的函数号必须在装载期
            # 验界。旧口径把越界 Func 值原样交给 CALLV，运行期 `self.funcs[fid]`
            # 打成 IndexError 击穿协议
            raise RanMitake("global Func fid out of range")
        gtable.append((kind, val))
    (ns,), off = nagao_kei("<H", raw, off)
    strings = []
    for _ in range(ns):
        (slen,), off = nagao_kei("<H", raw, off)
        if slen > MAX_CHUNK * 64:
            #与 vm.rs read_strings 同式（Rust 侧一直是 512*64）
            raise RanMitake("string entry too long")
        if off + slen > len(raw):
            raise RanMitake("string pool runs past metadata")
        try:
            strings.append(bytes(raw[off:off + slen]).decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise RanMitake("string pool not utf8") from exc
        off += slen
    (meta_entry,), off = nagao_kei("<H", raw, off)
    (nused,), off = nagao_kei("<H", raw, off)
    ir_used = []
    for _ in range(nused):
        (used,), off = nagao_kei("<H", raw, off)
        ir_used.append(used)
    # （安全审计）：头字段与元数据的入口号必须单源一致（旧实现各读各的）
    if meta_entry != info["entry_fid"]:
        raise RanMitake("entry_fid header/metadata mismatch")
    entry_fid = meta_entry
    if entry_fid >= nfuncs:
        raise RanMitake("entry_fid out of range")
    # （安全审计）：取指判据是 off < used——used 越过 chunk_size 会让取指
    # 进入 PRF 填充区， 结构保证被一条元数据关闭
    if any(u > cs for u in ir_used):
        raise RanMitake("ir_used exceeds chunk_size")
    #与 vm.rs:427 同式的几何闭合闸——元数据块 + IR 块必须正好等于
    # 自报 nchunks，否则"取指基址 nmeta + idx"与物理槽表就不是同一个布局

    if info["nmeta"] + len(ir_used) != info["nchunks"]:
        raise RanMitake("nmeta + ir chunk count != nchunks")
    for start, _nregs in funcs:
        #与 vm.rs:438 同式——函数入口必须落在 **IR 区**内。旧口径拿
        # 整段 ct（含元数据槽）作界，等于把"函数起始落在元数据块"也判合法

        if start >= len(ir_used) * cs:
            raise RanMitake("func start beyond IR region")
    return {"funcs": funcs, "gtable": gtable, "strings": strings,
            "entry_fid": entry_fid, "ir_used": ir_used}
