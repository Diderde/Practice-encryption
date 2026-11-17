# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""patcher：post-link 确定性写入（D-3 自身完整性，/Q2 定稿 0.0.39；/ 扩覆盖）。

职责（设计稿 patcher 组件行）：
- 计算**在场节摘要**（keyed BLAKE2s-256）写入独立只读数据节 `.v0`
  （boot.rs 内 `#[link_section]` 静态占位——摘要绝不写回被盖节本体，§8：写回即自我指涉）；
- 覆盖从"只有 `.text`"扩到**节表顺序上所有在场节的 raw bytes**（跳过 `.v0` 槽自身，
  `.reloc` 含入）——旧口径下 `.rdata`（字符串池/KDF 标签/错误串）与 `.rsrc`（RCDATA 载荷、
  版本资源）全程裸奔，f 攻击者已实测"改代码 + 重算无键摘要"走通（text_patched_repaired）。
  摘要同时改为 **keyed**：密钥 INTEG_KEY = HKDF-Expand(HKDF-Extract("", nonce), "integ", 32)，
  nonce 恒在产物头部（外部密钥档只置零 seed），故两种模式都可复算；
- 构建期断言 `.text` 重定位数为 0（§8 前提：ASLR fixup 全在 .rdata/.data，
  早期轮次 探针实测口径；非零即绝对地址进入 .text，摘要前提不成立）；
- PE 头 CheckSum 置零（§7  定稿字段）。

写入区间长度断言：槽节必须在场、raw 尺寸 ≥ 32、且第 32 字节之后至节尾
必须全零——布局漂移（槽节混入其他静态）在此被拒。输出 = f(输入 exe)，
确定性；配合 `/Brepro + /DEBUG:NONE` 链接旗标，两次完整构建逐字节一致
（native 套件钉死）。不改任何被盖节的内容；不做签名/证书。
"""
import hashlib

from d_side import keys

_TEXT_SECTION = ".text"
_SLOT_SECTION = ".v0"
_DIGEST_LEN = 32
# 密钥派生的双端单源口径（boot.rs `kaida_haru` 同式；layout.json self_digest）
# +（既有审计结论）：info 标签随 boot.rs 域分离标签批中性化（"integ"→"i8"），
# 双端必须同步改——否则摘要槽与 boot 校验值不一致、产物全坏
_INTEG_INFO = b"i8"
_NONCE_LEN = 12


def kaida_haru(nonce: bytes) -> bytes:
    """产物 nonce(12B) → 完整性密钥 INTEG_KEY(32B)。

    `HKDF-Expand(HKDF-Extract(salt="", ikm=nonce), info="integ", L=32)`——与载荷密钥
    不同 PRK（salt 为空），域分离靠 info 标签。nonce 在头部前 25 B 内，外部密钥档
    只把 seed 置零，故**两种模式都可复算**。"""
    if len(nonce) != _NONCE_LEN:
        raise ValueError("nonce must be %d bytes" % _NONCE_LEN)
    return keys._expand(keys._extract(b"", nonce), _INTEG_INFO, 32)


def _covered_image(blob: bytes, sections: list, nonce: bytes) -> bytes:
    """按节表顺序串接所有**在场**节的 raw bytes（跳过 `.v0` 槽自身），返回带键摘要。

    与 boot.rs `ars_almal` 逐字段同式：同一顺序、同一"在场"判据（ptr≠0 且 rsize≠0）、
    同一跳过规则。键在末尾附加——不改变被盖字节，只改变算法。"""
    parts = []
    for sec in sections:
        if sec["name"] == _SLOT_SECTION or sec["ptr"] == 0 or sec["rsize"] == 0:
            continue
        end = sec["ptr"] + sec["rsize"]
        if end > len(blob):
            raise RuntimeError("section %s raw range runs past the image" % sec["name"])
        parts.append(blob[sec["ptr"]:end])
    if not parts:
        raise RuntimeError("no section contributes to the self digest")
    return hashlib.blake2s(b"".join(parts), key=kaida_haru(nonce)).digest()



def nui_sociere(blob: bytes) -> tuple:
    """PE 解析：(e_lfanew, 节表)。节项 = dict(name/va/vsize/ptr/rsize/chars)。

    纯 Python 节表遍历（原 native_build._pe_sections 收编扩展）；镜像口径
    与 boot 运行期自解析逐字段一致，任一侧漂移都会被套件比字节钉出。"""
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise RuntimeError("not a PE image")
    e_lfanew = int.from_bytes(blob[0x3C:0x40], "little")
    if blob[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise RuntimeError("PE signature missing")
    num_sections = int.from_bytes(blob[e_lfanew + 6:e_lfanew + 8], "little")
    opt_size = int.from_bytes(blob[e_lfanew + 20:e_lfanew + 22], "little")
    table = e_lfanew + 24 + opt_size
    out = []
    for i in range(num_sections):
        base = table + 40 * i
        name = blob[base:base + 8].rstrip(b"\x00").decode("ascii", "replace")
        out.append({
            "name": name,
            "vsize": int.from_bytes(blob[base + 8:base + 12], "little"),
            "va": int.from_bytes(blob[base + 12:base + 16], "little"),
            "rsize": int.from_bytes(blob[base + 16:base + 20], "little"),
            "ptr": int.from_bytes(blob[base + 20:base + 24], "little"),
            "chars": int.from_bytes(blob[base + 36:base + 40], "little"),
        })
    return e_lfanew, out


def hakase_fuyuki(blob: bytes, sections: list) -> int:
    """统计落在 `.text` 区间内的基址重定位数（§8：构建期断言必须为 0）。"""
    text = next((s for s in sections if s["name"] == _TEXT_SECTION), None)
    if text is None:
        raise RuntimeError(".text section not found")
    lo, hi = text["va"], text["va"] + max(text["vsize"], text["rsize"])
    reloc = next((s for s in sections if s["name"] == ".reloc"), None)
    if reloc is None or reloc["rsize"] == 0:
        return 0
    data = blob[reloc["ptr"]:reloc["ptr"] + reloc["rsize"]]
    count = 0
    off = 0
    while off + 8 <= len(data):
        page = int.from_bytes(data[off:off + 4], "little")
        block = int.from_bytes(data[off + 4:off + 8], "little")
        if block == 0 or block < 8 or off + block > len(data):
            break
        for j in range(off + 8, off + block, 2):
            entry = int.from_bytes(data[j:j + 2], "little")
            if entry >> 12 == 0:  # IMAGE_REL_BASED_ABSOLUTE：填充，不计
                continue
            rva = page + (entry & 0x0FFF)
            if lo <= rva < hi:
                count += 1
        off += block
    return count


def hayama_marin(blob: bytes, nonce: bytes) -> bytes:
    """post-link 主入口：在场节 keyed 摘要入槽 + CheckSum 置零 + 全部断言。失败即抛错。

    `nonce` 取产物头部前 25 B 内的 12 B nonce（`pins` 同源，外部密钥档下同样在场）——
    摘要密钥由它派生，故**逐字节可复现**（：同输入同输出，两次构建仍然一致）。"""
    e_lfanew, sections = nui_sociere(blob)
    text = next((s for s in sections if s["name"] == _TEXT_SECTION), None)
    if text is None or text["rsize"] < 64 or text["ptr"] == 0:
        raise RuntimeError(".text section missing or too small")
    relocs = hakase_fuyuki(blob, sections)
    if relocs != 0:
        raise RuntimeError(".text carries %d relocations (self-digest premise broken)"
                           % relocs)
    slot = next((s for s in sections if s["name"] == _SLOT_SECTION), None)
    if slot is None or slot["ptr"] == 0 or slot["rsize"] < _DIGEST_LEN:
        raise RuntimeError("digest slot section %s missing or too small" % _SLOT_SECTION)
    tail = blob[slot["ptr"] + _DIGEST_LEN:slot["ptr"] + slot["rsize"]]
    if any(tail):
        raise RuntimeError("digest slot section carries foreign bytes past %d B"
                           % _DIGEST_LEN)
    digest = _covered_image(blob, sections, nonce)
    out = bytearray(blob)
    out[slot["ptr"]:slot["ptr"] + _DIGEST_LEN] = digest
    # PE32+ 可选头 CheckSum（e_lfanew + 24 + 64）： 定稿置零。显式界检——
    # 畸形超短 PE 上切片赋值会在 bytearray 尾部静默追加而非报错（
    # 0.0.40 审查）
    check_off = e_lfanew + 24 + 64
    if check_off + 4 > len(out):
        raise RuntimeError("optional header checksum offset out of range")
    out[check_off:check_off + 4] = b"\x00\x00\x00\x00"
    return bytes(out)
