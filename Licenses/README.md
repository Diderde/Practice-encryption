# Licenses — 第三方许可证券库

本目录集中存放本仓库涉及的全部第三方组件的**许可证全文**与**在场证据**。
打开本文件即可一览：谁、什么版本、什么许可证、出现在哪个产物里、证据是什么。

快速结论（审计口径）：

- 随产物分发的第三方**全部是宽松许可证**（PSF / MIT / BSD 系 / Apache-2.0 / Zlib /
  public domain），**没有专有件、没有需要授权费的件、没有传染性件**。
- 唯一的专有物是微软 vcruntime（MSVC 运行库）——已拍板**不随附**（见 §4）。
- 本仓库自身代码为 **GPL-3.0-only**（`LICENSE`），并附**产出例外**（`LICENSE.exception`）：
  用本工具产出的文件不受 copyleft 约束，包括 native exe 及其内嵌的引导器/壳代码；例外
  只覆盖产出，不覆盖工具源码本身。[日期略] 由 MIT 改为此口径——**此前已按 MIT 分发
  出去的副本仍按 MIT 生效**，改动只约束此后分发的版本。

三个分组对应三种分发义务面：

| 目录 | 含义 | 分发时是否需要随附这些文本 |
| --- | --- | --- |
| `native-product/` | 随 原生产物 native exe 分发的第三方 | **是**（按档位，见 §1.2） |
| `tool-deps/` | pyshroud 工具自身的可选依赖（装在用户环境） | 视发行方式（见 §2） |
| `dev-env/` | 仅存在于构建/测试机 | 否 |

## 1. native-product/ — 随 原生产物 native exe 分发的第三方

### 1.1 清单

boot exe 自身代码（含 Rust 标准库）+ PHM1 资源包内嵌的 CPython home。包内文件清单的
单一来源是 `d_side/builder/native_build.py` 的 `_HOME_COMMON_PYD` / `_HOME_COMMON_DLL` /
`HOME_FULL_EXTRA_*` 常量与 `_build_home_pack()`。

| 组件 | 版本 | 许可证 | 文本文件 | 在场位置 |
| --- | --- | --- | --- | --- |
| CPython | 3.12.10（tags/v3.12.10:0cc8128, MSC v.1943） | PSF License | `CPython-3.12.10-PSF-License.txt` | 全部档位：`python312.dll` + `python312.zip`（stdlib） |
| zlib | 1.3.1 | Zlib | `zlib-1.3.1-license.txt` | 静态链入 `python312.dll`（全部档位） |
| bzip2 / libbzip2 | 1.0.8 | bzip2（BSD 风格） | `bzip2-1.0.8-LICENSE.txt` | 静态链入 `DLLs/_bz2.pyd`（std/full） |
| liblzma（XZ Utils） | 5.2.5 | public domain（liblzma 部分） | `liblzma-5.2.5-xz-COPYING.txt` | 静态链入 `DLLs/_lzma.pyd`（std/full） |
| mpdecimal | 2.5.1 | BSD-2-Clause | `mpdecimal-2.5.1-BSD-2-Clause.txt` | 静态链入 `DLLs/_decimal.pyd`（std/full） |
| libexpat | 2.7.1 | MIT | `libexpat-2.7.1-MIT-COPYING.txt` | 静态链入 `DLLs/pyexpat.pyd` 与 `DLLs/_elementtree.pyd`（std/full） |
| libffi | 3.4.4 | MIT | `libffi-3.4.4-MIT-LICENSE.txt` | `DLLs/libffi-8.dll`（std/full，动态；`_ctypes.pyd` 消费） |
| OpenSSL | 3.0.16 | Apache-2.0 | `openssl-3.0.16-Apache-2.0-LICENSE.txt` | `DLLs/libssl-3.dll` + `DLLs/libcrypto-3.dll`（**仅 full**，动态；`_ssl.pyd`/`_hashlib.pyd` 消费） |
| SQLite | 3.49.1 | public domain | `sqlite-3.49.1-public-domain.txt` | `DLLs/sqlite3.dll`（**仅 full**，动态；`_sqlite3.pyd` 消费） |
| Unicode UCD | 15.0.0 | Unicode License | `unicodedata-UCD-15.0.0-unicode-license.txt` | 数据内嵌于 `DLLs/unicodedata.pyd`（std/full） |
| Rust std | 1.98.1（工具链） | MIT OR Apache-2.0（双许可） | `rust-std-1.98.1-LICENSE-MIT.txt` + `rust-std-1.98.1-LICENSE-APACHE.txt` | 静态链入 boot exe（恒在） |

随附义务提示：PSF 许可证含商标条款（第 7 条）——分发内嵌 CPython 的产物时，命名不得
暗示 Python 软件基金会背书。OpenSSL 3.0.16 无 NOTICE 文件，Apache-2.0 第 4 条义务以
随附 LICENSE 全文履行。Rust std 双许可，任选其一即可（两份全文都收在本库）。

### 1.2 档位 → 需随附的文本

| embed_home 档 | 内嵌内容 | 需随附的许可文本 |
| --- | --- | --- |
| lean | `python312.dll` + `python312.zip` | CPython(PSF) + zlib + Rust std（MIT + Apache-2.0） |
| std | 上述 + 17 个常用 pyd + `libffi-8.dll` | 上述 + bzip2 + liblzma + mpdecimal + libexpat + libffi + UCD |
| full | 上述 + `_ssl.pyd`/`_sqlite3.pyd` + `libssl-3.dll`/`libcrypto-3.dll`/`sqlite3.dll` | 上述 + OpenSSL(Apache-2.0) + SQLite(public domain) |

这条映射有机械出口：`python -m d_side build-native ... --with-notices` 会按当次档位把对应
文本复制到产物旁 `<exe 名>.licenses/`（名单单一出处 `d_side/builder/native_build.py`
的 `_notice_set`，缺席文件会如实报 `MISSING` 而不是静默少给）。**改这张表必须同改
`_notice_set`**——三处绑定（档位名单 / `native-product/` 目录实体 / §1.4 登记表与哈希）
由 `tests/d_side/test_native_builder.py` 的 `license_ledger_gate` 用例逐条钉住：多一份没进
档位、少一份没登记、登记了不打包的文件、同尺寸而哈希不符，四种情况都报红；本机
CPython 与 §1.4 不是同一份构建时按 expected-vs-environment 口径如实 SKIP（哈希门只在
本机成立，不打死 CI）。

未内嵌 home 的档位（v1 文件夹档 / v2 纯 VM 档）exe 只携带 Rust std；若你在它旁边同时
分发 CPython home，那份 home 的文本要按上表 lean/std/full 自行补齐。

### 1.3 在场证据（采证）

构建侧 CPython 是构建机上的 python.org 3.12.10 完整安装（`find_build_dll()` 定位到
`python312.dll`，其目录即 home；T7 门 `onomachi_haruka()` 实测 PE 版本资源 3.12.10 且
Authenticode 验签通过）。具体安装位置属构建机信息，不进本台账。二进制事实：

- **版本资源**：`libssl-3.dll`/`libcrypto-3.dll` = 3.0.16；`sqlite3.dll` = 3.49.1.0；
  全部 pyd 与 `python312.dll` = 3.12.10（"Python Core"）。
- **内嵌版本串**：`_bz2.pyd` 含 "1.0.8"（及 bzip2 许可证文案片段）；`_decimal.pyd` 含
  "2.5.1"（mpdecimal `MPD_VERSION`）；`pyexpat.pyd` 含 "expat_2.7.1"；`unicodedata.pyd`
  含 "15.0.0"；`libcrypto-3.dll` 含 "OpenSSL 3.0.16"。
- **导入表**（静态/动态链入的直接证明）：`_hashlib.pyd`→libcrypto-3.dll；
  `_ssl.pyd`→libssl-3.dll+libcrypto-3.dll；`_ctypes.pyd`→libffi-8.dll；
  `_sqlite3.pyd`→sqlite3.dll；`_bz2.pyd`/`_lzma.pyd`/`_decimal.pyd`/`pyexpat.pyd`/
  `_elementtree.pyd` 无任何第三方 DLL 导入（= 相应库静态内链）；`python312.dll` 无
  zlib.dll 导入且运行期 `zlib.ZLIB_VERSION == "1.3.1"`（= zlib 静态内链）。
- **CPython externals 钉**（v3.12.10 tag 的 `PCbuild/get_externals.bat`）：bzip2-1.0.8、
  libffi-3.4.4、openssl-3.0.16、sqlite-3.49.1.0、xz-5.2.5、zlib-1.3.1；vendored
  `Modules/_decimal/libmpdec` = 2.5.1、`Modules/expat` = 2.7.1（与二进制串一致）。
- **诚实边界**：liblzma 与 libffi 的确切版本无二进制可读证据（`_lzma.pyd` 无版本串、
  `libffi-8.dll` 无版本资源、两者均不导出版本符号）——版本取自 CPython 3.12.10 官方
  构建的 externals 钉（`xz-5.2.5`、`libffi-3.4.4`），即该 DLL 的唯一合理来源。
- Rust std 版本 = 构建工具链 `rustc 1.98.1 (48a229cea)`。

### 1.4 二进制 SHA-256 登记

对"携带第三方代码的文件"逐个登记（本机构建侧原件；升级 CPython 或任一 externals 后
须重算）：

| 文件 | 版本 | 大小（B） | SHA-256 |
| --- | --- | --- | --- |
| `python312.dll` | 3.12.10 | 6945272 | `9a0e3435aaa680d868150f87ab3e388ad2eebc22f87e036155c7b4eda8cd2120` |
| `DLLs/_bz2.pyd` | bzip2 1.0.8 | 86896 | `65f610646d10d5babea080e060d244b546ec52c54012e5e937dc72dcc2e2e7bc` |
| `DLLs/_lzma.pyd` | liblzma 5.2.5 | 161136 | `e3deecc1f59a3b811c608861decd84de1e8df8bafd5e2b39188861318c5a38cf` |
| `DLLs/_decimal.pyd` | mpdecimal 2.5.1 | 262000 | `aeacfead2befcc0768063a037bb64bd32109ae09cb144e5f571b04dd7965db9d` |
| `DLLs/_elementtree.pyd` | expat 2.7.1 | 135160 | `5009a9a53c03ef8387443b5cf6ce08e5c3a79727466a0b931c5bbca915bf89ca` |
| `DLLs/pyexpat.pyd` | expat 2.7.1 | 205304 | `d615e193d1affcdbfe504e90d3621cbdcff94bf72b79d899126534507fd6d27a` |
| `DLLs/_hashlib.pyd` | （消费 libcrypto） | 68976 | `03d233dbace599168eaffec823de6ed7beec8c2a4ebfe9b8a3d8e042a59af3ba` |
| `DLLs/_ssl.pyd` | （消费 libssl/libcrypto） | 179432 | `0bc527d2dbc50009f43b2ed5d5982c4f63f4b647647ffa9eda612dcda80f6040` |
| `DLLs/_ctypes.pyd` | （消费 libffi） | 127480 | `0e56107a891100535f2da79d85a5ae65ff1227b4765bd108f8593ac1a1110d81` |
| `DLLs/libffi-8.dll` | libffi 3.4.4 | 39696 | `eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a` |
| `DLLs/libssl-3.dll` | OpenSSL 3.0.16 | 794992 | `007142039f04d04e0ed607bda53de095e5bc6a8a10d26ecedde94ea7d2d7eefe` |
| `DLLs/libcrypto-3.dll` | OpenSSL 3.0.16 | 5231472 | `ccfffddcd3defb8d899026298af9af43bc186130f8483d77e97c93233d5f27d7` |
| `DLLs/sqlite3.dll` | SQLite 3.49.1 | 1583608 | `8daa45684bf6688fca28d956b2e8942f2fa98f656675ce68e6d61dd869848a7a` |
| `DLLs/_sqlite3.pyd` | （消费 sqlite3） | 126184 | `64b51df2805c58b023a875e8ae3be7ac7f61ef664f32ca6c90f6315da47ef0bc` |
| `DLLs/unicodedata.pyd` | UCD 15.0.0 | 1140592 | `208ee1cd3cbad0828433ca7246b05be2b1ff5569983d27d296c0b38888585488` |

## 2. tool-deps/ — pyshroud 工具自身的可选依赖

pyshroud 包本体**零强制第三方依赖**（仅标准库；发布面硬门
`tests/pyshroud/test_release_surface.py` 把关）。以下三项均为可选件，缺席时对应套件或
页签明确跳过、不计失败：

| 组件 | 版本 | 许可证 | 文本 | 用途 |
| --- | --- | --- | --- | --- |
| numpy | 2.5.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0（捆绑子组件见 `numpy-2.5.3/bundled/`） | `numpy-2.5.3/LICENSE.txt` | 数学区差分/模糊测试加速（可选） |
| z3-solver | 5.1.0.0 | MIT | `z3-solver-5.1.0.0-MIT.txt` | 表达式恒等改写的 Z3 等价验证（可选） |
| dearpygui | 2.3.1 | MIT | `dearpygui-2.3.1-MIT.txt` | GUI 页签（`gui` extra，可选） |

若把 pyshroud 打成 wheel/源码包分发：wheel 元数据已声明依赖为可选 extra，用户自装；
本目录文本用于向用户披露上述三项的许可证。

## 3. dev-env/ — 仅构建/测试机（不随任何产物）

| 组件 | 版本 | 许可证 | 文本 |
| --- | --- | --- | --- |
| pytest | 9.1.1 | MIT | `pytest-9.1.1-MIT.txt` |
| iniconfig | 2.3.0 | MIT | `iniconfig-2.3.0-MIT.txt` |
| pluggy | 1.6.0 | MIT | `pluggy-1.6.0-MIT.txt` |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | `packaging-26.3/`（LICENSE + LICENSE.APACHE + LICENSE.BSD） |
| pygments | 2.21.0 | BSD-2-Clause | `pygments-2.21.0-BSD-2-Clause.txt`（作者名单：`pygments-2.21.0-AUTHORS.txt`） |
| colorama | 0.4.6 | BSD-3-Clause | `colorama-0.4.6-BSD-3-Clause.txt` |
| pip | 25.0.1 | MIT | `pip-25.0.1-MIT.txt` |
| setuptools | 80.9.0 | MIT | `setuptools-80.9.0-MIT.txt` |
| PSIV 参考实现 | ePrint 2025/222 配套（MichielVerbauwhede/ChaCha20-Poly1305-PSIV） | CC0-1.0 | `psiv-reference-CC0-1.0.txt` |

另两项构建工具（无文本可收，登记口径）：Rust 工具链 1.98.1（MIT OR Apache-2.0，产物
输出不受限，其 std 的两份许可文本见 §1）；MSVC BuildTools / Visual Studio 2022 /
Windows SDK（`rc.exe`、`cl.exe`——微软专有构建工具，其许可允许产出的 exe 无限制再分发，
工具本身不进任何产物）。

PSIV 一行是**出处登记**而非随附义务：官方 CC0 参考实现只在历史 KAT 对照中用过
（对照脚本 `psiv_kat_check.py` 从未入版控，本仓不可复跑），其代码一行未进本仓、
更未进任何产物；`d_side/builder/psiv.rs` / `tests/d_side/test_vm_gates.py` 已按此口径
措辞。

附注：`.venv` 内偶存的 fonttools、pypdf 与本项目无关（项目代码零引用），未收录。

## 4. 明确不随附（记录，非许可证券）

- **vcruntime140.dll / vcruntime140_1.dll**（MSVC 运行库，微软专有再分发件）：
  [日期略] 拍板**不打包**。boot exe 导入表自带 `VCRUNTIME140.dll` 依赖，运行前提为
  目标机已装 VC++ 2015-2022 x64 运行库
  （<https://aka.ms/vs/17/release/vc_redist.x64.exe>）。构建端提示见
  `d_side/builder/native_build.py` 的 `_redist_note()`；GUI 环境自检同口径。
- **Windows 系统组件与 UCRT**（kernel32、ws2_32、wintrust 等）：运行期加载，从不
  重分发，无随附义务。
- **源码混淆产物**（混淆后的 `.py`）：仅含用户自己的代码。第三方依赖面由发布面硬门与
  产物 AST 扫描（导入集合仅标准库）双重把关，不携带任何第三方材料。

## 5. 文本来源与维护口径

- 全部许可证文本**逐字取自权威来源**，未手打、未凭记忆：
  - 上游 tag/官方站点：zlib（madler/zlib `v1.3.1`）、bzip2（sourceware `bzip2-1.0.8`）、
    liblzma（tukaani-project/xz `v5.2.5`）、libexpat（`R_2_7_1`）、libffi（`v3.4.4`）、
    OpenSSL（`openssl-3.0.16`）、Rust（rust-lang/rust `1.98.1`）、z3（Z3Prover/z3）、
    SQLite（sqlite.org/copyright.html，正文提取）、Unicode（unicode.org/license.txt）、
    CC0（creativecommons.org）。
  - 官方发行件：mpdecimal（bytereef.org `mpdecimal-2.5.1.tar.gz` 内 `LICENSE.txt`）、
    CPython（本机 python.org 3.12.10 分发件根 `LICENSE.txt`）。
  - pip 包随附件：tool-deps 与 dev-env 各项取自本机 `.venv` 对应 dist-info 的
    `licenses/` 目录原件。
- 行尾：全部文本按仓库惯例归一为 CRLF（`scripts/normalize_eol.py`，幂等）；除行尾外
  未作任何改动。
- 采证时间：[日期略]（构建机：python.org CPython 3.12.10 完整安装、rustc 1.98.1、
  VS 2022 BuildTools）。
- 更新触发：升级 CPython（`py_minor`/构建 DLL 变更）、rustc、或任一 CPython externals
  钉版本变动时，同步更新 §1 表格、对应文本与 §1.4 的 SHA-256 登记。
- 机械把关：`tests/d_side/test_native_builder.py::license_ledger_gate`（见 §1.2）——文本
  缺席、幻影条目、同尺寸哈希不符三种脱钩都会报红，不用人肉记"该同步了"。
- §2/§3 的版本号与 `requirements-lock.txt` 同源（该文件是已验证版本快照，`start.bat`
  与 CI 的安装命令都指向它）；升级任一依赖时同改本文件与锁文件。
