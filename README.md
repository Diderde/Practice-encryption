# Practice-encryption

一个对可分发的 Python 源码树做分层混淆的构建工具。

## 前言

**这只是一个练手项目，请不要完全信任该工具并真的希望它能够完全保护你的项目。**

这个项目有源码混淆跟原生exe两种混淆方式可选择，前者可以用于给新入门想学习反混淆的新人进行测试，后者可以给想要深入研究反混淆的提供练手项目，或者给Vibe coder测试模型能力如何。

项目的主要作用是提升逆向难度，防止被一些人通过Flash类型的LLM模型以极低的成本完成逆向。我相信在MATE环境下不存在任何不可攻破的防护手段，所以要做的便是提升逆向成本，让进攻者确信这个项目的逆向成本大于之后的收益，因此这个项目 **不承诺任何“不可攻破”或者“完全保护”的能力。**

我使用了一些相对较为冷门的算法以及一些数学论文，因为实测时候发现一些模型会试图“猜测使用了什么算法”而尝试算法暴力碰撞，试图使用穷举法来完成逆向。

*备注：如果你真的希望不会被逆向，那建议直接把项目本身写成屎山即可:)*

## 原理

- **源码文本混淆（pyshroud/）**：构建期以 seed 驱动多趟变换——字符串按构建期密钥加密、表达式做恒等改写、标识符与结构逐构建随机化。等价性由执行式闸门（实跑产物内联片段、逐轨道比对）与差分/模糊测试把关，不是形式化证明；同源码不同 seed 的产物逐字节不同。
- **原生产物（d_side/）**：源码编译为自研 ISA 字节码，分块认证加密后嵌入 Rust 引导器；密钥由 seed 经 HKDF 派生、默认不随产物分发（构建期可选内嵌档），运行期按需解密、逐条解释执行，不依赖 CPython。附反调试与 .text 自校验（定位为拖延档）。
- **数学区（b_side/）**：置换、MBA、谓词等数学对象与等价性闸门集中管理，供上述各层取用。
- **已废弃（c_side/）**：原计划的轻量体积裁剪档，未启动即废弃，仅留状态说明（`c_side/Now.md`）。

## 使用

- CLI：`python -m pyshroud build`（minimal / standard / max 三档；standard 套单层自解密壳，max 套双层）与 `python -m pyshroud check`（五项结构指标 cyclomatic / ast_nodes / string_entropy / string_residuals / ident_residuals，外加体积膨胀系数 Fa）
- 图形界面：双击 `start.bat`（自动体检并代装依赖），或 `.venv/Scripts/python -m pyshroud gui`
- 数学对象与闸门集中在 `b_side/`（全项目数学区）；`d_side/` 为原生产物构建（对应 GUI 的"原生 exe"页签）：`python -m d_side build` 出加密容器、`build-native` 出独立 exe——需要 `rustc` 与 MSVC 的 `rc.exe`（经 vswhere 定位，**不用 cargo**），以及一份 CPython 3.12 安装（`python312.dll` 与其 `Lib`，可用 `--embed-home lean|std|full` 打包进产物、首启释放到本地缓存）
- 许可证：工具自身为 GPL-3.0-only（`LICENSE`），并附产出例外（`LICENSE.exception`）——用本工具产出的文件（含 native exe 与其内嵌的引导器/壳代码）不受 copyleft 约束，可按你选定的条款分发
- 第三方组件与许可证：集中台账在 `Licenses/`（各第三方全文 + 在场证据 + 档位映射；随 native exe 分发的第三方全部为宽松许可证，vcruntime 不随附）

## 测试

```
python -m venv .venv
.venv/Scripts/python -m pip install --require-hashes -r requirements-lock.txt   # 已验证版本 + 摘要校验
.venv/Scripts/python scripts/run_suites.py          # 全部套件，聚合退出码
.venv/Scripts/python scripts/run_suites.py --fast   # 跳过五个耗时套件
```

可选依赖（numpy、z3-solver、dearpygui==2.3.1）缺席时相应套件或页签明确跳过，不计失败。`requirements-lock.txt` 是已验证版本快照（逐包 sha256 摘要，装时 `--require-hashes` 校验——本地环境走镜像、CI 走官方源，同一份摘要证明两条渠道拿到同一批字节）；`start.bat` 与 CI 的安装命令与之对齐。

## 故障处理

- 合法且刻意混淆的产物可能被包索引、杀软或企业网关误报。处置：保留构建 seed 与输入源码自证可复现，按平台渠道申诉；不通过改产物形态规避检测。

## 必须注意

- **请使用时候遵守所在国家或地区的法律法规，请不要用于任何违法或者违规的用途，对于所造成的一切后果，本项目概不负责**