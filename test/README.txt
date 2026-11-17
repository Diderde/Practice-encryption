本目录是 <PROVIDER> 会话 sess_<ID>（g5-a 逆向 T1-T8）的【净化公开副本】。

净化规则（v2，2026-10-13 复核后重做）：
  - 剔除 rollout\（552MB 模型 IO，内嵌完整系统提示与环境块）与 audit\（二阶审计副本）；
  - 全部本机绝对路径 → <G5A_WORKDIR>/<PROJECTS>/<DEVROOT>/<USERHOME>/<PY312>/<PY312_SCRIPTS>/<CDB>；
  - 用户名/账号/提供方/会话 ID/审计目录约定 → 占位符；
  - 逐调用标识 call_<24hex> 与结果 UUID → 按 createdAt 顺序重映射为 call_0001..call_0066；
    无 artifact 的后台执行调用 → call_0067（文件名、toolCallId、正文引用、exec 日志同步改名）；
  - 后台任务 UUID → <TASK_ID>；
  - 时间：本机时钟整体 −3h 平移，日期掩为 <会话日期>/<会话日期−1>，createdAt → clockRef（去掉毫秒）。
    分钟与秒值原样保留，因为正文若干推断依赖具体分钟数（如 "h3 = minute + 3? 02:31 → 34"）。
    代价：与原始会话库的时间相关性只是被打乱，并未消失——持库者可按分钟/秒模式复原。
  - T1~T8 的逆向叙事、equivalent.py 与 notes 内容完整保留；
    题目侧密钥材料（integ_key、.v0 根密钥、physmap、blake2s 中间值）按决定【原样保留】，
    它们来自题目二进制而非本机，不影响匿名性。

占位符清单：
  <PROVIDER> .<PROVIDER> <AUDITDIR> <TASK_ID> <ID> <USER> <USERHOME>
  <G5A_WORKDIR> <PROJECTS> <DEVROOT> <AVDIR> <PY312> <PY312_SCRIPTS> <CDB>
  <安全钩子> <会话日期> <会话日期−1>

已知保留项（非本机信息）：
  - 题目文件的 mtime：2025-04-08（python312.dll）、2026-10-05（python312.zip）、<会话日期−1> 13:17（原件部署）；
  - 进程号、镜像基址、哈希输出等运行时数值。

结构：artifacts\（66 个工具结果，call_0001..call_0066）| exec\（call_0067-stdout.log）| export\conversation.md（可读对话）。
