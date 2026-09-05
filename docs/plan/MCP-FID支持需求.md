# MCP 扩展需求：Function ID (FID) 签名库应用工具

> 目标仓库：`E:\_UKUCLOUD.WORK\ghidra-mcp`（dev 分支，GhidraMCP 7.x 演化版）
> 此文档由分析会话产出，供实现会话使用。所有结论均基于对 Ghidra 12.1.3 源码与
> 该仓库现有代码的实读，非猜测。

## 1. 背景与动机

relike（二进制重构系统）stage2（`stage2_lib_classify.py`，阶段 M2-B2）需要用 Ghidra 的
Function ID 识别 MSVC CRT / MFC / 第三方静态库，命中后用 `lib.xxx` 函数名重命名，
stage2 据此标记 `LIBRARY_CONFIRMED`。

现有事实：

- Ghidra 12.1.3（`D:\crack\ghidra\ghidra_12.1.3_PUBLIC`）**自带 10 个 `.fidbf`** 签名库：
  `Ghidra\Features\FunctionID\data\{vs2012,vs2015,vs2017,vs2019,vsOlder}_{x86,x64}.fidbf`，
  覆盖 MSVC CRT / 标准库。`.fidbf` 是 Ghidra 官方分发格式（raw 只读库），**不是用户可编辑的 `.fidb`**。
- 源码证实自动发现：`ghidra.feature.fid.db.FidFileManager.findDeliveredFidFiles()`
  调 `Application.findFilesByExtensionInApplication(".fidbf")`，启动即把安装目录下所有 `.fidbf`
  加载为 installed 库。`FidAnalyzer.getDefaultEnablement()` 返回 true。
- 因此 **"Ghidra 没有可用签名库" 是错误推断**（stage2 现有注释如此，需纠正）。
- 实际瓶颈在运行通道：
  - headless `analyzeHeadless -postScript` 加载我们的脚本报 `Script is not supported` /
    `Script not found`（已验证，此环境脚本 provider 不可用）。
  - MCP 桥的 Swing/EDT 线程限制（此前 crk-xnest 实测 18 次失败，`scheduleWorker may not
    be invoked from Swing thread`）说明**不能靠桥去执行任意 Ghidra 脚本**。
  - 因此正确方案是**在 MCP 插件内部直接实现 FID 应用逻辑**（插件跑在 Ghidra 进程内，
    有 Transaction + Tool 上下文），对外暴露一个专用工具。

## 2. 交付内容概述

在 `ghidra-mcp` 仓库的 Java 插件中新增一个 MCP 工具（端点），功能：

1. 枚举当前程序的 FID 签名库支持情况（哪些 `.fidbf` 可查该语言）。
2. 对程序（可限定地址范围或默认全部函数）执行 FID 匹配。
3. 把命中函数重命名为 `<lib>.<symbol>` 形式（与 `FidAnalyzer` 一致，如
   `libcmt._initterm`），写 bookmark（可选）与 plate comment（可选，FidAnalyzer 会在
   bookmarks 与 plate comment 里落 `Library:` 信息），全部在事务内一次提交。
4. 返回命中统计：每库命中数、函数名变更清单（批内前 N 条 + 总数）、耗时。

## 3. 必须遵循的现有代码模式

在 `src/main/java/com/xebyte/core/AnalysisService.java`：

- 工具格式：`@McpTool(path = "/xxx", method = "POST", description = "...", category = "analysis")`，
  参数用 `@Param(value = "name", defaultValue = "", description = "...")`。
  `programName` 参数走 `ServiceUtils.getProgramOrError(programProvider, programName)`。
- 线程与事务：必须用构造器注入的 `ThreadingStrategy threadingStrategy`，
  `threadingStrategy.executeWrite(program, "txName", () -> { ...; return null; })`
  （参考现成 `run_analysis` 端点 `AnalysisService.java:227`）。**不要**自己开 Transaction。
- 返回：`Response.ok(JsonHelper.mapOf(...))` / `Response.err(...)`。
- 端点注册：`@McpTool` 注解会被框架扫描自动注册，无需手动改注册表。
  `tests/endpoints.json` 需同步新增该端点的契约样例。

## 4. 端点到参数契约

工具名（path）建议：`/apply_fid`

| 参数 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `program` | string | 否 | "" | 目标程序名（多程序时指定） |
| `addresses` | string | 否 | "" | 逗号分隔地址；空 = 全部函数（批量主模式）；>200 按 200/段自动分段处理 |
| `score_threshold` | float | 否 | `FidService.getDefaultScoreThreshold()` | 单匹配分数阈值 |
| `multi_threshold` | float | 否 | `FidService.getDefaultMultiNameThreshold()` | 多名匹配阈值（透传；FID 内部多候选判定用） |
| `always_apply_labels` | bool | 否 | true | 对命中函数总是改名（含已是命名函数） |
| `create_bookmarks` | bool | 否 | true | 命中处写 bookmark（类别 `Function ID Analyzer`） |
| `create_plate_comment` | bool | 否 | true | 命中函数写 plate comment（`Library: ...`） |
| `dry_run` | bool | 否 | false | 只统计不落盘，返回 would-rename 列表 |
| `max_samples` | int | 否 | 20 | `samples` 返回条数上限；命中数 > 上限时 `truncated=true` |

返回 JSON：

```json
{
  "success": true,
  "program": "SPOffset.dll",
  "language": "x86:LE:64:default",
  "queryable": true,
  "queryable_libraries": ["vs2019_x64", "vsOlder_x64"],
  "scanned_functions": 44955,
  "matched_functions": 320,
  "renamed_functions": 310,
  "duration_ms": 12400,
  "duration_total_s": 12.4,
  "per_library": [
    {"library": "vs2019_x64", "hits": 180, "renamed": 175},
    {"library": "vsOlder_x64", "hits": 140, "renamed": 135}
  ],
  "samples": [
    {"address": "18001000", "old_name": "FUN_18001000", "new_name": "libcmt._initterm" }
  ],
  "max_samples": 20,
  "truncated": false,
  "errors": [],
  "dry_run": false,
  "error": null
}
```

成功/语义约定：
- `queryable=false`：该语言无可用库，`renamed=0`，不算错误（可能 `Response.ok`，
  调用方据 `queryable` 分支；但为避免静默，推荐在 `samples=[]` + 提示性 message）；
- 任一命中函数改名失败：不中止，计入 `errors` 数组（`{"address","reason"}`）；
- 当命中的样本数超过 `max_samples` 时，`samples` 只含前 `max_samples` 条且
  `truncated=true`（**显式声明截断，绝不静默丢数据**）；`matched_functions`/
  `renamed_functions`/`per_library` 始终为完整计数，不受采样截断影响。
- `addresses` > 200：服务端按 ≤200/段自动拆分逐段处理，段间独立容错，不静默丢弃；
  整体地址解析失败才 `Response.err`，单个地址解析失败在该段记 `errors[]`。
- `multi_threshold`：FID 内部多候选判定（`ApplyFidEntriesCommand` 规则），透传默认即可。
- 全程必须在一个 `executeWrite` 事务内完成改名与 bookmark（要么全成要么记录失败项，
  **不允许半事务**）；dry_run 时只读不改、不进入写事务。

## 5. FID 核心逻辑（直接复用官方 FID jar 的公共 API，不重新发明）

FunctionID.jar（`Ghidra/Features/FunctionID/lib/FunctionID.jar`）已含所需公共类，插件
直接 import 即可，无需引入额外依赖：

- `ghidra.feature.fid.service.FidService`：
  - `boolean canProcess(Language)` — 语言是否有可用库
  - `float getDefaultScoreThreshold()` / `float getDefaultMultiNameThreshold()`
  - `FidQueryService openFidQueryService(Language, boolean openForUpdate)`
    — 内部即 `FidFileManager.getInstance()` 自动装载 `.fidbf`
  - `List<FidSearchResult> processProgram(Program, FidQueryService, float scoreThreshold,
    TaskMonitor)` throws CancelledException/VersionException/IOException
    — 对全程序做匹配，**同一函数 hash 一次**（不要 per-function 重复调用）
- `ghidra.feature.fid.service.FidSearchResult`：公共字段 `function`、`matches`
  （`List<ghidra.feature.fid.service.FidMatch>`）
- `ghidra.feature.fid.service.FidMatch extends FidMatchScore`：`getLibraryRecord()`、
  （`FidMatchScore` 提供分数聚合）
- `ghidra.feature.fid.db.LibraryRecord`：`getLibraryFamilyName()`、
  `getLibraryVersion()`、`getLibraryVariant()`

改名格式（对齐 FidAnalyzer 行为，源码实读确认）：
- 命中单一强匹配 → `<lib>.<symbol>`：符号名 = `FidMatchScore.getFunctionRecord().getName()`
  （库内函数全名，MSVC 库构建时即落库为 `libcmt.<symbol>`，`libcmt._initterm` 形态，
  依据 `ApplyFidEntriesCommand` 最终 `createLabel(addr, name)`，family 不参与符号名）。
- 实现取 `fnRecord.getName()`；若个别非 MSVC 库的 name 不带 `.`（无 `lib` 前缀），
  用 `lib.getLibraryFamilyName() + "." + name` 兜底补前缀。
- ⚠ 不使用 `<familyName>.<symbol>`（`vs2019_x64.xxx`）：family 是 .fidbf 文件族名，
  会破坏 stage2 正则 `^[a-z][a-z0-9_]*\.[A-Za-z_]` 的库名语义。
- 多候选：判定由 FID 内建多候选规则处理（`ApplyFidEntriesCommand`，内部用
  `getDefaultMultiNameThreshold()`），`multi_threshold` 参数**透传默认即可**；冲突记入
  返回 samples 的 `conflict` 标记。
- **不要覆盖**已有 `lib.*` 模式名之外的已命名函数，除非 `always_apply_labels=true`。
  （保守默认与 M2 的不对称性一致：库未确证不跳过；这里是"确证才改"。）
- bookmark：`program.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS,
  "Function ID Analyzer", libName)`（bookmark 只写 `create_bookmarks=true`）。
- plate comment：`program.getListing().setComment(entry, CodeUnit.PLATE_COMMENT,
  "Library: " + libName)`（对齐 FidAnalyzer 的 Library 落盘；只写
  `create_plate_comment=true`。libName 用 `lib.getLibraryFamilyName()`）。

## 6. 推荐实现位置与步骤

1. 在 `src/main/java/com/xebyte/core/` 新增 `FidService.java`（注意与
   `ghidra.feature.fid.service.FidService` 的包隔离，建议类名 `FidAnalysisService.java`
   **避免与官方类同名歧义**），或在 `AnalysisService.java` 追加私有方法 + 一个 `@McpTool`。
   推荐后者（改动最小、复用注入的 threadingStrategy/programProvider）。
2. 方法骨架：

   ```java
   @McpTool(path = "/apply_fid", method = "POST", description = "Apply Function ID "
       + "signature matching; renames matched functions to <lib>.<symbol>", category = "analysis")
   public Response applyFid(
       @Param(value = "program", defaultValue = "") String programName,
       @Param(value = "addresses", defaultValue = "") String addresses,
       @Param(value = "score_threshold", defaultValue = "") Float scoreThreshold,
       @Param(value = "multi_threshold", defaultValue = "") Float multiThreshold,
       @Param(value = "always_apply_labels", defaultValue = "true") boolean alwaysApply,
       @Param(value = "create_bookmarks", defaultValue = "true") boolean bookmarks,
       @Param(value = "create_plate_comment", defaultValue = "true") boolean plateComment,
       @Param(value = "dry_run", defaultValue = "false") boolean dryRun,
       @Param(value = "max_samples", defaultValue = "20") int maxSamples) {
   ```

   - 默认值取 0/false/"" 时回落到 `FidService` 默认，避免协议层缺省值歧义。
   - `multi_threshold` **透传**：`processProgram` 只接受单个分数阈值，多候选判定由
     FID 内建 `getDefaultMultiNameThreshold()` 处理（对齐 `ApplyFidEntriesCommand`）。
   - 解析 `addresses` 为 `AddressSet`（空 = 全地址，即批量主模式）；列表 > 200 按
     ≤200/段自动拆分处理。整体解析失败返回 `Response.err`，单个地址失败记 `errors[]`。
   - samples 受 `max_samples` 约束，超额置 `truncated=true`；改名、bookmark 与
     plate comment 同事务。
   - 只读阶段（枚举、canProcess、openFidQueryService、processProgram）用
     `threadingStrategy.executeRead`；改名为 `executeWrite`（当 `dryRun=false` 时）。
   - 在非 Swing 线程路径调用（插件端点本身已是工作线程；不要切到 EDT 再跑
     `resultingSize` 等），`processProgram` 需要 `TaskMonitor`（`TaskMonitor.DUMMY` 足够；
     长任务建议 `TaskMonitorSplitter`/进度日志，非必须）。
3. 若确实认成"分析器"风格更贴近现状：`AutoAnalysisManager` 的简化路径是
   `FidAnalyzer extends Analyzer`，但**默认含 Function ID 的 `run_analysis`（reAnalyzeAll）
   即已覆盖**——`/apply_fid` 的差异化价值在于**可控地址集 + 事务化 + 统计回报**，且
   避免 `run_analysis` 对全程序做完整分析（慢、可能改动注册/分析状态）。两条路径并存时
   文档中写明使用者优先 `/apply_fid`。
4. 测试：
   - `tests/endpoints.json` 加 `apply_fid` 契约（请求/响应样例）。
   - 参考现有 `XrefCallGraphServiceValidationTest` 风格做离线/写入类单测；
   - 若需 FID 命中函数做夹具，建议建一个链接 `/MT` 静态 CRT 的合成 DLL（自有导出 +
     静态 CRT 函数），用它的函数名断言 `lib.*` 前缀出现。但这仅当 test 环境可构建时。
5. 构建/部署：`./gradlew build`（Gradle 是主构建，pom.xml 仅供版本元数据）。产物
   `GhidraMCP-<ver>.zip` 解压到 `D:\crack\ghidra\ghidra_12.1.3_PUBLIC\Extensions\`
   后重启 Ghidra（relike 侧用 `envtool.py server restart`）。插件装载后
   `/mcp/schema` 应出现 `apply_fid`。

## 7. 消费端（relike stage2）联动（实现会话可视需要一并对齐）

`E:\_UKUCLOUD.WORK\relike\tools\rebin\stage2_lib_classify.py`：
- B2 匹配当前只在读函数名regex（`^[a-z][a-z0-9_]*\.[A-Za-z_]`）命中才算。改造为：
  1. 调用 `/apply_fid`（dry_run=false）→ 取得 renamed_functions + samples；
  2. 用返回的 `new_name` 前缀 `lib.`（split(".",1)[0] 得库名如 `libcmt`）判定
     `LIBRARY_CONFIRMED`，或读回 `/list_functions_enhanced` 获取改名后的函数表再走原有 `fid_re` 匹配。
- 修正注释中"no .fidb → no match"的错误结论。
- M2 风险表 B2 覆盖项移除"签名库缺失"，改记"命中取决于目标链接方式（动态 CRT 走 B1）"。

## 8. 已知坑与边界（实现时勿踩）

- `.fidb` vs `.fidbf`：**只读 `.fidbf` 是官方分布格式**，够用；不需要、也不应尝试
  把用户库转成 `.fidb`（MFC 非内置库才需要 User-Add FID，本期不做）。
- `processProgram` 一次性全程序处理——**不要在函数循环里调用**。
- `FidQueryService` 用后必须 `close()`（防句柄泄漏；参考 `47f3666` 修的 open_program 泄漏教训）。
- 改名、bookmark 与 plate comment 同事务；`executeWrite` 内部已是正确开启的事务容器。
- 端点名用 `apply_fid`（避免与官方类/工具名撞车造成 bridge schema 冲突）。
- Ghidra 12.1.3 需要 JDK ≥ 17（本机 `D:\jdk\jdk-26` 可用，`build.gradle` 应已配置）。
- 不要依赖 `AutoAnalysisManager` 的 `analyzeAll` 做 FID——那是 `run_analysis` 的职责；
  `/apply_fid` 用 `FidService` 直连库里函数，只写命中改名，不动分析状态。

## 9. 验收标准

1. `GET /mcp/schema` 含 `apply_fid`；`./gradlew build` 通过。
2. GUI 打开 SPOffset.dll 后调用 `/apply_fid`（dry_run=false）：
   - 返回 `queryable=true`；若目标为纯导出 DLL、少静态库函数，`matched_functions`
     可较小（诚实计数），但返回结构完整、耗时有限（无卡死）。
3. 对链接静态 CRT 的合成样例：命中函数名变为 `lib*.xxx`，SPOffset 侧 MCP 读函数名
   可见 `lib` 前缀，stage2 B2 相应 `fid_hits>0`。
4. 幂等：重复调用不重复改名（已有 `lib.*` 名的不再覆盖），耗时下降为仅扫描。
5. 无句柄泄漏：连续 20 次调用后 GUI 内存/句柄稳定。
6. plate comment 与 bookmark 各受独立开关控制；`create_plate_comment=true` 时命中函数
   落 `Library: <familyName>` plate comment，`false` 时不落。