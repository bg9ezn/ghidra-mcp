# MCP 扩展需求：批量 plate 注释写入（收敛版）

> 目标仓库：`E:\_UKUCLOUD.WORK\ghidra-mcp`（dev 分支，GhidraMCP 7.x 演化版）
> 此文档由分析会话审计产出、经 2026-09-05 审核收敛，供实现会话使用。
>
> **状态：已实现并审核通过（2026-09-05，提交 8fb225a）。** 审核结论见文末第 10 节。
> 结论依据：git 提交历史 + 当前源码实读 + `tests/endpoints.json`（仓库权威目录，`total_endpoints=254`）。
> 注：此前记录"线上插件实时 schema 239 tools"与仓库计数不一致（疑似线上实例为旧构建/口径不同），一律以
> `tests/endpoints.json`（254）与 `EndpointsJsonParityTest` 为准。

## 1. 背景与动机

relike（二进制重构系统）stage2（`stage2_lib_classify.py`）需要向函数写入确定性 plate 注释
（形如 `relike stage2: <class> library=<lib> source=<src>`），SPOffset.dll 实测 **16,639 个
非 USER_CODE 函数**需写入（首跑 ~9 分钟串行写注释，2026-09-05 实测 17:26:14 → 17:35:12，
期间无输出，全为逐条 HTTP round-trip 主导）。

现有事实（已逐条核实）：

- `batch_get_comments`（`1901222` 引入）：**读侧**多地址批量——`addresses` 为逗号分隔字符串
  （`a,b,c`），支持 `only_with_comments`；每个地址返回与 `get_comment` 相同的五类注释形状。
- `batch_set_comments`：**写侧仍单地址**——`address` 必填，`plate_comment` 为单条字符串；
  仅 `decompiler_comments`/`disassembly_comments`（pre/eol）走数组，但全部绑定**同一个 address**。
  该端点用直接的 `SwingUtilities.invokeAndWait + startTransaction`（非 `ThreadingStrategy`），
  含 data 全局 plate 质量门（`NamingConventions.checkGlobalPlateComment`）与写后 500ms sleep。
- `set_comment`（7.0.0 合并后的存活端点，`POST`）：单地址、单类型
  `plate|pre|eol|post|repeatable`（别名 `decompiler=pre`、`disassembly=eol`，缺省 `plate`）。
  单点响应为 `{status:"success", message, warnings?}`——**无 `success:true`、无 `note`**。
- `set_property`（`1454ba4`）：已有 `entries=[{address,value},...]` 批量模式，一次事务写多条，
  逐条错误跟踪，响应 `{success, entries_set, entries_failed, errors?}`。为本次设计的直接参照。
- **不存在 `CommentUtils` 类**，也无任何 `entries>500` 限制契约——本节面"限额"须作为新的显式决策，而非"对齐 set_property"。

**结论：当前不存在"一次调用写多个地址的 plate 注释"能力。** 批量写 plate 需要新增。

## 2. 分析结论与方案选择

### 2.1 为什么不新增独立 `batch_*` 端点

该项目 7.0.0 已明确废弃 `batch_` 前缀独立端点（`batch_decompile` 已合并删除；
`disassemble_function`/`get_xrefs_from` 在 `b200569` 用 one-or-many 模式合并；
`set_property` 在 `1454ba4` 用 entries 合并）。因此推荐**沿用 set_property 的
entries 统一单/批量模式**，不新增端点。

### 2.2 方案对比

| 方案 | 端点 | 模式 | 备注 |
|------|------|------|------|
| A（推荐） | 现有 `set_comment` | 新增 `entries` 数组，非空时批量 | 与 `set_property` `1454ba4` 同构；存活端点，向后兼容 |
| B | 现有 `batch_set_comments` | 把 `address` 改复数/加 entries | 语义混杂（该端点本就是"一个函数的 pre/eol 集合"），改动面大，且非 executeWrite 模式 |
| C | 新增 `/batch_set_plate_comments` | 独立端点 | 违背 7.0.0 废弃 batch_ 前缀的方向 |

**选 A**：`set_comment` 增加 `entries=[{address, comment, type?}, ...]`，`entries` 非空时
忽略 `address`/`comment`/`type` 单点参数，进入批量模式，一次 HTTP = 一次 Ghidra 事务。

## 3. 端点到参数契约

端点：`POST /set_comment`（扩展，非新增）

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `address` | string | 否* | `""` | 单点模式。`entries` 非空时忽略 |
| `comment` | string | 否* | `""` | 单点模式。空串=清除该类型注释 |
| `type` | string | 否 | `plate` | 单点模式：`plate|pre|eol|post|repeatable`（含别名） |
| `entries` | array of `{address, comment, type?}` | 否 | `[]` | 批量模式。非空时忽略 address/comment/type 单点参数 |
| `program` | string | 否 | `""` | 目标程序（query source，与存量一致） |

`entries` 元素：

- `address`（必填）：`0x<hex>` 或 `<space>:<hex>`，任意地址（data 或 code），与单点一致。
- `comment`（必填，允许空串=清除）：注释文本。缺字段按逐条失败计入 `entries_failed`。
- `type`（可选，默认 `plate`）：接受与单点相同的取值及别名
  （`plate|pre|eol|post|repeatable`、`decompiler=pre`、`disassembly=eol`）。

**批量限额（新签名契约，实现新增，非沿用现有限制）**：单次 `entries` > 500 时
`Response.err` 显式拒绝（消息注明上限与批次建议），**不静默截断**。依据：对照
stage2 16,639 条 → 34 批；单事务保持小且可观测。`SecurityConfig.MAX_REQUEST_BODY_BYTES`
= 64 MiB，500 条 body 远低于该上限，不构成约束。

## 4. 必须遵循的现有代码模式

在 `src/main/java/com/xebyte/core/CommentService.java`：

- 沿用工具注解 `@McpTool(path = "/set_comment", method = "POST", ...)`；新增 `entries`
  `@Param(value = "entries", source = ParamSource.BODY, defaultValue = "[]",
  description = "Bulk mode: array of {address, comment, type} objects. When non-empty,
  address/comment/type params are ignored.") List<Map<String, String>> entries`。
- 线程与事务：**必须**用构造器注入的 `ThreadingStrategy threadingStrategy`，
  `threadingStrategy.executeWrite(program, "Batch Set Comments", () -> { ... })`
  （Runnable 重载）。参照 `ProgramScriptService.batchSetProperty`（`1454ba4`）。
  理由：CommentService 已注入但当前未用；`ThreadingStrategy` 在 GUI 模式封装
  `invokeAndWait`、headless 模式直接同步块执行——这正是该项目维护 headless 与 GUI
  端点并行的核心要求。**不要**复制 `batch_set_comments` 里手写 `startTransaction` 的方式。
- 逐条错误跟踪：事务内对每个 entry 解析地址→按 entry.type 写注释；单条失败加入集中
  `errors` 列表（字符串，对齐 `batchSetProperty`：缺字段/地址解析失败/写入异常均记录），
  `continue` 不中断整批；`successCount`/`errorCount` 原子计数。
- 注释写入（**修正：本仓库无 `CommentUtils.setPlateComment`**）直接用 Ghidra API：
  - 统一 `program.getListing().setComment(addr, commentType, text)` 即可同时覆盖
    函数与 data 全局（`batch_set_comments` 已证明 listing 路径对二者都生效）；
    空串 → `null`（清除），非空 → 文本。
  - entry.type 复用单点 `setComment` 的 `plate|pre|eol|post|repeatable`（含别名）映射。
  - 分类计数：`plate_set`/`pre_set`/`eol_set`/`post_set`/`repeatable_set`，损失度低可省略。
- plate 写后处理（对齐单点语义，批量化）：
  - 事务结束后 `program.flushEvents()` 刷新 decompiler 缓存。
  - **不复制** `batch_set_comments` 的 `Thread.sleep(500)`（粗暴延迟，34 批会凭空 +17s）；
    以 flushEvents 为准，验收标准 6 验证 plate 即时可见。
  - 结构警告 `NamingConventions.validatePlateCommentStructure` 对 plate 文本**按批聚合**
    （带地址前缀）放入 `warnings`，避免 500 条逐条刷屏。
- 返回：`Response.ok(JsonHelper.mapOf(...))` / `Response.err(...)`。批量响应形状：
  `success` + `entries_set`/`entries_failed` +（有失败时）`errors` + (可选) `program`。
  **不要返回 `note: "Call save_program..."`**（那是 property 服务约定，注释端点从不发）。
- `tests/endpoints.json` 需同步 `set_comment` 的 params（追加 `entries`）——
  `EndpointsJsonParityTest` 会校验注册 params 与目录一致（离线 JUnitCore 即可跑）。

在 `python/bridge_mcp_ghidra/dispatch.py`：

- `get_timeout()` 增加 `set_comment` 分支，镜像 `set_property`（第 51-54 行）：
  `count = len(payload.get("entries", [])); if count > 1: return min(base + count * 3, 600)`。
- `_normalize_post_payload()` 增加 `set_comment`：`entries` 可能是 MCP 桥传入的 JSON 字符串。
  现 `_coerce_comment_entries` 会丢弃 `type` 字段，故**为 set_comment 增加保留 `type` 的归一并入**
  （扩展现有 helper 或添加带 `type` 的变体），并把 `"set_comment"` 加入第 98-103 行分支。
  顺序保证：`dispatch_post` 先 `_normalize_post_payload`（289）后 `get_timeout`（292），
  因此 timeout 的 entries 计数已基于归并后的列表。

## 5. 响应（批量模式）

```json
{
  "success": true,
  "entries_set": 499,
  "entries_failed": 1,
  "errors": ["Invalid address 'xyz' 0xbad: ..."],
  "warnings": ["0x140001000: plate first line should summarize... (relike stage2 ...)"],
  "program": "SPOffset_x64.dll"
}
```

- `success:false` 仅当整批事务抛异常（由 `executeWrite` 回滚）或 entries>500 被拒。
- 单条失败只进 `errors`/`entries_failed`，不使整批失败（对齐 `batchSetProperty`）。

## 6. 验收标准

1. 一个 HTTP 调用写 ≥2 个地址的 plate 注释成功；对同一地址逐条 `set_comment` 后结果完全一致（用 `batch_get_comments` 复核）。
2. `entries` 非空时忽略单点参数；`entries` 为空/缺省时与旧单点行为完全一致（向后兼容）。
3. 单条地址非法/缺字段 → 计入 `entries_failed` 并附 `errors`，不中断整批；整批事务失败 → `success:false`。
4. 空串 `comment` 清除该类型注释，非空写入，与单点语义一致；`type` 缺省为 plate，别名 `decompiler`/`disassembly` 生效。
5. 限额：`entries` > 500 → 显式 `Response.err`，不静默截断（新契约，见第 3 节）。
6. 性能：16,639 条 plate 按 500/批 → 34 批，首跑写注释段从 ~9 分钟降到 <60 秒（不含 flushEvents 后校验）。
7. `pytest tests/unit/ -v --no-cov` 全绿（含 dispatch 新增用例：set_comment 批量超时缩放、单点不缩放、entries 归一并保留 type）；Java 侧 `EndpointsJsonParityTest` 通过、`mvn clean compile -q` 通过。

## 7. 变更文件清单（预估）

| 文件 | 变更类型 | 说明 |
|------|---------|------|
| `src/main/java/com/xebyte/core/CommentService.java` | Modify | `set_comment` 增 `entries` 批量模式 + 批量辅助方法（executeWrite、逐条错误、限额、聚合 warnings、flushEvents） |
| `python/bridge_mcp_ghidra/dispatch.py` | Modify | `get_timeout()` 增 `set_comment` 分支；`_normalize_post_payload` 增 set_comment entries 归一并保留 `type` |
| `tests/endpoints.json` | Modify | `set_comment` params 追加 `entries` |
| `tests/unit/` | Modify | 新增 set_comment 批量超时缩放/单点不缩放/entries 归并单测 |
| `CHANGELOG.md` | Modify | 记录 v7.0.0 后批量写注释变更 |

## 8. 兼容性说明

- 完全向后兼容：单点 `set_comment(address, comment, type)` 不受影响。
- 无需新增独立端点：复用 `/set_comment` 路径，schema 由 `@McpTool` 自动生成。
- 客户端 relike：`common/mcp_client.py` 增加 `set_comments_batch()`（按 500/批分页，
  entries 内可带 per-entry `type`，默认 plate），stage2 注释段改用批量模式，
  首跑不再被逐条写注释拖慢。

## 9. 修订记录（本轮审核 2026-09-05）

1. 工具数订正：`239 tools`（线上实例口径）→ 仓库权威 `tests/endpoints.json`=254。
2. 修正 `CommentUtils.setPlateComment` 引用：仓库不存在该类，改用 `Listing.setComment(PLATE_COMMENT, ...)` + `NamingConventions.validatePlateCommentStructure` 聚合。
3. 500 限额由"对齐 set_property 契约"改为**新的显式契约**（set_property 无任何条数限制）。
4. 移除响应中的 `note: "Call save_program..."`（纯 property 服务约定）。
5. 明确不复制 `batch_set_comments` 的 500ms sleep，改纯 `flushEvents`，并纳入验收 6。
6. 补充 `dispatch.py` 的 `_normalize_post_payload` 需求与顺序依赖（先归并后算超时）。
7. 明确批量写入线程模型：必须 `ThreadingStrategy.executeWrite`（headless/GUI 双模式对等），
   不复用存量注释代码的手写 `startTransaction`。
## 10. 审核结论（2026-09-05，实现后复审）

**结论：8fb225a 完整实现第 3/4/5 节契约与第 7 节全部 5 个变更文件，验收 1–5、7 通过；验收 6（性能）待 relike 侧接入批量后实测。**

逐项核对：

- 契约（第 3 节）：`entries=[{address, comment, type?}]`、非空时忽略单点参数、500 限额显式
  `Response.err`、空串清除、type 别名映射——均与 `CommentService.setComment`/`batchSetCommentEntries`
  实现一致。响应含 `success/entries_set/entries_failed/plate_comments/program/errors?/warnings?`，
  无 `note: save_program`（符合第 4 节修正）。
- 线程模型：`ThreadingStrategy.executeWrite(program, "Batch Set Comments", ...)` ✓；
  未复制手写 `startTransaction` 与 500ms sleep ✓；事务后 `flushEvents`（有写入才刷）✓；
  plate 结构警告带地址前缀聚合 ✓。
- Headless 对等：`HeadlessEndpointHandler` 两处调用适配 5 参签名 ✓。
- dispatch.py：`get_timeout` set_comment 分支（镜像 set_property）、
  `_coerce_comment_entries_with_type` 保留 per-entry type、归并先于超时计算 ✓。
- `tests/endpoints.json` 同步 entries 参数，`EndpointsJsonParityTest` OK (5 tests) ✓。

补充执行（本轮审核会话完成）：

1. **test_gradle_tasks.py 环境失败修复**：原 GBK 解码崩溃只是表象，真实根因是裸 shell 无
   JAVA_HOME 且 gradle 分发包无法经 TLS 引导（PKIX）。修复：测试自行定位 JDK
   （JAVA_HOME → PATH → 常见安装根目录，镜像 build.bat Find-Jdk）、subprocess 加
   `encoding="utf-8", errors="replace"`、`gradlew --version` 探测不可用时 skip
   （对齐套件既有平台 skip 惯例；权威构建路径 build.bat 本就不依赖 gradle）。
   至此 `pytest tests/unit/` 不带任何排除项也全绿（gradle 用例转为环境 skip）。
2. **mcp_schema.snap 同步（提前于"下次联调"完成）**：活插件仍为旧构建，改用离线路径——
   新增 build/SchemaDump（未入库）经 `AnnotationScanner.generateSchema()` 从当前源码
   生成权威 schema，按 runner.normalize() 归一化后写入快照。count 235 → 252
   （GUI 插件 schema；差的 4 个 `/configure_analyzer`、`/delete_project`、`/health`、
   `/list_projects` 为 headless 独有 manual 路由，GUI schema 本就不含）。
   顺带修复 offline `ServiceFactory` 漏装 `PromptPolicyService`（插件实际装配，
   缺它则 `/prompt_policy` 从扫描中消失）。**快照与新构建的部署后 schema 一致性
   将在下一次真实联调时由 conformance suite 复核。**
3. relike 客户端 `set_comments_batch()` 不在本仓库，仍待 relike 侧实现（见第 8 节）。
