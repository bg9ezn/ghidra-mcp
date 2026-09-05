# /apply_fid 实现计划（收敛版）

> 需求文档：`docs/plan/MCP-FID支持需求.md`（背景/动机/API 依据见该文）
> 本文是对需求的**收敛实现计划**，综合审核意见与本会话 API 实读修订（命名 `<lib>.<symbol>`、
> 批量主模式、采样截断、逐项容错、multi 透传、plate comment 等）。
> 目标仓库：本仓库（dev 分支，GhidraMCP 7.x）。全程中文。

**Goal:** 在 `AnalysisService` 内新增 `/apply_fid` 工具，用 Ghidra 官方 FID 公共
API 对程序（默认全程序批量扫描）执行签名匹配，命中函数事务化改名为 `<lib>.<symbol>`
（对齐 Ghidra 官方 FID 行为，如 `libcmt._initterm`；见 D5），
提供 ≤200 一段的分段容错、`max_samples` 采样截断（`truncated` 显式标志）与逐项 `errors[]`。

**Architecture:** 直接复用 `FidService`/`FidSearchResult`/`FidMatch`/`LibraryRecord`
公共 API（FunctionID.jar 已在 build.gradle 依赖）；匹配用 `processProgram` 全程序一次性
hash（同一函数只 hash 一次），`addresses` 仅作应用范围过滤（空 = 全部函数）；改名、
bookmark 与 plate comment 在同一 `executeWrite` 事务内完成，dry_run 只读不进事务。
`executeRead` 负责只读阶段（枚举/查询/匹配），`executeWrite` 负责落盘阶段。

**Tech Stack:** Java 21 + Ghidra 12.1.3 FID（`ghidra.feature.fid.*`）+ 本地 javac
全量编译验证；Python `pytest tests/unit/ -v --no-cov` + parity 测试同步 `tests/endpoints.json`。

---

## 收敛决策（本次审核修订）

### D1. 批量语义：主模式 = 全程序批量扫描

- **主模式（addresses 为空）**：`processProgram(program, fidQueryService, scoreThreshold,
  monitor)` 对全程序全部函数一次匹配。这就是批量；不再增设"多地址列表主模式"。
- **addresses（附加过滤，非主模式）**：逗号分隔地址。空 = 全部函数。
  - 服务端把地址解析为 `AddressSet`；若列表长度 > 200，**按每段 ≤200 拆段分别作为
    应用范围逐个处理**（一段一截批），段间独立容错。
  - 匹配成本不按地址放大：仍是一次 `processProgram` 全程序 hash，仅在**应用阶段**
    对落在 `AddressSet` 内的 `FidSearchResult` 做改名/统计（满足需求"同一函数 hash 一次"）。
  - addresses 每个地址仍要求可解析；整体解析失败返回 `Response.err`（不进入任何段）。

### D2. 采样截断：max_samples + truncated

- 新增参数 `max_samples`（int，默认 20）：`samples` 数组最多返回该条数。
- 当命中的样本数超过 `max_samples` 时，`samples` 只含前 `max_samples` 条，且
  **`truncated=true`**（显式声明截断，绝不静默丢数据）。
- `matched_functions`/`renamed_functions`/`per_library` 始终是完整计数，不受采样截断影响。

### D3. 逐项容错：errors[]

- 任一地址的处理失败（改名单个失败、bookmark 写入异常）**不中止整批**，
  记入 `errors[]`：`{"address", "reason"}`。
- 地址解析失败在该段内记错误并继续下一段（对齐 bulk 的 `{address,error}` 单行容错哲学）。
- 致命错误（FID 查询服务打不开、事务本身失败）才整体 `Response.err`。

### D4. addresses 上限哲学（对齐 bulk）

- 单段上限 200（`MAX_ADDRESS_PER_SEGMENT = 200`），超长按段自动拆分，**不静默丢弃**；
- 空段（`addresses` 全为空白）视为未提供，走全程序主模式；
- 段内每个地址单独 `{address, error|references...}` 式容错（对齐 get_xrefs_from 批量）。

### D5. 前缀与命名

- 改名格式：`<lib>.<symbol>`（对齐 Ghidra 官方 FID 行为，源码实读确认）。
- 依据：`ApplyFidEntriesCommand.applyTo` 最终符号名 = `FunctionRecord.getName()`
  （`MatchNameAnalysis.java:164` 的 `finalNameList = rawNames` → `addSymbolToFunction`
  → `createLabel(addr, name, ...)`）。MSVC 签名库构建时即以 `libcmt.<symbol>` 作为
  函数记录名落库（`libcmt._initterm` 形态），**不是** `LibraryRecord.family` 参与符号名
  （family 只进入 plate comment / bookmark 的 "Library:" 行）。
- 因此实现取 `fnRecord.getName()`（库内全名）即可得到 `<lib>.<symbol>`；
  若个别非 MSVC 库（第三方库）内函数名不带 `lib.` 前缀，则用
  `lib.getLibraryFamilyName() + "." + name` **补前缀兜底**（family 作为库名）。
- `symbol` 取 `FidMatchScore.getFunctionRecord().getName()`（javap 已验证 `FidMatchScore`
  声明该方法）。
- 已具 `lib.*` 前缀或非 `FUN_*` 命名函数：默认（`always_apply_labels=true`）也改名，
  幂等（新名与旧名相同则不动）；`samples` 里 `new_name==old_name` 表示已命中但无需改。
- symbol 含空格（如 `operator new`）：改名时必须 sanitize（空格→`_`，去除 `<>`, `::`, `?,`
  等非法字符），与 Ghidra 符号规则一致；sanitize 规则在本计划实现节给出。
- ⚠ 不采用 `<familyName>.<symbol>`（如 `vs2019_x64.operator new`）：family 是 .fidbf
  文件族名（`vs2019_x64`），用它会导致 relike stage2 正则 `^[a-z][a-z0-9_]*\.[A-Za-z_]`
  把 `vs2019_x64` 误判为库名，且与官方 `libcmt._initterm` 形态不一致。

### D6. multi_threshold 现实语义（对齐 FID 内建）

- `FidService.processProgram(Program, FidQueryService, float scoreThreshold, TaskMonitor)`
  **只接受一个分数阈值**；多候选（多名匹配）判定由 FID 内建常量
  `getDefaultMultiNameThreshold()` 处理（对齐 `ApplyFidEntriesCommand`）。
- 端点 `multi_threshold` 参数**保留为透传/兼容**：实现不自行实现"多候选阈值分支"，
  直接回落到 FidService 默认；多候选冲突在 `samples` 加 `"conflict": true` 标记。

### D7. bookmark 与 plate comment（对齐 FidAnalyzer）

- bookmark：`program.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS,
  "Function ID Analyzer", libName)`，仅 `create_bookmarks=true` 时写。
- plate comment：`program.getListing().setComment(entry, CodeUnit.PLATE_COMMENT,
  "Library: " + libName)`，仅 `create_plate_comment=true` 时写。
- 两开关独立；bookmark 类别沿用 `Function ID Analyzer`，plate comment 内容含
  family 名（`lib-vs2019_x64` / `libcmt` 取决于库），与 FidAnalyzer 落盘一致。

---

## 实现任务

### Task 1：端点骨架 + 参数契约

**Files:**
- Modify: `src/main/java/com/xebyte/core/AnalysisService.java`（追加方法，不改构造器）
- Test（契约单测，不入 Java 编译）：`tests/endpoints.json`（Task 5）

**Step 1：确认注入可用**
`AnalysisService` 构造器已注入 `programProvider`、`threadingStrategy`（`GhidraMCPPlugin.java:302`），
追加 `@McpTool` 方法即可被 `AnnotationScanner(Object... services)` 自动扫描，无需注册改动。

**Step 2：契约表（最终）**

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `program` | string | "" | 目标程序名 |
| `addresses` | string | "" | 逗号分隔地址（≤200/段，多段自动分批）；空=全程序主模式 |
| `score_threshold` | float | "" | 空则 `FidService.getDefaultScoreThreshold()` |
| `multi_threshold` | float | "" | 透传；空则 FID 内建默认（见 D6） |
| `always_apply_labels` | bool | true | 命中即改名（含已命名函数） |
| `create_bookmarks` | bool | true | 写 BookmarkType.ANALYSIS "Function ID Analyzer" |
| `create_plate_comment` | bool | true | 写 `Listing.setComment(addr, CodeUnit.PLATE_COMMENT, "Library: "+libName)` |
| `dry_run` | bool | false | 只读，仅统计 + would-rename samples |
| `max_samples` | int | 20 | samples 返回条数上限（≥1；超限 `truncated=true`） |

### Task 2：只读匹配阶段（executeRead）

**Files:**
- Modify: `src/main/java/com/xebyte/core/AnalysisService.java`

**Step 1：枚举 queryable 库**
`language = program.getLanguage()`；`fidService.canProcess(language)`；
`queryable_libraries` 用已验证 API：
```java
FidFileManager mgr = FidFileManager.getInstance();
List<String> ql = new ArrayList<>();
for (FidFile f : mgr.getFidFiles()) {
    if (f.canProcessLanguage(language)) ql.add(f.getBaseName());
}
```
（`FidFileManager.getInstance()` 启动即装载 `.fidbf`；`getBaseName()` 得 `vs2019_x64`；
`canProcessLanguage` 过滤当前语言可查。）若 `!canProcess` → `Response.ok` 返回
`queryable=false, renamed=0, scanned_functions=0, samples=[], errors=[]`，并在返回中带
说明 message（不算错误）。

**Step 2：open + 保护性 close**
`q = FidFileManager.getInstance().openFidQueryService(language, false)`（等价
`FidService.openFidQueryService`）；`FidQueryService implements Closeable`（javap 确认）。
必须 `try { ... } finally { q.close(); }`（防句柄泄漏，对齐 47f3666 教训）。

**Step 3：processProgram 全程序匹配**
```java
List<FidSearchResult> results = fidService.processProgram(program, q,
    scoreThreshold, TaskMonitor.DUMMY);
```
- 阈值回落：`scoreThreshold <= 0` 时用 `fidService.getDefaultScoreThreshold()`；
  `multi_threshold` **不透传给 processProgram**（其内部用 FID 内建 multi 判定，见 D6），
  仅保留参数实现"透传语义"。
- `results` 每项含 public `function` 与 `matches`（`List<FidMatch>`）。

**Step 4：地址过滤分段**
- 空 addresses → `AddressSet` = 整个程序（主模式），单段；
- 否则 `ServiceUtils.parseAddress` 逐个解析为 `AddressSet` 并**按 200 一段切分**；
- 应用阶段遍历 `results`，只处理 `AddressSet.contains(function.getEntryPoint())` 的命中。

### Task 3：落盘阶段（executeWrite + 改名 + bookmark + samples/errors）

**Files:**
- Modify: `src/main/java/com/xebyte/core/AnalysisService.java`

**Step 1：事务容器**
```java
if (dryRun) → executeRead，仅统计 + would-rename samples（不写）；
else → threadingStrategy.executeWrite(program, "Apply Function ID", () -> { ... });
```
完整逻辑（改名单个、per_library 计数、samples、errors 累积）全在事务 lambda 内；
任何异常由 lambda 抛出让事务回滚，或 catch 后记 `errors[]`（单条可降级，事务本身不废）。

**Step 2：首选匹配选择**
对每个 `FidSearchResult`：
- `matches` 非空 → 取 `score >= scoreThreshold` 的最高分 `FidMatch`（对齐 FID
  单匹配语义）。
- 多候选冲突：多候选判定由 FID 内建 `getDefaultMultiNameThreshold()` 处理（D6，不
  自行实现阈值分支）；对并列最高分仍存在多 match 时 `samples` 条目加 `"conflict": true`，
  `per_library` 计数照常。

**Step 3：改名**
```java
String libName = lib.getLibraryFamilyName();
String fnName  = fl.getFunctionRecord().getName();   // 库内全名，官方即 "<lib>.<symbol>"（libcmt._initterm）
newName = sanitize(fnName);
if (!fnName.contains(".")) {                          // 兜底：非 MSVC 第三方库 name 不带 "lib." 前缀
    newName = sanitize(libName + "." + fnName);
}
```
- `sanitize`：替换空白→`_`，剥离 `<>::?*` 等 Ghidra 非法名字符（规则见 Task 4）；
- `functionManager.renameFunction(func, newName, SourceType.ANALYSIS)`；
- 新旧名相同则不调（幂等），仍计入 `renamed` 的本批次命中统计。

**Step 4：bookmark 与 plate comment（可选，独立开关）**
`create_bookmarks=true` 时 `program.getBookmarkManager().setBookmark(entry,
BookmarkType.ANALYSIS, "Function ID Analyzer", libName)`；
`create_plate_comment=true` 时 `program.getListing().setComment(entry,
CodeUnit.PLATE_COMMENT, "Library: " + libName)`（对齐 FidAnalyzer 的 Library 落盘，
`CodeUnit.PLATE_COMMENT`/`Listing.setComment` 仓库已有先例，见 HeadlessEndpointHandler.java:860）。

**Step 5：计数与采样**
- `scanned_functions` = 处理段内函数总数；`matched_functions` = 满足阈值命中数；
  `renamed_functions` = 实际改名数（含幂等跳过时 == matched）；`per_library` 每库
  `{library, hits, renamed}`。
- `samples`：按处理顺序累积，最多 `max_samples` 条；一旦截断置 `truncated=true`。
- 每条 `{"address", "old_name", "new_name", "conflict"?}`。

**Step 6：返回**
```java
Map<String, Object> m = JsonHelper.mapOf(
  "success", true, "program", programName, "language", ...,
  "queryable", true, "queryable_libraries", ..., "scanned_functions", N,
  "matched_functions", N, "renamed_functions", N, "duration_ms", N,
  "duration_total_s", N/1000.0, "per_library", ..., "samples", ...,
  "max_samples", 20, "truncated", bool, "errors", ..., "dry_run", dryRun, "error", null);
return Response.ok(m);
```
- `queryable=false` 分支：`formattedMessage` 说明 + `Response.ok`（samples=[]，不静默）。

### Task 4：sanitize 与 helper

**Files:**
- Modify: `src/main/java/com/xebyte/core/AnalysisService.java`（私有方法）

```java
private static String sanitizeSymbol(String s) {
    StringBuilder sb = new StringBuilder();
    for (char c : s.toCharArray()) {
        if (Character.isWhitespace(c) || c == '<' || c == '>' || c == ':' ||
            c == '?' || c == '*' || c == '"' || c == '(' || c == ')' || c == ',') {
            sb.append('_');
        } else { sb.append(c); }
    }
    return sb.toString();
}
```
（对齐 Ghidra 符号规则：非法字符→下划线，避免 `renameFunction` 抛异常。）

### Task 5：契约同步与 Python/parity 测试

**Files:**
- Modify: `tests/endpoints.json` — 新增 `apply_fid` 条目：
  params `["program","addresses","score_threshold","multi_threshold",
  "always_apply_labels","create_bookmarks","create_plate_comment","dry_run","max_samples"]`，
  category `analysis`，含请求/响应样例（对齐需求第 4 节 JSON +
  truncated/max_samples/errors/dry_run/plate 字段）。
- `total_endpoints` 253 → 254。

> ⚠ parity 要求 endpoints.json 的 `params` **与 `@McpTool` 注解参数全序一致**：
> `program, addresses, score_threshold, multi_threshold, always_apply_labels,
> create_bookmarks, create_plate_comment, dry_run, max_samples`（参照
> disassemble_function 批量后 parity 通过的先例）。

**Step 1：parity 验证**
```bash
uv run --frozen python -m pytest tests/unit/test_endpoint_catalog.py -v --no-cov
```
EndpointsJsonParityTest（Java）验证 endpoints.json 与 `@McpTool` 注册一致 —— 需
`tests/endpoints.json` 参数**与注解全序一致**。参照 `disassemble_function` 批量后
parity 通过的先例。

**Step 2：编译验证**
```bash
# 用本机 JDK21 + Ghidra 12.1.3 jar 全量 javac --release 21（环境已就绪）
javac @compile/cp.txt -d compile/out src/main/java/com/xebyte/core/AnalysisService.java
# 全量 main 编译 EXIT 0
```

### Task 6：构建、打包、schema 冒烟

**Files:**
- Rebuild: `GhidraMCP-7.0.0.zip`（手动打包，无 mvn/gradle 可用——环境 workaround 已就绪）

**Step 1：zip 打包 + isDirectory 校验**
比对上次批量成功路径：stage 目录、`jar`/`cf` 打包、ZipCheck 校验 `isDirectory=true`。

**Step 2：验证**
- `uv run --frozen python -m pytest tests/unit/ -v --no-cov`（确认未引入 Python 回归，
  除 pre-existing GBK 失败项外全绿）；
- 打包后 `unzip` 抽查解出 3 文件，`javap` 确认 `AnalysisService` 含 `applyFid`。

### Task 7：CHANGELOG

**Files:**
- Modify: `CHANGELOG.md` — 追加 7.0.0 条目：`/apply_fid` 全程序 FID 批量匹配
（addresses 分段 ≤200/段、max_samples/truncated、errors[] 逐项、dry_run、
事务化改名 + bookmark + plate comment）。

---

## 命令速查

- 全量编译：`javac --release 21 @C:\Users\Administrator\AppData\Local\Temp\opencode\compile\cp.txt -d <out> <src...>`（JDK21：`C:\Users\Administrator\.cursor\extensions\redhat.java-1.52.0-win32-x64\jre\21.0.9-win32-x86_64\bin\javac.exe`）
- Python 单测：`uv run --frozen python -m pytest tests/unit/ -v --no-cov`
- Parity（Java 侧）：复用 tests/ 下的 EndpointsJsonParityTest 渠道
- 架构类验证：`javap -cp FunctionID.jar ghidra.feature.fid.service.FidService`

## 验收

1. `EndpointsJsonParityTest` 通过（`apply_fid` 在 endpoints.json 与 `@McpTool` 契约一致，参数全序）。
2. `javac --release 21` 全量 main 编译 EXIT 0。
3. 打包 zip 校验 `isDirectory`、解出文件完整；`javap` 见 `applyFid`。
4. Python 单测新增编号（endpoints.json 契约 + max_samples/truncated 逻辑）绿或 pre-existing 集外全绿。
5. `/apply_fid` 语义走查满足：主模式全程序、addresses≤200/段、max_samples+truncated、
   errors[] 逐项、dry_run 只读、单事务落盘（改名+bookmark+plate comment）、
   FidQueryService close、multi_threshold 透传。