# disassemble_function / get_xrefs_from 批量(one-or-many 统一模式)实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 为 `disassemble_function` 与 `get_xrefs_from` 提供 one-or-many 统一模式（新增逗号分隔参数，不新增独立端点），压缩 HTTP 往返开销。

**Architecture:** 完全对齐项目既有统一模式（`decompile_function`：GET + `address` 单模式/ `functions=` 批量模式；helper 合并不成独立 @McpTool，description 注明 "Replaces batch_..."）。**不新增** `batch_` 前缀端点（项目已废弃该用法；`batch_decompile` 已合并删除；`set_property` 同样用合并不加独立端点的 `entries` 模式）。保持**只读端点 GET**（两个端点均是只读，不引入 GET→POST breaking change；`@McpTool.method()` 为单值无法 GET/POST 双注册，故走 GET query）。**非 breaking**（单点地址用法完全不受影响）。

**Tech Stack:** Java (Ghidra extension), Python (bridge timeout scaling), JSON (endpoints catalog)

---

## 背景

### 已证实瓶颈数据（relike stage1 复查，SPOffset.dll，44,721 函数，实测 2026-09-01）

| 瓶颈             | 数量         | 端点                              |
| -------------- | ---------- | ------------------------------- |
| 单点反汇编          | 44,721     | `disassemble_function`（单地址 GET）|
| 站点级 xrefs     | 12,319     | `get_xrefs_from`（单地址 GET）       |
| **合计 HTTP 往返** | **57,040** | <br />                          |

采集阶段耗时 **61 秒**，瓶颈恰恰是海量单点 HTTP（读取+阻塞写导致的 57,491 读加交付小计 22+35 秒）。

**预估收益**:57,040 往返 → 约 510 批量请求（反汇编 100 函数/拖 → 448 批 + xrefs 200 地址/批 → 62 批），采集 61s → **预估 <15s**。

### 方案选择：为什么沿用 `decompile_function` 而非 `set_property` 的 POST body 模式

项目统一模式落地基本盘如此，单端点现状选择：

| 方案               | 先例                                                         | 说明                     |
| ---------------- | ---------------------------------------------------------- | ---------------------- |
| GET + 逗号分隔 query | `decompile_function`（functions=）                           | 只读端点、复用单地址 GET、无 body         |
| POST + 数组 body   | `set_property`（entries=）、`create_label`、`add_function_tag` | 写端点（需要 POST）、结构性，项目只读点不选 |

`disassemble_function` / `get_xrefs_from` 均为 **GET 只读端点**，沿用端点 `decompile_function` 的 GET 批量模式统一（query 逗号分隔）。**避免 GET→POST breaking change**。URL 长度上限（100 个地址 → ~18 字符 → 1.8KB，`decompile_function` 已用相同模式，限额完全够用）。

### 顺序价值与既有缺陷：沿用但需(a)超限报错而不是静默截断，(b)按目标审查与版本发布同步修复

`decompile_function` 批量模式（`batchDecompileFunctions`，FunctionService.java:342-344）有**既有限制**：`MAX_FUNCTIONS = 20`，循环用 `i < functionRefs.length && i < MAX_FUNCTIONS` 使超过 20 个函数时**静默截断**；调用方无从得知被截断（无声/低风险）。**本计划修复**：改为超限**显式报错**（与 `set_property` 批量 `entries_failed` 式语义一致，且与新增批量端点"超限即错"一致），绝不静默截断。

---

## 最终功能规范（对齐 decompile_function 统一模式）

**新增参数**：

- `disassemble_function`：`functions`（逗号分隔函数名/地址），与 `decompile_function` 的 `functions` 完全同义；`address` 单模式仍可用；**"When functions set, address is ignored."**

- `get_xrefs_from`：`addresses`（逗号分隔地址列表），对应端点单模式 `address` 的复数化。

**限额（超限=显式报错，绝不静默截断）：**

- `disassemble_function`：**200** 函数/次（比用于 decompile 的 20 大，已符合 100/批）

- `get_xrefs_from`：**200** 地址/批（已符合 200/批）

**统一响应格式**：`{results: [...], returned, program}`，`results` 为**排序明确**的数组（与 decompile 批量一致；map 对调用方原始顺序无保证；① 数组保留原始顺序；② 每结果内嵌 `address` 便于已分批单模式解析；③ 成功/失败并存）。`results[i]` 结构：

- 成功：`{address, name, instructions: [{address, instruction, comment?}, ...]}`，`instructions` 的条目与单模式**字段完全一致**（注意：条目键是 `instruction` 单数，非 `instructions`；单模式外层是 `listed("instructions",...)` → `{instructions:[...], count}` 信封，见 FunctionService.java:541，批量行内直接放数组）

- 失败：`{address, error}`（单条失败不中止整批，继续处理其余，同 `batch_analyze_completeness` 语义）

> **关于 success 字段**：只读 GET 端点遵循契约 list-shape（`{key:[...], count}`），批量外层**不带** `success`（与写端点 `set_property` 的 `{success,...}` 语义区分）。如后续确有需要可再加，先保持只读契约纯粹。

**线程策略**：只读，与单模式一致直接读 Listing/ReferenceManager，无事务。

---

## Task 1: `disassemble_function` 增加 `functions` 批量模式

**Files:**

- Modify: `src/main/java/com/xebyte/core/FunctionService.java`（`disassembleFunction()`，约 498 行）

**Step 1: 扩展注解与签名（address 可选 + functions）**

```java
@McpTool(path = "/disassemble_function", description = "Get assembly listing of ONE function (address) OR MANY (functions=comma-separated names/addresses, max 200 per call; over-limit is an error, never silent truncation). Each result carries the same instruction entries as single mode. On programs with multiple address spaces, prefix addresses with the space name (mem:1000).", category = "function")
public Response disassembleFunction(
        @Param(value = "address", paramType = "address", defaultValue = "",
               description = "Function address or name (single mode). Omit when using functions=") String addressStr,
        @Param(value = "functions", defaultValue = "",
               description = "Bulk mode: comma-separated function references (names or addresses), max 200. When set, address is ignored.") String functionsParam,
        @Param(value = "program", defaultValue = "") String programName) {
    if (functionsParam != null && !functionsParam.trim().isEmpty()) {
        return bulkDisassembleFunctions(functionsParam, programName);
    }
    if (addressStr == null || addressStr.isEmpty()) {
        return Response.err("address or functions is required");
    }
    // 以下为原单模式 body，唯一改动：抽出 collectInstructions 复用
    ...
}
```

**Step 2: 抽出 `collectInstructions` 私有 helper（单点+批量共用，保证字段零漂移）**

把单模式内联的指令收集循环（原 518-539 行）抽为：

```java
/** Shared instruction collector - identical fields to single mode. */
private List<Map<String, Object>> collectInstructions(Listing listing, Function func) {
    List<Map<String, Object>> instructions_out = new ArrayList<>();
    Address start = func.getEntryPoint();
    Address end = func.getBody().getMaxAddress();
    InstructionIterator instructions = listing.getInstructions(start, true);
    while (instructions.hasNext()) {
        Instruction instr = instructions.next();
        if (instr.getAddress().compareTo(end) > 0) break;
        String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("address", instr.getAddress().toString(false));
        entry.put("instruction", instr.toString());
        if (comment != null && !comment.isEmpty()) entry.put("comment", comment);
        instructions_out.add(entry);
    }
    return instructions_out;
}
```

单模式改为 `return ServiceUtils.listed("instructions", collectInstructions(listing, func));`（响应与现状完全一致）。

**Step 3: 批量 helper（合并不成独立 @McpTool）**

```java
// Bulk helper for disassemble_function(functions=...). Merged into
// disassemble_function in 7.0.0; not a standalone @McpTool.
public Response bulkDisassembleFunctions(String functionsParam, String programName) {
    ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
    if (pe.hasError()) return pe.error();
    Program program = pe.program();

    String[] refs = functionsParam.split(",");
    List<String> functionRefs = new ArrayList<>();
    for (String r : refs) { if (!r.trim().isEmpty()) functionRefs.add(r.trim()); }
    if (functionRefs.isEmpty()) return Response.err("functions is required for bulk mode");
    final int MAX_FUNCTIONS = 200;
    if (functionRefs.size() > MAX_FUNCTIONS) {
        return Response.err("functions exceeds max of " + MAX_FUNCTIONS
                + " per request (" + functionRefs.size() + " given); chunk client-side");
    }

    Listing listing = program.getListing();
    List<Map<String, Object>> results = new ArrayList<>();
    for (String funcRef : functionRefs) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("address", funcRef);
        try {
            Function func = ServiceUtils.resolveFunction(program, funcRef);
            if (func == null) { row.put("error", "No function found for " + funcRef); results.add(row); continue; }
            row.put("address", func.getEntryPoint().toString(false));
            row.put("name", func.getName());
            row.put("instructions", collectInstructions(listing, func));
        } catch (Exception e) {
            row.put("error", e.getMessage());
        }
        results.add(row);
    }
    return Response.ok(JsonHelper.mapOf("results", results, "returned", results.size(), "program", program.getName()));
}
```

**Step 4: 验证**

Run: `mvn clean compile -q`
Expected: BUILD SUCCESS

---

## Task 2: `get_xrefs_from` 增加 `addresses` 批量模式

**Files:**

- Modify: `src/main/java/com/xebyte/core/XrefCallGraphService.java`（`getXrefsFrom()`，约 85 行）

**Step 1: 扩展注解与签名（address 可选 + addresses；offset/limit 在批量下忽略）**

`address` 保留单模式（defaultValue=""），新增 `addresses`（逗号分隔，max 200）。**当 `addresses` 非空时忽略 `address`，并忽略 `offset`/`limit`**（批量语义 = 一次拿全每地址全部引用）。

```java
@McpTool(path = "/get_xrefs_from", description = "Get cross-references FROM ONE address OR MANY (addresses=comma-separated, max 200 per call; over-limit is an error, never silent truncation). Bulk mode returns every reference per address (offset/limit ignored). On programs with multiple address spaces, prefix addresses with the space name (mem:1000).", category = "xref")
public Response getXrefsFrom(
        @Param(value = "address", paramType = "address",
               description = "Address (single mode). Accepts 0x<hex> or <space>:<hex>. Omit when using addresses=") String addressStr,
        @Param(value = "addresses", defaultValue = "",
               description = "Bulk mode: comma-separated addresses, max 200. When set, address/offset/limit are ignored.") String addressesParam,
        @Param(value = "offset", defaultValue = "0") int offset,
        @Param(value = "limit", defaultValue = "100") int limit,
        @Param(value = "program", defaultValue = "") String programName) {
    if (addressesParam != null && !addressesParam.trim().isEmpty()) {
        return bulkGetXrefsFrom(addressesParam, programName);
    }
    if (addressStr == null || addressStr.isEmpty()) return Response.err("address or addresses is required");
    // 单模式 body 不变（沿用 paged("references", refs, offset, limit)）
    ...
}
```

**Step 2: 批量 helper，响应逐地址：成功 `{address, references:[...], count}` / 失败 `{address, error}`**

`references` 复用单模式生成的 **String 列表**（`"To <addr> to function X [TYPE]"` / `"To <addr> [TYPE]"`，见 XrefCallGraphService.java:123），保证与单模式条目完全一致。

```java
// Bulk helper for get_xrefs_from(addresses=...). Merged into
// get_xrefs_from in 7.0.0; not a standalone @McpTool.
public Response bulkGetXrefsFrom(String addressesParam, String programName) {
    ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
    if (pe.hasError()) return pe.error();
    Program program = pe.program();

    String[] parts = addressesParam.split(",");
    List<String> addrs = new ArrayList<>();
    for (String p : parts) { if (!p.trim().isEmpty()) addrs.add(p.trim()); }
    if (addrs.isEmpty()) return Response.err("addresses is required for bulk mode");
    final int MAX_ADDRESSES = 200;
    if (addrs.size() > MAX_ADDRESSES) {
        return Response.err("addresses exceeds max of " + MAX_ADDRESSES
                + " per request (" + addrs.size() + " given); chunk client-side");
    }

    ReferenceManager refManager = program.getReferenceManager();
    List<Map<String, Object>> results = new ArrayList<>();
    for (String addrStr : addrs) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("address", addrStr);
        try {
            Address addr = ServiceUtils.parseAddress(program, addrStr);
            if (addr == null) { row.put("error", ServiceUtils.getLastParseError()); results.add(row); continue; }
            List<String> refs = new ArrayList<>();
            for (Reference ref : refManager.getReferencesFrom(addr)) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) targetInfo = " to function " + toFunc.getName();
                else { Data data = program.getListing().getDataAt(toAddr);
                       if (data != null) targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName()); }
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            row.put("references", refs);
            row.put("count", refs.size());
        } catch (Exception e) {
            row.put("error", e.getMessage());
        }
        results.add(row);
    }
    return Response.ok(JsonHelper.mapOf("results", results, "returned", results.size(), "program", program.getName()));
}
```

**Step 3: 验证**

Run: `mvn clean compile -q`
Expected: BUILD SUCCESS

---

## Task 3: 修复 `decompile_function` 批量静默截断（改为显式 error）

**Files:**

- Modify: `src/main/java/com/xebyte/core/FunctionService.java`（`batchDecompileFunctions()`，约 328-344 行）

**决策**（审核收敛）：把静默截断改为**显式 error**，与新增批量端点"超限即错、绝不静默截断"完全一致。这是**有意的行为变更**，须同步检查调用方/测试是否依赖旧截断行为。

```java
if (functionRefs.size() > MAX_FUNCTIONS) {
    return Response.err("functions exceeds max of " + MAX_FUNCTIONS
            + " per request (" + functionRefs.size() + " given); chunk client-side");
}
// 循环去除 i < MAX_FUNCTIONS，改为完整遍历 functionRefs
```

**影响面检查（必须做）**：检索 `tests/`、`fun-doc/`、`tools/setup`、README 中对 `decompile_function` 批量调用的断言，确认无依赖旧 20 条静默截断的用例；`test_response_contract_callers.py` 等调用方守护测试若无相关用例则无需改。若发现依赖截断的用例，更新为新 error 语义。

**Step 验证**

Run: `mvn clean compile -q`
Expected: BUILD SUCCESS

---

## Task 4: 更新 Python 桥接超时放大

**Files:**

- Modify: `python/bridge_mcp_ghidra/dispatch.py`（`get_timeout`，约 18-56 行，紧跟 `set_property` 分支后新增）

注意：这两个端点是 **GET**，`dispatch_get` 在 `dispatch.py:231` 传入的 `params` 即 GET query 字典，故 `payload.get("functions")`/`get("addresses")` 可读到逗号分隔串。

```python
if name == "disassemble_function":
    count = len((payload.get("functions") or "").split(",")) if payload.get("functions") else 1
    if count > 1:
        return min(base + count * 3, 600)

if name == "get_xrefs_from":
    count = len((payload.get("addresses") or "").split(",")) if payload.get("addresses") else 1
    if count > 1:
        return min(base + count, 600)
```

Run: `pytest tests/unit/ -v --no-cov`
Expected: PASS

---

## Task 5: 更新 endpoints.json 目录

**Files:**

- Modify: `tests/endpoints.json`

**注意（审核确认）**：`disassemble_function` 的 params **当前已是** `["address","functions","program","timeout"]`（含 `functions`，属目录与 Java 不同步的残留，恰与本次目标一致，无需新增只需核对 description）；`get_xrefs_from` 当前 `["address","offset","limit","program"]`，需加 `"addresses"`。

- `disassemble_function`：核对 params（含 `functions`），description 更新为批量语义（含 max 200）
- `get_xrefs_from`：params 增加 `"addresses"`（`["address","addresses","offset","limit","program"]`），description 更新为批量语义
- `total_endpoints` 保持不变（253，同一端点扩展，不新增端点）

---

## Task 6: 编译、打包、单元测试、端到端对齐

**Step 1:**

Run: `mvn clean compile -q`
Expected: BUILD SUCCESS

**Step 2:**

Run: `mvn clean package assembly:single -DskipTests`
Expected: BUILD SUCCESS

**Step 3:**

Run: `pytest tests/unit/ -v --no-cov`
Expected: ALL PASS

**Step 4: 端到端对齐（关键收尾）**

起一个真实程序，抽样对比 ≥10 个函数

- `disassemble_function(functions="a,b,c,...")` 的每条 `results[i].instructions` 与 `disassemble_function(address=...)` 单模式**逐字段一致**（`address`/`instruction`/`comment?`，外层信封 `{instructions, count}`）

- `get_xrefs_from(addresses="a,b,c,...")` 与 `get_xrefs_from(address=...)` 的引用集合**一致**（String 条目 `"To <addr> ... [TYPE]"`）

- 超限（>200）：两者均返回明确 error，而非截断结果

- 单模式回退：`address` 未配 `functions`时，响应格式与改动前完全一致

---

## Task 7: 更新 CHANGELOG.md

```markdown
### Changed
- `disassemble_function` now accepts `functions=` (comma-separated, max 200) to disassemble many functions in one call; each result carries the same instruction entries as single mode (one-or-many pattern, matching decompile_function)
- `get_xrefs_from` now accepts `addresses=` (comma-separated, max 200) for batch reference retrieval; bulk mode returns every reference per address (offset/limit ignored); over-limit requests are explicit errors (no silent truncation)
- `decompile_function` bulk mode: requests over 20 functions now return an explicit error instead of silently truncating
```

---

## 收敛摘要

| 文件                                                        | 变更类型   | 说明                                                                                                                        |
| --------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------- |
| `src/main/java/com/xebyte/core/FunctionService.java`      | Modify | `disassembleFunction()` + `functions` 批量、`bulkDisassembleFunctions()` + `collectInstructions()` helper（单点复用）、Task3 decompile 截断改为显式 error |
| `src/main/java/com/xebyte/core/XrefCallGraphService.java` | Modify | `getXrefsFrom()` + `addresses` 批量（offset/limit 批量下忽略） |
| `python/bridge_mcp_ghidra/dispatch.py`                    | Modify | `get_timeout()` 批量端点放大（GET query 可读）                                                                                                     |
| `tests/endpoints.json`                                    | Modify | 核对 disassemble_function params、给 get_xrefs_from 加 addresses、更新 description（total_endpoints 不变） |
| `CHANGELOG.md`                                            | Modify | 记录本次批量能力 + decompile 截断修复                                                                                                                      |

## 遗留说明

- **只读端点保持 GET**，单地址调用（GET query）**非 breaking**（单模式行为与响应完全不变，仅 address 从必填改为"address 或 functions 至少其一"）

- **不新增端点**：均为现有端点 one-or-many 能力扩展（与 `decompile_function` 一致；`batch_` 前缀已废弃；`get_bulk_xrefs` 等旧式独立批量端点不建，统一到现有端点）

- **超限 = 显式 error**（拒绝 `decompile_function` 现有的静默截断故态）——Task3 是行为变更，需按步检查调用方

- 只涉及读取（无 ProgramDB 修改）

## 已复盘性能预期（relike stage1_extract.py，非常不可知名库工件）

- 采集反汇编类：44,721 个 → 448 次 `functions=` 批量（100/批）

- 站点 xrefs：12,319 个 → 62 次 `addresses=` 批量（200/批）

- relike 用 `mcp_client.call_text`（GET query）**零额外改动**，批量响应可直接落盘；`parse_disassembly` 已适配单点模式 `instructions` 结构，批量 `results[i].instructions` 直接复用

- 采集阶段 61s → 预估 <15s；stage1 全程 174s → 预估 ~120s