# set_property 批量修改功能实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在现有 `set_property` 端点上增加批量设置属性值的能力，保持完全向后兼容。

**Architecture:** 采用项目中 `create_label` / `add_function_tag` 使用的 **统一单/批量模式**——在现有端点上新增 `entries` 数组参数，非空时进入批量模式，空时走原有单点逻辑。无需新增独立端点。

**Tech Stack:** Java (Ghidra extension), Python (bridge timeout scaling), JSON (endpoints catalog)

---

## 分析结论

### 当前 `set_property` 状态
- 仅支持单点修改：`map` + `address` + `value`
- 实现位于 `ProgramScriptService.java:728-798`
- Python 桥接层由 schema 自动生成，无需手动添加

### 项目中已有的批量模式

| 模式 | 示例 | 特点 |
|------|------|------|
| **统一单/批量** | `create_label`, `add_function_tag` | 在同一端点增加数组参数，向后兼容 ✅ 推荐 |
| 独立 `batch_*` | `batch_set_comments`, `batch_get_comments` | 新建独立端点，旧端点保留 |
| 独立 `bulk_*` | `bulk_fuzzy_match` | 新建独立端点 |

**选择方案：统一单/批量模式**，与 `create_label` 保持一致。

---

## 命名与框架规范（对齐现有统一单/批量方案）

**批量参数命名**：`entries`（`List<Map<String,String>>`，存 `{address, value}` 对象）——对应 `labels`（`{address,name}`）、`assignments`（`{function,tags}`）的命名习惯，均为对象数组。

**批量辅助方法命名**：`batchSetProperty`——对应 `create_label→batchCreateLabels`、`add_function_tag→batchAddFunctionTags` 的 `batch<Verb><Noun>` 命名规则。

**辅助方法签名**：保留 `@Param` 注解（即使非 `@McpTool`），与 `batchCreateLabels`、`batchAddFunctionTags` 一致。

**辅助方法注释**：`// Bulk helper for set_property(entries=[...]). Merged into set_property in 7.0.0; no longer a standalone @McpTool.`——对齐现有批量辅助方法的注释约定。

**线程策略**：使用 `threadingStrategy.executeWrite()`——ProgramScriptService 单点 `setProperty` 已用该方法，且与 `add_function_tag` 的批量辅助方法一致（同属写操作）。

**批量响应格式**：`success` + `entries_set`/`entries_failed` 计数 + 可选 `errors`——对齐 `create_label` 返回 `labels_created`/`labels_skipped`/`labels_failed` 的计数风格。

**关于程序逻辑思路一致性的确认**：现有代码存在两种都会用到的批处理思路，两者均被项目采用且都合理：
- **集中计数 + errors 列表**（`batchCreateLabels`）：`successCount`/`skipCount`/`errorCount` 原子计数器 + 集中 `errors` 列表，不展开逐条结果。
- **逐条结构化 results**（`batchAddFunctionTags`）：每个条目产出独立 row（`LinkedHashMap` 含 `status`/`error`），`continue` 前就地 `results.add(row)`。

本计划的 `batchSetProperty` 选择 **`batchCreateLabels` 的集中计数 + errors 风格**，理由：
1. `set_property` 单点版本返回值本身就是精简 Map（`mapOf(success, map, address, value_type, ...)`），非逐条展开风格，批量版保持一致。
2. `ProgramScriptService` 的既有写工具（`createPropertyMap`/`deletePropertyMap`/`setProperty`）全部用 `threadingStrategy.executeWrite`，本方法沿用之。
3. `PropertyMap` 单条写入无论成功与否都只是 `add()` 调用，构造 per-row 结构化结果收益低（无 `added`/`already_present` 这类差异化附加信息），集中 errors 列表更贴合实际。

**差异确认（显式指出，避免误解）**：
- `batchAddFunctionTags` 在 `executeWrite` 后调用 `program.flushEvents()`。**本计划不调用** `flushEvents()`，因为 ProgramScriptService 的同服务单点 `setProperty`（`ProgramScriptService.java:774`）在 `executeWrite` 后并无 `flushEvents()`——与同文件既有写操作保持一致，而非照搬另一服务的方法。
- `batchCreateLabels` 用 `SwingUtilities.invokeAndWait` + 手动 `startTransaction`/`endTransaction`；本计划用 `threadingStrategy.executeWrite`（更现代的封装，同文件已用）。

---

## Task 1: 修改 `setProperty()` 方法签名和分发逻辑

**Files:**
- Modify: `src/main/java/com/ebyte/core/ProgramScriptService.java:728-798`

**Step 1: 更新 `@McpTool` 注解描述**

修改 `description` 和方法签名，增加 `entries` 参数：

```java
@McpTool(path = "/set_property", method = "POST",
         description = "Set ONE property at an address in a property map OR MANY in one transaction (entries=[{address,value}, ...]). The value is coerced to the map's type (int/long/string); 'void' maps ignore the value and just tag the address. Create the map first with create_property_map. Call save_program to persist.",
         category = "program")
public Response setProperty(
        @Param(value = "map", source = ParamSource.BODY, description = "Property map name (from list_property_maps).") String mapName,
        @Param(value = "address", paramType = "address", source = ParamSource.BODY,
               description = "Address (single mode). Omit when using entries[].") String addressStr,
        @Param(value = "value", source = ParamSource.BODY, defaultValue = "",
               description = "Value to store, as a string; parsed per the map's type. Ignored for 'void' maps. (single mode).") String value,
        @Param(value = "entries", source = ParamSource.BODY, defaultValue = "[]",
               description = "Bulk mode: array of {address, value} objects. When non-empty, address/value params are ignored.") List<Map<String, String>> entries,
        @Param(value = "program", defaultValue = "") String programName) {
```

**Step 2: 在 `Address` 解析之前添加批量模式分发**

参照 `create_label` 放置位置（在 program 解析、单点必填校验之前）：

```java
if (entries != null && !entries.isEmpty()) {
    return batchSetProperty(mapName, entries, programName);
}
```

**Step 3: 验证编译通过**

Run: `mvn clean compile -q`
Expected: BUILD SUCCESS

---

## Task 2: 实现 `batchSetProperty()` 辅助方法

**Files:**
- Modify: `src/main/java/com/ebyte/core/ProgramScriptService.java` (在 `setProperty()` 方法之后添加)

**Step 1: 添加批量方法**

在 `setProperty()` 方法结束后（约第 798 行后）插入新方法（保留 `@Param` 注解以对齐 `batchCreateLabels` 约定）：

```java
// Bulk helper for set_property(entries=[...]). Merged into set_property in 7.0.0;
// no longer a standalone @McpTool.
public Response batchSetProperty(
        @Param(value = "map", source = ParamSource.BODY) String mapName,
        @Param(value = "entries", source = ParamSource.BODY) List<Map<String, String>> entries,
        @Param(value = "program", defaultValue = "") String programName) {
    ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
    if (pe.hasError()) return pe.error();
    Program program = pe.program();

    if (mapName == null || mapName.isEmpty()) return Response.err("map is required");
    if (entries == null || entries.isEmpty()) return Response.err("No entries provided");

    PropertyMap<?> map = program.getUsrPropertyManager().getPropertyMap(mapName);
    if (map == null) {
        return Response.err("No property map named '" + mapName + "'. Create it with create_property_map.");
    }

    if (map instanceof ObjectPropertyMap) {
        return Response.err("Object property maps cannot be written via MCP (they require a registered Saveable type).");
    }

    final AtomicInteger successCount = new AtomicInteger(0);
    final AtomicInteger errorCount = new AtomicInteger(0);
    final List<String> errors = new ArrayList<>();

    try {
        threadingStrategy.executeWrite(program, "Batch Set Property", () -> {
            for (Map<String, String> entry : entries) {
                String addressStr = entry.get("address");
                String value = entry.get("value");

                if (addressStr == null || addressStr.isEmpty()) {
                    errors.add("Missing 'address' in entry");
                    errorCount.incrementAndGet();
                    continue;
                }

                Address address = ServiceUtils.parseAddress(program, addressStr);
                if (address == null) {
                    errors.add(ServiceUtils.getLastParseError());
                    errorCount.incrementAndGet();
                    continue;
                }

                try {
                    if (map instanceof IntPropertyMap ip) {
                        if (value == null || value.isEmpty()) {
                            errors.add("Value required for int map at " + addressStr);
                            errorCount.incrementAndGet();
                            continue;
                        }
                        ip.add(address, Integer.parseInt(value.trim()));
                    } else if (map instanceof LongPropertyMap lp) {
                        if (value == null || value.isEmpty()) {
                            errors.add("Value required for long map at " + addressStr);
                            errorCount.incrementAndGet();
                            continue;
                        }
                        lp.add(address, Long.parseLong(value.trim()));
                    } else if (map instanceof StringPropertyMap sp) {
                        if (value == null) {
                            errors.add("Value required for string map at " + addressStr);
                            errorCount.incrementAndGet();
                            continue;
                        }
                        sp.add(address, value);
                    } else if (map instanceof VoidPropertyMap vp) {
                        vp.add(address);
                    }
                    successCount.incrementAndGet();
                } catch (NumberFormatException nfe) {
                    errors.add("Invalid value '" + value + "' at " + addressStr + ": " + nfe.getMessage());
                    errorCount.incrementAndGet();
                } catch (Exception e) {
                    errors.add("Error at " + addressStr + ": " + e.getMessage());
                    errorCount.incrementAndGet();
                }
            }
            return null;
        });
    } catch (Exception e) {
        return Response.err("Batch transaction failed: " + e.getMessage());
    }

    Map<String, Object> result = JsonHelper.mapOf(
            "success", true,
            "map", mapName,
            "entries_set", successCount.get(),
            "entries_failed", errorCount.get(),
            "value_type", propertyMapValueType(map),
            "note", "Call save_program to persist this change to the database.",
            "program", program.getName());
    if (!errors.isEmpty()) {
        result.put("errors", errors);
    }
    return Response.ok(result);
}
```

**Step 2: 验证编译通过**

Run: `mvn clean compile -q`
Expected: BUILD SUCCESS

---

## Task 3: 更新 Python 桥接超时缩放

**Files:**
- Modify: `python/bridge_mcp_ghidra/dispatch.py:18` (`get_timeout` 函数)

**Step 1: 在 `get_timeout()` 中添加 `set_property` 的批量超时逻辑**

参考 `batch_set_comments` 的模式，添加：

```python
if name == "set_property":
    count = len(payload.get("entries", [])) if payload else 0
    if count > 1:
        return min(base + count * 3, 600)
```

**Step 2: 运行 Python 测试**

Run: `pytest tests/unit/ -v --no-cov`
Expected: PASS

---

## Task 4: 更新 endpoints.json 目录

**Files:**
- Modify: `tests/endpoints.json` (找到 `set_property` 条目)

**Step 1: 更新 `set_property` 的 params 列表**

在 `params` 数组中添加 `"entries"`（放在 `program` 之前，对齐 `create_label` 的 `["address","name","labels","program"]` 顺序），同时更新 description：

```json
{
  "path": "/set_property",
  "method": "POST",
  "category": "program",
  "params": ["map", "address", "value", "entries", "program"],
  "description": "Set ONE property at an address in a property map OR MANY in one transaction (entries=[{address,value}, ...]). The value is coerced to the map's type (int/long/string); 'void' maps ignore the value and just tag the address. Create the map first with create_property_map. Call save_program to persist."
}
```

**Step 2: 更新 `total_endpoints` 数值**

注意：总端点数不变（253），因为是同一个端点的扩展，不是新端点。

---

## Task 5: 编译验证和测试

**Step 1: Java 编译**

Run: `mvn clean compile -q`
Expected: BUILD SUCCESS

**Step 2: Java 打包**

Run: `mvn clean package assembly:single -DskipTests`
Expected: BUILD SUCCESS

**Step 3: Python 单元测试**

Run: `pytest tests/unit/ -v --no-cov`
Expected: ALL PASS

---

## Task 6: 更新 CHANGELOG.md

**Files:**
- Modify: `CHANGELOG.md`

**Step 1: 在最新版本条目下添加变更记录**

```markdown
### Changed
- `set_property` now supports bulk mode via `entries=[{address, value}, ...]` parameter
```

---

## 变更摘要

| 文件 | 变更类型 | 说明 |
|------|---------|------|
| `src/main/java/com/ebyte/core/ProgramScriptService.java` | Modify | `setProperty()` 签名 + 新增 `batchSetProperty()` |
| `python/bridge_mcp_ghidra/dispatch.py` | Modify | `get_timeout()` 增加 `set_property` 批量超时 |
| `tests/endpoints.json` | Modify | `set_property` params 增加 `entries` |
| `CHANGELOG.md` | Modify | 记录批量功能变更 |

## 兼容性说明

- **完全向后兼容**：原有 `map` + `address` + `value` 单点调用不受影响
- **无需 Python 桥接层手动注册**：schema 由 Java 端自动生成，Python 侧动态发现
- **无需新增独立端点**：复用 `/set_property` 路径
