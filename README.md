# vuln-registry

把组件漏洞的编号、受影响组件与版本区间、严重等级、修复版本和处置状态记录成可查询的服务，支持按组件与版本区间匹配受影响的漏洞。

## 运行要求

- Go 1.26 或以上
- SQLite（本服务自带存储，不需要外部数据库）

## 构建、测试与启动

```bash
go build ./...
go test ./...
go run .
```

服务默认监听 `127.0.0.1:8080`。可用环境变量覆盖：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `ADDR` | `127.0.0.1:8080` | HTTP 监听地址 |
| `DB_PATH` | `vuln-registry.db` | SQLite 数据库文件路径 |

## 已公开的入口

### `GET /healthz`

返回服务与存储状态。正常时 HTTP 200：

```json
{"status":"ok","database":"ok"}
```

存储不可用时 HTTP 503：

```json
{"error":{"code":"storage_unavailable","message":"database is not available"}}
```

### `POST /vulnerabilities`

登记一条漏洞。请求体是单个 JSON 对象：

| 字段 | 要求 |
|---|---|
| `id` | 唯一编号，非空字符串 |
| `component` | 组件名称，非空字符串，比较区分大小写 |
| `affected_ranges` | 一个或多个受影响版本区间，按并集解释 |
| `severity` | `low`、`medium`、`high`、`critical` 之一 |
| `fixed_version` | 修复版本，合法版本号且非空 |
| `status` | `open`、`in_progress`、`fixed`、`wont_fix`、`accepted` 之一 |

每个区间的字段：

| 字段 | 要求 |
|---|---|
| `lower` / `upper` | 下界/上界版本；`null`、空串或缺省表示该侧开放 |
| `lower_include` / `upper_include` | 对应边界非空时必须显式给出，布尔值，表示该边界是否包含 |

请求示例：

```json
{
  "id": "CVE-2024-0001",
  "component": "libxml2",
  "affected_ranges": [
    {"lower": "2.0", "lower_include": true, "upper": "2.9", "upper_include": false},
    {"upper": "1.5.0", "upper_include": true}
  ],
  "severity": "high",
  "fixed_version": "2.10.0",
  "status": "open"
}
```

成功返回 HTTP 201 与完整记录。编号已存在时返回 HTTP 409，响应体固定为纯文本
`error=DUPLICATE_VULNERABILITY`。以下任一情况返回 HTTP 400，响应体固定为纯文本
`error=INVALID_INPUT`：字段缺失、编号或组件为空、区间列表为空、版本格式非法、
边界非空却缺少对应的包含标志、下界严格大于上界、上下界相等但任一侧为开区间、
严重等级或处置状态不在允许集合内。登记在单个事务内完成，失败不会部分写入。

### `GET /vulnerabilities/affected`

按组件名称与具体版本查询当前仍受影响的漏洞，查询参数为 `component` 与 `version`。

- 组件名完全相同（区分大小写）且版本落在任一受影响区间内的记录才会返回。
- 结果按编号升序排列；每条包含 `id`、`component`、`matched_ranges`（命中的
  受影响区间，保持登记顺序）、`severity`、`fixed_version`、`status`。
- 组件为空或版本非法时返回 HTTP 400 与 `error=INVALID_INPUT`。
- 合法但无结果时返回 HTTP 200，响应体为稳定的空数组 `[]`。

### `PATCH /vulnerabilities/status/:id`

更新已有漏洞的处置状态，请求体为 `{"status":"fixed"}`，取值集合与登记相同。
成功返回 HTTP 200 与更新后的完整记录；状态值非法或字段缺失返回 HTTP 400 与
`error=INVALID_INPUT`；未知编号返回 HTTP 404，响应体固定为纯文本
`error=VULNERABILITY_NOT_FOUND`。更新只改变处置状态，其余字段保持不变。

### `GET /vulnerabilities/:id`

按编号取回一条完整漏洞记录。路径中的编号按登记值精确匹配，不做大小写折叠、
去空格或模糊匹配。命中返回 HTTP 200 与单个 JSON 对象，包含 `id`、`component`、
`affected_ranges`、`severity`、`fixed_version`、`status`；`affected_ranges` 保持
登记顺序，开放边界对应字段为 `null`。未知编号返回 HTTP 404，响应体固定为纯文本
`error=VULNERABILITY_NOT_FOUND`。此入口只读，不改变任何已登记数据。

## 版本顺序

版本号是一个或多个用点分隔的十进制数字段（如 `1`、`1.0.3`、`10.2.0`）。
比较时从左到右逐段按数值比较；缺失的尾段按 0 比较，因此 `1`、`1.0`、`1.0.0`
彼此相等。

## 错误约定

漏洞登记、查询与状态维护入口的错误响应为固定纯文本，形如
`error=DUPLICATE_VULNERABILITY`，不包含 SQL、堆栈或文件路径。此前已公开的
`GET /healthz` 等入口仍使用单个顶层 `error` 对象（含 `code` 与 `message` 两个
字符串字段），语义保持不变。
