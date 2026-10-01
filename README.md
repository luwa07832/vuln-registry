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

## 版本顺序

版本按从左到右的点分段逐段比较；缺失段按 0 比较（`1` 与 `1.0`、`1.0.0` 等价）；每段必须是非空纯数字，按数值比较（`1.10 > 1.9`）。版本串不能为空，也不允许出现空段或非数字字符，否则按非法输入处理。

## 允许的字段取值

- 严重等级 `severity`：`low`、`medium`、`high`、`critical`
- 处置状态 `status`：`open`、`in_progress`、`fixed`、`ignored`
- 组件名称按完全相同的字符串匹配，区分大小写
- 受影响版本区间 `ranges` 至少一条；每条区间的 `lower` / `upper` 可省略或为 `null` 表示该侧开放，`lowerInclusive` / `upperInclusive` 用布尔值明确表达边界是否包含（缺省为 `false`）；同一漏洞的多条区间按并集解释

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

### `POST /vulnerabilities` — 登记漏洞

请求体示例：

```json
{
  "id": "CVE-2024-0001",
  "component": "openssl",
  "ranges": [
    {"lower": "1.0.0", "lowerInclusive": true, "upper": "1.1.1", "upperInclusive": false},
    {"lower": "2.0", "lowerInclusive": true}
  ],
  "severity": "critical",
  "fixedVersion": "1.1.1",
  "status": "open"
}
```

所有字段都必填（`ranges` 至少一条）。成功时 HTTP 201，响应体为登记的完整记录；开放边界序列化为 `null`。

- 同一 `id` 重复登记：HTTP 409，响应体固定为纯文本 `error=DUPLICATE_VULNERABILITY`
- 字段缺失、`id` 或 `component` 为空、区间上下界颠倒、版本格式非法、严重等级或处置状态不在允许集合内、JSON 无法解析：HTTP 400，响应体固定为纯文本 `error=INVALID_INPUT`，且不会产生任何部分写入

### `GET /vulnerabilities/match?component=<名称>&version=<版本>` — 精确匹配查询

返回组件名称完全相同（区分大小写）且版本命中任一受影响区间的漏洞，按 `id` 升序排列。每条至少包含 `id`、`component`、命中的区间 `matchedRanges`（保留登记顺序，仅包含命中的区间）、`severity`、`fixedVersion`、`status`：

```json
[
  {
    "id": "CVE-2024-0001",
    "component": "openssl",
    "matchedRanges": [{"lower": "1.0.0", "lowerInclusive": true, "upper": "1.1.1", "upperInclusive": false}],
    "severity": "critical",
    "fixedVersion": "1.1.1",
    "status": "open"
  }
]
```

- 组件为空或版本非法：HTTP 400，响应体为纯文本 `error=INVALID_INPUT`
- 查询合法但没有命中：HTTP 200，响应体为 `[]`

### `PATCH /vulnerabilities/:id/status` — 更新处置状态

请求体为 `{"status":"fixed"}`，成功时 HTTP 200，返回更新后的完整记录。

- 未知编号：HTTP 404，响应体固定为纯文本 `error=VULNERABILITY_NOT_FOUND`
- 字段缺失或状态不在允许集合内：HTTP 400，响应体固定为纯文本 `error=INVALID_INPUT`

## 错误约定

登记、匹配查询与状态更新入口的错误响应体均为固定纯文本（`error=...`），状态码如上所述。服务级错误（如 `GET /healthz` 的 503 和未匹配路由的 404）保持单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message` 不包含 SQL、堆栈或文件路径。
