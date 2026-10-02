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

### `POST /vulnerabilities/batch`

在一次请求中原子登记多条漏洞。请求体是单个 JSON 对象，`vulnerabilities`
为漏洞对象数组，每项的字段、必填条件、版本区间语义、严重等级取值、修复版本
格式和处置状态取值与 `POST /vulnerabilities` 完全一致；数组必须包含 1 到 100
项，顶层与每条记录中的无关 JSON 字段继续忽略。

成功返回 HTTP 201 与单个 JSON 对象，`items` 是与输入顺序一致的完整漏洞记录
数组（每条记录的字段投影与单条登记的 201 一致，`affected_ranges` 保持该记录
内的登记顺序，开放边界字段为 `null`），`count` 等于本次成功登记条数：

```json
{"items":[{"id":"CVE-2024-0001","component":"libxml2","affected_ranges":[{"lower":"2.0","lower_include":true,"upper":"2.9","upper_include":false}],"severity":"high","fixed_version":"2.10.0","status":"open"}],"count":1}
```

请求按输入顺序校验与处理，但写入整体成功或整体失败，不修改或删除任何已有
记录：

- 任意一条记录缺少必填字段、编号或组件为空、`affected_ranges` 为空、版本或
  区间非法（含边界非空却缺少包含标志或包含标志不是布尔值）、严重等级或处置
  状态非法，以及请求体不是单个 JSON 对象、`vulnerabilities` 缺失或不是数组、
  数组为空或超过 100 项、任一元素不是对象时，整次请求返回 HTTP 400 与固定
  纯文本 `error=INVALID_INPUT`，数据库不新增任何记录。
- 数组内出现相同 `id`，或任一 `id` 已存在于数据库时，整次请求返回 HTTP 409
  与固定纯文本 `error=DUPLICATE_VULNERABILITY`，数据库同样不新增任何记录。
  输入校验先于重复检查：同时存在无效记录与重复编号时仍返回 `INVALID_INPUT`。
- 存储写入失败时返回 HTTP 500 与现有 `internal_error` JSON 错误对象，事务
  回滚保证没有部分提交。

### `GET /vulnerabilities/affected`

按组件名称与具体版本查询当前仍受影响的漏洞，查询参数为 `component` 与 `version`。

- 组件名完全相同（区分大小写）且版本落在任一受影响区间内的记录才会返回。
- 结果按编号升序排列；每条包含 `id`、`component`、`matched_ranges`（命中的
  受影响区间，保持登记顺序）、`severity`、`fixed_version`、`status`。
- 组件为空或版本非法时返回 HTTP 400 与 `error=INVALID_INPUT`。
- 合法但无结果时返回 HTTP 200，响应体为稳定的空数组 `[]`。

### `POST /vulnerabilities/match`

批量判断清单中多个组件版本是否命中已登记的受影响区间。请求体是单个 JSON 对象，
`components` 为非空数组，最多 100 项；每个元素包含非空的 `component` 与合法
版本 `version`：

```json
{
  "components": [
    {"component": "libxml2", "version": "2.4.1"},
    {"component": "zlib", "version": "1.2.11"}
  ]
}
```

- 匹配口径与 `GET /vulnerabilities/affected` 完全一致：组件名区分大小写精确
  匹配，版本按点分十进制数字段比较（缺失尾段视为 0），版本落入任一
  `affected_ranges` 即命中；处置状态不参与排除，所有状态的记录都会参与匹配。
- 响应为单个 JSON 对象，`results` 始终为数组且与输入一一对应、保持输入顺序；
  重复的组件版本分别处理，不合并。每个结果对象原样回显 `component`、
  `version`，并带 `vulnerabilities` 数组（无命中时为稳定的 `[]`）。
- `vulnerabilities` 中的漏洞按编号升序排列，每条只返回 `id`、`component`、
  `matched_ranges`、`severity`、`fixed_version`、`status`；`matched_ranges`
  只保留本次实际命中的区间并保持登记顺序。
- 与匹配无关的 JSON 字段忽略。以下任一情况整次请求返回 HTTP 400 与固定纯文本
  `error=INVALID_INPUT`，且不返回部分结果：请求体不是单个 JSON 对象、
  `components` 缺失或不是数组、数组为空或超过 100 项、任一元素不是对象、
  `component` 缺失或为空、`version` 缺失、为空或不是合法版本。
- 正常请求即使全部无命中也返回 HTTP 200。存储读取失败时返回 HTTP 500 与
  `internal_error` JSON 错误对象，不泄露 SQL、堆栈或文件路径。

### `POST /vulnerabilities/range-match`

按组件版本区间批量检索漏洞，用于判断一段待升级范围涉及哪些已登记漏洞。
请求体是单个 JSON 对象，`queries` 为非空数组，最多 100 项；每个元素包含：

| 字段 | 要求 |
|---|---|
| `component` | 非空组件名，区分大小写精确匹配 |
| `lower` | 必填的有限下界，合法版本号 |
| `upper` | 必填的有限上界，合法版本号 |
| `lower_include` / `upper_include` | 必填布尔值，表示对应边界是否包含 |

`lower` 不得严格大于 `upper`；二者相等时两端都必须为包含。示例：

```json
{
  "queries": [
    {"component": "libxml2", "lower": "2.4", "upper": "2.9", "lower_include": true, "upper_include": false},
    {"component": "zlib", "lower": "1.2.11", "upper": "1.3", "lower_include": true, "upper_include": true}
  ]
}
```

- 一条漏洞的任一 `affected_ranges` 与查询区间存在至少一个共同合法版本时才命中；
  登记区间的开放边界视为无界。两个区间只在共同端点相接时，仅当双方都包含
  该端点才相交（例如登记上界 2.9 为开区间时，查询下界恰为 2.9 且不与该区间
  在更低版本上重叠，则不命中）。
- 响应为单个 JSON 对象，`results` 始终为数组且与 `queries` 一一对应、保持
  输入顺序；每项原样回显 `component`、`lower`、`upper`、`lower_include`、
  `upper_include`，并带 `vulnerabilities` 数组（无命中时为稳定的 `[]`）。
- `vulnerabilities` 按编号升序排列，每条只返回 `id`、`component`、
  `matched_ranges`、`severity`、`fixed_version`、`status`；`matched_ranges`
  只保留与查询区间相交的受影响区间并保持登记顺序。所有处置状态都参与匹配。
- 与匹配无关的 JSON 字段忽略。以下任一情况整次请求返回 HTTP 400 与固定纯文本
  `error=INVALID_INPUT`，且不返回部分结果：请求体不是单个 JSON 对象、
  `queries` 缺失或不是数组、数组为空或超过 100 项、任一元素不是对象、
  缺少 `component`、`lower`、`upper`、`lower_include`、`upper_include`、
  `component` 为空、版本非法、包含标志不是布尔值、下界严格大于上界，或上下界
  相等却有任一端不包含。
- 正常请求即使全部无命中也返回 HTTP 200。存储读取失败时返回 HTTP 500 与
  `internal_error` JSON 错误对象，不泄露 SQL、堆栈或文件路径。

### `GET /vulnerabilities/:id`

按编号取回单条漏洞的完整登记内容，路径中的 `id` 与登记编号精确匹配
（区分大小写，不做去空格或模糊匹配）。命中时返回 HTTP 200 与单个 JSON 对象，
包含 `id`、`component`、`affected_ranges`、`severity`、`fixed_version`、
`status`；`affected_ranges` 保持登记顺序，每个区间的边界与包含标志沿用登记时的
JSON 语义，开放边界对应字段为 `null`。

未知编号返回 HTTP 404，响应体固定为纯文本 `error=VULNERABILITY_NOT_FOUND`。
该入口为只读操作；存储读取失败时返回 HTTP 500，沿用 `{"error":...}` 的
JSON 错误对象格式。

### `PATCH /vulnerabilities/status/:id`

更新已有漏洞的处置状态，请求体为 `{"status":"fixed"}`，取值集合与登记相同。
成功返回 HTTP 200 与更新后的完整记录；状态值非法或字段缺失返回 HTTP 400 与
`error=INVALID_INPUT`；未知编号返回 HTTP 404，响应体固定为纯文本
`error=VULNERABILITY_NOT_FOUND`。更新只改变处置状态，其余字段保持不变。

### `PATCH /vulnerabilities/statuses`

在一次请求中原子更新多条漏洞的处置状态。请求体是单个 JSON 对象，`updates`
为 1 到 100 个对象的数组；每个对象使用 `id`（漏洞编号，精确匹配、区分大小写）
与 `status`（取值集合与登记相同），顶层与每个对象中的无关字段均忽略，数组内
编号不得重复。

成功返回 HTTP 200 与单个 JSON 对象，`items` 按 `updates` 的请求顺序返回更新后的
完整记录（字段与按编号读取一致，`affected_ranges` 保持登记顺序，开放边界字段为
`null`），`count` 等于本次更新条数。每个对象可设置不同状态，但只改变处置状态，
其余字段保持不变；按编号读取、分页筛选与两类匹配查询立即反映新状态。

- 请求体不是单个 JSON 对象、`updates` 缺失或不是数组、数量为空或超过 100、任一
  元素不是对象、`id` 缺失或为空、`status` 缺失或非法，或数组内出现重复编号时，
  返回 HTTP 400 与固定纯文本 `error=INVALID_INPUT`，不修改任何记录。
- 结构合法但任一编号不存在时，无论未知编号有几个，都返回 HTTP 404 与固定纯文本
  `error=VULNERABILITY_NOT_FOUND`，不修改任何记录。
- 存储写入失败时返回 HTTP 500 与现有 `internal_error` JSON 错误对象；批量写入在
  单个事务内完成，全部成功或全部失败，不会留下部分更新。

### `PUT /vulnerabilities/:id`

完整修正一条已有漏洞，登记写错后无需更换编号。编号由路径决定，与
`GET /vulnerabilities/:id` 沿用相同的精确匹配规则（区分大小写，不做去空格或
模糊匹配）；请求体中的 `id` 与任何无关字段均忽略。请求体是单个 JSON 对象，
`component`、`affected_ranges`、`severity`、`fixed_version`、`status` 的字段
含义、必填条件、版本与区间语义（开放边界、包含标志、区间反向、等端点须同时
包含等）以及严重等级与处置状态取值，与 `POST /vulnerabilities` 完全一致。

成功时在单个事务内整体替换除编号外的全部内容（含全部受影响区间），返回
HTTP 200 与包含 `id`、`component`、`affected_ranges`、`severity`、
`fixed_version`、`status` 的完整记录；`affected_ranges` 保持请求顺序，开放
边界字段为 `null`。更新不改变编号，更新后的查询使用新组件、新区间、新严重
等级、新修复版本与新处置状态。

- 请求体不是单个 JSON 对象、解析失败、必填字段缺失或为空、
  `affected_ranges` 为空或含非法区间、版本或边界包含标志非法、区间反向、
  上下界相等却未同时包含、`fixed_version` 非法、`severity` 或 `status`
  越界时，返回 HTTP 400 与固定纯文本 `error=INVALID_INPUT`。请求体先于编号
  校验：即使路径编号不存在，无效请求仍返回 `INVALID_INPUT`。
- 请求体有效但编号未知时返回 HTTP 404，响应体固定为纯文本
  `error=VULNERABILITY_NOT_FOUND`。
- 更新整体成功或整体失败，失败不留下部分字段或区间。存储写入失败返回
  HTTP 500 与现有 `internal_error` JSON 错误对象，不泄露 SQL、堆栈或文件路径。

### `GET /vulnerabilities`

分页列出已登记的漏洞。查询参数均可选并任意组合，缺省表示不按该字段过滤：

| 参数 | 要求 |
|---|---|
| `component` | 精确匹配，区分大小写；显式给出时不能为空 |
| `severity` | `low`、`medium`、`high`、`critical` 之一 |
| `status` | `open`、`in_progress`、`fixed`、`wont_fix`、`accepted` 之一 |
| `page` | 从 1 开始的页码，缺省为 1 |
| `page_size` | 每页条数，缺省为 20，范围 1 到 100 |

三个筛选条件互为交集，`fixed_version` 不参与筛选；其他查询参数不参与筛选，
也不单独报错。成功返回 HTTP 200 与单个 JSON 对象：

```json
{"items":[{"id":"CVE-2024-0001","component":"libxml2","affected_ranges":[{"lower":"2.0","lower_include":true,"upper":"2.9","upper_include":false},{"lower":null,"lower_include":null,"upper":"1.5.0","upper_include":true}],"severity":"high","fixed_version":"2.10.0","status":"open"}],"page":1,"page_size":20,"total":1}
```

`items` 是命中的完整漏洞记录，字段与按编号读取一致，`affected_ranges`
保持登记顺序，开放边界为 `null`。记录按编号升序后按 `page` 与 `page_size`
切片；`total` 是筛选后的总记录数，`page` 与 `page_size` 回显有效请求值。
合法查询无命中或页码超过总页数时 `items` 为空数组，其余三个字段仍返回
确定值，不返回 404。`page`、`page_size` 不是正十进制整数或越界，以及筛选值
非法（显式 `component` 为空、`severity` 或 `status` 不在允许集合内）时，返回
HTTP 400 与纯文本 `error=INVALID_INPUT`。存储读取失败时返回 HTTP 500 与
`internal_error` JSON 错误对象。

## 版本顺序

版本号是一个或多个用点分隔的十进制数字段（如 `1`、`1.0.3`、`10.2.0`）。
比较时从左到右逐段按数值比较；缺失的尾段按 0 比较，因此 `1`、`1.0`、`1.0.0`
彼此相等。

## 错误约定

漏洞登记、查询与状态维护入口的错误响应为固定纯文本，形如
`error=DUPLICATE_VULNERABILITY`，不包含 SQL、堆栈或文件路径。此前已公开的
`GET /healthz` 等入口仍使用单个顶层 `error` 对象（含 `code` 与 `message` 两个
字符串字段），语义保持不变。
