# 下载 API 契约（v2）

服务端在每个已认证响应里返回 `X-Xsync-API-Version: 2`。v2 只做向后兼容的扩展：v1 客户端（不带 `max`、不带 `wait_seconds`、用 `DELETE` 释放）无需任何修改即可继续使用。

所有 `/v1/` 请求都需要：

```http
Authorization: Bearer <API Key>
```

错误响应统一为 JSON，不含服务端内部路径或堆栈：

```json
{"error": "the lease is no longer held", "code": "lease_mismatch", "status": 409}
```

| `code` | HTTP | 含义 |
|---|---|---|
| `bad_request` | 400 | 请求体或参数不合法 |
| `unauthorized` | 401 | API Key 缺失、错误或账号已停用 |
| `not_found` | 404 | 对象或租约不存在（或属于其他账号） |
| `lease_mismatch` | 409 | 租约已不属于调用方（过期、被释放或被他人重新认领） |
| `not_parked` | 409 | 只能对死信对象执行该操作 |
| `digest_mismatch` | 422 | commit 的大小或 SHA-256 与对象不一致 |
| `throttled` | 429 | 该来源地址认证失败次数过多，稍后再试 |
| `draining` / `critical_capacity` | 503 | 服务正在关闭，或磁盘处于危急水位（仅 `/readyz`） |
| `internal` | 500 | 服务端内部错误，细节只写日志 |

## 认领

```http
POST /v1/claims
{"client_id": "downloader-1", "prefix": "", "lease_seconds": 120, "max": 16, "wait_seconds": 20}
```

| 字段 | 说明 |
|---|---|
| `client_id` | 必填，下载端标识，只用于日志和审计 |
| `prefix` | 可选，按路径段匹配：`data` 命中 `data` 与 `data/…`，不命中 `database.txt` |
| `lease_seconds` | 租约长度，默认 120，范围 10 秒到 `delivery.max_lease`（默认 1 小时） |
| `max` | v2：一次最多认领多少个对象（上限 `delivery.max_batch`，默认 64）。**带上该字段时**，响应为批量格式 |
| `wait_seconds` | v2：队列为空时，在服务端等待新对象的最长时间（上限 `delivery.max_long_poll`，默认 30 秒） |

响应：

- 带 `max`：`200 {"claims": [<claim>, ...]}`；
- 不带 `max`（v1 兼容）：`201 <claim>`；
- 等到超时仍然没有对象：`204`。

认领单：

```json
{
  "lease_id": "…", "object_id": "…", "tenant": "…", "client_id": "…",
  "path": "in/report.csv", "size": 1234, "sha256": "…",
  "version": 42, "attempts": 1,
  "lease_until": "2026-09-24T12:00:00Z", "lease_seconds": 120
}
```

- `version` 在账号内单调递增。同一路径出现多个版本时，版本号大的更新。
- `attempts` 是该对象已被交出的次数，含本次。次数达到上限（`delivery.max_attempts` 或账号的 `max_attempts`，默认 10）后，下一次失败会让对象进入死信（PARKED）。

## 续租

```http
POST /v1/claims/{lease}/renew
{"lease_seconds": 120}
```

请求体可以省略。省略时按认领时的租约长度续期，不会因为漏传参数而缩短租约。已经过期的租约不能续：返回 `409`，下载端应立即停止写入。

## 下载

```http
GET /v1/objects/{object_id}/content
X-Xsync-Lease-ID: <lease_id>
Range: bytes=1048576-
If-Range: "sha256:<hex>"
```

- 支持 `Range` 和 `If-Range`，完整内容返回 `200`，部分内容返回 `206`。
- 响应头带 `ETag: "sha256:<hex>"`、`X-Content-SHA256` 和 `X-Xsync-Lease-Until`。
- 下载开始时租约必须有效。

## 确认删除

```http
POST /v1/objects/{object_id}/commit
{"lease_id": "…", "sha256": "<hex>", "size": 1234}
```

- 校验通过：删除对象（同一个事务内写入墓碑），返回 `204`。
- 对已删除对象重复 commit：仍返回 `204`（幂等，墓碑保留 `delivery.tombstone_ttl`，默认 7 天）。
- 租约已不属于调用方：`409`，文件不会被删除。
- 大小或哈希不一致：`422`。

## 释放

```http
POST /v1/claims/{lease}/release
{"reason": "destination conflict", "retry_after_seconds": 60, "permanent": false, "count_attempt": true}
```

`DELETE /v1/claims/{lease}` 与上面等价，可带相同的请求体，也可以不带。

| 字段 | 说明 |
|---|---|
| `reason` | 失败原因，记为对象的 `last_error`，在死信列表中可见 |
| `retry_after_seconds` | 对象回到队尾，并在这段时间内不可见（0–86400） |
| `permanent` | 不再重试，直接进入死信 |
| `count_attempt` | 设为 `false` 表示这次不算失败（例如下载端正在关闭），会退还一次投递次数 |

被释放的对象总是回到**队尾**，因此一个反复失败的对象不会堵住整个队列。上传方已删除或已覆盖的对象，释放后直接删除，不再投递。

## 死信

```http
GET    /v1/parked?limit=100               → 200 {"objects": [...]}
POST   /v1/objects/{object_id}/requeue    → 204（回到队尾，投递次数清零）
DELETE /v1/objects/{object_id}            → 204（只能删除死信对象）
```

## 探测

- `GET /healthz`：进程存活时返回 `200`。
- `GET /readyz`：服务正在关闭或磁盘处于危急水位时返回 `503`。只返回结论，不暴露磁盘细节。

## 下载端最小流程

```text
循环:
  POST /v1/claims {max: 空闲 worker 数, wait_seconds: 20}
  对每个认领单并行:
    后台按 lease_until 剩余时间的 1/3 续租；续租返回 404/409 时立即停止
    GET content（断点续传用 Range + If-Range）
    本地核对 size 与 sha256
    原子落盘
    POST commit
    失败时 release：可重试的错误带 retry_after_seconds；
                   不可能成功的错误（路径非法、冲突策略拒绝）带 permanent=true
  收到 SIGTERM：对手里的租约 release，并带 count_attempt=false
```
