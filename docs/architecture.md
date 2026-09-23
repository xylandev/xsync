# xsync 产品与架构说明

`xsync-server` 是单机、多租户的**文件中转服务**。上传方用现成的 SFTP、显式 FTPS 或兼容 S3 的客户端把文件写入暂存盘；下载方通过专用 HTTPS API 认领不可变文件版本，校验 SHA-256 后确认删除。

它不是网盘，也不是长期对象存储。磁盘是中转暂存盘：文件进来、被认领、校验通过后删除。部署与运维步骤见仓库根目录 [README.md](../README.md)。

## 1. 定位与适用场景

适合「客户侧已经有上传工具、我方需要可靠地收下并清走」的场景，例如：

- 合作方用 SFTP / FTP 客户端或 AWS 兼容 SDK 推送数据包
- 内部下载进程按队列拉取、校验、落库或转存后，让中转盘尽快腾出空间
- 多客户共用一台中转机，账号之间目录、bucket、凭证隔离

不适合：作为永久文件库、做跨机集群、提供完整 AWS S3 控制面（ACL、生命周期、复制、对象锁、S3 版本控制均不在范围内）。

## 2. 总体架构

一个进程、一块数据盘、一套共享 Store。进程内并行监听上传、下载和本机指标。

```text
上传 SDK ── SFTP :2022 ──┐
上传 SDK ── FTPS :2121 ──┼── Store (staging → objects + bbolt catalog)
上传 SDK ── S3   :9000 ──┘         ▲
                                   │ 容量控制器（水位 / 限速 / 租户配额）
下载客户端 ── HTTPS :9443 ─────────┘
本机监控 ── 127.0.0.1:9090/metrics
```

| 面 | 默认地址 | 传输 | 用途 |
|---|---|---|---|
| SFTP | `:2022` | SSH，密码或公钥 | 上传 |
| FTP / 显式 FTPS | `:2121`，被动口 `30000–30100` | 默认强制 TLS | 上传 |
| S3 兼容 | `:9000` | HTTPS + SigV4，path-style | 上传（及对象读写） |
| 下载 API | `:9443` | HTTPS + Bearer API Key | 认领 / 下载 / 确认删除 |
| 指标 | `127.0.0.1:9090/metrics` | 明文，仅本机 | 健康检查与 Prometheus |

三个上传前端写入同一套 Store。下载**不走** S3/SFTP 队列语义，只走带租约的 HTTPS API。容量控制器采样磁盘水位，按上传/下载/删除吞吐的 EWMA 调节写入预算。

数据盘布局：

```text
<data_dir>/
  staging/                 未完成上传
  objects/<tenant>/<id>.blob
  metadata/catalog.db      bbolt：对象、命名空间、队列、租约、墓碑
```

## 3. 核心概念

**租户（账号）**  
一个账号对应一个隔离 tenant，一次获得 SFTP、FTPS、S3、下载 API 四组凭证。账号 ID 默认同时作为 SFTP/FTP 用户名和 S3 bucket。

**对象版本**  
每次成功关闭的上传成为一条不可变记录，带独立 object ID、路径、大小、SHA-256。同一逻辑路径被覆盖时，namespace 指向新 ID；旧版本仍按自己的 ID 走完下载和删除，不会误删新文件。

**下载租约**  
下载端 `claim` 成功后对象进入 `LEASED`。拉取内容必须携带租约 ID。租约过期后对象回到 `READY`，可被再次认领。

**连接包**  
`account add` 生成 `client-configs/<id>.yaml`（权限 `0600`）：服务地址、四套凭证、CA 公钥、TLS/SSH 指纹。不含服务器私钥，应经安全渠道交给使用者。

## 4. 上传协议

路径会规范化（去前导 `/`、禁止 `..` 与 NUL）。写入先进入 `staging/`，客户端成功关闭后才会发布到下载队列。

### SFTP

- 密码认证；租户还可配置 `authorized_keys`
- 现代 OpenSSH 的 `sftp` 与默认 `scp`（走 SFTP subsystem）可用
- 中断的上传可按路径续传（`INTERRUPTED`）

### FTP / FTPS

- 显式 TLS（AUTH TLS），默认强制加密
- 仅当该租户 `allow_plain_ftp: true` 时接受明文 FTP
- 被动模式地址使用 `--advertise-ip` / `public_host`
- 修改被动端口范围时，必须同步改 Compose 端口映射和防火墙

### S3 兼容

- HTTPS 端点，path-style，region `us-east-1`
- 凭证为账号的 access key / secret key，bucket 默认等于账号 ID
- 支持核心对象操作、Range、multipart
- **不支持** ACL、生命周期、复制、对象锁、S3 版本控制
- 前端嵌入 `go-faster/fs`；上游仍标注为开发/测试用途，未经目标客户端兼容性与故障测试前，不能单独作为生产发布依据

本地可行验证中已跑通的上传客户端：paramiko、OpenSSH `sftp`/`scp`、Go `pkg/sftp`、Python `ftplib.FTP_TLS`、lftp、curl FTPS、Go `goftp`、boto3（单件与 multipart）、minio-py、Node AWS SDK v3、Go AWS SDK v2。

## 5. 下载 API

所有 `/v1/` 请求：

```http
Authorization: Bearer <API Key>
```

TLS 使用连接包里的 `security.tls_ca_pem` 校验服务端证书（证书算法为 ECDSA P-256，IP SAN 为 `advertise-ip`）。

未认证探测：

- `GET /healthz` → `200` / `ok`
- `GET /readyz` → 容量危急时 `503`

### 认领

```http
POST /v1/claims
Content-Type: application/json

{"client_id": "downloader-1", "prefix": "", "lease_seconds": 120}
```

| 字段 | 说明 |
|---|---|
| `client_id` | 必填，下载端标识 |
| `prefix` | 可选，只认领该路径下的对象。按路径段匹配：`data` 命中 `data` 与 `data/…`，不命中 `database.txt` |
| `lease_seconds` | 默认 120，上限 3600 |

- 有对象：`201`，body 为认领单
- 队列空：`204`

认领单字段：`lease_id`、`object_id`、`tenant`、`client_id`、`path`、`size`、`sha256`、`version`、`lease_until`。

续租：`POST /v1/claims/{lease}/renew`，body 可选 `{"lease_seconds": 120}`。  
放弃：`DELETE /v1/claims/{lease}`，对象回到可被他人认领。

### 下载内容

```http
GET /v1/objects/{object_id}/content
Authorization: Bearer <API Key>
X-Xsync-Lease-ID: <lease_id>
Range: bytes=0-1048575
```

响应带 `ETag`（`sha256:…`）和 `X-Content-SHA256`。支持 HTTP Range（完整命中为 `200`，部分为 `206`）。

### 确认删除

下载端在本地算完大小和 SHA-256 后提交：

```http
POST /v1/objects/{object_id}/commit
Content-Type: application/json

{"lease_id": "<lease_id>", "sha256": "<hex>", "size": 1234}
```

校验一致则删除该 object ID 对应的 blob，返回 `204`。大小或哈希不一致返回 `422`。对象已删后的重复 commit 仍返回 `204`（幂等）。

语义是**至少一次投递**：租约过期会重新进入队列；下载端必须以 commit 的幂等结果为准，不能假设「拉到一次就一定从服务器消失」。

## 6. 一致性与状态机

```text
UPLOADING → FINALIZING → READY → LEASED → DELETE_PENDING → DELETED
                ↘ INTERRUPTED（上传中断，可按路径续传）
                ↘ FAILED（无法恢复，等待回收）
```

1. 客户端写入 `staging/`，状态 `UPLOADING`
2. 关闭成功：`fsync` → 计算 SHA-256 → 原子改名到 `objects/` → catalog 事务发布，进入 `READY` 队列
3. 关闭失败或进程崩溃于上传中：`INTERRUPTED`
4. 下载端 claim 后 `LEASED`，同时离开队列；放弃或过期退回 `READY` 并按原顺序回队
5. commit 校验通过后 `DELETE_PENDING`，删 blob、写 tombstone

`DELETED` 是概念终态：对象记录被删除，只留一条 tombstone 用于幂等 commit。

SHA-256 在顺序写入时随流计算，`finalize` 不再重读一遍文件；一旦出现乱序写入或 truncate，则退回完整重算，保证目录里的哈希始终等于盘上内容。

启动恢复会：

- 把仍停在 `FINALIZING` 的上传做完（staging 还在则继续 finalize；blob 已改名则补发布）
- 过期 `LEASED` 退回 `READY`
- 未完成的 `DELETE_PENDING` 继续删
- 把崩溃时仍为 `UPLOADING` 的记录标为 `INTERRUPTED`

**单条记录恢复失败不会阻止启动**：读不出的 blob 等不可恢复情况会被标为 `FAILED` 并记入日志，服务继续启动，其余对象照常可用。若恢复期间无法写入 catalog（数据库本身损坏），才会拒绝启动。

后台维护循环（默认 30 秒）清理过期租约、超过 `partial_ttl`（默认 24 小时）的 `INTERRUPTED` / `FAILED` 记录及其残留 blob。扫描阶段只读，写入拆成逐条小事务，因此维护不会阻塞正在进行的上传。

## 7. 容量保护

默认水位（`config.Default()`）：

| 水位 | 默认 | 行为 |
|---|---|---|
| 软 | 75% | 按下载/删除 EWMA 与 30 分钟剩余窗口自适应限速；按租户 `weight` 分配上传预算 |
| 硬 | 90% | 拒绝新写入 |
| 危 | 95% 或低于 `min_free_bytes`（默认 5 GiB） | 保护状态，`/readyz` 为 503 |

租户还可设 `max_concurrent`（默认 8）和 `max_upload_bps`（0 表示不额外限制）。限速按整笔写入计费：超过令牌桶容量的大块写入会被切分逐段等待，不会有尾部字节免费通过。

S3 multipart 的 `CompleteMultipartUpload` 需要把各分片拼成完整对象，期间分片与成品同时在盘上，因此会先按分片总大小做一次容量预算，放不下时直接拒绝而不是写到危水位。拼装字节在分片上传时已计过量，不再重复限速。

上传长期快于下载时，任何单机系统最终都会写满。硬拒绝新写入是可靠性边界，不是故障。

## 8. 安全模型

- 对外 HTTPS / FTPS / S3 使用同一套 TLS 证书；`init` 签发 **ECDSA P-256** 证书（IP SAN = advertise-ip），最低 TLS 1.2。SSH host key 仍为 **Ed25519**。
- FTP 默认强制 TLS；明文 FTP 必须按租户打开。
- 主配置通常只有 `data_dir`、`public_host`、`accounts_file`，不含账号秘密。
- 账号库 `accounts.yaml` 与连接包权限 `0600`，由 `init` / `account add` 维护，不需手工改密钥。
- 下载 API 用 API Key 的 SHA-256 做常时间比较；SFTP/FTP 密码同样常时间比较。
- 认证后的租户身份只在请求 context 内传递，不经由请求头，客户端无法伪造。
- 下载 API 每个请求记一条访问日志（方法、路径、状态码、字节数、租户、来源地址、耗时），`/healthz` 与 `/readyz` 降到 debug 级以免刷屏。
- 生产镜像：UID/GID `65532`、只读根文件系统、drop 全部 Linux capabilities、两个 bind 卷（配置盘与数据盘）。
- 生产要求 `data_dir` 为独立挂载点，避免暂存写到系统盘。

## 9. 命令与账号

```text
xsync-server init             --config --data-dir --advertise-ip [--require-mount=false] [--force]
xsync-server account add      --config --id [--s3-bucket] [--weight] [--max-concurrent]
                              [--max-upload-bps] [--allow-plain-ftp] [--client-config]
xsync-server validate-config  --config
xsync-server serve            --config
xsync-server healthcheck      [--url http://127.0.0.1:9090/metrics]
xsync-server version
```

`init` 不创建账号。`account add` 在文件锁下原子写入账号库并生成连接包；**新账号需重启 `serve` 才生效**。

本地开发可 `--require-mount=false`。生产 Docker 流程以 README 为准。

## 10. 当前范围

- 单机，不是集群，没有跨节点复制或故障转移。
- S3 只覆盖核心对象路径；完整 AWS 兼容性不是目标。
- 连接包里的 `public_host` 必须是客户端能访问的 IP（同时用于证书 SAN 和 FTP 被动模式地址）。
- 指标中无上传限速时，`xsync_upload_limit_bytes_per_second` 可能显示为极大浮点数，属展示问题。

## 11. 下载端最小流程

```text
循环:
  POST /v1/claims          → 204 则空闲退出或退避
  GET  /v1/objects/{id}/content   (X-Xsync-Lease-ID)
  本地计算 size 与 sha256
  与认领单核对
  POST /v1/objects/{id}/commit
```

大文件应续租（`/v1/claims/{lease}/renew`）。需要断点续传时用 `Range`。哈希不一致不要 commit，可释放租约让对象重新入队。
