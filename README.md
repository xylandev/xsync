# xsync server

`xsync-server` 是单机、多租户的文件中转服务。上传方可以用 SFTP、FTP/FTPS 或兼容 S3 的客户端上传；下载方通过专用 HTTPS API 认领不可变的文件版本，校验 SHA-256 后确认删除。

- 产品定位、架构、状态机与安全模型：[docs/architecture.md](docs/architecture.md)
- 下载 API 契约：[docs/api.md](docs/api.md)

## Docker 部署

服务端只以 Docker 镜像部署。宿主机上的两个目录：

- `/etc/xsync` 保存配置、CA、证书、SSH host key、账号库和密钥；
- `/mnt/xsync` 是已经挂载好的数据暂存盘（通过 fstab、云盘或存储系统挂载）。

```bash
cp .env.example .env
sudo mkdir -p /etc/xsync /mnt/xsync
sudo chown -R 65532:65532 /etc/xsync /mnt/xsync

docker compose build
docker compose run --rm xsync-server init \
  --config /etc/xsync/config.yaml \
  --data-dir /data \
  --advertise-ip 203.0.113.10 \
  --metrics-listen 0.0.0.0:9090

docker compose run --rm xsync-server account add \
  --config /etc/xsync/config.yaml \
  --id customer-a

docker compose up -d
docker compose ps
```

`init` 生成以下内容：

- 长期 CA（10 年）和由它签发的服务证书（397 天，IP SAN 为 `--advertise-ip`，可以用 `--dns` 追加域名）；
- SSH host key；
- S3 密钥加密用的 `secrets.key`；
- 管理接口令牌 `admin.token`；
- 数据盘上的卷标记 `.xsync-volume`。

之后数据盘没有挂载时（容器里只剩一个空目录），服务会拒绝启动，不会把数据写到系统盘。

`init` 可以安全地重复执行：加 `--force` 只重写配置，账号、CA、SSH host key 都会保留。只有显式加上 `--regenerate-ca` 或 `--regenerate-ssh-key` 才会重新生成。

`--advertise-ip` 必须是客户端能访问到的 IP，它同时用于服务证书和 FTP 被动模式应答。

默认端口：

- SFTP `2022`
- FTP/显式 FTPS `2121`，被动端口 `30000-30100`
- S3 HTTPS `9000`
- 下载 API HTTPS `9443`
- 指标与管理接口 `9090`，compose 只映射到宿主机的 `127.0.0.1`

宿主机端口必须与容器端口一致，因为服务端会把自己的端口写进连接包和 FTP 被动应答。要改端口，需要同时修改 `config.yaml` 和 compose 的映射。

Docker 发送 `SIGTERM` 后，服务进入排空状态：拒绝新上传，已在进行的传输有 40 秒（`shutdown_grace`）来完成，未完成的上传保存为可续传分片。`stop_grace_period` 设为 50 秒。

## 账号管理

每个账号是一个隔离的租户，同时拥有 SFTP、FTPS、S3 和下载 API 四组凭证。**所有账号改动都会在 5 秒内自动生效，不需要重启服务。**

```bash
# 以下命令都在容器里执行：docker compose run --rm xsync-server <命令> --config /etc/xsync/config.yaml …
account add     --id customer-b [--s3-bucket b] [--weight 2] [--max-concurrent 8] \
                [--max-upload-bps N] [--max-stored-bytes N] [--allow-plain-ftp] \
                [--overwrite supersede|keep] [--no-hold | --hold-pattern '*.part'] \
                [--publish-delay 10s] [--max-attempts 10] [--client-config -]
account list
account update  --id customer-b --max-stored-bytes 500000000000
account disable --id customer-b      # 所有协议立即拒绝该账号，数据保留
account enable  --id customer-b
account rotate  --id customer-b      # 更换全部凭证并生成新的连接包
account remove  --id customer-b      # 然后执行 admin purge --tenant customer-b 删除数据
```

`account add` 和 `account rotate` 生成的连接包（`client-configs/<id>.yaml`，权限 0600）是唯一包含明文凭证的地方：

- 服务端对 SFTP/FTP 密码只保存加盐哈希，对下载 API Key 只保存 SHA-256；
- S3 secret 用 `secrets.key` 加密存放。

把连接包通过安全渠道交给使用者后，从服务器上删掉。也可以用 `--client-config -` 直接输出到标准输出，不落盘。

两个与投递相关的账号选项：

- **覆盖策略**：`supersede`（默认）表示同一路径再次上传时，丢弃尚未投递的旧版本；`keep` 表示每个版本都投递。
- **临时名暂存**：默认暂存 `*.filepart`、`*.partial`、`*.tmp`，改名为正式名后才投递。这样可以正确处理 WinSCP、rclone 等"先写临时名再改名"的工具。

## 证书

```bash
cert info  --config /etc/xsync/config.yaml
cert renew --config /etc/xsync/config.yaml [--days 397] [--advertise-ip …]
```

连接包信任的是 CA，所以续期服务证书不需要更换连接包，运行中的服务几秒内自动加载新证书。指标 `xsync_tls_cert_not_after_seconds` 可以用来设置到期告警。

## 运维

```bash
# 运行中的服务（通过本机管理接口，需要 admin.token）
admin tenants                        # 每个账号的积压、死信、最老对象的等待时长、上传速率
admin parked  --tenant customer-a    # 死信列表（投递次数用尽或下载端报告永久失败）
admin requeue --tenant customer-a --id <object>
admin delete  --tenant customer-a --id <object>
admin purge   --tenant customer-b    # 删除已停用或已移除账号的全部数据
admin check                          # 检查索引与 blob 的一致性
admin rebuild-indexes
admin reload                         # 立即重新加载账号和证书（也可以发 SIGHUP）

# 服务停止时
catalog check  --config …
catalog repair --config …            # 重建索引，并清理孤儿文件
```

指标：`curl http://127.0.0.1:9090/metrics`。存活探针用 `/healthz`，就绪探针用 `/readyz`（排空中或磁盘危急时返回 503）。

## 容量保护

- 使用率达到 75%：立即按"删除速率 + 剩余空间 / 30 分钟"限制上传速率，预算只在正在上传的账号之间按权重分配；
- 达到 90%：拒绝新上传；
- 达到 95%，或可用空间低于 `min_free_bytes`：所有写入失败。

服务端复制（S3 拼装、续传时克隆当前版本）会先预留空间。服务启动时空间不足也不会拒绝启动，而是只允许下载，让积压可以排空。

## 从上一版本升级

- **catalog**：打开时自动从 schema 1 迁移到 schema 2，不需要手工操作。
- **配置**：旧配置可以直接使用。第一次执行账号命令时，明文密码会改写为哈希；如果已配置 `secrets_key_file`，S3 secret 会被加密。
- **数据卷标记**：旧部署先执行一次 `volume adopt --config …`，写入数据卷标记。
- **证书**：旧部署的自签证书同时充当 CA，有效期 2 年。在到期前执行 `cert renew --new-ca`，然后用 `account rotate` 为每个账号重新签发连接包。
- **FTP 默认行为变化**：`ALLO` 声明的大小与实际不符时拒绝发布；控制连接在数据连接结束后 200ms 内断开时，按中断处理。

## 开发验证

需要 Go 1.26.6 或更新版本：

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

CI（`.github/workflows/ci.yml`）会检查格式、运行 vet、带竞态检测的测试、漏洞扫描和镜像构建。

## S3 范围

支持核心对象操作、Range 和 multipart。以下功能都会被前置守卫拒绝：

- ACL、生命周期、复制、对象锁、S3 版本控制；
- 服务端复制；
- 浏览器表单上传。

S3 前端基于 `go-faster/fs`，上游仍标注为开发/测试用途。xsync 已经在它前面加了独立的授权守卫，并在后端再做一次租户校验；上线前仍建议针对目标客户端做一轮兼容性测试。
