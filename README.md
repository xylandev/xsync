# xsync server

`xsync-server` 是单机、多租户的文件中转服务。上传方可使用 SFTP、FTP/FTPS 或兼容 S3 的客户端；下载方通过专用 HTTPS API 认领不可变文件版本，校验 SHA-256 后确认删除。

## Docker 部署

服务端只以 Docker 镜像部署。宿主机 `/etc/xsync` 保存配置、TLS 证书和 SSH host key，`/mnt/xsync` 示例为已经通过 fstab、云盘或存储系统挂载的数据暂存盘。先设置 Compose 环境并把目录交给镜像内的非 root 用户：

```bash
cp .env.example .env
sudo mkdir -p /etc/xsync /mnt/xsync
sudo chown -R 65532:65532 /etc/xsync /mnt/xsync

docker compose build
docker compose run --rm xsync-server init \
  --config /etc/xsync/config.yaml \
  --data-dir /data \
  --advertise-ip 203.0.113.10

docker compose run --rm xsync-server account add \
  --config /etc/xsync/config.yaml \
  --id customer-a

docker compose run --rm xsync-server validate-config --config /etc/xsync/config.yaml
docker compose up -d
docker compose ps
docker compose logs -f xsync-server
```

`--advertise-ip` 必须填写客户端可访问的服务器 IP：它会写入 TLS 证书，并作为 FTP 被动模式响应地址。`init` 只初始化服务配置、TLS 证书和 SSH host key，不创建任何默认账号。零账号时服务也可以正常启动，只是所有协议认证都会失败。

账号命令会生成 `/etc/xsync/client-configs/customer-a.yaml`。这个文件已经包含服务地址、SFTP/FTPS/S3 上传凭证、下载 API Key、CA 公钥证书和证书/SSH host key 指纹，不包含任何服务器私钥。它的权限为 `0600`，应通过安全渠道交给账号使用者。

生成的主配置只有三项，通常不需要人工修改：

```yaml
data_dir: /data
public_host: 203.0.113.10
accounts_file: /etc/xsync/accounts.yaml
```

协议端口、TLS/SSH 文件位置、容量水位、partial TTL 和性能参数均使用内置安全默认值。账号秘密位于权限为 `0600` 的 `accounts.yaml`，只由 `init` 和 `account add` 命令维护，不需要手工编辑。

默认 Compose 配置使用 UID/GID `65532`、只读根文件系统、移除 Linux capabilities，并把 `.env` 指定的两个持久目录绑定到 `/etc/xsync` 和 `/data`。如果宿主机目录属于其他服务账号，可修改 `XSYNC_UID` 和 `XSYNC_GID`。Compose 不为数据盘提供隐式默认值，未设置 `XSYNC_DATA_DIR` 会直接报错；请确保它指向真实挂载盘，而不是宿主机系统盘上的普通目录。

镜像健康检查访问容器内的指标端点。升级时执行 `docker compose build && docker compose up -d`，Docker 会向旧进程发送 `SIGTERM`，服务有 45 秒完成优雅退出。

默认监听端口：

- SFTP `2022`
- FTP/显式 FTPS `2121`，被动端口 `30000-30100`
- S3 HTTPS `9000`
- 下载 API HTTPS `9443`
- 本机指标 `127.0.0.1:9090/metrics`

FTP 默认要求 TLS。只有租户配置 `allow_plain_ftp: true` 时才接受明文 FTP。

如修改 `ftp.passive_start` 或 `ftp.passive_end`，必须同步修改 Compose 的被动端口映射。若服务器有防火墙，也需放行上述监听端口。

## 账号管理

一个账号对应一个隔离的 tenant，并一次性拥有 SFTP、FTPS、S3 和下载 API 四组凭证。`init` 不创建账号，所有账号统一使用 `account add` 创建：

```bash
docker compose run --rm xsync-server account add \
  --config /etc/xsync/config.yaml \
  --id customer-b

docker compose restart xsync-server
```

命令会在文件锁保护下原子更新账号库，并生成 `/etc/xsync/client-configs/customer-b.yaml`。从宿主机的 `${XSYNC_CONFIG_DIR}/client-configs/customer-b.yaml` 复制该文件即可；不需要再单独复制 `tls.crt`，也不需要人工拼装客户端配置。随后重启服务使新账号生效。

账号 ID 默认同时作为 SFTP/FTP 用户名和 S3 bucket；如 ID 不适合作为 bucket，可增加 `--s3-bucket uploads-customer-b`。高级场景仍可使用 `--weight`、`--max-concurrent`、`--max-upload-bps` 和 `--allow-plain-ftp`。如需把连接包输出到其他位置，使用 `--client-config /path/account.yaml`。

连接包结构示例（敏感值已省略）：

```yaml
version: 1
account: customer-b
download:
  endpoint: https://203.0.113.10:9443
  api_key: ...
sftp:
  host: 203.0.113.10
  port: 2022
  username: customer-b
  password: ...
  host_key_sha256: SHA256:...
ftps:
  host: 203.0.113.10
  port: 2121
  username: customer-b
  password: ...
  tls_mode: explicit
s3:
  endpoint: https://203.0.113.10:9000
  bucket: customer-b
  access_key: ...
  secret_key: ...
  region: us-east-1
security:
  tls_ca_pem: |-
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  tls_certificate_sha256: ...
```

由旧版本 `init` 生成且未修改高级参数的完整配置，会在第一次执行 `account add` 时自动迁移为上述三行主配置；原账号全部保留。

## 开发验证

本地开发要求 Go 1.26.6 或更新版本：

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

## 一致性模型

写入首先进入 `staging/`。成功关闭后执行文件 `fsync`、SHA-256、原子改名和元数据事务，之后才进入下载队列。同一路径的覆盖会产生新的不可变 object ID；旧版本下载完成时只删除旧 object ID，不会删除后来覆盖的新文件。

服务端状态机为：

```text
UPLOADING -> FINALIZING -> READY -> LEASED -> DELETE_PENDING -> DELETED
```

崩溃恢复会重新处理 `FINALIZING`、过期租约和 `DELETE_PENDING`。客户端下载采用至少一次投递、幂等确认语义。

## 下载 API

所有 `/v1/` 请求使用 `Authorization: Bearer <API Key>`：

- `POST /v1/claims`：认领对象。
- `POST /v1/claims/{lease}/renew`：续租。
- `DELETE /v1/claims/{lease}`：释放任务。
- `GET /v1/objects/{id}/content`：携带 `X-Xsync-Lease-ID` 下载，支持 HTTP Range。
- `POST /v1/objects/{id}/commit`：提交下载端计算的大小与 SHA-256，并条件删除远端版本。

## 容量保护

默认在 75% 水位开始自适应限速，90% 拒绝新写入，95% 进入保护状态。控制器使用上传、下载和确认删除吞吐的 EWMA 估算 30 分钟剩余容量窗口，并按租户权重分配上传预算。长期上传速率高于下载速率时，任何单机系统最终都会耗尽磁盘，因此硬水位拒绝新写入是可靠性边界。

## S3 范围

支持核心对象操作、Range 和 multipart。ACL、生命周期、复制、对象锁和 S3 版本控制不属于当前范围。S3 前端依赖 `go-faster/fs` 的可嵌入 handler；该上游仍标注为开发/测试用途，未经目标客户端兼容性测试和故障测试不得直接作为生产发布依据。
