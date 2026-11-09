# AGENTS.md — remotetool

跨平台（Windows/Linux/Android）私密远程工具：远程终端、文件传输、端口转发。Go + QUIC（quic-go v0.65，API 是 `quic.Conn`），SPAKE2-P256 配对 + 设备证书通道绑定。无账号、去中心化，hub 只见密文。

## 目录

- `cmd/rt` — 薄 CLI，**只与本机 rtd 的 web API 通信**（127.0.0.1），绝不直连对端
- `cmd/rtd` — 守护进程；`cmd/hub` — 自托管中继；`cmd/termprobe` — 终端 WS 自动化探针
- `internal/`：`config`（config.json+peers.json 持久化）、`daemon`（装配+webAPI+pair.go 配对）、`session`（握手/连接表/hubclient）、`transport`（QUIC 封装）、`proto`（JSON RPC + 二进制流头）、`term`/`filex`/`fwd`（三大 Feature）、`web`（embed 的 vanilla JS UI，无构建步骤）、`identity`（Ed25519 证书/SPAKE2）、`hub`、`discover`（mDNS）

## 工具链与命令

```bash
export PATH="/d/tools/go/bin:$PATH" GOPATH=/d/tools/gopath GOPROXY=https://goproxy.cn  # 本机必设，proxy.golang.org 被墙
go build ./... && go vet ./... && go test -count=1 ./...
./build.sh            # 产出 dist/{rt,rtd,hub}.exe（release 目标再交叉编译 4 平台）
gofmt -l .            # 必须为空
```

- Go 1.26（go.mod）；本机无 gcc，**`-race` 跑不了**，由 `.github/workflows/ci.yml`（ubuntu）执行 `go test -race`。
- `-X main.version` 只对 `var` 生效：`cmd/rt`、`cmd/rtd`、`cmd/hub` 的 `version` 必须保持 `var`，不许改 `const`。
- Windows 下 `go test` 后临时文件句柄可能延迟释放；测试里用 `t.TempDir()` 并显式 close。

## 架构边界（改代码前必读）

- `rt` 只走本机 web API；对端通信全部在 rtd 内（`session.Manager` → `Feature.AttachRPC/HandleStream`）。
- **会话/传输按设备隔离**：`term.Session.owner`、`filex.recvState.peerID` 是权威值；所有 RPC handler 和 HandleStream 路径必须校验归属，拒绝时对外统一报 "no such …"（防存在性探测）。
- **fwd 不做开放代理**：拨号目标从不上线缆（`h.Dial` 一律拒绝）。mode L 要求对端先经 `fwd.grant` 登记（按连接代际绑定、断连即清）；mode R 只认本机 config 里 `PeerID`==调用方且 `Mode=="R"` 的规则。改动 fwd 控制方法时保持归属校验。
- **配对防爆破**：错码 5 次作废邀请；按设备指数退避（2s→5min）；对端只见统一 `errPairingFailed`，具体原因只进本地日志；未配对连接有信号量(8)+令牌桶(10/s,20)。
- `webAPI.Push/Pull` 是**异步**：在传入 ctx 下起传输并立即返回 id（id 用 `filex.NewXferID()` 预生成，供 `/api/xfer/cancel` 取消）。
- SSE `/api/events` 按传输 id 缓存最新事件，`?xfer=<id>` 会回放 —— `rt cp` 的干净退出依赖它。**发送端进度必须走服务级 `s.progress()`**（webAPI 传的 per-call onProg 是 nil）。
- `config.Store.Get()` 返回深拷贝：禁止再对 `FwdRules` 做切片原地改写，增删用 `AddFwdRule/RemoveFwdRule`；`loadConfig` 只在 seed 时落盘（并发 rt 进程）。
- 关键超时不要删：`transport.Open` 内部 30s、握手 hello 10s、中继内层 TLS 15s、fwd 拨号 10s。流配额：每 peer 数据流 64、fwd 规则每设备 32、grant 256、hub 设备 256。
- 协议兼容：`DataHeader.RuleID` 要求与老版本不兼容（裸 Dial 被拒），此类改动必须随版本同步发布。

## 约定

- 标准 gofmt（tab）、英文注释、`log/slog`；不随意加依赖。
- 证书校验：仅自签 Ed25519，**有意不查有效期/CA**（见 `identity.VerifyFunc` 注释），认证靠钉扎公钥或配对码+通道绑定（`transport.CertBinding`，"rtd/cb/v1"，不是 TLS exporter）。
- Windows PTY 走 ConPTY（`pty_windows.go`），unix 走 creack/pty；`joinRemote` 按远端路径风格选分隔符。长驻 goroutine 顶层要有 recover（现有模式照抄）。
- web UI（`webdist/`，vanilla JS）无构建步骤；app.js 与 server 端 token/cookie 流程耦合，改一边要看另一边。

## 验证方法（双实例 e2e）

`RT_HOME=/d/rt-test/{a,b}` 各起 rtd（端口 27183/27184，web 27180/27181），hub `127.0.0.1:27190`（token hubtest），经 web API `X-RT-Token` 驱动；强制走中继 = 改 peers.json 的 `last_addr` 为错端口。坑：`/api/peers/connect` 只认十六进制设备 ID；`/api/fwd/add` 直接收 `FwdRule` JSON（字段名 `peer_id`）；termprobe 的 Origin 带端口。`docs/fix-plan.md` 各项修复附有逐条验证方式。

## 文档

`docs/design.md`（协议与机制描述，改协议须同步）、`docs/fix-plan.md`（v0.1 评审修复记录，全部已实施）、`README.md`（Go 版本须与 go.mod 一致）。`.gitignore` 含 `dist/`、`.zcode/`。
