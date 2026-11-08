# RT 远程 (remotetool)

私密、轻量、跨 **Windows / Linux (Ubuntu) / Android** 的远程工具。三大功能：

- **远程终端** — 真实 PTY（Windows ConPTY / Unix forkpty），多会话、断线重连回放
- **文件传输** — 分块流式、断点续传、SHA-256 校验、冲突策略、远程文件浏览器
- **端口转发** — SSH 隧道语义（`-L` 本地转发 / `-R` 远程转发），规则持久化

每一层都是端到端加密：配对用 **6 位配对码 + SPAKE2（P-256）+ TLS 通道绑定**，
连接用 **设备证书（Ed25519）+ QUIC/TLS 1.3 + 证书钉扎**，杜绝中间人。
无账号体系、无第三方服务器——局域网 mDNS 直连；跨公网用你**自建**的 hub，
中继只传输密文。

## 快速开始

### 1. 构建

```bash
./build.sh          # 当前平台 -> dist/
./build.sh release  # 交叉编译 windows/linux/android -> dist/release/
```

产物：`rtd`（守护进程，含 Web UI）、`rt`（CLI）、`hub`（可选自建中继）。

### 2. 启动守护进程

```bash
rtd                        # 默认配置目录（Windows %APPDATA%/remotetool，Linux ~/.config/remotetool）
rtd --name 我的电脑        # 设备名
rtd --listen-port 27183 --web-port 27180   # 自定义端口
```

启动后打印 Web UI 地址：`http://127.0.0.1:27180/?t=<token>`。浏览器打开即用。

### 3. 配对（每对设备做一次）

- **A 设备**（被信任的一方）：Web UI「设备」页 → 生成配对码；或 `rt pair`
- **B 设备**：输入 A 的地址 + 配对码；或 `rt pair 192.168.1.20:27183 123456`

配对码 5 分钟有效、单次使用；SPAKE2 保证码本身不离开设备。

### 4. 使用

```bash
rt status                  # 本机与设备列表
rt ls                      # 同上
rt term 设备B              # 远程终端（原始 TTY）
rt cp ./big.zip 设备B:Downloads/big.zip    # 上传
rt cp 设备B:C:/data/report.docx ./        # 下载
rt fwd add 设备B -L 13389:localhost:3389  # 经设备B访问其远程桌面
rt fwd add 设备B -R 9090:localhost:8080   # 让设备B访问本机服务
rt fwd list / rt fwd rm <id>
rt url                     # 打印 Web UI 地址
```

Web UI 提供等价的图形界面：设备管理、双栏文件浏览器（拖拽上传）、
xterm.js 终端、转发规则管理、hub 配置。

### 5. 跨公网：自建 hub（可选）

设备不在同一局域网时，在一台 VPS 上运行 hub：

```bash
hub --listen :27190 --token 换个长随机串
```

各设备 Web UI「设置」页填入 `VPS地址:27190` 与 token（或 `rt hub vps:27190 TOKEN`）。
之后连接优先直连（含 hub 提供的地址），失败自动走 hub 中继——
**中继流内部还有一层设备证书的 TLS 会话，hub 只见密文**。
详见 [docs/deploy-hub.md](docs/deploy-hub.md)。

## 安卓

`dist/release/android-arm64/` 内为 Termux 可用二进制（GOOS=android，PIE）：

```bash
# 在 Termux 中
./rtd --home ~/remotetool
```

安卓端定位为主控端 + 文件传输对端（浏览/收发文件、当远程终端的客户端）。
后续将提供内嵌 Web UI 的薄壳 APK。

## 架构一览

```
┌─────────┐  QUIC/TLS1.3 (27183/udp)  ┌─────────┐
│  设备A  │◄──────────────────────────►│  设备B  │   局域网 mDNS 直连
└────┬────┘   控制流(JSON RPC)+数据流  └─────────┘
     │        (终端/文件/转发)
     │ 跨公网：先信令/地址解析，直连失败走中继
┌────▼────┐
│  hub    │  你的 VPS：只见密文（内层 TLS 端到端）
└─────────┘
```

每条 QUIC 连接上：1 条控制流承载 JSON RPC（hello/配对/fs 操作/传输握手/
resize 等），数据流按类型复用（`ChanTerm`/`ChanFile`/`ChanFwd`）。
协议细节见 [docs/design.md](docs/design.md)。

## 依赖

Go 1.26；运行时零依赖。第三方库：quic-go、yamux、zeroconf、creack/pty、
x/sys、x/term、x/net（详见 go.mod）。

## 已验证

- 本机双实例：配对（正确码通过/错码拒绝）、连接、远程列目录
- 8MB 文件推送/拉取 SHA-256 一致；预置半成品续传（push/pull 双向）通过
- 端口转发 `-L`/`-R` 实测 HTTP 经隧道访问对端 Web 服务
- 浏览器 xterm.js 终端与 CLI `rt term` 交互正常
- 直连地址被破坏时自动经 hub 中继：连接/列目录/传输/终端全部通过
- 交叉编译：windows/amd64、linux/amd64、linux/arm64、android/arm64

## 已知限制（v0.1）

- 老 Windows（<10 1809）无 ConPTY，终端走管道兜底（无 ANSI、推荐 chcp 65001）
- Linux/安卓二进制为编译冒烟，建议在真机上先行验证
- UDP 打洞 P2P 直连尚未实现（当前直连失败即走 hub 中继）
- Android APK 薄壳、SOCKS5 出站代理在路线图中
