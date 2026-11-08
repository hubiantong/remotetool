# RT 远程 设计文档

> 参考基础：`D:\project\uu` 内 UU远程（GameViewer / `com.netease.uuremote`）四平台逆向报告。
> 本文标注了哪些设计借鉴自 UU、哪些为其轻量化/私密化替代。

## 1. 目标与边界

| 维度 | 决策 |
|---|---|
| 平台 | Windows 10+、Linux (Ubuntu)、Android（Termux 二进制 / 后续 APK） |
| 功能 | 远程终端、文件传输、端口转发（「端口调用」） |
| 不做 | 屏幕串流/远程控制（UU 的重头，需 WebRTC/硬编，超出本项目范围） |
| 隐私 | 无账号、无第三方云；E2E 加密；自建 hub 只见密文 |
| 形态 | 单静态二进制守护进程 `rtd`（内置 Web UI）+ CLI `rt` + 可选 `hub` |

## 2. 身份与配对

- **设备身份**：Ed25519 长期密钥对；设备ID = SHA-256(公钥) 前 8 字节 hex（16 位）。
- **证书**：自签名 X.509（Ed25519），QUIC 握手双向出示；`ClientAuth: RequireAnyClientCert`，
  CA 校验完全让位于**证书钉扎**（对端公钥必须等于已配对记录）。
- **配对协议**（借鉴 UU 的 8 位协助码模式，去中心化）：
  1. B 生成 6 位配对码（5 分钟、单次有效），A 在有效期内输入；
  2. 双方在 TLS 信道内运行 **SPAKE2-P256**（密码=配对码），密钥确认双向 HMAC；
  3. **通道绑定**：SPAKE2 transcript 混入各自 TLS 信道的证书指纹对
     （`H(sorted(own_leaf, peer_leaf))`）。直连时两端一致；MITM 终结两条信道时
     不一致 → 确认失败。这同时防住了 PAKE 的透明转发攻击；
  4. 成功后双方落盘 `peers.json`（ID/名称/公钥/最近地址）。
- 实现位置：`internal/identity/spake2.go`（M/N 常量 try-and-increment 派生，带
  错码/MITM/非法点单测）、`internal/daemon/pair.go`。

## 3. 传输层

- **QUIC**（quic-go v0.65）：单 UDP 承载全部功能；TLS1.3 内建；流级多路复用、
  无队头阻塞；keepalive 15s / idle 90s。
- 传输抽象 `transport.Conn / Stream`（`internal/transport`）：Open/Accept 流 +
  RemoteID/RemotePub/ChannelBinding。当前 QUIC 实现；中继场景由
  **TLS + yamux** 组合出同接口的 `muxConn`（见 §6）。

### 3.1 信道划分（借鉴 UU 的四通道模型，WebRTC DataChannel → QUIC 流）

- **控制流**（每连接 1 条，拨号方打开）：u32 前缀 JSON 帧多路复用请求/响应/
  通知（`internal/proto/rpc.go`）。方法：`hello`、`pair.*`、`fs.*`、`xfer.*`、
  `term.open/resize/close/list`、`fwd.listen/unlisten`。
- **数据流**（按需多条）：首字节信道类型 + u32 前缀 JSON 头，其后为纯二进制：
  - `ChanTerm`：会话 id 定位，之后为 PTY 原始字节（输入输出同流）；
  - `ChanFile`：传输 id 定位，从续传偏移起的文件字节；
  - `ChanFwd`：`Dial`（对端拨目标）或 `RuleID`（反向监听回连）定位，之后为
    转发 TCP 连接的双向字节。

借鉴 UU 的 16 字节 `TERM` 帧头思路（type+sessionId+len），改为「头 JSON +
裸字节」，QUIC 流本身已是消息边界可靠的字节流，无需分块帧。

## 4. 远程终端（`internal/term`）

- 服务端会话表：`term.open` 启动 PTY 返回会话 id；数据流挂接双向泵。
- **PTY 后端**：
  - Windows：ConPTY（`CreatePseudoConsole` 系，1809+）；老系统（如 Server
    2016）自动降级为管道模式（`-NoLogo`/`chcp 65001` 缓解，无 ANSI）；
  - Unix：`creack/pty` fork/exec，`$SHELL`，TERM=xterm-256color。
- **会话存活 + 回放**（借鉴 UU 的 tmux 思路但内建）：客户端断开不杀会话；
  服务端持续把输出写入 256KB 环形缓冲，重连/刷新页面时先回放缓冲
  （`ClientAttach` + `term.attach` 路径）。
- 前端 xterm.js（vendor 本地化，无 CDN）；CLI `rt term` 原始模式
  （unix SIGWINCH / windows 轮询 resize）。

## 5. 文件传输（`internal/filex`）

借鉴 UU 的 `Ask→Confirm→Block(+ACK)→Complete` 状态机，QUIC 流化后简化：

1. **ask**：`xfer.push {id, path, size, conflict}` 或 `xfer.pull {id, src, offset}`；
2. **confirm**：接收端解析冲突（rename/skip/overwrite）、若存在
   `<final>.rtpart` 则哈希其前缀得到**续传偏移**，随响应返回 `{offset, path}`；
3. **data**：发送端从偏移起裸流文件字节（发送端同步哈希前缀，保证校验和
   覆盖全文件）；
4. **complete**：`xfer.complete {id, sha256}`，接收端等齐 EOF 与校验和
   （两事件无顺序保证，用 ready 通道合并），校验通过原子改名落盘；
   不完整时保留 `.rtpart` 供续传，校验失败/取消时删除。

fs 浏览操作：`fs.list/mkdir/rename/remove/stat`（`fs.list` 空路径在 Windows
返回盘符列表）。目录推送：`filepath.WalkDir` 逐文件 push。进度经事件总线
（SSE）推送 Web UI。

## 6. 发现与广域网

- **局域网**：mDNS 广播/浏览 `_rtd._udp.local.`，TXT 带 `id`/`name`
  （`internal/discover`）。
- **自建 hub**（`cmd/hub` + `internal/hub` + `internal/session/hubclient.go`）：
  - 设备→hub：QUIC（ALPN `rtd-hub/1`），`reg {token, id}` 注册、
    `resolve` 地址解析、`relay` 中继请求；
  - **加密中继**：请求方开数据流写 `{token, dst}`，hub 通知目的端
    `relay.incoming {src, token}`，目的端回开流 `{token}`，hub 按 token 配对
    后纯转发两条流（早到流缓存防竞态）。两条流内部再跑一层**设备证书的
    TLS 1.3 + yamux**（`muxConn`），因此 hub 只见密文；ChannelBinding 与
    直连一致，配对/钉扎语义不变；
  - 拨号顺序：LastAddr → mDNS 候选 → hub 解析地址 → 直连全败走中继。
- **未做**：UDP 打洞（v0.2 路线图）；hub 集群/多 token。

## 7. Web UI 与 CLI

- Web UI（`internal/web/webdist`，go:embed）：原生 JS + xterm.js（vendor 化），
  深色主题。页面：设备（配对/连接/发现）、终端（多标签会话）、文件（双栏 +
  拖拽 + 传输进度）、转发、设置（设备名/hub）。鉴权：仅 127.0.0.1 + token
  （header/query/cookie）。事件流 SSE（peer_up/down、传输进度）。
- CLI `rt`：全部经 daemon 本地 HTTP API（不与守护进程抢连接；
  `term` 走 WebSocket 桥）。

## 8. 安全清单

- [x] 配对码不离开设备（SPAKE2），错码/中间人单测覆盖
- [x] 已配对连接证书钉扎，密钥更换即拒绝
- [x] 未配对设备只在存在有效邀请时进入配对路径，否则拒绝
- [x] 中继只见密文（内层 TLS）
- [x] Web UI 仅回环 + token
- [x] 转发规则本地落盘，监听默认 127.0.0.1
- [ ] hub 多租户隔离 / 速率限制（单用户自建场景暂不需要）

## 9. 验证记录（2026-11-07，本机双实例 + hub）

配对成功/错码拒绝、8MB push/pull SHA-256 一致、4MB/6MB 半成品续传一致、
-L/-R 转发 HTTP 实测、浏览器与 CLI 终端交互、直连破坏后中继路径
（连接/列目录/传输/终端）全部通过；windows/linux/android（arm64、amd64）
交叉编译产出静态/PIE 二进制。
