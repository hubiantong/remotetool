# 修复计划（基于 v0.1 架构评审）

本文档针对架构评审中发现的正确性、安全性与工程问题给出分批修复计划。原则：

- **先正确性/安全，后重构**：P0 不引入协议变更；P1 只做增量字段；P2 纯内部重构。
- 每个批次可独立合并、独立回滚、独立验证。
- 每项修复必须带一条可复现的验证方式，验证方式写入 PR 描述。

## 批次总览

| 批次 | 目标 | 包含项 | 是否改协议 |
|---|---|---|---|
| P0 安全与正确性 | 防越权、防爆破、消除数据竞争 | F1–F4 | 否 |
| P1 加固与可靠性 | 收敛攻击面、补超时、修平台 bug | F5–F10 | 少量增量字段 |
| P2 架构与工程 | 拆分职责、补测试/CI、清死代码 | F11–F14 | 否 |

建议拆成 4 个提交/PR：

1. `fix/session-isolation`（F1）
2. `fix/races-and-leaks`（F3 + F4）
3. `sec/pairing-hardening`（F2 + F5 + F6 + F7）
4. `chore/tooling`（F8/F10 杂项 + F11–F14）

P0 的两个 PR 应先合入。

---

## P0：安全与正确性

### F1 终端与文件会话按设备隔离

**问题**

- `term.open` 创建的会话进入全局表，`term.resize/close/list` 与数据流挂接都不校验来源设备。任何已配对设备只要用 `Session=1` 开一条流，就能接管别人正在使用的 shell。
- `filex` 的接收表只按 `XferID` 索引，同样没有来源校验，可跨设备注入数据或破坏在途传输。

**改动**

- `internal/term/service.go`
  - `AttachRPC(peer *session.Peer, rc *proto.RPCConn)` 中捕获 `owner := peer.ID`，在 `term.open` 时写入 `Session.owner`。
  - 新增 `getOwned(owner, id)`；`term.resize` / `term.close` / `term.list` 一律只操作属于调用者的会话；不属于自己的按“会话不存在”处理，避免泄露存在性。
  - `HandleStream` 校验 `sess.owner == peer.ID`，不匹配则直接关闭流。
- `internal/filex/service.go`
  - `prepareRecv` 增加 `peerID` 参数：`xfer.push` 传 `peer.ID`，`PullFile` 本地接收同样写入。
  - `HandleStream` 校验 `rs.peerID == peer.ID`。
  - `finalize`、`xfer.complete`、`xfer.cancel` 补同样的归属校验。
- 产品决策：默认隔离。如确需“多人共享同一 shell”，后续单独加 `term.open` 的 `shared` 开关，不在本项实现。

**验证**

- 双实例：A 建会话，B 用 A 的 session id 挂接/改尺寸/关闭 → 全部被拒且返回“不存在”。
- B 用 A 的 xferID 发数据流 → 被拒，A 的传输不受影响。
- A 自己断开重连挂接 → 正常。

---

### F2 配对码爆破防护

**问题**

- `pair.request` 对错误码不计数，邀请在 5 分钟有效期内可无限次尝试。6 位码（100 万空间）在 QUIC 上可被在线爆破。
- 未配对连接无并发上限，可被用来消耗 goroutine。

**改动**

- `internal/daemon/pair.go`
  - `invite` 增加 `attempts int`；错误码 `attempts++`，超过 5 次立即作废邀请。
  - 按远端设备 ID / IP 记录失败次数与 `nextAllowed`，指数退避（2s 起，上限 5 分钟），退避期内直接拒绝。
  - `HandleUnpairedConn` 前置容量为 8 的信号量，非阻塞获取失败即关闭连接。
  - 全局令牌桶限制未配对连接接入速率（建议 10/s，突发 20）。
  - 邀请校验、作废、配对成功共用同一把锁，防止并发确认。
- 失败路径统一返回“配对失败”，不区分“码错”与“邀请不存在”，避免探测。

**验证**

- 连续输错 6 次 → 邀请作废。
- 退避期内同设备重试 → 被拒。
- 20 个并发未配对连接 → 只有 8 个被处理，其余被及时关闭。
- 正确码流程、过期邀请、重复使用邀请的既有行为不变。

---

### F3 并发与资源泄漏

#### F3a `acceptHandshake` 数据竞争与忙等

- 位置：`internal/session/session.go` 中 `acceptHandshake`（约 420–461 行）。
- 问题：hello 处理器在 Serve goroutine 写入 `their`，主流程 25ms 轮询读取同一结构体，`-race` 必报。
- 改动：改为 `helloCh := make(chan hello, 1)`；处理器解析后写入；主流程 `select` 等待 `helloCh` / 连接关闭 / 10s 超时。删除轮询。
- 验证：`go test -race` 下双实例握手无告警；对端不发 hello 时 10s 返回错误。

#### F3b `Store.Get()` 浅拷贝被上层原地改写

- 位置：`internal/config/config.go` 的 `Get`；`internal/daemon/daemon.go` 的 `FwdRemove`（`out := rules[:0]`）。
- 问题：`Get` 按值返回但 `FwdRules` 共享底层数组；`FwdRemove` 绕过锁原地重写，破坏 `s.cfg` 一致性。
- 改动：`Get()` 深拷贝 `FwdRules`；新增 `Store.RemoveFwdRule(id)` / `Store.AddFwdRule(rule)`；daemon 侧改为调用新方法，禁止再用切片原地改写。
- 验证：并发 `Get` + 增删规则的 `-race` 测试；删除规则后 `Get` 结果与磁盘一致。

#### F3c hub 中继泄漏

- 位置：`internal/hub/hub.go` 的 `startRelay`。
- 问题：`pending` 存入后从不删除；`early` 无 TTL；两者都无上限。
- 改动：`startRelay` 用 `defer` 清理 `pending`（成功/超时/出错均清）；`early` 改为带 `created` 时间戳的结构，后台每分钟清理 TTL>1m 的条目；`pending` 数量超上限（1024）直接拒绝 `relay`。
- 验证：连续 200 次中继后 `pending`/`early` 长度回零（临时加 debug 计数或测试断言）。

#### F3d `filex.finalize` 重复关闭 channel

- 位置：`internal/filex/service.go` 的 `finalize`（`close(rs.ready)`）。
- 问题：重复收到 `xfer.complete` 会 panic（close of closed channel）；`finalize` 非幂等。
- 改动：`close(rs.ready)` 用 `sync.Once`；`finalize` 幂等，已完成的传输再次 complete 返回明确结果而不是 panic。
- 验证：重复 complete 的单元测试；断点续传完成两次不崩。

---

### F4 终端输出单一写入者

**问题**

- `readLoop` 直接写 `stream`，`HandleStream` 在挂接时又写回放 ring。两个写点会在重连瞬间交错，导致终端内容乱序/重复。

**改动**（`internal/term/service.go`）

- 为 `Session` 引入单一输出泵：
  - `readLoop` 只把输出追加到 `pending` 队列，并维护 scrollback ring，不再直接写流。
  - 每会话一个 writer goroutine：`stream` 非 nil 时，先按 ring 顺序回放，再按序排空 `pending`。
  - `HandleStream` 只做“切流 + 标记需要回放”，不写字节。
- 入站（stdin）与 resize 路径不变。

**验证**

- 反复“断开 → 重连”100 次，输出不重复、不乱序。
- 两客户端交替挂接不丢数据；`-race` 无告警。

---

## P1：加固与可靠性

### F5 端口转发收敛

- `fwd.listen` 强制 `ListenHost=127.0.0.1`；非回环地址必须由本机配置显式开启（新增 `AllowNonLoopbackFwd bool`，默认 false）。
- 每设备规则数上限（建议 32），超限拒绝。
- `Dial` 数据流头必须携带 `RuleID`；接收侧校验规则存在、属于调用方 peer、且为 mode L，再按规则中的目标拨号。去掉“任意已配对设备可让本机拨任意 host:port”的开放代理行为。
- 删除未使用的 `ruleListener.done`。
- 兼容性：老版本发送空 `RuleID` 会被新版本拒绝，因此该项需随新版本一起发布。

**验证**：伪造 `Dial`（无 RuleID / 借用他人规则）被拒；`-L` / `-R` 实测仍通；规则数超限被拒。

### F6 未配对连接与流量配额

- 未配对连接配额接入 F2 的信号量与令牌桶（daemon 层），Manager 不再无限起 goroutine。
- 按 peer 限制并发数据流（建议 64），到顶拒绝新的 `ChanFile` / `ChanFwd` / `ChanTerm` 流，避免单设备吃满 512 上限。
- hub：每设备注册/连接上限，`Resolve` 频率限制。

**验证**：单设备开 100 条转发流，第 65 条起被拒且不影响其他设备。

### F7 hub 服务端钉扎

- 配置新增可选 `hub_pubkey`（base16 fingerprint）；`hubclient` 用它构造 `TLSConfig(verify)`。
- 未配置时保持现状，但启动日志告警“未校验 hub 证书”。
- `Ensure` / `last_addr` 连接路径加单飞，避免并发 goroutine 重复 Dial hub。

**验证**：错误指纹 → 连接失败且报错明确；正确指纹正常；并发 `Resolve` 只建一条连接。

### F8 Web 层加固

- WebSocket 握手校验 `Origin`：空（CLI）或等于 `http://127.0.0.1:<port>` 才通过。
- token 只走 `X-RT-Token` 与 cookie；URL query token 仅用于首次页面加载，服务端种 cookie 后 302 去掉 `t` 参数；删除“读 cookie 但从不种 cookie”的死代码。
- `/api/xfer/push|pull`：先校验本地源文件存在/可读，失败立即 400；后台错误通过已有 SSE 事件回传；新增可取消的传输注册表与 `/api/xfer/cancel`。
- 补 `MaxHeaderBytes` 与请求体 `MaxBytesReader`。

**验证**：伪造 Origin 的 WS 被拒；无 token 的 API 返回 401；推送不存在的文件立即 400。

### F9 超时与流控

- `transport.Conn.Open` 接受 `ctx`（或内部 30s 超时），避免流配额耗尽时 `OpenStreamSync` 永久挂住。
- `dialHandshake` 的 `hello` 调用加 10s 超时。
- 中继内层 TLS：`streamNetConn` 的 deadline 是空实现，给 `newMuxConn` 加 15s 握手超时（超时即关流）。

**验证**：对端不响应 hello → 10s 报错而非挂死；配额耗尽时 `Open` 超时返回。

### F10 平台与工具链问题

- `joinRemote` 按远端 OS 选择分隔符（用路径风格判断或协议增加 `OS` 字段）；补“Windows → Linux 目录推送”用例。
- `rt cp` 的 `<dev>:<path>` 解析改为“冒号左侧必须匹配已配对设备名/ID 前缀”才视为远端，修复 Windows `C:\...` 被误判。
- `watchProgress` 按传输 ID 过滤事件，避免并发传输提前退出。
- `build.sh` 的 `-X main.version` 只对 `var` 生效：`rt` 与 `rtd` 的 `version` 改为 `var`，删除 rtd 硬编码 `0.1.0`。
- `.gitignore` 增加 `.zcode/`。

**验证**：Windows 上 `rt cp C:\big.zip dev:/tmp/` 正确；两个 `rt cp` 并行互不干扰；`rt version` 与 `git describe` 一致。

---

## P2：架构与工程

### F11 拆分 `session.Manager`

- `Manager`：连接表 + `Get/Connected/Disconnect` + feature/hook 注册。
- `dialer`：候选地址、`dialPeer`、`Connect` 单飞、hub 回退。
- `handshake`：`dialHandshake` / `acceptHandshake` / `register`。
- Web API 的巨型函数表按资源拆成 `peerAPI` / `fileAPI` / `fwdAPI` / `termAPI`，仍保持函数表形式，降低改动面。

**验证**：行为等价（P0/P1 测试全绿），无导出 API 变化。

### F12 去重与统一

- `transport.certBinding` 导出，`hubclient.certBindingFromTLS` 改为调用它，消除两份通道绑定实现。
- hub 的 JSON 分帧复用 `proto` 的 u32 帧工具。
- `identity.VerifyFunc` 对“有效期/自签 CA 约束”加显式检查或注释（钉扎场景下仅记录，不拒绝）。

### F13 崩溃与优雅退出

- 为 `term.readLoop`、`filex` 输出泵、`discover.browseLoop`、hub 各 goroutine 增加 recover 包装（当前只有 feature handler 有）。
- `daemon.Run` 退出时依次：停 web、关 listener、`term.Shutdown()`（kill 所有 PTY）、`filex` 取消在途传输、`fwd.StopAll()`，避免子 shell 变孤儿。

### F14 测试、CI 与清理

- 测试矩阵（优先覆盖 P0）：
  - `identity`：正确码/错码/重放/通道绑定不一致；
  - `session`：握手 channel、并发 Connect 单飞；
  - `term`：会话归属、重连回放顺序（可用假 PTY）；
  - `filex`：续传、校验失败清理、重复 complete；
  - `config`：并发 `Get/Update` 无 race。
- CI：`go vet ./...`、`go test -race ./...`、`./build.sh release`。
- 清理死代码：`_ = seen`、`pairing` 字段、`ruleListener.done`；`Progress.Direction` 语义明确化（`received/sent` 或注释）。
- 文档同步：README 与 `go.mod` 的 Go 版本对齐；`design.md` 修正 `term.attach`（实际不存在）与“TLS exporter”（实际用证书对哈希 + 通道绑定）两处描述。

---

## 执行顺序与依赖

```
P0: F3a → F1 → F3b / F3c / F3d → F4 → F2
P1: F6（依赖 F2 的信号量）→ F5 → F7 → F8 → F9 → F10
P2: F12 → F11 → F13 → F14
```

- F1 与 F4 都改 `term.Service`，应放在同一分支按顺序做，避免合并冲突。
- F5 的 `RuleID` 校验是唯一涉及对端语义的变化，必须随版本同步发布。
- F7 / F8 新增配置项均为可选、默认保持现状，不破坏既有安装。

---

## 风险与需要拍板的点

1. **会话隔离改变现有多设备行为**：如果“多人共享同一 shell”是产品特性，需要先确认；计划默认隔离，共享能力后置为显式开关。
2. `Store.Get()` 深拷贝带来一次切片拷贝：规则数量很小，性能可忽略。
3. F11 的 Manager 拆分是纯重构，必须由 F14 的测试兜底；不要与 P0/P1 混在同一 PR。
4. 本机当前 PATH 中没有 `go`，`-race` 验证需先安装工具链或在 CI 上完成。

---

## 完成标准（Definition of Done）

- [ ] F1：跨设备会话/传输访问全部被拒，同设备正常
- [ ] F2：错误码尝试受限、邀请可作废、未配对连接有配额
- [ ] F3：`go test -race ./...` 全绿；hub 长时间运行内存/条目数稳定；重复 complete 不 panic
- [ ] F4：重连 100 次输出顺序正确
- [ ] F5：无法被作为开放代理使用
- [ ] F6：单设备无法饿死全局流配额
- [ ] F7：可选 hub 指纹生效
- [ ] F8：WS 与 API 具备基础浏览器侧防护
- [ ] F9：关键路径无永久阻塞
- [ ] F10：Windows 路径、并发 cp、版本号三个 bug 修复
- [ ] F11–F13：重构后行为等价，退出无孤儿进程
- [ ] F14：CI 通过，文档与代码一致
