# hub 部署指南（自建中继/信令）

hub 是 RT 远程的可选自建组件：设备不在同一局域网时提供地址解析与加密中继。
它**只看到设备 ID 和密文**（中继流内部是设备证书的端到端 TLS），不会接触任何
明文。

## 1. 服务端（VPS）

上传 `dist/release/linux-amd64/hub`（在项目根 `./build.sh release` 产出）后：

```bash
# 生成一个长随机 token
TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '=+/')

# 直接运行（调试）
./hub --listen :27190 --token "$TOKEN"

# systemd 常驻
sudo tee /etc/systemd/system/rtd-hub.service >/dev/null <<EOF
[Unit]
Description=RT remotetool hub
After=network-online.target

[Service]
ExecStart=/opt/remotetool/hub --listen :27190 --token $TOKEN --dir /var/lib/rtd-hub
Restart=always
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now rtd-hub
```

记下 token。UDP 27190 需要在防火墙/安全组放行（QUIC）。

## 2. 设备端配置

任选其一：

- Web UI → 设置 → 「自建 hub」：填 `你的VPS:27190` 与 token，保存；
- CLI：`rt hub 你的VPS:27190 $TOKEN`；清除：`rt hub ""`。

设备会立即连上 hub；日志（`rtd.log`）出现 `hub connected` 即成功。

## 3. 工作方式

1. 设备注册后，对方可通过 hub 解析到你的当前地址（多数家用 NAT 下可直连）；
2. 直连失败时自动经 hub 中继：两端先与 hub 建立各自的加密信道，中继流内部
   再协商一层端到端 TLS（设备证书、钉扎校验不变），hub 纯转发密文；
3. hub 重启不影响已建立的直连，设备会自动重连 hub。

## 4. 常见问题

- **连不上 hub**：检查 UDP 27190 放行；确认 token 一致；`--v` 看 hub 日志。
- **hub 上线但仍是中继**：对称 NAT 或防火墙阻断了直连，中继即预期行为，
  速度取决于 VPS 带宽。
- **安全**：务必设置强 token；hub 不需要 root（监听 >1024 端口）。
