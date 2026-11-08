/* RT 远程 web UI */
"use strict";

// ------------------------------------------------------------- helpers ---

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

let TOKEN = localStorage.getItem("rt_token") || "";
const qs = new URLSearchParams(location.search);
if (qs.get("t")) { TOKEN = qs.get("t"); localStorage.setItem("rt_token", TOKEN); history.replaceState(null, "", location.pathname); }

async function api(method, path, body) {
  const opt = { method, headers: {} };
  // Without a stored token rely on the rt_token cookie the server seeded from
  // the ?t= handoff; sending an empty header would break that flow.
  if (TOKEN) opt.headers["X-RT-Token"] = TOKEN;
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opt);
  if (resp.status === 401) { showGate(); throw new Error("unauthorized"); }
  const text = await resp.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
  if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

function toast(msg, isErr) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.toggle("error", !!isErr);
  t.classList.remove("hidden");
  clearTimeout(t._tm);
  t._tm = setTimeout(() => t.classList.add("hidden"), 3200);
}

function fmtSize(n) {
  if (n == null) return "";
  const k = 1024;
  if (n >= k ** 3) return (n / k ** 3).toFixed(1) + " GB";
  if (n >= k ** 2) return (n / k ** 2).toFixed(1) + " MB";
  if (n >= k) return (n / k).toFixed(1) + " KB";
  return n + " B";
}
function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? "" : d.toLocaleString("zh-CN", { hour12: false });
}
function shortID(id) { return id ? id.slice(0, 8) : ""; }
function esc(s) { const d = document.createElement("div"); d.textContent = s ?? ""; return d.innerHTML; }

// ---------------------------------------------------------------- state ---

const state = {
  status: null,          // /api/status payload
  page: "devices",
  fs: {
    local: { path: "", entries: [] },
    remote: { path: "", entries: [] },
    selLocal: null, selRemote: null,
  },
  xfers: new Map(),      // id -> progress
  terms: [],             // {id, peer, session, term, ws, fit, tab, pane}
  activeTerm: null,
  termSeq: 0,
};

// ----------------------------------------------------------------- gate ---

function showGate() {
  $("#gate").classList.remove("hidden");
  $("#app").classList.add("hidden");
}
$("#gate-btn").addEventListener("click", () => tryGate());
$("#gate-token").addEventListener("keydown", (e) => { if (e.key === "Enter") tryGate(); });
async function tryGate(silent) {
  TOKEN = $("#gate-token").value.trim() || TOKEN;
  try {
    await api("GET", "/api/status");
    localStorage.setItem("rt_token", TOKEN);
    $("#gate").classList.add("hidden");
    $("#app").classList.remove("hidden");
    boot();
  } catch (e) {
    showGate();
    if (!silent) $("#gate-err").textContent = e.message === "unauthorized" ? "令牌错误" : e.message;
  }
}
// With no stored token the first /api/status call authenticates through the
// rt_token cookie seeded by the server's ?t= redirect; only a 401 falls back
// to the gate (kept free of an error line until the user retries).
if (TOKEN) tryGate(); else tryGate(true);

// ----------------------------------------------------------------- boot ---

let es = null;
function boot() {
  refreshStatus();
  connectEvents();
  setInterval(() => { if (state.page === "devices") refreshStatus(); }, 8000);
}

function connectEvents() {
  if (es) es.close();
  es = new EventSource("/api/events?t=" + encodeURIComponent(TOKEN));
  es.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch { return; }
    if (ev.type === "peer_up" || ev.type === "peer_down") {
      refreshStatus();
      if (ev.type === "peer_down") dropTermForPeer(ev.peer_id);
    } else if (ev.type === "xfer") {
      onXferEvent(ev.data);
    }
  };
  es.onerror = () => { /* EventSource auto-reconnects */ };
}

async function refreshStatus() {
  try {
    state.status = await api("GET", "/api/status");
    renderSide();
    renderDevices();
    renderTermPeers();
    renderFsPeers();
    renderFwdPeers();
  } catch (e) {
    if (e.message !== "unauthorized") toast(e.message, true);
  }
}

// ----------------------------------------------------------------- nav ---

$$(".nav-item").forEach((el) => el.addEventListener("click", () => {
  $$(".nav-item").forEach((x) => x.classList.remove("active"));
  el.classList.add("active");
  $$(".page").forEach((p) => p.classList.remove("active"));
  $("#page-" + el.dataset.page).classList.add("active");
  state.page = el.dataset.page;
  if (state.page === "devices") refreshStatus();
  if (state.page === "fwd") refreshFwd();
  if (state.page === "files") { renderFsPeers(); loadDir("local"); loadDir("remote"); }
  if (state.page === "term") $$(".term-pane.active").forEach((p) => p && fitTerm(p._ts));
}));

function renderSide() {
  const s = state.status; if (!s) return;
  $("#side-name").textContent = s.name;
  $("#side-name").title = s.name;
  $("#side-id").textContent = s.id;
  $("#set-id").textContent = s.id;
  $("#set-name").value = s.name;
  if (document.activeElement !== $("#set-hub")) $("#set-hub").value = s.hub_addr || "";
}

// -------------------------------------------------------------- devices ---

function renderDevices() {
  const s = state.status; if (!s) return;

  // invite
  const box = $("#invite-box");
  if (s.invite) {
    const left = Math.max(0, Math.round((s.invite.expires - Date.now()) / 1000));
    box.innerHTML = `<div class="invite-code">${esc(s.invite.code)}</div>
      <div class="invite-sub">${left > 0 ? left + " 秒后过期" : "已过期，请重新生成"}</div>
      <button class="btn small" id="invite-re" style="margin-top:8px">重新生成</button>`;
    $("#invite-re").addEventListener("click", makeInvite);
  } else {
    box.innerHTML = `<button id="invite-btn" class="btn primary">生成配对码</button>`;
    $("#invite-btn").addEventListener("click", makeInvite);
  }

  // peers
  const connected = new Map((s.connected || []).map((c) => [c.id, c]));
  const list = $("#peer-list");
  list.innerHTML = "";
  const peers = s.peers || [];
  if (!peers.length) list.innerHTML = `<div class="empty">还没有配对设备，用上面的配对码完成首次配对。</div>`;
  for (const p of peers) {
    const on = connected.has(p.id);
    const row = document.createElement("div");
    row.className = "peer-row" + (on ? " online" : "");
    row.innerHTML = `
      <span class="dot"></span>
      <div class="p-name">${esc(p.name)}</div>
      <div class="p-meta mono">${shortID(p.id)}${p.last_addr ? " · " + esc(p.last_addr) : ""}${p.last_seen ? " · " + fmtTime(p.last_seen) : ""}</div>
      <div class="p-actions"></div>`;
    const act = row.querySelector(".p-actions");
    const btn = document.createElement("button");
    btn.className = "btn small" + (on ? "" : " primary");
    btn.textContent = on ? "断开" : "连接";
    btn.addEventListener("click", async () => {
      try {
        await api("POST", on ? "/api/peers/disconnect" : "/api/peers/connect", { id: p.id });
        toast(on ? "已断开" : "已连接");
        refreshStatus();
      } catch (e) { toast(e.message, true); }
    });
    act.appendChild(btn);
    const btnT = document.createElement("button");
    btnT.className = "btn small";
    btnT.textContent = "终端";
    btnT.addEventListener("click", () => { openTerm(p.id); switchPage("term"); });
    act.appendChild(btnT);
    const btnF = document.createElement("button");
    btnF.className = "btn small";
    btnF.textContent = "文件";
    btnF.addEventListener("click", async () => { $("#fs-peer").value = p.id; switchPage("files"); });
    act.appendChild(btnF);
    const btnX = document.createElement("button");
    btnX.className = "btn small danger";
    btnX.textContent = "删除";
    btnX.addEventListener("click", async () => {
      if (!confirm(`删除配对 ${p.name} (${shortID(p.id)})？`)) return;
      try { await api("POST", "/api/peers/remove", { id: p.id }); refreshStatus(); } catch (e) { toast(e.message, true); }
    });
    act.appendChild(btnX);
    list.appendChild(row);
  }

  // discovered
  const dl = $("#discover-list");
  dl.innerHTML = "";
  if (!(s.discovered || []).length) {
    dl.innerHTML = `<div class="empty">同一局域网内未发现其他设备（双方都需运行 rtd）。</div>`;
  }
  for (const d of s.discovered || []) {
    const row = document.createElement("div");
    row.className = "peer-row";
    row.innerHTML = `
      <span class="dot" style="background:var(--acc)"></span>
      <div class="p-name">${esc(d.name || "未命名")}</div>
      <div class="p-meta mono">${shortID(d.id)} · ${esc(d.addr)}</div>
      <div class="p-actions"><button class="btn small primary">填入配对</button></div>`;
    row.querySelector("button").addEventListener("click", () => {
      $("#pair-addr").value = d.addr;
      $("#pair-code").focus();
      switchPage("devices");
    });
    dl.appendChild(row);
  }
}

async function makeInvite() {
  try {
    await api("POST", "/api/pair/invite", {});
    refreshStatus();
  } catch (e) { toast(e.message, true); }
}

$("#pair-btn").addEventListener("click", async () => {
  const addr = $("#pair-addr").value.trim();
  const code = $("#pair-code").value.trim();
  const msg = $("#pair-msg");
  msg.textContent = "配对中…";
  try {
    const res = await api("POST", "/api/pair/connect", { addr, code });
    msg.textContent = "";
    toast("已配对 " + (res.peer?.name || ""));
    $("#pair-addr").value = ""; $("#pair-code").value = "";
    refreshStatus();
  } catch (e) { msg.textContent = ""; toast(e.message, true); }
});

function switchPage(name) {
  $$(".nav-item").forEach((x) => x.classList.toggle("active", x.dataset.page === name));
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === "page-" + name));
  state.page = name;
  if (name === "fwd") refreshFwd();
  if (name === "files") { loadDir("local"); loadDir("remote"); }
}

// ---------------------------------------------------------------- term ---

function renderTermPeers() {
  const sel = $("#term-peer");
  const cur = sel.value;
  sel.innerHTML = (state.status?.peers || []).map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("");
  if (cur && [...sel.options].some((o) => o.value === cur)) sel.value = cur;
}

$("#term-open").addEventListener("click", () => openTerm($("#term-peer").value));

async function openTerm(peerID) {
  if (!peerID) { toast("请先选择设备", true); return; }
  const id = "t" + (++state.termSeq);
  const pane = document.createElement("div");
  pane.className = "term-pane";
  const host = document.createElement("div");
  pane.appendChild(host);
  $("#term-panes").appendChild(pane);
  const term = new Terminal({
    fontFamily: 'Consolas, "Cascadia Mono", monospace',
    fontSize: 13.5,
    cursorBlink: true,
    theme: { background: "#0b0e14", foreground: "#dfe6f3", cursor: "#4f7cff", selectionBackground: "rgba(79,124,255,.35)" },
    scrollback: 5000,
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(host);

  const cols = fit.proposeDimensions()?.cols || 80;
  const rows = fit.proposeDimensions()?.rows || 24;
  let ws;
  try {
    ws = new WebSocket(`ws://${location.host}/api/term/ws?peer=${encodeURIComponent(peerID)}&cols=${cols}&rows=${rows}&t=${encodeURIComponent(TOKEN)}`);
  } catch (e) { toast(e.message, true); pane.remove(); return; }
  ws.binaryType = "arraybuffer";
  const ts = { id, peer: peerID, session: 0, term, ws, fit, tab: null, pane, name: peerName(peerID) };
  pane._ts = ts;
  state.terms.push(ts);

  ws.onopen = () => { term.focus(); try { fit.fit(); } catch {} };
  ws.onmessage = (m) => {
    if (typeof m.data === "string") {
      // session id announcement (JSON)
      try { const j = JSON.parse(m.data); if (j.session) ts.session = j.session; } catch {}
      return;
    }
    term.write(new Uint8Array(m.data));
  };
  ws.onclose = () => {
    term.write("\r\n\x1b[90m— 会话已断开 —\x1b[0m\r\n");
    ts.dead = true;
  };
  term.onData((d) => { if (ws.readyState === 1) ws.send(new TextEncoder().encode(d)); });

  addTermTab(ts);
  activateTerm(ts);
}

function peerName(id) {
  const p = (state.status?.peers || []).find((x) => x.id === id);
  return p ? p.name : shortID(id);
}

function addTermTab(ts) {
  const tab = document.createElement("div");
  tab.className = "term-tab";
  tab.innerHTML = `<span>${esc(ts.name)}</span><span class="x">✕</span>`;
  tab.addEventListener("click", (e) => {
    if (e.target.classList.contains("x")) return;
    activateTerm(ts);
  });
  tab.querySelector(".x").addEventListener("click", () => closeTerm(ts));
  ts.tab = tab;
  $("#term-tabs").appendChild(tab);
}

function activateTerm(ts) {
  if (ts.dead) return;
  state.terms.forEach((x) => { x.pane.classList.remove("active"); x.tab.classList.remove("active"); });
  ts.pane.classList.add("active");
  ts.tab.classList.add("active");
  state.activeTerm = ts;
  requestAnimationFrame(() => { try { ts.fit.fit(); ts.term.focus(); } catch {} });
}

function closeTerm(ts) {
  try { ts.ws.close(); } catch {}
  ts.term.dispose();
  ts.tab.remove();
  ts.pane.remove();
  state.terms = state.terms.filter((x) => x !== ts);
  if (state.activeTerm === ts) {
    state.activeTerm = null;
    if (state.terms.length) activateTerm(state.terms[0]);
  }
}

function dropTermForPeer(peerID) {
  state.terms.filter((t) => t.peer === peerID).forEach((t) => {
    t.dead = true;
  });
}

function fitTerm(ts) { try { ts.fit.fit(); } catch {} }

window.addEventListener("resize", () => { if (state.activeTerm) fitTerm(state.activeTerm); });

// ---------------------------------------------------------------- files ---

function renderFsPeers() {
  const sel = $("#fs-peer");
  const cur = sel.value;
  sel.innerHTML = (state.status?.peers || []).map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("");
  if (cur && [...sel.options].some((o) => o.value === cur)) sel.value = cur;
}

async function loadDir(side) {
  const st = state.fs[side];
  const peer = side === "remote" ? $("#fs-peer").value : "";
  try {
    const res = await api("GET", `/api/fs/list?peer=${encodeURIComponent(peer)}&path=${encodeURIComponent(st.path)}`);
    st.path = res.path || "";
    st.entries = res.entries || [];
    renderDir(side);
  } catch (e) {
    if (!["unauthorized"].includes(e.message)) {
      $(side === "local" ? "#path-local" : "#path-remote").textContent = "错误: " + e.message;
    }
  }
}

function renderDir(side) {
  const st = state.fs[side];
  const pathEl = $(side === "local" ? "#path-local" : "#path-remote");
  const listEl = $(side === "local" ? "#list-local" : "#list-remote");
  pathEl.textContent = st.path || (side === "local" ? "本机" : "此电脑");
  listEl.innerHTML = "";
  for (const en of st.entries) {
    const row = document.createElement("div");
    row.className = "f-row " + (en.dir ? "dir" : "file");
    const selected = (side === "local" ? state.fs.selLocal : state.fs.selRemote) === en.name;
    if (selected) row.style.background = "rgba(79,124,255,.15)";
    row.innerHTML = `<span class="f-ic">${en.dir ? "▸" : "▪"}</span>
      <span class="f-name" title="${esc(en.name)}">${esc(en.name)}</span>
      <span class="f-size">${en.dir ? "" : fmtSize(en.size)}</span>
      <span class="f-act"></span>`;
    row.querySelector(".f-name").addEventListener("click", () => {
      if (en.dir) {
        const base = st.path || "";
        st.path = base ? base.replace(/[\\/]+$/, "") + "/" + en.name : en.name;
        loadDir(side);
      } else {
        if (side === "local") state.fs.selLocal = en.name; else state.fs.selRemote = en.name;
        renderDir(side);
      }
    });
    const act = row.querySelector(".f-act");
    const sideName = side === "local" ? "本机" : "远端";
    if (!en.dir) {
      const send = document.createElement("button");
      send.className = "icon-btn";
      send.title = side === "local" ? "发送到远端" : "下载到本机";
      send.textContent = side === "local" ? "⇒" : "⇐";
      send.addEventListener("click", () => transferFile(side, en.name));
      act.appendChild(send);
    }
    const ren = document.createElement("button");
    ren.className = "icon-btn"; ren.title = "重命名"; ren.textContent = "✎";
    ren.addEventListener("click", async () => {
      const nn = prompt("重命名", en.name);
      if (!nn || nn === en.name) return;
      const peer = side === "remote" ? $("#fs-peer").value : "";
      const base = (st.path || "").replace(/[\\/]+$/, "");
      try {
        await api("POST", "/api/fs/rename", { peer, from: base + "/" + en.name, to: base + "/" + nn });
        loadDir(side);
      } catch (e) { toast(e.message, true); }
    });
    const del = document.createElement("button");
    del.className = "icon-btn"; del.title = "删除"; del.textContent = "✕";
    del.addEventListener("click", async () => {
      if (!confirm(`删除 ${sideName} ${en.name}${en.dir ? "（含内容）" : ""}？`)) return;
      const peer = side === "remote" ? $("#fs-peer").value : "";
      const base = (st.path || "").replace(/[\\/]+$/, "");
      try {
        await api("POST", "/api/fs/remove", { peer, path: base + "/" + en.name, recursive: !!en.dir });
        loadDir(side);
      } catch (e) { toast(e.message, true); }
    });
    act.appendChild(ren); act.appendChild(del);
    listEl.appendChild(row);
  }
  if (!st.entries.length) listEl.innerHTML = `<div class="empty" style="padding:12px">空目录</div>`;
}

$$(".pane").forEach((pane) => {
  const side = pane.id === "pane-local" ? "local" : "remote";
  pane.querySelectorAll(".pane-actions .icon-btn").forEach((b) => {
    b.addEventListener("click", async () => {
      const act = b.dataset.act;
      const st = state.fs[side];
      if (act === "up") {
        const norm = st.path.replace(/[\\/]+$/, "");
        const i = Math.max(norm.lastIndexOf("/"), norm.lastIndexOf("\\"));
        st.path = i > 0 ? norm.slice(0, i) : (i === 0 ? norm.slice(0, 1) : "");
        loadDir(side);
      } else if (act === "refresh") {
        loadDir(side);
      } else if (act === "mkdir") {
        const n = prompt("文件夹名");
        if (!n) return;
        const peer = side === "remote" ? $("#fs-peer").value : "";
        const base = (st.path || "").replace(/[\\/]+$/, "");
        try {
          await api("POST", "/api/fs/mkdir", { peer, path: base + "/" + n });
          loadDir(side);
        } catch (e) { toast(e.message, true); }
      }
    });
  });
  // drag & drop upload (local -> remote)
  if (side === "local") return;
  pane.addEventListener("dragover", (e) => { e.preventDefault(); pane.classList.add("dropping"); });
  pane.addEventListener("dragleave", () => pane.classList.remove("dropping"));
  pane.addEventListener("drop", async (e) => {
    e.preventDefault(); pane.classList.remove("dropping");
    for (const f of e.dataTransfer.files) {
      await pushUpload(f);
    }
  });
});

async function pushUpload(file) {
  // Save the picked file under a temp name via the browser? The daemon has
  // no browser access, so uploads go through a two-step: local side chooses
  // the file again from disk by path. Instead we use File API -> not
  // supported across daemon; fallback: instruct manual path transfer.
  const peer = $("#fs-peer").value;
  if (!peer) { toast("请先选择远端设备", true); return; }
  const remotePath = joinPath(state.fs.remote.path, file.name);
  const localGuess = file.name;
  try {
    await api("POST", "/api/xfer/push", { peer, local: localGuess, remote: remotePath, conflict: "rename" });
    toast("已提交传输: " + file.name + "（需文件位于 rtd 工作目录）");
  } catch (e) { toast(e.message, true); }
}

$("#fs-peer").addEventListener("change", () => { state.fs.remote.path = ""; loadDir("remote"); });

function transferFile(side, name) {
  const peer = $("#fs-peer").value;
  if (!peer) { toast("请先选择远端设备", true); return; }
  const baseR = (state.fs.remote.path || "").replace(/[\\/]+$/, "");
  const baseL = (state.fs.local.path || "").replace(/[\\/]+$/, "");
  const remotePath = baseR ? baseR + "/" + name : name;
  const localPath = baseL ? baseL + "/" + name : name;
  (async () => {
    try {
      if (side === "local") {
        await api("POST", "/api/xfer/push", { peer, local: localPath, remote: remotePath, conflict: "rename" });
      } else {
        await api("POST", "/api/xfer/pull", { peer, remote: remotePath, local: localPath, conflict: "rename" });
      }
      toast("已开始传输: " + name);
    } catch (e) { toast(e.message, true); }
  })();
}

function joinPath(base, name) {
  const b = (base || "").replace(/[\\/]+$/, "");
  return b ? b + "/" + name : name;
}

// transfers ----------------------------------------------------------

function onXferEvent(p) {
  if (!p || !p.id) return;
  state.xfers.set(p.id, p);
  renderXfers();
}

function renderXfers() {
  const list = $("#xfer-list");
  list.innerHTML = "";
  for (const [id, p] of [...state.xfers.entries()].slice(-30)) {
    const row = document.createElement("div");
    row.className = "xfer-row";
    const pct = p.size > 0 ? Math.min(100, Math.round((100 * p.done) / p.size)) : 0;
    row.innerHTML = `
      <div class="x-top">
        <span class="x-name">${p.direction === "push" ? "↑" : "↓"} ${esc(p.name || p.local_path)}</span>
        <span class="x-state ${p.state}">${p.state === "running" ? fmtSize(p.done) + (p.size ? " / " + fmtSize(p.size) : "") : p.state + (p.err ? ": " + esc(p.err) : "")}</span>
      </div>
      <div class="xbar"><div style="width:${p.state === "done" ? 100 : pct}%"></div></div>`;
    list.appendChild(row);
  }
  const running = [...state.xfers.values()].filter((x) => x.state === "running").length;
  $("#fs-progress-summary").textContent = running ? `${running} 个传输中` : "";
}

$("#xfer-clear").addEventListener("click", () => { state.xfers.clear(); renderXfers(); });

// ----------------------------------------------------------------- fwd ---

function renderFwdPeers() {
  const sel = $("#fwd-peer");
  const cur = sel.value;
  sel.innerHTML = (state.status?.peers || []).map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("");
  if (cur && [...sel.options].some((o) => o.value === cur)) sel.value = cur;
}

async function refreshFwd() {
  renderFwdPeers();
  try {
    const res = await api("GET", "/api/fwd");
    const list = $("#fwd-list");
    list.innerHTML = "";
    const rules = res.rules || [];
    if (!rules.length) { list.innerHTML = `<div class="empty">暂无规则</div>`; return; }
    for (const r of rules) {
      const active = (res.active || {})[r.id];
      const peer = (state.status?.peers || []).find((p) => p.id === r.peer_id);
      const row = document.createElement("div");
      row.className = "peer-row" + (active ? " online" : "");
      row.innerHTML = `
        <span class="dot"></span>
        <div class="p-name">-${r.mode}</div>
        <div class="p-meta mono">${esc(peer?.name || shortID(r.peer_id))}: ${esc(r.listen_host || "127.0.0.1")}:${r.listen_port} → ${esc(r.target_host)}:${r.target_port}</div>
        <div class="p-actions"><span class="dim" style="font-size:12px">${active ? "生效中" : "等待连接"}</span></div>`;
      const act = row.querySelector(".p-actions");
      const del = document.createElement("button");
      del.className = "btn small danger"; del.textContent = "删除";
      del.addEventListener("click", async () => {
        try { await api("POST", "/api/fwd/remove", { id: r.id }); refreshFwd(); } catch (e) { toast(e.message, true); }
      });
      act.appendChild(del);
      list.appendChild(row);
    }
  } catch (e) { toast(e.message, true); }
}

$("#fwd-mode").addEventListener("change", () => {
  const m = $("#fwd-mode").value;
  $("#fwd-hint").textContent = m === "L"
    ? "-L 例：本机 13389 → 远端 localhost:3389，访问本机 13389 即访问远端远程桌面。"
    : "-R 例：远端 9090 → 本机 localhost:8080，让远端设备访问本机服务。";
});

$("#fwd-add").addEventListener("click", async () => {
  const body = {
    peer_id: $("#fwd-peer").value,
    mode: $("#fwd-mode").value,
    listen_host: "127.0.0.1",
    listen_port: parseInt($("#fwd-listen-port").value, 10),
    target_host: $("#fwd-target-host").value.trim() || "localhost",
    target_port: parseInt($("#fwd-target-port").value, 10),
  };
  if (!body.peer_id) { toast("请先选择设备", true); return; }
  if (!body.listen_port || !body.target_port) { toast("端口无效", true); return; }
  try { await api("POST", "/api/fwd/add", body); toast("已添加"); refreshFwd(); } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------- settings ---

$("#set-save").addEventListener("click", async () => {
  try {
    await api("POST", "/api/name", { name: $("#set-name").value.trim() });
    toast("已保存");
    refreshStatus();
  } catch (e) { toast(e.message, true); }
});

$("#set-hub-save").addEventListener("click", async () => {
  const msg = $("#set-hub-msg");
  msg.textContent = "连接 hub 中…";
  try {
    await api("POST", "/api/hub", { addr: $("#set-hub").value.trim(), token: $("#set-hub-token").value.trim() });
    msg.textContent = "";
    toast("hub 已更新");
    refreshStatus();
  } catch (e) { msg.textContent = ""; toast(e.message, true); }
});
