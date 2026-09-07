/* recon-pipeline SPA -- panels a-e (section 9.2), URL-shareable global filters (section 9.2-b),
   sortable tables + badges + collapsible JSON inspector (section 9.4). Zero-build
   vanilla JS; the API contract (section 9.1) is the stable surface. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const TOKEN_KEY = "recon_dashboard_token";

let TOKEN = localStorage.getItem(TOKEN_KEY) || "";
let CURRENT = { target: "example.com", assets: [], sort: { key: null, dir: 1 } };

async function api(method, path, body) {
  const headers = {};
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  if (res.status === 401) { toast("invalid token", true); throw new Error("401"); }
  if (res.status === 503) { toast("DASHBOARD_TOKEN not configured on backend", true); throw new Error("503"); }
  const doc = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(doc.detail || res.statusText);
  return doc;
}

function toast(msg, err) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast" + (err ? " err" : "");
  setTimeout(() => el.classList.add("hidden"), 3500);
  el.classList.remove("hidden");
}

function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

/* ---------------- panel switching ---------------- */
$("#tabs").addEventListener("click", (ev) => {
  const btn = ev.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === btn));
  document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
  $("#panel-" + btn.dataset.panel).classList.remove("hidden");
  loadPanel(btn.dataset.panel);
});

/* ---------------- a) TOOLS ---------------- */
async function loadTools() {
  const doc = await api("GET", "/api/tools");
  const tbody = $("#tools-table tbody");
  tbody.innerHTML = "";
  for (const t of doc.tools) {
    const params = Object.entries(t.params || {}).map(([k, v]) => `${k}=${esc(v)}`).join(" ") || "--";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(t.name)}</td><td class="dim">${esc(t.branch || "")}</td>` +
      `<td class="dim">${esc(t.image_ref || "")}</td>` +
      `<td><button class="${t.enabled ? "" : "danger"}" data-toggle="${esc(t.name)}">${t.enabled ? "ENABLED" : "DISABLED"}</button></td>` +
      `<td>${params}</td>`;
    tbody.appendChild(tr);
  }
  tbody.onclick = async (ev) => {
    const btn = ev.target.closest("[data-toggle]");
    if (!btn) return;
    const name = btn.dataset.toggle;
    const enable = btn.textContent === "DISABLED";
    await api("PUT", "/api/tools/" + name, enable ? { enabled: enable } : { enabled: enable });
    toast(`${name} ${enable ? "enabled" : "disabled"} (schema-validated)`);
    loadTools();
  };
}

async function loadWordlists() {
  const doc = await api("GET", "/api/wordlists");
  const root = $("#wordlists");
  root.innerHTML = "";
  for (const [task, spec] of Object.entries(doc.tasks || {})) {
    const selected = new Set(spec.selection || spec.default_selection || []);
    const box = document.createElement("div");
    box.className = "table-wrap";
    box.style.marginBottom = "14px";
    const rows = [];
    for (const group of ["fast", "expansion", "sources", "default_selection"]) {
      for (const key of spec[group] || []) {
        rows.push(`<tr><td><input type="checkbox" data-key="${esc(key)}" ${selected.has(key) ? "checked" : ""}></td>` +
          `<td>${esc(key)}</td><td class="dim">${esc(group)}</td></tr>`);
      }
    }
    box.innerHTML = `<table><thead><tr><th>SEL</th><th>${esc(task)} -- registry key</th><th>GROUP</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
    const bar = document.createElement("div");
    bar.className = "row";
    bar.innerHTML = `<button data-all="${esc(task)}">SELECT-ALL (all groups)</button><button data-save="${esc(task)}">SAVE SELECTION</button>`;
    box.before(bar);
    box.after(document.createElement("div"));
    root.appendChild(bar);
    root.appendChild(box);
  }
  root.onclick = async (ev) => {
    const all = ev.target.closest("[data-all]");
    const save = ev.target.closest("[data-save]");
    if (all) {
      const task = all.dataset.all;
      const spec = (await api("GET", "/api/wordlists")).tasks[task];
      const keys = [...new Set([].concat(spec.fast || [], spec.expansion || [], spec.sources || [], spec.default_selection || []))];
      const tables = [...root.querySelectorAll("table")];
      const box = tables.find((t) => t.querySelector(`[data-save="${task}"]`)) || null;
      root.querySelectorAll("input[type=checkbox][data-key]").forEach((cb) => { cb.checked = true; });
      toast("select-all ticked -- remember SAVE SELECTION");
    }
    if (save) {
      const task = save.dataset.save;
      const boxes = [...root.querySelectorAll("input[type=checkbox][data-key]:checked")].map((cb) => cb.dataset.key);
      await api("PUT", "/api/wordlists", { [task]: boxes });
      toast(`${task} selection saved (${boxes.length} keys)`);
    }
  };
}

/* ---------------- b) RESULTS ---------------- */
const FILTER_IDS = ["q", "source", "tag", "alive", "run", "scope"];

function readFilterUI() {
  const f = {};
  for (const id of FILTER_IDS) { const v = $("#f-" + id).value; if (v) f[id] = v; }
  return f;
}
function writeFilterUI(f) {
  for (const id of FILTER_IDS) $("#f-" + id).value = f[id] || "";
}
function shareFilters(f) { // URL-shareable state (section 9.2-b)
  const qs = new URLSearchParams(f).toString();
  const url = location.origin + location.pathname + "?panel=results" + (qs ? "&" + qs : "");
  history.pushState({}, "", url);
  return url;
}
function restoreFiltersFromURL() {
  const params = new URLSearchParams(location.search);
  const f = {};
  for (const id of FILTER_IDS) if (params.get(id)) f[id] = params.get(id);
  writeFilterUI(f);
  return params.get("panel") || "tools";
}

async function loadResults() {
  const f = readFilterUI();
  const qs = new URLSearchParams(f).toString();
  const doc = await api("GET", "/api/results/" + encodeURIComponent(CURRENT.target) + (qs ? "?" + qs : ""));
  CURRENT.assets = doc.assets;
  renderAssets();
  const cov = await api("GET", "/api/results/" + encodeURIComponent(CURRENT.target) + "/coverage");
  renderCoverage(cov);
  const diff = await api("GET", "/api/results/" + encodeURIComponent(CURRENT.target) + "/diff");
  renderDiff(diff);
}

function renderAssets() {
  const { key, dir } = CURRENT.sort;
  let rows = CURRENT.assets;
  if (key) {
    rows = [...rows].sort((a, b) => {
      const va = JSON.stringify(a[key] ?? ""), vb = JSON.stringify(b[key] ?? "");
      return dir * va.localeCompare(vb);
    });
  }
  const tbody = $("#assets-table tbody");
  tbody.innerHTML = rows.map((r) => `<tr>` +
    `<td>${esc(r.host)} ${r.is_new ? '<span class="badge new">NEW</span>' : ""}</td>` +
    `<td class="dim">${esc((r.ips || [r.ip]).filter(Boolean).join(", "))}</td>` +
    `<td><span class="badge ${r.alive ? "alive" : "dead"}">${r.alive ? "ALIVE" : "DEAD"}</span></td>` +
    `<td class="dim">${esc((r.sources || []).join(", "))}</td>` +
    `<td>${(r.tags || []).map((t) => `<span class="badge">${esc(t)}</span>`).join(" ")}</td>` +
    `<td><button data-json='${esc(JSON.stringify(r))}'>{ }</button></td></tr>`).join("") ||
    `<tr><td colspan="6" class="dim">no assets (run the pipeline first)</td></tr>`;
  tbody.onclick = (ev) => {
    const btn = ev.target.closest("[data-json]");
    if (!btn) return;
    const pre = $("#diff-view");
    pre.textContent = JSON.stringify(JSON.parse(btn.dataset.json), null, 2);
    pre.classList.remove("collapsed");
    pre.scrollIntoView({ behavior: "smooth" });
  };
}

function renderCoverage(cov) {
  const tbody = $("#coverage-table tbody");
  tbody.innerHTML = Object.entries(cov.contribution).map(([s, n]) =>
    `<tr><td>${esc(s)}</td><td>${n}</td><td>${cov.unique_assets[s] || 0}</td><td>${cov.uniqueness_pct[s] ?? 0}%</td></tr>`).join("");
  $("#overlap").textContent = "overlap (assets found by N sources): " + JSON.stringify(cov.overlap_by_n_sources);
}

function renderDiff(diff) {
  const badges = $("#diff-badges");
  if (!diff.exists) { badges.innerHTML = '<span class="badge">no diff yet (first run)</span>'; $("#diff-view").textContent = ""; return; }
  const n = (cls) => (diff.added[cls] || []).length;
  const r = (cls) => (diff.removed[cls] || []).length;
  badges.innerHTML =
    `<span class="badge new">+hosts ${n("hosts")}</span><span class="badge new">+ports ${n("ports")}</span>` +
    `<span class="badge dead">-hosts ${r("hosts")}</span><span class="badge dead">-ports ${r("ports")}</span>`;
  const pre = $("#diff-view");
  pre.textContent = JSON.stringify(diff, null, 2);
  pre.onclick = () => pre.classList.toggle("collapsed");
}

/* ---------------- b2) REPORTS ---------------- */
async function loadReports() {
  const target = ($("#rep-target").value.trim() || CURRENT.target);
  $("#rep-target").value = target;
  const badge = $("#rep-status");
  const tbody = $("#reports-table tbody");
  tbody.innerHTML = "";
  const doc = await api("GET", "/api/report/" + encodeURIComponent(target));
  if (!doc.exists) {
    badge.textContent = "no bundle"; badge.className = "badge dead";
    tbody.innerHTML = '<tr><td colspan="4" class="dim">no report bundle yet -- press GENERATE NOW</td></tr>';
    $("#rep-manifest").textContent = "";
    return;
  }
  badge.textContent = doc.verified ? "VERIFIED" : "TAMPER/DRIFT";
  badge.className = "badge " + (doc.verified ? "ok" : "alert");
  const m = doc.manifest || {};
  const files = m.files || {};
  tbody.innerHTML = Object.entries(files).map(([name, f]) =>
    `<tr><td>${esc(name)}</td><td class="dim">${esc(f.path)}</td><td class="dim">${esc(String(f.sha256 || "").slice(0, 16))}...</td>` +
    `<td><a class="badge ok" href="/static-file/${esc(target)}/${esc(f.path)}" target="_blank">OPEN</a></td></tr>`).join("") ||
    '<tr><td colspan="4" class="dim">manifest has no files</td></tr>';
  const pre = $("#rep-manifest");
  pre.textContent = JSON.stringify(m, null, 2);
  pre.onclick = () => pre.classList.toggle("collapsed");
}

/* ---------------- c) RUN CONTROL ---------------- */
async function loadRun() {
  const st = await api("GET", "/api/run/status/" + encodeURIComponent(CURRENT.target));
  const badge = $("#run-status");
  badge.textContent = st.exists ? `${CURRENT.target}: ${st.run_status || "?"}` : `${CURRENT.target}: no state`;
  badge.className = "badge " + (st.run_status === "completed" ? "ok" : st.run_status === "failed" || st.run_status === "anomaly" ? "alert" : "");
  $("#run-modules").textContent = st.exists ? Object.entries(st.modules || {}).map(([m, s]) => `${m}=${s.status}`).join("  ") : "";
  const sched = await api("GET", "/api/scheduler");
  $("#sched-interval").value = sched.interval_minutes;
  $("#sched-enabled").checked = !!sched.enabled;
  $("#sched-last").textContent = "last_run: " + (sched.last_run || "never");
}

function startLogStream() {
  clearInterval(window.__logTimer);
  let offset = 0;
  const pre = $("#live-log");
  pre.textContent = "";
  window.__logTimer = setInterval(async () => {
    if ($("#panel-run").classList.contains("hidden")) return;
    try {
      const doc = await api("GET", `/api/run/log/${encodeURIComponent(CURRENT.target)}?offset=${offset}`);
      if (!doc.exists) return;
      if (offset === 0 && doc.total > 200) offset = Math.max(0, doc.total - 200);
      if (doc.lines.length) {
        pre.textContent += doc.lines.map((l) => l + "\n").join("");
        pre.scrollTop = pre.scrollHeight;
      }
      offset = doc.next_offset;
    } catch (_e) { /* keep polling */ }
  }, 2000);
}

function startJournalStream() {
  clearInterval(window.__journalTimer);
  let joffset = 0;
  const pre = $("#agent-journal");
  pre.textContent = "";
  window.__journalTimer = setInterval(async () => {
    if ($("#panel-run").classList.contains("hidden")) return;
    try {
      const doc = await api("GET", `/api/run/agent-journal/${encodeURIComponent(CURRENT.target)}?offset=${joffset}`);
      if (!doc.exists) return;
      if (doc.rows.length) {
        pre.textContent += doc.rows.map((l) => { try { const r = JSON.parse(l); return `[${r.ts}] ${r.event}: ${JSON.stringify(r)}\n`; } catch (_e) { return l + "\n"; } }).join("");
        pre.scrollTop = pre.scrollHeight;
      }
      joffset = doc.next_offset;
    } catch (_e) { /* keep polling */ }
  }, 2000);
}

/* ---------------- d) API KEYS ---------------- */
async function loadKeys() {
  const doc = await api("GET", "/api/keys");
  const tbody = $("#keys-table tbody");
  tbody.innerHTML = doc.keys.map((k) => `<tr>` +
    `<td>${esc(k.name)}</td><td class="dim">${esc(k.module)}</td><td class="dim">${esc(k.fallback)}</td>` +
    `<td>${k.set ? `<span class="badge ok">${esc(k.masked)}</span>` : '<span class="badge dead">unset</span>'}</td>` +
    `<td><input type="password" data-val="${esc(k.name)}" placeholder="${k.set ? "replace (masked after save)" : "paste key"}"></td>` +
    `<td><button data-put="${esc(k.name)}">SAVE</button> <button class="danger" data-del="${esc(k.name)}">DEL</button></td></tr>`).join("");
  tbody.onclick = async (ev) => {
    const put = ev.target.closest("[data-put]");
    const del = ev.target.closest("[data-del]");
    if (put) {
      const input = tbody.querySelector(`[data-val="${put.dataset.put}"]`);
      if (!input.value) { toast("empty value", true); return; }
      await api("PUT", "/api/keys/" + put.dataset.put, { value: input.value });
      input.value = "";
      toast(`${put.dataset.put} saved to .env (masked, picked up next run)`);
      loadKeys();
    }
    if (del) {
      await api("DELETE", "/api/keys/" + del.dataset.del);
      toast(`${del.dataset.del} deleted from .env`);
      loadKeys();
    }
  };
}

/* ---------------- e) SETTINGS ---------------- */
function ruleRow(rule) {
  const div = document.createElement("div");
  div.className = "rule-row mono";
  div.innerHTML = `{"class": <select data-rk="class"><option ${rule.class === "hosts" ? "selected" : ""}>hosts</option><option ${rule.class === "ports" ? "selected" : ""}>ports</option></select>,` +
    `"enabled": <select data-rk="enabled"><option value="true" ${rule.enabled !== false ? "selected" : ""}>true</option><option value="false" ${rule.enabled === false ? "selected" : ""}>false</option></select>,` +
    `"require_new_ip": <select data-rk="require_new_ip"><option value="false" ${!rule.require_new_ip ? "selected" : ""}>false</option><option value="true" ${rule.require_new_ip ? "selected" : ""}>true</option></select>}` +
    `<button class="danger" data-del-rule>DEL</button>`;
  return div;
}

async function loadSettings() {
  const s = await api("GET", "/api/settings");
  $("#s-proxy").value = s.proxy_url || "";
  $("#s-tg-chat").value = (s.telegram || {}).chat_id || "";
  $("#s-digest").value = s.digest_threshold || 10;
  $("#s-cpu").value = (s.resource_budget || {}).cpu_cores || "";
  $("#s-ram").value = (s.resource_budget || {}).ram_mb || "";
  $("#s-agent-enabled").value = String((s.agent || {}).enabled === true);
  $("#s-agent-passive").value = (s.agent || {}).autonomy_passive || "auto-fix";
  $("#s-agent-active").value = (s.agent || {}).autonomy_active || "suggest";
  $("#s-agent-budget").value = (s.agent || {}).max_llm_calls ?? 20;
  const ret = s.retention || {};
  $("#s-ret-runs").value = ret.keep_runs ?? 20;
  $("#s-ret-log").value = ret.log_max_mb ?? 10;
  $("#s-ret-journal").value = ret.journal_max_mb ?? 5;
  $("#s-ret-gz").value = ret.log_keep_gz ?? 3;
  $("#s-ret-total").value = ret.max_total_mb ?? 1024;
  const editor = $("#rules-editor");
  editor.innerHTML = "";
  for (const rule of s.alert_rules || [{ class: "hosts", enabled: true }, { class: "ports", enabled: true }]) {
    editor.appendChild(ruleRow(rule));
  }
  editor.onclick = (ev) => { if (ev.target.closest("[data-del-rule]")) ev.target.closest(".rule-row").remove(); };
}

async function saveSettings() {
  const patch = {
    proxy_url: $("#s-proxy").value.trim(),
    digest_threshold: parseInt($("#s-digest").value || "10", 10),
    alert_rules: [...document.querySelectorAll("#rules-editor .rule-row")].map((row) => ({
      class: row.querySelector('[data-rk="class"]').value,
      enabled: row.querySelector('[data-rk="enabled"]').value === "true",
      require_new_ip: row.querySelector('[data-rk="require_new_ip"]').value === "true",
    })),
  };
  const token = $("#s-tg-token").value.trim();
  const chat = $("#s-tg-chat").value.trim();
  if (token || chat) patch.telegram = { ...(chat ? { chat_id: chat } : {}), ...(token ? { bot_token: token } : {}) };
  const cpu = parseInt($("#s-cpu").value, 10), ram = parseInt($("#s-ram").value, 10);
  if (!isNaN(cpu) || !isNaN(ram)) patch.resource_budget = { ...(isNaN(cpu) ? {} : { cpu_cores: cpu }), ...(isNaN(ram) ? {} : { ram_mb: ram }) };
  patch.agent = {
    enabled: $("#s-agent-enabled").value === "true",
    autonomy_passive: $("#s-agent-passive").value,
    autonomy_active: $("#s-agent-active").value,
  };
  const budget = parseInt($("#s-agent-budget").value, 10);
  if (!isNaN(budget)) patch.agent.max_llm_calls = budget;
  const ret = {
    keep_runs: parseInt($("#s-ret-runs").value, 10),
    log_max_mb: parseInt($("#s-ret-log").value, 10),
    journal_max_mb: parseInt($("#s-ret-journal").value, 10),
    log_keep_gz: parseInt($("#s-ret-gz").value, 10),
    max_total_mb: parseInt($("#s-ret-total").value, 10),
  };
  if (Object.values(ret).every((v) => !isNaN(v) && v >= 1)) patch.retention = ret;
  try {
    await api("PUT", "/api/settings", patch);
    $("#s-msg").textContent = "saved " + new Date().toISOString();
    $("#s-tg-token").value = "";
    toast("settings saved to dashboard/config.json (secrets masked)");
    loadSettings();
  } catch (e) { toast(e.message, true); }
}

/* ---------------- wiring ---------------- */
$("#token-save").addEventListener("click", async () => {
  TOKEN = $("#token").value.trim();
  localStorage.setItem(TOKEN_KEY, TOKEN);
  await health();
  loadPanel(document.querySelector(".tab.active").dataset.panel);
});
$("#f-apply").addEventListener("click", () => { shareFilters(readFilterUI()); loadResults(); });
$("#f-share").addEventListener("click", async () => {
  const url = shareFilters(readFilterUI());
  try { await navigator.clipboard.writeText(url); toast("filter URL copied -- state restores from URL"); }
  catch (_e) { toast(url); }
});
$("#f-clear").addEventListener("click", () => { writeFilterUI({}); shareFilters({}); loadResults(); });
document.querySelectorAll("#assets-table th[data-sort], #coverage-table th[data-sort], #tools-table th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    CURRENT.sort = { key, dir: CURRENT.sort.key === key ? -CURRENT.sort.dir : 1 };
    renderAssets();
  });
});
$("#run-start").addEventListener("click", async () => {
  try { const r = await api("POST", "/api/run/start", { target: $("#run-target").value.trim() }); toast("started pid=" + r.pid); }
  catch (e) { toast(e.message, true); }
  loadRun();
});
$("#run-resume").addEventListener("click", async () => {
  try { const r = await api("POST", "/api/run/resume", { target: $("#run-target").value.trim() }); toast("resumed pid=" + r.pid); }
  catch (e) { toast(e.message, true); }
});
$("#run-stop").addEventListener("click", async () => {
  try { const r = await api("POST", "/api/run/stop", { target: $("#run-target").value.trim() }); toast("stop exit=" + r.exit); }
  catch (e) { toast(e.message, true); }
  loadRun();
});
$("#sched-save").addEventListener("click", async () => {
  try {
    await api("PUT", "/api/scheduler", {
      interval_minutes: parseInt($("#sched-interval").value, 10),
      enabled: $("#sched-enabled").checked,
      last_run: null,
    });
    toast("scheduler.json saved (min interval 10 enforced)");
    loadRun();
  } catch (e) { toast(e.message, true); }
});
$("#s-add-rule").addEventListener("click", () => $("#rules-editor").appendChild(ruleRow({ class: "hosts", enabled: true })));
$("#s-save").addEventListener("click", saveSettings);
$("#rep-check").addEventListener("click", async () => {
  try { await loadReports(); toast("bundle checked (tamper-check runs server-side)"); }
  catch (e) { toast(e.message, true); }
});
$("#rep-generate").addEventListener("click", async () => {
  const target = ($("#rep-target").value.trim() || CURRENT.target);
  try {
    await api("POST", "/api/report/" + encodeURIComponent(target) + "/generate");
    toast("report bundle generated for " + target);
    await loadReports();
  } catch (e) { toast(e.message, true); }
});

async function health() {
  const el = $("#conn");
  try {
    const r = await fetch("/api/health");
    const doc = await r.json();
    el.textContent = doc.ok ? "- online" : "- ?"; 
    el.className = "badge " + (doc.ok ? "ok" : "dead");
  } catch (_e) { el.textContent = "- offline"; el.className = "badge alert"; }
}

function loadPanel(name) {
  if (!TOKEN) { toast("set DASHBOARD_TOKEN first (top right)"); return; }
  if (name === "tools") { loadTools(); loadWordlists(); }
  if (name === "results") loadResults();
  if (name === "reports") loadReports();
  if (name === "run") { loadRun(); startLogStream(); startJournalStream(); }
  if (name === "keys") loadKeys();
  if (name === "settings") loadSettings();
}

(async function init() {
  $("#token").value = TOKEN;
  await health();
  const panel = restoreFiltersFromURL();
  const tab = document.querySelector(`.tab[data-panel="${panel}"]`) || document.querySelector(".tab");
  tab.click();
})();
