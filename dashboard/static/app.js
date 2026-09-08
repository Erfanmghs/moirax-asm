/* recon-pipeline SPA -- panels a-e (section 9.2), URL-shareable global filters (section 9.2-b),
   sortable tables + badges + collapsible JSON inspector (section 9.4). Zero-build
   vanilla JS; the API contract (section 9.1) is the stable surface. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const TOKEN_KEY = "recon_dashboard_token";

function readToken() {
  const session = sessionStorage.getItem(TOKEN_KEY) || "";
  const leftover = localStorage.getItem(TOKEN_KEY) || "";
  if (leftover) {
    localStorage.removeItem(TOKEN_KEY);
    if (!session) sessionStorage.setItem(TOKEN_KEY, leftover);
  }
  return sessionStorage.getItem(TOKEN_KEY) || "";
}

function writeToken(value) {
  localStorage.removeItem(TOKEN_KEY);
  if (value) sessionStorage.setItem(TOKEN_KEY, value);
  else sessionStorage.removeItem(TOKEN_KEY);
}

let TOKEN = readToken();
let CURRENT = { target: localStorage.getItem("recon_last_target") || "", assets: [], sort: { key: null, dir: 1 } };
const TASK_LABELS = {
  "FFUF-0": "Optional HTTP brute (ffuf)",
  "DNSR-1": "DNS subdomain brute (dnsx)",
  "FFUF-2": "Virtual hosts (ffuf)",
};

function syncTokenFromBox() {
  const typed = ($("#token") && $("#token").value.trim()) || "";
  if (typed && typed !== TOKEN) {
    TOKEN = typed;
    writeToken(TOKEN);
  }
  return TOKEN;
}

async function api(method, path, body) {
  syncTokenFromBox();
  const headers = {};
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  if (res.status === 401) { toast("invalid token -- paste DASHBOARD_TOKEN and press SET", true); throw new Error("401"); }
  if (res.status === 503) { toast("DASHBOARD_TOKEN not configured on backend", true); throw new Error("503"); }
  const doc = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof doc.detail === "string" ? doc.detail : (res.statusText || String(res.status)));
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

/* Per-panel site pickers -- the platform is multi-target; the header never
   owns a single global TARGET. SCAN / RESULTS / REPORTS each pick a site. */
function panelTarget(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : "";
}

function rememberTarget(target) {
  if (!target) return;
  CURRENT.target = target;
  localStorage.setItem("recon_last_target", target);
}

function currentTarget() {
  return panelTarget("run-target") || panelTarget("results-target") || panelTarget("rep-target") || (CURRENT.target || "").trim();
}

function requireScanTarget() {
  const target = panelTarget("run-target");
  if (!target) {
    toast("Type a domain on the SCAN page first", true);
    return "";
  }
  rememberTarget(target);
  return target;
}

async function refreshKnownTargets() {
  const list = $("#known-targets");
  if (!list) return [];
  try {
    const doc = await api("GET", "/api/targets");
    const names = [...new Set([...(doc.known || []), ...Object.keys(doc.targets || {})])].sort();
    list.innerHTML = names.map((n) => `<option value="${esc(n)}"></option>`).join("");
    return names;
  } catch (_e) {
    return [];
  }
}

function seedPanelTargets(names) {
  const last = CURRENT.target;
  const pick = (id) => {
    const el = document.getElementById(id);
    if (!el || el.value.trim()) return;
    if (last) el.value = last;
    else if (names && names[0]) el.value = names[0];
  };
  pick("run-target");
  pick("results-target");
  pick("rep-target");
}

/* ---------------- panel switching ---------------- */
$("#tabs").addEventListener("click", (ev) => {
  const btn = ev.target.closest(".tab");
  if (!btn) return;
  activatePanel(btn.dataset.panel, true);
});

function activatePanel(name, push) {
  const btn = document.querySelector(`.tab[data-panel="${name}"]`);
  if (!btn) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === btn));
  document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
  const panel = $("#panel-" + name);
  if (panel) panel.classList.remove("hidden");
  try { localStorage.setItem("recon_last_panel", name); } catch (_e) { /* ignore */ }
  if (push) {
    const params = new URLSearchParams(location.search);
    params.set("panel", name);
    history.replaceState({}, "", location.pathname + "?" + params.toString());
  }
  loadPanel(name);
}

const brandHome = $("#brand-home");
if (brandHome) {
  brandHome.addEventListener("click", (ev) => {
    ev.preventDefault();
    activatePanel("run", true);
  });
}

/* ---------------- a) TOOLS ---------------- */
async function loadTools() {
  const tbody = $("#tools-table tbody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="dim">loading tools...</td></tr>';
  try {
    const doc = await api("GET", "/api/tools");
    const rows = doc.tools || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="dim">no operator tools in tools.yaml</td></tr>';
      return;
    }
    tbody.innerHTML = "";
    for (const t of rows) {
      const id = t.id || t.name;
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${esc(t.binary || t.name || id)}</td>` +
        `<td class="mono">${esc(id)}</td>` +
        `<td>${esc(t.technique || "")}</td>` +
        `<td class="wrap">${esc(t.controls || t.technique || "")}</td>` +
        `<td class="dim">${esc(t.branch || "")}</td>` +
        `<td><button class="${t.enabled ? "" : "danger"}" data-toggle="${esc(id)}" ${t.locked ? "disabled" : ""}>${t.locked ? "LOCKED ON" : (t.enabled ? "ENABLED" : "DISABLED")}</button></td>`;
      tbody.appendChild(tr);
    }
    tbody.onclick = async (ev) => {
      const btn = ev.target.closest("[data-toggle]");
      if (!btn) return;
      const name = btn.dataset.toggle;
      const enable = btn.textContent === "DISABLED";
      try {
        await api("PUT", "/api/tools/" + encodeURIComponent(name), { enabled: enable });
        toast(`${name} ${enable ? "enabled" : "disabled"}`);
        loadTools();
      } catch (e) { toast(e.message, true); }
    };
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="dim">could not load tools: ${esc(e.message)}</td></tr>`;
  }
}

async function loadWordlists() {
  const root = $("#wordlists");
  if (!root) return;
  root.innerHTML = '<p class="dim">loading wordlists...</p>';
  let doc;
  try {
    doc = await api("GET", "/api/wordlists");
  } catch (e) {
    root.innerHTML = `<p class="dim">could not load wordlists: ${esc(e.message)}</p>`;
    return;
  }
  root.innerHTML = "";
  const lists = doc.lists || {};
  const fileName = (key) => {
    const entry = lists[key] || {};
    return entry.name || (String(entry.path || "").split("/").pop()) || key;
  };
  for (const [task, spec] of Object.entries(doc.tasks || {})) {
    const selected = new Set(spec.selection || spec.default_selection || []);
    const box = document.createElement("div");
    box.className = "table-wrap";
    box.style.marginBottom = "14px";
    const seen = new Set();
    const rows = [];
    const keys = spec.allow_registry_wide
      ? Object.keys(lists)
      : [].concat(spec.fast || [], spec.expansion || [], spec.sources || [], spec.default_selection || []);
    const sorted = [...new Set(keys)].sort((a, b) => fileName(a).localeCompare(fileName(b)));
    for (const key of sorted) {
      if (seen.has(key)) continue;
      seen.add(key);
      const meta = lists[key] || {};
      const fname = fileName(key);
      rows.push(`<tr data-wl="${esc(key)}"><td><input type="checkbox" data-key="${esc(key)}" ${selected.has(key) ? "checked" : ""}></td>` +
        `<td class="mono">${esc(fname)}</td><td class="dim">${esc(meta.path || "")}</td></tr>`);
    }
    const label = TASK_LABELS[task] || task;
    box.innerHTML = `<table><thead><tr><th>SEL</th><th>${esc(label)} -- original filename</th><th>PATH</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
    const bar = document.createElement("div");
    bar.className = "row";
    bar.innerHTML = `<input data-filter="${esc(task)}" placeholder="filter by original filename" class="mono">` +
      `<button data-all="${esc(task)}">SELECT-ALL (visible)</button><button data-save="${esc(task)}">SAVE SELECTION</button>` +
      `<span class="dim">${sorted.length} lists</span>`;
    root.appendChild(bar);
    root.appendChild(box);
    const filter = bar.querySelector("[data-filter]");
    filter.addEventListener("input", () => {
      const q = filter.value.trim().toLowerCase();
      box.querySelectorAll("tbody tr").forEach((tr) => {
        tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? "" : "none";
      });
    });
    bindWordlistPreview(box);
  }
  if (!root.children.length) {
    root.innerHTML = `<p class="dim">no wordlist tasks in wordlists.yaml (${Object.keys(lists).length} lists in catalog)</p>`;
  }
  root.onclick = async (ev) => {
    const all = ev.target.closest("[data-all]");
    const save = ev.target.closest("[data-save]");
    if (all) {
      const table = all.closest(".row").nextElementSibling;
      table.querySelectorAll("tbody tr").forEach((tr) => {
        if (tr.style.display === "none") return;
        const cb = tr.querySelector("input[type=checkbox][data-key]");
        if (cb) cb.checked = true;
      });
      toast("select-all ticked -- remember SAVE SELECTION");
    }
    if (save) {
      const task = save.dataset.save;
      const table = save.closest(".row").nextElementSibling;
      const boxes = [...table.querySelectorAll("input[type=checkbox][data-key]:checked")].map((cb) => cb.dataset.key);
      await api("PUT", "/api/wordlists", { [task]: boxes });
      toast(`${task} selection saved (${boxes.length} lists)`);
    }
  };
}

let _wlPreviewGen = 0;
function clearWordlistPreview() {
  const label = $("#wl-preview-label");
  const body = $("#wl-preview-body");
  if (label) label.textContent = "hover a filename -- names stay visible";
  if (body) body.innerHTML = "";
}
function bindWordlistPreview(box) {
  const label = $("#wl-preview-label");
  const body = $("#wl-preview-body");
  if (!label || !body) return;
  const tbody = box.querySelector("tbody");
  if (!tbody) return;
  tbody.querySelectorAll("tr[data-wl]").forEach((tr) => {
    tr.addEventListener("mouseenter", async () => {
      const key = tr.getAttribute("data-wl");
      if (!key) return;
      const gen = ++_wlPreviewGen;
      const fname = (tr.querySelector("td.mono") && tr.querySelector("td.mono").textContent) || key;
      label.textContent = fname;
      body.innerHTML = "";
      try {
        const doc = await api("GET", "/api/wordlists/preview?key=" + encodeURIComponent(key));
        if (gen !== _wlPreviewGen) return;
        const samples = doc.samples || [];
        if (!samples.length) {
          body.innerHTML = "<li class=\"dim\">" + esc(doc.reason || "no sample lines") + "</li>";
          return;
        }
        body.innerHTML = samples.map((s) => "<li>" + esc(s) + "</li>").join("");
      } catch (e) {
        if (gen !== _wlPreviewGen) return;
        body.innerHTML = "<li class=\"dim\">" + esc(e.message) + "</li>";
      }
    });
  });
  tbody.addEventListener("mouseleave", () => {
    _wlPreviewGen += 1;
    clearWordlistPreview();
  });
}

/* ---------------- a2) TARGETS (C3 + D-protocol) ---------------- */
function targetProfileFromUI() {
  const profile = {};
  const desc = $("#t-desc").value.trim();
  if (desc) profile.description = desc;
  // PUT contract (C3 closed allow-list): sections at TOP level, no wrapper
  const tg = $("#t-tg").value.trim();
  const tgen = $("#t-tgen").value;
  const watch = $("#t-watch").value;
  const digest = $("#t-digest").value.trim();
  const notif = {};
  if (tg) notif.telegram_chat = tg;
  if (tgen !== "") notif.telegram_enabled = tgen === "true";
  if (watch !== "") notif.watchtower_enabled = watch === "true";
  if (digest) notif.digest_threshold = parseInt(digest, 10);
  if (Object.keys(notif).length) profile.notifications = notif;
  const tpool = $("#t-proxy").value.trim();
  if (tpool) profile.proxy = { proxy_pool: tpool };
  const budgets = {};
  for (const [id, key] of [["t-b-passive", "passive_branch_budget_sec"], ["t-b-active", "active_branch_budget_sec"],
    ["t-b-depth", "passive_recursion_depth"], ["t-b-dead", "ffuf3_max_dead_probes"],
    ["t-b-ffuf4", "ffuf4_max_jobs"]]) {
    const v = $("#" + id).value.trim();
    if (v !== "") budgets[key] = parseInt(v, 10);
  }
  if (Object.keys(budgets).length) profile.budgets = budgets;
  const modules = {};
  const act = $("#t-m-active").value.trim();
  const pas = $("#t-m-passive").value.trim();
  if (act) modules.active_branch_modules = act.split(",").map((s) => s.trim()).filter(Boolean);
  if (pas) modules.passive_branch_modules = pas.split(",").map((s) => s.trim()).filter(Boolean);
  if (Object.keys(modules).length) profile.modules = modules;
  const wl = {};
  for (const task of ["FFUF-0", "DNSR-1", "FFUF-2"]) {
    const v = $("#t-wl-" + task).value.trim();
    if (v) wl[task] = v.split(",").map((s) => s.trim()).filter(Boolean);
  }
  if (Object.keys(wl).length) profile.wordlist_selection = wl;
  return profile;
}

function targetProfileToUI(profile) {
  const s = (profile && profile.settings) || {};
  const n = s.notifications || {};
  $("#t-desc").value = (profile && profile.description) || "";
  $("#t-tg").value = n.telegram_chat || "";
  $("#t-tgen").value = n.telegram_enabled === true ? "true" : n.telegram_enabled === false ? "false" : "";
  $("#t-proxy").value = (s.proxy || {}).proxy_pool || "";
  $("#t-watch").value = n.watchtower_enabled === true ? "true" : n.watchtower_enabled === false ? "false" : "";
  $("#t-digest").value = n.digest_threshold || "";
  const b = s.budgets || {};
  $("#t-b-passive").value = b.passive_branch_budget_sec ?? "";
  $("#t-b-active").value = b.active_branch_budget_sec ?? "";
  $("#t-b-depth").value = b.passive_recursion_depth ?? "";
  $("#t-b-dead").value = b.ffuf3_max_dead_probes ?? "";
  $("#t-b-ffuf4").value = b.ffuf4_max_jobs ?? "";
  const m = s.modules || {};
  $("#t-m-active").value = (m.active_branch_modules || []).join(", ");
  $("#t-m-passive").value = (m.passive_branch_modules || []).join(", ");
  const wl = s.wordlist_selection || {};
  for (const task of ["FFUF-0", "DNSR-1", "FFUF-2"]) $("#t-wl-" + task).value = (wl[task] || []).join(", ");
}

async function loadTargetProfile() {
  const target = $("#t-name").value.trim();
  if (!target) { toast("enter a target name first", true); return; }
  try {
    const doc = await api("GET", "/api/targets/" + encodeURIComponent(target));
    targetProfileToUI(doc.profile);
    const sections = (doc.profile && Object.keys(doc.profile.settings || {}).length) ? Object.keys(doc.profile.settings).join(", ") : "no profile (committed defaults)";
    $("#t-status").textContent = target + ": " + sections;
    $("#t-status").className = "badge ok";
    $("#t-plan").textContent = doc.edit_plan && Object.keys(doc.edit_plan.wordlist_selection || {}).length ? "wordlist override active" : "";
    toast("profile loaded for " + target);
  } catch (e) { toast(e.message, true); }
}

async function saveTargetProfile() {
  const target = $("#t-name").value.trim();
  if (!target) { toast("enter a target name first", true); return; }
  try {
    const profile = targetProfileFromUI();
    if (!Object.keys(profile).length) { toast("nothing to save (all fields empty)", true); return; }
    await api("PUT", "/api/targets/" + encodeURIComponent(target), profile);
    toast("profile saved for " + target + " (closed allow-list enforced)");
    loadTargetsTable();
  } catch (e) { toast(e.message, true); }
}

async function deleteTargetProfile() {
  const target = $("#t-name").value.trim();
  if (!target) { toast("enter a target name first", true); return; }
  if (!window.confirm("Remove the saved profile for " + target + "? Recon files on disk stay.")) return;
  try {
    await api("PUT", "/api/targets/" + encodeURIComponent(target), {});
    targetProfileToUI({});
    toast("profile removed for " + target + " (back to committed defaults)");
    loadTargetsTable();
  } catch (e) { toast(e.message, true); }
}

async function loadTargetsTable() {
  const doc = await api("GET", "/api/targets");
  const tbody = $("#targets-table tbody");
  const names = Object.keys(doc.targets || {});
  if (!names.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="dim">no profiles yet -- add a domain above</td></tr>';
    return;
  }
  tbody.innerHTML = names.map((name) => {
    const p = doc.targets[name];
    const s = p.settings || {};
    const tg = (s.notifications || {}).telegram_chat || "--";
    return `<tr><td>${esc(name)}</td>` +
      `<td class="mono">${esc(tg)}</td>` +
      `<td><button data-tload="${esc(name)}">EDIT</button></td></tr>`;
  }).join("");
  tbody.onclick = (ev) => {
    const btn = ev.target.closest("[data-tload]");
    if (!btn) return;
    $("#t-name").value = btn.dataset.tload;
    loadTargetProfile();
  };
  refreshKnownTargets();
}

/* ---------------- a3) FLEET (C4) ---------------- */
async function loadFleet() {
  const doc = await api("GET", "/api/fleet");
  $("#fl-members-view").textContent = doc.members.length
    ? `members (${doc.members.length}, max concurrency ${doc.max_concurrency}): ` + doc.members.join(", ")
    : `no registered members -- create target profiles first (max concurrency ${doc.max_concurrency})`;
  const led = await api("GET", "/api/fleet/ledger");
  const pre = $("#fl-ledger");
  const badge = $("#fl-status");
  if (!led.exists) {
    pre.textContent = "no fleet run yet";
    badge.textContent = "no fleet run";
    badge.className = "badge dead";
    return;
  }
  const ok = led.clean === true;
  badge.textContent = ok ? "LAST FLEET CLEAN" : "LAST FLEET WITH FAILURES";
  badge.className = "badge " + (ok ? "ok" : "alert");
  pre.textContent = JSON.stringify(led, null, 2);
  pre.onclick = () => pre.classList.toggle("collapsed");
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
  return params.get("panel") || "run";
}

async function loadResults() {
  const target = panelTarget("results-target") || CURRENT.target;
  if (!target) { toast("Pick a site on the RESULTS page", true); return; }
  rememberTarget(target);
  $("#results-target").value = target;
  const f = readFilterUI();
  const qs = new URLSearchParams(f).toString();
  const doc = await api("GET", "/api/results/" + encodeURIComponent(CURRENT.target) + (qs ? "?" + qs : ""));
  CURRENT.assets = doc.assets;
  renderAssets();
  const cov = await api("GET", "/api/results/" + encodeURIComponent(CURRENT.target) + "/coverage");
  renderCoverage(cov);
  const diff = await api("GET", "/api/results/" + encodeURIComponent(CURRENT.target) + "/diff");
  renderDiff(diff);
  await loadWarehouseMeta(target);
}

async function loadWarehouseMeta(target) {
  const badge = $("#wh-badge");
  const meta = $("#wh-meta");
  try {
    const wh = await api("GET", "/api/warehouse/" + encodeURIComponent(target));
    const runsDoc = await api("GET", "/api/warehouse/" + encodeURIComponent(target) + "/runs");
    const runs = runsDoc.runs || [];
    fillRunSelects(runs);
    const n = (wh.facts && wh.facts.hosts) || 0;
    if (badge) {
      badge.textContent = wh.exists ? ("isolated " + (wh.runs || 0) + " runs") : "no warehouse yet";
      badge.className = "badge " + (wh.exists ? "ok" : "dead");
    }
    if (meta) {
      meta.textContent = "this site only: " + (wh.path || "") + " | hosts=" + n
        + " vhosts=" + ((wh.facts && wh.facts.vhosts) || 0)
        + " ports=" + ((wh.facts && wh.facts.ports) || 0);
    }
  } catch (_e) {
    if (badge) { badge.textContent = "warehouse unavailable"; badge.className = "badge alert"; }
  }
}

function fillRunSelects(runs) {
  const fromEl = $("#diff-from");
  const toEl = $("#diff-to");
  if (!fromEl || !toEl) return;
  const opts = ['<option value="">(empty baseline)</option>'].concat(
    runs.map((r) => `<option value="${esc(r.timestamp)}">${esc(r.timestamp)} ${esc(r.status || "")}</option>`)
  );
  const keepFrom = fromEl.value;
  const keepTo = toEl.value;
  fromEl.innerHTML = opts.join("");
  toEl.innerHTML = runs.map((r) => `<option value="${esc(r.timestamp)}">${esc(r.timestamp)} ${esc(r.status || "")}</option>`).join("");
  if (keepFrom && [...fromEl.options].some((o) => o.value === keepFrom)) fromEl.value = keepFrom;
  else if (runs.length >= 2) fromEl.value = runs[runs.length - 2].timestamp;
  if (keepTo && [...toEl.options].some((o) => o.value === keepTo)) toEl.value = keepTo;
  else if (runs.length) toEl.value = runs[runs.length - 1].timestamp;
}

async function compareWarehouseRuns() {
  const target = panelTarget("results-target") || CURRENT.target;
  if (!target) { toast("Pick a site on the RESULTS page", true); return; }
  const fromRun = ($("#diff-from") && $("#diff-from").value) || "";
  const toRun = ($("#diff-to") && $("#diff-to").value) || "";
  if (!toRun) { toast("Pick a TO RUN", true); return; }
  const qs = new URLSearchParams({ from_run: fromRun, to_run: toRun }).toString();
  const diff = await api("GET", "/api/results/" + encodeURIComponent(target) + "/diff?" + qs);
  renderDiff(diff);
  const doc = await api("GET", "/api/results/" + encodeURIComponent(target) + "?run=" + encodeURIComponent(toRun));
  CURRENT.assets = doc.assets;
  renderAssets();
}

async function rebuildWarehouse() {
  const target = panelTarget("results-target") || CURRENT.target;
  if (!target) { toast("Pick a site on the RESULTS page", true); return; }
  await api("POST", "/api/warehouse/" + encodeURIComponent(target) + "/rebuild");
  toast("warehouse rebuilt for " + target);
  await loadResults();
}

function portBadges(ports) {
  const list = Array.isArray(ports) ? ports : [];
  if (!list.length) return '<span class="dim">—</span>';
  return list.map((p) => {
    const label = (p && p.label) ? p.label : String(p);
    return `<span class="badge port">${esc(label)}</span>`;
  }).join(" ");
}

function renderPortsByHost() {
  const tbody = $("#ports-by-host tbody");
  if (!tbody) return;
  const rows = (CURRENT.assets || []).filter((r) => (r.open_ports || []).length);
  tbody.innerHTML = rows.map((r) => {
    const ips = (r.ips || [r.ip]).filter(Boolean).join(", ");
    return `<tr><td class="mono">${esc(r.host)}</td><td class="dim">${esc(ips)}</td><td class="ports-cell">${portBadges(r.open_ports)}</td></tr>`;
  }).join("") || '<tr><td colspan="3" class="dim">no open ports recorded for this site yet (run port-check / port-sweep)</td></tr>';
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
  tbody.innerHTML = rows.map((r) =>     `<tr>` +
    `<td>${esc(r.host)} ${r.is_new ? '<span class="badge new">NEW</span>' : ""}</td>` +
    `<td class="dim">${esc((r.ips || [r.ip]).filter(Boolean).join(", "))}</td>` +
    `<td class="ports-cell">${portBadges(r.open_ports)}</td>` +
    `<td><span class="badge ${r.alive ? "alive" : "dead"}">${r.alive ? "ALIVE" : "DEAD"}</span></td>` +
    `<td class="dim">${esc(r.length == null ? "" : String(r.length))}</td>` +
    `<td class="dim">${esc((r.tech || []).join(", "))}</td>` +
    `<td class="dim">${esc((r.sources || []).join(", "))}</td>` +
    `<td>${(r.tags || []).map((t) => `<span class="badge">${esc(t)}</span>`).join(" ")}</td>` +
    `<td class="dim">${esc(r.first_seen || "")}</td>` +
    `<td class="dim">${esc(r.last_seen || "")}</td>` +
    `<td><button data-json='${esc(JSON.stringify(r))}'>{ }</button></td></tr>`).join("") ||
    `<tr><td colspan="11" class="dim">no assets (run the pipeline first)</td></tr>`;
  tbody.onclick = (ev) => {
    const btn = ev.target.closest("[data-json]");
    if (!btn) return;
    const pre = $("#diff-view");
    pre.textContent = JSON.stringify(JSON.parse(btn.dataset.json), null, 2);
    pre.classList.remove("collapsed");
    pre.scrollIntoView({ behavior: "smooth" });
  };
  renderPortsByHost();
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
  const added = diff.added || {};
  const removed = diff.removed || {};
  const n = (cls) => (added[cls] || []).length;
  const r = (cls) => (removed[cls] || []).length;
  badges.innerHTML =
    `<span class="badge new">+hosts ${n("hosts")}</span><span class="badge new">+ports ${n("ports")}</span>` +
    `<span class="badge dead">-hosts ${r("hosts")}</span><span class="badge dead">-ports ${r("ports")}</span>` +
    (diff.from_run || diff.to_run ? `<span class="badge">${esc(diff.from_run || "baseline")} -> ${esc(diff.to_run || "")}</span>` : "");
  const pre = $("#diff-view");
  pre.textContent = JSON.stringify(diff, null, 2);
  pre.onclick = () => pre.classList.toggle("collapsed");
}

/* ---------------- b2) REPORTS ---------------- */
async function loadReports() {
  const target = ($("#rep-target").value.trim() || CURRENT.target);
  if (!target) { toast("Pick a site on the REPORTS page", true); return; }
  rememberTarget(target);
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

/* ---------------- c) RUN CONTROL -- multi-target board ---------------- */
const SCAN = { expanded: new Set(), streams: {}, boardTimer: null };

function statusBadgeClass(status) {
  if (status === "completed") return "ok";
  if (status === "failed" || status === "anomaly") return "alert";
  if (status === "running") return "new";
  if (status === "stopped") return "new";
  return "dead";
}

function cardFor(target) {
  return [...document.querySelectorAll(".scan-card")].find((c) => c.dataset.scan === target) || null;
}

async function loadRun() {
  const target = panelTarget("run-target") || CURRENT.target;
  if (target) {
    rememberTarget(target);
    $("#run-target").value = target;
  }
  try {
    const sched = await api("GET", "/api/scheduler");
    $("#sched-interval").value = sched.interval_minutes;
    $("#sched-enabled").checked = !!sched.enabled;
    $("#sched-last").textContent = "last_run: " + (sched.last_run || "never");
  } catch (_e) { /* board still loads */ }
  await loadScanBoard();
  if (target && !SCAN.expanded.size) setScanExpanded(target, true);
  const badge = $("#run-status");
  if (!badge) return;
  if (!target) {
    badge.textContent = "add a site to begin";
    badge.className = "badge dead";
    return;
  }
  try {
    const st = await api("GET", "/api/run/status/" + encodeURIComponent(target));
    const runStatus = (st.run && st.run.status) || st.run_status || "";
    const exists = st.exists !== false && (st.exists === true || !!st.modules || !!st.run);
    badge.textContent = exists ? `${target}: ${runStatus || "?"}` : `${target}: registered`;
    badge.className = "badge " + statusBadgeClass(runStatus);
  } catch (_e) {
    badge.textContent = target;
  }
  try {
    const st = await api("GET", "/api/run/status/" + encodeURIComponent(target));
    const box = $("#run-modules");
    if (box) {
      const mods = st.modules || {};
      box.innerHTML = Object.keys(mods).length
        ? Object.entries(mods).map(([m, s]) => {
            const status = (s && s.status) || "?";
            return `<span class="mod-chip ${esc(status)}">${esc(m)} <b>${esc(status)}</b></span>`;
          }).join("")
        : "";
    }
  } catch (_e) { /* modules optional */ }
}

function startLogStream() {
  clearInterval(window.__logTimer);
  const rawEl = $("#live-log");
  const prettyEl = $("#live-log-pretty");
  if (rawEl) rawEl.textContent = "";
  if (prettyEl) prettyEl.innerHTML = "";
  window.__livePretty = { prettyKey: "" };
  let offset = 0;
  let bound = "";
  window.__logTimer = setInterval(async () => {
    if (!$("#panel-run") || $("#panel-run").classList.contains("hidden")) return;
    const target = (CURRENT.target || panelTarget("run-target") || "").trim();
    if (!target) return;
    if (target !== bound) {
      bound = target;
      offset = 0;
      if (rawEl) rawEl.textContent = "";
      if (prettyEl) prettyEl.innerHTML = "";
      window.__livePretty = { prettyKey: "" };
    }
    try {
      const doc = await api("GET", `/api/run/log/${encodeURIComponent(target)}?offset=${offset}`);
      if (!doc.exists) return;
      if (offset === 0 && doc.total > 200) offset = Math.max(0, doc.total - 200);
      if (doc.lines && doc.lines.length) {
        if (rawEl) {
          rawEl.textContent += doc.lines.map((l) => l + "\n").join("");
          rawEl.scrollTop = rawEl.scrollHeight;
        }
        appendPrettyLogs(doc.lines, prettyEl, window.__livePretty);
      }
      offset = doc.next_offset;
    } catch (_e) { /* keep polling */ }
  }, 2000);
}

function scanCardHtml(row) {
  const t = row.target;
  const status = row.run_status || "idle";
  const open = SCAN.expanded.has(t);
  const modules = Object.entries(row.modules || {}).map(([m, s]) => {
    const st = (s && s.status) || "?";
    return `<span class="mod-chip ${esc(st)}">${esc(m)} <b>${esc(st)}</b></span>`;
  }).join("") || '<span class="dim">no module state yet</span>';
  const counts = row.last_counts || {};
  const countBits = Object.keys(counts).length
    ? Object.entries(counts).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(" ")
    : "";
  return `<article class="scan-card${open ? " open" : ""}" data-scan="${esc(t)}">
    <div class="scan-head">
      <button type="button" class="scan-toggle" data-expand="${esc(t)}" aria-expanded="${open ? "true" : "false"}">${open ? "COLLAPSE" : "EXPAND"}</button>
      <span class="scan-name">${esc(t)}</span>
      <span class="badge ${statusBadgeClass(status)}">${esc(status)}</span>
      <span class="scan-desc">${esc(row.description || (row.registered ? "registered" : "workspace only"))}${row.last_run ? " · last " + esc(row.last_run) : ""}${row.run_count ? " · " + row.run_count + " runs" : ""}</span>
      <div class="scan-head-actions">
        <button data-scan-start="${esc(t)}">START</button>
        <button data-scan-resume="${esc(t)}">RESUME</button>
        <button class="danger" data-scan-stop="${esc(t)}">STOP</button>
      </div>
    </div>
    <div class="scan-body">
      <div class="scan-modules">${modules}</div>
      <div class="scan-jumps">
        <button data-jump="results" data-jt="${esc(t)}">RESULTS</button>
        <button data-jump="reports" data-jt="${esc(t)}">REPORTS</button>
        <button data-jump="targets" data-jt="${esc(t)}">PROFILE</button>
      </div>
      <p class="mono dim">${countBits ? "last counts: " + countBits : "no completed run counts yet"} · logs ${row.has_logs ? "present" : "none yet"}</p>
      <div class="term">
        <div class="term-bar">
          <i></i><i></i><i></i>
          <span class="term-title">live log -- ${esc(t)}</span>
          <span class="log-mode">
            <button type="button" class="log-mode-btn active" data-logmode="pretty">Readable</button>
            <button type="button" class="log-mode-btn" data-logmode="raw">Raw</button>
          </span>
        </div>
        <div class="log-pretty scan-log-pretty" data-role="pretty"></div>
        <pre class="json-inspector hidden" data-role="raw"></pre>
      </div>
      <div class="term">
        <div class="term-bar"><i></i><i></i><i></i> assistant journal -- ${esc(t)}</div>
        <pre class="json-inspector" data-role="journal"></pre>
      </div>
    </div>
  </article>`;
}

function stopTargetStream(target) {
  const s = SCAN.streams[target];
  if (!s) return;
  clearInterval(s.logTimer);
  clearInterval(s.journalTimer);
  delete SCAN.streams[target];
}

function startTargetStream(target) {
  const card = cardFor(target);
  if (!card) return;
  const pretty = card.querySelector("[data-role=pretty]");
  const raw = card.querySelector("[data-role=raw]");
  const journal = card.querySelector("[data-role=journal]");
  const existing = SCAN.streams[target];
  if (existing && existing.card === card) return;
  stopTargetStream(target);
  if (pretty) pretty.innerHTML = "";
  if (raw) raw.textContent = "";
  if (journal) journal.textContent = "";
  const state = { card, logOff: 0, jOff: 0, prettyKey: "", skipped: false, logTimer: null, journalTimer: null };
  SCAN.streams[target] = state;
  async function pullLog() {
    if ($("#panel-run").classList.contains("hidden") || !SCAN.expanded.has(target)) return;
    try {
      const doc = await api("GET", `/api/run/log/${encodeURIComponent(target)}?offset=${state.logOff}`);
      if (!doc.exists) {
        if (pretty && !pretty.childElementCount) {
          pretty.innerHTML = '<div class="log-row info"><span class="log-msg">No log yet. Press START, then keep this row expanded.</span></div>';
        }
        return;
      }
      if (state.logOff === 0 && !state.skipped && doc.total > 200) {
        state.logOff = Math.max(0, doc.total - 200);
        state.skipped = true;
        return pullLog();
      }
      state.skipped = true;
      if (doc.lines && doc.lines.length) {
        if (pretty && pretty.querySelector(".log-row.info") && !pretty.querySelector(".log-time")) pretty.innerHTML = "";
        if (raw) {
          raw.textContent += doc.lines.map((l) => l + "\n").join("");
          raw.scrollTop = raw.scrollHeight;
        }
        appendPrettyLogs(doc.lines, pretty, state);
      }
      state.logOff = doc.next_offset;
    } catch (_e) { /* keep polling */ }
  }
  async function pullJournal() {
    if ($("#panel-run").classList.contains("hidden") || !SCAN.expanded.has(target)) return;
    try {
      const doc = await api("GET", `/api/run/agent-journal/${encodeURIComponent(target)}?offset=${state.jOff}`);
      if (!doc.exists || !journal) return;
      if (doc.rows && doc.rows.length) {
        journal.textContent += doc.rows.map((l) => {
          try { const r = JSON.parse(l); return `[${r.ts}] ${r.event}: ${JSON.stringify(r)}\n`; }
          catch (_e) { return l + "\n"; }
        }).join("");
        journal.scrollTop = journal.scrollHeight;
      }
      state.jOff = doc.next_offset;
    } catch (_e) { /* keep polling */ }
  }
  pullLog();
  pullJournal();
  state.logTimer = setInterval(pullLog, 2000);
  state.journalTimer = setInterval(pullJournal, 2000);
}

function setScanExpanded(target, open) {
  if (open) SCAN.expanded.add(target);
  else {
    SCAN.expanded.delete(target);
    stopTargetStream(target);
  }
  const card = cardFor(target);
  if (!card) return;
  card.classList.toggle("open", open);
  const btn = card.querySelector(".scan-toggle");
  if (btn) {
    btn.textContent = open ? "COLLAPSE" : "EXPAND";
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  }
  if (open) {
    if ($("#run-target")) $("#run-target").value = target;
    rememberTarget(target);
    startTargetStream(target);
    startLogStream();
    startJournalStream();
  }
}

async function loadScanBoard() {
  const board = $("#scan-board");
  if (!board) return;
  try {
    let doc;
    try {
      doc = await api("GET", "/api/scan/board");
    } catch (_boardErr) {
      const tdoc = await api("GET", "/api/targets");
      const names = [...new Set([...(tdoc.known || []), ...Object.keys(tdoc.targets || {})])].sort();
      const assembled = [];
      for (const name of names) {
        const profile = (tdoc.targets && tdoc.targets[name]) || {};
        let st = {};
        try { st = await api("GET", "/api/run/status/" + encodeURIComponent(name)); } catch (_st) { /* none */ }
        const run = (st.run && typeof st.run === "object") ? st.run : {};
        assembled.push({
          target: name,
          registered: !!(tdoc.targets && Object.prototype.hasOwnProperty.call(tdoc.targets, name)),
          description: profile.description || "",
          workspace: st.exists !== false,
          run_status: run.status || st.run_status || "",
          modules: st.modules || {},
          last_run: "",
          last_counts: {},
          run_count: 0,
          has_logs: st.exists === true,
        });
      }
      doc = { targets: assembled };
    }
    const rows = doc.targets || [];
    if (!rows.length) {
      board.innerHTML = '<p class="dim">no sites yet -- type a domain above and press ADD TARGET</p>';
      return;
    }
    const ids = rows.map((r) => r.target).join("\n");
    if (board.dataset.ids === ids && board.querySelector(".scan-card")) {
      for (const row of rows) {
        const card = cardFor(row.target);
        if (!card) continue;
        const badge = card.querySelector(".scan-head > .badge");
        const status = row.run_status || "idle";
        if (badge) {
          badge.textContent = status;
          badge.className = "badge " + statusBadgeClass(status);
        }
        const mods = card.querySelector(".scan-modules");
        if (mods) {
          const html = Object.entries(row.modules || {}).map(([m, s]) => {
            const st = (s && s.status) || "?";
            return `<span class="mod-chip ${esc(st)}">${esc(m)} <b>${esc(st)}</b></span>`;
          }).join("") || '<span class="dim">no module state yet</span>';
          mods.innerHTML = html;
        }
      }
      for (const t of [...SCAN.expanded]) startTargetStream(t);
      return;
    }
    board.dataset.ids = ids;
    board.innerHTML = rows.map(scanCardHtml).join("");
    for (const t of [...SCAN.expanded]) {
      if (!rows.some((r) => r.target === t)) {
        stopTargetStream(t);
        SCAN.expanded.delete(t);
        continue;
      }
      startTargetStream(t);
    }
  } catch (e) {
    board.innerHTML = '<p class="dim">could not load sites: ' + esc(e.message) + "</p>";
  }
}

async function refreshScanBadges() {
  try {
    const doc = await api("GET", "/api/scan/board");
    for (const row of doc.targets || []) {
      const card = cardFor(row.target);
      if (!card) continue;
      const badge = card.querySelector(".scan-head > .badge");
      if (badge) {
        badge.textContent = row.run_status || "idle";
        badge.className = "badge " + statusBadgeClass(row.run_status);
      }
    }
  } catch (_e) { /* keep UI */ }
}

function startScanBoardTimer() {
  clearInterval(SCAN.boardTimer);
  SCAN.boardTimer = setInterval(() => {
    if ($("#panel-run").classList.contains("hidden")) return;
    refreshScanBadges();
  }, 4000);
}

async function requestScanStop(target) {
  if (!target) {
    toast("Type a domain on the SCAN page first", true);
    return;
  }
  if (!window.confirm("Stop the current check for " + target + "?")) return;
  try {
    const r = await api("POST", "/api/run/stop", { target });
    const note = (r.stdout || r.stderr || ("exit=" + r.exit)).toString().trim();
    toast("stopped " + target + (note ? " -- " + note.split("\n").slice(-1)[0] : ""));
    stopTargetStream(target);
    if ($("#run-target")) $("#run-target").value = target;
    rememberTarget(target);
    await loadRun();
  } catch (e) {
    toast(e.message, true);
  }
}

async function addScanTarget(startAfter) {
  const target = requireScanTarget();
  if (!target) return "";
  const authorize = $("#run-authorize") ? $("#run-authorize").checked : true;
  try {
    await api("POST", "/api/scan/targets", { target, authorize });
  } catch (e) {
    try {
      await api("PUT", "/api/targets/" + encodeURIComponent(target), { description: "added from SCAN" });
    } catch (_e) { throw e; }
  }
  rememberTarget(target);
  SCAN.expanded.add(target);
  await refreshKnownTargets();
  seedPanelTargets([target]);
  if (startAfter) {
    const r = await api("POST", "/api/run/start", { target, authorize });
    toast("scan started for " + target + " (pid=" + r.pid + ")");
  } else {
    toast("target added: " + target + " (isolated workspace)");
  }
  await loadRun();
  startScanBoardTimer();
  return target;
}

const MODULE_LABELS = {
  "passive-recon": "Passive discovery",
  "resolver-forge": "DNS resolve",
  "dnsx-probe": "DNS probe",
  "dnsx": "DNS brute",
  "ffuf": "HTTP brute",
  "ffuf-vhost": "Virtual hosts",
  "httpx": "HTTP probe",
  "naabu": "Port scan",
  "nmap-sv": "Service fingerprint",
  "crtsh": "Certificate logs",
  "subfinder": "Subfinder",
  "amass": "Amass",
  "assetfinder": "Assetfinder",
  "assetfinder-related": "Related names",
  "findomain": "Findomain",
  "waybackurls": "Web archive",
  "gau": "Archive URLs",
  "chaos": "Chaos dataset",
  "curl-fetch": "Web fetch",
  "breaker": "Safety limiter",
  "passive": "Passive branch",
  "active": "Active branch",
};

function stripAnsi(s) {
  return String(s || "").replace(/\u001b\[[0-9;]*[A-Za-z]/g, "");
}

function clockFromIso(iso) {
  const m = String(iso || "").match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : "";
}

function moduleLabel(name) {
  const key = String(name || "").trim();
  if (!key || key === "-") return "Check";
  return MODULE_LABELS[key] || key.replace(/-/g, " ");
}

function isBannerNoise(text) {
  const t = String(text || "");
  if (/projectdiscovery\.io/i.test(t)) return true;
  if (/Current dnsx version/i.test(t)) return true;
  const symbols = (t.match(/[_\\|\/`]/g) || []).length;
  return t.length > 40 && symbols / t.length > 0.18;
}

function lastFfufProgress(text) {
  const matches = [...String(text).matchAll(/Progress:\s*\[(\d+)\/(\d+)\].*?(\d+)\s*req\/sec.*?Duration:\s*\[([^\]]+)\].*?Errors:\s*(\d+)/g)];
  if (!matches.length) return "";
  const m = matches[matches.length - 1];
  return `Brute progress ${m[1]} of ${m[2]} (${m[3]}/sec, ${m[4]}, ${m[5]} errors)`;
}

function cmdHint(cmd) {
  const c = String(cmd || "").trim();
  if (!c) return "";
  const short = c.length > 90 ? c.slice(0, 87) + "..." : c;
  const resolver = c.match(/\s-r\s+(\S+)/);
  if (resolver) return "resolver " + resolver[1];
  return short;
}

function friendlyMessage(ev) {
  let detail = ev.detail;
  const cmd = ev.cmd;
  if (ev.status === "throttle") {
    return "Slowing this tool down -- too many errors in a short window.";
  }
  if (ev.status === "pause") {
    return "Paused this tool -- error rate crossed the safety limit.";
  }
  if (/circuit breaker paused/i.test(detail)) {
    return "This step was paused by the safety limiter after repeated errors.";
  }
  const skip = detail.match(/^skip:\s*(.*)/i);
  if (skip) return "Skipped: " + skip[1];
  if (/pull access denied|Unable to find image/i.test(detail)) {
    return "Could not start the scanner container (image missing or not allowed).";
  }
  if (/no URL specified/i.test(detail)) {
    return "Fetch skipped -- no URL (search engine not configured).";
  }
  const psv = detail.match(/^psv-(\w+):\s*(.*)/i);
  if (psv) {
    const body = psv[2]
      .replace(/\bkept=(\d+)/g, "kept $1 names")
      .replace(/\bhosts=(\d+)/g, "$1 hosts")
      .replace(/\btagged=(\d+)/g, "$1 tagged")
      .replace(/\bstatus=(\d+)/g, "HTTP $1")
      .replace(/\bvia=/g, "via ")
      .replace(/\bsource=/g, "source ")
      .replace(/degraded-continue after section 4\.3 retries/g, "failed after retries, continuing")
      .replace(/disclosed, never silent/g, "shown on purpose")
      .replace(/no key in \.env/g, "no API key");
    return body;
  }
  if (/^search-forge:/i.test(detail)) {
    return detail
      .replace(/^search-forge:\s*/i, "")
      .replace(/engine=/g, "")
      .replace(/disabled -- no key in \.env \(([^)]+)\)/g, "off (no $1 key)")
      .replace(/disclosed, never silent/g, "")
      .replace(/error-ratio .* -> ISOLATED/g, "isolated after too many errors")
      .replace(/\s+/g, " ")
      .trim();
  }
  const progress = lastFfufProgress(detail);
  if (progress) return progress;
  if (/Maximum running time for this job reached/i.test(detail)) {
    return "Stopped this job because the time budget ran out; moving on.";
  }
  if (isBannerNoise(detail)) {
    const hint = cmdHint(cmd);
    return hint ? "Finished a DNS probe (" + hint + ")." : "Finished a DNS probe.";
  }
  detail = detail.replace(/\s+/g, " ").trim();
  if (!detail) {
    if (ev.status === "ok" || ev.status === "0") {
      const hint = cmdHint(cmd);
      return hint ? "Completed. Command: " + hint : "Completed successfully.";
    }
    if (ev.status === "fail") {
      return "Failed (exit " + (ev.code || "?") + ").";
    }
    return "Update from this step.";
  }
  if (detail.length > 280) detail = detail.slice(0, 277) + "...";
  return detail;
}

function parseLogLine(line) {
  const raw = stripAnsi(line).replace(/\r/g, "");
  if (!raw.trim()) return null;
  if (/^=====/.test(raw)) {
    return { kind: "marker", status: "info", time: "", module: "", text: raw.replace(/=+/g, " ").trim() };
  }
  const parts = raw.split("\t");
  if (parts.length >= 5 && /^\d{4}-\d{2}-\d{2}T/.test(parts[0])) {
    const time = parts[0];
    const module = parts[1];
    const tool = parts[2];
    const code = parts[3];
    const status = String(parts[4] || "").toLowerCase();
    let rest = parts.slice(5).join(" ").trim();
    let cmd = "";
    const cmdAt = rest.lastIndexOf("cmd=");
    if (cmdAt >= 0) {
      cmd = rest.slice(cmdAt + 4).trim();
      rest = rest.slice(0, cmdAt).trim();
    }
    const ev = { kind: "event", time, module, tool, code, status, detail: rest, cmd };
    ev.text = friendlyMessage(ev);
    ev.tone = (status === "fail" || status === "pause") ? "fail"
      : (status === "throttle" || /skip/i.test(ev.text)) ? "warn"
      : (status === "ok") ? "ok" : "info";
    ev.groupKey = [ev.tone, module, tool, ev.text].join("|");
    return ev;
  }
  return { kind: "plain", status: "info", tone: "info", time: "", module: "", text: raw, groupKey: "plain|" + raw };
}

function appendPrettyLogs(lines, box, state) {
  box = box || $("#live-log-pretty");
  if (!box) return;
  state = state || window.__scanPretty || (window.__scanPretty = { prettyKey: "" });
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 48;
  for (const line of lines) {
    const ev = parseLogLine(line);
    if (!ev) continue;
    if (ev.kind === "event" && ev.groupKey === state.prettyKey && box.lastElementChild) {
      const last = box.lastElementChild;
      const badge = last.querySelector(".log-count");
      const n = badge ? parseInt(badge.getAttribute("data-n"), 10) + 1 : 2;
      if (badge) {
        badge.textContent = "x" + n;
        badge.setAttribute("data-n", String(n));
      } else {
        const span = document.createElement("span");
        span.className = "log-count";
        span.setAttribute("data-n", String(n));
        span.textContent = "x" + n;
        const msg = last.querySelector(".log-msg");
        if (msg) msg.appendChild(span);
      }
      continue;
    }
    state.prettyKey = ev.kind === "event" ? ev.groupKey : "";
    const row = document.createElement("div");
    row.className = "log-row " + (ev.kind === "marker" ? "marker" : (ev.tone || ev.status || "info"));
    if (ev.kind === "marker") {
      row.textContent = ev.text;
    } else {
      row.innerHTML = `<span class="log-time">${esc(clockFromIso(ev.time) || "--:--:--")}</span>` +
        `<span class="log-pill" title="${esc(ev.module || "")}">${esc(moduleLabel(ev.module))}</span>` +
        `<span class="log-msg">${esc(ev.text)}</span>`;
    }
    box.appendChild(row);
  }
  if (stick) box.scrollTop = box.scrollHeight;
}

function setCardLogMode(card, mode) {
  if (!card) return;
  const pretty = card.querySelector("[data-role=pretty]");
  const raw = card.querySelector("[data-role=raw]");
  const readable = mode !== "raw";
  if (pretty) pretty.classList.toggle("hidden", !readable);
  if (raw) raw.classList.toggle("hidden", readable);
  card.querySelectorAll("[data-logmode]").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-logmode") === (readable ? "pretty" : "raw"));
  });
  try { localStorage.setItem("recon_log_mode", readable ? "pretty" : "raw"); } catch (_e) { /* ignore */ }
}

function setLogMode(mode) {
  const pretty = $("#live-log-pretty");
  const raw = $("#live-log");
  const prettyBtn = $("#log-mode-pretty");
  const rawBtn = $("#log-mode-raw");
  const readable = mode !== "raw";
  if (pretty) pretty.classList.toggle("hidden", !readable);
  if (raw) raw.classList.toggle("hidden", readable);
  if (prettyBtn) prettyBtn.classList.toggle("active", readable);
  if (rawBtn) rawBtn.classList.toggle("active", !readable);
  try { localStorage.setItem("recon_log_mode", readable ? "pretty" : "raw"); } catch (_e) { /* ignore */ }
}

function wireLogMode() {
  const prettyBtn = $("#log-mode-pretty");
  const rawBtn = $("#log-mode-raw");
  if (!prettyBtn || prettyBtn.dataset.wired) return;
  prettyBtn.dataset.wired = "1";
  prettyBtn.addEventListener("click", () => setLogMode("pretty"));
  if (rawBtn) rawBtn.addEventListener("click", () => setLogMode("raw"));
  let saved = "pretty";
  try { saved = localStorage.getItem("recon_log_mode") || "pretty"; } catch (_e) { /* ignore */ }
  setLogMode(saved);
}

wireLogMode();

function startJournalStream() {
  clearInterval(window.__journalTimer);
  let joffset = 0;
  const pre = $("#agent-journal");
  if (!pre) return;
  pre.textContent = "";
  window.__journalTimer = setInterval(async () => {
    if (!$("#panel-run") || $("#panel-run").classList.contains("hidden")) return;
    const target = (CURRENT.target || panelTarget("run-target") || "").trim();
    if (!target) return;
    try {
      const doc = await api("GET", `/api/run/agent-journal/${encodeURIComponent(target)}?offset=${joffset}`);
      if (!doc.exists) return;
      if (doc.rows && doc.rows.length) {
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
  const classes = ["hosts", "ports", "vhosts", "services", "passive_ips"];
  const clsOpts = classes.map((c) => `<option ${rule.class === c ? "selected" : ""}>${c}</option>`).join("");
  div.className = "rule-row mono";
  div.innerHTML = `{"class": <select data-rk="class">${clsOpts}</select>,` +
    `"enabled": <select data-rk="enabled"><option value="true" ${rule.enabled !== false ? "selected" : ""}>true</option><option value="false" ${rule.enabled === false ? "selected" : ""}>false</option></select>,` +
    `"require_new_ip": <select data-rk="require_new_ip"><option value="false" ${!rule.require_new_ip ? "selected" : ""}>false</option><option value="true" ${rule.require_new_ip ? "selected" : ""}>true</option></select>}` +
    `<button class="danger" data-del-rule>DEL</button>`;
  return div;
}

async function loadSettings() {
  const s = await api("GET", "/api/settings");
  $("#s-proxy").value = s.proxy_url || "";
  $("#s-proxy-pool").value = s.proxy_pool || "";
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
  for (const rule of s.alert_rules || [
    { class: "hosts", enabled: true },
    { class: "ports", enabled: true },
    { class: "vhosts", enabled: true },
    { class: "services", enabled: true },
    { class: "passive_ips", enabled: true },
  ]) {
    editor.appendChild(ruleRow(rule));
  }
  editor.onclick = (ev) => { if (ev.target.closest("[data-del-rule]")) ev.target.closest(".rule-row").remove(); };
}

async function saveSettings() {
  const patch = {
    proxy_url: $("#s-proxy").value.trim(),
    proxy_pool: $("#s-proxy-pool").value.trim(),
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

/* ---------------- per-feature help chips (user-friendly UI law) ----------
   Every '?' chip explains, in one sentence, what the feature next to it does.
   Hover shows the tooltip; click/tap pins it (touch screens). */
document.addEventListener("click", (ev) => {
  const chip = ev.target.closest(".help");
  document.querySelectorAll(".help.open").forEach((el) => { if (el !== chip) el.classList.remove("open"); });
  if (chip) chip.classList.toggle("open");
});

closeHelpOnEscape();
function closeHelpOnEscape() {
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") document.querySelectorAll(".help.open").forEach((el) => el.classList.remove("open")); });
}

/* ---------------- wiring ---------------- */
$("#token").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") { ev.preventDefault(); $("#token-save").click(); }
});
$("#token-save").addEventListener("click", async () => {
  TOKEN = $("#token").value.trim();
  writeToken(TOKEN);
  await health();
  if (TOKEN) {
    const names = await refreshKnownTargets();
    seedPanelTargets(names);
  }
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
async function startScan() {
  try { await addScanTarget(true); }
  catch (e) { toast(e.message, true); }
}
$("#run-start").addEventListener("click", startScan);
$("#run-target").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") { ev.preventDefault(); startScan(); }
});
const scanAddBtn = $("#scan-add");
if (scanAddBtn) scanAddBtn.addEventListener("click", () => addScanTarget(false).catch((e) => toast(e.message, true)));
const scanBoard = $("#scan-board");
if (scanBoard) {
  scanBoard.addEventListener("click", async (ev) => {
    const expand = ev.target.closest("[data-expand]");
    const start = ev.target.closest("[data-scan-start]");
    const resume = ev.target.closest("[data-scan-resume]");
    const stop = ev.target.closest("[data-scan-stop]");
    const jump = ev.target.closest("[data-jump]");
    const mode = ev.target.closest("[data-logmode]");
    const card = ev.target.closest(".scan-card");
    if (mode && card) {
      ev.preventDefault();
      setCardLogMode(card, mode.getAttribute("data-logmode"));
      return;
    }
    if (expand) {
      ev.preventDefault();
      ev.stopPropagation();
      const t = expand.getAttribute("data-expand");
      setScanExpanded(t, !SCAN.expanded.has(t));
      if ($("#run-target")) $("#run-target").value = t;
      rememberTarget(t);
      return;
    }
    if (start) {
      const t = start.getAttribute("data-scan-start");
      $("#run-target").value = t;
      rememberTarget(t);
      SCAN.expanded.add(t);
      try { await addScanTarget(true); } catch (e) { toast(e.message, true); }
      return;
    }
    if (resume) {
      const t = resume.getAttribute("data-scan-resume");
      try {
        const r = await api("POST", "/api/run/resume", { target: t });
        toast("resumed " + t + " pid=" + r.pid);
        setScanExpanded(t, true);
      } catch (e) { toast(e.message, true); }
      return;
    }
    if (stop) {
      const t = stop.getAttribute("data-scan-stop");
      await requestScanStop(t);
      return;
    }
    if (jump) {
      const t = jump.getAttribute("data-jt");
      const panel = jump.getAttribute("data-jump");
      rememberTarget(t);
      if (panel === "results" && $("#results-target")) $("#results-target").value = t;
      if (panel === "reports" && $("#rep-target")) $("#rep-target").value = t;
      if (panel === "targets" && $("#t-name")) $("#t-name").value = t;
      const tab = document.querySelector('.tab[data-panel="' + panel + '"]');
      if (tab) tab.click();
      return;
    }
    if (card && ev.target.closest(".scan-head") && !ev.target.closest(".scan-head-actions") && !ev.target.closest("button")) {
      const t = card.dataset.scan;
      setScanExpanded(t, !SCAN.expanded.has(t));
    }
  });
}
const runResume = $("#run-resume");
if (runResume) runResume.addEventListener("click", async () => {
  const target = requireScanTarget();
  if (!target) return;
  try { const r = await api("POST", "/api/run/resume", { target }); toast("resumed " + target + " pid=" + r.pid); }
  catch (e) { toast(e.message, true); }
});
const runStopEl = $("#run-stop");
if (runStopEl) runStopEl.addEventListener("click", async () => {
  await requestScanStop(requireScanTarget());
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
$("#s-test").addEventListener("click", async () => {
  const badge = $("#s-test-result");
  const hintLine = $("#s-test-hint");
  try {
    const r = await api("POST", "/api/notify/test", {});
    badge.textContent = r.sent ? "TEST SENT" : "SKIPPED: " + r.reason;
    badge.className = "badge " + (r.sent ? "ok" : "new");
    hintLine.textContent = r.sent
      ? (r.reason ? "Delivered: " + r.reason : "Message delivered -- check your Telegram.")
      : (r.hint || "");
    hintLine.className = "hint-line" + (r.sent ? " ok" : " warn");
  } catch (e) {
    badge.textContent = "ERROR: " + e.message;
    badge.className = "badge alert";
    hintLine.textContent = "";
  }
});
$("#t-load").addEventListener("click", loadTargetProfile);
$("#t-save").addEventListener("click", saveTargetProfile);
$("#t-clear").addEventListener("click", deleteTargetProfile);
$("#fl-run").addEventListener("click", async () => {
  try {
    const body = { members: $("#fl-members").value.trim() || "all" };
    const conc = $("#fl-conc").value.trim();
    if (conc) body.concurrency = parseInt(conc, 10);
    const r = await api("POST", "/api/fleet/run", body);
    toast("fleet started pid=" + r.pid + " members=" + r.members);
    loadFleet();
  } catch (e) { toast(e.message, true); }
});
$("#fl-refresh").addEventListener("click", loadFleet);
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
$("#results-load").addEventListener("click", () => loadResults());
$("#diff-compare").addEventListener("click", () => compareWarehouseRuns().catch((e) => toast(e.message, true)));
$("#wh-rebuild").addEventListener("click", () => rebuildWarehouse().catch((e) => toast(e.message, true)));
$("#results-target").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") { ev.preventDefault(); loadResults(); }
});

async function health() {
  const el = $("#conn");
  try {
    const r = await fetch("/api/health");
    const doc = await r.json();
    if (!doc.ok) { el.textContent = "?"; el.className = "badge dead"; return; }
    el.textContent = "online";
    el.className = "badge ok";
    if (!TOKEN) return;
    try {
      await api("GET", "/api/tools");
      el.textContent = "online";
      el.className = "badge ok";
    } catch (_authErr) {
      el.textContent = "online (token rejected)";
      el.className = "badge alert";
    }
  } catch (_e) { el.textContent = "offline"; el.className = "badge alert"; }
}

function loadPanel(name) {
  syncTokenFromBox();
  if (!TOKEN) {
    if (name !== "help" && name !== "run") toast("set DASHBOARD_TOKEN first (top right)");
    if (name === "engine") {
      const tbody = $("#tools-table tbody");
      if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="dim">paste DASHBOARD_TOKEN and press SET</td></tr>';
    }
    if (name === "tools") {
      const root = $("#wordlists");
      if (root) root.innerHTML = '<p class="dim">paste DASHBOARD_TOKEN and press SET</p>';
    }
    return;
  }
  if (name === "engine") loadTools();
  if (name === "tools") loadWordlists();
  if (name === "targets") { loadTargetsTable(); }
  if (name === "fleet") loadFleet();
  if (name === "results") loadResults();
  if (name === "reports") loadReports();
  if (name === "run") { loadRun(); startLogStream(); startJournalStream(); startScanBoardTimer(); }
  if (name === "keys") loadKeys();
  if (name === "settings") loadSettings();
  if (name === "help") { /* static guide -- nothing to fetch */ }
}

(async function init() {
  $("#token").value = TOKEN;
  await health();
  if (TOKEN) {
    const names = await refreshKnownTargets();
    seedPanelTargets(names);
  }
  const panel = restoreFiltersFromURL() || localStorage.getItem("recon_last_panel") || "run";
  const tab = document.querySelector(`.tab[data-panel="${panel}"]`) || document.querySelector(".tab");
  tab.click();
})();
