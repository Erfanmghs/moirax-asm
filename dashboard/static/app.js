/* moirax-ASM SPA -- panels a-e (section 9.2), URL-shareable global filters (section 9.2-b),
   sortable tables + badges + collapsible JSON inspector (section 9.4). Zero-build
   vanilla JS; the API contract (section 9.1) is the stable surface. */
"use strict";

const $ = (sel) => document.querySelector(sel);

function elVal(sel) {
  const el = $(sel);
  return (el && el.value != null) ? String(el.value) : "";
}

function setVal(sel, value) {
  const el = $(sel);
  if (!el) return;
  el.value = value == null ? "" : String(value);
}

function bind(sel, type, handler, opts) {
  const el = $(sel);
  if (!el) return;
  el.addEventListener(type, handler, opts);
}

function nudgeNumber(input, dir) {
  const step = Number(input.step) > 0 ? Number(input.step) : 1;
  const hasMin = input.min !== "";
  const hasMax = input.max !== "";
  const min = hasMin ? Number(input.min) : null;
  const max = hasMax ? Number(input.max) : null;
  const raw = String(input.value || "").trim();
  let n = raw === "" ? NaN : Number(raw);
  if (!Number.isFinite(n)) {
    if (dir < 0) return;
    n = min != null && Number.isFinite(min) ? min : 0;
  } else {
    n = n + dir * step;
  }
  if (min != null && Number.isFinite(min) && n < min) n = min;
  if (max != null && Number.isFinite(max) && n > max) n = max;
  input.value = String(n);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function bindNumHold(btn, fn) {
  let timer = 0;
  let delay = 0;
  let held = false;
  const stop = () => {
    if (delay) window.clearTimeout(delay);
    if (timer) window.clearInterval(timer);
    delay = 0;
    timer = 0;
  };
  btn.addEventListener("pointerdown", (ev) => {
    if (ev.pointerType === "mouse" && ev.button !== 0) return;
    held = false;
    stop();
    delay = window.setTimeout(() => {
      held = true;
      fn();
      timer = window.setInterval(fn, 70);
    }, 380);
  });
  btn.addEventListener("pointerup", stop);
  btn.addEventListener("pointerleave", stop);
  btn.addEventListener("pointercancel", stop);
  btn.addEventListener("blur", stop);
  btn.addEventListener("click", (ev) => {
    ev.preventDefault();
    if (held) {
      held = false;
      return;
    }
    fn();
  });
}

function enhanceNumberInputs(root) {
  const scope = root || document;
  scope.querySelectorAll("input[type=number]").forEach((el) => {
    const existing = el.closest(".num-wrap");
    if (existing) {
      if (existing.dataset.numBound) return;
      const btns = existing.querySelectorAll(".num-btn");
      if (btns.length >= 2) {
        bindNumHold(btns[0], () => nudgeNumber(el, -1));
        bindNumHold(btns[btns.length - 1], () => nudgeNumber(el, 1));
        existing.dataset.numBound = "1";
      }
      return;
    }
    const wrap = document.createElement("div");
    wrap.className = "num-wrap";
    if (el.classList.contains("w110")) {
      wrap.classList.add("w110");
      el.classList.remove("w110");
    }
    const minus = document.createElement("button");
    minus.type = "button";
    minus.className = "num-btn";
    minus.textContent = "-";
    minus.setAttribute("aria-label", "decrease");
    minus.tabIndex = -1;
    const plus = document.createElement("button");
    plus.type = "button";
    plus.className = "num-btn";
    plus.textContent = "+";
    plus.setAttribute("aria-label", "increase");
    plus.tabIndex = -1;
    el.parentNode.insertBefore(wrap, el);
    wrap.appendChild(minus);
    wrap.appendChild(el);
    wrap.appendChild(plus);
    bindNumHold(minus, () => nudgeNumber(el, -1));
    bindNumHold(plus, () => nudgeNumber(el, 1));
    wrap.dataset.numBound = "1";
  });
}
const IDLE_MS = 15 * 60 * 1000;

let AUTHED = false;
let LAST_CLICK = 0;
let TOUCH_AT = 0;
let CURRENT = { target: localStorage.getItem("recon_last_target") || "", assets: [], sort: { key: null, dir: 1 } };
let RESULTS_LIVE_TIMER = null;
let RESULTS_INFLIGHT = false;
let RESULTS_LAST_AT = 0;
const TASK_LABELS = {
  "FFUF-0": "Optional HTTP brute (ffuf)",
  "DNSR-1": "DNS subdomain brute (dnsx)",
  "FFUF-2": "Virtual hosts (ffuf)",
};

function showAuthError(msg) {
  const el = $("#auth-error");
  if (!el) return;
  el.textContent = msg || "";
  el.classList.toggle("hidden", !msg);
}

function setGate(mode, message) {
  const gate = $("#auth-gate");
  const title = $("#auth-title");
  const lead = $("#auth-lead");
  const confirmWrap = $("#auth-confirm-wrap");
  const submit = $("#auth-submit");
  const pw = $("#auth-password");
  const confirm = $("#auth-confirm");
  if (!gate || !title) return;
  if (!mode) {
    gate.hidden = true;
    gate.dataset.mode = "";
    document.body.classList.remove("auth-blocked");
    showAuthError("");
    return;
  }
  gate.hidden = false;
  gate.dataset.mode = mode;
  document.body.classList.add("auth-blocked");
  AUTHED = false;
  if (pw) pw.value = "";
  if (confirm) confirm.value = "";
  if (mode === "setup") {
    title.textContent = "Set operator password";
    lead.textContent = "";
    lead.classList.add("hidden");
    if (confirmWrap) {
      confirmWrap.hidden = false;
      confirmWrap.classList.remove("hidden");
    }
    if (confirm) {
      confirm.required = true;
      confirm.disabled = false;
    }
    if (pw) pw.autocomplete = "new-password";
    submit.textContent = "Register";
  } else {
    title.textContent = "Sign in";
    lead.textContent = message || "Enter your operator password.";
    lead.classList.toggle("hidden", !lead.textContent);
    // Login: one password field only -- Confirm is first-run setup only.
    if (confirmWrap) {
      confirmWrap.hidden = true;
      confirmWrap.classList.add("hidden");
    }
    if (confirm) {
      confirm.required = false;
      confirm.disabled = true;
      confirm.value = "";
    }
    if (pw) pw.autocomplete = "current-password";
    submit.textContent = "Sign in";
  }
  showAuthError("");
  setTimeout(() => { if (pw) pw.focus(); }, 30);
}

async function authStatus() {
  const res = await fetch("/api/auth/status", { credentials: "same-origin" });
  return res.json().catch(() => ({ ok: false }));
}

async function lockSession(message) {
  stopBackgroundPolls();
  try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }); } catch (_e) { /* ignore */ }
  AUTHED = false;
  setGate("login", message || "Session locked. Sign in again.");
}

async function afterSignedIn() {
  AUTHED = true;
  LAST_CLICK = Date.now();
  setGate(null);
  await health();
  try {
    const names = await refreshKnownTargets();
    seedPanelTargets(names);
  } catch (_e) { /* ignore */ }
  const tab = document.querySelector(".tab.active") || document.querySelector(".tab");
  if (tab) loadPanel(tab.dataset.panel);
}

function recordClick() {
  LAST_CLICK = Date.now();
  if (!AUTHED) return;
  if (Date.now() - TOUCH_AT < 2000) return;
  TOUCH_AT = Date.now();
  fetch("/api/auth/touch", { method: "POST", credentials: "same-origin" }).then((res) => {
    if (res.status === 401) lockSession("Idle timeout (15 minutes). Sign in again.");
  }).catch(() => {});
}

function stopBackgroundPolls() {
  clearInterval(window.__logTimer);
  window.__logTimer = null;
  clearInterval(window.__journalTimer);
  window.__journalTimer = null;
  if (typeof SCAN !== "undefined") {
    clearInterval(SCAN.boardTimer);
    SCAN.boardTimer = null;
    Object.values(SCAN.streams || {}).forEach((s) => {
      if (!s) return;
      clearInterval(s.logTimer);
      clearInterval(s.journalTimer);
      s.logTimer = null;
      s.journalTimer = null;
    });
  }
}

function syncTokenFromBox() {
  return AUTHED;
}

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    await lockSession("Session expired. Sign in again.");
    throw new Error("401");
  }
  if (res.status === 503) {
    setGate("setup");
    toast("set an operator password to continue", true);
    throw new Error("503");
  }
  const doc = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(apiDetail(doc, res));
  return doc;
}

async function exportRunArtifact(kind, target) {
  const t = (target || currentTarget() || "").trim();
  if (!t) {
    toast("pick a site first", true);
    return;
  }
  const path = kind === "journal"
    ? `/api/run/agent-journal/${encodeURIComponent(t)}/export`
    : `/api/run/log/${encodeURIComponent(t)}/export`;
  try {
    const res = await fetch(path, { method: "GET", credentials: "same-origin" });
    if (res.status === 401) {
      await lockSession("Session expired. Sign in again.");
      return;
    }
    if (res.status === 503) {
      setGate("setup");
      toast("set an operator password to continue", true);
      return;
    }
    if (!res.ok) {
      const doc = await res.json().catch(() => ({}));
      throw new Error(typeof doc.detail === "string" ? doc.detail : (res.statusText || String(res.status)));
    }
    const blob = await res.blob();
    const cd = res.headers.get("Content-Disposition") || "";
    const match = /filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i.exec(cd);
    let name = (match && (match[1] || match[2])) || "";
    try { name = decodeURIComponent(name); } catch (_e) { /* keep raw */ }
    if (!name) name = kind === "journal" ? `${t}-agent-journal.jsonl` : `${t}-run.log`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast("exported " + name);
  } catch (e) {
    toast(e.message || "export failed", true);
  }
}

function toast(msg, err) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = msg;
  el.className = "toast" + (err ? " err" : "");
  el.classList.remove("hidden");
  if (window.asmMotion) window.asmMotion.bump(el);
  setTimeout(() => el.classList.add("hidden"), 3500);
}

function apiDetail(doc, res) {
  const d = doc && doc.detail;
  if (typeof d === "string" && d) return d;
  if (Array.isArray(d) && d.length) {
    return d.map((row) => (row && (row.msg || row.detail)) || JSON.stringify(row)).join("; ");
  }
  return (res && (res.statusText || String(res.status))) || "request failed";
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
    const names = uniqueNames([...(doc.known || []), ...Object.keys(doc.targets || {})]).sort();
    list.innerHTML = names.map((n) => `<option value="${esc(n)}"></option>`).join("");
    return names;
  } catch (_e) {
    return [];
  }
}

function preferredScanSite(names) {
  const list = uniqueNames(names || []);
  const fromScan = panelTarget("run-target");
  if (fromScan && list.includes(fromScan)) return fromScan;
  const last = (CURRENT.target || "").trim();
  if (last && list.includes(last)) return last;
  if (list.length === 1) return list[0];
  return "";
}

function fillSiteSelect(el, names, preferred) {
  if (!el || el.tagName !== "SELECT") return;
  const keep = el.value.trim();
  const list = uniqueNames(names);
  const want = (keep && list.includes(keep)) ? keep : (preferred || "");
  el.innerHTML = ['<option value="">Choose a site from SCAN...</option>']
    .concat(list.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`))
    .join("");
  el.value = (want && list.includes(want)) ? want : "";
}

function syncSiteSelects(names) {
  const list = uniqueNames(names);
  const pref = preferredScanSite(list);
  fillSiteSelect($("#results-target"), list, pref);
  fillSiteSelect($("#rep-target"), list, pref);
}

async function refreshSiteSelects() {
  let names = [];
  try {
    const doc = await api("GET", "/api/scan/board");
    names = uniqueNames((doc.targets || []).map((r) => r.target));
  } catch (_e) {
    names = await refreshKnownTargets();
  }
  syncSiteSelects(names);
  return names;
}

function seedPanelTargets(names) {
  const last = (CURRENT.target || "").trim();
  const known = uniqueNames(names || []);
  const el = document.getElementById("run-target");
  if (el && !el.value.trim()) {
    if (last && known.includes(last)) el.value = last;
    else if (known[0]) el.value = known[0];
  }
  const shown = panelTarget("run-target");
  if (shown) rememberTarget(shown);
  syncSiteSelects(names);
}

/* ---------------- panel switching ---------------- */
bind("#tabs", "click", (ev) => {
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
  if (panel) {
    panel.classList.remove("hidden");
    if (window.asmMotion) window.asmMotion.enterPanel(panel);
  }
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
  WL_CATALOG = doc;
  root.innerHTML = "";
  const lists = doc.lists || {};
  for (const [task, spec] of Object.entries(doc.tasks || {})) {
    const selected = new Set(spec.selection || spec.default_selection || []);
    const box = document.createElement("div");
    box.className = "table-wrap";
    box.style.marginBottom = "14px";
    const rows = [];
    const sorted = wlTaskKeys(doc, task, selected);
    for (const key of sorted) {
      const meta = lists[key] || {};
      const fname = wlFileName(lists, key);
      rows.push(`<tr data-wl="${esc(key)}"><td><input type="checkbox" data-key="${esc(key)}" ${wlPathSelected(lists, selected, key) ? "checked" : ""}></td>` +
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
      const boxes = uniqueWlKeysByPath(lists, [...table.querySelectorAll("input[type=checkbox][data-key]:checked")].map((cb) => cb.dataset.key), task);
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
const SCAN_ACTIVE_MODULES = ["dns-resolve", "ffuf", "ffuf-3", "port-check"];
const SCAN_PASSIVE_MODULES = ["passive-recon"];
const SCAN_WL_TASKS = ["DNSR-1", "FFUF-2", "FFUF-0"];
const SCAN_MODULE_HELP = {
  "dns-resolve": "DNS brute + IP resolve (dnsx). Depth 1 = names under the apex. Depth 2+ also brutes under those names. New unique IPs are port-scanned later.",
  "ffuf": "Virtual hosts. Sends Host-header guesses to IPs you already found. Nested Host headers follow RECON DEPTH.",
  "ffuf-3": "Dead-name virtual hosts. Tries names that did not resolve in DNS, against known IPs.",
  "port-check": "Quick common-port look that starts as soon as DNS IPs exist (runs beside vhost). The main port scan after MERGE follows PORT SCAN MODE: full (nmap -p-), top ports, or custom nmap -p list.",
  "passive-recon": "Public/OSINT lookup (certificate logs, search, archives). Does not send scan packets to the site.",
};
const SCAN_WL_HELP = {
  "DNSR-1": "Names fed to dns-resolve (dnsx). Tick the filename you want this site to brute.",
  "FFUF-2": "Host-header guesses for virtual-host probes (ffuf / ffuf-3).",
  "FFUF-0": "Optional HTTP path/label brute. Leave inherited unless you turned that technique on.",
};
let WL_CATALOG = null;

function profileSettings(profile) {
  const p = profile || {};
  const inner = (p.settings && typeof p.settings === "object") ? p.settings : {};
  const pick = (key) => (inner[key] && typeof inner[key] === "object" ? inner[key] : (p[key] && typeof p[key] === "object" ? p[key] : {}));
  return {
    notifications: pick("notifications"),
    scheduler: pick("scheduler"),
    budgets: pick("budgets"),
    modules: pick("modules"),
    wordlist_selection: pick("wordlist_selection"),
    proxy: pick("proxy"),
    portsweep: pick("portsweep"),
  };
}

function buildTargetProfile(fields) {
  const profile = {};
  const desc = (fields.desc || "").trim();
  if (desc) profile.description = desc;
  const notif = {};
  const tg = (fields.tg || "").trim();
  const tgen = fields.tgen || "";
  const watch = fields.watch || "";
  const digest = (fields.digest || "").trim();
  if (tg) notif.telegram_chat = tg;
  if (tgen !== "") notif.telegram_enabled = tgen === "true";
  if (watch !== "") notif.watchtower_enabled = watch === "true";
  if (digest) notif.digest_threshold = parseInt(digest, 10);
  if (Object.keys(notif).length) profile.notifications = notif;
  const sched = {};
  const schedEn = fields.schedEn || "";
  const schedInt = (fields.schedInt || "").toString().trim();
  if (schedEn !== "") sched.enabled = schedEn === "true";
  if (schedInt !== "") sched.interval_minutes = parseInt(schedInt, 10);
  if (Object.keys(sched).length) profile.scheduler = sched;
  const tpool = (fields.proxy || "").trim();
  if (tpool) profile.proxy = { proxy_pool: tpool };
  const budgets = {};
  const budgetMap = [
    ["passive", "passive_branch_budget_sec"],
    ["active", "active_branch_budget_sec"],
    ["depth", "passive_recursion_depth"],
    ["recon", "recon_depth"],
    ["ffufDepth", "ffuf_depth"],
    ["dnsxParents", "dnsx_parallel_parents"],
    ["dead", "ffuf3_max_dead_probes"],
    ["ffuf4", "ffuf4_max_jobs"],
  ];
  for (const [key, name] of budgetMap) {
    const v = (fields[key] || "").toString().trim();
    if (v !== "") budgets[name] = parseInt(v, 10);
  }
  if (Object.keys(budgets).length) profile.budgets = budgets;
  const modules = {};
  const act = (fields.activeMods || "").trim();
  const pas = (fields.passiveMods || "").trim();
  if (act) modules.active_branch_modules = uniqueNames(act.split(","));
  if (pas) modules.passive_branch_modules = uniqueNames(pas.split(","));
  if (Object.keys(modules).length) profile.modules = modules;
  const wl = {};
  const lists = (WL_CATALOG && WL_CATALOG.lists) || {};
  for (const task of ["FFUF-0", "DNSR-1", "FFUF-2"]) {
    const v = (fields["wl-" + task] || "").trim();
    if (v) wl[task] = uniqueWlKeysByPath(lists, uniqueNames(v.split(",")), task, uniqueNames(v.split(",")));
  }
  if (Object.keys(wl).length) profile.wordlist_selection = wl;
  const ps = {};
  const psp = (fields.psProfile || "").trim().toLowerCase();
  if (psp) ps.profile = psp;
  const pspo = (fields.psPorts || "").trim();
  if (pspo !== "") ps.custom_ports = pspo;
  const psn = fields.psNmap || "";
  if (psn !== "") ps.nmap_sv = psn === "true";
  if (Object.keys(ps).length) profile.portsweep = ps;
  return profile;
}

function targetProfileFromUI() {
  return buildTargetProfile({
    desc: elVal("#t-desc"),
    tg: elVal("#t-tg"),
    tgen: elVal("#t-tgen"),
    watch: elVal("#t-watch"),
    digest: elVal("#t-digest"),
    schedEn: elVal("#t-sched-en"),
    schedInt: elVal("#t-sched-int"),
    proxy: elVal("#t-proxy"),
    passive: elVal("#t-b-passive"),
    active: elVal("#t-b-active"),
    depth: elVal("#t-b-depth"),
    recon: elVal("#t-b-recon"),
    ffufDepth: elVal("#t-b-ffuf-depth"),
    dnsxParents: elVal("#t-b-dnsx-parents"),
    dead: elVal("#t-b-dead"),
    ffuf4: elVal("#t-b-ffuf4"),
    psProfile: elVal("#t-ps-profile"),
    psPorts: elVal("#t-ps-ports"),
    psNmap: elVal("#t-ps-nmap"),
    activeMods: elVal("#t-m-active"),
    passiveMods: elVal("#t-m-passive"),
    "wl-FFUF-0": elVal("#t-wl-FFUF-0"),
    "wl-DNSR-1": elVal("#t-wl-DNSR-1"),
    "wl-FFUF-2": elVal("#t-wl-FFUF-2"),
  });
}

function pf(root, name) {
  return root.querySelector("[data-pf='" + name + "']");
}

function profileFromSetup(root) {
  const inherit = pf(root, "mod-inherit");
  let activeMods = "";
  let passiveMods = "";
  if (inherit && !inherit.checked) {
    activeMods = [...root.querySelectorAll("[data-mod][data-branch='active']:checked")].map((cb) => cb.getAttribute("data-mod")).join(",");
    passiveMods = [...root.querySelectorAll("[data-mod][data-branch='passive']:checked")].map((cb) => cb.getAttribute("data-mod")).join(",");
  }
  const wlInherit = pf(root, "wl-inherit");
  const wlFields = { "wl-FFUF-0": "", "wl-DNSR-1": "", "wl-FFUF-2": "" };
  if (wlInherit && !wlInherit.checked) {
    for (const task of SCAN_WL_TASKS) {
      wlFields["wl-" + task] = [...root.querySelectorAll('input[data-wl-task="' + task + '"]:checked')]
        .map((cb) => cb.getAttribute("data-wl-key")).filter(Boolean).join(",");
    }
  }
  const val = (name) => (pf(root, name) ? pf(root, name).value : "");
  return buildTargetProfile({
    desc: val("desc"),
    tg: val("tg"),
    tgen: val("tgen"),
    watch: val("watch"),
    digest: val("digest"),
    schedEn: val("sched-en"),
    schedInt: val("sched-int"),
    proxy: val("proxy"),
    passive: val("b-passive"),
    active: val("b-active"),
    depth: val("b-depth"),
    recon: val("b-recon"),
    ffufDepth: val("b-ffuf-depth"),
    dnsxParents: val("b-dnsx-parents"),
    dead: val("b-dead"),
    ffuf4: val("b-ffuf4"),
    psProfile: val("ps-profile"),
    psPorts: val("ps-ports"),
    psNmap: val("ps-nmap"),
    activeMods,
    passiveMods,
    "wl-FFUF-0": wlFields["wl-FFUF-0"],
    "wl-DNSR-1": wlFields["wl-DNSR-1"],
    "wl-FFUF-2": wlFields["wl-FFUF-2"],
  });
}

function setSetupModsEnabled(root, custom) {
  root.querySelectorAll("[data-mod]").forEach((cb) => { cb.disabled = !custom; });
  const picks = pf(root, "mod-picks");
  if (picks) picks.classList.toggle("is-inherit", !custom);
}

function setSetupWlEnabled(root, custom) {
  root.querySelectorAll("input[data-wl-task]").forEach((cb) => { cb.disabled = !custom; });
  const picks = pf(root, "wl-picks");
  if (picks) picks.classList.toggle("is-inherit", !custom);
}

async function ensureWlCatalog() {
  if (WL_CATALOG) return WL_CATALOG;
  WL_CATALOG = await api("GET", "/api/wordlists");
  return WL_CATALOG;
}

function wlFileName(lists, key) {
  const entry = (lists || {})[key] || {};
  return entry.name || (String(entry.path || "").split("/").pop()) || key;
}

function wlNormPath(lists, key) {
  const entry = (lists || {})[key] || {};
  const path = String(entry.path || "").replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase();
  return path || ("key:" + key);
}

function uniqueWlKeysByPath(lists, keys, task, selected) {
  const chosen = selected instanceof Set ? selected : new Set(selected || []);
  const rank = (key) => {
    const name = String(key || "");
    let family = 2;
    if (task === "FFUF-2") family = name.startsWith("vhost_") ? 0 : name.startsWith("dns_") ? 1 : name.startsWith("sl_") ? 3 : 2;
    else family = name.startsWith("dns_") ? 0 : name.startsWith("vhost_") ? 1 : name.startsWith("sl_") ? 3 : 2;
    return [chosen.has(name) ? 0 : 1, family, name];
  };
  const cmp = (a, b) => {
    for (let i = 0; i < a.length; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  };
  const picked = new Map();
  for (const key of keys || []) {
    if (!key) continue;
    const path = wlNormPath(lists, key);
    const prev = picked.get(path);
    if (!prev || cmp(rank(key), rank(prev)) < 0) picked.set(path, key);
  }
  return [...picked.values()].sort((a, b) => {
    const al = a === "platform_learned" ? 0 : 1;
    const bl = b === "platform_learned" ? 0 : 1;
    if (al !== bl) return al - bl;
    return wlFileName(lists, a).localeCompare(wlFileName(lists, b));
  });
}

function wlPathSelected(lists, selected, key) {
  const path = wlNormPath(lists, key);
  for (const other of selected || []) {
    if (other === key || wlNormPath(lists, other) === path) return true;
  }
  return false;
}

function uniqueNames(names) {
  const seen = new Set();
  const out = [];
  for (const name of names || []) {
    const n = String(name || "").trim();
    if (!n || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

function uniqueByTarget(rows) {
  const seen = new Set();
  const out = [];
  for (const row of rows || []) {
    const name = String((row && row.target) || "").trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    out.push(row);
  }
  return out;
}

function wlTaskKeys(doc, task, selected) {
  const lists = (doc && doc.lists) || {};
  const spec = ((doc && doc.tasks) || {})[task] || {};
  const keys = spec.allow_registry_wide
    ? Object.keys(lists)
    : [].concat(spec.fast || [], spec.expansion || [], spec.sources || [], spec.default_selection || [], spec.selection || []);
  const ticks = selected instanceof Set ? selected : new Set(selected || spec.selection || spec.default_selection || []);
  return uniqueWlKeysByPath(lists, keys, task, ticks);
}

function paintSetupWordlists(root, selectedMap) {
  const host = pf(root, "wl-picks");
  if (!host || !WL_CATALOG) return;
  const lists = WL_CATALOG.lists || {};
  const selected = selectedMap || {};
  const inherit = pf(root, "wl-inherit");
  const custom = inherit ? !inherit.checked : false;
  host.innerHTML = SCAN_WL_TASKS.map((task) => {
    const keys = wlTaskKeys(WL_CATALOG, task, selected[task] || ((WL_CATALOG.tasks || {})[task] || {}).selection);
    const picked = new Set(selected[task] || []);
    const globalSel = new Set((((WL_CATALOG.tasks || {})[task] || {}).selection) || []);
    const ticks = custom ? picked : (picked.size ? picked : globalSel);
    const rows = keys.map((key) => {
      const meta = lists[key] || {};
      const fname = wlFileName(lists, key);
      const on = wlPathSelected(lists, ticks, key) ? " checked" : "";
      return `<div class="setup-wl-row" data-wl-row="${esc(key)}">` +
        `<label class="check setup-wl-tick"><input type="checkbox" data-wl-task="${esc(task)}" data-wl-key="${esc(key)}"${on}${custom ? "" : " disabled"}>` +
        `<span class="setup-wl-name mono">${esc(fname)}</span></label>` +
        `<button type="button" class="setup-wl-sample-btn" data-wl-preview="${esc(key)}">show names</button>` +
        `<span class="dim setup-wl-path">${esc(meta.path || "")}</span>` +
        `</div>`;
    }).join("") || `<p class="dim">no lists registered for ${esc(task)}</p>`;
    return `<div class="setup-wl-task" data-wl-block="${esc(task)}">` +
      `<div class="setup-wl-task-head">` +
      `<span class="setup-mod-label">${esc(task)}</span>` +
      `<span class="setup-mod-what">${esc(SCAN_WL_HELP[task] || TASK_LABELS[task] || task)}</span>` +
      `</div>` +
      `<input class="mono setup-wl-filter" data-wl-filter="${esc(task)}" placeholder="filter by original filename">` +
      `<div class="setup-wl-rows">${rows}</div>` +
      `<pre class="setup-wl-sample dim" data-wl-sample="${esc(task)}">press SHOW NAMES to preview entries in that file</pre>` +
      `</div>`;
  }).join("");
  setSetupWlEnabled(root, custom);
}

async function refreshSetupWordlists(root, selectedMap) {
  try { await ensureWlCatalog(); } catch (_e) { return; }
  paintSetupWordlists(root, selectedMap);
}

function applyProfileToSetup(root, profile) {
  if (!root) return;
  const s = profileSettings(profile);
  const n = s.notifications || {};
  const setv = (name, value) => { const el = pf(root, name); if (el) el.value = value == null ? "" : String(value); };
  setv("desc", (profile && profile.description) || "");
  setv("tg", n.telegram_chat || "");
  setv("tgen", n.telegram_enabled === true ? "true" : n.telegram_enabled === false ? "false" : "");
  setv("proxy", (s.proxy || {}).proxy_pool || "");
  setv("watch", n.watchtower_enabled === true ? "true" : n.watchtower_enabled === false ? "false" : "");
  setv("digest", n.digest_threshold || "");
  const sch = s.scheduler || {};
  setv("sched-en", sch.enabled === true ? "true" : sch.enabled === false ? "false" : "");
  setv("sched-int", sch.interval_minutes || "");
  const b = s.budgets || {};
  setv("b-passive", b.passive_branch_budget_sec ?? "");
  setv("b-active", b.active_branch_budget_sec ?? "");
  setv("b-recon", b.recon_depth ?? "");
  setv("b-ffuf-depth", b.ffuf_depth ?? "");
  setv("b-dnsx-parents", b.dnsx_parallel_parents ?? "");
  setv("b-depth", b.passive_recursion_depth ?? "");
  setv("b-dead", b.ffuf3_max_dead_probes ?? "");
  setv("b-ffuf4", b.ffuf4_max_jobs ?? "");
  const ps = s.portsweep || {};
  setv("ps-profile", ps.profile || "");
  setv("ps-ports", ps.custom_ports || "");
  setv("ps-nmap", ps.nmap_sv === true ? "true" : ps.nmap_sv === false ? "false" : "");
  const wl = s.wordlist_selection || {};
  const hasWl = Object.keys(wl).some((task) => (wl[task] || []).length);
  const wlInherit = pf(root, "wl-inherit");
  if (wlInherit) wlInherit.checked = !hasWl;
  refreshSetupWordlists(root, wl);
  const m = s.modules || {};
  const hasMods = (m.active_branch_modules && m.active_branch_modules.length) || (m.passive_branch_modules && m.passive_branch_modules.length);
  const inherit = pf(root, "mod-inherit");
  if (inherit) inherit.checked = !hasMods;
  setSetupModsEnabled(root, !!hasMods);
  root.querySelectorAll("[data-mod]").forEach((cb) => {
    const list = cb.getAttribute("data-branch") === "passive" ? (m.passive_branch_modules || []) : (m.active_branch_modules || []);
    cb.checked = !!hasMods && list.indexOf(cb.getAttribute("data-mod")) >= 0;
  });
}

function scanSetupHtml(target) {
  const t = esc(target);
  const active = SCAN_ACTIVE_MODULES.map((m) =>
    `<label class="setup-mod-card"><input type="checkbox" data-mod="${esc(m)}" data-branch="active">` +
    `<span class="setup-mod-name">${esc(m)}</span>` +
    `<span class="setup-mod-what">${esc(SCAN_MODULE_HELP[m] || "")}</span></label>`).join("");
  const passive = SCAN_PASSIVE_MODULES.map((m) =>
    `<label class="setup-mod-card"><input type="checkbox" data-mod="${esc(m)}" data-branch="passive">` +
    `<span class="setup-mod-name">${esc(m)}</span>` +
    `<span class="setup-mod-what">${esc(SCAN_MODULE_HELP[m] || "")}</span></label>`).join("");
  return `<div class="scan-setup" data-setup="${t}">
    <div class="scan-setup-head">
      <h4>SETUP FOR THIS SITE</h4>
      <p class="hint">Optional. Leave empty to use global SETTINGS, TOOLS, and WORDLISTS for this site. SAVE SETUP only to override them here. Automatic checks for this site are in this form. Applies on the next START.</p>
    </div>
    <div class="form-grid">
      <label class="span-2">DESCRIPTION<input data-pf="desc" maxlength="200" placeholder="short ASCII note"></label>
      <label><span class="lbl">TELEGRAM USERNAME OR ID</span><input data-pf="tg" class="mono" placeholder="inherit global"></label>
      <label>DIGEST THRESHOLD<input data-pf="digest" type="number" min="1" class="mono" placeholder="inherit"></label>
      <label>TELEGRAM NOTIFICATIONS<select data-pf="tgen"><option value="">inherit global</option><option value="true">enabled</option><option value="false">MUTED for this target</option></select></label>
      <label>WATCHTOWER INSTANT ALERTS<select data-pf="watch"><option value="">inherit global</option><option value="true">enabled</option><option value="false">disabled</option></select></label>
      <label>AUTOMATIC CHECKS<select data-pf="sched-en"><option value="">inherit global</option><option value="true">enabled</option><option value="false">disabled</option></select></label>
      <label>INTERVAL (min)<input data-pf="sched-int" type="number" min="10" class="mono" placeholder="inherit global"></label>
      <label class="span-2">PROXY POOL<input data-pf="proxy" class="mono" placeholder="inherit global"></label>
      <label>PASSIVE BUDGET (sec)<input data-pf="b-passive" type="number" min="1" class="mono" placeholder="inherit"></label>
      <label>ACTIVE BUDGET (sec)<input data-pf="b-active" type="number" min="1" class="mono" placeholder="inherit"></label>
      <label>NESTED DNS DEPTH (1-5)<input data-pf="b-recon" type="number" min="1" max="5" class="mono" placeholder="inherit global"></label>
      <label>NESTED VHOST DEPTH (1-5)<input data-pf="b-ffuf-depth" type="number" min="1" max="5" class="mono" placeholder="inherit global"></label>
      <label>PARALLEL DNS PARENTS (1-8)<input data-pf="b-dnsx-parents" type="number" min="1" max="8" class="mono" placeholder="inherit global"></label>
      <label>PASSIVE RECURSION DEPTH<input data-pf="b-depth" type="number" min="0" max="5" class="mono" placeholder="inherit"></label>
      <label>FFUF-3 MAX DEAD PROBES<input data-pf="b-dead" type="number" min="1" class="mono" placeholder="inherit"></label>
      <label><span class="lbl">FFUF-4 MAX PORT JOBS <span class="help" tabindex="0" data-help="How many HTTP-like listeners FFUF-4 may probe after the port scan. 0 = every listener (run completes). A positive cap stops early and marks the run partial.">?</span></span><input data-pf="b-ffuf4" type="number" min="0" class="mono" placeholder="inherit"></label>
      <label><span class="lbl">PORT SCAN MODE <span class="help" tabindex="0" data-help="Same idea as nmap -p. full = all TCP ports (nmap -p-). top ports = common ports (like nmap --top-ports 100). custom = your list. Empty = global SETTINGS.">?</span></span><select data-pf="ps-profile"><option value="">inherit global</option><option value="full">full (nmap -p- / TCP 1-65535)</option><option value="light">top ports (like nmap --top-ports 100)</option><option value="custom">custom (nmap -p list)</option></select></label>
      <label class="span-2"><span class="lbl">CUSTOM PORTS <span class="help" tabindex="0" data-help="Used when PORT SCAN MODE is custom. Paste an nmap -p list: 22,80,443,8000-8080. Optional -p prefix is accepted.">?</span></span><input data-pf="ps-ports" class="mono" placeholder="like nmap -p 22,80,443,8000-8080"></label>
      <label><span class="lbl">SERVICE VERSION (nmap -sV) <span class="help" tabindex="0" data-help="When on, open ports are fingerprinted with nmap -Pn -sV (skip ping so firewalled hosts still get product/version). Default on. Empty = global SETTINGS.">?</span></span><select data-pf="ps-nmap"><option value="">inherit global</option><option value="true">on</option><option value="false">off</option></select></label>
    </div>
    <div class="setup-modules">
      <label class="check setup-inherit"><input type="checkbox" data-pf="mod-inherit" checked> inherit default tools (TOOLS tab)</label>
      <div class="setup-mod-picks is-inherit" data-pf="mod-picks">
        <div class="setup-mod-group span-2">
          <span class="setup-mod-label">ACTIVE TOOLS</span>
          <p class="hint">Tick only the steps this site should run. Each row says what that tool does.</p>
          <div class="setup-mod-stack">${active}</div>
        </div>
        <div class="setup-mod-group span-2">
          <span class="setup-mod-label">PASSIVE TOOLS</span>
          <div class="setup-mod-stack">${passive}</div>
        </div>
      </div>
    </div>
    <div class="setup-modules">
      <label class="check setup-inherit"><input type="checkbox" data-pf="wl-inherit" checked> inherit WORDLISTS tab (filenames below are the global pick, read-only until you uncheck)</label>
      <div class="setup-wl-picks is-inherit" data-pf="wl-picks"><p class="dim">loading wordlist filenames...</p></div>
    </div>
    <div class="targets-actions setup-actions">
      <button type="button" class="primary" data-setup-save="${t}">SAVE SETUP</button>
      <button type="button" data-setup-reset="${t}">CLEAR OVERRIDES</button>
      <span class="mono dim" data-role="setup-plan"></span>
    </div>
  </div>`;
}

async function loadScanSetup(target, force) {
  const card = cardFor(target);
  const form = card && card.querySelector("[data-setup]");
  if (!form) return;
  if (!force && form.dataset.dirty === "1") return;
  try {
    const doc = await api("GET", "/api/targets/" + encodeURIComponent(target));
    applyProfileToSetup(form, doc.profile);
    await refreshSetupWordlists(form, profileSettings(doc.profile).wordlist_selection);
    const plan = form.querySelector("[data-role=setup-plan]");
    if (plan) {
      const inherit = doc.inherits_globals !== false;
      plan.textContent = inherit
        ? "using global SETTINGS"
        : (doc.edit_plan && Object.keys(doc.edit_plan.wordlist_selection || {}).length
          ? "custom setup (wordlist override)"
          : "custom setup");
    }
    form.dataset.dirty = "0";
  } catch (_e) { /* keep existing fields */ }
}

async function saveScanSetup(target) {
  const card = cardFor(target);
  const form = card && card.querySelector("[data-setup]");
  if (!form) return;
  try {
    const inherit = pf(form, "mod-inherit");
    if (inherit && !inherit.checked) {
      const any = form.querySelector("[data-mod]:checked");
      if (!any) {
        toast("tick at least one tool, or inherit default tools", true);
        return;
      }
    }
    const wlInherit = pf(form, "wl-inherit");
    if (wlInherit && !wlInherit.checked) {
      const anyWl = form.querySelector("input[data-wl-task]:checked");
      if (!anyWl) {
        toast("tick at least one wordlist file, or inherit WORDLISTS", true);
        return;
      }
    }
    const profile = profileFromSetup(form);
    await api("PUT", "/api/targets/" + encodeURIComponent(target), profile);
    form.dataset.dirty = "0";
    toast("setup saved for " + target);
    await loadScanSetup(target, true);
    loadTargetsTable();
    const descEl = card.querySelector(".scan-desc");
    if (descEl && profile.description) {
      descEl.textContent = profile.description;
    }
  } catch (e) {
    toast(e.message, true);
  }
}

async function resetScanSetup(target) {
  if (!window.confirm("Clear custom setup for " + target + "? Empty fields will inherit globals again. Description can stay.")) return;
  const card = cardFor(target);
  const form = card && card.querySelector("[data-setup]");
  const desc = form && pf(form, "desc") ? pf(form, "desc").value.trim() : "";
  const profile = desc ? { description: desc } : {};
  try {
    await api("PUT", "/api/targets/" + encodeURIComponent(target), profile);
    toast("overrides cleared for " + target);
    await loadScanSetup(target, true);
    loadTargetsTable();
  } catch (e) {
    toast(e.message, true);
  }
}

function targetProfileToUI(profile) {
  const s = profileSettings(profile);
  const n = s.notifications || {};
  setVal("#t-desc", (profile && profile.description) || "");
  setVal("#t-tg", n.telegram_chat || "");
  setVal("#t-tgen", n.telegram_enabled === true ? "true" : n.telegram_enabled === false ? "false" : "");
  setVal("#t-proxy", (s.proxy || {}).proxy_pool || "");
  setVal("#t-watch", n.watchtower_enabled === true ? "true" : n.watchtower_enabled === false ? "false" : "");
  setVal("#t-digest", n.digest_threshold || "");
  const sch = s.scheduler || {};
  setVal("#t-sched-en", sch.enabled === true ? "true" : sch.enabled === false ? "false" : "");
  setVal("#t-sched-int", sch.interval_minutes || "");
  const b = s.budgets || {};
  setVal("#t-b-passive", b.passive_branch_budget_sec ?? "");
  setVal("#t-b-active", b.active_branch_budget_sec ?? "");
  setVal("#t-b-recon", b.recon_depth ?? "");
  setVal("#t-b-ffuf-depth", b.ffuf_depth ?? "");
  setVal("#t-b-dnsx-parents", b.dnsx_parallel_parents ?? "");
  setVal("#t-b-depth", b.passive_recursion_depth ?? "");
  setVal("#t-b-dead", b.ffuf3_max_dead_probes ?? "");
  setVal("#t-b-ffuf4", b.ffuf4_max_jobs ?? "");
  const ps = s.portsweep || {};
  setVal("#t-ps-profile", ps.profile || "");
  setVal("#t-ps-ports", ps.custom_ports || "");
  setVal("#t-ps-nmap", ps.nmap_sv === true ? "true" : ps.nmap_sv === false ? "false" : "");
  const m = s.modules || {};
  setVal("#t-m-active", (m.active_branch_modules || []).join(", "));
  setVal("#t-m-passive", (m.passive_branch_modules || []).join(", "));
  const wl = s.wordlist_selection || {};
  for (const task of ["FFUF-0", "DNSR-1", "FFUF-2"]) setVal("#t-wl-" + task, (wl[task] || []).join(", "));
}

async function loadTargetProfile() {
  const target = elVal("#t-name").trim();
  if (!target) { toast("enter a target name first", true); return; }
  try {
    const doc = await api("GET", "/api/targets/" + encodeURIComponent(target));
    targetProfileToUI(doc.profile);
    const sections = (doc.profile && Object.keys(doc.profile.settings || {}).length) ? Object.keys(doc.profile.settings).join(", ") : "no profile (committed defaults)";
    if ($("#t-status")) {
      $("#t-status").textContent = target + ": " + sections;
      $("#t-status").className = "badge ok";
    }
    if ($("#t-plan")) $("#t-plan").textContent = doc.edit_plan && Object.keys(doc.edit_plan.wordlist_selection || {}).length ? "wordlist override active" : "";
    toast("profile loaded for " + target);
  } catch (e) { toast(e.message, true); }
}

async function saveTargetProfile() {
  const target = elVal("#t-name").trim();
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
  const target = elVal("#t-name").trim();
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
  const names = uniqueNames(Object.keys(doc.targets || {}));
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

/* ---------------- b) RESULTS ---------------- */
const FILTER_IDS = ["q", "host", "ip", "ports", "alive", "length", "tech", "source", "tag", "first_seen", "last_seen", "run", "scope"];

function readFilterUI() {
  const f = {};
  for (const id of FILTER_IDS) {
    const v = elVal("#f-" + id);
    if (v) f[id] = v;
  }
  return f;
}
function writeFilterUI(f) {
  for (const id of FILTER_IDS) setVal("#f-" + id, (f && f[id]) || "");
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

function clearResultsView(message) {
  CURRENT.assets = [];
  renderAssets();
  const covBody = $("#coverage-table tbody");
  if (covBody) covBody.innerHTML = "";
  if ($("#overlap")) $("#overlap").textContent = "";
  if ($("#diff-badges")) $("#diff-badges").innerHTML = message
    ? `<span class="badge">${esc(message)}</span>` : "";
  if ($("#diff-view")) $("#diff-view").textContent = "";
  if ($("#wh-meta")) $("#wh-meta").textContent = message || "pick a site added on SCAN";
  if ($("#wh-badge")) { $("#wh-badge").textContent = "warehouse"; $("#wh-badge").className = "badge"; }
  const liveBadge = $("#results-live-badge");
  if (liveBadge) { liveBadge.textContent = "live"; liveBadge.className = "badge"; }
}

function startResultsLiveTimer() {
  clearInterval(RESULTS_LIVE_TIMER);
  RESULTS_LIVE_TIMER = setInterval(() => {
    const panel = $("#panel-results");
    if (!panel || panel.classList.contains("hidden")) return;
    loadResults({ quiet: true });
  }, 8000);
}

async function loadResults(opts) {
  const quiet = !!(opts && opts.quiet);
  // Load balance: RESULTS runs a multi-second warehouse ingest server-side.
  // Never let polling stack (two timers can call this) or fire faster than ~6s.
  if (quiet && Date.now() - RESULTS_LAST_AT < 6000) return;
  if (RESULTS_INFLIGHT) return;
  RESULTS_INFLIGHT = true;
  try {
    await _loadResultsBody(quiet);
  } finally {
    RESULTS_INFLIGHT = false;
    RESULTS_LAST_AT = Date.now();
  }
}

async function _loadResultsBody(quiet) {
  const names = await refreshSiteSelects();
  let target = panelTarget("results-target");
  if (!target) {
    const pick = preferredScanSite(names);
    if (pick) {
      const el = $("#results-target");
      if (el) el.value = pick;
      target = pick;
    }
  }
  if (!target) {
    clearResultsView("choose a site from SCAN");
    if (!quiet) toast("Pick a site on the RESULTS page", true);
    return;
  }
  rememberTarget(target);
  const f = readFilterUI();
  const qs = new URLSearchParams(f).toString();
  try {
    const doc = await api("GET", "/api/results/" + encodeURIComponent(target) + (qs ? "?" + qs : ""));
    CURRENT.assets = doc.assets || [];
    renderAssets();
    const liveBadge = $("#results-live-badge");
    if (liveBadge) {
      const n = (CURRENT.assets || []).length;
      liveBadge.textContent = n ? ("live " + n + " hosts") : "live (empty)";
      liveBadge.className = "badge " + (n ? "ok" : "");
    }
  } catch (e) {
    CURRENT.assets = [];
    renderAssets();
    if (!quiet) toast(e.message, true);
    return;
  }
  // Live polling only refreshes the host table (light). Coverage, diff (a
  // multi-MB payload) and warehouse meta are heavy and near-static during a
  // scan -- fetch them only on an explicit load (panel open / filter change),
  // never on the silent poll tick, to keep load off the server.
  if (quiet) return;
  try {
    const cov = await api("GET", "/api/results/" + encodeURIComponent(target) + "/coverage");
    renderCoverage(cov);
  } catch (_e) { /* coverage is extra */ }
  try {
    const diff = await api("GET", "/api/results/" + encodeURIComponent(target) + "/diff");
    renderDiff(diff);
  } catch (_e) { /* diff is extra */ }
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
  const target = panelTarget("results-target");
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
  const target = panelTarget("results-target");
  if (!target) { toast("Pick a site on the RESULTS page", true); return; }
  if (!window.confirm("Rebuild the warehouse for " + target + " from run history? This can take a while on large sites and replaces the current index.")) return;
  await api("POST", "/api/warehouse/" + encodeURIComponent(target) + "/rebuild");
  toast("warehouse rebuilt for " + target);
  await loadResults();
}

// Snapshot of the host whose port inspector is open (survives table re-render).
let PORT_INSPECTOR = null;

function portCountLabel(n) {
  const count = Number(n) || 0;
  if (count === 1) return "1 port";
  return count + " ports";
}

function hostHref(host) {
  const name = String(host || "").trim();
  if (!name) return "";
  if (/^https?:\/\//i.test(name)) return name;
  return "https://" + name;
}

function hostCell(host, isAlive, isNew) {
  const badge = isNew ? ' <span class="badge new">NEW</span>' : "";
  if (!host) return badge;
  if (!isAlive) return `${esc(host)}${badge}`;
  return `<a class="host-link" href="${esc(hostHref(host))}" target="_blank" rel="noopener noreferrer">${esc(host)}</a>${badge}`;
}

function portDetailTable(ports) {
  return `<table class="port-detail"><thead><tr><th>Port</th><th>Product</th><th>Version</th></tr></thead><tbody>`
    + ports.map((p) => {
      const port = (p.port != null ? String(p.port) : "") + (p.proto ? "/" + p.proto : "");
      const product = String(p.product || "").trim();
      const version = String(p.version || "").trim();
      return `<tr>`
        + `<td class="mono port-num">${esc(port)}</td>`
        + `<td>${product ? esc(product) : '<span class="dim">—</span>'}</td>`
        + `<td>${version ? esc(version) : '<span class="dim">—</span>'}</td>`
        + `</tr>`;
    }).join("")
    + "</tbody></table>";
}

function portSummaryCell(host, row) {
  const total = Number((row && row.open_ports_total) != null ? row.open_ports_total : 0) || 0;
  const ips = (row && (row.open_ports_by_ip || []).length)
    ? row.open_ports_by_ip
    : (row.ips || [row.ip]).filter(Boolean).map((ip) => ({ ip, count: 0 }));
  if (!total && !(ips && ips.length)) return '<span class="dim">--</span>';
  const shown = total ? String(total) : "0";
  return `<button type="button" class="ports-open" data-ports-open="${esc(host)}" title="Show IPs and open ports">`
    + `<span class="badge port">${esc(shown)}</span></button>`;
}

function openPortInspector(host) {
  const row = (CURRENT.assets || []).find((r) => (r.host || "") === host);
  if (!row) return;
  const fromJoin = Array.isArray(row.open_ports_by_ip) ? row.open_ports_by_ip : [];
  const fallback = (row.ips || [row.ip]).filter(Boolean).map((ip) => ({ ip, count: 0 }));
  PORT_INSPECTOR = {
    host,
    ips: fromJoin.length ? fromJoin : fallback,
    selectedIp: null,
    ports: [],
    loading: false,
  };
  renderPortInspector();
}

function closePortInspector() {
  PORT_INSPECTOR = null;
  const panel = $("#port-inspector");
  if (panel) panel.hidden = true;
}

function portInspectorBack() {
  if (!PORT_INSPECTOR || !PORT_INSPECTOR.selectedIp) {
    closePortInspector();
    return;
  }
  PORT_INSPECTOR.selectedIp = null;
  PORT_INSPECTOR.ports = [];
  PORT_INSPECTOR.loading = false;
  renderPortInspector();
}

async function selectPortIp(ip) {
  if (!PORT_INSPECTOR) return;
  PORT_INSPECTOR.selectedIp = ip;
  PORT_INSPECTOR.ports = [];
  PORT_INSPECTOR.loading = true;
  renderPortInspector();
  const target = panelTarget("results-target") || CURRENT.target || "";
  try {
    const qs = new URLSearchParams({ host: PORT_INSPECTOR.host, ip });
    const doc = await api("GET", "/api/results/" + encodeURIComponent(target) + "/ports?" + qs.toString());
    if (!PORT_INSPECTOR || PORT_INSPECTOR.selectedIp !== ip) return;
    PORT_INSPECTOR.ports = doc.ports || [];
  } catch (e) {
    if (PORT_INSPECTOR && PORT_INSPECTOR.selectedIp === ip) toast(e.message, true);
  } finally {
    if (PORT_INSPECTOR && PORT_INSPECTOR.selectedIp === ip) {
      PORT_INSPECTOR.loading = false;
      renderPortInspector();
    }
  }
}

function renderPortInspector() {
  const panel = $("#port-inspector");
  if (!panel || !PORT_INSPECTOR) return;
  const hostEl = $("#pi-host");
  const ipsEl = $("#pi-ips");
  const body = $("#pi-body");
  const back = $("#pi-back");
  if (hostEl) hostEl.textContent = PORT_INSPECTOR.host;
  if (back) back.hidden = !PORT_INSPECTOR.selectedIp;
  if (ipsEl) {
    ipsEl.textContent = PORT_INSPECTOR.selectedIp
      ? PORT_INSPECTOR.selectedIp
      : portCountLabel(PORT_INSPECTOR.ips.reduce((n, row) => n + (Number(row.count) || 0), 0));
  }
  if (body) {
    if (PORT_INSPECTOR.selectedIp) {
      if (PORT_INSPECTOR.loading) {
        body.innerHTML = '<span class="dim">loading ports…</span>';
      } else if (!(PORT_INSPECTOR.ports || []).length) {
        body.innerHTML = '<span class="dim">no open ports on this IP</span>';
      } else {
        body.innerHTML = portDetailTable(PORT_INSPECTOR.ports);
      }
    } else if (!(PORT_INSPECTOR.ips || []).length) {
      body.innerHTML = '<span class="dim">no IPs recorded</span>';
    } else {
      body.innerHTML = '<div class="port-ip-list">'
        + PORT_INSPECTOR.ips.map((row) => {
          const ip = row.ip || "";
          const n = Number(row.count) || 0;
          const disabled = !ip ? " disabled" : "";
          return `<button type="button" class="port-ip-row" data-port-ip="${esc(ip)}"${disabled}>`
            + `<span>${esc(ip || "no IP")}</span>`
            + `<span class="badge port">${esc(portCountLabel(n))}</span></button>`;
        }).join("")
        + "</div>";
    }
  }
  panel.hidden = false;
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
  if (!tbody) return;
  tbody.innerHTML = rows.map((r) => {
    // A host that resolves to an IP is a live asset even if HTTP did not answer;
    // never render an IP-bearing host as DEAD. HTTP status is shown separately.
    const hasIp = (r.ips || [r.ip]).filter(Boolean).length > 0;
    const isAlive = !!r.alive || hasIp;
    const host = r.host || "";
    return `<tr>` +
    `<td>${hostCell(host, isAlive, !!r.is_new)}</td>` +
    `<td class="ports-cell">${portSummaryCell(host, r)}</td>` +
    `<td><span class="badge ${isAlive ? "alive" : "dead"}">${isAlive ? "ALIVE" : "DEAD"}</span>${r.http_status ? ` <span class="badge">HTTP ${esc(String(r.http_status))}</span>` : ""}</td>` +
    `<td class="dim">${esc(r.length == null ? "" : String(r.length))}</td>` +
    `<td class="dim">${esc((r.tech || []).join(", "))}</td>` +
    `<td class="dim">${esc((r.sources || []).join(", "))}</td>` +
    `<td>${(r.tags || []).map((t) => `<span class="badge">${esc(t)}</span>`).join(" ")}</td>` +
    `<td class="dim">${esc(r.first_seen || "")}</td>` +
    `<td class="dim">${esc(r.last_seen || "")}</td>` +
    `<td><button data-json='${esc(JSON.stringify(r))}'>{ }</button></td></tr>`;
  }).join("") ||
    `<tr><td colspan="10" class="dim">no assets (run the pipeline first)</td></tr>`;
  tbody.onclick = (ev) => {
    const portsBtn = ev.target.closest("[data-ports-open]");
    if (portsBtn) {
      openPortInspector(portsBtn.getAttribute("data-ports-open"));
      return;
    }
    const btn = ev.target.closest("[data-json]");
    if (!btn) return;
    const pre = $("#diff-view");
    pre.textContent = JSON.stringify(JSON.parse(btn.dataset.json), null, 2);
    pre.classList.remove("collapsed");
    pre.scrollIntoView({ behavior: "smooth" });
  };
}

let LAST_COVERAGE = null;
let COVERAGE_SORT = { key: "contribution", dir: -1 };

function renderCoverage(cov) {
  if (cov !== undefined) LAST_COVERAGE = cov;
  cov = LAST_COVERAGE;
  const tbody = $("#coverage-table tbody");
  if (!tbody) return;
  const contribution = (cov && cov.contribution) || {};
  const uniq = (cov && cov.unique_assets) || {};
  const pct = (cov && cov.uniqueness_pct) || {};
  const rows = Object.keys(contribution).map((s) => ({
    source: s,
    contribution: Number(contribution[s]) || 0,
    unique: Number(uniq[s]) || 0,
    uniqueness: Number(pct[s]) || 0,
  }));
  const k = COVERAGE_SORT.key, dir = COVERAGE_SORT.dir;
  rows.sort((a, b) => {
    const av = a[k], bv = b[k];
    if (typeof av === "string") return dir * String(av).localeCompare(String(bv));
    return dir * (av - bv);
  });
  tbody.innerHTML = rows.map((r) =>
    `<tr><td>${esc(r.source)}</td><td>${r.contribution}</td><td>${r.unique}</td><td>${r.uniqueness}%</td></tr>`).join("");
  if ($("#overlap")) $("#overlap").textContent = "overlap (assets found by N sources): " + JSON.stringify((cov && cov.overlap_by_n_sources) || {});
}

function renderDiff(diff) {
  const badges = $("#diff-badges");
  if (!badges) return;
  if (!diff || !diff.exists) { badges.innerHTML = '<span class="badge">no diff yet (first run)</span>'; if ($("#diff-view")) $("#diff-view").textContent = ""; return; }
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
async function loadReports(opts) {
  const quiet = !!(opts && opts.quiet);
  const names = await refreshSiteSelects();
  let target = panelTarget("rep-target");
  if (!target) {
    const pick = preferredScanSite(names);
    if (pick) {
      const el = $("#rep-target");
      if (el) el.value = pick;
      target = pick;
    }
  }
  if (!target) {
    const badge = $("#rep-status");
    if (badge) { badge.textContent = "|"; badge.className = "badge"; }
    const tbody = $("#reports-table tbody");
    if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="dim">choose a site from SCAN</td></tr>';
    if ($("#rep-manifest")) $("#rep-manifest").textContent = "";
    if (!quiet) toast("Pick a site on the REPORTS page", true);
    return;
  }
  rememberTarget(target);
  const badge = $("#rep-status");
  const tbody = $("#reports-table tbody");
  if (tbody) tbody.innerHTML = "";
  const doc = await api("GET", "/api/report/" + encodeURIComponent(target));
  if (!doc.exists) {
    if (badge) { badge.textContent = "no bundle"; badge.className = "badge dead"; }
    if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="dim">no report bundle yet -- press GENERATE NOW</td></tr>';
    if ($("#rep-manifest")) $("#rep-manifest").textContent = "";
    return;
  }
  if (badge) {
    badge.textContent = doc.verified ? "VERIFIED" : "TAMPER/DRIFT";
    badge.className = "badge " + (doc.verified ? "ok" : "alert");
  }
  const m = doc.manifest || {};
  const files = m.files || {};
  if (tbody) {
    tbody.innerHTML = Object.entries(files).map(([name, f]) =>
      `<tr><td>${esc(name)}</td><td class="dim">${esc(f.path)}</td><td class="dim">${esc(String(f.sha256 || "").slice(0, 16))}...</td>` +
      `<td><a class="badge ok" href="/static-file/${esc(target)}/${esc(f.path)}" target="_blank">OPEN</a></td></tr>`).join("") ||
      '<tr><td colspan="4" class="dim">manifest has no files</td></tr>';
  }
  const pre = $("#rep-manifest");
  if (pre) {
    pre.textContent = JSON.stringify(m, null, 2);
    pre.onclick = () => pre.classList.toggle("collapsed");
  }
}

/* ---------------- c) RUN CONTROL -- multi-target board ---------------- */
const SCAN = { expanded: new Set(), streams: {}, boardTimer: null, halted: new Set(), stopping: new Set() };

function statusBadgeClass(status) {
  if (status === "failed" || status === "anomaly") return "alert";
  if (status === "completed") return "ok";
  if (status === "running") return "new";
  if (status === "stopped") return "new";
  return "dead";
}

const SOURCE_LABELS = {
  crtsh: "crt.sh",
  certspotter: "Cert Spotter",
  subfinder: "subfinder",
  amass: "amass",
  assetfinder: "assetfinder",
  findomain: "findomain",
  chaos: "Chaos",
  gau: "gau",
  "httpx-passive": "passive HTTP probe",
  "curl-fetch": "an HTTP data source",
};

function scanStillGoing(row) {
  if (row.run_live) return true;
  if ((row.modules_running || 0) > 0) return true;
  return Object.values(row.modules || {}).some((m) => m && m.status === "running");
}

function operatorRunView(row) {
  if (SCAN.stopping.has(row.target)) {
    return { label: "stopping", tone: "dead", limited: false, note: "" };
  }
  if (row.operator_label) {
    return {
      label: row.operator_label,
      tone: row.operator_tone || statusBadgeClass(row.run_status),
      limited: !!row.operator_limited,
      note: row.operator_note || "",
    };
  }
  const raw = row.run_status || "idle";
  const source = SOURCE_LABELS[row.failing_module] || row.failing_module || "a data source";
  if (raw === "anomaly") {
    if (scanStillGoing(row)) {
      return {
        label: "running",
        tone: "new",
        limited: true,
        note: source + " is paused after too many errors from that source. The rest of the scan continues. This is not a crash.",
      };
    }
    return {
      label: "done (source limited)",
      tone: "warn",
      limited: true,
      note: source + " was paused after too many errors from that source. Other steps still ran. This is a third-party source limit, not a broken scanner.",
    };
  }
  const notes = {
    partial: row.reason || "Some steps finished with gaps.",
    failed: row.reason || "The run failed.",
    stopped: row.reason || "Stopped by the operator.",
  };
  return {
    label: raw,
    tone: statusBadgeClass(raw),
    limited: false,
    note: notes[raw] || "",
  };
}

function paintOperatorStatus(card, row) {
  if (!card) return;
  const view = operatorRunView(row || { target: card.dataset.scan });
  const badge = card.querySelector("[data-run-badge]") || card.querySelector(".scan-head > .badge");
  if (badge) {
    badge.textContent = view.label;
    badge.className = "badge " + view.tone;
    badge.setAttribute("data-run-badge", "");
  }
  let limited = card.querySelector("[data-limited-badge]");
  if (view.limited) {
    if (!limited) {
      limited = document.createElement("span");
      limited.className = "badge warn";
      limited.setAttribute("data-limited-badge", "");
      if (badge && badge.parentNode) badge.insertAdjacentElement("afterend", limited);
    }
    limited.textContent = "source limited";
    limited.hidden = false;
  } else if (limited) {
    limited.remove();
  }
  let note = card.querySelector("[data-scan-note]");
  if (!note) {
    note = document.createElement("p");
    note.className = "scan-status-note";
    note.setAttribute("data-scan-note", "");
    const head = card.querySelector(".scan-head");
    if (head) head.insertAdjacentElement("afterend", note);
  }
  note.textContent = view.note || "";
  note.classList.toggle("is-limited", !!view.limited && !!view.note);
  note.hidden = !view.note;
}

function cardFor(target) {
  return [...document.querySelectorAll(".scan-card")].find((c) => c.dataset.scan === target) || null;
}

async function loadRun() {
  const target = panelTarget("run-target") || CURRENT.target;
  if (target) {
    rememberTarget(target);
    setVal("#run-target", target);
  }
  await loadScanBoard();
  if (target && !SCAN.expanded.size) setScanExpanded(target, true);
  const stray = $("#run-modules");
  if (stray) stray.innerHTML = "";
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
    const target = (panelTarget("run-target") || CURRENT.target || "").trim();
    if (!target) return;
    if (SCAN.halted.has(target) || SCAN.stopping.has(target)) return;
    if (target !== bound) {
      bound = target;
      offset = 0;
      if (rawEl) rawEl.textContent = "";
      if (prettyEl) prettyEl.innerHTML = "";
      window.__livePretty = { prettyKey: "" };
      const title = document.querySelector("#live-term .term-title");
      if (title) title.textContent = "live output -- " + target;
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

function scanModulesHtml(target, modules) {
  const entries = Object.entries(modules || {});
  const chips = entries.map(([m, s]) => {
    const st = (s && s.status) || "?";
    if (st === "failed" || st === "anomaly" || st === "skipped") {
      return `<span class="mod-chip">${esc(m)}</span>`;
    }
    return `<span class="mod-chip ${esc(st)}">${esc(m)} <b>${esc(st)}</b></span>`;
  }).join("");
  return `<span class="scan-mods-label">${esc(target)} steps</span>` +
    (chips || '<span class="dim">no module state yet for this site</span>');
}

function scanLiveHtml(row) {
  const live = row.live || {};
  const bits = [];
  const hits = live.host_hits || live.lines;
  if (live.parent) bits.push("parent " + live.parent);
  if (hits != null && hits !== "") bits.push("dns hits " + hits);
  const qps = live.qps != null ? live.qps : live.logged_qps;
  if (qps != null) bits.push("qps " + qps);
  const liveLine = bits.length
    ? `<p class="scan-live-line mono">${esc(bits.join(" · "))}</p>`
    : '<p class="scan-live-line mono dim">waiting for live progress</p>';
  return `<div class="scan-live" data-scan-live="${esc(row.target || "")}">${liveLine}</div>`;
}

function paintCardLive(card, row) {
  if (!card) return;
  const host = card.querySelector("[data-scan-live]");
  const html = scanLiveHtml(row);
  if (host) host.outerHTML = html;
  else {
    const head = card.querySelector(".scan-head");
    if (head) head.insertAdjacentHTML("afterend", html);
  }
}

function paintCardModules(card, target, modules) {
  if (!card) return;
  const host = card.querySelector("[data-scan-mods]");
  if (host) host.innerHTML = scanModulesHtml(target, modules);
}

function scanCardHtml(row) {
  const t = row.target;
  const view = operatorRunView(row);
  const open = SCAN.expanded.has(t);
  const modules = scanModulesHtml(t, row.modules);
  const counts = row.last_counts || {};
  const countBits = Object.keys(counts).length
    ? Object.entries(counts).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(" ")
    : "";
  const limitedBadge = view.limited ? `<span class="badge warn" data-limited-badge>source limited</span>` : "";
  const note = view.note
    ? `<p class="scan-status-note${view.limited ? " is-limited" : ""}" data-scan-note>${esc(view.note)}</p>`
    : `<p class="scan-status-note" data-scan-note hidden></p>`;
  return `<article class="scan-card${open ? " open" : ""}" data-scan="${esc(t)}">
    <div class="scan-head">
      <button type="button" class="scan-toggle" data-expand="${esc(t)}" aria-expanded="${open ? "true" : "false"}">${open ? "COLLAPSE" : "EXPAND"}</button>
      <span class="scan-name">${esc(t)}</span>
      <span class="badge ${esc(view.tone)}" data-run-badge>${esc(view.label)}</span>
      ${limitedBadge}
      <span class="badge ${row.inherits_globals === false ? "ok" : ""}">${esc(row.inherits_globals === false ? "custom" : "global")}</span>
      <span class="scan-desc">${esc(row.description || (row.registered ? "registered" : "workspace only"))}${row.last_run ? " | last " + esc(row.last_run) : ""}${row.run_count ? " | " + row.run_count + " runs" : ""}</span>
      <div class="scan-head-actions">
        <button type="button" data-setup-open="${esc(t)}">SETUP</button>
        <button data-scan-start="${esc(t)}">START</button>
        <button data-scan-resume="${esc(t)}">RESUME</button>
        <button class="warn" data-scan-restart="${esc(t)}" title="stop this site then begin from the first module">RESTART</button>
        <button class="danger" data-scan-stop="${esc(t)}">STOP</button>
        <button class="danger" data-scan-delete="${esc(t)}">DELETE</button>
      </div>
      <div class="scan-mods" data-scan-mods="${esc(t)}" aria-label="pipeline steps for ${esc(t)}">${modules}</div>
    </div>
    ${note}
    ${scanLiveHtml(row)}
    <div class="scan-body">
      ${scanSetupHtml(t)}
      <div class="scan-jumps">
        <button data-jump="results" data-jt="${esc(t)}">RESULTS</button>
        <button data-jump="reports" data-jt="${esc(t)}">REPORTS</button>
        <button data-jump="targets" data-jt="${esc(t)}">TARGETS TAB</button>
      </div>
      <p class="mono dim">${countBits ? "last counts: " + countBits : "no completed run counts yet"} | logs ${row.has_logs ? "present" : "none yet"}</p>
      <div class="term">
        <div class="term-bar">
          <i></i><i></i><i></i>
          <span class="term-title">live log -- ${esc(t)}</span>
          <span class="log-mode">
            <button type="button" class="log-mode-btn active" data-logmode="pretty">Readable</button>
            <button type="button" class="log-mode-btn" data-logmode="raw">Raw</button>
            <button type="button" class="log-mode-btn" data-export-log="${esc(t)}">Export</button>
          </span>
        </div>
        <div class="log-pretty scan-log-pretty" data-role="pretty"></div>
        <pre class="json-inspector hidden" data-role="raw"></pre>
      </div>
      <div class="term">
        <div class="term-bar">
          <i></i><i></i><i></i>
          <span class="term-title">assistant journal -- ${esc(t)}</span>
          <span class="log-mode">
            <button type="button" class="log-mode-btn" data-export-journal="${esc(t)}">Export</button>
          </span>
        </div>
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

function markScanStopping(target) {
  SCAN.stopping.add(target);
  SCAN.halted.add(target);
  stopTargetStream(target);
  const card = cardFor(target);
  if (!card) return;
  paintOperatorStatus(card, { target });
  const pretty = card.querySelector("[data-role=pretty]");
  if (pretty) {
    const row = document.createElement("div");
    row.className = "log-row warn";
    row.innerHTML = '<span class="log-msg">STOP pressed -- killing pipeline and tool containers now.</span>';
    pretty.appendChild(row);
    pretty.scrollTop = pretty.scrollHeight;
  }
  card.querySelectorAll("[data-scan-start],[data-scan-resume],[data-scan-restart],[data-scan-stop]").forEach((btn) => {
    btn.disabled = true;
  });
}

function markScanStopped(target) {
  SCAN.stopping.delete(target);
  SCAN.halted.add(target);
  stopTargetStream(target);
  const card = cardFor(target);
  if (!card) return;
  paintOperatorStatus(card, { target, run_status: "stopped" });
  card.querySelectorAll("[data-scan-start],[data-scan-resume],[data-scan-restart],[data-scan-stop]").forEach((btn) => {
    btn.disabled = false;
  });
}

function clearScanHalt(target) {
  SCAN.halted.delete(target);
  SCAN.stopping.delete(target);
}

function startTargetStream(target) {
  if (SCAN.halted.has(target) || SCAN.stopping.has(target)) return;
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
  const state = { card, logOff: 0, jOff: 0, prettyKey: "", skipped: false, logTimer: null, journalTimer: null, logBusy: false, journalBusy: false };
  SCAN.streams[target] = state;
  async function pullLog() {
    if (state.logBusy) return;
    if (SCAN.halted.has(target) || SCAN.stopping.has(target)) return;
    if ($("#panel-run").classList.contains("hidden") || !SCAN.expanded.has(target)) return;
    state.logBusy = true;
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
        state.logBusy = false;
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
    finally { state.logBusy = false; }
  }
  async function pullJournal() {
    if (SCAN.halted.has(target) || SCAN.stopping.has(target)) return;
    if ($("#panel-run").classList.contains("hidden") || !SCAN.expanded.has(target)) return;
    try {
      const doc = await api("GET", `/api/run/agent-journal/${encodeURIComponent(target)}?offset=${state.jOff}`);
      if (!doc.exists || !journal) return;
      if (doc.rows && doc.rows.length) {
        journal.textContent += doc.rows.map((l) => {
          try {
            const r = JSON.parse(l);
            const ev = r.event || "note";
            if (/error|fail|except/i.test(ev) || r.error) return "";
            return `[${r.ts || ""}] ${ev}\n`;
          } catch (_e) { return ""; }
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
    loadScanSetup(target, false);
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
      const names = uniqueNames([...(tdoc.known || []), ...Object.keys(tdoc.targets || {})]).sort();
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
          profile: profile,
          inherits_globals: !(profile.settings && Object.keys(profile.settings).length),
          workspace: st.exists !== false,
          run_status: run.status || st.run_status || "",
          reason: run.reason || "",
          failing_module: run.failing_module || "",
          modules: st.modules || {},
          last_run: "",
          last_counts: {},
          run_count: 0,
          has_logs: st.exists === true,
        });
      }
      doc = { targets: assembled };
    }
    const rows = uniqueByTarget(doc.targets || []);
    syncSiteSelects(rows.map((r) => r.target));
    if (!rows.length) {
      board.innerHTML = '<p class="dim">no sites yet -- type a domain above and press ADD TARGET</p>';
      return;
    }
    const ids = rows.map((r) => r.target).join("\n");
    if (board.dataset.ids === ids && board.querySelector(".scan-card")) {
      for (const row of rows) {
        const card = cardFor(row.target);
        if (!card) continue;
        paintOperatorStatus(card, row);
        paintCardModules(card, row.target, row.modules);
        paintCardLive(card, row);
      }
      for (const t of [...SCAN.expanded]) {
        if (!SCAN.halted.has(t) && !SCAN.stopping.has(t)) startTargetStream(t);
        const card = cardFor(t);
        if (card && card.dataset.setupLoaded !== "1") {
          loadScanSetup(t, false);
          card.dataset.setupLoaded = "1";
        }
      }
      return;
    }
    board.dataset.ids = ids;
    board.innerHTML = rows.map(scanCardHtml).join("");
    enhanceNumberInputs(board);
    for (const row of rows) {
      const form = cardFor(row.target) && cardFor(row.target).querySelector("[data-setup]");
      if (form && row.profile) applyProfileToSetup(form, row.profile);
    }
    for (const t of [...SCAN.expanded]) {
      if (!rows.some((r) => r.target === t)) {
        stopTargetStream(t);
        SCAN.expanded.delete(t);
        continue;
      }
      if (!SCAN.halted.has(t) && !SCAN.stopping.has(t)) startTargetStream(t);
      const card = cardFor(t);
      if (card && card.dataset.setupLoaded !== "1") {
        loadScanSetup(t, false);
        card.dataset.setupLoaded = "1";
      }
    }
  } catch (_e) {
    if (!board.querySelector(".scan-card")) {
      board.innerHTML = '<p class="dim">could not load sites -- try again</p>';
    }
  }
}

async function refreshScanBadges() {
  try {
    const doc = await api("GET", "/api/scan/board");
    for (const row of doc.targets || []) {
      const card = cardFor(row.target);
      if (!card) continue;
        paintOperatorStatus(card, row);
    }
  } catch (_e) { /* keep UI */ }
}

function startScanBoardTimer() {
  clearInterval(SCAN.boardTimer);
  SCAN.boardTimer = setInterval(() => {
    if (!$("#panel-run")?.classList.contains("hidden")) refreshScanBadges();
  }, 4000);
}

async function requestScanStop(target) {
  if (!target) {
    toast("Type a domain on the SCAN page first", true);
    return;
  }
  // Immediate UI halt -- do not wait for confirm or network before freezing logs.
  markScanStopping(target);
  toast("stopping " + target + "...");
  try {
    await api("POST", "/api/run/stop", { target });
    markScanStopped(target);
    toast("stopped " + target);
    if ($("#run-target")) $("#run-target").value = target;
    rememberTarget(target);
    // Refresh badges only -- do NOT restart log streams for a halted target.
    await refreshScanBadges();
  } catch (e) {
    markScanStopped(target);
    toast(e.message, true);
  }
}

async function addScanTarget(startAfter) {
  const target = requireScanTarget();
  if (!target) return "";
  const added = await addScanNames([target]);
  if (!added.length) return "";
  if (startAfter) await startScanFor(added[0]);
  return added[0];
}

function parseTargetList(text) {
  return [...new Set(String(text || "").split(/[\s,;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean))];
}

async function addScanNames(names) {
  const unique = [...new Set((names || []).map((s) => String(s || "").trim().toLowerCase()).filter(Boolean))];
  if (!unique.length) {
    toast("Type a domain, or paste a list, then ADD TARGET / ADD LIST", true);
    return [];
  }
  const authorize = $("#run-authorize") ? $("#run-authorize").checked : true;
  const doc = await api("POST", "/api/scan/targets", {
    targets: unique,
    authorize,
    description: unique.length > 1 ? "added from SCAN list" : "added from SCAN",
  });
  const rows = doc.targets || (doc.target ? [doc] : []);
  const added = rows.map((r) => r.target).filter(Boolean);
  for (const t of added) {
    rememberTarget(t);
    SCAN.expanded.add(t);
  }
  await refreshKnownTargets();
  seedPanelTargets(added);
  const rejected = doc.rejected || [];
  const errn = (doc.errors || []).length;
  if (added.length === 1 && !rejected.length && !errn) {
    toast("added " + added[0] + " -- SETUP is optional (otherwise global settings)");
  } else {
    toast("added " + added.length + " site(s)" + (rejected.length || errn ? " -- some names skipped" : ""));
  }
  await loadRun();
  startScanBoardTimer();
  if (added[0]) setScanExpanded(added[0], true);
  return added;
}

async function addScanList() {
  const box = $("#scan-list");
  const fromBox = parseTargetList(box ? box.value : "");
  const fromSite = parseTargetList($("#run-target") ? $("#run-target").value : "");
  const names = fromBox.length ? fromBox : fromSite;
  try {
    const added = await addScanNames(names);
    if (added.length && box) box.value = "";
    return added;
  } catch (e) {
    toast(e.message, true);
    return [];
  }
}

async function startScanFor(target) {
  if (!target) {
    toast("ADD TARGET first, then START on that site's row", true);
    return;
  }
  clearScanHalt(target);
  const authorize = $("#run-authorize") ? $("#run-authorize").checked : true;
  try {
    const r = await api("POST", "/api/run/start", { target, authorize });
    toast("scan started for " + target + " (pid=" + r.pid + ")");
    SCAN.expanded.add(target);
    if ($("#run-target")) $("#run-target").value = target;
    rememberTarget(target);
    setScanExpanded(target, true);
    await loadRun();
    startScanBoardTimer();
  } catch (e) {
    toast(e.message, true);
  }
}

async function restartScanFor(target) {
  if (!target) {
    toast("ADD TARGET first, then RESTART on that site's row", true);
    return;
  }
  clearScanHalt(target);
  const authorize = $("#run-authorize") ? $("#run-authorize").checked : true;
  try {
    const r = await api("POST", "/api/run/restart", { target, authorize });
    toast("restarted " + target + " from the first module (pid=" + r.pid + ")");
    SCAN.expanded.add(target);
    if ($("#run-target")) $("#run-target").value = target;
    rememberTarget(target);
    setScanExpanded(target, true);
    await loadRun();
    startScanBoardTimer();
  } catch (e) {
    toast(e.message, true);
  }
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

function lastDnsBruteProgress(text) {
  const matches = [...String(text).matchAll(/dns-brute parent=(\S+) chunk=(\d+) names=(\d+) qps=(\d+)/g)];
  if (!matches.length) return "";
  const m = matches[matches.length - 1];
  return `DNS brute ${m[1]} (chunk ${m[2]}, ${m[3]} names, ${m[4]} qps)`;
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
      .replace(/degraded-continue after section 4\.3 retries/g, "continuing")
      .replace(/disclosed, never silent/g, "")
      .replace(/no key in \.env/g, "no API key");
    return body;
  }
  if (/^search-forge:/i.test(detail)) {
    return detail
      .replace(/^search-forge:\s*/i, "")
      .replace(/engine=/g, "")
      .replace(/disabled -- no key in \.env \(([^)]+)\)/g, "off (no $1 key)")
      .replace(/disclosed, never silent/g, "")
      .replace(/error-ratio .* -> ISOLATED/g, "")
      .replace(/\s+/g, " ")
      .trim();
  }
  const dnsProgress = lastDnsBruteProgress(detail);
  if (dnsProgress) return dnsProgress;
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
    ev.tone = (status === "ok") ? "ok" : "info";
    ev.groupKey = [ev.tone, module, tool, ev.text].join("|");
    return ev;
  }
  return { kind: "plain", status: "info", tone: "info", time: "", module: "", text: raw, groupKey: "plain|" + raw };
}

function isInternalScanNoise(ev) {
  const st = String(ev.status || "").toLowerCase();
  const detail = String(ev.detail || "");
  const text = String(ev.text || "");
  const blob = detail + " " + text;
  if (/pull access denied|Unable to find image/i.test(blob)) return false;
  if (st === "throttle" || st === "pause" || st === "fail") return true;
  if (/^skip:/i.test(detail) || /^Skipped:/i.test(text)) return true;
  if (/circuit breaker|safety limiter|error rate|too many errors/i.test(blob)) return true;
  if (/canary|load-balance|throttle_factor|latency drift/i.test(blob)) return true;
  if (/ISOLATED|isolated after|search-forge/i.test(blob)) return true;
  if (/disclosed|never silent|degraded-continue|no key in \.env/i.test(detail)) return true;
  if (/Slowing this tool|Paused this tool/i.test(text)) return true;
  if (isBannerNoise(detail)) return true;
  return false;
}

function appendPrettyLogs(lines, box, state) {
  box = box || $("#live-log-pretty");
  if (!box) return;
  state = state || window.__scanPretty || (window.__scanPretty = { prettyKey: "" });
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 48;
  for (const line of lines) {
    const ev = parseLogLine(line);
    if (!ev) continue;
    if (ev.kind === "event" && isInternalScanNoise(ev)) continue;
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

function wireLogExport() {
  const logBtn = $("#log-export");
  const journalBtn = $("#journal-export");
  if (logBtn && !logBtn.dataset.wired) {
    logBtn.dataset.wired = "1";
    logBtn.addEventListener("click", () => exportRunArtifact("log"));
  }
  if (journalBtn && !journalBtn.dataset.wired) {
    journalBtn.dataset.wired = "1";
    journalBtn.addEventListener("click", () => exportRunArtifact("journal"));
  }
}

wireLogExport();

function startJournalStream() {
  clearInterval(window.__journalTimer);
  let joffset = 0;
  const pre = $("#agent-journal");
  if (!pre) return;
  pre.textContent = "";
  window.__journalTimer = setInterval(async () => {
    if (!$("#panel-run") || $("#panel-run").classList.contains("hidden")) return;
    const target = (panelTarget("run-target") || CURRENT.target || "").trim();
    if (!target) return;
    try {
      const doc = await api("GET", `/api/run/agent-journal/${encodeURIComponent(target)}?offset=${joffset}`);
      if (!doc.exists) return;
      if (doc.rows && doc.rows.length) {
        pre.textContent += doc.rows.map((l) => {
          try {
            const r = JSON.parse(l);
            const ev = r.event || "note";
            if (/error|fail|except/i.test(ev) || r.error) return "";
            return `[${r.ts || ""}] ${ev}\n`;
          } catch (_e) { return ""; }
        }).join("");
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
  const keys = [];
  const seen = new Set();
  for (const k of doc.keys || []) {
    const name = String((k && k.name) || "").trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    keys.push(k);
  }
  tbody.innerHTML = keys.map((k) => `<tr>` +
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
      if (!window.confirm("Delete " + del.dataset.del + " from .env? Any module that relies on this key falls back to its keyless mode on the next run.")) return;
      await api("DELETE", "/api/keys/" + del.dataset.del);
      toast(`${del.dataset.del} deleted from .env`);
      loadKeys();
    }
  };
}

/* ---------------- e) SETTINGS ---------------- */
const ALERT_CLASS_LABELS = {
  hosts: "Subdomains / hosts (includes HTTP length changes)",
  ports: "Open ports",
  vhosts: "Virtual hosts (Host header)",
  services: "Service / product banners",
  passive_ips: "Passive-discovered IPs",
};
const ALERT_SIDE_LABELS = {
  added: "New",
  removed: "Removed",
  changed: "Changed",
};

function defaultAlertRules() {
  return ["hosts", "ports", "vhosts", "services", "passive_ips"].map((cls) => ({
    class: cls,
    enabled: true,
    require_new_ip: false,
    sides: ["added", "removed", "changed"],
  }));
}

function paintAlertRules(rules) {
  const editor = $("#rules-editor");
  if (!editor) return;
  const byClass = {};
  for (const rule of rules || []) {
    if (rule && rule.class) byClass[rule.class] = rule;
  }
  const rows = Object.keys(ALERT_CLASS_LABELS).map((cls) => {
    const rule = byClass[cls] || { class: cls, enabled: true, require_new_ip: false, sides: ["added", "removed", "changed"] };
    const sides = new Set(Array.isArray(rule.sides) && rule.sides.length ? rule.sides : ["added", "removed", "changed"]);
    const sideBoxes = ["added", "removed", "changed"].map((side) =>
      `<label class="check alert-side"><input type="checkbox" data-alert-side="${side}" ${sides.has(side) ? "checked" : ""}> ${ALERT_SIDE_LABELS[side]}</label>`
    ).join("");
    const newIp = cls === "hosts"
      ? `<label class="check alert-side"><input type="checkbox" data-alert-newip ${rule.require_new_ip ? "checked" : ""}> only when IP is also new</label>`
      : "";
    return `<div class="rule-row alert-rule" data-alert-class="${esc(cls)}">` +
      `<label class="check alert-enable"><input type="checkbox" data-alert-enabled ${rule.enabled !== false ? "checked" : ""}>` +
      `<strong>${esc(ALERT_CLASS_LABELS[cls])}</strong></label>` +
      `<div class="alert-sides">${sideBoxes}${newIp}</div></div>`;
  });
  editor.innerHTML = rows.join("");
}

function collectAlertRules() {
  return [...document.querySelectorAll("#rules-editor .alert-rule")].map((row) => {
    const sides = [...row.querySelectorAll("[data-alert-side]:checked")].map((cb) => cb.getAttribute("data-alert-side"));
    return {
      class: row.getAttribute("data-alert-class"),
      enabled: !!(row.querySelector("[data-alert-enabled]") || {}).checked,
      require_new_ip: !!(row.querySelector("[data-alert-newip]") || {}).checked,
      sides: sides.length ? sides : [],
    };
  });
}

async function loadSettings() {
  const s = await api("GET", "/api/settings");
  setVal("#s-proxy", s.proxy_url || "");
  setVal("#s-proxy-pool", s.proxy_pool || "");
  setVal("#s-tg-chat", (s.telegram || {}).chat_id || "");
  setVal("#s-digest", s.digest_threshold || 10);
  setVal("#s-recon-depth", s.recon_depth || 1);
  setVal("#s-ffuf-depth", s.ffuf_depth || 1);
  setVal("#s-dnsx-parents", s.dnsx_parallel_parents || 4);
  setVal("#s-passive-depth", s.passive_recursion_depth ?? 2);
  setVal("#s-ps-profile", s.portsweep_profile || "full");
  setVal("#s-ps-ports", s.portsweep_custom_ports || "");
  setVal("#s-ps-nmap", String(s.portsweep_nmap_sv !== false));
  setVal("#s-ffuf4-jobs", s.ffuf4_max_jobs == null ? 0 : s.ffuf4_max_jobs);
  try {
    const sched = await api("GET", "/api/scheduler");
    setVal("#sched-interval", sched.interval_minutes);
    setVal("#sched-enabled", sched.enabled ? "true" : "false");
    if ($("#sched-last")) $("#sched-last").textContent = "last_run: " + (sched.last_run || "never");
    window.__schedLast = sched.last_run || null;
  } catch (_e) { /* scheduler optional */ }
  setVal("#s-cpu", (s.resource_budget || {}).cpu_cores || "");
  setVal("#s-ram", (s.resource_budget || {}).ram_mb || "");
  setVal("#s-agent-enabled", String((s.agent || {}).enabled === true));
  setVal("#s-agent-passive", (s.agent || {}).autonomy_passive || "auto-fix");
  setVal("#s-agent-active", (s.agent || {}).autonomy_active || "suggest");
  setVal("#s-agent-budget", (s.agent || {}).max_llm_calls ?? 20);
  const ret = s.retention || {};
  setVal("#s-ret-runs", ret.keep_runs ?? 20);
  setVal("#s-ret-log", ret.log_max_mb ?? 10);
  setVal("#s-ret-journal", ret.journal_max_mb ?? 5);
  setVal("#s-ret-gz", ret.log_keep_gz ?? 3);
  setVal("#s-ret-total", ret.max_total_mb ?? 1024);
  paintAlertRules(s.alert_rules && s.alert_rules.length ? s.alert_rules : defaultAlertRules());
}

async function saveSettings() {
  const patch = {
    proxy_url: elVal("#s-proxy").trim(),
    proxy_pool: elVal("#s-proxy-pool").trim(),
    alert_rules: collectAlertRules(),
  };
  const digest = parseInt(elVal("#s-digest") || "10", 10);
  if (!isNaN(digest) && digest > 0) patch.digest_threshold = digest;
  const token = elVal("#s-tg-token").trim();
  const chat = elVal("#s-tg-chat").trim();
  if (token || chat) patch.telegram = { ...(chat ? { chat_id: chat } : {}), ...(token ? { bot_token: token } : {}) };
  const cpu = parseInt(elVal("#s-cpu"), 10), ram = parseInt(elVal("#s-ram"), 10);
  if (!isNaN(cpu) || !isNaN(ram)) patch.resource_budget = { ...(isNaN(cpu) ? {} : { cpu_cores: cpu }), ...(isNaN(ram) ? {} : { ram_mb: ram }) };
  patch.agent = {
    enabled: elVal("#s-agent-enabled") === "true",
    autonomy_passive: elVal("#s-agent-passive") || "auto-fix",
    autonomy_active: elVal("#s-agent-active") || "suggest",
  };
  const budget = parseInt(elVal("#s-agent-budget"), 10);
  if (!isNaN(budget)) patch.agent.max_llm_calls = budget;
  const ret = {
    keep_runs: parseInt(elVal("#s-ret-runs"), 10),
    log_max_mb: parseInt(elVal("#s-ret-log"), 10),
    journal_max_mb: parseInt(elVal("#s-ret-journal"), 10),
    log_keep_gz: parseInt(elVal("#s-ret-gz"), 10),
    max_total_mb: parseInt(elVal("#s-ret-total"), 10),
  };
  if (Object.values(ret).every((v) => !isNaN(v) && v >= 1)) patch.retention = ret;
  const recon = parseInt(elVal("#s-recon-depth"), 10);
  if (!isNaN(recon)) patch.recon_depth = recon;
  const ffufD = parseInt(elVal("#s-ffuf-depth"), 10);
  if (!isNaN(ffufD)) patch.ffuf_depth = ffufD;
  const pasD = parseInt(elVal("#s-passive-depth"), 10);
  if (!isNaN(pasD)) patch.passive_recursion_depth = pasD;
  const dnsxP = parseInt(elVal("#s-dnsx-parents"), 10);
  if (!isNaN(dnsxP)) patch.dnsx_parallel_parents = dnsxP;
  const psProfile = (elVal("#s-ps-profile") || "full").trim().toLowerCase();
  patch.portsweep_profile = psProfile;
  patch.portsweep_custom_ports = elVal("#s-ps-ports").trim();
  patch.portsweep_nmap_sv = elVal("#s-ps-nmap") !== "false";
  const ffuf4Jobs = parseInt(elVal("#s-ffuf4-jobs"), 10);
  if (!isNaN(ffuf4Jobs)) patch.ffuf4_max_jobs = ffuf4Jobs;
  try {
    await api("PUT", "/api/settings", patch);
    try {
      if ($("#sched-interval") && $("#sched-enabled")) {
        const interval = parseInt(elVal("#sched-interval"), 10);
        if (!isNaN(interval)) {
          await api("PUT", "/api/scheduler", {
            interval_minutes: interval,
            enabled: elVal("#sched-enabled") === "true",
            last_run: window.__schedLast || null,
          });
        }
      }
    } catch (schedErr) {
      toast("settings saved; scheduler not saved: " + schedErr.message, true);
    }
    if ($("#s-msg")) $("#s-msg").textContent = "saved " + new Date().toISOString();
    setVal("#s-tg-token", "");
    toast("settings saved to dashboard/config.json (secrets masked)");
    loadSettings();
  } catch (e) { toast(e.message, true); }
}

/* ---------------- per-feature help chips --------------------------------
   Hover/focus shows a viewport-clamped tooltip. Click/tap pins it. */
function helpPopEl() {
  return $("#help-pop");
}

function placeHelpPop(chip) {
  const pop = helpPopEl();
  if (!pop || !chip) return;
  const text = chip.getAttribute("data-help") || "";
  if (!text) { pop.classList.add("hidden"); return; }
  pop.textContent = text;
  pop.classList.remove("hidden");
  pop.style.left = "8px";
  pop.style.top = "8px";
  const pad = 8;
  const r = chip.getBoundingClientRect();
  const pw = pop.offsetWidth;
  const ph = pop.offsetHeight;
  let left = r.left + r.width / 2 - pw / 2;
  let top = r.bottom + 8;
  if (left + pw > window.innerWidth - pad) left = window.innerWidth - pad - pw;
  if (left < pad) left = pad;
  if (top + ph > window.innerHeight - pad) top = r.top - ph - 8;
  if (top < pad) top = pad;
  pop.style.left = Math.round(left) + "px";
  pop.style.top = Math.round(top) + "px";
}

function hideHelpPop() {
  const pop = helpPopEl();
  if (pop) pop.classList.add("hidden");
}

function helpChipFrom(node) {
  return node && node.closest ? node.closest(".help") : null;
}

document.addEventListener("mouseover", (ev) => {
  const chip = helpChipFrom(ev.target);
  const from = helpChipFrom(ev.relatedTarget);
  if (chip && chip !== from) placeHelpPop(chip);
});
document.addEventListener("mouseout", (ev) => {
  const chip = helpChipFrom(ev.target);
  const to = helpChipFrom(ev.relatedTarget);
  if (chip && chip !== to && !chip.classList.contains("open")) hideHelpPop();
});
document.addEventListener("focusin", (ev) => {
  const chip = helpChipFrom(ev.target);
  if (chip) placeHelpPop(chip);
});
document.addEventListener("focusout", (ev) => {
  const chip = helpChipFrom(ev.target);
  if (chip && !chip.classList.contains("open")) hideHelpPop();
});
document.addEventListener("click", (ev) => {
  const chip = helpChipFrom(ev.target);
  document.querySelectorAll(".help.open").forEach((el) => { if (el !== chip) el.classList.remove("open"); });
  if (chip) {
    chip.classList.toggle("open");
    if (chip.classList.contains("open")) placeHelpPop(chip);
    else hideHelpPop();
  } else {
    hideHelpPop();
  }
});
window.addEventListener("scroll", () => {
  const open = document.querySelector(".help.open");
  if (open) placeHelpPop(open);
}, true);
window.addEventListener("resize", () => {
  const open = document.querySelector(".help.open") || document.querySelector(".help:hover");
  if (open) placeHelpPop(open);
  else hideHelpPop();
});

closeHelpOnEscape();
function closeHelpOnEscape() {
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    document.querySelectorAll(".help.open").forEach((el) => el.classList.remove("open"));
    hideHelpPop();
  });
}

/* ---------------- wiring ---------------- */
document.addEventListener("click", () => recordClick(), true);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    document.querySelectorAll(".help.open").forEach((el) => el.classList.remove("open"));
    hideHelpPop();
  }
  recordClick();
}, true);
setInterval(() => {
  if (AUTHED && LAST_CLICK && (Date.now() - LAST_CLICK) >= IDLE_MS) {
    lockSession("Idle timeout (15 minutes). Sign in again.");
  }
}, 5000);
bind("#session-lock", "click", () => lockSession("Locked. Sign in again."));
bind("#auth-form", "submit", async (ev) => {
  ev.preventDefault();
  const password = ($("#auth-password") && $("#auth-password").value) || "";
  const confirm = ($("#auth-confirm") && $("#auth-confirm").value) || "";
  const setup = ($("#auth-gate") && $("#auth-gate").dataset.mode) === "setup";
  showAuthError("");
  try {
    const path = setup ? "/api/auth/setup" : "/api/auth/login";
    const body = setup ? { password, confirm } : { password };
    const res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const doc = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = typeof doc.detail === "string" ? doc.detail : "";
      if (res.status === 404) {
        showAuthError("dashboard backend is old -- restart the dashboard container, then refresh");
        return;
      }
      showAuthError(detail || "sign-in failed");
      return;
    }
    await afterSignedIn();
  } catch (e) {
    showAuthError(e.message || "sign-in failed");
  }
});
bind("#f-apply", "click", () => { shareFilters(readFilterUI()); loadResults(); });
bind("#f-share", "click", async () => {
  const url = shareFilters(readFilterUI());
  try { await navigator.clipboard.writeText(url); toast("filter URL copied -- state restores from URL"); }
  catch (_e) { toast(url); }
});
bind("#f-clear", "click", () => { writeFilterUI({}); shareFilters({}); loadResults(); });
document.querySelectorAll("#assets-table th[data-sort], #coverage-table th[data-sort], #tools-table th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    if (th.closest("#coverage-table")) {
      COVERAGE_SORT = { key, dir: COVERAGE_SORT.key === key ? -COVERAGE_SORT.dir : 1 };
      renderCoverage();
      return;
    }
    CURRENT.sort = { key, dir: CURRENT.sort.key === key ? -CURRENT.sort.dir : 1 };
    renderAssets();
  });
});
bind("#run-target", "keydown", (ev) => {
  if (ev.key === "Enter") { ev.preventDefault(); addScanTarget(false).catch((e) => toast(e.message, true)); }
});
bind("#run-target", "change", () => {
  const target = panelTarget("run-target");
  if (target) rememberTarget(target);
});
bind("#run-target", "input", () => {
  const target = panelTarget("run-target");
  if (target) rememberTarget(target);
});
const scanAddBtn = $("#scan-add");
if (scanAddBtn) scanAddBtn.addEventListener("click", () => addScanTarget(false).catch((e) => toast(e.message, true)));
const scanAddListBtn = $("#scan-add-list");
if (scanAddListBtn) scanAddListBtn.addEventListener("click", () => addScanList());
const scanBoard = $("#scan-board");
if (scanBoard) {
  scanBoard.addEventListener("input", (ev) => {
    const form = ev.target.closest("[data-setup]");
    if (form) form.dataset.dirty = "1";
    const filter = ev.target.closest("[data-wl-filter]");
    if (filter) {
      const block = filter.closest("[data-wl-block]");
      const q = filter.value.trim().toLowerCase();
      if (block) {
        block.querySelectorAll(".setup-wl-row").forEach((row) => {
          row.style.display = !q || row.textContent.toLowerCase().includes(q) ? "" : "none";
        });
      }
    }
  });
  scanBoard.addEventListener("change", (ev) => {
    const inherit = ev.target.closest("[data-pf=mod-inherit]");
    if (inherit) {
      const form = inherit.closest("[data-setup]");
      if (form) {
        setSetupModsEnabled(form, !inherit.checked);
        form.dataset.dirty = "1";
      }
    }
    const wlInherit = ev.target.closest("[data-pf=wl-inherit]");
    if (wlInherit) {
      const form = wlInherit.closest("[data-setup]");
      if (form) {
        setSetupWlEnabled(form, !wlInherit.checked);
        form.dataset.dirty = "1";
      }
    }
  });
  scanBoard.addEventListener("click", async (ev) => {
    const setupSave = ev.target.closest("[data-setup-save]");
    const setupReset = ev.target.closest("[data-setup-reset]");
    const setupOpen = ev.target.closest("[data-setup-open]");
    if (setupSave) {
      ev.preventDefault();
      ev.stopPropagation();
      await saveScanSetup(setupSave.getAttribute("data-setup-save"));
      return;
    }
    if (setupReset) {
      ev.preventDefault();
      ev.stopPropagation();
      await resetScanSetup(setupReset.getAttribute("data-setup-reset"));
      return;
    }
    if (setupOpen) {
      ev.preventDefault();
      ev.stopPropagation();
      const t = setupOpen.getAttribute("data-setup-open");
      if ($("#run-target")) $("#run-target").value = t;
      rememberTarget(t);
      setScanExpanded(t, true);
      const form = cardFor(t) && cardFor(t).querySelector("[data-setup]");
      if (form) {
        form.scrollIntoView({ block: "nearest" });
        const first = pf(form, "desc");
        if (first) first.focus();
      }
      return;
    }
    const wlPrev = ev.target.closest("[data-wl-preview]");
    if (wlPrev) {
      ev.preventDefault();
      ev.stopPropagation();
      const key = wlPrev.getAttribute("data-wl-preview");
      const block = wlPrev.closest("[data-wl-block]");
      const sample = block && block.querySelector("[data-wl-sample]");
      if (sample) sample.textContent = "loading names...";
      try {
        const doc = await api("GET", "/api/wordlists/preview?key=" + encodeURIComponent(key));
        const lines = doc.samples || [];
        const title = (doc.name || key) + (doc.reason ? " -- " + doc.reason : "");
        if (sample) sample.textContent = lines.length
          ? title + "\n" + lines.join("\n")
          : (title + "\n(no sample lines on disk)");
      } catch (e) {
        if (sample) sample.textContent = e.message;
      }
      return;
    }
    if (ev.target.closest("[data-setup]")) ev.stopPropagation();
    const expand = ev.target.closest("[data-expand]");
    const start = ev.target.closest("[data-scan-start]");
    const resume = ev.target.closest("[data-scan-resume]");
    const restart = ev.target.closest("[data-scan-restart]");
    const stop = ev.target.closest("[data-scan-stop]");
    const del = ev.target.closest("[data-scan-delete]");
    const jump = ev.target.closest("[data-jump]");
    const mode = ev.target.closest("[data-logmode]");
    const exportLog = ev.target.closest("[data-export-log]");
    const exportJournal = ev.target.closest("[data-export-journal]");
    const card = ev.target.closest(".scan-card");
    if (exportLog) {
      ev.preventDefault();
      exportRunArtifact("log", exportLog.getAttribute("data-export-log"));
      return;
    }
    if (exportJournal) {
      ev.preventDefault();
      exportRunArtifact("journal", exportJournal.getAttribute("data-export-journal"));
      return;
    }
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
      setVal("#run-target", t);
      rememberTarget(t);
      SCAN.expanded.add(t);
      await startScanFor(t);
      return;
    }
    if (resume) {
      const t = resume.getAttribute("data-scan-resume");
      try {
        const r = await api("POST", "/api/run/resume", { target: t });
        toast("resumed " + t + " pid=" + r.pid);
        clearScanHalt(t);
        setScanExpanded(t, true);
      } catch (e) { toast(e.message, true); }
      return;
    }
    if (restart) {
      const t = restart.getAttribute("data-scan-restart");
      if (!window.confirm("Restart " + t + " from the FIRST module? This stops any live scan and discards this run's progress. Previous results/warehouse records are kept.")) return;
      setVal("#run-target", t);
      rememberTarget(t);
      SCAN.expanded.add(t);
      await restartScanFor(t);
      return;
    }
    if (stop) {
      const t = stop.getAttribute("data-scan-stop");
      if (SCAN.stopping.has(t)) return;
      // Fire without awaiting so the click handler returns immediately.
      void requestScanStop(t);
      return;
    }
    if (del) {
      ev.preventDefault();
      ev.stopPropagation();
      const t = del.getAttribute("data-scan-delete");
      if (!window.confirm("Remove " + t + " from SCAN now? Warehouse records stay for 7 days, then this site's files are deleted. Other sites are not touched.")) return;
      const card = [...document.querySelectorAll(".scan-card")].find((c) => c.dataset.scan === t);
      if (typeof stopTargetStream === "function") stopTargetStream(t);
      SCAN.expanded.delete(t);
      if (card) card.remove();
      if ($("#run-target") && $("#run-target").value.trim() === t) $("#run-target").value = "";
      (async () => {
        try {
          const led = await api("POST", "/api/scan/targets/" + encodeURIComponent(t) + "/delete", {});
          const days = led.kept_days || 7;
          toast("removed " + t + " from SCAN -- records kept " + days + " days");
          await loadScanBoard();
          refreshKnownTargets();
        } catch (e) {
          toast(e.message, true);
          loadScanBoard();
        }
      })();
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
bind("#s-reset-rules", "click", () => {
  paintAlertRules(defaultAlertRules());
  toast("alert filters reset -- tick New / Removed / Changed per class, then SAVE SETTINGS");
});
bind("#s-save", "click", saveSettings);
bind("#s-test", "click", async () => {
  const badge = $("#s-test-result");
  const hintLine = $("#s-test-hint");
  if (!badge) return;
  try {
    const r = await api("POST", "/api/notify/test", {});
    badge.textContent = r.sent ? "TEST SENT" : "SKIPPED: " + r.reason;
    badge.className = "badge " + (r.sent ? "ok" : "new");
    if (hintLine) {
      hintLine.textContent = r.sent
        ? (r.reason ? "Delivered: " + r.reason : "Message delivered -- check your Telegram.")
        : (r.hint || "");
      hintLine.className = "hint-line" + (r.sent ? " ok" : " warn");
    }
  } catch (e) {
    badge.textContent = "ERROR: " + e.message;
    badge.className = "badge alert";
    if (hintLine) hintLine.textContent = "";
  }
});
bind("#t-load", "click", loadTargetProfile);
bind("#t-save", "click", saveTargetProfile);
bind("#t-clear", "click", deleteTargetProfile);
bind("#rep-check", "click", async () => {
  try { await loadReports(); toast("bundle checked (tamper-check runs server-side)"); }
  catch (e) { toast(e.message, true); }
});
bind("#rep-generate", "click", async () => {
  const target = panelTarget("rep-target");
  if (!target) { toast("Pick a site on the REPORTS page", true); return; }
  try {
    await api("POST", "/api/report/" + encodeURIComponent(target) + "/generate");
    toast("report bundle generated for " + target);
    await loadReports();
  } catch (e) { toast(e.message, true); }
});
bind("#results-load", "click", () => loadResults());
bind("#diff-compare", "click", () => compareWarehouseRuns().catch((e) => toast(e.message, true)));
bind("#wh-rebuild", "click", () => rebuildWarehouse().catch((e) => toast(e.message, true)));
bind("#results-target", "change", () => loadResults().catch((e) => toast(e.message, true)));
bind("#rep-target", "change", () => loadReports().catch((e) => toast(e.message, true)));
bind("#pi-close", "click", closePortInspector);
bind("#pi-back", "click", portInspectorBack);
bind("#port-inspector", "click", (ev) => {
  if (ev.target === ev.currentTarget) closePortInspector();
  const ipBtn = ev.target.closest("[data-port-ip]");
  if (ipBtn && ipBtn.getAttribute("data-port-ip")) {
    selectPortIp(ipBtn.getAttribute("data-port-ip"));
  }
});
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Escape" || !PORT_INSPECTOR) return;
  if (PORT_INSPECTOR.selectedIp) portInspectorBack();
  else closePortInspector();
});

async function health() {
  const el = $("#conn");
  if (!el) return;
  try {
    const r = await fetch("/api/health", { credentials: "same-origin" });
    const doc = await r.json();
    if (!doc.ok) { el.textContent = "?"; el.className = "badge dead"; return; }
    el.textContent = "online";
    el.className = "badge ok";
    if (!AUTHED) return;
    try {
      await api("GET", "/api/tools");
      el.textContent = "online";
      el.className = "badge ok";
    } catch (_authErr) {
      el.textContent = "online (locked)";
      el.className = "badge alert";
    }
  } catch (_e) { el.textContent = "offline"; el.className = "badge alert"; }
}

function loadPanel(name) {
  if (!AUTHED) return;
  if (name === "engine") loadTools();
  if (name === "tools") loadWordlists();
  if (name === "targets") { loadTargetsTable(); }
  if (name === "results") { loadResults({ quiet: true }); startResultsLiveTimer(); startScanBoardTimer(); }
  if (name === "reports") loadReports({ quiet: true });
  if (name === "run") { loadRun(); startLogStream(); startJournalStream(); startScanBoardTimer(); }
  if (name === "keys") loadKeys();
  if (name === "settings") loadSettings();
  if (name === "help") { /* static guide -- nothing to fetch */ }
}

(async function init() {
  enhanceNumberInputs(document);
  try {
    sessionStorage.removeItem("recon_dashboard_token");
    localStorage.removeItem("recon_dashboard_token");
  } catch (_e) { /* ignore */ }
  const st = await authStatus().catch(() => ({ setup_required: true, authenticated: false }));
  if (st.authenticated) {
    await afterSignedIn();
  } else if (st.setup_required) {
    setGate("setup");
    await health();
  } else {
    setGate("login");
    await health();
  }
  const panel = restoreFiltersFromURL() || localStorage.getItem("recon_last_panel") || "run";
  const tab = document.querySelector(`.tab[data-panel="${panel}"]`) || document.querySelector(".tab");
  tab.click();
})();
