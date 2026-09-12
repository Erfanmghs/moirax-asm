"""Dashboard-styled HTML report: filterable assets, ports grouped by IP."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_LOGO = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Attack Surface Management">
  <defs>
    <linearGradient id="asm-ring" x1="8" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#7dd3fc"/><stop offset="1" stop-color="#22d3ee"/>
    </linearGradient>
    <radialGradient id="asm-core" cx="32" cy="30" r="22" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#163044"/><stop offset="1" stop-color="#071018"/>
    </radialGradient>
  </defs>
  <path fill="url(#asm-core)" stroke="url(#asm-ring)" stroke-width="2"
        d="M32 4.5 54.5 15.2v21.2c0 11.4-9.6 21.2-22.5 25.1C19.1 57.6 9.5 47.8 9.5 36.4V15.2Z"/>
  <ellipse cx="32" cy="34" rx="18" ry="7.2" fill="none" stroke="#22d3ee" stroke-opacity=".35" stroke-width="1.2"/>
  <ellipse cx="32" cy="31" rx="13.5" ry="5.4" fill="none" stroke="#67e8f9" stroke-opacity=".7" stroke-width="1.5"/>
  <ellipse cx="32" cy="28.4" rx="8" ry="3.2" fill="none" stroke="#22d3ee" stroke-width="1.6"/>
  <circle cx="32" cy="28.4" r="2.4" fill="#22d3ee"/>
</svg>"""

_CSS = """
:root{--bg:#070b12;--panel:#101a27;--line:#243447;--text:#d7e4f0;--dim:#7b90a6;--accent:#22d3ee;--accent-2:#67e8f9;--alive:#34d399;--dead:#64748b;--new:#fbbf24;--warn:#fbbf24;
--mono:ui-monospace,Menlo,Consolas,monospace;--sans:"Segoe UI",system-ui,sans-serif}
html{background:var(--bg);color-scheme:dark}
body{margin:0;color:var(--text);font:13.5px/1.5 var(--sans);background:var(--bg)}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
.hero{display:flex;gap:16px;align-items:center;padding:16px 18px;background:var(--panel);border:1px solid var(--line);border-radius:12px}
.logo{width:52px;height:52px}
.kicker{color:var(--accent);font:650 11px var(--mono);letter-spacing:.08em;text-transform:uppercase}
.title{font:700 18px var(--sans)}.title .accent{color:var(--accent)}
.sub{color:var(--dim);font:12px var(--mono);margin-top:4px}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.badge{display:inline-block;padding:2px 9px;font:650 11px var(--mono);border-radius:999px;border:1px solid var(--line)}
.badge.alive{color:var(--alive);border-color:var(--alive)}
.badge.dead{color:var(--dead);border-color:var(--dead)}
.badge.new{color:var(--new);border-color:var(--new)}
.badge.port{color:var(--accent-2);border-color:rgba(34,211,238,.45);background:rgba(34,211,238,.08)}
.badge.warn{color:var(--warn);border-color:var(--warn)}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:16px 0;padding:12px;background:var(--panel);border:1px solid var(--line);border-radius:8px}
.filters input,.filters select,button{background:#081018;color:var(--text);border:1px solid var(--line);min-height:34px;padding:0 12px;font:12px var(--mono);border-radius:8px}
button{cursor:pointer}button.primary{background:var(--accent);color:#041016;border-color:var(--accent);font-family:var(--sans);font-weight:650}
h2{margin:24px 0 8px;font:700 13px var(--mono);letter-spacing:.08em;color:var(--accent)}
.hint{color:var(--dim);font:12px var(--sans);font-weight:400;letter-spacing:0}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
th{text-align:left;padding:8px 10px;color:var(--dim);font-size:10px;letter-spacing:.06em;text-transform:uppercase;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:4;background:#0f1620;box-shadow:0 1px 0 var(--line)}
table#assets-table{border-collapse:separate;border-spacing:0}
a.host-link{color:var(--accent-2);text-decoration:none}a.host-link:hover{text-decoration:underline;color:var(--accent)}
td{padding:6px 10px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top}
.dim{color:var(--dim)}
.ports-open{display:inline-flex;align-items:center;background:none;border:0;padding:0;cursor:pointer}
.overlay{position:fixed;inset:0;background:rgba(4,8,14,.72);display:flex;align-items:center;justify-content:center;padding:24px;z-index:40}
.overlay[hidden]{display:none!important}
.card{width:min(720px,100%);max-height:80vh;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
.port-ip-list{display:flex;flex-direction:column;gap:6px}
.port-ip-row{display:flex;justify-content:space-between;align-items:center;gap:12px;width:100%;padding:10px 12px;background:#081018;border:1px solid var(--line);border-radius:8px;cursor:pointer;color:var(--text);font-family:var(--mono);text-align:left}
.port-ip-row:hover{border-color:var(--accent)}
.port-grid{display:flex;flex-wrap:wrap;gap:4px}
.port-detail{width:100%;border-collapse:collapse;font:12px var(--mono)}
.port-detail th{text-align:left;padding:8px 10px;color:var(--dim);font-size:10px;letter-spacing:.06em;text-transform:uppercase;border-bottom:1px solid var(--line)}
.port-detail td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}
.head-actions{display:flex;gap:8px}
td.port-num{color:var(--accent-2)} td.version{color:var(--alive)}
.foot{margin-top:24px;color:var(--dim);font:12px var(--mono)}
"""

_JS = r"""
function esc(s){const d=document.createElement("div");d.textContent=s==null?"":String(s);return d.innerHTML}
function $(s){return document.querySelector(s)}
function alive(r){return !!(r.alive||(r.ips&&r.ips.length))}
let selectedHost=null, selectedIp=null;
function portLabel(n){n=Number(n)||0; return n===1?"1 port":n+" ports"}
function ipsFor(r){
  if(Array.isArray(r.open_ports_by_ip)&&r.open_ports_by_ip.length) return r.open_ports_by_ip;
  const counts={};
  for(const p of r.open_ports||[]){const ip=p.ip||""; counts[ip]=(counts[ip]||0)+1}
  const ordered=[];
  for(const ip of r.ips||[]){if(ip&&!ordered.includes(ip)) ordered.push(ip)}
  for(const ip of Object.keys(counts)){if(!ordered.includes(ip)) ordered.push(ip)}
  return ordered.map(ip=>({ip, count:counts[ip]||0}));
}
function portChip(r){
  const n=Number(r.open_ports_total||(r.open_ports||[]).length)||0;
  if(!n && !(r.ips||[]).length) return '<span class="dim">--</span>';
  return `<button class="ports-open" data-host="${esc(r.host)}"><span class="badge port">${n}</span></button>`;
}
function hostHref(h){h=String(h||"").trim(); if(!h) return ""; return /^https?:\/\//i.test(h)?h:"https://"+h}
function hostCell(r,on){
  const host=r.host||"";
  const badge=r.is_new?' <span class="badge new">NEW</span>':"";
  if(!on) return esc(host)+badge;
  return `<a class="host-link" href="${esc(hostHref(host))}" target="_blank" rel="noopener noreferrer">${esc(host)}</a>`+badge;
}
function portTable(ports){
  return '<table class="port-detail"><thead><tr><th>Port</th><th>Product</th><th>Version</th></tr></thead><tbody>'
    +ports.map(p=>{
      const port=(p.port!=null?String(p.port):"")+(p.proto?"/"+p.proto:"");
      const product=String(p.product||"").trim();
      const version=String(p.version||"").trim();
      return `<tr><td class="port-num">${esc(port)}</td><td>${product?esc(product):'<span class="dim">—</span>'}</td><td>${version?esc(version):'<span class="dim">—</span>'}</td></tr>`;
    }).join("")
    +"</tbody></table>";
}
function overlayBody(r){
  if(selectedIp){
    const ports=(r.open_ports||[]).filter(p=>(p.ip||"")===selectedIp);
    if(!ports.length) return '<span class="dim">no open ports on this IP</span>';
    return portTable(ports);
  }
  const rows=ipsFor(r);
  if(!rows.length) return '<span class="dim">no IPs recorded</span>';
  return '<div class="port-ip-list">'+rows.map(row=>{
    const ip=row.ip||"";
    return `<button class="port-ip-row" data-ip="${esc(ip)}"><span>${esc(ip||"no IP")}</span><span class="badge port">${esc(portLabel(row.count))}</span></button>`;
  }).join("")+"</div>";
}
function match(r,f){
  if(f.alive==="true"&&!alive(r))return false;
  if(f.alive==="false"&&alive(r))return false;
  if(f.ports==="open"&&!(Number(r.open_ports_total||(r.open_ports||[]).length)>0))return false;
  if(f.ports==="none"&&Number(r.open_ports_total||(r.open_ports||[]).length)>0)return false;
  if(f.host&&!String(r.host||"").toLowerCase().includes(f.host))return false;
  if(f.ip&&!(r.ips||[]).join(" ").toLowerCase().includes(f.ip))return false;
  if(f.length&&!String(r.length==null?"":r.length).toLowerCase().includes(f.length))return false;
  if(f.tech&&!(r.tech||[]).join(" ").toLowerCase().includes(f.tech))return false;
  if(f.source&&!(r.sources||[]).some(s=>String(s).toLowerCase().includes(f.source)))return false;
  if(f.tag&&!(r.tags||[]).some(t=>String(t).toLowerCase().includes(f.tag)))return false;
  if(f.q){
    const blob=[r.host,(r.ips||[]).join(" "),(r.sources||[]).join(" "),(r.tags||[]).join(" "),(r.tech||[]).join(" "),(r.open_ports||[]).map(p=>[p.ip,p.port].join(" ")).join(" ")].join(" ").toLowerCase();
    if(!blob.includes(f.q))return false;
  }
  return true;
}
function filters(){return{q:($("#f-q")&&$("#f-q").value||"").trim().toLowerCase(),host:($("#f-host")&&$("#f-host").value||"").trim().toLowerCase(),ip:($("#f-ip")&&$("#f-ip").value||"").trim().toLowerCase(),ports:($("#f-ports")&&$("#f-ports").value)||"",source:($("#f-source")&&$("#f-source").value||"").trim().toLowerCase(),tag:($("#f-tag")&&$("#f-tag").value||"").trim().toLowerCase(),tech:($("#f-tech")&&$("#f-tech").value||"").trim().toLowerCase(),length:($("#f-length")&&$("#f-length").value||"").trim().toLowerCase(),alive:($("#f-alive")&&$("#f-alive").value)||""}}
function render(){
  const f=filters();
  const all=(REPORT.hosts||[]).filter(r=>match(r,f));
  const rows=all.slice(0,500);
  const meta=$("#asset-meta");
  if(meta) meta.textContent=rows.length+" of "+all.length+" hosts"+(all.length>500?" (first 500)":"");
  const tb=$("#assets-table tbody");
  if(!tb) return;
  tb.innerHTML=rows.map(r=>{
    const on=alive(r);
    return `<tr><td>${hostCell(r,on)}</td><td>${portChip(r)}</td><td><span class="badge ${on?"alive":"dead"}">${on?"ALIVE":"DEAD"}</span></td><td class="dim">${r.length==null?"":esc(r.length)}</td><td class="dim">${esc((r.sources||[]).join(", "))}</td><td>${(r.tags||[]).map(t=>`<span class="badge">${esc(t)}</span>`).join(" ")}</td></tr>`;
  }).join("")||'<tr><td colspan="6" class="dim">no hosts match these filters</td></tr>';
}
function extras(){
  const stb=$("#services-table tbody");
  if(stb){const rows=REPORT.services||[];stb.innerHTML=rows.map(s=>`<tr><td class="dim">${esc(s.ip||"")}</td><td class="port-num">${esc(s.port)}/${esc(s.proto||"tcp")}</td><td>${esc(s.name||s.service||"")}</td><td>${esc(s.product||"")}</td><td class="version">${esc(s.version||"")}</td></tr>`).join("")||'<tr><td colspan="5" class="dim">no nmap -sV product/version yet</td></tr>';}
  const vtb=$("#vhosts-table tbody");
  if(vtb){const rows=REPORT.vhosts||[];vtb.innerHTML=rows.map(v=>`<tr><td>${esc(v.vhost)}</td><td class="dim">${esc(v.base_host||"")}</td><td class="dim">${esc(v.ip||"")}</td><td>${esc(v.port||"")}</td><td>${v.alive?'<span class="badge alive">ALIVE</span>':'<span class="badge dead">DEAD</span>'}</td></tr>`).join("")||'<tr><td colspan="5" class="dim">no vhosts recorded</td></tr>';}
}
function drawOverlay(){
  const r=(REPORT.hosts||[]).find(x=>x.host===selectedHost); if(!r) return;
  $("#pi-host").textContent=selectedHost;
  $("#pi-ips").textContent=selectedIp||portLabel(r.open_ports_total||(r.open_ports||[]).length);
  const back=$("#pi-back"); if(back) back.hidden=!selectedIp;
  $("#pi-body").innerHTML=overlayBody(r);
  $("#overlay").hidden=false;
}
function openHost(host){ selectedHost=host; selectedIp=null; drawOverlay(); }
function closeOverlay(){ selectedHost=null; selectedIp=null; $("#overlay").hidden=true; }
document.addEventListener("DOMContentLoaded",()=>{
  render(); extras();
  ["f-q","f-host","f-ip","f-ports","f-source","f-tag","f-tech","f-length","f-alive"].forEach(id=>{const el=document.getElementById(id); if(el){el.addEventListener("input",render); el.addEventListener("change",render);}});
  $("#f-apply")&&$("#f-apply").addEventListener("click",render);
  $("#f-clear")&&$("#f-clear").addEventListener("click",()=>{["f-q","f-host","f-ip","f-source","f-tag","f-tech","f-length"].forEach(id=>{const el=document.getElementById(id); if(el) el.value=""}); if($("#f-alive")) $("#f-alive").value=""; if($("#f-ports")) $("#f-ports").value=""; render();});
  document.addEventListener("click",ev=>{
    const hostBtn=ev.target.closest("[data-host]"); if(hostBtn){openHost(hostBtn.getAttribute("data-host")); return;}
    const ipBtn=ev.target.closest("[data-ip]"); if(ipBtn&&selectedHost){selectedIp=ipBtn.getAttribute("data-ip")||""; drawOverlay(); return;}
    if(ev.target.id==="pi-back"&&selectedIp){selectedIp=null; drawOverlay(); return;}
    if(ev.target.id==="pi-close"||ev.target.id==="overlay") closeOverlay();
  });
  document.addEventListener("keydown",ev=>{
    if(ev.key!=="Escape") return;
    if(selectedIp){selectedIp=null; drawOverlay();}
    else closeOverlay();
  });
});
"""


def render_html(bundle: dict[str, Any], diff: dict[str, Any] | None = None) -> str:
    facts = bundle.get("facts") or {}
    counts = bundle.get("counts") or {}
    new_hosts = {str(r.get("host")) for r in ((diff or {}).get("added") or {}).get("hosts") or []}
    hosts = []
    for row in bundle.get("hosts") or []:
        hosts.append({
            "host": row.get("host"),
            "ips": list(row.get("ips") or []),
            "alive": bool(row.get("alive")),
            "length": row.get("length"),
            "tech": list(row.get("tech") or []),
            "sources": list(row.get("sources") or []),
            "tags": list(row.get("tags") or []),
            "is_new": str(row.get("host")) in new_hosts,
            "open_ports": list(row.get("open_ports") or []),
            "open_ports_total": int(row.get("open_ports_total") or len(row.get("open_ports") or [])),
            "open_ports_by_ip": list(row.get("open_ports_by_ip") or []),
        })
    payload = {
        "target": bundle.get("target"),
        "run_timestamp": bundle.get("run_timestamp"),
        "scope_digest": bundle.get("scope_digest"),
        "counts": counts,
        "hosts": hosts,
        "vhosts": list(facts.get("vhosts") or []),
        "services": list(facts.get("services") or []),
    }
    blob = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    target = bundle.get("target") or ""
    stamp = bundle.get("run_timestamp") or ""
    digest = bundle.get("scope_digest") or ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack Surface Management | {target}</title>
<style>{_CSS}</style></head><body>
<div class="wrap">
  <header class="hero">
    <div class="logo">{_LOGO}</div>
    <div>
      <div class="kicker">operator console</div>
      <div class="title">ASM ATTACK SURFACE <span class="accent">MANAGEMENT</span></div>
      <div class="sub">{target} &nbsp;|&nbsp; run timestamp: {stamp} &nbsp;|&nbsp; scope digest: {digest}</div>
    </div>
  </header>
  <div class="counts">
    <span class="badge">hosts: {counts.get("hosts", 0)}</span>
    <span class="badge alive">alive: {counts.get("alive_hosts", 0)}</span>
    <span class="badge">open-port rows: {counts.get("open_port_rows", 0)}</span>
    <span class="badge">vhosts: {len(payload["vhosts"])}</span>
    <span class="badge">services: {len(payload["services"])}</span>
    <span class="badge">module data.json: {counts.get("module_docs", 0)}</span>
  </div>
  <p class="dim">DNS names {facts.get("dns_names", 0)} (A/AAAA {facts.get("dns_with_ip", 0)}).
  Click the port count, then an IP, to see port, product, and version. Palette #0a0e14 / #070b12.</p>
  <div class="filters">
    <input id="f-q" placeholder="free-text search">
    <input id="f-host" placeholder="host">
    <input id="f-ip" placeholder="ip">
    <select id="f-ports"><option value="">ports: any</option><option value="open">has open ports</option><option value="none">no open ports</option></select>
    <select id="f-alive"><option value="">alive: any</option><option value="true">alive</option><option value="false">dead</option></select>
    <input id="f-length" placeholder="length">
    <input id="f-tech" placeholder="tech">
    <input id="f-source" placeholder="source (subfinder, crtsh...)">
    <input id="f-tag" placeholder="tag (dev, stage...)">
    <button type="button" class="primary" id="f-apply">APPLY</button>
    <button type="button" id="f-clear">CLEAR</button>
    <span id="asset-meta" class="dim"></span>
  </div>
  <h2>ASSETS <span class="hint">click a live host to open it — click the port count, then an IP, for port / product / version</span></h2>
  <div class="table-wrap"><table id="assets-table">
    <thead><tr><th>host</th><th>open ports</th><th>alive</th><th>length</th><th>sources</th><th>tags</th></tr></thead>
    <tbody></tbody>
  </table></div>
  <h2>SERVICES <span class="hint">nmap -sV fingerprints, one row per IP:port</span></h2>
  <div class="table-wrap"><table id="services-table">
    <thead><tr><th>ip</th><th>port</th><th>service</th><th>product</th><th>version</th></tr></thead>
    <tbody></tbody>
  </table></div>
  <h2>VHOSTS</h2>
  <div class="table-wrap"><table id="vhosts-table">
    <thead><tr><th>vhost</th><th>base host</th><th>ip</th><th>port</th><th>alive</th></tr></thead>
    <tbody></tbody>
  </table></div>
  <p class="foot">Attack Surface Management — only scan assets you own or have written permission to test.</p>
</div>
<div id="overlay" class="overlay" hidden>
  <div class="card">
    <div style="display:flex;justify-content:space-between;gap:12px">
      <div><div class="kicker">open ports</div><h3 id="pi-host" style="margin:4px 0 0">—</h3><p id="pi-ips" class="dim"></p></div>
      <div class="head-actions"><button type="button" id="pi-back" hidden>BACK</button><button type="button" id="pi-close">CLOSE</button></div>
    </div>
    <div id="pi-body"></div>
  </div>
</div>
<script>const REPORT={blob};
{_JS}
</script>
</body></html>
"""


def write_report_html(params: Any, target_dir: Path, bundle: dict[str, Any], diff: dict[str, Any] | None = None) -> Path:
    out = target_dir / str(params.require("report_dirname")) / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(bundle, diff), encoding="utf-8")
    return out
