#!/usr/bin/env python3
"""
whitelist_review.py — Interactive HTML reviewer for log_analyzer error-signature
matches. Browse a scanned log folder, see every error-signature match attributed
back to its rule in the SUT settings json, then whitelist / edit the noisy ones.
Saving rewrites the settings.<sut>.json (with a timestamped backup) so the *next*
log_analyzer run produces fewer false matches.

It reproduces the EXACT log_analyzer matcher (common/lib_log.py log_analyzer()):
    matched if  any(err.lower()  in line.lower() for err   in error_text)
            and not any(wl.lower() in line.lower() for wl in whitelist_text)
    file scoped by glob.glob(scan/**/<file>) i.e. fnmatch(basename, file_pattern)

Workflow
--------
1. log_analyzer.py is run on a folder -> produces error-signatures-details.log
2. python whitelist_review.py --scan_folder <folder> [--settings <name|path>]
3. A browser opens a dashboard. Per signature you see its matched lines and the
   live count that each candidate whitelist entry would suppress.
4. Add whitelist terms / edit error_text, then Save (backs up json, writes it).
   Undo restores the most recent backup. Re-run invokes log_analyzer again.

Zero third-party deps (stdlib http.server).

Usage:
    python whitelist_review.py --scan_folder <run folder>
    python whitelist_review.py --scan_folder <run> --settings sample
    python whitelist_review.py --scan_folder <run> --settings "<path>/settings.X.json"
"""
import os
import re
import sys
import json
import glob
import shutil
import fnmatch
import argparse
import logging
import datetime
import threading
import webbrowser
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("whitelist_review")

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SUT_ROOT = SCRIPT_DIR.parent / "sut"
LOG_ANALYZER = SCRIPT_DIR / "log_analyzer.py"
BACKUP_DIRNAME = "whitelist_backups"


# ── report header/footer ──────────────────────────────────────────────────
# Cosmetic only: this must never be the reason a page or report fails.
try:
    _common_dir = str(Path(__file__).resolve().parent.parent / "common")
    if _common_dir not in sys.path:
        sys.path.insert(0, _common_dir)
    import brand
except Exception:                                        # pragma: no cover
    class brand:                                         # noqa: N801
        brandify = staticmethod(lambda page, *a, **k: page)
        _nil = staticmethod(lambda *a, **k: "")
        brand_css = favicon_tag = brand_chip = _nil
        brand_banner = brand_footer = _nil


# ── settings discovery ───────────────────────────────────────────────────


def find_settings_candidates(sut_root: Path):
    """All settings.*.json under the sut root (excludes our own backups)."""
    out = []
    for p in sut_root.rglob("settings.*.json"):
        if BACKUP_DIRNAME in p.parts:
            continue
        out.append(p)
    return sorted(out)


def resolve_settings(arg, sut_root: Path):
    """Resolve --settings: a full path, a bare 'sample' name, or None."""
    if arg:
        p = Path(arg)
        if p.is_file():
            return p
        name = arg
        if name.startswith("settings."):
            name = name[len("settings."):]
        if name.endswith(".json"):
            name = name[:-len(".json")]
        for c in sut_root.rglob(f"settings.{name}.json"):
            if BACKUP_DIRNAME not in c.parts:
                return c
        raise SystemExit(f"settings file for '{arg}' not found under {sut_root}")
    return None


def load_config(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# ── details-log parsing ──────────────────────────────────────────────────
def parse_details(scan_folder: Path):
    """Parse error-signatures-details.log -> [{'line':..,'file':..}]."""
    f = scan_folder / "error-signatures-details.log"
    if not f.is_file():
        return None
    text = f.read_text(encoding="utf-8", errors="replace")
    matches = []
    for block in text.split("============"):
        block = block.strip()
        if not block:
            continue
        line_val = ""
        file_val = ""
        for ln in block.split("\n"):
            s = ln.strip()
            if s.startswith("Category:"):
                line_val = s[len("Category:"):].strip()
            elif s.startswith("File Path:"):
                file_val = s[len("File Path:"):].strip()
        if line_val:
            matches.append({"line": line_val, "file": file_val})
    return matches


# ── attribution (reproduces lib_log matcher) ─────────────────────────────
def _err_hit(line, error_text):
    ll = line.lower()
    for e in error_text:
        if e and e.lower() in ll:
            return e
    # exact lib_log semantics also count empty error_text as a hit; mirror it
    for e in error_text:
        if e == "" and "" in ll:
            return ""
    return None


def _wl_suppressed(line, whitelist_text):
    ll = line.lower()
    return any((w.lower() in ll) for w in whitelist_text)


def attribute(matches, config):
    """Attribute each matched line to the ERROR signature(s) that produced it.

    Returns (signatures, unattributed) where signatures is a list aligned to a
    subset of config['error_signatures'] (only ERROR sigs that own >=1 match),
    each carrying its deduped matched lines.
    """
    sigs = config.get("error_signatures", [])
    # per-signature accumulator keyed by sig index
    acc = {}
    unattributed = {}

    for m in matches:
        line = m["line"]
        base = os.path.basename(m["file"]) if m["file"] else ""
        owned = False
        for idx, sig in enumerate(sigs):
            if (sig.get("match_type", "ERROR").upper()) != "ERROR":
                continue
            patt = sig.get("file", "")
            if base and patt and not fnmatch.fnmatch(base, patt):
                continue
            if not base and patt:
                # no file recorded — fall back to text-only attribution
                pass
            error_text = sig.get("error_text", [])
            whitelist = sig.get("whitelist_text", [])
            term = _err_hit(line, error_text)
            if term is None:
                continue
            if _wl_suppressed(line, whitelist):
                continue
            owned = True
            d = acc.setdefault(idx, {})
            rec = d.get(line)
            if rec is None:
                d[line] = {"line": line, "count": 1, "files": {base} if base else set(), "term": term}
            else:
                rec["count"] += 1
                if base:
                    rec["files"].add(base)
        if not owned:
            rec = unattributed.get(line)
            if rec is None:
                unattributed[line] = {"line": line, "count": 1, "files": {base} if base else set()}
            else:
                rec["count"] += 1
                if base:
                    rec["files"].add(base)

    signatures = []
    for idx, sig in enumerate(sigs):
        if idx not in acc:
            continue
        lines = sorted(acc[idx].values(), key=lambda r: -r["count"])
        for r in lines:
            r["files"] = sorted(r["files"])
        signatures.append({
            "index": idx,
            "description": sig.get("description", ""),
            "match_type": sig.get("match_type", "ERROR"),
            "file": sig.get("file", ""),
            "error_text": sig.get("error_text", []),
            "whitelist_text": sig.get("whitelist_text", []),
            "comment": sig.get("comment", ""),
            "total_matches": sum(r["count"] for r in lines),
            "distinct": lines,
        })
    signatures.sort(key=lambda s: -s["total_matches"])

    un = sorted(unattributed.values(), key=lambda r: -r["count"])
    for r in un:
        r["files"] = sorted(r["files"])
    return signatures, un


def autodetect_settings(matches, candidates):
    """Pick the settings file whose ERROR signatures attribute the most matches."""
    best, best_cov = None, -1
    for c in candidates:
        try:
            cfg = load_config(c)
        except Exception:
            continue
        sigs, _ = attribute(matches, cfg)
        cov = sum(s["total_matches"] for s in sigs)
        if cov > best_cov:
            best, best_cov = c, cov
    return best, best_cov


# ── backup / save / undo ─────────────────────────────────────────────────
def backup_dir_for(settings_path: Path):
    d = settings_path.parent / BACKUP_DIRNAME
    d.mkdir(exist_ok=True)
    return d


def make_backup(settings_path: Path):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = backup_dir_for(settings_path) / f"{settings_path.stem}.{ts}.bak"
    shutil.copy2(settings_path, dest)
    log.info("Backed up %s -> %s", settings_path.name, dest.name)
    return dest


def list_backups(settings_path: Path):
    d = settings_path.parent / BACKUP_DIRNAME
    if not d.is_dir():
        return []
    return sorted(d.glob(f"{settings_path.stem}.*.bak"))


def apply_changes(settings_path: Path, changes):
    """changes = {'<sig_index>': {'whitelist_text':[...], 'error_text':[...]}}.
    Backs up then writes. Returns backup path name."""
    cfg = load_config(settings_path)
    sigs = cfg.get("error_signatures", [])
    for k, upd in changes.items():
        idx = int(k)
        if idx < 0 or idx >= len(sigs):
            continue
        if "whitelist_text" in upd:
            wl = [str(x) for x in upd["whitelist_text"]]
            # de-dupe preserving order, drop blanks the user didn't intend
            seen, clean = set(), []
            for w in wl:
                if w in seen:
                    continue
                seen.add(w)
                clean.append(w)
            sigs[idx]["whitelist_text"] = clean
        if "error_text" in upd:
            sigs[idx]["error_text"] = [str(x) for x in upd["error_text"]]
    bk = make_backup(settings_path)
    settings_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.info("Saved %s (%d signature change(s))", settings_path.name, len(changes))
    return bk.name


def undo_last(settings_path: Path):
    bks = list_backups(settings_path)
    if not bks:
        return None
    last = bks[-1]
    shutil.copy2(last, settings_path)
    last.unlink()
    log.info("Undo: restored %s from %s (and removed that backup)", settings_path.name, last.name)
    return last.name


# ── server state ─────────────────────────────────────────────────────────
class State:
    def __init__(self, scan_folder, settings_path, signature_name):
        self.scan_folder = Path(scan_folder)
        self.settings_path = Path(settings_path)
        self.signature_name = signature_name

    def build(self):
        matches = parse_details(self.scan_folder)
        if matches is None:
            return {"error": f"error-signatures-details.log not found in {self.scan_folder}"}
        cfg = load_config(self.settings_path)
        sigs, un = attribute(matches, cfg)
        return {
            "scan_folder": str(self.scan_folder),
            "settings_path": str(self.settings_path),
            "settings_name": self.settings_path.name,
            "sut_sku": cfg.get("SUT_SKU", ""),
            "signature_name": self.signature_name,
            "total_matches": len(matches),
            "attributed": sum(s["total_matches"] for s in sigs),
            "signatures": sigs,
            "unattributed": un[:200],
            "unattributed_count": len(un),
            "backups": [b.name for b in list_backups(self.settings_path)],
        }


STATE = None  # set in main


# ── HTTP ─────────────────────────────────────────────────────────────────
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Whitelist Review</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--fg:#c9d1d9;--mut:#8b949e;
--red:#f85149;--grn:#3fb950;--yel:#d29922;--blu:#58a6ff;--acc:#1f6feb;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font-family:Segoe UI,Arial,sans-serif;font-size:13px}
header{position:sticky;top:0;z-index:10;background:#010409;border-bottom:1px solid var(--bd);
padding:10px 16px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
header .t{font-size:15px;font-weight:600;color:#fff}
header .meta{color:var(--mut);font-size:12px}
header .sp{flex:1}
button{background:var(--panel);color:var(--fg);border:1px solid var(--bd);border-radius:6px;
padding:6px 12px;cursor:pointer;font-size:12px}
button:hover{border-color:var(--blu)}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff}
button.warn{border-color:var(--yel);color:var(--yel)}
button:disabled{opacity:.4;cursor:not-allowed}
#wrap{padding:14px 16px;max-width:1500px;margin:0 auto}
.bar{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:10px 14px;
margin-bottom:14px;display:flex;gap:22px;flex-wrap:wrap;align-items:center}
.bar b{color:#fff}
.stat{font-size:18px;font-weight:700}
.sig{background:var(--panel);border:1px solid var(--bd);border-radius:8px;margin-bottom:14px;overflow:hidden}
.sig.dirty{border-color:var(--yel)}
.sig h3{margin:0;padding:10px 14px;background:#11161d;border-bottom:1px solid var(--bd);
display:flex;gap:10px;align-items:center;cursor:pointer}
.sig h3 .desc{font-size:14px;color:#fff}
.sig h3 .cnt{margin-left:auto;color:var(--red);font-weight:700}
.sig .body{padding:12px 14px;display:none}
.sig.open .body{display:block}
.glob{font-family:Consolas,monospace;color:var(--blu);font-size:12px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}
.chip{background:#21262d;border:1px solid var(--bd);border-radius:12px;padding:2px 9px;font-size:11px;
font-family:Consolas,monospace;display:flex;align-items:center;gap:6px}
.chip.err{color:var(--yel)}
.chip.wl{color:var(--grn)}
.chip .x{cursor:pointer;color:var(--mut);font-weight:700}
.chip .x:hover{color:var(--red)}
.lbl{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-top:10px}
table{width:100%;border-collapse:collapse;margin-top:6px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:top;font-size:12px}
th{color:var(--mut);font-weight:600}
tr.sup td{opacity:.35;text-decoration:line-through}
.lntext{font-family:Consolas,monospace;font-size:11px;color:var(--fg);word-break:break-all;max-width:760px}
.cnt2{color:var(--red);font-weight:700;text-align:right;width:46px}
.files{color:var(--mut);font-size:10px}
.term{color:var(--yel);font-family:Consolas,monospace;font-size:11px}
.wlbtn{white-space:nowrap}
.addwl{display:flex;gap:6px;margin-top:8px}
.addwl input{flex:1;background:#0d1117;border:1px solid var(--bd);color:var(--fg);border-radius:6px;
padding:5px 8px;font-family:Consolas,monospace;font-size:12px}
.toast{position:fixed;bottom:20px;right:20px;background:#11161d;border:1px solid var(--grn);
color:var(--grn);padding:10px 16px;border-radius:8px;display:none;z-index:50}
.toast.err{border-color:var(--red);color:var(--red)}
.supnote{color:var(--grn);font-size:11px;margin-left:8px}
small.mut{color:var(--mut)}
</style></head><body>
<header>
<span class="t">🧹 Whitelist Review</span>
<span class="meta" id="hmeta"></span>
<span class="sp"></span>
<span id="dirtybadge" class="meta"></span>
<button id="btnSave" class="primary" disabled>💾 Save</button>
<button id="btnUndo" class="warn">↩ Undo last</button>
<button id="btnRerun">🔁 Re-run analyzer</button>
<button id="btnReload">⟳ Reload</button>
</header>
<div id="wrap"><div id="content">Loading…</div></div>
<div id="toast" class="toast"></div>
<script>
let DATA=null;          // server state
let PENDING={};         // sigIndex -> {whitelist_text:[...], error_text:[...]}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function toast(msg,isErr){const t=document.getElementById('toast');t.textContent=msg;
 t.className='toast'+(isErr?' err':'');t.style.display='block';setTimeout(()=>t.style.display='none',3500);}
function curWL(sig){return PENDING[sig.index]&&PENDING[sig.index].whitelist_text?PENDING[sig.index].whitelist_text:sig.whitelist_text.slice();}
function curET(sig){return PENDING[sig.index]&&PENDING[sig.index].error_text?PENDING[sig.index].error_text:sig.error_text.slice();}
function suppressed(line,wl){const ll=line.toLowerCase();return wl.some(w=>w&&ll.includes(w.toLowerCase()));}
function suggest(line){
 let m=line.match(/errors of type '([^']+)'/i); if(m)return m[1];
 m=line.match(/Message:(.*?),[A-Za-z_]+:/); if(m){let s=m[1].trim(); if(s.length>4&&s.toLowerCase()!=='none')return s.slice(0,160);}
 return line.trim().slice(0,160);
}
function markDirty(){
 const n=Object.keys(PENDING).length;
 document.getElementById('btnSave').disabled=n===0;
 document.getElementById('dirtybadge').textContent=n?('● '+n+' unsaved signature change(s)'):'';
 document.getElementById('dirtybadge').style.color=n?'#d29922':'';
}
function setWL(idx,wl){PENDING[idx]=PENDING[idx]||{};PENDING[idx].whitelist_text=wl;markDirty();render();}
function setET(idx,et){PENDING[idx]=PENDING[idx]||{};PENDING[idx].error_text=et;markDirty();render();}

function render(){
 if(!DATA){return;}
 if(DATA.error){document.getElementById('content').innerHTML='<div class="bar" style="border-color:#f85149;color:#f85149">'+esc(DATA.error)+'</div>';return;}
 document.getElementById('hmeta').innerHTML=esc(DATA.settings_name)+' &nbsp;·&nbsp; SKU '+esc(DATA.sut_sku);
 let h='';
 h+='<div class="bar">';
 h+='<div><div class="stat">'+DATA.total_matches+'</div><small class="mut">total match lines</small></div>';
 h+='<div><div class="stat">'+DATA.signatures.length+'</div><small class="mut">signatures firing</small></div>';
 h+='<div><div class="stat">'+DATA.attributed+'</div><small class="mut">attributed</small></div>';
 h+='<div><div class="stat">'+DATA.unattributed_count+'</div><small class="mut">unattributed</small></div>';
 h+='<div style="flex:1"></div>';
 h+='<div style="max-width:560px"><small class="mut">settings: </small><span class="glob">'+esc(DATA.settings_path)+'</span><br>';
 h+='<small class="mut">scan: '+esc(DATA.scan_folder)+'</small><br>';
 h+='<small class="mut">backups: '+DATA.backups.length+(DATA.backups.length?(' (latest '+esc(DATA.backups[DATA.backups.length-1])+')'):'')+'</small></div>';
 h+='</div>';

 for(const sig of DATA.signatures){
   const wl=curWL(sig), et=curET(sig);
   let supTotal=0, supLines=0;
   for(const r of sig.distinct){if(suppressed(r.line,wl)){supTotal+=r.count;supLines++;}}
   const dirty=!!PENDING[sig.index];
   const open=sig._open!==false;
   h+='<div class="sig'+(dirty?' dirty':'')+(open?' open':'')+'" data-idx="'+sig.index+'">';
   h+='<h3 onclick="toggleSig('+sig.index+')"><span class="desc">'+esc(sig.description)+'</span>';
   h+='<span class="glob">'+esc(sig.file)+'</span>';
   if(supTotal>0)h+='<span class="supnote">− '+supTotal+' line(s) / '+supLines+' pattern(s) would be suppressed</span>';
   h+='<span class="cnt">'+sig.total_matches+' hits</span></h3>';
   h+='<div class="body">';
   // error_text
   h+='<div class="lbl">error_text (any-of triggers a match)</div><div class="chips">';
   et.forEach((e,i)=>{h+='<span class="chip err">'+esc(e||'(empty)')+'<span class="x" onclick="rmET('+sig.index+','+i+')">×</span></span>';});
   h+='<span class="chip" style="cursor:pointer;color:#58a6ff" onclick="addET('+sig.index+')">+ add</span>';
   h+='</div>';
   // whitelist
   h+='<div class="lbl">whitelist_text (any-of suppresses the line) — edit me to cut noise</div><div class="chips">';
   wl.forEach((w,i)=>{h+='<span class="chip wl">'+esc(w||'(empty)')+'<span class="x" onclick="rmWL('+sig.index+','+i+')">×</span></span>';});
   if(!wl.length)h+='<small class="mut">none</small>';
   h+='</div>';
   h+='<div class="addwl"><input id="wlin_'+sig.index+'" placeholder="add whitelist substring (case-insensitive)…">'+
      '<button onclick="addWLfromInput('+sig.index+')">+ whitelist</button></div>';
   // matched lines
   h+='<div class="lbl">matched lines ('+sig.distinct.length+' distinct)</div>';
   h+='<table><tr><th class="cnt2">#</th><th>line</th><th>trigger</th><th>action</th></tr>';
   for(const r of sig.distinct){
     const sup=suppressed(r.line,wl);
     h+='<tr class="'+(sup?'sup':'')+'">';
     h+='<td class="cnt2">'+r.count+'</td>';
     h+='<td><div class="lntext">'+esc(r.line.length>320?r.line.slice(0,320)+'…':r.line)+'</div>';
     if(r.files&&r.files.length)h+='<div class="files">'+esc(r.files.join(', '))+'</div>';
     h+='</td>';
     h+='<td class="term">'+esc(r.term||'')+'</td>';
     h+='<td class="wlbtn"><button onclick="wlSuggest('+sig.index+',this)" data-line="'+esc(r.line).replace(/"/g,'&quot;')+'">whitelist…</button></td>';
     h+='</tr>';
   }
   h+='</table></div></div>';
 }
 if(DATA.unattributed&&DATA.unattributed.length){
   h+='<div class="sig"><h3 onclick="this.parentNode.classList.toggle(\'open\')"><span class="desc">Unattributed lines</span>'+
      '<span class="cnt">'+DATA.unattributed_count+'</span></h3><div class="body"><table>'+
      '<tr><th class="cnt2">#</th><th>line</th><th>files</th></tr>';
   for(const r of DATA.unattributed){h+='<tr><td class="cnt2">'+r.count+'</td><td class="lntext">'+esc(r.line.slice(0,320))+'</td><td class="files">'+esc((r.files||[]).join(', '))+'</td></tr>';}
   h+='</table></div></div>';
 }
 document.getElementById('content').innerHTML=h;
 markDirty();
}
function toggleSig(idx){const s=DATA.signatures.find(s=>s.index===idx);s._open=!(s._open!==false);render();}
function rmWL(idx,i){const sig=DATA.signatures.find(s=>s.index===idx);const wl=curWL(sig);wl.splice(i,1);setWL(idx,wl);}
function rmET(idx,i){const sig=DATA.signatures.find(s=>s.index===idx);const et=curET(sig);et.splice(i,1);setET(idx,et);}
function addET(idx){const v=prompt('New error_text substring:');if(v===null||v==='')return;const sig=DATA.signatures.find(s=>s.index===idx);const et=curET(sig);et.push(v);setET(idx,et);}
function addWLfromInput(idx){const el=document.getElementById('wlin_'+idx);const v=el.value.trim();if(!v)return;const sig=DATA.signatures.find(s=>s.index===idx);const wl=curWL(sig);if(!wl.includes(v))wl.push(v);setWL(idx,wl);}
function wlSuggest(idx,btn){const line=btn.getAttribute('data-line');const sug=suggest(line);
 const v=prompt('Whitelist substring (will suppress every line containing it, case-insensitive):',sug);
 if(v===null||v==='')return;const sig=DATA.signatures.find(s=>s.index===idx);const wl=curWL(sig);if(!wl.includes(v))wl.push(v);setWL(idx,wl);}

async function load(){
 const r=await fetch('/api/state');DATA=await r.json();PENDING={};
 // preserve open state default true
 if(DATA.signatures)DATA.signatures.forEach(s=>s._open=(s.total_matches>0));
 render();
}
document.getElementById('btnReload').onclick=load;
document.getElementById('btnSave').onclick=async()=>{
 if(!Object.keys(PENDING).length)return;
 const r=await fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({changes:PENDING})});
 const j=await r.json();
 if(j.ok){toast('Saved. Backup: '+j.backup);await load();}else{toast('Save failed: '+(j.error||'?'),true);}
};
document.getElementById('btnUndo').onclick=async()=>{
 if(!confirm('Restore the most recent backup of '+DATA.settings_name+'? This discards the last saved change.'))return;
 const r=await fetch('/api/undo',{method:'POST'});const j=await r.json();
 if(j.ok){toast('Undo: restored from '+j.restored);await load();}else{toast(j.error||'No backup to undo',true);}
};
document.getElementById('btnRerun').onclick=async()=>{
 if(!confirm('Re-run log_analyzer on this folder with the saved settings? This can take several minutes (LLM summary + good-log compare).'))return;
 toast('Re-running log_analyzer… watch the console window.');
 const r=await fetch('/api/rerun',{method:'POST'});const j=await r.json();
 if(j.ok){toast('Re-run done (rc='+j.rc+'). Reloading.');await load();}else{toast('Re-run failed: '+(j.error||'?'),true);}
};
load();
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return  # quiet

    def _send(self, code, body, ctype="application/json"):
        # Brand at the single HTML exit: every route that ever returns a page
        # is covered here, so no future route can ship unbranded.
        if "html" in ctype and not isinstance(body, bytes):
            body = brand.brandify(body, "Whitelist Review")
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "json" in ctype or "html" in ctype else ""))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, default=list), "application/json")

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, "text/html")
        elif self.path == "/api/state":
            self._json(STATE.build())
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        try:
            if self.path == "/api/save":
                changes = self._body().get("changes", {})
                if not changes:
                    return self._json({"ok": False, "error": "no changes"})
                bk = apply_changes(STATE.settings_path, changes)
                return self._json({"ok": True, "backup": bk})
            if self.path == "/api/undo":
                restored = undo_last(STATE.settings_path)
                if not restored:
                    return self._json({"ok": False, "error": "no backup to undo"})
                return self._json({"ok": True, "restored": restored})
            if self.path == "/api/rerun":
                rc = rerun_analyzer()
                return self._json({"ok": rc is not None, "rc": rc})
            self._send(404, b"not found", "text/plain")
        except Exception as e:
            log.exception("POST %s failed", self.path)
            self._json({"ok": False, "error": str(e)}, 500)


def rerun_analyzer():
    import subprocess
    if not STATE.signature_name:
        log.error("Cannot re-run: signature name unknown (use --settings <name>)")
        return None
    cmd = [sys.executable, str(LOG_ANALYZER), "--scan_folder", str(STATE.scan_folder),
           "--signature", STATE.signature_name, "--to_csv", "true",
           "--compare_good_log", "true", "--result_analyzer", "true"]
    log.info("Re-running: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, cwd=str(SCRIPT_DIR))
        return r.returncode
    except Exception as e:
        log.error("re-run failed: %s", e)
        return None


def main():
    global STATE
    ap = argparse.ArgumentParser(description="Interactive whitelist reviewer for log_analyzer matches")
    ap.add_argument("--scan_folder", required=True, help="Folder that log_analyzer scanned (has error-signatures-details.log)")
    ap.add_argument("--settings", help="settings name (e.g. sample) or full path to settings.<x>.json. Auto-detected if omitted.")
    ap.add_argument("--sut-root", default=str(DEFAULT_SUT_ROOT), help="Root to search settings.*.json")
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    scan = Path(args.scan_folder)
    if not scan.is_dir():
        raise SystemExit(f"scan folder not found: {scan}")
    sut_root = Path(args.sut_root)

    settings_path = resolve_settings(args.settings, sut_root)
    signature_name = None
    if settings_path is None:
        matches = parse_details(scan)
        if matches is None:
            raise SystemExit(f"error-signatures-details.log not found in {scan} — run log_analyzer first.")
        cands = find_settings_candidates(sut_root)
        settings_path, cov = autodetect_settings(matches, cands)
        if settings_path is None:
            raise SystemExit("could not auto-detect a settings file; pass --settings")
        log.info("Auto-detected settings: %s (covers %d matches)", settings_path, cov)
    # derive bare signature name for re-run
    if settings_path.name.startswith("settings.") and settings_path.name.endswith(".json"):
        signature_name = settings_path.name[len("settings."):-len(".json")]
    if args.settings and not Path(args.settings).is_file():
        signature_name = args.settings.replace("settings.", "").replace(".json", "")

    STATE = State(scan, settings_path, signature_name)
    # sanity build
    st = STATE.build()
    if "error" in st:
        raise SystemExit(st["error"])
    log.info("Settings : %s", settings_path)
    log.info("Scan     : %s", scan)
    log.info("Matches  : %d total, %d attributed across %d firing signatures",
             st["total_matches"], st["attributed"], len(st["signatures"]))

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    log.info("Serving whitelist review UI at %s  (Ctrl-C to stop)", url)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("Stopped.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
