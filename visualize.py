#!/usr/bin/env python3
"""
PhoenixCarve — Phase 3: Visual Evidence Map
Single self-contained HTML file: entropy map of the whole disk + carved files +
suspicious regions + clickable hex viewer. Browser-la open pannaa podhum, server venaam.

Usage: python3 visualize.py evidence.dd out/report.json [-o out/phoenix_map.html]
"""
import argparse
import base64
import json
import os

from entropy import analyze

FULL_EMBED_LIMIT = 16 * 1024 * 1024   # embed whole image below this size
SLICE = 4096


def build_slices(image, size, points):
    with open(image, "rb") as f:
        if size <= FULL_EMBED_LIMIT:
            return [[0, base64.b64encode(f.read()).decode()]]
        out, seen = [], set()
        for p in sorted(set([0] + points)):
            s = max(0, (p - 256) // 16 * 16)
            if s in seen:
                continue
            seen.add(s)
            f.seek(s)
            out.append([s, base64.b64encode(f.read(SLICE)).decode()])
        return out


def build_map(image, report_path, out=None, block=None):
    rep = json.load(open(report_path))
    ent = analyze(image, report_path, block)
    out_dir = os.path.dirname(report_path)
    json.dump(ent, open(os.path.join(out_dir, "entropy.json"), "w"), indent=2)

    points = [c["start_offset"] for c in rep["carved"]] + [u["start"] for u in ent["unexplained_high_entropy"]]
    payload = {
        "evidence": {**rep["evidence"], "name": os.path.basename(image)},
        "validation": rep.get("validation", {}),
        "carved": rep["carved"],
        "block_size": ent["block_size"],
        "entropy": [b["entropy"] for b in ent["blocks"]],
        "distribution": ent["class_distribution"],
        "unexplained": ent["unexplained_high_entropy"],
        "zero_regions": [r for r in ent["regions"] if r["class"] == "zero"],
        "slices": build_slices(image, rep["evidence"]["size"], points),
    }
    html = TEMPLATE.replace("__DATA__", json.dumps(payload).replace("</", "<\\/"))
    out = out or os.path.join(out_dir, "phoenix_map.html")
    with open(out, "w") as f:
        f.write(html)
    return out, ent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("report")
    ap.add_argument("-b", "--block", type=int, default=None)
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    out, _ = build_map(a.image, a.report, a.out, a.block)
    print(f"[*] Visual map saved: {out}")
    print(f"    open {out}")


TEMPLATE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhoenixCarve evidence map</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{
  --ash:#262321; --ash-2:#2f2b28; --ash-3:#3a3532; --bone:#e9e3d7; --muted:#9c948a;
  --ember:#e2552e; --amber:#d9a441; --slate:#5d7e99;
  --sans:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ash);color:var(--bone);font:15px/1.5 var(--sans)}
main{max-width:1180px;margin:0 auto;padding:40px 24px 64px}
h1{font-size:44px;line-height:1;margin:0 0 6px;font-weight:700;letter-spacing:-.02em}
h2{font-size:17px;margin:0 0 12px;font-weight:600}
.lede{color:var(--muted);margin:0 0 4px;max-width:72ch}
.hash{font:12px var(--mono);color:var(--muted);word-break:break-all}
.story{font-size:20px;max-width:60ch;margin:28px 0 20px;line-height:1.4}
.story b{color:var(--amber);font-weight:500}
.story .warn{color:var(--ember)}
.mapwrap{position:relative;margin:0 0 10px}
canvas{display:block;width:100%;border-radius:3px;cursor:crosshair;image-rendering:pixelated}
#tip{position:fixed;pointer-events:none;background:var(--bone);color:var(--ash);padding:6px 9px;
  border-radius:3px;font:12px/1.4 var(--mono);display:none;z-index:5;max-width:320px}
.legend{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:13px;flex-wrap:wrap}
.ramp{height:10px;width:220px;border-radius:2px;
  background:linear-gradient(90deg,#3a3532 0%,#5d7e99 30%,#d9a441 62%,#e2552e 88%,#ff6a3d 100%)}
.key{display:inline-flex;align-items:center;gap:6px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.grid{display:grid;grid-template-columns:minmax(0,5fr) minmax(0,7fr);gap:32px;margin-top:36px}
@media (max-width:860px){.grid{grid-template-columns:minmax(0,1fr)}}
ul{list-style:none;margin:0 0 28px;padding:0}
li button{all:unset;box-sizing:border-box;display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:10px;width:100%;
  padding:8px 10px;border-radius:3px;cursor:pointer;align-items:baseline}
li button:hover,li button[aria-current=true]{background:var(--ash-2)}
li button:focus-visible{outline:2px solid var(--amber);outline-offset:1px}
.fname{font:13px var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.meta{color:var(--muted);font-size:12px}
.why{grid-column:2/4;min-width:0;color:var(--muted);font-size:12px;margin-top:-4px}
.hex{background:var(--ash-2);border-radius:3px;padding:14px 16px;overflow-x:auto}
.hexhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:10px;flex-wrap:wrap}
.hexhead input{background:var(--ash);color:var(--bone);border:1px solid var(--ash-3);border-radius:3px;
  font:13px var(--mono);padding:5px 8px;width:130px}
.hexhead button{background:var(--ash-3);color:var(--bone);border:0;border-radius:3px;padding:6px 11px;
  font:13px var(--sans);cursor:pointer}
.hexhead button:focus-visible,.hexhead input:focus-visible{outline:2px solid var(--amber)}
pre{margin:0;font:13px/1.65 var(--mono);white-space:pre}
.o{color:var(--muted)} .z{color:#6a625b} .na{color:#4a4440}
.valid{color:var(--amber)} .corrupt{color:var(--ember)} .unverified{color:var(--slate)}
.sig{font-weight:600;text-decoration:underline;text-underline-offset:3px}
.hl{background:#4a2a1f;color:#ffb39b}
#ctx{font-size:13px;color:var(--muted);margin-top:10px;min-height:20px}
@media (prefers-reduced-motion:no-preference){canvas{animation:rise .9s ease-out both}
  @keyframes rise{from{opacity:0;filter:brightness(2.2) saturate(.3)}to{opacity:1;filter:none}}}
</style></head>
<body><main>
<h1>PhoenixCarve</h1>
<p class="lede" id="evname"></p>
<p class="hash" id="evhash"></p>
<p class="story" id="story"></p>

<div class="mapwrap"><canvas id="map" role="img" aria-label="Entropy map of the disk image"></canvas></div>
<div class="legend">
  <span>Entropy 0</span><span class="ramp"></span><span>8 bits/byte</span>
  <span class="key"><span class="dot" style="background:var(--amber)"></span>valid file</span>
  <span class="key"><span class="dot" style="background:var(--ember)"></span>damaged file</span>
  <span class="key"><span class="dot" style="background:var(--slate)"></span>unverified</span>
  <span class="key"><span class="dot" style="background:none;border:2px dashed #ff6a3d"></span>unexplained high entropy</span>
</div>

<div class="grid">
  <section>
    <h2 id="anomh">Suspicious regions</h2><ul id="anoms"></ul>
    <h2>Recovered files</h2><ul id="files"></ul>
  </section>
  <section>
    <div class="hex">
      <div class="hexhead">
        <h2 style="margin:0">Hex view</h2>
        <span>
          <button id="prev" aria-label="Previous 256 bytes">Back</button>
          <input id="goto" aria-label="Jump to offset" placeholder="0x0000">
          <button id="next" aria-label="Next 256 bytes">Forward</button>
        </span>
      </div>
      <pre id="hexout"></pre>
      <div id="ctx"></div>
    </div>
  </section>
</div>
</main>
<div id="tip"></div>
<script>
const D = __DATA__;
const $ = id => document.getElementById(id);
const hex = (n,w=8) => "0x"+n.toString(16).padStart(w,"0");
const human = n => n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(2)+" MB";

// ---- byte store from embedded slices ----
const slices = D.slices.map(([o,b]) => { const s=atob(b), a=new Uint8Array(s.length);
  for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i); return [o,a]; });
function byteAt(o){ for(const [s,a] of slices) if(o>=s && o<s+a.length) return a[o-s]; return null; }

// ---- header ----
const ev = D.evidence, V = D.validation;
$("evname").textContent = `${ev.name}, ${human(ev.size)}. Evidence ${ev.integrity_preserved?"unchanged during analysis":"CHANGED during analysis"}.`;
$("evhash").textContent = "SHA-256 " + ev.sha256_before;
const nCor = V.corrupt||0, nU = D.unexplained.length;
$("story").innerHTML = `<b>${D.carved.length} files</b> brought back from unallocated space`
  + (nCor?`, <span class="warn">${nCor} of them damaged</span>`:"")
  + `. ${V.false_positives_dropped||0} false signature hits were rejected. `
  + (nU?`<span class="warn">${nU} region${nU>1?"s":""} of high-entropy data</span> ${nU>1?"match":"matches"} no known file and may be encrypted.`
       :"Every high-entropy region is explained by a recovered file.");

// ---- entropy map ----
const cv=$("map"), ctx=cv.getContext("2d"), N=D.entropy.length, BS=D.block_size;
const stops=[[0,[58,53,50]],[2.4,[93,126,153]],[5,[217,164,65]],[7.1,[226,85,46]],[8,[255,106,61]]];
function col(e){ for(let i=1;i<stops.length;i++){ const [x1,c1]=stops[i-1],[x2,c2]=stops[i];
  if(e<=x2){ const t=(e-x1)/(x2-x1); return c1.map((v,k)=>Math.round(v+(c2[k]-v)*t)); } } return stops[4][1]; }
const statusCol={valid:"#d9a441",corrupt:"#e2552e",unverified:"#5d7e99"};
let COLS, cell, rows;
function draw(){
  const W=cv.parentElement.clientWidth, dpr=window.devicePixelRatio||1;
  COLS = Math.max(16, Math.min(64, Math.ceil(Math.sqrt(N*4))));
  cell = W/COLS; rows=Math.ceil(N/COLS);
  cv.width=W*dpr; cv.height=rows*cell*dpr; cv.style.height=rows*cell+"px";
  ctx.setTransform(dpr,0,0,dpr,0,0);
  for(let i=0;i<N;i++){ const [r,g,b]=col(D.entropy[i]); ctx.fillStyle=`rgb(${r},${g},${b})`;
    ctx.fillRect((i%COLS)*cell,Math.floor(i/COLS)*cell,cell-1,cell-1); }
  // unexplained regions: dashed outline per block
  ctx.setLineDash([3,3]); ctx.lineWidth=2; ctx.strokeStyle="#ffd2c2";
  for(const u of D.unexplained) for(let i=Math.floor(u.start/BS);i<Math.ceil(u.end/BS);i++)
    ctx.strokeRect((i%COLS)*cell+2,Math.floor(i/COLS)*cell+2,cell-5,cell-5);
  ctx.setLineDash([]);
  // carved files: dot at start block
  for(const c of D.carved){ const i=Math.floor(c.start_offset/BS);
    ctx.fillStyle=statusCol[c.status]||"#fff"; ctx.strokeStyle="#262321"; ctx.lineWidth=1.5;
    ctx.beginPath(); ctx.arc((i%COLS)*cell+cell/2, Math.floor(i/COLS)*cell+cell/2, Math.max(3,cell/5),0,7);
    ctx.fill(); ctx.stroke(); }
}
function blockAt(ev){ const r=cv.getBoundingClientRect(); const x=Math.floor((ev.clientX-r.left)/cell),
  y=Math.floor((ev.clientY-r.top)/cell), i=y*COLS+x; return (x>=0&&x<COLS&&i<N)?i:-1; }
cv.addEventListener("mousemove",ev=>{ const i=blockAt(ev), t=$("tip"); if(i<0){t.style.display="none";return;}
  const s=i*BS, e=s+BS, fs=D.carved.filter(c=>c.start_offset<e&&c.end_offset>s).map(c=>c.file.split("/").pop());
  const u=D.unexplained.some(r=>r.start<e&&r.end>s);
  t.innerHTML=`${hex(s)}<br>entropy ${D.entropy[i].toFixed(2)}${u?"<br>unexplained high entropy":""}${fs.length?"<br>"+fs.join("<br>"):""}`;
  t.style.display="block"; t.style.left=Math.min(ev.clientX+14,innerWidth-330)+"px"; t.style.top=ev.clientY+14+"px"; });
cv.addEventListener("mouseleave",()=>$("tip").style.display="none");
cv.addEventListener("click",ev=>{ const i=blockAt(ev); if(i>=0) show(i*BS); });
addEventListener("resize",draw); draw();

// ---- lists ----
function item(label, meta, why, cls, off, list){
  const li=document.createElement("li"), b=document.createElement("button");
  b.innerHTML=`<span class="dot" style="background:${cls}"></span><span class="fname"></span><span class="meta"></span><span class="why"></span>`;
  b.querySelector(".fname").textContent=label; b.querySelector(".meta").textContent=meta; b.querySelector(".why").textContent=why;
  b.onclick=()=>{ document.querySelectorAll("li button").forEach(x=>x.removeAttribute("aria-current")); b.setAttribute("aria-current","true"); show(off); };
  li.appendChild(b); list.appendChild(li);
}
if(!D.unexplained.length && !D.zero_regions.length) $("anomh").style.display="none";
for(const u of D.unexplained) item(`${hex(u.start)} to ${hex(u.end)}`, human(u.size),
  `Average entropy ${u.avg_entropy}. No file signature here, likely encrypted or packed data.`, "#ff6a3d", u.start, $("anoms"));
for(const z of D.zero_regions.filter(z=>z.size>=Math.max(BS*2,4096))) item(`${hex(z.start)} to ${hex(z.end)}`, human(z.size),
  "Zero-filled. Consistent with a wiped area.", "#6a625b", z.start, $("anoms"));
for(const c of D.carved) item(c.file.split("/").pop(), human(c.size), c.reason, statusCol[c.status], c.start_offset, $("files"));

// ---- hex viewer ----
let cur=0;
function regionAt(o){ return D.carved.find(c=>o>=c.start_offset&&o<c.end_offset); }
function show(off){
  cur=Math.max(0,Math.min(Math.floor(off/16)*16, Math.max(0,ev.size-256)));
  const target=off; let out="";
  for(let r=0;r<16;r++){ const base=cur+r*16; if(base>=ev.size)break;
    let h="", a="";
    for(let k=0;k<16;k++){ const o=base+k; if(o>=ev.size){h+="   ";continue;}
      const b=byteAt(o); if(k===8)h+=" ";
      if(b===null){h+='<span class="na">··</span> '; a+='<span class="na">·</span>'; continue;}
      const rg=regionAt(o); let c=rg?rg.status:(b===0?"z":"");
      if(rg && (o-rg.start_offset<4 || rg.end_offset-o<=2)) c+=" sig";
      if(o===target) c+=" hl";
      const ch=b>=32&&b<127?String.fromCharCode(b).replace(/[<>&]/g,m=>({"<":"&lt;",">":"&gt;","&":"&amp;"}[m])):".";
      h+=`<span class="${c}">${b.toString(16).padStart(2,"0")}</span> `; a+=`<span class="${c}">${ch}</span>`; }
    out+=`<span class="o">${base.toString(16).padStart(8,"0")}</span>  ${h} ${a}\n`; }
  $("hexout").innerHTML=out; $("goto").value=hex(target);
  const rg=regionAt(target), bi=Math.floor(target/BS);
  $("ctx").textContent = (rg?`Inside ${rg.file.split("/").pop()} (${rg.status}): ${rg.reason}. `:"Unallocated / unidentified data. ")
    + `Block entropy ${D.entropy[bi]?.toFixed(2)}.`;
}
$("prev").onclick=()=>show(cur-256); $("next").onclick=()=>show(cur+256);
$("goto").addEventListener("keydown",e=>{ if(e.key==="Enter"){ const v=parseInt($("goto").value); if(!isNaN(v)) show(v);} });
show(D.carved[0]?.start_offset||0);
</script></body></html>
"""

if __name__ == "__main__":
    main()
