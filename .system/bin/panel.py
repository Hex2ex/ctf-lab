#!/usr/bin/env python3
"""CTF Lab panel — web UI bound to 127.0.0.1. It holds no lab logic: every action runs the `ctf` command.

Access:
  local   http://127.0.0.1:8765/?t=<token>   (Host must be 127.0.0.1/localhost, API calls carry X-Token)
  remote  https://<this-pc>:8443/            (Caddy: HTTPS + password; adds the secret X-CTF-Proxy header)
"""
import html, json, os, re, secrets, shutil, subprocess, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import progress  # noqa: E402  flag verification + task tracking; the same module as `ctf flag`

SYS = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
ROOT = os.path.dirname(SYS)
CTF = os.path.join(SYS, "bin", "ctf")
PORT = 8765
WEB_PORT = 8443
TOKEN_FILE = os.path.join(SYS, "logs", "panel.token")
REMOTE = os.path.join(SYS, "remote")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
PEER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,20}$")
FILES_TOP_RE = re.compile(r"^0[1-9]-[a-z0-9-]+$")
ACTIONS = {  # action -> command template ({id} is only ever a value validated by ID_RE / PEER_RE)
    "start": ["start", "{id}"], "stop": ["stop", "{id}"], "reset": ["reset", "{id}"], "install": ["install", "{id}"],
    "kali-start": ["kali", "start"], "kali-boot": ["kali", "boot"], "kali-stop": ["kali", "stop"], "kali-setup": ["kali", "setup"],
    "targets-start": ["start", "vulhub"], "console": ["console", "{id}"], "sync": ["sync"], "layout": ["layout"],
    "vpn-add": ["vpn", "add", "{id}"], "vpn-remove": ["vpn", "remove", "{id}"],
}
PEER_ACTIONS = {"vpn-add", "vpn-remove"}
jobs, jobs_lock = {}, threading.Lock()
cache = {"t": 0, "data": None}
TOKEN = secrets.token_urlsafe(24)


def proxy_secret():
    """The secret Caddy adds to proxied requests (.system/remote/remote.env); None while remote access is off."""
    try:
        with open(os.path.join(REMOTE, "remote.env"), encoding="utf-8") as f:
            m = re.search(r"^CTF_PROXY_SECRET='([A-Za-z0-9]{16,})'$", f.read(), re.M)
        return m.group(1) if m and os.path.exists(os.path.join(REMOTE, "enabled")) else None
    except OSError:
        return None


def i18n(lang):
    try:
        with open(os.path.join(SYS, "catalog", "i18n", f"{lang}.json"), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    return {"s": d, "cat": progress.CATEGORIES[lang], "lvl": progress.LEVELS[lang]}


def status():
    if time.time() - cache["t"] < 2.5 and cache["data"]:
        return cache["data"]
    r = subprocess.run([CTF, "status", "--json"], capture_output=True, text=True, timeout=60)
    data = json.loads(r.stdout)
    cache.update(t=time.time(), data=data)
    return data


def full_status(lang="en"):  # lab state + progress (progress is not cached: a flag shows up immediately)
    d = json.loads(json.dumps(status()))
    if lang != "en":
        names = progress.catalog(lang)
        for lab in d.get("labs", []):
            t = names.get(lab.get("id"))
            if t:
                lab["name"], lab["desc"] = t["name"], t["desc"]
    return dict(d, progress=progress.overview(), remote=remote_info())


def remote_info():
    on = os.path.exists(os.path.join(REMOTE, "enabled"))
    info = {"enabled": on, "port": WEB_PORT, "vpn": shutil.which("wg") is not None and os.path.exists("/usr/local/bin/ctf-vpn-helper"), "peers": [], "urls": []}
    try:
        with open(os.path.join(REMOTE, "wg", "peers.tsv"), encoding="utf-8") as f:
            info["peers"] = [{"name": a[0], "ip": a[1]} for a in (l.rstrip("\n").split("\t") for l in f) if len(a) >= 3 and PEER_RE.match(a[0])]
    except OSError:
        pass
    if on:
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=5).stdout
            ips = [l.split()[3].split("/")[0] for l in out.splitlines() if not re.match(r"^\d+:\s+(virbr|docker|br-|veth|wg-ctf)", l)]
        except (OSError, IndexError, subprocess.SubprocessError):
            ips = []
        info["urls"] = [f"https://{ip}:{WEB_PORT}/" for ip in ips] + [f"https://192.168.100.1:{WEB_PORT}/"]
    return info


def start_job(action, id_):
    args = [a.replace("{id}", id_ or "") for a in ACTIONS[action]]
    jid = secrets.token_hex(4)
    rec = {"id": jid, "action": action, "lab": id_, "output": "", "done": False, "code": None, "t": time.time()}
    with jobs_lock:
        jobs[jid] = rec

    def run():
        p = subprocess.Popen([CTF] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, bufsize=1,
                             env=dict(os.environ, TERM="dumb", NO_COLOR="1"))
        for line in p.stdout:
            rec["output"] = (rec["output"] + re.sub(r"\x1b\[[0-9;]*m", "", line))[-6000:]
        rec["code"] = p.wait(); rec["done"] = True; cache["t"] = 0
    threading.Thread(target=run, daemon=True).start()
    return jid


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CTF Lab</title><style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1c2430;--muted:#667085;--line:#e4e7ec;--accent:#1d6fe0;--good:#12a150;--bad:#d92d20;--warn:#b54708;--code:#0d1117}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#171e28;--text:#e6eaf0;--muted:#95a1b3;--line:#283241;--accent:#5b9bff;--good:#3ecf8e;--bad:#ff6b5e;--warn:#f5a524}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
header{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);padding:12px 20px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
h1{font-size:17px;margin:0 8px 0 0}.vm{display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid var(--line);border-radius:10px;flex-wrap:wrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted);flex:none}.dot.ok{background:var(--good)}
button,.btn{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;padding:5px 11px;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,.btn:hover{border-color:var(--accent);color:var(--accent)}button.main{background:var(--accent);border-color:var(--accent);color:#fff}button.main:hover{color:#fff;filter:brightness(1.1)}
button:disabled{opacity:.5;cursor:wait}
nav{display:flex;gap:6px;flex-wrap:wrap;padding:12px 20px 0}nav button.tab{background:transparent}nav button.active{background:var(--text);color:var(--bg);border-color:var(--text)}
.right{margin-left:auto;display:flex;gap:8px;align-items:center}input{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;padding:6px 10px;width:210px}
main{padding:8px 20px 90px;max-width:1280px;margin:0 auto}h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:22px 0 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:13px 14px;display:flex;flex-direction:column;gap:8px}
.card h3{margin:0;font-size:15px;display:flex;gap:8px;align-items:center}.card p{margin:0;color:var(--muted);font-size:13px;flex:1}
.tag{font-size:11px;padding:1px 7px;border-radius:99px;border:1px solid var(--line);color:var(--muted);margin-left:auto;white-space:nowrap}
.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}.state{font-size:12px;color:var(--muted)}.state.ok{color:var(--good)}
#log{position:fixed;left:0;right:0;bottom:0;background:var(--code);color:#d6e2f0;font:12px/1.5 ui-monospace,Menlo,monospace;padding:8px 20px;max-height:34vh;overflow:auto;white-space:pre-wrap;display:none;border-top:2px solid var(--accent)}
#log b{color:#7ee2a8}.empty{color:var(--muted);padding:30px 0}
.prog{flex-direction:column;align-items:stretch;gap:5px;min-width:240px}.bar{height:7px;border-radius:99px;background:var(--line);overflow:hidden;display:flex}.bar i{display:block;height:100%}.bar .v{background:var(--good)}.bar .c{background:var(--warn)}
.badge{font-size:11px;padding:1px 8px;border-radius:99px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}.badge.ok{color:var(--good);border-color:var(--good)}.badge.claim{color:var(--warn);border-color:var(--warn)}
.card.done{border-left:3px solid var(--good)}.card.done.claim{border-left-color:var(--warn)}.card .row:nth-of-type(1){justify-content:space-between}
#veil{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:20;display:none;align-items:flex-start;justify-content:center;overflow:auto;padding:4vh 14px}
#dlg{background:var(--card);border:1px solid var(--line);border-radius:14px;max-width:780px;width:100%;padding:20px 24px 24px}
#dlg:focus{outline:none}#dlg h2{margin:20px 0 8px}#dlg h3{margin:0;font-size:19px}.dhead{display:flex;gap:12px;align-items:flex-start;justify-content:space-between}.sub{color:var(--muted);font-size:13px;margin:4px 0 10px}
.list{margin:0;padding-left:20px}.list li{margin:3px 0}.list small{color:var(--muted)}
.task{display:grid;grid-template-columns:24px 1fr;gap:2px 8px;padding:10px 0;border-top:1px solid var(--line)}.task:first-of-type{border-top:0}
.ti{font-size:16px;color:var(--muted);text-align:center}.ti.ok{color:var(--good)}.ti.claim{color:var(--warn)}
.task .tb{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.task .tb input{flex:1;min-width:180px;width:auto}.task .note{color:var(--muted);word-break:break-word}
.msg{grid-column:2;font-size:13px;min-height:0}.msg.good{color:var(--good)}.msg.bad{color:var(--bad)}
.banner{padding:9px 12px;border-radius:9px;border:1px solid var(--good);color:var(--good);margin:10px 0 0}
button.small{padding:3px 9px;font-size:13px}code{font:13px ui-monospace,Menlo,monospace;background:var(--bg);padding:1px 5px;border-radius:5px;word-break:break-all}
.peers{display:grid;gap:8px;margin:10px 0}.peer{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 10px;border:1px solid var(--line);border-radius:9px}.qr{background:#fff;padding:8px;border-radius:8px;max-width:260px}
@media (max-width:560px){header{padding:10px 14px}main,nav{padding-left:14px;padding-right:14px}.right{margin-left:0;width:100%}input{width:100%}#dlg{padding:16px 14px 20px}.prog{min-width:0;width:100%}}
</style></head><body>
<header><h1>CTF Lab</h1><div id="top" style="display:flex;gap:10px;flex-wrap:wrap"></div><div class="right"><input id="q" type="search"><button id="langbtn" class="small"></button></div></header>
<nav id="nav"></nav><main id="main"></main><div id="log"></div>
<div id="veil"><div id="dlg" role="dialog" aria-modal="true" aria-labelledby="dh"></div></div>
<script>window.__V=/*__V__*/null;window.__I=/*__I__*/null;window.__T=/*__T__*/null;window.__P=/*__P__*/false;</script>
<script>
const T=window.__T||new URLSearchParams(location.search).get('t')||sessionStorage.getItem('t')||'';sessionStorage.setItem('t',T);
const qs=new URLSearchParams(location.search);let L=qs.get('lang')||(()=>{try{return localStorage.getItem('lang')}catch(e){return null}})()||((navigator.language||'').toLowerCase().startsWith('tr')?'tr':'en');if(!['en','tr'].includes(L))L='en';
history.replaceState(null,'',location.pathname);
let I=window.__I||{en:{s:{},cat:{},lvl:{}},tr:{s:{},cat:{},lvl:{}}};
const S=(k,o)=>{let s=(I[L].s[k]??I.en.s[k]??k);if(o)for(const x in o)s=s.split('{'+x+'}').join(o[x]);return s;};
const CATS=['web','linux','windows','pwn','crypto','forensics','api','archives','custom'];
let V=window.__V||null,tab='web',filter='',busy=new Set(),Z={},D=null,lastFocus=null;
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date=t=>t?new Date(t*1000).toLocaleDateString(L==='tr'?'tr-TR':'en-GB',{day:'numeric',month:'short',year:'numeric'}):'';
const PR=()=>(V&&V.progress)||{overall:null,categories:{},labs:{}};
const norm=s=>s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,'').replace(/ı/g,'i');
const api=(u,b)=>fetch(u+(u.includes('?')?'&':'?')+'lang='+L,{method:b?'POST':'GET',headers:{'X-Token':T,'Content-Type':'application/json'},body:b?JSON.stringify(Object.assign({lang:L},b)):undefined}).then(r=>r.json());
const webUrl=p=>window.__P?p:`https://localhost:${(V&&V.remote&&V.remote.port)||8443}${p}`;
function setLang(l){L=l;try{localStorage.setItem('lang',l)}catch(e){}document.documentElement.lang=l;document.title=S('title');
 document.getElementById('q').placeholder=S('search');const b=document.getElementById('langbtn');b.textContent=S('lang');b.title=S('lang_title');refresh();if(D)openDetail(D.id);}
document.getElementById('langbtn').onclick=()=>setLang(L==='en'?'tr':'en');
function progBox(){const g=PR().overall;if(!g||!g.labs)return '';
 return `<div class="vm prog" title="${esc(S('progress_tip'))}"><span><b>${S('progress')}</b> <span class="state">${esc(S('progress_line',g))}</span></span><div class="bar" role="img" aria-label="${g.done} / ${g.labs}"><i class="v" style="width:${100*g.verified/g.labs}%"></i><i class="c" style="width:${100*g.claimed/g.labs}%"></i></div></div>`;}
function badge(o){if(!o||!o.total)return '';if(o.done)return o.badge==='claimed'?`<span class="badge claim">${S('badge_claimed')}</span>`:`<span class="badge ok">${S('badge_verified')}</span>`;return `<span class="badge">${esc(S('n_tasks',{n:o.verified+o.claimed,t:o.total}))}</span>`;}
function drawTop(){const k=V.kali,t=V.targets,up=s=>s==='running',r=V.remote||{},mode=(V.web&&V.web.mode)||'vm',noKali=k.state==='missing';
 const web=r.enabled?`<button onclick="openWeb('/kali')">${S('web_desktop')}</button><button onclick="openWeb('/term/')">${S('web_term')}</button>`:'';
 document.getElementById('top').innerHTML=
 `<div class="vm"><span class="dot ${up(k.state)?'ok':''}"></span><b>${S('kali')}</b><span class="state">${up(k.state)?S('on')+' · '+esc(k.ip):S('off')}</span>
  ${noKali?`<span class="state">${esc(S('kali_missing'))}</span>`:window.__P?(up(k.state)?'':`<button class="main" onclick="act('kali-boot')">${S('start')}</button>`):`<button class="main" onclick="act('kali-start')">${up(k.state)?S('open_window'):S('start')}</button>`}${up(k.state)?`<button onclick="act('kali-stop')">${S('shut_down')}</button>`:''}${noKali?'':web}</div>
  <div class="vm"><span class="dot ${up(t.state)?'ok':''}"></span><b>${S(mode==='docker'?'docker_local':'targets')}</b><span class="state">${mode==='none'?esc(S('web_none')):up(t.state)?(mode==='docker'?S('docker_desc'):S('targets_desc'))+' · '+esc(t.ip):S('off')}</span></div>`+progBox();}
function nav(){const n={};V.labs.forEach(l=>n[l.category]=(n[l.category]||0)+1);
 document.getElementById('nav').innerHTML=CATS.filter(k=>n[k]).map(k=>`<button class="tab ${tab===k&&!filter?'active':''}" onclick="tab='${k}';document.getElementById('q').value='';filter='';draw()">${esc(I[L].cat[k]||k)} <span style="opacity:.6" title="${S('done_of_total')}">${((PR().categories||{})[k]||{}).done||0}/${n[k]}</span></button>`).join('')
  +`<button class="tab ${tab==='remote'&&!filter?'active':''}" onclick="tab='remote';document.getElementById('q').value='';filter='';draw()">${S('remote')}</button>`;}
function card(l){const run=l.state==='running',notInst=l.state==='not-installed',runnable=['docker','vm','iso','vulhub'].includes(l.type),b=busy.has(l.id),o=(PR().labs||{})[l.id]||{};
 const addr=l.type==='docker'&&l.port?`http://${(V.web&&V.web.addr)||'192.168.100.20'}:${l.port}`:'';const kind=l.type==='docker'?S('type_web'):l.type==='vm'||l.type==='iso'?S('type_vm'):l.type==='local'?S('type_local'):l.type;
 const files=['local','repo','files'].includes(l.type)&&!notInst&&l.dir;
 return `<div class="card${o.done?' done'+(o.badge==='claimed'?' claim':''):''}"><h3>${esc(l.name)}<span class="tag">${esc(kind)}</span></h3>
 <p>${esc(l.desc)}</p><div class="row"><span class="state ${run?'ok':''}">● ${esc(S('state_'+l.state))}</span>${badge(o)}</div>
 <div class="row">${runnable?(run?`<button onclick="act('stop','${l.id}')" ${b?'disabled':''}>${S('stop')}</button>`:`<button class="main" onclick="act('start','${l.id}')" ${b?'disabled':''}>${notInst&&l.type!=='docker'?S('install_start'):S('start')}</button>`):''}
 ${run&&addr?`<a class="btn" href="${addr}" target="_blank" rel="noopener">${S('open')}</a>`:''}
 ${runnable&&l.type!=='vulhub'&&!notInst?`<button onclick="act('reset','${l.id}')" ${b?'disabled':''} title="${esc(S('reset_title'))}">${S('reset')}</button>`:''}
 ${!runnable&&notInst?`<button class="main" onclick="act('install','${l.id}')">${S('download')}</button>`:''}
 ${l.type==='vm'&&run&&!window.__P?`<button onclick="act('console','${l.id}')">${S('console')}</button>`:''}
 ${files?`<a class="btn" href="/files/${l.dir.split('/').map(encodeURIComponent).join('/')}/" target="_blank" rel="noopener">${S('files')}</a>`:''}
 <button onclick="openDetail('${l.id}')" title="${esc(S('details_title'))}">${S('details')}</button></div></div>`;}
function remotePane(){const r=V.remote||{};let h=`<h2>${S('remote')}</h2>`;
 h+=r.enabled?`<p>${S('remote_on')}</p><ul class="list">${(r.urls||[]).map(u=>`<li><code>${esc(u)}</code> — <code>${esc(u)}kali</code> · <code>${esc(u)}term/</code></li>`).join('')}</ul><p class="state">${S('remote_cert')}</p>`:`<p>${S('remote_off')}</p>`;
 h+=`<h2>${S('vpn')}</h2><p class="state">${S('vpn_help')}</p>`;
 if(!r.vpn)return h+`<p>${S('vpn_missing')}</p>`;
 h+=`<div class="row"><input id="peer" maxlength="21" placeholder="${esc(S('vpn_name'))}" onkeydown="if(event.key==='Enter')addPeer()"><button class="main" onclick="addPeer()">${S('vpn_add')}</button></div><div class="peers">`;
 h+=(r.peers||[]).length?r.peers.map(p=>`<div class="peer"><b>${esc(p.name)}</b><code>${esc(p.ip)}</code><span style="flex:1"></span><button class="small" onclick="peerConf('${p.name}')">${S('vpn_conf')}</button><button class="small" onclick="peerQr('${p.name}')">${S('vpn_qr')}</button><button class="small" onclick="delPeer('${p.name}')">${S('vpn_remove')}</button></div><div id="qr-${p.name}"></div>`).join(''):`<div class="state">${S('vpn_none')}</div>`;
 return h+'</div>';}
function draw(){if(!V)return;drawTop();nav();const m=document.getElementById('main');
 if(tab==='remote'&&!filter){m.innerHTML=remotePane();return;}
 const q=norm(filter).split(/\s+/).filter(Boolean);let labs=V.labs.filter(l=>q.length?q.every(t=>norm(l.name+' '+l.id+' '+l.desc+' '+(Z[l.id]||'')).includes(t)):l.category===tab);
 if(!labs.length){m.innerHTML=`<div class="empty">${S('empty')}</div>`;return;}
 let h='';[1,2,3,0].forEach(s=>{const g=labs.filter(l=>l.level===s);if(g.length)h+=`<h2>${esc(I[L].lvl[s])}</h2><div class="grid">${g.map(card).join('')}</div>`;});m.innerHTML=h;}
async function refresh(){try{V=await api('/api/status');draw();}catch(e){}}
async function act(a,id){if(id)busy.add(id);draw();const r=await api('/api/action',{action:a,id:id||''});if(r.error){alert(r.error);busy.delete(id);draw();return;}
 const g=document.getElementById('log');g.style.display='block';
 const t=setInterval(async()=>{const j=await api('/api/job/'+r.job);g.innerHTML=`<b>ctf ${esc(a)} ${esc(id||'')}</b>\n`+esc(j.output);g.scrollTop=g.scrollHeight;
  if(j.done){clearInterval(t);busy.delete(id);g.innerHTML+=`\n<b>${j.code===0?S('job_done'):esc(S('job_failed',{code:j.code}))}</b>`;refresh();setTimeout(()=>{if(j.code===0)g.style.display='none'},j.code===0?6000:0);}},900);}
async function openWeb(p){const w=window.open('about:blank','_blank');  // opened first so the popup blocker allows it; Kali is started if it is off
 if(V.kali.state!=='running'){const g=document.getElementById('log');g.style.display='block';g.textContent='ctf kali boot …';
  const r=await api('/api/action',{action:'kali-boot',id:''});for(let i=0;i<60;i++){const j=await api('/api/job/'+r.job);if(j.done)break;await new Promise(x=>setTimeout(x,1000));}
  await new Promise(x=>setTimeout(x,2000));g.style.display='none';}
 if(w)w.location=webUrl(p);refresh();}
function addPeer(){const n=(document.getElementById('peer').value||'').trim().toLowerCase();if(!/^[a-z0-9][a-z0-9-]{0,20}$/.test(n))return;act('vpn-add',n);}
function delPeer(n){if(confirm(S('vpn_remove_q',{name:n})))act('vpn-remove',n);}
async function peerConf(n){const r=await fetch('/api/vpn/'+n+'.conf',{headers:{'X-Token':T}});if(!r.ok)return;const b=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='ctf-lab-'+n+'.conf';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000);}
async function peerQr(n){const e=document.getElementById('qr-'+n);if(e.innerHTML){e.innerHTML='';return;}const r=await fetch('/api/vpn/'+n+'.svg',{headers:{'X-Token':T}});if(!r.ok)return;const u=URL.createObjectURL(await r.blob());e.innerHTML=`<img class="qr" alt="QR" src="${u}">`;}
let FL=null;
function taskRow(t){const k=t.state,hash=t.kind==='hash',id=esc(t.id),f=FL&&FL.tid===t.id?FL.text:'';
 const icon=k==='verified'?`<span class="ti ok" title="${S('verified')}">✓</span>`:k==='claimed'?`<span class="ti claim" title="${S('claimed')}">◐</span>`:'<span class="ti">○</span>';
 const below=k?`<div class="tb"><span class="state ${k==='verified'?'ok':''}">${k==='verified'?S('verified'):S('claimed')} · ${date(t.t)}</span>${t.note?`<span class="note">${esc(t.note)}</span>`:''}<button class="small" data-t="${id}" onclick="undoTask(this.dataset.t)">${S('undo')}</button></div>`
  :`<div class="tb"><input id="in-${id}" type="text" autocomplete="off" spellcheck="false" maxlength="500" data-t="${id}" aria-label="${esc(t.name)}" placeholder="${esc(hash?S('ph_flag'):S('ph_note'))}" onkeydown="if(event.key==='Enter')sendTask(this.dataset.t)"><button class="main small" data-t="${id}" onclick="sendTask(this.dataset.t)">${hash?S('submit'):S('mark_done')}</button></div>`;
 return `<div class="task">${icon}<div><div class="tb"><b>${esc(t.name)}</b><span class="badge">${hash?S('by_flag'):S('by_you')}</span></div>${below}</div><div class="msg ${f?'good':''}" id="msg-${id}" role="status">${esc(f)}</div></div>`;}
function dialog(banner,flash){FL=flash||null;const d=D,o=d.summary;
 document.getElementById('dlg').innerHTML=
 `<div class="dhead"><div><h3 id="dh">${esc(d.name)}</h3><div class="sub">${esc(d.category_name)} · ${esc(d.level_name)} ${badge(o)}</div></div><button onclick="closeDetail()" aria-label="${S('close')}">✕</button></div>
  <p style="margin:0;color:var(--muted)">${esc(d.desc)}</p>${banner?`<div class="banner" role="status">${esc(banner)}</div>`:''}
  ${d.learn.length?`<h2>${S('learn')}</h2><ul class="list">${d.learn.map(s=>`<li>${esc(s)}</li>`).join('')}</ul>`:''}
  ${d.vulns.length?`<h2>${S('vulns')}</h2><ul class="list">${d.vulns.map(v=>`<li><b>${esc(v.name)}</b>${v.desc?` <small>— ${esc(v.desc)}</small>`:''}</li>`).join('')}</ul>`:''}
  <h2>${S('tasks')} · ${o.verified+o.claimed}/${o.total}</h2>${d.tasks.map(taskRow).join('')}`;FL=null;}
async function openDetail(id){const r=await api('/api/detail/'+id);if(r.error){alert(r.error);return;}
 if(!D)lastFocus=document.activeElement;D=r;dialog();const p=document.getElementById('veil'),w=document.getElementById('dlg');
 p.style.display='flex';p.scrollTop=0;document.body.style.overflow='hidden';w.setAttribute('tabindex','-1');w.focus({preventScroll:true});}
function closeDetail(){D=null;document.getElementById('veil').style.display='none';document.body.style.overflow='';if(lastFocus&&lastFocus.focus)lastFocus.focus();}
function say(tid,text,good){const e=document.getElementById('msg-'+tid);if(e){e.textContent=text;e.className='msg '+(good?'good':'bad');}}
async function sendTask(tid){const t=D.tasks.find(x=>x.id===tid),inp=document.getElementById('in-'+tid);if(!t||!inp)return;
 const v=inp.value.trim(),hash=t.kind==='hash';if(hash&&!v){say(tid,S('need_flag'),false);return;}
 inp.disabled=true;
 const r=await api(hash?'/api/flag':'/api/done',hash?{lab:D.id,task:tid,flag:v}:{lab:D.id,task:tid,note:v}).catch(()=>({error:S('unreachable')}));
 if(r.error||!r.ok){inp.disabled=false;say(tid,r.error||r.message,false);inp.focus();inp.select();return;}
 D=await api('/api/detail/'+D.id);dialog(r.lab&&r.lab.done?S('lab_done'):'',{tid,text:r.message});refresh();}
async function undoTask(tid){const t=D.tasks.find(x=>x.id===tid);if(!t||!confirm(S('undo_q',{name:t.name})))return;
 const r=await api('/api/undo',{lab:D.id,task:tid});if(r.error||!r.ok){alert(r.error||r.message);return;}
 D=await api('/api/detail/'+D.id);dialog('',{tid,text:r.message});refresh();}
document.addEventListener('keydown',e=>{if(!D)return;if(e.key==='Escape'){closeDetail();return;}
 if(e.key==='Tab'){const f=[...document.querySelectorAll('#dlg button,#dlg input:not([disabled])')];if(!f.length)return;const i=f.indexOf(document.activeElement);
  if(e.shiftKey&&i<=0){e.preventDefault();f[f.length-1].focus();}else if(!e.shiftKey&&i===f.length-1){e.preventDefault();f[0].focus();}}});
document.getElementById('veil').addEventListener('mousedown',e=>{if(e.target.id==='veil')closeDetail();});
document.getElementById('q').addEventListener('input',e=>{filter=e.target.value;draw();});
api('/api/search').then(z=>{if(z&&!z.error)Z=z;draw();}).catch(()=>{});
setLang(L);setInterval(refresh,6000);
</script></body></html>"""


def files_listing(rel, path):
    parts = [p for p in rel.split("/") if p]
    rows = []
    if len(parts) > 1:
        rows.append(f'<li><a href="/files/{urllib.parse.quote("/".join(parts[:-1]))}/">⬑ ..</a></li>')
    try:
        entries = sorted(os.scandir(path), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))
    except OSError:
        entries = []
    for e in entries:
        if e.name.startswith(".") or e.is_symlink():
            continue
        href = "/files/" + urllib.parse.quote("/".join(parts + [e.name])) + ("/" if e.is_dir() else "")
        size = "" if e.is_dir() else f" <small>{e.stat().st_size:,} B</small>"
        rows.append(f'<li><a href="{href}">{html.escape(e.name)}{"/" if e.is_dir() else ""}</a>{size}</li>')
    title = html.escape("/".join(parts))
    return (f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>'
            '<style>body{font:15px/1.6 system-ui,sans-serif;margin:20px;background:#f6f7f9;color:#1c2430}@media (prefers-color-scheme:dark){body{background:#0f141b;color:#e6eaf0}a{color:#5b9bff}}'
            f'ul{{list-style:none;padding:0}}small{{opacity:.6}}</style></head><body><h3>{title}/</h3><ul>{"".join(rows)}</ul></body></html>')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store"); self.send_header("X-Frame-Options", "DENY"); self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' blob:; img-src 'self' blob: data:; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def _json(self, code, obj):
        return self._send(code, json.dumps(obj, ensure_ascii=False))

    def _local_host(self):  # DNS-rebinding protection for direct (non-proxied) access
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def _proxied(self):  # came through Caddy (HTTPS + password checked there)
        s = proxy_secret()
        return bool(s) and secrets.compare_digest(self.headers.get("X-CTF-Proxy", ""), s)

    def _authorized(self):  # API calls: CSRF protection with the token header, plus local Host or the proxy secret
        if not (self._local_host() or self._proxied()):
            return False
        return secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN)

    def _cookie_ok(self):
        m = re.search(r"(?:^|;\s*)ctf_t=([A-Za-z0-9_-]+)", self.headers.get("Cookie", ""))
        return bool(m) and secrets.compare_digest(m.group(1), TOKEN)

    def _lang(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        return "tr" if q.get("lang", ["en"])[0] == "tr" else "en"

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            proxied = self._proxied()
            if not (self._local_host() or proxied):
                return self._send(403, "forbidden", "text/plain")
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            token_ok = proxied or secrets.compare_digest(q.get("t", [""])[0], TOKEN)
            try:
                first = json.dumps(full_status(), ensure_ascii=False).replace("</", "<\\/")
            except Exception:
                first = "null"
            page = (PAGE.replace("/*__V__*/null", first)
                    .replace("/*__I__*/null", json.dumps({"en": i18n("en"), "tr": i18n("tr")}, ensure_ascii=False).replace("</", "<\\/"))
                    .replace("/*__T__*/null", json.dumps(TOKEN) if proxied else "null")
                    .replace("/*__P__*/false", "true" if proxied else "false"))
            extra = {"Set-Cookie": f"ctf_t={TOKEN}; Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if proxied else "")} if token_ok else None
            return self._send(200, page, "text/html; charset=utf-8", extra)
        if path.startswith("/files/"):
            if not ((self._local_host() or self._proxied()) and (self._proxied() or self._cookie_ok())):
                return self._send(403, "forbidden — open the panel first", "text/plain")
            return self._files(urllib.parse.unquote(path[len("/files/"):]))
        if not self._authorized():
            return self._json(403, {"error": "unauthorized"})
        lang = self._lang()
        if path == "/api/status":
            try:
                return self._json(200, full_status(lang))
            except Exception as e:
                return self._json(500, {"error": str(e)})
        if path == "/api/search":
            return self._json(200, progress.search_text())
        m = re.match(r"^/api/detail/([a-z0-9][a-z0-9-]{0,40})$", path)
        if m:
            d = progress.detail(m.group(1), lang)
            return self._json(200 if d else 404, d or {"error": "no such lab"})
        m = re.match(r"^/api/job/([0-9a-f]{8})$", path)
        if m and m.group(1) in jobs:
            return self._json(200, dict(jobs[m.group(1)]))
        m = re.match(r"^/api/vpn/([a-z0-9][a-z0-9-]{0,20})\.(conf|svg)$", path)
        if m:
            conf = os.path.join(REMOTE, "wg", m.group(1) + ".conf")
            if not os.path.isfile(conf):
                return self._json(404, {"error": "no such peer"})
            with open(conf, "rb") as f:
                data = f.read()
            if m.group(2) == "conf":
                return self._send(200, data, "text/plain; charset=utf-8", {"Content-Disposition": f'attachment; filename="ctf-lab-{m.group(1)}.conf"'})
            r = subprocess.run(["qrencode", "-t", "SVG", "-o", "-"], input=data, capture_output=True, timeout=10)
            return self._send(200 if r.returncode == 0 else 500, r.stdout or b"qrencode missing", "image/svg+xml")
        self._json(404, {"error": "not found"})

    def _files(self, rel):
        parts = [p for p in rel.split("/") if p]
        if not parts or not FILES_TOP_RE.match(parts[0]) or any(p.startswith(".") or p in ("..", ".") for p in parts):
            return self._send(404, "not found", "text/plain")
        top = os.path.realpath(os.path.join(ROOT, parts[0]))
        full = os.path.realpath(os.path.join(ROOT, *parts))
        if not (full == top or full.startswith(top + os.sep)) or not os.path.exists(full):
            return self._send(404, "not found", "text/plain")
        if os.path.isdir(full):
            if not self.path.endswith("/"):
                return self._send(301, "", "text/plain", {"Location": "/files/" + urllib.parse.quote("/".join(parts)) + "/"})
            return self._send(200, files_listing("/".join(parts), full), "text/html; charset=utf-8")
        size = os.path.getsize(full)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream"); self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(parts[-1]))
        self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers()
        with open(full, "rb") as f:
            shutil.copyfileobj(f, self.wfile, 1 << 16)

    def _progress(self, b, path):  # flag / done / undo — the logic lives in progress.py
        lab, task, lang = b.get("lab"), b.get("task") or None, "tr" if b.get("lang") == "tr" else "en"
        if not (isinstance(lab, str) and progress.ID_RE.match(lab)) or \
                not (task is None or (isinstance(task, str) and progress.TASK_RE.match(task))):
            return self._json(400, {"error": "invalid lab or task"})
        if path != "/api/flag" and task is None:
            return self._json(400, {"error": "task required"})
        try:
            if path == "/api/flag":
                if not isinstance(b.get("flag"), str):
                    return self._json(400, {"error": "flag required"})
                r = progress.submit(lab, b["flag"], task, lang)
            elif path == "/api/done":
                note = b.get("note")
                r = progress.done(lab, task, note if isinstance(note, str) else "", lang)
            else:
                r = progress.undo(lab, task, lang)
        except OSError as e:
            return self._json(500, {"error": f"could not write the record: {e}"})
        self._json(200, r)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if not self._authorized():
            return self._json(403, {"error": "unauthorized"})
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > 16384:
                return self._json(413, {"error": "request too large"})
            b = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(b, dict):
                raise ValueError
        except Exception:
            return self._json(400, {"error": "invalid request"})
        if path in ("/api/flag", "/api/done", "/api/undo"):
            return self._progress(b, path)
        a, i = b.get("action", ""), b.get("id", "")
        if path != "/api/action" or a not in ACTIONS:
            return self._json(400, {"error": "unknown action"})
        if a in PEER_ACTIONS:
            if not PEER_RE.match(i or ""):
                return self._json(400, {"error": "invalid name"})
        elif "{id}" in " ".join(ACTIONS[a]) and not ID_RE.match(i or ""):
            return self._json(400, {"error": "invalid id"})
        if a == "console" and self._proxied():
            return self._json(400, {"error": "the console opens a window on the lab computer; use the web Kali instead"})
        self._json(200, {"job": start_job(a, i)})


def running():
    import socket
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", PORT)); return True
    except OSError:
        return False
    finally:
        s.close()


if __name__ == "__main__":
    quiet = "--quiet" in sys.argv or "--sessiz" in sys.argv
    if running():  # already running: open the browser with the current token
        t = open(TOKEN_FILE).read().strip()
        print(f"The panel is already running → http://127.0.0.1:{PORT}")
        if not quiet:
            subprocess.Popen(["xdg-open", f"http://127.0.0.1:{PORT}/?t={t}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.exit(0)
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, TOKEN.encode()); os.close(fd)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}/?t={TOKEN}"
    print(f"CTF Lab panel: {url}   (Ctrl+C to stop)", flush=True)
    if not quiet:
        threading.Timer(0.8, lambda: subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
