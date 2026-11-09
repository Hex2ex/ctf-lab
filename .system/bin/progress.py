#!/usr/bin/env python3
"""CTF Lab progress tracking: flag verification (SHA256) and task marking.

Used by `ctf flag|done|undo|info|progress` and by the web panel.
Record: .system/progress.json   Flag hashes: catalog/flags.sha256   Lab info: catalog/learn/<lang>/*.json

There are two kinds of tasks:
  hash   the SHA256 of the flag is known; only the correct flag marks the task 'verified'.
  claim  the flag is unknown (inside a VM, or a web lab without flags); the user marks it themselves.
"""
import contextlib, fcntl, glob, hashlib, hmac, json, os, re, sys, tempfile, time

SYS = os.environ.get("CTF_SYS") or os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
TASK_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
FLAG_MAX = 500
NOTE_MAX = 500
LANGS = ("en", "tr")
CATEGORIES = {
    "en": {"web": "Web", "linux": "Linux Servers", "windows": "Windows", "pwn": "Pwn / Reverse", "crypto": "Crypto",
           "forensics": "Forensics / Stego / Misc", "api": "API / Mobile / Cloud", "archives": "Real CTF Archives", "custom": "My CTFs"},
    "tr": {"web": "Web", "linux": "Linux Sunucu", "windows": "Windows", "pwn": "Pwn / Reverse", "crypto": "Kripto",
           "forensics": "Forensics / Stego / Misc", "api": "API / Mobil / Bulut", "archives": "Gerçek CTF Arşivleri", "custom": "Kendi CTF'lerim"},
}
LEVELS = {"en": {0: "Unrated", 1: "Easy", 2: "Medium", 3: "Hard"}, "tr": {0: "Seviyesiz", 1: "Başlangıç", 2: "Orta", 3: "İleri"}}

MSG = {
    "unknown_lab": {"en": "Unknown lab: {0}", "tr": "Bilinmeyen lab: {0}"},
    "unknown_task": {"en": "Unknown task: {0}. Tasks: {1}", "tr": "Bilinmeyen görev: {0}. Görevler: {1}"},
    "empty_flag": {"en": "The flag is empty.", "tr": "Bayrak boş."},
    "long_flag": {"en": "The flag is too long.", "tr": "Bayrak çok uzun."},
    "already": {"en": "You already solved this task: {0}", "tr": "Bu görevi zaten çözmüştün: {0}"},
    "claimed_flag": {"en": "Saved (your own claim): {0}. This flag cannot be verified.",
                     "tr": "Kaydedildi (kendi beyanın): {0}. Bu bayrak doğrulanamıyor."},
    "no_hash": {"en": "{0} is not verified by flags. Mark progress with: ctf done {1} <task> [note]   Tasks: {2}",
                "tr": "{0} bayrakla doğrulanmıyor. İlerlemeyi işaretle: ctf done {1} <görev> [not]   Görevler: {2}"},
    "correct": {"en": "CORRECT! {0} solved.", "tr": "DOĞRU! {0} çözüldü."},
    "wrong": {"en": "Wrong flag.", "tr": "Yanlış bayrak."},
    "format": {"en": " (Format: CTFLAB{{...}})", "tr": " (Biçim: CTFLAB{{...}})"},
    "stuck": {"en": " Stuck? ctf solution {0} (spoiler!)", "tr": " Takılırsan: ctf solution {0} (spoiler!)"},
    "hash_task": {"en": '"{0}" is verified by a flag; you cannot mark it yourself. Submit the flag: ctf flag {1} \'<flag>\'',
                  "tr": '"{0}" bayrakla doğrulanır; kendin işaretleyemezsin. Bayrağı gönder: ctf flag {1} \'<bayrak>\''},
    "marked": {"en": "Marked (your own claim): {0}", "tr": "İşaretlendi (kendi beyanın): {0}"},
    "not_done": {"en": "This task is not completed: {0}", "tr": "Bu görev zaten tamamlanmamış: {0}"},
    "undone": {"en": "Undone: {0}", "tr": "Geri alındı: {0}"},
    "t_flag": {"en": "Find the flag", "tr": "Bayrağı bul"},
    "t_access": {"en": "Get initial access (shell) on the system", "tr": "Sisteme ilk erişimi (kabuk) al"},
    "t_admin": {"en": "Get Administrator / SYSTEM privileges", "tr": "Yönetici / SYSTEM yetkisi al"},
    "t_user": {"en": "Get initial access (shell / user) on the system", "tr": "Sisteme ilk erişimi (kabuk / kullanıcı) al"},
    "t_root": {"en": "Escalate privileges to root", "tr": "Yetki yükseltip root ol"},
    "t_exploit": {"en": "Exploit: {0}", "tr": "Sömür: {0}"},
    "t_complete": {"en": "Complete the lab", "tr": "Lab'ı tamamla"},
}


def msg(key, lang="en", *a):
    m = MSG[key]
    return m.get(lang, m["en"]).format(*a)


def _lang(lang):
    return lang if lang in LANGS else "en"


def _p(*a):
    return os.path.join(SYS, *a)


# ---------- data ----------
def catalog(lang="en"):
    """id -> {id, type, category, level, name, desc}  (labs.psv + generated.psv + custom.psv; TR overrides from i18n/tr-labs.json)"""
    labs = {}
    for name in ("labs.psv", "generated.psv", "custom.psv"):
        try:
            with open(_p("catalog", name), encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        for s in lines:
            if not s.strip() or s.startswith("#"):
                continue
            a = s.split("|", 7)
            if len(a) < 8:
                continue
            try:
                level = int(a[3])
            except ValueError:
                level = 0
            labs[a[0]] = {"id": a[0], "type": a[1], "category": a[2], "level": level, "name": a[4], "desc": a[7]}
    if _lang(lang) != "en":
        for i, t in _json(_p("catalog", "i18n", f"{lang}-labs.json")).items():
            if i in labs and isinstance(t, dict):
                labs[i].update({k: v for k, v in t.items() if k in ("name", "desc") and isinstance(v, str) and v})
    return labs


def _json(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def learn(lang="en"):
    """id -> {learn: [...], vulns: [{id, name, desc, task?}], tasks: [{id, name}]}  (catalog/learn/<lang>/*.json)"""
    data = {}
    for path in sorted(glob.glob(_p("catalog", "learn", _lang(lang), "*.json"))):
        data.update({k: v for k, v in _json(path).items() if isinstance(v, dict)})
    return data


def hashes():
    """key -> sha256.  The key is 'lab' (single flag, task 'flag') or 'lab#task'."""
    h = {}
    try:
        with open(_p("catalog", "flags.sha256"), encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return h
    for s in lines:
        p = s.split(None, 1)
        if len(p) == 2 and re.fullmatch(r"[0-9a-f]{64}", p[0]):
            h[p[1].strip()] = p[0]
    return h


def _slug(s):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return (s or "task")[:40].strip("-") or "task"


def _tasks(lab, info, hs, lang="en", info_en=None):
    """Task list of a lab: [{id, name, kind, _key}]. IDs always come from the English data so they never
    depend on the UI language; names come from `info` (the requested language)."""
    info_en = info if info_en is None else info_en
    names = {t.get("id"): t.get("name") for t in info.get("tasks", []) if isinstance(t, dict)}
    items = [{"id": t["id"], "name": names.get(t["id"]) or t["name"]}
             for t in info_en.get("tasks", []) if isinstance(t, dict) and t.get("id") and t.get("name")]
    if not items:
        if lab["id"] in hs:
            items = [{"id": "flag", "name": msg("t_flag", lang)}]
        elif lab["type"] in ("vm", "iso") and lab["category"] == "windows":
            items = [{"id": "access", "name": msg("t_access", lang)}, {"id": "admin", "name": msg("t_admin", lang)}]
        elif lab["type"] in ("vm", "iso"):
            items = [{"id": "user", "name": msg("t_user", lang)}, {"id": "root", "name": msg("t_root", lang)}]
        elif info_en.get("vulns"):
            local = {v.get("id"): v for v in info.get("vulns", []) if isinstance(v, dict)}
            for v in info_en["vulns"]:
                if not (isinstance(v, dict) and v.get("name")):
                    continue
                vid = v.get("id") or _slug(v["name"])
                lv = local.get(vid, v)
                items.append({"id": vid, "name": lv.get("task") or msg("t_exploit", lang, lv.get("name") or v["name"])})
        if not items:
            items = [{"id": "complete", "name": msg("t_complete", lang)}]
    seen, out = set(), []
    for t in items:
        tid, n = t["id"], 2
        while tid in seen:
            tid, n = f'{t["id"]}-{n}', n + 1
        seen.add(tid)
        key = lab["id"] if (tid == "flag" and lab["id"] in hs) else f'{lab["id"]}#{tid}'
        out.append({"id": tid, "name": t["name"], "kind": "hash" if key in hs else "claim", "_key": key})
    return out


# ---------- record (progress.json) ----------
def _read(backup=False):
    path = _p("progress.json")
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
    except FileNotFoundError:
        v = None
    except (OSError, ValueError):
        v = None
        if backup:  # do not overwrite a corrupt file and lose progress: move it aside
            with contextlib.suppress(OSError):
                os.replace(path, f"{path}.corrupt-{int(time.time())}")
    if not isinstance(v, dict) or not isinstance(v.get("labs"), dict):
        v = {"v": 2, "labs": {}}
    return v


@contextlib.contextmanager
def _lock():
    fd = os.open(_p("progress.json.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write(v):
    fd, tmp = tempfile.mkstemp(dir=SYS, prefix=".progress-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.flush(); os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, _p("progress.json"))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _lab_summary(tasks, rec):
    v = sum(1 for t in tasks if rec.get(t["id"], {}).get("state") == "verified")
    c = sum(1 for t in tasks if rec.get(t["id"], {}).get("state") == "claimed")
    done = bool(tasks) and v + c == len(tasks)
    return {"total": len(tasks), "verified": v, "claimed": c, "done": done,
            "badge": ("verified" if c == 0 else "claimed") if done else None}


def _context(lab_id, lang="en"):
    lab = catalog().get(lab_id) if ID_RE.match(lab_id or "") else None
    if not lab:
        return None, None, None
    hs = hashes()
    info_en = learn("en").get(lab_id, {})
    info = info_en if _lang(lang) == "en" else learn(lang).get(lab_id, {})
    return lab, _tasks(lab, info, hs, _lang(lang), info_en), hs


def _err(text):
    return {"ok": False, "message": text}


def _task_ids(tl):
    return ", ".join(t["id"] for t in tl)


# ---------- actions ----------
def _mark(lab_id, tl, t, state, text, note="", lang="en"):
    with _lock():
        v = _read(backup=True)
        rec = v["labs"].setdefault(lab_id, {})
        if rec.get(t["id"], {}).get("state") == "verified" and state == "verified":
            return {"ok": True, "state": state, "message": msg("already", lang, t["name"]), "lab": _lab_summary(tl, rec)}
        entry = {"state": state, "t": int(time.time())}
        if note:
            entry["note"] = note[:NOTE_MAX]
        rec[t["id"]] = entry
        _write(v)
        return {"ok": True, "state": state, "message": text, "lab": _lab_summary(tl, rec)}


def submit(lab_id, flag, task=None, lang="en"):
    """Verify a flag. Without a task, every hash task of the lab is tried."""
    lang = _lang(lang)
    lab, tl, hs = _context(lab_id, lang)
    if not lab:
        return _err(msg("unknown_lab", lang, lab_id))
    flag = (flag or "").strip()
    if not flag:
        return _err(msg("empty_flag", lang))
    if len(flag) > FLAG_MAX:
        return _err(msg("long_flag", lang))
    if task:
        t = next((x for x in tl if x["id"] == task), None)
        if not t:
            return _err(msg("unknown_task", lang, task, _task_ids(tl)))
        if t["kind"] == "claim":
            return _mark(lab_id, tl, t, "claimed", msg("claimed_flag", lang, t["name"]), flag, lang)
        candidates = [t]
    else:
        candidates = [x for x in tl if x["kind"] == "hash"]
        if not candidates:
            return _err(msg("no_hash", lang, lab["name"], lab_id, _task_ids(tl)))
    digest = hashlib.sha256(flag.encode()).hexdigest()
    for t in candidates:
        if hmac.compare_digest(hs[t["_key"]], digest):
            return _mark(lab_id, tl, t, "verified", msg("correct", lang, t["name"]), lang=lang)
    extra = msg("format", lang) if lab["type"] == "local" else ""
    if os.path.exists(_p("solutions", f"{lab_id}.md")):
        extra += msg("stuck", lang, lab_id)
    return _err(msg("wrong", lang) + extra)


def done(lab_id, task, note="", lang="en"):
    """Mark a task whose flag cannot be verified (claim) as completed."""
    lang = _lang(lang)
    lab, tl, hs = _context(lab_id, lang)
    if not lab:
        return _err(msg("unknown_lab", lang, lab_id))
    t = next((x for x in tl if x["id"] == (task or "")), None)
    if not t:
        return _err(msg("unknown_task", lang, task, _task_ids(tl)))
    if t["kind"] == "hash":
        return _err(msg("hash_task", lang, t["name"], lab_id))
    return _mark(lab_id, tl, t, "claimed", msg("marked", lang, t["name"]), (note or "").strip(), lang)


def undo(lab_id, task, lang="en"):
    lang = _lang(lang)
    lab, tl, hs = _context(lab_id, lang)
    if not lab:
        return _err(msg("unknown_lab", lang, lab_id))
    t = next((x for x in tl if x["id"] == (task or "")), None)
    if not t:
        return _err(msg("unknown_task", lang, task, _task_ids(tl)))
    with _lock():
        v = _read(backup=True)
        rec = v["labs"].get(lab_id, {})
        if t["id"] not in rec:
            return _err(msg("not_done", lang, t["name"]))
        del rec[t["id"]]
        if not rec:
            v["labs"].pop(lab_id, None)
        _write(v)
        return {"ok": True, "message": msg("undone", lang, t["name"]), "lab": _lab_summary(tl, rec)}


# ---------- reading ----------
def detail(lab_id, lang="en"):
    """Everything about one lab plus task states (panel drawer and `ctf info`)."""
    lang = _lang(lang)
    lab, tl, hs = _context(lab_id, lang)
    if not lab:
        return None
    lab = catalog(lang)[lab_id]
    info = learn(lang).get(lab_id) or learn("en").get(lab_id, {})
    rec = _read()["labs"].get(lab_id, {})
    tasks = []
    for t in tl:
        r = rec.get(t["id"], {})
        tasks.append({"id": t["id"], "name": t["name"], "kind": t["kind"], "state": r.get("state"), "t": r.get("t"), "note": r.get("note", "")})
    return {**lab, "category_name": CATEGORIES[lang].get(lab["category"], lab["category"]), "level_name": LEVELS[lang].get(lab["level"], ""),
            "learn": [s for s in info.get("learn", []) if isinstance(s, str)],
            "vulns": [v for v in info.get("vulns", []) if isinstance(v, dict) and v.get("name")],
            "tasks": tasks, "summary": _lab_summary(tl, rec)}


def overview():
    """Progress of every lab: panel header, category counters and card badges."""
    labs, hs, info_en, rec = catalog(), hashes(), learn("en"), _read()["labs"]
    o = {"labs": len(labs), "done": 0, "verified": 0, "claimed": 0, "tasks": 0, "tasks_verified": 0, "tasks_claimed": 0}
    cats, per_lab = {}, {}
    for lab_id, lab in labs.items():
        s = _lab_summary(_tasks(lab, info_en.get(lab_id, {}), hs), rec.get(lab_id, {}))
        per_lab[lab_id] = s
        c = cats.setdefault(lab["category"], {"labs": 0, "done": 0})
        c["labs"] += 1
        o["tasks"] += s["total"]; o["tasks_verified"] += s["verified"]; o["tasks_claimed"] += s["claimed"]
        if s["done"]:
            c["done"] += 1; o["done"] += 1
            o["verified" if s["badge"] == "verified" else "claimed"] += 1
    return {"overall": o, "categories": cats, "labs": per_lab}


def search_text(lang="en"):
    """id -> vulnerability/learning text in both languages, so searching 'sql' finds every related lab."""
    out = {}
    for lg in LANGS:
        for i, o in learn(lg).items():
            words = [v["name"] for v in o.get("vulns", []) if isinstance(v, dict) and v.get("name")] \
                + [s for s in o.get("learn", []) if isinstance(s, str)]
            out[i] = (out.get(i, "") + " " + " ".join(words)).strip()
    for i, t in catalog("tr").items():
        out[i] = (out.get(i, "") + " " + t["name"] + " " + t["desc"]).strip()
    return out


# ---------- command line ----------
def _color(code, s):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s


def _print_result(r):
    if r["ok"]:
        print(f'{_color("1;32", "✓")} {r["message"]}')
        s = r.get("lab")
        if s:
            print(f'  Lab progress: {s["verified"] + s["claimed"]}/{s["total"]}' + ("  — LAB COMPLETE 🎉" if s["done"] else ""))
        return 0
    print(f'{_color("1;31", "✗")} {r["message"]}', file=sys.stderr)
    return 1


def _bar(n, total, width=20):
    full = round(width * n / total) if total else 0
    return "█" * full + "░" * (width - full)


def _info(lab_id, as_json=False):
    d = detail(lab_id)
    if not d:
        print(f'{_color("1;31", "✗")} Unknown lab: {lab_id}', file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(d, ensure_ascii=False, indent=1))
        return 0
    print(f'{_color("1", d["name"])}   ({d["category_name"]} · {d["level_name"]})\n{d["desc"]}\n')
    if d["learn"]:
        print(_color("1;36", "What you will learn"))
        for s in d["learn"]:
            print(f"  • {s}")
        print()
    if d["vulns"]:
        print(_color("1;33", "Vulnerabilities"))
        for v in d["vulns"]:
            print(f'  • {v["name"]}' + (f' — {v["desc"]}' if v.get("desc") else ""))
        print()
    s = d["summary"]
    print(_color("1;32", f'Tasks  {s["verified"] + s["claimed"]}/{s["total"]}'))
    for t in d["tasks"]:
        sym, label = {"verified": ("✓", "verified"), "claimed": ("◐", "your claim")}.get(t["state"], ("○", ""))
        kind = "verified by flag" if t["kind"] == "hash" else "you mark it"
        print(f'  {sym} {t["id"]:<14} {t["name"]}   [{label or kind}]')
    return 0


def _progress(as_json=False):
    o = overview()
    if as_json:
        print(json.dumps(o, ensure_ascii=False, indent=1))
        return 0
    g = o["overall"]
    print(f'{_color("1", "Overall")}  {_bar(g["done"], g["labs"])}  {g["done"]}/{g["labs"]} labs done'
          f'  (verified {g["verified"]} · claimed {g["claimed"]})')
    order = list(CATEGORIES["en"])
    for cat, c in sorted(o["categories"].items(), key=lambda x: order.index(x[0]) if x[0] in order else 99):
        print(f'  {CATEGORIES["en"].get(cat, cat):<26} {_bar(c["done"], c["labs"], 12)}  {c["done"]}/{c["labs"]}')
    return 0


USAGE = """usage:
  ctf flag <lab> [task] '<flag>'   verify a flag (without a task, the matching task is found)
  ctf done <lab> <task> [note]     mark a task whose flag cannot be verified, as your own claim
  ctf undo <lab> <task>            remove a mark
  ctf info <lab> [--json]          what you will learn, vulnerabilities, tasks
  ctf progress [--json]            overall progress"""


def main(argv):
    if not argv:
        print(USAGE); return 1
    k, a = argv[0], argv[1:]
    if k == "flag" and len(a) in (2, 3):
        lab, task, flag = (a[0], None, a[1]) if len(a) == 2 else (a[0], a[1], a[2])
        if flag == "-":
            flag = sys.stdin.readline()
        return _print_result(submit(lab, flag, task))
    if k == "done" and len(a) >= 2:
        return _print_result(done(a[0], a[1], " ".join(a[2:])))
    if k == "undo" and len(a) == 2:
        return _print_result(undo(a[0], a[1]))
    if k == "info" and a and a[0] != "--json":
        return _info(a[0], "--json" in a[1:])
    if k == "progress":
        return _progress("--json" in a)
    print(USAGE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
