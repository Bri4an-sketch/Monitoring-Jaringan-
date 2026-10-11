import csv
import hmac
import io
import json
import os
import sqlite3
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

APP_TITLE = "NetWatch | MikroTik & CCTV"
DB_PATH = os.environ.get("DB_PATH", "/tmp/netwatch.sqlite3")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
DASH_USER = os.environ.get("DASH_USER", "admin")
DASH_PASS = os.environ.get("DASH_PASS", "")
STALE_AFTER = max(30, int(os.environ.get("STALE_AFTER_SECONDS", "180")))
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

app = FastAPI(title="MikroTik CCTV Monitor", version="3.0.0")
security = HTTPBasic()


class Heartbeat(BaseModel):
    site: str = Field(default="Site", max_length=100)
    cctv_replies: int = Field(default=0, ge=0, le=1000)
    router_uptime: Optional[str] = Field(default=None, max_length=100)
    ping_ms: Optional[float] = Field(default=None, ge=0, le=600000)
    router_status: Optional[str] = Field(default=None, max_length=40)
    # Optional agent-supplied detail; never inferred by this server.
    note: Optional[str] = Field(default=None, max_length=250)


def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL, received_at TEXT NOT NULL, site TEXT NOT NULL,
            cctv_replies INTEGER NOT NULL, router_uptime TEXT, ping_ms REAL,
            router_status TEXT, note TEXT
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL, event_at TEXT NOT NULL, device TEXT NOT NULL,
            event TEXT NOT NULL, message TEXT NOT NULL, duration_seconds INTEGER
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS outages (
            device TEXT PRIMARY KEY, started_ts REAL NOT NULL,
            started_at TEXT NOT NULL, last_state TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL
        )""")


init_db()


def utc_now():
    return datetime.now(timezone.utc)


def iso_now():
    return utc_now().isoformat(timespec="seconds")


def check_dashboard(user: HTTPBasicCredentials = Depends(security)):
    ok_user = hmac.compare_digest(user.username.encode(), DASH_USER.encode())
    ok_pass = bool(DASH_PASS) and hmac.compare_digest(user.password.encode(), DASH_PASS.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Login diperlukan", headers={"WWW-Authenticate": "Basic"})


def telegram_send(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = urllib.parse.urlencode({"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": "true"}).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception:
        # Do not fail heartbeat handling if Telegram is unavailable.
        return False


def add_event(device: str, event: str, message: str, duration_seconds=None):
    now_ts = time.time()
    with db_connect() as db:
        db.execute("INSERT INTO events(ts,event_at,device,event,message,duration_seconds) VALUES(?,?,?,?,?,?)",
                   (now_ts, iso_now(), device, event, message, duration_seconds))
    if event in ("OFFLINE", "RECOVERED", "ALERT"):
        telegram_send(f"[NetWatch] {event}\nPerangkat: {device}\n{message}\nWaktu: {iso_now()}")


def set_device_state(device: str, online: bool, message: str):
    """Track state transitions so outage duration is measured from known transitions."""
    now_ts, now_iso = time.time(), iso_now()
    with db_connect() as db:
        row = db.execute("SELECT started_ts, started_at FROM outages WHERE device=?", (device,)).fetchone()
        if online:
            if row:
                duration = max(0, int(now_ts - row["started_ts"]))
                db.execute("DELETE FROM outages WHERE device=?", (device,))
                db.execute("INSERT INTO events(ts,event_at,device,event,message,duration_seconds) VALUES(?,?,?,?,?,?)",
                           (now_ts, now_iso, device, "RECOVERED", f"Perangkat pulih. {message}", duration))
                recovered = True
            else:
                recovered = False
        else:
            if not row:
                db.execute("INSERT INTO outages(device,started_ts,started_at,last_state) VALUES(?,?,?,?)",
                           (device, now_ts, now_iso, "OFFLINE"))
                db.execute("INSERT INTO events(ts,event_at,device,event,message,duration_seconds) VALUES(?,?,?,?,?,NULL)",
                           (now_ts, now_iso, device, "OFFLINE", message))
                recovered = False
            else:
                recovered = False
    # Telegram call outside DB transaction.
    if not online and not row:
        telegram_send(f"[NetWatch] OFFLINE\nPerangkat: {device}\n{message}\nWaktu: {now_iso}")
    elif online and row:
        telegram_send(f"[NetWatch] RECOVERED\nPerangkat: {device}\nGangguan berlangsung {duration} detik. {message}\nWaktu: {now_iso}")


def latest_row():
    with db_connect() as db:
        row = db.execute("SELECT * FROM heartbeats ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def current_status():
    item = latest_row()
    if not item:
        return {"received_at": None, "stale": True, "age_seconds": None,
                "cctv_replies": None, "router_uptime": None, "ping_ms": None,
                "router_status": None, "site": None, "router_online": None, "cctv_online": None}
    age = max(0, int(time.time() - item["ts"]))
    stale = age > STALE_AFTER
    # Router is considered reachable only while reports are fresh. Explicit agent status can provide extra context.
    router_online = not stale and (item.get("router_status") or "online").lower() not in ("offline", "down", "unreachable", "false", "0")
    cctv_online = None if stale else item["cctv_replies"] > 0
    item.update({"stale": stale, "age_seconds": age, "router_online": router_online,
                 "cctv_online": cctv_online, "stale_after_seconds": STALE_AFTER})
    return item


@app.get("/", response_class=HTMLResponse)
def dashboard(_: None = Depends(check_dashboard)):
    return HTMLResponse(HTML)


@app.get("/api/status")
def api_status(_: None = Depends(check_dashboard)):
    status = current_status()
    # Register stale-report transition once when the service notices it.
    if status.get("received_at") and status.get("stale"):
        set_device_state("MikroTik / Agent", False, f"Tidak ada heartbeat selama {status.get('age_seconds')} detik.")
        # Do not mark CCTV offline solely because its agent is stale; its state is unknown.
    elif status.get("received_at"):
        set_device_state("MikroTik / Agent", bool(status.get("router_online")), "Heartbeat diterima.")
        set_device_state("CCTV", bool(status.get("cctv_online")), "Hasil pemeriksaan dari agent.")
        if status.get("ping_ms") is not None and status["ping_ms"] >= float(os.environ.get("HIGH_PING_MS", "150")):
            # Rate-limit repeated high ping alarms to one per 5 minutes.
            with db_connect() as db:
                recent = db.execute("SELECT ts FROM events WHERE device='MikroTik / Agent' AND event='ALERT' ORDER BY id DESC LIMIT 1").fetchone()
            if not recent or time.time() - recent["ts"] > 300:
                add_event("MikroTik / Agent", "ALERT", f"Ping tinggi: {status['ping_ms']} ms.")
    return status


@app.post("/api/heartbeat")
def heartbeat(data: Heartbeat, x_agent_token: str = Header(default="")):
    if not AGENT_TOKEN or not hmac.compare_digest(x_agent_token, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="Token agent salah atau belum dikonfigurasi")
    now_ts, now_iso = time.time(), iso_now()
    payload = data.model_dump() if hasattr(data, "model_dump") else data.dict()
    with db_connect() as db:
        db.execute("INSERT INTO heartbeats(ts,received_at,site,cctv_replies,router_uptime,ping_ms,router_status,note) VALUES(?,?,?,?,?,?,?,?)",
                   (now_ts, now_iso, payload["site"], payload["cctv_replies"], payload["router_uptime"],
                    payload["ping_ms"], payload["router_status"], payload["note"]))
        db.execute("DELETE FROM heartbeats WHERE id NOT IN (SELECT id FROM heartbeats ORDER BY id DESC LIMIT 10000)")
    return {"ok": True, "received_at": now_iso}


@app.get("/api/history")
def api_history(hours: int = Query(default=24, ge=1, le=720), _: None = Depends(check_dashboard)):
    cutoff = time.time() - hours * 3600
    with db_connect() as db:
        rows = db.execute("SELECT ts,received_at,cctv_replies,ping_ms,router_uptime,router_status FROM heartbeats WHERE ts>=? ORDER BY ts ASC", (cutoff,)).fetchall()
    return {"hours": hours, "points": [dict(r) for r in rows]}


@app.get("/api/events")
def api_events(limit: int = Query(default=100, ge=1, le=1000), _: None = Depends(check_dashboard)):
    with db_connect() as db:
        events = db.execute("SELECT id,event_at,device,event,message,duration_seconds FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        outages = db.execute("SELECT device,started_at,started_ts FROM outages ORDER BY started_ts ASC").fetchall()
    active = []
    for o in outages:
        active.append({"device": o["device"], "started_at": o["started_at"], "duration_seconds": max(0, int(time.time()-o["started_ts"]))})
    return {"events": [dict(e) for e in events], "active_outages": active}


@app.get("/api/devices")
def api_devices(_: None = Depends(check_dashboard)):
    s = current_status()
    return {"devices": [
        {"name": "MikroTik / Agent", "type": "Router / heartbeat", "address": "Dikirim oleh agent", "online": s.get("router_online"), "detail": s.get("router_status") or ("Laporan kedaluwarsa" if s.get("stale") else "Heartbeat diterima" if s.get("received_at") else "Belum ada laporan")},
        {"name": "CCTV", "type": "IP camera / ping result", "address": "192.168.1.235", "online": s.get("cctv_online"), "detail": "Belum ada hasil pemeriksaan" if not s.get("received_at") else "Laporan kedaluwarsa" if s.get("stale") else f"Balasan: {s.get('cctv_replies', 0)}"}
    ]}


@app.get("/api/settings")
def api_get_settings(_: None = Depends(check_dashboard)):
    with db_connect() as db:
        rows = db.execute("SELECT key,value FROM settings").fetchall()
    values = {r["key"]: r["value"] for r in rows}
    return {"stale_after_seconds": STALE_AFTER, "high_ping_ms": float(os.environ.get("HIGH_PING_MS", "150")),
            "telegram_configured": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
            "site_label": values.get("site_label", "NetWatch Site"),
            "router_lat": values.get("router_lat", ""), "router_lon": values.get("router_lon", ""),
            "cctv_lat": values.get("cctv_lat", ""), "cctv_lon": values.get("cctv_lon", "")}


@app.post("/api/settings")
def api_save_settings(body: dict, _: None = Depends(check_dashboard)):
    # Coordinates are optional; never infer or fabricate physical locations.
    label = str(body.get("site_label", "NetWatch Site")).strip()[:100] or "NetWatch Site"
    values = {"site_label": label}
    for key in ("router_lat", "router_lon", "cctv_lat", "cctv_lon"):
        raw = str(body.get(key, "")).strip()
        if raw:
            try:
                num = float(raw)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} harus berupa angka koordinat")
            limit = 90 if key.endswith("_lat") else 180
            if not -limit <= num <= limit:
                raise HTTPException(status_code=400, detail=f"{key} di luar rentang koordinat")
            values[key] = str(num)
        else:
            values[key] = ""
    with db_connect() as db:
        for key, value in values.items():
            db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    return {"ok": True, **values}


@app.get("/api/map")
def api_map(_: None = Depends(check_dashboard)):
    with db_connect() as db:
        rows = db.execute("SELECT key,value FROM settings WHERE key IN ('site_label','router_lat','router_lon','cctv_lat','cctv_lon')").fetchall()
    values = {r["key"]: r["value"] for r in rows}
    status = current_status()
    def coords(prefix):
        try:
            lat, lon = values.get(prefix + "_lat", ""), values.get(prefix + "_lon", "")
            if lat == "" or lon == "":
                return None
            return {"lat": float(lat), "lon": float(lon)}
        except (TypeError, ValueError):
            return None
    return {"site_label": values.get("site_label", "NetWatch Site"),
            "router": {**(coords("router") or {}), "online": status.get("router_online"),
                       "detail": "Laporan kedaluwarsa" if status.get("stale") else "Heartbeat diterima" if status.get("received_at") else "Belum ada laporan"},
            "cctv": {**(coords("cctv") or {}), "online": status.get("cctv_online"),
                     "detail": "Belum ada hasil pemeriksaan" if not status.get("received_at") else "Laporan kedaluwarsa" if status.get("stale") else "Balasan ping: " + str(status.get("cctv_replies", 0))}}


@app.get("/api/export.csv")
def export_csv(_: None = Depends(check_dashboard)):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["timestamp_utc", "site", "cctv_replies", "ping_ms", "router_uptime", "router_status", "note"])
    with db_connect() as db:
        rows = db.execute("SELECT received_at,site,cctv_replies,ping_ms,router_uptime,router_status,note FROM heartbeats ORDER BY id ASC").fetchall()
    for row in rows:
        writer.writerow([row["received_at"], row["site"], row["cctv_replies"], row["ping_ms"], row["router_uptime"], row["router_status"], row["note"]])
    data = "\ufeff" + output.getvalue()
    return StreamingResponse(iter([data]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=netwatch-history.csv"})


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "netwatch"}


HTML = r'''<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0b1020"><title>NetWatch | Monitoring</title><link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/><script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<style>
:root{color-scheme:dark;--bg:#080d19;--panel:#101827;--panel2:#131f31;--line:#25344a;--text:#edf4ff;--muted:#8fa2bd;--blue:#69a7ff;--green:#42dfaa;--red:#ff7185;--amber:#ffd078}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 70% -20%,#1a3154 0,transparent 40%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}button,input,select{font:inherit}button{cursor:pointer}.app{min-height:100vh;display:grid;grid-template-columns:245px minmax(0,1fr)}.sidebar{border-right:1px solid var(--line);background:#0b1220;padding:24px 15px;display:flex;flex-direction:column;gap:26px}.brand{display:flex;align-items:center;gap:11px;padding:0 8px}.logo{width:42px;height:42px;display:grid;place-items:center;border-radius:14px;background:linear-gradient(145deg,#284c78,#172941);border:1px solid #3a5b85;color:#b8d6ff;font-size:22px}.brand strong{display:block;font-size:16px}.brand small{color:var(--muted);font-size:10px;letter-spacing:.13em;text-transform:uppercase}.nav-label{color:#60738e;font-size:10px;letter-spacing:.16em;font-weight:800;padding:0 12px;margin-bottom:8px}.nav{display:grid;gap:5px}.nav button{border:1px solid transparent;background:transparent;color:#9dafc8;padding:11px 12px;border-radius:11px;text-align:left;display:flex;gap:12px;align-items:center}.nav button .ico{width:22px;text-align:center;font-size:16px}.nav button:hover{background:#131f31;color:#fff}.nav button.active{background:#182b45;border-color:#2a4567;color:#e9f3ff}.side-bottom{margin-top:auto}.sitebox{border:1px solid var(--line);border-radius:13px;padding:13px;background:#101a2a}.sitebox small{color:var(--muted);display:block}.sitebox strong{display:block;margin-top:4px}.main{min-width:0;padding:26px clamp(16px,3vw,38px) 35px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:27px}.mobile-brand{display:none}.connection{display:inline-flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;border:1px solid var(--line);border-radius:999px;padding:8px 12px}.dot{width:7px;height:7px;border-radius:50%;background:var(--amber)}.dot.ok{background:var(--green)}.dot.bad{background:var(--red)}.top-actions{display:flex;gap:9px;align-items:center}.btn{border:1px solid #2b405b;background:#17263a;color:#dceaff;border-radius:10px;padding:9px 12px;font-size:12px}.btn:hover{border-color:#5480b4}.btn.primary{background:#244a79;border-color:#35649a}.page{display:none}.page.active{display:block}.eyebrow{color:var(--blue);font-size:10px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}.hero{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:21px}.hero h1{font-size:clamp(26px,3vw,35px);letter-spacing:-.05em;line-height:1.1;margin:7px 0}.hero p{margin:0;color:var(--muted);max-width:650px}.muted{color:var(--muted)}.small{font-size:11px}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px}.panel{background:linear-gradient(145deg,#121d2e,#0d1523);border:1px solid var(--line);border-radius:17px;padding:19px;min-width:0;box-shadow:0 12px 35px #0002}.metric-top{display:flex;align-items:center;justify-content:space-between;gap:8px}.metric-title{font-size:11px;color:var(--muted);font-weight:800;letter-spacing:.09em;text-transform:uppercase}.iconbox{width:37px;height:37px;border-radius:12px;background:#17283e;border:1px solid #2a405c;display:grid;place-items:center;color:#b5d4ff;font-size:17px}.metric-value{font-size:clamp(19px,2vw,25px);font-weight:800;letter-spacing:-.04em;margin:16px 0 4px;overflow-wrap:anywhere}.state{font-size:11px;font-weight:800;display:inline-flex;align-items:center;gap:7px}.state:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}.ok{color:var(--green)!important}.bad{color:var(--red)!important}.wait{color:var(--amber)!important}.section{margin-top:17px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}.section-head h2{font-size:16px;margin:0;letter-spacing:-.02em}.section-head p{margin:3px 0 0;color:var(--muted);font-size:11px}.topology{display:grid;grid-template-columns:1fr 32px 1fr 32px 1fr;align-items:center;gap:8px}.node{border:1px solid #2a3d56;background:#121e30;border-radius:14px;text-align:center;padding:17px 8px;min-width:0}.node .ni{font-size:22px}.node strong{display:block;font-size:12px;margin-top:7px}.node small{display:block;color:var(--muted);font-size:10px;overflow-wrap:anywhere}.arrow{text-align:center;color:#6786ae;font-size:20px}.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.rows{display:grid}.row{display:flex;justify-content:space-between;gap:12px;border-top:1px solid #243249;padding:11px 0;font-size:12px}.row:first-child{border-top:0}.row span{color:var(--muted)}.row strong{text-align:right;overflow-wrap:anywhere}.notice{background:#172237;border:1px solid #2a3b54;color:var(--muted);padding:12px 14px;border-radius:12px;font-size:11px;margin-top:13px}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:13px}.table{width:100%;border-collapse:collapse;min-width:560px;font-size:12px}.table th,.table td{text-align:left;padding:12px 13px;border-bottom:1px solid #243249}.table th{color:#8fa2bd;background:#111c2b;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.table tr:last-child td{border-bottom:0}.badge{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:4px 8px;font-size:10px;font-weight:800}.badge.ok{border-color:#235947;background:#102a25}.badge.bad{border-color:#66313b;background:#301a23}.badge.wait{border-color:#5c4b2b;background:#2a2418}.chartbox{height:270px;position:relative}.chartbox canvas{width:100%;height:100%;display:block}.chart-controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.field{background:#0c1422;border:1px solid #2a3b54;color:var(--text);padding:9px 10px;border-radius:9px;max-width:100%}.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:13px}.map-frame{height:430px;width:100%;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:#0b1220}.map-frame .leaflet-container{height:100%;width:100%;background:#0b1220;font:12px system-ui}.map-frame .leaflet-popup-content-wrapper,.map-frame .leaflet-popup-tip{background:#101827;color:#edf4ff}.map-frame .leaflet-control-attribution{background:#101827dd;color:#8fa2bd}.map-frame .leaflet-control-attribution a{color:#69a7ff}.map-legend{display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:var(--muted)}.map-pin{border:2px solid #edf4ff;border-radius:50%;width:15px;height:15px;box-shadow:0 0 0 4px #10182788}.map-pin.ok{background:#42dfaa}.map-pin.bad{background:#ff7185}.map-pin.wait{background:#ffd078}.fieldlabel{display:block;font-size:12px;color:var(--muted);margin-bottom:7px}.empty{padding:30px;text-align:center;color:var(--muted);font-size:12px}.footer{color:#637791;font-size:10px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:24px}.hamburger{display:none}.mobile-nav{display:none}
@media(max-width:900px){.app{grid-template-columns:205px minmax(0,1fr)}.sidebar{padding:20px 10px}.main{padding:22px 17px}.cards{grid-template-columns:1fr 1fr}.cards .metric:last-child{grid-column:1/-1}.topology{grid-template-columns:1fr;gap:5px}.arrow{transform:rotate(90deg);height:22px}.node{padding:12px}.node .ni{font-size:18px}.node strong{margin-top:3px}}
@media(max-width:650px){.app{display:block}.sidebar{display:none}.main{padding:14px 12px 28px}.topbar{margin-bottom:22px}.mobile-brand{display:flex;align-items:center;gap:9px}.mobile-brand .logo{width:36px;height:36px}.mobile-brand strong{font-size:14px}.hamburger{display:inline-block}.top-actions .btn.export-label{display:none}.connection{padding:7px 9px;font-size:10px}.hero{display:block}.hero p{font-size:12px}.hero .smallnote{margin-top:12px}.cards{grid-template-columns:1fr 1fr;gap:9px}.panel{padding:14px;border-radius:14px}.metric-value{font-size:19px;margin-top:12px}.metric-title{font-size:9px}.iconbox{width:31px;height:31px}.cards .metric:last-child{grid-column:auto}.grid2,.settings-grid{grid-template-columns:1fr}.topology{grid-template-columns:1fr}.section-head{align-items:flex-start}.chartbox{height:220px}.map-frame{height:360px}.mobile-nav{display:flex;position:fixed;z-index:20;left:8px;right:8px;bottom:8px;justify-content:space-around;gap:3px;padding:7px;background:#111c2bf2;border:1px solid #2b3c53;border-radius:16px;backdrop-filter:blur(15px)}.mobile-nav button{flex:1;border:0;background:transparent;color:#8fa2bd;border-radius:10px;padding:8px 3px;font-size:9px}.mobile-nav button span{display:block;font-size:16px;margin-bottom:2px}.mobile-nav button.active{background:#1b304c;color:#e9f3ff}.footer{padding-bottom:68px}.hero h1{font-size:27px}}
</style></head><body>
<div class="app"><aside class="sidebar"><div class="brand"><div class="logo">⌁</div><div><strong>NetWatch</strong><small>Network monitor</small></div></div><div><div class="nav-label">WORKSPACE</div><nav class="nav" id="side-nav"><button class="active" data-page="dashboard"><span class="ico">▦</span>Dashboard</button><button data-page="devices"><span class="ico">⌘</span>Perangkat</button><button data-page="topology"><span class="ico">⌁</span>Topologi</button><button data-page="charts"><span class="ico">▥</span>Grafik</button><button data-page="logs"><span class="ico">≡</span>Log Aktivitas</button><button data-page="settings"><span class="ico">⚙</span>Pengaturan</button></nav></div><div class="side-bottom sitebox"><small>Site monitoring</small><strong id="site-side">NetWatch Site</strong><small style="margin-top:8px">MikroTik · CCTV</small></div></aside>
<main class="main"><header class="topbar"><div class="mobile-brand"><div class="logo">⌁</div><strong>NetWatch</strong></div><div class="connection"><span id="connection-dot" class="dot"></span><span id="connection-label">Menghubungkan…</span></div><div class="top-actions"><button class="btn export-label" onclick="exportCSV()">↓ Ekspor CSV</button><button class="btn hamburger" onclick="toggleMobileNav()">☰ Menu</button></div></header>
<section class="page active" id="page-dashboard"><div class="hero"><div><div class="eyebrow">Overview / Site monitor</div><h1>Dashboard</h1><p>Status perangkat, kondisi koneksi, dan ringkasan gangguan terbaru.</p></div><div class="small muted smallnote">Update otomatis setiap 10 detik<br><strong id="last-update">Menunggu heartbeat</strong></div></div>
<div class="cards"><article class="panel"><div class="metric-top"><div class="metric-title">MikroTik / Agent</div><div class="iconbox">⌘</div></div><div class="metric-value" id="router-main">Belum ada data</div><div class="state wait" id="router-state">Menunggu laporan</div><div class="muted small" style="margin-top:10px">Status heartbeat agent</div></article><article class="panel"><div class="metric-top"><div class="metric-title">CCTV</div><div class="iconbox">▣</div></div><div class="metric-value" id="cctv-main">Belum ada data</div><div class="state wait" id="cctv-state">Menunggu pemeriksaan</div><div class="muted small" style="margin-top:10px">192.168.1.235</div></article><article class="panel"><div class="metric-top"><div class="metric-title">Ping terakhir</div><div class="iconbox">◷</div></div><div class="metric-value" id="ping-main">—</div><div class="state wait" id="ping-state">Belum ada sampel</div><div class="muted small" style="margin-top:10px" id="age-main">Menunggu laporan</div></article></div>
<div class="section panel"><div class="section-head"><div><h2>Topologi jaringan</h2><p>Ilustrasi jalur jaringan; status hanya berdasarkan data yang tersedia.</p></div><button class="btn" onclick="navigate('topology')">Detail</button></div><div class="topology"><div class="node"><div class="ni">☁</div><strong>Starlink / Internet</strong><small>Belum ada probe WAN</small><div class="state wait" style="justify-content:center;margin-top:8px">Belum dipantau</div></div><div class="arrow">→</div><div class="node"><div class="ni">⌘</div><strong>MikroTik / Agent</strong><small id="topo-router-detail">Menunggu data</small><div class="state wait" id="topo-router" style="justify-content:center;margin-top:8px">Menunggu data</div></div><div class="arrow">→</div><div class="node"><div class="ni">▣</div><strong>CCTV</strong><small>192.168.1.235</small><div class="state wait" id="topo-cctv" style="justify-content:center;margin-top:8px">Menunggu data</div></div></div><div class="notice">Server tidak melakukan ping ke jaringan lokal. Agent yang berada di jaringan harus mengirim hasil pemeriksaan melalui endpoint heartbeat.</div></div>
<div class="section panel"><div class="section-head"><div><h2>Peta lokasi perangkat</h2><p>Marker muncul setelah koordinat disimpan di Pengaturan.</p></div><button class="btn" onclick="navigate('topology')">Buka peta lengkap</button></div><div id="dashboard-map" class="map-frame"></div><div class="notice" id="dashboard-map-note">Koordinat belum dikonfigurasi. Masukkan latitude dan longitude di Pengaturan.</div></div>
<div class="section grid2"><div class="panel"><div class="section-head"><div><h2>Detail perangkat</h2><p>Snapshot laporan terakhir</p></div><button class="btn" onclick="navigate('devices')">Semua perangkat</button></div><div class="rows"><div class="row"><span>Uptime MikroTik</span><strong id="uptime">—</strong></div><div class="row"><span>Site</span><strong id="site">—</strong></div><div class="row"><span>Balasan CCTV</span><strong id="cctv-replies">—</strong></div><div class="row"><span>Laporan terakhir</span><strong id="received-at">—</strong></div></div></div><div class="panel"><div class="section-head"><div><h2>Gangguan aktif</h2><p>Durasi dihitung sejak transisi offline terdeteksi.</p></div><button class="btn" onclick="navigate('logs')">Lihat log</button></div><div id="active-outages" class="empty">Memuat status gangguan…</div></div></div>
</section>
<section class="page" id="page-devices"><div class="hero"><div><div class="eyebrow">Inventory</div><h1>Perangkat</h1><p>Daftar perangkat yang dipantau dan sumber statusnya.</p></div></div><div class="panel"><div class="section-head"><div><h2>Daftar perangkat</h2><p>Status tidak akan ditebak jika belum ada laporan.</p></div><button class="btn" onclick="loadDevices()">↻ Refresh</button></div><div class="tablewrap"><table class="table"><thead><tr><th>Perangkat</th><th>Tipe</th><th>Alamat / sumber</th><th>Status</th><th>Detail</th></tr></thead><tbody id="devices-table"><tr><td colspan="5" class="empty">Memuat…</td></tr></tbody></table></div></div></section>
<section class="page" id="page-topology"><div class="hero"><div><div class="eyebrow">Network map</div><h1>Topologi</h1><p>Alur logis Starlink → MikroTik → CCTV.</p></div></div><div class="panel"><div class="topology"><div class="node"><div class="ni">☁</div><strong>Starlink / Internet</strong><small>WAN</small><div class="state wait" style="justify-content:center;margin-top:8px">Belum dipantau</div></div><div class="arrow">→</div><div class="node"><div class="ni">⌘</div><strong>MikroTik</strong><small>Router / gateway</small><div class="state wait" id="topo-router-page" style="justify-content:center;margin-top:8px">Menunggu data</div></div><div class="arrow">→</div><div class="node"><div class="ni">▣</div><strong>CCTV</strong><small>192.168.1.235</small><div class="state wait" id="topo-cctv-page" style="justify-content:center;margin-top:8px">Menunggu data</div></div></div><div class="notice">Starlink belum diuji langsung oleh server ini. Tambahkan probe WAN di agent bila ingin memantau koneksi internet secara eksplisit.</div></div><div class="section panel"><div class="section-head"><div><h2>Peta geografis interaktif</h2><p>Leaflet + OpenStreetMap. Tidak ada koordinat yang diasumsikan.</p></div><button class="btn" onclick="loadMap(true)">↻ Muat ulang peta</button></div><div id="topology-map" class="map-frame"></div><div class="map-legend" style="margin-top:12px"><span>● <b class="ok">Online</b></span><span>● <b class="bad">Offline</b></span><span>● <b class="wait">Belum diketahui</b></span></div><div class="notice" id="topology-map-note">Masukkan koordinat di halaman Pengaturan untuk menampilkan marker.</div></div></section>
<section class="page" id="page-charts"><div class="hero"><div><div class="eyebrow">Telemetry</div><h1>Grafik</h1><p>Grafik dibuat dari sampel heartbeat yang benar-benar diterima. Tidak ada data contoh yang ditambahkan.</p></div><div class="chart-controls"><select class="field" id="range-hours" onchange="loadHistory()"><option value="1">1 jam</option><option value="6">6 jam</option><option value="24" selected>24 jam</option><option value="168">7 hari</option><option value="720">30 hari</option></select><button class="btn" onclick="loadHistory()">↻ Refresh</button></div></div><div class="panel"><div class="section-head"><div><h2>Ping agent (ms)</h2><p>Hanya sampel ping_ms yang dikirim agent.</p></div><span id="ping-sample-count" class="badge">0 sampel</span></div><div class="chartbox"><canvas id="ping-chart"></canvas></div><div id="ping-chart-empty" class="empty">Belum ada data ping untuk rentang ini.</div></div><div class="section panel"><div class="section-head"><div><h2>Balasan pemeriksaan CCTV</h2><p>Nilai dari cctv_replies yang dikirim agent.</p></div><span id="cctv-sample-count" class="badge">0 sampel</span></div><div class="chartbox"><canvas id="cctv-chart"></canvas></div><div id="cctv-chart-empty" class="empty">Belum ada data pemeriksaan CCTV untuk rentang ini.</div></div></section>
<section class="page" id="page-logs"><div class="hero"><div><div class="eyebrow">Audit trail</div><h1>Log Aktivitas</h1><p>Riwayat offline, pemulihan, dan alarm ping tinggi yang terdeteksi server.</p></div><button class="btn" onclick="loadEvents()">↻ Refresh</button></div><div class="panel"><div class="section-head"><div><h2>Gangguan aktif</h2><p>Gangguan belum pulih.</p></div></div><div class="tablewrap"><table class="table"><thead><tr><th>Perangkat</th><th>Mulai</th><th>Durasi</th></tr></thead><tbody id="outages-table"><tr><td colspan="3" class="empty">Memuat…</td></tr></tbody></table></div></div><div class="section panel"><div class="section-head"><div><h2>Riwayat peristiwa</h2><p>Catatan disimpan di database SQLite.</p></div><button class="btn" onclick="exportCSV()">↓ Ekspor CSV heartbeat</button></div><div class="tablewrap"><table class="table"><thead><tr><th>Waktu (UTC)</th><th>Perangkat</th><th>Peristiwa</th><th>Pesan</th><th>Durasi</th></tr></thead><tbody id="events-table"><tr><td colspan="5" class="empty">Memuat…</td></tr></tbody></table></div></div></section>
<section class="page" id="page-settings"><div class="hero"><div><div class="eyebrow">Configuration</div><h1>Pengaturan</h1><p>Pengaturan tampilan dan status konfigurasi. Token tidak pernah ditampilkan di dashboard.</p></div></div><div class="panel"><div class="section-head"><div><h2>Preferensi dashboard</h2><p>Pengaturan ini tidak mengubah secret environment Railway.</p></div></div><div class="settings-grid"><label><span class="fieldlabel">Nama site dashboard</span><input class="field" id="site-label-input" maxlength="100" placeholder="NetWatch Site" style="width:100%"></label><div><span class="fieldlabel">Batas heartbeat kedaluwarsa</span><div class="field" id="stale-setting">—</div></div><div><span class="fieldlabel">Ambang ping tinggi</span><div class="field" id="ping-setting">—</div></div><div><span class="fieldlabel">Telegram</span><div class="field" id="telegram-setting">Memeriksa konfigurasi…</div></div></div><div style="margin-top:15px;display:flex;gap:9px;flex-wrap:wrap"><button class="btn primary" onclick="saveSettings()">Simpan nama site</button><button class="btn" onclick="testTelegram()">Kirim tes Telegram</button></div><div class="notice" id="settings-message">Secret Telegram harus diatur melalui environment variables TELEGRAM_BOT_TOKEN dan TELEGRAM_CHAT_ID di Railway.</div></div><div class="section panel"><div class="section-head"><div><h2>Koordinat peta</h2><p>Isi dari GPS atau sumber koordinat resmi. Kosongkan jika belum diketahui.</p></div></div><div class="settings-grid"><label><span class="fieldlabel">MikroTik latitude</span><input class="field" id="router-lat" type="number" min="-90" max="90" step="any" placeholder="-6.200000" style="width:100%"></label><label><span class="fieldlabel">MikroTik longitude</span><input class="field" id="router-lon" type="number" min="-180" max="180" step="any" placeholder="106.816666" style="width:100%"></label><label><span class="fieldlabel">CCTV latitude</span><input class="field" id="cctv-lat" type="number" min="-90" max="90" step="any" placeholder="Latitude CCTV" style="width:100%"></label><label><span class="fieldlabel">CCTV longitude</span><input class="field" id="cctv-lon" type="number" min="-180" max="180" step="any" placeholder="Longitude CCTV" style="width:100%"></label></div><div style="margin-top:15px;display:flex;gap:9px;flex-wrap:wrap"><button class="btn primary" onclick="saveSettings()">Simpan nama site & koordinat</button><button class="btn" onclick="clearMapCoordinates()">Hapus koordinat</button></div><div class="notice">Koordinat kosong tidak akan menampilkan marker. Kalau router dan CCTV berada di lokasi fisik yang sama, lo boleh memasukkan koordinat site yang sama untuk keduanya. Peta memerlukan koneksi internet untuk memuat tile OpenStreetMap dan library Leaflet.</div></div><div class="section panel"><h2 style="font-size:15px;margin-top:0">Environment variables</h2><div class="rows"><div class="row"><span>DASH_USER</span><strong>Username login dashboard</strong></div><div class="row"><span>DASH_PASS</span><strong>Password dashboard (wajib diisi)</strong></div><div class="row"><span>AGENT_TOKEN</span><strong>Token rahasia untuk heartbeat</strong></div><div class="row"><span>TELEGRAM_BOT_TOKEN</span><strong>Token bot Telegram (opsional)</strong></div><div class="row"><span>TELEGRAM_CHAT_ID</span><strong>Chat ID penerima (opsional)</strong></div><div class="row"><span>HIGH_PING_MS</span><strong>Ambang alarm ping, default 150 ms</strong></div><div class="row"><span>STALE_AFTER_SECONDS</span><strong>Batas laporan kedaluwarsa, default 180 detik</strong></div></div></div></section>
<footer class="footer"><span>NETWATCH · MIKROTIK + CCTV · v3.0</span><span id="footer-status">API siap</span></footer></main></div>
<nav class="mobile-nav" id="mobile-nav"><button class="active" data-page="dashboard"><span>▦</span>Dashboard</button><button data-page="devices"><span>⌘</span>Perangkat</button><button data-page="topology"><span>⌁</span>Topologi</button><button data-page="charts"><span>▥</span>Grafik</button><button data-page="logs"><span>≡</span>Log</button><button data-page="settings"><span>⚙</span>Setting</button></nav>
<script>
const $=id=>document.getElementById(id);let currentPage='dashboard';
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function state(el,text,kind){if(!el)return;el.textContent=text;el.className='state '+kind;}
function badge(online){return online===true?'<span class="badge ok">ONLINE</span>':online===false?'<span class="badge bad">OFFLINE</span>':'<span class="badge wait">UNKNOWN</span>';}
function dur(s){if(s==null||!Number.isFinite(Number(s)))return '—';s=Math.max(0,Math.floor(Number(s)));let d=Math.floor(s/86400);s%=86400;let h=Math.floor(s/3600);s%=3600;let m=Math.floor(s/60);s%=60;return (d?d+'h ':'')+(h?h+'j ':'')+(m?m+'m ':'')+s+'d';}
function fmtTime(v){if(!v)return '—';try{return new Date(v).toLocaleString('id-ID',{timeZone:'UTC',hour12:false})+' UTC'}catch{return v}}
async function api(url,opts={}){let r=await fetch(url,{cache:'no-store',...opts});if(!r.ok)throw Error('HTTP '+r.status);return r;}
function navigate(page){currentPage=page;document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+page));document.querySelectorAll('[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===page));if(page==='devices')loadDevices();if(page==='charts')loadHistory();if(page==='logs')loadEvents();if(page==='settings')loadSettings();if(page==='topology'||page==='dashboard')loadMap(true);window.scrollTo({top:0,behavior:'smooth'});}
function toggleMobileNav(){const n=$('mobile-nav');n.style.display=n.style.display==='none'?'flex':'flex';}
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.page)));
async function refreshStatus(){try{let d=await (await api('/api/status')).json();$('connection-dot').className='dot ok';$('connection-label').textContent='API terhubung';$('footer-status').textContent='Pembaruan '+new Date().toLocaleTimeString('id-ID');
if(!d.received_at){$('last-update').textContent='Belum ada heartbeat';$('router-main').textContent='Belum ada data';$('cctv-main').textContent='Belum ada data';$('ping-main').textContent='—';state($('router-state'),'Menunggu laporan','wait');state($('cctv-state'),'Menunggu pemeriksaan','wait');state($('ping-state'),'Belum ada sampel','wait');$('age-main').textContent='Agent belum mengirim data';$('uptime').textContent='—';$('site').textContent='—';$('cctv-replies').textContent='—';$('received-at').textContent='—';state($('topo-router'),'Menunggu data','wait');state($('topo-cctv'),'Menunggu data','wait');state($('topo-router-page'),'Menunggu data','wait');state($('topo-cctv-page'),'Menunggu data','wait');$('topo-router-detail').textContent='Menunggu data';return;}
const stale=!!d.stale, rOnline=stale?false:d.router_online, cOnline=stale?null:d.cctv_online;$('last-update').textContent=fmtTime(d.received_at);$('router-main').textContent=stale?'Laporan kedaluwarsa':'Agent aktif';state($('router-state'),stale?'Tidak ada heartbeat baru':'Heartbeat diterima',stale?'bad':'ok');$('cctv-main').textContent=cOnline===true?'Terjangkau':stale?'Tidak terverifikasi':cOnline===false?'Tidak merespons':'Belum diketahui';state($('cctv-state'),stale?'Data kedaluwarsa':cOnline===true?'Ada balasan':'Tidak ada balasan',stale?'wait':cOnline===true?'ok':'bad');$('ping-main').textContent=d.ping_ms==null?'—':Number(d.ping_ms).toFixed(1)+' ms';let high=Number(d.ping_ms)>=Number($('ping-setting')?.dataset?.threshold||150);state($('ping-state'),d.ping_ms==null?'Tidak dikirim agent':high?'Ping tinggi':'Sampel diterima',d.ping_ms==null?'wait':high?'bad':'ok');$('age-main').textContent='Heartbeat '+dur(d.age_seconds)+' lalu';$('uptime').textContent=d.router_uptime||'Tidak dikirim agent';$('site').textContent=d.site||'—';$('cctv-replies').textContent=d.cctv_replies??'—';$('received-at').textContent=fmtTime(d.received_at);state($('topo-router'),stale?'Laporan putus':'Agent aktif',stale?'bad':'ok');state($('topo-router-page'),stale?'Laporan putus':'Agent aktif',stale?'bad':'ok');$('topo-router-detail').textContent=stale?'Heartbeat kedaluwarsa':'Heartbeat diterima';state($('topo-cctv'),stale?'Tidak terverifikasi':cOnline?'Terjangkau':'Tidak merespons',stale?'wait':cOnline?'ok':'bad');state($('topo-cctv-page'),stale?'Tidak terverifikasi':cOnline?'Terjangkau':'Tidak merespons',stale?'wait':cOnline?'ok':'bad');
}catch(e){$('connection-dot').className='dot bad';$('connection-label').textContent='API gagal';$('footer-status').textContent='Gagal memuat status';console.error(e)} }
async function loadDevices(){try{let d=await (await api('/api/devices')).json();$('devices-table').innerHTML=d.devices.map(x=>`<tr><td><strong>${esc(x.name)}</strong></td><td>${esc(x.type)}</td><td>${esc(x.address)}</td><td>${badge(x.online)}</td><td>${esc(x.detail)}</td></tr>`).join('')}catch(e){$('devices-table').innerHTML=`<tr><td colspan="5" class="empty">Gagal memuat perangkat: ${esc(e.message)}</td></tr>`}}
async function loadEvents(){try{let d=await (await api('/api/events?limit=200')).json();$('active-outages').innerHTML=d.active_outages.length?d.active_outages.map(o=>`<div class="row"><span>${esc(o.device)} sejak ${esc(fmtTime(o.started_at))}</span><strong class="bad">${esc(dur(o.duration_seconds))}</strong></div>`).join(''):'<div class="empty">Tidak ada gangguan aktif yang tercatat.</div>';$('outages-table').innerHTML=d.active_outages.length?d.active_outages.map(o=>`<tr><td>${esc(o.device)}</td><td>${esc(fmtTime(o.started_at))}</td><td>${esc(dur(o.duration_seconds))}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">Tidak ada gangguan aktif.</td></tr>';$('events-table').innerHTML=d.events.length?d.events.map(e=>`<tr><td>${esc(fmtTime(e.event_at))}</td><td>${esc(e.device)}</td><td><span class="badge ${e.event==='RECOVERED'?'ok':e.event==='OFFLINE'?'bad':'wait'}">${esc(e.event)}</span></td><td>${esc(e.message)}</td><td>${e.duration_seconds==null?'—':esc(dur(e.duration_seconds))}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">Belum ada peristiwa tercatat.</td></tr>'}catch(e){$('events-table').innerHTML=`<tr><td colspan="5" class="empty">Gagal memuat log: ${esc(e.message)}</td></tr>`}}
function drawChart(canvasId,points,key,color){const c=$(canvasId),ctx=c.getContext('2d'),box=c.getBoundingClientRect(),ratio=window.devicePixelRatio||1;c.width=Math.max(1,box.width*ratio);c.height=Math.max(1,box.height*ratio);ctx.scale(ratio,ratio);const w=box.width,h=box.height,pad={l:38,r:12,t:15,b:27};ctx.clearRect(0,0,w,h);let vals=points.map(p=>p[key]).filter(v=>v!==null&&v!==undefined&&Number.isFinite(Number(v))).map(Number);if(!vals.length)return false;let min=Math.min(0,...vals),max=Math.max(...vals);if(max===min)max=min+1;ctx.font='10px system-ui';ctx.strokeStyle='#26364d';ctx.fillStyle='#8fa2bd';ctx.lineWidth=1;for(let i=0;i<5;i++){let y=pad.t+(h-pad.t-pad.b)*i/4;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();ctx.fillText((max-(max-min)*i/4).toFixed(max<10?1:0),3,y+3)}const x=i=>pad.l+(w-pad.l-pad.r)*(points.length<2?0:i/(points.length-1));const y=v=>pad.t+(h-pad.t-pad.b)*(max-v)/(max-min);ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();let started=false;points.forEach((p,i)=>{let v=p[key];if(v===null||v===undefined||!Number.isFinite(Number(v))){started=false;return}if(!started){ctx.moveTo(x(i),y(Number(v)));started=true}else ctx.lineTo(x(i),y(Number(v)))});ctx.stroke();ctx.fillStyle='#8fa2bd';ctx.fillText(points[0]?.received_at?new Date(points[0].received_at).toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit',timeZone:'UTC'}):'',pad.l,w-60,h-7);let last=points[points.length-1];if(last?.received_at)ctx.fillText(new Date(last.received_at).toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit',timeZone:'UTC'}),Math.max(pad.l,w-54),h-7);return true}
async function loadHistory(){try{let hrs=$('range-hours').value,d=await (await api('/api/history?hours='+hrs)).json(),pts=d.points||[];$('ping-sample-count').textContent=pts.filter(p=>p.ping_ms!=null).length+' sampel';$('cctv-sample-count').textContent=pts.length+' sampel';let a=drawChart('ping-chart',pts,'ping_ms','#69a7ff');$('ping-chart-empty').style.display=a?'none':'block';$('ping-chart').style.display=a?'block':'none';let b=drawChart('cctv-chart',pts,'cctv_replies','#42dfaa');$('cctv-chart-empty').style.display=b?'none':'block';$('cctv-chart').style.display=b?'block':'none'}catch(e){$('ping-chart-empty').textContent='Gagal memuat grafik: '+e.message;$('ping-chart-empty').style.display='block'}}
async function loadSettings(){try{let d=await (await api('/api/settings')).json();$('stale-setting').textContent=d.stale_after_seconds+' detik';$('ping-setting').textContent=d.high_ping_ms+' ms';$('ping-setting').dataset.threshold=d.high_ping_ms;$('telegram-setting').textContent=d.telegram_configured?'Terkonfigurasi':'Belum dikonfigurasi';$('telegram-setting').className='field '+(d.telegram_configured?'ok':'wait');$('site-label-input').value=d.site_label;$('site-side').textContent=d.site_label;$('router-lat').value=d.router_lat??'';$('router-lon').value=d.router_lon??'';$('cctv-lat').value=d.cctv_lat??'';$('cctv-lon').value=d.cctv_lon??''}catch(e){$('settings-message').textContent='Gagal membaca pengaturan: '+e.message}}
async function saveSettings(){try{let payload={site_label:$('site-label-input').value,router_lat:$('router-lat').value,router_lon:$('router-lon').value,cctv_lat:$('cctv-lat').value,cctv_lon:$('cctv-lon').value};let r=await api('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});let d=await r.json();$('site-side').textContent=d.site_label;$('settings-message').textContent='Nama site dan koordinat berhasil disimpan.';await loadMap(true)}catch(e){$('settings-message').textContent='Gagal menyimpan: '+e.message}}
async function clearMapCoordinates(){$('router-lat').value='';$('router-lon').value='';$('cctv-lat').value='';$('cctv-lon').value='';await saveSettings()}
async function testTelegram(){try{let r=await api('/api/telegram-test',{method:'POST'});let d=await r.json();$('settings-message').textContent=d.ok?'Pesan tes berhasil dikirim.':'Telegram belum terkonfigurasi atau pengiriman gagal.'}catch(e){$('settings-message').textContent='Tes Telegram gagal: '+e.message}}
let leafletMaps={dashboard:null,topology:null},mapLayers={dashboard:[],topology:[]},lastMapData=null;
function markerIcon(online){let kind=online===true?'ok':online===false?'bad':'wait';return L.divIcon({className:'',html:`<div class="map-pin ${kind}"></div>`,iconSize:[23,23],iconAnchor:[11,11]})}
function ensureLeafletMap(which){if(!window.L){const note=$(which==='dashboard'?'dashboard-map-note':'topology-map-note');if(note)note.textContent='Leaflet tidak termuat. Periksa koneksi internet atau CDN.';return null}let id=which==='dashboard'?'dashboard-map':'topology-map';if(!leafletMaps[which]){leafletMaps[which]=L.map(id,{scrollWheelZoom:false}).setView([0,0],2);L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a>'}).addTo(leafletMaps[which])}return leafletMaps[which]}
async function loadMap(force=false){try{let d=await (await api('/api/map')).json();lastMapData=d;['dashboard','topology'].forEach(which=>{let map=ensureLeafletMap(which);if(!map)return;mapLayers[which].forEach(layer=>map.removeLayer(layer));mapLayers[which]=[];let pts=[];for(let [key,label] of [['router','MikroTik'],['cctv','CCTV']]){let x=d[key];if(typeof x.lat!=='number'||typeof x.lon!=='number'||!Number.isFinite(x.lat)||!Number.isFinite(x.lon))continue;let status=x.online===true?'ONLINE':x.online===false?'OFFLINE':'BELUM DIKETAHUI';let mk=L.marker([x.lat,x.lon],{icon:markerIcon(x.online)}).addTo(map).bindPopup(`<strong>${esc(label)}</strong><br>${esc(d.site_label)}<br>Status: ${esc(status)}<br>${esc(x.detail||'')}<br><small>${x.lat.toFixed(6)}, ${x.lon.toFixed(6)}</small>`);mapLayers[which].push(mk);pts.push([x.lat,x.lon])}if(pts.length===1)map.setView(pts[0],15);else if(pts.length>1)map.fitBounds(pts,{padding:[35,35],maxZoom:16});else map.setView([0,0],2);setTimeout(()=>map.invalidateSize(),100)});let configured=Boolean((d.router&&typeof d.router.lat==='number'&&typeof d.router.lon==='number')||(d.cctv&&typeof d.cctv.lat==='number'&&typeof d.cctv.lon==='number'));let msg=configured?'Marker memakai koordinat yang disimpan di Pengaturan. Status berasal dari heartbeat agent.':'Koordinat belum dikonfigurasi. Buka Pengaturan dan masukkan latitude/longitude yang benar; peta tidak menebak lokasi.';if($('dashboard-map-note'))$('dashboard-map-note').textContent=msg;if($('topology-map-note'))$('topology-map-note').textContent=msg;if(force&&currentPage==='topology')setTimeout(()=>leafletMaps.topology?.invalidateSize(),120)}catch(e){console.error(e);if($('topology-map-note'))$('topology-map-note').textContent='Gagal memuat konfigurasi peta: '+e.message}}
function exportCSV(){window.location.href='/api/export.csv'}
refreshStatus();loadEvents();loadMap();setInterval(()=>{refreshStatus();loadEvents();if(currentPage==='devices')loadDevices();},10000);window.addEventListener('resize',()=>{if(currentPage==='charts')loadHistory()});
</script></body></html>'''


@app.post("/api/telegram-test")
def telegram_test(_: None = Depends(check_dashboard)):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {"ok": False, "configured": False}
    ok = telegram_send(f"[NetWatch] Tes notifikasi berhasil. Waktu: {iso_now()}")
    return {"ok": ok, "configured": True}
