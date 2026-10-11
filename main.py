import os
import time
import hmac
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="MikroTik CCTV Monitor")
security = HTTPBasic()

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
DASH_USER = os.environ.get("DASH_USER", "admin")
DASH_PASS = os.environ.get("DASH_PASS", "")

# Data sementara di memori; restart akan menghapus status terakhir.
latest = {}


class Heartbeat(BaseModel):
    site: str = "AQMS"
    cctv_replies: int = 0
    logger_replies: int = 0
    router_uptime: Optional[str] = None


def check_dashboard(user: HTTPBasicCredentials = Depends(security)):
    ok_user = hmac.compare_digest(
        user.username.encode(), DASH_USER.encode()
    )
    ok_pass = hmac.compare_digest(
        user.password.encode(), DASH_PASS.encode()
    ) if DASH_PASS else False

    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=401,
            detail="Login diperlukan",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.get("/", response_class=HTMLResponse)
def dashboard(_: None = Depends(check_dashboard)):
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="id">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Monitor</title>
<style>
body{font-family:Arial,sans-serif;background:#101722;color:#eef2f7;
margin:0;padding:24px}
h1{margin-bottom:5px}.muted{color:#9eacbd}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
gap:14px;margin-top:24px}
.card{background:#1b2635;border:1px solid #344154;border-radius:14px;padding:20px}
.status{font-size:23px;font-weight:bold;margin:12px 0}
.ok{color:#42d392}.bad{color:#ff7777}.wait{color:#ffd166}
small{color:#9eacbd}
</style>
</head>
<body>
<h1>Network Monitor</h1>
<div class="muted">MikroTik · CCTV · Data Logger</div>
<div id="updated" class="muted">Menunggu laporan pertama...</div>
<div class="grid">
 <div class="card"><small>MIKROTIK AGENT</small>
 <div id="router" class="status wait">Belum ada data</div>
 <div id="uptime">Uptime: -</div></div>
 <div class="card"><small>CCTV</small>
 <div id="cctv" class="status wait">Belum ada data</div>
 <div id="cctvdetail">Ping: -</div></div>
 <div class="card"><small>DATA LOGGER</small>
 <div id="logger" class="status wait">Belum ada data</div>
 <div id="loggerdetail">Ping: -</div></div>
</div>
<script>
function status(id, online, label) {
 const e = document.getElementById(id);
 e.textContent = label;
 e.className = 'status ' + (online ? 'ok' : 'bad');
}
async function refresh() {
 try {
  const r = await fetch('/api/status', {cache:'no-store'});
  if (!r.ok) throw Error('Tidak bisa membaca status');
  const d = await r.json();
  if (!d.received_at) {
   document.getElementById('updated').textContent =
     'Belum menerima laporan dari MikroTik';
   return;
  }
  if (d.stale) {
   status('router', false, 'STALE / TERPUTUS');
   status('cctv', false, 'DATA KEDALUWARSA');
   status('logger', false, 'DATA KEDALUWARSA');
  } else {
   status('router', true, 'AGENT ONLINE');
   status('cctv', d.cctv_replies > 0,
     d.cctv_replies > 0 ? 'TERJANGKAU' : 'TIDAK MERESPONS');
   status('logger', d.logger_replies > 0,
     d.logger_replies > 0 ? 'TERJANGKAU' : 'TIDAK MERESPONS');
  }
  document.getElementById('cctvdetail').textContent =
    'Balasan ping: ' + d.cctv_replies;
  document.getElementById('loggerdetail').textContent =
    'Balasan ping: ' + d.logger_replies;
  document.getElementById('uptime').textContent =
    'Uptime router: ' + (d.router_uptime || '-');
  document.getElementById('updated').textContent =
    'Laporan terakhir: ' + d.received_at +
    (d.stale ? ' — lebih dari 3 menit' : '');
 } catch(e) {
  document.getElementById('updated').textContent =
    'Gagal mengambil status: ' + e.message;
 }
}
refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
""")


@app.post("/api/heartbeat")
def heartbeat(
    data: Heartbeat,
    x_agent_token: str = Header(default="")
):
    if not AGENT_TOKEN or not hmac.compare_digest(
        x_agent_token, AGENT_TOKEN
    ):
        raise HTTPException(status_code=401, detail="Token salah")

    latest.clear()
    latest.update(data.model_dump())
    latest["received_at"] = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")
    latest["received_ts"] = time.time()
    return {"ok": True}


@app.get("/api/status")
def get_status(_: None = Depends(check_dashboard)):
    if not latest:
        return {
            "received_at": None,
            "stale": True,
            "cctv_replies": 0,
            "logger_replies": 0,
            "router_uptime": None,
        }

    age = time.time() - latest["received_ts"]
    return {
        **latest,
        "stale": age > 180,
        "age_seconds": int(age),
    }
