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
body {
  font-family: Arial, sans-serif;
  background: #07111f;
  color: #e8f0ff;
  margin: 0;
  padding: 24px;
}
h1 {
  font-size: 32px;
  margin-bottom: 8px;
  letter-spacing: -1px;
}
.muted {
  color: #8fa8cc;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-top: 28px;
}

@media (max-width: 600px) {
  body {
    padding: 16px;
  }

  h1 {
    font-size: 28px;
  }

  .card {
    padding: 20px;
  }
}
.card {
  background: linear-gradient(145deg, #12243b, #0c192b);
  border: 1px solid #243c5b;
  border-radius: 18px;
  padding: 24px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
  transition: border-color 0.2s, transform 0.2s;
}
.card:hover {
  border-color: #398bff;
  transform: translateY(-2px);
}
.card:nth-child(1) {
  border-bottom: 3px solid #398bff;
}
.card:nth-child(2) {
  border-bottom: 3px solid #2ee6a6;
}
.card:nth-child(3) {
  border-bottom: 3px solid #a66bff;
}
.status {
  font-size: 24px;
  font-weight: bold;
  margin: 16px 0;
}
.ok {
  color: #2ee6a6;
}
.bad {
  color: #ff647c;
}
.wait {
  color: #ffd166;
}
small {
  color: #9db4d4;
  letter-spacing: 1px;
  font-size: 12px;
}
</style>
</head>
<body>
<h1>Network Monitor</h1>
<div class="muted">MikroTik · CCTV · Data Logger</div>
<div id="updated" class="muted">Menunggu laporan pertama...</div>
<div class="card">
  <h2 style="margin-top:0">Status Jaringan</h2>
  <p class="muted">Ringkasan kondisi perangkat</p>

  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap">
    <div>
      <small>MIKROTIK</small>
      <div id="net-router" class="status wait">Menunggu data</div>
    </div>
    <div>
      <small>CCTV</small>
      <div id="net-cctv" class="status wait">Menunggu data</div>
    </div>
    <div>
      <small>DATA LOGGER</small>
      <div id="net-logger" class="status wait">Menunggu data</div>
    </div>
  </div>

  <hr style="border-color:#243c5b">
  <small>Laporan terakhir diterima</small>
  <div id="net-updated" style="margin-top:8px">Belum ada laporan</div>
</div>
<div class="grid">
  <div class="card">
    <small>MIKROTIK ROUTER</small>
    <div id="router" class="status wait">Belum ada data</div>
    <div id="uptime">Uptime: -</div>
  </div>

  <div class="card">
    <small>CCTV</small>
    <div id="cctv" class="status wait">Belum ada data</div>
    <div id="cctvdetail">Balasan ping: -</div>
    <div class="muted">IP: 192.168.1.235</div>
  </div>

  <div class="card">
    <small>DATA LOGGER</small>
    <div id="logger" class="status wait">Belum ada data</div>
    <div id="loggerdetail">Balasan ping: -</div>
    <div class="muted">IP: 192.168.88.15</div>
  </div>
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
  const nr = document.getElementById('net-router');
const nc = document.getElementById('net-cctv');
const nl = document.getElementById('net-logger');
const nu = document.getElementById('net-updated');

if (nr && nc && nl && nu) {
  const hasReport = Boolean(d.received_at);
  const fresh = hasReport && !d.stale;

  nr.textContent = !hasReport ? 'Menunggu data' : fresh ? 'AGENT ONLINE' : 'LAPORAN TERPUTUS';
  nr.className = 'status ' + (!hasReport ? 'wait' : fresh ? 'ok' : 'bad');

  nc.textContent = !hasReport ? 'Menunggu data' : fresh ? (d.cctv_replies > 0 ? 'TERJANGKAU' : 'TIDAK MERESPONS') : 'DATA KEDALUWARSA';
  nc.className = 'status ' + (!hasReport ? 'wait' : fresh && d.cctv_replies > 0 ? 'ok' : fresh ? 'bad' : 'wait');

  nl.textContent = !hasReport ? 'Menunggu data' : fresh ? (d.logger_replies > 0 ? 'TERJANGKAU' : 'TIDAK MERESPONS') : 'DATA KEDALUWARSA';
  nl.className = 'status ' + (!hasReport ? 'wait' : fresh && d.logger_replies > 0 ? 'ok' : fresh ? 'bad' : 'wait');

  nu.textContent = hasReport ? d.received_at : 'Belum ada laporan';
}
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
