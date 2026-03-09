import os
import re
import json
import hmac
import hashlib
import secrets
import base64
import time

from fastapi import FastAPI, Depends, HTTPException, Request, Header
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, text, Column, String, Integer, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional

# Config
DATABASE_URL = os.environ["DATABASE_URL"]
TOKEN_SECRET = os.environ["TOKEN_SECRET"].encode()
ADMIN_SECRET = os.environ["ADMIN_SECRET"]
STUDENT_ID_RE = re.compile(r"(?<!\d)(\d{8})(?!\d)")

# Auth
def require_admin(x_admin_secret: Optional[str] = Header(default=None)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorised.")


# Database
engine = create_engine(DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://"))
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Member(Base):
    __tablename__ = "members"
    id         = Column(Integer, primary_key=True)
    student_id = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True))


class MemberVoted(Base):
    __tablename__ = "members_voted"
    id         = Column(Integer, primary_key=True)
    student_id = Column(String, unique=True, nullable=False)
    issued_at  = Column(DateTime(timezone=True))


class Ballot(Base):
    __tablename__ = "ballots"
    id        = Column(Integer, primary_key=True)
    token     = Column(String, unique=True, nullable=False)
    submitted = Column(Boolean, default=False)


class ElectionState(Base):
    __tablename__ = "election_state"
    id         = Column(Integer, primary_key=True)
    status     = Column(String, default="pending")
    started_at = Column(DateTime(timezone=True))
    results_at = Column(DateTime(timezone=True))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Token signing
def sign_token(random_part: str) -> str:
    """
    Sign a random token string.
    Token format: <random_hex>.<hmac_hex>
    """
    mac = hmac.new(TOKEN_SECRET, random_part.encode(), hashlib.sha256).hexdigest()
    return f"{random_part}.{mac}"


def issue_ballot_token(db: Session) -> str:
    random_part = secrets.token_hex(32)
    token = sign_token(random_part)
    db.add(Ballot(token=token, submitted=False))
    return token


# App
app = FastAPI(title="HackSoc Election -- Registration Service")

STYLE = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #1c1f1e; color: #d4d8d5;
           min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: #222725; border: 1px solid #2e3532; border-radius: 10px;
            padding: 2.5rem; max-width: 420px; width: 100%; }
    h1 { color: #a8c5a0; font-size: 1.5rem; margin-bottom: 0.4rem; font-weight: 600; }
    p.sub { color: #7a8c7e; font-size: 0.88rem; margin-bottom: 1.8rem; }
    label { display: block; font-size: 0.82rem; color: #7a8c7e; margin-bottom: 0.4rem;
            text-transform: uppercase; letter-spacing: 0.05em; }
    input[type=text] { width: 100%; padding: 0.7rem 0.9rem; border-radius: 6px;
                       border: 1px solid #2e3532; background: #1a1f1d; color: #d4d8d5;
                       font-size: 1rem; outline: none; }
    input[type=text]:focus { border-color: #5a7a54; }
    button { width: 100%; margin-top: 1.2rem; padding: 0.75rem; border-radius: 6px;
             border: none; background: #4a7244; color: #e8f0e5; font-size: 0.95rem;
             font-weight: 600; cursor: pointer; }
    button:hover { opacity: 0.85; }
    .msg { margin-top: 1.2rem; padding: 0.75rem 1rem; border-radius: 6px;
           font-size: 0.88rem; display: none; }
    .msg.ok  { background: #2a3d28; color: #a8c5a0; border: 1px solid #3d5c3a; }
    .msg.err { background: #3d2828; color: #c5a0a0; border: 1px solid #5c3a3a; }
    .token-box { margin-top: 1rem; padding: 0.8rem 1rem; background: #1a1f1d;
                 border-radius: 6px; font-family: monospace; font-size: 0.82rem;
                 word-break: break-all; border: 1px solid #2e3532; color: #8aab82; }
    .locked { text-align: center; }
    .locked h1 { font-size: 1.3rem; margin-bottom: 1rem; }
"""


@app.get("/", response_class=HTMLResponse)
async def register_page(db: Session = Depends(get_db)):
    state = db.query(ElectionState).filter_by(id=1).first()
    if not state or state.status == "pending":
        return HTMLResponse(_locked("Registration is not open yet.",
                                    "The election has not started. Please wait."))
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HackSoc Elections -- Register</title>
    <style>{STYLE}</style>
</head>
<body>
<div class="card">
    <h1>HackSoc Committee Elections</h1>
    <p class="sub">Enter your University of Nottingham student ID to receive your ballot.</p>
    <label for="sid">Student ID</label>
    <input type="text" id="sid" placeholder="e.g. 20123456" autocomplete="off" maxlength="8" />
    <button onclick="verify()">Get My Ballot</button>
    <div class="msg" id="msg"></div>
</div>
<script>
async function verify() {{
    const sid = document.getElementById('sid').value.trim();
    const msg = document.getElementById('msg');
    if (!sid) {{ show(msg, 'Please enter your student ID.', false); return; }}
    const resp = await fetch('verify', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ student_id: sid }})
    }});
    const data = await resp.json();
    if (resp.ok) {{
        msg.className = 'msg ok';
        msg.innerHTML = 'Ballot issued. Your voting link:<div class="token-box">'
            + '<a href="http://localhost:10001/?token=' + data.token
            + '" style="color:#8aab82">http://localhost:10001/?token=' + data.token + '</a></div>';
        msg.style.display = 'block';
    }} else {{
        show(msg, data.detail || 'Error', false);
    }}
}}
function show(el, text, ok) {{
    el.textContent = text;
    el.className = 'msg ' + (ok ? 'ok' : 'err');
    el.style.display = 'block';
}}
</script>
</body></html>"""
    return HTMLResponse(html)


class VerifyRequest(BaseModel):
    student_id: str


@app.post("/verify")
async def verify(req: VerifyRequest, db: Session = Depends(get_db)):
    state = db.query(ElectionState).filter_by(id=1).first()
    if not state or state.status == "pending":
        raise HTTPException(403, "The election has not started yet.")

    sid = req.student_id.strip()
    if not re.fullmatch(r"\d{8}", sid):
        raise HTTPException(400, "Student ID must be exactly 8 digits.")

    if not db.query(Member).filter_by(student_id=sid).first():
        raise HTTPException(403, "Student ID not found. Are you a current HackSoc member?")

    if db.query(MemberVoted).filter_by(student_id=sid).first():
        raise HTTPException(409, "A ballot has already been issued for this student ID.")

    token = issue_ballot_token(db)
    db.add(MemberVoted(student_id=sid, issued_at=datetime.now(timezone.utc)))
    db.commit()
    return {"token": token}


# Member import
def _auth_form() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/register/">
    <title>HackSoc Elections -- Admin</title>
    <style>{STYLE}</style>
</head>
<body>
<div class="card">
    <h1>Admin Access</h1>
    <p class="sub">Enter the admin secret to continue.</p>
    <label for="s">Admin secret</label>
    <input type="password" id="s" />
    <button onclick="go()">Continue</button>
</div>
<script>
function go() {{
    const s = document.getElementById('s').value;
    location.href = 'import-members?secret=' + encodeURIComponent(s);
}}
</script>
</body></html>"""


@app.get("/import-members", response_class=HTMLResponse)
async def import_page(db: Session = Depends(get_db)):
    count = db.query(Member).count()
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HackSoc Elections -- Import Members</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #1c1f1e; color: #d4d8d5;
               padding: 2rem 1rem; max-width: 680px; margin: 0 auto; }}
        h1 {{ color: #a8c5a0; font-size: 1.4rem; margin-bottom: 0.3rem; }}
        .sub {{ color: #7a8c7e; font-size: 0.88rem; margin-bottom: 1.5rem; }}
        .card {{ background: #222725; border: 1px solid #2e3532; border-radius: 10px;
                 padding: 1.6rem; margin-bottom: 1.2rem; }}
        h2 {{ color: #8aab82; font-size: 0.95rem; margin-bottom: 0.8rem;
              text-transform: uppercase; letter-spacing: 0.06em; }}
        textarea {{ width: 100%; background: #1a1f1d; border: 1px solid #2e3532;
                    border-radius: 6px; color: #d4d8d5; padding: 0.7rem; font-family: monospace;
                    font-size: 0.8rem; resize: vertical; outline: none; }}
        textarea:focus {{ border-color: #5a7a54; }}
        .btn {{ padding: 0.55rem 1.1rem; border-radius: 6px; border: none; cursor: pointer;
                font-size: 0.85rem; font-weight: 600; margin-top: 0.8rem; }}
        .btn-primary {{ background: #4a7244; color: #e8f0e5; }}
        .btn-danger  {{ background: #7a4444; color: #f0e5e5; }}
        .btn:hover {{ opacity: 0.85; }}
        .msg {{ margin-top: 0.8rem; padding: 0.65rem 1rem; border-radius: 6px;
                font-size: 0.85rem; display: none; }}
        .msg.ok  {{ background: #2a3d28; color: #a8c5a0; border: 1px solid #3d5c3a; display: block; }}
        .msg.err {{ background: #3d2828; color: #c5a0a0; border: 1px solid #5c3a3a; display: block; }}
        .stat {{ display: inline-block; background: #2e3532; border-radius: 6px;
                 padding: 0.4rem 0.9rem; font-size: 0.85rem; margin-bottom: 1rem; }}
        .stat b {{ color: #a8c5a0; }}
        input[type=file] {{ color: #d4d8d5; font-size: 0.85rem; margin-top: 0.5rem; }}
    </style>
</head>
<body>
    <h1>Member Import</h1>
    <p class="sub">Import valid student IDs from a SUMS member export.</p>
    <div class="stat">Members in database: <b id="count">{count}</b></div>

    <div class="card">
        <h2>Admin Secret</h2>
        <input type="password" id="admin-secret" placeholder="Required for all actions"
               style="width:100%;padding:0.55rem 0.8rem;border-radius:6px;border:1px solid #2e3532;
                      background:#1a1f1d;color:#d4d8d5;font-size:0.9rem;outline:none;" />
    </div>

    <div class="card">
        <h2>Paste text</h2>
        <p style="font-size:0.82rem;color:#5a6b5e;margin-bottom:0.7rem">
            Any text containing 8-digit student IDs. All other content is ignored.
        </p>
        <textarea id="raw" rows="7" placeholder="Paste SUMS export here..."></textarea>
        <button class="btn btn-primary" onclick="importText()">Import</button>
        <div class="msg" id="paste-msg"></div>
    </div>

    <div class="card">
        <h2>Upload file</h2>
        <input type="file" id="file-input" accept=".txt,.csv,text/plain" /><br>
        <button class="btn btn-primary" onclick="importFile()">Import</button>
        <div class="msg" id="file-msg"></div>
    </div>

    <div class="card" style="border-color:#5a3a3a">
        <h2 style="color:#9e7474">Clear member list</h2>
        <p style="font-size:0.82rem;color:#5a6b5e;margin-bottom:0.8rem">
            Removes all members. Only use before an election starts.
        </p>
        <button class="btn btn-danger" onclick="clearMembers()">Clear All Members</button>
        <div class="msg" id="clear-msg"></div>
    </div>

<script>
async function importText() {{
    const raw = document.getElementById('raw').value;
    await doImport(raw, document.getElementById('paste-msg'));
}}
async function importFile() {{
    const f = document.getElementById('file-input').files[0];
    const msg = document.getElementById('file-msg');
    if (!f) {{ show(msg, 'No file selected.', false); return; }}
    await doImport(await f.text(), msg);
}}
async function doImport(text, msg) {{
    if (!text.trim()) {{ show(msg, 'Nothing to import.', false); return; }}
    const secret = document.getElementById('admin-secret').value;
    const resp = await fetch('import-members', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json', 'X-Admin-Secret': secret}},
        body: JSON.stringify({{ raw_text: text }})
    }});
    const d = await resp.json();
    if (resp.ok) {{
        show(msg, d.message, true);
        document.getElementById('count').textContent = d.total;
    }} else {{
        show(msg, d.detail || 'Error', false);
    }}
}}
async function clearMembers() {{
    if (!confirm('Clear all members? This cannot be undone.')) return;
    const secret = document.getElementById('admin-secret').value;
    const resp = await fetch('members', {{ method: 'DELETE', headers: {{'X-Admin-Secret': secret}} }});
    const d = await resp.json();
    const msg = document.getElementById('clear-msg');
    show(msg, resp.ok ? d.message : (d.detail || 'Error'), resp.ok);
    if (resp.ok) document.getElementById('count').textContent = '0';
}}
function show(el, text, ok) {{
    el.textContent = text;
    el.className = 'msg ' + (ok ? 'ok' : 'err');
}}
</script>
</body></html>"""
    return HTMLResponse(html)


class ImportRequest(BaseModel):
    raw_text: str


@app.post("/import-members")
async def import_members(req: ImportRequest, db: Session = Depends(get_db),
                         x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    ids = list(dict.fromkeys(STUDENT_ID_RE.findall(req.raw_text)))
    if not ids:
        raise HTTPException(422, "No 8-digit student IDs found.")
    added = 0
    for sid in ids:
        if not db.query(Member).filter_by(student_id=sid).first():
            db.add(Member(student_id=sid, created_at=datetime.now(timezone.utc)))
            added += 1
    db.commit()
    total = db.query(Member).count()
    return {"message": f"{added} new member(s) added ({len(ids) - added} already existed).",
            "added": added, "total": total}


@app.delete("/members")
async def clear_members(db: Session = Depends(get_db),
                        x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    count = db.query(Member).count()
    db.query(MemberVoted).delete()
    db.query(Member).delete()
    db.commit()
    return {"message": f"Deleted {count} member(s)."}


@app.get("/status")
async def status(db: Session = Depends(get_db)):
    return {
        "total_members":  db.query(Member).count(),
        "ballots_issued": db.query(MemberVoted).count(),
    }


def _locked(title: str, msg: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HackSoc Elections</title>
    <style>{STYLE}</style>
</head>
<body>
<div class="card locked">
    <h1>{title}</h1>
    <p>{msg}</p>
</div>
</body></html>"""