import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from typing import List, Optional

from irv import compute_all_results


def verify_vote_hmac(ballot) -> bool:
    """Verify the stored vote HMAC matches the ballot's votes."""
    if not ballot.vote_hmac or not ballot.votes:
        return False
    canonical = json.dumps(ballot.votes, sort_keys=True, separators=(',', ':'))
    expected  = hmac.new(TOKEN_SECRET, canonical.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, ballot.vote_hmac)


def verified_ballots(ballots) -> list:
    """Filter to only ballots with valid vote HMACs. Logs any rejected."""
    valid    = []
    rejected = 0
    for b in ballots:
        if verify_vote_hmac(b):
            valid.append(b)
        else:
            rejected += 1
    if rejected:
        print(f"[tally] WARNING: {rejected} ballot(s) failed HMAC verification and were excluded.")
    return valid

# Config
DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_SECRET = os.environ["ADMIN_SECRET"]
TOKEN_SECRET = os.environ["TOKEN_SECRET"].encode()

# Database
engine = create_engine(DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://"))
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Ballot(Base):
    __tablename__ = "ballots"
    id           = Column(Integer, primary_key=True)
    token        = Column(String)
    submitted    = Column(Boolean, default=False)
    votes        = Column(JSONB)
    vote_hmac    = Column(String)
    submitted_at = Column(DateTime(timezone=True))


class Candidate(Base):
    __tablename__ = "candidates"
    id         = Column(Integer, primary_key=True)
    role       = Column(String, unique=True)
    candidates = Column(JSONB)
    idx        = Column(Integer, default=0)


class Member(Base):
    __tablename__ = "members"
    id         = Column(Integer, primary_key=True)
    student_id = Column(String)


class MemberVoted(Base):
    __tablename__ = "members_voted"
    id         = Column(Integer, primary_key=True)
    student_id = Column(String)


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


def get_state(db: Session) -> ElectionState:
    return db.query(ElectionState).filter_by(id=1).first()


# Auth
def require_admin(x_admin_secret: Optional[str] = Header(default=None)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(401, "Unauthorised.")


# Shared styles
BASE_STYLE = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #1c1f1e; color: #d4d8d5;
           padding: 2rem 1rem; max-width: 960px; margin: 0 auto; }
    h1 { color: #a8c5a0; margin-bottom: 0.3rem; font-weight: 600; letter-spacing: -0.01em; }
    h2 { color: #8aab82; margin: 1.8rem 0 0.8rem; font-size: 1rem; text-transform: uppercase;
         letter-spacing: 0.06em; font-weight: 600; }
    .sub { color: #7a8c7e; font-size: 0.88rem; margin-bottom: 1.5rem; }
    a { color: #8aab82; }
    .nav { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 2rem;
           padding-bottom: 1.2rem; border-bottom: 1px solid #2c3330; }
    .nav a { padding: 0.4rem 0.9rem; background: #242827; border-radius: 6px;
             text-decoration: none; font-size: 0.83rem; color: #9aaa9e;
             border: 1px solid #2e3532; transition: all 0.15s; }
    .nav a:hover { border-color: #5a7a54; color: #a8c5a0; background: #2a302d; }
    .nav a.active { border-color: #6b9663; color: #a8c5a0; background: #2a302d; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer;
           font-size: 0.85rem; font-weight: 600; transition: opacity 0.15s; }
    .btn-primary { background: #5a7a54; color: #e8f0e5; }
    .btn-success { background: #4a7244; color: #e8f0e5; }
    .btn-danger  { background: #7a4444; color: #f0e5e5; }
    .btn-muted   { background: #2e3532; color: #9aaa9e; border: 1px solid #3a4540; }
    .btn:hover { opacity: 0.85; }
    .msg { padding: 0.65rem 1rem; border-radius: 6px; font-size: 0.85rem;
           margin-top: 0.8rem; display: none; }
    .msg.ok  { background: #2a3d28; color: #a8c5a0; border: 1px solid #3d5c3a; display: block; }
    .msg.err { background: #3d2828; color: #c5a0a0; border: 1px solid #5c3a3a; display: block; }
"""

NAV = """
<div class="nav">
    <a href=""{r}>Results</a>
    <a href="verbose"{v}>Detailed Results</a>
    <a href="setup"{s}>Election Setup</a>
    <a href="start"{st}>Start Election</a>
    <a href="results.json">Raw JSON</a>
</div>
"""


def nav(active=""):
    return NAV.format(
        r=' class="active"'  if active == "results"  else "",
        v=' class="active"'  if active == "verbose"  else "",
        s=' class="active"'  if active == "setup"    else "",
        st=' class="active"' if active == "start"    else "",
    )


def stats(db: Session) -> dict:
    return {
        "total_members":    db.query(Member).count(),
        "ballots_issued":   db.query(MemberVoted).count(),
        "ballots_submitted": db.query(Ballot).filter_by(submitted=True).count(),
    }


# App
app = FastAPI(title="HackSoc Election -- Tally Service")


# Results dashboard
@app.get("/", response_class=HTMLResponse)
async def dashboard(db: Session = Depends(get_db)):
    state = get_state(db)
    st    = stats(db)
    n     = nav("results")

    # Pending
    if not state or state.status == "pending":
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/admin/">
    <title>HackSoc Election</title>
    <style>{BASE_STYLE}</style>
</head>
<body>
    <h1>HackSoc Election Admin</h1>
    <p class="sub">Election has not started yet.</p>
    {n}
    <p style="color:#5a6b5e;font-style:italic">
        Configure roles in Election Setup, import members at the registration
        service, then start the election.
    </p>
</body></html>"""
        return HTMLResponse(html)

    # Open = show countdown
    if state.status == "open":
        results_at_iso = state.results_at.isoformat() if state.results_at else ""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/admin/">
    <title>HackSoc Election -- Live</title>
    <style>
        {BASE_STYLE}
        .stats {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
        .stat {{ background:#222725; border:1px solid #2e3532; border-radius:8px;
                 padding:0.9rem 1.3rem; min-width:140px; }}
        .stat-val {{ font-size:1.8rem; font-weight:700; color:#a8c5a0; }}
        .stat-lbl {{ font-size:0.78rem; color:#5a6b5e; margin-top:0.2rem;
                     text-transform:uppercase; letter-spacing:0.05em; }}
        .countdown-box {{ background:#222725; border:1px solid #2e3532; border-radius:10px;
                          padding:2rem; max-width:380px; text-align:center; margin-top:1rem; }}
        .countdown {{ font-size:3rem; font-weight:300; color:#a8c5a0; font-family:monospace;
                      letter-spacing:0.15em; margin:0.5rem 0; }}
        .countdown.expired {{ color:#6a9e62; }}
        .reveal-btn {{ margin-top:1.2rem; padding:0.75rem 2rem; border-radius:6px; border:none;
                       background:#4a7244; color:#e8f0e5; font-size:0.95rem; font-weight:600;
                       cursor:pointer; display:none; }}
        .reveal-btn:hover {{ opacity:0.85; }}
    </style>
</head>
<body>
    <h1>HackSoc Election Admin</h1>
    <p class="sub">Voting is open.</p>
    {n}
    <h2>Statistics</h2>
    <div class="stats" style="display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem;">
        <div class="stat">
            <div class="stat-val">{st['total_members']}</div>
            <div class="stat-lbl">Members</div>
        </div>
        <div class="stat">
            <div class="stat-val">{st['ballots_issued']}</div>
            <div class="stat-lbl">Ballots Issued</div>
        </div>
        <div class="stat">
            <div class="stat-val" id="submitted-count">{st['ballots_submitted']}</div>
            <div class="stat-lbl">Votes Cast</div>
        </div>
    </div>

    <h2>Time Remaining</h2>
    <div class="countdown-box">
        <div style="font-size:0.82rem;color:#5a6b5e;margin-bottom:0.5rem" id="cd-sub">
            Voting closes at {state.results_at.strftime('%H:%M') if state.results_at else ''}
        </div>
        <div class="countdown" id="countdown">--:--</div>
        <button class="reveal-btn" id="reveal-btn"
                onclick="location.href='results-reveal'">
            Close Voting and View Results
        </button>
    </div>

<script>
const resultsAt = new Date("{results_at_iso}");
const el  = document.getElementById('countdown');
const sub = document.getElementById('cd-sub');
const btn = document.getElementById('reveal-btn');

function tick() {{
    const diff = resultsAt - Date.now();
    if (diff <= 0) {{
        el.textContent = '00:00';
        el.classList.add('expired');
        sub.textContent = 'Voting period has ended.';
        btn.style.display = 'inline-block';
        return;
    }}
    const total = Math.floor(diff / 1000);
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    el.textContent = h > 0
        ? String(h).padStart(2,'0') + ':' + String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0')
        : String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
    setTimeout(tick, 1000);
}}
tick();

setInterval(async () => {{
    const r = await fetch('stats');
    if (r.ok) {{
        const d = await r.json();
        document.getElementById('submitted-count').textContent = d.ballots_submitted;
    }}
}}, 15000);
</script>
</body></html>"""
        return HTMLResponse(html)

    # Closed = click-to-reveal
    roles     = db.query(Candidate).order_by(Candidate.idx).all()
    submitted = verified_ballots(db.query(Ballot).filter_by(submitted=True).all())
    results   = compute_all_results(roles, submitted)
    rjson     = json.dumps(results, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/admin/">
    <title>HackSoc Election -- Results</title>
    <style>
        {BASE_STYLE}
        .stats {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
        .stat {{ background:#222725; border:1px solid #2e3532; border-radius:8px;
                 padding:0.9rem 1.3rem; min-width:140px; }}
        .stat-val {{ font-size:1.8rem; font-weight:700; color:#a8c5a0; }}
        .stat-lbl {{ font-size:0.78rem; color:#5a6b5e; margin-top:0.2rem;
                     text-transform:uppercase; letter-spacing:0.05em; }}
        .role-card {{ background:#222725; border:1px solid #2e3532; border-radius:8px;
                      padding:1.2rem 1.4rem; margin-bottom:1rem; cursor:pointer;
                      transition:border-color 0.2s; user-select:none; }}
        .role-card:hover {{ border-color:#5a7a54; }}
        .role-card.revealed {{ cursor:default; }}
        .role-header {{ display:flex; justify-content:space-between; align-items:center; }}
        .role-title {{ font-size:1rem; font-weight:600; color:#c8d8c4; }}
        .reveal-hint {{ font-size:0.78rem; color:#4a5a4e; }}
        .winner-reveal {{ margin-top:1rem; padding:1rem; background:#1e2a1e;
                          border:1px solid #3a5a34; border-radius:6px; text-align:center; }}
        .winner-name {{ font-size:1.4rem; font-weight:700; color:#a8c5a0; }}
        .winner-label {{ font-size:0.78rem; color:#5a7a54; text-transform:uppercase;
                         letter-spacing:0.08em; margin-bottom:0.4rem; }}
        .no-winner {{ color:#7a6a5a; font-style:italic; font-size:0.9rem; }}
        .no-ballots {{ color:#5a6b5e; font-style:italic; font-size:0.88rem; }}
        .detail-link {{ display:inline-block; margin-top:0.6rem; font-size:0.8rem;
                        color:#5a7a54; text-decoration:none; }}
        .detail-link:hover {{ color:#a8c5a0; }}
    </style>
</head>
<body>
    <h1>HackSoc Election Results</h1>
    <p class="sub">Click a role to reveal the winner.</p>
    {n}
    <h2>Statistics</h2>
    <div class="stats">
        <div class="stat">
            <div class="stat-val">{st['total_members']}</div>
            <div class="stat-lbl">Members</div>
        </div>
        <div class="stat">
            <div class="stat-val">{st['ballots_issued']}</div>
            <div class="stat-lbl">Ballots Issued</div>
        </div>
        <div class="stat">
            <div class="stat-val">{st['ballots_submitted']}</div>
            <div class="stat-lbl">Votes Cast</div>
        </div>
    </div>
    <h2>Results</h2>
    <div id="results"></div>

<script>
const DATA = {rjson};
const container = document.getElementById('results');
DATA.forEach(role => {{
    const card = document.createElement('div');
    card.className = 'role-card';
    card.innerHTML = `
        <div class="role-header">
            <div class="role-title">${{role.role}}</div>
            <div class="reveal-hint" id="hint-${{role.role}}">Click to reveal</div>
        </div>
        <div id="reveal-${{role.role}}" style="display:none"></div>`;
    card.addEventListener('click', () => {{
        if (card.classList.contains('revealed')) return;
        card.classList.add('revealed');
        document.getElementById('hint-' + role.role).style.display = 'none';
        const reveal = document.getElementById('reveal-' + role.role);
        reveal.style.display = 'block';
        if (role.total_ballots === 0) {{
            reveal.innerHTML = '<div class="no-ballots">No votes cast.</div>';
        }} else if (role.winner) {{
            reveal.innerHTML = `<div class="winner-reveal">
                <div class="winner-label">Winner</div>
                <div class="winner-name">${{role.winner}}</div>
                <a class="detail-link" href="verbose">View detailed breakdown</a>
            </div>`;
        }} else {{
            reveal.innerHTML = '<div class="winner-reveal"><div class="no-winner">No majority reached.</div></div>';
        }}
    }});
    container.appendChild(card);
}});
</script>
</body></html>"""
    return HTMLResponse(html)


# Verbose results

@app.get("/verbose", response_class=HTMLResponse)
async def verbose(db: Session = Depends(get_db)):
    state = get_state(db)
    n     = nav("verbose")

    if not state or state.status != "closed":
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/admin/">
    <title>HackSoc Election -- Detailed Results</title>
    <style>{BASE_STYLE}</style>
</head>
<body>
    <h1>HackSoc Election</h1>
    <p class="sub">Results are not available yet.</p>
    {n}
    <p style="color:#5a6b5e;font-style:italic">Check back once voting has closed.</p>
</body></html>"""
        return HTMLResponse(html)

    roles     = db.query(Candidate).order_by(Candidate.idx).all()
    submitted = verified_ballots(db.query(Ballot).filter_by(submitted=True).all())
    results   = compute_all_results(roles, submitted)
    rjson     = json.dumps(results, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/admin/">
    <title>HackSoc Election -- Detailed Results</title>
    <style>
        {BASE_STYLE}
        .role-card {{ background:#222725; border:1px solid #2e3532; border-radius:8px;
                      padding:1.4rem; margin-bottom:1.4rem; }}
        .role-title {{ font-size:1rem; font-weight:600; color:#c8d8c4; margin-bottom:0.3rem; }}
        .winner-line {{ font-size:0.88rem; color:#a8c5a0; margin-bottom:1rem;
                        padding:0.5rem 0.8rem; background:#1e2a1e; border-radius:5px;
                        border-left:3px solid #4a7244; }}
        .no-winner-line {{ font-size:0.88rem; color:#7a6a5a; margin-bottom:1rem;
                           padding:0.5rem 0.8rem; background:#2a2218; border-radius:5px;
                           border-left:3px solid #7a6a3a; }}
        .round {{ margin-bottom:0.8rem; }}
        .round-label {{ font-size:0.73rem; color:#4a5a4e; text-transform:uppercase;
                        letter-spacing:0.07em; margin-bottom:0.5rem; font-weight:600; }}
        .bar-row {{ display:flex; align-items:center; gap:0.7rem; margin-bottom:0.35rem; }}
        .bar-name {{ width:160px; font-size:0.82rem; color:#c8d8c4; overflow:hidden;
                     text-overflow:ellipsis; white-space:nowrap; flex-shrink:0; }}
        .bar-track {{ flex:1; background:#1a1f1d; border-radius:3px; height:12px; }}
        .bar-fill {{ height:12px; background:#4a7244; border-radius:3px; min-width:2px; }}
        .bar-fill.winner {{ background:#6a9e62; }}
        .bar-label {{ font-size:0.78rem; color:#5a6b5e; min-width:90px; }}
        .elim-note {{ font-size:0.78rem; color:#7a5a4a; margin-top:0.3rem;
                      padding-left:0.3rem; border-left:2px solid #5a3a2a; }}
        .note {{ font-size:0.8rem; color:#4a5a4e; margin-top:0.5rem; font-style:italic; }}
        .no-ballots {{ color:#5a6b5e; font-style:italic; font-size:0.88rem; }}
    </style>
</head>
<body>
    <h1>HackSoc Election -- Detailed Results</h1>
    <p class="sub">Round-by-round IRV breakdown. Bars show share of active votes each round.</p>
    {n}
    <div id="results"></div>

<script>
const DATA = {rjson};
const container = document.getElementById('results');

DATA.forEach(role => {{
    const card = document.createElement('div');
    card.className = 'role-card';
    let html = `<div class="role-title">${{role.role}}</div>`;

    if (role.total_ballots === 0) {{
        html += '<div class="no-ballots">No votes cast.</div>';
        card.innerHTML = html; container.appendChild(card); return;
    }}

    html += role.winner
        ? `<div class="winner-line">Winner: <strong>${{role.winner}}</strong></div>`
        : `<div class="no-winner-line">No majority reached.</div>`;

    role.rounds.forEach((round, idx) => {{
        const total  = Object.values(round.counts).reduce((a,b)=>a+b, 0);
        const sorted = Object.entries(round.counts).sort((a,b)=>b[1]-a[1]);
        const isLast = idx === role.rounds.length - 1;
        html += `<div class="round"><div class="round-label">Round ${{idx+1}}${{isLast?' (final)':''}}</div>`;
        sorted.forEach(([name, count]) => {{
            const pct     = total > 0 ? (count / total * 100) : 0;
            const isWin   = name === role.winner && isLast;
            html += `<div class="bar-row">
                <div class="bar-name" title="${{name}}">${{name}}</div>
                <div class="bar-track">
                    <div class="bar-fill${{isWin?' winner':''}}" style="width:${{pct.toFixed(1)}}%"></div>
                </div>
                <div class="bar-label">${{count}} (${{pct.toFixed(1)}}%)</div>
            </div>`;
        }});
        if (round.eliminated)
            html += `<div class="elim-note">Eliminated: ${{round.eliminated}}</div>`;
        html += '</div>';
    }});

    if (role.rounds.length > 1)
        html += `<div class="note">Vote counts increase in later rounds as eliminated
                 candidates' ballots transfer to the next valid preference.</div>`;

    card.innerHTML = html;
    container.appendChild(card);
}});
</script>
</body></html>"""
    return HTMLResponse(html)


# Election setup
@app.get("/setup", response_class=HTMLResponse)
async def setup_page(db: Session = Depends(get_db)):
    roles = db.query(Candidate).order_by(Candidate.idx).all()
    roles_json = json.dumps([
        {"id": r.id, "role": r.role, "candidates": r.candidates, "idx": r.idx}
        for r in roles
    ])
    n = nav("setup")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/admin/">
    <title>HackSoc Election -- Setup</title>
    <style>
        {BASE_STYLE}
        .card {{ background:#222725; border:1px solid #2e3532; border-radius:8px;
                 padding:1.4rem; margin-bottom:1rem; }}
        .field {{ margin-bottom:0.9rem; }}
        .field label {{ display:block; font-size:0.78rem; color:#7a8c7e; margin-bottom:0.3rem;
                        text-transform:uppercase; letter-spacing:0.05em; }}
        .field input, .field textarea {{
            width:100%; padding:0.55rem 0.8rem; border-radius:6px;
            border:1px solid #2e3532; background:#1a1f1d; color:#d4d8d5;
            font-size:0.9rem; outline:none; }}
        .field input:focus, .field textarea:focus {{ border-color:#5a7a54; }}
        .role-row {{ display:flex; justify-content:space-between; align-items:center;
                     padding:0.6rem 0.9rem; background:#1a1f1d; border-radius:6px;
                     margin-bottom:0.5rem; border:1px solid #2e3532; }}
        .role-name {{ font-weight:600; color:#c8d8c4; font-size:0.9rem; }}
        .role-cands {{ font-size:0.78rem; color:#5a6b5e; }}
        .row-btns {{ display:flex; gap:0.4rem; }}
    </style>
</head>
<body>
    <h1>HackSoc Election Admin</h1>
    <p class="sub">Election Setup</p>
    {n}

    <h2>Add Role</h2>
    <div class="card">
        <div class="field">
            <label>Role name</label>
            <input type="text" id="role-name" placeholder="e.g. President" />
        </div>
        <div class="field">
            <label>Candidates (one per line, RON added automatically)</label>
            <textarea id="role-cands" rows="4" placeholder="Alice Smith&#10;Bob Jones"></textarea>
        </div>
        <div class="field">
            <label>Display order (lower = first)</label>
            <input type="number" id="role-idx" value="0" min="0" />
        </div>
        <button class="btn btn-primary" onclick="addRole()">Add Role</button>
        <div class="msg" id="add-msg"></div>
    </div>

    <h2>Configured Roles</h2>
    <div id="roles-list"></div>

<script>
let ROLES = {roles_json};

function render() {{
    const el = document.getElementById('roles-list');
    if (!ROLES.length) {{
        el.innerHTML = '<p style="color:#5a6b5e;font-style:italic;font-size:0.88rem">No roles configured yet.</p>';
        return;
    }}
    el.innerHTML = ROLES.map(r => `
        <div class="role-row">
            <div>
                <div class="role-name">${{r.role}}</div>
                <div class="role-cands">${{r.candidates.join(', ')}}</div>
            </div>
            <div class="row-btns">
                <button class="btn btn-muted" onclick="deleteRole(${{r.id}})">Remove</button>
            </div>
        </div>`).join('');
}}
render();

async function addRole() {{
    const role = document.getElementById('role-name').value.trim();
    const raw  = document.getElementById('role-cands').value;
    const idx  = parseInt(document.getElementById('role-idx').value) || 0;
    const cands = raw.split('\\n').map(s=>s.trim()).filter(Boolean);
    if (!role || !cands.length) {{
        show('add-msg', 'Role name and at least one candidate required.', false); return;
    }}
    if (!cands.includes('Re-open Nominations')) cands.push('Re-open Nominations');
    const resp = await fetch('setup', {{
        method: 'POST',
        headers: {{'Content-Type':'application/json', 'X-Admin-Secret': prompt('Admin secret')}},
        body: JSON.stringify({{ role, candidates: cands, idx }})
    }});
    const d = await resp.json();
    if (resp.ok) {{
        ROLES = d.roles;
        render();
        show('add-msg', 'Role added.', true);
        document.getElementById('role-name').value = '';
        document.getElementById('role-cands').value = '';
    }} else show('add-msg', d.detail || 'Error', false);
}}

async function deleteRole(id) {{
    if (!confirm('Delete this role?')) return;
    const secret = prompt('Admin secret');
    const resp = await fetch('setup/' + id, {{
        method: 'DELETE',
        headers: {{'X-Admin-Secret': secret}}
    }});
    const d = await resp.json();
    if (resp.ok) {{ ROLES = d.roles; render(); }}
    else alert(d.detail || 'Error');
}}

function show(id, text, ok) {{
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = 'msg ' + (ok ? 'ok' : 'err');
}}
</script>
</body></html>"""
    return HTMLResponse(html)


class RoleIn(BaseModel):
    role:       str
    candidates: List[str]
    idx:        int = 0


@app.post("/setup")
async def add_role(r: RoleIn, db: Session = Depends(get_db),
                   x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    if db.query(Candidate).filter_by(role=r.role).first():
        raise HTTPException(409, f"Role '{r.role}' already exists.")
    db.add(Candidate(role=r.role, candidates=r.candidates, idx=r.idx))
    db.commit()
    roles = db.query(Candidate).order_by(Candidate.idx).all()
    return {"roles": [{"id": x.id, "role": x.role, "candidates": x.candidates, "idx": x.idx}
                      for x in roles]}


@app.delete("/setup/{role_id}")
async def delete_role(role_id: int, db: Session = Depends(get_db),
                      x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    r = db.query(Candidate).filter_by(id=role_id).first()
    if not r:
        raise HTTPException(404, "Role not found.")
    db.delete(r)
    db.commit()
    roles = db.query(Candidate).order_by(Candidate.idx).all()
    return {"roles": [{"id": x.id, "role": x.role, "candidates": x.candidates, "idx": x.idx}
                      for x in roles]}


# Start election
@app.get("/start", response_class=HTMLResponse)
async def start_page(db: Session = Depends(get_db)):
    state  = get_state(db)
    status = state.status if state else "pending"
    n      = nav("start")
    roles_count = db.query(Candidate).count()

    if status == "pending":
        body = f"""
        <div style="background:#2a2218;border-left:3px solid #7a6a3a;padding:0.8rem 1rem;
                    border-radius:4px;font-size:0.83rem;color:#9a8a6a;margin-bottom:1.2rem">
            Starting will wipe all existing ballots and issued-ballot records.
        </div>
        <ul style="list-style:none;font-family:monospace;margin-bottom:1.4rem">
            <li style="color:{'#7a9e74' if roles_count > 0 else '#9e7474'};padding:0.3rem 0">
                [{'v' if roles_count > 0 else 'x'}] {roles_count} role(s) configured
            </li>
        </ul>
        <div style="margin-bottom:1rem">
            <label style="display:block;font-size:0.78rem;color:#7a8c7e;margin-bottom:0.35rem;
                          text-transform:uppercase;letter-spacing:0.05em">Admin secret</label>
            <input type="password" id="secret" style="padding:0.55rem 0.8rem;border-radius:6px;
                   border:1px solid #2e3532;background:#1a1f1d;color:#d4d8d5;font-size:0.9rem;
                   outline:none;width:100%;max-width:280px" />
        </div>
        <div style="margin-bottom:1.2rem">
            <label style="display:block;font-size:0.78rem;color:#7a8c7e;margin-bottom:0.35rem;
                          text-transform:uppercase;letter-spacing:0.05em">Duration (minutes)</label>
            <input type="number" id="duration" value="30" min="1" max="1440"
                   style="padding:0.55rem 0.8rem;border-radius:6px;border:1px solid #2e3532;
                          background:#1a1f1d;color:#d4d8d5;font-size:0.9rem;outline:none;
                          max-width:120px" />
        </div>
        <button class="btn btn-success" onclick="startElection()"
                {'disabled' if roles_count == 0 else ''}>Start Election</button>
        <div class="msg" id="start-msg"></div>"""
    elif status == "open":
        body = """<div style="background:#1e2a1e;border:1px solid #3a5a34;border-radius:6px;
                              padding:0.8rem 1rem;color:#8aab82;font-size:0.9rem">
                    Voting is currently open.</div>"""
    else:
        body = """
        <div style="background:#222725;border:1px solid #3a4a3a;border-radius:6px;
                    padding:0.8rem 1rem;color:#7a8c7e;font-size:0.9rem;margin-bottom:1rem">
            The election has finished.
        </div>
        <p style="font-size:0.85rem;color:#5a6b5e;margin-bottom:1rem">
            Reset ballot data and return to pre-election state.
            Member lists and role configuration are preserved.
        </p>
        <div style="margin-bottom:1.1rem">
            <label style="display:block;font-size:0.78rem;color:#7a8c7e;margin-bottom:0.35rem;
                          text-transform:uppercase;letter-spacing:0.05em">Admin secret</label>
            <input type="password" id="reset-secret"
                   style="padding:0.55rem 0.8rem;border-radius:6px;border:1px solid #2e3532;
                          background:#1a1f1d;color:#d4d8d5;font-size:0.9rem;outline:none;
                          width:100%;max-width:280px" />
        </div>
        <button class="btn btn-danger" onclick="resetElection()">Reset for New Election</button>
        <div class="msg" id="reset-msg"></div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/admin/">
    <title>HackSoc Election -- Start</title>
    <style>{BASE_STYLE}</style>
</head>
<body>
    <h1>HackSoc Election Admin</h1>
    <p class="sub">Election control</p>
    {n}
    <div style="background:#222725;border:1px solid #2e3532;border-radius:10px;
                padding:2rem;max-width:480px">
        {body}
    </div>

<script>
async function startElection() {{
    const mins = parseInt(document.getElementById('duration').value);
    const secret = document.getElementById('secret').value;
    if (!mins || mins < 1) {{ show('start-msg','Enter a valid duration.', false); return; }}
    if (!confirm('Start the election for ' + mins + ' minute(s)? All ballots will be wiped.')) return;
    const btn = document.querySelector('.btn-success');
    btn.disabled = true; btn.textContent = 'Starting...';
    const resp = await fetch('start', {{
        method: 'POST',
        headers: {{'Content-Type':'application/json','X-Admin-Secret':secret}},
        body: JSON.stringify({{ duration_minutes: mins }})
    }});
    const d = await resp.json();
    if (resp.ok) {{
        show('start-msg','Election started. Redirecting...', true);
        setTimeout(() => location.href = './', 1500);
    }} else {{
        show('start-msg', d.detail || 'Error', false);
        btn.disabled = false; btn.textContent = 'Start Election';
    }}
}}

async function resetElection() {{
    const secret = document.getElementById('reset-secret').value;
    if (!confirm('Reset all ballot data?')) return;
    const btn = document.querySelector('.btn-danger');
    btn.disabled = true; btn.textContent = 'Resetting...';
    const resp = await fetch('reset', {{
        method: 'POST',
        headers: {{'X-Admin-Secret': secret}}
    }});
    const d = await resp.json();
    if (resp.ok) {{
        show('reset-msg','Reset complete. Redirecting...', true);
        setTimeout(() => location.href = './', 1500);
    }} else {{
        show('reset-msg', d.detail || 'Error', false);
        btn.disabled = false; btn.textContent = 'Reset for New Election';
    }}
}}

function show(id, text, ok) {{
    const el = document.getElementById(id);
    el.textContent = text; el.className = 'msg ' + (ok ? 'ok' : 'err');
}}
</script>
</body></html>"""
    return HTMLResponse(html)


class StartRequest(BaseModel):
    duration_minutes: int


@app.post("/start")
async def start_election(req: StartRequest, db: Session = Depends(get_db),
                         x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    state = get_state(db)
    if state and state.status == "open":
        raise HTTPException(409, "Election is already running.")

    from datetime import timedelta
    # Wipe all ballot data
    db.query(Ballot).delete()
    db.execute(text("DELETE FROM members_voted"))

    now        = datetime.now(timezone.utc)
    results_at = now + timedelta(minutes=req.duration_minutes)

    if state:
        state.status     = "open"
        state.started_at = now
        state.results_at = results_at
    else:
        db.add(ElectionState(id=1, status="open", started_at=now, results_at=results_at))

    db.commit()
    return {"message": "Election started.", "results_at": results_at.isoformat()}


@app.post("/reset")
async def reset_election(db: Session = Depends(get_db),
                         x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    state = get_state(db)
    if not state or state.status != "closed":
        raise HTTPException(409, "Can only reset a closed election.")

    db.query(Ballot).delete()
    db.execute(text("DELETE FROM members_voted"))

    state.status     = "pending"
    state.started_at = None
    state.results_at = None
    db.commit()
    return {"message": "Election reset. Ready for a new election."}


@app.get("/results-reveal", response_class=HTMLResponse)
async def results_reveal(db: Session = Depends(get_db)):
    state = get_state(db)
    if state and state.status == "open":
        now = datetime.now(timezone.utc)
        if state.results_at and now >= state.results_at.replace(tzinfo=timezone.utc):
            state.status = "closed"
            db.commit()
    return RedirectResponse("/admin/")


# JSON endpoints
@app.get("/results.json")
async def results_json(db: Session = Depends(get_db)):
    roles     = db.query(Candidate).order_by(Candidate.idx).all()
    submitted = verified_ballots(db.query(Ballot).filter_by(submitted=True).all())
    return compute_all_results(roles, submitted)


@app.get("/stats")
async def stats_endpoint(db: Session = Depends(get_db)):
    return stats(db)


@app.get("/setup.json")
async def setup_json(db: Session = Depends(get_db)):
    roles = db.query(Candidate).order_by(Candidate.idx).all()
    return [{"id": r.id, "role": r.role, "candidates": r.candidates, "idx": r.idx}
            for r in roles]
