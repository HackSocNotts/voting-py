import os
import hmac
import hashlib
import json
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from typing import Dict, List, Optional

# Config
DATABASE_URL = os.environ["DATABASE_URL"]
TOKEN_SECRET = os.environ["TOKEN_SECRET"].encode()

# Database
engine = create_engine(DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://"))
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Ballot(Base):
    __tablename__ = "ballots"
    id           = Column(Integer, primary_key=True)
    token        = Column(String, unique=True, nullable=False)
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


# Token verification
def verify_token(token: str) -> bool:
    """
    Verify an HMAC-signed token.
    Format: <random_hex>.<hmac_hex>
    """
    try:
        random_part, received_mac = token.rsplit(".", 1)
        expected_mac = hmac.new(TOKEN_SECRET, random_part.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_mac, received_mac)
    except Exception:
        return False


def sign_votes(votes: dict) -> str:
    """
    Compute HMAC-SHA256 over a canonical JSON representation of the votes.
    """
    canonical = json.dumps(votes, sort_keys=True, separators=(',', ':'))
    return hmac.new(TOKEN_SECRET, canonical.encode(), hashlib.sha256).hexdigest()


# Styles
STYLE = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #1c1f1e; color: #d4d8d5;
           padding: 2rem 1rem; max-width: 680px; margin: 0 auto; }
    h1 { color: #a8c5a0; margin-bottom: 0.3rem; font-weight: 600; font-size: 1.4rem; }
    .sub { color: #7a8c7e; font-size: 0.88rem; margin-bottom: 2rem; }
    .role-card { background: #222725; border: 1px solid #2e3532; border-radius: 8px;
                 padding: 1.4rem; margin-bottom: 1.2rem; }
    .role-title { font-size: 1rem; font-weight: 600; color: #c8d8c4; margin-bottom: 0.3rem; }
    .instruction { font-size: 0.78rem; color: #5a6b5e; margin-bottom: 0.9rem; }
    .candidate-list { list-style: none; }
    .candidate-list li { display: flex; align-items: center; gap: 0.75rem;
                         padding: 0.55rem 0.8rem; margin-bottom: 0.35rem;
                         background: #1a1f1d; border-radius: 6px; cursor: grab;
                         border: 1px solid #2e3532; transition: border-color 0.15s;
                         user-select: none; }
    .candidate-list li:hover { border-color: #4a6a44; }
    .candidate-list li.dragging { opacity: 0.35; }
    .candidate-list li.over { border-color: #6a9e62; background: #1e2a1e; }
    .rank-badge { background: #2e3532; color: #8aab82; border-radius: 4px; min-width: 26px;
                  text-align: center; padding: 2px 5px; font-size: 0.78rem; font-weight: 700;
                  font-family: monospace; }
    .drag-handle { color: #3a4a3e; font-size: 1.1rem; }
    .btn { display: block; width: 100%; margin-top: 1.2rem; padding: 0.85rem;
           border-radius: 6px; border: none; background: #4a7244; color: #e8f0e5;
           font-size: 0.95rem; font-weight: 600; cursor: pointer; }
    .btn:hover { opacity: 0.85; }
    .error-banner { background: #3d2828; color: #c5a0a0; padding: 0.9rem 1.1rem;
                    border-radius: 6px; border: 1px solid #5c3a3a; margin-bottom: 1.5rem; }
    .success-banner { background: #2a3d28; color: #a8c5a0; padding: 1.1rem 1.3rem;
                      border-radius: 6px; border: 1px solid #3d5c3a; margin-bottom: 1.5rem; }
    .msg { margin-top: 1rem; padding: 0.75rem; border-radius: 6px; display: none; }
    .msg.error { background: #3d2828; color: #c5a0a0; border: 1px solid #5c3a3a; }
    .msg.ok    { background: #2a3d28; color: #a8c5a0; border: 1px solid #3d5c3a; }
    .locked { min-height: 100vh; display: flex; align-items: center; justify-content: center;
              padding: 0; max-width: none; }
    .locked-card { background: #222725; border: 1px solid #2e3532; border-radius: 10px;
                   padding: 2.5rem; max-width: 420px; width: 100%; text-align: center; }
    .locked-card h1 { font-size: 1.3rem; margin-bottom: 1rem; font-weight: 500; }
    .locked-card p { color: #7a8c7e; font-size: 0.92rem; line-height: 1.6; }
"""


def locked_page(title: str, msg: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/ballot/">
    <title>HackSoc Elections</title>
    <style>{STYLE}</style>
</head>
<body class="locked">
<div class="locked-card">
    <h1>{title}</h1>
    <p>{msg}</p>
</div>
</body></html>"""


# App
app = FastAPI(title="HackSoc Election -- Ballot Service")


@app.get("/", response_class=HTMLResponse)
async def ballot_page(token: Optional[str] = None, db: Session = Depends(get_db)):
    state = db.query(ElectionState).filter_by(id=1).first()
    if not state or state.status == "pending":
        return HTMLResponse(locked_page("Voting Not Open",
            "The election has not started yet. Please wait for an administrator to open voting."))

    if state.status == "closed":
        return HTMLResponse(locked_page("Voting Closed",
            "The voting period has ended. Thank you for participating."))

    token_error = None
    already_submitted = False

    if not token:
        token_error = "No ballot token provided. Please register first."
    elif not verify_token(token):
        token_error = "Invalid or tampered ballot token."
    else:
        ballot = db.query(Ballot).filter_by(token=token).first()
        if not ballot:
            token_error = "Ballot token not recognised. Please register again."
        elif ballot.submitted:
            already_submitted = True

    roles = db.query(Candidate).order_by(Candidate.idx).all()
    roles_json = json.dumps([
        {"id": str(r.id), "role": r.role, "candidates": r.candidates}
        for r in roles
    ])

    if already_submitted:
        return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/ballot/">
    <title>HackSoc Elections -- Already Voted</title>
    <style>{STYLE}</style>
</head>
<body>
    <h1>HackSoc Committee Elections</h1>
    <div class="success-banner">Your ballot has already been submitted. Thank you for voting.</div>
</body></html>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/ballot/">
    <title>HackSoc Elections -- Cast Your Vote</title>
    <style>{STYLE}</style>
</head>
<body>
    <h1>HackSoc Committee Elections</h1>
    <p class="sub">Drag candidates to rank your preferences. 1 = most preferred.</p>

    {"<div class='error-banner'>" + token_error + "</div>" if token_error else ""}
    <div id="ballot-form"></div>
    {"<button class='btn' onclick='submitBallot()'>Submit My Ballot</button>" if not token_error else ""}
    <div class="msg" id="result-msg"></div>

<script>
const ROLES  = {roles_json};
const TOKEN  = {json.dumps(token or '')};

// Build drag-and-drop ballot
ROLES.forEach(role => {{
    const card = document.createElement('div');
    card.className = 'role-card';
    card.innerHTML = `
        <div class="role-title">${{role.role}}</div>
        <div class="instruction">Drag to reorder. Top = most preferred.</div>
        <ul class="candidate-list" id="list-${{role.id}}"></ul>`;
    document.getElementById('ballot-form').appendChild(card);

    const ul = document.getElementById('list-' + role.id);
    role.candidates.forEach((name, idx) => {{
        const li = document.createElement('li');
        li.dataset.name = name;
        li.innerHTML = `<span class="rank-badge">${{idx + 1}}</span>
                        <span class="drag-handle">&#8597;</span>
                        <span>${{name}}</span>`;
        ul.appendChild(li);
        makeDraggable(li, ul);
    }});
}});

function makeDraggable(li, ul) {{
    li.draggable = true;
    li.addEventListener('dragstart', () => {{ li.classList.add('dragging'); }});
    li.addEventListener('dragend',   () => {{
        li.classList.remove('dragging');
        updateRanks(ul);
    }});
    ul.addEventListener('dragover', e => {{
        e.preventDefault();
        const dragging = ul.querySelector('.dragging');
        const siblings = [...ul.querySelectorAll('li:not(.dragging)')];
        const after = siblings.find(s => {{
            const rect = s.getBoundingClientRect();
            return e.clientY < rect.top + rect.height / 2;
        }});
        ul.insertBefore(dragging, after || null);
        siblings.forEach(s => s.classList.remove('over'));
        if (after) after.classList.add('over');
    }});
}}

function updateRanks(ul) {{
    [...ul.querySelectorAll('li')].forEach((li, i) => {{
        li.querySelector('.rank-badge').textContent = i + 1;
        li.querySelector('li')?.classList.remove('over');
    }});
}}

async function submitBallot() {{
    const votes = {{}};
    ROLES.forEach(role => {{
        const ul = document.getElementById('list-' + role.id);
        votes[role.id] = [...ul.querySelectorAll('li')].map(li => li.dataset.name);
    }});

    const btn = document.querySelector('.btn');
    btn.disabled = true; btn.textContent = 'Submitting...';

    const resp = await fetch('submit', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ token: TOKEN, votes }})
    }});
    const data = await resp.json();
    const msg  = document.getElementById('result-msg');
    if (resp.ok) {{
        msg.textContent = 'Your ballot has been submitted. Thank you for voting.';
        msg.className   = 'msg ok';
        msg.style.display = 'block';
        btn.style.display = 'none';
    }} else {{
        msg.textContent = data.detail || 'Submission failed.';
        msg.className   = 'msg error';
        msg.style.display = 'block';
        btn.disabled = false; btn.textContent = 'Submit My Ballot';
    }}
}}
</script>
</body></html>"""
    return HTMLResponse(html)


class SubmitRequest(BaseModel):
    token: str
    votes: Dict[str, List[str]]


@app.post("/submit")
async def submit_ballot(req: SubmitRequest, db: Session = Depends(get_db)):
    state = db.query(ElectionState).filter_by(id=1).first()
    if not state or state.status != "open":
        raise HTTPException(403, "Voting is not currently open.")

    if not verify_token(req.token):
        raise HTTPException(401, "Invalid ballot token.")

    ballot = db.query(Ballot).filter_by(token=req.token).first()
    if not ballot:
        raise HTTPException(404, "Ballot token not recognised.")
    if ballot.submitted:
        raise HTTPException(409, "This ballot has already been submitted.")

    ballot.votes        = req.votes
    ballot.vote_hmac    = sign_votes(req.votes)
    ballot.submitted    = True
    ballot.submitted_at = datetime.now(timezone.utc)
    db.commit()
    return {"message": "Ballot submitted successfully."}
