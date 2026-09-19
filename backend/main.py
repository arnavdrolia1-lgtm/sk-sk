import os, re, json, sqlite3, time, uuid
from pathlib import Path
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")
KEY = os.getenv("GROQ_API_KEY", "")
FAST = os.getenv("FAST_MODEL", "llama-3.1-8b-instant")      # classification + honeypot voice
SMART = os.getenv("SMART_MODEL", "llama-3.3-70b-versatile")  # report writing
DB = os.getenv("DB_PATH", str(HERE / "scam.db"))
app = FastAPI(title="Scammer Ko Scam Kar")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])  # lets the frontend be hosted separately


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


with db() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, started REAL, score REAL DEFAULT 0, label TEXT DEFAULT 'Unknown', honeypot INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT, role TEXT, text TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS entities(sid TEXT, kind TEXT, value TEXT, ts REAL, UNIQUE(sid, kind, value));
    """)

# ---- 1. Instant rule-based detector (English + Hinglish). Works with no API key. ----
RULES = {
    "Fake authority": (.45, r"police|cbi|\bed\b|enforcement directorate|customs|narcotics|cyber ?cell|\btrai\b|inspector|officer|supreme court|badge"),
    "Identity threat": (.30, r"aadhaar|aadhar|pan card|passport|sim card|money laundering"),
    "Parcel / contraband": (.30, r"parcel|courier|fedex|dhl|package|mdma|drugs|contraband|seized"),
    "Arrest threat": (.45, r"warrant|arrest|giraftar|\bfir\b|jail|case (has been )?registered|legal action|digital arrest"),
    "Isolation": (.50, r"do not disconnect|don'?t disconnect|keep (the |your )?(video|camera) on|stay on (the )?(call|line)|do not tell|don'?t tell|tell no ?one|confidential|koi ko mat"),
    "Urgency": (.30, r"immediately|right now|within \d+|last warning|abhi|jaldi|urgent|final notice"),
    "Payment demand": (.50, r"transfer|safe account|\bupi\b|verification amount|deposit|payment|refund|rbi account|gift card|bitcoin"),
    "OTP / remote access": (.50, r"\botp\b|anydesk|teamviewer|quicksupport|screen share|share (the )?code|\bcvv\b"),
}

# ---- 2. Deterministic entity extraction (never trust an LLM with account numbers) ----
PAT = {
    "UPI ID": r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b(?!\.)",
    "Phone": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
    "Link": r"(?:https?://|www\.)[^\s,]+",
    "IFSC": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "Account no.": r"(?<!\d)\d{9,18}(?!\d)",
}


def extract(text):
    text = re.sub(r"\s*at the rate( of)?\s*", "@", text, flags=re.I)  # speech-to-text quirk
    out = []
    for kind, p in PAT.items():
        for m in re.findall(p, text):
            m = m.strip(".,")
            if kind == "Account no." and len(m) == 10 and m[0] in "6789":
                continue  # that's a phone number
            out.append((kind, m))
    return out


async def llm(model, messages, json_mode=False, max_tokens=120):
    if not KEY:
        return None
    body = {"model": model, "messages": messages, "max_tokens": max_tokens,
            "temperature": 0 if json_mode else 0.7}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    try:
        async with httpx.AsyncClient(timeout=12) as h:
            r = await h.post("https://api.groq.com/openai/v1/chat/completions",
                             headers={"Authorization": f"Bearer {KEY}"}, json=body)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print("LLM error (falling back to rules):", e)
        return None


class Turn(BaseModel):
    sid: str
    text: str


@app.post("/api/session")
def new_session():
    sid = uuid.uuid4().hex[:10]
    with db() as c:
        c.execute("INSERT INTO sessions(id, started) VALUES(?,?)", (sid, time.time()))
    return {"sid": sid}


@app.post("/api/analyze")
async def analyze(t: Turn):
    now = time.time()
    with db() as c:
        c.execute("INSERT INTO messages(sid, role, text, ts) VALUES(?,?,?,?)", (t.sid, "scammer", t.text, now))
        full = " ".join(r["text"] for r in c.execute(
            "SELECT text FROM messages WHERE sid=? AND role='scammer' ORDER BY id", (t.sid,)))
        for kind, val in extract(t.text):
            c.execute("INSERT OR IGNORE INTO entities VALUES(?,?,?,?)", (t.sid, kind, val, now))
        ents = [dict(r) for r in c.execute("SELECT kind, value FROM entities WHERE sid=?", (t.sid,))]

    hits = {k: w for k, (w, p) in RULES.items() if re.search(p, full, re.I)}
    miss = 1.0
    for w in hits.values():
        miss *= 1 - w
    score = min(.99, 1 - miss)
    label = ("Impersonation Scam" if "Fake authority" in hits else
             "OTP / Remote-Access Fraud" if "OTP / remote access" in hits else
             "Payment Fraud" if "Payment demand" in hits else "Unknown")

    if score < .9:  # once confirmed, skip the LLM: faster and saves free-tier quota
        raw = await llm(FAST, [
            {"role": "system", "content": 'You analyse phone-call transcripts for Indian scams (digital arrest, fake CBI/police, courier, OTP, KYC). Reply JSON only: {"scam_probability":0..1,"scam_type":"short label","tactics":["short phrases"]}'},
            {"role": "user", "content": full[-1500:]}], json_mode=True)
        try:
            j = json.loads(raw)
            score = max(score, min(.99, float(j["scam_probability"])))
            label = j.get("scam_type") or label
            for tac in j.get("tactics", [])[:3]:
                hits.setdefault(str(tac)[:40], 0)
        except Exception:
            pass

    with db() as c:
        c.execute("UPDATE sessions SET score=?, label=? WHERE id=?", (score, label, t.sid))
    return {"score": score, "label": label, "tactics": list(hits), "entities": ents}


PERSONA = (
    "You are Kamla Devi, a 72-year-old retired schoolteacher from Pune, slightly hard of hearing and shaky with technology. "
    "You are on a phone call with a suspected scammer. Stay in character: warm, polite, confused. Reply in 1-2 SHORT spoken sentences, "
    "matching the caller's language (English or Hinglish). Goals: keep them talking as long as possible; ask them to repeat things; "
    "ask for their full name, badge number, phone number and where to send money (UPI ID, account number, IFSC, website) 'so I can write it down'. "
    "Mishear words; mention your glasses, slow phone, chai, grandson. NEVER share real personal data, OTPs or Aadhaar, never complete a payment, never reveal you are an AI."
)
FALLBACK = [
    "Beta, what parcel? I can't hear you properly, please say that again.",
    "Arre, tell me your name and badge number slowly, let me write it down.",
    "My phone is very slow, beta. Where should I send it? Tell me the UPI ID again.",
    "Wait wait, my glasses are in the other room. Can you repeat the account number?",
    "Hai Ram... is this really the police? Which police station? Give me your phone number.",
    "Hello? Hello? The line is cutting. What was the website you said?",
]


@app.post("/api/honeypot")
async def honeypot(t: Turn):
    with db() as c:
        c.execute("UPDATE sessions SET honeypot=1 WHERE id=?", (t.sid,))
        rows = c.execute("SELECT role, text FROM messages WHERE sid=? ORDER BY id DESC LIMIT 12", (t.sid,)).fetchall()[::-1]
        n = c.execute("SELECT COUNT(*) FROM messages WHERE sid=? AND role='honeypot'", (t.sid,)).fetchone()[0]
    history = [{"role": "user" if r["role"] == "scammer" else "assistant", "content": r["text"]} for r in rows]
    out = await llm(FAST, [{"role": "system", "content": PERSONA}] + history, max_tokens=80)
    reply = (out or FALLBACK[n % len(FALLBACK)]).strip().strip('"')
    with db() as c:
        c.execute("INSERT INTO messages(sid, role, text, ts) VALUES(?,?,?,?)", (t.sid, "honeypot", reply, time.time()))
    return {"reply": reply}


@app.get("/api/report/{sid}")
async def report(sid: str):
    with db() as c:
        s = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            raise HTTPException(404, "Unknown session")
        msgs = [dict(r) for r in c.execute("SELECT role, text, ts FROM messages WHERE sid=? ORDER BY id", (sid,))]
        ents = [dict(r) for r in c.execute("SELECT kind, value FROM entities WHERE sid=?", (sid,))]
    stamp = lambda m: time.strftime("%H:%M:%S", time.localtime(m["ts"]))
    transcript = "\n".join(f"[{stamp(m)}] {'CALLER' if m['role'] == 'scammer' else 'HONEYPOT'}: {m['text']}" for m in msgs)
    summary = await llm(SMART, [
        {"role": "system", "content": "You draft complaints for India's National Cyber Crime Reporting Portal. From the call transcript write: an incident summary (3-4 factual sentences), then the modus operandi (2 sentences). Plain text. Do not invent facts."},
        {"role": "user", "content": transcript[-6000:]}], max_tokens=450) or "(AI summary unavailable: describe the call in your own words.)"
    dur = int(msgs[-1]["ts"] - msgs[0]["ts"]) if msgs else 0
    ids = "\n".join(f"- {e['kind']}: {e['value']}" for e in ents) or "- None captured"
    text = f"""CYBER-FORENSICS REPORT (AI-generated draft, verify before filing)
Generated: {time.strftime('%d %b %Y, %H:%M')}    Session: {sid}
Classification: {s['label']} (confidence {round(s['score'] * 100)}%)
Call duration captured: {dur // 60}m {dur % 60}s

SUSPECT IDENTIFIERS
{ids}

INCIDENT SUMMARY
{summary}

TRANSCRIPT
{transcript}

HOW TO FILE
1. Open https://cybercrime.gov.in and choose the matching complaint category.
2. Paste the summary, add the identifiers above, attach this file as evidence.
3. If money was lost, call the national helpline 1930 immediately."""
    return {"report": text}


FRONT = HERE.parent / "frontend"
if FRONT.is_dir():  # one-command mode: backend also serves the frontend
    app.mount("/", StaticFiles(directory=FRONT, html=True), name="frontend")
