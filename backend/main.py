import os, re, json, sqlite3, time, uuid, random, io, asyncio
from pathlib import Path
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")
KEY = os.getenv("GROQ_API_KEY", "")
FAST = os.getenv("FAST_MODEL", "llama-3.1-8b-instant")      # classification + honeypot voice
SMART = os.getenv("SMART_MODEL", "llama-3.3-70b-versatile")  # report writing
WHISPER = os.getenv("WHISPER_MODEL", "whisper-large-v3-turbo")
THRESH = .6  # honeypot unlocks at 60% confidence
PROVIDER = os.getenv("LLM_PROVIDER", "auto")  # auto = local Ollama first, Groq as backup
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
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
    "Fake authority": (.45, r"police|पुलिस|सीबीआई|cbi|\bed\b|enforcement directorate|customs|narcotics|cyber ?cell|\btrai\b|inspector|officer|supreme court|badge|head office|\bsbi\b|\bhdfc\b|\bicici\b|\brbi\b"),
    "Identity threat": (.30, r"aadhaar|aadhar|आधार|pan card|passport|sim card|money laundering"),
    "Parcel / contraband": (.30, r"parcel|पार्सल|courier|fedex|dhl|package|mdma|drugs|contraband|seized"),
    "Arrest threat": (.45, r"warrant|वारंट|arrest|गिरफ्तार|giraftar|\bfir\b|jail|case (has been )?registered|legal action|digital arrest"),
    "Isolation": (.50, r"do not disconnect|don'?t disconnect|keep (the |your )?(video|camera) on|stay on (the )?(call|line)|do not tell|don'?t tell|tell no ?one|confidential|koi ko mat"),
    "Urgency": (.30, r"immediately|तुरंत|right now|within \d+|last warning|abhi|jaldi|urgent|final notice"),
    "Service cutoff / KYC": (.35, r"\bkyc\b|will be (blocked|suspended|disconnected)|sim (card )?(will|is)|power (supply )?(will be )?(cut|disconnected)|bill (is )?(pending|overdue|unpaid)|account (will be )?(blocked|frozen)"),
    "Payment demand": (.50, r"transfer|ट्रांसफर|safe account|\bupi\b|verification amount|deposit|payment|refund|rbi account|gift card|bitcoin|clearance fee|processing fee"),
    "OTP / remote access": (.50, r"\botp\b|ओटीपी|anydesk|teamviewer|quicksupport|screen share|share (the )?code|\bcvv\b|install (the )?(app|apk)|\bapk\b|card details"),
}

# ---- 2. Deterministic entity extraction (never trust an LLM with account numbers) ----
PAT = {
    "UPI ID": r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b(?!\.[a-zA-Z])",
    "Phone": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
    "Link": r"(?:https?://|www\.)[^\s,]+",
    "IFSC": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "Account no.": r"(?<!\d)\d{9,18}(?!\d)",
}


PAT["Email"] = r"[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}"
DIGITS = [("zero", "shunya", "sunya", "शून्य"), ("one", "ek", "एक"), ("two", "do", "दो"), ("three", "teen", "तीन"), ("four", "chaar", "char", "चार"),
          ("five", "paanch", "panch", "पांच", "पाँच"), ("six", "chhe", "chhah", "छह", "छः"), ("seven", "saat", "सात"), ("eight", "aath", "आठ"), ("nine", "nau", "नौ")]
W2D = {w: str(i) for i, ws in enumerate(DIGITS) for w in ws}
HANDLES = "okaxis|oksbi|okhdfcbank|okicici|ybl|ibl|axl|paytm|apl|upi|sbi|hdfcbank|icici|axisbank|fbl|pnb|jio|airtel|ptsbi|pthdfc|ptyes|yapl|ikwik|postbank|kotak|idfcbank|yesbank|aubank|rbl|federal|freecharge|amazonpay"
MAILS = "gmail|yahoo|outlook|hotmail|rediffmail|icloud|proton"
AUTH = r"\b(mumbai police|delhi police|cyber ?cell|cbi|enforcement directorate|narcotics|customs|trai|fedex|dhl|electricity board|income tax|rbi|sbi|hdfc|icici)\b"
AMT = r"(?:(?:rs\.?|₹|rupees?)\s*([\d,]{3,})|([\d,]{3,})\s*(?:rupees|rs\b))"
NAME = r"(?:this is|i am|i'm|my name is|name is|mera naam|speaking|officer|inspector)\s+(?:(?:inspector|officer|sir|mr|mrs|dr)\.?\s+)?([a-z]{3,}(?:\s[a-z]{3,})?)"
STOP = {"the", "a", "an", "calling", "from", "your", "not", "very", "really", "here", "sorry", "just", "going", "trying", "will", "can", "who", "has", "and", "is", "was", "for", "to", "also", "now"}
LLM = {"ok": None, "err": "", "engine": ""}


def spoken_digits(text):
    """'nine eight seven six', 'double nine', '98765 43210' -> one digit string (only runs of 4+ digits)."""
    out, run, mult = [], [], 1

    def flush():
        nonlocal run
        if sum(len(d) for _, d in run) >= 4:
            out.append("".join(d for _, d in run))
        else:
            out.extend(o for o, _ in run)
        run = []
    for tok in text.split():
        w = tok.lower().strip(".,;:!?-।")
        if w in ("double", "triple"):
            mult = 2 if w == "double" else 3
            run.append((tok, ""))
            continue
        d = W2D.get(w) or (w if w.isdigit() else None)
        if d is not None:
            run.append((tok, d * mult))
            mult = 1
        else:
            mult = 1
            flush()
            out.append(tok)
    flush()
    return " ".join(out)


def normalize(text):
    """Turn speech-to-text output into something the regexes can read."""
    t = spoken_digits(text.translate(str.maketrans("०१२३४५६७८९", "0123456789")))
    t = re.sub(r"\s+dot\s+", ".", t, flags=re.I)
    t = re.sub(r"\s+underscore\s+", "_", t, flags=re.I)
    t = re.sub(r"\s+(?:dash|hyphen)\s+", "-", t, flags=re.I)
    t = re.sub(r"\s*at the rate( of)?\s*", "@", t, flags=re.I)
    t = re.sub(r"([\w.\-]+)\s+at\s+(%s)\b" % HANDLES, r"\1@\2", t, flags=re.I)
    return re.sub(r"([\w.\-]+)\s+at\s+(%s)\b" % MAILS, r"\1@\2", t, flags=re.I)


def extract(text):
    """Instant, offline extraction of anything identifying the caller."""
    text = normalize(text)
    out, rest = [], text
    for kind, p in PAT.items():
        for m in re.findall(p, text):
            m = m.strip(".,")
            if kind == "Account no." and len(m) == 10 and m[0] in "6789":
                continue  # that's a phone number
            out.append((kind, m))
            rest = rest.replace(m, " ")
    for m in re.finditer(AMT, rest, re.I):
        out.append(("Amount", "Rs " + (m.group(1) or m.group(2)).strip(",")))
    rest = re.sub(AMT, " ", rest, flags=re.I)
    out += [("Number / ID", n) for n in re.findall(r"(?<!\d)\d{4,8}(?!\d)", rest)]
    for m in re.finditer(r"\b(?:[A-Za-z][\s.\-]+){2,}[A-Za-z]\b", text):  # spelled out: "a y u s h"
        out.append(("Spelled name", re.sub(r"[\s.\-]", "", m.group(0)).title()))
    for m in re.finditer(AUTH, text, re.I):
        v = m.group(1)
        out.append(("Organisation", v.upper() if len(v) <= 4 else v.title()))
    for m in re.finditer(NAME, text, re.I):
        w = m.group(1).split()
        if w[0].lower() in STOP:
            continue
        out.append(("Name", " ".join(w[:1] if len(w) > 1 and w[1].lower() in STOP else w).title()))
        break
    m = re.search(r"badge\s*(?:number|no\.?|id)?\s*(?:is\s*)?([A-Za-z]{0,3}\d{3,8})", text, re.I)
    if m:
        out.append(("Badge / ID", m.group(1).upper()))
    return list(dict.fromkeys(out))


async def llm(model, messages, json_mode=False, max_tokens=120, temp=None):
    """Local Ollama first (free, unlimited, private), Groq as backup. `model` is only used for Groq."""
    t = 0 if json_mode else (.7 if temp is None else temp)
    tries = (["ollama"] if PROVIDER in ("auto", "ollama") else []) + (["groq"] if PROVIDER in ("auto", "groq") and KEY else [])
    err = "No AI engine reachable: start Ollama (ollama pull %s) or set GROQ_API_KEY" % OLLAMA_MODEL
    for prov in tries:
        try:
            async with httpx.AsyncClient(timeout=120 if prov == "ollama" else 15) as h:
                if prov == "ollama":
                    r = await h.post(f"{OLLAMA_URL}/api/chat", json={
                        "model": OLLAMA_MODEL, "messages": messages, "stream": False, "keep_alive": "30m",
                        **({"format": "json"} if json_mode else {}), "options": {"temperature": t, "num_predict": max_tokens}})
                    r.raise_for_status()
                    out = r.json()["message"]["content"]
                else:
                    body = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": t}
                    if "gpt-oss" in model:  # reasoning models burn tokens thinking, so give them room
                        body.update(reasoning_effort="low", max_tokens=max_tokens + 300)
                    if json_mode:
                        body["response_format"] = {"type": "json_object"}
                    r = await h.post("https://api.groq.com/openai/v1/chat/completions", headers={"Authorization": f"Bearer {KEY}"}, json=body)
                    r.raise_for_status()
                    out = r.json()["choices"][0]["message"]["content"]
            if out and out.strip():
                LLM.update(ok=True, err="", engine=f"Ollama {OLLAMA_MODEL}" if prov == "ollama" else f"Groq {model}")
                return out
            err = f"{prov} returned an empty reply"
        except Exception as e:
            err = f"{prov}: {str(e)[:120]}"
    LLM.update(ok=False, err=err, engine="")
    print("AI engine unavailable, using offline rules:", err)
    return None


class Turn(BaseModel):
    sid: str
    text: str
    pace: float = 0  # speaking pace in words/min, measured by the frontend
    lang: str = "en-IN"


@app.post("/api/session")
def new_session():
    sid = uuid.uuid4().hex[:10]
    with db() as c:
        c.execute("INSERT INTO sessions(id, started) VALUES(?,?)", (sid, time.time()))
    return {"sid": sid}


def rule_score(full, pace=0):
    hits, miss = {}, 1.0
    for k, (w, p) in RULES.items():
        n = len(re.findall(p, full, re.I))
        if n:
            hits[k] = w
            miss *= (1 - w) ** (1 + .3 * (min(n, 4) - 1))  # repeated tactics push the score up
    if hits:
        miss *= .997 ** min(len(full.split()), 100)        # long, pressuring calls creep upward
    if pace > 170 and hits:
        hits["Rapid, pressured speech"] = .15
        miss *= .85
    label = ("Impersonation Scam" if "Fake authority" in hits else
             "OTP / Remote-Access Fraud" if "OTP / remote access" in hits else
             "KYC / Service-Cutoff Scam" if "Service cutoff / KYC" in hits else
             "Payment Fraud" if "Payment demand" in hits else "Unknown")
    return min(.99, 1 - miss), label, hits


@app.post("/api/analyze")  # instant: rules + regex capture. No AI call, so it never waits.
async def analyze(t: Turn):
    now = time.time()
    with db() as c:
        c.execute("INSERT INTO messages(sid, role, text, ts) VALUES(?,?,?,?)", (t.sid, "scammer", t.text, now))
        full = " ".join(r["text"] for r in c.execute("SELECT text FROM messages WHERE sid=? AND role='scammer' ORDER BY id", (t.sid,)))
        for kind, val in extract(t.text):
            c.execute("INSERT OR IGNORE INTO entities VALUES(?,?,?,?)", (t.sid, kind, val, now))
        s = c.execute("SELECT score, label FROM sessions WHERE id=?", (t.sid,)).fetchone()
        score, label, hits = rule_score(full, t.pace)
        if s:
            score = max(score, s["score"])  # a call's threat never drops mid-call
            label = s["label"] if label == "Unknown" else label
        c.execute("UPDATE sessions SET score=?, label=? WHERE id=?", (score, label, t.sid))
        ents = [dict(r) for r in c.execute("SELECT kind, value FROM entities WHERE sid=?", (t.sid,))]
    return {"score": score, "label": label, "tactics": list(hits), "entities": ents}


KINDS = ["Name", "Phone", "Email", "UPI ID", "Account no.", "IFSC", "Link", "Organisation", "Badge / ID", "Address", "Amount", "Other"]
ENRICH = ('You analyse a phone call for an Indian scam-detection tool. Analyse the LAST CALLER line; earlier lines are context '
          '(if KAMLA asked the caller to spell a name, the letters that follow are that name). Reply JSON only: '
          '{"scam_probability":0..1,"scam_type":"2-4 words","tactics":["short phrases"],"details":[{"kind":"' + "|".join(KINDS) + '","value":"exact value the CALLER just gave"}]}. '
          'Only list details the caller actually stated in the last line. Numbers as digits; spelled-out letters joined into one word. Never invent values.')


@app.post("/api/enrich")  # slower: the AI reads the last lines in context and records what regexes can't
async def enrich(t: Turn):
    with db() as c:
        rows = c.execute("SELECT role, text FROM messages WHERE sid=? ORDER BY id DESC LIMIT 6", (t.sid,)).fetchall()[::-1]
        full = " ".join(r["text"] for r in c.execute("SELECT text FROM messages WHERE sid=? AND role='scammer' ORDER BY id", (t.sid,)))
        s = c.execute("SELECT score, label FROM sessions WHERE id=?", (t.sid,)).fetchone()
    score, label, hits = rule_score(full, t.pace)
    convo = "\n".join(f"{'CALLER' if r['role'] == 'scammer' else 'KAMLA'}: {r['text']}" for r in rows)
    raw = await llm(FAST, [{"role": "system", "content": ENRICH}, {"role": "user", "content": convo}], json_mode=True, max_tokens=260)
    found = []
    try:
        j = json.loads(raw)
        score = max(score, min(float(j.get("scam_probability", 0)), score + .25))  # the AI can nudge the rules, not overrule them
        blob = re.sub(r"\W", "", (t.text + " " + normalize(t.text)).lower())
        for d in j.get("details", [])[:8]:
            k, v = str(d.get("kind", "")).strip(), str(d.get("value", "")).strip()
            if k not in KINDS or not 2 <= len(v) <= 60:
                continue
            if k in PAT:
                v = re.sub(r"\s+", "", v).strip(".,")
                if not re.search(PAT[k], v):
                    continue
            if re.sub(r"\W", "", v.lower()) not in blob:  # must really be in what was said
                continue
            found.append((k, v.title() if k in ("Name", "Organisation", "Address") else v))
        typ = str(j.get("scam_type", "")).replace("_", " ").strip().title()[:40]
        if label == "Unknown" and typ and score >= .5:
            label = typ
        for tac in j.get("tactics", [])[:3]:
            hits.setdefault(str(tac)[:40], 0)
    except Exception:
        pass
    with db() as c:
        for k, v in found:
            c.execute("INSERT OR IGNORE INTO entities VALUES(?,?,?,?)", (t.sid, k, v, time.time()))
        if s:
            score = max(score, s["score"])
            label = s["label"] if label == "Unknown" else label
        c.execute("UPDATE sessions SET score=?, label=? WHERE id=?", (score, label, t.sid))
        ents = [dict(r) for r in c.execute("SELECT kind, value FROM entities WHERE sid=?", (t.sid,))]
    return {"score": score, "label": label, "tactics": list(hits), "entities": ents}


def persona(hi):
    lang = "Hindi written in Devanagari script" if hi else "simple Indian English (a word like beta or arre is fine)"
    return f"""You are Kamla Devi, a 72-year-old retired schoolteacher in Pune: widow, lives alone, hard of hearing, slow with phones, warm and chatty. Grandson Rohan (at college) sets up her phone; neighbour Sharma-ji; she loves tea and has bad knees and thick glasses.
You are on a phone call with the "Caller". Reply as Kamla in {lang}: one or two short spoken sentences.
First understand what the caller just said and answer it directly, in character (answer their questions, react to their words, numbers and names). Then, if it fits, ask one follow-up. Never repeat an earlier line.
If asked for her own details (bank, Aadhaar, OTP, email, address, card), stall in character (diary, glasses, ask Rohan) and never give real or made-up numbers.
If the caller sounds like a scammer, quietly keep them talking and get them to say their name, phone number, UPI ID, bank account with IFSC, or website, and read it back to check. Never say you are an AI or that you suspect a scam."""


NEED = ["UPI ID", "Phone", "Account no.", "Link"]
BANK = [
    (r"\b(parcel|courier|package|customs|fedex)\b|पार्सल", ["Parcel? Beta, I haven't ordered anything. My grandson Rohan does the ordering, not me.", "A parcel in MY name? Which courier company, beta? Spell it slowly for me."]),
    (r"\b(aadhaar|aadhar)\b|आधार", ["Adhar? The card with my photo? Hold on, it's in the almirah, where are my keys...", "Beta, I have never given my Aadhaar to anyone. Why would they use it?"]),
    (r"\b(police|cbi|inspector|officer|court)\b|पुलिस", ["Police?! Hai Ram, my heart is beating so fast. Tell me your name and ID number, I'll write it in my diary.", "Which police station, beta? Sharma-ji's son is also in the police, I can ask him."]),
    (r"\b(arrest|warrant|jail|giraftar)\b|गिरफ्तार|वारंट", ["Arrest?! But I am a retired teacher, beta! Please talk slowly, I cannot hear well.", "Wait wait, let me sit down first. Now say again, what is the case number?"]),
    (r"do not tell|don'?t tell|disconnect|\bvideo\b|confidential", ["Not tell anyone? Beta, my neighbour is right here, let me call... arre, the phone is slipping.", "Video? How do I do that, which button is it?"]),
    (r"\b(upi|transfer|account|ifsc|amount|fee)\b", ["Okay okay, I will pay, but I am very slow with this. Say the UPI ID again, letter by letter.", "The app is asking me something, beta. Tell me the account number once more, slowly, my pen is not writing."]),
    (r"\b(otp|code|pin|anydesk|quicksupport|install|app)\b", ["A message has come but my glasses are in the other room, wait wait... what should I press first?", "Install what? Spell the name, beta, my phone is very old, it keeps hanging."]),
    (r"\b(link|website|http|www)\b", ["Website? Say it letter by letter, dot com or dot in? I am writing.", "The page is not opening, beta. Say the address again, and your phone number in case it cuts."]),
]
GENERIC = ["Hello? Hello? The line is breaking, beta. What did you say?", "Arre, one minute, the kettle is whistling. Don't hang up, okay?",
           "Beta, my hearing is not good. Speak slowly and tell me your name again?", "Sorry, sorry, the doorbell rang. What was your phone number, in case the line cuts?"]
ASK = {"UPI ID": "Beta, what was that UPI ID again? Say it slowly.", "Phone": "In case the call cuts, give me your phone number, I'll write it down.",
       "Account no.": "And the account number? Please say it digit by digit.", "Link": "What was the website address? Letter by letter please."}
STOPW = {"beta", "please", "should", "because", "really", "about", "which", "there", "would", "could", "again", "before", "after", "other", "these", "those", "where", "number", "sorry"}


LABELS = {"Number / ID": "number", "Phone": "phone number", "Account no.": "account number", "IFSC": "IFSC code", "Link": "website", "Email": "email"}


def spell(v):
    return " ".join(v) if v.isdigit() else v.replace("@", " at ").replace(".", " dot ")


def offline_reply(text, prev, missing, fresh, n):
    """Rule-based chat used only when no AI engine is reachable. It reacts to what was said and reads back captured details."""
    t = text.lower()
    tiers = [[], [], []]  # 0 direct reactions, 1 topic keywords, 2 nudges
    for kind, v in fresh:
        if kind in ("UPI ID", "Phone", "Account no.", "IFSC", "Link", "Email", "Number / ID"):
            tiers[0].append(f"Wait wait, let me write it in my diary... {LABELS.get(kind, kind.lower())} {spell(v)}. Did I write it right, beta?")
        elif kind in ("Name", "Spelled name"):
            tiers[0].append(f"{v}? Nice name, beta. Which office are you calling from, and what is your phone number?")
        elif kind == "Organisation":
            tiers[0].append(f"{v}?! Hai Ram... beta, give me a number where I can call you back, I will write it down.")
        elif kind == "Amount":
            tiers[0] += [f"{v}?! Beta, that is my whole month's pension. How do I even send it, tell me slowly."]
    for p, opts in [
        (r"\b(your|ur|aapka)\b.*\b(bank|account|card|email|mail|aadhaar|otp|pin|password|details)\b", ["My details? Beta, all that is with Rohan, he keeps the passbook. Why do you need it?", "Email? Rohan made one for me but I don't remember it, it is written in my diary somewhere."]),
        (r"^\W*(hello|hi|namaste|good (morning|afternoon|evening))", ["Namaste beta! Who is this? Speak a little slowly, my hearing is weak.", "Hello hello, yes? Who is speaking, beta?"]),
        (r"how are you|kaise ho|aap kaisi", ["I am fine beta, only my knees are paining. But who is this?"]),
        (r"your name|who are you|aapka naam", ["Kamla Devi, beta. Retired teacher. And you? Say your name once more."]),
        (r"where do you live|your address|kahan rehti", ["Pune, beta, near the old temple. But why do you need it? First tell me who you are."]),
        (r"\balone\b|anyone (at home|with you)|your (son|family)", ["My grandson Rohan is at college, beta. Why are you asking? Is something wrong?"]),
        (r"stupid|idiot|shut up|\bfool\b|bakwas", ["Why are you shouting, beta? I am an old lady, I am trying my best to understand."]),
        (r"are you there|hello\?|listening", ["Yes yes, I am here, beta. The line keeps breaking. Say it again?"]),
        (r"^\W*(yes|yeah|no|okay|ok|haan|nahi|theek)\W*$", ["Okay beta... then what do I do next? Tell me step by step."])]:
        if re.search(p, t):
            tiers[0] += opts
    for p, opts in BANK:
        if re.search(p, t):
            tiers[1] += opts
    if missing and n >= 1:
        tiers[2].append(ASK[random.choice(missing)])
    words = [w for w in re.findall(r"[a-z]{5,}", t) if w not in STOPW]
    if words:
        tiers[2].append(f"{max(words, key=len).title()}? Sorry beta, I did not understand. Explain it like I am your grandmother.")
    tiers.append(GENERIC)
    for pool in tiers:
        pool = [o for o in pool if o not in prev]
        if pool:
            return random.choice(pool)
    return random.choice(GENERIC)


def clean(s):
    s = re.sub(r"\*[^*]*\*", "", s)
    s = re.sub(r"^\W*(kamla( devi)?|caller)\s*:\s*", "", s.strip(), flags=re.I).strip().strip('"“”')
    out = " ".join(x.strip() for x in re.findall(r"[^.!?।]+(?:\.{3}|[.!?।])?", s)[:2])
    return re.sub(r"\s+([,.!?])", r"\1", out).strip()


@app.post("/api/honeypot")
async def honeypot(t: Turn):
    fresh = extract(t.text)
    with db() as c:
        c.execute("UPDATE sessions SET honeypot=1 WHERE id=?", (t.sid,))
        rows = c.execute("SELECT role, text FROM messages WHERE sid=? ORDER BY id DESC LIMIT 12", (t.sid,)).fetchall()[::-1]
        prev = [r["text"] for r in c.execute("SELECT text FROM messages WHERE sid=? AND role='honeypot' ORDER BY id DESC LIMIT 6", (t.sid,))]
        got = {r["kind"] for r in c.execute("SELECT kind FROM entities WHERE sid=?", (t.sid,))}
    missing = [k for k in NEED if k not in got]
    hint = f"Already captured: {', '.join(sorted(got)) or 'nothing'}. Still get them to say: {', '.join(missing) or 'nothing more, just keep stalling'}."
    hot = [f"{k} {v}" for k, v in fresh if k in NEED + ["IFSC", "Email"]]
    if hot:
        hint += f" The caller just gave: {', '.join(hot)}. Read it back slowly and ask if it is right."
    if prev:
        hint += " Do NOT reuse or paraphrase these earlier lines: " + " | ".join(prev[:4])
    history = [{"role": "user" if r["role"] == "scammer" else "assistant", "content": r["text"]} for r in rows]
    out = await llm(FAST, [{"role": "system", "content": persona(t.lang.startswith("hi")) + "\n" + hint}] + history, max_tokens=100, temp=.85)
    reply = clean(out) if out else ""
    engine = LLM["engine"] if reply else "offline"
    reply = reply or offline_reply(t.text, prev, missing, fresh, len(prev))
    with db() as c:
        c.execute("INSERT INTO messages(sid, role, text, ts) VALUES(?,?,?,?)", (t.sid, "honeypot", reply, time.time()))
    return {"reply": reply, "engine": engine, "why": "" if engine != "offline" else LLM["err"]}


VOICES = {("en", "honeypot"): (os.getenv("VOICE_KAMLA", "en-IN-NeerjaNeural"), "-6%", "-4Hz"), ("en", "scammer"): (os.getenv("VOICE_CALLER", "en-IN-PrabhatNeural"), "+4%", "-2Hz"),
          ("hi", "honeypot"): ("hi-IN-SwaraNeural", "-6%", "-4Hz"), ("hi", "scammer"): ("hi-IN-MadhurNeural", "+4%", "+0Hz")}


@app.get("/api/tts")  # neural voices via edge-tts (free, no key). Hindi text gets a Hindi voice. Frontend falls back to a browser voice.
async def tts(text: str, who: str = "honeypot", lang: str = "en"):
    try:
        import edge_tts
    except Exception:
        raise HTTPException(503, "edge-tts is not installed")
    voice, rate, pitch = VOICES.get((lang, who), VOICES[("en", "honeypot")])
    last = ""
    for _ in range(2):
        try:
            comm = edge_tts.Communicate(text[:500], voice, rate=rate, pitch=pitch)
            audio = b"".join([ch["data"] async for ch in comm.stream() if ch["type"] == "audio"])
            if audio:
                return Response(audio, media_type="audio/mpeg")
        except Exception as e:
            last = str(e)[:100]
    raise HTTPException(503, f"edge-tts could not reach its voice service ({last or 'no audio'})")


_wh = {}


def _local_whisper(audio, lang):
    from faster_whisper import WhisperModel
    if "m" not in _wh:
        _wh["m"] = WhisperModel(os.getenv("WHISPER_LOCAL", "small"), device="cpu", compute_type="int8")
    segs, _ = _wh["m"].transcribe(io.BytesIO(audio), language=lang, beam_size=1, vad_filter=True,
                                  initial_prompt="Indian phone call in English or Hindi: Aadhaar, CBI, police, UPI, OTP, IFSC.")
    return " ".join(s.text.strip() for s in segs).strip()


@app.post("/api/transcribe")  # local Whisper (faster-whisper) if installed, else Groq Whisper
async def transcribe(request: Request, lang: str = "en"):
    audio = await request.body()
    if len(audio) < 2000:
        return {"text": ""}
    try:
        import faster_whisper  # noqa
        return {"text": await asyncio.to_thread(_local_whisper, audio, lang)}
    except ImportError:
        pass
    except Exception as e:
        raise HTTPException(502, f"local Whisper failed: {e}")
    if not KEY:
        raise HTTPException(503, "Install faster-whisper (pip install faster-whisper) or set GROQ_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=20) as h:
            r = await h.post("https://api.groq.com/openai/v1/audio/transcriptions", headers={"Authorization": f"Bearer {KEY}"},
                             files={"file": ("chunk.webm", audio, "audio/webm")},
                             data={"model": WHISPER, "language": lang, "temperature": "0"})
            r.raise_for_status()
            return {"text": r.json().get("text", "").strip()}
    except Exception as e:
        raise HTTPException(502, str(e))


def _sessions():
    with db() as c:
        return [dict(r) for r in c.execute("""SELECT * FROM (SELECT s.id, s.started, s.score, s.label, s.honeypot,
            (SELECT COUNT(*) FROM messages m WHERE m.sid = s.id) AS msgs,
            (SELECT COUNT(*) FROM entities e WHERE e.sid = s.id) AS ents,
            (SELECT COALESCE(MAX(ts) - MIN(ts), 0) FROM messages m WHERE m.sid = s.id) AS dur
            FROM sessions s) WHERE msgs > 0 ORDER BY started DESC LIMIT 100""")]


@app.get("/api/sessions")
def list_sessions():
    return _sessions()


@app.get("/api/session/{sid}")
def session_detail(sid: str):
    with db() as c:
        return {"messages": [dict(r) for r in c.execute("SELECT role, text, ts FROM messages WHERE sid=? ORDER BY id", (sid,))],
                "entities": [dict(r) for r in c.execute("SELECT kind, value FROM entities WHERE sid=?", (sid,))]}


@app.delete("/api/session/{sid}")
def delete_session(sid: str):
    with db() as c:
        for tb, col in (("messages", "sid"), ("entities", "sid"), ("sessions", "id")):
            c.execute(f"DELETE FROM {tb} WHERE {col}=?", (sid,))
    return {"ok": True}


@app.delete("/api/sessions")
def clear_all():
    with db() as c:
        for tb in ("messages", "entities", "sessions"):
            c.execute(f"DELETE FROM {tb}")
    return {"ok": True}


@app.get("/api/stats")
def stats():
    from collections import Counter
    rows = _sessions()
    with db() as c:
        kinds = {r["kind"]: r["n"] for r in c.execute("SELECT kind, COUNT(*) AS n FROM entities GROUP BY kind")}
    return {"total": len(rows), "flagged": sum(r["score"] >= THRESH for r in rows),
            "avg": sum(r["score"] for r in rows) / len(rows) if rows else 0, "captured": sum(kinds.values()),
            "wasted": sum(r["dur"] for r in rows if r["honeypot"]),
            "by_label": dict(Counter(r["label"] for r in rows if r["score"] >= THRESH)), "by_kind": kinds}


@app.get("/api/status")
async def status(ping: int = 0):
    import importlib.util as iu
    try:
        async with httpx.AsyncClient(timeout=2) as h:
            have = [m["name"] for m in (await h.get(f"{OLLAMA_URL}/api/tags")).json().get("models", [])]
        ai = (f"Ollama running, {OLLAMA_MODEL} ready (local, unlimited)" if OLLAMA_MODEL in have or f"{OLLAMA_MODEL}:latest" in have
              else f"Ollama running but the model is missing. Run: ollama pull {OLLAMA_MODEL}")
    except Exception:
        ai = "Ollama not running (install it from ollama.com)"
    if ping:
        await llm(FAST, [{"role": "user", "content": "Say OK"}], max_tokens=5)
    with db() as c:
        n = c.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    return {"lines": {
        "Local AI": ai,
        "Groq backup": "key set" if KEY else "no key (optional)",
        "Engine used last": LLM["engine"] or LLM["err"] or "not used yet",
        "Speech recognition": "local Whisper" if iu.find_spec("faster_whisper") else ("Groq Whisper" if KEY else "browser only (pip install faster-whisper for the accurate option)"),
        "Voice output": "edge-tts neural voices" if iu.find_spec("edge_tts") else "browser voices only (pip install edge-tts)",
        "Saved messages": str(n)}}


@app.on_event("startup")
async def warm_up():  # load the local model into memory so the first reply isn't slow
    asyncio.create_task(llm(FAST, [{"role": "user", "content": "hi"}], max_tokens=2))


FRONT = HERE.parent / "frontend"
if FRONT.is_dir():  # one-command mode: backend also serves the frontend
    app.mount("/", StaticFiles(directory=FRONT, html=True), name="frontend")
