import os, re, json, sqlite3, time, uuid, random
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
# NOTE: Groq retired llama-3.1-8b-instant and llama-3.3-70b-versatile on 16 Aug 2026.
# Calls to a dead model id fail silently in llm() below and the app quietly drops to the
# canned rule-based replies -- that's what made the honeypot feel repetitive. These are
# Groq's own recommended replacements; override via .env if Groq rotates models again.
FAST = os.getenv("FAST_MODEL", "openai/gpt-oss-20b")        # classification + honeypot voice
SMART = os.getenv("SMART_MODEL", "openai/gpt-oss-120b")     # report writing
WHISPER = os.getenv("WHISPER_MODEL", "whisper-large-v3-turbo")
THRESH = .6  # honeypot unlocks at 60% confidence
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
    CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT, label TEXT, score REAL, text TEXT, ts REAL);
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
# Speech recognisers do not write "ramesh@oksbi" or "9876543210". They write "ramesh at oksbi",
# "98765 43210", "nine eight seven ...", "sbin0001234" (lowercase) and "scamsite dot com slash verify".
# normalise_spoken() turns those back into the written forms before the regexes run.
PAT = {
    "UPI ID": r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b(?!\.[a-zA-Z])",
    "Phone": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
    "Link": r"(?:https?://|www\.)[^\s,]+|(?<![@\w.\-])[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.(?:com|in|co\.in|net|org|xyz|info|link|top|online|site|app|club|live|cc|biz|shop|store|help|support)\b(?:/[^\s,]*)?",
    "IFSC": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "Account no.": r"(?<!\d)\d{9,18}(?!\d)",
}
UPI_HANDLES = "ok(?:sbi|axis|hdfcbank|icici)|ybl|ibl|axl|paytm|apl|upi|sbi|axisbank|hdfcbank|icici|fam|jupiter|ikwik|postbank|pnb|barodampay|unionbank|airtel|freecharge|yapl|rbl|federal|idfcbank|kotak|indus|cnrb|abfspay|slc|okbizaxis"
NUM = {"zero": "0", "oh": "0", "shunya": "0", "one": "1", "ek": "1", "two": "2", "do": "2", "three": "3", "teen": "3",
       "four": "4", "char": "4", "chaar": "4", "five": "5", "paanch": "5", "panch": "5", "six": "6", "chhe": "6", "chah": "6",
       "seven": "7", "saat": "7", "sat": "7", "eight": "8", "aath": "8", "nine": "9", "nau": "9"}
NUMW = "|".join(sorted(NUM, key=len, reverse=True))


def normalise_spoken(text):
    t = re.sub(r"\s*\bat the rate( of)?\b\s*", "@", text, flags=re.I)              # "at the rate of" -> @
    t = re.sub(r"\b([\w.\-]+)\s+at\s+(" + UPI_HANDLES + r")\b", r"\1@\2", t, flags=re.I)  # "ramesh at oksbi" -> ramesh@oksbi
    t = re.sub(r"\s*\b(?:dot|dott)\b\s*", ".", t, flags=re.I)                     # "scamsite dot com" -> scamsite.com
    t = re.sub(r"\s*\bslash\b\s*", "/", t, flags=re.I)
    t = re.sub(r"\bplus\s+(?=91)", "", t, flags=re.I)
    t = re.sub(r"\s*\b(?:underscore|under score)\b\s*", "_", t, flags=re.I)
    t = re.sub(r"\s*\b(?:hyphen|dash)\b\s*", "-", t, flags=re.I)
    t = re.sub(r"\b(double|triple)\s+(" + NUMW + r"|\d)\b",                       # "double nine" -> 99
               lambda m: (NUM.get(m.group(2).lower(), m.group(2))) * (2 if m.group(1).lower() == "double" else 3), t, flags=re.I)
    t = re.sub(r"\b(" + NUMW + r")\b", lambda m: NUM[m.group(1).lower()], t, flags=re.I)  # digit words -> digits
    # join digit groups the recogniser split up: "98765 43210", "9 8 7 6 5 ...", "1234 5678 9012"
    def join(m):
        d = re.sub(r"\D", "", m.group(0))
        if len(d) == 12 and re.match(r"91[6-9]", d):
            d = d[2:]                  # "91 98765 43210" -> country code dropped, it's a phone number
        return d if len(d) >= 9 else m.group(0)
    t = re.sub(r"(?<![\d+])\d{1,5}(?:[\s\-,]\d{1,5})+(?!\d)", join, t)
    return t


def extract(text):
    t = normalise_spoken(text)
    out = []
    for kind, p in PAT.items():
        for m in re.findall(p, t):
            m = m.strip(".,/")
            if kind == "Account no." and ((len(m) == 10 and m[0] in "6789") or (len(m) == 12 and re.match(r"91[6-9]", m))):
                continue  # that's a phone number (bare or with +91)
            if kind == "Link" and "@" in m:
                continue
            out.append((kind, m))
    # IFSC is spelled out ("s b i n zero zero ...") and lower-cased: search a squashed, upper-cased copy
    for m in re.findall(PAT["IFSC"].replace(r"\b", ""), re.sub(r"[\s\-]", "", t).upper()):
        if ("IFSC", m) not in out:
            out.append(("IFSC", m))
    return list(dict.fromkeys(out))


AI_STATUS = {"ok": None, "error": None, "ts": 0}  # last-call health, surfaced at /api/health


async def llm(model, messages, json_mode=False, max_tokens=400):
    """Call Groq chat completions. Returns the reply text, or None on ANY failure (with the reason in AI_STATUS).

    openai/gpt-oss-* are *reasoning* models: hidden thinking tokens are billed against the token cap. At the
    default effort ("medium") a small cap (we used 70 / 120) is spent entirely on thinking, Groq answers HTTP 200
    with finish_reason="length" and content="", and the app looked like it had no AI. So we ask for LOW effort,
    leave headroom, and treat an empty reply as a failure instead of a success.
    """
    if not KEY:
        AI_STATUS.update(ok=False, error="No GROQ_API_KEY set (is backend/.env present and did you restart uvicorn?)", ts=time.time())
        return None
    body = {"model": model, "messages": messages, "max_completion_tokens": max_tokens,
            "temperature": 0 if json_mode else 0.7}
    if "gpt-oss" in model:            # other model families reject this parameter with a 400
        body["reasoning_effort"] = "low"
        body["include_reasoning"] = False
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    url, headers = "https://api.groq.com/openai/v1/chat/completions", {"Authorization": f"Bearer {KEY}"}
    try:
        async with httpx.AsyncClient(timeout=20) as h:
            r = await h.post(url, headers=headers, json=body)
            if r.status_code == 400 and json_mode:      # model without JSON mode: retry, the prompt already says "JSON only"
                body.pop("response_format", None)
                r = await h.post(url, headers=headers, json=body)
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code} from Groq: {r.text[:300]}")
            choice = r.json()["choices"][0]
            text = (choice["message"].get("content") or "").strip()
            if not text:
                raise RuntimeError(f"Groq returned an empty reply (finish_reason={choice.get('finish_reason')}) - "
                                   f"the model spent its token budget thinking; raise max_tokens or lower reasoning_effort")
            AI_STATUS.update(ok=True, error=None, ts=time.time())
            return text
    except Exception as e:
        # 401 = bad/revoked key, 404 = model id retired (console.groq.com/docs/deprecations), 429 = rate limit
        print("LLM error (falling back to rules):", e)
        AI_STATUS.update(ok=False, error=str(e)[:300], ts=time.time())
        return None


def parse_json(raw):
    """Pull the first {...} object out of a model reply (tolerates ```json fences and stray prose)."""
    m = re.search(r"\{.*\}", raw or "", re.S)
    return json.loads(m.group(0)) if m else {}


class Turn(BaseModel):
    sid: str
    text: str
    pace: float = 0  # speaking pace in words/min, measured by the frontend


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

    hits, miss = {}, 1.0
    for k, (w, p) in RULES.items():
        n = len(re.findall(p, full, re.I))
        if n:
            hits[k] = w
            miss *= (1 - w) ** (1 + .3 * (min(n, 4) - 1))  # repeated tactics push the score up
    if hits:
        miss *= .997 ** min(len(full.split()), 100)        # long, pressuring calls creep upward
    if t.pace > 170 and hits:
        hits["Rapid, pressured speech"] = .15
        miss *= .85
    score = min(.99, 1 - miss)
    label = ("Impersonation Scam" if "Fake authority" in hits else
             "OTP / Remote-Access Fraud" if "OTP / remote access" in hits else
             "KYC / Service-Cutoff Scam" if "Service cutoff / KYC" in hits else
             "Payment Fraud" if "Payment demand" in hits else "Unknown")

    if score < THRESH:  # once confirmed, skip the LLM: faster and saves free-tier quota
        raw = await llm(FAST, [
            {"role": "system", "content": 'You analyse phone-call transcripts for Indian scams (digital arrest, fake CBI/police, courier, OTP, KYC). Reply JSON only: {"scam_probability":0..1,"scam_type":"short label","tactics":["short phrases"]}'},
            {"role": "user", "content": full[-1500:]}], json_mode=True, max_tokens=500)
        try:
            j = parse_json(raw)
            score = max(score, min(.99, float(j["scam_probability"])))
            label = j.get("scam_type") or label
            for tac in j.get("tactics", [])[:3]:
                hits.setdefault(str(tac)[:40], 0)
        except Exception:
            pass

    with db() as c:
        c.execute("UPDATE sessions SET score=?, label=? WHERE id=?", (score, label, t.sid))
    return {"score": score, "label": label, "tactics": list(hits), "entities": ents}


PERSONA = """You are Kamla Devi, 72, a retired schoolteacher in Pune who lives alone; your grandson Rohan sets up your phone. You are hard of hearing, slow with technology, warm, chatty and a little scared of 'police'. You are secretly stalling a suspected scammer on a phone call.
Rules: reply in 1-2 SHORT natural spoken sentences. Use Roman-script Hinglish if the caller uses Hindi words, otherwise simple Indian English. Never repeat an earlier line, never sound scripted or clever.
Tactics, rotate them: mishear a word and ask what it means; ask them to repeat slowly; ask their name, officer ID, station and callback number 'for my diary'; go look for glasses, pen or charger; kettle whistling or doorbell; the app is loading or confusing; nervously comply but slowly ('okay beta, I'm opening it... which button?'); ask them to repeat any UPI ID, account number or link letter by letter.
Goal: make them say their UPI ID, phone number, bank account with IFSC, and any link, and keep the call going. Never give real data, OTPs or Aadhaar; never finish a payment; never say you are an AI or suspect a scam."""

NEED = ["UPI ID", "Phone", "Account no.", "Link"]
BANK = [
    (r"parcel|courier|package|customs|fedex|पार्सल", ["Parcel? Beta, I haven't ordered anything. My grandson Rohan does the ordering, not me.", "A parcel in MY name? Which courier company, beta? Spell it slowly for me."]),
    (r"aadhaar|aadhar|आधार", ["Adhar? The card with my photo? Hold on, it's in the almirah, where are my keys...", "Beta, I have never given my Aadhaar to anyone. Why would they use it?"]),
    (r"police|cbi|inspector|officer|court|पुलिस", ["Police?! Hai Ram, my heart is beating so fast. Tell me your name and ID number, I'll write it in my diary.", "Which police station, beta? Sharma-ji's son is also in the police, I can ask him."]),
    (r"arrest|warrant|jail|giraftar|गिरफ्तार|वारंट", ["Arrest?! But I am a retired teacher, beta! Please talk slowly, I cannot hear well.", "Wait wait, let me sit down first. Now say again, what is the case number?"]),
    (r"do not tell|don'?t tell|disconnect|video|confidential", ["Not tell anyone? Beta, my neighbour is right here, let me call... arre, the phone is slipping.", "Video? How do I do that, which button is it?"]),
    (r"upi|transfer|account|safe account|ifsc|amount|fee", ["Okay okay, I will pay, but I am very slow with this. Say the UPI ID again, letter by letter.", "The app is asking me something, beta. Tell me the account number once more, slowly, my pen is not writing."]),
    (r"otp|code|pin|anydesk|quicksupport|install|app\b", ["A message has come but my glasses are in the other room, wait wait... what should I press first?", "Install what? Spell the name, beta, my phone is very old, it keeps hanging."]),
    (r"link|website|http|www|open ", ["Website? Say it letter by letter, dot com or dot in? I am writing.", "The page is not opening, beta. Say the address again, and your phone number in case it cuts."]),
]
GENERIC = ["Hello? Hello? The line is breaking, beta. What did you say?", "Arre, one minute, the kettle is whistling. Don't hang up, okay?",
           "Beta, my hearing is not good. Speak slowly and tell me your name again?", "Sorry, sorry, the doorbell rang. What was your phone number, in case the line cuts?",
           "Wait beta, let me put on my glasses, I can't see the phone screen properly.",
           "One second, my grandson usually helps me with this phone, he has gone to the market.",
           "Hah? Say again na, this network in my building is very poor.",
           "Achha achha, I am listening, my hands are just shaking a little, go slow."]
ASK = {"UPI ID": ["Beta, what was that UPI ID again? Say it slowly, letter by letter.", "The app is asking 'enter UPI', can you repeat the ID once more?"],
       "Phone": ["In case the call cuts, give me your phone number, I'll write it down.", "What is your direct number, beta, so I can call back if this drops?"],
       "Account no.": ["And the account number? Please say it digit by digit, my pen is slow.", "Which account should I send to, read the number again na."],
       "Link": ["What was the website address? Letter by letter please.", "The page is still loading, tell me the link again, dot com or dot in?"]}
CONFIRM = ["Wait, you said {v}? Let me write that down... {v}... okay.",
           "So it is {v}, correct? My hearing is not so good, confirm once.",
           "{v}, I have written it, but the app shows an error, say it again slowly?",
           "Hold on beta, {v} — is that right, or did I get one letter wrong?"]


def fallback(text, prev, missing, got_vals=None):
    """Rule-based Kamla Devi reply, used when the Groq call fails or no key is set.
    Weighted so it (a) reacts to what the caller just said, (b) occasionally reads a
    just-captured value back for 'confirmation' so the reply doesn't feel canned, and
    (c) works through the missing-details list instead of asking at random."""
    pool = [o for p, opts in BANK if re.search(p, text, re.I) for o in opts]
    # Echo back a value the caller just gave, in character -- reads as active listening
    # instead of a scripted line, and doubles as a second chance to capture it correctly.
    just_given = (got_vals or {}).get("_latest")
    if just_given and random.random() < .5:
        pool.append(random.choice(CONFIRM).format(v=just_given))
    if missing:
        pool.extend(ASK[random.choice(missing)])
    pool = [o for o in pool if o not in prev] or [o for o in (ASK.get(missing[0], []) if missing else []) if o not in prev] \
        or [g for g in GENERIC if g not in prev] or GENERIC
    return random.choice(pool)


@app.post("/api/honeypot")
async def honeypot(t: Turn):
    with db() as c:
        c.execute("UPDATE sessions SET honeypot=1 WHERE id=?", (t.sid,))
        # 20 turns of real context (was 12) -- short history is a big reason the AI repeats
        # itself, since it can't see it already asked the same thing two turns ago.
        rows = c.execute("SELECT role, text FROM messages WHERE sid=? ORDER BY id DESC LIMIT 20", (t.sid,)).fetchall()[::-1]
        prev = [r["text"] for r in c.execute("SELECT text FROM messages WHERE sid=? AND role='honeypot' ORDER BY id DESC LIMIT 8", (t.sid,))]
        ent_rows = [dict(r) for r in c.execute("SELECT kind, value FROM entities WHERE sid=? ORDER BY ts", (t.sid,))]
    got = {e["kind"] for e in ent_rows}
    missing = [k for k in NEED if k not in got]
    captured_line = "; ".join(f"{e['kind']}={e['value']}" for e in ent_rows) or "nothing yet"
    hint = (f"Already captured (use these exact values if you refer back to them, e.g. to 'confirm' one): {captured_line}.\n"
            f"Still get them to say: {', '.join(missing) or 'nothing more, just keep stalling and wasting their time'}.\n"
            f"You have exchanged {len(rows)} lines already -- do not reuse an earlier line or ask the same question twice in a row.")
    history = [{"role": "user" if r["role"] == "scammer" else "assistant", "content": r["text"]} for r in rows]
    out = await llm(FAST, [{"role": "system", "content": PERSONA + "\n" + hint}] + history, max_tokens=400)
    this_turn = extract(t.text)  # anything the caller just said this turn, for the fallback's "confirm" flavour
    got_vals = {"_latest": this_turn[0][1] if this_turn else None}
    reply = (out or fallback(t.text, prev, missing, got_vals)).strip().strip('"')
    with db() as c:
        c.execute("INSERT INTO messages(sid, role, text, ts) VALUES(?,?,?,?)", (t.sid, "honeypot", reply, time.time()))
    return {"reply": reply, "ai": bool(out), "why": None if out else AI_STATUS["error"]}


VOICES = {"honeypot": ("en-IN-NeerjaNeural", "-15%", "-3Hz"), "scammer": ("en-IN-PrabhatNeural", "+8%", "-2Hz")}


@app.get("/api/tts")  # neural voices via edge-tts (free, no key). Frontend falls back to the browser voice on error.
async def tts(text: str, who: str = "honeypot"):
    try:
        import edge_tts
        voice, rate, pitch = VOICES.get(who, VOICES["honeypot"])
        comm = edge_tts.Communicate(text[:400], voice, rate=rate, pitch=pitch)
        audio = b"".join([ch["data"] async for ch in comm.stream() if ch["type"] == "audio"])
        return Response(audio, media_type="audio/mpeg")
    except Exception as e:
        raise HTTPException(503, f"TTS unavailable: {e}")


@app.post("/api/transcribe")  # Whisper large-v3-turbo on Groq: far better on Hinglish and noisy calls than browser STT
async def transcribe(request: Request, lang: str = "en"):
    audio = await request.body()
    if not KEY:
        raise HTTPException(503, "Whisper needs GROQ_API_KEY (backend/.env)")
    if len(audio) < 1500:
        return {"text": ""}          # a near-empty chunk is silence, not an error
    ctype = (request.headers.get("content-type") or "audio/webm").split(";")[0]
    ext = "mp4" if "mp4" in ctype else "ogg" if "ogg" in ctype else "webm"   # Safari records mp4, Chrome/Edge webm
    try:
        async with httpx.AsyncClient(timeout=30) as h:
            r = await h.post("https://api.groq.com/openai/v1/audio/transcriptions",
                             headers={"Authorization": f"Bearer {KEY}"},
                             files={"file": (f"chunk.{ext}", audio, ctype)},
                             data={"model": WHISPER, "language": lang, "temperature": "0",
                                   "prompt": "Indian phone call in English or Hinglish: Aadhaar, CBI, police, parcel, warrant, UPI, OTP, IFSC, digital arrest."})
            if r.status_code >= 400:
                print("Whisper error:", r.status_code, r.text[:300])
                AI_STATUS.update(ok=False, error=f"Whisper HTTP {r.status_code}: {r.text[:200]}", ts=time.time())
                raise HTTPException(502, f"Groq Whisper HTTP {r.status_code}: {r.text[:200]}")
            text = r.json().get("text", "").strip()
            if text.lower().strip(" .!") in {"thank you", "thanks for watching", "you", "bye"}:
                text = ""            # classic Whisper hallucination on near-silence
            return {"text": text}
    except HTTPException:
        raise
    except Exception as e:
        print("Whisper error:", e)
        raise HTTPException(502, str(e))


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
        {"role": "user", "content": transcript[-6000:]}], max_tokens=1500) or "(AI summary unavailable: describe the call in your own words.)"
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
    with db() as c:
        c.execute("INSERT INTO reports(sid, label, score, text, ts) VALUES(?,?,?,?,?)",
                   (sid, s["label"], s["score"], text, time.time()))
    return {"report": text}


@app.get("/api/sessions")
def list_sessions():
    """Call History tab: every session with a quick summary, newest first."""
    with db() as c:
        rows = c.execute("""
            SELECT s.id, s.started, s.score, s.label, s.honeypot,
                   (SELECT COUNT(*) FROM messages m WHERE m.sid = s.id) AS messages,
                   (SELECT COUNT(*) FROM entities e WHERE e.sid = s.id) AS entities,
                   (SELECT MAX(ts) FROM messages m WHERE m.sid = s.id) AS last_ts
            FROM sessions s ORDER BY s.started DESC
        """).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/session/{sid}")
def session_detail(sid: str):
    """Call History tab: transcript + captured entities for one session."""
    with db() as c:
        s = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            raise HTTPException(404, "Unknown session")
        msgs = [dict(r) for r in c.execute("SELECT role, text, ts FROM messages WHERE sid=? ORDER BY id", (sid,))]
        ents = [dict(r) for r in c.execute("SELECT kind, value, ts FROM entities WHERE sid=? ORDER BY ts", (sid,))]
    return {"session": dict(s), "messages": msgs, "entities": ents}


@app.delete("/api/session/{sid}")
def delete_session(sid: str):
    with db() as c:
        c.execute("DELETE FROM sessions WHERE id=?", (sid,))
        c.execute("DELETE FROM messages WHERE sid=?", (sid,))
        c.execute("DELETE FROM entities WHERE sid=?", (sid,))
        c.execute("DELETE FROM reports WHERE sid=?", (sid,))
    return {"ok": True}


@app.delete("/api/sessions")
def clear_all():
    """Settings tab: wipe every call, entity and report -- e.g. before handing the laptop to someone else."""
    with db() as c:
        c.executescript("DELETE FROM sessions; DELETE FROM messages; DELETE FROM entities; DELETE FROM reports;")
    return {"ok": True}


@app.get("/api/reports")
def list_reports():
    """Reports tab: every AI-drafted complaint generated so far, newest first."""
    with db() as c:
        rows = c.execute("SELECT id, sid, label, score, text, ts FROM reports ORDER BY ts DESC").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/stats")
def stats():
    """Scam Trends tab: aggregate numbers across every call recorded so far."""
    with db() as c:
        sessions = [dict(r) for r in c.execute("SELECT score, label, honeypot, started FROM sessions ORDER BY started")]
        ent_counts = [dict(r) for r in c.execute("SELECT kind, COUNT(*) AS n FROM entities GROUP BY kind ORDER BY n DESC")]
        label_counts = [dict(r) for r in c.execute(
            "SELECT label, COUNT(*) AS n FROM sessions WHERE label != 'Unknown' GROUP BY label ORDER BY n DESC")]
    total = len(sessions)
    caught = sum(1 for s in sessions if s["honeypot"])
    avg_score = round(sum(s["score"] for s in sessions) / total, 3) if total else 0
    flagged = sum(1 for s in sessions if s["score"] >= THRESH)
    return {"total_calls": total, "flagged_calls": flagged, "honeypot_activations": caught,
            "avg_score": avg_score, "by_label": label_counts, "by_entity": ent_counts,
            "score_trend": [round(s["score"], 3) for s in sessions[-30:]]}


@app.get("/api/health")
async def health(probe: int = 0):
    """Settings tab: is the Groq key working, and which models is it calling. ?probe=1 makes a real test call."""
    if probe:
        got = await llm(FAST, [{"role": "user", "content": "Reply with the single word: ready"}], max_tokens=200)
        AI_STATUS["probe"] = (got or "")[:60] or None
    return {"ai_configured": bool(KEY), "ai_last_ok": AI_STATUS["ok"], "ai_last_error": AI_STATUS["error"],
            "ai_probe": AI_STATUS.get("probe"), "fast_model": FAST, "smart_model": SMART, "whisper_model": WHISPER,
            "threshold": THRESH}


FRONT = HERE.parent / "frontend"
if FRONT.is_dir():  # one-command mode: backend also serves the frontend
    app.mount("/", StaticFiles(directory=FRONT, html=True), name="frontend")