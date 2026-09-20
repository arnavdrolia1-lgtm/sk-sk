# Scammer Ko Scam Kar

A live guardian for India's phone scams — fake "digital arrest," bogus CBI/police calls, courier-parcel threats, KYC/SIM-block pressure, and OTP/remote-access fraud. It listens to a call as it's happening, scores every sentence for known scam tactics, and — once it's confident — hands the call to **Kamla Devi**: an AI-voiced 72-year-old retired schoolteacher who keeps the caller talking, in their own language, while quietly writing down every UPI ID, phone number, bank account and link they give away. One click turns the transcript into a draft complaint for cybercrime.gov.in.

## Why

Digital-arrest and impersonation scams work because they isolate the victim (*"don't tell anyone," "stay on video," "you'll be arrested"*) and rush them into a payment before anyone else can intervene. This project flips that dynamic: instead of a real person being isolated and rushed, it's the scammer who ends up stuck on a long, unproductive call with an AI decoy, while the real details needed for a police complaint get captured automatically.

## How it works

```
Caller speaks  →  Speech-to-text  →  Rule engine scores the sentence
                                            │
                          score < 60%       │      score ≥ 60%
                          (keep listening)  ▼      (fraud confirmed)
                                     Entities extracted        Kamla Devi (AI) replies
                                     (regex, instantly)         in-character, in-language,
                                            │                   and steers the caller into
                                            ▼                   giving up more details
                                   LLM enrichment pass
                                (catches paraphrased /
                                 spoken-out details)
                                            │
                                            ▼
                              Everything saved → one-click
                              draft complaint for cybercrime.gov.in
```

## Key features

**Detection**
- A weighted rule engine across 9 tactic categories (fake authority, arrest threats, isolation demands, urgency, KYC/service-cutoff threats, payment demands, OTP/remote-access requests, identity threats, parcel/contraband scripts), each matched in English **and** the native script of 9 other Indian languages.
- Speaking pace is a signal too — fast, pressured speech nudges the score up.
- The threat ring, a sparkline of the call's score history, and a live mic-level meter give an at-a-glance read on where a call stands.

**Capturing evidence**
- Instant regex extraction of UPI IDs, phone numbers, bank accounts, IFSC codes, emails, links, spelled-out names, amounts, organisations and badge/ID numbers — including numbers spoken as words ("double nine," "at the rate," Hindi number words, Unicode digits from any Indian script).
- A second, asynchronous LLM pass re-reads the last few turns and catches details the caller *paraphrased* rather than stated cleanly (e.g. spelling a UPI ID one letter at a time) — it never blocks the UI, and never invents a value that wasn't actually said.

**The honeypot — Kamla Devi**
- A consistent persona (widow, retired teacher, hard of hearing, worried about her pension, grandson Rohan handles her phone) that reacts in-character to whatever the caller just said, then steers toward getting their name, number, UPI ID, or bank account.
- Answers fully in the caller's chosen language and script (10 languages), not just translated English.
- **Self-critiques its own replies** before sending them: a guardrail step rejects anything too long, that repeats an earlier line, that breaks character (sounds like an AI, mentions being recorded, uses words like "scam" or "verify"), that claims a step is already done, or that invents a number the caller never said — and asks the model to try again in character.
- **Prompt-injection resistant**: recognises attempts to redirect it ("ignore previous instructions," "are you an AI," "translate this," a maths question) and reacts with in-character confusion instead of complying.
- **Local-first AI**: tries an on-device Ollama model first (private, free, unlimited) and only falls back to the cloud (Groq, running OpenAI's open-weight GPT-OSS models) if Ollama isn't running — configurable via `LLM_PROVIDER`.
- Falls back to a large hand-written offline reply library (also tactic-aware and non-repeating) if no AI engine answers at all, so the demo never goes silent.

**Voice, in either direction**
- Text-to-speech tries Sarvam Bulbul (natural Indian voices, all 10 languages) → Microsoft Edge neural voices (free, 9 languages) → Kokoro (fully local/offline, English) → ElevenLabs (optional) → the browser's own voice, automatically, and shows which one actually spoke.
- Speech-to-text tries Sarvam Saaras → Groq Whisper (large-v3-turbo) → a local faster-whisper model → the browser's Web Speech API, with the same automatic fallback.
- A **Practice mode** toggle lets you chat with Kamla Devi at any threat level, for testing or demos without needing to build up a score first.

**Everything else you'd want in a real tool, not just a demo**
- **Call History** — every past call, replayable transcript, captured details.
- **Scam Trends** — totals, scam types caught, details captured by kind, and total time wasted on scammers.
- **Reports** — an AI-drafted cybercrime.gov.in complaint per call, exportable as a PDF via the browser's print dialog, or copied straight to the clipboard with a link to file it.
- **Settings** — live status of every AI/voice/STT engine and which one is actually active, theme picker (6 themes), and a "delete everything" control.
- A short marketing-style landing page with an animated mock of the detection flow, and a (non-live, waitlist-only) pricing page — the product framing this was built to pitch.
- Everything is stored in one local SQLite file (`backend/scam.db`); nothing leaves the machine except the AI/voice/STT API calls you've opted into.

## Quick start

1. **Python 3.9+**: check with `python --version` (Mac/Linux: `python3 --version`).
2. From the `backend` folder, create a virtual environment and install the core packages:
   ```
   cd backend
   python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install fastapi "uvicorn[standard]" httpx python-dotenv
   ```
3. **Optional extras** — the app runs without any of these (it just falls back to the next engine), but each unlocks one more capability:
   ```
   pip install edge-tts            # free Microsoft neural voices
   pip install faster-whisper      # local, offline speech-to-text
   pip install kokoro-onnx soundfile   # local, offline English voice
   ```
   For the local voice model: `python download_voice_models.py` (or `--small` for a lighter int8 version).
4. **Add API keys you want to use** — copy `.env.example` to `.env` in `backend/` and fill in any of:
   - `GROQ_API_KEY` — free tier at console.groq.com; powers the cloud AI fallback and Whisper STT.
   - `SARVAM_API_KEY` — best-quality Indian TTS/STT across all 10 languages, from sarvam.ai.
   - `ELEVENLABS_API_KEY` — optional extra voice option.
   - None of these are required — without any key at all, the app still detects scams and replies using the local/offline engines.
5. **(Optional) run Ollama locally** for a private, unlimited AI engine: install from ollama.com, then `ollama pull qwen2.5:1.5b` (or set `OLLAMA_MODEL` to whatever you've pulled).
6. **Start the server**: `uvicorn main:app --reload`, then open **http://localhost:8000** (Chrome or Edge recommended). The backend serves the frontend directly, so there's only one process to run.
7. **Try it**: click **Run demo call** and turn your volume up, or open **Settings → Voice & listening** to pick engines, or flip on **Practice mode** and just type as the caller.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/session` | start a new call, returns a session id |
| `POST /api/analyze {sid,text,pace,lang}` | score a line, extract entities (regex), update the session |
| `POST /api/enrich {sid,text,lang}` | async LLM pass: catches paraphrased details, refines the scam type |
| `POST /api/honeypot {sid,text,lang}` | Kamla Devi's next reply (local/cloud AI, or offline fallback) |
| `GET /api/report/{sid}` | AI-drafted cybercrime.gov.in complaint for one call |
| `GET /api/sessions` / `GET /api/session/{sid}` | call history list / single call detail |
| `DELETE /api/session/{sid}` / `DELETE /api/sessions` | delete one call / delete everything |
| `GET /api/stats` | aggregate trends across all calls |
| `GET /api/status?ping=1` | which AI/voice/STT engines are currently reachable |
| `GET /api/tts?text=&who=&lang=&engine=` | synthesize speech |
| `POST /api/transcribe?lang=` | transcribe an audio chunk |
| `GET /api/languages` | supported languages and their greetings |

## Limits, honestly

- This runs in the browser — it does **not** join a real phone line. Real telephony integration (Twilio, Exotel, etc.) would sit in front of the same `/api/analyze` and `/api/honeypot` endpoints via a webhook.
- Speech recognition can mishear numbers, especially over a phone speaker. **Verify every captured identifier before filing a complaint.**
- The report is an AI draft, not a legal document. If money has already been sent, call the national helpline **1930** and file at **cybercrime.gov.in** immediately — don't wait to generate a report first.
- Pricing tiers shown in the app are a mocked waitlist, not a live payment system.
- Not affiliated with the Government of India, I4C, or any bank.

## Project structure

```
backend/
├── main.py                  FastAPI server: detection, honeypot, TTS/STT routing, SQLite
├── download_voice_models.py fetches the local Kokoro voice model
├── test_sarvam.py           standalone smoke test for the Sarvam TTS key
├── .env.example
└── scam.db                  created automatically on first run
frontend/
└── index.html                the entire dashboard: landing page, live guardian,
                               call history, trends, reports, settings (no build step)
```
