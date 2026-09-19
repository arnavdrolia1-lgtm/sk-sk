# Scammer Ko Scam Kar

Real-time scam-call guardian with an AI honeypot. It scores a call as it happens, then Kamla Devi, a confused 72-year-old, chats with the caller and records their name, phone number, UPI ID, bank details and links. One click turns the call into a draft complaint for cybercrime.gov.in.

```
backend/    FastAPI server: detection, AI chat, capture, SQLite, reports
frontend/   Landing page + dashboard (plain HTML/JS, no build step)
```

## Stack (all free, no per-request limits)

| Part | Choice |
|---|---|
| AI chat and analysis | **Ollama, running locally**. It uses the best model you have installed (`gemma3:4b` recommended). Groq is an optional backup |
| Voice output | **Kokoro-82M, local** (natural, no network). Fallbacks: Microsoft neural voices (edge-tts), then your browser's voice |
| Speech to text | Browser speech (fast) or faster-whisper, local (accurate, optional) |
| Detection | Rule engine (instant) plus the AI reading the call in context |
| Capture | Regex for spoken and typed details plus AI extraction that is checked against what was actually said |
| Database | SQLite (built into Python, `backend/scam.db` is created automatically) |

## Setup, step by step

1. **Install Ollama** from https://ollama.com and open it once.
2. **Download a model once** (use a network without HTTPS filtering):
   ```
   ollama pull gemma3:4b
   ```
   Short on memory? `llama3.2:3b` or `llama3.2:1b` also work. 16 GB or more? `llama3.1:8b` writes best. The app picks the best one installed.
3. **Backend**:
   ```
   cd backend
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```
4. **Natural voice (Kokoro)**:
   ```
   pip install -r requirements-voice.txt
   python download_voice_models.py
   ```
   The download is about 310 MB (`--small` gives a 90 MB version that is faster on weak laptops). If pip says it cannot find a matching version, your Python is too new for these packages: install Python 3.12, create the venv with `python3.12 -m venv .venv`, and repeat.
5. **Start it**: `uvicorn main:app --reload`, then open http://localhost:8000 in Chrome or Edge and hard-refresh (`Cmd + Shift + R`).
6. **Check it**: Settings, System status. "Local AI" should say ready and "Voice output" should say Kokoro. Use *Test Kamla* and *Test caller*.

Optional accurate listening: `pip install -r requirements-stt.txt`, then choose Whisper under Listening.

## Voices

- **Settings, Voice engine**: Auto tries Kokoro, then Microsoft neural, then the browser. Or force one.
- **Voice for Kamla / Voice for caller** list every Kokoro voice, so you can audition them. `bf_emma` (default), `bf_alice` and `bf_isabella` are warm British female voices; `bm_george` is the default caller.
- Kokoro has no Indian-English voice. Microsoft's `en-IN` voices sound more Indian but need internet: pick "Microsoft neural" under Voice engine to compare.
- Replies are spoken sentence by sentence, so the next sentence is rendered while the last one plays.
- The "Voice:" line under the mic buttons shows which engine is speaking, and why if it fell back.

## Using it

- **Landing page**, then **Live Guardian**: run a random demo call, use the microphone, or type as the caller. Tick *Practice mode* to chat with Kamla at any threat level. Choose **Hindi** under Language for Hindi replies and a Hindi voice.
- **Call History** replays calls, **Scam Trends** shows totals, **Reports** builds complaint drafts, **Settings** holds preferences and system status.

## Troubleshooting

- **Replies say "offline rules"**: Ollama is not running or no model is pulled.
- **First reply is slow**: the model loads into memory once; later replies are faster.
- **Voice says "browser voice"**: read the reason next to it. Usually Kokoro is not set up (step 4) or the network blocks Microsoft's service.
- **`uvicorn` not found**: activate the virtual environment again.

## Limits

It does not join real phone calls (that needs a paid telephony provider); the call runs in the browser. Speech recognition can mishear numbers, so check captured details before filing. Reports are AI drafts. If money was lost, call **1930** and file at https://cybercrime.gov.in.
