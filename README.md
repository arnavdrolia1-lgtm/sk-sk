# sk-sk
# Scammer Ko Scam Kar

Real-time scam-call guardian with an AI honeypot. It scores a call as it happens, then Kamla Devi, a confused 72-year-old, chats with the caller and records their name, phone number, UPI ID, bank details and links. One click turns the call into a draft complaint for cybercrime.gov.in.

```
backend/    FastAPI server: detection, AI chat, capture, SQLite, reports
frontend/   Landing page + dashboard (plain HTML/JS, no build step)
```

## Stack (all free, no per-request limits)

| Part | Choice |
|---|---|
| AI chat and analysis | **Ollama, running locally** (`llama3.2:3b`). Groq is an optional backup |
| Speech to text | Browser speech (fast) or **faster-whisper, local** (accurate, optional) |
| Voice output | edge-tts neural voices (Indian English and Hindi); falls back to the best browser voice |
| Detection | Rule engine (instant) plus the AI reading the call in context |
| Capture | Regex for spoken and typed details (UPI, phone, email, IFSC, account, names, amounts) plus AI extraction that is checked against what was actually said |
| Database | SQLite (built into Python, `backend/scam.db` is created automatically) |

## Setup, step by step

1. **Install Ollama** from https://ollama.com (Mac: drag the app to Applications and open it once; it then runs in the background).
2. **Download the model once** (about 2 GB; use a network without HTTPS filtering):
   ```
   ollama pull llama3.2:3b
   ```
   Low on memory? Use `llama3.2:1b` and set `OLLAMA_MODEL=llama3.2:1b` in `.env`. 16 GB or more? Try `gemma3:4b`.
3. **Backend setup** (in a new terminal):
   ```
   cd backend
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   uvicorn main:app --reload
   ```
4. Open **http://localhost:8000** in Chrome or Edge, hard-refresh with `Cmd + Shift + R`.
5. **Check it**: Settings tab, System status. "Local AI" should say the model is ready and "Engine used last" should say `Ollama llama3.2:3b`.

Optional accurate offline listening: `pip install -r requirements-voice.txt`, then pick Whisper under Listening. If your Python version has no wheels for it, skip it and use Browser listening.

## Using it

- **Landing page** to **Live Guardian**: run a random demo call, use the microphone, or type as the caller. Tick *Practice mode* to chat with Kamla at any threat level.
- Choose **Hindi** under Language and Kamla answers in Hindi with a Hindi voice.
- **Call History** replays calls, **Scam Trends** shows totals, **Reports** builds complaint drafts, **Settings** holds preferences, voice choice and system status.

## Better voices

The green "Voice:" line under the mic buttons says which voice is playing. If it says browser voice, the neural service could not be reached (usually a network that filters HTTPS). Then: use Microsoft Edge (it ships natural Indian voices), or on Mac add "Veena" or "Rishi" (Enhanced) in System Settings, Accessibility, Spoken Content, then pick it in Settings, Browser voice.

## Troubleshooting

- **Replies say "offline rules"**: Ollama is not running or the model is not pulled. Open the Ollama app and run `ollama pull llama3.2:3b`.
- **First reply is slow**: the model loads into memory once (the server warms it at start-up). Later replies are faster.
- **Groq errors**: only relevant if you set a key. Use `llama-3.1-8b-instant`; reasoning models like `gpt-oss` are slow and rate limited.
- **`uvicorn` not found**: activate the virtual environment again.

## Limits

It does not join real phone calls (that needs a paid telephony provider); the call runs in the browser. Speech recognition can mishear numbers, so check captured details before filing. Reports are AI drafts. If money was lost, call **1930** and file at https://cybercrime.gov.in.
