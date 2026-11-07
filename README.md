# EchoGuard — Pause before the scam wins

A calm, explainable second pair of ears that helps seniors spot a scam phone
call **while it is happening** — and hang up safely.

**SLAY HACKS 2026 submission — built 2026-11-07 (v1).** Dependency-free web app
(HTML/CSS/JS). Live demo: GitHub Pages (link in the Devpost project).

## What it does

EchoGuard follows a call transcript — typed, pasted, simulated, or **live from
the microphone** (Web Speech API) — and watches for six classic
social-engineering moves: artificial urgency, secrecy demands, unusual payment
requests, credential requests, authority + threats, and remote-access requests.
Each detection is a **named signal with the exact words that triggered it**.
The verdict is large-type and plain: **LOW / CAUTION / HIGH RISK**, with one safe
next step: *Pause. Hang up. Call the official number yourself.*

A **family code word** adds a human layer scammers cannot rehearse: if a caller
claiming to be a relative in an emergency cannot give the secret word your
family agreed on, EchoGuard flags it (+25).

Full **EN/FR interface** — Québec seniors are a first audience.

## Responsible AI & limits

- The **risk score is computed 100% on-device** and nothing is recorded or
  stored. Typed, pasted and simulated transcripts never leave the device. One
  honest exception: live microphone transcription is performed by the
  browser's speech service (in Chrome, audio is processed by Google) — that is
  the browser's service, disclosed here and in the app, not hidden.
- It **never acts for you** — no calls, payments, blocks or reports. A human
  always decides.
- It **can be wrong**: a clever scam may score low; an unusual legitimate call
  may score high. A low score is never a guarantee. The in-app "Responsible AI
  & limits" page says this in plain language.
- Every score point is **auditable in the source** — no black box.

## Run it

```bash
cd echoguard
python3 -m http.server 8000   # open http://127.0.0.1:8000
```

Microphone listening needs Chrome (Web Speech API) and mic permission; typing,
pasting and the simulated calls work in any modern browser.

## Test the engine

```bash
node test.js   # 22 checks, all green required before submission
```

Verified results (v1, 2026-11-07): bank fraud-department scam **100 HIGH** ·
CRA/revenue-agency scam **100 HIGH** · grandparent scam **75 HIGH** (100 with the
family-code check armed and the word missing — the v0.1 score of 100 came from
a credential/payment double-count that v1 fixes: "read me the numbers" is a
payment signal, not a credential request) · paraphrased scams in EN and FR
(prepaid cards, "don't hang up", six-digit code) **HIGH** · legitimate clinic
reminder **0 LOW** · legitimate pharmacy call **0 LOW** · empty input **0 LOW**.

## Use it in 3 steps (set up before a suspicious call ever comes)

1. Save the demo page to your home screen or bookmarks.
2. Agree on a family code word with your relatives, in person.
3. During a doubtful call: speakerphone on → open EchoGuard → tap
   "Listen live".

## Layout

- `index.html` — the app (UI, EN/FR, live listen, Responsible AI page)
- `engine.js` — the explainable engine (browser + Node, same logic, testable)
- `test.js` — Node test suite
