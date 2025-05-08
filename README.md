# 🛡️ CortexPhish — Phishing Threat Analyzer

CortexPhish is a lightweight, interactive phishing detection tool that scans URLs for common red flags and provides AI-generated security analysis along with a downloadable forensic PDF report.

---

## 🔍 What Is Phishing?

Phishing is a social engineering attack where cybercriminals impersonate trusted entities (like banks or tech companies) to deceive users into revealing sensitive information such as passwords, card numbers, or personal details.

Phishing manipulates **human psychology**, not systems, using urgency, trust mimicry, fake links, or emotional triggers.


## 🧠 CortexPhish — Introduction

CortexPhish is a full-stack phishing detection app combining:
- ✅ Local heuristic analysis
- 🧠 AI-powered reasoning
- 📄 PDF report generation
- 🌍 Live cyber threat map

Built to provide **educational awareness**, **real-time triage**, and **GRC compliance support**.

---

## 🎯 Key Use Cases

- SOC analysts (pre-click triage)
- GRC/audit professionals
- Cybersecurity awareness programs
- Student demos & training

---

## 🏗️ Architecture Overview

- **Frontend (HTML, CSS, JS):** Live interaction, heuristic validation, AI output, PDF download
- **Backend (Python Flask):** Deep validation, AI integration, PDF creation
- **OpenAI via OpenRouter:** Contextual NLP explanation
- **No external data stored** – all local unless self-deployed

---

## ⚙️ Technology Stack

| Layer | Tools |
|-------|-------|
| Frontend | HTML, CSS (dark theme), Vanilla JS |
| Backend | Python, Flask |
| AI | OpenRouter (GPT-based reasoning) |
| Reports | FPDF |
| Threat Feed | Check Point Cyber Threat Map (embed) |

---

## 🔁 System Flow

1. User pastes URL
2. Frontend applies heuristic checks
3. Backend re-validates + queries AI
4. AI responds with detailed verdict
5. UI displays result + optional PDF

---

## 🔍 Detection Parameters

- HTTPS Protocol
- IP Address usage
- Subdomain Depth
- Hyphen Abuse
- Punycode Encoding
- Suspicious TLDs
- URL Length
- Keywords in Path (e.g. "login", "verify")
- DNS Reachability
- SSL Certificate Status

---

## 🤖 AI Verdict via OpenRouter

Once checks complete, CortexPhish sends a structured prompt to OpenAI's model:
- ✅ Pass/Fail checklist
- 🧠 4-bullet AI analysis
- ✅ 4-bullet user recommendations
- 🧾 Final verdict summary

---

## 🧾 PDF Report Details

The PDF contains:
- Timestamp
- URL analyzed
- Full checklist
- Definitions
- AI explanation
- Legal disclaimer

Great for GRC documentation, SOC analysis, or cybersecurity training.

---

## 🌐 User Experience Highlights

- Dark mode UI
- Green/red signal colors
- One-click PDF download
- Cyber threat map dashboard
- Info tab with detailed user guide

---

## 📦 How to Run Locally

```bash
git clone https://github.com/yourusername/cortexphish.git
cd cortexphish
pip install -r requirements.txt
python ai_server.py
