# AI-Generated Code Security-Debt Scorer

> Avishkar Industrial-Ready Hackathon Project

A developer security platform that detects vulnerabilities in AI-generated code, calculates a measurable "Security Debt Score" (0-100), explains risks using Claude AI, and demonstrates scan → fix → rescan improvement.

## 🎯 Product Thesis

Traditional security tools answer: **"What vulnerabilities exist?"**

This platform adds: **"How much security debt has accumulated, what's driving it, and how much did a fix reduce it?"**

## 🏗️ Architecture

```
Repository/ZIP → FastAPI Backend → Scanners (Semgrep + Gitleaks + Custom)
                                    ↓
                            Finding Normalizer
                                    ↓
                            Claude AI Reasoning
                                    ↓
                            Security Debt Engine
                                    ↓
                        SQLite Database + Next.js Dashboard
                                    ↓
                            GitHub PR Integration
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- Git

### Backend Setup

```bash
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Install Semgrep
pip install semgrep

# Download Gitleaks (Windows)
# Visit: https://github.com/gitleaks/gitleaks/releases
# Place gitleaks.exe in C:\tools\gitleaks\ or update config

# Create .env file
cp .env.example .env
# Edit .env with your CLAUDE_API_KEY

# Run backend
uvicorn main:app --reload
```

Backend runs at: http://localhost:8000

API docs at: http://localhost:8000/docs

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Create .env.local
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local

# Run frontend
npm run dev
```

Frontend runs at: http://localhost:3000

### Testing

```bash
cd backend
pytest tests/ -v
```

## 📊 Security Debt Formula

```
Finding Debt = Severity × Exploitability × Exposure × Remediation Effort × Confidence

Project Score = min(100, sum(finding_debt) / PROJECT_CAPACITY × 100)
```

**Risk Bands**:
- 0-20: LOW
- 21-40: MODERATE
- 41-60: ELEVATED
- 61-80: HIGH
- 81-100: CRITICAL

## 🔍 Detection Strategy

| Risk Area | Scanner | Example |
|-----------|---------|---------|
| SQL Injection | Semgrep + Custom | String concatenation in queries |
| Secrets | Gitleaks | API keys, tokens in source |
| Weak Crypto | Semgrep + Custom | MD5/SHA1 for passwords |
| Command Injection | Semgrep | os.system(user_input) |
| Path Traversal | Semgrep | Unvalidated file paths |
| Insecure Config | Custom | debug=True, verify=False |

## 🎬 Demo Flow

1. Open dashboard → "New Scan"
2. Upload `sample_projects/vulnerable-python.zip`
3. Wait ~10 seconds → Score: 78 (HIGH)
4. Open SQL Injection finding → AI explanation
5. Apply parameterized query fix
6. Rescan → Score: 52 (ELEVATED) ✅
7. Show trend chart with improvement

## 📁 Project Structure

```
AVISHKAR/
├── backend/
│   ├── main.py              # FastAPI app
│   ├── config.py            # Configuration
│   ├── api/                 # API endpoints
│   ├── scanners/            # Semgrep, Gitleaks, Custom
│   ├── ai/                  # Claude API integration
│   ├── scoring/             # Debt calculation
│   ├── models/              # Pydantic models
│   └── database/            # SQLite + CRUD
├── frontend/                # Next.js dashboard
├── rules/                   # Custom security rules
├── sample_projects/         # Vulnerable demo projects
└── tests/                   # Test suite
```

## 🔒 Security Features

- Path traversal validation
- 50MB file size limit
- Workspace isolation
- Secret redaction in logs/UI
- Webhook signature verification
- Rate limiting on AI calls
- Input sanitization

## 📚 Implementation Phases

1. ✅ Repository skeleton + FastAPI
2. ⏳ Upload & repository ingestion
3. ⏳ Semgrep integration
4. ⏳ Gitleaks integration
5. ⏳ Custom Python security rules
6. ⏳ Normalization + SQLite database
7. ⏳ Security Debt Engine
8. ⏳ AI reasoning layer (Claude API)
9. ⏳ Next.js Dashboard
10. ⏳ GitHub integration

## 🛠️ Tech Stack

- **Backend**: Python, FastAPI, SQLite
- **Scanners**: Semgrep, Gitleaks, Custom (AST-based)
- **AI**: Anthropic Claude API
- **Frontend**: Next.js, React, Recharts
- **Deployment**: Vercel (frontend), Python host (backend)

## 📖 API Endpoints

- `GET /health` - Health check
- `POST /api/upload` - Upload ZIP for scanning
- `POST /api/scan-repo` - Scan Git repository
- `GET /api/scans/{scan_id}` - Get scan results
- `GET /api/projects` - List projects
- `GET /api/scans/{scan_id}/findings` - Get findings
- `POST /api/github/webhook` - GitHub webhook handler

## 🎓 References

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Gitleaks GitHub](https://github.com/gitleaks/gitleaks)
- [GitHub Apps Documentation](https://docs.github.com/en/apps)
- [Anthropic Claude API](https://docs.anthropic.com/)

## 📝 License

MIT License - Built for Avishkar Industrial-Ready Hackathon

---

**Built with Antigravity IDE for rapid AI-assisted development**
