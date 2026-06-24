# CyberShield v2 — AI Cybersecurity Platform
## Complete Setup Guide

---

## What's Built

**Backend:** Django 4.2 + Django REST Framework + JWT authentication  
**Frontend:** React 18 + Vite + Tailwind CSS  
**ML Model:** XGBoost + LightGBM + CatBoost soft-voting ensemble  
**Dataset:** 1.58M URLs (original 651k + 789k live phishing + 154k malware hosts, 2024)  
**Accuracy:** 94.57% · F1: 94.62% · AUC: 99.37% · Malware Recall: 97.56% · Phishing Recall: 92.34%  

---

## One-Time Setup (15 minutes)

### 1. Install Python dependencies
```bash
cd cybershield
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Linux only (for QR decoding):
sudo apt-get install -y libzbar0
# macOS only:
brew install zbar
```

### 2. Set up database
```bash
python manage.py migrate
python manage.py createsuperuser
# → enter: admin / admin123
```

### 3. Install React dependencies
```bash
cd ../cybershield-ui
npm install
```

### 4. (Optional) Add Threat Intelligence API keys
Copy `.env.example` to `.env` and fill in keys for:
| Service | Free Tier | Register |
|---------|-----------|----------|
| VirusTotal | 500 req/day | virustotal.com/gui/join-us |
| Google Safe Browsing | 10k req/day | developers.google.com/safe-browsing |
| AbuseIPDB | 1k req/day | abuseipdb.com/register |
| URLScan.io | 100/hour | urlscan.io/user/signup |
| PhishTank | Free | phishtank.com/api_info.php |

**The platform works fully without API keys.** ML model runs completely offline.

---

## Running the Platform

### Option A — One command (Linux/macOS)
```bash
cd cybershield
bash start.sh
```

### Option B — Two terminals

**Terminal 1 — Django API:**
```bash
cd cybershield
source venv/bin/activate
python manage.py runserver 8000
```

**Terminal 2 — React UI:**
```bash
cd cybershield-ui
npm run dev
```

Open **http://localhost:5173** in your browser.  
Login with: `admin` / `admin123`

---

## Project Structure

```
cybershield/                      ← Django backend
├── cybershield/
│   ├── settings.py               ← All config (DRF, JWT, CORS, ML paths)
│   └── urls.py                   ← REST API routes
├── security/
│   ├── models.py                 ← URLScan, QRScan, ScanReport
│   ├── api_views.py              ← All DRF API endpoints
│   └── serializers.py            ← JSON serialization
├── ml_engine/
│   ├── feature_extractor.py      ← 45 URL features (DGA, entropy, TLD risk…)
│   ├── predictor.py              ← Load model + predict with whitelist correction
│   ├── ensemble.py               ← Ensemble class (importable for joblib)
│   └── saved_models/             ← Trained XGB+LGB+CAT model files
├── threat_intel/
│   ├── virustotal.py             ← 90+ AV engines
│   ├── google_safebrowsing.py    ← Google threat DB
│   ├── phishtank.py              ← Phishing DB
│   ├── abuseipdb.py              ← IP reputation
│   ├── urlscan_io.py             ← Live sandbox
│   └── aggregator.py             ← Weighted risk score formula
├── qr_scanner/decoder.py         ← Multi-strategy QR decoding
├── dataset/
│   ├── malicious_phish.csv       ← 651k original URLs (2021)
│   ├── phishing_active.txt       ← 789k live phishing (2024)
│   ├── blacklist_hosts.txt       ← 154k malware hosts (2024)
│   └── combined_dataset.csv      ← 1.58M merged & deduped
├── scripts/train_model.py        ← Full retraining pipeline
└── requirements.txt

cybershield-ui/                   ← React frontend
├── src/
│   ├── api/client.js             ← Axios + JWT auto-refresh
│   ├── components/
│   │   ├── Layout.jsx            ← Sidebar navigation
│   │   ├── RiskGauge.jsx         ← Animated score circle
│   │   ├── ThreatBadge.jsx       ← Color-coded threat badge
│   │   └── ProtectedRoute.jsx    ← Auth guard
│   ├── pages/
│   │   ├── Login.jsx             ← JWT login form
│   │   ├── Signup.jsx            ← User registration
│   │   ├── Dashboard.jsx         ← Stats + live charts
│   │   ├── URLScanner.jsx        ← Full scan interface
│   │   ├── QRScanner.jsx         ← Drag-drop QR upload
│   │   ├── History.jsx           ← Filterable scan table
│   │   ├── Analytics.jsx         ← Recharts analytics
│   │   └── Report.jsx            ← Full report detail
│   └── App.jsx                   ← React Router setup
└── tailwind.config.js            ← Dark cyber theme tokens
```

---

## REST API Reference

All endpoints require: `Authorization: Bearer <access_token>`

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/token/` | Login → get JWT tokens |
| POST | `/api/token/refresh/` | Refresh access token |
| POST | `/api/auth/signup/` | Register new user |
| POST | `/api/scan/url/` | Scan a URL |
| POST | `/api/scan/qr/` | Scan QR image(s) |
| GET | `/api/history/` | Scan history (filter: ?q=&level=) |
| DELETE | `/api/history/<id>/` | Delete a scan |
| GET | `/api/report/<id>/` | Full scan report |
| GET | `/api/analytics/` | Stats + chart data |

---

## Retrain on Full Dataset

```bash
cd cybershield
source venv/bin/activate
python scripts/train_model.py
# Trains on 1.58M URLs (sample_size=250_000 by default, ~5 min)
# Edit train_model.py → main(sample_size=None) for full dataset (~25 min)
```

---

## Admin Panel
http://localhost:8000/admin/  
Username: `admin` | Password: `admin123`

---

## Troubleshooting

**`pyzbar` not found:**
```bash
sudo apt-get install libzbar0  # Linux
brew install zbar              # macOS
pip install pyzbar
```

**Model files missing:**
```bash
python scripts/train_model.py
```

**React can't reach Django:**
Make sure Django is on port 8000, React on 5173.
The Vite proxy `/api → http://localhost:8000` handles CORS automatically.
