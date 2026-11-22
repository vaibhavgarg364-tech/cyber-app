# Veyron - Cyber Safety Platform

Veyron is a comprehensive cyber safety platform with AI-powered threat detection, malware scanning, deepfake detection, and India-focused complaint/resource management.

## 🏠 Run Locally (Development)

### Prerequisites
- Python 3.11+
- `pip`

### Setup
1. Go to backend:
   - `cd backend`
2. Create environment file:
   - Copy `.env.example` to `.env`
   - Fill API keys (`GEMINI_API_KEY`, `SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`)
3. Install dependencies:
   - `python -m venv .venv`
   - Windows: `.venv\Scripts\activate`
   - Linux/macOS: `source .venv/bin/activate`
   - `pip install -r requirements.txt`
4. Start backend:
   - `uvicorn main:app --host 0.0.0.0 --port 8000 --reload`

### Verify
- Health: [http://localhost:8000/health](http://localhost:8000/health)
- Swagger docs: [http://localhost:8000/docs](http://localhost:8000/docs)

### Deepfake debug images
Deepfake debug image storage is disabled by default, so normal analysis does not save uploaded or derived images. For local debugging only, explicitly set `VEYRON_DEBUG_FACES=true` in `backend/.env`. This writes intermediate images and heatmaps under `debug_outputs/` for inspection; successful debug artifacts are retained until you remove them. If analysis fails, artifacts created by that operation are removed. Uploaded and downloaded processing files are temporary and are cleaned up after analysis. Do not enable this option in production.

## (Optional) Run with Docker

### Prerequisites
- Docker Engine + Docker Compose plugin

### One-command deployment
From repo root:
- `chmod +x deploy.sh`
- `./deploy.sh`

The script will:
- Check Docker and Compose availability
- Pull latest Git code (if repo exists)
- Build and run with `docker compose up -d --build`

### Manual Docker command
From repo root:
- `docker compose up -d --build`

### Service endpoint
- Frontend: [http://localhost](http://localhost)
- Backend: [http://localhost:8000](http://localhost:8000)

## 3) How to Test Core Endpoints

Use Swagger UI (`/docs`) or `curl`.

### Health
`GET /health`

### CyberSaathi Chatbot
`POST /api/chat`
```json
{
  "message": "Mujhe online scam call aaya, kya karun?",
  "history": []
}
```

### Email Breach Checker
`POST /api/check-email`
```json
{"email": "user@example.com"}
```

### Link Scanner
`POST /api/scan-link`
```json
{"url": "https://example.com"}
```

### App Authenticity
`POST /api/check-app`
```json
{"appName": "UMANG", "packageName": "in.gov.umang.negd.g2c"}
```

### Helplines Hub
`POST /api/get-helplines`
```json
{"incidentType": "upi_fraud", "userState": "Maharashtra"}
```

### Browser Extension Fast Check
`POST /api/extension/check-site`
```json
{"url": "https://example.com"}
```

## 4) Judge Quick Start

1. Clone repository.
2. Add API keys in `backend/.env` (copy from `backend/.env.example`).
3. Run:
   - `chmod +x deploy.sh && ./deploy.sh`
4. Open:
   - [http://localhost:8000/docs](http://localhost:8000/docs)
5. Run sample requests from this README.

This is sufficient for live demo and endpoint evaluation during hackathon judging.

## Production HTTPS

For domain-based HTTPS deployment, see `PRODUCTION.md`.

Quick command:
- `./setup-prod.sh example.com`
