import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Deque, Dict, Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from routes.chatbot import router as chatbot_router
from routes.compliance import router as compliance_router
from routes.detectors import router as detectors_router
from routes import deepfake_pipeline
from routes.utils import sanitize_for_json

# ── Environment-aware logging ──
APP_ENV = os.getenv("APP_ENV", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG" if APP_ENV == "development" else "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("veyron-backend")

@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("Starting Veyron backend (env=%s, log_level=%s)", APP_ENV, LOG_LEVEL)
    logger.info("CORS origins: %s", settings.origins)
    logger.info(
        "API keys: Gemini=%s, VirusTotal=%s, SafeBrowsing=%s, HIBP=%s",
        "configured" if settings.gemini_api_key else "MISSING",
        "configured" if settings.virustotal_api_key else "MISSING",
        "configured" if settings.safe_browsing_api_key else "MISSING",
        "configured" if settings.hibp_api_key else "MISSING",
    )
    logger.info(
        "[Deepfake Startup Audit] deepfake_pipeline_path=%s mediapipe_initialized=%s tasks_vision_active=%s startup_info=%s",
        getattr(deepfake_pipeline, "__file__", "unknown"),
        deepfake_pipeline.mp_startup_info.get("detector_init", False),
        deepfake_pipeline.mp_startup_info.get("api") == "tasks_vision",
        deepfake_pipeline.mp_startup_info,
    )
    
    # Preload classifier models in background thread to avoid blocking server startup
    import threading
    threading.Thread(target=deepfake_pipeline.preload_models, daemon=True, name="model-preload").start()
        
    yield


class SanitizedJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return super().render(sanitize_for_json(content))

app = FastAPI(
    title="Veyron Cyber Safety Backend", 
    version="1.0.0", 
    lifespan=lifespan,
    default_response_class=SanitizedJSONResponse
)

# Inject explicit Vite dynamic ports as requested
dev_origins = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:5174",
    "http://localhost:5174",
    "http://127.0.0.1:5175",
    "http://localhost:5175",
]
all_origins = list(set(settings.origins + dev_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=all_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RATE_LIMIT = 100
WINDOW_SECONDS = 60
EXPENSIVE_ENDPOINT_LIMITS = {
    "/api/detect-deepfake": 20,
    "/api/scan-link": 40,
    "/api/chat": 60,
}
ip_hits: Dict[str, Deque[float]] = defaultdict(deque)


@app.middleware("http")
async def log_and_rate_limit(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 55 * 1024 * 1024:
        logger.warning("Rejected payload of size %s bytes from %s", content_length, ip)
        return JSONResponse(status_code=413, content={"detail": "Payload too large"})

    if settings.backend_api_key and path in EXPENSIVE_ENDPOINT_LIMITS:
        supplied = request.headers.get("x-api-key", "").strip()
        if supplied != settings.backend_api_key:
            logger.warning("Unauthorized access attempt to %s from %s", path, ip)
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid API key for this endpoint."},
            )

    now = time.time()
    bucket = f"{ip}:{path if path in EXPENSIVE_ENDPOINT_LIMITS else '*'}"
    dq = ip_hits[bucket]
    while dq and (now - dq[0]) > WINDOW_SECONDS:
        dq.popleft()
    limit = EXPENSIVE_ENDPOINT_LIMITS.get(path, RATE_LIMIT)
    if len(dq) >= limit:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please retry shortly.", "path": path},
        )
    dq.append(now)

    started = time.time()
    response = await call_next(request)
    elapsed = (time.time() - started) * 1000
    logger.info("%s %s %s %.2fms", request.method, request.url.path, response.status_code, elapsed)

    # Security headers (production hardening)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.exception_handler(ValueError)
async def value_error_handler(_: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def generic_error_handler(_: Request, exc: Exception):
    logger.exception("Unhandled server error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health")
def health():
    return {"status": "ok", "service": "veyron-backend"}


try:
    app.include_router(chatbot_router, prefix="/api")
    app.include_router(detectors_router, prefix="/api")
    app.include_router(compliance_router, prefix="/api")
except Exception:
    logger.exception("Route registration failed")
    raise


if __name__ == "__main__":
    logger.info("Launching Uvicorn server from main.py")
    try:
        uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
    except Exception:
        logger.exception("Server failed to start")
        raise
