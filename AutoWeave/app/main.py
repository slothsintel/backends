import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import router as api_router

app = FastAPI(title="AutoWeave API", version="0.1.0")

# CORS: allow your static site to call this API from the browser.
# You can tighten later.
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "https://autoweave.slothsintel.com,http://localhost:5173,http://localhost:5500",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "service": "autoweave_backend",
        "ok": True,
        "docs": "/docs",
        "health": "/health",
        "merge": "/api/v1/merge/autotrac",
    }

@app.get("/health")
def health():
    return {"ok": True}

app.include_router(api_router, prefix="/api/v1")
