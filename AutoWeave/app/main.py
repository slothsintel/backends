from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import router as api_router

app = FastAPI(title="AutoWeave API", version="0.1.0")

# IMPORTANT: set to your real frontend origins
allowed_origins = [
    "https://autoweave.slothsintel.com",
    "http://localhost:5173",
    "http://localhost:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

app.include_router(api_router, prefix="/api/v1")
