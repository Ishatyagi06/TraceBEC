"""phisGuard Backend Application Server.

FastAPI orchestration layer for:
- Digital email forensic analysis
- Linguistic BEC detection
- Multimodal evidence fusion
- Research experiment tracking & dataset profiling
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1.analyze import router as analyze_router
from app.api.v1.datasets import router as datasets_router
from app.api.v1.experiments import router as experiments_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.campaigns import router as campaigns_router
from app.api.v1.origin_map import router as origin_map_router


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Research-Oriented BEC Detection & Digital Email Forensics Platform",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1 Routers
api_v1_prefix = settings.api_v1_str
app.include_router(analyze_router, prefix=api_v1_prefix)
app.include_router(datasets_router, prefix=api_v1_prefix)
app.include_router(experiments_router, prefix=api_v1_prefix)
app.include_router(investigations_router, prefix=api_v1_prefix)
app.include_router(campaigns_router, prefix=api_v1_prefix)
app.include_router(origin_map_router, prefix=api_v1_prefix)


@app.get("/")
def root():
    return {
        "platform": settings.app_name,
        "version": settings.version,
        "status": "online",
        "api_v1_docs": "/docs",
        "retention_mode": settings.retention_mode
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
