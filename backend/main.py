import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from config import settings
from database.db import init_db
from api import scan, projects, findings, github

# Configure logging
log_file = Path(settings.LOG_DIR) / "app.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup, cleanup on shutdown"""
    logger.info("Initializing database...")
    await init_db()
    logger.info("Application startup complete")
    yield
    logger.info("Application shutdown")


# Create FastAPI app
app = FastAPI(
    title="AI-Generated Code Security-Debt Scorer",
    description="Detects vulnerabilities in AI-generated code and calculates security debt score",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, prefix="/api", tags=["scan"])
app.include_router(projects.router, prefix="/api", tags=["projects"])
app.include_router(findings.router, prefix="/api", tags=["findings"])
app.include_router(github.router, prefix="/api", tags=["github"])


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "ok",
        "service": "security-debt-scorer",
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AI-Generated Code Security-Debt Scorer API",
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True
    )
