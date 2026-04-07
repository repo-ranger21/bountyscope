from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import get_settings
from backend.routers import scope, scanner, targets

settings = get_settings()

app = FastAPI(
    title="BountyScope API",
    description="WordPress Bug Bounty Research Workstation — @lucius-log",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scope.router,   prefix="/api")
app.include_router(scanner.router, prefix="/api")
app.include_router(targets.router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "researcher": "@lucius-log"}
