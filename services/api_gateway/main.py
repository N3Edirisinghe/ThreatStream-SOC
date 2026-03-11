"""
SOC Platform — API Gateway
Main FastAPI application: auth, alerts, incidents, metrics, rules.
"""
import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base
from routers import auth, alerts, incidents, metrics, rules, playbooks, simulate
from alert_consumer import consume_alerts

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (idempotent — SQL schema already handles this)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Start Alert Consumer in background
    kafka_servers = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
    asyncio.create_task(consume_alerts(kafka_servers))
    
    yield

app = FastAPI(
    title="SOC Platform API",
    version="1.0.0",
    description="Autonomous SOC Simulation Platform — REST API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router,      prefix="/api/v1/auth",      tags=["Auth"])
app.include_router(alerts.router,    prefix="/api/v1/alerts",    tags=["Alerts"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents"])
app.include_router(metrics.router,   prefix="/api/v1/metrics",   tags=["Metrics"])
app.include_router(rules.router,     prefix="/api/v1/rules",     tags=["Rules"])
app.include_router(playbooks.router, prefix="/api/v1/playbooks", tags=["Playbooks"])
app.include_router(simulate.router,  prefix="/api/v1/simulate",  tags=["Simulation"])

@app.get("/health")
async def health():
    return {"status": "ok", "service": "api-gateway"}
