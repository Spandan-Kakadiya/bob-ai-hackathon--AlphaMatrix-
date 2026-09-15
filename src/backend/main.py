"""
BOB Defense Threat Intelligence Platform
FastAPI Production Backend Server
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load environment variables from .env if present
env_file = PROJECT_ROOT / ".env"
if env_file.exists():
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from backend.engine.mitre_mapper import MitreMapper
from backend.engine.correlator import ThreatCorrelator
from backend.engine.bluf_generator import BLUFGenerator
from backend.engine.feed_simulator import get_initial_seed_alerts, generate_random_alert
from backend.security import (
    sanitize_input_string, sanitize_alert_payload, 
    check_rate_limit, generate_analyst_session_token
)

app = FastAPI(
    title="BOB Defense Threat Intelligence Platform",
    description="Multi-Source Threat Correlation, MITRE ATT&CK Mapping & BLUF Generation System",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Initialize Core Defense Engines
mitre_mapper = MitreMapper()
correlator = ThreatCorrelator(mitre_mapper)
# Initial API key configuration from environment variable
api_key = os.environ.get("OPENAI_API_KEY", "")
bluf_generator = BLUFGenerator(api_key=api_key)

# Seed initial threat environment
seed_data = get_initial_seed_alerts()
for raw_alert in seed_data:
    correlator.ingest_and_process_alert(raw_alert)

# Security Middleware for Defense Headers
@app.middleware("http")
async def add_security_headers_and_rate_limit(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    # Rate limit check on API endpoints
    if request.url.path.startswith("/api/"):
        if not check_rate_limit(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Rate limit exceeded. Too many intelligence telemetry requests."}
            )

    response = await call_next(request)
    
    # Defense-grade HTTP security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: https:; connect-src 'self' https://api.openai.com;"
    )
    return response

from backend.supabase_client import supabase_auth

# Security Dependency for Protected Intelligence Endpoints
def require_authenticated_analyst(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    
    analyst = supabase_auth.validate_session(token)
    if not analyst:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access Denied: You must register clearance and login to access defense intelligence."
        )
    return analyst

def apply_clearance_redaction(item_dict: Dict[str, Any], clearance: str) -> Dict[str, Any]:
    """
    Redacts sensitive defense intelligence based on analyst clearance.
    Level 5: Full access.
    Level 4: Redacts Top Secret C2 strike keys.
    Level 3: Redacts Space RF telemetry coordinates & Top Secret BLUF judgments.
    """
    redacted = dict(item_dict)
    is_level_5 = "LEVEL-5" in clearance.upper()
    is_level_4 = "LEVEL-4" in clearance.upper() or is_level_5

    if not is_level_4:
        # Level 3 Confidential Cyber Analyst
        if "source_type" in redacted and redacted["source_type"] == "SATELLITE":
            redacted["description"] = "[REDACTED // REQUIRES LEVEL-4+ SPACE/EW CLEARANCE]"
            redacted["source_ip_or_coord"] = "[CLASSIFIED ORBIT]"
        if "bottom_line_up_front" in redacted:
            redacted["rules_of_engagement_impact"] = "[REDACTED // LEVEL-5 COMMANDER CLEARANCE REQUIRED]"
        if "affected_assets" in redacted:
            redacted["affected_assets"] = [
                a if "SATCOM" not in a else "[CLASSIFIED SATCOM C2 RELAY]" 
                for a in redacted["affected_assets"]
            ]
    elif not is_level_5:
        # Level 4 Secret Intel Officer
        if "rules_of_engagement_impact" in redacted:
            redacted["rules_of_engagement_impact"] = "[CLASSIFIED // LEVEL-5 AUTHORIZATION REQUIRED]"

    return redacted

# Schemas
class AlertIngestRequest(BaseModel):
    source_type: str = Field(default="CYBER", description="SIEM, SATELLITE, CYBER, INTEL")
    source_feed: str = Field(default="Manual-Analyst-Entry")
    severity: str = Field(default="HIGH")
    title: str = Field(..., max_length=500)
    description: str = Field(default="", max_length=5000)
    target_asset: str = Field(default="COMMAND-POST-PRIMARY")
    source_ip_or_coord: str = Field(default="Unknown")
    tags: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.85, ge=0.0, le=1.0)

class BLUFGenerateRequest(BaseModel):
    cluster_id: str

class AICopilotRequest(BaseModel):
    question: str = Field(..., max_length=1000)
    cluster_id: Optional[str] = None

class IncidentMitigateRequest(BaseModel):
    cluster_id: str
    action_type: str = Field(default="ISOLATE_ASSET") # ISOLATE_ASSET, COUNTER_EW, REVOKE_TOKENS

class LLMConfigRequest(BaseModel):
    api_key: str

class AnalystRegisterRequest(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=6, max_length=128)
    callsign: str = Field(default="ECHO-01", max_length=50)
    name: str = Field(default="Defense Analyst", max_length=100)
    clearance_level: str = Field(default="LEVEL-3 (CONFIDENTIAL // CYBER)")
    division: str = Field(default="Defensive Cyberspace Operations")

class AnalystLoginRequest(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., max_length=128)

class SupabaseConfigRequest(BaseModel):
    supabase_url: str
    supabase_key: str

# Authentication Endpoints
@app.post("/api/auth/register")
async def register_analyst(payload: AnalystRegisterRequest):
    clean_data = {
        "email": sanitize_input_string(payload.email.strip().lower()),
        "password": payload.password,
        "callsign": sanitize_input_string(payload.callsign.strip().upper()),
        "name": sanitize_input_string(payload.name.strip()),
        "clearance_level": sanitize_input_string(payload.clearance_level.strip()),
        "division": sanitize_input_string(payload.division.strip())
    }
    success, msg, data = supabase_auth.register_analyst(clean_data)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "REGISTERED", "message": msg, "session": data}

@app.post("/api/auth/login")
async def login_analyst(payload: AnalystLoginRequest):
    success, msg, data = supabase_auth.login_analyst(payload.email, payload.password)
    if not success:
        raise HTTPException(status_code=401, detail=msg)
    return {"status": "AUTHENTICATED", "message": msg, "session": data}

@app.get("/api/auth/me")
async def get_current_analyst(request: Request):
    analyst = require_authenticated_analyst(request)
    return {"status": "ACTIVE", "analyst": analyst, "supabase_synced": supabase_auth.is_supabase_configured()}

@app.post("/api/auth/logout")
async def logout_analyst(request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split(" ", 1)[1].strip() if "Bearer " in auth_header else None
    supabase_auth.logout_session(token)
    return {"status": "LOGGED_OUT"}

@app.post("/api/config/supabase")
async def configure_supabase(payload: SupabaseConfigRequest, request: Request):
    require_authenticated_analyst(request)
    clean_url = sanitize_input_string(payload.supabase_url.strip())
    clean_key = sanitize_input_string(payload.supabase_key.strip())
    supabase_auth.update_config(clean_url, clean_key)
    return {
        "status": "CONFIGURED",
        "supabase_connected": supabase_auth.is_supabase_configured(),
        "message": "Supabase credentials updated successfully."
    }

@app.get("/api/config/supabase/status")
async def get_supabase_status(request: Request):
    require_authenticated_analyst(request)
    return {
        "supabase_url": supabase_auth.supabase_url or "Not Configured (Using Local Secure Vault)",
        "is_configured": supabase_auth.is_supabase_configured()
    }

# Protected Intelligence Endpoints
@app.get("/api/stats")
async def get_dashboard_stats(request: Request):
    analyst = require_authenticated_analyst(request)
    stats = correlator.get_stats()
    stats["analyst_clearance"] = analyst.get("clearance_level", "LEVEL-3")
    return stats

@app.get("/api/alerts")
async def get_alerts(request: Request, source: Optional[str] = None, genuine_only: bool = False, limit: int = 50):
    analyst = require_authenticated_analyst(request)
    clearance = analyst.get("clearance_level", "LEVEL-3")
    
    alerts = correlator.active_alerts
    if genuine_only:
        alerts = [a for a in alerts if not a.is_false_positive]
    if source and source.upper() != "ALL":
        alerts = [a for a in alerts if a.source_type.upper() == source.upper()]
        
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]
    return [apply_clearance_redaction(a.to_dict(), clearance) for a in sorted_alerts]

@app.post("/api/alerts/ingest")
async def ingest_alert(payload: AlertIngestRequest, request: Request):
    analyst = require_authenticated_analyst(request)
    clean_dict = sanitize_alert_payload(payload.model_dump())
    clean_dict["source_feed"] = f"Analyst-{analyst.get('callsign', 'OPS')}"
    alert = correlator.ingest_and_process_alert(clean_dict)
    return {
        "status": "INGESTED",
        "alert_id": alert.id,
        "is_false_positive": alert.is_false_positive,
        "fp_reason": alert.fp_reason,
        "mitre_tactics": alert.mitre_tactics,
        "mitre_techniques": alert.mitre_techniques
    }

@app.get("/api/clusters")
async def get_threat_clusters(request: Request):
    analyst = require_authenticated_analyst(request)
    clearance = analyst.get("clearance_level", "LEVEL-3")
    clusters = list(correlator.threat_clusters.values())
    sorted_clusters = sorted(clusters, key=lambda c: c.confidence_score, reverse=True)
    return [apply_clearance_redaction(c.to_dict(), clearance) for c in sorted_clusters]

@app.get("/api/clusters/{cluster_id}")
async def get_cluster_detail(cluster_id: str, request: Request):
    analyst = require_authenticated_analyst(request)
    clearance = analyst.get("clearance_level", "LEVEL-3")
    cluster = correlator.threat_clusters.get(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Threat cluster not found")
    return apply_clearance_redaction(cluster.to_dict(), clearance)

@app.post("/api/clusters/mitigate")
async def mitigate_cluster(req: IncidentMitigateRequest, request: Request):
    analyst = require_authenticated_analyst(request)
    cluster = correlator.threat_clusters.get(req.cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Threat cluster not found")
    
    # Apply containment action
    cluster.kill_chain_phase = f"CONTAINED ({req.action_type} by {analyst.get('callsign', 'COMMAND')})"
    cluster.severity = "CONTAINED"
    return {
        "status": "MITIGATED",
        "cluster_id": cluster.cluster_id,
        "new_phase": cluster.kill_chain_phase,
        "action_taken": req.action_type,
        "authorized_by": analyst.get("callsign")
    }

@app.get("/api/clusters/{cluster_id}/stix")
async def get_cluster_stix_bundle(cluster_id: str, request: Request):
    require_authenticated_analyst(request)
    cluster = correlator.threat_clusters.get(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Threat cluster not found")
    return bluf_generator.export_stix_bundle(cluster)

@app.get("/api/mitre/matrix")
async def get_mitre_matrix(request: Request):
    require_authenticated_analyst(request)
    technique_counts: Dict[str, int] = {}
    for alert in correlator.active_alerts:
        if not alert.is_false_positive:
            for tech in alert.mitre_techniques:
                technique_counts[tech] = technique_counts.get(tech, 0) + 1
                
    return mitre_mapper.get_full_matrix_state(technique_counts)

@app.post("/api/bluf/generate")
async def generate_bluf(req: BLUFGenerateRequest, request: Request):
    analyst = require_authenticated_analyst(request)
    clearance = analyst.get("clearance_level", "LEVEL-3")
    cluster = correlator.threat_clusters.get(req.cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail=f"Threat cluster {req.cluster_id} not found")
        
    report = bluf_generator.generate_bluf_brief(cluster)
    return apply_clearance_redaction(report.to_dict(), clearance)

@app.post("/api/ai/ask")
async def ask_ai_copilot(req: AICopilotRequest, request: Request):
    analyst = require_authenticated_analyst(request)
    clean_query = sanitize_input_string(req.question.strip())
    if not clean_query:
        raise HTTPException(status_code=400, detail="Question cannot be empty")
    
    cluster = None
    if req.cluster_id:
        cluster = correlator.threat_clusters.get(req.cluster_id)
    all_clusters = list(correlator.threat_clusters.values())
    
    answer_data = bluf_generator.ask_copilot(
        f"Analyst Clearance [{analyst.get('clearance_level')}]: {clean_query}", 
        cluster=cluster, 
        all_clusters=all_clusters
    )
    return answer_data

@app.post("/api/simulate/tick")
async def simulate_incoming_telemetry_batch(request: Request):
    require_authenticated_analyst(request)
    new_alerts = []
    for _ in range(3):
        raw = generate_random_alert()
        alert = correlator.ingest_and_process_alert(raw)
        new_alerts.append(alert.to_dict())
    return {
        "ingested_count": len(new_alerts),
        "alerts": new_alerts,
        "current_stats": correlator.get_stats()
    }

@app.post("/api/config/llm")
async def configure_llm(req: LLMConfigRequest):
    clean_key = sanitize_input_string(req.api_key.strip())
    if not clean_key.startswith("sk-"):
        raise HTTPException(status_code=400, detail="Invalid API key format")
    bluf_generator.set_api_key(clean_key)
    return {"status": "CONFIGURED", "message": "OpenAI LLM synthesis engine activated safely."}

@app.get("/api/health")
@app.get("/api/ping")
async def health_check():
    return {
        "status": "HEALTHY",
        "platform": "PROJECT BOB Defense Intelligence",
        "version": "1.0.0",
        "active_clusters": len(correlator.threat_clusters),
        "total_alerts": len(correlator.active_alerts)
    }

# Mount Frontend Static Assets
POSSIBLE_FRONTEND_DIRS = [
    PROJECT_ROOT / "frontend",
    PROJECT_ROOT / "public",
    Path("frontend"),
    Path("public"),
    Path(__file__).resolve().parent.parent / "frontend",
    Path(__file__).resolve().parent.parent / "public"
]

FRONTEND_DIR = None
for candidate in POSSIBLE_FRONTEND_DIRS:
    if candidate.exists() and (candidate / "index.html").exists():
        FRONTEND_DIR = candidate
        break

if FRONTEND_DIR and FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
async def serve_index():
    if FRONTEND_DIR:
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
    return {"status": "BOB Defense Backend Operational", "platform": "PROJECT BOB"}

@app.get("/styles.css")
async def serve_styles():
    if FRONTEND_DIR:
        styles_file = FRONTEND_DIR / "styles.css"
        if styles_file.exists():
            return FileResponse(str(styles_file), media_type="text/css")
    raise HTTPException(status_code=404, detail="styles.css not found")

@app.get("/app.js")
async def serve_app_js():
    if FRONTEND_DIR:
        app_js_file = FRONTEND_DIR / "app.js"
        if app_js_file.exists():
            return FileResponse(str(app_js_file), media_type="application/javascript")
    raise HTTPException(status_code=404, detail="app.js not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
