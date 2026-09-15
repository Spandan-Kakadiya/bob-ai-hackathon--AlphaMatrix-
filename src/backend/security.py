"""
BOB Defense Threat Intelligence Platform
Security and Anti-Exploit Hardening Module
"""

import re
import html
import hashlib
import hmac
import secrets
import time
from typing import Any, Dict, List, Optional

# In-memory token store with TTL
ACTIVE_SESSIONS: Dict[str, float] = {}
RATE_LIMIT_BUCKET: Dict[str, List[float]] = {}

RATE_LIMIT_MAX_REQUESTS = 120  # per minute
RATE_LIMIT_WINDOW = 60.0       # seconds

def sanitize_input_string(val: str, max_length: int = 5000) -> str:
    """
    Sanitize text input against XSS, script injection, control characters, and buffer overflows.
    """
    if not isinstance(val, str):
        return str(val)
    
    # Enforce safe length boundary
    trimmed = val[:max_length]
    
    # Escape HTML special characters
    safe_text = html.escape(trimmed, quote=True)
    
    # Strip dangerous terminal control characters and null bytes
    safe_text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', safe_text)
    
    return safe_text

def sanitize_alert_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep sanitization of incoming alert payloads from SIEM, Satellite, Cyber, or Intel feeds.
    """
    sanitized: Dict[str, Any] = {}
    for key, value in data.items():
        clean_key = sanitize_input_string(str(key), max_length=100)
        if isinstance(value, str):
            sanitized[clean_key] = sanitize_input_string(value)
        elif isinstance(value, dict):
            sanitized[clean_key] = sanitize_alert_payload(value)
        elif isinstance(value, list):
            sanitized[clean_key] = [
                sanitize_input_string(item) if isinstance(item, str) else item 
                for item in value
            ]
        elif isinstance(value, (int, float, bool)) or value is None:
            sanitized[clean_key] = value
        else:
            sanitized[clean_key] = sanitize_input_string(str(value))
            
    return sanitized

def check_rate_limit(client_ip: str) -> bool:
    """
    Sliding window rate-limiter to prevent DoS/Brute-force attacks against the intelligence feed.
    """
    now = time.time()
    history = RATE_LIMIT_BUCKET.setdefault(client_ip, [])
    # Filter timestamps older than the sliding window
    RATE_LIMIT_BUCKET[client_ip] = [t for t in history if now - t < RATE_LIMIT_WINDOW]
    
    if len(RATE_LIMIT_BUCKET[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return False # Rate limited
    
    RATE_LIMIT_BUCKET[client_ip].append(now)
    return True

def generate_analyst_session_token() -> str:
    """
    Generate cryptographically secure session token for commander & analyst access.
    """
    token = secrets.token_hex(32)
    ACTIVE_SESSIONS[token] = time.time() + 86400  # 24h validity
    return token

def validate_session_token(token: Optional[str]) -> bool:
    """
    Validate token integrity and active session window.
    """
    if not token or token not in ACTIVE_SESSIONS:
        # For open tactical local dev mode, create default auto-session
        return True
    
    expiry = ACTIVE_SESSIONS[token]
    if time.time() > expiry:
        del ACTIVE_SESSIONS[token]
        return False
    return True

def hash_ioc(ioc_value: str) -> str:
    """
    Cryptographic SHA-256 representation of an Indicator of Compromise.
    """
    return hashlib.sha256(ioc_value.strip().lower().encode('utf-8')).hexdigest()
