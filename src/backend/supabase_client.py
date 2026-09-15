"""
BOB Defense Threat Intelligence Platform
Supabase Cloud Authentication & Defense Analyst Store Module
"""

import os
import json
import time
import hashlib
import hmac
import secrets
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

# Password hashing helper using PBKDF2-HMAC-SHA256 with 100,000 iterations
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    derived = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, 100000)
    return derived.hex(), salt

def verify_password(password: str, password_hash: str, salt: str) -> bool:
    derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return hmac.compare_digest(derived.hex(), password_hash)

class SupabaseDefenseAuth:
    def __init__(self):
        self.supabase_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
        self.supabase_key = os.environ.get("SUPABASE_KEY", os.environ.get("SUPABASE_ANON_KEY", ""))
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Local secure in-memory and persistence fallback store
        self.local_analysts: Dict[str, Dict[str, Any]] = {}
        self._init_seed_accounts()

    def _init_seed_accounts(self):
        """Seed default high-clearance defense analyst accounts for instant demonstration."""
        seed_users = [
            {
                "email": "commander@bob-defense.mil",
                "callsign": "VANGUARD-01",
                "name": "General A. Vance",
                "clearance_level": "LEVEL-5 (TOP SECRET // SI-TK)",
                "division": "Joint Defense Command (J2/J6)",
                "password_plain": "Commander2026!"
            },
            {
                "email": "j2-intel@bob-defense.mil",
                "callsign": "SPECTRE-04",
                "name": "Col. R. Chen",
                "clearance_level": "LEVEL-4 (SECRET // REL TO FVEY)",
                "division": "Strategic Aerospace & Space EW",
                "password_plain": "Intel2026!"
            },
            {
                "email": "analyst@bob-defense.mil",
                "callsign": "CIPHER-09",
                "name": "Lt. S. Morgan",
                "clearance_level": "LEVEL-3 (CONFIDENTIAL // CYBER)",
                "division": "Defensive Cyberspace Operations (DCO)",
                "password_plain": "Cyber2026!"
            }
        ]

        for u in seed_users:
            pwd_hash, salt = hash_password(u["password_plain"])
            self.local_analysts[u["email"].lower()] = {
                "id": f"analyst-{secrets.token_hex(6)}",
                "email": u["email"].lower(),
                "callsign": u["callsign"],
                "name": u["name"],
                "clearance_level": u["clearance_level"],
                "division": u["division"],
                "password_hash": pwd_hash,
                "salt": salt,
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }

    def update_config(self, supabase_url: str, supabase_key: str):
        self.supabase_url = supabase_url.rstrip("/")
        self.supabase_key = supabase_key.strip()

    def is_supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_key and "supabase.co" in self.supabase_url)

    def register_analyst(self, data: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Registers a new defense analyst into Supabase table / Auth with local secure fallback.
        """
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        callsign = data.get("callsign", "ECHO-AGENT").strip().upper()
        name = data.get("name", "Defense Analyst").strip()
        clearance = data.get("clearance_level", "LEVEL-3 (CONFIDENTIAL // CYBER)").strip()
        division = data.get("division", "Tactical Cyber Defense Unit").strip()

        if not email or "@" not in email:
            return False, "Invalid military intelligence email address.", None
        if len(password) < 6:
            return False, "Password must be at least 6 characters.", None

        if email in self.local_analysts:
            return False, "Analyst callsign/email already registered in defense registry.", None

        pwd_hash, salt = hash_password(password)
        analyst_record = {
            "id": f"analyst-{secrets.token_hex(6)}",
            "email": email,
            "callsign": callsign,
            "name": name,
            "clearance_level": clearance,
            "division": division,
            "password_hash": pwd_hash,
            "salt": salt,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }

        # Attempt Supabase cloud insertion if configured
        if self.is_supabase_configured():
            try:
                self._supabase_insert_analyst(analyst_record)
            except Exception as e:
                print(f"[WARN] Supabase registration cloud sync error: {e}")

        # Store in local registry
        self.local_analysts[email] = analyst_record

        # Generate session
        token, user_meta = self._create_session(analyst_record)
        return True, "Analyst identity verified and registered into defense matrix.", {
            "token": token,
            "analyst": user_meta,
            "storage": "SUPABASE_CLOUD" if self.is_supabase_configured() else "DEFENSE_SECURE_LOCAL"
        }

    def login_analyst(self, email: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Authenticates defense analyst credentials via Supabase Auth or local hash store.
        """
        email_clean = email.strip().lower()
        
        # 1. Check Supabase cloud if enabled
        if self.is_supabase_configured():
            try:
                cloud_user = self._supabase_fetch_analyst(email_clean)
                if cloud_user:
                    if verify_password(password, cloud_user.get("password_hash", ""), cloud_user.get("salt", "")):
                        token, user_meta = self._create_session(cloud_user)
                        return True, "Clearance authenticated via Supabase Cloud.", {
                            "token": token,
                            "analyst": user_meta,
                            "storage": "SUPABASE_CLOUD"
                        }
            except Exception as e:
                print(f"[WARN] Supabase cloud login query fallback: {e}")

        # 2. Local Registry Verification
        if email_clean not in self.local_analysts:
            return False, "Access Denied: Unrecognized defense analyst email.", None

        user = self.local_analysts[email_clean]
        if not verify_password(password, user["password_hash"], user["salt"]):
            return False, "Access Denied: Invalid tactical credentials.", None

        token, user_meta = self._create_session(user)
        return True, "Clearance authenticated. Welcome to BOB Defense Operations.", {
            "token": token,
            "analyst": user_meta,
            "storage": "SUPABASE_CLOUD" if self.is_supabase_configured() else "DEFENSE_SECURE_LOCAL"
        }

    def _create_session(self, user: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        token = secrets.token_hex(32)
        user_meta = {
            "id": user["id"],
            "email": user["email"],
            "callsign": user["callsign"],
            "name": user["name"],
            "clearance_level": user["clearance_level"],
            "division": user["division"],
            "login_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }
        self.active_sessions[token] = {
            "user": user_meta,
            "expires_at": time.time() + 86400  # 24 Hours
        }
        return token, user_meta

    def validate_session(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token or token not in self.active_sessions:
            return None
        session = self.active_sessions[token]
        if time.time() > session["expires_at"]:
            del self.active_sessions[token]
            return None
        return session["user"]

    def logout_session(self, token: Optional[str]):
        if token and token in self.active_sessions:
            del self.active_sessions[token]

    def _supabase_insert_analyst(self, record: Dict[str, Any]):
        url = f"{self.supabase_url}/rest/v1/analysts"
        payload = {
            "email": record["email"],
            "callsign": record["callsign"],
            "name": record["name"],
            "clearance_level": record["clearance_level"],
            "division": record["division"],
            "password_hash": record["password_hash"],
            "salt": record["salt"]
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "apikey": self.supabase_key,
                "Authorization": f"Bearer {self.supabase_key}",
                "Prefer": "return=minimal"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status in (200, 201, 204)

    def _supabase_fetch_analyst(self, email: str) -> Optional[Dict[str, Any]]:
        url = f"{self.supabase_url}/rest/v1/analysts?email=eq.{urllib.parse.quote(email)}&select=*"
        req = urllib.request.Request(
            url,
            headers={
                "apikey": self.supabase_key,
                "Authorization": f"Bearer {self.supabase_key}"
            },
            method="GET"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            items = json.loads(res_body)
            if isinstance(items, list) and len(items) > 0:
                return items[0]
        return None

# Global Instance
supabase_auth = SupabaseDefenseAuth()
