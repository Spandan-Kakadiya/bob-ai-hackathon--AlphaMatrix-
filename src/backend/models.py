"""
BOB Defense Threat Intelligence Platform
Data Schemas and Type Definitions
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import uuid

def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _today_str():
    return datetime.now(timezone.utc).strftime('%Y%m%d')

@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=_now_iso)
    source_type: str = "CYBER"  # SIEM, SATELLITE, CYBER, INTEL
    source_feed: str = "Zeek-IDS"
    severity: str = "HIGH"      # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str = ""
    description: str = ""
    raw_payload: str = ""
    target_asset: str = "Command-Post-GW"
    source_ip_or_coord: str = "192.168.1.1"
    destination_ip_or_coord: str = "10.0.4.12"
    confidence_score: float = 0.85
    is_false_positive: bool = False
    fp_reason: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)  # e.g., ["T1059.001", "T1078"]
    geo_location: Optional[Dict[str, Any]] = None # {"lat": 34.55, "lon": 43.12, "region": "Sector 4"}
    ioc_hashes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ThreatCluster:
    cluster_id: str = field(default_factory=lambda: f"INC-{str(uuid.uuid4())[:6].upper()}")
    name: str = ""
    threat_actor: str = "UNKNOWN-APT"
    campaign: str = "Operation Nightfall"
    severity: str = "CRITICAL"
    confidence_score: float = 0.92
    first_seen: str = ""
    last_seen: str = ""
    alert_ids: List[str] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    mitre_tactics_covered: List[str] = field(default_factory=list)
    mitre_techniques_covered: List[str] = field(default_factory=list)
    kill_chain_phase: str = "Execution -> Command & Control"
    false_positives_filtered: int = 0
    raw_alert_count: int = 0
    status: str = "ACTIVE_INVESTIGATION" # ACTIVE_INVESTIGATION, CONTAINED, ESCALATED, ARCHIVED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class BLUFReport:
    report_id: str = field(default_factory=lambda: f"BLUF-{_today_str()}-{str(uuid.uuid4())[:4].upper()}")
    timestamp: str = field(default_factory=_now_iso)
    cluster_id: str = ""
    classification_level: str = "SECRET // NOFORN"
    threat_level: str = "CRITICAL"
    confidence_assessment: str = "HIGH (94% Multi-Source Correlation)"
    
    # Core BLUF Sections
    bluf_headline: str = ""
    bottom_line_up_front: str = ""
    key_judgments: List[str] = field(default_factory=list)
    incident_timeline: List[Dict[str, str]] = field(default_factory=list)
    attributed_threat_actor: str = "UNC2544 / APT-COSMIC"
    attack_vector_summary: str = ""
    mitre_matrix_summary: List[Dict[str, str]] = field(default_factory=list)
    tactical_impact: List[str] = field(default_factory=list)
    recommended_commander_actions: List[Dict[str, str]] = field(default_factory=list)
    rules_of_engagement_impact: str = "Immediate cyber quarantine & satellite uplink re-route permitted under ROE Annex C."
    analyst_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
