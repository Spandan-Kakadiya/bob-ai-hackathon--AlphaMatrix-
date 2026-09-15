import random
from datetime import datetime, timezone
from typing import Dict, Any, List

SAMPLE_TARGET_ASSETS = [
    "DEF-RADAR-STATION-ALPHA",
    "TACTICAL-COMMAND-POST-BRAVO",
    "SATCOM-UPLINK-TERMINAL-04",
    "AIR-DEFENSE-C2-GATEWAY",
    "NAVAL-BATTLESPACE-RELAY-1"
]

GENUINE_SCENARIOS = [
    # Scenario 1: Coordinated Satellite Jamming + Cyber Infiltration (APT-COSMIC)
    {
        "source_type": "SATELLITE",
        "source_feed": "DEF-SPACE-SSN-SENSOR-09",
        "severity": "CRITICAL",
        "title": "Severe RF Uplink Jamming & GNSS Spoofing Detected on Ku-Band",
        "description": "Satellite transponder #4 experienced sudden 22dB SNR drop and loss of lock. Correlated GNSS coordinates indicate localized spoofing field.",
        "target_asset": "SATCOM-UPLINK-TERMINAL-04",
        "source_ip_or_coord": "Sector-7 / Azimuth 142.4°",
        "destination_ip_or_coord": "GEO-SAT-DEF-2",
        "tags": ["APT-COSMIC", "RF Jamming", "Electronic Warfare", "Satellite"],
        "geo_location": {"lat": 36.14, "lon": 44.01, "region": "Northern Defense Sector"}
    },
    {
        "source_type": "CYBER",
        "source_feed": "Zeek-Network-Sensor",
        "severity": "CRITICAL",
        "title": "Cobalt Strike C2 Beaconing via Encrypted DNS Tunneling",
        "description": "Repetitive 60s jitter beacon observed to external rogue IP 185.220.101.44 matching known nation-state C2 profile.",
        "target_asset": "SATCOM-UPLINK-TERMINAL-04",
        "source_ip_or_coord": "185.220.101.44",
        "destination_ip_or_coord": "10.42.1.18",
        "tags": ["APT-COSMIC", "C2", "DNS Tunneling"],
        "geo_location": {"lat": 36.14, "lon": 44.01, "region": "Northern Defense Sector"}
    },
    {
        "source_type": "INTEL",
        "source_feed": "STIX-2.1-Adversary-Feed",
        "severity": "HIGH",
        "title": "Flash Advisory: APT-COSMIC Targeting Forward Satcom Uplinks",
        "description": "SIGINT indicates threat group actively deploying custom RF jamming pods in tandem with spear-phishing payloads against tactical communications relays.",
        "target_asset": "SATCOM-UPLINK-TERMINAL-04",
        "source_ip_or_coord": "Adversary Cell Bravo",
        "destination_ip_or_coord": "Tactical Infrastructure",
        "tags": ["APT-COSMIC", "Adversary Profile", "Threat Advisory"],
        "geo_location": {"lat": 36.14, "lon": 44.01, "region": "Northern Defense Sector"}
    },
    {
        "source_type": "SIEM",
        "source_feed": "Splunk-Command-Logs",
        "severity": "CRITICAL",
        "title": "Anomalous PowerShell Base64 Execution & Service Account Impersonation",
        "description": "Event ID 4688: Process creation 'powershell.exe -EncodedCommand WwBTAG8AY...'. Service account 'svc_satcom' logged in from unexpected subnet.",
        "target_asset": "SATCOM-UPLINK-TERMINAL-04",
        "source_ip_or_coord": "10.42.1.88",
        "destination_ip_or_coord": "10.42.1.18",
        "tags": ["APT-COSMIC", "Execution", "Privilege Escalation"],
        "geo_location": {"lat": 36.14, "lon": 44.01, "region": "Northern Defense Sector"}
    },
    
    # Scenario 2: Air Defense C2 Recon & Lateral Movement (SANDWORM-DERIVATIVE)
    {
        "source_type": "CYBER",
        "source_feed": "CrowdStrike-EDR",
        "severity": "CRITICAL",
        "title": "Mimikatz LSASS Memory Dump and Kerberoasting Sweep",
        "description": "Unauthorized procdump targeting lsass.exe detected on radar command workstation. 14 service ticket requests dispatched in 3 seconds.",
        "target_asset": "AIR-DEFENSE-C2-GATEWAY",
        "source_ip_or_coord": "10.10.8.22",
        "destination_ip_or_coord": "10.10.0.1",
        "tags": ["SANDWORM", "Credential Dumping", "Lateral Movement"],
        "geo_location": {"lat": 32.89, "lon": 35.62, "region": "Coastal Command Division"}
    },
    {
        "source_type": "SIEM",
        "source_feed": "Elastic-Security-Analytics",
        "severity": "HIGH",
        "title": "Mass Remote PsExec Invocation across Defense Subnets",
        "description": "High volume of ADMIN$ SMB shares accessed concurrently with execution of remote service binary 'radartrack_sync.exe'.",
        "target_asset": "AIR-DEFENSE-C2-GATEWAY",
        "source_ip_or_coord": "10.10.8.22",
        "destination_ip_or_coord": "10.10.8.50",
        "tags": ["SANDWORM", "Lateral Movement", "Remote Services"],
        "geo_location": {"lat": 32.89, "lon": 35.62, "region": "Coastal Command Division"}
    }
]

BENIGN_NOISE_FEED = [
    {
        "source_type": "CYBER",
        "source_feed": "Tenable-Nessus-Scanner",
        "severity": "LOW",
        "title": "Vulnerability Scanner Scheduled Network Port Sweep",
        "description": "Internal automated health check and compliance scan dispatched from authorized scanner node 10.0.99.10.",
        "target_asset": "TACTICAL-COMMAND-POST-BRAVO",
        "source_ip_or_coord": "10.0.99.10",
        "destination_ip_or_coord": "10.0.0.0/24",
        "tags": ["Automated", "Vulnerability Scanner", "Routine"],
        "geo_location": {"lat": 34.05, "lon": 40.22, "region": "Base Command"}
    },
    {
        "source_type": "SATELLITE",
        "source_feed": "Space-Optics-Telemetry",
        "severity": "LOW",
        "title": "Satellite Telemetry Sun-Glint Calibration Sequence",
        "description": "Optical sensor temporary saturation during solar alignment pass. Standard atmospheric refraction test completed.",
        "target_asset": "DEF-RADAR-STATION-ALPHA",
        "source_ip_or_coord": "LEO-ORBIT-22",
        "destination_ip_or_coord": "Ground Receiver 1",
        "tags": ["Telemetry", "Calibration", "Routine"],
        "geo_location": {"lat": 38.12, "lon": 45.30, "region": "Eastern High Range"}
    },
    {
        "source_type": "SIEM",
        "source_feed": "Windows-Server-Logs",
        "severity": "LOW",
        "title": "Scheduled Backup Sync and IT Patch Tuesday Deployment",
        "description": "Approved defense post maintenance window: WSUS client updating KB5034441 and database snapshot archive.",
        "target_asset": "NAVAL-BATTLESPACE-RELAY-1",
        "source_ip_or_coord": "10.200.1.5",
        "destination_ip_or_coord": "10.200.1.100",
        "tags": ["Maintenance", "Backup", "Routine"],
        "geo_location": {"lat": 31.20, "lon": 34.79, "region": "Southern Littoral Command"}
    }
]

def generate_random_alert() -> Dict[str, Any]:
    """
    Simulates incoming feed stream: 60% benign background noise, 40% coordinated threats.
    """
    is_noise = random.random() < 0.60
    if is_noise:
        template = random.choice(BENIGN_NOISE_FEED).copy()
        template["id"] = f"NOISE-{random.randint(1000, 9999)}"
        template["confidence_score"] = round(random.uniform(0.15, 0.40), 2)
    else:
        template = random.choice(GENUINE_SCENARIOS).copy()
        template["id"] = f"ALERT-{random.randint(1000, 9999)}"
        template["confidence_score"] = round(random.uniform(0.85, 0.99), 2)

    template["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return template

def get_initial_seed_alerts() -> List[Dict[str, Any]]:
    """
    Returns an initial batch of multi-source alerts demonstrating full correlation.
    """
    alerts = []
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # Add genuine coordinated attack alerts
    for item in GENUINE_SCENARIOS:
        c = item.copy()
        c["id"] = f"SEED-ALERT-{len(alerts)+1:03d}"
        c["timestamp"] = now_str
        c["confidence_score"] = 0.94
        alerts.append(c)
        
    # Add benign noise alerts (to be filtered out by correlation engine)
    for item in BENIGN_NOISE_FEED:
        c = item.copy()
        c["id"] = f"SEED-NOISE-{len(alerts)+1:03d}"
        c["timestamp"] = now_str
        c["confidence_score"] = 0.25
        alerts.append(c)
        
    random.shuffle(alerts)
    return alerts
