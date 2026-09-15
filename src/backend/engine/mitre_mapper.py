"""
BOB Defense Threat Intelligence Platform
MITRE ATT&CK Mapping and TTP Extraction Engine
"""

from typing import Dict, List, Any, Tuple
import re

MITRE_TACTICS = {
    "TA0043": {"name": "Reconnaissance", "description": "Gathering information to plan future adversary operations."},
    "TA0042": {"name": "Resource Development", "description": "Establishing resources to support operations."},
    "TA0001": {"name": "Initial Access", "description": "Gaining an initial foothold within your network/perimeter."},
    "TA0002": {"name": "Execution", "description": "Running adversary-controlled malicious code or scripts."},
    "TA0003": {"name": "Persistence", "description": "Maintaining access across restarts, changed credentials, and interrupts."},
    "TA0004": {"name": "Privilege Escalation", "description": "Gaining higher-level permissions (e.g. root, SYSTEM)."},
    "TA0005": {"name": "Defense Evasion", "description": "Avoiding detection by SIEM, EDR, and cyber defenses."},
    "TA0006": {"name": "Credential Access", "description": "Stealing credentials such as tokens, hashes, and passwords."},
    "TA0007": {"name": "Discovery", "description": "Observing environment topology, satellites, radar, and networks."},
    "TA0008": {"name": "Lateral Movement", "description": "Navigating through systems and subnets across command nodes."},
    "TA0009": {"name": "Collection", "description": "Aggregating critical defense data, intel, and mission plans."},
    "TA0011": {"name": "Command and Control", "description": "Communicating with compromised systems via covert channels."},
    "TA0010": {"name": "Exfiltration", "description": "Stealing confidential tactical data and broadcasting out."},
    "TA0040": {"name": "Impact", "description": "Disrupting, manipulating, or destroying mission-critical systems."},
    "TA0050": {"name": "Electronic Warfare / Space", "description": "Jamming satellite up/downlinks, spoofing GPS/AIS, RF flooding."}
}

# Rule database matching alert signatures, keywords, protocols, and payloads to MITRE Techniques
MITRE_TECHNIQUES_DB = {
    "T1566": {
        "name": "Phishing",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "patterns": [r"phish", r"spear-phishing", r"malicious attachment", r"invoice\.exe", r"macro", r"credential harvest email"],
        "severity": "HIGH"
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "patterns": [r"cve-\d{4}-\d+", r"sql injection", r"sqli", r"rce", r"remote code execution", r"unauthenticated endpoint", r"log4j", r"spring4shell"],
        "severity": "CRITICAL"
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "patterns": [r"powershell", r"cmd\.exe", r"/bin/bash", r"python -c", r"wscript", r"cscript", r"encodedcommand", r"base64 -d"],
        "severity": "HIGH"
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "patterns": [r"anomalous login", r"impossible travel", r"admin account logon", r"service account token reuse", r"kerberoasting"],
        "severity": "HIGH"
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "TA0004",
        "tactic_name": "Privilege Escalation",
        "patterns": [r"privilege escalation", r"dirtypipe", r"uac bypass", r"token impersonation", r"setuid", r"sudoers modified"],
        "severity": "CRITICAL"
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "patterns": [r"wevtutil", r"clear-eventlog", r"auditlog wiped", r"rm -rf /var/log", r"history -c", r"kill edr agent"],
        "severity": "CRITICAL"
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "patterns": [r"mimikatz", r"lsass\.exe", r"ntds\.dit", r"/etc/shadow", r"sam dump", r"procdump"],
        "severity": "CRITICAL"
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "patterns": [r"port scan", r"nmap", r"masscan", r"syn flood discovery", r"arp scan", r"reconnaissance sweep"],
        "severity": "MEDIUM"
    },
    "T1021": {
        "name": "Remote Services (Lateral Movement)",
        "tactic": "TA0008",
        "tactic_name": "Lateral Movement",
        "patterns": [r"psexec", r"wmi exec", r"rdp brute", r"smb lateral", r"ssh pivot", r"winrm execution"],
        "severity": "HIGH"
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "TA0009",
        "tactic_name": "Collection",
        "patterns": [r"classified dir accessed", r"bulk file read", r"tar -czf", r"zip archive intel", r"sql dump export"],
        "severity": "HIGH"
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "tactic": "TA0011",
        "tactic_name": "Command and Control",
        "patterns": [r"cobalt strike", r"beaconing", r"dns tunneling", r"c2 heartbeat", r"reverse shell", r"tor hidden service"],
        "severity": "CRITICAL"
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "TA0010",
        "tactic_name": "Exfiltration",
        "patterns": [r"exfiltration to foreign ip", r"encrypted outbound burst", r"mega\.nz upload", r"cloud staging transfer"],
        "severity": "CRITICAL"
    },
    "T1485": {
        "name": "Data Destruction / Ransomware",
        "tactic": "TA0040",
        "tactic_name": "Impact",
        "patterns": [r"wiper", r"mbr overwritten", r"ransomware", r"shadow copy deleted", r"sc kill", r"firmware flash corruption"],
        "severity": "CRITICAL"
    },
    "T0800": {
        "name": "RF Spectrum & Uplink Jamming",
        "tactic": "TA0050",
        "tactic_name": "Electronic Warfare / Space",
        "patterns": [r"rf jamming", r"gnss spoofing", r"gps loss of lock", r"satellite telemetry loss", r"ku-band noise saturation", r"orbital transponder de-sync"],
        "severity": "CRITICAL"
    },
    "T0801": {
        "name": "Geospatial Spoofing / AIS Injection",
        "tactic": "TA0050",
        "tactic_name": "Electronic Warfare / Space",
        "patterns": [r"ais false track", r"radar decoy", r"synthetic aperture radar ghosting", r"coordinate teleportation anomaly"],
        "severity": "HIGH"
    }
}

class MitreMapper:
    def __init__(self):
        self.tactics = MITRE_TACTICS
        self.techniques = MITRE_TECHNIQUES_DB

    def map_alert_to_mitre(self, title: str, description: str, raw_payload: str, tags: List[str] = None) -> Tuple[List[str], List[str]]:
        """
        Extracts MITRE Tactics and Technique IDs from alert content.
        Returns: (tactics_list, techniques_list)
        """
        combined_text = f"{title} {description} {raw_payload} {' '.join(tags or [])}".lower()
        
        detected_techniques = set()
        detected_tactics = set()

        for tech_id, info in self.techniques.items():
            for pattern in info["patterns"]:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    detected_techniques.add(tech_id)
                    detected_tactics.add(info["tactic_name"])
                    break
        
        # Space / Satellite specific fallback
        if "satellite" in combined_text or "orbital" in combined_text or "uplink" in combined_text or "radar" in combined_text:
            if not detected_techniques:
                detected_techniques.add("T0800")
                detected_tactics.add("Electronic Warfare / Space")

        # Fallback to Discovery if unknown recon
        if not detected_techniques and ("scan" in combined_text or "probe" in combined_text):
            detected_techniques.add("T1046")
            detected_tactics.add("Discovery")

        return list(detected_tactics), list(detected_techniques)

    def get_full_matrix_state(self, active_technique_counts: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Generates tactical matrix structure with active adversary hit-counts.
        """
        matrix = []
        for tactic_id, tactic_info in self.tactics.items():
            tactic_name = tactic_info["name"]
            techs_in_tactic = []
            
            for tech_id, tech_info in self.techniques.items():
                if tech_info["tactic"] == tactic_id or tech_info["tactic_name"] == tactic_name:
                    count = active_technique_counts.get(tech_id, 0)
                    techs_in_tactic.append({
                        "id": tech_id,
                        "name": tech_info["name"],
                        "severity": tech_info["severity"],
                        "hit_count": count,
                        "is_active": count > 0
                    })
            
            matrix.append({
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "description": tactic_info["description"],
                "active_count": sum(t["hit_count"] for t in techs_in_tactic),
                "techniques": techs_in_tactic
            })
            
        return matrix
