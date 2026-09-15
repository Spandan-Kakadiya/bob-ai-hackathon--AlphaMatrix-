"""
BOB Defense Threat Intelligence Platform
Multi-Source Threat Correlation and Noise Reduction Engine
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone
import re
from backend.models import Alert, ThreatCluster
from backend.engine.mitre_mapper import MitreMapper

KNOWN_BENIGN_PATTERNS = [
    (r"vulnerability scanner|nessus|qualys|internal automated health check", "Routine Internal Security Vulnerability Sweep"),
    (r"satellite telemetry sun-glint calibration|atmospheric refraction test", "Scheduled Satellite Optical/RF Sensor Recalibration"),
    (r"scheduled backup sync|it patch tuesday deployment", "Approved Defense Post Maintenance Window"),
    (r"benign test ping|icmp keepalive", "Standard Infrastructure Heartbeat Telemetry"),
    (r"ntp drift correction|clock sync jitter", "Benign Network Time Protocol Adjustment")
]

class ThreatCorrelator:
    def __init__(self, mitre_mapper: MitreMapper):
        self.mitre_mapper = mitre_mapper
        self.active_alerts: List[Alert] = []
        self.threat_clusters: Dict[str, ThreatCluster] = {}
        self.false_positives_count: int = 0
        self.total_processed: int = 0

    def evaluate_false_positive(self, alert: Alert) -> Tuple[bool, str]:
        """
        Determines if an alert is a benign false positive or noise based on heuristic baselines.
        """
        search_blob = f"{alert.title} {alert.description} {alert.raw_payload} {' '.join(alert.tags)}".lower()
        
        for pattern, reason in KNOWN_BENIGN_PATTERNS:
            if re.search(pattern, search_blob, re.IGNORECASE):
                return True, reason
                
        # Low confidence isolated scans from internal test ranges
        if alert.confidence_score < 0.35 and alert.source_type == "CYBER" and "scan" in search_blob:
            return True, "Low-confidence isolated non-actionable network sweep"
            
        return False, ""

    def ingest_and_process_alert(self, raw_alert_dict: Dict[str, Any]) -> Alert:
        """
        Ingest, sanitize, map to MITRE, filter noise, and correlate.
        """
        self.total_processed += 1
        now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        # Build alert object
        alert = Alert(
            id=raw_alert_dict.get("id") or f"ALT-{self.total_processed:04d}",
            timestamp=raw_alert_dict.get("timestamp") or now_ts,
            source_type=raw_alert_dict.get("source_type", "CYBER").upper(),
            source_feed=raw_alert_dict.get("source_feed", "Unknown-Feed"),
            severity=raw_alert_dict.get("severity", "MEDIUM").upper(),
            title=raw_alert_dict.get("title", "Threat Signal Detected"),
            description=raw_alert_dict.get("description", ""),
            raw_payload=raw_alert_dict.get("raw_payload", ""),
            target_asset=raw_alert_dict.get("target_asset", "Command-Center-Node-1"),
            source_ip_or_coord=raw_alert_dict.get("source_ip_or_coord", "Unknown"),
            destination_ip_or_coord=raw_alert_dict.get("destination_ip_or_coord", "Unknown"),
            confidence_score=float(raw_alert_dict.get("confidence_score", 0.8)),
            geo_location=raw_alert_dict.get("geo_location"),
            ioc_hashes=raw_alert_dict.get("ioc_hashes", []),
            tags=raw_alert_dict.get("tags", [])
        )

        # 1. MITRE ATT&CK Mapping
        tactics, techniques = self.mitre_mapper.map_alert_to_mitre(
            alert.title, alert.description, alert.raw_payload, alert.tags
        )
        alert.mitre_tactics = tactics
        alert.mitre_techniques = techniques

        # 2. False Positive Evaluation
        is_fp, fp_reason = self.evaluate_false_positive(alert)
        if is_fp:
            alert.is_false_positive = True
            alert.fp_reason = fp_reason
            alert.severity = "BENIGN"
            self.false_positives_count += 1
        
        self.active_alerts.append(alert)

        # 3. Multi-Source Incident Correlation (if genuine)
        if not is_fp:
            self._correlate_into_clusters(alert)

        return alert

    def _correlate_into_clusters(self, alert: Alert):
        """
        Group multi-source genuine alerts into coordinated threat incidents based on:
        - Target Defense Asset overlap
        - Geographical / Tactical sector proximity
        - Kill-chain progression (Recon -> Access -> Execution -> C2 -> EW Jamming)
        - Threat Actor TTP signature overlap
        """
        matched_cluster = None

        # Look for active clusters targeting the same asset or sector
        for cluster in self.threat_clusters.values():
            if cluster.status not in ["ACTIVE_INVESTIGATION", "ESCALATED"]:
                continue

            # Criteria 1: Target asset matching
            if alert.target_asset in cluster.affected_assets:
                matched_cluster = cluster
                break
                
            # Criteria 2: Multi-source cyber + space convergence on command sector
            if alert.source_type in ["SATELLITE", "CYBER", "INTEL"] and any(
                a["target_asset"] == alert.target_asset or 
                a.get("source_ip_or_coord") == alert.source_ip_or_coord 
                for a in cluster.alerts
            ):
                matched_cluster = cluster
                break

        if not matched_cluster:
            # Create new correlated threat cluster
            threat_actor = "UNKNOWN-NATION-STATE"
            campaign_name = f"Incident on {alert.target_asset}"
            
            # Infer threat actor & campaign from intel tags
            for tag in alert.tags:
                if "APT" in tag.upper() or "COSMIC" in tag.upper() or "BEAR" in tag.upper() or "VIPER" in tag.upper():
                    threat_actor = tag.upper()
                    campaign_name = f"Campaign: {threat_actor} Offensive Operation"

            cluster_id = f"THREAT-ACT-{len(self.threat_clusters) + 1:03d}"
            matched_cluster = ThreatCluster(
                cluster_id=cluster_id,
                name=campaign_name,
                threat_actor=threat_actor,
                campaign=campaign_name,
                severity=alert.severity,
                first_seen=alert.timestamp,
                last_seen=alert.timestamp,
                affected_assets=[alert.target_asset],
                attack_vectors=[alert.source_type],
                mitre_tactics_covered=list(alert.mitre_tactics),
                mitre_techniques_covered=list(alert.mitre_techniques)
            )
            self.threat_clusters[cluster_id] = matched_cluster

        # Add to cluster
        matched_cluster.last_seen = alert.timestamp
        matched_cluster.alert_ids.append(alert.id)
        matched_cluster.alerts.append(alert.to_dict())
        matched_cluster.raw_alert_count += 1
        
        if alert.target_asset not in matched_cluster.affected_assets:
            matched_cluster.affected_assets.append(alert.target_asset)
        if alert.source_type not in matched_cluster.attack_vectors:
            matched_cluster.attack_vectors.append(alert.source_type)

        for tactic in alert.mitre_tactics:
            if tactic not in matched_cluster.mitre_tactics_covered:
                matched_cluster.mitre_tactics_covered.append(tactic)
        for tech in alert.mitre_techniques:
            if tech not in matched_cluster.mitre_techniques_covered:
                matched_cluster.mitre_techniques_covered.append(tech)

        # Recalculate Multi-Source Confidence and Escalation
        source_count = len(matched_cluster.attack_vectors)
        if source_count >= 3:  # Multi-source convergence (e.g. SIEM + Cyber + Satellite RF)
            matched_cluster.severity = "CRITICAL"
            matched_cluster.confidence_score = 0.98
            matched_cluster.status = "ESCALATED"
        elif source_count == 2:
            matched_cluster.severity = "HIGH" if matched_cluster.severity != "CRITICAL" else "CRITICAL"
            matched_cluster.confidence_score = max(matched_cluster.confidence_score, 0.91)
        else:
            matched_cluster.confidence_score = max(matched_cluster.confidence_score, alert.confidence_score)

        # Dynamic kill-chain status
        if any("Electronic Warfare" in t for t in matched_cluster.mitre_tactics_covered):
            matched_cluster.kill_chain_phase = "Coordinated Cyber-EW Strike"
        elif any("Command and Control" in t or "Exfiltration" in t for t in matched_cluster.mitre_tactics_covered):
            matched_cluster.kill_chain_phase = "C2 / Data Exfiltration in Progress"
        elif any("Lateral Movement" in t or "Privilege Escalation" in t for t in matched_cluster.mitre_tactics_covered):
            matched_cluster.kill_chain_phase = "Internal Lateral Spread"
        else:
            matched_cluster.kill_chain_phase = "Perimeter Infiltration / Recon"

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns real-time defense metrics, noise filtering efficiency, and threat counts.
        """
        genuine_alerts = [a for a in self.active_alerts if not a.is_false_positive]
        fp_ratio = (self.false_positives_count / max(1, self.total_processed)) * 100.0
        
        return {
            "total_alerts_ingested": self.total_processed,
            "false_positives_filtered": self.false_positives_count,
            "genuine_threats_isolated": len(genuine_alerts),
            "noise_reduction_percentage": round(fp_ratio, 1),
            "active_threat_clusters": len(self.threat_clusters),
            "critical_clusters": sum(1 for c in self.threat_clusters.values() if c.severity == "CRITICAL"),
            "high_clusters": sum(1 for c in self.threat_clusters.values() if c.severity == "HIGH"),
            "sources_monitored": ["SIEM (Splunk/CEF)", "Satellite RF/SAR", "Cyber Sensors (Zeek/EDR)", "Strategic Intel (STIX 2.1)"]
        }
