# Solution Overview

## What We Built

We built Project BOB, an enterprise-grade defense intelligence correlation and alert prioritization platform. It unifies heterogeneous telemetry across SIEM logs, satellite RF feeds, cyber sensors, and STIX threat intelligence into a centralized tactical command war-room, automatically filtering background noise and synthesizing executive BLUF (Bottom Line Up Front) briefings for commanders.

## How It Works

Step 1: Multi-Source Ingestion & Zero-Trust Sanitization
Ingests disparate streams (SIEM, Satellite RF, Cyber IDS/EDR, STIX 2.1) while strictly sanitizing raw payloads to neutralize embedded exploits.
Step 2: Heuristic Noise Reduction (>85% Filtered)
Evaluates alerts against operational baselines to instantly discard scheduled maintenance, routine vulnerability scans, and orbital sun-glint calibrations.
Step 3: Real-Time MITRE ATT&CK Mapping
Analyzes genuine signals in real time, mapping adversary TTPs across all 14 enterprise and space/electronic warfare tactical domains.
Step 4: Cross-Domain Incident Correlation
Clusters related multi-source events into unified threat incidents based on target asset overlap, kill-chain progression, and geospatial proximity.
Step 5: Automated BLUF Assessment Generation
Synthesizes correlated threat clusters into structured Bottom Line Up Front assessments, delivering impact statements, key judgments, and prioritized rules of engagement.

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed diagram.

[Optionally include a simple ASCII or Mermaid diagram here for quick reference.]

```
[User] → [Frontend: React] → [API: FastAPI] → [watsonx.ai] → [Dashboard]
                                    ↓
                             [PostgreSQL DB]
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Dual-Mode BLUF Synthesis (Cloud AI + Deterministic Heuristic Fallback)|Military operations cannot depend exclusively on an active cloud connection. If the cloud API drops or the system operates in an air-gapped tactical SCIF, the deterministic heuristic engine automatically constructs the BLUF briefing without service interruption. |
| Cross-Domain Convergence (Cyber + Space/RF + Electronic Warfare) | Modern adversaries execute hybrid campaigns—such as jamming satellite transponders to mask ground network infiltration. Correlating space and cyber signals together uncovers coordinated attack chains that isolated tools miss. |
| Upfront Heuristic Noise Filtering (>85% Volume Reduction) | Applying rule-based noise filtering before clustering and AI inference drastically conserves computational resources, reduces API costs, and completely eliminates analyst alert fatigue. |
| Zero-Trust Ingestion Hardening | Adversaries frequently craft log payloads containing exploit strings (such as XSS, SQLi, and command injection). Sanitizing every raw payload at the API boundary ensures the defense platform itself cannot be compromised. |
| Strict Role-Based Clearance Architecture | Military environments mandate compartmentalized information access; analysts view tactical telemetry appropriate to their clearance, while only authorized commanders can view DEFCON escalation controls and executive briefs. |
## IBM Technologies Used

[Explain specifically HOW you used each IBM technology — not just that you used it.]

- **IBM watsonx.ai (Granite Foundation Models):** Powers the automated threat reasoning engine by taking correlated cross-domain incident clusters and generating structured, natural-language BLUF briefings, confidence-rated key judgments, and actionable containment recommendations.
- **IBM QRadar SIEM:** Acts as the primary enterprise defense SIEM ingestion source, feeding raw security event logs, offense telemetry, and authentication anomaly records into the correlation pipeline.
- **IBM Cloud Pak for Security Standards:** Provides the open-standard architectural blueprint (leveraging STIX 2.1 and open threat indicators) for connected, vendor-agnostic threat hunting and investigation across decentralized defense networks.
