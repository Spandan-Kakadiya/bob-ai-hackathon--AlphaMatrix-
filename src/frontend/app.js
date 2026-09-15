/**
 * BOB Defense Threat Intelligence Platform
 * Tactical Operations HUD, Attack Topology, RF Oscilloscope & BLUF Briefing Client
 */

document.addEventListener('DOMContentLoaded', () => {
  // State variables
  let currentSourceFilter = 'ALL';
  let autoStreamTimer = null;
  let currentBLUFReport = null;
  let soundEnabled = true;
  let currentAuthToken = localStorage.getItem('bob_defense_auth_token') || null;
  let currentAnalyst = null;
  let cachedClusters = [];
  let cachedAlerts = [];
  let searchQuery = '';
  let counterEWActive = false;

  // Audio synthesizer for military tactical beeps
  function playTacticalBeep(freq = 880, duration = 0.08, type = 'sine') {
    if (!soundEnabled) return;
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return;
      const ctx = new AudioContext();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + duration);
    } catch (e) {}
  }

  // DOM Elements - Auth Gate
  const authGateOverlay = document.getElementById('authGateOverlay');
  const tabBtnLogin = document.getElementById('tabBtnLogin');
  const tabBtnRegister = document.getElementById('tabBtnRegister');
  const formLogin = document.getElementById('formLogin');
  const formRegister = document.getElementById('formRegister');
  const loginErrorMsg = document.getElementById('loginErrorMsg');
  const regErrorMsg = document.getElementById('regErrorMsg');
  const btnLogout = document.getElementById('btnLogout');
  const displayUserName = document.getElementById('displayUserName');
  const displayUserClearance = document.getElementById('displayUserClearance');
  const userAvatar = document.getElementById('userAvatar');
  const watermarkLevelText = document.getElementById('watermarkLevelText');
  const threatSearchInput = document.getElementById('threatSearchInput');
  const selectDefcon = document.getElementById('selectDefcon');
  const hudSystemStatus = document.getElementById('hudSystemStatus');

  // DOM Elements - Metrics
  const metricTotalAlerts = document.getElementById('metricTotalAlerts');
  const metricFpFiltered = document.getElementById('metricFpFiltered');
  const metricActiveClusters = document.getElementById('metricActiveClusters');
  const metricMitreCount = document.getElementById('metricMitreCount');
  
  const alertFeedContainer = document.getElementById('alertFeedContainer');
  const threatClustersContainer = document.getElementById('threatClustersContainer');
  const feedCountChip = document.getElementById('feedCountChip');
  const mitreGridContainer = document.getElementById('mitreGridContainer');

  // Modals
  const modalIngest = document.getElementById('modalIngest');
  const modalSupabase = document.getElementById('modalSupabase');
  const modalLlm = document.getElementById('modalLlm');
  const modalMitreDetail = document.getElementById('modalMitreDetail');
  const mitreModalTitle = document.getElementById('mitreModalTitle');
  const mitreModalBody = document.getElementById('mitreModalBody');
  const btnCloseMitreModal = document.getElementById('btnCloseMitreModal');

  const modalNodeDetail = document.getElementById('modalNodeDetail');
  const nodeModalTitle = document.getElementById('nodeModalTitle');
  const nodeModalBody = document.getElementById('nodeModalBody');
  const btnCloseNodeModal = document.getElementById('btnCloseNodeModal');

  const btnOpenIngestModal = document.getElementById('btnOpenIngestModal');
  const btnCloseIngestModal = document.getElementById('btnCloseIngestModal');
  const btnCancelIngest = document.getElementById('btnCancelIngest');
  const btnConfigSupabase = document.getElementById('btnConfigSupabase');
  const btnCloseSupabaseModal = document.getElementById('btnCloseSupabaseModal');
  const btnCancelSupabase = document.getElementById('btnCancelSupabase');
  const btnConfigLlm = document.getElementById('btnConfigLlm');
  const btnCloseLlmModal = document.getElementById('btnCloseLlmModal');
  const btnCancelLlm = document.getElementById('btnCancelLlm');

  // RF Controls
  const btnToggleCounterEW = document.getElementById('btnToggleCounterEW');
  const rfStatusChip = document.getElementById('rfStatusChip');
  const rfNoiseFloorText = document.getElementById('rfNoiseFloorText');
  const rfHoppingStatus = document.getElementById('rfHoppingStatus');

  // Buttons
  const btnSimulateFeed = document.getElementById('btnSimulateFeed');
  const btnAutoStreamToggle = document.getElementById('btnAutoStreamToggle');
  const autoStreamState = document.getElementById('autoStreamState');
  const btnSoundToggle = document.getElementById('btnSoundToggle');
  const soundState = document.getElementById('soundState');
  const btnQuickBlufAll = document.getElementById('btnQuickBlufAll');
  const btnExportMarkdown = document.getElementById('btnExportMarkdown');
  const btnExportStix = document.getElementById('btnExportStix');
  const btnPrintReport = document.getElementById('btnPrintReport');
  const btnAuthorizeROE = document.getElementById('btnAuthorizeROE');

  // Forms
  const formIngestAlert = document.getElementById('formIngestAlert');
  const formSupabaseConfig = document.getElementById('formSupabaseConfig');
  const formLlmConfig = document.getElementById('formLlmConfig');
  const formCopilot = document.getElementById('formCopilot');
  const copilotInput = document.getElementById('copilotInput');
  const copilotChatLog = document.getElementById('copilotChatLog');
  const btnSendCopilot = document.getElementById('btnSendCopilot');

  // Authenticated Fetch Helper
  async function authFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (currentAuthToken) {
      options.headers['Authorization'] = `Bearer ${currentAuthToken}`;
    }
    const res = await fetch(url, options);
    if (res.status === 401) {
      authGateOverlay.classList.remove('hidden');
      throw new Error('Authentication required');
    }
    return res;
  }

  // --- DEFCON ESCALATION LOGIC ---
  if (selectDefcon) {
    selectDefcon.addEventListener('change', (e) => {
      const defconVal = e.target.value;
      document.body.className = `defcon-${defconVal}`;
      if (defconVal === '1') {
        playTacticalBeep(1800, 0.4, 'sawtooth');
        hudSystemStatus.innerHTML = '<span class="pulse-dot" style="background:var(--crimson);"></span><span style="color:var(--crimson); font-weight:800;">DEFCON 1 // MAXIMUM RED ALERT ACTIVE</span>';
      } else if (defconVal === '2') {
        playTacticalBeep(1200, 0.2, 'square');
        hudSystemStatus.innerHTML = '<span class="pulse-dot"></span><span>DEFCON 2 // ARMED ATTACK IMMINENT</span>';
      } else {
        playTacticalBeep(880, 0.1);
        hudSystemStatus.innerHTML = `<span class="pulse-dot" style="background:var(--emerald);"></span><span>DEFCON ${defconVal} // TACTICAL PATROL ACTIVE</span>`;
      }
    });
  }

  // --- SCENARIO INJECTORS ---
  document.querySelectorAll('.btn-scenario').forEach(btn => {
    btn.addEventListener('click', async () => {
      const scenario = btn.getAttribute('data-scenario');
      btn.disabled = true;
      btn.textContent = '⚡ Injecting...';
      playTacticalBeep(1300, 0.1);

      let payloadBatch = [];
      if (scenario === 'space_cyber') {
        payloadBatch = [
          { source_type: 'SATELLITE', source_feed: 'Space-SSN-Sensor', severity: 'CRITICAL', title: 'Severe RF Uplink Jamming (+24dB Delta)', description: 'Ku-Band carrier noise floor surge at 14.25 GHz', target_asset: 'SATCOM-UPLINK-TERMINAL-04', tags: ['APT-COSMIC', 'RF Jamming'] },
          { source_type: 'CYBER', source_feed: 'Zeek-IDS', severity: 'CRITICAL', title: 'Cobalt Strike C2 DNS Tunneling', description: 'Outbound suspicious DNS queries to rogue apex server', target_asset: 'SATCOM-UPLINK-TERMINAL-04', tags: ['APT-COSMIC', 'C2'] }
        ];
      } else if (scenario === 'radar_spoof') {
        payloadBatch = [
          { source_type: 'SIEM', source_feed: 'Air-Defense-Firewall', severity: 'HIGH', title: 'Radar Gateway Credential Spraying', description: 'Repeated Kerberos pre-auth failures from foreign subnet', target_asset: 'AIR-DEFENSE-RADAR-ALPHA', tags: ['SANDWORM', 'Credential Access'] },
          { source_type: 'CYBER', source_feed: 'Suricata-NIDS', severity: 'HIGH', title: 'Tactical Track Spoofing Packet Injection', description: 'Malformed Link-16 telemetry frames targeting secondary radar', target_asset: 'AIR-DEFENSE-RADAR-ALPHA', tags: ['SANDWORM', 'Spoofing'] }
        ];
      } else if (scenario === 'ransomware') {
        payloadBatch = [
          { source_type: 'CYBER', source_feed: 'CrowdStrike-EDR', severity: 'CRITICAL', title: 'BlackCat/ALPHV Ransomware Binary Staged', description: 'Unauthorized PowerShell execution invoking vssadmin delete shadows', target_asset: 'COMMAND-POST-CORE-ROUTER', tags: ['APT28', 'Execution'] }
        ];
      } else if (scenario === 'benign_noise') {
        payloadBatch = [
          { source_type: 'CYBER', source_feed: 'Nessus-Scanner', severity: 'LOW', title: 'Routine Scheduled Vulnerability Scan Sweep', description: 'Internal compliance sweep on subnet 10.0.99.0/24', target_asset: 'DMZ-WEB-PORTAL-01', tags: ['Automated'] },
          { source_type: 'SATELLITE', source_feed: 'Orbital-Optical', severity: 'LOW', title: 'Transient Solar Reflection / Glint Noise', description: 'Nominal solar panel glint across star tracker optical sensor', target_asset: 'LEO-SAT-04', tags: ['Routine'] }
        ];
      }

      try {
        for (const item of payloadBatch) {
          await authFetch('/api/alerts/ingest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(item)
          });
        }
        await refreshAll();
        playTacticalBeep(1400, 0.15);
      } catch (e) {
      } finally {
        btn.disabled = false;
        if (scenario === 'space_cyber') btn.textContent = '🚀 1. Space-Cyber Assault (APT-COSMIC)';
        else if (scenario === 'radar_spoof') btn.textContent = '🛰️ 2. Radar Spoofing & C2 (SANDWORM)';
        else if (scenario === 'ransomware') btn.textContent = '💻 3. Command Post Ransomware (APT28)';
        else btn.textContent = '🚫 4. Test Noise Filter Batch';
      }
    });
  });

  // --- COUNTER-EW TOGGLE ---
  if (btnToggleCounterEW) {
    btnToggleCounterEW.addEventListener('click', () => {
      counterEWActive = !counterEWActive;
      if (counterEWActive) {
        rfStatusChip.textContent = 'HOPPING ACTIVE: STABILIZED';
        rfStatusChip.style.color = 'var(--emerald)';
        rfNoiseFloorText.textContent = '-92 dBm (CLEAN / NORMAL)';
        rfNoiseFloorText.style.color = 'var(--emerald)';
        rfHoppingStatus.textContent = 'ENGAGED (1,000 hops/sec Pseudo-Random)';
        rfHoppingStatus.style.color = 'var(--emerald)';
        btnToggleCounterEW.textContent = '⏹️ Disengage Carrier Hopping';
        playTacticalBeep(1600, 0.15, 'square');
      } else {
        rfStatusChip.textContent = 'JAMMING: +22dB';
        rfStatusChip.style.color = 'var(--crimson)';
        rfNoiseFloorText.textContent = '-48 dBm (DEGRADED)';
        rfNoiseFloorText.style.color = 'var(--crimson)';
        rfHoppingStatus.textContent = 'STANDBY (Standard Carrier)';
        rfHoppingStatus.style.color = 'var(--amber)';
        btnToggleCounterEW.textContent = '📡 Engage Frequency Agile Hopping';
        playTacticalBeep(700, 0.15, 'sawtooth');
      }
    });
  }

  // --- AUTHENTICATION GATE HANDLING ---
  tabBtnLogin.addEventListener('click', () => {
    tabBtnLogin.classList.add('active');
    tabBtnRegister.classList.remove('active');
    formLogin.classList.add('active');
    formRegister.classList.remove('active');
    loginErrorMsg.textContent = '';
  });

  tabBtnRegister.addEventListener('click', () => {
    tabBtnRegister.classList.add('active');
    tabBtnLogin.classList.remove('active');
    formRegister.classList.add('active');
    formLogin.classList.remove('active');
    regErrorMsg.textContent = '';
  });

  async function checkActiveSession() {
    if (!currentAuthToken) {
      authGateOverlay.classList.remove('hidden');
      return;
    }
    try {
      const res = await fetch('/api/auth/me', {
        headers: { 'Authorization': `Bearer ${currentAuthToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        currentAnalyst = data.analyst;
        renderUserProfile(data.analyst);
        authGateOverlay.classList.add('hidden');
        refreshAll();
      } else {
        localStorage.removeItem('bob_defense_auth_token');
        currentAuthToken = null;
        authGateOverlay.classList.remove('hidden');
      }
    } catch (e) {
      authGateOverlay.classList.remove('hidden');
    }
  }

  function renderUserProfile(analyst) {
    if (!analyst) return;
    displayUserName.textContent = `${analyst.callsign} (${analyst.name})`;
    displayUserClearance.textContent = analyst.clearance_level || 'LEVEL-5 TOP SECRET';
    watermarkLevelText.textContent = analyst.clearance_level || 'LEVEL-5 TOP SECRET';

    if (analyst.clearance_level.includes('LEVEL-5')) {
      userAvatar.textContent = '🎖️';
      displayUserClearance.style.color = 'var(--cyan)';
      watermarkLevelText.style.color = 'var(--cyan)';
    } else if (analyst.clearance_level.includes('LEVEL-4')) {
      userAvatar.textContent = '🛰️';
      displayUserClearance.style.color = 'var(--purple)';
      watermarkLevelText.style.color = 'var(--purple)';
    } else {
      userAvatar.textContent = '💻';
      displayUserClearance.style.color = 'var(--emerald)';
      watermarkLevelText.style.color = 'var(--emerald)';
    }
  }

  formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginErrorMsg.textContent = '';
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();
      if (!res.ok) {
        loginErrorMsg.textContent = data.detail || 'Authentication failed.';
        playTacticalBeep(350, 0.15, 'sawtooth');
        return;
      }

      currentAuthToken = data.session.token;
      currentAnalyst = data.session.analyst;
      localStorage.setItem('bob_defense_auth_token', currentAuthToken);
      renderUserProfile(data.session.analyst);
      authGateOverlay.classList.add('hidden');
      playTacticalBeep(1200, 0.1);
      refreshAll();
    } catch (err) {
      loginErrorMsg.textContent = 'Error connecting to defense auth matrix.';
    }
  });

  formRegister.addEventListener('submit', async (e) => {
    e.preventDefault();
    regErrorMsg.textContent = '';
    const payload = {
      name: document.getElementById('regName').value.trim(),
      callsign: document.getElementById('regCallsign').value.trim(),
      email: document.getElementById('regEmail').value.trim(),
      clearance_level: document.getElementById('regClearance').value,
      division: document.getElementById('regDivision').value.trim(),
      password: document.getElementById('regPassword').value
    };

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) {
        regErrorMsg.textContent = data.detail || 'Registration rejected.';
        playTacticalBeep(350, 0.15, 'sawtooth');
        return;
      }

      currentAuthToken = data.session.token;
      currentAnalyst = data.session.analyst;
      localStorage.setItem('bob_defense_auth_token', currentAuthToken);
      renderUserProfile(data.session.analyst);
      authGateOverlay.classList.add('hidden');
      playTacticalBeep(1400, 0.12);
      refreshAll();
    } catch (err) {
      regErrorMsg.textContent = 'Error enrolling into Supabase matrix.';
    }
  });

  if (btnLogout) {
    btnLogout.addEventListener('click', async () => {
      try {
        if (currentAuthToken) {
          await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentAuthToken}` }
          });
        }
      } catch (e) {}
      localStorage.removeItem('bob_defense_auth_token');
      currentAuthToken = null;
      currentAnalyst = null;
      authGateOverlay.classList.remove('hidden');
      playTacticalBeep(500, 0.1);
    });
  }

  // Interactive Threat Search Filter
  if (threatSearchInput) {
    threatSearchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      renderFilteredAlerts();
      renderFilteredClusters();
    });
  }

  // Sound Toggle
  if (btnSoundToggle) {
    btnSoundToggle.addEventListener('click', () => {
      soundEnabled = !soundEnabled;
      soundState.textContent = soundEnabled ? 'ON' : 'OFF';
      soundState.style.color = soundEnabled ? 'var(--cyan)' : 'var(--text-muted)';
      if (soundEnabled) playTacticalBeep(1200, 0.1);
    });
  }

  // Tab Navigation
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');

  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      navTabs.forEach(t => t.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));
      
      tab.classList.add('active');
      const targetId = tab.getAttribute('data-tab');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');

      playTacticalBeep(980, 0.05);

      if (targetId === 'tab-mitre') {
        loadMitreMatrix();
      }
    });
  });

  // Source Feed Filters
  const feedFilterBtns = document.querySelectorAll('.feed-filter-btn');
  feedFilterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      feedFilterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentSourceFilter = btn.getAttribute('data-source');
      playTacticalBeep(750, 0.04);
      loadAlerts();
    });
  });

  // Presets in Ingest Modal
  document.querySelectorAll('.btn-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-type');
      if (type === 'sat_jam') {
        document.getElementById('inputSourceType').value = 'SATELLITE';
        document.getElementById('inputTargetAsset').value = 'SATCOM-UPLINK-TERMINAL-04';
        document.getElementById('inputAlertTitle').value = 'High-Intensity RF Carrier Interference (Ku-Band)';
        document.getElementById('inputAlertDesc').value = 'Uplink telemetry carrier signal experiencing +26dB noise floor disruption at 14.25 GHz with hostile sweep patterns.';
      } else if (type === 'siem_c2') {
        document.getElementById('inputSourceType').value = 'SIEM';
        document.getElementById('inputTargetAsset').value = 'COMMAND-POST-CORE-ROUTER';
        document.getElementById('inputAlertTitle').value = 'Cobalt Strike C2 Beaconing to Suspicious Foreign IP';
        document.getElementById('inputAlertDesc').value = 'CEF:0|BOB-SIEM|Firewall|1.0|C2-01|Hostile C2 Beacon|9|src=192.168.10.45 dst=185.220.101.55 proto=TCP dport=443';
      } else if (type === 'benign_scan') {
        document.getElementById('inputSourceType').value = 'CYBER';
        document.getElementById('inputTargetAsset').value = 'DMZ-WEB-PORTAL-01';
        document.getElementById('inputAlertTitle').value = 'Routine Automated Vulnerability Scanner Probing';
        document.getElementById('inputAlertDesc').value = 'Scheduled Nessus vulnerability scan from internal security compliance subnetwork 10.0.99.12.';
      }
      playTacticalBeep(1100, 0.05);
    });
  });

  // Quick Copilot Prompts
  document.querySelectorAll('.btn-quick-prompt').forEach(btn => {
    btn.addEventListener('click', () => {
      const query = btn.getAttribute('data-query');
      copilotInput.value = query;
      submitCopilotQuery(query);
    });
  });

  // Fetch and Update Core Metrics
  async function loadDashboardStats() {
    try {
      const res = await authFetch('/api/stats');
      if (!res.ok) return;
      const stats = await res.json();
      
      metricTotalAlerts.textContent = stats.total_alerts_ingested;
      metricFpFiltered.textContent = `${stats.false_positives_filtered} (${stats.noise_reduction_percentage}%)`;
      metricActiveClusters.textContent = `${stats.active_threat_clusters} Active`;
      
      feedCountChip.textContent = `${stats.total_alerts_ingested} processed`;
    } catch (e) {}
  }

  // Fetch and Render Ingested Alerts
  async function loadAlerts() {
    try {
      const url = `/api/alerts?source=${currentSourceFilter}&limit=40`;
      const res = await authFetch(url);
      if (!res.ok) return;
      cachedAlerts = await res.json();
      renderFilteredAlerts();
    } catch (e) {}
  }

  function renderFilteredAlerts() {
    let filtered = cachedAlerts;
    if (searchQuery) {
      filtered = filtered.filter(a => 
        a.title.toLowerCase().includes(searchQuery) ||
        a.description.toLowerCase().includes(searchQuery) ||
        a.target_asset.toLowerCase().includes(searchQuery)
      );
    }

    alertFeedContainer.innerHTML = '';
    if (filtered.length === 0) {
      alertFeedContainer.innerHTML = '<div style="color:var(--text-muted); font-size:0.8rem; padding:12px;">No matching alerts found.</div>';
      return;
    }

    filtered.forEach(alert => {
      const item = document.createElement('div');
      const isFp = alert.is_false_positive;
      item.className = `alert-item ${isFp ? 'is-fp' : 'is-genuine'}`;

      const sourceClass = alert.source_type.toLowerCase();
      let timeStr = alert.timestamp;
      if (timeStr.includes('T')) {
        timeStr = timeStr.split('T')[1].replace('Z', ' UTC').substring(0, 8);
      }

      const fpHtml = isFp 
        ? `<span class="fp-badge">🚫 NOISE FILTERED: ${alert.fp_reason || 'Benign Pattern'}</span>`
        : `<span style="color:var(--crimson); font-weight:700; font-family:var(--font-mono); font-size:0.7rem;">⚠️ GENUINE THREAT [${alert.severity}]</span>`;

      const mitreTags = (alert.mitre_techniques || []).map(t => `<span class="meta-chip" style="color:var(--amber)">${t}</span>`).join(' ');

      const descHtml = alert.description.includes('REDACTED') 
        ? `<span class="redacted-tag">${alert.description}</span>` 
        : alert.description;

      item.innerHTML = `
        <div class="alert-top">
          <span class="source-tag ${sourceClass}">[${alert.source_type}] ${alert.source_feed}</span>
          <span style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-muted);">${timeStr}</span>
        </div>
        <div class="alert-title">${alert.title}</div>
        <div class="alert-desc">${descHtml}</div>
        <div class="alert-meta">
          <span class="meta-chip">Target: ${alert.target_asset}</span>
          ${mitreTags}
          ${fpHtml}
        </div>
      `;
      alertFeedContainer.appendChild(item);
    });
  }

  // Fetch and Render Correlated Clusters
  async function loadClusters() {
    try {
      const res = await authFetch('/api/clusters');
      if (!res.ok) return;
      cachedClusters = await res.json();
      renderFilteredClusters();
    } catch (e) {}
  }

  function renderFilteredClusters() {
    let filtered = cachedClusters;
    if (searchQuery) {
      filtered = filtered.filter(c => 
        c.name.toLowerCase().includes(searchQuery) ||
        c.threat_actor.toLowerCase().includes(searchQuery) ||
        c.affected_assets.some(a => a.toLowerCase().includes(searchQuery))
      );
    }

    threatClustersContainer.innerHTML = '';
    if (filtered.length === 0) {
      threatClustersContainer.innerHTML = '<div style="color:var(--text-muted); font-size:0.8rem; padding:12px;">No matching threat incidents detected.</div>';
      return;
    }

    filtered.forEach(cluster => {
      const card = document.createElement('div');
      const sevClass = cluster.severity.toLowerCase();
      card.className = `cluster-card ${sevClass}`;

      const vectorBadges = cluster.attack_vectors.map(v => 
        `<span class="source-tag ${v.toLowerCase()}">${v}</span>`
      ).join(' ');

      const techChips = (cluster.mitre_techniques_covered || []).map(t => 
        `<span class="meta-chip" style="border:1px solid var(--amber); color:var(--amber); cursor:pointer;" onclick="window.inspectMitreTechnique('${t}')">${t}</span>`
      ).join(' ');

      card.innerHTML = `
        <div class="cluster-header">
          <div class="cluster-title-wrap">
            <h3>${cluster.name}</h3>
            <div class="cluster-actor">THREAT ACTOR: ${cluster.threat_actor} • CONFIDENCE: ${(cluster.confidence_score * 100).toFixed(0)}%</div>
          </div>
          <div class="cluster-badge-row">
            <span class="source-tag cyber">${cluster.severity}</span>
          </div>
        </div>

        <div class="kill-chain-wrap">
          <div class="kill-chain-label">KILL-CHAIN PHASE: ${cluster.kill_chain_phase}</div>
          <div class="kill-chain-bar">
            <div class="kill-chain-progress" style="width: ${cluster.severity === 'CONTAINED' ? '100%' : (cluster.severity === 'CRITICAL' ? '85%' : '55%')}"></div>
          </div>
        </div>

        <div class="converged-sources">
          <span style="font-size:0.75rem; color:var(--text-muted); align-self:center;">Converged Domains:</span>
          ${vectorBadges}
        </div>

        <div style="font-size:0.75rem; color:var(--text-muted); margin: 6px 0;">
          <strong>Target Defense Assets:</strong> ${cluster.affected_assets.join(', ')}<br>
          <strong>MITRE TTPs:</strong> ${techChips || '<span style="color:var(--text-muted)">None mapped</span>'}
        </div>

        <div class="cluster-actions">
          <button class="btn btn-primary btn-generate-bluf" data-cluster-id="${cluster.cluster_id}">
            📋 Synthesize Commander BLUF
          </button>
          <span style="font-size:0.72rem; font-family:var(--font-mono); color:var(--text-muted); align-self:center;">
            ${cluster.raw_alert_count} multi-source events
          </span>
        </div>

        <!-- Interactive Triage & Mitigation Actions -->
        <div class="cluster-mitigation-row">
          <span style="font-size:0.7rem; color:var(--cyan); font-family:var(--font-mono);">⚡ MITIGATE:</span>
          <button class="btn btn-mitigate" data-cluster-id="${cluster.cluster_id}" data-action="ISOLATE_GATEWAY">
            🔒 Isolate Network Gateway
          </button>
          <button class="btn btn-mitigate" data-cluster-id="${cluster.cluster_id}" data-action="COUNTER_EW_JAM">
            📡 Deploy Counter-EW Hopping
          </button>
          <button class="btn btn-mitigate" data-cluster-id="${cluster.cluster_id}" data-action="REVOKE_TOKENS">
            🔑 Revoke Admin Session Tokens
          </button>
        </div>
      `;
      threatClustersContainer.appendChild(card);
    });

    document.querySelectorAll('.btn-generate-bluf').forEach(btn => {
      btn.addEventListener('click', () => {
        const clusterId = btn.getAttribute('data-cluster-id');
        generateBLUFReport(clusterId);
      });
    });

    document.querySelectorAll('.btn-mitigate').forEach(btn => {
      btn.addEventListener('click', async () => {
        const clusterId = btn.getAttribute('data-cluster-id');
        const actionType = btn.getAttribute('data-action');
        btn.disabled = true;
        btn.textContent = '⚡ Mitigating...';
        try {
          const res = await authFetch('/api/clusters/mitigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cluster_id: clusterId, action_type: actionType })
          });
          if (res.ok) {
            playTacticalBeep(1400, 0.15, 'square');
            await loadClusters();
          }
        } catch (e) {}
      });
    });
  }

  // Interactive MITRE Technique Playbook Inspector
  window.inspectMitreTechnique = function(techId) {
    mitreModalTitle.textContent = `⚔️ MITRE TTP Playbook: ${techId}`;
    
    let playbookDesc = "Adversary utilizing direct command line or network protocol to execute malicious operations.";
    let playbookRemediation = "1. Isolate endpoint from tactical VLAN.\n2. Revoke Kerberos tickets and service account tokens.\n3. Verify EDR telemetry memory hashes.";
    let detectionRule = `rule Detect_${techId} {\n  meta:\n    technique = "${techId}"\n    severity = "CRITICAL"\n  condition:\n    any of them\n}`;

    if (techId === 'T0800') {
      playbookDesc = "Electronic Warfare (EW) RF Uplink/Downlink Jamming: Targeted frequency noise saturation against satellite ground transponders.";
      playbookRemediation = "1. Initiate frequency-agile pseudo-random carrier hopping on transponder 4.\n2. Engage ground-based RF Direction Finding (DF) triangulation.\n3. Switch tactical telemetry link to hardened troposcatter backup.";
      detectionRule = "ALERT Space_EW_RF_Jamming:\n  carrier_noise_floor_delta > +18dB\n  frequency_band = 'Ku' AND transponder_status = 'DEGRADED'";
    } else if (techId === 'T1071') {
      playbookDesc = "Command and Control via Application Layer Protocols (DNS Tunneling / HTTPS Covert Channels).";
      playbookRemediation = "1. Blackhole rogue C2 IP/FQDN at tactical boundary edge firewall.\n2. Force DNS query inspection and drop TXT record sizes exceeding 255 bytes.\n3. Perform full host RAM acquisition.";
      detectionRule = "zeek_dns_log | where query_len > 120 and qtype_name == 'TXT' | count by src_ip > 50";
    }

    mitreModalBody.innerHTML = `
      <div class="playbook-section">
        <div class="playbook-title">Tactical Mechanism</div>
        <div class="playbook-text">${playbookDesc}</div>
      </div>
      <div class="playbook-section">
        <div class="playbook-title">Defense Mitigation Playbook</div>
        <div class="playbook-text" style="white-space:pre-line;">${playbookRemediation}</div>
      </div>
      <div class="playbook-section">
        <div class="playbook-title">Real-Time Sensor Detection Logic</div>
        <div class="playbook-code">${detectionRule}</div>
      </div>
    `;

    modalMitreDetail.style.display = 'flex';
    playTacticalBeep(1100, 0.08);
  };

  if (btnCloseMitreModal) {
    btnCloseMitreModal.addEventListener('click', () => modalMitreDetail.style.display = 'none');
  }
  if (btnCloseNodeModal) {
    btnCloseNodeModal.addEventListener('click', () => modalNodeDetail.style.display = 'none');
  }

  // Fetch and Render MITRE ATT&CK Matrix Grid
  async function loadMitreMatrix() {
    try {
      const res = await authFetch('/api/mitre/matrix');
      if (!res.ok) return;
      const matrix = await res.json();

      let activeTotal = 0;
      mitreGridContainer.innerHTML = '';
      matrix.forEach(tactic => {
        activeTotal += tactic.active_count;
        const col = document.createElement('div');
        col.className = 'mitre-tactic-col';

        let techCardsHtml = '';
        tactic.techniques.forEach(tech => {
          const activeClass = tech.is_active ? 'active-threat' : '';
          const countBadge = tech.hit_count > 0 ? `<span style="color:var(--crimson); font-weight:800;">(${tech.hit_count})</span>` : '';
          
          techCardsHtml += `
            <div class="mitre-tech-card ${activeClass}" title="Click to view playbook" onclick="window.inspectMitreTechnique('${tech.id}')">
              <div class="mitre-tech-id">${tech.id} ${countBadge}</div>
              <div class="mitre-tech-name">${tech.name}</div>
            </div>
          `;
        });

        col.innerHTML = `
          <div class="mitre-tactic-name">
            <span>${tactic.tactic_name}</span>
            <span style="color:var(--text-muted); font-size:0.7rem;">${tactic.active_count} active</span>
          </div>
          ${techCardsHtml}
        `;
        mitreGridContainer.appendChild(col);
      });

      metricMitreCount.textContent = `${activeTotal} Active`;
    } catch (e) {}
  }

  // Generate and Display BLUF Commander Briefing
  async function generateBLUFReport(clusterId) {
    try {
      const blufTab = document.querySelector('[data-tab="tab-bluf"]');
      if (blufTab) blufTab.click();

      playTacticalBeep(660, 0.12, 'sawtooth');
      document.getElementById('blufHeadlineTitle').textContent = 'SYNTHESIZING MULTI-SOURCE BLUF BRIEFING...';
      document.getElementById('blufHeadlineBody').textContent = 'Synthesizing satellite telemetry, cyber sensor feeds, and SIEM logs with OpenAI GPT-4o intelligence engine...';

      const res = await authFetch('/api/bluf/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cluster_id: clusterId })
      });

      if (!res.ok) {
        alert('Failed to synthesize BLUF report.');
        return;
      }

      const report = await res.json();
      currentBLUFReport = report;
      renderBLUFReport(report);
      playTacticalBeep(1400, 0.1);
    } catch (e) {}
  }

  function renderBLUFReport(report) {
    document.getElementById('blufClassification').textContent = report.classification_level || 'TOP SECRET // NOFORN';
    document.getElementById('blufMetaId').textContent = `REPORT: ${report.report_id} • ATTRIBUTED: ${report.attributed_threat_actor} • CONFIDENCE: ${report.confidence_assessment}`;
    
    document.getElementById('blufHeadlineTitle').textContent = report.bluf_headline;
    document.getElementById('blufHeadlineBody').textContent = report.bottom_line_up_front;

    // Judgments
    const judgmentsList = document.getElementById('blufJudgmentsList');
    judgmentsList.innerHTML = '';
    (report.key_judgments || []).forEach(j => {
      const el = document.createElement('div');
      el.className = 'judgment-item';
      el.textContent = j;
      judgmentsList.appendChild(el);
    });

    // Timeline
    const timelineContainer = document.getElementById('blufTimelineContainer');
    timelineContainer.innerHTML = '';
    (report.incident_timeline || []).forEach(t => {
      const row = document.createElement('div');
      row.style.cssText = 'background:rgba(14,22,36,0.6); padding:8px 12px; border-radius:4px; font-size:0.78rem; display:flex; justify-content:space-between; font-family:var(--font-mono);';
      row.innerHTML = `
        <span style="color:var(--cyan);">${t.time}</span>
        <span style="color:var(--text-bright);">${t.source} — ${t.event}</span>
        <span style="color:var(--crimson); font-weight:700;">[${t.severity}]</span>
      `;
      timelineContainer.appendChild(row);
    });

    // Tactical Impact
    const impactList = document.getElementById('blufImpactList');
    impactList.innerHTML = '';
    (report.tactical_impact || []).forEach(imp => {
      const el = document.createElement('div');
      el.className = 'impact-item';
      el.textContent = imp;
      impactList.appendChild(el);
    });

    // Commander Actions Table
    const actionsTbody = document.getElementById('blufActionsTbody');
    actionsTbody.innerHTML = '';
    (report.recommended_commander_actions || []).forEach(act => {
      const tr = document.createElement('tr');
      const pClass = act.priority.toLowerCase().includes('immediate') ? 'immediate' : (act.priority.toLowerCase().includes('priority') ? 'priority' : 'routine');
      tr.innerHTML = `
        <td><span class="priority-badge ${pClass}">${act.priority}</span></td>
        <td style="color:var(--text-bright); font-weight:500;">${act.action}</td>
        <td style="font-family:var(--font-mono); color:var(--cyan);">${act.owner}</td>
      `;
      actionsTbody.appendChild(tr);
    });
  }

  // AI Copilot Logic
  async function submitCopilotQuery(query) {
    if (!query) return;

    const userMsg = document.createElement('div');
    userMsg.className = 'copilot-msg user';
    userMsg.innerHTML = `<strong>ANALYST:</strong> ${escapeHtml(query)}`;
    copilotChatLog.appendChild(userMsg);

    const botMsg = document.createElement('div');
    botMsg.className = 'copilot-msg bot';
    botMsg.innerHTML = `<strong>BOB DEFENSE COPILOT:</strong> <span class="pulse-dot"></span> Correlating multi-source intelligence...`;
    copilotChatLog.appendChild(botMsg);
    copilotChatLog.scrollTop = copilotChatLog.scrollHeight;

    btnSendCopilot.disabled = true;
    try {
      const payload = {
        question: query,
        cluster_id: currentBLUFReport ? currentBLUFReport.cluster_id : null
      };

      const res = await authFetch('/api/ai/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        botMsg.innerHTML = `<strong>BOB DEFENSE COPILOT:</strong> Error processing query. Status: ${res.status}`;
        return;
      }

      const data = await res.json();
      const formattedAns = data.answer.replace(/\n/g, '<br>');
      botMsg.innerHTML = `<strong>BOB DEFENSE COPILOT [${data.mode}]:</strong><br><br>${formattedAns}`;
      playTacticalBeep(1200, 0.08);
    } catch (e) {
      botMsg.innerHTML = `<strong>BOB DEFENSE COPILOT:</strong> Telemetry connection interrupted. ${e.message}`;
    } finally {
      btnSendCopilot.disabled = false;
      copilotInput.value = '';
      copilotChatLog.scrollTop = copilotChatLog.scrollHeight;
    }
  }

  if (formCopilot) {
    formCopilot.addEventListener('submit', (e) => {
      e.preventDefault();
      submitCopilotQuery(copilotInput.value.trim());
    });
  }

  btnSimulateFeed.addEventListener('click', async () => {
    btnSimulateFeed.disabled = true;
    btnSimulateFeed.textContent = '⚡ Ingesting...';
    playTacticalBeep(800, 0.06);
    try {
      const res = await authFetch('/api/simulate/tick', { method: 'POST' });
      if (res.ok) {
        await refreshAll();
        playTacticalBeep(1050, 0.08);
      }
    } catch (e) {
    } finally {
      btnSimulateFeed.disabled = false;
      btnSimulateFeed.textContent = '⚡ Ingest Telemetry (+3)';
    }
  });

  btnAutoStreamToggle.addEventListener('click', () => {
    if (autoStreamTimer) {
      clearInterval(autoStreamTimer);
      autoStreamTimer = null;
      autoStreamState.textContent = 'OFF';
      autoStreamState.style.color = 'var(--text-muted)';
      playTacticalBeep(500, 0.08);
    } else {
      autoStreamTimer = setInterval(async () => {
        try {
          await authFetch('/api/simulate/tick', { method: 'POST' });
          await refreshAll();
          playTacticalBeep(900, 0.03);
        } catch (e) {}
      }, 5000);
      autoStreamState.textContent = 'ACTIVE (5s)';
      autoStreamState.style.color = 'var(--emerald)';
      playTacticalBeep(1100, 0.08);
    }
  });

  btnQuickBlufAll.addEventListener('click', async () => {
    if (cachedClusters.length > 0) {
      generateBLUFReport(cachedClusters[0].cluster_id);
    } else {
      alert('No active threat clusters available.');
    }
  });

  btnExportMarkdown.addEventListener('click', () => {
    if (!currentBLUFReport) {
      alert('Please synthesize a BLUF report first.');
      return;
    }
    const r = currentBLUFReport;
    const mdContent = `# ${r.classification_level} // COMMANDER BLUF ASSESSMENT
**Report ID:** ${r.report_id}  
**Date/Time:** ${r.timestamp}  
**Attributed Threat Actor:** ${r.attributed_threat_actor}  
**Confidence Assessment:** ${r.confidence_assessment}  

---

## 1. BOTTOM LINE UP FRONT (BLUF)
> **${r.bluf_headline}**  
> ${r.bottom_line_up_front}

---

## 2. KEY INTELLIGENCE JUDGMENTS
${(r.key_judgments || []).map(j => `- ${j}`).join('\n')}

---

## 3. CHRONOLOGICAL MULTI-SOURCE TIMELINE
${(r.incident_timeline || []).map(t => `- **${t.time}** | ${t.source} — ${t.event} [${t.severity}]`).join('\n')}

---

## 4. TACTICAL & MISSION IMPACT
${(r.tactical_impact || []).map(i => `- ${i}`).join('\n')}

---

## 5. PRIORITISED COMMANDER ACTIONS & RULES OF ENGAGEMENT
${(r.recommended_commander_actions || []).map(a => `- **[${a.priority}]** (${a.owner}): ${a.action}`).join('\n')}

*Rules of Engagement:* ${r.rules_of_engagement_impact}
`;

    const blob = new Blob([mdContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${r.report_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  });

  if (btnExportStix) {
    btnExportStix.addEventListener('click', async () => {
      if (!currentBLUFReport) {
        alert('Please synthesize a BLUF report first.');
        return;
      }
      try {
        const res = await authFetch(`/api/clusters/${currentBLUFReport.cluster_id}/stix`);
        if (!res.ok) throw new Error('STIX generation failed');
        const stixData = await res.json();
        const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `STIX-2.1-${currentBLUFReport.cluster_id}.json`;
        a.click();
        URL.revokeObjectURL(url);
        playTacticalBeep(1200, 0.08);
      } catch (err) {
        alert('STIX export failed: ' + err.message);
      }
    });
  }

  if (btnPrintReport) {
    btnPrintReport.addEventListener('click', () => {
      if (!currentBLUFReport) {
        alert('Please synthesize a BLUF report first.');
        return;
      }
      window.print();
    });
  }

  btnAuthorizeROE.addEventListener('click', () => {
    if (currentAnalyst && !currentAnalyst.clearance_level.includes('LEVEL-5')) {
      alert('ACCESS DENIED: ROE Authorization requires Level-5 Commander Clearance.');
      playTacticalBeep(350, 0.2, 'sawtooth');
      return;
    }
    playTacticalBeep(1500, 0.2, 'square');
    alert('COMMAND ACTION CONFIRMED:\nTactical Cyber Isolation & Counter-EW Measures Dispatched to J6 Defense Operations under Standing ROE Rule 4.1.');
  });

  btnOpenIngestModal.addEventListener('click', () => modalIngest.style.display = 'flex');
  btnCloseIngestModal.addEventListener('click', () => modalIngest.style.display = 'none');
  btnCancelIngest.addEventListener('click', () => modalIngest.style.display = 'none');

  if (btnConfigSupabase) {
    btnConfigSupabase.addEventListener('click', () => modalSupabase.style.display = 'flex');
    btnCloseSupabaseModal.addEventListener('click', () => modalSupabase.style.display = 'none');
    btnCancelSupabase.addEventListener('click', () => modalSupabase.style.display = 'none');
  }

  btnConfigLlm.addEventListener('click', () => modalLlm.style.display = 'flex');
  btnCloseLlmModal.addEventListener('click', () => modalLlm.style.display = 'none');
  btnCancelLlm.addEventListener('click', () => modalLlm.style.display = 'none');

  formIngestAlert.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      source_type: document.getElementById('inputSourceType').value,
      source_feed: 'Manual-Command-Entry',
      target_asset: document.getElementById('inputTargetAsset').value,
      title: document.getElementById('inputAlertTitle').value,
      description: document.getElementById('inputAlertDesc').value,
      confidence_score: 0.95
    };

    try {
      const res = await authFetch('/api/alerts/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        modalIngest.style.display = 'none';
        formIngestAlert.reset();
        await refreshAll();
        playTacticalBeep(1300, 0.1);
      }
    } catch (err) {}
  });

  if (formSupabaseConfig) {
    formSupabaseConfig.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = document.getElementById('inputSupabaseUrl').value;
      const key = document.getElementById('inputSupabaseKey').value;
      try {
        const res = await authFetch('/api/config/supabase', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ supabase_url: url, supabase_key: key })
        });
        if (res.ok) {
          alert('Supabase Cloud Database credentials configured successfully!');
          modalSupabase.style.display = 'none';
          playTacticalBeep(1200, 0.1);
        }
      } catch (err) {}
    });
  }

  formLlmConfig.addEventListener('submit', async (e) => {
    e.preventDefault();
    const apiKey = document.getElementById('inputApiKey').value;
    try {
      const res = await authFetch('/api/config/llm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: apiKey })
      });
      if (res.ok) {
        alert('AI Synthesis Engine successfully updated.');
        modalLlm.style.display = 'none';
        playTacticalBeep(1200, 0.1);
      }
    } catch (err) {}
  });

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // --- INTERACTIVE ATTACK TOPOLOGY GRAPH ENGINE ---
  function initTopologyGraph() {
    const canvas = document.getElementById('topologyCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function resize() {
      if (!canvas.parentElement) return;
      canvas.width = canvas.parentElement.clientWidth || 600;
      canvas.height = canvas.parentElement.clientHeight || 480;
    }
    resize();
    window.addEventListener('resize', resize);

    // Dynamic Graph Nodes
    const nodes = [
      { id: 'actor_cosmic', label: 'APT-COSMIC', type: 'adversary', x: 80, y: 120, radius: 22, color: '#ff2a55' },
      { id: 'actor_sandworm', label: 'SANDWORM', type: 'adversary', x: 80, y: 360, radius: 22, color: '#ff2a55' },
      { id: 'vector_rf', label: 'RF Jamming T0800', type: 'vector', x: 260, y: 100, radius: 18, color: '#ffb700' },
      { id: 'vector_c2', label: 'DNS C2 T1071', type: 'vector', x: 260, y: 220, radius: 18, color: '#ffb700' },
      { id: 'vector_spray', label: 'Spray T1110', type: 'vector', x: 260, y: 370, radius: 18, color: '#ffb700' },
      { id: 'boundary_fw', label: 'Boundary Firewall', type: 'boundary', x: 440, y: 240, radius: 20, color: '#00f0ff' },
      { id: 'asset_satcom', label: 'SATCOM Terminal 04', type: 'asset', x: 620, y: 120, radius: 24, color: '#b057f5' },
      { id: 'asset_radar', label: 'Air-Def Radar Alpha', type: 'asset', x: 620, y: 250, radius: 24, color: '#00ff9d' },
      { id: 'asset_post', label: 'Command Post Core', type: 'asset', x: 620, y: 380, radius: 24, color: '#00f0ff' }
    ];

    const edges = [
      { from: 'actor_cosmic', to: 'vector_rf', speed: 0.02 },
      { from: 'actor_cosmic', to: 'vector_c2', speed: 0.03 },
      { from: 'actor_sandworm', to: 'vector_spray', speed: 0.025 },
      { from: 'vector_rf', to: 'asset_satcom', speed: 0.04 },
      { from: 'vector_c2', to: 'boundary_fw', speed: 0.03 },
      { from: 'vector_spray', to: 'boundary_fw', speed: 0.025 },
      { from: 'boundary_fw', to: 'asset_radar', speed: 0.035 },
      { from: 'boundary_fw', to: 'asset_post', speed: 0.04 }
    ];

    let draggedNode = null;
    let pulseOffset = 0;

    canvas.addEventListener('mousedown', (e) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      draggedNode = nodes.find(n => Math.hypot(n.x - mx, n.y - my) <= n.radius);
    });

    window.addEventListener('mousemove', (e) => {
      if (!draggedNode) return;
      const rect = canvas.getBoundingClientRect();
      draggedNode.x = e.clientX - rect.left;
      draggedNode.y = e.clientY - rect.top;
    });

    window.addEventListener('mouseup', () => {
      draggedNode = null;
    });

    canvas.addEventListener('click', (e) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const clicked = nodes.find(n => Math.hypot(n.x - mx, n.y - my) <= n.radius);
      if (clicked) {
        openNodeDetailModal(clicked);
      }
    });

    function renderTopology() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Draw Edges
      edges.forEach(edge => {
        const n1 = nodes.find(n => n.id === edge.from);
        const n2 = nodes.find(n => n.id === edge.to);
        if (!n1 || !n2) return;

        ctx.strokeStyle = 'rgba(0, 240, 255, 0.2)';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(n1.x, n1.y);
        ctx.lineTo(n2.x, n2.y);
        ctx.stroke();

        // Pulsing Attack Particle
        const t = (pulseOffset * edge.speed * 20) % 1;
        const px = n1.x + (n2.x - n1.x) * t;
        const py = n1.y + (n2.y - n1.y) * t;

        ctx.fillStyle = n1.color;
        ctx.shadowColor = n1.color;
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(px, py, 4, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw Nodes
      nodes.forEach(node => {
        ctx.fillStyle = 'rgba(6, 9, 17, 0.9)';
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 2;
        ctx.shadowColor = node.color;
        ctx.shadowBlur = 12;

        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Label
        ctx.fillStyle = '#ffffff';
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + node.radius + 14);
      });

      pulseOffset += 0.01;
      requestAnimationFrame(renderTopology);
    }
    renderTopology();
  }

  function openNodeDetailModal(node) {
    nodeModalTitle.textContent = `🌐 Node Telemetry: ${node.label}`;
    nodeModalBody.innerHTML = `
      <div class="playbook-section">
        <div class="playbook-title">Node Classification & Role</div>
        <div class="playbook-text">
          <strong>Type:</strong> ${node.type.toUpperCase()}<br>
          <strong>Status:</strong> ACTIVE MONITORING<br>
          <strong>Tactical Blast Radius:</strong> Cross-Domain (Space + Ground Command Relay)
        </div>
      </div>
      <div class="playbook-section">
        <div class="playbook-title">Security Containment Action</div>
        <div class="playbook-text">
          Direct sensor telemetry confirmed active packets. Use the <strong>MITIGATE</strong> buttons in the Operations HUD to isolate this node.
        </div>
      </div>
    `;
    modalNodeDetail.style.display = 'flex';
    playTacticalBeep(1100, 0.08);
  }

  // --- LIVE RF SPECTRUM OSCILLOSCOPE ENGINE ---
  function initRFOscilloscope() {
    const canvas = document.getElementById('rfSpectrumCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function resize() {
      if (!canvas.parentElement) return;
      canvas.width = canvas.parentElement.clientWidth || 300;
      canvas.height = canvas.parentElement.clientHeight || 260;
    }
    resize();
    window.addEventListener('resize', resize);

    let phase = 0;
    function renderWaveform() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const w = canvas.width;
      const h = canvas.height;
      const cy = h / 2;

      // Draw Grid
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.06)';
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 20) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let y = 0; y < h; y += 20) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // Base Carrier Waveform
      ctx.beginPath();
      ctx.lineWidth = 2;
      ctx.strokeStyle = counterEWActive ? '#00ff9d' : '#ff2a55';
      ctx.shadowColor = counterEWActive ? '#00ff9d' : '#ff2a55';
      ctx.shadowBlur = 8;

      for (let x = 0; x < w; x++) {
        let noise = counterEWActive ? Math.sin(x * 0.2 + phase * 4) * 4 : Math.sin(x * 0.3 + phase * 6) * 28 + (Math.random() - 0.5) * 16;
        let y = cy + Math.sin(x * 0.05 + phase) * 35 + noise;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Center carrier frequency line
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.4)';
      ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(w / 2, 0); ctx.lineTo(w / 2, h); ctx.stroke();
      ctx.setLineDash([]);

      phase += 0.04;
      requestAnimationFrame(renderWaveform);
    }
    renderWaveform();
  }

  // --- GEOSPATIAL RADAR CANVAS ---
  function initTacticalMap() {
    const canvas = document.getElementById('tacticalMapCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    function resize() {
      if (!canvas.parentElement) return;
      canvas.width = canvas.parentElement.clientWidth || 300;
      canvas.height = canvas.parentElement.clientHeight || 260;
    }
    resize();
    window.addEventListener('resize', resize);

    let angle = 0;
    function renderMap() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const w = canvas.width;
      const h = canvas.height;
      const cx = w / 2;
      const cy = h / 2;

      // Draw Grid Lines
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.08)';
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 30) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let y = 0; y < h; y += 30) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // Draw Radar Range Circles
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.2)';
      ctx.beginPath(); ctx.arc(cx, cy, 60, 0, Math.PI * 2); ctx.stroke();
      ctx.beginPath(); ctx.arc(cx, cy, 110, 0, Math.PI * 2); ctx.stroke();

      // Sweeping radar beam
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);
      const grad = ctx.createLinearGradient(0, 0, 110, 0);
      grad.addColorStop(0, 'rgba(0, 240, 255, 0.4)');
      grad.addColorStop(1, 'rgba(0, 240, 255, 0)');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, 110, 0, Math.PI / 4);
      ctx.fill();
      ctx.restore();

      // Satellites in Orbit
      const sat1X = cx + Math.cos(angle * 0.7) * 90;
      const sat1Y = cy + Math.sin(angle * 0.7) * 45;
      ctx.fillStyle = '#b057f5';
      ctx.beginPath(); ctx.arc(sat1X, sat1Y, 4, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = '#cbd5e1';
      ctx.font = '9px monospace';
      ctx.fillText('LEO-SAT-04', sat1X + 6, sat1Y - 4);

      // Ground Command Station Node
      const cmdX = cx - 35;
      const cmdY = cy + 30;
      ctx.fillStyle = '#00f0ff';
      ctx.beginPath(); ctx.arc(cmdX, cmdY, 5, 0, Math.PI * 2); ctx.fill();
      ctx.fillText('COMMAND-POST', cmdX + 7, cmdY + 3);

      // RF Jamming Pulse Node (Red)
      const jamX = cx + 45;
      const jamY = cy - 20;
      const pulseR = 6 + Math.sin(angle * 4) * 4;
      ctx.strokeStyle = '#ff2a55';
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(jamX, jamY, pulseR, 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = '#ff2a55';
      ctx.beginPath(); ctx.arc(jamX, jamY, 3, 0, Math.PI * 2); ctx.fill();
      ctx.fillText('RF-JAM-ZONE', jamX + 8, jamY - 2);

      // Connection Vector Line
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.3)';
      ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(sat1X, sat1Y); ctx.lineTo(cmdX, cmdY); ctx.stroke();
      ctx.setLineDash([]);

      angle += 0.02;
      requestAnimationFrame(renderMap);
    }
    renderMap();
  }

  async function refreshAll() {
    if (!currentAuthToken) return;
    await loadDashboardStats();
    await loadAlerts();
    await loadClusters();
    await loadMitreMatrix();
  }

  // Initial Boot
  checkActiveSession();
  initTacticalMap();
  initTopologyGraph();
  initRFOscilloscope();
});
